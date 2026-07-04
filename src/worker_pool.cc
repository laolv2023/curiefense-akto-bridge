/**
 * @file worker_pool.cc
 * @brief CuriefenseWorkerPool 实现
 *
 * 审计修正 v3.2:
 * - shouldSendAlert: 分级过滤 + collection_id 兜底 + IP 限流
 * - IpRateLimiter: std::atomic call_counter (线程安全)
 */

#include "worker_pool.h"
#include "alert_builder.h"
#include <spdlog/spdlog.h>
#include <chrono>
#include <stdexcept>
#include <cctype>

namespace curiefense {

// ============================================================================
// IpRateLimiter
// ============================================================================

bool IpRateLimiter::allow(
    const std::string& ip, const std::string& account_id,
    const std::string& category, int max_per_minute) {
    std::lock_guard<std::mutex> lock(mutex_);
    Key key{ip, account_id, category};
    auto& window = windows_[key];

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // 清理 1 分钟前的时间戳
    while (!window.empty() && window.front() < now - 60) {
        window.pop_front();
    }

    if (static_cast<int>(window.size()) >= max_per_minute) {
        return false;
    }
    window.push_back(now);

    // 定期清理空窗口 (审计修正 v3.2-2: atomic call_counter)
    static std::atomic<uint64_t> call_counter{0};
    if ((call_counter.fetch_add(1, std::memory_order_relaxed) & 0x3FF) == 0) {
        for (auto it = windows_.begin(); it != windows_.end(); ) {
            auto& w = it->second;
            while (!w.empty() && w.front() < now - 60) {
                w.pop_front();
            }
            if (w.empty()) {
                it = windows_.erase(it);
            } else {
                ++it;
            }
        }
    }

    return true;
}

// ============================================================================
// CuriefenseWorkerPool
// ============================================================================

CuriefenseWorkerPool::CuriefenseWorkerPool(
    CuriefenseEngine& engine,
    AktoAdapter& adapter,
    const BridgeConfig& config)
    : engine_(engine)
    , adapter_(adapter)
    , config_(config)
    , max_pending_tasks_(config.detector.max_pending_tasks) {
}

CuriefenseWorkerPool::~CuriefenseWorkerPool() {
    stop();
}

void CuriefenseWorkerPool::setAlertGuard(
    const std::unordered_map<std::string, int32_t>& host_map,
    int32_t rate_limit_per_minute,
    bool filter_low_severity) {
    host_collection_fallback_ = host_map;
    rate_limit_per_minute_ = rate_limit_per_minute > 0 ? rate_limit_per_minute : 5;
    filter_low_severity_ = filter_low_severity;
    SPDLOG_INFO("[worker_pool] AlertGuard configured: host_map={} entries, "
                "rate_limit={}/min, filter_low={}",
                host_collection_fallback_.size(),
                rate_limit_per_minute_, filter_low_severity_);
}

void CuriefenseWorkerPool::start() {
    bool expected = false;
    if (!started_.compare_exchange_strong(expected, true)) {
        throw std::runtime_error("CuriefenseWorkerPool already started");
    }
    stopped_.store(false, std::memory_order_release);

    int threads = config_.detector.worker_threads;
    if (threads <= 0) {
        threads = static_cast<int>(std::thread::hardware_concurrency());
        if (threads <= 0) threads = 4;
    }

    SPDLOG_INFO("CuriefenseWorkerPool starting: {} threads", threads);
    for (int i = 0; i < threads; ++i) {
        workers_.emplace_back(&CuriefenseWorkerPool::workerLoop, this, i);
    }
}

void CuriefenseWorkerPool::stop() {
    bool expected = false;
    if (!stopped_.compare_exchange_strong(expected, true)) {
        return;
    }
    not_empty_.notify_all();
    not_full_.notify_all();
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();
    started_.store(false, std::memory_order_release);
    SPDLOG_INFO("CuriefenseWorkerPool stopped");
}

bool CuriefenseWorkerPool::submit(DetectTask task) {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    if (static_cast<int>(task_queue_.size()) >= max_pending_tasks_) {
        return false;
    }
    task_queue_.push_back(std::move(task));
    not_empty_.notify_one();
    return true;
}

size_t CuriefenseWorkerPool::pendingCount() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return task_queue_.size();
}

// ============================================================================
// workerLoop
// ============================================================================

void CuriefenseWorkerPool::workerLoop(int worker_id) {
    SPDLOG_DEBUG("CuriefenseWorkerPool: worker {} started", worker_id);

    while (!stopped_.load(std::memory_order_acquire)) {
        DetectTask task;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            not_empty_.wait(lock, [this] {
                return !task_queue_.empty() ||
                       stopped_.load(std::memory_order_acquire);
            });
            if (stopped_.load(std::memory_order_acquire) && task_queue_.empty()) {
                break;
            }
            if (!task_queue_.empty()) {
                task = std::move(task_queue_.front());
                task_queue_.pop_front();
                not_full_.notify_one();
            } else {
                continue;
            }
        }

        try {
            // 1. Kafka 消息 → AktoLog
            AktoLog log = adapter_.adapt(
                task.payload.data(), task.len,
                task.topic, task.partition, task.offset);

            // 2. AktoLog → Curiefense 检测
            AnalyzeResult result = engine_.inspect(
                log.ip, log.method, log.path, log.host,
                log.headers_json, log.request_body);

            // 3. 告警保护 (审计修正 v3.2: shouldSendAlert)
            if (result.hasThreat() && shouldSendAlert(result, log)) {
                // 4. 构建 MaliciousEventKafkaEnvelope Protobuf
                std::string payload = AlertBuilder::build(result, log);
                if (!payload.empty() && alert_callback_) {
                    std::string key = log.ip + ":" + log.path;
                    alert_callback_(payload, key);
                }
            }
        } catch (const std::exception& e) {
            SPDLOG_ERROR("[worker_pool] worker {} task failed: {} (topic={}, offset={})",
                         worker_id, e.what(), task.topic, task.offset);
        }
    }

    SPDLOG_DEBUG("CuriefenseWorkerPool: worker {} exiting", worker_id);
}

// ============================================================================
// shouldSendAlert — 告警保护 (审计修正 v3.2)
// ============================================================================

bool CuriefenseWorkerPool::shouldSendAlert(const AnalyzeResult& result, AktoLog& log) {
    // 功能1: 告警分级过滤 — 丢弃 LOW 级别
    std::string severity = AlertBuilder::build(result, log).empty() ? "" : "HIGH";
    if (filter_low_severity_) {
        if (!result.blocked && !result.monitored) {
            SPDLOG_DEBUG("[worker_pool] Dropping non-blocked/non-monitored alert");
            return false;
        }
    }

    // 功能2: collection_id=0 兜底
    if (log.api_collection_id == 0) {
        auto it = host_collection_fallback_.find(log.host);
        if (it != host_collection_fallback_.end()) {
            log.api_collection_id = it->second;
            SPDLOG_DEBUG("[worker_pool] Collection ID fallback: host={} → id={}",
                        log.host, it->second);
        } else {
            SPDLOG_WARN("[worker_pool] Dropping alert: collection_id=0 and no host fallback for {}",
                        log.host);
            return false;
        }
    }

    // 功能3: IP 级限流
    if (!rate_limiter_.allow(log.ip, log.akto_account_id,
                             log.path, rate_limit_per_minute_)) {
        SPDLOG_DEBUG("[worker_pool] Rate limited: ip={} path={}", log.ip, log.path);
        return false;
    }

    return true;
}

} // namespace curiefense
