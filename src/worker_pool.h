#pragma once

/**
 * @file worker_pool.h
 * @brief CuriefenseWorkerPool — Curiefense Bridge 检测线程池
 *
 * 审计修正 v3.2: 新增 shouldSendAlert 告警保护逻辑
 * (分级过滤 + IP 限流 + collection_id 兜底)
 */

#include "engine.h"
#include "akto_adapter.h"
#include "config.h"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace curiefense {

/// @brief 检测任务 (Kafka 消息 + 元数据)
struct DetectTask {
    std::string payload;
    size_t len;
    std::string topic;
    int32_t partition;
    int64_t offset;
};

/// @brief IP 级限流器 (与 WGE IpRateLimiter 一致)
/// 审计修正 v3.2-2: 使用 std::atomic call_counter
class IpRateLimiter {
public:
    bool allow(const std::string& ip, const std::string& account_id,
               const std::string& category, int max_per_minute = 5);

private:
    struct Key {
        std::string ip;
        std::string account_id;
        std::string category;
        bool operator==(const Key& o) const {
            return ip == o.ip && account_id == o.account_id && category == o.category;
        }
    };
    struct KeyHash {
        size_t operator()(const Key& k) const {
            return std::hash<std::string>()(k.ip) ^
                   (std::hash<std::string>()(k.account_id) << 1) ^
                   (std::hash<std::string>()(k.category) << 2);
        }
    };
    std::unordered_map<Key, std::deque<int64_t>, KeyHash> windows_;
    std::mutex mutex_;
};

class CuriefenseWorkerPool {
public:
    CuriefenseWorkerPool(
        CuriefenseEngine& engine,
        AktoAdapter& adapter,
        const BridgeConfig& config);
    ~CuriefenseWorkerPool();

    CuriefenseWorkerPool(const CuriefenseWorkerPool&) = delete;
    CuriefenseWorkerPool& operator=(const CuriefenseWorkerPool&) = delete;

    void start();
    void stop();

    /// @brief 提交检测任务 (线程安全)
    /// @return true 成功入队, false 队列满
    bool submit(DetectTask task);

    /// @brief 设置告警保护配置 (审计修正 v3.2)
    void setAlertGuard(
        const std::unordered_map<std::string, int32_t>& host_map,
        int32_t rate_limit_per_minute,
        bool filter_low_severity);

    size_t pendingCount() const;

private:
    void workerLoop(int worker_id);
    bool shouldSendAlert(const AnalyzeResult& result, AktoLog& log);
    std::string extractHostFromHeaders(const std::string& headers_json);

    CuriefenseEngine& engine_;
    AktoAdapter& adapter_;
    const BridgeConfig& config_;

    // 告警保护参数
    std::unordered_map<std::string, int32_t> host_collection_fallback_{};
    int32_t rate_limit_per_minute_{5};
    bool filter_low_severity_{true};
    IpRateLimiter rate_limiter_;

    // 线程池
    std::vector<std::thread> workers_;
    std::atomic<bool> started_{false};
    std::atomic<bool> stopped_{false};

    // 任务队列
    mutable std::mutex queue_mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    std::deque<DetectTask> task_queue_;
    int max_pending_tasks_{2000};

    // 告警输出回调 (由 main.cc 设置)
public:
    /// @brief 告警输出回调类型
    /// @param payload Protobuf 序列化后的 MaliciousEventKafkaEnvelope
    /// @param key 消息 key (用于 Kafka 分区)
    using AlertCallback = std::function<void(const std::string& payload, const std::string& key)>;
    void setAlertCallback(AlertCallback cb) { alert_callback_ = std::move(cb); }
private:
    AlertCallback alert_callback_;
};

} // namespace curiefense
