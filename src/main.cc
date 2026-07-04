/**
 * @file main.cc
 * @brief Curiefense-Akto Bridge 入口
 *
 * 消费 Akto Kafka 流量日志 → Curiefense WAF 检测 → MaliciousEventKafkaEnvelope Protobuf
 */

#include "config.h"
#include "engine.h"
#include "akto_adapter.h"
#include "alert_builder.h"
#include "worker_pool.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <librdkafka/rdkafkacpp.h>
#include <csignal>
#include <atomic>
#include <cstdlib>
#include <memory>

static std::atomic<bool> g_running{true};

static void signalHandler(int sig) {
    g_running.store(false, std::memory_order_release);
}

// ============================================================================
// Kafka Consumer 回调
// ============================================================================

class BridgeConsumer : public RdKafka::RebalanceCb {
public:
    void rebalance_cb(RdKafka::KafkaConsumer* consumer,
                      RdKafka::Error* err,
                      std::vector<RdKafka::TopicPartition*>* partitions) override {
        if (err->code() == RdKafka::ERR__ASSIGN_PARTITIONS) {
            consumer->assign(*partitions);
        } else {
            consumer->unassign();
        }
    }
};

// ============================================================================
// Kafka Producer 辅助
// ============================================================================

static RdKafka::Producer* createProducer(const curiefense::BridgeConfig::Producer& cfg) {
    std::string errstr;
    RdKafka::Conf* conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);

    conf->set("bootstrap.servers", cfg.bootstrap_servers, errstr);
    if (cfg.enable_idempotence) {
        conf->set("enable.idempotence", "true", errstr);
    }
    conf->set("batch.size", std::to_string(cfg.batch_size), errstr);
    conf->set("linger.ms", std::to_string(cfg.linger_ms), errstr);
    conf->set("retries", std::to_string(cfg.retries), errstr);
    if (!cfg.security_protocol.empty()) {
        conf->set("security.protocol", cfg.security_protocol, errstr);
        if (!cfg.sasl_mechanism.empty()) {
            conf->set("sasl.mechanism", cfg.sasl_mechanism, errstr);
        }
        if (!cfg.sasl_username.empty()) {
            conf->set("sasl.username", cfg.sasl_username, errstr);
        }
        if (!cfg.sasl_password.empty()) {
            conf->set("sasl.password", cfg.sasl_password, errstr);
        }
    }

    RdKafka::Producer* producer = RdKafka::Producer::create(conf, errstr);
    delete conf;
    if (!producer) {
        throw std::runtime_error("Failed to create Kafka producer: " + errstr);
    }
    return producer;
}

static RdKafka::KafkaConsumer* createConsumer(const curiefense::BridgeConfig::Consumer& cfg) {
    std::string errstr;
    RdKafka::Conf* conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);

    conf->set("bootstrap.servers", cfg.bootstrap_servers, errstr);
    conf->set("group.id", cfg.group_id, errstr);
    conf->set("auto.offset.reset", cfg.auto_offset_reset, errstr);
    conf->set("enable.auto.commit", cfg.enable_auto_commit ? "true" : "false", errstr);
    conf->set("max.poll.records", std::to_string(cfg.max_poll_records), errstr);
    conf->set("session.timeout.ms", std::to_string(cfg.session_timeout_ms), errstr);
    if (!cfg.security_protocol.empty()) {
        conf->set("security.protocol", cfg.security_protocol, errstr);
        if (!cfg.sasl_mechanism.empty()) {
            conf->set("sasl.mechanism", cfg.sasl_mechanism, errstr);
        }
        if (!cfg.sasl_username.empty()) {
            conf->set("sasl.username", cfg.sasl_username, errstr);
        }
        if (!cfg.sasl_password.empty()) {
            conf->set("sasl.password", cfg.sasl_password, errstr);
        }
    }

    RdKafka::KafkaConsumer* consumer = RdKafka::KafkaConsumer::create(conf, errstr);
    delete conf;
    if (!consumer) {
        throw std::runtime_error("Failed to create Kafka consumer: " + errstr);
    }
    return consumer;
}

// ============================================================================
// main
// ============================================================================

int main(int argc, char* argv[]) {
    // 初始化日志
    auto logger = spdlog::stdout_color_mt("console");
    spdlog::set_default_logger(logger);
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");

    std::string config_path = "/etc/curiefense-bridge/curiefense-bridge.yaml";
    if (argc > 1) config_path = argv[1];

    SPDLOG_INFO("Curiefense-Akto Bridge starting (config={})", config_path);

    // 加载配置
    curiefense::BridgeConfig cfg;
    try {
        cfg = curiefense::loadConfig(config_path);
    } catch (const std::exception& e) {
        SPDLOG_ERROR("Config load failed: {}", e.what());
        return 1;
    }

    // 设置日志级别
    if (cfg.observability.log_level == "debug") {
        spdlog::set_level(spdlog::level::debug);
    } else if (cfg.observability.log_level == "trace") {
        spdlog::set_level(spdlog::level::trace);
    }

    // 信号处理
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    try {
        // 1. 初始化 Curiefense 引擎
        curiefense::CuriefenseEngine engine(cfg.curiefense.config_dir);

        // 2. 初始化 AktoAdapter
        curiefense::AktoAdapter adapter(cfg.consumer.input_format);

        // 3. 初始化 WorkerPool
        curiefense::CuriefenseWorkerPool pool(engine, adapter, cfg);
        pool.setAlertGuard(
            cfg.alert_guard.host_collection_map,
            cfg.alert_guard.rate_limit_per_minute,
            cfg.alert_guard.filter_low_severity);

        // 4. 初始化 Kafka Producer (RAII: unique_ptr 确保异常安全)
        auto producer = std::unique_ptr<RdKafka::Producer>(createProducer(cfg.producer));

        // 设置告警输出回调
        pool.setAlertCallback(
            [&producer, &cfg](const std::string& payload, const std::string& key) {
                RdKafka::ErrorCode err = producer->produce(
                    cfg.producer.topic,
                    RdKafka::Topic::PARTITION_UA,
                    RdKafka::Producer::RK_MSG_COPY,
                    const_cast<char*>(payload.data()), payload.size(),
                    key.data(), key.size(),
                    0, nullptr);
                if (err != RdKafka::ERR_NO_ERROR) {
                    SPDLOG_ERROR("Kafka produce failed: {}", RdKafka::err2str(err));
                }
            });

        // 5. 初始化 Kafka Consumer (RAII)
        auto consumer = std::unique_ptr<RdKafka::KafkaConsumer>(createConsumer(cfg.consumer));
        std::vector<std::string> topics = {cfg.consumer.topic};
        RdKafka::ErrorCode err = consumer->subscribe(topics);
        if (err != RdKafka::ERR_NO_ERROR) {
            SPDLOG_ERROR("Failed to subscribe to {}: {}", cfg.consumer.topic,
                         RdKafka::err2str(err));
            return 1;  // consumer/producer 由 unique_ptr 自动释放
        }

        SPDLOG_INFO("Subscribed to topic: {}", cfg.consumer.topic);

        // 6. 启动 WorkerPool
        pool.start();

        // 7. 主消费循环
        SPDLOG_INFO("Curiefense-Akto Bridge running");
        while (g_running.load(std::memory_order_acquire)) {
            auto msg = consumer->consume(cfg.detector.poll_interval_ms);
            if (msg->err() == RdKafka::ERR__TIMED_OUT) {
                continue;
            }
            if (msg->err() != RdKafka::ERR_NO_ERROR) {
                SPDLOG_WARN("Consumer error: {}", RdKafka::err2str(msg->err()));
                continue;
            }

            curiefense::DetectTask task;
            task.payload.assign(static_cast<const char*>(msg->payload()), msg->len());
            task.len = msg->len();
            task.topic = msg->topic_name();
            task.partition = msg->partition();
            task.offset = msg->offset();

            if (!pool.submit(std::move(task))) {
                SPDLOG_WARN("Queue full, dropping message (topic={}, offset={})",
                            task.topic, task.offset);
            }

            // 手动提交 offset
            if (!cfg.consumer.enable_auto_commit) {
                consumer->commitAsync(msg);
            }
        }

        // 8. 优雅关闭 (consumer/producer 由 unique_ptr 自动释放)
        SPDLOG_INFO("Shutting down...");
        pool.stop();
        consumer->close();
        // consumer unique_ptr 析构时自动 delete

        producer->flush(30'000);
        // producer unique_ptr 析构时自动 delete

        SPDLOG_INFO("Curiefense-Akto Bridge stopped");
        return 0;

    } catch (const std::exception& e) {
        SPDLOG_ERROR("Fatal error: {}", e.what());
        return 1;
    }
}
