#pragma once

/**
 * @file config.h
 * @brief Curiefense Bridge 配置结构体
 */

#include <cstdint>
#include <string>
#include <unordered_map>

namespace curiefense {

enum class InputFormat { Auto, Json, Protobuf };

struct BridgeConfig {
    // Kafka Consumer
    struct Consumer {
        std::string bootstrap_servers{"localhost:9092"};
        std::string group_id{"curiefense-bridge"};
        std::string topic{"akto.api.logs2"};
        InputFormat input_format{InputFormat::Auto};
        std::string auto_offset_reset{"latest"};
        bool enable_auto_commit{false};
        int max_poll_records{100};
        int session_timeout_ms{30000};
        std::string security_protocol;
        std::string sasl_mechanism;
        std::string sasl_username;
        std::string sasl_password;
    } consumer;

    // Kafka Producer
    struct Producer {
        std::string bootstrap_servers{"localhost:9092"};
        std::string topic{"akto.threat_detection.malicious_events"};
        std::string dlq_topic{"curiefense-input-dlq"};
        bool enable_idempotence{true};
        int batch_size{65536};
        int linger_ms{20};
        int retries{3};
        std::string security_protocol;
        std::string sasl_mechanism;
        std::string sasl_username;
        std::string sasl_password;
    } producer;

    // Curiefense
    struct Curiefense {
        std::string config_dir{"/etc/curiefense/config"};
        bool enable_rate_limit{false};
    } curiefense;

    // Detector
    struct Detector {
        int worker_threads{0};  // 0 = auto
        int batch_size{100};
        int max_pending_tasks{2000};
        int task_timeout_ms{5000};
        int poll_interval_ms{100};
    } detector;

    // 告警保护 (审计修正 v3.2: 与 WGE shouldSendAlert 对齐)
    struct AlertGuard {
        bool filter_low_severity{true};
        int32_t rate_limit_per_minute{5};
        std::unordered_map<std::string, int32_t> host_collection_map{};
    } alert_guard;

    // Observability
    struct Observability {
        std::string log_level{"info"};
        std::string log_format{"json"};
        bool prometheus_enabled{true};
        int prometheus_port{9101};
    } observability;

    // WAL
    struct Wal {
        std::string dir{"/var/lib/curiefense-bridge/wal"};
        int64_t segment_max_size{256 * 1024 * 1024};
    } wal;
};

/// @brief 从 YAML 文件加载配置
/// @param path 配置文件路径
/// @return BridgeConfig 配置结构体
/// @throws std::runtime_error 如果配置文件不存在或格式错误
BridgeConfig loadConfig(const std::string& path);

} // namespace curiefense
