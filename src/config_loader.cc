/**
 * @file config_loader.cc
 * @brief YAML 配置加载 + 环境变量替换
 */

#include "config.h"
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>
#include <regex>
#include <cstdlib>
#include <stdexcept>

namespace curiefense {

namespace {

// 环境变量替换: ${VAR} 或 ${VAR:-default}
std::string expandEnvVars(const std::string& value) {
    thread_local const std::regex env_pattern(
        R"(\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\})");

    std::string result = value;
    for (int iteration = 0; iteration < 32; ++iteration) {
        std::string working = result;
        if (!std::regex_search(working, env_pattern)) break;

        std::string replaced;
        size_t last_pos = 0;
        auto it = std::sregex_iterator(working.begin(), working.end(), env_pattern);
        auto end = std::sregex_iterator();

        for (; it != end; ++it) {
            auto match = *it;
            replaced += working.substr(last_pos, match.position() - last_pos);

            std::string var_name = match[1].str();
            std::string default_val = match[2].matched ? match[2].str() : "";

            const char* env_val = std::getenv(var_name.c_str());
            if (env_val != nullptr) {
                replaced += env_val;
            } else {
                replaced += default_val;
            }
            last_pos = match.position() + match.length();
        }
        replaced += working.substr(last_pos);
        result = replaced;
    }
    return result;
}

InputFormat parseInputFormat(const std::string& s) {
    if (s == "json") return InputFormat::Json;
    if (s == "protobuf" || s == "proto") return InputFormat::Protobuf;
    return InputFormat::Auto;
}

std::string getStr(const YAML::Node& node, const std::string& key,
                   const std::string& default_val = "") {
    if (node[key] && !node[key].IsNull()) {
        return expandEnvVars(node[key].as<std::string>());
    }
    return default_val;
}

int getInt(const YAML::Node& node, const std::string& key, int default_val = 0) {
    if (node[key] && !node[key].IsNull()) {
        return node[key].as<int>();
    }
    return default_val;
}

bool getBool(const YAML::Node& node, const std::string& key, bool default_val = false) {
    if (node[key] && !node[key].IsNull()) {
        return node[key].as<bool>();
    }
    return default_val;
}

} // anonymous namespace

BridgeConfig loadConfig(const std::string& path) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("Failed to load config '" + path + "': " + e.what());
    }

    BridgeConfig cfg;

    // Kafka
    if (root["kafka"]) {
        const auto& kafka = root["kafka"];
        if (kafka["consumer"]) {
            const auto& c = kafka["consumer"];
            cfg.consumer.bootstrap_servers = getStr(c, "bootstrap_servers", "localhost:9092");
            cfg.consumer.group_id = getStr(c, "group_id", "curiefense-bridge");
            cfg.consumer.topic = getStr(c, "topic", "akto.api.logs2");
            cfg.consumer.input_format = parseInputFormat(getStr(c, "input_format", "auto"));
            cfg.consumer.auto_offset_reset = getStr(c, "auto_offset_reset", "latest");
            cfg.consumer.enable_auto_commit = getBool(c, "enable_auto_commit", false);
            cfg.consumer.max_poll_records = getInt(c, "max_poll_records", 100);
            cfg.consumer.session_timeout_ms = getInt(c, "session_timeout_ms", 30000);
            cfg.consumer.security_protocol = getStr(c, "security_protocol");
            cfg.consumer.sasl_mechanism = getStr(c, "sasl_mechanism");
            cfg.consumer.sasl_username = getStr(c, "sasl_username");
            cfg.consumer.sasl_password = getStr(c, "sasl_password");
        }
        if (kafka["producer"]) {
            const auto& p = kafka["producer"];
            cfg.producer.bootstrap_servers = getStr(p, "bootstrap_servers", "localhost:9092");
            cfg.producer.topic = getStr(p, "topic", "akto.threat_detection.malicious_events");
            cfg.producer.dlq_topic = getStr(p, "dlq_topic", "curiefense-input-dlq");
            cfg.producer.enable_idempotence = getBool(p, "enable_idempotence", true);
            cfg.producer.batch_size = getInt(p, "batch_size", 65536);
            cfg.producer.linger_ms = getInt(p, "linger_ms", 20);
            cfg.producer.retries = getInt(p, "retries", 3);
            cfg.producer.security_protocol = getStr(p, "security_protocol");
            cfg.producer.sasl_mechanism = getStr(p, "sasl_mechanism");
            cfg.producer.sasl_username = getStr(p, "sasl_username");
            cfg.producer.sasl_password = getStr(p, "sasl_password");
        }
    }

    // Curiefense
    if (root["curiefense"]) {
        const auto& cf = root["curiefense"];
        cfg.curiefense.config_dir = getStr(cf, "config_dir", "/etc/curiefense/config");
        cfg.curiefense.enable_rate_limit = getBool(cf, "enable_rate_limit", false);
    }

    // Detector
    if (root["detector"]) {
        const auto& d = root["detector"];
        cfg.detector.worker_threads = getInt(d, "worker_threads", 0);
        cfg.detector.batch_size = getInt(d, "batch_size", 100);
        cfg.detector.max_pending_tasks = getInt(d, "max_pending_tasks", 2000);
        cfg.detector.task_timeout_ms = getInt(d, "task_timeout_ms", 5000);
        cfg.detector.poll_interval_ms = getInt(d, "poll_interval_ms", 100);
    }

    // AlertGuard (审计修正 v3.2)
    if (root["alert_guard"]) {
        const auto& ag = root["alert_guard"];
        cfg.alert_guard.filter_low_severity = getBool(ag, "filter_low_severity", true);
        cfg.alert_guard.rate_limit_per_minute = getInt(ag, "rate_limit_per_minute", 5);
        if (ag["host_collection_map"] && ag["host_collection_map"].IsMap()) {
            const auto& hcm = ag["host_collection_map"];
            for (const auto& kv : hcm) {
                try {
                    std::string host = kv.first.as<std::string>();
                    int32_t col_id = kv.second.as<int32_t>();
                    cfg.alert_guard.host_collection_map[host] = col_id;
                } catch (const YAML::BadConversion& e) {
                    SPDLOG_WARN("config_loader: skipping invalid host_collection_map entry: {}", e.what());
                }
            }
        }
    }

    // Observability
    if (root["observability"]) {
        const auto& obs = root["observability"];
        cfg.observability.log_level = getStr(obs, "log_level", "info");
        cfg.observability.log_format = getStr(obs, "log_format", "json");
        cfg.observability.prometheus_enabled = getBool(obs, "prometheus_enabled", true);
        cfg.observability.prometheus_port = getInt(obs, "prometheus_port", 9101);
    }

    // WAL
    if (root["wal"]) {
        const auto& wal = root["wal"];
        cfg.wal.dir = getStr(wal, "dir", "/var/lib/curiefense-bridge/wal");
        cfg.wal.segment_max_size = getInt(wal, "segment_max_size", 256 * 1024 * 1024);
    }

    SPDLOG_INFO("Config loaded from {}: consumer_topic={}, producer_topic={}, "
                 "worker_threads={}, host_map_entries={}",
                 path, cfg.consumer.topic, cfg.producer.topic,
                 cfg.detector.worker_threads,
                 cfg.alert_guard.host_collection_map.size());

    return cfg;
}

} // namespace curiefense
