/**
 * @file alert_builder.cc
 * @brief AlertBuilder 实现 — 构建 MaliciousEventKafkaEnvelope Protobuf
 *
 * 审计修正 (P0-1): 输出 Protobuf 而非 JSON
 * 源码实证: Akto SendMaliciousEventsToBackend.java L37
 *   envelope = MaliciousEventKafkaEnvelope.parseFrom(r.value());
 * JSON 输出会被 InvalidProtocolBufferException 静默丢弃
 */

#include "alert_builder.h"
#include "malicious_event.pb.h"
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <simdjson.h>
#include <spdlog/spdlog.h>
#include <chrono>

namespace curiefense {

std::string AlertBuilder::build(const AnalyzeResult& result, const AktoLog& log) {
    if (!result.hasThreat()) {
        return ""; // 无威胁，不生成告警
    }

    std::string sub_category = mapSubCategory(result.reasons_json);
    std::string severity = mapSeverityFromCuriefense(result);
    std::string filter_id = generateFilterId(result.reasons_json);

    // 审计修正 (P1-1): detected_at 使用毫秒级
    // Akto MaliciousEventMessage.detected_at (proto field 3) 是 int64 毫秒
    // HttpResponseParam.time 是 int32 秒，需要 × 1000 转换
    int64_t detected_at_ms;
    if (log.time > 0) {
        detected_at_ms = static_cast<int64_t>(log.time) * 1000;
    } else {
        detected_at_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    // 审计修正 (P0-1): 输出 Protobuf 而非 JSON
    using namespace threat_detection::message::malicious_event::v1;

    MaliciousEventKafkaEnvelope envelope;
    envelope.set_account_id(log.akto_account_id);
    envelope.set_actor(log.ip);

    auto* evt = envelope.mutable_malicious_event();
    evt->set_actor(log.ip);
    evt->set_filter_id(filter_id);
    evt->set_detected_at(detected_at_ms);
    evt->set_latest_api_ip(log.ip);
    evt->set_latest_api_endpoint(log.path);
    evt->set_latest_api_method(log.method);
    evt->set_latest_api_collection_id(log.api_collection_id);
    evt->set_latest_api_payload(log.request_body);
    evt->set_event_type(EventType::EVENT_TYPE_SINGLE);
    evt->set_category("ApiAbuse");
    evt->set_sub_category(sub_category);
    evt->set_severity(severity);
    // 审计修正 (P2-3): successful_exploit 从 result.blocked 映射
    evt->set_successful_exploit(result.blocked);
    evt->set_label("THREAT");
    evt->set_host(log.host);
    evt->set_status(log.response_status);
    evt->set_context_source("API");

    std::string output;
    envelope.SerializeToString(&output);
    return output;
}

// ============================================================================
// mapSubCategory — 从 reasons_json 提取 Curiefense BlockReason 类型
// ============================================================================

std::string AlertBuilder::mapSubCategory(const std::string& reasons_json) {
    // 解析 reasons_json，提取第一个 BlockReason 的 initiator
    // Curiefense BlockReason 变体 (block_reasons.rs):
    //   GlobalFilter → SM
    //   Acl { tags, stage } → EDE
    //   ContentFilter { ruleid, risk_level } → INJ
    //   Limit { threshold } → RateLimit (SM)
    //   Restriction { tpe, actual, expected } → SM
    simdjson::ondemand::parser parser;
    try {
        auto doc = parser.parse(
            reinterpret_cast<const uint8_t*>(reasons_json.data()),
            reasons_json.size());
        auto arr = doc.get_array();
        for (auto item : arr) {
            // 检查 initiator 类型
            if (item.get_object_value("ruleid").error() == simdjson::SUCCESS) {
                return "SQLInjection"; // ContentFilter → INJ
            }
            if (item.get_object_value("tags").error() == simdjson::SUCCESS) {
                return "AccessControl"; // ACL → EDE
            }
            if (item.get_object_value("threshold").error() == simdjson::SUCCESS) {
                return "RateLimit"; // Limit → SM
            }
            if (item.get_object_value("type").error() == simdjson::SUCCESS) {
                auto type = item.get_string("type");
                if (type.error() == simdjson::SUCCESS) {
                    std::string_view sv = type.value();
                    if (sv == "phase1" || sv == "phase2") return "BotDetection";
                }
                return "SecurityMisconfiguration"; // Restriction → SM
            }
        }
    } catch (...) {}
    return "SecurityMisconfiguration"; // GlobalFilter 兜底
}

// ============================================================================
// mapSeverityFromCuriefense — Curiefense 严重级别映射
// ============================================================================

std::string AlertBuilder::mapSeverityFromCuriefense(const AnalyzeResult& result) {
    // Curiefense 的 blocked/monitored 不同于 WGE 的 syslog 级别
    // blocked (拦截) → HIGH
    // monitored (仅记录) → MEDIUM
    // 其他 → LOW
    if (result.blocked) return "HIGH";
    if (result.monitored) return "MEDIUM";
    return "LOW";
}

// ============================================================================
// generateFilterId — CUR_ + reasons_json 哈希
// ============================================================================

std::string AlertBuilder::generateFilterId(const std::string& reasons_json) {
    uint64_t hash = 0;
    for (char c : reasons_json) {
        hash = hash * 31 + static_cast<unsigned char>(c);
    }
    std::ostringstream oss;
    oss << "CUR_" << std::hex << std::setfill('0') << std::setw(8)
        << (hash & 0xFFFFFFFF);
    return oss.str();
}

// ============================================================================
// escapeJson (用于 headers_json 构建)
// ============================================================================

std::string AlertBuilder::escapeJson(const std::string& s) {
    std::string result;
    result.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n";  break;
            case '\r': result += "\\r";  break;
            case '\t': result += "\\t";  break;
            case '\b': result += "\\b";  break;
            case '\f': result += "\\f";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    result += buf;
                } else {
                    result += static_cast<char>(c);
                }
        }
    }
    return result;
}

} // namespace curiefense
