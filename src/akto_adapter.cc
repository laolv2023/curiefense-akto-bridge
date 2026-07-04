/**
 * @file akto_adapter.cc
 * @brief AktoAdapter 实现 — Kafka 消息 → AktoLog
 *
 * 支持两种输入格式:
 * - JSON: akto.api.logs (nginx-middleware JSON 格式)
 * - Protobuf: akto.api.logs2 (HttpResponseParam protobuf)
 *
 * 自动识别: 首字节 '{' (0x7B) → JSON, 否则 → Protobuf
 */

#include "akto_adapter.h"
#include "akto_message.pb.h"  // HttpResponseParam (与 WGE proto/akto_message.proto 一致)
#include <simdjson.h>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <cctype>

namespace curiefense {

// ── JSON 字符串转义 (防止 header value 中的 " 和 \ 导致 JSON 解析失败) ──

static std::string escapeJsonStr(const std::string& s) {
    std::string result;
    result.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n";  break;
            case '\r': result += "\\r";  break;
            case '\t': result += "\\t";  break;
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

// ── map<string, StringList> → JSON 字符串 ──

static std::string headersMapToJson(
    const google::protobuf::Map<std::string, wge::kafka::akto::StringList>& headers) {
    std::ostringstream oss;
    oss << "{";
    bool first = true;
    for (const auto& [key, vals] : headers) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << escapeJsonStr(key) << "\":\"";
        for (int i = 0; i < vals.values_size(); ++i) {
            if (i > 0) oss << ",";
            oss << escapeJsonStr(vals.values(i));
        }
        oss << "\"";
    }
    oss << "}";
    return oss.str();
}

// ── 从 headers JSON 中提取 Host header ──

static std::string extractHostFromJson(const std::string& headers_json) {
    if (headers_json.empty() || headers_json == "{}") return "";
    try {
        simdjson::ondemand::parser parser;
        simdjson::padded_string padded(headers_json);
        auto doc = parser.iterate(padded);
        // 大小写不敏感查找 Host
        auto obj = doc.get_object();
        for (auto field : obj) {
            std::string_view key = field.unescaped_key().value();
            // 转小写比较
            std::string lower_key(key);
            for (auto& c : lower_key) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lower_key == "host") {
                std::string_view val = field.value().get_string().value();
                return std::string(val);
            }
        }
    } catch (...) {}
    return "";
}

// ============================================================================
// AktoAdapter 实现
// ============================================================================

AktoAdapter::AktoAdapter(InputFormat format) : format_(format) {}

AktoLog AktoAdapter::adapt(const char* payload, size_t len,
                            const std::string& topic,
                            int32_t partition, int64_t offset) {
    auto fmt = resolveFormat(topic,
        reinterpret_cast<const uint8_t*>(payload), len);
    AktoLog log;
    try {
        log = (fmt == InputFormat::Protobuf)
            ? parseProto(reinterpret_cast<const uint8_t*>(payload), len)
            : parseJson(reinterpret_cast<const uint8_t*>(payload), len);
    } catch (const std::exception& e) {
        SPDLOG_WARN("AktoAdapter parse failed: {}", e.what());
        log.ip = "0.0.0.0";
        log.method = "GET";
        log.path = "/";
    }
    log.kafka_topic = topic;
    log.kafka_partition = partition;
    log.kafka_offset = offset;
    return log;
}

InputFormat AktoAdapter::resolveFormat(const std::string& topic,
                                        const uint8_t* data, size_t len) {
    if (format_ != InputFormat::Auto) return format_;
    // Auto: 首字节判断
    // JSON 以 '{' (0x7B) 开头; Protobuf 以 field tag 开头
    if (len > 0 && data[0] == '{') return InputFormat::Json;
    return InputFormat::Protobuf;
}

// ── Protobuf 路径 (默认, 高性能) ──

AktoLog AktoAdapter::parseProto(const uint8_t* data, size_t len) {
    wge::kafka::akto::HttpResponseParam pb;
    if (!pb.ParseFromArray(data, static_cast<int>(len))) {
        throw std::runtime_error("Protobuf parse failed");
    }

    AktoLog log;
    log.ip = pb.ip();
    log.method = pb.method();
    log.path = pb.path();
    log.request_body = pb.request_payload();
    log.response_status = std::to_string(pb.status_code());
    log.akto_account_id = pb.akto_account_id();
    log.time = pb.time();
    log.source = pb.source();
    log.dest_ip = pb.dest_ip();

    // 审计修正 (P0-2): api_collection_id 从 akto_vxlan_id 解析
    // 源码实证: Akto MaliciousTrafficDetectorTask.java L610
    //   apiCollectionIdStr = httpResponseParamProto.getAktoVxlanId();
    log.api_collection_id = 0;
    try {
        log.api_collection_id = std::stoi(pb.akto_vxlan_id());
    } catch (...) {
        log.api_collection_id = 0;
    }

    // headers: map<string, StringList> → JSON 字符串
    log.headers_json = headersMapToJson(pb.request_headers());
    log.host = extractHostFromJson(log.headers_json);

    return log;
}

// ── JSON 路径 (兼容模式) ──

AktoLog AktoAdapter::parseJson(const uint8_t* data, size_t len) {
    AktoLog log;
    simdjson::ondemand::parser parser;
    simdjson::padded_string padded(reinterpret_cast<const char*>(data), len);
    auto doc = parser.iterate(padded);

    // 提取字段 (simdjson ondemand API)
    auto get_str = [&](const char* key) -> std::string {
        try {
            auto val = doc[key].get_string();
            if (val.error() == simdjson::SUCCESS) {
                return std::string(std::string_view(val.value()));
            }
        } catch (...) {}
        return "";
    };

    log.method = get_str("method");
    log.path = get_str("path");
    log.ip = get_str("ip");
    log.akto_account_id = get_str("akto_account_id");
    log.source = get_str("source");
    log.dest_ip = get_str("dest_ip");
    log.request_body = get_str("requestPayload");
    log.response_status = get_str("statusCode");

    // time
    try {
        auto val = doc["time"].get_string();
        if (val.error() == simdjson::SUCCESS) {
            log.time = std::stoll(std::string(std::string_view(val.value())));
        }
    } catch (...) {}

    // 审计修正 (P0-2): api_collection_id 从 akto_vxlan_id 解析
    auto ac = doc["akto_vxlan_id"].get_string();
    if (ac.error() == simdjson::SUCCESS) {
        try { log.api_collection_id = std::stoi(
            std::string(std::string_view(ac.value()))); } catch(...) {}
    }

    // headers
    log.headers_json = get_str("requestHeaders");
    if (log.headers_json.empty()) log.headers_json = "{}";
    log.host = extractHostFromJson(log.headers_json);

    return log;
}

} // namespace curiefense
