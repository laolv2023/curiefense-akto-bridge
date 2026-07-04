#pragma once

/**
 * @file akto_adapter.h
 * @brief AktoAdapter — Kafka 消息 → AktoLog 中间结构
 *
 * 支持 JSON (akto.api.logs) 和 Protobuf (akto.api.logs2) 双模自动识别。
 */

#include <cstdint>
#include <string>
#include <unordered_map>

namespace curiefense {

enum class InputFormat { Auto, Json, Protobuf };

/// @brief Akto 日志中间结构 (从 Kafka 消息解析)
struct AktoLog {
    std::string ip;
    std::string method;
    std::string path;
    std::string host;
    std::string headers_json;
    std::string request_body;
    std::string response_status;
    std::string akto_account_id;
    int32_t api_collection_id{0};
    int64_t time{0};
    std::string source;
    std::string dest_ip;
    std::string kafka_topic;
    int32_t kafka_partition{0};
    int64_t kafka_offset{0};
};

class AktoAdapter {
public:
    explicit AktoAdapter(InputFormat format = InputFormat::Auto);

    /// @brief Kafka 消息 → AktoLog
    AktoLog adapt(const char* payload, size_t len,
                  const std::string& topic,
                  int32_t partition, int64_t offset);

private:
    InputFormat format_;

    InputFormat resolveFormat(const std::string& topic,
                              const uint8_t* data, size_t len);
    AktoLog parseJson(const uint8_t* data, size_t len);
    AktoLog parseProto(const uint8_t* data, size_t len);
    std::string extractHost(const std::string& headers_json);
};

} // namespace curiefense
