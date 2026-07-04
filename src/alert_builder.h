#pragma once

/**
 * @file alert_builder.h
 * @brief AlertBuilder — CAnalyzeResult + AktoLog → MaliciousEventKafkaEnvelope Protobuf
 */

#include "engine.h"
#include "akto_adapter.h"
#include <string>

namespace curiefense {

class AlertBuilder {
public:
    /// 构建 Akto MaliciousEventKafkaEnvelope Protobuf
    /// 仅当 result.hasThreat() 时生成，否则返回空字符串
    static std::string build(const AnalyzeResult& result, const AktoLog& log);

private:
    static std::string mapSubCategory(const std::string& reasons_json);
    static std::string mapSeverity(const AnalyzeResult& result);
    static std::string generateFilterId(const std::string& reasons_json);
    /// @brief Curiefense 严重级别映射
    /// 与 WGE mapSeverityToAkto 不同: WGE 用 syslog 0-7，Curiefense 用 blocked/monitored
    /// blocked → HIGH, monitored → MEDIUM, 其他 → LOW
    static std::string mapSeverityFromCuriefense(const AnalyzeResult& result);
    static std::string escapeJson(const std::string& s);
};

} // namespace curiefense
