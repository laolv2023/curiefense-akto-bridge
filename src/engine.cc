/**
 * @file engine.cc
 * @brief CuriefenseEngine 实现 — Rust FFI 安全包装
 */

#include "engine.h"
#include <spdlog/spdlog.h>
#include <stdexcept>

namespace curiefense {

CuriefenseEngine::CuriefenseEngine(const std::string& config_dir)
    : config_dir_(config_dir) {
    if (config_dir.empty()) {
        throw std::runtime_error("CuriefenseEngine: config_dir is empty");
    }

    SPDLOG_INFO("Initializing Curiefense engine: config_dir={}", config_dir);

    const char* err = curiefense_init(config_dir.c_str());
    if (err != nullptr) {
        std::string error_msg(err);
        curiefense_free_string(err);
        throw std::runtime_error("Curiefense init failed: " + error_msg);
    }

    SPDLOG_INFO("Curiefense engine initialized successfully");
}

AnalyzeResult CuriefenseEngine::inspect(
    const std::string& ip,
    const std::string& method,
    const std::string& path,
    const std::string& authority,
    const std::string& headers_json,
    const std::string& body) {

    // 构建 C ABI 请求
    // 注意: C 字符串指针在 CRawRequest 生命周期内必须有效
    // std::string 的 c_str() 在 string 不被修改时指针稳定
    CRawRequest req{
        .ip = ip.c_str(),
        .method = method.c_str(),
        .path = path.c_str(),
        .authority = authority.c_str(),
        .protocol = "HTTP/1.1",
        .request_id = "",
        .headers_json = headers_json.c_str(),
        .body = body.empty() ? nullptr : body.c_str(),
        .body_len = body.size(),
    };

    // 调用 FFI
    CAnalyzeResult c_result = curiefense_inspect(&req);

    // 转换为 C++ 安全结构 (拷贝字符串)
    AnalyzeResult result;
    result.blocked = c_result.blocked != 0;
    result.is_blocking = c_result.is_blocking != 0;
    result.monitored = c_result.monitored != 0;
    result.action_type = c_result.action_type;
    if (c_result.reasons_json) result.reasons_json = c_result.reasons_json;
    if (c_result.tags_json) result.tags_json = c_result.tags_json;
    if (c_result.stats_json) result.stats_json = c_result.stats_json;
    if (c_result.error) result.error = c_result.error;

    // 释放 FFI 内存
    curiefense_free_result(&c_result);

    if (!result.error.empty()) {
        SPDLOG_WARN("Curiefense inspect error: {}", result.error);
    }

    return result;
}

bool CuriefenseEngine::healthCheck() const {
    // 用一个简单的 GET / 请求测试引擎是否正常
    // 不能调用自身的 inspect (非 const)，用 FFI 直接测试
    CRawRequest req{
        .ip = "127.0.0.1",
        .method = "GET",
        .path = "/",
        .authority = "localhost",
        .protocol = "HTTP/1.1",
        .request_id = "",
        .headers_json = "{}",
        .body = nullptr,
        .body_len = 0,
    };

    CAnalyzeResult c_result = curiefense_inspect(&req);
    bool ok = c_result.error == nullptr;
    curiefense_free_result(&c_result);
    return ok;
}

} // namespace curiefense
