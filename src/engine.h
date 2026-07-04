#pragma once

/**
 * @file engine.h
 * @brief CuriefenseEngine — Rust FFI 安全包装
 *
 * 封装 Curiefense Rust FFI 的 C ABI，提供 C++ RAII 安全接口。
 */

#include <cstdint>
#include <memory>
#include <string>

namespace curiefense {

// ── FFI 类型 (与 Rust curiefense_ffi.h 对齐) ──

struct CRawRequest {
    const char* ip;
    const char* method;
    const char* path;
    const char* authority;
    const char* protocol;
    const char* request_id;
    const char* headers_json;
    const char* body;
    size_t body_len;
};

struct CAnalyzeResult {
    uint8_t blocked;
    uint8_t is_blocking;
    uint8_t monitored;
    uint8_t _pad;
    uint32_t action_type;
    const char* reasons_json;
    const char* tags_json;
    const char* stats_json;
    const char* error;
};

extern "C" {
    const char* curiefense_init(const char* config_path);
    CAnalyzeResult curiefense_inspect(const CRawRequest* req);
    void curiefense_free_result(CAnalyzeResult* result);
    void curiefense_free_string(const char* s);
}

// ── C++ 安全包装 ──

/// @brief Curiefense 检测结果 (RAII 管理 FFI 字符串内存)
struct AnalyzeResult {
    bool blocked{false};
    bool is_blocking{false};
    bool monitored{false};
    uint32_t action_type{0};
    std::string reasons_json;
    std::string tags_json;
    std::string stats_json;
    std::string error;

    /// @brief 是否有威胁 (blocked 或 monitored)
    bool hasThreat() const { return blocked || monitored; }
};

/// @brief Curiefense 引擎封装
class CuriefenseEngine {
public:
    /// @brief 初始化引擎 (加载配置)
    /// @param config_dir Curiefense 配置目录路径
    /// @throws std::runtime_error 如果初始化失败
    explicit CuriefenseEngine(const std::string& config_dir);

    ~CuriefenseEngine() = default;

    CuriefenseEngine(const CuriefenseEngine&) = delete;
    CuriefenseEngine& operator=(const CuriefenseEngine&) = delete;

    /// @brief 执行安全检测
    /// @param ip 客户端 IP
    /// @param method HTTP 方法 (GET/POST/...)
    /// @param path 请求路径 (含 query string)
    /// @param authority Host header
    /// @param headers_json 请求头 JSON ({"key":"value1,value2",...})
    /// @param body 请求体
    /// @return AnalyzeResult 检测结果
    AnalyzeResult inspect(
        const std::string& ip,
        const std::string& method,
        const std::string& path,
        const std::string& authority,
        const std::string& headers_json,
        const std::string& body);

    /// @brief 健康检查
    bool healthCheck() const;

private:
    std::string config_dir_;
};

} // namespace curiefense
