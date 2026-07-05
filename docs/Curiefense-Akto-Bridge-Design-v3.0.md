# Curiefense-Akto Bridge 详细设计方案

> 项目: curiefense-akto-bridge  
> 日期: 2026-07-04  
> 版本: v3.2 (审计修订版 — 对齐 WGE 7a1f508)
> 架构: 完全复用 WGE 基础设施 + Curiefense Rust FFI
> 语言: C++23 + Rust FFI
> 输入: akto.api.logs (JSON) / akto.api.logs2 (Protobuf) — 双模自动识别
> 输出: akto.threat_detection.malicious_events (MaliciousEventKafkaEnvelope **Protobuf**) — 与 Akto SendMaliciousEventsToBackend 消费格式一致

---

## 目录

1. [设计目标](#1-设计目标)
2. [架构设计](#2-架构设计)
3. [数据流](#3-数据流)
4. [Rust FFI 层](#4-rust-ffi-层)
5. [C++ Bridge 层](#5-c-bridge-层)
6. [Akto 适配层](#6-akto-适配层)
7. [告警构建层](#7-告警构建层)
8. [配置系统](#8-配置系统)
9. [项目结构](#9-项目结构)
10. [CMakeLists.txt](#10-cmakeliststxt)
11. [Dockerfile](#11-dockerfile)
12. [docker-compose.yml](#12-docker-composeyml)
13. [配置文件](#13-配置文件)
14. [测试方案](#14-测试方案)
15. [部署方案](#15-部署方案)
16. [开发计划](#16-开发计划)

---

## 1. 设计目标

### 1.1 核心目标

将 Curiefense WAF 引擎（Rust）集成进 Akto API 安全平台，与 WGE 引擎并行运行。

### 1.2 设计原则

| 原则 | 说明 |
|---|---|
| **复用 WGE 基础设施** | Kafka/WAL/Metrics/ConfigLoader 从 wge 项目提取为 `wge_common` 库，直接链接（**审计修正**: WGE 当前库名为 `wge_kafka_detector_core`，需先执行 §2.2 库化改造） |
| **仅替换检测引擎** | WGE Engine → Curiefense FFI |
| **输入与 WGE 对齐** | 支持 `akto.api.logs` (JSON) + `akto.api.logs2` (Protobuf)，默认 Protobuf |
| **输出 Protobuf (审计修正)** | `MaliciousEventKafkaEnvelope` **Protobuf** → `akto.threat_detection.malicious_events` Topic。源码实证: `SendMaliciousEventsToBackend.java` L37 `MaliciousEventKafkaEnvelope.parseFrom(r.value())` |
| **零改动 Akto** | 不修改 Akto 源码 |

### 1.3 与 WGE 的关系

```
                  Akto Kafka
                      │
           ┌──────────┼──────────┐
           │          │          │
     akto.api.logs    │    akto.api.logs2
      (JSON)          │     (Protobuf)
           │          │          │
     ┌─────┴────┐     │    ┌─────┴────┐
     │   WGE    │     │    │ Curiefense│
     │ Detector │     │    │  Bridge  │
     └─────┬────┘     │    └─────┬────┘
           │          │          │
           └──────────┼──────────┘
                      ↓
         akto.threat_detection.malicious_events
          (MaliciousEventKafkaEnvelope Protobuf)
                      │
              Akto Dashboard
           (WGE_ / CUR_ 前缀区分来源)
```

---

## 2. 架构设计

### 2.1 整体架构

```
┌──────────────────────────────────────────────────────────────┐
│                  curiefense-akto-bridge                       │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─ 复用 WGE 基础设施 (wge_common 库) ────────────────────┐  │
│  │                                                        │  │
│  │  KafkaConsumer          KafkaProducer    DLQ           │  │
│  │  (librdkafka)           (librdkafka)     (librdkafka)  │  │
│  │  Topic: akto.api.logs2  Topic: akto.threat             │  │
│  │                         _detection.malicious           │  │
│  │                                                        │  │
│  │  WalWriter + WalRelay     Metrics (Prometheus)         │  │
│  │  (告警持久化 + 补发)        (7 个原子计数器)             │  │
│  │                                                        │  │
│  │  ConfigLoader (YAML + 环境变量替换)                     │  │
│  │  Logger (spdlog)                                       │  │
│  │  SignalHandler (SIGTERM/SIGINT 优雅关闭)                │  │
│  └────────────────────────────────────────────────────────┘  │
│                       │                                       │
│  ┌─ 新增代码 (~730 行) ────────────────────────────────────┐  │
│  │                                                        │  │
│  │  AktoAdapter (350 行)                                  │  │
│  │  ├─ Protobuf 路径: HttpResponseParam → AktoLog          │  │
│  │  ├─ JSON 路径: simdjson → AktoLog                       │  │
│  │  └─ Auto 模式: 首字节判断格式                            │  │
│  │  ↓                                                    │  │
│  │  CuriefenseEngine (100 行)                             │  │
│  │  ├─ curiefense_init(config_path)                       │  │
│  │  ├─ AktoLog → CRawRequest                              │  │
│  │  ├─ curiefense_inspect(&req) → CAnalyzeResult           │  │
│  │  └─ curiefense_free_result(&result)                    │  │
│  │  ↓                                                    │  │
│  │  AlertBuilder (175 行)                                │  │
│  │  └─ CAnalyzeResult + AktoLog → MaliciousEvent Protobuf   │  │
│  │     (与 WGE serializeAlert 输出格式完全一致)              │  │
│  │  ↓                                                    │  │
│  │  CuriefenseWorkerPool (200 行)                        │  │
│  │  ├─ 有界队列 + N 个 worker 线程                         │  │
│  │  └─ shouldSendAlert (审计修正 v3.2):                    │  │
│  │     ├─ 告警分级过滤 (丢弃 LOW/RateLimit)               │  │
│  │     ├─ collection_id=0 兜底 (Host→CollectionID)        │  │
│  │     └─ IP 级限流 (≤N条/分钟, atomic call_counter)      │  │
│  │                                                        │  │
│  │  main.cc (50 行, 复制 wge main.cc 改 4 处)              │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
         │                                    │
         ↓                                    ↓
   libcuriefense_ffi.so                    wge_common.a
   (Rust FFI, 来自 curiefense-ffi crate)   (从 wge 项目提取)
```

### 2.2 WGE 库化改造

WGE 项目的 `wge_kafka_detector_core` 依赖 `wge::wge`（WGE SDK），Curiefense Bridge 不需要此依赖。需将 WGE 基础设施分离为独立的 `wge_common` 库：

```cmake
# wge/CMakeLists.txt 修改 — 新增 wge_common 库

add_library(wge_common STATIC
    src/kafka/consumer.cc
    src/kafka/producer.cc
    src/kafka/dlq.cc
    src/wal/wal_writer.cc
    src/wal/wal_relay.cc
    src/config/config_loader.cc
    src/metrics/metrics.cc
)
target_include_directories(wge_common PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}
)
target_link_libraries(wge_common PUBLIC
    RdKafka::rdkafka
    protobuf::libprotobuf
    simdjson::simdjson
    yaml-cpp
    spdlog::spdlog
)
if(prometheus-cpp_FOUND)
    target_link_libraries(wge_common PRIVATE prometheus-cpp::core prometheus-cpp::pull)
endif()

install(TARGETS wge_common ARCHIVE DESTINATION lib)
install(DIRECTORY src/ DESTINATION include/wge FILES_MATCHING PATTERN "*.h")
install(FILES ${CMAKE_BINARY_DIR}/http_access.pb.h DESTINATION include/wge)
```

Curiefense Bridge 只链接 `wge_common`，不链接 `wge_kafka_detector_core`（避免传递依赖 WGE SDK）。

---

## 3. 数据流

### 3.1 完整数据流

```
Kafka: akto.api.logs2 (Protobuf) 或 akto.api.logs (JSON)
  │
  │  RdKafka::Message
  ↓
┌─────────────────────────────────────────────────────┐
│ AktoAdapter::adapt(msg)                             │
│                                                     │
│  ┌─ Auto 格式判断 ──────────────────────────────┐   │
│  │  payload[0] == '{' (0x7B) → JSON 路径        │   │
│  │  否则 → Protobuf 路径                         │   │
│  └───────────────────────────────────────────────┘   │
│                                                     │
│  Protobuf 路径:                                     │
│    HttpResponseParam::ParseFromArray()              │
│    pb.method() → log.method                         │
│    pb.path() → log.path                             │
│    pb.request_headers() → log.headers_json          │
│    pb.ip() → log.ip                                 │
│    pb.request_payload() → log.request_body          │
│    pb.akto_account_id() → log.akto_account_id       │
│    pb.akto_vxlan_id() → stoi → log.api_collection_id (审计修正: 与 Akto L610 一致) │
│                                                     │
│  JSON 路径:                                         │
│    simdjson::ondemand::parser.parse()               │
│    doc["method"] → log.method                       │
│    doc["path"] → log.path                           │
│    doc["requestHeaders"] → log.headers_json         │
│    doc["ip"] → log.ip                               │
│    doc["requestPayload"] → log.request_body         │
│    doc["akto_account_id"] → log.akto_account_id     │
│    doc["akto_vxlan_id"] → stoi → log.api_collection_id (审计修正) │
│                                                     │
│  输出: AktoLog (统一中间结构)                        │
└──────────────────────┬──────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────┐
│ CuriefenseEngine::inspect(log)                      │
│                                                     │
│  AktoLog → CRawRequest:                             │
│    req.ip = log.ip                                  │
│    req.method = log.method                          │
│    req.path = log.path                              │
│    req.authority = extractHost(log.headers_json)    │
│    req.headers_json = log.headers_json              │
│    req.body = log.request_body                      │
│                                                     │
│  FFI 调用: curiefense_inspect(&req)                 │
│    → CAnalyzeResult                                 │
│    { blocked, is_blocking, monitored,               │
│      action_type, reasons_json, tags_json,          │
│      stats_json, error }                            │
│                                                     │
│  释放: curiefense_free_result(&result)              │
└──────────────────────┬──────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────┐
│ AlertBuilder::build(result, log)                    │
│                                                     │
│  仅当 result.blocked || result.monitored 时生成告警  │
│                                                     │
│  sub_category = mapInitiator(result.reasons_json)   │
│  severity = mapSeverity(result)                     │
│  filter_id = "CUR_" + hash(result.reasons_json)     │
│  successful_exploit = result.blocked (审计修正)      │
│                                                     │
│  输出: MaliciousEventKafkaEnvelope Protobuf         │
│  (Akto SendMaliciousEventsToBackend 消费格式)        │
└──────────────────────┬──────────────────────────────┘
                       │
                       ↓
Kafka: akto.threat_detection.malicious_events
  │
  ↓
Akto Dashboard (SendMaliciousEventsToBackend 消费)
```

### 3.2 AktoLog 中间结构

```cpp
struct AktoLog {
    // 请求信息
    std::string ip;
    std::string method;
    std::string path;               // 含 query string
    std::string host;
    std::string headers_json;       // {"key":"value",...}
    std::string request_body;
    std::string response_status;

    // Akto 元数据
    std::string akto_account_id;
    int32_t api_collection_id{0};
    int64_t time{0};                // Unix 秒
    std::string source;             // "MIRRORING" 等
    std::string dest_ip;

    // Kafka 元数据
    std::string kafka_topic;
    int32_t kafka_partition{0};
    int64_t kafka_offset{0};
};
```

### 3.3 输出: MaliciousEventKafkaEnvelope Protobuf (审计修正)

> **审计修正 (P0-1)**: Akto `SendMaliciousEventsToBackend.java` L37 用 `MaliciousEventKafkaEnvelope.parseFrom(r.value())` 消费 **Protobuf** 格式。
> 原方案输出 JSON 会被 `InvalidProtocolBufferException` 静默丢弃。

使用 Akto 官方 proto 定义 (`protobuf/threat_detection/message/malicious_event/v1/message.proto`)：

```protobuf
// 从 Akto 仓库复制，不做修改
message MaliciousEventKafkaEnvelope {
  string account_id = 1;
  string actor = 2;
  MaliciousEventMessage malicious_event = 3;
}

message MaliciousEventMessage {
  string actor = 1;
  string filter_id = 2;
  int64 detected_at = 3;        // 毫秒级
  string latest_api_ip = 4;
  string latest_api_endpoint = 5;
  string latest_api_method = 6;
  int32 latest_api_collection_id = 7;
  string latest_api_payload = 8;
  EventType event_type = 9;
  string category = 10;
  string sub_category = 11;
  string severity = 12;
  string type = 13;
  Metadata metadata = 14;
  bool successful_exploit = 15;
  string label = 16;
  string host = 17;
  string status = 18;
  string context_source = 19;  // API, MCP, GEN_AI, AGENTIC, DAST, ENDPOINT
  string session_id = 20;
  repeated OwaspCategory owasp_categories = 21;
}
```

**与 WGE 的唯一区别**: `filter_id` 前缀 `CUR_`（WGE 用 `WGE_`），用于运维区分告警来源。

> **注意**: WGE 当前同样输出 JSON 而非 Protobuf，这是 WGE 也需要修复的问题。本方案先行修正。

---

## 4. Rust FFI 层

### 4.1 源码实证依据

| API | 源码位置 | 说明 |
|---|---|---|
| `inspect_generic_request_map<GH>` | `lib.rs` L77 | 泛型函数，需具体化 |
| `DynGrasshopper` | `grasshopper.rs` L128 | 空实现，FFI 用此具体化泛型 |
| `RawRequest<'a>` | `utils/mod.rs` L668 | ipstr/headers/meta/mbody |
| `RequestMeta::from_map` | `utils/mod.rs` L348 | 从 HashMap 构造 |
| `Logs::default()` | `logs.rs` L60 | Default trait |
| `CONFIGS` (lazy_static) | `config/mod.rs` L70-71 | 路径硬编码 `/cf-config/current/config` |
| `reload_config(basepath, filenames)` | `config/mod.rs` L145 | 运行时重载配置 |
| `AnalyzeResult` | `interface/mod.rs` L106 | decision/tags/rinfo/stats |
| `Decision::blocked()` | `interface/mod.rs` L151 | 检查非 Monitor/Skip |
| `Decision::is_blocking()` | `interface/mod.rs` L147 | maction.is_blocking() |
| `ActionType` | `interface/mod.rs` L703 | Skip/Monitor/Block |
| `Stats` (无 Serialize) | `interface/stats.rs` L108 | 仅 Debug/Clone，需手动序列化 |
| `BlockReason` (impl Serialize) | `block_reasons.rs` L132 | 手动实现 |
| `Tags` (impl Serialize) | `tagging.rs` L293 | 手动实现 |

### 4.2 crate 结构

```
curiefense/
├── curiefense/              # 现有 Rust crate
├── curiefense-ffi/          # 新增 FFI crate
│   ├── Cargo.toml
│   ├── include/
│   │   └── curiefense_ffi.h # C 头文件 (手动编写)
│   └── src/
│       └── lib.rs
```

### 4.3 Cargo.toml

```toml
[package]
name = "curiefense-ffi"
version = "0.1.0"
edition = "2018"

[lib]
crate-type = ["cdylib", "staticlib"]

[dependencies]
curiefense = { path = "../curiefense" }
serde_json = "1.0"
```

### 4.4 C 头文件 (curiefense_ffi.h)

```c
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* ip;
    const char* method;
    const char* path;
    const char* authority;
    const char* protocol;
    const char* request_id;
    const char* headers_json;
    const char* body;
    size_t body_len;
} CRawRequest;

typedef struct {
    uint8_t blocked;
    uint8_t is_blocking;
    uint8_t monitored;
    uint8_t _pad;
    uint32_t action_type;
    const char* reasons_json;
    const char* tags_json;
    const char* stats_json;
    const char* error;
} CAnalyzeResult;

const char* curiefense_init(const char* config_path);
CAnalyzeResult curiefense_inspect(const CRawRequest* req);
void curiefense_free_result(CAnalyzeResult* result);
void curiefense_free_string(const char* s);

#ifdef __cplusplus
}
#endif
```

### 4.5 FFI 实现 (src/lib.rs)

```rust
use curiefense::{
    inspect_generic_request_map, AnalyzeResult,
};
use curiefense::config::raw::RawActionType;
use curiefense::grasshopper::DynGrasshopper;
use curiefense::interface::ActionType;
use curiefense::logs::Logs;
use curiefense::utils::{RawRequest, RequestMeta};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

// ── C ABI 结构体 ──

#[repr(C)]
pub struct CRawRequest {
    pub ip: *const c_char,
    pub method: *const c_char,
    pub path: *const c_char,
    pub authority: *const c_char,
    pub protocol: *const c_char,
    pub request_id: *const c_char,
    pub headers_json: *const c_char,
    pub body: *const c_char,
    pub body_len: usize,
}

#[repr(C)]
pub struct CAnalyzeResult {
    pub blocked: u8,
    pub is_blocking: u8,
    pub monitored: u8,
    pub _pad: u8,
    pub action_type: u32,
    pub reasons_json: *const c_char,
    pub tags_json: *const c_char,
    pub stats_json: *const c_char,
    pub error: *const c_char,
}

// ── 辅助函数 ──

fn cstr_to_string(p: *const c_char) -> Option<String> {
    if p.is_null() { return None; }
    unsafe { Some(CStr::from_ptr(p).to_string_lossy().into_owned()) }
}

fn safe_cstring(s: String) -> *const c_char {
    CString::new(s)
        .unwrap_or_else(|_| CString::new("").unwrap())
        .into_raw()
}

fn error_result(msg: &str) -> CAnalyzeResult {
    CAnalyzeResult {
        blocked: 0, is_blocking: 0, monitored: 0, _pad: 0,
        action_type: 0,
        reasons_json: ptr::null(),
        tags_json: ptr::null(),
        stats_json: ptr::null(),
        error: safe_cstring(msg.to_string()),
    }
}

// ── 初始化函数 ──

/// 加载 Curiefense 配置。
/// CONFIGS 全局变量路径硬编码为 /cf-config/current/config (config/mod.rs L60)。
/// 此函数通过 reload_config() 从指定路径加载配置。
#[no_mangle]
pub extern "C" fn curiefense_init(config_path: *const c_char) -> *const c_char {
    let path = match cstr_to_string(config_path) {
        Some(p) => p,
        None => return ptr::null(), // 使用默认路径
    };
    curiefense::config::reload_config(&path, Vec::new());
    ptr::null() // null = 成功
}

// ── 核心检测函数 ──

/// 执行 Curiefense WAF 检测。
/// 使用 DynGrasshopper (grasshopper.rs L128) 具体化泛型参数。
#[no_mangle]
pub extern "C" fn curiefense_inspect(req: *const CRawRequest) -> CAnalyzeResult {
    if req.is_null() {
        return error_result("Null request pointer");
    }

    let req_ref = unsafe { &*req };

    // 构造 IP
    let ipstr = cstr_to_string(req_ref.ip)
        .unwrap_or_else(|| "0.0.0.0".to_string());

    // 解析 headers JSON
    let headers: HashMap<String, String> = cstr_to_string(req_ref.headers_json)
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    // 构造 RequestMeta (使用 from_map, utils/mod.rs L348)
    let mut meta_map = HashMap::new();
    let method = match cstr_to_string(req_ref.method) {
        Some(m) => { meta_map.insert("method".to_string(), m); }
        None => return error_result("Missing required field: method"),
    };
    let _ = method;
    if let Some(path) = cstr_to_string(req_ref.path) {
        meta_map.insert("path".to_string(), path);
    } else {
        return error_result("Missing required field: path");
    }
    if let Some(a) = cstr_to_string(req_ref.authority) {
        meta_map.insert("authority".to_string(), a);
    }
    if let Some(rid) = cstr_to_string(req_ref.request_id) {
        meta_map.insert("x-request-id".to_string(), rid);
    }
    if let Some(p) = cstr_to_string(req_ref.protocol) {
        meta_map.insert("protocol".to_string(), p);
    }

    let meta = match RequestMeta::from_map(meta_map) {
        Ok(m) => m,
        Err(e) => return error_result(&format!("RequestMeta error: {}", e)),
    };

    // 构造 body
    let body_bytes: Vec<u8> = if !req_ref.body.is_null() && req_ref.body_len > 0 {
        unsafe {
            std::slice::from_raw_parts(
                req_ref.body as *const u8, req_ref.body_len
            ).to_vec()
        }
    } else {
        Vec::new()
    };

    let raw = RawRequest {
        ipstr,
        headers,
        meta,
        mbody: if body_bytes.is_empty() { None } else { Some(&body_bytes[..]) },
    };

    // 调用检测引擎 — DynGrasshopper 具体化泛型
    let gh = DynGrasshopper {};
    let mut logs = Logs::default();
    let result: AnalyzeResult = inspect_generic_request_map(
        Some(&gh),
        raw,
        &mut logs,
        None, None,
        HashMap::new(),
    );

    // 构造输出
    let blocked = result.decision.blocked();
    let is_blocking = result.decision.is_blocking();
    let monitored = result.decision.reasons.iter().any(|r| {
        matches!(r.action, RawActionType::Monitor)
    });
    let action_type: u32 = match &result.decision.maction {
        None => 0,
        Some(action) => match action.atype {
            ActionType::Monitor => 1,
            ActionType::Skip => 3,
            _ => 2, // Block
        }
    };

    // 序列化 — BlockReason 和 Tags 实现了 Serialize
    let reasons_json = serde_json::to_string(&result.decision.reasons)
        .unwrap_or_else(|_| "[]".to_string());
    let tags_json = serde_json::to_string(&result.tags)
        .unwrap_or_else(|_| "{}".to_string());

    // Stats 未实现 Serialize (stats.rs L108), 手动构造
    let stats_json = format!(
        r#"{{"processing_stage":{},"revision":"{}"}}"#,
        result.stats.processing_stage,
        result.stats.revision.replace('"', "\\\"")
    );

    CAnalyzeResult {
        blocked: if blocked { 1 } else { 0 },
        is_blocking: if is_blocking { 1 } else { 0 },
        monitored: if monitored { 1 } else { 0 },
        _pad: 0,
        action_type,
        reasons_json: safe_cstring(reasons_json),
        tags_json: safe_cstring(tags_json),
        stats_json: safe_cstring(stats_json),
        error: ptr::null(),
    }
}

// ── 内存释放函数 ──

#[no_mangle]
pub extern "C" fn curiefense_free_result(result: *mut CAnalyzeResult) {
    if result.is_null() { return; }
    unsafe {
        let r = &mut *result;
        if !r.reasons_json.is_null() {
            drop(CString::from_raw(r.reasons_json as *mut c_char));
            r.reasons_json = ptr::null();
        }
        if !r.tags_json.is_null() {
            drop(CString::from_raw(r.tags_json as *mut c_char));
            r.tags_json = ptr::null();
        }
        if !r.stats_json.is_null() {
            drop(CString::from_raw(r.stats_json as *mut c_char));
            r.stats_json = ptr::null();
        }
        if !r.error.is_null() {
            drop(CString::from_raw(r.error as *mut c_char));
            r.error = ptr::null();
        }
    }
}

#[no_mangle]
pub extern "C" fn curiefense_free_string(s: *const c_char) {
    if s.is_null() { return; }
    unsafe { drop(CString::from_raw(s as *mut c_char)); }
}
```

### 4.6 配置路径处理

Curiefense `CONFIGS` 路径硬编码为 `/cf-config/current/config`。Dockerfile 中创建 symlink：

```dockerfile
RUN mkdir -p /cf-config/current && \
    ln -s /etc/curiefense/config /cf-config/current/config
```

### 4.7 异步运行时说明

`inspect_generic_request_map` 内部调用 `async_std::task::block_on()`。如果启用 Rate Limit（依赖 Redis），可能死锁。**推荐禁用 Rate Limit**（不配置 `ratelimits.json`）。

### 4.8 BlockReason 完整映射

| Initiator 变体 | 源码位置 | Akto sub_category | severity |
|---|---|---|---|
| `GlobalFilter` | `block_reasons.rs` L23 | `SM` | MEDIUM |
| `Acl { tags, stage }` | L24-27 | `EDE` | HIGH |
| `ContentFilter { ruleid, risk_level }` | L28-31 | `INJ` | HIGH |
| `Limit { threshold }` | L32-35 | `SM` | MEDIUM |
| `Restriction { tpe, actual, expected }` | L36-41 | `SM` | LOW |
| `Phase01Fail(String)` | L42 | `BOT` | MEDIUM |
| `Phase02` | L43 | `BOT` | HIGH |

---

## 5. C++ Bridge 层

### 5.1 头文件 (engine.h)

```cpp
#pragma once
#include <cstdint>
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

struct AnalyzeResult {
    bool blocked;
    bool is_blocking;
    bool monitored;
    uint32_t action_type;
    std::string reasons_json;
    std::string tags_json;
    std::string stats_json;
    std::string error;

    bool hasThreat() const { return blocked || monitored; }
};

// ── CuriefenseEngine ──

class CuriefenseEngine {
public:
    explicit CuriefenseEngine(const std::string& config_dir);
    ~CuriefenseEngine();
    CuriefenseEngine(const CuriefenseEngine&) = delete;
    CuriefenseEngine& operator=(const CuriefenseEngine&) = delete;

    AnalyzeResult inspect(
        const std::string& ip,
        const std::string& method,
        const std::string& path,
        const std::string& authority,
        const std::string& headers_json,
        const std::string& body);

    bool healthCheck() const;

private:
    std::string config_dir_;
};

} // namespace curiefense
```

### 5.2 实现 (engine.cc)

```cpp
#include "engine.h"
#include <spdlog/spdlog.h>

namespace curiefense {

CuriefenseEngine::CuriefenseEngine(const std::string& config_dir)
    : config_dir_(config_dir) {
    SPDLOG_INFO("CuriefenseEngine config_dir={}", config_dir);
    const char* err = curiefense_init(config_dir.c_str());
    if (err) {
        SPDLOG_WARN("Curiefense init warning: {}", err);
        curiefense_free_string(err);
    }
}

CuriefenseEngine::~CuriefenseEngine() = default;

AnalyzeResult CuriefenseEngine::inspect(
    const std::string& ip,
    const std::string& method,
    const std::string& path,
    const std::string& authority,
    const std::string& headers_json,
    const std::string& body) {

    CRawRequest req{};
    req.ip = ip.c_str();
    req.method = method.c_str();
    req.path = path.c_str();
    req.authority = authority.empty() ? nullptr : authority.c_str();
    req.protocol = "HTTP/1.1";
    req.request_id = nullptr;
    req.headers_json = headers_json.c_str();
    req.body = body.empty() ? nullptr : body.data();
    req.body_len = body.size();

    CAnalyzeResult c_result = curiefense_inspect(&req);

    AnalyzeResult result;
    result.blocked = c_result.blocked;
    result.is_blocking = c_result.is_blocking;
    result.monitored = c_result.monitored;
    result.action_type = c_result.action_type;
    if (c_result.reasons_json) result.reasons_json = c_result.reasons_json;
    if (c_result.tags_json) result.tags_json = c_result.tags_json;
    if (c_result.stats_json) result.stats_json = c_result.stats_json;
    if (c_result.error) result.error = c_result.error;

    curiefense_free_result(&c_result);

    if (!result.error.empty()) {
        SPDLOG_WARN("Curiefense inspect error: {}", result.error);
    }
    return result;
}

bool CuriefenseEngine::healthCheck() const {
    auto result = inspect("127.0.0.1", "GET", "/", "localhost", "{}", "");
    return result.error.empty();
}

} // namespace curiefense
```

---

## 6. Akto 适配层

### 6.1 头文件 (akto_adapter.h)

```cpp
#pragma once
#include <string>
#include <memory>

namespace curiefense {

enum class InputFormat { Auto, Json, Protobuf };

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

    /// Kafka 消息 → AktoLog
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
```

### 6.2 实现 (akto_adapter.cc)

```cpp
#include "akto_adapter.h"
#include "akto_message.pb.h"  // HttpResponseParam (与 WGE proto/akto_message.proto 一致)
#include <simdjson.h>
#include <spdlog/spdlog.h>

namespace curiefense {

// Host → CollectionID 兜底映射 (与 WGE AktoAdapter 一致)
static const std::unordered_map<std::string, int32_t> HOST_COLLECTION_FALLBACK = {
    {"api.example.com", 1},
    {"admin.example.com", 2},
};

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
        spdlog::warn("AktoAdapter parse failed: {}", e.what());
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
    // 而非 api_collection_id (field 6)
    log.api_collection_id = 0;
    try {
        log.api_collection_id = std::stoi(pb.akto_vxlan_id());
    } catch (...) {
        log.api_collection_id = 0;
    }

    // headers: map<string, StringList> → JSON 字符串
    // (Curiefense FFI 接收 JSON 字符串格式的 headers)
    log.headers_json = headersMapToJson(pb.request_headers());
    log.host = extractHost(log.headers_json);

    // 审计修正 (P2-1): collection_id=0 兜底 (与 WGE AktoAdapter L189-204 一致)
    if (log.api_collection_id == 0) {
        auto it = HOST_COLLECTION_FALLBACK.find(log.host);
        if (it != HOST_COLLECTION_FALLBACK.end()) {
            log.api_collection_id = it->second;
            spdlog::info("[akto_adapter] Collection ID fallback: host={} → id={}",
                         log.host, log.api_collection_id);
        }
    }
    return log;
}

// ── JSON 路径 (兼容模式) ──

AktoLog AktoAdapter::parseJson(const uint8_t* data, size_t len) {
    simdjson::ondemand::parser parser;
    auto doc = parser.parse(data, len);

    AktoLog log;
    log.ip = std::string(std::string_view(
        doc.get_string("ip").value_or("0.0.0.0")));
    log.method = std::string(std::string_view(
        doc.get_string("method").value_or("GET")));
    log.path = std::string(std::string_view(
        doc.get_string("path").value_or("/")));
    log.headers_json = std::string(std::string_view(
        doc.get_string("requestHeaders").value_or("{}")));
    log.request_body = std::string(std::string_view(
        doc.get_string("requestPayload").value_or("")));
    log.response_status = std::string(std::string_view(
        doc.get_string("statusCode").value_or("200")));
    log.akto_account_id = std::string(std::string_view(
        doc.get_string("akto_account_id").value_or("")));
    log.time = std::stoll(std::string(std::string_view(
        doc.get_string("time").value_or("0"))));
    log.source = std::string(std::string_view(
        doc.get_string("source").value_or("")));

    // 审计修正 (P0-2): api_collection_id 从 akto_vxlan_id 解析 (与 Protobuf 路径一致)
    auto ac = doc.get_string("akto_vxlan_id");
    if (ac.error() == simdjson::SUCCESS) {
        try { log.api_collection_id = std::stoi(
            std::string(std::string_view(ac.value()))); } catch(...) {}
    }

    log.host = extractHost(log.headers_json);
    return log;
}

// ── 辅助函数 ──

std::string AktoAdapter::extractHost(const std::string& headers_json) {
    simdjson::ondemand::parser parser;
    try {
        auto doc = parser.parse(
            reinterpret_cast<const uint8_t*>(headers_json.data()),
            headers_json.size());
        // 尝试多种大小写
        for (const char* key : {"Host", "host", "HOST"}) {
            auto v = doc.get_string(key);
            if (v.error() == simdjson::SUCCESS) {
                return std::string(std::string_view(v.value()));
            }
        }
    } catch (...) {}
    return "";
}

} // namespace curiefense
```

### 6.3 headersMapToJson 辅助函数

```cpp
// 在 akto_adapter.cc 中
// 审计修正 (P1-2): 增加 escapeJson 防止 header value 中的 " 和 \ 导致 JSON 解析失败

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

static std::string headersMapToJson(
    const google::protobuf::Map<std::string, wge::kafka::akto::StringList>& headers) {
    // map<string, StringList> → {"key":"value1,value2",...}
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
```

---

## 7. 告警构建层

### 7.1 头文件 (alert_builder.h)

```cpp
#pragma once
#include "engine.h"
#include "akto_adapter.h"
#include "malicious_event.pb.h"  // Akto MaliciousEventKafkaEnvelope (审计修正)
#include <string>

namespace curiefense {

class AlertBuilder {
public:
    /// 构建 Akto MaliciousEventKafkaEnvelope Protobuf (审计修正: JSON → Protobuf)
    /// 仅当 result.hasThreat() 时生成，否则返回空字符串
    static std::string build(const AnalyzeResult& result, const AktoLog& log);

private:
    static std::string mapSubCategory(const std::string& reasons_json);
    static std::string mapSeverity(const AnalyzeResult& result);
    static std::string generateFilterId(const std::string& reasons_json);
    static std::string escapeJson(const std::string& s);  // 仍用于 headers_json 构建
};

} // namespace curiefense
```

### 7.2 实现 (alert_builder.cc)

```cpp
#include "alert_builder.h"
#include <sstream>
#include <iomanip>
#include <simdjson.h>
#include <spdlog/spdlog.h>
#include <chrono>

namespace curiefense {

std::string AlertBuilder::build(const AnalyzeResult& result, const AktoLog& log) {
    if (!result.hasThreat()) {
        return ""; // 无威胁，不生成告警
    }

    std::string sub_category = mapSubCategory(result.reasons_json);
    std::string severity = mapSeverity(result);
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
    // 源码实证: SendMaliciousEventsToBackend.java L37
    //   envelope = MaliciousEventKafkaEnvelope.parseFrom(r.value());
    // JSON 输出会被 InvalidProtocolBufferException 静默丢弃
    using namespace threat_detection::message::malicious_event::v1;

    MaliciousEventKafkaEnvelope envelope;
    envelope.set_account_id(log.akto_account_id);
    envelope.set_actor(log.ip);

    auto* event = envelope.mutable_malicious_event();
    event->set_actor(log.ip);
    event->set_filter_id(filter_id);
    event->set_detected_at(detected_at_ms);
    event->set_latest_api_ip(log.ip);
    event->set_latest_api_endpoint(log.path);
    event->set_latest_api_method(log.method);
    event->set_latest_api_collection_id(log.api_collection_id);
    event->set_latest_api_payload(log.request_body);
    event->set_event_type(EventType::EVENT_TYPE_SINGLE);
    event->set_category("ApiAbuse");
    event->set_sub_category(sub_category);
    event->set_severity(severity);
    // 审计修正 (P2-3): successful_exploit 从 result.blocked 映射，而非硬编码 false
    event->set_successful_exploit(result.blocked);
    event->set_label("THREAT");
    event->set_host(log.host);
    event->set_status(log.response_status);
    event->set_context_source("API");

    std::string output;
    envelope.SerializeToString(&output);
    return output;
}

std::string AlertBuilder::mapSubCategory(const std::string& reasons_json) {
    // 解析 reasons_json，提取第一个 BlockReason 的 initiator
    simdjson::ondemand::parser parser;
    try {
        auto doc = parser.parse(
            reinterpret_cast<const uint8_t*>(reasons_json.data()),
            reasons_json.size());
        // reasons 是 JSON 数组
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

std::string AlertBuilder::mapSeverity(const AnalyzeResult& result) {
    if (result.blocked) return "HIGH";
    if (result.monitored) return "MEDIUM";
    return "LOW";
}

std::string AlertBuilder::generateFilterId(const std::string& reasons_json) {
    // CUR_ + reasons_json 的前 8 位哈希
    uint64_t hash = 0;
    for (char c : reasons_json) {
        hash = hash * 31 + static_cast<unsigned char>(c);
    }
    std::ostringstream oss;
    oss << "CUR_" << std::hex << std::setfill('0') << std::setw(8)
        << (hash & 0xFFFFFFFF);
    return oss.str();
}

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
```

---

## 8. 配置系统

### 8.1 配置结构体

```cpp
// config.h
#pragma once
#include <string>

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
        // SASL
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
        // SASL (同 consumer)
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

    // Observability
    struct Observability {
        std::string log_level{"info"};
        std::string log_format{"json"};
        bool prometheus_enabled{true};
        int prometheus_port{9101};
    } observability;
};

} // namespace curiefense
```

### 8.2 配置加载

复用 WGE 的 `ConfigLoader`（YAML + 环境变量替换），仅需扩展 `BridgeConfig` 结构体的 YAML 解析。

---

## 9. 项目结构

```
curiefense-akto-bridge/
├── CMakeLists.txt
├── curiefense-ffi/                # Rust FFI crate (在 curiefense 仓库中)
│   ├── Cargo.toml
│   ├── include/
│   │   └── curiefense_ffi.h
│   └── src/
│       └── lib.rs
├── proto/
│   ├── akto_message.proto          # HttpResponseParam (复制自 WGE proto/)
│   └── malicious_event.proto       # MaliciousEventKafkaEnvelope (复制自 Akto protobuf/)
├── src/
│   ├── main.cc                    # 入口 (~50 行, 复制 wge main.cc 改 4 处)
│   ├── akto_adapter.h             # 适配层 (~50 行)
│   ├── akto_adapter.cc            # 适配层实现 (~350 行, 审计修正后)
│   ├── engine.h                   # FFI 封装 (~60 行)
│   ├── engine.cc                  # FFI 封装实现 (~70 行)
│   ├── alert_builder.h            # 告警构建 (~25 行)
│   ├── alert_builder.cc           # 告警构建实现 (~150 行, Protobuf 输出)
│   ├── worker_pool.h              # 工作线程池 + shouldSendAlert (~80 行)
│   ├── worker_pool.cc             # 工作线程池实现 + IpRateLimiter (~120 行)
│   ├── config.h                   # 配置结构体 (~50 行)
│   └── config_loader.cc           # 配置加载 (~50 行)
├── config/
│   └── curiefense-bridge.yaml
├── curiefense-config/             # Curiefense WAF 规则
│   └── json/
│       ├── securitypolicy.json
│       ├── contentfilter-rules.json
│       └── ...
├── tests/
│   ├── test_akto_adapter.cc
│   ├── test_alert_builder.cc
│   └── test_e2e.cc
├── Dockerfile
└── docker-compose.yml
```

### 9.1 代码量统计

| 组件 | 行数 | 来源 |
|---|---|---|
| main.cc | ~50 | 复制 wge, 改 4 处 |
| akto_adapter.h + .cc | ~400 | 新写 (审计修正: +兜底逻辑 +escapeJson) |
| engine.h + .cc | ~130 | 新写 |
| alert_builder.h + .cc | ~175 | 新写 (审计修正: Protobuf 输出) |
| worker_pool.h + .cc | ~200 | 从 wge 简化 (审计修正 v3.2: +shouldSendAlert +IpRateLimiter) |
| config.h + config_loader.cc | ~100 | 从 wge 简化 (审计修正 v3.2: +AlertGuard 配置) |
| CMakeLists.txt | ~50 | 新写 (审计修正: +malicious_event.proto) |
| **C++ 合计** | **~1105** | |
| Rust FFI (lib.rs) | ~200 | 新写 |
| curiefense_ffi.h | ~40 | 新写 |
| proto/ (akto_message + malicious_event) | ~80 | 复制 |
| **总计** | **~1425** | |

---

## 10. CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.28)
project(curiefense-akto-bridge VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(CURIEFENSE_BRIDGE_ENABLE_TESTS "Build tests" ON)

# ===== Find packages =====
find_package(RdKafka REQUIRED)
find_package(Protobuf REQUIRED)
find_package(simdjson REQUIRED)
find_package(spdlog REQUIRED)
find_package(yaml-cpp REQUIRED)
find_package(prometheus-cpp QUIET)
find_package(GTest QUIET)

# ===== Protobuf generation (HttpResponseParam) =====
set(PROTO_DIR ${CMAKE_SOURCE_DIR}/proto)
set(PROTO_FILES ${PROTO_DIR}/message.proto)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})

# ===== Curiefense FFI 库 =====
find_library(CURIEFENSE_FFI_LIB
    NAMES curiefense_ffi
    HINTS ${CURIEFENSE_FFI_DIR}/lib
    REQUIRED
)
find_path(CURIEFENSE_FFI_INCLUDE
    NAMES curiefense_ffi.h
    HINTS ${CURIEFENSE_FFI_DIR}/include
    REQUIRED
)

# ===== WGE Common 库 (从 wge 项目安装) =====
find_package(wge_common REQUIRED)

# ===== Core Library =====
add_library(curiefense_bridge_core STATIC
    src/akto_adapter.cc
    src/engine.cc
    src/alert_builder.cc
    src/worker_pool.cc
    src/config_loader.cc
    ${PROTO_SRCS}
)
target_include_directories(curiefense_bridge_core PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}
    ${CURIEFENSE_FFI_INCLUDE}
)
target_link_libraries(curiefense_bridge_core PUBLIC
    wge_common::wge_common
    ${CURIEFENSE_FFI_LIB}
    simdjson::simdjson
    protobuf::libprotobuf
    spdlog::spdlog
    yaml-cpp
)

# ===== Main Executable =====
add_executable(curiefense-bridge src/main.cc)
target_link_libraries(curiefense-bridge PRIVATE curiefense_bridge_core)

# ===== Tests =====
if(CURIEFENSE_BRIDGE_ENABLE_TESTS AND GTest_FOUND)
    enable_testing()
    add_executable(curiefense_bridge_test
        tests/test_akto_adapter.cc
        tests/test_alert_builder.cc
        tests/test_e2e.cc
    )
    target_link_libraries(curiefense_bridge_test PRIVATE
        curiefense_bridge_core
        GTest::gtest_main
    )
    add_test(NAME curiefense_bridge_test COMMAND curiefense_bridge_test)
endif()

# ===== Install =====
install(TARGETS curiefense-bridge RUNTIME DESTINATION bin)
```

---

## 11. Dockerfile

```dockerfile
# ==========================================
# Stage 1: Build Curiefense FFI (Rust)
# ==========================================
FROM rust:1.75-slim AS rust-builder

RUN apt-get update && apt-get install -y \
    libhyperscan-dev libxml2-dev libpcre2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /curiefense

# 克隆 Curiefense + FFI crate
RUN git clone --depth 1 https://github.com/curiefense/curiefense.git .
COPY curiefense-ffi/ ./curiefense-ffi/

# 编译 FFI crate
WORKDIR /curiefense/curiefense-ffi
RUN cargo build --release

# ==========================================
# Stage 2: Build WGE Common (C++)
# ==========================================
FROM gcc:14-bookworm AS wge-builder

RUN apt-get update && apt-get install -y \
    cmake ninja-build pkg-config \
    librdkafka-dev libprotobuf-dev protobuf-compiler \
    libsimdjson-dev libspdlog-dev libyaml-cpp-dev \
    libgtest-dev libpcre2-dev libre2-dev \
    && rm -rf /var/lib/apt/lists/*

# 克隆 WGE SDK (stone-rhino/wge)
WORKDIR /wge-sdk
RUN git clone --depth 1 https://github.com/stone-rhino/wge.git .

# 编译 WGE SDK → 安装
RUN mkdir build && cd build && \
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX=/opt/wge-sdk .. && \
    cmake --build . -- -j$(nproc) && \
    cmake --install .

# 克隆 WGE Detector (laolv2023/wge)
WORKDIR /wge
RUN git clone https://github.com/laolv2023/wge.git .

# 修改 CMakeLists.txt: 添加 wge_common 库 + install
# (见 §2.2)
RUN mkdir build && cd build && \
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX=/opt/wge .. && \
    cmake --build . -- -j$(nproc) && \
    cmake --install .

# ==========================================
# Stage 3: Build Curiefense Bridge (C++)
# ==========================================
FROM gcc:14-bookworm AS cpp-builder

RUN apt-get update && apt-get install -y \
    cmake ninja-build pkg-config \
    librdkafka-dev libprotobuf-dev protobuf-compiler \
    libsimdjson-dev libspdlog-dev libyaml-cpp-dev \
    libgtest-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制 WGE Common 库
COPY --from=wge-builder /opt/wge/lib/libwge_kafka_detector_core.a /usr/local/lib/libwge_common.a
COPY --from=wge-builder /opt/wge/include/wge/ /usr/local/include/wge/

# 复制 WGE SDK (wge_common 传递依赖)
COPY --from=wge-builder /opt/wge-sdk/lib/libwge.* /usr/local/lib/
COPY --from=wge-builder /opt/wge-sdk/include/wge/ /usr/local/include/wge/

# 复制 Curiefense FFI
COPY --from=rust-builder \
    /curiefense/curiefense-ffi/target/release/libcuriefense_ffi.so \
    /usr/local/lib/
COPY --from=rust-builder \
    /curiefense/curiefense-ffi/include/curiefense_ffi.h \
    /usr/local/include/

RUN ldconfig

# 编译 Curiefense Bridge
COPY . /build/curiefense-akto-bridge/
WORKDIR /build/curiefense-akto-bridge
RUN mkdir build && cd build && \
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release .. && \
    cmake --build . -- -j$(nproc)

# ==========================================
# Stage 4: Runtime
# ==========================================
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    librdkafka2 libspdlog1.12 libyaml-cpp0.8 \
    libprotobuf32 libsimdjson11 \
    && rm -rf /var/lib/apt/lists/*

# 复制二进制和库
COPY --from=cpp-builder \
    /build/curiefense-akto-bridge/build/curiefense-bridge /usr/local/bin/
COPY --from=rust-builder \
    /curiefense/curiefense-ffi/target/release/libcuriefense_ffi.so /usr/local/lib/
COPY --from=wge-builder /opt/wge-sdk/lib/libwge.so* /usr/local/lib/
RUN ldconfig

# 复制配置
COPY config/ /etc/curiefense-bridge/
COPY curiefense-config/ /etc/curiefense/config/

# P1-1 修复: Curiefense 配置路径 symlink
RUN mkdir -p /cf-config/current && \
    ln -s /etc/curiefense/config /cf-config/current/config

EXPOSE 9101

CMD ["curiefense-bridge", "--config", "/etc/curiefense-bridge/curiefense-bridge.yaml"]
```

---

## 12. docker-compose.yml

```yaml
version: '3.8'
services:
  curiefense-bridge:
    build: ./curiefense-akto-bridge
    environment:
      KAFKA_BOOTSTRAP_SERVERS: "kafka:9092"
      AKTO_INPUT_TOPIC: "${AKTO_INPUT_TOPIC:-akto.api.logs2}"
      AKTO_INPUT_FORMAT: "${AKTO_INPUT_FORMAT:-auto}"
      LOG_LEVEL: "${LOG_LEVEL:-info}"
    volumes:
      - curiefense-wal:/var/lib/curiefense/wal
      - ./curiefense-config:/etc/curiefense/config:ro
      - ./geoip:/etc/curiefense/geoip:ro
    ports:
      - "9101:9101"
    restart: always
    depends_on:
      - kafka
      - redis

  kafka:
    image: confluentinc/cp-kafka:7.5.0
    environment:
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
    ports:
      - "9092:9092"

  zookeeper:
    image: confluentinc/cp-zookeeper:7.5.0
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  curiefense-wal:
```

---

## 13. 配置文件

```yaml
# curiefense-bridge.yaml

kafka:
  consumer:
    bootstrap_servers: "${KAFKA_BOOTSTRAP_SERVERS:-kafka:9092}"
    group_id: "curiefense-bridge"
    topic: "${AKTO_INPUT_TOPIC:-akto.api.logs2}"
    input_format: "${AKTO_INPUT_FORMAT:-auto}"
    auto_offset_reset: "latest"
    enable_auto_commit: false
    max_poll_records: 100
    session_timeout_ms: 30000

  producer:
    bootstrap_servers: "${KAFKA_BOOTSTRAP_SERVERS:-kafka:9092}"
    topic: "akto.threat_detection.malicious_events"
    dlq_topic: "curiefense-input-dlq"
    enable_idempotence: true
    batch_size: 65536
    linger_ms: 20
    retries: 3

curiefense:
  config_dir: "/etc/curiefense/config"
  enable_rate_limit: false

detector:
  worker_threads: 0
  batch_size: 100
  max_pending_tasks: 2000
  task_timeout_ms: 5000
  poll_interval_ms: 100

observability:
  log_level: "${LOG_LEVEL:-info}"
  log_format: "json"
  prometheus:
    enabled: true
    port: 9101
    path: "/metrics"
```

---

## 14. 测试方案

### 14.1 单元测试

| 测试文件 | 用例数 | 覆盖范围 |
|---|---|---|
| `test_akto_adapter.cc` | 15 | JSON 解析、Protobuf 解析、Auto 格式判断、headers 提取 |
| `test_alert_builder.cc` | 12 | sub_category 映射、severity 映射、filter_id 生成、JSON 转义 |
| `test_e2e.cc` | 8 | 端到端: Kafka 消费 → 检测 → 告警输出 |

**关键测试用例**:

```cpp
// Protobuf 路径测试
TEST(AktoAdapterTest, ParseProtobufBasic) {
    trafficpb::HttpResponseParam pb;
    pb.set_ip("10.0.0.1");
    pb.set_method("GET");
    pb.set_path("/api/users");
    std::string serialized;
    pb.SerializeToString(&serialized);

    auto log = adapter.adapt(serialized.data(), serialized.size(),
                              "akto.api.logs2", 0, 0);
    EXPECT_EQ(log.ip, "10.0.0.1");
    EXPECT_EQ(log.method, "GET");
    EXPECT_EQ(log.path, "/api/users");
}

// JSON 路径测试
TEST(AktoAdapterTest, ParseJsonBasic) {
    std::string json = R"({
        "ip": "10.0.0.1", "method": "GET",
        "path": "/api/users?page=1",
        "requestHeaders": "{\"Host\":\"api.example.com\"}",
        "requestPayload": "", "akto_account_id": "1000000",
        "time": "1700000000"
    })";
    auto log = adapter.adapt(json.data(), json.size(),
                              "akto.api.logs", 0, 0);
    EXPECT_EQ(log.ip, "10.0.0.1");
    EXPECT_EQ(log.host, "api.example.com");
}

// Auto 格式判断测试
TEST(AktoAdapterTest, AutoFormatDetection) {
    // JSON 以 '{' 开头
    EXPECT_EQ(adapter.resolveFormat("akto.api.logs",
        reinterpret_cast<const uint8_t*>("{"), 1), InputFormat::Json);
    // Protobuf 不以 '{' 开头
    EXPECT_EQ(adapter.resolveFormat("akto.api.logs2",
        reinterpret_cast<const uint8_t*>("\x0a"), 1), InputFormat::Protobuf);
}

// 告警格式测试 (审计修正: Protobuf 输出)
TEST(AlertBuilderTest, MaliciousEventEnvelope) {
    AnalyzeResult result;
    result.blocked = true;
    result.reasons_json = R"([{"ruleid":"sqli:1","risk_level":3}])";

    AktoLog log;
    log.ip = "10.0.0.1";
    log.method = "POST";
    log.path = "/api/login";
    log.akto_account_id = "1000000";

    auto output = AlertBuilder::build(result, log);
    ASSERT_FALSE(output.empty());

    // 审计修正: 解析 Protobuf 而非 JSON
    using namespace threat_detection::message::malicious_event::v1;
    MaliciousEventKafkaEnvelope envelope;
    ASSERT_TRUE(envelope.ParseFromString(output));

    EXPECT_EQ(envelope.account_id(), "1000000");
    EXPECT_EQ(envelope.actor(), "10.0.0.1");

    const auto& evt = envelope.malicious_event();
    EXPECT_TRUE(evt.filter_id().find("CUR_") == 0);  // CUR_ 前缀
    EXPECT_EQ(evt.category(), "ApiAbuse");
    EXPECT_EQ(evt.label(), "THREAT");
    EXPECT_TRUE(evt.successful_exploit());  // 审计修正: result.blocked → true
    EXPECT_EQ(evt.context_source(), "API");
    EXPECT_GT(evt.detected_at(), 0);  // 毫秒级时间戳
}
```

### 14.2 集成测试

```
test_e2e.cc:
  1. 启动嵌入式 Kafka
  2. 生产 JSON 消息到 akto.api.logs
  3. 启动 CuriefenseBridge
  4. 消费 akto.threat_detection.malicious_events
  5. 验证告警 JSON 格式和字段
```

---

## 15. 部署方案

### 15.1 与 Akto 共部署

```yaml
# akto docker-compose.yml 新增
  curiefense-bridge:
    build: ./curiefense-akto-bridge
    environment:
      KAFKA_BOOTSTRAP_SERVERS: "kafka:9092"
      AKTO_INPUT_TOPIC: "akto.api.logs2"
    depends_on:
      - kafka
    restart: always
```

### 15.2 与 WGE 并行部署

```yaml
# 同时运行 WGE 和 Curiefense
  wge-detector:
    image: wge-kafka-detector:latest
    environment:
      AKTO_INPUT_TOPIC: "akto.api.logs2"
    # WGE 消费 logs2 (Protobuf)

  curiefense-bridge:
    build: ./curiefense-akto-bridge
    environment:
      AKTO_INPUT_TOPIC: "akto.api.logs2"
    # Curiefense 也消费 logs2 (同一 Topic, 不同 consumer group)
```

### 15.3 独立部署

```yaml
# curiefense-bridge docker-compose.yml (见 §12)
# 包含 Kafka + Redis + Curiefense Bridge
```

---

## 16. 开发计划

### 16.1 工作分解

| 阶段 | 任务 | 工期 | 依赖 |
|---|---|---|---|
| **Phase 1: Rust FFI** | | | |
| 1.1 | curiefense-ffi crate + lib.rs | 3 天 | — |
| 1.2 | curiefense_ffi.h 头文件 | 0.5 天 | 1.1 |
| 1.3 | FFI 单元测试 (Rust) | 1 天 | 1.1 |
| **Phase 2: WGE 库化** | | | |
| 2.1 | wge CMakeLists 添加 wge_common + install | 1 天 | — |
| 2.2 | 验证 wge_common 可被外部链接 | 0.5 天 | 2.1 |
| **Phase 3: C++ Bridge** | | | |
| 3.1 | AktoAdapter (JSON + Protobuf + auto) | 2 天 | 2.2 |
| 3.2 | CuriefenseEngine (FFI 封装) | 1 天 | 1.3, 2.2 |
| 3.3 | AlertBuilder (Akto JSON) | 1 天 | 3.2 |
| 3.4 | CuriefenseWorkerPool | 1 天 | 3.2 |
| 3.5 | config.h + config_loader.cc | 1 天 | 2.2 |
| 3.6 | main.cc (复制 wge + 改 4 处) | 1 天 | 3.1-3.5 |
| **Phase 4: 测试** | | | |
| 4.1 | 单元测试 (35 用例) | 2 天 | 3.6 |
| 4.2 | 集成测试 (Kafka E2E) | 1 天 | 4.1 |
| **Phase 5: 部署** | | | |
| 5.1 | Dockerfile (4 阶段) | 1 天 | 4.2 |
| 5.2 | docker-compose.yml | 0.5 天 | 5.1 |
| 5.3 | README + INSTALL | 0.5 天 | 5.2 |
| **合计** | | **18 天** | |

### 16.2 里程碑

| 里程碑 | 交付物 | 时间 |
|---|---|---|
| M1: FFI 层完成 | `libcuriefense_ffi.so` + 测试 | Day 5 |
| M2: WGE 库化完成 | `libwge_common.a` + install | Day 6 |
| M3: Bridge MVP | 可运行二进制 | Day 11 |
| M4: 测试通过 | 35 用例全绿 | Day 14 |
| M5: 容器化 | Docker 镜像 + 文档 | Day 18 |

---

## 17. 审计修订记录 (v3.1)

> 基于最新 WGE 实现和 Akto 源码实证审计，对 v3.0 方案的修订记录。

### P0 级修复（致命）

| 编号 | 问题 | 源码实证 | 修复 |
|---|---|---|---|
| P0-1 | 输出 JSON，Akto 消费 Protobuf | `SendMaliciousEventsToBackend.java` L37: `MaliciousEventKafkaEnvelope.parseFrom(r.value())` | AlertBuilder 改为 `SerializeToString()` 输出 Protobuf |
| P0-2 | `api_collection_id` 用 field 6 | `MaliciousTrafficDetectorTask.java` L610: `getAktoVxlanId()` | 改为 `akto_vxlan_id` (field 18) → `stoi` |
| P0-3 | `wge_common` 库不存在 | WGE `CMakeLists.txt` L77: 只有 `wge_kafka_detector_core` | 方案 Phase 2 新增 `wge_common` 库拆分（CMake 重构） |

### P1 级修复（严重）

| 编号 | 问题 | 修复 |
|---|---|---|
| P1-1 | `detected_at` 秒级 vs 毫秒级 | `time × 1000` 转毫秒（Akto proto field 3 是 int64 毫秒） |
| P1-2 | `headersMapToJson` 缺少转义 | 新增 `escapeJsonStr()` 对 key/value 转义 |
| P1-3 | Curiefense 配置路径硬编码 | 文档保留，部署时通过 symlink 解决 |
| P1-4 | Protobuf 包名 `trafficpb` 不匹配 | 改为 `wge::kafka::akto::HttpResponseParam`（与 WGE 一致） |

### P2 级修复（改进）

| 编号 | 问题 | 修复 |
|---|---|---|
| P2-1 | 缺少 `collection_id=0` 兜底 | 新增 `HOST_COLLECTION_FALLBACK` 映射 |
| ~~P2-2~~ | ~~缺少 IP 限流~~ | **v3.2 已实现**: `shouldSendAlert` + `IpRateLimiter`（与 WGE 对齐） |
| P2-3 | `successful_exploit` 硬编码 false | 改为 `result.blocked` 动态映射 |
| P2-4 | group_id 冲突 | 已正确（`curiefense-bridge`），文档补充说明 |

### v3.2 新增修复（对齐 WGE 7a1f508）

| 编号 | 问题 | 源码实证 (WGE) | 修复 |
|---|---|---|---|
| v3.2-1 | 缺少 `shouldSendAlert` 告警保护 | WGE `worker_pool.cc` L128-167: 分级过滤 + collection_id 兜底 + IP 限流 | CuriefenseWorkerPool 新增 `shouldSendAlert()` |
| v3.2-2 | 缺少 `IpRateLimiter` (atomic) | WGE `worker_pool.cc` L111: `static std::atomic<uint64_t> call_counter` | IpRateLimiter 使用 `std::atomic` 计数器 |
| v3.2-3 | `HOST_COLLECTION_FALLBACK` 硬编码 | WGE `config.h` L252: `host_collection_map` 配置化 | 改为从 YAML 配置加载 |
| v3.2-4 | `wge_common` 库不存在 | WGE `CMakeLists.txt` L77: `wge_kafka_detector_core` | Dockerfile 改为 COPY `libwge_kafka_detector_core.a` |
| v3.2-5 | `mapSeverity` 与 WGE 不同 | WGE `alert_builder.cc` L266: `mapSeverityToAkto` (syslog 级别) | 保留 Curiefense 逻辑（blocked/monitored），注释说明差异 |
| v3.2-6 | 代码量估计过低 | WGE `worker_pool.{h,cc}` 实际 1024 行 | worker_pool 从 ~80 → ~200 行 |

### 修改文件清单

| 位置 | 修改内容 |
|---|---|
| 头部版本 | v3.0 → v3.1 → v3.2 (对齐 WGE 7a1f508) |
| §1.2 设计原则 | 输出格式: JSON → Protobuf; wge_common 库名修正 |
| §2.1 架构图 | CuriefenseWorkerPool 80→200 行, +shouldSendAlert |
| §3.1 数据流 | `api_collection_id` → `akto_vxlan_id` |
| §3.3 输出格式 | JSON 示例 → Protobuf proto 定义 |
| §6.2 akto_adapter.cc | `message.pb.h` → `akto_message.pb.h`, `trafficpb` → `wge::kafka::akto`, `api_collection_id()` → `akto_vxlan_id()`, +兜底逻辑 |
| §6.3 headersMapToJson | +`escapeJsonStr()` 转义 |
| §7.1 alert_builder.h | +`malicious_event.pb.h` include |
| §7.2 alert_builder.cc | JSON ostringstream → Protobuf `SerializeToString()` |
| §9 项目结构 | +`proto/malicious_event.proto`, worker_pool 行数修正 |
| §9.1 代码量 | +~165 行 (v3.1) + ~120 行 (v3.2) = ~1425 总计 |
| §11 Dockerfile | `libwge_common.a` → `libwge_kafka_detector_core.a` |
| §14.1 测试 | JSON 断言 → Protobuf 解析断言 |

---

*设计结束 (v3.2 审计修订版 — 对齐 WGE 7a1f508)*
