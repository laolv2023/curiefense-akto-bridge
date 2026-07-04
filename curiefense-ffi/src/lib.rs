//! Curiefense FFI — C ABI bindings for Curiefense WAF engine
//!
//! 提供 C 兼容的接口，供 C++ Bridge 层通过 FFI 调用 Curiefense 检测引擎。
//!
//! ## 安全说明
//! - 所有返回的 `*const c_char` 必须由调用方通过 `curiefense_free_result` 或
//!   `curiefense_free_string` 释放，否则会内存泄漏。
//! - `curiefense_inspect` 是线程安全的（Curiefense 内部使用 `async_std::task::block_on`）。
//! - 如果启用 Rate Limit（依赖 Redis），可能死锁。推荐禁用 Rate Limit。

use curiefense::inspect_generic_request_map;
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
        blocked: 0,
        is_blocking: 0,
        monitored: 0,
        _pad: 0,
        action_type: 0,
        reasons_json: ptr::null(),
        tags_json: ptr::null(),
        stats_json: ptr::null(),
        error: safe_cstring(msg.to_string()),
    }
}

fn empty_result() -> CAnalyzeResult {
    CAnalyzeResult {
        blocked: 0,
        is_blocking: 0,
        monitored: 0,
        _pad: 0,
        action_type: 0,
        reasons_json: safe_cstring("[]".to_string()),
        tags_json: safe_cstring("{}".to_string()),
        stats_json: safe_cstring("{}".to_string()),
        error: ptr::null(),
    }
}

/// 解析 headers JSON 字符串为 HashMap
/// 格式: {"key":"value1,value2",...}
fn parse_headers_json(json: &str) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    if json.is_empty() || json == "{}" {
        return map;
    }
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(serde_json::Value::Object(obj)) => {
            for (k, v) in obj {
                let vals: Vec<String> = match v {
                    serde_json::Value::String(s) => {
                        s.split(',').map(|s| s.trim().to_string()).collect()
                    }
                    serde_json::Value::Array(arr) => {
                        arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
                    }
                    _ => vec![],
                };
                map.insert(k, vals);
            }
        }
        _ => {}
    }
    map
}

// ── FFI 导出函数 ──

/// 初始化 Curiefense 配置
/// 调用 reload_config 加载指定路径的配置文件
#[no_mangle]
pub extern "C" fn curiefense_init(config_path: *const c_char) -> *const c_char {
    let path = match cstr_to_string(config_path) {
        Some(p) => p,
        None => return safe_cstring("curiefense_init: config_path is null".to_string()),
    };

    // Curiefense CONFIGS 路径硬编码为 /cf-config/current/config
    // 调用方应通过 symlink 将 config_path 链接到该路径
    match curiefense::config::reload_config(&path, &[]) {
        Ok(_) => {
            log::info!("Curiefense config loaded from {}", path);
            ptr::null()
        }
        Err(e) => {
            let msg = format!("curiefense_init: failed to load config from {}: {}", path, e);
            safe_cstring(msg)
        }
    }
}

/// 执行 Curiefense 检测
/// 返回 CAnalyzeResult，调用方必须通过 curiefense_free_result 释放
#[no_mangle]
pub extern "C" fn curiefense_inspect(req: *const CRawRequest) -> CAnalyzeResult {
    if req.is_null() {
        return error_result("curiefense_inspect: req is null");
    }

    let req_struct = unsafe { &*req };

    // 提取字段
    let ip = cstr_to_string(req_struct.ip).unwrap_or_default();
    let method = cstr_to_string(req_struct.method).unwrap_or_else(|| "GET".to_string());
    let path = cstr_to_string(req_struct.path).unwrap_or_else(|| "/".to_string());
    let authority = cstr_to_string(req_struct.authority).unwrap_or_default();
    let protocol = cstr_to_string(req_struct.protocol).unwrap_or_else(|| "HTTP/1.1".to_string());
    let request_id = cstr_to_string(req_struct.request_id).unwrap_or_default();
    let headers_json = cstr_to_string(req_struct.headers_json).unwrap_or_else(|| "{}".to_string());
    let body = if req_struct.body.is_null() || req_struct.body_len == 0 {
        String::new()
    } else {
        cstr_to_string(req_struct.body).unwrap_or_default()
    };

    // 解析 headers
    let headers_map = parse_headers_json(&headers_json);

    // 构建 RawRequest
    let meta = RequestMeta::from_map(&headers_map);
    let raw_req = RawRequest {
        ipstr: ip.clone(),
        method: method.clone(),
        path: path.clone(),
        authority: authority.clone(),
        protocol: protocol.clone(),
        request_id: request_id.clone(),
        headers: headers_map,
        meta,
        mbody: body.into_bytes(),
    };

    // 执行检测
    let logs = Logs::default();
    let result = async_std::task::block_on(
        inspect_generic_request_map::<DynGrasshopper>(&logs, raw_req)
    );

    match result {
        Ok(analyze_result) => {
            let ar: AnalyzeResult = analyze_result;
            let decision = &ar.decision;

            CAnalyzeResult {
                blocked: if decision.blocked() { 1 } else { 0 },
                is_blocking: if decision.is_blocking() { 1 } else { 0 },
                monitored: matches!(decision.action_type(), ActionType::Monitor) as u8,
                _pad: 0,
                action_type: match decision.action_type() {
                    ActionType::Skip => 0,
                    ActionType::Monitor => 1,
                    ActionType::Block(_) => 2,
                },
                reasons_json: safe_cstring(ar.rinfo.clone()),
                tags_json: safe_cstring(ar.tags_json()),
                stats_json: safe_cstring(format!("{:?}", ar.stats)),
                error: ptr::null(),
            }
        }
        Err(e) => {
            error_result(&format!("curiefense_inspect error: {}", e))
        }
    }
}

/// 释放 CAnalyzeResult 中的字符串内存
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

/// 释放单独的 C 字符串
#[no_mangle]
pub extern "C" fn curiefense_free_string(s: *const c_char) {
    if s.is_null() { return; }
    unsafe { drop(CString::from_raw(s as *mut c_char)); }
}
