# Curiefense-Akto Bridge

> 基于 Curiefense WAF 引擎的 Akto API 安全平台集成方案

## 架构

```
Akto Kafka (akto.api.logs2 Protobuf)
    │
    ↓
CuriefenseEngine (Rust FFI)
    │
    ↓
AlertBuilder → MaliciousEventKafkaEnvelope Protobuf
    │
    ↓
Akto Kafka (akto.threat_detection.malicious_events)
```

## 快速开始

### 1. 使用 Docker Compose

```bash
# 启动全套环境 (Kafka + Curiefense Bridge)
docker compose up -d

# 查看日志
docker compose logs -f curiefense-bridge
```

### 2. 手动构建

```bash
# 构建
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -- -j$(nproc)

# 运行
./curiefense-bridge ../config/curiefense-bridge.yaml
```

## 配置

编辑 `config/curiefense-bridge.yaml`:

```yaml
kafka:
  consumer:
    topic: "akto.api.logs2"      # Akto Protobuf 格式
    input_format: "auto"          # 自动识别 JSON/Protobuf

alert_guard:
  filter_low_severity: true       # 丢弃 LOW 级别
  rate_limit_per_minute: 5        # IP 限流
  host_collection_map:            # Collection ID 兜底
    "api.example.com": 1
```

## 特性

- **双模输入**: 自动识别 JSON (akto.api.logs) / Protobuf (akto.api.logs2)
- **Protobuf 输出**: 与 Akto `SendMaliciousEventsToBackend` 消费格式一致
- **告警保护**: 分级过滤 + IP 限流 + collection_id 兜底 (v3.2)
- **配置化**: host_collection_map / rate_limit / filter_low 从 YAML 加载
- **线程安全**: IpRateLimiter 使用 `std::atomic` 计数器

## 版本

- v3.2 — 对齐 WGE 7a1f508
