# =============================================================================
# Curiefense-Akto Bridge — Dockerfile (4 阶段构建)
# =============================================================================

# Stage 1: Build Curiefense FFI (Rust)
FROM rust:1.78-bookworm AS rust-builder
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /curiefense
# 克隆 Curiefense 并构建 FFI crate
RUN git clone --depth 1 https://github.com/curiefense/curiefense.git .
COPY curiefense-ffi/ /curiefense/curiefense-ffi/
WORKDIR /curiefense/curiefense-ffi
RUN cargo build --release

# Stage 2: Build WGE Common 库
FROM gcc:14-bookworm AS wge-builder
RUN apt-get update && apt-get install -y \
    cmake ninja-build pkg-config \
    librdkafka-dev libprotobuf-dev protobuf-compiler \
    libsimdjson-dev libspdlog-dev libyaml-cpp-dev \
    libre2-dev \
    && rm -rf /var/lib/apt/lists/*
# 克隆 WGE 并编译 (审计修正 v3.2-4: 实际库名 wge_kafka_detector_core)
RUN git clone --depth 1 https://github.com/laolv2023/wge.git /wge
WORKDIR /wge
RUN mkdir build && cd build && \
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release .. && \
    cmake --build . -- -j$(nproc) && \
    cmake --install . --prefix /opt/wge

# Stage 3: Build Curiefense Bridge (C++)
FROM gcc:14-bookworm AS cpp-builder
RUN apt-get update && apt-get install -y \
    cmake ninja-build pkg-config \
    librdkafka-dev libprotobuf-dev protobuf-compiler \
    libsimdjson-dev libspdlog-dev libyaml-cpp-dev \
    libgtest-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制 WGE 库
COPY --from=wge-builder /opt/wge/lib/libwge_kafka_detector_core.a /usr/local/lib/
COPY --from=wge-builder /opt/wge/include/ /usr/local/include/wge/

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

# Stage 4: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    librdkafka2 libspdlog1.12 libyaml-cpp0.8 \
    libprotobuf32 libsimdjson11 \
    && rm -rf /var/lib/apt/lists/*

# 复制二进制和库
COPY --from=cpp-builder \
    /build/curiefense-akto-bridge/build/curiefense-bridge /usr/local/bin/
COPY --from=rust-builder \
    /curiefense/curiefense-ffi/target/release/libcuriefense_ffi.so \
    /usr/local/lib/

# Curiefense 配置路径 symlink
RUN mkdir -p /cf-config/current && \
    ln -s /etc/curiefense/config /cf-config/current/config

RUN ldconfig

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:9101/health || exit 1

EXPOSE 9101

CMD ["curiefense-bridge", "/etc/curiefense-bridge/curiefense-bridge.yaml"]
