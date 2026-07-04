cmake_minimum_required(VERSION 3.28)
project(curiefense-akto-bridge VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ===== Options =====
option(CURIEFENSE_BRIDGE_ENABLE_TESTS "Build unit tests" ON)

# ===== Find packages =====
find_package(RdKafka REQUIRED)
find_package(Protobuf REQUIRED)
find_package(simdjson REQUIRED)
find_package(spdlog REQUIRED)
find_package(yaml-cpp REQUIRED)
find_package(GTest QUIET)

# ===== Protobuf generation =====
set(PROTO_DIR ${CMAKE_SOURCE_DIR}/proto)
set(PROTO_FILES
    ${PROTO_DIR}/akto_message.proto
    ${PROTO_DIR}/malicious_event.proto
)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})
target_include_directories(protobuf::libprotobuf INTERFACE ${CMAKE_BINARY_DIR})

# ===== Compiler options =====
add_compile_options(-Wall -Wextra -Wpedantic -Werror)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -O0)
endif()

# ===== Curiefense FFI 库 =====
find_library(CURIEFENSE_FFI_LIB
    NAMES curiefense_ffi
    HINTS ${CURIEFENSE_FFI_DIR}/lib /usr/local/lib
    REQUIRED
)
find_path(CURIEFENSE_FFI_INCLUDE
    NAMES curiefense_ffi.h
    HINTS ${CURIEFENSE_FFI_DIR}/include /usr/local/include
    REQUIRED
)

# ===== WGE Common 库 =====
# 审计修正 v3.2-4: WGE 实际库名为 wge_kafka_detector_core
find_library(WGE_COMMON_LIB
    NAMES wge_kafka_detector_core wge_common
    HINTS ${WGE_DIR}/lib /usr/local/lib
)
if(WGE_COMMON_LIB)
    find_path(WGE_COMMON_INCLUDE
        NAMES kafka/consumer.h
        HINTS ${WGE_DIR}/include /usr/local/include/wge
    )
endif()

# ===== Core Library =====
set(CORE_SOURCES
    src/akto_adapter.cc
    src/engine.cc
    src/alert_builder.cc
    src/worker_pool.cc
    src/config_loader.cc
)

add_library(curiefense_bridge_core STATIC ${CORE_SOURCES} ${PROTO_SRCS})
target_include_directories(curiefense_bridge_core PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}
    ${CURIEFENSE_FFI_INCLUDE}
)
target_link_libraries(curiefense_bridge_core PUBLIC
    ${CURIEFENSE_FFI_LIB}
    simdjson::simdjson
    protobuf::libprotobuf
    spdlog::spdlog
    yaml-cpp::yaml-cpp
    RdKafka::rdkafka
)

if(WGE_COMMON_LIB AND WGE_COMMON_INCLUDE)
    target_include_directories(curiefense_bridge_core PUBLIC ${WGE_COMMON_INCLUDE})
    target_link_libraries(curiefense_bridge_core PUBLIC ${WGE_COMMON_LIB})
    target_compile_definitions(curiefense_bridge_core PUBLIC WGE_COMMON_AVAILABLE=1)
endif()

# ===== Main Executable =====
add_executable(curiefense-bridge src/main.cc)
target_link_libraries(curiefense-bridge PRIVATE curiefense_bridge_core)
install(TARGETS curiefense-bridge RUNTIME DESTINATION bin)

# ===== Tests =====
if(CURIEFENSE_BRIDGE_ENABLE_TESTS AND GTest_FOUND)
    enable_testing()
    add_executable(curiefense_bridge_test
        tests/test_akto_adapter.cc
        tests/test_alert_builder.cc
    )
    target_link_libraries(curiefense_bridge_test PRIVATE
        curiefense_bridge_core
        GTest::gtest_main
    )
    add_test(NAME curiefense_bridge_test COMMAND curiefense_bridge_test)
endif()
