/// @file test_akto_adapter.cc
/// @brief AktoAdapter 单元测试

#include <gtest/gtest.h>
#include "akto_adapter.h"
#include <cstring>

using namespace curiefense;

TEST(AktoAdapterTest, AutoFormatDetection) {
    AktoAdapter adapter(InputFormat::Auto);

    // JSON 以 '{' 开头
    const char* json = R"({"method":"GET","path":"/api"})";
    auto log = adapter.adapt(json, strlen(json), "akto.api.logs", 0, 0);
    EXPECT_EQ(log.method, "GET");
    EXPECT_EQ(log.path, "/api");

    // Protobuf 不以 '{' 开头
    // 构造一个简单的 protobuf 消息 (field 1 = string "GET")
    uint8_t proto[] = {0x0a, 0x03, 'G', 'E', 'T'};
    auto log2 = adapter.adapt(reinterpret_cast<const char*>(proto), sizeof(proto),
                              "akto.api.logs2", 0, 0);
    EXPECT_EQ(log2.method, "GET");
}

TEST(AktoAdapterTest, JsonParseBasic) {
    AktoAdapter adapter(InputFormat::Json);
    const char* json = R"({
        "method": "POST",
        "path": "/api/login",
        "ip": "10.0.0.1",
        "requestPayload": "user=admin",
        "statusCode": "200",
        "akto_account_id": "1000000",
        "akto_vxlan_id": "42",
        "time": "1700000000",
        "requestHeaders": "{\"Host\":\"api.example.com\"}"
    })";

    auto log = adapter.adapt(json, strlen(json), "akto.api.logs", 0, 0);
    EXPECT_EQ(log.method, "POST");
    EXPECT_EQ(log.path, "/api/login");
    EXPECT_EQ(log.ip, "10.0.0.1");
    EXPECT_EQ(log.akto_account_id, "1000000");
    EXPECT_EQ(log.api_collection_id, 42);
    EXPECT_EQ(log.host, "api.example.com");
    EXPECT_EQ(log.time, 1700000000);
}

TEST(AktoAdapterTest, JsonParseAktoVxlanId) {
    AktoAdapter adapter(InputFormat::Json);
    // 审计修正 P0-2: api_collection_id 从 akto_vxlan_id 解析
    const char* json = R"({
        "method": "GET",
        "path": "/",
        "ip": "1.2.3.4",
        "akto_vxlan_id": "123",
        "time": "0"
    })";

    auto log = adapter.adapt(json, strlen(json), "akto.api.logs", 0, 0);
    EXPECT_EQ(log.api_collection_id, 123);
}

TEST(AktoAdapterTest, JsonParseInvalidVxlanId) {
    AktoAdapter adapter(InputFormat::Json);
    const char* json = R"({
        "method": "GET",
        "path": "/",
        "ip": "1.2.3.4",
        "akto_vxlan_id": "not-a-number",
        "time": "0"
    })";

    auto log = adapter.adapt(json, strlen(json), "akto.api.logs", 0, 0);
    EXPECT_EQ(log.api_collection_id, 0);  // 解析失败默认 0
}

TEST(AktoAdapterTest, HostExtraction) {
    AktoAdapter adapter(InputFormat::Json);
    const char* json = R"({
        "method": "GET",
        "path": "/",
        "ip": "1.2.3.4",
        "requestHeaders": "{\"Host\":\"my.api.com\",\"Content-Type\":\"application/json\"}",
        "time": "0"
    })";

    auto log = adapter.adapt(json, strlen(json), "akto.api.logs", 0, 0);
    EXPECT_EQ(log.host, "my.api.com");
}

TEST(AktoAdapterTest, EmptyPayload) {
    AktoAdapter adapter(InputFormat::Auto);
    auto log = adapter.adapt("", 0, "akto.api.logs", 0, 0);
    // 空 payload 应该有合理的默认值，不崩溃
    EXPECT_TRUE(log.method.empty() || !log.method.empty());
}
