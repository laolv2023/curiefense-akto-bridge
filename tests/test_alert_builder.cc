/// @file test_alert_builder.cc
/// @brief AlertBuilder 单元测试

#include <gtest/gtest.h>
#include "alert_builder.h"
#include "engine.h"
#include "akto_adapter.h"

using namespace curiefense;

TEST(AlertBuilderTest, EmptyWhenNoThreat) {
    AnalyzeResult result;
    result.blocked = false;
    result.monitored = false;

    AktoLog log;
    log.ip = "10.0.0.1";

    auto output = AlertBuilder::build(result, log);
    EXPECT_TRUE(output.empty());  // 无威胁不生成告警
}

TEST(AlertBuilderTest, ProtobufOutputWhenBlocked) {
    AnalyzeResult result;
    result.blocked = true;
    result.is_blocking = true;
    result.monitored = false;
    result.reasons_json = R"([{"ruleid":"sqli:1","risk_level":3}])";

    AktoLog log;
    log.ip = "10.0.0.1";
    log.method = "POST";
    log.path = "/api/login";
    log.akto_account_id = "1000000";
    log.api_collection_id = 42;
    log.host = "api.example.com";
    log.time = 1700000000;

    auto output = AlertBuilder::build(result, log);
    ASSERT_FALSE(output.empty());

    // 验证是 Protobuf 格式 (不是 JSON)
    // Protobuf 不以 '{' 开头
    EXPECT_NE(output[0], '{');

    // 解析 Protobuf 验证字段
    using namespace threat_detection::message::malicious_event::v1;
    MaliciousEventKafkaEnvelope envelope;
    ASSERT_TRUE(envelope.ParseFromString(output));

    EXPECT_EQ(envelope.account_id(), "1000000");
    EXPECT_EQ(envelope.actor(), "10.0.0.1");

    const auto& evt = envelope.malicious_event();
    EXPECT_EQ(evt.actor(), "10.0.0.1");
    EXPECT_TRUE(evt.filter_id().find("CUR_") == 0);  // CUR_ 前缀
    EXPECT_EQ(evt.category(), "ApiAbuse");
    EXPECT_EQ(evt.label(), "THREAT");
    EXPECT_TRUE(evt.successful_exploit());  // blocked → true
    EXPECT_EQ(evt.context_source(), "API");
    EXPECT_GT(evt.detected_at(), 0);  // 毫秒级时间戳
    EXPECT_EQ(evt.latest_api_method(), "POST");
    EXPECT_EQ(evt.latest_api_endpoint(), "/api/login");
    EXPECT_EQ(evt.latest_api_collection_id(), 42);
    EXPECT_EQ(evt.host(), "api.example.com");
}

TEST(AlertBuilderTest, ProtobufOutputWhenMonitored) {
    AnalyzeResult result;
    result.blocked = false;
    result.monitored = true;
    result.reasons_json = R"([{"ruleid":"xss:1"}])";

    AktoLog log;
    log.ip = "192.168.1.1";
    log.method = "GET";
    log.path = "/search?q=<script>";
    log.akto_account_id = "2000000";
    log.api_collection_id = 1;
    log.time = 0;  // 测试 fallback 到当前时间

    auto output = AlertBuilder::build(result, log);
    ASSERT_FALSE(output.empty());

    using namespace threat_detection::message::malicious_event::v1;
    MaliciousEventKafkaEnvelope envelope;
    ASSERT_TRUE(envelope.ParseFromString(output));

    const auto& evt = envelope.malicious_event();
    EXPECT_FALSE(evt.successful_exploit());  // monitored → false
    EXPECT_EQ(evt.severity(), "MEDIUM");     // monitored → MEDIUM
}

TEST(AlertBuilderTest, DetectedAtMilliseconds) {
    AnalyzeResult result;
    result.blocked = true;
    result.reasons_json = R"([{"ruleid":"test"}])";

    AktoLog log;
    log.ip = "1.1.1.1";
    log.time = 1700000000;  // 秒级

    auto output = AlertBuilder::build(result, log);
    ASSERT_FALSE(output.empty());

    using namespace threat_detection::message::malicious_event::v1;
    MaliciousEventKafkaEnvelope envelope;
    envelope.ParseFromString(output);

    // time(秒) × 1000 = 毫秒
    EXPECT_EQ(envelope.malicious_event().detected_at(), 1700000000LL * 1000);
}

TEST(AlertBuilderTest, FilterIdFormat) {
    AnalyzeResult result;
    result.blocked = true;
    result.reasons_json = R"([{"ruleid":"sqli:1"}])";

    AktoLog log;
    log.ip = "1.1.1.1";

    auto output = AlertBuilder::build(result, log);
    ASSERT_FALSE(output.empty());

    using namespace threat_detection::message::malicious_event::v1;
    MaliciousEventKafkaEnvelope envelope;
    envelope.ParseFromString(output);

    // filter_id 格式: CUR_ + 8位hex
    const auto& fid = envelope.malicious_event().filter_id();
    EXPECT_EQ(fid.substr(0, 4), "CUR_");
    EXPECT_GE(fid.size(), 12);  // CUR_ + 至少 8 字符
}

TEST(AlertBuilderTest, SubCategoryMapping) {
    AnalyzeResult result;
    result.blocked = true;

    AktoLog log;
    log.ip = "1.1.1.1";

    // ContentFilter → SQLInjection
    result.reasons_json = R"([{"ruleid":"sqli:1","risk_level":3}])";
    auto output = AlertBuilder::build(result, log);
    ASSERT_FALSE(output.empty());

    using namespace threat_detection::message::malicious_event::v1;
    MaliciousEventKafkaEnvelope envelope;
    envelope.ParseFromString(output);
    EXPECT_EQ(envelope.malicious_event().sub_category(), "SQLInjection");
}
