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
