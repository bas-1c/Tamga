#include "core/TspClient.h"
#include "core/HttpClient.h"
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "byte_array.h"
#include "oids.h"
#include "pkix_structs.h"
#include "tsp_request.h"
#include "tsp_request_engine.h"
#include "tsp_response.h"
#include "content_info.h"
#include "INTEGER.h"
#include "asn1_utils.h"
#include "pkix_utils.h"
}

// ADR-027: перейменовано з `BuildRcError`. Це ІНША функція: інша сигнатура
// і інший текст повідомлення ("failed with code N" замість
// "failed (cryptonite rc=N)"). Збіг імені з `Internal.h` лише створював
// враження, що це та сама діагностика.
static std::string BuildTspRcError(const std::string& action, int rc) {
    return action + " failed with code " + std::to_string(rc);
}

const char* TspTraceDir() {
    const char* dir = std::getenv("TAMGA_TSP_TRACE_DIR");
    return (dir != nullptr && dir[0] != '\0') ? dir : nullptr;
}

void WriteTraceBinary(const char* name, const std::vector<std::uint8_t>& data) {
    const char* dir = TspTraceDir();
    if (dir == nullptr) {
        return;
    }

    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::u8path(dir), ec);
    const std::filesystem::path path = std::filesystem::u8path(dir) / name;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return;
    }
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

void WriteTraceText(const char* name, const std::string& text) {
    const char* dir = TspTraceDir();
    if (dir == nullptr) {
        return;
    }

    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::u8path(dir), ec);
    const std::filesystem::path path = std::filesystem::u8path(dir) / name;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return;
    }
    out << text;
}
#endif

namespace tamga::core {

bool TspClient::GetTimestamp(const std::vector<std::uint8_t>& hashed_data,
                             const std::string& hash_alg_oid,
                             const std::string& tsp_server_url,
                             const std::int32_t timeout_ms,
                             const std::string& policy_oid,
                             std::vector<std::uint8_t>& out_timestamp_token,
                             std::string& error_message) {
#if TAMGA_CRYPTONITE_ENABLED
    int rc = RET_OK;
    TimeStampReq_t* tsp_req = nullptr;
    AlgorithmIdentifier_t* digest_aid = nullptr;
    ByteArray* hash_ba = nullptr;
    ByteArray* req_der_ba = nullptr;
    TimeStampResp_t* tsp_resp = nullptr;
    ByteArray* resp_der_ba = nullptr;
    ContentInfo_t* ts_token = nullptr;
    ByteArray* token_der_ba = nullptr;
    OBJECT_IDENTIFIER_t* policy_oid_ptr = nullptr;
    OidNumbers* hash_oid_nums = nullptr;

    // 1. Створення digest_aid
    digest_aid = (AlgorithmIdentifier_t*)calloc(1, sizeof(AlgorithmIdentifier_t));
    if (digest_aid == nullptr) {
        error_message = "Unable to allocate AlgorithmIdentifier";
        goto cleanup;
    }

    hash_oid_nums = oids_get_oid_numbers_by_str(hash_alg_oid.c_str());
    if (hash_oid_nums == nullptr) {
        error_message = "Unsupported hash algorithm OID: " + hash_alg_oid;
        goto cleanup;
    }

    rc = pkix_set_oid(hash_oid_nums, &digest_aid->algorithm);
    if (rc != RET_OK) {
        error_message = BuildTspRcError("setting hash OID", rc);
        goto cleanup;
    }

    // 2. Створення hash ByteArray
    hash_ba = ba_alloc_from_uint8(hashed_data.data(), hashed_data.size());
    if (hash_ba == nullptr) {
        error_message = "Unable to allocate ByteArray for hash";
        goto cleanup;
    }

    // 3. Створення policy_oid_ptr
    {
        std::string policy_str = policy_oid;
        if (policy_str.empty()) {
            policy_str = "1.2.804.2.1.1.1.2.3.1"; // Дефолтна політика
        }
        rc = asn_create_oid_from_text(policy_str.c_str(), &policy_oid_ptr);
        if (rc != RET_OK) {
            error_message = BuildTspRcError("creating policy OID", rc);
            goto cleanup;
        }
    }

    // 4. Генерація запиту TSP
    rc = etspreq_generate_from_hash(digest_aid, hash_ba, nullptr, policy_oid_ptr, true, &tsp_req);
    if (rc != RET_OK) {
        error_message = BuildTspRcError("generating TSP request", rc);
        goto cleanup;
    }

    // 5. Кодування запиту в DER
    rc = tsreq_encode(tsp_req, &req_der_ba);
    if (rc != RET_OK) {
        error_message = BuildTspRcError("encoding TSP request", rc);
        goto cleanup;
    }

    // 6. Надсилання запиту через HttpClient
    {
        std::vector<std::uint8_t> req_data(ba_get_buf(req_der_ba), ba_get_buf(req_der_ba) + ba_get_len(req_der_ba));
        WriteTraceBinary("request.der", req_data);
        {
            std::ostringstream req_info;
            req_info << "POST " << tsp_server_url << "\n"
                     << "Content-Type: application/timestamp-query\n"
                     << "Accept: application/timestamp-reply\n"
                     << "Timeout-Ms: " << timeout_ms << "\n"
                     << "Request-Body-Bytes: " << req_data.size() << "\n";
            WriteTraceText("request.http.txt", req_info.str());
        }
        
        HttpPostResult post_res = HttpClient::Post(tsp_server_url, req_data, "application/timestamp-query", timeout_ms);
        if (!post_res.body.empty()) {
            WriteTraceBinary("response.der", post_res.body);
        }
        {
            std::ostringstream headers;
            headers << "URL: " << tsp_server_url << "\n"
                    << "HTTP-Status: " << post_res.status_code << "\n"
                    << "Succeeded: " << (post_res.succeeded ? "true" : "false") << "\n"
                    << "Message: " << post_res.message << "\n"
                    << "Request-Content-Type: application/timestamp-query\n"
                    << "Response-Content-Type: " << post_res.response_content_type << "\n"
                    << "Response-Body-Bytes: " << post_res.body.size() << "\n"
                    << "\n"
                    << post_res.response_headers;
            WriteTraceText("http-headers.txt", headers.str());
        }
        if (!post_res.succeeded) {
            error_message = "HTTP POST to TSP server failed: " + post_res.message + " (status: " + std::to_string(post_res.status_code) + ")";
            goto cleanup;
        }

        if (post_res.body.empty()) {
            error_message = "TSP server returned empty response";
            goto cleanup;
        }

        // 7. Декодування відповіді TSP
        resp_der_ba = ba_alloc_from_uint8(post_res.body.data(), post_res.body.size());
        if (resp_der_ba == nullptr) {
            error_message = "Unable to allocate ByteArray for TSP response";
            goto cleanup;
        }
    }

    tsp_resp = tsresp_alloc();
    if (tsp_resp == nullptr) {
        error_message = "Unable to allocate TimeStampResp struct";
        goto cleanup;
    }

    rc = tsresp_decode(tsp_resp, resp_der_ba);
    if (rc != RET_OK) {
        error_message = BuildTspRcError("decoding TSP response", rc);
        goto cleanup;
    }

    // 8. Перевірка статусу відповіді
    {
        long status_val = -1;
        rc = asn_INTEGER2long(&tsp_resp->status.status, &status_val);
        if (rc != RET_OK) {
            error_message = BuildTspRcError("extracting PKI status", rc);
            goto cleanup;
        }

        if (status_val != 0 && status_val != 1) {
            error_message = "TSP server rejected request with PKI status " + std::to_string(status_val);
            goto cleanup;
        }
    }

    // 9. Вилучення токену мітки часу
    rc = tsresp_get_ts_token(tsp_resp, &ts_token);
    if (rc != RET_OK || ts_token == nullptr) {
        error_message = BuildTspRcError("extracting TimeStampToken from response", rc);
        goto cleanup;
    }

    // 10. Кодування токену в DER
    rc = cinfo_encode(ts_token, &token_der_ba);
    if (rc != RET_OK) {
        error_message = BuildTspRcError("encoding TimeStampToken", rc);
        goto cleanup;
    }

    out_timestamp_token.assign(ba_get_buf(token_der_ba), ba_get_buf(token_der_ba) + ba_get_len(token_der_ba));

cleanup:
    if (digest_aid) {
        ASN_FREE(&AlgorithmIdentifier_desc, digest_aid);
    }
    if (hash_oid_nums) {
        oids_oid_numbers_free(hash_oid_nums);
    }
    if (hash_ba) {
        ba_free(hash_ba);
    }
    if (policy_oid_ptr) {
        ASN_FREE(&OBJECT_IDENTIFIER_desc, policy_oid_ptr);
    }
    if (tsp_req) {
        ASN_FREE(&TimeStampReq_desc, tsp_req);
    }
    if (req_der_ba) {
        ba_free(req_der_ba);
    }
    if (resp_der_ba) {
        ba_free(resp_der_ba);
    }
    if (tsp_resp) {
        tsresp_free(tsp_resp);
    }
    if (ts_token) {
        cinfo_free(ts_token);
    }
    if (token_der_ba) {
        ba_free(token_der_ba);
    }

    return error_message.empty();
#else
    (void)hashed_data;
    (void)hash_alg_oid;
    (void)tsp_server_url;
    (void)timeout_ms;
    (void)policy_oid;
    (void)out_timestamp_token;
    error_message = "Cryptonite is disabled in this build";
    return false;
#endif
}

} // namespace tamga::core
