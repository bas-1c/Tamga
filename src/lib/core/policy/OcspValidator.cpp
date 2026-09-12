#include "core/policy/OcspValidator.h"
#include "core/cryptonite/Internal.h"
#include "core/cryptonite/CertUtil.h"

#include "core/HttpClient.h"
#include "core/policy/EkuUtils.h"
#include "core/policy/Sha256Helper.h"
#include "core/policy/CertificateChainValidator.h"

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <memory>

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "asn1_utils.h"
#include "byte_array.h"
#include "cert.h"
#include "cryptonite_manager.h"
#include "oids.h"
#include "BasicOCSPResponse.h"
#include "CertStatus.h"
#include "ocsp_request.h"
#include "ocsp_request_engine.h"
#include "ocsp_response.h"
#include "OCSPResponseStatus.h"
#include "pkix_errors.h"
}
#endif

namespace tamga::core::policy {

namespace {

#if TAMGA_CRYPTONITE_ENABLED
template <typename T, void (*FreeFn)(T*)>
struct CDeleter {
    void operator()(T* value) const {
        FreeFn(value);
    }
};

using ScopedByteArray = std::unique_ptr<ByteArray, CDeleter<ByteArray, ba_free>>;
using ScopedCertificate = std::unique_ptr<Certificate_t, CDeleter<Certificate_t, cert_free>>;
using ScopedOcspRequest = std::unique_ptr<OCSPRequest_t, CDeleter<OCSPRequest_t, ocspreq_free>>;
using ScopedOcspResponse = std::unique_ptr<OCSPResponse_t, CDeleter<OCSPResponse_t, ocspresp_free>>;
using ScopedDigestAdapter = std::unique_ptr<DigestAdapter, CDeleter<DigestAdapter, digest_adapter_free>>;
using ScopedVerifyAdapter = std::unique_ptr<VerifyAdapter, CDeleter<VerifyAdapter, verify_adapter_free>>;

struct OcspResponseStatusDeleter {
    void operator()(OCSPResponseStatus_t* value) const {
        ASN_FREE(&OCSPResponseStatus_desc, value);
    }
};

struct BasicOcspResponseDeleter {
    void operator()(BasicOCSPResponse_t* value) const {
        ASN_FREE(&BasicOCSPResponse_desc, value);
    }
};

// ADR-027: локальна копія прибрана — спільні обгортки живуть у
// `core/cryptonite/Internal.h`.
// Копія повертала nullptr на порожньому вході; на цьому тримається,
// зокрема, відхилення порожнього тіла OCSP-відповіді.
using cryptonite_detail::MakeByteArrayOrNull;

std::vector<std::uint8_t> ToVector(const ByteArray* data) {
    if (data == nullptr) {
        return {};
    }
    const auto* begin = ba_get_buf(data);
    return std::vector<std::uint8_t>(begin, begin + ba_get_len(data));
}

std::vector<std::uint8_t> ToVector(const OCTET_STRING_t& data) {
    return std::vector<std::uint8_t>(data.buf, data.buf + data.size);
}

std::vector<std::uint8_t> EncodeSerialNumber(const CertificateSerialNumber_t& serial_number) {
    ByteArray* encoded_raw = nullptr;
    if (asn_encode_ba(&CertificateSerialNumber_desc, &serial_number, &encoded_raw) != RET_OK ||
        encoded_raw == nullptr) {
        return {};
    }
    ScopedByteArray encoded(encoded_raw);
    return ToVector(encoded.get());
}

detail::OcspCertIdFields ExtractCertIdFields(const CertID_t& cert_id) {
    detail::OcspCertIdFields fields;
    fields.issuer_name_hash = ToVector(cert_id.issuerNameHash);
    fields.issuer_key_hash = ToVector(cert_id.issuerKeyHash);
    fields.serial_number = EncodeSerialNumber(cert_id.serialNumber);
    return fields;
}

// ADR-027: копія прибрана — декодування живе в `core/cryptonite/CertUtil`.
using cryptonite_detail::DecodeCertificateDerInto;

// Чи certificate криптографічно підписаний issuer (як VerifyByIssuer у
// CertificateChainValidator — тут своя мінімальна копія, щоб не тягнути
// internal linkage іншого модуля заради однієї перевірки).
bool VerifiedByIssuer(const Certificate_t* certificate, Certificate_t* issuer) {
    if (certificate == nullptr || issuer == nullptr) {
        return false;
    }
    VerifyAdapter* adapter_raw = nullptr;
    if (verify_adapter_init_by_cert(issuer, &adapter_raw) != RET_OK || adapter_raw == nullptr) {
        verify_adapter_free(adapter_raw);
        return false;
    }
    ScopedVerifyAdapter adapter(adapter_raw);
    return cert_verify(certificate, adapter.get()) == RET_OK;
}

struct OcspResponseCerts {
    Certificate_t** certs{nullptr};
    int count{0};

    ~OcspResponseCerts() {
        for (int i = 0; i < count; ++i) {
            if (certs != nullptr && certs[i] != nullptr) {
                cert_free(certs[i]);
            }
        }
        std::free(certs);
    }
};

// Перевіряє підпис САМОЇ OCSP-відповіді через делегованого responder-
// сертифіката, вбудованого у BasicOCSPResponse.certs (RFC 6960 §4.2.2.2):
// кандидат має бути підписаний тим самим issuer, що й запитуваний CertID,
// нести EKU id-kp-OCSPSigning, і фактично перевіряти підпис відповіді.
// issuer тут уже довірений (прийшов з trust-validated шляху сертифікатів у
// RevocationEngine), тож "підписаний issuer" — легітимна прив'язка
// делегування. Повертає true, щойно знайдено кандидата, чий ключ дійсно
// підтверджує підпис відповіді.
bool VerifyResponseWithDelegatedResponder(OCSPResponse_t* response, Certificate_t* issuer) {
    Certificate_t** certs_raw = nullptr;
    int certs_len = 0;
    if (ocspresp_get_certs(response, &certs_raw, &certs_len) != RET_OK || certs_len <= 0) {
        return false;
    }
    OcspResponseCerts owned;
    owned.certs = certs_raw;
    owned.count = certs_len;

    for (int i = 0; i < certs_len; ++i) {
        Certificate_t* candidate = owned.certs[i];
        if (candidate == nullptr) {
            continue;
        }
        if (!VerifiedByIssuer(candidate, issuer) || !HasOcspSigningEku(candidate)) {
            continue;
        }
        VerifyAdapter* candidate_adapter_raw = nullptr;
        if (verify_adapter_init_by_cert(candidate, &candidate_adapter_raw) != RET_OK ||
            candidate_adapter_raw == nullptr) {
            verify_adapter_free(candidate_adapter_raw);
            continue;
        }
        ScopedVerifyAdapter candidate_adapter(candidate_adapter_raw);
        if (ocspresp_verify(response, candidate_adapter.get()) == RET_OK) {
            return true;
        }
    }
    return false;
}

bool EncodeRequestAndExtractCertId(OCSPRequest_t* request,
                                   std::vector<std::uint8_t>& request_der,
                                   detail::OcspCertIdFields& requested_cert_id,
                                   std::string& message) {
    if (request == nullptr ||
        request->tbsRequest.requestList.list.count <= 0 ||
        request->tbsRequest.requestList.list.array[0] == nullptr) {
        message = "Generated OCSP request does not contain CertID.";
        return false;
    }
    requested_cert_id = ExtractCertIdFields(request->tbsRequest.requestList.list.array[0]->reqCert);

    ByteArray* encoded_raw = nullptr;
    if (ocspreq_encode(request, &encoded_raw) != RET_OK || encoded_raw == nullptr) {
        message = "Failed to encode OCSP request.";
        return false;
    }
    ScopedByteArray encoded(encoded_raw);
    request_der = ToVector(encoded.get());
    if (request_der.empty()) {
        message = "Generated OCSP request is empty.";
        return false;
    }
    return true;
}

bool GenerateRequestWithDefaultNonce(Certificate_t* issuer,
                                    Certificate_t* signer,
                                    OCSPRequest_t** request,
                                    std::string& message) {
    if (eocspreq_generate_from_cert(issuer, signer, request) != RET_OK || request == nullptr || *request == nullptr) {
        message = "Failed to generate OCSP request.";
        return false;
    }
    return true;
}

bool GenerateRequestWithoutNonce(Certificate_t* issuer,
                                 Certificate_t* signer,
                                 OCSPRequest_t** request,
                                 std::string& message) {
    VerifyAdapter* issuer_adapter_raw = nullptr;
    if (verify_adapter_init_by_cert(issuer, &issuer_adapter_raw) != RET_OK || issuer_adapter_raw == nullptr) {
        verify_adapter_free(issuer_adapter_raw);
        message = "Failed to initialize OCSP issuer verify adapter.";
        return false;
    }
    ScopedVerifyAdapter issuer_adapter(issuer_adapter_raw);

    DigestAdapter* digest_adapter_raw = nullptr;
    if (digest_adapter_init_default(&digest_adapter_raw) != RET_OK || digest_adapter_raw == nullptr) {
        digest_adapter_free(digest_adapter_raw);
        message = "Failed to initialize OCSP digest adapter.";
        return false;
    }
    ScopedDigestAdapter digest_adapter(digest_adapter_raw);

    OcspRequestEngine* engine_raw = nullptr;
    if (eocspreq_alloc(false, issuer_adapter.get(), nullptr, nullptr, digest_adapter.get(), &engine_raw) != RET_OK ||
        engine_raw == nullptr) {
        eocspreq_free(engine_raw);
        message = "Failed to initialize OCSP request engine.";
        return false;
    }
    std::unique_ptr<OcspRequestEngine, decltype(&eocspreq_free)> engine(engine_raw, eocspreq_free);

    if (eocspreq_add_cert(engine.get(), signer) != RET_OK) {
        message = "Failed to add signer certificate to OCSP request.";
        return false;
    }

    if (eocspreq_generate(engine.get(), nullptr, request) != RET_OK || request == nullptr || *request == nullptr) {
        message = "Failed to generate OCSP request.";
        return false;
    }
    return true;
}

bool BuildRequestDer(const OcspValidationInput& input,
                     std::vector<std::uint8_t>& request_der,
                     detail::OcspCertIdFields& requested_cert_id,
                     std::string& message) {
    ScopedCertificate signer(cert_alloc());
    ScopedCertificate issuer(cert_alloc());
    if (!signer || !issuer) {
        message = "Failed to allocate certificate objects.";
        return false;
    }

    if (!DecodeCertificateDerInto(input.signer_certificate_der, signer.get())) {
        message = "Failed to decode signer certificate.";
        return false;
    }

    if (!DecodeCertificateDerInto(input.issuer_certificate_der, issuer.get())) {
        message = "Failed to decode issuer certificate.";
        return false;
    }

    OCSPRequest_t* request_raw = nullptr;
    if (input.use_nonce) {
        if (!GenerateRequestWithDefaultNonce(issuer.get(), signer.get(), &request_raw, message)) {
            return false;
        }
    } else {
        // eocspreq_generate_from_cert always emits a nonce; the configurable no-nonce path
        // must use the lower-level request engine while preserving the same signer CertID.
        if (!GenerateRequestWithoutNonce(issuer.get(), signer.get(), &request_raw, message)) {
            return false;
        }
    }
    ScopedOcspRequest request(request_raw);
    return EncodeRequestAndExtractCertId(request.get(), request_der, requested_cert_id, message);
}

std::vector<detail::OcspMappedCertificateStatus> ExtractResponseCertIds(OCSPResponse_t* response) {
    std::vector<detail::OcspMappedCertificateStatus> cert_ids;
    if (response == nullptr || response->responseBytes == nullptr) {
        return cert_ids;
    }

    auto* basic_raw = static_cast<BasicOCSPResponse_t*>(asn_decode_with_alloc(
        &BasicOCSPResponse_desc,
        response->responseBytes->response.buf,
        response->responseBytes->response.size));
    std::unique_ptr<BasicOCSPResponse_t, BasicOcspResponseDeleter> basic(basic_raw);
    if (!basic) {
        return cert_ids;
    }

    const int count = basic->tbsResponseData.responses.list.count;
    cert_ids.reserve(count > 0 ? static_cast<std::size_t>(count) : 0U);
    for (int i = 0; i < count; ++i) {
        const SingleResponse_t* single = basic->tbsResponseData.responses.list.array[i];
        if (single == nullptr) {
            continue;
        }
        detail::OcspMappedCertificateStatus mapped;
        mapped.cert_id = ExtractCertIdFields(single->certID);
        cert_ids.push_back(std::move(mapped));
    }
    return cert_ids;
}

std::vector<detail::OcspMappedCertificateStatus> ExtractStatusesWithCryptoniteApi(OCSPResponse_t* response) {
    std::vector<detail::OcspMappedCertificateStatus> statuses;
    OcspCertStatus** api_statuses = nullptr;
    int api_statuses_len = 0;
    if (ocspresp_get_certs_status(response, &api_statuses, &api_statuses_len) != RET_OK ||
        api_statuses_len <= 0) {
        return statuses;
    }

    statuses.reserve(static_cast<std::size_t>(api_statuses_len));
    for (int i = 0; i < api_statuses_len; ++i) {
        OcspCertStatus* entry = api_statuses[i];
        if (entry != nullptr) {
            detail::OcspMappedCertificateStatus mapped;
            if (entry->serial_number != nullptr) {
                mapped.cert_id.serial_number = EncodeSerialNumber(*entry->serial_number);
            }
            mapped.status = entry->status != nullptr ? entry->status : "unknown";
            mapped.revocation_time = entry->revocationTime;
            statuses.push_back(std::move(mapped));
        }
        ocspresp_certs_status_free(entry);
    }
    std::free(api_statuses);
    return statuses;
}

std::vector<detail::OcspMappedCertificateStatus> ExtractResponseStatuses(OCSPResponse_t* response) {
    auto cert_ids = ExtractResponseCertIds(response);
    auto api_statuses = ExtractStatusesWithCryptoniteApi(response);

    // ocspresp_get_certs_status exposes status and serial only. Full CertID binding also
    // requires issuerNameHash and issuerKeyHash, so BasicOCSPResponse CertID remains the
    // authority and the cryptonite API supplies status values by SingleResponse order.
    return detail::MergeOcspStatusesByResponseOrder(std::move(cert_ids), api_statuses);
}
#endif

bool SameCertIdFields(const detail::OcspCertIdFields& left, const detail::OcspCertIdFields& right) {
    return left.issuer_name_hash == right.issuer_name_hash &&
           left.issuer_key_hash == right.issuer_key_hash &&
           left.serial_number == right.serial_number;
}

} // namespace

namespace detail {

RevocationStatus MapOcspStatusForRequestedCertId(
    const OcspCertIdFields& requested,
    const std::vector<OcspMappedCertificateStatus>& statuses,
    bool& revoked,
    time_t& revocation_time,
    std::string& message) {
    revoked = false;
    revocation_time = 0;
    if (statuses.empty()) {
        message = "OCSP response does not contain certificate status records.";
        return RevocationStatus::Unknown;
    }

    for (const auto& entry : statuses) {
        if (!SameCertIdFields(requested, entry.cert_id)) {
            continue;
        }
        if (entry.status == "revoked") {
            revoked = true;
            revocation_time = entry.revocation_time;
            return RevocationStatus::Revoked;
        }
        if (entry.status == "good") {
            return RevocationStatus::Good;
        }
        if (entry.status == "unknown") {
            return RevocationStatus::Unknown;
        }
    }

    message = "OCSP response does not contain status for requested certificate.";
    return RevocationStatus::Unknown;
}

std::vector<OcspMappedCertificateStatus> MergeOcspStatusesByResponseOrder(
    std::vector<OcspMappedCertificateStatus> cert_ids,
    const std::vector<OcspMappedCertificateStatus>& api_statuses) {
    const auto count = std::min(cert_ids.size(), api_statuses.size());
    for (std::size_t i = 0; i < count; ++i) {
        cert_ids[i].status = api_statuses[i].status.empty() ? "unknown" : api_statuses[i].status;
        cert_ids[i].revocation_time = api_statuses[i].revocation_time;
    }
    for (auto& cert_id : cert_ids) {
        if (cert_id.status.empty()) {
            cert_id.status = "unknown";
        }
    }
    return cert_ids;
}

} // namespace detail

namespace {

#if TAMGA_CRYPTONITE_ENABLED
RevocationStatus DecodeAndMapResponse(const OcspValidationInput& input,
                                      const detail::OcspCertIdFields& requested_cert_id,
                                      const std::vector<std::uint8_t>& response_body,
                                      bool is_embedded_response,
                                      bool& revoked,
                                      time_t& revocation_time,
                                      std::string& message) {
    ScopedByteArray encoded(MakeByteArrayOrNull(response_body));
    if (!encoded) {
        message = "OCSP response body is empty.";
        return RevocationStatus::Invalid;
    }

    ScopedOcspResponse response(ocspresp_alloc());
    if (!response || ocspresp_decode(response.get(), encoded.get()) != RET_OK) {
        message = "Failed to decode OCSP response.";
        return RevocationStatus::Invalid;
    }

    OCSPResponseStatus_t* response_status_raw = nullptr;
    if (ocspresp_get_status(response.get(), &response_status_raw) != RET_OK || response_status_raw == nullptr) {
        message = "Failed to read OCSP response status.";
        return RevocationStatus::Invalid;
    }
    std::unique_ptr<OCSPResponseStatus_t, OcspResponseStatusDeleter> response_status(response_status_raw);

    long response_status_value = -1;
    if (asn_INTEGER2long(response_status.get(), &response_status_value) != RET_OK) {
        message = "Failed to convert OCSP response status.";
        return RevocationStatus::Invalid;
    }
    if (response_status_value != OCSPResponseStatus_successful) {
        message = "OCSP responder returned non-success status.";
        return RevocationStatus::ResponderUnavailable;
    }
    if (response->responseBytes == nullptr) {
        message = "OCSP successful response does not contain responseBytes.";
        return RevocationStatus::Invalid;
    }

    time_t validation_time_sec = std::time(nullptr);
    if (!input.validation_time.empty()) {
        time_t parsed_time = 0;
        if (ParseIso8601Time(input.validation_time, parsed_time)) {
            validation_time_sec = parsed_time;
        }
    }

    // WP-5: `timeout_ms` bounds a LIVE request/response round-trip (responder
    // took too long / clock skew) — it has no meaningful reading for
    // pre-supplied/embedded evidence (e.g. XAdES RevocationValues), which is
    // routinely checked long after it was produced. Applying it there would
    // reject genuinely good, long-term evidence just because it is "old".
    // С-12: раніше для embedded-доказів передавався -1, що ВИМИКАЄ перевірку
    // `producedAt` повністю. Разом із тим, що `nextUpdate` за RFC 6960
    // необовʼязковий (і його відсутність Tamga свідомо трактує як
    // неістотну), це давало відповіді БЕЗ ЖОДНОЇ часової межі: давня
    // легітимно підписана `good`-відповідь приймалася як доказ довільно
    // пізніше.
    //
    // Тепер межа є, але прив'язана до `validation_time`, а не до "зараз":
    // vendor перевіряє `current_time > producedAt + timeout`, де
    // `current_time` — саме момент оцінки підпису. Тобто історична мітка,
    // видана коли доказ був свіжим, лишається дійсною — це і є сенс LTV.
    //
    // Межа свідомо щедра: для XAdES-LT/PAdES-LT докази збираються під час
    // підписання, тож різниця з `validation_time` — хвилини. Рік покриває
    // навіть відкладене архівування, але відсікає доказ, зібраний за роки до
    // моменту, який він начебто підтверджує.
    constexpr int kEmbeddedEvidenceMaxAgeMinutes = 366 * 24 * 60;
    const int timeout_minutes = is_embedded_response
        ? kEmbeddedEvidenceMaxAgeMinutes
        : (input.timeout_ms > 0 ? (input.timeout_ms + 59999) / 60000 : 1);
    const int validity_check = eocspreq_validate_resp(response.get(), validation_time_sec, timeout_minutes);
    // RET_PKIX_OCSP_REQ_RESPONSE_NEXTUP_WARNING is a non-fatal advisory the
    // engine returns even on an otherwise-successful check (RFC 6960 allows
    // omitting nextUpdate — it means "no stated freshness bound", not "stale").
    if (validity_check != RET_OK && validity_check != RET_PKIX_OCSP_REQ_RESPONSE_NEXTUP_WARNING) {
        message = "OCSP response validity window check failed.";
        return RevocationStatus::Invalid;
    }

    ScopedCertificate issuer(cert_alloc());
    if (!issuer || !DecodeCertificateDerInto(input.issuer_certificate_der, issuer.get())) {
        message = "Failed to decode issuer certificate for OCSP response signature validation.";
        return RevocationStatus::Invalid;
    }

    VerifyAdapter* adapter_raw = nullptr;
    if (verify_adapter_init_by_cert(issuer.get(), &adapter_raw) != RET_OK || adapter_raw == nullptr) {
        verify_adapter_free(adapter_raw);
        message = "Failed to initialize OCSP response signature validation adapter.";
        return RevocationStatus::Invalid;
    }
    ScopedVerifyAdapter adapter(adapter_raw);
    // Спершу пробуємо найпростіший випадок — issuer підписав відповідь
    // напряму. Якщо ні, це може бути делегований responder (RFC 6960
    // §4.2.2.2, звичайна практика для укр. КНЕДП): шукаємо серед
    // BasicOCSPResponse.certs сертифікат, виданий цим-таки issuer з EKU
    // id-kp-OCSPSigning, чий ключ дійсно підтверджує підпис відповіді.
    if (ocspresp_verify(response.get(), adapter.get()) != RET_OK &&
        !VerifyResponseWithDelegatedResponder(response.get(), issuer.get())) {
        message = "OCSP response signature validation failed.";
        return RevocationStatus::Invalid;
    }

    return detail::MapOcspStatusForRequestedCertId(
        requested_cert_id,
        ExtractResponseStatuses(response.get()),
        revoked,
        revocation_time,
        message);
}
#endif
} // namespace

OcspValidationResult OcspValidator::Validate(const OcspValidationInput& input) const {
    OcspValidationResult result;

    if (input.url.empty() && input.response_der.empty()) {
        result.checked = false;
        result.status = RevocationStatus::NotChecked;
        result.message = "OCSP endpoint is not configured.";
        return result;
    }

#if !TAMGA_CRYPTONITE_ENABLED
    result.checked = false;
    result.status = RevocationStatus::NotChecked;
    result.message = "OCSP validation is not supported without cryptonite.";
    return result;
#else
    std::vector<std::uint8_t> request_der;
    detail::OcspCertIdFields requested_cert_id;
    if (!BuildRequestDer(input, request_der, requested_cert_id, result.message)) {
        result.checked = false;
        result.status = RevocationStatus::NotChecked;
        return result;
    }

    result.request_evidence_id = ComputeSha256Hex(request_der);

    const bool is_embedded_response = !input.response_der.empty();
    std::vector<std::uint8_t> response_body;
    if (is_embedded_response) {
        response_body = input.response_der;
        result.checked = true;
        result.responder_answered = true;
    } else {
        const auto http = HttpClient::Post(
            input.url,
            request_der,
            "application/ocsp-request",
            "application/ocsp-response",
            input.timeout_ms);
        result.checked = true;
        if (!http.succeeded || http.status_code < 200 || http.status_code >= 300) {
            result.status = RevocationStatus::ResponderUnavailable;
            result.message = http.message.empty()
                ? "OCSP responder unavailable."
                : "OCSP responder unavailable: " + http.message;
            if (!http.body.empty()) {
                result.response_evidence_id = ComputeSha256Hex(http.body);
            }
            return result;
        }
        response_body = http.body;
        result.responder_answered = true;
    }

    result.response_evidence_id = ComputeSha256Hex(response_body);
    result.status = DecodeAndMapResponse(input, requested_cert_id, response_body, is_embedded_response,
                                         result.revoked, result.revocation_time, result.message);
    if (result.status == RevocationStatus::Good || result.status == RevocationStatus::Revoked) {
        result.response_der = std::move(response_body);
    }
    return result;
#endif
}

} // namespace tamga::core::policy
