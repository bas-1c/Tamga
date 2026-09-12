#include "core/policy/AiaIssuerFetcher.h"
#include "util/Hex.h"
#include "core/cryptonite/Internal.h"
#include "core/cryptonite/CertUtil.h"

#include "core/HttpClient.h"
#include "core/KeyParsers.h"
#include "util/FileSystem.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <set>
#include <sstream>
#include <system_error>

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "AccessDescription.h"
#include "AuthorityInfoAccessSyntax.h"
#include "CertificateSet.h"
#include "Extension.h"
#include "Extensions.h"
#include "GeneralName.h"
#include "asn1_utils.h"
#include "byte_array.h"
#include "cert.h"
#include "content_info.h"
#include "signed_data.h"
}
#endif

namespace tamga::core::policy {
namespace {

// ADR-027: копія прибрана — одна реалізація в `util/Hex`.
using tamga::util::HexFromUInt64;

// ADR-027: копія прибрана — спільна реалізація в `util/Hex.h`.
using tamga::util::StableDerHash;

// ADR-027: копія прибрана — спільна реалізація в `core/HttpClient.h`.
using tamga::core::IsHttpSuccess;

bool IsLikelyHttpUrl(const std::string& url) {
    return url.rfind("http://", 0) == 0 || url.rfind("https://", 0) == 0;
}

void AddUniqueUrl(std::vector<std::string>& urls, std::string url) {
    if (url.empty() || !IsLikelyHttpUrl(url)) {
        return;
    }
    if (std::find(urls.begin(), urls.end(), url) == urls.end()) {
        urls.push_back(std::move(url));
    }
}

#if TAMGA_CRYPTONITE_ENABLED
// ADR-027: локальна копія прибрана — спільні обгортки живуть у
// `core/cryptonite/Internal.h`.
// Тутешня копія повертала nullptr на порожньому вході, і всі місця виклику
// на це спираються — тому саме `MakeByteArrayOrNull`, а не `MakeByteArray`.
using cryptonite_detail::MakeByteArrayOrNull;

// ADR-027: копія прибрана — декодування живе в `core/cryptonite/CertUtil`.
using cryptonite_detail::DecodeCertificateDer;

bool IsDecodableCertificate(const std::vector<std::uint8_t>& der) {
    return DecodeCertificateDer(der) != nullptr;
}

// ADR-027: копія прибрана. Та сама семантика вже була в
// `core/cryptonite/CertUtil.h` — просто цей модуль її не включав.
using cryptonite_detail::EncodeCertificateDer;

bool IsOid(const OBJECT_IDENTIFIER_t* oid, const std::vector<unsigned long>& expected) {
    if (oid == nullptr || expected.empty()) {
        return false;
    }
    unsigned long arcs[16]{};
    const int count = OBJECT_IDENTIFIER_get_arcs(oid, arcs, sizeof(arcs[0]), 16);
    if (count < 0 || static_cast<std::size_t>(count) != expected.size()) {
        return false;
    }
    for (std::size_t i = 0; i < expected.size(); ++i) {
        if (arcs[i] != expected[i]) {
            return false;
        }
    }
    return true;
}

void AppendAiaUrlsFromDer(const std::vector<std::uint8_t>& aia_der, std::vector<std::string>& urls) {
    auto* aia = static_cast<AuthorityInfoAccessSyntax_t*>(
        asn_decode_with_alloc(get_AuthorityInfoAccessSyntax_desc(), aia_der.data(), aia_der.size()));
    if (aia == nullptr) {
        return;
    }

    const std::vector<unsigned long> kCaIssuers = {1, 3, 6, 1, 5, 5, 7, 48, 2};
    for (int i = 0; i < aia->list.count; ++i) {
        const AccessDescription_t* description = aia->list.array[i];
        if (description == nullptr || !IsOid(&description->accessMethod, kCaIssuers)) {
            continue;
        }
        if (description->accessLocation.present != GeneralName_PR_uniformResourceIdentifier) {
            continue;
        }
        const auto& uri = description->accessLocation.choice.uniformResourceIdentifier;
        if (uri.buf != nullptr && uri.size > 0) {
            AddUniqueUrl(urls, std::string(reinterpret_cast<const char*>(uri.buf), uri.size));
        }
    }

    ASN_FREE(get_AuthorityInfoAccessSyntax_desc(), aia);
}

void AppendAiaUrlsFromCertificate(const std::vector<std::uint8_t>& certificate_der, std::vector<std::string>& urls) {
    const cryptonite_detail::ScopedCert certificate = DecodeCertificateDer(certificate_der);
    if (!certificate) {
        return;
    }

    TBSCertificate_t* tbs_raw = nullptr;
    const int rc = cert_get_tbs_cert(certificate.get(), &tbs_raw);
    if (rc != RET_OK || tbs_raw == nullptr) {
        return;
    }

    const std::unique_ptr<TBSCertificate_t, void (*)(TBSCertificate_t*)> tbs(
        tbs_raw,
        [](TBSCertificate_t* value) { ASN_FREE(get_TBSCertificate_desc(), value); });

    const std::vector<unsigned long> kAia = {1, 3, 6, 1, 5, 5, 7, 1, 1};
    if (tbs->extensions == nullptr) {
        return;
    }
    for (int i = 0; i < tbs->extensions->list.count; ++i) {
        const Extension_t* extension = tbs->extensions->list.array[i];
        if (extension == nullptr || !IsOid(&extension->extnID, kAia)) {
            continue;
        }
        if (extension->extnValue.buf != nullptr && extension->extnValue.size > 0) {
            AppendAiaUrlsFromDer(
                std::vector<std::uint8_t>(extension->extnValue.buf,
                                          extension->extnValue.buf + extension->extnValue.size),
                urls);
        }
    }
}

void AppendPkcs7Certificates(const std::vector<std::uint8_t>& der,
                             std::vector<std::vector<std::uint8_t>>& certificates) {
    ByteArray* ba = MakeByteArrayOrNull(der);
    ContentInfo_t* content_info = cinfo_alloc();
    SignedData_t* signed_data = nullptr;
    CertificateSet_t* certs = nullptr;
    if (ba == nullptr || content_info == nullptr) {
        ba_free(ba);
        cinfo_free(content_info);
        return;
    }

    int rc = cinfo_decode(content_info, ba);
    ba_free(ba);
    if (rc != RET_OK) {
        cinfo_free(content_info);
        return;
    }

    rc = cinfo_get_signed_data(content_info, &signed_data);
    cinfo_free(content_info);
    if (rc != RET_OK || signed_data == nullptr) {
        ASN_FREE(get_SignedData_desc(), signed_data);
        return;
    }

    rc = sdata_get_certs(signed_data, &certs);
    ASN_FREE(get_SignedData_desc(), signed_data);
    if (rc != RET_OK || certs == nullptr) {
        ASN_FREE(get_CertificateSet_desc(), certs);
        return;
    }

    for (int i = 0; i < certs->list.count; ++i) {
        const CertificateChoices_t* choice = certs->list.array[i];
        if (choice == nullptr || choice->present != CertificateChoices_PR_certificate) {
            continue;
        }
        std::vector<std::uint8_t> certificate_der;
        if (EncodeCertificateDer(&choice->choice.certificate, certificate_der)) {
            certificates.push_back(std::move(certificate_der));
        }
    }
    ASN_FREE(get_CertificateSet_desc(), certs);
}
#endif

void AppendRawScannedAiaUrls(const std::vector<std::uint8_t>& der, std::vector<std::string>& urls) {
    const std::vector<std::uint8_t> kAiaOid = {0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01};
    const std::vector<std::uint8_t> kCaIssuersOid = {0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02};

    auto it = std::search(der.begin(), der.end(), kAiaOid.begin(), kAiaOid.end());
    while (it != der.end()) {
        const auto search_start = static_cast<std::size_t>(std::distance(der.begin(), it));
        const auto next = std::search(it + 1, der.end(), kAiaOid.begin(), kAiaOid.end());
        const std::size_t search_end = next == der.end()
            ? der.size()
            : static_cast<std::size_t>(std::distance(der.begin(), next));

        auto ca_it = std::search(der.begin() + static_cast<std::ptrdiff_t>(search_start),
                                 der.begin() + static_cast<std::ptrdiff_t>(search_end),
                                 kCaIssuersOid.begin(),
                                 kCaIssuersOid.end());
        while (ca_it != der.begin() + static_cast<std::ptrdiff_t>(search_end)) {
            const std::size_t ca_pos = static_cast<std::size_t>(std::distance(der.begin(), ca_it));
            const std::size_t uri_tag = ca_pos + kCaIssuersOid.size();
            if (uri_tag + 2U <= der.size() && der[uri_tag] == 0x86) {
                const std::size_t uri_len = der[uri_tag + 1U];
                if (uri_tag + 2U + uri_len <= der.size()) {
                    AddUniqueUrl(urls, std::string(der.begin() + static_cast<std::ptrdiff_t>(uri_tag + 2U),
                                                   der.begin() + static_cast<std::ptrdiff_t>(uri_tag + 2U + uri_len)));
                }
            }
            ca_it = std::search(ca_it + 1,
                                der.begin() + static_cast<std::ptrdiff_t>(search_end),
                                kCaIssuersOid.begin(),
                                kCaIssuersOid.end());
        }
        it = next;
    }
}

} // namespace

std::vector<std::string> AiaIssuerFetcher::ExtractCaIssuersUrls(
    const std::vector<std::uint8_t>& certificate_der) {
    std::vector<std::string> urls;
#if TAMGA_CRYPTONITE_ENABLED
    AppendAiaUrlsFromCertificate(certificate_der, urls);
#endif
    AppendRawScannedAiaUrls(certificate_der, urls);
    return urls;
}

std::vector<std::vector<std::uint8_t>> AiaIssuerFetcher::ParseDownloadedCertificates(
    const std::vector<std::uint8_t>& body,
    std::string& error_message) {
    std::vector<std::vector<std::uint8_t>> certificates;
    error_message.clear();
    if (body.empty()) {
        error_message = "AIA issuer response is empty";
        return certificates;
    }

    if (body.front() == 0x30) {
#if TAMGA_CRYPTONITE_ENABLED
        if (IsDecodableCertificate(body)) {
            certificates.push_back(body);
            return certificates;
        }
        AppendPkcs7Certificates(body, certificates);
#endif
        if (certificates.empty()) {
            error_message = "AIA issuer response is neither DER certificate nor supported PKCS#7";
        }
        return certificates;
    }

    std::vector<tamga::core::PemDerLoader::PemBlock> blocks;
    tamga::core::PemDerLoader::LoadOptions options;
    options.strict_mode = false;
    if (!tamga::core::PemDerLoader::LoadAll(body, blocks, error_message, options)) {
        return certificates;
    }

    for (const auto& block : blocks) {
        if (block.type.find("CERTIFICATE") != std::string::npos) {
#if TAMGA_CRYPTONITE_ENABLED
            if (IsDecodableCertificate(block.der_payload)) {
                certificates.push_back(block.der_payload);
            }
#else
            certificates.push_back(block.der_payload);
#endif
            continue;
        }
        if (block.type.find("PKCS7") != std::string::npos ||
            block.type.find("PKCS #7") != std::string::npos ||
            block.type.find("CMS") != std::string::npos) {
#if TAMGA_CRYPTONITE_ENABLED
            AppendPkcs7Certificates(block.der_payload, certificates);
#endif
        }
    }

    if (certificates.empty() && error_message.empty()) {
        error_message = "AIA issuer PEM response does not contain certificates";
    }
    return certificates;
}

AiaIssuerFetchResult AiaIssuerFetcher::FetchMissingIssuers(const AiaIssuerFetchInput& input) const {
    AiaIssuerFetchResult result;
    std::ostringstream debug;
    debug << "AIA:\n"
          << "  networkEnabled=" << (input.network_enabled ? "true" : "false") << "\n"
          << "  workDir=" << input.work_dir << "\n"
          << "  seedCertificates=" << input.seed_certificates_der.size() << "\n";
    if (!input.network_enabled) {
        result.message = "AIA issuer fetch skipped: network access was not explicitly enabled";
        debug << "  attempted=false\n"
              << "  reason=" << result.message << "\n";
        result.debug_log = debug.str();
        return result;
    }
    if (input.work_dir.empty() || input.seed_certificates_der.empty() || input.max_depth == 0U || input.max_urls == 0U) {
        result.message = "AIA issuer fetch skipped: empty input";
        debug << "  attempted=false\n"
              << "  reason=" << result.message << "\n";
        result.debug_log = debug.str();
        return result;
    }

    const std::filesystem::path intermediate_dir = std::filesystem::u8path(input.work_dir) / "intermediate-store";
    std::vector<std::vector<std::uint8_t>> queue = input.seed_certificates_der;
    std::set<std::string> seen_cert_hashes;
    std::set<std::string> attempted_urls;
    for (const auto& certificate : queue) {
        seen_cert_hashes.insert(StableDerHash(certificate));
    }

    std::size_t processed = 0;
    std::size_t depth = 0;
    while (processed < queue.size() && depth < input.max_depth && attempted_urls.size() < input.max_urls) {
        const std::size_t level_end = queue.size();
        for (; processed < level_end && attempted_urls.size() < input.max_urls; ++processed) {
            const auto urls = ExtractCaIssuersUrls(queue[processed]);
            debug << "  seed[" << processed << "] caIssuersUrls=" << urls.size() << "\n";
            for (const auto& url : urls) {
                debug << "    url=" << url << "\n";
            }
            for (const auto& url : urls) {
                if (attempted_urls.size() >= input.max_urls || !attempted_urls.insert(url).second) {
                    continue;
                }
                result.attempted = true;
                debug << "  fetch=" << url << "\n";

                tamga::core::HttpPostResult response;
                const std::size_t attempts = std::max<std::size_t>(1U, input.max_retries);
                for (std::size_t attempt = 0; attempt < attempts; ++attempt) {
                    response = tamga::core::HttpClient::Get(
                        url,
                        "application/pkix-cert, application/pkcs7-mime, application/x-pkcs7-certificates, */*",
                        input.timeout_ms);
                    if (IsHttpSuccess(response)) {
                        break;
                    }
                }
                if (!IsHttpSuccess(response)) {
                    debug << "    status=" << response.status_code
                          << " succeeded=" << (response.succeeded ? "true" : "false")
                          << " message=" << response.message << "\n";
                    continue;
                }
                debug << "    status=" << response.status_code
                      << " bodyBytes=" << response.body.size() << "\n";

                std::string parse_error;
                const auto downloaded = ParseDownloadedCertificates(response.body, parse_error);
                debug << "    parsedCertificates=" << downloaded.size();
                if (!parse_error.empty()) {
                    debug << " parseError=" << parse_error;
                }
                debug << "\n";

                for (auto& certificate : downloaded) {
                    const std::string hash = StableDerHash(certificate);
                    if (!seen_cert_hashes.insert(hash).second) {
                        debug << "    duplicateCertificateHash=" << hash << "\n";
                        continue;
                    }
                    const auto cache_path = intermediate_dir / ("aia-" + hash + ".cer");
                    if (tamga::util::WriteBinaryFileAtomic(cache_path, certificate)) {
                        ++result.cached_count;
                        debug << "    cached=" << cache_path.u8string() << "\n";
                    } else {
                        debug << "    cacheFailed=" << cache_path.u8string() << "\n";
                    }
                    result.certificates_der.push_back(certificate);
                    queue.push_back(std::move(certificate));
                    ++result.downloaded_count;
                }
            }
        }
        ++depth;
    }

    std::ostringstream message;
    message << "AIA issuer fallback downloaded " << result.downloaded_count
            << " certificate(s), cached " << result.cached_count << ".";
    result.message = message.str();
    debug << "  downloaded=" << result.downloaded_count << "\n"
          << "  cached=" << result.cached_count << "\n";
    result.debug_log = debug.str();
    return result;
}

} // namespace tamga::core::policy
