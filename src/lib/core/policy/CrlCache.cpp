#include "core/policy/CrlCache.h"

#include "core/CryptoniteAdapter.h"
#include "core/HttpClient.h"
#include "util/Der.h"
#include "util/FileSystem.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
#include "core/cryptonite/Internal.h"
#include "core/cryptonite/CertUtil.h"
extern "C" {
#include "CRLDistributionPoints.h"
#include "DistributionPointName.h"
#include "GeneralName.h"
#include "asn1_utils.h"
#include "byte_array.h"
#include "cert.h"
#include "crl.h"
#include "oids.h"
}
#endif

namespace tamga::core::policy {
namespace {

std::string StableStringHash(const std::string& str) {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const char c : str) {
        hash ^= static_cast<std::uint8_t>(c);
        hash *= 1099511628211ULL;
    }
    constexpr char kHex[] = "0123456789abcdef";
    std::string out(16U, '0');
    for (std::size_t i = 0; i < out.size(); ++i) {
        const std::size_t shift = (out.size() - 1U - i) * 4U;
        out[i] = kHex[(hash >> shift) & 0x0FU];
    }
    return out;
}

std::vector<std::uint8_t> ReadFileBytes(const std::filesystem::path& path) {
    std::vector<std::uint8_t> data;
    std::string read_error;
    if (!util::ReadBinaryFileLimited(path, util::kMaxCachedArtifactSize, data, read_error)) {
        return {};
    }
    return data;
}

} // namespace

std::vector<std::string> ExtractCrlDistributionUrls(const std::vector<std::uint8_t>& cert_der) {
    std::vector<std::string> urls;
    if (cert_der.empty()) {
        return urls;
    }
#if TAMGA_CRYPTONITE_ENABLED
    ByteArray* cert_ba = ba_alloc_from_uint8(cert_der.data(), cert_der.size());
    Certificate_t* cert = cert_alloc();
    ByteArray* ext_value = nullptr;
    CRLDistributionPoints_t* distribution_points = nullptr;

    if (cert_ba == nullptr || cert == nullptr || cert_decode(cert, cert_ba) != RET_OK) {
        ba_free(cert_ba);
        cert_free(cert);
        return urls;
    }

    const auto* oid = oids_get_oid_numbers_by_id(OID_CRL_DISTRIBUTION_POINTS_EXTENSION_ID);
    if (oid == nullptr || cert_get_ext_value(cert, oid, &ext_value) != RET_OK || ext_value == nullptr) {
        ba_free(ext_value);
        ba_free(cert_ba);
        cert_free(cert);
        return urls;
    }

    distribution_points = static_cast<CRLDistributionPoints_t*>(
        asn_decode_ba_with_alloc(&CRLDistributionPoints_desc, ext_value));
    if (distribution_points == nullptr) {
        ba_free(ext_value);
        ba_free(cert_ba);
        cert_free(cert);
        return urls;
    }

    for (int i = 0; i < distribution_points->list.count; ++i) {
        const auto* point = distribution_points->list.array[i];
        if (point == nullptr ||
            point->distributionPoint == nullptr ||
            point->distributionPoint->present != DistributionPointName_PR_fullName) {
            continue;
        }

        const auto& full_name = point->distributionPoint->choice.fullName;
        for (int j = 0; j < full_name.list.count; ++j) {
            const auto* general_name = full_name.list.array[j];
            if (general_name == nullptr ||
                general_name->present != GeneralName_PR_uniformResourceIdentifier) {
                continue;
            }

            const auto& uri = general_name->choice.uniformResourceIdentifier;
            if (uri.buf == nullptr || uri.size <= 0) {
                continue;
            }

            std::string url(reinterpret_cast<const char*>(uri.buf),
                            reinterpret_cast<const char*>(uri.buf) + uri.size);
            if (!url.empty() && std::find(urls.begin(), urls.end(), url) == urls.end()) {
                urls.push_back(std::move(url));
            }
        }
    }

    ASN_FREE(&CRLDistributionPoints_desc, distribution_points);
    ba_free(ext_value);
    ba_free(cert_ba);
    cert_free(cert);
#endif
    return urls;
}

bool IsValidCrlDer(const std::vector<std::uint8_t>& crl_der) {
    if (crl_der.empty()) {
        return false;
    }
    tamga::util::TlvView tlv;
    if (!tamga::util::ParseTlvAt(crl_der, 0, tlv)) {
        return false;
    }
    if (tlv.tag != 0x30 || tlv.next_offset != crl_der.size()) {
        return false;
    }
#if TAMGA_CRYPTONITE_ENABLED
    std::time_t this_update = 0;
    std::time_t next_update = 0;
    if (!CryptoniteAdapter::GetCrlValidityWindow(crl_der, this_update, next_update)) {
        return false;
    }
#endif
    return true;
}

bool CrlMatchesCertificate(const std::vector<std::uint8_t>& crl_der,
                           const std::vector<std::uint8_t>& cert_der) {
#if TAMGA_CRYPTONITE_ENABLED
    using namespace cryptonite_detail;
    if (crl_der.empty() || cert_der.empty()) {
        return false;
    }
    if (!IsValidCrlDer(crl_der)) {
        return false;
    }
    ScopedByteArray encoded(MakeByteArray(crl_der), ba_free);
    ScopedCrl crl(crl_alloc(), crl_free);
    if (!encoded || !crl || crl_decode(crl.get(), encoded.get()) != RET_OK) {
        return false;
    }
    ScopedCert cert = DecodeCertificateDer(cert_der);
    if (!cert) {
        return false;
    }
    return asn_equals(&Name_desc, &crl->tbsCertList.issuer, &cert->tbsCertificate.issuer) == 1;
#else
    (void)crl_der;
    (void)cert_der;
    return false;
#endif
}

bool IsCachedCrlFresh(const std::vector<std::uint8_t>& crl_der, std::time_t now) {
    if (!IsValidCrlDer(crl_der)) {
        return false;
    }
    std::time_t next_update = 0;
    if (!CryptoniteAdapter::GetCrlNextUpdate(crl_der, next_update)) {
        return false;
    }
    return next_update > now;
}

void DownloadAndCacheCrlsForCert(const std::vector<std::uint8_t>& cert_der,
                                 const std::string& work_dir,
                                 std::int32_t timeout_ms) {
    if (cert_der.empty() || work_dir.empty()) {
        return;
    }
    const auto urls = ExtractCrlDistributionUrls(cert_der);
    const std::time_t now = std::time(nullptr);

    for (const auto& url : urls) {
        const std::string url_hash = StableStringHash(url);
        const std::filesystem::path dest_dir = std::filesystem::u8path(work_dir) / "crl-store";
        const std::filesystem::path dest_path = dest_dir / ("crl-" + url_hash + ".crl");

        std::error_code ec;
        if (std::filesystem::exists(dest_path, ec)) {
            if (IsCachedCrlFresh(ReadFileBytes(dest_path), now)) {
                continue;  // ще чинний за nextUpdate — мережевий запит не потрібен
            }
        }

        auto get_res = HttpClient::Get(url, "application/pkix-crl, */*", timeout_ms);
        if (get_res.succeeded) {
            if (!get_res.body.empty() && IsValidCrlDer(get_res.body)) {
                tamga::util::WriteBinaryFileAtomic(dest_path, get_res.body);
            }
        }
    }
}

void LoadCrlsFromWorkDir(const std::string& work_dir,
                         std::vector<std::vector<std::uint8_t>>& crls) {
    if (work_dir.empty()) {
        return;
    }
    const std::filesystem::path base = std::filesystem::u8path(work_dir);
    for (const auto& dir_name : {"crl-store", "crls"}) {
        const std::filesystem::path dir_path = base / dir_name;
        std::error_code ec;
        if (!std::filesystem::exists(dir_path, ec) || !std::filesystem::is_directory(dir_path, ec)) {
            continue;
        }
        for (const auto& entry : std::filesystem::directory_iterator(dir_path, ec)) {
            if (ec || !entry.is_regular_file(ec)) {
                continue;
            }
            std::vector<std::uint8_t> data;
            std::string read_error;
            if (!util::ReadBinaryFileLimited(entry.path(), util::kMaxCachedArtifactSize, data,
                                             read_error)) {
                continue;
            }
            if (!data.empty()) {
                crls.push_back(std::move(data));
            }
        }
    }
}

void LoadMatchingCrlsFromWorkDir(const std::string& work_dir,
                                 const std::vector<std::vector<std::uint8_t>>& certs,
                                 std::vector<std::vector<std::uint8_t>>& crls) {
    if (work_dir.empty() || certs.empty()) {
        return;
    }
    std::vector<std::vector<std::uint8_t>> all_crls;
    LoadCrlsFromWorkDir(work_dir, all_crls);
    for (auto& crl : all_crls) {
        if (!IsValidCrlDer(crl)) {
            continue;
        }
        bool matches = false;
        for (const auto& cert : certs) {
            if (CrlMatchesCertificate(crl, cert)) {
                matches = true;
                break;
            }
        }
        if (matches) {
            crls.push_back(std::move(crl));
        }
    }
}

} // namespace tamga::core::policy
