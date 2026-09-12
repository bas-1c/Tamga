#include "core/policy/CertificateChainValidator.h"
#include "core/cryptonite/Names.h"
#include "core/cryptonite/CertUtil.h"

#include "util/Der.h"
#include "util/Hex.h"
#include "util/X509Name.h"

#include <cstdio>
#include <ctime>
#include <deque>
#include <iomanip>
#include <memory>
#include <set>
#include <sstream>

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "asn1_utils.h"
#include "BasicConstraints.h"
#include "byte_array.h"
#include "cert.h"
#include "cryptonite_manager.h"
#include "KeyUsage.h"
#include "OBJECT_IDENTIFIER.h"
#include "oids.h"
#include "TBSCertificate.h"
#include "verify_adapter.h"
}
#endif

namespace tamga::core::policy {

// ADR-027: HexEncode і таблиця OID більше не визначаються тут.
// Тутешня `OidShortName` була ТРЕТЬОЮ таблицею в дереві (8 записів, серед них
// 2.5.4.97, якого не знали дві інші) — і пройшла повз сторожу дублювання лише
// тому, що називалася інакше за решту. Таблиці обʼєднані в util.
using tamga::util::HexEncode;
inline const char* OidShortName(const std::string& oid) {
    return tamga::util::LookupOidShortName(oid);
}

bool ParseIso8601Time(const std::string& text, time_t& out_time) {
    if (text.empty()) {
        return false;
    }
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    char z = 0;
    int matched = std::sscanf(text.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d%c", &year, &month, &day, &hour, &minute, &second, &z);
    if (matched < 6) {
        return false;
    }
    struct tm tm_time{};
    tm_time.tm_year = year - 1900;
    tm_time.tm_mon = month - 1;
    tm_time.tm_mday = day;
    tm_time.tm_hour = hour;
    tm_time.tm_min = minute;
    tm_time.tm_sec = second;
    tm_time.tm_isdst = 0;
#ifdef _WIN32
    time_t t_val = _mkgmtime(&tm_time);
#else
    time_t t_val = timegm(&tm_time);
#endif
    if (t_val == -1) {
        return false;
    }
    if (matched == 7 && z != 'Z' && z != 'z') {
        size_t t_pos = text.find('T');
        if (t_pos != std::string::npos) {
            size_t sign_pos = text.find_first_of("+-", t_pos + 1);
            if (sign_pos != std::string::npos) {
                int tz_hour = 0, tz_min = 0;
                char sign = text[sign_pos];
                if (std::sscanf(text.c_str() + sign_pos + 1, "%2d:%2d", &tz_hour, &tz_min) >= 1) {
                    time_t offset_sec = tz_hour * 3600 + tz_min * 60;
                    if (sign == '+') {
                        t_val -= offset_sec;
                    } else {
                        t_val += offset_sec;
                    }
                }
            }
        }
    }
    out_time = t_val;
    return true;
}

#if TAMGA_CRYPTONITE_ENABLED
namespace {

// ADR-027: і псевдонім, і декодер прибрані. `ScopedCert` уже був у
// `cryptonite/Internal.h`, а декодування — у `cryptonite/CertUtil`.
using cryptonite_detail::DecodeCertificateDer;
using cryptonite_detail::ScopedCert;

bool VerifyByIssuer(const Certificate_t* certificate, const Certificate_t* issuer) {
    if (certificate == nullptr || issuer == nullptr) {
        return false;
    }

    VerifyAdapter* verify_adapter = nullptr;
    const int init_rc = verify_adapter_init_by_cert(issuer, &verify_adapter);
    if (init_rc != RET_OK || verify_adapter == nullptr) {
        verify_adapter_free(verify_adapter);
        return false;
    }

    const bool valid = cert_verify(certificate, verify_adapter) == RET_OK;
    verify_adapter_free(verify_adapter);
    return valid;
}

// WP-4 (RFC 5280 §6.1): дані basicConstraints кандидата у видавці.
struct IssuerBasicConstraints {
    bool present{false};
    bool is_ca{false};
    bool has_path_len{false};
    long path_len{0};
};

IssuerBasicConstraints ReadIssuerBasicConstraints(const Certificate_t* cert) {
    IssuerBasicConstraints out;
    if (cert == nullptr) {
        return out;
    }
    ByteArray* ext = nullptr;
    const auto* oid = oids_get_oid_numbers_by_id(OID_BASIC_CONSTRAINTS_EXTENSION_ID);
    if (oid == nullptr || cert_get_ext_value(cert, oid, &ext) != RET_OK || ext == nullptr) {
        ba_free(ext);
        return out;  // без basicConstraints -> не CA
    }
    auto* bc = static_cast<BasicConstraints_t*>(
        asn_decode_with_alloc(get_BasicConstraints_desc(), ba_get_buf(ext), ba_get_len(ext)));
    ba_free(ext);
    if (bc == nullptr) {
        return out;
    }
    out.present = true;
    out.is_ca = bc->cA != nullptr && *bc->cA != 0;
    if (bc->pathLenConstraint != nullptr) {
        long value = 0;
        if (asn_INTEGER2long(bc->pathLenConstraint, &value) == 0) {
            out.has_path_len = true;
            out.path_len = value;
        }
    }
    ASN_FREE(get_BasicConstraints_desc(), bc);
    return out;
}

// keyUsage.keyCertSign. Відсутній keyUsage трактуємо як дозволений (як і решта
// коду проєкту, напр. PolicyCache). Сам розбір розширення — у
// `cryptonite_detail::CertificateAllowsKeyUsage`, щоб копія була одна.
bool IssuerHasKeyCertSign(const Certificate_t* cert) {
    return tamga::core::cryptonite_detail::CertificateAllowsKeyUsage(cert, KeyUsage_keyCertSign);
}

// Повертає причину відхилення кандидата у ПРОМІЖНІ видавці, або "" якщо він
// придатний як CA. intermediates_below — к-сть проміжних CA між ним і листом.
std::string IssuerCaRejectReason(const Certificate_t* cert, long intermediates_below) {
    const IssuerBasicConstraints bc = ReadIssuerBasicConstraints(cert);
    if (!bc.is_ca) {
        return "non-ca-issuer";
    }
    if (!IssuerHasKeyCertSign(cert)) {
        return "issuer-missing-keyCertSign";
    }
    if (bc.has_path_len && intermediates_below > bc.path_len) {
        return "pathlen-exceeded";
    }
    return "";
}

struct CandidateCertificate {
    ScopedCert certificate;
    const std::vector<std::uint8_t>* der{nullptr};
};

[[maybe_unused]] std::vector<CandidateCertificate> DecodeCandidates(const std::vector<std::vector<std::uint8_t>>& certificates) {
    std::vector<CandidateCertificate> decoded;
    decoded.reserve(certificates.size());
    for (const auto& der : certificates) {
        auto certificate = DecodeCertificateDer(der);
        if (certificate) {
            decoded.push_back(CandidateCertificate{std::move(certificate), &der});
        }
    }
    return decoded;
}

bool IsValidAt(const Certificate_t* certificate, const std::string& validation_time) {
    if (certificate == nullptr) {
        return false;
    }
    time_t val_time;
    if (ParseIso8601Time(validation_time, val_time)) {
        return cert_check_validity_with_date(certificate, val_time) == RET_OK;
    }
    return cert_check_validity(certificate) == RET_OK;
}



std::string HexEncodeByteArray(ByteArray* value) {
    if (value == nullptr) {
        return {};
    }
    return HexEncode(ba_get_buf(value), ba_get_len(value));
}

// ADR-027: власна копія прибрана — OidFromAsn1(OBJECT_IDENTIFIER_t) один,
// у `cryptonite/Names`.
using tamga::core::cryptonite_detail::OidFromAsn1;


// ADR-027: перейменовано з `ExtractDerStringValue` — це інша сигнатура
// (ANY_t, а не сирі байти), і збіг імені з `util::ExtractDerStringValue`
// лише заплутував: здавалося, що це та сама функція.
std::string ExtractAnyStringValue(const ANY_t& value) {
    if (value.buf == nullptr || value.size <= 2) {
        return {};
    }
    const auto* data = value.buf;
    const auto total = static_cast<std::size_t>(value.size);
    // Хвиля 8, п.2: власна копія розбору довжини прибрана. Її перевірка
    // `offset + length > value.size` переповнювалася так само, як у С-06;
    // fallback на HexEncode при некоректному кодуванні збережено.
    tamga::util::TlvView tlv{};
    if (!tamga::util::ParseTlvAt(data, 0U, total, tlv)) {
        return HexEncode(data, total);
    }
    const std::size_t offset = tlv.value_offset;
    const std::size_t length = tlv.value_length;
    const auto tag = tlv.tag;
    if (tag == 0x0CU || tag == 0x13U || tag == 0x16U) {
        return std::string(reinterpret_cast<const char*>(data + offset), length);
    }
    if (tag == 0x1EU && length >= 2U) {
        std::string out;
        for (std::size_t i = 0; i + 1U < length; i += 2U) {
            if (data[offset + i] == 0U && data[offset + i + 1U] >= 0x20U && data[offset + i + 1U] < 0x7FU) {
                out.push_back(static_cast<char>(data[offset + i + 1U]));
            }
        }
        if (!out.empty()) {
            return out;
        }
    }
    return "#" + HexEncode(data, static_cast<std::size_t>(value.size));
}

std::string FormatName(const Name_t& name) {
    if (name.present != Name_PR_rdnSequence) {
        return {};
    }
    std::vector<std::string> rdns;
    const RDNSequence_t* rdn_seq = &name.choice.rdnSequence;
    for (int i = 0; i < rdn_seq->list.count; ++i) {
        const auto* rdn = rdn_seq->list.array[i];
        if (rdn == nullptr) {
            continue;
        }
        std::vector<std::string> parts;
        for (int j = 0; j < rdn->list.count; ++j) {
            const auto* atv = rdn->list.array[j];
            if (atv == nullptr) {
                continue;
            }
            const std::string oid = OidFromAsn1(atv->type);
            const char* short_name = OidShortName(oid);
            parts.push_back(std::string(short_name != nullptr ? short_name : oid.c_str()) + "=" +
                            ExtractAnyStringValue(atv->value));
        }
        for (std::size_t j = 0; j < parts.size(); ++j) {
            if (j > 0) {
                rdns.back() += '+';
                rdns.back() += parts[j];
            } else {
                rdns.push_back(parts[j]);
            }
        }
    }
    std::string out;
    for (auto it = rdns.rbegin(); it != rdns.rend(); ++it) {
        if (!out.empty()) {
            out += ',';
        }
        out += *it;
    }
    return out;
}

struct CertificateDebugInfo {
    std::string subject;
    std::string issuer;
    std::string serial;
    std::string ski;
    std::string aki;
    bool decodable{false};
};

CertificateDebugInfo DescribeCertificate(const Certificate_t* certificate) {
    CertificateDebugInfo info;
    if (certificate == nullptr) {
        return info;
    }
    info.decodable = true;
    TBSCertificate_t* tbs_raw = nullptr;
    if (cert_get_tbs_cert(certificate, &tbs_raw) == RET_OK && tbs_raw != nullptr) {
        info.subject = FormatName(tbs_raw->subject);
        info.issuer = FormatName(tbs_raw->issuer);
        ASN_FREE(get_TBSCertificate_desc(), tbs_raw);
    }
    ByteArray* serial = nullptr;
    if (cert_get_sn(certificate, &serial) == RET_OK && serial != nullptr) {
        info.serial = HexEncodeByteArray(serial);
    }
    ba_free(serial);
    ByteArray* ski = nullptr;
    if (cert_get_subj_key_id(certificate, &ski) == RET_OK && ski != nullptr) {
        info.ski = HexEncodeByteArray(ski);
    }
    ba_free(ski);
    ByteArray* aki = nullptr;
    if (cert_get_auth_key_id(certificate, &aki) == RET_OK && aki != nullptr) {
        info.aki = HexEncodeByteArray(aki);
    }
    ba_free(aki);
    return info;
}

std::string OneLineCertificate(const CertificateDebugInfo& info) {
    std::ostringstream out;
    out << "subject=" << info.subject
        << "; issuer=" << info.issuer
        << "; serial=" << info.serial
        << "; ski=" << info.ski
        << "; aki=" << info.aki;
    return out.str();
}

std::string MatchFailureReason(const CertificateDebugInfo& child,
                               const CertificateDebugInfo& issuer,
                               const bool signature_valid) {
    std::vector<std::string> reasons;
    if (!child.issuer.empty() && !issuer.subject.empty() && child.issuer != issuer.subject) {
        reasons.push_back("subject/issuer mismatch");
    }
    if (!child.aki.empty() && !issuer.ski.empty() && child.aki != issuer.ski) {
        reasons.push_back("AKI/SKI mismatch");
    }
    if (!signature_valid) {
        reasons.push_back("signature verification failed");
    }
    if (child.aki.empty()) {
        reasons.push_back("serial mismatch not checked: AKI has no parsed authority serial");
    }
    if (reasons.empty()) {
        reasons.push_back("DN and key identifiers did not explain failure");
    }
    std::string out;
    for (std::size_t i = 0; i < reasons.size(); ++i) {
        if (i > 0) {
            out += "; ";
        }
        out += reasons[i];
    }
    return out;
}

void AppendCertBlock(std::ostringstream& out, const std::string& title, const CertificateDebugInfo& info) {
    out << title << ":\n"
        << "  subject=" << info.subject << "\n"
        << "  issuer=" << info.issuer << "\n"
        << "  serial=" << info.serial << "\n"
        << "  ski=" << info.ski << "\n"
        << "  aki=" << info.aki << "\n";
}

struct SourceCertificate {
    ScopedCert certificate;
    const std::vector<std::uint8_t>* der{nullptr};
    std::string source;
    CertificateDebugInfo info;
};

std::vector<SourceCertificate> DecodeSourceCandidates(
    const std::vector<std::pair<const std::vector<std::vector<std::uint8_t>>*, const char*>>& groups,
    std::ostringstream& debug) {
    std::vector<SourceCertificate> decoded;
    for (const auto& group : groups) {
        const auto* certificates = group.first;
        const char* source = group.second;
        debug << "Loaded " << source << " certificates=" << (certificates == nullptr ? 0U : certificates->size()) << "\n";
        if (certificates == nullptr) {
            continue;
        }
        for (std::size_t i = 0; i < certificates->size(); ++i) {
            auto certificate = DecodeCertificateDer((*certificates)[i]);
            if (!certificate) {
                debug << "  [" << i << "] decode=false\n";
                continue;
            }
            auto info = DescribeCertificate(certificate.get());
            debug << "  [" << i << "] " << OneLineCertificate(info) << "\n";
            decoded.push_back(SourceCertificate{std::move(certificate), &(*certificates)[i], source, std::move(info)});
        }
    }
    return decoded;
}

} // namespace
#endif

CertificateChainResult CertificateChainValidator::Validate(const CertificateChainInput& input) const {
    CertificateChainResult result;

#if !TAMGA_CRYPTONITE_ENABLED
    (void)input;
    result.checked = false;
    result.status = ChainStatus::NotChecked;
    result.message = "Certificate chain validation is not supported without cryptonite.";
    result.chain_debug = "Certificate chain validation is not supported without cryptonite.\n";
    return result;
#else
    result.checked = true;

    if (input.signer_certificate_der.empty()) {
        result.status = ChainStatus::SignerMissing;
        result.message = "Signer certificate is missing.";
        result.chain_debug = "Signer certificate is missing.\n";
        return result;
    }

    auto signer = DecodeCertificateDer(input.signer_certificate_der);
    if (!signer) {
        result.status = ChainStatus::InvalidSignature;
        result.message = "Signer certificate DER cannot be decoded.";
        result.chain_debug = "Signer certificate DER cannot be decoded.\n";
        return result;
    }

    std::ostringstream debug;
    const auto signer_info = DescribeCertificate(signer.get());
    AppendCertBlock(debug, "Signer", signer_info);

    if (!IsValidAt(signer.get(), input.validation_time)) {
        result.status = ChainStatus::Expired;
        result.message = "Signer certificate is outside its validity window.";
        debug << "Final:\n"
              << "  chain terminated at=" << signer_info.subject << "\n"
              << "  trusted=false\n"
              << "  reason=signer certificate is outside its validity window\n";
        result.chain_debug = debug.str();
        return result;
    }
    // WP-3: signer's own notBefore/notAfter window is confirmed at this point,
    // independent of whether a trust anchor is reachable below.
    result.signer_certificate_time_valid = true;

    if (input.trust_anchors_der.empty()) {
        result.status = ChainStatus::Untrusted;
        result.message = "Trust store is empty.";
        debug << "Loaded trust-store certificates=0\n"
              << "Final:\n"
              << "  chain terminated at=" << signer_info.subject << "\n"
              << "  trusted=false\n"
              << "  reason=trust-store loaded incorrectly or empty; missing trust anchor\n";
        result.chain_debug = debug.str();
        return result;
    }

    const std::string anchor_source = input.trust_anchor_source.empty() ? "trust-store" : input.trust_anchor_source;
    std::vector<std::pair<const std::vector<std::vector<std::uint8_t>>*, const char*>> anchor_groups = {
        {&input.trust_anchors_der, anchor_source.c_str()},
    };
    auto anchors = DecodeSourceCandidates(anchor_groups, debug);
    if (anchors.empty()) {
        result.status = ChainStatus::Untrusted;
        result.message = "Trust store does not contain decodable trust anchors.";
        debug << "Final:\n"
              << "  chain terminated at=" << signer_info.subject << "\n"
              << "  trusted=false\n"
              << "  reason=trust-store loaded incorrectly: no decodable trust anchors\n";
        result.chain_debug = debug.str();
        return result;
    }

    std::vector<std::pair<const std::vector<std::vector<std::uint8_t>>*, const char*>> issuer_groups = {
        {&input.embedded_certificates_der, "embedded"},
        {&input.intermediate_certificates_der, "intermediate-store"},
        {&input.aia_certificates_der, "AIA"},
    };
    auto issuer_candidates = DecodeSourceCandidates(issuer_groups, debug);

    struct ChainNode {
        const Certificate_t* certificate{nullptr};
        const std::vector<std::uint8_t>* der{nullptr};
        const std::vector<std::uint8_t>* signer_issuer_der{nullptr};
        CertificateDebugInfo info;
        std::string source;
        std::vector<std::string> path;
        std::size_t depth{0};
    };

    std::deque<ChainNode> queue;
    std::set<std::vector<std::uint8_t>> visited;
    queue.push_back(ChainNode{signer.get(),
                              &input.signer_certificate_der,
                              nullptr,
                              signer_info,
                              "signer",
                              {},
                              0});
    visited.insert(input.signer_certificate_der);

    // С-18: обмеження бюджету перевірок підпису.
    //
    // BFS виконує повну криптографічну перевірку (`VerifyByIssuer`) для КОЖНОЇ
    // пари «вузол — кандидат». Глибина обмежена, але сам пул кандидатів — ні, а
    // до нього входять сертифікати, вбудовані в НЕДОВІРЕНИЙ CMS. Отже
    // контрольована атакуючим кількість сертифікатів давала квадратичну
    // кількість криптоперевірок — DoS-поверхня, підсилена тим, що вхідний файл
    // до В-04 не мав ліміту розміру взагалі.
    //
    // Ліміт свідомо щедрий: легітимні українські ланцюги мають одиниці
    // сертифікатів, а кілька сотень кандидатів покривають навіть найширші
    // бандли. Перевищення — не помилка ланцюга, а відмова будувати далі:
    // результат лишається fail-closed (ланцюг просто не добудується до якоря).
    constexpr std::size_t kMaxIssuerCandidates = 256;
    if (issuer_candidates.size() > kMaxIssuerCandidates) {
        debug << "Candidate pool truncated:" << "\n"
              << "  reason=issuer candidate pool exceeds the verification budget" << "\n"
              << "  candidates=" << issuer_candidates.size()
              << " limit=" << kMaxIssuerCandidates << "\n";
        // `resize` тут неможливий: SourceCertificate не default-constructible.
        issuer_candidates.erase(
            issuer_candidates.begin() + static_cast<std::ptrdiff_t>(kMaxIssuerCandidates),
            issuer_candidates.end());
    }

    const std::size_t max_depth = issuer_candidates.size() + anchors.size() + 1;
    bool found_issuer_path = false;
    bool found_expired_issuer_path = false;
    ChainNode last_path_node = queue.front();
    CertificateDebugInfo expired_issuer_info;
    std::vector<std::string> expired_issuer_path;
    CertificateDebugInfo missing_issuer_for = signer_info;

    while (!queue.empty()) {
        const ChainNode current = queue.front();
        queue.pop_front();
        last_path_node = current;
        missing_issuer_for = current.info;

        if (current.certificate == nullptr || current.der == nullptr || current.depth > max_depth) {
            continue;
        }

        for (const auto& anchor : anchors) {
            if (!IsValidAt(anchor.certificate.get(), input.validation_time)) {
                debug << "Anchor reject:\n"
                      << "  candidate=" << anchor.info.subject << "\n"
                      << "  source=" << anchor.source << "\n"
                      << "  reason=root exists but is outside validity window; root exists but not marked trusted by current policy\n";
                continue;
            }
            const bool verified_by_anchor = VerifyByIssuer(current.certificate, anchor.certificate.get());
            if (verified_by_anchor) {
                auto trusted_path = current.path;
                std::ostringstream step;
                step << "Step " << (trusted_path.size() + 1U) << ":\n"
                     << "  matched issuer=" << anchor.info.subject << "\n"
                     << "  source=" << anchor.source << "\n";
                trusted_path.push_back(step.str());
                for (const auto& item : trusted_path) {
                    debug << item;
                }
                result.trusted = true;
                result.chain_valid = true;
                result.status = ChainStatus::Trusted;
                result.issuer_certificate_der = *anchor.der;
                result.signer_issuer_certificate_der = current.signer_issuer_der != nullptr
                    ? *current.signer_issuer_der
                    : *anchor.der;
                result.message = current.depth == 0
                    ? "Signer certificate validates against trust anchor."
                    : "Signer certificate validates through issuer certificates and trust anchor.";
                debug << "Final:\n"
                      << "  chain terminated at=" << anchor.info.subject << "\n"
                      << "  trusted=true\n"
                      << "  reason=chain builder reached configured trust anchor\n";
                result.chain_debug = debug.str();
                return result;
            }
            debug << "Trust anchor reject:\n"
                  << "  candidate=" << anchor.info.subject << "\n"
                  << "  source=" << anchor.source << "\n"
                  << "  reason=" << MatchFailureReason(current.info, anchor.info, verified_by_anchor) << "\n";
        }

        if (current.depth >= max_depth) {
            continue;
        }

        for (const auto& issuer : issuer_candidates) {
            if (issuer.der == nullptr || visited.find(*issuer.der) != visited.end()) {
                continue;
            }
            const bool verified_by_issuer = VerifyByIssuer(current.certificate, issuer.certificate.get());
            if (!verified_by_issuer) {
                debug << "Issuer reject:\n"
                      << "  candidate=" << issuer.info.subject << "\n"
                      << "  source=" << issuer.source << "\n"
                      << "  reason=" << MatchFailureReason(current.info, issuer.info, verified_by_issuer) << "\n";
                continue;
            }
            if (!IsValidAt(issuer.certificate.get(), input.validation_time)) {
                auto rejected_path = current.path;
                std::ostringstream step;
                step << "Step " << (rejected_path.size() + 1U) << ":\n"
                     << "  matched issuer=" << issuer.info.subject << "\n"
                     << "  source=" << issuer.source << "\n";
                rejected_path.push_back(step.str());
                if (!found_expired_issuer_path) {
                    found_expired_issuer_path = true;
                    expired_issuer_info = issuer.info;
                    expired_issuer_path = std::move(rejected_path);
                }
                debug << "Issuer reject:\n"
                      << "  candidate=" << issuer.info.subject << "\n"
                      << "  source=" << issuer.source << "\n"
                      << "  reason=issuer certificate is outside validity window; continuing with alternative issuer candidates\n";
                continue;
            }

            // WP-4 (RFC 5280 §6.1): проміжний видавець мусить бути CA з keyCertSign
            // і не порушувати pathLenConstraint. Інакше не-CA сертифікат, чий ключ
            // технічно підписав subject, був би прийнятий як CA (Opus H1).
            const std::string ca_reject =
                IssuerCaRejectReason(issuer.certificate.get(), static_cast<long>(current.depth));
            if (!ca_reject.empty()) {
                debug << "Issuer reject:\n"
                      << "  candidate=" << issuer.info.subject << "\n"
                      << "  source=" << issuer.source << "\n"
                      << "  reason=" << ca_reject << "\n";
                continue;
            }

            found_issuer_path = true;
            visited.insert(*issuer.der);
            auto next_path = current.path;
            std::ostringstream step;
            step << "Step " << (next_path.size() + 1U) << ":\n"
                 << "  matched issuer=" << issuer.info.subject << "\n"
                 << "  source=" << issuer.source << "\n";
            next_path.push_back(step.str());
            queue.push_back(ChainNode{
                issuer.certificate.get(),
                issuer.der,
                current.signer_issuer_der != nullptr ? current.signer_issuer_der : issuer.der,
                issuer.info,
                issuer.source,
                std::move(next_path),
                current.depth + 1});
        }
    }

    if (!found_issuer_path && found_expired_issuer_path) {
        result.status = ChainStatus::Expired;
        result.message = "Issuer certificate is outside its validity window.";
        for (const auto& item : expired_issuer_path) {
            debug << item;
        }
        debug << "Final:\n"
              << "  chain terminated at=" << expired_issuer_info.subject << "\n"
              << "  trusted=false\n"
              << "  reason=issuer certificate is outside its validity window\n";
        result.chain_debug = debug.str();
        return result;
    }

    result.status = found_issuer_path ? ChainStatus::Incomplete : ChainStatus::Untrusted;
    result.message = found_issuer_path
        ? "Certificate chain has issuer certificates but does not reach a configured trust anchor."
        : "Certificate chain is not trusted by configured trust anchors.";
    for (const auto& item : last_path_node.path) {
        debug << item;
    }
    debug << "Final:\n"
          << "  chain terminated at=" << last_path_node.info.subject << "\n"
          << "  trusted=false\n"
          << "  reason=" << (found_issuer_path
                 ? "chain builder stops before configured trust anchor; missing trust anchor or anchor mismatch"
                 : "no issuer certificate matched signer; missing issuer") << "\n"
          << "  issuer searched=" << missing_issuer_for.issuer << "\n";
    if (found_issuer_path) {
        debug << "  missing trust anchor=true\n";
    }
    result.chain_debug = debug.str();
    return result;
#endif
}

// С-19: публічна обгортка над файловим IsValidAt.
//
// Без cryptonite декодувати сертифікат нема чим, тож відповідь — fail-closed
// `false`: у діагностичній конфігурації sign/verify і так повертають
// NotSupported, і «сертифікат чинний» тут стверджувати не можна.
bool IsCertificateValidAt(const std::vector<std::uint8_t>& certificate_der,
                          const std::string& validation_time) {
#if !TAMGA_CRYPTONITE_ENABLED
    (void)certificate_der;
    (void)validation_time;
    return false;
#else
    if (certificate_der.empty()) {
        return false;
    }
    ScopedCert certificate = DecodeCertificateDer(certificate_der);
    if (!certificate) {
        return false;
    }
    return IsValidAt(certificate.get(), validation_time);
#endif
}

} // namespace tamga::core::policy
