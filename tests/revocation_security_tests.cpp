#include "support/FixturePaths.h"
// В-02 / С-01: перевірка відкликання через CRL мусить бути fail-closed.
//
// Дві незалежні прогалини, знайдені аудитом 2026-08-26:
//
//   В-02. `CheckCertificateRevocation` обчислює `crl_valid` (підпис CRL) ЛИШЕ
//         коли передано сертифікат issuer, а `CrlValidator` вимагав `crl_valid`
//         теж лише за цієї умови. Оскільки `crl_check_cert` у vendored
//         cryptonite звіряє **тільки серійний номер** (ані issuer CRL, ані
//         дати), будь-який CRL без issuer-сертифіката — зокрема вбудований у
//         сам недовірений документ — давав `Good`.
//
//   С-01. Поле `CrlValidationInput::validation_time` існувало, але не читалося
//         жодного разу: вікно [thisUpdate, nextUpdate] не перевірялося взагалі,
//         тож дворічний CRL «підтверджував», що сертифікат не відкликаний.
//
// Тест будує СИНТЕТИЧНИЙ CRL із завідомо недійсним підписом. Саме в цьому суть:
// на старому коді такий CRL проходив як доказ. Щоб тест не був зеленим намарно
// (CRL не декодувався б -> Unknown з іншої причини), сценарій A спершу доводить,
// що DER справді розбирається і вікно дійсності читається.
//
// Коди виходу: 0 = поведінка коректна; 1 = регресія; 77 = фікстури відсутні.

#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "core/CryptoniteAdapter.h"
#include "core/policy/CrlValidator.h"
#include "util/Base64.h"
#include "util/Der.h"

namespace {

constexpr int kSkip = 77;
int g_failures = 0;

void Fail(const std::string& what) {
    std::cerr << "FAILED: " << what << "\n";
    ++g_failures;
}

std::filesystem::path Fixture(const std::string& rel) {
    return tamga_test::TestDataRoot() / "tests" / "fixtures" / rel;
}

bool ReadText(const std::filesystem::path& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return false;
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

// PEM -> DER (перший блок CERTIFICATE).
bool LoadPemCertificate(const std::filesystem::path& path, std::vector<std::uint8_t>& der) {
    std::string pem;
    if (!ReadText(path, pem)) return false;
    const std::string begin = "-----BEGIN CERTIFICATE-----";
    const std::string end = "-----END CERTIFICATE-----";
    const auto b = pem.find(begin);
    const auto e = pem.find(end);
    if (b == std::string::npos || e == std::string::npos || e <= b) return false;
    std::string body = pem.substr(b + begin.size(), e - b - begin.size());
    std::string cleaned;
    for (const char c : body) {
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t') cleaned += c;
    }
    return tamga::util::Base64Decode(cleaned, der) && !der.empty();
}

// --- мінімальний DER-конструктор ------------------------------------------

void AppendLength(std::vector<std::uint8_t>& out, const std::size_t len) {
    if (len < 0x80U) {
        out.push_back(static_cast<std::uint8_t>(len));
        return;
    }
    std::vector<std::uint8_t> be;
    std::size_t v = len;
    while (v > 0) {
        be.insert(be.begin(), static_cast<std::uint8_t>(v & 0xFFU));
        v >>= 8;
    }
    out.push_back(static_cast<std::uint8_t>(0x80U | be.size()));
    out.insert(out.end(), be.begin(), be.end());
}

std::vector<std::uint8_t> Tlv(const std::uint8_t tag, const std::vector<std::uint8_t>& value) {
    std::vector<std::uint8_t> out;
    out.push_back(tag);
    AppendLength(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
    return out;
}

std::vector<std::uint8_t> Concat(const std::vector<std::vector<std::uint8_t>>& parts) {
    std::vector<std::uint8_t> out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

std::vector<std::uint8_t> Bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

// UTCTime YYMMDDHHMMSSZ
std::vector<std::uint8_t> UtcTime(const std::time_t t) {
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    // Кожне поле зводиться до [0, 99] ЯВНО, у беззнаковому типі. З `%02d` та
    // `int` GCC 13 не може довести межу й падає на -Werror=format-truncation:
    // шість полів по 11 байтів у буфер на 16 — з погляду компілятора можливо.
    const auto two = [](const int v) { return static_cast<unsigned>(v < 0 ? 0 : v) % 100U; };
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02u%02u%02u%02u%02u%02uZ", two(tm.tm_year + 1900),
                  two(tm.tm_mon + 1), two(tm.tm_mday), two(tm.tm_hour), two(tm.tm_min),
                  two(tm.tm_sec));
    return Tlv(0x17, Bytes(std::string(buf)));
}

// sha256WithRSAEncryption (1.2.840.113549.1.1.11) + NULL
std::vector<std::uint8_t> SignatureAlgorithm() {
    const std::vector<std::uint8_t> oid = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
    return Tlv(0x30, Concat({Tlv(0x06, oid), Tlv(0x05, {})}));
}

// Копіюємо точний issuer Name цільового сертифіката: фікстура мусить
// пройти applicability-фільтр, щоб перевіряти підпис і свіжість CRL.
std::vector<std::uint8_t> CertificateIssuerName(const std::vector<std::uint8_t>& certificate) {
    using tamga::util::ParseTlvAt;
    tamga::util::TlvView outer, tbs, field;
    if (!ParseTlvAt(certificate, 0, outer) || outer.tag != 0x30 ||
        !ParseTlvAt(certificate, outer.value_offset, outer.next_offset, tbs) || tbs.tag != 0x30) return {};
    std::size_t offset = tbs.value_offset;
    if (!ParseTlvAt(certificate, offset, tbs.next_offset, field)) return {};
    if (field.tag == 0xA0) offset = field.next_offset;
    if (!ParseTlvAt(certificate, offset, tbs.next_offset, field) || field.tag != 0x02) return {};
    offset = field.next_offset;
    if (!ParseTlvAt(certificate, offset, tbs.next_offset, field) || field.tag != 0x30) return {};
    offset = field.next_offset;
    if (!ParseTlvAt(certificate, offset, tbs.next_offset, field) || field.tag != 0x30) return {};
    return {certificate.begin() + static_cast<std::ptrdiff_t>(offset),
            certificate.begin() + static_cast<std::ptrdiff_t>(field.next_offset)};
}

// Синтетичний CertificateList із завідомо НЕДІЙСНИМ підписом і порожнім
// переліком відкликаних. Саме такий вхід на старому коді давав `Good`.
std::vector<std::uint8_t> BuildForgedCrl(const std::time_t this_update,
                                         const std::time_t next_update,
                                         const std::vector<std::uint8_t>& issuer_name) {
    const auto version = Tlv(0x02, {0x01});  // v2
    const auto tbs = Tlv(0x30, Concat({version, SignatureAlgorithm(), issuer_name,
                                       UtcTime(this_update), UtcTime(next_update)}));
    // BIT STRING: 0 невикористаних бітів + сміття замість підпису.
    std::vector<std::uint8_t> sig_bits;
    sig_bits.push_back(0x00);
    for (int i = 0; i < 64; ++i) sig_bits.push_back(static_cast<std::uint8_t>(0xA5));
    return Tlv(0x30, Concat({tbs, SignatureAlgorithm(), Tlv(0x03, sig_bits)}));
}

const char* StatusName(const tamga::core::policy::RevocationStatus s) {
    using tamga::core::policy::RevocationStatus;
    switch (s) {
        case RevocationStatus::NotChecked: return "not-checked";
        case RevocationStatus::Good: return "good";
        case RevocationStatus::Revoked: return "revoked";
        case RevocationStatus::Unknown: return "unknown";
        case RevocationStatus::Invalid: return "invalid";
        case RevocationStatus::Stale: return "stale";
        case RevocationStatus::ResponderUnavailable: return "temporarily-unavailable";
    }
    return "?";
}

}  // namespace

int main() {
#if !TAMGA_CRYPTONITE_ENABLED
    std::cerr << "Skipping revocation security suite: cryptonite is disabled in this build\n";
    return kSkip;
#else
    std::vector<std::uint8_t> signer_der;
    if (!LoadPemCertificate(Fixture("pki/cert.pem"), signer_der)) {
        std::cerr << "Skipping revocation security suite: tests/fixtures/pki/cert.pem missing\n";
        return kSkip;
    }

    const std::time_t now = std::time(nullptr);
    const std::time_t day = 24 * 60 * 60;
    const auto issuer_name = CertificateIssuerName(signer_der);
    if (issuer_name.empty()) {
        Fail("issuer Name сертифіката не розібрано — фікстура CRL не перевіряла б потрібний захист");
        return EXIT_FAILURE;
    }

    // --- A: свіжий, але непідписаний CRL без issuer-сертифіката -----------
    {
        const auto fresh_crl = BuildForgedCrl(now - day, now + 30 * day, issuer_name);

        // Антивакуумна перевірка: DER мусить справді розбиратися, інакше
        // "не Good" нижче нічого не доводило б.
        std::time_t parsed_this = 0;
        std::time_t parsed_next = 0;
        if (!tamga::core::CryptoniteAdapter::GetCrlValidityWindow(fresh_crl, parsed_this,
                                                                  parsed_next)) {
            Fail("синтетичний CRL не розбирається — тест був би зеленим намарно");
        } else if (parsed_next <= parsed_this) {
            Fail("вікно дійсності синтетичного CRL прочитано некоректно");
        } else {
            std::cout << "[revocation] OK: синтетичний CRL розбирається, вікно дійсності читається\n";
        }

        tamga::core::policy::CrlValidationInput input;
        input.signer_certificate_der = signer_der;
        input.issuer_certificate_der.clear();  // ланцюг не побудовано
        input.crls_der.push_back(fresh_crl);

        const auto res = tamga::core::policy::CrlValidator{}.Validate(input);
        if (res.status == tamga::core::policy::RevocationStatus::Good) {
            Fail("В-02: CRL без сертифіката issuer прийнято як доказ 'не відкликаний' "
                 "(підпис CRL при цьому ніде не перевірявся)");
        } else {
            std::cout << "[revocation] SECURE: без issuer-сертифіката статус = "
                      << StatusName(res.status) << ", не good\n";
        }
        if (res.revoked) {
            Fail("В-02: несподіване revoked=true для CRL із порожнім переліком");
        }
        if (res.status != tamga::core::policy::RevocationStatus::Unknown ||
            res.message.find("issuer certificate is unavailable") == std::string::npos) {
            Fail("В-02: відмова має бути саме через неперевірений підпис без issuer, а не через сторонній CRL");
        }
    }

    // --- B: прострочений CRL -----------------------------------------------
    // Issuer лишаємо порожнім НАВМИСНО: із заповненим першою спрацювала б
    // перевірка підпису підробленого CRL, і тест доводив би не те. Свіжість
    // перевіряється раніше за issuer-гілку, тож саме її видно у повідомленні.
    {
        const auto stale_crl = BuildForgedCrl(now - 800 * day, now - 700 * day, issuer_name);

        tamga::core::policy::CrlValidationInput input;
        input.signer_certificate_der = signer_der;
        input.issuer_certificate_der.clear();
        input.crls_der.push_back(stale_crl);

        const auto res = tamga::core::policy::CrlValidator{}.Validate(input);
        if (res.status == tamga::core::policy::RevocationStatus::Good) {
            Fail("С-01: прострочений CRL прийнято як доказ 'не відкликаний'");
        } else {
            std::cout << "[revocation] SECURE: прострочений CRL не дає good (статус = "
                      << StatusName(res.status) << ")\n";
        }
        if (res.message.find("stale") == std::string::npos) {
            Fail("С-01: очікувалося повідомлення про застарілий CRL, отримано: " + res.message);
        }
        if (res.status != tamga::core::policy::RevocationStatus::Stale) {
            Fail("С-01: прострочений застосовний CRL має точний статус Stale");
        }
    }

    // --- C: CRL, що ще не набув чинності ------------------------------------
    {
        const auto future_crl = BuildForgedCrl(now + 30 * day, now + 60 * day, issuer_name);

        tamga::core::policy::CrlValidationInput input;
        input.signer_certificate_der = signer_der;
        input.issuer_certificate_der.clear();
        input.crls_der.push_back(future_crl);

        const auto res = tamga::core::policy::CrlValidator{}.Validate(input);
        if (res.status == tamga::core::policy::RevocationStatus::Good) {
            Fail("С-01: CRL із майбутнім thisUpdate прийнято як доказ");
        } else {
            std::cout << "[revocation] SECURE: CRL із майбутнім thisUpdate не дає good\n";
        }
        if (res.status != tamga::core::policy::RevocationStatus::Stale ||
            res.message.find("not yet valid") == std::string::npos) {
            Fail("С-01: майбутній застосовний CRL відхиляється саме за thisUpdate");
        }
    }

    if (g_failures == 0) {
        std::cout << "Revocation security suite: OK\n";
        return EXIT_SUCCESS;
    }
    std::cerr << "revocation_security_tests: " << g_failures << " failure(s)\n";
    return EXIT_FAILURE;
#endif
}
