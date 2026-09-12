#include "xmldsig/XmlDigestEngine.h"

#include "xmldsig/XmlAlgorithmRegistry.h"

#include <cctype>
#include <unordered_map>

namespace tamga::xmldsig {

namespace {

using tamga::core::ImprintDigest;

// Канонічні W3C XMLDSIG/XMLEnc DigestMethod URI -> алгоритм імпринту.
// SHA-1 свідомо не підтримується (застарілий і відсутній серед ImprintDigest).
const std::unordered_map<std::string, ImprintDigest>& W3cDigestUriMap() {
    static const std::unordered_map<std::string, ImprintDigest> kMap = {
        {"http://www.w3.org/2001/04/xmlenc#sha256", ImprintDigest::Sha256},
        {"http://www.w3.org/2001/04/xmldsig-more#sha384", ImprintDigest::Sha384},
        {"http://www.w3.org/2001/04/xmlenc#sha512", ImprintDigest::Sha512},
        // Українські DSTU/ГОСТ DigestMethod URI (конвенція xmldsig-more, що нею
        // користуються українські XMLDSIG/XAdES-реалізації). Остаточну
        // відповідність офіційному профілю підтверджуємо cross-validation
        // у Phase 8.
        {"http://www.w3.org/2001/04/xmldsig-more#gost34311", ImprintDigest::Gost34311},
        {"http://www.w3.org/2001/04/xmlenc#gost34311", ImprintDigest::Gost34311},
        // WP-9: канонічні UA Kupyna (ДСТУ 7564) DigestMethod URI — закриває
        // TODO(phase 3). Раніше розпізнавались лише через ImprintFromDigestOid.
        {"http://www.w3.org/2001/04/xmldsig-more#kupyna256", ImprintDigest::Kupyna256},
        {"http://www.w3.org/2001/04/xmlenc#kupyna256", ImprintDigest::Kupyna256},
        // Канонічне написання за ДСТУ 7564:2014 — саме його ставить Дія у
        // DigestMethod/SignatureMethod реальних ASiC-E контейнерів.
        {"http://www.w3.org/2001/04/xmlenc#dstu7564-256", ImprintDigest::Kupyna256},
        {"http://www.w3.org/2001/04/xmldsig-more#dstu7564-256", ImprintDigest::Kupyna256},
    };
    return kMap;
}

}  // namespace

std::optional<ImprintDigest> XmlDigestEngine::MapDigestUri(const std::string& algo_uri) {
    const auto& map = W3cDigestUriMap();
    const auto it = map.find(algo_uri);
    if (it != map.end()) {
        return it->second;
    }

    // Запасний шлях: повний URI або його хвіст можуть бути bare-іменем/OID-ом,
    // які вже знає ImprintFromDigestOid (зокрема українські kupyna256/gost34311).
    //
    // TODO(phase 3) прибрано 2026-08-29: він вимагав «зафіксувати канонічні UA
    // DSTU DigestMethod URI у W3cDigestUriMap», а вони там уже є (WP-9, чотири
    // написання kupyna256/dstu7564-256 вище) — опис пережив свою задачу. Що
    // справді лишається: офіційний профіль українського XAdES не узгоджений,
    // тож перелік написань виведений із реальних контейнерів Дії, а не з
    // нормативного джерела. Це межа знання, а не незроблена робота.
    if (auto direct = tamga::core::ImprintFromDigestOid(algo_uri)) {
        return direct;
    }
    return tamga::core::ImprintFromDigestOid(UriTail(algo_uri));
}

std::optional<ImprintDigest> XmlDigestEngine::MapSignatureMethodUri(const std::string& algo_uri) {
    // С-07: розпізнавання йде через КАНОНІЧНИЙ реєстр, а не через
    // `lower.find(needle)`.
    //
    // Реєстр `AlgorithmRegistry` існував і був покритий власними тестами, але
    // продакшн-верифікатор його НЕ викликав — `XmlSignatureVerifier.cpp` лише
    // включав заголовок. Фактичне розпізнавання йшло підрядками, тож
    // нестандартний URI виду `urn:evil:kupyna:...` приймався як підтримуваний
    // алгоритм. Обхід підпису це не давало (невірно обраний дайджест не
    // зійшовся б із SignatureValue), але тести реєстру доводили властивість,
    // якої продукт не мав, — а це гірше за відсутність тестів.
    //
    // Реєстр звіряє ХВІСТ URI з явним whitelist. Невідомий вхід -> nullopt,
    // без жодного «вгадування».
    if (const auto alg = AlgorithmRegistry::MapSignatureUri(algo_uri)) {
        return AlgorithmRegistry::ToImprint(*alg);
    }

    // SignatureMethod може бути заданий і як bare-ім'я/OID дайджесту — це
    // окремий формат запису, а не послаблення whitelist.
    return MapDigestUri(algo_uri);
}

bool XmlDigestEngine::ComputeDigest(const std::vector<std::uint8_t>& data,
                                    const std::string& algo_uri,
                                    std::vector<std::uint8_t>& digest_out,
                                    std::string& error_message) {
    const auto alg = MapDigestUri(algo_uri);
    if (!alg) {
        error_message = "Непідтримуваний XMLDSIG DigestMethod URI: " + algo_uri;
        return false;
    }

    tamga::core::ImprintResult result;
    if (!tamga::core::ComputeImprint(*alg, data, result, error_message)) {
        return false;
    }

    digest_out = std::move(result.hash);
    return true;
}

bool XmlDigestEngine::ComputeDigestByCertificate(const std::vector<std::uint8_t>& data,
                                                 const std::string& algo_uri,
                                                 const std::vector<std::uint8_t>& certificate_der,
                                                 std::vector<std::uint8_t>& digest_out,
                                                 std::string& error_message) {
    const auto alg = MapDigestUri(algo_uri);
    if (!alg) {
        error_message = "Непідтримуваний XMLDSIG DigestMethod URI: " + algo_uri;
        return false;
    }

    tamga::core::ImprintResult result;
    if (!tamga::core::ComputeImprintByCertificate(certificate_der, *alg, data, result, error_message)) {
        return false;
    }

    digest_out = std::move(result.hash);
    return true;
}

}  // namespace tamga::xmldsig
