// O-02: вимірювання вартості CertificateResolver::Resolve для 1/10/100
// кандидатів. Тимчасовий інструмент; у репозиторій не потрапляє.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "core/CryptoniteAdapter.h"
#include "core/net/CertificateResolver.h"

extern "C" {
#include "aid.h"
#include "asn1_utils.h"
#include "byte_array.h"
#include "cert.h"
#include "cert_engine.h"
#include "certificate_request_engine.h"
#include "cryptonite_manager.h"
#include "digest_adapter.h"
#include "dstu4145.h"
#include "ext.h"
#include "gost28147.h"
#include "oids.h"
#include "pkcs12.h"
#include "pkcs8.h"
#include "spki.h"
}

namespace {

struct Pair {
    std::vector<std::uint8_t> key;   // pkcs12 blob або pkcs8 der
    std::vector<std::uint8_t> cert;  // сертифікат, що відповідає ключу
    bool valid{false};
};

std::vector<std::uint8_t> FromBa(ByteArray* ba) {
    return std::vector<std::uint8_t>(ba_get_buf(ba), ba_get_buf(ba) + ba_get_len(ba));
}

Extensions_t* MakeKeyUsageExtensions() {
    Extension_t* key_usage_ext = nullptr;
    if (ext_create_key_usage(true,
            static_cast<KeyUsageBits>(KEY_USAGE_DIGITAL_SIGNATURE | KEY_USAGE_KEY_CERTSIGN),
            &key_usage_ext) != 0) {
        return nullptr;
    }
    Extensions_t* extensions = static_cast<Extensions_t*>(calloc(1, sizeof(Extensions_t)));
    if (extensions == nullptr) {
        return nullptr;
    }
    if (ASN_SEQUENCE_ADD(&extensions->list, key_usage_ext) != 0) {
        free(extensions);
        return nullptr;
    }
    return extensions;
}

bool IssueSelfSignedCert(SignAdapter* sa, VerifyAdapter* va, const char* subject,
                         unsigned char serial_seed, std::vector<std::uint8_t>& cert_der) {
    SubjectPublicKeyInfo_t* spki = nullptr;
    DigestAdapter* da = nullptr;
    CertificateRequestEngine* creq_eng = nullptr;
    CertificationRequest_t* cert_req = nullptr;
    CertificateEngine* cert_eng = nullptr;
    Certificate_t* cert = nullptr;
    ByteArray* cert_encoded = nullptr;
    Extensions_t* extensions = nullptr;
    bool ok = false;

    if (va->get_pub_key(va, &spki) != 0) goto cleanup;
    if (digest_adapter_init_by_aid(&spki->algorithm, &da) != 0) goto cleanup;
    if (ecert_request_alloc(sa, &creq_eng) != 0) goto cleanup;
    if (ecert_request_set_subj_name(creq_eng, subject) != 0) goto cleanup;
    if (ecert_request_generate(creq_eng, &cert_req) != 0) goto cleanup;
    extensions = MakeKeyUsageExtensions();
    if (extensions == nullptr) goto cleanup;
    if (ecert_alloc(sa, da, true, &cert_eng) != 0) goto cleanup;
    {
        unsigned char serial_bytes[20];
        for (int i = 0; i < 20; ++i) {
            serial_bytes[i] = static_cast<unsigned char>(serial_seed + i);
        }
        ByteArray* serial_ba = ba_alloc_from_uint8(serial_bytes, sizeof(serial_bytes));
        time_t not_before = std::time(nullptr) - 86400;
        time_t not_after = not_before + 365 * 86400;
        const int rc = ecert_generate(cert_eng, cert_req, 2, serial_ba, &not_before, &not_after,
                                      extensions, &cert);
        ba_free(serial_ba);
        if (rc != 0) goto cleanup;
    }
    if (cert_encode(cert, &cert_encoded) != 0) goto cleanup;
    cert_der = FromBa(cert_encoded);
    ok = !cert_der.empty();

cleanup:
    ba_free(cert_encoded);
    if (cert != nullptr) cert_free(cert);
    ecert_free(cert_eng);
    if (extensions != nullptr) {
        ASN_FREE_CONTENT_STATIC(get_Extensions_desc(), extensions);
        free(extensions);
    }
    ecert_request_free(creq_eng);
    if (cert_req != nullptr) ASN_FREE(get_CertificationRequest_desc(), cert_req);
    spki_free(spki);
    digest_adapter_free(da);
    return ok;
}

// PKCS#12-контейнер БЕЗ certBag (рівно той випадок, який обслуговує резолвер).
Pair MakePkcs12Pair(const char* subject, unsigned char serial_seed) {
    Pair result;
    Dstu4145Ctx* ec_params = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB);
    Gost28147Ctx* cipher_params = gost28147_alloc(GOST28147_SBOX_ID_1);
    AlgorithmIdentifier_t* aid = nullptr;
    ByteArray* aid_ba = nullptr;
    Pkcs12Ctx* storage = nullptr;
    SignAdapter* sa = nullptr;
    VerifyAdapter* va = nullptr;
    ByteArray* storage_body = nullptr;

    if (ec_params == nullptr || cipher_params == nullptr) goto cleanup;
    if (aid_create_dstu4145(ec_params, cipher_params, true, &aid) != 0) goto cleanup;
    if (aid_encode(aid, &aid_ba) != 0) goto cleanup;
    if (pkcs12_create(KS_FILE_PKCS12_WITH_GOST34311, "test", 1024, &storage) != 0) goto cleanup;
    if (pkcs12_generate_key(storage, aid_ba) != 0) goto cleanup;
    if (pkcs12_store_key(storage, "signer", "test", 1024) != 0) goto cleanup;
    if (pkcs12_select_key(storage, "signer", "test") != 0) goto cleanup;
    if (pkcs12_get_sign_adapter(storage, &sa) != 0) goto cleanup;
    if (pkcs12_get_verify_adapter(storage, &va) != 0) goto cleanup;
    if (!IssueSelfSignedCert(sa, va, subject, serial_seed, result.cert)) goto cleanup;
    if (pkcs12_encode(storage, &storage_body) != 0) goto cleanup;
    result.key = FromBa(storage_body);
    result.valid = !result.key.empty() && !result.cert.empty();

cleanup:
    ba_free(storage_body);
    verify_adapter_free(va);
    sign_adapter_free(sa);
    pkcs12_free(storage);
    ba_free(aid_ba);
    aid_free(aid);
    gost28147_free(cipher_params);
    dstu4145_free(ec_params);
    return result;
}

Pair MakePkcs8Pair(const char* subject, unsigned char serial_seed) {
    Pair result;
    Dstu4145Ctx* ec_params = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB);
    Gost28147Ctx* cipher_params = gost28147_alloc(GOST28147_SBOX_ID_1);
    AlgorithmIdentifier_t* aid = nullptr;
    PrivateKeyInfo_t* pkey = nullptr;
    SignAdapter* sa = nullptr;
    VerifyAdapter* va = nullptr;
    ByteArray* pkcs8_encoded = nullptr;

    if (ec_params == nullptr || cipher_params == nullptr) goto cleanup;
    if (aid_create_dstu4145(ec_params, cipher_params, true, &aid) != 0) goto cleanup;
    if (pkcs8_generate(aid, &pkey) != 0) goto cleanup;
    if (pkcs8_get_sign_adapter(pkey, nullptr, &sa) != 0) goto cleanup;
    if (pkcs8_get_verify_adapter(pkey, &va) != 0) goto cleanup;
    if (!IssueSelfSignedCert(sa, va, subject, serial_seed, result.cert)) goto cleanup;
    if (pkcs8_encode(pkey, &pkcs8_encoded) != 0) goto cleanup;
    result.key = FromBa(pkcs8_encoded);
    result.valid = !result.key.empty() && !result.cert.empty();

cleanup:
    ba_free(pkcs8_encoded);
    verify_adapter_free(va);
    sign_adapter_free(sa);
    if (pkey != nullptr) pkcs8_free(pkey);
    aid_free(aid);
    gost28147_free(cipher_params);
    dstu4145_free(ec_params);
    return result;
}

void WriteFile(const std::filesystem::path& path, const std::vector<std::uint8_t>& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

double MedianMs(std::vector<double> samples) {
    std::sort(samples.begin(), samples.end());
    return samples[samples.size() / 2];
}

// Каталог із `count` кандидатами. Правильний сертифікат кладеться ОСТАННІМ у
// порядку обходу (`zzz-`), щоб виміряти найгірший випадок — саме той, що
// описано в O-02: розбір і розкриття контейнера на КОЖНОГО кандидата.
void PrepareDir(const std::filesystem::path& dir, const Pair& own, const Pair& other,
                const std::string& key_ext, std::size_t count) {
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir, ec);
    WriteFile(dir / ("key" + key_ext), own.key);
    for (std::size_t i = 0; i + 1 < count; ++i) {
        char name[64];
        snprintf(name, sizeof(name), "aaa-%03zu.cer", i);
        WriteFile(dir / name, other.cert);
    }
    WriteFile(dir / "zzz-own.cer", own.cert);
}

void Measure(const char* label, const Pair& own, const Pair& other, const std::string& key_ext,
             const std::string& password, std::size_t count, int repeats) {
    const auto dir = std::filesystem::temp_directory_path() /
                     ("tamga-o02-" + std::string(label) + "-" + std::to_string(count));
    PrepareDir(dir, own, other, key_ext, count);

    tamga::core::net::CertificateResolveRequest request;
    request.key_material = own.key;
    request.password = password;
    request.key_file_path = (dir / ("key" + key_ext)).string();
    request.offline_mode = true;
    // work_dir порожній — кеш вимкнений, інакше друга ітерація вимірювала б кеш.

    tamga::core::net::CertificateResolver resolver;
    // Прогрів.
    auto warm = resolver.Resolve(request);
    if (!warm.succeeded) {
        std::printf("%-8s n=%-4zu ПОМИЛКА: %s\n", label, count, warm.message.c_str());
        return;
    }

    std::vector<double> samples;
    int rejected = 0;
    for (int i = 0; i < repeats; ++i) {
        const auto t0 = std::chrono::steady_clock::now();
        const auto r = resolver.Resolve(request);
        const auto t1 = std::chrono::steady_clock::now();
        if (!r.succeeded) {
            std::printf("%-8s n=%-4zu ПОМИЛКА: %s\n", label, count, r.message.c_str());
            return;
        }
        rejected = r.rejected_candidates;
        samples.push_back(std::chrono::duration<double, std::milli>(t1 - t0).count());
    }
    std::sort(samples.begin(), samples.end());
    std::printf("%-8s n=%-4zu медіана=%9.3f мс  min=%9.3f  max=%9.3f  відхилено=%d  source=%s\n",
                label, count, MedianMs(samples), samples.front(), samples.back(), rejected,
                warm.source.c_str());
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

}  // namespace

int main(int argc, char** argv) {
    const int repeats = argc > 1 ? std::atoi(argv[1]) : 7;

    std::printf("Генерація фікстур ДСТУ 4145 (M257_PB)...\n");
    const Pair p12_own = MakePkcs12Pair("{CN=O-02 P12 Own}{O=Tamga}{C=UA}", 0x01);
    const Pair p12_other = MakePkcs12Pair("{CN=O-02 P12 Other}{O=Tamga}{C=UA}", 0x41);
    const Pair p8_own = MakePkcs8Pair("{CN=O-02 P8 Own}{O=Tamga}{C=UA}", 0x81);
    const Pair p8_other = MakePkcs8Pair("{CN=O-02 P8 Other}{O=Tamga}{C=UA}", 0xC1);

    if (!p12_own.valid || !p12_other.valid || !p8_own.valid || !p8_other.valid) {
        std::printf("Не вдалося згенерувати фікстури\n");
        return 1;
    }
    std::printf("PKCS#12 %zu Б, PKCS#8 %zu Б, повторів=%d\n\n", p12_own.key.size(),
                p8_own.key.size(), repeats);

    for (std::size_t n : {std::size_t{1}, std::size_t{10}, std::size_t{100}}) {
        Measure("pkcs12", p12_own, p12_other, ".dat", "test", n, repeats);
    }
    std::printf("\n");
    for (std::size_t n : {std::size_t{1}, std::size_t{10}, std::size_t{100}}) {
        Measure("pkcs8", p8_own, p8_other, ".p8", "", n, repeats);
    }
    return 0;
}
