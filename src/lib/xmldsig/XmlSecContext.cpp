#include "xmldsig/XmlSecContext.h"

// Q-013: цей модуль компілюється ЛИШЕ у tamga-tests коли увімкнено
// TAMGA_ENABLE_XMLSEC_CROSSCHECK (не до lib — xmlsec1 не є виробничою
// залежністю). Подвійний guard страхує від випадкового включення у збірку без
// xmlsec.
#if defined(TAMGA_XMLSEC_CROSSCHECK_ENABLED)

#include <mutex>
#include <stdexcept>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/crypto.h>
#include <xmlsec/errors.h>

namespace tamga::xmldsig {

namespace {

std::mutex g_engine_mutex;
bool g_engine_initialized = false;

// Hardening проти XXE/SSRF: блокуємо будь-яке завантаження зовнішніх сутностей
// та DTD по мережі ще на рівні libxml2 entity-loader.
xmlParserInputPtr HardenedEntityLoader(const char* /*url*/,
                                       const char* /*id*/,
                                       xmlParserCtxtPtr /*ctxt*/) {
    return nullptr;
}

// Ініціалізує libxml2 + xmlsec один раз на процес. На Windows/MSVC release CI
// monolithic tamga-tests може створювати багато короткоживучих XML/XAdES
// контекстів підряд. Повний xmlSec/xmlCleanupParser shutdown після кожного
// останнього контексту нестабільний для vcpkg xmlsec/libxml2 runtime і може
// завершувати процес SEGFAULT уже після успішного проходження unit-тестів.
// Тому рушій лишається живим до завершення процесу; ОС коректно звільнить
// process-wide runtime ресурси, а per-operation об'єкти звільняються окремо.
void AcquireEngine() {
    std::lock_guard<std::mutex> lock(g_engine_mutex);
    if (g_engine_initialized) {
        return;
    }

    xmlInitParser();

    // Глобально блокуємо будь-яке завантаження зовнішніх сутностей. Інші
    // parser-hardening параметри задаються per-document у ParseHardened().
    xmlSetExternalEntityLoader(HardenedEntityLoader);

    if (xmlSecInit() < 0) {
        xmlCleanupParser();
        throw std::runtime_error("xmlSecInit failed");
    }

#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if (xmlSecCryptoDLLoadLibrary(nullptr) < 0) {
        xmlSecShutdown();
        xmlCleanupParser();
        throw std::runtime_error("xmlSecCryptoDLLoadLibrary failed");
    }
#endif

    if (xmlSecCryptoAppInit(nullptr) < 0) {
        xmlSecShutdown();
        xmlCleanupParser();
        throw std::runtime_error("xmlSecCryptoAppInit failed");
    }

    if (xmlSecCryptoInit() < 0) {
        xmlSecCryptoAppShutdown();
        xmlSecShutdown();
        xmlCleanupParser();
        throw std::runtime_error("xmlSecCryptoInit failed");
    }

    g_engine_initialized = true;
}

}  // namespace

struct XmlSecContext::Impl {
    // Маркер успішної ініціалізації process-wide рушія. Сам рушій навмисно не
    // завершується в деструкторі контексту; див. коментар в AcquireEngine().
    bool engine_ready{false};
};

XmlSecContext::XmlSecContext() : impl_(std::make_unique<Impl>()) {
    AcquireEngine();
    impl_->engine_ready = true;
}

XmlSecContext::~XmlSecContext() = default;

}  // namespace tamga::xmldsig

#endif  // TAMGA_XMLSEC_CROSSCHECK_ENABLED
