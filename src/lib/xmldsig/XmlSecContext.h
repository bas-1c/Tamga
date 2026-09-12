#pragma once

#include <memory>

namespace tamga::xmldsig {

// Внутрішній RAII-адаптер до libxml2/xmlsec: одноразова безпечна ініціалізація
// рушія, per-operation контекст і hardening (вимкнення external entities).
// Типи xmlsec не протікають у заголовок — реалізація лишається непрозорою.
class XmlSecContext {
public:
    // Одноразова ініціалізація libxml2/xmlsec під `g_engine_mutex` і
    // hardening (заборона external entities, DTD-завантаження) — реалізовано
    // в `XmlSecContext.cpp`. TODO(phase 1) прибрано 2026-08-29: він описував
    // як майбутнє те, що вже зроблено.
    XmlSecContext();
    ~XmlSecContext();

    XmlSecContext(const XmlSecContext&) = delete;
    XmlSecContext& operator=(const XmlSecContext&) = delete;

private:
    // Непрозора реалізація — приховує залежності libxml2/xmlsec від заголовка.
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace tamga::xmldsig
