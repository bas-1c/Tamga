#pragma once

// Розбір і форматування імен X.509 (Name/RDN) та OID.
//
// Виділено з CryptoniteAdapter.cpp (O-01). Використовується двома модулями:
// CertificateInfo.cpp (метадані сертифіката) і CmsAttributeOps.cpp (OID
// алгоритму гешування підписанта), тому живе в окремому внутрішньому заголовку.

#include "core/cryptonite/Internal.h"
#include "util/X509Name.h"

#include <initializer_list>

#if TAMGA_CRYPTONITE_ENABLED

namespace tamga::core::cryptonite_detail {

struct NameAttribute {
    std::string oid;
    std::string short_name;
    std::string value;
};

// ADR-027: ці три більше не мають власної реалізації в cryptonite — вона одна,
// у `util/X509Name`, бо не потребує ASN.1-структур і мусить бути доступна також
// у збірці `vendor=OFF`.
//
// Саме `using`, а не inline-обгортка: обгортка є ВИЗНАЧЕННЯМ, і сторожа
// дублювання цілком слушно рахувала б її як другу копію. `using` лише вносить
// ім'я в namespace, тож `LookupOidShortName`, `EscapeRfc4514` і
// `ExtractDerStringValue` тут — рівно ті самі функції, що в `util`.
using tamga::util::EscapeRfc4514;
using tamga::util::ExtractDerStringValue;
using tamga::util::LookupOidShortName;

// ADR-027: ім'я тепер каже, що саме функція приймає. Донедавна тут і в
// `util/X509Name` жили ДВІ РІЗНІ функції з однаковим іменем `OidToString`:
// ця бере розібрану ASN.1-структуру, та — сирі байти DER. Збіг імені не
// був дублюванням, але читач коду мусив щоразу з'ясовувати, яка саме
// перед ним, а храповик дублювання не міг відрізнити збіг від копії.
std::string OidFromAsn1(const OBJECT_IDENTIFIER_t& oid);

std::vector<NameAttribute> CollectNameAttributes(const Name_t* name);

std::string FormatNameRfc4514(const Name_t* name);

std::string FirstNameAttributeValue(const std::vector<NameAttribute>& attributes,
                                    std::initializer_list<const char*> names_or_oids);

}  // namespace tamga::core::cryptonite_detail

#endif  // TAMGA_CRYPTONITE_ENABLED
