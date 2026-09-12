#pragma once

// Дрібні хелпери навколо libxml2 і URI алгоритмів — одна реалізація (ADR-027).
//
// `XadesBuilder.cpp` систематично повторював `XmlSignatureBuilder.cpp`:
// `AddChild`, `AddTextChild`, `SetAttr`, `C14nMethodToUri`. Те саме між
// `XadesVerifier` і `XmlSignatureVerifier` (`TrimmedText`), між білдером і
// верифікатором XMLDSIG (`IsIdFragmentUri`, `IsCanonicalizationOnlyTransform`)
// і між реєстром алгоритмів та digest-рушієм (`UriTail`).
//
// Порівняння тіл показало, що всі вісім були семантично ТОТОЖНІ — розходилися
// лише форматуванням (тернарний оператор проти `if`, зайвий `using`). Тобто тут
// не ховався дефект, на відміну від кластера X.509-імен, де три таблиці OID
// давали три різні DN. Це прибирання шуму, і воно того варте лише тому, що
// шум — це середовище, у якому дефект наступного разу не помітять.

#include <string>
#include <vector>

#include <libxml/tree.h>

#include "xmldsig/XmlCanonicalizer.h"

namespace tamga::xmldsig {

// --- вузли libxml2 ---------------------------------------------------------
xmlNodePtr AddChild(xmlNodePtr parent, xmlNsPtr ns, const char* name);
xmlNodePtr AddTextChild(xmlNodePtr parent, xmlNsPtr ns, const char* name, const std::string& text);
void SetAttr(xmlNodePtr node, const char* name, const std::string& value);

// Текст вузла без ведучих і хвостових пробільних символів.
std::string TrimmedText(xmlNodePtr node);

// --- URI -------------------------------------------------------------------

// Чи URI є посиланням на `#id` у цьому ж документі; `fragment` отримує сам id.
bool IsIdFragmentUri(const std::string& uri, std::string& fragment);

// Чи набір трансформацій зводиться лише до канонікалізації.
bool IsCanonicalizationOnlyTransform(const std::vector<std::string>& transforms);

// URI методу канонікалізації.
const char* C14nMethodToUri(CanonicalizationMethod method);

} // namespace tamga::xmldsig
