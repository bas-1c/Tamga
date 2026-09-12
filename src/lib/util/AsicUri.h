#pragma once

#include <string>

namespace tamga::util {

// WP-7 (ME-05): єдина точка нормалізації для зіставлення ds:Reference URI
// (XAdES/XMLDSIG) з іменами entry всередині ASiC-E контейнера. До цієї
// функції існувало три незалежні, розбіжні реалізації (percent-decode у
// XmlReferenceResolver::ResolveReference, окремий percent-decode +
// "./"-strip у Session::NormalizeCoverageUri, і третій варіант лише для
// "/"-префікса у Session::NormalizeAsicReference для legacy CAdES-шляху) —
// що спричиняло функціональну розбіжність між coverage-перевіркою (яка
// прибирала "./") і фактичним резолвінгом вмісту (який цього не робив):
// ds:Reference URI="./file.pdf" міг пройти coverage-перевірку, але провалити
// резолвінг дайджесту (false negative для валідного контейнера).
//
// Політика нормалізації:
// - percent-decode (%XX -> байт); некоректна послідовність -> false;
// - рівно ОДИН провідний "./" знімається (як з URI, так і з entry-імені —
//   симетрично, щоб обидві сторони порівняння давали однаковий канонічний
//   вигляд незалежно від того, з якого боку прийшов префікс);
// - порівняння РЕГІСТРОЗАЛЕЖНЕ (case-sensitive) — відповідає семантиці ZIP
//   entry-імен і байт-точній семантиці URI за специфікацією; жодного
//   implicit case-folding не додається (може приховати реальну розбіжність
//   імен, а не полагодити false positive);
// - Unicode NFC/NFD-нормалізація НЕ виконується (свідоме обмеження: у
//   vendor/ немає жодної Unicode-бібліотеки (ICU/utf8proc), а додавання
//   нової залежності заради цього рідкісного edge case визнано
//   непропорційним; задокументовано в docs/audit/opus-remediation-plan.md).
//
// Повертає false лише при некоректному percent-encoding (непарні/нешістнадцяткові
// цифри після '%'); порожній рядок — валідний результат.
bool NormalizeAsicEntryUri(const std::string& uri, std::string& out, std::string& error_message);

}  // namespace tamga::util
