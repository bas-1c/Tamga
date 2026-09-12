#pragma once

// Спільний message-imprint builder для XAdES ArchiveTimeStamp (ETSI EN 319
// 132-1 §5.5.2.3, not-distributed case) -- використовується і XadesBuilder
// (створення нового ArchiveTimeStamp), і XadesVerifier (перевірка вже
// наявного). Раніше builder і verifier мали ДВІ незалежні,
// "Tamga-визначені" реалізації TBS, що не відповідали порядку конкатенації
// зі стандарту; ця спільна функція замінює обидві.
//
// Доступно лише у збірці з TAMGA_ENABLE_XML_SIGNATURES.

#if defined(TAMGA_XML_SIGNATURES_ENABLED)

#include <string>
#include <vector>

#include <libxml/tree.h>

#include "xmldsig/XmlReferenceResolver.h"
#include "xmldsig/XmlTransformEngine.h"
#include "xmldsig/detail/XmlDocUtil.h"

namespace tamga::xades::detail {

// Same-document "#id"-посилання (без xpointer) -- кандидат на канонікалізацію
// безпосередньо у вихідному дереві doc, БЕЗ серіалізації елемента в окремий
// рядок і перепарсингу (що губить namespace-декларації, успадковані від
// предків -- напр. xmlns:xades, оголошений на QualifyingProperties, предку
// SignedProperties). Дзеркалить IsIdFragmentUri з XmlSignatureVerifier.cpp.
inline bool IsArchiveImprintIdFragmentUri(const std::string& uri, std::string& fragment) {
    if (uri.size() < 2 || uri.front() != '#') {
        return false;
    }
    fragment = uri.substr(1);
    return fragment.rfind("xpointer", 0) != 0;
}

// Чи складається transforms щонайбільше з одного (C14N) перетворення -- саме
// такий випадок коректно покриває канонікалізація по Id напряму в doc.
// Дзеркалить IsCanonicalizationOnlyTransform з XmlSignatureVerifier.cpp.
inline bool IsArchiveImprintCanonicalizationOnlyTransform(const std::vector<std::string>& transforms) {
    if (transforms.size() > 1) {
        return false;
    }
    if (transforms.empty()) {
        return true;
    }
    int mode = 0;
    int comments = 0;
    return tamga::xmldsig::detail::C14nUriToMode(transforms.front(), mode, comments);
}

// Будує вхід для message imprint архівної мітки часу за ETSI EN 319 132-1
// §5.5.2.3 (not-distributed case). Порядок конкатенації:
//
//   1. результати обробки ВСІХ ds:Reference у ds:SignedInfo цього підпису, у
//      порядку появи, включно з посиланням на SignedProperties (XMLDSIG
//      reference processing: resolve -> transforms; якщо результат --
//      node-set, він канонікалізується всередині ApplyTransforms);
//   2. ds:SignedInfo (канонікалізований);
//   3. ds:SignatureValue (канонікалізований);
//   4. ds:KeyInfo (канонікалізований), якщо присутній;
//   5. unsigned qualifying properties, перелічені у
//      unsigned_property_local_names_present -- викликач передає ТОЧНИЙ
//      перелік і порядок: при СТВОРЕННІ нового ArchiveTimeStamp це всі
//      unsigned properties, наявні на момент побудови; при ПЕРЕВІРЦІ вже
//      наявного ArchiveTimeStamp це лише ті властивості, що йому
//      ПЕРЕДУЮТЬ у документі (не всі, і не наступні/новіші);
//   6. усі ds:Object, КРІМ того, що містить xades:QualifyingProperties
//      (сам QualifyingProperties/SignedProperties вже покритий кроком 1
//      через ds:Reference на SignedProperties).
//
// Підтримується ЛИШЕ not-distributed case: усі time-stamped unsigned
// properties мають того самого батька (UnsignedSignatureProperties), що й
// (майбутній) ArchiveTimeStamp. У Tamga це завжди виконується (один
// UnsignedSignatureProperties на підпис) -- distributed case (xades:Include)
// не застосовний до поточної структури підпису Tamga і не реалізований.
//
// signature_node/signature_position_1based -- та сама пара, що й у
// FindFirstElementInSubtree/ConcatCanonicalWithinSignature (WP-2 scoping):
// увесь пошук/канонікалізація виконуються СТРОГО в межах ОДНОГО
// ds:Signature, без ризику "просочування" в сусідній підпис.
inline bool BuildArchiveTimeStampImprintInput(
    xmlDocPtr doc,
    const std::string& signed_xml,
    int signature_position_1based,
    xmlNodePtr signature_node,
    const std::vector<std::string>& unsigned_property_local_names_present,
    int c14n_mode,
    int c14n_with_comments,
    std::string& out,
    std::string& error_message) {
    out.clear();

    // Крок 1: результати ds:Reference (СТРОГО в межах цього підпису).
    tamga::xmldsig::XmlReferenceResolver resolver;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    std::vector<tamga::xmldsig::XmlReference> references;
    if (!resolver.ExtractReferencesForSignature(signed_xml, signature_position_1based, references,
                                                error_message)) {
        return false;
    }
    for (const auto& ref : references) {
        std::string octets;
        std::string fragment;
        if (IsArchiveImprintIdFragmentUri(ref.uri, fragment) &&
            IsArchiveImprintCanonicalizationOnlyTransform(ref.transforms)) {
            // Same-document "#id" з щонайбільше одним (C14N) transform --
            // канонікалізуємо ПРЯМО в doc (той самий патерн, що й
            // XmlSignatureVerifier::VerifySignatureAtPosition, щоб SignedProperties
            // не втратив успадковані namespace-декларації при перепарсингу).
            int ref_mode = XML_C14N_1_0;
            int ref_comments = 0;
            if (!ref.transforms.empty()) {
                tamga::xmldsig::detail::C14nUriToMode(ref.transforms.front(), ref_mode, ref_comments);
            }
            if (!tamga::xmldsig::detail::CanonicalizeSubtreeById(doc, fragment, ref_mode, ref_comments,
                                                                 octets, error_message)) {
                return false;
            }
        } else {
            std::string resolved;
            if (!resolver.ResolveReference(signed_xml, ref, resolved, error_message)) {
                return false;
            }
            if (!transform_engine.ApplyTransforms(resolved, ref, octets, error_message)) {
                return false;
            }
        }
        out += octets;
    }

    // Кроки 2-4: SignedInfo, SignatureValue, KeyInfo (KeyInfo пропускається,
    // якщо відсутній -- ConcatCanonicalWithinSignature вже це підтримує).
    std::string core_octets;
    if (!tamga::xmldsig::detail::ConcatCanonicalWithinSignature(
            doc, signature_position_1based, signature_node,
            {"SignedInfo", "SignatureValue", "KeyInfo"}, c14n_mode, c14n_with_comments,
            core_octets, error_message)) {
        return false;
    }
    out += core_octets;

    // Крок 5: unsigned qualifying properties за переліком викликача.
    std::string usp_octets;
    if (!tamga::xmldsig::detail::ConcatCanonicalWithinSignature(
            doc, signature_position_1based, signature_node,
            unsigned_property_local_names_present, c14n_mode, c14n_with_comments,
            usp_octets, error_message)) {
        return false;
    }
    out += usp_octets;

    // Крок 6: усі ds:Object, крім того, що містить QualifyingProperties.
    std::string objects_octets;
    if (!tamga::xmldsig::detail::CanonicalizeNonQualifyingObjectsWithinSignature(
            doc, signature_position_1based, c14n_mode, c14n_with_comments, objects_octets,
            error_message)) {
        return false;
    }
    out += objects_octets;

    return true;
}

}  // namespace tamga::xades::detail

#endif  // TAMGA_XML_SIGNATURES_ENABLED
