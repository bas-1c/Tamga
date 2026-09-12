#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tamga::pades { struct PadesValidationEvidence; }
namespace tamga::core { struct OcspSettings; }

namespace tamga::core::pades_detail {

// Внутрішня точка перевірки збору доказів без PDF/TSP-транспорту.
// Кожен виклик повторно перевіряє наявні CRL/OCSP на validation_time;
// наявність сертифіката в кеші не замінює перевірку нового моменту часу.
// Доступна в конфігурації TAMGA_PDF_SIGNATURES_ENABLED.
bool CollectPadesCertificateEvidence(
    const std::vector<std::uint8_t>& certificate,
    const std::vector<std::vector<std::uint8_t>>& candidates,
    const std::vector<std::vector<std::uint8_t>>& ca_anchors,
    const std::string& work_dir, bool offline, const OcspSettings& ocsp_settings,
    const std::string& validation_time, tamga::pades::PadesValidationEvidence& evidence,
    std::string& error);

} // namespace tamga::core::pades_detail
