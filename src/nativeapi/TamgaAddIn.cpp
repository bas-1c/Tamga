#include "nativeapi/TamgaAddIn.h"
#include "util/FileSystem.h"

#include <algorithm>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iterator>

#include "util/Base64.h"
#include "util/SecureZero.h"
#include "util/Utf.h"
#include "nativeapi/VariantUtils.h"

namespace tamga::nativeapi {

namespace {
enum class SignatureFormat {
    CmsDetached,
    CmsAttached,
    CadesBes,
    CadesT,
    AsicS,
    AsicE,
    // CAdES-розкладка ASiC. Типові AsicS/AsicE віддають XAdES, а ці два
    // значення явно обирають CAdES-варіант контейнера.
    AsicSCades,
    AsicECades,
    Xades,
    Pades,
    AsicEXades,
};

enum class EncodingMode {
    Binary,
    Base64,
    File,
    Text,
    None,
};

const std::array<const wchar_t*, TamgaAddIn::ePropLast> kPropNames = {
    L"IsInitialized", L"OfflineMode", L"IsPrivateKeyReaded", L"NeedSetSettings"};
const std::array<const wchar_t*, TamgaAddIn::ePropLast> kPropNamesRu = {
    L"БиблиотекаИнициализирована", L"АвтономныйРежим", L"ЛичныйКлючСчитан", L"НеобходимоУстановитьПараметры"};

const std::array<const wchar_t*, TamgaAddIn::eMethLast> kMethodNames = {
    L"Initialize", L"Finalize", L"ShowCertificates", L"ShowCRLs", L"GetPrivateKeyMedia", L"GetCertificateInfo",
    L"BASE64Encode", L"BASE64Decode", L"SignData", L"VerifyData", L"SignFile", L"VerifyFile", L"SignXml", L"VerifyXml", L"SignPdf", L"VerifyPdf",
    L"Configure", L"ConfigureTsp", L"ConfigureOcsp", L"ConfigureLdap", L"ConfigureCmp", L"LoadKey", L"ResetKey",
    L"GetReport", L"GetError", L"ConfigureTrustList", L"SyncTrustList", L"GetUserReport"};
const std::array<const wchar_t*, TamgaAddIn::eMethLast> kMethodNamesRu = {
    L"Инициализировать", L"ЗавершитьРаботу", L"ПоказатьСертификаты", L"ПоказатьСпискиОтзыва",
    L"ОпределитьПараметрыНосителяЛичногоКлюча", L"ПолучитьИнформациюОСертификате", L"BASE64Кодировать",
    L"BASE64Декодировать", L"ПодписатьДанные", L"ПроверитьПодпись", L"ПодписатьФайл", L"ПроверитьПодписьФайла", L"ПодписатьXML", L"ПроверитьXML", L"ПодписатьPDF",
    L"ПроверитьPDF", L"Настроить", L"НастроитьTSP", L"НастроитьOCSP", L"НастроитьLDAP", L"НастроитьCMP", L"ЗагрузитьКлюч",
    L"СброситьКлюч", L"ПолучитьОтчет", L"ПолучитьОшибку", L"НастроитьДоверенныйСписок",
    L"ОбновитьДоверенныйСписок", L"ПолучитьОтчетПользователя"};

constexpr WCHAR_T kClassNames[] = u"Tamga";
constexpr WCHAR_T kExtensionName[] = u"Tamga";

bool SetUtf8Result(IMemoryManager* memory, tVariant* result, const std::string& value) {
    return util::SetWString(memory, result, util::FromUtf8(value));
}

[[maybe_unused]] bool GetOptionalWString(const tVariant* variant, std::wstring& value) {
    if (variant == nullptr || TV_VT(variant) == VTYPE_EMPTY || TV_VT(variant) == VTYPE_NULL) {
        value.clear();
        return true;
    }
    return util::GetWString(variant, value);
}

bool GetOptionalBool(const tVariant* params, const long size, const long index, bool& value) {
    if (index >= size || params == nullptr || TV_VT(&params[index]) == VTYPE_EMPTY || TV_VT(&params[index]) == VTYPE_NULL) {
        return true;
    }
    return util::GetBool(&params[index], value);
}

bool GetOptionalInt32(const tVariant* params, const long size, const long index, std::int32_t& value) {
    if (index >= size || params == nullptr || TV_VT(&params[index]) == VTYPE_EMPTY || TV_VT(&params[index]) == VTYPE_NULL) {
        return true;
    }
    return util::GetInt32(&params[index], value);
}

bool GetOptionalString(const tVariant* params, const long size, const long index, std::wstring& value) {
    if (index >= size || params == nullptr || TV_VT(&params[index]) == VTYPE_EMPTY || TV_VT(&params[index]) == VTYPE_NULL) {
        return true;
    }
    return util::GetWString(&params[index], value);
}

std::wstring Lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

// N-004: регістронезалежний fold для порівняння імен методів/властивостей.
// Мова 1С регістронезалежна до ідентифікаторів, а платформа передає ім'я так,
// як його набрав розробник (у довільному регістрі), тому FindMethod/FindProp
// мусять порівнювати без урахування регістру. std::towlower ненадійний для
// кирилиці (залежить від C-локалі процесу), тому робимо явний fold для ASCII
// (A-Z) і кириличних діапазонів (А-Я + Ё) — саме той набір, що зустрічається в
// англійських і російських alias-ах kMethodNames/kPropNames. Значення поза цими
// діапазонами лишаються без змін.
wchar_t FoldNameChar(wchar_t ch) {
    if (ch >= L'A' && ch <= L'Z') {
        return static_cast<wchar_t>(ch + (L'a' - L'A'));
    }
    const auto code = static_cast<unsigned long>(ch);
    if (code >= 0x0410 && code <= 0x042F) {  // Cyrillic А-Я -> а-я
        return static_cast<wchar_t>(code + 0x20);
    }
    if (code == 0x0401) {  // Cyrillic Ё -> ё
        return static_cast<wchar_t>(0x0451);
    }
    return ch;
}

bool NameEqualsFolded(const wchar_t* candidate, const std::wstring& value) {
    // Захисна перевірка (Gemini review PR #43): candidate завжди приходить зі
    // статичного масиву рядкових літералів (kMethodNames/kPropNames) і не буває
    // null, але guard знімає ризик розіменування, якщо джерело колись зміниться.
    if (candidate == nullptr) {
        return false;
    }
    std::size_t i = 0;
    for (; candidate[i] != L'\0' && i < value.size(); ++i) {
        if (FoldNameChar(candidate[i]) != FoldNameChar(value[i])) {
            return false;
        }
    }
    return candidate[i] == L'\0' && i == value.size();
}

bool ParseSignatureFormat(const std::wstring& value, SignatureFormat& out) {
    const auto mode = Lower(value.empty() ? L"cms-detached" : value);
    if (mode == L"cms-detached") {
        out = SignatureFormat::CmsDetached;
        return true;
    }
    if (mode == L"cms-attached") {
        out = SignatureFormat::CmsAttached;
        return true;
    }
    if (mode == L"cades-bes") {
        out = SignatureFormat::CadesBes;
        return true;
    }
    if (mode == L"cades-t") {
        out = SignatureFormat::CadesT;
        return true;
    }
    if (mode == L"asic-s") {
        out = SignatureFormat::AsicS;
        return true;
    }
    if (mode == L"asic-e") {
        out = SignatureFormat::AsicE;
        return true;
    }
    if (mode == L"asic-s-cades") {
        out = SignatureFormat::AsicSCades;
        return true;
    }
    if (mode == L"asic-e-cades") {
        out = SignatureFormat::AsicECades;
        return true;
    }
    if (mode == L"xades") {
        out = SignatureFormat::Xades;
        return true;
    }
    if (mode == L"pades") {
        out = SignatureFormat::Pades;
        return true;
    }
    if (mode == L"asic-e-xades") {
        out = SignatureFormat::AsicEXades;
        return true;
    }
    return false;
}

bool ParseEncodingMode(const std::wstring& value, EncodingMode& out) {
    const auto mode = Lower(value.empty() ? L"binary" : value);
    if (mode == L"binary") {
        out = EncodingMode::Binary;
        return true;
    }
    if (mode == L"base64") {
        out = EncodingMode::Base64;
        return true;
    }
    if (mode == L"file") {
        out = EncodingMode::File;
        return true;
    }
    if (mode == L"text") {
        out = EncodingMode::Text;
        return true;
    }
    if (mode == L"none") {
        out = EncodingMode::None;
        return true;
    }
    return false;
}

std::filesystem::path NativePathFromWString(const std::wstring& value) {
#if defined(_WIN32)
    return std::filesystem::path(value);
#else
    return std::filesystem::path(util::ToUtf8(value));
#endif
}

tamga::core::TimestampMode TimestampModeFor(const SignatureFormat format) {
    if (format == SignatureFormat::CadesBes) {
        return tamga::core::TimestampMode::Disabled;
    }
    if (format == SignatureFormat::CadesT) {
        return tamga::core::TimestampMode::Required;
    }
    return tamga::core::TimestampMode::BestEffort;
}

bool SetInt32Result(tVariant* result, std::int32_t value) {
    if (result == nullptr) {
        return false;
    }
    tVarInit(result);
    TV_VT(result) = VTYPE_I4;
    result->lVal = value;
    return true;
}
} // namespace

bool TamgaAddIn::Init(void* connection) {
    connection_ = static_cast<IAddInDefBase*>(connection);
    return connection_ != nullptr;
}

bool TamgaAddIn::setMemManager(void* mem) {
    memory_ = static_cast<IMemoryManager*>(mem);
    return memory_ != nullptr;
}

long TamgaAddIn::GetInfo() { return 2000; }

void TamgaAddIn::Done() { session_.Finalize(); }

bool TamgaAddIn::RegisterExtensionAs(WCHAR_T** wsExtensionName) {
    if (memory_ == nullptr || wsExtensionName == nullptr) {
        return false;
    }
    const unsigned len = static_cast<unsigned>(std::char_traits<char16_t>::length(kExtensionName));
    if (!memory_->AllocMemory(reinterpret_cast<void**>(wsExtensionName), (len + 1) * sizeof(WCHAR_T))) {
        return false;
    }
    std::copy(kExtensionName, kExtensionName + len + 1, *wsExtensionName);
    return true;
}

long TamgaAddIn::GetNProps() { return ePropLast; }

long TamgaAddIn::FindProp(const WCHAR_T* wsPropName) {
    const auto name = util::FromShortWchar(wsPropName);
    const auto by_en = FindName(kPropNames, name);
    return by_en >= 0 ? by_en : FindName(kPropNamesRu, name);
}

const WCHAR_T* TamgaAddIn::GetPropName(const long lPropNum, const long lPropAlias) {
    if (lPropNum < 0 || lPropNum >= ePropLast || memory_ == nullptr) {
        return nullptr;
    }
    const auto* source = (lPropAlias == 0) ? kPropNames[lPropNum] : kPropNamesRu[lPropNum];
    const std::u16string value = util::ToShortWchar(std::wstring(source));

    WCHAR_T* result = nullptr;
    if (!memory_->AllocMemory(reinterpret_cast<void**>(&result), static_cast<unsigned>((value.size() + 1) * sizeof(WCHAR_T)))) {
        return nullptr;
    }
    std::copy(value.begin(), value.end(), result);
    result[value.size()] = 0;
    return result;
}

bool TamgaAddIn::GetPropVal(const long lPropNum, tVariant* pvarPropVal) {
    switch (lPropNum) {
        case ePropIsInitialized:
            util::SetBool(pvarPropVal, session_.IsInitialized());
            return true;
        case ePropOfflineMode:
            util::SetBool(pvarPropVal, session_.OfflineMode());
            return true;
        case ePropIsPrivateKeyReaded:
            util::SetBool(pvarPropVal, session_.IsPrivateKeyLoaded());
            return true;
        case ePropNeedSetSettings:
            util::SetBool(pvarPropVal, session_.NeedSetSettings());
            return true;
        default:
            return false;
    }
}

bool TamgaAddIn::SetPropVal(const long, tVariant*) { return false; }

bool TamgaAddIn::IsPropReadable(const long lPropNum) { return lPropNum >= 0 && lPropNum < ePropLast; }

bool TamgaAddIn::IsPropWritable(const long) { return false; }

long TamgaAddIn::GetNMethods() { return eMethLast; }

long TamgaAddIn::FindMethod(const WCHAR_T* wsMethodName) {
    const auto name = util::FromShortWchar(wsMethodName);
    const auto by_en = FindName(kMethodNames, name);
    return by_en >= 0 ? by_en : FindName(kMethodNamesRu, name);
}

const WCHAR_T* TamgaAddIn::GetMethodName(const long lMethodNum, const long lMethodAlias) {
    if (lMethodNum < 0 || lMethodNum >= eMethLast || memory_ == nullptr) {
        return nullptr;
    }
    const auto* source = (lMethodAlias == 0) ? kMethodNames[lMethodNum] : kMethodNamesRu[lMethodNum];
    const std::u16string value = util::ToShortWchar(std::wstring(source));

    WCHAR_T* result = nullptr;
    if (!memory_->AllocMemory(reinterpret_cast<void**>(&result), static_cast<unsigned>((value.size() + 1) * sizeof(WCHAR_T)))) {
        return nullptr;
    }
    std::copy(value.begin(), value.end(), result);
    result[value.size()] = 0;
    return result;
}

long TamgaAddIn::GetNParams(const long lMethodNum) {
    switch (lMethodNum) {
        case eMethGetCertificateInfo: return 2;
        case eMethBase64Encode: return 1;
        case eMethBase64Decode: return 1;
        case eMethSignData: return 3;
        case eMethVerifyData: return 5;
        case eMethSignFile: return 4;
        case eMethVerifyFile: return 4;
        case eMethSignXml: return 2;
        case eMethVerifyXml: return 1;
        // А-07: другий параметр — профіль PAdES (необовʼязковий, типово B).
        case eMethSignPdf: return 2;
        case eMethVerifyPdf: return 1;
        // П'ятий параметр allowAiaIssuerFetch є явним opt-in для мережевих URL,
        // що походять із недовіреного сертифіката.
        case eMethConfigure: return 5;
        case eMethConfigureTsp: return 4;
        case eMethConfigureOcsp: return 3;
        case eMethConfigureLdap: return 3;
        case eMethConfigureCmp: return 3;
        case eMethConfigureTrustList: return 5;
        case eMethSyncTrustList: return 0;
        case eMethGetUserReport: return 0;
        case eMethLoadKey: return 5;
        case eMethResetKey: return 0;
        case eMethGetReport: return 0;
        case eMethGetError: return 0;
        default: return 0;
    }
}

bool TamgaAddIn::GetParamDefValue(const long lMethodNum, const long lParamNum, tVariant* pvarParamDefValue) {
    if (pvarParamDefValue == nullptr) {
        return false;
    }

    if (lMethodNum == eMethConfigure) {
        if (lParamNum == 0) {
            util::SetBool(pvarParamDefValue, true);
            return true;
        }
        if (lParamNum == 1) return util::SetWString(memory_, pvarParamDefValue, L"");
        if (lParamNum == 2) return util::SetWString(memory_, pvarParamDefValue, L"strict");
        // F-11: validationLevel; "standard" — те саме, що діяло досі неявно.
        if (lParamNum == 3) return util::SetWString(memory_, pvarParamDefValue, L"standard");
        if (lParamNum == 4) {
            util::SetBool(pvarParamDefValue, false);
            return true;
        }
    }
    // ME-08: опційний validationTimeIso -- порожній рядок = поведінка "як раніше" (validAt для "зараз").
    if (lMethodNum == eMethGetCertificateInfo) {
        if (lParamNum == 1) return util::SetWString(memory_, pvarParamDefValue, L"");
    }
    if (lMethodNum == eMethConfigureTsp) {
        if (lParamNum == 0 || lParamNum == 1 || lParamNum == 3) return util::SetWString(memory_, pvarParamDefValue, L"");
        if (lParamNum == 2) return SetInt32Result(pvarParamDefValue, 10000);
    }
    if (lMethodNum == eMethConfigureOcsp) {
        if (lParamNum == 0) return util::SetWString(memory_, pvarParamDefValue, L"");
        if (lParamNum == 1) {
            util::SetBool(pvarParamDefValue, true);
            return true;
        }
        if (lParamNum == 2) return SetInt32Result(pvarParamDefValue, 10000);
    }
    if (lMethodNum == eMethConfigureLdap || lMethodNum == eMethConfigureCmp) {
        if (lParamNum == 0 || lParamNum == 1) return util::SetWString(memory_, pvarParamDefValue, L"");
        if (lParamNum == 2) return SetInt32Result(pvarParamDefValue, 10000);
    }
    if (lMethodNum == eMethConfigureTrustList) {
        if (lParamNum == 0) return util::SetWString(memory_, pvarParamDefValue, L"");
        if (lParamNum == 1) return SetInt32Result(pvarParamDefValue, 30000);
        if (lParamNum == 2) return SetInt32Result(pvarParamDefValue, 24);
        // B-3: pinnedCertBase64 — порожній дефолт зберігає сумісність із 3-параметровими
        // викликами з 1С (той самий прийом, що ME-08 для GetCertificateInfo).
        if (lParamNum == 3 || lParamNum == 4) return util::SetWString(memory_, pvarParamDefValue, L"");
    }
    if (lMethodNum == eMethLoadKey) {
        if (lParamNum == 2 || lParamNum == 3) return util::SetWString(memory_, pvarParamDefValue, L"");
        if (lParamNum == 4) return util::SetWString(memory_, pvarParamDefValue, L"auto");
    }
    if (lMethodNum == eMethSignXml) {
        if (lParamNum == 1) return util::SetWString(memory_, pvarParamDefValue, L"");
    }
    if (lMethodNum == eMethSignPdf) {
        // А-07: порожній рядок = PAdES-B, тобто поведінка до зміни без змін.
        if (lParamNum == 1) return util::SetWString(memory_, pvarParamDefValue, L"");
    }
    if (lMethodNum == eMethSignData) {
        if (lParamNum == 1) return util::SetWString(memory_, pvarParamDefValue, L"cms-detached");
        if (lParamNum == 2) return util::SetWString(memory_, pvarParamDefValue, L"binary");
    }
    if (lMethodNum == eMethVerifyData) {
        if (lParamNum == 2) return util::SetWString(memory_, pvarParamDefValue, L"cms-detached");
        if (lParamNum == 3) return util::SetWString(memory_, pvarParamDefValue, L"binary");
        if (lParamNum == 4) return util::SetWString(memory_, pvarParamDefValue, L"none");
    }
    if (lMethodNum == eMethSignFile) {
        if (lParamNum == 1) return util::SetWString(memory_, pvarParamDefValue, L"");
        if (lParamNum == 2) return util::SetWString(memory_, pvarParamDefValue, L"cms-detached");
        if (lParamNum == 3) return util::SetWString(memory_, pvarParamDefValue, L"binary");
    }
    if (lMethodNum == eMethVerifyFile) {
        if (lParamNum == 1) return util::SetWString(memory_, pvarParamDefValue, L"");
        if (lParamNum == 2) return util::SetWString(memory_, pvarParamDefValue, L"cms-detached");
        if (lParamNum == 3) return util::SetWString(memory_, pvarParamDefValue, L"binary");
    }

    tVarInit(pvarParamDefValue);
    return false;
}

bool TamgaAddIn::HasRetVal(const long lMethodNum) {
    return lMethodNum >= 0 && lMethodNum < eMethLast;
}

bool TamgaAddIn::CallAsProc(long, tVariant*, long) { return false; }

bool TamgaAddIn::CallAsFunc(const long lMethodNum, tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray) {
    switch (lMethodNum) {
        case eMethInitialize:
            util::SetBool(pvarRetValue, session_.Initialize());
            return true;
        case eMethFinalize:
            util::SetBool(pvarRetValue, session_.Finalize());
            return true;
        case eMethShowCertificates:
            util::SetBool(pvarRetValue, session_.ShowCertificates());
            return true;
        case eMethShowCRLs:
            util::SetBool(pvarRetValue, session_.ShowCRLs());
            return true;
        case eMethGetPrivateKeyMedia: {
            std::string media_json;
            if (!session_.DescribeSupportedMedia(media_json)) return false;
            return SetUtf8Result(memory_, pvarRetValue, media_json);
        }
        case eMethGetCertificateInfo: {
            if (lSizeArray < 1 || lSizeArray > 2) return false;
            std::vector<std::uint8_t> cert_data;
            std::wstring validation_time_iso;
            std::string cert_json;
            if (!util::GetBlob(&paParams[0], cert_data)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 1, validation_time_iso)) return false;
            if (!session_.GetCertificateInfo(cert_data, cert_json, util::ToUtf8(validation_time_iso))) return false;
            return SetUtf8Result(memory_, pvarRetValue, cert_json);
        }
        case eMethBase64Encode: {
            if (lSizeArray != 1) return false;
            std::vector<std::uint8_t> data;
            std::string output;
            if (!util::GetBlob(&paParams[0], data)) return false;
            if (!session_.Base64Encode(data, output)) return false;
            return SetUtf8Result(memory_, pvarRetValue, output);
        }
        case eMethBase64Decode: {
            if (lSizeArray != 1) return false;
            std::wstring data;
            std::vector<std::uint8_t> output;
            if (!util::GetWString(&paParams[0], data)) return false;
            if (!session_.Base64Decode(util::ToUtf8(data), output)) return false;
            return util::SetBlob(memory_, pvarRetValue, output);
        }
        case eMethSignData: {
            if (lSizeArray < 1 || lSizeArray > 3) return false;
            std::vector<std::uint8_t> data;
            std::wstring format_text = L"cms-detached";
            std::wstring encoding_text = L"binary";
            std::vector<std::uint8_t> signature;
            if (!util::GetBlob(&paParams[0], data)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 1, format_text)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 2, encoding_text)) return false;

            SignatureFormat format = SignatureFormat::CmsDetached;
            EncodingMode encoding = EncodingMode::Binary;
            if (!ParseSignatureFormat(format_text, format) || !ParseEncodingMode(encoding_text, encoding)) return false;
            if (format == SignatureFormat::AsicS || format == SignatureFormat::AsicE ||
                format == SignatureFormat::AsicSCades || format == SignatureFormat::AsicECades ||
                format == SignatureFormat::Xades || format == SignatureFormat::Pades ||
                format == SignatureFormat::AsicEXades || encoding == EncodingMode::File ||
                encoding == EncodingMode::Text || encoding == EncodingMode::None) {
                return false;
            }

            const auto timestamp_mode = TimestampModeFor(format);
            const bool ok = (format == SignatureFormat::CmsAttached)
                ? session_.SignDataInternal(data, signature, timestamp_mode)
                : session_.SignData(data, signature, timestamp_mode);
            if (!ok) return false;
            if (encoding == EncodingMode::Base64) {
                return SetUtf8Result(memory_, pvarRetValue, tamga::util::Base64Encode(signature));
            }
            return util::SetBlob(memory_, pvarRetValue, signature);
        }
        case eMethVerifyData: {
            auto fail_verify_data = [&](const char* message) {
                session_.RecordVerifyFailure("VerifyData", tamga::core::ErrorCode::InvalidArgument, message);
                return false;
            };
            if (lSizeArray < 2 || lSizeArray > 5) return fail_verify_data("VerifyData argument count is invalid");
            std::vector<std::uint8_t> data;
            std::vector<std::uint8_t> signature;
            std::wstring format_text = L"cms-detached";
            std::wstring input_encoding_text = L"binary";
            std::wstring content_encoding_text = L"none";
            bool valid = false;
            if (!GetOptionalString(paParams, lSizeArray, 2, format_text)) return fail_verify_data("VerifyData signatureFormat argument is invalid");
            if (!GetOptionalString(paParams, lSizeArray, 3, input_encoding_text)) return fail_verify_data("VerifyData inputEncoding argument is invalid");
            if (!GetOptionalString(paParams, lSizeArray, 4, content_encoding_text)) return fail_verify_data("VerifyData contentEncoding argument is invalid");

            SignatureFormat format = SignatureFormat::CmsDetached;
            EncodingMode input_encoding = EncodingMode::Binary;
            EncodingMode content_encoding = EncodingMode::None;
            if (!ParseSignatureFormat(format_text, format) ||
                !ParseEncodingMode(input_encoding_text, input_encoding) ||
                !ParseEncodingMode(content_encoding_text, content_encoding)) {
                return fail_verify_data("VerifyData format or encoding value is invalid");
            }
            if (format != SignatureFormat::CmsAttached && !util::GetBlob(&paParams[0], data)) {
                return fail_verify_data("VerifyData payload argument is invalid");
            }

            if (input_encoding == EncodingMode::Base64) {
                std::wstring signature_base64;
                if (!util::GetWString(&paParams[1], signature_base64)) return fail_verify_data("VerifyData Base64 signature argument is invalid");
                if (!tamga::util::Base64Decode(util::ToUtf8(signature_base64), signature)) {
                    return fail_verify_data("Signature Base64 is invalid");
                }
            } else if (input_encoding == EncodingMode::Binary) {
                if (!util::GetBlob(&paParams[1], signature)) return fail_verify_data("VerifyData signature argument is invalid");
            } else {
                return fail_verify_data("VerifyData inputEncoding mode is unsupported");
            }

            if (format == SignatureFormat::CmsAttached) {
                if (content_encoding != EncodingMode::Text &&
                    content_encoding != EncodingMode::Binary &&
                    content_encoding != EncodingMode::None) {
                    return fail_verify_data("VerifyData contentEncoding mode is unsupported");
                }
                std::vector<std::uint8_t> content;
                if (!session_.VerifyDataInternal(signature, valid, content)) {
                    util::SetBool(pvarRetValue, false);
                    return true;
                }
                if (content_encoding == EncodingMode::Text) {
                    return SetUtf8Result(memory_, pvarRetValue, std::string(content.begin(), content.end()));
                }
                if (content_encoding == EncodingMode::Binary) {
                    return util::SetBlob(memory_, pvarRetValue, content);
                }
                if (content_encoding != EncodingMode::None) {
                    return fail_verify_data("VerifyData contentEncoding mode is unsupported");
                }
                util::SetBool(pvarRetValue, valid);
                return true;
            }

            if (format == SignatureFormat::AsicS || format == SignatureFormat::AsicE ||
                format == SignatureFormat::AsicSCades || format == SignatureFormat::AsicECades ||
                format == SignatureFormat::Xades || format == SignatureFormat::Pades ||
                format == SignatureFormat::AsicEXades) {
                return fail_verify_data("VerifyData signatureFormat mode is unsupported");
            }
            if (!session_.VerifyData(data, signature, valid)) {
                util::SetBool(pvarRetValue, false);
                return true;
            }
            util::SetBool(pvarRetValue, valid);
            return true;
        }
        case eMethSignFile: {
            if (lSizeArray < 1 || lSizeArray > 4) return false;
            std::wstring input_path;
            std::wstring output_path;
            std::wstring format_text = L"cms-detached";
            std::wstring output_encoding_text = L"binary";
            std::vector<std::uint8_t> signature;
            if (!util::GetWString(&paParams[0], input_path)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 1, output_path)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 2, format_text)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 3, output_encoding_text)) return false;

            SignatureFormat format = SignatureFormat::CmsDetached;
            EncodingMode output_encoding = EncodingMode::Binary;
            if (!ParseSignatureFormat(format_text, format) || !ParseEncodingMode(output_encoding_text, output_encoding)) return false;

            if (format == SignatureFormat::Xades || format == SignatureFormat::Pades || format == SignatureFormat::AsicEXades) return false;

            if (format == SignatureFormat::AsicS || format == SignatureFormat::AsicE ||
                format == SignatureFormat::AsicSCades || format == SignatureFormat::AsicECades) {
                if (output_path.empty() || output_encoding != EncodingMode::File) return false;
                const std::string in = util::ToUtf8(input_path);
                const std::string out_file = util::ToUtf8(output_path);
                bool ok = false;
                switch (format) {
                    case SignatureFormat::AsicS: ok = session_.SignFileAsicS(in, out_file); break;
                    case SignatureFormat::AsicE: ok = session_.SignFileAsicE(in, out_file); break;
                    case SignatureFormat::AsicSCades: ok = session_.SignFileAsicSCades(in, out_file); break;
                    default: ok = session_.SignFileAsicECades(in, out_file); break;
                }
                util::SetBool(pvarRetValue, ok);
                return true;
            }

            if (format == SignatureFormat::CmsAttached || output_encoding == EncodingMode::Text || output_encoding == EncodingMode::None) {
                return false;
            }
            if (output_encoding == EncodingMode::File) {
                if (output_path.empty()) return false;
                util::SetBool(pvarRetValue,
                              session_.RawSignFile(util::ToUtf8(input_path), util::ToUtf8(output_path), TimestampModeFor(format)));
                return true;
            }
            if (!session_.SignFile(util::ToUtf8(input_path), signature, TimestampModeFor(format))) return false;
            if (output_encoding == EncodingMode::Base64) {
                return SetUtf8Result(memory_, pvarRetValue, tamga::util::Base64Encode(signature));
            }
            return util::SetBlob(memory_, pvarRetValue, signature);
        }
        case eMethVerifyFile: {
            auto fail_verify_file = [&](const std::string& message) {
                session_.RecordVerifyFailure("VerifyFile", tamga::core::ErrorCode::InvalidArgument, message);
                return false;
            };
            if (lSizeArray < 1 || lSizeArray > 4) return fail_verify_file("VerifyFile argument count is invalid");
            std::wstring input_path;
            std::wstring signature_or_path;
            std::wstring format_text = L"cms-detached";
            std::wstring input_encoding_text = L"binary";
            std::vector<std::uint8_t> signature;
            bool valid = false;
            if (!util::GetWString(&paParams[0], input_path)) return fail_verify_file("VerifyFile input path argument is invalid");
            if (!GetOptionalString(paParams, lSizeArray, 2, format_text)) return fail_verify_file("VerifyFile signatureFormat argument is invalid");
            if (!GetOptionalString(paParams, lSizeArray, 3, input_encoding_text)) return fail_verify_file("VerifyFile inputEncoding argument is invalid");

            SignatureFormat format = SignatureFormat::CmsDetached;
            EncodingMode input_encoding = EncodingMode::Binary;
            if (!ParseSignatureFormat(format_text, format) || !ParseEncodingMode(input_encoding_text, input_encoding)) {
                return fail_verify_file("VerifyFile format or encoding value is invalid");
            }

            if (format == SignatureFormat::Xades) {
                if (input_encoding != EncodingMode::File) return fail_verify_file("VerifyFile XAdES requires file inputEncoding");
                // В-04: ліміт 64 MiB діяв лише на шляху Session; NativeAPI
                // VerifyFile(xades/pades) читав файл довільного розміру цілком.
                std::string signed_xml;
                std::string read_error;
                if (!tamga::util::ReadTextFileLimited(NativePathFromWString(input_path),
                                                      tamga::util::kMaxInputFileSize,
                                                      signed_xml, read_error)) {
                    return fail_verify_file("XAdES file cannot be read: " + read_error);
                }
                if (!session_.VerifyXml(signed_xml, valid)) { util::SetBool(pvarRetValue, false); return true; }
                util::SetBool(pvarRetValue, valid);
                return true;
            }
            if (format == SignatureFormat::Pades) {
                if (input_encoding != EncodingMode::File) return fail_verify_file("VerifyFile PAdES requires file inputEncoding");
                std::vector<std::uint8_t> pdf;
                std::string read_error;
                if (!tamga::util::ReadBinaryFileLimited(NativePathFromWString(input_path),
                                                        tamga::util::kMaxInputFileSize,
                                                        pdf, read_error)) {
                    return fail_verify_file("PAdES file cannot be read: " + read_error);
                }
                if (!session_.VerifyPdf(pdf, valid)) { util::SetBool(pvarRetValue, false); return true; }
                util::SetBool(pvarRetValue, valid);
                return true;
            }
            if (format == SignatureFormat::AsicEXades) {
                const bool ok = session_.VerifyFileAsicEXades(util::ToUtf8(input_path), valid);
                if (!ok) { util::SetBool(pvarRetValue, false); return true; }
                util::SetBool(pvarRetValue, valid);
                return true;
            }

            if (format == SignatureFormat::AsicS || format == SignatureFormat::AsicE ||
                format == SignatureFormat::AsicSCades || format == SignatureFormat::AsicECades) {
                const bool ok = (format == SignatureFormat::AsicS ||
                                 format == SignatureFormat::AsicSCades)
                    ? session_.VerifyFileAsicS(util::ToUtf8(input_path), valid)
                    : session_.VerifyFileAsicE(util::ToUtf8(input_path), valid);
                if (!ok) {
                    util::SetBool(pvarRetValue, false);
                    return true;
                }
                util::SetBool(pvarRetValue, valid);
                return true;
            }
            if (format == SignatureFormat::CmsAttached || input_encoding == EncodingMode::Text || input_encoding == EncodingMode::None) {
                return fail_verify_file("VerifyFile format or inputEncoding mode is unsupported");
            }

            if (input_encoding == EncodingMode::File) {
                if (lSizeArray < 2 || !util::GetWString(&paParams[1], signature_or_path)) {
                    return fail_verify_file("VerifyFile signature path argument is invalid");
                }
                if (!session_.RawVerifyFile(util::ToUtf8(input_path), util::ToUtf8(signature_or_path), valid)) {
                    util::SetBool(pvarRetValue, false);
                    return true;
                }
                util::SetBool(pvarRetValue, valid);
                return true;
            } else if (input_encoding == EncodingMode::Base64) {
                std::wstring signature_base64;
                if (lSizeArray < 2 || !util::GetWString(&paParams[1], signature_base64)) {
                    return fail_verify_file("VerifyFile Base64 signature argument is invalid");
                }
                if (!tamga::util::Base64Decode(util::ToUtf8(signature_base64), signature)) {
                    return fail_verify_file("Signature Base64 is invalid");
                }
            } else {
                if (lSizeArray < 2 || !util::GetBlob(&paParams[1], signature)) {
                    return fail_verify_file("VerifyFile signature argument is invalid");
                }
            }

            if (!session_.VerifyFile(util::ToUtf8(input_path), signature, valid)) {
                util::SetBool(pvarRetValue, false);
                return true;
            }
            util::SetBool(pvarRetValue, valid);
            return true;
        }

        case eMethSignXml: {
            if (lSizeArray < 1 || lSizeArray > 2) return false;
            std::wstring xml;
            std::wstring profile_w;
            if (!util::GetWString(&paParams[0], xml)) return false;
            if (lSizeArray >= 2 && !util::GetWString(&paParams[1], profile_w)) return false;
            std::string signed_xml;
            const std::string profile = util::ToUtf8(profile_w);
            if (!session_.SignXml(util::ToUtf8(xml), profile, signed_xml)) return false;
            return SetUtf8Result(memory_, pvarRetValue, signed_xml);
        }
        case eMethVerifyXml: {
            // Q-06: молодший близнюк `VerifyData`/`VerifyFile`. Ті вже писали
            // невдачу аргументів у звіт через `RecordVerifyFailure`, а тут
            // ранній `return false` лишав у сесії звіт від ПОПЕРЕДНЬОЇ —
            // можливо успішної — перевірки. Сусідні методи одного контракту
            // мають поводитися однаково, інакше `GetLastVerifyReport` після
            // помилки означає різне залежно від того, який метод її дав.
            auto fail_verify_xml = [&](const char* message) {
                session_.RecordVerifyFailure("VerifyXml", tamga::core::ErrorCode::InvalidArgument, message);
                return false;
            };
            if (lSizeArray != 1) return fail_verify_xml("VerifyXml argument count is invalid");
            std::wstring xml;
            bool valid = false;
            if (!util::GetWString(&paParams[0], xml)) return fail_verify_xml("VerifyXml xml argument is invalid");
            if (!session_.VerifyXml(util::ToUtf8(xml), valid)) { util::SetBool(pvarRetValue, false); return true; }
            util::SetBool(pvarRetValue, valid);
            return true;
        }
        case eMethSignPdf: {
            // А-07: другий параметр необовʼязковий — виклик з одним аргументом
            // лишається дійсним і дає PAdES-B, як і до зміни.
            if (lSizeArray < 1 || lSizeArray > 2) return false;
            std::vector<std::uint8_t> pdf;
            std::wstring profile_w;
            std::vector<std::uint8_t> signed_pdf;
            if (!util::GetBlob(&paParams[0], pdf)) return false;
            if (lSizeArray >= 2 && !util::GetWString(&paParams[1], profile_w)) return false;
            if (!session_.SignPdf(pdf, util::ToUtf8(profile_w), signed_pdf)) return false;
            return util::SetBlob(memory_, pvarRetValue, signed_pdf);
        }
        case eMethVerifyPdf: {
            // Q-06: див. коментар у eMethVerifyXml — та сама неузгодженість.
            auto fail_verify_pdf = [&](const char* message) {
                session_.RecordVerifyFailure("VerifyPdf", tamga::core::ErrorCode::InvalidArgument, message);
                return false;
            };
            if (lSizeArray != 1) return fail_verify_pdf("VerifyPdf argument count is invalid");
            std::vector<std::uint8_t> pdf;
            bool valid = false;
            if (!util::GetBlob(&paParams[0], pdf)) return fail_verify_pdf("VerifyPdf pdf argument is invalid");
            if (!session_.VerifyPdf(pdf, valid)) { util::SetBool(pvarRetValue, false); return true; }
            util::SetBool(pvarRetValue, valid);
            return true;
        }
        case eMethConfigure: {
            if (lSizeArray > 5) return false;
            bool offline = true;
            bool allow_aia_issuer_fetch = false;
            std::wstring workdir;
            std::wstring trust_mode;
            std::wstring validation_level;
            if (!GetOptionalBool(paParams, lSizeArray, 0, offline)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 1, workdir)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 2, trust_mode)) return false;
            // F-11: рівень валідації (basic/standard/extended/forensic) був
            // доступний лише з C++ через Settings — з 1С його виставити було
            // неможливо, тож рівень завжди лишався типовим. Порожній рядок
            // означає «не задано»: SetSettings підставить "standard", а не
            // відхилить виклик, тому старі 3-параметрові виклики працюють як досі.
            if (!GetOptionalString(paParams, lSizeArray, 3, validation_level)) return false;
            if (!GetOptionalBool(paParams, lSizeArray, 4, allow_aia_issuer_fetch)) return false;
            tamga::core::Settings settings;
            settings.offline_mode = offline;
            settings.work_dir = util::ToUtf8(workdir);
            settings.trust_mode = util::ToUtf8(trust_mode);
            settings.validation_level = util::ToUtf8(validation_level);
            settings.allow_aia_issuer_fetch = allow_aia_issuer_fetch;
            // Нерозпізнаний рівень відхиляється в SetSettings (fail-closed) —
            // мовчазний відкат до "standard" приховав би помилку конфігурації.
            util::SetBool(pvarRetValue, session_.SetSettings(settings));
            return true;
        }
        case eMethConfigureTsp: {
            if (lSizeArray > 4) return false;
            std::wstring url;
            std::wstring policy;
            std::int32_t timeout_ms = 10000;
            std::wstring imprint_digest_oid;
            if (!GetOptionalString(paParams, lSizeArray, 0, url)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 1, policy)) return false;
            if (!GetOptionalInt32(paParams, lSizeArray, 2, timeout_ms)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 3, imprint_digest_oid)) return false;
            tamga::core::TspSettings settings;
            settings.url = util::ToUtf8(url);
            settings.policy_oid = util::ToUtf8(policy);
            settings.timeout_ms = timeout_ms;
            settings.imprint_digest_oid = util::ToUtf8(imprint_digest_oid);
            util::SetBool(pvarRetValue, session_.SetTspSettings(settings));
            return true;
        }
        case eMethConfigureOcsp: {
            if (lSizeArray > 3) return false;
            std::wstring url;
            bool use_nonce = true;
            std::int32_t timeout_ms = 10000;
            if (!GetOptionalString(paParams, lSizeArray, 0, url)) return false;
            if (!GetOptionalBool(paParams, lSizeArray, 1, use_nonce)) return false;
            if (!GetOptionalInt32(paParams, lSizeArray, 2, timeout_ms)) return false;
            tamga::core::OcspSettings settings;
            settings.url = util::ToUtf8(url);
            settings.use_nonce = use_nonce;
            settings.timeout_ms = timeout_ms;
            util::SetBool(pvarRetValue, session_.SetOcspSettings(settings));
            return true;
        }
        case eMethConfigureLdap: {
            if (lSizeArray > 3) return false;
            std::wstring url;
            std::wstring base_dn;
            std::int32_t timeout_ms = 10000;
            if (!GetOptionalString(paParams, lSizeArray, 0, url)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 1, base_dn)) return false;
            if (!GetOptionalInt32(paParams, lSizeArray, 2, timeout_ms)) return false;
            tamga::core::LdapSettings settings;
            settings.url = util::ToUtf8(url);
            settings.base_dn = util::ToUtf8(base_dn);
            settings.timeout_ms = timeout_ms;
            util::SetBool(pvarRetValue, session_.SetLdapSettings(settings));
            return true;
        }
        case eMethConfigureCmp: {
            if (lSizeArray > 3) return false;
            std::wstring url;
            std::wstring profile;
            std::int32_t timeout_ms = 10000;
            if (!GetOptionalString(paParams, lSizeArray, 0, url)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 1, profile)) return false;
            if (!GetOptionalInt32(paParams, lSizeArray, 2, timeout_ms)) return false;
            tamga::core::CmpSettings settings;
            settings.url = util::ToUtf8(url);
            settings.profile = util::ToUtf8(profile);
            settings.timeout_ms = timeout_ms;
            util::SetBool(pvarRetValue, session_.SetCmpSettings(settings));
            return true;
        }
        case eMethConfigureTrustList: {
            // B-3: 4-й параметр pinnedCertBase64 додано backward-compatible
            // (той самий прийом, що ME-08 для GetCertificateInfo). Без pinned-
            // сертифіката перевірка підпису TL доводить лише самоузгодженість
            // документа, а не його походження.
            if (lSizeArray > 5) return false;
            std::wstring url;
            std::int32_t timeout_ms = 30000;
            std::int32_t ttl_hours = 24;
            std::wstring pinned_cert_base64;
            std::wstring signature_policy;
            if (!GetOptionalString(paParams, lSizeArray, 0, url)) return false;
            if (!GetOptionalInt32(paParams, lSizeArray, 1, timeout_ms)) return false;
            if (!GetOptionalInt32(paParams, lSizeArray, 2, ttl_hours)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 3, pinned_cert_base64)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 4, signature_policy)) return false;
            tamga::core::TrustListSettings settings;
            // B-3: 5-й параметр дає 1С контроль над перевіркою підпису TL. Без нього
            // інтеграція, чий TL Tamga не вміє перевірити, не мала б жодного виходу,
            // окрім відмови від синхронізації взагалі.
            if (!signature_policy.empty()) {
                using XmlSigPolicy = tamga::core::TrustListSettings::XmlSignaturePolicy;
                const auto policy = Lower(signature_policy);
                if (policy == L"disabled" || policy == L"off") {
                    settings.xml_signature_policy = XmlSigPolicy::Disabled;
                } else if (policy == L"prefer" || policy == L"prefer-available") {
                    settings.xml_signature_policy = XmlSigPolicy::PreferAvailable;
                } else if (policy == L"require" || policy == L"required") {
                    settings.xml_signature_policy = XmlSigPolicy::Require;
                } else {
                    // Нерозпізнане значення — fail-closed: краще відмовити в
                    // конфігурації, ніж мовчки застосувати не ту політику.
                    util::SetBool(pvarRetValue, false);
                    return true;
                }
            }
            settings.url = util::ToUtf8(url);
            settings.timeout_ms = timeout_ms;
            settings.cache_ttl_hours = ttl_hours;
            if (!pinned_cert_base64.empty()) {
                const std::string pinned_b64 = util::ToUtf8(pinned_cert_base64);
                std::vector<std::uint8_t> pinned_der;
                if (!tamga::util::Base64Decode(pinned_b64, pinned_der) || pinned_der.empty()) {
                    // Fail-closed: краще відмовити в конфігурації, ніж мовчки
                    // продовжити без pinned-anchor, який користувач намагався задати.
                    util::SetBool(pvarRetValue, false);
                    return true;
                }
                settings.xml_signer_cert_der = std::move(pinned_der);
            }
            util::SetBool(pvarRetValue, session_.SetTrustListSettings(settings));
            return true;
        }
        case eMethSyncTrustList:
            if (lSizeArray != 0) return false;
            util::SetBool(pvarRetValue, session_.SyncTrustList());
            return true;
        case eMethLoadKey: {
            if (lSizeArray < 2 || lSizeArray > 5) return false;
            // П-06: секрети на межі з 1С.
            //
            // Ядро (`SessionKeyLoading.ipp`) і CLI (`main.cpp`) свої копії
            // паролів уже затирають — `SecureErase` і `util::ScopedSecret`
            // відповідно. Саме межа NativeAPI цього не робила: пароль, пароль
            // ключа, alias і матеріал ключа виходили зі scope звичайним
            // деструктором, а `ToUtf8(...)` у списку аргументів створював ще
            // одну незахищену копію-тимчасовий об'єкт. `clear()` і деструктора
            // тут недостатньо з причини, описаної в `docs/security.md`:
            // звичайний запис нулів — dead store, який компілятор має право
            // усунути, а `clear()` не звільняє ємність буфера.
            //
            // МЕЖА (і вона тут справжня): буфер усередині `tVariant` належить
            // платформі 1С. Контракту на його час життя, розміщення чи право
            // модифікації в SDK немає, тож ми його НЕ затираємо — затираємо
            // лише власні копії. Пароль, який 1С тримає у своїй пам'яті,
            // лишається зоною відповідальності платформи.
            std::wstring password;
            std::wstring key_password;
            std::wstring alias;
            std::wstring source_type = L"auto";
            const util::ScopedSecret password_wide_guard(password);
            const util::ScopedSecret key_password_wide_guard(key_password);
            const util::ScopedSecret alias_wide_guard(alias);
            if (!util::GetWString(&paParams[1], password)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 2, key_password)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 3, alias)) return false;
            if (!GetOptionalString(paParams, lSizeArray, 4, source_type)) return false;

            // Одна конверсія на виклик замість трьох-чотирьох тимчасових
            // `ToUtf8(...)` у списках аргументів: менше копій секрета — менше
            // місць, які нема кому затерти.
            std::string password_utf8 = util::ToUtf8(password);
            std::string key_password_utf8 = util::ToUtf8(key_password);
            std::string alias_utf8 = util::ToUtf8(alias);
            const util::ScopedSecret password_utf8_guard(password_utf8);
            const util::ScopedSecret key_password_utf8_guard(key_password_utf8);
            const util::ScopedSecret alias_utf8_guard(alias_utf8);

            const std::wstring source_type_lower = Lower(source_type);
            const bool binary_source_type = source_type_lower == L"auto" ||
                                            source_type_lower == L"binary" ||
                                            source_type_lower == L"jks" ||
                                            source_type_lower == L"pkcs12" ||
                                            source_type_lower == L"p12" ||
                                            source_type_lower == L"pfx" ||
                                            source_type_lower == L"pem" ||
                                            source_type_lower == L"der";
            if (binary_source_type && TV_VT(&paParams[0]) == VTYPE_BLOB) {
                // Вміст контейнера — це матеріал приватного ключа, а не просто
                // вхідні дані.
                std::vector<std::uint8_t> key_blob;
                const util::ScopedSecret key_blob_guard(key_blob);
                if (!util::GetBlob(&paParams[0], key_blob)) return false;
                util::SetBool(pvarRetValue,
                              session_.ReadPrivateKeyBinary(key_blob,
                                                            password_utf8,
                                                            key_password_utf8,
                                                            alias_utf8));
                return true;
            }

            std::wstring source;
            if (!util::GetWString(&paParams[0], source)) return false;
            if (source_type_lower == L"descriptor") {
                // JSON-дескриптор може містити пароль усередині себе (те саме
                // врахував CLI у В-07), тож обидві його копії — секрет.
                const util::ScopedSecret source_wide_guard(source);
                std::string source_utf8 = util::ToUtf8(source);
                const util::ScopedSecret source_utf8_guard(source_utf8);
                util::SetBool(pvarRetValue, session_.ReadPrivateKey(source_utf8, password_utf8));
                return true;
            }
            if (!binary_source_type && source_type_lower != L"file") {
                return false;
            }
            // Тут `source` — це шлях до файлу, а не секрет; затирати його
            // немає підстав.
            util::SetBool(pvarRetValue,
                          session_.ReadPrivateKeyFile(util::ToUtf8(source),
                                                      password_utf8,
                                                      key_password_utf8,
                                                      alias_utf8));
            return true;
        }
        case eMethResetKey:
            util::SetBool(pvarRetValue, session_.ResetPrivateKey());
            return true;
        case eMethGetReport: {
            std::string verify_json;
            if (!session_.GetLastVerifyReport(verify_json)) return false;
            return SetUtf8Result(memory_, pvarRetValue, verify_json);
        }
        case eMethGetUserReport: {
            std::string user_report_json;
            if (!session_.GetUserReport(user_report_json)) return false;
            return SetUtf8Result(memory_, pvarRetValue, user_report_json);
        }
        case eMethGetError: {
            const auto error = session_.GetLastError();
            return SetUtf8Result(memory_, pvarRetValue, error.message);
        }
        default:
            return false;
    }
}

void TamgaAddIn::SetLocale(const WCHAR_T* /*loc*/) {}

void TamgaAddIn::SetUserInterfaceLanguageCode(const WCHAR_T* /*lang*/) {}

long TamgaAddIn::FindName(const std::array<const wchar_t*, ePropLast>& names, const std::wstring& value) const {
    for (std::size_t i = 0; i < names.size(); ++i) {
        // N-004: регістронезалежне порівняння (1С передає ім'я в довільному регістрі).
        if (NameEqualsFolded(names[i], value)) {
            return static_cast<long>(i);
        }
    }
    return -1;
}

long TamgaAddIn::FindName(const std::array<const wchar_t*, eMethLast>& names, const std::wstring& value) const {
    for (std::size_t i = 0; i < names.size(); ++i) {
        // N-004: регістронезалежне порівняння (1С передає ім'я в довільному регістрі).
        if (NameEqualsFolded(names[i], value)) {
            return static_cast<long>(i);
        }
    }
    return -1;
}

} // namespace tamga::nativeapi
