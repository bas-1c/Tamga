#include "tamga/tamga_c_api.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <new>
#include <string>
#include <vector>

#include "tamga/Tamga.h"
#include "util/FileSystem.h"
#include "util/SecureZero.h"

// Версія приходить ЛИШЕ від системи збірки (`project()` -> CMakeLists.txt:658).
// Тут стояв запасний літерал `"0.4.1"` — і він мовчки застарівав: якби
// визначення колись перестало доходити до цієї TU, `tamga_version()` почав би
// повідомляти чужу версію, а збірка лишалася б зеленою. Для API, за яким
// споживач визначає сумісність, тиха неправда гірша за відмову зібратися.
#ifndef TAMGA_VERSION_STRING
#error "TAMGA_VERSION_STRING must come from the build system (see project() in CMakeLists.txt)"
#endif

struct tamga_session_opaque {
    tamga::core::Session session;
    std::string last_error_message;
    tamga_c_error_code_t last_error_code{TAMGA_C_OK};
    std::string last_report_cache;
    std::string user_report_cache;
};

namespace {

tamga_c_error_code_t MapErrorCode(tamga::core::ErrorCode code) {
    switch (code) {
        case tamga::core::ErrorCode::None:
            return TAMGA_C_OK;
        case tamga::core::ErrorCode::NotInitialized:
            return TAMGA_C_ERR_NOT_INITIALIZED;
        case tamga::core::ErrorCode::SettingsRequired:
            return TAMGA_C_ERR_SETTINGS_REQUIRED;
        case tamga::core::ErrorCode::InvalidArgument:
            return TAMGA_C_ERR_INVALID_ARGUMENT;
        case tamga::core::ErrorCode::KeyNotLoaded:
            return TAMGA_C_ERR_KEY_NOT_LOADED;
        case tamga::core::ErrorCode::OnlineServiceUnavailable:
            return TAMGA_C_ERR_ONLINE_UNAVAILABLE;
        case tamga::core::ErrorCode::RevocationCheckFailed:
            return TAMGA_C_ERR_REVOCATION_FAILED;
        // Н-10: три різні причини більше не зводяться в один код.
        // POLICY_INVALID лишається за власне policy-помилкою, а довіра й мітка
        // часу отримали власні значення.
        case tamga::core::ErrorCode::TrustValidationFailed:
            return TAMGA_C_ERR_TRUST_FAILED;
        case tamga::core::ErrorCode::TimestampValidationFailed:
            return TAMGA_C_ERR_TIMESTAMP_FAILED;
        case tamga::core::ErrorCode::PolicyValidationFailed:
            return TAMGA_C_ERR_POLICY_INVALID;
        case tamga::core::ErrorCode::NotSupported:
            return TAMGA_C_ERR_NOT_SUPPORTED;
        case tamga::core::ErrorCode::GuiNotAvailable:
            return TAMGA_C_ERR_GUI_NOT_AVAILABLE;
        case tamga::core::ErrorCode::InternalError:
        default:
            return TAMGA_C_ERR_INTERNAL;
    }
}

// В-04: C ABI читав файл довільного розміру цілком, обходячи ліміт 64 MiB,
// який діяв лише на шляху Session. Тепер обидва входи спираються на спільний
// util-хелпер із перевіркою розміру до і під час читання.
// ADR-027: перейменовано з `ReadBinaryFile`. Це адаптер під C-рядок з
// публічного ABI, а не ще одна реалізація читання файлу — сама робота
// давно в `util::ReadBinaryFileLimited`. Ім'я збігалося з сесійним
// хелпером, який має ІНШУ сигнатуру і додає мітку до повідомлення про
// помилку; через це храповик дублювання бачив «дві копії» там, де їх
// немає, і запис у ньому вводив в оману.
bool ReadBinaryFileArg(const char* path, std::vector<std::uint8_t>& out) {
    if (!path || !*path) return false;
    std::string error;
    return tamga::util::ReadBinaryFileLimited(std::filesystem::u8path(path),
                                              tamga::util::kMaxInputFileSize, out, error);
}

bool ReadTextFile(const char* path, std::string& out) {
    if (!path || !*path) return false;
    std::string error;
    return tamga::util::ReadTextFileLimited(std::filesystem::u8path(path),
                                            tamga::util::kMaxInputFileSize, out, error);
}

// П-12: обидва вихідні шляхи C ABI йдуть через спільний атомарний writer.
// Раніше вони писали прямим `ofstream ... trunc`, тобто обнуляли наявний
// файл ще до появи першого байта результату. Семантику перезапису описано
// один раз у `util/FileSystem.h`.
bool WriteBinaryFile(const char* path, const std::vector<std::uint8_t>& data) {
    if (!path || !*path) return false;
    return tamga::util::WriteBinaryFileAtomic(std::filesystem::u8path(path), data);
}

bool WriteTextFile(const char* path, const std::string& text) {
    if (!path || !*path) return false;
    return tamga::util::WriteTextFileAtomic(std::filesystem::u8path(path), text);
}

void SetLastError(tamga_session_t s, tamga_c_error_code_t code, const std::string& msg) noexcept {
    if (s) {
        s->last_error_code = code;
        try {
            s->last_error_message = msg;
        } catch (...) {
            s->last_error_message.clear();
        }
    }
}

void SetInternalErrorNoThrow(tamga_session_t s, const char* message) noexcept {
    if (!s) return;
    s->last_error_code = TAMGA_C_ERR_INTERNAL;
    try {
        s->last_error_message = message ? message : "Unhandled exception in Tamga C API";
    } catch (...) {
        s->last_error_message.clear();
    }
}

void SyncSessionError(tamga_session_t s) noexcept {
    if (s) {
        try {
            const auto err = s->session.GetLastError();
            s->last_error_code = MapErrorCode(err.code);
            s->last_error_message = err.message;
        } catch (...) {
            SetInternalErrorNoThrow(s, "Failed to read the session error");
        }
    }
}

enum class CApiFormat {
    CmsDetached,
    CmsAttached,
    CadesBes,
    CadesT,
    XadesBes,
    XadesT,
    Pades,
    AsicS,
    AsicE,
    AsicEXades,
    Invalid,
};



// С-04: ЄДИНА таблиця відповідності «формат -> режим мітки часу» для всього
// C ABI. До цього tamga_session_sign_file і tamga_session_sign_data кожен
// вирішували самі, і для cms/cms-detached розходилися: файловий шлях робив
// мережевий TSP-запит (BestEffort), буферний не робив мітки ніколи (Disabled).
//
// Значення узгоджені з NativeAPI (`TamgaAddIn.cpp`, TimestampModeFor):
//   cades-bes -> Disabled  (профіль BES мітки не має за визначенням);
//   cades-t   -> Required  (без мітки підпис не є CAdES-T);
//   решта     -> BestEffort.
tamga::core::TimestampMode TimestampModeForFormat(CApiFormat format) {
    switch (format) {
        case CApiFormat::CadesBes:
            return tamga::core::TimestampMode::Disabled;
        case CApiFormat::CadesT:
            return tamga::core::TimestampMode::Required;
        default:
            return tamga::core::TimestampMode::BestEffort;
    }
}

CApiFormat ParseFormat(const char* raw) noexcept {
    if (!raw || !*raw || std::strcmp(raw, "cms") == 0 || std::strcmp(raw, "cms-detached") == 0) return CApiFormat::CmsDetached;
    if (std::strcmp(raw, "cms-attached") == 0) return CApiFormat::CmsAttached;
    if (std::strcmp(raw, "cades-bes") == 0) return CApiFormat::CadesBes;
    if (std::strcmp(raw, "cades-t") == 0) return CApiFormat::CadesT;
    if (std::strcmp(raw, "xades") == 0 || std::strcmp(raw, "xades-bes") == 0) return CApiFormat::XadesBes;
    if (std::strcmp(raw, "xades-t") == 0) return CApiFormat::XadesT;
    if (std::strcmp(raw, "pades") == 0) return CApiFormat::Pades;
    if (std::strcmp(raw, "asic-s") == 0) return CApiFormat::AsicS;
    if (std::strcmp(raw, "asic-e") == 0) return CApiFormat::AsicE;
    if (std::strcmp(raw, "asic-e-xades") == 0) return CApiFormat::AsicEXades;
    if (std::strcmp(raw, "xmldsig") == 0) return CApiFormat::XadesBes;
    return CApiFormat::Invalid;
}

bool IsXadesFormat(const char* raw) noexcept {
    return raw && (std::strcmp(raw, "xades") == 0 || std::strcmp(raw, "xades-bes") == 0 ||
                   std::strcmp(raw, "xades-t") == 0);
}

bool IsXmlDsigFormat(const char* raw) noexcept {
    return raw && std::strcmp(raw, "xmldsig") == 0;
}

bool IsDetachedCmsFormat(CApiFormat format) {
    return format == CApiFormat::CmsDetached || format == CApiFormat::CadesBes || format == CApiFormat::CadesT;
}

int RejectFormat(tamga_session_t s, const char* message) noexcept {
    SetLastError(s, TAMGA_C_ERR_INVALID_ARGUMENT, message ? message : "Unsupported signature format");
    return TAMGA_C_ERR_INVALID_ARGUMENT;
}

// Q-06: назва операції, під якою рання відмова C ABI потрапляє у звіт.
// Свідомо НЕ збігається з іменами методів `Session` ("VerifyFile", "VerifyXml"
// тощо): у момент відмови конкретний метод ще не обрано — саме вибір формату
// або читання входу і зірвалися. Підставити тут "VerifyFile" означало б
// приписати звіт операції, яка не виконувалася.
constexpr const char kVerifyFileOperation[] = "tamga_session_verify_file";
constexpr const char kVerifyDataOperation[] = "tamga_session_verify_data";

// Q-06: рання відмова перевірки має лишати ТОЙ САМИЙ слід, що й невдала
// перевірка всередині `Session`. До цього такі шляхи оновлювали лише
// обгортковий `last_error`, а `last_verify_report_` у сесії лишався від
// попереднього — успішного — виклику. Послідовність
//   verify_file(..., "cms")   -> TAMGA_C_OK
//   verify_file(..., "xades") -> помилка читання файлу
// віддавала з `tamga_session_get_last_report` звіт про CMS-перевірку, тобто
// звіт про операцію, якої останній виклик не робив. Для доказового артефакта
// це гірше за відсутність звіту: він виглядає достовірним.
//
// `RecordVerifyFailure` бере мутекс сесії й виділяє памʼять, тож викликається
// під try/catch: збій запису звіту не має підмінити код помилки, який
// зобовʼязана повернути функція C ABI.
int RejectVerify(tamga_session_t s, const char* operation, const char* message) noexcept {
    const char* text = message ? message : "Unsupported verification format";
    if (s) {
        try {
            s->session.RecordVerifyFailure(operation ? operation : "verify",
                                           tamga::core::ErrorCode::InvalidArgument, text);
        } catch (...) {
            // Свідомо ковтаємо: нижче все одно виставляється код і текст помилки.
        }
    }
    SetLastError(s, TAMGA_C_ERR_INVALID_ARGUMENT, text);
    return TAMGA_C_ERR_INVALID_ARGUMENT;
}

} // namespace

extern "C" {

const char* tamga_version(void) {
    return TAMGA_VERSION_STRING;
}

tamga_session_t tamga_session_create(void) {
    try {
        auto* s = new (std::nothrow) tamga_session_opaque();
        if (s) {
            s->session.Initialize();
        }
        return s;
    } catch (...) {
        return nullptr;
    }
}

void tamga_session_destroy(tamga_session_t session) {
    delete session;
}

int tamga_session_configure(
    tamga_session_t session,
    const char* work_dir,
    int offline_mode,
    const char* trust_mode
) {
    if (!session) return TAMGA_C_ERR_INVALID_ARGUMENT;
    try {
        tamga::core::Settings settings;
        settings.offline_mode = (offline_mode != 0);
        if (work_dir && *work_dir) {
            settings.work_dir = work_dir;
        }
        if (trust_mode && *trust_mode) {
            settings.trust_mode = trust_mode;
        }
        if (!session->session.SetSettings(settings) || !session->session.Initialize()) {
            SyncSessionError(session);
            return session->last_error_code;
        }
        SetLastError(session, TAMGA_C_OK, "");
        return TAMGA_C_OK;
    } catch (const std::exception& e) {
        SetInternalErrorNoThrow(session, e.what());
        return TAMGA_C_ERR_INTERNAL;
    } catch (...) {
        SetInternalErrorNoThrow(session, nullptr);
        return TAMGA_C_ERR_INTERNAL;
    }
}

int tamga_session_read_key_file(
    tamga_session_t session,
    const char* path,
    const char* password,
    const char* key_password,
    const char* alias
) {
    if (!session || !path || !password) return TAMGA_C_ERR_INVALID_ARGUMENT;
    try {
        // П-06: власні копії пароля, пароля ключа й alias затираються при
        // виході зі scope тим самим механізмом, що вже застосовують ядро
        // (`SessionKeyLoading.ipp`) і CLI (`main.cpp`). Без цього C ABI
        // лишав секрети у купі, хоча обидва його сусіди їх прибирають.
        //
        // МЕЖА: `password`/`key_password`/`alias` — це буфери ВИКЛИКАЧА
        // (`const char*` з публічного ABI). Контракту на їх затирання немає:
        // вони можуть бути літералами в read-only секції або належати чужому
        // алокатору. Затираємо лише те, чим володіємо самі; прибирання
        // власного буфера лишається обов'язком викликача.
        const std::string p(path);
        std::string pass(password);
        std::string kpass(key_password ? key_password : "");
        std::string al(alias ? alias : "");
        const tamga::util::ScopedSecret pass_guard(pass);
        const tamga::util::ScopedSecret kpass_guard(kpass);
        const tamga::util::ScopedSecret al_guard(al);
        if (!session->session.ReadPrivateKeyFile(p, pass, kpass, al)) {
            SyncSessionError(session);
            return session->last_error_code;
        }
        SetLastError(session, TAMGA_C_OK, "");
        return TAMGA_C_OK;
    } catch (const std::exception& e) {
        SetInternalErrorNoThrow(session, e.what());
        return TAMGA_C_ERR_INTERNAL;
    } catch (...) {
        SetInternalErrorNoThrow(session, nullptr);
        return TAMGA_C_ERR_INTERNAL;
    }
}

int tamga_session_read_key_descriptor(
    tamga_session_t session,
    const char* descriptor_json,
    const char* password
) {
    if (!session || !descriptor_json || !password) return TAMGA_C_ERR_INVALID_ARGUMENT;
    try {
        // Дескриптор може містити пароль усередині JSON, тож наша копія — теж
        // секрет. Буфери викликача (`descriptor_json`, `password`) не чіпаємо
        // з тієї самої причини, що й у `tamga_session_read_key_file`.
        std::string descriptor(descriptor_json);
        std::string pass(password);
        const tamga::util::ScopedSecret descriptor_guard(descriptor);
        const tamga::util::ScopedSecret pass_guard(pass);
        if (!session->session.ReadPrivateKey(descriptor, pass)) {
            SyncSessionError(session);
            return session->last_error_code;
        }
        SetLastError(session, TAMGA_C_OK, "");
        return TAMGA_C_OK;
    } catch (const std::exception& e) {
        SetInternalErrorNoThrow(session, e.what());
        return TAMGA_C_ERR_INTERNAL;
    } catch (...) {
        SetInternalErrorNoThrow(session, nullptr);
        return TAMGA_C_ERR_INTERNAL;
    }
}

int tamga_session_is_key_loaded(tamga_session_t session) {
    if (!session) return 0;
    try {
        return session->session.IsPrivateKeyLoaded() ? 1 : 0;
    } catch (...) {
        SetInternalErrorNoThrow(session, nullptr);
        return 0;
    }
}

int tamga_session_sign_file(
    tamga_session_t session,
    const char* input_path,
    const char* output_path,
    const char* format
) {
    if (!session || !input_path || !output_path) return TAMGA_C_ERR_INVALID_ARGUMENT;
    const CApiFormat parsed_format = ParseFormat(format);
    if (parsed_format == CApiFormat::Invalid || parsed_format == CApiFormat::AsicEXades ||
        (IsXmlDsigFormat(format)) || (parsed_format == CApiFormat::XadesBes &&
        !IsXadesFormat(format))) {
        return RejectFormat(session, "Unsupported signature format for signing");
    }
    try {
        if (!session->session.IsPrivateKeyLoaded()) {
            SetLastError(session, TAMGA_C_ERR_KEY_NOT_LOADED, "Private key is not loaded");
            return TAMGA_C_ERR_KEY_NOT_LOADED;
        }
    } catch (...) {
        SetInternalErrorNoThrow(session, nullptr);
        return TAMGA_C_ERR_INTERNAL;
    }

    bool success = false;
    try {
        if (parsed_format == CApiFormat::CmsDetached) {
            // С-04: режим передається ЯВНО. Раніше тут викликалося
            // перевантаження за замовчуванням, яке дає BestEffort, тоді як
            // tamga_session_sign_data для того самого формату використовувало
            // Disabled. FFI-споживач отримував підписи різної юридичної сили
            // залежно від того, працює він з файлом чи з буфером — за
            // ідентичних аргументів і без жодної згадки про це в заголовку.
            success = session->session.RawSignFile(input_path, output_path,
                                                   TimestampModeForFormat(parsed_format));
        } else if (parsed_format == CApiFormat::CadesBes) {
            success = session->session.RawSignFile(input_path, output_path, tamga::core::TimestampMode::Disabled);
        } else if (parsed_format == CApiFormat::CadesT) {
            success = session->session.RawSignFile(input_path, output_path, tamga::core::TimestampMode::Required);
        } else if (parsed_format == CApiFormat::CmsAttached) {
            std::vector<std::uint8_t> in_bytes;
            if (!ReadBinaryFileArg(input_path, in_bytes)) {
                SetLastError(session, TAMGA_C_ERR_INVALID_ARGUMENT, "Cannot read input file");
                return TAMGA_C_ERR_INVALID_ARGUMENT;
            }
            std::vector<std::uint8_t> out_bytes;
            success = session->session.SignDataInternal(in_bytes, out_bytes);
            if (success) {
                success = WriteBinaryFile(output_path, out_bytes);
            }
        } else if (parsed_format == CApiFormat::XadesBes) {
            std::string xml_in;
            if (!ReadTextFile(input_path, xml_in)) {
                SetLastError(session, TAMGA_C_ERR_INVALID_ARGUMENT, "Cannot read XML input");
                return TAMGA_C_ERR_INVALID_ARGUMENT;
            }
            std::string xml_out;
            success = session->session.SignXml(xml_in, "xades-bes", xml_out);
            if (success) {
                success = WriteTextFile(output_path, xml_out);
            }
        } else if (parsed_format == CApiFormat::XadesT) {
            std::string xml_in;
            if (!ReadTextFile(input_path, xml_in)) {
                SetLastError(session, TAMGA_C_ERR_INVALID_ARGUMENT, "Cannot read XML input");
                return TAMGA_C_ERR_INVALID_ARGUMENT;
            }
            std::string xml_out;
            success = session->session.SignXml(xml_in, "xades-t", xml_out);
            if (success) {
                success = WriteTextFile(output_path, xml_out);
            }
        } else if (parsed_format == CApiFormat::Pades) {
            std::vector<std::uint8_t> pdf_in;
            if (!ReadBinaryFileArg(input_path, pdf_in)) {
                SetLastError(session, TAMGA_C_ERR_INVALID_ARGUMENT, "Cannot read PDF input");
                return TAMGA_C_ERR_INVALID_ARGUMENT;
            }
            std::vector<std::uint8_t> pdf_out;
            success = session->session.SignPdf(pdf_in, pdf_out);
            if (success) {
                success = WriteBinaryFile(output_path, pdf_out);
            }
        } else if (parsed_format == CApiFormat::AsicS) {
            success = session->session.SignFileAsicS(input_path, output_path);
        } else if (parsed_format == CApiFormat::AsicE) {
            success = session->session.SignFileAsicE(input_path, output_path);
        } else {
            return RejectFormat(session, "Unsupported signature format for signing");
        }

        if (!success) {
            SyncSessionError(session);
            return session->last_error_code != TAMGA_C_OK ? session->last_error_code : TAMGA_C_ERR_INTERNAL;
        }
        SetLastError(session, TAMGA_C_OK, "");
        return TAMGA_C_OK;
    } catch (const std::exception& e) {
        SetInternalErrorNoThrow(session, e.what());
        return TAMGA_C_ERR_INTERNAL;
    } catch (...) {
        SetInternalErrorNoThrow(session, nullptr);
        return TAMGA_C_ERR_INTERNAL;
    }
}

int tamga_session_sign_data(
    tamga_session_t session,
    const uint8_t* data,
    size_t data_len,
    const char* format,
    uint8_t** out_data,
    size_t* out_len
) {
    if (!session || !data || data_len == 0 || !out_data || !out_len) {
        return TAMGA_C_ERR_INVALID_ARGUMENT;
    }
    *out_data = nullptr;
    *out_len = 0;

    const CApiFormat parsed_format = ParseFormat(format);
    if (parsed_format == CApiFormat::Invalid || parsed_format == CApiFormat::AsicS ||
        parsed_format == CApiFormat::AsicE || parsed_format == CApiFormat::AsicEXades ||
        IsXmlDsigFormat(format) || (parsed_format == CApiFormat::XadesBes && !IsXadesFormat(format))) {
        return RejectFormat(session, "Unsupported signature format for data signing");
    }
    try {
        if (!session->session.IsPrivateKeyLoaded()) {
            SetLastError(session, TAMGA_C_ERR_KEY_NOT_LOADED, "Private key is not loaded");
            return TAMGA_C_ERR_KEY_NOT_LOADED;
        }
    } catch (...) {
        SetInternalErrorNoThrow(session, nullptr);
        return TAMGA_C_ERR_INTERNAL;
    }

    try {
        const std::vector<std::uint8_t> input(data, data + data_len);
        std::vector<std::uint8_t> signed_data;
        bool ok = false;

        if (parsed_format == CApiFormat::XadesBes) {
            const std::string xml(reinterpret_cast<const char*>(data), data_len);
            std::string out_xml;
            ok = session->session.SignXml(xml, "xades-bes", out_xml);
            if (ok) {
                signed_data.assign(out_xml.begin(), out_xml.end());
            }
        } else if (parsed_format == CApiFormat::XadesT) {
            const std::string xml(reinterpret_cast<const char*>(data), data_len);
            std::string out_xml;
            ok = session->session.SignXml(xml, "xades-t", out_xml);
            if (ok) {
                signed_data.assign(out_xml.begin(), out_xml.end());
            }
        } else if (parsed_format == CApiFormat::Pades) {
            ok = session->session.SignPdf(input, signed_data);
        } else if (parsed_format == CApiFormat::CmsAttached) {
            ok = session->session.SignDataInternal(input, signed_data);
        } else {
            // С-04: та сама таблиця «формат -> режим мітки часу», що й у
            // tamga_session_sign_file. Раніше гілка `else` беззастережно
            // ставила Disabled, через що cms/cms-detached поводився інакше,
            // ніж у файловому API.
            ok = session->session.SignData(input, signed_data,
                                           TimestampModeForFormat(parsed_format));
        }

        if (!ok || signed_data.empty()) {
            SyncSessionError(session);
            return session->last_error_code != TAMGA_C_OK ? session->last_error_code : TAMGA_C_ERR_INTERNAL;
        }

        auto* buf = static_cast<uint8_t*>(std::malloc(signed_data.size()));
        if (!buf) {
            SetLastError(session, TAMGA_C_ERR_INTERNAL, "Memory allocation failed");
            return TAMGA_C_ERR_INTERNAL;
        }
        std::memcpy(buf, signed_data.data(), signed_data.size());
        *out_data = buf;
        *out_len = signed_data.size();
        SetLastError(session, TAMGA_C_OK, "");
        return TAMGA_C_OK;
    } catch (const std::exception& e) {
        SetInternalErrorNoThrow(session, e.what());
        return TAMGA_C_ERR_INTERNAL;
    } catch (...) {
        SetInternalErrorNoThrow(session, nullptr);
        return TAMGA_C_ERR_INTERNAL;
    }
}

int tamga_session_verify_file(
    tamga_session_t session,
    const char* input_path,
    const char* signature_path,
    const char* format,
    int* out_valid
) {
    // Q-06: обнулення вихідного прапорця йде ПЕРШИМ. Раніше воно стояло після
    // перевірки аргументів, тож виклик із `input_path == nullptr` при
    // справному `out_valid` лишав у ньому попереднє значення — і те могло бути 1.
    if (out_valid) *out_valid = 0;
    if (!session || !input_path || !out_valid) {
        return RejectVerify(session, kVerifyFileOperation,
                            "tamga_session_verify_file requires a session, an input path and an output flag");
    }

    const CApiFormat parsed_format = ParseFormat(format);
    if (parsed_format == CApiFormat::Invalid) {
        return RejectVerify(session, kVerifyFileOperation, "Unsupported verification format");
    }
    if (!IsDetachedCmsFormat(parsed_format) && signature_path && *signature_path) {
        return RejectVerify(session, kVerifyFileOperation,
                            "This verification format does not accept a detached signature path");
    }
    bool valid = false;
    bool execution_ok = false;

    try {
        if (parsed_format == CApiFormat::CmsDetached || parsed_format == CApiFormat::CadesBes ||
            parsed_format == CApiFormat::CadesT) {
            if (!signature_path || !*signature_path) {
                return RejectVerify(session, kVerifyFileOperation, "CMS detached requires signature path");
            }
            execution_ok = session->session.RawVerifyFile(input_path, signature_path, valid);
        } else if (parsed_format == CApiFormat::CmsAttached) {
            std::vector<std::uint8_t> data;
            if (!ReadBinaryFileArg(input_path, data)) {
                return RejectVerify(session, kVerifyFileOperation, "Cannot read attached CMS file");
            }
            std::vector<std::uint8_t> content;
            execution_ok = session->session.VerifyDataInternal(data, valid, content);
        } else if ((parsed_format == CApiFormat::XadesBes || parsed_format == CApiFormat::XadesT) &&
                   (IsXadesFormat(format) || IsXmlDsigFormat(format))) {
            std::string xml;
            if (!ReadTextFile(input_path, xml)) {
                return RejectVerify(session, kVerifyFileOperation, "Cannot read XML file");
            }
            execution_ok = session->session.VerifyXml(xml, valid);
        } else if (parsed_format == CApiFormat::Pades) {
            std::vector<std::uint8_t> pdf;
            if (!ReadBinaryFileArg(input_path, pdf)) {
                return RejectVerify(session, kVerifyFileOperation, "Cannot read PDF file");
            }
            execution_ok = session->session.VerifyPdf(pdf, valid);
        } else if (parsed_format == CApiFormat::AsicS) {
            execution_ok = session->session.VerifyFileAsicS(input_path, valid);
        } else if (parsed_format == CApiFormat::AsicE) {
            execution_ok = session->session.VerifyFileAsicE(input_path, valid);
        } else if (parsed_format == CApiFormat::AsicEXades) {
            execution_ok = session->session.VerifyFileAsicEXades(input_path, valid);
        } else {
            return RejectVerify(session, kVerifyFileOperation, "Unsupported verification format");
        }

        *out_valid = valid ? 1 : 0;
        if (!execution_ok) {
            SyncSessionError(session);
            return session->last_error_code != TAMGA_C_OK ? session->last_error_code : TAMGA_C_ERR_INTERNAL;
        }
        SetLastError(session, TAMGA_C_OK, "");
        return TAMGA_C_OK;
    } catch (const std::exception& e) {
        SetInternalErrorNoThrow(session, e.what());
        return TAMGA_C_ERR_INTERNAL;
    } catch (...) {
        SetInternalErrorNoThrow(session, nullptr);
        return TAMGA_C_ERR_INTERNAL;
    }
}

int tamga_session_verify_data(
    tamga_session_t session,
    const uint8_t* data,
    size_t data_len,
    const uint8_t* signature,
    size_t signature_len,
    const char* format,
    int* out_valid
) {
    // Q-06: те саме, що й у tamga_session_verify_file. Виклик із `data == nullptr`
    // і справним `out_valid`, який раніше містив 1, лишав у ньому 1 — тобто
    // «valid» після відмови. Обнуляємо до будь-якої іншої перевірки.
    if (out_valid) *out_valid = 0;
    if (!session || !data || data_len == 0 || !out_valid) {
        return RejectVerify(session, kVerifyDataOperation,
                            "tamga_session_verify_data requires a session, non-empty data and an output flag");
    }

    const CApiFormat parsed_format = ParseFormat(format);
    if (parsed_format == CApiFormat::Invalid || parsed_format == CApiFormat::AsicS ||
        parsed_format == CApiFormat::AsicE || parsed_format == CApiFormat::AsicEXades ||
        parsed_format == CApiFormat::XadesT) {
        return RejectVerify(session, kVerifyDataOperation, "Unsupported verification format for data");
    }
    bool valid = false;
    bool execution_ok = false;

    try {
        if (parsed_format == CApiFormat::XadesBes &&
            (IsXadesFormat(format) || IsXmlDsigFormat(format))) {
            if (signature != nullptr || signature_len != 0) {
                return RejectVerify(session, kVerifyDataOperation, "XAdES verification does not accept a detached signature");
            }
            const std::string xml(reinterpret_cast<const char*>(data), data_len);
            execution_ok = session->session.VerifyXml(xml, valid);
        } else if (parsed_format == CApiFormat::Pades) {
            if (signature != nullptr || signature_len != 0) {
                return RejectVerify(session, kVerifyDataOperation, "PAdES verification does not accept a detached signature");
            }
            const std::vector<std::uint8_t> pdf(data, data + data_len);
            execution_ok = session->session.VerifyPdf(pdf, valid);
        } else if (parsed_format == CApiFormat::CmsAttached) {
            if (signature != nullptr || signature_len != 0) {
                return RejectVerify(session, kVerifyDataOperation, "Attached CMS verification requires no detached signature");
            }
            const std::vector<std::uint8_t> payload(data, data + data_len);
            std::vector<std::uint8_t> content;
            execution_ok = session->session.VerifyDataInternal(payload, valid, content);
        } else if (IsDetachedCmsFormat(parsed_format)) {
            if (!signature || signature_len == 0) {
                return RejectVerify(session, kVerifyDataOperation, "CMS detached verification requires a non-empty signature");
            }
            const std::vector<std::uint8_t> payload(data, data + data_len);
            const std::vector<std::uint8_t> sig(signature, signature + signature_len);
            execution_ok = session->session.VerifyData(payload, sig, valid);
        } else {
            return RejectVerify(session, kVerifyDataOperation, "Unsupported verification format for data");
        }

        /* Keep the output deterministic even when a backend reports invalid. */
        if (execution_ok) {
            *out_valid = valid ? 1 : 0;
        } else {
            *out_valid = 0;
        }
        if (!execution_ok) {
            SyncSessionError(session);
            return session->last_error_code != TAMGA_C_OK ? session->last_error_code : TAMGA_C_ERR_INTERNAL;
        }
        SetLastError(session, TAMGA_C_OK, "");
        return TAMGA_C_OK;
    } catch (const std::exception& e) {
        SetInternalErrorNoThrow(session, e.what());
        return TAMGA_C_ERR_INTERNAL;
    } catch (...) {
        SetInternalErrorNoThrow(session, nullptr);
        return TAMGA_C_ERR_INTERNAL;
    }
}

int tamga_session_sync_trust_list(tamga_session_t session) {
    if (!session) return TAMGA_C_ERR_INVALID_ARGUMENT;
    try {
        if (!session->session.SyncTrustList()) {
            SyncSessionError(session);
            return session->last_error_code != TAMGA_C_OK ? session->last_error_code : TAMGA_C_ERR_ONLINE_UNAVAILABLE;
        }
        SetLastError(session, TAMGA_C_OK, "");
        return TAMGA_C_OK;
    } catch (const std::exception& e) {
        SetInternalErrorNoThrow(session, e.what());
        return TAMGA_C_ERR_INTERNAL;
    } catch (...) {
        SetInternalErrorNoThrow(session, nullptr);
        return TAMGA_C_ERR_INTERNAL;
    }
}

const char* tamga_session_get_last_error(tamga_session_t session) {
    if (!session) return "Invalid session handle";
    try {
        return session->last_error_message.c_str();
    } catch (...) {
        return "Internal error";
    }
}

int tamga_session_get_last_error_code(tamga_session_t session) {
    if (!session) return TAMGA_C_ERR_INVALID_ARGUMENT;
    return session->last_error_code;
}

const char* tamga_session_get_last_report(tamga_session_t session) {
    if (!session) return nullptr;
    try {
        if (session->session.GetLastVerifyReport(session->last_report_cache)) {
            return session->last_report_cache.c_str();
        }
    } catch (...) {
        SetInternalErrorNoThrow(session, nullptr);
    }
    return nullptr;
}

const char* tamga_session_get_user_report(tamga_session_t session) {
    if (!session) return nullptr;
    try {
        if (session->session.GetUserReport(session->user_report_cache)) {
            return session->user_report_cache.c_str();
        }
    } catch (...) {
        SetInternalErrorNoThrow(session, nullptr);
    }
    return nullptr;
}

void tamga_free_bytes(uint8_t* ptr) {
    std::free(ptr);
}

void tamga_free_string(char* str) {
    std::free(str);
}

} // extern "C"
