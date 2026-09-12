#include "nativeapi/VariantUtils.h"

#include <cstdint>
#include <cstring>
#include <limits>

#include "util/FileSystem.h"
#include "util/Utf.h"

namespace tamga::util {
namespace {

// П-11: єдина межа для ПРЯМИХ (не файлових) вхідних даних з 1С.
//
// Ліміт `kMaxInputFileSize` (64 МіБ) досі застосовувався лише там, де вхід
// приходив ШЛЯХОМ до файлу. Прямі виклики — `SignXml`, `VerifyXml`,
// `SignPdf`, `VerifyPdf`, `SignData`, `VerifyData` — приймають дані
// ЗНАЧЕННЯМ, і тут межі не було жодної: `GetBlob` робив
// `assign(pstrVal, pstrVal + strLen)`, а `GetWString` — повну конверсію за
// `wstrLen`. Обидві довжини повністю керуються тим, хто викликає компоненту.
//
// Чим це НЕ є (і це перевірено, а не припущено): аварійним завершенням
// процесу 1С. `NativeApiExceptionGuard` у `src/nativeapi/Export.cpp` обгортає
// КОЖНУ точку входу `IComponentBase` — включно з `CallAsFunc` — і ловить
// `std::bad_alloc` разом з рештою винятків; метод повертає false, процес
// живий. Твердження «неперехоплений bad_alloc валить платформу» для цього
// дерева неправдиве.
//
// Чим це Є: відсутністю ПЕРЕДБАЧУВАНОЇ межі. Один виклик міг спричинити
// сплеск виділення пам'яті довільного розміру всередині чужого процесу, а
// відмова наставала не за правилом, а за фактом вичерпання пам'яті — тобто
// недетерміновано і в момент, який не залежить від вхідних даних.
//
// Ліміт свідомо той самий, що й файловий: для політики немає різниці, чи
// прийшли ті самі байти шляхом, чи значенням. Другої константи тут не
// заводимо — розбіжність двох «однакових» лімітів рано чи пізно стає
// розбіжністю поведінки.
bool ExceedsDirectInputLimit(const std::uintmax_t size_bytes) {
    return size_bytes > kMaxInputFileSize;
}

}  // namespace

void SetBool(tVariant* var, const bool value) {
    tVarInit(var);
    TV_VT(var) = VTYPE_BOOL;
    TV_BOOL(var) = value;
}

bool GetBool(const tVariant* var, bool& value) {
    if (var == nullptr) {
        return false;
    }
    if (TV_VT(var) != VTYPE_BOOL) {
        return false;
    }
    value = TV_BOOL(var);
    return true;
}


bool GetInt32(const tVariant* var, std::int32_t& value) {
    if (var == nullptr) {
        return false;
    }
    switch (TV_VT(var)) {
        case VTYPE_I4: value = TV_I4(var); return true;
        case VTYPE_I2: value = TV_I2(var); return true;
        case VTYPE_INT: value = TV_INT(var); return true;
        case VTYPE_UI4: {
            const std::uint32_t raw = TV_UI4(var);
            if (raw > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())) {
                return false;
            }
            value = static_cast<std::int32_t>(raw);
            return true;
        }
        case VTYPE_UI2: value = static_cast<std::int32_t>(TV_UI2(var)); return true;
        default: return false;
    }
}
bool SetWString(IMemoryManager* memory, tVariant* var, const std::wstring& value) {
    if (memory == nullptr || var == nullptr) {
        return false;
    }

    tVarInit(var);
    TV_VT(var) = VTYPE_PWSTR;

    const std::u16string utf16 = ToShortWchar(value);
    WCHAR_T* output = nullptr;
    const auto len = static_cast<unsigned>(utf16.size());
    if (!memory->AllocMemory(reinterpret_cast<void**>(&output), static_cast<unsigned>((len + 1) * sizeof(WCHAR_T)))) {
        return false;
    }

    for (unsigned i = 0; i < len; ++i) {
        output[i] = utf16[i];
    }
    output[len] = 0;

    var->pwstrVal = output;
    var->wstrLen = len;
    return true;
}

bool GetWString(const tVariant* var, std::wstring& value) {
    if (var == nullptr || TV_VT(var) != VTYPE_PWSTR || var->pwstrVal == nullptr) {
        return false;
    }

    // Перевірка ДО конверсії. Якби вона стояла після `FromShortWchar`, пам'ять
    // уже була б виділена і межа лишилася б декларативною.
    if (ExceedsDirectInputLimit(static_cast<std::uintmax_t>(var->wstrLen) * sizeof(WCHAR_T))) {
        return false;
    }

    value = FromShortWchar(var->pwstrVal, var->wstrLen);
    return true;
}

bool SetBlob(IMemoryManager* memory, tVariant* var, const std::vector<std::uint8_t>& value) {
    if (memory == nullptr || var == nullptr) {
        return false;
    }

    tVarInit(var);
    TV_VT(var) = VTYPE_BLOB;

    char* output = nullptr;
    const auto size = static_cast<unsigned>(value.size());
    if (!memory->AllocMemory(reinterpret_cast<void**>(&output), size)) {
        return false;
    }

    if (size > 0) {
        std::memcpy(output, value.data(), size);
    }

    var->pstrVal = output;
    var->strLen = size;
    return true;
}

bool GetBlob(const tVariant* var, std::vector<std::uint8_t>& value) {
    if (var == nullptr || TV_VT(var) != VTYPE_BLOB || var->pstrVal == nullptr) {
        return false;
    }
    // Перевірка ДО `assign`: сам `assign` і є тим копіюванням, яке ми
    // обмежуємо.
    if (ExceedsDirectInputLimit(var->strLen)) {
        return false;
    }
    value.assign(var->pstrVal, var->pstrVal + var->strLen);
    return true;
}

} // namespace tamga::util
