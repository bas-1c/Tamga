#include <exception>
#include <new>
#include <string>
#include <utility>

#include "nativeapi/TamgaAddIn.h"
#include "util/Utf.h"

// On Windows the export set is defined by src/nativeapi/Tamga.def, so the macro
// expands to nothing there. On Linux/macOS the NativeAPI objects are compiled
// with -fvisibility=hidden, which turns these symbols local before the linker
// version script (src/nativeapi/version.script) runs. A version script can only
// keep symbols that are already global, so without an explicit default
// visibility the resulting .so would export zero symbols. Marking the five
// 1C entry points as default-visible makes them survive into the dynamic
// symbol table; the version script then prunes everything else.
#if defined(_WIN32)
#define TAMGA_NATIVEAPI_EXPORT
#else
#define TAMGA_NATIVEAPI_EXPORT __attribute__((visibility("default")))
#endif

namespace {
std::u16string g_class_name(u"Tamga");

void AppendAscii(std::u16string& out, const char* text) {
    if (text == nullptr) {
        return;
    }
    while (*text != '\0') {
        const unsigned char ch = static_cast<unsigned char>(*text++);
        out.push_back(ch < 0x80U ? static_cast<char16_t>(ch) : u'?');
    }
}

// WP-17: `what()`/помилки, що потрапляють у виняткові повідомлення 1С, часто
// містять українськомовний текст (кирилиця, UTF-8) — джерела помилок з решти
// кодової бази. Стара `AppendAscii` підміняла кожен не-ASCII байт на '?', тому
// такий текст ставав нечитабельним. Декодуємо як UTF-8 і додаємо як є; якщо
// вхід не є коректним UTF-8 (наприклад, третьосторонній виняток із
// locale-залежним narrow-char текстом), безпечно деградуємо до ASCII-проекції
// замість кидання винятку в noexcept-шляху звітування про помилки.
void AppendUtf8(std::u16string& out, const char* text) {
    if (text == nullptr) {
        return;
    }
    std::u16string decoded;
    if (tamga::util::TryDecodeUtf8ToUtf16(text, decoded)) {
        out += decoded;
        return;
    }
    AppendAscii(out, text);
}

void SetFalseResult(tVariant* result) noexcept {
    if (result == nullptr) {
        return;
    }
    tVarInit(result);
    TV_VT(result) = VTYPE_BOOL;
    TV_BOOL(result) = false;
}

class NativeApiExceptionGuard final : public IComponentBase {
public:
    bool ADDIN_API Init(void* connection) override {
        connection_ = static_cast<IAddInDefBase*>(connection);
        return Guard("Init", false, [&] { return impl_.Init(connection); });
    }

    bool ADDIN_API setMemManager(void* mem) override {
        return Guard("setMemManager", false, [&] { return impl_.setMemManager(mem); });
    }

    long ADDIN_API GetInfo() override {
        return Guard("GetInfo", 0L, [&] { return impl_.GetInfo(); });
    }

    void ADDIN_API Done() override {
        GuardVoid("Done", [&] { impl_.Done(); });
    }

    bool ADDIN_API RegisterExtensionAs(WCHAR_T** wsExtensionName) override {
        return Guard("RegisterExtensionAs", false, [&] { return impl_.RegisterExtensionAs(wsExtensionName); });
    }

    long ADDIN_API GetNProps() override {
        return Guard("GetNProps", 0L, [&] { return impl_.GetNProps(); });
    }

    long ADDIN_API FindProp(const WCHAR_T* wsPropName) override {
        return Guard("FindProp", -1L, [&] { return impl_.FindProp(wsPropName); });
    }

    const WCHAR_T* ADDIN_API GetPropName(long lPropNum, long lPropAlias) override {
        return Guard("GetPropName", static_cast<const WCHAR_T*>(nullptr),
                     [&] { return impl_.GetPropName(lPropNum, lPropAlias); });
    }

    bool ADDIN_API GetPropVal(const long lPropNum, tVariant* pvarPropVal) override {
        return Guard("GetPropVal", false, [&] { return impl_.GetPropVal(lPropNum, pvarPropVal); });
    }

    bool ADDIN_API SetPropVal(const long lPropNum, tVariant* varPropVal) override {
        return Guard("SetPropVal", false, [&] { return impl_.SetPropVal(lPropNum, varPropVal); });
    }

    bool ADDIN_API IsPropReadable(const long lPropNum) override {
        return Guard("IsPropReadable", false, [&] { return impl_.IsPropReadable(lPropNum); });
    }

    bool ADDIN_API IsPropWritable(const long lPropNum) override {
        return Guard("IsPropWritable", false, [&] { return impl_.IsPropWritable(lPropNum); });
    }

    long ADDIN_API GetNMethods() override {
        return Guard("GetNMethods", 0L, [&] { return impl_.GetNMethods(); });
    }

    long ADDIN_API FindMethod(const WCHAR_T* wsMethodName) override {
        return Guard("FindMethod", -1L, [&] { return impl_.FindMethod(wsMethodName); });
    }

    const WCHAR_T* ADDIN_API GetMethodName(const long lMethodNum, const long lMethodAlias) override {
        return Guard("GetMethodName", static_cast<const WCHAR_T*>(nullptr),
                     [&] { return impl_.GetMethodName(lMethodNum, lMethodAlias); });
    }

    long ADDIN_API GetNParams(const long lMethodNum) override {
        return Guard("GetNParams", 0L, [&] { return impl_.GetNParams(lMethodNum); });
    }

    bool ADDIN_API GetParamDefValue(const long lMethodNum,
                                    const long lParamNum,
                                    tVariant* pvarParamDefValue) override {
        return Guard("GetParamDefValue", false,
                     [&] { return impl_.GetParamDefValue(lMethodNum, lParamNum, pvarParamDefValue); });
    }

    bool ADDIN_API HasRetVal(const long lMethodNum) override {
        return Guard("HasRetVal", false, [&] { return impl_.HasRetVal(lMethodNum); });
    }

    bool ADDIN_API CallAsProc(const long lMethodNum, tVariant* paParams, const long lSizeArray) override {
        return Guard("CallAsProc", false, [&] { return impl_.CallAsProc(lMethodNum, paParams, lSizeArray); });
    }

    bool ADDIN_API CallAsFunc(const long lMethodNum,
                              tVariant* pvarRetValue,
                              tVariant* paParams,
                              const long lSizeArray) override {
        try {
            return impl_.CallAsFunc(lMethodNum, pvarRetValue, paParams, lSizeArray);
        } catch (const std::exception& ex) {
            ReportException("CallAsFunc", ex.what());
        } catch (...) {
            ReportException("CallAsFunc", "unknown C++ exception");
        }
        SetFalseResult(pvarRetValue);
        return true;
    }

    void ADDIN_API SetLocale(const WCHAR_T* loc) override {
        GuardVoid("SetLocale", [&] { impl_.SetLocale(loc); });
    }

    void ADDIN_API SetUserInterfaceLanguageCode(const WCHAR_T* lang) override {
        GuardVoid("SetUserInterfaceLanguageCode", [&] { impl_.SetUserInterfaceLanguageCode(lang); });
    }

private:
    template <typename F, typename R>
    R Guard(const char* entry, R fallback, F&& fn) noexcept {
        try {
            return std::forward<F>(fn)();
        } catch (const std::exception& ex) {
            ReportException(entry, ex.what());
        } catch (...) {
            ReportException(entry, "unknown C++ exception");
        }
        return fallback;
    }

    template <typename F>
    void GuardVoid(const char* entry, F&& fn) noexcept {
        try {
            std::forward<F>(fn)();
        } catch (const std::exception& ex) {
            ReportException(entry, ex.what());
        } catch (...) {
            ReportException(entry, "unknown C++ exception");
        }
    }

    void ReportException(const char* entry, const char* what) noexcept {
        if (connection_ == nullptr) {
            return;
        }
        try {
            std::u16string source = u"Tamga";
            std::u16string description = u"Tamga native exception";
            if (entry != nullptr && *entry != '\0') {
                description += u" in ";
                AppendAscii(description, entry);
            }
            if (what != nullptr && *what != '\0') {
                description += u": ";
                AppendUtf8(description, what);
            }
            connection_->AddError(ADDIN_E_FAIL,
                                  reinterpret_cast<const WCHAR_T*>(source.c_str()),
                                  reinterpret_cast<const WCHAR_T*>(description.c_str()),
                                  0);
        } catch (...) {
        }
    }

    IAddInDefBase* connection_{nullptr};
    tamga::nativeapi::TamgaAddIn impl_{};
};
}  // namespace

extern "C" TAMGA_NATIVEAPI_EXPORT long GetClassObject(const WCHAR_T* class_name, IComponentBase** pInterface) {
    if (class_name == nullptr || pInterface == nullptr || *pInterface != nullptr) {
        return 0;
    }
    if (g_class_name != class_name) {
        return 0;
    }

    *pInterface = new (std::nothrow) NativeApiExceptionGuard();
    return (*pInterface != nullptr) ? 1L : 0L;
}

// Точка входу 1С: платформа повідомляє рівень своїх можливостей, компонента
// відповідає рівнем, за яким хоче працювати. Експорт обов'язковий і лишається
// в `Tamga.def` / `version.script` / `exported_symbols.list`.
//
// Мертвим було не саме API, а СХОВИЩЕ під переданий рівень: `g_capabilities`
// присвоювався тут і більше ніде не читався (`rg -n "g_capabilities" src tests
// include tools` знаходив лише визначення і це присвоєння). Відповідь
// `eAppCapabilitiesLast` — константа, вона ніколи не залежала від аргументу,
// тож зі зникненням змінної поведінка на дроті не змінюється.
//
// Свідомо НЕ реалізуємо фактичне використання рівня: жодна гілка компоненти
// зараз не розрізняє можливості платформи, а завести розрізнення означало б
// змінити публічну поведінку без рішення про контракт. Якщо таке розрізнення
// знадобиться, повертати треба разом зі споживачем, а не «про запас».
extern "C" TAMGA_NATIVEAPI_EXPORT AppCapabilities SetPlatformCapabilities(const AppCapabilities capabilities) {
    (void)capabilities;
    return eAppCapabilitiesLast;
}

extern "C" TAMGA_NATIVEAPI_EXPORT AttachType GetAttachType() { return eCanAttachAny; }

extern "C" TAMGA_NATIVEAPI_EXPORT long DestroyObject(IComponentBase** pIntf) {
    if (pIntf == nullptr || *pIntf == nullptr) {
        return -1;
    }
    delete *pIntf;
    *pIntf = nullptr;
    return 0;
}

extern "C" TAMGA_NATIVEAPI_EXPORT const WCHAR_T* GetClassNames() { return g_class_name.c_str(); }
