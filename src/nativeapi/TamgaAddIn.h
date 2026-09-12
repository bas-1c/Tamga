#pragma once

#include <array>
#include <string>

#include "AddInDefBase.h"
#include "ComponentBase.h"
#include "IMemoryManager.h"
#include "core/Session.h"

namespace tamga::nativeapi {

class TamgaAddIn final : public IComponentBase {
public:
    enum Props {
        ePropIsInitialized = 0,
        ePropOfflineMode,
        ePropIsPrivateKeyReaded,
        ePropNeedSetSettings,
        ePropLast
    };

    enum Methods {
        eMethInitialize = 0,
        eMethFinalize,
        eMethShowCertificates,
        eMethShowCRLs,
        eMethGetPrivateKeyMedia,
        eMethGetCertificateInfo,
        eMethBase64Encode,
        eMethBase64Decode,
        eMethSignData,
        eMethVerifyData,
        eMethSignFile,
        eMethVerifyFile,
        eMethSignXml,
        eMethVerifyXml,
        eMethSignPdf,
        eMethVerifyPdf,
        eMethConfigure,
        eMethConfigureTsp,
        eMethConfigureOcsp,
        eMethConfigureLdap,
        eMethConfigureCmp,
        eMethLoadKey,
        eMethResetKey,
        eMethGetReport,
        eMethGetError,
        eMethConfigureTrustList,
        eMethSyncTrustList,
        eMethGetUserReport,
        eMethLast
    };

    bool ADDIN_API Init(void* connection) override;
    bool ADDIN_API setMemManager(void* mem) override;
    long ADDIN_API GetInfo() override;
    void ADDIN_API Done() override;

    bool ADDIN_API RegisterExtensionAs(WCHAR_T** wsExtensionName) override;
    long ADDIN_API GetNProps() override;
    long ADDIN_API FindProp(const WCHAR_T* wsPropName) override;
    const WCHAR_T* ADDIN_API GetPropName(long lPropNum, long lPropAlias) override;
    bool ADDIN_API GetPropVal(long lPropNum, tVariant* pvarPropVal) override;
    bool ADDIN_API SetPropVal(long lPropNum, tVariant* varPropVal) override;
    bool ADDIN_API IsPropReadable(long lPropNum) override;
    bool ADDIN_API IsPropWritable(long lPropNum) override;

    long ADDIN_API GetNMethods() override;
    long ADDIN_API FindMethod(const WCHAR_T* wsMethodName) override;
    const WCHAR_T* ADDIN_API GetMethodName(long lMethodNum, long lMethodAlias) override;
    long ADDIN_API GetNParams(long lMethodNum) override;
    bool ADDIN_API GetParamDefValue(long lMethodNum, long lParamNum, tVariant* pvarParamDefValue) override;
    bool ADDIN_API HasRetVal(long lMethodNum) override;
    bool ADDIN_API CallAsProc(long lMethodNum, tVariant* paParams, long lSizeArray) override;
    bool ADDIN_API CallAsFunc(long lMethodNum, tVariant* pvarRetValue, tVariant* paParams, long lSizeArray) override;

    void ADDIN_API SetLocale(const WCHAR_T* loc) override;
    void ADDIN_API SetUserInterfaceLanguageCode(const WCHAR_T* lang) override;

private:
    long FindName(const std::array<const wchar_t*, ePropLast>& names, const std::wstring& value) const;
    long FindName(const std::array<const wchar_t*, eMethLast>& names, const std::wstring& value) const;

    IAddInDefBase* connection_{nullptr};
    IMemoryManager* memory_{nullptr};
    tamga::core::Session session_{};
};

} // namespace tamga::nativeapi
