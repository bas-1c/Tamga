# Методи бібліотеки Tamga

Цей документ описує C++ API бібліотечного шару Tamga — **як він виглядає
всередині дерева проєкту**. Основна точка входу для внутрішніх споживачів
(`tamga-cli`, реалізація C ABI) — `tamga::core::Session` через
`include/tamga/Tamga.h`.

> **Межа install-пакета (В-06).** `tamga/Tamga.h` і `tamga/Session.h` **не
> встановлюються** і не є частиною публічного контракту. Вони включають
> внутрішні `core/Errors.h`, `core/Session.h` та `util/Base64.h`, яких в
> install-дереві немає, тож зовнішній C++ споживач їх не скомпілював би —
> раніше це давало `C1083` і не ловилося жодним тестом.
>
> Стабільною публічною межею пакета є **C ABI** (`tamga/tamga_c_api.h`,
> ADR-025). Саме він встановлюється, і саме його можна включати з C і з C++.
> Опис — у `include/tamga/tamga_c_api.h`.
>
> Гейт: `tamga-installed-package-consumer` компілює **кожен** заголовок,
> фактично присутній в install-дереві, окремо як C і як C++ — перелік не
> задається вручну, а виводиться з вмісту префікса.

`tamga-lib.dll` є runtime-артефактом для C/C++ застосунків і language bindings.
Описаний нижче C++ API — engineering contract поточної гілки для коду
**всередині** репозиторію, а не обіцянка зовнішньої сумісності.

## Build-прапори форматів

| Прапор CMake | Що вмикає | Основні залежності |
| --- | --- | --- |
| `TAMGA_ENABLE_VENDOR_CRYPTONITE=ON` | ДСТУ/CMS/CAdES, ASiC-S/ASiC-E, trust/revocation policy path | vendored `cryptonite` |
| `TAMGA_ENABLE_XML_SIGNATURES=ON` | XMLDSIG, XAdES, `SignXml()`, `VerifyXml()`, `VerifyFileAsicEXades()` | — (`libxml2` потрібен ЗАВЖДИ, незалежно від прапорця: ADR-030) |
| `TAMGA_ENABLE_PDF_SIGNATURES=ON` | PAdES, `SignPdf()`, `VerifyPdf()` | `qpdf` |

Якщо відповідний прапор вимкнено, форматні методи повертають `false`,
`GetLastError().code == NotSupported` і повідомлення про потрібний build-прапор.
Mock-результати для цих сценаріїв не використовуються.

## Життєвий цикл сесії

| Метод | Призначення |
| --- | --- |
| `Initialize()` | Ініціалізує сесію і застосовує поточні налаштування. |
| `Finalize()` | Завершує сесію, очищає завантажений ключ і стан звітів. |
| `SetSettings(settings)` | Налаштовує offline mode, `workDir`, trust mode і validation level. |
| `SetFileStoreSettings(settings)` | Налаштування файлового сховища. |
| `SetOcspSettings(settings)` | Налаштування OCSP endpoint, nonce і timeout. |
| `SetTspSettings(settings)` | Налаштування TSP/TSA endpoint, policy OID, timeout і digest imprint. |
| `SetLdapSettings(settings)` | Конфігураційна точка LDAP; production-функція належить до наступних фаз. |
| `SetCmpSettings(settings)` | Конфігураційна точка CMP; production-функція належить до наступних фаз. |
| `SetTrustListSettings(settings)` | Налаштовує URL, timeout і TTL довірчого списку. |
| `SyncTrustList()` | Завантажує/оновлює TL XML, state cache, `trust-store` і metadata сервісів. |

## Ключі та сертифікати

| Метод | Призначення |
| --- | --- |
| `DescribeSupportedMedia(outJson)` | Повертає JSON capability report для ключових контейнерів і policy capability. |
| `ReadPrivateKey(mediaDescriptorJson, password)` | Історичний descriptor-based спосіб завантаження ключа. |
| `ReadPrivateKeyBinary(keyData, storePassword, keyPassword, jksAlias)` | Завантажує ключ із байтів JKS/PKCS#12/PEM/DER. |
| `ReadPrivateKeyFile(path, storePassword, keyPassword, jksAlias)` | Завантажує ключ із файла. |
| `ResetPrivateKey()` | Очищає завантажений приватний ключ і сертифікат. |
| `GetCertificateInfo(certData, outJson)` | Повертає JSON з даними сертифіката. |
| `CheckCertificateRevocation(certData, crlData, issuerCertData, outJson)` | Перевіряє CRL-відкликання для переданого сертифіката. |

## CMS/CAdES і ASiC

| Метод | Призначення |
| --- | --- |
| `SignData(data, signature)` | Створює detached CMS/CAdES підпис для байтів. |
| `SignData(data, signature, timestampMode)` | Detached CMS/CAdES із керованим timestamp mode. |
| `VerifyData(data, signature, isValid)` | Перевіряє detached CMS/CAdES підпис. |
| `SignDataInternal(data, signedData)` | Створює attached CMS із вбудованими даними. |
| `VerifyDataInternal(signedData, isValid, content)` | Перевіряє attached CMS і повертає вбудований content. |
| `SignFile(path, signature)` | Читає файл і повертає detached CMS/CAdES підпис у пам'яті. |
| `VerifyFile(path, signature, isValid)` | Перевіряє detached підпис до файла. |
| `RawSignFile(inputPath, signaturePath)` | Створює файл detached-підпису. |
| `RawVerifyFile(inputPath, signaturePath, isValid)` | Перевіряє detached-підпис із файла. |
| `SignFileAsicS(inputPath, outputPath)` | Створює ASiC-S контейнер. |
| `VerifyFileAsicS(asicsPath, isValid)` | Перевіряє ASiC-S контейнер із CMS/CAdES підписом. |
| `SignFileAsicE(inputPath, outputPath)` | Створює базовий ASiC-E контейнер. |
| `VerifyFileAsicE(asicePath, isValid)` | Перевіряє ASiC-E контейнер із CMS/CAdES підписом. |
| `VerifyFileAsicEXades(asicePath, isValid)` | Перевіряє ASiC-E контейнер із detached XAdES/XMLDSIG підписом у `META-INF/signatures*.xml`. |

`VerifyFileAsicEXades()` читає ZIP-контейнер, знаходить документальні entries
поза `META-INF`, знаходить XAdES signature entry, перевіряє `ds:Reference URI`
до entry контейнера, блокує `file://`, `http://`, абсолютні шляхи і traversal
`../`, підставляє байти entry у XMLDSIG resolver і запускає наявний trust /
revocation policy path для сертифіката з `KeyInfo/X509Certificate`.

## XMLDSIG/XAdES

| Метод | Потрібний прапор | Призначення |
| --- | --- | --- |
| `SignXml(xml, signedXmlOut)` | `TAMGA_ENABLE_XML_SIGNATURES=ON` | Створює enveloped XMLDSIG/XAdES підпис над XML-рядком з використанням завантаженого ключа. |
| `VerifyXml(signedXml, isValid)` | `TAMGA_ENABLE_XML_SIGNATURES=ON` | Перевіряє XMLDSIG/XAdES документ, оновлює `GetLastVerifyReport()` і `GetUserReport()`. |

`VerifyXml()` заповнює форматні поля звіту: `operation="VerifyXml"`,
`signatureFormat="XAdES"`, `formatProfile` відповідно до знайденого профілю
(`XAdES-BES`, `XAdES-T`, `XAdES-X-L`, `XAdES-A` тощо), timestamp/LTV-сигнали
і policy fields для сертифіката підписувача.

`formatProfile`/`signature.profile` — структурний хінт (наявність
`CertificateValues`/`RevocationValues`/`SignatureTimeStamp`). WP-5 додає
`signature.validatedProfile` — те саме значення, але виставлене ЛИШЕ коли
вбудовані XAdES `CertificateValues`/`RevocationValues` фактично прив'язані
(evidence binding), передані у `ValidationEngine`/`RevocationEngine` як
intermediates/revocation evidence, і trust-ланцюг + відкликання підтверджено
саме на цих доказах. Порожній рядок означає, що структурний хінт ще не
підтверджено криптографічно (LTV substitution/manipulation можливі). Це саме
поле застосовується і до `VerifyFileAsicEXades()`.

WP-6 (H2): `VerifyXml()` тепер доводить `SignatureTimeStamp` до повної довіри
TSA (сертифікат/ланцюг/EKU id-kp-timeStamping), а не лише до криптографічної
валідності RFC3161-токена — той самий шлях (`ApplyXadesTimestampPolicyValidation`),
який вже застосовувався у `VerifyFileAsicEXades()`. Це означає, що
`timestampValid`/`ltvValid` для голого XAdES-XML (без ASiC-E) тепер можуть
стати `false`, якщо TSA-сертифікат недовірений чи без потрібного EKU —
раніше такий стан не виявлявся поза ASiC-E.

WP-12 (CR-01, частково): `tamga::xmldsig::XmlSignatureVerifier` отримав
`VerifyAll()` — незалежну перевірку кожного верхньорівневого `ds:Signature`,
коли в ОДНОМУ XML-документі їх кілька (на відміну від ASiC-E multi-file
co-signing через окремі `signatures*.xml`, вже підтриманого на рівні
`Session`). Це внутрішній будівельний блок XMLDSIG-рівня: `Session::VerifyXml`/
`VerifyFileAsicEXades()` продовжують використовувати `Verify()` (один підпис)
без змін — `VerifyAll()` поки не підключений до `XadesVerifier`/`Session`, це
окремий подальший WP.

## PAdES

| Метод | Потрібний прапор | Призначення |
| --- | --- | --- |
| `SignPdf(documentContent, signedPdfOut)` | `TAMGA_ENABLE_PDF_SIGNATURES=ON` | Створює PAdES-B PDF з підписом поверх завантаженого ключа. |
| `SignPdf(documentContent, padesProfile, signedPdfOut)` | `TAMGA_ENABLE_PDF_SIGNATURES=ON` | Створює PAdES-B/T/LT/LTA; розширені рівні потребують TSA та матеріалів валідації й не понижуються мовчки. |
| `VerifyPdf(pdf, isValid)` | `TAMGA_ENABLE_PDF_SIGNATURES=ON` | Перевіряє PAdES PDF, ByteRange, CMS-підпис і форматний report. |

`VerifyPdf()` заповнює `operation="VerifyPdf"`, `signatureFormat="PAdES"`,
`formatProfile` (`PAdES-B`, `PAdES-T`, `PAdES-LT`, `PAdES-LTA`) і `ltvValid`
для LTV-профілів, а signer certificate проходить той самий policy path, що й
CMS/XAdES сценарії.

## Канонічна модель валідації (WP-11, HI-06)

Для всіх форматів (CMS/CAdES, XAdES, ASiC-E, PAdES) `trust`/`revocation`/
`certificate.timeValid`/timestamp поля `VerifyReport` походять ЛИШЕ з одного
джерела — `tamga::core::validation::ValidationEngine::Validate()`, спроєктованого
у `VerifyReport` через `tamga::core::ProjectVerifyReport()` (чиста функція без
побічних ефектів і без мутації переданого стану). Раніше CMS/CAdES-шлях
(`VerifyData`/`VerifyFile`/`VerifyDataInternal`) додатково проходив через
окремий legacy trust-пайплайн (`ApplyTrustPipelineStatus`), який мутував ті самі
поля ще раз, незалежно — це могло залишити суміш значень із двох різних
policy-моделей (HI-06). Legacy-пайплайн і паралельний
embedded-chain-only шлях (`ApplyPolicyInfoToVerifyReport`) прибрано; єдина
відмінність між форматами тепер — які саме вхідні докази (embedded-сертифікати,
XAdES `CertificateValues`/`RevocationValues`, живий OCSP/AIA-fetch для CMS)
передаються у `ValidationEngine::Validate()` перед проєкцією.

Жива OCSP-перевірка (`OcspSettings.url`) і AIA (Authority Information Access)
issuer-fallback для CMS/CAdES лишаються доступними — тепер як явні pre-steps
перед викликом `ValidationEngine::Validate()` (`ValidationContext.ocsp_url`,
`EnrichWithAiaIssuersIfNeeded()`), а не як частина видаленого legacy-пайплайна.
Свідомо спрощено: окремий "TSP endpoint reachability" cosmetic-probe
(`trust_status="tsp-responder-unavailable"`/`"online-policy-services-available"`)
для CMS/CAdES прибрано разом із legacy-пайплайном — він не впливав на сам
verdict (`trust_valid`/`revocation_status`), лише на допоміжний UX-лейбл.

## Звіти та помилки

| Метод | Призначення |
| --- | --- |
| `GetLastVerifyReport(outJson)` | Технічний machine-readable JSON останньої перевірки. |
| `GetUserReport(outJson)` | User-facing JSON для UI/1С. |
| `RecordVerifyFailure(operation, errorCode, message)` | Допоміжна точка для фіксації verify-помилки у report state. |
| `GetLastError()` | Останній `ErrorCode` і текст помилки. |

Boolean `Verify*` показує execution/integrity результат. Повний policy verdict
треба читати з `GetLastVerifyReport().policyDecision.valid` або
`GetUserReport().verificationResult.valid`.

`certificate.timeValid`/`certificateTimeValid` (WP-3, CR-02) — канонічне
значення реальної X.509 перевірки notBefore/notAfter сертифіката підписанта на
фактичний evaluation time, що встановлюється у `ApplyValidationEngineReport`
(XAdES/PAdES/ASiC-E, через `ValidationEngine`/`CertificateChainValidator`) і
`ApplyPolicyInfoToVerifyReport` (CMS/CAdES). Раніше для XAdES-B-LT це поле
могло стати `true` через оптимістичний fallback, коли контейнер лише ВИГЛЯДАВ
як baseline-LT (сертифікат присутній, підпис валідний, timestamp перевірено),
без фактичного підтвердження дійсності сертифіката — цей fallback прибрано.
`certificate.validationTimeSource` супроводжує це поле і чесно відображає, який
момент часу справді використано для перевірки: `trustedTimestamp` (доведений
RFC3161), `signingTime` (заявлений/недоведений), `currentTime` (поточний
момент виклику — типовий випадок без довіреної мітки часу) або `unknown`
(сертифікат відсутній).
