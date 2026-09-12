# Коди помилок Tamga

Коди визначені в `src/lib/core/Errors.h` як `tamga::core::ErrorCode`.

Зовнішній C ABI має окремий append-only enum `tamga_c_error_code_t` у
`include/tamga/tamga_c_api.h`. Значення 0–9 збережені; нові значення не
перенумеровують старі:

| Код | Ім'я | Відображення core |
| --- | --- | --- |
| 10 | `TAMGA_C_ERR_NOT_SUPPORTED` | `NotSupported` |
| 11 | `TAMGA_C_ERR_SETTINGS_REQUIRED` | `SettingsRequired` |
| 12 | `TAMGA_C_ERR_GUI_NOT_AVAILABLE` | `GuiNotAvailable` |
| 13 | `TAMGA_C_ERR_REVOCATION_FAILED` | `RevocationCheckFailed` (не ототожнюється автоматично з `CERT_REVOKED`) |
| 14 | `TAMGA_C_ERR_TRUST_FAILED` | `TrustValidationFailed` |
| 15 | `TAMGA_C_ERR_TIMESTAMP_FAILED` | `TimestampValidationFailed` |

**Н-10.** До 2026-08-26 `TrustValidationFailed`, `PolicyValidationFailed` і
`TimestampValidationFailed` зводилися в один `TAMGA_C_ERR_POLICY_INVALID` (7),
тож FFI-споживач (C#, Python, Rust, Go) не міг відрізнити проблему довіри від
проблеми мітки часу. Розширення append-only: значення 0–13 не змінені, старий
код працює як раніше, але тепер отримує точнішу причину. `POLICY_INVALID`
лишається за власне policy-помилкою.

| Код | Ім'я | Значення для користувача 1С | Типові дії |
| --- | --- | --- | --- |
| 0 | `None` | Помилки немає. | Додаткових дій не потрібно. |
| 1 | `NotInitialized` | Метод потребує попереднього `Initialize()` / `Инициализировать()`. | Викличте `Configure()` за потреби, потім `Initialize()`. |
| 2 | `SettingsRequired` | Налаштування відсутні або неповні. | Для нового V2 workflow використовуйте `Configure(...)`; `Initialize()` має дефолти, але некоректні параметри можуть лишити сесію неготовою. |
| 3 | `KeyNotLoaded` | Метод підпису викликано без завантаженого ключа. | Викличте `LoadKey(...)` / `ЗагрузитьКлюч(...)`. |
| 4 | `InvalidArgument` | Передано некоректний аргумент. | Перевірте шлях, blob, Base64, формат ключа, alias, пароль або режим `signatureFormat`. Деталі доступні через `GetError()`. |
| 5 | `InternalError` | Внутрішня помилка бібліотеки або файлової операції. | Перевірте `GetError()`, вхідні дані і права на файлову систему. |
| 6 | `NotSupported` | Функція недоступна в цій збірці або ще не реалізована. | Для sign/verify використовуйте збірку з `TAMGA_ENABLE_VENDOR_CRYPTONITE=ON`; для XMLDSIG/XAdES — з `TAMGA_ENABLE_XML_SIGNATURES=ON`, для PAdES — з `TAMGA_ENABLE_PDF_SIGNATURES=ON`. Наступною фазою лишаються вендорні CMP-профілі отримання **власного** сертифіката (ADR-017) і GUI, а не LDAP/CMP загалом: пошук у LDAP і `genm`/`id-it-caCerts` реалізовані. |
| 7 | `GuiNotAvailable` | GUI-функціональність недоступна. | Не покладайтеся на GUI-вибір сертифікатів у серверних/headless сценаріях. |
| 8 | `TrustValidationFailed` | Криптографічна перевірка може бути успішною, але policy-довіра не пройдена: локальний `workDir\trust-store` порожній, chain не доведений до довіреного anchor або статус не вкладається в окремі коди нижче. | Аналізуйте `GetReport().policyDecision`, `trustStatus`, top-level `trustList`, `chainValid`, `certificateTimeValid` і `message`. `trust sync` оновлює TL XML/state, але не створює anchors автоматично. |
| 9 | `RevocationCheckFailed` | Перевірка відкликання дала негативний або некоректний результат: signer certificate відкликаний, CRL/OCSP відповідь невалідна або policy не може прийняти revocation status. | Перевірте `revocationStatus`, `categories.revocation`, OCSP URL, CRL cache у `workDir` і `GetReport()`. |
| 10 | `OnlineServiceUnavailable` | Online-сервіс недоступний: trust-list download, OCSP responder або TSP responder не відповів у межах timeout. | Перевірте URL, timeout, мережу, proxy/TLS і наявність придатного кешу. Для trust list повторіть `trust sync`; для signer revocation така недоступність не дає full policy-pass. |
| 11 | `TimestampValidationFailed` | RFC 3161 timestamp-перевірка не пройдена: imprint не збігається або timestamp token структурно невалідний. | Перевірте TSP-налаштування, режим `cades-t`, `categories.timestamp` у `GetReport()` і повторіть підписання за потреби. Частковий стан `timestamp-not-fully-validated` не є цим кодом, якщо imprint збігся, але TSA signature/chain/EKU validation ще не виконана. |
| 12 | `PolicyValidationFailed` | Загальна policy-перевірка не пройдена, хоча execution path міг завершитися коректно. | Аналізуйте `policyDecision.valid`, `policyDecision.summary`, `trustStatus`, `revocationStatus`, `timestampValid` і `message` у `GetReport()`. |

## Отримання помилки в 1С

```bsl
Если Не Компонента.ПодписатьФайл(ПутьДаних, ПутьПодписи, "cms-detached", "file") Тогда
    Сообщить("Помилка Tamga: " + Компонента.ПолучитьОшибку());
КонецЕсли;
```

## Типовий порядок V2-викликів

```text
Configure(...)       -> optional, якщо потрібні не дефолтні параметри
Initialize()         -> ініціалізація сесії
LoadKey(...)         -> завантаження ключа
SignData/SignFile    -> підпис
VerifyData/VerifyFile -> перевірка
GetReport()          -> структурований verify report
GetUserReport()      -> user-facing report для UI/1С
GetError()           -> текст останньої помилки
Finalize()           -> завершення
```

## Відображення policy-станів на чинні коди

Tamga не має окремих enum-значень для кожного report status. Документація нижче описує, як поточні `trustStatus`, `revocationStatus` і `categories.timestamp` стани вкладаються в наявні `ErrorCode`.

| Стан у report | Типовий ErrorCode | Коментар |
| --- | --- | --- |
| `trustList.cacheStatus=missing`, не вдалося завантажити trust list | `OnlineServiceUnavailable` | Це статус sync/cache, а не proof довіри. Verify policy все одно спирається на локальний `workDir\trust-store`. |
| `trustList.cacheStatus=stale` | `OnlineServiceUnavailable` або останній verify policy code | Застарілий TL XML cache не треба трактувати як повну довіру і він не матеріалізує anchors автоматично. |
| `revocationStatus=revoked` | `RevocationCheckFailed` | Відкликаний signer certificate завжди валить policy. |
| `revocationStatus=invalid` або `trustStatus=ocsp-response-invalid` / `revocation-check-invalid` | `RevocationCheckFailed` | Некоректна CRL/OCSP відповідь не дає policy-pass. |
| `revocationStatus=unknown` або `temporarily-unavailable` для signer certificate | `TrustValidationFailed` або `OnlineServiceUnavailable` | Boolean `Verify*` може лишитися успішним для integrity, але `policyDecision.valid=false`. |
| `trustStatus=ocsp-responder-unavailable` або `tsp-responder-unavailable` | `OnlineServiceUnavailable` | Недоступність online-сервісу явно відображається в summary `integrity-but-online-service-unavailable`. |
| `trustStatus=timestamp-invalid` | `TimestampValidationFailed` | Timestamp token не пройшов структурну або imprint-перевірку. |
| `trustStatus=timestamp-not-fully-validated` | не `TimestampValidationFailed`; policy summary `integrity-but-timestamp-not-fully-validated` | Imprint збігся, але TSA signature/chain/EKU validation ще не завершена. |
