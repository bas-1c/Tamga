# NativeAPI-контракт Tamga

Цей документ є джерелом істини для публічного 1С NativeAPI-контракту `Tamga.dll`.
Компонента має англійські і російські імена методів та властивостей.

## Властивості

Усі властивості доступні тільки для читання.

| Англійська назва | Російський alias | Тип | Опис |
| --- | --- | --- | --- |
| `IsInitialized` | `БиблиотекаИнициализирована` | Boolean | Сесія ініціалізована через `Initialize()` / `Инициализировать()`. |
| `OfflineMode` | `АвтономныйРежим` | Boolean | Поточний режим роботи без онлайн-сервісів. |
| `IsPrivateKeyReaded` | `ЛичныйКлючСчитан` | Boolean | Приватний ключ завантажено у сесію. |
| `NeedSetSettings` | `НеобходимоУстановитьПараметры` | Boolean | Історичний status-прапорець. Новий код не має будувати workflow навколо нього: `Initialize()` застосовує дефолти. |

## Методи

| Метод | Російський alias | Параметри | Результат |
| --- | --- | --- | --- |
| `Initialize()` | `Инициализировать` | немає | Boolean |
| `Finalize()` | `ЗавершитьРаботу` | немає | Boolean |
| `ShowCertificates()` | `ПоказатьСертификаты` | немає | Boolean; GUI поки може повернути `GuiNotAvailable`. |
| `ShowCRLs()` | `ПоказатьСпискиОтзыва` | немає | Boolean; GUI поки може повернути `GuiNotAvailable`. |
| `GetPrivateKeyMedia()` | `ОпределитьПараметрыНосителяЛичногоКлюча` | немає | JSON-рядок із capability report. |
| `GetCertificateInfo(certData, validationTimeIso = "")` | `ПолучитьИнформациюОСертификате` | `certData: Blob`, `validationTimeIso: String` | JSON-рядок з полями сертифіката. `validationTimeIso` — опційний ISO 8601 (напр. `"2026-06-15T12:00:00Z"`); якщо заданий, але не розпізнаний — Boolean `false` + `InvalidArgument`. |
| `BASE64Encode(data)` | `BASE64Кодировать` | `data: Blob` | Рядок Base64. |
| `BASE64Decode(text)` | `BASE64Декодировать` | `text: String` | Blob. |
| `Configure(offline = true, workDir = "", trustMode = "strict", validationLevel = "standard", allowAiaIssuerFetch = false)` | `Настроить` | Boolean, String, String, String, Boolean | Boolean. `offline=true` є безпечним типовим значенням NativeAPI і збігається з `Settings::offline_mode`: виклик `Configure()` без аргументів не вмикає мережу. Явне `offline=false` є online-opt-in. `trustMode` приймає `strict`, `compatibility`, `ukraine-legal`, `offline` або `forensic` (той самий набір, що `--validation-profile` у CLI). `validationLevel` приймає `basic`, `standard`, `extended` або `forensic`; нерозпізнане значення відхиляється (`False` + `GetError()`), порожній рядок дає `standard`. `workDir` приймається як Unicode-рядок 1С. `allowAiaIssuerFetch=false` окремо забороняє HTTP(S)-завантаження issuer-сертифікатів за AIA URL із недовіреного сертифіката; AIA виконується лише коли одночасно `offline=false` і цей прапорець явно `true`. Наявні 4-параметрові виклики сумісні. |
| `ConfigureTsp(url = "", policyOid = "", timeoutMs = 10000, imprintDigestOid = "")` | `НастроитьTSP` | String, String, Number, String | Boolean. |
| `ConfigureOcsp(url = "", useNonce = true, timeoutMs = 10000)` | `НастроитьOCSP` | String, Boolean, Number | Boolean. |
| `ConfigureLdap(url = "", baseDn = "", timeoutMs = 10000)` | `НастроитьLDAP` | String, String, Number | Boolean. **ТЗ Рівень 3:** адреса LDAP-каталогу КНЕДП (`ldap://host[:port][/base-dn]`), звідки авто-резолвер бере відкритий сертифікат для контейнерів без `certBag`. Порожній URL просто вимикає мережевий крок — Рівні 1–2 (явний сертифікат, sidecar, кеш) працюють як раніше. Знайдений сертифікат приймається **лише** якщо математично відповідає закритому ключу. |
| `ConfigureCmp(url = "", profile = "", timeoutMs = 10000)` | `НастроитьCMP` | String, String, Number | Boolean. **ТЗ Рівень 3:** CMP over HTTP (RFC 4210/6712). Порожній URL — адреса береться з реєстру КНЕДП `CAs.json` ЦЗО за підказкою `ca`/`provider` у дескрипторі ключа (у довірчому списку `cmpAddress` немає). Надсилається стандартний `genm`/`id-it-caCerts`; вендорні профілі отримання **власного** сертифіката не реалізовані — див. `docs/adr/017-cmp-scope-standard-genm-only.md`. |
| `ConfigureTrustList(url = "", timeoutMs = 30000, ttlHours = 24, pinnedCertBase64 = "", signaturePolicy = "")` | `НастроитьДоверенныйСписок` | String, Number, Number, String, String | Boolean. Налаштовує URL довірчого списку ЦЗО, timeout завантаження і TTL локального кешу. Порожній URL використовує стандартний `https://czo.gov.ua/download/tl/TL-UA-EC.xml`. **B-3:** `pinnedCertBase64` — DER сертифіката підписанта TL у base64 (перевірка підпису TL проти закріпленого ключа замість самоузгодженості); `signaturePolicy` приймає `disabled`, `prefer-available` **(типове)** або `require`. Невалідний base64 чи нерозпізнана політика відхиляються (fail-closed). |
| `SyncTrustList()` | `ОбновитьДоверенныйСписок` | немає | Boolean. Потребує попереднього `Initialize()` / `Инициализировать()` та `offline=false`. В offline-режимі повертає `false`, `OnlineServiceUnavailable` і не викликає транспорт. В online-режимі оновлює локальний кеш TL XML і `state.json`, матеріалізує активні CA/MR-CA trust anchors у `workDir\trust-store` і metadata сервісів у `workDir\policy\trust-store-metadata.json`; без доступного `workDir`, мережевого успіху або успішного запису кешу повертає `false` і заповнює останню помилку. |
| `LoadKey(source, password, keyPassword = "", alias = "", sourceType = "auto")` | `ЗагрузитьКлюч` | Blob/String, String, String, String, String | Boolean. |
| `ResetKey()` | `СброситьКлюч` | немає | Boolean. |
| `SignData(data, signatureFormat = "cms-detached", outputEncoding = "binary")` | `ПодписатьДанные` | Blob, String, String | Blob або Base64-рядок. |
| `VerifyData(data, signature, signatureFormat = "cms-detached", inputEncoding = "binary", contentEncoding = "none")` | `ПроверитьПодпись` | Blob, Blob/String, String, String, String | Boolean, Blob або String для attached CMS content. |
| `SignFile(inputPath, outputPath = "", signatureFormat = "cms-detached", outputEncoding = "binary")` | `ПодписатьФайл` | String, String, String, String | Boolean, Blob або Base64-рядок. |
| `VerifyFile(inputPath, signatureOrPath = "", signatureFormat = "cms-detached", inputEncoding = "binary")` | `ПроверитьПодписьФайла` | String, Blob/String, String, String | Boolean. |
| `SignXml(xml, profile = "")` | `ПодписатьXML` | `xml: String; profile: String` | String signed XML. `profile`: `""` або `"xmldsig"` — плоский XMLDSIG-enveloped (за замовчуванням); `"xades-bes"` — XAdES-BES з `SignedProperties`; `"xades-t"` — XAdES-T (BES + `SignatureTimeStamp`, використовує `ConfigureTsp()` і `offline=false`). |
| `VerifyXml(signedXml)` | `ПроверитьXML` | `signedXml: String` | Boolean; оновлює `GetReport()` / `GetUserReport()`. |
| `SignPdf(pdfContent, [padesProfile])` | `ПодписатьPDF` | `pdfContent: Blob`, `padesProfile: String = ""` | Blob signed PDF. `padesProfile` — `""`/`b`/`t`/`lt`/`lta` (див. розділ про профіль нижче); типово PAdES-B. `pdfContent` має бути повним незашифрованим PDF; підпис додається incremental update із збереженням попередніх ревізій і підписів. Не-PDF відхиляється. |
| `VerifyPdf(pdf)` | `ПроверитьPDF` | `pdf: Blob` | Boolean; оновлює `GetReport()` / `GetUserReport()`. |
| `GetReport()` | `ПолучитьОтчет` | немає | Технічний machine-readable JSON останнього verify report для діагностики, логування і автоматизованої обробки. Структура `schemaVersion:"2.2"` з блоками `summary`/`signature`/`certificate`/`trust`/`revocation`/`timestamp`/`ltv`/`signaturePolicy`/`dataObjectFormats`/`policy`/`diagnostics`/`signatures[]`; окремі результати TSA — у `timestamp.details[]` і `signatures[].timestamps[]`. |
| `GetUserReport()` | `ПолучитьОтчетПользователя` | немає | JSON-звіт `schemaVersion:"2.2"` для UI/1С зі спільними check-блоками, деталями TSA та двомовними повідомленнями; див. відмінності від `GetReport()` нижче. |
| `GetError()` | `ПолучитьОшибку` | немає | Рядок останньої помилки. |

**ME-08 (`GetCertificateInfo` — validity vs verify-report timeValid):** `validity`
у `GetCertificateInfo()` містить:

- `validNow` (legacy) і `validAtCurrentTime` (новий, однозначний alias для
  того самого значення) — чи дійсний сертифікат `notBefore..notAfter` НА
  МОМЕНТ ВИКЛИКУ `GetCertificateInfo()`. Це НЕ те саме, що `certificate.timeValid`
  у `GetLastVerifyReport()`/`GetReport()` — те поле оцінюється відносно
  `validationTimeSource` (довіреного RFC 3161 timestamp'а чи заявленого часу
  підпису, залежно від профілю верифікації), а не "зараз". Архівний підпис із
  простроченим НА ПОТОЧНИЙ МОМЕНТ сертифікатом підписанта коректно показує
  `certificate.timeValid=true` у verify-звіті, але `validNow=false` тут —
  очікувана, не суперечлива поведінка.
- `validAt` — новий блок `{"time", "valid"}` для перевірки валідності на
  ДОВІЛЬНИЙ момент часу, заданий через опційний параметр `validationTimeIso`
  (ISO 8601, напр. `"2026-06-15T12:00:00Z"`). `time` — ехо заданого значення
  (порожній рядок, якщо параметр не переданий); `valid` — результат
  порівняння з `notBefore..notAfter`. Непорожній, але нерозпізнаний
  `validationTimeIso` -> `GetCertificateInfo` повертає `false` з `InvalidArgument`
  (fail-closed, а не мовчазний ignore).

**ME-06 (TSP endpoint default):** якщо `ConfigureTsp` не викликано
з явним `url`, CMS/CAdES/ASiC-шляхи підписання (`SignData`/`SignFile` і похідні
`SignFileAsicS`/`SignFileAsicE`) за замовчуванням намагаються підібрати TSP URL
у два кроки (`ResolveDefaultTspUrlCombined`). `SignXml` з профілем `""` або
`"xmldsig"` (без XAdES) і `SignPdf` **не** звертаються до TSA — `SignXml` (xmldsig)
створює плоский XMLDSIG-enveloped підпис без `SignedProperties`/timestamp, а
`SignPdf` без другого параметра створює PAdES-B без timestamp; `SignPdf(pdf, "pades-t")` і вище використовують TSA так само, як `SignXml(xml, "xades-t")`. `SignXml(xml, "xades-t")`
TSP-сервер: спершу перевіряє явно заданий `ConfigureTsp` URL, далі робить таку
ж автоматичну резолюцію (`ResolveDefaultTspUrlCombined`), що й CMS-шляхи; якщо
URL порожній або активний `offline_mode` — повертає помилку.

1. **TL-based резолюція (пріоритет).** Читає `workDir\policy\trust-store-metadata.json`
   (записаний `SyncTrustList()`) і бере перший `tspUrl` БУДЬ-ЯКОГО грантованого
   TSA-сервіса (`MR-TSA/QTST`/`National-TSA/QTST`) з офіційного TL, БЕЗ прив'язки
   до issuer'а сертифіката підписанта (RFC 3161 не вимагає такого зв'язку). Читає
   файл щоразу (без кешу сесії) — переживає рестарт процесу. Локальний файл, тому
   працює й у `offline_mode`, якщо TL раніше синхронізовано (`SyncTrustList()`).
2. **Хардкод-таблиця (fallback).** Якщо TL ще не синхронізовано чи в кеші немає
   жодного TSA-сервіса — issuer DN сертифіката підписанта звіряється з таблицею
   відомих українських КНЕДП (`ResolveDefaultTspUrlFromIssuerTable`).

Обидва — best-effort compatibility convenience, а НЕ security/policy-рішення:
обраний URL визначає лише куди надіслати timestamp-запит під час підпису, а сам
отриманий RFC3161-токен незалежно й повністю криптографічно перевіряється кожним,
хто пізніше верифікує підпис. Хардкод-таблиця — крихке джерело (issuer DN може
змінитись, substring-збіг неточний), і частина її адрес досі на `http://` (сам
timestamp-request, не токен-відповідь). Для production/regulated використання явно
викликайте `ConfigureTsp` з потрібним URL або синхронізуйте TL через `SyncTrustList()`.

## Формати і кодування

`signatureFormat`:

- `cms-detached`
- `cms-attached`
- `cades-bes`
- `cades-t`
- `asic-s`
- `asic-e`
- `asic-s-cades`
- `asic-e-cades`
- `xades`
- `pades`
- `asic-e-xades`

Форматні значення `xades`, `pades` і `asic-e-xades` доступні тільки у збірці,
де відповідні рушії ввімкнені на етапі CMake:

| Формат | Потрібний прапор | Залежності |
| --- | --- | --- |
| `xades` / `asic-e-xades` | `TAMGA_ENABLE_XML_SIGNATURES=ON` (лише підсистема **підпису**; сам `libxml2` потрібен у будь-якій конфігурації — ADR-030) | `libxml2` |
| `pades` | `TAMGA_ENABLE_PDF_SIGNATURES=ON` | `qpdf` |

Якщо форматний рушій не зібрано, метод повертає `false`, `GetError()` містить
повідомлення про потрібний build-прапор, а mock-результат не створюється.

### Аргумент `signatureFormat` асиметричний: підпис ≠ перевірка

Перелік вище — це словник **розпізнаваних** значень, а не перелік того, що
кожен метод уміє зробити. Набір форматів, які метод справді ПІДПИСУЄ, вужчий
за набір, який він ПЕРЕВІРЯЄ, і навіть повний build-прапор цього не змінює:

| Метод | Приймає `signatureFormat` | Відхиляє (повертає `Ложь`/`false`) |
| --- | --- | --- |
| `SignData` / `ПодписатьДанные` | `cms-detached`, `cms-attached`, `cades-bes`, `cades-t` | `asic-s`, `asic-e`, `asic-s-cades`, `asic-e-cades`, `xades`, `pades`, `asic-e-xades` |
| `VerifyData` / `ПроверитьПодпись` | ті самі CMS/CAdES-значення | `asic-s`, `asic-e`, `asic-s-cades`, `asic-e-cades`, `xades`, `pades`, `asic-e-xades` |
| `SignFile` / `ПодписатьФайл` | `cms-detached`, `cades-bes`, `cades-t`, `asic-s`, `asic-e`, `asic-s-cades`, `asic-e-cades` | `xades`, `pades`, `asic-e-xades`; `cms-attached` у будь-якому кодуванні |
| `VerifyFile` / `ПроверитьПодписьФайла` | усі значення, крім `cms-attached` | `cms-attached` (використовуйте `VerifyData`) |

Практичний наслідок, який варто прочитати буквально:

- **Контейнери ASiC типово підписуються XAdES (з 0.9.0).** `asic-s`/`asic-e`
  вимагають непорожнього `outputPath` **і** `outputEncoding="file"`; із типовим
  `"binary"` метод повертає `false`, не створивши контейнера.

  | Формат | Розкладка |
  | --- | --- |
  | `asic-s` | `META-INF/signatures.xml` |
  | `asic-e` | `META-INF/manifest.xml` (OASIS ODF) + `META-INF/signatures001.xml` |
  | `asic-s-cades` | `META-INF/signature.p7s` |
  | `asic-e-cades` | `META-INF/signature001.p7s` + `META-INF/ASiCManifest001.xml` |

  У ZIP-представленні `mimetype` завжди є першим незжатим записом без extra
  field. Його локальний заголовок одразу містить CRC і розміри та не
  використовує data descriptor. `manifest.xml` і XAdES XML у `META-INF`
  стискаються DEFLATE, як у досліджених еталонах Дії, і також мають остаточні
  CRC/розміри в локальних заголовках.

  Для `asic-e` файл `META-INF/signatures001.xml` формується за профілем
  ETSI EN 319 162-1: корінь `asic:XAdESSignatures` безпосередньо оголошує
  простори імен `asic`, `ds`, `xades` і `xsi`; посилання на документ має
  `Id="id-<GUID>-1"` і фізично присутній атрибут `Type=""`; `<GUID>` — це
  32 малі шістнадцяткові символи без дефісів. `ds:Signature`
  має `Id="id-<GUID>"`, а `xades:SignedProperties` —
  `Id="xades-id-<GUID>"`, тобто всі три ідентифікатори утворюють спільну
  сумісну з еталонами Дії сім'ю. У
  `xades:SignedDataObjectProperties` є `xades:DataObjectFormat`, чий
  `ObjectReference` посилається на цей `Id`, а `MimeType` визначається за
  розширенням файла. Профіль також містить `SigningCertificateV2` і
  використовує exclusive canonicalization для `SignedInfo` та
  `SignedProperties`. Нові ASiC/XAdES Tamga явно формує в сучасному профілі
  ДСТУ 4145 + Купина-256 (`dstu4145-dstu7564-256` / `dstu7564-256`). OID
  `signatureAlgorithm` сертифіката для цього не використовується: він описує
  підпис сертифіката його видавцем, а не алгоритм гешування нового документа.
  Перевірка приймає як профіль Купини, так і сумісні старі підписи ГОСТ, але
  завжди виконує саме алгоритм, явно оголошений у `SignatureMethod` і
  `DigestMethod`; підміна ГОСТ на Купину за сертифікатом заборонена.

  Обидві розкладки дозволені ETSI EN 319 162-1. Зокрема, ASiC-S може містити
  як XAdES у `META-INF/signatures.xml`, так і CAdES у
  `META-INF/signature.p7s`; саме розширення `.asics` і mimetype
  `application/vnd.etsi.asic-s+zip` не вимагають лише CMS/CAdES. Тому XML-файл
  `signatures.xml` усередині ASiC-S сам по собі не є помилкою формату.
  У Tamga XAdES-розкладка доступна як `asic-s`/`asic-e`, а CAdES-розкладка —
  як `asic-s-cades`/`asic-e-cades`. Сумісність конкретного контейнера із
  зовнішнім сервісом треба підтверджувати окремою перевіркою, а не визначати
  лише за розширенням або назвою signature entry.

  **Перевірка розпізнає розкладку за вмістом контейнера, а не за іменем
  формату.** `VerifyFile(..., "asic-e", ...)` читає і XAdES-, і CAdES-контейнер;
  `asic-e-xades` лишається явним іменем того самого XAdES-шляху.
- **Окремий `META-INF/timestamp.tst` не створюється.** Мітка часу для
  CAdES-профілів лежить усередині підпису як `id-aa-signatureTimeStampToken`.
  Контейнер ASiC-S, у якому присутні І `signature.p7s`, І `timestamp.tst`,
  відхиляється при читанні: ETSI EN 319 162-1 §4.3.3.2 допускає лише один з
  них. Профіль timestamp-only ASiC-S не реалізований.
- **Невдалий запит до TSA більше не мовчазний.** Якщо `offline=false`, але
  TSA-запит неуспішний, `SignFile(..., "asic-*", ...)` створює контейнер рівня BES,
  повертає `true` і лишає причину в `GetError()` з кодом
  `OnlineServiceUnavailable`.
- **XAdES і PAdES підписуються окремими методами, а не через `SignFile`.**
  Для XML це `SignXml` / `ПодписатьXML` (профілі `xmldsig`, `xades-bes`,
  `xades-t` — `SessionXmlOps.ipp:135`), для PDF — `SignPdf` / `ПодписатьPDF`,
  де необов'язковий другий параметр обирає `pades-b`, `pades-t`, `pades-lt`
  або `pades-lta`. Рівні XAdES-LT/A компонента **перевіряє**, але публічний
  `SignXml` їх не створює.
- Відмова у цих випадках — це `false` від `SignData`/`SignFile` без окремого
  `ErrorCode`: аргумент відхиляється до входу в сесію.

`outputEncoding` / `inputEncoding`:

- `binary`
- `base64`
- `file`

`contentEncoding` для attached verify:

- `none`
- `binary`
- `text`

`LoadKey.sourceType`:

- `auto`
- `file`
- `binary`
- `jks`
- `pkcs12`, `p12`, `pfx`
- `pem`
- `der`
- `descriptor`

`descriptor` — це JSON-рядок. Він дає змогу передати sidecar явно, не змінюючи
публічну сигнатуру `LoadKey`:

```bsl
ОписКлюча = "{""path"":""C:\\Keys\\key.dat"",""certificatePath"":""C:\\Keys\\key.cer""}";
КлючЗавантажено = Компонента.ЗагрузитьКлюч(
    ОписКлюча, Пароль, "", "", "descriptor");
```

Підтримуються також alias-поля `filePath` і `certPath`. Пароль можна лишити
другим параметром `LoadKey`; зберігати його в JSON не рекомендовано.

`.ZS2` АЦСК «Україна» завантажується нативним PKCS#12-шляхом: PBES2 із
KMAC Купина-256 та Калина-256 CBC розшифровується vendored `cryptonite`, а
весь dual-key контейнер `DU` лишається доступним для перебору. Ключ підпису
обирається за відповідністю відкритого ключа сертифікату та за `keyUsage`, а
не за позицією мішка в контейнері.

Для `.dat`, `.ZS2` та інших PKCS#12 без `certBag` компонента автоматично шукає
сертифікат під час першої операції `Sign*`. Спочатку використовується явний
`certificatePath`, потім перевіряються однойменні
`<stem>.cer`, `<stem>.crt`, `<stem>.der`, `<stem>.pem`, потім інші сертифікати
того самого каталогу, локальний кеш і лише після них мережеві джерела. Такий
порядок не дозволяє старому перевиданому сертифікату з кешу перекрити явно
покладений поруч sidecar. Кандидат приймається лише за одночасного збігу з
одним із закритих ключів та дозволу `digitalSignature` або `nonRepudiation`
у `keyUsage`; тому sidecar сертифіката шифрування не зупиняє подальший пошук.
`LoadKey` навмисно може завершитися успішно без сертифіката, щоб лишити
доступним `SignHash`; якщо наступна файлова/CMS/XML/PDF/ASiC-операція звертається
до X.509, а придатного сертифіката немає, `GetError()` повертає:

> Не знайдено відкритий сертифікат для закритого ключа. Покладіть файл
> сертифіката (.cer/.crt) поруч із ключем або передайте через параметр
> certificatePath


### Приклад ASiC-E + XAdES detached

Якщо `.asice` контейнер містить документальний entry на кшталт `rahunok2.pdf` і XAdES/XMLDSIG підпис у `META-INF/signatures001.xml` із `ds:Reference URI="rahunok2.pdf"`, перевірку треба запускати через формат `asic-e-xades`. PDF у цьому сценарії є підписаним об'єктом, а не носієм PAdES-підпису.

`ds:Reference URI` зіставляється з іменем entry контейнера через нормалізацію (WP-7, ME-05): percent-decode (напр. `URI="rahunok%202.pdf"` відповідає entry `rahunok 2.pdf`) і зняття рівно одного провідного `"./"` (напр. `URI="./rahunok2.pdf"` відповідає entry `rahunok2.pdf`). Порівняння РЕГІСТРОЗАЛЕЖНЕ; Unicode NFC/NFD-нормалізація (композиційно різні, але візуально ідентичні імена) НЕ виконується. Якщо два різних entry контейнера нормалізуються в однаковий канонічний URI, перевірка відхиляє контейнер цілком (неоднозначність, а не автоматичний вибір одного з них).

```bsl
Результат = Компонента.ПроверитьПодписьФайла(
    ПутьКонтейнера,
    "",
    "asic-e-xades",
    "file");

Отчет = Компонента.ПолучитьОтчет();
ОтчетПользователя = Компонента.ПолучитьОтчетПользователя();
```

Для такого сценарію технічний і користувацький звіти показують `operation="VerifyFileAsicEXades"`, `signatureFormat="XAdES"` і `containerType="ASiC-E"`, а сертифікат підписанта з `KeyInfo/X509Certificate` проходить той самий policy/trust/revocation шлях, що й форматні XAdES/PAdES перевірки.

### Підтримувані рівні XAdES (WP-19)

Таблиця нижче описує внутрішні `XadesBuilder`/`XadesVerifier`, а не перелік
значень другого аргументу NativeAPI `SignXml`. Компонента 1С створює лише BES
і T; C/X/X-L/A доступні для розбору та внутрішніх builder round-trip, але не є
публічними профілями підписання.

| Профіль (`format_profile`) | Статус рушія | Примітка |
| --- | --- | --- |
| `XAdES-BES` | Підтримується | `SignedProperties`, `SigningCertificate`/`CertDigest`. Повний sign+verify round-trip, тестовано (`TestXadesBesSignVerifyRoundTrip`). |
| `XAdES-T` | Підтримується | `SignatureTimeStamp` із повною TSA-довірою (сертифікат/ланцюг/EKU TSA, WP-6) — не лише криптоперевірка RFC 3161-токена. |
| `XAdES-C` | Підтримується | `CompleteCertificateRefs`/`CompleteRevocationRefs`. |
| `XAdES-X` (legacy) | Структурний | Розпізнається й перевіряється структурно (наявність `Complete*Refs` без baseline LT-значень), але не є основним LTV-шляхом Tamga — для нового коду орієнтуйтесь на `XAdES-X-L`/baseline B-LT нижче. |
| `XAdES-X-L` (baseline B-LT) | Підтримується | `CertificateValues`/`RevocationValues` + evidence-binding (digest кожного `CompleteCertificateRefs`/`CompleteRevocationRefs` проти відповідних значень, WP-5 ME-04/ME-07) — основний LTV-шлях Tamga для Дія та сумісних ASiC-E/XAdES-B-LT контейнерів. |
| `XAdES-A` | **Структурно узгоджений із ETSI, не cross-validated** | `ArchiveTimeStamp` message imprint (WP-13) тепер побудований за покроковим алгоритмом ETSI EN 319 132-1 §5.5.2.3 (not-distributed case): результати `ds:Reference` (включно з `SignedProperties`) → `SignedInfo`/`SignatureValue`/`KeyInfo` → unsigned qualifying properties → `ds:Object` (крім того, що містить `QualifyingProperties`) — спільна реалізація для builder і verifier (`xades/detail/XadesArchiveImprint.h`), замість попереднього "Tamga-визначеного" фіксованого набору. **Не покрито**: distributed case (`xades:Include`) — не застосовний до поточної структури підпису Tamga (єдиний `UnsignedSignatureProperties` на підпис); кілька послідовних `ArchiveTimeStamp` (Tamga створює не більше одного за раз); і, найважливіше, **незалежна cross-validation саме для `ArchiveTimeStamp` XAdES-A не проводилась**. Тут раніше стояло пояснення «мережевий доступ цього середовища обмежений лише репозиторієм Tamga» — воно **хибне й прибране**: диференційну звірку проти ETSI DSS виконано (Хвиля 8, п.4, `tools/dss-crosscheck`, `docs/dss-crosscheck.md`), просто вона покрила структурний шар і RSA-напрямок, а не архівні мітки XAdES-A. Незасвідчені «блокери» цього роду в цьому дереві спростовувалися вже пʼять разів; формулювання «неможливо, бо X» без запису «перевірено `<дата>` командою `<команда>`» більше не вживати. Round-trip Tamga↔Tamga і token-swap регресія (`TestXadesArchiveTimeStampRejectsSwappedToken`) підтверджені тестами. Див. `docs/bugfix-log.md` і зведений аудит `docs/audit/final-2026-08-26-project-audit.md`. |

Boolean-результат `VerifyXml` або `VerifyFile` (для формату `asic-e-xades`) відображає крипто-цілісність підпису на детектованому рівні; `format_profile`/`profile` у звіті показує, ЯКИЙ саме рівень був виявлений і перевірений — для `XAdES-A` це не є гарантією ETSI-сумісності архівної позначки часу (див. таблицю вище).

**HI-04:** `format_profile`/`detected_profile`/`profile` (і транзитивно `validatedProfile`)
позначаються як `XAdES-A` ЛИШЕ коли `ArchiveTimeStamp` фактично пройшов криптоперевірку
(`archive_timestamps_valid=true`), а не за самою структурною наявністю елемента.
Пошкоджений, чужий або підмінений `ArchiveTimeStamp` (напр. token-swap) падає на
наступний тир драбини профілів (типово `XAdES-B-LT`, якщо LTV-докази присутні) —
детальна причина лишається в `chainDebug`/діагностичних нотатках. Регресія:
`TestXadesArchiveTimeStampRejectsSwappedToken` (рівень `XadesVerifier`) і
`TestSessionVerifyXmlArchiveProfileRequiresValidTimestamp` (рівень `Session`/JSON-звіт).

**П-13 (namespace-aware класифікація):** рівень профілю визначається ЛИШЕ за
властивостями XAdES у дозволених просторах імен ETSI —
`http://uri.etsi.org/01903/v1.3.2#` (єдиний, який генерує Tamga і який мають усі
XAdES-фікстури репозиторію) і `http://uri.etsi.org/01903/v1.4.1#` (нормативне
місце `ArchiveTimeStamp`/`TimeStampValidationData` за ETSI TS 101 903 V1.4.1).
Allowlist задано в `xmldsig/detail/XmlDocUtil.h:122-123`.

Другий запис внесено за **нормативним аргументом**, а не за фікстурою:
властивостей у просторі імен `01903/v1.4.1#` у дереві немає. Перевірено
2026-08-30 командою `grep -rl "01903/v1.4.1" tests/` → єдине влучання
`tests/TL-UA-EC.xml`, і там це лише оголошення префікса `xmlns:ns6`, яким не
користується жоден елемент (`grep -c "ns6:" ` → `0`). Тобто гілка allowlist для
v1.4.1 у сюїті не виконується; тримати її варто, але вважати перевіреною —
ні.
Елемент із чужим простором імен, але зі збіжною локальною назвою
(`evil:SignatureTimeStamp`, `evil:CompleteCertificateRefs`,
`evil:CertificateValues`/`evil:RevocationValues`), більше НЕ піднімає
`format_profile`/`profile` і не виставляє поля доказів
(`certificateValuesPresent`, `revocationValuesPresent`, `ltvDataPresent`,
`timestampTokenCount`, `certRefsComplete`). Сертифікат підписувача береться
винятково з `ds:X509Certificate` у просторі імен XMLDSIG; без нього підпис
не звіряється взагалі (fail-closed).

Це виправлення значення поля до вже задокументованої семантики («ЯКИЙ рівень
виявлено і перевірено»), а не зміна набору полів: на момент П-13
`schemaVersion` залишався `2.1` (ADR-028). Поточна схема `2.2` додала
деталізацію TSA окремою зміною (ADR-035). Практичний наслідок
для конфігурацій 1С: для документа з чужими XAdES-подібними вузлами `profile`
тепер може бути НИЖЧИМ (наприклад `XAdES-B-B` замість `XAdES-C`/`XAdES-T`) —
це і є правильне значення. Регресія: `TestXadesProfileIgnoresForeignNamespaceProperties`,
`TestXadesForeignNamespaceStructuralNodesRejected`,
`TestXmlDsigSignatureScopeIsNamespaceAware`.

**ME-02:** top-level `revocation.checked`/`revocation.ocspChecked` (і legacy flat
`revocationChecked`/`ocspChecked`) відображають ЛИШЕ канонічний вердикт
ValidationEngine/RevocationEngine (`report.revocation_checked`/`report.ocsp_checked`) —
раніше XAdES-B-LT з присутнім сертифікатом і валідним підписом міг звітувати
`ocspChecked=true` за самою структурною наявністю LTV-доказів, незалежно від
того, чи RevocationEngine дійсно щось перевірив (той самий клас проблеми, що
WP-3/CR-02 уже усунув для `certificateTimeValid`). Структурний факт наявності
`RevocationValues` не втрачено — новий top-level `revocation.evidencePresent`
відображає його окремо. Регресія: `TestSessionVerifyXmlRevocationEvidencePresentField`.

**ME-05:** RFC 3161 timestamp-токен із нерозпізнаним `messageImprint.hashAlgorithm`
OID (не Kupyna-256/GOST34311/SHA-256) більше НЕ приймається за випадковим
чи навмисним збігом `hashedMessage` з будь-яким із трьох відомих digest —
`TimestampValidator::ValidateTimestampToken` тепер відхиляє нерозпізнаний OID
так само fail-closed, як і розпізнаний, але незбіжний. Стосується всіх
timestamp-шляхів (`SignatureTimeStamp`/`SigAndRefsTimeStamp`/`ArchiveTimeStamp`
у XAdES, PAdES-T/LTA, окремий `TimestampEngine`). Профіль-залежна поблажка
(forensic mode) НЕ реалізована. Щоб її внести, `ValidationProfile` довелося б
прокинути у форматні верифікатори: перевірено 2026-08-30 командою
`grep -c ValidationProfile src/lib/xades/XadesVerifier.h src/lib/pades/PadesVerifier.h
src/lib/core/validation/TimestampEngine.h` → `0 / 0 / 1`, тобто профіль сьогодні
доходить лише до `TimestampEngineInput`, а `XadesVerifier` і `PadesVerifier` про
нього не знають узагалі. Оцінка «архітектурно ширша зміна» лишається оцінкою, а
не виміряним блокером. Регресія: `TestTimestampValidatorRejectsUnknownImprintOid`.

**HI-02:** top-level `ltv` блок у `GetLastVerifyReport()`/`GetReport()` (і в
`GetUserReport()`) розділено на деталізовані сигнали замість одного
`ltvValid`, який раніше змішував "докази структурно присутні" з "LTV дійсно
підтверджено":

- `ltv.valid` (legacy `ltvValid`) — **без зміни поведінки/контракту**, той
  самий структурний сигнал, що й раніше (для XAdES: сертифікат/timestamp
  крипто-валідні + `CertificateValues`/`RevocationValues` присутні; для
  PAdES: DSS-словник + `/Certs` присутні). Інтегратори, що вже читають це
  поле як "докази присутні", не отримують breaking change;
- `ltv.evidenceBound` (нове) — докази структурно ПРИВ'ЯЗАНІ до підпису
  (`ltv_evidence_bound`), незалежно від підтвердження trust/revocation;
- `ltv.evidenceValidated` — сумісний сигнал доказів **підписанта**: докази
  прив'язані, його trust-ланцюг довірений і відкликання підтверджено.
  Не включає підтвердження TSA і не є юридичним висновком;
- `ltv.fullyValidated` і `ltv.fullValidationState` (схема `2.2`) — окремий
  повний висновок: `evidenceValidated=true`, докази всіх записів
  `signatures[]` підтверджені, усі враховані мітки часу канонічно валідні.
  Невідоме відкликання TSA не дає `fullyValidated=true`, навіть якщо
  `evidenceValidated=true`. Стани `fullValidationState`: `valid`,
  `unavailable` або `skipped`.

Публічний machine-readable вердикт `ltv.status`/`ltv.code` (в обох
`GetLastVerifyReport()` і `GetUserReport()`) у схемі `2.2` вимагає
`ltv.fullyValidated` для `"LTV_VALID"` — раніше він гейтувався лише
структурним `ltv.valid`, тож self-signed/untrusted підпис зі структурно
присутніми LTV-доказами міг помилково отримати вердикт `"LTV_VALID"` попри
непідтверджений trust-ланцюг. Регресія:
`TestSessionVerifyXmlLtvEvidenceSplitFields` (XAdES-X-L, self-signed
untrusted chain: `evidenceBound=true`, `evidenceValidated=false`) і
розширений `TestPadesTandLtaSignVerifyRoundTrip` (PAdES-LTA: демонструє
чистий випадок legacy `ltvValid=true` при `evidenceValidated=false`, бо
PAdES structural `ltv_valid` не залежить від trust-ланцюга так, як XAdES).

### Приклади XML/XAdES і PDF/PAdES

XML/XAdES можна перевіряти напряму рядком XML:

```bsl
ПодписанныйXML = ПрочитатьXMLКакСтроку(ПутьКXML);
Результат = Компонента.ПроверитьXML(ПодписанныйXML);

Если Не Результат Тогда
    Сообщить(Компонента.ПолучитьОшибку());
КонецЕсли;

Отчет = Компонента.ПолучитьОтчет();
```

PDF/PAdES перевіряється як Blob із байтами PDF:

```bsl
PDF = Новый ДвоичныеДанные(ПутьКPDF);
Результат = Компонента.ПроверитьPDF(PDF);

Отчет = Компонента.ПолучитьОтчет();
ОтчетПользователя = Компонента.ПолучитьОтчетПользователя();
```

`ПодписатьPDF` працює з наявним PDF, а не з довільним payload: він додає нову
ревізію документа, тому байти оригіналу та попередні підписи залишаються
доступними для подальшої перевірки.

### Профіль PAdES (другий параметр, А-07)

До 2026-08-30 метод жорстко створював профіль **B**, хоча рушій реалізує
T/LT/LTA. Тепер профіль задається другим, **необовʼязковим** параметром:

| Значення | Рівень | Що потрібно |
| --- | --- | --- |
| `""` (типово), `"b"`, `"pades-b"` | PAdES-B | нічого понад ключ |
| `"t"`, `"pades-t"` | + мітка часу підпису | `НастроитьTSP` і `Настроить(offline=Ложь)` |
| `"lt"`, `"pades-lt"` | + `/DSS`: сертифікати й CRL/OCSP підписанта та фактичної TSA | те саме + матеріали ланцюгів і підтверджені докази відкликання |
| `"lta"`, `"pades-lta"` | + документна мітка часу | те саме, що для LT |

Регістр не має значення. Виклик з одним аргументом лишається дійсним і дає
той самий результат, що раніше.

```bsl
// Як було — працює без змін
ПодписанийPDF = Компонента.ПодписатьPDF(ДвоичныеДанныеPDF);

// З міткою часу
Компонента.Настроить(Ложь);                       // offline = Ложь
Компонента.НастроитьTSP("http://acskidd.gov.ua/services/tsp/");
ПодписанийPDF = Компонента.ПодписатьPDF(ДвоичныеДанныеPDF, "pades-t");
```

**Поведінка fail-closed — це частина контракту, а не деталь реалізації.**
Якщо матеріалу для заявленого рівня немає (не налаштовано TSA, увімкнено
автономний режим, не знайдено перевіреного видавця, немає придатного CRL/OCSP), метод
повертає `Ложь` і заповнює `ПолучитьОшибку()` — і **не** створює документ
нижчим рівнем. PDF, який заявляє LT і не несе доказів валідації, є хибним
твердженням усередині підписаного документа, і виявить його вже перевіряльник.

Невідома назва профілю відхиляється з `NotSupported`, а не трактується як `B`.

Основний словник підпису у всіх чотирьох профілях має
`/SubFilter /ETSI.CAdES.detached`; PAdES-LTA додає окремий
`/Type /DocTimeStamp` із `/SubFilter /ETSI.RFC3161`. Варіант
`/adbe.pkcs7.detached` Tamga більше не генерує для PAdES.

`SignPdf` зберігає номер **і покоління** початкового об'єкта `Catalog`:
посилання `/Root` не змінюється. Нові трейлери успадковують `/Info` та перший
ідентифікатор `/ID`, а другий `/ID` оновлюється для кожної ревізії. Числа
`/ByteRange` записуються десятковими без ведучих нулів; залишок фіксованого
слота заповнюється пробілами, без зсуву підписаних байтів.
Виключений проміжок `/Contents` охоплює весь шістнадцятковий рядок разом із
роздільниками `<` і `>`; усі інші байти ревізії входять до підпису.

Порядок **доданих** ревізій (початкові ревізії PDF не входять у цей рахунок):

| Профіль | Послідовність оновлень |
| --- | --- |
| B/T | Основний підпис; для T його CMS уже містить мітку часу підпису |
| LT | Основний підпис T → окрема ревізія `/DSS` |
| LTA | Основний підпис T → `/DSS` → окремий `/DocTimeStamp`, що покриває попередні ревізії разом із DSS |

Докази TSA збираються з **фактично отриманих** токенів, а не з попереднього
пробного запиту: перевіряються imprint і підпис токена, добираються
сертифікати його TSA та перевірені видавці, додаються CRL або DER-відповіді
OCSP. Дублікати доказів не створюють нового циклу. Якщо `DocTimeStamp`
приносить нову TSA або нові докази, LTA додає ще `/DSS` → `/DocTimeStamp`,
не змінюючи попередніх байтів. Дозволено не більше **трьох повторних
оновлень** після початкової документної мітки; якщо докази не стабілізуються,
підписання завершується помилкою без часткового PDF (ADR-035).
Збір доказів не замінює незалежну перевірку довіри під час `VerifyPdf`.

Основний `ByteRange` завершується на ревізії підпису, тож пізніше доданий DSS
не входить до нього. Це обраний порядок формування Tamga, а не правило про
обов'язкову кількість ревізій у будь-якому сторонньому PAdES-документі.

Заявлений час підписувача записується в `/M` основного словника `/Sig` у
форматі PDF-дати; `/Reason` присутній навіть за порожнього значення. CMS
цього підпису **не містить** атрибута `signingTime`; поведінка звичайних
CMS/CAdES-методів не змінена. Поле `/M` саме по собі не є довіреною міткою
часу TSA. Віджет має `/P` на першу сторінку, якщо вона є, `/M` і
`/Rect [0 0 50 50]`; наявні поля форми та анотації зберігаються. Це не
додає видимого зображення підпису на сторінку.

Через універсальний `VerifyFile()` форматний dispatch виглядає так:

```bsl
РезультатXML = Компонента.ПроверитьПодписьФайла(
    ПутьКXML,
    "",
    "xades",
    "file");

РезультатPDF = Компонента.ПроверитьПодписьФайла(
    ПутьКPDF,
    "",
    "pades",
    "file");
```

## Межі розміру вхідних даних (П-11)

Спільна межа розміру недовіреного вводу — **64 МіБ**
(`tamga::util::kMaxInputFileSize`). Раніше вона застосовувалася **лише** там,
де вхід приходив шляхом до файлу. Тепер вона однакова для обох способів
передачі: для політики немає різниці, чи прийшли ті самі байти шляхом, чи
значенням.

| Спосіб передачі | Що вимірюється | Межа |
| --- | --- | --- |
| `inputEncoding = "file"`, `LoadKey` з файлу | розмір файлу | 64 МіБ |
| Двійковий параметр (BLOB): `SignData`, `VerifyData`, `SignPdf`, `VerifyPdf`, `LoadKey` з двійковими даними | довжина значення в байтах | 64 МіБ |
| Рядковий параметр: `SignXml`, `VerifyXml`, підпис/шлях/дескриптор у решті методів | довжина UTF-16-навантаження в байтах (кількість символів × 2) | 64 МіБ |

**Зміна спостережуваної поведінки.** Виклик із параметром, більшим за межу,
тепер повертає `False` **детерміновано і до копіювання даних**. До цієї зміни
такий виклик або відпрацьовував (виділивши стільки пам'яті, скільки просив
викликач), або переривався на вичерпанні пам'яті — тобто результат залежав від
стану процесу 1С, а не від вхідних даних.

Чим ця зміна **не** є: вона не рятує процес 1С від аварійного завершення. Кожна
точка входу компоненти вже обгорнута перехопленням винятків
(`src/nativeapi/Export.cpp`), тож `std::bad_alloc` і раніше не виходив за межу
компоненти: метод повертав `False`, а процес платформи лишався живим.
Виправлено саме **відсутність передбачуваної межі**, а не крах.

Окремо: XML-документ, більший за 2 ГіБ, відхиляється з повідомленням
українською ще на вході в парсер. Довжина в libxml2 має тип `int`, і мовчазне
звуження означало б розбір **частини** документа з успішним результатом — для
підпису це гірше за відмову.

## Семантика запису вихідних файлів (П-12)

Усі методи, що пишуть файл (`SignFile`, `VerifyFile` з `outputEncoding="file"`,
ASiC-виходи, `--evidence-out` у CLI, обидва вихідні шляхи C ABI), користуються
одним атомарним writer-ом. Семантика описана один раз у
`src/lib/util/FileSystem.h` і однакова для всіх:

- запис **заміщує** наявний файл цілком; проміжного стану немає — читач бачить
  або старий вміст, або повний новий;
- при невдачі цільовий файл лишається **недоторканим**, а тимчасовий
  прибирається;
- заборона перезапису (`Output file already exists`) лишається рішенням
  **політики** і перевіряється до запису; сам writer завжди заміщує.

До цієї зміни вихідні шляхи писалися прямим `ofstream ... trunc`: цільовий
файл обнулявся ще до появи першого байта результату, тож перервана операція
(немає місця, зникла мережева шара, процес убито) лишала на місці підписаного
контейнера порожній або усічений файл.

## Звіт після ранньої відмови перевірки (Q-06)

Будь-яка відмова методу перевірки — включно з відмовою **до** початку
криптографічної роботи (невірний формат, невірний тип чи кількість аргументів,
нечитабельний вхідний файл) — тепер **записує невдалу операцію у звіт**.
Раніше такі шляхи оновлювали лише текст останньої помилки, а
`GetReport()` / `GetLastVerifyReport()` / `tamga_session_get_last_report`
віддавали звіт **попереднього** виклику. Для доказового артефакта це гірше
за відсутність звіту: він виглядав достовірним.

Контракт після зміни однаковий для всіх чотирьох методів перевірки:

| Джерело | Метод | Поведінка при ранній відмові |
| --- | --- | --- |
| NativeAPI | `VerifyData`, `VerifyFile` | `False`; у звіті — `operation="VerifyData"`/`"VerifyFile"`, `errorCode=InvalidArgument` |
| NativeAPI | `VerifyXml`, `VerifyPdf` | `False`; у звіті — `operation="VerifyXml"`/`"VerifyPdf"`, `errorCode=InvalidArgument` |
| C ABI | `tamga_session_verify_file` | `TAMGA_C_ERR_INVALID_ARGUMENT`; у звіті — `operation="tamga_session_verify_file"` |
| C ABI | `tamga_session_verify_data` | `TAMGA_C_ERR_INVALID_ARGUMENT`; у звіті — `operation="tamga_session_verify_data"` |

Два значення `operation` для C ABI — нові й свідомо НЕ збігаються з іменами
методів `Session`: у момент ранньої відмови конкретний метод ще не обрано,
тож назва `VerifyFile` приписала б звіт операції, яка не виконувалася.

Додатково для C ABI: вихідний прапорець `out_valid` обнуляється **першою**
дією, до перевірки решти аргументів. Раніше обнулення стояло після неї, і
виклик із `data == nullptr` (або `input_path == nullptr`) при справному
`out_valid` лишав у ньому попереднє значення — тобто `1` після успішного
попереднього виклику. Жоден із цих шляхів ніколи не повертав успішного
вердикту; проблема була в достовірності супутнього звіту й у детермінованості
виходу.

## Вилучений V1 API

Публічний NativeAPI dispatch більше не містить V1 wrappers:

`GetErrorDescription`, `SetSettings`, `ReadPrivateKey`, `ReadPrivateKeyBinary`, `ReadPrivateKeyFile`, `ResetPrivateKey`, `SetFileStoreSettings`, `SetOCSPSettings`, `SetTSPSettings`, `SetLDAPSettings`, `SetCMPSettings`, `SignDataBase64`, `VerifyDataBase64`, `SignDataInternal`, `VerifyDataInternal`, `VerifyDataInternalStr`, `SignDataInternalBase64`, `VerifyDataInternalBase64`, `VerifyDataInternalBase64Str`, `RawSignFile`, `RawVerifyFile`, `GetLastVerifyReport`, `SignFileAsicS`, `VerifyFileAsicS`, `SignFileAsicE`, `VerifyFileAsicE`, `AddSignatureToAsicE`.

Сценарії цих методів треба виконувати через V2-методи з параметрами `signatureFormat`, `inputEncoding`, `outputEncoding` і `contentEncoding`.

## Verify policy

`VerifyData` і `VerifyFile` повертають Boolean для execution-level результату і криптографічної цілісності CMS/ASiC. Цей Boolean не є повним policy-verdict для довіри до підпису.

Той самий принцип діє для `VerifyXml` і `VerifyPdf` (WP-19): Boolean відображає лише execution-level результат і криптографічну цілісність XMLDSIG/XAdES чи PDF-підпису (усі дайджести `ds:Reference`, підпис `SignedInfo`, за наявності — `SignedProperties`), а НЕ повний policy-verdict довіри до сертифіката/ланцюга/відкликання/timestamp. Як і для `VerifyData`/`VerifyFile`, авторитетний policy-результат після `VerifyXml`/`VerifyPdf` — це блок `policy` (`policy.status`/`policy.code`) і `summary` у `GetReport()`/`GetLastVerifyReport()`, а не сам Boolean.

`GetReport()` повертає технічний JSON `schemaVersion:"2.2"` з такими top-level блоками:

- `summary` — `{status, code, summaryCode}`: агрегований машиночитаний вердикт. **`status="invalid"` означає доведену відмову**, `status="warning"` — що перевірку не вдалося завершити. Ці два стани розрізняються з 2026-08-29 (П-02): доти будь-яка невдача політики давала `warning`/`SIGNATURE_INTEGRITY_ONLY`, тож відкликаний сертифікат був нерозрізнимий від ненаcтроєного довірчого списку. Доведені відмови: `CERTIFICATE_REVOKED`, `CERTIFICATE_INVALID_AT_VALIDATION_TIME`, `REVOCATION_INVALID`, `TIMESTAMP_INVALID`, `CONTAINER_COVERAGE_INCOMPLETE`, **`CONTAINER_MALFORMED`**, `SIGNATURE_INVALID`, `VERIFICATION_EXECUTION_FAILED`. Незавершені перевірки (`trust-store-empty`, `certificate-chain-incomplete`, `*-responder-unavailable`, `timestamp-not-fully-validated`) свідомо лишаються `warning`;
- `signature` — `{status, code, format, profile, validatedProfile, coverageStatus, containerType}`;
- `certificate` — `{status, code, present, qualifyingPropertiesPresent, timeValid, validationTimeSource, chain:{checked,valid}}`;
- `trust` — `{status, code, checked, valid, mode, reason, trustStatus, historicalTrustUsed, historicalAnchor:{subject,serial}}`;
- `revocation` — `{status, code, checked, ocspChecked, crlChecked, evidencePresent, revocationStatus}`;
- `timestamp` — `{status, code, checked, tspChecked, timestampStatus, details:[...]}`;
- `ltv` — `{status, code, valid, evidenceBound, evidenceValidated, fullyValidated, fullValidationState}` (HI-02, ADR-035);
- `signaturePolicy` — `{present, id, hashAlgorithmUri}` (WP-12);
- `dataObjectFormats` — масив `{objectReference, mimeType, description}` (WP-12);
- `policy` — `{status, code, level, warnings:[...]}`: авторитетний policy-verdict;
- `diagnostics` — технічна діагностика (нижче);
- `signatures[]` — per-signature масив для мультипідпису (WP-2, окремий розділ нижче).

`diagnostics` містить: `operation`, `format`, `profile`, `containerType`, `errorCode`, `message`, вкладений `trustList` (стан TL цього verify-виклику), `trustListSync` (стан останнього явного `SyncTrustList()`), `chainDebug:{trace}` і `flags` — сумісний набір плоских булевих полів для існуючих інтеграцій:

- `hasResult`, `executionSucceeded`, `signatureValid`
- `trustChecked`, `trustValid`, `revocationChecked`, `ocspChecked`, `tspChecked`
- `timestampChecked`, `timestampValid`, `signerCertificatePresent`, `certificateTimeValid`
- `chainChecked`, `chainValid`, `ltvValid`, `containerCoverageComplete`

**`diagnostics.trustListSync.xmlSignatureStatus`.** Єдиний спосіб для 1С
дізнатися, з якою силою прийнято довірчий список ЦЗО. Поле довго було відсутнє
в цьому документі, хоча є в JSON — тож інтеграції його не читали й не
відрізняли випадок, коли якір довіри тримається лише на TLS.

| Значення | Що означає |
| --- | --- |
| `verified-pinned` | Підпис TL перевірено проти **закріпленого** сертифіката (`pinnedCertBase64`). Найсильніший стан |
| `verified-self-consistent` | Підпис TL узгоджений сам із собою. **Не є доказом походження**: документ підтверджує лише те, що його не змінювали після підписання тим ключем, який у ньому ж і лежить |
| `not-verified-disabled` | Перевірку вимкнено політикою (`signaturePolicy=disabled`) |
| `not-verified-unsupported` | Алгоритм підпису TL не підтримується цією збіркою |
| `not-checked` | `SyncTrustList()` ще не виконувався — початковий стан |
| `failed` | Перевірку виконано, і вона не пройшла |

`diagnostics.trustList` має поля `checked`, `source`, `cacheStatus`, `lastSync`, `updateSucceeded` і описує sync/cache стан TL XML для ЦЬОГО verify-виклику (окремо від `diagnostics.trustListSync`, який відображає стан останнього явного `SyncTrustList()`). Після успішного `SyncTrustList()` локальний `workDir\trust-store` містить матеріалізовані CA/MR-CA anchors із TL XML, а `workDir\policy\trust-store-metadata.json` — metadata CA/TSA-сервісів.

`diagnostics.chainDebug.trace` є технічним текстовим trace для розбору проблем chain validation. Він показує signer subject/issuer/SKI/AKI/serial, кількість і вміст certificates із embedded CMS, `intermediate-store`, AIA, `trust-store` і `historical-trust-store`, URL-и AIA `caIssuers`, завантажені `.p7b`/`.cer`, matched issuer steps, trust-anchor reject reasons і фінальну точку зупинки chain. Поле призначене для логування та діагностики; інтеграційна бізнес-логіка має спиратися на `policy.status`, `trust.trustStatus`, `certificate.chain.valid` і `trust.valid`.

Під час verify chain validation додатково читає проміжні CA-сертифікати з `workDir\intermediate-store`. Якщо ланцюг неповний, але signer або embedded certificate містить AIA `caIssuers` URL, Tamga може завантажити issuer-сертифікат через HTTP(S), кешувати його в `intermediate-store` і повторити chain validation — лише після явного `allowAiaIssuerFetch=true` та в online-режимі. Кожна HTTP(S)-адреса проходить destination policy: локальні, приватні, link-local, metadata й усі інші non-public A/AAAA адреси заборонені; правило повторюється для redirect-ів. У `strict` режимі єдиним джерелом trust anchors є `workDir\trust-store`, матеріалізований із поточного TL-UA. У `compatibility` режимі, якщо поточний `trust-store` не довів ланцюг до anchor, Tamga додатково пробує явно налаштований `workDir\historical-trust-store`. AIA та `intermediate-store` ніколи не стають trust source автоматично.

Historical compatibility призначений для legacy українських КЕП, де issuer/root був довіреним в історичному TL-UA або curated bundle, але вже відсутній у поточному TL-UA. Сертифікат у `historical-trust-store` має бути явно довіреним через архівний TL, curated historical CA bundle, ручне конфігурування або імпортований historical root. Якщо fallback спрацював, report містить `trustMode="historical"`, `historicalTrustUsed=true`, `trustReason="historical-anchor-explicitly-trusted"` і `historicalAnchor.subject/serial`. Якщо strict mode бачить валідний issuer path, який не доходить до current TL anchor, `trustReason` дорівнює `legacy-anchor-not-in-current-tl`.

Пер-категорійний стан перевірки живе у відповідних top-level блоках
(`signature`, `certificate`, `trust`, `revocation`, `timestamp`, `ltv`) —
окремого блоку `categories` немає. Кожен із цих блоків має власні
`status`/`code` (машиночитаний стан складової), а плоскі булеві поля
сумісності — під `diagnostics.flags`.

Авторитетний report-level policy результат міститься в блоці `policy`
(`policy.status`/`policy.code`) і агрегованому `summary`
(`summary.status`/`summary.summaryCode`):

- `policy.status` — статус policy-вердикту (`valid`/`warning`/`invalid`/`skipped`);
- `policy.level` — досягнутий рівень політики (`basic`/`standard`/`extended`/`forensic`);
- `summary.summaryCode` — стабільний machine-readable підсумок причини рішення.

`policy.status` може бути `invalid`/`warning`, навіть якщо `VerifyData` / `VerifyFile` повернули успішний Boolean для криптографічної цілісності, наприклад при невизначеному відкликанні, недоступному OCSP/TSP-сервісі або частково перевіреному RFC 3161 timestamp.

Основні `summary.summaryCode` значення:

- `not-executed`
- `execution-failed`
- `integrity-failed`
- `integrity-only`
- `integrity-without-trust-store`
- `integrity-and-trust`
- `integrity-trust-and-revocation`
- `integrity-trust-revocation-and-timestamp`
- `integrity-but-revoked`
- `integrity-but-certificate-expired`
- `integrity-but-chain-incomplete`
- `integrity-but-untrusted-chain`
- `integrity-but-revocation-check-invalid`
- `integrity-but-revocation-unknown`
- `integrity-but-online-service-unavailable`
- `integrity-but-timestamp-invalid`
- `integrity-but-timestamp-not-fully-validated`
- `content-not-fully-signed` (К-01)

**Свіжість доказів відкликання й міток часу (С-12 / С-19).** Усі часові межі
оцінюються проти `validation_time` — моменту, на який перевіряється підпис, — а
не проти поточного часу. Це навмисно: історична валідація підпису на момент
його створення має працювати з доказами, зібраними тоді ж, інакше LTV втрачає
сенс.

- **Embedded OCSP** (XAdES `RevocationValues`, PAdES `/DSS`) має скінченну межу
  давності відносно `validation_time`. Раніше для вбудованих доказів перевірка
  `producedAt` вимикалася повністю, а `nextUpdate` за RFC 6960 необовʼязковий —
  тож давня легітимно підписана `good`-відповідь приймалася як доказ довільно
  пізніше.
- **Мітка часу з TL direct-match**: збіг сертифіката TSA із записом довірчого
  списку знімає потребу будувати ланцюжок, але **не** знімає перевірку строку
  дії сертифіката на момент самої мітки.

**CRL як доказ (В-02 / С-01).** CRL приймається як доказ «не відкликаний» лише тоді, коли його підпис справді перевірено, тобто доступний сертифікат issuer, і сам CRL перебуває у своєму вікні `[thisUpdate, nextUpdate]` на момент валідації. Інакше `revocationStatus` — `unknown`, а не `good`.

Правило навмисно **асиметричне**: якщо серійний номер УЖЕ є у списку відкликаних, статус `revoked` виставляється навіть за неперевіреного підпису чи простроченого CRL. Ціна двох помилок різна — хибне «відкликано» веде до відмови у прийнятті документа, хибне «не відкликано» — до прийняття відкликаного сертифіката.

Свіжість оцінюється проти `validation_time`, а не поточного часу, тож історична валідація підпису на момент його створення працює зі старим CRL коректно. Відсутній `nextUpdate` (RFC 5280 це дозволяє) означає «без заявленої межі свіжості», а не «протерміновано».

Для signer certificate policy вимагає доведений revocation-статус `good` через OCSP або CRL. Значення `revocationStatus` на кшталт `unknown`, `temporarily-unavailable`, `invalid`, `stale` або `revoked` не дають `policy.status=valid`; `revoked` і `invalid` також фіксуються як `RevocationCheckFailed`. Summary `integrity-but-revocation-check-invalid` означає, що криптографічна цілісність і trust-chain були опрацьовані, але CRL/OCSP-дані некоректні; це відрізняється від `integrity-but-untrusted-chain`, де проблема саме в довірі до ланцюга.

**Покриття документа підписом (`containerCoverageComplete`, К-01).** Поле відповідає на питання, чи покритий підписами ВЕСЬ вміст, а не лише на те, чи цілий сам підпис. Для ASiC-E воно означає, що кожен data-object покритий підписом — `ds:Reference` на шляху XAdES (`VerifyFileAsicEXades`) і `DataObjectReference` з `ASiCManifest` на шляху CAdES (`VerifyFileAsicE`). Для PAdES — що після підписаної ревізії немає непідписаних змін вмісту.

> **Обидва шляхи ASiC-E перевіряють це однаково — з 2026-08-29.** Доти шлях CAdES звіряв кожен підпис із рівно одним об'єктом його маніфесту й ніколи не питав, чи лишилися в контейнері файли, не покриті жодним підписом: `containerCoverageComplete` там не присвоювалося зовсім і лишалося дефолтним `true`. Контейнер із валідно підписаним `document.pdf` і додатковим непідписаним `payload.bin` приймався як валідний, тоді як той самий за змістом контейнер на шляху XAdES коректно відхилявся.

PDF дозволяє інкрементальні оновлення після підписання, і саме так штатно додається `/DSS` у PAdES-LT (у реальних контейнерах Дії це ~14 КБ поза будь-яким `ByteRange`) та DocTimeStamp у LTA. Тому сам факт непокритого «хвоста» не є ознакою підробки. Tamga класифікує його і повертає результат у полі `signature.coverageStatus` (а також дублює в `diagnostics.message`):

| `coverageStatus` | Значення | `containerCoverageComplete` |
| --- | --- | --- |
| `complete` | Підписи покривають файл до останнього байта | `true` |
| `extended-by-unsigned-revisions` | Далі є коректні інкрементальні оновлення (типово `/DSS`), вміст сторінок не змінено | `true` |
| `modified-after-signing` | Вміст сторінок змінено після підписання | `false` |
| `unsigned-data-appended` | «Хвіст» не є коректним оновленням PDF (файл не завершується `%%EOF`) | `false` |
| `coverage-unverifiable` | Класифікувати не вдалося; трактується fail-closed | `false` |
| `container-object-not-signed` | ASiC-E: у контейнері є data-object, не покритий жодним підписом | `false` |
| `not-applicable` | Формат не має поняття контейнера чи ревізій (detached CMS/CAdES, XMLDSIG поза контейнером) | `true` |

**ASiC-S** повертає `complete` за побудовою: контейнер зобовʼязаний містити рівно один підписаний обʼєкт (ETSI TS 102 918 §5.2), і контейнер із двома документами відхиляється ще на розборі. До 2026-08-29 розбір мовчки лишав **останній** документ за порядком у ZIP, тож контейнер із чужим файлом попереду підписаного приймався як валідний.

> **Сторожа проти повторення.** `TestCoverageInvariantIsAppliedOnEveryContainerPath` вимагає, щоб кожен шлях `Session::Verify*`, який робить твердження про контейнер або документ, **явно** оголошував `coverageStatus`. Мовчання лишає дефолт `not-applicable` + `containerCoverageComplete=true` — тобто «покрито все» — і гейт К-01 перетворюється на no-op. Новий шлях перевірки, не внесений до списку в тесті, теж валить сторожу: рішення має бути прийняте явно, а не пропущене за замовчуванням.

Якщо `containerCoverageComplete=false`, `summary` отримує `status="invalid"`, `code="CONTAINER_COVERAGE_INCOMPLETE"` і `summaryCode="content-not-fully-signed"`, а `VerifyPdf`, `VerifyFileAsicEXades` і `VerifyFileAsicE` повертають `false` (раніше ASiC-E повертав `true` попри `containerCoverageComplete=false` — саме той хибнопозитив, від якого застерігає `tests/asic_coverage_tests.cpp`). `tamga-cli` завершується кодом **4** (Signature Invalid), а не 7: змінений документ — це відмова у прийнятті підпису, а не проблема довіри. При цьому `signatureValid` лишається **криптографічною** цілісністю CMS і може бути `true`: сам підпис не пошкоджений — він просто не покриває весь документ.

Порівняння вмісту звіряє підписану ревізію з поточним документом за такими складовими:

| Що звіряється | Навіщо |
| --- | --- |
| Кількість сторінок | додана або вилучена сторінка |
| Геометрія сторінки: `/MediaBox`, `/CropBox`, `/Rotate`, `/UserUnit` | `/CropBox` може приховати підписаний вміст, не торкаючись жодного потоку |
| Декодовані потоки `/Contents` | інструкції малювання |
| **Усе піддерево `/Resources`** (рекурсивно: `/XObject`, `/Font`, `/Pattern`, `/Shading`, `/ExtGState`, потоки й словники всередині) | те, **чим** малюють: `/Contents` містить лише `/Im0 Do`, а саме зображення — окремий обʼєкт |
| Підтип і потік вигляду (`/AP /N`) кожної анотації | видимий шар анотацій |
| Документне `/OCProperties` | перемикання видимості шару приховує вміст, не змінюючи ані `/Contents`, ані `/Resources` |

**Чому `/Resources` тут окремим рядком.** До 2026-08-29 порівняння дивилося лише на `/Contents` і анотації. Інкрементальне оновлення, що перевизначає обʼєкт-зображення зі `/Resources`, лишало обидва побайтово незмінними — і підроблений документ отримував `containerCoverageComplete=true` та звіт, що відрізнявся від звіту оригіналу **лише полем `documentSize`**. Тобто виправлення К-01 закривало один клас інкрементальної підміни з двох. Клас E у `tests/pades_security_tests.cpp` відтворює цю атаку на реальній фікстурі Дії.

**Що лишається поза порівнянням** (названо прямо, а не приховано): повний вміст анотацій поза `/Subtype` і `/AP /N`; `/AcroForm` і значення полів форми (`/V`) при `NeedAppearances`; обхід обмежений глибиною 12 і 64 МіБ на сторінку — досягнення межі фіксується у відбитку маркером, тож не є мовчазним пропуском. Класифікація змін за DocMDP (які саме модифікації дозволив підписант) належить до наступної фази.

**Поведінка `SignFile` при невдалому обов'язковому штампі часу (С-02).** Якщо
формат вимагає мітку часу (`cades-t`, тобто `TimestampMode::Required`), а TSA
недоступна, підписання не відбувається — і файл підпису, що вже існував за
цільовим шляхом, **обнуляється**. Це свідома вимога: після невдалого підписання
поруч не має лишитися файл, який викликач прийме за щойно створений підпис.

Наслідок для інтегратора: якщо попередній підпис цінний, підписуйте у
тимчасовий шлях і переносьте його самі після успіху. Успішний запис виконується
атомарно (тимчасовий файл + rename), тож стану «файл є, але недописаний» не
виникає.

**RFC 3161 timestamp (В-03).** `timestampValid=true` означає, що враховані
токени пройшли всі кроки: imprint і підпис TSA, перевірку часу, довіру до
сертифіката TSA, EKU `id-kp-timeStamping` та відкликання (`TimestampEngine`).
Неповний результат дає `timestamp.timestampStatus="timestamp-partial"`,
`timestampValid=false`, `timestamp.status="warning"` і
`TIMESTAMP_NOT_FULLY_VALIDATED`; доведена відмова — `timestamp-invalid`.
`timestampChecked` і `tspChecked` означають обробку доказу, не успіх усіх
кроків; криптографічний результат конкретної мітки міститься в `cryptoValid`.

Повний вердикт дає **лише** канонічний `ValidationEngine`/`TimestampEngine` — другої реалізації політики довіри до TSA в компоненті немає (ADR-026). Через нього тепер проходять усі формати: CMS/CAdES, XAdES, контейнерний токен ASiC-S/E і, з 2026-08-29, PAdES.

Що саме подається в рушій для PAdES (ПД-01):

| Профіль | Доказ мітки | Як подається |
| --- | --- | --- |
| PAdES-B | мітки немає | `timestampChecked=false`, статус мітки не виставляється |
| PAdES-T | signature timestamp у неприв'язаних атрибутах CMS (`id-aa-signatureTimeStampToken`) | сам детачд CMS із `/Contents` іде в `ValidationContext::cms_der` |
| PAdES-LT | те саме, що T, плюс `/DSS` як пул сертифікатів і revocation-доказів | кожен `cms_der` + `/DSS/Certs`, `/DSS/CRLs`, `/DSS/OCSPs` |
| PAdES-LTA | те саме, що LT, плюс кожна документна мітка (`SubFilter=ETSI.RFC3161`) | токен і його підписані байти йдуть окремим явним входом разом із тим самим пулом DSS |

З ADR-035 обидва входи передають вбудовані сертифікати, CRL та OCSP у
`TimestampEngine`; XAdES `SignatureTimeStamp` отримує відповідні
`CertificateValues`/`RevocationValues`. Сертифікати з документа є лише
кандидатами: вони можуть дати відсутній TSA signer або проміжний CA, але
не стають trust anchors. Вибір TSA signer звіряє `SignerIdentifier` і
підпис токена, а вибір видавця — issuer/subject та підпис X.509. Навіть
TL direct-match не дозволяє вважати несамопідписаний TSA власним видавцем.

Відкликання TSA перевіряється окремо від відкликання підписанта на коректний
`genTime` токена. Хибний календар відхиляється без підстановки поточного
часу. OCSP URL обирається з AIA TSA, інакше — з локально кешованого реєстру
за підтвердженим видавцем; адреса не створює довіри. Online-запити зберігають
загальну offline/SSRF-політику. За м'якої політики невідоме відкликання може
дати `policyAcceptable=true`, але не повний `valid=true` і не довірений час.

Доти для PAdES у рушій передавався **порожній** CMS, тож жодного timestamp evidence він не бачив і статус залишався `timestamp-partial` назавжди — це був дефект передачі доказу, а не межа формату.

`timestamp-partial` означає неповну перевірку — наприклад, не знайдено TSA
сертифіката/видавця, довіреного шляху або підтвердження відкликання. Відсутній
EKU, доведене відкликання, неправильний час чи imprint/підпис дають
`timestamp-invalid`. Для PAdES-LTA повний статус вимагає успіху кожної мітки
кожного основного підпису й кожної документної мітки. Будь-який `invalid`
має пріоритет над `partial`; перша успішна мітка не приховує наступну відмову.

Інтегратор, що читав `timestampValid` як «мітка часу є», має перейти на `timestampChecked`/`tspChecked`.

`GetUserReport()` повертає user-facing JSON для 1С/UI. Він не замінює технічний `GetReport()`: `GetReport()` призначений для машинної діагностики, а `GetUserReport()` — для відображення зрозумілого користувацького результату.

`GetUserReport()` використовує спільні блоки `schemaVersion:"2.2"`
(`summary`/`signature`/`certificate`/`trust`/`revocation`/`timestamp`/`ltv`/`policy`/`diagnostics`),
включно з `timestamp.details[]`. Масив `signatures[]`, `signaturePolicy` та
`dataObjectFormats` лишаються деталями технічного `GetReport()`. Відмінності для UI:

- кожен check-блок додатково несе двомовне поле `message:{"en","uk"}` (локалізований людський опис складової);
- блок `certificate` доповнено даними суб'єкта з метаданих підписанта: `subject`, `issuer`, `serialNumber`, `organization`, `country`.

Якщо verify ще не виконувався, звіт відображає порожній/skipped стан у відповідних блоках (`summary.status="skipped"` тощо), а `diagnostics` лишається джерелом технічного стану для UI.

Мінімальний 1С-потік із trust list і звітом:

```bsl
Компонента.Настроить(Ложь, "C:\Tamga\work");
Компонента.Инициализировать();
Компонента.НастроитьДоверенныйСписок("", 30000, 24);
Компонента.ОбновитьДоверенныйСписок();

Компонента.ПроверитьПодписьФайла(ПутьДаних, ПутьПодписи, "cms-detached", "file");
ОтчетДляЛога = Компонента.ПолучитьОтчет();
ОтчетДляПользователя = Компонента.ПолучитьОтчетПользователя();
```

`ОбновитьДоверенныйСписок()` кешує TL XML і state та автоматично створює/оновлює `.cer` файли для активних CA/MR-CA trust anchors у `workDir\trust-store`. TSA-сервіси з TL XML зберігаються в metadata і не використовуються як CA-якорі для ланцюга підписанта.

Якщо збірку виконано з `TAMGA_ENABLE_VENDOR_CRYPTONITE=OFF`, sign/verify сценарії повертають `NotSupported`, а не mock-результат.

## GetReport() — структура `schemaVersion:"2.2"`

`GetReport()`/`GetLastVerifyReport()` повертають технічний JSON із коренем
`{"schemaVersion":"2.2", ...}`. Авторитетний policy-verdict — блок `policy`
(і `summary`); плоскі булеві поля сумісності перенесені під
`diagnostics.flags`. Ключові поля блоку `policy`:

| Поле | Тип | Опис |
| --- | --- | --- |
| `policy.status` | String | `valid`, `warning`, `invalid`, `skipped` тощо (машиночитаний статус). |
| `policy.code` | String | Деталізований код policy-рішення. |
| `policy.level` | String | Досягнутий рівень перевірки (`basic`, `standard`, `extended`, `forensic`). |
| `policy.warnings` | Array[String] | Коди попереджень (напр. `HISTORICAL_TRUST_USED`, `TIMESTAMP_NOT_FULLY_VALIDATED`). |
| `summary.status`/`summary.code`/`summary.summaryCode` | String | Агрегований підсумок вердикту. |

Повний перелік top-level блоків і полів `diagnostics.flags` — у розділі
«Verify policy» вище. Історична схема з `decision.overallStatus`/`version:5`
більше не емітується.

### Деталі TSA: `timestamp.details[]` і `signatures[].timestamps[]`

Схема `2.2` додає окремий результат кожної переданої канонічному рушію
мітки. Порожній масив не є доказом успіху. Спільні поля запису:

| Поля | Значення |
| --- | --- |
| `signatureIndex`, `kind`, `signedRevisionEnd` | Зв'язок із підписом; `kind` — `signature`, `document` або `container`. У PAdES індекси основних підписів починаються з 1, документні мітки нумеруються після них; `signedRevisionEnd` — кінець їхнього `ByteRange`. Для непридатного/не-PDF зв'язку може бути 0. |
| `status`, `timestampStatus`, `valid` | Детальний стан `valid`/`invalid`/`unavailable`, сумісний `timestamp-*` і повна валідність. `valid=true` лише для `status="valid"`. |
| `policyAcceptable` | Прийнятність за політикою; soft-fail невідомого відкликання не підвищує `valid`. |
| `cryptoValid`, `genTimeValid`, `certificateTimeValid`, `ekuValid`, `trustValid` | Результати кроків: imprint/підпис, календар `genTime`, чинність TSA на цей момент, EKU timestamping і довіра. `false` може означати також крок, до якого перевірка не дійшла; причину пояснює `reasonCode`. |
| `revocationChecked`, `ocspAttempted`, `crlAttempted`, `revocationStatus` | Фактично виконані спроби й результат відкликання саме TSA, незалежні від верхньорівневого `revocation` підписанта. |
| `genTime`, `validationTime` | Час із токена та нормалізований UTC-час перевірки; помилковий `genTime` не замінюється на «зараз». |
| `tsaSubject`, `tsaIssuer`, `tsaSerial`, `tsaFingerprintSha256` | Ідентифікація сертифіката TSA, коли його знайдено. |
| `reasonCode`, `trustSource`, `historicalTrustUsed` | Причина результату та походження довіри, включно з дозволеним історичним джерелом. |
| `because`, `warnings`, `limitations`, `evidenceIds` | Масиви пояснень, попереджень, обмежень та ідентифікаторів використаних доказів; не самі DER-дані. |

Приклади причин: `TIMESTAMP_VALID`, `TIMESTAMP_IMPRINT_MISMATCH`,
`TIMESTAMP_TIME_INVALID`, `TSA_CERTIFICATE_MISSING`, `TSA_ISSUER_MISSING`,
`TSA_EKU_INVALID`, `TSA_UNTRUSTED`, `TSA_REVOKED`,
`TSA_REVOCATION_UNKNOWN`, `TSA_REVOCATION_STALE`, `TSA_REVOCATION_INVALID`.
Це діагностичні причини, не нові значення `ErrorCode`.

`timestamp.details[]` агрегує мітки документа/контейнера;
`signatures[].timestamps[]` містить мітки відповідного підпису. Документні
PAdES-мітки лишаються на верхньому рівні й не приписуються одному signer.
Для XAdES деталізовано `SignatureTimeStamp` кожного підпису; цей масив не
заявляє окремої повної TSA-перевірки `ArchiveTimeStamp` чи `SigAndRefsTimeStamp`.

## GetReport() / GetLastVerifyReport() — `signatures[]` (WP-2, мультипідпис)

`VerifyXml` і `VerifyFileAsicEXades` тепер перевіряють УСІ `ds:Signature` документа/контейнера
(`XadesVerifier::VerifyAll`, включно з кількома `ds:Signature` в одному XML-файлі та кількома
`META-INF/signatures*.xml` в ASiC-E). Технічний звіт (`GetLastVerifyReport()`/`GetReport()`)
додатково містить top-level масив `signatures` — по одному запису на кожен знайдений підпис,
у порядку документа:

- `index` — 1-based позиція підпису;
- `signatureValid` — крипто-цілісність саме цього підпису (XMLDSIG + XAdES-дайджести);
- `certificatePresent` — чи присутній `SigningCertificate`/`X509Certificate` для цього підпису;
- `profile` — детектований XAdES-профіль цього підпису;
- `timestampChecked`, `timestampValid`, `timestampStatus` — стан `SignatureTimeStamp` цього підпису;
- `timestamps[]` (схема `2.2`) — його канонічні результати TSA за схемою вище;
- `ltvValid` — LTV-дійсність цього підпису (структурна, без окремої trust-перевірки для
  кожного співпідписанта);
- `ltvEvidenceBound` (HI-02) — `CertificateValues`/`RevocationValues` цього підпису
  структурно ПРИВ'ЯЗАНІ (digest-binding `CompleteCertificateRefs`/`CompleteRevocationRefs`,
  або сама наявність values для baseline B-LT без Complete*Refs) — БЕЗ підтвердження
  trust-ланцюга/відкликання самого по собі;
- `ltvEvidenceValidated` (HI-01) — докази прив'язані **І** trust-ланцюг САМЕ цього
  підписанта довірений **І** його відкликання підтверджено (`"valid"`/`"good"`) — per-signer
  еквівалент `ltv.evidenceValidated` (HI-02), обчислюваний тепер, коли trust/revocation
  рахуються для КОЖНОГО підписанта окремо;
- `certificate`, `trust`, `revocation` (HI-01) — повна незалежна trust/revocation/
  certificate.timeValid-перевірка САМЕ цього підписанта (окремий X.509 chain + OCSP/CRL
  на кожного співпідписанта, а не лише на один репрезентативний, як було раніше):
  - `certificate.timeValid`, `certificate.validationTimeSource`, `certificate.chain.checked`/`.valid`;
  - `trust.checked`, `trust.valid`, `trust.mode`, `trust.reason`, `trust.trustStatus`,
    `trust.historicalTrustUsed`, `trust.historicalAnchor.subject`/`.serial`;
  - `revocation.checked`, `revocation.ocspChecked`, `revocation.revocationStatus`.

**HI-01 (агрегація верхнього рівня):** верхньорівневі `trustValid`/`chainValid`/
`certificateTimeValid`/`revocationChecked`/`ocspChecked` (і відповідні `trust`/`revocation`/
`certificate` блоки в JSON) тепер — **AND-агрегація по ВСІХ підписантах** (`all_valid` policy,
рішення користувача): кожен співпідписант МАЄ бути trusted/valid, інакше верхньорівневий
вердикт стає `false`, НЕЗАЛЕЖНО від того, чи trusted репрезентативний підпис (обраний за
crypto-цілісністю, як і раніше). Рядкові діагностичні поля (`trustStatus`, `trustReason`,
`revocationStatus`, `chainDebug`, `historicalTrustUsed` тощо) беруться з "найгіршого"
підписанта: перший, чий `trust.valid=false`, інакше перший, чиє відкликання не підтверджено,
інакше перший загалом. До HI-01 ці поля рахувались лише для ОДНОГО репрезентативного
підпису — genuinely dual-signed документ, де один підписант trusted, а інший ні, міг
помилково показати верхньорівневий `trustValid=true`. `signatureValid`/`timestampValid`/
`ltvValid`/`signaturePolicy*` на верхньому рівні лишалися поза скоупом HI-01
(HI-01 стосується саме trust/revocation/certificate.timeValid). З ADR-035
`timestampValid` окремо агрегує результати всіх врахованих міток, а
`ltv.fullyValidated` — також докази всіх представлених підписантів.
Регресія: `TestSessionVerifyXmlPerSignerTrustAggregation` (два РІЗНІ підписанти одного
документа, лише один із них — trust anchor; доводить і per-signer trust-результат, і
AND-агрегацію верхнього рівня).

У PAdES `signatures[]` також містить кожен основний CMS-підпис із його
незалежними certificate/trust/revocation результатами та мітками часу.
ASiC-E CAdES зберігає результати підписів контейнера. Для окремого CMS
`timestamp.details[]` доступний і без непорожнього `signatures[]`.

## GetReport() / GetLastVerifyReport() — `signaturePolicy` / `dataObjectFormats` (WP-12)

`XadesBuilder`/`XadesVerifier` генерують і структурно парсять `SignaturePolicyIdentifier`
(ETSI EN 319 132-1 §5.2.1.3) та `SignedDataObjectProperties/DataObjectFormat*` (§5.2.2) з
`SignedProperties` XAdES-підпису. Технічний звіт (`GetLastVerifyReport()`/`GetReport()`) тепер
проброшує ці дані на двох рівнях, тим самим принципом, що WP-2 застосував до `signatures[]`:

**Top-level** (для репрезентативного підпису — той самий "перший невалідний, або перший
загалом" принцип, що й решта верхньорівневих агрегованих полів):

- `signaturePolicy.present` — чи присутній `SignaturePolicyIdentifier`;
- `signaturePolicy.id` — `SigPolicyId/Identifier`;
- `signaturePolicy.hashAlgorithmUri` — `SigPolicyHash/DigestMethod/@Algorithm`;
- `dataObjectFormats` — масив `{objectReference, mimeType, description}`, по одному запису на
  кожен `DataObjectFormat`.

**Per-signature**, у кожному записі `signatures[]`: `signaturePolicyPresent`, `signaturePolicyId`,
`signaturePolicyHashAlgorithmUri`, `dataObjectFormats` — той самий набір полів, що й top-level,
але для конкретного підпису в документі/контейнері з кількома `ds:Signature`.

**Важливе застереження:** ці поля відображають лише СТРУКТУРНУ наявність і парсинг —
`SigPolicyHash` НЕ звіряється криптографічно проти реального зовнішнього документа політики
підпису (Tamga не має доступу до реєстру політик конкретної CA). Присутність
`signaturePolicy.present=true` не є доказом, що підпис відповідає заявленій політиці — лише що
підписант ЗАЯВИВ про використання цієї політики.

Підтримується у `VerifyXml` та `VerifyFileAsicEXades` (обидва XAdES-шляхи). Для операцій без
XAdES (`SignData`/`VerifyFile`, CMS, PAdES тощо) `signaturePolicy.present=false` і
`dataObjectFormats` — порожній масив.

## GetReport() / GetLastVerifyReport() — `certificate.present` виправлено для XAdES (ME-01)

До цього фіксу `VerifyXml` виставляв верхньорівневий `certificate.present` (і
`signatures[].certificatePresent`) за наявністю `xades:SignedProperties`, а не за
наявністю самого сертифіката (`ds:KeyInfo/ds:X509Certificate`) — два незалежних
структурних факти, які XAdES-підпис може мати в будь-якій комбінації. Підпис зі
`SignedProperties`, але без вбудованого сертифіката, міг звітувати
`certificate.present=true`, хоча trust-валідації для нього нема на чому будувати:
без `ds:X509Certificate` немає ні signer-сертифіката, ні точки входу в ланцюг. `VerifyFileAsicEXades`
(ASiC-E XAdES-шлях) цього дефекту не мав — уже використовував правильний критерій.

`VerifyXml` тепер узгоджено з `VerifyFileAsicEXades`: `certificate.present`/`certificatePresent`
відображають виключно наявність `ds:X509Certificate`. Структурна наявність
`SignedProperties`/`QualifyingProperties` тепер експонується окремим полем:

- top-level `certificate.qualifyingPropertiesPresent`;
- per-signature `signatures[].qualifyingPropertiesPresent`.

Для операцій без XAdES (`SignData`/`VerifyFile`, CMS, PAdES тощо) `qualifyingPropertiesPresent`
завжди `false` — поле не застосовується.

## CLI validation options

Команди `verify` та `verify-file` підтримують такі параметри валідації:

| Параметр | Значення | Опис |
| --- | --- | --- |
| `--validation-profile` | `strict`, `compatibility`, `ukraine-legal`, `offline`, `forensic` | Профіль валідації. Якщо не вказано — використовується `--trust-mode`. |
| `--validation-level` | `basic`, `standard`, `extended`, `forensic` | Глибина доказової перевірки. |
| `--evidence-out` | `<шлях>` | Шлях для збереження доказового пакету (JSON) після перевірки. |
