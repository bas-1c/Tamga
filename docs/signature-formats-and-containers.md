# Формати підпису, ключі та контейнери Tamga

Це прикладна пам'ятка для `tamga-lib`, `Tamga.dll` NativeAPI і `tamga-cli`.

## Джерело ключа

Параметр `sourceType` у `LoadKey()` визначає, як Tamga трактує перший параметр методу.

| Значення | Що означає |
| --- | --- |
| `auto` | Автовизначення типу за вмістом або шляхом. Рекомендований варіант за замовчуванням. |
| `file` | Перший параметр є шляхом до файла ключа. |
| `binary` | Перший параметр є двійковими даними ключового контейнера. |
| `jks` | Java KeyStore (SunJKS key protector). |
| `pkcs12` | PKCS#12 контейнер (`*.pfx`, `*.p12`, `*.dat`, `*.ZS2`). |
| `p12` | Alias для PKCS#12. |
| `pfx` | Alias для PKCS#12. |
| `pem` | PEM-файл із ключем/сертифікатом. |
| `der` | DER-файл із ключем/сертифікатом. |
| `descriptor` | Текстовий descriptor для сумісності з внутрішнім library-шаром. |

Практично очікувані розширення: `*.jks`, `*.p12`, `*.pfx`, `*.dat`, `*.ZS2`,
`*.pem`, `*.der`.

Детальний розбір контейнерів ключа (`.jks`, `.dat`, `.pfx`, `.ZS2`), перелік
підтримуваних алгоритмів захисту і каскад пошуку сертифіката до ключа —
в окремому документі [key-containers.md](key-containers.md).

Розширення не визначає формат: тип контейнера розпізнається за вмістом
(`NormalizeKeyContainer`, `SessionStateAndNormalization.ipp`). Файловий ключ КЕП
від українських КНЕДП (`Key-6.dat`, рідше `*.pfx`) — це PKCS#12, «голий»
PKCS#8 DER або власний контейнер ІІТ (AID `1.3.6.1.4.1.19398.1.1.1.2`); перші
два йдуть штатними гілками PKCS#12/PKCS#8, третій розшифровується власною
гілкою ІІТ і далі теж перетворюється на PKCS#8. Формати
поза таблицею (JCEKS, BKS, власний контейнер `*.pkf`) не підтримуються:
нормалізація відхиляє їх із `Unsupported key format`.

Для JKS підтримується **лише** стандартний SunJKS key protector
(OID `1.3.6.1.4.1.42.2.17.1.1`) — саме він використовується в контейнерах
ПриватБанку. Інший алгоритм захисту entry відхиляється з
`JKS private key entry uses unsupported protection algorithm`. Сертифікат
підписувача береться з ланцюга самого JKS: обирається той, що математично
відповідає закритому ключу (звірка `SubjectPublicKeyInfo`), а не перший у списку.

Контейнери без `certBag` — типовий випадок для `.dat` — завантажуються, але
сертифікат до них добирає авто-резолвер: явний шлях/base64 → sidecar поруч із
ключем (`Key-6.dat` → `Key-6.cer`) → кеш → LDAP-каталог КНЕДП (`ConfigureLdap`)
або CMP. Кандидат приймається fail-closed, тільки при збігу з відкритим ключем
контейнера. Якщо сертифікат не знайдено, `LoadKey` усе одно успішний (частина
операцій, як-от `SignHash`, сертифіката не потребує), але CMS-підпис потім
відмовляє з повідомленням: «Не знайдено відкритий сертифікат для закритого
ключа. Покладіть файл сертифіката (.cer/.crt) поруч із ключем або передайте
через параметр certificatePath».

## Файли підпису

| Розширення | Призначення |
| --- | --- |
| `.p7s` | Типовий файл CMS/CAdES-підпису. |
| `.sig` | Прикладне розширення для файла підпису; вміст зазвичай той самий CMS/CAdES. |
| `.xml` | XMLDSIG/XAdES документ або detached XML-підпис у контейнері. |
| `.pdf` | PDF-документ із вбудованим PAdES-підписом. |
| `.asics` | ASiC-S контейнер. |
| `.asice` | ASiC-E контейнер. |

Для detached-підпису потрібні два об'єкти: оригінальний документ і файл підпису `.p7s` або `.sig`.

## Матриця форматів Дії та Tamga

Матрицю складено 2026-09-03 за трьома знімками інтерфейсу Дії/ІІТ у
`tmp/test`. Вони не є нормативною специфікацією і мають розбіжності: один
перелік не показує XAdES-enveloping та міжнародні алгоритми, інший їх показує;
в одному місці для ASiC-E наведено розширення `.asics`. Нижче використано
перетин цих відомостей, фактичний публічний API Tamga та валідні еталони з
`tmp/еталон`.

Стан засвідчено 2026-09-03 командами
`rg -n "SignXml|SignPdf|SignFileAsic|XadesProfile|PadesProfile" src tests` →
публічні шляхи й профільні тести знайдено; `tamga-tests.exe` у shipping x64 →
`all checks passed` (54 CTest-сценарії перевіряються окремим релізним гейтом).

| Сімейство | Що вже створює і перевіряє Tamga | Що доцільно доробити | Що зараз не заявляється |
| --- | --- | --- | --- |
| CAdES/CMS | Detached CAdES-BES і CAdES-T; attached CMS; криптографічна перевірка всіх цих варіантів | CAdES-C та X Long із повною моделлю evidence і профільними interop-фікстурами; окремий явний attached+CAdES профіль | Генерація CAdES-C/X Long і profile-policy валідація їхніх доказів |
| XAdES | Enveloped XMLDSIG/XAdES-BES і XAdES-T; detached XAdES-B-B/B-T усередині ASiC-S/E; перевірка enveloping-фікстур та розширених XAdES evidence | Публічне створення standalone detached/enveloping; XAdES-B-LT/B-LTA з однозначним збиранням OCSP/CRL/TSA evidence | Публічний `SignXml` для B-LT/B-LTA та самостійного detached/enveloping |
| PAdES | B-B, B-T, B-LT, B-LTA через CLI, core і NativeAPI; incremental update, `/DSS`, `DocTimeStamp`, перевірка кількох ревізій | Повторна зовнішня перевірка нових файлів після виправлення `SubFilter`; доповнення OCSP evidence там, де його вимагає конкретний профіль | Окремий detached/enveloping режим: для PAdES підпис за визначенням вбудований у PDF |
| ASiC-S | Один payload із XAdES B-B/B-T (`asic-s`) або CAdES-BES/T (`asic-s-cades`), створення й перевірка | Явний вибір рівня, co-signature, LT/LTA після готовності внутрішнього XAdES/CAdES профілю | Кілька документів у публічному sign API; одночасні `signature.p7s` і `timestamp.tst` |
| ASiC-E | Один payload із XAdES B-B/B-T (`asic-e`) або CAdES-BES/T (`asic-e-cades`), створення й перевірка; verifier читає багатодокументні еталони | Публічний multi-file/co-sign API та LT/LTA/C/X Long після готовності внутрішнього профілю | Ненумерована CAdES-пара як новий вихід: генератор використовує `ASiCManifest001.xml` + `signature001.p7s` |

### Алгоритми

| Алгоритм у віджеті | Стан Tamga | Рішення |
| --- | --- | --- |
| ДСТУ 4145 + ДСТУ 7564 (Купина-256) | Наскрізне створення/перевірка CMS, PAdES та ASiC-XAdES; це явний профіль нових ASiC-XAdES | Підтримувати як основний сучасний український профіль |
| ДСТУ 4145 + ГОСТ 34.311 | Створення/перевірка CMS і standalone XMLDSIG/XAdES; verifier приймає точні ГОСТ URI | Додати публічний селектор алгоритму замість висновку з `signatureAlgorithm` сертифіката, якщо потрібен керований вибір у всіх форматах |
| RSA + SHA-2 | XMLDSIG/XAdES verification для RSA-SHA256/384/512 реалізовано; production signing route з RSA-ключем не експоновано | Реалізація доцільна для міжнародної сумісності. Гіпотеза: для неї знадобляться окремий key/signing adapter та наскрізні фікстури; не перевірено |
| ECDSA + SHA-2 | URI є в реєстрі, але наскрізний production sign/verify route не засвідчено | Вважати нереалізованим до появи backend, key-loading і позитивних/негативних interop-тестів |
| SHA-224, Купина-384/512 | Немає повного XML registry і публічного вибору | Не додавати лише за фактом наявності в загальному списку віджета. Гіпотеза: доцільність можна оцінити за реальним ключем, точними OID/URI та профільним тестом; не перевірено |

Алгоритм нового підпису не можна визначати з зовнішнього
`certificate.signatureAlgorithm`: це алгоритм, яким ЦСК підписав сертифікат.
Tamga має виконувати саме `SignatureMethod`/`DigestMethod`, оголошені у
підписі, а генератор — обирати явний профіль. Тому непомітна підміна ГОСТ на
Купину через сертифікат не є допустимою реалізацією.

Окремі селектори detached/enveloped для ASiC не потрібні: зв'язок даних із
підписом визначає внутрішня розкладка контейнера. Для CAdES терміни
«attached» і «enveloped» описують той самий CMS `eContent`; окреме
«enveloping» не утворює третього бінарного формату. Timestamp-only ASiC-S є
іншим профілем, але не повинен змішуватися з CAdES-T в одному контейнері.

## Формати CMS/CAdES

Параметр `signatureFormat` у `SignData()`, `VerifyData()`, `SignFile()` і `VerifyFile()`:

| Формат | Що створюється | TSP-поведінка |
| --- | --- | --- |
| `cms-detached` | Detached CMS: підпис окремо від даних. | Best-effort для позначки часу у сценаріях, де це доступно. |
| `cms-attached` | Attached CMS: дані вбудовані в CMS-контейнер. | Best-effort для позначки часу у сценаріях, де це доступно. |
| `cades-bes` | Базовий CAdES/CMS-підпис. | TSP навмисно не є обов'язковим. |
| `cades-t` | CAdES-BES + RFC 3161 timestamp token. | TSP обов'язковий під час підписання; verify path проганяє вбудований токен крізь `TimestampEngine` (imprint + підпис TSA + ланцюг + EKU, WP-6). |

`CAdES-BES` містить підписувача, сертифікат і signed attributes, але не гарантує кваліфіковану позначку часу від TSA.

`CAdES-T` додає unsigned attribute `id-aa-signatureTimeStampToken`. Для сервісів, які вимагають підпис із позначкою часу, використовуйте `cades-t`.

Поточний verify baseline для CAdES-T:

- витягує `id-aa-signatureTimeStampToken` із CMS;
- декодує RFC 3161 `TSTInfo`;
- обчислює Kupyna-256 від CMS signature value;
- звіряє message imprint із `TSTInfo.messageImprint.hashedMessage`.

Якщо imprint не збігається або timestamp token структурно невалідний, report показує `trustStatus=timestamp-invalid`, `timestampValid=false`, а `ErrorCode` може бути `TimestampValidationFailed`.

Якщо imprint збігається, вбудований токен додатково проходить повну TSA-валідацію через `TimestampEngine` (перевірка підпису TSA, побудова й довіра до ланцюга TSA-сертифіката проти `tsa-store`/TL, перевірка EKU `id-kp-timeStamping`, WP-6). `timestampValid=true` виставляється лише коли токен проходить усі ці кроки; інакше — `timestamp.timestampStatus=timestamp-partial`/`timestamp-invalid` і policy-попередження `TIMESTAMP_NOT_FULLY_VALIDATED`. **S-001 знято (Хвиля 8, п.3).** Окремий *контейнерний* RFC 3161-токен ASiC-S/ASiC-E (`META-INF`, не вбудований у CMS) теж іде через канонічний `TimestampEngine` — `SessionAsicOps.ipp:593` передає його в `TryCanonicalTimestampVerdict`, тобто з побудовою й довірою до ланцюга TSA, перевіркою EKU і відкликання. Раніше цей шлях справді обмежувався криптографічною перевіркою; застереження лишалося в документі довше за сам дефект.

## ASiC-контейнери

ASiC — це ZIP-контейнер для документа, підпису і службових файлів. `.p7s` є самим CMS/CAdES-підписом, а `.asics` / `.asice` є обгорткою.

| Формат | Розширення | Призначення |
| --- | --- | --- |
| `asic-s` | `.asics` | Один документ і XAdES detached-підпис. |
| `asic-e` | `.asice` | ODF-маніфест і XAdES detached-підпис. |
| `asic-s-cades` | `.asics` | Один документ і CAdES detached-підпис. |
| `asic-e-cades` | `.asice` | Розширений контейнер з ASiC-маніфестом і CAdES-підписом маніфесту. |
| `asic-e-xades` | `.asice` | Явний alias перевірки ASiC-E з XAdES; генерація виконується через `asic-e`. |

ASiC зручний, коли треба передати один файл-контейнер замість пари `документ + .p7s`.

### Розкладка контейнерів (виправлено 2026-09-03)

| Формат | Файл підпису | Маніфест | Що покриває підпис |
| --- | --- | --- | --- |
| `asic-s` | `META-INF/signatures.xml` | немає | файл через зовнішній `ds:Reference` |
| `asic-e` | `META-INF/signatures001.xml` | `META-INF/manifest.xml` (OASIS ODF) | файл через зовнішній `ds:Reference` |
| `asic-s-cades` | `META-INF/signature.p7s` | немає | сам файл |
| `asic-e-cades` | `META-INF/signature001.p7s` | `META-INF/ASiCManifest001.xml` | **маніфест**, а файл прив'язаний до нього дайджестом Купини-256 |

Маніфест CAdES-варіанта ASiC-E будується за `en_31916201v010101.xsd`: `SigReference` —
порожній елемент, `DataObjectReference` — його СУСІД, і кожен несе обов'язкові
`ds:DigestMethod` та `ds:DigestValue`.

До 2026-09-03 обидва формати були нестандартні: ASiC-S писав
`META-INF/signatures.p7s` (множина — це назва для XAdES), а ASiC-E вкладав
`DataObjectReference` усередину `SigReference`, не писав жодного дайджесту й
підписував документ напряму замість маніфесту. Власний верифікатор Tamga це
приймав, тож дефект не проявлявся, поки контейнер не потрапляв до стороннього
валідатора: сервіс Дії відхиляв такий файл із «помилка при розборі чи формуванні
даних».

Контейнери, створені до цієї дати, лишаються читабельними: якщо в маніфесті
немає дайджестів, перевірка повертається до старої семантики (підпис над
даними). Але третіми сторонами вони не приймаються — такі документи треба
перепідписати.

## Практичний вибір

| Потреба | Рекомендований режим |
| --- | --- |
| Звичайний окремий підпис до файла | `cms-detached` + `.p7s` |
| Підпис із обов'язковою позначкою часу | `cades-t` |
| Базовий підпис без online-вимоги до TSA | `cades-bes` |
| Один файл, який містить документ і підпис | `asic-s`/`asic-e` для XAdES або явні `asic-s-cades`/`asic-e-cades` |
| Attached CMS з вбудованими даними | `cms-attached` |
| XML-документ із XMLDSIG/XAdES | `xades` або `VerifyXml()` |
| PDF із вбудованим PAdES-підписом | `pades-b`/`pades-t`/`pades-lt`/`pades-lta` або `VerifyPdf()` |
| ASiC-E, де `META-INF/signatures*.xml` посилається на PDF/інший entry | `asic-e` для створення, `asic-e` або `asic-e-xades` для перевірки |

## Verify policy

Поточний `VerifyData()` / `VerifyFile()` перевіряє криптографічну цілісність підпису і доступні embedded chain/time ознаки. Додатково local policy baseline використовує локальний `workDir\trust-store`, chain validation і hybrid CRL/OCSP revocation policy. `trust sync` кешує TL XML, стан синхронізації та матеріалізує активні CA/MR-CA trust anchors у `workDir\trust-store`.

Boolean результат `VerifyData()` / `VerifyFile()` не є повним policy verdict. Для policy-рішення використовуйте (звіт `schemaVersion:"2.0"`):

- `GetReport().policy.status` — машиночитаний policy-вердикт;
- `GetReport().policy.level` — досягнутий рівень перевірки;
- `GetReport().summary.status` / `GetReport().summary.summaryCode`;
- `GetUserReport().verificationResult.valid`.

Повна production policy для CAdES-T ще потребує додаткової interop-матриці, pinned trust-list bootstrap і XML signature verification довірчого списку.


### ASiC-E з XAdES detached signature

Для контейнерів виду `rahunok2.pdf.asice`, де ZIP містить `mimetype`, документальний entry `rahunok2.pdf`, `META-INF/manifest.xml` і `META-INF/signatures001.xml`, Tamga використовує окремий формат `asic-e-xades`. Це не PAdES, бо підпис не вбудовано у PDF, і не CMS `.p7s`, бо підпис є XMLDSIG/XAdES.

Під час перевірки core читає ZIP, знаходить `META-INF/signatures*.xml`, витягує `ds:Reference URI`, дозволяє тільки безпечні відносні entry name всередині контейнера, підставляє байти відповідного entry у XMLDSIG/XAdES resolver і відхиляє `file://`, `http://`, абсолютні шляхи та traversal `../`. Після криптографічної перевірки сертифікат із `KeyInfo/X509Certificate` проходить наявний trust/revocation policy path, а звіт фіксує `operation="VerifyFileAsicEXades"`, `signatureFormat="XAdES"`, `containerType="ASiC-E"`.

### Статус PAdES

`PadesVerifier` розбирає PDF через об'єктний граф qpdf, локалізує всі словники
`/Type /Sig`, перевіряє кожен `ByteRange` і відрізняє основні підписи від
`/Type /DocTimeStamp`. Для PAdES-LT/LTA він також читає `/DSS` і передає
сертифікати, CRL та OCSP до LTV-перевірки. Результат `VerifyPdf` підтверджує
криптографічну цілісність; повний trust/revocation verdict залишається в
`GetReport()` і не ототожнюється з Boolean API.

`PadesBuilder::SignPdf` приймає **вже сформований незашифрований PDF**, відхиляє
не-PDF і додає підпис як incremental update. Початкові байти та всі попередні
ревізії зберігаються без змін, тому послідовне підписання підтримує кілька
підписів і не знищує наявні AcroForm-поля. Профілі B/T/LT/LTA формують відповідні
CMS/DocTimeStamp та `/DSS`-докази; NativeAPI `SignPdf` приймає необов'язковий
профіль `b`/`t`/`lt`/`lta`, типово `b`. Основний словник підпису має
`/SubFilter /ETSI.CAdES.detached`, а документна мітка LTA —
`/SubFilter /ETSI.RFC3161`.

## Build-залежності XML/PDF форматів

| Сценарій | CMake-прапор | Залежність |
| --- | --- | --- |
| XMLDSIG/XAdES, `VerifyXml()`, `VerifyFile(..., "xades")`, `VerifyFileAsicEXades()` | `TAMGA_ENABLE_XML_SIGNATURES=ON` | — (`libxml2` потрібен завжди, ADR-030) |
| PAdES, `VerifyPdf()`, `VerifyFile(..., "pades")` | `TAMGA_ENABLE_PDF_SIGNATURES=ON` | `qpdf` |

`xmlsec1` тут більше не значиться: власний рушій XMLDSIG (ADR-014) залежить
лише від `libxml2`, а `xmlsec` лишився окремою вимкненою фічею
`xmlsec-crosscheck` для діагностичної перехресної перевірки.

Windows release workflow ставить ці залежності через vcpkg. Runtime-DLL у
release ZIP **не пакуються**: збірка постачання статична, і `Tamga.dll`
залежить лише від системних бібліотек. Якщо відповідний прапор вимкнено,
форматний метод повертає `NotSupported`.
