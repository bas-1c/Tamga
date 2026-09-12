# Інструкція з використання tamga-cli

`tamga-cli.exe` — консольна утиліта Tamga для автоматизації та сценаріїв без 1С. Вона лінкує core-код статично і не потребує `tamga-lib.dll` поруч для запуску.

CLI підтримує повний набір операцій: завантаження ключів (PKCS#8, PKCS#12, JKS, PEM/DER), формати підписів (CMS, CAdES, XAdES, PAdES, ASiC-S/E), синхронізацію довірчого списку ЦЗО (`trust sync`), валідацію, генерацію звітів (`technical-json` та `pretty-json`) та детерміновану таблицю exit-кодів (0..7).

## Розташування

Після локальної збірки через release-скрипт:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build-windows.ps1 -Arch all -Config Release
```

готові CLI-файли лежать у:

```text
release/tamga-cli_x64.exe
release/tamga-cli_x86.exe
```

Після звичайної CMake-збірки CLI лежить у build-каталозі:

```text
build-msvc/src/cli/Release/tamga-cli.exe
```

## Загальний синтаксис

```text
tamga-cli <command> [--config file] [--key value]
```

Аргументи здебільшого задаються парами `--ключ значення`. Виняток: глобальні `--help` / `help` і `--help` для `trust` та `verify` обробляються до читання `--config`, створення сесії або мережевих дій.

## Config-файл

`--config file` читає простий текстовий файл у форматі `key=value`.

```ini
# tamga.conf
offline=true
work-dir=C:\Tamga\work
input=C:\Tamga\data\document.pdf
output=C:\Tamga\data\document.pdf.sig
key=C:\Tamga\keys\Key-6.dat
password=SecretPass123
format=pades
```

Правила:

- порожні рядки і рядки з `#` на початку ігноруються;
- пробіли навколо ключа і значення обрізаються;
- якщо ключ задано і в CLI, і в config-файлі, значення з CLI має пріоритет;
- помилка читання або некоректний рядок без `=` завершує команду з помилкою.

## Глобальні налаштування сесії

Ці ключі використовуються командами, які створюють `Session`.

| Ключ | Значення | За замовчуванням | Опис |
| --- | --- | --- | --- |
| `--config` | шлях | немає | Файл налаштувань `key=value`. |
| `--offline` | `true` або `false` | `true` | Режим без онлайн-сервісів. Тільки точне `false` вмикає online mode. |
| `--work-dir` | шлях до каталогу | порожньо | Робочий каталог сесії. |
| `--trust-mode` | `strict` або `compatibility` | `strict` | Режим перевірки довіри. |
| `--validation-profile` | `strict`, `compatibility`, `ukraine-legal`, `offline`, `forensic` | `strict` | Профіль перевірки (перекриває `trust-mode`). |
| `--validation-level` | `basic`, `standard`, `extended`, `forensic` | `standard` | Глибина верифікації політики. |

## Опції завантаження ключів (для `sign-file`)

| Ключ | Опис |
| --- | --- |
| `--key` (або `--key-path`) | Шлях до файлу контейнера ключа (`.jks`, `.p12`, `.pfx`, `.dat`, `.ZS2`, `.pem`, `.der`). |
| `--password` (або `--pass`) | Пароль до сховища / контейнера ключа. |
| `--key-password` | Пароль до конкретного ключа (якщо відрізняється від пароля сховища). |
| `--alias` | Аліас ключа у сховищі (для JKS або PKCS#12). |
| `--cert` (або `--cert-path`) | Шлях до відповідного файлу відкритого сертифіката X.509 (`.cer`, `.crt`, `.der`, `.pem`). |
| `--ca` (або `--provider`) | Підказка КНЕДП для автоматичного резолвера сертифіката. |
| `--edrpou` / `--drfo` / `--subject` | Ідентифікатор суб'єкта для LDAP-пошуку сертифіката в КНЕДП. |

## Підтримувані формати підпису (`--format` / `--signature-format`)

| Формат | Призначення для `sign-file` | Призначення для `verify-file` / `verify` |
| --- | --- | --- |
| `cms-detached` (або `cms`) | Detached CMS підпис (за замовчуванням). | Перевірка detached CMS підпису (вимагає `--input` та `--signature`). |
| `cms-attached` | Attached CMS підпис (дані всередині підпису). | Перевірка attached CMS підпису (достатньо `--input`). |
| `cades-bes` | CAdES-BES підпис. | Перевірка CAdES-BES. |
| `cades-t` | CAdES-T підпис із обов'язковим RFC 3161 штампом часу. | Перевірка CAdES-T. |
| `xades` (або `xades-bes`) | XMLDSIG / XAdES-BES enveloped підпис XML-документа; довільний PDF цим форматом не підписується. | Перевірка підписаного XML-документа. |
| `xades-t` | XAdES-T підпис XML-документа зі штампом часу; для PDF використовуйте ASiC із XAdES. | Перевірка XAdES-T. |
| `pades` (або `pades-b`) | PAdES-B підпис PDF-документа. | Перевірка підписаного PDF-документа. |
| `pades-t` | PAdES-T зі штампом часу RFC 3161; потрібні TSA й онлайн-режим. | Перевірка PAdES із фактичним визначенням профілю. |
| `pades-lt` | PAdES-LT зі штампом часу та матеріалом валідації в `/DSS`; потрібні ланцюг сертифікатів і CRL. | Перевірка PAdES із фактичним визначенням профілю. |
| `pades-lta` | PAdES-LTA з `/DSS` та `DocTimeStamp`; потрібні ті самі матеріали, що для LT. | Перевірка PAdES із фактичним визначенням профілю. |
| `asic-s` | Створення ASiC-S із XAdES у `META-INF/signatures.xml`. | Автовизначення і перевірка XAdES або CAdES у ASiC-S. |
| `asic-e` | Створення ASiC-E із ODF `manifest.xml` та XAdES у `META-INF/signatures001.xml`. | Автовизначення і перевірка XAdES або CAdES у ASiC-E. |
| `asic-s-cades` | Створення ASiC-S із CAdES у `META-INF/signature.p7s`. | Явна перевірка CAdES у ASiC-S. |
| `asic-e-cades` | Створення ASiC-E із CAdES у `META-INF/signature001.p7s` та `ASiCManifest001.xml`. | Явна перевірка CAdES у ASiC-E. |
| `asic-e-xades` | — | Явна перевірка ASiC-E із XAdES. |

## Команди

### `help`

Показує повну довідку по командах та кодах завершення.

```powershell
release\tamga-cli_x64.exe help
```

Exit code: `0`.

### `media`

Показує JSON capability report для підтримуваних носіїв/форматів ключів.

```powershell
release\tamga-cli_x64.exe media
```

Exit code: `0` — успіх; `1` — помилка сесії.

### `trust sync`

Синхронізує online trust list ЦЗО в локальний кеш `work-dir` і друкує технічний JSON-звіт `GetReport()` / `GetLastVerifyReport()` у stdout.

```powershell
release\tamga-cli_x64.exe trust sync --work-dir C:\Tamga\work
release\tamga-cli_x64.exe trust sync `
  --work-dir C:\Tamga\work `
  --url https://czo.gov.ua/download/tl/TL-UA-EC.xml `
  --timeout-ms 30000 `
  --ttl-hours 24
```

Exit code:
- `0` — успішно синхронізовано;
- `1` — некоректні аргументи або помилка синтаксису;
- `3` — мережева помилка (онлайн-сервіс недоступний).

### `base64-encode` / `base64-decode`

Кодує або декодує файли у формат Base64.

```powershell
release\tamga-cli_x64.exe base64-encode --input data.bin --output data.b64
release\tamga-cli_x64.exe base64-decode --input data.b64 --output data.bin
```

Exit code: `0` — успіх; `1` — помилка читання/запису або невалідний Base64.

### `sign-file`

Підписує файл у вказаному форматі з використанням наданого закритого ключа.

```powershell
# Detached CMS підпис (типово)
release\tamga-cli_x64.exe sign-file `
  --input C:\Tamga\document.pdf `
  --output C:\Tamga\document.pdf.p7s `
  --key C:\Tamga\keys\Key-6.dat `
  --password SecretPassword

# PAdES підпис PDF
release\tamga-cli_x64.exe sign-file `
  --input C:\Tamga\document.pdf `
  --output C:\Tamga\document_signed.pdf `
  --format pades `
  --key C:\Tamga\keys\key.p12 `
  --password SecretPassword

# XAdES підпис XML
release\tamga-cli_x64.exe sign-file `
  --input C:\Tamga\invoice.xml `
  --output C:\Tamga\invoice_signed.xml `
  --format xades `
  --key C:\Tamga\keys\key.jks `
  --password SecretPassword `
  --alias mykey

# ASiC-S контейнер із XAdES
release\tamga-cli_x64.exe sign-file `
  --input C:\Tamga\document.pdf `
  --output C:\Tamga\document.asics `
  --format asic-s `
  --key C:\Tamga\keys\key.p12 `
  --password SecretPassword

# ASiC-E контейнер із CAdES
release\tamga-cli_x64.exe sign-file `
  --input C:\Tamga\document.pdf `
  --output C:\Tamga\document.asice `
  --format asic-e-cades `
  --key C:\Tamga\keys\key.p12 `
  --password SecretPassword
```

Exit code:
- `0` — підпис успішно створено;
- `1` — некоректні аргументи / помилка I/O;
- `2` — помилка ключа або сертифіката (ключ/сертифікат не знайдено, невірний пароль);
- `3` — мережева помилка (якщо потрібен TSP/OCSP).

### `verify-file` / `verify`

Перевіряє підпис файлу у вказаному форматі. Підтримує виведення `valid`/`invalid`, технічного звіту (`--report technical-json`) або користувацького звіту (`--report pretty-json`), а також збереження доказів (`--evidence-out`).

```powershell
# Перевірка detached CMS
release\tamga-cli_x64.exe verify `
  --input C:\Tamga\document.pdf `
  --signature C:\Tamga\document.pdf.p7s `
  --work-dir C:\Tamga\work `
  --offline false `
  --report pretty-json

# Перевірка PAdES PDF
release\tamga-cli_x64.exe verify `
  --input C:\Tamga\document_signed.pdf `
  --format pades `
  --report pretty-json

# Перевірка XAdES XML
release\tamga-cli_x64.exe verify `
  --input C:\Tamga\invoice_signed.xml `
  --format xades `
  --report technical-json

# Перевірка ASiC-E XAdES
release\tamga-cli_x64.exe verify `
  --input C:\Tamga\package.asice `
  --format asic-e-xades `
  --report technical-json
```

#### `--evidence-out`: запитаний артефакт, а не побічний ефект (Q-07)

`--evidence-out <шлях>` зберігає технічний звіт (той самий JSON, що й
`--report technical-json`) у файл. Правила:

- звіт зберігається і для **невдалої** перевірки — саме він найцінніший для
  розбору. Раніше блок збереження стояв після раннього виходу, тож у файл
  такий звіт не потрапляв узагалі;
- якщо файл записати **не вдалося** (непридатний батьківський шлях, права,
  диск) або сесія не віддала звіт, CLI завершується кодом **`1`** (`IOError`)
  **незалежно від вердикту перевірки**, а причину друкує у `stderr`. Раніше
  невдача запису лише друкувалася, а код повернення визначала валідність
  підпису — тож для валідного документа можливий був `exit 0` **без**
  запитаного файла;
- за успішного запису код виходу визначається вердиктом перевірки, як і досі;
- сам запис атомарний (див. «Семантика запису вихідних файлів» у
  [component-methods.md](component-methods.md)): обірваний на півслові
  доказовий файл гірший за його відсутність.

Нових значень exit-кодів це не вводить: `1` уже позначено як `IOError`.

## Пароль ключа (В-07)

Пароль до контейнера КЕП **не слід передавати через argv**: у такому вигляді він
видимий у списку процесів, в історії оболонки та в логах CI.

| Спосіб | Стан |
| --- | --- |
| `--password-file <path>` / `--key-password-file <path>` | **Рекомендовано.** Пароль читається з файлу; хвостові пробільні символи обрізаються, тож звичайний перенос рядка від редактора не заважає |
| `--password <pass>` / `--key-password <pass>` | **Deprecated.** Лишається для зворотної сумісності, але видимий у списку процесів |
| Пароль у `--config` файлі | Той самий ризик, що й файл пароля, плюс ширша область дії — тримайте права доступу до файлу вузькими |

Одночасне задання `--password` і `--password-file` відхиляється явною помилкою:
мовчазний вибір одного з них міг би призвести до підписання не тим ключем.

Той самий канал доступний у `tamga-tsp-diag` і `tamga-interop-diag`.

## Стандартизовані коди завершення (Exit Codes)

| Код | Символічна назва | Опис |
| :---: | :--- | :--- |
| **`0`** | `Success` | Операція виконана успішно; підпис повністю валідний. |
| **`1`** | `InvalidArgument / SyntaxError / IOError` | Помилка параметрів командного рядка, синтаксису або читання/запису файлів. Сюди ж належить невдача запису запитаного `--evidence-out` — вона перекриває вердикт перевірки (Q-07). |
| **`2`** | `KeyError` | Помилка закритого ключа або потрібного сертифіката (ключ/сертифікат відсутній, невірний пароль, помилка структури контейнера). |
| **`3`** | `NetworkError` | Мережева помилка (онлайн-сервіс ЦЗО/КНЕДП недоступний, таймаут запиту). |
| **`4`** | `SignatureInvalid` | Підпис не приймається: або порушено криптографічну цілісність, або підпис не покриває весь документ (`containerCoverageComplete=false` — див. `coverageStatus` у [component-methods.md](component-methods.md)). |
| **`5`** | `CertificateExpired` | Сертифікат підписувача прострочений або ще не набув чинності на момент підпису. |
| **`6`** | `CertificateRevoked` | Сертифікат підписувача відкликано за даними OCSP або CRL. |
| **`7`** | `PolicyInvalid / VerificationFailure` | Помилка перевірки ланцюжка довіри до кореневого ЦЗО, штампа часу або вимог політики. |

### Звідки береться код виходу перевірки

Значення кодів не змінювалися. Змінилося джерело: код виходу обчислюється з
**названих полів** технічного звіту (`--report technical-json`), а не з пошуку
підрядків у його тексті.

| Код | Поле звіту, що його визначає |
| :---: | :--- |
| **`4`** | `diagnostics.flags.signatureValid = false` або `diagnostics.flags.containerCoverageComplete = false` |
| **`5`** | `diagnostics.flags.certificateTimeValid = false` |
| **`6`** | `revocation.revocationStatus = "revoked"` (а також `ErrorCode = RevocationCheckFailed`) |
| **`7`** | решта невдалих перевірок |

Коди `2` і `3` визначаються кодом помилки сесії (`KeyNotLoaded`,
`OnlineServiceUnavailable`) і мають пріоритет над полями звіту.

Практичне значення для сценаріїв: збіг у сторонній секції звіту (наприклад
у per-signature масиві `signatures[]`) більше не впливає на код виходу —
враховуються лише поля за наведеними шляхами.
