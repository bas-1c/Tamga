# Third-Party Notices

Власний код Tamga — BSD-3-Clause. Сторонні матеріали зберігають умови своїх правовласників; повні тексти й copyright banners у vendor залишено без змін.

## Склад вихідного дерева

| Компонент | Походження та умови |
| --- | --- |
| cryptonite | `patches/cryptonite/upstream.json`, повний текст у `vendor/cryptonite/LICENSE`; BSD-2-Clause-подібна ліцензія |
| miniz | `vendor/miniz/`; збережені MIT copyright/license banners і LICENSE |
| pthread | Windows-реалізація в `vendor/cryptonite/src/pthread`; умови й attribution у вихідних файлах |
| 1C NativeAPI SDK headers | `vendor/1c-nativeapi-sdk/include`; в імпортованій копії немає окремого license-файла. Заголовки належать сторонньому SDK; ліцензія власного коду Tamga не встановлює умови їх поширення |

Невикористовувані upstream libs, тести та приклади виключено з дистрибуції. Кожний вилучений шлях і hash записано в `patches/cryptonite/excluded-paths.json`; patch replay перевіряє проєкцію patched upstream на це дерево. Повний standalone-набір upstream tests у цій проєкції не постачається.

## Склад бінарників

`scripts/generate-sbom.ps1` отримує фактичний граф лінкування через CMake File API. libxml2 потрібна ядру завжди; PDF додає qpdf, libjpeg-turbo і zlib. `default-features: false` для libxml2 задано у vcpkg manifest. Зовнішні DLL і статично влінковані бібліотеки перевіряються окремо.

<!-- BEGIN GENERATED SBOM -->

<!--
  Цей блок ГЕНЕРУЄТЬСЯ scripts/generate-sbom.ps1 із фактичного графа
  лінкування (CMake File API), а не пишеться руками. Правити вручну
  безглуздо: CI звіряє його прогоном з -CheckNotices і падає на розбіжності.
-->

**Виміряна конфігурація:** triplet `x64-windows-static`, `VENDOR_CRYPTONITE=ON`, `XML_SIGNATURES=ON`, `PDF_SIGNATURES=ON`.

| Компонент | Версія | Ліцензія | Походження | Влінковано в | Джерело ліцензії |
| --- | --- | --- | --- | --- | --- |
| `cryptonite` | snapshot 3618d340d22e | BSD-2-Clause-подібна | vendor/cryptonite | tamga-cli.exe, tamga-lib.dll, Tamga.dll | `vendor/cryptonite/LICENSE` |
| `libjpeg-turbo` | 3.2.0 | BSD-3-Clause | vcpkg | tamga-cli.exe, tamga-lib.dll, Tamga.dll | `vcpkg_installed/x64-windows-static/share/libjpeg-turbo/vcpkg.spdx.json` |
| `libxml2` | 2.15.3 | MIT | vcpkg | tamga-cli.exe, tamga-lib.dll, Tamga.dll | `vcpkg_installed/x64-windows-static/share/libxml2/vcpkg.spdx.json` |
| `miniz` | n/a | MIT | vendor/miniz | tamga-cli.exe, tamga-lib.dll, Tamga.dll | `vendor/miniz/LICENSE` |
| `qpdf` | 12.4.0 | Apache-2.0 AND MIT | vcpkg | tamga-cli.exe, tamga-lib.dll, Tamga.dll | `vcpkg_installed/x64-windows-static/share/qpdf/vcpkg.spdx.json` |
| `zlib` | 1.3.2#2 | Zlib | vcpkg | tamga-cli.exe, tamga-lib.dll, Tamga.dll | `vcpkg_installed/x64-windows-static/share/zlib/vcpkg.spdx.json` |

Компоненти, яких у цій таблиці НЕМАЄ, у бінарнику відсутні — незалежно
від того, чи лежать вони в дереві. Зокрема це стосується вмісту
`vendor/cryptonite/libs/` (Bee2, Libgcrypt, cppcrypto, LibreSSL, vendored
libiconv): `vendor/cryptonite/CMakeLists.txt` не додає каталог `libs/`.

Повний перелік бібліотек рядка лінкування, включно з системними, — в
артефакті релізу `link-map-<triplet>.txt`; машиночитний варіант —
`sbom-<triplet>.json` (CycloneDX 1.5).

<!-- END GENERATED SBOM -->

Для відтворення: `pwsh -File scripts/generate-sbom.ps1 -BuildDir <shipping-build> -CheckNotices`. Для інших triplets генеруйте окремий SBOM. Файли copyright встановлених портів повинні входити в релізний пакет; сам перелік ліцензій їх не замінює. Порядок — [release-process.md](docs/release-process.md).

`NOTICE` зберігає отримані acknowledgements; наявність історичного acknowledgement сама по собі не доводить включення відповідної бібліотеки у поточний бінарник.
