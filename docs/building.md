# Збірка

Потрібні CMake 3.23+, C++17-компілятор, Git та libxml2. На Windows рекомендовані MSVC, Ninja і manifest-режим vcpkg. Для PDF потрібен qpdf. Версії портів фіксує `builtin-baseline` у `vcpkg.json`.

## Windows

У Developer PowerShell/Command Prompt потрібної архітектури, з кореня репозиторію:

```powershell
$env:VCPKG_ROOT = 'C:/tools/vcpkg'
cmake -S . -B build-x64-shipping -G Ninja -DCMAKE_BUILD_TYPE=Release `
  "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_MANIFEST_MODE=ON -DVCPKG_TARGET_TRIPLET=x64-windows-static `
  "-DVCPKG_MANIFEST_FEATURES=xml-signatures;pdf-signatures" `
  -DTAMGA_ENABLE_VENDOR_CRYPTONITE=ON `
  -DTAMGA_ENABLE_XML_SIGNATURES=ON -DTAMGA_ENABLE_PDF_SIGNATURES=ON `
  -DTAMGA_BUILD_TESTS=ON -DTAMGA_BUILD_CLI=ON
cmake --build build-x64-shipping --parallel
ctest --test-dir build-x64-shipping --output-on-failure
cmake --install build-x64-shipping --prefix install-x64
```

Для x86 ініціалізуй середовище MSVC x86, зміни build-каталог і triplet на `x86-windows-static`. Розрядність NativeAPI DLL має відповідати процесу 1С/BAS. `TAMGA_MSVC_STATIC_RUNTIME` керує runtime; static triplet використовує `/MT`.

## Linux

Після встановлення CMake, Ninja, GCC/Clang, UUID і development-пакета libxml2:

```bash
bash scripts/build-linux.sh --arch x64 --config Release --tests
```

Це базовий режим. XML вмикається `--enable-xml-signatures`. Shipping із статичними сторонніми залежностями використовує vcpkg: `--static-third-party-deps --vcpkg-triplet x64-linux`; задайте `VCPKG_ROOT`. x86 додатково потребує multilib та 32-бітних development-пакетів. Комбінації й експорти перевіряють workflows у `.github/workflows/`.

## Конфігурації

| Режим | Cryptonite | XML/PDF | Призначення |
| --- | --- | --- | --- |
| Shipping | ON | ON/ON | Повні форматні рушії, qpdf і libxml2 |
| Base | ON | OFF/OFF | CMS/ASiC і базові операції |
| Vendor OFF | OFF | OFF/OFF | Діагностика API, криптографічні операції повертають NotSupported |

`libxml2` потрібна в усіх режимах. `TAMGA_BUILD_TOOLS=ON` додає діагностичні програми; benchmark пошуку сертифікатів доступний за наявності cryptonite. ASan вмикається через `TAMGA_ENABLE_SANITIZERS`; на MSVC потрібна runtime DLL відповідного toolset.

Перелік і обмеження тестів — у [testing-strategy.md](testing-strategy.md). Порядок перевірки випуску — у [release-process.md](release-process.md).
