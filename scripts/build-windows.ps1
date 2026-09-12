param(
    [ValidateSet('x86','x64','all')]
    [string]$Arch = 'x64',
    [ValidateSet('Debug','Release')]
    [string]$Config = 'Release',
    [switch]$EnableCryptonite,
    [switch]$DisableCryptonite,
    [switch]$BuildTools,
    [string]$VcpkgRoot
)

$ErrorActionPreference = 'Stop'

if ($EnableCryptonite -and $DisableCryptonite) {
    throw 'Use either -EnableCryptonite or -DisableCryptonite, not both.'
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$releaseDir = Join-Path $repoRoot 'release'
$generator = 'Visual Studio 17 2022'
$cryptoniteFlag = if ($DisableCryptonite) { 'OFF' } else { 'ON' }
$toolsFlag = if ($BuildTools) { 'ON' } else { 'OFF' }

# ADR-030: `libxml2` — БЕЗУМОВНА залежність ядра, тож `find_package(LibXml2
# REQUIRED)` виконується в БУДЬ-ЯКІЙ конфігурації, включно з діагностичною
# `-DisableCryptonite`. До цієї правки скрипт конфігурував узагалі без
# toolchain vcpkg і після ADR-030 падав на першому ж кроці:
#   CMake Error ... Could NOT find LibXml2 (missing: LIBXML2_LIBRARY
#   LIBXML2_INCLUDE_DIR) ... CMakeLists.txt:185 (find_package)
# перевірено 2026-08-30 командою
#   cmake -S . -B build-notoolchain -G Ninja -DCMAKE_BUILD_TYPE=Release
#     -DTAMGA_ENABLE_VENDOR_CRYPTONITE=ON -DTAMGA_BUILD_TESTS=ON -DTAMGA_BUILD_CLI=ON
#   → Configuring incomplete, errors occurred! (exit 1)
# Це не теорія: саме цю команду `docs/release-process.md` (крок 3) велить
# запустити випускальнику.
#
# Manifest-режим, а не класичний: класичний `vcpkg install` дає ІНШИЙ граф
# залежностей (libxml2 із дефолтною фічею `iconv` під LGPL) — це і був П-09.
$vcpkgRootResolved = $VcpkgRoot
if (-not $vcpkgRootResolved) { $vcpkgRootResolved = $env:VCPKG_ROOT }
if (-not $vcpkgRootResolved) { $vcpkgRootResolved = $env:VCPKG_INSTALLATION_ROOT }
if (-not $vcpkgRootResolved) {
    throw @'
Не знайдено корінь vcpkg. Після ADR-030 libxml2 — безумовна залежність ядра,
тож збірка без toolchain vcpkg падає на find_package(LibXml2 REQUIRED).
Вкажіть -VcpkgRoot <шлях> або задайте VCPKG_ROOT / VCPKG_INSTALLATION_ROOT.
'@
}
$vcpkgToolchain = Join-Path $vcpkgRootResolved 'scripts/buildsystems/vcpkg.cmake'
if (-not (Test-Path -LiteralPath $vcpkgToolchain)) {
    throw "toolchain vcpkg не знайдено: $vcpkgToolchain"
}

function Copy-ReleaseArtifact {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$DestinationName
    )

    if (-not (Test-Path $Source)) {
        throw "Build artifact not found: $Source"
    }

    Copy-Item $Source (Join-Path $releaseDir $DestinationName) -Force
}

function Invoke-TamgaWindowsBuild {
    param(
        [ValidateSet('x86','x64')]
        [string]$TargetArch
    )

    $platform = if ($TargetArch -eq 'x86') { 'Win32' } else { 'x64' }
    $triplet = "$TargetArch-windows-static"
    $buildDir = Join-Path $repoRoot "build/windows-$TargetArch-$Config"

    # Конфігурація ПОСТАЧАННЯ, як її називає docs/release-process.md (крок 3):
    # vendor=ON, XML=ON, PDF=ON. До цієї правки скрипт збирав базову
    # конфігурацію (без XML/PDF), тобто `release/Tamga_<арх>.dll` не містив ні
    # XAdES, ні PAdES — а саме ці файли забирає scripts/pack-addon.ps1.
    #
    # У діагностичному режимі (-DisableCryptonite) XML/PDF лишаються OFF
    # свідомо: це одна з ТРЬОХ конфігурацій, для яких tests/CMakeLists.txt має
    # задокументований гейт кількості тестів (37). Комбінація vendor=OFF +
    # XML/PDF=ON гейту не має, тож перемикання на неї тихо позбавило б
    # діагностичний прогін цієї сторожі.
    $formatEngines = if ($DisableCryptonite) { 'OFF' } else { 'ON' }

    cmake -S $repoRoot -B $buildDir -G $generator -A $platform `
        "-DCMAKE_TOOLCHAIN_FILE=$vcpkgToolchain" `
        "-DVCPKG_TARGET_TRIPLET=$triplet" `
        -DVCPKG_MANIFEST_MODE=ON `
        "-DVCPKG_MANIFEST_FEATURES=xml-signatures;pdf-signatures" `
        -DTAMGA_ENABLE_VENDOR_CRYPTONITE=$cryptoniteFlag `
        -DTAMGA_ENABLE_XML_SIGNATURES=$formatEngines `
        -DTAMGA_ENABLE_PDF_SIGNATURES=$formatEngines `
        -DTAMGA_BUILD_TESTS=ON `
        -DTAMGA_BUILD_TOOLS=$toolsFlag `
        -DTAMGA_BUILD_CLI=ON
    if ($LASTEXITCODE -ne 0) { throw "cmake configure не вдався для $TargetArch (triplet $triplet)" }

    cmake --build $buildDir --config $Config --parallel
    if ($LASTEXITCODE -ne 0) { throw "cmake --build не вдався для $TargetArch" }
    ctest --test-dir $buildDir -C $Config --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw "ctest не пройшов для $TargetArch" }

    New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null

    Copy-ReleaseArtifact `
        -Source (Join-Path $buildDir "$Config/Tamga.dll") `
        -DestinationName "Tamga_$TargetArch.dll"
    Copy-ReleaseArtifact `
        -Source (Join-Path $buildDir "src/cli/$Config/tamga-cli.exe") `
        -DestinationName "tamga-cli_$TargetArch.exe"
    Copy-ReleaseArtifact `
        -Source (Join-Path $buildDir "$Config/tamga-lib.dll") `
        -DestinationName "tamga-lib_$TargetArch.dll"

    $dumpbin = Get-Command dumpbin -ErrorAction SilentlyContinue
    if ($null -ne $dumpbin) {
        powershell -NoProfile -ExecutionPolicy Bypass `
            -File (Join-Path $repoRoot 'scripts/build-windows-smoke.ps1') `
            -BuildDir $buildDir `
            -Configuration $Config
    } else {
        Write-Warning 'dumpbin was not found in PATH. Skipping export/runtime smoke verification.'
    }
}

$architectures = if ($Arch -eq 'all') { @('x64', 'x86') } else { @($Arch) }
foreach ($targetArch in $architectures) {
    Invoke-TamgaWindowsBuild -TargetArch $targetArch
}

Write-Host "Release artifacts copied to $releaseDir"
