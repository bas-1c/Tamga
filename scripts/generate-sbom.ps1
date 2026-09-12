<#
.SYNOPSIS
    SBOM і link-map із ФАКТИЧНОГО графа лінкування конфігурації збірки.

.DESCRIPTION
    Джерело істини — CMake File API (`.cmake/api/v1/reply`), а не вміст
    репозиторію і не перелік у документації. Для кожного цільового артефакту
    (`Tamga.dll`, `tamga-lib.dll`, `tamga-cli.exe`) береться той самий рядок
    лінкування, який отримає лінкер, і кожна бібліотека в ньому зіставляється
    з компонентом та його ліцензією.

    Чому саме так. Раніше `THIRD_PARTY_NOTICES.md` описував склад бінарника
    вручну — і назвав `libiconv`/`libcharset` під LGPL «єдиним реальним
    LGPL-ризиком», прив'язавши це до конфігурації, яка НЕ постачалася (П-09).
    Далі ADR-030 зробив `libxml2` безумовною залежністю ядра, тобто склад
    змінився ще раз. Ручний перелік не може не відставати; згенерований — може
    лише не збігтися, і тоді перевірка падає.

    Свідомо ВІДСУТНІЙ «очікуваний список залежностей». Очікування зафіксоване
    у згенерованому блоці `THIRD_PARTY_NOTICES.md`; будь-яка зміна складу дає
    розбіжність із ним, а не тихо проходить. Бібліотека, якої немає в
    `scripts/sbom-components.json`, валить генерацію з вимогою назвати ліцензію.

.PARAMETER BuildDir
    Каталог конфігурованої збірки (Ninja, Visual Studio, Makefiles — байдуже:
    File API генератор-незалежний).

.PARAMETER OutDir
    Куди складати артефакти. За замовчуванням `<BuildDir>/sbom`.

.PARAMETER Triplet
    Позначка конфігурації для імен файлів. За замовчуванням береться з
    `CMakeCache.txt` (`VCPKG_TARGET_TRIPLET`).

.PARAMETER Targets
    Цілі, склад яких вважається «у бінарнику».

.PARAMETER CheckNotices
    Звірити згенерований блок із тим, що записано в `THIRD_PARTY_NOTICES.md`.
    Розбіжність = ненульовий код виходу і показаний diff.

.PARAMETER UpdateNotices
    Перезаписати згенерований блок у `THIRD_PARTY_NOTICES.md`.

.EXAMPLE
    pwsh -File scripts/generate-sbom.ps1 -BuildDir build-verify -CheckNotices
#>
param(
    [Parameter(Mandatory = $true)][string]$BuildDir,
    [string]$OutDir,
    [string]$Triplet,
    [string[]]$Targets = @('tamga-nativeapi', 'tamga-lib', 'tamga-cli'),
    [switch]$CheckNotices,
    [switch]$UpdateNotices
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$BuildDir = (Resolve-Path -LiteralPath $BuildDir).Path
$inventoryPath = Join-Path $PSScriptRoot 'sbom-components.json'
$noticesPath = Join-Path $repoRoot 'THIRD_PARTY_NOTICES.md'
$beginMarker = '<!-- BEGIN GENERATED SBOM -->'
$endMarker = '<!-- END GENERATED SBOM -->'

function Write-Step { param([string]$T) Write-Host "==> $T" }
function Write-Ok { param([string]$T) Write-Host "    OK: $T" }

# ------------------------------------------------------------- CMake File API
Write-Step 'CMake File API'
$apiQuery = Join-Path $BuildDir '.cmake/api/v1/query'
$apiReply = Join-Path $BuildDir '.cmake/api/v1/reply'
New-Item -ItemType Directory -Path $apiQuery -Force | Out-Null
$queryFile = Join-Path $apiQuery 'codemodel-v2'
if (-not (Test-Path -LiteralPath $queryFile)) {
    New-Item -ItemType File -Path $queryFile -Force | Out-Null
}
$codemodel = @(Get-ChildItem -LiteralPath $apiReply -Filter 'codemodel-v2-*.json' -ErrorAction SilentlyContinue)
if ($codemodel.Count -eq 0) {
    Write-Host '    відповіді немає — переконфігуровую (cmake -S ... -B ...)'
    $srcDir = $repoRoot
    & cmake -S $srcDir -B $BuildDir | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'cmake reconfigure не вдався; сконфігуруйте збірку вручну і повторіть' }
    $codemodel = @(Get-ChildItem -LiteralPath $apiReply -Filter 'codemodel-v2-*.json')
}
if ($codemodel.Count -eq 0) { throw "CMake File API не дав відповіді в $apiReply" }
$cm = Get-Content -LiteralPath $codemodel[0].FullName -Raw | ConvertFrom-Json
Write-Ok "codemodel: $($codemodel[0].Name)"

# ------------------------------------------------------------- конфігурація
function Get-CacheValue {
    param([string]$Name)
    $cache = Join-Path $BuildDir 'CMakeCache.txt'
    if (-not (Test-Path -LiteralPath $cache)) { return $null }
    $m = Select-String -LiteralPath $cache -Pattern ("^" + [regex]::Escape($Name) + ":[A-Z]+=(.*)$") |
        Select-Object -First 1
    if ($m) { return $m.Matches[0].Groups[1].Value } else { return $null }
}

if (-not $Triplet) { $Triplet = Get-CacheValue 'VCPKG_TARGET_TRIPLET' }
if (-not $Triplet) {
    $sys = Get-CacheValue 'CMAKE_SYSTEM_NAME'
    if (-not $sys) { $sys = 'unknown' }
    $Triplet = $sys.ToLowerInvariant() + '-nontriplet'
}
$buildType = Get-CacheValue 'CMAKE_BUILD_TYPE'
if (-not $buildType) { $buildType = '(multi-config)' }
$generator = Get-CacheValue 'CMAKE_GENERATOR'

$featureNames = @('TAMGA_ENABLE_VENDOR_CRYPTONITE', 'TAMGA_ENABLE_XML_SIGNATURES', 'TAMGA_ENABLE_PDF_SIGNATURES')
$features = [ordered]@{}
foreach ($f in $featureNames) {
    $v = Get-CacheValue $f
    if ($null -ne $v) { $features[$f] = $v }
}
Write-Ok "triplet=$Triplet build=$buildType generator=$generator"

if (-not $OutDir) { $OutDir = Join-Path $BuildDir 'sbom' }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# ------------------------------------------------------------- довідник
$inv = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json
$sysWin = @($inv.system_libraries.windows)
$sysPosix = @($inv.system_libraries.posix)
$firstPartyPatterns = @($inv.first_party_patterns)

$libIndex = @{}
foreach ($c in $inv.components) {
    foreach ($lib in $c.libraries) {
        $key = $lib.ToLowerInvariant()
        if ($libIndex.ContainsKey($key)) {
            throw "sbom-components.json: бібліотеку '$lib' оголошено двічі ($($libIndex[$key].id) і $($c.id))"
        }
        $libIndex[$key] = $c
    }
}

# ------------------------------------------------------------- версії vcpkg
# Manifest-режим кладе дерево в <BuildDir>/vcpkg_installed, класичний — у
# <VCPKG_ROOT>/installed. Перевіряємо обидва, бо скрипт запускають і на
# збірках, сконфігурованих вручну в класичному режимі. Джоби `release.yml`
# після правки `scripts/build-linux.sh` усі manifest-режимні, тож для них
# спрацьовує перший шлях.
$vcpkgRoots = New-Object System.Collections.Generic.List[string]
$cacheInstalled = Get-CacheValue '_VCPKG_INSTALLED_DIR'
if ($cacheInstalled) { $vcpkgRoots.Add($cacheInstalled) }
$vcpkgRoots.Add((Join-Path $BuildDir 'vcpkg_installed'))
foreach ($envVar in @('VCPKG_ROOT', 'VCPKG_INSTALLATION_ROOT')) {
    $v = [Environment]::GetEnvironmentVariable($envVar)
    if ($v) { $vcpkgRoots.Add((Join-Path $v 'installed')) }
}
function Get-VcpkgPackage {
    param([string]$Port)
    $spdx = $null
    foreach ($root in $vcpkgRoots) {
        $cand = Join-Path $root "$Triplet/share/$Port/vcpkg.spdx.json"
        if (Test-Path -LiteralPath $cand) { $spdx = $cand; break }
    }
    if (-not $spdx) { return $null }
    $j = Get-Content -LiteralPath $spdx -Raw | ConvertFrom-Json
    $p = $j.packages | Where-Object { $_.name -eq $Port } | Select-Object -First 1
    if (-not $p) { $p = $j.packages[0] }
    # У джерелі ліцензії свідомо стоїть відносний, стабільний шлях, а не
    # абсолютний: інакше згенерований блок залежав би від каталогу раннера.
    return [pscustomobject]@{
        version = $p.versionInfo
        license = $p.licenseConcluded
        source  = "vcpkg_installed/$Triplet/share/$Port/vcpkg.spdx.json"
    }
}

# ------------------------------------------------------------- розбір цілей
function Split-LinkFragment {
    # Один fragment може містити кілька токенів; шляхи бувають у лапках.
    param([string]$Fragment)
    $out = New-Object System.Collections.Generic.List[string]
    $cur = ''
    $inQuote = $false
    foreach ($ch in $Fragment.ToCharArray()) {
        if ($ch -eq '"') { $inQuote = -not $inQuote; continue }
        if (-not $inQuote -and ($ch -eq ' ' -or $ch -eq "`t")) {
            if ($cur) { $out.Add($cur); $cur = '' }
            continue
        }
        $cur += $ch
    }
    if ($cur) { $out.Add($cur) }
    return $out
}

function Get-LibraryName {
    param([string]$Token)
    if ($Token -cmatch '^-l(.+)$') { return $Matches[1] }
    # RPATH/-L можуть містити шляхи, але залишаються прапорцями.
    # Абсолютні Unix-шляхи бібліотек починаються з / і не є MSVC options.
    if ($Token.StartsWith('-') -or $Token -match '^/[A-Za-z]+:') { return $null }
    $leaf = ($Token -split '[\\/]')[-1]
    # Unix додає lib до імені target; довідник використовує ім'я бібліотеки.
    # Windows .lib зберігає власне ім'я (наприклад, libxml2.lib).
    if ($leaf -match '^lib.+\.(a|so|dylib)(\.[0-9.]+)?$') { $leaf = $leaf.Substring(3) }
    $leaf = $leaf -replace '\.(lib|a|so|dylib|tbd|dll)(\.[0-9.]+)?$', ''
    if (-not $leaf) { return $null }
    return $leaf
}

$targetIndex = @{}
foreach ($cfg in $cm.configurations) {
    foreach ($t in $cfg.targets) { $targetIndex[$t.name] = (Join-Path $apiReply $t.jsonFile) }
}

$unknown = New-Object System.Collections.Generic.List[string]
$targetReports = New-Object System.Collections.Generic.List[object]
$componentHits = [ordered]@{}

Write-Step 'Розбір рядків лінкування'
foreach ($name in $Targets) {
    if (-not $targetIndex.ContainsKey($name)) {
        Write-Host "    ПРОПУЩЕНО: цілі '$name' немає в цій конфігурації"
        continue
    }
    $tj = Get-Content -LiteralPath $targetIndex[$name] -Raw | ConvertFrom-Json
    if (-not $tj.PSObject.Properties.Name.Contains('link')) {
        Write-Host "    ПРОПУЩЕНО: ціль '$name' не лінкується (type=$($tj.type))"
        continue
    }
    $artifact = if ($tj.PSObject.Properties.Name.Contains('artifacts')) { ($tj.artifacts[0].path -split '[\\/]')[-1] } else { $name }

    $entries = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($frag in $tj.link.commandFragments) {
        if ($frag.role -ne 'libraries') { continue }
        foreach ($tok in (Split-LinkFragment $frag.fragment)) {
            $lib = Get-LibraryName $tok
            if (-not $lib) { continue }
            $key = $lib.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true

            $kind = $null; $comp = $null
            if ($libIndex.ContainsKey($key)) { $kind = 'third-party'; $comp = $libIndex[$key] }
            elseif ($firstPartyPatterns | Where-Object { $lib -match $_ }) { $kind = 'first-party' }
            elseif ($sysWin -contains $key -or $sysPosix -contains $key) { $kind = 'system' }
            else { $kind = 'unknown'; $unknown.Add("$lib  (ціль $name, токен '$tok')") }

            $entries.Add([pscustomobject]@{ library = $lib; token = $tok; kind = $kind; component = $(if ($comp) { $comp.id } else { $null }) })
            if ($comp) {
                if (-not $componentHits.Contains($comp.id)) {
                    $componentHits[$comp.id] = [pscustomobject]@{ component = $comp; artifacts = (New-Object System.Collections.Generic.List[string]) }
                }
                if (-not $componentHits[$comp.id].artifacts.Contains($artifact)) { $componentHits[$comp.id].artifacts.Add($artifact) }
            }
        }
    }
    $targetReports.Add([pscustomobject]@{ target = $name; artifact = $artifact; entries = $entries })
    Write-Ok "$name -> $artifact : $($entries.Count) бібліотек"
}

if ($targetReports.Count -eq 0) { throw "жодної з цілей ($($Targets -join ', ')) немає в цій конфігурації" }

# ------------------------------------------------------------- сторожі
$fatal = New-Object System.Collections.Generic.List[string]

if ($unknown.Count) {
    $fatal.Add(@"
У рядку лінкування знайдено бібліотеки, яких немає в scripts/sbom-components.json:
$($unknown | ForEach-Object { "      - $_" } | Out-String)
    Це НЕ дрібниця: невідома бібліотека означає невідому ліцензію в артефакті,
    який постачається. Додайте запис у 'components' із полями origin/license/risk
    (для портів vcpkg достатньо 'vcpkg_port' — версію і ліцензію скрипт візьме
    з vcpkg.spdx.json) і повторіть.
"@)
}

foreach ($id in $componentHits.Keys) {
    $c = $componentHits[$id].component
    $risk = if ($c.PSObject.Properties.Name.Contains('risk')) { $c.risk } else { 'review' }
    $allowed = $c.PSObject.Properties.Name.Contains('allowed_in_binary') -and $c.allowed_in_binary
    if ($risk -ne 'permissive' -and -not $allowed) {
        $note = if ($c.PSObject.Properties.Name.Contains('note')) { $c.note } else { '' }
        $fatal.Add(@"
Компонент '$id' (risk=$risk) ФАКТИЧНО влінковано в: $($componentHits[$id].artifacts -join ', ')
    $note
    Або приберіть його з графа лінкування, або додайте компоненту
    "allowed_in_binary": true з письмовим обґрунтуванням у 'note'.
"@)
    }
}

# ------------------------------------------------------------- збірка звітів
$thirdParty = New-Object System.Collections.Generic.List[object]
foreach ($id in $componentHits.Keys) {
    $c = $componentHits[$id].component
    $version = 'n/a'
    $license = if ($c.PSObject.Properties.Name.Contains('license')) { $c.license } else { 'невідомо' }
    $licSrc = if ($c.PSObject.Properties.Name.Contains('license_source')) { $c.license_source } else { 'scripts/sbom-components.json' }
    if ($c.PSObject.Properties.Name.Contains('vcpkg_port')) {
        $pkg = Get-VcpkgPackage $c.vcpkg_port
        if ($pkg) {
            $version = $pkg.version
            if ($pkg.license -and $pkg.license -ne 'NOASSERTION') { $license = $pkg.license }
            $licSrc = $pkg.source
        }
        else {
            $version = 'vcpkg (версію не встановлено)'
        }
    }
    elseif ($id -eq 'cryptonite') {
        $pin = Join-Path $repoRoot 'patches/cryptonite/upstream.json'
        if (Test-Path -LiteralPath $pin) {
            $pj = Get-Content -LiteralPath $pin -Raw | ConvertFrom-Json
            $version = 'snapshot ' + $pj.commit.Substring(0, 12)
        }
    }
    $thirdParty.Add([pscustomobject]@{
            id        = $id
            origin    = $c.origin
            version   = $version
            license   = $license
            licenseSource = $licSrc
            risk      = $(if ($c.PSObject.Properties.Name.Contains('risk')) { $c.risk } else { 'review' })
            artifacts = @($componentHits[$id].artifacts)
        })
}
$thirdParty = @($thirdParty | Sort-Object id)

# Повні тексти умов постачаються разом із SBOM; перелік SPDX їх не замінює.
# Окремий ZIP на triplet зберігає імена компонентів під час flatten у release job.
$licenseFiles = [ordered]@{}
foreach ($c in $thirdParty) {
    $definition = $componentHits[$c.id].component
    if ($definition.PSObject.Properties.Name.Contains('vcpkg_port')) {
        $port = $definition.vcpkg_port
        $share = $null
        foreach ($root in $vcpkgRoots) {
            $candidate = Join-Path $root "$Triplet/share/$port"
            if (Test-Path -LiteralPath (Join-Path $candidate 'copyright')) { $share = $candidate; break }
        }
        if (-not $share) { throw "Повний copyright для $port не знайдено в дереві збірки" }
        foreach ($file in Get-ChildItem -LiteralPath $share -File | Where-Object { $_.Name -match '^(copyright|license|notice|copying)' }) {
            $licenseFiles["$($c.id)/$($file.Name)"] = $file.FullName
        }
    }
    elseif ($definition.PSObject.Properties.Name.Contains('license_source')) {
        $file = Join-Path $repoRoot $definition.license_source
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Не знайдено текст ліцензії: $file" }
        $licenseFiles["$($c.id)/$([IO.Path]::GetFileName($file))"] = $file
    }
}
$licenseArchive = Join-Path $OutDir "licenses-$Triplet.zip"
$licenseTemp = $licenseArchive + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
try {
    $zip = [IO.Compression.ZipFile]::Open($licenseTemp, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $licenseFiles.Keys) {
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $licenseFiles[$name], $name) | Out-Null
        }
    }
    finally { $zip.Dispose() }
    Move-Item -LiteralPath $licenseTemp -Destination $licenseArchive -Force
}
finally { if (Test-Path -LiteralPath $licenseTemp) { Remove-Item -LiteralPath $licenseTemp } }
Write-Ok "повні ліцензії: $licenseArchive ($($licenseFiles.Count) файлів)"

# ------------------------------------------------------------- link-map
$linkMapPath = Join-Path $OutDir "link-map-$Triplet.txt"
$lm = New-Object System.Collections.Generic.List[string]
$lm.Add("Tamga link-map")
$lm.Add("triplet      : $Triplet")
$lm.Add("build type   : $buildType")
$lm.Add("generator    : $generator")
foreach ($k in $features.Keys) { $lm.Add(("{0,-13}: {1}" -f $k.Replace('TAMGA_ENABLE_', ''), $features[$k])) }
$lm.Add("джерело      : CMake File API ($($codemodel[0].Name))")
$lm.Add('')
foreach ($tr in $targetReports) {
    $lm.Add("[$($tr.artifact)]  (ціль $($tr.target))")
    foreach ($e in ($tr.entries | Sort-Object kind, library)) {
        $lm.Add(("  {0,-12} {1,-22} {2}" -f $e.kind, $e.library, $(if ($e.component) { $e.component } else { '' })).TrimEnd())
    }
    $lm.Add('')
}
[IO.File]::WriteAllText($linkMapPath, ($lm -join "`n") + "`n")
Write-Ok "link-map: $linkMapPath"

# ------------------------------------------------------------- CycloneDX
$bom = [ordered]@{
    bomFormat   = 'CycloneDX'
    specVersion = '1.5'
    version     = 1
    metadata    = [ordered]@{
        tools      = @(@{ name = 'scripts/generate-sbom.ps1'; vendor = 'Tamga' })
        component  = [ordered]@{ type = 'application'; name = 'Tamga'; description = "конфігурація $Triplet / $buildType" }
        properties = @(
            @{ name = 'tamga:triplet'; value = $Triplet },
            @{ name = 'tamga:buildType'; value = $buildType },
            @{ name = 'tamga:generator'; value = "$generator" },
            @{ name = 'tamga:source'; value = 'cmake-file-api' }
        ) + @($features.Keys | ForEach-Object { @{ name = "tamga:$_"; value = $features[$_] } })
    }
    components  = @($thirdParty | ForEach-Object {
            [ordered]@{
                type        = 'library'
                name        = $_.id
                version     = $_.version
                licenses    = @(@{ license = @{ name = $_.license } })
                description = "походження: $($_.origin); ліцензія з: $($_.licenseSource)"
                properties  = @(
                    @{ name = 'tamga:risk'; value = $_.risk },
                    @{ name = 'tamga:linkedInto'; value = ($_.artifacts -join ', ') }
                )
            }
        })
}
$sbomPath = Join-Path $OutDir "sbom-$Triplet.json"
[IO.File]::WriteAllText($sbomPath, (($bom | ConvertTo-Json -Depth 12) -replace "`r`n", "`n") + "`n")
Write-Ok "SBOM: $sbomPath"

# ------------------------------------------------------------- блок notices
$nb = New-Object System.Collections.Generic.List[string]
$nb.Add($beginMarker)
$nb.Add('')
$nb.Add('<!--')
$nb.Add('  Цей блок ГЕНЕРУЄТЬСЯ scripts/generate-sbom.ps1 із фактичного графа')
$nb.Add('  лінкування (CMake File API), а не пишеться руками. Правити вручну')
$nb.Add('  безглуздо: CI звіряє його прогоном з -CheckNotices і падає на розбіжності.')
$nb.Add('-->')
$nb.Add('')
# Генератор і тип збірки у блок НЕ входять свідомо: склад компонентів від них
# не залежить, а різниця в них зробила б перевірку неможливою в CI релізу
# (Windows-джоб використовує multi-config генератор). Що входить — triplet і
# фічі: саме вони визначають, що потрапляє в бінарник.
$nb.Add("**Виміряна конфігурація:** triplet ``$Triplet``" +
    $(if ($features.Count) { ', ' + (($features.Keys | ForEach-Object { "``$($_.Replace('TAMGA_ENABLE_',''))=$($features[$_])``" }) -join ', ') } else { '' }) + '.')
$nb.Add('')
$nb.Add('| Компонент | Версія | Ліцензія | Походження | Влінковано в | Джерело ліцензії |')
$nb.Add('| --- | --- | --- | --- | --- | --- |')
foreach ($c in $thirdParty) {
    $nb.Add("| ``$($c.id)`` | $($c.version) | $($c.license) | $($c.origin) | $(($c.artifacts | Sort-Object) -join ', ') | ``$($c.licenseSource)`` |")
}
$nb.Add('')
$nb.Add('Компоненти, яких у цій таблиці НЕМАЄ, у бінарнику відсутні — незалежно')
$nb.Add('від того, чи лежать вони в дереві. Зокрема це стосується вмісту')
$nb.Add('`vendor/cryptonite/libs/` (Bee2, Libgcrypt, cppcrypto, LibreSSL, vendored')
$nb.Add('libiconv): `vendor/cryptonite/CMakeLists.txt` не додає каталог `libs/`.')
$nb.Add('')
$nb.Add('Повний перелік бібліотек рядка лінкування, включно з системними, — в')
$nb.Add('артефакті релізу `link-map-<triplet>.txt`; машиночитний варіант —')
$nb.Add('`sbom-<triplet>.json` (CycloneDX 1.5).')
$nb.Add('')
$nb.Add($endMarker)
$noticeBlock = ($nb -join "`n")

$blockPath = Join-Path $OutDir "notices-block-$Triplet.md"
[IO.File]::WriteAllText($blockPath, $noticeBlock + "`n")
Write-Ok "блок notices: $blockPath"

# ------------------------------------------------------------- звіт/сторожі
Write-Host ''
Write-Step 'Компоненти в бінарнику'
foreach ($c in $thirdParty) {
    Write-Host ("    {0,-16} {1,-14} {2,-28} risk={3,-10} -> {4}" -f $c.id, $c.version, $c.license, $c.risk, ($c.artifacts -join ', '))
}

$exitCode = 0
if ($fatal.Count) {
    Write-Host ''
    foreach ($f in $fatal) { Write-Host "ПОМИЛКА: $f" }
    $exitCode = 1
}

if ($CheckNotices -or $UpdateNotices) {
    Write-Host ''
    Write-Step 'Звірка з THIRD_PARTY_NOTICES.md'
    $text = [IO.File]::ReadAllText($noticesPath) -replace "`r`n", "`n"
    $bi = $text.IndexOf($beginMarker)
    $ei = $text.IndexOf($endMarker)
    if ($bi -lt 0 -or $ei -lt 0) {
        throw "THIRD_PARTY_NOTICES.md: не знайдено маркерів $beginMarker / $endMarker"
    }
    $current = $text.Substring($bi, $ei + $endMarker.Length - $bi)
    if ($current -ceq $noticeBlock) {
        Write-Ok 'згенерований блок збігається з тим, що в репозиторії'
    }
    elseif ($UpdateNotices) {
        $updated = $text.Substring(0, $bi) + $noticeBlock + $text.Substring($ei + $endMarker.Length)
        [IO.File]::WriteAllText($noticesPath, $updated)
        Write-Ok 'блок у THIRD_PARTY_NOTICES.md оновлено'
    }
    else {
        Write-Host '    ПОМИЛКА: блок у THIRD_PARTY_NOTICES.md НЕ відповідає фактичному графу лінкування.'
        Write-Host ''
        $curLines = $current -split "`n"
        $newLines = $noticeBlock -split "`n"
        Compare-Object -ReferenceObject $curLines -DifferenceObject $newLines |
            ForEach-Object { Write-Host ("      {0} {1}" -f $(if ($_.SideIndicator -eq '<=') { 'у репозиторії:' } else { 'фактично:    ' }), $_.InputObject) }
        Write-Host ''
        Write-Host "    Виправити: pwsh -File scripts/generate-sbom.ps1 -BuildDir $BuildDir -UpdateNotices"
        Write-Host '    і переглянути diff перед комітом — розбіжність могла зʼявитися й через'
        Write-Host '    небажану зміну складу залежностей.'
        $exitCode = 1
    }
}

exit $exitCode
