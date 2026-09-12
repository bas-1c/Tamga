<#
.SYNOPSIS
    Механічний replay черги патчів vendor/cryptonite.

.DESCRIPTION
    Доводить рівність:

        upstream(pin) + patches/cryptonite/series.txt  ==  vendor/cryptonite

    Крок за кроком:
      1. читає пін upstream із patches/cryptonite/upstream.json (URL + commit SHA);
      2. дістає ЧИСТИЙ знімок цього коміту (мережею або з наданого каталогу);
      3. звіряє, що отриманий SHA дорівнює пінованому;
      4. послідовно накладає патчі із series.txt (порядок = порядок рядків);
      5. побайтово порівнює отримане дерево з vendor/cryptonite у робочому дереві;
      6. успіх = порожній diff (жодного зайвого, відсутнього чи відмінного файлу).

    Якщо перевірка падає — це або ручна правка у vendor/cryptonite повз чергу,
    або патч, що більше не відповідає своєму файлу, або зміщений пін upstream.

.PARAMETER SnapshotDir
    Каталог із уже підготовленим ЧИСТИМ upstream-знімком (без .git або з ним).
    Використовується замість завантаження. Не змінюється: скрипт робить копію.

.PARAMETER Offline
    Забороняє мережу. Без -SnapshotDir скрипт у цьому режимі одразу падає з
    поясненням, що саме лишилося неперевіреним.

.PARAMETER WorkDir
    Каталог для тимчасових даних. За замовчуванням — новий каталог у TEMP.

.PARAMETER KeepWorkDir
    Не видаляти WorkDir після завершення (корисно для розбору розходжень).

.EXAMPLE
    pwsh -File scripts/verify-cryptonite-patches.ps1

.EXAMPLE
    pwsh -File scripts/verify-cryptonite-patches.ps1 -SnapshotDir C:\cache\cryptonite -Offline
#>
param(
    [string]$SnapshotDir,
    [switch]$Offline,
    [string]$WorkDir,
    [switch]$KeepWorkDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$patchDir = Join-Path $repoRoot 'patches/cryptonite'
$manifestPath = Join-Path $patchDir 'upstream.json'
$seriesPath = Join-Path $patchDir 'series.txt'

function Write-Step { param([string]$Text) Write-Host "==> $Text" }
function Write-Ok { param([string]$Text) Write-Host "    OK: $Text" }
function Write-Bad { param([string]$Text) Write-Host "    ПОМИЛКА: $Text" }

# ---------------------------------------------------------------- 1. маніфест
Write-Step 'Читання піна upstream'
foreach ($p in @($manifestPath, $seriesPath)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "не знайдено обовʼязковий файл: $p" }
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$upstreamUrl = $manifest.url
$upstreamCommit = $manifest.commit
$vendorPath = Join-Path $repoRoot $manifest.vendor_path

if ($upstreamCommit -notmatch '^[0-9a-f]{40}$') {
    throw "upstream.json: 'commit' має бути повним 40-символьним SHA, отримано '$upstreamCommit'"
}
if (-not (Test-Path -LiteralPath $vendorPath)) {
    throw "не знайдено vendor-дерево: $vendorPath"
}
Write-Ok "$upstreamUrl @ $upstreamCommit"

$series = @(Get-Content -LiteralPath $seriesPath |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -ne '' -and -not $_.StartsWith('#') })
Write-Ok "series.txt: $($series.Count) патч(ів)"

# Сторожа проти дефекту, який уже траплявся: файл лежить у каталозі, але його
# немає в series.txt (або навпаки). Тоді replay «успішний», а патч не бере
# участі в жодній перевірці.
$patchFiles = @(Get-ChildItem -LiteralPath $patchDir -Filter '*.patch' -File |
    Sort-Object Name | Select-Object -ExpandProperty Name)
$onlyOnDisk = @($patchFiles | Where-Object { $series -notcontains $_ })
$onlyInSeries = @($series | Where-Object { $patchFiles -notcontains $_ })
if ($onlyOnDisk.Count -or $onlyInSeries.Count) {
    if ($onlyOnDisk.Count) { Write-Bad "патчі є на диску, але немає в series.txt: $($onlyOnDisk -join ', ')" }
    if ($onlyInSeries.Count) { Write-Bad "патчі є в series.txt, але немає на диску: $($onlyInSeries -join ', ')" }
    throw 'series.txt і каталог патчів розійшлися'
}
Write-Ok "каталог і series.txt збігаються ($($patchFiles.Count) файлів)"

# --------------------------------------------------------------- 2. робочий каталог
if (-not $WorkDir) {
    $WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("tamga-cryptonite-replay-" + [System.Guid]::NewGuid().ToString('N').Substring(0, 12))
}
if (Test-Path -LiteralPath $WorkDir) { throw 'WorkDir already exists; choose a new empty path' }
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
$replayDir = Join-Path $WorkDir 'replay'

$exitCode = 0
try {
    # ------------------------------------------------------ 3. чистий знімок
    Write-Step 'Отримання чистого upstream-знімка'
    if ($SnapshotDir) {
        $src = (Resolve-Path -LiteralPath $SnapshotDir).Path
        Write-Ok "з кешу: $src"
        Copy-Item -LiteralPath $src -Destination $replayDir -Recurse -Force
        $cachedGit = Join-Path $replayDir '.git'
        if (Test-Path -LiteralPath $cachedGit) {
            # Кешований знімок міг прийти як повний клон: звіряємо SHA.
            $head = (& git -C $replayDir rev-parse HEAD 2>$null)
            if ($LASTEXITCODE -eq 0 -and $head) {
                $head = $head.Trim()
                if ($head -ne $upstreamCommit) {
                    throw "кешований знімок на коміті $head, а пін вимагає $upstreamCommit"
                }
                Write-Ok "SHA кешу збігається з піном: $head"
            }
            Remove-Item -LiteralPath $cachedGit -Recurse -Force
        }
        else {
            Write-Host "    УВАГА: кеш без .git — походження знімка НЕ засвідчене цим запуском."
            Write-Host "           Перевірено лише «series.txt відтворює те, що лежить у vendor/»,"
            Write-Host "           але НЕ «знімок дорівнює $upstreamCommit»."
        }
    }
    elseif ($Offline) {
        throw @'
режим -Offline без -SnapshotDir: чистий знімок узяти нізвідки.
Дайте -SnapshotDir <каталог> або запустіть без -Offline.
'@
    }
    else {
        $fetchDir = Join-Path $WorkDir 'upstream'
        New-Item -ItemType Directory -Path $fetchDir -Force | Out-Null
        # core.autocrlf=false / core.eol=lf — обовʼязково. Інакше на Windows
        # git підмінює переводи рядків при checkout, і побайтове порівняння
        # падає на файлах, яких жоден патч не торкався.
        $gitCfg = @('-c', 'core.autocrlf=false', '-c', 'core.eol=lf', '-c', 'core.symlinks=false')
        & git @gitCfg init --quiet $fetchDir
        if ($LASTEXITCODE -ne 0) { throw 'git init не вдався' }
        & git @gitCfg -C $fetchDir remote add origin $upstreamUrl
        if ($LASTEXITCODE -ne 0) { throw 'git remote add не вдався' }
        Write-Host "    fetch --depth 1 $upstreamUrl $upstreamCommit"
        & git @gitCfg -C $fetchDir fetch --quiet --depth 1 origin $upstreamCommit
        if ($LASTEXITCODE -ne 0) {
            throw "git fetch не дістав $upstreamCommit з $upstreamUrl (мережа або зміщений/видалений коміт)"
        }
        & git @gitCfg -C $fetchDir checkout --quiet --detach FETCH_HEAD
        if ($LASTEXITCODE -ne 0) { throw 'git checkout FETCH_HEAD не вдався' }

        $head = (& git -C $fetchDir rev-parse HEAD).Trim()
        if ($head -ne $upstreamCommit) {
            throw "отримано коміт $head, а пін вимагає $upstreamCommit"
        }
        Write-Ok "знімок на пінованому коміті $head"

        Copy-Item -LiteralPath $fetchDir -Destination $replayDir -Recurse -Force
        Remove-Item -LiteralPath (Join-Path $replayDir '.git') -Recurse -Force
    }

    # Ізольований Git-корінь обов'язковий, коли WorkDir усередині іншого repo.
    # Інакше git apply може успішно пропустити всі patches як сторонні шляхи.
    & git -c core.autocrlf=false -c core.eol=lf init --quiet $replayDir
    if ($LASTEXITCODE -ne 0) { throw 'Не вдалося ізолювати Git-корінь replay' }

    # ------------------------------------------------------ 4. накладання серії
    Write-Step "Накладання $($series.Count) патчів у порядку series.txt"
    $applied = 0
    foreach ($name in $series) {
        $patch = Join-Path $patchDir $name

        # Патчі в цій черзі історично мають ДВА різні корені:
        #   0001-0005 — шляхи від кореня cryptonite      (a/CMakeLists.txt)
        #   0006-0016 — шляхи від кореня Tamga           (a/vendor/cryptonite/CMakeLists.txt)
        # Рівень -p визначаємо з самого патча, а не з номера, і вимагаємо,
        # щоб у межах одного патча корінь був однаковий.
        $targets = @(Select-String -LiteralPath $patch -Pattern '^\+\+\+ (?!/dev/null)b?/?(.+?)(\s|$)' -AllMatches |
            ForEach-Object { $_.Matches[0].Groups[1].Value })
        if ($targets.Count -eq 0) { throw "$name : не знайдено жодного рядка '+++'" }

        $prefixed = @($targets | Where-Object { $_ -like "$($manifest.vendor_path)/*" })
        if ($prefixed.Count -eq $targets.Count) {
            $strip = 1 + ($manifest.vendor_path -split '/').Count   # b/ + vendor/ + cryptonite/
            $root = $manifest.vendor_path
        }
        elseif ($prefixed.Count -eq 0) {
            $strip = 1
            $root = '<корінь cryptonite>'
        }
        else {
            throw "$name : змішані корені шляхів (частина від '$($manifest.vendor_path)/', частина ні) — патч не можна накласти однією командою"
        }

        # Git apply також читає глобальний core.autocrlf; фіксуємо LF,
        # щоб SHA-256 пропатчених виключень збігався на Windows і Linux.
        & git -c core.autocrlf=false -c core.eol=lf -C $replayDir apply --check "-p$strip" --whitespace=nowarn -- $patch 2>&1 | ForEach-Object { Write-Host "    $_" }
        if ($LASTEXITCODE -ne 0) {
            Write-Bad "$name не накладається (корінь $root, -p$strip)"
            throw "патч $name не накладається на upstream+попередні патчі"
        }
        & git -c core.autocrlf=false -c core.eol=lf -C $replayDir apply "-p$strip" --whitespace=nowarn -- $patch
        if ($LASTEXITCODE -ne 0) { throw "патч $name не застосувався попри успішний --check" }
        $applied++
        Write-Host ("    [{0,2}/{1}] {2}  (-p{3})" -f $applied, $series.Count, $name, $strip)
    }
    Write-Ok "усі $applied патчів накладено без відхилень"

    # ------------------------------------------------------ 5. порівняння дерев
    Write-Step "Порівняння з $($manifest.vendor_path)"

    function Get-TreeIndex {
        param([string]$Root)
        $map = [ordered]@{}
        $prefix = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\', '/')
        Get-ChildItem -LiteralPath $Root -Recurse -File -Force |
            Where-Object { $_.FullName -notmatch '(\\|/)\.git(\\|/)' } |
            ForEach-Object {
                $rel = $_.FullName.Substring($prefix.Length + 1).Replace('\', '/')
                $map[$rel] = $_.FullName
            }
        return $map
    }

    $left = Get-TreeIndex $replayDir      # upstream + series
    $right = Get-TreeIndex $vendorPath

    # Явна проєкція: вилучені файли перевіряються за SHA-256 після replay.
    $excludedPath = Join-Path $patchDir 'excluded-paths.json'
    if (Test-Path -LiteralPath $excludedPath) {
        $excluded = @(Get-Content -LiteralPath $excludedPath -Raw | ConvertFrom-Json)
        foreach ($entry in $excluded) {
            $rel = [string]$entry.path
            if (-not $left.Contains($rel)) { throw "Excluded path missing from upstream replay: $rel" }
            if ($right.Contains($rel)) { throw "Excluded path is present in distribution: $rel" }
            $actual = (Get-FileHash -LiteralPath $left[$rel] -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $entry.sha256) { throw "Excluded path hash mismatch: $rel" }
            $left.Remove($rel)
        }
        Write-Ok "Підтверджено вилучені файли: $($excluded.Count)"
    }
    # те, що лежить у репозиторії

    $missing = @($left.Keys | Where-Object { -not $right.Contains($_) })   # є в replay, немає у vendor
    $extra = @($right.Keys | Where-Object { -not $left.Contains($_) })     # є у vendor, немає в replay
    $differ = @()
    $eolOnly = @()

    foreach ($rel in $left.Keys) {
        if (-not $right.Contains($rel)) { continue }
        $a = [System.IO.File]::ReadAllBytes($left[$rel])
        $b = [System.IO.File]::ReadAllBytes($right[$rel])
        if ($a.Length -eq $b.Length) {
            $same = $true
            for ($i = 0; $i -lt $a.Length; $i++) { if ($a[$i] -ne $b[$i]) { $same = $false; break } }
            if ($same) { continue }
        }
        # Розрізняємо справжнє розходження вмісту і різницю лише в CRLF/LF:
        # друге залежить від налаштувань checkout, а не від черги патчів.
        $na = ([System.Text.Encoding]::Latin1.GetString($a)) -replace "`r`n", "`n"
        $nb = ([System.Text.Encoding]::Latin1.GetString($b)) -replace "`r`n", "`n"
        if ($na -ceq $nb) { $eolOnly += $rel } else { $differ += $rel }
    }

    Write-Ok "файлів у replay: $($left.Count); у vendor: $($right.Count)"
    if ($eolOnly.Count) {
        Write-Host "    УВАГА: різниця лише в переводах рядків ($($eolOnly.Count) файл(ів)):"
        $eolOnly | Select-Object -First 20 | ForEach-Object { Write-Host "      ~ $_" }
        Write-Host "    Це наслідок налаштувань checkout (core.autocrlf), а не черги патчів."
    }

    if ($missing.Count -or $extra.Count -or $differ.Count) {
        Write-Host ''
        Write-Bad 'дерева РОЗІЙШЛИСЯ — vendor/cryptonite не дорівнює upstream + series.txt'
        foreach ($f in $missing) { Write-Host "      - відсутній у vendor: $f" }
        foreach ($f in $extra) { Write-Host "      + зайвий у vendor (не походить із upstream і не створений жодним патчем): $f" }
        foreach ($f in $differ) { Write-Host "      ! відрізняється вміст: $f" }
        Write-Host ''
        Write-Host '    Три типові причини:'
        Write-Host '      1) правку внесено прямо у vendor/cryptonite повз patches/cryptonite/ —'
        Write-Host '         оформіть її окремим патчем і додайте в кінець series.txt;'
        Write-Host '      2) патч у черзі не відповідає своєму вмісту (перегенеруйте його);'
        Write-Host '      3) зміщено пін upstream у patches/cryptonite/upstream.json.'
        Write-Host ''
        Write-Host "    Дерево replay залишено для розбору: $replayDir"
        Write-Host "    Приклад: diff -ru `"$replayDir`" `"$vendorPath`""
        $KeepWorkDir = $true
        $exitCode = 1
    }
    else {
        Write-Host ''
        Write-Host "РЕЗУЛЬТАТ: diff порожній."
        Write-Host "  $($manifest.vendor_path) == $upstreamUrl@$($upstreamCommit.Substring(0,12)) + $($series.Count) патчів із series.txt"
        if ($eolOnly.Count) { Write-Host "  (з точністю до переводів рядків у $($eolOnly.Count) файл(ах) — див. вище)" }
    }
}
finally {
    if ($KeepWorkDir) {
        Write-Host "Робочий каталог збережено: $WorkDir"
    }
    elseif (Test-Path -LiteralPath $WorkDir) {
        Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

exit $exitCode
