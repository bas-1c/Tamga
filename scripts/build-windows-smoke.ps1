param(
    [Parameter(Mandatory = $true)]
    [string]$BuildDir,
    [Parameter(Mandatory = $false)]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = 'Stop'

$requiredExports = @(
    'GetClassObject',
    'DestroyObject',
    'GetClassNames',
    'SetPlatformCapabilities',
    'GetAttachType'
)

$allowedDependents = @(
    'KERNEL32.dll',
    'USER32.dll',
    'ADVAPI32.dll',
    # CRYPT32/BCRYPT — RSASSA-PKCS1-v1_5 через Windows CNG (перевірка підпису
    # довірчого списку ЦЗО: cryptonite не реалізує RSA, а реальний TL підписаний
    # rsa-sha256). WLDAP32 — LDAP-каталог КНЕДП як джерело сертифіката
    # підписувача (ТЗ Рівень 3). Усі три — системні DLL Windows, тож
    # single-DLL постачання не порушується.
    'CRYPT32.dll',
    'BCRYPT.dll',
    'WLDAP32.dll',
    'WINHTTP.dll',
    'WS2_32.dll',
    'UCRTBASE.dll',
    'api-ms-win-crt-runtime-l1-1-0.dll',
    'api-ms-win-crt-heap-l1-1-0.dll',
    'api-ms-win-crt-string-l1-1-0.dll',
    'api-ms-win-crt-stdio-l1-1-0.dll',
    'api-ms-win-crt-convert-l1-1-0.dll',
    'api-ms-win-crt-math-l1-1-0.dll',
    'api-ms-win-crt-utility-l1-1-0.dll',
    'api-ms-win-crt-locale-l1-1-0.dll',
    'api-ms-win-crt-time-l1-1-0.dll',
    'api-ms-win-crt-filesystem-l1-1-0.dll',
    'api-ms-win-crt-environment-l1-1-0.dll'
)

$disallowedDependentPatterns = @(
    '^TAMGA-LIB\.DLL$',
    '^LIBXML2.*\.DLL$',
    '^XMLSEC.*\.DLL$',
    '^QPDF.*\.DLL$',
    '^LIBCRYPTO.*\.DLL$',
    '^LIBSSL.*\.DLL$',
    '^(ZLIB|ZLIB1).*\.DLL$',
    '^(JPEG|JPEGTURBO|TURBOJPEG|LIBJPEG|LIBTURBOJPEG).*\.DLL$',
    '^LIBCURL.*\.DLL$',
    '^CURL.*\.DLL$',
    '^MSVCP.*\.DLL$',
    '^VCRUNTIME.*\.DLL$'
)

function Write-Section([string]$Title) {
    "`n===== $Title =====" | Out-File -FilePath $script:reportPath -Append -Encoding utf8
}

function Get-DumpbinExports([string[]]$DumpbinOutput) {
    $names = New-Object 'System.Collections.Generic.List[string]'
    $inTable = $false

    foreach ($line in $DumpbinOutput) {
        if ($line -match '^\s*ordinal\s+hint\s+RVA\s+name\s*$') {
            $inTable = $true
            continue
        }

        if (-not $inTable) {
            continue
        }

        if ($line -match '^\s*Summary\s*$') {
            break
        }

        if ($line -match '^\s*\d+\s+[0-9A-F]+\s+[0-9A-F]+\s+([^\s]+)') {
            $names.Add($Matches[1])
        }
    }

    return @($names | Sort-Object -Unique)
}

function Get-DumpbinDependents([string[]]$DumpbinOutput) {
    $deps = New-Object 'System.Collections.Generic.List[string]'
    $capture = $false
    $seenDependency = $false

    foreach ($line in $DumpbinOutput) {
        if ($line -match '^\s*Image has the following(?: delay load)? dependencies:\s*$') {
            $capture = $true
            $seenDependency = $false
            continue
        }

        if (-not $capture) {
            continue
        }

        if ($line.Trim().Length -eq 0) {
            if ($seenDependency) {
                $capture = $false
            }
            continue
        }

        if ($line -match '^\s*([A-Za-z0-9._-]+\.dll)\s*$') {
            $deps.Add($Matches[1])
            $seenDependency = $true
        }
    }

    return @($deps | Sort-Object -Unique)
}
# Артефакт шукаємо в обох розкладках, а не лише в багатоконфігураційній.
#
# Visual Studio кладе бінарники у <build>/<Configuration>/, а single-config
# генератори (Ninja) — просто у <build>/. Скрипт знав лише перший варіант, тому
# на Ninja-збірці падав із "Tamga.dll not found: build-static\Release\Tamga.dll",
# хоча DLL лежала поруч. Саме Ninja + статичний triplet — конфігурація, з якої
# постачається single-DLL, тож підтримувати треба насамперед її.
function Resolve-BuildArtifact {
    param(
        [string]$RelativeDir,   # "" для кореня збірки, інакше напр. "tests"
        [string]$FileName
    )

    $candidates = @()
    foreach ($dir in @("$RelativeDir/$Configuration", $RelativeDir)) {
        $trimmed = $dir.Trim('/')
        $candidates += if ([string]::IsNullOrEmpty($trimmed)) {
            Join-Path $BuildDir $FileName
        } else {
            Join-Path $BuildDir "$trimmed/$FileName"
        }
    }

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }
    throw "$FileName not found. Looked in: $($candidates -join ', ')"
}

$dllPath      = Resolve-BuildArtifact -RelativeDir ""        -FileName "Tamga.dll"
$testsExePath = Resolve-BuildArtifact -RelativeDir "tests"   -FileName "tamga-tests.exe"
$cliPath      = Resolve-BuildArtifact -RelativeDir "src/cli" -FileName "tamga-cli.exe"

$script:reportPath = Join-Path $BuildDir "smoke-report.txt"
"Tamga smoke report" | Out-File -FilePath $script:reportPath -Encoding utf8
"DLL: $dllPath" | Out-File -FilePath $script:reportPath -Append -Encoding utf8
"Tests EXE: $testsExePath" | Out-File -FilePath $script:reportPath -Append -Encoding utf8
"CLI EXE: $cliPath" | Out-File -FilePath $script:reportPath -Append -Encoding utf8

$dumpbinCmd = Get-Command dumpbin -ErrorAction SilentlyContinue
if ($null -eq $dumpbinCmd) {
    throw "dumpbin is unavailable in PATH"
}

Write-Section "dumpbin /exports"
$exportRaw = & dumpbin /exports $dllPath
$exportRaw | Out-File -FilePath $script:reportPath -Append -Encoding utf8

$actualExports = Get-DumpbinExports -DumpbinOutput $exportRaw
if ($actualExports.Count -ne 5) {
    throw "Export gate failed: expected exactly 5 exports, found $($actualExports.Count): $($actualExports -join ', ')"
}

foreach ($name in $requiredExports) {
    if ($actualExports -notcontains $name) {
        throw "Export gate failed: required symbol missing: $name"
    }
}

$extraExports = @($actualExports | Where-Object { $requiredExports -notcontains $_ })
if ($extraExports.Count -gt 0) {
    throw "Export gate failed: unexpected exports detected: $($extraExports -join ', ')"
}

foreach ($binaryPath in @($dllPath, $cliPath)) {
    Write-Section "dumpbin /dependents $([System.IO.Path]::GetFileName($binaryPath))"
    $dependentsRaw = & dumpbin /dependents $binaryPath
    $dependentsRaw | Out-File -FilePath $script:reportPath -Append -Encoding utf8

    $actualDependents = Get-DumpbinDependents -DumpbinOutput $dependentsRaw
    if ($actualDependents.Count -eq 0) {
        throw "Dependency gate failed for ${binaryPath}: dumpbin did not return dependent DLLs"
    }

    if (@($actualDependents | Where-Object { $_.ToUpperInvariant() -eq 'TAMGA-LIB.DLL' }).Count -gt 0) {
        throw "Dependency gate failed for ${binaryPath}: single-file artifact depends on tamga-lib.dll"
    }

    $explicitlyDisallowedDependents = @(
        $actualDependents | Where-Object {
            $candidate = $_.ToUpperInvariant()
            $blocked = $false
            foreach ($pattern in $disallowedDependentPatterns) {
                if ($candidate -match $pattern) {
                    $blocked = $true
                    break
                }
            }
            $blocked
        }
    )

    if ($explicitlyDisallowedDependents.Count -gt 0) {
        throw "Dependency gate failed for ${binaryPath}: forbidden single-binary runtime dependencies detected: $($explicitlyDisallowedDependents -join ', ')"
    }

    $disallowedDependents = @(
        $actualDependents | Where-Object {
            $candidate = $_.ToUpperInvariant()
            $isAllowed = $false
            foreach ($allowed in $allowedDependents) {
                if ($candidate -eq $allowed.ToUpperInvariant()) {
                    $isAllowed = $true
                    break
                }
            }
            if (-not $isAllowed -and $candidate -match '^(API-MS-WIN|EXT-MS-WIN)-') {
                $isAllowed = $true
            }
            -not $isAllowed
        }
    )

    if ($disallowedDependents.Count -gt 0) {
        throw "Dependency gate failed for ${binaryPath}: disallowed DLL dependencies detected: $($disallowedDependents -join ', ')"
    }
}

Write-Section "gate summary"
"Export gate: PASS (exactly 5 symbols)." | Out-File -FilePath $script:reportPath -Append -Encoding utf8
"Dependency gate: PASS (Tamga.dll and tamga-cli.exe are single-file artifacts without tamga-lib.dll, XML/PDF, OpenSSL, zlib, JPEG, Curl, or dynamic MSVC runtime DLLs)." | Out-File -FilePath $script:reportPath -Append -Encoding utf8
"All Windows smoke gates passed." | Out-File -FilePath $script:reportPath -Append -Encoding utf8

Write-Host "Export/runtime smoke checks passed. Report: $script:reportPath"
