param(
    [string]$OutArchive = "Tamga.zip",
    [string]$WindowsX86Dll = "",
    [string]$WindowsX64Dll = "",
    [string]$LinuxX86So = "",
    [string]$LinuxX64So = "",
    [switch]$RequireLinux = $false
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Resolve-Path (Join-Path $scriptDir "..")

function Find-CandidatePath([string[]]$candidates) {
    foreach ($path in $candidates) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $resolved = if ([System.IO.Path]::IsPathRooted($path)) { $path } else { Join-Path $projectRoot $path }
        if (Test-Path $resolved) {
            return (Resolve-Path $resolved).Path
        }
    }
    return $null
}

# Пошук Windows бінарників
#
# А-03: до цієї правки список знав лише розкладку multi-config генератора
# Visual Studio (`<dir>/Release/Tamga.dll`) і каталог `release/`, куди кладе
# `build-windows.ps1`. Розкладки Ninja (`<dir>/Tamga.dll`, без підкаталогу
# конфігурації) тут не було — а Ninja є ЄДИНИМ генератором, який працює на
# машинах без toolset v143. Наслідок: крок 6 порядку випуску не знаходив
# нічого і завершувався помилкою «No component binaries found», хоча зібрані
# й перевірені бінарники лежали поруч.
#
# Порядок кандидатів має значення: спершу явний аргумент, потім артефакти CI,
# потім `release/`, і лише потім типові локальні каталоги збірки.
$x86Dll = Find-CandidatePath @(
    $WindowsX86Dll,
    "artifacts/windows-x86/Tamga.dll",
    "release/Tamga_x86.dll",
    "build-windows-x86-release/Tamga.dll",
    "build-msvc-x86/Release/Tamga.dll",
    # Ninja (single-config): підкаталогу конфігурації немає.
    "build-x86-ship/Tamga.dll",
    "build-msvc-x86/Tamga.dll",
    "build-x86/Tamga.dll"
)
$x64Dll = Find-CandidatePath @(
    $WindowsX64Dll,
    "artifacts/windows-x64/Tamga.dll",
    "release/Tamga_x64.dll",
    "build-windows-x64-release/Tamga.dll",
    "build-msvc-x64/Release/Tamga.dll",
    "build-msvc/Release/Tamga.dll",
    # Ninja (single-config).
    "build-wave4-shipping/Tamga.dll",
    "build-msvc-x64/Tamga.dll",
    "build-x64/Tamga.dll"
)

# Пошук Linux бінарників
$x86So = Find-CandidatePath @(
    $LinuxX86So,
    "artifacts/linux-x86/libTamga.so",
    "artifacts/libTamga-linux-x86.so",
    "dist/libTamga-linux-x86.so",
    "build-linux-x86-release/libTamga.so"
)
$x64So = Find-CandidatePath @(
    $LinuxX64So,
    "artifacts/linux-x64/libTamga.so",
    "artifacts/libTamga-linux-x64.so",
    "dist/libTamga-linux-x64.so",
    "build-linux-x64-release/libTamga.so"
)

# Перевірка наявності Windows файлів
if (-not $x86Dll -or -not (Test-Path $x86Dll)) {
    Write-Warning "Windows x86 DLL not found."
} else {
    Write-Host "Found Windows x86: $x86Dll"
}

if (-not $x64Dll -or -not (Test-Path $x64Dll)) {
    Write-Warning "Windows x64 DLL not found."
} else {
    Write-Host "Found Windows x64: $x64Dll"
}

if ($RequireLinux) {
    if (-not $x86So -or -not (Test-Path $x86So)) {
        Write-Error "Linux x86 SO required but not found."
    }
    if (-not $x64So -or -not (Test-Path $x64So)) {
        Write-Error "Linux x64 SO required but not found."
    }
}

if ($x86So) { Write-Host "Found Linux x86: $x86So" }
if ($x64So) { Write-Host "Found Linux x64: $x64So" }

if (-not $x86Dll -and -not $x64Dll -and -not $x86So -and -not $x64So) {
    Write-Error "No component binaries found to pack into add-in archive."
}

# Тимчасовий каталог належить лише цьому запуску; готовий архів замінюється
# після успішного пакування. Невдалий запуск зберігає попередній результат.
$outPath = [IO.Path]::GetFullPath($(if ([IO.Path]::IsPathRooted($OutArchive)) { $OutArchive } else { Join-Path $projectRoot $OutArchive }))
$outParent = [IO.Path]::GetDirectoryName($outPath)
New-Item -ItemType Directory -Path $outParent -Force | Out-Null
$tempDir = [IO.Path]::GetFullPath((Join-Path $outParent ('.tamga-pack-' + [Guid]::NewGuid().ToString('N'))))
if (-not $tempDir.StartsWith($outParent.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe staging path' }
$null = New-Item -ItemType Directory -Path $tempDir
$tempArchive = $tempDir + '.zip'
try {

$componentsXml = [System.Collections.Generic.List[string]]::new()

if ($x86Dll -and (Test-Path $x86Dll)) {
    Copy-Item $x86Dll (Join-Path $tempDir "TamgaNative.dll") -Force
    $componentsXml.Add('    <component os="Windows" path="TamgaNative.dll" type="native" arch="i386" />')
}
if ($x64Dll -and (Test-Path $x64Dll)) {
    Copy-Item $x64Dll (Join-Path $tempDir "TamgaNative64.dll") -Force
    $componentsXml.Add('    <component os="Windows" path="TamgaNative64.dll" type="native" arch="x86_64" />')
}
if ($x86So -and (Test-Path $x86So)) {
    Copy-Item $x86So (Join-Path $tempDir "libTamga32.so") -Force
    $componentsXml.Add('    <component os="Linux" path="libTamga32.so" type="native" arch="i386" />')
}
if ($x64So -and (Test-Path $x64So)) {
    Copy-Item $x64So (Join-Path $tempDir "libTamga64.so") -Force
    $componentsXml.Add('    <component os="Linux" path="libTamga64.so" type="native" arch="x86_64" />')
}

# Створення MANIFEST.XML
$manifestLines = @(
    '<?xml version="1.0" encoding="UTF-8" ?>',
    '<bundle xmlns="http://v8.1c.ru/8.2/addin/bundle" name="Tamga">'
) + $componentsXml + @(
    '</bundle>'
)
$manifestContent = $manifestLines -join "`r`n"
$manifestPath = Join-Path $tempDir "MANIFEST.XML"
[System.IO.File]::WriteAllText($manifestPath, $manifestContent, [System.Text.Encoding]::UTF8)

# Створення ZIP архіву
Write-Host "Creating archive at $outPath..."
Compress-Archive -Path (Join-Path $tempDir "*") -DestinationPath $tempArchive
Move-Item -LiteralPath $tempArchive -Destination $outPath -Force

# Очищення
}
finally {
    if (Test-Path -LiteralPath $tempDir) { Remove-Item -LiteralPath $tempDir -Recurse -Force }
    if (Test-Path -LiteralPath $tempArchive) { Remove-Item -LiteralPath $tempArchive }
}

Write-Host "Success! Component is packed into $OutArchive with $($componentsXml.Count) component(s)."

