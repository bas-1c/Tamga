# Підготовка випуску

1. Звір версію `CMakeLists.txt`, `vcpkg.json` і тег. Запусти [shipping-збірки](building.md) для потрібних архітектур, CTest, export gates і installed package consumer.
2. Відтвори vendor: `pwsh -File scripts/verify-cryptonite-patches.ps1`. Upstream commit і проєкцію файлів задають `patches/cryptonite/upstream.json` та `excluded-paths.json`.
3. Для кожної конфігурації згенеруй SBOM: `pwsh -File scripts/generate-sbom.ps1 -BuildDir <build> -OutDir <sbom>`. Скрипт також створює `licenses-<triplet>.zip` із повними текстами умов; відсутній copyright потрібного порту завершує перевірку помилкою. Для x64 Windows shipping додай `-CheckNotices`.
4. Перевір runtime-залежності (`dumpbin /DEPENDENTS` на Windows), склад source-архіву, ліцензії та повні notices. Невизначені права перелічені в [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
5. Збери пакет: `pwsh -File scripts/pack-addon.ps1 -WindowsX86Dll <x86.dll> -WindowsX64Dll <x64.dll> -OutArchive <Tamga.zip>`. Для повного Linux-пакета передай обидва `.so` і `-RequireLinux`.
6. Публікуй перевірені бінарники, SBOM і hashes як release assets. Workflow `release.yml` запускається тегом або вручну; артефакти збірки в Git не накопичуються.

## Випуск через GitHub Actions

Після push перевіреного commit у `main` запусти:

```sh
gh workflow run release.yml --repo bas-1c/Tamga --ref main -f tag=v0.10.0 -f prerelease=false
```

Тег має відповідати версії у `vcpkg.json`. Workflow перевіряє vendor patches, збирає й тестує Windows/Linux x86/x64 з XML/PDF та статичними сторонніми залежностями. Публікація виконується тільки після успіху всіх платформ, smoke gates і генерації SBOM.

Для встановлення компоненти в 1С/BAS потрібен `Tamga.zip`: `MANIFEST.XML`, `TamgaNative.dll`, `TamgaNative64.dll`, `libTamga32.so`, `libTamga64.so`. Разом із ним поширюй `Tamga-licenses.zip` із повними умовами для всіх чотирьох збірок. Окремі бінарники, CLI, SBOM і link maps також доступні в assets випуску.

`scripts/prepare-release.py` перевіряє архітектуру PE/ELF, повноту manifest та збіг hashes упакованих компонентів з CI artifacts. `release-manifest.json` фіксує commit джерел і SHA-256 чотирьох компонентів; `SHA256SUMS.txt` містить контрольні суми всіх assets, крім самого файлу сум.
