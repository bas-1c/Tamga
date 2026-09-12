#!/usr/bin/env bash
#
# Native Linux build for Tamga (x86-64 and x86 32-bit).
#
# Mirrors scripts/build-windows.ps1: configures with CMake, builds the
# NativeAPI .so, the standalone shared library and the CLI, optionally runs the
# test suite, and copies the deliverables into a per-arch build directory.
#
# Usage:
#   scripts/build-linux.sh [--arch x64|x86|all] [--config Release|Debug]
#                          [--enable-cryptonite|--disable-cryptonite]
#                          [--enable-xml-signatures] [--enable-pdf-signatures]
#                          [--static-third-party-deps] [--tests] [--tools]
#                          [--jobs N]
#
# Examples:
#   scripts/build-linux.sh                         # x64 Release, cryptonite ON
#   scripts/build-linux.sh --arch x86 --config Debug
#   scripts/build-linux.sh --arch all --tests      # CI/CD entry point
#   scripts/build-linux.sh --arch x64 --tests --static-third-party-deps
#
# Environment overrides:
#   CC / CXX   compilers to use (default: gcc-13 / g++-13 when present, else
#              gcc / g++).
#   VCPKG_ROOT root of vcpkg checkout for --static-third-party-deps.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ARCH="x64"
CONFIG="Release"
CRYPTONITE="ON"
BUILD_TESTS="OFF"
BUILD_TOOLS="OFF"
XML_SIGNATURES="OFF"
PDF_SIGNATURES="OFF"
STATIC_THIRD_PARTY_DEPS="OFF"
VCPKG_ROOT_ARG=""
VCPKG_TRIPLET_ARG=""
JOBS="$(nproc 2>/dev/null || echo 2)"

die() { echo "error: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)               [[ $# -ge 2 ]] || die "option $1 requires a value"; ARCH="$2"; shift 2 ;;
        --config)             [[ $# -ge 2 ]] || die "option $1 requires a value"; CONFIG="$2"; shift 2 ;;
        --enable-cryptonite)  CRYPTONITE="ON"; shift ;;
        --disable-cryptonite) CRYPTONITE="OFF"; shift ;;
        --enable-xml-signatures) XML_SIGNATURES="ON"; shift ;;
        --disable-xml-signatures) XML_SIGNATURES="OFF"; shift ;;
        --enable-pdf-signatures) PDF_SIGNATURES="ON"; shift ;;
        --disable-pdf-signatures) PDF_SIGNATURES="OFF"; shift ;;
        --static-third-party-deps) STATIC_THIRD_PARTY_DEPS="ON"; XML_SIGNATURES="ON"; PDF_SIGNATURES="ON"; shift ;;
        --vcpkg-root)         [[ $# -ge 2 ]] || die "option $1 requires a value"; VCPKG_ROOT_ARG="$2"; shift 2 ;;
        --vcpkg-triplet)      [[ $# -ge 2 ]] || die "option $1 requires a value"; VCPKG_TRIPLET_ARG="$2"; shift 2 ;;
        --tests)              BUILD_TESTS="ON"; shift ;;
        --tools)              BUILD_TOOLS="ON"; shift ;;
        --jobs)               [[ $# -ge 2 ]] || die "option $1 requires a value"; JOBS="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$ARCH" in
    x64|x86|all) ;;
    *) die "--arch must be one of: x64, x86, all (got '$ARCH')" ;;
esac
case "$CONFIG" in
    Release|Debug) ;;
    *) die "--config must be one of: Release, Debug (got '$CONFIG')" ;;
esac

# Prefer the pinned gcc-13/g++-13 toolchain, fall back to the default compiler.
if [[ -z "${CC:-}" ]]; then
    if command -v gcc-13 >/dev/null 2>&1; then CC="gcc-13"; else CC="gcc"; fi
fi
if [[ -z "${CXX:-}" ]]; then
    if command -v g++-13 >/dev/null 2>&1; then CXX="g++-13"; else CXX="g++"; fi
fi

build_one() {
    local target_arch="$1"
    local build_dir="$ROOT_DIR/build-${target_arch}-$(echo "$CONFIG" | tr '[:upper:]' '[:lower:]')"
    local vcpkg_triplet="$VCPKG_TRIPLET_ARG"
    local cmake_vcpkg_args=()

    local extra_flags=""
    local arch_args=()
    if [[ "$target_arch" == "x86" ]]; then
        # 32-bit build requires gcc-multilib and 32-bit runtime libraries.
        extra_flags="-m32 -march=i686 -msse2 -mfpmath=sse"
        # Розрядність задається ПРАПОРЦЯМИ компілятора, тож CMake далі вважає
        # систему x86_64 і шукає бібліотеки в /usr/lib/x86_64-linux-gnu. Для
        # libxml2 (безумовна залежність ядра з ADR-030) це давало 64-бітний
        # .so у 32-бітному лінкуванні і помилку «file in wrong format» — на
        # етапі ЛІНКУВАННЯ, а не конфігурації, тобто далеко від причини.
        # Спроба задати CMAKE_LIBRARY_ARCHITECTURE тут НЕ спрацювала: значення
        # перетирається під час визначення ABI компілятора (CMakeDetermineCompilerABI
        # виводить його з самого компілятора), і лінкування знову брало 64-бітний
        # .so. Тому шлях до 32-бітної libxml2 задається прямо — і лише якщо файл
        # справді на місці, інакше нехай падає звичайний find_package.
        local libxml2_i386="/usr/lib/i386-linux-gnu/libxml2.so"
        if [[ -f "$libxml2_i386" ]]; then
            arch_args+=(-DLIBXML2_LIBRARY="$libxml2_i386")
            [[ -d /usr/include/libxml2 ]] && arch_args+=(-DLIBXML2_INCLUDE_DIR=/usr/include/libxml2)
        fi
        # Для решти пошуків через pkg-config — той самий multiarch-каталог.
        if [[ -d /usr/lib/i386-linux-gnu/pkgconfig ]]; then
            export PKG_CONFIG_LIBDIR="/usr/lib/i386-linux-gnu/pkgconfig:/usr/share/pkgconfig"
        fi
        echo ">>> 32-bit build: ensure 'gcc-multilib'/'g++-multilib' and 32-bit"
        echo ">>> libc/libstdc++ are installed (Debian/Ubuntu: libc6-dev-i386)."
    fi

    if [[ "$STATIC_THIRD_PARTY_DEPS" == "ON" ]]; then
        local vcpkg_root="${VCPKG_ROOT_ARG:-${VCPKG_ROOT:-${VCPKG_INSTALLATION_ROOT:-}}}"
        [[ -n "$vcpkg_root" ]] || die "--static-third-party-deps requires VCPKG_ROOT or --vcpkg-root"
        [[ -f "$vcpkg_root/scripts/buildsystems/vcpkg.cmake" ]] || die "vcpkg toolchain not found: $vcpkg_root/scripts/buildsystems/vcpkg.cmake"

        if [[ -z "$vcpkg_triplet" ]]; then
            if [[ "$target_arch" == "x86" ]]; then
                vcpkg_triplet="x86-linux"
            else
                vcpkg_triplet="x64-linux"
            fi
        fi

        # VCPKG_MANIFEST_MODE і VCPKG_MANIFEST_FEATURES задаються ЯВНО, а не
        # лишаються на самовизначення toolchain.
        #
        # Причина конкретна. `scripts/buildsystems/vcpkg.cmake` вмикає
        # manifest-режим САМ, щойно бачить `vcpkg.json` у CMAKE_SOURCE_DIR:
        #   if(NOT DEFINED VCPKG_MANIFEST_DIR)
        #     if(EXISTS "${CMAKE_SOURCE_DIR}/vcpkg.json") ... endif()
        #   option(VCPKG_MANIFEST_MODE "..." "${Z_VCPKG_HAS_MANIFEST_DIR}")
        #   elseif(VCPKG_MANIFEST_MODE)
        #     set(... "${CMAKE_BINARY_DIR}/vcpkg_installed")
        # Тобто дерево залежностей береться з <build>/vcpkg_installed, а НЕ з
        # <VCPKG_ROOT>/installed, куди ставить класичний `vcpkg install` у
        # `release.yml`. А без VCPKG_MANIFEST_FEATURES manifest-режим ставить
        # лише кореневі `dependencies` маніфесту (сам libxml2) — без qpdf,
        # libjpeg-turbo і zlib, які дає фіча `pdf-signatures`.
        #
        # Наслідок для конфігурації постачання (тут XML/PDF примусово ON):
        # `find_package(qpdf CONFIG QUIET)` не знаходить нічого, і керування
        # доходить до `pkg_check_modules(QPDF REQUIRED ...)` у
        # `CMakeLists.txt:257-259`, тобто до фатальної помилки configure.
        #
        # Явні прапорці роблять Linux тим самим шляхом, що й Windows-джоби
        # (`release.yml`, `windows-static-shipping.yml`): один manifest-режим і
        # той самий набір фіч. Саме розходження між тим, ЩО тестується, і тим,
        # ЩО постачається, було причиною П-09.
        cmake_vcpkg_args+=(
            "-DCMAKE_TOOLCHAIN_FILE=$vcpkg_root/scripts/buildsystems/vcpkg.cmake"
            "-DVCPKG_TARGET_TRIPLET=$vcpkg_triplet"
            "-DVCPKG_OVERLAY_TRIPLETS=$ROOT_DIR/cmake/vcpkg-triplets"
            "-DVCPKG_MANIFEST_MODE=ON"
            "-DVCPKG_MANIFEST_FEATURES=xml-signatures;pdf-signatures"
            "-DCMAKE_DISABLE_FIND_PACKAGE_CURL=ON"
        )
        echo ">>> Static third-party dependency mode: vcpkg triplet $vcpkg_triplet"
    fi

    echo "==> Configuring $target_arch ($CONFIG) in $build_dir"
    cmake -S "$ROOT_DIR" -B "$build_dir" -G Ninja \
        "${cmake_vcpkg_args[@]}" \
        -DCMAKE_BUILD_TYPE="$CONFIG" \
        -DCMAKE_C_COMPILER="$CC" \
        -DCMAKE_CXX_COMPILER="$CXX" \
        -DCMAKE_C_FLAGS="$extra_flags" \
        -DCMAKE_CXX_FLAGS="$extra_flags" \
        "${arch_args[@]}" \
        -DTAMGA_ENABLE_VENDOR_CRYPTONITE="$CRYPTONITE" \
        -DTAMGA_ENABLE_XML_SIGNATURES="$XML_SIGNATURES" \
        -DTAMGA_ENABLE_PDF_SIGNATURES="$PDF_SIGNATURES" \
        -DTAMGA_BUILD_CLI=ON \
        -DTAMGA_BUILD_TESTS="$BUILD_TESTS" \
        -DTAMGA_BUILD_TOOLS="$BUILD_TOOLS"

    echo "==> Building $target_arch ($CONFIG)"
    cmake --build "$build_dir" --config "$CONFIG" --parallel "$JOBS"

    if [[ "$BUILD_TESTS" == "ON" ]]; then
        echo "==> Running tests for $target_arch"
        ctest --test-dir "$build_dir" -C "$CONFIG" --output-on-failure
    fi

    if [[ "$STATIC_THIRD_PARTY_DEPS" == "ON" ]]; then
        echo "==> Running static third-party dependency smoke gate for $target_arch"
        bash "$ROOT_DIR/scripts/build-linux-smoke.sh" --build-dir "$build_dir"
    fi

    local so="$build_dir/libTamga.so"
    [[ -f "$so" ]] || die "expected artifact not found: $so"

    echo "==> Artifacts in $build_dir:"
    echo "    $(basename "$so") -> $(file -b "$so")"
    echo "==> Shared library dependencies (ldd):"
    ldd "$so" || true
    echo "==> Exported NativeAPI symbols (expected exactly 5):"
    # List ALL defined dynamic symbols and compare to the expected set exactly,
    # so the check fails on both missing exports AND leaked extra symbols
    # (pre-filtering to the 5 names would hide leakage and always "pass").
    local exports expected
    exports="$(nm -D --defined-only "$so" 2>/dev/null | awk '{print $NF}' | sort || true)"
    echo "$exports" | sed 's/^/    /'
    expected="$(printf '%s\n' DestroyObject GetAttachType GetClassNames GetClassObject SetPlatformCapabilities | sort)"
    if [[ "$exports" != "$expected" ]]; then
        die "exported symbols do not match the expected 5 NativeAPI symbols exactly (possible leakage or missing export)"
    fi

    if [[ "$CONFIG" == "Release" ]]; then
        echo "==> Stripping unneeded symbols from release binaries ($target_arch)"
        strip --strip-unneeded "$so" 2>/dev/null || true
        [[ -f "$build_dir/libtamga-lib.so" ]] && strip --strip-unneeded "$build_dir/libtamga-lib.so" 2>/dev/null || true
        [[ -f "$build_dir/src/cli/tamga-cli" ]] && strip --strip-unneeded "$build_dir/src/cli/tamga-cli" 2>/dev/null || true
    fi
    echo "==> OK: $target_arch ($CONFIG)"
}

if [[ "$ARCH" == "all" ]]; then
    build_one x64
    build_one x86
else
    build_one "$ARCH"
fi

echo "All requested Linux builds completed."
