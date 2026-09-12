#!/usr/bin/env bash
#
# Linux release smoke gate for the NativeAPI artifact and CLI.
#
# The gate intentionally allows the normal platform runtime, but rejects
# Tamga/XML/PDF/OpenSSL/zlib/JPEG/Curl runtime .so dependencies that must be
# linked statically or disabled for release artifacts.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR=""
REPORT_PATH=""

die() { echo "error: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir) [[ $# -ge 2 ]] || die "option $1 requires a value"; BUILD_DIR="$2"; shift 2 ;;
        --report)    [[ $# -ge 2 ]] || die "option $1 requires a value"; REPORT_PATH="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$BUILD_DIR" ]] || die "--build-dir is required"
if [[ "$BUILD_DIR" != /* ]]; then
    BUILD_DIR="$ROOT_DIR/$BUILD_DIR"
fi
REPORT_PATH="${REPORT_PATH:-$BUILD_DIR/linux-smoke-report.txt}"

nativeapi="$BUILD_DIR/libTamga.so"
cli="$BUILD_DIR/src/cli/tamga-cli"
[[ -f "$nativeapi" ]] || die "libTamga.so not found: $nativeapi"
[[ -f "$cli" ]] || die "tamga-cli not found: $cli"

command -v readelf >/dev/null 2>&1 || die "readelf is unavailable in PATH"
command -v nm >/dev/null 2>&1 || die "nm is unavailable in PATH"

allowed_regex='^(libc\.so|libc\.so\..*|libm\.so|libm\.so\..*|libstdc\+\+\.so|libstdc\+\+\.so\..*|libgcc_s\.so|libgcc_s\.so\..*|libpthread\.so|libpthread\.so\..*|libdl\.so|libdl\.so\..*|librt\.so|librt\.so\..*|ld-linux\.so\.2|ld-linux-x86-64\.so\.2)$'
forbidden_regex='^(libtamga-lib\.so.*|libxml2\.so.*|libxmlsec.*\.so.*|libqpdf\.so.*|libcrypto\.so.*|libssl\.so.*|libz\.so.*|zlib\.so.*|libjpeg.*\.so.*|libturbojpeg.*\.so.*|libcurl\.so.*)$'

list_elf_needed_deps() {
    local binary="$1"
    readelf -d "$binary" |
        sed -n 's/.*(NEEDED).*Shared library: \[\([^]]*\)\].*/\1/p' |
        sort -u
}

check_no_unexpected_dynamic_deps() {
    local binary="$1"
    local label="$2"
    local deps dep bad=()

    {
        echo
        echo "===== readelf -d $label ====="
        # DT_NEEDED is the linker-authored dependency list. Unlike ldd output,
        # it does not include linux-vdso.so.1. The glibc loader can also be
        # an explicit DT_NEEDED dependency and is part of the platform runtime.
        readelf -d "$binary"
        echo
        echo "===== DT_NEEDED $label ====="
        list_elf_needed_deps "$binary" | sed 's/^/    /'
    } >> "$REPORT_PATH"

    deps="$(list_elf_needed_deps "$binary")"
    while IFS= read -r dep; do
        [[ -n "$dep" ]] || continue
        if [[ "$dep" =~ $forbidden_regex ]]; then
            bad+=("$dep")
            continue
        fi
        if [[ ! "$dep" =~ $allowed_regex ]]; then
            bad+=("$dep")
        fi
    done <<< "$deps"

    if [[ "${#bad[@]}" -gt 0 ]]; then
        die "dependency gate failed for $label: ${bad[*]}"
    fi
}

check_exports() {
    local exports expected
    {
        echo
        echo "===== nm -D --defined-only libTamga.so ====="
        nm -D --defined-only "$nativeapi"
    } >> "$REPORT_PATH"

    exports="$(nm -D --defined-only "$nativeapi" 2>/dev/null | awk '{print $NF}' | sort || true)"
    expected="$(printf '%s\n' DestroyObject GetAttachType GetClassNames GetClassObject SetPlatformCapabilities | sort)"
    if [[ "$exports" != "$expected" ]]; then
        die "export gate failed: expected exactly 5 NativeAPI symbols, got: $(echo "$exports" | tr '\n' ' ')"
    fi
}

mkdir -p "$(dirname "$REPORT_PATH")"
{
    echo "Tamga Linux smoke report"
    echo "Build dir: $BUILD_DIR"
    echo "NativeAPI: $nativeapi"
    echo "CLI: $cli"
} > "$REPORT_PATH"

check_no_unexpected_dynamic_deps "$nativeapi" "libTamga.so"
check_no_unexpected_dynamic_deps "$cli" "tamga-cli"
check_exports

{
    echo
    echo "===== gate summary ====="
    echo "Dependency gate: PASS (no libtamga-lib/XML/PDF/OpenSSL/zlib/JPEG/Curl runtime .so dependencies)."
    echo "Export gate: PASS (exactly 5 NativeAPI symbols)."
    echo "All Linux smoke gates passed."
} >> "$REPORT_PATH"

echo "Linux runtime/export smoke checks passed. Report: $REPORT_PATH"
