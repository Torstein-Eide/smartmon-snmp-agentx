#!/bin/bash
# Build and export a Debian 11-linked smartmon-snmp-agentxd binary.
#
# Step 1: docker build  — creates/refreshes the toolchain image (cached).
# Step 2: docker run    — mounts repo, object cache, and output dir; runs make
#                         inside the container so artifacts land on the host.
#
# Object files are cached in .tmp/debian11-build between runs so only changed
# files are recompiled.  Pass --no-cache to wipe the object cache and force a
# full rebuild.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE_TAG="smartmon-agentxd:debian11-build"
OUTPUT_DIR="$REPO_ROOT/.tmp/export/debian11"
OBJ_CACHE_DIR="$REPO_ROOT/.tmp/debian11-build"
DOCKERFILE="$REPO_ROOT/ci/Dockerfile.debian11"
BUILD_ARGS=()
SKIP_TESTS=0
CLEAN_OBJS=0

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --tag TAG       Docker image tag (default: $IMAGE_TAG)
  --output DIR    Export directory (default: .tmp/export/debian11)
  --no-cache      Wipe object cache and rebuild toolchain image from scratch
  --no-tests      Skip unit tests during the build
  -h, --help      Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --tag)
            [ -n "${2-}" ] && [[ "$2" != -* ]] || { echo "ERROR: --tag requires a value" >&2; exit 2; }
            IMAGE_TAG="$2"
            shift 2
            ;;
        --output)
            [ -n "${2-}" ] && [[ "$2" != -* ]] || { echo "ERROR: --output requires a directory" >&2; exit 2; }
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --no-cache)
            BUILD_ARGS+=(--no-cache)
            CLEAN_OBJS=1
            shift
            ;;
        --no-tests)
            SKIP_TESTS=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Step 1: build (or reuse cached) toolchain image
# ---------------------------------------------------------------------------
echo "=== Step 1: toolchain image ==="
echo "  image     : $IMAGE_TAG"
echo "  dockerfile: $DOCKERFILE"
docker build "${BUILD_ARGS[@]}" -f "$DOCKERFILE" -t "$IMAGE_TAG" "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Step 2: compile inside container with repo + caches mounted
# ---------------------------------------------------------------------------
if [ "$CLEAN_OBJS" = "1" ]; then
    echo "=== Wiping object cache ==="
    rm -rf "$OBJ_CACHE_DIR"
fi

mkdir -p "$OBJ_CACHE_DIR"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

echo "=== Step 2: compile ==="
echo "  source    : $REPO_ROOT"
echo "  obj cache : $OBJ_CACHE_DIR"
echo "  output    : $OUTPUT_DIR"

docker run --rm \
    -v "$REPO_ROOT:/src:ro" \
    -v "$OBJ_CACHE_DIR:/build" \
    -v "$OUTPUT_DIR:/out" \
    "$IMAGE_TAG" \
    bash -euo pipefail -c "
        make -C /src BUILDDIR=/build SYSCONFDIR=/etc NET_SNMP_CONFIG=/usr/bin/net-snmp-config
        $([ "$SKIP_TESTS" = "1" ] || echo 'make -C /src/tests test SRCDIR=/src/src REPO_ROOT=/src BUILDDIR=/build/tests')
        cp /build/smartmon-snmp-agentxd /out/
        file /out/smartmon-snmp-agentxd | tee /out/file.txt
        ldd  /out/smartmon-snmp-agentxd | tee /out/ldd.txt
        ! grep -q '/usr/local' /out/ldd.txt
        dpkg-query -W \
            g++ \
            libsnmp-dev \
            libsnmp40 \
            libsystemd-dev \
            libsystemd0 \
            make \
            snmp \
            snmpd \
            > /out/packages.txt
        {
            echo \"Built in: debian:11-slim\"
            echo \"Compiler: \$(g++ --version | head -n 1)\"
            echo \"net-snmp-config: \$(command -v net-snmp-config)\"
            echo \"net-snmp libs: \$(net-snmp-config --agent-libs)\"
        } > /out/build-info.txt
    "

echo "=== Exported Debian 11 artifacts ==="
ls -lh "$OUTPUT_DIR"

echo "=== Linkage ==="
cat "$OUTPUT_DIR/ldd.txt"

echo "=== Debian 11 export ready ==="
echo "  binary: $OUTPUT_DIR/smartmon-snmp-agentxd"
