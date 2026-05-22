#!/bin/bash
# Build and export a Debian 11-linked smartmon-snmp-agentxd binary.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE_TAG="smartmon-agentxd:debian11-export"
OUTPUT_DIR="$REPO_ROOT/.tmp/export/debian11"
DOCKERFILE="$REPO_ROOT/ci/Dockerfile.debian11"
BUILD_ARGS=()

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --tag TAG       Docker image tag (default: $IMAGE_TAG)
  --output DIR    Export directory (default: .tmp/export/debian11)
  --no-cache      Build without Docker cache
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

mkdir -p "$OUTPUT_DIR"

echo "=== Building Debian 11 export image ==="
echo "  image     : $IMAGE_TAG"
echo "  dockerfile: $DOCKERFILE"
docker build "${BUILD_ARGS[@]}" -f "$DOCKERFILE" -t "$IMAGE_TAG" "$REPO_ROOT"

container=""
cleanup() {
    [ -n "$container" ] && docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

container="$(docker create "$IMAGE_TAG")"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
docker cp "$container:/out/." "$OUTPUT_DIR/"

echo "=== Exported Debian 11 artifacts ==="
ls -lh "$OUTPUT_DIR"

echo "=== Linkage ==="
cat "$OUTPUT_DIR/ldd.txt"

if grep -q '/usr/local' "$OUTPUT_DIR/ldd.txt"; then
    echo "ERROR: exported binary links against /usr/local libraries" >&2
    exit 1
fi

echo "=== Debian 11 export ready ==="
echo "  binary: $OUTPUT_DIR/smartmon-snmp-agentxd"
