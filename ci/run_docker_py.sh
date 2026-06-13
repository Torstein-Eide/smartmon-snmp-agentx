#!/bin/bash
# ci/run_docker_py.sh - build the Python AgentX test image and run integration tests.

set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --no-cache          Build the Docker image without cache
  --tag TAG           Docker image tag (default: smartmon-agentx-py-test:local)
  --fixtures DIR      Mount committed-style fixture JSON files from DIR
  --output DIR        Write test output to DIR (default: .tmp/test-py)
  --debug             Run agent with --log-level VERBOSE
  --debug-full        Run agent with --log-level DEBUG and net-snmp AgentX debug logs
  --debug-net-snmp    Enable net-snmp AgentX/callback debug logs
  -h, --help          Show this help
EOF
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE_TAG="smartmon-agentx-py-test:local"
DOCKERFILE="$REPO_ROOT/ci/Dockerfile.agentx_py"
FIXTURES_DIR=""
OUTPUT_DIR="$REPO_ROOT/.tmp/test-py"
BUILD_ARGS=()
RUN_ARGS=(--rm --cap-add NET_BIND_SERVICE)

while [ $# -gt 0 ]; do
    case "$1" in
        --no-cache)
            BUILD_ARGS+=(--no-cache)
            shift
            ;;
        --tag)
            [ -n "${2-}" ] && [[ "$2" != -* ]] || { echo "ERROR: --tag requires a value" >&2; exit 2; }
            IMAGE_TAG="$2"
            shift 2
            ;;
        --fixtures)
            [ -n "${2-}" ] && [[ "$2" != -* ]] || { echo "ERROR: --fixtures requires a directory" >&2; exit 2; }
            FIXTURES_DIR="$2"
            shift 2
            ;;
        --output)
            [ -n "${2-}" ] && [[ "$2" != -* ]] || { echo "ERROR: --output requires a directory" >&2; exit 2; }
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --debug)
            RUN_ARGS+=(-e AGENTXD_EXTRA_ARGS=--log-level=VERBOSE)
            shift
            ;;
        --debug-full)
            RUN_ARGS+=(
                -e AGENTXD_EXTRA_ARGS=--log-level=DEBUG
                -e AGENTXD_NETSNMP_LOG=1
                -e AGENTXD_NETSNMP_DEBUG=agentx,callback,transport,snmp_agent
                -e SNMPD_EXTRA_ARGS=-Dagentx,callback,transport,snmp_agent
            )
            shift
            ;;
        --debug-net-snmp)
            RUN_ARGS+=(
                -e AGENTXD_NETSNMP_LOG=1
                -e AGENTXD_NETSNMP_DEBUG=agentx,callback,transport,snmp_agent
                -e SNMPD_EXTRA_ARGS=-Dagentx,callback,transport,snmp_agent
            )
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

echo "=== Building Docker image ==="
echo "  tag       : $IMAGE_TAG"
echo "  dockerfile: $DOCKERFILE"
docker build "${BUILD_ARGS[@]}" -f "$DOCKERFILE" -t "$IMAGE_TAG" "$REPO_ROOT"

RUN_ARGS+=(-v "$OUTPUT_DIR:/output")

if [ -n "$FIXTURES_DIR" ] && [ -d "$FIXTURES_DIR" ] && compgen -G "$FIXTURES_DIR/*.json" >/dev/null; then
    echo "  fixtures  : $FIXTURES_DIR"
    RUN_ARGS+=(-v "$FIXTURES_DIR:/fixtures:ro" -e FIXTURES=/fixtures)
else
    echo "  fixtures  : image defaults"
fi

RUN_ARGS+=(-e AGENTXD_BIN=/src/smartmon_agentx.py)

echo "  output    : $OUTPUT_DIR"
echo "=== Running integration test ==="
docker run "${RUN_ARGS[@]}" "$IMAGE_TAG" \
    python3 /src/ci/run_integration_test.py \
    --config /src/ci/integration_test.yaml

echo "=== Output ==="
ls -lh "$OUTPUT_DIR" 2>/dev/null || true
RUN_INFO="$OUTPUT_DIR/run-info.txt"
[ -f "$RUN_INFO" ] && { echo "--- run-info.txt ---"; cat "$RUN_INFO"; }
