#!/usr/bin/env bash
set -euo pipefail

# Hardened offline TaskID / staging transcript analyzer: runs `artex-hunt analyze-tasks`
# inside a --network=none, read-only, non-root, capability-dropped container mounting
# ONLY the target quarantined file or directory read-only.
#
# WARNING — Operational Safety (Zero Bare-Metal Exposure):
# Never browse, curl, download, or inspect raw attacker directories (SimpleHTTP),
# exposed operator consoles, or suspect C2 infrastructure from a bare-metal host.
# Only pass transcripts exported from passive intel platforms or an air-gapped Tier 3 VM.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE_NAME="artex-defense-sandbox:latest"

usage() {
  cat <<EOF
Usage: $(basename "$0") <quarantined_task_file_or_dir> [output_json_file]

Runs \`artex-hunt analyze-tasks\` inside the hardened offline Docker sandbox
(--network=none, --read-only, --cap-drop=ALL, non-root) to extract tool
distributions and failure->retry chains with mandatory secret/IP/domain
redaction and defanging.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]]; then
  usage
  exit 1
fi

INPUT_PATH="$(realpath "$1")"
OUTPUT_FILE="${2:-}"

if [[ ! -e "$INPUT_PATH" ]]; then
  echo "Error: input path not found: $INPUT_PATH" >&2
  exit 1
fi

if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
  echo "Building hardened sandbox image $IMAGE_NAME..."
  docker build -f "${PROJECT_DIR}/docker/Dockerfile.sandbox" -t "$IMAGE_NAME" "$PROJECT_DIR"
fi

if [[ -d "$INPUT_PATH" ]]; then
  CONTAINER_TARGET="/quarantine/tasks"
else
  INPUT_BASE="$(basename "$INPUT_PATH")"
  CONTAINER_TARGET="/quarantine/${INPUT_BASE}"
fi

DOCKER_ARGS=(
  run --rm
  --user "$(id -u):$(id -g)"
  --network=none
  --read-only
  --cap-drop=ALL
  --security-opt=no-new-privileges:true
  --pids-limit=128
  --memory=2g
  --cpus=4
  --tmpfs /tmp:rw,noexec,nosuid,size=256m
  -v "${INPUT_PATH}:${CONTAINER_TARGET}:ro"
)

if [[ -n "$OUTPUT_FILE" ]]; then
  OUT_DIR="$(dirname "$(realpath -m "$OUTPUT_FILE")")"
  OUT_BASE="$(basename "$OUTPUT_FILE")"
  mkdir -p "$OUT_DIR"
  DOCKER_ARGS+=(-v "${OUT_DIR}:/out:rw")
  exec docker "${DOCKER_ARGS[@]}" "$IMAGE_NAME" analyze-tasks "$CONTAINER_TARGET" --out "/out/${OUT_BASE}"
else
  exec docker "${DOCKER_ARGS[@]}" "$IMAGE_NAME" analyze-tasks "$CONTAINER_TARGET"
fi
