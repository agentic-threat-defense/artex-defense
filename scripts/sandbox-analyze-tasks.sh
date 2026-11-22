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
if [[ "$INPUT_PATH" == *:* || "$INPUT_PATH" == *,* || "$INPUT_PATH" == *$'\n'* ]]; then
  echo "Error: input path contains unsupported mount delimiters (':' or ',')." >&2
  exit 1
fi

if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
  echo "Building hardened sandbox image $IMAGE_NAME..."
  docker build -f "${PROJECT_DIR}/docker/Dockerfile.sandbox" -t "$IMAGE_NAME" "$PROJECT_DIR"
fi

if [[ -d "$INPUT_PATH" ]]; then
  CONTAINER_TARGET="/quarantine/tasks"
else
  SAFE_BASE="$(basename "$INPUT_PATH" | tr -c 'A-Za-z0-9._-' '_' | sed 's/^-*/input_/')"
  [[ -z "$SAFE_BASE" || "$SAFE_BASE" == "." || "$SAFE_BASE" == ".." ]] && SAFE_BASE="input_artifact.jsonl"
  CONTAINER_TARGET="/quarantine/${SAFE_BASE}"
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
  --mount "type=bind,source=${INPUT_PATH},target=${CONTAINER_TARGET},readonly"
)

if [[ -n "$OUTPUT_FILE" ]]; then
  OUT_REAL="$(realpath -m "$OUTPUT_FILE")"
  OUT_DIR="$(dirname "$OUT_REAL")"
  OUT_BASE="$(basename "$OUT_REAL")"
  if [[ "$OUT_DIR" == "/" || "$OUT_DIR" == "$HOME" ]]; then
    echo "Error: refusing to mount '$OUT_DIR' read-write into sandbox; use a dedicated output subdirectory." >&2
    exit 1
  fi
  if [[ "$OUT_DIR" == *:* || "$OUT_DIR" == *,* || "$OUT_BASE" == -* || "$OUT_BASE" =~ [^A-Za-z0-9._-] ]]; then
    echo "Error: unsafe output path or filename: $OUTPUT_FILE" >&2
    exit 1
  fi
  mkdir -p "$OUT_DIR"
  DOCKER_ARGS+=(--mount "type=bind,source=${OUT_DIR},target=/out")
  exec docker "${DOCKER_ARGS[@]}" "$IMAGE_NAME" analyze-tasks --out "/out/${OUT_BASE}" -- "$CONTAINER_TARGET"
else
  exec docker "${DOCKER_ARGS[@]}" "$IMAGE_NAME" analyze-tasks -- "$CONTAINER_TARGET"
fi
