#!/usr/bin/env bash
set -euo pipefail

# Hardened offline Stage 1 scanner: runs artex-hunt inside a --network=none,
# read-only, non-root, capability-dropped container mounting ONLY the target file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE_NAME="artex-defense-sandbox:latest"

usage() {
  cat <<EOF
Usage: $(basename "$0") <input_jsonl_file> [output_json_file]

Builds (if needed) and runs the hardened offline Docker sandbox (--network=none,
--read-only, --cap-drop=ALL, non-root) to scan and sanitize untrusted telemetry.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]]; then
  usage
  exit 1
fi

INPUT_FILE="$(realpath "$1")"
OUTPUT_FILE="${2:-}"

if [[ ! -f "$INPUT_FILE" ]]; then
  echo "Error: input file not found: $INPUT_FILE" >&2
  exit 1
fi

if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
  echo "Building hardened sandbox image $IMAGE_NAME..."
  docker build -f "${PROJECT_DIR}/docker/Dockerfile.sandbox" -t "$IMAGE_NAME" "$PROJECT_DIR"
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
  -v "${INPUT_FILE}:/quarantine/input.jsonl:ro"
)

if [[ -n "$OUTPUT_FILE" ]]; then
  OUT_DIR="$(dirname "$(realpath -m "$OUTPUT_FILE")")"
  OUT_BASE="$(basename "$OUTPUT_FILE")"
  mkdir -p "$OUT_DIR"
  DOCKER_ARGS+=(-v "${OUT_DIR}:/out:rw")
  exec docker "${DOCKER_ARGS[@]}" "$IMAGE_NAME" scan /quarantine/input.jsonl --sanitize --out "/out/${OUT_BASE}"
else
  exec docker "${DOCKER_ARGS[@]}" "$IMAGE_NAME" scan /quarantine/input.jsonl --sanitize
fi
