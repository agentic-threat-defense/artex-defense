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
if [[ "$INPUT_FILE" == *:* || "$INPUT_FILE" == *,* || "$INPUT_FILE" == *$'\n'* ]]; then
  echo "Error: input file path contains unsupported mount delimiters (':' or ',')." >&2
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
  --mount "type=bind,source=${INPUT_FILE},target=/quarantine/input.jsonl,readonly"
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
  exec docker "${DOCKER_ARGS[@]}" "$IMAGE_NAME" scan --sanitize --out "/out/${OUT_BASE}" -- /quarantine/input.jsonl
else
  exec docker "${DOCKER_ARGS[@]}" "$IMAGE_NAME" scan --sanitize -- /quarantine/input.jsonl
fi
