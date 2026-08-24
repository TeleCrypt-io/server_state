#!/usr/bin/env bash
set -euo pipefail

mode=combined
max_bytes=65536
timeout_seconds=180
if [[ "${1:-}" == "--separate" ]]; then
  mode=separate
  max_stdout="${2:?maximum stdout bytes are required}"
  max_stderr="${3:?maximum stderr bytes are required}"
  stdout_output="${4:?stdout output path is required}"
  stderr_output="${5:?stderr output path is required}"
  timeout_seconds="${6:?timeout seconds are required}"
  shift 6
elif [[ "${1:-}" == "--max-bytes" ]]; then
  max_bytes="${2:?maximum output bytes are required}"
  shift 2
fi
if [[ "$mode" == combined ]]; then
  output="${1:?output path is required}"
  shift
fi
[[ $# -gt 0 ]] || { printf 'bounded command is required\n' >&2; exit 64; }
if [[ "$mode" == separate ]]; then
  [[ "$max_stdout" =~ ^[1-9][0-9]*$ && "$max_stderr" =~ ^[1-9][0-9]*$ ]] || {
    printf 'maximum stream bytes must be positive\n' >&2
    exit 64
  }
else
  [[ "$max_bytes" =~ ^[1-9][0-9]*$ ]] || { printf 'maximum output bytes must be positive\n' >&2; exit 64; }
  max_stdout="$max_bytes"
  max_stderr="$max_bytes"
fi
[[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || { printf 'timeout seconds must be positive\n' >&2; exit 64; }

temporary="$(mktemp -d)"
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT
trap 'cleanup; exit 143' HUP INT TERM
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
set +e
if [[ "$mode" == separate ]]; then
  /usr/bin/python3 "$script_dir/bounded-command.py" \
    --stdout-limit "$max_stdout" --stderr-limit "$max_stderr" \
    --stdout-path "$temporary/stdout" --stderr-path "$temporary/stderr" \
    --timeout "$timeout_seconds" -- "$@"
  status=$?
else
  /usr/bin/python3 "$script_dir/bounded-command.py" \
    --stdout-limit "$max_bytes" --stderr-limit "$max_bytes" \
    --stdout-path "$temporary/stdout" --stderr-path "$temporary/stderr" \
    --combined-limit "$max_bytes" --timeout "$timeout_seconds" -- "$@"
  status=$?
fi
set -e
if [[ "$mode" == separate ]]; then
  cp -- "$temporary/stdout" "$stdout_output"
  cp -- "$temporary/stderr" "$stderr_output"
else
  cat -- "$temporary/stdout" "$temporary/stderr" >"$output"
  if (( $(wc -c <"$output") > max_bytes )); then
    printf 'bounded combined output exceeded %s bytes\n' "$max_bytes" >&2
    exit 1
  fi
fi
if (( status != 0 )); then
  exit "$status"
fi
