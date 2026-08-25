#!/usr/bin/env bash

CONTAINER_HELPERS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CONTAINER_HELPERS_DIR

container_bounded() {
  local inherit_stdin=false
  local sensitive=false
  while [[ "${1:-}" == --* ]]; do
    case "$1" in
      --inherit-stdin) inherit_stdin=true ;;
      --sensitive) sensitive=true ;;
      *) return 2 ;;
    esac
    shift
  done
  local max_bytes="$1" output="$2" timeout_seconds="$3" stderr_file status
  shift 3
  [[ "$max_bytes" =~ ^[1-9][0-9]*$ && "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || return 2
  [[ $# -gt 0 ]] || return 2
  stderr_file="${output}.stderr"
  local bounded_args=(--separate "$max_bytes" "$max_bytes" "$output" "$stderr_file" "$timeout_seconds")
  if [[ "$inherit_stdin" == true ]]; then
    bounded_args=(--inherit-stdin "${bounded_args[@]}")
  fi
  bounded_args+=("$@")
  if "$CONTAINER_HELPERS_DIR/run_bounded_combined.sh" "${bounded_args[@]}"; then
    status=0
  else
    status="$?"
  fi
  if [[ "$sensitive" == false ]]; then
    cat -- "$output"
    if [[ -s "$stderr_file" ]]; then
      cat -- "$stderr_file" >&2
    fi
  fi
  if (( status != 0 )); then
    if [[ "$sensitive" == false ]]; then
      rm -f -- "$stderr_file"
    fi
    return "$status"
  fi
  if grep -Eaiq '(^|[^[:alnum:]_])(warn(ing)?s?|errors?|fatals?|fail(ed|ure|ures)?|denied|unauthorized)([^[:alnum:]_]|$)' "$stderr_file"; then
    if [[ "$sensitive" == false ]]; then
      echo 'successful container command emitted failure diagnostics' >&2
    fi
    if [[ "$sensitive" == false ]]; then
      rm -f -- "$stderr_file"
    fi
    return 1
  fi
  if [[ "$sensitive" == false ]]; then
    rm -f -- "$stderr_file"
  fi
}
