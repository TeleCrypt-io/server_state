#!/usr/bin/env bash

CONTAINER_HELPERS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CONTAINER_HELPERS_DIR

container_sensitive_failure_class() {
  case "${1:-}" in
    success|uid|mount-content|mount-owner|mount-mode|secrets-json|forbidden-mount|environment-leak)
      printf '%s\n' "$1"
      ;;
    *) return 1 ;;
  esac
}

container_sensitive_marker_class() {
  local output="${1:-}" candidate
  [[ -f "$output" ]] || return 1
  candidate="$(awk '
    NR == 1 && $0 ~ /^telecrypt-synapse-proof:(success|uid|mount-content|mount-owner|mount-mode|secrets-json|forbidden-mount|environment-leak)$/ {
      class = $0
      sub(/^telecrypt-synapse-proof:/, "", class)
      next
    }
    { invalid = 1 }
    END {
      if (NR == 1 && !invalid) print class
    }
  ' "$output" 2>/dev/null)" || return 1
  container_sensitive_failure_class "$candidate"
}

container_sensitive_proof_class() {
  local status="${1:-}" output="${2:-}" stderr_file="${3:-}" marker
  [[ "$status" =~ ^[0-9]+$ ]] || {
    printf '%s\n' 'bounded-command'
    return 0
  }
  marker="$(container_sensitive_marker_class "$output" || true)"
  if (( status != 0 )); then
    case "$marker" in
      uid|mount-content|mount-owner|mount-mode|secrets-json|forbidden-mount|environment-leak)
        container_sensitive_failure_class "$marker"
        ;;
      success)
        if [[ -s "$stderr_file" ]]; then
          printf '%s\n' 'stderr-diagnostics'
        else
          printf '%s\n' 'bounded-command'
        fi
        ;;
      '')
        if [[ -s "$output" ]]; then
          printf '%s\n' 'output-contract'
        else
          printf '%s\n' 'bounded-command'
        fi
        ;;
      *) printf '%s\n' 'output-contract' ;;
    esac
  elif [[ "$marker" == success ]]; then
    printf '%s\n' 'success'
  else
    printf '%s\n' 'output-contract'
  fi
}

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
