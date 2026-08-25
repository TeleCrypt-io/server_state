#!/usr/bin/env bash

CONTAINER_HELPERS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CONTAINER_HELPERS_DIR

container_sensitive_failure_class() {
  case "${1:-}" in
    success|uid|mount-content|secrets-json|forbidden-mount|environment-leak)
      printf '%s\n' "$1"
      ;;
    *) return 1 ;;
  esac
}

container_sensitive_marker_class() {
  local output="${1:-}" candidate
  [[ -f "$output" ]] || return 1
  candidate="$(awk '
    NR == 1 && $0 ~ /^telecrypt-synapse-proof:(success|uid|mount-content|secrets-json|forbidden-mount|environment-leak)$/ {
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

container_sensitive_preflight_failure_class() {
  case "${1:-}" in
    image-pull|registry-auth|mount-source|entrypoint-executable|compose-secrets|compose-config|runtime-permission|file-shape|oci-runtime|daemon-resource|timeout|container-runtime)
      printf '%s\n' "$1"
      ;;
    *) return 1 ;;
  esac
}

container_sensitive_preflight_class() {
  local stderr_file="${1:-}" candidate
  [[ -f "$stderr_file" ]] || return 1
  candidate="$(awk '
    {
      line = tolower($0)
      if (line ~ /timed[[:space:]]+out|timeout|i\/o timeout|deadline exceeded|context deadline/) {
        print "timeout"
        exit
      }
      if (line ~ /unauthorized|authentication required|authentication failed|pull access denied|denied: requested access|requested access to the resource is denied|insufficient_scope|login required|may require.*docker login/) {
        print "registry-auth"
        exit
      }
      if (line ~ /required variable[^[:alnum:]]+.*(not set|is required|missing|empty)|variable[^[:alnum:]]+.*(not set|is required|missing|empty)|interpolation|invalid compose (file|configuration)|compose[^[:alnum:]]+(config|file)[^[:alnum:]]+.*(invalid|failed|error)|additional property.*(not allowed|is required)|refers to undefined|external[^[:alnum:]]+.*could not be found/) {
        print "compose-config"
        exit
      }
      if (line ~ /manifest unknown|no matching manifest|failed to (resolve|pull|fetch)|failed to copy|image[^[:alnum:]]+not found|repository[^[:alnum:]]+not found/) {
        print "image-pull"
        exit
      }
      if (line ~ /executable file not found|exec format error|oci runtime create failed.*exec|exec[^[:alnum:]]+.*(not found|no such file)|cannot start service.*exec/) {
        print "entrypoint-executable"
        exit
      }
      if (line ~ /invalid mount config|mounts denied|bind source path does not exist|source path[^[:alnum:]]+does not exist|mount[^[:alnum:]]+(source|no such file|does not exist)/) {
        print "mount-source"
        exit
      }
      if (line ~ /secret[^[:alnum:]]+(not found|missing|source|environment|file|mount)|failed to create secret|invalid[^[:alnum:]]+secret|secrets?[^[:alnum:]]+(required|not set)/) {
        print "compose-secrets"
        exit
      }
      if (line ~ /permission denied|operation not permitted|operation not allowed|read-only file system|access denied/) {
        print "runtime-permission"
        exit
      }
      if (line ~ /not a directory|is a directory|no such file or directory|not a file|expected (a )?(file|directory)/) {
        print "file-shape"
        exit
      }
      if (line ~ /oci runtime|runc|failed to create (a )?(shim )?task|failed to start (the )?container|failed to initialize|container process|failed to mount|mount[^[:alnum:]]+failed/) {
        print "oci-runtime"
        exit
      }
      if (line ~ /cannot connect to the docker daemon|is the docker daemon running|error during connect|connection refused|daemon[^[:alnum:]]+(unavailable|not running|error)|no space left on device|resource temporarily unavailable|too many open files|out of memory|quota exceeded|device or resource busy|failed to create[^[:alnum:]]+(container|network|shim task)|network[^[:alnum:]]+(not found|unavailable|error)/) {
        print "daemon-resource"
        exit
      }
    }
  ' "$stderr_file" 2>/dev/null)" || return 1
  if [[ -n "$candidate" ]]; then
    container_sensitive_preflight_failure_class "$candidate"
  elif [[ -s "$stderr_file" ]]; then
    printf '%s\n' 'container-runtime'
  else
    return 1
  fi
}

container_sensitive_proof_class() {
  local status="${1:-}" output="${2:-}" stderr_file="${3:-}" marker preflight_class
  [[ "$status" =~ ^[0-9]+$ ]] || {
    printf '%s\n' 'bounded-command'
    return 0
  }
  marker="$(container_sensitive_marker_class "$output" || true)"
  if (( status != 0 )); then
    case "$marker" in
      uid|mount-content|secrets-json|forbidden-mount|environment-leak)
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
          preflight_class="$(container_sensitive_preflight_class "$stderr_file" || true)"
          if [[ -n "$preflight_class" ]]; then
            printf '%s\n' "$preflight_class"
          else
            printf '%s\n' 'bounded-command'
          fi
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
