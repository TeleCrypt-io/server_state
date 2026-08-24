#!/usr/bin/env bash
set -euo pipefail

# This helper is the only Git entry point used by release verification. Keep
# its executable, repository, configuration, and output boundary independent
# of the caller's process environment and repository metadata.
readonly TRUSTED_GIT='/usr/bin/git'
readonly SAFE_PATH='/usr/bin:/bin'
readonly CANONICAL_REPOSITORY='TeleCrypt-io/server_state'
readonly CANONICAL_URL='https://github.com/TeleCrypt-io/server_state.git'
readonly MAX_CONFIG_OUTPUT_BYTES=$((64 * 1024))
readonly CONFIG_TIMEOUT_SECONDS=10
readonly CONFIG_KILL_GRACE_SECONDS=5

die() {
  printf 'git transport refused: %s\n' "$1" >&2
  exit 64
}

[[ -x "$TRUSTED_GIT" ]] || die 'trusted Git executable is unavailable'
export PATH="$SAFE_PATH"
config_workdir="$(mktemp -d /tmp/telecrypt-git-transport.XXXXXX)" || die 'could not create a private output directory'
trap 'rm -rf -- "$config_workdir"' EXIT

clear_transport_environment() {
  # Do not allow inherited Git configuration to add arbitrary -c options.
  for variable in ${!GIT_CONFIG_KEY_@} ${!GIT_CONFIG_VALUE_@}; do
    [[ -n "$variable" ]] && unset "$variable"
  done
  unset \
    GIT_CONFIG_PARAMETERS GIT_DIR GIT_COMMON_DIR GIT_OBJECT_DIRECTORY \
    GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_INDEX_FILE GIT_NAMESPACE \
    GIT_REPLACE_REF_BASE GIT_NO_REPLACE_OBJECTS GIT_QUARANTINE_PATH \
    GIT_WORK_TREE GIT_CEILING_DIRECTORIES GIT_DISCOVERY_ACROSS_FILESYSTEM \
    GIT_EXEC_PATH GIT_TEMPLATE_DIR GIT_CONFIG GIT_OPTIONAL_LOCKS \
    GIT_EXT_SERVICE GIT_EXT_SERVICE_NOPREFIX
  export GIT_CONFIG_SYSTEM=/dev/null
  export GIT_CONFIG_GLOBAL=/dev/null
  export GIT_CONFIG_NOSYSTEM=1
  export GIT_CONFIG_COUNT=0
  export GIT_CONFIG_PARAMETERS=
  export GIT_ASKPASS=
  export SSH_ASKPASS=
  export GIT_SSH=
  export GIT_SSH_COMMAND=
  export GIT_SSH_VARIANT=
  export GIT_PROXY_COMMAND=
  export HTTP_PROXY=
  export HTTPS_PROXY=
  export ALL_PROXY=
  export NO_PROXY=
  export http_proxy=
  export https_proxy=
  export all_proxy=
  export no_proxy=
  export GIT_HTTP_PROXY_AUTHMETHOD=
  export GIT_SSL_NO_VERIFY=
  export GIT_SSL_CIPHER_LIST=
  export GIT_SSL_VERSION=
  export GIT_SSL_CAFILE=
  export GIT_SSL_CAINFO=
  export GIT_SSL_CAPATH=
  export GIT_SSL_CERT=
  export GIT_SSL_KEY=
  export SSL_CERT_FILE=
  export SSL_CERT_DIR=
  export CURL_CA_BUNDLE=
  export REQUESTS_CA_BUNDLE=
  export GIT_TRACE=
  export GIT_TRACE_PACKET=
  export GIT_TRACE_CURL=
  export GIT_CURL_VERBOSE=
  export GIT_TERMINAL_PROMPT=0
}

readonly GIT_SAFE_OPTIONS=(
  -c protocol.version=2
  -c protocol.allow=never
  -c protocol.https.allow=always
  -c protocol.file.allow=never
  -c protocol.ext.allow=never
  -c credential.helper=
  -c credential.useHttpPath=false
  -c credential.interactive=false
  -c http.proxy=
  -c http.sslVerify=true
  -c http.sslCAInfo=
  -c http.sslCAPath=
  -c http.sslCert=
  -c http.sslKey=
  -c core.sshCommand=
  -c core.gitproxy=
  -c core.hooksPath=/dev/null
  -c remote.origin.proxy=
  -c remote.origin.uploadpack=
)

git_safe() {
  "$TRUSTED_GIT" "${GIT_SAFE_OPTIONS[@]}" "$@"
}

bounded_git() {
  local stdout_path="$1" stderr_path="$2" status
  shift 2
  rm -f -- "$stdout_path" "$stderr_path"
  set +e
  (
    ulimit -f "$(((MAX_CONFIG_OUTPUT_BYTES + 511) / 512))"
    timeout --signal=TERM --kill-after="${CONFIG_KILL_GRACE_SECONDS}s" \
      "${CONFIG_TIMEOUT_SECONDS}s" "$TRUSTED_GIT" "${GIT_SAFE_OPTIONS[@]}" "$@" \
      >"$stdout_path" 2>"$stderr_path"
  )
  status=$?
  set -e
  if [[ "$(wc -c <"$stdout_path")" -gt "$MAX_CONFIG_OUTPUT_BYTES" ||
        "$(wc -c <"$stderr_path")" -gt "$MAX_CONFIG_OUTPUT_BYTES" ]]; then
    die 'Git inspection exceeded the bounded output limit'
  fi
  [[ ! -s "$stderr_path" ]] || die 'Git inspection emitted unexpected diagnostics'
  return "$status"
}

read_one_line() {
  local path="$1" label="$2" value
  [[ "$(wc -l <"$path")" -eq 1 ]] || die "$label returned an unexpected shape"
  value="$(<"$path")"
  [[ -n "$value" && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "$label returned an invalid path"
  printf '%s\n' "$value"
}

reject_special_config_file() {
  local path="$1" label="$2"
  if [[ -L "$path" || -p "$path" || ! -f "$path" ]]; then
    die "$label is not a regular file"
  fi
  [[ "$(stat -c '%s' -- "$path")" -le "$MAX_CONFIG_OUTPUT_BYTES" ]] ||
    die "$label exceeds the bounded input limit"
}

discover_git_dir_without_git() {
  local metadata="$PWD/.git" pointer git_dir
  [[ ! -L "$metadata" ]] || die 'repository metadata must not be a symlink'
  if [[ -d "$metadata" ]]; then
    printf '%s\n' "$metadata"
    return
  fi
  [[ -f "$metadata" ]] || die 'repository metadata is missing'
  [[ "$(stat -c '%s' -- "$metadata")" -le 4096 ]] || die 'repository metadata pointer is oversized'
  IFS= read -r pointer <"$metadata" || die 'repository metadata pointer is malformed'
  [[ "$pointer" == gitdir:\ * ]] || die 'repository metadata pointer is malformed'
  git_dir="${pointer#gitdir: }"
  [[ -n "$git_dir" && "$git_dir" != *$'\n'* && "$git_dir" != *$'\r'* ]] || die 'repository metadata pointer is malformed'
  case "$git_dir" in
    /*) ;;
    *) git_dir="$PWD/$git_dir" ;;
  esac
  [[ -d "$git_dir" && ! -L "$git_dir" ]] || die 'repository Git directory is invalid'
  printf '%s\n' "$git_dir"
}

check_config_scope() {
  local scope="$1" config_file="$2" key_output="$3" key_error="$4"
  local status key
  local -a config_args=(config "$scope")
  if [[ "$scope" = --file ]]; then
    config_args=(config --file "$config_file")
  fi
  # core.askpass, remote\..*\.(uploadpack|proxy), and custom VCS/push URL settings are always forbidden.
  if bounded_git "$key_output" "$key_error" "${config_args[@]}" --no-includes --name-only --get-regexp \
    '^(url(\..*)?|http(\..*)?|protocol(\..*)?|credential(\..*)?|include(\..*)?|core\.(askpass|ssh.*|gitproxy|worktree|alternateobjectdirectories)|ssh\..*|fetch\..*|transfer\..*|uploadpack\..*|receivepack\..*|remote\..*\.(pushurl|vcs|uploadpack|proxy|receivepack))$'; then
    status=0
  else
    status=$?
    [[ "$status" -eq 1 ]] || die "Git $scope configuration could not be inspected"
  fi
  while IFS= read -r key; do
    [[ -z "$key" ]] && continue
    case "$key" in
      remote.*.url)
        [[ "$key" = remote.origin.url ]] || die "Git $scope configuration contains an unsafe transport key"
        ;;
      *)
        die "Git $scope configuration contains an unsafe transport key"
        ;;
    esac
  done <"$key_output"

  # A normal checkout has one canonical origin URL. Any other remote URL,
  # push URL, or custom VCS helper is rejected rather than being consulted.
  if [[ "$scope" = --local ]]; then
    if bounded_git "$key_output" "$key_error" config "$scope" --no-includes --get-all remote.origin.url; then
      status=0
    else
      status=$?
      [[ "$status" -eq 1 ]] || die "Git $scope remote URL could not be inspected"
      return
    fi
  else
    if bounded_git "$key_output" "$key_error" config --file "$config_file" --no-includes --get-all remote.origin.url; then
      status=0
    else
      status=$?
      [[ "$status" -eq 1 ]] || die "Git $scope remote URL could not be inspected"
      return
    fi
  fi
  [[ "$(wc -l <"$key_output")" -eq 1 && "$(<"$key_output")" = "$CANONICAL_URL" ]] ||
    die "Git $scope origin URL is not canonical"
}

reject_config_overrides() {
  local local_keys="$config_workdir/local-keys" local_error="$config_workdir/local-keys.stderr"
  local worktree_keys="$config_workdir/worktree-keys" worktree_error_keys="$config_workdir/worktree-keys.stderr"
  local git_dir config_worktree

  git_dir="$(discover_git_dir_without_git)"
  reject_special_config_file "$git_dir/config" 'Git local configuration'
  check_config_scope --local "$git_dir/config" "$local_keys" "$local_error"

  config_worktree="$git_dir/config.worktree"
  if [[ -L "$config_worktree" || -e "$config_worktree" ]]; then
    reject_special_config_file "$config_worktree" 'Git worktree configuration'
    check_config_scope --file "$config_worktree" "$worktree_keys" "$worktree_error_keys"
  fi
}

validate_local_ref() {
  local ref="$1"
  [[ -n "$ref" && "$ref" != -* && "$ref" != *$'\n'* && "$ref" != *$'\r'* && "$ref" != *$' '* && "$ref" != *$'\t'* ]] ||
    die 'local Git reference is malformed'
}

local_read() {
  local kind="$1" ref="$2" output="$config_workdir/local-read" error="$config_workdir/local-read.stderr" status
  validate_local_ref "$ref"
  case "$kind" in
    cat-file-type)
      bounded_git "$output" "$error" cat-file -t -- "$ref" || status=$?
      ;;
    rev-parse)
      bounded_git "$output" "$error" rev-parse --verify "$ref" || status=$?
      ;;
    *)
      die 'unsupported local Git read'
      ;;
  esac
  status="${status:-0}"
  [[ "$status" -eq 0 ]] || die 'local Git read failed'
  cat -- "$output"
}

local_ancestor() {
  local commit="$1" ancestor="$2" output="$config_workdir/ancestor" error="$config_workdir/ancestor.stderr" status
  validate_local_ref "$commit"
  validate_local_ref "$ancestor"
  if bounded_git "$output" "$error" merge-base --is-ancestor "$commit" "$ancestor"; then
    return 0
  else
    status=$?
  fi
  [[ "$status" -eq 1 ]] && return 1
  die 'local Git ancestry check failed'
}

canonical_url() {
  local repository="$1"
  [[ "$repository" == "$CANONICAL_REPOSITORY" ]] || die 'non-canonical repository slug'
  printf '%s\n' "$CANONICAL_URL"
}

run_transport() {
  local operation="$1" repository="$2" url ref
  shift 2
  for ref in "$@"; do
    [[ -n "$ref" && "$ref" != -* ]] || die 'options must be fixed by the transport helper'
  done
  clear_transport_environment
  reject_config_overrides
  case "$operation" in
    fetch)
      url="$(canonical_url "$repository")"
      if ! bounded_git "$config_workdir/transport-fetch" "$config_workdir/transport-fetch.stderr" \
        fetch --quiet --force --no-tags "$url" "$@"; then
        die 'Git fetch failed'
      fi
      [[ ! -s "$config_workdir/transport-fetch" ]] || die 'Git fetch emitted unexpected output'
      ;;
    ls-remote)
      url="$(canonical_url "$repository")"
      if ! bounded_git "$config_workdir/transport-ls-remote" "$config_workdir/transport-ls-remote.stderr" \
        ls-remote --quiet --exit-code "$url" "$@"; then
        die 'Git ls-remote failed'
      fi
      cat -- "$config_workdir/transport-ls-remote"
      ;;
    check)
      ;;
    local-read)
      [[ "$#" -eq 2 ]] || die 'local-read requires a fixed read kind and reference'
      local_read "$1" "$2"
      ;;
    local-ancestor)
      [[ "$#" -eq 2 ]] || die 'local-ancestor requires two fixed references'
      local_ancestor "$1" "$2"
      ;;
    *)
      die 'unsupported operation'
      ;;
  esac
}

[[ $# -ge 1 ]] || die 'operation is required'
operation="$1"
shift
case "$operation" in
  check)
    [[ $# -eq 0 ]] || die 'check takes no arguments'
    run_transport check ignored
    ;;
  local-read|local-ancestor)
    [[ $# -eq 2 ]] || die "$operation requires exactly two arguments"
    run_transport "$operation" ignored "$@"
    ;;
  fetch|ls-remote)
    [[ $# -ge 1 ]] || die 'repository slug is required'
    repository="$1"
    shift
    run_transport "$operation" "$repository" "$@"
    ;;
  *)
    die 'unsupported operation'
    ;;
esac
