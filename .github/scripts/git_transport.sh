#!/usr/bin/env bash
set -euo pipefail

# Release checks use one fixed HTTPS repository and a trusted runner Git. Keep
# the boundary small: reject options/refspecs, clear ambient transport state,
# and let Git validate the checkout it is operating on.
readonly GIT=/usr/bin/git
readonly REPOSITORY='TeleCrypt-io/server_state'
# actions/checkout's HTTPS fetch URL intentionally omits `.git`; the helper's own
# fetch target retains it. Both exact forms identify the same canonical repository.
readonly REMOTE_NO_SUFFIX='https://github.com/TeleCrypt-io/server_state'
readonly REMOTE='https://github.com/TeleCrypt-io/server_state.git'
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

die() { printf 'git transport refused: %s\n' "$1" >&2; exit 64; }

[[ -x "$GIT" ]] || die 'trusted Git executable is unavailable'
export PATH=/usr/bin:/bin
for variable in ${!GIT_CONFIG_KEY_@} ${!GIT_CONFIG_VALUE_@}; do
  unset "$variable"
done
unset GIT_CONFIG_PARAMETERS GIT_DIR GIT_COMMON_DIR GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_INDEX_FILE GIT_NAMESPACE GIT_REPLACE_REF_BASE \
  GIT_QUARANTINE_PATH GIT_WORK_TREE GIT_CEILING_DIRECTORIES \
  GIT_DISCOVERY_ACROSS_FILESYSTEM GIT_EXEC_PATH GIT_TEMPLATE_DIR GIT_CONFIG \
  GIT_OPTIONAL_LOCKS GIT_SSH GIT_SSH_COMMAND GIT_SSH_VARIANT GIT_PROXY_COMMAND \
  GIT_EXT_SERVICE GIT_EXT_SERVICE_NOPREFIX
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_COUNT=0 GIT_NO_REPLACE_OBJECTS=1 GIT_TERMINAL_PROMPT=0
unset GIT_ASKPASS SSH_ASKPASS HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
  http_proxy https_proxy all_proxy no_proxy GIT_HTTP_PROXY_AUTHMETHOD \
  GIT_SSL_NO_VERIFY GIT_SSL_CAFILE GIT_SSL_CAINFO GIT_SSL_CAPATH GIT_SSL_CERT \
  GIT_SSL_KEY GIT_SSL_CIPHER_LIST GIT_SSL_VERSION SSL_CERT_FILE SSL_CERT_DIR \
  CURL_CA_BUNDLE REQUESTS_CA_BUNDLE GIT_ALLOW_PROTOCOL GIT_PROTOCOL_FROM_USER \
  GIT_TRACE GIT_TRACE_PACK_ACCESS GIT_TRACE_PERFORMANCE GIT_TRACE_SETUP \
  GIT_TRACE_PACKET GIT_TRACE_SHALLOW GIT_TRACE_CURL GIT_CURL_VERBOSE GIT_TRACE2 \
  GIT_TRACE2_EVENT GIT_TRACE2_PERF GIT_TRACE2_BRIEF GIT_TRACE2_CONFIG \
  GIT_TRACE2_ENV_VARS GIT_TRACE2_MAX_FILES GIT_TRACE2_PARENT GIT_TRACE2_PERF_BRIEF \
  GIT_TRACE_REDACT

readonly GIT_OPTIONS=(
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
  -c core.sshCommand=
  -c core.gitproxy=
  -c core.hooksPath=/dev/null
  -c remote.origin.proxy=
  -c remote.origin.uploadpack=
)

git_safe() {
  local temporary status
  temporary="$(mktemp -d "${TMPDIR:-/tmp}/server-state-git.XXXXXX")"
  set +e
  bash "$SCRIPT_DIR/run_bounded_combined.sh" --separate \
    $((64 * 1024)) $((64 * 1024)) "$temporary/stdout" "$temporary/stderr" 30 \
    "$GIT" "${GIT_OPTIONS[@]}" "$@"
  status=$?
  set -e
  cat -- "$temporary/stdout"
  cat -- "$temporary/stderr" >&2
  rm -rf -- "$temporary"
  return "$status"
}

reject_local_transport_config() {
  local git_dir config_file config_worktree
  [[ ! -L "$PWD/.git" ]] || die 'repository metadata must not be a symlink'
  git_dir="$(git_safe rev-parse --git-dir)"
  [[ -d "$git_dir" && ! -L "$git_dir" ]] || die 'repository Git directory is invalid'
  config_file="$git_dir/config"
  inspect_config_file "$config_file"
  config_worktree="$git_dir/config.worktree"
  if [[ -L "$config_worktree" || -e "$config_worktree" ]]; then
    inspect_config_file "$config_worktree"
  fi
}

inspect_config_file() {
  local config_file="$1" keys remote_keys origin status key
  [[ -f "$config_file" && ! -L "$config_file" ]] || die 'Git configuration is not a regular file'
  [[ "$(stat -c '%s' -- "$config_file")" -le 65536 ]] || die 'Git configuration exceeds the bounded input limit'

  set +e
  keys="$(git_safe config --file "$config_file" --no-includes --name-only --get-regexp \
    '^(include(if)?\.|url(\..*)?$|credential(\..*)?$|hooks(\.|$)|core\.(askpass|ssh.*|gitproxy|hookspath|worktree|alternateobjectdirectories)$|http(\..*)?$|protocol(\..*)?$|ssh\..*$|fetch\..*$|transfer\..*$|uploadpack\..*$|receivepack\..*$|remote\..*\.(pushurl|vcs|uploadpack|proxy|receivepack)$)')"
  status=$?
  set -e
  [[ "$status" -eq 0 || "$status" -eq 1 ]] || die 'Git configuration could not be inspected'
  [[ -z "$keys" ]] || die 'Git transport, credential, or hook configuration is not allowed'

  set +e
  remote_keys="$(git_safe config --file "$config_file" --no-includes --name-only --get-regexp '^remote\..*\.url$')"
  status=$?
  set -e
  [[ "$status" -eq 0 || "$status" -eq 1 ]] || die 'Git remote configuration could not be inspected'
  while IFS= read -r key; do
    [[ -z "$key" || "$key" == remote.origin.url ]] || die 'non-canonical Git remote URL is not allowed'
  done <<<"$remote_keys"

  set +e
  origin="$(git_safe config --file "$config_file" --no-includes --get-all remote.origin.url)"
  status=$?
  set -e
  [[ "$status" -eq 0 || "$status" -eq 1 ]] || die 'Git origin could not be inspected'
  if [[ -n "$origin" ]]; then
    [[ "$origin" == "$REMOTE" || "$origin" == "$REMOTE_NO_SUFFIX" ]] || die 'local Git origin is not canonical'
  fi
}

validate_ref() {
  [[ "$1" =~ ^(HEAD|[0-9a-f]{40}|refs/(tags|remotes/origin)/[A-Za-z0-9._/-]+(\^\{commit\}|\^\{\})?)$ ]] ||
    die 'local Git reference is malformed'
}

validate_tag() {
  [[ "$1" =~ ^server-state-[0-9a-f]{7,10}$ ]] || die 'release tag is not canonical'
}

validate_refspec() {
  [[ "$1" =~ ^refs/(heads/main|tags/[A-Za-z0-9._/-]+):refs/(remotes/origin/[A-Za-z0-9._/-]+|tags/[A-Za-z0-9._/-]+)$ ]] ||
    die 'Git fetch refspec is malformed'
  if [[ "$1" =~ ^refs/tags/([^:]+): ]]; then validate_tag "${BASH_REMATCH[1]}"; fi
}

local_read() {
  local kind="$1" ref="$2"
  validate_ref "$ref"
  case "$kind" in
    cat-file-type) git_safe cat-file -t -- "$ref" ;;
    rev-parse) git_safe rev-parse --verify "$ref" ;;
    *) die 'unsupported local Git read' ;;
  esac
}

case "${1:-}" in
  check)
    [[ $# -eq 1 ]] || die 'check takes no arguments'
    reject_local_transport_config
    git_safe rev-parse --git-dir >/dev/null
    ;;
  local-read)
    [[ $# -eq 3 ]] || die 'local-read requires a read kind and reference'
    reject_local_transport_config
    local_read "$2" "$3"
    ;;
  local-ancestor)
    [[ $# -eq 3 ]] || die 'local-ancestor requires two references'
    reject_local_transport_config
    validate_ref "$2"; validate_ref "$3"
    git_safe merge-base --is-ancestor "$2" "$3"
    ;;
  fetch)
    [[ $# -ge 3 && "$2" == "$REPOSITORY" ]] || die 'fetch requires the canonical repository'
    reject_local_transport_config
    shift 2
    for refspec; do validate_refspec "$refspec"; done
    git_safe fetch --quiet --force --no-tags "$REMOTE" "$@"
    ;;
  ls-remote)
    [[ $# -ge 3 && "$2" == "$REPOSITORY" ]] || die 'ls-remote requires the canonical repository'
    reject_local_transport_config
    shift 2
    for ref; do
      [[ "$ref" =~ ^refs/tags/([A-Za-z0-9._/-]+)$ ]] || die 'Git remote reference is malformed'
      validate_tag "${BASH_REMATCH[1]}"
    done
    git_safe ls-remote --quiet --exit-code "$REMOTE" "$@"
    ;;
  *) die 'unsupported operation' ;;
esac
