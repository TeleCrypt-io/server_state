#!/usr/bin/env bash
# Deploy one immutable, exact release tag of the TeleCrypt server stack.
#
# This script is intentionally run by an operator on the Linux VM. It never follows a
# branch, resets a working tree, reads secret values, or changes host-side ingress.
set -euo pipefail

REPO="${TELECRYPT_REPO:-$HOME/server}"
DATA="${TELECRYPT_DATA:-$HOME/persistent_data}"
SECRETS="$DATA/secrets"
STATE="$DATA/deploy-state"
ENV_FILE="${TELECRYPT_ENV_FILE:-$REPO/.env}"

export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DOCKER_HOST="${DOCKER_HOST:-unix:///run/user/$(id -u)/docker.sock}"

usage() {
  cat <<'EOF'
Usage:
  deploy.sh release <exact-release-tag>
  deploy.sh rollback [<exact-release-tag>]

`release` deploys only the supplied tag fetched from origin. `rollback` without a
tag uses the previous successful release recorded outside the repository.
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
log() { printf '\n== %s ==\n' "$*"; }

require_clean_tree() {
  [ -d "$REPO/.git" ] || die "repository not found at $REPO"
  [ -z "$(git -C "$REPO" status --porcelain --untracked-files=all)" ] ||
    die "repository is not clean; commit, stash, or discard local changes before deployment"
}

validate_tag_name() {
  local tag="$1"
  [ -n "$tag" ] || die "release tag is required"
  git check-ref-format --allow-onelevel "refs/tags/$tag" ||
    die "invalid release tag: $tag"
}

fetch_release_tag() {
  local tag="$1"
  # Fetch this ref explicitly and force the local tag to the remote value. This avoids
  # selecting an accidentally stale local tag; tag immutability is a release-policy rule.
  git -C "$REPO" fetch --quiet --force origin "refs/tags/$tag:refs/tags/$tag" ||
    die "origin does not provide release tag '$tag'"
  git -C "$REPO" rev-parse --verify --quiet "$tag^{commit}" >/dev/null ||
    die "release tag '$tag' does not resolve to a commit"
}

check_mode() {
  local expected="$1" path="$2" actual
  actual="$(stat -c '%a' "$path")"
  [ "$actual" = "$expected" ] ||
    die "unexpected mode on $path (need $expected; found $actual)"
}

env_value() {
  local key="$1" file="$2"
  awk -v wanted="$key" '
    index($0, wanted "=") == 1 {
      print substr($0, length(wanted) + 2)
      exit
    }
  ' "$file"
}

check_secrets() {
  local required=(
    synapse.secrets.yaml
    synapse_signing.key
    mas.secrets.yaml
    locker.secrets.env
    cashier.secrets.env
  )
  local name

  [ -d "$SECRETS" ] || die "secrets directory is missing: $SECRETS"
  [ -f "$ENV_FILE" ] || die "server-only Compose environment is missing: $ENV_FILE"
  for name in "${required[@]}"; do
    [ -f "$SECRETS/$name" ] || die "required secret file is missing: $SECRETS/$name"
    check_mode 600 "$SECRETS/$name"
  done

  local cashier_db locker_db
  [ "$(env_value BILLING_ENV "$SECRETS/cashier.secrets.env")" = test ] ||
    die "cashier.secrets.env must explicitly set BILLING_ENV=test for this release"
  [ "$(env_value DODO_API_BASE "$SECRETS/cashier.secrets.env")" = https://test.dodopayments.com ] ||
    die "cashier.secrets.env must select the exact Dodo test API origin for this release"
  cashier_db="$(env_value CONTROLPLANE_DB_URL "$SECRETS/cashier.secrets.env")"
  locker_db="$(env_value CONTROLPLANE_DB_URL "$SECRETS/locker.secrets.env")"
  [ -n "$cashier_db" ] || die "cashier.secrets.env is missing CONTROLPLANE_DB_URL"
  [ "$cashier_db" = "$locker_db" ] ||
    die "cashier and janitor must use the same control-plane database"
}

preflight_release() {
  local tag="$1" candidate
  candidate="$(mktemp -d "${TMPDIR:-/tmp}/telecrypt-release.XXXXXX")"
  trap 'git -C "$REPO" worktree remove --force "$candidate" >/dev/null 2>&1 || true; rmdir "$candidate" >/dev/null 2>&1 || true' RETURN

  git -C "$REPO" worktree add --detach --quiet "$candidate" "$tag"
  check_secrets
  docker info >/dev/null || die "rootless Docker is unavailable"
  docker compose --env-file "$ENV_FILE" --project-directory "$candidate" \
    -f "$candidate/compose.yml" config -q ||
    die "compose configuration preflight failed for release '$tag'"
  docker compose --env-file "$ENV_FILE" --project-directory "$candidate" \
    -f "$candidate/compose.yml" run --rm --no-deps caddy \
    caddy validate --config /etc/caddy/Caddyfile ||
    die "Caddy configuration preflight failed for release '$tag'"

  trap - RETURN
  git -C "$REPO" worktree remove --force "$candidate" >/dev/null 2>&1 || true
  rmdir "$candidate" >/dev/null 2>&1 || true
}

read_recorded_release() {
  local file="$1" value
  [ -f "$file" ] || return 1
  IFS= read -r value <"$file" || true
  validate_tag_name "$value"
  printf '%s\n' "$value"
}

wait_for_health() {
  local attempt status
  for attempt in $(seq 1 24); do
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' tc_synapse 2>/dev/null || true)"
    if [ "$status" = healthy ] &&
       curl --fail --silent --show-error --max-time 5 \
         https://backend.telecrypt.io/health >/dev/null &&
       curl --fail --silent --show-error --max-time 5 \
         https://backend.telecrypt.io/auth/.well-known/openid-configuration >/dev/null &&
       curl --fail --silent --show-error --max-time 5 \
         https://backend.telecrypt.io/plan >/dev/null; then
      return 0
    fi
    sleep 5
  done
  return 1
}

apply_release() {
  local tag="$1" previous=""
  previous="$(read_recorded_release "$STATE/current-release" 2>/dev/null || true)"

  log "Checkout exact release tag: $tag"
  git -C "$REPO" switch --detach "$tag"

  log "Pull release images and converge services"
  cd "$REPO"
  docker compose --env-file "$ENV_FILE" pull
  # Do not remove orphans implicitly: deleting a service is an explicit operator action.
  docker compose --env-file "$ENV_FILE" up -d
  # A bind-mounted Caddyfile needs a recreated mount after a release changes it.
  docker compose --env-file "$ENV_FILE" up -d --no-deps --force-recreate caddy

  log "Health checks"
  if ! wait_for_health; then
    printf 'release %s did not become healthy\n' "$tag" >&2
    if [ -n "$previous" ]; then
      printf 'rollback command: %s rollback %s\n' "$0" "$previous" >&2
    else
      printf 'no previous successful release is recorded; inspect the stack before retrying\n' >&2
    fi
    docker compose --env-file "$ENV_FILE" ps >&2 || true
    return 1
  fi

  if [ -e "$STATE" ]; then
    [ -d "$STATE" ] || die "deployment state path is not a directory: $STATE"
    check_mode 700 "$STATE"
  else
    mkdir -m 700 -p "$STATE"
  fi
  if [ -n "$previous" ] && [ "$previous" != "$tag" ]; then
    printf '%s\n' "$previous" >"$STATE/previous-release"
    chmod 600 "$STATE/previous-release"
  fi
  printf '%s\n' "$tag" >"$STATE/current-release"
  chmod 600 "$STATE/current-release"

  log "Release active"
  printf 'active release: %s\n' "$tag"
  docker compose --env-file "$ENV_FILE" ps
}

main() {
  local command="${1:-}" tag="${2:-}"
  case "$command" in
    release)
      [ "$#" -eq 2 ] || { usage >&2; exit 2; }
      ;;
    rollback)
      [ "$#" -le 2 ] || { usage >&2; exit 2; }
      if [ -z "$tag" ]; then
        tag="$(read_recorded_release "$STATE/previous-release")" ||
          die "no previous successful release is recorded; supply an exact release tag"
      fi
      ;;
    -h|--help|help)
      usage
      return 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac

  validate_tag_name "$tag"
  require_clean_tree
  fetch_release_tag "$tag"
  log "Preflight release: $tag"
  preflight_release "$tag"
  apply_release "$tag"
}

main "$@"
