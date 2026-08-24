#!/usr/bin/env bash
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${METADATA_DIR:?METADATA_DIR is required}"

MAX_RELEASE_JSON_BYTES=1048576
MAX_RELEASE_ASSET_BYTES=1048576
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

bounded_api() {
  local max_bytes="$1" output="$2"
  shift 2
  (( max_bytes > 0 )) || return 1
  local stderr="$output.stderr" status
  set +e
  "$SCRIPT_DIR/run_bounded_combined.sh" --separate "$max_bytes" "$max_bytes" \
    "$output" "$stderr" 60 gh api "$@"
  status=$?
  set -e
  if [[ "$status" -ne 0 ]]; then
    echo "GitHub API request failed (status $status; stderr bytes $(wc -c < "$stderr"))" >&2
    return "$status"
  fi
  if [[ -s "$stderr" ]]; then
    echo "GitHub API request emitted unexpected stderr ($(wc -c < "$stderr") bytes)" >&2
    return 1
  fi
  rm -f "$stderr"
  test "$(wc -c < "$output")" -le "$max_bytes"
}

# shellcheck disable=SC1091
source versions.env
mkdir -p "$METADATA_DIR"

fetch_release_asset() {
  local key="$1" image="$2" repository="$3" asset_name="$4"
  local tag="${image##*:}"
  local release_path="$METADATA_DIR/$key.release.json"
  local asset_path="$METADATA_DIR/$key.release.asset"
  local tag_ref_path="$METADATA_DIR/$key.annotated-tag-ref.json"
  local annotated_tag_path="$METADATA_DIR/$key.annotated-tag.json"
  local api_root="https://api.github.com/repos/$repository"
  local annotated_tag_sha
  bounded_api "$MAX_RELEASE_JSON_BYTES" "$tag_ref_path" \
    --hostname github.com \
    --header 'Accept: application/vnd.github+json' \
    --header 'X-GitHub-Api-Version: 2026-03-10' \
    "repos/$repository/git/ref/tags/$tag"
  annotated_tag_sha="$(jq -er --arg ref "refs/tags/$tag" --arg url "$api_root/git/refs/tags/$tag" \
    '. | select(type == "object" and .ref == $ref and .url == $url) |
     .object | select(type == "object" and .type == "tag" and
       (.sha | type == "string" and test("^[0-9a-f]{40}$"))) | .sha' "$tag_ref_path")"
  bounded_api "$MAX_RELEASE_JSON_BYTES" "$annotated_tag_path" \
    --hostname github.com \
    --header 'Accept: application/vnd.github+json' \
    --header 'X-GitHub-Api-Version: 2026-03-10' \
    "repos/$repository/git/tags/$annotated_tag_sha"
  jq -e --arg tag "$tag" --arg sha "$annotated_tag_sha" --arg commit_url "$api_root/git/commits/" \
    --arg object_url "$api_root/git/tags/$annotated_tag_sha" \
    '. | select(type == "object" and .sha == $sha and .tag == $tag and .url == $object_url) |
     .object as $target | $target | select(type == "object" and .type == "commit" and
       (.sha | type == "string" and test("^[0-9a-f]{40}$")) and
       ($target.url | type == "string" and . == ($commit_url + $target.sha)))' "$annotated_tag_path" >/dev/null
  bounded_api "$MAX_RELEASE_JSON_BYTES" "$release_path" \
    --hostname github.com \
    --header 'Accept: application/vnd.github+json' \
    --header 'X-GitHub-Api-Version: 2026-03-10' \
    "repos/$repository/releases/tags/$tag"
  test "$(wc -c < "$release_path")" -le "$MAX_RELEASE_JSON_BYTES"
  local asset_id
  asset_id="$(jq -er --arg asset "$asset_name" '.assets | map(select(.name == $asset)) |
    if length == 1 then .[0].id else error end |
    select(type == "number" and . == floor and . > 0)' "$release_path")"
  bounded_api "$MAX_RELEASE_ASSET_BYTES" "$asset_path" \
    --hostname github.com \
    --header 'Accept: application/octet-stream' \
    --header 'X-GitHub-Api-Version: 2026-03-10' \
    "repos/$repository/releases/assets/$asset_id"
  test -s "$asset_path"
  test "$(wc -c < "$asset_path")" -le "$MAX_RELEASE_ASSET_BYTES"
  test "$(wc -c < "$asset_path")" -eq "$(jq -er --arg asset "$asset_name" '.assets | map(select(.name == $asset)) |
    if length == 1 then .[0].size else error end |
    select(type == "number" and . == floor and . > 0)' "$release_path")"
}

fetch_release_asset SYNAPSE_IMAGE "$SYNAPSE_IMAGE" TeleCrypt-io/telecrypt-synapse \
  "telecrypt-synapse-${SYNAPSE_IMAGE##*:}.digest.json"
fetch_release_asset CONTROLPLANE_IMAGE "$CONTROLPLANE_IMAGE" TeleCrypt-io/controlplane \
  "controlplane-${CONTROLPLANE_IMAGE##*:}.digest.json"
fetch_release_asset CASHIER_IMAGE "$CASHIER_IMAGE" TeleCrypt-io/cashier \
  "telecrypt-cashier-${CASHIER_IMAGE##*:}.digest.json"
