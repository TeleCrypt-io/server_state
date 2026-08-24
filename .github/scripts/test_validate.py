#!/usr/bin/env python3
"""Unit tests for the high-risk Server State invariants."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import validate  # noqa: E402


class SourceInvariantTests(unittest.TestCase):
    def test_manifest_has_exactly_five_versioned_images(self) -> None:
        values = validate.load_manifest()
        self.assertEqual(set(values), set(validate.IMAGE_KEYS))
        self.assertEqual(len(set(values.values())), 5)
        with self.assertRaises(AssertionError):
            validate.parse_manifest([*map(lambda item: f"{item[0]}={item[1]}", values.items()), "EXTRA=x:1"])

    def test_versions_manifest_is_exactly_ordered_and_uncommented(self) -> None:
        path = validate.ROOT / "versions.env"
        raw = path.read_text(encoding="utf-8")
        self.assertEqual(raw, "\n".join(f"{key}={validate.load_manifest()[key]}" for key in validate.IMAGE_KEYS) + "\n")
        malformed = (
            raw[:-1],
            raw.replace("\n", "\n\n", 1),
            raw.replace("CADDY_IMAGE", " CADDY_IMAGE", 1),
            raw.replace("CADDY_IMAGE", "# CADDY_IMAGE", 1),
            "\n".join(raw[:-1].splitlines()[::-1]) + "\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "versions.env"
            for text in malformed:
                candidate.write_text(text, encoding="utf-8")
                with self.assertRaises(AssertionError):
                    validate.load_manifest(candidate)

    def test_registry_platform_validation_covers_selected_single_or_index_child(self) -> None:
        validate.validate_image_platform(
            {"Os": "linux", "Architecture": "amd64", "Digest": "sha256:" + "a" * 64},
            {"os": "linux", "architecture": "amd64"},
        )
        with self.assertRaises(AssertionError):
            validate.validate_image_platform(
                {"Os": "linux", "Architecture": "arm64"},
                {"os": "linux", "architecture": "amd64"},
            )

    def test_server_name_derives_public_hosts(self) -> None:
        self.assertEqual(validate.public_site_host("SERVER_NAME=telecrypt.io\n"), "www.telecrypt.io")
        self.assertEqual(validate.backend_host("SERVER_NAME=stage.telecrypt.io\n"), "backend-stage.telecrypt.io")
        accepted = "a" * 40
        self.assertEqual(validate.backend_host(f"SERVER_NAME={accepted}.telecrypt.io\n"), f"backend-{accepted}.telecrypt.io")
        with self.assertRaises(AssertionError):
            validate.public_site_host(f"SERVER_NAME={'a' * 41}.telecrypt.io\n")

    def test_private_service_environment_sets_are_exact_and_disjoint(self) -> None:
        compose = (validate.ROOT / "compose.yml").read_text(encoding="utf-8")
        self.assertNotIn("env_file:", compose)
        self.assertNotIn("container_name:", compose)
        self.assertIn("host_ip: ${INGRESS_BIND_ADDRESS:?set INGRESS_BIND_ADDRESS}", compose)
        self.assertNotIn('"${INGRESS_BIND_ADDRESS:?set INGRESS_BIND_ADDRESS}:8080:8080"', compose)
        for key in validate.JANITOR_REQUIRED_ENV_KEYS:
            self.assertIn(f"{key}=${{{key}:?set {key}}}", compose)
        for key in validate.JANITOR_OPTIONAL_ENV_KEYS:
            self.assertIn(f"{key}=${{{key}:-}}", compose)
        self.assertEqual(validate.SERVICE_ENV_KEYS["janitor"] - {"SERVER_NAME"}, validate.JANITOR_ENV_KEYS)
        self.assertEqual(validate.SERVICE_ENV_KEYS["plan"] - {"SERVER_NAME"}, validate.PLAN_ENV_KEYS)
        self.assertEqual(validate.SERVICE_ENV_KEYS["cashier"] - {"SERVER_NAME"}, validate.CASHIER_ENV_KEYS)
        self.assertFalse(validate.JANITOR_ENV_KEYS & validate.PLAN_ENV_KEYS)
        self.assertFalse(validate.PLAN_ENV_KEYS & validate.CASHIER_ENV_KEYS)

    def test_caddy_rejects_non_terminator_transport_peers(self) -> None:
        caddy = (validate.ROOT / "Caddyfile").read_text(encoding="utf-8")
        self.assertIn("RootlessKit >= 3.0", caddy)
        self.assertIn("built-in TCP source-address propagation", caddy)
        self.assertIn("userland-proxy disabled", caddy)
        self.assertIn("prove the observed peer/X-Forwarded behavior live", caddy)
        self.assertEqual(caddy.count("not remote_ip {$TRUSTED_PROXY}"), 1)
        self.assertEqual(caddy.count("abort @untrusted_ingress_peer"), 1)
        self.assertEqual(caddy.count("import ingress_peer_gate"), 2)
        self.assertFalse(validate.JANITOR_ENV_KEYS & validate.CASHIER_ENV_KEYS)

    def test_mas_listeners_and_proxy_trust_are_network_scoped(self) -> None:
        compose = (validate.ROOT / "compose.yml").read_text(encoding="utf-8")
        mas = (validate.ROOT / "mas.yaml").read_text(encoding="utf-8")
        self.assertIn("- mas-edge", compose)
        self.assertIn("- mas-synapse", compose)
        self.assertIn("- mas-plan", compose)
        self.assertIn("- mas-admin", compose)
        self.assertEqual(mas.count("- host: mas-edge\n          port: 8080"), 1)
        self.assertEqual(mas.count("- host: mas-synapse\n          port: 8080"), 1)
        self.assertEqual(mas.count("- host: mas-plan\n          port: 8080"), 1)
        self.assertNotIn("address: '[::]:8080'", mas)
        self.assertIn("trusted_proxies: []", mas)
        self.assertNotIn("10.0.0.0/8", mas)
        self.assertNotIn("172.16.0.0/12", mas)
        self.assertNotIn("fd00::/8", mas)


class ImageProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.labels = {
            "org.opencontainers.image.source": "https://github.com/TeleCrypt-io/telecrypt-synapse",
            "org.opencontainers.image.revision": "a" * 40,
            "org.opencontainers.image.version": "1.159-tc3",
            "org.opencontainers.image.base.name": "ghcr.io/element-hq/synapse",
            "org.opencontainers.image.base.version": "1.159.0",
            "org.telecrypt.controlplane.release": "0.4.0",
            "org.telecrypt.s3-provider.version": "1.7.0",
            "org.telecrypt.controlplane.wheel.sha256": "a" * 64,
            "org.telecrypt.s3-provider.archive.sha256": "b" * 64,
        }

    def test_embedded_release_is_independent_and_channels_agree(self) -> None:
        validate.validate_synapse_provenance(self.labels, dict(self.labels), "1.159-tc3", "0.4.0")
        changed = dict(self.labels)
        changed["org.telecrypt.controlplane.release"] = "0.5.0"
        with self.assertRaises(AssertionError):
            validate.validate_synapse_provenance(self.labels, changed, "1.159-tc3", "0.4.0")

    def test_provenance_rejects_floating_or_prefixed_digests(self) -> None:
        malformed = dict(self.labels)
        malformed["org.telecrypt.controlplane.release"] = "latest"
        with self.assertRaises(AssertionError):
            validate.validate_synapse_provenance(malformed, malformed, "1.159-tc3", "0.5.0")
        malformed = dict(self.labels)
        malformed["org.telecrypt.controlplane.wheel.sha256"] = "sha256:" + "a" * 64
        with self.assertRaises(AssertionError):
            validate.validate_synapse_provenance(malformed, malformed, "1.159-tc3", "0.5.0")


class ReleaseEvidenceTests(unittest.TestCase):
    def test_git_transport_helper_is_explicit_and_rejects_hostile_config(self) -> None:
        workflow = (Path(__file__).parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        helper_path = Path(__file__).parent / "git_transport.sh"
        helper = helper_path.read_text(encoding="utf-8")
        self.assertIn('bash .github/scripts/git_transport.sh fetch "$GITHUB_REPOSITORY"', workflow)
        self.assertIn('bash .github/scripts/git_transport.sh ls-remote "$GITHUB_REPOSITORY"', workflow)
        self.assertNotIn("git fetch --", workflow)
        self.assertNotIn("git ls-remote", workflow)
        for required in (
            "/usr/bin/git",
            "https://github.com/TeleCrypt-io/server_state.git",
            "GIT_CONFIG_SYSTEM=/dev/null",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_CONFIG_COUNT=0",
            "GIT_CONFIG_PARAMETERS=",
            "GIT_ASKPASS=",
            "GIT_SSH_COMMAND=",
            "HTTP_PROXY=",
            "HTTPS_PROXY=",
            "GIT_SSL_NO_VERIFY=",
            "GIT_SSL_CAINFO=",
            "GIT_DIR",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
            "GIT_NAMESPACE",
            "GIT_REPLACE_REF_BASE",
            "GIT_EXEC_PATH",
            "core.askpass",
            "protocol.version=2",
            "protocol.https.allow=always",
            "credential.helper=",
            "credential.useHttpPath=false",
            "core.sshCommand=",
            "core.gitproxy=",
            "core.hooksPath=/dev/null",
            "--no-includes",
            "protocol(\\..*)?",
            "remote\\..*\\.(uploadpack|proxy)",
        ):
            self.assertIn(required, helper)

        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
            hostile_environment = {
                **os.environ,
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.proxy",
                "GIT_CONFIG_VALUE_0": "http://evil.example:8080",
                "GIT_CONFIG_PARAMETERS": "'http.proxy=http://evil.example:8080'",
                "GIT_ASKPASS": "/tmp/evil-askpass",
                "GIT_SSH_COMMAND": "ssh -oProxyCommand=evil",
                "HTTPS_PROXY": "http://evil.example:8080",
                "GIT_SSL_NO_VERIFY": "1",
            }
            result = subprocess.run(
                ["bash", str(helper_path), "check"], cwd=repo, env=hostile_environment, check=False
            )
            self.assertEqual(result.returncode, 0, "hostile process environment was not blanked")
            hostile = [
                ("url.https://evil.example/.insteadOf", "https://github.com/"),
                ("http.proxy", "http://evil.example:8080"),
                ("http.sslVerify", "false"),
                ("protocol.file.allow", "always"),
                ("credential.helper", "!touch /tmp/credential-helper"),
                ("include.path", "/tmp/evil-git-config"),
                ("core.askPass", "/tmp/evil-askpass"),
                ("core.sshCommand", "ssh -oProxyCommand=evil"),
                ("core.gitProxy", "evil-proxy"),
                ("remote.origin.pushurl", "https://evil.example/push.git"),
                ("remote.origin.vcs", "ssh"),
                ("remote.origin.uploadpack", "evil-upload-pack"),
                ("remote.origin.proxy", "http://evil.example:8080"),
            ]
            for key, value in hostile:
                subprocess.run(["git", "-C", str(repo), "config", "--local", key, value], check=True)
                result = subprocess.run(["bash", str(helper_path), "check"], cwd=repo, check=False)
                self.assertNotEqual(result.returncode, 0, key)
                subprocess.run(["git", "-C", str(repo), "config", "--local", "--unset-all", key], check=False)
            subprocess.run(["git", "-C", str(repo), "config", "extensions.worktreeConfig", "true"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "--worktree", "remote.origin.proxy", "http://evil.example:8080"], check=True)
            result = subprocess.run(["bash", str(helper_path), "check"], cwd=repo, check=False)
            self.assertNotEqual(result.returncode, 0, "worktree override")

    def test_git_transport_rejects_option_smuggling_and_bounds_config_files(self) -> None:
        helper_path = Path(__file__).parent / "git_transport.sh"
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
            hostile_environment = {
                **os.environ,
                "GIT_DIR": str(repo / ".git"),
                "GIT_COMMON_DIR": str(repo / ".git"),
                "GIT_OBJECT_DIRECTORY": str(repo / "objects-hostile"),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(repo / "alternates-hostile"),
                "GIT_INDEX_FILE": str(repo / "index-hostile"),
                "GIT_NAMESPACE": "hostile",
                "GIT_REPLACE_REF_BASE": "refs/replace/hostile/",
                "GIT_EXEC_PATH": str(repo / "git-core-hostile"),
            }
            result = subprocess.run(
                ["/bin/bash", str(helper_path), "check"],
                cwd=repo,
                env=hostile_environment,
                timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 0)

            result = subprocess.run(
                [
                    "bash",
                    str(helper_path),
                    "fetch",
                    "TeleCrypt-io/server_state",
                    "--upload-pack=/tmp/secret-capture",
                ],
                cwd=repo,
                timeout=5,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)

            config_path = repo / ".git" / "config"
            with config_path.open("a", encoding="utf-8") as config:
                for index in range(5000):
                    config.write(f"[hostile-{index}]\\n\\tvalue = {index}\\n")
            result = subprocess.run(
                ["bash", str(helper_path), "check"],
                cwd=repo,
                timeout=5,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)

            config_path.unlink()
            os.mkfifo(config_path)
            result = subprocess.run(
                ["bash", str(helper_path), "check"],
                cwd=repo,
                timeout=5,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_git_transport_ignores_hostile_git_and_remote_helper_executables(self) -> None:
        helper_path = Path(__file__).parent / "git_transport.sh"
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
            executable_dir = repo / "hostile-bin"
            executable_dir.mkdir()
            marker = repo / "executed"
            fake_git = executable_dir / "git"
            fake_git.write_text(f"#!/bin/sh\\nprintf secret > {marker}\\nexit 99\\n", encoding="utf-8")
            fake_git.chmod(0o700)
            fake_remote = executable_dir / "git-remote-https"
            fake_remote.write_text(f"#!/bin/sh\\nprintf secret > {marker}\\nexit 99\\n", encoding="utf-8")
            fake_remote.chmod(0o700)
            result = subprocess.run(
                ["/bin/bash", str(helper_path), "check"],
                cwd=repo,
                env={
                    **os.environ,
                    "PATH": str(executable_dir),
                    "GIT_EXEC_PATH": str(executable_dir),
                    "HTTPS_PROXY": "https://secret.invalid",
                },
                timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def test_release_workflow_bounds_remote_output(self) -> None:
        workflow = (Path(__file__).parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        fetcher = (Path(__file__).parent / "fetch_product_releases.sh").read_text(encoding="utf-8")
        validator = (Path(__file__).parent / "validate.py").read_text(encoding="utf-8")
        self.assertIn('bounded_output 1048576 "$metadata_dir/release-create.log"', workflow)
        self.assertIn('bounded_output 1024 "$digest_path"', workflow)
        self.assertIn('bounded_output 65536 "$metadata_dir/source-fetch.log"', workflow)
        self.assertIn('bounded_output 65536 "$remote_tag_path"', workflow)
        self.assertIn("gh api --include --silent", workflow)
        self.assertIn("checkout_annotated_tag_sha=", workflow)
        self.assertIn(".body == $body", workflow)
        self.assertIn(".created_at", workflow)
        self.assertIn('2> "$stderr"', workflow)
        self.assertIn("unexpected stderr", workflow)
        self.assertIn("stderr bytes", workflow)
        self.assertIn('bounded_asset_download 1048576', workflow)
        self.assertIn('--repo "github.com/$GITHUB_REPOSITORY" --draft \\\n                --verify-tag', workflow)
        self.assertNotIn("target_commitish", workflow)
        self.assertNotIn("--target", workflow)
        self.assertIn("--override-os linux --override-arch amd64", workflow)
        self.assertIn("tag-digest", workflow)
        self.assertIn("product-release-recheck", workflow)
        self.assertIn('gh release edit "$GITHUB_REF_NAME"', workflow)
        self.assertIn('--tag "$GITHUB_REF_NAME" --draft=false --verify-tag', workflow)
        self.assertIn('expected_release_url="https://github.com/$GITHUB_REPOSITORY/releases/tag/$GITHUB_REF_NAME"', workflow)
        self.assertIn('printf \'%s\\n\' "$expected_release_url" >"$expected_url_file"', workflow)
        self.assertIn('cmp -- "$expected_url_file" "$metadata_dir/release-edit.log"', workflow)
        self.assertNotIn('test ! -s "$metadata_dir/release-edit.log"', workflow)
        self.assertIn('gh release edit --help | grep -F -- \'--verify-tag\'', workflow)
        self.assertNotIn("mentions_count", workflow)
        self.assertNotIn("mentions_count", validator)
        self.assertIn('/releases/tag/\" + $tag', workflow)
        self.assertIn('/releases/\" + $tag', workflow)
        self.assertEqual(workflow.count('GIT_CONFIG_SYSTEM: /dev/null'), 2)
        self.assertEqual(workflow.count('GIT_CONFIG_GLOBAL: /dev/null'), 2)
        self.assertEqual(workflow.count('GIT_CONFIG_NOSYSTEM: "1"'), 2)
        self.assertEqual(workflow.count('GIT_CONFIG_KEY_0: credential.helper'), 2)
        self.assertEqual(workflow.count('GIT_CONFIG_VALUE_0: ""'), 2)
        self.assertIn('if type == "boolean" then tostring', workflow)
        self.assertIn('resolved_image="docker://$repository@$resolved_digest"', workflow)
        self.assertIn('draft-asset-state', workflow)
        self.assertIn('recheck_product_release_evidence', workflow)
        self.assertIn('final-product-evidence', workflow)
        self.assertIn('releases?per_page=100&page=$page', workflow)
        self.assertIn('GitHub Releases enumeration reached its page limit', workflow)
        self.assertIn('SERVER_STATE_ANNOTATED_TAG_SHA', workflow)
        self.assertNotIn('SERVER_STATE_TAG_OBJECT', workflow)
        self.assertIn('2> "$stderr"', fetcher)
        self.assertIn("unexpected stderr", fetcher)
        self.assertIn("stderr bytes", fetcher)
        self.assertIn('git/ref/tags/$tag', fetcher)
        self.assertIn('git/tags/$annotated_tag_sha', fetcher)
        self.assertIn('max_bytes % 1024', workflow)
        self.assertIn('MAX_RELEASE_JSON_BYTES % 1024', fetcher)

    def test_final_release_false_draft_state_is_parsed_as_a_string(self) -> None:
        workflow = (Path(__file__).parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        expression = '.draft | if type == "boolean" then tostring else halt_error(1) end'
        self.assertIn(expression, workflow)
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release.json"
            release.write_text(json.dumps({"draft": False}), encoding="utf-8")
            parsed = subprocess.run(
                ["jq", "-er", expression, str(release)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(parsed.returncode, 0, parsed.stderr)
            self.assertEqual(parsed.stdout, "false\n")
            release.write_text(json.dumps({"draft": "false"}), encoding="utf-8")
            rejected = subprocess.run(
                ["jq", "-er", expression, str(release)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)

    def test_outer_manifest_binds_annotated_server_tag(self) -> None:
        values = validate.load_manifest()
        metadata = {
            key: {"Name": image.rsplit(":", 1)[0], "Digest": "sha256:" + "a" * 64}
            for key, image in values.items()
        }
        labels = {
            key: {
                "org.opencontainers.image.source": "https://github.com/example/repository",
                "org.opencontainers.image.version": image.rsplit(":", 1)[1],
                "org.opencontainers.image.revision": "a" * 40,
            }
            for key, image in values.items()
        }
        release_result = {field: "placeholder" for field in validate.PRODUCT_RELEASE_RECORD_KEYS}
        release_result.update({
            "source_commit": "a" * 40, "tag": "0.0.0", "asset": "asset",
            "asset_digest": "sha256:" + "b" * 64, "repository": "example/repository",
            "annotated_tag_sha": "b" * 40, "body": "notes",
            "created_at": "2026-08-23T00:00:00Z", "published_at": "2026-08-23T00:00:00Z",
        })
        with patch.object(validate, "validate_product_release", return_value=release_result):
            document = validate.image_release_manifest(
                values, metadata, labels, "server-state-abcdef1", "a" * 40, "b" * 40,
                {key: {} for key in validate.FIRST_PARTY_RELEASES},
                {key: b"asset" for key in validate.FIRST_PARTY_RELEASES},
                {key: {} for key in validate.FIRST_PARTY_RELEASES},
                {key: {} for key in validate.FIRST_PARTY_RELEASES},
                {key: "sha256:" + ("b" if key == "CADDY_IMAGE" else "c") * 64 for key in validate.IMAGE_KEYS},
            )
        self.assertEqual(document["annotated_tag_sha"], "b" * 40)
        self.assertEqual(set(document["images"]), set(validate.IMAGE_KEYS))
        self.assertEqual(document["images"]["CADDY_IMAGE"]["digest"], "sha256:" + "b" * 64)
        self.assertEqual(document["images"]["SYNAPSE_IMAGE"]["release"], release_result)

    def test_first_party_release_binds_asset_and_exact_release_links(self) -> None:
        values = validate.load_manifest()
        key = "CASHIER_IMAGE"
        image = values[key]
        tag = image.rsplit(":", 1)[1]
        digest = "sha256:" + "a" * 64
        raw = (f'{{"annotated_tag_sha":"{"b" * 40}","digest":"{digest}",'
               f'"image":"{image.rsplit(":", 1)[0]}","schema_version":1,'
               f'"source_commit":"{"a" * 40}","tag":"{tag}"}}\n').encode()
        asset = validate.product_release_asset_name(key, image)
        repository = validate.FIRST_PARTY_RELEASES[key]["repository"]
        release = {
            "id": 7,
            "tag_name": tag,
            "name": tag,
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "url": f"https://api.github.com/repos/{repository}/releases/7",
            "html_url": f"https://github.com/{repository}/releases/tag/{tag}",
            "assets_url": f"https://api.github.com/repos/{repository}/releases/7/assets",
            "upload_url": f"https://uploads.github.com/repos/{repository}/releases/7/assets{{?name,label}}",
            "tarball_url": f"https://api.github.com/repos/{repository}/tarball/{tag}",
            "zipball_url": f"https://api.github.com/repos/{repository}/zipball/{tag}",
            "body": f"Exact Cashier release for source commit {'a' * 40}.",
            "created_at": "2026-08-22T00:00:00Z",
            "published_at": "2026-08-23T00:00:00Z",
            "assets": [{
                "name": asset,
                "id": 8,
                "label": None,
                "state": "uploaded",
                "size": len(raw),
                "url": f"https://api.github.com/repos/{repository}/releases/assets/8",
                "browser_download_url": f"https://github.com/{repository}/releases/download/{tag}/{asset}",
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "created_at": "2026-08-22T00:00:01Z",
                "updated_at": "2026-08-22T00:00:02Z",
            }],
        }
        labels = {"org.opencontainers.image.revision": "a" * 40}
        annotated_tag_sha = "b" * 40
        tag_ref = {
            "ref": f"refs/tags/{tag}",
            "url": f"https://api.github.com/repos/{repository}/git/refs/tags/{tag}",
            "object": {"type": "tag", "sha": annotated_tag_sha, "url": f"https://api.github.com/repos/{repository}/git/tags/{annotated_tag_sha}"},
        }
        annotated_tag = {
            "url": f"https://api.github.com/repos/{repository}/git/tags/{annotated_tag_sha}",
            "sha": annotated_tag_sha,
            "tag": tag,
            "object": {"type": "commit", "sha": "a" * 40, "url": f"https://api.github.com/repos/{repository}/git/commits/{'a' * 40}"},
        }
        result = validate.validate_product_release(key, image, digest, labels, release, raw, tag_ref, annotated_tag)
        self.assertEqual(result["tag"], tag)
        self.assertEqual(result["annotated_tag_sha"], "b" * 40)
        self.assertEqual(result["body"], f"Exact Cashier release for source commit {'a' * 40}.")
        self.assertEqual(result["created_at"], "2026-08-22T00:00:00Z")
        alternate_html_release = {**release, "html_url": f"https://github.com/{repository}/releases/{tag}"}
        validate.validate_product_release(key, image, digest, labels, alternate_html_release, raw, tag_ref, annotated_tag)
        self.assertEqual(set(result), validate.PRODUCT_RELEASE_RECORD_KEYS)
        self.assertNotIn("mentions_count", validate.product_release_api_stable_record(release))
        volatile = {**release, "download_count": 9, "node_id": "volatile", "mentions_count": 9}
        validate.compare_product_release_evidence(
            key, image, digest, labels, release, volatile, raw, raw, tag_ref, tag_ref, annotated_tag, annotated_tag
        )
        stable_change = {**release, "body": "Exact Cashier release for source commit " + "c" * 40 + "."}
        with self.assertRaises(AssertionError):
            validate.compare_product_release_evidence(
                key, image, digest, labels, release, stable_change, raw, raw, tag_ref, tag_ref, annotated_tag, annotated_tag
            )
        release["html_url"] = "https://github.com/example.invalid/wrong"
        with self.assertRaises(AssertionError):
            validate.validate_product_release(key, image, digest, labels, release, raw, tag_ref, annotated_tag)
        release["html_url"] = f"https://github.com/{repository}/releases/tag/{tag}"
        release["id"] = True
        with self.assertRaises(AssertionError):
            validate.validate_product_release(key, image, digest, labels, release, raw, tag_ref, annotated_tag)
        release["id"] = 7
        release["assets"][0]["size"] = True
        with self.assertRaises(AssertionError):
            validate.validate_product_release(key, image, digest, labels, release, raw, tag_ref, annotated_tag)

        release["assets"][0]["size"] = len(raw)
        release.pop("body")
        with self.assertRaises(AssertionError):
            validate.validate_product_release(key, image, digest, labels, release, raw, tag_ref, annotated_tag)
        release["body"] = f"Exact Cashier release for source commit {'a' * 40}."
        release["created_at"] = True
        with self.assertRaises(AssertionError):
            validate.validate_product_release(key, image, digest, labels, release, raw, tag_ref, annotated_tag)

    def test_release_timestamps_are_real_utc_and_chronological(self) -> None:
        release = {
            "created_at": "2026-02-28T23:59:59Z",
            "published_at": "2026-03-01T00:00:02.123Z",
            "assets": [{
                "created_at": "2026-03-01T00:00:00Z",
                "updated_at": "2026-03-01T00:00:01Z",
            }],
        }
        validate.validate_release_timestamps(release, require_published=True)
        for field, value in (("created_at", "2026-02-30T00:00:00Z"), ("published_at", "2026-03-01T00:00:00+00:00")):
            malformed = dict(release)
            malformed[field] = value
            with self.assertRaises(AssertionError):
                validate.validate_release_timestamps(malformed, require_published=True)
        malformed = {**release, "published_at": "2026-02-28T23:00:00Z"}
        with self.assertRaises(AssertionError):
            validate.validate_release_timestamps(malformed, require_published=True)

    def test_synapse_release_body_is_current_contract(self) -> None:
        self.assertEqual(
            validate.product_release_body("SYNAPSE_IMAGE", "1.159-tc3", "a" * 40),
            f"Exact Synapse release for source commit {'a' * 40}.",
        )

    def test_draft_asset_recovery_classifies_safe_states(self) -> None:
        name = "server-state-abcdef1-images.json"
        digest = "sha256:" + "a" * 64
        base = {"name": name, "state": "uploaded", "size": 123, "digest": digest}
        self.assertEqual(validate.draft_asset_action({"assets": []}, name, 123, digest), "upload")
        self.assertEqual(validate.draft_asset_action({"assets": [base]}, name, 123, digest), "verify")
        self.assertEqual(validate.draft_asset_action({"assets": [{**base, "size": 12}]}, name, 123, digest), "replace")
        self.assertEqual(validate.draft_asset_action({"assets": [{**base, "state": "new"}]}, name, 123, digest), "replace")
        with self.assertRaises(AssertionError):
            validate.draft_asset_action({"assets": [base, base]}, name, 123, digest)
        with self.assertRaises(AssertionError):
            validate.draft_asset_action({"assets": [{**base, "name": "unrelated.json"}]}, name, 123, digest)

    def test_release_asset_is_canonical_and_schema_bound(self) -> None:
        raw = b'{"annotated_tag_sha":"' + b"b" * 40 + b'","digest":"sha256:' + b"a" * 64 + b'","image":"repo/image","schema_version":1,"source_commit":"' + b"a" * 40 + b'","tag":"1.0.0"}\n'
        self.assertEqual(validate.parse_product_release_asset("CASHIER_IMAGE", raw)["tag"], "1.0.0")
        with self.assertRaises(AssertionError):
            validate.parse_product_release_asset("CASHIER_IMAGE", raw.replace(b'"tag":"1.0.0"', b'"tag":"1.0.0","extra":true'))
        with self.assertRaises(AssertionError):
            validate.parse_product_release_asset("CASHIER_IMAGE", raw.replace(b'"schema_version":1', b'"schema_version":true'))
        with self.assertRaises(AssertionError):
            validate.parse_product_release_asset("CASHIER_IMAGE", raw.replace(b'"source_commit":"' + b"a" * 40 + b'"', b'"source_commit":true'))


if __name__ == "__main__":
    unittest.main()
