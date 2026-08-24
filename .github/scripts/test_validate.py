#!/usr/bin/env python3
"""Focused semantic tests for Server State validation and release evidence."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
import validate  # noqa: E402


HELPER = Path(__file__).parent / "git_transport.sh"


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["/usr/bin/git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


class ManifestTests(unittest.TestCase):
    def test_billing_profile_table_is_exact_and_propagation_is_minimal(self) -> None:
        self.assertEqual(
            validate.VALID_PROFILES,
            {("telecrypt.io", "test"), ("stage.telecrypt.io", "test"), ("telecrypt.io", "live")},
        )
        for profile in validate.VALID_PROFILES:
            self.assertEqual(validate.validate_profile({"SERVER_NAME": profile[0], "BILLING_ENVIRONMENT": profile[1]}), profile)
        for profile in (("stage.telecrypt.io", "live"), ("other.telecrypt.io", "test"), ("telecrypt.io", "sandbox")):
            with self.assertRaises(AssertionError):
                validate.validate_profile({"SERVER_NAME": profile[0], "BILLING_ENVIRONMENT": profile[1]})
        compose = (Path(__file__).resolve().parents[2] / "compose.yml").read_text(
            encoding="utf-8"
        )
        for service in ("caddy", "registration", "synapse", "mas"):
            body = validate.service_section(compose, service)
            self.assertNotIn("BILLING_ENVIRONMENT", body)
        for service in ("janitor", "plan", "cashier"):
            body = validate.service_section(compose, service)
            self.assertIn("BILLING_ENVIRONMENT=${BILLING_ENVIRONMENT:?set BILLING_ENVIRONMENT}", body)

    def test_plan_secret_name_is_scoped_and_legacy_name_is_absent(self) -> None:
        compose = (Path(__file__).resolve().parents[2] / "compose.yml").read_text(encoding="utf-8")
        workflow = (Path(__file__).resolve().parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("PLAN_SESSION_KEY", validate.PLAN_ENV_KEYS)
        self.assertNotIn("SESSION_KEY", validate.PLAN_ENV_KEYS)
        self.assertIn("PLAN_SESSION_KEY=${PLAN_SESSION_KEY:?set PLAN_SESSION_KEY}", compose)
        self.assertNotRegex(compose, r"(?m)^\s*-\s*SESSION_KEY=")
        self.assertIn("PLAN_SESSION_KEY", workflow)
        self.assertNotRegex(workflow, r"(?m)(?:^|\s)SESSION_KEY(?:\s|$)")

    def test_synapse_mas_peer_is_internal_and_egress_isolated(self) -> None:
        compose = (Path(__file__).resolve().parents[2] / "compose.yml").read_text(encoding="utf-8")
        self.assertEqual(validate.EGRESS_NETWORKS["synapse"], "synapse_egress_net")
        self.assertEqual(validate.EGRESS_NETWORKS["mas"], "mas_egress_net")
        self.assertIn("synapse_mas_net", validate.INTERNAL_NETWORKS)
        self.assertNotIn("synapse_egress_net", validate.INTERNAL_NETWORKS)
        self.assertNotIn("mas_egress_net", validate.INTERNAL_NETWORKS)
        self.assertEqual(
            validate.SERVICE_NETWORKS["synapse"],
            {"edge_synapse_net", "synapse_mas_net", "synapse_egress_net", "cashier_synapse_net"},
        )
        self.assertEqual(
            validate.SERVICE_NETWORKS["mas"],
            {"edge_mas_net", "synapse_mas_net", "mas_egress_net", "plan_mas_net", "mas_admin_net"},
        )
        self.assertIn("synapse_mas_net:\n    internal: true", compose)
        self.assertIn("synapse_egress_net:\n  mas_egress_net:", compose)
        self.assertIn("mas-synapse", compose)
        self.assertNotRegex(compose, r"(?s)synapse_mas_net:\s*\n\s*gw_priority:\s*1")

    def test_matrix_private_layers_are_json_and_base_owns_nonsecret_options(self) -> None:
        compose = (Path(__file__).resolve().parents[2] / "compose.yml").read_text(encoding="utf-8")
        synapse = (Path(__file__).resolve().parents[2] / "synapse.yaml").read_text(encoding="utf-8")
        mas = (Path(__file__).resolve().parents[2] / "mas.yaml").read_text(encoding="utf-8")
        workflow = (Path(__file__).resolve().parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("SYNAPSE_SECRETS_JSON", validate.SECRET_ENV.values())
        self.assertIn("MAS_SECRETS_JSON", validate.SECRET_ENV.values())
        self.assertNotIn("secrets.yaml", compose + synapse + mas)
        self.assertIn("target: /secrets.json", compose)
        self.assertIn("name: psycopg2", synapse)
        self.assertIn("endpoint: http://mas:8080", synapse)
        self.assertIn("kind: synapse", mas)
        self.assertIn("endpoint: http://synapse:8008", mas)
        self.assertIn("transport: blackhole", mas)
        self.assertIn("account_deactivation_allowed: true", mas)
        self.assertIn("client_registration/violation", mas)
        self.assertNotIn("postgres_mas", mas)
        self.assertIn("HomeServerConfig", workflow)
        self.assertIn("config check --config=/config.yaml --config=/secrets.json", workflow)
        self.assertIn('"client_auth_method":"client_secret_basic"', workflow)
        self.assertNotIn('"transport":"disabled"', workflow)
        self.assertNotIn("SYNAPSE_SECRETS_YAML", workflow)
        self.assertNotIn("MAS_SECRETS_YAML", workflow)

    def test_synapse_signing_key_is_a_secret_not_environment_data(self) -> None:
        compose = (Path(__file__).resolve().parents[2] / "compose.yml").read_text(encoding="utf-8")
        document = yaml.safe_load(compose)
        synapse = document["services"]["synapse"]
        self.assertEqual(validate.SERVICE_ENV_KEYS["synapse"], {"TMPDIR"})
        self.assertEqual(synapse["environment"], ["TMPDIR=/staging/tmp"])
        self.assertEqual(
            synapse["secrets"],
            [
                {
                    "source": "synapse_secrets_json",
                    "target": "/secrets.json",
                    "uid": "991",
                    "gid": "991",
                    "mode": 0o400,
                },
                {
                    "source": "synapse_signing_key",
                    "target": "/signing.key",
                    "uid": "991",
                    "gid": "991",
                    "mode": 0o400,
                },
            ],
        )

    def test_manifest_has_exactly_five_versioned_images(self) -> None:
        values = validate.load_manifest()
        self.assertEqual(set(values), set(validate.IMAGE_KEYS))
        self.assertEqual(len(set(values.values())), len(validate.IMAGE_KEYS))
        with self.assertRaises(AssertionError):
            validate.parse_manifest([*(f"{key}={value}" for key, value in values.items()), "EXTRA=x:1"])

    def test_version_and_toolchain_validation_rejects_malformed_values(self) -> None:
        validate.version_tuple("24.0.9", "engine")
        validate.validate_toolchain("28.0.0", "2.40.0")
        for value in ("", "1.2", "1.2.3.4"):
            with self.assertRaises(AssertionError):
                validate.version_tuple(value, "version")

    def test_image_platform_and_provenance_are_bound(self) -> None:
        validate.validate_image_platform(
            {"Os": "linux", "Architecture": "amd64", "Digest": "sha256:" + "a" * 64},
            {"os": "linux", "architecture": "amd64"},
        )
        labels = {
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
        validate.validate_synapse_provenance(labels, dict(labels), "1.159-tc3", "0.4.0")
        with self.assertRaises(AssertionError):
            validate.validate_image_platform(
                {"Os": "linux", "Architecture": "arm64"},
                {"os": "linux", "architecture": "amd64"},
            )
        changed = dict(labels)
        changed["org.telecrypt.controlplane.release"] = "latest"
        with self.assertRaises(AssertionError):
            validate.validate_synapse_provenance(labels, changed, "1.159-tc3", "0.4.0")


class GitTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="server-state-git-")
        self.root = Path(self.directory.name)
        git(self.root, "init", "--quiet")
        (self.root / "fixture").write_text("first\n", encoding="utf-8")
        git(self.root, "-c", "user.email=test@example.invalid", "-c", "user.name=Test", "add", "fixture")
        git(self.root, "-c", "user.email=test@example.invalid", "-c", "user.name=Test", "commit", "--quiet", "-m", "first")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def run_helper(self, *args: str, **environment: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash", str(HELPER), *args],
            cwd=self.root,
            env={**os.environ, **environment},
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_reads_use_checkout_identity_despite_ambient_git_state(self) -> None:
        expected = git(self.root, "rev-parse", "HEAD")
        result = self.run_helper(
            "local-read", "rev-parse", "HEAD",
            GIT_DIR=str(self.root / "missing"),
            GIT_INDEX_FILE=str(self.root / "missing-index"),
            GIT_OBJECT_DIRECTORY=str(self.root / "missing-objects"),
            GIT_REPLACE_REF_BASE="refs/replace/hostile",
            GIT_CONFIG_COUNT="1",
            GIT_CONFIG_KEY_0="http.proxy",
            GIT_CONFIG_VALUE_0="http://evil.invalid",
            GIT_TRACE="/tmp/server-state-hostile-trace",
            GIT_TRACE2="/tmp/server-state-hostile-trace2",
            GIT_TRACE_PACK_ACCESS="1",
            GIT_TRACE_PERFORMANCE="1",
            GIT_TRACE_PACKET="1",
            GIT_TRACE_SHALLOW="1",
            GIT_CURL_VERBOSE="1",
            GIT_TRACE2_ENV_VARS="GIT_DIR",
            GIT_TRACE2_MAX_FILES="1",
            HTTPS_PROXY="http://evil.invalid",
            GIT_ALLOW_PROTOCOL="file:ext:ssh",
            GIT_PROTOCOL_FROM_USER="1",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), expected)

    def test_replacement_refs_do_not_change_tag_identity(self) -> None:
        first_commit = git(self.root, "rev-parse", "HEAD")
        git(self.root, "-c", "user.email=test@example.invalid", "-c", "user.name=Test", "tag", "-a", "v1", "-m", "v1")
        first_tag = git(self.root, "rev-parse", "refs/tags/v1")
        (self.root / "fixture").write_text("second\n", encoding="utf-8")
        git(self.root, "add", "fixture")
        git(self.root, "-c", "user.email=test@example.invalid", "-c", "user.name=Test", "commit", "--quiet", "-m", "second")
        second_tag = git(self.root, "rev-parse", "HEAD")
        git(self.root, "-c", "user.email=test@example.invalid", "-c", "user.name=Test", "tag", "-a", "v2", "-m", "v2")
        git(self.root, "replace", first_tag, git(self.root, "rev-parse", "refs/tags/v2"))
        raw = self.run_helper("local-read", "rev-parse", "refs/tags/v1")
        peeled = self.run_helper("local-read", "rev-parse", "refs/tags/v1^{}")
        self.assertEqual(raw.returncode, 0, raw.stderr)
        self.assertEqual(peeled.returncode, 0, peeled.stderr)
        self.assertEqual(raw.stdout.strip(), first_tag)
        self.assertEqual(peeled.stdout.strip(), first_commit)
        self.assertNotEqual(second_tag, first_commit)

    def test_transport_accepts_only_canonical_bounded_refs(self) -> None:
        wrong_repo = self.run_helper("fetch", "Other/repository", "refs/heads/main:refs/remotes/origin/main")
        self.assertNotEqual(wrong_repo.returncode, 0)
        option = self.run_helper("fetch", "TeleCrypt-io/server_state", "--upload-pack=/tmp/hostile")
        self.assertNotEqual(option.returncode, 0)
        malformed = self.run_helper("local-read", "rev-parse", "--option")
        self.assertNotEqual(malformed.returncode, 0)

    def test_rejects_repository_local_transport_configuration(self) -> None:
        for key, value in (
            ("url.hostile.insteadOf", "https://github.com/"),
            ("url.hostile.pushInsteadOf", "https://github.com/"),
            ("include.path", str(self.root / "included-config")),
            ("includeIf.onbranch:main.path", str(self.root / "included-config")),
            ("credential.helper", "store"),
            ("hooks.allownonstdhook", "true"),
            ("core.hooksPath", str(self.root / "hooks")),
            ("remote.origin.vcs", "hostile-helper"),
            ("remote.origin.proxy", "http://evil.invalid"),
            ("remote.origin.uploadpack", "/tmp/hostile-upload-pack"),
            ("remote.origin.receivepack", "/tmp/hostile-receive-pack"),
            ("remote.origin.pushurl", "https://evil.invalid/repository.git"),
            ("remote.evil.vcs", "hostile-helper"),
            ("remote.evil.pushurl", "https://evil.invalid/repository.git"),
            ("remote.evil.url", "https://evil.invalid/repository.git"),
        ):
            git(self.root, "config", "--local", key, value)
            result = self.run_helper("local-read", "rev-parse", "HEAD")
            self.assertNotEqual(result.returncode, 0, key)
            git(self.root, "config", "--local", "--unset-all", key)


class ReleaseEvidenceTests(unittest.TestCase):
    def test_product_tag_evidence_binds_exact_api_urls(self) -> None:
        key = "CASHIER_IMAGE"
        tag = validate.load_manifest()[key].rsplit(":", 1)[1]
        repository = validate.FIRST_PARTY_RELEASES[key]["repository"]
        annotated_tag_sha = "b" * 40
        source_commit = "a" * 40
        api_root = f"https://api.github.com/repos/{repository}"
        tag_ref = {
            "ref": f"refs/tags/{tag}",
            "url": f"{api_root}/git/refs/tags/{tag}",
            "object": {
                "type": "tag",
                "sha": annotated_tag_sha,
                "url": f"{api_root}/git/tags/{annotated_tag_sha}",
            },
        }
        annotated_tag = {
            "sha": annotated_tag_sha,
            "tag": tag,
            "url": f"{api_root}/git/tags/{annotated_tag_sha}",
            "object": {
                "type": "commit",
                "sha": source_commit,
                "url": f"{api_root}/git/commits/{source_commit}",
            },
        }
        validate.validate_product_tag_evidence(
            key, tag, source_commit, annotated_tag_sha, tag_ref, annotated_tag
        )
        invalid = {**annotated_tag, "object": {**annotated_tag["object"], "url": f"{api_root}/git/commits/{source_commit}/unexpected"}}
        with self.assertRaises(AssertionError):
            validate.validate_product_tag_evidence(
                key, tag, source_commit, annotated_tag_sha, tag_ref, invalid
            )

    def test_product_asset_schema_is_strict(self) -> None:
        raw = (
            b'{"annotated_tag_sha":"' + b"b" * 40 + b'","digest":"sha256:' + b"a" * 64 +
            b'","image":"repo/image","schema_version":1,"source_commit":"' + b"a" * 40 +
            b'","tag":"1.0.0"}\n'
        )
        self.assertEqual(validate.parse_product_release_asset("CASHIER_IMAGE", raw)["tag"], "1.0.0")
        with self.assertRaises(AssertionError):
            validate.parse_product_release_asset("CASHIER_IMAGE", raw[:-1] + b" ")

    def test_release_workflow_uses_bounded_machine_http_status_checks(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("gh api --include", workflow)
        self.assertIn("http_status", workflow)
        self.assertIn("bounded_gh", workflow)
        self.assertIn("bounded-command.py", Path(__file__).with_name("run_bounded_combined.sh").read_text(encoding="utf-8"))
        self.assertNotRegex(workflow, r"grep -Eiq '.*404")

    def test_product_release_fetch_rejects_oversized_api_response(self) -> None:
        script = Path(__file__).parent / "fetch_product_releases.sh"
        with tempfile.TemporaryDirectory(prefix="server-state-gh-") as directory:
            root = Path(directory)
            fake_gh = root / "gh"
            fake_gh.write_text(
                "#!/bin/sh\n"
                "head -c 1100000 /dev/zero\n",
                encoding="utf-8",
            )
            fake_gh.chmod(0o755)
            metadata = root / "metadata"
            result = subprocess.run(
                ["/bin/bash", str(script)],
                cwd=script.parents[2],
                env={
                    **os.environ,
                    "PATH": f"{root}:{os.environ['PATH']}",
                    "GH_TOKEN": "offline-test-token",
                    "METADATA_DIR": str(metadata),
                },
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_bounded_combined_allows_large_child_work_file(self) -> None:
        script = Path(__file__).parent / "run_bounded_combined.sh"
        with tempfile.TemporaryDirectory(prefix="server-state-bounded-") as directory:
            root = Path(directory)
            output = root / "output"
            result = subprocess.run(
                [
                    "/bin/bash",
                    str(script),
                    str(output),
                    "/usr/bin/python3",
                    "-c",
                    "from pathlib import Path; Path('work.bin').write_bytes(b'x' * 131072); print('ok')",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(encoding="utf-8").strip(), "ok")
            self.assertEqual((root / "work.bin").stat().st_size, 131072)

    def test_bounded_combined_enforces_one_aggregate_limit(self) -> None:
        script = Path(__file__).parent / "run_bounded_combined.sh"
        with tempfile.TemporaryDirectory(prefix="server-state-combined- bound-") as directory:
            output = Path(directory) / "output"
            result = subprocess.run(
                ["/bin/bash", str(script), "--max-bytes", "1024", str(output),
                 "/usr/bin/python3", "-c", "import sys; sys.stdout.write('x' * 1024); sys.stderr.write('y')"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertLessEqual(output.stat().st_size, 1024)

    def test_bounded_combined_kills_inherited_descriptor_descendants(self) -> None:
        script = Path(__file__).parent / "run_bounded_combined.sh"
        with tempfile.TemporaryDirectory(prefix="server-state-descendant-") as directory:
            output = Path(directory) / "output"
            result = subprocess.run(
                ["/bin/bash", str(script), "--max-bytes", "1024", str(output),
                 "/usr/bin/python3", "-c",
                 "import subprocess, sys; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); print('leader')"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(encoding="utf-8"), "leader\n")


if __name__ == "__main__":
    unittest.main()
