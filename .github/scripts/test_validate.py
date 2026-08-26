#!/usr/bin/env python3
"""Focused semantic tests for Server State validation and release evidence."""

from __future__ import annotations

import os
import json
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

sys.path.insert(0, str(Path(__file__).parent))
import validate  # noqa: E402


HELPER = Path(__file__).parent / "git_transport.sh"
CONTAINER_HELPER = Path(__file__).parent / "container-helpers.sh"


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

    def test_janitor_dry_run_policy_is_documented_for_test_profiles(self) -> None:
        readme = (Path(__file__).resolve().parents[2] / "README.md").read_text(encoding="utf-8")
        self.assertIn("either test profile", readme)
        self.assertIn("rejected for the", readme)
        self.assertIn("live billing profile", readme)
        compose = (Path(__file__).resolve().parents[2] / "compose.yml").read_text(encoding="utf-8")
        janitor = validate.service_section(compose, "janitor")
        self.assertIn("test billing profiles may use dry-run, while live billing may not", janitor)

    def test_plan_secret_name_is_scoped_and_legacy_name_is_absent(self) -> None:
        compose = (Path(__file__).resolve().parents[2] / "compose.yml").read_text(encoding="utf-8")
        workflow = (Path(__file__).resolve().parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("PLAN_SESSION_KEY", validate.PLAN_ENV_KEYS)
        self.assertNotIn("SESSION_KEY", validate.PLAN_ENV_KEYS)
        self.assertIn("PLAN_SESSION_KEY=${PLAN_SESSION_KEY:?set PLAN_SESSION_KEY}", compose)
        self.assertNotRegex(compose, r"(?m)^\s*-\s*SESSION_KEY=")
        self.assertIn("PLAN_SESSION_KEY", workflow)
        self.assertNotRegex(workflow, r"(?m)(?:^|\s)SESSION_KEY(?:\s|$)")

    def test_validation_workflow_has_no_legacy_persistent_media_path(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertNotIn("synapse/media_store", workflow)

    def test_validation_workflow_runs_only_on_trusted_pushes(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn(
            '  push:\n    branches: [main]\n    tags: ["server-state-*"]',
            workflow,
        )
        self.assertNotIn("pull_request:", workflow)

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

    def test_matrix_private_layers_own_complete_shallow_merged_maps(self) -> None:
        compose = (Path(__file__).resolve().parents[2] / "compose.yml").read_text(encoding="utf-8")
        synapse = (Path(__file__).resolve().parents[2] / "synapse.yaml").read_text(encoding="utf-8")
        synapse_document = yaml.safe_load(synapse)
        mas = (Path(__file__).resolve().parents[2] / "mas.yaml").read_text(encoding="utf-8")
        workflow = (Path(__file__).resolve().parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        readme = (Path(__file__).resolve().parents[2] / "README.md").read_text(encoding="utf-8")
        mas_fixture = (Path(__file__).resolve().parents[1] / "fixtures" / "mas.secrets.json").read_text(encoding="utf-8")
        synapse_fixture = yaml.safe_load(
            (Path(__file__).resolve().parents[1] / "fixtures" / "synapse.secrets.json").read_text(encoding="utf-8")
        )
        signing_fixture = (Path(__file__).resolve().parents[1] / "fixtures" / "synapse-signing-fixture.txt").read_text(encoding="utf-8")
        self.assertIn("SYNAPSE_SECRETS_JSON", validate.SECRET_ENV.values())
        self.assertIn("MAS_SECRETS_JSON", validate.SECRET_ENV.values())
        self.assertNotIn("secrets.yaml", compose + synapse + mas)
        self.assertIn("target: /secrets.json", compose)
        self.assertNotIn("database", synapse_document)
        self.assertNotIn("matrix_authentication_service", synapse_document)
        self.assertIn("kind: synapse", mas)
        self.assertIn("endpoint: http://synapse:8008", mas)
        self.assertIn("transport: blackhole", mas)
        self.assertIn("account_deactivation_allowed: true", mas)
        self.assertIn("client_registration/violation", mas)
        self.assertNotIn("postgres_mas", mas)
        self.assertIn("HomeServerConfig", workflow)
        self.assertIn("load_config", workflow)
        self.assertNotIn("loader.read_config", workflow)
        self.assertIn("shallow-merged by top-level key", synapse)
        self.assertEqual(synapse_fixture["database"]["name"], "psycopg2")
        self.assertEqual(
            set(synapse_fixture["database"]["args"]),
            {"user", "password", "database", "host", "port", "sslmode", "connect_timeout"},
        )
        self.assertEqual(
            synapse_fixture["matrix_authentication_service"],
            {"enabled": True, "endpoint": "http://mas:8080", "secret": "ci-matrix-secret"},
        )
        self.assertEqual(
            synapse_fixture["media_storage_providers"][0]["config"]["endpoint_url"],
            "https://sss.telecrypt.io",
        )
        self.assertIn("reachable only from the production VM", synapse)
        self.assertIn("reachable only from the production VM", readme)
        self.assertNotIn("s3.telecrypt.io", synapse + workflow + readme)
        self.assertRegex(signing_fixture, r"\Aed25519 0 [A-Za-z0-9+/]{43}\n\Z")
        self.assertIn("config check --config=/config.yaml --config=/secrets.json", workflow)
        self.assertIn('"client_auth_method":"client_secret_basic"', mas_fixture)
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
                },
                {
                    "source": "synapse_signing_key",
                    "target": "/signing.key",
                },
            ],
        )
        self.assertEqual(
            yaml.safe_load(compose)["secrets"],
            {
                "synapse_secrets_json": {"file": "${TELECRYPT_DATA_DIR:?set TELECRYPT_DATA_DIR}/secrets/synapse.secrets.json"},
                "synapse_signing_key": {"file": "${TELECRYPT_DATA_DIR:?set TELECRYPT_DATA_DIR}/secrets/synapse_signing.key"},
                "mas_secrets_json": {"file": "${TELECRYPT_DATA_DIR:?set TELECRYPT_DATA_DIR}/secrets/mas.secrets.json"},
            },
        )

    def test_caddy_capability_exception_is_exact_and_non_caddy_stays_capability_free(self) -> None:
        compose = yaml.safe_load((Path(__file__).resolve().parents[2] / "compose.yml").read_text(encoding="utf-8"))
        services = compose["services"]
        self.assertEqual(services["caddy"]["cap_drop"], ["ALL"])
        self.assertEqual(services["caddy"]["cap_add"], ["NET_BIND_SERVICE"])
        validate.validate_service_capabilities("caddy", services["caddy"])
        with self.assertRaises(AssertionError):
            validate.validate_service_capabilities(
                "caddy", {**services["caddy"], "cap_add": ["NET_ADMIN"]}
            )
        with self.assertRaises(AssertionError):
            validate.validate_service_capabilities("caddy", {key: value for key, value in services["caddy"].items() if key != "cap_add"})
        for service, settings in services.items():
            if service == "caddy":
                continue
            self.assertNotIn("cap_add", settings)
            validate.validate_service_capabilities(service, settings)
            with self.assertRaises(AssertionError):
                validate.validate_service_capabilities(
                    service, {**settings, "cap_add": ["NET_ADMIN"]}
                )
        workflow = (Path(__file__).resolve().parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        caddy_step = workflow[workflow.index("      - name: Validate Caddy"):workflow.index("\n  release:", workflow.index("      - name: Validate Caddy"))]
        self.assertIn("--cap-drop ALL \\\n            --cap-add NET_BIND_SERVICE", caddy_step)

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
        controlplane_version = validate.load_manifest()["CONTROLPLANE_IMAGE"].rsplit(":", 1)[1]
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
            "org.telecrypt.controlplane.release": controlplane_version,
            "org.telecrypt.s3-provider.version": "1.7.0",
            "org.telecrypt.controlplane.wheel.sha256": "a" * 64,
            "org.telecrypt.s3-provider.archive.sha256": "b" * 64,
        }
        validate.validate_synapse_provenance(labels, dict(labels), "1.159-tc3", controlplane_version)
        with self.assertRaises(AssertionError):
            validate.validate_image_platform(
                {"Os": "linux", "Architecture": "arm64"},
                {"os": "linux", "architecture": "amd64"},
            )
        changed = dict(labels)
        changed["org.telecrypt.controlplane.release"] = "latest"
        with self.assertRaises(AssertionError):
            validate.validate_synapse_provenance(labels, changed, "1.159-tc3", controlplane_version)

    def test_published_image_config_allows_omitted_null_fields_only(self) -> None:
        values = validate.load_manifest()
        digest = "sha256:" + "a" * 64
        synapse_labels = {
            "org.opencontainers.image.source": "https://github.com/TeleCrypt-io/telecrypt-synapse",
            "org.opencontainers.image.revision": "a" * 40,
            "org.opencontainers.image.version": values["SYNAPSE_IMAGE"].rsplit(":", 1)[1],
            "org.opencontainers.image.base.name": "ghcr.io/element-hq/synapse",
            "org.opencontainers.image.base.version": "1.159.0",
            "org.telecrypt.controlplane.release": values["CONTROLPLANE_IMAGE"].rsplit(":", 1)[1],
            "org.telecrypt.s3-provider.version": "1.7.0",
            "org.telecrypt.controlplane.wheel.sha256": "b" * 64,
            "org.telecrypt.s3-provider.archive.sha256": "c" * 64,
        }
        product_labels = {
            key: {
                "org.opencontainers.image.source": f"https://github.com/TeleCrypt-io/{'controlplane' if key == 'CONTROLPLANE_IMAGE' else 'cashier'}",
                "org.opencontainers.image.version": values[key].rsplit(":", 1)[1],
                "org.opencontainers.image.revision": "d" * 40,
                "io.telecrypt.config-contract": "1",
            }
            for key in ("CONTROLPLANE_IMAGE", "CASHIER_IMAGE")
        }
        base_configs = {
            "CADDY_IMAGE": {"Cmd": ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]},
            "SYNAPSE_IMAGE": {"Labels": synapse_labels},
            "MAS_IMAGE": {"Entrypoint": ["/usr/local/bin/mas-cli"]},
            "CONTROLPLANE_IMAGE": {"Cmd": ["/registration"], "Labels": product_labels["CONTROLPLANE_IMAGE"], "User": "991:991"},
            "CASHIER_IMAGE": {"Entrypoint": ["/cashier"], "Labels": product_labels["CASHIER_IMAGE"], "User": "991:991"},
        }

        def write_fixture(directory: Path, mutate=None) -> None:
            configs = {key: dict(config) for key, config in base_configs.items()}
            if mutate is not None:
                mutate(configs)
            for key, image in values.items():
                name = validate.image_reference_filename(image)
                labels = synapse_labels if key == "SYNAPSE_IMAGE" else product_labels.get(key, {})
                config_document = {"os": "linux", "architecture": "amd64", "config": configs[key]}
                metadata = {
                    "Name": image.rsplit(":", 1)[0],
                    "Digest": digest,
                    "Os": "linux",
                    "Architecture": "amd64",
                }
                (directory / f"{name}.labels").write_text(json.dumps(labels), encoding="utf-8")
                (directory / f"{name}.config").write_text(json.dumps(config_document), encoding="utf-8")
                (directory / f"{name}.metadata").write_text(json.dumps(metadata), encoding="utf-8")

        with tempfile.TemporaryDirectory(prefix="server-state-image-config-") as directory:
            root = Path(directory)
            valid = root / "valid"
            valid.mkdir()
            write_fixture(valid)
            validate.validate_published_images(valid)

            mutations = {
                "missing-required-command": lambda configs: configs["CADDY_IMAGE"].pop("Cmd"),
                "wrong-required-command": lambda configs: configs["CADDY_IMAGE"].update(Cmd=["unexpected"]),
                "missing-required-entrypoint": lambda configs: configs["MAS_IMAGE"].pop("Entrypoint"),
                "wrong-required-entrypoint": lambda configs: configs["MAS_IMAGE"].update(Entrypoint=["unexpected"]),
            }
            for name, mutation in mutations.items():
                with self.subTest(name=name):
                    invalid = root / name
                    invalid.mkdir()
                    write_fixture(invalid, mutation)
                    with self.assertRaises(AssertionError):
                        validate.validate_published_images(invalid)


class CaddyRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        root = Path(__file__).resolve().parents[2]
        self.caddy = (root / "Caddyfile").read_text(encoding="utf-8")
        compose = (root / "compose.yml").read_text(encoding="utf-8")
        self.caddy_body = validate.service_section(compose, "caddy")

    def test_media_deletion_route_is_exact_bounded_and_before_generic_matrix_proxy(self) -> None:
        path = "/_matrix/client/unstable/io.telecrypt.storage/delete_media"
        post = self.caddy.index("@telecrypt_delete_media {")
        generic = self.caddy.index("\t@synapse path_regexp")
        self.assertLess(post, generic)
        self.assertIn("method POST", self.caddy[post:self.caddy.index("\n\t}", post)])
        self.assertIn(f"path {path}", self.caddy[post:self.caddy.index("\n\t}", post)])
        self.assertIn("max_size 32KiB", self.caddy[post:generic])

    def test_media_deletion_non_post_is_rejected_with_allow_header(self) -> None:
        start = self.caddy.index("@telecrypt_delete_media_other_method {")
        end = self.caddy.index("\n\t}", start)
        matcher = self.caddy[start:end]
        handle_start = self.caddy.index("handle @telecrypt_delete_media_other_method {")
        handle_end = self.caddy.index("\n\t}", handle_start)
        handle = self.caddy[handle_start:handle_end]
        self.assertIn("path /_matrix/client/unstable/io.telecrypt.storage/delete_media", matcher)
        self.assertIn("not method POST", matcher)
        self.assertIn('header Allow "POST"', handle)
        self.assertIn('respond "Method Not Allowed" 405', handle)
        self.assertNotIn("reverse_proxy", handle)

    def test_closed_federation_discovery_is_direct_all_method_404(self) -> None:
        start = self.caddy.index("handle /.well-known/matrix/server {")
        end = self.caddy.index("\n\t}", start)
        handle = self.caddy[start:end]
        self.assertLess(start, self.caddy.index("@production_apex"))
        self.assertIn('respond "Not Found" 404', handle)
        self.assertNotIn("method ", handle)
        self.assertNotIn("redir ", handle)
        self.assertNotIn("reverse_proxy", handle)
        self.assertNotIn("Location", handle)


class GitTransportTests(unittest.TestCase):
    def test_transport_retains_the_runner_system_ca_store(self) -> None:
        helper = HELPER.read_text(encoding="utf-8")
        self.assertIn("-c http.sslVerify=true", helper)
        self.assertIn("GIT_SSL_CAINFO", helper)
        self.assertIn("GIT_SSL_CAPATH", helper)
        self.assertNotIn("-c http.sslCAInfo=", helper)
        self.assertNotIn("-c http.sslCAPath=", helper)
        self.assertNotIn("-c http.sslCert=", helper)
        self.assertNotIn("-c http.sslKey=", helper)

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

    def test_accepts_exact_github_actions_https_origin_forms(self) -> None:
        for origin in (
            "https://github.com/TeleCrypt-io/server_state",
            "https://github.com/TeleCrypt-io/server_state.git",
        ):
            git(self.root, "remote", "add", "origin", origin)
            result = self.run_helper("check")
            self.assertEqual(result.returncode, 0, (origin, result.stderr))
            git(self.root, "remote", "remove", "origin")

    def test_rejects_github_origin_near_misses(self) -> None:
        for origin in (
            "https://github.com/TeleCrypt-io/server_state/",
            "https://github.com/TeleCrypt-io/server_state.git/",
            "https://github.com/TeleCrypt-io/server_state.evil",
            "https://github.com/TeleCrypt-io/server_state-other",
            "https://github.com/telecrypt-io/server_state",
            "https://x-access-token:redacted@github.com/TeleCrypt-io/server_state",
            "git@github.com:TeleCrypt-io/server_state.git",
        ):
            git(self.root, "remote", "add", "origin", origin)
            result = self.run_helper("check")
            self.assertNotEqual(result.returncode, 0, origin)
            git(self.root, "remote", "remove", "origin")

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
    def test_container_commands_use_the_step_scoped_diagnostics_classifier(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        lines = workflow.splitlines()
        blocks: list[list[str]] = []
        block: list[str] = []
        for line in lines:
            if line.startswith("      - "):
                if block:
                    blocks.append(block)
                block = [line]
            elif block:
                block.append(line)
        if block:
            blocks.append(block)
        command_pattern = re.compile(r"\b(?:docker|skopeo)\s+")
        invocation_count = 0
        for block in blocks:
            for index, line in enumerate(block):
                if not command_pattern.search(line):
                    continue
                if line.lstrip().startswith("uses: "):
                    continue
                invocation_count += 1
                start = index
                while start and block[start - 1].rstrip().endswith("\\"):
                    start -= 1
                self.assertTrue(
                    any("source .github/scripts/container-helpers.sh" in prior for prior in block[: index + 1]),
                    block[0],
                )
                self.assertIn("container_bounded", "\n".join(block[start : index + 1]), line)
        self.assertGreater(invocation_count, 0)
        self.assertNotRegex(
            workflow,
            r"run_bounded_combined\.sh[^\n]*(?:\bdocker\b|\bskopeo\b)",
        )

    def test_stdin_inheritance_is_reserved_for_registry_login(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn('authdir="$(mktemp -d)"', workflow)
        self.assertIn('authfile="$authdir/auth.json"', workflow)
        self.assertIn('rm -rf "$authdir" "$metadata_dir" "$manifest_path"', workflow)
        self.assertNotIn('authfile="$(mktemp)"', workflow)
        self.assertEqual(workflow.count("container_bounded --sensitive --inherit-stdin"), 1)
        login_start = workflow.index("container_bounded --sensitive --inherit-stdin")
        login_end = workflow.index("\n", login_start)
        login_line = workflow[login_start:login_end]
        self.assertIn("skopeo login", login_line)
        self.assertIn("--password-stdin", workflow[login_start : workflow.index("ghcr.io; then", login_start)])
        token_copy = workflow.index('registry_token="$GH_TOKEN"')
        token_unset = workflow.index("unset GH_TOKEN", token_copy)
        self.assertLess(token_unset, login_start)
        token_restore = workflow.index('export GH_TOKEN="$registry_token"', login_start)
        first_api = workflow.index("gh api --include", token_restore)
        self.assertLess(token_restore, first_api)
        final_token_unset = workflow.rindex("unset GH_TOKEN")
        final_registry_check = workflow.rindex("verify_registry_digests")
        self.assertLess(final_token_unset, final_registry_check)
        self.assertIn("unset registry_token", workflow[final_registry_check:])

    def test_registry_login_uses_missing_authfile_and_password_stdin(self) -> None:
        """The login path must let Skopeo create its JSON auth file, without leaking the token."""
        helper = CONTAINER_HELPER
        with tempfile.TemporaryDirectory(prefix="server-state-skopeo-login-") as directory:
            root = Path(directory)
            fake_skopeo = root / "skopeo"
            fake_skopeo.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "[ \"${1:-}\" = login ]\n"
                "shift\n"
                "authfile=\n"
                "while [ $# -gt 0 ]; do\n"
                "  case \"$1\" in\n"
                "    --authfile) authfile=$2; shift 2 ;;\n"
                "    *) shift ;;\n"
                "  esac\n"
                "done\n"
                "[ -n \"$authfile\" ]\n"
                "[ ! -e \"$authfile\" ]\n"
                "printf '%s' absent > \"$AUTHFILE_STATE\"\n"
                "token=$(cat)\n"
                "printf '%s' \"$token\" > \"$TOKEN_CAPTURE\"\n"
                "printf '%s' '{\"auths\":{\"ghcr.io\":{\"auth\":\"offline\"}}}' > \"$authfile\"\n",
                encoding="utf-8",
            )
            fake_skopeo.chmod(0o755)
            authfile_state = root / "authfile-state"
            token_capture = root / "token-capture"
            login_output = root / "login.stdout"
            command = (
                f"source {shlex.quote(str(helper))}; "
                f"export PATH={shlex.quote(str(root))}:$PATH; "
                "authdir=\"$(mktemp -d)\"; "
                "authfile=\"$authdir/auth.json\"; "
                "cleanup() { rm -rf \"$authdir\"; }; trap cleanup EXIT; "
                "registry_token='offline-registry-token'; "
                f"AUTHFILE_STATE={shlex.quote(str(authfile_state))} "
                f"TOKEN_CAPTURE={shlex.quote(str(token_capture))} "
                f"export AUTHFILE_STATE TOKEN_CAPTURE; "
                f"printf '%s' \"$registry_token\" | container_bounded --sensitive --inherit-stdin 65536 "
                f"{shlex.quote(str(login_output))} 30 skopeo login --authfile \"$authfile\" "
                "--username actor --password-stdin ghcr.io"
            )
            result = subprocess.run(
                ["/bin/bash", "-c", command],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(authfile_state.read_text(encoding="utf-8"), "absent")
            self.assertEqual(token_capture.read_text(encoding="utf-8"), "offline-registry-token")
            self.assertNotIn("offline-registry-token", result.stdout + result.stderr)

    def test_secret_bearing_compose_inspection_is_non_emitting(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn('container_bounded --sensitive 1048576 "$rendered_compose"', workflow)
        self.assertIn('container_bounded --sensitive 65536 "$raw_images_file"', workflow)
        self.assertIn('container_bounded --sensitive 65536 "$image_list"', workflow)

    def test_container_diagnostics_accept_progress_and_reject_hostile_markers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="server-state-container-diagnostics-") as directory:
            root = Path(directory)

            def run(
                code: str,
                max_bytes: int = 65536,
                timeout: int = 10,
                *,
                sensitive: bool = False,
            ) -> subprocess.CompletedProcess[str]:
                output = root / "output"
                option = "--sensitive " if sensitive else ""
                command = (
                    f"source {shlex.quote(str(CONTAINER_HELPER))}; "
                    f"container_bounded {option}{max_bytes} {shlex.quote(str(output))} {timeout} "
                    f"/usr/bin/python3 -c {shlex.quote(code)}"
                )
                return subprocess.run(
                    ["/bin/bash", "-c", command],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    timeout=12,
                    check=False,
                )

            progress = run("import sys; sys.stdout.write('digest\\n'); sys.stderr.write('progress: exporting layers\\n')")
            self.assertEqual(progress.returncode, 0, progress.stderr)
            self.assertEqual(progress.stdout, "digest\n")
            self.assertIn("progress: exporting layers", progress.stderr)
            self.assertNotIn("failure diagnostics", progress.stderr)

            for marker in ("warning", "WARN", "error", "fatal", "failure", "denied", "unauthorized"):
                result = run(f"import sys; sys.stdout.write('partial\\n'); sys.stderr.write('{marker}: hostile fixture\\n')")
                self.assertEqual(result.returncode, 1, marker)
                self.assertEqual(result.stdout, "partial\n", marker)
                self.assertIn("hostile fixture", result.stderr, marker)
                self.assertIn("failure diagnostics", result.stderr, marker)

            boundary = run("import sys; sys.stderr.write('warningish error_code\\n')")
            self.assertEqual(boundary.returncode, 0, boundary.stderr)
            self.assertNotIn("failure diagnostics", boundary.stderr)

            sensitive = run(
                "import sys; sys.stdout.write('private stdout\\n'); "
                "sys.stderr.write('warning: private stderr\\n')",
                sensitive=True,
            )
            self.assertEqual(sensitive.returncode, 1)
            self.assertNotIn("private", sensitive.stdout + sensitive.stderr)

            failed = run("import sys; sys.stdout.write('partial\\n'); sys.stderr.write('ordinary diagnostic\\n'); raise SystemExit(17)")
            self.assertEqual(failed.returncode, 17, failed.stderr)
            self.assertIn("ordinary diagnostic", failed.stderr)

            overflow = run("import sys; sys.stderr.write('x' * 70000)", max_bytes=1024)
            self.assertNotEqual(overflow.returncode, 0)
            self.assertIn("bounded command output exceeded its limit", overflow.stderr)

            timed_out = run("import time; time.sleep(60)", timeout=1)
            self.assertEqual(timed_out.returncode, 124, timed_out.stderr)
            self.assertIn("bounded command timed out", timed_out.stderr)

    def test_secret_proof_cleanup_and_value_reads_preserve_failures(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("trap cleanup_on_exit EXIT", workflow)
        self.assertIn("if ! cleanup; then", workflow)
        self.assertNotIn(
            'docker rm -f "$mas_container" "$missing_container" >/dev/null || true',
            workflow,
        )
        bounded_value_start = workflow.index("bounded_docker_value()")
        bounded_value_end = workflow.index("\n          }", bounded_value_start)
        bounded_value = workflow[bounded_value_start:bounded_value_end]
        self.assertIn("if container_bounded", bounded_value)
        self.assertIn('return "$status"', bounded_value)

    def test_sensitive_proof_failures_have_fixed_classes_without_diagnostics(self) -> None:
        classifications = {
            "success": "success",
            "uid": "uid",
            "mount-content": "mount-content",
            "secrets-json": "secrets-json",
            "forbidden-mount": "forbidden-mount",
            "environment-leak": "environment-leak",
        }
        with tempfile.TemporaryDirectory(prefix="server-state-sensitive-class-") as directory:
            root = Path(directory)
            for marker, expected in classifications.items():
                result = subprocess.run(
                    [
                        "/bin/bash",
                        "-c",
                        f"source {shlex.quote(str(CONTAINER_HELPER))}; container_sensitive_failure_class {shlex.quote(marker)}",
                    ],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, marker)
                self.assertEqual(result.stdout, expected + "\n", marker)
                self.assertEqual(result.stderr, "", marker)

                marker_file = root / "marker"
                marker_file.write_text(f"telecrypt-synapse-proof:{marker}\n", encoding="utf-8")
                parsed = subprocess.run(
                    [
                        "/bin/bash",
                        "-c",
                        f"source {shlex.quote(str(CONTAINER_HELPER))}; container_sensitive_marker_class {shlex.quote(str(marker_file))}",
                    ],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(parsed.returncode, 0, marker)
                self.assertEqual(parsed.stdout, expected + "\n", marker)
                self.assertEqual(parsed.stderr, "", marker)

            signing_fixture = (Path(__file__).resolve().parents[1] / "fixtures" / "synapse-signing-fixture.txt").read_text(encoding="utf-8").strip()
            for hostile in (
                signing_fixture,
                f"telecrypt-synapse-proof:uid\n{signing_fixture}",
                "telecrypt-synapse-proof:uid\nnot-a-marker",
            ):
                marker_file = root / "hostile-marker"
                marker_file.write_text(hostile, encoding="utf-8")
                rejected = subprocess.run(
                    [
                        "/bin/bash",
                        "-c",
                        f"source {shlex.quote(str(CONTAINER_HELPER))}; container_sensitive_marker_class {shlex.quote(str(marker_file))}",
                    ],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(rejected.returncode, 0, hostile)
                self.assertEqual(rejected.stdout, "", hostile)
                self.assertEqual(rejected.stderr, "", hostile)

            marker_file = root / "marker"
            stderr_file = root / "stderr"
            marker_file.write_text("telecrypt-synapse-proof:success\n", encoding="utf-8")
            stderr_file.write_text("warning: private diagnostic\n", encoding="utf-8")
            rejected_stderr = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    f"source {shlex.quote(str(CONTAINER_HELPER))}; "
                    f"container_sensitive_proof_class 1 {shlex.quote(str(marker_file))} {shlex.quote(str(stderr_file))}",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(rejected_stderr.returncode, 0)
            self.assertEqual(rejected_stderr.stdout, "stderr-diagnostics\n")
            self.assertEqual(rejected_stderr.stderr, "")

            no_marker = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    f"source {shlex.quote(str(CONTAINER_HELPER))}; "
                    f"container_sensitive_proof_class 1 {shlex.quote(str(root / 'missing'))} {shlex.quote(str(stderr_file))}",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(no_marker.returncode, 0)
            self.assertEqual(no_marker.stdout, "container-runtime\n")
            self.assertEqual(no_marker.stderr, "")

            preflight_cases = {
                "Error response from daemon: manifest unknown: private-fixture": "image-pull",
                "unauthorized: authentication required for ci-secret-fixture": "registry-auth",
                "invalid mount config for type bind: bind source path does not exist: ci-secret-fixture": "mount-source",
                'OCI runtime create failed: exec: "python": executable file not found in $PATH ci-secret-fixture': "entrypoint-executable",
                "failed to create secret ci-secret-fixture: secret not found": "compose-secrets",
                "secret source file does not exist: ci-secret-fixture": "compose-secrets",
                "permission denied while opening ci-secret-fixture": "runtime-permission",
                "operation not permitted while opening ci-secret-fixture": "runtime-permission",
                "read-only file system while opening ci-secret-fixture": "runtime-permission",
                "not a directory: ci-secret-fixture": "file-shape",
                "no such file or directory: ci-secret-fixture": "file-shape",
                "OCI runtime create failed while mounting ci-secret-fixture": "oci-runtime",
                "Cannot connect to the Docker daemon at unix:///var/run/docker.sock: ci-secret-fixture": "daemon-resource",
                "bounded command timed out while handling ci-secret-fixture": "timeout",
            }
            preflight_file = root / "preflight-stderr"
            for diagnostic, expected in preflight_cases.items():
                preflight_file.write_text(diagnostic + "\n", encoding="utf-8")
                classified = subprocess.run(
                    [
                        "/bin/bash",
                        "-c",
                        f"source {shlex.quote(str(CONTAINER_HELPER))}; "
                        f"container_sensitive_preflight_class {shlex.quote(str(preflight_file))}",
                    ],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(classified.returncode, 0, diagnostic)
                self.assertEqual(classified.stdout, expected + "\n", diagnostic)
                self.assertEqual(classified.stderr, "", diagnostic)
                self.assertNotIn("ci-secret-fixture", classified.stdout + classified.stderr, diagnostic)

                proof_class = subprocess.run(
                    [
                        "/bin/bash",
                        "-c",
                        f"source {shlex.quote(str(CONTAINER_HELPER))}; "
                        f"container_sensitive_proof_class 1 {shlex.quote(str(root / 'missing'))} "
                        f"{shlex.quote(str(preflight_file))}",
                    ],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(proof_class.returncode, 0, diagnostic)
                self.assertEqual(proof_class.stdout, expected + "\n", diagnostic)
                self.assertEqual(proof_class.stderr, "", diagnostic)
                self.assertNotIn("ci-secret-fixture", proof_class.stdout + proof_class.stderr, diagnostic)

            preflight_file.write_text("private fixture only: ci-secret-fixture\n", encoding="utf-8")
            generic_preflight = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    f"source {shlex.quote(str(CONTAINER_HELPER))}; "
                    f"container_sensitive_proof_class 1 {shlex.quote(str(root / 'missing'))} "
                    f"{shlex.quote(str(preflight_file))}",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(generic_preflight.returncode, 0)
            self.assertEqual(generic_preflight.stdout, "container-runtime\n")
            self.assertEqual(generic_preflight.stderr, "")
            self.assertNotIn("ci-secret-fixture", generic_preflight.stdout + generic_preflight.stderr)

            preflight_file.write_text("", encoding="utf-8")
            unknown_preflight = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    f"source {shlex.quote(str(CONTAINER_HELPER))}; "
                    f"container_sensitive_proof_class 1 {shlex.quote(str(root / 'missing'))} "
                    f"{shlex.quote(str(preflight_file))}",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(unknown_preflight.returncode, 0)
            self.assertEqual(unknown_preflight.stdout, "bounded-command\n")
            self.assertEqual(unknown_preflight.stderr, "")

            output = root / "proof"
            failed = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    f"source {shlex.quote(str(CONTAINER_HELPER))}; "
                    f"container_bounded --sensitive 1024 {shlex.quote(str(output))} 10 "
                    "/usr/bin/python3 -c 'raise SystemExit(71)'",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(failed.returncode, 71)
            self.assertEqual(failed.stdout, "")
            self.assertEqual(failed.stderr, "")

            redirected_output = root / "redirected-proof"
            redirected = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    f"source {shlex.quote(str(CONTAINER_HELPER))}; "
                    f"container_bounded --sensitive 1024 {shlex.quote(str(redirected_output))} 10 "
                    "/usr/bin/python3 -c 'print(\"telecrypt-synapse-proof:uid\")' >/dev/null",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(redirected.returncode, 0)
            self.assertEqual(redirected.stdout, "")
            self.assertEqual(redirected.stderr, "")
            self.assertEqual(redirected_output.read_text(encoding="utf-8"), "telecrypt-synapse-proof:uid\n")

        workflow = (Path(__file__).resolve().parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("container_sensitive_proof_class", workflow)
        self.assertIn("proof_status=$?", workflow)
        proof_start = workflow.index("      - name: Verify UID-991 secret runtime contract")
        proof_end = workflow.index("Verify UID-991 MAS secret isolation", proof_start)
        proof_block = workflow[proof_start:proof_end]
        self.assertIn("-f .github/secret-proof.compose.yml", proof_block)
        self.assertNotIn('mkdir -p "$TELECRYPT_DATA_DIR/runtime/synapse-staging"', proof_block)
        self.assertIn('install -d -m 700 "$fixture_secrets"', workflow)
        self.assertIn("install -m 444 .github/fixtures/synapse.secrets.json", workflow)
        self.assertIn("install -m 444 .github/fixtures/synapse-signing-fixture.txt", workflow)
        for phase in (
            "config-check",
            "config-output-read",
            "container-user-inspection",
            "container-user-contract",
            "output-secret-isolation",
            "missing-signing-path-accepted",
            "missing-signing-path-timeout",
            "cleanup",
        ):
            self.assertIn(f"mas_failure {phase}", workflow)
        self.assertIn('echo "MAS secret proof failed: $1; sensitive diagnostics were withheld"', workflow)
        self.assertIn("allowed_config_paths", workflow)
        self.assertIn("contextlib.redirect_stdout", workflow)
        self.assertIn("contextlib.redirect_stderr", workflow)
        self.assertIn("getattr(error, \"path\", None)", workflow)
        self.assertIn("marker = config_marker(error)", workflow)
        self.assertIn("except FileNotFoundError", workflow)
        self.assertIn("except PermissionError", workflow)
        self.assertIn("except ModuleNotFoundError", workflow)
        self.assertIn("except ImportError", workflow)
        self.assertIn("except SystemExit", workflow)
        self.assertIn("except Exception", workflow)
        for marker in (
            "success",
            "config-server",
            "config-database",
            "config-logging",
            "config-repository",
            "config-key",
            "config-media",
            "config-listeners",
            "config-unknown",
            "file-not-found",
            "permission",
            "module-import",
            "parser-exit",
            "unexpected",
        ):
            self.assertIn(f"telecrypt-synapse-loader:{marker}", workflow)
        self.assertIn("synapse_loader_failure container-diagnostic", workflow)
        self.assertIn("synapse_loader_failure container-run", workflow)
        self.assertIn("synapse_loader_failure output-read", workflow)
        self.assertIn("synapse_loader_failure output-contract", workflow)
        loader_start = workflow.index("      - name: Verify pinned Synapse JSON config loader")
        loader_end = workflow.index("Verify exact selected container images", loader_start)
        loader_block = workflow[loader_start:loader_end]
        self.assertIn(
            "          ' >/dev/null; then\n"
            "            synapse_loader_status=0\n"
            "          else\n"
            "            synapse_loader_status=$?\n"
            "          fi",
            loader_block,
        )
        self.assertNotIn("if ! container_bounded", loader_block)
        self.assertNotIn("Synapse config loader returned no config", workflow)
        self.assertNotIn("str(error)", workflow)
        self.assertNotIn("repr(error)", workflow)
        self.assertIn('echo "Synapse JSON loader proof failed: $1; sensitive diagnostics were withheld"', workflow)

        proof_compose = yaml.safe_load((Path(__file__).resolve().parents[1] / "secret-proof.compose.yml").read_text(encoding="utf-8"))
        canonical_compose = yaml.safe_load((Path(__file__).resolve().parents[2] / "compose.yml").read_text(encoding="utf-8"))
        proof_services = proof_compose["services"]
        canonical_services = canonical_compose["services"]
        copied_fields = ("image", "user", "read_only", "security_opt", "cap_drop", "secrets")
        for proof_name, canonical_name in (
            ("synapse-secret-proof", "synapse"),
            ("synapse-loader-proof", "synapse"),
            ("mas-secret-proof", "mas"),
        ):
            for field in copied_fields:
                self.assertEqual(proof_services[proof_name][field], canonical_services[canonical_name][field], (proof_name, field))
            self.assertEqual(proof_services[proof_name]["network_mode"], "none")
            self.assertNotIn("networks", proof_services[proof_name])
            self.assertNotIn("depends_on", proof_services[proof_name])
        self.assertNotIn("volumes", proof_services["synapse-secret-proof"])
        self.assertEqual(
            proof_services["synapse-loader-proof"]["tmpfs"],
            [
                "/tmp:uid=991,gid=991,mode=1777,size=16m",
                "/staging:uid=991,gid=991,mode=0700,size=16m",
            ],
        )
        self.assertEqual(proof_services["synapse-loader-proof"]["environment"], ["TMPDIR=/staging/tmp"])
        self.assertGreaterEqual(workflow.count("-f .github/secret-proof.compose.yml"), 4)

        for status in range(70, 75):
            self.assertIn(f"fail({status},", workflow)

    def test_product_tag_evidence_binds_exact_api_urls(self) -> None:
        key = "SYNAPSE_IMAGE"
        tag = validate.load_manifest()[key].rsplit(":", 1)[1]
        repository = validate.PUBLIC_RELEASES[key]["repository"]
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
        self.assertEqual(validate.parse_product_release_asset("SYNAPSE_IMAGE", raw)["tag"], "1.0.0")
        with self.assertRaises(AssertionError):
            validate.parse_product_release_asset("SYNAPSE_IMAGE", raw[:-1] + b" ")
        with self.assertRaises(AssertionError):
            validate.parse_product_release_asset("CASHIER_IMAGE", raw)

    def test_product_release_asset_label_is_exact_empty_string(self) -> None:
        self.assertEqual(validate.validate_release_asset_label("SYNAPSE_IMAGE", {"label": ""}), "")
        for label in (None, "asset-label"):
            with self.subTest(label=label), self.assertRaises(AssertionError):
                validate.validate_release_asset_label("SYNAPSE_IMAGE", {"label": label})

    def test_cashier_manifest_shape_and_oci_provenance_are_strict(self) -> None:
        image = validate.load_manifest()["CASHIER_IMAGE"]
        labels = {
            "org.opencontainers.image.source": "https://github.com/TeleCrypt-io/cashier",
            "org.opencontainers.image.version": image.rsplit(":", 1)[1],
            "org.opencontainers.image.revision": "a" * 40,
        }
        self.assertNotIn("CASHIER_IMAGE", validate.PUBLIC_RELEASES)
        self.assertEqual(
            validate.validate_cashier_provenance(labels, image),
            {"source": labels["org.opencontainers.image.source"], "version": labels["org.opencontainers.image.version"], "revision": labels["org.opencontainers.image.revision"]},
        )
        self.assertEqual(validate.IMAGE_RECORD_KEYS, {"digest", "image"})
        for field, value in (
            ("org.opencontainers.image.source", "https://github.com/TeleCrypt-io/other"),
            ("org.opencontainers.image.version", "0.0.0"),
            ("org.opencontainers.image.revision", "not-a-commit"),
        ):
            mutated = {**labels, field: value}
            with self.subTest(field=field), self.assertRaises(AssertionError):
                validate.validate_cashier_provenance(mutated, image)

    def test_image_release_manifest_serializes_only_exact_image_digest_records(self) -> None:
        values = validate.load_manifest()
        digest = "sha256:" + "a" * 64
        metadata = {key: {"Name": image.rsplit(":", 1)[0], "Digest": digest} for key, image in values.items()}
        labels = {
            key: {
                "org.opencontainers.image.source": f"https://github.com/TeleCrypt-io/{'telecrypt-synapse' if key == 'SYNAPSE_IMAGE' else 'controlplane'}",
                "org.opencontainers.image.version": image.rsplit(":", 1)[1],
                "org.opencontainers.image.revision": "b" * 40,
            }
            for key, image in values.items()
            if key in validate.PUBLIC_RELEASE_KEYS
        }
        labels["CASHIER_IMAGE"] = {
            "org.opencontainers.image.source": "https://github.com/TeleCrypt-io/cashier",
            "org.opencontainers.image.version": values["CASHIER_IMAGE"].rsplit(":", 1)[1],
            "org.opencontainers.image.revision": "c" * 40,
        }

        def fake_release(key: str, image: str, _digest: str, provenance: dict, *_evidence: object) -> dict:
            release = {field: "fixture" for field in validate.PRODUCT_RELEASE_RECORD_KEYS}
            release["source_commit"] = provenance["org.opencontainers.image.revision"]
            return release

        with mock.patch.object(validate, "validate_product_release", side_effect=fake_release):
            document = validate.image_release_manifest(
                values,
                metadata,
                labels,
                "server-state-abc1234",
                "d" * 40,
                "e" * 40,
                product_releases={key: {} for key in validate.PUBLIC_RELEASE_KEYS},
                product_assets={key: b"fixture" for key in validate.PUBLIC_RELEASE_KEYS},
                product_tag_refs={key: {"fixture": True} for key in validate.PUBLIC_RELEASE_KEYS},
                product_annotated_tags={key: {"fixture": True} for key in validate.PUBLIC_RELEASE_KEYS},
                resolved_digests={key: digest for key in values},
            )
        for key, record in document["images"].items():
            with self.subTest(key=key):
                self.assertEqual(set(record), validate.IMAGE_RECORD_KEYS)
                validate.validate_image_record(key, record)
        cashier_with_extra = {**document["images"]["CASHIER_IMAGE"], "release": {}}
        with self.assertRaises(AssertionError):
            validate.validate_image_record("CASHIER_IMAGE", cashier_with_extra)

    def test_product_release_fetch_is_public_only_and_reports_safe_request_identity(self) -> None:
        script = Path(__file__).parent / "fetch_product_releases.sh"
        text = script.read_text(encoding="utf-8")
        self.assertNotIn("TeleCrypt-io/cashier", text)
        self.assertNotIn("fetch_release_asset CASHIER_IMAGE", text)
        for phase in ("tag-ref", "annotated-tag", "release", "asset"):
            self.assertIn(f'{phase} "$repository" "$tag"', text)
        with tempfile.TemporaryDirectory(prefix="server-state-gh-unauthorized-") as directory:
            root = Path(directory)
            fake_gh = root / "gh"
            fake_gh.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' 'gh: Not Found (HTTP 404)' >&2\n"
                "exit 1\n",
                encoding="utf-8",
            )
            fake_gh.chmod(0o755)
            result = subprocess.run(
                ["/bin/bash", str(script)],
                cwd=script.parents[2],
                env={
                    **os.environ,
                    "PATH": f"{root}:{os.environ['PATH']}",
                    "GH_TOKEN": "offline-test-token",
                    "METADATA_DIR": str(root / "metadata"),
                },
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("phase=tag-ref", result.stderr)
            self.assertIn("repository=TeleCrypt-io/telecrypt-synapse", result.stderr)
            self.assertIn("tag=1.159-tc7", result.stderr)
            self.assertNotIn("offline-test-token", result.stdout + result.stderr)

    def test_release_workflow_uses_bounded_machine_http_status_checks(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("gh api --include", workflow)
        self.assertIn("http_status", workflow)
        self.assertIn("bounded_gh", workflow)
        self.assertIn("bounded-command.py", Path(__file__).with_name("run_bounded_combined.sh").read_text(encoding="utf-8"))
        self.assertNotRegex(workflow, r"grep -Eiq '.*404")
        self.assertEqual(workflow.count('.label == ""'), 2)
        self.assertNotIn(".label == null", workflow)

    def test_release_workflow_discovers_complete_unique_draft_by_numeric_id(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("releases?per_page=100&page=$page", workflow)
        self.assertIn("--jq '[.[] | {id,tag_name,draft}]'", workflow)
        self.assertIn("max_release_pages=100", workflow)
        self.assertIn("Release list completeness cannot be proven", workflow)
        self.assertIn("match_count", workflow)
        self.assertIn("get_release_by_id", workflow)
        self.assertIn("release_id", workflow)
        self.assertIn("upload_url", workflow)
        self.assertIn("--method PATCH", workflow)
        self.assertNotIn("/releases/tags/$GITHUB_REF_NAME", workflow)
        self.assertNotIn("gh release create", workflow)
        self.assertNotIn("gh release upload", workflow)
        self.assertNotIn("gh release edit", workflow)

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

    def test_bounded_container_explicit_stdin_inheritance_is_secret_safe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="server-state-stdin-") as directory:
            root = Path(directory)
            output = root / "output"
            secret = "offline-fixture-secret\n"
            child = (
                "import sys; value=sys.stdin.read(); "
                "assert value == 'offline-fixture-secret\\n'; "
                "sys.stdout.write(value); sys.stderr.write(value)"
            )
            command = (
                f"source {shlex.quote(str(CONTAINER_HELPER))}; "
                f"container_bounded --sensitive --inherit-stdin 1024 {shlex.quote(str(output))} 10 "
                f"/usr/bin/python3 -c {shlex.quote(child)}"
            )
            result = subprocess.run(
                ["/bin/bash", "-c", command],
                cwd=root,
                input=secret,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            transcript = result.stdout + result.stderr
            self.assertNotIn(secret, transcript)
            self.assertEqual(output.read_text(encoding="utf-8"), secret)
            self.assertEqual(Path(f"{output}.stderr").read_text(encoding="utf-8"), secret)

    def test_bounded_container_keeps_stdin_closed_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="server-state-stdin-closed-") as directory:
            root = Path(directory)
            output = root / "output"
            secret = "offline-secret-must-not-reach-child\n"
            child = "import sys; assert sys.stdin.read() == ''; print('stdin closed')"
            command = (
                f"source {shlex.quote(str(CONTAINER_HELPER))}; "
                f"container_bounded 1024 {shlex.quote(str(output))} 10 "
                f"/usr/bin/python3 -c {shlex.quote(child)}"
            )
            result = subprocess.run(
                ["/bin/bash", "-c", command],
                cwd=root,
                input=secret,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            transcript = result.stdout + result.stderr + output.read_text(encoding="utf-8")
            self.assertIn("stdin closed", transcript)
            self.assertNotIn(secret, transcript)

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
                 "import os, subprocess, sys; descendant=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); print('leader'); sys.stdout.flush(); os._exit(0)"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(encoding="utf-8"), "leader\n")


if __name__ == "__main__":
    unittest.main()
