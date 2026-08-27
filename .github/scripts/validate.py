#!/usr/bin/env python3
"""Dependency-free checks for the Server State source and release contract.

Compose is the parser for Compose.  This module checks the small set of invariants that Compose
cannot express: image coordinates, identity derivation, security boundaries, route policy, OCI
provenance, and the immutable release evidence used by the final manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
IMAGE_KEYS = ("CADDY_IMAGE", "SYNAPSE_IMAGE", "MAS_IMAGE", "CONTROLPLANE_IMAGE", "CASHIER_IMAGE")
IMAGE_RULES = {
    "CADDY_IMAGE": ("docker.io/caddy", r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-alpine"),
    "SYNAPSE_IMAGE": ("ghcr.io/telecrypt-io/telecrypt-synapse", r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-tc(?:0|[1-9][0-9]*)"),
    "MAS_IMAGE": ("ghcr.io/element-hq/matrix-authentication-service", r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"),
    "CONTROLPLANE_IMAGE": ("ghcr.io/telecrypt-io/controlplane", r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"),
    "CASHIER_IMAGE": ("ghcr.io/telecrypt-io/telecrypt-cashier", r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"),
}
SERVICES = ("caddy", "synapse", "mas", "registration", "janitor", "plan", "cashier")
SERVICE_IMAGES = {
    "caddy": "CADDY_IMAGE", "synapse": "SYNAPSE_IMAGE", "mas": "MAS_IMAGE",
    "registration": "CONTROLPLANE_IMAGE", "janitor": "CONTROLPLANE_IMAGE",
    "plan": "CONTROLPLANE_IMAGE", "cashier": "CASHIER_IMAGE",
}
SERVICE_NETWORKS = {
    "caddy": {"caddy_ingress_net", "edge_synapse_net", "edge_mas_net", "edge_registration_net", "edge_plan_net", "edge_cashier_net"},
    "synapse": {"edge_synapse_net", "synapse_mas_net", "synapse_egress_net", "cashier_synapse_net"},
    "mas": {"edge_mas_net", "synapse_mas_net", "mas_egress_net", "plan_mas_net", "mas_admin_net"},
    "registration": {"edge_registration_net", "registration_egress_net"},
    "janitor": {"mas_admin_net", "janitor_egress_net"},
    "plan": {"edge_plan_net", "plan_mas_net", "plan_cashier_net"},
    "cashier": {"edge_cashier_net", "plan_cashier_net", "cashier_synapse_net", "cashier_egress_net"},
}
CADDY_INGRESS_NETWORK = "caddy_ingress_net"
INTERNAL_NETWORKS = {
    "edge_synapse_net", "edge_mas_net", "edge_registration_net", "edge_plan_net", "edge_cashier_net",
    "synapse_mas_net", "cashier_synapse_net", "plan_cashier_net", "plan_mas_net", "mas_admin_net",
}
EGRESS_NETWORKS = {"synapse": "synapse_egress_net", "mas": "mas_egress_net", "registration": "registration_egress_net",
                   "janitor": "janitor_egress_net", "cashier": "cashier_egress_net"}
SECRET_ENV = {
    "synapse_secrets_json": "SYNAPSE_SECRETS_JSON",
    "synapse_signing_key": "SYNAPSE_SIGNING_KEY",
    "mas_secrets_json": "MAS_SECRETS_JSON",
}
SECRET_FILES = {
    "synapse_secrets_json": "synapse.secrets.json",
    "synapse_signing_key": "synapse_signing.key",
    "mas_secrets_json": "mas.secrets.json",
}
JANITOR_ENV_KEYS = {
    "MAS_ADMIN_CLIENT_ID", "MAS_ADMIN_CLIENT_SECRET", "JANITOR_DB_URL", "OWNER_EMAIL",
    "JANITOR_DRY_RUN", "SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM",
}
JANITOR_REQUIRED_ENV_KEYS = {"MAS_ADMIN_CLIENT_ID", "MAS_ADMIN_CLIENT_SECRET", "JANITOR_DB_URL", "JANITOR_DRY_RUN"}
JANITOR_OPTIONAL_ENV_KEYS = JANITOR_ENV_KEYS - JANITOR_REQUIRED_ENV_KEYS
PLAN_ENV_KEYS = {"MAS_OIDC_CLIENT_ID", "MAS_OIDC_CLIENT_SECRET", "PLAN_SESSION_KEY", "PLAN_ASSERTION_PRIVATE_KEY"}
CASHIER_ENV_KEYS = {
    "SYNAPSE_ADMIN_TOKEN", "CASHIER_DB_URL", "DODO_API_KEY", "DODO_WEBHOOK_SECRET",
    "DODO_PRODUCT_ID", "PLAN_ASSERTION_PUBLIC_KEY",
}
PUBLIC_RELEASES = {
    "SYNAPSE_IMAGE": {"repository": "TeleCrypt-io/telecrypt-synapse", "asset_prefix": "telecrypt-synapse-"},
    "CONTROLPLANE_IMAGE": {"repository": "TeleCrypt-io/controlplane", "asset_prefix": "controlplane-"},
}
PUBLIC_RELEASE_KEYS = frozenset(PUBLIC_RELEASES)
IMAGE_RECORD_KEYS = frozenset({"digest", "image"})
PRODUCT_RELEASE_RECORD_KEYS = {
    "asset", "asset_id", "asset_label", "asset_digest", "asset_size",
    "release_id", "source_commit", "tag", "annotated_tag_sha", "body",
}
SYNAPSE_LABELS = (
    "org.opencontainers.image.source", "org.opencontainers.image.revision", "org.opencontainers.image.version",
    "org.opencontainers.image.base.name", "org.opencontainers.image.base.version",
    "org.telecrypt.controlplane.release", "org.telecrypt.s3-provider.version",
    "org.telecrypt.controlplane.wheel.sha256", "org.telecrypt.s3-provider.archive.sha256",
)
IMAGE_CONFIG = {
    "CADDY_IMAGE": {"Entrypoint": None, "Cmd": ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]},
    "MAS_IMAGE": {"Entrypoint": ["/usr/local/bin/mas-cli"], "Cmd": None},
    "CONTROLPLANE_IMAGE": {"Entrypoint": None, "Cmd": ["/registration"]},
    "CASHIER_IMAGE": {"Entrypoint": ["/cashier"], "Cmd": None},
}
SERVICE_ENV_KEYS = {
    "caddy": {"TRUSTED_PROXY", "SERVER_NAME"},
    "synapse": {"TMPDIR"}, "mas": set(),
    "registration": {"SERVER_NAME"}, "janitor": {"SERVER_NAME"},
    "plan": {"SERVER_NAME"}, "cashier": {"SERVER_NAME"},
}
SERVICE_ENV_KEYS["janitor"].update(JANITOR_ENV_KEYS)
SERVICE_ENV_KEYS["plan"].update(PLAN_ENV_KEYS)
SERVICE_ENV_KEYS["cashier"].update(CASHIER_ENV_KEYS)
for _service in ("janitor", "plan", "cashier"):
    SERVICE_ENV_KEYS[_service].add("BILLING_ENVIRONMENT")
EXPECTED_TMPFS = {
    "caddy": ["/config/caddy:uid=65532,gid=65532,mode=0700", "/data/caddy:uid=65532,gid=65532,mode=0700"],
    "synapse": ["/tmp:uid=991,gid=991,mode=1777,size=16m"],
}
EXPECTED_LOGGING = {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}}
EXPECTED_HEALTHCHECKS = {
    "synapse": {"test": ["CMD", "curl", "-fSs", "http://localhost:8008/health"], "interval": "15s", "timeout": "5s", "retries": 3, "start_period": "15s"},
    "mas": {"test": ["CMD", "/usr/local/bin/mas-cli", "config", "check", "--config=/config.yaml", "--config=/secrets.json", "--config=/runtime-identity.yaml"], "interval": "15s", "timeout": "5s", "retries": 5, "start_period": "30s"},
    "cashier": {"test": ["CMD", "/cashier", "healthcheck"], "interval": "15s", "timeout": "5s", "retries": 5, "start_period": "30s"},
}
EXPECTED_DEPENDS_ON = {
    "caddy": {"synapse": "service_started", "mas": "service_started"},
    "synapse": {"mas": "service_started"}, "registration": {"mas": "service_started"},
    "janitor": {"mas": "service_healthy", "cashier": "service_healthy"},
    "plan": {"mas": "service_started"}, "mas": {}, "cashier": {},
}
FORBIDDEN_SERVICE_KEYS = {"privileged", "network_mode", "pid", "ipc", "devices", "runtime", "device_cgroup_rules", "userns_mode", "uts", "cgroup", "cgroup_parent", "sysctls", "extra_hosts"}
MIN_DOCKER_ENGINE = (28, 0, 0)
MIN_COMPOSE = (2, 33, 1)
MAS_LISTENER_BINDINGS = {
    "web": "0.0.0.0:8080",
    "internal": "192.168.254.2:8081",
}
MAS_LISTENER_RESOURCES = {
    "web": ["discovery", "human", "oauth", "compat", "graphql", "assets"],
    "internal": ["adminapi", "oauth"],
}
MAS_ADMIN_SUBNET = "192.168.254.0/29"
MAS_ADMIN_ADDRESS = "192.168.254.2"
PROJECT_NETWORK_POOL = "10.254.0.0/24"
POSTGRES_LAN = "192.168.10.0/24"
NETWORK_SUBNETS = {
    "caddy_ingress_net": "10.254.0.0/28",
    "edge_synapse_net": "10.254.0.16/28",
    "edge_mas_net": "10.254.0.32/28",
    "edge_registration_net": "10.254.0.48/28",
    "edge_plan_net": "10.254.0.64/28",
    "edge_cashier_net": "10.254.0.80/28",
    "synapse_mas_net": "10.254.0.96/28",
    "synapse_egress_net": "10.254.0.112/28",
    "mas_egress_net": "10.254.0.128/28",
    "cashier_synapse_net": "10.254.0.144/28",
    "plan_mas_net": "10.254.0.160/28",
    "plan_cashier_net": "10.254.0.176/28",
    "registration_egress_net": "10.254.0.192/28",
    "cashier_egress_net": "10.254.0.208/28",
    "janitor_egress_net": "10.254.0.224/28",
    "mas_admin_net": MAS_ADMIN_SUBNET,
}


def check(condition: object, message: object) -> None:
    if not condition:
        raise AssertionError(message)


def validate_service_capabilities(service: str, settings: dict) -> None:
    check(settings.get("cap_drop") == ["ALL"], (service, "cap_drop"))
    if service == "caddy":
        check(settings.get("cap_add") == ["NET_BIND_SERVICE"], (service, "cap_add"))
    else:
        check("cap_add" not in settings, (service, "cap_add"))


def assignments(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line)
        check(match and match.group(1) not in values, raw)
        values[match.group(1)] = match.group(2)
    return values


def parse_manifest(lines: list[str]) -> dict[str, str]:
    check(len(lines) == len(IMAGE_KEYS), lines)
    values: dict[str, str] = {}
    for expected_key, line in zip(IMAGE_KEYS, lines):
        check(line and line == line.strip() and not line.startswith("#"), line)
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=([^\s]+)", line)
        check(match and match.group(1) == expected_key and expected_key not in values, line)
        values[expected_key] = match.group(2)
    for key, (repository, pattern) in IMAGE_RULES.items():
        image_repository, separator, tag = values[key].rpartition(":")
        check(separator and image_repository == repository and re.fullmatch(pattern, tag), (key, values[key]))
        check("@" not in values[key] and "latest" not in tag.lower(), (key, values[key]))
    return values


def load_manifest(path: Path = ROOT / "versions.env") -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    check(text.endswith("\n") and not text.endswith("\n\n"), "manifest must have one final newline")
    return parse_manifest(text[:-1].split("\n"))


def image_reference_filename(image: str) -> str:
    check(re.fullmatch(r"[^:@\s]+:[^:@\s]+", image), image)
    return image.translate(str.maketrans("/:", "__"))


def version_tuple(raw: str, label: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", raw.strip())
    check(match, (label, raw))
    return tuple(int(part) for part in match.groups())


def validate_toolchain(engine_version: str, compose_version: str) -> None:
    check(version_tuple(engine_version, "Docker Engine") >= MIN_DOCKER_ENGINE, engine_version)
    check(version_tuple(compose_version, "Compose") >= MIN_COMPOSE, compose_version)


def export(values: dict[str, str]) -> None:
    target = os.environ.get("GITHUB_ENV")
    if not target:
        return
    with Path(target).open("a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


VALID_PROFILES = {
    ("telecrypt.io", "test"),
    ("stage.telecrypt.io", "test"),
    ("telecrypt.io", "live"),
}


def validate_profile(env: dict[str, str]) -> tuple[str, str]:
    profile = (env.get("SERVER_NAME", ""), env.get("BILLING_ENVIRONMENT", ""))
    check(profile in VALID_PROFILES, profile)
    return profile


def _server_name(env: dict[str, str]) -> str:
    return validate_profile(env)[0]


def derived_backend_host(env_text: str) -> str:
    name = _server_name(assignments(env_text))
    return f"backend.{name}"


def derived_public_site_host(env_text: str) -> str:
    name = _server_name(assignments(env_text))
    # The landing site is production-only. Stage has no public website and must
    # never derive or redirect to a stage-named landing host.
    return "www.telecrypt.io" if name == "telecrypt.io" else ""


def service_section(compose: str, service: str) -> str:
    found = re.search(rf"(?ms)^  {re.escape(service)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9_-]*:\n|\Z)", compose)
    check(found, f"missing {service} service")
    return found.group("body")


def service_network_names(service_body: str) -> set[str]:
    found = re.search(r"(?m)^    networks:\n(?P<body>(?:^      .*(?:\n|\Z))*)", service_body)
    check(found, "missing service networks")
    names = re.findall(r"^      ([a-z][a-z0-9_-]*):(?:[ \t].*)?$", found.group("body"), re.MULTILINE)
    check(len(names) == len(set(names)), "duplicate service network")
    return set(names)


def service_network_options(service_body: str, network: str) -> str:
    found = re.search(
        rf"(?m)^      {re.escape(network)}:\n(?P<body>(?:^        .*(?:\n|\Z))*)",
        service_body,
    )
    check(found, (network, "missing service network"))
    return found.group("body")


def validate_network_subnets(actual: dict[str, str]) -> None:
    check(set(actual) == set(NETWORK_SUBNETS), "network IPAM map")
    pool = ipaddress.ip_network(PROJECT_NETWORK_POOL)
    postgres_lan = ipaddress.ip_network(POSTGRES_LAN)
    parsed = {}
    for name, expected in NETWORK_SUBNETS.items():
        subnet = actual.get(name)
        check(subnet == expected, (name, "subnet", subnet))
        try:
            network = ipaddress.ip_network(subnet, strict=True)
        except ValueError:
            check(False, (name, "invalid subnet", subnet))
        check(network.version == 4, (name, "IPv4 subnet", subnet))
        if name == "mas_admin_net":
            check(not network.overlaps(pool), (name, "project pool overlap"))
        else:
            check(network.subnet_of(pool), (name, "project pool membership", subnet))
        check(not network.overlaps(postgres_lan), (name, "PostgreSQL LAN overlap", subnet))
        parsed[name] = network
    names = list(parsed)
    for index, left_name in enumerate(names):
        for right_name in names[index + 1 :]:
            check(not parsed[left_name].overlaps(parsed[right_name]), (left_name, right_name, "subnet overlap"))


def validate_mas_listeners(mas: str) -> None:
    """Require MAS's supported socket-address listener contract.

    This deployment uses the official IPv4 wildcard web socket and fixed IPv4 internal socket
    rather than Docker network self-aliases. Network attachment and resource selection provide the
    reachability boundary instead; the private listener exposes only the admin API and Janitor's
    OAuth token endpoint.
    """
    listener_matches = list(re.finditer(
        r"(?ms)^    - name: (?P<name>[a-z][a-z0-9_-]*)\n(?P<body>.*?)(?=^    - name: |\n  trusted_proxies:)",
        mas,
    ))
    check([match.group("name") for match in listener_matches] == ["web", "internal"], "MAS listener set")
    for match in listener_matches:
        name = match.group("name")
        body = match.group("body")
        resources = re.findall(r"(?m)^        - name: ([a-z][a-z0-9_-]*)\s*(?:#.*)?$", body)
        check(resources == MAS_LISTENER_RESOURCES[name], (name, "resources"))
        binds = re.findall(r"(?m)^        - address: '([^']+)'\s*$", body)
        check(binds == [MAS_LISTENER_BINDINGS[name]], (name, "binds"))
        check(not re.search(r"(?m)^\s*-\s+(?:host|port):", body), (name, "hostname/port bind"))
        check(not re.search(r"mas-(?:edge|synapse|plan|admin)", body), (name, "hostname alias bind"))


def validate_mas_admin_network(compose: str, sections: dict[str, str]) -> None:
    """Require one deterministic private MAS admin interface and no alias-based bind path."""
    check(
        ipaddress.ip_address(MAS_ADMIN_ADDRESS) in ipaddress.ip_network(MAS_ADMIN_SUBNET),
        "MAS admin address/subnet",
    )
    admin_network = re.search(
        r"(?ms)^  mas_admin_net:\n(?P<body>.*?)(?=^  [a-z][a-z0-9_-]*:\n|\Z)",
        compose[compose.index("\nnetworks:") + 1 :],
    )
    check(admin_network, "MAS admin network declaration")
    network_body = admin_network.group("body")
    check(
        re.search(r"(?m)^    internal: true\s*$", network_body)
        and re.findall(r"(?m)^        - subnet: ([^\s]+)\s*$", network_body) == [MAS_ADMIN_SUBNET],
        "MAS admin private subnet",
    )
    mas_admin_options = service_network_options(sections["mas"], "mas_admin_net")
    check(
        re.fullmatch(
            r"        aliases:\n          - mas-admin\n"
            r"        ipv4_address: " + re.escape(MAS_ADMIN_ADDRESS) + r"\n?",
            mas_admin_options,
        ),
        "MAS admin alias and static address",
    )
    check(not service_network_options(sections["janitor"], "mas_admin_net").strip(), "Janitor static admin address")
    for service, networks in SERVICE_NETWORKS.items():
        for network in networks:
            if service == "mas" and network == "mas_admin_net":
                continue
            options = service_network_options(sections[service], network)
            check(
                "ipv4_address:" not in options and "aliases:" not in options,
                (service, network, "unexpected network option"),
            )


def validate_source_topology(compose: str, sections: dict[str, str]) -> None:
    for service, expected in SERVICE_NETWORKS.items():
        check(service_network_names(sections[service]) == expected, (service, "networks"))

    networks_start = compose.index("\nnetworks:")
    networks_text = compose[networks_start:]
    matches = list(re.finditer(r"(?m)^  ([a-z][a-z0-9_-]*):[ \t]*$", networks_text))
    blocks = {
        match.group(1): networks_text[match.end(): (matches[index + 1].start() if index + 1 < len(matches) else len(networks_text))]
        for index, match in enumerate(matches)
    }
    expected_networks = set().union(*SERVICE_NETWORKS.values())
    check(len(matches) == len(blocks) and set(blocks) == expected_networks, "network declarations")
    actual_subnets = {}
    for name, body in blocks.items():
        internal = re.search(r"(?m)^    internal:[ \t]*true[ \t]*$", body) is not None
        check(internal is (name in INTERNAL_NETWORKS), (name, "internal"))
        subnets = re.findall(r"(?m)^        - subnet: ([^\s]+)[ \t]*$", body)
        check(len(subnets) == 1, (name, "IPAM subnet"))
        actual_subnets[name] = subnets[0]
    validate_network_subnets(actual_subnets)
    check(CADDY_INGRESS_NETWORK in blocks and CADDY_INGRESS_NETWORK not in INTERNAL_NETWORKS, "Caddy ingress network")


def validate_manifest_negative(values: dict[str, str]) -> None:
    base = [f"{key}={value}" for key, value in values.items()]
    mutations = (base + ["EXTRA_IMAGE=docker.io/caddy:1.0.0-alpine"], base + [base[0]],
                 [line.replace(":2.11.4-alpine", "@sha256:" + "0" * 64) for line in base],
                 [line.replace(":2.11.4-alpine", ":latest") for line in base])
    for candidate in mutations:
        try:
            parse_manifest(candidate)
        except AssertionError:
            continue
        raise AssertionError("image manifest mutation was accepted")


def validate_caddy(caddy: str, caddy_body: str) -> None:
    def matcher(name: str) -> str:
        found = re.search(rf"(?ms)^\t@{name} \{{.*?^\t\}}", caddy)
        check(found, f"missing {name} matcher")
        return found.group(0)

    def rejects_methods(name: str) -> None:
        found = re.search(rf"(?ms)^\thandle @{name} \{{.*?^\t\}}", caddy)
        check(found and 'header Allow "POST"' in found.group(0) and 'respond "Method Not Allowed" 405' in found.group(0), name)
        check("reverse_proxy" not in found.group(0), name)

    login = "@matrix_compat_login path_regexp ^/_matrix/client/[^/]+/login/?$"
    check(login in caddy and caddy.index(login) < caddy.index("@mas_compat"), "login boundary/order")
    other = matcher("mas_compat_other_method")
    check("path_regexp ^/_matrix/client/[^/]+/(logout|refresh)/?$" in other and "not method POST" in other, "MAS rejection")
    compat = matcher("mas_compat")
    check("method POST" in compat and "logout|refresh" in compat, "MAS compatibility")
    check(caddy.index("@mas_compat_other_method") < caddy.index("\t@synapse path_regexp"), "MAS rejection order")
    check("@mas path /auth /auth/*" in caddy, "OAuth routes")
    check("method GET" in matcher("well_known_client") and "path /.well-known/matrix/client" in caddy, "discovery")
    federation_discovery = re.search(
        r'(?ms)^\thandle /\.well-known/matrix/server \{.*?^\t\}',
        caddy,
    )
    check(
        federation_discovery
        and 'respond "Not Found" 404' in federation_discovery.group(0)
        and "method " not in federation_discovery.group(0)
        and "redir " not in federation_discovery.group(0)
        and "reverse_proxy" not in federation_discovery.group(0)
        and "Location" not in federation_discovery.group(0)
        and federation_discovery.start() < caddy.index("@production_apex"),
        "closed-federation discovery rejection",
    )
    agents = matcher("agents_post")
    check("method POST" in agents and "path /agents" in agents, "registration")
    check("path /agents" in matcher("agents_other_method") and "not method POST" in matcher("agents_other_method"), "registration rejection")
    rejects_methods("mas_compat_other_method")
    rejects_methods("agents_other_method")
    delete_path = "/_matrix/client/unstable/io.telecrypt.storage/delete_media"
    delete_other = matcher("telecrypt_delete_media_other_method")
    delete_post = matcher("telecrypt_delete_media")
    check(
        f"path {delete_path}" in delete_other and "not method POST" in delete_other,
        "media deletion rejection matcher",
    )
    check(
        f"method POST" in delete_post and f"path {delete_path}" in delete_post,
        "media deletion POST matcher",
    )
    rejects_methods("telecrypt_delete_media_other_method")
    delete_handle = re.search(r"(?ms)^\thandle @telecrypt_delete_media \{.*?^\t\}", caddy)
    check(
        delete_handle
        and "request_body" in delete_handle.group(0)
        and "max_size 32KiB" in delete_handle.group(0)
        and "reverse_proxy synapse:8008" in delete_handle.group(0),
        "media deletion body limit/proxy",
    )
    check(
        caddy.index("@telecrypt_delete_media_other_method") < caddy.index("\t@synapse path_regexp")
        and caddy.index("@telecrypt_delete_media {") < caddy.index("\t@synapse path_regexp"),
        "media deletion route order",
    )
    check("http://{$SERVER_NAME}:8080" in caddy and "http://backend.{$SERVER_NAME}:8080" in caddy, "host identities")
    sites = re.findall(r"(?ms)^http://[^\n]+ \{.*?^\}", caddy)
    check(len(sites) == 2 and all("import ingress_peer_gate" in site and "import access_log" in site for site in sites), "ingress peer gate/logs")
    check(caddy.count("not remote_ip {$TRUSTED_PROXY}") == 1, "immediate ingress peer matcher")
    check(caddy.count("abort @untrusted_ingress_peer") == 0, "unmatched ingress abort")
    gate = re.compile(r"(?ms)^\thandle @untrusted_ingress_peer \{\n\t\tabort\n\t\}")
    check(len(gate.findall(caddy)) == 1, "matched ingress peer gate")
    for site in sites:
        gate_match = re.search(r"(?m)^\timport ingress_peer_gate$", site)
        terminal = re.search(r"(?m)^\thandle \{\n", site)
        check(gate_match and terminal and gate_match.start() < terminal.start(), "ingress gate route order")
    backend = caddy[caddy.index("http://backend.{$SERVER_NAME}:8080 {"):]
    check("@mas path /auth /auth/*" in backend and "@plan path /plan /plan/* /api/plan /api/plan/*" in backend, "backend routes")
    check(not re.search(r"(?i)frame-ancestors\s+(?:['\"]?\*['\"]?|https?://[^;[:space:]]+)", caddy), "frame policy")
    check(
        "@production_apex host telecrypt.io" in caddy
        and "redir https://www.telecrypt.io{http.request.uri.path} 301" in caddy
        and 'respond "Not Found" 404' in caddy
        and "www.{$SERVER_NAME}" not in caddy,
        "production-only site redirect",
    )
    check(not any("{query}" in line or "{http.request.uri}" in line for line in caddy.splitlines() if "www.telecrypt.io" in line), "redirect query")
    proxies = re.findall(r"(?ms)^\s*reverse_proxy [^\n]+ \{.*?^\s*\}", caddy)
    check(proxies and all("import strip_untrusted_client_ip" in proxy for proxy in proxies), "proxy identity")
    plan = caddy[caddy.index("@plan path"):caddy.index("\n\t}", caddy.index("@plan path"))]
    check("reverse_proxy plan:9012" in plan and "cashier:9011" not in plan, "Plan boundary")
    check(
        "path_regexp ^/_matrix/media/(r0|v1|v3)/upload(/[^/]+/[^/]+)?/?$" in caddy
        and "max_size 128MiB" in caddy,
        "Caddy media upload body limit",
    )
    check("path /agents" in caddy and "reverse_proxy registration:9009" in caddy, "Registration boundary")
    for field in ("request>headers>Authorization", "request>headers>Cookie", "request>headers>Proxy-Authorization", "resp_headers>Set-Cookie"):
        check(len(re.findall(rf"(?im)^\s*{re.escape(field)}\s+delete\s*$", caddy)) == 1, field)
    check("response>headers>Set-Cookie" not in caddy and "trusted_proxies_strict" in caddy, "header policy")
    check(caddy.count("header_up -X-Telecrypt-Client-IP") == 1 and not re.search(r"(?im)^\s*header_up\s+X-Telecrypt-Client-IP(?:\s|$)", caddy), "client identity")
    check("@dodo_webhook_path path /webhooks/dodo" in caddy and "log_skip @dodo_webhook_path" in caddy, "Dodo logging")
    dodo = caddy[caddy.index("@dodo_webhook {"):caddy.index("\n\t}", caddy.index("@dodo_webhook {"))]
    handle = caddy[caddy.index("handle @dodo_webhook {"):caddy.index("\n\t}", caddy.index("handle @dodo_webhook {"))]
    check("method POST" in dodo and "path /webhooks/dodo" in dodo and "reverse_proxy cashier:9011" in handle and 'Cache-Control "no-store"' in handle, "Dodo route")
    check("uri replace" not in handle and not re.search(r"(?m)^\s*log_skip @dodo_webhook\s*$", caddy), "Dodo route stability")
    consumed = set(re.findall(r"\{\$([A-Z][A-Z0-9_]*)\}", caddy))
    declared = set(re.findall(r"^\s+- ([A-Z][A-Z0-9_]*)=", caddy_body, re.MULTILINE))
    check(consumed <= declared, ("undeclared Caddy variables", consumed - declared))
    check("@synapse path_regexp ^/_matrix/(client|media)(/|$)" in caddy, "Synapse route")
    matrix = re.compile(r"^/_matrix/(client|media)(/|$)")
    check(all(matrix.match(path) for path in ("/_matrix/client", "/_matrix/client/v3/sync", "/_matrix/media")), "Synapse route examples")
    check(not any(matrix.match(path) for path in ("/_matrix", "/_matrix/federation/v1/version", "/_matrix/identity/api/v1", "/_matrix/key/v2/server", "/_matrix/clientevil", "/_matrixevil")), "Synapse route exclusions")
    admin = caddy[caddy.index("@mas_admin path /auth/api/admin /auth/api/admin/*"):]
    check('respond "Not Found" 404' in admin and "reverse_proxy" not in admin[:admin.index("\n\t}")] if "\n\t}" in admin else False, "MAS admin boundary")


def validate_caddy_negative(caddy: str, body: str) -> None:
    mutations = (
        caddy.replace("\t@mas_compat {\n\t\tmethod POST\n", "\t@mas_compat {\n", 1),
        caddy.replace("\t\tnot method POST\n", "", 1),
        caddy.replace("\t\tpath /agents\n\t\tnot method POST\n", "\t\tpath /agents\n", 1),
        caddy.replace(
            "\t@telecrypt_delete_media {\n\t\tmethod POST\n",
            "\t@telecrypt_delete_media {\n",
            1,
        ),
        caddy.replace("\t\tmax_size 32KiB\n", "\t\tmax_size 128MiB\n", 1),
        caddy.replace("\t\tmethod GET\n\t\tpath /.well-known/matrix/client", "\t\tmethod POST\n\t\tpath /.well-known/matrix/client", 1),
        caddy.replace(
            '\thandle /.well-known/matrix/server {\n\t\trespond "Not Found" 404\n\t}\n',
            "",
            1,
        ),
        caddy.replace(
            '\t\trespond "Not Found" 404\n\t}\n\n\t# The public website exists only',
            '\t\trespond "Not Found" 404\n\t\treverse_proxy synapse:8008\n\t}\n\n\t# The public website exists only',
            1,
        ),
        caddy.replace(
            '\t\trespond "Not Found" 404\n\t}\n\n\t# The public website exists only',
            '\t\trespond "Not Found" 404\n\t\tredir https://www.telecrypt.io 301\n\t}\n\n\t# The public website exists only',
            1,
        ),
        caddy.replace("\timport ingress_peer_gate\n", "", 1),
    )
    for candidate in mutations:
        try:
            validate_caddy(candidate, body)
        except (AssertionError, ValueError):
            continue
        raise AssertionError("Caddy policy mutation was accepted")


def _adapted_route_lists(value: object):
    if isinstance(value, dict):
        routes = value.get("routes")
        if isinstance(routes, list):
            yield routes
            yield from _adapted_route_lists(routes)
        for key, child in value.items():
            if key != "routes":
                yield from _adapted_route_lists(child)
    elif isinstance(value, list):
        for child in value:
            yield from _adapted_route_lists(child)


def _adapted_contains_handler(value: object, names: set[str]) -> bool:
    if isinstance(value, dict):
        if value.get("handler") in names:
            return True
        return any(_adapted_contains_handler(child, names) for child in value.values())
    if isinstance(value, list):
        return any(_adapted_contains_handler(child, names) for child in value)
    return False


def _adapted_untrusted_peer_match(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    negated = value.get("not")
    if not isinstance(negated, list) or len(negated) != 1:
        return False
    peer_match = negated[0]
    return (
        isinstance(peer_match, dict)
        and set(peer_match) == {"remote_ip"}
        and isinstance(peer_match["remote_ip"], dict)
        and set(peer_match["remote_ip"]) == {"ranges"}
        and peer_match["remote_ip"]["ranges"] == ["192.0.2.10/32"]
    )


def validate_adapted_caddy(path: Path) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    check(isinstance(document, dict), "adapted Caddy document shape")
    checked = 0
    for routes in _adapted_route_lists(document):
        for index, route in enumerate(routes):
            if not isinstance(route, dict):
                continue
            matchers = route.get("match")
            if not isinstance(matchers, list) or not any(_adapted_untrusted_peer_match(matcher) for matcher in matchers):
                continue
            check(_adapted_contains_handler(route.get("handle"), {"abort"}), "adapted ingress gate abort")
            terminal_index = next(
                (
                    candidate
                    for candidate in range(index + 1, len(routes))
                    if isinstance(routes[candidate], dict)
                    and "match" not in routes[candidate]
                    and _adapted_contains_handler(routes[candidate].get("handle"), {"static_response", "reverse_proxy", "file_server"})
                ),
                None,
            )
            check(terminal_index is not None and index < terminal_index, "adapted ingress gate route order")
            checked += 1
    check(checked == 2, ("adapted ingress gates", checked))
    print("Verified adapted Caddy ingress peer gates before terminal fallbacks")


def validate_source(values: dict[str, str]) -> None:
    compose = (ROOT / "compose.yml").read_text(encoding="utf-8")
    caddy = (ROOT / "Caddyfile").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
    env_text = (ROOT / ".env.example").read_text(encoding="utf-8")
    env = assignments(env_text)
    sections = {service: service_section(compose, service) for service in SERVICES}
    validate_source_topology(compose, sections)
    boundary = compose.index("\n# Compose file-backed secrets")
    check(set(re.findall(r"(?m)^  ([a-z][a-z0-9_-]*):$", compose[:boundary])) == set(SERVICES), "service set")
    for service, key in SERVICE_IMAGES.items():
        check(re.findall(r"(?m)^    image: (.+)$", sections[service]) == [f"${{{key}:?set {key}}}"], (service, "image placeholder"))
    check(len(re.findall(r"(?m)^    image:", compose)) == len(SERVICE_IMAGES) and not re.search(r"(?m)^    image: [^$]", compose), "image indirection")
    check("build:" not in compose, "local builds")
    check("container_name:" not in compose, "global container names")
    check("synapse/media_store" not in workflow, "legacy persistent media path")
    for forbidden in ("privileged:", "network_mode:", "pid:", "ipc:", "devices:", "/var/run/docker.sock"):
        check(forbidden not in compose, forbidden)
    check('cap_add: ["NET_BIND_SERVICE"]' in sections["caddy"], "Caddy execution capability")
    check(all("cap_add:" not in sections[service] for service in SERVICES if service != "caddy"), "non-Caddy capabilities")
    check("ports:" in sections["caddy"] and all("ports:" not in sections[s] for s in SERVICES if s != "caddy"), "listener ownership")
    check("env_file:" not in compose, "live env files")
    check("secrets:" not in sections["caddy"], "Caddy credentials")
    check("secrets:" not in sections["registration"] and "volumes:" not in sections["registration"], "registration credentials")
    for service in ("janitor", "plan", "cashier"):
        private_keys = SERVICE_ENV_KEYS[service] - {"SERVER_NAME"}
        required_keys = JANITOR_REQUIRED_ENV_KEYS if service == "janitor" else private_keys
        optional_keys = JANITOR_OPTIONAL_ENV_KEYS if service == "janitor" else set()
        for key in required_keys:
            check(f"{key}=${{{key}:?set {key}}}" in sections[service], (service, key, "required environment"))
        for key in optional_keys:
            check(f"{key}=${{{key}:-}}" in sections[service], (service, key, "optional environment"))
    check("SERVER_NAME=${SERVER_NAME:?set SERVER_NAME}" in "".join(sections[s] for s in ("registration", "janitor", "plan", "cashier")), "runtime identity")
    check("BILLING_ENVIRONMENT=${BILLING_ENVIRONMENT:?set BILLING_ENVIRONMENT}" in "".join(sections[s] for s in ("janitor", "plan", "cashier")), "billing identity")
    check(set(env) == {"TELECRYPT_DATA_DIR", "SERVER_NAME", "BILLING_ENVIRONMENT", "INGRESS_BIND_ADDRESS", "TRUSTED_PROXY"}, env)
    validate_profile(env)
    check(not set(env) & set(SECRET_ENV.values()) and not set(env) & set(IMAGE_KEYS), "operator secret/image variables")
    ingress = ipaddress.ip_address(env["INGRESS_BIND_ADDRESS"])
    check(str(ingress) == env["INGRESS_BIND_ADDRESS"] and not (ingress.is_unspecified or ingress.is_loopback or ingress.is_multicast or ingress.is_link_local), env["INGRESS_BIND_ADDRESS"])
    trusted = ipaddress.ip_interface(env["TRUSTED_PROXY"])
    check(trusted.network.prefixlen == trusted.network.max_prefixlen and str(trusted) == env["TRUSTED_PROXY"] and not (trusted.ip.is_unspecified or trusted.ip.is_loopback or trusted.ip.is_multicast or trusted.ip.is_link_local), env["TRUSTED_PROXY"])
    caddy_body = sections["caddy"]
    for key in ("TRUSTED_PROXY", "SERVER_NAME"):
        check(f"- {key}=${{{key}:?set {key}}}" in caddy_body, key)
    check(
        "host_ip: ${INGRESS_BIND_ADDRESS:?set INGRESS_BIND_ADDRESS}" in caddy_body
        and "target: 8080" in caddy_body and "published: 8080" in caddy_body
        and "protocol: tcp" in caddy_body and "mode: ingress" in caddy_body,
        "Caddy listener",
    )
    for service in ("caddy", "registration", "synapse", "mas"):
        check("BILLING_ENVIRONMENT" not in sections[service], (service, "billing isolation"))
    expected_public_site = "www.telecrypt.io" if env["SERVER_NAME"] == "telecrypt.io" else ""
    check(
        derived_backend_host(env_text) == f"backend.{env['SERVER_NAME']}"
        and derived_public_site_host(env_text) == expected_public_site,
        "derived hosts",
    )
    check(not any(f"{name}=" in env_text for name in SECRET_ENV.values()), "secret variable in operator environment")
    for text in ('user: "65532:65532"', "read_only: true", 'security_opt: ["no-new-privileges:true"]', 'cap_drop: ["ALL"]'):
        check(text in caddy_body, ("Caddy", text))
    synapse = (ROOT / "synapse.yaml").read_text(encoding="utf-8")
    mas = (ROOT / "mas.yaml").read_text(encoding="utf-8")
    check(
        "names: [client]" in synapse
        and "max_upload_size: 128M" in synapse
        and "media_store_path: /staging/media" in synapse
        and "enable_local_media_storage: false" in synapse
        and "pid_file: /tmp/homeserver.pid" in synapse,
        "Synapse listeners/upload/staging",
    )
    check("url_preview_enabled: false" in synapse, "Synapse URL previews disabled")
    synapse_fixture = json.loads(
        (ROOT / ".github" / "fixtures" / "synapse.secrets.json").read_text(encoding="utf-8")
    )
    synapse_media_providers = synapse_fixture.get("media_storage_providers")
    check(
        not re.search(r"^\s*database:\s*$", synapse, re.MULTILINE)
        and not re.search(r"^\s*matrix_authentication_service:\s*$", synapse, re.MULTILINE)
        and "shallow-merged by top-level key" in synapse
        and synapse_fixture.get("database", {}).get("name") == "psycopg2"
        and set(synapse_fixture.get("database", {}).get("args", {}))
        == {"user", "password", "database", "host", "port", "sslmode", "connect_timeout"}
        and synapse_fixture.get("matrix_authentication_service")
        == {"enabled": True, "endpoint": "http://mas:8080", "secret": "ci-matrix-secret"}
        and isinstance(synapse_media_providers, list)
        and len(synapse_media_providers) == 1
        and synapse_media_providers[0].get("config", {}).get("endpoint_url")
        == "https://sss.telecrypt.io"
        and "reachable only from the production VM" in synapse
        and "media_store_path: /staging/media" in synapse,
        "Synapse complete private loader maps",
    )
    check(not re.search(r"^\s*(server_name|public_baseurl):", synapse, re.MULTILINE), "Synapse identity overlay")
    validate_mas_listeners(mas)
    validate_mas_admin_network(compose, sections)
    check(
        "- name: adminapi" in mas
        and "- name: oauth" in mas
        and "- name: health" not in mas
        and "mas_admin_net" in sections["mas"]
        and "mas_admin_net" in sections["janitor"]
        and "mas_admin_net" not in sections["caddy"],
        "MAS private credential-gated admin boundary",
    )
    check("  trusted_proxies: []" in mas, "MAS proxy trust disabled explicitly")
    check("kind: synapse" in mas and "endpoint: http://synapse:8008" in mas, "MAS committed loader options")
    check("transport: blackhole" in mas and "password_recovery_enabled: false" in mas, "MAS email transport is explicitly non-delivering")
    check("account_deactivation_allowed: true" in mas, "MAS self-deactivation is enabled")
    check("postgres_mas" not in mas, "MAS database endpoint comment is not a Compose alias")
    for entrypoint in (
        "client_registration/violation", "register/violation", "authorization_grant/violation",
        "compat_login/violation", "password/violation", "email/violation",
    ):
        check(entrypoint in mas, ("MAS policy entrypoint", entrypoint))
    check(not re.search(r"^\s*(public_base|issuer|plan_management_iframe_uri):", mas, re.MULTILINE), "MAS identity overlay")
    check("extra_hosts:" not in compose and "response>headers>Set-Cookie" not in caddy, "static/header boundary")
    check(
        "RootlessKit >= 3.0" in caddy
        and "built-in TCP source-address propagation" in caddy
        and "userland-proxy disabled" in caddy
        and "prove the observed peer/X-Forwarded behavior live" in caddy,
        "rootless source-peer activation prerequisite",
    )
    check('test: ["CMD", "/cashier", "healthcheck"]' in sections["cashier"], "Cashier health")
    check("profiles: [janitor]" in sections["janitor"], "Janitor profile")
    check(
        "- TMPDIR=/staging/tmp" in sections["synapse"]
        and "/runtime/synapse-staging:/staging:rw" in sections["synapse"]
        and "/synapse/media_store:/data" not in sections["synapse"]
        and "worker_app" not in compose,
        "Synapse disposable staging boundary",
    )
    validate_caddy(caddy, caddy_body)
    validate_caddy_negative(caddy, caddy_body)
    export(values)
    print("Verified source image, identity, security, release, and Caddy invariants")


def _env_map(value: object) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        result = {}
        for item in value:
            check(isinstance(item, str) and "=" in item, item)
            key, val = item.split("=", 1)
            check(key not in result, key)
            result[key] = val
        return result
    return {}


def _mounts(settings: dict) -> dict[str, dict]:
    result = {}
    for mount in settings.get("volumes", []):
        check(isinstance(mount, dict) and mount.get("target") not in result, ("mount", mount))
        result[mount["target"]] = mount
    return result


def validate_rendered(path: Path) -> None:
    def pairs(items):
        result = {}
        for key, value in items:
            check(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result

    document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    check(isinstance(document, dict) and set(document) == {"name", "services", "networks", "secrets"}, "Compose document shape")
    validate_mas_listeners((ROOT / "mas.yaml").read_text(encoding="utf-8"))
    services, networks = document["services"], document["networks"]
    check(set(services) == set(SERVICES) and set(networks) == set({name for names in SERVICE_NETWORKS.values() for name in names}), "Compose topology")
    ingress_members = {service for service, settings in services.items() if CADDY_INGRESS_NETWORK in (settings.get("networks") or {})}
    check(ingress_members == {"caddy"}, "Caddy ingress network ownership")
    check(networks[CADDY_INGRESS_NETWORK].get("internal", False) is False, "Caddy ingress network is non-internal")
    env_text = (ROOT / ".env.example").read_text(encoding="utf-8")
    env = assignments(env_text)
    manifest = load_manifest()
    data_dir = os.environ.get("TELECRYPT_DATA_DIR", "")
    check(data_dir, "TELECRYPT_DATA_DIR")
    expected_identity = {"caddy": {"SERVER_NAME": env["SERVER_NAME"], "TRUSTED_PROXY": env["TRUSTED_PROXY"]}}
    for service in SERVICES:
        settings = services[service]
        check(settings.get("image") == manifest[SERVICE_IMAGES[service]], (service, "image"))
        check("container_name" not in settings, (service, "global container name"))
        check("build" not in settings and settings.get("read_only") is True, (service, "immutable runtime"))
        validate_service_capabilities(service, settings)
        check(settings.get("security_opt") == ["no-new-privileges:true"], (service, "privilege boundary"))
        check(settings.get("user") == ("65532:65532" if service == "caddy" else "991:991"), (service, "uid"))
        check(not set(settings) & FORBIDDEN_SERVICE_KEYS, (service, "forbidden runtime"))
        check(set(settings.get("networks") or {}) == SERVICE_NETWORKS[service], (service, "networks"))
        for network, options in (settings.get("networks") or {}).items():
            options = options or {}
            allowed = set()
            if service == "mas" and network == "mas_admin_net":
                allowed.add("aliases")
                allowed.add("ipv4_address")
                check(
                    options == {"aliases": ["mas-admin"], "ipv4_address": MAS_ADMIN_ADDRESS},
                    (service, network, "admin alias/address"),
                )
            else:
                check("aliases" not in options, (service, network, "network alias"))
                check("ipv4_address" not in options, (service, network, "unexpected static address"))
            if network == EGRESS_NETWORKS.get(service):
                allowed.add("gw_priority")
                check(options.get("gw_priority") == 1, (service, "egress priority"))
            check(set(options) <= allowed, (service, network, options))
        runtime = expected_identity.get(service, {})
        runtime.update({"SERVER_NAME": env["SERVER_NAME"]} if service in ("registration", "janitor", "plan", "cashier") else {})
        runtime.update({"BILLING_ENVIRONMENT": env["BILLING_ENVIRONMENT"]} if service in ("janitor", "plan", "cashier") else {})
        actual_env = _env_map(settings.get("environment", {}))
        check(set(actual_env) == SERVICE_ENV_KEYS[service], (service, "environment keys"))
        for key, value in runtime.items():
            check(actual_env.get(key) == value, (service, key))
        check(not set(actual_env) & set(SECRET_ENV.values()), (service, "secret environment"))
        check("env_file" not in settings, (service, "live env files"))
        check(settings.get("logging") == EXPECTED_LOGGING, (service, "log rotation"))
        check(settings.get("tmpfs", []) == EXPECTED_TMPFS.get(service, []), (service, "tmpfs"))
        expected_healthcheck = EXPECTED_HEALTHCHECKS.get(service)
        if expected_healthcheck is None:
            check("healthcheck" not in settings, (service, "healthcheck"))
        else:
            check(settings.get("healthcheck") == expected_healthcheck, (service, "healthcheck"))
        dependencies = settings.get("depends_on", {})
        expected_dependencies = EXPECTED_DEPENDS_ON[service]
        check(set(dependencies) == set(expected_dependencies), (service, "depends_on"))
        for dependency, condition in expected_dependencies.items():
            detail = dependencies[dependency]
            check(isinstance(detail, dict) and detail.get("condition") == condition and detail.get("required", True) is True, (service, dependency, "depends_on"))
        check(settings.get("profiles", []) == (["janitor"] if service == "janitor" else []), (service, "profiles"))
    check(len(services["caddy"].get("ports", [])) == 1, "one Caddy binding")
    port = services["caddy"]["ports"][0]
    check(
        set(port) == {"host_ip", "target", "published", "protocol", "mode"}
        and port["host_ip"] == env["INGRESS_BIND_ADDRESS"]
        and str(port["target"]) == "8080"
        and str(port["published"]) == "8080"
        and port["protocol"] == "tcp"
        and port["mode"] == "ingress",
        port,
    )
    check(all("ports" not in services[s] for s in SERVICES if s != "caddy"), "unintended ports")
    actual_subnets = {}
    for name, settings in networks.items():
        expected_subnet = NETWORK_SUBNETS[name]
        expected_ipam = {"config": [{"subnet": expected_subnet}]}
        check(
            set(settings) <= {"internal", "name", "ipam"}
            and settings.get("ipam", {}) == expected_ipam,
            (name, "network options", settings),
        )
        actual_subnets[name] = settings["ipam"]["config"][0]["subnet"]
        if name in INTERNAL_NETWORKS:
            check(settings.get("internal") is True, (name, "internal"))
        else:
            check(settings.get("internal", False) is False, (name, "egress"))
        if "name" in settings:
            check(settings["name"] == f"{document['name']}_{name}", (name, "network name"))
    validate_network_subnets(actual_subnets)
    check(set(document["secrets"]) == set(SECRET_FILES), "secret set")
    expected_secret_files = {name: f"{data_dir}/secrets/{filename}" for name, filename in SECRET_FILES.items()}
    for name, expected_file in expected_secret_files.items():
        secret = document["secrets"][name]
        check(
            set(secret) <= {"file", "name"}
            and secret.get("file") == expected_file
            and secret.get("name") in {None, name, f"{document['name']}_{name}"},
            (name, "secret source", secret),
        )
    secret_mounts = {
        "synapse": {"synapse_secrets_json": "/secrets.json", "synapse_signing_key": "/signing.key"},
        "mas": {"mas_secrets_json": "/secrets.json"},
    }
    for service, expected in secret_mounts.items():
        found = {}
        for item in services[service].get("secrets", []):
            check(set(item) == {"source", "target"}, (service, item))
            found[item["source"]] = item["target"]
        check(found == expected, (service, "secret mounts"))
    for service in ("caddy", "registration", "janitor", "plan", "cashier"):
        check(not services[service].get("secrets"), (service, "secret isolation"))
    for service in ("registration", "janitor", "plan", "cashier"):
        check(not services[service].get("volumes"), (service, "volume isolation"))
    expected_mounts = {
        "caddy": {"/etc/caddy/Caddyfile": (str(ROOT / "Caddyfile"), True)},
        "synapse": {"/homeserver.yaml": (str(ROOT / "synapse.yaml"), True), "/runtime-identity.yaml": (f"{data_dir}/runtime/synapse.identity.yaml", True), "/log.config": (str(ROOT / "synapse.log.config"), True), "/staging": (f"{data_dir}/runtime/synapse-staging", False)},
        "mas": {"/config.yaml": (str(ROOT / "mas.yaml"), True), "/runtime-identity.yaml": (f"{data_dir}/runtime/mas.identity.yaml", True)},
    }
    for service, expected in expected_mounts.items():
        found = _mounts(services[service])
        check(set(found) == set(expected), (service, "mount targets"))
        for target, (source, read_only) in expected.items():
            item = found[target]
            check(item.get("type") == "bind" and item.get("source") == source and item.get("read_only", False) is read_only, (service, target))
    check(services["synapse"].get("entrypoint") == ["/telecrypt-synapse-entrypoint"] and services["synapse"].get("command") == ["-c", "/homeserver.yaml", "-c", "/secrets.json", "-c", "/runtime-identity.yaml"], "Synapse config order")
    check(services["mas"].get("command") == ["server", "--config=/config.yaml", "--config=/secrets.json", "--config=/runtime-identity.yaml"], "MAS config order")
    check(services["janitor"].get("command") == ["/janitor"] and services["plan"].get("command") == ["/plan"], "service commands")
    for service in ("caddy", "mas", "registration", "janitor", "plan", "cashier"):
        # Compose's JSON model materializes an omitted entrypoint as null.  A non-null value
        # would be an explicit service override and must remain rejected.
        check(services[service].get("entrypoint") is None, (service, "entrypoint override"))
    for service in ("caddy", "registration", "cashier"):
        # As with entrypoint above, Compose serializes an omitted command as null.
        check(services[service].get("command") is None, (service, "command override"))
    check(services["janitor"].get("profiles") == ["janitor"] and services["janitor"].get("restart") == "no", "Janitor profile")
    check(all(services[s].get("restart") == "unless-stopped" for s in SERVICES if s != "janitor"), "service restart")
    print("Verified rendered Compose images, identity, topology, secrets, hardening, and listener invariants")


def config_parts(document: object) -> dict:
    check(isinstance(document, dict), "OCI config object")
    config = document.get("config", document)
    check(isinstance(config, dict), "OCI config section")
    return config


def _metadata_name(repository: str) -> set[str]:
    names = {repository}
    if repository.startswith("docker.io/") and repository.count("/") == 1:
        names.add(repository.replace("docker.io/", "docker.io/library/", 1))
    return names


def validate_image_platform(metadata: object, config_document: object) -> None:
    check(isinstance(metadata, dict) and metadata.get("Os") == "linux" and metadata.get("Architecture") == "amd64", "linux/amd64 metadata selection")
    check(isinstance(config_document, dict) and config_document.get("os") == "linux" and config_document.get("architecture") == "amd64", "linux/amd64 config selection")


def validate_synapse_provenance(inspect_labels: object, config_labels: object, version: str, expected_controlplane_version: str) -> None:
    expected = {"org.opencontainers.image.source": "https://github.com/TeleCrypt-io/telecrypt-synapse", "org.opencontainers.image.version": version, "org.opencontainers.image.base.name": "ghcr.io/element-hq/synapse"}
    for labels in (inspect_labels, config_labels):
        check(isinstance(labels, dict), "Synapse labels")
        check(set(SYNAPSE_LABELS) <= set(labels), "complete Synapse provenance")
        check(all(type(labels[label]) is str for label in SYNAPSE_LABELS), "Synapse label types")
        for label, value in expected.items():
            check(labels.get(label) == value, (label, labels.get(label)))
        check(re.fullmatch(r"[0-9a-f]{40}", labels.get("org.opencontainers.image.revision", "")), "Synapse revision")
        check(labels.get("org.telecrypt.controlplane.release") == expected_controlplane_version, "embedded Controlplane release")
        check(re.fullmatch(r"v?\d+\.\d+\.\d+", labels.get("org.opencontainers.image.base.version", "")), "Synapse base version")
        check(re.fullmatch(r"v?\d+\.\d+\.\d+", labels.get("org.telecrypt.s3-provider.version", "")), "S3 provider version")
        for label in ("org.telecrypt.controlplane.wheel.sha256", "org.telecrypt.s3-provider.archive.sha256"):
            check(re.fullmatch(r"[0-9a-f]{64}", labels.get(label, "")), label)
    check(all(inspect_labels[label] == config_labels[label] for label in SYNAPSE_LABELS), "Synapse metadata channel mismatch")


def validate_published_images(directory: Path) -> None:
    values = load_manifest()
    images = {}
    for key in IMAGE_KEYS:
        name = image_reference_filename(values[key])
        labels = json.loads((directory / f"{name}.labels").read_text(encoding="utf-8"))
        config_document = json.loads((directory / f"{name}.config").read_text(encoding="utf-8"))
        config = config_parts(config_document)
        metadata = json.loads((directory / f"{name}.metadata").read_text(encoding="utf-8"))
        repository = values[key].rsplit(":", 1)[0]
        check(type(metadata) is dict and type(metadata.get("Name")) is str and type(metadata.get("Digest")) is str, (key, "metadata fields"))
        check(metadata["Name"] in _metadata_name(repository), (key, "repository"))
        validate_image_platform(metadata, config_document)
        check(re.fullmatch(r"sha256:[0-9a-f]{64}", metadata["Digest"]), (key, "digest"))
        for field, expected in IMAGE_CONFIG.get(key, {}).items():
            check(config.get(field) == expected, (key, field, config.get(field)))
        images[key] = (labels, config, metadata)
    for key in ("CONTROLPLANE_IMAGE", "CASHIER_IMAGE"):
        labels, config, _ = images[key]
        version = values[key].rsplit(":", 1)[1]
        config_labels = config.get("Labels")
        for channel in (labels, config_labels):
            check(type(channel) is dict, (key, "labels"))
            check(all(type(channel.get(label)) is str for label in (
                "org.opencontainers.image.source", "org.opencontainers.image.version",
                "org.opencontainers.image.revision", "io.telecrypt.config-contract",
            )), (key, "label types"))
            check(channel.get("org.opencontainers.image.source") == f"https://github.com/TeleCrypt-io/{'controlplane' if key == 'CONTROLPLANE_IMAGE' else 'cashier'}", (key, "source"))
            check(channel.get("org.opencontainers.image.version") == version, (key, "version"))
            check(re.fullmatch(r"[0-9a-f]{40}", channel.get("org.opencontainers.image.revision", "")), (key, "revision"))
            check(channel.get("io.telecrypt.config-contract") == "1", (key, "config contract"))
        check(labels["org.opencontainers.image.revision"] == config_labels["org.opencontainers.image.revision"], (key, "label channels"))
        if key == "CASHIER_IMAGE":
            check(validate_cashier_provenance(labels, values[key]) == validate_cashier_provenance(config_labels, values[key]), (key, "label channels"))
        check(config.get("User") == "991:991", (key, "user"))
    labels, config, _ = images["SYNAPSE_IMAGE"]
    validate_synapse_provenance(
        labels,
        config.get("Labels"),
        values["SYNAPSE_IMAGE"].rsplit(":", 1)[1],
        values["CONTROLPLANE_IMAGE"].rsplit(":", 1)[1],
    )
    print("Verified published image repositories, digests, config, and provenance labels")


def product_release_asset_name(key: str, image: str) -> str:
    return f"{PUBLIC_RELEASES[key]['asset_prefix']}{image.rsplit(':', 1)[1]}.digest.json"


def validate_cashier_provenance(labels: object, image: str) -> dict[str, str]:
    version = image.rsplit(":", 1)[1]
    check(type(labels) is dict, ("CASHIER_IMAGE", "provenance labels"))
    source = labels.get("org.opencontainers.image.source")
    label_version = labels.get("org.opencontainers.image.version")
    revision = labels.get("org.opencontainers.image.revision")
    check(
        type(source) is str
        and source == "https://github.com/TeleCrypt-io/cashier"
        and type(label_version) is str
        and label_version == version
        and type(revision) is str
        and re.fullmatch(r"[0-9a-f]{40}", revision),
        ("CASHIER_IMAGE", "provenance"),
    )
    return {"source": source, "version": label_version, "revision": revision}


def validate_image_record(key: str, record: object) -> None:
    check(type(record) is dict and set(record) == IMAGE_RECORD_KEYS, (key, "record shape"))


def product_release_asset_names(key: str, image: str) -> set[str]:
    tag = image.rsplit(":", 1)[1]
    names = {product_release_asset_name(key, image)}
    if key == "CONTROLPLANE_IMAGE":
        names.add(f"telecrypt_tier_controller-{tag}-py3-none-any.whl")
    return names


def parse_product_release_asset(key: str, raw: bytes) -> dict[str, str]:
    check(key in PUBLIC_RELEASE_KEYS, (key, "public release evidence"))
    try:
        text = raw.decode("utf-8")
        values = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError((key, "release asset JSON")) from error
    check(type(values) is dict and json.dumps(values, sort_keys=True, separators=(",", ":")) + "\n" == text, (key, "canonical asset"))
    fields = {"annotated_tag_sha", "digest", "image", "schema_version", "source_commit", "tag"}
    check(set(values) == fields and type(values["schema_version"]) is int and values["schema_version"] == 1, (key, "asset schema"))
    for field in fields - {"schema_version"}:
        check(type(values[field]) is str, (key, field, "asset field type"))
    return {"image": values["image"], "tag": values["tag"], "commit": values["source_commit"], "annotated_tag_sha": values["annotated_tag_sha"], "digest": values["digest"]}


def product_release_body(key: str, tag: str, source_commit: str) -> str:
    check(key in PUBLIC_RELEASE_KEYS, (key, "public release evidence"))
    if key == "CONTROLPLANE_IMAGE":
        return f"Exact Controlplane release {tag}."
    if key == "SYNAPSE_IMAGE":
        return f"Exact Synapse release for source commit {source_commit}."
    return "TeleCrypt immutable image digest record."


def validate_release_asset_label(key: str, item: object) -> str:
    check(type(item) is dict and type(item.get("label")) is str and item["label"] == "", (key, "asset label"))
    return item["label"]


def validate_product_tag_evidence(
    key: str,
    tag: str,
    source_commit: str,
    annotated_tag_sha: str,
    tag_ref_document: dict,
    annotated_tag_document: dict,
) -> None:
    api_root = f"https://api.github.com/repos/{PUBLIC_RELEASES[key]['repository']}"
    check(
        type(tag_ref_document) is dict
        and tag_ref_document.get("ref") == f"refs/tags/{tag}",
        (key, "tag ref"),
    )
    check(
        tag_ref_document.get("url") == f"{api_root}/git/refs/tags/{tag}",
        (key, "tag ref URL"),
    )
    ref_object = tag_ref_document.get("object")
    check(
        type(ref_object) is dict
        and ref_object.get("type") == "tag"
        and ref_object.get("sha") == annotated_tag_sha,
        (key, "annotated tag ref object"),
    )
    check(
        ref_object.get("url") == f"{api_root}/git/tags/{annotated_tag_sha}",
        (key, "annotated tag ref object URL"),
    )
    check(
        type(annotated_tag_document) is dict
        and annotated_tag_document.get("sha") == annotated_tag_sha
        and annotated_tag_document.get("tag") == tag,
        (key, "annotated tag object"),
    )
    check(
        annotated_tag_document.get("url") == f"{api_root}/git/tags/{annotated_tag_sha}",
        (key, "annotated tag object URL"),
    )
    peeled = annotated_tag_document.get("object")
    check(
        type(peeled) is dict
        and peeled.get("type") == "commit"
        and peeled.get("sha") == source_commit,
        (key, "peeled tag commit"),
    )
    check(
        peeled.get("url") == f"{api_root}/git/commits/{source_commit}",
        (key, "peeled tag commit URL"),
    )


def validate_product_release(
    key: str,
    image: str,
    expected_digest: str,
    labels: dict,
    release_document: dict,
    asset: bytes,
    tag_ref_document: dict,
    annotated_tag_document: dict,
) -> dict[str, object]:
    tag = image.rsplit(":", 1)[1]
    expected_asset = product_release_asset_name(key, image)
    check(isinstance(release_document, dict), (key, "release object"))
    release_id = release_document.get("id")
    check(type(release_id) is int and release_id > 0, (key, "release id"))
    check(
        release_document.get("tag_name") == tag
        and release_document.get("name") == tag
        and release_document.get("draft") is False
        and release_document.get("prerelease") is False
        and release_document.get("immutable") is True,
        (key, "release identity/state"),
    )
    release_body_value = release_document.get("body")
    check(type(release_body_value) is str, (key, "release body type"))
    check(
        release_body_value == product_release_body(key, tag, labels.get("org.opencontainers.image.revision", "")),
        (key, "release body"),
    )
    assets = release_document.get("assets")
    expected_assets = product_release_asset_names(key, image)
    check(type(assets) is list and len(assets) == len(expected_assets), (key, "asset set"))
    asset_names = [item.get("name") if type(item) is dict else None for item in assets]
    check(all(type(name) is str for name in asset_names) and set(asset_names) == expected_assets, (key, "asset set"))
    seen_ids: set[int] = set()
    for item in assets:
        check(type(item) is dict and type(item.get("id")) is int and item["id"] > 0 and item["id"] not in seen_ids, (key, "asset id"))
        seen_ids.add(item["id"])
        validate_release_asset_label(key, item)
        name = item.get("name")
        check(
            type(name) is str
            and item.get("state") == "uploaded"
            and type(item.get("size")) is int
            and item["size"] > 0
            and item["size"] <= 64 * 1024 * 1024,
            (key, name, "asset state/size"),
        )
        check(
            type(item.get("digest")) is str
            and re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"]),
            (key, name, "asset digest"),
        )
    selected = next(item for item in assets if item.get("name") == expected_asset)
    check(selected["size"] <= 1048576 and len(asset) == selected["size"] and "sha256:" + hashlib.sha256(asset).hexdigest() == selected["digest"], (key, "asset bytes"))
    payload = parse_product_release_asset(key, asset)
    check(payload["image"] == image.rsplit(":", 1)[0] and payload["tag"] == tag and re.fullmatch(r"[0-9a-f]{40}", payload["commit"]) and payload["commit"] == labels.get("org.opencontainers.image.revision") and payload["digest"] == expected_digest, (key, "asset binding"))
    check(re.fullmatch(r"[0-9a-f]{40}", payload["annotated_tag_sha"]), (key, "annotated tag"))
    validate_product_tag_evidence(key, tag, payload["commit"], payload["annotated_tag_sha"], tag_ref_document, annotated_tag_document)
    return {
        "asset": expected_asset,
        "asset_id": selected["id"],
        "asset_label": selected["label"],
        "asset_digest": selected["digest"],
        "asset_size": selected["size"],
        "release_id": release_id,
        "source_commit": payload["commit"],
        "tag": tag,
        "annotated_tag_sha": payload["annotated_tag_sha"],
        "body": release_body_value,
    }


def image_release_manifest(values: dict[str, str], metadata: dict[str, dict], labels: dict[str, dict], release_tag: str, source_commit: str, annotated_tag_sha: str, product_releases: dict[str, dict] | None = None, product_assets: dict[str, bytes] | None = None, product_tag_refs: dict[str, dict] | None = None, product_annotated_tags: dict[str, dict] | None = None, resolved_digests: dict[str, str] | None = None) -> dict:
    check(re.fullmatch(r"server-state-[0-9a-f]{7,10}", release_tag) and re.fullmatch(r"[0-9a-f]{40}", source_commit) and re.fullmatch(r"[0-9a-f]{40}", annotated_tag_sha), "outer release identity")
    records = {}
    for key in IMAGE_KEYS:
        image = values[key]
        repository = image.rsplit(":", 1)[0]
        document = metadata[key]
        check(type(document) is dict and type(document.get("Name")) is str and type(document.get("Digest")) is str and document["Name"] in _metadata_name(repository) and re.fullmatch(r"sha256:[0-9a-f]{64}", document["Digest"]), (key, "image metadata"))
        digest = resolved_digests.get(key, document["Digest"]) if resolved_digests else document["Digest"]
        check(re.fullmatch(r"sha256:[0-9a-f]{64}", digest), (key, "resolved digest"))
        record = {"digest": digest, "image": image}
        if key in PUBLIC_RELEASE_KEYS:
            check(product_releases and product_assets and product_tag_refs and product_annotated_tags and key in product_releases and key in product_assets and key in product_tag_refs and key in product_annotated_tags, (key, "release evidence"))
            provenance = labels[key]
            check(type(provenance) is dict, (key, "provenance labels"))
            expected_source = f"https://github.com/TeleCrypt-io/{'telecrypt-synapse' if key == 'SYNAPSE_IMAGE' else 'controlplane'}"
            check(
                type(provenance.get("org.opencontainers.image.source")) is str
                and provenance["org.opencontainers.image.source"] == expected_source
                and type(provenance.get("org.opencontainers.image.version")) is str
                and provenance["org.opencontainers.image.version"] == image.rsplit(":", 1)[1],
                (key, "provenance"),
            )
            release_record = validate_product_release(
                key,
                image,
                digest,
                provenance,
                product_releases[key],
                product_assets[key],
                product_tag_refs[key],
                product_annotated_tags[key],
            )
            check(set(release_record) == PRODUCT_RELEASE_RECORD_KEYS, (key, "release record shape"))
            check(release_record["source_commit"] == provenance.get("org.opencontainers.image.revision"), (key, "release revision"))
        elif key == "CASHIER_IMAGE":
            validate_cashier_provenance(labels[key], image)
        validate_image_record(key, record)
        records[key] = record
    check(set(records) == set(IMAGE_KEYS), "five-image manifest")
    return {"annotated_tag_sha": annotated_tag_sha, "images": records, "schema_version": 1, "server_state_tag": release_tag, "source_commit": source_commit}


def validate_image_release_manifest(directory: Path, output: Path, release_tag: str, source_commit: str, annotated_tag_sha: str) -> None:
    values = load_manifest()
    validate_published_images(directory)
    metadata = {key: json.loads((directory / f"{image_reference_filename(values[key])}.metadata").read_text(encoding="utf-8")) for key in IMAGE_KEYS}
    labels = {key: json.loads((directory / f"{image_reference_filename(values[key])}.labels").read_text(encoding="utf-8")) for key in IMAGE_KEYS}
    releases = {key: json.loads((directory / f"{key}.release.json").read_text(encoding="utf-8")) for key in PUBLIC_RELEASES}
    assets = {key: (directory / f"{key}.release.asset").read_bytes() for key in PUBLIC_RELEASES}
    tag_refs = {key: json.loads((directory / f"{key}.annotated-tag-ref.json").read_text(encoding="utf-8")) for key in PUBLIC_RELEASES}
    annotated_tags = {key: json.loads((directory / f"{key}.annotated-tag.json").read_text(encoding="utf-8")) for key in PUBLIC_RELEASES}
    resolved_digests = {
        key: (directory / f"{key}.tag-digest").read_text(encoding="utf-8").strip()
        for key in IMAGE_KEYS
    }
    check(all(re.fullmatch(r"sha256:[0-9a-f]{64}", digest) for digest in resolved_digests.values()), "resolved tag digests")
    document = image_release_manifest(values, metadata, labels, release_tag, source_commit, annotated_tag_sha, releases, assets, tag_refs, annotated_tags, resolved_digests)
    output.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"Wrote deterministic image release manifest: {output}")


def validate_image_list(path: Path) -> None:
    expected = set(load_manifest().values())
    actual = path.read_text(encoding="utf-8").splitlines()
    check(len(actual) == len(set(actual)) == len(expected) and set(actual) == expected, actual)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("manifest", "source", "rendered-compose", "adapted-caddy", "image-list", "images", "image-release-manifest", "image-name", "toolchain"))
    parser.add_argument("path", nargs="?", type=Path)
    parser.add_argument("value", nargs="?")
    parser.add_argument("output", nargs="?", type=Path)
    args = parser.parse_args()
    values = load_manifest()
    if args.command == "manifest":
        export(values)
    elif args.command == "source":
        validate_manifest_negative(values)
        validate_source(values)
    elif args.command == "rendered-compose":
        check(args.path is not None, "rendered Compose JSON path required")
        validate_rendered(args.path)
    elif args.command == "adapted-caddy":
        check(args.path is not None, "adapted Caddy JSON path required")
        validate_adapted_caddy(args.path)
    elif args.command == "image-list":
        check(args.path is not None, "image list path required")
        validate_image_list(args.path)
    elif args.command == "image-release-manifest":
        check(args.path and args.value and args.output and args.path.is_dir(), "image metadata directory, release tag, and output required")
        source_commit = os.environ.get("GITHUB_SHA", "")
        annotated_tag_sha = os.environ.get("SERVER_STATE_ANNOTATED_TAG_SHA", "")
        check(source_commit and annotated_tag_sha, "release identity environment")
        validate_image_release_manifest(args.path, args.output, args.value, source_commit, annotated_tag_sha)
    elif args.command == "image-name":
        check(args.path is not None, "image coordinate required")
        print(image_reference_filename(str(args.path)))
    elif args.command == "toolchain":
        check(args.path is not None and args.value is not None, "toolchain versions required")
        validate_toolchain(str(args.path), args.value)
    else:
        check(args.path and args.path.is_dir(), "image metadata directory required")
        validate_published_images(args.path)


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"Server State contract failure: {error}", file=sys.stderr)
        raise SystemExit(1)
