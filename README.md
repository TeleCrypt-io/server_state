# TeleCrypt.io server state

Public runtime configuration for the TeleCrypt Matrix service:

- Synapse homeserver with closed federation.
- A TeleCrypt Synapse image containing the exact-version Controlplane policy-module wheel.
- Matrix Authentication Service (MAS / MSC3861).
- Caddy HTTP ingress behind an external TLS terminator.
- TeleCrypt services (Registration, Janitor, and Plan) plus private Cashier. Registration, Janitor,
  and Plan run from the `controlplane` image; the image/repository name is retained for release identity.
- External PostgreSQL and S3-backed media storage at `sss.telecrypt.io`; the storage endpoint is
  reachable only from the production VM. The provider synchronously stores local uploads in S3
  while remote-media fetching is disabled. The VM's
  `${TELECRYPT_DATA_DIR}/runtime/synapse-staging` directory is disposable staging/cache, not a
  durable media authority; the image entrypoint clears only that fixed mount at startup.

## Configuration and activation

1. Obtain the private deployment procedure and secret-file contract from the TeleCrypt Harness
   maintained by the operator.
2. Use the Harness guarded activator for every production validation and activation. It verifies
   the exact state release, rendered Compose and Caddy configuration, published images,
   `--no-build` activation, and the result record.
3. Do not run direct `docker compose pull`, `up`, `run`, or equivalent production activation
   commands from this public repository. The repository workflow validates public state; Harness
   performs the guarded VM preflight and owns private environment and secret handling.

`versions.env` is the canonical image coordinate manifest and must contain exactly these five keys:
`CADDY_IMAGE`, `SYNAPSE_IMAGE`, `MAS_IMAGE`, `CONTROLPLANE_IMAGE`, and `CASHIER_IMAGE`. The private
environment, derived backend and public-site hostnames, ingress binding, identity overlays, and
secret-file contract are maintained by the operator's private Harness. Harness snapshots the
private Janitor, Plan, and Cashier records and exports each service's exact environment contract
only to the guarded Compose process; Compose does not read live service `env_file` paths. The
committed `.env.example` contains TEST-NET documentation values only; replace them through the private
deployment procedure before activation.

The Matrix private inputs are `${TELECRYPT_DATA_DIR}/secrets/synapse.secrets.json`,
`${TELECRYPT_DATA_DIR}/secrets/synapse_signing.key`, and `${TELECRYPT_DATA_DIR}/secrets/mas.secrets.json`;
Harness validates their bounded contracts before passing them as file-backed Compose secrets; the
signing key is mounted as `/signing.key`. The MAS overlay contains its encryption/signing secrets,
database URI, Matrix shared secret, and two exact environment-bound clients. Synapse's config files
are shallow-merged by top-level key, so its private overlay owns each complete `database` and
`matrix_authentication_service` map; the committed base has no partial map that could overwrite it.
Email and policy defaults remain in `mas.yaml`; the final runtime identity layer supplies the Janitor
admin-client ID. The committed base configs retain reviewed nonsecret loader options, while
credentials, database URIs, OAuth client secrets, and provider values remain outside this repository.

The configured Matrix server name serves discovery. Only the production profile redirects ordinary
web traffic to the production-only landing site at `https://www.telecrypt.io`; the stage profile has
no public website and returns a bounded 404 for other apex requests. The only accepted public
identities are the exact production and future stage names; their backend and Storage hosts derive
directly from `SERVER_NAME`, while billing mode derives only from `BILLING_ENVIRONMENT`. Neither is
a separate provider or secret-file override.
Registration has no host publication and is attached to a dedicated Caddy edge network plus its
own outbound network; its public-URL calls do not expose it to the other application services.
MAS's internal/admin listener uses the supported `192.168.254.2:8081` socket address. Docker networks
are its only transport paths: no MAS port is published on the host, and Caddy does not route the admin path.
The MAS admin API remains credential-gated. The private `mas_admin_net`, which contains only MAS and
Janitor, is Janitor's dedicated application path; other attached application peers cannot use the API
without an authorized MAS client scope.
The listener is bound only to MAS's static `192.168.254.2:8081` address on `mas_admin_net`; Compose
reserves the minimal `192.168.254.0/29` private subnet for that path. The
operator must check this subnet against host, VPN, and other Docker routes before activation because
Docker cannot detect an overlap outside its own networks.
Janitor resolves that fixed address through the sole remaining `mas-admin` Docker alias on
`mas_admin_net`; this alias is name resolution only and is never used as a MAS socket bind.
The pinned distroless MAS image's Compose healthcheck validates configuration only; its bundled tools
cannot prove that either listener is accepting connections. Janitor is therefore excluded
from the default Compose start. Harness checks OIDC discovery and Plan readiness before starting the
one-shot `janitor` profile against the active exact state, without recreating or restarting MAS and
with the equivalent of Compose `--no-deps`.
Every service runs as its image-supported non-root UID/GID with no new privileges and drops Docker's
full default capability set. The official Caddy executable carries a `NET_BIND_SERVICE` file
capability, so Caddy alone adds back that exact capability inside its container to execute the image;
it grants no host privilege, and every other service remains capability-free. Each root filesystem
is read-only; only Caddy's two private temporary directories, Synapse's UID-991 `/tmp`, and
Synapse's disposable staging/cache mount are writable. Only Caddy publishes the unprivileged 8080
ingress port through its dedicated normal bridge network. It reaches each routed upstream through a
dedicated internal edge network; Synapse and MAS share only their required peer network, Plan shares
only its MAS and Cashier peer networks, Synapse and MAS share only the internal `synapse_mas_net` peer
network (retaining Compose service DNS) and use separate non-internal `synapse_egress_net` and
`mas_egress_net` paths, Cashier
has separate Plan, Synapse-admin, and external-egress paths, and Janitor's MAS-admin and external-egress
paths remain separate. Synapse's 8008 listener
must serve Caddy, MAS, and Cashier on their distinct peer networks, so it remains container-interface
bound; it has no host-published port and no fixed network addresses are assigned.
Deterministic default-route selection uses Compose `gw_priority: 1` on exactly five non-internal
egress attachments: Synapse and MAS on their separate egress networks, plus Registration, Cashier,
and Janitor on their dedicated egress networks. Docker Engine 28+ and Compose 2.33.1+ are required; the
workflow fails closed on older toolchains.
Synapse's Web and CLI upload ceiling is the same 128 MiB limit; no separate upload-size variable is
accepted. Local media storage is disabled, `TMPDIR` points to the disk-backed staging mount, and
only the 16 MiB `/tmp` tmpfs is RAM-backed. Extending that ceiling further requires a deliberate streaming design, including bounded
stream handling and end-to-end verification; it must not be raised by changing one setting.

Administrative Synapse and MAS paths are deliberately unavailable through public ingress. MAS's
administrator API is served on its separate internal listener/resource and is not placed on the
public web resources or routed by Caddy. Its MAS authorization scope remains the security boundary
for peers on attached Docker networks. The external TLS terminator must discard any
client-supplied forwarding headers, then append the observed client address and
`X-Forwarded-Proto: https` before forwarding to Caddy. Caddy strictly trusts only the exact
configured proxy host address for forwarded protocol and client context; Registration receives no
derived client-IP identity header. The guarded activation must verify RootlessKit 3.0 or newer with
built-in TCP source-address propagation and rootless Docker's userland-proxy disabled, then prove the
actual transport peer and forwarded-protocol behavior live; other rootless publish paths do not satisfy
the Caddy `remote_ip` boundary.
MAS's web listener uses the supported `[::]:8080` socket address. Docker network attachment controls
which peers can reach each listener, while Caddy routes only the public web resources; no hostname
aliases are used as MAS socket binds. Harness supplies the public URL and issuer in the final identity
layer.
MAS's `trusted_proxies` list is explicitly empty because that setting
only controls whether MAS accepts `X-Forwarded-For` for client-IP rate limiting and logging; leaving
it out would restore MAS's broad private-range defaults. MAS consequently sees Caddy as the source
for those IP-based limits/logs, while peer services cannot spoof a client address through MAS.
The guarded Harness must reject `TRUSTED_PROXY` values that are ranges, lists, or host bits: only
one canonical IPv4 address with `/32` or IPv6 address with `/128` is accepted.

MAS's hosted `/auth/login` remains available for OAuth browser and device authorization. Caddy
returns `404` for public `/_matrix/client/*/login`, so Matrix password authentication is
unavailable. Only logout and refresh routes remain routed to MAS where Matrix clients require them.

## Billing identity

`SERVER_NAME` owns public, Matrix, database-name, and OIDC topology. `BILLING_ENVIRONMENT` is the
separate explicit Dodo mode. Only these profiles are valid: `telecrypt.io` plus `test` (temporary
v1 acceptance), `stage.telecrypt.io` plus `test` (later isolated test), and `telecrypt.io` plus
`live` (launched production). Every other name, value, or pair is rejected; credentials and
ambient endpoint overrides never select a profile. Test deployments display a sandbox banner and
Dodo's test-card instructions; card data is entered only on Dodo's hosted checkout page.

Cashier uses `CASHIER_DB_URL`; Janitor uses `JANITOR_DB_URL`. The credentials may differ, but both
URLs must target the same PostgreSQL host, port, and database. Synapse and MAS use that exact same
owner-managed PostgreSQL host and port while retaining their own derived database names and roles.
Cashier owns the private billing schema; the owner-managed Janitor role is read-only for its sweep.
Plan, Janitor, and Cashier receive their own snapshotted private keys plus the validated
`SERVER_NAME` and `BILLING_ENVIRONMENT`. Caddy, Registration, Synapse, and MAS receive no billing
environment value; Caddy receives only its proxy and server identity values.
Janitor's MAS-admin credentials, database URL, and explicit `JANITOR_DRY_RUN` selector are always
required in the guarded Compose process environment. The selector must be exactly `0` or `1`; its
absence or emptiness is rejected. A dry run is allowed for either test profile (`SERVER_NAME` set to
`telecrypt.io` or `stage.telecrypt.io` with `BILLING_ENVIRONMENT=test`) and is rejected for the live billing profile.
Owner email and SMTP values remain required by Controlplane for a real sweep
and may be empty only for an explicitly selected test dry run.

The fixed `/webhooks/dodo` endpoint is proxied unchanged to Cashier; Cashier's Dodo signature
verification is the authentication boundary. Switching to live billing requires a separately
reviewed exact release and live-only keys/product/webhook material.

The Dodo API origin is selected only from the validated `BILLING_ENVIRONMENT`; it is not a separate
state or secret-file setting. Keep provider credentials and webhook signature material in the owner's private secret store
or VM secret input, never in Harness source; Harness snapshots and passes them only to Cashier's
guarded Compose process.

## Releases

This repository contains declarative state only. It publishes no packages, images, deployment
tooling, secret templates, binaries, or wheels. Each exact state Release carries one deterministic
JSON manifest binding the five selected image coordinates to their observed registry digests. Before
that manifest is published, the workflow verifies live immutable GitHub Release and annotated-tag
evidence for the public Synapse and Controlplane repositories. Every image entry in the published
manifest contains only its selected coordinate and digest; the private Harness owns deployment
operations and the secret-file contract.

A deliberately pushed, reviewed state tag receives an exact `server-state-<short-git-sha>` GitHub
Release record through a draft-first flow: the workflow verifies the complete draft metadata and
asset bytes before publishing, and resumes only an exact draft. A pre-existing published Release is
refused. It selects exact component image releases, which must already be published and verified. The
private Cashier immutable-Release check is intentionally an owner-authenticated local Harness gate
performed before Server State selection; the hosted workflow validates Cashier only from its selected
public GHCR digest and the exact OCI source, version, and revision labels. The Release's single JSON asset binds those selected tags to their observed canonical
registry digests for Harness preflight. `versions.env` is the one canonical image coordinate manifest
with exactly the five image keys used by Compose (`CADDY_IMAGE`, `SYNAPSE_IMAGE`, `MAS_IMAGE`,
`CONTROLPLANE_IMAGE`, and `CASHIER_IMAGE`); the workflow
rejects any Compose image tag, first-party image label, default command, entrypoint, user, route, or
public-origin contract that differs from the selected release contract. The state release is an
identity for one configuration commit, not a package version. Controlplane and Cashier images
advertise config contract `1`, and trusted exact state-tag runs of the public workflow
authenticate to GHCR to verify both first-party images as well as the public images; main and
pull-request runs receive the exact local contract checks without registry credentials. Do not change
`versions.env` or `compose.yml` independently; update their exact coordinates and contracts together
in one reviewed exact state change.

## Security and licence

Do not commit `.env`, populated secret templates, signing keys, or deployment inventory. Report
security issues according to [SECURITY.md](./SECURITY.md).

Licensed under [BUSL-1.1](./LICENSE); converts to Apache-2.0 on 2030-07-20.
