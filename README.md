# TeleCrypt.io server

Public runtime configuration for the TeleCrypt Matrix service:

- Synapse homeserver with closed federation.
- A controlplane-owned, exact-version Synapse policy-module image.
- Matrix Authentication Service (MAS / MSC3861).
- Caddy HTTP ingress behind an external TLS terminator.
- TeleCrypt control-plane services (`redpill`, `janitor`, and `cashier`).
- External PostgreSQL and S3-backed encrypted media.

## Configure

1. Copy `.env.example` to the server-only `.env`.
2. Copy `secrets/*.example.*` to a private directory outside this repository and replace every
   placeholder.
3. Set `TELECRYPT_SECRETS_DIR` and `TELECRYPT_DATA_DIR` in `.env`.
4. Validate before starting:

```sh
docker compose config --quiet
docker compose run --rm caddy caddy validate --config /etc/caddy/Caddyfile
docker compose up -d
docker compose ps
```

`telecrypt.io` serves Matrix discovery and redirects ordinary web traffic to `www.telecrypt.io`.
Matrix, MAS, and registration endpoints live at `backend.telecrypt.io`. Production billing is
disabled in the base stack until a separately reviewed live-billing release.

Administrative Synapse and MAS paths are deliberately unavailable through public ingress.

## Isolated billing sandbox

The Dodo test flow is a complete, separate Matrix deployment—not a test cashier attached to the
production-shaped Matrix stack. It uses `test.telecrypt.io` / `backend.test.telecrypt.io`, separate
Synapse and MAS state, a separate signing key and media bucket/prefix, separate MAS/OIDC clients,
and one shared test-only control-plane database for both cashier and janitor. Sharing that one
test-only database is required so janitor sees paid and manual grants; it is never shared with
production.

Copy `.env.billing-test.example` to an untracked `.env.billing-test`. Populate a new secrets
directory from the `*.billing-test.example.*` templates (renaming them to the ordinary runtime
filenames), create a separate Synapse signing key, and use a separate data directory. Then validate
the merged stack:

```sh
docker compose --project-name telecrypt-billing-test \
  --env-file .env.billing-test \
  -f compose.yml -f compose.billing-test.yml \
  --profile billing-test config --quiet

docker compose --project-name telecrypt-billing-test \
  --env-file .env.billing-test \
  -f compose.yml -f compose.billing-test.yml \
  --profile billing-test run --rm caddy \
  caddy validate --config /etc/caddy/Caddyfile
```

Before starting it, the owner must manually provision DNS and the upstream TLS/HAProxy routes for
both test hostnames and point the Dodo test-product webhook at
`https://backend.test.telecrypt.io/webhooks/dodo`. Do not reuse production databases, credentials,
products, webhooks, signing keys, media storage, or accounts. Start/deploy this override with its
own reviewed procedure; the production-oriented `deploy/deploy.sh` is intentionally not used.

## Releases

Runtime images use exact version tags by project policy. Upgrade them deliberately after testing.
See `deploy/README.md` for the exact-release-tag deployment entry point.

The `redpill`, `janitor`, and `cashier` services use
`ghcr.io/telecrypt-io/telecrypt-controlplane:0.3.0`, while `synapse` uses the matching
`ghcr.io/telecrypt-io/telecrypt-synapse-tier-controller:0.3.0` image. Their source, tests, and
Synapse compatibility work belong in `controlplane`; this repository only selects the coordinated
exact release and configures it. Release both controlplane images before changing these references.
The server release must remain blocked until both `0.3.0` images are published.

## Security and licence

Do not commit `.env`, populated secret templates, signing keys, or deployment inventory. Report
security issues according to [SECURITY.md](./SECURITY.md).

Licensed under [BUSL-1.1](./LICENSE); converts to Apache-2.0 on 2030-07-20.
