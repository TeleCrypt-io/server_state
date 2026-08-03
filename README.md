# TeleCrypt.io server state

Public runtime configuration for the TeleCrypt Matrix service:

- Synapse homeserver with closed federation.
- A controlplane-owned, exact-version Synapse policy-module image.
- Matrix Authentication Service (MAS / MSC3861).
- Caddy HTTP ingress behind an external TLS terminator.
- TeleCrypt control-plane services (`redpill`, `janitor`, and `steward`) plus private Cashier.
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
Matrix, MAS, registration, and Plan endpoints live at `backend.telecrypt.io`.

Administrative Synapse and MAS paths are deliberately unavailable through public ingress.

## Billing mode

The production Matrix deployment currently uses Dodo's test environment while live billing is
unavailable. `BILLING_ENV=test` is explicit, the Dodo API origin is the exact test origin, and MAS
shows the Plan page at `https://backend.telecrypt.io/plan`. The Plan page displays a sandbox banner
and Dodo's test-card instructions; card data is entered only on Dodo's hosted checkout page.

Cashier and janitor must use the same `CONTROLPLANE_DB_URL`. Both bind that database permanently to
`BILLING_ENV=test` and `MATRIX_DEPLOYMENT_ID=production` before serving or sweeping. A future live
billing release must use a different database; changing keys or environment variables cannot
silently reuse the test-billing state.

Configure the Dodo test-product webhook as
`https://backend.telecrypt.io/webhooks/dodo`. Switching to live billing requires a separately
reviewed immutable release, live-only keys/product/webhook, `BILLING_ENV=production`, and a new
control-plane database.

## Releases

This repository publishes no container packages, binaries, wheels, or other build artifacts.
Every reviewed change merged to `main` is eligible for one immutable declarative-state release:
an annotated Git tag and GitHub Release record whose notes identify the configuration change.
The deployment host consumes only those exact tags. See `deploy/README.md`.

It selects, but never builds, exact component releases. A server_state release must remain blocked
until every referenced component image/release is already published and verified.

## Security and licence

Do not commit `.env`, populated secret templates, signing keys, or deployment inventory. Report
security issues according to [SECURITY.md](./SECURITY.md).

Licensed under [BUSL-1.1](./LICENSE); converts to Apache-2.0 on 2030-07-20.
