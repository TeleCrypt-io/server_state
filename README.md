# TeleCrypt.io server state

Public runtime configuration for the TeleCrypt Matrix service:

- Synapse homeserver with closed federation.
- A controlplane-owned, exact-version Synapse policy-module image.
- Matrix Authentication Service (MAS / MSC3861).
- Caddy HTTP ingress behind an external TLS terminator.
- TeleCrypt control-plane services (`controlplane`, `janitor`, and `steward`) plus private Cashier.
- External PostgreSQL and S3-backed encrypted media.

## Configuration and activation

1. Obtain the private deployment procedure and secret-file contract from TeleCrypt Harness.
2. Use the Harness guarded activator for every production validation and activation. It verifies
   the exact immutable state release, validates rendered Compose and Caddy configuration, pulls
   released images, activates with `--no-build`, and records the result.
3. Do not run direct `docker compose pull`, `up`, `run`, or equivalent production activation
   commands from this public repository. Public source/config validation is performed by the
   repository workflow; the Harness performs the corresponding guarded VM preflight.

The private `.env` must contain exactly one value for each of `SERVER_NAME`, `BACKEND_HOST`, and
`BILLING_ENV`, plus `TELECRYPT_DATA_DIR` and the ingress binding values.
The deployment procedure derives the public backend origin as `https://${BACKEND_HOST}` and keeps
MAS at `/auth` and Plan at `/plan`; those paths are fixed in Compose rather than repeated as
operator-supplied URLs. Secret files are read from the mode-600
`TELECRYPT_DATA_DIR/secrets` directory. Harness writes the nonsecret Synapse and MAS identity
layers under `TELECRYPT_DATA_DIR/runtime` before Compose validation; private overlays contain
secret and application-specific settings only.

The configured Matrix server name serves discovery and redirects ordinary web traffic to
`https://www.telecrypt.io`. The configured backend host serves Matrix, MAS, registration, and Plan.
The ingress container listens on an unprivileged port as a non-root user, has a read-only root
filesystem, and receives only two private temporary directories needed by the official image.

Administrative Synapse and MAS paths are deliberately unavailable through public ingress. MAS's
administrator API is bound only to its internal listener; it is not placed on the public web
listener and is not routed by Caddy.

MAS's hosted `/auth/login` remains available for OAuth browser and device authorization. Caddy
returns `404` for public `/_matrix/client/*/login`, so Matrix password authentication is
unavailable. Only logout and refresh routes remain routed to MAS where Matrix clients require them.

## Billing mode

`BILLING_ENV` is explicit and must be exactly `test` or `production`. The Dodo API origin and
Cashier's identity checks derive from that value; MAS shows the Plan page at the fixed `/plan` URL.
Test mode displays a sandbox banner and Dodo's test-card instructions; card data is entered only on
Dodo's hosted checkout page.

Cashier uses `CASHIER_DB_URL`; Janitor uses `JANITOR_DB_URL`. The credentials may differ, but both
URLs must target the same PostgreSQL host, port, and database. Cashier owns the private billing
schema; the owner-managed Janitor role is read-only for its sweep. Both services enforce the same
explicit `BILLING_ENV`.

The Dodo webhook is a generated private capability URL held only in the VM's mode-600
`ingress.secrets.env`; it is never committed to this repository. Switching to live billing
requires a separately reviewed immutable release, live-only keys/product/webhook, and
`BILLING_ENV=production`.

The Dodo API origin is derived from `BILLING_ENV`; it is not a separate state or secret-file
setting. Keep provider credentials and webhook material in the cashier and ingress secret files.

## Releases

This repository contains declarative state only. It publishes no packages, images, deployment
tooling, secret templates, binaries, wheels, or other artifacts. The private Harness owns
deployment operations and the secret-file contract.

Every reviewed state change merged to `main` receives an immutable `server-state-<short-git-sha>` tag and
GitHub Release record. It selects exact component image releases, which must already be published
and verified. The state release is an identity for one configuration commit, not a package version.
Controlplane and Cashier release images advertise config contract `1`; Harness verifies that label
after authenticated pulls before activation.

## Security and licence

Do not commit `.env`, populated secret templates, signing keys, or deployment inventory. Report
security issues according to [SECURITY.md](./SECURITY.md).

Licensed under [BUSL-1.1](./LICENSE); converts to Apache-2.0 on 2030-07-20.
