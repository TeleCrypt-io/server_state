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

`telecrypt.io` serves Matrix discovery and redirects ordinary web traffic to `www.telecrypt.io`.
Matrix, MAS, registration, and Plan endpoints live at `backend.telecrypt.io`.

Administrative Synapse and MAS paths are deliberately unavailable through public ingress. MAS's
administrator API is bound only to its internal listener; it is not placed on the public web
listener and is not routed by Caddy.

MAS's hosted `/auth/login` remains available for OAuth browser and device authorization. Caddy
returns `404` for public `/_matrix/client/*/login` before the MAS compatibility handler, so Matrix
password authentication is unavailable. Only compatibility logout and refresh routes remain routed
to MAS where Matrix clients require them.

## Billing mode

The production Matrix deployment currently uses Dodo's test environment while live billing is
unavailable. `BILLING_ENV=test` is explicit, the Dodo API origin is the exact test origin, and MAS
shows the Plan page at `https://backend.telecrypt.io/plan`. The Plan page displays a sandbox banner
and Dodo's test-card instructions; card data is entered only on Dodo's hosted checkout page.

Cashier and janitor must use the same `CONTROLPLANE_DB_URL`. Both bind that database permanently to
`BILLING_ENV=test` and `MATRIX_DEPLOYMENT_ID=production` before serving or sweeping. A future live
billing release must use a different database; changing keys or environment variables cannot
silently reuse the test-billing state.

The Dodo webhook is a generated private capability URL held only in the VM's mode-600
`ingress.secrets.env`; it is never committed to this repository. Switching to live billing
requires a separately reviewed immutable release, live-only keys/product/webhook,
`BILLING_ENV=production`, and a new control-plane database.

## Releases

This repository contains declarative state only. It publishes no packages, images, deployment
tooling, secret templates, binaries, wheels, or other artifacts. The private Harness owns
deployment operations and the secret-file contract.

Every reviewed state change merged to `main` receives an immutable `server-state-<short-git-sha>` tag and
GitHub Release record. It selects exact component image releases, which must already be published
and verified. The state release is an identity for one configuration commit, not a package version.

## Security and licence

Do not commit `.env`, populated secret templates, signing keys, or deployment inventory. Report
security issues according to [SECURITY.md](./SECURITY.md).

Licensed under [BUSL-1.1](./LICENSE); converts to Apache-2.0 on 2030-07-20.
