# Secret templates

This directory contains placeholders only. Real values live outside the repository and are mounted
read-only by Compose.

| Template | Service |
|---|---|
| `synapse.secrets.example.yaml` | Synapse database, S3, and shared MAS secret |
| `mas.secrets.example.yaml` | MAS database, signing keys, and OAuth clients |
| `locker.secrets.example.env` | Janitor database, MAS admin client, and mail settings |
| `cashier.secrets.example.env` | Cashier database, Synapse token, OIDC, session, and Dodo settings |
| `*.billing-test.example.*` | Isolated full-stack billing sandbox counterparts |

Copy templates to `TELECRYPT_SECRETS_DIR`, remove `.example` from their names, replace every
`__CHANGEME__`/placeholder, and restrict access to the deployment owner. Never print populated files
in logs or commit them.

The same Synapse↔MAS shared secret must be configured on both services. Use separate database roles
and separate service credentials. Keep test and production cashier OIDC clients, Dodo credentials,
products, webhooks, and databases in different secret directories; `TELECRYPT_ENV` must match the
Dodo endpoint, public Plan hostname, and database identifier. The ordinary templates are for the
production-shaped base stack; the `*.billing-test.example.*` templates belong only to the isolated
test override.

Inside the test secrets directory, `cashier.secrets.env` and `locker.secrets.env` must contain the
same test-only `CONTROLPLANE_DB_URL`. This is an intentional enforcement invariant: cashier writes
billing/manual-grant provenance there and janitor reads the same provenance before locking test
accounts. The Synapse, MAS, control-plane, and media databases/buckets still remain distinct by
service and remain wholly separate from production.
