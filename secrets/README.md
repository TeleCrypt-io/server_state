# Secret templates

This directory contains placeholders only. Real values live outside the repository and are mounted
read-only by Compose.

| Template | Service |
|---|---|
| `synapse.secrets.example.yaml` | Synapse database, S3, and shared MAS secret |
| `mas.secrets.example.yaml` | MAS database, signing keys, and OAuth clients |
| `locker.secrets.example.env` | Janitor database, MAS admin client, and mail settings |
| `plan.secrets.example.env` | Plan MAS OIDC, browser session, and Cashier assertion private key |
| `cashier.secrets.example.env` | Cashier database, Synapse token, Dodo, and Plan assertion public key |

Copy templates to `TELECRYPT_SECRETS_DIR`, remove `.example` from their names, replace every
`__CHANGEME__`/placeholder, and restrict access to the deployment owner. Never print populated files
in logs or commit them.

The same Synapse↔MAS shared secret must be configured on both services. Use separate database roles
and separate service credentials. `cashier.secrets.env` and `locker.secrets.env` must contain the
same test-billing `CONTROLPLANE_DB_URL`: cashier writes billing/manual-grant provenance there and
janitor reads it before locking accounts. `BILLING_ENV=test` must match the exact Dodo test origin.
Both processes permanently bind that database to the billing and Matrix deployment identities, so
a future live-billing release must use a different control-plane database and live-only credentials.
Keep the deprecated `TELECRYPT_ENV=test` alias in cashier's file while server `0.2.1` remains the
recorded rollback target; the new release ignores it, but the prior cashier requires it.
