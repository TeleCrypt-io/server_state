# Secret templates

This directory contains placeholders only. Real values live outside the repository and are mounted
read-only by Compose.

| Template | Service |
|---|---|
| `synapse.secrets.example.yaml` | Synapse database, S3, and shared MAS secret |
| `mas.secrets.example.yaml` | MAS database, signing keys, and OAuth clients |
| `locker.secrets.example.env` | Janitor database, MAS admin client, and mail settings |
| `cashier.secrets.example.env` | Cashier database, Synapse token, OIDC, session, and Dodo settings |

Copy templates to `TELECRYPT_SECRETS_DIR`, remove `.example` from their names, replace every
`__CHANGEME__`/placeholder, and restrict access to the deployment owner. Never print populated files
in logs or commit them.

The same Synapse↔MAS shared secret must be configured on both services. Use separate database roles
and separate service credentials. Keep test and production Dodo credentials, products, webhooks,
and databases in different secret files; `TELECRYPT_ENV` must match the configured Dodo endpoint.
