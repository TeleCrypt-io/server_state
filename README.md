# TeleCrypt.io server

Public runtime configuration for the TeleCrypt Matrix service:

- Synapse homeserver with closed federation.
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
Matrix, MAS, registration, and Plan endpoints live at `backend.telecrypt.io`.

Administrative Synapse and MAS paths are deliberately unavailable through public ingress.

## Releases

Runtime images use exact version tags by project policy. Upgrade them deliberately after testing.
See `deploy/README.md` for the exact-release-tag deployment entry point.

## Security and licence

Do not commit `.env`, populated secret templates, signing keys, or deployment inventory. Report
security issues according to [SECURITY.md](./SECURITY.md).

Licensed under [BUSL-1.1](./LICENSE); converts to Apache-2.0 on 2030-07-20.
