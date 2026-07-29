# One-time deployment-host setup

This is a minimal, reusable setup guide. Keep environment-specific addresses, access
methods, credentials, TLS configuration, backup locations, and operator identities in
the private Harness runbook rather than this public repository.

## Prerequisites

- A Linux host with rootless Docker, the Compose plugin, Git, Bash, `curl`, and `stat`.
- A clone of this repository authenticated with a **read-only** deploy key or other
  read-only credential.
- Persistent storage outside the checkout for service data and secrets.
- A separately operated TLS-terminating reverse proxy/load balancer, configured manually
  to forward the public service to the Caddy listener. This repository does not manage
  that host.

## Required secret files

Create a private secrets directory and provide these files from the templates in
`secrets/`:

```text
synapse.secrets.yaml
synapse_signing.key
mas.secrets.yaml
locker.secrets.env
cashier.secrets.env
```

Each required file must be mode `600`. Use ownership compatible with the rootless Docker
deployment and each container's mapped identity. Do not put secret contents in Git, shell history,
CI variables, or this document.

Copy `.env.example` to an untracked `.env` in the deployment checkout and set the persistent data,
secret directory, ingress bind address, and exact trusted-proxy CIDR. The release preflight uses
that server-only file even while validating a candidate tag in an isolated worktree.

By default `deploy.sh` expects the checkout and persistent-data locations used by the
existing service. For a different host layout, set `TELECRYPT_REPO` and `TELECRYPT_DATA`
in the operator's environment before invoking it.

## First release

1. Review the release and create an immutable annotated version tag.
2. From a clean checkout on the deployment host, run:

   ```bash
   deploy/deploy.sh release v1.0.0
   ```

3. Verify the public endpoints and the authenticated application flow using the private
   acceptance checklist.

The first successful release establishes the local rollback state. No migration is made
from a branch-based deployment; choose and deploy an explicit release tag instead.
