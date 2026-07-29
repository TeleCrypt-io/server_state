# Release deployment

The server is deployed manually from an **exact, immutable Git release tag**. The
deployment host never follows `main`, performs a hard reset, or receives a push from
CI. This keeps a running version explicit and makes rollback a deliberate action.

```bash
deploy/deploy.sh release 0.2.0
```

Before changing the running stack, the script:

- requires a clean checkout;
- fetches exactly the requested tag from `origin`;
- validates that tag in an isolated temporary worktree with `docker compose config`;
- checks only the required secret filenames, permissions, and local readability (it
  never prints or parses their contents).

It then checks out the tag detached, pulls the images specified by that release,
converges Compose, recreates Caddy so its bind-mounted configuration is refreshed,
and waits for Synapse and the public authentication discovery endpoint to respond.
It does not remove Compose orphans implicitly.

After a successful deployment, the active and prior release tag are stored outside
the checkout. Roll back to the previously successful release with:

```bash
deploy/deploy.sh rollback
```

Or select a known tag explicitly:

```bash
deploy/deploy.sh rollback 0.2.0
```

If health checks fail, the script leaves the failure visible and prints an exact
rollback command; it does not make an unreviewed automatic rollback decision.

## Release rules

- Create a reviewed, annotated release tag only after CI and a staging/test-environment
  check pass. Treat published release tags as immutable.
- Use version tags, not floating branches, image `latest` tags, or image digests. Image
  tags remain exact versions in `compose.yml`, by project policy.
- Keep actual secrets and host-specific ingress or backup procedures outside this public
  repository. The upstream TLS/load-balancer configuration remains an operator-managed
  manual responsibility.

`SETUP.md` describes the minimal one-time prerequisites. It deliberately contains no
production host inventory.
