# tier_controller

Pure-Python Synapse module (`module_api` callbacks only — no outbound HTTP, no credentials,
enforcement is its only job). Bind-mounted read-only into the `synapse` container at `/modules`
(`PYTHONPATH=/modules`, see `server/compose.yml`) and loaded via `modules:` in
`server/synapse/homeserver.yaml` — no image rebuild needed to deploy a change here.

Formerly `tc_enforcement`; renamed when the tier model was inverted and simplified (see
`server/CHANGELOG.md` for the history — this file only covers the module itself).

## Model

A user is **RESTRICTED** unless their Synapse `users.user_type` is exactly `'verified'`.
NULL/absent `user_type` (the default for every freshly registered account, human or agent) is
restricted. There is no second tier: `verified` is uncapped, everything else shares one
`restricted_room_cap`. A DB error while looking up `user_type` also fails closed to restricted —
see the fail-closed comments in `__init__.py`.

Three callbacks enforce this:
- `is_user_allowed_to_upload_media_of_size` — denies uploads for restricted users.
- `user_may_create_room` — denies room creation once a restricted user is at `restricted_room_cap`.
- `check_event_for_spam` — denies `m.room.encryption` state events for restricted users.

Per-user `user_type` (and room-count) lookups are cached for `_CACHE_TTL_SECONDS` (30s) to avoid a
DB round trip on every upload/room-create/state-event; a tier change (e.g. via `cashier`'s `reconcileTeamEntitlement` or `tc-verify.sh`) can take up to that long to take effect.

## Config

```yaml
modules:
  - module: tier_controller.TierController
    config:
      restricted_room_cap: 3   # rooms a restricted user may create; verified users are uncapped
```

## Denial messages

Where the Synapse 1.155.0 callback API supports it, denials carry an actionable message pointing
the user at verification:

> This account is unverified. Uploads/room creation/encryption require a verified account — sign
> in at https://telecrypt.io with an email address to request verification. See
> https://telecrypt.io/llms.txt

This works for `user_may_create_room` and `check_event_for_spam` — both can return
`(Codes.FORBIDDEN, {"error": "..."})`, and Synapse's `SynapseError.error_dict()` lets that dict's
`"error"` key overwrite the handler's own fixed message before it reaches the client (see the
`__init__.py` module docstring for the exact code paths that make this true, verified against the
installed `matrix-synapse==1.155.0` package source, not docs).

**Known limitation:** `is_user_allowed_to_upload_media_of_size` is declared
`Callable[[str, int], Awaitable[bool]]` — a bare bool, nothing else. Synapse's own caller
(`synapse/rest/media/upload_resource.py`) raises a hardcoded
`SynapseError(413, "Upload request body is too large", errcode=Codes.TOO_LARGE)` regardless of
what the module returns; there is no message channel on this callback in 1.155.0. A restricted
user's upload is denied, but the client sees the generic "too large" error rather than the
verification message. Nothing to do here short of a Synapse-side change.

## Tests

Fake-`module_api` unit tests, no live Synapse required to run them — see
`test_tier_controller.py`'s module docstring for the exact command. They do require
`matrix-synapse==1.155.0` importable (real package, not the fake) so the test file can import real
`Codes`/`NOT_SPAM` symbols; install into a scratch venv if one isn't already set up:

```sh
python3 -m venv /tmp/synvenv && source /tmp/synvenv/bin/activate
pip install matrix-synapse==1.155.0 pytest pytest-asyncio
cd server/synapse/modules/tier_controller && python -m pytest test_tier_controller.py -v
```
