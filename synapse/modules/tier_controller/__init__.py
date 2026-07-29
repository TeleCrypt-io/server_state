# tier_controller — fail-closed capability restrictions for unverified users.
#
# Bind-mounted into the stock synapse container (see server/compose.yml, PYTHONPATH) and loaded
# via `modules:` in homeserver.yaml — no image rebuild. Inverted tier model (see README.md in this
# directory): everyone is RESTRICTED (no uploads, a capped number of created rooms, no
# m.room.encryption) unless user_type == 'verified'. NULL/absent user_type (the default for a
# freshly registered account, agent or human) is restricted; only an explicit 'verified' user_type
# lifts the restriction. There is no second tier — 'verified' is uncapped, everything else shares
# one cap.
#
# Callback signatures + return-value handling verified by reading the installed Synapse 1.155.0
# package source directly (pip install matrix-synapse==1.155.0 in a scratch venv), not guessed
# from docs:
#   - media_repository_callbacks.is_user_allowed_to_upload_media_of_size(user_id, size) -> bool
#       synapse/rest/media/upload_resource.py hardcodes the client-facing error message
#       ("Upload request body is too large") regardless of what the module returns — bool is the
#       whole channel, there is no way for a module to attach a message here.
#   - spamchecker_callbacks.user_may_create_room(user_id, room_config)
#       -> NOT_SPAM | Codes | (Codes, dict) | bool (module_api/callbacks/spamchecker_callbacks.py).
#       synapse/handlers/room.py raises SynapseError(403, "You are not permitted to create rooms",
#       errcode=spam_check[0], additional_fields=spam_check[1]); SynapseError.error_dict() builds
#       the response as cs_error(msg, errcode, **additional_fields), and cs_error() seeds
#       {"error": msg, "errcode": errcode} then overwrites with **kwargs — so an additional_fields
#       dict containing an "error" key overwrites the fixed msg in the JSON body actually sent to
#       the client. Returning (Codes.FORBIDDEN, {"error": "<our message>"}) puts our text in the
#       "error" field a client displays. Confirmed empirically against the installed package:
#       SynapseError(403, "...", errcode=Codes.FORBIDDEN,
#       additional_fields={"error": "x"}).error_dict(None) == {"error": "x", "errcode": ...}.
#   - spamchecker_callbacks.check_event_for_spam(event)
#       -> NOT_SPAM | Codes | (Codes, dict) | str (same file). synapse/handlers/message.py raises
#       SynapseError(403, "This message has been rejected as probable spam", code, dict) for the
#       tuple case — same additional_fields["error"] overwrite mechanism applies; verified the same
#       way. (A bare non-NOT_SPAM string is also honoured directly as the message, but is called
#       out in Synapse's own docstring as deprecated/non-i18n; we use the tuple form for both
#       spam-checker callbacks for consistency.)
from __future__ import annotations

import logging
import time
from typing import Any

from synapse.api.errors import Codes
from synapse.module_api import ModuleApi, NOT_SPAM
from synapse.module_api.errors import ConfigError

logger = logging.getLogger(__name__)

VERIFIED = "verified"

# The message shown to a restricted user on every denial path that supports one (room creation,
# encryption). See README.md for why upload denials can't carry this text.
_DENIAL_MESSAGE = (
    "This account is unverified. Uploads/room creation/encryption require a verified account "
    "— sign in at https://telecrypt.io with an email address to request verification. "
    "See https://telecrypt.io/llms.txt"
)

# How long a user_type/room-count lookup is trusted before re-querying the DB. Bounds staleness
# after a tier change (the owner's verification script setting user_type='verified') without a DB
# round trip on every upload/room-create/state-event: a freshly verified account can see stale
# denials for up to this long.
_CACHE_TTL_SECONDS = 30.0


class TierControllerConfig:
    def __init__(self, restricted_room_cap: int) -> None:
        self.restricted_room_cap = restricted_room_cap


class TierController:
    def __init__(self, config: TierControllerConfig, api: ModuleApi) -> None:
        self.config = config
        self.api = api
        # user_id -> (user_type, expires_at_monotonic)
        self._user_type_cache: dict[str, tuple[str | None, float]] = {}

        api.register_media_repository_callbacks(
            is_user_allowed_to_upload_media_of_size=self.is_user_allowed_to_upload_media_of_size,
        )
        api.register_spam_checker_callbacks(
            user_may_create_room=self.user_may_create_room,
            check_event_for_spam=self.check_event_for_spam,
        )

    @staticmethod
    def parse_config(config: dict[str, Any]) -> TierControllerConfig:
        try:
            restricted_room_cap = int(config.get("restricted_room_cap", 3))
        except (TypeError, ValueError) as e:
            raise ConfigError("restricted_room_cap must be an integer") from e
        return TierControllerConfig(restricted_room_cap)

    async def _get_user_type(self, user_id: str) -> str | None:
        cached = self._user_type_cache.get(user_id)
        now = time.monotonic()
        if cached is not None and cached[1] > now:
            return cached[0]

        def txn(cursor: Any) -> str | None:
            cursor.execute("SELECT user_type FROM users WHERE name = %s", (user_id,))
            row = cursor.fetchone()
            return row[0] if row else None

        try:
            user_type = await self.api.run_db_interaction(
                "tier_controller_get_user_type", txn
            )
        except Exception:
            logger.exception(
                "tier_controller: user_type lookup failed for %s, failing closed", user_id
            )
            # Fail-closed: don't cache a DB-error result, so the next call retries the DB
            # instead of pinning the user as restricted for the full TTL. Returning None here is
            # enough to fail closed — _is_restricted() treats anything != VERIFIED as restricted.
            return None

        self._user_type_cache[user_id] = (user_type, now + _CACHE_TTL_SECONDS)
        return user_type

    async def _is_restricted(self, user_id: str) -> bool:
        # Inverted model: restricted unless explicitly verified. NULL/absent user_type (humans and
        # agents alike, fresh out of registration) and a DB error both surface as None here, which
        # is != VERIFIED, so both are restricted. There is no unrestricted default.
        return await self._get_user_type(user_id) != VERIFIED

    async def _count_created_rooms(self, user_id: str) -> int:
        def txn(cursor: Any) -> int:
            cursor.execute("SELECT count(*) FROM rooms WHERE creator = %s", (user_id,))
            row = cursor.fetchone()
            return int(row[0]) if row else 0

        try:
            return await self.api.run_db_interaction(
                "tier_controller_count_created_rooms", txn
            )
        except Exception:
            logger.exception(
                "tier_controller: room count lookup failed for %s, failing closed", user_id
            )
            # Fail-closed: an unreadable count is treated as already at the cap.
            return self.config.restricted_room_cap

    async def is_user_allowed_to_upload_media_of_size(self, user_id: str, size: int) -> bool:
        # Bool-only callback (see module docstring) — no message channel available here.
        return not await self._is_restricted(user_id)

    async def user_may_create_room(self, user_id: str, room_config: dict) -> Any:
        if not await self._is_restricted(user_id):
            return NOT_SPAM
        count = await self._count_created_rooms(user_id)
        if count >= self.config.restricted_room_cap:
            return Codes.FORBIDDEN, {"error": _DENIAL_MESSAGE}
        return NOT_SPAM

    async def check_event_for_spam(self, event: Any) -> Any:
        if event.type != "m.room.encryption" or not event.is_state():
            return NOT_SPAM
        if await self._is_restricted(event.sender):
            return Codes.FORBIDDEN, {"error": _DENIAL_MESSAGE}
        return NOT_SPAM
