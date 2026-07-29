"""Unit tests for tier_controller using a fake module_api — no live Synapse required.

Run: cd server/synapse/modules/tier_controller && python -m pytest test_tier_controller.py -v
"""
import time
from types import SimpleNamespace

import pytest

from synapse.api.errors import Codes
from synapse.module_api import NOT_SPAM

from tier_controller import TierController, TierControllerConfig, _DENIAL_MESSAGE


class FakeModuleApi:
    """Duck-typed stand-in for synapse.module_api.ModuleApi."""

    def __init__(self, user_types: dict, room_counts: dict, db_error: bool = False):
        self.user_types = user_types
        self.room_counts = room_counts
        self.db_error = db_error
        self.registered_media = {}
        self.registered_spam = {}

    def register_media_repository_callbacks(self, **callbacks):
        self.registered_media.update(callbacks)

    def register_spam_checker_callbacks(self, **callbacks):
        self.registered_spam.update(callbacks)

    async def run_db_interaction(self, desc, func):
        if self.db_error:
            raise RuntimeError("simulated db failure")
        if desc == "tier_controller_get_user_type":
            return _run_user_type(self, func)
        elif desc == "tier_controller_count_created_rooms":
            return _run_room_count(self, func)
        raise AssertionError(f"unexpected desc {desc}")


def _run_user_type(api, func):
    # func expects cursor.execute(sql, (user_id,)) then cursor.fetchone(). We don't know user_id
    # ahead of time, so use a recording cursor that looks up user_types after execute() is called.
    class RecordingCursor:
        def __init__(self, table):
            self.table = table

        def execute(self, sql, args):
            self.user_id = args[0]

        def fetchone(self):
            val = self.table.get(self.user_id, "__missing__")
            if val == "__missing__":
                return None
            return (val,)

    return func(RecordingCursor(api.user_types))


def _run_room_count(api, func):
    class RecordingCursor:
        def __init__(self, table):
            self.table = table

        def execute(self, sql, args):
            self.user_id = args[0]

        def fetchone(self):
            return (self.table.get(self.user_id, 0),)

    return func(RecordingCursor(api.room_counts))


def make_module(user_types=None, room_counts=None, db_error=False, restricted_room_cap=3):
    api = FakeModuleApi(user_types or {}, room_counts or {}, db_error=db_error)
    config = TierControllerConfig(restricted_room_cap=restricted_room_cap)
    module = TierController(config, api)
    return module, api


def make_event(event_type, sender, is_state=True):
    return SimpleNamespace(type=event_type, sender=sender, is_state=lambda: is_state)


@pytest.mark.asyncio
async def test_unverified_denied_upload():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is False


@pytest.mark.asyncio
async def test_verified_allowed_upload():
    module, _ = make_module(user_types={"@a:x": "verified"})
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is True


@pytest.mark.asyncio
async def test_null_type_denied_upload():
    # Inverted model: NULL/absent user_type (humans and agents alike, fresh out of registration)
    # is restricted by default — only an explicit 'verified' lifts it.
    module, _ = make_module(user_types={"@a:x": None})
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is False


@pytest.mark.asyncio
async def test_unknown_legacy_type_denied_upload():
    # free_agent/paid_agent are gone; anything that isn't literally 'verified' is restricted,
    # including stale legacy values that might still be sitting in the DB.
    module, _ = make_module(user_types={"@a:x": "paid_agent"})
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is False


@pytest.mark.asyncio
async def test_restricted_room_cap_denied_at_cap():
    module, _ = make_module(
        user_types={"@a:x": "unverified"}, room_counts={"@a:x": 3}, restricted_room_cap=3
    )
    result = await module.user_may_create_room("@a:x", {})
    assert result == (Codes.FORBIDDEN, {"error": _DENIAL_MESSAGE})


@pytest.mark.asyncio
async def test_restricted_room_cap_allowed_under_cap():
    module, _ = make_module(
        user_types={"@a:x": "unverified"}, room_counts={"@a:x": 2}, restricted_room_cap=3
    )
    result = await module.user_may_create_room("@a:x", {})
    assert result is NOT_SPAM


@pytest.mark.asyncio
async def test_verified_bypasses_room_cap():
    module, _ = make_module(
        user_types={"@a:x": "verified"}, room_counts={"@a:x": 999999}
    )
    result = await module.user_may_create_room("@a:x", {})
    assert result is NOT_SPAM


@pytest.mark.asyncio
async def test_unverified_encryption_denied():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    event = make_event("m.room.encryption", "@a:x")
    result = await module.check_event_for_spam(event)
    assert result == (Codes.FORBIDDEN, {"error": _DENIAL_MESSAGE})


@pytest.mark.asyncio
async def test_verified_encryption_allowed():
    module, _ = make_module(user_types={"@a:x": "verified"})
    event = make_event("m.room.encryption", "@a:x")
    assert await module.check_event_for_spam(event) is NOT_SPAM


@pytest.mark.asyncio
async def test_null_type_encryption_denied():
    module, _ = make_module(user_types={"@a:x": None})
    event = make_event("m.room.encryption", "@a:x")
    result = await module.check_event_for_spam(event)
    assert result == (Codes.FORBIDDEN, {"error": _DENIAL_MESSAGE})


@pytest.mark.asyncio
async def test_non_encryption_event_ignored():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    event = make_event("m.room.message", "@a:x")
    assert await module.check_event_for_spam(event) is NOT_SPAM


@pytest.mark.asyncio
async def test_encryption_event_non_state_ignored():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    event = make_event("m.room.encryption", "@a:x", is_state=False)
    assert await module.check_event_for_spam(event) is NOT_SPAM


@pytest.mark.asyncio
async def test_db_error_fails_closed_on_upload():
    module, _ = make_module(user_types={"@a:x": "verified"}, db_error=True)
    # Even though the "real" type is verified, a DB error must fail closed (restricted).
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is False


@pytest.mark.asyncio
async def test_db_error_fails_closed_on_room_create():
    module, _ = make_module(user_types={"@a:x": "verified"}, db_error=True)
    result = await module.user_may_create_room("@a:x", {})
    assert result == (Codes.FORBIDDEN, {"error": _DENIAL_MESSAGE})


@pytest.mark.asyncio
async def test_cache_avoids_second_db_call():
    calls = {"n": 0}
    module, api = make_module(user_types={"@a:x": "unverified"})

    orig = api.run_db_interaction

    async def counting(desc, func):
        calls["n"] += 1
        return await orig(desc, func)

    api.run_db_interaction = counting

    await module._get_user_type("@a:x")
    await module._get_user_type("@a:x")
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_cache_expires_after_ttl(monkeypatch):
    module, api = make_module(user_types={"@a:x": "unverified"})

    calls = {"n": 0}
    orig = api.run_db_interaction

    async def counting(desc, func):
        calls["n"] += 1
        return await orig(desc, func)

    api.run_db_interaction = counting

    t = {"now": 1000.0}
    monkeypatch.setattr(time, "monotonic", lambda: t["now"])

    await module._get_user_type("@a:x")
    t["now"] += 31.0
    await module._get_user_type("@a:x")
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_db_error_result_not_cached():
    module, api = make_module(user_types={"@a:x": "verified"}, db_error=True)
    await module._get_user_type("@a:x")
    api.db_error = False
    result = await module._get_user_type("@a:x")
    assert result == "verified"
