"""Tests for Telegram inline keyboard approval buttons."""

import asyncio
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure the repo root is importable
# ---------------------------------------------------------------------------
_repo = str(Path(__file__).resolve().parents[2])
if _repo not in sys.path:
    sys.path.insert(0, _repo)


# ---------------------------------------------------------------------------
# Minimal Telegram mock so TelegramAdapter can be imported
# ---------------------------------------------------------------------------
def _ensure_telegram_mock():
    """Wire up the minimal mocks required to import TelegramAdapter."""
    if "telegram" in sys.modules and hasattr(sys.modules["telegram"], "__file__"):
        return

    mod = MagicMock()
    mod.ext.ContextTypes.DEFAULT_TYPE = type(None)
    mod.constants.ParseMode.MARKDOWN = "Markdown"
    mod.constants.ParseMode.MARKDOWN_V2 = "MarkdownV2"
    mod.constants.ParseMode.HTML = "HTML"
    mod.constants.ChatType.PRIVATE = "private"
    mod.constants.ChatType.GROUP = "group"
    mod.constants.ChatType.SUPERGROUP = "supergroup"
    mod.constants.ChatType.CHANNEL = "channel"
    # Provide real exception classes so ``except (NetworkError, ...)`` in
    # connect() doesn't blow up under xdist when this mock leaks.
    mod.error.NetworkError = type("NetworkError", (OSError,), {})
    mod.error.TimedOut = type("TimedOut", (OSError,), {})
    mod.error.BadRequest = type("BadRequest", (Exception,), {})

    for name in ("telegram", "telegram.ext", "telegram.constants", "telegram.request"):
        sys.modules.setdefault(name, mod)
    sys.modules.setdefault("telegram.error", mod.error)


_ensure_telegram_mock()

from plugins.platforms.telegram.adapter import TelegramAdapter
from gateway.config import Platform, PlatformConfig


_GLADLY_APPROVAL_TEST_SECRET = "telegram-approval-secret"


def _make_adapter(extra=None):
    """Create a TelegramAdapter with mocked internals."""
    config = PlatformConfig(enabled=True, token="test-token", extra=extra or {})
    adapter = TelegramAdapter(config)
    adapter._bot = AsyncMock()
    adapter._app = MagicMock()
    return adapter


def _gladly_token(approval_id: str, decision: str) -> str:
    payload = {
        "v": 1,
        "a": approval_id,
        "d": decision,
        "iat": "2026-05-15T08:00:00.000Z",
        "exp": "2099-05-15T12:00:00.000Z",
        "n": f"nonce-{decision}",
    }
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8").hex()
    signed_part = f"hta.v1.h{encoded}"
    signature = hmac.new(
        _GLADLY_APPROVAL_TEST_SECRET.encode("utf-8"),
        signed_part.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{signed_part}.{signature}"


@pytest.fixture(autouse=True)
def _gladly_approval_secret(monkeypatch):
    monkeypatch.setenv("HERMES_TELEGRAM_APPROVAL_SECRET", _GLADLY_APPROVAL_TEST_SECRET)
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "*")


class _AuthRunner:
    """Minimal runner shim for callback auth tests."""

    def __init__(self, authorized: bool):
        self.authorized = authorized
        self.last_source = None

    async def _handle_message(self, event):
        return None

    def _is_user_authorized(self, source):
        self.last_source = source
        return self.authorized


class TestGladlyPortalApprovalButtons:
    @pytest.mark.asyncio
    async def test_send_attaches_buttons_and_hides_signed_commands(self, tmp_path):
        adapter = _make_adapter()
        adapter._bot.send_message = AsyncMock(return_value=SimpleNamespace(message_id=77))
        home = tmp_path / "home"
        content = "\n".join([
            "Beslut behövs: Godkänn lösning",
            "Kopiera ett helt kommando:",
            "Godkänn:",
            f"/gladly_approve {_gladly_token('approval-send', 'approved')}",
            "Begär ändring:",
            f"/gladly_change {_gladly_token('approval-send', 'changes_requested')}",
            "Stoppa:",
            f"/gladly_stop {_gladly_token('approval-send', 'rejected')}",
            "Ingen kundkontakt eller publicering görs utan godkännande.",
        ])

        with patch("hermes_constants.get_hermes_home", return_value=home):
            result = await adapter.send("12345", content, metadata={"notify": True})

        assert result.success is True
        kwargs = adapter._bot.send_message.call_args.kwargs
        assert kwargs["reply_markup"] is not None
        sent_text = kwargs["text"].replace("\\.", ".")
        assert "/gladly_" not in sent_text
        assert "hta.v1" not in sent_text
        assert "Välj ett alternativ med knapparna nedan." in sent_text

    def test_extracts_commands_into_short_telegram_buttons(self, tmp_path):
        adapter = _make_adapter()
        home = tmp_path / "home"
        content = "\n".join([
            "Beslut behövs: [P1] Godkänn lösning",
            "Kund A: Ta beslutet i Telegram eller öppna approval i Portalen.",
            "Risk: Kundsynlig effekt kräver mänskligt beslut.",
            "Kopiera ett helt kommando:",
            "",
            "Godkänn:",
            f"/gladly_approve {_gladly_token('approval-1', 'approved')}",
            "",
            "Begär ändring:",
            f"/gladly_change {_gladly_token('approval-1', 'changes_requested')}",
            "",
            "Stoppa:",
            f"/gladly_stop {_gladly_token('approval-1', 'rejected')}",
            "",
            "Ingen kundkontakt eller publicering görs utan godkännande.",
        ])

        with patch("hermes_constants.get_hermes_home", return_value=home):
            cleaned, keyboard = adapter._extract_gladly_approval_buttons(content)

        assert keyboard is not None
        assert "/gladly_" not in cleaned
        assert "hta.v1" not in cleaned
        assert "Kopiera ett helt kommando" not in cleaned
        assert "Välj ett alternativ med knapparna nedan." in cleaned

        state = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())
        entries = list(state["buttons"].values())
        assert sorted(entry["decision"] for entry in entries) == [
            "approved",
            "changes_requested",
            "rejected",
        ]
        assert all(len(entry["id"]) < 20 for entry in entries)
        assert all(entry["token"].startswith("hta.v1.") for entry in entries)

    def test_rejects_buttons_without_valid_signed_token(self, tmp_path, monkeypatch):
        adapter = _make_adapter()
        home = tmp_path / "home"
        token = _gladly_token("approval-invalid", "approved")
        tampered = f"{token}x"
        content = f"/gladly_approve {tampered}"

        with patch("hermes_constants.get_hermes_home", return_value=home):
            cleaned, keyboard = adapter._extract_gladly_approval_buttons(content)

        assert keyboard is None
        assert "/gladly_" not in cleaned
        assert "hta.v1" not in cleaned
        assert "Knappar kunde inte skapas" in cleaned
        assert not (home / "state-snapshots" / "telegram-approval-buttons.json").exists()

        monkeypatch.delenv("HERMES_TELEGRAM_APPROVAL_SECRET", raising=False)
        with patch("hermes_constants.get_hermes_home", return_value=home):
            cleaned, keyboard = adapter._extract_gladly_approval_buttons(f"/gladly_approve {token}")

        assert keyboard is None
        assert "/gladly_" not in cleaned
        assert "hta.v1" not in cleaned
        assert "Knappar kunde inte skapas" in cleaned

    def test_new_approval_notice_keeps_previous_buttons_for_same_approval(self, tmp_path):
        adapter = _make_adapter()
        home = tmp_path / "home"
        first_content = "\n".join([
            f"/gladly_approve {_gladly_token('approval-repeat', 'approved')}",
            f"/gladly_change {_gladly_token('approval-repeat', 'changes_requested')}",
            f"/gladly_stop {_gladly_token('approval-repeat', 'rejected')}",
        ])
        second_content = "\n".join([
            "Påminnelse: beslut behövs.",
            f"/gladly_approve {_gladly_token('approval-repeat', 'approved')}",
            f"/gladly_change {_gladly_token('approval-repeat', 'changes_requested')}",
            f"/gladly_stop {_gladly_token('approval-repeat', 'rejected')}",
        ])

        with patch("hermes_constants.get_hermes_home", return_value=home):
            adapter._extract_gladly_approval_buttons(first_content)
            first_state = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())
            first_ids = set(first_state["buttons"].keys())

            adapter._extract_gladly_approval_buttons(second_content)
            second_state = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())

        assert len(first_ids) == 3
        assert len(second_state["buttons"]) == 6
        assert first_ids.issubset(second_state["buttons"].keys())
        assert {entry["approval_id"] for entry in second_state["buttons"].values()} == {"approval-repeat"}

    @pytest.mark.asyncio
    async def test_callback_submits_signed_token_to_portal_script(self, tmp_path):
        adapter = _make_adapter()
        home = tmp_path / "home"
        content = f"/gladly_approve {_gladly_token('approval-2', 'approved')}"

        with patch("hermes_constants.get_hermes_home", return_value=home):
            adapter._extract_gladly_approval_buttons(content)
            state = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())
            button_id, entry = next(iter(state["buttons"].items()))

        query = AsyncMock()
        query.data = f"ga:{button_id}"
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.message.chat.type = "private"
        query.message.text = "\n".join([
            "Beslut behövs: Godkänn lösning",
            "Välj ett alternativ med knapparna nedan.",
            "Ingen kundkontakt eller publicering görs utan godkännande.",
        ])
        query.from_user = MagicMock()
        query.from_user.id = "12345"
        query.from_user.first_name = "Olle"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        proc = MagicMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"Beslutet sparades.", b""))

        with patch("hermes_constants.get_hermes_home", return_value=home):
            with patch("tools.environments.local._sanitize_subprocess_env", return_value={}):
                with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)) as spawn:
                    await adapter._handle_gladly_approval_callback(
                        query,
                        f"ga:{button_id}",
                        chat_id=12345,
                        chat_type="private",
                        thread_id=None,
                        user_name="Olle",
                    )

        spawn.assert_awaited_once()
        args = spawn.await_args.args
        kwargs = spawn.await_args.kwargs
        assert args[:3] == ("bash", str(home / "scripts" / "gladly-telegram-approval-action.sh"), "approved")
        assert kwargs["env"]["HERMES_QUICK_COMMAND_ARGS"] == entry["token"]
        assert kwargs["env"]["HERMES_QUICK_PLATFORM"] == "telegram"
        assert kwargs["env"]["HERMES_QUICK_USER_ID"] == "12345"

        query.edit_message_text.assert_awaited_once()
        edit_kwargs = query.edit_message_text.await_args.kwargs
        assert edit_kwargs["reply_markup"] is None
        assert "Välj ett alternativ" not in edit_kwargs["text"]
        assert "Beslut: Godkänt av Olle" in edit_kwargs["text"]

        remaining_state = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())
        assert remaining_state["buttons"] == {}

    @pytest.mark.asyncio
    async def test_callback_409_clears_stale_buttons_without_error_alert(self, tmp_path):
        adapter = _make_adapter()
        home = tmp_path / "home"
        content = "\n".join([
            f"/gladly_approve {_gladly_token('approval-stale', 'approved')}",
            f"/gladly_change {_gladly_token('approval-stale', 'changes_requested')}",
            f"/gladly_stop {_gladly_token('approval-stale', 'rejected')}",
        ])

        with patch("hermes_constants.get_hermes_home", return_value=home):
            adapter._extract_gladly_approval_buttons(content)
            state = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())
            button_id = next(
                item_id
                for item_id, item in state["buttons"].items()
                if item["decision"] == "approved"
            )

        query = AsyncMock()
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.message.chat.type = "private"
        query.message.text = "\n".join([
            "Beslut behövs: Godkänn lösning",
            "Välj ett alternativ med knapparna nedan.",
        ])
        query.from_user = MagicMock()
        query.from_user.id = "12345"
        query.from_user.first_name = "Olle"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        proc = MagicMock()
        proc.returncode = 1
        proc.communicate = AsyncMock(return_value=(b"", b"[gladly-telegram-approval] Approval redan beslutat. status=409"))

        with patch("hermes_constants.get_hermes_home", return_value=home):
            with patch("tools.environments.local._sanitize_subprocess_env", return_value={}):
                with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)):
                    await adapter._handle_gladly_approval_callback(
                        query,
                        f"ga:{button_id}",
                        chat_id=12345,
                        chat_type="private",
                        thread_id=None,
                        user_name="Olle",
                    )

        query.answer.assert_awaited_once()
        assert query.answer.await_args.kwargs["text"] == "Redan hanterat i Portalen."
        assert query.answer.await_args.kwargs.get("show_alert") is not True
        query.edit_message_text.assert_awaited_once()
        edit_kwargs = query.edit_message_text.await_args.kwargs
        assert edit_kwargs["reply_markup"] is None
        assert "Välj ett alternativ" not in edit_kwargs["text"]
        assert "Status: Godkännandet är redan hanterat i Portalen." in edit_kwargs["text"]

        remaining_state = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())
        assert remaining_state["buttons"] == {}

    @pytest.mark.asyncio
    async def test_missing_button_removes_markup_from_stale_message(self, tmp_path):
        adapter = _make_adapter()
        home = tmp_path / "home"

        query = AsyncMock()
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.message.chat.type = "private"
        query.message.text = "\n".join([
            "Beslut behövs: Godkänn lösning",
            "Välj ett alternativ med knapparna nedan.",
        ])
        query.from_user = MagicMock()
        query.from_user.id = "12345"
        query.from_user.first_name = "Olle"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        with patch("hermes_constants.get_hermes_home", return_value=home):
            await adapter._handle_gladly_approval_callback(
                query,
                "ga:missing-button",
                chat_id=12345,
                chat_type="private",
                thread_id=None,
                user_name="Olle",
            )

        query.answer.assert_awaited_once()
        assert query.answer.await_args.kwargs["text"] == "Beslutet har gått ut eller är redan hanterat."
        query.edit_message_text.assert_awaited_once()
        edit_kwargs = query.edit_message_text.await_args.kwargs
        assert edit_kwargs["reply_markup"] is None
        assert "Status: Godkännandet är redan hanterat i Portalen." in edit_kwargs["text"]

    @pytest.mark.asyncio
    async def test_wait_button_snoozes_approval_in_portal_without_decision(self, tmp_path):
        adapter = _make_adapter()
        home = tmp_path / "home"
        content = f"/gladly_approve {_gladly_token('approval-wait', 'approved')}"

        with patch("hermes_constants.get_hermes_home", return_value=home):
            adapter._extract_gladly_approval_buttons(content)
            state = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())
            button_id = next(iter(state["buttons"].keys()))

        query = AsyncMock()
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.message.chat.type = "private"
        query.message.text = "\n".join([
            "Beslut behövs: Godkänn lösning",
            "Välj ett alternativ med knapparna nedan.",
        ])
        query.message.reply_markup = "existing-buttons"
        query.from_user = MagicMock()
        query.from_user.id = "12345"
        query.from_user.first_name = "Olle"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        proc = MagicMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b'{"ok":true}', b""))

        with patch("hermes_constants.get_hermes_home", return_value=home):
            with patch("tools.environments.local._sanitize_subprocess_env", return_value={}):
                with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)) as spawn:
                    await adapter._handle_gladly_approval_wait_callback(
                        query,
                        f"gw:{button_id}:2h",
                        chat_id=12345,
                        chat_type="private",
                        thread_id=None,
                        user_name="Olle",
                    )

        spawn.assert_awaited_once()
        args = spawn.await_args.args
        kwargs = spawn.await_args.kwargs
        assert args[:3] == ("bash", str(home / "scripts" / "gladly-telegram-approval-snooze.sh"), "approval-wait")
        assert args[3] == "--until"
        assert str(args[4]).endswith("Z")
        assert kwargs["env"]["HERMES_QUICK_PLATFORM"] == "telegram"
        query.answer.assert_awaited_once()
        assert "Påminner" in query.answer.await_args.kwargs["text"]
        query.edit_message_text.assert_awaited_once()
        assert query.edit_message_text.await_args.kwargs["reply_markup"] == "existing-buttons"
        assert "Avvaktar 2 timmar" in query.edit_message_text.await_args.kwargs["text"]

        remaining_state = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())
        assert remaining_state["buttons"][button_id]["deferred_by"] == "Olle"
        assert remaining_state["buttons"][button_id]["deferred_at"]
        assert remaining_state["buttons"][button_id]["snooze_preset"] == "2h"

        snooze_state = json.loads((home / "state-snapshots" / "telegram-approval-snoozes.json").read_text())
        assert snooze_state["snoozes"]["approval-wait"]["preset"] == "2h"
        assert snooze_state["snoozes"]["approval-wait"]["snoozed_until"]

    @pytest.mark.asyncio
    async def test_wait_button_clears_stale_buttons_when_portal_says_not_pending(self, tmp_path):
        adapter = _make_adapter()
        home = tmp_path / "home"
        content = f"/gladly_approve {_gladly_token('approval-wait-stale', 'approved')}"

        with patch("hermes_constants.get_hermes_home", return_value=home):
            adapter._extract_gladly_approval_buttons(content)
            state = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())
            button_id = next(iter(state["buttons"].keys()))

        query = AsyncMock()
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.message.chat.type = "private"
        query.message.text = "\n".join([
            "Beslut behövs: Godkänn lösning",
            "Välj ett alternativ med knapparna nedan.",
        ])
        query.message.reply_markup = "existing-buttons"
        query.from_user = MagicMock()
        query.from_user.id = "12345"
        query.from_user.first_name = "Olle"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        proc = MagicMock()
        proc.returncode = 1
        proc.communicate = AsyncMock(return_value=(
            b"",
            "status=404 Approval hittades inte eller är inte i 'pending'-status.".encode("utf-8"),
        ))

        with patch("hermes_constants.get_hermes_home", return_value=home):
            with patch("tools.environments.local._sanitize_subprocess_env", return_value={}):
                with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)):
                    await adapter._handle_gladly_approval_wait_callback(
                        query,
                        f"gw:{button_id}:2h",
                        chat_id=12345,
                        chat_type="private",
                        thread_id=None,
                        user_name="Olle",
                    )

        query.answer.assert_awaited_once()
        assert query.answer.await_args.kwargs["text"] == "Redan hanterat i Portalen."
        query.edit_message_text.assert_awaited_once()
        assert query.edit_message_text.await_args.kwargs["reply_markup"] is None
        remaining_state = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())
        assert remaining_state["buttons"] == {}

    @pytest.mark.asyncio
    async def test_wait_button_does_not_update_local_snooze_when_portal_fails(self, tmp_path):
        adapter = _make_adapter()
        home = tmp_path / "home"
        content = f"/gladly_approve {_gladly_token('approval-wait-fail', 'approved')}"

        with patch("hermes_constants.get_hermes_home", return_value=home):
            adapter._extract_gladly_approval_buttons(content)
            state = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())
            button_id = next(iter(state["buttons"].keys()))

        query = AsyncMock()
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.message.chat.type = "private"
        query.message.text = "Beslut behövs"
        query.message.reply_markup = "existing-buttons"
        query.from_user = MagicMock()
        query.from_user.id = "12345"
        query.from_user.first_name = "Olle"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        proc = MagicMock()
        proc.returncode = 1
        proc.communicate = AsyncMock(return_value=(b"", b"status=0 connect timed out"))

        with patch("hermes_constants.get_hermes_home", return_value=home):
            with patch("tools.environments.local._sanitize_subprocess_env", return_value={}):
                with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)):
                    await adapter._handle_gladly_approval_wait_callback(
                        query,
                        f"gw:{button_id}:2h",
                        chat_id=12345,
                        chat_type="private",
                        thread_id=None,
                        user_name="Olle",
                    )

        query.answer.assert_awaited_once()
        assert "Hermes når inte Portalen" in query.answer.await_args.kwargs["text"]
        query.edit_message_text.assert_not_awaited()
        assert not (home / "state-snapshots" / "telegram-approval-snoozes.json").exists()

    @pytest.mark.asyncio
    async def test_change_button_asks_for_comment_then_submits_decision_notes(self, tmp_path):
        adapter = _make_adapter()
        home = tmp_path / "home"
        content = f"/gladly_change {_gladly_token('approval-change', 'changes_requested')}"

        with patch("hermes_constants.get_hermes_home", return_value=home):
            adapter._extract_gladly_approval_buttons(content)
            state = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())
            button_id, entry = next(iter(state["buttons"].items()))

        query = AsyncMock()
        query.data = f"ga:{button_id}"
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.message.message_id = 99
        query.message.chat.type = "private"
        query.message.text = "\n".join([
            "Förslag: Godkänn lösning",
            "Välj ett alternativ med knapparna nedan.",
        ])
        query.message.reply_markup = "existing-buttons"
        query.from_user = MagicMock()
        query.from_user.id = "12345"
        query.from_user.first_name = "Olle"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        with patch("hermes_constants.get_hermes_home", return_value=home):
            with patch("asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
                await adapter._handle_gladly_approval_callback(
                    query,
                    f"ga:{button_id}",
                    chat_id=12345,
                    chat_type="private",
                    thread_id=None,
                    user_name="Olle",
                )

        spawn.assert_not_called()
        query.answer.assert_awaited_once()
        assert "Skriv kommentaren" in query.answer.await_args.kwargs["text"]
        assert "Skriv kort vad du vill ändra" in query.edit_message_text.await_args.kwargs["text"]
        assert query.edit_message_text.await_args.kwargs["reply_markup"] is None
        pending = json.loads((home / "state-snapshots" / "telegram-approval-comments.json").read_text())
        assert pending["comments"]["12345::12345"]["token"] == entry["token"]

        message = MagicMock()
        message.text = "Justera källorna innan publicering."
        message.chat_id = 12345
        message.chat = MagicMock()
        message.chat.id = 12345
        message.message_thread_id = None
        message.from_user = MagicMock()
        message.from_user.id = "12345"
        message.from_user.first_name = "Olle"

        proc = MagicMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"Beslutet sparades.", b""))

        with patch("hermes_constants.get_hermes_home", return_value=home):
            with patch("tools.environments.local._sanitize_subprocess_env", return_value={}):
                with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)) as spawn:
                    handled = await adapter._handle_gladly_approval_comment_message(message)

        assert handled is True
        spawn.assert_awaited_once()
        kwargs = spawn.await_args.kwargs
        assert kwargs["env"]["HERMES_QUICK_COMMAND_ARGS"] == entry["token"]
        assert kwargs["env"]["HERMES_QUICK_DECISION_NOTES"] == "Justera källorna innan publicering."
        adapter._bot.edit_message_text.assert_awaited_once()
        edit_kwargs = adapter._bot.edit_message_text.await_args.kwargs
        assert edit_kwargs["reply_markup"] is None
        assert "Beslut: Ändring begärd av Olle" in edit_kwargs["text"]
        assert "Kommentar: Justera källorna innan publicering." in edit_kwargs["text"]

        remaining_comments = json.loads((home / "state-snapshots" / "telegram-approval-comments.json").read_text())
        assert remaining_comments["comments"] == {}
        remaining_buttons = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())
        assert remaining_buttons["buttons"] == {}

    @pytest.mark.asyncio
    async def test_final_decision_clears_pending_change_comment(self, tmp_path):
        adapter = _make_adapter()
        home = tmp_path / "home"
        content = "\n".join([
            f"/gladly_approve {_gladly_token('approval-clear-comment', 'approved')}",
            f"/gladly_change {_gladly_token('approval-clear-comment', 'changes_requested')}",
            f"/gladly_stop {_gladly_token('approval-clear-comment', 'rejected')}",
        ])

        with patch("hermes_constants.get_hermes_home", return_value=home):
            adapter._extract_gladly_approval_buttons(content)
            state = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())
            change_id = next(item_id for item_id, item in state["buttons"].items() if item["decision"] == "changes_requested")
            approve_id = next(item_id for item_id, item in state["buttons"].items() if item["decision"] == "approved")

        query = AsyncMock()
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.message.message_id = 99
        query.message.chat.type = "private"
        query.message.text = "Förslag: Godkänn lösning"
        query.message.reply_markup = "existing-buttons"
        query.from_user = MagicMock()
        query.from_user.id = "12345"
        query.from_user.first_name = "Olle"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        with patch("hermes_constants.get_hermes_home", return_value=home):
            await adapter._handle_gladly_approval_callback(
                query,
                f"ga:{change_id}",
                chat_id=12345,
                chat_type="private",
                thread_id=None,
                user_name="Olle",
            )
            pending = json.loads((home / "state-snapshots" / "telegram-approval-comments.json").read_text())
            assert pending["comments"]

        proc = MagicMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"Beslutet sparades.", b""))
        query.edit_message_text = AsyncMock()

        with patch("hermes_constants.get_hermes_home", return_value=home):
            with patch("tools.environments.local._sanitize_subprocess_env", return_value={}):
                with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)):
                    await adapter._handle_gladly_approval_callback(
                        query,
                        f"ga:{approve_id}",
                        chat_id=12345,
                        chat_type="private",
                        thread_id=None,
                        user_name="Olle",
                    )

        comments = json.loads((home / "state-snapshots" / "telegram-approval-comments.json").read_text())
        assert comments["comments"] == {}

    @pytest.mark.asyncio
    async def test_successful_decision_sends_receipt_when_edit_fails(self, tmp_path):
        adapter = _make_adapter()
        home = tmp_path / "home"
        content = f"/gladly_approve {_gladly_token('approval-edit-fails', 'approved')}"

        with patch("hermes_constants.get_hermes_home", return_value=home):
            adapter._extract_gladly_approval_buttons(content)
            state = json.loads((home / "state-snapshots" / "telegram-approval-buttons.json").read_text())
            button_id = next(iter(state["buttons"].keys()))

        query = AsyncMock()
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.message.chat.type = "private"
        query.message.text = "Förslag: Godkänn lösning"
        query.from_user = MagicMock()
        query.from_user.id = "12345"
        query.from_user.first_name = "Olle"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock(side_effect=RuntimeError("Telegram edit failed"))

        proc = MagicMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"Beslutet sparades.", b""))

        with patch("hermes_constants.get_hermes_home", return_value=home):
            with patch("tools.environments.local._sanitize_subprocess_env", return_value={}):
                with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)):
                    await adapter._handle_gladly_approval_callback(
                        query,
                        f"ga:{button_id}",
                        chat_id=12345,
                        chat_type="private",
                        thread_id=None,
                        user_name="Olle",
                    )

        adapter._bot.send_message.assert_awaited_once()
        assert "Beslut: Godkänt av Olle" in adapter._bot.send_message.await_args.kwargs["text"]

    def test_portal_failure_alerts_are_specific(self):
        adapter = _make_adapter()

        assert (
            adapter._gladly_approval_failure_message(
                "[gladly-telegram-approval] Portal bridge svarade 403. status=403"
            )
            == "Portalen nekade beslutstoken. Skicka en ny approval-notis."
        )
        assert (
            adapter._gladly_approval_failure_message(
                "[gladly-telegram-approval] Godkännande saknas. status=404"
            )
            == "Godkännandet finns inte längre i Portalen."
        )
        assert (
            adapter._gladly_approval_failure_message(
                "[gladly-telegram-approval] Approval redan beslutat. status=409"
            )
            == "Godkännandet är redan beslutat i Portalen."
        )


# ===========================================================================
# send_exec_approval — inline keyboard buttons
# ===========================================================================

class TestTelegramExecApproval:
    """Test the send_exec_approval method sends InlineKeyboard buttons."""

    @pytest.mark.asyncio
    async def test_sends_inline_keyboard(self):
        adapter = _make_adapter()
        mock_msg = MagicMock()
        mock_msg.message_id = 42
        adapter._bot.send_message = AsyncMock(return_value=mock_msg)

        result = await adapter.send_exec_approval(
            chat_id="12345",
            command="rm -rf /important",
            session_key="agent:main:telegram:group:12345:99",
            description="dangerous deletion",
        )

        assert result.success is True
        assert result.message_id == "42"

        adapter._bot.send_message.assert_called_once()
        kwargs = adapter._bot.send_message.call_args[1]
        assert kwargs["chat_id"] == 12345
        assert "rm -rf /important" in kwargs["text"]
        assert "dangerous deletion" in kwargs["text"]
        assert kwargs["reply_markup"] is not None  # InlineKeyboardMarkup

    @pytest.mark.asyncio
    async def test_smart_deny_owner_override_only_offers_once_and_deny(self, monkeypatch):
        adapter = _make_adapter()
        adapter._bot.send_message = AsyncMock(return_value=SimpleNamespace(message_id=42))
        buttons = []
        monkeypatch.setattr(
            "plugins.platforms.telegram.adapter.InlineKeyboardButton",
            lambda text, callback_data: buttons.append((text, callback_data)) or (text, callback_data),
        )
        monkeypatch.setattr(
            "plugins.platforms.telegram.adapter.InlineKeyboardMarkup", lambda rows: rows
        )

        await adapter.send_exec_approval(
            chat_id="12345", command="rm -rf /", session_key="s",
            allow_permanent=False, smart_denied=True,
        )

        labels = [label for label, _ in buttons]
        assert labels == ["✅ Allow Once", "❌ Deny"]
        text = adapter._bot.send_message.call_args.kwargs["text"]
        assert "one operation" in text.lower()

    @pytest.mark.asyncio
    async def test_non_smart_allow_permanent_false_keeps_session(self, monkeypatch):
        adapter = _make_adapter()
        adapter._bot.send_message = AsyncMock(return_value=SimpleNamespace(message_id=42))
        buttons = []
        monkeypatch.setattr(
            "plugins.platforms.telegram.adapter.InlineKeyboardButton",
            lambda text, callback_data: buttons.append(text) or text,
        )
        monkeypatch.setattr(
            "plugins.platforms.telegram.adapter.InlineKeyboardMarkup", lambda rows: rows
        )

        await adapter.send_exec_approval(
            chat_id="12345", command="curl example.test", session_key="s",
            allow_permanent=False,
        )

        assert buttons == ["✅ Allow Once", "✅ Session", "❌ Deny"]

    @pytest.mark.asyncio
    async def test_stores_approval_state(self):
        adapter = _make_adapter()
        mock_msg = MagicMock()
        mock_msg.message_id = 42
        adapter._bot.send_message = AsyncMock(return_value=mock_msg)

        await adapter.send_exec_approval(
            chat_id="12345",
            command="echo test",
            session_key="my-session-key",
        )

        # The approval_id should map to the session_key
        assert len(adapter._approval_state) == 1
        approval_id = list(adapter._approval_state.keys())[0]
        assert adapter._approval_state[approval_id] == "my-session-key"

    @pytest.mark.asyncio
    async def test_sends_in_thread(self):
        adapter = _make_adapter()
        mock_msg = MagicMock()
        mock_msg.message_id = 42
        adapter._bot.send_message = AsyncMock(return_value=mock_msg)

        await adapter.send_exec_approval(
            chat_id="12345",
            command="ls",
            session_key="s",
            metadata={"thread_id": "999"},
        )

        kwargs = adapter._bot.send_message.call_args[1]
        assert kwargs.get("message_thread_id") == 999

    @pytest.mark.asyncio
    async def test_retries_without_thread_when_thread_not_found(self):
        adapter = _make_adapter()
        call_log = []

        class FakeBadRequest(Exception):
            pass

        async def mock_send_message(**kwargs):
            call_log.append(dict(kwargs))
            if kwargs.get("message_thread_id") is not None:
                raise FakeBadRequest("Message thread not found")
            return SimpleNamespace(message_id=42)

        adapter._bot.send_message = AsyncMock(side_effect=mock_send_message)

        result = await adapter.send_exec_approval(
            chat_id="12345",
            command="ls",
            session_key="s",
            metadata={"thread_id": "999"},
        )

        assert result.success is True
        assert len(call_log) == 2
        assert call_log[0]["message_thread_id"] == 999
        assert "message_thread_id" not in call_log[1] or call_log[1]["message_thread_id"] is None

    @pytest.mark.asyncio
    async def test_not_connected(self):
        adapter = _make_adapter()
        adapter._bot = None
        result = await adapter.send_exec_approval(
            chat_id="12345", command="ls", session_key="s"
        )
        assert result.success is False

    @pytest.mark.asyncio
    async def test_disable_link_previews_sets_preview_kwargs(self):
        adapter = _make_adapter(extra={"disable_link_previews": True})
        mock_msg = MagicMock()
        mock_msg.message_id = 42
        adapter._bot.send_message = AsyncMock(return_value=mock_msg)

        await adapter.send_exec_approval(
            chat_id="12345", command="ls", session_key="s"
        )

        kwargs = adapter._bot.send_message.call_args[1]
        assert (
            kwargs.get("disable_web_page_preview") is True
            or kwargs.get("link_preview_options") is not None
        )

    @pytest.mark.asyncio
    async def test_send_update_prompt_escapes_dynamic_prompt(self):
        adapter = _make_adapter()
        sent = {}

        async def mock_send_message(**kwargs):
            sent.update(kwargs)
            return SimpleNamespace(message_id=55)

        adapter._bot.send_message = AsyncMock(side_effect=mock_send_message)

        result = await adapter.send_update_prompt(
            chat_id="12345",
            prompt="Fix [issue]_1 and verify *markdown*",
            default="alpha_beta",
            metadata={"thread_id": "999"},
        )

        assert result.success is True
        assert "MARKDOWN_V2" in repr(sent["parse_mode"])
        assert "Fix \\[issue\\]\\_1" in sent["text"]
        assert "alpha\\_beta" in sent["text"]

    @pytest.mark.asyncio
    async def test_truncates_long_command(self):
        adapter = _make_adapter()
        mock_msg = MagicMock()
        mock_msg.message_id = 1
        adapter._bot.send_message = AsyncMock(return_value=mock_msg)

        long_cmd = "x" * 5000
        await adapter.send_exec_approval(
            chat_id="12345", command=long_cmd, session_key="s"
        )

        kwargs = adapter._bot.send_message.call_args[1]
        assert "..." in kwargs["text"]
        assert len(kwargs["text"]) < 5000
# _handle_callback_query — approval button clicks
# ===========================================================================

class TestTelegramApprovalCallback:
    """Test the approval callback handling in _handle_callback_query."""

    @pytest.mark.asyncio
    async def test_resolves_approval_on_click(self):
        adapter = _make_adapter()
        # Set up approval state
        adapter._approval_state[1] = "agent:main:telegram:group:12345:99"

        # Mock callback query
        query = AsyncMock()
        query.data = "ea:once:1"
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.from_user = MagicMock()
        query.from_user.first_name = "Norbert"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        update = MagicMock()
        update.callback_query = query
        context = MagicMock()
        query.from_user.id = "12345"

        with patch.dict(os.environ, {"TELEGRAM_ALLOWED_USERS": "*"}, clear=False):
            with patch("tools.approval.resolve_gateway_approval", return_value=1) as mock_resolve:
                await adapter._handle_callback_query(update, context)

        mock_resolve.assert_called_once_with("agent:main:telegram:group:12345:99", "once")
        query.answer.assert_called_once()
        query.edit_message_text.assert_called_once()

        # State should be cleaned up
        assert 1 not in adapter._approval_state

    @pytest.mark.asyncio
    async def test_resume_typing_after_inline_approval(self):
        """Clicking an inline approval button must un-pause the chat's typing.

        Regression for #27853: the text /approve path resumed typing, but the
        ea: callback path did not, so the typing indicator stayed gone for the
        rest of a long-running turn after a button click.
        """
        adapter = _make_adapter()
        adapter._approval_state[5] = "agent:main:telegram:group:12345:99"
        adapter.pause_typing_for_chat("12345")
        assert "12345" in adapter._typing_paused

        query = AsyncMock()
        query.data = "ea:once:5"
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.from_user = MagicMock()
        query.from_user.first_name = "Norbert"
        query.from_user.id = "12345"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        update = MagicMock()
        update.callback_query = query
        context = MagicMock()

        with patch.dict(os.environ, {"TELEGRAM_ALLOWED_USERS": "*"}, clear=False):
            with patch("tools.approval.resolve_gateway_approval", return_value=1):
                await adapter._handle_callback_query(update, context)

        assert "12345" not in adapter._typing_paused

    @pytest.mark.asyncio
    async def test_typing_stays_paused_when_resolve_returns_zero(self):
        """If resolve_gateway_approval reports 0 resolves, the agent thread
        was never unblocked, so typing should NOT be force-resumed."""
        adapter = _make_adapter()
        adapter._approval_state[6] = "agent:main:telegram:group:12345:99"
        adapter.pause_typing_for_chat("12345")

        query = AsyncMock()
        query.data = "ea:once:6"
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.from_user = MagicMock()
        query.from_user.first_name = "Norbert"
        query.from_user.id = "12345"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        update = MagicMock()
        update.callback_query = query
        context = MagicMock()

        with patch.dict(os.environ, {"TELEGRAM_ALLOWED_USERS": "*"}, clear=False):
            with patch("tools.approval.resolve_gateway_approval", return_value=0):
                await adapter._handle_callback_query(update, context)

        assert "12345" in adapter._typing_paused

    @pytest.mark.asyncio
    async def test_approval_callback_escapes_dynamic_user_name(self):
        adapter = _make_adapter()
        adapter._approval_state[3] = "agent:main:telegram:group:12345:99"

        query = AsyncMock()
        query.data = "ea:once:3"
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.from_user = MagicMock()
        query.from_user.first_name = "Alice_Bob"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        update = MagicMock()
        update.callback_query = query
        context = MagicMock()
        query.from_user.id = "12345"

        with patch.dict(os.environ, {"TELEGRAM_ALLOWED_USERS": "*"}, clear=False):
            with patch("tools.approval.resolve_gateway_approval", return_value=1):
                await adapter._handle_callback_query(update, context)

        edit_kwargs = query.edit_message_text.call_args[1]
        assert "MARKDOWN_V2" in repr(edit_kwargs["parse_mode"])
        assert "Alice\\_Bob" in edit_kwargs["text"]
        assert "Approved once" in edit_kwargs["text"]

    @pytest.mark.asyncio
    async def test_deny_button(self):
        adapter = _make_adapter()
        adapter._approval_state[2] = "some-session"

        query = AsyncMock()
        query.data = "ea:deny:2"
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.from_user = MagicMock()
        query.from_user.first_name = "Alice"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        update = MagicMock()
        update.callback_query = query
        context = MagicMock()
        query.from_user.id = "12345"

        with patch.dict(os.environ, {"TELEGRAM_ALLOWED_USERS": "*"}, clear=False):
            with patch("tools.approval.resolve_gateway_approval", return_value=1) as mock_resolve:
                await adapter._handle_callback_query(update, context)

        mock_resolve.assert_called_once_with("some-session", "deny")
        edit_kwargs = query.edit_message_text.call_args[1]
        assert "Denied" in edit_kwargs["text"]

    @pytest.mark.asyncio
    async def test_approval_callback_rejects_user_blocked_by_global_allowlist(self):
        adapter = _make_adapter()
        adapter._approval_state[7] = "agent:main:telegram:group:12345:99"
        runner = _AuthRunner(authorized=False)
        adapter._message_handler = runner._handle_message

        query = AsyncMock()
        query.data = "ea:once:7"
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.message.chat.type = "private"
        query.from_user = MagicMock()
        query.from_user.id = 222
        query.from_user.first_name = "Mallory"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        update = MagicMock()
        update.callback_query = query
        context = MagicMock()

        with patch("tools.approval.resolve_gateway_approval") as mock_resolve:
            await adapter._handle_callback_query(update, context)

        mock_resolve.assert_not_called()
        query.answer.assert_called_once()
        assert "not authorized" in query.answer.call_args[1]["text"].lower()
        query.edit_message_text.assert_not_called()
        assert adapter._approval_state[7] == "agent:main:telegram:group:12345:99"
        assert runner.last_source is not None
        assert runner.last_source.platform == Platform.TELEGRAM
        assert runner.last_source.user_id == "222"
        assert runner.last_source.chat_id == "12345"

    @pytest.mark.asyncio
    async def test_already_resolved(self):
        adapter = _make_adapter()
        # No state for approval_id 99 — already resolved

        query = AsyncMock()
        query.data = "ea:once:99"
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.from_user = MagicMock()
        query.from_user.first_name = "Bob"
        query.answer = AsyncMock()

        update = MagicMock()
        update.callback_query = query
        context = MagicMock()
        query.from_user.id = "12345"

        with patch.dict(os.environ, {"TELEGRAM_ALLOWED_USERS": "*"}, clear=False):
            with patch("tools.approval.resolve_gateway_approval") as mock_resolve:
                await adapter._handle_callback_query(update, context)

        # Should NOT resolve — already handled
        mock_resolve.assert_not_called()
        # Should still ack with "already resolved" message
        query.answer.assert_called_once()
        assert "already been resolved" in query.answer.call_args[1]["text"]

    @pytest.mark.asyncio
    async def test_model_picker_callback_not_affected(self):
        """Ensure model picker callbacks still route correctly."""
        adapter = _make_adapter()

        query = AsyncMock()
        query.data = "mp:some_provider"
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.from_user = MagicMock()

        update = MagicMock()
        update.callback_query = query
        context = MagicMock()

        # Model picker callback should be handled (not crash)
        # We just verify it doesn't try to resolve an approval
        with patch("tools.approval.resolve_gateway_approval") as mock_resolve:
            with patch.object(adapter, "_handle_model_picker_callback", new_callable=AsyncMock):
                await adapter._handle_callback_query(update, context)

        mock_resolve.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_prompt_callback_not_affected(self, tmp_path):
        """Ensure update prompt callbacks still work."""
        adapter = _make_adapter()

        query = AsyncMock()
        query.data = "update_prompt:y"
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.from_user = MagicMock()
        query.from_user.id = 123
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        update = MagicMock()
        update.callback_query = query
        context = MagicMock()

        with patch("tools.approval.resolve_gateway_approval") as mock_resolve:
            with patch("hermes_constants.get_hermes_home", return_value=tmp_path):
                # Allow the caller — the new fail-closed allowlist gate
                # (#24457) rejects empty TELEGRAM_ALLOWED_USERS, but this
                # test isn't exercising that gate; it's verifying the
                # update_prompt callback still writes the response.
                with patch.dict(os.environ, {"TELEGRAM_ALLOWED_USERS": "*"}):
                    await adapter._handle_callback_query(update, context)

        # Should NOT have triggered approval resolution
        mock_resolve.assert_not_called()
        assert (tmp_path / ".update_response").read_text() == "y"

    @pytest.mark.asyncio
    async def test_update_prompt_callback_rejects_unauthorized_user(self, tmp_path):
        """Update prompt buttons should honor TELEGRAM_ALLOWED_USERS."""
        adapter = _make_adapter()

        query = AsyncMock()
        query.data = "update_prompt:y"
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.from_user = MagicMock()
        query.from_user.id = 222
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        update = MagicMock()
        update.callback_query = query
        context = MagicMock()

        with patch("hermes_constants.get_hermes_home", return_value=tmp_path):
            with patch.dict(os.environ, {"TELEGRAM_ALLOWED_USERS": "111"}):
                await adapter._handle_callback_query(update, context)

        query.answer.assert_called_once()
        assert "not authorized" in query.answer.call_args[1]["text"].lower()
        query.edit_message_text.assert_not_called()
        assert not (tmp_path / ".update_response").exists()

    @pytest.mark.asyncio
    async def test_update_prompt_callback_rejects_user_blocked_by_global_allowlist(self, tmp_path):
        adapter = _make_adapter()
        runner = _AuthRunner(authorized=False)
        adapter._message_handler = runner._handle_message

        query = AsyncMock()
        query.data = "update_prompt:y"
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.message.chat.type = "private"
        query.from_user = MagicMock()
        query.from_user.id = 222
        query.from_user.first_name = "Mallory"
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        update = MagicMock()
        update.callback_query = query
        context = MagicMock()

        with patch("hermes_constants.get_hermes_home", return_value=tmp_path):
            with patch.dict(os.environ, {"TELEGRAM_ALLOWED_USERS": ""}):
                await adapter._handle_callback_query(update, context)

        query.answer.assert_called_once()
        assert "not authorized" in query.answer.call_args[1]["text"].lower()
        query.edit_message_text.assert_not_called()
        assert not (tmp_path / ".update_response").exists()
        assert runner.last_source is not None
        assert runner.last_source.platform == Platform.TELEGRAM
        assert runner.last_source.user_id == "222"

    @pytest.mark.asyncio
    async def test_update_prompt_callback_allows_authorized_user(self, tmp_path):
        """Allowed Telegram users can still answer update prompt buttons."""
        adapter = _make_adapter()

        query = AsyncMock()
        query.data = "update_prompt:n"
        query.message = MagicMock()
        query.message.chat_id = 12345
        query.from_user = MagicMock()
        query.from_user.id = 111
        query.answer = AsyncMock()
        query.edit_message_text = AsyncMock()

        update = MagicMock()
        update.callback_query = query
        context = MagicMock()

        with patch("hermes_constants.get_hermes_home", return_value=tmp_path):
            with patch.dict(os.environ, {"TELEGRAM_ALLOWED_USERS": "111"}):
                await adapter._handle_callback_query(update, context)

        query.answer.assert_called_once()
        query.edit_message_text.assert_called_once()
        assert (tmp_path / ".update_response").read_text() == "n"
