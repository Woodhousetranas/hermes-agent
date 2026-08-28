"""Gladly Portal Telegram approval buttons (Hermes adapter mixin).

Restored onto gladly-desktop-staging after upstream merges dropped the Gladly
inline-keyboard + callback path. Keeps Portal approvals button-driven while
signed /gladly_* text commands remain the fallback.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path as _Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

from hermes_constants import get_hermes_home
from utils import atomic_replace

try:
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
except Exception:  # pragma: no cover - import-time telegram mock in tests
    InlineKeyboardButton = object  # type: ignore
    InlineKeyboardMarkup = object  # type: ignore

_GLADLY_APPROVAL_COMMAND_RE = re.compile(
    r"^/(gladly_approve|gladly_change|gladly_stop)\s+(hta\.v1\.[^\s]+)\s*$"
)
_GLADLY_APPROVAL_PORTAL_URL_RE = re.compile(r"^Portal:\s+(https?://\S+)\s*$", re.IGNORECASE)
_GLADLY_APPROVAL_LABEL_LINES = {
    "Godkänn:",
    "Begär ändring:",
    "Stoppa:",
    "Kopiera ett helt kommando:",
}
_GLADLY_APPROVAL_DECISIONS = {
    "gladly_approve": ("approved", "Godkänn", "Godkänt i Portalen."),
    "gladly_change": ("changes_requested", "Begär ändring", "Ändring begärd i Portalen."),
    "gladly_stop": ("rejected", "Stoppa", "Stoppat i Portalen."),
}
_GLADLY_APPROVAL_SNOOZE_PRESETS = {
    "30m": ("30 min", 30 * 60),
    "2h": ("2 timmar", 2 * 60 * 60),
    "tomorrow": ("imorgon", None),
}


class GladlyTelegramApprovalsMixin:
    def _gladly_approval_state_path(self) -> _Path:
        from hermes_constants import get_hermes_home

        return get_hermes_home() / "state-snapshots" / "telegram-approval-buttons.json"

    def _gladly_approval_snooze_state_path(self) -> _Path:
        from hermes_constants import get_hermes_home

        return get_hermes_home() / "state-snapshots" / "telegram-approval-snoozes.json"

    def _gladly_approval_comment_state_path(self) -> _Path:
        from hermes_constants import get_hermes_home

        return get_hermes_home() / "state-snapshots" / "telegram-approval-comments.json"

    @staticmethod
    def _gladly_approval_payload_from_token(token: str) -> Dict[str, Any]:
        parts = token.strip().split(".")
        if len(parts) != 4 or ".".join(parts[:2]) != "hta.v1":
            raise ValueError("invalid Gladly approval token")

        encoded = parts[2]
        if encoded.startswith("h"):
            raw = bytes.fromhex(encoded[1:]).decode("utf-8")
        else:
            if encoded.startswith("p"):
                encoded = encoded[1:]
            padded = encoded + ("=" * (-len(encoded) % 4))
            raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        payload = json.loads(raw)
        return payload if isinstance(payload, dict) else {}

    @classmethod
    def _gladly_approval_verified_payload_from_token(cls, token: str) -> Dict[str, Any]:
        parts = token.strip().split(".")
        if len(parts) != 4 or ".".join(parts[:2]) != "hta.v1":
            raise ValueError("invalid Gladly approval token")

        secret = (
            os.getenv("HERMES_TELEGRAM_APPROVAL_SECRET", "").strip()
            or os.getenv("GLADLY_TELEGRAM_APPROVAL_SECRET", "").strip()
        )
        if not secret:
            raise ValueError("missing Gladly approval token secret")

        signed_part = ".".join(parts[:3])
        expected = hmac.new(secret.encode("utf-8"), signed_part.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(parts[3] or "", expected):
            raise ValueError("invalid Gladly approval token signature")

        payload = cls._gladly_approval_payload_from_token(token)
        expires_at = cls._gladly_approval_epoch(payload.get("exp"))
        if expires_at is None:
            raise ValueError("invalid Gladly approval token expiry")
        if expires_at <= time.time():
            raise ValueError("expired Gladly approval token")
        return payload

    @staticmethod
    def _gladly_approval_epoch(value: Any) -> Optional[float]:
        if not value:
            return None
        try:
            text = str(value).strip()
            if text.endswith("Z"):
                text = f"{text[:-1]}+00:00"
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _gladly_approval_portal_url(content: str) -> Optional[str]:
        for line in content.splitlines():
            match = _GLADLY_APPROVAL_PORTAL_URL_RE.match(line.strip())
            if match:
                return match.group(1)
        return None

    @staticmethod
    def _gladly_approval_comment_key(
        *,
        chat_id: Optional[Any],
        thread_id: Optional[Any],
        user_id: Optional[Any],
    ) -> str:
        return ":".join([
            str(chat_id or ""),
            str(thread_id or ""),
            str(user_id or ""),
        ])

    @staticmethod
    def _load_gladly_json_state(path: _Path, key: str) -> Dict[str, Dict[str, Any]]:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except Exception as exc:
            logger.warning("[Telegram] Failed to read Gladly approval state %s: %s", path, exc)
            return {}
        if not isinstance(raw, dict):
            return {}
        state = raw.get(key, raw)
        if not isinstance(state, dict):
            return {}
        return {
            str(item_id): item
            for item_id, item in state.items()
            if isinstance(item, dict)
        }

    @staticmethod
    def _save_gladly_json_state(path: _Path, key: str, state: Dict[str, Dict[str, Any]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(path.parent),
            suffix=".tmp",
            prefix=f".{key}_",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({key: state}, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            atomic_replace(tmp_path, path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    @staticmethod
    def _gladly_approval_snooze_until(preset: str) -> tuple[str, str]:
        label, seconds = _GLADLY_APPROVAL_SNOOZE_PRESETS.get(
            preset,
            _GLADLY_APPROVAL_SNOOZE_PRESETS["30m"],
        )
        now = datetime.now().astimezone()
        if seconds is None:
            target = (now + timedelta(days=1)).replace(hour=9, minute=0, second=0, microsecond=0)
        else:
            target = now + timedelta(seconds=seconds)
        return label, target.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def _load_gladly_approval_buttons(self) -> Dict[str, Dict[str, Any]]:
        path = self._gladly_approval_state_path()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except Exception as exc:
            logger.warning("[%s] Failed to read Gladly approval button state: %s", self.name, exc)
            return {}
        if not isinstance(raw, dict):
            return {}
        state = raw.get("buttons", raw)
        if not isinstance(state, dict):
            return {}
        return {
            str(button_id): entry
            for button_id, entry in state.items()
            if isinstance(entry, dict)
        }

    def _save_gladly_approval_buttons(self, state: Dict[str, Dict[str, Any]]) -> None:
        path = self._gladly_approval_state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(path.parent),
            suffix=".tmp",
            prefix=".telegram_approval_buttons_",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"buttons": state}, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            atomic_replace(tmp_path, path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _purge_expired_gladly_approval_buttons(
        self,
        state: Dict[str, Dict[str, Any]],
        *,
        now: Optional[float] = None,
    ) -> bool:
        current = now if now is not None else time.time()
        expired = [
            button_id
            for button_id, entry in state.items()
            if self._gladly_approval_epoch(entry.get("expires_at")) is not None
            and self._gladly_approval_epoch(entry.get("expires_at")) <= current
        ]
        for button_id in expired:
            state.pop(button_id, None)
        return bool(expired)

    def _register_gladly_approval_button(
        self,
        command_name: str,
        token: str,
        *,
        portal_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        decision, label, success_text = _GLADLY_APPROVAL_DECISIONS[command_name]
        payload = self._gladly_approval_payload_from_token(token)
        state = self._load_gladly_approval_buttons()
        self._purge_expired_gladly_approval_buttons(state)

        for _ in range(10):
            button_id = secrets.token_urlsafe(8)
            if button_id not in state:
                break
        else:
            raise RuntimeError("could not allocate Gladly approval callback id")

        entry = {
            "id": button_id,
            "token": token,
            "decision": decision,
            "label": label,
            "success_text": success_text,
            "approval_id": str(payload.get("a") or ""),
            "expires_at": str(payload.get("exp") or ""),
            "created_at": time.time(),
        }
        if portal_url:
            entry["portal_url"] = portal_url
        state[button_id] = entry
        self._gladly_approval_buttons = state
        self._save_gladly_approval_buttons(state)
        return entry

    @staticmethod
    def _compact_blank_lines(lines: List[str]) -> List[str]:
        compacted: List[str] = []
        for line in lines:
            if not line.strip() and (not compacted or not compacted[-1].strip()):
                continue
            compacted.append(line)
        while compacted and not compacted[-1].strip():
            compacted.pop()
        return compacted

    def _extract_gladly_approval_buttons(
        self,
        content: str,
    ) -> tuple[str, Optional["InlineKeyboardMarkup"]]:
        matches = [
            _GLADLY_APPROVAL_COMMAND_RE.match(line.strip())
            for line in content.splitlines()
        ]
        command_matches = [match for match in matches if match]
        if not command_matches:
            return content, None

        entries: List[Dict[str, Any]] = []
        seen_decisions: set[str] = set()
        portal_url = self._gladly_approval_portal_url(content)
        for match in command_matches:
            command_name, token = match.group(1), match.group(2)
            decision = _GLADLY_APPROVAL_DECISIONS[command_name][0]
            if decision in seen_decisions:
                continue
            try:
                self._gladly_approval_verified_payload_from_token(token)
                entries.append(self._register_gladly_approval_button(command_name, token, portal_url=portal_url))
            except Exception as exc:
                logger.warning("[%s] Ignoring invalid Gladly approval command token: %s", self.name, exc)
                continue
            seen_decisions.add(decision)

        if not entries:
            # Never expose a signed Portal command as ordinary chat text. If
            # validation fails, strip the command and its button-only labels
            # instead of leaking an unusable (or tampered) approval token.
            cleaned = self._compact_blank_lines(
                [
                    line
                    for line in content.splitlines()
                    if not _GLADLY_APPROVAL_COMMAND_RE.match(line.strip())
                    and line.strip() not in _GLADLY_APPROVAL_LABEL_LINES
                ]
            )
            cleaned.append(
                "Knappar kunde inte skapas säkert. Öppna godkännandet i Portalen."
            )
            return "\n".join(cleaned), None

        cleaned_lines: List[str] = []
        for line in content.splitlines():
            stripped = line.strip()
            if _GLADLY_APPROVAL_COMMAND_RE.match(stripped):
                continue
            if stripped in _GLADLY_APPROVAL_LABEL_LINES:
                continue
            cleaned_lines.append(line)

        cleaned_lines = self._compact_blank_lines(cleaned_lines)
        hint = "Välj ett alternativ med knapparna nedan."
        if hint not in "\n".join(cleaned_lines):
            guard_index = next(
                (
                    index
                    for index, line in enumerate(cleaned_lines)
                    if "Ingen kundkontakt" in line
                ),
                len(cleaned_lines),
            )
            cleaned_lines.insert(guard_index, hint)

        by_decision = {str(entry.get("decision")): entry for entry in entries}
        decision_buttons = [
            InlineKeyboardButton(
                str(entry["label"]),
                callback_data=f"ga:{entry['id']}",
            )
            for entry in entries
        ]
        rows = [
            decision_buttons[:2],
            decision_buttons[2:],
        ]
        snooze_entry = by_decision.get("approved") or (entries[0] if entries else None)
        if snooze_entry:
            rows.append([
                InlineKeyboardButton(
                    "30 min",
                    callback_data=f"gw:{snooze_entry['id']}:30m",
                ),
                InlineKeyboardButton(
                    "2 h",
                    callback_data=f"gw:{snooze_entry['id']}:2h",
                ),
                InlineKeyboardButton(
                    "Imorgon",
                    callback_data=f"gw:{snooze_entry['id']}:tomorrow",
                ),
            ])
        keyboard = InlineKeyboardMarkup([row for row in rows if row])
        return "\n".join(cleaned_lines), keyboard

    def _get_gladly_approval_button(self, button_id: str) -> Optional[Dict[str, Any]]:
        state = self._load_gladly_approval_buttons()
        changed = self._purge_expired_gladly_approval_buttons(state)
        entry = state.get(button_id)
        if changed:
            self._save_gladly_approval_buttons(state)
        self._gladly_approval_buttons = state
        return entry

    def _remove_gladly_approval_buttons(
        self,
        *,
        button_id: str,
        approval_id: Optional[str],
    ) -> None:
        state = self._load_gladly_approval_buttons()
        for key, entry in list(state.items()):
            if key == button_id or (approval_id and entry.get("approval_id") == approval_id):
                state.pop(key, None)
        self._gladly_approval_buttons = state
        self._save_gladly_approval_buttons(state)

    def _remove_gladly_approval_buttons_for_approval_ids(self, approval_ids: set[str]) -> None:
        if not approval_ids:
            return
        state = self._load_gladly_approval_buttons()
        for key, entry in list(state.items()):
            if str(entry.get("approval_id") or "") in approval_ids:
                state.pop(key, None)
        self._gladly_approval_buttons = state
        self._save_gladly_approval_buttons(state)

    def _mark_gladly_approval_waiting(
        self,
        *,
        button_id: str,
        approval_id: Optional[str],
        user_name: Optional[str],
        preset: str = "30m",
        snoozed_until: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        state = self._load_gladly_approval_buttons()
        entry = state.get(button_id)
        if not entry:
            return None
        marker = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        label, computed_snoozed_until = self._gladly_approval_snooze_until(preset)
        snoozed_until = snoozed_until or computed_snoozed_until
        for current in state.values():
            if current is entry or (approval_id and current.get("approval_id") == approval_id):
                current["deferred_at"] = marker
                current["snooze_preset"] = preset
                current["snoozed_until"] = snoozed_until
                if user_name:
                    current["deferred_by"] = user_name
        self._gladly_approval_buttons = state
        self._save_gladly_approval_buttons(state)

        if approval_id:
            snoozes = self._load_gladly_json_state(self._gladly_approval_snooze_state_path(), "snoozes")
            snoozes[approval_id] = {
                "approval_id": approval_id,
                "preset": preset,
                "label": label,
                "snoozed_until": snoozed_until,
                "deferred_at": marker,
                "deferred_by": user_name or "",
                "portal_url": str(entry.get("portal_url") or ""),
            }
            self._save_gladly_json_state(self._gladly_approval_snooze_state_path(), "snoozes", snoozes)
        return entry

    def _load_gladly_approval_comment_state(self) -> Dict[str, Dict[str, Any]]:
        state = self._load_gladly_json_state(self._gladly_approval_comment_state_path(), "comments")
        changed = False
        now = time.time()
        for key, entry in list(state.items()):
            expires_at = self._gladly_approval_epoch(entry.get("expires_at"))
            if expires_at is not None and expires_at <= now:
                state.pop(key, None)
                changed = True
        if changed:
            self._save_gladly_json_state(self._gladly_approval_comment_state_path(), "comments", state)
        return state

    def _save_gladly_approval_comment_state(self, state: Dict[str, Dict[str, Any]]) -> None:
        self._save_gladly_json_state(self._gladly_approval_comment_state_path(), "comments", state)

    def _clear_gladly_approval_comment_pending_for_approval_id(self, approval_id: Optional[str]) -> None:
        if not approval_id:
            return
        state = self._load_gladly_approval_comment_state()
        changed = False
        for key, entry in list(state.items()):
            if str(entry.get("approval_id") or "") == str(approval_id):
                state.pop(key, None)
                changed = True
        if changed:
            self._save_gladly_approval_comment_state(state)

    def _set_gladly_approval_comment_pending(
        self,
        *,
        entry: Dict[str, Any],
        query: Any,
        chat_id: Optional[Any],
        thread_id: Optional[Any],
        user_name: Optional[str],
    ) -> None:
        user_id = getattr(getattr(query, "from_user", None), "id", None)
        key = self._gladly_approval_comment_key(chat_id=chat_id, thread_id=thread_id, user_id=user_id)
        state = self._load_gladly_approval_comment_state()
        message = getattr(query, "message", None)
        state[key] = {
            **entry,
            "chat_id": str(chat_id or ""),
            "thread_id": str(thread_id or ""),
            "user_id": str(user_id or ""),
            "user_name": str(user_name or ""),
            "message_id": str(getattr(message, "message_id", "") or ""),
            "original_text": str(getattr(message, "text", "") or ""),
            "pending_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        self._save_gladly_approval_comment_state(state)

    def _pop_gladly_approval_comment_pending(
        self,
        *,
        chat_id: Optional[Any],
        thread_id: Optional[Any],
        user_id: Optional[Any],
    ) -> Optional[Dict[str, Any]]:
        key = self._gladly_approval_comment_key(chat_id=chat_id, thread_id=thread_id, user_id=user_id)
        state = self._load_gladly_approval_comment_state()
        entry = state.pop(key, None)
        if entry is not None:
            self._save_gladly_approval_comment_state(state)
        return entry


    async def _run_gladly_approval_button(
        self,
        entry: Dict[str, Any],
        *,
        query: Any,
        chat_id: Optional[Any],
        user_name: Optional[str],
        decision_notes: Optional[str] = None,
    ) -> tuple[bool, str]:
        from hermes_constants import get_hermes_home
        from tools.environments.local import build_subprocess_env

        home = get_hermes_home()
        script = home / "scripts" / "gladly-telegram-approval-action.sh"
        env = build_subprocess_env()
        env["HERMES_HOME"] = str(home)
        env["HERMES_QUICK_COMMAND_ARGS"] = str(entry.get("token") or "")
        env["HERMES_QUICK_PLATFORM"] = "telegram"
        env["HERMES_QUICK_USER_ID"] = str(getattr(getattr(query, "from_user", None), "id", "") or "")
        env["HERMES_QUICK_CHAT_ID"] = str(chat_id or "")
        env["HERMES_QUICK_USER_NAME"] = str(user_name or "")
        if decision_notes:
            env["HERMES_QUICK_DECISION_NOTES"] = decision_notes

        proc = await asyncio.create_subprocess_exec(
            "bash",
            str(script),
            str(entry.get("decision") or ""),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = ((stdout or b"") + (b"\n" if stdout and stderr else b"") + (stderr or b"")).decode(
            "utf-8",
            errors="replace",
        ).strip()
        if output:
            try:
                from agent.redact import redact_sensitive_text

                output = redact_sensitive_text(output)
            except Exception:
                pass
        return proc.returncode == 0, output

    async def _run_gladly_approval_snooze(
        self,
        entry: Dict[str, Any],
        *,
        query: Any,
        chat_id: Optional[Any],
        user_name: Optional[str],
        until: str,
    ) -> tuple[bool, str]:
        from hermes_constants import get_hermes_home
        from tools.environments.local import build_subprocess_env

        home = get_hermes_home()
        script = home / "scripts" / "gladly-telegram-approval-snooze.sh"
        env = build_subprocess_env()
        env["HERMES_HOME"] = str(home)
        env["HERMES_QUICK_PLATFORM"] = "telegram"
        env["HERMES_QUICK_USER_ID"] = str(getattr(getattr(query, "from_user", None), "id", "") or "")
        env["HERMES_QUICK_CHAT_ID"] = str(chat_id or "")
        env["HERMES_QUICK_USER_NAME"] = str(user_name or "")

        proc = await asyncio.create_subprocess_exec(
            "bash",
            str(script),
            str(entry.get("approval_id") or ""),
            "--until",
            until,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = ((stdout or b"") + (b"\n" if stdout and stderr else b"") + (stderr or b"")).decode(
            "utf-8",
            errors="replace",
        ).strip()
        if output:
            try:
                from agent.redact import redact_sensitive_text

                output = redact_sensitive_text(output)
            except Exception:
                pass
        return proc.returncode == 0, output

    @staticmethod
    def _gladly_approval_failure_is_resolved(output: str) -> bool:
        text = (output or "").lower()
        if "status=409" in text or "redan" in text:
            return True
        if "status=404" in text and ("pending" in text or "saknas" in text or "inte längre" in text):
            return True
        return False

    @staticmethod
    def _gladly_approval_failure_message(output: str) -> str:
        text = (output or "").lower()
        if "status=403" in text or "signatur" in text or "payload" in text or "token" in text:
            return "Portalen nekade beslutstoken. Skicka en ny approval-notis."
        if "status=404" in text or "saknas" in text:
            return "Godkännandet finns inte längre i Portalen."
        if "status=409" in text or "redan" in text:
            return "Godkännandet är redan beslutat i Portalen."
        if "gått ut" in text or "gatt ut" in text or "expired" in text:
            return "Beslutet har gått ut. Vänta på en ny approval-notis."
        if "status=0" in text or "dns" in text or "connect" in text or "timed out" in text:
            return "Hermes når inte Portalen just nu. Försök igen strax."
        return "Portalen kunde inte spara beslutet. Kontrollera approval i Portalen."

    def _gladly_approval_status_text(self, original_text: str, status_line: str) -> str:
        ignored = {
            "Välj ett alternativ med knapparna nedan.",
            "Skriv kort vad du vill ändra. Jag sparar kommentaren i Portalen.",
        }
        original_lines = [
            line
            for line in original_text.splitlines()
            if line.strip() not in ignored
            and not line.strip().startswith("Status:")
            and not line.strip().startswith("Beslut:")
            and not line.strip().startswith("Kommentar:")
        ]
        final_lines = self._compact_blank_lines(original_lines)
        final_lines.append("")
        final_lines.append(status_line)
        return "\n".join(self._compact_blank_lines(final_lines)).strip()

    async def _mark_gladly_approval_message_resolved(self, query: Any) -> None:
        original_text = str(getattr(getattr(query, "message", None), "text", "") or "").strip()
        final_text = self._gladly_approval_status_text(
            original_text,
            "Status: Godkännandet är redan hanterat i Portalen.",
        )
        try:
            await query.edit_message_text(
                text=final_text[:4000],
                parse_mode=None,
                reply_markup=None,
            )
        except Exception as exc:
            logger.warning("[%s] Failed to mark stale Gladly approval message: %s", self.name, exc)

    @staticmethod
    def _gladly_approval_receipt_label(entry: Dict[str, Any]) -> str:
        success_text = str(entry.get("success_text") or "Beslutet sparat").rstrip(".")
        return success_text.replace(" i Portalen", "").strip() or "Beslutet sparat"

    def _gladly_approval_receipt_text(
        self,
        original_text: str,
        entry: Dict[str, Any],
        *,
        user_name: Optional[str],
        decision_notes: Optional[str] = None,
    ) -> str:
        ignored = {
            "Välj ett alternativ med knapparna nedan.",
            "Skriv kort vad du vill ändra. Jag sparar kommentaren i Portalen.",
        }
        original_lines = [
            line
            for line in original_text.splitlines()
            if line.strip() not in ignored
            and not line.strip().startswith("Status:")
            and not line.strip().startswith("Beslut:")
            and not line.strip().startswith("Kommentar:")
        ]
        final_lines = self._compact_blank_lines(original_lines)
        actor = str(user_name or "Telegram").strip()
        decided_at = datetime.now().astimezone().strftime("%H:%M")
        final_lines.append("")
        final_lines.append(f"Beslut: {self._gladly_approval_receipt_label(entry)} av {actor} {decided_at}.")
        note = str(decision_notes or "").replace("\n", " ").strip()
        if note:
            final_lines.append(f"Kommentar: {note[:180]}")
        portal_url = str(entry.get("portal_url") or "").strip()
        if portal_url and not any(line.strip().lower().startswith("portal:") for line in final_lines):
            final_lines.append(f"Portal: {portal_url}")
        return "\n".join(self._compact_blank_lines(final_lines)).strip()

    @staticmethod
    def _gladly_approval_display_time(value: str) -> str:
        try:
            text = str(value).strip()
            if text.endswith("Z"):
                text = f"{text[:-1]}+00:00"
            return datetime.fromisoformat(text).astimezone().strftime("%d/%m %H:%M")
        except Exception:
            return "senare"

    async def _handle_gladly_approval_callback(
        self,
        query: Any,
        data: str,
        *,
        chat_id: Optional[Any],
        chat_type: Optional[Any],
        thread_id: Optional[Any],
        user_name: Optional[str],
    ) -> None:
        parts = data.split(":", 2)
        button_id = parts[1].strip() if len(parts) > 1 else ""
        preset = parts[2].strip() if len(parts) > 2 and parts[2].strip() else "30m"
        caller_id = str(getattr(getattr(query, "from_user", None), "id", "") or "")
        if not self._is_callback_user_authorized(
            caller_id,
            chat_id=str(chat_id) if chat_id is not None else None,
            chat_type=str(chat_type) if chat_type is not None else None,
            thread_id=str(thread_id) if thread_id is not None else None,
            user_name=user_name,
        ):
            await query.answer(text="Du är inte behörig att ta beslut här.", show_alert=True)
            return

        entry = self._get_gladly_approval_button(button_id)
        if not entry:
            await self._mark_gladly_approval_message_resolved(query)
            await query.answer(text="Beslutet har gått ut eller är redan hanterat.")
            return

        if str(entry.get("decision") or "") == "changes_requested":
            self._set_gladly_approval_comment_pending(
                entry=entry,
                query=query,
                chat_id=chat_id,
                thread_id=thread_id,
                user_name=user_name,
            )
            original_text = str(getattr(getattr(query, "message", None), "text", "") or "").strip()
            original_lines = [
                line
                for line in original_text.splitlines()
                if line.strip() != "Skriv kort vad du vill ändra. Jag sparar kommentaren i Portalen."
            ]
            final_text = "\n".join(self._compact_blank_lines(original_lines)).strip()
            prompt_line = "Skriv kort vad du vill ändra. Jag sparar kommentaren i Portalen."
            final_text = f"{final_text}\n\n{prompt_line}" if final_text else prompt_line
            try:
                await query.edit_message_text(
                    text=final_text[:4000],
                    parse_mode=None,
                    reply_markup=None,
                )
            except Exception as exc:
                logger.warning("[%s] Failed to mark Gladly approval comment prompt: %s", self.name, exc)
            await query.answer(text="Skriv kommentaren som nästa meddelande.", show_alert=True)
            return

        try:
            self._clear_gladly_approval_comment_pending_for_approval_id(str(entry.get("approval_id") or ""))
            ok, output = await self._run_gladly_approval_button(
                entry,
                query=query,
                chat_id=chat_id,
                user_name=user_name,
            )
        except asyncio.TimeoutError:
            await query.answer(text="Portalen svarade inte i tid. Försök igen.", show_alert=True)
            return
        except Exception as exc:
            logger.error("[%s] Gladly approval button failed: %s", self.name, exc, exc_info=True)
            await query.answer(text="Kunde inte skicka beslutet till Portalen.", show_alert=True)
            return

        if not ok:
            logger.warning("[%s] Gladly approval button returned failure: %s", self.name, output)
            if self._gladly_approval_failure_is_resolved(output):
                approval_id = str(entry.get("approval_id") or "")
                self._remove_gladly_approval_buttons(button_id=button_id, approval_id=approval_id)
                await self._mark_gladly_approval_message_resolved(query)
                await query.answer(text="Redan hanterat i Portalen.")
                return
            await query.answer(text=self._gladly_approval_failure_message(output), show_alert=True)
            return

        approval_id = str(entry.get("approval_id") or "")
        self._remove_gladly_approval_buttons(button_id=button_id, approval_id=approval_id)

        original_text = str(getattr(getattr(query, "message", None), "text", "") or "").strip()
        final_text = self._gladly_approval_receipt_text(original_text, entry, user_name=user_name)

        try:
            await query.edit_message_text(
                text=final_text[:4000],
                parse_mode=None,
                reply_markup=None,
            )
        except Exception as exc:
            logger.warning("[%s] Failed to edit Gladly approval message: %s", self.name, exc)
            if self._bot and chat_id is not None:
                try:
                    await self._bot.send_message(chat_id=chat_id, text=final_text[:4000])
                except Exception as send_exc:
                    logger.warning("[%s] Failed to send Gladly approval fallback receipt: %s", self.name, send_exc)
        await query.answer(text=f"{self._gladly_approval_receipt_label(entry)} i Portalen.")

    async def _handle_gladly_approval_wait_callback(
        self,
        query: Any,
        data: str,
        *,
        chat_id: Optional[Any],
        chat_type: Optional[Any],
        thread_id: Optional[Any],
        user_name: Optional[str],
    ) -> None:
        parts = data.split(":", 2)
        button_id = parts[1].strip() if len(parts) > 1 else ""
        preset = parts[2].strip() if len(parts) > 2 and parts[2].strip() else "30m"
        caller_id = str(getattr(getattr(query, "from_user", None), "id", "") or "")
        if not self._is_callback_user_authorized(
            caller_id,
            chat_id=str(chat_id) if chat_id is not None else None,
            chat_type=str(chat_type) if chat_type is not None else None,
            thread_id=str(thread_id) if thread_id is not None else None,
            user_name=user_name,
        ):
            await query.answer(text="Du är inte behörig att ta beslut här.", show_alert=True)
            return

        entry = self._get_gladly_approval_button(button_id)
        if not entry:
            await self._mark_gladly_approval_message_resolved(query)
            await query.answer(text="Beslutet har gått ut eller är redan hanterat.")
            return

        approval_id = str(entry.get("approval_id") or "")
        label, snoozed_until = self._gladly_approval_snooze_until(preset)
        try:
            self._clear_gladly_approval_comment_pending_for_approval_id(approval_id)
            ok, output = await self._run_gladly_approval_snooze(
                entry,
                query=query,
                chat_id=chat_id,
                user_name=user_name,
                until=snoozed_until,
            )
        except asyncio.TimeoutError:
            await query.answer(text="Portalen svarade inte i tid. Försök igen.", show_alert=True)
            return
        except Exception as exc:
            logger.error("[%s] Gladly approval snooze failed: %s", self.name, exc, exc_info=True)
            await query.answer(text="Kunde inte pausa påminnelsen i Portalen.", show_alert=True)
            return

        if not ok:
            logger.warning("[%s] Gladly approval snooze returned failure: %s", self.name, output)
            if self._gladly_approval_failure_is_resolved(output):
                self._remove_gladly_approval_buttons(button_id=button_id, approval_id=approval_id)
                await self._mark_gladly_approval_message_resolved(query)
                await query.answer(text="Redan hanterat i Portalen.")
                return
            await query.answer(text=self._gladly_approval_failure_message(output), show_alert=True)
            return

        marked = self._mark_gladly_approval_waiting(
            button_id=button_id,
            approval_id=approval_id,
            user_name=user_name,
            preset=preset,
            snoozed_until=snoozed_until,
        )
        snoozed_until = str((marked or entry).get("snoozed_until") or "")
        snooze_label = str((marked or entry).get("snooze_preset") or preset)
        label = _GLADLY_APPROVAL_SNOOZE_PRESETS.get(snooze_label, (label, None))[0]

        original_text = str(getattr(getattr(query, "message", None), "text", "") or "").strip()
        original_lines = [
            line
            for line in original_text.splitlines()
            if not line.strip().startswith("Status: Avvaktar")
        ]
        final_text = "\n".join(self._compact_blank_lines(original_lines)).strip()
        status_line = f"Status: Avvaktar {label}, till {self._gladly_approval_display_time(snoozed_until)}. Godkännandet ligger kvar i Portalen."
        final_text = f"{final_text}\n\n{status_line}" if final_text else status_line

        try:
            await query.edit_message_text(
                text=final_text[:4000],
                parse_mode=None,
                reply_markup=getattr(getattr(query, "message", None), "reply_markup", None),
            )
        except Exception as exc:
            logger.warning("[%s] Failed to mark Gladly approval as waiting: %s", self.name, exc)
        await query.answer(text=f"Okej. Påminner {label}.")

    async def _handle_gladly_approval_comment_message(self, message: Any) -> bool:
        text = str(getattr(message, "text", "") or "").strip()
        if not text:
            return False

        chat_id = getattr(message, "chat_id", None) or getattr(getattr(message, "chat", None), "id", None)
        thread_id = getattr(message, "message_thread_id", None)
        user = getattr(message, "from_user", None)
        user_id = getattr(user, "id", None)
        key = self._gladly_approval_comment_key(chat_id=chat_id, thread_id=thread_id, user_id=user_id)
        state = self._load_gladly_approval_comment_state()
        if key not in state:
            return False

        lowered = text.lower()
        if lowered in {"avbryt", "cancel", "/cancel"}:
            state.pop(key, None)
            self._save_gladly_approval_comment_state(state)
            if self._bot and chat_id is not None:
                await self._bot.send_message(chat_id=chat_id, text="Avbrutet. Godkännandet ligger kvar i Portalen.")
            return True
        if text.startswith("/"):
            return False

        entry = state.pop(key)
        self._save_gladly_approval_comment_state(state)
        user_name = str(
            getattr(user, "first_name", None)
            or getattr(user, "username", None)
            or entry.get("user_name")
            or "Telegram"
        )
        fake_query = SimpleNamespace(from_user=user)

        try:
            ok, output = await self._run_gladly_approval_button(
                entry,
                query=fake_query,
                chat_id=chat_id,
                user_name=user_name,
                decision_notes=text,
            )
        except asyncio.TimeoutError:
            ok, output = False, "timeout"
        except Exception as exc:
            logger.error("[%s] Gladly approval comment submit failed: %s", self.name, exc, exc_info=True)
            ok, output = False, str(exc)

        if not ok:
            if self._gladly_approval_failure_is_resolved(output):
                approval_id = str(entry.get("approval_id") or "")
                self._remove_gladly_approval_buttons(button_id=str(entry.get("id") or ""), approval_id=approval_id)
                message_id_text = str(entry.get("message_id") or "").strip()
                if self._bot and chat_id is not None and message_id_text:
                    try:
                        await self._bot.edit_message_text(
                            chat_id=chat_id,
                            message_id=int(message_id_text),
                            text=self._gladly_approval_status_text(
                                str(entry.get("original_text") or ""),
                                "Status: Godkännandet är redan hanterat i Portalen.",
                            )[:4000],
                            parse_mode=None,
                            reply_markup=None,
                        )
                    except Exception as exc:
                        logger.warning("[%s] Failed to edit stale Gladly approval comment message: %s", self.name, exc)
                if self._bot and chat_id is not None:
                    await self._bot.send_message(chat_id=chat_id, text="Redan hanterat i Portalen.")
                return True
            state = self._load_gladly_approval_comment_state()
            state[key] = entry
            self._save_gladly_approval_comment_state(state)
            if self._bot and chat_id is not None:
                await self._bot.send_message(
                    chat_id=chat_id,
                    text=self._gladly_approval_failure_message(output),
                )
            return True

        approval_id = str(entry.get("approval_id") or "")
        self._remove_gladly_approval_buttons(button_id=str(entry.get("id") or ""), approval_id=approval_id)

        final_text = self._gladly_approval_receipt_text(
            str(entry.get("original_text") or ""),
            entry,
            user_name=user_name,
            decision_notes=text,
        )
        message_id_text = str(entry.get("message_id") or "").strip()
        edited = False
        if self._bot and chat_id is not None and message_id_text:
            try:
                await self._bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=int(message_id_text),
                    text=final_text[:4000],
                    parse_mode=None,
                    reply_markup=None,
                )
                edited = True
            except Exception as exc:
                logger.warning("[%s] Failed to edit Gladly approval comment receipt: %s", self.name, exc)
        if self._bot and chat_id is not None and not edited:
            await self._bot.send_message(chat_id=chat_id, text=final_text[:4000])
        return True
