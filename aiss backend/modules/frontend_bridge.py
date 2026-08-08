"""AISS — Frontend Bridge & Popup Injection System
Automatically injects popup dialogs into the frontend whenever:
  1. A new module registers questions via setup_wizard.register_module_questions()
  2. A new feature is detected at startup
  3. The frontend makes its first connection

How it works:
  - This module watches for frontend connections via WebSocket
  - On connect, sends all pending popup questions automatically
  - Stores popup state (shown/answered) in data/popup_state.json
  - When frontend is not yet implemented → questions are shown in CMD wizard
  - When frontend IS implemented → questions auto-appear as popups

Frontend integration contract (for when frontend is built):
  WS message: { event: "popup_question", question: {...}, wizard_step: "3_ai" }
  WS message: { event: "popup_batch",    questions: [...], step_count: 10 }
  WS message: { event: "wizard_complete" }

  Frontend responds: { action: "popup_answer", question_id: "...", value: "..." }

Auto-injection: any new Python module that calls
    from modules.frontend_bridge import register_popup
    register_popup(question_dict)
will have its popup automatically shown in the frontend on next connection.
"""
import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from utils.logger import setup_logger

logger = setup_logger("frontend_bridge")

_STATE_FILE  = Path("data/popup_state.json")
_PENDING_WS_QUEUE: list[dict] = []   # queued for next frontend WS connection
_ACTIVE_WS_SOCKETS: list = []        # active frontend WebSocket connections


# ─────────────────────────────────────────────────────────────────────
# Popup state persistence
# ─────────────────────────────────────────────────────────────────────

def _load_state() -> dict:
    try:
        if _STATE_FILE.exists():
            return json.loads(_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {"shown": {}, "answered": {}, "dismissed": set(), "version": "2.0.0"}


def _save_state(state: dict) -> None:
    try:
        _STATE_FILE.parent.mkdir(exist_ok=True)
        # Convert any sets to lists for JSON serialisation
        s = dict(state)
        if isinstance(s.get("dismissed"), set):
            s["dismissed"] = list(s["dismissed"])
        _STATE_FILE.write_text(json.dumps(s, indent=2), encoding="utf-8")
    except Exception as e:
        logger.debug(f"popup state save error: {e}")


_state = _load_state()


# ─────────────────────────────────────────────────────────────────────
# Public API — called by modules to register their popups
# ─────────────────────────────────────────────────────────────────────

def register_popup(question: dict, force: bool = False) -> None:
    """
    Register a popup question for the frontend.
    If frontend is connected → sends immediately.
    If not → queues for next connection.
    If already answered (and not forced) → skips.

    question dict keys:
        id, title, label, type, placeholder, default,
        required, options, help_text, help_url, step, icon
    """
    qid = question.get("id", "")
    if not qid:
        return

    answered = _state.get("answered", {})
    dismissed = set(_state.get("dismissed", []))

    if not force and (qid in answered or qid in dismissed):
        return   # Already handled

    # Also register in setup wizard for completeness
    try:
        from modules.setup_wizard import register_module_questions, Question
        q = Question(
            id=qid,
            step=question.get("step", "99_auto"),
            title=question.get("title", qid),
            label=question.get("label", qid),
            type=question.get("type", "text"),
            placeholder=question.get("placeholder", ""),
            default=question.get("default", ""),
            required=question.get("required", False),
            options=question.get("options", []),
            help_text=question.get("help_text", ""),
            help_url=question.get("help_url", ""),
            icon=question.get("icon", ""),
        )
        register_module_questions([q])
    except Exception:
        pass

    # Send to active frontend WebSocket connections
    sent = False
    for ws in list(_ACTIVE_WS_SOCKETS):
        try:
            asyncio.create_task(_send_popup(ws, question))
            sent = True
        except Exception:
            pass

    if not sent:
        # Queue for when frontend connects
        if not any(p.get("id") == qid for p in _PENDING_WS_QUEUE):
            _PENDING_WS_QUEUE.append(question)
            logger.debug(f"Popup queued for frontend: {qid}")


async def _send_popup(ws, question: dict) -> None:
    """Send a single popup question over WebSocket."""
    try:
        await ws.send_text(json.dumps({
            "event":    "popup_question",
            "question": question,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))
    except Exception as e:
        logger.debug(f"popup send error: {e}")
        if ws in _ACTIVE_WS_SOCKETS:
            _ACTIVE_WS_SOCKETS.remove(ws)


async def send_wizard_to_frontend(ws) -> None:
    """
    Called when a frontend WebSocket connects.
    Sends all pending/unanswered popup questions as a batch.
    """
    try:
        from modules.setup_wizard import setup_wizard
        data     = setup_wizard.get_questions()
        answered = _state.get("answered", {})

        # Find unanswered questions
        pending  = []
        for step_questions in data["questions_by_step"].values():
            for q in step_questions:
                if q.get("required") and not answered.get(q["id"]):
                    pending.append(q)
                elif not answered.get(q["id"]) and q.get("current_value", "") == "":
                    pending.append(q)

        if pending:
            await ws.send_text(json.dumps({
                "event":      "wizard_start",
                "message":    "Welcome to AISS! Let's configure your system.",
                "steps":      data["steps"],
                "questions":  pending,
                "total":      len(pending),
                "timestamp":  datetime.now(timezone.utc).isoformat(),
            }))
            logger.info(f"Sent {len(pending)} wizard questions to frontend")

        # Also send any manually queued popups
        for question in list(_PENDING_WS_QUEUE):
            qid = question.get("id", "")
            if qid and qid not in answered:
                await _send_popup(ws, question)

    except Exception as e:
        logger.debug(f"send_wizard_to_frontend error: {e}")


def record_answer(question_id: str, value: Any) -> None:
    """Record that a popup was answered — won't show again."""
    _state.setdefault("answered", {})[question_id] = {
        "value": value,
        "at":    datetime.now(timezone.utc).isoformat(),
    }
    # Also write to .env
    try:
        _apply_to_env(question_id, str(value))
    except Exception:
        pass
    _save_state(_state)
    # Remove from pending queue
    global _PENDING_WS_QUEUE
    _PENDING_WS_QUEUE = [p for p in _PENDING_WS_QUEUE if p.get("id") != question_id]


def dismiss_popup(question_id: str) -> None:
    """Mark a popup as dismissed (won't ask again this session)."""
    dismissed = _state.setdefault("dismissed", [])
    if question_id not in dismissed:
        dismissed.append(question_id)
    _save_state(_state)


def _apply_to_env(key: str, value: str) -> None:
    """Write an answered popup value to .env."""
    if key.startswith("_"):
        return  # internal wizard keys
    env_file = Path(".env")
    if not env_file.exists():
        return
    lines    = env_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    written  = False
    new_lines = []
    for line in lines:
        if line.strip().startswith(f"{key}=") or line.strip() == f"{key}=":
            new_lines.append(f"{key}={value}")
            written = True
        else:
            new_lines.append(line)
    if not written:
        new_lines.append(f"{key}={value}")
    env_file.write_text("\n".join(new_lines), encoding="utf-8")
    os.environ[key] = value


def register_frontend_socket(ws) -> None:
    """Called when a frontend WebSocket connects."""
    if ws not in _ACTIVE_WS_SOCKETS:
        _ACTIVE_WS_SOCKETS.append(ws)


def unregister_frontend_socket(ws) -> None:
    """Called when a frontend WebSocket disconnects."""
    if ws in _ACTIVE_WS_SOCKETS:
        _ACTIVE_WS_SOCKETS.remove(ws)


def get_popup_status() -> dict:
    """Return current popup/wizard state for the status API."""
    answered  = _state.get("answered", {})
    dismissed = _state.get("dismissed", [])
    pending   = len(_PENDING_WS_QUEUE)
    return {
        "answered_count":  len(answered),
        "dismissed_count": len(dismissed),
        "pending_popups":  pending,
        "frontend_connected": len(_ACTIVE_WS_SOCKETS) > 0,
        "answered_keys":   list(answered.keys()),
    }
