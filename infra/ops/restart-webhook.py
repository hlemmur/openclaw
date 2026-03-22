#!/usr/bin/env python3
"""
Telegram webhook listener for secure gateway restart operations.

Design goals:
  - run outside OpenClaw agent execution path
  - accept only authenticated Telegram webhooks
  - authorize only explicit chat/user allowlists
  - execute restart with a single-flight lock
  - keep auditable logs without exposing sensitive output in chat
"""

from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import shlex
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


OPENCLAW_HOME = Path(os.environ.get("OPENCLAW_HOME", str(Path.home() / ".openclaw"))).resolve()
LOG_DIR = OPENCLAW_HOME / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

BOT_TOKEN = os.environ.get("TELEGRAM_OPS_BOT_TOKEN", "").strip()
WEBHOOK_SECRET = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "").strip()
WEBHOOK_PATH = os.environ.get("TELEGRAM_WEBHOOK_PATH", "/telegram/restart-webhook").strip() or "/telegram/restart-webhook"
LISTEN_HOST = os.environ.get("TELEGRAM_RESTART_WEBHOOK_HOST", "127.0.0.1").strip() or "127.0.0.1"
LISTEN_PORT = int(os.environ.get("TELEGRAM_RESTART_WEBHOOK_PORT", "8787"))

ALLOWED_CHAT_IDS = {
    x.strip()
    for x in os.environ.get("TELEGRAM_ALLOWED_CHAT_IDS", "").split(",")
    if x.strip()
}
ALLOWED_USER_IDS = {
    x.strip()
    for x in os.environ.get("TELEGRAM_ALLOWED_USER_IDS", "").split(",")
    if x.strip()
}

RESTART_SCRIPT = Path(
    os.environ.get("OPENCLAW_RESTART_SCRIPT", str(OPENCLAW_HOME / "infra" / "restart-secure.sh"))
).resolve()
EXTRA_RESTART_ARGS = shlex.split(os.environ.get("OPENCLAW_RESTART_EXTRA_ARGS", "").strip())
ALLOWED_FLAGS = {"--egress", "--net"}

RESTART_LOCK = OPENCLAW_HOME / ".restart-secure.lock"
AUDIT_LOG = LOG_DIR / "restart-webhook-audit.jsonl"

_state_lock = threading.Lock()
_restart_running = False


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def audit(event: str, **fields: Any) -> None:
    record = {"ts": now_iso(), "event": event, **fields}
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=True) + "\n")


def send_telegram_message(chat_id: str, text: str, reply_to: int | None = None) -> None:
    if not BOT_TOKEN:
        return
    payload: dict[str, Any] = {"chat_id": chat_id, "text": text}
    if reply_to is not None:
        payload["reply_to_message_id"] = reply_to
    req = urllib.request.Request(
        url=f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            _ = resp.read()
    except Exception as exc:  # pragma: no cover
        audit("telegram_send_failed", error=str(exc))


def parse_restart_command(text: str) -> list[str] | None:
    parts = text.strip().split()
    if not parts:
        return None
    command = parts[0].split("@", 1)[0]
    if command != "/restart_secure":
        return None
    flags: list[str] = []
    for item in parts[1:]:
        if item not in ALLOWED_FLAGS:
            raise ValueError(f"unsupported flag: {item}")
        flags.append(item)
    return flags


def run_restart_async(chat_id: str, user_id: str, update_id: int, message_id: int | None, flags: list[str]) -> None:
    global _restart_running
    lock_handle = None
    started = time.monotonic()
    cmd = [str(RESTART_SCRIPT), *flags, *EXTRA_RESTART_ARGS]
    try:
        with _state_lock:
            if _restart_running:
                send_telegram_message(chat_id, "Restart is already in progress.", reply_to=message_id)
                audit(
                    "restart_rejected_already_running",
                    chat_id=chat_id,
                    user_id=user_id,
                    update_id=update_id,
                    flags=flags,
                )
                return
            _restart_running = True

        lock_handle = RESTART_LOCK.open("w", encoding="utf-8")
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            send_telegram_message(chat_id, "Restart lock is held. Try again later.", reply_to=message_id)
            audit(
                "restart_rejected_lock_held",
                chat_id=chat_id,
                user_id=user_id,
                update_id=update_id,
                flags=flags,
            )
            return

        lock_handle.write(f"pid={os.getpid()} ts={now_iso()} cmd={' '.join(cmd)}\n")
        lock_handle.flush()

        if not RESTART_SCRIPT.exists():
            send_telegram_message(chat_id, f"Restart script not found: `{RESTART_SCRIPT}`", reply_to=message_id)
            audit(
                "restart_failed_missing_script",
                chat_id=chat_id,
                user_id=user_id,
                update_id=update_id,
                script=str(RESTART_SCRIPT),
            )
            return

        if not os.access(RESTART_SCRIPT, os.X_OK):
            send_telegram_message(chat_id, "Restart script is not executable. Run chmod +x first.", reply_to=message_id)
            audit(
                "restart_failed_not_executable",
                chat_id=chat_id,
                user_id=user_id,
                update_id=update_id,
                script=str(RESTART_SCRIPT),
            )
            return

        audit(
            "restart_started",
            chat_id=chat_id,
            user_id=user_id,
            update_id=update_id,
            command=cmd,
            flags=flags,
        )
        send_telegram_message(chat_id, f"Secure restart started: `{shlex.join(cmd)}`", reply_to=message_id)

        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(OPENCLAW_HOME))
        elapsed = round(time.monotonic() - started, 2)

        if proc.returncode == 0:
            send_telegram_message(chat_id, f"Secure restart completed in {elapsed}s.", reply_to=message_id)
            audit(
                "restart_completed",
                chat_id=chat_id,
                user_id=user_id,
                update_id=update_id,
                returncode=proc.returncode,
                elapsed_seconds=elapsed,
            )
        else:
            send_telegram_message(
                chat_id,
                "Secure restart failed. Check ~/.openclaw/logs/restart-webhook-audit.jsonl and command output locally.",
                reply_to=message_id,
            )
            audit(
                "restart_failed",
                chat_id=chat_id,
                user_id=user_id,
                update_id=update_id,
                returncode=proc.returncode,
                elapsed_seconds=elapsed,
                stdout_tail=proc.stdout[-2000:],
                stderr_tail=proc.stderr[-2000:],
            )
    finally:
        if lock_handle is not None:
            try:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            lock_handle.close()
        with _state_lock:
            _restart_running = False


class Handler(BaseHTTPRequestHandler):
    server_version = "OpenClawRestartWebhook/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # pragma: no cover
        audit("http_log", client=self.client_address[0], message=(fmt % args))

    def _json_response(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._json_response(HTTPStatus.OK, {"ok": True, "service": "telegram-restart-webhook"})
            return
        self._json_response(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:
        parsed_path = urllib.parse.urlparse(self.path).path
        if parsed_path != WEBHOOK_PATH:
            self._json_response(HTTPStatus.NOT_FOUND, {"ok": False, "error": "path_not_found"})
            return

        secret = self.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if not WEBHOOK_SECRET or secret != WEBHOOK_SECRET:
            audit("webhook_rejected_secret", remote=self.client_address[0])
            self._json_response(HTTPStatus.FORBIDDEN, {"ok": False, "error": "forbidden"})
            return

        content_len = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_len)
        try:
            update = json.loads(raw.decode("utf-8"))
        except Exception:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid_json"})
            return

        message = update.get("message") or update.get("edited_message")
        if not isinstance(message, dict):
            self._json_response(HTTPStatus.OK, {"ok": True, "ignored": "no_message"})
            return

        chat = message.get("chat") or {}
        sender = message.get("from") or {}
        chat_id = str(chat.get("id", ""))
        user_id = str(sender.get("id", ""))
        text = str(message.get("text", "")).strip()
        update_id = int(update.get("update_id", -1))
        message_id = message.get("message_id")
        message_id = int(message_id) if isinstance(message_id, int) else None

        if not ALLOWED_CHAT_IDS or not ALLOWED_USER_IDS:
            audit("webhook_misconfig_allowlists_empty", update_id=update_id)
            self._json_response(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": "allowlist_misconfigured"})
            return

        if chat_id not in ALLOWED_CHAT_IDS or user_id not in ALLOWED_USER_IDS:
            audit("webhook_rejected_identity", chat_id=chat_id, user_id=user_id, update_id=update_id)
            self._json_response(HTTPStatus.OK, {"ok": True, "ignored": "unauthorized_sender"})
            return

        try:
            flags = parse_restart_command(text)
        except ValueError as exc:
            send_telegram_message(chat_id, f"Invalid restart command: {exc}", reply_to=message_id)
            audit("webhook_invalid_command", chat_id=chat_id, user_id=user_id, update_id=update_id, text=text)
            self._json_response(HTTPStatus.OK, {"ok": True, "ignored": "invalid_command"})
            return

        if flags is None:
            self._json_response(HTTPStatus.OK, {"ok": True, "ignored": "not_restart_command"})
            return

        thread = threading.Thread(
            target=run_restart_async,
            args=(chat_id, user_id, update_id, message_id, flags),
            daemon=True,
        )
        thread.start()
        self._json_response(HTTPStatus.OK, {"ok": True, "accepted": True})


def main() -> int:
    missing = []
    if not BOT_TOKEN:
        missing.append("TELEGRAM_OPS_BOT_TOKEN")
    if not WEBHOOK_SECRET:
        missing.append("TELEGRAM_WEBHOOK_SECRET")
    if missing:
        print(f"[restart-webhook] missing required env vars: {', '.join(missing)}")
        return 2
    if not RESTART_SCRIPT.exists():
        print(f"[restart-webhook] warning: restart script does not exist yet: {RESTART_SCRIPT}")

    print(
        f"[restart-webhook] listening on http://{LISTEN_HOST}:{LISTEN_PORT}{WEBHOOK_PATH} "
        f"(allowed chats={len(ALLOWED_CHAT_IDS)}, users={len(ALLOWED_USER_IDS)})"
    )
    httpd = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
