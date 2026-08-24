import hashlib
import os
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

try:
    import requests
except Exception:
    requests = None

from itsdangerous import BadSignature, URLSafeSerializer

from common_paths import auth_db_path

AUTH_COOKIE_NAME = "ar_access"
DEVICE_COOKIE_NAME = "ar_device"
POLL_INTERVAL_SEC = 2

_LOCK = threading.Lock()
_WORKER_STARTED = {}


def utcnow():
    return datetime.now(timezone.utc)


def iso_now():
    return utcnow().isoformat()


def _connect(account=None):
    from common_paths import set_account, get_current_account
    old = get_current_account()
    if account:
        set_account(account)
    path = auth_db_path()
    if old:
        set_account(old)
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def _connect_for(account):
    path = None
    from common_paths import _ACCOUNTS_DIR
    if account:
        path = os.path.join(_ACCOUNTS_DIR, account, "auth.db")
    else:
        from common_paths import auth_db_path as _adb
        path = _adb()
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_db(account=None):
    conn = _connect_for(account)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS auth_requests (
            request_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            device_hash TEXT NOT NULL,
            user_agent_hash TEXT NOT NULL,
            ip TEXT,
            status TEXT NOT NULL,
            telegram_message_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS trusted_devices (
            device_hash TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            user_agent_hash TEXT NOT NULL,
            approved_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_ip TEXT,
            last_seen_at TEXT NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS auth_meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )"""
    )
    conn.commit()
    conn.close()


def sha256_text(value):
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def get_or_create_device_id(raw_device_id):
    if raw_device_id and 12 <= len(raw_device_id) <= 128:
        return raw_device_id
    return secrets.token_urlsafe(32)


def build_user_agent_hash(user_agent, accept_language=None):
    return sha256_text(f"{user_agent or ''}|{accept_language or ''}")


def build_device_hash(device_id, user_agent_hash):
    return sha256_text(f"{device_id}|{user_agent_hash}")


def build_auth_serializer(secret_key):
    return URLSafeSerializer(secret_key, salt="anti-revoke-access")


def create_access_token(secret_key, device_hash):
    return build_auth_serializer(secret_key).dumps({"device_hash": device_hash})


def parse_access_token(secret_key, token):
    if not token:
        return None
    try:
        payload = build_auth_serializer(secret_key).loads(token)
    except BadSignature:
        return None
    return payload.get("device_hash")


def cleanup_expired(account=None):
    now = iso_now()
    conn = _connect_for(account)
    conn.execute("DELETE FROM auth_requests WHERE expires_at <= ?", (now,))
    conn.execute("DELETE FROM trusted_devices WHERE expires_at <= ?", (now,))
    conn.commit()
    conn.close()


def create_auth_request(device_id, user_agent, accept_language, ip, timeout_sec, account=None):
    cleanup_expired(account)
    user_agent_hash = build_user_agent_hash(user_agent, accept_language)
    device_hash = build_device_hash(device_id, user_agent_hash)
    request_id = uuid.uuid4().hex
    now = utcnow()
    expires_at = now + timedelta(seconds=max(30, timeout_sec))

    conn = _connect_for(account)
    conn.execute(
        """INSERT INTO auth_requests
           (request_id, device_id, device_hash, user_agent_hash, ip, status,
            telegram_message_id, created_at, updated_at, expires_at)
           VALUES (?, ?, ?, ?, ?, 'pending', NULL, ?, ?, ?)""",
        (request_id, device_id, device_hash, user_agent_hash, ip,
         now.isoformat(), now.isoformat(), expires_at.isoformat()),
    )
    conn.commit()
    conn.close()
    return {
        "request_id": request_id,
        "device_hash": device_hash,
        "user_agent_hash": user_agent_hash,
        "expires_at": expires_at.isoformat(),
    }


def get_auth_request(request_id, account=None):
    cleanup_expired(account)
    conn = _connect_for(account)
    row = conn.execute("SELECT * FROM auth_requests WHERE request_id = ?", (request_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_auth_request_message(request_id, message_id, account=None):
    conn = _connect_for(account)
    conn.execute(
        "UPDATE auth_requests SET telegram_message_id = ?, updated_at = ? WHERE request_id = ?",
        (message_id, iso_now(), request_id),
    )
    conn.commit()
    conn.close()


def set_auth_request_status(request_id, status, account=None):
    conn = _connect_for(account)
    conn.execute(
        "UPDATE auth_requests SET status = ?, updated_at = ? WHERE request_id = ?",
        (status, iso_now(), request_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM auth_requests WHERE request_id = ?", (request_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def trust_device(device_id, user_agent_hash, ip, trust_days, account=None):
    device_hash = build_device_hash(device_id, user_agent_hash)
    now = utcnow()
    expires_at = now + timedelta(days=max(1, trust_days))
    conn = _connect_for(account)
    conn.execute(
        """INSERT INTO trusted_devices
           (device_hash, device_id, user_agent_hash, approved_at, expires_at, last_ip, last_seen_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(device_hash) DO UPDATE SET
               approved_at = excluded.approved_at,
               expires_at = excluded.expires_at,
               last_ip = excluded.last_ip,
               last_seen_at = excluded.last_seen_at""",
        (device_hash, device_id, user_agent_hash, now.isoformat(), expires_at.isoformat(), ip, now.isoformat()),
    )
    conn.commit()
    conn.close()
    return {"device_hash": device_hash, "expires_at": expires_at.isoformat()}


def is_trusted_device(device_hash, account=None):
    if not device_hash:
        return False
    cleanup_expired(account)
    conn = _connect_for(account)
    row = conn.execute(
        "SELECT device_hash FROM trusted_devices WHERE device_hash = ? AND expires_at > ?",
        (device_hash, iso_now()),
    ).fetchone()
    conn.close()
    return bool(row)


def touch_trusted_device(device_hash, ip, account=None):
    conn = _connect_for(account)
    conn.execute(
        "UPDATE trusted_devices SET last_ip = ?, last_seen_at = ? WHERE device_hash = ?",
        (ip, iso_now(), device_hash),
    )
    conn.commit()
    conn.close()


def set_meta(key, value, account=None):
    conn = _connect_for(account)
    conn.execute(
        "INSERT INTO auth_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()
    conn.close()


def get_meta(key, default="0", account=None):
    conn = _connect_for(account)
    row = conn.execute("SELECT value FROM auth_meta WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def send_telegram_approval_request(bot_token, chat_id, ip, request_id):
    if requests is None:
        return False, "requests is not installed", None

    text = (
        "WARNING! Confirm login to Anti-Revoke\n"
        f"IP: {ip or 'unknown'}\n"
        f"Request ID: {request_id[:10]}"
    )
    keyboard = {
        "inline_keyboard": [[
            {"text": "Allow", "callback_data": f"allow:{request_id}"},
            {"text": "Deny", "callback_data": f"deny:{request_id}"},
        ]]
    }

    try:
        response = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "reply_markup": keyboard},
            timeout=15,
        )
        payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        if response.status_code == 200 and payload.get("ok") is True:
            message_id = (((payload.get("result") or {}).get("message_id")))
            return True, "ok", message_id
        return False, payload.get("description") or response.text[:200], None
    except Exception as exc:
        return False, str(exc), None


def answer_callback_query(bot_token, callback_query_id, text):
    if requests is None:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{bot_token}/answerCallbackQuery",
            json={"callback_query_id": callback_query_id, "text": text[:180], "show_alert": False},
            timeout=10,
        )
    except Exception:
        pass


def edit_callback_message(bot_token, chat_id, message_id, text):
    if requests is None:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{bot_token}/editMessageText",
            json={"chat_id": chat_id, "message_id": message_id, "text": text},
            timeout=10,
        )
    except Exception:
        pass


def process_callback(bot_token, chat_id, callback_query, trust_days, account=None):
    data = str(callback_query.get("data") or "")
    query_id = str(callback_query.get("id") or "")
    message = callback_query.get("message") or {}
    message_id = int(message.get("message_id") or 0)

    if ":" not in data:
        answer_callback_query(bot_token, query_id, "Unknown action")
        return

    action, request_id = data.split(":", 1)
    request_row = get_auth_request(request_id, account)
    if not request_row:
        answer_callback_query(bot_token, query_id, "Request already expired")
        if message_id:
            edit_callback_message(bot_token, chat_id, message_id, "Access request expired")
        return

    if action == "allow":
        trust_device(request_row["device_id"], request_row["user_agent_hash"],
                     request_row.get("ip") or "", trust_days, account)
        set_auth_request_status(request_id, "approved", account)
        answer_callback_query(bot_token, query_id, "Access approved")
        if message_id:
            edit_callback_message(
                bot_token, chat_id, message_id,
                f"Access approved\nIP: {request_row.get('ip') or 'unknown'}\nRequest ID: {request_id[:10]}",
            )
        return

    if action == "deny":
        set_auth_request_status(request_id, "denied", account)
        answer_callback_query(bot_token, query_id, "Access denied")
        if message_id:
            edit_callback_message(
                bot_token, chat_id, message_id,
                f"Access denied\nIP: {request_row.get('ip') or 'unknown'}\nRequest ID: {request_id[:10]}",
            )
        return

    answer_callback_query(bot_token, query_id, "Unknown action")


def poll_telegram_callbacks_for_account(account_name, config_loader, logger):
    while True:
        try:
            cfg = config_loader() or {}
            enabled = bool(cfg.get("access_control_enabled", True))
            bot_token = str(cfg.get("bot_token") or "").strip()
            chat_id = str(cfg.get("access_chat_id") or cfg.get("bot_chat_id") or "").strip()
            trust_days = int(cfg.get("trust_days") or 30)

            if not enabled or not bot_token or not chat_id or requests is None:
                time.sleep(3)
                continue

            offset = int(get_meta("telegram_update_offset", "0", account_name) or 0)
            response = requests.get(
                f"https://api.telegram.org/bot{bot_token}/getUpdates",
                params={"timeout": 20, "offset": offset},
                timeout=25,
            )
            payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
            if response.status_code != 200 or payload.get("ok") is not True:
                logger(f"auth poll failed: {response.status_code} {str(payload)[:200]}")
                time.sleep(5)
                continue

            for update in payload.get("result") or []:
                update_id = int(update.get("update_id") or 0)
                set_meta("telegram_update_offset", str(update_id + 1), account_name)
                callback_query = update.get("callback_query")
                if callback_query:
                    process_callback(bot_token, chat_id, callback_query, trust_days, account_name)
        except Exception as exc:
            logger(f"auth poll error: {exc}")
            time.sleep(5)


def ensure_polling_started_for_account(account_name, config_loader, logger):
    key = account_name
    with _LOCK:
        if _WORKER_STARTED.get(key):
            return
        worker = threading.Thread(
            target=poll_telegram_callbacks_for_account,
            args=(account_name, config_loader, logger),
            daemon=True,
            name=f"telegram-auth-poller-{account_name}",
        )
        worker.start()
        _WORKER_STARTED[key] = True
