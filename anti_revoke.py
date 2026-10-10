# anti_revoke.py (exe-ready) - TTL fix (media.ttl_seconds)
# Account-aware version: python anti_revoke.py <account_name>
import os, json, sqlite3, traceback, shutil, sys, re, time, asyncio
from datetime import datetime, timezone

# --- account setup (must happen before any path imports) ---
if len(sys.argv) < 2:
    print("Usage: python anti_revoke.py <account_name>")
    sys.exit(1)

from common_paths import set_account, db_path, settings_file, gui_cfg_file, media_folder, log_dir, session_base, legacy_session_base
set_account(sys.argv[1])

from telethon import TelegramClient, events
from telethon.tl.types import Message
from telethon.tl.types import UpdateDeleteChannelMessages, UpdateDeleteMessages
from telethon.sessions import sqlite as telethon_sqlite
try:
    import requests
except Exception:
    requests = None

from storage_cleanup import normalize_cleanup_settings, run_cleanup

API_ID = int(os.environ.get("AR_API_ID", "0"))
API_HASH = os.environ.get("AR_API_HASH", "")

DEFAULT_SETTINGS = {
    "capture_private": True,
    "capture_group": True,
    "capture_channel": True,
    "download_ephemeral": True,
    "retention_days": 30,
    "storage_soft_limit_mb": 420,
    "storage_target_mb": 360,
    "storage_mode": "light",
    "text_retention_days": 7,
}

DEFAULT_GUI = {
    "bot_token": "",
    "bot_chat_id": "",
    "send_to_bot": False,
    "exclude_own_chat": True,
    "exclude_from_bot": [],
}

def _detect_session_cols():
    """Detect how many columns the installed Telethon expects in sessions table."""
    try:
        import inspect
        src = inspect.getsource(telethon_sqlite.SQLiteSession.__init__)
        for line in src.split('\n'):
            if 'self._dc_id' in line and 'self._port' in line:
                if 'tmp_key' in line or 'tmp_auth_key' in line:
                    return ["dc_id", "server_address", "port", "auth_key", "tmp_auth_key", "takeout_id"]
                return ["dc_id", "server_address", "port", "auth_key", "takeout_id"]
    except Exception:
        pass
    return ["dc_id", "server_address", "port", "auth_key", "takeout_id"]

def _session_cols_sql(cols):
    """Return (create_table_sql, insert_columns, insert_placeholders, select_sql)."""
    if len(cols) == 6:
        return (
            "dc_id integer primary key, server_address text, port integer, auth_key blob, tmp_auth_key blob, takeout_id integer",
            "(dc_id, server_address, port, auth_key, tmp_auth_key, takeout_id)",
            "(?,?,?,?,?,?)",
            "SELECT dc_id, server_address, port, auth_key, tmp_auth_key, takeout_id FROM sessions"
        )
    return (
        "dc_id integer primary key, server_address text, port integer, auth_key blob, takeout_id integer",
        "(dc_id, server_address, port, auth_key, takeout_id)",
        "(?,?,?,?,?)",
        "SELECT dc_id, server_address, port, auth_key, takeout_id FROM sessions"
    )

def _patch_telethon_sqlite_session():
    pass

def _ensure_dirs():
    os.makedirs(media_folder(), exist_ok=True)
    os.makedirs(log_dir(), exist_ok=True)

def _log(line: str):
    try:
        with open(os.path.join(log_dir(), "receiver.log"), "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} {line}\n")
    except Exception:
        pass

def load_settings() -> dict:
    try:
        sf = settings_file()
        if not os.path.exists(sf):
            with open(sf, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_SETTINGS, f, ensure_ascii=False, indent=2)
            return dict(DEFAULT_SETTINGS)
        with open(sf, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        out = normalize_cleanup_settings(data)
        for k in ("capture_private", "capture_group", "capture_channel", "download_ephemeral"):
            out[k] = bool(data.get(k, DEFAULT_SETTINGS[k]))
        return out
    except Exception:
        return dict(DEFAULT_SETTINGS)

def load_gui_cfg() -> dict:
    try:
        gf = gui_cfg_file()
        if not os.path.exists(gf):
            return dict(DEFAULT_GUI)
        with open(gf, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        out = dict(data)
        for k, v in DEFAULT_GUI.items():
            if k not in out:
                out[k] = v
        out["send_to_bot"] = bool(out.get("send_to_bot", False))
        return out
    except Exception:
        return dict(DEFAULT_GUI)

def _fmt_dt(dt_raw: str) -> str:
    try:
        return datetime.fromisoformat(dt_raw).strftime("%d.%m.%Y %H:%M:%S")
    except Exception:
        return dt_raw or ""

def _bot_send_text(token: str, chat_id: str, text: str) -> bool:
    if requests is None:
        return False
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": text[:3900]},
            timeout=20
        )
        if (r.headers.get("content-type", "") or "").startswith("application/json"):
            return bool((r.json() or {}).get("ok"))
        return r.status_code == 200
    except Exception:
        return False

def _bot_send_media(token: str, chat_id: str, caption: str, mtype: str, path: str) -> bool:
    if requests is None:
        return False
    try:
        with open(path, "rb") as f:
            if mtype == "photo":
                r = requests.post(
                    f"https://api.telegram.org/bot{token}/sendPhoto",
                    data={"chat_id": chat_id, "caption": caption[:950]},
                    files={"photo": f},
                    timeout=45
                )
            elif mtype == "video":
                r = requests.post(
                    f"https://api.telegram.org/bot{token}/sendVideo",
                    data={"chat_id": chat_id, "caption": caption[:950]},
                    files={"video": f},
                    timeout=60
                )
            elif mtype == "video_note":
                r = requests.post(
                    f"https://api.telegram.org/bot{token}/sendVideoNote",
                    data={"chat_id": chat_id},
                    files={"video_note": f},
                    timeout=60
                )
            else:
                r = requests.post(
                    f"https://api.telegram.org/bot{token}/sendDocument",
                    data={"chat_id": chat_id, "caption": caption[:950]},
                    files={"document": f},
                    timeout=60
                )
        if (r.headers.get("content-type", "") or "").startswith("application/json"):
            return bool((r.json() or {}).get("ok"))
        return r.status_code == 200
    except Exception:
        return False

def _build_bot_header(row: dict) -> str:
    from common_paths import get_current_account
    dt = _fmt_dt(row.get("date") or "")
    flag = "DELETED" if int(row.get("is_deleted") or 0) else "TTL"
    chat_type = (row.get("chat_type") or "").capitalize()
    chat_title = row.get("chat_title") or str(row.get("chat_id"))
    sender = row.get("sender") or ""
    username = row.get("username") or "-"
    acct = get_current_account() or ""
    acct_tag = f"[{acct}] " if acct else ""
    return "\n".join([
        f"{acct_tag}[{flag}] {dt}",
        f"{sender} {username}",
        f"[{chat_type}] {chat_title}",
        ""
    ])

def _has_secret_bot() -> bool:
    from common_paths import get_current_account, _ACCOUNTS_DIR
    acct = get_current_account()
    if not acct:
        return False
    accounts_file = os.path.join(_ACCOUNTS_DIR, "..", "accounts.json")
    try:
        with open(accounts_file, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        for a in data.get("accounts", []):
            if a.get("name") == acct:
                return bool(a.get("secret_bot_token") and a.get("secret_bot_chat_id"))
    except Exception:
        pass
    return False

def _is_excluded_from_bot(row: dict) -> bool:
    cfg = load_gui_cfg()
    bot_chat_id = (cfg.get("bot_chat_id") or "").strip()

    if cfg.get("exclude_own_chat", True) and bot_chat_id:
        row_chat = str(row.get("chat_id") or "")
        if row_chat == bot_chat_id:
            return True

    exclude_list = cfg.get("exclude_from_bot") or []
    if not exclude_list:
        return False

    exclude_lower = [str(e).lower().strip() for e in exclude_list if e]
    if not exclude_lower:
        return False

    sender = str(row.get("sender") or "").lower().strip()
    username = str(row.get("username") or "").lower().strip().lstrip("@")
    phone = str(row.get("phone") or "").lower().strip()
    chat_title = str(row.get("chat_title") or "").lower().strip()
    chat_id = str(row.get("chat_id") or "")

    for exc in exclude_lower:
        if exc and (exc == sender or exc == username or exc == phone or exc == chat_title or exc == chat_id):
            return True

    return False

def _notify_bot_for_row(row: dict):
    cfg = load_gui_cfg()
    token = (cfg.get("bot_token") or "").strip()
    chat_id = (cfg.get("bot_chat_id") or "").strip()
    if not cfg.get("send_to_bot") or not token or not chat_id or not chat_id.lstrip("-").isdigit():
        return False
    if int(row.get("sent_to_bot") or 0):
        return True
    if _is_excluded_from_bot(row):
        return False

    header = _build_bot_header(row)
    text = (row.get("text") or "")
    caption = (header + text)[:950]
    media_path = (row.get("media_path") or "").strip()
    media_type = (row.get("media_type") or "").strip()
    if media_path and os.path.exists(media_path):
        ok = _bot_send_media(token, chat_id, caption, media_type, media_path)
    else:
        ok = _bot_send_text(token, chat_id, header + text)
    return ok

def _mark_sent(chat_id: int, msg_id: int):
    conn = _conn()
    cur = conn.cursor()
    cur.execute("UPDATE messages SET sent_to_bot=1 WHERE chat_id=? AND msg_id=?", (int(chat_id), int(msg_id)))
    conn.commit()
    conn.close()

def _fetch_message_row(chat_id: int, msg_id: int) -> dict | None:
    conn = _conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM messages WHERE chat_id=? AND msg_id=? LIMIT 1", (int(chat_id), int(msg_id)))
    row = cur.fetchone()
    if row is None and int(chat_id) == 0:
        cur.execute("SELECT * FROM messages WHERE msg_id=? ORDER BY date DESC LIMIT 1", (int(msg_id),))
        row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def _repair_session_schema(session_base_val: str):
    session_path = session_base_val + ".session"
    if not os.path.exists(session_path):
        return
    expected = _detect_session_cols()
    src = None
    dst = None
    temp_path = session_path + ".fixed"
    try:
        src = sqlite3.connect(f"file:{session_path}?mode=ro&immutable=1", uri=True, timeout=10)
        cur = src.cursor()
        cols = cur.execute("PRAGMA table_info(sessions)").fetchall()
        col_names = [str(c[1]) for c in cols]
        if col_names == expected:
            return
        # need to migrate
        create_sql, ins_cols, ins_vals, sel_sql = _session_cols_sql(expected)
        backup_path = session_path + f".bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(session_path, backup_path)
        dst = sqlite3.connect(temp_path, timeout=10)
        src.backup(dst)
        cur = dst.cursor()
        cur.execute("BEGIN")
        cur.execute(f"""
            CREATE TABLE sessions_fixed ({create_sql})
        """)
        if len(expected) == 6 and "tmp_auth_key" not in col_names:
            cur.execute(f"""
                INSERT INTO sessions_fixed {ins_cols}
                SELECT dc_id, server_address, port, auth_key, NULL, takeout_id
                FROM sessions
            """)
        elif len(expected) == 5 and "tmp_auth_key" in col_names:
            cur.execute(f"""
                INSERT INTO sessions_fixed {ins_cols}
                SELECT dc_id, server_address, port, auth_key, takeout_id
                FROM sessions
            """)
        else:
            cur.execute(f"""
                INSERT INTO sessions_fixed {ins_cols} {sel_sql}
            """)
        cur.execute("DROP TABLE sessions")
        cur.execute("ALTER TABLE sessions_fixed RENAME TO sessions")
        dst.commit()
        try:
            stale_journal = session_path + "-journal"
            if os.path.exists(stale_journal):
                os.replace(stale_journal, stale_journal + f".stale_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        except Exception:
            pass
        os.replace(temp_path, session_path)
        _log(f"session schema repaired to {len(expected)} cols, backup={os.path.basename(backup_path)}")
    except Exception:
        if dst is not None:
            try:
                dst.rollback()
            except Exception:
                pass
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass
        _log("session repair failed:\n" + traceback.format_exc())
    finally:
        if dst is not None:
            try:
                dst.close()
            except Exception:
                pass
        if src is not None:
            try:
                src.close()
            except Exception:
                pass

def _bootstrap_session_from_legacy(session_base_val: str, legacy_base: str):
    session_path = session_base_val + ".session"
    legacy_path = legacy_base + ".session"
    if os.path.exists(session_path) or not os.path.exists(legacy_path):
        return
    src = None
    dst = None
    try:
        os.makedirs(os.path.dirname(session_path), exist_ok=True)
        src = sqlite3.connect(f"file:{legacy_path}?mode=ro&immutable=1", uri=True, timeout=10)
        expected = _detect_session_cols()
        create_sql, ins_cols, ins_vals, sel_sql = _session_cols_sql(expected)
        row = src.execute(sel_sql).fetchone()
        if not row:
            return
        dst = sqlite3.connect(session_path, timeout=10)
        cur = dst.cursor()
        cur.execute("CREATE TABLE version (version integer primary key)")
        cur.execute(f"""
            CREATE TABLE sessions ({create_sql})
        """)
        cur.execute("""
            CREATE TABLE entities (
                id integer primary key,
                hash integer not null,
                username text,
                phone integer,
                name text,
                date integer
            )
        """)
        cur.execute("""
            CREATE TABLE sent_files (
                md5_digest blob,
                file_size integer,
                type integer,
                id integer,
                hash integer,
                primary key(md5_digest, file_size, type)
            )
        """)
        cur.execute("""
            CREATE TABLE update_state (
                id integer primary key,
                pts integer,
                qts integer,
                date integer,
                seq integer
            )
        """)
        cur.execute("INSERT INTO version VALUES (?)", (telethon_sqlite.CURRENT_VERSION,))
        cur.execute(f"INSERT INTO sessions {ins_cols} VALUES {ins_vals}", row)
        dst.commit()
        _log(f"session migrated to temp storage: {session_path}")
    except Exception:
        _log("session bootstrap failed:\n" + traceback.format_exc())
    finally:
        if dst is not None:
            try:
                dst.close()
            except Exception:
                pass
        if src is not None:
            try:
                src.close()
            except Exception:
                pass

def _build_runtime_session():
    sb = session_base()
    lb = legacy_session_base()
    for base in (sb, lb):
        session_path = base + ".session"
        if not os.path.exists(session_path):
            continue
        try:
            conn = sqlite3.connect(f"file:{session_path}?mode=ro&immutable=1", uri=True, timeout=10)
            row = conn.execute(
                "SELECT dc_id, server_address, port, auth_key, takeout_id FROM sessions LIMIT 1"
            ).fetchone()
            conn.close()
            if not row:
                continue
            _log(f"session found at {session_path}, using SQLiteSession directly")
            return base
        except Exception:
            _log(f"runtime session load failed from {session_path}:\n" + traceback.format_exc())
    return sb

def _conn():
    c = sqlite3.connect(db_path(), timeout=30)
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("PRAGMA busy_timeout=30000;")
    c.row_factory = sqlite3.Row
    return c

def ensure_schema():
    conn = _conn()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        msg_id  INTEGER NOT NULL,
        chat_title TEXT DEFAULT '',
        chat_type  TEXT DEFAULT '',
        sender   TEXT,
        username TEXT,
        phone    TEXT,
        date     TEXT,
        text     TEXT,
        media_path TEXT,
        media_type TEXT,
        is_deleted INTEGER DEFAULT 0,
        deletion_date TEXT,
        is_ephemeral INTEGER DEFAULT 0,
        sent_to_bot INTEGER DEFAULT 0,
    is_outgoing INTEGER DEFAULT 0,
    UNIQUE(chat_id, msg_id)
    )
    """)
    try:
        conn.execute("ALTER TABLE messages ADD COLUMN is_outgoing INTEGER DEFAULT 0")
    except Exception:
        pass
    conn.commit()
    conn.close()
    run_cleanup(load_settings(), logger=_log)

def _chat_kind_from_entity(ent) -> str:
    try:
        if getattr(ent, "broadcast", False):
            return "channel"
        if getattr(ent, "megagroup", False):
            return "group"
    except Exception:
        pass
    try:
        if hasattr(ent, "first_name"):
            return "private"
    except Exception:
        pass
    return "group"

def _allowed(chat_type: str, s: dict) -> bool:
    if chat_type == "private":
        return bool(s.get("capture_private", True))
    if chat_type == "group":
        return bool(s.get("capture_group", True))
    if chat_type == "channel":
        return bool(s.get("capture_channel", True))
    return True

async def _resolve_chat_info(client: TelegramClient, msg: Message) -> tuple[int, str, str]:
    ent = None
    try:
        ent = await client.get_entity(msg.peer_id)
    except Exception:
        try:
            ent = await msg.get_chat()
        except Exception:
            ent = None

    chat_id = int(getattr(ent, "id", 0) or 0)
    if not chat_id:
        try:
            chat_id = int(getattr(msg, "chat_id", 0) or 0)
        except Exception:
            chat_id = 0
    if not chat_id:
        try:
            peer = getattr(msg, "peer_id", None)
            chat_id = int(
                getattr(peer, "channel_id", 0)
                or getattr(peer, "chat_id", 0)
                or getattr(peer, "user_id", 0)
                or 0
            )
        except Exception:
            chat_id = 0

    chat_title = getattr(ent, "title", "") or getattr(ent, "first_name", "") or str(chat_id or "unknown")
    chat_type = _chat_kind_from_entity(ent) if ent is not None else ("private" if getattr(msg, "is_private", False) else "group")
    return chat_id, chat_title, chat_type

def _media_type(msg: Message) -> str:
    try:
        if getattr(msg, "photo", None):
            return "photo"
        if getattr(msg, "video", None):
            return "video"
        try:
            if getattr(msg, "voice", None) is not None:
                return "voice"
        except Exception:
            pass
        if getattr(msg, "document", None):
            if getattr(msg, "video_note", False):
                return "video_note"
            return "document"
    except Exception:
        pass
    return ""

def _ttl_seconds(msg: Message) -> int:
    for attr in ("ttl_period", "ttl_seconds"):
        try:
            v = getattr(msg, attr, None)
            if v:
                return int(v)
        except Exception:
            pass
    try:
        m = getattr(msg, "media", None)
        v = getattr(m, "ttl_seconds", None)
        if v:
            return int(v)
    except Exception:
        pass
    return 0

_SERVICE_SENDER_IDS = {777000, 148900897, 136817688}
_SERVICE_SENDER_NAMES = {"telegram", "tg", "telegram notifications"}

def _is_service_message(sender, text: str) -> bool:
    try:
        if sender:
            sid = getattr(sender, "id", 0)
            if sid in _SERVICE_SENDER_IDS:
                return True
            uname = str(getattr(sender, "username", "") or "").lower().strip()
            if uname in _SERVICE_SENDER_NAMES:
                return True
            sname = str(getattr(sender, "first_name", "") or "").lower().strip()
            if sname in _SERVICE_SENDER_NAMES:
                return True
    except Exception:
        pass
    if text:
        t = text.strip()
        if re.match(r'^\d{5,6}$', t):
            return True
        if re.match(r'(?i)^(login code|код для входа|verification code|код подтверждения|your code|ваш код|code[:\s])', t):
            return True
    return False

def _save_message_sync(chat_id, msg_id, chat_title, chat_type, sender_name, username, phone, dt_iso, text, media_path, media_type, is_ephemeral, is_outgoing):
    conn = _conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT OR IGNORE INTO messages
        (chat_id, msg_id, chat_title, chat_type, sender, username, phone, date, text,
         media_path, media_type, is_deleted, deletion_date, is_ephemeral, sent_to_bot, is_outgoing)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        chat_id, int(msg_id), str(chat_title), str(chat_type),
        sender_name, username, phone,
        dt_iso, text,
        media_path, media_type,
        0, None,
        is_ephemeral, 0,
        is_outgoing
    ))
    cur.execute("""
        UPDATE messages SET
            chat_title=?,
            chat_type=?,
            sender=?,
            username=?,
            phone=?,
            date=?,
            text=?,
            media_path=?,
            media_type=?,
            is_ephemeral=CASE WHEN ?=1 THEN 1 ELSE is_ephemeral END,
            is_outgoing=CASE WHEN is_outgoing=0 AND ?=1 THEN 1 ELSE is_outgoing END
        WHERE chat_id=? AND msg_id=?
    """, (
        str(chat_title), str(chat_type),
        sender_name, username, phone,
        dt_iso, text,
        media_path if media_path else None, media_type if media_type else None,
        int(is_ephemeral),
        int(is_outgoing),
        chat_id, int(msg_id)
    ))
    conn.commit()
    conn.close()

async def _save_message(client: TelegramClient, msg: Message):
    s = load_settings()
    light_mode = s.get("storage_mode", "light") == "light"

    chat_id, chat_title, chat_type = await _resolve_chat_info(client, msg)

    if not _allowed(chat_type, s):
        return

    sender_name = ""
    username = ""
    phone = ""
    sender = None

    try:
        sender = await msg.get_sender()
        if sender:
            sender_name = " ".join(
                [p for p in [getattr(sender, "first_name", ""), getattr(sender, "last_name", "")] if p]
            ).strip()
            username = getattr(sender, "username", "") or ""
            phone = getattr(sender, "phone", "") or ""
    except Exception:
        pass

    if _is_service_message(sender if sender else None, msg.message or ""):
        return

    is_outgoing = 1 if getattr(msg, "out", False) else 0

    dt = msg.date
    try:
        if dt and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    dt_iso = dt.isoformat() if dt else ""

    text = msg.message or ""

    is_ephemeral = 1 if _ttl_seconds(msg) > 0 else 0
    media_path = None
    media_type = _media_type(msg)

    if not light_mode and media_type and ((not is_ephemeral) or bool(s.get("download_ephemeral", True))):
        try:
            fname = f"{chat_id}_{msg.id}"
            media_path = await client.download_media(msg, file=os.path.join(media_folder(), fname))
            if media_path:
                media_path = os.path.abspath(media_path)
        except Exception as e:
            _log(f"download_media failed chat={chat_id} msg={msg.id}: {e}")

    await asyncio.to_thread(
        _save_message_sync,
        chat_id, int(msg.id), str(chat_title), str(chat_type),
        sender_name, username, phone, dt_iso, text,
        media_path, media_type, is_ephemeral, is_outgoing
    )

def _mark_deleted_sync(chat_id: int, msg_id: int):
    conn = _conn()
    cur = conn.cursor()
    deleted_at = datetime.now(timezone.utc).isoformat()
    if chat_id:
        cur.execute("""
            UPDATE messages SET is_deleted=1, deletion_date=?
            WHERE chat_id=? AND msg_id=? AND is_deleted=0
        """, (deleted_at, int(chat_id), int(msg_id)))
        if cur.rowcount == 0:
            cur.execute("""
                UPDATE messages SET is_deleted=1, deletion_date=?
                WHERE msg_id=? AND is_deleted=0
            """, (deleted_at, int(msg_id)))
    else:
        cur.execute("""
            UPDATE messages SET is_deleted=1, deletion_date=?
            WHERE msg_id=? AND is_deleted=0
        """, (deleted_at, int(msg_id)))
    conn.commit()
    conn.close()

async def main():
    print("[receiver] starting main()")
    _ensure_dirs()
    ensure_schema()
    _patch_telethon_sqlite_session()
    _bootstrap_session_from_legacy(session_base(), legacy_session_base())
    _repair_session_schema(session_base())

    if not API_ID or not API_HASH:
        _log("API_ID/API_HASH not set via AR_API_ID / AR_API_HASH env vars")
        print("[receiver] API_ID/API_HASH not set")
        return

    runtime_base = _build_runtime_session()
    print(f"[receiver] using session base: {runtime_base}")
    print(f"[receiver] session file exists: {os.path.exists(runtime_base + '.session')}")
    sys.stdout.flush()

    try:
        client = TelegramClient(runtime_base, API_ID, API_HASH)
        print(f"[receiver] created TelegramClient, connecting...")
    except Exception as e:
        print(f"[receiver] ERROR creating TelegramClient: {e}")
        traceback.print_exc()
        return

    sys.stdout.flush()
    try:
        await client.start()
        print(f"[receiver] client.start() completed, user: {await client.get_me()}")
    except Exception as e:
        print(f"[receiver] ERROR in client.start(): {e}")
        traceback.print_exc()
        return
    sys.stdout.flush()

    @client.on(events.NewMessage)
    async def on_new(event):
        try:
            await _save_message(client, event.message)
        except Exception:
            _log("on_new exception:\n" + traceback.format_exc())

    @client.on(events.MessageDeleted)
    async def on_del(event):
        try:
            cid = int(event.chat_id or 0)
            for mid in event.deleted_ids:
                await asyncio.to_thread(_mark_deleted_sync, cid, int(mid))
        except Exception:
            _log("on_del exception:\n" + traceback.format_exc())

    @client.on(events.Raw)
    async def on_raw(update):
        try:
            if isinstance(update, UpdateDeleteChannelMessages):
                cid = int(getattr(update, "channel_id", 0) or 0)
                for mid in getattr(update, "messages", []) or []:
                    await asyncio.to_thread(_mark_deleted_sync, cid, int(mid))
            elif isinstance(update, UpdateDeleteMessages):
                for mid in getattr(update, "messages", []) or []:
                    await asyncio.to_thread(_mark_deleted_sync, 0, int(mid))
        except Exception:
            _log("on_raw delete exception:\n" + traceback.format_exc())

    print("[receiver] Receiver started, waiting for events...")
    _log("Receiver started")
    await client.run_until_disconnected()
    print("[receiver] disconnected")

if __name__ == "__main__":
    try:
        import asyncio
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception:
        _log("FATAL:\n" + traceback.format_exc())
        print("[receiver] FATAL:\n" + traceback.format_exc())
        sys.stdout.flush()
