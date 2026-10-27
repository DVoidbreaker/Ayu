import os, re, sys, json, sqlite3, subprocess, time, shutil, tempfile, zipfile, secrets, hmac, asyncio, threading
import hashlib, binascii
from datetime import datetime

try:
    import requests
except Exception:
    requests = None

from flask import Flask, request, jsonify, Response, abort, send_from_directory, send_file, Blueprint

from auth_layer import (
    AUTH_COOKIE_NAME,
    DEVICE_COOKIE_NAME,
    POLL_INTERVAL_SEC,
    build_device_hash,
    build_user_agent_hash,
    cleanup_expired,
    create_access_token,
    create_auth_request,
    ensure_polling_started_for_account,
    get_auth_request,
    get_or_create_device_id,
    init_auth_db,
    is_trusted_device,
    parse_access_token,
    send_telegram_approval_request,
    touch_trusted_device,
    trust_device,
    update_auth_request_message,
)
from common_paths import BASE_DIR, set_account, get_current_account, db_path, settings_file, gui_cfg_file, log_dir, media_folder, account_dir, legacy_session_base
from storage_cleanup import get_storage_usage_bytes, normalize_cleanup_settings, run_cleanup

ACCOUNTS_CONFIG_PATH = os.path.join(BASE_DIR, "accounts.json")
PASSWORDS_CONFIG_PATH = os.path.join(BASE_DIR, "passwords.json")

# --- Brute-force protection -------------------------------------------------
# Shared password is the master key to every account, so gate it behind a
# simple per-IP attempt limiter. Too many wrong attempts -> temporary lockout.
_AUTH_FAILS = {}          # ip -> [first_fail_ts, fail_count]
_AUTH_LOCKS = {}          # ip -> locked_until_ts
_AUTH_WINDOW_SEC = 300    # sliding window for counting failures
_AUTH_MAX_FAILS = 5       # wrong attempts allowed within the window
_AUTH_LOCK_SEC = 300      # lockout duration once the limit is exceeded


def _client_key():
    """Per-client key for rate limiting (real IP behind proxy when present)."""
    forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return forwarded or (request.remote_addr or "unknown")


def _auth_locked(key):
    """Return remaining lockout seconds (0 = not locked)."""
    until = _AUTH_LOCKS.get(key)
    if not until:
        return 0
    now = time.time()
    if now >= until:
        _AUTH_LOCKS.pop(key, None)
        _AUTH_FAILS.pop(key, None)
        return 0
    return int(until - now) + 1


def _auth_register_fail(key):
    """Record a failed password attempt; lock the key when it exceeds the max."""
    now = time.time()
    entry = _AUTH_FAILS.get(key)
    if not entry or (now - entry[0]) > _AUTH_WINDOW_SEC:
        entry = [now, 0]
    entry[1] += 1
    _AUTH_FAILS[key] = entry
    if entry[1] >= _AUTH_MAX_FAILS:
        _AUTH_LOCKS[key] = now + _AUTH_LOCK_SEC
        _AUTH_FAILS.pop(key, None)


def _auth_clear(key):
    _AUTH_FAILS.pop(key, None)


def _safe_eq(a, b):
    """Constant-time string comparison (defends against timing attacks)."""
    return hmac.compare_digest((a or "").encode("utf-8"),
                               (b or "").encode("utf-8"))


# --- Password hashing ---------------------------------------------------
# SECURITY FIX: passwords.json used to store every password (secret,
# registration, deletion, admin) in plain text on disk. Anyone who can read
# that one file (a misconfigured volume, a backup, a Docker image layer
# that accidentally included it, another local process) recovers every
# password immediately. Passwords are now salted + hashed with PBKDF2-HMAC
# (stdlib `hashlib`, no extra dependency) and only the hash is ever
# persisted; legacy plain-text values are transparently migrated to hashes
# the first time they are read.
_PBKDF2_ALGO = "pbkdf2_sha256"
_PBKDF2_ITERATIONS = 390_000


def _hash_password(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return f"{_PBKDF2_ALGO}${_PBKDF2_ITERATIONS}${binascii.hexlify(salt).decode()}${binascii.hexlify(dk).decode()}"


def _is_hashed_password(value):
    return isinstance(value, str) and value.startswith(_PBKDF2_ALGO + "$")


def _verify_password(password, stored):
    """Compare a user-supplied password against a stored value. Supports
    both the new hashed format and (defensively) a legacy plain-text value,
    so verification never breaks while a password.json is mid-migration."""
    stored = stored or ""
    if not password:
        return False
    if not _is_hashed_password(stored):
        # Not yet migrated (should be rare - _load_passwords migrates on
        # read) - fall back to a constant-time plain comparison.
        return _safe_eq(password, stored)
    try:
        _algo, iterations, salt_hex, hash_hex = stored.split("$")
        salt = binascii.unhexlify(salt_hex)
        expected = binascii.unhexlify(hash_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def _unlink_quiet(path):
    try:
        os.unlink(path)
    except Exception:
        pass


# --- In-browser Telegram login (creates the .session file) -------------------
# Lets a user authorize a freshly added account right from the web panel
# (phone -> code -> optional 2FA) instead of uploading a .session by hand.
_LOGIN_LOCK = threading.Lock()
_LOGIN_STATES = {}     # account -> {"client", "phone", "phone_code_hash"}
_LOGIN_LOOP = None
_LOGIN_LOOP_THREAD = None


def _ensure_login_loop():
    """Start a dedicated asyncio loop in a daemon thread (shared by all logins)."""
    global _LOGIN_LOOP, _LOGIN_LOOP_THREAD
    if _LOGIN_LOOP is not None:
        return _LOGIN_LOOP
    with _LOGIN_LOCK:
        if _LOGIN_LOOP is not None:
            return _LOGIN_LOOP
        loop = asyncio.new_event_loop()

        def _runner():
            asyncio.set_event_loop(loop)
            loop.run_forever()

        t = threading.Thread(target=_runner, name="tg-login-loop", daemon=True)
        t.start()
        _LOGIN_LOOP = loop
        _LOGIN_LOOP_THREAD = t
        return loop


def _run_login_coro(coro, timeout=60):
    """Run a coroutine on the shared login loop and wait for the result."""
    loop = _ensure_login_loop()
    fut = asyncio.run_coroutine_threadsafe(coro, loop)
    return fut.result(timeout=timeout)


def _login_session_base(account_name):
    # Legacy path: accounts/<name>/anti_revoke  -> writes accounts/<name>/anti_revoke.session
    # The receiver bootstraps this file into its runtime session dir automatically.
    set_account(account_name)
    return legacy_session_base()


def _normalize_phone(raw):
    """Coerce a user-typed phone into strict international form (+<digits>).

    If the number already carries a leading "+" (with or without spaces,
    dashes, parentheses typed around it), it is trusted as-is and only
    cleaned up - no country is ever guessed for it. Country-guessing only
    kicks in for a number typed *without* a "+", and is intentionally
    narrow (exact digit-count + prefix) so it never reinterprets a number
    that is already a valid, different country's number:

      Russia    89XXXXXXXXX (11 digits) / 9XXXXXXXXX (10 digits)  -> +7...
      Ukraine   80XXXXXXXXX (11 digits) / 0XXXXXXXXX (10 digits)  -> +380...

    BUG FIX: Ukrainian numbers typed in their local form - e.g. the common
    "0501234567" (10 digits, national trunk "0") or the older
    "80501234567" (11 digits, Soviet-style "8" trunk prefix, analogous to
    the Russian 89... convention) - used to fall through to the generic
    "just add a +" path, producing "+0501234567" / "+80501234567": not a
    real number, so Telegram either rejected it outright or simply never
    delivered a code. Only +7/+380 are special-cased on purpose; any other
    country typed without a "+" is left as typed (digits only, "+" in
    front) rather than guessed, since guessing wrong silently sends the
    code to a different, unrelated number.
    """
    p = re.sub(r"[^\d+]", "", str(raw or "").strip())
    if p.startswith("+"):
        return "+" + re.sub(r"\D", "", p)
    digits = re.sub(r"\D", "", p)
    if len(digits) == 11 and digits.startswith("89"):
        digits = "7" + digits[1:]
    elif len(digits) == 10 and digits.startswith("9"):
        digits = "7" + digits
    elif len(digits) == 11 and digits.startswith("80"):
        digits = "380" + digits[2:]
    elif len(digits) == 10 and digits.startswith("0"):
        digits = "380" + digits[1:]
    return "+" + digits


async def _tg_send_code(account_name, api_id, api_hash, phone, force_sms=False):
    from telethon import TelegramClient
    # Drop any previous login attempt for this account: a leftover connected
    # client would keep holding the same .session file (SQLite lock) and can
    # make the new code request silently fail.
    await _tg_discard(account_name)
    base = _login_session_base(account_name)
    client = TelegramClient(base, int(api_id), str(api_hash))
    await client.connect()
    try:
        # force_sms=True makes Telegram deliver by SMS instead of into the
        # Telegram app - the fallback when the code went "в приложение" but
        # the user cannot find it there.
        sent = await client.send_code_request(phone, force_sms=force_sms)
    except Exception as e:
        try:
            await client.disconnect()
        except Exception:
            pass
        ename = type(e).__name__
        if "FloodWait" in ename:
            secs = int(getattr(e, "seconds", 60) or 60)
            mins = max(1, (secs + 59) // 60)
            raise RuntimeError(
                f"Telegram ограничил отправку кодов с этого адреса. "
                f"Подождите ~{mins} мин. и запросите код заново."
            ) from e
        if "PhoneNumberInvalid" in ename:
            raise RuntimeError("Номер телефона некорректен — проверьте формат.") from e
        if "PhoneNumberBanned" in ename:
            raise RuntimeError("Этот номер заблокирован Telegram.") from e
        if "ApiIdInvalid" in ename:
            raise RuntimeError("api_id/api_hash не приняты Telegram — проверьте их на my.telegram.org.") from e
        raise
    # Where did Telegram deliver the code? For a number that is already logged
    # in on another device the code goes to the Telegram app (official chat),
    # not via SMS — tell the user so they know where to look.
    via = "app"
    try:
        tname = type(sent.type).__name__
        if "Sms" in tname:
            via = "sms"
        elif "App" in tname:
            via = "app"
        else:
            via = tname
    except Exception:
        via = "unknown"
    with _LOGIN_LOCK:
        _LOGIN_STATES[account_name] = {
            "client": client,
            "phone": phone,
            "phone_code_hash": sent.phone_code_hash,
        }
    return via


async def _tg_sign_in(account_name, code, password_2fa):
    with _LOGIN_LOCK:
        st = _LOGIN_STATES.get(account_name)
    if not st:
        return False, "Сессия входа не найдена. Начните заново."
    client = st["client"]
    phone = st["phone"]
    phone_code_hash = st["phone_code_hash"]
    try:
        from telethon.errors import SessionPasswordNeededError
    except Exception:
        SessionPasswordNeededError = None
    try:
        await client.sign_in(phone=phone, code=code, phone_code_hash=phone_code_hash)
    except Exception as e:
        need_pw = SessionPasswordNeededError is not None and isinstance(e, SessionPasswordNeededError)
        if not need_pw:
            await _tg_discard(account_name)
            return False, f"Код неверен или истёк: {e}"
        if not password_2fa:
            # 2FA is enabled: ask the client for the cloud password next step.
            return False, "__NEED_2FA__"
        try:
            await client.sign_in(password=password_2fa)
        except Exception as e2:
            await _tg_discard(account_name)
            return False, f"Неверный пароль двухфакторной защиты: {e2}"
    # Success: the client has already persisted the auth key into the .session file.
    try:
        await client.disconnect()
    except Exception:
        pass
    with _LOGIN_LOCK:
        _LOGIN_STATES.pop(account_name, None)
    return True, None


async def _tg_discard(account_name):
    with _LOGIN_LOCK:
        st = _LOGIN_STATES.pop(account_name, None)
    if st and st.get("client"):
        try:
            await st["client"].disconnect()
        except Exception:
            pass


def _load_accounts_config():
    try:
        with open(ACCOUNTS_CONFIG_PATH, "r", encoding="utf-8-sig") as f:
            return json.load(f) or {}
    except Exception:
        return {}

def _get_account_list():
    cfg = _load_accounts_config()
    return cfg.get("accounts", [])

def _find_account(name):
    for acct in _get_account_list():
        if acct.get("name") == name:
            return acct
    return None

ACCOUNT_CACHE = {}

def _log_for(account_name, line):
    set_account(account_name)
    try:
        ld = log_dir()
        os.makedirs(ld, exist_ok=True)
        with open(os.path.join(ld, "web.log"), "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} [{account_name}] {line}\n")
    except Exception:
        pass

DEFAULT_SETTINGS = {
    "capture_private": True,
    "capture_group": True,
    "capture_channel": True,
    "download_ephemeral": True,
    "ui_scale": 100,
    "retention_days": 30,
    "storage_soft_limit_mb": 420,
    "storage_target_mb": 360,
}

def _load_settings(account_name):
    set_account(account_name)
    sf = settings_file()
    try:
        if not os.path.exists(sf):
            with open(sf, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_SETTINGS, f, ensure_ascii=False, indent=2)
            return dict(DEFAULT_SETTINGS)
        with open(sf, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        out = dict(DEFAULT_SETTINGS)
        out.update(data)
        out = normalize_cleanup_settings(out)
        out["ui_scale"] = int(out.get("ui_scale") or 100)
        if out["ui_scale"] < 70: out["ui_scale"] = 70
        if out["ui_scale"] > 140: out["ui_scale"] = 140
        for k in ("capture_private", "capture_group", "capture_channel", "download_ephemeral"):
            out[k] = bool(out.get(k, DEFAULT_SETTINGS[k]))
        return out
    except Exception:
        return dict(DEFAULT_SETTINGS)

def _save_settings(account_name, s):
    out = _load_settings(account_name)
    out.update(s or {})
    out = normalize_cleanup_settings(out)
    out["ui_scale"] = int(out.get("ui_scale") or 100)
    if out["ui_scale"] < 70: out["ui_scale"] = 70
    if out["ui_scale"] > 140: out["ui_scale"] = 140
    for k in ("capture_private", "capture_group", "capture_channel", "download_ephemeral"):
        out[k] = bool(out.get(k, DEFAULT_SETTINGS[k]))
    set_account(account_name)
    sf = settings_file()
    with open(sf, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

DEFAULT_GUI = {
    "bot_token": "",
    "bot_chat_id": "",
    "send_to_bot": False,
    "access_control_enabled": True,
    "access_chat_id": "",
    "auth_timeout_sec": 180,
    "trust_days": 30,
    "auth_secret": "",
    "exclude_own_chat": True,
    "exclude_from_bot": [],
}

def _load_gui_cfg(account_name):
    set_account(account_name)
    gf = gui_cfg_file()
    try:
        if not os.path.exists(gf):
            seed = dict(DEFAULT_GUI)
            seed["auth_secret"] = secrets.token_urlsafe(48)
            with open(gf, "w", encoding="utf-8") as f:
                json.dump(seed, f, ensure_ascii=False, indent=2)
            return seed
        with open(gf, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        out = dict(data)
        for k, v in DEFAULT_GUI.items():
            if k not in out:
                out[k] = v
        if not out.get("auth_secret"):
            out["auth_secret"] = secrets.token_urlsafe(48)
            with open(gf, "w", encoding="utf-8") as f:
                merged = dict(data)
                merged.update(out)
                json.dump(merged, f, ensure_ascii=False, indent=2)
        out["send_to_bot"] = bool(out.get("send_to_bot", False))
        out["access_control_enabled"] = bool(out.get("access_control_enabled", True))
        out["auth_timeout_sec"] = max(30, min(int(out.get("auth_timeout_sec") or 180), 900))
        out["trust_days"] = max(1, min(int(out.get("trust_days") or 30), 365))
        return out
    except Exception:
        fallback = dict(DEFAULT_GUI)
        fallback["auth_secret"] = secrets.token_urlsafe(48)
        return fallback

def _save_gui_cfg(account_name, cfg):
    out = _load_gui_cfg(account_name)
    out.update(cfg or {})
    out["send_to_bot"] = bool(out.get("send_to_bot", False))
    out["access_control_enabled"] = bool(out.get("access_control_enabled", True))
    out["auth_timeout_sec"] = max(30, min(int(out.get("auth_timeout_sec") or 180), 900))
    out["trust_days"] = max(1, min(int(out.get("trust_days") or 30), 365))
    if not out.get("auth_secret"):
        out["auth_secret"] = secrets.token_urlsafe(48)
    set_account(account_name)
    gf = gui_cfg_file()
    with open(gf, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

def _save_accounts_config(cfg):
    tmp = ACCOUNTS_CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, ACCOUNTS_CONFIG_PATH)


# --- Passwords file (passwords.json) -----------------------------------------
# Stores the three app passwords in one place. Right now all three are the
# same value; they can be split apart later without touching call sites.
PASSWORD_KEYS = ("secret_password", "registration_password", "deletion_password", "admin_password")


def _default_passwords():
    return {k: "" for k in PASSWORD_KEYS}


def _load_passwords():
    """Read passwords.json. If missing/empty, seed it from the legacy shared
    password in accounts.json so existing installs keep working.

    SECURITY FIX: any plain-text password found on disk (from an older
    version of this app, or from a hand-edited file) is transparently
    re-hashed and persisted here, so passwords.json converges to
    hashed-only storage without any manual migration step."""
    pw = _default_passwords()
    changed = False
    try:
        with open(PASSWORDS_CONFIG_PATH, "r", encoding="utf-8-sig") as f:
            data = json.load(f) or {}
        for k in PASSWORD_KEYS:
            raw = str(data.get(k) or "").strip()
            if k == "admin_password" and raw == _LEAKED_DEFAULT_ADMIN_PASSWORD:
                # SECURITY: this exact value was hard-coded in the source
                # (and is now publicly known / documented in the security
                # audit). Never migrate it as-is, even hashed - treat it as
                # unset so _ensure_admin_password_initialized() mints a
                # brand-new random one instead of perpetuating a leaked
                # credential.
                raw = ""
                changed = True
            elif raw and not _is_hashed_password(raw):
                raw = _hash_password(raw)
                changed = True
            pw[k] = raw
    except FileNotFoundError:
        pass
    except Exception:
        pass

    if not any(pw.get(k) for k in ("secret_password", "registration_password", "deletion_password")):
        # No passwords file (or empty) -> migrate from the old shared password.
        legacy = _legacy_shared_password()
        if legacy:
            hashed = _hash_password(legacy)
            for k in ("secret_password", "registration_password", "deletion_password"):
                pw[k] = hashed
            changed = True

    if changed:
        _save_passwords(pw)
    return pw


def _save_passwords(pw):
    # Merge: keys missing from `pw` keep their current value on disk, so a
    # partial update (e.g. setting the shared password) never wipes others.
    # Raw read (no _load_passwords) to avoid the migration recursion.
    current = {}
    try:
        with open(PASSWORDS_CONFIG_PATH, "r", encoding="utf-8-sig") as f:
            current = json.load(f) or {}
    except Exception:
        current = {}
    for k in PASSWORD_KEYS:
        if k not in pw and str(current.get(k) or "").strip():
            pw[k] = current[k]
    tmp = PASSWORDS_CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({k: str(pw.get(k, "") or "") for k in PASSWORD_KEYS}, f,
                  ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, PASSWORDS_CONFIG_PATH)


def _legacy_shared_password():
    """Old source of truth: top-level "secret_password" in accounts.json,
    falling back to the first non-empty per-account value. Kept only to seed
    passwords.json on first run (migration)."""
    cfg = _load_accounts_config()
    pwd = str(cfg.get("secret_password") or "").strip()
    if pwd:
        return pwd
    for acct in cfg.get("accounts") or []:
        pwd = str(acct.get("secret_password") or "").strip()
        if pwd:
            return pwd
    return ""


def _get_shared_secret_password():
    """The secret password (from passwords.json). Falls back to the legacy
    accounts.json value for installs that predate passwords.json."""
    pw = _load_passwords()
    return str(pw.get("secret_password") or "").strip() or _legacy_shared_password()


def _get_registration_password():
    pw = _load_passwords()
    return str(pw.get("registration_password") or "").strip() or _get_shared_secret_password()


def _get_deletion_password():
    pw = _load_passwords()
    return str(pw.get("deletion_password") or "").strip() or _get_shared_secret_password()


# SECURITY: this was the hard-coded default admin password shipped in the
# source code (and now also documented in the security audit) - it must
# never be treated as a valid/current password again, see _load_passwords().
_LEAKED_DEFAULT_ADMIN_PASSWORD = "uC1dyF7hoA5izT0"

# SECURITY FIX: there used to be a hard-coded default admin password here
# ("uC1dyF7hoA5izT0"), published in the source code, that unlocked
# `/api/admin/export` - a full dump of accounts.json, passwords.json and
# every account's live Telegram .session file (= account takeover) for
# anyone who had ever seen this file and whose operator never changed it.
# A random admin password is now generated and hashed into passwords.json
# on first startup (see `_ensure_admin_password_initialized`, called from
# `create_app()`); there is no built-in fallback value any more.


def _get_admin_password():
    pw = _load_passwords()
    return str(pw.get("admin_password") or "").strip()


def _ensure_admin_password_initialized():
    """Generate a random admin password on first run and print it once.
    Idempotent: does nothing once passwords.json already has one."""
    pw = _load_passwords()
    if pw.get("admin_password"):
        return
    generated = secrets.token_urlsafe(24)
    pw["admin_password"] = _hash_password(generated)
    _save_passwords(pw)
    print("=" * 72)
    print("[SECURITY] Сгенерирован пароль админ-панели (/api/admin/*):")
    print(f"[SECURITY]   {generated}")
    print("[SECURITY] Он хранится только в виде хеша и повторно показан не будет.")
    print("[SECURITY] Сохраните его в надёжном месте (например, в менеджере паролей).")
    print("=" * 72)


def _verify_admin_password(password):
    """Gate for the global admin panel. Returns (ok, error_message)."""
    password = (password or "").strip()
    key = "admin:" + _client_key()

    locked = _auth_locked(key)
    if locked:
        return False, f"Слишком много попыток. Попробуйте через {locked} сек."

    admin_hash = _get_admin_password()
    if not admin_hash:
        # Should not happen in normal operation (initialized at startup),
        # but never fail open: with no admin password configured, admin
        # login is refused outright rather than silently allowed.
        return False, "Пароль администратора не настроен. Обратитесь к оператору сервиса."

    if not password or not _verify_password(password, admin_hash):
        _auth_register_fail(key)
        time.sleep(1.0)
        return False, "Неверный пароль"
    _auth_clear(key)
    return True, None


# Short-lived admin tokens issued after a successful password check.
_ADMIN_TOKENS = {}
_ADMIN_TOKEN_TTL = 12 * 3600


def _admin_issue_token():
    token = secrets.token_urlsafe(32)
    now = time.time()
    # drop expired entries while we are here
    for t in [t for t, exp in list(_ADMIN_TOKENS.items()) if exp < now]:
        _ADMIN_TOKENS.pop(t, None)
    _ADMIN_TOKENS[token] = now + _ADMIN_TOKEN_TTL
    return token


def _admin_token_ok(token):
    exp = _ADMIN_TOKENS.get(str(token or ""))
    return bool(exp and exp >= time.time())


def _get_account_secret_password(account_name=None):
    return _get_shared_secret_password()


def _selector_password_state():
    accounts = _get_account_list()
    shared = _get_shared_secret_password()
    return {
        "accounts": len(accounts),
        "password_exists": bool(shared),
        # SECURITY FIX: this used to be False on a fresh install (no
        # accounts yet, no password set), which made the frontend skip the
        # password step entirely for the very first account - so the first
        # profile created through the site was reachable by anyone, with no
        # password and no authentication whatsoever. A password must always
        # be set (or entered) before any account is created or managed.
        "password_required": True,
    }


_MIN_NEW_PASSWORD_LEN = 8


def _verify_selector_password(password):
    """Gate for adding/managing accounts from the selector. Returns
    (ok, error_message).

    SECURITY FIX: this used to return `True` unconditionally for the very
    first account on a fresh install (no password check of any kind), and
    then let *any* unauthenticated visitor's *next* request silently become
    the permanent shared password once one account existed - a takeover
    race, and the root cause of "a newly created profile is reachable by
    anyone with no password". Now a real password (>= 8 chars) must be
    supplied and is persisted atomically in the very same request that
    establishes it, whether that is the first account ever or a recovery
    after passwords.json was lost - there is no longer a window in which an
    account exists without a password protecting it.
    """
    password = (password or "").strip()
    key = _client_key()

    locked = _auth_locked(key)
    if locked:
        return False, f"Слишком много попыток. Попробуйте через {locked} сек."

    shared = _get_registration_password()

    if not shared:
        if len(password) < _MIN_NEW_PASSWORD_LEN:
            _auth_register_fail(key)
            time.sleep(1.0)
            return False, f"Общий пароль не задан. Придумайте пароль (минимум {_MIN_NEW_PASSWORD_LEN} символов)"
        _auth_clear(key)
        hashed = _hash_password(password)
        _save_passwords({k: hashed
                         for k in ("secret_password", "registration_password", "deletion_password")})
        return True, None

    if not password or not _verify_password(password, shared):
        _auth_register_fail(key)
        time.sleep(1.0)
        return False, "Неверный пароль"
    _auth_clear(key)
    return True, None


def _verify_deletion_password(password):
    """Gate for deleting an account. Uses the deletion password (same as the
    shared one for now). Returns (ok, error_message)."""
    password = (password or "").strip()
    key = _client_key()

    locked = _auth_locked(key)
    if locked:
        return False, f"Слишком много попыток. Попробуйте через {locked} сек."

    target = _get_deletion_password()
    if not target:
        # Fresh install with no password yet: nothing to delete anyway.
        return False, "Пароль удаления не задан"

    if not password or not _verify_password(password, target):
        _auth_register_fail(key)
        time.sleep(1.0)
        return False, "Неверный пароль"
    _auth_clear(key)
    return True, None

def _get_account_bot_credentials(account_name):
    acct = _find_account(account_name)
    if acct:
        return str(acct.get("secret_bot_token") or ""), str(acct.get("secret_bot_chat_id") or "")
    return "", ""

def _is_access_control_enabled(account_name):
    """Whether the account panel requires a trusted-device cookie to be seen.

    SECURITY FIX: this used to additionally require a configured Telegram
    bot (bot_token + access_chat_id). That meant every freshly created
    account - before its owner had gone and set up Telegram-based login
    approval - was reachable by *anyone* who knew (or guessed) its URL,
    with no password and no login of any kind: `_request_has_access()`
    short-circuits to "allowed" whenever this function returns False.
    Password-based login (`/api/auth/password_login`) never depended on the
    bot being configured, so access control must stay enabled by default
    regardless of whether the optional Telegram-bot approval flow is set up.
    """
    cfg = _load_gui_cfg(account_name)
    return bool(cfg.get("access_control_enabled", True))

def _get_client_ip():
    forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    real_ip = (request.headers.get("X-Real-IP") or "").strip()
    return forwarded or real_ip or (request.remote_addr or "")

def _should_use_secure_cookie():
    forwarded_proto = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
    scheme = (forwarded_proto or request.scheme or "").lower()
    return scheme == "https"

def _attach_device_cookie(resp, device_id, path_prefix, max_age_days=365):
    resp.set_cookie(
        DEVICE_COOKIE_NAME,
        device_id,
        max_age=max_age_days * 24 * 60 * 60,
        httponly=True,
        secure=_should_use_secure_cookie(),
        samesite="Lax",
        path=f"/{path_prefix}/",
    )

def _attach_access_cookie(resp, device_hash, trust_days, path_prefix, account_name):
    cfg = _load_gui_cfg(account_name)
    token = create_access_token(cfg["auth_secret"], device_hash)
    resp.set_cookie(
        AUTH_COOKIE_NAME,
        token,
        max_age=trust_days * 24 * 60 * 60,
        httponly=True,
        secure=_should_use_secure_cookie(),
        samesite="Lax",
        path=f"/{path_prefix}/",
    )

def _clear_access_cookies(resp, path_prefix):
    resp.delete_cookie(AUTH_COOKIE_NAME, path=f"/{path_prefix}/")
    resp.delete_cookie(DEVICE_COOKIE_NAME, path=f"/{path_prefix}/")


# --- "Secret" sub-panel access -----------------------------------------------
# SECURITY FIX: the secret password used to be embedded in plain text in the
# page's HTML/JS and compared in the browser (`SECRET_PWD`), and none of the
# /<account>/api/secret/* endpoints checked anything beyond the *general*
# panel login. That meant the second factor protecting the most sensitive
# actions (reading/deleting/editing real Telegram messages, downloading
# media, dumping full chat history) did not exist server-side at all.
#
# Now a correct password issues a short-lived, signed, httponly cookie
# (same mechanism as the main access cookie) and every /secret/* route is
# gated on it in `_bp_before_request`.
SECRET_COOKIE_NAME = "ar_secret"
SECRET_UNLOCK_TTL_SEC = 30 * 60  # 30 minutes


def _attach_secret_cookie(resp, account_name):
    cfg = _load_gui_cfg(account_name)
    token = create_access_token(cfg["auth_secret"], f"secret:{account_name}")
    resp.set_cookie(
        SECRET_COOKIE_NAME,
        token,
        max_age=SECRET_UNLOCK_TTL_SEC,
        httponly=True,
        secure=_should_use_secure_cookie(),
        samesite="Lax",
        path=f"/{account_name}/",
    )


def _secret_unlocked(account_name):
    cfg = _load_gui_cfg(account_name)
    token = request.cookies.get(SECRET_COOKIE_NAME)
    payload = parse_access_token(cfg["auth_secret"], token)
    return payload == f"secret:{account_name}"


def _clear_secret_cookie(resp, path_prefix):
    resp.delete_cookie(SECRET_COOKIE_NAME, path=f"/{path_prefix}/")

def _request_has_access(account_name):
    if not _is_access_control_enabled(account_name):
        return True, None
    cfg = _load_gui_cfg(account_name)
    token = request.cookies.get(AUTH_COOKIE_NAME)
    device_hash = parse_access_token(cfg["auth_secret"], token)
    if not device_hash:
        return False, None
    if not is_trusted_device(device_hash, account_name):
        return False, device_hash
    touch_trusted_device(device_hash, _get_client_ip(), account_name)
    return True, device_hash

def _db_ok(account_name):
    set_account(account_name)
    return os.path.exists(db_path())

def _ensure_schema(account_name):
    if not _db_ok(account_name):
        return
    set_account(account_name)
    dp = db_path()
    conn = sqlite3.connect(dp)
    conn.execute("PRAGMA journal_mode=WAL;")
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

def _fmt_dt(dt_raw):
    try:
        return datetime.fromisoformat(dt_raw).strftime("%d.%m.%Y %H:%M:%S")
    except Exception:
        return dt_raw or ""

def _guess_media_api(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"):
        return "sendPhoto"
    if ext in (".mp4", ".webm", ".mov", ".m4v", ".mkv"):
        return "sendVideo"
    if ext in (".mp3", ".wav", ".ogg", ".m4a", ".aac", ".flac", ".opus"):
        return "sendVoice" if ext in (".ogg", ".opus") else "sendAudio"
    return "sendDocument"

def _bot_send_media_smart(token, chat_id, file_path, caption=""):
    if requests is None:
        return False, "requests is not installed."
    api_method = _guess_media_api(file_path)
    field_map = {"sendPhoto": "photo", "sendVideo": "video", "sendVoice": "voice",
                 "sendAudio": "audio", "sendDocument": "document"}
    field = field_map.get(api_method, "document")
    try:
        with open(file_path, "rb") as f:
            r = requests.post(
                f"https://api.telegram.org/bot{token}/{api_method}",
                data={"chat_id": chat_id, "caption": caption[:1024]},
                files={field: f},
                timeout=300
            )
        j = r.json() if (r.headers.get("content-type", "") or "").startswith("application/json") else {}
        if r.status_code == 200 and j.get("ok") is True:
            return True, "OK"
        return False, f"{r.status_code} {r.text[:200]}"
    except Exception as e:
        return False, str(e)

def _build_db_export_copy(account_name):
    set_account(account_name)
    dp = db_path()
    if not os.path.exists(dp):
        return None, "messages.db not found."
    set_account(account_name)
    tmp_dir = tempfile.mkdtemp(prefix="ar_db_", dir=account_dir())
    db_copy_path = os.path.join(tmp_dir, f"messages_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db")
    src = None
    dst = None
    try:
        src = sqlite3.connect(dp, timeout=10)
        dst = sqlite3.connect(db_copy_path, timeout=10)
        src.backup(dst)
        dst.commit()
        return db_copy_path, "OK"
    except Exception as e:
        try:
            if os.path.exists(db_copy_path):
                os.remove(db_copy_path)
        except Exception:
            pass
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return None, str(e)
    finally:
        try:
            if dst is not None:
                dst.close()
        except Exception:
            pass
        try:
            if src is not None:
                src.close()
        except Exception:
            pass

def _build_media_export_zip(account_name):
    set_account(account_name)
    mf = media_folder()
    if not os.path.isdir(mf):
        return None, "media folder not found."
    has_files = False
    set_account(account_name)
    tmp_dir = tempfile.mkdtemp(prefix="ar_media_", dir=account_dir())
    zip_path = os.path.join(tmp_dir, f"media_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
    try:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(mf):
                for name in files:
                    full_path = os.path.join(root, name)
                    rel_path = os.path.relpath(full_path, mf)
                    zf.write(full_path, arcname=rel_path)
                    has_files = True
        if not has_files:
            try:
                os.remove(zip_path)
            except Exception:
                pass
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return None, "No media files."
        return zip_path, "OK"
    except Exception as e:
        try:
            if os.path.exists(zip_path):
                os.remove(zip_path)
        except Exception:
            pass
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return None, str(e)


AUTH_GATE_HTML = r"""
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Access Check</title>
<style>
:root{
  --bg:#09111d; --panel:rgba(10,19,34,.84); --border:rgba(163,185,214,.18); --text:#ecf4ff;
  --muted:rgba(236,244,255,.68); --accent:#54a6ff; --accent-2:#77f2b4; --danger:#ff6d7f;
}
*{box-sizing:border-box}
body{
  margin:0; min-height:100vh; display:grid; place-items:center; padding:24px;
  color:var(--text); font-family:Segoe UI, Arial, sans-serif;
  background:
    radial-gradient(900px 540px at 15% 10%, rgba(84,166,255,.28), transparent 60%),
    radial-gradient(860px 520px at 85% 85%, rgba(119,242,180,.14), transparent 58%),
    linear-gradient(180deg, #08101b, #0d1726 55%, #0a1321);
}
.shell{
  width:min(100%, 560px); border:1px solid var(--border); border-radius:28px; padding:28px;
  background:linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.01)), var(--panel);
  box-shadow:0 28px 80px rgba(0,0,0,.38);
}
.eyebrow{display:inline-flex; align-items:center; gap:10px; color:var(--muted); font-size:13px; letter-spacing:.04em; text-transform:uppercase}
.dot{width:10px; height:10px; border-radius:50%; background:var(--accent); box-shadow:0 0 0 8px rgba(84,166,255,.14)}
h1{margin:18px 0 10px; font-size:30px; line-height:1.08}
p{margin:0; color:var(--muted); line-height:1.55}
.card{
  margin-top:18px; border:1px solid var(--border); border-radius:20px; padding:18px;
  background:rgba(255,255,255,.03);
}
.status{font-size:17px; font-weight:600}
.meta{display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:12px; margin-top:16px}
.cell{padding:12px 14px; border-radius:16px; background:rgba(8,15,26,.5); border:1px solid rgba(163,185,214,.1)}
.label{font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.06em}
.value{margin-top:8px; font-size:15px; word-break:break-word}
.spinner{
  width:54px; height:54px; border-radius:50%; margin-top:18px;
  border:4px solid rgba(255,255,255,.12); border-top-color:var(--accent-2);
  animation:spin .9s linear infinite;
}
.actions{display:flex; gap:12px; margin-top:18px; flex-wrap:wrap}
button{
  border:0; border-radius:14px; padding:12px 16px; cursor:pointer; font-weight:600;
  background:linear-gradient(135deg, #5aa8ff, #3d7eff); color:white;
}
button.alt{background:rgba(255,255,255,.06); color:var(--text); border:1px solid var(--border)}
.danger{color:var(--danger)}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
  <div class="shell">
    <div class="eyebrow"><span class="dot" onclick="onDotClick()"></span><span>Protected Access</span></div>
    <h1>Anti-Revoke</h1>
    <p>Нажмите "Войти" для подтверждения входа через Telegram.</p>

    <div class="actions" id="loginActions">
      <button onclick="startAuth()">Войти</button>
      <button class="alt" onclick="location.reload()">Refresh</button>
    </div>

    <div id="pwdSection" style="display:none; margin-top:18px">
      <div class="card">
        <div class="status" style="font-size:15px">Вход по паролю</div>
        <div style="margin-top:10px">
          <input id="secretPwd" type="password" placeholder="Пароль"
            style="width:100%;border:1px solid var(--border);background:rgba(255,255,255,.03);padding:10px 12px;border-radius:16px;color:var(--text);outline:none;font-size:14px" />
        </div>
        <div class="actions" style="margin-top:10px">
          <button onclick="submitPassword()">Войти</button>
        </div>
        <div class="small" id="pwdStatus" style="margin-top:8px;color:var(--muted);font-size:13px"></div>
      </div>
    </div>

    <div class="spinner" id="spinner" style="display:none"></div>
    <div class="card" id="authCard" style="display:none">
      <div class="status" id="status"></div>
      <div class="meta">
        <div class="cell"><div class="label">IP</div><div class="value" id="ip">&mdash;</div></div>
        <div class="cell"><div class="label">State</div><div class="value" id="state">&mdash;</div></div>
      </div>
      <div class="actions">
        <button id="retry" onclick="startAuth()" style="display:none">Отправить заново</button>
        <button class="alt" onclick="location.reload()">Refresh</button>
      </div>
    </div>
  </div>
<script>
let activeRequestId = null;
let pollTimer = null;
let dotClickCount = 0;
const PFX = '/' + window.location.pathname.split('/')[1] + '/';

async function startAuth(){
  clearInterval(pollTimer);
  document.getElementById('loginActions').style.display='none';
  document.getElementById('pwdSection').style.display='none';
  document.getElementById('authCard').style.display='block';
  document.getElementById('retry').style.display='none';
  document.getElementById('status').textContent='Sending request for approval...';
  document.getElementById('state').textContent='Waiting';
  document.getElementById('spinner').style.display='block';
  try{
    const r = await fetch(PFX+'api/auth/request', {method:'POST', headers:{'Content-Type':'application/json'}});
    const data = await r.json();
    document.getElementById('ip').textContent = data.ip || 'unknown';
    if(!r.ok || !data.ok){
      throw new Error(data.error || 'Cannot create access request');
    }
    activeRequestId = data.request_id;
    document.getElementById('status').textContent='Approval request sent to Telegram. Waiting for your answer...';
    pollTimer = setInterval(checkStatus, (data.poll_interval_sec || 2) * 1000);
    await checkStatus();
  }catch(err){
    document.getElementById('status').textContent = err.message || 'Authorization failed';
    document.getElementById('state').innerHTML = '<span class="danger">Error</span>';
    document.getElementById('spinner').style.display='none';
    document.getElementById('retry').style.display='inline-flex';
  }
}

async function checkStatus(){
  if(!activeRequestId) return;
  try{
    const r = await fetch(PFX+`api/auth/status/${activeRequestId}`);
    const data = await r.json();
    if(!r.ok){
      throw new Error(data.error || 'Status check failed');
    }
    document.getElementById('state').textContent = data.status || 'waiting';
    if(data.status === 'approved'){
      clearInterval(pollTimer);
      document.getElementById('status').textContent='Access approved. Opening site...';
      document.getElementById('state').textContent='Approved';
      setTimeout(()=>location.reload(), 500);
    }else if(data.status === 'denied'){
      clearInterval(pollTimer);
      document.getElementById('status').textContent='Access denied in Telegram.';
      document.getElementById('spinner').style.display='none';
      document.getElementById('retry').style.display='inline-flex';
    }else if(data.status === 'expired'){
      clearInterval(pollTimer);
      document.getElementById('status').textContent='Request expired. Send a new one.';
      document.getElementById('spinner').style.display='none';
      document.getElementById('retry').style.display='inline-flex';
    }
  }catch(err){
    clearInterval(pollTimer);
    document.getElementById('status').textContent = err.message || 'Status check failed';
    document.getElementById('spinner').style.display='none';
    document.getElementById('retry').style.display='inline-flex';
  }
}

function onDotClick(){
  dotClickCount++;
  if(dotClickCount >= 10){
    document.getElementById('pwdSection').style.display = 'block';
    dotClickCount = 0;
  }
}

async function submitPassword(){
  var pwd = (document.getElementById('secretPwd').value || '').trim();
  var st = document.getElementById('pwdStatus');
  if(!pwd){ st.textContent = 'Введите пароль'; return; }
  st.textContent = 'Проверка...';
  try{
    var r = await fetch(PFX+'api/auth/password_login',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({password: pwd})
    });
    var data = await r.json();
    if(r.ok && data.ok){
      st.textContent = 'Успешно! Перенаправление...';
      setTimeout(function(){ location.reload(); }, 400);
    }else{
      st.textContent = data.error || 'Неверный пароль';
    }
  }catch(err){
    st.textContent = err.message || 'Ошибка подключения';
  }
}
</script>
</body>
</html>
"""

SELECTOR_HTML = r"""
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Anti-Revoke - Accounts</title>
<style>
:root{
  --bg:#09111d; --panel:rgba(10,19,34,.84); --border:rgba(163,185,214,.18); --text:#ecf4ff;
  --muted:rgba(236,244,255,.68); --accent:#54a6ff; --accent-2:#77f2b4;
}
*{box-sizing:border-box}
body{
  margin:0; min-height:100vh; display:grid; place-items:center; padding:24px;
  color:var(--text); font-family:Segoe UI, Arial, sans-serif;
  background:
    radial-gradient(900px 540px at 15% 10%, rgba(84,166,255,.28), transparent 60%),
    radial-gradient(860px 520px at 85% 85%, rgba(119,242,180,.14), transparent 58%),
    linear-gradient(180deg, #08101b, #0d1726 55%, #0a1321);
}
.shell{
  width:min(100%, 600px); border:1px solid var(--border); border-radius:28px; padding:28px;
  background:linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.01)), var(--panel);
  box-shadow:0 28px 80px rgba(0,0,0,.38);
}
.eyebrow{display:inline-flex; align-items:center; gap:10px; color:var(--muted); font-size:13px; letter-spacing:.04em; text-transform:uppercase}
.dot{width:10px; height:10px; border-radius:50%; background:var(--accent); box-shadow:0 0 0 8px rgba(84,166,255,.14)}
h1{margin:18px 0 10px; font-size:28px; line-height:1.08}
p{margin:0; color:var(--muted); line-height:1.55}
.accounts{margin-top:20px; display:flex; flex-direction:column; gap:12px}
.acc-empty{color:var(--muted); text-align:center; padding:20px; overflow-wrap:anywhere}
.acc-card{
  display:flex; align-items:center; justify-content:space-between; gap:10px;
  padding:16px 18px; border:1px solid var(--border); border-radius:18px;
  background:rgba(255,255,255,.03); text-decoration:none; color:var(--text);
  transition: background .15s, border-color .15s;
}
.acc-card:hover{background:rgba(91,140,255,.1); border-color:rgba(91,140,255,.4)}
.acc-body{min-width:0}
.acc-name{font-size:17px; font-weight:600; overflow-wrap:anywhere}
.acc-meta{font-size:12px; color:var(--muted); margin-top:4px; overflow-wrap:anywhere}
.acc-del{
  flex:0 0 auto; border:1px solid rgba(255,91,110,.4); background:rgba(255,91,110,.08);
  color:#ff8b98; border-radius:12px; padding:8px 12px; cursor:pointer; font-size:13px;
}
.acc-del:hover{background:rgba(255,91,110,.18)}
.add-wrap{margin-top:16px}
.add-btn{
  width:100%; padding:14px 16px; border:1px dashed rgba(163,185,214,.35); border-radius:18px;
  background:rgba(255,255,255,.03); color:var(--text); font-size:15px; font-weight:600;
  cursor:pointer; transition: background .15s, border-color .15s;
}
.add-btn:hover{background:rgba(84,166,255,.12); border-color:rgba(84,166,255,.5)}
.admin-btn{
  margin-top:10px; width:100%; padding:9px 16px; border:1px solid var(--border); border-radius:14px;
  background:rgba(255,255,255,.02); color:var(--muted); font-size:12px; cursor:pointer;
  transition: color .15s, border-color .15s;
}
.admin-btn:hover{color:var(--text); border-color:rgba(163,185,214,.4)}
/* --- Modal overlay --- */
.modal-overlay{
  position:fixed; inset:0; z-index:50; display:none;
  align-items:center; justify-content:center; padding:20px;
  background:rgba(4,9,17,.62); backdrop-filter:blur(6px);
  -webkit-backdrop-filter:blur(6px);
}
.modal-overlay.open{display:flex}
.modal{
  width:min(100%, 460px); max-height:88vh; overflow:auto;
  border:1px solid var(--border); border-radius:22px; padding:22px;
  background:linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.015)), var(--panel);
  box-shadow:0 30px 90px rgba(0,0,0,.55);
}
.modal-head{display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:16px}
.modal-x{
  border:1px solid var(--border); background:rgba(255,255,255,.05); color:var(--muted);
  width:32px; height:32px; border-radius:10px; cursor:pointer; font-size:20px; line-height:1;
  display:flex; align-items:center; justify-content:center; flex:0 0 auto;
}
.modal-x:hover{color:var(--text); background:rgba(255,255,255,.1)}
.modal-step{display:none; flex-direction:column; gap:12px}
.modal-step.active{display:flex}
.add-title{font-size:15px; font-weight:600; overflow-wrap:anywhere}
.field{display:flex; flex-direction:column; gap:6px; font-size:12px; color:var(--muted)}
.inp{
  width:100%; border:1px solid var(--border); background:rgba(255,255,255,.03); padding:11px 12px;
  border-radius:14px; color:var(--text); outline:none; font-size:14px; overflow-wrap:anywhere;
}
.inp:focus{border-color:rgba(84,166,255,.55)}
.api-help{
  display:inline-block; margin:-4px 0 8px; font-size:12px; color:#5b8cff;
  text-decoration:none; overflow-wrap:anywhere;
}
.api-help:hover{text-decoration:underline}
.add-status{font-size:13px; color:var(--muted); min-height:16px; overflow-wrap:anywhere; word-break:break-word}
.add-status.err{color:#ff8b98}
.add-status.ok{color:var(--accent-2)}
.add-row{display:flex; gap:10px; margin-top:2px}
.add-go{
  border:0; border-radius:14px; padding:11px 16px; cursor:pointer; font-weight:600; font-size:14px;
  background:linear-gradient(135deg, #5aa8ff, #3d7eff); color:#fff;
}
.add-back{
  border:1px solid var(--border); background:rgba(255,255,255,.05); color:var(--text);
  border-radius:14px; padding:11px 16px; cursor:pointer; font-size:14px;
}
.add-go:disabled, .add-back:disabled{opacity:.6; cursor:default}
</style>
</head>
<body>
  <div class="shell">
    <div class="eyebrow"><span class="dot"></span><span>Multi-Account</span></div>
    <h1>Anti-Revoke</h1>
    <p>Выберите аккаунт:</p>
    <div class="accounts" id="accountsList"></div>

    <div class="add-wrap">
      <button class="add-btn" id="addBtn" type="button">+ Добавить аккаунт</button>
      <button class="admin-btn" id="adminBtn" type="button">Админ-панель</button>
    </div>
  </div>

  <div class="modal-overlay" id="modalOverlay">
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modalTitle">
      <div class="modal-head">
        <div class="add-title" id="modalTitle">Новый аккаунт</div>
        <button class="modal-x" id="modalClose" type="button" aria-label="Закрыть">&times;</button>
      </div>

      <div class="modal-step" id="unlockStep">
        <div class="add-title" id="unlockTitle">Введите пароль</div>
        <input id="unlockPwd" class="inp" type="password" placeholder="Пароль" autocomplete="off"/>
        <div class="add-status" id="unlockStatus"></div>
        <div class="add-row">
          <button class="add-go" id="unlockBtn" type="button">Продолжить</button>
          <button class="add-back" id="unlockCancel" type="button">Отмена</button>
        </div>
      </div>

      <div class="modal-step" id="formStep">
        <label class="field">Имя аккаунта
          <input id="fldName" class="inp" placeholder="например, myaccount" autocomplete="off" autocapitalize="none" spellcheck="false"/>
        </label>
        <label class="field">api_id
          <input id="fldApiId" class="inp" inputmode="numeric" placeholder="12345678" autocomplete="off"/>
        </label>
        <label class="field">api_hash
          <input id="fldApiHash" class="inp" placeholder="32 символа с my.telegram.org" autocomplete="off" autocapitalize="none" spellcheck="false"/>
        </label>
        <a class="api-help" href="https://my.telegram.org" target="_blank" rel="noopener noreferrer">
          Получить api_id и api_hash на my.telegram.org ↗
        </a>
        <div class="add-status" id="formStatus"></div>
        <div class="add-row">
          <button class="add-go" id="saveBtn" type="button">Добавить</button>
          <button class="add-back" id="backBtn" type="button">Назад</button>
        </div>
      </div>

      <div class="modal-step" id="doneStep">
        <div class="add-title">Аккаунт добавлен</div>
        <div class="add-status ok" id="doneStatus"></div>
        <div class="add-row">
          <button class="add-go" id="openBtn" type="button">Открыть панель</button>
          <button class="add-back" id="reloadBtn" type="button">К списку</button>
        </div>
      </div>

      <div class="modal-step" id="loginStep">
        <div class="add-title">Вход в Telegram</div>
        <label class="field">Номер телефона
          <input id="fldPhone" class="inp" type="tel" placeholder="+79991234567" autocomplete="off"/>
        </label>
        <label class="field" id="codeField" style="display:none">Код из Telegram
          <input id="fldCode" class="inp" inputmode="numeric" placeholder="12345" autocomplete="off"/>
        </label>
        <label class="field" id="twofaField" style="display:none">Пароль двухфакторной защиты
          <input id="fld2fa" class="inp" type="password" placeholder="Пароль 2FA" autocomplete="off"/>
        </label>
        <div class="add-status" id="loginStatus"></div>
        <div class="add-row">
          <button class="add-go" id="sendCodeBtn" type="button">Отправить код</button>
          <button class="add-back" id="resendBtn" type="button" style="display:none">Отправить ещё раз</button>
          <button class="add-back" id="loginSkipBtn" type="button">Пропустить</button>
        </div>
      </div>

      <div class="modal-step" id="botStep">
        <div class="add-title">Бот уведомлений</div>
        <label class="field">API токен бота
          <input id="fldBotToken" class="inp" placeholder="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11" autocomplete="off" autocapitalize="none" spellcheck="false"/>
        </label>
        <label class="field">Chat ID
          <input id="fldBotChat" class="inp" placeholder="-1001234567890" autocomplete="off" spellcheck="false"/>
        </label>
        <div class="add-status" id="botStatus"></div>
        <div class="add-row">
          <button class="add-go" id="saveBotBtn" type="button">Сохранить</button>
          <button class="add-back" id="botSkipBtn" type="button">Пропустить</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Глобальная админ-панель (не привязана к аккаунту) -->
  <div class="modal-overlay" id="adminOverlay">
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="adminTitle">
      <div class="modal-head">
        <div class="add-title" id="adminTitle">Админ-панель</div>
        <button class="modal-x" id="adminClose" type="button" aria-label="Закрыть">&times;</button>
      </div>

      <div class="modal-step active" id="adminUnlockStep">
        <div class="add-title">Введите пароль администратора</div>
        <input id="adminPwd" class="inp" type="password" placeholder="Пароль" autocomplete="off"/>
        <div class="add-status" id="adminUnlockStatus"></div>
        <div class="add-row">
          <button class="add-go" id="adminLoginBtn" type="button">Войти</button>
          <button class="add-back" id="adminCancelBtn" type="button">Отмена</button>
        </div>
      </div>

      <div class="modal-step" id="adminPanelStep">
        <div class="add-title">Перенос на другой хост</div>
        <div class="add-status" id="adminAccountsInfo"></div>
        <label class="field" style="flex-direction:row; align-items:center; gap:8px">
          <input type="checkbox" id="adminInclMedia" style="width:auto"/>
          Включить медиафайлы (фото/видео — архив может быть большим)
        </label>
        <div class="add-status" id="adminStatus"></div>
        <div class="add-row">
          <button class="add-go" id="adminExportBtn" type="button">Выгрузить всё (ZIP)</button>
          <button class="add-back" id="adminLogoutBtn" type="button">Выйти</button>
        </div>
        <div class="add-status" style="font-size:12px">
          В архив попадут: accounts.json, passwords.json и папки accounts/ (сессии,
          настройки, базы, логи). Распакуйте их в корень нового хоста и перезапустите.
        </div>
      </div>
    </div>
  </div>
<script>
const ACCOUNTS = __ACCOUNTS_JSON__;
const list = document.getElementById('accountsList');

// Safe card builder (no innerHTML) so an account name can never inject markup.
function addText(parent, cls, text){
  const d = document.createElement('div');
  d.className = cls;
  d.textContent = text;
  parent.appendChild(d);
}

function buildAccountCard(name, api_id){
  const card = document.createElement('a');
  card.className = 'acc-card';
  card.href = '/' + name + '/';
  const body = document.createElement('div');
  body.className = 'acc-body';
  addText(body, 'acc-name', name);
  addText(body, 'acc-meta', 'api_id: ' + (api_id || '—'));
  card.appendChild(body);
  const del = document.createElement('button');
  del.className = 'acc-del';
  del.type = 'button';
  del.textContent = 'Удалить';
  del.addEventListener('click', e => {
    e.preventDefault();
    e.stopPropagation();
    deleteAccount(name, card);
  });
  card.appendChild(del);
  return card;
}

async function deleteAccount(name, card){
  if(!confirm('Удалить аккаунт «' + name + '»? Все его данные будут удалены.')) return;
  const pwd = prompt('Введите пароль для удаления:');
  if(pwd === null) return; // cancelled
  try{
    const r = await fetch('/api/accounts/delete', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({password: pwd, name})
    });
    const d = await r.json();
    if(!r.ok || !d.ok){
      alert(d.error || 'Не удалось удалить аккаунт');
      return;
    }
    if(card && card.parentNode) card.remove();
    const i = ACCOUNTS.findIndex(a => a.name === name);
    if(i >= 0) ACCOUNTS.splice(i, 1);
    if(!ACCOUNTS.length && !list.querySelector('.acc-empty')){
      addText(list, 'acc-empty', 'Аккаунтов пока нет — добавьте первый.');
    }
  }catch(e){
    alert(e.message || 'Ошибка подключения');
  }
}
if(!ACCOUNTS.length){
  addText(list, 'acc-empty', 'Аккаунтов пока нет — добавьте первый.');
}else{
  ACCOUNTS.forEach(a=> list.appendChild(buildAccountCard(a.name, a.api_id)));
}

const addState = {password: '', exists: false, required: false, path: '', name: ''};
const $ = id => document.getElementById(id);
const overlay = $('modalOverlay');

function openModal(){ overlay.classList.add('open'); }
function closeModal(){ overlay.classList.remove('open'); }

function showStep(id){
  ['unlockStep','formStep','doneStep','loginStep','botStep'].forEach(s => $(s).classList.toggle('active', s === id));
  // Set the modal title to match the current step.
  $('modalTitle').textContent =
    id === 'unlockStep' ? 'Вход'
    : id === 'doneStep' ? 'Готово'
    : id === 'loginStep' ? 'Вход в Telegram'
    : id === 'botStep' ? 'Бот уведомлений'
    : 'Новый аккаунт';
}
function setStatus(id, text, cls){
  const el = $(id);
  el.textContent = text || '';
  el.className = 'add-status' + (cls ? ' ' + cls : '');
}

$('modalClose').addEventListener('click', closeModal);
$('unlockCancel').addEventListener('click', closeModal);
$('backBtn').addEventListener('click', () => showStep('unlockStep'));
// Close on backdrop click (but not when clicking inside the modal).
overlay.addEventListener('click', e => { if(e.target === overlay) closeModal(); });
document.addEventListener('keydown', e => { if(e.key === 'Escape' && overlay.classList.contains('open')) closeModal(); });

$('addBtn').addEventListener('click', async () => {
  openModal();
  showStep('unlockStep');
  setStatus('unlockStatus', 'Загрузка...');
  $('unlockPwd').value = '';
  try{
    const r = await fetch('/api/selector/state');
    const s = await r.json();
    addState.required = !!s.password_required;
    addState.exists = !!s.password_exists;
    // SECURITY FIX: a password step used to be skipped entirely for the
    // very first account on a fresh install, so it was created without any
    // password protecting it. The server now always requires one
    // (`password_required` is always true), and this step is always shown.
    $('unlockTitle').textContent = addState.exists
      ? 'Введите пароль'
      : 'Придумайте пароль (минимум 8 символов)';
    $('unlockPwd').placeholder = 'Пароль';
    setStatus('unlockStatus', '');
    showStep('unlockStep');
    $('unlockPwd').focus();
  }catch(e){
    setStatus('unlockStatus', 'Ошибка связи с сервером', 'err');
  }
});

$('unlockBtn').addEventListener('click', doUnlock);
$('unlockPwd').addEventListener('keydown', e => { if(e.key === 'Enter') doUnlock(); });

async function doUnlock(){
  const pwd = ($('unlockPwd').value || '').trim();
  if(addState.required && !pwd){ setStatus('unlockStatus', 'Введите пароль', 'err'); return; }
  setStatus('unlockStatus', 'Проверка...');
  $('unlockBtn').disabled = true;
  try{
    const r = await fetch('/api/selector/unlock', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({password: pwd})
    });
    const d = await r.json();
    if(!r.ok || !d.ok){
      setStatus('unlockStatus', d.error || 'Неверный пароль', 'err');
      return;
    }
    addState.password = pwd;
    showForm();
  }catch(e){
    setStatus('unlockStatus', e.message || 'Ошибка подключения', 'err');
  }finally{
    $('unlockBtn').disabled = false;
  }
}

function showForm(){
  setStatus('formStatus', '');
  $('fldName').value = '';
  $('fldApiId').value = '';
  $('fldApiHash').value = '';
  showStep('formStep');
  $('fldName').focus();
}

$('fldName').addEventListener('input', e => {
  e.target.value = e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, '');
});

$('saveBtn').addEventListener('click', saveAccount);

async function saveAccount(){
  const name = ($('fldName').value || '').trim();
  const api_id = ($('fldApiId').value || '').trim();
  const api_hash = ($('fldApiHash').value || '').trim();
  if(!name){ setStatus('formStatus', 'Введите имя аккаунта', 'err'); return; }
  if(!api_id){ setStatus('formStatus', 'Введите api_id', 'err'); return; }
  if(!api_hash){ setStatus('formStatus', 'Введите api_hash', 'err'); return; }

  setStatus('formStatus', 'Добавление...');
  $('saveBtn').disabled = true;
  try{
    const r = await fetch('/api/accounts', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({password: addState.password, name, api_id, api_hash})
    });
    const d = await r.json();
    if(!r.ok || !d.ok){
      setStatus('formStatus', d.error || 'Не удалось добавить аккаунт', 'err');
      if(r.status === 403){ addState.password = ''; showStep('unlockStep'); }
      return;
    }
    addState.path = d.path || ('/' + d.name + '/');
    // Continue into the Telegram login step (creates the .session file).
    addState.name = d.name;
    // Show the account in the list right away so closing the modal (X) never
    // leaves a "created but invisible" account behind.
    refreshAccountList(d.name, api_id);
    $('loginStatus').textContent = 'Авторизуйтесь в Telegram, чтобы создать сессию, или пропустите.';
    $('loginStatus').className = 'add-status';
    // Reset login fields.
    $('fldPhone').value = ''; $('fldCode').value = ''; $('fld2fa').value = '';
    $('codeField').style.display = 'none';
    $('twofaField').style.display = 'none';
    $('sendCodeBtn').textContent = 'Отправить код';
    $('resendBtn').style.display = 'none';
    showStep('loginStep');
  }catch(e){
    setStatus('formStatus', e.message || 'Ошибка подключения', 'err');
  }finally{
    $('saveBtn').disabled = false;
  }
}

$('openBtn').addEventListener('click', () => { location.href = addState.path; });
$('reloadBtn').addEventListener('click', () => location.reload());

// Refresh the on-page account list so a freshly added account shows up
// immediately (fixes "added but invisible / already exists" when closing).
function refreshAccountList(name, api_id){
  const empty = list.querySelector('.acc-empty');
  if(empty) empty.remove();
  if(ACCOUNTS.some(a => a.name === name)) return;
  ACCOUNTS.push({name, api_id});
  list.appendChild(buildAccountCard(name, api_id));
}

function goBotStep(){
  $('botStatus').textContent = 'Укажите бота для уведомлений или пропустите.';
  $('botStatus').className = 'add-status';
  $('fldBotToken').value = ''; $('fldBotChat').value = '';
  showStep('botStep');
}

// --- Telegram login step (creates the .session) ---
$('loginSkipBtn').addEventListener('click', () => goBotStep());

$('sendCodeBtn').addEventListener('click', async () => {
  const phone = ($('fldPhone').value || '').trim();
  if(!phone){ setStatus('loginStatus', 'Введите номер телефона', 'err'); return; }
  const codeSent = $('codeField').style.display !== 'none';
  const btn = $('sendCodeBtn');
  btn.disabled = true;
  try{
    if(!codeSent){
      setStatus('loginStatus', 'Отправляем код…', '');
      const r = await fetch('/api/session/start', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({password: addState.password, name: addState.name, phone})
      });
      const d = await r.json();
      if(!r.ok || !d.ok){
        setStatus('loginStatus', d.error || 'Не удалось отправить код', 'err');
        if(r.status === 403){ addState.password=''; showStep('unlockStep'); }
        return;
      }
      $('codeField').style.display = '';
      $('sendCodeBtn').textContent = 'Войти';
      $('resendBtn').style.display = '';
      const num = d.phone || phone;
      const via = d.sent_via === 'sms'
        ? 'Код отправлен по SMS на ' + num
        : 'Код ушёл в приложение Telegram на ' + num + ' (официальный чат «Telegram»).';
      setStatus('loginStatus', via, 'ok');
    }else{
      const code = ($('fldCode').value || '').trim();
      const twofa = ($('fld2fa').value || '').trim();
      if(!code){ setStatus('loginStatus', 'Введите код из Telegram', 'err'); return; }
      setStatus('loginStatus', 'Проверяем код…', '');
      const r = await fetch('/api/session/verify', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({password: addState.password, name: addState.name, code, code_password: twofa})
      });
      const d = await r.json();
      if(!r.ok || !d.ok){
        if(d.need === '2fa'){
          $('twofaField').style.display = '';
          setStatus('loginStatus', d.error || 'Введите пароль 2FA', 'err');
        }else{
          setStatus('loginStatus', d.error || 'Код неверен', 'err');
          if(r.status === 403){ addState.password=''; showStep('unlockStep'); }
        }
        return;
      }
      goBotStep();
    }
  }catch(e){
    setStatus('loginStatus', e.message || 'Ошибка подключения', 'err');
  }finally{
    btn.disabled = false;
  }
});

// Resend the code (re-runs /api/session/start with the current phone).
$('resendBtn').addEventListener('click', async () => {
  const phone = ($('fldPhone').value || '').trim();
  if(!phone){ setStatus('loginStatus', 'Введите номер телефона', 'err'); return; }
  const btn = $('resendBtn');
  btn.disabled = true;
  setStatus('loginStatus', 'Отправляем код ещё раз…', '');
  try{
    const r = await fetch('/api/session/start', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({password: addState.password, name: addState.name, phone})
    });
    const d = await r.json();
    if(!r.ok || !d.ok){
      setStatus('loginStatus', d.error || 'Не удалось отправить код', 'err');
      if(r.status === 403){ addState.password=''; showStep('unlockStep'); }
      return;
    }
    $('twofaField').style.display = 'none';
    $('fld2fa').value = '';
    const via = d.sent_via === 'sms'
      ? 'Код отправлен по SMS.'
      : 'Код отправлен в приложение Telegram — откройте официальный чат «Telegram» и введите код оттуда.';
    setStatus('loginStatus', via, 'ok');
  }catch(e){
    setStatus('loginStatus', e.message || 'Ошибка подключения', 'err');
  }finally{
    btn.disabled = false;
  }
});

// --- Bot step (saves bot token + chat id) ---
$('botSkipBtn').addEventListener('click', () => {
  $('doneStatus').textContent = 'Аккаунт добавлен. Бота можно настроить позже в панели.';
  showStep('doneStep');
});

$('saveBotBtn').addEventListener('click', async () => {
  const token = ($('fldBotToken').value || '').trim();
  const chat = ($('fldBotChat').value || '').trim();
  if(!token && !chat){
    setStatus('botStatus', 'Введите токен и Chat ID, либо нажмите «Пропустить»', 'err');
    return;
  }
  if(token && !token.includes(':')){ setStatus('botStatus', 'Токен в формате 123456:ABC-...', 'err'); return; }
  if(chat && !/^-?\d+$/.test(chat)){ setStatus('botStatus', 'Chat ID должен быть числом', 'err'); return; }
  const btn = $('saveBotBtn');
  btn.disabled = true;
  setStatus('botStatus', 'Сохраняем…', '');
  try{
    const r = await fetch('/api/accounts/secret-bot', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({password: addState.password, name: addState.name, secret_bot_token: token, secret_bot_chat_id: chat})
    });
    const d = await r.json();
    if(!r.ok || !d.ok){
      setStatus('botStatus', d.error || 'Не удалось сохранить', 'err');
      if(r.status === 403){ addState.password=''; showStep('unlockStep'); }
      return;
    }
    $('doneStatus').textContent = d.message || 'Готово.';
    showStep('doneStep');
  }catch(e){
    setStatus('botStatus', e.message || 'Ошибка подключения', 'err');
  }finally{
    btn.disabled = false;
  }
});

// ===================== Глобальная админ-панель =====================
const adminOverlay = $('adminOverlay');
const adminState = { token: '' };

function adminShowStep(id){
  ['adminUnlockStep','adminPanelStep'].forEach(s => $(s).classList.toggle('active', s === id));
  $('adminTitle').textContent = id === 'adminUnlockStep' ? 'Админ-панель' : 'Перенос на другой хост';
}
function adminStatus(text, cls){ setStatus('adminStatus', text, cls); }

$('adminBtn').addEventListener('click', () => {
  adminOverlay.classList.add('open');
  adminShowStep('adminUnlockStep');
  setStatus('adminUnlockStatus', '', '');
  $('adminPwd').value = '';
  // If we still hold a valid token, jump straight to the panel.
  if(adminState.token){ adminShowStep('adminPanelStep'); adminLoadInfo(); }
});
$('adminClose').addEventListener('click', () => adminOverlay.classList.remove('open'));
$('adminCancelBtn').addEventListener('click', () => adminOverlay.classList.remove('open'));
adminOverlay.addEventListener('click', e => { if(e.target === adminOverlay) adminOverlay.classList.remove('open'); });
document.addEventListener('keydown', e => { if(e.key === 'Escape' && adminOverlay.classList.contains('open')) adminOverlay.classList.remove('open'); });

$('adminLoginBtn').addEventListener('click', async () => {
  const pwd = ($('adminPwd').value || '').trim();
  if(!pwd){ setStatus('adminUnlockStatus', 'Введите пароль', 'err'); return; }
  const btn = $('adminLoginBtn');
  btn.disabled = true;
  setStatus('adminUnlockStatus', 'Проверка...', '');
  try{
    const r = await fetch('/api/admin/login', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({password: pwd})
    });
    const d = await r.json();
    if(!r.ok || !d.ok){
      setStatus('adminUnlockStatus', d.error || 'Неверный пароль', 'err');
      return;
    }
    adminState.token = d.token;
    $('adminPwd').value = '';
    adminShowStep('adminPanelStep');
    adminLoadInfo();
  }catch(e){
    setStatus('adminUnlockStatus', e.message || 'Ошибка подключения', 'err');
  }finally{
    btn.disabled = false;
  }
});

async function adminLoadInfo(){
  const el = $('adminAccountsInfo');
  el.textContent = 'Загрузка...';
  try{
    const r = await fetch('/api/admin/info?token=' + encodeURIComponent(adminState.token));
    const d = await r.json();
    if(!r.ok || !d.ok){
      adminState.token = '';
      adminShowStep('adminUnlockStep');
      setStatus('adminUnlockStatus', d.error || 'Сессия истекла', 'err');
      return;
    }
    const n = (d.accounts || []).length;
    const noSess = (d.accounts || []).filter(a => !a.has_session);
    let txt = 'Аккаунтов: ' + n;
    if(noSess.length){
      txt += ' (без сессии: ' + noSess.map(a => a.name).join(', ') + ')';
    }
    el.textContent = txt;
  }catch(e){
    el.textContent = 'Не удалось загрузить список: ' + (e.message || '');
  }
}

$('adminExportBtn').addEventListener('click', () => {
  if(!adminState.token){ adminShowStep('adminUnlockStep'); return; }
  const btn = $('adminExportBtn');
  btn.disabled = true;
  adminStatus('Собираем архив... большие базы могут занять время.', '');
  const media = $('adminInclMedia').checked ? '1' : '0';
  // Direct download: browser navigates to the export URL with the token.
  const a = document.createElement('a');
  a.href = '/api/admin/export?token=' + encodeURIComponent(adminState.token) + '&media=' + media;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => {
    btn.disabled = false;
    adminStatus('Архив выгружен. Если диалог не появился — проверьте загрузки браузера.', 'ok');
  }, 1500);
});

$('adminLogoutBtn').addEventListener('click', () => {
  adminState.token = '';
  adminShowStep('adminUnlockStep');
  $('adminPwd').value = '';
  setStatus('adminUnlockStatus', '', '');
});
</script>
</body>
</html>
"""

HTML_TEMPLATE = r"""
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Anti-Revoke</title>
<style>
:root{
  --bg:#0b0e13; --panel:rgba(255,255,255,.04); --border:rgba(255,255,255,.08);
  --txt:rgba(255,255,255,.92); --muted:rgba(255,255,255,.62);
  --danger:#ff5b6e; --warn:#ffcc66;
  --r:18px; --shadow: 0 18px 60px rgba(0,0,0,.35);
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 700px at 40% 10%, rgba(91,140,255,.14), transparent 60%),
     radial-gradient(900px 650px at 70% 70%, rgba(255,204,102,.10), transparent 60%),
     var(--bg); color:var(--txt); font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;}
.app{display:grid;grid-template-columns:260px 1fr;min-height:100vh}
.side{border-right:1px solid var(--border); padding:18px; position:sticky; top:0; height:100vh}
.brand{display:flex; gap:10px; align-items:center; margin-bottom:14px}
.brand .dot{width:14px;height:14px;border-radius:50%;background:rgba(91,140,255,.9); box-shadow:0 0 0 6px rgba(91,140,255,.12)}
.brand h1{font-size:16px;margin:0}
.brand p{margin:0;color:var(--muted);font-size:12px}
.nav{display:flex;flex-direction:column;gap:10px;margin-top:12px}
.btn{border:1px solid var(--border); background:rgba(255,255,255,.03); color:var(--txt);
  padding:10px 12px; border-radius:14px; cursor:pointer; text-align:left}
.btn:hover{background:rgba(255,255,255,.05)}
.btn.active{border-color:rgba(91,140,255,.45); background:rgba(91,140,255,.12)}
.main{padding:18px 18px 70px 18px}
.top{display:flex; gap:12px; align-items:center; justify-content:space-between; margin-bottom:12px}
.search{flex:1; display:flex; align-items:center; gap:10px; border:1px solid var(--border);
  background:rgba(255,255,255,.03); border-radius:16px; padding:10px 12px}
.search input{flex:1; border:0; outline:0; background:transparent; color:var(--txt)}
.pill{font-size:12px;color:var(--muted); border:1px solid var(--border); padding:2px 8px; border-radius:999px}
.grid{display:grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap:12px}
.card{background:linear-gradient(180deg, rgba(255,255,255,.05), transparent 45%), var(--panel);
  border:1px solid var(--border); border-radius:var(--r); padding:14px; box-shadow:var(--shadow)}
.meta{display:flex;flex-wrap:wrap;gap:10px;align-items:center;color:var(--muted);font-size:12px;margin-bottom:8px}
.tag{padding:2px 8px;border-radius:999px;background:rgba(255,255,255,.06);border:1px solid var(--border);color:var(--muted)}
.tag.warn{color:var(--warn);border-color: rgba(255,204,102,.35); background: rgba(255,204,102,.08)}
.tag.danger{color:var(--danger);border-color: rgba(255,91,110,.35); background: rgba(255,91,110,.08)}
.body{white-space:pre-wrap;line-height:1.35;font-size:14px}
.file{margin-top:10px;font-size:12px;color:var(--muted)}
.media-shell{
  margin-top:12px;
  border:1px solid rgba(255,255,255,.08);
  border-radius:16px;
  background:linear-gradient(180deg, rgba(255,255,255,.045), rgba(255,255,255,.02));
  overflow:hidden;
}
.media-toggle{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  width:100%;
  padding:12px 14px;
  cursor:pointer;
  list-style:none;
  user-select:none;
}
.media-toggle::-webkit-details-marker{display:none}
.media-toggle:hover{background:rgba(255,255,255,.03)}
.media-toggle-main{display:flex; align-items:center; gap:10px; min-width:0}
.media-toggle-icon{
  width:30px; height:30px; border-radius:10px;
  display:grid; place-items:center;
  background:rgba(91,140,255,.14);
  color:#bcd5ff; font-size:14px; flex:none;
}
.media-toggle-text{display:block; min-width:0}
.media-toggle-title{display:block; font-size:13px; color:var(--txt)}
.media-toggle-name{
  display:block;
  margin-top:2px;
  font-size:12px;
  color:var(--muted);
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
}
.media-toggle-arrow{
  color:var(--muted);
  font-size:12px;
  transition:transform .18s ease, color .18s ease;
}
.media-shell[open] .media-toggle-arrow{transform:rotate(180deg); color:var(--txt)}
.media-panel{
  padding:0 14px 14px;
  border-top:1px solid rgba(255,255,255,.06);
}
.media-placeholder{
  margin-top:12px;
  min-height:72px;
  display:grid;
  place-items:center;
  border:1px dashed rgba(255,255,255,.08);
  border-radius:14px;
  color:var(--muted);
  font-size:12px;
  background:rgba(0,0,0,.14);
}
.media-preview{
  display:block;
  width:100%;
  margin-top:12px;
  border-radius:14px;
  border:1px solid rgba(255,255,255,.08);
  background:rgba(0,0,0,.22);
}
img.media-preview{
  max-height:320px;
  object-fit:contain;
}
video.media-preview{max-height:360px}
audio.media-preview{min-height:56px}
.media-actions{display:flex; gap:10px; flex-wrap:wrap; margin-top:12px}
.media-link{
  display:inline-flex;
  align-items:center;
  gap:8px;
  padding:9px 12px;
  border-radius:12px;
  border:1px solid rgba(255,255,255,.08);
  background:rgba(255,255,255,.03);
  color:var(--txt);
  text-decoration:none;
  font-size:12px;
}
.media-link:hover{background:rgba(255,255,255,.06)}
.panel{background:linear-gradient(180deg, rgba(255,255,255,.05), transparent 45%), var(--panel);
  border:1px solid var(--border); border-radius:var(--r); padding:14px; box-shadow:var(--shadow)}
.row{display:flex; gap:10px; flex-wrap:wrap}
.kpi{background:rgba(255,255,255,.03); border:1px solid var(--border); border-radius:16px; padding:10px 12px;}
.kpi b{display:block;font-size:12px;color:var(--muted);font-weight:600}
.kpi span{display:block;font-size:16px;margin-top:2px}
.switch{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 12px;
  border:1px solid var(--border); background:rgba(255,255,255,.03); border-radius:16px; margin-top:10px;}
.input{width:100%; border:1px solid var(--border); background:rgba(255,255,255,.03); padding:10px 12px;
  border-radius:16px; color:var(--txt); outline:none}
.input:focus{border-color: rgba(91,140,255,.55)}
.actions{display:flex;gap:10px;margin-top:12px;flex-wrap:wrap}
.primary{background:rgba(91,140,255,.18); border-color: rgba(91,140,255,.05);}
.okbtn{background:rgba(87,242,135,.16); border-color: rgba(87,242,135,.45);}
.toast{position:fixed; right:18px; bottom:76px; background:rgba(0,0,0,.55); border:1px solid var(--border);
  padding:10px 12px; border-radius:16px; color:var(--txt); opacity:0; transform:translateY(8px);
  transition:.18s ease; pointer-events:none; max-width:420px}
.toast.show{opacity:1; transform:translateY(0)}
#stoast{position:fixed; right:18px; bottom:126px; background:rgba(0,0,0,.55); border:1px solid var(--border);
  padding:10px 12px; border-radius:16px; color:var(--txt); opacity:0; transform:translateY(8px);
  transition:.18s ease; pointer-events:none; max-width:420px;z-index:1001}
#stoast.show{opacity:1; transform:translateY(0)}
.footerbar{position:fixed; left:0; right:0; bottom:0; border-top:1px solid var(--border);
  background:rgba(0,0,0,.35); backdrop-filter: blur(8px); padding:10px 18px; display:flex; justify-content:space-between; gap:10px; color:var(--muted); font-size:12px}
.canvas{width:100%; max-width:760px; aspect-ratio: 16/9; background:#0b0e13; border:1px solid var(--border);
  border-radius:16px; box-shadow:var(--shadow);}
.gamewrap{display:grid; grid-template-columns: 1fr 330px; gap:14px; align-items:start}
.kbd{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  font-size:12px; padding:2px 6px; border:1px solid var(--border); border-radius:8px; background:rgba(255,255,255,.04); color:var(--muted);}
.small{font-size:12px;color:var(--muted)}
.danger{color:var(--danger)}
.ctx_item{transition:background .12s ease}
</style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="brand">
      <div class="dot" id="secret_dot" title="Secret"></div>
      <div><h1>Anti-Revoke</h1><p>__ACCOUNT_NAME__</p></div>
    </div>

    <div class="nav">
      <button class="btn active" id="nav_all" onclick="setTab('all')">Сообщения</button>
      <button class="btn" id="nav_hidden" onclick="setTab('hidden')">Удалённые / TTL</button>
      <button class="btn" id="nav_scan" onclick="setTab('scan')">Поиск TTL</button>
      <button class="btn" id="nav_settings" onclick="setTab('settings')">Настройки</button>
      <button class="btn" id="nav_game" onclick="setTab('game')">Snake</button>
    </div>
  </aside>

  <main class="main">
    <div class="top">
      <div class="search" id="search_box">
        <span class="pill">Поиск</span>
        <input id="q" placeholder="текст / чат / username" oninput="debouncedRefresh()" />
        <span class="pill" id="counts">—</span>
      </div>
      <button class="btn primary" onclick="refreshNow()">Обновить</button>
    </div>

    <section id="view_all" class="grid"></section>
    <section id="view_hidden" class="grid" style="display:none"></section>

    <section id="view_scan" style="display:none">
      <div class="panel" style="max-width:980px">
        <div class="small">Чат</div>
        <div style="margin-top:10px">
          <input class="input" id="scan_target" placeholder="@username / id / phone" />
        </div>
        <div class="row" style="margin-top:12px">
          <div style="flex:1">
            <div class="small">Сканировать последних</div>
            <input class="input" id="scan_limit" type="number" min="10" max="5000" value="250" />
          </div>
          <div style="flex:1">
            <div class="small">2FA пароль</div>
            <input class="input" id="scan_pwd" placeholder="если включён" />
          </div>
        </div>
        <div class="switch"><label>Скачивать медиа</label><input type="checkbox" id="scan_download" checked/></div>

        <div class="actions">
          <button class="btn okbtn" onclick="runScan()">Запуск</button>
        </div>

        <div class="small" style="margin-top:12px">Результат</div>
        <pre class="card" id="scan_result" style="overflow:auto; max-height:320px; margin-top:10px"></pre>
      </div>
    </section>

    <section id="view_settings" style="display:none">
      <div class="panel" style="max-width:780px">
        <div class="switch"><label>Личные</label><input type="checkbox" id="s_private"/></div>
        <div class="switch"><label>Группы</label><input type="checkbox" id="s_group"/></div>
        <div class="switch"><label>Каналы</label><input type="checkbox" id="s_channel"/></div>
        <div class="switch"><label>TTL: скачивать</label><input type="checkbox" id="s_ttl"/></div>

        <div class="row" style="margin-top:14px">
          <div style="flex:1">
            <div class="small">Хранить дней</div>
            <input class="input" id="s_retention_days" type="number" min="1" max="3650" value="30" />
          </div>
          <div style="flex:1">
            <div class="small">Чистить с размера, MB</div>
            <input class="input" id="s_soft_limit_mb" type="number" min="64" max="500" value="420" />
          </div>
          <div style="flex:1">
            <div class="small">После чистки оставить, MB</div>
            <input class="input" id="s_target_mb" type="number" min="32" max="480" value="360" />
          </div>
        </div>
        <div class="small" id="storage_note" style="margin-top:10px"></div>

        <div style="margin-top:14px">
          <div class="small">Масштаб: <span id="scale_val">100</span>%</div>
          <input class="input" id="s_scale" type="range" min="70" max="140" value="100" oninput="scale_val.textContent=this.value" />
        </div>

        <hr style="border:none;border-top:1px solid var(--border); margin:16px 0">

        <div class="small">Бот</div>
        <div style="margin-top:10px">
          <input class="input" id="b_token" placeholder="BOT_TOKEN" />
        </div>
        <div style="margin-top:10px">
          <input class="input" id="b_chat" placeholder="Chat ID" />
        </div>
        <div class="switch"><label>Отправлять</label><input type="checkbox" id="b_send"/></div>
        <div class="switch"><label>Не слать из чата бота</label><input type="checkbox" id="b_exclude_own" checked/></div>
        <div style="margin-top:10px">
          <div class="small">Исключения (каждое с новой строки: @ник, номер, ID чата)</div>
          <textarea class="input" id="b_exclude_list" rows="4" placeholder="@username&#10;+79001234567&#10;123456789" style="resize:vertical;font-family:inherit"></textarea>
        </div>

        <hr style="border:none;border-top:1px solid var(--border); margin:16px 0">

        <div class="small">Сессия Telegram</div>
        <div class="small" id="sess_note" style="margin-top:6px"></div>
        <div style="margin-top:10px">
          <input class="input" type="file" id="sess_file" accept=".session" style="padding:8px" />
        </div>
        <div class="actions">
          <button class="btn okbtn" onclick="uploadSession()">Загрузить файл сессии</button>
        </div>

        <div class="actions">
          <button class="btn okbtn" onclick="saveSettings()">Сохранить</button>
          <button class="btn" onclick="loadSettings()">Обновить</button>
          <button class="btn" onclick="runCleanup()">Очистить сейчас</button>
          <button class="btn primary" onclick="testBot()">Тест</button>
          <button class="btn" id="btn_export_media" onclick="exportDbAndMedia()">Выгрузить DB + media</button>
        </div>
        <div class="small" id="bot_note"></div>
      </div>
    </section>

    <section id="view_game" style="display:none">
      <div class="panel">
        <div class="row" style="justify-content:space-between; align-items:center; margin-bottom:12px">
          <div class="small">Управление: <span class="kbd">WASD</span> / стрелки, пауза <span class="kbd">Space</span></div>
          <div class="row">
            <div class="kpi"><b>Счёт</b><span id="s_score">0</span></div>
            <div class="kpi"><b>Рекорд</b><span id="s_best">0</span></div>
          </div>
        </div>
        <div class="gamewrap">
          <canvas id="snake_cv" class="canvas" width="960" height="540"></canvas>
          <div>
            <div class="card" style="margin:0">
              <div class="actions">
                <button class="btn okbtn" onclick="snakeStart()">Старт</button>
                <button class="btn" onclick="snakeResetBest()">Сброс</button>
              </div>
              <div class="small" id="snake_hint"></div>
            </div>
          </div>
        </div>
      </div>
    </section>

  </main>
</div>

<div class="toast" id="toast"></div>
<div class="toast" id="stoast"></div>
<div class="footerbar">
  <div id="f_status">—</div>
  <div>by hotjart | Droidzero | ####</div>
</div>

<div id="secret_overlay" style="display:none;position:fixed;inset:0;z-index:999;background:rgba(0,0,0,.7);backdrop-filter:blur(6px);align-items:center;justify-content:center;padding:20px">
  <div style="background:#0b0e13;border:1px solid var(--border);border-radius:24px;width:min(100%,900px);max-height:90vh;overflow-y:auto;padding:24px;box-shadow:0 30px 100px rgba(0,0,0,.6)">
    
    <!-- Password Screen -->
    <div id="sec_pwd_screen">
      <div style="font-size:22px;font-weight:700;margin-bottom:16px">Secret Access</div>
      <div class="small" style="margin-bottom:10px">Введите пароль:</div>
      <input class="input" id="sec_pwd" type="password" placeholder="••••••••••" style="max-width:300px" onkeydown="if(event.key==='Enter')secVerify()" />
      <div class="actions" style="margin-top:12px">
        <button class="btn okbtn" onclick="secVerify()">Подтвердить</button>
        <button class="btn" onclick="secClose()">Закрыть</button>
      </div>
      <div class="small danger" id="sec_pwd_err" style="margin-top:8px;display:none">Неверный пароль</div>
    </div>

    <!-- Mode & Search Screen -->
    <div id="sec_main_screen" style="display:none">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
        <div style="font-size:22px;font-weight:700">Secret Panel</div>
        <button class="btn" onclick="secClose()" style="border-color:var(--danger);color:var(--danger)">&#x2715;</button>
      </div>

      <!-- Mode selection -->
      <div id="sec_mode_row" style="display:flex;gap:12px;margin-bottom:16px">
        <button class="btn sec_mode_btn" data-mode="server" onclick="secSetMode('server')">&#x1F5A5; Сервер</button>
        <button class="btn sec_mode_btn active" data-mode="pc" onclick="secSetMode('pc')">&#x1F4BB; ПК</button>
      </div>

      <!-- Chat search -->
      <div style="display:flex;gap:10px;margin-bottom:16px">
        <input class="input" id="sec_search" placeholder="@username / номер / ID чата" style="flex:1" onkeydown="if(event.key==='Enter')secResolve()" />
        <button class="btn okbtn" onclick="secResolve()">Найти</button>
      </div>

      <!-- Chat info bar -->
      <div id="sec_chat_info" style="display:none;padding:14px;border:1px solid var(--border);border-radius:16px;background:rgba(255,255,255,.03);margin-bottom:14px">
        <div style="font-size:15px;font-weight:600" id="sec_chat_title">—</div>
        <div class="small" id="sec_chat_meta">—</div>
        <div class="actions" style="margin-top:10px">
          <button class="btn sec_tab_btn active" data-tab="chat" onclick="secSetTab('chat')">Чат</button>
          <button class="btn sec_tab_btn" data-tab="media" onclick="secSetTab('media')">Медиа</button>
        </div>
      </div>

      <!-- Error -->
      <div id="sec_err" class="small danger" style="display:none;margin-bottom:12px"></div>

      <!-- Loading -->
      <div id="sec_loading" style="display:none;text-align:center;padding:30px;color:var(--muted)">Загрузка...</div>

      <!-- Chat messages -->
      <div id="sec_chat_view" style="display:none;max-height:55vh;overflow-y:auto;padding:10px 0">
        <div style="text-align:center;margin-bottom:10px">
          <button class="btn" id="sec_load_history_btn" onclick="secLoadFullHistory()" style="font-size:12px">&#x1F4E5; Загрузить полную историю из Telegram</button>
          <span id="sec_history_status" class="small" style="margin-left:8px"></span>
        </div>
        <div id="sec_msgs"></div>
      </div>

      <!-- Media grid -->
      <div id="sec_media_view" style="display:none">
        <div class="actions" style="margin-bottom:12px">
          <button class="btn okbtn" onclick="secSendToBot()">&#x1F4E4; Скинуть все медиа в бота</button>
        </div>
        <div id="sec_media_grid" class="grid"></div>
      </div>

    </div>

  </div>
</div>

<!-- Context menu for messages -->
<div id="sec_ctx_menu" style="display:none;position:fixed;z-index:1000;background:#161c27;border:1px solid var(--border);border-radius:14px;padding:6px;min-width:180px;box-shadow:0 12px 40px rgba(0,0,0,.5)">
  <div id="sec_ctx_items"></div>
</div>

<script>
const PFX = '/' + window.location.pathname.split('/')[1] + '/';

let tab='all', debounceT=null, lastSig={all:null, hidden:null};

function toast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 1200);
}
function setTab(t){
  tab=t;
  for(const [id,name] of [["nav_all","all"],["nav_hidden","hidden"],["nav_scan","scan"],["nav_settings","settings"],["nav_game","game"]]){
    document.getElementById(id).classList.toggle('active', t===name);
  }
  view_all.style.display = (t==='all')?'':'none';
  view_hidden.style.display = (t==='hidden')?'':'none';
  view_scan.style.display = (t==='scan')?'':'none';
  view_settings.style.display = (t==='settings')?'':'none';
  view_game.style.display = (t==='game')?'':'none';
  search_box.style.visibility = (t==='settings' || t==='game' || t==='scan')?'hidden':'visible';
  if(t==='settings'){ loadSettings(); loadBot(); }
  else if(t==='scan'){ scan_result.textContent=''; }
  else if(t==='game'){ snakeInit(); }
  else refreshNow();
}
function esc(s){return (s||'').toString().replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');}
function mediaKind(m){
  const name=(m.media||'').toLowerCase();
  if(m.media_type==='photo' || /\.(png|jpe?g|gif|webp|bmp|svg)$/i.test(name)) return 'image';
  if(m.media_type==='video' || m.media_type==='video_note' || /\.(mp4|webm|mov|m4v|mkv)$/i.test(name)) return 'video';
  if(m.media_type==='voice' || /\.(mp3|wav|ogg|m4a|aac|flac|opus)$/i.test(name)) return 'audio';
  return 'file';
}
function mediaMarkup(m){
  if(!m.media) return '';
  const kind=mediaKind(m);
  const mediaUrl=PFX+'media/'+encodeURIComponent(m.media);
  const icon=kind==='image'?'IMG':(kind==='video'?'VID':(kind==='audio'?'AUD':'FILE'));
  const title=kind==='image'?'Медиа-превью':(kind==='video'?'Видео':(kind==='audio'?'Аудио':'Файл'));
  return `<details class="media-shell" data-media-url="${mediaUrl}" data-media-kind="${kind}" data-media-name="${esc(m.media)}">
    <summary class="media-toggle">
      <span class="media-toggle-main">
        <span class="media-toggle-icon">${icon}</span>
        <span class="media-toggle-text">
          <span class="media-toggle-title">${title}</span>
          <span class="media-toggle-name">${esc(m.media)}</span>
        </span>
      </span>
      <span class="media-toggle-arrow">&#x25BC;</span>
    </summary>
    <div class="media-panel">
      <div class="media-placeholder">Нажмите, чтобы показать медиа</div>
    </div>
  </details>`;
}
function card(m){
  const tags = (m.is_deleted?`<span class="tag danger">удалено</span>`:'') + (m.is_ephemeral?`<span class="tag warn">ttl</span>`:'');
  const file = mediaMarkup(m);
  return `<div class="card">
    <div class="meta"><span class="tag">${esc(m.dt||'')}</span><span class="tag">${esc(m.chat||'')}</span>${tags}</div>
    <div class="meta"><b style="color:var(--txt)">${esc(m.who||'')}</b> &middot; ${esc(m.username||'-')} &middot; ${esc(m.phone||'-')}</div>
    <div class="body">${esc(m.text||'') || '<span class="small">&mdash;</span>'}</div>${file}
  </div>`;
}
function buildMediaContent(kind, url, name){
  if(kind==='image') return `<img class="media-preview" src="${url}" alt="${esc(name)}" loading="lazy" decoding="async" />`;
  if(kind==='video') return `<video class="media-preview" src="${url}" controls preload="none" playsinline></video>`;
  if(kind==='audio') return `<audio class="media-preview" src="${url}" controls preload="none"></audio>`;
  return `<div class="file">Файл: ${esc(name)}</div>`;
}
function attachMediaAccordions(scope=document){
  const blocks=scope.querySelectorAll('.media-shell');
  for(const block of blocks){
    if(block.dataset.bound==='1') continue;
    block.dataset.bound='1';
    block.addEventListener('toggle', ()=>{
      if(!block.open || block.dataset.loaded==='1') return;
      const panel=block.querySelector('.media-panel');
      const url=block.dataset.mediaUrl||'';
      const kind=block.dataset.mediaKind||'file';
      const name=block.dataset.mediaName||'media';
      panel.innerHTML = `${buildMediaContent(kind, url, name)}
        <div class="media-actions">
          <a class="media-link" href="${url}" target="_blank" rel="noopener noreferrer">Открыть</a>
          <a class="media-link" href="${url}" download="${name}">Скачать</a>
        </div>`;
      block.dataset.loaded='1';
    });
  }
}
async function fetchMessages(hidden){
  const q=document.getElementById('q').value||'';
  const r=await fetch(PFX+`api/messages?hidden=${hidden?1:0}&limit=300&offset=0&q=${encodeURIComponent(q)}`);
  return await r.json();
}
function render(whereId,payload,kind){
  f_status.textContent = payload.db_ok ? ('db ok | last: ' + (payload.last_dt||'—')) : 'db ?';
  const sig=JSON.stringify(payload.signature||null);
  if(lastSig[kind]===sig) return;
  lastSig[kind]=sig;
  const where=document.getElementById(whereId);
  where.innerHTML = payload.items.length ? payload.items.map(card).join('') : `<div class="small">Ничего нет.</div>`;
  attachMediaAccordions(where);
  counts.textContent = `${payload.count} / ${payload.items.length}`;
}
async function refreshNow(){
  if(tab==='settings'||tab==='game'||tab==='scan') return;
  try{
    const hidden=(tab==='hidden');
    const payload=await fetchMessages(hidden);
    render(hidden?'view_hidden':'view_all', payload, hidden?'hidden':'all');
  }catch(e){ toast('ошибка'); }
}
function debouncedRefresh(){ if(debounceT) clearTimeout(debounceT); debounceT=setTimeout(refreshNow,250); }

/* settings */
async function loadSettings(){
  const s=await (await fetch(PFX+'api/settings')).json();
  s_private.checked=!!s.capture_private; s_group.checked=!!s.capture_group; s_channel.checked=!!s.capture_channel; s_ttl.checked=!!s.download_ephemeral;
  s_retention_days.value = String(s.retention_days||30);
  s_soft_limit_mb.value = String(s.storage_soft_limit_mb||420);
  s_target_mb.value = String(s.storage_target_mb||360);
  s_scale.value = String(s.ui_scale||100); scale_val.textContent = String(s.ui_scale||100);
  storage_note.textContent = `Сейчас занято: ${Number(s.total_mb||0).toFixed(2)} MB (media ${Number(s.media_mb||0).toFixed(2)} / db ${Number(s.db_mb||0).toFixed(2)})`;
  document.body.style.zoom = (Number(s.ui_scale||100)/100);
}

async function saveBot(silent=false){
  const exRaw=(b_exclude_list.value||'').split('\n').map(s=>s.trim()).filter(s=>s);
  const payload={bot_token:b_token.value.trim(), bot_chat_id:b_chat.value.trim(), send_to_bot:b_send.checked, exclude_own_chat:b_exclude_own.checked, exclude_from_bot:exRaw};
  const j=await (await fetch(PFX+'api/bot',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})).json();
  if(!silent) toast(j.ok?'ok':'err');
  bot_note.textContent=j.msg||'';
  return j;
}

async function saveSettings(){
  const payload={
    capture_private:s_private.checked,
    capture_group:s_group.checked,
    capture_channel:s_channel.checked,
    download_ephemeral:s_ttl.checked,
    retention_days: Number(s_retention_days.value||30),
    storage_soft_limit_mb: Number(s_soft_limit_mb.value||420),
    storage_target_mb: Number(s_target_mb.value||360),
    ui_scale: Number(s_scale.value||100)
  };
  const j=await (await fetch(PFX+'api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})).json();
  const b=await saveBot(true);
  toast((j.ok && b.ok)?'ok':'err');
  document.body.style.zoom = (Number(payload.ui_scale||100)/100);
  if((j&&j.ok) && (b&&b.ok)) bot_note.textContent='Настройки и бот сохранены.';
  if(j && j.cleanup) storage_note.textContent = `После очистки: ${Number(j.cleanup.total_mb||0).toFixed(2)} MB`;
  return {ok: !!(j.ok && b.ok)};
}

/* bot */
async function loadBot(){
  const b=await (await fetch(PFX+'api/bot')).json();
  b_token.value=b.bot_token||''; b_chat.value=b.bot_chat_id||''; b_send.checked=!!b.send_to_bot;
  b_exclude_own.checked=b.exclude_own_chat!==false;
  const exList=b.exclude_from_bot||[];
  b_exclude_list.value=exList.join('\n');
  bot_note.textContent='';
  refreshSessionStatus();
}

/* session file upload */
function refreshSessionStatus(){
  fetch(PFX+'api/session/status').then(r=>r.json()).then(j=>{
    sess_note.textContent = j.has_session
      ? 'Сессия загружена и активна.'
      : 'Сессии нет. Загрузите файл .session, чтобы приёмник мог запуститься.';
  }).catch(()=>{});
}

async function uploadSession(){
  const inp=document.getElementById('sess_file');
  if(!inp.files || !inp.files[0]){ toast('сначала выберите файл .session'); return; }
  const fd=new FormData();
  fd.append('session', inp.files[0]);
  sess_note.textContent='Загружаю и проверяю сессию...';
  const j=await (await fetch(PFX+'api/session/upload',{method:'POST',body:fd})).json();
  toast(j.ok?'ok':'err');
  sess_note.textContent=j.msg||'';
  if(j.ok) inp.value='';
}

async function testBot(){
  const j=await (await fetch(PFX+'api/bot/test',{method:'POST'})).json();
  toast(j.ok?'ок':'не ок');
  bot_note.textContent=j.msg||'';
}

async function runCleanup(){
  const j=await (await fetch(PFX+'api/cleanup',{method:'POST'})).json();
  toast(j.ok?'ok':'err');
  if(j && j.cleanup){
    storage_note.textContent = `После очистки: ${Number(j.cleanup.total_mb||0).toFixed(2)} MB, удалено записей ${j.cleanup.deleted_rows||0}, файлов ${j.cleanup.deleted_files||0}`;
  }
}

async function exportDbAndMedia(){
  bot_note.textContent='Готовлю и отправляю базу данных + медиа...';
  const j=await (await fetch(PFX+'api/bot/export_all',{method:'POST'})).json();
  toast(j.ok?'ok':'err');
  bot_note.textContent=j.msg||'';
}

/* scan ttl */
async function runScan(){
  const payload={
    target:(scan_target.value||'').trim(),
    limit:Number(scan_limit.value||250),
    download: !!scan_download.checked,
    password:(scan_pwd.value||'').toString()
  };
  if(!payload.target){ toast('укажи чат'); return; }
  scan_result.textContent = '...';
  const r = await fetch(PFX+'api/scan_ttl',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const j = await r.json();
  scan_result.textContent = JSON.stringify(j,null,2);
  if(j.ok) toast('готово'); else toast('ошибка');
}

/* snake */
let S=null;
function snakeInit(){
  if(S) return;
  const cv=snake_cv, ctx=cv.getContext('2d',{alpha:false});
  const best=Number(localStorage.getItem('snake_best')||'0'); s_best.textContent=String(best);
  S={cv,ctx,tile:18,cols:Math.floor(cv.width/18),rows:Math.floor(cv.height/18),
     dir:{x:1,y:0},next:{x:1,y:0},snake:[],food:{x:10,y:10},score:0,best,
     running:false,paused:false,last:0,speed:90};
  window.addEventListener('keydown',(e)=>{
    if(tab!=='game') return;
    const k=e.key.toLowerCase();
    if(k===' '){ if(S.running){ S.paused=!S.paused; snake_hint.textContent=S.paused?'пауза':''; e.preventDefault(); } return; }
    const map={'arrowup':{x:0,y:-1},'w':{x:0,y:-1},'arrowdown':{x:0,y:1},'s':{x:0,y:1},
               'arrowleft':{x:-1,y:0},'a':{x:-1,y:0},'arrowright':{x:1,y:0},'d':{x:1,y:0}};
    if(map[k]){ const nd=map[k]; if(S.dir.x+nd.x===0 && S.dir.y+nd.y===0) return; S.next=nd; e.preventDefault(); }
  },{passive:false});
  snakeDrawSplash();
}
function snakeDrawSplash(){
  const {ctx,cv}=S; ctx.fillStyle='#0b0e13'; ctx.fillRect(0,0,cv.width,cv.height);
  ctx.fillStyle='rgba(255,255,255,.85)'; ctx.font='700 28px system-ui'; ctx.fillText('Snake',36,70);
}
function snakeResetBest(){ localStorage.setItem('snake_best','0'); if(S){S.best=0;s_best.textContent='0';} toast('ок'); }
function snakeStart(){
  snakeInit();
  const mx=Math.floor(S.cols/2), my=Math.floor(S.rows/2);
  S.snake=[{x:mx,y:my},{x:mx-1,y:my},{x:mx-2,y:my}]; S.dir={x:1,y:0}; S.next={x:1,y:0};
  S.score=0; s_score.textContent='0'; S.food=snakeFood(); S.running=true; S.paused=false; snake_hint.textContent='';
  requestAnimationFrame(snakeLoop);
}
function snakeFood(){ while(true){ const x=Math.floor(Math.random()*S.cols), y=Math.floor(Math.random()*S.rows);
  if(!S.snake.some(s=>s.x===x&&s.y===y)) return {x,y}; } }
function snakeLoop(ts){
  if(!S||!S.running) return;
  if(S.paused){ requestAnimationFrame(snakeLoop); return; }
  if(ts-S.last>=S.speed){ S.last=ts; snakeTick(); snakeDraw(); }
  requestAnimationFrame(snakeLoop);
}
function snakeTick(){
  S.dir=S.next;
  let head={x:S.snake[0].x+S.dir.x,y:S.snake[0].y+S.dir.y};
  if(head.x<0) head.x=S.cols-1; if(head.y<0) head.y=S.rows-1; if(head.x>=S.cols) head.x=0; if(head.y>=S.rows) head.y=0;
  if(S.snake.some((s,i)=>i>0&&s.x===head.x&&s.y===head.y)){ S.running=false; snake_hint.textContent='game over'; toast('game over'); return; }
  S.snake.unshift(head);
  if(head.x===S.food.x&&head.y===S.food.y){
    S.score++; s_score.textContent=String(S.score);
    if(S.score>S.best){ S.best=S.score; localStorage.setItem('snake_best',String(S.best)); s_best.textContent=String(S.best); }
    if(S.speed>55 && S.score%6===0) S.speed-=2;
    S.food=snakeFood();
  }else S.snake.pop();
}
function snakeDraw(){
  const {ctx,cv,tile}=S; ctx.fillStyle='#0b0e13'; ctx.fillRect(0,0,cv.width,cv.height);
  ctx.strokeStyle='rgba(255,255,255,.03)'; ctx.lineWidth=1;
  for(let x=0;x<cv.width;x+=tile){ ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,cv.height); ctx.stroke(); }
  for(let y=0;y<cv.height;y+=tile){ ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(cv.width,y); ctx.stroke(); }
  ctx.fillStyle='rgba(255,204,102,.95)'; ctx.fillRect(S.food.x*tile+2,S.food.y*tile+2,tile-4,tile-4);
  for(let i=0;i<S.snake.length;i++){ const s=S.snake[i];
    ctx.fillStyle=i===0?'rgba(91,140,255,.95)':'rgba(91,140,255,.65)';
    ctx.fillRect(s.x*tile+2,s.y*tile+2,tile-4,tile-4);
  }
}

/* secret */
let secClickCount=0;
let secState={chat_id:null,chat_title:'',mode:'pc',tab:'chat',ctxMsgId:null,ctxChatId:null,loadingHistory:false};
function stoast(m){
  const t=document.getElementById('stoast');
  t.textContent=m; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 1200);
}
function secShowMain(){
  document.getElementById('sec_pwd_screen').style.display='none';
  document.getElementById('sec_main_screen').style.display='block';
  secState.mode=localStorage.getItem('sec_mode')||'pc';
  document.querySelectorAll('.sec_mode_btn').forEach(b=>b.classList.toggle('active',b.dataset.mode===secState.mode));
}
async function secOpen(){
  document.getElementById('secret_overlay').style.display='flex';
  document.getElementById('sec_pwd_screen').style.display='block';
  document.getElementById('sec_main_screen').style.display='none';
  document.getElementById('sec_pwd').value='';
  document.getElementById('sec_pwd_err').style.display='none';
  // The secret section is server-side gated (api/secret/verify sets a
  // short-lived cookie). If this browser already holds a valid cookie,
  // skip straight to the panel instead of asking again.
  try{
    const j=await (await fetch(PFX+'api/secret/status')).json();
    if(j && j.ok && j.unlocked){ secShowMain(); }
  }catch(e){}
}
function secClose(){
  document.getElementById('secret_overlay').style.display='none';
  document.getElementById('sec_ctx_menu').style.display='none';
}
async function secFetch(url, opts){
  // Every api/secret/* call is enforced server-side; if the secret cookie
  // is missing/expired the server replies 403 {error:'secret_locked'} and
  // we fall back to the password screen instead of silently failing.
  const r = await fetch(url, opts);
  if(r.status===403){
    try{
      const j=await r.clone().json();
      if(j && j.error==='secret_locked'){ secOpen(); }
    }catch(e){}
  }
  return r;
}
async function secVerify(){
  const pwd=document.getElementById('sec_pwd').value;
  const errEl=document.getElementById('sec_pwd_err');
  try{
    const r=await secFetch(PFX+'api/secret/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pwd})});
    const j=await r.json();
    if(!j.ok){
      errEl.textContent=j.error||'Неверный пароль';
      errEl.style.display='block';
      return;
    }
  }catch(e){
    errEl.textContent='Ошибка сети';
    errEl.style.display='block';
    return;
  }
  errEl.style.display='none';
  secShowMain();
}
function secSetMode(m){
  secState.mode=m;
  localStorage.setItem('sec_mode',m);
  document.querySelectorAll('.sec_mode_btn').forEach(b=>b.classList.toggle('active',b.dataset.mode===m));
}
async function secResolve(){
  const v=document.getElementById('sec_search').value.trim();
  if(!v){stoast('Введите данные');return;}
  document.getElementById('sec_loading').style.display='block';
  document.getElementById('sec_chat_view').style.display='none';
  document.getElementById('sec_media_view').style.display='none';
  document.getElementById('sec_err').style.display='none';
  document.getElementById('sec_chat_info').style.display='none';
  try{
    const r=await secFetch(PFX+'api/secret/resolve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({identifier:v})});
    const j=await r.json();
    document.getElementById('sec_loading').style.display='none';
    if(!j.ok || !j.results || !j.results.length){
      document.getElementById('sec_err').textContent=j.error||'Не найдено';
      document.getElementById('sec_err').style.display='block';
      return;
    }
    const res=j.results[0];
    secState.chat_id=res.chat_id;
    secState.chat_title=res.title||('Chat '+res.chat_id);
    document.getElementById('sec_chat_title').textContent=secState.chat_title;
    document.getElementById('sec_chat_meta').textContent='ID: '+res.chat_id+(res.username?' | @'+res.username:'')+(res.chat_type?' | '+res.chat_type:'');
    document.getElementById('sec_chat_info').style.display='block';
    document.getElementById('sec_search').value='';
    secSetTab('chat');
  }catch(e){
    document.getElementById('sec_loading').style.display='none';
    document.getElementById('sec_err').textContent='Ошибка: '+e.message;
    document.getElementById('sec_err').style.display='block';
  }
}
function secSetTab(t){
  secState.tab=t;
  document.querySelectorAll('.sec_tab_btn').forEach(b=>b.classList.toggle('active',b.dataset.tab===t));
  document.getElementById('sec_chat_view').style.display=t==='chat'?'block':'none';
  document.getElementById('sec_media_view').style.display=t==='media'?'block':'none';
  if(t==='chat') secLoadChat();
  else if(t==='media') secLoadMedia();
}
async function secLoadChat(){
  if(!secState.chat_id) return;
  document.getElementById('sec_loading').style.display='block';
  try{
    const r=await secFetch(PFX+'api/secret/chat/'+secState.chat_id+'?limit=200');
    const j=await r.json();
    document.getElementById('sec_loading').style.display='none';
    if(!j.ok){document.getElementById('sec_err').textContent='Ошибка загрузки';document.getElementById('sec_err').style.display='block';return;}
    const container=document.getElementById('sec_msgs');
    if(!j.items.length){container.innerHTML='<div class="small" style="text-align:center;padding:20px">Нет сообщений</div>';return;}
    container.innerHTML=j.items.map(m=>secMsgHtml(m)).join('');
    secBindCtxMenus();
  }catch(e){
    document.getElementById('sec_loading').style.display='none';
    stoast('Ошибка: '+e.message);
  }
}
async function secLoadFullHistory(){
  if(!secState.chat_id || secState.loadingHistory) return;
  secState.loadingHistory=true;
  const btn=document.getElementById('sec_load_history_btn');
  const status=document.getElementById('sec_history_status');
  btn.disabled=true;
  status.textContent='&#x23F3; Загрузка истории из Telegram...';
  try{
    const controller=new AbortController();
    const timeoutId=setTimeout(()=>controller.abort(), 60000);
    const r=await secFetch(PFX+'api/secret/fetch_history',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:secState.chat_id,limit:99999}),signal:controller.signal});
    clearTimeout(timeoutId);
    const j=await r.json();
    if(!j.ok){
      status.textContent='&#x274C; '+j.error;
      stoast('Ошибка: '+j.error);
      document.getElementById('sec_err').textContent='Ошибка загрузки истории: '+j.error;
      document.getElementById('sec_err').style.display='block';
    }else if(j.count>0){
      status.textContent='&#x2705; Загружено '+j.count+' сообщений (новых: '+j.saved+')';
      secLoadChat();
    }else{
      status.textContent='&#x26A0; Сообщений из Telegram нет. Показываю что есть в БД.';
      secLoadChat();
    }
  }catch(e){
    status.textContent='&#x274C; '+(e.name==='AbortError'?'Таймаут 60с':e.message);
    stoast('Ошибка: '+(e.name==='AbortError'?'Превышено время ожидания':e.message));
  }
  btn.disabled=false;
  secState.loadingHistory=false;
}
function secMsgHtml(m){
  const isOut=m.is_outgoing;
  const side=isOut?'flex-end':'flex-start';
  const bg=isOut?'rgba(91,140,255,.25)':'rgba(255,255,255,.06)';
  const align=isOut?'right':'left';
  const mediaTag=m.media?`<div class="small" style="margin-top:6px">&#x1F4CE; ${esc(m.media)}</div>`:'';
  const mediaPreview=m.media?`<div style="margin-top:6px"><a class="media-link" href="${PFX}media/${encodeURIComponent(m.media)}" target="_blank">Открыть медиа</a></div>`:'';
  return `<div style="display:flex;justify-content:${side};margin-bottom:8px">
    <div style="max-width:80%;background:${bg};border-radius:16px;padding:10px 14px;border:1px solid rgba(255,255,255,.06);position:relative">
      <div style="font-size:13px;color:var(--txt);white-space:pre-wrap;text-align:${align}">${esc(m.text)||'<span class="small">&mdash;</span>'}</div>
      ${mediaTag}${mediaPreview}
      <div style="display:flex;justify-content:space-between;align-items:center;margin-top:4px">
        <span class="small">${esc(m.date)}</span>
        <span class="small" style="cursor:pointer;padding:2px 6px;border-radius:8px" data-ctx-chat="${m.chat_id}" data-ctx-msg="${m.msg_id}" data-ctx-out="${isOut?1:0}" onclick="secOpenCtxMenu(event,this)">&#x22EF;</span>
      </div>
    </div>
  </div>`;
}
function secBindCtxMenus(){}
function secOpenCtxMenu(ev,el){
  ev.stopPropagation();
  secState.ctxChatId=parseInt(el.dataset.ctxChat);
  secState.ctxMsgId=parseInt(el.dataset.ctxMsg);
  const isOut=parseInt(el.dataset.ctxOut);
  const menu=document.getElementById('sec_ctx_items');
  let items='';
  items+=`<div class="ctx_item" onclick="secDeleteSelf()" style="padding:8px 14px;cursor:pointer;border-radius:10px">&#x1F5D1; Удалить у себя</div>`;
  items+=`<div class="ctx_item" onclick="secDeleteBoth()" style="padding:8px 14px;cursor:pointer;border-radius:10px">&#x1F5D1; Удалить у обоих</div>`;
  if(isOut) items+=`<div class="ctx_item" onclick="secEditMsg()" style="padding:8px 14px;cursor:pointer;border-radius:10px">&#x270F; Редактировать</div>`;
  menu.innerHTML=items;
  const cm=document.getElementById('sec_ctx_menu');
  cm.style.display='block';
  cm.style.left=Math.min(ev.clientX,window.innerWidth-200)+'px';
  cm.style.top=Math.min(ev.clientY,window.innerHeight-120)+'px';
  document.querySelectorAll('.ctx_item').forEach(el=>{
    el.onmouseover=function(){this.style.background='rgba(91,140,255,.15)'};
    el.onmouseout=function(){this.style.background='transparent'};
  });
}
document.addEventListener('click',function(e){
  if(!e.target.closest('#sec_ctx_menu')&&!e.target.closest('[data-ctx-msg]')){
    document.getElementById('sec_ctx_menu').style.display='none';
  }
});
async function secDeleteSelf(){
  document.getElementById('sec_ctx_menu').style.display='none';
  try{
    const r=await secFetch(PFX+'api/secret/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:secState.ctxChatId,msg_ids:[secState.ctxMsgId],scope:'self'})});
    const j=await r.json();
    if(j.ok){stoast('Удалено');secLoadChat();}else stoast('Ошибка');
  }catch(e){stoast('Ошибка');}
}
async function secDeleteBoth(){
  document.getElementById('sec_ctx_menu').style.display='none';
  try{
    const r=await secFetch(PFX+'api/secret/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:secState.ctxChatId,msg_ids:[secState.ctxMsgId],scope:'both'})});
    const j=await r.json();
    if(j.ok){stoast('Удалено');secLoadChat();}else stoast('Ошибка');
  }catch(e){stoast('Ошибка');}
}
async function secEditMsg(){
  document.getElementById('sec_ctx_menu').style.display='none';
  const newText=prompt('Новый текст:');
  if(!newText||!newText.trim()) return;
  try{
    const r=await secFetch(PFX+'api/secret/edit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:secState.ctxChatId,msg_id:secState.ctxMsgId,text:newText.trim()})});
    const j=await r.json();
    if(j.ok){stoast('Изменено');secLoadChat();}else stoast('Ошибка');
  }catch(e){stoast('Ошибка');}
}
async function secLoadMedia(){
  if(!secState.chat_id) return;
  document.getElementById('sec_loading').style.display='block';
  try{
    const controller=new AbortController();
    setTimeout(()=>controller.abort(), 30000);
    const r=await secFetch(PFX+'api/secret/chat/'+secState.chat_id+'/media',{signal:controller.signal});
    const j=await r.json();
    document.getElementById('sec_loading').style.display='none';
    const g=document.getElementById('sec_media_grid');
    if(!j.ok){g.innerHTML='<div class="small danger" style="padding:20px;text-align:center">Ошибка API: '+esc(j.error)+'</div>';return;}
    if(!j.items||!j.items.length){
      g.innerHTML='<div class="small" style="text-align:center;padding:20px">Нет медиа</div>'+
        '<div class="small" style="text-align:center;padding:10px;color:#888">'+
        'Всего записей с media в БД: '+j.db_rows+'<br>'+
        'chat_id='+secState.chat_id+'</div>'+
        '<button class="btn" onclick="secDebugDb()" style="margin:10px auto;display:block;font-size:11px">&#x1F6E0; Отладка: показать все типы в БД</button>';
      return;
    }
    g.innerHTML=j.items.map(m=>{
      let preview='';
      const isImage=m.media_type==='photo' || /\.(png|jpe?g|gif|webp|bmp)$/i.test(m.media);
      const isVideo=m.media_type==='video' || /\.(mp4|webm|mov|m4v)$/i.test(m.media);
      if(m.file_missing){
        preview='<div class="small" style="color:var(--warn);margin-bottom:4px">&#x1F4CE; Файл не скачан</div>'+
          '<button class="btn" style="font-size:11px;padding:2px 10px" onclick="secDownloadMedia('+m.msg_id+',this)">&#x2B07; Скачать из Telegram</button>';
      }else{
        const url=PFX+'media/'+encodeURIComponent(m.media);
        if(m.has_audio_player){
          preview=`<audio src="${url}" controls preload="none" style="width:100%;min-height:40px"></audio>`;
        }else if(isImage){
          preview=`<a href="${url}" target="_blank"><img src="${url}" style="max-width:100%;max-height:300px;border-radius:8px;cursor:pointer" loading="lazy"></a>`;
        }else if(isVideo){
          preview=`<video src="${url}" controls preload="none" style="max-width:100%;max-height:300px;border-radius:8px" loading="lazy"></video>`;
        }else{
          preview=`<a class="media-link" href="${url}" target="_blank">&#x1F4CE; ${esc(m.media)}</a>`;
        }
      }
      const btnGroup=m.file_missing?'':`<div class="actions" style="margin-top:6px;gap:6px">
        <a class="btn" style="font-size:11px;padding:2px 10px" href="${PFX}media/${encodeURIComponent(m.media)}" download="${esc(m.media)}">&#x1F4BE; Скачать на устройство</a>
        <button class="btn" style="font-size:11px;padding:2px 10px" onclick="secSendToBotMsg(${m.msg_id})">&#x1F916; В тайного бота</button>
      </div>`;
      return `<div class="card" style="padding:10px">
      <div class="small">${esc(m.date)}</div>
      <div style="margin:8px 0">${preview}</div>
      ${btnGroup}
      <div class="small">${esc(m.text)||'&mdash;'}</div>
    </div>`;
    }).join('');
  }catch(e){
    document.getElementById('sec_loading').style.display='none';
    stoast('Ошибка: '+e.message);
  }
}
async function secDebugDb(){
  if(!secState.chat_id) return;
  const g=document.getElementById('sec_media_grid');
  g.innerHTML='<div class="small" style="text-align:center;padding:20px">Проверка БД...</div>';
  try{
    const r=await secFetch(PFX+'api/secret/chat/'+secState.chat_id+'?limit=50');
    const j=await r.json();
    if(!j.ok){g.innerHTML='<div class="small danger" style="padding:20px">Ошибка: '+esc(j.error)+'</div>';return;}
    const types={};
    for(const m of j.items){
      const t=esc(m.media_type||'(пусто)');
      types[t]=(types[t]||0)+1;
    }
    g.innerHTML='<div class="small" style="text-align:center;padding:10px">Последние 50 сообщений (всего: '+j.total+'):<br>'+
      Object.entries(types).map(([k,v])=>'<b>'+k+'</b>: '+v).join(' | ')+
      '</div>';
  }catch(e){
    g.innerHTML='<div class="small danger" style="padding:20px">Ошибка: '+esc(e.message)+'</div>';
  }
}
async function secDownloadMedia(msgId, btn){
  if(!secState.chat_id) return;
  btn.disabled=true;
  btn.textContent='&#x23F3;...';
  try{
    const r=await secFetch(PFX+'api/secret/download_media',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:secState.chat_id,msg_id:msgId})});
    const j=await r.json();
    if(j.ok){
      stoast('&#x2705; Скачано');
      secLoadMedia();
    }else{
      stoast('&#x274C; '+j.error);
      btn.disabled=false;
      btn.textContent='&#x2B07; Скачать';
    }
  }catch(e){
    stoast('&#x274C; '+e.message);
    btn.disabled=false;
    btn.textContent='&#x2B07; Скачать';
  }
}
async function secSendToBotMsg(msgId){
  if(!secState.chat_id) return;
  if(!confirm('Отправить это медиа в тайного бота?')) return;
  try{
    const r=await secFetch(PFX+'api/secret/send_to_bot_msg',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:secState.chat_id,msg_id:msgId})});
    const j=await r.json();
    if(j.ok) stoast('&#x2705; Отправлено');
    else stoast('&#x274C; '+j.error);
  }catch(e){
    stoast('&#x274C; '+e.message);
  }
}
async function secSendToBot(){
  if(!secState.chat_id) return;
  if(!confirm('Отправить все медиа в бота?')) return;
  document.getElementById('sec_loading').style.display='block';
  try{
    const r=await secFetch(PFX+'api/secret/send_to_bot',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:secState.chat_id,media_type:'all'})});
    const j=await r.json();
    document.getElementById('sec_loading').style.display='none';
    if(j.ok) stoast('Отправлено: '+j.sent+(j.errors?' ('+j.errors+' ошибок)':''));
    else stoast(j.error||'Ошибка');
  }catch(e){
    document.getElementById('sec_loading').style.display='none';
    stoast('Ошибка: '+e.message);
  }
}
document.getElementById('secret_dot').addEventListener('click',function(){
  secClickCount++;
  if(secClickCount>=10){
    secClickCount=0;
    secOpen();
  }else{
    const dot=document.getElementById('secret_dot');
    dot.style.transition='box-shadow .15s ease';
    dot.style.boxShadow='0 0 0 12px rgba(84,166,255,.25)';
    setTimeout(()=>dot.style.boxShadow='0 0 0 6px rgba(84,140,255,.12)',300);
  }
});

/* boot */
(function(){
  loadSettings().catch(()=>{});
  loadBot().catch(()=>{});
  refreshNow();
  setInterval(refreshNow, 3000);
})();
</script>
</body>
</html>
"""


def _session_file_authorized(path):
    """True if the SQLite session file exists and holds a non-empty auth_key."""
    if not os.path.exists(path):
        return False
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True, timeout=5)
        try:
            cols = [str(c[1]) for c in con.execute("PRAGMA table_info(sessions)").fetchall()]
            if not cols or "auth_key" not in cols:
                return False
            row = con.execute("SELECT auth_key FROM sessions LIMIT 1").fetchone()
            return bool(row and row[0])
        finally:
            con.close()
    except Exception:
        return False


def _validate_session_file(path):
    """Check an uploaded .session is a Telethon SQLite session with an
    authorized auth_key. Returns (ok, error_msg)."""
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True, timeout=5)
        try:
            tables = {str(r[0]) for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            if "sessions" not in tables:
                return False, "Это не файл сессии Telethon (нет таблицы sessions)."
            cols = [str(c[1]) for c in con.execute("PRAGMA table_info(sessions)").fetchall()]
            if "auth_key" not in cols:
                return False, "В сессии нет колонки auth_key — файл неавторизован."
            row = con.execute("SELECT auth_key FROM sessions LIMIT 1").fetchone()
            if not row or not row[0]:
                return False, "Сессия не авторизована (пустой auth_key). Войдите в Telegram заново."
            return True, None
        finally:
            con.close()
    except sqlite3.DatabaseError:
        return False, "Файл не является базой SQLite (нужен .session из Telethon)."
    except Exception as e:
        return False, f"Ошибка чтения файла: {e}"


def create_account_blueprint():
    """Single blueprint serving every account panel as /<account>/...

    The account name comes from the URL, so an account added at runtime
    (from the account selector) works immediately, without re-registration.
    """
    bp = Blueprint("account_panel", __name__)

    def _acct():
        name = (request.view_args or {}).get("account")
        if not name or not _find_account(name):
            abort(404)
        return name

    def _set_ctx():
        set_account(_acct())

    def _log(line):
        _log_for(_acct(), line)

    def _bp_before_request():
        _set_ctx()
        cleanup_expired(_acct())
        path = request.path
        if path.startswith(f"/{_acct()}/api/auth/"):
            return None
        if path.endswith("/favicon.ico"):
            return None

        allowed, stale_hash = _request_has_access(_acct())
        if not allowed:
            if stale_hash:
                _log(f"stale auth cookie for ip={_get_client_ip()}")

            if path.startswith(f"/{_acct()}/api/"):
                resp = jsonify({"ok": False, "auth_required": True, "error": "authorization required"})
                _clear_access_cookies(resp, _acct())
                return resp, 401

            resp = Response(AUTH_GATE_HTML, mimetype="text/html", status=401)
            _clear_access_cookies(resp, _acct())
            return resp

        # SECURITY FIX: the "secret" sub-panel (reading/deleting/editing real
        # Telegram messages, media download, full history fetch) must be
        # gated server-side on its own password, not merely on the general
        # panel login above. `/api/secret/verify` and `/api/secret/status`
        # are reachable without the secret cookie (one checks the password,
        # the other only reports whether it's already set).
        if path.startswith(f"/{_acct()}/api/secret/") and \
                path not in (f"/{_acct()}/api/secret/verify", f"/{_acct()}/api/secret/status"):
            if not _secret_unlocked(_acct()):
                return jsonify({"ok": False, "error": "secret_locked"}), 403

        return None

    bp.before_request(_bp_before_request)

    @bp.get("/<account>/")
    def index(account=None):
        _set_ctx()
        # SECURITY: the secret password used to be injected directly into the
        # HTML/JS sent to the browser and compared client-side - anyone could
        # read it via "View Source". It is now verified exclusively server
        # side (see api_secret_verify / _secret_unlocked), so nothing secret
        # is ever embedded in the page.
        html = HTML_TEMPLATE.replace("__ACCOUNT_NAME__", _acct())
        return Response(html, mimetype="text/html")

    @bp.post("/<account>/api/auth/request")
    def api_auth_request(account=None):
        _set_ctx()
        cfg = _load_gui_cfg(_acct())
        if not cfg.get("access_control_enabled", True):
            return jsonify({"ok": False, "error": "Access control is disabled for this account."}), 400
        bot_token = str(cfg.get("bot_token") or "").strip()
        chat_id_cfg = str(cfg.get("access_chat_id") or cfg.get("bot_chat_id") or "").strip()
        if not bot_token or not chat_id_cfg:
            return jsonify({"ok": False, "error": "Telegram bot is not configured. Use the password login instead."}), 400

        device_id = get_or_create_device_id(request.cookies.get(DEVICE_COOKIE_NAME))
        user_agent = request.headers.get("User-Agent", "")
        accept_language = request.headers.get("Accept-Language", "")
        ip = _get_client_ip()
        auth_request = create_auth_request(
            device_id=device_id,
            user_agent=user_agent,
            accept_language=accept_language,
            ip=ip,
            timeout_sec=int(cfg.get("auth_timeout_sec") or 180),
            account=_acct(),
        )
        ok, msg, message_id = send_telegram_approval_request(
            bot_token=str(cfg.get("bot_token") or "").strip(),
            chat_id=str(cfg.get("access_chat_id") or cfg.get("bot_chat_id") or "").strip(),
            ip=ip,
            request_id=auth_request["request_id"],
        )
        if not ok:
            _log(f"auth request send failed: {msg}")
            return jsonify({"ok": False, "error": f"Telegram request failed: {msg}", "ip": ip}), 502

        if message_id:
            update_auth_request_message(auth_request["request_id"], int(message_id), account=_acct())

        resp = jsonify({
            "ok": True,
            "request_id": auth_request["request_id"],
            "ip": ip,
            "poll_interval_sec": POLL_INTERVAL_SEC,
        })
        _attach_device_cookie(resp, device_id, _acct())
        return resp

    @bp.get("/<account>/api/auth/status/<request_id>")
    def api_auth_status(request_id, account=None):
        _set_ctx()
        cfg = _load_gui_cfg(_acct())
        row = get_auth_request(request_id, account=_acct())
        if not row:
            return jsonify({"ok": True, "status": "expired"})

        status = row.get("status") or "pending"
        if status == "approved":
            resp = jsonify({"ok": True, "status": "approved"})
            _attach_device_cookie(resp, row["device_id"], _acct())
            _attach_access_cookie(resp, row["device_hash"], int(cfg.get("trust_days") or 30), _acct(), _acct())
            return resp
        return jsonify({"ok": True, "status": status})

    @bp.post("/<account>/api/auth/password_login")
    def api_auth_password_login(account=None):
        _set_ctx()
        data = request.get_json(silent=True) or {}
        password = str(data.get("password") or "").strip()
        secret_pwd = _get_account_secret_password(_acct())

        key = _client_key()
        locked = _auth_locked(key)
        if locked:
            return jsonify({"ok": False,
                            "error": f"Слишком много попыток. Попробуйте через {locked} сек."}), 429
        if not password or not _verify_password(password, secret_pwd):
            _auth_register_fail(key)
            time.sleep(1.0)
            return jsonify({"ok": False, "error": "Invalid password"}), 403
        _auth_clear(key)

        cfg = _load_gui_cfg(_acct())
        device_id = get_or_create_device_id(request.cookies.get(DEVICE_COOKIE_NAME))
        user_agent = request.headers.get("User-Agent", "")
        accept_language = request.headers.get("Accept-Language", "")
        user_agent_hash = build_user_agent_hash(user_agent, accept_language)
        trust_device(device_id, user_agent_hash, _get_client_ip(), int(cfg.get("trust_days") or 30), account=_acct())
        device_hash = build_device_hash(device_id, user_agent_hash)
        resp = jsonify({"ok": True})
        _attach_device_cookie(resp, device_id, _acct())
        _attach_access_cookie(resp, device_hash, int(cfg.get("trust_days") or 30), _acct(), _acct())
        _log(f"password login accepted ip={_get_client_ip()}")
        return resp

    @bp.post("/<account>/api/auth/logout")
    def api_auth_logout(account=None):
        _set_ctx()
        resp = jsonify({"ok": True})
        _clear_access_cookies(resp, _acct())
        _clear_secret_cookie(resp, _acct())
        return resp

    @bp.get("/<account>/api/settings")
    def api_get_settings(account=None):
        _set_ctx()
        payload = _load_settings(_acct())
        payload.update(get_storage_usage_bytes())
        return jsonify(payload)

    @bp.post("/<account>/api/settings")
    def api_post_settings(account=None):
        _set_ctx()
        data = request.get_json(silent=True) or {}
        cur = _load_settings(_acct())
        cur.update({k: data.get(k, cur.get(k)) for k in DEFAULT_SETTINGS})
        _save_settings(_acct(), cur)
        cleanup_result = run_cleanup(_load_settings(_acct()), logger=_log, force=True)
        return jsonify({"ok": True, "cleanup": cleanup_result})

    @bp.post("/<account>/api/cleanup")
    def api_cleanup(account=None):
        _set_ctx()
        result = run_cleanup(_load_settings(_acct()), logger=_log, force=True)
        return jsonify({"ok": True, "cleanup": result})

    @bp.get("/<account>/api/session/status")
    def api_session_status(account=None):
        _set_ctx()
        name = _acct()
        persistent = os.path.join(BASE_DIR, "accounts", name, "anti_revoke.session")
        try:
            runtime = os.path.join(tempfile.gettempdir(), "AuySoft", "anti_revoke",
                                   name, "anti_revoke.session")
        except Exception:
            runtime = persistent
        has = _session_file_authorized(persistent) or _session_file_authorized(runtime)
        return jsonify({"ok": True, "has_session": has})

    @bp.post("/<account>/api/session/upload")
    def api_session_upload(account=None):
        _set_ctx()
        name = _acct()
        f = request.files.get("session")
        if not f or not f.filename:
            return jsonify({"ok": False, "msg": "Файл не выбран."}), 400
        if not f.filename.lower().endswith(".session"):
            return jsonify({"ok": False, "msg": "Нужен файл с расширением .session."}), 400

        data = f.read()
        if not data:
            return jsonify({"ok": False, "msg": "Файл пуст."}), 400
        if len(data) > 5 * 1024 * 1024:
            return jsonify({"ok": False, "msg": "Файл слишком большой (лимит 5 MB)."}), 400

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".session")
        try:
            tmp.write(data)
            tmp.close()
            valid, err = _validate_session_file(tmp.name)
            if not valid:
                return jsonify({"ok": False, "msg": err}), 400

            # Persist to the canonical account path the watchdog reads.
            dest_dir = os.path.join(BASE_DIR, "accounts", name)
            os.makedirs(dest_dir, exist_ok=True)
            dest = os.path.join(dest_dir, "anti_revoke.session")
            shutil.copy2(tmp.name, dest)
            _log(f"session uploaded ({len(data)} bytes) -> {os.path.basename(dest)}")
            return jsonify({
                "ok": True,
                "msg": "Сессия загружена. Приёмник запустится автоматически (до ~30 сек)."
            })
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    @bp.get("/<account>/api/bot")
    def api_get_bot(account=None):
        _set_ctx()
        cfg = _load_gui_cfg(_acct())
        acct = _find_account(_acct())
        secret_token = str(acct.get("secret_bot_token") or "") if acct else ""
        secret_chat = str(acct.get("secret_bot_chat_id") or "") if acct else ""
        return jsonify({
            "bot_token": cfg.get("bot_token", "") or secret_token,
            "bot_chat_id": cfg.get("bot_chat_id", "") or secret_chat,
            "send_to_bot": bool(cfg.get("send_to_bot", False)),
            "access_control_enabled": bool(cfg.get("access_control_enabled", True)),
            "access_chat_id": cfg.get("access_chat_id", ""),
            "auth_timeout_sec": int(cfg.get("auth_timeout_sec") or 180),
            "trust_days": int(cfg.get("trust_days") or 30),
            "exclude_own_chat": bool(cfg.get("exclude_own_chat", True)),
            "exclude_from_bot": cfg.get("exclude_from_bot") or [],
        })

    @bp.post("/<account>/api/bot")
    def api_post_bot(account=None):
        _set_ctx()
        data = request.get_json(silent=True) or {}
        current_cfg = _load_gui_cfg(_acct())
        token = str(data.get("bot_token", "") or "").strip()
        chat_id = str(data.get("bot_chat_id", "") or "").strip()
        send_to_bot = bool(data.get("send_to_bot", False))
        access_control_enabled = bool(data.get("access_control_enabled", current_cfg.get("access_control_enabled", True)))
        access_chat_id = str(data.get("access_chat_id", current_cfg.get("access_chat_id", "")) or "").strip()
        auth_timeout_sec = max(30, min(int(data.get("auth_timeout_sec", current_cfg.get("auth_timeout_sec", 180)) or 180), 900))
        trust_days = max(1, min(int(data.get("trust_days", current_cfg.get("trust_days", 30)) or 30), 365))
        exclude_own_chat = bool(data.get("exclude_own_chat", True))
        exclude_from_bot = data.get("exclude_from_bot") or []

        ok = True
        msg = ""
        if token and ":" not in token:
            ok = False; msg = "Token looks invalid."
        if chat_id and not chat_id.lstrip("-").isdigit():
            ok = False; msg = "Chat ID must be numeric."
        if access_chat_id and not access_chat_id.lstrip("-").isdigit():
            ok = False; msg = "Access Chat ID must be numeric."
        if ok:
            _save_gui_cfg(_acct(), {
                "bot_token": token,
                "bot_chat_id": chat_id,
                "send_to_bot": send_to_bot,
                "access_control_enabled": access_control_enabled,
                "access_chat_id": access_chat_id,
                "auth_timeout_sec": auth_timeout_sec,
                "trust_days": trust_days,
                "exclude_own_chat": exclude_own_chat,
                "exclude_from_bot": exclude_from_bot,
            })
            msg = "Saved."
        return jsonify({"ok": ok, "msg": msg})

    @bp.post("/<account>/api/bot/test")
    def api_bot_test(account=None):
        _set_ctx()
        if requests is None:
            return jsonify({"ok": False, "msg": "requests not installed."})
        cfg = _load_gui_cfg(_acct())
        acct = _find_account(_acct())
        token = (cfg.get("bot_token") or (acct.get("secret_bot_token") if acct else "") or "").strip()
        chat_id = (cfg.get("bot_chat_id") or (acct.get("secret_bot_chat_id") if acct else "") or "").strip()
        if not token or not chat_id:
            return jsonify({"ok": False, "msg": "Fill token and chat id."})
        if not chat_id.lstrip("-").isdigit():
            return jsonify({"ok": False, "msg": "Chat ID must be numeric."})
        try:
            r = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                data={"chat_id": chat_id, "text": "Anti-Revoke: test"},
                timeout=12
            )
            j = r.json() if (r.headers.get("content-type", "") or "").startswith("application/json") else {}
            if r.status_code == 200 and j.get("ok") is True:
                return jsonify({"ok": True, "msg": "OK"})
            return jsonify({"ok": False, "msg": f"{r.status_code} {r.text[:120]}"})
        except Exception as e:
            return jsonify({"ok": False, "msg": f"{e}"})

    @bp.post("/<account>/api/bot/export_media")
    def api_bot_export_media(account=None):
        _set_ctx()
        cfg = _load_gui_cfg(_acct())
        acct = _find_account(_acct())
        token = (cfg.get("bot_token") or (acct.get("secret_bot_token") if acct else "") or "").strip()
        chat_id = (cfg.get("bot_chat_id") or (acct.get("secret_bot_chat_id") if acct else "") or "").strip()
        if requests is None:
            return jsonify({"ok": False, "msg": "requests not installed."})
        if not token or not chat_id:
            return jsonify({"ok": False, "msg": "Fill BOT_TOKEN and Chat ID."})
        if not chat_id.lstrip("-").isdigit():
            return jsonify({"ok": False, "msg": "Chat ID must be numeric."})

        zip_path = None
        try:
            zip_path, build_msg = _build_media_export_zip(_acct())
            if not zip_path:
                return jsonify({"ok": False, "msg": build_msg})

            caption = f"Anti-Revoke media export {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}"
            ok, send_msg = _bot_send_media_smart(token, chat_id, zip_path, caption)
            if ok:
                return jsonify({"ok": True, "msg": "Media archive sent to bot."})
            return jsonify({"ok": False, "msg": f"Failed to send archive: {send_msg}"})
        except Exception as e:
            _log(f"export media error: {e}")
            return jsonify({"ok": False, "msg": str(e)})
        finally:
            if zip_path:
                try:
                    tmp_dir = os.path.dirname(zip_path)
                    if os.path.exists(zip_path):
                        os.remove(zip_path)
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                except Exception:
                    pass

    @bp.post("/<account>/api/bot/export_db")
    def api_bot_export_db(account=None):
        _set_ctx()
        cfg = _load_gui_cfg(_acct())
        acct = _find_account(_acct())
        token = (cfg.get("bot_token") or (acct.get("secret_bot_token") if acct else "") or "").strip()
        chat_id = (cfg.get("bot_chat_id") or (acct.get("secret_bot_chat_id") if acct else "") or "").strip()
        if requests is None:
            return jsonify({"ok": False, "msg": "requests not installed."})
        if not token or not chat_id:
            return jsonify({"ok": False, "msg": "Fill BOT_TOKEN and Chat ID."})
        if not chat_id.lstrip("-").isdigit():
            return jsonify({"ok": False, "msg": "Chat ID must be numeric."})

        db_copy_path = None
        try:
            db_copy_path, build_msg = _build_db_export_copy(_acct())
            if not db_copy_path:
                return jsonify({"ok": False, "msg": build_msg})

            caption = f"Anti-Revoke DB export {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}"
            ok, send_msg = _bot_send_media_smart(token, chat_id, db_copy_path, caption)
            if ok:
                return jsonify({"ok": True, "msg": "messages.db sent to bot."})
            return jsonify({"ok": False, "msg": f"Failed to send DB: {send_msg}"})
        except Exception as e:
            _log(f"export db error: {e}")
            return jsonify({"ok": False, "msg": str(e)})
        finally:
            if db_copy_path:
                try:
                    tmp_dir = os.path.dirname(db_copy_path)
                    if os.path.exists(db_copy_path):
                        os.remove(db_copy_path)
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                except Exception:
                    pass

    @bp.post("/<account>/api/bot/export_all")
    def api_bot_export_all(account=None):
        _set_ctx()
        cfg = _load_gui_cfg(_acct())
        acct = _find_account(_acct())
        token = (cfg.get("bot_token") or (acct.get("secret_bot_token") if acct else "") or "").strip()
        chat_id = (cfg.get("bot_chat_id") or (acct.get("secret_bot_chat_id") if acct else "") or "").strip()
        if requests is None:
            return jsonify({"ok": False, "msg": "requests not installed."})
        if not token or not chat_id:
            return jsonify({"ok": False, "msg": "Fill BOT_TOKEN and Chat ID."})
        if not chat_id.lstrip("-").isdigit():
            return jsonify({"ok": False, "msg": "Chat ID must be numeric."})

        db_copy_path = None
        zip_path = None
        sent = []
        try:
            db_copy_path, build_msg = _build_db_export_copy(_acct())
            if not db_copy_path:
                return jsonify({"ok": False, "msg": build_msg})

            db_caption = f"Anti-Revoke DB export {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}"
            ok, send_msg = _bot_send_media_smart(token, chat_id, db_copy_path, db_caption)
            if not ok:
                return jsonify({"ok": False, "msg": f"Failed to send DB: {send_msg}"})
            sent.append("DB")

            zip_path, build_msg = _build_media_export_zip(_acct())
            if not zip_path:
                return jsonify({"ok": True, "msg": f"DB sent. Media skipped: {build_msg}"})

            media_caption = f"Anti-Revoke media export {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}"
            ok, send_msg = _bot_send_media_smart(token, chat_id, zip_path, media_caption)
            if not ok:
                return jsonify({"ok": True, "msg": f"DB sent. Media not sent: {send_msg}"})
            sent.append("media")

            return jsonify({"ok": True, "msg": "DB and media archive sent."})
        except Exception as e:
            _log(f"export all error: {e}")
            if sent:
                return jsonify({"ok": True, "msg": f"Partially sent: {', '.join(sent)}. Error: {e}"})
            return jsonify({"ok": False, "msg": str(e)})
        finally:
            for path in (db_copy_path, zip_path):
                if path:
                    try:
                        tmp_dir = os.path.dirname(path)
                        if os.path.exists(path):
                            os.remove(path)
                        shutil.rmtree(tmp_dir, ignore_errors=True)
                    except Exception:
                        pass

    @bp.get("/<account>/api/stats")
    def api_stats(account=None):
        _set_ctx()
        if not _db_ok(_acct()):
            usage = get_storage_usage_bytes()
            return jsonify({"db_ok": False, "total": 0, "hidden": 0, **usage})
        _ensure_schema(_acct())
        run_cleanup(_load_settings(_acct()), logger=_log)
        set_account(_acct())
        dp = db_path()
        conn = sqlite3.connect(dp)
        cur = conn.cursor()
        total = cur.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        hidden = cur.execute("SELECT COUNT(*) FROM messages WHERE is_deleted=1 OR is_ephemeral=1").fetchone()[0]
        last = cur.execute("SELECT MAX(date) FROM messages").fetchone()[0]
        conn.close()
        return jsonify({"db_ok": True, "total": total, "hidden": hidden, "last_dt": last, **get_storage_usage_bytes()})

    @bp.get("/<account>/api/messages")
    def api_messages(account=None):
        _set_ctx()
        if not _db_ok(_acct()):
            return jsonify({"db_ok": False, "count": 0, "items": [], "signature": None, "last_dt": None})
        _ensure_schema(_acct())
        run_cleanup(_load_settings(_acct()), logger=_log)
        hidden = request.args.get("hidden", "0") == "1"
        limit = max(1, min(int(request.args.get("limit", "300")), 600))
        offset = max(0, int(request.args.get("offset", "0")))
        q = (request.args.get("q", "") or "").strip()

        set_account(_acct())
        dp = db_path()
        conn = sqlite3.connect(dp)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        where = []
        args = []
        if hidden:
            where.append("(is_deleted=1 OR is_ephemeral=1)")
        if q:
            where.append("(text LIKE ? OR chat_title LIKE ? OR username LIKE ?)")
            like = f"%{q}%"
            args.extend([like, like, like])

        wsql = ("WHERE " + " AND ".join(where)) if where else ""
        cur.execute(f"""
            SELECT chat_id, msg_id, chat_title, chat_type, sender, username, phone,
                   text, date, media_path, media_type, is_deleted, is_ephemeral, is_outgoing
            FROM messages
            {wsql}
            ORDER BY date DESC
            LIMIT ? OFFSET ?
        """, (*args, limit, offset))
        rows = [dict(r) for r in cur.fetchall()]
        last = cur.execute("SELECT MAX(date) FROM messages").fetchone()[0]
        conn.close()

        items = []
        for r in rows:
            items.append({
                "chat": r.get("chat_title") or str(r.get("chat_id")),
                "dt": _fmt_dt(r.get("date") or ""),
                "who": r.get("sender") or "",
                "username": r.get("username") or "",
                "phone": r.get("phone") or "",
                "text": r.get("text") or "",
                "media": os.path.basename(r.get("media_path") or "") if (r.get("media_path") or "") else "",
                "media_type": r.get("media_type") or "",
                "is_deleted": bool(r.get("is_deleted")),
                "is_ephemeral": bool(r.get("is_ephemeral")),
                "is_outgoing": bool(r.get("is_outgoing")),
            })

        sig = {"hidden": hidden, "q": q, "n": len(items), "last": last}
        return jsonify({"db_ok": True, "count": len(items), "items": items, "signature": sig, "last_dt": last})

    @bp.get("/<account>/media/<path:filename>")
    def media_file(filename, account=None):
        _set_ctx()
        if not filename:
            abort(404)
        safe_name = os.path.basename(filename)
        set_account(_acct())
        mf = media_folder()
        full_path = os.path.abspath(os.path.join(mf, safe_name))
        media_root = os.path.abspath(mf)
        if os.path.commonpath([media_root, full_path]) != media_root:
            abort(404)
        if not os.path.isfile(full_path):
            abort(404)
        return send_from_directory(mf, safe_name, conditional=True)

    @bp.post("/<account>/api/scan_ttl")
    def api_scan_ttl(account=None):
        _set_ctx()
        data = request.get_json(silent=True) or {}
        target = (data.get("target") or "").strip()
        limit = int(data.get("limit") or 250)
        limit = max(10, min(limit, 5000))
        download = bool(data.get("download", True))
        pwd = str(data.get("password") or "").strip()

        if not target:
            return jsonify({"ok": False, "error": "target required"})

        set_account(_acct())
        acct_dir = account_dir()
        scan_exe = os.path.join(acct_dir, "scan_ttl.exe")
        scan_py = os.path.join(acct_dir, "scan_ttl.py")

        if os.path.exists(scan_exe):
            cmd = [scan_exe, "--target", target, "--limit", str(limit), "--download", "1" if download else "0"]
            if pwd:
                cmd += ["--password", pwd]
        else:
            runner = sys.executable
            if getattr(sys, "frozen", False) and os.path.exists(os.path.join(acct_dir, "python.exe")):
                runner = os.path.join(acct_dir, "python.exe")
            cmd = [runner, scan_py, "--target", target, "--limit", str(limit), "--download", "1" if download else "0"]
            if pwd:
                cmd += ["--password", pwd]

        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=180, cwd=acct_dir, stdin=subprocess.DEVNULL)
            out = (p.stdout or "").strip()
            if not out:
                return jsonify({"ok": False, "error": (p.stderr or "").strip()[:400] or "no output"})
            try:
                return jsonify(json.loads(out))
            except Exception:
                return jsonify({"ok": False, "error": "bad json", "raw": out[:400]})
        except subprocess.TimeoutExpired:
            return jsonify({"ok": False, "error": "timeout"})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)})

    @bp.get("/<account>/api/secret/status")
    def api_secret_status(account=None):
        _set_ctx()
        return jsonify({"ok": True, "unlocked": _secret_unlocked(_acct())})

    @bp.post("/<account>/api/secret/verify")
    def api_secret_verify(account=None):
        _set_ctx()
        data = request.get_json(silent=True) or {}
        pwd = data.get("password", "")
        secret_pwd = _get_account_secret_password(_acct())
        key = "secret:" + _client_key()
        if _auth_locked(key):
            return jsonify({"ok": False, "error": "Too many attempts"})
        if not pwd or not _verify_password(str(pwd), secret_pwd):
            _auth_register_fail(key)
            time.sleep(1.0)
            return jsonify({"ok": False, "error": "Invalid password"})
        _auth_clear(key)
        resp = jsonify({"ok": True})
        _attach_secret_cookie(resp, _acct())
        _log(f"secret unlocked ip={_get_client_ip()}")
        return resp

    @bp.post("/<account>/api/secret/resolve")
    def api_secret_resolve(account=None):
        _set_ctx()
        data = request.get_json(silent=True) or {}
        identifier = (data.get("identifier") or "").strip()
        if not identifier:
            return jsonify({"ok": False, "error": "Enter username/phone/ID"})

        rows = []
        if _db_ok(_acct()):
            # BUG FIX: same lazily-created-schema issue as the other /secret/
            # endpoints - avoid a raw 500 when `messages` doesn't exist yet.
            _ensure_schema(_acct())
            set_account(_acct())
            dp = db_path()
            conn = sqlite3.connect(dp)
            try:
                cur = conn.cursor()
                clean = identifier.lstrip("@")
                cur.execute("""
                    SELECT DISTINCT chat_id, chat_title, username, chat_type
                    FROM messages
                    WHERE username LIKE ? OR chat_title LIKE ? OR CAST(chat_id AS TEXT) LIKE ?
                    LIMIT 10
                """, (f"%{clean}%", f"%{identifier}%", f"%{identifier}%"))
                rows = cur.fetchall()
            finally:
                conn.close()

        if rows:
            results = [{"chat_id": r[0], "title": r[1], "username": r[2], "chat_type": r[3]} for r in rows]
            return jsonify({"ok": True, "from_db": True, "results": results})

        set_account(_acct())
        acct_dir = account_dir()
        secret_py = os.path.join(acct_dir, "secret_ops.py")
        if os.path.exists(secret_py):
            try:
                runner = sys.executable
                p = subprocess.run(
                    [runner, secret_py, "resolve", "--identifier", identifier],
                    capture_output=True, text=True, timeout=30, cwd=acct_dir, stdin=subprocess.DEVNULL
                )
                out = (p.stdout or "").strip()
                if out:
                    result = json.loads(out)
                    if result.get("ok"):
                        return jsonify({"ok": True, "from_db": False, "results": [result]})
                    return jsonify({"ok": False, "error": result.get("error", "Not found")})
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)})

        return jsonify({"ok": False, "error": "Chat not found in DB or Telegram."})

    @bp.get("/<account>/api/secret/chat/<chat_id>")
    def api_secret_chat(chat_id, account=None):
        _set_ctx()
        try:
            chat_id = int(chat_id)
        except (ValueError, TypeError):
            return jsonify({"ok": False, "error": "Invalid chat_id"})
        limit = min(int(request.args.get("limit", 200)), 500)
        offset = max(0, int(request.args.get("offset", 0)))

        # BUG FIX: without this, a freshly created account (whose `messages`
        # table has never been created, since that normally happens lazily
        # from /api/messages or /api/stats) returned a raw 500/traceback
        # here instead of an empty, well-formed result.
        if not _db_ok(_acct()):
            return jsonify({"ok": True, "chat_id": chat_id, "chat_title": f"Chat {chat_id}",
                             "chat_type": "", "total": 0, "items": []})
        _ensure_schema(_acct())

        set_account(_acct())
        dp = db_path()
        conn = sqlite3.connect(dp)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.cursor()

            cur.execute("""
                SELECT chat_id, msg_id, chat_title, chat_type, sender, username, phone,
                       text, date, media_path, media_type, is_deleted, is_ephemeral, is_outgoing
                FROM messages
                WHERE chat_id=?
                ORDER BY date DESC
                LIMIT ? OFFSET ?
            """, (chat_id, limit, offset))
            rows = [dict(r) for r in cur.fetchall()]

            cur.execute("SELECT COUNT(*) FROM messages WHERE chat_id=?", (chat_id,))
            total = cur.fetchone()[0]

            cur.execute("""
                SELECT chat_title, chat_type, MIN(date), MAX(date)
                FROM messages WHERE chat_id=? GROUP BY chat_title, chat_type
            """, (chat_id,))
            info = cur.fetchone()
        finally:
            conn.close()

        items = []
        for r in reversed(rows):
            items.append({
                "chat_id": r["chat_id"],
                "msg_id": r["msg_id"],
                "text": r.get("text") or "",
                "date": _fmt_dt(r.get("date") or ""),
                "sender": r.get("sender") or "",
                "username": r.get("username") or "",
                "is_outgoing": bool(r.get("is_outgoing")),
                "media": os.path.basename(r.get("media_path") or "") if r.get("media_path") else "",
                "media_type": r.get("media_type") or "",
                "is_deleted": bool(r.get("is_deleted")),
            })

        chat_title = info[0] if info else f"Chat {chat_id}"
        chat_type = info[1] if info else ""

        return jsonify({
            "ok": True,
            "chat_id": chat_id,
            "chat_title": chat_title,
            "chat_type": chat_type,
            "total": total,
            "items": items,
        })

    @bp.get("/<account>/api/secret/chat/<chat_id>/media")
    def api_secret_chat_media(chat_id, account=None):
        _set_ctx()
        try:
            chat_id = int(chat_id)
        except (ValueError, TypeError):
            return jsonify({"ok": False, "error": "Invalid chat_id"})

        # BUG FIX: same lazily-created-schema issue as api_secret_chat above.
        if not _db_ok(_acct()):
            return jsonify({"ok": True, "items": [], "count": 0, "db_rows": 0})
        _ensure_schema(_acct())

        set_account(_acct())
        dp = db_path()
        conn = sqlite3.connect(dp)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT msg_id, text, date, media_path, media_type, is_outgoing
                FROM messages
                WHERE chat_id=?
                  AND (media_path IS NOT NULL AND media_path != ''
                       OR media_type IS NOT NULL AND media_type != '')
                ORDER BY date DESC
            """, (chat_id,))
            rows = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

        audio_exts = {'.ogg', '.opus', '.oga', '.wav', '.mp3', '.m4a', '.aac', '.flac'}
        items = []
        for r in rows:
            fname = os.path.basename(r.get("media_path") or "")
            ext = os.path.splitext(fname)[1].lower()
            mt = r.get("media_type") or ""
            items.append({
                "msg_id": r["msg_id"],
                "text": (r.get("text") or "")[:100],
                "date": _fmt_dt(r.get("date") or ""),
                "media": fname,
                "media_type": mt or "unknown",
                "is_outgoing": bool(r.get("is_outgoing")),
                "file_missing": 1 if not fname else 0,
                "has_audio_player": 1 if (mt in ('voice', 'video_note') or ext in audio_exts) else 0,
            })

        return jsonify({"ok": True, "items": items, "count": len(items), "db_rows": len(rows)})

    @bp.post("/<account>/api/secret/delete")
    def api_secret_delete(account=None):
        _set_ctx()
        data = request.get_json(silent=True) or {}
        chat_id = data.get("chat_id")
        msg_ids = data.get("msg_ids", [])
        scope = data.get("scope", "self")

        if not chat_id or not msg_ids:
            return jsonify({"ok": False, "error": "chat_id and msg_ids required"})
        try:
            chat_id = int(chat_id)
            msg_ids = [int(m) for m in msg_ids]
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "chat_id and msg_ids must be integers"}), 400

        set_account(_acct())
        dp = db_path()
        conn = sqlite3.connect(dp, timeout=10)
        try:
            cur = conn.cursor()
            for mid in msg_ids:
                cur.execute("""
                    UPDATE messages SET is_deleted=1, sent_to_bot=1
                    WHERE chat_id=? AND msg_id=?
                """, (chat_id, mid))
            conn.commit()
        finally:
            conn.close()

        if scope == "both":
            acct_dir = account_dir()
            secret_py = os.path.join(acct_dir, "secret_ops.py")
            if os.path.exists(secret_py):
                try:
                    runner = sys.executable
                    ids_str = [str(m) for m in msg_ids]
                    p = subprocess.run(
                        [runner, secret_py, "delete", "--chat-id", str(chat_id),
                         "--msg-ids"] + ids_str + ["--revoke", "true"],
                        capture_output=True, text=True, timeout=30, cwd=acct_dir, stdin=subprocess.DEVNULL
                    )
                    out = (p.stdout or "").strip()
                    if out:
                        result = json.loads(out)
                        if not result.get("ok"):
                            return jsonify({"ok": True, "warning": "Deleted locally, but not in Telegram: " + result.get("error", "")})
                except Exception as e:
                    return jsonify({"ok": True, "warning": f"Deleted locally. Telegram error: {str(e)}"})

        return jsonify({"ok": True})

    @bp.post("/<account>/api/secret/edit")
    def api_secret_edit(account=None):
        _set_ctx()
        data = request.get_json(silent=True) or {}
        chat_id = data.get("chat_id")
        msg_id = data.get("msg_id")
        new_text = (data.get("text") or "").strip()

        if not chat_id or not msg_id or not new_text:
            return jsonify({"ok": False, "error": "chat_id, msg_id and text required"})
        try:
            chat_id = int(chat_id)
            msg_id = int(msg_id)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "chat_id and msg_id must be integers"}), 400

        set_account(_acct())
        dp = db_path()
        conn = sqlite3.connect(dp, timeout=10)
        try:
            cur = conn.cursor()
            cur.execute("UPDATE messages SET text=? WHERE chat_id=? AND msg_id=?", (new_text, chat_id, msg_id))
            conn.commit()
        finally:
            conn.close()

        acct_dir = account_dir()
        secret_py = os.path.join(acct_dir, "secret_ops.py")
        if os.path.exists(secret_py):
            try:
                runner = sys.executable
                subprocess.run(
                    [runner, secret_py, "edit", "--chat-id", str(chat_id),
                     "--msg-ids", str(msg_id), "--text", new_text],
                    capture_output=True, text=True, timeout=30, cwd=acct_dir, stdin=subprocess.DEVNULL
                )
            except Exception:
                pass

        return jsonify({"ok": True})

    def _get_secret_bot():
        acct = _find_account(_acct())
        token = str(acct.get("secret_bot_token") or "") if acct else ""
        chat_id_bot = str(acct.get("secret_bot_chat_id") or "") if acct else ""
        if not token or not chat_id_bot:
            cfg = _load_gui_cfg(_acct())
            token = (cfg.get("bot_token") or "").strip()
            chat_id_bot = (cfg.get("bot_chat_id") or "").strip()
        return token, chat_id_bot

    @bp.post("/<account>/api/secret/send_to_bot_msg")
    def api_secret_send_to_bot_msg(account=None):
        _set_ctx()
        try:
            data = request.get_json(silent=True) or {}
            chat_id = data.get("chat_id")
            msg_id = data.get("msg_id")

            if not chat_id or not msg_id:
                return jsonify({"ok": False, "error": "chat_id and msg_id required"})

            set_account(_acct())
            dp = db_path()
            conn = sqlite3.connect(dp, timeout=10)
            cur = conn.cursor()
            cur.execute("SELECT media_path, text, sender, date FROM messages WHERE chat_id=? AND msg_id=?", (int(chat_id), int(msg_id)))
            row = cur.fetchone()
            conn.close()

            if not row:
                return jsonify({"ok": False, "error": "Message not found"})
            media_path, text, sender, date = row
            if not media_path or not os.path.exists(media_path):
                return jsonify({"ok": False, "error": "Media file not found on disk. Download it first."})

            token, chat_id_bot = _get_secret_bot()
            if not token or not chat_id_bot:
                return jsonify({"ok": False, "error": "Secret bot not configured"})

            caption = f"{sender} {_fmt_dt(date)}"[:1024]
            ok, err = _bot_send_media_smart(token, chat_id_bot, media_path, caption)
            if ok:
                return jsonify({"ok": True})
            return jsonify({"ok": False, "error": err})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)})

    @bp.post("/<account>/api/secret/send_to_bot")
    def api_secret_send_to_bot(account=None):
        _set_ctx()
        data = request.get_json(silent=True) or {}
        chat_id = data.get("chat_id")
        media_type_filter = data.get("media_type", "all")

        if not chat_id:
            return jsonify({"ok": False, "error": "chat_id required"})

        token, chat_id_bot = _get_secret_bot()
        if not token or not chat_id_bot:
            return jsonify({"ok": False, "error": "Secret bot not configured"})

        where_media = "media_path IS NOT NULL AND media_path != ''"

        set_account(_acct())
        dp = db_path()
        conn = sqlite3.connect(dp)
        cur = conn.cursor()
        cur.execute(f"""
            SELECT media_path, media_type, text, date, sender
            FROM messages
            WHERE chat_id=? AND {where_media}
            ORDER BY date ASC
        """, (int(chat_id),))
        rows = cur.fetchall()
        conn.close()

        if not rows:
            return jsonify({"ok": False, "error": "No files to send"})

        sent = 0
        errors = []
        for media_path, mtype, text, date, sender in rows:
            if not media_path or not os.path.exists(media_path):
                continue
            caption = f"{sender} {_fmt_dt(date)}"
            ok, _ = _bot_send_media_smart(token, chat_id_bot, media_path, caption)
            if ok:
                sent += 1
            else:
                errors.append(os.path.basename(media_path))
            time.sleep(0.3)

        return jsonify({"ok": True, "sent": sent, "errors": len(errors)})

    @bp.post("/<account>/api/secret/fetch_history")
    def api_secret_fetch_history(account=None):
        _set_ctx()
        data = request.get_json(silent=True) or {}
        chat_id = data.get("chat_id")
        limit = min(int(data.get("limit", 50000)), 50000)

        if not chat_id:
            return jsonify({"ok": False, "error": "chat_id required"})

        set_account(_acct())
        acct_dir = account_dir()
        secret_py = os.path.join(acct_dir, "secret_ops.py")
        if not os.path.exists(secret_py):
            return jsonify({"ok": False, "error": "secret_ops.py not found"})

        try:
            runner = sys.executable
            p = subprocess.run(
                [runner, secret_py, "fetch", "--chat-id", str(chat_id), "--limit", str(limit)],
                capture_output=True, text=True, timeout=180, cwd=acct_dir, stdin=subprocess.DEVNULL
            )
            out = (p.stdout or "").strip()
            err = (p.stderr or "").strip()[:500]
            if not out:
                msg = "No response from fetcher"
                if err:
                    msg += f" (stderr: {err})"
                return jsonify({"ok": False, "error": msg})
            try:
                result = json.loads(out)
            except json.JSONDecodeError:
                return jsonify({"ok": False, "error": "fetcher returned non-JSON: " + out[:300] + f" | stderr: {err}"})
            if not result.get("ok"):
                return jsonify({"ok": False, "error": result.get("error", "fetch failed") + (f" | stderr: {err}" if err else "")})

            messages = result.get("messages", [])
            chat_title = result.get("chat_title", "")
            chat_type = result.get("chat_type", "private")
            saved = 0
            dp = db_path()
            conn = sqlite3.connect(dp, timeout=10)
            cur = conn.cursor()
            for m in messages:
                msg_id_m = m.get("msg_id")
                text_m = m.get("text", "")
                date_m = m.get("date", "")
                sender_m = m.get("sender", "")
                username_m = m.get("username", "")
                is_outgoing_m = int(m.get("is_outgoing", 0))
                media_type_m = m.get("media_type", "") or ""
                cur.execute("""
                    INSERT OR IGNORE INTO messages
                    (chat_id, msg_id, chat_title, chat_type, sender, username, phone, date, text,
                     media_path, media_type, is_deleted, deletion_date, is_ephemeral, sent_to_bot, is_outgoing)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    int(chat_id), int(msg_id_m), chat_title, chat_type,
                    sender_m, username_m, "",
                    date_m, text_m,
                    "", media_type_m or None,
                    0, None,
                    0, 0,
                    is_outgoing_m
                ))
                if cur.rowcount:
                    saved += 1
            conn.commit()
            conn.close()
            return jsonify({"ok": True, "count": len(messages), "saved": saved})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)})

    @bp.post("/<account>/api/secret/download_media")
    def api_secret_download_media(account=None):
        _set_ctx()
        data = request.get_json(silent=True) or {}
        chat_id = data.get("chat_id")
        msg_id = data.get("msg_id")
        if not chat_id or not msg_id:
            return jsonify({"ok": False, "error": "chat_id and msg_id required"})

        set_account(_acct())
        acct_dir = account_dir()
        secret_py = os.path.join(acct_dir, "secret_ops.py")
        if not os.path.exists(secret_py):
            return jsonify({"ok": False, "error": "secret_ops.py not found"})
        try:
            runner = sys.executable
            p = subprocess.run(
                [runner, secret_py, "download", "--chat-id", str(chat_id), "--msg-ids", str(msg_id)],
                capture_output=True, text=True, timeout=60, cwd=acct_dir, stdin=subprocess.DEVNULL
            )
            out = (p.stdout or "").strip()
            err = (p.stderr or "").strip()[:300]
            if not out:
                return jsonify({"ok": False, "error": "No response" + (f" (stderr: {err})" if err else "")})
            result = json.loads(out)
            if not result.get("ok"):
                return jsonify({"ok": False, "error": result.get("error", "download failed")})
            media_path = result.get("media_path")
            media_type = result.get("media_type", "")
            if media_path:
                dp = db_path()
                conn = sqlite3.connect(dp, timeout=10)
                cur = conn.cursor()
                cur.execute("UPDATE messages SET media_path=?, media_type=? WHERE chat_id=? AND msg_id=?",
                            (media_path, media_type, int(chat_id), int(msg_id)))
                conn.commit()
                conn.close()
            return jsonify({"ok": True, "media": result.get("media", ""), "media_path": media_path})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)})

    return bp


def init_account_runtime(name):
    """Create account folders/databases and start its Telegram auth poller."""
    set_account(name)
    os.makedirs(account_dir(), exist_ok=True)
    init_auth_db(name)
    _load_gui_cfg(name)
    _load_settings(name)
    ensure_polling_started_for_account(
        name,
        lambda a=name: _load_gui_cfg(a),
        lambda msg, a=name: _log_for(a, msg),
    )


def create_app():
    # static_folder=None: this app never ships a /static directory and has
    # no reason to expose Flask's default static-file route, which would
    # otherwise serve anything placed under a "static/" folder next to this
    # file with no authentication at all.
    app = Flask(__name__, static_folder=None)

    # SECURITY FIX: used to fall back to a hard-coded default password
    # ("uC1dyF7hoA5izT0") for /api/admin/* (full backup/export of every
    # account's secrets and live Telegram sessions). A random one is now
    # generated and hashed into passwords.json on first run if missing.
    _ensure_admin_password_initialized()

    # One blueprint serves every account (/<account>/...), so an account added
    # at runtime from the selector is immediately available.
    app.register_blueprint(create_account_blueprint())

    for acct in _get_account_list():
        name = acct.get("name")
        if not name:
            continue
        init_account_runtime(name)

    @app.get("/")
    def root_index():
        accts = _get_account_list()
        accts_json = json.dumps([{"name": a.get("name", ""), "api_id": a.get("api_id", "")} for a in accts], ensure_ascii=False)
        html = SELECTOR_HTML.replace("__ACCOUNTS_JSON__", accts_json)
        return Response(html, mimetype="text/html")

    @app.get("/api/selector/state")
    def selector_state():
        return jsonify({"ok": True, **_selector_password_state()})

    @app.post("/api/selector/unlock")
    def selector_unlock():
        data = request.get_json(silent=True) or {}
        ok, err = _verify_selector_password(str(data.get("password") or ""))
        if not ok:
            return jsonify({"ok": False, "error": err}), 403
        return jsonify({"ok": True})

    # --- Global admin panel (not tied to any account) ----------------------
    @app.post("/api/admin/login")
    def api_admin_login():
        data = request.get_json(silent=True) or {}
        ok, err = _verify_admin_password(str(data.get("password") or ""))
        if not ok:
            return jsonify({"ok": False, "error": err}), 403
        _log_for("_admin", f"admin login ip={_get_client_ip()}")
        return jsonify({"ok": True, "token": _admin_issue_token()})

    @app.get("/api/admin/info")
    def api_admin_info():
        if not _admin_token_ok(request.args.get("token") or request.headers.get("X-Admin-Token")):
            return jsonify({"ok": False, "error": "Требуется вход в админ-панель"}), 403
        accounts = []
        for a in _get_account_list():
            name = str(a.get("name") or "")
            d = os.path.join(BASE_DIR, "accounts", name)
            has_session = os.path.exists(os.path.join(d, "anti_revoke.session"))
            accounts.append({"name": name, "api_id": a.get("api_id", ""),
                             "has_session": has_session})
        return jsonify({"ok": True, "accounts": accounts})

    @app.get("/api/admin/export")
    def api_admin_export():
        token = request.args.get("token") or request.headers.get("X-Admin-Token")
        if not _admin_token_ok(token):
            return jsonify({"ok": False, "error": "Требуется вход в админ-панель"}), 403
        include_media = str(request.args.get("media") or "0") == "1"

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        tmp.close()
        written = 0
        try:
            with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as z:
                for fname in ("accounts.json", "passwords.json"):
                    p = os.path.join(BASE_DIR, fname)
                    if os.path.exists(p):
                        z.write(p, fname)
                        written += 1
                acc_root = os.path.join(BASE_DIR, "accounts")
                if os.path.isdir(acc_root):
                    for base, dirs, files in os.walk(acc_root):
                        if not include_media:
                            dirs[:] = [d for d in dirs if d != "media"]
                        for f in files:
                            if f.endswith((".tmp", ".bak")):
                                continue
                            fp = os.path.join(base, f)
                            rel = os.path.relpath(fp, BASE_DIR)
                            z.write(fp, rel)
                            written += 1
                z.writestr("README_MIGRATION.txt",
                           "Anti-Revoke backup.\n"
                           "1. Распакуйте contents/ в корень нового хоста\n"
                           "   (accounts.json, passwords.json, accounts/).\n"
                           "2. Не перезаписывайте accounts.json/passwords.json,\n"
                           "   если на новом хосте уже есть ваши данные.\n"
                           "3. Перезапустите приложение.\n")
            _log_for("_admin", f"admin export: {written} files "
                               f"media={include_media} ip={_get_client_ip()}")
            stamp = time.strftime("%Y%m%d_%H%M%S")
            resp = send_file(tmp.name, as_attachment=True,
                             download_name=f"anti_revoke_backup_{stamp}.zip",
                             mimetype="application/zip")
            resp.call_on_close(lambda: _unlink_quiet(tmp.name))
            return resp
        except Exception:
            _unlink_quiet(tmp.name)
            raise

    @app.post("/api/accounts")
    def api_add_account():
        data = request.get_json(silent=True) or {}

        ok, err = _verify_selector_password(str(data.get("password") or ""))
        if not ok:
            return jsonify({"ok": False, "error": err}), 403

        name = str(data.get("name") or "").strip().lower()
        if not re.fullmatch(r"[a-z0-9_-]{2,32}", name):
            return jsonify({"ok": False, "error": "Имя аккаунта: 2-32 символа, латиница, цифры, _ и -"}), 400
        if _find_account(name):
            return jsonify({"ok": False, "error": "Аккаунт с таким именем уже существует"}), 409

        api_id_raw = str(data.get("api_id") or "").strip()
        api_hash = str(data.get("api_hash") or "").strip().lower()
        if not api_id_raw.isdigit() or int(api_id_raw) <= 0:
            return jsonify({"ok": False, "error": "api_id должен быть числом"}), 400
        if not re.fullmatch(r"[0-9a-f]{32}", api_hash):
            return jsonify({"ok": False, "error": "api_hash — 32 hex-символа (из my.telegram.org)"}), 400

        cfg = _load_accounts_config()
        accounts = cfg.setdefault("accounts", [])
        if any(str(a.get("name") or "").lower() == name for a in accounts):
            return jsonify({"ok": False, "error": "Аккаунт с таким именем уже существует"}), 409

        accounts.append({
            "name": name,
            "api_id": int(api_id_raw),
            "api_hash": api_hash,
            "secret_password": _get_shared_secret_password(),
            "secret_bot_token": "",
            "secret_bot_chat_id": "",
        })
        _save_accounts_config(cfg)

        init_account_runtime(name)
        _log_for(name, f"account added via selector ip={_get_client_ip()}")

        return jsonify({
            "ok": True,
            "name": name,
            "path": f"/{name}/",
            "message": (
                f"Аккаунт «{name}» добавлен. Панель уже доступна: /{name}/. "
                f"Загрузите файл сессии accounts/{name}/anti_revoke.session — "
                "приёмник сообщений подключится сам в течение ~30 секунд."
            ),
        })

    # --- Telegram login from the selector (creates .session) --------------
    @app.post("/api/session/start")
    def api_session_start():
        data = request.get_json(silent=True) or {}
        ok, err = _verify_selector_password(str(data.get("password") or ""))
        if not ok:
            return jsonify({"ok": False, "error": err}), 403

        name = str(data.get("name") or "").strip().lower()
        acct = _find_account(name)
        if not acct:
            return jsonify({"ok": False, "error": "Аккаунт не найден. Сначала добавьте аккаунт."}), 404

        phone = _normalize_phone(data.get("phone") or "")
        if not re.fullmatch(r"\+\d{7,15}", phone):
            return jsonify({"ok": False, "error": "Телефон в формате +79991234567"}), 400

        api_id = acct.get("api_id")
        api_hash = acct.get("api_hash")
        if not api_id or not api_hash:
            return jsonify({"ok": False, "error": "У аккаунта нет api_id/api_hash"}), 400

        # Optional: user clicks "resend via SMS" -> force SMS delivery instead
        # of dropping the code into the Telegram app.
        force_sms = str(data.get("force_sms") or "").lower() in ("1", "true", "yes")

        try:
            via = _run_login_coro(_tg_send_code(name, api_id, api_hash, phone, force_sms=force_sms),
                                 timeout=90)
        except Exception as e:
            return jsonify({"ok": False, "error": f"Не удалось отправить код: {e}"}), 502

        _log_for(name, f"session login: code requested via={via} phone={phone} force_sms={force_sms} ip={_get_client_ip()}")
        return jsonify({"ok": True, "need": "code", "sent_via": via, "phone": phone})

    @app.post("/api/session/verify")
    def api_session_verify():
        data = request.get_json(silent=True) or {}
        ok, err = _verify_selector_password(str(data.get("password") or ""))
        if not ok:
            return jsonify({"ok": False, "error": err}), 403

        name = str(data.get("name") or "").strip().lower()
        if not _find_account(name):
            return jsonify({"ok": False, "error": "Аккаунт не найден"}), 404

        code = str(data.get("code") or "").strip()
        if not code:
            return jsonify({"ok": False, "error": "Введите код из Telegram"}), 400
        password_2fa = str(data.get("code_password") or "").strip()

        try:
            done, err = _run_login_coro(_tg_sign_in(name, code, password_2fa), timeout=90)
        except Exception as e:
            return jsonify({"ok": False, "error": f"Ошибка входа: {e}"}), 502

        if not done:
            if err == "__NEED_2FA__":
                return jsonify({"ok": False, "need": "2fa",
                                "error": "Включена двухфакторная защита — введите пароль"})
            return jsonify({"ok": False, "error": err}), 400

        _log_for(name, f"session login success ip={_get_client_ip()}")
        return jsonify({
            "ok": True,
            "message": (
                f"Авторизация завершена, сессия сохранена для «{name}». "
                "Приёмник сообщений подключится в течение ~30 секунд."
            ),
        })

    # --- Save secret bot credentials (token + chat id) for an account -----
    @app.post("/api/accounts/secret-bot")
    def api_accounts_secret_bot():
        data = request.get_json(silent=True) or {}
        ok, err = _verify_selector_password(str(data.get("password") or ""))
        if not ok:
            return jsonify({"ok": False, "error": err}), 403

        name = str(data.get("name") or "").strip().lower()
        cfg = _load_accounts_config()
        acct = next((a for a in cfg.get("accounts", []) if a.get("name") == name), None)
        if not acct:
            return jsonify({"ok": False, "error": "Аккаунт не найден"}), 404

        token = str(data.get("secret_bot_token") or "").strip()
        chat_id = str(data.get("secret_bot_chat_id") or "").strip()

        # Both fields are optional, but if one is given the other must be valid.
        if token and ":" not in token:
            return jsonify({"ok": False, "error": "Токен бота в формате 123456:ABC-..."}), 400
        if chat_id and not chat_id.lstrip("-").isdigit():
            return jsonify({"ok": False, "error": "Chat ID должен быть числом"}), 400

        acct["secret_bot_token"] = token
        acct["secret_bot_chat_id"] = chat_id
        _save_accounts_config(cfg)
        _log_for(name, f"secret bot saved (token={'yes' if token else 'no'}) ip={_get_client_ip()}")

        if token and chat_id:
            msg = f"Бот сохранён для «{name}»."
        else:
            msg = f"Данные бота сохранены для «{name}» (пусто)."
        return jsonify({"ok": True, "message": msg})

    # --- Delete an account (config entry + its data folder) ---------------
    @app.post("/api/accounts/delete")
    def api_accounts_delete():
        data = request.get_json(silent=True) or {}
        ok, err = _verify_deletion_password(str(data.get("password") or ""))
        if not ok:
            return jsonify({"ok": False, "error": err}), 403

        name = str(data.get("name") or "").strip().lower()
        if not re.fullmatch(r"[a-z0-9_-]{2,32}", name):
            return jsonify({"ok": False, "error": "Некорректное имя аккаунта"}), 400

        cfg = _load_accounts_config()
        before = len(cfg.get("accounts", []))
        cfg["accounts"] = [a for a in cfg.get("accounts", []) if a.get("name") != name]
        if len(cfg.get("accounts", [])) == before:
            return jsonify({"ok": False, "error": "Аккаунт не найден"}), 404
        _save_accounts_config(cfg)

        try:
            _log_for(name, f"account deleted ip={_get_client_ip()}")
        except Exception:
            pass

        # Remove the account's data folder LAST — _log_for above recreates the
        # directory (via account_dir -> makedirs), so deleting after it is safe.
        removed_dir = False
        try:
            folder = os.path.join(BASE_DIR, "accounts", name)
            if os.path.isdir(folder):
                shutil.rmtree(folder, ignore_errors=True)
                removed_dir = not os.path.isdir(folder)
        except Exception:
            removed_dir = False

        return jsonify({
            "ok": True,
            "message": f"Аккаунт «{name}» удалён." + ("" if removed_dir else " Папка данных осталась на диске."),
        })

    return app


def main():
    port = int(os.environ.get("AR_PORT", "7860"))
    host = os.environ.get("AR_HOST", "127.0.0.1")
    app = create_app()
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
