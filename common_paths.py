import os
import stat
import tempfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_ACCOUNTS_DIR = os.path.join(BASE_DIR, "accounts")

_current_account = None


def _secure_dir(path):
    """Create `path` (and parents) and make sure it is only readable by the
    owner (0700). Session files, auth DBs and message DBs live under these
    directories, so a world-readable temp/account folder would let any other
    local user or process read Telegram auth keys and private messages.
    """
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except Exception:
        pass
    return path


def _secure_file(path):
    """Tighten permissions on an existing sensitive file (sessions, DBs)."""
    try:
        if os.path.exists(path):
            os.chmod(path, 0o600)
    except Exception:
        pass


def set_account(name):
    global _current_account
    _current_account = name


def get_account():
    return _current_account


def account_dir():
    name = get_current_account()
    if name:
        d = os.path.join(_ACCOUNTS_DIR, name)
        return _secure_dir(d)
    return BASE_DIR


def get_current_account():
    return _current_account


def db_path():
    return os.path.join(account_dir(), "messages.db")


def settings_file():
    return os.path.join(account_dir(), "settings.json")


def gui_cfg_file():
    return os.path.join(account_dir(), "gui_config.json")


def auth_db_path():
    return os.path.join(account_dir(), "auth.db")


def media_folder():
    d = os.path.join(account_dir(), "media", "anti_revoke")
    return _secure_dir(d)


def log_dir():
    d = os.path.join(account_dir(), "logs")
    return _secure_dir(d)


def session_dir():
    # NOTE: the Telethon .session file holds a long-lived `auth_key` that is
    # equivalent to a password-free login to the Telegram account, so this
    # directory (even though it lives under the shared system temp dir) must
    # never be left with default (often world-readable) permissions.
    d = os.path.join(tempfile.gettempdir(), "AuySoft", "anti_revoke", get_current_account() or "default")
    return _secure_dir(d)


def session_base():
    return os.path.join(session_dir(), "anti_revoke")


def legacy_session_base():
    return os.path.join(account_dir(), "anti_revoke")


DB_PATH = None
SETTINGS_FILE = None
GUI_CFG_FILE = None
AUTH_DB_PATH = None
MEDIA_FOLDER = None
LOG_DIR = None
SESSION_DIR = None
SESSION_BASE = None
LEGACY_SESSION_BASE = None
