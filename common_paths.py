import os
import tempfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_ACCOUNTS_DIR = os.path.join(BASE_DIR, "accounts")

_current_account = None


def set_account(name):
    global _current_account
    _current_account = name


def get_account():
    return _current_account


def account_dir():
    name = get_current_account()
    if name:
        d = os.path.join(_ACCOUNTS_DIR, name)
        os.makedirs(d, exist_ok=True)
        return d
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
    os.makedirs(d, exist_ok=True)
    return d


def log_dir():
    d = os.path.join(account_dir(), "logs")
    os.makedirs(d, exist_ok=True)
    return d


def session_dir():
    d = os.path.join(tempfile.gettempdir(), "AuySoft", "anti_revoke", get_current_account() or "default")
    os.makedirs(d, exist_ok=True)
    return d


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
