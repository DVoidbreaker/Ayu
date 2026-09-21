import os, sys, json, time
from datetime import datetime

try:
    import requests
except Exception:
    requests = None

from common_paths import set_account, gui_cfg_file, media_folder, log_dir, _ACCOUNTS_DIR, notify_queue_dir

POLL_SEC = 2

DEFAULT_GUI = {
    "bot_token": "",
    "bot_chat_id": "",
    "send_to_bot": False,
    "exclude_own_chat": True,
    "exclude_from_bot": [],
}

LAST_UPDATE_ID = 0


def load_secret_bot(account_name: str) -> dict:
    accounts_file = os.path.join(_ACCOUNTS_DIR, "..", "accounts.json")
    try:
        with open(accounts_file, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        for acct in data.get("accounts", []):
            if acct.get("name") == account_name:
                token = str(acct.get("secret_bot_token") or "").strip()
                chat_id = str(acct.get("secret_bot_chat_id") or "").strip()
                if token and chat_id:
                    return {"bot_token": token, "chat_id": chat_id}
    except Exception:
        pass
    return {}

def check_callbacks(token):
    global LAST_UPDATE_ID

    if requests is None:
        return

    try:
        r = requests.get(
            f"https://api.telegram.org/bot{token}/getUpdates",
            params={"offset": LAST_UPDATE_ID + 1},
            timeout=10
        )

        data = r.json()

        for upd in data.get("result", []):
            LAST_UPDATE_ID = upd["update_id"]

            cb = upd.get("callback_query")
            if not cb:
                continue

            data_cb = cb.get("data", "")
            callback_id = cb.get("id")

            requests.post(
                f"https://api.telegram.org/bot{token}/answerCallbackQuery",
                data={"callback_query_id": callback_id}
            )

            if data_cb.startswith("allow:") and approve:
                approve(data_cb.split(":")[1])

            elif data_cb.startswith("deny:") and deny:
                deny(data_cb.split(":")[1])

    except Exception as e:
        _log(f"callback error: {e}")

def _log(line: str):
    try:
        ld = log_dir()
        os.makedirs(ld, exist_ok=True)
        with open(os.path.join(ld, "bot_sender.log"), "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} {line}\n")
    except Exception:
        pass

def load_gui_cfg() -> dict:
    try:
        gc = gui_cfg_file()
        if not os.path.exists(gc):
            with open(gc, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_GUI, f, ensure_ascii=False, indent=2)
            return dict(DEFAULT_GUI)
        with open(gc, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        out = dict(data)
        for k, v in DEFAULT_GUI.items():
            if k not in out:
                out[k] = v
        out["send_to_bot"] = bool(out.get("send_to_bot", False))
        return out
    except Exception:
        return dict(DEFAULT_GUI)

def is_excluded_from_bot(row: dict, cfg: dict) -> bool:
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

def fmt_dt(dt_raw: str) -> str:
    try:
        return datetime.fromisoformat(dt_raw).strftime("%d.%m.%Y %H:%M:%S")
    except Exception:
        return dt_raw or ""

def bot_send_text(token: str, chat_id: str, text: str) -> bool:
    if requests is None:
        return False
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": text},
            timeout=20
        )
        j = {}
        try:
            if (r.headers.get("content-type","") or "").startswith("application/json"):
                j = r.json()
        except Exception:
            pass
        return (r.status_code == 200 and j.get("ok") is True)
    except Exception:
        return False

def bot_send_media(token: str, chat_id: str, caption: str, mtype: str, path: str) -> bool:
    if requests is None:
        return False
    try:
        with open(path, "rb") as f:
            if mtype == "photo":
                r = requests.post(
                    f"https://api.telegram.org/bot{token}/sendPhoto",
                    data={"chat_id": chat_id, "caption": caption},
                    files={"photo": f},
                    timeout=45
                )
            elif mtype == "video":
                r = requests.post(
                    f"https://api.telegram.org/bot{token}/sendVideo",
                    data={"chat_id": chat_id, "caption": caption},
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
                    data={"chat_id": chat_id, "caption": caption},
                    files={"document": f},
                    timeout=60
                )
        j = {}
        try:
            if (r.headers.get("content-type","") or "").startswith("application/json"):
                j = r.json()
        except Exception:
            pass
        return (r.status_code == 200 and j.get("ok") is True)
    except Exception:
        return False

def build_header(row: dict, account_name: str = "") -> str:
    dt = fmt_dt(row.get("date") or "")
    flag = "DELETED" if int(row.get("is_deleted") or 0) else "TTL"
    chat_type = (row.get("chat_type") or "").capitalize()
    chat_title = row.get("chat_title") or str(row.get("chat_id"))
    sender = row.get("sender") or ""
    username = row.get("username") or "-"
    acct_tag = f"[{account_name}] " if account_name else ""
    return "\n".join([
        f"{acct_tag}[{flag}] {dt}",
        f"{sender} {username}",
        f"[{chat_type}] {chat_title}",
        ""
    ])

def check_auth_commands(token: str, chat_id: str):
    if requests is None or not approve:
        return

    try:
        r = requests.get(
            f"https://api.telegram.org/bot{token}/getUpdates",
            timeout=10
        )
        data = r.json()

        for upd in data.get("result", []):
            msg = upd.get("message", {})
            text = (msg.get("text") or "").strip()

            if text.startswith("/approve"):
                parts = text.split(" ")
                if len(parts) >= 2:
                    approve(parts[1])
    except Exception:
        pass

def main():
    if len(sys.argv) < 2:
        print("Usage: python bot_sender.py <account_name>")
        sys.exit(1)

    account_name = sys.argv[1]
    set_account(account_name)

    print(f"Bot sender started for account: {account_name}")
    if requests is None:
        print("requests missing: pip install requests")

    while True:
        try:
            cfg = load_gui_cfg()
            secret = load_secret_bot(account_name)

            token = (cfg.get("bot_token") or "").strip()
            chat_id = (cfg.get("bot_chat_id") or "").strip()
            has_primary = cfg.get("send_to_bot") and token and chat_id and chat_id.lstrip("-").isdigit()

            has_secret = bool(secret.get("bot_token") and secret.get("chat_id"))

            if not has_primary and not has_secret:
                time.sleep(POLL_SEC)
                continue

            qdir = notify_queue_dir()
            files = sorted([f for f in os.listdir(qdir) if f.endswith(".json")])

            for fname in files:
                fpath = os.path.join(qdir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        row = json.load(f)
                except Exception:
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass
                    continue

                if is_excluded_from_bot(row, cfg):
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass
                    continue

                text = (row.get("text") or "")
                p = (row.get("media_path") or "").strip()
                mt = (row.get("media_type") or "").strip()

                primary_ok = False
                secret_ok = False

                if has_primary:
                    header = build_header(row, account_name)
                    full_text = (header + text)[:3900]
                    if p and os.path.exists(p):
                        primary_ok = bot_send_media(token, chat_id, (header + text)[:950], mt, p)
                    else:
                        primary_ok = bot_send_text(token, chat_id, full_text)
                    if not primary_ok:
                        _log(f"primary send failed chat={row.get('chat_id')} msg={row.get('msg_id')}")

                if has_secret:
                    header = build_header(row, account_name)
                    full_text = (header + text)[:3900]
                    st = secret["bot_token"]
                    sc = secret["chat_id"]
                    for _retry in range(2):
                        try:
                            if p and os.path.exists(p):
                                secret_ok = bot_send_media(st, sc, (header + text)[:950], mt, p)
                            else:
                                secret_ok = bot_send_text(st, sc, full_text)
                            if secret_ok:
                                break
                            time.sleep(1)
                        except Exception:
                            time.sleep(1)
                    if not secret_ok:
                        _log(f"secret send failed chat={row.get('chat_id')} msg={row.get('msg_id')}")

                if (has_primary and primary_ok) or (has_secret and secret_ok):
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass

        except Exception as e:
            _log(f"loop exception: {e}")

        time.sleep(POLL_SEC)

if __name__ == "__main__":
    main()
