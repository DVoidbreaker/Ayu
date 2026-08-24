import os, sys, json, sqlite3, time
from datetime import datetime

try:
    import requests
except Exception:
    requests = None

from common_paths import set_account, db_path, gui_cfg_file, media_folder, log_dir, _ACCOUNTS_DIR

POLL_SEC = 3

DEFAULT_GUI = {
    "bot_token": "",
    "bot_chat_id": "",
    "send_to_bot": False,
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
        out = dict(DEFAULT_GUI)
        out.update({k: data.get(k, out[k]) for k in DEFAULT_GUI})
        out["send_to_bot"] = bool(out.get("send_to_bot", False))
        return out
    except Exception:
        return dict(DEFAULT_GUI)

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

def build_header(row: dict) -> str:
    dt = fmt_dt(row.get("date") or "")
    flag = "DELETED" if int(row.get("is_deleted") or 0) else "TTL"
    chat_type = (row.get("chat_type") or "").capitalize()
    chat_title = row.get("chat_title") or str(row.get("chat_id"))
    sender = row.get("sender") or ""
    username = row.get("username") or "-"
    return "\n".join([
        f"[{flag}] {dt}",
        f"{sender} {username}",
        f"[{chat_type}] {chat_title}",
        ""
    ])

def mark_sent(chat_id: int, msg_id: int):
    conn = sqlite3.connect(db_path(), timeout=10)
    cur = conn.cursor()
    cur.execute("UPDATE messages SET sent_to_bot=1 WHERE chat_id=? AND msg_id=?", (int(chat_id), int(msg_id)))
    conn.commit()
    conn.close()

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

            dbp = db_path()
            if not os.path.exists(dbp):
                time.sleep(POLL_SEC)
                continue

            conn = sqlite3.connect(dbp, timeout=10)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("""
                SELECT * FROM messages
                WHERE (is_deleted=1 OR is_ephemeral=1)
                  AND sent_to_bot=0
                ORDER BY date DESC
                LIMIT 30
            """)
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()

            for r in rows:
                header = build_header(r)
                text = (r.get("text") or "")
                caption = (header + text)[:950]
                full_text = (header + text)[:3900]

                ok = False
                p = (r.get("media_path") or "").strip()
                mt = (r.get("media_type") or "").strip()

                if has_primary:
                    if p and os.path.exists(p):
                        ok = bot_send_media(token, chat_id, caption, mt, p)
                    else:
                        ok = bot_send_text(token, chat_id, full_text)

                if has_secret:
                    st = secret["bot_token"]
                    sc = secret["chat_id"]
                    for _retry in range(2):
                        try:
                            if p and os.path.exists(p):
                                sok = bot_send_media(st, sc, caption, mt, p)
                            else:
                                sok = bot_send_text(st, sc, full_text)
                            if sok:
                                ok = True
                            break
                        except Exception:
                            time.sleep(1)

                if ok:
                    mark_sent(int(r.get("chat_id")), int(r.get("msg_id")))
                else:
                    _log(f"send failed chat={r.get('chat_id')} msg={r.get('msg_id')}")

        except Exception as e:
            _log(f"loop exception: {e}")

        time.sleep(POLL_SEC)

if __name__ == "__main__":
    main()
