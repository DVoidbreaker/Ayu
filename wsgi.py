import os
import sys
import json
import base64
import subprocess
import time
import signal

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_accounts():
    path = os.path.join(BASE_DIR, "accounts.json")
    if not os.path.exists(path):
        print(f"[wsgi] accounts.json not found at {path}")
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f) or {}
    return data.get("accounts", [])


def decode_sessions(accounts):
    for acct in accounts:
        name = acct["name"]
        env_key = f"TG_SESSION_{name.upper()}"
        tg_session_b64 = os.environ.get(env_key, "").strip()
        if not tg_session_b64:
            tg_session_b64 = os.environ.get("TG_SESSION", "").strip()
        if not tg_session_b64:
            continue
        session_dir = os.path.join(BASE_DIR, "accounts", name)
        os.makedirs(session_dir, exist_ok=True)
        session_path = os.path.join(session_dir, "anti_revoke.session")
        try:
            data = base64.b64decode(tg_session_b64)
            with open(session_path, "wb") as f:
                f.write(data)
            print(f"[wsgi] Session decoded for {name}: {len(data)} bytes -> {session_path}")
        except Exception as e:
            print(f"[wsgi] Failed to decode session for {name}: {e}", file=sys.stderr)


def start_receivers(accounts):
    procs = []
    for acct in accounts:
        name = acct["name"]
        env = os.environ.copy()
        env["AR_ACCOUNT"] = name
        env["AR_API_ID"] = str(acct.get("api_id", ""))
        env["AR_API_HASH"] = acct.get("api_hash", "")

        print(f"[wsgi] Starting receiver for account: {name}")
        proc = subprocess.Popen(
            [sys.executable, "-u", os.path.join(BASE_DIR, "anti_revoke.py"), name],
            stdout=sys.stdout,
            stderr=sys.stderr,
            env=env,
        )
        procs.append(proc)
        time.sleep(1)

        print(f"[wsgi] Starting bot_sender for account: {name}")
        proc_bot = subprocess.Popen(
            [sys.executable, "-u", os.path.join(BASE_DIR, "bot_sender.py"), name],
            stdout=sys.stdout,
            stderr=sys.stderr,
            env=env,
        )
        procs.append(proc_bot)
        time.sleep(0.5)

    return procs


if __name__ == "__main__":
    accounts = load_accounts()
    if not accounts:
        print("[wsgi] No accounts defined in accounts.json")
        sys.exit(1)

    print(f"[wsgi] Found {len(accounts)} accounts: {[a['name'] for a in accounts]}")

    decode_sessions(accounts)
    procs = start_receivers(accounts)

    from anti_revoke_web import create_app

    app = create_app()
    port = int(os.environ.get("PORT", 10000))
    print(f"[wsgi] Starting web server on port {port}")

    def shutdown(signum, frame):
        print("[wsgi] Shutting down...")
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        app.run(host="0.0.0.0", port=port, debug=False)
    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
