import os
import sys
import json
import base64
import subprocess
import time
import signal
import threading

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


class ProcessManager:
    def __init__(self):
        self._procs = {}
        self._lock = threading.Lock()
        self._accounts = []
        self._envs = {}

    def start_process(self, name, cmd, env, label):
        key = f"{name}:{label}"
        with self._lock:
            old = self._procs.get(key)
            if old and old.poll() is None:
                print(f"[watchdog] {key} still running, skipping")
                return
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                    env=env,
                )
                self._procs[key] = proc
                print(f"[watchdog] Started {key} (pid={proc.pid})")
            except Exception as e:
                print(f"[watchdog] Failed to start {key}: {e}", file=sys.stderr)

    def _make_env(self, acct):
        env = os.environ.copy()
        env["AR_ACCOUNT"] = acct["name"]
        env["AR_API_ID"] = str(acct.get("api_id", ""))
        env["AR_API_HASH"] = acct.get("api_hash", "")
        return env

    def start_all(self, accounts):
        self._accounts = accounts
        for acct in accounts:
            name = acct["name"]
            env = self._make_env(acct)
            self._envs[name] = env

            self.start_process(
                name,
                [sys.executable, "-u", os.path.join(BASE_DIR, "anti_revoke.py"), name],
                env, "receiver"
            )
            time.sleep(1)
            self.start_process(
                name,
                [sys.executable, "-u", os.path.join(BASE_DIR, "bot_sender.py"), name],
                env, "bot_sender"
            )
            time.sleep(0.5)

    def restart_dead(self):
        for acct in self._accounts:
            name = acct["name"]
            env = self._envs[name]

            recv_key = f"{name}:receiver"
            bot_key = f"{name}:bot_sender"

            with self._lock:
                recv = self._procs.get(recv_key)
                bot = self._procs.get(bot_key)

            if recv is None or recv.poll() is not None:
                code = recv.poll() if recv else "never started"
                print(f"[watchdog] {recv_key} died (exit={code}), restarting...")
                self.start_process(
                    name,
                    [sys.executable, "-u", os.path.join(BASE_DIR, "anti_revoke.py"), name],
                    env, "receiver"
                )
                time.sleep(2)

            if bot is None or bot.poll() is not None:
                code = bot.poll() if bot else "never started"
                print(f"[watchdog] {bot_key} died (exit={code}), restarting...")
                self.start_process(
                    name,
                    [sys.executable, "-u", os.path.join(BASE_DIR, "bot_sender.py"), name],
                    env, "bot_sender"
                )
                time.sleep(1)

    def shutdown_all(self):
        with self._lock:
            for key, proc in self._procs.items():
                try:
                    proc.terminate()
                    print(f"[watchdog] Stopped {key}")
                except Exception:
                    pass
            self._procs.clear()


manager = ProcessManager()


def watchdog_loop(interval=30):
    while True:
        time.sleep(interval)
        try:
            manager.restart_dead()
        except Exception as e:
            print(f"[watchdog] error: {e}", file=sys.stderr)


if __name__ == "__main__":
    accounts = load_accounts()
    if not accounts:
        print("[wsgi] No accounts defined in accounts.json")
        sys.exit(1)

    print(f"[wsgi] Found {len(accounts)} accounts: {[a['name'] for a in accounts]}")

    decode_sessions(accounts)
    manager.start_all(accounts)

    watchdog = threading.Thread(target=watchdog_loop, args=(30,), daemon=True)
    watchdog.start()
    print("[wsgi] Watchdog started (checks every 30s)")

    from anti_revoke_web import create_app

    app = create_app()
    port = int(os.environ.get("PORT", 10000))
    print(f"[wsgi] Starting web server on port {port}")

    def shutdown(signum, frame):
        print("[wsgi] Shutting down...")
        manager.shutdown_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        app.run(host="0.0.0.0", port=port, debug=False)
    finally:
        manager.shutdown_all()
