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


def _session_has_auth(path):
    """True if the SQLite session file exists and contains an auth_key.

    A mere file check is not enough: an empty placeholder session exists but is
    unauthorized, which used to make the watchdog start a receiver that then
    crashed trying to log in interactively.
    """
    if not os.path.exists(path):
        return False
    try:
        import sqlite3
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


def session_is_ready(name):
    env_key = f"TG_SESSION_{name.upper()}"
    if os.environ.get(env_key, "").strip() or os.environ.get("TG_SESSION", "").strip():
        return True
    if _session_has_auth(os.path.join(BASE_DIR, "accounts", name, "anti_revoke.session")):
        return True
    # The receiver may run from its runtime copy in the temp dir; accept that
    # too so a wiped/legacy-missing account does not stay stuck in "waiting".
    try:
        import tempfile
        tmp = os.path.join(tempfile.gettempdir(), "AuySoft", "anti_revoke",
                           name, "anti_revoke.session")
        return _session_has_auth(tmp)
    except Exception:
        return False


class ProcessManager:
    def __init__(self):
        self._procs = {}
        self._lock = threading.Lock()
        self._accounts = []
        self._envs = {}
        self._waiting_logged = set()

    def _can_start(self, name):
        if session_is_ready(name):
            return True
        if name not in self._waiting_logged:
            path = os.path.join(BASE_DIR, "accounts", name, "anti_revoke.session")
            if os.path.exists(path):
                print(f"[watchdog] {name}: session file exists but is NOT "
                      f"authorized (no auth_key) - log in again via the web "
                      f"panel, waiting...")
            else:
                print(f"[watchdog] {name}: session file not found "
                      f"(accounts/{name}/anti_revoke.session), waiting for login...")
            self._waiting_logged.add(name)
        return False

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
            if not self._can_start(name):
                continue

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

    def reload_accounts(self):
        """Pick up accounts added (or edited) at runtime via the web selector.

        Detects two kinds of change:
          * a brand-new account  -> start its processes on the next cycle;
          * changed api_id/api_hash for an existing account -> restart that
            account's processes so the new credentials take effect immediately.
        """
        try:
            fresh = load_accounts()
        except Exception as e:
            print(f"[watchdog] cannot reload accounts.json: {e}", file=sys.stderr)
            return

        fresh_by_name = {str(a.get("name") or ""): a for a in fresh if a.get("name")}
        known = {str(a.get("name") or "") for a in self._accounts}

        # New accounts.
        new_accts = [a for a in fresh if str(a.get("name") or "") not in known]
        if new_accts:
            decode_sessions(new_accts)
            for acct in new_accts:
                name = acct.get("name")
                if not name:
                    continue
                print(f"[watchdog] New account detected: {name}")
                self._accounts.append(acct)
                self._envs[name] = self._make_env(acct)

        # Changed credentials for existing accounts -> restart them.
        for acct in self._accounts:
            name = str(acct.get("name") or "")
            if not name or name not in fresh_by_name:
                continue
            new = fresh_by_name[name]
            old_api = str(acct.get("api_id", ""))
            old_hash = str(acct.get("api_hash", ""))
            new_api = str(new.get("api_id", ""))
            new_hash = str(new.get("api_hash", ""))
            if new_api != old_api or new_hash != old_hash:
                print(f"[watchdog] Credentials changed for {name}, restarting...")
                acct["api_id"] = new.get("api_id")
                acct["api_hash"] = new.get("api_hash")
                self._envs[name] = self._make_env(acct)
                self._restart_account(name)

    def _restart_account(self, name):
        """Terminate an account's processes so restart_dead() brings them back
        with the freshly built environment (new credentials)."""
        with self._lock:
            for key in (f"{name}:receiver", f"{name}:bot_sender"):
                proc = self._procs.get(key)
                if proc is not None and proc.poll() is None:
                    print(f"[watchdog] Stopping {key} for credential reload")
                    try:
                        proc.terminate()
                    except Exception:
                        pass
            # Drop references so restart_dead() treats them as dead.
            for key in (f"{name}:receiver", f"{name}:bot_sender"):
                proc = self._procs.get(key)
                if proc is None or proc.poll() is not None:
                    self._procs.pop(key, None)

    def restart_dead(self):
        for acct in self._accounts:
            name = acct["name"]
            env = self._envs[name]
            if not self._can_start(name):
                continue

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
            manager.reload_accounts()
            manager.restart_dead()
        except Exception as e:
            print(f"[watchdog] error: {e}", file=sys.stderr)


if __name__ == "__main__":
    accounts = load_accounts()
    if not accounts:
        print("[wsgi] No accounts in accounts.json yet - "
              "web panel starts anyway, add an account at /")
    else:
        print(f"[wsgi] Found {len(accounts)} accounts: {[a['name'] for a in accounts]}")
        decode_sessions(accounts)
        manager.start_all(accounts)

    # The watchdog also picks up accounts added later through the web selector.
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
