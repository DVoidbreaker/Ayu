# Security fixes applied — operator notes

Read this before (re)deploying. It explains what changed and the two
actions you need to take.

## 1. First start: check your console/logs once

On the very first start after this update, the app will:

- **Migrate `passwords.json` to hashed storage.** Your existing panel
  password(s) keep working exactly as before — only the on-disk format
  changes (plain text → salted PBKDF2 hash). Nothing to do.
- **Rotate the admin password.** Your `passwords.json` shipped with
  `admin_password` set to the old hard-coded default
  (`uC1dyF7hoA5izT0`), which was published in the source code and is no
  longer treated as valid. A new random admin password is generated
  automatically and printed **once** to stdout/logs, e.g.:

  ```
  [SECURITY] Сгенерирован пароль админ-панели (/api/admin/*):
  [SECURITY]   <random-password-here>
  ```

  **Save it immediately** (password manager) — it is stored only as a
  hash and will not be shown again. If you lose it, delete the
  `admin_password` key from `passwords.json` and restart to generate a
  new one.

## 2. Every account panel now requires a password by default

Previously, a freshly created account's panel (`/<account>/`) was
reachable by anyone with the URL until its owner manually configured a
Telegram bot for login approval. That is now fixed: **a shared
panel/registration password is required from the very first account you
create**, and the password-based login (`/api/auth/password_login`)
always works — the optional Telegram-bot approval flow is an addition
on top, not a prerequisite.

## 3. What else changed (summary — see audit report for full detail)

- The "secret" sub-panel's password is no longer embedded in the page's
  HTML/JS (it used to be readable via "View Source"). It is now checked
  exclusively server-side and gates every `/api/secret/*` endpoint via a
  short-lived (30 min), httponly cookie.
- Telegram `.session` files, `auth.db` and account data directories are
  now created with restrictive permissions (`0700`/`0600`) instead of
  default (often world-readable) permissions.
- Added `.dockerignore` / `.gitignore` so `accounts.json`, `passwords.json`,
  `accounts/`, and `*.session` files are never baked into a Docker image
  or committed to version control.
- Fixed a crash (`500 Internal Server Error`) on `/api/secret/*` chat
  endpoints for a brand-new account whose database schema had not been
  created yet.
- Fixed a race condition where, if `passwords.json` was ever lost while
  accounts already existed, the *first* anonymous visitor to submit any
  4+ character password became the permanent owner of the shared
  password for every account. Password setup is now atomic with the
  account that establishes it.
- Removed dead/broken code in `bot_sender.py` (`check_callbacks`,
  `check_auth_commands`) that referenced undefined names and would have
  crashed with `NameError` if ever invoked; the working equivalent
  already exists in `auth_layer.py`.
- Hardened several database-touching endpoints against resource leaks
  (missing `try/finally`) and against raw tracebacks on malformed input
  (`chat_id`/`msg_id` now validated before use).

No functionality was removed. Everything that worked before — account
creation, Telegram login (phone/code/QR), message capture, the secret
panel, exports, cleanup — still works; it is now actually protected by
the passwords that were always meant to protect it.
