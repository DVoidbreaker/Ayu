#!/usr/bin/env python3
import os, sys, json, asyncio, tempfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ACCOUNTS_DIR = os.path.join(BASE_DIR, "accounts")

def _get_account():
    if len(sys.argv) < 2:
        print(json.dumps({"ok": False, "error": "Usage: python secret_ops.py <account_name> <command> ..."}))
        sys.exit(1)
    return sys.argv[1]

def _account_dir(name):
    d = os.path.join(ACCOUNTS_DIR, name)
    os.makedirs(d, exist_ok=True)
    return d

def _session_dir(name):
    d = os.path.join(tempfile.gettempdir(), "AuySoft", "anti_revoke", name)
    os.makedirs(d, exist_ok=True)
    return d

def _session_base(name):
    return os.path.join(_session_dir(name), "anti_revoke")

def _legacy_session_base(name):
    return os.path.join(_account_dir(name), "anti_revoke")

def _db_path(name):
    return os.path.join(_account_dir(name), "messages.db")

def _media_folder(name):
    d = os.path.join(_account_dir(name), "media", "anti_revoke")
    os.makedirs(d, exist_ok=True)
    return d

def _bootstrap_session(name):
    legacy = _legacy_session_base(name) + ".session"
    runtime = _session_base(name) + ".session"
    if os.path.exists(legacy) and not os.path.exists(runtime):
        import shutil
        shutil.copy2(legacy, runtime)

def _load_api_creds(name):
    accounts_file = os.path.join(ACCOUNTS_DIR, "..", "accounts.json")
    try:
        with open(accounts_file, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        for a in data.get("accounts", []):
            if a.get("name") == name:
                return int(a.get("api_id", 0)), str(a.get("api_hash", ""))
    except Exception:
        pass
    return int(os.environ.get("AR_API_ID", "0")), os.environ.get("AR_API_HASH", "")

def _media_type_from_msg(msg):
    if getattr(msg, "photo", None):
        return "photo"
    if getattr(msg, "video", None):
        return "video"
    if getattr(msg, "voice", None):
        return "voice"
    if getattr(msg, "video_note", None):
        return "video_note"
    if getattr(msg, "audio", None):
        return "audio"
    if getattr(msg, "document", None):
        return "document"
    return ""

async def cmd_resolve(account_name, identifier):
    api_id, api_hash = _load_api_creds(account_name)
    if not api_id or not api_hash:
        print(json.dumps({"ok": False, "error": "API credentials not found"}))
        return

    _bootstrap_session(account_name)
    client = None
    try:
        from telethon import TelegramClient
        client = TelegramClient(_session_base(account_name), api_id, api_hash)
        await client.start()

        v = identifier.strip()
        entity = None
        if v.startswith("@"):
            entity = await client.get_entity(v)
        elif v.lstrip("-").isdigit():
            entity = await client.get_entity(int(v))
        else:
            try:
                entity = await client.get_entity(v)
            except Exception:
                try:
                    entity = await client.get_entity(f"+{v}")
                except Exception:
                    pass

        if not entity:
            print(json.dumps({"ok": False, "error": "Not found: " + identifier}))
            return

        title = ""
        uname = ""
        ctype = ""
        cid = getattr(entity, "id", 0)

        if hasattr(entity, "first_name"):
            parts = [p for p in [getattr(entity, "first_name", ""), getattr(entity, "last_name", "")] if p]
            title = " ".join(parts)
            uname = getattr(entity, "username", "") or ""
            ctype = "private"
        elif hasattr(entity, "title"):
            title = getattr(entity, "title", "")
            uname = getattr(entity, "username", "") or ""
            ctype = "group" if hasattr(entity, "megagroup") and entity.megagroup else "channel"
        else:
            title = str(cid)
            ctype = "private"

        print(json.dumps({
            "ok": True,
            "results": [{
                "chat_id": cid,
                "title": title,
                "username": uname,
                "chat_type": ctype
            }]
        }))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
    finally:
        if client:
            try:
                await client.disconnect()
            except Exception:
                pass

async def cmd_fetch(account_name, chat_id, limit):
    api_id, api_hash = _load_api_creds(account_name)
    if not api_id or not api_hash:
        print(json.dumps({"ok": False, "error": "API credentials not found"}))
        return

    _bootstrap_session(account_name)
    client = None
    try:
        from telethon import TelegramClient
        from telethon.tl.types import Message

        client = TelegramClient(_session_base(account_name), api_id, api_hash)
        await client.start()

        entity = await client.get_entity(int(chat_id))

        chat_title = ""
        chat_type = "private"
        if hasattr(entity, "first_name"):
            parts = [p for p in [getattr(entity, "first_name", ""), getattr(entity, "last_name", "")] if p]
            chat_title = " ".join(parts)
            chat_type = "private"
        elif hasattr(entity, "title"):
            chat_title = getattr(entity, "title", "")
            chat_type = "group" if getattr(entity, "megagroup", False) else "channel"

        messages = []
        me = await client.get_me()
        my_id = me.id if me else 0

        async for msg in client.iter_messages(entity, limit=int(limit)):
            sender_name = ""
            username = ""
            is_outgoing = 1 if msg.out else 0

            if msg.sender_id:
                try:
                    sender_entity = await client.get_entity(msg.sender_id)
                    if hasattr(sender_entity, "first_name"):
                        parts = [p for p in [getattr(sender_entity, "first_name", ""), getattr(sender_entity, "last_name", "")] if p]
                        sender_name = " ".join(parts)
                        username = getattr(sender_entity, "username", "") or ""
                except Exception:
                    pass

            media_type = ""
            if msg.photo:
                media_type = "photo"
            elif msg.video:
                media_type = "video"
            elif msg.voice:
                media_type = "voice"
            elif msg.video_note:
                media_type = "video_note"
            elif msg.audio:
                media_type = "audio"
            elif msg.document:
                media_type = "document"

            dt = msg.date
            try:
                if dt and dt.tzinfo is None:
                    from datetime import timezone
                    dt = dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass
            date_str = dt.isoformat() if dt else ""

            messages.append({
                "msg_id": msg.id,
                "text": msg.message or "",
                "date": date_str,
                "sender": sender_name,
                "username": username,
                "is_outgoing": is_outgoing,
                "media_type": media_type,
            })

        print(json.dumps({
            "ok": True,
            "chat_title": chat_title,
            "chat_type": chat_type,
            "messages": messages
        }))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
    finally:
        if client:
            try:
                await client.disconnect()
            except Exception:
                pass

async def cmd_download(account_name, chat_id, msg_ids_str):
    api_id, api_hash = _load_api_creds(account_name)
    if not api_id or not api_hash:
        print(json.dumps({"ok": False, "error": "API credentials not found"}))
        return

    _bootstrap_session(account_name)
    client = None
    try:
        from telethon import TelegramClient
        client = TelegramClient(_session_base(account_name), api_id, api_hash)
        await client.start()

        entity = await client.get_entity(int(chat_id))
        msg_ids = [int(x.strip()) for x in msg_ids_str.split(",") if x.strip()]

        results = []
        mf = _media_folder(account_name)
        for mid in msg_ids:
            try:
                messages = await client.get_messages(entity, ids=[mid])
                if not messages or not messages[0]:
                    results.append({"msg_id": mid, "ok": False, "error": "not found"})
                    continue
                msg = messages[0]
                fname = f"{chat_id}_{mid}"
                path = await client.download_media(msg, file=os.path.join(mf, fname))
                if path:
                    path = os.path.abspath(path)
                    mt = ""
                    if msg.photo:
                        mt = "photo"
                    elif msg.video:
                        mt = "video"
                    elif msg.voice:
                        mt = "voice"
                    elif msg.video_note:
                        mt = "video_note"
                    elif msg.audio:
                        mt = "audio"
                    elif msg.document:
                        mt = "document"
                    results.append({"msg_id": mid, "ok": True, "media_path": path, "media_type": mt})
                else:
                    results.append({"msg_id": mid, "ok": False, "error": "download returned None"})
            except Exception as e:
                results.append({"msg_id": mid, "ok": False, "error": str(e)})

        first = results[0] if results else {"ok": False, "error": "no messages"}
        print(json.dumps({
            "ok": first.get("ok", False),
            "media_path": first.get("media_path", ""),
            "media_type": first.get("media_type", ""),
            "error": first.get("error", ""),
            "results": results
        }))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
    finally:
        if client:
            try:
                await client.disconnect()
            except Exception:
                pass

async def cmd_delete(account_name, chat_id, msg_ids_str, revoke=False):
    api_id, api_hash = _load_api_creds(account_name)
    if not api_id or not api_hash:
        print(json.dumps({"ok": False, "error": "API credentials not found"}))
        return

    _bootstrap_session(account_name)
    client = None
    try:
        from telethon import TelegramClient
        client = TelegramClient(_session_base(account_name), api_id, api_hash)
        await client.start()

        entity = await client.get_entity(int(chat_id))
        msg_ids = [int(x.strip()) for x in msg_ids_str.split(",") if x.strip()]
        await client.delete_messages(entity, msg_ids, revoke=bool(revoke))
        print(json.dumps({"ok": True}))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
    finally:
        if client:
            try:
                await client.disconnect()
            except Exception:
                pass

async def cmd_edit(account_name, chat_id, msg_id, text):
    api_id, api_hash = _load_api_creds(account_name)
    if not api_id or not api_hash:
        print(json.dumps({"ok": False, "error": "API credentials not found"}))
        return

    _bootstrap_session(account_name)
    client = None
    try:
        from telethon import TelegramClient
        client = TelegramClient(_session_base(account_name), api_id, api_hash)
        await client.start()

        entity = await client.get_entity(int(chat_id))
        messages = await client.get_messages(entity, ids=[int(msg_id)])
        if not messages or not messages[0]:
            print(json.dumps({"ok": False, "error": "Message not found"}))
            return
        await messages[0].edit(text)
        print(json.dumps({"ok": True}))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
    finally:
        if client:
            try:
                await client.disconnect()
            except Exception:
                pass

async def cmd_dialogs(account_name, limit=100):
    api_id, api_hash = _load_api_creds(account_name)
    if not api_id or not api_hash:
        print(json.dumps({"ok": False, "error": "API credentials not found"}))
        return
    _bootstrap_session(account_name)
    client = None
    try:
        from telethon import TelegramClient
        client = TelegramClient(_session_base(account_name), api_id, api_hash)
        await client.start()
        me = await client.get_me()
        my_id = me.id if me else 0
        dialogs = []
        async for dialog in client.iter_dialogs(limit=int(limit)):
            ent = dialog.entity
            cid = getattr(ent, "id", 0)
            title = dialog.name or str(cid)
            ctype = "private"
            if hasattr(ent, "megagroup"):
                ctype = "group" if ent.megagroup else "channel"
            elif hasattr(ent, "title") and not hasattr(ent, "first_name"):
                ctype = "channel"
            uname = getattr(ent, "username", "") or ""
            last_msg = dialog.message
            last_text = ""
            last_date = ""
            last_outgoing = False
            if last_msg:
                last_text = getattr(last_msg, "message", "") or ""
                dt = getattr(last_msg, "date", None)
                if dt:
                    try:
                        from datetime import timezone
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                    except Exception:
                        pass
                    last_date = dt.isoformat() if dt else ""
                last_outgoing = bool(getattr(last_msg, "out", False))
            unread = dialog.unread_count or 0
            dialogs.append({
                "chat_id": cid,
                "title": title,
                "chat_type": ctype,
                "username": uname,
                "last_text": last_text,
                "last_date": last_date,
                "last_outgoing": last_outgoing,
                "unread": unread,
            })
        print(json.dumps({"ok": True, "dialogs": dialogs, "my_id": my_id}))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
    finally:
        if client:
            try:
                await client.disconnect()
            except Exception:
                pass

def _detect_account():
    cwd = os.getcwd()
    if os.path.basename(os.path.dirname(cwd)) == "accounts":
        return os.path.basename(cwd)
    parent = os.path.dirname(cwd)
    if os.path.exists(os.path.join(parent, "accounts.json")):
        for name in os.listdir(os.path.join(parent, "accounts")):
            if os.path.abspath(os.path.join(cwd)) == os.path.abspath(os.path.join(parent, "accounts", name)):
                return name
    return None

def main():
    account_name = _detect_account()
    if not account_name:
        print(json.dumps({"ok": False, "error": "Cannot detect account from cwd"}))
        sys.exit(1)

    if len(sys.argv) < 2:
        print(json.dumps({"ok": False, "error": "Usage: python secret_ops.py <command> [args]"}))
        sys.exit(1)

    command = sys.argv[1]

    if command == "resolve":
        identifier = sys.argv[2] if len(sys.argv) > 2 else ""
        asyncio.run(cmd_resolve(account_name, identifier))
    elif command == "fetch":
        chat_id = 0
        limit = 5000
        args = sys.argv[2:]
        for i in range(0, len(args), 2):
            if args[i] == "--chat-id" and i+1 < len(args):
                chat_id = int(args[i+1])
            elif args[i] == "--limit" and i+1 < len(args):
                limit = int(args[i+1])
        asyncio.run(cmd_fetch(account_name, chat_id, limit))
    elif command == "download":
        chat_id = 0
        msg_ids = ""
        args = sys.argv[2:]
        for i in range(0, len(args), 2):
            if args[i] == "--chat-id" and i+1 < len(args):
                chat_id = int(args[i+1])
            elif args[i] == "--msg-ids" and i+1 < len(args):
                msg_ids = args[i+1]
        asyncio.run(cmd_download(account_name, chat_id, msg_ids))
    elif command == "delete":
        chat_id = 0
        msg_ids = ""
        revoke = False
        args = sys.argv[2:]
        for i in range(0, len(args), 2):
            if args[i] == "--chat-id" and i+1 < len(args):
                chat_id = int(args[i+1])
            elif args[i] == "--msg-ids" and i+1 < len(args):
                msg_ids = args[i+1]
            elif args[i] == "--revoke" and i+1 < len(args):
                revoke = args[i+1].lower() in ("true", "1", "yes")
        asyncio.run(cmd_delete(account_name, chat_id, msg_ids, revoke))
    elif command == "edit":
        chat_id = 0
        msg_id = 0
        text = ""
        args = sys.argv[2:]
        for i in range(0, len(args), 2):
            if args[i] == "--chat-id" and i+1 < len(args):
                chat_id = int(args[i+1])
            elif args[i] == "--msg-id" and i+1 < len(args):
                msg_id = int(args[i+1])
            elif args[i] == "--text" and i+1 < len(args):
                text = args[i+1]
        asyncio.run(cmd_edit(account_name, chat_id, msg_id, text))
    elif command == "dialogs":
        limit = 100
        args = sys.argv[2:]
        for i in range(0, len(args), 2):
            if args[i] == "--limit" and i+1 < len(args):
                limit = int(args[i+1])
        asyncio.run(cmd_dialogs(account_name, limit))
    else:
        print(json.dumps({"ok": False, "error": f"Unknown command: {command}"}))

if __name__ == "__main__":
    main()
