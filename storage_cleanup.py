import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from common_paths import db_path, log_dir, media_folder

DEFAULT_RETENTION_DAYS = 2
DEFAULT_SOFT_LIMIT_MB = 300
DEFAULT_TARGET_MB = 360
MIN_SOFT_LIMIT_MB = 64
MIN_TARGET_MB = 32
MIN_RETENTION_DAYS = 1
RUN_INTERVAL_SECONDS = 300

_last_cleanup_at = {}


def _safe_int(value, default):
    try:
        return int(value)
    except Exception:
        return int(default)


def normalize_cleanup_settings(settings):
    data = dict(settings or {})
    retention_days = _safe_int(data.get("retention_days"), DEFAULT_RETENTION_DAYS)
    soft_limit_mb = _safe_int(data.get("storage_soft_limit_mb"), DEFAULT_SOFT_LIMIT_MB)
    target_mb = _safe_int(data.get("storage_target_mb"), DEFAULT_TARGET_MB)
    text_retention_days = _safe_int(data.get("text_retention_days"), 7)
    retention_days = max(MIN_RETENTION_DAYS, retention_days)
    soft_limit_mb = max(MIN_SOFT_LIMIT_MB, soft_limit_mb)
    target_mb = max(MIN_TARGET_MB, target_mb)
    text_retention_days = max(1, text_retention_days)
    if target_mb >= soft_limit_mb:
        target_mb = max(MIN_TARGET_MB, soft_limit_mb - 32)
    data["retention_days"] = retention_days
    data["storage_soft_limit_mb"] = soft_limit_mb
    data["storage_target_mb"] = target_mb
    data["text_retention_days"] = text_retention_days
    return data


def _iter_existing_files(paths):
    for path in paths:
        try:
            if path and os.path.exists(path):
                yield path
        except Exception:
            continue


def _dir_size_bytes(root):
    total = 0
    if not os.path.isdir(root):
        return total
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                total += os.path.getsize(path)
            except Exception:
                pass
    return total


def get_storage_usage_bytes():
    db = db_path()
    media = media_folder()
    db_files = [db, db + "-wal", db + "-shm"]
    db_bytes = sum(os.path.getsize(path) for path in _iter_existing_files(db_files))
    media_bytes = _dir_size_bytes(media)
    total_bytes = db_bytes + media_bytes
    return {
        "db_bytes": db_bytes,
        "media_bytes": media_bytes,
        "total_bytes": total_bytes,
        "db_mb": round(db_bytes / (1024 * 1024), 2),
        "media_mb": round(media_bytes / (1024 * 1024), 2),
        "total_mb": round(total_bytes / (1024 * 1024), 2),
    }


def _delete_media_file(path):
    if not path:
        return False
    try:
        abs_media = os.path.abspath(media_folder())
        abs_path = os.path.abspath(path)
        if os.path.commonpath([abs_media, abs_path]) != abs_media:
            return False
        if os.path.isfile(abs_path):
            os.remove(abs_path)
            return True
    except Exception:
        return False
    return False


def _delete_rows(conn, rows):
    deleted_rows = 0
    deleted_files = 0
    cur = conn.cursor()
    for row_id, media_path in rows:
        if _delete_media_file(media_path or ""):
            deleted_files += 1
        cur.execute("DELETE FROM messages WHERE id=?", (int(row_id),))
        deleted_rows += cur.rowcount or 0
    conn.commit()
    return deleted_rows, deleted_files


def _cleanup_orphan_media(conn, target_bytes):
    mf = media_folder()
    if not os.path.isdir(mf):
        return 0
    referenced_paths = {
        os.path.abspath(row[0])
        for row in conn.execute(
            "SELECT media_path FROM messages WHERE COALESCE(NULLIF(media_path, ''), '') != ''"
        ).fetchall()
        if row[0]
    }
    orphan_files = []
    for dirpath, _, filenames in os.walk(mf):
        for name in filenames:
            path = os.path.abspath(os.path.join(dirpath, name))
            if path in referenced_paths:
                continue
            try:
                stat = os.stat(path)
            except Exception:
                continue
            orphan_files.append((stat.st_mtime, path))
    orphan_files.sort()
    deleted_files = 0
    for _, path in orphan_files:
        usage = get_storage_usage_bytes()
        if usage["total_bytes"] <= target_bytes:
            break
        try:
            os.remove(path)
            deleted_files += 1
        except Exception:
            continue
    return deleted_files


def _cleanup_by_retention(conn, retention_days):
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    cutoff_iso = cutoff.isoformat()
    rows = conn.execute(
        """SELECT id, media_path FROM messages
           WHERE COALESCE(NULLIF(date, ''), '') != '' AND date < ?
           ORDER BY date ASC, id ASC""",
        (cutoff_iso,),
    ).fetchall()
    if not rows:
        return 0, 0
    return _delete_rows(conn, rows)


def _cleanup_by_size(conn, target_bytes):
    deleted_rows = 0
    deleted_files = 0
    while True:
        usage = get_storage_usage_bytes()
        if usage["total_bytes"] <= target_bytes:
            break
        rows = conn.execute(
            "SELECT id, media_path FROM messages ORDER BY date ASC, id ASC LIMIT 50"
        ).fetchall()
        if not rows:
            break
        part_rows, part_files = _delete_rows(conn, rows)
        deleted_rows += part_rows
        deleted_files += part_files
        if part_rows == 0:
            break
    return deleted_rows, deleted_files


def _cleanup_strip_content(conn, text_retention_days):
    if text_retention_days <= 0:
        return 0, 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=text_retention_days)
    cutoff_iso = cutoff.isoformat()
    mf = media_folder()
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT id, media_path FROM messages WHERE date < ? AND (text != '' OR media_path IS NOT NULL) AND is_deleted=0",
        (cutoff_iso,)
    ).fetchall()
    deleted_files = 0
    for row_id, media_path in rows:
        if media_path and os.path.isfile(media_path):
            try:
                os.remove(media_path)
                deleted_files += 1
            except Exception:
                pass
    cur.execute(
        "UPDATE messages SET text='', media_path=NULL, media_type=NULL, sender='', username='', phone='' WHERE date < ? AND is_deleted=0",
        (cutoff_iso,)
    )
    conn.commit()
    return cur.rowcount or 0, deleted_files


def run_cleanup(settings, logger=None, force=False):
    from common_paths import get_current_account
    acct = get_current_account() or "default"
    now = time.time()
    if not force and (now - _last_cleanup_at.get(acct, 0)) < RUN_INTERVAL_SECONDS:
        usage = get_storage_usage_bytes()
        return {"ok": True, "skipped": True, "deleted_rows": 0, "deleted_files": 0, **usage}

    db = db_path()
    cfg = normalize_cleanup_settings(settings)
    usage_before = get_storage_usage_bytes()

    result = {
        "ok": True, "skipped": False, "deleted_rows": 0, "deleted_files": 0,
        "reason": [], **usage_before,
    }

    if not os.path.exists(db):
        _last_cleanup_at[acct] = now
        return result

    conn = sqlite3.connect(db, timeout=20)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=10000;")

        rows_deleted, files_deleted = _cleanup_by_retention(conn, cfg["retention_days"])
        if rows_deleted or files_deleted:
            result["reason"].append("retention")
            result["deleted_rows"] += rows_deleted
            result["deleted_files"] += files_deleted

        text_ret = cfg.get("text_retention_days", 7)
        if text_ret > 0:
            stripped, media_removed = _cleanup_strip_content(conn, text_ret)
            if stripped or media_removed:
                result["reason"].append("strip_content")
                result["deleted_rows"] += stripped
                result["deleted_files"] += media_removed

        soft_limit_bytes = cfg["storage_soft_limit_mb"] * 1024 * 1024
        target_bytes = cfg["storage_target_mb"] * 1024 * 1024
        usage_mid = get_storage_usage_bytes()
        if usage_mid["total_bytes"] > soft_limit_bytes:
            rows_deleted, files_deleted = _cleanup_by_size(conn, target_bytes)
            if rows_deleted or files_deleted:
                result["reason"].append("size")
                result["deleted_rows"] += rows_deleted
                result["deleted_files"] += files_deleted

            orphan_files_deleted = _cleanup_orphan_media(conn, target_bytes)
            if orphan_files_deleted:
                if "orphan_media" not in result["reason"]:
                    result["reason"].append("orphan_media")
                result["deleted_files"] += orphan_files_deleted

        if result["deleted_rows"] > 0:
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            except Exception:
                pass
            try:
                conn.execute("VACUUM")
            except Exception:
                pass
    finally:
        conn.close()

    usage_after = get_storage_usage_bytes()
    result.update(usage_after)
    _last_cleanup_at[acct] = now

    if logger and (result["deleted_rows"] or result["deleted_files"]):
        try:
            logger(
                f"cleanup: rows={result['deleted_rows']} files={result['deleted_files']} "
                f"usage={result['total_mb']}MB reasons={','.join(result['reason']) or '-'}"
            )
        except Exception:
            pass

    return result
