#!/usr/bin/env python3
"""
RIAN Commander V2 local work-mail index (runs ON the owner's PC only).

* Read-only toward the mailbox: IMAP folders are opened with EXAMINE and
  messages are fetched with BODY.PEEK[] (does not even set \\Seen). The IMAP
  wrapper exposes no STORE, COPY, MOVE, EXPUNGE, APPEND or DELETE, and this
  module has no SMTP code at all: it cannot send or delete mail.
* Sync merges new mail into the existing local index and never drops existing
  entries (a 120-day index stays intact when a 14-day sync runs).
* Before every index write the previous index is copied to backups/ (last 10
  kept) and the new index is written atomically (temp file + fsync + replace).
* The index is bound to an account fingerprint: syncing a different account
  stops with ACCOUNT_MISMATCH before anything is written.
* Message bodies live in bodies/<id>.txt and are only returned by
  read_message() for exactly one validated message ID. search() never returns
  bodies. Metadata is what a general listing would ever show.
* A legacy JSON index can seed the V2 index once; the legacy file is only read.
"""
import argparse
import datetime as dt
import email
import email.policy
import hashlib
import html
import importlib.util
import json
import os
import re
import secrets
import sys
import tempfile
from email.utils import parsedate_to_datetime
from pathlib import Path

INDEX_VERSION = 2
MESSAGE_ID = re.compile(r"^[a-f0-9]{20,64}$")
MAX_SYNC_DAYS = 14
MAX_SYNC_MESSAGES = 1000
MAX_BODY_STORE_BYTES = 256 * 1024
MAX_BODY_RETURN_BYTES = 64 * 1024
KEEP_BACKUPS = 10
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


class MailError(RuntimeError):
    """Error codes only; never message content, credentials or server replies."""


class MailCancelled(MailError):
    pass


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def iso(value):
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value):
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(dt.timezone.utc)
    except (TypeError, ValueError):
        return None


def account_fingerprint(account):
    if not isinstance(account, str) or not account.strip() or len(account) > 320:
        raise MailError("INVALID_ACCOUNT")
    return hashlib.sha256(("rian-mail-account-v2|" + account.strip().lower()).encode("utf-8")).hexdigest()


def message_key(account_fp, header_message_id, date, sender, subject):
    """Stable 40-hex id. Prefers the RFC Message-ID; falls back to date/sender/subject."""
    header = (header_message_id or "").strip()
    if header and "@" in header:
        basis = "mid|" + header.strip("<>").lower()
    else:
        minute = iso(date)[:16] if isinstance(date, dt.datetime) else str(date or "")[:16]
        basis = "meta|" + minute + "|" + (sender or "").strip().lower() + "|" + (subject or "").strip()
    return hashlib.sha256(("rian-mail-v2|" + account_fp + "|" + basis).encode("utf-8")).hexdigest()[:40]


def _clip(text, limit):
    text = "" if text is None else str(text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text if len(text) <= limit else text[:limit]


def _fsync_dir(path):
    if os.name == "nt":
        return
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class MailStore:
    def __init__(self, data_dir):
        self.root = Path(data_dir)
        if not str(data_dir):
            raise MailError("MAIL_DATA_DIR_REQUIRED")
        self.index_path = self.root / "index.json"
        self.bodies = self.root / "bodies"
        self.backups = self.root / "backups"
        self.lock_path = self.root / ".sync.lock"

    # -- index -------------------------------------------------------------
    def load(self):
        if not self.index_path.exists():
            return None
        try:
            data = json.loads(self.index_path.read_text("utf-8"))
        except (OSError, UnicodeError, ValueError):
            raise MailError("INDEX_UNREADABLE") from None
        if not isinstance(data, dict) or data.get("version") != INDEX_VERSION or not isinstance(data.get("messages"), dict) \
                or not re.fullmatch(r"[a-f0-9]{64}", str(data.get("account", ""))):
            raise MailError("INDEX_INVALID")
        for key, meta in data["messages"].items():
            if not MESSAGE_ID.fullmatch(key) or not isinstance(meta, dict):
                raise MailError("INDEX_INVALID")
        return data

    def save(self, index):
        payload = json.dumps(index, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        atomic_write(self.index_path, payload)
        reread = self.load()
        if reread is None or len(reread["messages"]) != len(index["messages"]):
            raise MailError("INDEX_READBACK_FAILED")

    def backup(self, now):
        if not self.index_path.exists():
            return None
        self.backups.mkdir(parents=True, exist_ok=True)
        name = "index-" + now.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3) + ".json"
        atomic_write(self.backups / name, self.index_path.read_bytes())
        # Rotation removes only our own old index backups, never mail or the live index.
        olds = sorted(p for p in self.backups.glob("index-*.json") if p.is_file())
        for stale in olds[:-KEEP_BACKUPS]:
            stale.unlink()
        return name

    # -- bodies ------------------------------------------------------------
    def body_path(self, message_id):
        if not MESSAGE_ID.fullmatch(message_id or ""):
            raise MailError("INVALID_MESSAGE_ID")
        return self.bodies / (message_id + ".txt")

    def has_body(self, message_id):
        return self.body_path(message_id).is_file()

    def put_body(self, message_id, text):
        data = (text or "").encode("utf-8")[:MAX_BODY_STORE_BYTES]
        atomic_write(self.body_path(message_id), data)

    # -- single local writer -------------------------------------------------
    def acquire(self):
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(self.lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            age = utcnow().timestamp() - self.lock_path.stat().st_mtime
            if age < 2 * 3600:
                raise MailError("SYNC_ALREADY_RUNNING") from None
            self.lock_path.unlink()  # stale lock from a crashed process (>2h)
            fd = os.open(str(self.lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(str(os.getpid()))

    def release(self):
        try:
            self.lock_path.unlink()
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------- sources
class FixtureSource:
    """Synthetic mailbox for tests and E2E. JSON: {"account": "...", "messages": [...]}"""

    def __init__(self, path, account=None):
        data = json.loads(Path(path).read_text("utf-8"))
        self.account = account or data["account"]
        self.messages = data["messages"]

    def fetch_since(self, since, limit):
        out = []
        for m in self.messages:
            when = parse_iso(m["date"])
            if when and when >= since:
                out.append({"message_id": m.get("message_id"), "date": when, "from": m.get("from", ""), "to": m.get("to", ""),
                            "subject": m.get("subject", ""), "folder": m.get("folder", "INBOX"),
                            "size": len(m.get("body", "").encode("utf-8")), "attachments": int(m.get("attachments", 0)),
                            "body": m.get("body", "")})
        out.sort(key=lambda x: x["date"], reverse=True)
        return out[:limit]


class ReadOnlyImap:
    """Whitelist wrapper: only LOGIN, EXAMINE, UID SEARCH, UID FETCH (PEEK), LOGOUT exist."""

    def __init__(self, conn):
        object.__setattr__(self, "_conn", conn)

    def login(self, user, password):
        typ, _ = self._conn.login(user, password)
        if typ != "OK":
            raise MailError("IMAP_LOGIN_FAILED")

    def examine(self, folder):
        if not isinstance(folder, str) or not re.fullmatch(r"[^\x00-\x1f\"\\]{1,100}", folder):
            raise MailError("INVALID_FOLDER")
        typ, _ = self._conn.select('"' + folder + '"', readonly=True)
        if typ != "OK":
            raise MailError("IMAP_FOLDER_UNAVAILABLE")

    def uid_search_since(self, since):
        stamp = "%02d-%s-%04d" % (since.day, _MONTHS[since.month - 1], since.year)
        typ, data = self._conn.uid("SEARCH", None, "SINCE", stamp)
        if typ != "OK":
            raise MailError("IMAP_SEARCH_FAILED")
        return [x for x in (data[0] or b"").split() if x.isdigit()]

    def uid_fetch_peek(self, uid):
        if not isinstance(uid, (bytes, str)) or not str(uid if isinstance(uid, str) else uid.decode()).isdigit():
            raise MailError("INVALID_UID")
        typ, data = self._conn.uid("FETCH", uid, "(RFC822.SIZE BODY.PEEK[])")
        if typ != "OK":
            raise MailError("IMAP_FETCH_FAILED")
        for item in data or []:
            if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], (bytes, bytearray)):
                return bytes(item[1])
        raise MailError("IMAP_FETCH_EMPTY")

    def logout(self):
        try:
            self._conn.logout()
        except Exception:  # noqa: BLE001 - logout failure is irrelevant after read
            pass

    def __getattr__(self, name):
        raise MailError("IMAP_COMMAND_FORBIDDEN")

    def __setattr__(self, name, value):
        raise MailError("IMAP_COMMAND_FORBIDDEN")


def _text_body(msg):
    part = msg.get_body(preferencelist=("plain", "html"))
    if part is None:
        return ""
    try:
        content = part.get_content()
    except (LookupError, ValueError):
        payload = part.get_payload(decode=True) or b""
        content = payload.decode("utf-8", "replace")
    if part.get_content_type() == "text/html":
        content = html.unescape(re.sub(r"(?s)<(script|style).*?</\1>|<[^>]+>", " ", content))
    return content


def parse_rfc822(raw, folder):
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    try:
        when = parsedate_to_datetime(str(msg["date"])) if msg["date"] else None
        when = when.astimezone(dt.timezone.utc) if when and when.tzinfo else (when.replace(tzinfo=dt.timezone.utc) if when else None)
    except (TypeError, ValueError, IndexError):
        when = None
    return {"message_id": str(msg["message-id"] or ""), "date": when or utcnow(), "from": str(msg["from"] or ""),
            "subject": str(msg["subject"] or ""), "to": str(msg["to"] or ""), "folder": folder, "size": len(raw),
            "attachments": sum(1 for _ in msg.iter_attachments()), "body": _text_body(msg)}


class ImapSource:
    """Read-only IMAP over TLS. Credentials come from local config only, never from the relay."""

    def __init__(self, host, user, password, account=None, port=993, folders=("INBOX",), connect=None):
        if not host or not user or not password:
            raise MailError("MAIL_CREDENTIALS_MISSING")
        self.account = account or user
        self._args = (host, int(port))
        self._user, self._password, self._folders = user, password, list(folders)
        self._connect = connect

    def fetch_since(self, since, limit):
        if self._connect is not None:
            conn = self._connect(*self._args)
        else:
            import imaplib
            import ssl
            conn = imaplib.IMAP4_SSL(self._args[0], self._args[1], ssl_context=ssl.create_default_context(), timeout=60)
        box = ReadOnlyImap(conn)
        out = []
        try:
            box.login(self._user, self._password)
            for folder in self._folders:
                box.examine(folder)
                uids = box.uid_search_since(since)
                for uid in reversed(uids):
                    if len(out) >= limit:
                        break
                    out.append(parse_rfc822(box.uid_fetch_peek(uid), folder))
        finally:
            box.logout()
        out.sort(key=lambda x: x["date"], reverse=True)
        return out[:limit]


class OutlookBridgeSource:
    """Reuse an owner-installed local Bridge and its Windows vault entry; no secret crosses the relay."""

    def __init__(self, root):
        path = Path(root)
        if not path.is_absolute() or not path.is_dir() or path.is_symlink():
            raise MailError("OUTLOOK_BRIDGE_PATH_INVALID")
        script = path / "outlook_bridge.py"
        if not script.is_file() or script.is_symlink():
            raise MailError("OUTLOOK_BRIDGE_PATH_INVALID")
        spec = importlib.util.spec_from_file_location("rian_owner_outlook_bridge", script)
        if spec is None or spec.loader is None:
            raise MailError("OUTLOOK_BRIDGE_PATH_INVALID")
        bridge = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(bridge)
            config = bridge.validate_config(bridge.load_json(bridge.CONFIG, {}))
        except Exception:
            raise MailError("OUTLOOK_BRIDGE_CONFIG_INVALID") from None
        if not bridge.secret_present():
            raise MailError("MAIL_CREDENTIALS_MISSING")
        self.account = config["username"]
        self._bridge = bridge
        self._host, self._port = config["host"], config["port"]

    def fetch_since(self, since, limit):
        days = min(MAX_SYNC_DAYS, max(1, int((utcnow() - since).total_seconds() // 86400)))
        try:
            with self._bridge.imaplib.IMAP4_SSL(self._host, self._port, timeout=25) as imap:
                imap.login(self.account, self._bridge.get_secret())
                rows, errors = self._bridge.fetch_imap_messages(imap, days, limit)
                imap.logout()
        except Exception:
            raise MailError("OUTLOOK_BRIDGE_FETCH_FAILED") from None
        if errors:
            raise MailError("OUTLOOK_BRIDGE_PARTIAL_FETCH")
        results = []
        for row in rows:
            when = parse_iso(row.get("date"))
            if when is None or when < since:
                continue
            results.append({"message_id": row.get("id"), "date": when, "from": row.get("from"),
                            "to": row.get("to"), "subject": row.get("subject"), "folder": row.get("folder"),
                            "body": row.get("body"), "attachments": int(bool(row.get("has_attachments")))})
        return results[:limit]


def source_from_config(cfg):
    kind = (cfg or {}).get("type")
    if kind == "fixture":
        return FixtureSource(cfg["path"], cfg.get("account"))
    if kind == "outlook_bridge_v1":
        if set(cfg) != {"type", "root"}:
            raise MailError("OUTLOOK_BRIDGE_CONFIG_INVALID")
        return OutlookBridgeSource(cfg["root"])
    if kind == "imap":
        password = None
        if cfg.get("password_env"):
            password = os.environ.get(cfg["password_env"])
        elif cfg.get("password_file"):
            password = Path(cfg["password_file"]).read_text("utf-8").strip()
        return ImapSource(cfg.get("host"), cfg.get("user"), password, cfg.get("account"), cfg.get("port", 993), cfg.get("folders", ["INBOX"]))
    raise MailError("MAIL_SOURCE_NOT_CONFIGURED")


# ---------------------------------------------------------------- legacy
_LEGACY_FIELDS = {"id": ("message_id", "msgid", "Message-ID", "messageId"), "date": ("date", "received", "received_at", "sent_at"),
                  "from": ("from", "sender", "from_addr"), "subject": ("subject", "title")}


def _legacy_entries(data):
    if isinstance(data, dict):
        data = data.get("messages", data.get("items", data))
    if isinstance(data, dict):
        data = list(data.values())
    if not isinstance(data, list):
        raise MailError("LEGACY_INDEX_UNSUPPORTED")
    return data


def seed_from_legacy(path, account_fp, expected_account_field=None):
    """Read-only import of an older JSON index. Returns {id: metadata}. Never writes the legacy file."""
    try:
        data = json.loads(Path(path).read_text("utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise MailError("LEGACY_INDEX_UNREADABLE") from None
    if expected_account_field and isinstance(data, dict) and data.get("account"):
        if account_fingerprint(str(data["account"])) != account_fp:
            raise MailError("ACCOUNT_MISMATCH")
    out = {}
    for entry in _legacy_entries(data):
        if not isinstance(entry, dict):
            continue
        pick = {k: next((entry[f] for f in fields if entry.get(f)), None) for k, fields in _LEGACY_FIELDS.items()}
        when = parse_iso(pick["date"]) if pick["date"] else None
        if when is None and pick["date"]:
            try:
                when = parsedate_to_datetime(str(pick["date"])).astimezone(dt.timezone.utc)
            except (TypeError, ValueError, IndexError):
                when = None
        if when is None:
            continue
        key = message_key(account_fp, pick["id"], when, pick["from"], pick["subject"])
        out[key] = {"date": iso(when), "from": _clip(pick["from"], 200), "subject": _clip(pick["subject"], 300),
                    "folder": _clip(entry.get("folder", "INBOX"), 100), "size": 0, "attachments": 0, "legacy": True}
    return out


# ---------------------------------------------------------------- operations
def _bounded_int(value, low, high, code):
    if not isinstance(value, int) or isinstance(value, bool) or not (low <= value <= high):
        raise MailError(code)
    return value


def sync(data_dir, source, days, max_messages, *, now=None, legacy_index=None, progress=None, should_cancel=None):
    days = _bounded_int(days, 1, MAX_SYNC_DAYS, "SYNC_SCOPE_EXCEEDED")
    max_messages = _bounded_int(max_messages, 1, MAX_SYNC_MESSAGES, "SYNC_SCOPE_EXCEEDED")
    now = now or utcnow()
    progress = progress or (lambda **_: None)
    should_cancel = should_cancel or (lambda: False)
    store = MailStore(data_dir)
    account_fp = account_fingerprint(source.account)
    store.acquire()
    try:
        progress(stage="checking_index", percent=1)
        index = store.load()
        seeded = 0
        if index is not None and index["account"] != account_fp:
            raise MailError("ACCOUNT_MISMATCH")
        if index is None:
            index = {"version": INDEX_VERSION, "account": account_fp, "created_at": iso(now), "messages": {}}
            if legacy_index:
                index["messages"] = seed_from_legacy(legacy_index, account_fp, expected_account_field=True)
                seeded = len(index["messages"])
        before = len(index["messages"])
        progress(stage="fetching", percent=5)
        fetched = source.fetch_since(now - dt.timedelta(days=days), max_messages)
        added = unchanged = backfilled = 0
        for i, m in enumerate(fetched, 1):
            if should_cancel():
                raise MailCancelled("CANCELLED")
            key = message_key(account_fp, m.get("message_id"), m["date"], m.get("from"), m.get("subject"))
            if key in index["messages"]:
                unchanged += 1
                if not store.has_body(key):
                    store.put_body(key, m.get("body", ""))
                    backfilled += 1
            else:
                store.put_body(key, m.get("body", ""))
                index["messages"][key] = {"date": iso(m["date"]), "from": _clip(m.get("from"), 200), "subject": _clip(m.get("subject"), 300),
                                          "folder": _clip(m.get("folder", "INBOX"), 100), "to": _clip(m.get("to"), 300), "size": int(m.get("size", 0)),
                                          "attachments": int(m.get("attachments", 0))}
                added += 1
            progress(stage="merging", percent=5 + int(85 * i / max(1, len(fetched))), done=i, total=len(fetched))
        if should_cancel():
            raise MailCancelled("CANCELLED")
        progress(stage="backing_up", percent=92)
        backup = store.backup(now)
        index["updated_at"] = iso(now)
        progress(stage="writing_index", percent=96)
        store.save(index)
        dates = sorted(v["date"] for v in index["messages"].values())
        return {"ok": True, "account_match": True, "days": days, "max_messages": max_messages, "fetched": len(fetched),
                "added": added, "unchanged": unchanged, "bodies_backfilled": backfilled, "legacy_seeded": seeded,
                "before": before, "total": len(index["messages"]), "removed": 0, "backup": backup,
                "oldest": dates[0] if dates else None, "newest": dates[-1] if dates else None,
                "mailbox_modified": False}
    finally:
        store.release()


def validate_search_params(query, limit=20, offset=0, since=None, until=None, sender=None, recipient=None, folder=None):
    if not isinstance(query, str) or not query.strip() or len(query) > 120 or query.startswith("-") or re.search(r"[\x00-\x1f\x7f]", query):
        raise MailError("INVALID_SEARCH")
    _bounded_int(limit, 1, 20, "INVALID_LIMIT")
    _bounded_int(offset, 0, 500, "INVALID_OFFSET")
    for value in (sender, recipient, folder):
        if value is not None and (not isinstance(value, str) or not value.strip() or len(value) > 120 or re.search(r"[\x00-\x1f\x7f]", value)):
            raise MailError("INVALID_FILTER")
    for value in (since, until):
        if value is not None and (not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:Z|[+-]\d\d:\d\d)", value) or parse_iso(value) is None):
            raise MailError("INVALID_DATE")
    if since is not None and until is not None and parse_iso(since) > parse_iso(until):
        raise MailError("INVALID_DATE")


def search(data_dir, query, limit=20, offset=0, since=None, until=None, sender=None, recipient=None, folder=None, *, expected_account_fingerprint=None):
    validate_search_params(query, limit, offset, since, until, sender, recipient, folder)
    index = verify_mail_account(data_dir, expected_account_fingerprint) if expected_account_fingerprint is not None else MailStore(data_dir).load()
    if index is None:
        raise MailError("INDEX_NOT_FOUND")
    needle = query.strip().lower()
    hits = []
    for key, meta in index["messages"].items():
        if needle not in (str(meta.get("subject", "")) + " " + str(meta.get("from", ""))).lower():
            continue
        date = parse_iso(meta.get("date"))
        if since is not None and (date is None or date < parse_iso(since)):
            continue
        if until is not None and (date is None or date > parse_iso(until)):
            continue
        if sender is not None and sender.casefold() not in str(meta.get("from", "")).casefold():
            continue
        if recipient is not None and recipient.casefold() not in str(meta.get("to", "")).casefold():
            continue
        if folder is not None and folder.casefold() != str(meta.get("folder", "")).casefold():
            continue
        hits.append((key, meta))
    hits.sort(key=lambda kv: kv[1].get("date", ""), reverse=True)
    return {"ok": True, "query": query, "count": len(hits), "offset": offset,
            "next_offset": offset + limit if offset + limit < len(hits) and offset + limit <= 500 else None,
            "results": [{"message_id": k, "date": v.get("date"), "from": v.get("from"), "to": v.get("to"),
                         "subject": v.get("subject"), "folder": v.get("folder")} for k, v in hits[offset:offset + limit]],
            "updated_at": index.get("updated_at"), "synced_at": index.get("updated_at"),
            "bodies_included": False, "mailbox_modified": False}


def _mail_direction(folder):
    # Folder names are deliberately conservative; unknown/localized folders need explicit configuration.
    name = str(folder or "").strip().lower().replace("\\\\", "/")
    tail = name.rsplit("/", 1)[-1]
    if name == "inbox":
        return "inbox"
    if tail in ("sent", "sent items", "sent mail", "보낸 편지함", "보낸메일함", "보낸 메일함"):
        return "sent"
    return "unknown"


def validate_recent_params(days, limit=20, offset=0, folder="all", sender=None, recipient=None, query=None):
    _bounded_int(days, 1, MAX_SYNC_DAYS, "INVALID_DAYS")
    _bounded_int(limit, 1, 20, "INVALID_LIMIT")
    _bounded_int(offset, 0, 1000, "INVALID_OFFSET")
    if folder not in ("all", "inbox", "sent"):
        raise MailError("INVALID_FOLDER")
    for value in (sender, recipient, query):
        if value is not None and (not isinstance(value, str) or not value.strip() or len(value) > 120 or re.search(r"[\x00-\x1f\x7f]", value)):
            raise MailError("INVALID_FILTER")


def verify_mail_account(data_dir, expected_account_fingerprint):
    if not isinstance(expected_account_fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_account_fingerprint):
        raise MailError("MAIL_ACCOUNT_PIN_REQUIRED")
    index = MailStore(data_dir).load()
    if index is not None and index["account"] != expected_account_fingerprint:
        raise MailError("ACCOUNT_MISMATCH")
    return index


def status(data_dir, *, expected_account_fingerprint):
    index = verify_mail_account(data_dir, expected_account_fingerprint)
    messages = index["messages"] if index is not None else {}
    counts = {"inbox": 0, "sent": 0, "unknown": 0}
    for meta in messages.values():
        counts[_mail_direction(meta.get("folder"))] += 1
    return {"ok": True, "index_exists": index is not None, "messages": len(messages),
            "updated_at": index.get("updated_at") if index is not None else None,
            "synced_at": index.get("updated_at") if index is not None else None,
            "folder_counts": counts, "recipient_metadata_available": sum(bool(v.get("to")) for v in messages.values()),
            "mailbox_modified": False, "bodies_included": False}


def recent(data_dir, days, limit=20, offset=0, folder="all", sender=None, recipient=None, query=None, *,
           expected_account_fingerprint, now=None):
    validate_recent_params(days, limit, offset, folder, sender, recipient, query)
    index = verify_mail_account(data_dir, expected_account_fingerprint)
    if index is None:
        raise MailError("INDEX_NOT_FOUND")
    now = now or utcnow()
    earliest = now - dt.timedelta(days=days)
    matches, unknown_recipient, unknown_folder = [], 0, 0
    for key, meta in index["messages"].items():
        date = parse_iso(meta.get("date"))
        if date is None or not earliest <= date <= now + dt.timedelta(minutes=5):
            continue
        direction = _mail_direction(meta.get("folder"))
        if direction == "unknown":
            unknown_folder += 1
        if folder != "all" and direction != folder:
            continue
        if sender is not None and sender.casefold() not in str(meta.get("from", "")).casefold():
            continue
        if query is not None and query.casefold() not in (str(meta.get("subject", "")) + " " + str(meta.get("from", ""))).casefold():
            continue
        if not meta.get("to"):
            unknown_recipient += 1
        if recipient is not None and recipient.casefold() not in str(meta.get("to", "")).casefold():
            continue
        matches.append((date, key, {"message_id": key, "date": meta.get("date"), "from": meta.get("from"),
                        "to": meta.get("to"), "subject": meta.get("subject"), "folder": meta.get("folder"),
                        "direction": direction, "body_cached": MailStore(data_dir).has_body(key)}))
    matches.sort(key=lambda item: (item[0], item[1]), reverse=True)
    page = matches[offset:offset + limit]
    return {"ok": True, "days": days, "count": len(matches), "offset": offset,
            "next_offset": offset + limit if offset + limit < len(matches) and offset + limit <= 1000 else None,
            "results": [item[2] for item in page], "updated_at": index.get("updated_at"),
            "synced_at": index.get("updated_at"),
            "unknown_recipient_count": unknown_recipient, "unknown_folder_count": unknown_folder,
            "pagination_limit": 1000, "bodies_included": False, "mailbox_modified": False,
            "pending_status": "NOT_DETERMINED_METADATA_ONLY"}


def review_pending(data_dir, days, limit=20, offset=0, *, expected_account_fingerprint, now=None):
    validate_recent_params(days, limit, offset)
    index = verify_mail_account(data_dir, expected_account_fingerprint)
    sent = []
    for meta in index["messages"].values():
        if _mail_direction(meta.get("folder")) == "sent":
            sent.append((parse_iso(meta.get("date")), str(meta.get("subject", "")).casefold()))
    def subject(value):
        return re.sub(r"^(?:(?:re|fw|fwd)\s*:\s*)+", "", str(value or "").strip(), flags=re.I).casefold()
    # This is only a candidate list: matching subjects do not prove a reply.
    matches = []
    for key, meta in index["messages"].items():
        if _mail_direction(meta.get("folder")) != "inbox":
            continue
        received = parse_iso(meta.get("date"))
        current = now or utcnow()
        if received is None or not current - dt.timedelta(days=days) <= received <= current + dt.timedelta(minutes=5):
            continue
        matched = bool(sent) and any(d is not None and d >= received and subject(s) == subject(meta.get("subject")) for d, s in sent)
        matches.append((received, key, {"message_id": key, "date": meta.get("date"), "from": meta.get("from"),
                                       "to": meta.get("to"), "subject": meta.get("subject"),
                                       "reply_check": "POSSIBLE_REPLY_FOUND" if matched else "REVIEW_CANDIDATE" if sent else "SENT_NOT_INDEXED"}))
    matches.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return {"ok": True, "count": len(matches), "offset": offset,
            "next_offset": offset + limit if offset + limit < len(matches) and offset + limit <= 1000 else None,
            "results": [item[2] for item in matches[offset:offset + limit]], "sent_folder_indexed": bool(sent),
            "updated_at": index.get("updated_at"), "bodies_included": False, "mailbox_modified": False,
            "heuristic_only": True, "pending_status": "CANDIDATES_ONLY" if sent else "SENT_NOT_INDEXED"}


def read_message(data_dir, message_id, max_bytes=MAX_BODY_RETURN_BYTES):
    if not isinstance(message_id, str) or not MESSAGE_ID.fullmatch(message_id):
        raise MailError("INVALID_MESSAGE_ID")
    store = MailStore(data_dir)
    index = store.load()
    if index is None:
        raise MailError("INDEX_NOT_FOUND")
    meta = index["messages"].get(message_id)
    if meta is None:
        raise MailError("MESSAGE_NOT_FOUND")
    path = store.body_path(message_id)
    if not path.is_file():
        raise MailError("BODY_NOT_CACHED")
    raw = path.read_bytes()
    body = raw[:max_bytes].decode("utf-8", "ignore")
    return {"ok": True, "message_id": message_id, "date": meta.get("date"), "from": meta.get("from"), "subject": meta.get("subject"),
            "body": body, "truncated": len(raw) > max_bytes, "messages_returned": 1}


def doctor(data_dir):
    store = MailStore(data_dir)
    index = store.load()
    return {"ok": True, "index_present": index is not None, "messages": len(index["messages"]) if index else 0,
            "backups": len(list(store.backups.glob("index-*.json"))) if store.backups.exists() else 0}


def main(argv=None):
    p = argparse.ArgumentParser(description="RIAN Commander V2 local mail index (read-only mailbox)")
    p.add_argument("--data", required=True)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sync")
    s.add_argument("--source-config", required=True)
    s.add_argument("--days", type=int, required=True)
    s.add_argument("--max-messages", type=int, required=True)
    s.add_argument("--legacy-index")
    q = sub.add_parser("search")
    q.add_argument("query")
    q.add_argument("--limit", type=int, default=20)
    r = sub.add_parser("read")
    r.add_argument("message_id")
    sub.add_parser("doctor")
    a = p.parse_args(argv)
    try:
        if a.cmd == "sync":
            src = source_from_config(json.loads(Path(a.source_config).read_text("utf-8")))
            out = sync(a.data, src, a.days, a.max_messages, legacy_index=a.legacy_index)
        elif a.cmd == "search":
            out = search(a.data, a.query, a.limit)
        elif a.cmd == "read":
            out = read_message(a.data, a.message_id)
        else:
            out = doctor(a.data)
        print(json.dumps(out, ensure_ascii=False))
        return 0
    except MailError as err:
        print(json.dumps({"ok": False, "error": str(err)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
