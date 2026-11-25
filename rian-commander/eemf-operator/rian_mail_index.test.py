"""Synthetic-data tests for the V2 local mail index. No real mailbox, no network."""
import datetime as dt
import hashlib
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rian_mail_index as mail  # noqa: E402

NOW = dt.datetime(2026, 11, 21, 3, 0, tzinfo=dt.timezone.utc)
ACCOUNT = "synthetic.user@example.test"


def synthetic_mailbox(days, per_day, start_offset=0, prefix="m"):
    out = []
    for d in range(start_offset, start_offset + days):
        for k in range(per_day):
            when = NOW - dt.timedelta(days=d, hours=k)
            out.append({"message_id": f"<{prefix}-{d}-{k}@example.test>", "date": mail.iso(when),
                        "from": f"sender{k}@example.test", "subject": f"합성 견적 {d}-{k}",
                        "body": f"SYNTHETIC BODY {d}-{k} " + "x" * 50, "attachments": k % 2})
    return out


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.data = self.root / "rian-mail-v2"

    def tearDown(self):
        self.tmp.cleanup()

    def source(self, messages, account=ACCOUNT):
        path = self.root / ("box-" + hashlib.sha1(json.dumps(messages).encode()).hexdigest()[:8] + ".json")
        path.write_text(json.dumps({"account": account, "messages": messages}), "utf-8")
        return mail.FixtureSource(path)


class SyncTests(Fixture):
    def test_120_day_index_is_kept_and_14_day_sync_merges_without_duplicates(self):
        legacy = synthetic_mailbox(120, 2)                   # 240 messages over 120 days
        legacy_path = self.root / "legacy-index.json"
        legacy_path.write_text(json.dumps({"account": ACCOUNT, "messages": [
            {k: v for k, v in m.items() if k != "body"} for m in legacy]}), "utf-8")
        recent = synthetic_mailbox(14, 2) + synthetic_mailbox(3, 4, prefix="new")  # 28 overlapping + 12 new
        events = []
        r = mail.sync(self.data, self.source(recent), 14, 1000, now=NOW, legacy_index=legacy_path,
                      progress=lambda **kw: events.append(kw))
        self.assertTrue(r["ok"])
        self.assertEqual(r["legacy_seeded"], 240)
        self.assertEqual(r["added"], 12)
        self.assertEqual(r["unchanged"], 28)
        self.assertEqual(r["bodies_backfilled"], 28)
        self.assertEqual(r["total"], 252)
        self.assertEqual(r["removed"], 0)
        self.assertFalse(r["mailbox_modified"])
        idx = mail.MailStore(self.data).load()
        dates = sorted(v["date"] for v in idx["messages"].values())
        self.assertLessEqual(mail.parse_iso(dates[0]), NOW - dt.timedelta(days=119))
        self.assertIn("merging", {e.get("stage") for e in events})
        self.assertEqual(json.loads(legacy_path.read_text("utf-8"))["messages"][0]["subject"], legacy[0]["subject"], "legacy file untouched")
        # second 14-day sync: idempotent, index still 252, a backup of the previous index exists
        r2 = mail.sync(self.data, self.source(recent), 14, 1000, now=NOW + dt.timedelta(hours=1))
        self.assertEqual((r2["added"], r2["unchanged"], r2["total"], r2["before"]), (0, 40, 252, 252))
        backups = list((self.data / "backups").glob("index-*.json"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(len(json.loads(backups[0].read_text("utf-8"))["messages"]), 252)

    def test_sync_respects_day_window_and_message_cap(self):
        r = mail.sync(self.data, self.source(synthetic_mailbox(30, 5)), 14, 20, now=NOW)
        self.assertEqual((r["fetched"], r["added"], r["total"]), (20, 20, 20))
        for bad in [(0, 10), (15, 10), (14, 0), (14, 1001), ("14", 10), (True, 10)]:
            with self.assertRaises(mail.MailError):
                mail.sync(self.data, self.source([]), *bad, now=NOW)

    def test_account_mismatch_stops_before_any_write(self):
        mail.sync(self.data, self.source(synthetic_mailbox(5, 1)), 14, 100, now=NOW)
        before = (self.data / "index.json").read_bytes()
        bodies = sorted(p.name for p in (self.data / "bodies").iterdir())
        with self.assertRaisesRegex(mail.MailError, "ACCOUNT_MISMATCH"):
            mail.sync(self.data, self.source(synthetic_mailbox(2, 1, prefix="other"), account="someone.else@example.test"), 14, 100, now=NOW)
        self.assertEqual((self.data / "index.json").read_bytes(), before)
        self.assertEqual(sorted(p.name for p in (self.data / "bodies").iterdir()), bodies)
        self.assertFalse((self.data / "backups").exists())
        self.assertFalse((self.data / ".sync.lock").exists(), "lock released on failure")

    def test_legacy_index_for_other_account_is_refused(self):
        legacy = self.root / "legacy.json"
        legacy.write_text(json.dumps({"account": "other@example.test", "messages": []}), "utf-8")
        with self.assertRaisesRegex(mail.MailError, "ACCOUNT_MISMATCH"):
            mail.sync(self.data, self.source([]), 14, 10, now=NOW, legacy_index=legacy)
        self.assertFalse((self.data / "index.json").exists())

    def test_cancel_leaves_previous_index_intact(self):
        mail.sync(self.data, self.source(synthetic_mailbox(3, 1)), 14, 100, now=NOW)
        before = (self.data / "index.json").read_bytes()
        calls = {"n": 0}

        def cancel_after_two():
            calls["n"] += 1
            return calls["n"] > 2
        with self.assertRaises(mail.MailCancelled):
            mail.sync(self.data, self.source(synthetic_mailbox(10, 3, prefix="c")), 14, 100, now=NOW, should_cancel=cancel_after_two)
        self.assertEqual((self.data / "index.json").read_bytes(), before)

    def test_concurrent_local_sync_is_refused(self):
        store = mail.MailStore(self.data)
        store.acquire()
        try:
            with self.assertRaisesRegex(mail.MailError, "SYNC_ALREADY_RUNNING"):
                mail.sync(self.data, self.source([]), 14, 10, now=NOW)
        finally:
            store.release()

    def test_backups_rotate_to_last_ten(self):
        box = self.source(synthetic_mailbox(2, 1))
        for i in range(13):
            mail.sync(self.data, box, 14, 10, now=NOW + dt.timedelta(minutes=i))
        self.assertEqual(len(list((self.data / "backups").glob("index-*.json"))), 10)


class ReadSearchTests(Fixture):
    def setUp(self):
        super().setUp()
        mail.sync(self.data, self.source(synthetic_mailbox(14, 3)), 14, 1000, now=NOW)
        self.index = mail.MailStore(self.data).load()

    def test_search_returns_metadata_only(self):
        r = mail.search(self.data, "견적 3-", 5)
        self.assertEqual(len(r["results"]), 3)
        self.assertFalse(r["bodies_included"])
        self.assertNotIn("SYNTHETIC BODY", json.dumps(r, ensure_ascii=False))
        for bad in ["", "--all", "x\ny", "a" * 121]:
            with self.assertRaises(mail.MailError):
                mail.search(self.data, bad)

    def test_search_pagination_date_and_sender_filters(self):
        first = mail.search(self.data, "견적", 5, sender="sender1@example.test", since=mail.iso(NOW - dt.timedelta(days=3)))
        self.assertEqual(first["count"], 3)
        self.assertEqual(len(first["results"]), 3)
        self.assertIsNone(first["next_offset"])
        self.assertEqual(first["synced_at"], mail.iso(NOW))
        page = mail.search(self.data, "견적", 2, offset=2)
        self.assertEqual(page["next_offset"], 4)
        self.assertNotEqual(page["results"][0]["message_id"], mail.search(self.data, "견적", 2)["results"][0]["message_id"])
        for params in ({"offset": -1}, {"offset": 501}, {"since": "invalid"},
                       {"since": mail.iso(NOW), "until": mail.iso(NOW - dt.timedelta(days=1))},
                       {"sender": "a\nb"}):
            with self.assertRaises(mail.MailError):
                mail.search(self.data, "견적", **params)

    def test_read_exactly_one_selected_message(self):
        target = mail.search(self.data, "견적 2-1", 1)["results"][0]["message_id"]
        r = mail.read_message(self.data, target)
        self.assertEqual(r["messages_returned"], 1)
        self.assertIn("SYNTHETIC BODY 2-1", r["body"])
        self.assertNotIn("SYNTHETIC BODY 2-2", r["body"])
        for bad in ["../index", "A" * 40, "a" * 19, target + "\n", "*"]:
            with self.assertRaises(mail.MailError):
                mail.read_message(self.data, bad)
        with self.assertRaisesRegex(mail.MailError, "MESSAGE_NOT_FOUND"):
            mail.read_message(self.data, "f" * 40)

    def test_body_is_bounded(self):
        target = next(iter(self.index["messages"]))
        mail.MailStore(self.data).put_body(target, "가" * 40000)
        r = mail.read_message(self.data, target, max_bytes=1000)
        self.assertTrue(r["truncated"])
        self.assertLessEqual(len(r["body"].encode("utf-8")), 1000)

    def test_recent_and_pending_report_uncertainty_when_sent_is_not_indexed(self):
        pin = mail.account_fingerprint(ACCOUNT)
        recent = mail.recent(self.data, 3, 2, expected_account_fingerprint=pin, now=NOW)
        self.assertEqual(len(recent["results"]), 2)
        self.assertIsNotNone(recent["next_offset"])
        review = mail.review_pending(self.data, 3, 2, expected_account_fingerprint=pin, now=NOW)
        self.assertTrue(review["heuristic_only"])
        self.assertFalse(review["sent_folder_indexed"])
        self.assertEqual(review["results"][0]["reply_check"], "SENT_NOT_INDEXED")

    def test_recipient_filter_and_sent_subject_reply_hint(self):
        messages = [
            {"message_id": "<in-1@example.test>", "date": mail.iso(NOW - dt.timedelta(hours=2)),
             "from": "partner@example.test", "to": "owner@example.test", "subject": "견적 검토", "folder": "INBOX", "body": "request"},
            {"message_id": "<out-1@example.test>", "date": mail.iso(NOW - dt.timedelta(hours=1)),
             "from": "owner@example.test", "to": "partner@example.test", "subject": "Re: 견적 검토", "folder": "Sent", "body": "reply"},
        ]
        mail.sync(self.data, self.source(messages), 14, 100, now=NOW)
        by_recipient = mail.search(self.data, "견적", recipient="owner@example.test")
        self.assertEqual(len(by_recipient["results"]), 1)
        self.assertEqual(by_recipient["results"][0]["folder"], "INBOX")
        review = mail.review_pending(self.data, 2, expected_account_fingerprint=mail.account_fingerprint(ACCOUNT), now=NOW)
        self.assertTrue(review["sent_folder_indexed"])
        match = next(row for row in review["results"] if row["subject"] == "견적 검토")
        self.assertEqual(match["reply_check"], "POSSIBLE_REPLY_FOUND")


class BridgeAdapterTests(Fixture):
    def test_local_bridge_adapter_reuses_bounded_read_only_fetch_without_returning_credential(self):
        bridge_dir = self.root / "bridge"
        bridge_dir.mkdir()
        (bridge_dir / "outlook_bridge.py").write_text('''
from pathlib import Path
import datetime as dt
CONFIG = Path(__file__).with_name("config.json")
def load_json(path, default): return {"username":"synthetic.user@example.test", "host":"mail.example.test", "port":993}
def validate_config(cfg): return cfg
def secret_present(): return True
def get_secret(): return "synthetic-password"
class FakeImap:
    def __init__(self, host, port, timeout): self.host=host
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def login(self, user, password): assert password == "synthetic-password"
    def logout(self): pass
class imaplib:
    IMAP4_SSL = FakeImap
def fetch_imap_messages(imap, days, limit):
    assert 1 <= days <= 14 and limit <= 1000
    return ([{"id":"local-id", "date":dt.datetime.now(dt.timezone.utc).isoformat(),
             "from":"sender@example.test", "to":"synthetic.user@example.test",
             "subject":"synthetic", "folder":"INBOX", "body":"synthetic body", "has_attachments":False}], [])
''', "utf-8")
        source = mail.source_from_config({"type": "outlook_bridge_v1", "root": str(bridge_dir)})
        self.assertEqual(source.account, ACCOUNT)
        result = source.fetch_since(mail.utcnow() - dt.timedelta(days=2), 20)
        self.assertEqual(len(result), 1)
        self.assertNotIn("synthetic-password", json.dumps(result, default=str))
        with self.assertRaisesRegex(mail.MailError, "OUTLOOK_BRIDGE_CONFIG_INVALID"):
            mail.source_from_config({"type": "outlook_bridge_v1", "root": str(bridge_dir), "password": "bad"})


class FakeImap:
    def __init__(self, raw_messages):
        self.raw, self.calls = raw_messages, []

    def login(self, user, password):
        self.calls.append("LOGIN")
        return "OK", [b""]

    def select(self, folder, readonly=False):
        self.calls.append("EXAMINE" if readonly else "SELECT")
        return "OK", [b"3"]

    def uid(self, command, *args):
        self.calls.append("UID " + command + " " + " ".join(str(a) for a in args if a is not None))
        if command == "SEARCH":
            return "OK", [b" ".join(str(i + 1).encode() for i in range(len(self.raw)))]
        return "OK", [(b"1 (UID 1 BODY[] {10}", self.raw[int(args[0]) - 1]), b")"]

    def logout(self):
        self.calls.append("LOGOUT")

    def store(self, *a):  # present on real imaplib; must never be reachable
        raise AssertionError("STORE must never be called")

    def expunge(self):
        raise AssertionError("EXPUNGE must never be called")


def rfc822(i, when):
    return (f"Message-ID: <imap-{i}@example.test>\r\nDate: {when.strftime('%a, %d %b %Y %H:%M:%S +0000')}\r\n"
            f"From: Sender {i} <s{i}@example.test>\r\nSubject: =?utf-8?b?7ZWp7ISxIOuplOydvA==?= {i}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n\r\nimap synthetic body " + str(i) + "\r\n").encode()


class ImapReadOnlyTests(Fixture):
    def test_imap_uses_examine_and_body_peek_only(self):
        fake = FakeImap([rfc822(i, NOW - dt.timedelta(days=i)) for i in range(3)])
        src = mail.ImapSource("imap.example.test", ACCOUNT, "synthetic-password", connect=lambda h, p: fake)
        r = mail.sync(self.data, src, 7, 10, now=NOW)
        self.assertEqual(r["added"], 3)
        self.assertIn("EXAMINE", fake.calls)
        self.assertNotIn("SELECT", fake.calls)
        fetches = [c for c in fake.calls if c.startswith("UID FETCH")]
        self.assertTrue(fetches and all("BODY.PEEK[]" in c for c in fetches))
        self.assertTrue(all(c.split()[0] in {"LOGIN", "EXAMINE", "UID", "LOGOUT"} for c in fake.calls))
        self.assertTrue(any("SINCE 14-Nov-2026" in c for c in fake.calls), "locale-independent IMAP date")
        hit = mail.search(self.data, "합성 메일", 5)
        self.assertEqual(hit["count"], 3)

    def test_wrapper_exposes_no_mutating_commands(self):
        box = mail.ReadOnlyImap(FakeImap([]))
        for name in ["store", "expunge", "copy", "move", "append", "delete", "select", "uid", "_conn_replace"]:
            with self.assertRaisesRegex(mail.MailError, "IMAP_COMMAND_FORBIDDEN"):
                getattr(box, name)
        with self.assertRaises(mail.MailError):
            box.examine('INBOX" (bad')

    def test_source_has_no_send_or_delete_capability(self):
        code = Path(mail.__file__).read_text("utf-8")
        executable = "\n".join(l for l in code.splitlines() if not l.strip().startswith(("#", '"""', "*")))
        for forbidden in ["smtplib", "sendmail", ".store(", ".expunge(", ".copy(", ".append(\"", "\\\\Deleted", "MOVE "]:
            self.assertNotIn(forbidden, executable)
        self.assertIsNone(re.search(r"select\([^)]*\)(?<!readonly=True\))", executable.replace('select(\'"\' + folder + \'"\', readonly=True)', "")))

    def test_credentials_missing_is_explicit(self):
        with self.assertRaisesRegex(mail.MailError, "MAIL_CREDENTIALS_MISSING"):
            mail.ImapSource("imap.example.test", ACCOUNT, None)


if __name__ == "__main__":
    unittest.main()
