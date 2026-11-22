"""Collector tests: parsers, config, real read-only collection on this OS, transport rules, bounded retry.
No network outside loopback, no command channel, no mailbox or file content access."""
import http.server
import importlib.util
import json
import os
import platform
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("collector", HERE.parent / "collector" / "rian_health_collector.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
SOURCE = (HERE.parent / "collector" / "rian_health_collector.py").read_text("utf-8")


class Parsers(unittest.TestCase):
    def test_linux_proc(self):
        a = c.parse_proc_stat("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 2 3 4\n")
        b = c.parse_proc_stat("cpu  150 0 150 900 0 0 0 0 0 0\n")
        self.assertEqual(c.cpu_percent_from_proc(a, b), 50.0)
        total, used = c.parse_meminfo("MemTotal:       16000000 kB\nMemFree: 1 kB\nMemAvailable:    4000000 kB\n")
        self.assertEqual((total, used), (16000000 * 1024, 12000000 * 1024))

    def test_macos_top_and_vm_stat(self):
        top = "Processes: 1\nCPU usage: 50.0% user, 10.0% sys, 40.0% idle\n\nProcesses: 1\nCPU usage: 6.74% user, 12.35% sys, 80.89% idle\n"
        self.assertEqual(c.parse_top_cpu(top), 19.1, "uses the second sample, not the since-boot one")
        vm = ("Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free:                               1000.\n"
              "Pages active:                             5000.\nPages inactive:                           2000.\nPages speculative:                         500.\n")
        total, used = c.parse_vm_stat(vm, 16384 * 10000)
        self.assertEqual(used, 16384 * (10000 - 3500))

    def test_windows_outputs(self):
        self.assertEqual(c.parse_tasklist_csv('"sqlservr.exe","1","Services","0","9 K"\n"svchost.exe","2","x","0","1 K"\n'), {"sqlservr.exe", "svchost.exe"})
        self.assertTrue(c.parse_sc_query("SERVICE_NAME: MSSQLSERVER\n        STATE              : 4  RUNNING\n"))
        self.assertFalse(c.parse_sc_query("        STATE              : 1  STOPPED\n"))

    def test_bad_input_is_an_error_code(self):
        with self.assertRaises(c.CollectorError):
            c.parse_top_cpu("nothing")
        with self.assertRaises(c.CollectorError):
            c.parse_meminfo("MemTotal: 1 kB\n")


class Config(unittest.TestCase):
    def cfg(self, **over):
        d = tempfile.mkdtemp()
        p = Path(d) / "c.json"
        p.write_text(json.dumps({"device_id": "DEV-1", **over}), "utf-8")
        return c.load_config(p)

    def test_disabled_by_default_and_defaults(self):
        cfg = self.cfg()
        self.assertFalse(cfg["enabled"])
        self.assertEqual(cfg["interval_seconds"], 300)
        self.assertEqual(len(cfg["disks"]), 1)

    def test_rejects_unsafe_names_and_intervals(self):
        for over in [{"services": [{"name": "nginx; rm -rf /", "type": "process"}]}, {"services": [{"name": "x", "type": "shell"}]},
                     {"interval_seconds": 5}, {"device_id": "../etc"}, {"disks": "C:\\"}, {"disks": [""]}]:
            with self.assertRaises(c.CollectorError, msg=str(over)):
                self.cfg(**over)

    def test_never_uses_a_shell_and_has_no_inbound_or_exec_path(self):
        self.assertNotIn("shell=True", SOURCE)
        for forbidden in ("os.system", "eval(", "exec(", "socketserver", "HTTPServer", "Popen"):
            self.assertNotIn(forbidden, SOURCE, forbidden)


class LiveCollection(unittest.TestCase):
    def test_collects_this_machine_read_only(self):
        cfg = {"device_id": "LIVE-1", "disks": [c.default_disk()], "services": [{"name": "definitely-not-running-xyz", "type": "process"}]}
        s = c.collect(cfg)
        self.assertEqual(s["os"]["family"], {"Darwin": "macOS"}.get(platform.system(), platform.system()))
        if s["cpu"] is not None:
            self.assertTrue(0 <= s["cpu"]["percent"] <= 100)
        else:
            self.assertTrue(any(e.startswith("CPU") for e in s["collection"]["errors"]))
        self.assertIsNotNone(s["memory"], s["collection"]["errors"])
        self.assertTrue(0 < s["memory"]["percent"] <= 100)
        self.assertEqual(len(s["disks"]), 1)
        self.assertTrue(0 < s["disks"][0]["percent"] <= 100)
        self.assertEqual(s["services"][0]["running"], False)
        json.dumps(s)


class FakeSender:
    def __init__(self, fail):
        self.fail, self.sent = fail, []

    def send(self, sample):
        if self.fail():
            raise c.CollectorError("SERVER_UNREACHABLE")
        self.sent.append(sample)


class LoopBehaviour(unittest.TestCase):
    def test_bounded_queue_rate_limited_logs_and_recovery(self):
        down = {"v": True}
        sender = FakeSender(lambda: down["v"])
        n = {"i": 0}

        def fake_collect(cfg):
            n["i"] += 1
            return {"seq": n["i"]}

        loop = c.Loop({"interval_seconds": 300}, sender, collect_fn=fake_collect, sleep=lambda s: None)
        logs = []
        with patch.object(c, "log", side_effect=lambda e, **f: logs.append((e, f))):
            for _ in range(30):
                loop.tick()
            self.assertEqual(len(loop.queue), c.MAX_QUEUE)
            self.assertEqual(loop.dropped, 30 - c.MAX_QUEUE)
            self.assertEqual(sum(1 for e, _ in logs if e == "SEND_FAILED"), 1 + 30 // c.LOG_EVERY)
            down["v"] = False
            loop.tick()
        # The recovering tick adds sample 31, so the newest MAX_QUEUE samples (20..31) are delivered in order.
        self.assertEqual([s["seq"] for s in sender.sent], list(range(31 - c.MAX_QUEUE + 1, 32)))
        self.assertEqual(logs[-1][0], "SEND_RECOVERED")


class Transport(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.token = Path(self.d) / "token"
        self.token.write_text("t" * 48, "utf-8")
        os.chmod(self.token, 0o600)

    def cfg(self, url, loop=True):
        return {"server_url": url, "token_file": str(self.token), "allow_test_loopback": loop}

    def test_https_required_outside_loopback(self):
        for url in ["http://example.test", "https://u:p@example.test", "https://example.test/x", "ftp://example.test"]:
            with self.assertRaises(c.CollectorError):
                c.Sender(self.cfg(url))
        c.Sender(self.cfg("https://example.test"))

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_token_permissions(self):
        os.chmod(self.token, 0o644)
        with self.assertRaises(c.CollectorError):
            c.Sender(self.cfg("https://example.test"))

    def test_server_reply_is_never_an_instruction(self):
        seen = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                seen.append((self.path, self.headers.get("Authorization"), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
                body = json.dumps({"ok": True, "command": "shutdown -h now", "run": ["rm", "-rf", "/"]}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        sender = c.Sender(self.cfg("http://127.0.0.1:%d" % srv.server_address[1]))
        with patch.object(c, "run_query", side_effect=AssertionError("no OS query during send")), \
                patch.object(c.subprocess, "run", side_effect=AssertionError("nothing executed")):
            self.assertIsNone(sender.send({"deviceId": "D", "x": 1}))
        self.assertEqual(seen[0][0], "/v1/health/ingest")
        self.assertEqual(seen[0][1], "Bearer " + "t" * 48)


if __name__ == "__main__":
    unittest.main()
