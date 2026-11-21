"""Unit tests for the V2 agent: local allowlist, runner outcomes, exactly-once and recovery. No network."""
import importlib.util
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rian_v2_agent", HERE / "rian-v2-agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
JOB = "0f8fad5b-d9cb-469f-a165-70867728950e"


class FakeClient:
    def __init__(self, job=None, fail=None):
        self.job, self.fail, self.calls = job, fail, []

    def request(self, method, path, payload=None):
        self.calls.append((path, payload))
        code = self.fail(path) if self.fail else None
        if code:
            raise agent.TransferError(code)
        if path.endswith("/claim"):
            job, self.job = self.job, None
            return {"job": job}
        if path.endswith("/heartbeat"):
            return {"state": "RUNNING", "cancel": False}
        return {"state": payload.get("outcome")}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cfg = {"relay_url": "http://127.0.0.1:9", "device_id": "PC-A", "state_dir": str(self.root / "state"),
                    "allowed_kinds": ["diag.wait", "mail.search"], "mail": {"data_dir": str(self.root / "rian-mail-v2")}}
        self.cfg_path = self.root / "agent.json"
        self.cfg_path.write_text(json.dumps(self.cfg), "utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def job_dir(self, kind, params, deadline=600):
        d = self.root / "state" / "jobs" / JOB
        d.mkdir(parents=True)
        agent.write_json(d / "job.json", {"jobId": JOB, "kind": kind, "params": params, "leaseToken": "t" * 43,
                                          "leaseSeconds": 45, "runDeadline": time.time() + deadline, "claimedAt": time.time() - 60})
        return d


class AllowlistTests(Base):
    def test_local_allowlist_is_independent_of_the_relay(self):
        for kind, params in [("mail.sync", {"days": 1, "maxMessages": 1}), ("diag.wait", {"seconds": 0}), ("diag.wait", {"seconds": 5, "argv": ["cmd"]}),
                             ("mail.search", {"query": "x", "cwd": "C:/"}), ("shell", {}), ("mail.read", {"messageId": "a" * 40})]:
            with self.assertRaises(agent.mail.MailError):
                agent.validate_local(kind, params, self.cfg)
        agent.validate_local("diag.wait", {"seconds": 5}, self.cfg)

    def test_unknown_kind_in_config_is_refused(self):
        self.cfg_path.write_text(json.dumps({**self.cfg, "allowed_kinds": ["run_command"]}), "utf-8")
        with self.assertRaises(SystemExit):
            agent.load_config(self.cfg_path)


class RunnerTests(Base):
    def test_runner_writes_progress_and_result(self):
        d = self.job_dir("diag.wait", {"seconds": 2})
        agent.run_job(d, self.cfg)
        result = agent.read_json(d / "result.json")
        self.assertEqual(result["outcome"], "SUCCEEDED")
        self.assertEqual(json.loads(result["output"])["waited_seconds"], 2)
        self.assertEqual(agent.read_json(d / "progress.json")["stage"], "waiting")

    def test_cancel_file_stops_runner(self):
        d = self.job_dir("diag.wait", {"seconds": 30})
        (d / "cancel").write_text("OWNER_CANCELLED")
        agent.run_job(d, self.cfg)
        self.assertEqual(agent.read_json(d / "result.json")["outcome"], "CANCELLED")

    def test_deadline_reports_timed_out(self):
        d = self.job_dir("diag.wait", {"seconds": 30}, deadline=1)
        agent.run_job(d, self.cfg)
        self.assertEqual(agent.read_json(d / "result.json")["outcome"], "TIMED_OUT")

    def test_mail_errors_are_codes_only(self):
        d = self.job_dir("mail.search", {"query": "견적", "limit": 3})
        agent.run_job(d, self.cfg)
        result = agent.read_json(d / "result.json")
        self.assertEqual(result["outcome"], "FAILED")
        self.assertEqual(json.loads(result["output"]), {"ok": False, "error": "INDEX_NOT_FOUND"})


class SupervisorTests(Base):
    def test_job_id_is_never_executed_twice_on_this_pc(self):
        client = FakeClient({"jobId": JOB, "kind": "diag.wait", "params": {"seconds": 1}, "leaseToken": "t" * 43, "leaseSeconds": 45, "maxRuntimeSeconds": 60})
        sup = agent.Supervisor(self.cfg, self.cfg_path, client)
        sup.remember(JOB)
        self.assertIsNone(sup.claim())
        self.assertEqual(list(sup.active()), [])

    @unittest.skipIf(sys.platform.startswith("win"), "POSIX permissions")
    def test_journal_directories_are_owner_only(self):
        import os
        import stat
        jobs = Path(self.cfg["state_dir"]) / "jobs"
        jobs.mkdir(parents=True)
        os.chmod(jobs, 0o755)  # as left by an older agent version
        client = FakeClient({"jobId": JOB, "kind": "mail.sync", "params": {"days": 1, "maxMessages": 1}, "leaseToken": "t" * 43, "leaseSeconds": 45, "maxRuntimeSeconds": 60})
        sup = agent.Supervisor(self.cfg, self.cfg_path, client)
        self.assertEqual(sup.claim(), JOB)  # rejected locally: journal written, nothing executed
        for path in (sup.state, sup.jobs, sup.jobs / JOB):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700, str(path))
        lock = agent.single_instance(sup.state)
        try:
            self.assertEqual(stat.S_IMODE((sup.state / "supervisor.lock").stat().st_mode), 0o600)
        finally:
            lock.close()

    def test_relay_job_outside_local_allowlist_is_reported_failed_not_run(self):
        client = FakeClient({"jobId": JOB, "kind": "mail.sync", "params": {"days": 1, "maxMessages": 1}, "leaseToken": "t" * 43, "leaseSeconds": 45, "maxRuntimeSeconds": 60})
        sup = agent.Supervisor(self.cfg, self.cfg_path, client)
        self.assertEqual(sup.claim(), JOB)
        sup.supervise(sup.jobs / JOB)
        path, payload = client.calls[-1]
        self.assertTrue(path.endswith("/complete"))
        self.assertEqual(payload["outcome"], "FAILED")
        self.assertIn("KIND_NOT_ALLOWED_ON_THIS_PC", payload["output"])

    def test_restart_with_dead_runner_reports_interrupted_once(self):
        d = self.job_dir("diag.wait", {"seconds": 30})
        client = FakeClient()
        sup = agent.Supervisor(self.cfg, self.cfg_path, client)
        sup.supervise(d)
        path, payload = client.calls[-1]
        self.assertEqual(payload["outcome"], "INTERRUPTED")
        self.assertFalse(d.exists(), "journal removed after the result was accepted")

    def test_result_is_kept_while_relay_is_unreachable(self):
        d = self.job_dir("diag.wait", {"seconds": 1})
        agent.write_json(d / "result.json", {"outcome": "SUCCEEDED", "exitCode": 0, "output": "{}"})
        sup = agent.Supervisor(self.cfg, self.cfg_path, FakeClient(fail=lambda p: "BROKER_UNREACHABLE"))
        with self.assertRaises(agent.TransferError):
            sup.supervise(d)
        self.assertTrue((d / "result.json").exists())
        ok = FakeClient()
        agent.Supervisor(self.cfg, self.cfg_path, ok).supervise(d)
        self.assertEqual(ok.calls[-1][1]["outcome"], "SUCCEEDED")
        self.assertFalse(d.exists())

    def test_own_runner_that_died_without_result_is_reaped_and_reported_interrupted(self):
        import os
        import subprocess
        d = self.job_dir("diag.wait", {"seconds": 30})
        proc = subprocess.Popen([sys.executable, "-c", "pass"])  # exits at once without result.json
        time.sleep(0.5)  # the child has exited but nobody has waited for it yet
        meta = agent.read_json(d / "job.json")
        meta["runnerPid"] = proc.pid
        agent.write_json(d / "job.json", meta)
        if os.name != "nt":
            self.assertTrue(agent.pid_running(proc.pid), "unreaped child is a zombie that still looks alive")
        client = FakeClient()
        sup = agent.Supervisor(self.cfg, self.cfg_path, client)
        sup.children[JOB] = proc
        sup.supervise(d)
        self.assertEqual(client.calls[-1][1]["outcome"], "INTERRUPTED")
        self.assertFalse(agent.pid_running(proc.pid))
        self.assertFalse(d.exists())

    def test_hosting_edge_404_during_relay_outage_is_retried_not_lease_lost(self):
        # Railway answers 404 'Application not found' while the relay deployment is down.
        d = self.job_dir("diag.wait", {"seconds": 30})
        (d / "alive").write_text("1")
        sup = agent.Supervisor(self.cfg, self.cfg_path, FakeClient(fail=lambda p: "BROKER_EDGE_HTTP_404"))
        with self.assertRaises(agent.TransferError):
            sup.supervise(d)
        self.assertFalse((d / "cancel").exists(), "runner must keep working")
        agent.write_json(d / "result.json", {"outcome": "SUCCEEDED", "exitCode": 0, "output": "{}"})
        with self.assertRaises(agent.TransferError):
            sup.supervise(d)
        self.assertTrue((d / "result.json").exists(), "result kept until the relay itself answers")

    def test_client_tells_relay_errors_from_hosting_edge_errors(self):
        import http.server
        import threading
        routes = {
            "/v2/edge": (404, {"x-railway-fallback": "true"}, b'{"status":"error","code":404,"message":"Application not found","request_id":"x"}'),
            "/v2/edge-json": (404, {}, b'{"status":"error","code":404,"message":"Application not found"}'),
            "/v2/proxy": (502, {"content-type": "text/html"}, b"<html>Bad gateway</html>"),
            "/v2/relay404": (404, {}, b'{"error":"NOT_FOUND"}'),
            "/v2/relay409": (409, {}, b'{"error":"LEASE_MISMATCH"}'),
            "/v2/too-large": (413, {}, b""),
        }

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                code, headers, body = routes[self.path]
                self.send_response(code)
                for k, v in {"content-type": "application/json", **headers}.items():
                    self.send_header(k, v)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        client = agent.Client("http://127.0.0.1:%d" % server.server_address[1], "t" * 43, allow_test_loopback=True, timeout=5)
        expect = {"/v2/edge": "BROKER_EDGE_HTTP_404", "/v2/edge-json": "BROKER_EDGE_HTTP_404", "/v2/proxy": "BROKER_EDGE_HTTP_502",
                  "/v2/relay404": "BROKER_HTTP_404", "/v2/relay409": "BROKER_HTTP_409", "/v2/too-large": "BROKER_HTTP_413"}
        for path, code in expect.items():
            with self.assertRaises(agent.TransferError) as ctx:
                client.request("POST", path, {})
            self.assertEqual(str(ctx.exception), code, path)

    def test_lost_lease_signals_runner_to_stop(self):
        d = self.job_dir("diag.wait", {"seconds": 30})
        (d / "alive").write_text("1")
        sup = agent.Supervisor(self.cfg, self.cfg_path, FakeClient(fail=lambda p: "BROKER_HTTP_409" if p.endswith("/heartbeat") else None))
        sup.supervise(d)
        self.assertEqual((d / "cancel").read_text(), "LEASE_LOST")

    def test_oversized_result_is_replaced_once_not_retried_forever(self):
        d = self.job_dir("diag.wait", {"seconds": 1})
        agent.write_json(d / "result.json", {"outcome": "SUCCEEDED", "exitCode": 0, "output": "x"})
        calls = []

        def fail(path):
            calls.append(path)
            return "BROKER_HTTP_413" if len(calls) == 1 else None
        sup = agent.Supervisor(self.cfg, self.cfg_path, FakeClient(fail=fail))
        sup.supervise(d)
        self.assertIn("OUTPUT_TOO_LARGE", agent.read_json(d / "result.json")["output"])
        client = FakeClient()
        agent.Supervisor(self.cfg, self.cfg_path, client).supervise(d)
        self.assertEqual(client.calls[-1][1]["outcome"], "FAILED")
        self.assertFalse(d.exists())

    def test_long_korean_body_fits_relay_request_limit(self):
        cfg = {**self.cfg, "allowed_kinds": ["mail.read"]}
        data = Path(cfg["mail"]["data_dir"])
        store = agent.mail.MailStore(data)
        mid = "d" * 40
        store.root.mkdir(parents=True)
        agent.mail.atomic_write(store.index_path, json.dumps({"version": 2, "account": "e" * 64, "messages": {mid: {"date": "2026-11-20T00:00:00Z", "from": "a", "subject": "s"}}}).encode())
        store.put_body(mid, "한국어 본문 " * 12000)
        d = self.job_dir("mail.read", {"messageId": mid})
        agent.run_job(d, cfg)
        result = agent.read_json(d / "result.json")
        self.assertEqual(result["outcome"], "SUCCEEDED")
        out = json.loads(result["output"])
        self.assertTrue(out["truncated"])
        wire = json.dumps({"leaseToken": "t" * 43, **result}, separators=(",", ":"))
        self.assertLess(len(wire.encode()), 110_000, "complete() request must fit the staging body limit")

    def test_second_supervisor_on_same_state_dir_is_refused(self):
        first = agent.single_instance(self.cfg["state_dir"])
        self.assertIsNotNone(first)
        try:
            self.assertIsNone(agent.single_instance(self.cfg["state_dir"]))
            # A separate process is refused before any token read or network call.
            import subprocess
            p = subprocess.run([sys.executable, str(HERE / "rian-v2-agent.py"), "run", "--config", str(self.cfg_path), "--max-seconds", "1"],
                               capture_output=True, text=True, timeout=20)
            self.assertEqual(p.returncode, agent.ALREADY_RUNNING_EXIT, p.stderr[-300:])
            self.assertIn("AGENT_ALREADY_RUNNING", p.stdout)
        finally:
            first.close()
        again = agent.single_instance(self.cfg["state_dir"])
        self.assertIsNotNone(again)
        again.close()

    def test_windows_safe_process_probe(self):
        import os
        self.assertTrue(agent.pid_running(os.getpid()))
        self.assertFalse(agent.pid_running(0))
        self.assertFalse(agent.pid_running(2 ** 31 - 7))


if __name__ == "__main__":
    unittest.main()
