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
