import importlib.util
import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import rian_fleet_tasks as F  # noqa: E402

_spec = importlib.util.spec_from_file_location("rian_v2_agent", HERE / "rian-v2-agent.py")
A = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(A)
nop = lambda **k: None  # noqa: E731


class CpuBench(unittest.TestCase):
    def test_same_work_unit_gives_the_same_digest_anywhere(self):
        a = F.cpu_bench(3, 1, nop, lambda: False)
        b = F.cpu_bench(3, 1, nop, lambda: False)
        c = F.cpu_bench(4, 1, nop, lambda: False)
        self.assertEqual(a["digest"], b["digest"])
        self.assertNotEqual(a["digest"], c["digest"])
        self.assertTrue(a["ok"] and a["seconds"] > 0)

    def test_cancel_stops_at_a_unit_boundary(self):
        with self.assertRaises(F.FleetCancelled):
            F.cpu_bench(1, 5, nop, lambda: True)


class Inventory(unittest.TestCase):
    def test_nvidia_reports_measured_free_memory_not_a_guess(self):
        from unittest.mock import patch
        rows = "0, Test GPU, 6144, 2000, 4000, 12, 55, 572.83\n1, Unknown GPU, 8192, N/A, N/A, N/A, N/A, 572.83\n"
        with patch.object(F.shutil, "which", return_value="nvidia-smi"), patch.object(F, "_run", side_effect=[rows, "", "CUDA Version: 12.8"]) as run:
            result = F.nvidia_gpus()
        self.assertIn("memory.free", run.call_args_list[0].args[0][1])
        g, unknown = result["gpus"]
        self.assertEqual((g["vram_total_mib"], g["vram_used_mib"], g["vram_free_mib"], g["util_pct"], g["driver"]), (6144, 2000, 4000, 12, "572.83"))
        self.assertIsNone(unknown["vram_free_mib"])
        self.assertIsNone(unknown["vram_used_mib"])
        self.assertIsNone(unknown["util_pct"])

    def test_reads_names_and_numbers_only(self):
        r = F.inventory(nop)
        s = r["snapshot"]
        self.assertTrue(r["ok"])
        for k in ("host", "os", "cpu", "ram", "gpus", "disks", "encryption", "runtimes", "ai_processes"):
            self.assertIn(k, s)
        self.assertGreater(s["cpu"]["logical"], 0)
        self.assertGreater(s["ram"]["total_mib"], 0)
        text = json.dumps(r).lower()
        for bad in ("token", "password", "secret", "commandline", "--api-key"):
            self.assertNotIn(bad, text)
        self.assertTrue(all(isinstance(v, int) for v in s["ai_processes"].values()))


class QloraProbe(unittest.TestCase):
    def test_estimate_is_monotonic_and_plausible(self):
        small = F.qlora_estimate(256, 1, 16, True)
        big = F.qlora_estimate(1024, 1, 16, True)
        nockpt = F.qlora_estimate(1024, 1, 16, False)
        self.assertLess(small["total_estimate_mib"], big["total_estimate_mib"])
        self.assertLess(big["total_estimate_mib"], nockpt["total_estimate_mib"])
        self.assertTrue(3000 < small["weights_nf4_mib"] < 4500)       # ~6.95B non-embedding params at 4 bit
        self.assertEqual(small["lora_params"], 36 * 16 * ((4096 + 4096) * 2 + (4096 + 1024) * 2 + (4096 + 12288) * 3))

    def test_never_measures_without_the_full_stack_or_local_opt_in(self):
        r = F.qlora_probe({"seqLen": 256, "batch": 1, "steps": 1, "rank": 16, "gradCheckpointing": True}, {}, nop, lambda: False)
        self.assertFalse(r["ok"])
        self.assertIn(r["error"], {"NO_NVIDIA_GPU", "PREREQUISITES_MISSING", "MEASUREMENT_NOT_ENABLED_ON_THIS_PC", "GPU_PROTECTED_PROCESS_PRESENT"})
        self.assertNotEqual(r.get("measurement"), {})


class AgentConfig(unittest.TestCase):
    def cfg(self, **extra):
        d = tempfile.mkdtemp()
        c = {"relay_url": "https://x.invalid", "device_id": "pc1", "state_dir": d, "allowed_kinds": ["fleet.inventory"], **extra}
        p = Path(d) / "agent.json"
        p.write_text(json.dumps(c), "utf-8")
        return p

    def test_fleet_kinds_need_this_pcs_own_denylist(self):
        with self.assertRaises(SystemExit) as e:
            A.load_config(self.cfg())
        self.assertEqual(str(e.exception), "CONFIG_FLEET_DENYLIST_REQUIRED")

    def test_a_denied_host_never_starts(self):
        with self.assertRaises(SystemExit) as e:
            A.load_config(self.cfg(fleet={"denied_hosts": [socket.gethostname().upper() + ".local"]}))
        self.assertEqual(str(e.exception), "HOST_DENIED")
        with self.assertRaises(SystemExit):
            A.load_config(self.cfg(device_id="BLOCKED-PC", fleet={"denied_hosts": ["blocked-pc"]}))
        self.assertEqual(A._norm_host("Mac-1.local"), A._norm_host("mac-1.LOCAL.local"))   # macOS names end in .local
        self.assertEqual(A.load_config(self.cfg(fleet={"denied_hosts": ["SOME-OTHER-PC"]}))["device_id"], "pc1")

    def test_runner_gets_an_absolute_config_path(self):
        # 2026-11-22 real Mac run: "--config ../run/agent.json" broke the runner, which starts in the job dir.
        p = self.cfg(fleet={"denied_hosts": ["SOME-OTHER-PC"]})
        rel = Path(__import__("os").path.relpath(p))
        sup = A.Supervisor(A.load_config(p), rel, client=None)
        self.assertTrue(Path(sup.config_path).is_absolute())
        self.assertEqual(Path(sup.config_path), p.resolve())

    def test_local_bounds_are_independent_of_the_server(self):
        c = {"allowed_kinds": ["fleet.cpu_bench", "youngmin.qlora_probe"]}
        A.validate_local("fleet.cpu_bench", {"chunk": 1, "units": 2}, c)
        for bad in ({"chunk": 1}, {"chunk": 1, "units": 999}, {"chunk": 1, "units": True}, {"chunk": 1, "units": 2, "argv": "x"}):
            with self.assertRaises(A.mail.MailError):
                A.validate_local("fleet.cpu_bench", bad, c)
        with self.assertRaises(A.mail.MailError):
            A.validate_local("fleet.gpu_probe", {"mib": 64}, c)              # not allowed on this PC
        with self.assertRaises(A.mail.MailError):
            A.validate_local("youngmin.qlora_probe", {"seqLen": 256, "batch": 1, "steps": 1, "rank": 16, "gradCheckpointing": 1}, c)


class BlobVerify(unittest.TestCase):
    def test_hashes_its_own_store_and_names_a_tampered_file(self):
        import hashlib
        d = Path(tempfile.mkdtemp())
        good = b"public model bytes" * 1000
        (d / ("sha256-" + hashlib.sha256(good).hexdigest())).write_bytes(good)
        bad = b"tampered"
        (d / ("sha256-" + hashlib.sha256(b"original").hexdigest())).write_bytes(bad)
        (d / "README.txt").write_text("not a blob", "utf-8")              # ignored: not content-addressed
        cfg = {"blob_stores": {"models": str(d)}}
        r = F.blob_verify("models", 0, 1, cfg, nop, lambda: False)
        self.assertFalse(r["ok"])
        self.assertEqual((r["files"], r["error"], len(r["mismatched"])), (2, "HASH_MISMATCH", 1))
        halves = [F.blob_verify("models", i, 2, cfg, nop, lambda: False)["files"] for i in (0, 1)]
        self.assertEqual(sum(halves), 2)                                   # shards partition the store
        with self.assertRaises(F.FleetError):
            F.blob_verify("elsewhere", 0, 1, cfg, nop, lambda: False)      # a store this PC did not configure
        hf = Path(tempfile.mkdtemp())                                      # Hugging Face layout: models--x/blobs/<hex>
        (hf / "models--a--b" / "blobs").mkdir(parents=True)
        (hf / "models--a--b" / "blobs" / hashlib.sha256(good).hexdigest()).write_bytes(good)
        (hf / "models--a--b" / "blobs" / ("0" * 40)).write_bytes(b"git sha1 named small file")   # not sha256: skipped
        r2 = F.blob_verify("both", 0, 1, {"blob_stores": {"both": [str(hf), str(d)]}}, nop, lambda: False)
        self.assertEqual((r2["files"], len(r2["mismatched"])), (3, 1))

    def test_agent_bounds_for_the_store_name(self):
        c = {"allowed_kinds": ["fleet.blob_verify"]}
        A.validate_local("fleet.blob_verify", {"store": "ollama-c", "shard": 0, "shards": 2}, c)
        for bad in ({"store": "C:\RIAN", "shard": 0, "shards": 1}, {"store": "ok", "shard": 0, "shards": 99}, {"store": "ok", "shard": 0}):
            with self.assertRaises(A.mail.MailError):
                A.validate_local("fleet.blob_verify", bad, c)


class OwnerCli(unittest.TestCase):
    def test_inventory_cli_writes_one_json_and_reads_nothing_secret(self):
        out = Path(tempfile.mkdtemp()) / "inv.json"
        self.assertEqual(F._cli(["inventory", "--out", str(out)]), 0)
        d = json.loads(out.read_text("utf-8"))
        self.assertTrue(d["ok"]) and self.assertIn("snapshot", d)
        self.assertNotIn("token", out.read_text("utf-8").lower())

    @unittest.skipUnless(sys.platform == "win32", "Windows scheduled tasks")
    def test_security_inventory_is_read_only_metadata(self):
        r = F.security_inventory()
        self.assertTrue(r["ok"])
        for k in ("tasks", "gpu_engine_top", "defender", "listening"):
            self.assertIn(k, r["security"])


class TestShard(unittest.TestCase):
    def repo(self):
        import subprocess
        d = Path(tempfile.mkdtemp())
        (d / "t").mkdir()
        (d / "t" / "a_ok.test.py").write_text("print('ok')" + chr(10), "utf-8")
        (d / "t" / "b_ok.test.py").write_text("print('ok')" + chr(10), "utf-8")
        (d / "t" / "c_fail.test.py").write_text("raise SystemExit(3)" + chr(10), "utf-8")
        g = ["git", "-C", str(d), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
        subprocess.run(["git", "init", "-q", str(d)], check=True)
        subprocess.run(g + ["add", "."], check=True)
        subprocess.run(g + ["commit", "-q", "-m", "t"], check=True)
        head = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        cfg = {"test_suites": {"demo": {"repo": str(d), "cwd": "t", "glob": "*.test.py", "command": [sys.executable], "per_file": True}}}
        return d, head, cfg

    def test_runs_only_on_the_named_clean_commit_and_shards_partition(self):
        d, head, cfg = self.repo()
        r = [F.test_shard("demo", head, i, 2, cfg, nop, lambda: False) for i in (0, 1)]
        self.assertEqual(sum(x["files"] for x in r), 3)
        self.assertEqual([x["failed_files"] for x in r if not x["ok"]], [["c_fail.test.py"]])
        self.assertEqual(F.test_shard("demo", "0" * 40, 0, 1, cfg, nop, lambda: False)["error"], "CHECKOUT_NOT_AT_COMMIT")
        (d / "t" / "a_ok.test.py").write_text("print('changed')" + chr(10), "utf-8")
        self.assertEqual(F.test_shard("demo", head, 0, 1, cfg, nop, lambda: False)["error"], "CHECKOUT_HAS_LOCAL_CHANGES")
        with self.assertRaises(F.FleetError):
            F.test_shard("other", head, 0, 1, cfg, nop, lambda: False)

    def test_agent_bounds_for_the_commit(self):
        c = {"allowed_kinds": ["dev.test_shard"]}
        A.validate_local("dev.test_shard", {"suite": "demo", "commit": "a" * 40, "shard": 0, "shards": 2}, c)
        for bad in ({"suite": "demo", "commit": "HEAD", "shard": 0, "shards": 2}, {"suite": "demo", "commit": "a" * 40, "shard": 0}):
            with self.assertRaises(A.mail.MailError):
                A.validate_local("dev.test_shard", bad, c)



class Memory(unittest.TestCase):
    # Measured 2026-11-22 on a 32 GB fleet PC: under 1 GB available while its own services ran.
    TIGHT = {"total_mib": 32133, "available_mib": 962}

    def test_pressure_rule_reads_every_os_signal(self):
        self.assertEqual(F.classify_pressure(32133, 962), ("high", ["LOW_AVAILABLE"]))
        self.assertEqual(F.classify_pressure(32108, 8110, commit_pct=80.2), ("normal", []))        # another 32 GB PC the same day
        self.assertEqual(F.classify_pressure(32108, 8110, commit_pct=93.0)[1], ["COMMIT_HIGH"])
        self.assertEqual(F.classify_pressure(65536, 20000, os_level=2)[1], ["OS_PRESSURE"])
        self.assertEqual(F.classify_pressure(16000, 9000, psi_some_avg10=12.5)[1], ["PSI_STALLS"])
        self.assertEqual(F.classify_pressure(4096, 900)[0], "high")                                 # floor is at least 1 GiB

    def test_this_pc_measures_itself(self):
        st = F.memory_state()
        self.assertIn(st["pressure"], ("normal", "high"))
        self.assertGreater(st["total_mib"], 0)
        self.assertTrue(0 < st["available_mib"] <= st["total_mib"])

    def test_under_pressure_only_inventory_runs(self):
        # owner, 2026-11-22: with 0.94 GiB available, hold real work and allow read-only inventory only
        st = dict(self.TIGHT)
        st["pressure"], st["pressure_reasons"] = F.classify_pressure(st["total_mib"], st["available_mib"])
        self.assertIsNone(F.memory_hold("fleet.inventory", 4096, st))
        self.assertEqual(F.memory_hold("fleet.cpu_bench", 1024, st)["error"], "LOCAL_MEMORY_HOLD")
        for kind in ("fleet.cpu_bench", "fleet.blob_verify", "dev.test_shard", "fleet.gpu_probe", "youngmin.qlora_probe"):
            self.assertEqual(F.memory_hold(kind, 512, st)["error"], "LOCAL_MEMORY_PRESSURE", kind)
        recovered = {"total_mib": 32133, "available_mib": 6000}
        recovered["pressure"], _ = F.classify_pressure(recovered["total_mib"], recovered["available_mib"])
        self.assertIsNone(F.memory_hold("fleet.cpu_bench", 1024, recovered))                    # CPU work resumes by itself
        self.assertEqual(F.memory_hold("fleet.cpu_bench", 512, {"available_mib": None})["error"], "LOCAL_MEMORY_UNKNOWN")
        self.assertIsNone(F.memory_hold("dev.test_shard", 1024, {"total_mib": 32108, "available_mib": 8110, "pressure": "normal"}))

    def test_fleet_work_runs_below_normal_priority(self):
        import subprocess
        probe = ("import os,sys,ctypes; sys.path.insert(0, sys.argv[1]); import rian_fleet_tasks as F; ok = F.lower_priority()\n"
                 "if F.WIN:\n k = ctypes.WinDLL('kernel32'); k.GetCurrentProcess.restype = ctypes.c_void_p\n"
                 " k.GetPriorityClass.argtypes = [ctypes.c_void_p]; print(ok, k.GetPriorityClass(k.GetCurrentProcess()) == 0x4000)\n"
                 "else:\n print(ok, os.getpriority(os.PRIO_PROCESS, 0) >= 10)\n")
        out = subprocess.run([sys.executable, "-c", probe, str(HERE)], capture_output=True, text=True, timeout=60).stdout.split()
        self.assertEqual(out, ["True", "True"])

    def test_the_agent_refuses_before_any_work_and_says_why(self):
        import time
        d = Path(tempfile.mkdtemp())
        A.write_json(d / "job.json", {"jobId": "j1", "kind": "fleet.cpu_bench", "params": {"chunk": 1, "units": 1},
                                      "runDeadline": time.time() + 60})
        cfg = {"allowed_kinds": ["fleet.cpu_bench"], "fleet": {"denied_hosts": ["SOME-OTHER-PC"], "low_priority": False,
                                                               "min_available_mib": 1 << 30}}
        A.run_job(d, cfg)
        r = A.read_json(d / "result.json")
        out = json.loads(r["output"])
        self.assertEqual((r["outcome"], out["error"]), ("FAILED", "LOCAL_MEMORY_HOLD"))
        self.assertNotIn("digest", out)                                   # nothing was computed
        self.assertEqual(out["memory"]["min_available_mib"], 1 << 30)
        cfg["fleet"]["min_available_mib"] = 0
        A.run_job(d, cfg)
        self.assertEqual(A.read_json(d / "result.json")["outcome"], "SUCCEEDED")


if __name__ == "__main__":
    unittest.main()
