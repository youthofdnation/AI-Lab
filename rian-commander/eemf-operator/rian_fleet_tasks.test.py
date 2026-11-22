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


if __name__ == "__main__":
    unittest.main()
