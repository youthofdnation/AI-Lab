#!/usr/bin/env python3
"""macOS-only tests: no launchd service is started, no network or mailbox is touched."""
import importlib.util
import json
import os
import plistlib
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rian_macos_installer", HERE / "install-v2-agent-macos.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


@unittest.skipUnless(sys.platform == "darwin", "requires macOS")
class MacInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rian-v2-macos-ci-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.home_env = patch.dict(os.environ, {"HOME": str(self.home)})
        self.home_env.start()
        self.addCleanup(self.home_env.stop)
        self.pp = installer.paths()
        secret_dir = self.home / "secrets"
        secret_dir.mkdir(mode=0o700)
        self.secret = secret_dir / "token"
        self.secret.write_text("synthetic-token-not-a-real-key-" + "x" * 40, encoding="utf-8")
        self.secret.chmod(0o600)
        self.config = self.home / "owner-config.json"
        self.cfg = {
            "relay_url": "https://stage.example.test",
            "device_id": "MAC-CI-TEST",
            "state_dir": str(self.pp["state"]),
            "token_file": str(self.secret),
            "allowed_kinds": ["diag.wait"],
            "poll_seconds": 5,
        }
        self.save()

    def save(self):
        self.config.write_text(json.dumps(self.cfg), encoding="utf-8")

    def test_default_status_has_no_side_effect(self):
        self.assertFalse(self.pp["base"].exists())
        info = installer.status(self.pp)
        self.assertFalse(info["installed"])
        self.assertFalse(info["agent_files"])
        self.assertFalse(self.pp["base"].exists())

    def test_prepare_generates_valid_private_plist_and_config(self):
        r = installer.prepare(self.config)
        self.assertTrue(r["prepared"])
        self.assertFalse(r["launchd_started"])
        self.assertFalse(r["mail_enabled"])
        data = plistlib.loads(self.pp["prepared_plist"].read_bytes())
        # Prepare-only must never enable auto-start on the next login.
        self.assertFalse(self.pp["plist"].exists())
        self.assertFalse(self.pp["plist"].parent.exists())
        self.assertFalse(installer.status(self.pp)["installed"])
        self.assertEqual(data["Label"], installer.LABEL)
        self.assertEqual(data["ProgramArguments"][2:], ["run", "--config", str(self.pp["config"])])
        self.assertEqual(data["EnvironmentVariables"], {"PYTHONUNBUFFERED": "1"})
        self.assertNotIn("synthetic-token", str(data))
        self.assertTrue(data["RunAtLoad"])
        self.assertEqual(set(p.name for p in self.pp["agent"].iterdir()), set(installer.FILES))
        for key in ("base", "state", "logs", "agent"):
            self.assertEqual(stat.S_IMODE(self.pp[key].stat().st_mode), 0o700)
        for key in ("config", "prepared_plist"):
            self.assertEqual(stat.S_IMODE(self.pp[key].stat().st_mode), 0o600)
        subprocess.run(["plutil", "-lint", str(self.pp["prepared_plist"])], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertFalse(installer.status(self.pp)["launchd_loaded"])

    def test_install_only_explicitly_activates_and_preserves_launchagents_permissions(self):
        parent = self.pp["plist"].parent
        parent.mkdir(parents=True)
        parent.chmod(0o755)
        with patch.object(installer, "loaded", side_effect=[False, True]), patch.object(installer.subprocess, "run") as runner:
            result = installer.install(self.config)
        self.assertTrue(result["launchd_started"])
        self.assertTrue(self.pp["plist"].exists())
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755)
        self.assertEqual(len(runner.call_args_list), 2)
        self.assertEqual(runner.call_args_list[0].args[0][1], "bootstrap")
        self.assertEqual(runner.call_args_list[1].args[0][1], "kickstart")

    def test_agent_status_from_prepared_directory_never_connects(self):
        installer.prepare(self.config)
        p = subprocess.run(
            [sys.executable, str(self.pp["agent"] / "rian-v2-agent.py"),
             "status", "--config", str(self.pp["config"])],
            check=True, capture_output=True, text=True, timeout=10,
        )
        result = json.loads(p.stdout)
        self.assertEqual(result["device"], "MAC-CI-TEST")
        self.assertEqual(result["allowed_kinds"], ["diag.wait"])
        self.assertEqual(result["journal_jobs"], [])

    def test_homebrew_cellar_python_is_pinned_to_stable_opt_link(self):
        brew = self.home / "brew"
        cellar_bin = brew / "Cellar" / "python@3.14" / "3.14.6" / "bin"
        cellar_bin.mkdir(parents=True)
        (cellar_bin / "python3.14").write_text("", encoding="utf-8")
        (brew / "opt").mkdir()
        (brew / "opt" / "python@3.14").symlink_to("../Cellar/python@3.14/3.14.6")
        (brew / "bin").mkdir()
        (brew / "bin" / "python3").symlink_to("../Cellar/python@3.14/3.14.6/bin/python3.14")
        chosen = installer.stable_python(str(brew / "bin" / "python3"), (3, 14))
        self.assertEqual(chosen, brew.resolve() / "opt" / "python@3.14" / "bin" / "python3.14")
        self.assertNotIn("3.14.6", str(chosen))
        # Without an opt link the real interpreter path is kept.
        (brew / "opt" / "python@3.14").unlink()
        self.assertEqual(installer.stable_python(str(brew / "bin" / "python3"), (3, 14)), (cellar_bin / "python3.14").resolve())

    def test_throttle_leaves_margin_inside_agent_lease(self):
        installer.prepare(self.config)
        data = plistlib.loads(self.pp["prepared_plist"].read_bytes())
        # heartbeat <=15 s + respawn delay + startup must stay well inside the 45 s lease.
        self.assertLessEqual(15 + data["ThrottleInterval"] + 5, 30)
        self.assertEqual(data["ProgramArguments"][0], str(installer.stable_python()))

    def test_rejects_mail_without_explicit_opt_in(self):
        self.cfg["allowed_kinds"] = ["diag.wait", "mail.read"]
        self.save()
        with self.assertRaisesRegex(RuntimeError, "MAIL_DISABLED_FOR_MAC_PILOT"):
            installer.prepare(self.config)
        self.assertFalse(self.pp["plist"].exists())

    def test_rejects_insecure_device_token(self):
        self.secret.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "TOKEN_FILE_PERMISSIONS"):
            installer.prepare(self.config)

    def test_rejects_http_and_test_mode(self):
        self.cfg["relay_url"] = "http://stage.example.test"
        self.save()
        with self.assertRaisesRegex(RuntimeError, "HTTPS_RELAY_ORIGIN_REQUIRED"):
            installer.prepare(self.config)
        self.cfg["relay_url"] = "https://stage.example.test"
        self.cfg["allow_test_loopback"] = True
        self.save()
        with self.assertRaisesRegex(RuntimeError, "TEST_LOOPBACK_DENIED"):
            installer.prepare(self.config)

    def test_rejects_state_directory_outside_private_home(self):
        self.cfg["state_dir"] = str(self.home / "not-the-isolated-agent")
        self.save()
        with self.assertRaisesRegex(RuntimeError, "PRIVATE_STATE_DIR_REQUIRED"):
            installer.prepare(self.config)

    def test_rejects_identity_switch_and_active_journal(self):
        installer.prepare(self.config)
        self.cfg["device_id"] = "DIFFERENT-PC"
        self.save()
        with self.assertRaisesRegex(RuntimeError, "EXISTING_AGENT_IDENTITY_MISMATCH"):
            installer.prepare(self.config)
        self.cfg["device_id"] = "MAC-CI-TEST"
        self.save()
        job = self.pp["state"] / "jobs" / "99999999-9999-9999-9999-999999999999"
        job.mkdir(parents=True)
        with self.assertRaisesRegex(RuntimeError, "ACTIVE_JOB_JOURNAL_PRESENT"):
            installer.prepare(self.config)
        with self.assertRaisesRegex(RuntimeError, "ACTIVE_JOB_JOURNAL_PRESENT"):
            installer.uninstall()


if __name__ == "__main__":
    unittest.main()
