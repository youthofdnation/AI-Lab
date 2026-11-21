#!/usr/bin/env python3
"""RIAN Commander V2 per-user macOS LaunchAgent installer.

No admin rights, listening port, firewall changes, mail access, or secrets in
launchd. Default 'status' is read-only. 'prepare' writes local files but does
not start anything. 'install' is the explicit owner action that starts launchd.
The first Mac pilot is diagnostics-only; mail needs --allow-mail separately.
"""
import argparse
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

LABEL = "company.rian.commander.v2.agent"
FILES = ("rian-v2-agent.py", "rian_mail_index.py", "tenant-artifact-agent.py")
KINDS = {"diag.wait", "mail.sync", "mail.search", "mail.read"}


def paths():
    home = Path.home().resolve()
    base = home / "Library" / "Application Support" / "RIAN-Commander-V2"
    return {
        "home": home,
        "base": base,
        "agent": base / "agent",
        "config": base / "agent.json",
        "state": base / "state",
        "logs": base / "logs",
        "plist": home / "Library" / "LaunchAgents" / (LABEL + ".plist"),
        "prepared_plist": base / "prepared-agent.plist",
    }


def ensure_macos():
    if sys.platform != "darwin":
        raise RuntimeError("MACOS_ONLY")
    if sys.version_info < (3, 10):
        raise RuntimeError("PYTHON_3_10_OR_NEWER_REQUIRED")


def mkdir_private(path):
    if path.is_symlink():
        raise RuntimeError("SYMLINK_DIRECTORY_DENIED")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def atomic_bytes(path, data, mode=0o600):
    fd, temp = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def validate_config(config_path, pp, allow_mail=False):
    file = Path(config_path).expanduser()
    if file.is_symlink() or not file.is_file():
        raise RuntimeError("CONFIG_FILE_REQUIRED")
    cfg = json.loads(file.read_text("utf-8"))
    if not isinstance(cfg, dict):
        raise RuntimeError("INVALID_CONFIG")
    address = cfg.get("relay_url", "")
    parsed = urlsplit(address) if isinstance(address, str) else None
    if (not parsed or parsed.scheme != "https" or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")):
        raise RuntimeError("HTTPS_RELAY_ORIGIN_REQUIRED")
    device = cfg.get("device_id")
    if not isinstance(device, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,128}", device):
        raise RuntimeError("INVALID_DEVICE_ID")
    kinds = cfg.get("allowed_kinds")
    if not isinstance(kinds, list) or not kinds or len(kinds) != len(set(map(str, kinds))) or not all(isinstance(k, str) and k in KINDS for k in kinds):
        raise RuntimeError("INVALID_ALLOWED_KINDS")
    if not allow_mail and (any(k.startswith("mail.") for k in kinds) or cfg.get("mail")):
        raise RuntimeError("MAIL_DISABLED_FOR_MAC_PILOT")
    if cfg.get("allow_test_loopback"):
        raise RuntimeError("TEST_LOOPBACK_DENIED")
    state_dir = cfg.get("state_dir")
    if not isinstance(state_dir, str) or Path(state_dir).expanduser().resolve() != pp["state"]:
        raise RuntimeError("PRIVATE_STATE_DIR_REQUIRED")
    token_file = cfg.get("token_file")
    if not isinstance(token_file, str):
        raise RuntimeError("PRIVATE_TOKEN_FILE_REQUIRED")
    secret = Path(token_file).expanduser()
    if not secret.is_absolute() or secret.is_symlink() or not secret.is_file():
        raise RuntimeError("PRIVATE_TOKEN_FILE_REQUIRED")
    resolved = secret.resolve()
    if not resolved.is_relative_to(pp["home"]):
        raise RuntimeError("TOKEN_FILE_OUTSIDE_HOME")
    info = secret.stat()
    if info.st_uid != os.getuid() or (stat.S_IMODE(info.st_mode) & 0o077):
        raise RuntimeError("TOKEN_FILE_PERMISSIONS")
    if info.st_size < 32 or info.st_size > 4096:
        raise RuntimeError("TOKEN_FILE_SIZE")
    if pp["config"].is_file():
        existing = json.loads(pp["config"].read_text("utf-8"))
        if existing.get("device_id") != device or existing.get("relay_url") != address:
            raise RuntimeError("EXISTING_AGENT_IDENTITY_MISMATCH")
    return cfg


def active_jobs(pp):
    jobs = pp["state"] / "jobs"
    return jobs.is_dir() and any(p.is_dir() for p in jobs.iterdir())


def launch_target():
    return "gui/" + str(os.getuid()) + "/" + LABEL


def loaded():
    if sys.platform != "darwin" or shutil.which("launchctl") is None:
        return False
    result = subprocess.run(["launchctl", "print", launch_target()], capture_output=True, text=True, check=False)
    return result.returncode == 0


def status(pp):
    state = {"platform": sys.platform, "device": None,
             "installed": pp["plist"].is_file(),
             "agent_files": all((pp["agent"] / file).is_file() for file in FILES),
             "launchd_loaded": loaded(), "active_journals": bool(active_jobs(pp))}
    if pp["config"].is_file():
        try:
            cfg = json.loads(pp["config"].read_text("utf-8"))
            state["device"] = cfg.get("device_id")
            state["allowed_kinds"] = cfg.get("allowed_kinds")
        except (ValueError, OSError):
            state["config_error"] = "INVALID_CONFIG"
    return state


def prepare(config_path, allow_mail=False):
    ensure_macos()
    pp = paths()
    if active_jobs(pp):
        raise RuntimeError("ACTIVE_JOB_JOURNAL_PRESENT_DO_NOT_RESTART")
    cfg = validate_config(config_path, pp, allow_mail=allow_mail)
    source = Path(__file__).resolve().parent
    for f in FILES:
        if not (source / f).is_file():
            raise RuntimeError("MISSING_AGENT_FILE_" + f)
    for path in (pp["base"], pp["agent"], pp["state"], pp["logs"]):
        mkdir_private(path)
    for f in FILES:
        atomic_bytes(pp["agent"] / f, (source / f).read_bytes())
    atomic_bytes(pp["config"], json.dumps(cfg, ensure_ascii=False, sort_keys=True).encode("utf-8"))
    for name in ("stdout.log", "stderr.log"):
        path = pp["logs"] / name
        if not path.exists():
            atomic_bytes(path, b"")
        else:
            os.chmod(path, 0o600)
    plist = {
        "Label": LABEL,
        "ProgramArguments": [str(Path(sys.executable).resolve()), str(pp["agent"] / "rian-v2-agent.py"),
                             "run", "--config", str(pp["config"])],
        "WorkingDirectory": str(pp["agent"]),
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 30,
        "ProcessType": "Background",
        "StandardOutPath": str(pp["logs"] / "stdout.log"),
        "StandardErrorPath": str(pp["logs"] / "stderr.log"),
        "EnvironmentVariables": {"PYTHONUNBUFFERED": "1"},
    }
    # 'prepare' must NOT place a plist in ~/Library/LaunchAgents:
    # launchd would otherwise start it automatically at the next login.
    atomic_bytes(pp["prepared_plist"], plistlib.dumps(plist))
    return {"prepared": True, "device": cfg["device_id"], "launchd_started": False, "mail_enabled": allow_mail}


def install(config_path, allow_mail=False):
    pp = paths()
    prepared = prepare(config_path, allow_mail=allow_mail)
    mkdir_private(pp["plist"].parent)
    if loaded():
        subprocess.run(["launchctl", "bootout", launch_target()], check=True)
    atomic_bytes(pp["plist"], pp["prepared_plist"].read_bytes())
    subprocess.run(["launchctl", "bootstrap", "gui/" + str(os.getuid()), str(pp["plist"])], check=True)
    subprocess.run(["launchctl", "kickstart", launch_target()], check=True)
    if not loaded():
        raise RuntimeError("LAUNCHAGENT_NOT_LOADED")
    return {**prepared, "launchd_started": True}


def uninstall():
    ensure_macos()
    pp = paths()
    if active_jobs(pp):
        raise RuntimeError("ACTIVE_JOB_JOURNAL_PRESENT_DO_NOT_STOP")
    if loaded():
        subprocess.run(["launchctl", "bootout", launch_target()], check=True)
    if pp["plist"].exists():
        pp["plist"].unlink()
    # Never delete a token, config, job journal, index, backup or log.
    return {"uninstalled": True, "local_data_preserved": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description="RIAN Commander V2 macOS LaunchAgent installer")
    parser.add_argument("action", nargs="?", default="status", choices=["status", "prepare", "install", "uninstall"])
    parser.add_argument("--config")
    parser.add_argument("--allow-mail", action="store_true", help="Requires separate owner approval; never use for a diagnostics pilot")
    args = parser.parse_args(argv)
    try:
        if args.action == "status":
            result = status(paths())
        elif args.action == "uninstall":
            result = uninstall()
        elif not args.config:
            raise RuntimeError("OWNER_CONFIG_REQUIRED")
        elif args.action == "prepare":
            result = prepare(args.config, args.allow_mail)
        else:
            result = install(args.config, args.allow_mail)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        # Error class/code only; never print configuration, tokens, paths or mail data.
        code = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__.upper()
        print(json.dumps({"ok": False, "error": code if len(code) < 100 else "INSTALL_FAILED"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
