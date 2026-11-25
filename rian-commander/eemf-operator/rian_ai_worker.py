"""Fixed, locally configured SALPION Mac detector lifecycle for Commander V2.

The relay supplies only a job kind. It cannot supply code, paths, arguments,
weights, frames, credentials, or network destinations. This module never edits
Tailscale/Serve, firewall rules, or the Commander's own service.
"""
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


class WorkerError(Exception):
    pass


def _file(path, *, private=False, allow_symlink=False):
    p = Path(path)
    if not p.is_absolute() or (p.is_symlink() and not allow_symlink) or not p.is_file():
        raise WorkerError("WORKER_CONFIG_FILE_INVALID")
    if private:
        info = p.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise WorkerError("WORKER_PRIVATE_FILE_PERMISSIONS")
    return p


def _sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _spec(fleet, *, verify_artifacts=False):
    spec = fleet.get("ai_worker")
    if sys.platform != "darwin" or not isinstance(spec, dict) or set(spec) != {
            "python", "script", "script_sha256", "weights", "weights_sha256",
            "token_file", "state_file", "record_file", "log_file"}:
        raise WorkerError("MAC_WORKER_NOT_CONFIGURED")
    if not all(isinstance(value, str) and value for value in spec.values()):
        raise WorkerError("WORKER_CONFIG_FILE_INVALID")
    paths = [Path(spec[k]) for k in ("python", "script", "weights", "token_file", "state_file", "record_file", "log_file")]
    if not all(p.is_absolute() for p in paths) or len({str(p) for p in paths}) != len(paths):
        raise WorkerError("WORKER_STATE_PATH_INVALID")
    python = _file(spec["python"], allow_symlink=True) if verify_artifacts else paths[0]  # venv/bin/python is normally a symlink
    script = _file(spec["script"]) if verify_artifacts else paths[1]
    weights = _file(spec["weights"]) if verify_artifacts else paths[2]
    token = _file(spec["token_file"], private=True)
    for key, path in (("script_sha256", script), ("weights_sha256", weights)):
        value = spec[key]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) or (verify_artifacts and _sha(path) != value):
            raise WorkerError("WORKER_ARTIFACT_SHA_MISMATCH")
    if not 32 <= len(token.read_text("utf-8").strip()) <= 256:
        raise WorkerError("WORKER_TOKEN_INVALID")
    for key in ("state_file", "record_file", "log_file"):
        p = Path(spec[key])
        if (p.is_symlink() or not p.parent.is_dir() or p.parent.is_symlink() or
                p.parent.stat().st_uid != os.getuid() or stat.S_IMODE(p.parent.stat().st_mode) & 0o077):
            raise WorkerError("WORKER_STATE_PATH_INVALID")
    return {**spec, "python": str(python), "script": str(script), "weights": str(weights)}


def _read(path):
    try:
        return json.loads(Path(path).read_text("utf-8"))
    except (OSError, ValueError):
        return None


def _process(pid):
    if not isinstance(pid, int) or pid <= 0:
        return None
    p = subprocess.run(["ps", "-p", str(pid), "-o", "lstart=", "-o", "command="], capture_output=True, text=True, timeout=3)
    return p.stdout.strip() if p.returncode == 0 else None


def _owned(spec, record):
    if not isinstance(record, dict):
        return False
    info = _process(record.get("pid"))
    return bool(info and info[:24] == record.get("started") and spec["script"] in info and spec["state_file"] in info)


def _status(spec):
    record = _read(spec["record_file"])
    if record is None:
        return {"ok": True, "state": "UNREGISTERED" if not Path(spec["state_file"]).exists() else "UNMANAGED_STATE"}
    if not _owned(spec, record):
        return {"ok": True, "state": "STALE_OR_UNOWNED_PROCESS"}
    state = _read(spec["state_file"])
    if not isinstance(state, dict) or state.get("schema") != "SALPION_MAC_DETECTOR_V1" or state.get("model_sha256") != spec["weights_sha256"]:
        return {"ok": True, "state": "STARTING_OR_UNHEALTHY"}
    port = state.get("port")
    if not isinstance(port, int) or not 1 <= port <= 65535 or state.get("host") != "127.0.0.1":
        return {"ok": True, "state": "INVALID_WORKER_BINDING"}
    token = _file(spec["token_file"], private=True).read_text("utf-8").strip()
    request = urllib.request.Request(f"http://127.0.0.1:{port}/v1/health", headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            health = json.load(response)
    except (OSError, ValueError):
        return {"ok": True, "state": "UNHEALTHY"}
    if health.get("schema") != "salpion-remote-detect-v1" or health.get("model") != "rfdetr-nano" or health.get("weights_sha256") != spec["weights_sha256"]:
        return {"ok": True, "state": "IDENTITY_MISMATCH"}
    return {"ok": True, "state": "READY", "model": "rfdetr-nano", "weights_sha256": spec["weights_sha256"],
            "device": health.get("device"), "port": port, "pid": record["pid"],
            "accepted_source_kinds": health.get("accepted_source_kinds", [])}


def status(fleet):
    return _status(_spec(fleet))


def start(fleet, progress=lambda **kwargs: None, cancelled=lambda: False):
    spec = _spec(fleet, verify_artifacts=True)
    if Path(spec["record_file"]).exists() or Path(spec["state_file"]).exists():
        current = _status(spec)
        if current.get("state") == "READY":
            return current
        raise WorkerError("WORKER_EXISTING_STATE_REQUIRES_REVIEW")
    argv = [spec["python"], spec["script"], "--weights", spec["weights"], "--expected-sha256",
            spec["weights_sha256"], "--variant", "nano", "--state", spec["state_file"],
            "--token-file", spec["token_file"], "--max-batch", "4", "--max-threads", "4",
            "--mps-memory-fraction", "0.3"]
    log = Path(spec["log_file"])
    fd = os.open(log, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    os.fchmod(fd, 0o600)
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=fd, stderr=fd, start_new_session=True, close_fds=True)
    finally:
        os.close(fd)
    process = None
    for _ in range(30):
        process = _process(child.pid)
        if process and spec["script"] in process:
            break
        if child.poll() is not None:
            raise WorkerError("WORKER_START_FAILED")
        time.sleep(0.1)
    if not process:
        raise WorkerError("WORKER_PROCESS_IDENTITY_UNKNOWN")
    record_path = Path(spec["record_file"])
    fd = os.open(record_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"pid": child.pid, "started": process[:24]}, f)
    progress(stage="loading_model", percent=20)
    try:
        for _ in range(120):
            if cancelled():
                raise WorkerError("WORKER_START_CANCELLED")
            current = _status(spec)
            if current.get("state") == "READY":
                return current
            if child.poll() is not None:
                raise WorkerError("WORKER_START_FAILED")
            time.sleep(0.25)
        raise WorkerError("WORKER_START_TIMEOUT")
    except WorkerError:
        # A cancelled/failed start must not leave a new persistent worker behind.
        if child.poll() is None and _owned(spec, _read(record_path)):
            child.send_signal(signal.SIGINT)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass  # never force-kill; the owner can inspect this exact process
        if child.poll() is not None:
            record_path.unlink(missing_ok=True)
            Path(spec["state_file"]).unlink(missing_ok=True)
        raise


def stop(fleet):
    spec = _spec(fleet)
    record = _read(spec["record_file"])
    if not _owned(spec, record):
        raise WorkerError("WORKER_NOT_OWNED_OR_NOT_RUNNING")
    os.kill(record["pid"], signal.SIGINT)
    for _ in range(50):
        if _process(record["pid"]) is None:
            Path(spec["record_file"]).unlink()
            Path(spec["state_file"]).unlink(missing_ok=True)
            return {"ok": True, "state": "STOPPED", "pid": record["pid"]}
        time.sleep(0.2)
    raise WorkerError("WORKER_STOP_TIMEOUT_MANUAL_REVIEW")
