#!/usr/bin/env python3
"""
RIAN Commander V2 long-running job agent (outbound HTTPS only, no listener).

  python rian-v2-agent.py run --config agent.json        # supervisor loop
  python rian-v2-agent.py status --config agent.json     # local doctor, no network

The relay only ever sends (kind, bounded params). This agent keeps its own
local allowlist (config "allowed_kinds") and builds every operation itself:
no argv, shell, path or credential is accepted from the server.

Durability
  Each claimed job gets a journal directory. The work runs in a detached
  runner process that keeps going if the supervisor restarts, writes progress
  and finally result.json atomically. A restarted supervisor finds the journal,
  resumes heartbeats and reports the result ("automatic result collection").
  If the runner died without a result, the job is reported INTERRUPTED and is
  never re-executed locally. A job id is executed at most once per PC.
  While the relay is unreachable (e.g. redeploy) the supervisor keeps the work
  running and retries heartbeats/results with backoff.
"""
import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import rian_mail_index as mail  # noqa: E402  (shipped next to this file)

_spec = importlib.util.spec_from_file_location("rian_tenant_artifact_agent", HERE / "tenant-artifact-agent.py")
_artifact = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_artifact)
Client, TransferError = _artifact.Client, _artifact.TransferError

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
KNOWN_KINDS = {"mail.sync", "mail.search", "mail.read", "mail.status", "mail.recent", "diag.wait"}
MAX_OUTPUT = 96 * 1024
# The result travels as an ASCII-escaped JSON string (Korean = 6 bytes/char) inside a
# request the relay caps at 110,000 bytes, so bound the *wire* size, not the UTF-8 size.
MAX_WIRE = 90_000
ALIVE_STALE_SECONDS = 20
ALREADY_RUNNING_EXIT = 75  # EX_TEMPFAIL: another supervisor already owns this state directory


def log(event, **fields):
    # Ids, kinds and states only. Never params, mail data, tokens or paths.
    print(json.dumps({"event": event, "at": int(time.time()), **fields}), flush=True)


def write_json(path, value):
    mail.atomic_write(path, json.dumps(value, ensure_ascii=False).encode("utf-8"))


def read_json(path):
    try:
        return json.loads(Path(path).read_text("utf-8"))
    except (OSError, ValueError):
        return None


def load_config(path):
    cfg = json.loads(Path(path).read_text("utf-8"))
    for key in ("relay_url", "device_id", "state_dir", "allowed_kinds"):
        if key not in cfg:
            raise SystemExit("CONFIG_MISSING_" + key.upper())
    if not set(cfg["allowed_kinds"]) <= KNOWN_KINDS:
        raise SystemExit("CONFIG_UNKNOWN_KIND")
    return cfg


def device_token(cfg):
    token = os.environ.get("RIAN_V2_DEVICE_TOKEN")
    if not token and cfg.get("token_file"):
        token = Path(cfg["token_file"]).read_text("utf-8").strip()
    if not token:
        raise SystemExit("DEVICE_TOKEN_MISSING")
    return token


def validate_local(kind, params, cfg):
    """Second, independent allowlist on the PC (defence against a compromised relay)."""
    if kind not in cfg["allowed_kinds"] or not isinstance(params, dict):
        raise mail.MailError("KIND_NOT_ALLOWED_ON_THIS_PC")
    keys = set(params)
    if kind == "diag.wait":
        if keys != {"seconds"} or not isinstance(params["seconds"], int) or not 1 <= params["seconds"] <= 900:
            raise mail.MailError("INVALID_PARAMS")
    elif kind == "mail.sync":
        if keys != {"days", "maxMessages"}:
            raise mail.MailError("INVALID_PARAMS")
        mail._bounded_int(params["days"], 1, mail.MAX_SYNC_DAYS, "SYNC_SCOPE_EXCEEDED")
        mail._bounded_int(params["maxMessages"], 1, mail.MAX_SYNC_MESSAGES, "SYNC_SCOPE_EXCEEDED")
    elif kind == "mail.search":
        if not keys <= {"query", "limit"} or "query" not in keys:
            raise mail.MailError("INVALID_PARAMS")
    elif kind == "mail.status":
        if keys:
            raise mail.MailError("INVALID_PARAMS")
        if not re.fullmatch(r"[a-f0-9]{64}", str((cfg.get("mail") or {}).get("account_fingerprint", ""))):
            raise mail.MailError("MAIL_ACCOUNT_PIN_REQUIRED")
    elif kind == "mail.recent":
        if not keys <= {"days", "limit", "offset", "folder", "sender", "recipient", "query"} or "days" not in keys:
            raise mail.MailError("INVALID_PARAMS")
        if not re.fullmatch(r"[a-f0-9]{64}", str((cfg.get("mail") or {}).get("account_fingerprint", ""))):
            raise mail.MailError("MAIL_ACCOUNT_PIN_REQUIRED")
        mail.validate_recent_params(**params)
    elif kind == "mail.read":
        if keys != {"messageId"} or not mail.MESSAGE_ID.fullmatch(str(params["messageId"])):
            raise mail.MailError("INVALID_MESSAGE_ID")


# ------------------------------------------------------------------ runner
def run_job(job_dir, cfg):
    job_dir = Path(job_dir)
    job = read_json(job_dir / "job.json")
    stop = threading.Event()

    def keep_alive():
        while not stop.is_set():
            try:
                (job_dir / "alive").write_text(str(os.getpid()))
            except OSError:
                pass
            stop.wait(2)

    threading.Thread(target=keep_alive, daemon=True).start()
    deadline = job["runDeadline"]

    def progress(stage=None, percent=None, done=None, total=None):
        value = {k: v for k, v in {"stage": stage, "percent": percent, "done": done, "total": total}.items() if v is not None}
        write_json(job_dir / "progress.json", value)

    def cancelled():
        return (job_dir / "cancel").exists() or time.time() >= deadline

    outcome, code, output = "FAILED", 1, {"ok": False, "error": "UNEXPECTED"}
    try:
        validate_local(job["kind"], job["params"], cfg)
        params = job["params"]
        if job["kind"] == "diag.wait":
            total = params["seconds"]
            start = time.time()
            for i in range(total):
                if cancelled():
                    raise mail.MailCancelled("CANCELLED")
                progress(stage="waiting", percent=int(100 * i / total), done=i, total=total)
                time.sleep(max(0.0, start + i + 1 - time.time()))
            output = {"ok": True, "waited_seconds": total, "runner_pid": os.getpid()}
        else:
            mcfg = cfg.get("mail") or {}
            data_dir = mcfg.get("data_dir")
            if not data_dir:
                raise mail.MailError("MAIL_DATA_DIR_REQUIRED")
            account_pin = mcfg.get("account_fingerprint")
            if account_pin is not None:
                mail.verify_mail_account(data_dir, account_pin)
            if job["kind"] == "mail.sync":
                source = mail.source_from_config(mcfg.get("source"))
                if account_pin is not None and mail.account_fingerprint(source.account) != account_pin:
                    raise mail.MailError("ACCOUNT_MISMATCH")
                output = mail.sync(data_dir, source, params["days"], params["maxMessages"],
                                   legacy_index=mcfg.get("legacy_index"), progress=progress, should_cancel=cancelled)
            elif job["kind"] == "mail.status":
                output = mail.status(data_dir, expected_account_fingerprint=account_pin)
            elif job["kind"] == "mail.recent":
                output = mail.recent(data_dir, expected_account_fingerprint=account_pin, **params)
            elif job["kind"] == "mail.search":
                output = mail.search(data_dir, params["query"], params.get("limit", 20))
            else:
                limit = mail.MAX_BODY_RETURN_BYTES
                output = mail.read_message(data_dir, params["messageId"], max_bytes=limit)
                while len(json.dumps(json.dumps(output, ensure_ascii=False))) > MAX_WIRE and limit > 1024:
                    limit //= 2
                    output = mail.read_message(data_dir, params["messageId"], max_bytes=limit)
        outcome, code = "SUCCEEDED", 0
    except mail.MailCancelled:
        outcome = "TIMED_OUT" if time.time() >= deadline else "CANCELLED"
        code, output = 130, {"ok": False, "error": outcome}
    except mail.MailError as err:
        code, output = 2, {"ok": False, "error": str(err)}
    except Exception as err:  # noqa: BLE001 - only the exception type is reported
        code, output = 1, {"ok": False, "error": "RUNNER_" + type(err).__name__.upper()}
    text = json.dumps(output, ensure_ascii=False)
    if len(text.encode("utf-8")) > MAX_OUTPUT or len(json.dumps(text)) > MAX_WIRE:
        text = json.dumps({"ok": False, "error": "OUTPUT_TOO_LARGE"})
        outcome, code = "FAILED", 3
    write_json(job_dir / "result.json", {"outcome": outcome, "exitCode": code, "output": text})
    stop.set()
    return 0


# ------------------------------------------------------------------ supervisor
def pid_running(pid):
    if not isinstance(pid, int) or pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = wintypes.HANDLE
        handle = kernel.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            ok = kernel.GetExitCodeProcess(handle, ctypes.byref(code))
            return bool(ok) and code.value == 259  # STILL_ACTIVE
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)  # POSIX only: signal 0 does not terminate
        return True
    except OSError:
        return False


def private_dir(path):
    """Create the directory (or tighten one left by an older agent) as owner-only on POSIX."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        os.chmod(path, 0o700)
    return path


def single_instance(state_dir):
    """Exclusive, non-blocking lock so two supervisors never share one journal.

    The OS releases it when the process exits, including SIGKILL/TerminateProcess.
    Python descriptors are non-inheritable and the runner is spawned with
    close_fds=True, so a detached runner never keeps the lock across a restart.
    Returns the open lock file (keep a reference) or None if another supervisor holds it.
    """
    state = private_dir(state_dir)
    fd = os.open(state / "supervisor.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
    handle = os.fdopen(fd, "r+b")
    try:
        if os.name == "nt":
            import msvcrt
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    return handle


class Supervisor:
    def __init__(self, cfg, config_path, client):
        self.cfg, self.config_path, self.client = cfg, str(config_path), client
        self.state = Path(cfg["state_dir"])
        self.jobs = self.state / "jobs"
        private_dir(self.state)
        private_dir(self.jobs)
        self.seen_file = self.state / "executed-job-ids.json"
        self.backoff = 1
        # Runners started by THIS supervisor are its children: they must be reaped, or a runner that
        # died without a result stays a zombie that pid_running() reports as alive forever.
        self.children, self.exited = {}, set()

    def reap(self):
        for job_id, proc in list(self.children.items()):
            if proc.poll() is not None:
                del self.children[job_id]
                self.exited.add(job_id)

    def executed(self):
        return set(read_json(self.seen_file) or [])

    def remember(self, job_id):
        ids = list(self.executed() | {job_id})[-500:]
        write_json(self.seen_file, ids)

    def spawn(self, job_dir):
        args = [sys.executable, str(Path(__file__).resolve()), "run-job", "--job-dir", str(job_dir), "--config", self.config_path]
        kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "close_fds": True, "cwd": str(job_dir)}
        if os.name == "nt":
            kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        proc = subprocess.Popen(args, **kwargs)
        self.children[job_dir.name] = proc
        meta = read_json(job_dir / "job.json")
        meta["runnerPid"] = proc.pid
        write_json(job_dir / "job.json", meta)
        return proc

    def claim(self):
        reply = self.client.request("POST", "/v2/agent/claim", {"deviceId": self.cfg["device_id"]})
        job = reply.get("job")
        if not job:
            return None
        job_id = job.get("jobId", "")
        if not UUID.fullmatch(job_id) or job_id in self.executed():
            # Exactly-once on this PC: never execute an id twice, even if the relay misbehaves.
            log("JOB_REFUSED_DUPLICATE", job=job_id)
            return None
        job_dir = self.jobs / job_id
        job_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        record = {"jobId": job_id, "kind": job["kind"], "params": job["params"], "leaseToken": job["leaseToken"],
                  "leaseSeconds": job["leaseSeconds"], "runDeadline": time.time() + job["maxRuntimeSeconds"], "claimedAt": time.time()}
        try:
            validate_local(job["kind"], job["params"], self.cfg)
        except mail.MailError as err:
            write_json(job_dir / "job.json", record)
            write_json(job_dir / "result.json", {"outcome": "FAILED", "exitCode": 2, "output": json.dumps({"ok": False, "error": str(err)})})
            self.remember(job_id)
            log("JOB_REJECTED_LOCALLY", job=job_id, kind=job["kind"])
            return job_id
        write_json(job_dir / "job.json", record)
        self.remember(job_id)
        self.spawn(job_dir)
        log("JOB_STARTED", job=job_id, kind=job["kind"])
        return job_id

    def supervise(self, job_dir):
        job = read_json(job_dir / "job.json")
        if not job:
            shutil.rmtree(job_dir, ignore_errors=True)
            return
        path = "/v2/agent/jobs/" + job["jobId"]
        result = read_json(job_dir / "result.json")
        if result is None:
            alive = job_dir / "alive"
            fresh = alive.exists() and time.time() - alive.stat().st_mtime < ALIVE_STALE_SECONDS
            self.reap()
            gone = job["jobId"] in self.exited or not pid_running(job.get("runnerPid"))
            if not fresh and gone and time.time() - job.get("claimedAt", 0) > 10:
                result = {"outcome": "INTERRUPTED", "exitCode": -1, "output": json.dumps({"ok": False, "error": "RUNNER_LOST_DURING_AGENT_RESTART"})}
                write_json(job_dir / "result.json", result)
                log("JOB_INTERRUPTED", job=job["jobId"])
        if result is not None:
            try:
                self.client.request("POST", path + "/complete", {"leaseToken": job["leaseToken"], **result})
                log("JOB_REPORTED", job=job["jobId"], outcome=result["outcome"])
            except TransferError as err:
                small = {"outcome": "FAILED", "exitCode": 3, "output": json.dumps({"ok": False, "error": "OUTPUT_TOO_LARGE"})}
                if str(err) == "BROKER_HTTP_413" and result != small:
                    # Never loop on an oversized result: replace it once with a small, explicit failure.
                    write_json(job_dir / "result.json", small)
                    log("JOB_RESULT_TOO_LARGE", job=job["jobId"])
                    return
                if str(err) in ("BROKER_HTTP_409", "BROKER_HTTP_404", "BROKER_HTTP_400", "BROKER_HTTP_413"):
                    log("JOB_RESULT_REFUSED", job=job["jobId"], code=str(err))
                else:
                    raise  # relay unreachable: keep journal, retry later
            shutil.rmtree(job_dir, ignore_errors=True)
            return
        due = job.get("nextHeartbeat", 0)
        if time.time() < due:
            return
        progress = read_json(job_dir / "progress.json") or {}
        try:
            reply = self.client.request("POST", path + "/heartbeat", {"leaseToken": job["leaseToken"], "progress": progress})
            if reply.get("cancel"):
                (job_dir / "cancel").write_text(str(reply.get("reason") or "CANCEL"))
        except TransferError as err:
            if str(err) in ("BROKER_HTTP_409", "BROKER_HTTP_404"):
                # Relay no longer holds this lease: stop the work; the result is still reported once.
                (job_dir / "cancel").write_text("LEASE_LOST")
            else:
                raise
        job["nextHeartbeat"] = time.time() + max(2, min(15, job["leaseSeconds"] // 3))
        write_json(job_dir / "job.json", job)

    def active(self):
        return sorted(p for p in self.jobs.iterdir() if p.is_dir())

    def loop(self, poll_seconds=5, max_seconds=None):
        started = time.time()
        log("AGENT_STARTED", device=self.cfg["device_id"], recovered=len(self.active()))
        while max_seconds is None or time.time() - started < max_seconds:
            try:
                self.reap()
                for job_dir in self.active():
                    self.supervise(job_dir)
                if not self.active():
                    if self.claim():
                        continue
                self.backoff = 1
                time.sleep(1 if self.active() else poll_seconds)
            except TransferError as err:
                log("RELAY_UNAVAILABLE", code=str(err), retry_in=self.backoff)
                time.sleep(self.backoff)
                self.backoff = min(30, self.backoff * 2)


def status(cfg):
    state = Path(cfg["state_dir"]) / "jobs"
    jobs = [p.name for p in state.iterdir() if p.is_dir()] if state.exists() else []
    out = {"device": cfg["device_id"], "allowed_kinds": cfg["allowed_kinds"], "journal_jobs": jobs}
    if (cfg.get("mail") or {}).get("data_dir"):
        try:
            out["mail_index"] = mail.doctor(cfg["mail"]["data_dir"])
        except mail.MailError as err:
            out["mail_index"] = {"ok": False, "error": str(err)}
    print(json.dumps(out))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="RIAN Commander V2 job agent")
    p.add_argument("command", choices=["run", "run-job", "status"])
    p.add_argument("--config", required=True)
    p.add_argument("--job-dir")
    p.add_argument("--max-seconds", type=float)
    a = p.parse_args(argv)
    cfg = load_config(a.config)
    if a.command == "run-job":
        return run_job(a.job_dir, cfg)
    if a.command == "status":
        return status(cfg)
    lock = single_instance(cfg["state_dir"])
    if lock is None:
        # e.g. a manual start while launchd/the logon task already runs the agent
        log("AGENT_ALREADY_RUNNING", device=cfg["device_id"])
        return ALREADY_RUNNING_EXIT
    try:
        client = Client(cfg["relay_url"], device_token(cfg), allow_test_loopback=cfg.get("allow_test_loopback") is True, timeout=25)
        Supervisor(cfg, a.config, client).loop(cfg.get("poll_seconds", 5), a.max_seconds)
    finally:
        lock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
