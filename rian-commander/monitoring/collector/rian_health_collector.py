#!/usr/bin/env python3
"""RIAN Commander Health Collector — READ-ONLY device health sampling.

  python rian_health_collector.py collect --config collector.json   # print one sample, no network
  python rian_health_collector.py once    --config collector.json   # collect and send one sample
  python rian_health_collector.py run     --config collector.json   # every interval_seconds (default 300)

Properties (by construction, see tests):
- Disabled until the device owner sets "enabled": true in the local config.
- Outbound HTTPS POST to <server_url>/v1/health/ingest only. No listener, no redirects.
- The server response is never interpreted as an instruction. There is no command channel.
- Only fixed, read-only OS queries are run, as argv lists (never a shell). Process/service names
  come from the local config and are validated.
- Bounded retry: at most MAX_QUEUE samples are kept while the server is unreachable, failures are
  logged on state change and then at most once per LOG_EVERY attempts.
Python 3.10+ standard library only.
"""
import argparse
import ctypes
import json
import os
import platform
import re
import shutil
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

VERSION = "0.1.0"
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@:+()-]{0,99}$")
DEVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
MAX_QUEUE = 12          # one hour at the default interval
LOG_EVERY = 12
QUERY_TIMEOUT = 10


class CollectorError(RuntimeError):
    pass


def log(event, **fields):
    # Codes and counters only: never tokens, URLs with credentials, process lists or metric dumps.
    print(json.dumps({"event": event, "at": int(time.time()), **fields}), flush=True)


def run_query(argv):
    """Run one fixed read-only OS query. argv is a list; shell is never used."""
    return subprocess.run(argv, capture_output=True, text=True, timeout=QUERY_TIMEOUT, check=False,
                          stdin=subprocess.DEVNULL)


# ------------------------------------------------------------------ parsers (pure, unit-tested)
def parse_proc_stat(text):
    fields = text.splitlines()[0].split()
    if fields[0] != "cpu":
        raise CollectorError("CPU_UNAVAILABLE")
    values = [int(v) for v in fields[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def cpu_percent_from_proc(a, b):
    total, idle = b[0] - a[0], b[1] - a[1]
    if total <= 0:
        raise CollectorError("CPU_UNAVAILABLE")
    return round(100.0 * (total - idle) / total, 1)


def parse_top_cpu(text):
    """macOS `top -l 2 -n 0`: use the LAST 'CPU usage' line (the first sample is since boot)."""
    lines = [l for l in text.splitlines() if l.startswith("CPU usage:")]
    m = re.search(r"([\d.]+)% idle", lines[-1]) if lines else None
    if not m:
        raise CollectorError("CPU_UNAVAILABLE")
    return round(100.0 - float(m.group(1)), 1)


def parse_meminfo(text):
    info = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            info[key] = int(parts[0]) * 1024
    if "MemTotal" not in info or "MemAvailable" not in info:
        raise CollectorError("MEMORY_UNAVAILABLE")
    return info["MemTotal"], info["MemTotal"] - info["MemAvailable"]


def parse_vm_stat(text, total):
    m = re.search(r"page size of (\d+) bytes", text)
    if not m:
        raise CollectorError("MEMORY_UNAVAILABLE")
    page = int(m.group(1))
    pages = {k.strip(): int(v.strip().rstrip(".")) for k, v in re.findall(r"^(Pages [^:]+):\s+(\d+)\.?$", text, re.M)}
    available = sum(pages.get("Pages " + k, 0) for k in ("free", "inactive", "speculative")) * page
    return total, max(0, min(total, total - available))


def parse_tasklist_csv(text):
    names = set()
    for line in text.splitlines():
        if line.startswith('"'):
            names.add(line.split('","')[0].strip('"').lower())
    return names


def parse_sc_query(text):
    m = re.search(r"STATE\s*:\s*\d+\s+(\w+)", text)
    return bool(m and m.group(1).upper() == "RUNNING")


def percent(used, total):
    return round(100.0 * used / total, 1) if total else None


# ------------------------------------------------------------------ OS readers
def _win_cpu_times():
    class FILETIME(ctypes.Structure):
        _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]
    idle, kernel, user = FILETIME(), FILETIME(), FILETIME()
    if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
        raise CollectorError("CPU_UNAVAILABLE")
    v = lambda f: (f.hi << 32) | f.lo
    return v(kernel) + v(user), v(idle)   # kernel time includes idle time


def read_cpu(system):
    if system == "Linux":
        a = parse_proc_stat(Path("/proc/stat").read_text())
        time.sleep(1)
        return cpu_percent_from_proc(a, parse_proc_stat(Path("/proc/stat").read_text()))
    if system == "Darwin":
        return parse_top_cpu(run_query(["/usr/bin/top", "-l", "2", "-n", "0", "-s", "1"]).stdout)
    if system == "Windows":
        a = _win_cpu_times()
        time.sleep(1)
        return cpu_percent_from_proc(a, _win_cpu_times())
    raise CollectorError("CPU_UNSUPPORTED_OS")


def read_memory(system):
    if system == "Linux":
        return parse_meminfo(Path("/proc/meminfo").read_text())
    if system == "Darwin":
        total = int(run_query(["/usr/sbin/sysctl", "-n", "hw.memsize"]).stdout.strip() or 0)
        return parse_vm_stat(run_query(["/usr/bin/vm_stat"]).stdout, total)
    if system == "Windows":
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_uint32), ("dwMemoryLoad", ctypes.c_uint32), ("ullTotalPhys", ctypes.c_uint64),
                        ("ullAvailPhys", ctypes.c_uint64), ("ullTotalPageFile", ctypes.c_uint64), ("ullAvailPageFile", ctypes.c_uint64),
                        ("ullTotalVirtual", ctypes.c_uint64), ("ullAvailVirtual", ctypes.c_uint64), ("ullAvailExtendedVirtual", ctypes.c_uint64)]
        s = MEMORYSTATUSEX()
        s.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(s)):
            raise CollectorError("MEMORY_UNAVAILABLE")
        return s.ullTotalPhys, s.ullTotalPhys - s.ullAvailPhys
    raise CollectorError("MEMORY_UNSUPPORTED_OS")


def running_processes(system):
    if system == "Linux":
        names = set()
        for p in Path("/proc").iterdir():
            if p.name.isdigit():
                try:
                    names.add((p / "comm").read_text().strip().lower())
                except OSError:
                    pass
        return names
    if system == "Darwin":
        out = run_query(["/bin/ps", "-axo", "comm="]).stdout
        return {os.path.basename(l.strip()).lower() for l in out.splitlines() if l.strip()}
    if system == "Windows":
        return parse_tasklist_csv(run_query(["tasklist", "/fo", "csv", "/nh"]).stdout)
    raise CollectorError("PROCESS_UNSUPPORTED_OS")


def service_running(system, name):
    if system == "Linux":
        if not shutil.which("systemctl"):
            raise CollectorError("SERVICE_QUERY_UNAVAILABLE")
        return run_query(["systemctl", "is-active", "--quiet", name]).returncode == 0
    if system == "Windows":
        return parse_sc_query(run_query(["sc", "query", name]).stdout)
    if system == "Darwin":
        for domain in ("gui/%d" % os.getuid(), "system"):
            r = run_query(["/bin/launchctl", "print", domain + "/" + name])
            if r.returncode == 0:
                return bool(re.search(r"^\s*state = running", r.stdout, re.M))
        return False
    raise CollectorError("SERVICE_UNSUPPORTED_OS")


def os_info(system):
    info = {"family": {"Darwin": "macOS"}.get(system, system), "arch": platform.machine()[:32]}
    if system == "Darwin":
        info["version"] = platform.mac_ver()[0]
    elif system == "Linux":
        try:
            pretty = re.search(r'^PRETTY_NAME="?([^"\n]+)', Path("/etc/os-release").read_text(), re.M)
            info["version"] = (pretty.group(1) if pretty else platform.release())
        except OSError:
            info["version"] = platform.release()
    else:
        info["version"] = platform.version()
    info["version"] = str(info.get("version") or "")[:64]
    return info


# ------------------------------------------------------------------ config + sample
def default_disk():
    return os.environ.get("SystemDrive", "C:") + "\\" if os.name == "nt" else "/"


def load_config(path):
    file = Path(path)
    cfg = json.loads(file.read_text("utf-8"))
    if not isinstance(cfg, dict):
        raise CollectorError("INVALID_CONFIG")
    out = {
        "enabled": cfg.get("enabled") is True,
        "server_url": cfg.get("server_url", ""),
        "device_id": cfg.get("device_id", ""),
        "token_file": cfg.get("token_file", ""),
        "interval_seconds": cfg.get("interval_seconds", 300),
        "disks": cfg.get("disks") or [default_disk()],
        "services": cfg.get("services") or [],
        "allow_test_loopback": cfg.get("allow_test_loopback") is True,
    }
    if not isinstance(out["device_id"], str) or not DEVICE.fullmatch(out["device_id"]):
        raise CollectorError("INVALID_DEVICE_ID")
    if not isinstance(out["interval_seconds"], int) or not 60 <= out["interval_seconds"] <= 3600:
        raise CollectorError("INVALID_INTERVAL")
    if not isinstance(out["disks"], list) or not 1 <= len(out["disks"]) <= 16 or not all(isinstance(d, str) and 0 < len(d) <= 200 for d in out["disks"]):
        raise CollectorError("INVALID_DISKS")
    services = []
    for s in out["services"] if isinstance(out["services"], list) else [None]:
        if not isinstance(s, dict) or s.get("type") not in ("process", "service") or not isinstance(s.get("name"), str) or not NAME.fullmatch(s["name"]):
            raise CollectorError("INVALID_SERVICES")
        services.append({"name": s["name"], "type": s["type"]})
    if len(services) > 32:
        raise CollectorError("INVALID_SERVICES")
    out["services"] = services
    return out


def collect(cfg, system=None):
    system = system or platform.system()
    sample = {"deviceId": cfg["device_id"], "collectedAt": int(time.time()), "collector": VERSION, "os": os_info(system),
              "cpu": None, "memory": None, "disks": [], "services": [], "collection": {"ok": True, "errors": []}}
    errors = sample["collection"]["errors"]

    def guard(code, fn):
        try:
            return fn()
        except CollectorError as e:
            errors.append(str(e))
        except (OSError, ValueError, subprocess.SubprocessError, AttributeError):
            errors.append(code)
        return None

    cpu = guard("CPU_UNAVAILABLE", lambda: read_cpu(system))
    if cpu is not None:
        sample["cpu"] = {"percent": max(0.0, min(100.0, cpu))}
    mem = guard("MEMORY_UNAVAILABLE", lambda: read_memory(system))
    if mem:
        sample["memory"] = {"totalBytes": int(mem[0]), "usedBytes": int(mem[1]), "percent": percent(mem[1], mem[0])}
    for mount in cfg["disks"]:
        du = guard("DISK_UNAVAILABLE", lambda m=mount: shutil.disk_usage(m))
        if du:
            used = du.total - du.free
            sample["disks"].append({"mount": mount[:200], "totalBytes": du.total, "usedBytes": used, "freeBytes": du.free, "percent": percent(used, du.total)})
    procs = None
    for svc in cfg["services"]:
        if svc["type"] == "process":
            if procs is None:
                procs = guard("PROCESS_LIST_UNAVAILABLE", lambda: running_processes(system)) or set()
            running = svc["name"].lower() in procs
        else:
            running = guard("SERVICE_QUERY_UNAVAILABLE", lambda s=svc: service_running(system, s["name"]))
        sample["services"].append({"name": svc["name"], "type": svc["type"], "running": bool(running) if running is not None else None})
    sample["collection"]["ok"] = not errors
    return sample


# ------------------------------------------------------------------ transport
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CollectorError("REDIRECT_BLOCKED")


class Sender:
    def __init__(self, cfg):
        url = urllib.parse.urlsplit(cfg["server_url"]) if isinstance(cfg["server_url"], str) else None
        loopback = cfg["allow_test_loopback"] and url and url.scheme == "http" and url.hostname in ("127.0.0.1", "localhost")
        if not url or not url.hostname or (url.scheme != "https" and not loopback) or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
            raise CollectorError("HTTPS_SERVER_REQUIRED")
        self.endpoint = cfg["server_url"].rstrip("/") + "/v1/health/ingest"
        self.token = read_token(cfg["token_file"])
        self.opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def send(self, sample):
        req = urllib.request.Request(self.endpoint, data=json.dumps(sample, separators=(",", ":")).encode(), method="POST",
                                     headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=15) as r:
                body = json.loads(r.read(4096).decode("utf-8"))
            if not isinstance(body, dict) or body.get("ok") is not True:
                raise CollectorError("UNEXPECTED_RESPONSE")
            # Deliberately ignore every other field: the server cannot instruct a collector.
        except urllib.error.HTTPError as e:
            raise CollectorError("SERVER_HTTP_%d" % e.code) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise CollectorError("SERVER_UNREACHABLE") from None
        except (ValueError, UnicodeError):
            raise CollectorError("UNEXPECTED_RESPONSE") from None


def read_token(path):
    p = Path(path)
    if not p.is_absolute() or not p.is_file() or p.is_symlink():
        raise CollectorError("TOKEN_FILE_REQUIRED")
    if os.name != "nt":
        st = p.stat()
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise CollectorError("TOKEN_FILE_PERMISSIONS")
    token = p.read_text("utf-8").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,256}", token):
        raise CollectorError("TOKEN_FILE_INVALID")
    return token


class Loop:
    """Bounded queue + rate-limited failure logging; one collection per interval, never a tight loop."""

    def __init__(self, cfg, sender, collect_fn=collect, sleep=time.sleep):
        self.cfg, self.sender, self.collect, self.sleep = cfg, sender, collect_fn, sleep
        self.queue, self.failures, self.dropped = [], 0, 0

    def tick(self):
        self.queue.append(self.collect(self.cfg))
        if len(self.queue) > MAX_QUEUE:
            self.dropped += len(self.queue) - MAX_QUEUE
            self.queue = self.queue[-MAX_QUEUE:]
        while self.queue:
            try:
                self.sender.send(self.queue[0])
            except CollectorError as e:
                self.failures += 1
                if self.failures == 1 or self.failures % LOG_EVERY == 0:
                    log("SEND_FAILED", code=str(e), failures=self.failures, queued=len(self.queue), dropped=self.dropped)
                return False
            self.queue.pop(0)
        if self.failures:
            log("SEND_RECOVERED", after_failures=self.failures, dropped=self.dropped)
            self.failures = 0
        return True

    def run(self, max_ticks=None):
        n = 0
        while max_ticks is None or n < max_ticks:
            started = time.time()
            self.tick()
            n += 1
            if max_ticks is None or n < max_ticks:
                self.sleep(max(1.0, self.cfg["interval_seconds"] - (time.time() - started)))


def main(argv=None):
    p = argparse.ArgumentParser(description="RIAN Commander read-only Health Collector")
    p.add_argument("command", choices=["collect", "once", "run"])
    p.add_argument("--config", required=True)
    a = p.parse_args(argv)
    try:
        cfg = load_config(a.config)
        if a.command == "collect":
            print(json.dumps(collect(cfg), ensure_ascii=False))
            return 0
        if not cfg["enabled"]:
            log("COLLECTOR_DISABLED", hint="device owner must set enabled=true")
            return 0
        loop = Loop(cfg, Sender(cfg))
        if a.command == "once":
            return 0 if loop.tick() else 3
        log("COLLECTOR_STARTED", device=cfg["device_id"], interval=cfg["interval_seconds"], version=VERSION)
        loop.run()
        return 0
    except (CollectorError, OSError, ValueError) as e:
        code = str(e) if isinstance(e, CollectorError) else type(e).__name__.upper()
        log("COLLECTOR_ERROR", code=code)
        return 2


if __name__ == "__main__":
    sys.exit(main())
