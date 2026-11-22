"""RIAN AI Fleet job bodies for rian-v2-agent.py (Python 3.9+, Windows and macOS).

Every operation is fixed here; the server only picks a kind and bounded integers. Nothing here
reads file contents, credentials or process command lines, kills a process, or changes a setting.

  fleet.inventory        read-only machine facts (names and numbers only)
  fleet.cpu_bench        deterministic SHA-256 chain: the same (chunk, units) gives the same digest
                         on every PC, so a parallel run can be checked against a single-PC run
  fleet.gpu_probe        allocate a synthetic tensor in a CHILD process, let it exit, then measure
                         that the GPU memory came back (gpu_release)
  youngmin.qlora_probe   checks the QLoRA stack first; measures only when this PC's own config sets
                         fleet.qlora_measure=true (random weights + synthetic tokens, no data files)

memory_state() is what inventory reports and what the agent checks before it starts fleet work: a PC
that is short of memory (or already under OS memory pressure) is not given heavy work, and fleet work
runs below normal priority so the PC's own services (a production model server, other projects) win.
"""
import ctypes
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import string
import subprocess
import sys
import time
from pathlib import Path

try:
    from importlib import metadata as _md
except ImportError:  # pragma: no cover
    _md = None

AI_PROCESS = re.compile(r"^(ollama|llama-server|llama|vllm|lms|mlx_lm|tritonserver|text-generation|comfyui|python\d*(\.\d+)?|pythonw|node|bun|d23\w*)(\.exe)?$", re.I)
PACKAGES = ("torch", "transformers", "peft", "bitsandbytes", "accelerate", "vllm", "llama_cpp_python", "mlx", "mlx-lm")
WIN = sys.platform == "win32"
MAC = sys.platform == "darwin"


class FleetError(Exception):
    pass


class FleetCancelled(Exception):
    pass


def _run(argv, timeout=20):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace",
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return None
    return p.stdout if p.returncode == 0 else None


def _ps(script, timeout=30):
    """A fixed PowerShell snippet (never built from server input); returns parsed JSON or None."""
    out = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                "$ErrorActionPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;& {" + script + "} | ConvertTo-Json -Compress -Depth 4"], timeout)
    try:
        return json.loads(out) if out and out.strip() else None
    except ValueError:
        return None


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------------ GPU (NVIDIA)
def nvidia_gpus():
    exe = shutil.which("nvidia-smi")
    if not exe:
        return None
    out = _run([exe, "--query-gpu=index,name,memory.total,memory.used,utilization.gpu,temperature.gpu,driver_version",
                "--format=csv,noheader,nounits"])
    if out is None:
        return None
    apps = _run([exe, "--query-compute-apps=gpu_uuid,pid,process_name,used_memory", "--format=csv,noheader,nounits"]) or ""
    head = _run([exe]) or ""
    cuda = re.search(r"CUDA Version:\s*([\d.]+)", head)
    gpus = []
    for line in out.strip().splitlines():
        f = [x.strip() for x in line.split(",")]
        if len(f) < 7:
            continue
        gpus.append({"index": int(f[0]), "name": f[1], "vram_total_mib": _num(f[2]), "vram_used_mib": _num(f[3]),
                     "util_pct": _num(f[4]), "temp_c": _num(f[5]), "driver": f[6], "cuda_driver_api": cuda.group(1) if cuda else None,
                     "compute_processes": []})
    pids = []
    for line in apps.strip().splitlines():
        f = [x.strip() for x in line.split(",")]
        if len(f) >= 3:
            name = re.split(r"[\\/]", f[2])[-1] if f[2] and "[" not in f[2] else "UNREADABLE"
            pids.append(f[1])
            for g in gpus[:1]:
                g["compute_processes"].append(name)
    return {"gpus": gpus, "pids": pids}


def gpu_used_mib():
    g = nvidia_gpus()
    if not g or not g["gpus"]:
        return None, []
    return g["gpus"][0]["vram_used_mib"], g["pids"]


# ------------------------------------------------------------------ inventory
def _packages():
    out = {"python": platform.python_version()}
    for name in PACKAGES:
        try:
            out[name] = _md.version(name) if _md else None
        except Exception:  # noqa: BLE001 - not installed
            out[name] = None
    t = out.get("torch") or ""
    out["torch_build"] = "cuda" if "+cu" in t else "cpu" if "+cpu" in t else ("unknown" if t else None)
    node = shutil.which("node") or ("/opt/homebrew/bin/node" if MAC and Path("/opt/homebrew/bin/node").exists() else None)
    out["node"] = ((_run([node, "--version"]) or "").strip() or None) if node else None
    return out


def _ai_processes():
    if WIN:
        names = _ps("Get-Process | Select-Object -ExpandProperty ProcessName") or []
        names = names if isinstance(names, list) else [names]
    else:
        names = [Path(x.strip()).name for x in (_run(["ps", "-axco", "comm"]) or "").splitlines()[1:]]
    counts = {}
    for n in names:
        n = str(n)
        if AI_PROCESS.match(n):
            k = n.lower().replace(".exe", "")
            counts[k] = counts.get(k, 0) + 1
    return counts


def _disks():
    roots = [c + ":\\" for c in string.ascii_uppercase if os.path.exists(c + ":\\")] if WIN else \
        ["/"] + [str(p) for p in Path("/Volumes").glob("*") if p.is_dir() and not p.is_symlink()]
    out = []
    for r in roots:
        try:
            u = shutil.disk_usage(r)
        except OSError:
            continue
        out.append({"root": r, "total_gib": round(u.total / 2**30, 1), "free_gib": round(u.free / 2**30, 1)})
    return out


def _encryption(disks):
    if MAC:
        s = (_run(["fdesetup", "status"]) or "").strip()
        return {"filevault": "ON" if "FileVault is On" in s else "OFF" if "FileVault is Off" in s else "UNKNOWN"}
    if WIN:
        # The shell's BitLocker property needs no admin rights (manage-bde does).
        codes = {1: "ON", 2: "OFF", 3: "ENCRYPTING", 4: "DECRYPTING", 5: "SUSPENDED", 6: "ON_LOCKED"}
        out = {}
        for d in disks:
            letter = d["root"][:2]
            v = _ps("(New-Object -ComObject Shell.Application).NameSpace('%s').Self.ExtendedProperty('System.Volume.BitLockerProtection')" % letter)
            out[letter] = codes.get(v, "NONE" if v in (None, 0) else "CODE_%s" % v)
        return {"bitlocker": out}
    return {}


def inventory(progress):
    progress(stage="cpu", percent=5)
    snap = {"host": socket.gethostname(), "os": {"system": platform.system(), "release": platform.release(),
                                                 "version": platform.version()[:80], "machine": platform.machine()}}
    cpu = {"logical": os.cpu_count()}
    if WIN:
        p = _ps("Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,LoadPercentage")
        p = p[0] if isinstance(p, list) else p
        if p:
            cpu.update(model=p.get("Name"), physical=p.get("NumberOfCores"), load_pct=_num(p.get("LoadPercentage")))
    elif not MAC:  # Linux (CI runners, future nodes)
        info = Path("/proc/cpuinfo").read_text("utf-8", "replace") if Path("/proc/cpuinfo").exists() else ""
        model = re.search(r"^model name\s*:\s*(.+)$", info, re.M)
        cpu.update(model=model.group(1).strip() if model else None,
                   load_pct=round(min(100.0, 100.0 * os.getloadavg()[0] / max(1, os.cpu_count() or 1)), 1))
    else:
        cpu.update(model=(_run(["sysctl", "-n", "machdep.cpu.brand_string"]) or "").strip(),
                   physical=int((_run(["sysctl", "-n", "hw.physicalcpu"]) or "0").strip() or 0))
        top = _run(["top", "-l", "1", "-n", "0"]) or ""
        idle = re.search(r"([\d.]+)% idle", top)
        cpu["load_pct"] = round(100 - float(idle.group(1)), 1) if idle else None
    snap["cpu"], snap["ram"] = cpu, memory_state()
    progress(stage="gpu", percent=35)
    g = nvidia_gpus()
    if g:
        snap["gpus"] = g["gpus"]
    elif MAC:
        sp = _run(["system_profiler", "SPDisplaysDataType", "-json"], 30)
        try:
            items = json.loads(sp)["SPDisplaysDataType"] if sp else []
        except (ValueError, KeyError):
            items = []
        snap["gpus"] = [{"name": i.get("sppci_model"), "cores": i.get("sppci_cores"), "unified_memory": True,
                         "vram_total_mib": None, "vram_used_mib": None, "util_pct": None, "temp_c": None, "compute_processes": []}
                        for i in items]
    else:
        snap["gpus"] = []
    progress(stage="disk", percent=60)
    snap["disks"] = _disks()
    snap["encryption"] = _encryption(snap["disks"])
    progress(stage="runtime", percent=80)
    snap["runtimes"] = _packages()
    snap["ai_processes"] = _ai_processes()
    if WIN:
        n = _ps("Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name,LinkSpeed")
        snap["network"] = [{"name": x.get("Name"), "link": x.get("LinkSpeed")} for x in (n if isinstance(n, list) else [n] if n else [])]
    return {"ok": True, "snapshot": snap}


# ------------------------------------------------------------------ memory
def classify_pressure(total_mib, available_mib, commit_pct=None, os_level=None, psi_some_avg10=None):
    """Pure rule, the same on every OS: 'high' when any signal says the PC is short of memory."""
    reasons = []
    if available_mib is not None and total_mib and available_mib < max(1024, 0.05 * total_mib):
        reasons.append("LOW_AVAILABLE")
    if commit_pct is not None and commit_pct >= 90:
        reasons.append("COMMIT_HIGH")            # Windows: committed memory near the page-file limit
    if os_level is not None and os_level >= 2:
        reasons.append("OS_PRESSURE")            # macOS kern.memorystatus_vm_pressure_level: 2 warn, 4 critical
    if psi_some_avg10 is not None and psi_some_avg10 >= 10:
        reasons.append("PSI_STALLS")             # Linux: tasks stalled on memory >= 10% of the last 10 s
    return ("high" if reasons else "normal"), reasons


def memory_state():
    """{total_mib, available_mib, commit_pct?, swap_used_mib?, os_level?, psi_some_avg10?, pressure, pressure_reasons}"""
    out = {"total_mib": None, "available_mib": None}
    try:
        if WIN:
            class MemStatus(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            m = MemStatus()
            m.dwLength = ctypes.sizeof(MemStatus)
            if ctypes.WinDLL("kernel32").GlobalMemoryStatusEx(ctypes.byref(m)):
                out.update(total_mib=round(m.ullTotalPhys / 2**20), available_mib=round(m.ullAvailPhys / 2**20))
                if m.ullTotalPageFile:
                    out["commit_pct"] = round(100.0 * (1 - m.ullAvailPageFile / m.ullTotalPageFile), 1)
        elif MAC:
            total = int((_run(["sysctl", "-n", "hw.memsize"]) or "0").strip() or 0)
            vm = _run(["vm_stat"]) or ""
            page = int((re.search(r"page size of (\d+)", vm) or [0, 16384])[1])
            free_pages = sum(int(x) for k in ("Pages free", "Pages inactive", "Pages speculative")
                             for x in re.findall(k + r":\s+(\d+)", vm))
            out.update(total_mib=round(total / 2**20), available_mib=round(free_pages * page / 2**20))
            level = (_run(["sysctl", "-n", "kern.memorystatus_vm_pressure_level"]) or "").strip()
            if level.isdigit():
                out["os_level"] = int(level)
            swap = re.search(r"used = ([\d.]+)M", _run(["sysctl", "-n", "vm.swapusage"]) or "")
            if swap:
                out["swap_used_mib"] = round(float(swap.group(1)))
        else:
            mem = Path("/proc/meminfo").read_text("utf-8", "replace") if Path("/proc/meminfo").exists() else ""
            kib = {k: int(v) for k, v in re.findall(r"^(\w+):\s+(\d+) kB", mem, re.M)}
            out.update(total_mib=round(kib.get("MemTotal", 0) / 1024), available_mib=round(kib.get("MemAvailable", 0) / 1024))
            if "SwapTotal" in kib:
                out["swap_used_mib"] = round((kib["SwapTotal"] - kib.get("SwapFree", 0)) / 1024)
            psi = Path("/proc/pressure/memory")
            hit = re.search(r"^some avg10=([\d.]+)", psi.read_text("utf-8", "replace"), re.M) if psi.exists() else None
            if hit:
                out["psi_some_avg10"] = float(hit.group(1))
    except (OSError, ValueError, AttributeError):
        pass
    out["pressure"], out["pressure_reasons"] = classify_pressure(out["total_mib"], out["available_mib"], out.get("commit_pct"),
                                                                 out.get("os_level"), out.get("psi_some_avg10"))
    if not out["available_mib"]:
        out["pressure"], out["pressure_reasons"] = "unknown", ["NOT_MEASURED"]
    return out


def memory_hold(kind, min_available_mib, state=None):
    """None when fleet work of this kind may start now, else the refusal (with the measurement).

    Inventory always runs (it is how the owner sees the PC). Below `min_available_mib`, or while the PC
    reports memory pressure, nothing else starts. An unmeasurable PC is treated as short of memory."""
    if kind == "fleet.inventory":
        return None
    st = state if state is not None else memory_state()
    seen = {k: st.get(k) for k in ("available_mib", "total_mib", "pressure", "pressure_reasons")}
    if not st.get("available_mib"):
        return {"ok": False, "error": "LOCAL_MEMORY_UNKNOWN", "memory": seen}
    if st["available_mib"] < min_available_mib:
        return {"ok": False, "error": "LOCAL_MEMORY_HOLD", "memory": dict(seen, min_available_mib=min_available_mib)}
    if st.get("pressure") == "high":
        return {"ok": False, "error": "LOCAL_MEMORY_PRESSURE", "memory": seen}
    return None


def lower_priority():
    """Run this process (and the children it starts) below normal priority. Returns True on success."""
    try:
        if WIN:
            k = ctypes.WinDLL("kernel32")
            k.GetCurrentProcess.restype = ctypes.c_void_p
            k.SetPriorityClass.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
            return bool(k.SetPriorityClass(k.GetCurrentProcess(), 0x00004000))   # BELOW_NORMAL_PRIORITY_CLASS
        # setpriority/getpriority, not os.nice(): nice()'s return value differed on a CI macOS runner.
        if os.getpriority(os.PRIO_PROCESS, 0) < 10:
            os.setpriority(os.PRIO_PROCESS, 0, 10)
        return os.getpriority(os.PRIO_PROCESS, 0) >= 10
    except (OSError, AttributeError):
        return False


# ------------------------------------------------------------------ CPU bench
ITER_PER_UNIT = 400_000


def cpu_bench(chunk, units, progress, cancelled):
    h = hashlib.sha256(("rian-fleet-bench|%d" % chunk).encode()).digest()
    start = time.perf_counter()
    for u in range(units):
        if cancelled():
            raise FleetCancelled()
        for _ in range(ITER_PER_UNIT):
            h = hashlib.sha256(h).digest()
        progress(stage="hashing", percent=int(100 * (u + 1) / units), done=u + 1, total=units)
    return {"ok": True, "chunk": chunk, "units": units, "digest": h.hex(), "seconds": round(time.perf_counter() - start, 3),
            "host": socket.gethostname(), "pid": os.getpid()}


# ------------------------------------------------------------------ GPU hand-back
def _measure_release(before, before_pids, tolerance=256, wait_s=15):
    after, pids = gpu_used_mib()
    t0 = time.time()
    while after is not None and before is not None and after > before + tolerance and time.time() - t0 < wait_s:
        time.sleep(1)
        after, pids = gpu_used_mib()
    return {"before_mib": before, "after_mib": after, "leftover_pids": [p for p in pids if p not in before_pids]}


def _protected(cfg_fleet):
    g = nvidia_gpus()
    names = [n.lower() for x in (g["gpus"] if g else []) for n in x["compute_processes"]]
    wanted = cfg_fleet.get("gpu_protected_processes") or []
    hit = [p for p in wanted if any(p.lower() in n for n in names)]
    # A GPU process this user may not name (e.g. a SYSTEM service) could be the protected one: fail closed.
    if wanted and "unreadable" in names and not hit:
        hit = ["UNREADABLE_GPU_PROCESS"]
    return hit


CHILD_ALLOC = ("import sys,torch\n"
               "assert torch.cuda.is_available()\n"
               "t=torch.empty(int(sys.argv[1])*262144,dtype=torch.float32,device='cuda');t.fill_(1.0);torch.cuda.synchronize()\n"
               "print(int(torch.cuda.max_memory_allocated()//1048576))\n")


def gpu_probe(mib, cfg_fleet, progress, cancelled):
    before, before_pids = gpu_used_mib()
    if before is None:
        raise FleetError("NO_NVIDIA_GPU")
    prot = _protected(cfg_fleet)
    if prot:
        return {"ok": False, "error": "GPU_PROTECTED_PROCESS_PRESENT", "protected": prot,
                "gpu_release": _measure_release(before, before_pids)}
    progress(stage="allocating", percent=20)
    env = dict(os.environ, CUDA_VISIBLE_DEVICES="0", PYTHONIOENCODING="utf-8")
    try:
        p = subprocess.run([sys.executable, "-I", "-c", CHILD_ALLOC, str(mib)], capture_output=True, text=True, timeout=180, env=env)
        peak = int(p.stdout.strip().splitlines()[-1]) if p.returncode == 0 and p.stdout.strip() else None
        err = None if p.returncode == 0 else ("TORCH_CUDA_UNAVAILABLE" if "AssertionError" in p.stderr or "ModuleNotFoundError" in p.stderr else "CHILD_FAILED")
    except subprocess.TimeoutExpired:
        peak, err = None, "CHILD_TIMEOUT"
    progress(stage="verifying_release", percent=70)
    rel = _measure_release(before, before_pids)
    return {"ok": err is None, **({"error": err} if err else {}), "requested_mib": mib, "child_peak_mib": peak, "gpu_release": rel}


# ------------------------------------------------------------------ QLoRA probe
QWEN3_8B = {"hidden_size": 4096, "intermediate_size": 12288, "num_hidden_layers": 36, "num_attention_heads": 32,
            "num_key_value_heads": 8, "head_dim": 128, "vocab_size": 151936, "max_position_embeddings": 40960,
            "rms_norm_eps": 1e-6, "rope_theta": 1000000.0, "tie_word_embeddings": False}


def qlora_estimate(seq_len, batch, rank, grad_ckpt):
    """Closed-form memory budget for 4-bit NF4 Qwen3-8B + LoRA (all 7 projections), in MiB."""
    c = QWEN3_8B
    h, i, L, v = c["hidden_size"], c["intermediate_size"], c["num_hidden_layers"], c["vocab_size"]
    kv = c["num_key_value_heads"] * c["head_dim"]
    per_layer_linear = h * h * 2 + h * kv * 2 + h * i * 3           # q,o + k,v + gate,up,down
    nf4 = L * per_layer_linear * 0.5 * (1 + 1 / 32) / 2**20       # 4-bit + absmax constants
    emb = 2 * v * h * 2 / 2**20                                   # bf16 embed + lm_head
    lora_params = L * rank * ((h + h) * 2 + (h + kv) * 2 + (h + i) * 3)
    lora = lora_params * (2 + 4 + 8) / 2**20                       # bf16 weight + fp32 grad + Adam m,v
    tokens = seq_len * batch
    act_layer = tokens * h * 2 * (2 if grad_ckpt else 34) / 2**20   # checkpoint keeps ~2 tensors per layer
    logits = tokens * v * 4 * 2 / 2**20                            # fp32 logits + grad
    return {"weights_nf4_mib": round(nf4), "embeddings_bf16_mib": round(emb), "lora_and_optimizer_mib": round(lora),
            "activations_mib": round(act_layer * L), "logits_mib": round(logits),
            "total_estimate_mib": round(nf4 + emb + lora + act_layer * L + logits + 600), "lora_params": lora_params,
            "note": "closed-form estimate incl. ~600 MiB CUDA context; a measurement replaces it when it runs"}


def qlora_probe(params, cfg_fleet, progress, cancelled):
    pk = _packages()
    missing = [n for n in ("torch", "transformers", "peft", "bitsandbytes", "accelerate") if not pk.get(n)]
    if pk.get("torch_build") != "cuda":
        missing.append("torch(CUDA build)")
    before, before_pids = gpu_used_mib()
    g = nvidia_gpus()
    gpu = g["gpus"][0] if g and g["gpus"] else None
    est = qlora_estimate(params["seqLen"], params["batch"], params["rank"], params["gradCheckpointing"])
    base = {"estimate": est, "gpu": gpu and {k: gpu[k] for k in ("name", "vram_total_mib", "vram_used_mib")},
            "fits_by_estimate": bool(gpu and gpu["vram_total_mib"] and est["total_estimate_mib"] <= gpu["vram_total_mib"] - (gpu["vram_used_mib"] or 0)),
            "packages": {k: pk.get(k) for k in ("python", "torch", "torch_build", "transformers", "peft", "bitsandbytes", "accelerate")}}
    if gpu is None:
        return {"ok": False, "error": "NO_NVIDIA_GPU", **base}
    prot = _protected(cfg_fleet)
    if prot:
        return {"ok": False, "error": "GPU_PROTECTED_PROCESS_PRESENT", "protected": prot, **base, "gpu_release": _measure_release(before, before_pids)}
    if missing:
        return {"ok": False, "error": "PREREQUISITES_MISSING", "missing": missing, "measurement": "NOT_RUN", **base,
                "gpu_release": _measure_release(before, before_pids)}
    if cfg_fleet.get("qlora_measure") is not True:
        return {"ok": False, "error": "MEASUREMENT_NOT_ENABLED_ON_THIS_PC", "measurement": "NOT_RUN", **base,
                "gpu_release": _measure_release(before, before_pids)}
    progress(stage="measuring", percent=10)
    script = Path(__file__).with_name("youngmin_qlora_measure.py")
    env = dict(os.environ, CUDA_VISIBLE_DEVICES="0", PYTHONIOENCODING="utf-8", HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1")
    try:
        p = subprocess.run([sys.executable, "-I", str(script), json.dumps(params)], capture_output=True, text=True, timeout=3300, env=env)
        line = (p.stdout.strip().splitlines() or ["{}"])[-1]
        measured = json.loads(line) if p.returncode == 0 else {"error": "MEASURE_FAILED", "exit": p.returncode,
                                                                 "type": (re.findall(r"^(\w+(?:Error|Exception)):", p.stderr, re.M) or ["UNKNOWN"])[-1]}
    except (subprocess.TimeoutExpired, ValueError):
        measured = {"error": "MEASURE_TIMEOUT_OR_BAD_OUTPUT"}
    return {"ok": "error" not in measured, "measurement": measured, **base, "gpu_release": _measure_release(before, before_pids)}


# ------------------------------------------------------------------ store integrity (real research ops)
# Ollama names blobs "sha256-<hex>"; the Hugging Face hub names LFS blobs by the bare sha256 hex.
BLOB = re.compile(r"^(?:sha256[-:])?([0-9a-f]{64})$")


def _store_files(spec):
    """A store is one path or a list; a path may hold blobs itself or HF-style */blobs folders."""
    out = []
    for root in ([spec] if isinstance(spec, str) else list(spec)):
        base = Path(root)
        if not base.is_dir():
            raise FleetError("STORE_MISSING")
        dirs = [base] + sorted(p for p in base.glob("*/blobs") if p.is_dir())
        out += [p for d in dirs for p in d.iterdir() if p.is_file() and not p.is_symlink() and BLOB.match(p.name)]
    return sorted(set(out), key=lambda p: (p.name, str(p)))


def blob_verify(store, shard, shards, cfg_fleet, progress, cancelled):
    """Hash every content-addressed file (name = its sha256) in this PC's own store; report only counts."""
    stores = cfg_fleet.get("blob_stores") or {}
    spec = stores.get(store)
    if not spec:
        raise FleetError("STORE_NOT_CONFIGURED_ON_THIS_PC")
    files = _store_files(spec)
    mine = [p for i, p in enumerate(files) if i % shards == shard]
    total = sum(p.stat().st_size for p in mine)
    done_bytes, bad, start = 0, [], time.perf_counter()
    for i, p in enumerate(mine):
        h = hashlib.sha256()
        with p.open("rb") as f:
            for block in iter(lambda: f.read(8 << 20), b""):
                if cancelled():
                    raise FleetCancelled()
                h.update(block)
                done_bytes += len(block)
        if h.hexdigest() != BLOB.match(p.name).group(1):
            bad.append(p.name[:20])
        progress(stage="hashing", percent=int(100 * done_bytes / max(1, total)), done=i + 1, total=len(mine))
    secs = time.perf_counter() - start
    return {"ok": not bad, **({"error": "HASH_MISMATCH"} if bad else {}), "store": store, "shard": shard, "shards": shards,
            "files": len(mine), "files_in_store": len(files), "bytes": total, "seconds": round(secs, 2),
            "mb_per_s": round(total / 2**20 / max(secs, 1e-6), 1), "mismatched": bad, "host": socket.gethostname()}



# ------------------------------------------------------------------ distributed code tests
def _git(repo, *args):
    out = _run(["git", "-C", str(repo), *args], timeout=30)
    return None if out is None else out.strip()


def test_shard(suite, commit, shard, shards, cfg_fleet, progress, cancelled):
    """Run one shard of a test suite this PC's config defines, only on a clean checkout at `commit`."""
    spec = (cfg_fleet.get("test_suites") or {}).get(suite)
    if not spec:
        raise FleetError("SUITE_NOT_CONFIGURED_ON_THIS_PC")
    repo, cwd = Path(spec["repo"]), Path(spec["repo"]) / spec.get("cwd", ".")
    head = _git(repo, "rev-parse", "HEAD")
    if head != commit:
        return {"ok": False, "error": "CHECKOUT_NOT_AT_COMMIT", "head": (head or "")[:12]}
    if _git(repo, "status", "--porcelain", "--untracked-files=no"):
        return {"ok": False, "error": "CHECKOUT_HAS_LOCAL_CHANGES"}
    files = sorted(str(p.relative_to(cwd)).replace("\\", "/") for p in cwd.glob(spec["glob"]) if p.is_file())
    files = [f for f in files if f not in set(spec.get("exclude") or [])]
    mine = [f for i, f in enumerate(files) if i % shards == shard]
    if not mine:
        return {"ok": True, "files": 0, "seconds": 0.0, "exit": 0, "suite": suite, "shard": shard, "shards": shards}
    argv = [str(x) for x in spec["command"]]
    exe = shutil.which(argv[0]) or argv[0]
    progress(stage="testing", percent=5, done=0, total=len(mine))
    start = time.perf_counter()
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    results = []
    if spec.get("per_file"):
        for i, f in enumerate(mine):
            if cancelled():
                raise FleetCancelled()
            p = subprocess.run([exe, *argv[1:], f], cwd=str(cwd), capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=int(spec.get("timeout", 900)), env=env)
            results.append((f, p.returncode, (p.stdout + p.stderr)[-600:]))
            progress(stage="testing", percent=int(100 * (i + 1) / len(mine)), done=i + 1, total=len(mine))
    else:
        p = subprocess.run([exe, *argv[1:], *mine], cwd=str(cwd), capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=int(spec.get("timeout", 900)), env=env)
        results.append(("*", p.returncode, (p.stdout + p.stderr)[-2000:]))
    failed = [f for f, rc, _ in results if rc != 0]
    tail = chr(10).join(t for _, rc, t in results if rc != 0)[-2000:]
    return {"ok": not failed, **({"error": "TESTS_FAILED"} if failed else {}), "suite": suite, "shard": shard, "shards": shards,
            "files": len(mine), "failed_files": failed[:20], "seconds": round(time.perf_counter() - start, 2),
            "failure_tail": tail, "host": socket.gethostname(), "commit": commit[:12]}

# ------------------------------------------------------------------ owner-run read-only CLI
SECURITY_PS = r"""
$o = [ordered]@{}
$o.tasks = @(Get-ScheduledTask | Where-Object { $_.TaskName -like 'GoogleUpdate*' -or $_.TaskPath -like '*Google*' } | ForEach-Object {
  $a = $_.Actions | Select-Object -First 1
  $exe = if ($a.Execute) { [Environment]::ExpandEnvironmentVariables($a.Execute.Trim('"')) } else { $null }
  $sig = if ($exe -and (Test-Path -LiteralPath $exe)) { Get-AuthenticodeSignature -LiteralPath $exe } else { $null }
  $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
  [ordered]@{ name = $_.TaskName; path = $_.TaskPath; state = [string]$_.State; principal = $_.Principal.UserId; run_level = [string]$_.Principal.RunLevel
    exe = $exe; exe_exists = [bool]($exe -and (Test-Path -LiteralPath $exe)); signature = if ($sig) { [string]$sig.Status } else { $null }
    signer = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
    sha256 = if ($exe -and (Test-Path -LiteralPath $exe)) { (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash } else { $null }
    arguments_present = [bool]$a.Arguments; last_run = if ($info) { [string]$info.LastRunTime } else { $null }; last_result = if ($info) { $info.LastTaskResult } else { $null } } })
$o.gpu_engine_top = @(Get-Counter '\GPU Engine(*)\Utilization Percentage' -ErrorAction SilentlyContinue | ForEach-Object { $_.CounterSamples } |
  Where-Object { $_.CookedValue -gt 1 } | Sort-Object CookedValue -Descending | Select-Object -First 10 |
  ForEach-Object { $pid_ = if ($_.InstanceName -match 'pid_(\d+)') { [int]$Matches[1] } else { $null }
    [ordered]@{ pid = $pid_; process = if ($pid_) { (Get-Process -Id $pid_ -ErrorAction SilentlyContinue).ProcessName } else { $null }; util_pct = [math]::Round($_.CookedValue, 1) } })
$o.defender = try { $m = Get-MpComputerStatus -ErrorAction Stop; [ordered]@{ realtime = $m.RealTimeProtectionEnabled; antivirus = $m.AntivirusEnabled; signature_age_days = $m.AntivirusSignatureAge; last_quick_scan = [string]$m.QuickScanEndTime } } catch { 'UNREADABLE' }
$o.listening = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ port = $_.LocalPort; address = $_.LocalAddress; process = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } } | Sort-Object port -Unique)
$o
"""


def security_inventory():
    if not WIN:
        return {"ok": False, "error": "WINDOWS_ONLY"}
    data = _ps(SECURITY_PS, timeout=120)
    return {"ok": data is not None, "host": socket.gethostname(), "security": data,
            "note": "read-only: names, paths, signatures and hashes only; nothing stopped or changed"}


def _cli(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="RIAN fleet read-only inventory (owner-run; no network, nothing changed)")
    ap.add_argument("what", choices=["inventory", "security"])
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    res = inventory(lambda **k: None) if a.what == "inventory" else security_inventory()
    res["collected_at"] = int(time.time())
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1), "utf-8")
    print(json.dumps({"written": a.out, "ok": res.get("ok")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
