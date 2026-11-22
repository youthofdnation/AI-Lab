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
"""
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
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired):
        return None
    return p.stdout if p.returncode == 0 else None


def _ps(script, timeout=30):
    """A fixed PowerShell snippet (never built from server input); returns parsed JSON or None."""
    out = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                "$ErrorActionPreference='SilentlyContinue';" + script + " | ConvertTo-Json -Compress -Depth 4"], timeout)
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
        m = _ps("Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory")
        ram = {"total_mib": round(_num(m["TotalVisibleMemorySize"]) / 1024), "available_mib": round(_num(m["FreePhysicalMemory"]) / 1024)} if m else {}
    elif not MAC:  # Linux (CI runners, future nodes)
        info = Path("/proc/cpuinfo").read_text("utf-8", "replace") if Path("/proc/cpuinfo").exists() else ""
        model = re.search(r"^model name\s*:\s*(.+)$", info, re.M)
        cpu.update(model=model.group(1).strip() if model else None,
                   load_pct=round(min(100.0, 100.0 * os.getloadavg()[0] / max(1, os.cpu_count() or 1)), 1))
        mem = Path("/proc/meminfo").read_text("utf-8", "replace") if Path("/proc/meminfo").exists() else ""
        kib = {k: int(v) for k, v in re.findall(r"^(\w+):\s+(\d+) kB", mem, re.M)}
        ram = {"total_mib": round(kib.get("MemTotal", 0) / 1024), "available_mib": round(kib.get("MemAvailable", 0) / 1024)}
    else:
        cpu.update(model=(_run(["sysctl", "-n", "machdep.cpu.brand_string"]) or "").strip(),
                   physical=int((_run(["sysctl", "-n", "hw.physicalcpu"]) or "0").strip() or 0))
        top = _run(["top", "-l", "1", "-n", "0"]) or ""
        idle = re.search(r"([\d.]+)% idle", top)
        cpu["load_pct"] = round(100 - float(idle.group(1)), 1) if idle else None
        total = int((_run(["sysctl", "-n", "hw.memsize"]) or "0").strip() or 0)
        vm = _run(["vm_stat"]) or ""
        page = int((re.search(r"page size of (\d+)", vm) or [0, 16384])[1])
        free_pages = sum(int(x) for k in ("Pages free", "Pages inactive", "Pages speculative")
                         for x in re.findall(k + r":\s+(\d+)", vm))
        ram = {"total_mib": round(total / 2**20), "available_mib": round(free_pages * page / 2**20)}
    snap["cpu"], snap["ram"] = cpu, ram
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
