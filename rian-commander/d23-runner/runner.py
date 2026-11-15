#!/usr/bin/env python3
"""RIAN D23 local-only allowlisted observation helper. No remote broker."""
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess

DEVICE="DESKTOP-1QGT8D6"
TASK="D23_AUDIT_READONLY_V1"
OUT=Path(r"C:\Users\M\salpion-d23-readonly") if os.name=="nt" else Path.cwd()/"d23-readonly"

def canonical(v):
    return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def check(document,key,now=None):
    if not isinstance(document,dict) or set(document)!={"payload","mac"}:raise ValueError("manifest_fields")
    p=document["payload"]
    if not isinstance(p,dict) or set(p)!={"device","task","issued_at","expires_at","nonce"}:raise ValueError("payload_fields")
    if p["device"]!=DEVICE or p["task"]!=TASK:raise ValueError("scope_denied")
    if not isinstance(p["nonce"],str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,64}",p["nonce"]):raise ValueError("nonce_invalid")
    if not isinstance(p["issued_at"],int) or not isinstance(p["expires_at"],int):raise ValueError("invalid_times")
    t=int(now if now is not None else dt.datetime.now(dt.timezone.utc).timestamp())
    if p["issued_at"]>t+30 or p["expires_at"]<=t or p["expires_at"]-p["issued_at"]>300:raise ValueError("expired")
    signature=document["mac"]
    if not isinstance(signature,str) or not re.fullmatch("[a-f0-9]{64}",signature):raise ValueError("mac_invalid")
    if not hmac.compare_digest(hmac.new(key,canonical(p),hashlib.sha256).hexdigest(),signature):raise ValueError("invalid_signature")
    return p

def observed(argv):
    try:
        q=subprocess.run(argv,shell=False,stdin=subprocess.DEVNULL,capture_output=True,
                         text=True,encoding="utf-8",errors="replace",timeout=15)
        return {"exit":q.returncode,"stdout":q.stdout[:1500],"stderr":q.stderr[:400]}
    except (FileNotFoundError,subprocess.TimeoutExpired,OSError) as e:
        return {"status":"unavailable","reason":type(e).__name__}

def collect():
    v={"device":DEVICE,"checked_at_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
       "d23_training":"UNKNOWN","gpu":observed(["nvidia-smi","--query-gpu=name,memory.total,memory.used,memory.free","--format=csv,noheader,nounits"])}
    if os.name=="nt":
        v["python_processes"]=observed(["powershell.exe","-NoProfile","-NonInteractive",
           "-Command",'Get-CimInstance Win32_Process -Filter "Name=\'python.exe\' or Name=\'pythonw.exe\'" | Select-Object ProcessId,CreationDate | ConvertTo-Json -Compress'])
    return v

def execute(doc,key,folder=OUT,now=None):
    p=check(doc,key,now)
    if os.name=="nt" and folder.resolve()!=OUT.resolve():raise ValueError("output_root_denied")
    folder.mkdir(parents=True,exist_ok=True)
    (folder/(".nonce-"+p["nonce"])).open("x").close()
    result=collect()
    result["request_nonce_hash"]=hashlib.sha256(p["nonce"].encode()).hexdigest()[:16]
    stamp=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    target=folder/("status-"+stamp+".json")
    with target.open("x",encoding="utf-8") as f:json.dump(result,f,ensure_ascii=False,indent=2)
    return target

if __name__=="__main__":
    import argparse
    ap=argparse.ArgumentParser()
    ap.add_argument("--manifest",type=Path,required=True)
    a=ap.parse_args()
    key=os.environ.get("RIAN_D23_TASK_KEY","").encode()
    if len(key)<32:ap.error("local task key unavailable")
    doc=json.loads(a.manifest.read_text(encoding="utf-8"))
    print(json.dumps({"ok":True,"result_path":str(execute(doc,key))},ensure_ascii=False))
