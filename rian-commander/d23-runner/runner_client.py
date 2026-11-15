#!/usr/bin/env python3
"""One-shot, opt-in D23 runner client. Not an always-on service."""
import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from runner import DEVICE, execute, check, OUT

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirect_denied")

def post(base, endpoint, obj, bearer):
    url = urlparse(base)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
        raise ValueError("invalid_broker_origin")
    if endpoint not in ("/v1/d23/lease","/v1/d23/complete"):
        raise ValueError("endpoint_denied")
    if not isinstance(bearer,str) or len(bearer)<48:
        raise ValueError("runner_identity_missing")
    payload=json.dumps(obj,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    if len(payload)>4096:raise ValueError("request_too_large")
    req=Request(base.rstrip("/")+endpoint,data=payload,method="POST",
                headers={"Content-Type":"application/json","Authorization":"Bearer "+bearer,"Accept":"application/json"})
    opener=build_opener(NoRedirect)
    try:
        with opener.open(req,timeout=20) as resp:
            raw=resp.read(8193)
            if len(raw)>8192 or resp.status!=200:raise ValueError("bad_server_response")
            return json.loads(raw)
    except (HTTPError,URLError) as e:
        raise ValueError("broker_unavailable") from e

def run_once(base,runner_token,signing_key,output=OUT):
    if not isinstance(signing_key,bytes) or len(signing_key)<32:raise ValueError("task_signing_key_missing")
    job=post(base,"/v1/d23/lease",{"device":DEVICE},runner_token)
    if job is None:return {"status":"no_approved_job"}
    if not isinstance(job,dict) or set(job)!={"job_id","manifest"}:
        raise ValueError("unexpected_job_fields")
    if not isinstance(job["job_id"],str) or len(job["job_id"])<16:
        raise ValueError("invalid_job_id")
    check(job["manifest"],signing_key)
    path=execute(job["manifest"],signing_key,folder=output)
    result=post(base,"/v1/d23/complete",
                {"job_id":job["job_id"],"nonce":job["manifest"]["payload"]["nonce"],"result_path":path.name},
                runner_token)
    return {"status":"completed" if result.get("state")=="COMPLETE" else "unconfirmed",
            "result_path":str(path)}

if __name__=="__main__":
    args=argparse.ArgumentParser()
    args.add_argument("--once",action="store_true",required=True,
                      help="Run exactly one approved D23 observation job, if available.")
    opt=args.parse_args()
    base=os.environ.get("RIAN_D23_BROKER_URL","")
    runner_token=os.environ.get("RIAN_D23_RUNNER_TOKEN","")
    signing_key=os.environ.get("RIAN_D23_TASK_KEY","").encode("utf-8")
    print(json.dumps(run_once(base,runner_token,signing_key),ensure_ascii=False))
