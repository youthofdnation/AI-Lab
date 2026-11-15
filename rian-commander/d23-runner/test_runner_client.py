import hashlib
import hmac
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from runner import canonical, DEVICE, TASK
from runner_client import run_once, post

KEY=b"Z"*48
TOKEN="R"*64

def job():
    payload={"device":DEVICE,"task":TASK,"issued_at":1794750000,
             "expires_at":1794750240,"nonce":"abcdefghijk123456789"}
    return {"job_id":"abcdefghijklmnop01234567",
            "manifest":{"payload":payload,"mac":hmac.new(KEY,canonical(payload),hashlib.sha256).hexdigest()}}

class ClientTests(unittest.TestCase):
    def test_non_https_origin_rejected_without_network(self):
        with self.assertRaisesRegex(ValueError,"invalid_broker_origin"):
            post("http://untrusted.example","/v1/d23/lease",{"device":DEVICE},TOKEN)
    def test_no_redirect_target_accepted(self):
        with self.assertRaisesRegex(ValueError,"invalid_broker_origin"):
            post("https://broker.example/unsafe","/v1/d23/lease",{"device":DEVICE},TOKEN)
    def test_unauthorized_endpoint_denied(self):
        with self.assertRaisesRegex(ValueError,"endpoint_denied"):
            post("https://broker.example","/v1/d23/run_command",{},TOKEN)
    def test_runner_token_is_required(self):
        with self.assertRaisesRegex(ValueError,"runner_identity_missing"):
            post("https://broker.example","/v1/d23/lease",{"device":DEVICE},"weak")
    def test_no_job_runs_nothing(self):
        with patch("runner_client.post",return_value=None) as call, patch("runner_client.execute") as exec_task:
            result=run_once("https://broker.example",TOKEN,KEY)
            self.assertEqual(result["status"],"no_approved_job")
            self.assertEqual(call.call_count,1)
            exec_task.assert_not_called()
    def test_bad_manifest_never_executes(self):
        j=job()
        j["manifest"]["payload"]["task"]="run_command"
        with patch("runner_client.post",return_value=j), patch("runner_client.execute") as exec_task:
            with self.assertRaisesRegex(ValueError,"scope_denied"):
                run_once("https://broker.example",TOKEN,KEY)
            exec_task.assert_not_called()
    def test_valid_task_acknowledged(self):
        j=job()
        with tempfile.TemporaryDirectory() as tmp:
            file=Path(tmp)/"status-20261115-190000-abcdef12.json"
            with patch("runner_client.post",side_effect=[j,{"job_id":j["job_id"],"state":"COMPLETE"}]) as remote, patch("runner_client.execute",return_value=file) as exec_task, patch("runner_client.check",return_value=j["manifest"]["payload"]):
                result=run_once("https://broker.example",TOKEN,KEY)
                self.assertEqual(result["status"],"completed")
                self.assertEqual(exec_task.call_count,1)
                self.assertEqual(remote.call_count,2)
                self.assertEqual(remote.call_args_list[-1].args[1],"/v1/d23/complete")
    def test_short_signing_key(self):
        with patch("runner_client.post") as remote:
            with self.assertRaisesRegex(ValueError,"task_signing_key_missing"):
                run_once("https://broker.example",TOKEN,b"bad")
            remote.assert_not_called()

if __name__=="__main__":
    unittest.main()
