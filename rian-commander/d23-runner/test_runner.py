import hashlib
import hmac
import unittest

from runner import canonical, check, execute
import tempfile
import json
from pathlib import Path
from unittest.mock import patch

KEY=b"A"*40
TIME=1794730000

def document(**updates):
    p={"device":"DESKTOP-1QGT8D6","task":"D23_AUDIT_READONLY_V1",
       "issued_at":TIME-1,"expires_at":TIME+120,"nonce":"ABCDEFGHIJKLMNopqr234"}
    p.update(updates)
    return {"payload":p,"mac":hmac.new(KEY,canonical(p),hashlib.sha256).hexdigest()}

class RunnerSafetyTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(check(document(),KEY,TIME)["task"],"D23_AUDIT_READONLY_V1")
    def test_wrong_key(self):
        with self.assertRaisesRegex(ValueError,"invalid_signature"):check(document(),b"B"*40,TIME)
    def test_wrong_device(self):
        with self.assertRaisesRegex(ValueError,"scope_denied"):check(document(device="OTHER"),KEY,TIME)
    def test_command_denied(self):
        with self.assertRaisesRegex(ValueError,"scope_denied"):check(document(task="RUN_COMMAND"),KEY,TIME)
    def test_expired(self):
        with self.assertRaisesRegex(ValueError,"expired"):check(document(expires_at=TIME-1),KEY,TIME)
    def test_overlong_lifetime(self):
        with self.assertRaisesRegex(ValueError,"expired"):check(document(expires_at=TIME+999),KEY,TIME)
    def test_tampering(self):
        x=document()
        x["payload"]["nonce"]="differentNonceABCDEFG"
        with self.assertRaisesRegex(ValueError,"invalid_signature"):check(x,KEY,TIME)
    def test_extra_arguments(self):
        x=document()
        x["payload"]["argv"]=["cmd.exe"]
        with self.assertRaisesRegex(ValueError,"payload_fields"):check(x,KEY,TIME)
    def test_bad_nonce(self):
        with self.assertRaisesRegex(ValueError,"nonce_invalid"):check(document(nonce="../a"),KEY,TIME)
    def test_short_key_rejected(self):
        with self.assertRaisesRegex(ValueError,"key_missing"):check(document(),b"small",TIME)
    def test_none_key_rejected(self):
        with self.assertRaisesRegex(ValueError,"key_missing"):check(document(),None,TIME)
    def test_zero_duration_rejected(self):
        with self.assertRaisesRegex(ValueError,"expired"):check(document(issued_at=TIME+1,expires_at=TIME+1),KEY,TIME)
    def test_invalid_timestamp_type(self):
        with self.assertRaisesRegex(ValueError,"invalid_times"):check(document(issued_at="not_time"),KEY,TIME)
    def test_unexpected_top_level_fields(self):
        d=document();d["argv"]=["cmd.exe"]
        with self.assertRaisesRegex(ValueError,"manifest_fields"):check(d,KEY,TIME)
    def test_future_issued_at(self):
        with self.assertRaisesRegex(ValueError,"expired"):check(document(issued_at=TIME+35,expires_at=TIME+200),KEY,TIME)

    def test_full_local_handoff_and_replay_protection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            with patch("runner.OUT",root),patch("runner.collect",return_value={"device":"DESKTOP-1QGT8D6","d23_training":"UNKNOWN"}):
                dest=execute(document(),KEY,folder=root,now=TIME)
                self.assertTrue(dest.exists())
                result=json.loads(dest.read_text(encoding="utf-8"))
                self.assertEqual(result["d23_training"],"UNKNOWN")
                self.assertEqual(result["device"],"DESKTOP-1QGT8D6")
                self.assertIn("request_nonce_hash",result)
                self.assertNotIn("mac",result)
                with self.assertRaises(FileExistsError):
                    execute(document(),KEY,folder=root,now=TIME)
                self.assertEqual(len(list(root.glob("status-*.json"))),1)

    def test_failed_signature_does_not_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            with patch("runner.OUT",root):
                with self.assertRaisesRegex(ValueError,"invalid_signature"):
                    execute(document(),b"Z"*40,folder=root,now=TIME)
                self.assertEqual(list(root.iterdir()),[])

if __name__=="__main__":
    unittest.main()
