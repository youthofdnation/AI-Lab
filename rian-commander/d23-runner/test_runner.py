import hashlib
import hmac
import unittest

from runner import canonical, check

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

if __name__=="__main__":
    unittest.main()
