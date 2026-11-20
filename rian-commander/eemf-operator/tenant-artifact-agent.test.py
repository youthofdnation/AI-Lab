"""RIAN Commander outbound artifact agent: synthetic files and two simulated accounts only."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4
import hashlib
import base64
import os

SPEC = importlib.util.spec_from_file_location('rian_artifact_agent', Path(__file__).with_name('tenant-artifact-agent.py'))
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


class FakeTransfer:
    def __init__(self, contents, name='result.bin'):
        self.id = str(uuid4())
        self.contents = contents
        self.name = name
        self.chunks = {}
        self.state = 'UPLOADING'
        self.call_count = 0
        self.interrupt_after = None
        self.corrupt_download = False

    def client(self, role):
        parent = self

        class FakeClient:
            def request(self, method, path, payload=None):
                parent.call_count += 1
                if parent.interrupt_after is not None and parent.call_count == parent.interrupt_after:
                    raise agent.TransferError('BROKER_UNREACHABLE')
                if not path.startswith('/v2/transfers/'+parent.id):
                    raise agent.TransferError('BROKER_HTTP_404')
                rest = path[len('/v2/transfers/'+parent.id):]
                if method == 'GET' and not rest:
                    return {'transferId':parent.id,'state':parent.state,'name':parent.name,'sha256':agent.sha256(parent.contents),
                        'sizeBytes':len(parent.contents),'totalChunks':(len(parent.contents)+agent.CHUNK_BYTES-1)//agent.CHUNK_BYTES,
                        'chunkBytes':agent.CHUNK_BYTES}
                if method == 'PUT' and role == 'source' and rest.startswith('/chunks/'):
                    i = int(rest.split('/')[-1])
                    chunk = base64.b64decode(payload['base64'])
                    if agent.sha256(chunk) != payload['chunkSha256']:
                        raise agent.TransferError('BROKER_HTTP_409')
                    if i in parent.chunks:
                        return {'index':i,'state':'ALREADY_PRESENT'}
                    parent.chunks[i] = chunk
                    return {'index':i,'state':'STORED'}
                if method == 'POST' and role == 'source' and rest == '/finalize':
                    assembled=b''.join(parent.chunks[i] for i in range(len(parent.chunks)))
                    if assembled != parent.contents:
                        raise agent.TransferError('BROKER_HTTP_409')
                    parent.state='READY'
                    return {'state':'READY'}
                if method == 'GET' and role == 'target' and rest.startswith('/chunks/'):
                    i = int(rest.split('/')[-1])
                    chunk=parent.chunks[i]
                    if parent.corrupt_download:
                        chunk=b'broken'
                    return {'index':i,'base64':base64.b64encode(chunk).decode(),'sha256':agent.sha256(parent.chunks[i])}
                if method == 'POST' and role == 'target' and rest == '/ack' and payload['receivedSha256']==agent.sha256(parent.contents):
                    parent.state='DELIVERED'
                    return {'state':'DELIVERED'}
                raise agent.TransferError('BROKER_HTTP_404')
        return FakeClient()


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.source=self.root/'source'
        self.target=self.root/'inbox'
        self.source.mkdir()
        self.target.mkdir()

    def test_exact_filename_and_sha_approved_transfer(self):
        content=b'RIAN_TEST_ONLY_'*5000
        (self.source/'result.bin').write_bytes(content)
        transfer=FakeTransfer(content)
        source_result=agent.upload(transfer.client('source'),self.source,'result.bin',transfer.id)
        self.assertEqual(source_result['state'],'READY')
        target_result=agent.download(transfer.client('target'),self.target,transfer.id)
        self.assertEqual(target_result['state'],'DELIVERED')
        self.assertEqual((self.target/'result.bin').read_bytes(),content)

    def test_upload_interruption_then_idempotent_retry(self):
        content=os.urandom(agent.CHUNK_BYTES+17)
        (self.source/'result.bin').write_bytes(content)
        t=FakeTransfer(content)
        t.interrupt_after=3
        with self.assertRaisesRegex(agent.TransferError,'BROKER_UNREACHABLE'):
            agent.upload(t.client('source'),self.source,'result.bin',t.id)
        self.assertEqual(len(t.chunks),1)
        t.interrupt_after=None
        self.assertEqual(agent.upload(t.client('source'),self.source,'result.bin',t.id)['state'],'READY')

    def test_download_partial_recovery_after_connection_failure(self):
        content=os.urandom(agent.CHUNK_BYTES+99)
        (self.source/'result.bin').write_bytes(content)
        t=FakeTransfer(content)
        agent.upload(t.client('source'),self.source,'result.bin',t.id)
        t.call_count=0
        t.interrupt_after=3
        with self.assertRaisesRegex(agent.TransferError,'BROKER_UNREACHABLE'):
            agent.download(t.client('target'),self.target,t.id)
        self.assertFalse((self.target/'result.bin').exists())
        self.assertTrue((self.target/('.rian-'+t.id+'.part')).exists())
        t.interrupt_after=None
        self.assertEqual(agent.download(t.client('target'),self.target,t.id)['state'],'DELIVERED')
        self.assertEqual((self.target/'result.bin').read_bytes(),content)

    def test_rejects_bad_source_hash_or_filename_and_never_uploads(self):
        t=FakeTransfer(b'expected')
        (self.source/'result.bin').write_bytes(b'corrupted')
        with self.assertRaisesRegex(agent.TransferError,'SOURCE_HASH_MISMATCH'):
            agent.upload(t.client('source'),self.source,'result.bin',t.id)
        (self.source/'another.bin').write_bytes(b'expected')
        with self.assertRaisesRegex(agent.TransferError,'MANIFEST_FILENAME_MISMATCH'):
            agent.upload(t.client('source'),self.source,'another.bin',t.id)
        self.assertFalse(t.chunks)

    def test_rejects_path_escape_and_symlink(self):
        (self.root/'secrets.txt').write_text('no')
        with self.assertRaises(agent.TransferError):
            agent.authorized_path(self.source,'../secrets.txt',must_exist=True)
        try:
            (self.source/'alias').symlink_to(self.root/'secrets.txt')
        except (OSError, NotImplementedError):
            self.skipTest('Symlinks unavailable on this host')
        with self.assertRaisesRegex(agent.TransferError,'SYMLINK_NOT_ALLOWED'):
            agent.authorized_path(self.source,'alias',must_exist=True)

    def test_failed_destination_checksum_must_not_ack(self):
        content=b'a'*100
        (self.source/'result.bin').write_bytes(content)
        t=FakeTransfer(content)
        agent.upload(t.client('source'),self.source,'result.bin',t.id)
        t.corrupt_download=True
        with self.assertRaisesRegex(agent.TransferError,'CHUNK_HASH_OR_LENGTH_MISMATCH'):
            agent.download(t.client('target'),self.target,t.id)
        self.assertEqual(t.state,'READY')
        self.assertFalse((self.target/'result.bin').exists())

    def test_existing_different_file_not_overwritten(self):
        content=b'approved'
        (self.source/'result.bin').write_bytes(content)
        (self.target/'result.bin').write_bytes(b'existing customer file')
        t=FakeTransfer(content)
        agent.upload(t.client('source'),self.source,'result.bin',t.id)
        with self.assertRaisesRegex(agent.TransferError,'DESTINATION_EXISTS_DIFFERENT_CONTENT'):
            agent.download(t.client('target'),self.target,t.id)
        self.assertEqual((self.target/'result.bin').read_bytes(),b'existing customer file')

    def test_existing_exact_file_allows_ack_retry_after_network_failure(self):
        content=b'approved'
        (self.source/'result.bin').write_bytes(content)
        (self.target/'result.bin').write_bytes(content)
        t=FakeTransfer(content)
        agent.upload(t.client('source'),self.source,'result.bin',t.id)
        result=agent.download(t.client('target'),self.target,t.id)
        self.assertEqual(result['state'],'DELIVERED')
        self.assertTrue(result['alreadyPresent'])

    def test_no_public_plain_http_or_invalid_device_token(self):
        with self.assertRaisesRegex(agent.TransferError,'HTTPS_RELAY_REQUIRED'):
            agent.Client('http://example.com','A'*48)
        with self.assertRaisesRegex(agent.TransferError,'HTTPS_RELAY_REQUIRED'):
            agent.Client('http://127.0.0.1:4000','A'*48)
        with self.assertRaisesRegex(agent.TransferError,'DEVICE_BEARER_REQUIRED'):
            agent.Client('https://relay.example','tiny')
        agent.Client('http://127.0.0.1:4000','A'*48,allow_test_loopback=True)

    def test_bad_uuid_denied(self):
        for bad in ('../meta','abc','', 'not-a-valid-id'):
            with self.assertRaises(agent.TransferError):
                agent.valid_id(bad)


if __name__=='__main__':
    unittest.main()
