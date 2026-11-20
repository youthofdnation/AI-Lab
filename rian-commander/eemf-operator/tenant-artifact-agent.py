#!/usr/bin/env python3
"""
RIAN Commander tenant artifact agent (prototype, no auto-install / no auto-execute).
A source agent uploads an approved manifest. A destination agent downloads only
to an explicitly configured inbox and verifies SHA-256 before acknowledgment.

No direct PC-to-PC ports, firewall edits, Tailscale configuration, shell, or
AI-Hub/D23 access. A signed owner consent is required *before* the server creates
the transfer. The agent never receives the owner signing key.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from uuid import UUID

CHUNK_BYTES = 65536
MAX_BYTES = 8 * 1024 * 1024
SHA = re.compile(r"^[a-f0-9]{64}$")
NAME = re.compile(r"^[^/\\\x00-\x1f\x7f<>:\"|?*]{1,120}$")


class TransferError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise TransferError("REDIRECT_BLOCKED")


def sha256(payload):
    return hashlib.sha256(payload).hexdigest()


def valid_id(raw):
    try:
        value = str(UUID(raw))
    except (TypeError, ValueError, AttributeError):
        raise TransferError("INVALID_TRANSFER_ID") from None
    if value != raw.lower():
        raise TransferError("INVALID_TRANSFER_ID")
    return value


def safe_name(raw):
    if not isinstance(raw, str) or not NAME.fullmatch(raw) or raw in (".", ".."):
        raise TransferError("INVALID_FILENAME")
    # Windows rejects reserved basenames and names ending in a dot or space.
    base = raw.split(".", 1)[0].upper()
    if base in {"CON", "PRN", "AUX", "NUL"} or re.fullmatch(r"(COM|LPT)[1-9]", base) or raw.endswith((".", " ")):
        raise TransferError("INVALID_FILENAME")
    return raw


def authorized_path(root, relative, *, must_exist):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise TransferError("APPROVED_ROOT_NOT_DIRECTORY")
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        raise TransferError("INVALID_RELATIVE_PATH")
    user_path = Path(relative)
    if user_path.is_absolute() or any(part in ("..", "", ".") for part in user_path.parts):
        raise TransferError("PATH_OUTSIDE_APPROVED_ROOT")
    candidate = root / user_path
    # Disallow symlink components even when they point back inside the root.
    walk = root
    for part in user_path.parts:
        walk = walk / part
        if walk.is_symlink():
            raise TransferError("SYMLINK_NOT_ALLOWED")
    try:
        result = candidate.resolve(strict=must_exist)
        result.relative_to(root)
    except (ValueError, OSError):
        raise TransferError("PATH_OUTSIDE_APPROVED_ROOT") from None
    return result


class Client:
    def __init__(self, endpoint, bearer, *, allow_test_loopback=False, timeout=20):
        url = urllib.parse.urlsplit(endpoint)
        local_test = (allow_test_loopback and url.scheme == "http" and url.hostname in ("127.0.0.1", "localhost"))
        if (url.scheme != "https" and not local_test) or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
            raise TransferError("HTTPS_RELAY_REQUIRED")
        if not isinstance(bearer, str) or not re.fullmatch(r"[A-Za-z0-9_-]{40,256}", bearer):
            raise TransferError("DEVICE_BEARER_REQUIRED")
        self.url = endpoint.rstrip("/")
        self.bearer = bearer
        self.timeout = timeout
        self.opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        # No test override outside a clearly bound loopback endpoint.
        if local_test and not allow_test_loopback:
            raise TransferError("HTTPS_RELAY_REQUIRED")

    def request(self, method, path, payload=None):
        if not path.startswith("/v2/") or "//" in path or "?" in path or "#" in path:
            raise TransferError("INVALID_API_PATH")
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(
            self.url + path,
            data=data,
            method=method,
            headers={"Authorization": "Bearer " + self.bearer, "Content-Type": "application/json", "Cache-Control": "no-store"},
        )
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                body = response.read(112000)
                obj = json.loads(body.decode("utf-8"))
                if not isinstance(obj, dict):
                    raise TransferError("INVALID_BROKER_RESPONSE")
                return obj
        except urllib.error.HTTPError as err:
            # Do not include response bodies: they may include confidential detail.
            raise TransferError("BROKER_HTTP_" + str(err.code)) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise TransferError("BROKER_UNREACHABLE") from None
        except (UnicodeError, ValueError, json.JSONDecodeError):
            raise TransferError("INVALID_BROKER_RESPONSE") from None


def fetch_manifest(client, transfer_id):
    t = client.request("GET", "/v2/transfers/" + valid_id(transfer_id))
    required = ("transferId", "state", "name", "sizeBytes", "sha256", "chunkBytes", "totalChunks")
    if not all(field in t for field in required):
        raise TransferError("INVALID_MANIFEST")
    if t["transferId"] != transfer_id or not SHA.fullmatch(str(t["sha256"])):
        raise TransferError("INVALID_MANIFEST")
    if not isinstance(t["sizeBytes"], int) or not (1 <= t["sizeBytes"] <= MAX_BYTES) or t["chunkBytes"] != CHUNK_BYTES:
        raise TransferError("UNSUPPORTED_MANIFEST")
    if t["totalChunks"] != (t["sizeBytes"] + CHUNK_BYTES - 1) // CHUNK_BYTES:
        raise TransferError("INVALID_MANIFEST")
    safe_name(t["name"])
    return t


def upload(client, source_root, relative_name, transfer_id):
    path = authorized_path(source_root, relative_name, must_exist=True)
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise TransferError("SOURCE_FILE_INVALID")
    manifest = fetch_manifest(client, transfer_id)
    if manifest["state"] not in ("UPLOADING", "READY"):
        raise TransferError("TRANSFER_NOT_UPLOADABLE")
    if manifest["name"] != path.name:
        raise TransferError("MANIFEST_FILENAME_MISMATCH")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if path.is_symlink():
        raise TransferError("SYMLINK_NOT_ALLOWED")
    with os.fdopen(os.open(path, flags), "rb") as reader:
        content = reader.read(MAX_BYTES + 1)
    if len(content) != manifest["sizeBytes"] or sha256(content) != manifest["sha256"]:
        raise TransferError("SOURCE_HASH_MISMATCH")
    if manifest["state"] == "READY":
        return {"state": "READY", "transferId": transfer_id}
    for i in range(manifest["totalChunks"]):
        block = content[i * CHUNK_BYTES:(i + 1) * CHUNK_BYTES]
        outcome = client.request("PUT", f"/v2/transfers/{transfer_id}/chunks/{i}", {
            "base64": base64.b64encode(block).decode("ascii"),
            "chunkSha256": sha256(block),
        })
        if outcome.get("state") not in ("STORED", "ALREADY_PRESENT"):
            raise TransferError("UPLOAD_CHUNK_REJECTED")
    ready = client.request("POST", f"/v2/transfers/{transfer_id}/finalize")
    if ready.get("state") != "READY":
        raise TransferError("BROKER_FINALIZE_FAILED")
    return {"state": "READY", "transferId": transfer_id}


def download(client, approved_inbox_root, transfer_id):
    root = Path(approved_inbox_root).resolve(strict=True)
    if not root.is_dir():
        raise TransferError("APPROVED_INBOX_INVALID")
    manifest = fetch_manifest(client, transfer_id)
    if manifest["state"] != "READY":
        raise TransferError("TRANSFER_NOT_READY")
    final = authorized_path(root, manifest["name"], must_exist=False)
    if final.exists() or final.is_symlink():
        if final.is_file() and not final.is_symlink() and sha256(final.read_bytes()) == manifest["sha256"]:
            acknowledged = client.request("POST", f"/v2/transfers/{transfer_id}/ack", {"receivedSha256": manifest["sha256"]})
            return {"state": acknowledged.get("state"), "alreadyPresent": True}
        raise TransferError("DESTINATION_EXISTS_DIFFERENT_CONTENT")
    partial = authorized_path(root, ".rian-" + valid_id(transfer_id) + ".part", must_exist=False)
    if partial.exists() and not partial.is_file():
        raise TransferError("INVALID_PARTIAL_FILE")
    # Only the approved inbox root is writable. No unrestricted destination path.
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(partial, flags, 0o600)
    try:
        with os.fdopen(fd, "r+b") as file:
            for i in range(manifest["totalChunks"]):
                resp = client.request("GET", f"/v2/transfers/{transfer_id}/chunks/{i}")
                if resp.get("index") != i or not SHA.fullmatch(str(resp.get("sha256", ""))):
                    raise TransferError("INVALID_CHUNK")
                try:
                    block = base64.b64decode(resp["base64"], validate=True)
                except (KeyError, TypeError, ValueError, base64.binascii.Error):
                    raise TransferError("INVALID_CHUNK") from None
                expected = min(CHUNK_BYTES, manifest["sizeBytes"] - i * CHUNK_BYTES)
                if len(block) != expected or sha256(block) != resp["sha256"]:
                    raise TransferError("CHUNK_HASH_OR_LENGTH_MISMATCH")
                file.seek(i * CHUNK_BYTES)
                existing = file.read(expected)
                if existing != block:
                    file.seek(i * CHUNK_BYTES)
                    file.write(block)
            file.truncate(manifest["sizeBytes"])
            file.flush()
            os.fsync(file.fileno())
        if sha256(partial.read_bytes()) != manifest["sha256"]:
            raise TransferError("FULL_FILE_HASH_MISMATCH")
        # Hard link commits the verified data without overwriting an existing name.
        # Source and destination are both in one approved inbox filesystem.
        try:
            os.link(partial, final)
        except FileExistsError:
            raise TransferError("DESTINATION_CREATED_CONCURRENTLY") from None
        except OSError:
            raise TransferError("ATOMIC_COMMIT_UNAVAILABLE") from None
        partial.unlink()
    except Exception:
        # Leave partial file for safe resume after network loss.
        raise
    acknowledged = client.request("POST", f"/v2/transfers/{transfer_id}/ack", {"receivedSha256": manifest["sha256"]})
    if acknowledged.get("state") != "DELIVERED":
        raise TransferError("DESTINATION_ACK_FAILED")
    return {"state": "DELIVERED", "transferId": transfer_id}


def main(argv=None):
    parser = argparse.ArgumentParser(description="RIAN Commander exact-grant artifact transfer")
    parser.add_argument("action", choices=["upload", "download"])
    parser.add_argument("--transfer-id", required=True)
    parser.add_argument("--file", help="Relative file under approved source root; upload only")
    opts = parser.parse_args(argv)
    try:
        client = Client(os.environ.get("RIAN_ARTIFACT_RELAY_URL", ""), os.environ.get("RIAN_ARTIFACT_DEVICE_TOKEN", ""))
        if opts.action == "upload":
            if not opts.file:
                raise TransferError("SOURCE_FILE_REQUIRED")
            result = upload(client, os.environ.get("RIAN_ARTIFACT_SOURCE_ROOT", ""), opts.file, opts.transfer_id)
        else:
            if opts.file:
                raise TransferError("DOWNLOAD_FILENAME_COMES_FROM_APPROVED_MANIFEST")
            result = download(client, os.environ.get("RIAN_ARTIFACT_INBOX_ROOT", ""), opts.transfer_id)
        print(json.dumps(result))
    except TransferError as err:
        print(json.dumps({"error": str(err)}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
