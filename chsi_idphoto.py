#!/usr/bin/env python3
"""CHSI 2.6.1 idphoto transport, reconstructed from the supplied APK.

No face recognition, liveness signal, image alteration, or server approval is
implemented. Default live mode uploads the bytes and reports the OSS receipt;
the separate final-confirmation endpoint is only called with --confirm.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
from email.message import Message
import hashlib
import json
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

import requests
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


VERSION = "2.6.1"
BOOTSTRAP_URL = "https://account.chsi.com.cn/passport/d1/device"
API = "https://appapi.chsi.com.cn/idphoto/v1/"
IV = b"A-16-Byte-String"
URI_SAFE = "_-.!~'()*"
USER_AGENT = (
    "Dalvik/2.1.0 (Linux; U; Android 7.0; Android SDK built for x86_64 "
    "Build/NYC) volley/129 ChesiccApp/2.6.1"
)
# Public verification/encryption key: strings.xml:k1 + 7662 + 7660 + 7661.
# This is a PUBLIC key from the APK, not an account credential.
BOOTSTRAP_KEY_B64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtun9BqHsnm630ep6XvvOG2z1"
    "HttoQpa1BJF5xYrn0iA1K2j2M8nDDe46qvbremzsBtCCmnzt8HRIUXJPB4JhajWGUaq"
    "Hc2wARhsSK7UT+ztLEleYHCa1YYL745Q8DFmWgC8Xffc56gTLeDCColBp2EOK5Xa8CNcy"
    "pixlkxZFxCpkdBTHRCKluRhk7RPX9evgDlRQZ2FnYxd8P+DrIHLs+Vfw1/FZwLL8/kcg3"
    "SxaEIqtLAce/yZxsbXZs1PvofRM3bBCDjlNcM/AkB3fQnMYqdZTRoIJSnhRoRCqJWlu9d"
    "oMVg1jBfyNcQja3O85Hk0XtCzz6eUoHegXat7TnoWpqwIDAQAB"
)
DEVICE_INFO = {
    "width": 1080, "height": 1920, "manufacturer": "Google",
    "product": "sdk_google_phone_x86_64", "brand": "Android",
    "model": "Android SDK built for x86_64", "board": "goldfish_x86_64",
    "device": "generic_x86_64", "sdk": 24, "release": "7.0",
}


class ClientError(Exception):
    def __init__(self, stage: str, message: str, code=None):
        super().__init__(message)
        self.stage = stage
        self.code = code


def compact(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def android_b64(data: bytes) -> str:
    # android.util.Base64.DEFAULT: LF every 76 characters plus a trailing LF.
    return base64.encodebytes(data).decode("ascii")


def public_key(value: str):
    if "-----BEGIN" in value:
        key = serialization.load_pem_public_key(value.encode("ascii"))
    else:
        key = serialization.load_der_public_key(base64.b64decode(value))
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Expected an RSA public key")
    return key


def public_key_b64(key) -> str:
    return base64.b64encode(key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )).decode("ascii")


def aes_encrypt(data: bytes, key: bytes) -> str:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    ctx = Cipher(algorithms.AES(key), modes.CBC(IV)).encryptor()
    return android_b64(ctx.update(padded) + ctx.finalize())


def aes_decrypt(value: str, key: bytes) -> bytes:
    ctx = Cipher(algorithms.AES(key), modes.CBC(IV)).decryptor()
    padded = ctx.update(base64.b64decode(value)) + ctx.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def rsa_public_recover(value: str, key) -> bytes:
    """Java Cipher(DECRYPT_MODE, publicKey), PKCS#1 v1.5 type 1.

    The server seals the bootstrap response with its private key. The app
    recovers a Base64-encoded key string with the public key, then decodes it.
    The returned bytes are still Base64 text; a.b() decodes them once again.
    """
    encrypted = base64.b64decode(value)
    size = (key.key_size + 7) // 8
    if len(encrypted) != size:
        raise ValueError("Invalid bootstrap RSA block length")
    numbers = key.public_numbers()
    cipher_int = int.from_bytes(encrypted, "big")
    if cipher_int >= numbers.n:
        raise ValueError("Invalid bootstrap RSA block value")
    block = pow(cipher_int, numbers.e, numbers.n).to_bytes(size, "big")
    sep = block.find(b"\0", 2)
    if block[:2] != b"\0\x01" or sep < 10 or block[2:sep] != b"\xff" * (sep - 2):
        raise ValueError("Invalid bootstrap RSA padding")
    return base64.b64decode(block[sep + 1:])


def envelope(payload: dict, key, did: str | None = None) -> dict:
    session_key = uuid.uuid4().hex.encode("ascii")
    wrapped_key = android_b64(key.encrypt(
        android_b64(session_key).encode("ascii"), rsa_padding.PKCS1v15()))
    wrapped_data = aes_encrypt(compact(payload).encode("utf-8"), session_key)
    if did is None:  # Bootstrap does not Uri.encode k/d.
        return {"k": wrapped_key, "d": wrapped_data}
    return {
        "did": did, "v": "v1",
        "k": quote(wrapped_key, safe=URI_SAFE),
        "d": quote(wrapped_data, safe=URI_SAFE),
    }


def parse_qr(value: str) -> str:
    value = value.strip()
    parts = urlsplit(value)
    if parts.scheme != "chesicc" or parts.netloc != "idphoto":
        raise ValueError("Expected chesicc://idphoto/<opaque-token>")
    if parts.query or parts.fragment or not parts.path.startswith("/"):
        raise ValueError("Unexpected QR URL query, fragment, or path")
    # Uri.getPath decodes percent escapes, but never turns '+' into a space.
    issue_id = unquote(parts.path[1:]).strip()
    if not issue_id or any(c in issue_id for c in "\r\n\0"):
        raise ValueError("Empty or invalid QR token")
    return issue_id


def load_did(path: Path) -> str:
    if path.exists():
        value = json.loads(path.read_text(encoding="utf-8"))["did"]
        uuid.UUID(value)
        return value
    value = uuid.uuid4().hex
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"did": value}, indent=2), encoding="utf-8")
    return value


def as_object(value, stage: str) -> dict:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict):
        raise ClientError(stage, "Expected a JSON object")
    return value


def save_checkpoint(path: Path | None, data: dict):
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def status_summary(data: dict) -> dict:
    result = dict(data)
    photo = result.pop("photo", None)
    if photo:
        decoded = base64.b64decode(photo)
        result["photo_received"] = {"bytes": len(decoded),
                                    "sha256": hashlib.sha256(decoded).hexdigest()}
    return result


def signature_is_fresh(sign: dict) -> bool:
    if not sign.get("expiration"):
        return False
    try:
        expiration = datetime.fromisoformat(str(sign["expiration"]).replace("Z", "+00:00"))
        if expiration.tzinfo is None:
            return False
        return expiration.timestamp() > time.time() + 30
    except ValueError:
        return False


class IdPhotoClient:
    def __init__(self, did: str, session=None, timeout: float = 30,
                 bootstrap_key=None, progress=None):
        self.did = did
        self.session = session if session is not None else requests.Session()
        self.timeout = timeout
        self.bootstrap_key = bootstrap_key or public_key(BOOTSTRAP_KEY_B64)
        self.key = None
        self.jwt = None
        self.progress = progress or (lambda stage: None)

    def post(self, url: str, payload: dict, stage: str, authorization=None) -> dict:
        self.progress(stage)
        headers = {"User-Agent": USER_AGENT,
                   "Content-Type": "application/json; charset=utf-8"}
        if authorization:
            # B.java passes the returned JWT verbatim; no added "Bearer ".
            headers["Authorization"] = authorization
        try:
            response = self.session.post(
                url, data=compact(payload).encode("utf-8"), headers=headers,
                timeout=self.timeout, allow_redirects=False)
        except requests.RequestException as exc:
            raise ClientError(stage, type(exc).__name__ + ": network request failed") from exc
        try:
            # APK defaults to UTF-8, respecting only an explicit charset.
            content_type = Message()
            content_type["Content-Type"] = response.headers.get("Content-Type", "")
            charset = content_type.get_content_charset() or "utf-8"
            result = as_object(json.loads(response.content.decode(charset)), stage)
        except (ValueError, ClientError) as exc:
            raise ClientError(stage, f"HTTP {response.status_code}: non-JSON response") from exc
        if not 200 <= response.status_code < 300:
            raise ClientError(stage, str(result.get("message") or result.get("error_msg")
                                         or f"HTTP {response.status_code}"), result.get("code"))
        return result

    def bootstrap(self):
        payload = {"appId": self.did, "deviceInfo": DEVICE_INFO,
                   "appVersion": VERSION, "deviceType": "android"}
        result = self.post(BOOTSTRAP_URL, envelope(payload, self.bootstrap_key), "bootstrap")
        if str(result.get("code")) not in {"000000", "000008"}:
            raise ClientError("bootstrap", str(result.get("error_msg") or result.get("message")
                                               or "Device initialization failed"), result.get("code"))
        wrapped = as_object(result.get("data"), "bootstrap")
        try:
            session_key = base64.b64decode(rsa_public_recover(wrapped["k"], self.bootstrap_key))
            config = json.loads(aes_decrypt(wrapped["d"], session_key))
            self.key = public_key(config["publicKey"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ClientError("bootstrap", "Cannot decode service public key: " + str(exc)) from exc
        return {"code": result["code"], "service_key_sha256": hashlib.sha256(
            self.key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()}

    def business(self, path: str, payload: dict, authenticated=True) -> dict:
        if self.key is None:
            raise ClientError(path, "Bootstrap is required")
        result = self.post(API + path, envelope(payload, self.key, self.did), path,
                           self.jwt if authenticated else None)
        if str(result.get("code", "FAIL")).upper() != "SUCCESS":
            raise ClientError(path, str(result.get("message") or "Business request rejected"),
                              result.get("code"))
        return as_object(result.get("data"), path)

    def check(self, issue_id: str, uid: str | None = None) -> dict:
        payload = {"issueId": issue_id}
        if uid:
            payload["uid"] = uid
        data = self.business("check", payload, authenticated=False)
        if not data.get("jwt") or not data.get("captureId"):
            raise ClientError("check", "Response has no jwt or captureId")
        self.jwt = data["jwt"]
        return data

    def upload(self, sign: dict, jpg: Path) -> dict:
        self.progress("oss-upload")
        fields = {
            "key": sign["objectKey"],
            "OSSAccessKeyId": sign["xOssCredential"].split("/")[0],
            "x-oss-credential": sign["xOssCredential"], "policy": sign["policy"],
            "x-oss-signature": sign["signature"], "Signature": sign["signature"],
            "x-oss-security-token": sign["securityToken"],
            "x-oss-date": sign["xOssDate"], "x-oss-signature-version": sign["version"],
            "success_action_status": str(sign["successActionStatus"]),
        }
        host = sign["host"]
        parsed_host = urlsplit(host)
        if parsed_host.scheme == "http":
            # The service currently returns an HTTP OSS host. OSS also serves
            # this same hostname over TLS; the form signature is unchanged.
            host = parsed_host._replace(scheme="https").geturl()
        elif parsed_host.scheme != "https":
            raise ClientError("oss-upload", "OSS host is not HTTPS")
        headers = {"User-Agent": USER_AGENT}
        if sign.get("origin"):
            headers["Origin"] = sign["origin"]
        filename = sign["objectKey"].rsplit("/", 1)[-1]
        # A fresh session prevents CHSI cookies/Authorization leaking to OSS.
        uploader = self.session if isinstance(self.session, SimulationSession) else requests.Session()
        try:
            with jpg.open("rb") as stream:
                response = uploader.post(
                    host, data=fields, files={"file": (filename, stream, "image/jpeg")},
                    headers=headers, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException as exc:
            raise ClientError("oss-upload", type(exc).__name__ + ": network request failed") from exc
        finally:
            if uploader is not self.session:
                uploader.close()
        if not 200 <= response.status_code < 300:
            detail = ""
            try:
                root = ET.fromstring(response.content)
                detail = ": " + str(root.findtext("Code") or "") + " " + str(root.findtext("Message") or "")
            except (ET.ParseError, AttributeError):
                pass
            raise ClientError("oss-upload", f"OSS returned HTTP {response.status_code}" + detail)
        etag = response.headers.get("ETag", "")
        if not etag and response.status_code == 201:
            try:
                root = ET.fromstring(response.content)
                etag = next((node.text or "" for node in root.iter()
                             if node.tag.rsplit("}", 1)[-1] == "ETag"), "")
            except (ET.ParseError, AttributeError):
                pass
        etag = etag.replace('"', "")
        if not etag:
            # Android request a.I accepts ETag from the header, not an assumed MD5.
            raise ClientError("oss-upload", "OSS accepted bytes but returned no ETag")
        return {"http_status": response.status_code, "etag": etag}

    def run(self, qr: str, jpg: Path, *, bg_color="DEFAULT", uid=None,
            wait_seconds=0, confirm=False, report=None, session_path: Path | None = None) -> dict:
        result = report if report is not None else {}
        result.update({"mode": "simulation" if isinstance(self.session, SimulationSession) else "live",
                       "storage_uploaded": False, "receipt_accepted": False,
                       "confirmed": False, "server_status": None})
        issue_id = parse_qr(qr)
        qr_hash = hashlib.sha256(issue_id.encode("utf-8")).hexdigest()
        file_hash = hashlib.sha256(jpg.read_bytes()).hexdigest()
        context = {}
        if session_path is not None and session_path.exists():
            context = as_object(json.loads(session_path.read_text(encoding="utf-8")), "resume")
            if context.get("qr_hash") != qr_hash or context.get("did") != self.did:
                raise ClientError("resume", "Session does not match the QR or installation UUID")
            if context.get("upload") and (context.get("file_sha256") != file_hash
                                         or context.get("bg_color") != bg_color):
                raise ClientError("resume", "This session already uploaded another file/background choice")
            if context.get("check_pending") and not context.get("check"):
                raise ClientError("resume", "A previous QR check has an uncertain result; refresh the QR instead of rescanning")
        if not context:
            context = {"qr_hash": qr_hash, "did": self.did,
                       "file_sha256": file_hash, "bg_color": bg_color}
            # Ensure the directory and state file are writable BEFORE consuming
            # a one-use QR. A check with an uncertain outcome is never retried.
            save_checkpoint(session_path, context)
        result["bootstrap"] = self.bootstrap()
        if context.get("check"):
            check = context["check"]
            self.jwt = check["jwt"]
            result["resumed"] = True
        else:
            context["check_pending"] = True
            save_checkpoint(session_path, context)
            check = self.check(issue_id, uid)
            context.update({"check": check, "check_pending": False})
            # check consumes a one-use QR. Persist its JWT/captureId BEFORE
            # attempting the signature or upload, so retries never rescan it.
            save_checkpoint(session_path, context)
            result["resumed"] = False
        capture_id = check["captureId"]
        common = {"issueId": issue_id, "captureId": capture_id}
        with_bg = {**common, "bgColor": bg_color}
        result["task_tip"] = check.get("tip", "")
        if context.get("upload"):
            upload_result = context["upload"]
            sts_id = context["sts_id"]
        else:
            sign = context.get("pending_sign", {})
            if not signature_is_fresh(sign):
                sign = self.business("capture/osssign", with_bg)
            for field in ("stsId", "host", "objectKey", "xOssCredential", "policy", "signature",
                          "securityToken", "xOssDate", "version", "successActionStatus"):
                if not sign.get(field):
                    raise ClientError("capture/osssign", "Missing signature field: " + field)
            sts_id = sign["stsId"]
            context["pending_sign"] = sign
            save_checkpoint(session_path, context)
            upload_result = self.upload(sign, jpg)
            context.update({"upload": upload_result, "sts_id": sts_id,
                            "file_sha256": file_hash, "bg_color": bg_color})
            context.pop("pending_sign", None)
            save_checkpoint(session_path, context)
        result["storage_uploaded"] = True
        result["upload"] = upload_result
        if context.get("receipt") is not None:
            receipt = context["receipt"]
        else:
            receipt = self.business("capture/ossrs", {
                **with_bg, "stsId": sts_id, "eTag": upload_result["etag"],
            })
            if float(receipt.get("timeout", 0)) <= 0 or float(receipt.get("interval", 0)) <= 0:
                raise ClientError("capture/ossrs", "Receipt has no valid timeout/interval")
            context["receipt"] = receipt
            save_checkpoint(session_path, context)
        result["receipt_accepted"] = True
        result["receipt"] = receipt
        result["server_status"] = context.get("server_status")
        if context.get("confirmation") is not None:
            result["confirmation"] = context["confirmation"]
            result["confirmed"] = True
            return result
        if wait_seconds > 0 or confirm:
            deadline = time.monotonic() + max(wait_seconds, 1)
            interval = 3  # g.o(): normal successful PROCESSING interval.
            while True:
                status = self.business("capture/checkst", common)
                result["server_status"] = status_summary(status)
                context["server_status"] = result["server_status"]
                save_checkpoint(session_path, context)
                state = str(status.get("status", ""))
                if state == "QUALITY_CHECKING":
                    break
                if state == "EXP" or state != "PROCESSING":
                    if confirm:
                        raise ClientError("confirm", "Confirmation not completed; server status: " + state)
                    return result  # Preserve unfamiliar states; never assume acceptance.
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    result["poll_timed_out"] = True
                    if confirm:
                        raise ClientError("confirm", "Timed out before confirmation became available")
                    return result
                time.sleep(min(interval, remaining))
        if confirm:
            if (result.get("server_status") or {}).get("status") != "QUALITY_CHECKING":
                raise ClientError("confirm", "Task has not reached QUALITY_CHECKING")
            if str(result["server_status"].get("confirmPhoto", "")) != "1":
                raise ClientError("confirm", "Server has not enabled confirmPhoto")
            result["confirmation"] = self.business("capture/confirm", common)
            result["confirmed"] = True
            context["confirmation"] = result["confirmation"]
            save_checkpoint(session_path, context)
        return result


class SimulationResponse:
    def __init__(self, data=None, *, status=200, headers=None):
        self.data = data
        self.status_code = status
        self.headers = headers or {}
        self.content = compact(data).encode("utf-8") if data is not None else b""

    def json(self):
        return self.data


class SimulationSession:
    """In-memory peer that independently decrypts and validates each request.

    No network request is made. Synthetic RSA keys/JWT/OSS credentials are used.
    The real photo is read, prepared as multipart, and compared byte-for-byte.
    """
    def __init__(self, jpg: Path):
        self.bootstrap_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.service_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.expected_bytes = jpg.read_bytes()
        self.calls = []
        self.issue_id = None
        self.did = None
        self.jwt = "simulation-jwt"
        self.etag = hashlib.md5(self.expected_bytes).hexdigest()

    @staticmethod
    def unwrap(body, private):
        encoded_key = unquote(body["k"]) if "did" in body else body["k"]
        encoded_data = unquote(body["d"]) if "did" in body else body["d"]
        key = base64.b64decode(private.decrypt(base64.b64decode(encoded_key), rsa_padding.PKCS1v15()))
        return json.loads(aes_decrypt(encoded_data, key))

    def bootstrap_response(self):
        key = uuid.uuid4().hex.encode("ascii")
        message = android_b64(android_b64(key).encode("ascii")).encode("ascii")
        size = (self.bootstrap_private.key_size + 7) // 8
        block = b"\0\x01" + b"\xff" * (size - len(message) - 3) + b"\0" + message
        numbers = self.bootstrap_private.private_numbers()
        signed = pow(int.from_bytes(block, "big"), numbers.d, numbers.public_numbers.n).to_bytes(size, "big")
        return {"code": "000000", "data": {
            "k": android_b64(signed),
            "d": aes_encrypt(compact({"publicKey": public_key_b64(
                self.service_private.public_key())}).encode(), key)}}

    def post(self, url, *, data, headers, timeout, allow_redirects, files=None):
        assert allow_redirects is False
        self.calls.append(url)
        if url == BOOTSTRAP_URL:
            payload = self.unwrap(json.loads(data), self.bootstrap_private)
            assert payload["deviceType"] == "android"
            assert payload["appVersion"] == VERSION
            self.did = payload["appId"]
            return SimulationResponse(self.bootstrap_response())
        if url == "https://simulation.invalid/oss":
            assert "Authorization" not in headers and "Cookie" not in headers
            assert data["key"] == "simulation/photo.jpg"
            assert data["x-oss-signature"] == data["Signature"] == "simulation-signature"
            assert data["OSSAccessKeyId"] == "simulation-access-id"
            assert files["file"][0] == "photo.jpg" and files["file"][2] == "image/jpeg"
            uploaded = files["file"][1].read()
            assert uploaded == self.expected_bytes
            files["file"][1].seek(0)
            prepared = requests.Request("POST", url, data=data, files=files).prepare()
            assert self.expected_bytes in prepared.body
            assert b'name="file"; filename="photo.jpg"' in prepared.body
            assert b"Content-Type: image/jpeg" in prepared.body
            return SimulationResponse(status=204, headers={"ETag": '"' + self.etag + '"'})
        assert url.startswith(API)
        body = json.loads(data)
        assert body["v"] == "v1" and body["did"] == self.did
        payload = self.unwrap(body, self.service_private)
        path = url[len(API):]
        if path == "check":
            assert "Authorization" not in headers
            self.issue_id = payload["issueId"]
            return SimulationResponse({"code": "SUCCESS", "data": {
                "jwt": self.jwt, "captureId": "simulation-capture", "tip": "LOCAL SIMULATION"}})
        assert headers["Authorization"] == self.jwt
        assert payload["issueId"] == self.issue_id
        assert payload["captureId"] == "simulation-capture"
        if path == "capture/osssign":
            assert payload["bgColor"] in {"DEFAULT", "WHITE"}
            result = {"stsId": "simulation-sts", "host": "https://simulation.invalid/oss",
                      "objectKey": "simulation/photo.jpg", "origin": "https://simulation.invalid",
                      "xOssCredential": "simulation-access-id/scope", "policy": "simulation-policy",
                      "signature": "simulation-signature", "securityToken": "simulation-token",
                      "xOssDate": "20261021T000000Z", "version": "OSS4-HMAC-SHA256",
                      "successActionStatus": "204"}
        elif path == "capture/ossrs":
            assert payload["eTag"] == self.etag and payload["stsId"] == "simulation-sts"
            result = {"timeout": 60, "interval": 3, "tip": "LOCAL SIMULATION"}
        elif path == "capture/checkst":
            result = {"status": "QUALITY_CHECKING", "confirmPhoto": 1, "simulation": True}
        elif path == "capture/confirm":
            result = {"simulation": True}
        else:
            raise AssertionError("Unexpected simulated endpoint: " + path)
        return SimulationResponse({"code": "SUCCESS", "data": result})

    def close(self):
        pass


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qr", nargs="?", help="chesicc://idphoto/... (omit to paste interactively)")
    parser.add_argument("jpg", nargs="?", type=Path, help="Path to the original JPG")
    parser.add_argument("--dry-run", action="store_true", help="Local crypto/multipart simulation; no network")
    parser.add_argument("--bootstrap-only", action="store_true", help="Initialize only; no QR or photo sent")
    parser.add_argument("--state", type=Path, default=Path(".chsi-idphoto-state.json"), help="Persistent installation UUID")
    parser.add_argument("--session-dir", type=Path, default=Path(".chsi-idphoto-sessions"),
                        help="Private resume files holding JWT/captureId; keep them for retries")
    parser.add_argument("--report", type=Path, help="Write a JSON result (no QR/JWT/OSS credentials)")
    parser.add_argument("--bg", choices=["DEFAULT", "WHITE"], default="DEFAULT", help="DEFAULT preserves uploaded photo")
    parser.add_argument("--uid", help="Optional uid; the app omits it when unavailable")
    parser.add_argument("--wait", type=float, default=0, metavar="SECONDS", help="Poll after upload; default stops at receipt")
    parser.add_argument("--confirm", action="store_true", help="Also call the final confirmation endpoint after polling")
    parser.add_argument("--timeout", type=float, default=30, help="Timeout per HTTP request")
    args = parser.parse_args(argv)
    report = {}
    client = None
    try:
        if args.timeout <= 0 or args.wait < 0:
            raise ValueError("Timeout must be positive; wait must be nonnegative")
        if args.bootstrap_only and args.dry_run:
            raise ValueError("Use --bootstrap-only or --dry-run separately")
        if args.bootstrap_only:
            did = load_did(args.state)
            client = IdPhotoClient(did, timeout=args.timeout,
                                  progress=lambda s: print(s, file=sys.stderr))
            report = {"mode": "bootstrap-only", "bootstrap": client.bootstrap(),
                      "storage_uploaded": False, "confirmed": False}
        else:
            qr = args.qr if args.qr else input("QR URL: ").strip()
            jpg = args.jpg if args.jpg else Path(input("JPG path: ").strip().strip('"'))
            parse_qr(qr)
            jpg = jpg.expanduser().resolve(strict=True)
            if not jpg.is_file():
                raise ValueError("JPG path is not a regular file")
            with jpg.open("rb") as stream:
                if stream.read(3) != b"\xff\xd8\xff":
                    raise ValueError("File does not have a JPEG header")
            if args.dry_run:
                simulation = SimulationSession(jpg)
                client = IdPhotoClient(str(uuid.uuid4()), session=simulation,
                    bootstrap_key=simulation.bootstrap_private.public_key(),
                    progress=lambda s: print("[LOCAL] " + s, file=sys.stderr))
            else:
                client = IdPhotoClient(load_did(args.state), timeout=args.timeout,
                                      progress=lambda s: print(s, file=sys.stderr))
            report["file"] = {"bytes": jpg.stat().st_size,
                "sha256": hashlib.sha256(jpg.read_bytes()).hexdigest(), "modified": False}
            client.run(qr, jpg, bg_color=args.bg, uid=args.uid,
                       wait_seconds=max(args.wait, 120 if args.confirm else 0),
                       confirm=args.confirm, report=report,
                       session_path=None if args.dry_run else args.session_dir / (
                           hashlib.sha256(parse_qr(qr).encode("utf-8")).hexdigest() + ".json"))
            if args.dry_run:
                report["network_requests"] = 0
                report["simulated_steps"] = len(client.session.calls)
        report["ok"] = True
        exit_code = 0
    except ClientError as exc:
        report.update({"ok": False, "error": {"stage": exc.stage,
                       "code": exc.code, "message": str(exc)}})
        exit_code = 2
    except (ValueError, OSError, KeyError, TypeError) as exc:
        report.update({"ok": False, "error": {"stage": "client", "message": str(exc)}})
        exit_code = 2
    except KeyboardInterrupt:
        report.update({"ok": False, "error": {"stage": "client", "message": "Interrupted"}})
        exit_code = 130
    finally:
        if client is not None:
            client.session.close()
    output = json.dumps(report, ensure_ascii=False, indent=2)
    print(output)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(output + "\n", encoding="utf-8")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
