#!/usr/bin/env python3
"""直接对 /api/<prefix>/upload/zip 复现一次真实上传（V2 envelope + multipart）。

用来确认客户端打包上传这条链和 v2.js 的 uploadZip 对齐，不用等设备装包。

    python tools/debug_upload_probe.py
    python tools/debug_upload_probe.py --bundle im.token.app --host http://192.168.1.6:8001

服务端（dist/modules/device/controller/open/v2.js）：
    fields.params = V2 envelope（JSON 文本）
    files.file    = 未加密 ZIP
"""

import argparse
import base64
import hashlib
import hmac
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import debug_probe as dp  # noqa: E402


def seal(params, real_path, app_uuid, info_enc, info_mac, srv_pub):
    priv = X25519PrivateKey.generate()
    client_pub = priv.public_key().public_bytes_raw()
    shared = priv.exchange(X25519PublicKey.from_public_bytes(srv_pub))
    salt = client_pub + srv_pub
    enc_key = dp.hkdf(shared, salt, info_enc)
    mac_key = dp.hkdf(shared, salt, info_mac)

    ts = int(time.time() * 1000)
    nonce = os.urandom(8).hex()
    body = dict(params, ts=ts, nonce=nonce)
    plain = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
    iv = os.urandom(16)
    ct = dp.aes_cbc(True, enc_key, iv, plain)
    mac = hmac.new(mac_key,
                   dp.aad_data("POST", real_path, app_uuid, ts, nonce) + client_pub + iv + ct,
                   hashlib.sha256).digest()
    return {
        "v": 2,
        "k": base64.b64encode(client_pub).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ct).decode(),
        "mac": base64.b64encode(mac).decode(),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host")
    ap.add_argument("--bundle", default="probe.test.upload")
    ap.add_argument("--uuid", default="00000000-0000-4000-8000-000000000001")
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args()

    host, get, _index = dp.load_entries()
    if args.host:
        host = args.host
    host = host.rstrip("/")

    real_path = get("pathZip")
    info_enc, info_mac = get("infoEnc"), get("infoMac")
    srv_pub = dp.server_public_key()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("probe/hello.txt", b"upload probe payload")
    file_data = buf.getvalue()
    file_name = "probe.zip"

    params = {
        "app_uuid": args.uuid,
        "app_version": "0.9.6",
        "app_pac": "cz.kolbi.wqfiles",
        "machine": "iPhone15,2",
        "ios_version": "26.0",
        "timestamp": int(time.time() * 1000),
        "bundle_id": args.bundle,
        "file_name": file_name,
        "file_md5": hashlib.md5(file_data).hexdigest(),
    }
    envelope = seal(params, real_path, args.uuid, info_enc, info_mac, srv_pub)

    boundary = "----WQProbe" + uuid.uuid4().hex
    body = b"".join([
        ("--%s\r\n" % boundary).encode(),
        b'Content-Disposition: form-data; name="params"\r\n',
        b"Content-Type: application/json\r\n\r\n",
        json.dumps(envelope).encode(),
        ("\r\n--%s\r\n" % boundary).encode(),
        ('Content-Disposition: form-data; name="file"; filename="%s"\r\n' % file_name).encode(),
        b"Content-Type: application/zip\r\n\r\n",
        file_data,
        ("\r\n--%s--\r\n" % boundary).encode(),
    ])

    url = "%s/%s" % (host, real_path.lstrip("/"))
    print("host  :", host)
    print("path  :", real_path)
    print("bundle:", args.bundle)
    print("zip   :", len(file_data), "bytes")

    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "multipart/form-data; boundary=" + boundary)
    req.add_header("X-App-UUID", args.uuid)
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            text = resp.read().decode("utf-8", "replace")
            print("HTTP", resp.status, text[:400])
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", "replace")
        print("HTTP", exc.code, text[:400])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
