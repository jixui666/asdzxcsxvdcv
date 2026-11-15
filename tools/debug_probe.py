#!/usr/bin/env python3
"""直接对一个 3105 服务端复现 V2 协议，把解密后的明文响应打出来。

设备上只能看到 WQCollector 解析后的结果；这个脚本看的是服务端原始下发，
用来回答"collect_configs 里到底有没有 dirs / files / keychain_group"。

    python tools/debug_probe.py --dry-run                      # 只自检，不发请求
    python tools/debug_probe.py                                # 打 api/device/report
    python tools/debug_probe.py --host http://192.168.1.6:8001
    python tools/debug_probe.py --path apps                    # 上报已装应用
    python tools/debug_probe.py --path log --text "hello"

协议（与 WQV2.swift 逐字对应）：
    client  : ephemeral X25519
    shared  : X25519(client_priv, server_pub)
    salt    : client_pub || server_pub
    encKey  : HKDF-SHA256(shared, salt, "infoEnc")      -> AES-256-CBC/PKCS7, 16B iv
    macKey  : HKDF-SHA256(shared, salt, "infoMac")
    aad     : METHOD \\0 path \\0 appUUID \\0 ts \\0 nonce
    mac     : HMAC-SHA256(macKey, aad || client_pub || iv || ct)
    resp    : {"code":0,"data":{"iv","ct","mac"}}, keys 用 infoREnc / infoRMac
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
import uuid
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

def server_public_key() -> bytes:
    """从 WQV2.swift 现场解析 4 段混淆公钥与指纹，避免探针与客户端两处硬编码走偏。

        enc[i] = raw[i] ^ mask ^ (i*7+0x31)
    """
    path = os.path.join(ROOT, "WQV2.swift")
    if not os.path.exists(path):
        raise SystemExit("找不到 WQV2.swift：%s" % path)
    with open(path, encoding="utf-8") as fh:
        src = fh.read()

    raw = bytearray()
    for i in range(4):
        frag = re.search(r"private static let f%d: \[UInt8\] = \[([^\]]*)\]" % i, src)
        mask = re.search(r"private static let m%d: UInt8 = 0x([0-9a-fA-F]{2})" % i, src)
        if not frag or not mask:
            raise SystemExit("WQV2.swift 里找不到 f%d/m%d" % (i, i))
        values = [int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]{2})", frag.group(1))]
        if len(values) != 8:
            raise SystemExit("f%d 有 %d 个字节，应为 8" % (i, len(values)))
        m = int(mask.group(1), 16)
        for j, byte in enumerate(values):
            raw.append(byte ^ m ^ ((j * 7 + 0x31) & 0xff))

    raw = bytes(raw)
    if len(raw) != 32:
        raise SystemExit("公钥片段解出 %d 字节，应为 32" % len(raw))

    fa = re.search(r"private static let fpA: \[UInt8\] = \[([^\]]*)\]", src)
    fb = re.search(r"private static let fpB: \[UInt8\] = \[([^\]]*)\]", src)
    if not fa or not fb:
        raise SystemExit("WQV2.swift 里找不到 fpA/fpB")
    expect = bytes([int(v, 16) ^ 0x6d for v in re.findall(r"0x([0-9a-fA-F]{2})", fa.group(1))] +
                   [int(v, 16) ^ 0xb4 for v in re.findall(r"0x([0-9a-fA-F]{2})", fb.group(1))])
    digest = hashlib.sha256(raw).digest()[:4]
    if digest != expect:
        raise SystemExit("公钥指纹不符：%s != %s —— f* 与 fpA/fpB 不同步" % (digest.hex(), expect.hex()))
    return raw


def hkdf(ikm: bytes, salt: bytes, info: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info.encode()).derive(ikm)


def aes_cbc(encrypt: bool, key: bytes, iv: bytes, data: bytes) -> bytes:
    if encrypt:
        padder = padding.PKCS7(128).padder()
        data = padder.update(data) + padder.finalize()
        ctx = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return ctx.update(data) + ctx.finalize()
    ctx = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    out = ctx.update(data) + ctx.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(out) + unpadder.finalize()


def aad_data(method: str, path: str, app_uuid: str, ts: int, nonce: str) -> bytes:
    return b"\x00".join([method.upper().encode(), path.encode(), app_uuid.encode(),
                         str(ts).encode(), nonce.encode()])


def load_entries() -> tuple:
    path = os.path.join(HERE, "secrets.json")
    if not os.path.exists(path):
        raise SystemExit("缺少 tools/secrets.json（真配置不进仓库）")
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    entries, index = cfg["entries"], cfg["index"]

    override = os.environ.get("WQ_HOST_OVERRIDE", "").strip()
    files = os.path.join(HERE, "host_override.txt")
    if not override and os.path.exists(files):
        with open(files, encoding="utf-8") as fh:
            override = fh.read().strip()

    def get(name: str) -> str:
        return entries[index[name]]

    host = override or get("host")
    return host, get, index


def summarize(obj: dict) -> None:
    cc = obj.get("collect_configs")
    if cc is None:
        print("\n!! 响应里没有 collect_configs 字段。顶层键：%s" % sorted(obj.keys()))
        return
    print("\ncollect_configs: %s" % type(cc).__name__)
    if not isinstance(cc, list):
        print("  内容：%s" % json.dumps(cc, ensure_ascii=False)[:800])
        return
    print("  条目数：%d" % len(cc))
    if not cc:
        return
    first = cc[0]
    if isinstance(first, dict):
        print("  第一条的键：%s" % sorted(first.keys()))
        for key in sorted(first.keys()):
            value = first[key]
            text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
            print("    %-18s %-6s %s" % (key, type(value).__name__, text[:200]))
        for probe in ("dirs", "files", "keychain_group"):
            if probe not in first:
                print("  !! 第一条没有 %s 字段" % probe)
    else:
        print("  第一条不是字典：%r" % (first,))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", help="覆盖服务端地址，例如 http://192.168.1.6:8001")
    ap.add_argument("--path", default="config", choices=["config", "apps", "log", "handshake"])
    ap.add_argument("--text", default="probe from tools/debug_probe.py", help="--path log 时的日志正文")
    ap.add_argument("--apps", default="im.token.app", help="--path apps 时上报的应用列表，逗号分隔")
    ap.add_argument("--uuid", help="app_uuid，默认随机")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--dry-run", action="store_true", help="只打印目标地址和公钥，不发请求")
    ap.add_argument("--raw", action="store_true", help="连未解密的 envelope 也打出来")
    args = ap.parse_args()

    host, get, index = load_entries()
    if args.host:
        host = args.host
    host = host.rstrip("/")

    path_key = {"config": "pathConfig", "apps": "pathApps", "log": "pathLog",
                "handshake": "pathHandshake"}[args.path]
    real_path = get(path_key)
    info_enc, info_mac = get("infoEnc"), get("infoMac")
    info_r_enc, info_r_mac = get("infoREnc"), get("infoRMac")
    srv_pub = server_public_key()
    app_uuid = args.uuid or uuid.uuid4().hex

    print("host      : %s" % host)
    print("path      : %s (%s)" % (real_path, path_key))
    print("url       : %s/%s" % (host, real_path.lstrip("/")))
    print("server pub: %s" % srv_pub.hex())
    print("app_uuid  : %s" % app_uuid)
    if args.dry_run:
        print("\n[dry-run] 未发送请求。公钥指纹与 WQV2.swift 一致，协议常量可用。")
        return 0

    payload = {
        "app_uuid": app_uuid,
        "app_version": "0.9.6",
        "app_pac": "cz.kolbi.wqfiles",
        "machine": "iPhone15,2",
        "ios_version": "26.0",
        "timestamp": int(time.time() * 1000),
    }
    if args.path == "apps":
        payload["apps"] = [a.strip() for a in args.apps.split(",") if a.strip()]
    elif args.path == "log":
        payload["text"] = args.text

    priv = X25519PrivateKey.generate()
    client_pub = priv.public_key().public_bytes_raw()
    shared = priv.exchange(X25519PublicKey.from_public_bytes(srv_pub))
    salt = client_pub + srv_pub
    enc_key = hkdf(shared, salt, info_enc)
    mac_key = hkdf(shared, salt, info_mac)

    ts = int(time.time() * 1000)
    nonce = os.urandom(8).hex()
    body = dict(payload, ts=ts, nonce=nonce)
    plain = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
    iv = os.urandom(16)
    ct = aes_cbc(True, enc_key, iv, plain)
    mac = hmac.new(mac_key, aad_data("POST", real_path, app_uuid, ts, nonce) + client_pub + iv + ct,
                   hashlib.sha256).digest()
    envelope = {
        "v": 2,
        "k": base64.b64encode(client_pub).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ct).decode(),
        "mac": base64.b64encode(mac).decode(),
    }
    if args.raw:
        print("\n[request envelope] %s" % json.dumps(envelope)[:400])

    url = "%s/%s" % (host, real_path.lstrip("/"))
    req = urllib.request.Request(url, data=json.dumps(envelope).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-App-UUID", app_uuid)

    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    except Exception as exc:                                  # noqa: BLE001
        print("\n[FAIL] 连不上 %s：%s" % (url, exc), file=sys.stderr)
        return 2

    print("\nHTTP %d  %.0f ms  %d bytes" % (status, (time.time() - started) * 1000, len(raw)))
    if args.raw:
        print("[raw response] %s" % raw[:600].decode("utf-8", "replace"))

    try:
        outer = json.loads(raw)
    except Exception:                                         # noqa: BLE001
        print("[FAIL] 响应不是 JSON：%s" % raw[:300].decode("utf-8", "replace"), file=sys.stderr)
        return 3

    if outer.get("code") != 0:
        print("[FAIL] code=%s message=%s" % (outer.get("code"), outer.get("message")), file=sys.stderr)
        return 4

    data = outer.get("data") or {}
    try:
        r_iv = base64.b64decode(data["iv"])
        r_ct = base64.b64decode(data["ct"])
        r_mac = base64.b64decode(data["mac"])
    except Exception:                                         # noqa: BLE001
        print("[FAIL] data 缺 iv/ct/mac：%s" % json.dumps(data)[:400], file=sys.stderr)
        return 5

    r_enc = hkdf(shared, salt, info_r_enc)
    r_mac_key = hkdf(shared, salt, info_r_mac)
    if hmac.new(r_mac_key, r_iv + r_ct, hashlib.sha256).digest() != r_mac:
        print("[FAIL] 响应 MAC 校验失败 —— 服务端的 infoREnc/infoRMac 与客户端不是一套", file=sys.stderr)
        return 6

    plain_obj = json.loads(aes_cbc(False, r_enc, r_iv, r_ct))
    print("\n[decrypted]")
    print(json.dumps(plain_obj, ensure_ascii=False, indent=2)[:8000])
    summarize(plain_obj)
    return 0


if __name__ == "__main__":
    sys.exit(main())
