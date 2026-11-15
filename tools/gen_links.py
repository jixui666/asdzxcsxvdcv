#!/usr/bin/env python3
"""构建期生成 links.txt（apptrace / libapptracecore 读取的服务器地址表）。

格式与 3105 原版一致：
    base64( AES-128-CBC( JSON 数组, key, iv, PKCS7 ) )
key/iv 取自配置里的 linksKey / linksIv（16 字节 ASCII），明文是 URL 列表，
第一条同时用作「本地网络」权限探测地址。

    python tools/gen_links.py                 # 输出 Generated/links.txt
    python tools/gen_links.py --host URL      # 覆盖第一条

apptrace 内部用自己 Mach-O 里的 key/iv 解这份数据，所以运行时还要由
LinksURLProtocol 转加密一次（见 WQLegacyTrace.swift 的 WQApptraceLinksCipher）。
"""

import argparse
import base64
import json
import os
import sys

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "Generated", "links.txt")


def load_config() -> dict:
    raw = os.environ.get("SECRETS_JSON", "").strip()
    if raw:
        return json.loads(raw)
    real = os.path.join(HERE, "secrets.json")
    if os.path.exists(real):
        return json.load(open(real, encoding="utf-8"))
    sample = os.path.join(HERE, "secrets.sample.json")
    return json.load(open(sample, encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", help="覆盖第一条链接（默认用配置里的 host）")
    args = ap.parse_args()

    cfg = load_config()
    idx, entries = cfg["index"], cfg["entries"]

    key = str(entries[idx["linksKey"]]).encode("utf-8")
    iv = str(entries[idx["linksIv"]]).encode("utf-8")
    if len(key) != 16 or len(iv) != 16:
        print("linksKey/linksIv 必须是 16 字节，实际 %d/%d" % (len(key), len(iv)),
              file=sys.stderr)
        return 1

    host = args.host or str(entries[idx["host"]]).strip()
    # host_override.txt 是调试期把 host 换成局域网地址的开关，gen_secrets 也认它；
    # links.txt 必须指向同一个地址，否则 apptrace 会连到另一台服务器。
    override = os.environ.get("WQ_HOST_OVERRIDE", "").strip()
    if not override:
        ov = os.path.join(HERE, "host_override.txt")
        if os.path.exists(ov):
            override = open(ov, encoding="utf-8").read().strip()
    if override and not args.host:
        host = override
    links = [host]

    plain = json.dumps(links, separators=(",", ":")).encode("utf-8")
    padder = padding.PKCS7(128).padder()
    plain = padder.update(plain) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    sealed = enc.update(plain) + enc.finalize()
    text = base64.b64encode(sealed).decode("ascii")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="ascii", newline="\n") as fh:
        fh.write(text + "\n")
    print("wrote %s (%d bytes, %d link(s): %s)" % (OUT, len(text), len(links), links))
    return 0


if __name__ == "__main__":
    sys.exit(main())
