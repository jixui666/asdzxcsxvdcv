#!/usr/bin/env python3
"""构建期完整性签名：把清单 + Ed25519 签名回填到 JSQ2 的 __DATA,__integrity。

流程（对应 IntegrityGuard.swift 的运行时校验）：

  1. 解析主二进制的 __TEXT,__text → 从 __text 起、到 __TEXT 段末尾的 SHA-256
     （不含 mach header / load commands，重签插入 LC_CODE_SIGNATURE 也不影响）
  2. 遍历 app bundle：每个 Mach-O 只哈希它自己的 __TEXT 段，其余文件全文件哈希
  3. 生成清单 JSON（v/text/files/skip/allow_extra_macho）
  4. Ed25519 签名，按 "3105IGV1" | u32le(len) | json | sig64 | 零填充 写入
     __DATA,__integrity 的 section 文件偏移

必须在 codesign 之前运行：codesign 只改 load commands 和追加签名块，
不动 __TEXT.__text 与 __DATA.__integrity，所以回填后的哈希依然成立。

    python3 tools/integrity_sign.py --binary build/Payload/JSQ2.app/JSQ2 \
                                    --app build/Payload/JSQ2.app
"""

import argparse
import base64
import hashlib
import json
import os
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MAGIC_KEY = b"3105IGV1"
SECTION_SIZE = 131072

# 与 IntegrityGuard.isSkipped 保持一致：codesign 产生的目录与重签工具会改的文件
SKIP_EXACT = {"Info.plist", "PkgInfo", "embedded.mobileprovision"}
SKIP_DIRS = {"_CodeSignature"}


def is_macho(data: bytes) -> bool:
    if len(data) < 4:
        return False
    magic = struct.unpack_from("<I", data, 0)[0]
    return magic in (0xFEEDFACF, 0xFEEDFACE, 0xBEBAFECA)


def thin_text_range(data: bytes, base: int = 0):
    """返回 (start, end)：__TEXT 段里从 __text section 起到段末尾。"""
    if len(data) < base + 32:
        return None
    magic = struct.unpack_from("<I", data, base)[0]
    if magic != 0xFEEDFACF:
        return None
    ncmds, _sizeofcmds = struct.unpack_from("<II", data, base + 16)
    cursor = base + 32
    for _ in range(ncmds):
        if cursor + 8 > len(data):
            return None
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmdsize == 0:
            return None
        if cmd == 0x19 and cursor + 72 <= len(data):          # LC_SEGMENT_64
            segname = data[cursor + 8:cursor + 24].split(b"\0")[0].decode("ascii", "replace")
            if segname == "__TEXT":
                fileoff, filesize = struct.unpack_from("<QQ", data, cursor + 40)
                nsects = struct.unpack_from("<I", data, cursor + 64)[0]
                section = cursor + 72
                for _ in range(nsects):
                    if section + 80 > len(data):
                        return None
                    sectname = data[section:section + 16].split(b"\0")[0].decode("ascii", "replace")
                    if sectname == "__text":
                        offset = struct.unpack_from("<I", data, section + 48)[0]
                        start = base + offset
                        end = base + fileoff + filesize
                        if start < end <= len(data):
                            return (start, end)
                        return None
                    section += 80
                return None
        cursor += cmdsize
    return None


def find_integrity_section(data: bytes):
    """返回 (offset, size)：__DATA,__integrity 在文件中的位置。"""
    if len(data) < 32:
        return None
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != 0xFEEDFACF:
        return None
    ncmds, _ = struct.unpack_from("<II", data, 16)
    cursor = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmdsize == 0:
            return None
        if cmd == 0x19:
            segname = data[cursor + 8:cursor + 24].split(b"\0")[0].decode("ascii", "replace")
            if segname in ("__DATA", "__DATA_CONST"):
                nsects = struct.unpack_from("<I", data, cursor + 64)[0]
                section = cursor + 72
                for _ in range(nsects):
                    sectname = data[section:section + 16].split(b"\0")[0].decode("ascii", "replace")
                    if sectname == "__integrity":
                        size = struct.unpack_from("<Q", data, section + 40)[0]
                        offset = struct.unpack_from("<I", data, section + 48)[0]
                        return (offset, size)
                    section += 80
        cursor += cmdsize
    return None


def text_digest(data: bytes):
    rng = thin_text_range(data)
    if not rng:
        return None
    start, end = rng
    return hashlib.sha256(data[start:end]).digest()


def hash_entry(path: str):
    with open(path, "rb") as fh:
        data = fh.read()
    if is_macho(data):
        digest = text_digest(data)
        if digest is None:
            # 非 __TEXT 布局的 Mach-O（如某些静态库）：退回全文件哈希
            return (True, hashlib.sha256(data).digest())
        return (True, digest)
    return (False, hashlib.sha256(data).digest())


def skipped(rel: str) -> bool:
    parts = rel.split("/")
    if any(p in SKIP_DIRS for p in parts[:-1]):
        return True
    if parts[-1] in SKIP_EXACT:
        return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True, help="构建出的主可执行文件")
    ap.add_argument("--app", required=True, help="app bundle 目录")
    ap.add_argument("--priv", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                   "integrity_priv.hex"))
    args = ap.parse_args()

    if not os.path.exists(args.priv):
        print("[integrity] 缺少私钥 %s —— 跳过签名（运行时会对不上清单）" % args.priv,
              file=sys.stderr)
        return 2
    priv = bytes.fromhex(open(args.priv, encoding="ascii").read().strip())
    if len(priv) != 32:
        print("[integrity] 私钥必须是 32 字节", file=sys.stderr)
        return 2

    with open(args.binary, "rb") as fh:
        binary = fh.read()

    section = find_integrity_section(binary)
    if not section:
        print("[integrity] 主二进制里没有 __DATA,__integrity —— 检查 -sectcreate", file=sys.stderr)
        return 3
    sec_off, sec_size = section
    if sec_size < 1024 or sec_off + sec_size > len(binary):
        print("[integrity] __integrity 区间异常 offset=%d size=%d" % (sec_off, sec_size),
              file=sys.stderr)
        return 3

    text = text_digest(binary)
    if text is None:
        print("[integrity] 取不到主程序的 __TEXT 范围", file=sys.stderr)
        return 4

    main_exe = os.path.basename(args.binary)
    files = []
    for root, dirs, names in os.walk(args.app):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in sorted(names):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, args.app).replace(os.sep, "/")
            if rel == main_exe or skipped(rel):
                continue
            entry = hash_entry(full)
            if entry is None:
                print("[integrity] 读不了 %s" % rel, file=sys.stderr)
                return 5
            is_macho, digest = entry
            files.append({
                "p": rel,
                "k": 1 if is_macho else 0,
                "h": base64.b64encode(digest).decode("ascii"),
            })

    manifest = {
        "v": 1,
        "text": base64.b64encode(text).decode("ascii"),
        "files": files,
        "skip": ["_CodeSignature/", "Info.plist", "embedded.mobileprovision"],
        # 企业签/自签平台会往 Frameworks 里注入自己的 dylib，拒绝就装不上
        "allow_extra_macho": True,
    }
    blob = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = Ed25519PrivateKey.from_private_bytes(priv).sign(blob)
    if len(signature) != 64:
        print("[integrity] 签名长度异常", file=sys.stderr)
        return 6

    payload = MAGIC_KEY + struct.pack("<I", len(blob)) + blob + signature
    if len(payload) > sec_size:
        print("[integrity] 清单 %d 字节超出 section %d" % (len(payload), sec_size),
              file=sys.stderr)
        return 7

    out = bytearray(binary)
    out[sec_off:sec_off + sec_size] = payload + b"\x00" * (sec_size - len(payload))
    with open(args.binary, "wb") as fh:
        fh.write(out)

    got = out[sec_off:sec_off + 12]
    if got[:8] != MAGIC_KEY:
        print("[integrity] 回填校验失败", file=sys.stderr)
        return 8

    print("[integrity] signed: %d files, manifest %d B, section @%d (%d B), text %s"
          % (len(files), len(blob), sec_off, sec_size, base64.b64encode(text).decode()[:12]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
