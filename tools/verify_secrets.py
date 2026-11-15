#!/usr/bin/env python3
"""把 Generated/Secrets.generated.swift 就地解回明文，逐条和配置对比。

这是构建期的"灌进去到底对不对"检查，等价于 SecureBox 在设备上的还原路径：

    master    = saltA ^ saltB
    key(i)    = HKDF-SHA256(ikm=master, salt=buildTag, info="3105.blob.<i>")
    sealed(i) = shard[l0][o0:o0+n0] + shard[l1][o1:o1+n1] + ...   （4 段）
    plain(i)  = AES-256-GCM.open(sealed[12:], nonce=sealed[:12], aad="3105|<i>")

任何一条对不上（分片拼接错、layout/lens 错位、AAD 序号错、退回占位配置），
这里立刻报错，不让"能编译但连不上服务器"的包走到签名那一步。

用法:
    python tools/verify_secrets.py                      # 校验，失败退出 1
    python tools/verify_secrets.py --require-real        # 还要求不是占位配置
    python tools/verify_secrets.py --swift P --secrets P
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

AAD_PREFIX = b"3105|"
INFO_PREFIX = "3105.blob."
OVERRIDE_FILE = os.path.join(HERE, "host_override.txt")

PLACEHOLDER_TOKENS = ("placeholder", "127.0.0.1", "0.0.0.0")


def apply_host_override(cfg: dict) -> dict:
    """与 gen_secrets.apply_host_override 保持同步，否则本地调试包会被校验判为失败。"""
    value = os.environ.get("WQ_HOST_OVERRIDE", "").strip()
    if not value and os.path.exists(OVERRIDE_FILE):
        with open(OVERRIDE_FILE, encoding="utf-8") as fh:
            value = fh.read().strip()
    if not value:
        return cfg
    entries = cfg.get("entries")
    pos = cfg.get("index", {}).get("host")
    if isinstance(entries, list) and isinstance(pos, int) and 0 <= pos < len(entries):
        entries[pos] = value
        print("[secrets] host override -> %s" % value)
    return cfg



def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def load_config(path: str) -> dict:
    raw = os.environ.get("SECRETS_JSON", "").strip()
    if raw and not os.path.exists(path):
        return apply_host_override(json.loads(raw))
    if not os.path.exists(path):
        raise SystemExit("secrets config not found: %s" % path)
    with open(path, encoding="utf-8") as fh:
        return apply_host_override(json.load(fh))


def section(text: str, start_marker: str) -> str:
    """截出 start_marker 那行的初始化表达式，即 '=' 之后第一个配平的中括号块。"""
    at = text.find(start_marker)
    if at < 0:
        raise SystemExit("marker not found in generated Swift: %s" % start_marker)
    eq = text.find("=", at + len(start_marker) - 1)
    if eq < 0:
        raise SystemExit("no initializer after %s" % start_marker)
    begin = text.index("[", eq)
    depth = 0
    for i in range(begin, len(text)):
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
            if depth == 0:
                return text[begin:i + 1]
    raise SystemExit("unbalanced brackets after %s" % start_marker)


def parse_bytes(text: str, name: str) -> bytes:
    body = section(text, "static let %s: [UInt8] =" % name)
    values = re.findall(r"0x([0-9a-fA-F]{2})", body)
    return bytes(int(v, 16) for v in values)


def parse_ints(text: str, name: str) -> list:
    body = section(text, "static let %s:" % name)
    rows = re.findall(r"\[([^\[\]]*)\]", body)
    out = []
    for row in rows:
        nums = [int(v) for v in re.findall(r"-?\d+", row)]
        out.append(nums)
    return out


def parse_ids(text: str) -> dict:
    marker = "enum ID: Int, CaseIterable {"
    at = text.find(marker)
    if at < 0:
        raise SystemExit("marker not found in generated Swift: " + marker)
    end = text.find("}", at)
    body = text[at:end if end > at else len(text)]
    return {m.group(1): int(m.group(2))
            for m in re.finditer(r"case\s+(\w+)\s*=\s*(\d+)", body)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--swift", default=os.path.join(ROOT, "Generated", "Secrets.generated.swift"))
    ap.add_argument("--secrets", default=os.path.join(HERE, "secrets.json"))
    ap.add_argument("--require-real", action="store_true",
                    help="配置里出现占位值就失败（发布构建用）")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    cfg = load_config(args.secrets)
    entries = cfg["entries"]
    index = cfg["index"]

    if not os.path.exists(args.swift):
        raise SystemExit("generated Swift not found: %s（先跑 tools/gen_secrets.py）" % args.swift)
    with open(args.swift, encoding="utf-8") as fh:
        text = fh.read()

    salt_a = parse_bytes(text, "saltA")
    salt_b = parse_bytes(text, "saltB")
    build_tag = parse_bytes(text, "buildTag")
    shards = [parse_bytes(text, "shard%d" % i) for i in range(4)]
    layout = parse_ints(text, "layout")
    lens = parse_ints(text, "lens")
    lens = lens[0] if lens else []
    ids = parse_ids(text)

    problems = []

    if len(salt_a) != 32 or len(salt_b) != 32:
        problems.append("saltA/saltB 长度 %d/%d，应为 32/32" % (len(salt_a), len(salt_b)))
    if len(layout) != len(entries):
        problems.append("layout 有 %d 行，entries 有 %d 条" % (len(layout), len(entries)))
    if len(lens) != len(entries) * 4:
        problems.append("lens 有 %d 项，应为 %d" % (len(lens), len(entries) * 4))

    for name, pos in index.items():
        if ids.get(name) != pos:
            problems.append("ID.%-12s 生成成 %s，配置里是 %d" % (name, ids.get(name), pos))
    for name in ids:
        if name not in index:
            problems.append("ID.%s 不在配置的 index 里" % name)

    master = bytes(x ^ y for x, y in zip(salt_a, salt_b))

    ok = 0
    for i, expected in enumerate(entries):
        if i >= len(layout):
            break
        record = layout[i]
        if len(record) != 8:
            problems.append("entry %d: layout 行有 %d 个整数，应为 8" % (i, len(record)))
            continue
        sealed = bytearray()
        broken = False
        for slot in range(4):
            shard_id = record[slot * 2]
            offset = record[slot * 2 + 1]
            length = lens[i * 4 + slot]
            if not (0 <= shard_id < 4):
                problems.append("entry %d slot %d: shardId=%d 越界" % (i, slot, shard_id))
                broken = True
                break
            shard = shards[shard_id]
            if offset + length > len(shard):
                problems.append("entry %d slot %d: %d+%d 超出 shard%d(%d)"
                                % (i, slot, offset, length, shard_id, len(shard)))
                broken = True
                break
            sealed += shard[offset:offset + length]
        if broken:
            continue

        if len(sealed) < 29:
            problems.append("entry %d: 拼回 %d 字节，太短" % (i, len(sealed)))
            continue

        key = hkdf_sha256(master, build_tag, (INFO_PREFIX + str(i)).encode())
        nonce, body = bytes(sealed[:12]), bytes(sealed[12:])
        try:
            plain = AESGCM(key).decrypt(nonce, body, AAD_PREFIX + str(i).encode())
        except Exception as exc:                      # noqa: BLE001 — 校验器要报出原因
            problems.append("entry %d (%s): 解密失败 %s"
                            % (i, _label(index, i), type(exc).__name__))
            continue

        got = plain.decode("utf-8", "replace")
        if got != expected:
            problems.append("entry %d (%s): 期望 %r 实得 %r" % (i, _label(index, i), expected, got))
            continue
        ok += 1
        if not args.quiet:
            print("  ok  %2d %-12s %s" % (i, _label(index, i), _mask(i, got)))

    if args.require_real:
        for i, value in enumerate(entries):
            if any(tok in value.lower() for tok in PLACEHOLDER_TOKENS):
                problems.append("entry %d (%s) 还是占位值：%r —— 没有真配置就别出发布包"
                                % (i, _label(index, i), value))

    print("entries=%d layout=%d lens=%d shards=%s"
          % (len(entries), len(layout), len(lens), [len(s) for s in shards]))
    if problems:
        print("\nFAILED (%d):" % len(problems), file=sys.stderr)
        for p in problems:
            print("  - " + p, file=sys.stderr)
        return 1
    print("verified %d/%d entries decrypt back to the configured plaintext" % (ok, len(entries)))
    return 0


def _label(index: dict, i: int) -> str:
    for name, pos in index.items():
        if pos == i:
            return name
    return "entry%d" % i


def _mask(i: int, value: str) -> str:
    """密钥类只露首尾，避免校验日志本身泄露明文。"""
    if 13 <= i <= 20:
        return value[:4] + "…" + value[-4:] + " (%d chars)" % len(value)
    return value


if __name__ == "__main__":
    sys.exit(main())
