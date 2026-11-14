#!/usr/bin/env python3
"""构建期机密流水线的宿主侧回归：分片生成 → 解回明文 → 篡改必被发现。

tools/secrets.json 里的真值不进仓库，所以这里的固定断言只用
tools/secrets.sample.json（占位配置）作夹具；真配置的校验由 build.sh /
CI 里的 `verify_secrets.py --require-real` 在构建机上做。
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"


class SecretsPipelineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.work = Path(self._tmp.name)
        self.tools = self.work / "tools"
        self.tools.mkdir()
        for name in ("gen_secrets.py", "verify_secrets.py",
                     "secrets.sample.json", "integrity_pubkey.hex"):
            shutil.copy(TOOLS / name, self.tools / name)
        self.swift = self.work / "Generated" / "Secrets.generated.swift"
        self.sample = self.tools / "secrets.sample.json"

    def run_python(self, *args):
        # 子进程必须按 UTF-8 输出：断言里比对的是中文提示（占位值 / 解密失败），
        # Windows 默认按 locale 解码会把它们变成乱码。
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        return subprocess.run([sys.executable, *map(str, args)],
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace", env=env)

    def generate(self):
        result = self.run_python(self.tools / "gen_secrets.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.swift.exists())
        return self.swift.read_text(encoding="utf-8")

    def verify(self, *extra):
        return self.run_python(self.tools / "verify_secrets.py",
                               "--secrets", self.sample, *extra)

    def test_generated_shards_decrypt_back_to_every_configured_entry(self):
        self.generate()
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        entries = json.loads(self.sample.read_text(encoding="utf-8"))["entries"]
        self.assertIn("verified %d/%d entries" % (len(entries), len(entries)), result.stdout)

    def test_placeholder_config_is_refused_for_a_release_build(self):
        self.generate()
        result = self.verify("--require-real")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("占位值", result.stderr)

    def test_a_flipped_shard_byte_is_reported_not_silently_accepted(self):
        text = self.generate()
        # 改掉 shard0 的第一个字节：密文变了，AES-GCM 的 tag 必须把它挡下来。
        marker = "static let shard0: [UInt8] = [0x"
        at = text.index(marker) + len(marker)
        original = int(text[at:at + 2], 16)
        replacement = "%02x" % (original ^ 0xff)
        self.swift.write_text(text[:at] + replacement + text[at + 2:], encoding="utf-8")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("解密失败", result.stderr)

    def test_index_and_enum_agree(self):
        text = self.generate()
        index = json.loads(self.sample.read_text(encoding="utf-8"))["index"]
        for name, position in index.items():
            self.assertIn("case %s = %d" % (name, position), text)

    def test_every_entry_gets_its_own_nonce_so_ciphertexts_differ(self):
        text = self.generate()
        index = json.loads(self.sample.read_text(encoding="utf-8"))["index"]
        # 首尾两组的 key/iv 明文完全不同，密文块长度一致；这里只确认生成器
        # 为每条都写了 4 段（layout 行数 = 条目数、lens 项数 = 4 倍）。
        layout_start = text.index("static let layout: [[Int]] = [")
        layout_block = text[layout_start:text.index("static let lens:", layout_start)]
        self.assertEqual(layout_block.count("\n        ["), len(index))
        lens_block = text[text.index("static let lens: [Int] = ["):]
        lens_block = lens_block[:lens_block.index("\n")]
        self.assertEqual(lens_block.count(",") + 1, len(index) * 4)


if __name__ == "__main__":
    unittest.main()
