#!/usr/bin/env python3
"""把 tools/secrets.json 灌进 GitHub Actions Secrets（仓库公钥做 sealed box 加密）。

CI 的 build.sh / gen_secrets.py 优先读 SECRETS_JSON secret，所以本地 secrets.json
不会进仓库，靠这一步把真配置送进 CI。

用法:
    export GITHUB_TOKEN=...          # repo scope 或 fine-grained 的 Secrets: write
    python tools/push_secrets.py                  # 默认推到 origin 仓库
    python tools/push_secrets.py --repo o/r
    python tools/push_secrets.py --check          # 只列出会推什么，不写

依赖: pip install pynacl
"""

import base64
import json
import os
import subprocess
import sys
import urllib.request

from nacl import encoding, public

HERE = os.path.dirname(os.path.abspath(__file__))


def api(path, token, method="GET", payload=None):
    url = "https://api.github.com" + path
    data = None
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "User-Agent": "wqfiles-secrets",
    }
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
        return json.loads(body) if body else {}


def encrypt(public_key_b64: str, secret_value: bytes) -> str:
    pk = public.PublicKey(public_key_b64.encode(), encoding.Base64Encoder())
    return base64.b64encode(public.SealedBox(pk).encrypt(secret_value)).decode()


def default_repo() -> str:
    """从 git remote 推 origin 的 owner/name，推不出来时用占位。"""
    root = os.path.dirname(HERE)
    try:
        url = subprocess.check_output(
            ["git", "-C", root, "remote", "get-url", "origin"],
            stderr=subprocess.DEVNULL,
        ).decode().strip()
    except Exception:                                    # noqa: BLE001
        return "OWNER/REPO"
    if url.startswith("git@github.com:"):
        url = url[len("git@github.com:"):]
    elif "github.com/" in url:
        url = url.split("github.com/", 1)[1]
    return url[:-4] if url.endswith(".git") else url


def main() -> int:
    repo = default_repo()
    if "--repo" in sys.argv:
        repo = sys.argv[sys.argv.index("--repo") + 1]

    secrets_json = os.path.join(HERE, "secrets.json")
    if not os.path.exists(secrets_json):
        print("tools/secrets.json 不存在 —— 先放好真配置")
        return 2
    payload = open(secrets_json, "rb").read()
    parsed = json.loads(payload.decode("utf-8"))
    print("repo   : %s" % repo)
    print("secret : SECRETS_JSON (%d bytes, %d entries)" % (len(payload), len(parsed["entries"])))

    if "--check" in sys.argv:
        return 0

    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        print("missing GITHUB_TOKEN")
        return 2

    pk = api("/repos/%s/actions/secrets/public-key" % repo, token)
    api("/repos/%s/actions/secrets/SECRETS_JSON" % repo, token, method="PUT",
        payload={"encrypted_value": encrypt(pk["key"], payload), "key_id": pk["key_id"]})
    print("uploaded SECRETS_JSON -> %s" % repo)
    return 0


if __name__ == "__main__":
    sys.exit(main())
