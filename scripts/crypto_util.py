# -*- coding: utf-8 -*-
"""
AES-256-GCM + PBKDF2-SHA256 加解密工具
与前端 Web Crypto API 完全互通（同一 salt/iv/iter/算法参数即可互相解开）

密文 JSON 结构（公开放仓库也不泄露内容）:
{
  "v": 1, "alg": "AES-GCM", "kdf": "PBKDF2-SHA256", "iter": 210000,
  "salt": "base64", "iv": "base64", "ct": "base64",
  "updated": "2026-10-31T01:40:00+08:00", "by": "gfwair-clash-sync"
}
"""
import base64
import json
import os
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 210000
SALT_LEN = 16
IV_LEN = 12


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def derive_key(password: str, salt: bytes, iterations: int = ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_payload(password: str, data: dict, updated: str = "") -> dict:
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    key = derive_key(password, salt)
    ct = AESGCM(key).encrypt(iv, plaintext, None)
    if not updated:
        updated = datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds")
    return {
        "v": 1,
        "alg": "AES-GCM",
        "kdf": "PBKDF2-SHA256",
        "iter": ITERATIONS,
        "salt": _b64e(salt),
        "iv": _b64e(iv),
        "ct": _b64e(ct),
        "updated": updated,
        "by": "gfwair-clash-sync",
    }


def decrypt_payload(password: str, blob: dict) -> dict:
    salt = _b64d(blob["salt"])
    iv = _b64d(blob["iv"])
    ct = _b64d(blob["ct"])
    key = derive_key(password, salt, int(blob.get("iter", ITERATIONS)))
    plaintext = AESGCM(key).decrypt(iv, ct, None)
    return json.loads(plaintext.decode("utf-8"))


def mask_url(u: str) -> str:
    """脱敏显示订阅链接，日志里不打印完整 token"""
    if not u:
        return "(空)"
    if len(u) <= 18:
        return u[:6] + "***"
    return u[:16] + "..." + u[-6:]


if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 3 and sys.argv[1] == "selftest":
        pwd = sys.argv[2]
        demo = {"sub": "https://demo.example/api/v1/client/subscribe?token=ABC123", "note": "自检"}
        blob = encrypt_payload(pwd, demo)
        back = decrypt_payload(pwd, blob)
        assert back == demo, "自检失败：解密结果不一致"
        print("自检通过，密文长度", len(blob["ct"]))
        print(json.dumps(blob, ensure_ascii=False)[:160], "...")
    else:
        print("用法: python crypto_util.py selftest <密码>")
