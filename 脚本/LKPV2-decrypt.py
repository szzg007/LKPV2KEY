#!/usr/bin/env python3
"""
LKPV2-decrypt (修复版) — 按 ADR-plan-s-v2 §四 解密 .csk / .ckb

修复历史:
  - v1 (5月20日): 占位实现，仅识别 CSK2 头部，不真正解密
  - v2 (7月02日): 重写完整解密逻辑，支持单文件和目录批量解密

用法:
  python3 LKPV2-decrypt.py <encrypted.csk> [output.md]
  python3 LKPV2-decrypt.py <directory>     # 批量解密目录下所有 .csk 文件

环境变量:
  LKPV2_KEY_DIR  指定密钥目录（默认 ~/Desktop/LKPV2解密/密钥套件0702）
"""

import os
import sys
import struct
import hashlib
import glob
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

MAGIC_SKILL = b"CSK2"
MAGIC_KB = b"CKB2"

DEFAULT_KEY_DIR = os.path.expanduser("~/Desktop/LKPV2解密/密钥套件0702")


def hkdf_derive(input_key_material: bytes, info: str, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"conaeon-dek-v1",
        info=info.encode("utf-8"),
    ).derive(input_key_material)


def load_keys(key_dir: str):
    """加载密钥（必须在解密前调用）"""
    device_priv = load_pem_private_key(
        open(os.path.join(key_dir, "device_private_key.pem"), "rb").read(),
        password=None,
    )
    signer_pub = load_pem_public_key(
        open(os.path.join(key_dir, "online_signer_public_key.pem"), "rb").read()
    )
    return device_priv, signer_pub


def decrypt_csk(enc_path: str, device_priv, signer_pub):
    """解密单个 .csk 文件，返回明文字节

    ADR-plan-s-v2 §四 TLV 布局:
      [4] Magic (CSK2)
      [4] Version
      [2] alg_id
      [32] content_id
      [1] eph_pubkey_len
      [eph_pubkey_len] eph_pubkey_bytes
      [12] wrap_nonce
      [32] wrapped_cek
      [16] wrap_tag
      [12] content_nonce
      [N] ciphertext
      [16] content_auth_tag
      [cert_pem_len] signer_cert_pem
      [64] vendor_signature
    """
    data = open(enc_path, "rb").read()
    o = 0

    magic = data[o:o+4]; o += 4
    if magic not in (MAGIC_SKILL, MAGIC_KB):
        raise ValueError(f"无效的魔数: {magic}")
    version = struct.unpack(">I", data[o:o+4])[0]; o += 4
    alg_id = struct.unpack(">H", data[o:o+2])[0]; o += 2
    content_id = data[o:o+32]; o += 32

    eph_len = struct.unpack(">B", data[o:o+1])[0]; o += 1
    eph_pub = data[o:o+eph_len]; o += eph_len
    wrap_nonce = data[o:o+12]; o += 12
    wrapped_cek = data[o:o+32]; o += 32
    wrap_tag = data[o:o+16]; o += 16

    content_nonce = data[o:o+12]; o += 12

    # 从尾部倒推: sig(64) + cert_pem + auth_tag(16) + ciphertext
    sig = data[-64:]
    sig_start = len(data) - 64
    cert_begin = data.rfind(b"-----BEGIN CERTIFICATE-----\n", 0, sig_start)
    if cert_begin < 0:
        raise ValueError("未找到签名证书")
    if cert_begin < 16:
        raise ValueError("auth_tag 位置异常")
    auth_tag = data[cert_begin-16:cert_begin]
    ciphertext = data[o:cert_begin-16]

    # 验证签名
    ct_hash = hashlib.sha256(ciphertext).digest()
    rebuilt = struct.pack(">B", eph_len) + eph_pub + wrap_nonce + wrapped_cek + wrap_tag
    signed_bytes = (
        magic + struct.pack(">I", version) + struct.pack(">H", alg_id) +
        content_id + rebuilt + content_nonce + ct_hash + auth_tag
    )
    signer_pub.verify(sig, signed_bytes)

    # ECDH 派生 wrap_key 并解包 CEK
    eph_pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), eph_pub)
    shared = device_priv.exchange(ec.ECDH(), eph_pk)
    wrap_key = hkdf_derive(shared, f"wrap-key-{content_id.hex()[:16]}")
    cek = AESGCM(wrap_key).decrypt(wrap_nonce, wrapped_cek + wrap_tag, None)

    # 用 CEK 解密内容
    plaintext = AESGCM(cek).decrypt(content_nonce, ciphertext + auth_tag, None)

    return plaintext, magic.decode("ascii"), version


def decrypt_single_file(enc_path: str, out_path, key_dir: str):
    device_priv, signer_pub = load_keys(key_dir)
    plaintext, magic, version = decrypt_csk(enc_path, device_priv, signer_pub)

    if out_path:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(plaintext)
        print(f"  ✅ 解密 → {out_path} ({len(plaintext):,} bytes)")
    else:
        sys.stdout.buffer.write(plaintext)
    return True


def decrypt_directory(directory: str, out_dir: str, key_dir: str):
    """批量解密目录"""
    device_priv, signer_pub = load_keys(key_dir)

    csk_files = sorted(glob.glob(os.path.join(directory, "*.csk")))
    print(f"📁 {directory}: 找到 {len(csk_files)} 个 .csk 文件")

    success = 0
    failed = []
    for csk_path in csk_files:
        name = os.path.splitext(os.path.basename(csk_path))[0]
        out_path = os.path.join(out_dir, name, "SKILL.md")
        try:
            plaintext, magic, version = decrypt_csk(csk_path, device_priv, signer_pub)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(plaintext)
            print(f"  ✅ {name}.csk → {name}/SKILL.md ({len(plaintext):,} bytes)")
            success += 1
        except Exception as e:
            print(f"  ❌ {name}: {e}")
            failed.append(name)

    print(f"\n📊 解密完成: 成功={success} 失败={len(failed)}")
    if failed:
        print(f"  失败: {', '.join(failed)}")
    return success, failed


def main():
    print("🔓 LKPV2 Decrypt (修复版)")
    print(f"时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print()

    key_dir = os.environ.get("LKPV2_KEY_DIR", DEFAULT_KEY_DIR)
    if not os.path.isdir(key_dir):
        print(f"❌ 密钥目录不存在: {key_dir}")
        return 1

    if len(sys.argv) < 2:
        print("用法:")
        print("  python3 LKPV2-decrypt.py <encrypted.csk> [output.md]")
        print("  python3 LKPV2-decrypt.py <directory>")
        print()
        print("环境变量:")
        print(f"  LKPV2_KEY_DIR  (默认: {DEFAULT_KEY_DIR})")
        return 1

    target = sys.argv[1]

    if os.path.isfile(target):
        out = sys.argv[2] if len(sys.argv) > 2 else None
        try:
            decrypt_single_file(target, out, key_dir)
            return 0
        except Exception as e:
            print(f"❌ 解密失败: {e}")
            return 1

    elif os.path.isdir(target):
        out_dir = sys.argv[2] if len(sys.argv) > 2 else \
                  os.path.expanduser("~/.openclaw/runtime/skills")
        success, failed = decrypt_directory(target, out_dir, key_dir)
        return 0 if not failed else 1

    else:
        print(f"❌ 文件/目录不存在: {target}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
