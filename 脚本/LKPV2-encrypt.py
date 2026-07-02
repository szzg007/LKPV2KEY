#!/usr/bin/env python3
"""
LKPV2-encrypt — 按 ADR-plan-s-v2 §四 TLV 格式加密 .md → .csk / .ckb

加密流程 (按 ADR §五 BUILD 阶段):
  1. 生成独立 CEK (AES-256)
  2. 用 CEK 加密 .md → ciphertext + content_auth_tag
  3. 生成 ephemeral P-256 密钥对 (用于 per-customer wrapped_CEK)
  4. ECDH(eph_priv, Device Public Key) → shared secret
  5. HKDF 派生 wrap_key
  6. AES-256-GCM(wrap_key, CEK) → wrapped_CEK + wrap_tag
  7. 组装 TLV 包头 + 包体 + signing block
  8. 用 Online Package Signer 签名 canonical_bytes
  9. 输出 .csk (skill) 或 .ckb (knowledge base)

⚠️  注意:
  - 本脚本是开发态 (per ADR §五 v1 错误纠正: 不每次激活重加密内容)
  - 真正的生产环境应:
    * CEK 通过 KMS/HSM 包裹存 vault (E3 P0 修复)
    * per-customer 激活时只重包 wrapped_CEK (per §五 INSTALL 阶段)
    * 签名走独立签名服务 (Online Package Signer Service, §三-bis 安全域 2)

用法:
  python3 LKPV2-encrypt.py \\
      --key-dir KEY2.0 \\
      --device-passphrase-env LKPV2_DEVICE_PASS \\
      input.md output.csk
"""

import os
import sys
import struct
import secrets
import hashlib
import argparse
import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)


# ============================================================================
# ADR-plan-s-v2 §四 TLV 包结构
# ============================================================================

MAGIC_SKILL = b"CSK2"   # Skill
MAGIC_KB    = b"CKB2"   # Knowledge Base
VERSION     = 2

# alg_id 编码 (高字节 = 内容加密, 低字节 = 密钥包裹)
ALG_AES256_GCM          = 0x0001  # 内容加密
ALG_P256_ECDH_AES256_GCM = 0x0101  # 密钥包裹
ALG_ED25519             = 0x0201  # 签名


def hkdf_derive(input_key_material: bytes, info: str, length: int = 32) -> bytes:
    """ADR §六 HKDF 派生"""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"conaeon-dek-v1",
        info=info.encode("utf-8"),
    ).derive(input_key_material)


def build_canonical_signed_bytes(
    magic: bytes,
    version: int,
    alg_id: int,
    content_id: bytes,
    wrapped_cek_blob: bytes,
    content_nonce: bytes,
    ciphertext: bytes,
    content_auth_tag: bytes,
) -> bytes:
    """ADR §四 Canonical Signing Bytes (修复 A4)
    签名覆盖完整 manifest, 不含 vendor_signature 本身
    """
    return (
        magic
        + struct.pack(">I", version)
        + struct.pack(">H", alg_id)
        + content_id
        + wrapped_cek_blob
        + content_nonce
        + hashlib.sha256(ciphertext).digest()
        + content_auth_tag
    )


def assemble_package(
    magic: bytes,
    content_id: bytes,
    eph_pubkey_bytes: bytes,
    wrap_nonce: bytes,
    wrapped_cek: bytes,
    wrap_tag: bytes,
    content_nonce: bytes,
    ciphertext: bytes,
    content_auth_tag: bytes,
    signer_cert_pem: bytes,
    vendor_signature: bytes,
) -> bytes:
    """组装完整 .csk/.ckb 包"""
    wrapped_cek_blob = (
        struct.pack(">B", len(eph_pubkey_bytes))
        + eph_pubkey_bytes
        + wrap_nonce
        + wrapped_cek
        + wrap_tag
    )
    return (
        magic
        + struct.pack(">I", VERSION)
        + struct.pack(">H", ALG_P256_ECDH_AES256_GCM)
        + content_id
        + wrapped_cek_blob
        + content_nonce
        + ciphertext
        + content_auth_tag
        + signer_cert_pem
        + vendor_signature
    )


# ============================================================================
# 加密主流程
# ============================================================================

def encrypt_file(
    plaintext: bytes,
    device_pubkey_pem: bytes,
    signer_priv_key,
    signer_cert_pem: bytes,
    output_kind: str = "skill",  # "skill" or "kb"
) -> bytes:
    magic = MAGIC_SKILL if output_kind == "skill" else MAGIC_KB

    # 1. 生成 content_id (32 bytes random, per-file unique)
    content_id = secrets.token_bytes(32)

    # 2. 生成独立 CEK (AES-256)
    cek = secrets.token_bytes(32)

    # 3. 生成 content_nonce (per ADR §四 协议级要求: HKDF 派生)
    content_nonce = hkdf_derive(content_id, "content-nonce-v2", 12)

    # 4. 用 CEK 加密内容
    content_aead = AESGCM(cek)
    ciphertext_with_tag = content_aead.encrypt(content_nonce, plaintext, None)
    ciphertext = ciphertext_with_tag[:-16]
    content_auth_tag = ciphertext_with_tag[-16:]

    # 5. 生成 ephemeral P-256 密钥对 (per-customer wrapped_CEK)
    eph_priv = ec.generate_private_key(ec.SECP256R1())
    eph_pub = eph_priv.public_key()
    eph_pub_bytes = eph_pub.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.CompressedPoint,
    )

    # 6. 加载 Device Public Key
    device_pub = serialization.load_pem_public_key(device_pubkey_pem)

    # 7. ECDH + HKDF 派生 wrap_key
    shared_secret = eph_priv.exchange(ec.ECDH(), device_pub)
    wrap_key = hkdf_derive(shared_secret, f"wrap-key-{content_id.hex()[:16]}")

    # 8. AES-256-GCM 包裹 CEK
    wrap_nonce = secrets.token_bytes(12)
    wrap_aead = AESGCM(wrap_key)
    wrapped_cek_with_tag = wrap_aead.encrypt(wrap_nonce, cek, None)
    wrapped_cek = wrapped_cek_with_tag[:-16]
    wrap_tag = wrapped_cek_with_tag[-16:]

    # 9. 组装 wrapped_CEK_blob
    wrapped_cek_blob = (
        struct.pack(">B", len(eph_pub_bytes))
        + eph_pub_bytes
        + wrap_nonce
        + wrapped_cek
        + wrap_tag
    )

    # 10. 签名 canonical_bytes
    signed_bytes = build_canonical_signed_bytes(
        magic, VERSION, ALG_P256_ECDH_AES256_GCM,
        content_id, wrapped_cek_blob,
        content_nonce, ciphertext, content_auth_tag,
    )
    vendor_signature = signer_priv_key.sign(signed_bytes)

    # 11. 组装完整包
    package = assemble_package(
        magic, content_id,
        eph_pub_bytes, wrap_nonce,
        wrapped_cek, wrap_tag,
        content_nonce, ciphertext, content_auth_tag,
        signer_cert_pem, vendor_signature,
    )

    return package


def main():
    parser = argparse.ArgumentParser(
        description="LKPV2-encrypt — 按 ADR-plan-s-v2 §四 加密 .md → .csk/.ckb",
    )
    parser.add_argument("input", help="输入文件 (.md)")
    parser.add_argument("output", help="输出文件 (.csk 或 .ckb)")
    parser.add_argument(
        "--key-dir",
        default=os.path.expanduser("~/Desktop/LKPV2解密/KEY2.0"),
        help="KEY2.0 目录路径",
    )
    parser.add_argument(
        "--kind",
        choices=["skill", "kb"],
        default=None,
        help="包类型 (skill→.csk / kb→.ckb), 默认按扩展名推断",
    )
    parser.add_argument(
        "--signer-passphrase-env",
        default="LKPV2_SIGNER_PASS",
        help="Online Signer 私钥 passphrase 环境变量名 (开发态通常无, 仅 device 需要)",
    )
    args = parser.parse_args()

    key_dir = os.path.abspath(args.key_dir)
    if not os.path.isdir(key_dir):
        print(f"❌ KEY2.0 目录不存在: {key_dir}")
        print(f"   请先运行: python3 LKPV2-keygen.py --output-dir {key_dir}")
        return 1

    # 推断类型
    kind = args.kind
    if kind is None:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".csk":
            kind = "skill"
        elif ext == ".ckb":
            kind = "kb"
        else:
            print(f"❌ 无法推断包类型, 请 --kind 指定: {args.output}")
            return 1

    # 读输入
    with open(args.input, "rb") as f:
        plaintext = f.read()

    # 加载密钥
    device_pub_pem_path = os.path.join(key_dir, "device_public_key.pem")
    signer_priv_path = os.path.join(key_dir, "online_signer_private_key.pem")
    signer_cert_path = os.path.join(key_dir, "online_signer_cert.pem")

    if not os.path.exists(device_pub_pem_path):
        print(f"❌ 缺少: {device_pub_pem_path}")
        return 1
    if not os.path.exists(signer_priv_path):
        print(f"❌ 缺少: {signer_priv_path}")
        return 1
    if not os.path.exists(signer_cert_path):
        print(f"❌ 缺少: {signer_cert_path}")
        return 1

    with open(device_pub_pem_path, "rb") as f:
        device_pub_pem = f.read()
    with open(signer_cert_path, "rb") as f:
        signer_cert_pem = f.read()

    # 加载 Online Signer 私钥 (开发态: 无 passphrase)
    signer_passphrase = os.environ.get(args.signer_passphrase_env, "").encode() or None
    with open(signer_priv_path, "rb") as f:
        signer_priv = load_pem_private_key(f.read(), password=signer_passphrase)

    print("=" * 70)
    print("LKPV2-encrypt — ADR-plan-s-v2 §四 TLV 加密")
    print("=" * 70)
    print(f"📥 输入: {args.input} ({len(plaintext):,} bytes)")
    print(f"📤 输出: {args.output}")
    print(f"📂 KEY2.0: {key_dir}")
    print(f"🏷️  类型: {kind}")
    print()

    # 加密
    package = encrypt_file(
        plaintext=plaintext,
        device_pubkey_pem=device_pub_pem,
        signer_priv_key=signer_priv,
        signer_cert_pem=signer_cert_pem,
        output_kind=kind,
    )

    # 写文件
    with open(args.output, "wb") as f:
        f.write(package)
    os.chmod(args.output, 0o644)

    overhead = len(package) - len(plaintext)
    print(f"✅ 加密完成")
    print(f"   原文: {len(plaintext):,} bytes")
    print(f"   密文: {len(package):,} bytes (overhead {overhead} bytes, ADR §四预估 +260)")
    print(f"   魔数: {'CSK2' if kind == 'skill' else 'CKB2'}")
    print(f"   算法: alg_id=0x{ALG_P256_ECDH_AES256_GCM:04x} (P-256 ECDH + AES-256-GCM + Ed25519)")
    print()
    print("🔒 安全: 仅 Online Signer 私钥 + Device Public Key 参与加密.")
    print("    CEK 用 Device PubKey 包裹, 无 Device Private Key 无法解.")

    return 0


if __name__ == "__main__":
    sys.exit(main())