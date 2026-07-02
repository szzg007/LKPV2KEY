#!/usr/bin/env python3
"""
Plan S v2 加密方案测试脚本
测试范围：
  1. szzg007-tavily-search SKILL.md → .csk
  2. knowledge/架构/ 下全部文件 → .ckb

按照 ADR-plan-s-v2 规范实现：
  - CEK (AES-256) 加密内容
  - Device Key (P-256) 包裹 CEK
  - Ed25519 签名
  - 模拟 Build → Install → Runtime 全流程
"""

import os
import sys
import json
import hashlib
import time
import struct
import glob
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ============================================================
# 工具函数
# ============================================================

def hkdf_derive(input_key_material: bytes, info: str, length: int = 32) -> bytes:
    """HKDF-SHA256 派生密钥"""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"conaeon-dek-v1",
        info=info.encode("utf-8"),
    ).derive(input_key_material)

def generate_content_id(filename: str) -> bytes:
    """生成 32 字节 content_id"""
    h = hashlib.sha256()
    h.update(filename.encode("utf-8"))
    h.update(str(time.time()).encode("utf-8"))
    return h.digest()

# ============================================================
# Phase 1: Build 阶段 — 生成密钥
# ============================================================

def phase1_build():
    """模拟 Build 阶段"""
    print("=" * 60)
    print("📦 Phase 1: Build 阶段")
    print("=" * 60)

    # 1.1 Offline Root Key (Ed25519)
    print("\n[1.1] 生成 Offline Root Signing Key (Ed25519)")
    offline_root_private = ed25519.Ed25519PrivateKey.generate()
    offline_root_public = offline_root_private.public_key()
    print(f"  ✅ Offline Root Public Key 已生成")

    # 1.2 Online Package Signer Key (Ed25519)
    print("\n[1.2] 生成 Online Package Signer Key (Ed25519)")
    online_signer_private = ed25519.Ed25519PrivateKey.generate()
    online_signer_public = online_signer_private.public_key()
    print(f"  ✅ Online Package Signer Key 已生成")

    # 1.3 KEK (AES-256) — 模拟 KMS
    print("\n[1.3] 生成 KEK (AES-256) — 模拟 KMS")
    kek = os.urandom(32)
    print(f"  ✅ KEK 已生成 (32 bytes)")

    # 1.4 Lease Issuer Key (Ed25519)
    print("\n[1.4] 生成 Lease Issuer Key (Ed25519)")
    lease_issuer_private = ed25519.Ed25519PrivateKey.generate()
    lease_issuer_public = lease_issuer_private.public_key()
    print(f"  ✅ Lease Issuer Key 已生成")

    return {
        "offline_root_private": offline_root_private,
        "offline_root_public": offline_root_public,
        "online_signer_private": online_signer_private,
        "online_signer_public": online_signer_public,
        "kek": kek,
        "lease_issuer_private": lease_issuer_private,
        "lease_issuer_public": lease_issuer_public,
    }

# ============================================================
# Phase 2: 加密 + 打包
# ============================================================

def build_package(plaintext: bytes, filename: str, device_public_key,
                  online_signer_private, kek: bytes, magic: str) -> dict:
    """
    完整构建 .csk / .ckb 包：
    1. 生成独立 CEK
    2. 用 CEK 加密内容
    3. 用 KEK 包裹 CEK (模拟 KMS)
    4. 用 Device Public Key + ECDH 重包 CEK (per-customer)
    5. 签名
    6. 组装文件
    """
    content_id = generate_content_id(filename)

    # Step 1: 生成 CEK
    cek = os.urandom(32)

    # Step 2: 用 KEK 包裹 CEK (模拟 KMS vault 存储)
    kek_nonce = os.urandom(12)
    cek_aead = AESGCM(kek)
    wrapped_cek_persistent = cek_aead.encrypt(kek_nonce, cek, None)

    # Step 3: 用 Device Public Key + ECDH 重包 CEK (per-customer)
    # Ephemeral key
    eph_private = ec.generate_private_key(ec.SECP256R1())
    eph_public = eph_private.public_key()
    eph_public_bytes = eph_public.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    # ECDH shared secret
    shared_secret = eph_private.exchange(ec.ECDH(), device_public_key)

    # HKDF 派生 wrap_key
    wrap_key = hkdf_derive(shared_secret, f"wrap-key-{content_id.hex()[:16]}")

    # AES-256-GCM 包裹 CEK (per-customer)
    wrap_nonce = os.urandom(12)
    wrap_aead = AESGCM(wrap_key)
    wrapped_cek_with_tag = wrap_aead.encrypt(wrap_nonce, cek, None)
    wrapped_cek = wrapped_cek_with_tag[:-16]  # 32 bytes
    wrap_tag = wrapped_cek_with_tag[-16:]     # 16 bytes

    # Step 4: 派生 content_nonce (按 v2 规范)
    content_nonce = HKDF(
        algorithm=hashes.SHA256(),
        length=12,
        salt=b"",
        info=b"content-nonce-v2",
    ).derive(content_id)

    # Step 5: 用 CEK 加密内容
    content_aead = AESGCM(cek)
    ciphertext_and_tag = content_aead.encrypt(content_nonce, plaintext, None)
    # NOTE: AESGCM.encrypt returns ciphertext + 16-byte tag appended
    ciphertext = ciphertext_and_tag[:-16]
    content_auth_tag = ciphertext_and_tag[-16:]

    # Step 6: 构建 wrapped_CEK_blob
    # [eph_pubkey_len (1)] [eph_pubkey (65)] [wrap_nonce (12)] [wrapped_CEK (32)] [wrap_tag (16)]
    wrapped_cek_blob = (
        struct.pack(">B", len(eph_public_bytes)) +
        eph_public_bytes +
        wrap_nonce +
        wrapped_cek +
        wrap_tag
    )

    # Step 7: 构建 canonical signing bytes
    magic_bytes = magic.encode("ascii")[:4]
    version = 2
    alg_id = 1  # AES-256-GCM + P-256 ECDH + Ed25519

    # 签名覆盖范围 (v2 规范)
    ciphertext_hash = hashlib.sha256(ciphertext).digest()
    signed_bytes = (
        magic_bytes +
        struct.pack(">I", version) +
        struct.pack(">H", alg_id) +
        content_id +
        wrapped_cek_blob +
        content_nonce +
        ciphertext_hash +
        content_auth_tag
    )

    # Step 8: Ed25519 签名
    vendor_signature = online_signer_private.sign(signed_bytes)

    # Step 9: 组装完整文件
    file_data = b""
    # Header
    file_data += magic_bytes                          # magic (4)
    file_data += struct.pack(">I", version)           # version (4)
    file_data += struct.pack(">H", alg_id)            # alg_id (2)
    file_data += content_id                           # content_id (32)
    file_data += wrapped_cek_blob                     # wrapped_CEK_blob (1+65+12+32+16=126)
    # Encrypted Content
    file_data += content_nonce                        # content_nonce (12)
    file_data += ciphertext                           # ciphertext (variable)
    file_data += content_auth_tag                     # content_auth_tag (16)
    # Signing Block
    file_data += vendor_signature                     # vendor_signature (64)

    # 清除敏感数据
    del cek

    return {
        "file_data": file_data,
        "content_id": content_id,
        "filename": filename,
        "original_size": len(plaintext),
        "package_size": len(file_data),
        "magic": magic,
    }

# ============================================================
# Phase 3: 运行时解密
# ============================================================

def decrypt_package(file_data: bytes, device_private_key,
                    online_signer_public) -> dict:
    """
    解密 .csk / .ckb 文件，模拟 helper 进程运行时解密
    """
    offset = 0

    # 1. 解析 Header
    magic = file_data[offset:offset+4]; offset += 4
    version = struct.unpack(">I", file_data[offset:offset+4])[0]; offset += 4
    alg_id = struct.unpack(">H", file_data[offset:offset+2])[0]; offset += 2
    content_id = file_data[offset:offset+32]; offset += 32

    # 2. 解析 wrapped_CEK_blob
    eph_pubkey_len = struct.unpack(">B", file_data[offset:offset+1])[0]; offset += 1
    eph_pubkey_bytes = file_data[offset:offset+eph_pubkey_len]; offset += eph_pubkey_len
    wrap_nonce = file_data[offset:offset+12]; offset += 12
    wrapped_cek = file_data[offset:offset+32]; offset += 32
    wrap_tag = file_data[offset:offset+16]; offset += 16

    # 3. 解析 Encrypted Content
    content_nonce = file_data[offset:offset+12]; offset += 12
    # ciphertext 长度 = 总长 - 已解析 - content_auth_tag(16) - signing block(64)
    ciphertext_len = len(file_data) - offset - 16 - 64
    ciphertext = file_data[offset:offset+ciphertext_len]; offset += ciphertext_len
    content_auth_tag = file_data[offset:offset+16]; offset += 16

    # 4. 解析 Signing Block
    vendor_signature = file_data[offset:offset+64]

    # 5. 验证签名
    ciphertext_hash = hashlib.sha256(ciphertext).digest()
    rebuilt_blob = (
        struct.pack(">B", eph_pubkey_len) +
        eph_pubkey_bytes +
        wrap_nonce +
        wrapped_cek +
        wrap_tag
    )
    signed_bytes = (
        magic +
        struct.pack(">I", version) +
        struct.pack(">H", alg_id) +
        content_id +
        rebuilt_blob +
        content_nonce +
        ciphertext_hash +
        content_auth_tag
    )
    # DEBUG: compare signed_bytes
    with open("/tmp/decrypt_signed_bytes.bin", "wb") as _df:
        _df.write(signed_bytes)
    # Also load build signed_bytes
    script_dir = os.path.dirname(os.path.abspath(__file__))
    build_files = glob.glob(os.path.join(script_dir, "plan-s-test-output", "*.build.sb"))
    if build_files:
        with open(build_files[0], "rb") as f:
            build_sb = f.read()
        if build_sb != signed_bytes:
            print(f"  DEBUG: signed_bytes mismatch! build={len(build_sb)} decrypt={len(signed_bytes)}")
            for i in range(min(len(build_sb), len(signed_bytes))):
                if build_sb[i] != signed_bytes[i]:
                    print(f"  DEBUG: first diff at byte {i}: build={build_sb[i]:02x} decrypt={signed_bytes[i]:02x}")
                    print(f"  DEBUG: build context: {build_sb[max(0,i-3):i+3].hex()}")
                    print(f"  DEBUG: decrypt context: {signed_bytes[max(0,i-3):i+3].hex()}")
                    break
            import shutil
            shutil.copy(build_files[0], "/tmp/build.sb")
            with open("/tmp/dec.sb", "wb") as f:
                f.write(signed_bytes)
    online_signer_public.verify(vendor_signature, signed_bytes)

    # 6. ECDH 解包 CEK
    eph_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), eph_pubkey_bytes
    )
    shared_secret = device_private_key.exchange(ec.ECDH(), eph_public_key)
    wrap_key = hkdf_derive(shared_secret, f"wrap-key-{content_id.hex()[:16]}")

    wrap_aead = AESGCM(wrap_key)
    cek = wrap_aead.decrypt(wrap_nonce, wrapped_cek + wrap_tag, None)

    # 7. 用 CEK 解密内容
    content_aead = AESGCM(cek)
    plaintext = content_aead.decrypt(content_nonce, ciphertext + content_auth_tag, None)

    # 8. 清除敏感数据
    del cek

    return {
        "magic": magic,
        "version": version,
        "content_id": content_id,
        "plaintext": plaintext,
        "plaintext_size": len(plaintext),
        "signature_verified": True,
    }

# ============================================================
# 测试执行
# ============================================================

def main():
    print("\n" + "🔐" * 30)
    print("Plan S v2 加密方案测试")
    print(f"测试时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("🔐" * 30 + "\n")

    # Phase 1: Build
    keys = phase1_build()

    # Phase 2: 模拟客户机激活
    print("\n" + "=" * 60)
    print("💻 Phase 2: Install 阶段 — 客户机激活")
    print("=" * 60)

    print("\n[2.1] 生成 Device Key Pair (P-256)")
    device_private = ec.generate_private_key(ec.SECP256R1())
    device_public = device_private.public_key()
    print(f"  ✅ Device Key Pair 已生成")

    # 准备测试文件列表
    test_files = [
        {
            "path": "/Users/kfj-001/.openclaw_test/workspace/skills/szzg007-tavily-search/SKILL.md",
            "name": "szzg007-tavily-search/SKILL.md",
            "magic": "CSK2",
            "is_skill": True,
        },
        {
            "path": "/Users/kfj-001/.openclaw_test/workspace-main/knowledge/架构/agents.md",
            "name": "knowledge/架构/agents.md",
            "magic": "CKB2",
            "is_skill": False,
        },
        {
            "path": "/Users/kfj-001/.openclaw_test/workspace-main/knowledge/架构/monitoring.md",
            "name": "knowledge/架构/monitoring.md",
            "magic": "CKB2",
            "is_skill": False,
        },
        {
            "path": "/Users/kfj-001/.openclaw_test/workspace-main/knowledge/架构/scripts-index.md",
            "name": "knowledge/架构/scripts-index.md",
            "magic": "CKB2",
            "is_skill": False,
        },
    ]

    output_dir = "/Users/kfj-001/.openclaw_test/plan-s-test-output"
    os.makedirs(output_dir, exist_ok=True)

    results = []

    for tf in test_files:
        print(f"\n{'─' * 50}")
        print(f"📄 处理文件: {tf['name']}")

        # 读取原始内容
        with open(tf["path"], "rb") as f:
            original_content = f.read()
        original_hash = hashlib.sha256(original_content).hexdigest()[:16]
        print(f"  📥 原始大小: {len(original_content)} bytes (SHA256: {original_hash}...)")

        # 加密 + 打包
        package = build_package(
            original_content, tf["name"], device_public,
            keys["online_signer_private"], keys["kek"], tf["magic"]
        )

        # 保存加密包
        ext = ".csk" if tf["is_skill"] else ".ckb"
        safe_name = tf["name"].replace("/", "_").replace(" ", "_")
        output_path = os.path.join(output_dir, safe_name + ext)
        with open(output_path, "wb") as f:
            f.write(package["file_data"])

        print(f"  📦 打包完成: {output_path}")
        print(f"     包大小: {package['package_size']} bytes (原始: {package['original_size']} bytes)")
        print(f"     开销: +{package['package_size'] - package['original_size']} bytes")

        # Phase 3: 运行时解密测试
        print(f"\n  🔓 Phase 3: 运行时解密测试")
        try:
            decrypted = decrypt_package(
                package["file_data"], device_private,
                keys["online_signer_public"]
            )

            decrypted_hash = hashlib.sha256(decrypted["plaintext"]).hexdigest()[:16]
            match = original_hash == decrypted_hash

            print(f"  ✅ 解密成功!")
            print(f"     签名验证: {'✅ 通过' if decrypted['signature_verified'] else '❌ 失败'}")
            print(f"     解密大小: {decrypted['plaintext_size']} bytes")
            print(f"     内容哈希: {decrypted_hash}... {'✅ 匹配' if match else '❌ 不匹配'}")
            print(f"     包格式: {decrypted['magic']} v{decrypted['version']}")

            # 保存解密结果
            dec_path = output_path.replace(ext, ".decrypted.md")
            with open(dec_path, "wb") as f:
                f.write(decrypted["plaintext"])

            results.append({
                "file": tf["name"],
                "package": output_path,
                "original_size": package["original_size"],
                "package_size": package["package_size"],
                "decrypted_size": decrypted["plaintext_size"],
                "hash_match": match,
                "status": "✅ PASS" if match else "❌ FAIL",
            })

        except Exception as e:
            print(f"  ❌ 解密失败: {e}")
            import traceback
            traceback.print_exc()
            results.append({
                "file": tf["name"],
                "package": output_path,
                "status": f"❌ FAIL: {e}",
            })

    # 汇总报告
    print("\n" + "=" * 60)
    print("📊 测试汇总报告")
    print("=" * 60)

    passed = sum(1 for r in results if r.get("hash_match", False))
    total = len(results)

    print(f"\n总计: {passed}/{total} 通过\n")

    for r in results:
        status = r["status"]
        file = r["file"]
        if "original_size" in r:
            overhead = r["package_size"] - r["original_size"]
            print(f"  {status} {file}")
            print(f"     原始: {r['original_size']}B → 加密包: {r['package_size']}B (+{overhead}B 开销)")

    print(f"\n📁 加密包输出目录: {output_dir}")
    print(f"   文件列表:")
    for f in sorted(os.listdir(output_dir)):
        fpath = os.path.join(output_dir, f)
        fsize = os.path.getsize(fpath)
        print(f"     {f} ({fsize} bytes)")

    # 内容预览对比
    print(f"\n🔍 内容对比验证:")
    for r in results:
        if r.get("hash_match"):
            dec_path = r["package"].replace(".csk", ".decrypted.md").replace(".ckb", ".decrypted.md")
            if os.path.exists(dec_path):
                with open(dec_path, "r") as f:
                    preview = f.read()[:150].replace("\n", " ")
                print(f"  ✅ {r['file']}")
                print(f"     预览: {preview}...")

    # 验证加密包不可读
    print(f"\n🔒 加密包内容验证 (确认不可读):")
    for r in results:
        if "package" in r and os.path.exists(r["package"]):
            with open(r["package"], "rb") as f:
                raw = f.read()
            # 检查原始内容是否出现在加密包中
            with open([tf["path"] for tf in test_files if tf["name"] == r["file"]][0], "rb") as f:
                original = f.read()
            found = original in raw
            print(f"  {'❌ 原始内容泄露!' if found else '✅ 加密包中无明文内容'}: {r['file']}")

    print(f"\n{'🔐' * 30}")
    print("测试完成!")
    print(f"{'🔐' * 30}\n")

    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
