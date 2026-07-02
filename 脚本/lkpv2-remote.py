#!/usr/bin/env python3
"""
LKPV2 Remote Decrypt - 不落盘解密模块

工作原理:
  1. 从 GitHub raw 拉取密钥文件到内存 (BytesIO, 不写磁盘)
  2. 加载密钥到内存对象
  3. 解密 .csk 文件 (从磁盘读密文)
  4. 返回明文 bytes (调用方决定是否落盘)
  5. 密钥和明文均不写磁盘

用法:
  # 解密单个文件
  python3 lkpv2-remote.py <encrypted.csk> [output.md]
  
  # 解密整个目录
  python3 lkpv2-remote.py <directory> [output_directory]
  
  # 作为模块使用
  from lkpv2_remote import decrypt_file_in_memory, decrypt_directory_in_memory
  plaintext = decrypt_file_in_memory("/path/to/file.csk")
"""

import os
import sys
import struct
import hashlib
import glob
from io import BytesIO

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

# GitHub 仓库配置
GITHUB_OWNER = "szzg007"
GITHUB_REPO = "LKPV2KEY"
GITHUB_BRANCH = "main"
GITHUB_KEY_DIR = "密钥"  # 中文目录名

# 密钥文件清单（按需加载, 不一次性下载全部）
KEY_FILES = {
    "device_private_key.pem": "device",
    "device_public_key.pem": None,
    "online_signer_private_key.pem": None,
    "online_signer_public_key.pem": "signer_pub",
    "online_signer_cert.pem": None,
    "offline_root_private.pem": None,
    "offline_root_public.pem": None,
    "lease_issuer_private_key.pem": None,
    "lease_issuer_public_key.pem": None,
    "kek.bin": None,
    "revocation_manifest.json": None,
    "meta.json": None,
}

# Session 重用 (避免重复 TCP 握手)
_session = None


def get_session() -> requests.Session:
    """获取复用的 requests Session"""
    global _session
    if _session is None:
        _session = requests.Session()
        _session.headers.update({
            "User-Agent": "Conaeon-LKPV2-Remote/1.0",
            "Accept": "*/*",
        })
    return _session


def fetch_key_to_memory(filename: str, timeout: int = 30) -> bytes:
    """
    从 GitHub 拉取密钥文件到内存 (BytesIO)
    
    Args:
        filename: 密钥文件名 (如 device_private_key.pem)
        timeout: HTTP 超时秒数
    
    Returns:
        文件原始 bytes (不写磁盘)
    
    Raises:
        requests.HTTPError: HTTP 错误
        FileNotFoundError: 远程文件不存在
    """
    url = (
        f"https://raw.githubusercontent.com/{GITHUB_OWNER}/"
        f"{GITHUB_REPO}/{GITHUB_BRANCH}/{GITHUB_KEY_DIR}/{filename}"
    )
    
    session = get_session()
    response = session.get(url, timeout=timeout)
    
    if response.status_code == 404:
        raise FileNotFoundError(
            f"密钥文件不存在: {url}\n"
            f"请确认 {GITHUB_OWNER}/{GITHUB_REPO} 仓库已上传密钥"
        )
    
    response.raise_for_status()
    return response.content


def hkdf_derive(ikm: bytes, info: str, length: int = 32) -> bytes:
    """HKDF 密钥派生"""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"conaeon-dek-v1",
        info=info.encode("utf-8"),
    ).derive(ikm)


def decrypt_csk_in_memory(
    enc_data: bytes,
    device_priv_pem: bytes,
    signer_pub_pem: bytes,
) -> tuple[bytes, str, int]:
    """
    在内存中解密 .csk 文件
    
    Args:
        enc_data: 加密文件原始 bytes
        device_priv_pem: device 私钥 PEM (bytes, 从 GitHub 拉取)
        signer_pub_pem: online_signer 公钥 PEM (bytes)
    
    Returns:
        (plaintext, magic_str, version) 元组
    
    Raises:
        ValueError: 魔数错误 / 签名失败 / 解包失败
    """
    # 加载密钥到内存对象
    device_priv = load_pem_private_key(device_priv_pem, password=None)
    signer_pub = load_pem_public_key(signer_pub_pem)

    # 解析 TLV 布局
    if len(enc_data) < 4:
        raise ValueError(f"文件太小: {len(enc_data)} bytes")

    magic = enc_data[:4]
    if magic not in (b"CSK2", b"CKB2"):
        raise ValueError(f"无效的魔数: {magic}")
    magic_str = magic.decode("ascii")

    offset = 4
    version = struct.unpack(">I", enc_data[offset:offset + 4])[0]
    offset += 4
    alg_id = struct.unpack(">H", enc_data[offset:offset + 2])[0]
    offset += 2
    content_id = enc_data[offset:offset + 32]
    offset += 32

    eph_len = struct.unpack(">B", enc_data[offset:offset + 1])[0]
    offset += 1
    eph_pub = enc_data[offset:offset + eph_len]
    offset += eph_len

    wrap_nonce = enc_data[offset:offset + 12]
    offset += 12
    wrapped_cek = enc_data[offset:offset + 32]
    offset += 32
    wrap_tag = enc_data[offset:offset + 16]
    offset += 16

    content_nonce = enc_data[offset:offset + 12]
    offset += 12

    # 从尾部倒推
    sig = enc_data[-64:]
    sig_start = len(enc_data) - 64
    cert_begin = enc_data.rfind(b"-----BEGIN CERTIFICATE-----\n", 0, sig_start)
    if cert_begin < 0:
        raise ValueError("未找到签名证书")
    if cert_begin < 16:
        raise ValueError("auth_tag 位置异常")
    auth_tag = enc_data[cert_begin - 16:cert_begin]
    ciphertext = enc_data[offset:cert_begin - 16]

    # 验证签名
    ct_hash = hashlib.sha256(ciphertext).digest()
    rebuilt = struct.pack(">B", eph_len) + eph_pub + wrap_nonce + wrapped_cek + wrap_tag
    signed_bytes = (
        magic
        + struct.pack(">I", version)
        + struct.pack(">H", alg_id)
        + content_id
        + rebuilt
        + content_nonce
        + ct_hash
        + auth_tag
    )
    signer_pub.verify(sig, signed_bytes)

    # ECDH 派生 wrap_key 并解包 CEK
    eph_pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), eph_pub)
    shared = device_priv.exchange(ec.ECDH(), eph_pk)
    wrap_key = hkdf_derive(shared, f"wrap-key-{content_id.hex()[:16]}")
    cek = AESGCM(wrap_key).decrypt(wrap_nonce, wrapped_cek + wrap_tag, None)

    # 解密内容
    plaintext = AESGCM(cek).decrypt(content_nonce, ciphertext + auth_tag, None)

    return plaintext, magic_str, version


def decrypt_file_in_memory(enc_path: str) -> bytes:
    """
    解密单个 .csk 文件到内存
    
    流程:
      1. 从磁盘读密文 (不可避免)
      2. 从 GitHub 拉密钥到内存 (不落盘)
      3. 在内存解密
      4. 返回明文 bytes
    
    Args:
        enc_path: 加密文件路径
    
    Returns:
        明文 bytes
    """
    # 1. 读密文 (磁盘 I/O, 不可避免)
    enc_data = open(enc_path, "rb").read()

    # 2. 从 GitHub 拉密钥到内存
    device_priv_pem = fetch_key_to_memory("device_private_key.pem")
    signer_pub_pem = fetch_key_to_memory("online_signer_public_key.pem")

    # 3. 在内存解密
    plaintext, magic, version = decrypt_csk_in_memory(
        enc_data, device_priv_pem, signer_pub_pem
    )

    # 4. 清理密钥 bytes (虽然会被 GC, 显式覆盖)
    device_priv_pem = b"\x00" * len(device_priv_pem)
    signer_pub_pem = b"\x00" * len(signer_pub_pem)

    return plaintext


def decrypt_directory_in_memory(enc_dir: str, out_dir: str = None) -> dict:
    """
    批量解密目录下的所有 .csk 文件
    
    Args:
        enc_dir: 加密文件目录
        out_dir: 输出目录 (可选, 默认不写盘)
    
    Returns:
        {filename: plaintext_bytes} 字典
    """
    results = {}

    # 一次拉取密钥, 复用
    device_priv_pem = fetch_key_to_memory("device_private_key.pem")
    signer_pub_pem = fetch_key_to_memory("online_signer_public_key.pem")

    csk_files = sorted(glob.glob(os.path.join(enc_dir, "*.csk")))
    print(f"📁 {enc_dir}: 找到 {len(csk_files)} 个 .csk")

    for csk_path in csk_files:
        name = os.path.splitext(os.path.basename(csk_path))[0]
        try:
            enc_data = open(csk_path, "rb").read()
            plaintext, magic, version = decrypt_csk_in_memory(
                enc_data, device_priv_pem, signer_pub_pem
            )
            results[name] = plaintext

            # 如果指定了 out_dir, 写出去
            if out_dir:
                out_path = os.path.join(out_dir, name, "SKILL.md")
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as f:
                    f.write(plaintext)
                print(f"  ✅ {name}.csk → {name}/SKILL.md ({len(plaintext):,} bytes)")
            else:
                print(f"  ✅ {name} ({len(plaintext):,} bytes, 仅内存)")

        except Exception as e:
            print(f"  ❌ {name}: {e}")

    # 清理密钥
    device_priv_pem = b"\x00" * len(device_priv_pem)
    signer_pub_pem = b"\x00" * len(signer_pub_pem)

    return results


def cmd_single(enc_path: str, out_path: str = None):
    """单文件解密命令"""
    if not os.path.isfile(enc_path):
        print(f"❌ 文件不存在: {enc_path}")
        return 1

    magic = open(enc_path, "rb").read(4)
    if magic not in (b"CSK2", b"CKB2"):
        print(f"❌ 不是 LKPV2 加密文件: {enc_path} (魔数: {magic})")
        return 1

    print(f"🔓 LKPV2 Remote Decrypt (不落盘)")
    print(f"   密文: {enc_path}")
    print(f"   密钥: GitHub {GITHUB_OWNER}/{GITHUB_REPO} (内存, 不写盘)")
    print()

    try:
        plaintext = decrypt_file_in_memory(enc_path)

        if out_path:
            os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(plaintext)
            print(f"✅ 明文 → {out_path} ({len(plaintext):,} bytes)")
            print(f"   (密钥未落盘, 仅密文和明文写入磁盘)")
        else:
            sys.stdout.buffer.write(plaintext)

        return 0
    except Exception as e:
        print(f"❌ 解密失败: {e}")
        return 1


def cmd_directory(enc_dir: str, out_dir: str = None):
    """批量目录解密命令"""
    if not os.path.isdir(enc_dir):
        print(f"❌ 目录不存在: {enc_dir}")
        return 1

    print(f"🔓 LKPV2 Remote Decrypt (不落盘) - 批量")
    print(f"   密文目录: {enc_dir}")
    print(f"   输出目录: {out_dir or '(仅内存, 不写盘)'}")
    print(f"   密钥: GitHub (内存, 不写盘)")
    print()

    try:
        results = decrypt_directory_in_memory(enc_dir, out_dir)
        print(f"\n📊 完成: {len(results)} 个文件解密成功")
        if not out_dir:
            print(f"   明文未落盘 (在内存中, 调用方负责处理)")
        return 0
    except Exception as e:
        print(f"❌ 解密失败: {e}")
        return 1


def main():
    print("🔓 LKPV2 Remote Decrypt (不落盘版本)")
    print(f"   时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"   密钥源: https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}")
    print()

    if len(sys.argv) < 2:
        print("用法:")
        print("  python3 lkpv2-remote.py <encrypted.csk> [output.md]")
        print("  python3 lkpv2-remote.py <directory> [output_directory]")
        print()
        print("特点:")
        print("  ✅ 密钥从 GitHub 远程拉取, 仅在内存中使用")
        print("  ✅ 密钥不写磁盘")
        print("  ✅ 密文必须从磁盘读 (输入文件)")
        print("  ⚠️  明文可选落盘 (默认不落盘, stdout 输出)")
        return 1

    target = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else None

    if os.path.isfile(target):
        return cmd_single(target, out)
    elif os.path.isdir(target):
        return cmd_directory(target, out)
    else:
        print(f"❌ 文件/目录不存在: {target}")
        return 1


if __name__ == "__main__":
    from datetime import datetime, timezone
    sys.exit(main())