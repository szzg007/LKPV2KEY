#!/usr/bin/env python3
"""Debug: find signed_bytes mismatch between build and decrypt"""
import struct, hashlib, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Generate keys
device_private = ec.generate_private_key(ec.SECP256R1())
device_public = device_private.public_key()
signer_private = ed25519.Ed25519PrivateKey.generate()
signer_public = signer_private.public_key()

# Build phase
content_id = os.urandom(32)
cek = os.urandom(32)
content_nonce = os.urandom(12)
ciphertext = os.urandom(100)
content_auth_tag = os.urandom(16)

# ECDH
eph_private = ec.generate_private_key(ec.SECP256R1())
eph_public = eph_private.public_key()
eph_public_bytes = eph_public.public_bytes(
    serialization.Encoding.X962,
    serialization.PublicFormat.UncompressedPoint
)
print(f"eph_public_bytes length: {len(eph_public_bytes)}")

shared_secret = eph_private.exchange(ec.ECDH(), device_public)
wrap_key = HKDF(
    algorithm=hashes.SHA256(), length=32, salt=b"conaeon-dek-v1",
    info=f"wrap-key-{content_id.hex()[:16]}".encode("utf-8"),
).derive(shared_secret)

wrap_nonce = os.urandom(12)
wrap_aead = AESGCM(wrap_key)
wrapped_cek_with_tag = wrap_aead.encrypt(wrap_nonce, cek, None)
wrapped_cek = wrapped_cek_with_tag[:-16]
wrap_tag = wrapped_cek_with_tag[-16:]

# Build wrapped_cek_blob
wrapped_cek_blob = (
    struct.pack(">B", len(eph_public_bytes)) +
    eph_public_bytes +
    wrap_nonce +
    wrapped_cek +
    wrap_tag
)
print(f"wrapped_cek_blob length: {len(wrapped_cek_blob)}")
print(f"  len byte: {wrapped_cek_blob[0]}")

# Build signed_bytes (build phase)
signed_bytes_build = (
    b"CSK2" +
    struct.pack(">I", 2) +
    struct.pack(">H", 1) +
    content_id +
    wrapped_cek_blob +
    content_nonce +
    hashlib.sha256(ciphertext).digest() +
    content_auth_tag
)
print(f"signed_bytes_build length: {len(signed_bytes_build)}")

# Sign
vendor_signature = signer_private.sign(signed_bytes_build)

# === Decrypt phase ===
# Parse from file_data
offset = 0
magic = signed_bytes_build[0:4]  # wrong - parse from file_data instead
# Let's just parse the blob
offset = 0
eph_pubkey_len = wrapped_cek_blob[offset]; offset += 1
print(f"Parsed eph_pubkey_len: {eph_pubkey_len}")
eph_pubkey_bytes = wrapped_cek_blob[offset:offset+eph_pubkey_len]; offset += eph_pubkey_len
print(f"Parsed eph_pubkey_bytes length: {len(eph_pubkey_bytes)}")
wrap_nonce_p = wrapped_cek_blob[offset:offset+12]; offset += 12
wrapped_cek_p = wrapped_cek_blob[offset:offset+32]; offset += 32
wrap_tag_p = wrapped_cek_blob[offset:offset+16]; offset += 16

# Rebuild blob
rebuilt_blob = (
    struct.pack(">B", eph_pubkey_len) +
    eph_pubkey_bytes +
    wrap_nonce_p +
    wrapped_cek_p +
    wrap_tag_p
)

print(f"Blob match: {wrapped_cek_blob == rebuilt_blob}")
print(f"Blob bytes: {wrapped_cek_blob.hex()}")
print(f"Rebuilt:    {rebuilt_blob.hex()}")

# Rebuild signed_bytes
signed_bytes_decrypt = (
    b"CSK2" +
    struct.pack(">I", 2) +
    struct.pack(">H", 1) +
    content_id +
    rebuilt_blob +
    content_nonce +
    hashlib.sha256(ciphertext).digest() +
    content_auth_tag
)

print(f"signed_bytes_decrypt length: {len(signed_bytes_decrypt)}")
print(f"Signed bytes match: {signed_bytes_build == signed_bytes_decrypt}")

if signed_bytes_build != signed_bytes_decrypt:
    for i in range(min(len(signed_bytes_build), len(signed_bytes_decrypt))):
        if signed_bytes_build[i] != signed_bytes_decrypt[i]:
            print(f"First diff at byte {i}: build={signed_bytes_build[i]:02x} decrypt={signed_bytes_decrypt[i]:02x}")
            break
    if len(signed_bytes_build) != len(signed_bytes_decrypt):
        print(f"Length diff: build={len(signed_bytes_build)} decrypt={len(signed_bytes_decrypt)}")
else:
    # Verify signature
    try:
        signer_public.verify(vendor_signature, signed_bytes_decrypt)
        print("✅ Signature verified!")
    except Exception as e:
        print(f"❌ Signature verify failed: {e}")
