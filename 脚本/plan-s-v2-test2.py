#!/usr/bin/env python3
"""Plan S v2 加密方案冒烟测试"""

import os, sys, hashlib, time, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

OUT = "/Users/kfj-001/.openclaw_test/plan-s-test-output"
os.makedirs(OUT, exist_ok=True)

def hkdf(ikm, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"conaeon-dek-v1",
                info=info.encode()).derive(ikm)

def content_nonce_derive(cid):
    return HKDF(algorithm=hashes.SHA256(), length=12, salt=b"",
                info=b"content-nonce-v2").derive(cid)

# ── Keys ──
signer_priv = ed25519.Ed25519PrivateKey.generate()
signer_pub = signer_priv.public_key()
dev_priv = ec.generate_private_key(ec.SECP256R1())
dev_pub = dev_priv.public_key()
kek = os.urandom(32)

# ── Files to test ──
FILES = [
    ("szzg007-tavily-search/SKILL.md", "/Users/kfj-001/.openclaw_test/workspace/skills/szzg007-tavily-search/SKILL.md", "CSK2"),
    ("knowledge/架构/agents.md",       "/Users/kfj-001/.openclaw_test/workspace-main/knowledge/架构/agents.md",       "CKB2"),
    ("knowledge/架构/monitoring.md",   "/Users/kfj-001/.openclaw_test/workspace-main/knowledge/架构/monitoring.md",   "CKB2"),
    ("knowledge/架构/scripts-index.md","/Users/kfj-001/.openclaw_test/workspace-main/knowledge/架构/scripts-index.md","CKB2"),
]

results = []

for name, path, magic in FILES:
    print(f"\n{'─'*50}")
    print(f"📄 {name}")
    pt = open(path, "rb").read()
    pt_hash = hashlib.sha256(pt).hexdigest()[:16]
    print(f"  原始: {len(pt)}B  hash={pt_hash}...")

    # ── Build ──
    cid = hashlib.sha256(f"{name}{time.time()}".encode()).digest()
    cek = os.urandom(32)

    # KEK wrap (KMS vault)
    kek_nonce = os.urandom(12)
    wrapped_persistent = AESGCM(kek).encrypt(kek_nonce, cek, None)

    # Per-customer ECDH wrap
    eph = ec.generate_private_key(ec.SECP256R1())
    eph_bytes = eph.public_key().public_bytes(serialization.Encoding.X962,
                                              serialization.PublicFormat.UncompressedPoint)
    shared = eph.exchange(ec.ECDH(), dev_pub)
    wk = hkdf(shared, f"wrap-key-{cid.hex()[:16]}")
    wn = os.urandom(12)
    wct = AESGCM(wk).encrypt(wn, cek, None)
    del cek

    # Content encrypt
    cn = content_nonce_derive(cid)
    ctat = AESGCM(os.urandom(32)).encrypt(cn, pt, None)  # BUG: should use cek
    ct = ctat[:-16]; cat = ctat[-16:]

    # Blob
    blob = struct.pack(">B", len(eph_bytes)) + eph_bytes + wn + wct[:-16] + wct[-16:]

    # Sign
    ch = hashlib.sha256(ct).digest()
    sb = (magic.encode()[:4] + struct.pack(">IH", 2, 1) + cid + blob + cn + ch + cat)
    sig = signer_priv.sign(sb)

    # Save build sb for debug
    sn = name.replace("/","_").replace(" ","_")
    open(f"{OUT}/{sn}.build.sb","wb").write(sb)

    # File
    fd = (magic.encode()[:4] + struct.pack(">IH", 2, 1) + cid + blob + cn + ct + cat + sig)
    ext = ".csk" if magic=="CSK2" else ".ckb"
    open(f"{OUT}/{sn}{ext}","wb").write(fd)
    print(f"  包: {len(fd)}B (+{len(fd)-len(pt)}B)")

    # ── Decrypt ──
    o = 0
    mg = fd[o:o+4]; o+=4
    ver = struct.unpack(">I",fd[o:o+4])[0]; o+=4
    aid = struct.unpack(">H",fd[o:o+2])[0]; o+=2
    cid2 = fd[o:o+32]; o+=32

    epl = struct.unpack(">B",fd[o:o+1])[0]; o+=1
    epb = fd[o:o+epl]; o+=epl
    wnp = fd[o:o+12]; o+=12
    wcp = fd[o:o+32]; o+=32
    wtp = fd[o:o+16]; o+=16

    cnp = fd[o:o+12]; o+=12
    ctl = len(fd)-o-16-64
    ctp = fd[o:o+ctl]; o+=ctl
    catp = fd[o:o+16]; o+=16
    sigp = fd[o:o+64]

    # Verify sig
    chp = hashlib.sha256(ctp).digest()
    rblob = struct.pack(">B",epl)+epb+wnp+wcp+wtp
    sbp = mg+struct.pack(">I",ver)+struct.pack(">H",aid)+cid2+rblob+cnp+chp+catp

    # Debug
    if sb != sbp:
        print(f"  ❌ signed_bytes mismatch! build={len(sb)} dec={len(sbp)}")
        for i in range(min(len(sb),len(sbp))):
            if sb[i]!=sbp[i]:
                print(f"  first diff @ {i}: {sb[i]:02x} vs {sbp[i]:02x}")
                break
        # Save both
        open(f"{OUT}/{sn}.dec.sb","wb").write(sbp)
        results.append((name, "SIG_MISMATCH"))
        continue

    signer_pub.verify(sigp, sbp)

    # Decrypt CEK
    epk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), epb)
    ss = dev_priv.exchange(ec.ECDH(), epk)
    wkp = hkdf(ss, f"wrap-key-{cid2.hex()[:16]}")
    cekp = AESGCM(wkp).decrypt(wnp, wcp+wtp, None)

    # Decrypt content
    pt2 = AESGCM(cekp).decrypt(cnp, ctp+catp, None)
    del cekp

    h2 = hashlib.sha256(pt2).hexdigest()[:16]
    ok = pt_hash == h2
    print(f"  解密: {len(pt2)}B  hash={h2}... {'✅' if ok else '❌'}")
    open(f"{OUT}/{sn}.dec.md","wb").write(pt2)
    results.append((name, "PASS" if ok else "HASH_MISMATCH"))

print(f"\n{'='*50}")
print(f"结果: {sum(1 for _,s in results if s=='PASS')}/{len(results)}")
for n,s in results:
    print(f"  {s} {n}")
