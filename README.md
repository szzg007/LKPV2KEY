# LKPV2 - LockPlan v2

> ⚠️ **警告：此仓库包含加密密钥的私钥。**
> 任何人都可以克隆此仓库并解密所有 LKPV2 加密的 Skill.md / Agent 配置。
> 这是一个**演示/开发**仓库，用于测试"线上密钥分发"工作流。
> 生产环境应使用私有仓库 + 加密通信 + KMS/HSM。

## 📋 概述

LKPV2 (LockPlan v2) 是基于 **ADR-plan-s-v2 §四** 规范的加密/解密工具。

- **加密算法**: AES-256-GCM (内容) + P-256 ECDH (密钥包裹)
- **签名算法**: Ed25519
- **格式**: 自定义 TLV 布局
- **魔数**: `CSK2` (Skill) / `CKB2` (Knowledge Base)

## 📁 目录结构

```
LKPV2KEY/
├── 密钥/                                  # 完整密钥套件 (含私钥)
│   ├── device_private_key.pem            # P-256 (用于密钥解包)
│   ├── device_public_key.pem
│   ├── online_signer_private_key.pem     # Ed25519 (用于签名)
│   ├── online_signer_public_key.pem
│   ├── online_signer_cert.pem
│   ├── offline_root_private.pem          # Ed25519 (离线根签名)
│   ├── offline_root_public.pem
│   ├── lease_issuer_private.pem          # Ed25519 (Lease Token)
│   ├── lease_issuer_public.pem
│   ├── kek.bin                           # AES-256 (32 bytes)
│   ├── revocation_manifest.json
│   └── meta.json
├── 脚本/
│   ├── LKPV2-decrypt.py                  # 主解密工具
│   ├── LKPV2-encrypt.py                  # 主加密工具
│   ├── plan-s-v2-test.py                 # 完整测试
│   ├── plan-s-v2-test2.py
│   └── debug-sign.py
└── 文档/
    └── ADR-plan-s-v2.md                  # ADR 规范
```

## 🚀 使用

### 在线获取密钥（不落盘）

```python
import requests
from io import BytesIO

# 从 GitHub raw 拉密钥到内存
def get_key_from_github(filename):
    url = f"https://raw.githubusercontent.com/szzg007/LKPV2KEY/main/密钥/{filename}"
    return BytesIO(requests.get(url).content)

# 内存解密
device_priv = load_pem_private_key(
    get_key_from_github("device_private_key.pem").read(),
    password=***
)
```

### 本地解密

```bash
python3 脚本/LKPV2-decrypt.py <encrypted.csk> <output.md>
```

## 📊 当前密钥版本

- **创建时间**: 2026-07-02
- **来源**: 密钥套件0702 (开发态)
- **API base**: `https://server.smartlead.ai/api/v1`

## 🔄 密钥更新流程

1. 生成新密钥套件（`LKPV2-keygen.py`）
2. 测试加密/解密流程
3. 推送到本仓库覆盖旧版本
4. 通知所有 Agent 更新引用

## ⚠️ 安全警告

- **不要在生产环境使用此公开仓库**
- **不要把生产密钥上传到公开位置**
- **定期轮换密钥**（建议 90 天）

## 📜 License

Internal use only.
