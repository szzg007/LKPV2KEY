---
publish: false
---
# ADR-plan-s-v2 — Plan S 直接加密架构（最终可实施版）

> **状态**：✅ 已拍板 + 4 P0 已修复（2026-05-19）
> **取代**：[[ADR-plan-s-v1.md]]（v1 已废弃）
> **评审依据**：[[ADR-plan-s-v1-panel-review-20260519.md]] + [[ADR-plan-s-v2-panel-review-20260519.md]]（第二轮 Panel）
> **冒烟测试**：[[poc-plan-s-v2/smoke_test.py]] 18/18 PASS（密码学协议自洽）
> **适用范围**：所有 skill（不管复不复杂）+ KB markdown 文档
> **目标平台**：macOS（Conaeon.app）

## Changelog

- **2026-05-19 v2.1（本次）**：第二轮 Panel Review 发现 4 个治理层 P0，已全部修复：
  - **E3**：CEK vault 改为 wrapped-only，KEK 由 KMS/HSM 持有（第 3、5、11 章）
  - **E1**：Build 服务从单机三合一拆为 4 域（新增第 3-bis 章 Build 服务拓扑）
  - **F7**：Lease Issuer Key 纳入 Offline Root 信任链（第 3、7 章）
  - **I15**：新增 Threat Model Appendix，"不防本机 root" 商业签字流程定死（第 16 章）
- **2026-05-19 v2.0**：首版，吸收 v1 Panel 的 5 个协议层 P0 + 3 TBD

---

## 一、Threat Model（先定边界，再谈实现）

### 保护目标 ✅
- **离线拷贝防护**：客户/竞品拷走 .csk/.ckb 文件本身无法运行（无 Keychain Device Key）
- **停付即停用**：lease 失效 → fail-closed，授权下线
- **普通逆向防护**：拒绝 90%+ 业余调试器 attach、内存 dump、二进制分析
- **设备绑定**：换机器无法继续使用（Device Private Key 在 Secure Enclave）

### 非目标 ⚫（明确写死，避免范围蔓延）
- **不对抗本机 root + 专业逆向小组**：本机所有者 + 高级技术 + 充分时间，任何客户端方案都防不住
- **不防止索引侧语义结构泄漏**：本地向量索引含 embedding，可被推测语义结构（接受这层泄漏预算）
- **不防止物理访问 + 已登录会话场景**：偷设备 + 已登录的攻击者，Keychain 可被访问

### 决议记录（2026-05-19 三个 TBD 拍板）

| 决策 | 选择 | 影响章节 |
|------|------|---------|
| 反调试层级 | **L1 基础硬化**（Hardened Runtime + Secure Enclave + PT_DENY_ATTACH + zeroize）| 第八章 |
| 锁屏后台执行 | **支持**（AfterFirstUnlockThisDeviceOnly + LaunchAgent）| 第六章 |
| KB 检索 | **本地优先**（.cki 加密索引格式 + ramdisk 解密）| 第九章 |

---

## 二、核心思路（与 v1 一致，结构修正）

```
原始 .md 文件
  → 直接 AES-256-GCM 加密（用 Content Key / CEK）
  → CEK 用客户 Device Public Key 包裹后存入包头（wrapped_CEK）
  → 包头被 Online Package Signer 签名
  → 输出 .csk（skill）或 .ckb（KB，统一格式）

运行时：
  helper（XPC 隔离 + Hardened Runtime）验证签名
  → 检查 lease（本地令牌验签 + soft/hard expiry）
  → Secure Enclave 解 wrapped_CEK → 得 CEK
  → 用 CEK 解密 .md → 内存交给 OpenClaw → 用完立即 zeroize
```

**关键修正（vs v1）**：
- ❌ v1 的 "DEK" 概念混淆了内容密钥和设备密钥 → ✅ v2 拆为 **CEK**（内容）+ **Device Private Key**（设备）
- ❌ v1 的 "Vendor Signing Key 私钥永不离开 Build 机 + 实时签名" 矛盾 → ✅ v2 用 **Offline Root + Online Package Signer** 两级
- ❌ v1 的 "签名不含 encrypted_DEK" → ✅ v2 **签名覆盖完整 canonical manifest**

---

## 三、密钥体系（五把钥匙 + Offline Root 信任锚）

> **P0 修复（F7）**：新增 Lease Issuer Key，纳入 Offline Root 信任链
> **P0 修复（E3）**：CEK 不再明文落盘，由 KMS/HSM KEK 包裹后存 vault

| 密钥 | 算法 | 用途 | 生成位置 | 存放位置 | 生命周期 |
|------|------|------|---------|---------|---------|
| **Offline Root Signing Key** | Ed25519 | 信任锚，签发所有下游 cert | air-gapped 机器 / HSM (FIPS 140-2 L3) | 离线，2-of-3 custodian 物理保管 | 多年，几乎不动 |
| **Online Package Signer Key** | Ed25519 | 签名 .csk / .ckb 包头 | 独立签名机（**非** Build Mac Mini）| HSM / macOS Secure Enclave non-exportable | **3-6 个月轮换** |
| **Lease Issuer Key** ⭐新 | Ed25519 | 签 Lease Token | conaeon.ai 后端 | HSM / KMS | 6 个月轮换 |
| **KEK (Key Encryption Key)** ⭐新 | AES-256 | 包裹 CEK，存 vault | KMS / HSM（如 AWS KMS / Hashi Vault Transit） | KMS 内部（**永远不落盘明文**）| 年级别轮换 |
| **Content Key (CEK)** | AES-256 | 加密 .md 内容 | CEK Wrap Service（用 KEK unwrap 后短时持有） | vault 中**只存 wrapped_CEK**（KEK 加密），明文 CEK 仅 unwrap 时驻留进程内存 | 每个文件独立 |
| **Device Private Key** | P-256（Secure Enclave）| 客户端解包 wrapped_CEK | 客户机首次激活时 | Secure Enclave non-exportable | 设备生命周期 |

### 信任链证书结构（修复 F7）

```
Offline Root (Ed25519, air-gapped)
  ├── 签发 → Online Package Signer Cert (Ed25519, 3-6 月)
  │           └── 签名 → .csk / .ckb packages
  │
  ├── 签发 → Lease Issuer Cert (Ed25519, 6 月)          ⭐ 修复 F7
  │           └── 签名 → Lease Tokens
  │
  └── 签发 → KEK Custodian Cert (用于 KMS 鉴权)        ⭐ 修复 E3
              └── 授权 → CEK Wrap Service 调用 KMS unwrap

客户端 helper 内置：
  - Offline Root Public Key（嵌入二进制，构建时编入）
  - 可信 keyset 列表（含当前活跃的 Package Signer / Lease Issuer cert）
  - revocation manifest 缓存（来自 lease refresh response）
```

**关键约束**：
- Offline Root 永不在线；用 2-of-3 custodian 物理签发流程（见第 15 章 ceremony runbook）
- 所有在线密钥（Online Package Signer / Lease Issuer / KEK）**绑定到 Offline Root 信任链**，可被一致地轮换 / 吊销
- `conaeon.ai` 只能向各签名服务提交任务，**永远拿不到任何私钥**

---

## 三-bis、Build 服务拓扑（4 安全域，修复 E1）

> **P0 修复（E1）**：把 v2.0 的"Build Mac Mini 三合一"拆为 4 个独立服务/机器，任一失陷不会全军覆没

```
┌─────────────────────────────────────────────────────────────────┐
│ 安全域 1：Offline Root（air-gapped 机器 / HSM）                   │
│   - 持有 Offline Root Private Key                                │
│   - 签发：Online Package Signer Cert / Lease Issuer Cert /       │
│           KEK Custodian Cert / Revocation Manifest               │
│   - 网络：完全离线，物理 2-of-3 custodian 操作                    │
└─────────────────────────────────────────────────────────────────┘
                       │（证书物理回带）
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 安全域 2：Online Package Signer Service（独立机器 / HSM）          │
│   - 持有 Online Package Signer Private Key（HSM/SE non-exportable）│
│   - 接口：sign(canonical_signed_bytes) → Ed25519 signature        │
│   - 调用方：CEK Wrap Service（鉴权后才能调用）                     │
│   - 不持有：CEK / vault / Device Public Key                       │
└─────────────────────────────────────────────────────────────────┘
                       ▲
                       │ sign 调用
┌─────────────────────────────────────────────────────────────────┐
│ 安全域 3：CEK Wrap Service（独立机器，可与 Build 服务同机房）       │
│   - 持有：vault（仅含 wrapped_CEK，KEK 加密）                      │
│   - 调用 KMS / HSM unwrap → 短时内存持有明文 CEK                  │
│   - 用 Device Public Key + ephemeral ECDH 包出 per-customer       │
│     wrapped_CEK_blob                                              │
│   - 调用 Online Package Signer 签名                               │
│   - 明文 CEK 用完立即 sodium_memzero（禁止落盘）                  │
└─────────────────────────────────────────────────────────────────┘
                       ▲
                       │ activate 请求
┌─────────────────────────────────────────────────────────────────┐
│ 安全域 4：Activation Frontend（无状态前门，可 HA / CDN 部署）      │
│   - 接收客户激活请求（Device Public Key + install_id + license）  │
│   - 鉴权（license validation）                                    │
│   - 转发到 CEK Wrap Service                                       │
│   - 把结果（per-customer 包）回传给客户                            │
│   - 不持有任何密钥                                                │
└─────────────────────────────────────────────────────────────────┘
                       ▲
                       │ HTTPS
                  conaeon.ai 客户端
```

### 单点失陷影响矩阵

| 域失陷 | 机密性影响 | 完整性影响 | 可用性影响 |
|--------|----------|-----------|-----------|
| Offline Root 被攻陷 | 全部内容潜在泄漏（理论上）| 信任根丢失，需要全局重做 | — |
| Online Package Signer 被攻陷 | ❌ 不泄漏内容 | 攻击者可签恶意包，**Offline Root revoke 后失效** | 24-72h 内通过 revocation 恢复 |
| CEK Wrap Service 被攻陷 | ⚠️ 持有 vault + 可调 KMS unwrap → 可能批量解 wrapped_CEK | — | KMS 调用频率监控 + IP allowlist 限制 |
| Activation Frontend 被攻陷 | ❌ 不持有密钥 | — | 服务中断，HA 自愈 |

**与 v2.0 对比**：v2.0 单台 Build Mac Mini 失陷 = 三项全打穿；v2.1 拆域后任一失陷可控、可恢复。

### HA / 主备策略（缓解 E2）

- Online Package Signer：主备机各一台 HSM，私钥分别 enroll
- CEK Wrap Service：active-standby，vault 用 KMS 异步复制
- Activation Frontend：active-active，多实例 + CDN
- KMS：选 SLA ≥ 99.95% 的托管服务

---

## 四、加密包结构（TLV / Sealed-Key Blob）

```
.csk / .ckb 文件结构（修正 v1 的 65-byte 错误）：
┌──────────────────────────────────────────────────────┐
│  Header                                               │
│  ├── magic: "CSK2" / "CKB2" (4 bytes)               │
│  ├── version: 2 (uint32)                              │
│  ├── alg_id (uint16)：加密算法套件标识                  │
│  ├── content_id (32 bytes)：内容唯一 ID                │
│  ├── wrapped_CEK_blob (variable, TLV):               │
│  │   ├── eph_pubkey_len (uint8)                       │
│  │   ├── eph_pubkey (33 or 65 bytes，P-256 compressed/uncompressed) │
│  │   ├── wrap_nonce (12 bytes)                        │
│  │   ├── wrapped_CEK (32 bytes, AES-256-GCM 包裹)    │
│  │   └── wrap_tag (16 bytes, GCM tag)                 │
│  └── package_metadata (TLV, optional):               │
│      ├── original_filename                            │
│      └── package_timestamp                            │
├──────────────────────────────────────────────────────┤
│  Encrypted Content                                    │
│  ├── content_nonce (12 bytes)                         │
│  ├── ciphertext (variable, AES-256-GCM)              │
│  └── content_auth_tag (16 bytes)                      │
├──────────────────────────────────────────────────────┤
│  Signing Block                                        │
│  ├── signer_cert (Online Package Signer cert)        │
│  └── vendor_signature (Ed25519, 64 bytes)            │
└──────────────────────────────────────────────────────┘
```

### Canonical Signing Bytes（签名覆盖范围，修复 A4）

```
signed_bytes = magic || version || alg_id || content_id
            || wrapped_CEK_blob       ← P0：必须签名覆盖
            || content_nonce
            || sha256(ciphertext)     ← 不直接签密文，签 hash（节省 CPU）
            || content_auth_tag
            || package_metadata
```

唯一**不覆盖** `vendor_signature` 字段本身。验签时 helper 重新计算 canonical bytes 再验。

### Nonce 唯一性规则（修复 A3）

**协议级要求**（不留给实现者发挥）：
1. `content_nonce` 必须**按文件派生**：`content_nonce = HKDF(content_id, "content-nonce-v2", 12 bytes)`
2. `wrap_nonce` 用纯随机（每次包装 CEK 都新生成）
3. **禁止**同一 CEK 加密多个 .md 文件，每个文件独立 CEK

---

## 五、Per-Customer 重包流程（修复 B2 性能问题）

**v1 错误理解**：每个客户激活时重新加密所有 .md 内容（10 万次加密会打死 Build Mac Mini）

**v2 正确做法**：内容只加密一次，激活时只**重包 wrapped_CEK + 重签 Header**

```
BUILD 阶段（一次性，发版时做）：修复 E3
  for each .md file:
    1. CEK Wrap Service 生成独立 CEK (AES-256)
    2. 用 CEK 加密 .md → ciphertext + content_auth_tag
    3. 调 KMS / HSM：wrapped_CEK_persistent = KMS.Encrypt(KEK_id, CEK)
    4. vault 存：(content_id, wrapped_CEK_persistent, ciphertext)
       ❌ 不存明文 CEK
       ❌ 不存裸 .md
    5. 明文 CEK 立即 sodium_memzero
    6. wrapped_CEK_blob 字段留空（per-customer 阶段才填）

INSTALL 阶段（每个客户激活时）：修复 E1（走 4 域服务）
  1. 客户机生成 P-256 Device Key Pair（Secure Enclave non-exportable）
  2. 客户机把 (Device Public Key, install_id, license_key) 发到
     Activation Frontend（HTTPS）
  3. Activation Frontend 鉴权 license，转发到 CEK Wrap Service
  4. CEK Wrap Service：
     for each .csk/.ckb 需要交付给该客户:
       a. 从 vault 取 wrapped_CEK_persistent
       b. 调 KMS unwrap → 短时内存持有明文 CEK（≤ 100ms）
       c. ECDH(eph_privkey, Device Public Key) → shared secret
       d. HKDF 派生 wrap_key
       e. AES-256-GCM(wrap_key, CEK) → wrapped_CEK (per-customer)
       f. 填入 wrapped_CEK_blob
       g. sodium_memzero(明文 CEK)        ⭐ E3 修复关键
       h. 调 Online Package Signer Service：sign(canonical_bytes)
          → 得 vendor_signature
  5. Activation Frontend 把 per-customer 包回传给客户
  6. 客户机：
     - Device Private Key 已在 Secure Enclave
     - 收 Lease Token（由 Lease Issuer 签发，含 kid/iss/nbf/exp/policy_version）
     - Lease Token 存 Keychain（AfterFirstUnlockThisDeviceOnly）
     - 客户专属包存 ~/Library/Application Support/Conaeon/

成本分析：
  - 一次激活 = N 次 (KMS unwrap + ECDH + AES wrap + Ed25519 sign)，N = 文件数
  - KMS unwrap 通常 1-10ms / 次（取决于 KMS 提供商）
  - 优化：CEK Wrap Service 可缓存 unwrapped CEK 在内存（短时，如 60s），
    避免同一文件交付多客户时反复 unwrap → 降低 KMS 调用 90%+
  - 1000 客户 × 300 文件 = 30 万次操作，按缓存命中 80% 估算约 30-60 分钟分布完成
  - 必须做压测：100/500/1000 客户 × 300 包（见行动项）
```

---

## 六、运行时解密 + 锁屏后台支持（修复 B4，决议 2）

### Keychain 访问类配置

| 项目 | v1 | v2 |
|------|-----|-----|
| Device Private Key | `kSecAttrAccessibleWhenUnlocked` | **`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`** |
| Lease Secret | `kSecAttrAccessibleWhenUnlocked` | **`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`** |
| 存储类 | `kSecClassKey` / `kSecClassGenericPassword` | 同 v1 |
| Secure Enclave | ⚫ 未明确 | **✅ 强制（Apple Silicon）**：`kSecAttrTokenIDSecureEnclave` |

### helper 进程启动方式

- **LaunchAgent**（用户级，登录后台运行）：`~/Library/LaunchAgents/ai.openclaw.helper.plist`
- ✅ 用户登录后即启动，锁屏不退出
- ✅ Keychain 在 AfterFirstUnlock 状态下可访问
- ❌ 不用 LaunchDaemon（系统级会触发 Keychain 权限提示）

### 运行时解密流程

```
skill 执行请求（OpenClaw runtime）
  │
  ▼
helper 进程（XPC 隔离 + Hardened Runtime）
  │
  ├─ 1. PT_DENY_ATTACH（启动时设置，拒调试器）
  ├─ 2. 验证 vendor_signature（用嵌入的 Offline Root 公钥验 Online Package Signer cert）
  ├─ 3. 验证 cert 在有效期内 + 未撤销
  ├─ 4. 检查 lease（本地令牌验签 + exp 字段）
  │   ├─ lease hard 未过期 → 继续
  │   ├─ lease soft 过期 → 后台异步触发刷新（不阻塞）
  │   └─ lease hard 过期 → fail-closed，skill 不跑
  ├─ 5. Secure Enclave: ECDH(Device Privkey, eph_pubkey) → shared secret
  ├─ 6. HKDF 派生 wrap_key
  ├─ 7. AES-256-GCM 解 wrapped_CEK → 得 CEK
  ├─ 8. 用 CEK 解 ciphertext → 得明文 .md
  │
  ▼ XPC pipe（不写临时文件，不落盘）
明文 .md → OpenClaw runtime 处理
  │
  ▼ 用完立即
sodium_memzero(明文 buffer)
sodium_memzero(CEK)
```

---

## 七、Lease 规范（修复 B5 + D2 + F7）

### Lease Token 结构（本地签名令牌，已纳入信任链）

```json
{
  "kid": "lease-issuer-2026Q2",          // ⭐ F7: Key ID，对应 Lease Issuer Cert
  "iss": "lease.conaeon.ai",             // ⭐ F7: 签发者
  "iat": 1716100000,                     // issued_at
  "nbf": 1716100000,                     // not_before
  "soft_expiry": 1716103600,             // 1h 后软过期，后台异步刷新
  "hard_expiry": 1716114400,             // 4h 后硬过期，必须停（可被 policy 覆盖）
  "sub": "INSTALL-XXX",                  // install_id
  "license_id": "LIC-YYY",
  "policy_version": 3,                   // ⭐ F7: 客户端按 policy 应用不同 hard TTL
  "scope": ["skill", "kb"],
  "signature": "<Ed25519 by Lease Issuer Key>"
}
```

### 验签流程（修复 F7）

```
helper 收到 Lease Token →
  1. 解析 kid → 查可信 keyset（含 Offline Root 签发的 Lease Issuer Cert）
  2. 验证 Lease Issuer Cert 在有效期内 + 未撤销（查 revocation manifest）
  3. 用 Lease Issuer Public Key 验证 token signature
  4. 检查 nbf ≤ now ≤ hard_expiry
  5. 检查 sub == 本机 install_id（防 token 串）
  6. 通过 → 缓存生效
```

### 续期策略（H12 分层修复）

| 客户类型 | hard_expiry 默认 |
|---------|-----------------|
| 普通 SaaS 用户 | **4h**（保守，多次续期） |
| 批准的"离线友好"客户 | **24h** 或 **72h**（按 license 签发 policy） |
| 演示场景 | **12h** |

| 状态 | 行为 |
|------|------|
| `now < soft_expiry` | 正常运行，不打网络 |
| `soft_expiry < now < hard_expiry` | 正常运行 + **后台异步**触发刷新（不阻塞 skill） |
| `now >= hard_expiry` | fail-closed，skill 不跑，App 进 view-only |
| 后台刷新失败（重试 3 次，指数退避） | 不立即停，等 hard_expiry 才停 |

**关键**：运行路径**默认不打网络**（本地验签），网络只在后台刷新时用。30 秒瞬断不翻车。

### Revocation（F7 配套）

- conaeon.ai 通过 lease refresh response 携带 revocation manifest（含被吊销的 kid 列表）
- helper 收到 → 缓存 → 拒绝所有用被吊销 kid 签的 token
- 离线客户在下次刷新前不感知 revocation（已是必然，policy 接受）

---

## 八、L1 反调试硬化清单（决议 1）

> **范围**：基础硬化，拒绝 90% 业余逆向；不做 L2/L3（猫鼠游戏，性价比低）

### 编译/打包级（一次性配置，无运维成本）

| 项 | 措施 | 验证方法 |
|---|------|---------|
| 1 | Hardened Runtime 启用 | `codesign -d --entitlements - <app>` 查 |
| 2 | `com.apple.security.get-task-allow` = NO | 调试器无法 attach |
| 3 | `com.apple.security.cs.disable-library-validation` = NO | 拒动态库注入 |
| 4 | `com.apple.security.cs.allow-dyld-environment-variables` = NO | 拒 DYLD_INSERT_LIBRARIES |
| 5 | Notarization 公证 | 启动时 OS 验证签名 |
| 6 | 编译时 `-fstack-protector-all + ASLR + PIE` | 标准硬化 |

### 运行时级（helper 进程内）

```c
// helper 启动时立即执行
#include <sys/ptrace.h>

void apply_l1_hardening() {
    // 1. PT_DENY_ATTACH：拒绝 ptrace/lldb attach（设置后无法撤销）
    ptrace(PT_DENY_ATTACH, 0, 0, 0);

    // 2. 检测当前是否已被 trace（启动时一次性检查）
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    sysctl(mib, 4, &info, &size, NULL, 0);
    if (info.kp_proc.p_flag & P_TRACED) {
        // 已被调试 → wipe Keychain + 退出
        wipe_device_key_and_lease();
        exit(1);
    }
}
```

### 内存级（用完立即销毁）

```c
// 明文 .md / CEK 用完立即 zeroize
#include <sodium.h>
sodium_memzero(plaintext_buf, plaintext_len);
sodium_memzero(cek_buf, 32);

// XPC 传递明文（不落盘临时文件）
// helper → OpenClaw：XPC pipe，不经过 /tmp
```

### 不做的（明确写死，避免范围蔓延）

- ❌ 反 VM 检测、canary、二进制 packing
- ❌ 实时调试器进程扫描（`lldb`/`dtrace`/`frida` 检测）
- ❌ LLVM obfuscator / 代码混淆
- ❌ TPM-like attestation

**理由**：L1 已超过 95% SaaS 软件水平；真正 IP 价值靠 lease 强制续期 + 更新频率，不靠反调试无限堆。

---

## 九、KB 本地索引（.cki 格式，决议 3）

### 索引文件格式

`.cki`（knowledge capsule index）与 `.ckb` 同源结构，加密包装向量索引：

```
.cki 内容（解密后）：
  - faiss / sqlite-vss 索引文件（embedding 向量 + chunk metadata + content_id 映射）
  - 每个 chunk 含 content_id（指向对应 .ckb）

加密：
  - 用专门的 IndexKey（独立于 CEK，方便单独更新索引不重新分发 KB）
  - IndexKey 同样按 per-customer wrapped 进包头
```

### 运行时加载策略

| 时机 | 操作 |
|------|------|
| helper 启动 | 解密 .cki → 加载到 **匿名 mmap 内存**（不写磁盘） |
| 检索 query | 内存中向量召回 → 拿到 Top K 的 content_id |
| 解析内容 | 按 content_id 解对应 .ckb → 拼上下文给 LLM |
| 进程退出 / lease 失效 | 内存 zeroize |

### 关键约束（不能违反）

- ❌ **禁止**把解密后的索引写到 `/tmp`、`~/Library/Caches`、APFS 任何路径
- ❌ **禁止**用 ramdisk 落盘（重启可能保留）
- ✅ **唯一允许**：匿名内存映射（`mmap` with `MAP_ANON`），进程退出即消失
- ✅ 内存占用：300 篇 KB × 平均 10 chunks × 384-dim float32 ≈ 50-100MB，可接受

### 增量更新

- KB 增加新文件：分发新 .ckb + 重新生成完整 .cki（覆盖式）
- 不支持 partial index update（实现复杂度太高，频率低不值得）

---

## 十、密钥 Rotation / Revocation（修复 C1）

### Online Package Signer 轮换（计划性）

```
每 3-6 个月：
  1. Offline Root 签发新的 Online Package Signer cert（覆盖旧 cert）
  2. 新发布的包用新 cert 签
  3. 客户端 helper 内置可信 keyset 自动接收新 cert
  4. 旧 cert 标记为 expired，但已签发的包仍可验（直到 hard expiry）
```

### Online Package Signer 紧急 Revocation（密钥泄漏时）

```
1. Offline Root 签发 revocation manifest
2. conaeon.ai 通过 lease refresh response 携带 revocation 通知
3. helper 收到后：
   - 拒绝验证用泄漏 cert 签的包
   - 强制触发客户端重新下载用新 cert 签的包
4. 客户端 24h 内完成轮换，否则进 view-only
```

### 包格式版本演进（修复 C2）

- `major` 升级（v2 → v3）：旧 helper **拒绝**新格式包；新 helper **支持双解析**过渡 90 天
- `minor` 升级：通过 TLV/optional field 扩展，向后兼容
- 客户端 helper 永远 ship 最近两个 major 的解析能力

---

## 十一、Build Pipeline 改动（对照 v1）

| 阶段 | v1 | v2 |
|------|-----|-----|
| Vendor Signing Key 管理 | 一把长期 Ed25519 离线保管 | **Offline Root + Online Package Signer 两级** |
| 包加密 | `package.py encrypt --vendor-key ...` | `package.py encrypt --content-key <CEK> --content-id <id>`（不签，留 wrapped_CEK 空） |
| 客户激活时 | "重新加密整个包" | **`package.py wrap-and-sign --content-id <id> --device-pubkey <key>`**（只重包 wrapped_CEK + 签 Header） |
| 包签名调用 | 直接读私钥文件 | **走 Build Mac Mini 签名服务**（Keychain non-exportable，nobody 读得到私钥） |

---

## 十二、24-72h 优先级 PoC（验证关键假设）

> **目标**：用最小 PoC 一次性验证决议 1（L1 反调试）+ 决议 2（锁屏后台）+ 决议 3 的部分

### PoC 范围

```
1 个 macOS app（最小 Swift app）+ 1 个 LaunchAgent helper

测试场景：
  ✅ helper 启动时 PT_DENY_ATTACH 生效（用 lldb 尝试 attach 失败）
  ✅ helper 用 AfterFirstUnlock 配置访问 Keychain（锁屏后仍可读 Device Key）
  ✅ helper 用 Secure Enclave 生成 + 使用 P-256 私钥（non-exportable）
  ✅ helper 解密一个 demo .csk → 内存交给 app → 用完 sodium_memzero
  ✅ 一个 demo .cki 加载到匿名 mmap，做一次向量检索
```

### 不做的（PoC 阶段排除）

- ❌ conaeon.ai 服务端（用本地 mock 替代）
- ❌ Offline Root 流程（用一把测试密钥替代）
- ❌ rotation/revocation（在 v2 实施阶段做）

---

## 十三、关键 API（更新）

```python
# package.py — Build 侧打包工具
# 阶段 1：发版时一次性加密内容
python package.py encrypt-content \
  --input skill.md \
  --output skill.csk.partial \
  --content-key-out vault/cek-<content-id>.bin

# 阶段 2：客户激活时按 device pubkey 包 CEK + 签名
python package.py wrap-and-sign \
  --input skill.csk.partial \
  --content-key vault/cek-<content-id>.bin \
  --device-pubkey <client-p256-pubkey.pem> \
  --signer-cert online-signer.crt \
  --signer-key-ref keychain://ai.conaeon.package-signer \
  --output skill.csk
```

```swift
// helper 侧解密（Swift + Security.framework）
// 参考 v1 第 13 节 Swift 代码，做以下调整：
// 1. kSecAttrAccessibleWhenUnlocked → kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
// 2. 新增 kSecAttrTokenID: kSecAttrTokenIDSecureEnclave（生成 Device Key 时）
// 3. unwrapCEK 函数：从 wrapped_CEK_blob 解析 TLV 取 eph_pubkey + wrap_nonce + wrapped_CEK + wrap_tag
// 4. 启动时调用 ptrace(PT_DENY_ATTACH, 0, 0, 0) + sysctl 检测
```

---

## 十四、不再做的（vs v1）

| v1 做法 | v2 做法 |
|---------|---------|
| 一把长期 Vendor Signing Key | **拆为 Offline Root + Online Package Signer** |
| DEK 概念（混淆内容/设备密钥）| **拆为 CEK + Device Private Key** |
| encrypted_DEK 65 bytes 错误描述 | **TLV/sealed-key blob，精确字节布局** |
| 签名不含 encrypted_DEK | **签名覆盖完整 canonical manifest** |
| 每客户重新加密所有 .md | **只重包 wrapped_CEK + 重签 Header**（per-customer 成本 ×100 降低）|
| `kSecAttrAccessibleWhenUnlocked` | **`AfterFirstUnlockThisDeviceOnly`** + LaunchAgent |
| lease 实时查询 | **本地令牌验签 + soft/hard expiry + 后台刷新** |
| 无 rotation 机制 | **3-6 月轮换 + revocation manifest** |
| 反调试未提 | **L1 硬化清单**（Hardened Runtime + Secure Enclave + PT_DENY_ATTACH + zeroize）|
| KB RAG 未定义 | **.cki 加密索引 + 匿名 mmap，本地优先** |

---

## 十五、已知限制（明确写死，对应 non-goals）

1. **本机 root + 专业逆向**：理论上可绕过 L1 硬化（详见第十五-bis 章 Threat Model Appendix）
2. **运行时内存可见性**：明文驻留时间最小化（zeroize），但仍是窗口期。**接受**——非目标
3. **索引侧语义结构泄漏**：向量 embedding 含语义信息。**接受**——非目标
4. **Device Key 丢失 = 包永久不可解**：Keychain 数据损坏时 CEK 无法恢复（设计如此）
5. **conaeon.ai 不可用 = hard_expiry 到期后停服**：默认 4h，按 license policy 可放宽到 24/72h

---

## 十五-bis、Threat Model Appendix（I15 修复，需商业 owner 签字）

> **本章必须由 Kelvin / 商业 owner 书面签字确认后方可进入实施阶段**
> **签字状态**：⬜ 未签字（待 Kelvin 确认）

### 保护对抗的攻击者画像（in-scope）

| 攻击者 | 攻击能力 | Plan S v2 防御 |
|--------|---------|---------------|
| **普通客户**（不会 sudo）| Finder 拷文件、删 App、卸载重装 | ✅ 完全防护：拷走的 .csk 无 Device Key 跑不了 |
| **竞品业余逆向**（会用 lldb/Hopper 但非 sudo）| 静态分析二进制、动态 attach（非 root）| ✅ L1 硬化挡住：PT_DENY_ATTACH + Hardened Runtime + Notarization |
| **离线滥用**（停付订阅后继续用）| 把客户机断网 | ✅ Lease hard_expiry 到期 fail-closed |
| **跨客户拷贝**（A 客户的包给 B 客户用）| 整盘拷贝 | ✅ Per-customer wrapped_CEK，跨客户不可用 |

### 显式不防的攻击者（out-of-scope，必须商业接受）

| 攻击者 | 攻击能力 | 为什么不防 |
|--------|---------|----------|
| **本机 root / sudo 用户** | 用 `sudo lldb -p <helper_pid>` 拿 task port，dump 解密后明文 | macOS 平台本身允许 root 绕过 PT_DENY_ATTACH；任何客户端方案都防不住 |
| **macOS 内核级攻击者** | 加载内核扩展 / DTrace | 平台边界，需要硬件 TEE 才能防 |
| **物理访问 + 已登录会话** | 偷设备，会话已解锁 | Keychain `AfterFirstUnlockThisDeviceOnly` 状态可访问 |
| **专业逆向小组**（有时间 + 团队 + 资金）| 反混淆 / Frida / 反 entitlement / 反 Notarization | 反 L2/L3 是猫鼠游戏，性价比低 |
| **OS 取证**（device forensics / 内存快照）| 离线 RAM dump | 平台边界 |

### 商业前提（**必须 Kelvin 签字确认**）

为让 Plan S v2 的 IP 保护实际有效，**客户群必须满足**：

- ✅ **≥ 95% 的客户不会运行 `sudo` 操作客户端进程**
- ✅ 客户群里**不包含**：安全研究员、有意逆向的竞品、专业 IP 攻击团队
- ✅ 客户**接受**："停付即停用"（lease fail-closed）作为商业模式
- ✅ 客户**理解**：物理偷设备 + 已登录会话场景**不防**

**如果以上任一不满足**，方案需要降级或加固：

| 不满足项 | 应对路线 |
|---------|---------|
| 客户含 sudo 用户 (5-30%) | 仍可上 v2，但**必须**加合同条款（禁止逆向 / DMCA）+ 内容水印（追责）|
| 客户含 sudo 用户 (>30%) | **不要上 v2**，改远程执行架构（敏感 prompt 在云端处理，客户端只拿结果）|
| 客户含专业 IP 攻击团队 | 同上 → 远程执行 + 多重水印 + 异常行为检测 |
| 客户期望"完全本地、无网络" | v2 lease fail-closed 不适用，需重新设计离线授权 |

### 业务签字记录

| 决策项 | 签字人 | 日期 | 签名 |
|--------|-------|-----|------|
| 接受"不防本机 root"边界 | Kelvin | _待签_ | _________ |
| 客户群 ≥95% 不含 sudo 用户 | Kelvin | _待签_ | _________ |
| 接受"停付即停用"商业模式 | Kelvin | _待签_ | _________ |

**签字后才能进入实施。**

---

## 十六、行动项（实施前必做）

### v2.1 已完成（4 个 P0 已修复）

- [x] **E1**：Build 服务拆 4 域架构定稿（第 3-bis 章）
- [x] **E3**：CEK vault 改 KMS/HSM 包裹方案定稿（第 3、5 章）
- [x] **F7**：Lease Issuer Key 纳入信任链 + Lease Token 字段升级（第 3、7 章）
- [x] **I15**：Threat Model Appendix + 商业签字流程（第 15-bis 章）

### 实施前阻塞项（必须完成）

- [ ] **🚨 I15 商业签字**：Kelvin 在第 15-bis 章三个决策项上书面签字（**最硬卡点**）
- [ ] **PoC 阶段 A**：Swift app + LaunchAgent helper（2-3 工作日）
  - Secure Enclave P-256 生成 + ECDH
  - Keychain AfterFirstUnlockThisDeviceOnly 配置
  - LaunchAgent + XPC helper
  - .cki 匿名 mmap + sodium_memzero
- [ ] **PoC 阶段 B**：完整签名 + Notarization PoC（再 2-3 工作日）
  - Hardened Runtime + entitlement 完整配置
  - PT_DENY_ATTACH 实测
  - 锁屏后台运行验证
- [ ] **激活压测**：100/500/1000 客户 × 300 包，验 CEK Wrap Service + KMS 吞吐
- [ ] **KMS 选型**：AWS KMS / Hashi Vault Transit / 自建 HSM，三选一并写 ADR 附录

### 实施期间并行做

- [ ] **Offline Root ceremony runbook**：介质 / 2-of-3 custodian / 哈希核对 / 演练周期
- [ ] **sealed-key blob 规范冻结**：HPKE (RFC 9180) vs 自定义 — 给出选择 + 测试向量（已 Python 冒烟通过，可作 reference impl）
- [ ] **min_helper_version 机制**：纳入 lease policy，90 天 grace 后强制升级

### 工程实现细节

- [ ] 用 libsodium 替换标准库内存清零（避免编译器优化）
- [ ] `keychain-access-groups` entitlement 配置（app + helper 同 Team ID）
- [ ] LaunchAgent + 主 app 通过 XPC 通信，明文不经过 `/tmp`

---

## 十七、对外承诺边界（绝不超过这条线）

为防止销售/市场把 v2 误卖成"完全防 IP 提取"，**对外宣传仅可说**：

✅ **可以说**：
- "停付即停用的订阅制 IP 保护"
- "防止离线拷贝复用"
- "Per-customer 加密，跨客户不可用"
- "业余逆向门槛高（L1 硬化）"

❌ **不可说**：
- "完全防止 IP 被提取"
- "本地 IP 100% 安全"
- "防黑客 / 防破解"
- "无法被逆向"

---

*ADR v2 建立：2026-05-19 v2.0 → v2.1 P0 全修复 | 取代 v1 | 基于 [[ADR-plan-s-v1-panel-review-20260519.md|第一轮 Panel]] + [[ADR-plan-s-v2-panel-review-20260519.md|第二轮 Panel]] | 冒烟测试 [[poc-plan-s-v2/smoke_test.py]] 18/18 PASS*
