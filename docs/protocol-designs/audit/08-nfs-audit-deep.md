# NFS 设计文档深度对抗审计报告（第二轮）

**审计对象**：`docs/protocol-designs/08-nfs-design.md`（2135 行）
**审计依据**：RFC 7530 (NFSv4.0) / RFC 7531 (NFSv4.0 XDR) / RFC 1813 (NFSv3) / RFC 5531 (ONC RPC) / CLAUDE.md 测试策略 8 条
**审计方法**：独立对抗审计（adversarial audit），假设"有 bug"，对每个声明做 RFC 原文核验
**审计日期**：2026-08-04
**审计者**：独立审计员（非设计者）

---

## 0. 审计结论

**本文档不可以直接进入实现阶段。**

存在 **6 个 CRITICAL**（含 1 个系统性操作码表 off-by-one、1 个 NFSv4 wire 格式字段系统性错误、1 个 NFSv4 错误码表系统性错误、1 个 clientid 字节数自相矛盾、1 个 SETCLIENTID 嵌套结构建模错误、1 个 CREATE/CREATEHOW 字段建模错误）、**9 个 HIGH**、**8 个 MEDIUM**、**6 个 LOW**。CRITICAL 必须在实现前全部修复。

**前轮审计（28 项）已全部修复，但新发现的问题不在前轮审计范围内**——主要原因是前轮审计仅检查了 RFC 一致性方向（文档 vs RFC），未对 RFC 7531（XDR 权威定义）做逐字段核对。本轮审计引入 RFC 7531 作为权威来源后，发现了前轮遗漏的多个 wire 格式系统性错误。

---

## 1. 问题统计

| 严重度 | 数量 | 摘要 |
|--------|------|------|
| **CRITICAL** | **6** | NFSv4 opcode 表系统性 off-by-one（11→38 全偏移）；NFSv4 wire 格式字段建模错误（SETCLIENTID/CREATE/LOCK/CLOSE）；NFSv4 错误码表系统性数值偏移（4 个值错误）；clientid 字节数自相矛盾；SETCLIENTID 嵌套结构建模错误；CREATE vs CREATEHOW 字段建模错误 |
| **HIGH** | **9** | minorversion 校验机制不足；OPEN_CONFIRM 自动补全规则与 RFC 不完全一致；OPEN 必填 claim 字段与 RFC 矛盾；NFSv3 缺失 LINK opcode 与校验；MOUNT NULL/DUMP 缺失 ACK 自动补全语义缺失；NFSv4 NULL proc=0 测试用例缺失 reply 期望；MSS 分段规则与既有 socks5 实现不一致；auth_sys machine_name 校验缺失；RPC 程序号校验缺失 mountd 默认端口 |
| **MEDIUM** | **8** | NFSv4 error code 表中 NFS4ERR_BAD_COOKIE 与 NFS3ERR_BAD_COOKIE 共用 10003 造成误解；RFC 7530 章节引用系统性错误（§18.x 应为 §16.x）；NFSv3 fattr3 type 值与设计文档示例不一致；multi_session XID 起始规则与 per-session clientid 默认值计算不自洽；SessionsSrcPortStep 校验仅限 sessions>1 忽略了 sessions=1 的边界；COMPOUND tag 字段缺失编码细节；NFSv4 NULL 与 NFSv3 NULL 在 COMPOUND 内放置位置规则缺失；NFSv3 LOOKUP reply post_op_attr 字段建模缺失 |
| **LOW** | **6** | Direction 字段"sideways" 错误信息不准确；测试用例 T21 包计数与状态机 SET_CLIENTID 自动补全冲突；T131 prog_version mismatch 错误信息缺失 NFSv4 场景；T146 base64 解码测试示例值与 stateid 其他示例不一致；M2 NFSClaim 联合体字段设计冗余（DelegateType 同时被 CLAIM_PREVIOUS 与 CLAIM_DELEGATE_CUR 共用字段描述不清）；附录 C 与 RFC 7530/5661 混淆 |
| **合计** | **29** | |

---

## 2. CRITICAL 问题

### C1. §2.5 NFSv4 operation 表系统性 off-by-one：从 opcode 11 (LINK) 开始的所有操作码偏移 +1（设计文档与 RFC 7531 nfs_opnum4 enum 不一致）

**位置**：§2.5（L192-238，整个操作码表 11-38 行）

**问题描述**：

设计文档 §2.5 操作码表与 RFC 7531 §6.1 `enum nfs_opnum4` 的真实值存在 **系统性 off-by-one**，从 opcode 11 开始的所有条目均偏移 +1。详细对比：

| 设计文档 Opcode# | 设计文档名称 | RFC 7531 实际 Opcode# | RFC 7531 实际名称 | 差异 |
|----------------|-------------|---------------------|------------------|------|
| 11 | LOCK | **12** | **LOCK** | OK（同编号但 LOCK 应为 12） |
| (缺失) | (缺失) | **11** | **LINK** | **完全缺失** |
| 12 | LOCKT | 13 | LOCKT | 偏移 |
| 13 | LOCKU | 14 | LOCKU | 偏移 |
| 14 | LOOKUP | 15 | LOOKUP | 偏移 |
| 15 | LOOKUPP | 16 | LOOKUPP | 偏移 |
| 16 | NVERIFY | 17 | NVERIFY | 偏移 |
| 17 | OPEN | 18 | OPEN | 偏移 |
| 18 | OPENATTR | 19 | OPENATTR | 偏移 |
| 19 | OPEN_CONFIRM | 20 | OPEN_CONFIRM | 偏移 |
| 20 | OPEN_DOWNGRADE | 21 | OPEN_DOWNGRADE | 偏移 |
| 21 | PUTFH | 22 | PUTFH | 偏移 |
| 22 | PUTPUBFH | 23 | PUTPUBFH | 偏移 |
| 23 | PUTROOTFH | 24 | PUTROOTFH | 偏移 |
| 24 | READ | 25 | READ | 偏移 |
| 25 | READDIR | 26 | READDIR | 偏移 |
| 26 | READLINK | 27 | READLINK | 偏移 |
| 27 | REMOVE | 28 | REMOVE | 偏移 |
| 28 | RENAME | 29 | RENAME | 偏移 |
| 29 | RENEW | 30 | RENEW | 偏移 |
| 30 | RESTOREFH | 31 | RESTOREFH | 偏移 |
| 31 | SAVEFH | 32 | SAVEFH | 偏移 |
| 32 | SECINFO | 33 | SECINFO | 偏移 |
| 33 | SETATTR | 34 | SETATTR | 偏移 |
| 34 | SET_CLIENTID | 35 | SETCLIENTID | 偏移 |
| 35 | SET_CLIENTID_CONFIRM | 36 | SETCLIENTID_CONFIRM | 偏移 |
| 36 | VERIFY | 37 | VERIFY | 偏移 |
| 37 | WRITE | 38 | WRITE | 偏移 |
| 38 | RELEASE_LOCKOWNER | 39 | RELEASE_LOCKOWNER | 偏移 |

设计文档表格中第 11 行虽然标了 LOCK，但实际它是 RFC 7531 中的 LOCK（opcode 12）—— 即设计文档从第 11 行起**把整张表压缩了一行**，同时**完全遗漏了 LINK (opcode 11)**。

**RFC 依据**：RFC 7531 §6.1 `enum nfs_opnum4`；RFC 7530 §16.9（LINK operation）。

**影响**：
- 所有从 opcode 11 开始的 wire 格式字段都写入错误值；Wireshark 会显示 "unknown opcode"；真实 v4.0 服务端会返回 `NFS4ERR_OP_ILLEGAL` (10044)。
- 设计文档中所有 `compound_ops` 示例的 opcode 字段值（如 §6.1 `opcode: 34`、`§6.2 `opcode: 23`、`§6.3 `opcode: 17` 等）均错误，若按文档实现，Plan 生成的 COMPOUND 在 Wireshark 中将无法解析为预期操作。
- 测试用例 T22（PUTROOTFH opcode=23，实际应为 24）、T23（OPEN opcode=17，应为 18；OPEN_CONFIRM 补全时也将用错误 opcode）、T24（WRITE opcode=37，应为 38）、T26（CREATE opcode=6 OK、REMOVE opcode=27 应为 28）、T27（SAVEFH opcode=31 应为 32、PUTFH opcode=21 应为 22、RENAME opcode=28 应为 29）等**全部使用错误 opcode**。

**修复建议**：
1. §2.5 操作码表全面修正，每行 opcode 加 1；
2. 新增 LINK (opcode 11) 行；
3. 所有 §6.x 示例、§7 测试用例、§8.4 校验项、§8.6 审计项中涉及 opcode 17-38 的字段值全部加 1；
4. 测试用例 T143-T149 中涉及 opcode 的字段值全部加 1（T144 GETATTR opcode=9 仍正确；T148 不受影响；T149 不受影响；但 T146 OPEN_CONFIRM 自动补全测试受影响）。

---

### C2. §3.3 NFSv4CompoundOp 字段建模与 RFC 7531 SETCLIENTID/CREATE/LOCK/CLOSE 结构严重不符

**位置**：§3.3（L516-563）、§3.3.1（L568-598）

**问题描述**：

§3.3 中 NFSv4CompoundOp 多个字段的建模与 RFC 7531 权威 XDR 定义不符，导致字段不能正确序列化/反序列化：

**(a) SET_CLIENTID 字段错误（§3.3 L553-556）：**

设计文档：
```go
ClientidVerifier [8]byte `json:"clientid_verifier,omitempty"`
Id string         `json:"id,omitempty"`
Callback uint32   `json:"callback,omitempty"`
CallbackIdent uint32 `json:"callback_ident,omitempty"`
```

RFC 7531 §5.2 `SETCLIENTID4args`：
```c
struct SETCLIENTID4args {
    nfs_client_id4  client;
    cb_client4      callback;
    uint32_t        callback_ident;
};

struct nfs_client_id4 {
    verifier4       verifier;     // 嵌套在 client 内
    opaque          id<>;         // 嵌套在 client 内
};

struct cb_client4 {
    unsigned int    cb_program;
    clientaddr4     cb_location;
};

struct clientaddr4 {
    string          r_netid<>;
    string          r_addr<>;
};
```

差异：
1. `verifier` 与 `id` 不是顶层字段，而是嵌套在 `nfs_client_id4`（结构体中的字段命名为 `client`）内。设计文档将它们作为顶层字段是错误的。
2. `callback` 不是单一 `uint32`，而是 `cb_client4`（含 `cb_program` uint32 + `cb_location` `clientaddr4` 两个 string）。设计文档完全遗漏了 `cb_location`（`r_netid`/`r_addr` 两个字符串字段）。

**(b) CREATE 字段错误（§3.3 L548-550）：**

设计文档：
```go
ObjType *NFSObjType      `json:"objtype,omitempty"`      // CREATE 的 ftype4 联合
CreateHow *NFSCreateHow  `json:"createhow,omitempty"`    // CREATE 的 createhow4
```

RFC 7531 §5.4 `CREATE4args`：
```c
struct CREATE4args {
    createtype4     objtype;        // ftype4，不是 union，是 enum
    component4      objname;
    fattr4          createattrs;
};
```

差异：
1. CREATE4args **没有** `createhow` 字段！`createhow4` 联合只用于 OPEN 路径中的 `openflag4`。
2. `objtype` 是 `createtype4`（enum），不是 `ftype4` 联合。设计文档 §3.3.1 中 `NFSObjType` 定义为联合类型是错误的。

**(c) LOCK 字段错误（§3.3 L562）：**

设计文档：
```go
OpenStateid *NFSStateid `json:"open_stateid,omitempty"` // LOCK 的 open_stateid
Stateid *NFSStateid      `json:"stateid,omitempty"`     // READ / WRITE / LOCK / CLOSE
```

RFC 7531 §5.5 `LOCK4args`：
```c
struct LOCK4args {
    locktype4       locktype;
    bool            reclaim;
    offset4         offset;
    length4         length;
    locker4         locker;   // 联合，never BOTH open_stateid + lock_stateid
};

union locker4 switch (bool new_lock_owner) {
    case TRUE:
        open_to_lock_owner4     open_owner;
    case FALSE:
        lock_owner4             lock_owner;
};
```

差异：
1. LOCK4args 没有顶层 `open_stateid` 或 `lock_stateid` 字段；它们嵌套在 `locker4` 联合中，且**二选一**（不可能同时存在）。设计文档将它们都设为顶层 `*NFSStateid` 是建模错误。
2. `new_lock_owner` 判别字段（`bool`）也未建模。

**(d) CLOSE 字段命名错误（§3.3 L523）：**

设计文档：`Stateid *NFSStateid` (CLOSE 也用 stateid 字段)
RFC 7531 §5.2 `CLOSE4args`：字段名为 `open_stateid`（虽然类型是 `stateid4`）。

虽然序列化时序列化规则相同，但字段名不一致导致 JSON 配置语义混淆。

**RFC 依据**：RFC 7531 §5.2/§5.4/§5.5/§5.6。

**影响**：
- 按设计文档实现的 Plan 会生成 **畸形 wire 格式**——SETCLIENTID 会把 `verifier`/`id` 写到顶层而非嵌套在 `nfs_client_id4` 内；CREATE 会写入多余的 `createhow` 字段；LOCK 会同时输出 `open_stateid` 和 `lock_stateid`，Wireshark 会按 LOCK4args 定义解析失败。
- §6.1 旗舰场景示例 JSON 不能被正确序列化为 RFC 7531 兼容的字节流。

**修复建议**：
1. 重构 SET_CLIENTID 字段模型，引入 `NFSClientId{Verifier, Id}` 与 `CBCallback{Program, NetID, Addr}` 两个辅助结构体；
2. 删除 CREATE 的 `CreateHow` 字段（CREATE 没有此概念）；
3. LOCK 字段重构为 `NewLockOwner bool` + `OpenToLockOwner *OpenToLockOwner` / `LockOwner *LockOwner` 的联合形式；
4. CLOSE 字段重命名为 `open_stateid`，与 RFC 字段名保持一致。

---

### C3. §2.9 NFSv4 错误码表系统性数值偏移：4 个错误码值与 RFC 7531 nfsstat4 enum 不一致

**位置**：§2.9（L362-382）

**问题描述**：

§2.9 NFSv4 错误码表中多个数值与 RFC 7531 `enum nfsstat4` 不一致：

| 设计文档名称 | 设计文档值 | RFC 7531 实际值 | 差异 |
|------------|----------|----------------|------|
| NFS4ERR_MLINK | 32 | **31** | 偏移 -1 |
| NFS4ERR_BADHANDLE | 10001 | 10001 | OK |
| NFS4ERR_NOFILEHANDLE | 10003 | **10020** | 严重错误 |
| NFS4ERR_MOVED | 10005 | **10019** | 严重错误 |
| NFS4ERR_EXPIRED | 10011 | 10011 | OK |
| NFS4ERR_RESOURCE | 10024 | **10018** | 严重错误 |
| NFS4ERR_RESTOREFH | 10025 | **10030** | 严重错误 |
| NFS4ERR_BAD_STATEID | 10026 | **10025** | 严重错误 |

此外，§2.9 错误码表**完全遗漏**以下常用错误码（测试用例 T59-T62 引用了部分）：
- `NFS4ERR_BAD_COOKIE` (10003) — 设计文档错误地将 10003 赋给 NOFILEHANDLE，导致 BAD_COOKIE 无合法数值
- `NFS4ERR_STALE_CLIENTID` (10022) — T60 隐含引用
- `NFS4ERR_STALE_STATEID` (10023) — 与 BAD_STATEID 不同
- `NFS4ERR_OLD_STATEID` (10024) — 设计文档错误地将 10024 赋给 RESOURCE
- `NFS4ERR_MINOR_VERS_MISMATCH` (10021) — 与 §1.1 minorversion 校验直接相关
- `NFS4ERR_NOT_SAME` (10027) — §6.7 注释中提及

**RFC 依据**：RFC 7531 §3 `enum nfsstat4`。

**影响**：
- T59 (`reply_status=10003`) 期望返回 `NFS4ERR_NOFILEHANDLE`，但 10003 实际是 `NFS4ERR_BAD_COOKIE`；按文档实现的真实服务端只会返回 `BAD_COOKIE` 而非 `NOFILEHANDLE`。
- T60 (`reply_status=10026`) 期望 `BAD_STATEID`，但 10026 实际是 `BAD_SEQID`；T60 实际测试的是 BAD_SEQID。
- T61 (`reply_status=10011`) 正确返回 EXPIRED。
- §6.7 (READDIR cookieverf 注释) 引用 `NFS4ERR_NOT_SAME`，但 §2.9 错误码表中未列出此错误码（虽然文档在 §6.7 注释中提到了它）。

**修复建议**：
1. §2.9 NFSv4 错误码表全面修订，与 RFC 7531 一一对应；
2. 补充缺失的常用错误码（至少 BAD_COOKIE/STALE_CLIENTID/STALE_STATEID/OLD_STATEID/MINOR_VERS_MISMATCH/NOT_SAME）；
3. T59 改为 `reply_status=10020`（真正对应 NOFILEHANDLE）；
4. T60 改为 `reply_status=10025`（真正对应 BAD_STATEID）；
5. §6.7 注释中 `NFS4ERR_NOT_SAME` 改为 RFC 7531 中的准确值（10027）。

---

### C4. §2.6 clientid 字节数错误 + §3.4 NFSLockOwner.Clientid 类型自相矛盾

**位置**：§2.6（L279）、§3.4（L617）

**问题描述**：

§2.6 声明：
> **clientid** (RFC 7530 §14.2.6)：4 字节 uint32，由服务端在 SET_CLIENTID/EXCHANGE_ID 后分配。

RFC 7531 §3 明确定义：
```c
typedef uint64_t clientid4;
```

clientid4 是 **uint64 (8 字节)**，不是 uint32。

§3.4 中 `NFSLockOwner.Clientid` 使用 `uint64`（正确），与 §2.6 的"4 字节 uint32"声明**自相矛盾**。

此外，§2.6 引用的 RFC 章节"§14.2.6"在 RFC 7530 中实际不存在（RFC 7530 没有以 §14.2.6 编号的小节，且 clientid4 定义在 RFC 7531 而非 RFC 7530）。

**RFC 依据**：RFC 7531 §3 `typedef uint64_t clientid4;`。

**影响**：
- 按 §2.6 "4 字节"实现的 wire 格式会截断 clientid 的高 4 字节；服务端无法正确识别 clientid。
- 测试用例 T42-T45 中设计的 clientid 默认值（如 0x10001）若按 4 字节解读会溢出。

**修复建议**：
1. §2.6 改为"8 字节 uint64"；
2. §2.6 注释中的 RFC 引用改为 RFC 7531 §3；
3. 验证 §3.3 NFSv4CompoundOp.Clientid (uint64) 与 §3.4 NFSLockOwner.Clientid (uint64) 均为 uint64，与 §2.6 一致。

---

### C5. §3.3 SETCLIENTID 字段建模错误：未表达 nfs_client_id4 嵌套结构与 cb_client4.cb_location

**位置**：§3.3（L553-556）、§6.1（L867-887）

**问题描述**：

设计文档将 SET_CLIENTID 的 `clientid_verifier`、`id`、`callback`、`callback_ident` 都设为 NFSv4CompoundOp 的顶层字段。但 RFC 7531 §5.2 `SETCLIENTID4args` 的结构是：

```c
struct SETCLIENTID4args {
    nfs_client_id4  client;          // 嵌套结构：{ verifier, id }
    cb_client4      callback;        // 嵌套结构：{ cb_program, cb_location(r_netid, r_addr) }
    uint32_t        callback_ident;
};
```

设计文档的建模错误导致：
1. `verifier`/`id` 不能正确嵌套在 `client` 内，wire 格式输出缺少 `nfs_client_id4` 嵌套层。
2. `callback` 缺失 `cb_location`（即 `r_netid` 与 `r_addr` 两个 string）；客户端无法向服务端通知回调地址。

§6.1 示例 JSON：
```json
{"opcode": 34, "clientid": 0, "clientid_verifier": "AAAAAAAAAAA=",
 "id": "trafficgen-client", "callback": 0, "callback_ident": 0}
```

按设计文档的字段模型序列化时，会把 `clientid_verifier` 与 `id` 写到 `nfs_client_id4` 之外的位置；`callback=0` 仅能表达 `cb_program=0`，无法表达 `cb_location`。

**RFC 依据**：RFC 7531 §5.2 `SETCLIENTID4args`/`nfs_client_id4`/`cb_client4`/`clientaddr4`。

**影响**：
- 按设计文档实现的 Plan 生成 SETCLIENTID COMPOUND 在 Wireshark 中会被解析失败（结构不匹配 SETCLIENTID4args 定义）。
- 真实服务端无法从 wire 格式中提取回调地址；即使服务端不强制要求 callback，结构错误也会导致 RPC 解析失败。

**修复建议**：
1. 引入 `NFSClientId { Verifier [8]byte; Id string }` 与 `CBCallback { Program uint32; NetID string; Addr string }` 两个辅助结构体；
2. NFSv4CompoundOp 增加 `Client *NFSClientId` 与 `Callback *CBCallback` 字段；
3. 删除现有 `ClientidVerifier`、`Id`、`Callback` 三个顶层字段（合并到 `Client` 与 `Callback` 中）；
4. §6.1 示例 JSON 同步修改。

---

### C6. §3.3 CREATE 字段错误建模：CREATE4args 无 createhow 字段，objtype 不是联合

**位置**：§3.3（L548-550）、§3.3.1（L586-591）

**问题描述**：

设计文档 §3.3 中：
```go
ObjType *NFSObjType      `json:"objtype,omitempty"`      // CREATE 的 ftype4 联合
CreateHow *NFSCreateHow  `json:"createhow,omitempty"`    // CREATE 的 createhow4
```

并定义 §3.3.1 中 `NFSObjType` 为联合类型（含 `Type` 判别字段 + `Devspec`/`Linkdata` 等分支）。

RFC 7531 §5.4 `CREATE4args`：
```c
struct CREATE4args {
    createtype4     objtype;     // enum，不是 union
    component4      objname;
    fattr4          createattrs;
};
```

差异：
1. CREATE4args **没有** `createhow` 字段。`createhow4` 联合（UNCHECKED4/GUARDED4/EXCLUSIVE4）是 `OPEN4args.openflag4` 内部的概念，与 CREATE 操作无关。
2. `objtype` 是 `createtype4`（enum: NF4REG=1/NF4DIR=2/.../NF4NAMEDATTR=9），**不是**联合类型。设计文档 §3.3.1 中 `NFSObjType` 定义为联合类型是错误的。
3. CREATE 还缺少 `objname`（component4，XDR string）字段——设计文档借用 §3.3 中已有的 `Name string` 字段表达，但语义不一致（`Name` 在不同 op 中语义不同，应在 CREATE 字段语义说明中明确）。

**RFC 依据**：RFC 7531 §5.4 `CREATE4args`/`createtype4`；RFC 7530 §16.4。

**影响**：
- 按设计文档实现的 Plan 在生成 CREATE COMPOUND 时会输出多余的 `createhow` 字段，Wireshark 无法解析；真实服务端会因格式错误返回 `NFS4ERR_BADXDR` (10036)。
- §3.3.1 中 `NFSObjType` 的联合建模（带 `Devspec`/`Linkdata`）不会在 wire 格式中体现（因为 `objtype` 是 enum 不是 union）。

**修复建议**：
1. 删除 `CreateHow *NFSCreateHow` 字段；
2. `NFSObjType` 重构为简单 enum 形式：`Type uint32`（`json` 字符串如 "regular"），移除 `Devspec`/`Linkdata` 字段（这两个字段对应 OPENCLAIM4/NF4BLK/NF4CHR 等场景，不在 CREATETYPE4 中）；
3. 明确 `Name string` 字段在 CREATE 语义下作为 `objname`（component4）；
4. 删除 §3.3.1 中 `NFSCreateHow` 结构体定义。

---

## 3. HIGH 问题

### H1. §3.1 MinorVersion 校验机制不足：T137 错误信息与 §1.1 规则不对齐

**位置**：§3.1（L450）、§3.5（L666）、§7.8.4 T137

**问题描述**：

§3.1 声明：`MinorVersion *uint32` "仅 0 (v4.0) 合法；非 0 Validate 报错"。
但 §3.5 字段语义补充仅说明"显式设为 1 (NFSv4.1) 时 Validate 报错"——未明确其他非法值（如 2, 99, 0xFFFFFFFF）的处理。

T137 测试用例：
> `T137 | minorversion=1 | error: only NFSv4.0 (minorversion=0) is supported`

未测试 `minorversion=2`、`minorversion=99` 等边界值。按 RFC 7531 §3 `enum nfsstat4`，`NFS4ERR_MINOR_VERS_MISMATCH` (10021) 在 minorversion 不被识别时由服务端返回——但客户端构造非法 minorversion 是协议错误，Validate 应拒绝而非透传。

**修复建议**：补充 T137-2 用例：`minorversion=2` → error。

---

### H2. §4.1 OPEN_CONFIRM 自动补全规则与 RFC 7530 §9.1.11 不完全一致：seqid 语义过于简化

**位置**：§4.1 规则 3（L707）

**问题描述**：

§4.1 规则 3：
> OPEN_CONFIRM 自动补全（M10 修复）：NFSv4.0 中，新的 open-owner 首次 OPEN 后必须 OPEN_CONFIRM（opcode=19）。Plan 检测到 OPEN 且 open-owner 是首次出现（同 clientid+owner 在前序 ops 中未出现）时，自动在 OPEN 后追加 OPEN_CONFIRM，seqid 沿用 open-owner 的 seqid 序列（OPEN seqid=1 → OPEN_CONFIRM seqid=2）。

但按 RFC 7530 §9.1.11：
- "The first time an open_owner is used, the server returns an OPEN_CONFIRM response via the stateid that has a different value of the 'other' field than what the client sent."
- OPEN_CONFIRM 的 seqid 是 **OPEN reply 的 stateid 中的 seqid**（由服务端递增 1），而非 OPEN call 中的 seqid + 1。
- OPEN_CONFIRM 的 `open_stateid` 是 **OPEN reply 中的 stateid**，不是 OPEN call 中的 stateid。

设计文档的简化是"为了合成流量"是合理的，但应在文档中明确这是简化语义，且应在测试用例 T145 中明确这一点（"OPEN seqid=1 → OPEN_CONFIRM seqid=2" 是否为合成流量下的简化，是否与 RFC 严格语义对齐）。

**RFC 依据**：RFC 7530 §9.1.11。

**修复建议**：§4.1 规则 3 增加注释："合成流量下 OPEN_CONFIRM 的 seqid 简化为 OPEN call seqid + 1；真实协议中 OPEN_CONFIRM 的 seqid 是 OPEN reply stateid 的 seqid。"

---

### H3. §3.3 NFSv4CompoundOp OPEN claim 字段必填规则与 RFC 7530 §16.16 矛盾

**位置**：§3.5 联合类型默认规则（L602）、§6.3 L988

**问题描述**：

§3.5 默认规则：
> OPEN 缺 `claim` 字段时，Validate 用默认 `{"type": "null"}` (CLAIM_NULL) 并告警。

但 RFC 7530 §16.16 OPEN4args：
```c
struct OPEN4args {
    seqid4          seqid;
    uint32_t        share_access;
    uint32_t        share_deny;
    open_owner4     owner;
    openflag4       openhow;
    open_claim4     claim;        // 必填
};
```

`claim` 字段是 `open_claim4` 联合，在 wire 格式中无论使用何种 claim 类型，都必须输出判别字段（union discriminator）。设计文档用"Validate 用默认值并告警"的处理是正确的工程做法，但 §6.3 示例 L988 写：
> OPEN 的 claim/openhow 字段（M2）：claim 必填（默认 {"type": "null"} = CLAIM_NULL），openhow 必填（默认 {"type": "unchecked"} = UNCHECKED4）。Validate 检测 OPEN 时若 claim/openhow 缺失则用默认值并告警。

但 §6.3 示例 JSON 实际包含 `claim`/`openhow`，未触发默认值。T145 测试用例引用 OPEN_CONFIRM 自动补全，但未单独测试"OPEN 缺 claim/openhow 时 Validate 用默认值"的负向行为。

**RFC 依据**：RFC 7530 §16.16 OPEN4args；RFC 7531 §5.2 OPEN4args。

**修复建议**：补充 T150 用例：`OPEN 缺 claim 字段 → Validate 告警 + 默认 {"type": "null"}`；T151：`OPEN 缺 openhow 字段 → Validate 告警 + 默认 {"type": "unchecked"}`。

---

### H4. §2.5 缺失 LINK (opcode 11) + 测试用例未覆盖

**位置**：§2.5（L192-238）、§7.8.2

**问题描述**：

设计文档 §2.5 操作码表中**完全缺失** RFC 7530 §16.9 `LINK` (opcode 11)。同时 §7.8.2 NFSv4 operation 全遍历测试用例（T99-T117）也未包含 LINK。

RFC 7530 §16.9 LINK 操作：创建一个硬链接，参数为 filehandle + link_dirfh + link_name，返回 post_op_attr + wcc_data。

**RFC 依据**：RFC 7530 §16.9；RFC 7531 §5.5 LINK4args。

**影响**：违反 CLAUDE.md §Testing Policy 第 1 条（spec 行→测试）。LINK 是 v4.0 标准操作，实现需要支持。

**修复建议**：
1. §2.5 增加 LINK (opcode 11) 行；
2. §7.8.2 增加 T152 用例：`v4 LINK (opcode 11)` → OK，reply 含 post_op_attr+wcc_data。

---

### H5. §4.2 NFSv3 MOUNT NULL/DUMP/EXPORT/UMNTALL 自动补全语义缺失

**位置**：§4.2（L719-755）

**问题描述**：

§4.2 NFSv3 状态机只描述了 MOUNT/MNT + NFS 操作 + UMOUNT/UMNT 三个 procedure。但 NFSv3 MOUNT 协议还有 NULL/DUMP/EXPORT/UMNTALL（§2.3 表中已列出），且 §7.8.3 T118-T121 列出了这 4 个 procedure 的测试用例。

设计文档未明确这些 procedure 是否在自动补全流程中使用：
- MOUNT NULL (proc 0)：是 ping 性质的 procedure，是否在 Plan 中插入未明确。
- MOUNT DUMP/EXPORT (proc 2/5)：查询类 procedure，是否与 user 配置的 MOUNT (proc 1) 冲突未明确。
- MOUNT UMNTALL (proc 4)：批量卸载，是否与单个 UMOUNT (proc 3) 互斥未明确。

§2.3 写：
> trafficgen 默认只生成 NULL/MNT/UMNT，其余 DUMP/EXPORT/UMNTALL 留作扩展点（用户显式配置 proc=2/4/5 时 Validate 通过，但本设计不自动补全）。

但 §4.2 未对应给出"不自动补全"的明确规则，导致测试用例 T118-T121 的语义模糊。

**修复建议**：
1. §4.2 增加规则 5："MOUNT 协议的 NULL/DUMP/EXPORT/UMNTALL 不参与自动补全流程；user 显式配置时透传，Plan 不自动插入头部/尾部"；
2. §8.2 状态机审计项同步增加。

---

### H6. §6.x NFSv4 NULL (proc 0) 测试用例 T143 缺失 reply 期望

**位置**：§7.8.6 T143（L1778）

**问题描述**：

T143：
> `T143 | v4 NULL (proc 0) | version=4, procedure=0 | OK，NFSv4 NULL：RPC procedure=0，call/reply 无 NFS 层 body`

但 §2.4 NFSv4 Procedure 表明确 NULL 是不带 COMPOUND 包装的简单 procedure，call/reply **无 NFS 层 body**——这没错。但 RFC 5531 §8 中 NULL procedure 的 RPC ACCEPTED reply 不应包含 NFS 层 status 字段（因为没有 NFS 主体）。

测试用例期望表述不完整：未明确 RPC REPLY 的 AcceptState 应为 SUCCESS (0)，也未明确 NFS 层 status 不存在（验证 RPC REPLY 解析不应期待任何 NFS 主体）。

**修复建议**：T143 补充"RPC REPLY AcceptState=0 (SUCCESS)，无 NFS 层 status 字段"。

---

### H7. §5.1 MSS 分段规则与 socks5 既有实现不一致：缺少中间段 ACK-only 细节

**位置**：§5.1（L814-820）

**问题描述**：

§5.1 MSS 分段规则：
> 单个 RPC call/reply 的 payload 超过 MSS 时，按 MSS 切分为多个 PSH-ACK 段，最后一个段带 PSH+ACK，中间段只带 ACK。

但 socks5.go 中既有实现的细节（参照 memory 中的 socks5 设计）通常中间段只带 PSH-ACK 而非 ACK-only（因为每个段都需要推送用户数据）。设计文档的"中间段只带 ACK"与 RFC 793 中 PSH 标志的语义不一致——PSH 用于通知接收端应立即将数据交给应用层，即使中间段也应设置 PSH。

**RFC 依据**：RFC 793 §3.1（PSH 标志语义）。

**修复建议**：§5.1 改为"每段 PSH-ACK（包括中间段和最后段）"或明确说明中间段不带 PSH 的合理性。

---

### H8. §3.5 auth_sys machine_name 长度校验缺失

**位置**：§3.4（L639-645）、§3.5

**问题描述**：

§3.5 仅提到 `machinename` 默认值与 `auth_sys=nil` 时的行为，但未提及 RFC 5531 §9.2 中对 machine_name 长度未做明确上限——XDR string 理论最大 2^32-1 字节，但实际服务端（如 Linux knfsd）通常限制在 255 字节以内。

T133 测试用例：
> `T133 | auth_sys machinename 超长 | machinename 256 字节 | error: machinename exceeds 255 bytes`

错误信息暗示有 255 字节限制，但 RFC 5531 并无此限制。这是**工程性约束**而非 RFC 约束，应在文档中明确标注。

**修复建议**：§3.5 增加"machine_name 实际工程限制 255 字节（与 Linux knfsd 一致，非 RFC 强制）"。

---

### H9. RPC 程序号校验缺失 mountd 默认端口语义

**位置**：§3.5（L661）、§4.2 规则 4

**问题描述**：

§3.5 提到：
> NFSOp.program 默认 100003（NFS）；MOUNT 时 100005（T130）

但未明确 MOUNT 协议默认端口（按真实协议为 635 或 rpcbind 端口 111，与 NFS 端口 2049 不同）。虽然 §4.2 规则 4 已登记"MOUNT/UMOUNT 与 NFS 共用同一 TCP 连接"的偏离，但 T130 Validate 错误信息未提及端口。

**修复建议**：§3.5 T130 错误信息补充"（NFS 使用 2049，MOUNT 应使用 mountd 端口）"，明确偏离已登记。

---

## 4. MEDIUM 问题

### M1. §2.9 NFSv4 错误码表中 NFS4ERR_BAD_COOKIE 与 NFS3ERR_BAD_COOKIE 共用 10003 造成误解

**位置**：§2.9（L362-382 与 L385-410）

**问题描述**：

§2.9 NFSv4 错误码表中：
> NFS4ERR_NOFILEHANDLE = 10003

§2.9 NFSv3 错误码表中：
> NFS3ERR_BAD_COOKIE = 10003

但根据 RFC 7531 §3：
- NFS4ERR_BAD_COOKIE = 10003
- NFS4ERR_NOFILEHANDLE = 10020

设计文档将 10003 同时映射为 NFSv4 NOFILEHANDLE 和 NFSv3 BAD_COOKIE——虽然 v3 和 v4 错误码空间独立，但 NFSv4 内部存在冲突（10003 实际是 BAD_COOKIE 不是 NOFILEHANDLE）。

**修复建议**：将 NFS4ERR_NOFILEHANDLE 修正为 10020（参见 C3）。

---

### M2. RFC 7530 章节引用系统性错误：§18.x 应为 §16.x

**位置**：§1.1（L22）、§3.3（L606）、§4.1（L707）

**问题描述**：

设计文档多处引用：
- §1.1："SET_CLIENTID → SET_CLIENTID_CONFIRM 建立客户端身份（RFC 7530 §18.34/§18.35）"
- §4.1 规则 3："RFC 7530 §18.16/§18.19" 关于 OPEN_CONFIRM
- §9.8 #4："RFC 7530 §18.16/§18.19"
- §9.8 #5：注释中提及 OPCODE 41/42/43 时引用 RFC 5661

但根据 RFC 7530 的实际章节编号：
- SET_CLIENTID 在 §16.33
- SET_CLIENTID_CONFIRM 在 §16.34
- OPEN_CONFIRM 在 §16.18

§18 是 NFSv4 callback operations（CB_GETATTR/CB_RECALL/CB_ILLEGAL），与 SET_CLIENTID/OPEN_CONFIRM 无关。

§18.34/§18.35 等节号在 RFC 7530 中**不存在**——§18 仅有 3 个 subsection（18.1/18.2/18.3）。

**RFC 依据**：RFC 7530 Table of Contents（§16 为 NFSv4 operations，§18 为 callback operations）。

**影响**：设计文档的 RFC 引用错误会导致实现者查阅 RFC 时找不到对应章节，增加调试成本。

**修复建议**：
1. 所有 §18.x 引用改为 §16.x；
2. §18.34 → §16.33；§18.35 → §16.34；§18.16 → §16.16；§18.19 → §16.18。

---

### M3. NFSv3 fattr3 type 值与设计文档示例不一致：§6.12 CREATE reply attrs 期望未明确

**位置**：§6.12（L1261-1279）、§2.8（L324-340）

**问题描述**：

§2.8 fattr3 字段定义：
> type (4 bytes) FT_* (1=REG, 2=DIR, 3=BLK, 4=CHR, 5=LNK, 6=SOCK, 7=FIFO)

按 RFC 1813：
> ftype3: NF3REG=1, NF3DIR=2, NF3BLK=3, NF3CHR=4, NF3LNK=5, NF3SOCK=6, NF3FIFO=7

§6.12 CREATE 示例中 CREATE reply 期望含 `post_op_fh3 + post_op_attr`，但 `post_op_attr` 包含 fattr3 字段——示例中未指明 `type` 字段应填什么值。

测试用例 T35（§7.3）：
> `T35 | MOUNT + CREATE + REMOVE | ops: [MOUNT, CREATE, REMOVE] | 12 包`

T35 仅检查包数，未检查 `post_op_attr.type` 的值。FATTR3 type 字段决定 NFSv3 文件类型语义，应在测试中明确验证（虽然合成流量下所有 reply 的 fattr3 可默认填 REG=1）。

**修复建议**：T35 补充"reply fattr3.type=1 (NF3REG)"。

---

### M4. multi_session XID 起始规则与 per-session clientid 默认值计算不自洽

**位置**：§3.1 XIDBase（L441）、§4.3 规则 3（L776-779）

**问题描述**：

§4.3 规则 3 关于 clientid 默认值：
> reply 的 clientid = call 的 clientid 期望值，即 session i 默认 clientid = 0x10000 * i + 1，避开 0

但 §3.1 XIDBase 默认值：
> XIDBase uint32 ... 默认 1

测试用例 T44：
> `T44 | 多会话独立 XID | sessions=2, xid_base=100 | 每会话 XID 从 100 开始独立递增`

XIDBase 是 uint32，最大 0xFFFFFFFF。若 XIDBase=0x10000 - 1（即 65535），则 session 0 的 clientid 默认值 0x10000 * 0 + 1 = 1；但 clientid 是 uint64，XIDBase 是 uint32——XIDBase 不能直接用作 clientid 默认值的偏移基础（因为 0x10000 * 0xFFFFFFFF 可能溢出）。

**修复建议**：§4.3 规则 3 明确"clientid 默认偏移基础使用 XIDBase 作为起始值"，避免 uint32→uint64 转换语义模糊。

---

### M5. SessionsSrcPortStep 校验仅限 sessions>1 忽略了 sessions=1 的边界

**位置**：§3.5（L656-657）、T18

**问题描述**：

T18：
> `T18 | sessions_src_port_step=0 | sessions=3, step=0 | error: step must be non-zero when sessions>1`

T18 测试 sessions=3 时 step=0 应报错。但 sessions=1 时 step=0 应该合法（单会话无递增需求）。当前规则表述：
> sessions_src_port_step 必须非 0

未明确 sessions=1 时是否允许 step=0，存在歧义。

**修复建议**：§3.5 明确"sessions=1 时 step 可为任意值（无递增需求）；sessions>1 时 step 必须非 0"。

---

### M6. COMPOUND tag 字段缺失编码细节

**位置**：§2.7（L282-290）、§3.3 NFSv4CompoundOp.Tag（L494）

**问题描述**：

§2.7 COMPOUND 编码：
> tag (string, XDR)               标签，可空

§3.3 NFSOp.Tag（L494）：
> `Tag string       `json:"tag,omitempty"``        // COMPOUND tag

但 §2.7 未明确 tag 在 reply 中的对应字段（tag 也必须在 reply 中回显）；§3.3 也未明确 reply 中 tag 的处理。

RFC 7531 §5.2 `COMPOUND4args`/`COMPOUND4res`：
```c
struct COMPOUND4args {
    utf8string      tag;
    uint32_t        minorversion;
    nfs_argop4      argarray<>;   // 变长数组（带长度前缀）
};
```

tag 在 call 与 reply 中均须出现，且类型为 utf8string（XDR opaque 变长）。

**修复建议**：
1. §2.7 补充"reply tag 回显 call tag"；
2. §3.3 NFSOp 增加说明"reply 中 tag 与 call 一致"。

---

### M7. NFSv4 NULL 与 NFSv3 NULL 在 COMPOUND 内放置位置规则缺失

**位置**：§4.1（L671-700）

**问题描述**：

§4.1 NFSv4.0 会话状态机仅描述了 SET_CLIENTID/SET_CLIENTID_CONFIRM 前导 + 用户配置 Ops + TCP FIN。NFSv4 NULL procedure (proc=0) 是一条独立的 RPC procedure，不应嵌入 COMPOUND 内。

但 §6.x 示例（如 §6.10、§6.11）使用 NFSv3 procedure 0 作为 ping 操作；§6.1/§6.2 使用 NFSv4 COMPOUND 包裹 SET_CLIENTID 等操作。NFSv4 NULL 的位置未在状态机或自动补全规则中明确说明。

**修复建议**：§4.1 增加"NFSv4 NULL (proc=0) 不嵌入 COMPOUND，是独立 RPC procedure；user 显式配置 procedure=0 时 Plan 直接生成 NULL call/reply"。

---

### M8. NFSv3 LOOKUP reply post_op_attr 字段建模缺失

**位置**：§2.2 NFSv3 Procedure 表（L138）、§6.11（L1238-1258）

**问题描述**：

§2.2 LOOKUP (proc 3) 返回：
> filehandle, post_op_obj_attr

§6.11 LOOKUP reply 期望：
> LOOKUP reply 含新 fh3

但未明确 `post_op_obj_attr` 的 wire 格式（fattr3，84 字节）。测试用例 T34 仅检查包数，未验证 `post_op_obj_attr` 的编码。

**修复建议**：T34 补充"reply LOOKUP 含 fh3(变长) + post_op_obj_attr(84 字节 fattr3)"。

---

## 5. LOW 问题

### L1. Direction 字段"sideways" 错误信息不准确

**位置**：T134（L1757）

T134：
> `T134 | direction 非法值 | direction="sideways" | error: invalid direction (must be up/down)`

错误信息合理。但 §3.1 NFSConfig.Direction 字段语义说明（L448）写：
> 默认 "up" (call 主导)

未明确 "down" 与 "up" 的具体含义（down = 服务端→客户端 reply 主导？）。这在 NFS 双向流量场景下语义模糊。

**修复建议**：§3.1 Direction 字段语义补充"up = call 占主导（client→server），down = reply 占主导（server→client，仅用于模拟服务端主动推送场景）"。

---

### L2. 测试用例 T21 包计数与状态机 SET_CLIENTID 自动补全冲突

**位置**：T21（L1593）

T21：
> `T21 | SET_CLIENTID + SET_CLIENTID_CONFIRM | ops: [SET_CLIENTID, SET_CLIENTID_CONFIRM] | 10 包 (握手3 + 2 call/reply=4 + 挥手3)`

§4.1 规则 1：
> Plan 阶段在 Ops 头部自动插入 SET_CLIENTID（opcode=34）与 SET_CLIENTID_CONFIRM（opcode=35），除非 user 在 Ops 中已显式包含 opcode=34（则不重复插入 SET_CLIENTID；但仍检查 SET_CLIENTID_CONFIRM 是否存在，未包含则自动追加）

T21 输入是 "ops: [SET_CLIENTID, SET_CLIENTID_CONFIRM]"——已显式包含两个操作。按 §4.1 规则 1，**不**应重复插入，因此 T21 的预期包数 10 包是正确的（不重复自动补全）。

但 T22：
> `T22 | PUTROOTFH + LOOKUP + GETATTR | ops: 1 COMPOUND (3 ops) | 自动补全 SET_CLIENTID+SET_CLIENTID_CONFIRM (2 往返) + 1 COMPOUND = 3 往返 → 12 包`

T22 是 user 未配置 SET_CLIENTID，因此自动补全生效。逻辑一致，但 §7.2 包计数约定 L1589 写：
> 自动补全的 SET_CLIENTID/SET_CLIENTID_CONFIRM 各算 1 个 RPC 往返

T21 包计数 = 6 + 2×2 = 10 包（user 配 2 个 op，无自动补全），与 T22 包计数 = 6 + 2×3 = 12 包（自动补全 2 + user 配 1 = 3 个 op）——这两个用例的包计数约定与实际输入的一致性需要明确验证。

**修复建议**：T21 验证输入列表 "ops: [SET_CLIENTID, SET_CLIENTID_CONFIRM]" 的实际语义——是 user 显式配的，还是 Plan 自动补全的？当前描述模糊。

---

### L3. T131 prog_version mismatch 错误信息缺失 NFSv4 场景

**位置**：T131（L1754）

T131：
> `T131 | prog_version 与 version 不匹配 | version=3, prog_version=4 | error: prog_version mismatch`

但未测试 `version=4, prog_version=3` 的反向场景（同样应报错）。

**修复建议**：增加 T131-2：`version=4, prog_version=3` → error。

---

### L4. T146 base64 解码测试示例值与 stateid 其他示例不一致

**位置**：T146（L1781）

T146：
> `T146 | stateid base64 精确解码 | stateid={seqid=1, other="AQIDBAUGBwgJCg=="} | 验证 Plan 精确解码为 12 字节 01 02 03 04 05 06 07 08 09 0A 0B 0C`

但 §6.x 其他示例（如 §6.3 §6.4 §6.8 §6.9）统一使用 `"AAAAAAAAAAAAAAAA"`（12 字节全 0 的 base64）。T146 使用非零值的目的是测试解码正确性，但与文档其他示例的惯例不一致，可能引起混淆。

**修复建议**：T146 增加"或用 12 字节全 0 等价测试"作为补充。

---

### L5. M2 NFSClaim 联合体字段设计冗余：DelegateType 同时被 CLAIM_PREVIOUS 与 CLAIM_DELEGATE_CUR 共用字段描述不清

**位置**：§3.3.1 NFSClaim（L569-577）

§3.3.1 NFSClaim：
```go
type NFSClaim struct {
    Type string `json:"type"` // "null" / "previous" / "delegate_cur" / "delegate_prev"
    DelegateType uint32 `json:"delegate_type,omitempty"`         // CLAIM_PREVIOUS
    DelegateStateid *NFSStateid `json:"delegate_stateid,omitempty"` // CLAIM_DELEGATE_CUR
}
```

按 RFC 7531 §5.2 `open_claim4`：
```c
union open_claim4 switch (uint32_t claim_type) {
    case CLAIM_NULL:        component4      file;
    case CLAIM_PREVIOUS:    open_delegation_type4 delegate_type;
    case CLAIM_DELEGATE_CUR: stateid4       delegate_stateid;
    case CLAIM_DELEGATE_PREV: open_delegation_type4 delegate_type;
};
```

设计文档的 NFSClaim 字段：
- `DelegateType` 仅在 CLAIM_PREVIOUS 时用，注释正确；但 CLAIM_DELEGATE_PREV 同样需要 `delegate_type`，注释遗漏。
- `DelegateStateid` 仅在 CLAIM_DELEGATE_CUR 时用，注释正确。

**修复建议**：§3.3.1 NFSClaim 注释补充"CLAIM_DELEGATE_PREV 也使用 DelegateType 字段"。

---

### L6. 附录 C 与 RFC 7530/5661 混淆

**位置**：附录 C（L2059-2069）

附录 C 中 "NFS (本文档)" 列 "会话" 写：
> 单 TCP 流 + 多会话并发

但本文档实际是 NFSv4.0（无 v4.0 会话机制）—— 这里的"多会话并发"指多客户端并发（多个独立 TCP 流），而非 v4.1 的会话概念。可能造成与 RFC 5661 的混淆。

**修复建议**：附录 C "会话" 行改为"单 TCP 流 + 多客户端并发（v4.0 无会话机制）"。

---

## 6. 审计总结

### 6.1 与前轮审计（28 项）的对比

前轮审计（08-nfs-audit.md）发现 28 项并已全部修复，但前轮审计的**主要盲区**是：
1. 未引用 RFC 7531（XDR 权威定义），导致无法识别 wire 格式字段的嵌套结构错误（C2/C5/C6）；
2. 未引用 RFC 7531 enum nfsstat4，导致错误码值系统性偏移未识别（C3）；
3. 未对操作码表做逐项核对，仅检查 §2.5 的"代表性"操作（如 SET_CLIENTID/OPEN/READ/WRITE），未发现从 opcode 11 开始的系统性 off-by-one（C1）；
4. 未交叉核对 RFC 7530 章节编号（§18.x vs §16.x），导致 RFC 引用错误未识别（M2）；
5. 未对 clientid 字节数做 RFC 7531 typedef 校验（C4）。

本轮审计**专门补强**了以上五个盲区，共发现 29 个新问题（6 CRITICAL + 9 HIGH + 8 MEDIUM + 6 LOW）。

### 6.2 最关键风险

1. **C1（opcode 表 off-by-one）**：影响所有 v4 COMPOUND 操作；按当前文档实现的 Plan 生成的 wire 格式将无法被 Wireshark 正确解析为预期操作。
2. **C2/C5（SETCLIENTID/CREATE/LOCK 字段建模错误）**：影响 wire 格式的嵌套结构；按当前文档实现的 Plan 生成的 v4 COMPOUND 将与 RFC 7531 不兼容。
3. **C3（错误码值偏移）**：影响测试用例的语义正确性（T59/T60 测试的实际不是预期错误码）。
4. **C4（clientid 字节数）**：影响 clientid 字段的 wire 编码。

### 6.3 必须返工的问题清单（实现前必须修复）

| 优先级 | 问题编号 | 简要描述 |
|--------|---------|---------|
| P0 | C1 | §2.5 操作码表系统性 off-by-one（11→38）+ LINK 缺失 |
| P0 | C2 | §3.3 NFSv4CompoundOp 字段建模（SETCLIENTID/CREATE/LOCK/CLOSE） |
| P0 | C3 | §2.9 NFSv4 错误码表数值偏移 + 缺失 |
| P0 | C4 | §2.6 clientid 字节数 + RFC 引用错误 |
| P0 | C5 | §3.3 SETCLIENTID 嵌套结构建模 |
| P0 | C6 | §3.3 CREATE 字段建模（删除 createhow） |
| P1 | H1-H9 | HIGH 级问题（含 minorversion 校验、OPEN_CONFIRM 语义、缺失 LINK 测试用例、MSS 分段等） |
| P2 | M1-M8 | MEDIUM 级问题（含 RFC 章节引用系统性错误等） |
| P3 | L1-L6 | LOW 级问题 |

### 6.4 最终结论

**本文档不可以直接进入实现阶段（否）。**

必须先返工的问题编号：
- **P0（必须修复）**：C1, C2, C3, C4, C5, C6
- **P1（建议修复）**：H1, H2, H3, H4, H5, H6, H7, H8, H9
- **P2（可选修复）**：M1, M2, M3, M4, M5, M6, M7, M8
- **P3（后续清理）**：L1, L2, L3, L4, L5, L6

**修复 C1-C6 后**，预计新增/修改测试用例 15-20 个（opcode 修正后所有引用 opcode 的测试用例需更新；clientid 字节数修正后 T42-T45 需更新；错误码值修正后 T59/T60 需更新；CREATE 字段重构后 T26/T35 需更新）。建议在修复 CRITICAL 后再次进行第三轮审计（重点验证 wire 格式字段级正确性）。

---

**文档结束**。

实现者按本文档审计结果修复后，应重新进行第三轮审计（wire 格式 byte-level 验证，使用 RFC 7531 enum 与 struct 定义作为权威依据）。