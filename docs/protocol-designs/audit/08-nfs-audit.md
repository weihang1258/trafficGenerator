# NFS 设计文档对抗审计报告

**审计对象**：`docs/protocol-designs/08-nfs-design.md`（1717 行）
**审计依据**：RFC 7530 (NFSv4.0) / RFC 1813 (NFSv3) / RFC 5531 (ONC RPC) / RFC 5665 (NFSv4.1) / RFC 1094 (NFSv2, 对照) / CLAUDE.md 测试策略 8 条 / `internal/protocol/socks5/socks5.go`（Planner 模式基准）
**审计方法**：独立对抗审计（adversarial audit，与设计者无共享假设）；对每条发现做 RFC 原文核验与文档内部自洽性核验，再按严重度定级
**审计日期**：2026-08-03
**审计结论**：文档结构完整、RFC 引用基本正确，但存在 **2 个 CRITICAL**（NFSv4 状态机与 COMPOUND minorversion 自相矛盾；RPC procedure 字段误用 opcode）与 **7 个 HIGH**（含 1 个 wire 格式表错误、1 个系统性测试断言错误），不建议按当前版本直接进入实现，必须先修复 CRITICAL/HIGH。

---

## 1. 审计概览

### 1.1 审计范围与方法

本次审计覆盖：

1. **RFC 一致性**（维度 1）：RPC 头布局、程序号、procedure/operation 编号、filehandle/stateid/RecordMark 编码，逐项与 RFC 5531 §8/§9/§11、RFC 1813 §2/附录 I、RFC 7530 §14/§18 核对。
2. **扩展表 29 字段覆盖**（维度 2）：`nfsProtRpt`（扩展表 #8）上报字段与设计文档映射关系。
3. **状态机**（维度 3）：NFSv4 会话状态机（EXCHANGE_ID → CREATE_SESSION → COMPOUND × N → DESTROY_SESSION）与 NFSv3 状态机（MOUNT → 操作 → UMOUNT）的协议合法性。
4. **多会话**（维度 4）：M 客户端并发的 4-tuple 与 clientid 唯一性设计。
5. **测试用例质量**（维度 5）：82 条用例按 CLAUDE.md §1-§8 逐条比对。
6. **常见陷阱**（维度 6）：XID 配对、COMPOUND 串行、PUTFH/stateid 前置条件、auth_flavor 取值。

### 1.2 问题统计

| 严重度 | 数量 | 摘要 |
|--------|------|------|
| CRITICAL | 2 | 状态机与 minorversion 自相矛盾；RPC procedure 字段误用 opcode |
| HIGH | 7 | fattr3 长度表错误；MOUNT v3 PATHCHK 幽灵 procedure；测试包计数系统性错误；操作表覆盖率不足；测试引用未定义配置字段；attr_mask 无映射表且示例指向 v4.1 属性；T69 不可实现 |
| MEDIUM | 11 | MountFilehandle 字段缺失；示例字段与结构体不一致；seqid 全局递增违反 per-owner 语义；匿名 stateid 覆盖规则自相矛盾；cookieverf 示例长度错误；MOUNT 同连接承载未声明；opcode 范围三处不一致；v4 procedure=99 违反自身约束；ReplyStatus 机制未定义；OPEN_CONFIRM 缺失未声明；多会话显式 clientid 冲突 |
| LOW | 8 | 特殊 stateid 省略号；CB_COMPOUND 方向标注；SETATTR 匿名 stateid 自相矛盾；扩展表对照缺失；Validate 测试覆盖不完整；示例 base64 不完整；UDP 大载荷越界未限制；Interleave 字段未定义 |
| **合计** | **28** | |

### 1.3 总体评价

**做得好的部分**：

- RPC CALL/REPLY 头部字段顺序（XID → Type → RPCVersion → Program → Version → Procedure → Credentials → Verifier）与 RFC 5531 §8 完全一致（§1.3、§2.1）。
- Program Number 100003 (NFS) / 100005 (MOUNT) 正确；NFSv4 procedure 0/1/2（NULL/COMPOUND/CB_COMPOUND）、NFSv3 procedure 0-21 编号表逐项核对无错。
- NFSv4 operation 3-38 编号表（§2.5）经与 RFC 7530 §18 逐项核对全部正确，无编号错误。
- filehandle 上限（v4=128 / v3=64）、stateid 16 字节（4 seqid + 12 other）、RecordMark 位 31 语义、XDR 4 字节对齐规则均正确。
- 自动补全（MOUNT/UMOUNT/EXCHANGE_ID/DESTROY_SESSION）的"用户已配置则不重复补全"原则（§4.1 规则 1）设计合理，与 socks5 的固定阶段模式思路一致。
- 多会话独立 4-tuple + 独立 XID 序列 + 独立包序号的设计与 socks5 FlowID 模式一致，可复用 `groupIDMeta`/`segmentByMSS` 等既有基础设施（socks5.go L513-520、L776-793）。

**主要风险集中在三处**：

1. **NFSv4.0 与 NFSv4.1 的版本混淆**（C1/C2）—— 这是本文档最严重的问题，牵动状态机、旗舰场景示例与多条测试用例。
2. **wire 格式表错误**（H1 fattr3、H2 PATHCHK、M5 cookieverf 示例）—— 正是 memory 中"LDAP 单测断言过错误嵌套还通过"的同型风险：文档表错了，单测照着文档写也会"通过"。
3. **测试断言与实现可表达性脱节**（H3 包计数、H5 未定义字段、H7 不可实现用例）—— 违反 CLAUDE.md §5（断言可观察值）与 §1（spec 行→测试）。

---

## 2. CRITICAL 问题

### C1. NFSv4 状态机依赖 NFSv4.1 操作（EXCHANGE_ID/CREATE_SESSION/DESTROY_SESSION），但 COMPOUND minorversion 固定为 0，且 §2.5 自声明"39+ 不实现"——文档自相矛盾

**位置**：§2.5（L186-231，尤其 L226-231）、§2.7（L256-265）、§4.1（L535-580）、§6.1（L720-759）、T21/T22/T79（L1399、L1401、L1482）

**问题描述**：

- §4.1 状态机将 `EXCHANGE_ID → CREATE_SESSION → COMPOUND × N → DESTROY_SESSION` 定为 NFSv4 的强制会话流程，并规定 Plan 自动补全（规则 1）。
- §6.1 的旗舰场景用 opcode 41（EXCHANGE_ID）与 42（CREATE_SESSION）作为自动补全/显式配置的目标操作；DESTROY_SESSION 的 opcode 是 43。
- 但 **EXCHANGE_ID(41)、CREATE_SESSION(42)、DESTROY_SESSION(43) 是 NFSv4.1（RFC 5661）才引入的 COMPOUND 内操作**，在 NFSv4.0（RFC 7530）中不存在。RFC 7530 §18 的 opcode 表止于 38（RELEASE_LOCKOWNER），39-62 为保留/后续版本。
- §2.7 明确 COMPOUND 编码中 `minorversion = 0 = NFSv4.0`，且全文只定义了 minorversion=0 一种编码。
- §2.5 自己声明"39-62：NFSv4.1+ ops（本文档不实现）"。

**矛盾链**：状态机要求自动注入 opcode 41/42/43 → 这些 opcode 只在 minorversion=1 的 COMPOUND 中合法 → 文档只定义 minorversion=0 → 按文档生成的真实流量中，服务端会以 `NFS4ERR_OP_ILLEGAL` 拒绝每个 COMPOUND。文档同时违反自己的 §2.5 边界声明。

**RFC 依据**：RFC 5661 §15.31/§15.32/§15.34（EXCHANGE_ID/CREATE_SESSION/DESTROY_SESSION 仅 NFSv4.1+）；RFC 7530 §18（v4.0 无会话机制，只有 SET_CLIENTID/SET_CLIENTID_CONFIRM，L534 文档自己也画了这条"可选路径"但未给出与 EXCHANGE_ID 路径的切换规则）。

**影响**：整个 NFSv4 会话层按当前设计生成的流量在真实服务端（如 Linux knfsd）上必然失败；Wireshark 对 minorversion=0 + opcode 41 的 COMPOUND 也无法正常解析（会显示为 unknown opcode）。这是"成功路径"设计的根基性缺陷。

**修复建议**（二选一，必须明确选择）：

1. **方案 A（v4.0）**：minorversion 保持 0，状态机改用 `SET_CLIENTID → SET_CLIENTID_CONFIRM`（opcode 34/35）替代 EXCHANGE_ID/CREATE_SESSION，去掉 DESTROY_SESSION（v4.0 无会话）；§4.1 的"自动补全 EXCHANGE_ID"改为"自动补全 SET_CLIENTID + SET_CLIENTID_CONFIRM"。
2. **方案 B（v4.1）**：COMPOUND minorversion 设为 1，状态机保留 EXCHANGE_ID/CREATE_SESSION/DESTROY_SESSION；但需同步：§2.5 把 39-62 从"不实现"改为"41/42/43 已实现"、§2.7 补充 minorversion=1 编码说明、以及 CREATE_SESSION 必需的 cb_program/cb_attrs 参数（当前 §6.1 的 CREATE_SESSION 参数只有 clientid+seqid，缺 cb_program 等字段，见 M2）。

文档当前把两套互斥的会话机制画进同一张状态机图（L537-573），且未定义用户配置 SET_CLIENTID（opcode 34）时 Plan 是否还注入 EXCHANGE_ID（规则 1 只检测"已包含 EXCHANGE_ID"，不检测 SET_CLIENTID）——无论选哪套方案，都要先定义检测与互斥规则。

---

### C2. §6.1 场景把 opcode 41/42 误填到 RPC procedure 字段——NFSv4 的 RPC procedure 恒为 1 (COMPOUND)

**位置**：§6.1（L726-743，尤其 L731/L737）、§3.2（L424）、§2.4（L174-184）

**问题描述**：

§6.1 的 Config 示例：

```json
{
  "version": 4,
  "ops": [
    {"procedure": 41, "compound_ops": [{"opcode": 41, "clientid": 0, "owner": "trafficgen-client"}]},
    {"procedure": 42, "compound_ops": [{"opcode": 42, "clientid": 12345, "seqid": 1}]}
  ]
}
```

- §3.2 自己的字段语义写明：`Procedure // NFSv3 proc 编号 / NFSv4 = 1 (COMPOUND)`；§2.4 也写明 NFSv4 只有 3 个 procedure（0 NULL / 1 COMPOUND / 2 CB_COMPOUND）。
- 但 §6.1 示例把 41/42 放进 RPC 头的 Procedure 字段——按此生成，RPC 头 `Program=100003, Version=4, Procedure=41`，服务端会回 `PROC_UNAVAIL`（procedure 41 在 NFSv4 不存在），Wireshark 显示 "Procedure: 41 (unknown)"。
- 41/42 是 **COMPOUND 内部的 opcode**（C1 已述），只能出现在 argarray 的 operation 里，不能出现在 RPC 头。
- 更隐蔽的连带问题：即使把 procedure 改回 1，§6.1 的两个 op 各自带一个 COMPOUND（op1 只含 EXCHANGE_ID，op2 只含 CREATE_SESSION）——这是合法形态（COMPOUND 单操作），但 §6.1 的"关键校验点"（L756-758）说"op1 XID=XIDBase, op2 XID=XIDBase+1"，这没问题；问题在 procedure 字段本身。

**RFC 依据**：RFC 5531 §8（Procedure 字段是"程序内的过程号"）；RFC 7530 §18（NFSv4 程序只有 NULL/COMPOUND/CB_COMPOUND 三个过程）。

**影响**：旗舰场景（也是 T21 的直接输入）生成的流量在 RPC 层即被拒绝。这是可被 Wireshark 立即识别的 wire 格式错误，属于"设计文档把错误当正确示例"的高危类型——实现者照抄示例，测试照抄期望，全部通过。

**修复建议**：§6.1 两个 op 的 `"procedure"` 改为 1；EXCHANGE_ID/CREATE_SESSION 只通过 `compound_ops[].opcode` 表达。同时在 §8.1 审计清单（L1510）加一项："NFSv4 所有 op 的 RPC Procedure 字段必须等于 1"（现有清单 L1510 只说"RPC CALL 头部 7 字段顺序正确"，未含 procedure=1 的校验点）。

---

## 3. HIGH 问题

### H1. §2.8 fattr3 编码表：atime/mtime/ctime 标注"12 bytes"，实际 nfstime3 是 8 字节；行内注释自相矛盾

**位置**：§2.8（L296-299）

**问题描述**：

```
atime (12 bytes)       seconds(4) + nseconds(4) ... 实际 8+8+12+12+12...
mtime (12 bytes)
ctime (12 bytes)
```

- RFC 1813 §2.6：`nfstime3 = { uint32 seconds; uint32 nseconds; }`，**8 字节**。fattr3 三个时间字段各 8 字节。
- 文档标注"12 bytes"，与括号内自己写的"seconds(4) + nseconds(4)"（= 8 字节）直接矛盾；行尾注释"实际 8+8+12+12+12"是一段无意义的残句，无法解读出正确布局。
- fattr3 正确总长：type(4)+mode(4)+nlink(4)+uid(4)+gid(4)+size(8)+used(8)+rdev(8)+fsid(8)+fileid(8)+atime(8)+mtime(8)+ctime(8) = **84 字节**。按文档"12 bytes"实现则每个时间字段多 4 字节，三个字段共多 12 字节，整个 fattr3 布局错位 12 字节，后续字段（乃至整条 reply）全部解析错位。

**RFC 依据**：RFC 1813 §2.6（nfstime3 定义）。

**影响**：wire 格式表错误。这正是 memory 中反复出现的教训类型（LDAP：单测断言过错误嵌套还通过；MPLS：pcap 匿名化致校验和失效）——若测试只按文档表断言字节数，测试会"正确地"通过错误布局。

**修复建议**：改为 `atime (8 bytes) = seconds(4) + nseconds(4)`，删除残句；并建议在测试中直接用真实 pcap（附录 B 已列 NFSv3 场景）的 fattr3 字节做 golden 断言。

---

### H2. MOUNT v3 procedure 表包含 PATHCHK (proc 6)——PATHCHK 是 NFSv2 时代的过程，RFC 1813 附录 I 的 v3 MOUNT 只有 0-5

**位置**：§2.3（L158-172，PATHCHK 在 L170）

**问题描述**：

- §2.3 列出 MOUNT (Program=100005, Version=3) 的 7 个 procedure：0 NULL / 1 MNT / 2 DUMP / 3 UMNT / 4 UMNTALL / 5 EXPORT / 6 PATHCHK。
- RFC 1813 附录 I（MOUNT 协议 v3）只定义 6 个 procedure：NULL(0)、MNT(1)、DUMP(2)、UMNT(3)、UMNTALL(4)、EXPORT(5)。**PATHCHK 是 RFC 1094（NFSv2）MOUNT 协议的 procedure 6，v3 已删除**。
- 文档 L172 自己写"trafficgen 默认只生成 NULL/MNT/UMNT，其余 DUMP/EXPORT/UMNTALL/PATHCHK 留作扩展点"——把不存在的 v3 过程列入"扩展点"，实现者若真按 v3 程序表生成 proc=6 的 call，服务端返回 PROC_UNAVAIL。

**RFC 依据**：RFC 1813 附录 I；RFC 1094 附录 A（PATHCHK 属 v2）。

**影响**：spec 表错误 + 误导性的扩展点声明。轻则实现者困惑，重则实现出无效 procedure。同样属于"文档错误被测试固化"风险。

**修复建议**：从 §2.3 删除 PATHCHK 行；如需保留"扩展点"表述，注明"PATHCHK 仅存在于 MOUNT v2（RFC 1094），本设计不支持 MOUNT v2"。§8.4 的 Validate 清单也应加一条：MOUNT 程序仅支持 proc 0/1/3（实现范围内的合法值）。

---

### H3. 测试用例包计数系统性错误：全部正向用例的期望包数比真实线缆包数少 4；T21 与 T79 自相矛盾

**位置**：§7.2（T21-T32，L1399-1410）、§7.3（T33-T40，L1416-1423）、§5.1（L645-680）

**问题描述**：

先建立文档自身的计数约定。由 §5.1 的包序列可知：每个会话 = TCP 三次握手（3 包）+ 2×RPC往返数（每往返 call+reply 各 1）+ 三次挥手（3 包）= **6 + 2×N 包**（N = RPC 往返数）。但文档所有期望值都满足 **2 + 2×N**，即把握手+挥手 6 包算成了 2 包，每个用例系统性少 4 包：

| 用例 | N（RPC 往返） | 文档期望 | 按 §5.1 真实值 |
|------|--------------|----------|----------------|
| T21 | 2（EXCHANGE_ID+CREATE_SESSION 显式） | 6 | 10 |
| T22 | 4（EXCHANGE+CS+COMPOUND+DESTROY） | 10 | 14 |
| T23-T31 | 4（同上，单 COMPOUND） | 10 | 14 |
| T32 | 6（3 COMPOUND + 3 自动） | 14 | 18 |
| T33/T34/T35/T37/T38 | 3 | 8 | 12 |
| T36 | 2 | 6 | 10 |

（T23-T31 的 N=4 与 T22 相同：ops 数组只有 1 个 COMPOUND，内部 5 个 operation 仍是 1 个 RPC 往返；自动补全 EXCHANGE+CS+DESTROY 共 4 往返。这点文档内部是一致的，错的只是"+2"的基数。）

**T21 的额外矛盾**：T21 期望"6 包"，只计了 2 个往返——即它假设 DESTROY_SESSION 没有被自动追加。但 T79（L1482）规定"user 未配置 DESTROY_SESSION 时 Plan 自动追加"，T21 的输入（[EXCHANGE_ID, CREATE_SESSION]）未含 DESTROY_SESSION，按 T79 应追加 → N=3，按文档自己的约定也应是 8 包。T21 与 T79 直接冲突。同理 §4.1 规则 1（L577）只豁免"用户已显式包含"的操作，DESTROY_SESSION 未豁免。

**影响**：违反 CLAUDE.md §5"断言可观察输出"——包数量是最基本的可观察输出，8 条断言里 8 条错。若测试按文档期望写，测试会与实现一起错（真实包数 10/14/12，断言 6/10/8，实现正确时测试失败，倒逼实现改错；或实现按断言写死包数，管线层丢包）。这也是典型"测试通过但测的是错的"陷阱。

**修复建议**：统一改为 6+2N 并逐条重算；T21 明确"含/不含自动 DESTROY_SESSION"并使其与 T79 一致（建议 T21 显式配置 DESTROY_SESSION 以测试"用户已配置不重复补全"，另加一条用例测自动追加）。

---

### H4. 操作表覆盖率严重不足：NFSv3 22 个 procedure 只测 6 个，NFSv4 36 个 operation 只测 17 个——违反 CLAUDE.md §1

**位置**：§2.2（L129-156）、§2.5（L186-231）、§7.2-7.6（L1395-1467）

**问题描述**：

按 CLAUDE.md §1（"每一行 spec 表都要有至少一个测试"）逐行比对：

**NFSv3 procedure（22 个，0-21）**，有测试的只有 6 个：
- 有测试：1 GETATTR（T33/T37）、3 LOOKUP（T34/T63）、6 READ（T34）、8 CREATE（T35）、12 REMOVE（T35）、17 READDIRPLUS（T36）。
- **零测试（16 个）**：0 NULL、2 SETATTR、4 ACCESS、5 READLINK、7 WRITE、9 MKDIR、10 SYMLINK、11 MKNOD、13 RMDIR、14 RENAME、15 LINK、16 READDIR、18 FSSTAT、19 FSINFO、20 PATHCONF、21 COMMIT。
- 特别注意：**NFSv3 的 WRITE（proc 7）全程无测试**——§6.16.5 的 data 边界测试（T50-T53）和 §5.1 的 MSS 分段规则全部只挂在 v4 WRITE 上，v3 的数据面（含 v3 WRITE 的 stable_how/committed/verf 语义）完全空白。
- MOUNT 协议 7 行（§2.3）只有 MNT(1)/UMNT(3) 有测试；NULL(0) 无、DUMP/UMNTALL/EXPORT/PATHCHK 声明为扩展点但无"扩展点不生成"的负向测试（用户显式配置 proc=2 时行为未定义）。

**NFSv4 operation（36 个，3-38）**，有测试的约 17 个：
- 有测试：4 CLOSE、6 CREATE、9 GETATTR、11 LOCK、13 LOCKU、14 LOOKUP、17 OPEN、21 PUTFH、23 PUTROOTFH、24 READ、25 READDIR、27 REMOVE、28 RENAME、29 RENEW（T61）、31 SAVEFH、33 SETATTR、37 WRITE。
- **零测试（19 个）**：3 ACCESS、5 COMMIT、7 DELEGPURGE、8 DELEGRETURN、10 GETFH、12 LOCKT、15 LOOKUPP、16 NVERIFY、18 OPENATTR、19 OPEN_CONFIRM、20 OPEN_DOWNGRADE、22 PUTPUBFH、26 READLINK、30 RESTOREFH、32 SECINFO、34 SET_CLIENTID、35 SET_CLIENTID_CONFIRM、36 VERIFY、38 RELEASE_LOCKOWNER。
- 尤其讽刺：§4.1 状态机把 SET_CLIENTID → SET_CLIENTID_CONFIRM 画成"可选路径"（L540-549），但全文档没有任何一条用例走这条路径（T57 只测了 Validate 层 clientid=0 合法，没有 Plan 层完整往返测试）——状态机图上的路径与实际测试覆盖脱节。

**影响**：违反 CLAUDE.md §1 的直接后果（历史教训：28 字段 FlowModel 有 6 字段零测试）。实现者会"按表实现 36 个 opcode 的编码器"但 19 个无测试保障；尤其 COMMIT/ACCESS/VERIFY/NVERIFY 这类有独立参数语义的操作，编码错误将无测试拦截。

**修复建议**：按 §2.2/§2.5 每行补至少 1 条 Plan 测试（可合并为"procedure 表全遍历"用例：一个 ops 数组依次覆盖全部 procedure/opcode，断言每条的 opcode 与最小参数编码）；v3 补 WRITE+COMMIT 数据面用例；补 SET_CLIENTID 完整往返用例（呼应 C1 修复方案 A）。

---

### H5. T64-T68 与 §6.17.5-9 引用未定义的配置字段（rpc_accept_state / rpc_reject_state / rpc_mismatch_low / rpc_mismatch_high / auth_stat）——实现者无法按设计实现这些用例

**位置**：§3.2（L414-448，NFSOp 结构体）、§6.17.5-9（L1285-1364）、§7.6（T64-T68，L1462-1466）

**问题描述**：

- §6.17.5 的配置示例使用 `"rpc_accept_state": 4`，§6.17.6 使用 `"rpc_reject_state": 0, "rpc_mismatch_low": 2, "rpc_mismatch_high": 2`，§6.17.9 使用 `"rpc_reject_state": 1, "auth_stat": 1`。
- 但 §3.2 的 NFSOp 结构体只有 20 个字段（Program/ProgVersion/Procedure/Filehandle/Filename/Attributes/Offset/Count/Data/StableHow/Access/Cookie/CookieVerf/DirCount/MaxCount/CompoundOps/Tag/DirPath/ReplyStatus），**没有任何 rpc_\* 字段**。
- §6.17.5 自己写"通过 NFSConfig.RPCError 字段（扩展）"——把实现前提含糊地推给"(扩展)"，但 §3.1 的 NFSConfig 结构体（L382-399）也没有 RPCError 字段；§9（集成点）与 §9.8（扩展点清单）均未定义或登记这些字段。
- 结果：T64-T68 这 5 条异常路径用例（RPC 层错误注入的核心测试）在文档给定的 Config 结构下**不可实现**。实现者只有两个选择：自行发明字段（偏离设计，无 spec 依据，违反 CLAUDE.md §1 的 spec-driven 要求），或跳过这些用例（RPC 层错误路径零覆盖）。

**影响**：设计文档的 Config 层与测试层脱节。RPC 层错误（GARBAGE_ARGS/PROG_MISMATCH/PROC_UNAVAIL/AUTH_ERROR）是 §1.4 边界"成功路径为主"之外最有价值的负向测试面，失去它们则 RPC 层错误注入完全没有测试。

**修复建议**：在 §3.2 NFSOp 明确增加 5 个字段（`RPCAcceptState *uint32`、`RPCRejectState *uint32`、`RPCMismatchLow/High *uint32`、`AuthStat *uint32`，指针语义=未设置走默认成功路径），在 §3.5 补字段语义，并同步 §9.8 移除"(扩展)"含糊表述。

---

### H6. GETATTR 的 attr_mask 无"属性名→bitmap"映射表，且四个场景示例 [0,0,0x1000] 指向 NFSv4.1 属性（attr 76）——按示例生成的 GETATTR 在 v4.0 下非法

**位置**：§6.2（L776）、§6.7（L945）、§6.9（L1005）、§6.14（L1128/L1133）、§3.3（L468，AttrMask 字段）

**问题描述**：

- NFSv4 的 attrmask 是 `bitmap4`：uint32 数组，attr N 落在 word N/32 的第 N%32 位。`[0, 0, 0x1000]` = word 2 bit 12 = **attr 76**。
- RFC 7530（v4.0）只定义 attr 0-55（§18.2），56-63 保留，64+ 是 NFSv4.1（RFC 5661 §5.8）才定义的属性。attr 76 在 v4.0 下不存在。
- 文档没有任何"属性名 → word/bit"对照表。用户想"GETATTR 拿 mode/size"（§6.9 场景意图明显是查 SETATTR 改过的属性），需要自己手算：FATTR4_MODE=33 → word 1 bit 1（0x00000002）；FATTR4_SIZE=4 → word 0 bit 4（0x00000010）。文档四处理想当然地复用同一个 `[0, 0, 0x1000]`，无一正确表达"查属性"的意图。
- 按 §2.7 的 minorversion=0 编码（C1 修复前的现状），v4.0 服务端对含未支持属性位的 GETATTR 返回 NFS4ERR_INVAL（RFC 7530 §18.9：请求中任何未支持的属性位导致操作失败）。文档自称"只生成成功路径"（§1.4 规则 1），但示例本身就是失败路径。

**RFC 依据**：RFC 7530 §18.2（属性编号表）、§18.9（GETATTR）；RFC 5661 §5.8（64+ 属性属 v4.1）。

**影响**：所有含 GETATTR/READDIR 的示例场景（6.2/6.7/6.9/6.14，对应 T22/T28/T30/T31）在真实服务端全部失败；用户无映射表可依，只能猜 bitmap。属"文档示例即错误"高传播风险。

**修复建议**：新增"附录：常用属性名→attr 号→bitmap word/bit 对照表"（至少 SUPPORTED_ATTRS=0、TYPE=1、SIZE=4、FSID=8、FILEID=20、MODE=33、OWNER=36、OWNER_GROUP=37、TIME_MODIFY=53），示例全部改为合法值（如 mode: [0, 0x00000002, 0]），并在 Validate 层对 AttrMask 做"非零 word 不得超出 v4.0 范围"的软校验（或文档明示不做校验但测试断言具体 word/bit）。

---

### H7. T69（COMPOUND 中途失败：第 2 个 operation 失败）在给定结构体下不可实现——失败注入只能到 NFSOp（整个往返）粒度

**位置**：§7.6（T69，L1467）、§3.3（L450-479，NFSv4CompoundOp 结构体）、§2.7（L267-277，COMPOUND reply 语义）

**问题描述**：

- T69 输入："compound_ops=[OK op, FAIL op, OK op], reply_status 在第 2 op 失败"，期望"resarray 长度=2（后续不执行）"。
- 但失败注入字段 `ReplyStatus` 定义在 **NFSOp**（§3.2，L446：一个 RPC 往返）上，NFSv4CompoundOp（§3.3）没有任何 status/reply 控制字段。一个 COMPOUND 往返内 3 个 operation 只能共享同一个 NFSOp.ReplyStatus——无法表达"只有第 2 个 operation 失败"。
- §2.7 正确描述了 RFC 语义（op 失败后 oparray 只含已执行部分、COMPOUND 顶层 status=失败码），但文档没有给出实现该语义所需的 per-operation 失败注入机制。

**影响**：T69 是"COMPOUND 串行语义"的唯一负向测试（CLAUDE.md §2 要求的失败路径），不可实现则 COMPOUND 中途失败语义（oparray 截断）零覆盖——这正是 CLAUDE.md 历史教训"e2e 从不注入坏 spec"的反向变体。

**修复建议**：给 NFSv4CompoundOp 增加 per-op status 字段（如 `OpStatus *uint32`），并定义规则：op i 的 OpStatus≠0 时，COMPOUND 顶层 status 取该值，oparray 只含 0..i。补一条"第 2 op 失败"实现后即可测试；同时补"顶层 status 与单 op status 的关系"说明（见 M9）。

---

## 4. MEDIUM 问题

### M1. §4.2 规则 2 引用 `NFSConfig.MountFilehandle` 字段，但 §3.1 结构体没有该字段

**位置**：§4.2（L616）、§3.1（L382-399）

**问题描述**：规则 2 说"trafficgen 生成的 MOUNT reply 用 NFSConfig.MountFilehandle（默认全 0x01，16 字节）"。§3.1 的 NFSConfig 字段列表（Version/Transport/AuthFlavor/AuthSys/XIDBase/XIDIncr/Ops/Sessions/SessionsSrcPortBase/SessionsSrcPortStep/ResultStatus/Direction）中不存在 MountFilehandle。实现者要么发明字段，要么默认值不可配置——"默认全 0x01、16 字节"又恰好没有 Validate 边界测试（65+ 字节的 MOUNT fh 场景无法构造）。同型问题：§6.10 校验点"MOUNT reply 的 fh3 长度 ≤ 64"的测试对象（超长配置）不存在。

**修复建议**：在 NFSConfig 增加 `MountFilehandle []byte`（默认 16×0x01），Validate 限 ≤64，并补 T12 同型的 MOUNT fh 超长用例。

### M2. §6.x 场景示例使用结构体未定义的字段（claim / openhow / owner 类型不匹配 / CREATE objtype）

**位置**：§6.3（L813-815）、§6.4（L854）、§6.5（L885）、§3.3（L450-479）

**问题描述**：

- §6.3 的 OPEN 配置含 `"claim": {"type": "null"}`——NFSv4CompoundOp 无 Claim 字段；OPEN 的 openhow（OPEN4 args 的 open_how4 联合）也无字段，openhow 默认值未定义。
- §6.1 的 EXCHANGE_ID 用 `"owner": "trafficgen-client"`（字符串），而 §3.3 的 Owner 类型是 `*NFSLockOwner{Clientid, Owner []byte}`——类型不匹配，且 EXCHANGE_ID 的 owner 语义是 nfs_client_id4{verifier, id}，与 NFSLockOwner 根本不是一个结构。
- §6.4 的 OPEN 完全省略 owner 与 claim——RFC 7530 §18.16 中 OPEN4args 的 owner（open_owner4）与 claim（open_claim4 联合）是必填字段，省略后 Plan 用什么默认值、Validate 是否报错，文档未定义。
- §6.5 的 CREATE 未提供 objtype（CREATE4args 的 ftype4 联合）与 createhow（createhow4 联合）——同样无默认值定义。

**影响**：所有 v4 有状态操作（OPEN/CREATE）的示例都无法直接映射到结构体；联合类型（openhow/claim/createhow/objtype/locker）的 XDR 编码全文无定义，实现者只能查 RFC 自行发挥，且无 spec 依据（违反 CLAUDE.md §1）。

**修复建议**：NFSv4CompoundOp 增加 Claim/OpenHow/ObjType/CreateHow 字段（或明确定义"省略=UNCHECKED4+CLAIM_NULL"默认规则并在 Validate 补校验）；§6.1 的 owner 改走新字段语义；在 §2.5 或附录补"联合类型编码参考"。

### M3. §4.1 规则 4"OPEN/CLOSE/LOCK/LOCKU 的 seqid 全局单调递增"违反 RFC 7530 的 per-state-owner seqid 语义

**位置**：§4.1（L580）、§6.3（L836）、§6.8（L986-988）

**问题描述**：

- RFC 7530 §8.2.2/§8.2.5/§8.2.8：seqid 是**按 state-owner 独立**的计数器——open-owner 有自己的 OPEN/CLOSE/OPEN_DOWNGRADE 序列，lock-owner 有自己的 LOCK/LOCKU 序列。服务端按 (owner, stateid) 校验 seqid 连续性。
- 文档规则 4 把四个操作并入"单 clientid 下单调递增"的单一序列。§6.8 的示例正是后果：OPEN seqid=1（open-owner 序列到 1）→ LOCK seqid=1（lock-owner 序列到 1）→ LOCKU seqid=2（lock-owner 到 2）→ CLOSE seqid=3（open-owner 序列变成 1→3，**跳过了 2**）。按 RFC 7530 §8.2.5，CLOSE 的 seqid 必须是该 open-owner 上一次 OPEN seqid+1=2，服务端会对 seqid=3 的 CLOSE 返回 NFS4ERR_BAD_SEQID。
- 同理 §6.3：OPEN seqid=1 → CLOSE seqid=2，恰好碰对（因为中间没有其它 open-owner 操作），但这只是"全局递增恰好等于 per-owner 递增"的特例，L460/L476 的结构体把 Seqid 设计成单字段，实现上无法表达 per-owner 独立性。

**影响**：LOCK 场景（§6.8/T29）生成的是真实服务端会拒绝的 seqid 序列。文档自称"成功路径"但此例即失败路径。

**修复建议**：规则 4 改为"按 owner 维护独立 seqid 序列：OPEN/CLOSE 同 open-owner 递增，LOCK/LOCKU 同 lock-owner 递增"；§6.8 示例的 CLOSE seqid 改 2；测试 T29 断言各 owner 序列值。

### M4. §4.1 规则 3（全 0 stateid 自动替换为 OPEN reply stateid）与 §6.16.2（全 0 = 合法匿名 stateid）自相矛盾

**位置**：§4.1（L579）、§6.16.2（L1188-1193）、§6.3（L835）

**问题描述**：

- §6.16.2 明确：全 0 stateid 是 RFC 7530 §8.1.4 定义的**匿名 stateid**，用于 READ/WRITE 合法；T48 也断言"OK (匿名)"。
- §4.1 规则 3 却规定"OPEN 后跟 READ 且 READ 的 stateid 全 0 时，Plan 自动用 OPEN reply 的 stateid 替换"。全 0 是用户**显式表达**的匿名访问意图，规则 3 把它悄悄改写，与 §6.16.2 直接冲突；且"OPEN reply 的 stateid"是 Plan 自己合成的 reply 里的值——该值从哪来（用户配置？随机？）、OPEN reply stateid 与 READ 的 stateid 一致性如何保证，全文未定义。
- 连带：CLOSE 的 stateid 同样要求是 OPEN 返回的 open stateid（§6.3 示例两个 op 都用"AAAAAAAAAAAAAA==" 全 0），按规则 3 会被替换，但替换值来源不明。

**影响**：规则 3 与匿名 stateid 合法性的语义边界混乱；实现者无法确定"什么时候替换、替换成什么"。匿名 READ 是 §6.3 场景的显式配置，被规则 3 静默改写后用户预期（匿名）与生成流量（具名）不符。

**修复建议**：删除规则 3，改为"stateid 一致性由用户负责（§1.4 规则 5 已声明），Plan 只做透传"；或定义明确机制：OPEN reply stateid 由用户配置（如 `OpenReplyStateid` 字段）并在后续 op 引用，全 0 永不自动改写。

### M5. §6.13 的 cookie_verf 示例 "AAAAAAAAAAAAAAAA" 解码为 12 字节，而 cookieverf3 是 8 字节；且 v4 READDIR 无 cookieverf 配置字段

**位置**：§6.13（L1105）、§3.2（L434，CookieVerf [8]byte 在 NFSOp 上）、§3.3（L450-479，NFSv4CompoundOp 无 CookieVerf）

**问题描述**：

- cookieverf3 = opaque[8]（RFC 1813 §2.6）。8 个零字节的 base64 是 `"AAAAAAAAAAA="`（12 字符）；`"AAAAAAAAAAAAAAAA"`（16 字符）解码为 **12 字节**，超长。
- 更实质的问题：CookieVerf 字段只存在于 NFSOp（v3 用），**NFSv4CompoundOp 没有 cookieverf 字段**——v4 READDIR（opcode 25）的参数（RFC 7530 §18.25：cookie + cookieverf + dircount + maxcount + attrmask）在结构体层面无法配置 cookieverf，恒为全 0。§6.7 自己承认"call 中可全 0"，但全 0 cookieverf 并非协议默认——服务端对 READDIR 返回的 cookieverf 必须被后续 READDIR 原样回传，否则返回 NFS4ERR_NOT_SAME。合成流量的零值 cookieverf 在真实服务端上属于"碰运气"。

**影响**：v3 示例的字段值 wire 长度错误；v4 READDIR 参数缺字段。两者都无测试覆盖（READDIR 用例只断言"reply 含 entries"）。

**修复建议**：示例改为 `"AAAAAAAAAAA="`；NFSv4CompoundOp 增加 CookieVerf 字段；文档明示"cookieverf 全 0 是合成流量的简化，真实服务端可能拒绝"（列入 §9.8 已知偏离）。

### M6. NFSv3 的 MOUNT/UMOUNT 与 NFS 操作被设计成同一 TCP 连接、同一端口（2049）——真实 NFSv3 客户端中 MOUNT 走独立通道（rpcbind/mountd，端口 635）

**位置**：§4.2（L582-617）、§6.10（L1018-1050，8 包单会话）、§9.8（L1655-1664，已知偏离清单无此条）

**问题描述**：

- 真实 NFSv3：客户端先经 rpcbind（111）查 mountd 端口（通常 635），在**独立的 TCP 连接**上完成 MNT 取得 fh3，再在**另一条连接**（2049）上做 NFS 操作；UMOUNT 同样走 mountd 连接。
- 文档把 MOUNT + GETATTR + UMOUNT 设计成一条 4-tuple（端口 2049）上的 3 个 RPC 往返（T33 期望 8 包）。真实 mountd 不监听 2049，此流量在真实环境必然失败。
- 作为合成流量，单连接承载多程序在 RPC 层是合法的（每条 RPC 自带 Program 号，Wireshark 可解析），但文档**未声明这是与真实 NFSv3 客户端行为的有意偏离**，§9.8 的已知偏离清单也未登记。实现者/用户会误以为这是真实行为。

**影响**：文档的"真实性"承诺（附录 B 参考真实 pcap）与单连接设计矛盾；用户按文档理解抓包对比真实客户端时会困惑。

**修复建议**：§1.4 或 §9.8 明示偏离："MOUNT/UMOUNT 与 NFS 共用同一 TCP 连接是 trafficgen 的合成简化；真实 v3 客户端使用独立 mountd 连接（端口 635，经 rpcbind 发现）"。可选：设计 MOUNT 子流（socks5 UDP 中继的子流模式可参考）。

### M7. opcode 合法范围三处表述不一致：§2.5"3-38"、§3.5"3-38，39+ 不报错"、T15 错误消息"must be 3-62"

**位置**：§2.5（L228-231）、§3.5（L523）、T15（L1388）、T16（L1389）

**问题描述**：

- §2.5："3-38：NFSv4.0 操作；39+：本文档不实现但 Validate 不报错"。
- §3.5："Opcode 范围：3-38。39+ 不报错但生成时 opcode 直接写入"。
- T15 的期望错误消息："error: invalid opcode (must be 3-62)"——上限 62 与"3-38"矛盾（62 不是任何版本的合法 opcode 上限；v4.1 到 44、v4.2 到 49）。
- T16 说 opcode=39 OK，与"must be 3-62"兼容但与"3-38"矛盾。没有 opcode 63+/负值/0 的测试。
- 同一份文档内实现者无法确定 Validate 的边界写死为 38、62 还是其它值。

**影响**：Validate 边界语义漂移，T15 的断言与 §3.5 冲突时测试会失败（或实现按错误消息实现而偏离设计）。

**修复建议**：统一为"3-38 合法；39-62 允许（透传）；63+ 报错"（v4.1 最大 opcode 44、v4.2 49，62 是…若选 62 需注释依据）；修正 T15 消息；补 opcode=0/63 的负向用例。

### M8. §6.17.7 用 version=4 + procedure=99，违反 §3.2 自己定义的"NFSv4 procedure = 1 (COMPOUND)"

**位置**：§6.17.7（L1323-1334）、§3.2（L424）

**问题描述**：T66/PROC_UNAVAIL 场景配置 `{"version": 4, "procedure": 99, ...}`。§3.2 明确 NFSv4 的 Procedure 只能是 1（COMPOUND）。按该配置，Validate 是否应报错？文档未定义 v4 procedure≠1 的校验；若 Validate 不校验，则 C2 的 procedure 误用问题（EXCHANGE_ID 场景）也无法被 Validate 拦截——两者是同一校验的缺失。PROC_UNAVAIL 的合理构造方式应该是 **v3**（procedure 22，超出 0-21）而非 v4。

**修复建议**：Validate 增加"v4 时 NFSOp.Procedure 必须为 0 或 1（0=NULL，1=COMPOUND）"；§6.17.7 改用 v3 procedure=22。

### M9. ReplyStatus/ResultStatus 与 COMPOUND 顶层 status、单 op status 的关系未定义——T59 期望顶层 status=10003 的机制缺失

**位置**：§3.1（L412）、§3.2（L446）、§2.7（L267-277）、§6.17.1（L1221-1238）

**问题描述**：

- §2.7 正确描述：COMPOUND reply 有顶层 status（L271）与每个 op 的 op_status（L273）两个层级。
- §3.1/§3.2 的 ResultStatus/ReplyStatus 只声明"reply 在 NFS 层返回该错误码"，未定义它作用于哪个层级：单 op 失败时，顶层 status 是否也置为该错误码？oparray 中失败 op 的 op_status 是否等于该码？后续 op 的 op_status 是"不返回"还是"返回成功"？
- §6.17.1（T59）期望"reply status=10003、resarray 长度=1"——隐含顶层 status=10003，但没有任何规则说明这是 ReplyStatus 的机制产物。多 op COMPOUND 配 ReplyStatus（如 T69 相关配置）时语义完全悬空。

**影响**：实现者无从确定 reply 合成规则；T59-T62 的断言"reply NFS status=xxx"可被多种实现满足（顶层/op 层），测试无法锚定行为。违反 CLAUDE.md §5（断言可观察值但可观察值定义缺失）。

**修复建议**：在 §2.7 补三条规则：(a) 单 op COMPOUND：op_status 与顶层 status 均取 ReplyStatus；(b) 多 op COMPOUND：ReplyStatus 只作用于最后一个 op 的 op_status 与顶层 status，oparray 截断至该 op；(c) ResultStatus 同 (b) 但对所有 op。并在测试中分别断言顶层与 op 层两个字段。

### M10. v4.0 的 OPEN 流程缺 OPEN_CONFIRM——文档全程无此操作且未列入已知偏离

**位置**：§6.3（L798-838）、§6.4（L839-868）、§6.8（L958-988）、§9.8（L1655-1664）

**问题描述**：

- RFC 7530 §18.16/§18.19：NFSv4.0 中，客户端对**新的 open-owner** 执行首次 OPEN 后，必须用 OPEN_CONFIRM 确认（服务端返回 delegation 的情况除外），确认前 open state 不可用于 READ/WRITE；未确认的 OPEN 状态在服务端会过期。
- 文档所有 OPEN 场景（6.3/6.4/6.8）都是 OPEN → READ/WRITE/LOCK → CLOSE，无 OPEN_CONFIRM（opcode 19）。合成流量在 Wireshark 层面可解析（Wireshark 不校验该语义），但真实服务端（Linux knfsd 在 v4.0 模式）会对未确认 state 的 READ 返回 NFS4ERR_BAD_STATEID。
- 若选择方案 B（v4.1），则 OPEN_CONFIRM 在 v4.1 已删除、无此问题——所以此问题与 C1 的修复方案绑定。但文档当前（v4.0 假设 + 无 OPEN_CONFIRM）的组合是失败的，且 §9.8 未登记此偏离。

**影响**：OPEN 场景自称"成功路径"实际是服务端拒绝路径；与 H3（包计数）叠加，OPEN 场景的可观察行为在文档中无一正确。

**修复建议**：选方案 A（v4.0）时在 OPEN 后自动补 OPEN_CONFIRM（opcode 19，带 open_stateid+seqid），或在 §9.8 明示偏离；选方案 B（v4.1）时在 §2.5 注明"19 OPEN_CONFIRM 为 v4.0 专用，v4.1 不生成"。

### M11. 多会话的 clientid 唯一性规则与用户显式 clientid 冲突；EXCHANGE_ID owner 每会话区分未定义

**位置**：§4.3（L636-641）、§6.15（L1152-1176）、§6.1（L733）

**问题描述**：

- §4.3 规则 3："独立 clientid：每会话 clientid 不同（默认按 session 序号偏移）"——但偏移只作用于**默认值**。用户若在 ops 里显式配置 clientid（如 §6.1 的 12345、§6.3 OPEN owner 的 12345），Sessions>1 时所有会话共用同一 clientid，规则 3 的"独立性"失效。
- 更深一层：NFSv4 语义中，**同一 clientid 本来就可以跨多条 TCP 连接**（一个客户端、一个 clientid、多条连接是 v4.1 的常态——EXCHANGE_ID 的 owner 相同即视为同一客户端）。设计把"每会话 clientid 必须不同"当规则，反而制造了与真实语义的偏离，且未声明。
- EXCHANGE_ID 自动补全时（T22 等），每个会话的 EXCHANGE_ID owner 字符串是否区分（如 "trafficgen-client-1"、"trafficgen-client-2"）未定义；若 owner 相同而 clientid 不同，服务端视为同一客户端跨连接（可接受），若意图是"M 个不同客户端"，owner 必须不同——设计意图（"模拟多客户端并发"§6.15）与实现机制（owner 未区分）不符。

**影响**：多会话场景（T41-T45、T72/T77）的核心断言"3 个独立 clientid"在显式配置下不可满足；"多客户端"语义名不副实。

**修复建议**：定义 (a) 显式 clientid 是否参与会话偏移（建议：op 内 clientid=0 视为"按会话分配"，非 0 视为显式并校验跨会话不重复）；(b) 自动 EXCHANGE_ID 的 owner 每会话追加序号；(c) §6.15 校验点"3 个独立 clientid"改为"3 个独立 (owner, clientid) 对"。

---

## 5. LOW 问题

### L1. §2.6 特殊 stateid 写为"0x01000000..."（省略号），未给出精确 12 字节

**位置**：§2.6（L252）

**问题描述**：RFC 7530 §8.1.4 定义了精确的特殊 stateid（seqid=0，other 为特定 12 字节值）。文档以省略号结尾，实现者无法按文档编码；且 §6.16.2 的边界测试只覆盖全 0 与长度异常，未覆盖特殊 stateid 的精确字节断言。

**修复建议**：写出完整 12 字节（可注明十六进制与十进制两种写法），并补一条"特殊 stateid 编码"断言测试。

### L2. §2.4 CB_COMPOUND 的方向标注为 "call/reply"——CB_COMPOUND 是服务端发起的 call

**位置**：§2.4（L182）

**问题描述**：CB_COMPOUND（procedure 2）是**服务端→客户端**的回调通道过程（RFC 7530 §18.5），方向应为"server→client call"（文档 §1.4 已声明不实现回调通道）。方向列标"call/reply"与其 own 的"方向"列语义（该列其它行表示 call 方向）不符，易误导。

**修复建议**：改注"（回调通道，本设计不生成）"。

### L3. §6.9 的 SETATTR 使用全 0 stateid，与 §6.16.2"匿名 stateid 仅 READ/WRITE 合法"自相矛盾

**位置**：§6.9（L1005）、§6.16.2（L1188-1193）

**问题描述**：§6.16.2 明确匿名 stateid 的合法用途是"匿名 READ/WRITE"；§6.9 的 SETATTR（opcode 33，必带 stateid 参数）示例却用全 0。文档内部矛盾：按 §6.16.2，该配置是非法输入，Validate 是否拦截、生成流量是否被服务端拒绝，均未定义。

**修复建议**：SETATTR 示例改用 OPEN 返回的 stateid（与 M4 的机制联动），或在 §6.16.2 补充"SETATTR 用全 0 stateid 的后果"说明。

### L4. 缺少"扩展表 #8 (nfsProtRpt) 上报字段对照"章节

**位置**：全文（对照：13-modbus-design.md §9.4、17-a2a-design.md 均有"与扩展表对照"表）

**问题描述**：文档头部声明"未实现协议清单节点：nfsProtRpt (扩展表 #8)"，但正文没有像 modbus 设计（§9.4：协议名/端口/事务数/功能码分布/异常码分布/Unit ID 分布→来源）那样的上报字段映射表。扩展表要求的字段（协议版本分布、操作类型分布、procedure 分布、错误码分布、会话数等）哪些由 NFSConfig/Plan 输出直接可得、哪些需要新增聚合逻辑（如按 opcode 计数），均无来源映射。实现完 Planner 后上报模块无从下手。

**修复建议**：新增"扩展表对照"小节，逐字段列来源（如：版本分布→Ops[].ProgVersion；操作分布→按 NFSOp.Procedure/NFSv4CompoundOp.Opcode 计数；错误码分布→ReplyStatus/ResultStatus 配置值；会话数→Sessions）。

### L5. Validate 测试（T01-T20）按 CLAUDE.md §1 逐行核对仍有缺口

**位置**：§7.1（L1370-1393）

**问题描述**：§3.1 声明"Validate 拒绝 0/1/2/5/6"，但 T02 只测了 version=2，0/1/5/6 无测试；auth_flavor 只测 0/1/6，未测 2-5/7+ 等其它非法值；opcode 上限（63+，见 M7）无测试；NFSOp.Program 非法值（如 7）、prog_version 与 version 不匹配（v3 配 prog_version=4）、v4 配 Program=100005（MOUNT 程序配 v4）、auth_sys 的 machinename 超长（XDR string 上限）、direction 非法值（§3.1 有 Direction 字段但无任何校验测试）均无覆盖。

**修复建议**：按 §3.1/§3.5/§8.4 的每一条校验规则逐条补负向用例。

### L6. §6.4/§6.9 示例中的 stateid 值 "AAAA..." 不是完整 base64

**位置**：§6.4（L855）、§6.9（L1005）

**问题描述**：`"other": "AAAA..."` 带省略号，不是可解码的 base64 字符串；与 §6.3 的完整值 "AAAAAAAAAAAAAAAAAAAAAA=="（12 字节全 0）风格不一致。文档示例声称可运行，但这两处无法直接使用。

**修复建议**：统一为完整 base64（12 字节全 0 = "AAAAAAAAAAAAAAAAAAAAAA=="）。

### L7. v3+UDP 传输下 data 大小无上限约束——1MB WRITE 超过 UDP 数据报上限（65507 字节）

**位置**：§5.2（L682-693）、§6.16.5（L1208-1214）、T53（L1446）

**问题描述**：§6.16.5 的 1MB data 用例（T53）标注"~715 段"，隐含 TCP 分段；但 T39 允许 v3+UDP，UDP 场景下 RPC 消息不分段（§5.2"整个 payload 单个 UDP 包"），1MB data 的 WRITE 在 UDP 下生成 1MB 的 UDP 数据报——超过 UDP 最大载荷 65507，无法在线缆上传输。Validate 对"transport=udp 时 op 内 data/Count 上限"无校验、无文档说明。

**修复建议**：Validate 或 §5.2 增加"udp 传输时 RPC 消息 ≤ 65507 字节"约束（并拒绝超限配置），测试补一条"v3+udp+大 WRITE → Validate 报错"。

### L8. §4.3 规则 4 引用 `Interleave=true` 配置，但 NFSConfig 无 Interleave 字段

**位置**：§4.3（L641）、§3.1（L382-399）

**问题描述**：与 M1 同型的"引用未定义字段"：规则 4 说"会话间不交错（除非用户配置 Interleave=true，留作扩展）"，但结构体无此字段，扩展点清单（§9.8）也未登记。

**修复建议**：删除该从句或加入 §9.8 扩展点登记。

---

## 6. 字段覆盖率审计（扩展表 29）

### 6.1 审计说明

扩展表 #8（`nfsProtRpt`，规范 9.4.1.38 协议扩展信息上报）要求每个扩展协议上报一组统计字段（参照同项目 modbus 设计 §9.4 的对照格式：协议名/端口/事务数/功能码分布/异常码分布等）。该扩展表的 29 个字段本体不在仓库内，本次按"设计文档是否提供可推导来源"审计。

### 6.2 逐维度覆盖结论

| 扩展表维度（推断） | 文档来源 | 覆盖结论 |
|--------------------|----------|----------|
| 协议名/节点名 | 头部声明 `nfsProtRpt`（L6） | 覆盖 |
| 端口 | 2049（L5），v3 可 UDP | 覆盖 |
| 传输层 | Transport 字段（tcp/udp） | 覆盖 |
| 协议版本分布 | `Version`（3/4）+ `ProgVersion`（默认 3/4） | 覆盖 |
| procedure/opcode 分布 | §2.2/§2.3/§2.4/§2.5 全表 + Ops[].Procedure + NFSv4CompoundOp.Opcode | **覆盖（表完整）** |
| 错误码分布 | §2.9 全表 + ResultStatus/ReplyStatus | 部分覆盖（NFS 层错误码全，RPC 层错误注入字段未定义，见 H5） |
| 会话/连接数 | `Sessions` | 覆盖 |
| 流量方向分布 | `Direction`（默认 up） | 覆盖（但无校验测试，见 L5） |
| 数据量/事务数 | Ops 数量 × Sessions | 可推导 |
| 上报映射表 | **无** | **缺失**（见 L4） |

### 6.3 结论

版本/procedure 覆盖维度（审计任务维度 2 的核心）**设计文档覆盖完整且编号正确**——§2.2 的 22 个 v3 procedure、§2.5 的 36 个 v4 operation 经逐项 RFC 核对无编号错误。但"扩展表上报字段 → 实现来源"的映射表缺失（L4），且 procedure 覆盖的**完整性只在编号层面**成立——测试层只覆盖 6/22（v3）与 17/36（v4）（H4）。结论：**编号表合格，测试覆盖不合格，上报映射缺失**。

---

## 7. 测试用例质量审计（CLAUDE.md §1-§8 逐条）

### 7.1 按规则逐条审计

**§1（spec 驱动）**：**FAIL**。§2.2 表 22 行只测 6 行、§2.5 表 36 行只测 17 行（H4）；§2.3 MOUNT 表 7 行只测 2 行；§3.1 的 Direction 字段零测试（L5）；§2.9 错误码表 30+ 行只测 6 个错误码（T59-T63）。

**§2（失败路径）**：**部分通过**。T59-T69 覆盖了 11 条 NFS/RPC 错误路径，方向正确；但其中 T64-T68 引用未定义字段（H5）、T69 不可实现（H7）、§6.17.7 的输入违反自身约束（M8）——3/11 的异常用例无法按设计实现。

**§3（测对函数/路径）**：**FAIL**。状态机的 SET_CLIENTID 路径（§4.1 图示）零测试（H4）；v4 数据面（MSS 分段）测了而 v3 数据面（proc 7 WRITE）零测试（H4）；XID 配对只测 v4 场景（T73），v3 多往返 XID 递增（§6.10 校验点）无独立测试。

**§4（集成测试）**：**部分通过**。T70-T82 是合格的跨层集成清单（TCP→RPC→NFS→teardown、多会话 resequencer、XID 配对）；但 §7.7 的集成用例全部是"验证点"描述而非具体输入/断言，T72/T77 依赖 H3 的错误包计数。

**§5（断言可观察输出）**：**FAIL**。包计数断言系统性错误（H3，8 条正例全错）；T22/T28/T30 断言"10 包"而真实 14；T21 与 T79 冲突。T41-T45 的多会话断言（FlowID/SrcPort）方向正确但 clientid 断言依赖未定义机制（M11）。

**§6（并发正确性）**：**部分通过**。T41-T45+T72+T77 覆盖了多会话隔离与独立计数，符合"测量聚合可观察行为"的要求；但会话内（单 flow）无并发，NFS 本身无共享速率组件，此项风险低于其它协议。

**§7（失败测试先行）**：N/A（设计文档阶段，但实现时必须为 H1/H2/H3/H5/H7 的修复先写失败测试——这些正是最容易"实现照着文档错"的点）。

**§8（测试质量对抗评审）**：**FAIL**。已发现：包计数错（H3）、示例配置不可实现（H5/H7/M2）、示例值长度错（M5）、示例字段缺失（M2/M5）、示例违反自身约束（M8/C2）——测试用例表中含"正确性未知或错误"的断言超过 15 条。

### 7.2 用例统计表核对

§7.8 的算术（20+12+8+5+13+11+13=82）无误，但"82 ≥ 30"的达标声明只满足数量阈值，不满足质量阈值：按上述审计，**82 条中约 24 条存在断言错误、不可实现或依赖未定义机制**（T21/T22/T23-T31/T33-T38 包计数；T64-T68 字段缺失；T69 不可实现；T41/T45 clientid 机制缺失；T53 缺 UDP 边界）。

---

## 8. 多会话场景正确性

### 8.1 设计正确之处

- 每会话独立 4-tuple（SrcPort 从 base 递增 step）、独立 XID 序列、独立 PacketIndex、独立 FlowID（格式与 socks5 一致）——多会话包序号与 resequencer 隔离的机制成立（T41-T44/T72/T77）。
- 自动补全（EXCHANGE_ID/CREATE_SESSION/DESTROY_SESSION/MOUNT/UMOUNT）按会话独立执行、不跨会话共享状态，符合"多会话 = 多独立流"的定位（§1.4 规则 6）。
- XID 每会话从 XIDBase 独立递增（§4.3 规则 2），不会跨会话碰撞，reply echo 语义（§2.1）与 T73 一致。

### 8.2 问题汇总（详见前文）

1. **显式 clientid 与规则 3 冲突**（M11）：用户显式配置的 clientid 不参与会话偏移，Sessions>1 时跨会话重复。
2. **"多客户端"语义名不副实**（M11）：EXCHANGE_ID 自动补全时 owner 字符串每会话是否区分未定义——若相同 owner，服务端视为同一客户端的多连接（真实 NFSv4 语义本就允许），与 §6.15"模拟多客户端并发"的意图不符。
3. **v4.1 会话机制未定**（C1）：多会话流程本身建立在 EXCHANGE_ID/CREATE_SESSION 之上，C1 不修复则多会话测试全部无效。
4. **UDP 多会话边界**（L7）：Sessions>1 + v3 + UDP 的源端口分配未定义边界。

### 8.3 结论

多会话的**传输层隔离**设计正确且与既有实现模式（socks5）一致；但**会话身份层**（clientid/owner 的分配与唯一性）存在 M11 的机制缺口，且整体依赖 C1 的版本决策。修复 C1 与 M11 后，多会话场景可以成立。

---

## 9. 总体评分

### 9.1 各维度评分

| 维度 | 得分（/10） | 说明 |
|------|------------|------|
| RFC 一致性（编号/布局） | 7 | 编号表全部正确，但 fattr3 长度表错（H1）、PATHCHK 幽灵过程（H2）、minorversion 与 opcode 体系矛盾（C1） |
| 扩展表 29 字段覆盖 | 4 | 版本/procedure 编号覆盖完整，但无上报映射表（L4） |
| 状态机 | 3 | v4 状态机建立在 v4.1 操作 + v4.0 minorversion 的矛盾组合上（C1）；v3 状态机基本成立但 MOUNT 同连接偏离未声明（M6） |
| 多会话 | 5 | 传输层隔离正确（8.1），会话身份层有缺口（M11） |
| 测试用例质量 | 3 | 82 条数量达标，约 24 条存在断言错误/不可实现/依赖未定义机制（§7.2）；违反 CLAUDE.md §1/§2/§3/§5/§8 |
| 可实现性（Config→Plan 映射） | 4 | 多处示例引用未定义字段（H5/H7/M1/M2/L8），结构体与场景示例脱节 |
| **总体** | **4.3 / 10** | **不可直接进入实现** |

### 9.2 问题总数与严重度分布

- **总数：28**
- CRITICAL：2（C1 版本体系自相矛盾、C2 procedure 字段误用）
- HIGH：7（H1 fattr3 表错、H2 PATHCHK、H3 包计数系统性错、H4 操作表测试覆盖不足、H5 测试引用未定义字段、H6 attr_mask 无映射且示例非法、H7 T69 不可实现）
- MEDIUM：11（M1-M11）
- LOW：8（L1-L8）

### 9.3 修复优先级建议

1. **P0（实现前必须）**：C1（版本决策 + 状态机重写）、C2（procedure 修正）、H1（fattr3 表）、H2（PATHCHK 删除）、H3（包计数全部重算 + T21/T79 对齐）。
2. **P1（与实现同步）**：H5（RPC 错误注入字段入结构体）、H6（attr_mask 映射表 + 示例修正）、H7（per-op status 字段）、M1/M2/M5/M8（结构体字段补齐）、M9（reply 合成规则）。
3. **P2（测试完善）**：H4（操作表全遍历用例）、M3/M4/M10/M11（seqid/stateid/OPEN_CONFIRM/clientid 语义修正）、L1-L8。
4. **P3（文档补充）**：L4（扩展表上报映射）、§9.8 已知偏离清单补登（M6/M10/M5 的 cookieverf 简化）。

**最终结论**：文档骨架与编号体系扎实（这决定了修复成本可控），但版本体系自相矛盾与测试断言系统性错误使其当前状态不合格。按 P0 → P1 → P2 顺序修复并逐条补失败测试后，可进入实现；实现完成后必须用附录 B 的真实 pcap + Wireshark 做字段级终审（遵循"tshark 是最终裁判"的项目经验）。
