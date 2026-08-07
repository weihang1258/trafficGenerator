# 08-nfs-design.md 复审报告（r4, v2.0.3）

**审计对象**：`/home/weihang/trafficGenerator/docs/protocol-designs/08-nfs-design.md`（v2.0.3，2392 行）
**规范**：RFC 7530/7531 (NFSv4.0)、RFC 1813 (NFSv3)、RFC 5531 (ONC RPC)、RFC 5661 (v4.1 对照)
**审计方式**：全文分段通读（4×600 行）+ 15 个 HexDump 逐字节核算（脚本验证全部偏移与 RM）+ 逐项核对 v2.0.2→v2.0.3 修订记录（§11.9 与正文一一对应）+ RFC 原文核实（RFC 7531 §3/§5.2 open_claim4/openflag4/createhow4/fattr4/COMPOUND4args/COMPOUND4res、RFC 1813 §2.5/§3.3.2/§3.3.3/§3.3.16/§3.3.17 LOOKUP3resok/READDIR3resok/dirlist3/sattr3/time_how/writeverf3、RFC 5531 §8 call_body/accepted_reply/rejected_reply/authsys_parms、RFC 7530 §16.18.4/§16.34）
**结论**：**否（不能直接进入实现阶段）。**

## 一、总体结论

v2.0.3 的 15 项修复（5 CRITICAL + 3 HIGH + 4 MEDIUM + 3 LOW）经逐项 RFC 原文核对**全部正确落地**：

- **C-1**（恢复 S12 CLAIM_NULL 的 component4 file）：RFC 7531 §5.2 原文 `case CLAIM_NULL: component4 file;` 非 void，S12 已恢复 file 字段（len @ 0078 + 'f' @ 007C + pad，至 0x7F），S12 全偏移按新核算重排，CALL RM=0x80000124（292B）经逐字节脚本核算完全正确。
- **C-2**（删除 S9 外层 eof）：RFC 1813 §3.3.16/§3.3.17 原文核实 `READDIR3resok = post_op_attr + cookieverf3 + dirlist3`、`dirlist3 = entries<> + eof`，只有内层一个 eof。S9 已删除外层 eof，entries length @ 0080、eof @ 0084 正确。
- **C-3**（S11 补 attr_vals 长度前缀）：RFC 7531 §3 `attrlist4 = typedef opaque attrlist4<>;` 变长带 4 字节长度前缀。S11 已补 `attr_vals length=12` @ 0048，size @ 004C-0053、mode @ 0054-0057，REPLY 总长 84=0x54、RM=0x80000054 核算正确。
- **C-4**（S4 LOOKUP3resok 顺序）：RFC 1813 §3.3.3 原文核实 fh 在前。S4 已重排为 object（fh_len+fh_data）@ 0020-0027 → obj_attributes（判别+fattr3）@ 0028-007F → dir_attributes @ 0080，总长 128B 核算正确，T-037 已含顺序断言。
- **C-5**（openhow 改 opentype4 判别）：RFC 7531 §5.2 原文核实 `union openflag4 switch (opentype4 opentype)`。S12 已改为 opentype=1 @ 0064 + createmode=0 @ 0068 + createattrs（bitmap_len 0 + attr_vals_len 0）@ 006C-0073 共 16 字节，T-082~T-084 断言同步，NFSOpenHow 定义完整（含 "nocreate" 分支）。
- **H-1**（T-033 time_how 统一为 1）：T-033 已改 set_atime=01，§3.4 注释补映射规则，与 §2.8 自洽。
- **H-2**（T-155 10025=0x2729）：T-155 已改为 00002729，§2.7 补低 32 位说明。
- **H-3**（T-080/T-081 补分支字段断言）：T-080 已断言 delegate_stateid4 16B + file；T-081 已断言 file_delegate_prev。§3.3.1 NFSClaim 注释完整。
- **M-1~M-4、L-1~L-3**：全部正确落地（T-163 语义、§4.3 reply clientid、S12 OPEN reply stateid 说明、T-074 bitmap 回显断言、§11.1 表述统一、§2.9 错误码补全、S2/S4/S5 表述统一）。

但本次复审仍发现 **8 个新问题：0 CRITICAL + 1 HIGH + 3 MEDIUM + 4 LOW**。

---

## 二、HIGH（1 个）

### H-1. NFSv3 多参数 procedure 的 Config 字段缺失——RENAME/LINK/SYMLINK/MKNOD 的 args 无法表达

**位置**：§3.2 NFSOp（行 510-552）+ §2.2 表（行 138-143）+ T-054/T-055/T-058/T-059（行 1633-1637）。

**描述**：RFC 1813 中以下 NFSv3 procedure 需要**多个**参数，但 §3.2 NFSOp 只有单个 Filehandle + 单个 Filename：

| procedure | RFC 1813 参数 | 文档 Config 字段 | 缺口 |
|-----------|--------------|------------------|------|
| RENAME (14) | `from (fh) + fromwhat (name) + to (fh) + towhat (name)` | Filehandle×1 + Filename×1；Oldname/Newname 标注为 v4 字段 | **缺 to fh（第二个 dirfh）**；old_name/new_name 无 v3 映射说明 |
| LINK (15) | `filehandle + link_dirfh + link_name` | Filehandle×1 + Filename×1 | **缺 link_dirfh**；link_name 无字段 |
| SYMLINK (10) | `dirfh + name + symlink (path) + sattr3` | Filehandle + Filename + Attributes | **缺 symlink 目标路径字段** |
| MKNOD (11) | `dirfh + name + ftype + sattr3 + devdata` | Filehandle + Filename + Attributes | **缺 ftype / devdata 字段** |

T-054 输入 `target:"/target"`、T-055 输入 `mode:0x2060`（MKNOD）、T-058 输入 `old_dirfh, old_name, new_dirfh, new_name`、T-059 输入 `link_dirfh, link_name`——这些输入在 §3.2 中**没有对应 Config 字段**。实现者面对 T-058/T-059 无法知道第二个 dirfh 从哪个字段取、old_name/new_name 用 Filename 还是 Oldname 表达（Oldname/Newname 的注释"RENAME"位于 §3.3 NFSv4CompoundOp，是 v4 字段）。

**依据**：RFC 1813 §3.3.10 (SYMLINK3args)、§3.3.11 (MKNOD3args)、§3.3.14 (RENAME3args)、§3.3.15 (LINK3args)。

**影响**：按文档实现 v3 RENAME/LINK/SYMLINK/MKNOD 时，planner 无法确定 args 编码（缺字段定义），或实现者凭猜测编码导致 wire 错误。测试用例与 Config 结构脱节（违反 CLAUDE.md §Testing Policy 规则 1：测试必须与 spec 对应）。

**修复建议**：§3.2 NFSOp 增加 v3 专用字段：`LinkDirFh []byte`（LINK 的 link_dirfh）、`SymlinkTarget string`（SYMLINK 的 symlink path）、`Ftype uint32` + `Devdata []byte`（MKNOD）、并明确 v3 RENAME 的 to fh/to name 字段（如复用 Filehandle2/Name2 或新增 FromFh/ToFh），同时更新 T-054/055/058/059 的输入与 §2.2 表注释。

---

## 三、MEDIUM（3 个）

### M-1. S14 的 RM 数值错误——RM(len=64) 与自身偏移自相矛盾

**位置**：§6 S14（行 1505 `RM (len=64)`、行 1519-1520 VerfFlavor @ 003C / VerfLen @ 0040、行 1522 NFS payload @ 0044）。

**描述**：S14 标注 `RM=0x80000040 (len=64)`，但按文档自身偏移核算：CALL 消息（不含 RM）= XID(4)+Type(4)+RPCVer(4)+Prog(4)+Ver(4)+Proc(4)+CredFlavor(4)+CredLen(4)+CredBody(24)+VerfFlavor(4)+VerfLen(4) = **64 字节恰好到 0x40**——即 VerfLen 字段自身占据 0x40-0x43，NFS body 从 0x44 起。消息总长 = 0x44 + len(NFS body) ≥ 0x44+12（COMPOUND body 最少 tag 4 + minorversion 4 + argarray 4）= **80 字节**。RM len=64 意味着"消息共 64 字节、NFS body 为空"，与 NFS body @ 0x44 的标注直接矛盾。S14 是 version=4 的 COMPOUND（Procedure=1），NFS body 至少 12 字节，RM 至少应为 0x80000050。

**影响**：实现者按 S14 的 RM 标注计算 RecordMark 会少算 ≥16 字节，TCP 流解析错位。S14 是 AUTH_SYS 演示场景，错误仅在此场景的 RM 标注，但会误导实现与测试断言。

**依据**：RFC 5531 §11.B 记录标记语义 + 文档自身 S14 偏移行（CredBody 24B @ 0024-003B、VerfFlavor @ 003C、VerfLen @ 0040、NFS body @ 0044）。

**修复建议**：S14 RM 改为 `0x80000050`（len=80，含最小 COMPOUND body 12B）并附核算说明，或注明"NFS body 未展开，RM 按实际 COMPOUND body 计算"。

### M-2. S9 的 RM 核算文字算术错误——24+4+88+8+4+4=132≠128

**位置**：§6 S9（行 1269）。

**描述**：行 1269 写"RPC reply 头 24 字节 + status 4 + post_op_attr 88 + cookieverf3 8 + entries length 4 + eof 4 = **128 字节 = 0x80**（payload 含 RM 共 132 字节，HexDump 止于 0x0088）"。实际 24+4+88+8+4+4 = **132**。且"payload 含 RM 共 132 字节"也不对：payload（不含 RM）=132、含 RM=136、HexDump 止于 0x0088 与 eof @ 0084+4B=0x88 自洽。数字 128/0x80 与 132 并存，是复制 S4 核算（S4 确实 =128）时未改全。S9 的 HexDump 行本身正确（eof @ 0084、止于 0x0088）。

**影响**：实现者按文字核算"128 字节"会少算 4 字节；T-059a/T-059b 断言"内层唯一 eof @ 0084"正确未受影响，但 RM 类断言若参照此文字会错。

**依据**：S9 HexDump 自身偏移（cookieverf3 @ 0078 + 8B → entries @ 0080 → eof @ 0084 → 止于 0x88 = 136 字节含 RM）。

**修复建议**：行 1269 改为 "= **132 字节 = 0x84**（payload 含 RM 共 136 字节，HexDump 止于 0x0088）"。

### M-3. T-110 与 §4.1 规则 3 冲突——open_seqid=1 与 OPEN_CONFIRM 补全矛盾

**位置**：§7.4 T-110（行 1700）+ §4.1 规则 3（行 789）+ S12 说明（行 1380）。

**描述**：T-110 输入 `compound_ops:[OPEN, LOCK{..., open_to_lock_owner:{open_seqid:1, ...}}]`。按 §4.1 规则 3，OPEN 的 open-owner 是首次出现（同一 COMPOUND 内）→ Plan 自动补 OPEN_CONFIRM → open-owner 序列变为 OPEN=1 → OPEN_CONFIRM=2 → CLOSE=3，LOCK 的 open_seqid 应为 **2**。S12 场景已明确"若 user 配置 open_seqid=1，与补全后的 open-owner 序列冲突，Validate 报错"。T-110 的输入 open_seqid=1 与这条规则直接矛盾：按规则实现，T-110 输入会触发 Validate 报错而非生成 LOCK 字节。

**影响**：T-110 作为正例测试，输入与规则冲突。实现者要么让 T-110 失败（按规则报错），要么绕过规则（T-110 通过但 S12 的校验失效）。v2.0.2 H-7 同类问题（S12 与规则冲突）已修复，T-110 是漏网的同型矛盾。

**依据**：§4.1 规则 3（自动补全适用于所有新 open-owner 首次 OPEN）、S12 说明行 1380（open_seqid=1 → Validate 报错）、T-110 输入行 1700（open_seqid:1）。

**修复建议**：T-110 的 open_seqid 改为 2（与 S12 一致），或显式声明"本用例的 OPEN 已由 user 配置跳过补全场景（不适用规则 3）"并说明机制。

---

## 四、LOW（4 个）

### L-1. 匿名 stateid 的字节标注错误——other 12 字节标"共 16 字节"

**位置**：§2.6（行 272）。

**描述**：匿名 stateid 行写"精确字节：`00 00 00 00 00 00 00 00 00 00 00 00`（共 16 字节）"——反引号内是 **12 个零字节**（other 部分），标注"共 16 字节"把 seqid（4B）+ other（12B）混淆；且与下一行 READ bypass 的写法（"seqid `FF FF FF FF` + other `FF...`（12 个），合计 16 字节"）格式不一致，匿名行缺 seqid 部分。wire 上 stateid4 是 seqid(4B)+other(12B)=16 字节，匿名 = `00 00 00 00` + 12×`00`。

**影响**：实现者若按反引号内字节数（12）编码会缺 4 字节；但 T-131 断言（seqid=00000000；other=12×00）正确，此处仅为 §2.6 文字标注错误。

**修复建议**：改为"精确字节：seqid `00 00 00 00` + other 12×`00`，合计 16 字节"（与 READ bypass 行格式统一）。

### L-2. T-143 的 filename 长度断言错误——"文件.txt" UTF-8 是 10 字节非 6 字节

**位置**：§7.5 T-143（行 1738）。

**描述**：T-143 输入 filename="文件.txt"，断言"filename len=6；data=E6 96 87 E4 BB B6 2E 74 78 74"。UTF-8 编码："文件"=6 字节（E6 96 87 + E4 BB B6）、".txt"=4 字节（2E 74 78 74），共 **10 字节**。hex data 列了 10 字节但 len 标 6——两者自相矛盾。len 应为 `0000000A`。

**影响**：按 len=6 断言实现的测试必失败，或实现者反向输出错误长度前缀导致 wire 错位。

**依据**：UTF-8 编码核算（"文件"各 3 字节 + ".txt" 4 字节 = 10）。

**修复建议**：T-143 断言改为"filename len=0000000A（10 字节）"，data hex 不变。

### L-3. S2 标题笔误——"filehandle=4 字节 0x01"应为 1 字节

**位置**：§6 S2 标题（行 1000）。

**描述**：标题写"filehandle=4 字节 0x01"，但 Config `filehandle:"AAE="` 解码为 **1 字节** 0x01（行 1002 自己也写"filehandle=1 字节 0x01"），HexDump fh len=1、3 字节 padding。标题"4 字节"是笔误（可能与其他场景的 4 字节 fh 混淆）。

**影响**：仅标题文字误导，正文与 HexDump 正确。

**修复建议**：标题改为"filehandle=1 字节 0x01"。

### L-4. OPEN 的 share_access/share_deny 无 Validate 范围校验

**位置**：§8.3（V19-V23 之间无 share 校验）+ §3.3 NFSv4CompoundOp（ShareAccess/ShareDeny 字段）+ T-087~T-089（行 1672-1674）。

**描述**：RFC 7530 §16.17.2 OPEN4 share_access 枚举合法值 1=READ/2=WRITE/3=BOTH、share_deny 合法值 0=NONE/1=READ/2=WRITE。文档无 Validate 规则校验（V23 只校验 StableHow），T-087~089 只有正例（1/3/2），无负例（share_access=0/4、share_deny=3）。按 CLAUDE.md §Testing Policy 规则 2（覆盖失败路径），缺非法值负例。

**影响**：实现者可不校验 share 值直接写字节，非法值（如 share_access=0）wire 上无意义但测试全绿。

**修复建议**：§8.3 新增 V 规则（share_access 仅 1/2/3、share_deny 仅 0/1/2），补 T 负例。

---

---

## 五、v2.0.3 修复正确性核对（15 项逐项，依据 RFC 原文）

| r3 编号 | v2.0.3 修复 | 核对结果 |
|---------|------------|----------|
| C-1 | 恢复 S12 CLAIM_NULL 的 component4 file，全偏移重排，RM=0x80000124 | ✅ 正确（RFC 7531 §5.2 原文核实；S12 逐字节脚本核算 292B/0x124 完全吻合：LOOKUP @ 0038、OPEN @ 0044-007F、OPEN_CONFIRM @ 0080-0097、LOCK @ 0098-00DF、LOCKU @ 00E0-010B、CLOSE @ 010C-0123） |
| C-2 | 删除 S9 外层 eof，保留内层 eof @ 0084 | ✅ 正确（RFC 1813 §3.3.16/§3.3.17 原文核实 dirlist3 唯一 eof；T-059a/T-059b 已删双 eof 断言） |
| C-3 | S11 补 attr_vals 长度前缀，RM 0x50→0x54 | ✅ 正确（RFC 7531 §3 attrlist4 变长 opaque 核实；S11 REPLY 84B/0x54 核算吻合，size @ 004C、mode @ 0054） |
| C-4 | S4 LOOKUP3resok 重排 fh→obj_attributes→dir_attributes | ✅ 正确（RFC 1813 §3.3.3 原文核实；S4 总长 128B 核算吻合；T-037 顺序断言已补） |
| C-5 | openhow 改 opentype4 判别 + createhow4（含 createattrs） | ✅ 正确（RFC 7531 §5.2 openflag4/createhow4 原文核实；S12 openhow 块 16B、T-082~T-084 断言同步） |
| H-1 | T-033 time_how 统一（未提供→1） | ✅ 正确（§2.8/§3.4/T-033 三方自洽） |
| H-2 | T-155 10025=0x2729 | ✅ 正确（10025=0x2729 核实；T-170 同值） |
| H-3 | T-080/T-081 补分支字段字节断言 | ✅ 正确（delegate_stateid4 16B + file 字节已断言） |
| M-1 | T-163 low/high 语义 + §1.3 互斥说明 | ✅ 正确 |
| M-2 | §4.3 reply clientid 合成规则 | ✅ 正确（与 §10.4 对齐） |
| M-3 | S12 OPEN reply stateid 合成说明 | ✅ 正确（§9.5 #2 引用完整） |
| M-4 | T-074 bitmap 回显断言（含尾部 0 word） | ✅ 正确 |
| L-1 | §11.1 "40 字节头"统一表述 | ✅ 正确 |
| L-2 | §2.9/§9.3 补 NFS4ERR_DELAY/NOT_SAME | ✅ 正确 |
| L-3 | S2/S4/S5 fattr3 "84B/88B"表述统一 | ✅ 正确 |

**核对统计**：15 项全部 ✅ 正确，无反向修复、无值错误。

---

## 六、HexDump 自洽性总检

| 场景 | 长度核算 | RM | 结论 |
|------|----------|-----|------|
| S1 CALL | 40B | 0x28 | ✅ |
| S1 REPLY | 24B | 0x18 | ✅ |
| S2 CALL | 40+8=48B | 0x30 | ✅（仅标题"4 字节"笔误，见 L-3） |
| S2 REPLY | 24+4+88=116B | 0x74 | ✅ |
| S3 CALL | 40+8+28+4=80B | （未标） | ✅ sattr3 28B + sattrguard3 @ 004C 正确 |
| S4 CALL | 40+8+12=60B | （未标） | ✅ |
| S4 REPLY | 24+4+8+88+4=128B | 0x80 | ✅ 顺序 fh→attrs→dir_attrs 正确（C-4） |
| S5 CALL | 40+8+8+4=60B | （未标） | ✅ |
| S5 REPLY | 24+4+88+4+4+12=136B | （未标） | ✅ count @ 0078 正确 |
| S6 CALL | 40+8+8+4+4+12=76B | （未标） | ✅ |
| S6 REPLY | 24+4+92+4+4+8=136B | （未标） | ✅ count @ 007C、verf @ 0084 正确 |
| S7 CALL | 40+8+12+28=88B | （未标） | ✅ |
| S7 REPLY | 24+4+12+88+92=220B | （未标） | ✅ dir_wcc @ 0084、止于 0xE0 正确 |
| S8 CALL | 60B | （未标） | ✅ |
| S8 REPLY | 24+4+92=120B | （未标） | ✅ |
| S9 CALL | 40+8+8+8+4+4=72B | （未标） | ✅ |
| S9 REPLY | 24+4+88+8+4+4=132B | 0x84 | ⚠️ HexDump 行正确（eof @ 0084、止于 0x88），**但核算文字写 128/0x80 错误**（M-2） |
| S10 CALL | 60B | （未标） | ✅ |
| S10 REPLY | 24+4+92+8=128B | （未标） | ✅ verf @ 007C 正确 |
| S11 CALL | 40+36=76B | 0x4C | ✅ |
| S11 REPLY | 24+28+32=84B | 0x54 | ✅ attr_vals_len @ 0048 正确（C-3） |
| S12 CALL | 40+252=292B | 0x124 | ✅ 全偏移逐字节核算吻合（C-1/C-5） |
| S13 | 多会话表 | — | ✅ 4-tuple/clientid 表自洽 |
| S14 CALL | RPC 头含 cred 64B + NFS body | 0x40 | ❌ **RM 与偏移自相矛盾**（M-1）：VerfLen @ 0x40、NFS body @ 0x44，消息 ≥80B，RM 应 ≥0x50 |
| S15 REPLY | 24+20=44B | 0x2C | ✅ 截断规则正确 |

---

## 七、测试用例与 CLAUDE.md §Testing Policy 合规性

**整体评价**：v2.0.3 的 200+ 用例结构良好——r3 报告的测试问题（T-033 矛盾、T-155 值错、T-080/081 断言不全、T-082~084 模型错误）全部修复；负向测试约 25 条（T-011/012/026/028/040/047a/050/065/068/108/133~136/141/149/175/181~184/199 等）、边界值（T-016/017/120/142/187~190）、集成路径（T-191~200）覆盖完整。

**不符合项**：

1. **T-143 断言值错误（规则 5：断言可观察输出）**：filename len=6 与实际 UTF-8 10 字节矛盾（L-2）。
2. **T-110 输入与规则冲突（规则 1：spec 驱动）**：open_seqid=1 与 §4.1 规则 3 的 OPEN_CONFIRM 补全矛盾，按规则实现该用例必失败（M-3）。
3. **v3 多参数 procedure 无 Config 字段（规则 3：每个代码路径）**：T-054/055/058/059 的输入（target/ftype/link_dirfh/双 fh）无字段表达，实现时测试与 spec 脱节（H-1）。
4. **share_access/share_deny 无负例（规则 2：覆盖失败路径）**：T-087~089 只有正例，非法值（share_access=0/4）无测试（L-4）。
5. **T-110 的 open_seqid 断言缺失**：T-110 期望列只断言"LOCK opcode；locker4 new_lock_owner=01"，未断言 open_seqid 值——即使实现错误输出 open_seqid=1 测试也通过。

---

## 八、其他复核要点（未发现问题的项）

1. **OPEN_CONFIRM seqid 规则**：RFC 7530 §16.18.4 原文核实"sequence id passed to OPEN_CONFIRM must be 1 greater than the seqid passed to OPEN"，§4.1 规则 3 完全一致。
2. **SETCLIENTID_CONFIRM**：RFC 7530 §16.34 原文核实 clientid + verifier4 参数，文档正确。
3. **RPC 头部布局**：RFC 5531 §8 call_body/accepted_reply/rejected_reply 原文核实，文档 §1.3 完全一致（含 PROG_MISMATCH low/high 附带字段、MSG_DENIED 分支互斥）。
4. **AUTH_SYS 编码**：RFC 5531 §9.2 authsys_parms 原文核实（stamp/machinename/uid/gid/gids<16>），S14 字节正确（仅 RM 标注错，见 M-1）。
5. **writeverf3 定长 opaque[8] 无长度前缀**：RFC 1813 §2.5 原文核实，S6/S10 正确。
6. **wcc_data 92B 结构**：pre_op_attr 判别 + post_op_attr 判别 + fattr3 84B，与 RFC 1813 一致。
7. **sattr3 判别联合**：RFC 1813 §2.5 原文核实（set_mode3/set_atime 判别联合、time_how 0/1/2 语义），S3/S7 + §2.8 + T-029~T-035 完全一致，是本文档最扎实的部分。
8. **COMPOUND CALL/REPLY 非对称**：RFC 7531 §5.2/§15.2.3 原文核实，文档 §2.7 正确。
9. **opcode 表**：38=WRITE、39=RELEASE_LOCKOWNER、40=WANT_DELEGATION、41=BIND_CONN_TO_SESSION、42=EXCHANGE_ID、43=CREATE_SESSION、44=DESTROY_SESSION 与 RFC 5661 一致。
10. **S12 的 seqid 序列**：open-owner OPEN=1→OPEN_CONFIRM=2→CLOSE=3、lock-owner LOCK=1→LOCKU=2 与 RFC 7530 §8.2 按 owner 独立维护一致。
11. **错误码 hex**：10018=0x2722、10019=0x2723、10020=0x2724、10025=0x2729、10027=0x272B 全部核算正确。
12. **S12 的 LOOKUP "f" 后 OPEN CLAIM_NULL "f"**：CURRENT_FH 是文件而非目录（真实服务端会 NFS4ERR_NOTDIR），合成流量不模拟真实服务端可接受，但建议在 §9.5 已知偏离中登记（未发现为阻塞项）。

---

---

## 九、修复优先级建议

**必须修复（阻塞实现）**：

1. **H-1**：§3.2 NFSOp 补齐 v3 多参数 procedure 的字段（RENAME 双 fh 双名、LINK link_dirfh、SYMLINK target、MKNOD ftype/devdata），同步 T-054/055/058/059 输入。**这是唯一阻塞项**——其余问题均不涉及 wire 格式，属文字/数值/测试输入错误。

**建议修复（高优先级）**：

2. **M-1**：S14 RM 0x80000040 → 0x80000050（或注明按实际 COMPOUND body 计算）。
3. **M-2**：S9 行 1269 核算文字 128/0x80 → 132/0x84（含 RM 136B）。
4. **M-3**：T-110 open_seqid 1 → 2（与 S12/§4.1 规则 3 一致）。

**可选**：

5. **L-1**：§2.6 匿名 stateid 字节标注补 seqid 部分。
6. **L-2**：T-143 filename len 6 → 10。
7. **L-3**：S2 标题"4 字节"→"1 字节"。
8. **L-4**：§8.3 补 share_access/share_deny 范围校验 + T 负例。

**修复后复核要求**：H-1 新增字段后需为 v3 RENAME/LINK/SYMLINK/MKNOD 各补一个字节级 HexDump 场景（或至少 CALL args 展开），并核对 T-054/055/058/059 的断言与字段映射一一对应。

---

## 十、问题汇总

**共 8 个问题：0 CRITICAL + 1 HIGH + 3 MEDIUM + 4 LOW**

| 严重度 | 编号 | 位置 | 摘要 |
|--------|------|------|------|
| HIGH | H-1 | §3.2 NFSOp | v3 RENAME/LINK/SYMLINK/MKNOD 多参数 procedure 缺 Config 字段（双 fh、link_dirfh、target、ftype/devdata），T-054/055/058/059 输入无法表达 |
| MEDIUM | M-1 | §6 S14 | RM=0x80000040 与自身偏移矛盾（VerfLen @ 0x40、NFS body @ 0x44，消息 ≥80B，RM 应 ≥0x50） |
| MEDIUM | M-2 | §6 S9 | RM 核算文字 24+4+88+8+4+4 写成 128/0x80，实际 132/0x84（HexDump 行本身正确） |
| MEDIUM | M-3 | §7.4 T-110 | open_seqid=1 与 §4.1 规则 3（OPEN_CONFIRM 补全后 open_seqid=2）+ S12 的"open_seqid=1 报错"规则矛盾 |
| LOW | L-1 | §2.6 | 匿名 stateid 反引号内 12 字节标"共 16 字节"，缺 seqid 部分 |
| LOW | L-2 | §7.5 T-143 | "文件.txt" UTF-8 为 10 字节，断言 len=6 与 data hex 自相矛盾 |
| LOW | L-3 | §6 S2 | 标题"filehandle=4 字节"应为 1 字节（正文/HexDump 正确） |
| LOW | L-4 | §8.3/T-087~89 | OPEN share_access/share_deny 无 Validate 范围校验、无非法值负例 |

**15 项修复核对**：15 项全部正确（5C+3H+4M+3L 无一反向修复、无一值错误）。对比 r3（25 项中 3 项错误 + 2 项部分），v2.0.3 的修复质量显著提升，且 §11.9 已固化"以 RFC 原文为准"的修复流程教训。

---

## 十一、最终结论

**否（不能直接进入实现阶段）。**

v2.0.3 修复了 r3 报告的全部 15 个问题且质量扎实（全部经 RFC 原文核实），wire 格式层面已无 CRITICAL/HIGH 错误。但存在 **1 个 HIGH（v3 多参数 procedure 的 Config 字段缺失）** 会阻塞实现：NFSv3 的 RENAME/LINK/SYMLINK/MKNOD 四个 procedure 的 args 无法从现有 Config 结构表达，planner 无法确定编码。其余 3 MEDIUM + 4 LOW 为数值/文字/测试输入错误，修复成本低。

修复 H-1（补字段）+ M-1/M-2/M-3（改数值）后即可进入实现阶段。建议按 §9 优先级顺序修复，并补 v3 多参数 procedure 的 CALL args 字节级场景。
