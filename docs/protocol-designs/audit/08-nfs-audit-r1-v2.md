# 08-NFS 设计文档复审报告（r1-v2）

**审计对象**：`/home/weihang/trafficGenerator/docs/protocol-designs/08-nfs-design.md`（v2.0.0，约 2133 行）
**规范**：RFC 7530 (NFSv4.0) / RFC 7531 (NFSv4.0 XDR) / RFC 1813 (NFSv3) / RFC 5531 (ONC RPC) / RFC 4506 (XDR)
**审计日期**：2026-08-05
**审计员**：独立审计代理
**方法**：逐节对照 RFC 核对 + 逐字节核算全部 HexDump 的 RM 长度自洽性 + 全表数值回算（opcode/错误码/偏移/base64）+ 按 CLAUDE.md §Testing Policy 8 条规则评估测试用例

---

## 审计结论摘要

| 严重度 | 数量 |
|--------|------|
| CRITICAL | 7 |
| HIGH | 6 |
| MEDIUM | 7 |
| LOW | 5 |
| **合计** | **25** |

**最终结论：否（不能直接进入实现阶段）。** v2.0.0 确实修复了 v1 的 RPC 头偏移（§1.3 布局与 RFC 5531 §8 一致，本次复审确认）、COMPOUND 编码顺序（tag→minorversion→argarray→ops 正确）、stateid4 定长 12 字节、clientid4 uint64、FHSIZE 区分（64/128）、NOFILEHANDLE=10020、错误码表（RESOURCE=10018 / MOVED=10019 / BAD_STATEID=10025 均正确）。但本次复审发现**一批新的系统性错误**：

1. **NFSv4 opcode 表整体错位（CRITICAL）**：RFC 7530/7531 中 WANT_DELEGATION 在 NFSv4.0 **不存在**，opcode 38=WRITE、39=RELEASE_LOCKOWNER；文档却插入 WANT_DELEGATION=38 并把 WRITE 移到 39、RELEASE_LOCKOWNER 移到 40。这是全文档性的 off-by-one，波及 §2.5 表、§3.3 注释、§7 测试、§10.2 元数据，实现者照抄必错。
2. **全部 HexDump 的 RM（Record Mark）长度系统性少算 12–16 字节（CRITICAL）**：文档把 RPC 头当成 24 字节（只算 XID..Procedure），漏掉 CredFlavor/CredLen/VerfFlavor/VerfLen 四个 uint32。实测每个场景的偏移行与其自报 RM 长度自相矛盾（偏移行用的是正确的 40 字节头）。
3. **REPLY 偏移约定自相矛盾（CRITICAL）**：§7.1 测试头声明 AcceptState @ 28-2B，但 RFC 5531 与 §6 全部 HexDump（AcceptState @ 0x18=24）都正确，§7.1 声明错了 4 字节；且 §7.1 的 VerfBody=24 与「空 verifier 时 AcceptState=24」冲突。
4. **writeverf3 / verf4 编码错误（CRITICAL）**：RFC 1813 writeverf3 与 RFC 7531 verf4 都是 `opaque[8]`（8 字节定长，**无长度前缀**），文档 S6/S10 却画成「4 字节长度 + 8 字节 verf」。
5. **S9 READDIR reply 缺少 cookieverf3 字段（CRITICAL）**：RFC 1813 readdir3resok = dir_attributes + **cookieverf3** + entries + eof；文档 reply 缺 8 字节 cookieverf3。
6. **多会话 clientid 表格自相矛盾（HIGH）**：§10.4 公式 `uint64(0x10000)*i + 1` 对 session 0 得 0x10001（文档自己注释也是 0x0000000000010001），但 §4.3 示例写「session 0 clientid=0x10000+1、session 1=0x20000+1」（多乘了 2），S13 表格又写 session 1=0x0000000000010002、session 2=0x0000000000010003。三处三样，相互矛盾。
7. **测试用例大量复读文档自身错误值，形成「自证」闭环（HIGH）**：T-001/T-002 断言的 RM=0x80000018/0x80000014 就是错误的 RM 值；T-006 的「CredLen=18」与「24B」混用；S15 的 RM=0x80000024 同样少算 16 字节。违反 CLAUDE.md §Testing Policy 第 1/5 条。

若不修复，实现者按文档写出的报文将被 Wireshark 标记为「malformed」或长度错位。

---

## 核对基线（本次复审确认正确的部分）

以下内容经逐字段核对 RFC，**确认无问题**，实现阶段可直接采用：

1. **§1.3 RPC CALL 头部布局**：XID=4、Type=8、RPCVer=12、Program=16、Version=20、Procedure=24、CredFlavor=28、CredLen=32、CredBody=36+、VerfFlavor/VerfLen，与 RFC 5531 §8 完全一致（本次复审逐偏移核算通过）。
2. **§1.3 RPC REPLY 布局**：ReplyState=12、VerfFlavor=16、VerfLen=20、AcceptState=24（空 verifier 时），与 RFC 5531 §8/§9 一致（§6 各 REPLY HexDump 的 AcceptState @ 0x18 正确）。
3. **§1.3 TCP Record Mark 语义**：位 31=LAST_FRAGMENT、位 30-0=段长度、RM=0x80000000|len，正确（RFC 5531 §11.B）；问题只出在具体数值少算，见 C-2 系。
4. **§2.2 NFSv3 procedure 表 0-21**：NULL/GETATTR/SETATTR/LOOKUP/ACCESS/READLINK/READ/WRITE/CREATE/MKDIR/SYMLINK/MKNOD/REMOVE/RMDIR/RENAME/LINK/READDIR/READDIRPLUS/FSSTAT/FSINFO/PATHCONF/COMMIT 全部与 RFC 1813 §2 对应编号一致。
5. **§2.3 MOUNT v3 procedure 表 0-5**：NULL/MNT/DUMP/UMNT/UMNTALL/EXPORT 正确；PATHCHK 系 NFSv2 遗留的说明正确。
6. **§2.4 NFSv4 procedure 表**：0=NULL、1=COMPOUND、2=CB_COMPOUND（不生成），正确。
7. **§2.5 中 3-37 的 opcode**：ACCESS=3 … VERIFY=37 全部与 RFC 7530 §16 / RFC 7531 §6.1 一致（LINK=11 正确，无 off-by-one，问题在 38+，见 C-1）。
8. **§2.5 attrmask 对照表**：FATTR4_TYPE=1/SIZE=4/FSID=8/FILEID=20/MODE=33/OWNER=36/OWNER_GROUP=37/TIME_MODIFY=53，word/bit 计算（word=N/32、bit=N%32）全部正确。
9. **§2.6 filehandle**：opaque<> 变长 + 4 字节长度前缀 + XDR 填充，正确；NFS4_FHSIZE=128 / NFS3_FHSIZE=64 区分正确。
10. **§2.6 stateid4**：seqid(4B BE) + other[12] 定长无长度前缀，正确；匿名 stateid（全 0）与 READ bypass stateid（seqid=0xFFFFFFFF + other 12×0xFF）字节与 RFC 7530 §9.1.4.3 一致。
11. **§2.6 clientid4**：uint64 8 字节，正确。
12. **§2.7 COMPOUND4args**：tag → minorversion → argarray length → [opcode + args]，顺序正确（RFC 7531 §5.2）。
13. **§2.7/§9.2 COMPOUND reply 截断规则**：失败 op 后 resarray 截断至该 op（含），失败 op 无 result 字段，正确（RFC 7530 §18.2.1）。
14. **§2.8 fattr3 = 84 字节**：4×5+8×5+3×8=84（type/mode/nlink/uid/gid 各 4、size/used/rdev/fsid/fileid 各 8、atime/mtime/ctime nfstime3 各 8），正确；nfstime3=8 字节（secs+nsecs）正确。
15. **§2.9 错误码表**：NFS4ERR_RESOURCE=10018、MOVED=10019、NOFILEHANDLE=10020、BAD_STATEID=10025、BAD_SEQID=10026、OLD_STATEID=10024、NOT_SAME=10027、BAD_COOKIE=10003、RESTOREFH=10030、OP_ILLEGAL=10044、STALE_CLIENTID=10022、STALE_STATEID=10023、EXPIRED=10011，全部正确（经 RFC 7531 §3 nfsstat4 核对）；NFS3 错误码表（ACCES=13、MLINK=32、NOT_SYNC=10002 等）正确。
16. **§2.9 错误码十六进制**：T-168 10019=0x2723、T-169 10018=0x2722、T-170 10025=0x2729、T-152/T-154 10020=0x2724，全部回算正确。
17. **AUTH_SYS 编码**（S14/T-006）：stamp(4)+machinename_len(4)+machinename+pad+uid(4)+gid(4)+gid_count(4)，与 RFC 5531 §9.2 一致；「host」=4B 无填充正确；S14 的 Cred Body Len=24（0x18）正确。
18. **§4.1 seqid 按 state-owner 独立**（RFC 7530 §8.2.2/§8.2.5）：open-owner 与 lock-owner 各自独立序列，正确；S12 的 OPEN=1→CLOSE=3 / LOCK=1→LOCKU=2 逻辑正确。
19. **S12 OPEN4args 布局**：seqid→share_access→share_deny→open_owner4(clientid+owner opaque)→openhow(createmode)→claim(claim_type)，逐偏移核算正确；LOCK4args locker4 联合（new_lock_owner=true → open_to_lock_owner4 = open_seqid+open_stateid+lock_seqid+lock_owner4）布局正确。
20. **§2.5 保留 opcode 说明**：opcode 41-62 为 v4.1+（EXCHANGE_ID=41/CREATE_SESSION=42/DESTROY_SESSION=43）透传不报错的设计，以及 63+ 报错，本身合理（唯一问题是 38-40 被污染，见 C-1）。
21. **MOUNT procedure 0-5 合法、6+ 报错**（T-136），正确（RFC 1813 附录 I）。
22. **base64 用例值**：「AAE=」=1 字节 0x01、「AQ==」=1 字节 0x01、「aGVsbG8=」="hello"、「AAAAAAAAAAA=」=8 字节全 0（S9 cookieverf）、「AAAAAAAAAAAAAAAA」=12 字节全 0（S12 stateid.other），全部回算正确。
23. **§5.1 MSS 分段规则**：每段（含中间段）PSH-ACK、RM 在第一段开头不分段，符合 RFC 793 PSH 语义。
24. **UDP 上限 65507** = 65535 - 20 IP - 8 UDP，正确；T-141/T-142 边界测试设计正确。
25. **§3.2 NFSOp 字段全集**与 §3.3 NFSv4CompoundOp 字段全集：结构完整（Procedure/Filehandle/Filename/Attributes/Offset/Count/Data/StableHow/Access/Cookie/CookieVerf/DirCount/MaxCount/CompoundOps/Tag/DirPath/ReplyStatus/RPCAcceptState/RPCRejectState/AuthStat/OpenReplyStateid），与 RFC 参数表一一对应。
26. **§4.1 SETCLIENTID/SETCLIENTID_CONFIRM 自动补全、PUTROOTFH 自动补全、OPEN_CONFIRM 自动补全**的状态机逻辑合理（OPEN_CONFIRM 仅在 v4.0、新 open-owner 首次 OPEN 后），且 §9.5 #2 已如实登记 seqid 简化偏离。
27. **§7.4 T-119 跨 owner seqid 示例**（OPEN=1 → LOCK=1 → LOCKU=2 → CLOSE=2）与 §4.1 规则 5 自洽（OPEN_CONFIRM 占 open-owner 的 seqid=2，故 OPEN 后接 OPEN_CONFIRM=2 时 CLOSE=3；T-119 省略 OPEN_CONFIRM，序列为 OPEN(1)/LOCK(1)/LOCKU(2)/CLOSE(2)，两者都是合法的简化场景，不冲突）。
28. **§10.5 XID 生成函数**：base 默认 1、incr=0 时同 XID、回绕 uint32 溢出，正确。
29. **§10.6 writeRPCCallHeader 函数**：XID/Type=0/RPCVer=2/Program/Version/Procedure/CredFlavor/CredLen/CredBody/VerfFlavor=0/VerfLen=0 顺序正确，与 §1.3 一致。
30. **NFSv4 NULL (proc=0) 不嵌入 COMPOUND**（§2.4/§4.1 规则 7）：正确，RFC 7530 §18.1 的 NULL 是独立 procedure。

---

## CRITICAL 问题（7 项）

### C-1. NFSv4 opcode 表系统性错位：38=WANT_DELEGATION（v4.0 不存在）、WRITE=39、RELEASE_LOCKOWNER=40（规范为 38/39）

**位置**：§2.5 表第 38-40 行（行 221-223）；连带 §3.3 行 525 注释（「3-40（v4.0）」）、§3.5 行 677、§7.4 T-95（WRITE opcode=00000027=39）、T-129（RELEASE_LOCKOWNER=00000028=40）、§10.2 行 1957。

**描述**：RFC 7530 §16 与 RFC 7531 §6.1 `enum nfs_opnum4`（本次复审经 rfc-editor.org 原文核实）为：

```
OP_ACCESS=3 ... OP_VERIFY=37, OP_WRITE=38, OP_RELEASE_LOCKOWNER=39, OP_ILLEGAL=10044
```

**WANT_DELEGATION 在 RFC 7530/7531 中根本不存在**——它是 NFSv4.1（RFC 5661）才引入的操作（opcode 41）。文档在 VERIFY=37 之后插入「38 WANT_DELEGATION」，把 WRITE 推成 39、RELEASE_LOCKOWNER 推成 40，恰好整体 +1。v4.0 的合法操作上限是 39 而非 40。

**依据**：
- RFC 7531 §6.1：`WRITE=38`、`RELEASE_LOCKOWNER=39`、无 WANT_DELEGATION；
- RFC 5661 §6.1：WANT_DELEGATION=41（v4.1 引入）。

**影响**：实现者按文档生成 WRITE 会写成 opcode 39，Wireshark 显示为 RELEASE_LOCKOWNER，真实服务端返回 NFS4ERR_OP_ILLEGAL；§2.5 行 230 声称「opcode 41-62 为 v4.1+ 操作」的边界也随之整体错位（实际 v4.1 从 40 开始）。§7 的 T-95（`WRITE opcode=00000027`）与 T-129（`RELEASE_LOCKOWNER opcode=00000028`）复读错误值。

**修复建议**：
1. 删除 §2.5 第 38 行 WANT_DELEGATION（v4.0 无此操作）；
2. WRITE 改回 38、RELEASE_LOCKOWNER 改回 39；
3. 保留 opcode 表 3-39 为 v4.0 合法操作，40-62 为 v4.1+ 透传范围（40=WANT_DELEGATION、41=EXCHANGE_ID、42=CREATE_SESSION、43=DESTROY_SESSION…）；
4. §3.3 行 525 注释「3-40」改「3-39」；§3.5 行 677、§10.2 同步；
5. T-095 期望字节改为 `WRITE opcode=00000026`（38=0x26），T-129 改为 `RELEASE_LOCKOWNER opcode=00000027`（39=0x27）；
6. 新增一条针对 opcode 38=WRITE、39=RELEASE_LOCKOWNER 的字节级断言用例（防回归），并核对 §6 所有含 WRITE/RELEASE_LOCKOWNER 的场景。

### C-2. 全部 HexDump 的 Record Mark 长度系统性少算 12-16 字节（RPC 头被当成 24 字节，漏掉 Cred/Verf 四个 uint32）

**位置**：§6 S1（行 912 RM=0x80000018、行 928 RM=0x80000014）、S2（行 948 RM=0x80000024、行 967 RM=0x80000068）、S11 CALL（行 1229 RM=0x8000003C）、S11 REPLY（行 1254 RM=0x80000024）、S14（行 1384 RM=0x80000040）、S15（行 1418 RM=0x80000024）、§7.1 T-001（RM=0x80000018）、T-002（RM=0x80000014）。

**描述**：RFC 5531 CALL 消息的固定头为 XID+Type+RPCVer+Program+Version+Procedure+CredFlavor+CredLen+VerfFlavor+VerfLen = **40 字节**（auth_none/auth_sys 空 verifier 时）。文档自报的 RM 长度却按「XID..Procedure=24 字节」计算，所有 CALL 的 RM 少算 16 字节（S2 因带 filehandle 只少 12 字节）。每个场景自报 RM 与其自身偏移行**直接矛盾**：

| 场景 | 文档 RM 长度 | 实际长度（按文档偏移行核算） | 偏差 |
|------|-------------|------------------------------|------|
| S1 CALL | 0x18=24 | 40（RPC 头仅 11 个 uint32，无 body） | -16 |
| S1 REPLY | 0x14=20 | 24（6 个 uint32） | -4 |
| S2 CALL | 0x24=36 | 48（头 40 + fh_len4 + fh1 + pad3） | -12 |
| S2 REPLY | 0x68=104 | 116（头 24 + status4 + attrfollow4 + fattr3 84） | -12 |
| S11 CALL | 0x3C=60 | 76（头 40 + tag4 + minor4 + argarray4 + op1op4 + op2op4 + bitmap4+3×4） | -16 |
| S11 REPLY | 0x24=36 | 52（头 24 + tag4 + status4 + resarray4 + 4 op 字段 ×4） | -16 |
| S14 CALL | 0x40=64 | 68（头 36 + cred24 + verf8） | -4 |
| S15 REPLY | 0x24=36 | 52（头 24 + tag4 + status4 + resarray4 + opcode4 + op_status4） | -16 |

**依据**：RFC 5531 §8/§9 消息结构；S2 的 fattr3 长度取文档自己 §2.8 声明的 84 字节（而非其偏移行注释里的「80 bytes fattr3」，见 H-4）。

**影响**：所有 HexDump 的 RM 值 100% 错误（S1-S15 无一幸免），实现者若按 RM 值写测试断言，生成的报文长度与 RM 不符，Wireshark 会把消息切成错误边界。这是 v2.0.0 声称「修复 H-2 RM 语义」之后的**数值回归**——语义修对了，数值全算错了。

**修复建议**：
1. 以「RPC 头 40 字节（auth_none 空 verifier）为基准」重算全部 RM：CALL 场景 RM = 40 + cred_len + verf_len + NFS body 长度；REPLY 场景 RM = 24 + verf_len + NFS body 长度；
2. S1 CALL=0x80000028、S1 REPLY=0x80000018、S2 CALL=0x80000030、S2 REPLY=0x80000074、S11 CALL=0x8000004C、S11 REPLY=0x80000034、S14 CALL=0x80000044、S15 REPLY=0x80000034（供参考，实现时按公式重算）；
3. §7.1 T-001/T-002 的 RM 断言同步修正；
4. 增加一条「RM = 0x80000000 | 实际 payload 长度」的自动一致性测试（在测试代码中直接计算，不硬编码文档数值），防止此类全表性错误再次发生。

### C-3. §7.1 测试偏移约定自相矛盾：REPLY 的 AcceptState 声明在 28-2B，实际是 24-27

**位置**：§7 行 1442（「REPLY 偏移：RM=0、XID=4、Type=8、ReplyState=12、VerfFlavor=16、VerfLen=20、VerfBody=24、AcceptState=28」）；对照 §6 全部 REPLY HexDump（S1 行 934、S2 行 973、S11 行 1260、S15 行 1424 均为 AcceptState @ 0x18=24）与 §1.3 行 69-71。

**描述**：RFC 5531 MSG_ACCEPTED reply 为 XID(4)+Type(4)+ReplyState(4)+Verifier(flavor4+len4+body)+AcceptState(4)。空 verifier 时 AcceptState 在偏移 **24-27**。§7.1 声明 VerfBody=24、AcceptState=28——若 verifier body 为空（auth_none 时 body 长度 0），AcceptState 与 VerfBody 重叠；若按「VerfBody=24 起」则 AcceptState 应紧跟其后，不可能是固定 28。该声明与文档自己 §6 的 15 个 HexDump 全部矛盾，也与 RFC 矛盾。

**依据**：RFC 5531 §9.1；文档 §6 S1 REPLY 偏移 0x18=24（自证矛盾）。

**影响**：测试用例若按此偏移断言 AcceptState，会读到 Verifier 的字节（偏移 28 实为 NFS body 或越界），所有 reply 类字节断言全部错位。

**修复建议**：§7.1 的 REPLY 偏移约定改为「RM=0、XID=4、Type=8、ReplyState=12、VerfFlavor=16、VerfLen=20、VerfBody=24（若 len>0）、AcceptState=24+verf_len」，并注明空 verifier 时 AcceptState @ 24。

### C-4. writeverf3 / verf4 编码错误：S6/S10 画成「4 字节长度 + 8 字节 verf」，规范是 8 字节定长无长度前缀

**位置**：§6 S6（行 1107-1108：「verf length=8 + verf data (8 字节)」）、S10（行 1216-1217：同样）；连带 T-047/T-048/T-096 的表述。

**描述**：RFC 1813 §2.6 `typedef opaque writeverf3[NFS3_WRITEVERFSIZE]`（NFS3_WRITEVERFSIZE=8）、RFC 7531 §3 `typedef opaque verf4[NFS4_VERIFIER_SIZE]`（=8），两者都是**定长 opaque[8]，XDR 编码为 8 字节裸数据，无 4 字节长度前缀**（只有变长 opaque<> 才有长度前缀）。文档 S6 WRITE reply 的 committed 后画成「verf length=8 + verf data(8B)」共 12 字节；S10 COMMIT reply 同样。

**依据**：RFC 1813 §2.6 writeverf3；RFC 7531 §3 verf4；XDR 定长 opaque 无长度前缀（RFC 4506 §4.9）。

**影响**：实现者按文档会多写 4 字节长度前缀，reply 总长多 4，Wireshark 解析 COMMIT/WRITE 失败。T-048/T-096 断言「verf 8B」未给出带前缀与否的字节级断言，掩盖了此问题。

**修复建议**：S6/S10 删除「verf length=8」两行，verf 直接 8 字节；在 T-048/T-096 增加「verf 无长度前缀，直接 8B 数据」的字节级断言。

### C-5. S9 READDIR reply 缺少 cookieverf3 字段（8 字节）

**位置**：§6 S9 REPLY（行 1186-1191）：status + post_op_attr + entries.value_follows + eof，中间缺 cookieverf3。

**描述**：RFC 1813 §2.2.17 `readdir3resok = { post_op_attr dir_attributes; cookieverf3 cookieverf; dirlist3 reply; bool eof; }`——reply 在 post_op_attr 之后必须有 8 字节 cookieverf3（opaque[8] 无长度前缀，等于 call 的 cookieverf），然后才是 entries 列表与 eof。文档的 offset 连续（0x74 value_follows、0x78 eof）说明其总长按缺 cookieverf3 计算，若补上 8 字节则后续偏移需全部 +8。

**依据**：RFC 1813 §2.2.17。

**影响**：READDIR reply 报文结构错误，解析器读出的 entries/eof 位置错位。

**修复建议**：S9 REPLY 在 post_op_attr 后补 8 字节 cookieverf3（值 = call 的 cookieverf，全 0），后续偏移 +8；新增一条 READDIR reply 字节级断言用例（status + attrfollow + fattr3 + cookieverf3 8B + value_follows + eof）。

### C-6. 多会话 clientid 三处示例相互矛盾

**位置**：§4.3 行 817（「session i 从 0 起…clientid 默认偏移基础为 uint64(0x10000)*uint64(i)+1」，「session 0 clientid=0x10000+1；session 1 clientid=0x20000+1」）；§10.4 行 1984-1991（`defaultClientID` 函数注释「session 0: 0x0000000000010001 / session 1: 0x0000000000020001 / session 2: 0x0000000000030001」）；S13 表（行 1367-1369：「Flow 1 reply clientid=0x0000000000010001 / Flow 2=0x0000000000010002 / Flow 3=0x0000000000010003」）；§7.4 T-106（「session 0 clientid=0x10000+1；session 1 clientid=0x20000+1」）、T-177（「session 0 clientid=0x10001；session 1 clientid=0x20001」）。

**描述**：同一公式 `0x10000*i+1` 被写成三套结果：

- §4.3/T-106/T-177 的文字示例：「session 0 = 0x10001；session 1 = 0x20001」→ 按公式 `0x10000*1+1 = 0x10001`，则「0x20001」是**多乘了 2**（等于 `0x10000*2+1`）；
- §10.4 函数注释：session 0=0x10001、session 1=0x20001、session 2=0x30001 —— 与公式一致；
- S13 表格：session 1=0x0000000000010002、session 2=0x0000000000010003 —— 又是另一套（按 i 递增 1）。

三处对同一个 session 1 给出了 0x10001、0x20001、0x10002 三个值。

**依据**：同一设计文档内部一致性要求；§10.4 的 Go 函数是唯一明确可执行的定义。

**影响**：实现者无从判断哪个是对的；测试断言（T-106/T-177）若按错误文字写，会与实现函数（§10.4）冲突。

**修复建议**：以 §10.4 函数为准，统一为 session i = `0x10000*(i+1)+1`（session 0=0x10001、1=0x20001、2=0x30001），或改为公式字面值 `0x10000*i+1`（session 0=0x00001、1=0x10001、2=0x20001）——**二选一**，然后修正 §4.3 文字示例、S13 表格（改为与公式一致的三行值）、T-106/T-177 期望值，并补一条「按公式逐 session 生成 clientid」的集成断言。

### C-7. 测试用例复读文档自身错误值，违反 CLAUDE.md §Testing Policy 第 1/5 条

**位置**：§7.1 T-001（「CALL RM=0x80000018」——错误值，见 C-2）、T-002（「REPLY RM=0x80000014」——错误值）；T-006（「CredLen=18 (24B)」——0x18=24，进制混用无标注）；§7.2 T-046（「NFS status @ reply=70 00 00 00?」——带问号的草稿式断言，且括号内两种说法自相矛盾）；T-060（「procedure 范围 12-14（hex）」——程序号 18/19/20 的十六进制是 0x12/0x13/0x14，表述歧义）；§7.6 T-152/T-154（「op_status=000027 24」——带空格的分组写法，与 T-168 的「000027 23」等不一致，易误读）；S2/S4/S5/S7（fattr3 偏移行注释写「[80 bytes fattr3]」，文本却写 84 字节——同一场景自相矛盾，见 H-4）。

**描述**：测试用例大量直接引用文档 §6 的错误数值（RM、fattr3 长度），而不是独立于 RFC 计算的值，形成「文档写错 → 测试复读错 → 测试通过」的自证闭环，正是 CLAUDE.md §Testing Policy 第 1 条（spec-driven，不从文档抄）与第 5 条（断言可观察输出，不许断言错误值）明令禁止的模式。此外 T-006「18 (24B)」的进制混写、T-152 的「000027 24」空格分组、T-046 的「?」占位符，都达不到「测试断言必须可执行、无歧义」的标准。

**依据**：CLAUDE.md §Testing Policy 规则 1/5；本次复审对 S1/S2/S11 的 RM 独立核算（C-2）。

**影响**：v2.0.0 声称「200+ 条测试用例」的字节断言中，凡是引用 §6 RM/fattr3 数值的部分都需要重算；若照原样实现并写测试，错误会被固化并表现为「测试全绿但报文 malformed」。

**修复建议**：
1. 所有测试的字节期望值独立按 RFC 重算（RPC 头 40B/24B + XDR 规则），不与 §6 错误数值绑定；
2. 进制统一：十六进制一律写 4 位或 8 位并注明（如 `0x18=24`），删除「18 (24B)」式写法；
3. 删除 T-046 的「?」占位断言，改为明确断言（status=0、eof=1）；
4. 全文「000027 24」改为 `00 00 27 24` 连续字节写法；
5. S2/S4/S5/S7 的 fattr3 注释统一为 84 字节（或按 C-2 修正后的 RM 一并修订）。

---

## HIGH 问题（6 项）

### H-1. S11/S15 的 GETATTR reply result 结构未给出字节（bitmap + attrs），规则未闭环

**位置**：§6 S11 REPLY（行 1251-1268）：op #2 GETATTR op_status=0 后仅 `0038 [bitmap + fattr4 attrs]` 注释，无实际字节；S15 的失败 GETATTR 无 result（正确）。

**描述**：GETATTR 成功 reply 必须含 bitmap4（长度+words）与 attrs（按 mask 位序的属性值）。S11 call 请求了 size+mode，reply 至少应给出 bitmap + size(8B) + mode(4B)。文档以注释占位，无字节，测试无从断言；§7.3 T-074 只说「attrs 含 size(8B)+mode(4B)」，未定义 reply bitmap 与 call mask 的关系（回显 mask？支持属性集？）。

**依据**：RFC 7530 §16.9 GETATTR4resok = fattr4 attrs（bitmap4 + 属性值序列，按 mask 位序）。

**影响**：GETATTR reply 是 §2.7 COMPOUND 编码之外唯一「按 mask 生成 attrs」的地方，未定义完整将导致实现不确定性。

**修复建议**：补齐 S11 REPLY 的 GETATTR result 字节（bitmap len + words + size 8B + mode 4B），并明确规则：reply attrs 顺序 = call mask 的位序（size → mode），bitmap 回显 call 的 mask（或明确定义为「支持属性集」的固定值）。

### H-2. OPEN_CONFIRM 自动补全与 seqid 序列的边界条件未定义（非首个 COMPOUND 的 OPEN、同 COMPOUND 多个 OPEN、user 显式 seqid）

**位置**：§4.1 规则 3（行 736-738）、§4.1 规则 5（行 742-746）、§9.5 #2。

**描述**：规则 3 说「Plan 检测到 OPEN 且 open-owner 是首次出现（同 clientid+owner 在前序 ops 中未出现）时，自动在 OPEN 后追加 OPEN_CONFIRM」，但未定义：
1. OPEN 出现在**非首个 COMPOUND**（如第二个 COMPOUND 内）时，OPEN_CONFIRM 追加在哪个 COMPOUND？若追加到同一 COMPOUND 尾部尚可，若另起 COMPOUND 则需新增一个 NFSOp，语义未说；
2. 同一个 COMPOUND 内出现**两个不同 owner 的 OPEN** 时，各追加一个 OPEN_CONFIRM？追加顺序？
3. OPEN seqid 由 user 显式给定时（如 5），OPEN_CONFIRM seqid 是否为 6——文档未说「+1」是对 user 值还是对内部计数。

**依据**：RFC 7530 §16.18（OPEN_CONFIRM 用于确认 OPEN reply 的 stateid，与 OPEN 同 COMPOUND 或后续 COMPOUND 均可）；设计文档需对这些分支给出确定规则。

**影响**：实现者遇到多 OPEN / 非首 COMPOUND OPEN 时行为不确定，生成的复合流量在 Wireshark 中显示「OPEN_CONFIRM missing」或 seqid 不连续。

**修复建议**：明确定义：
1. OPEN_CONFIRM 追加到 OPEN 所在的同一 COMPOUND 尾部；
2. 每个「首次出现的 (clientid, owner)」各追加一个 OPEN_CONFIRM，顺序与 OPEN 出现顺序一致；
3. seqid 规则改为「OPEN_CONFIRM.seqid = user 显式 Seqid 时用 user 值（并校验与 OPEN 的差异），否则 = 该 owner 上一个 OPEN/OPEN_CONFIRM 的 seqid + 1」，并新增多 OPEN 场景测试（T-119 变体）。

### H-3. stateid 引用机制自相矛盾：OpenReplyStateid 声明「可建立引用」但 Plan「不自动改写」，无实际接线

**位置**：§3.2 行 516（OpenReplyStateid 注释）、§3.5 行 686（「若 user 希望后续 op 用 OPEN reply 的 stateid，需自行在该 op 的 stateid 字段中填入相同值，或通过此字段建立引用」）、§4.1 规则 4（「Plan 只做透传」）。

**描述**：`OpenReplyStateid` 字段声称「通过此字段建立引用」，但 §4.1 规则 4 与 §9.5 #9 都只说「Plan 不自动改写、透传、user 自行配置」。「通过此字段建立引用」具体如何接线（Plan 是否把 OPEN reply 的 stateid 值填入引用它的 op？）从未定义，字段名与语义描述互相打架。且 §4.1 规则 3 说「OPEN_CONFIRM 的 open_stateid 取自 OPEN reply」——说明 Plan 确实会合成 OPEN reply stateid，那为何不能同时填入后续 op？设计未闭环。

**依据**：设计文档内部一致性要求；RFC 7530 §16.18/§16.19（stateid 由 reply 返回后由后续 op 使用）。

**影响**：实现者无法实现「OPEN → WRITE 用 OPEN stateid」的最常见真实场景；若照 §9.5 #9 透传，则 T-090（「OPEN 后续 op 用同 stateid」）没有任何可执行机制。

**修复建议**：二选一并写死：
1. 删除 OpenReplyStateid 字段，明确「OPEN reply stateid 由 Plan 合成，合成值 = 确定性伪值（如 (clientid, owner, seqid) 派生），user 可在后续 op 显式填入该值」；
2. 或实现真正的引用解析：Plan 遇到 OpenReplyStateid 时把前序 OPEN 的合成 stateid 值写入引用该字段的 op，并新增端到端测试（OPEN → WRITE 使用同一 stateid 字节断言）。推荐方案 1（与「合成流量确定性」原则一致）。

### H-4. S2/S4/S5/S7 的 fattr3 长度标签与文本自相矛盾（80 vs 84 字节）

**位置**：§6 S2（行 976「[80 bytes fattr3]」+ 行 981「fattr3 总长 84 字节」）、S4（行 1041/1049）、S5（行 1070/1080）、S7（行 1139）。

**描述**：偏移行注释写「[80 bytes fattr3]」，文本校验点写「fattr3 (84 字节)」。§2.8 已声明 fattr3=84 字节，且本次复审核算 84 正确（4×5+8×5+3×8）。偏移行与实际长度 84 不符，导致依赖偏移的读者（与 C-2 的 RM 核算）无从判断 reply 布局。

**依据**：RFC 1813 §2.6 fattr3 各字段求和 = 84 字节；文档 §2.8 自述 84。

**影响**：若实现者按「80」写偏移，reply 尾部 4 字节错位；按 84 写则与文档偏移注释矛盾——文档无法指导实现。

**修复建议**：S2/S4/S5/S7 的「[80 bytes fattr3]」全部改为「[84 bytes fattr3]」，并按 84 复核各场景 REPLY 的 RM（见 C-2）。

### H-5. S6/S8/S10 的 wcc_data 结构与长度标签自相矛盾（36 字节 vs 括号内容 92 字节 vs RFC 116 字节）

**位置**：§6 S6（行 1104「[36 bytes file_wcc]」+ 行 1105「wcc_data (pre_op_attr 4 字节 + post_op_attr 4+84 字节，简化)」）、S8（行 1165「[36 bytes wcc_data] … (pre_op_attr 4 字节 + post_op_attr 4+84)」）、S10（行 1215「[36 bytes file_wcc]」）。

**描述**：RFC 1813 §2.6 `wcc_data = { wcc_attr pre_op_attr; post_op_attr post_op_attr; }`，其中 pre_op_attr = 4 字节 bool + wcc_attr（size8+mtime8+ctime8 = 24 字节），post_op_attr = 4 字节 bool + fattr3 84 字节。即：
- pre_op_attr 分支 = 4（follow）+ 24（wcc_attr）= 28 字节；
- post_op_attr 分支 = 4（follow）+ 84 = 88 字节；
- wcc_data 合计 = 28 + 88 = **116 字节**（若两个都 follow），文档写「36 bytes」且括号内「pre_op_attr 4 字节 + post_op_attr 4+84」合计也是 92（4+4+84），不是 36，括号内容与长度标签自相矛盾；且 pre_op_attr 的「4 字节」漏了 wcc_attr 24 字节。

**依据**：RFC 1813 §2.6 wcc_data/wcc_attr 定义。

**影响**：WRITE/REMOVE/COMMIT reply 的 wcc_data 长度与结构均无确定指导，实现者要么写错要么无法实现。

**修复建议**：S6/S8/S10 改为明确结构：pre_op_attr(4B bool + 24B wcc_attr) + post_op_attr(4B bool + 84B fattr3)，或明确定义「简化：pre_op_attr follow=0（4B）、post_op_attr follow=1（4+84B），wcc_data=92B」，并让长度标签与结构一致；新增 WRITE reply wcc_data 字节级断言。

### H-6. NFSv3 错误 reply 的结构无字节级定义（§9.2 一句话带过，T-046 语义自相矛盾）

**位置**：§2.8、§9.2 行 1803（「NFSv3 reply 错误：reply 的 NFS status 字段填错误码…结果体按 spec 缩短（如 GETATTR 失败只返回 status，无 fattr3）」）、§6 无 v3 错误场景、§7.2 T-046（「NFS status @ reply=70 00 00 00?（NFS3ERR_EOF 不存在…）」）。

**描述**：v3 错误 reply 的精确结构（status=错误码后是否还有任何字段）只在 §9.2 一句话带过，无 HexDump、无字节级测试。且 T-046 自己承认「NFS3ERR_EOF 不存在」却把场景命名为「READ offset 超出 EOF」并期望 status=70（STALE）——offset 超 EOF 在 v3 中返回 eof=true 且 status=0，用例的语义与断言互相矛盾。

**依据**：RFC 1813 §2.2.7（READ3res = status + [data] + [eof] 的联合结构：失败时仅 status）。

**影响**：v3 错误路径（§9.3 表格 20 个错误码场景）没有任何字节级覆盖，实现自由发挥。

**修复建议**：
1. 新增一个 v3 错误 reply HexDump（如 GETATTR reply_status=2，仅 status 无 fattr3，RM 相应缩短）；
2. 修正 T-046：明确「offset 超 EOF → status=0 + eof=true」，另立用例「reply_status=70 → status=70 无结果体」；
3. v3 各 procedure 失败 reply 结构表（哪些返回仅 status）补全。

---

## MEDIUM 问题（7 项）

### M-1. §2.5 表首行「0 | ILLEGAL4」错误命名：RFC 中 opcode 0 不存在，非法 op 由服务端以 OP_ILLEGAL（10044）表达

**位置**：§2.5 表第 0 行（行 185「0 | ILLEGAL4 | （保留，COMPOUND 中无效 op 自动转为 ILLEGAL4）」）、行 228「0/1/2：保留（INVALID_OP, ILLEGAL_OP, ILLEGAL_OP）」。

**描述**：RFC 7531 §6.1 `enum nfs_opnum4` 只有 OP_ILLEGAL=10044，没有 opcode 0 对应的名称（0-2 是未赋值空间，不是「INVALID_OP/ILLEGAL_OP」）。「COMPOUND 中无效 op 自动转为 ILLEGAL4」的说法不准确：服务端对未知 opcode 返回的 op_status=NFS4ERR_OP_ILLEGAL（错误码 10044），并非把 opcode 换成 10044 再返回。文档把「保留/未分配（0-2）」与「ILLEGAL4」混为一谈。

**依据**：RFC 7531 §6.1；RFC 7530 §16.1（服务端对未知 op 返回 NFS4ERR_OP_ILLEGAL）。

**影响**：语义表述错误，实现者可能误把 opcode=0 当合法「ILLEGAL4」发送。

**修复建议**：第 0 行改为「未分配（0-2 无名称，Validate 拒绝）」；明确「COMPOUND 中非法 opcode 的 reply 行为：op_status = NFS4ERR_OP_ILLEGAL (10044)」；§2.5 行 228 的「INVALID_OP, ILLEGAL_OP」命名删除。

### M-2. NFSv4 REPLY 的 oparray 元素含 opcode，但测试多数只断言 call 侧，reply 侧 op 顺序/数量覆盖不足

**位置**：§2.7 REPLY 编码（行 293「op #1 opcode + op_status + result」）、§7.4 T-110~T-130 多数只断言 call 侧。

**描述**：COMPOUND reply 的 resarray 元素顺序必须与 call 的 argarray 一致（除截断外）。文档测试大量只断言 call 侧 opcode，reply 侧仅 T-155/T-156/T-157 覆盖 resarray 数量，缺少「reply op 顺序 = call op 顺序」的断言。S12 等场景未给 reply HexDump。

**依据**：RFC 7530 §18.2.1；CLAUDE.md §Testing Policy 第 5 条（断言可观察输出）。

**影响**：实现时 reply 顺序错误（如按 mask 位序而非 op 顺序返回）不会被测试发现。

**修复建议**：为 T-155/T-157 补充「resarray 元素 opcode 顺序逐一等于 call argarray opcode 顺序」的断言；为 S12 增加 reply HexDump（或至少 op 序列清单）。

### M-3. §3.3 的 AttrMask 校验（V30）与 T-073/T-138~T-140 的 bitmap「尾部零 word」语义冲突未定义

**位置**：§2.5 行 248、V30（行 1743）、T-073（attr_mask:[0x10,0x02,0]）、T-140（attr_mask:[0x10,0x02,0]）。

**描述**：XDR bitmap4 是变长数组，规范允许尾部 0 word 省略（数组长度为「最后一个非零 word +1」）。文档 T-073/T-140 显式传 `[0x10, 0x02, 0]` 并要求「bitmap len=3」（含 word2=0），但未定义「user 传尾部 0 时是否规范化截断」。若实现保留 3-word 写法（len=3, word2=0），与大多数服务端的 2-word 最优编码不同——虽然 XDR 合法，Wireshark 正常解析；若截断则与 T-073 断言冲突。V30 只说 word2+ 非零报错，未说尾部零的处理。

**依据**：RFC 4506 变长数组；文档 T-073/T-140 自述。

**影响**：实现者按 T-073 写 3-word 或按「截断」写 2-word 均可能，行为未定。

**修复建议**：明确「user 提供的 attr_mask 保留原样编码（含尾部 0 word）」或「规范化：去掉尾部 0 word 后编码」，二选一，并与 T-073/T-140 断言一致；建议保留原样并让 T-073 同时断言「len=3」的行为。

### M-4. §9.2 字段优先级表缺失 ResultStatus 在 v4 多 op 下的行为（resarray 各 op_status 取值未定义）

**位置**：§9.2 行 1801-1813、§3.5 行 684、T-151（只断言「reply 顶层 status=13」）。

**描述**：§9.2 的优先级「ReplyStatus > ResultStatus > 0」按 NFSv4 COMPOUND 语义表述（顶层 status 与 op_status），但 §3.1 ResultStatus 注释说「非 0 时所有 reply 在 NFS 层返回该错误码」——对 v3 是「NFS status 字段填错误码」，对 v4 是「顶层 status + 全部 op_status 填错误码」还是「仅顶层」？ResultStatus≠0 且多 op 全成功时 resarray 是否全 op_status=ResultStatus、是否截断，未定义。

**依据**：设计文档一致性；T-151 断言不完整。

**影响**：v4 多 op + ResultStatus≠0 时 op_status 取值无指导。

**修复建议**：明确「ResultStatus≠0 时：顶层 status=ResultStatus，resarray 完整返回（不截断），每个 op_status=ResultStatus」或与 OpStatus 截断规则组合的确定规则；T-151 增加多 op 断言。

### M-5. NFSv3 READ/WRITE 的 count 与 Data 长度一致性未校验（call count 与 data 长度可矛盾）

**位置**：§3.2 Count 字段、§7.2 T-043（offset:0, count:5, data="hello"）、T-047。

**描述**：RFC 1813 WRITE3args = filehandle, offset, count, stable_how, data——count 必须等于 data 长度（否则服务端按 count 截断/报错）。文档未规定「count 与 len(data) 不一致时如何处理」（以 count 为准？以 data 为准？Validate 报错？）。T-047 的 count=5 与 data=5 一致，未覆盖不一致场景。

**依据**：RFC 1813 §2.2.6；CLAUDE.md §Testing Policy 第 2 条（负向路径）。

**影响**：实现自由发挥，生成 count≠len(data) 的畸形 WRITE。

**修复建议**：新增 Validate 规则「WRITE 时 count 必须等于 len(data)（v3 与 v4 均适用），否则报错」，并加对应测试（count=5, data=3 字节 → 报错）。

### M-6. MOUNT NULL（program=100005, procedure=0）场景未覆盖

**位置**：§2.3、§7.1。

**描述**：MOUNT 协议也有 NULL (proc=0)。文档 §2.3 说「trafficgen 默认只生成 NULL/MNT/UMNT」，但 §7 没有 MOUNT NULL 的用例；§4.2 自动补全只插 MOUNT proc=1/UMOUNT proc=3。user 配置 program=100005, procedure=0 时的行为（MOUNT 自动补全是否跳过？）未定义。

**依据**：RFC 1813 附录 I（MOUNT NULL 存在）；CLAUDE.md §Testing Policy 第 3 条（每个分支都要测）。

**影响**：MOUNT NULL 场景（可用作 rpcbind 探测等价物）无行为定义。

**修复建议**：明确「user 显式配置 program=100005 procedure=0 时，Plan 生成 MOUNT NULL call/reply，且不重复自动插入 MOUNT proc=1（头部补全跳过）」并新增用例。

### M-7. S13 的 client.id 命名与 §4.3/§10.4 的会话序号约定不一致

**位置**：S13（行 1367-1369：client.id = "trafficgen-client-1"/"trafficgen-client-2"/"trafficgen-client-3"）；§4.3 行 819（「默认 'trafficgen-client-{session序号}'」）；§7.4 T-179（「session 0 id='trafficgen-client-0'；session 1 id='trafficgen-client-1'」）。

**描述**：§4.3/T-179 用 0-based 序号（session 0 → "trafficgen-client-0"），S13 用 1-based（Flow 1 → "trafficgen-client-1"）。同一字段两种编号，与 C-6 的 clientid 数值矛盾同源（S13 整表需要重做）。

**依据**：设计文档一致性；T-101 行 1563 也用「trafficgen-client-0」（0-based）。

**影响**：多会话测试断言（T-179 vs S13）不一致。

**修复建议**：统一为 0-based（session 0 → "trafficgen-client-0"），S13 表格改 1-3 行为 0/1/2。

---

## LOW 问题（5 项）

### L-1. §7.2 T-046 断言含「?」占位符与自相矛盾的括号说明

**位置**：§7.2 T-046（行 1498）。

**描述**：「NFS status @ reply=70 00 00 00?（NFS3ERR_EOF 不存在，v3 用 eof=true 表达；status=0 + eof=1）」——期望值带问号、括号内两种说法矛盾。offset 超 EOF 在 v3 是 status=0 + eof=1，不是 status=70。

**依据**：RFC 1813 §2.2.7。

**修复建议**：改为「offset 超 EOF → status=0（NFS3_OK）+ eof=1；若需测错误路径用 reply_status=70 → status=70 且无 data」。

### L-2. §7.2 T-060 断言「procedure 范围 12-14（hex）」歧义

**位置**：§7.2 T-060（行 1512）。

**描述**：procedure 18/19/20 的十六进制是 0x12/0x13/0x14，但「procedure 范围 12-14」会被误读为十进制的 12-14（对应 REMOVE/RMDIR/RENAME）。应写「Procedure @ 18-1B = 00000012/00000013/00000014」。

**修复建议**：改写为明确字节值。

### L-3. §10.2 元数据表 `nfs_accept_state` 偏移与 §7.1 的 AcceptState 偏移声明重复出错源

**位置**：§10.2 行 1953（「nfs_accept_state … 写入偏移 28-31」）。

**描述**：与 C-3 相同偏移错误（AcceptState 应在 24-27，空 verifier 时）。§10.2 行 1952 的 `nfs_reply_state`「写入偏移 12-15」正确。

**修复建议**：改 28-31 为 24-27，并注明「空 verifier 时」。

### L-4. S3 sattr3 的 set_atime=0 标注「DONT_CHANGE」与 RFC 的 set 值语义混淆

**位置**：§6 S3 行 1009（「set_atime=false (DONT_CHANGE)」）。

**描述**：sattr3 的 atime/mtime 是 `sattrguard3` 联合：set(1=SET_TO_SERVER_TIME, 2=SET_TO_CLIENT_TIME) + nfstime3，判别值仅 1/2（RFC 无 DONT_CHANGE 枚举）。T-033/T-034 正确表达了 set 字段值 1/2 语义；S3 把「set=false」标注为「DONT_CHANGE」会把布尔 set 位与 sattrguard3 的判别值混淆——false（0）在 sattrguard3 判别下是不存在分支（属性不改变）。

**依据**：RFC 1813 §2.6 sattrguard3（判别值仅 1/2）。

**修复建议**：S3 注释改为「set=false → 该属性不修改」。

### L-5. §5.6 时间戳规则未定义 reply 与 call 的时间戳关系

**位置**：§5.6（行 892-896）。

**描述**：只定义「第一个包 Timestamp=time.Now()、后续按 PktInterval 递增」，未说明 reply 相对 call 的间隔（真实 NFS 有 RTT）。对合成流量可接受，但应显式说明「reply 与 call 时间戳相同或相差固定值」以免实现分歧。

**修复建议**：补充一句「reply 时间戳 = 对应 call 时间戳（无 RTT 模拟）」。

---

## 测试用例质量评估（CLAUDE.md §Testing Policy）

| 规则 | 评估 | 说明 |
|------|------|------|
| 1. Spec-driven | ⚠️ 部分 | T-001~T-200 覆盖面广、与 §2-§6 一一对应，但大量字节断言直接复读 §6 的错误 RM/fattr3 数值（C-2/C-4/C-7），非独立于 RFC 计算 |
| 2. 失败路径 | ✅ 大部分 | T-133/T-134（stateid 长度）、T-141（UDP 超限）、T-050（stable_how）、V1-V38 均有负向用例；缺「WRITE count≠len(data)」（M-5）、MOUNT NULL（M-6） |
| 3. 正确 scope | ✅ 大部分 | 各函数/字段基本各有用例（opcode 3-39 全有对应 T-xxx）；38-40 的错位使部分断言断言了错误值（C-1） |
| 4. 集成测试 | ✅ | T-191~T-200 覆盖完整会话/MSS 分段/PCAP/失败传播；T-199 验证 broken spec 使任务失败，符合规则 |
| 5. 可观察输出 | ⚠️ | T-046 占位符、T-006 进制混用、T-152 空格分组、S2 等 fattr3 80/84 矛盾（C-7/H-4）；部分 reply 侧断言缺失（M-2） |
| 6. 并发正确性 | N/A | NFS 场景以 4-tuple 隔离多会话为主，多会话用例 T-171~T-180 覆盖端口/XID/clientid 独立性；「会话间不交错」由 T-180 断言，无共享速率问题 |
| 7. Failing-test-first | N/A | 设计文档阶段，无代码 |
| 8. 测试质量对抗评审 | ⚠️ | 本次复审即此环节；发现测试复读文档错误值的问题（C-7） |

---

## 修复优先级建议

1. **立即修复（阻断实现）**：C-1（opcode 表）、C-2（RM 全表重算）、C-3（AcceptState 偏移声明）、C-4（verf 编码）、C-5（cookieverf3 缺失）、C-6（clientid 三处矛盾）。
2. **实现前修复（影响正确性）**：H-1~H-6（GETATTR reply 结构、OPEN_CONFIRM 边界、stateid 引用接线、fattr3 80/84、wcc_data 结构、v3 错误 reply）。
3. **随实现完善**：M-1~M-7、L-1~L-5。

---

## 最终结论

**否——本文档不能直接进入实现阶段。**

正面：v2.0.0 的核心结构层（RPC 头偏移、COMPOUND 编码顺序、stateid4/clientid4 定长、FHSIZE 区分、错误码表、AUTH_SYS 编码、fattr3 84 字节、seqid 按 owner 独立）经本次复审全部正确，说明 v1.1 → v2.0.0 的修复方向是对的。

阻断项：**NFSv4 opcode 38-40 错位（C-1）** 与 **全 HexDump RM 长度系统性少算（C-2）** 是两处全文档性错误，前者会让所有含 WRITE/RELEASE_LOCKOWNER 的报文错 opcode，后者让 15 个 HexDump 的 RM 值与自身偏移行全部矛盾；加上 C-3~C-6 四处结构/数值错误，共 7 项 CRITICAL。修复后需至少重算 §6 全部 RM 数值、重写 §2.5 表 38-40 行、统一 clientid 三处示例，并让测试断言改为独立于 RFC 计算的值（打破「自证」闭环），方可进入实现。
