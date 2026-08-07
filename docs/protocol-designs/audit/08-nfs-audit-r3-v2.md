# 08-nfs-design.md 复审报告（r3, v2.0.2）

**审计对象**：`/home/weihang/trafficGenerator/docs/protocol-designs/08-nfs-design.md`（v2.0.2，2316 行）
**规范**：RFC 7530/7531 (NFSv4.0)、RFC 1813 (NFSv3)、RFC 5531 (ONC RPC)、RFC 5661 (v4.1 对照)
**审计方式**：全文分段通读（4×600 行）+ 逐字节核算 15 个 HexDump + 逐项核对 v2.0.1→v2.0.2 修订记录（§11.8 与正文一一对应）+ RFC 原文核实（WebFetch RFC 7531 §5.2 open_claim4/openflag4/fattr4/GETATTR4resok、RFC 1813 §2.5/§2.6/§3.3.3 LOOKUP3resok/wcc_data/sattr3）
**结论**：**否（不能直接进入实现阶段）。**

## 一、总体结论

v2.0.2 的 25 项修复中 20 项正确落地（RM 长度、verf 去前缀、sattr3 判别联合、clientid 统一、AcceptState 偏移、wcc_data 92B、MOUNT/opcode 表等），但本次复审发现 **15 个问题：5 CRITICAL + 3 HIGH + 4 MEDIUM + 3 LOW**。

最严重的一类问题性质相同：**r2 复审报告自身有两处 RFC 判断错误（S12 CLAIM_NULL 判为 void、S9 判为缺内层 eof），v2.0.2 未对照 RFC 原文验证，直接按 r2 做了"反向修复"，把原本正确的 wire 格式改错**。经 RFC 7531 §5.2 原文核实，open_claim4 的 CLAIM_NULL 分支**含 component4 file 字段**（r2 判 void 是错的）；经 RFC 1813 §3.3.16 核实，readdir3resok 只有 dirlist3 内层**一个 eof**（r2 补"外层 eof"是错的）。教训：修复必须"以 RFC 为准、以复审报告为参考"，不能以复审报告为准。

另一类 CRITICAL 源于**"合成 reply 简化"与"真实 XDR 编码"混淆**：S11 GETATTR result 的 fattr4 缺 attrlist4 的 4 字节长度前缀（RFC 7531：`struct fattr4 { bitmap4 attrmask; attrlist4 attr_vals; }`，attrlist4 是变长 opaque）；S4 LOOKUP3resok 字段顺序画反（RFC 1813：object (fh) 在前、obj_attributes 在后，且漏 dir_attributes）；S12 的 openhow 把 createmode4 当 openflag4 的判别值写（openflag4 判别是 opentype4，unchecked/guarded/exclusive 是 createhow4 内层的 createmode）。

---

## 二、CRITICAL（5 个）

### C-1. S12 CLAIM_NULL 被判为 void——反向修复，RFC 7531 原文 CLAIM_NULL 分支含 component4 file

**位置**：§6 S12（行 1383-1384、1431）+ §11.8 H-1 修复记录（行 2283）。

**描述**：r2 报告 H-1 断言"open_claim4 的 CLAIM_NULL 分支为 void（仅 4 字节判别值），文档多画了幽灵 component4"；v2.0.2 据此删除了 S12 中 OPEN 的 file 字段，并声明"claim_type @ 0068 后**没有** component4 file 字段（file 名已在 LOOKUP 阶段解析）"。经 WebFetch 核实 RFC 7531 §5.2 原文：

```
union open_claim4 switch (open_claim_type4 claim) {
case CLAIM_NULL:          /* CURRENT_FH: directory */
    component4 file;
case CLAIM_PREVIOUS:
    open_delegation_type4 delegate_type;
case CLAIM_DELEGATE_CUR:
    open_claim_delegate_cur4 delegate_cur_info;
case CLAIM_DELEGATE_PREV:
    component4 file_delegate_prev;
};
```

**CLAIM_NULL 分支非 void，含 component4 file**。文件名由 OPEN 自身携带（RFC 7530 §16.18.2："OPEN with CLAIM_NULL ... the name of the file is in the open_claim4"），与是否先 LOOKUP 无关。v2.0.1 原始版本画了 file 字段（行 1332），在这一点上是**正确**的。r2 的 H-1 是错误判断，v2.0.2 反向修复把正确格式改错。

**影响**：S12 的 OPEN 参数区少画 8 字节（len 4 + 'f' 1 + padding 3），LOCK/LOCKU/CLOSE 全部后续偏移 -8；CALL 长度核算（232B/0xE8）与 RM=0x80000110 全部错误；按文档实现的 OPEN 请求会被真实 v4.0 服务端判为 GARBAGE_ARGS，Wireshark 解析错位。S12 修正后的完整重算见 C-5 末尾统一核算。

**修复建议**：恢复 CLAIM_NULL 的 file 字段（字段名用"component4 file（CLAIM_NULL 分支携带文件名，RFC 7531 §5.2）"），按 C-5 统一核算重排全部偏移；§11.8 H-1 条目改为"r2 报告 H-1 判断错误，v2.0.2 撤销其修复"。

### C-2. S9 "双 eof"是反向修复——readdir3resok 只有 dirlist3 内层一个 eof

**位置**：§6 S9（行 1241-1244、1252）+ §11.8 H-6（行 2288）+ T-059a/T-059b（行 1604-1605）。

**描述**：r2 报告 H-6 声称"S9 缺 dirlist3 内层 eof"，v2.0.2 据此补成**两个** eof（行 1243-1244：dirlist3 eof @ 0084 + resok eof @ 0088）。RFC 1813 §3.3.16/§3.3.17 原文：

```
struct dirlist3 {
    entry3      entries<>;
    bool        eof;
};
struct READDIR3resok {
    post_op_attr      dir_attributes;
    cookieverf3       cookieverf;
    dirlist3          reply;
};
```

READDIR3resok = `post_op_attr + cookieverf + dirlist3`，**只有 dirlist3 内层一个 eof，没有外层 eof**。READDIRPLUS3resok 同理（dirlistplus3{entries<>, eof}）。v2.0.1 原版的单个 eof 是**正确**的；r2 的 H-6 描述（"S9 缺内层 eof"）把正确的单 eof 误当缺失，v2.0.2 又在此基础上加了一层，wire 上凭空多出 4 字节。

**影响**：S9 reply 多算 4 字节（应 128B 不是 132B）；T-059a/T-059b 的"双 eof @ 0084/@ 0088"断言照抄实现将生成 4 字节多余数据；Wireshark 解析 readdir3resok 在 eof 后读到 4 字节垃圾。

**修复建议**：S9 reply 删除外层 eof 行，保留 dirlist3 内层 eof @ 0084（entries length @ 0080、eof @ 0084、reply 止于 0x88）；T-059a/T-059b 删除"双 eof"断言；§11.8 H-6 标注"r2 判断错误，已撤销"。

### C-3. S11 GETATTR result 的 fattr4 编码错误——attrlist4 是变长 opaque，缺 4 字节长度前缀

**位置**：§6 S11 REPLY（行 1331-1339）+ §7.3 T-074（行 1625）+ §11.8 H-4（行 2286）。

**描述**：v2.0.2 按 r2 H-4 把 GETATTR result 展开为"bitmap（3 words 12B）+ size 8B + mode 4B"，并规定"对每个置位属性按 fattr4 的 XDR 编码输出值"。经 WebFetch 核实 RFC 7531 原文：

```
struct fattr4 {
    bitmap4   attrmask;
    attrlist4 attr_vals;    /* typedef opaque attrlist4<>; ——变长 opaque，XDR 带 4 字节长度前缀 */
};
struct GETATTR4resok {
    fattr4 obj_attributes;
};
```

fattr4 = bitmap4 + **attrlist4<>**（4 字节长度前缀 + 属性值字节流 + 对齐填充）。S11 画的 result 缺 attr_vals 的长度前缀 4 字节。FATTR4_SIZE (attr 4) XDR 编码 uint64 8B、FATTR4_MODE (attr 33) uint32 4B，attr_vals 总长 12B，故 GETATTR result 应为：bitmap_len 4 + words 12 + **attr_vals_len 4** + size 8 + mode 4 = **32 字节**，而非文档的 28 字节。

**影响**：S11 REPLY RM 0x80000050 (80) 应改为 **0x80000054 (84)**；HexDump 在 0048 处缺 attr_vals_len 行，size 应 @ 004C-0053、mode @ 0054-0057；T-074 "完整 reply RM=0x80000050" 断言错误。照文档实现，Wireshark NFSv4 dissector 会把 size 值的前 4 字节误读为 attrlist 长度，属性解析错乱。

**修复建议**：S11 REPLY 在 bitmap（0x38-0x47）后补 `attr_vals length=12 (0x0000000C)` @ 0048 行，size @ 004C、mode @ 0054；REPLY 总长 84B，RM=0x80000054；T-074 同步；§2.7 增加"fattr4 编码 = bitmap4 + attrlist4<>（变长带长度前缀）"通用定义。

### C-4. S4 LOOKUP3resok 字段顺序画反——fh 在前、obj_attributes 在后，且漏 dir_attributes

**位置**：§6 S4 REPLY（行 1082-1090）+ T-037（行 1581）。

**描述**：S4 的 LOOKUP reply 画成 `status → post_op_obj_attr (fattr3 88B) → post_op_fh3 (fh)`。经 WebFetch 核实 RFC 1813 §3.3.3 原文：

```
struct LOOKUP3resok {
    nfs_fh3      object;
    post_op_attr obj_attributes;
    post_op_attr dir_attributes;
};
```

**顺序是 fh (object) 在前、属性在后**，且 resok 还有第三个字段 dir_attributes。S4 恰好画反（属性在前、fh 在后），并漏掉 dir_attributes。注意 object 是裸 nfs_fh3（长度前缀+数据），不是 post_op_fh3 联合。

**影响**：S4 reply 字节序列错误（fh 块与 attrs 块互换位置）；若照 S4 实现，Wireshark 解析 LOOKUP reply 直接错位。T-037 只断言"fh len>0 + post_op_attr present"未断言顺序，掩盖了该错误。

**修复建议**：S4 REPLY 重排：status 4B @ 001C → object（fh_len 4 + fh_data 4，共 8B）@ 0020-0027 → obj_attributes（判别 4B @ 0028 + fattr3 84B @ 002C-007F）→ dir_attributes（判别 4B @ 0080，简化合成时 =0 不 follow）。REPLY 总长 = 24+4+8+88+4 = 128B；T-037 补"fh 在 obj_attributes 之前"顺序断言；§2.2 LOOKUP 关键返回改为 "filehandle, post_op_obj_attr, post_op_dir_attr"。

### C-5. S12 openhow 编码错误——openflag4 判别是 opentype4 不是 createmode4；T-084 会写出非法 opentype=2；且缺 createattrs

**位置**：§6 S12（行 1381-1383）+ §3.3 NFSOpenHow（行 631-636）+ T-082~T-084（行 1633-1635）。

**描述**：经 WebFetch 核实 RFC 7531 §5.2 原文：

```
union openflag4 switch (opentype4 opentype) {
case OPEN4_CREATE:
    createhow4     how;
default:            /* OPEN4_NOCREATE */
    void;
};
union createhow4 switch (createmode4 mode) {
case UNCHECKED4:
case GUARDED4:
    fattr4         createattrs;
case EXCLUSIVE4:
    verifier4      createverf;
};
```

openflag4 的判别字段是 **opentype4**（OPEN4_NOCREATE=0 / OPEN4_CREATE=1）；"unchecked/guarded/exclusive" 是**内层 createhow4** 的 createmode4 值（0/1/2），不能直接当 openflag4 判别写。文档的 NFSOpenHow 模型把两者合并：S12 在 openhow 位置只写 `00 00 00 00  createmode=0 (UNCHECKED4)`——这 4 字节在 wire 上是 **opentype=0 (OPEN4_NOCREATE)**，与配置 "type:unchecked"（本意是 create 语义）矛盾，只是字节恰好以 UNCHECKED4=0=NOCREATE 对齐而"看起来能解析"；T-083 guarded 会写出 opentype=1 (OPEN4_CREATE) 后缺 createhow4、claim 位置错位；T-084 exclusive 会写出 **非法 opentype=2**（opentype4 只有 0/1），XDR 解码必然失败。

**影响**：S12 openhow 块语义错误；T-082~T-084 的字节断言建立在错误模型上，照实现 T-084 的 EXCLUSIVE 场景 wire 上是不存在的 opentype 值。

**修复建议**：NFSOpenHow 增加 opentype 语义（或约定：type="unchecked/guarded/exclusive" → opentype=1 (OPEN4_CREATE) + createhow4{mode, createattrs/createverf}；新增 type="nocreate" → opentype=0 无 how）。S12 的 openhow 块应为：opentype=1 @ 0064 + createmode=0 (UNCHECKED4) @ 0068 + createattrs（空 fattr4 = bitmap_len 0 @ 006C + attr_vals_len 0 @ 0070，共 8B）→ 16 字节；T-082~T-084 断言同步改为 opentype 判别 + createmode + createattrs 字节。

**S12 修正后完整重算（C-1 + C-5 统一核算）**：

```
0028  tag len=0          4B
002C  minorversion=0     4B
0030  argarray len=7     4B
0034  op#1 PUTROOTFH     4B
0038  op#2 LOOKUP: opcode 4B + name len 4B + 'f' 1B + pad 3B    （12B，至 0x43）
0044  op#3 OPEN:  opcode 4B
0048    seqid=1 4B
004C    share_access=2 4B
0050    share_deny=0 4B
0054    owner: clientid 8B (0x54-0x5B) + owner len=1 4B (0x5C) + 0x01+pad 4B (0x60-0x63)
0064    openhow: opentype=1 (OPEN4_CREATE) 4B
0068      createmode=0 (UNCHECKED4) 4B
006C      createattrs: bitmap_len=0 4B + attr_vals_len=0 4B
0074    claim: claim_type=0 (CLAIM_NULL) 4B
0078      file: len=1 4B + 'f' 1B + pad 3B（0x7C-0x7F）
      OPEN 块共 60B（0x44-0x80）
0080  op#4 OPEN_CONFIRM: opcode 4B + open_stateid 16B (0x84-0x93) + seqid=2 4B (0x94)  （至 0x97）
0098  op#5 LOCK: opcode 4B + lock_type 4B + reclaim 4B + offset 8B + length 8B
00B4    new_lock_owner=1 4B + open_seqid=2 4B (0xB8) + open_stateid 16B (0xBC-0xCB)
00CC    lock_seqid=1 4B + lock_owner clientid 8B (0xD0) + owner len 4B (0xD8) + 0x01+pad (0xDC-0xDF)
      （72B，至 0xDF）
00E0  op#6 LOCKU: opcode 4B + lock_type 4B + seqid=2 4B (0xE8) + stateid 16B (0xEC-0xFB)
00FC    offset 8B + length 8B（至 0x10B）
010C  op#7 CLOSE: opcode 4B + seqid=3 4B (0x110) + open_stateid 16B (0x114-0x123)
```

COMPOUND body = 0x28→0x124 = **252B**；CALL 总长 = 40 + 252 = **292 = 0x124**；**RM = 0x80000124**。LOCK 的 open_seqid=2、CLOSE seqid=3 与 OPEN_CONFIRM 补全逻辑（§4.1 规则 3）不变。

---

## 三、HIGH（3 个）

### H-1. T-033 期望与 §2.8 time_how 映射规则直接矛盾

**位置**：§7.2 T-033（行 1575）+ §2.8（行 373）+ T-034（行 1576）。

**描述**：§2.8 映射规则："SetAtime=true 且 AtimeSecs=0xFFFFFFFF **或未显式提供** → time_how=1 (SET_TO_SERVER_TIME)"。但 T-033 写"set_atime=true, atime_secs 未提供（默认 0 不触发 SET_TO_CLIENT_TIME）→ set_atime=00 (DONT_CHANGE)"——**"未提供"按 §2.8 应映射 time_how=1，T-033 却断言 0**。T-034（atime_secs=0xFFFFFFFF → 1）与 T-033（未提供 → 0）在 §2.8 中属同一分支（都映射 1），两条测试期望互相矛盾。实现者无法同时满足 §2.8 与 T-033；按 §2.8 实现则 T-033 必失败。

**依据**：§2.8 行 373 原文 vs T-033 行 1575 原文；RFC 1813 time_how 语义（0=DONT_CHANGE 表示"不设置"，与 set_atime=true 的本意相悖）。

**修复建议**：二选一，必须让 §2.8 与 T-033/T-034 自洽：(a) 推荐——"SetAtime=true 且 AtimeSecs 未提供 → time_how=1"，T-033 期望改 01；(b) 或在 §2.8 增加"AtimeSecs 显式提供为 0 时 → time_how=2 (SET_TO_CLIENT_TIME, secs=0)"分支，使"未提供→DONT_CHANGE、显式 0→CLIENT_TIME"成立。

### H-2. T-155 顶层 status 的 hex 值错误：10025 = 0x2729，文档写 0x00002719

**位置**：§7.6 T-155（行 1721）+ §11.8 L-5（行 2314）。

**描述**：T-155 断言"顶层 status=000027 19（=失败 op 的 OpStatus 10025）"。10025 decimal = 0x2729（0x2700=9984，10025-9984=41=0x29）。文档自己在 §2.9（行 403）写 NFS4ERR_BAD_STATEID=10025，T-170（行 1736）断言 00002729 正确——T-155 的 0x2719 是笔误。§11.8 L-5 声称"T-155 补断言顶层 status"，补的却是错值。

**影响**：照 T-155 实现的测试断言必失败（或实现者反向输出 0x2719，产生错误 wire 字节）。同类 100xx 的 hex 均已核对：10018=0x2722、10019=0x2723、10020=0x2724（T-168/169/170 正确），仅 T-155 错。

**修复建议**：T-155 断言改为 00002729。

### H-3. T-080/T-081 只断言联合判别值，未断言分支字段字节——CLAIM_DELEGATE_CUR/PREV 的实现缺陷无法被测出

**位置**：§7.3 T-080（行 1631）、T-081（行 1632）。

**描述**：T-079（CLAIM_PREVIOUS）断言了 discriminator + delegate_type 两个字节（好）；T-080 只断言 discriminator=02，未断言 delegate_cur_info（delegate_stateid4 16B + component4 file 的字节）；T-081 只断言 discriminator=03，未断言 file_delegate_prev（component4 的字节）。按 CLAUDE.md §Testing Policy 规则 5（断言可观察输出），联合分支的 branch 字段是 wire 上真实存在的字节，必须逐一断言。

**依据**：RFC 7531 §5.2 open_claim4（CLAIM_DELEGATE_CUR: delegate_cur_info = delegate_stateid4 + component4；CLAIM_DELEGATE_PREV: component4 file_delegate_prev）。

**影响**：实现时若 CLAIM_DELEGATE_CUR 漏编码 delegate_stateid 或 file，测试全绿但 wire 错误——正是 CLAUDE.md 反复强调的"测试通过但测错东西"模式。

**修复建议**：T-080 补断言"claim=02 后含 delegate_stateid 16B（seqid+other12）+ file 的 len+data+pad"；T-081 补断言"claim=03 后含 file 的 len+data+pad"；并建议为三个非默认 claim 分支补一个 HexDump 场景（S16）。

---

## 四、MEDIUM（4 个）

### M-1. §9.1 MSG_DENIED 布局中 RPC_MISMATCH 的 low/high 语义未标注；T-163 未断言"low/high=服务端支持的版本范围"这一 RFC 语义

**位置**：§9.1（行 1883-1887）+ T-163（行 1729）+ §1.3（行 73-76）。

**描述**：字节布局本身正确（RejectState @ 12 后，RPC_MISMATCH 附带 low/high 4B+4B；AUTH_ERROR 附带 auth_stat 4B）。但 RFC 5531 §8 中 low/high 是**服务端支持的 RPC 版本范围**（reject 表示"服务端只支持 low..high"，客户端版本不在其中），T-163 断言"low=2；high=2"却未说明该语义，实现者可能把 low/high 当任意可注入值。此外 §1.3 的行 75 把 low/high 与 auth_stat 并列为 `[if ...]` 分支，未解释两者互斥（一个 RPC_MISMATCH 分支就没有 auth_stat）。

**修复建议**：T-163 期望列补"low/high = 服务端支持的 RPC 版本范围（RFC 5531 §8），注入 low=high=2 表示仅支持 v2"；§1.3 补"RPC_MISMATCH 与 AUTH_ERROR 分支互斥"。

### M-2. §4.3 与 §10.4 对 SETCLIENTID reply 的 clientid 取值来源规定不一致

**位置**：§4.3 规则 3（行 852）+ §10.4（行 2090）。

**描述**：§10.4 说"每会话的 SETCLIENTID reply 返回的 clientid 即为该会话的默认 clientid；user 显式配置 clientid≠0 时使用 user 值"。§4.3 规则 3 只规定 call 侧（"op 内 clientid=0 视为按会话分配"），未说明 SETCLIENTID **reply** 的 clientid 字段在 user 显式配置时回显 user 值还是默认公式。合成流量中 reply 由 Plan 生成，该取值必须唯一确定。

**修复建议**：§4.3 规则 3 补一句"SETCLIENTID reply 的 clientid 合成规则同 call 侧：user 显式配置该会话 clientid 时 reply 回显 user 值，否则用默认公式"，与 §10.4 对齐。

### M-3. §6 S12 与 T-091 未定义 OPEN reply 的合成 stateid（OPEN_CONFIRM/CLOSE 全 0 的来源）

**位置**：§6 S12（行 1388-1389、1422-1423）+ §4.1 规则 3（行 771）。

**描述**：S12 的 OPEN_CONFIRM open_stateid 画全 0、CLOSE open_stateid 画全 0，§4.1 规则 3 说 OPEN_CONFIRM 的 open_stateid"取自 OPEN reply 的合成值"，但 S12 未定义 OPEN reply 的 stateid 合成规则（§3.5 OpenReplyStateid 机制在 S12 未使用）。§9.5 #2 已登记"不模拟服务端递增 stateid"，但缺一句"未配置 OpenReplyStateid 时 OPEN reply 的 stateid 全 0"的明确声明。

**修复建议**：S12 增加说明"OPEN reply 合成 stateid：未配置 OpenReplyStateid → 全 0 回显（§3.5/§9.5 #2）"，使 OPEN_CONFIRM/CLOSE 的全 0 字节有依据。

### M-4. T-074 的 GETATTR reply 断言与 S11 的"回显 call 3 words 12B"规则在 attrmask 尾部 0 word 场景上不自洽

**位置**：§7.3 T-074（行 1625）+ §6 S11（行 1341）+ T-140（行 1701）。

**描述**：S11 的合成规则说"bitmap 回显 call 的 attr_mask（含尾部 0 word 时保留原样，见 §7.5 T-140）"。T-074 输入 attr_mask=[0x10,0x02,0]（3 words），断言"bitmap（回显 call 3 words 12B）+ size(8B)+mode(4B)"——方向正确。但 T-074 没断言 bitmap 三个 word 的值（word2=0 是否保留），且 reply RM=0x80000050 依赖"无 attr_vals_len"的错误布局（见 C-3）。两条规则（T-140 保留尾部 0 word vs GETATTR reply 只回显 call words）在"call 配置 2 words、服务端合成 3 words"之类场景的裁剪边界未定义。

**修复建议**：T-074 补断言"bitmap words = 0x10,0x02,0（与 call 一致，含尾部 0 word）"；在 §6 合成规则中明确"GETATTR reply 的 bitmap 严格回显 call 的 attr_mask 全部 word（含尾部 0）"。

---

## 五、LOW（3 个）

### L-1. §11.1 的 "CredBody=36+" 与修订记录 "40 字节头" 表述并存，args 起点易误算

**位置**：§11.1 C-1（行 2164）+ §11.8 C-1（行 2273）+ §7.1（行 1532）。

**描述**：§11.1 说"CALL 偏移：... CredFlavor=28、CredLen=32、CredBody=36+"——正确（空 cred/verf 时 CredBody @ 36、VerfFlavor @ 36、VerfLen @ 40、args 从 44=0x2C 起）；§11.8 说"S4-S10/S12 CALL args 偏移统一按 RPC 头 40 字节重排（args 从 0028 起）"——也正确（空 auth 时头恰 40B=0x28）。两者数字一致，但"36+"与"40 字节"两种表述并存，读者易把 args 起点误算为 36。§7.1 行 1532 的偏移序列（CredBody=36、VerfFlavor、VerfLen、VerfBody）与本段同理。

**修复建议**：§11.1 补一句"空 cred/verf 时 RPC 头共 40 字节（CredBody=36、VerfFlavor=36、VerfLen=40、args=44）"，统一表述。

### L-2. §2.9 NFSv4 错误码表缺常用码（NFS4ERR_DELAY=10008、NFS4ERR_NOT_SAME=10027 已有但缺 READDIR 场景用例）

**位置**：§2.9（行 379-414）+ §9.3（行 1916-1940）。

**描述**：NFS4ERR_NOT_SAME=10027（cookieverf 不匹配）已列入表（行 401），但 §9.3 业务错误表没有对应行、测试没有对应用例（cookieverf 不匹配是 READDIR 最常见错误）；NFS4ERR_DELAY=10008、NFS4ERR_RETRY_UNCACHED_REP=10009 等 v4.0 常用码未列入。不阻塞实现，属完整性建议。

**修复建议**：§9.3 补 NFS4ERR_NOT_SAME=10027（READDIR cookieverf 不匹配）行及对应测试；§2.9 补 NFS4ERR_DELAY=10008。

### L-3. S5 的 fattr3 标注"84B/88B"表述分裂（v2.0.1 L1 修复残留）

**位置**：§6 S5（行 1115 vs 1126）、S2（行 1018 vs 1021）、S4（行 1084 vs 1090）。

**描述**：三处 reply 既标注 `[84 bytes fattr3]` 又标注 post_op_attr"判别 4B + fattr3 84B = 88B"。两者数学上一致，但"84B"与"88B"两种写法并存，实现者易在计算后续字段（count @ 0078、fh @ 0080）偏移时少加判别值 4B。

**修复建议**：统一表述为"post_op_attr = 判别 4B + fattr3 84B = 88B"，避免单独标注 [84 bytes]。

---

## 六、v2.0.2 修复正确性核对（25 项逐项，依据 RFC 原文）

| r2 编号 | v2.0.2 修复 | 核对结果 |
|---------|------------|----------|
| C-1 RM 长度重算 | S1 CALL 40B/RM=0x28、S1 REPLY 24B/RM=0x18、S2 CALL 48B/RM=0x30 | ✅ 正确（§6 核算无误；T-001/T-002 同步） |
| C-2 verf 去长度前缀 | S6/S10 verf 8B 定长无前缀 | ✅ 正确（RFC 1813 writeverf3=opaque[8]） |
| C-3 sattr3 判别联合 | §2.8 + S3/S7 28B + T-029~T-035 | ✅ 正确（RFC 1813 §2.6 核实：bool 判别 false=void、time_how 0/1/2 语义准确） |
| C-3b AcceptState @ 24 | §7.1/T-002/T-158/§10.2 改 24+verf_len | ✅ 正确（空 verifier 时 AcceptState @ 24；T-158 的 @ 18-1B 与 @ 24 表述自洽） |
| C-4 clientid 统一 | §4.3/§10.4/S13/T-106/T-177 = 0x10001/0x20001/0x30001 | ✅ 正确（三处一致；T-179 0-based client.id 一致） |
| H-1 S12 幽灵 component4 | 删除 4B claim file 字段 | ❌ **反向修复**（见 C-1）——CLAIM_NULL 分支实含 component4 file，应恢复 |
| H-2 S9 cookieverf 一致性 | call/reply 均 8×00 | ✅ 正确（Config "AAAAAAAAAAA=" 解码 8×00，回显一致） |
| H-3 wcc_data 92B | §2.8 + S6/S7/S8/S10 统一 | ✅ 正确（pre 判别 4 + post 判别 4 + fattr3 84 = 92；RFC 1813 wcc_data 结构核实一致） |
| H-4 S11 GETATTR result | 展开 bitmap+size+mode，RM=0x50 | ⚠️ 部分错误（见 C-3）——fattr4 的 attrlist4 缺 4B 长度前缀，RM 应为 0x54 |
| H-5 AcceptState 偏移 | 同 C-3b | ✅ 正确 |
| H-6 S9 双 eof | 补 dirlist3 eof @ 0084 + resok eof @ 0088 | ❌ **反向修复**（见 C-2）——readdir3resok 只有 dirlist3 一个 eof，v2.0.1 原版正确 |
| H-7 S12 OPEN_CONFIRM 补全 | argarray=7、open_seqid=2、CLOSE seqid=3 | ✅ 方向正确（§4.1 规则 3 自洽）；受 C-1/C-5 影响偏移需按新核算重排 |
| M-1 0/1/2 未分配 | §2.5 措辞 | ✅ 正确 |
| M-2 opcode 40 行 | §2.5 补 40=WANT_DELEGATION | ✅ 正确（RFC 5661 核实 40=WANT_DELEGATION） |
| M-3 client.id 0-based | S13/T-179 | ✅ 正确 |
| M-4 T-148 补 rpc_accept_state | §9.4 示例 2 | ✅ 正确 |
| M-5 READ 返回顺序 | §2.2 post_op_attr,count,eof,data | ✅ 正确（RFC 1813 read3resok 核实） |
| M-6 PROG_MISMATCH low/high | §9.1 布局 + T-159 | ✅ 字节正确（语义标注见 M-1） |
| M-7 bitmap 尾部 0 word | T-140 保留原样 | ✅ 正确（S11 回显规则见 M-4 细化建议） |
| M-8 V23a count=len(data) | T-047a | ✅ 正确 |
| M-9 ResultStatus 完整 resarray | §2.7/§9.2/T-151 | ✅ 正确 |
| M-10 OpenReplyStateid 机制 | §3.5/§4.1 | ✅ 定义清晰（S12 应用说明见 M-3） |
| L-1 CredLen 进制 | T-006/T-193 | ✅ 正确 |
| L-2 reply 时间戳 | §5.6 | ✅ 正确 |
| L-3 MOUNT proc=0 | §4.2 规则 5 | ✅ 正确 |
| L-4 opcode 40 行 | 同 M-2 | ✅ 正确 |
| L-5 T-155 顶层 status | 补 0x2719 | ❌ **值错误**（见 H-2）——10025=0x2729 非 0x2719 |

**核对统计**：25 项中 ✅ 20 项、❌ 3 项（H-1/H-6 反向修复、L-5 值错）、⚠️ 2 项（H-4 部分错误、H-7 方向对但受 C-1/C-5 牵连需重算偏移）。

---

## 七、测试用例与 CLAUDE.md §Testing Policy 合规性

**整体评价**：v2.0.2 的 200 条用例结构明显改善——负向测试约 20 条（T-011/012/026/028/040/047a/050/065/068/133~136/141/149/175/184/199 等）、边界值（T-016/017/120/187~190）、集成路径（T-191~T-200 含 PCAP/tshark/broken-spec 失败断言）。多数用例与 spec 行对应。

**不符合项**：

1. **T-033 vs §2.8 矛盾（规则 1：spec 驱动）**：测试期望与它声称覆盖的映射规则冲突（H-1）。
2. **T-155 断言值错误（规则 5：断言可观察输出）**：0x2719 ≠ 10025 的 hex 0x2729（H-2）。
3. **T-080/T-081 断言不全（规则 5）**：只断言联合判别值，不验证分支字段字节（H-3）。
4. **T-082~T-084 模型错误（规则 1/5）**：openflag4 判别写成 createmode，T-084 会断言非法 opentype=2（C-5）。
5. **正例缺失（规则 3：每个代码路径）**：§4.1 规则 2（PUTROOTFH 自动补全）无正例测试（T-154 是故意不补的错误路径）；§4.2 规则 1/5（MOUNT/UMOUNT 显式配置不重复插入）无测试；S12 的 OPEN_CONFIRM 补全场景（T-091）只断言 opcode 未断言 open_seqid 联动。
6. **S12 无 reply HexDump（规则 4：集成）**：S12 只画 CALL，COMPOUND reply（OPEN_CONFIRM 的 stateid 合成、CLOSE 的 final stateid）无字节级场景。
7. **sattr3 分支覆盖好但 time_how=2 的 nfstime3 值未与 §2.8 的 Secs/Nsecs 映射对照**：T-035 断言 secs=499602D2（=1234567890 的 hex，正确），nsecs 默认 0 也写了——这条合格。但 T-035 未断言"time_how=2 时 nfstime3 8B 紧随判别值之后、无其他字段"，可补。

---

## 八、HexDump 自洽性总检

| 场景 | 长度核算 | RM | 结论 |
|------|----------|-----|------|
| S1 CALL | 40B（无 body） | 0x28 | ✅ |
| S1 REPLY | 24B | 0x18 | ✅ |
| S2 CALL | 40+8=48B | 0x30 | ✅ |
| S2 REPLY | 24+4+88=116B | 0x74 | ✅ |
| S3 CALL | 40+8+28+4=80B | （未标） | ✅ 核算正确；sattrguard3 @ 004C 正确 |
| S4 CALL | 40+8+8+4=60B | （未标） | ✅；REPLY 字段顺序 ❌（C-4） |
| S5 CALL | 40+8+8+4=60B | （未标） | ✅；REPLY 标注表述分裂（L-3） |
| S6 CALL | 40+8+8+4+4+8=72B | （未标） | ✅ |
| S6 REPLY | 24+4+92+4+4+8=136B | （未标） | ✅ 偏移 007C 正确 |
| S7 CALL | 40+8+8+28=84B | （未标） | ✅ |
| S7 REPLY | 24+4+4+8+4+88+92=224B | （未标） | ✅ 偏移 0084/00E0 正确 |
| S8 CALL | 40+8+8+4=60B | （未标） | ✅；REPLY 无字段细节（可接受） |
| S9 CALL | 40+8+8+8+4+4=72B | （未标） | ✅ |
| S9 REPLY | 24+4+88+8+4+4=132B | （未标） | ❌ 外层 eof 多 4B，应 128B（C-2） |
| S10 CALL | 40+8+8+4=60B | （未标） | ✅ |
| S10 REPLY | 24+4+92+8=128B | （未标） | ✅ 偏移 007C 正确 |
| S11 CALL | 40+36=76B | 0x4C | ✅ |
| S11 REPLY | 24+28+28=80B | 0x50 | ❌ 应 84B/0x54（C-3） |
| S12 CALL | 40+232=272B | 0x110 | ❌ 缺 CLAIM_NULL file 8B + openhow 模型错，应 292B/0x124（C-1+C-5） |
| S13 | 多会话表 | — | ✅ 4-tuple/clientid 表自洽 |
| S14 CALL | 40+24=64B（+COMPOUND body） | 0x40 | ✅ Cred 核算正确 |
| S15 REPLY | 24+20=44B | 0x2C | ✅ 截断规则正确 |

---

## 九、其他复核要点（未发现问题的项）

1. **MOUNT 协议**：§2.3 表（0-5）与 RFC 1813 附录 I 一致；PATHCHK 是 NFSv2 时代 procedure 6 的说明正确。
2. **MOUNT/NFS 同连接**：§4.2 规则 4 + §9.5 #1 登记为已知偏离，处理恰当。
3. **RPC CALL/REPLY 头部布局**：§1.3 与 RFC 5531 §8 一致（XID/Type/RPCVer/Program/Version/Procedure/Cred/Verf；REPLY 的 MSG_ACCEPTED/MSG_DENIED 分支正确）。
4. **TCP RecordMark**：位 31=LAST、0x80000000|len 语义正确（RFC 5531 §11.B）。
5. **stateid4 特殊值**：anonymous（seqid=0+12×00）与 READ bypass（全 FF）字节精确（RFC 7530 §9.1.4.3）。
6. **fattr3 84 字节**：RFC 1813 fattr3 字段序列核实一致（type/mode/nlink/uid/gid/size/used/rdev/fsid/fileid/atime/mtime/ctime；nfstime3=8B）。
7. **wcc_data 92B**：§2.8 结构定义与 RFC 1813 一致，合成策略 92B 自洽。
8. **opcode 表**：38=WRITE、39=RELEASE_LOCKOWNER、40=WANT_DELEGATION、41=BIND_CONN_TO_SESSION、42=EXCHANGE_ID、43=CREATE_SESSION、44=DESTROY_SESSION 全部核实正确。
9. **COMPOUND 编码**：CALL tag→minorversion→argarray、REPLY status→tag→resarray 的非对称与 RFC 7531 §5.2/§15.2.3 一致。
10. **S15 错误场景**：顶层 status=10020、resarray 截断至失败 op、无 result——均正确（RFC 7530 COMPOUND 失败语义）。
11. **T-141/T-142 UDP 65507 边界**：65535-20-8=65507 计算正确，正负边界都有。
12. **Validate 规则 38 条**：V1-V38 与正文引用一致，错误消息与 T 用例引用一致（除 T-155 值错外）。
13. **§9.5 已知偏离**：10 项与实现边界（§1.4）一致，登记完整。
14. **sattr3 判别联合修复质量高**：§2.8 的定义、长度核算（全 false=24B、仅 set_mode=true=28B）、S3/S7 的 28 字节展开、T-029~T-035 的逐分支断言，与 RFC 1813 §2.6 完全一致，是本次修复中最扎实的一项。

---

## 十、修复优先级建议

**必须修复（阻塞实现）**：

1. **C-1**：恢复 S12 CLAIM_NULL 的 component4 file，按 C-5 末尾的统一核算重排全部偏移与 RM。
2. **C-2**：删除 S9 外层 eof，恢复单 eof（entries length @ 0080、eof @ 0084）。
3. **C-3**：S11 GETATTR result 补 attrlist4 长度前缀（4B），RM 0x50→0x54，T-074 同步。
4. **C-4**：S4 LOOKUP reply 重排为 fh→obj_attributes→dir_attributes。
5. **C-5**：openhow 编码改为 opentype4 判别 + createhow4（unchecked/guarded 带 createattrs fattr4，exclusive 带 verifier4），T-082~T-084 同步。
6. **H-2**：T-155 的 0x2719→0x2729。

**建议修复（高优先级）**：H-1（T-033 与 §2.8 的 time_how 映射矛盾二选一）、H-3（T-080/T-081 补分支字段断言）、M-2（§4.3 reply clientid 取值）、M-3（S12 OPEN reply stateid 合成说明）。

**可选**：M-1（T-163 语义注释）、M-4（T-074 bitmap 回显断言）、L-1~L-3（表述与表补充）。

**修复后复核要求**：S12 偏移重排后需重新核对 OPEN_CONFIRM/LOCK/LOCKU/CLOSE 全部偏移与 argarray=7 的字节级核算；S11 改 84B 后核对 T-074 的 RM 断言与 §11.8 H-4 描述；S4 重排后核对 T-037 断言。**强烈建议**：对 r2 报告中所有"新发现"先对照 RFC 原文验证再动手——本次 C-1/C-2 两个反向修复的教训，应写入本项目的修订流程。

---

## 十一、问题汇总

**共 15 个问题：5 CRITICAL + 3 HIGH + 4 MEDIUM + 3 LOW**

| 严重度 | 编号 | 位置 | 摘要 |
|--------|------|------|------|
| CRITICAL | C-1 | §6 S12 | open_claim4 CLAIM_NULL 分支实含 component4 file，v2.0.2 按 r2 误判删除（反向修复）；偏移/RM 全错 |
| CRITICAL | C-2 | §6 S9 | readdir3resok 仅一个 eof（dirlist3 内层），v2.0.2 补的"外层 eof"是反向修复，wire 多 4B |
| CRITICAL | C-3 | §6 S11 | fattr4 的 attrlist4 是变长 opaque 需 4B 长度前缀，S11 缺，RM 0x50→0x54 |
| CRITICAL | C-4 | §6 S4 | LOOKUP3resok 字段顺序画反（fh 应在 attrs 前），且漏 dir_attributes |
| CRITICAL | C-5 | §6 S12/T-084 | openflag4 判别是 opentype4 非 createmode4；unchecked/guarded 缺 createattrs，exclusive 写出非法 opentype=2 |
| HIGH | H-1 | §7.2 T-033 | T-033 与 §2.8 time_how 映射规则直接矛盾（未提供→0 vs →1） |
| HIGH | H-2 | §7.6 T-155 | 10025 的 hex 写 0x2719，应为 0x2729 |
| HIGH | H-3 | §7.3 T-080/081 | 联合分支字段字节（delegate_stateid/file）无断言，实现缺陷无法被测出 |
| MEDIUM | M-1 | §9.1/T-163 | RPC_MISMATCH 的 low/high 版本范围语义未文档化 |
| MEDIUM | M-2 | §4.3/§10.4 | SETCLIENTID reply 的 clientid 取值来源两处规定不一致 |
| MEDIUM | M-3 | §6 S12 | OPEN reply 合成 stateid（OPEN_CONFIRM/CLOSE 全 0）来源未声明 |
| MEDIUM | M-4 | §7.3 T-074 | bitmap 回显规则（含尾部 0 word）在 T-074 未断言，与 T-140 联动边界未定义 |
| LOW | L-1 | §11.1/§11.8 | "CredBody=36+"与"40 字节头"表述并存，args 起点易误算 |
| LOW | L-2 | §2.9/§9.3 | 错误码表缺 NFS4ERR_DELAY=10008；NOT_SAME=10027 无对应测试 |
| LOW | L-3 | §6 S5/S2/S4 | fattr3 "84B/88B"表述分裂，偏移核算易错 |

**25 项修复核对**：20 项正确，3 项错误（H-1/H-6 反向修复、L-5 值错），2 项部分/受牵连（H-4、H-7）。
