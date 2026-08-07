# NFS 协议设计与测试用例（v2.0.4）

**协议**：NFS（Network File System，网络文件系统）
**规范来源**：RFC 7530 (NFSv4.0) / RFC 7531 (NFSv4.0 XDR) / RFC 1813 (NFSv3) / RFC 5531 (ONC RPC) / RFC 5665 (NFSv4.1，仅对照参考)
**默认端口**：2049 (TCP，NFSv3 也可用 UDP)
**版本**：v2.0.4
**未实现协议清单节点**：`nfsProtRpt`（扩展表 #8）
**文档目的**：为 trafficgen 项目实现 NFS 协议 Planner 提供完整设计依据、Config 字段表、状态机、Plan 输出规则、15 个 HexDump 逐字节场景与 200+ 条测试用例。本文档不包含实现代码。

---

## 1. 协议概述

### 1.1 协议定位

NFS 是分布式文件系统协议，客户端通过 RPC（Remote Procedure Call，远程过程调用）框架向服务端发起文件操作请求，服务端返回结果。NFS 不直接承载于 TCP/UDP 之上，而是先封装在 ONC RPC (RFC 5531) 帧内，RPC 帧再封装在 TCP 字节流（使用 4 字节记录标记 Record Mark）或 UDP 数据报中。

NFS 在 trafficgen 中归属"文件传输/共享"业务领域。一个 NFS 流量场景通常包含：

1. **MOUNT 阶段（仅 NFSv3）**：客户端通过 MOUNT 协议（Program 100005）获取文件句柄 filehandle。
2. **NFS 操作阶段**：客户端通过 NFS 协议（Program 100003）执行 GETATTR / LOOKUP / READ / WRITE / CREATE / REMOVE / RENAME / READDIR 等操作。
3. **UMOUNT 阶段（仅 NFSv3）**：客户端卸载挂载点。
4. **状态机阶段（仅 NFSv4.0）**：客户端通过 SET_CLIENTID → SET_CLIENTID_CONFIRM 建立客户端身份（RFC 7530 §16.33/§16.34），PUTROOTFH/PUTFH 设置当前文件句柄，COMPOUND 内串行执行多个 operation。v4.0 没有会话机制（CREATE_SESSION/DESTROY_SESSION 是 v4.1 操作，opcode 43/44），会话拆除由 TCP FIN 表达；RENEW（opcode 29，维持 lease）仅由 user 显式配置，本设计不自动补全。

> **版本决策**：本文档严格遵循 **NFSv4.0 (RFC 7530)**。不使用 EXCHANGE_ID/CREATE_SESSION/DESTROY_SESSION（这些是 NFSv4.1 RFC 5661 引入的操作）。NFSv4.0 的客户端身份由 SET_CLIENTID → SET_CLIENTID_CONFIRM 建立，clientid 由服务端在 SET_CLIENTID reply 中分配。COMPOUND minorversion 恒为 0。NFSv4.1+ 操作（opcode 40+）不在自动补全流程中使用。

### 1.2 NFSv3 / NFSv4.0 / NFSv4.1 对比

| 维度 | NFSv3 (RFC 1813) | NFSv4.0 (RFC 7530/7531) | NFSv4.1 (RFC 5661/5665) |
|------|------------------|--------------------------|--------------------------|
| 传输层 | TCP 或 UDP，端口 2049 | 仅 TCP，端口 2049 | 仅 TCP，端口 2049 |
| 状态 | 无状态（stateless），服务端不保留客户端状态 | 有状态（stateful），clientid / stateid / seqid | 有状态 + 会话（session） |
| 文件句柄来源 | 由 MOUNT 协议（Program 100005）返回 | 由 LOOKUP / OPEN 等 operation 在 COMPOUND 内返回 | 同 v4.0 |
| Procedure 模型 | 一请求一 procedure（如 READ 是一个独立 RPC call） | 一请求一 COMPOUND，COMPOUND 内可串行多个 operation | 同 v4.0 + 复合操作 |
| 锁模型 | 由独立 NLM 协议（Program 100021）实现 | 内建 LOCK / LOCKT / LOCKU operation | 同 v4.0 |
| 鉴权 | RPC auth_sys (UNIX) 或 auth_none | RPC auth_sys / auth_none / RPCSEC_GSS | 同 v4.0 + 更强 GSS 集成 |
| 客户端身份 | 无 | SET_CLIENTID / SET_CLIENTID_CONFIRM | EXCHANGE_ID / CREATE_SESSION |
| 会话机制 | 无 | 无 | 有（CREATE_SESSION/DESTROY_SESSION） |
| 字符编码 | 文件名按字节处理 | 文件名 UTF-8 (RFC 7530 §14) | 同 v4.0 |
| 挂载协议 | 必需（MOUNT 协议） | 不需要（内建于 PUTFH/PUTROOTFH） | 同 v4.0 |
| 本文档支持 | **完整支持** | **完整支持（本设计主线）** | **仅对照参考，不实现** |

### 1.3 RPC 层（RFC 5531）通用规则

所有 NFS 流量都先封装为 RPC 消息。RPC 消息有两种：

- **CALL**：客户端 → 服务端，Type=0
- **REPLY**：服务端 → 客户端，Type=1

RPC CALL 头部布局（RFC 5531 §8）：

```
XID (4 bytes, uint32)            事务标识符，reply 必须 echo call 的 XID
Type (4 bytes, uint32)           0 = CALL, 1 = REPLY
RPC Version (4 bytes, uint32)    固定 = 2
Program (4 bytes, uint32)        100003 = NFS, 100005 = MOUNT, 100021 = NLM, ...
Version (4 bytes, uint32)        NFSv3 = 3, NFSv4 = 4, MOUNTv3 = 3
Procedure (4 bytes, uint32)      procedure 编号，见 §2.2/§2.4
Credentials (variable)           auth_unix / auth_none，前 4 字节为 flavor
Verifier (variable)              前 4 字节为 flavor，剩余为 body
```

RPC REPLY 头部布局：

```
XID (4 bytes)                    echo call
Type (4 bytes)                   = 1
Reply State (4 bytes, uint32)    0 = MSG_ACCEPTED, 1 = MSG_DENIED
[if MSG_ACCEPTED:]
  Verifier (variable)            reply verifier
  Accept State (4 bytes)         0=SUCCESS, 1=PROG_UNAVAIL, 2=PROG_MISMATCH,
                                 3=PROC_UNAVAIL, 4=GARBAGE_ARGS, 5=SYSTEM_ERR
[if MSG_DENIED:]
  Reject State (4 bytes)         0=RPC_MISMATCH, 1=AUTH_ERROR
  [if RPC_MISMATCH:]             RPC version range (low, high)
  [if AUTH_ERROR:]               auth_stat (1-9)
```

注意：**RPC_MISMATCH 与 AUTH_ERROR 两个分支互斥**（RFC 5531 §8）——RejectState=0 时附带 low/high 版本范围字段，RejectState=1 时附带 auth_stat，二者不会同时出现；且 RPC_MISMATCH 分支下**没有** AcceptState/auth_stat，AUTH_ERROR 分支下**没有** low/high。MSG_DENIED 整体也没有 AcceptState 字段（AcceptState 仅存在于 MSG_ACCEPTED 分支）。

**TCP 记录分帧**（RFC 5531 §11.B）：每个 RPC 消息在 TCP 上传输时，前 4 字节为记录标记（Record Mark，RM）：

```
位 31 (0x80000000)：最后一段标志（LAST_FRAGMENT），1 = 该段是消息的最后一段
位 30-0：段长度（不含 4 字节头部本身）
```

trafficgen 实现的所有 NFS RPC 请求都不分片（单段），所以 RM = `0x80000000 | len(msg)`。

### 1.4 trafficgen 实现边界

trafficgen 生成的是确定性流量（不是真实 NFS 客户端），所以以下边界成立：

1. **只生成"成功路径"**：NFS 操作返回 NFS4_OK (0) / NFS3_OK (0)，不模拟服务端真实文件系统状态机的复杂性（除非用户显式配置错误状态码）。
2. **不实现 RPCSEC_GSS**：仅支持 auth_none（flavor=0）与 auth_sys（flavor=1）。
3. **不实现 NFSv4.1+ pNFS**：不实现 GETDEVICEINFO / LAYOUTGET / LAYOUTRETURN 等布局操作（留作扩展点）。
4. **不实现回调通道**：CB_COMPOUND (procedure 2) 不生成，NFSv4.1 backchannel 不实现。
5. **filehandle / stateid / clientid 由用户提供**：trafficgen 不维护真实状态，这些字段是 Config 输入。用户必须保证逻辑一致性（例如 OPEN 后的 stateid 在后续 WRITE / CLOSE 中复用），否则抓包工具会报"未知 stateid"但 trafficgen 不报错。
6. **多会话并发 = 多独立 4-tuple**：每个客户端会话是独立的 TCP 流，不共享 XID / seq 序列。

---

## 2. 数据类型与编码

NFS 使用 XDR（External Data Representation，RFC 4506）编码。所有字段默认大端（Big-Endian，BE）字节序。

### 2.1 XDR 基础类型

| XDR 类型 | 编码规则 |
|----------|----------|
| `int` / `uint32` | 4 字节大端 |
| `uint64` / `hyper` | 8 字节大端 |
| `bool` | 4 字节（0=false, 1=true） |
| `string<>` | 4 字节长度 + 字节串 + 0-3 字节零填充对齐 4 |
| `opaque<>`（变长字节） | 4 字节长度 + 字节 + 0-3 字节零填充对齐 4 |
| `opaque[N]`（定长字节） | N 字节 + 0-3 字节零填充对齐 4 |
| `enum` | 同 int（4 字节大端） |
| `struct` | 字段按声明顺序编码 |
| `union` | 判别 int + 对应分支字段 |
| `array<T>` | 4 字节长度 + 元素按顺序编码 |

### 2.2 NFSv3 Procedure 表（RFC 1813）

Program = 100003, Version = 3

| Proc# | 名称 | 关键参数 | 关键返回 |
|-------|------|----------|----------|
| 0 | NULL | 无 | 无 |
| 1 | GETATTR | filehandle | fattr3（属性） |
| 2 | SETATTR | filehandle, sattr3 | wcc_data |
| 3 | LOOKUP | dirfh, filename | filehandle, post_op_obj_attr, post_op_dir_attr（LOOKUP3resok = object fh 在前、obj_attributes、dir_attributes，RFC 1813 §3.3.3，见 S4） |
| 4 | ACCESS | filehandle, access | access, post_op_attr |
| 5 | READLINK | filehandle | symlink, post_op_attr |
| 6 | READ | filehandle, offset, count | post_op_attr, count, eof, data |
| 7 | WRITE | filehandle, offset, count, stable_how, data | file_wcc, count, committed, verf |
| 8 | CREATE | dirfh, name, sattr3 | post_op_fh3, post_op_attr |
| 9 | MKDIR | dirfh, name, sattr3 | post_op_fh3, post_op_attr |
| 10 | SYMLINK | dirfh + name + symlink（symlinkdata3 = symlink_attributes sattr3 + symlink_data 路径） | post_op_fh3, post_op_attr |
| 11 | MKNOD | dirfh + name + ftype（mknoddata3 判别）+ sattr3 + devdata（specdata3，仅 NF3CHR/NF3BLK） | post_op_fh3, post_op_attr |
| 12 | REMOVE | dirfh, filename | wcc_data |
| 13 | RMDIR | dirfh, filename | wcc_data |
| 14 | RENAME | old_dirfh + old_name + new_dirfh + new_name（RENAME3args = diropargs3 from + diropargs3 to） | source_wcc, target_wcc |
| 15 | LINK | filehandle + link_dirfh + link_name（LINK3args = nfs_fh3 file + diropargs3 link） | post_op_attr, wcc_data |
| 16 | READDIR | filehandle, cookie, cookieverf, count | dir_attributes, cookieverf, dirlist3（entries<> + 内层 eof，RFC 1813 §3.3.16） |
| 17 | READDIRPLUS | filehandle, cookie, cookieverf, dircount, maxcount | dir_attributes, cookieverf, dirlistplus3（entries<> + 内层 eof，RFC 1813 §3.3.17） |
| 18 | FSSTAT | filehandle | fsstat3resok |
| 19 | FSINFO | filehandle | fsinfo3resok |
| 20 | PATHCONF | filehandle | pathconf3resok |
| 21 | COMMIT | filehandle, offset, count | file_wcc, verf |

**procedure 范围**：NFS v3 程序（100003）的合法 procedure 为 0-21。procedure 22+ 时 Validate **不报错**（透传，生成时直接写入），这是构造 RPC PROC_UNAVAIL 测试的机制（见 §9.1/T-148）——真实服务端对超出范围的 procedure 返回 PROC_UNAVAIL；合成流量中需显式配置 `rpc_accept_state=3` 才能在 reply 注入该错误。MOUNT 程序（100005）例外：v3 仅 0-5 合法，6+ 报错（见 §2.3）。

### 2.3 MOUNT Procedure 表（RFC 1813 附录 I / mount v3）

Program = 100005, Version = 3

| Proc# | 名称 | 关键参数 | 关键返回 |
|-------|------|----------|----------|
| 0 | NULL | 无 | 无 |
| 1 | MNT | dirpath | fh3, auth_flavors |
| 2 | DUMP | 无 | mountlist |
| 3 | UMNT | dirpath | 无 |
| 4 | UMNTALL | 无 | 无 |
| 5 | EXPORT | 无 | exports |

RFC 1813 附录 I 的 MOUNT v3 只定义 6 个 procedure（0-5）。PATHCHK 是 NFSv2 时代（RFC 1094 附录 A）MOUNT 协议的 procedure 6，v3 已删除，本设计不支持 MOUNT v2。

trafficgen 默认只生成 NULL/MNT/UMNT，其余 DUMP/EXPORT/UMNTALL 留作扩展点（用户显式配置 proc=2/4/5 时 Validate 通过，但本设计不自动补全，详见 §4.2 规则 5）。proc=6+ 在 v3 下 Validate 报错 "MOUNT v3 procedure out of range (0-5)"。

### 2.4 NFSv4 Procedure 表（RFC 7530）

Program = 100003, Version = 4

| Proc# | 名称 | 关键参数 | 关键返回 |
|-------|------|----------|----------|
| 0 | NULL | 无 | 无 |
| 1 | COMPOUND | argarray（operation 列表） | resarray（operation 结果列表） |
| 2 | CB_COMPOUND | （回调通道，本设计不生成） | （回调通道） |

NFSv4 实际只通过 COMPOUND 一个 procedure 传输所有操作。其余的"操作"都是 COMPOUND 内的 operation。CB_COMPOUND 是服务端→客户端的回调通道过程（RFC 7530 §18.1），本设计不生成回调通道（§1.4 规则 4）。

**NFSv4 NULL (proc 0)**：不嵌入 COMPOUND，是独立 RPC procedure；user 显式配置 procedure=0 时 Plan 直接生成 NULL call/reply，call/reply 无 NFS 层 body（无 status 字段）。RPC REPLY 的 AcceptState 应为 0 (SUCCESS)。

### 2.5 NFSv4 Operation 表（在 COMPOUND 内，依据 RFC 7531 §6.1 enum nfs_opnum4）

| Op# | 名称 | 关键参数 | 关键返回 |
|-----|------|----------|----------|
| 0 | ILLEGAL4 | （保留，COMPOUND 中无效 op 由服务端以 op_status=NFS4ERR_OP_ILLEGAL 表达） | status |
| 3 | ACCESS | access bits | supported, access |
| 4 | CLOSE | seqid, open_stateid | stateid |
| 5 | COMMIT | offset, count | verf |
| 6 | CREATE | objtype, objname, createattrs | change_info, attrsset |
| 7 | DELEGPURGE | clientid | 无 |
| 8 | DELEGRETURN | delegstateid | 无 |
| 9 | GETATTR | attrmask | attrs |
| 10 | GETFH | （无） | fh |
| 11 | LINK | newdir, newname | change_info |
| 12 | LOCK | locktype, reclaim, offset, length, locker | lock_stateid |
| 13 | LOCKT | locktype, offset, length, owner | （冲突或无） |
| 14 | LOCKU | locktype, seqid, stateid, offset, length | stateid |
| 15 | LOOKUP | name | （无） |
| 16 | LOOKUPP | （无） | （无） |
| 17 | NVERIFY | obj_attr | （无） |
| 18 | OPEN | seqid, share_access, share_deny, owner, openhow, claim | stateid, change_info, attrsset, delegation |
| 19 | OPENATTR | createdir | （无） |
| 20 | OPEN_CONFIRM | open_stateid, seqid | stateid（v4.0 专用；v4.1 已删除，参见 RFC 5661） |
| 21 | OPEN_DOWNGRADE | stateid, seqid, share_access, share_deny | stateid |
| 22 | PUTFH | fh | （无） |
| 23 | PUTPUBFH | （无） | （无） |
| 24 | PUTROOTFH | （无） | （无） |
| 25 | READ | stateid, offset, count | eof, data |
| 26 | READDIR | cookie, dircount, maxcount, attrmask | entries |
| 27 | READLINK | （无） | link |
| 28 | REMOVE | name | change_info |
| 29 | RENAME | oldname, newname | source_cinfo, target_cinfo |
| 30 | RENEW | clientid | （无） |
| 31 | RESTOREFH | （无） | （无） |
| 32 | SAVEFH | （无） | （无） |
| 33 | SECINFO | name | secinfo |
| 34 | SETATTR | stateid, attrs | attrsset |
| 35 | SETCLIENTID | client, callback, callback_ident | clientid, setclientid_confirm |
| 36 | SETCLIENTID_CONFIRM | clientid, verf | （无） |
| 37 | VERIFY | obj_attr | （无） |
| 38 | WRITE | stateid, offset, stable_how, data | count, committed, verf |
| 39 | RELEASE_LOCKOWNER | owner | （无） |
| 40 | WANT_DELEGATION | clientid, want | （无）（NFSv4.1 操作，RFC 5661） |
| 41-62 | NFSv4.1+ ops（BIND_CONN_TO_SESSION=41, EXCHANGE_ID=42, CREATE_SESSION=43, DESTROY_SESSION=44 等） | Validate 不报错但本设计自动补全流程不使用 | （不生成） |

**OPCODE 范围说明**：

- 0/1/2：未分配（RFC 7531 §6.1 中 0-2 无名称，Validate 拒绝，报错 "invalid opcode (must be 3-62)"）。非法 op 由服务端以 op_status=NFS4ERR_OP_ILLEGAL (10044) 表达，不存在"自动转为 ILLEGAL4"的合成行为。
- 3-39：NFSv4.0 操作（RFC 7530 §16 / RFC 7531 §6.1 `enum nfs_opnum4`），本设计完整支持。其中 OP_WRITE=38、OP_RELEASE_LOCKOWNER=39（RFC 7531 将 RELEASE_LOCKOWNER 标注为 Mandatory not-to-implement，但保留 opcode 39）。
- 40-62：NFSv4.1+ 引入的操作（RFC 5661/5663），其中 40=WANT_DELEGATION、41=BIND_CONN_TO_SESSION、42=EXCHANGE_ID、43=CREATE_SESSION、44=DESTROY_SESSION。Validate 不报错（透传），但本设计的自动补全流程（§4.1）不使用这些操作。用户显式配置时，生成时 opcode 直接写入，Wireshark 在 minorversion=0 下会显示 "unknown opcode"，真实 v4.0 服务端返回 NFS4ERR_OP_ILLEGAL (10044)。
- 63+：非法值，Validate 报错 "invalid opcode (must be 3-62)"。

**常用 NFSv4 属性 → attrmask 对照表**：bitmap4 是 uint32 数组，属性 attr N 落在 word N/32 的第 N%32 位（word 0 = attr 0-31，word 1 = attr 32-63，word 2+ = attr 64+，属 NFSv4.1 RFC 5661 §5.8）。

| 属性名 (RFC 7530 §16.2) | attr 号 | word / bit | 3-word bitmap 示例 |
|--------------------------|---------|------------|--------------------|
| FATTR4_SUPPORTED_ATTRS | 0 | word 0 bit 0 | [0x00000001, 0, 0] |
| FATTR4_TYPE | 1 | word 0 bit 1 | [0x00000002, 0, 0] |
| FATTR4_SIZE | 4 | word 0 bit 4 | [0x00000010, 0, 0] |
| FATTR4_FSID | 8 | word 0 bit 8 | [0x00000100, 0, 0] |
| FATTR4_FILEID | 20 | word 0 bit 20 | [0x00100000, 0, 0] |
| FATTR4_MODE | 33 | word 1 bit 1 | [0, 0x00000002, 0] |
| FATTR4_OWNER | 36 | word 1 bit 4 | [0, 0x00000010, 0] |
| FATTR4_OWNER_GROUP | 37 | word 1 bit 5 | [0, 0x00000020, 0] |
| FATTR4_TIME_MODIFY | 53 | word 1 bit 21 | [0, 0x00200000, 0] |
| size + mode（本文档示例常用组合） | 4, 33 | word 0 bit 4 + word 1 bit 1 | [0x00000010, 0x00000002, 0] |

Validate 规则：AttrMask 的非零 word 只允许 word 0/1（attr 0-63）；word 2+ 非零（attr 64+ 属 NFSv4.1）时 Validate 报错 "attrmask contains NFSv4.1+ attributes"（T149）。

### 2.6 filehandle / stateid / clientid 编码

**filehandle**（RFC 7531 §3 / RFC 1813 §2.6，opaque<> 变长）：

```
length (4 bytes, uint32)     filehandle 长度，0 ≤ length ≤ NFS4_FHSIZE (128) / NFS3_FHSIZE (64)
data (variable bytes)        filehandle 字节串
padding (0-3 bytes)          XDR 4 字节对齐填充（零填充）
```

**stateid4**（RFC 7531 §3 `typedef struct { uint32_t seqid; opaque other[12]; } stateid4;`）：

```
seqid (4 bytes, uint32)      序列号，每次操作递增
other (12 bytes, opaque[12]) state 标识符，由服务端分配（定长 12 字节，无长度前缀）
```

特殊 stateid（依据 RFC 7530 §9.1.4.3 给出精确字节）：

- **匿名 stateid（anonymous）**：seqid=0, other=12 字节全 0。用于 READ/WRITE/SETATTR 的"匿名访问"语义（RFC 7530 §9.1.4.3 第 1 段："The anonymous state id is used during READ, WRITE and SETATTR operations..."）。精确字节：seqid `00 00 00 00` + other 12×`00`，合计 16 字节。
- **READ bypass stateid**（RFC 7530 §9.1.4.3 第 2 段）：seqid=全 1（0xFFFFFFFF），other=12 字节全 1。用于客户端尚未持有 OPEN stateid 但需绕过 OPEN 直接 READ 的场景。精确字节：seqid `FF FF FF FF` + other `FF FF FF FF FF FF FF FF FF FF FF FF`，合计 16 字节。

**clientid4**（RFC 7531 §3 `typedef uint64_t clientid4;`）：**8 字节 uint64**（不是 4 字节），由服务端在 SET_CLIENTID reply 中分配。0 = "未分配"，在 SET_CLIENTID call 本身中合法。

### 2.7 NFSv4.0 COMPOUND 编码（RFC 7531 §5.2）

CALL（COMPOUND4args）：

```
tag (string, XDR)               标签，可空（call 与 reply 必须一致）
minorversion (4 bytes, uint32)  恒为 0 = NFSv4.0（本设计不支持 v4.1+ 的 minorversion=1）
argarray length (4 bytes)       operation 个数
[op #1 opcode (4 bytes)] [op #1 args (XDR)]
[op #2 opcode (4 bytes)] [op #2 args (XDR)]
...
```

REPLY（COMPOUND4res，RFC 7531 §15.2.3 `struct COMPOUND4res { nfsstat4 status; utf8str_cs tag; nfs_resop4 resarray<>; };`）：

```
status (4 bytes, uint32)        NFS4_OK=0 或错误码（顶层 status，反映 COMPOUND 整体结果）
tag (string, XDR)               回显 call 的 tag
oparray length (4 bytes)
[op #1 opcode (4 bytes)] [op #1 op_status (4 bytes)] [op #1 result (XDR)]
...
```

**CALL 与 REPLY 的非对称**：CALL（COMPOUND4args）的顺序是 `tag → minorversion → argarray`（tag 在前），而 REPLY（COMPOUND4res）的顺序是 `status → tag → resarray`（status 在前）。这是 RFC 7531 有意为之的非对称设计（status 是顶层 NFS 状态码，需在 tag 之前解码以决定后续是否解析 oparray）。

**minorversion 取值约束**：
- `minorversion = 0`：NFSv4.0（本设计唯一支持值）。
- `minorversion = 1`：NFSv4.1（RFC 5661，本设计不生成）。
- Validate 规则：若 NFSConfig.MinorVersion 显式设为非 0 → 报错 "only NFSv4.0 (minorversion=0) is supported"。

注意：如果某个 operation 失败，COMPOUND 不再返回后续 operation 结果，但 resarray 长度反映已执行的 operation 数（oparray 截断规则，见上表与 §9.2）。

**reply 合成规则**：

| 情形 | 顶层 status | oparray 内容 | 单 op 的 op_status |
|------|-------------|--------------|---------------------|
| 单 op COMPOUND，ReplyStatus≠0 | = ReplyStatus | 仅含该 op | = ReplyStatus |
| 多 op COMPOUND，所有 op 成功 | NFS4_OK (0) | 含全部 op | 每个 op = NFS4_OK |
| 多 op COMPOUND，第 i 个 op 失败（OpStatus≠0） | = 第 i op 的 OpStatus | 仅含 op 1..i（截断） | op 1..i-1 = NFS4_OK，op i = OpStatus |
| ResultStatus≠0（全局） | = ResultStatus | 含全部 op（不截断，所有 op 均正常执行） | 每个 op = ResultStatus |

字段优先级：NFSOp.ReplyStatus > NFSConfig.ResultStatus > 默认 0 (NFS4_OK)。

> **错误码取低 32 位说明**：顶层 status 与 op_status 都是 uint32，若配置的错误码值超过 32 位（如 10025），以低 32 位为准（10025 的低 32 位即 10025=0x2729），bit 位深度不改变字节值本身。

### 2.8 NFSv3 字段编码摘要

**filename**（RFC 1813 §2.6）：4 字节长度 + 字节串 + 0-3 字节 XDR 填充。

**fattr3**（RFC 1813 §2.6）：

```
type (4 bytes)         NF3* (1=NF3REG, 2=NF3DIR, 3=NF3BLK, 4=NF3CHR, 5=NF3LNK, 6=NF3SOCK, 7=NF3FIFO)
mode (4 bytes)         9 位权限位
nlink (4 bytes)        硬链接数
uid (4 bytes)
gid (4 bytes)
size (8 bytes, uint64)
used (8 bytes, uint64)
rdev (8 bytes)         specdata1(4) + specdata2(4)
fsid (8 bytes)
fileid (8 bytes)
atime (8 bytes)        nfstime3 = seconds(4) + nseconds(4)
mtime (8 bytes)        nfstime3 = seconds(4) + nseconds(4)
ctime (8 bytes)        nfstime3 = seconds(4) + nseconds(4)
```

**fattr3 总长度 = 4+4+4+4+4+8+8+8+8+8+8+8+8 = 84 字节**（nfstime3 是 8 字节，非 12 字节）。

**wcc_data**（RFC 1813 §3.3.2 `struct wcc_data { wcc_attr pre_op_attr; post_op_attr post_op_attr; };`，注意 pre_op_attr 是 `union pre_op_attr switch (bool attributes_follow)`，post_op_attr 是 `union post_op_attr switch (bool attributes_follow)`）：

```
pre_op_attr 判别 (4 bytes, bool)   attributes_follow=1 时随后写 wcc_attr 24B
wcc_attr (24 bytes, 可选)          size (8B) + mtime (8B nfstime3) + ctime (8B nfstime3)
post_op_attr 判别 (4 bytes, bool)  attributes_follow=1 时随后写 fattr3 84B
fattr3 (84 bytes, 可选)            type + mode + nlink + uid + gid + size + used + rdev + fsid + fileid + atime + mtime + ctime
```

**wcc_data 长度核算**：本设计合成 reply 简化策略——pre_op_attr 判别=0（不 follow，4 字节）+ post_op_attr 判别=1 + fattr3 84 字节 = **92 字节**（括号标注 [92 bytes]）。

**nfstime3 编码**（RFC 1813 §2.6）：

```
seconds (4 bytes, uint32)    自 1970-01-01 UTC 的秒数
nseconds (4 bytes, uint32)   纳秒部分 (0-999999999)
```

**fattr4 编码**（RFC 7531 §3 `struct fattr4 { bitmap4 attrmask; attrlist4 attr_vals; };`，attrlist4 = `typedef opaque attrlist4<>;` 变长 opaque）：**bitmap4（4 字节长度 + word 数组）+ attrlist4 的 4 字节长度前缀 + 属性值字节流 + 0-3 字节对齐填充**。attr_vals 与 bitmap 对应：bitmap 置位位按位序排列的属性 XDR 编码值依次拼接。例如 attr 4 (FATTR4_SIZE, uint64 8B) + attr 33 (FATTR4_MODE, uint32 4B) → attr_vals = 长度前缀 4 + 8 + 4 = 16 字节。**注意：fattr4 不是"bitmap + 属性值裸拼"——attr_vals 必须带 4 字节长度前缀**（见 S11）。

**sattr3**（RFC 1813 §2.6，判别联合 discriminant union）：mode/uid/gid/size 为 `union set_mode3 switch (bool set_it)`——set 判别值后**仅当为 true 才写对应值**（false 分支为 void，不写值）；atime/mtime 为 `union set_atime switch (time_how)`——time_how 判别值 **0=DONT_CHANGE（不写值）、1=SET_TO_SERVER_TIME（不写值）、2=SET_TO_CLIENT_TIME（写 nfstime3 8 字节）**。RFC 1813 §2.6 原文（本次核实）：`union set_atime switch (time_how set_it) { case SET_TO_CLIENT_TIME: nfstime3 atime; default: void; };`（0/1 落入 default: void 分支）。各字段按声明顺序编码：

```
set_mode (4 bytes, bool)    判别值；true 时随后写 mode (4B)
set_uid (4 bytes, bool)     true 时随后写 uid (4B)
set_gid (4 bytes, bool)     true 时随后写 gid (4B)
set_size (4 bytes, bool)    true 时随后写 size (8B, uint64)
set_atime (4 bytes, time_how) 0=DONT_CHANGE / 1=SET_TO_SERVER_TIME / 2=SET_TO_CLIENT_TIME（2 时随后写 nfstime3 8B）
set_mtime (4 bytes, time_how) 同上（2 时随后写 nfstime3 8B）
```

**sattr3 长度核算**：全部 false/0（DONT_CHANGE）时 = 6×4 = 24 字节；仅 set_mode=true 时 = 4 (set_mode) + 4 (mode) + 4×4 (其余五个判别值) = 28 字节。注意 false 分支**不写占位值**（wire 上不存在 uid/gid/size/atime/mtime 的值字段）。

**NFSAttributes 字段 → sattr3 映射规则**：`SetMode=true` → set_mode=1 + mode；`SetUid=true` → set_uid=1 + uid；`SetGid=true` → set_gid=1 + gid；`SetSize=true` → set_size=1 + size；`SetAtime=true` 时由 AtimeSecs 值决定：**AtimeSecs=0xFFFFFFFF → 1 (SET_TO_SERVER_TIME，不写值)；AtimeSecs 未显式提供（字段为默认 0）→ 1 (SET_TO_SERVER_TIME，不写值)；其余值 → 2 (SET_TO_CLIENT_TIME + nfstime3)**；`SetAtime=false`（默认）→ set_atime=0 (DONT_CHANGE，不写值)；`SetMtime` 同理映射 MtimeSecs。即 time_how 不设独立 Config 字段，由 Set 位 + Secs 值推导（与 T-033/T-034/T-035 一致）。**注意：SetAtime=true 且 AtimeSecs 未提供时映射 time_how=1（SET_TO_SERVER_TIME），不是 0（DONT_CHANGE）**——DONT_CHANGE 的语义是"不改变服务器时间"，与 set_atime=true 的本意相悖（RFC 1813 §2.6 time_how 语义）。

**NFSv3 多参数 procedure 的 Config 字段映射**（RFC 1813 §3.3.10/§3.3.11/§3.3.14/§3.3.15，v2.0.4 新增，对应 §3.2 NFSOp 字段）：

| procedure | RFC 1813 args | Config 字段 |
|-----------|---------------|-------------|
| SYMLINK (10) | `where`（diropargs3 = dir fh + name）+ `symlink`（symlinkdata3 = symlink_attributes sattr3 + symlink_data nfspath3） | dir fh = Filehandle；name = Filename；symlink_attributes = Attributes（sattr3）；**symlink_data = SymlinkTarget**（nfspath3 = 变长 opaque<>，XDR 长度前缀 + 路径字节 + 对齐填充） |
| MKNOD (11) | `where`（diropargs3）+ `what`（mknoddata3 判别联合，判别字段 ftype3） | dir fh = Filehandle；name = Filename；**ftype = Ftype**（mknoddata3.type）；case NF3CHR/NF3BLK：devicedata3（dev_attributes sattr3 + spec）→ Attributes + **Devdata**（specdata3 = specdata1 主设备号 4B + specdata2 次设备号 4B）；case NF3SOCK/NF3FIFO：pipe_attributes → Attributes（devdata 不写）；default（NF3REG/NF3DIR/NF3LNK）：void |
| RENAME (14) | `from`（diropargs3 = from.dir + from.name）+ `to`（diropargs3 = to.dir + to.name） | **old_dirfh = Filehandle；old_name = Oldname；new_dirfh = Filehandle2；new_name = Newname**（Filehandle2 是第二个 dirfh，与 Filehandle 相对；两对字段互不混用） |
| LINK (15) | `file`（nfs_fh3）+ `link`（diropargs3 = link.dir + link.name） | file fh = Filehandle；**link.dir = LinkDirFh**；**link.name = Newname** |

注意：Oldname/Newname 在 NFSv3 场景下由 §3.2 NFSOp 使用（v3 RENAME/LINK），在 NFSv4 场景下由 §3.3 NFSv4CompoundOp 使用（v4 RENAME/LINK），两处为不同结构体的独立字段（v2.0.4 起 v3 侧字段已在 §3.2 定义）。

### 2.9 错误码

NFSv4 (RFC 7531 §3 `enum nfsstat4`) 常用：

| 名称 | 值 | 触发场景 |
|------|----|----|
| NFS4_OK | 0 | 成功 |
| NFS4ERR_PERM | 1 | 权限不足 |
| NFS4ERR_NOENT | 2 | 文件不存在 |
| NFS4ERR_IO | 5 | IO 错误 |
| NFS4ERR_ACCESS | 13 | 访问拒绝 |
| NFS4ERR_EXIST | 17 | 文件已存在 |
| NFS4ERR_XDEV | 18 | 跨设备链接 |
| NFS4ERR_NOTDIR | 20 | 不是目录 |
| NFS4ERR_ISDIR | 21 | 是目录 |
| NFS4ERR_INVAL | 22 | 参数错误 |
| NFS4ERR_FBIG | 27 | 文件过大 |
| NFS4ERR_NOSPC | 28 | 空间不足 |
| NFS4ERR_ROFS | 30 | 只读文件系统 |
| NFS4ERR_MLINK | 31 | 链接过多 |
| NFS4ERR_NAMETOOLONG | 63 | 文件名过长 |
| NFS4ERR_NOTEMPTY | 66 | 目录非空 |
| NFS4ERR_DQUOT | 69 | 配额超出 |
| NFS4ERR_STALE | 70 | 旧 filehandle |
| NFS4ERR_BADHANDLE | 10001 | 无效 filehandle |
| NFS4ERR_BAD_COOKIE | 10003 | cookie 无效 |
| NFS4ERR_DELAY | 10008 | 服务端暂时无法处理（资源忙，客户端应稍后重试） |
| NFS4ERR_NOT_SAME | 10027 | cookieverf 不匹配（READDIR） |
| NFS4ERR_EXPIRED | 10011 | state 过期 |
| NFS4ERR_BAD_STATEID | 10025 | 无效 stateid |
| NFS4ERR_BAD_SEQID | 10026 | seqid 错误 |
| NFS4ERR_BAD_XDR | 10036 | XDR 解码失败 |
| NFS4ERR_RESOURCE | 10018 | 资源不足 |
| NFS4ERR_NOFILEHANDLE | 10020 | 当前无 filehandle |
| NFS4ERR_MINOR_VERS_MISMATCH | 10021 | minorversion 不匹配 |
| NFS4ERR_STALE_CLIENTID | 10022 | clientid 过期 |
| NFS4ERR_STALE_STATEID | 10023 | stateid 过期 |
| NFS4ERR_OLD_STATEID | 10024 | 旧 stateid |
| NFS4ERR_MOVED | 10019 | 文件系统已迁移 |
| NFS4ERR_RESTOREFH | 10030 | RESTOREFH 失败（无 saved fh） |
| NFS4ERR_OP_ILLEGAL | 10044 | 非法 opcode |

NFSv3 (RFC 1813 §2.7) 常用：

| 名称 | 值 |
|------|----|
| NFS3_OK | 0 |
| NFS3ERR_PERM | 1 |
| NFS3ERR_NOENT | 2 |
| NFS3ERR_IO | 5 |
| NFS3ERR_NXIO | 6 |
| NFS3ERR_ACCES | 13 |
| NFS3ERR_EXIST | 17 |
| NFS3ERR_XDEV | 18 |
| NFS3ERR_NODEV | 19 |
| NFS3ERR_NOTDIR | 20 |
| NFS3ERR_ISDIR | 21 |
| NFS3ERR_INVAL | 22 |
| NFS3ERR_FBIG | 27 |
| NFS3ERR_NOSPC | 28 |
| NFS3ERR_ROFS | 30 |
| NFS3ERR_MLINK | 31 |
| NFS3ERR_NAMETOOLONG | 63 |
| NFS3ERR_NOTEMPTY | 66 |
| NFS3ERR_DQUOT | 69 |
| NFS3ERR_STALE | 70 |
| NFS3ERR_BADHANDLE | 10001 |
| NFS3ERR_NOT_SYNC | 10002 |
| NFS3ERR_BAD_COOKIE | 10003 |

RPC 层错误（RFC 5531）：

| 名称 | 值 |
|------|----|
| RPC_SUCCESS | 0 |
| RPC_PROG_UNAVAIL | 1 |
| RPC_PROG_MISMATCH | 2 |
| RPC_PROC_UNAVAIL | 3 |
| RPC_GARBAGE_ARGS | 4 |
| RPC_SYSTEM_ERR | 5 |
| RPC_MISMATCH | 0（reject_state） |
| RPC_AUTH_ERROR | 1（reject_state） |

---

## 3. 消息结构与配置类型定义

### 3.1 NFSConfig（顶层）

```go
// NFSConfig holds NFS (RFC 7530 v4 / RFC 1813 v3) protocol configuration.
// One flow = one TCP session carrying an RPC stream. Multi-session
// scenarios use one FlowSpec per session (multiple 4-tuples).
type NFSConfig struct {
    Version int              `json:"version"`                       // 3 or 4（必填）
    Transport string         `json:"transport,omitempty"`           // "tcp"（默认）或 "udp"（仅 v3）
    AuthFlavor uint32        `json:"auth_flavor,omitempty"`         // 0=auth_none（默认）, 1=auth_sys
    AuthSys *AuthSysInfo     `json:"auth_sys,omitempty"`            // AuthFlavor=1 时必需
    XIDBase uint32           `json:"xid_base,omitempty"`            // XID 起始值，默认 1
    XIDIncr int              `json:"xid_incr,omitempty"`            // XID 递增步长，默认 1
    Ops []NFSOp              `json:"ops"`                           // 操作序列（v3 procedure / v4 compound_ops）
    Sessions int             `json:"sessions,omitempty"`            // 并发会话数（默认 1），每会话独立 4-tuple
    SessionsSrcPortBase uint16 `json:"sessions_src_port_base,omitempty"` // 多会话源端口起始
    SessionsSrcPortStep int  `json:"sessions_src_port_step,omitempty"`  // 默认 1
    ResultStatus uint32      `json:"result_status,omitempty"`        // 默认 0=OK；非 0 模拟错误返回
    Direction string         `json:"direction,omitempty"`            // 默认 "up"（call 主导）；"down"=reply 主导
    MountFilehandle []byte   `json:"mount_filehandle,omitempty"`     // MOUNT reply 返回的 fh3，默认 16×0x01；Validate 限 ≤64 (NFS3_FHSIZE)
    MinorVersion *uint32     `json:"minorversion,omitempty"`         // NFSv4 minorversion，默认/唯一合法值 0 (v4.0)；非 0 Validate 报错
}
```

字段语义：

- **Version**（必填）：3 → NFSv3 + MOUNT 协议；4 → NFSv4 COMPOUND。Validate 拒绝 0/1/2/5/6。
- **Transport**：默认 "tcp"。NFSv3 可设 "udp"（UDP 上 RPC 无记录标记）。
- **AuthFlavor**：默认 0（auth_none）。设 1 → 用 AuthSys 填 credentials。设 6（RPCSEC_GSS）→ Validate 报错 "RPCSEC_GSS not supported"。
- **AuthSys**：AuthFlavor=1 时必填，nil 时 Validate 用默认值（stamp=0, machinename="trafficgen", uid=0, gid=0）。
- **XIDBase**：第一个 RPC call 的 XID。默认 1。XIDIncr=1 时第二个 call 的 XID=2。
- **XIDIncr**：默认 1。设 0 → 所有 call 共用同一 XID（用于测试 reply echo 行为）。
- **Ops**：操作序列。每个 NFSOp 描述一次 RPC 往返（一个 call + 一个 reply）。
- **Sessions**：默认 1。>1 时生成 Sessions 个独立 TCP 流，源端口递增（用于多客户端场景）。sessions=1 时 SessionsSrcPortStep 可为任意值（无递增需求）；sessions>1 时必须非 0。
- **SessionsSrcPortStep**：sessions=1 时可为任意值（含 0）；sessions>1 时必须非 0，否则 Validate 报错。
- **ResultStatus**：默认 0（NFS_OK）。非 0 时所有 reply 在 NFS 层返回该错误码（RPC 层仍 MSG_ACCEPTED）。仅用于测试错误路径。
- **MountFilehandle**：MOUNT reply 中合成的 fh3。默认 16 字节全 0x01。Validate 限长度 ≤ 64（NFS3_FHSIZE）。
- **MinorVersion**：NFSv4 COMPOUND 的 minorversion 字段。默认 0（NFSv4.0）。显式设为 1（NFSv4.1）时 Validate 报错 "only NFSv4.0 (minorversion=0) is supported"。nil 时按 0 处理。
- **Direction**：默认 "up"（call 占主导，client→server）；"down"=reply 占主导（server→client，仅用于模拟服务端主动推送场景，NFS 本身少用）。

### 3.2 NFSOp（操作单元）

```go
// NFSOp describes one RPC round-trip: one CALL + one REPLY.
// For NFSv3: each Op = one procedure call.
// For NFSv4: each Op = one COMPOUND carrying CompoundOps.
type NFSOp struct {
    // NFSv3 字段
    Program uint32   `json:"program,omitempty"`    // 100003=NFS, 100005=MOUNT，默认 100003
    ProgVersion uint32 `json:"prog_version,omitempty"` // 默认按 Version: v3=3, v4=4
    Procedure uint32 `json:"procedure,omitempty"`   // NFSv3 proc 编号 / NFSv4 = 1 (COMPOUND)
    Filehandle []byte `json:"filehandle,omitempty"` // NFSv3 procedure 参数 / NFSv4 PUTFH 参数
    Filename string   `json:"filename,omitempty"`   // LOOKUP / CREATE / REMOVE 等
    Oldname string   `json:"oldname,omitempty"`     // NFSv3 RENAME（proc=14）的 from.name（源名）
    Newname string   `json:"newname,omitempty"`     // NFSv3 RENAME（proc=14）的 to.name（目标名）/ LINK（proc=15）的 link.name
    Filehandle2 []byte `json:"filehandle2,omitempty"` // NFSv3 RENAME 的 to.dir（第二个 dirfh）；LINK 的 link.dir 用 LinkDirFh（见下）
    LinkDirFh []byte `json:"link_dirfh,omitempty"`  // NFSv3 LINK（proc=15）的 link.dir（硬链接所在目录 fh）
    SymlinkTarget string `json:"symlink_target,omitempty"` // NFSv3 SYMLINK（proc=10）的 symlink_data（符号链接目标路径）
    Ftype uint32     `json:"ftype,omitempty"`       // NFSv3 MKNOD（proc=11）的 mknoddata3.type 判别（1=NF3REG, 2=NF3DIR, 3=NF3BLK, 4=NF3CHR, 5=NF3LNK, 6=NF3SOCK, 7=NF3FIFO）
    Devdata [8]byte  `json:"devdata,omitempty"`     // NFSv3 MKNOD（proc=11）的 specdata3（specdata1=主设备号 4B + specdata2=次设备号 4B）；仅 ftype=3/4 (NF3BLK/NF3CHR) 时写入
    Attributes *NFSAttributes `json:"attributes,omitempty"` // SETATTR / CREATE sattr3
    Offset uint64     `json:"offset,omitempty"`     // READ / WRITE
    Count uint32      `json:"count,omitempty"`      // READ / WRITE / READDIR
    Data []byte       `json:"data,omitempty"`       // WRITE payload
    StableHow uint32  `json:"stable_how,omitempty"` // WRITE: 0=UNSTABLE4, 1=DATA_SYNC4, 2=FILE_SYNC4
    Access uint32     `json:"access,omitempty"`     // ACCESS
    Cookie uint64     `json:"cookie,omitempty"`     // READDIR
    CookieVerf [8]byte `json:"cookie_verf,omitempty"` // READDIR（v3: cookieverf3=opaque[8]；v4: verifier4=opaque[8]）
    DirCount uint32   `json:"dir_count,omitempty"`  // READDIRPLUS（NFSv3 proc=17）的 dircount；READDIR（proc=16）时 MaxCount 作为单一 count 使用
    MaxCount uint32   `json:"max_count,omitempty"`  // READDIR（NFSv3 proc=16）的 count / READDIRPLUS 的 maxcount

    // NFSv4 COMPOUND 字段
    CompoundOps []NFSv4CompoundOp `json:"compound_ops,omitempty"` // NFSv4 operation 列表
    Tag string       `json:"tag,omitempty"`         // COMPOUND tag（reply 中回显 call tag）

    // NFSv3 MOUNT 字段（Program=100005）
    DirPath string   `json:"dirpath,omitempty"`     // MOUNT/UMOUNT 路径

    // 通用 reply 控制
    ReplyStatus uint32 `json:"reply_status,omitempty"` // 单 op 的 NFS status，0=OK（默认）；覆盖 NFSConfig.ResultStatus

    // RPC 层错误注入（指针语义：nil = 走默认成功路径）
    RPCAcceptState *uint32   `json:"rpc_accept_state,omitempty"`   // 0=SUCCESS, 1=PROG_UNAVAIL, 2=PROG_MISMATCH, 3=PROC_UNAVAIL, 4=GARBAGE_ARGS, 5=SYSTEM_ERR
    RPCRejectState *uint32   `json:"rpc_reject_state,omitempty"`   // 0=RPC_MISMATCH, 1=AUTH_ERROR
    RPCMismatchLow *uint32   `json:"rpc_mismatch_low,omitempty"`   // RPC_MISMATCH 时的最低版本
    RPCMismatchHigh *uint32  `json:"rpc_mismatch_high,omitempty"`  // RPC_MISMATCH 时的最高版本
    AuthStat *uint32         `json:"auth_stat,omitempty"`           // AUTH_ERROR 时的 auth_stat (1=AUTH_BADCRED, 2=AUTH_REJECTEDCRED, 3=AUTH_BADVERF, 4=AUTH_REJECTEDVERF, 5=AUTH_TOOWEAK, 6=AUTH_INVALIDRESP, 7=AUTH_FAILED)

    // OPEN reply stateid 引用（user 显式配置后续 op 使用的 stateid）
    OpenReplyStateid *NFSStateid `json:"open_reply_stateid,omitempty"`
}
```

### 3.3 NFSv4CompoundOp（NFSv4 COMPOUND 内 operation，依据 RFC 7531 §5.2-§5.6）

```go
// NFSv4CompoundOp describes one operation inside a COMPOUND request.
type NFSv4CompoundOp struct {
    Opcode uint32 `json:"opcode"` // 3-39（v4.0），40-62 透传不报错，详见 §2.5

    // 共用参数字段（按 opcode 选取）
    Filehandle []byte `json:"filehandle,omitempty"` // PUTFH（PUTROOTFH/PUTPUBFH 忽略）
    Name string `json:"name,omitempty"`             // LOOKUP / CREATE / REMOVE / RENAME（CREATE 时作 objname）
    OpenStateid *NFSStateid `json:"open_stateid,omitempty"` // CLOSE 的 open_stateid（RFC 7531 §5.2 CLOSE4args）
    Stateid *NFSStateid `json:"stateid,omitempty"`   // READ / WRITE / SETATTR / LOCKU
    Seqid uint32 `json:"seqid,omitempty"`            // OPEN / CLOSE / LOCK / LOCKU / OPEN_CONFIRM / OPEN_DOWNGRADE
    Clientid uint64 `json:"clientid,omitempty"`      // SET_CLIENTID_CONFIRM / RENEW / DELEGPURGE（8 字节 uint64）
    Owner *NFSLockOwner `json:"owner,omitempty"`     // LOCK / OPEN（open_owner4 或 lock_owner4）
    Offset uint64 `json:"offset,omitempty"`          // READ / WRITE / LOCK / COMMIT
    Count uint32 `json:"count,omitempty"`            // READ / WRITE / COMMIT
    Data []byte `json:"data,omitempty"`              // WRITE
    StableHow uint32 `json:"stable_how,omitempty"`   // WRITE
    Access uint32 `json:"access,omitempty"`          // ACCESS
    AttrMask []uint32 `json:"attr_mask,omitempty"`   // GETATTR / SETATTR / READDIR
    Attrs *NFSAttributes `json:"attrs,omitempty"`    // SETATTR / CREATE
    Cookie uint64 `json:"cookie,omitempty"`          // READDIR
    CookieVerf [8]byte `json:"cookie_verf,omitempty"` // READDIR 的 cookieverf（v4: verifier4=opaque[8]）
    Oldname string `json:"oldname,omitempty"`        // RENAME
    Newname string `json:"newname,omitempty"`        // RENAME / LINK
    ShareAccess uint32 `json:"share_access,omitempty"` // OPEN
    ShareDeny uint32 `json:"share_deny,omitempty"`    // OPEN
    LockType uint32 `json:"lock_type,omitempty"`      // LOCK / LOCKU
    Reclaim bool `json:"reclaim,omitempty"`           // LOCK
    Length uint64 `json:"length,omitempty"`           // LOCK / LOCKU

    // OPEN 联合类型字段（RFC 7531 §5.2 OPEN4args）
    Claim *NFSClaim `json:"claim,omitempty"`         // OPEN 的 open_claim4 联合（默认 CLAIM_NULL）
    OpenHow *NFSOpenHow `json:"openhow,omitempty"`   // OPEN 的 openflag4（createmode，默认 UNCHECKED4）

    // CREATE 字段（RFC 7531 §5.4 CREATE4args）
    ObjType uint32 `json:"objtype,omitempty"`         // CREATE 的 createtype4（enum: NF4REG=1/NF4DIR=2/.../NF4NAMEDATTR=9，默认 NF4REG）

    // SETCLIENTID 字段（RFC 7531 §5.2 SETCLIENTID4args）
    Client *NFSClientId `json:"client,omitempty"`    // SET_CLIENTID 的 nfs_client_id4（含 verifier + id）
    Callback *CBCallback `json:"callback,omitempty"` // SET_CLIENTID 的 cb_client4（含 cb_program + cb_location）
    CallbackIdent uint32 `json:"callback_ident,omitempty"` // SET_CLIENTID 的 callback_ident

    // SETCLIENTID_CONFIRM 字段
    ClientidVerifier [8]byte `json:"clientid_verifier,omitempty"` // SETCLIENTID_CONFIRM 的 setclientid_confirm_verify（8 字节）

    // LOCK 字段（RFC 7531 §5.5 LOCK4args）
    NewLockOwner bool `json:"new_lock_owner,omitempty"` // LOCK 的 locker4 判别字段
    OpenToLockOwner *OpenToLockOwner `json:"open_to_lock_owner,omitempty"` // new_lock_owner=true 时
    LockOwner *LockOwner `json:"lock_owner,omitempty"` // new_lock_owner=false 时

    // per-op 失败注入（COMPOUND 中途失败语义）
    OpStatus *uint32 `json:"op_status,omitempty"`    // 该 op 的 op_status，nil=默认 NFS4_OK；非 0 时 COMPOUND 截断
}
```

#### 3.3.1 NFS 联合类型辅助结构

```go
// NFSClientId 表示 SETCLIENTID4args 的 nfs_client_id4（RFC 7531 §5.2）。
type NFSClientId struct {
    Verifier [8]byte `json:"verifier"` // verifier4（8 字节）
    Id string `json:"id"`              // opaque<>（变长 owner 标识字符串）
}

// CBCallback 表示 SETCLIENTID4args 的 cb_client4（RFC 7531 §5.2）。
type CBCallback struct {
    Program uint32 `json:"program"`   // cb_program
    NetID string `json:"netid"`       // r_netid（如 "tcp"）
    Addr string `json:"addr"`         // r_addr（如 "192.0.2.1.2049"）
}

// NFSClaim 表示 OPEN4args 的 open_claim4 联合（RFC 7531 §5.2）。
type NFSClaim struct {
    Type string `json:"type"` // "null"（CLAIM_NULL=0）/ "previous"（CLAIM_PREVIOUS=1）/ "delegate_cur"（CLAIM_DELEGATE_CUR=2）/ "delegate_prev"（CLAIM_DELEGATE_PREV=3）
    // CLAIM_NULL 分支（RFC 7531 §5.2）：case CLAIM_NULL: component4 file; ——携带文件名（在 OPEN.Name 字段表达）
    // CLAIM_PREVIOUS 分支：open_delegation_type4 delegate_type
    // CLAIM_DELEGATE_CUR 分支：open_claim_delegate_cur4 = stateid4 delegate_stateid + component4 file
    // CLAIM_DELEGATE_PREV 分支：component4 file_delegate_prev
    // 注意：CLAIM_NULL 与 CLAIM_DELEGATE_PREV 都携带 component4 file（wire 上有 len+data+pad），
    //       前者的文件名在 OPEN.Name 字段表达，后者的在 Claim.File 字段表达（两者互斥使用）。
    File string `json:"file,omitempty"`                          // CLAIM_DELEGATE_CUR / CLAIM_DELEGATE_PREV 的 component4 file
    DelegateType uint32 `json:"delegate_type,omitempty"`         // CLAIM_PREVIOUS / CLAIM_DELEGATE_PREV
    DelegateStateid *NFSStateid `json:"delegate_stateid,omitempty"` // CLAIM_DELEGATE_CUR（16 字节 stateid4）
}

// NFSOpenHow 表示 OPEN4args 的 openflag4 联合（RFC 7531 §5.2）。
// wire 编码：判别字段是 opentype4（0=OPEN4_NOCREATE / 1=OPEN4_CREATE），
//            OPEN4_CREATE 分支内是 createhow4 联合（判别字段 createmode4：
//            UNCHECKED4=0/GUARDED4=1 分支携带 fattr4 createattrs；EXCLUSIVE4=2 分支携带 verifier4）。
type NFSOpenHow struct {
    Type string `json:"type"` // "nocreate"（OPEN4_NOCREATE，无 how）/ "unchecked"（UNCHECKED4）/ "guarded"（GUARDED4）/ "exclusive"（EXCLUSIVE4）
    // "unchecked"/"guarded"/"exclusive" → opentype=1 (OPEN4_CREATE) + createhow4{mode, createattrs/createverf}
    // "nocreate" → opentype=0 (OPEN4_NOCREATE)，createhow4 不编码（默认缺省时按 "unchecked" 处理，与 §4.1/§8.3 V20 一致）
    // unchecked/guarded 分支：createattrs 为 fattr4，未配置属性时合成空 fattr4 = bitmap_len 4B + attr_vals_len 4B = 8 字节
    // exclusive 分支：createverf 为 verifier4（8 字节定长 opaque）
    Verifier [8]byte `json:"verifier,omitempty"` // EXCLUSIVE4 时含 verifier (8 字节)
}

// OpenToLockOwner 表示 LOCK4args 的 open_to_lock_owner4（new_lock_owner=true 分支，RFC 7531 §5.5）。
type OpenToLockOwner struct {
    OpenSeqid uint32 `json:"open_seqid"`           // open-owner 的 seqid
    OpenStateid *NFSStateid `json:"open_stateid"`  // OPEN reply 的 stateid
    LockSeqid uint32 `json:"lock_seqid"`           // lock-owner 的 seqid
    LockOwner *NFSLockOwner `json:"lock_owner"`    // lock_owner4
}

// LockOwner 表示 LOCK4args 的 lock_owner4（new_lock_owner=false 分支，RFC 7531 §5.5）。
type LockOwner struct {
    Clientid uint64 `json:"clientid"`
    Owner []byte   `json:"owner"` // 变长 owner 标识符
}
```

**联合类型默认规则**：
- OPEN 缺 `claim` 字段时，Validate 用默认 `{"type": "null"}`（CLAIM_NULL）并告警。
- OPEN 缺 `openhow` 字段时，Validate 用默认 `{"type": "unchecked"}`（UNCHECKED4）并告警。
- CREATE 缺 `objtype` 字段时，Validate 用默认 `1`（NF4REG）并告警。
- LOCK 缺 `new_lock_owner` 字段时，Validate 默认 `false`（使用 LockOwner 分支）。
- OPEN 的 `openhow.type` 合法值仅 "nocreate"/"unchecked"/"guarded"/"exclusive"（"nocreate" 为 v2.0.3 新增）；其他值 Validate 报错。

### 3.4 NFSStateid / NFSLockOwner / NFSAttributes

```go
// NFSStateid 表示 RFC 7531 §3 stateid4。
type NFSStateid struct {
    Seqid uint32 `json:"seqid"`
    Other [12]byte `json:"other"` // 12 字节，state 标识符（定长，无长度前缀）
}

// NFSLockOwner 表示 open_owner4 / lock_owner4 中的 owner 字段。
type NFSLockOwner struct {
    Clientid uint64 `json:"clientid"` // 8 字节 uint64
    Owner []byte   `json:"owner"`     // 变长 owner 标识符
}

// NFSAttributes 表示 NFSv3 sattr3 / NFSv4 fattr4 共用字段。
type NFSAttributes struct {
    SetMode bool   `json:"set_mode,omitempty"`
    Mode uint32    `json:"mode,omitempty"`
    SetUid bool    `json:"set_uid,omitempty"`
    Uid uint32     `json:"uid,omitempty"`
    SetGid bool    `json:"set_gid,omitempty"`
    Gid uint32     `json:"gid,omitempty"`
    SetSize bool   `json:"set_size,omitempty"`
    Size uint64    `json:"size,omitempty"`
    SetAtime bool  `json:"set_atime,omitempty"`
    AtimeSecs uint32 `json:"atime_secs,omitempty"`
    AtimeNsecs uint32 `json:"atime_nsecs,omitempty"`
    SetMtime bool  `json:"set_mtime,omitempty"`
    MtimeSecs uint32 `json:"mtime_secs,omitempty"`
    MtimeNsecs uint32 `json:"mtime_nsecs,omitempty"`
    // NFSv3 sattr3 的 atime/mtime 是 time_how 判别联合（RFC 1813 §2.6）：
    //   SetAtime=false（默认）→ time_how=0 (DONT_CHANGE，不写值)
    //   SetAtime=true 且 AtimeSecs=0xFFFFFFFF（哨兵）→ time_how=1 (SET_TO_SERVER_TIME，不写值)
    //   SetAtime=true 且 AtimeSecs 未显式提供（默认 0）→ time_how=1 (SET_TO_SERVER_TIME，不写值)
    //   SetAtime=true 且 AtimeSecs 为其他值 → time_how=2 (SET_TO_CLIENT_TIME + nfstime3 8B)
    //   SetMtime/MtimeSecs 同理。time_how 无独立 Config 字段，由 Set 位 + Secs 值推导（§2.8）。
    // NFSv3 SETATTR3args 的 sattrguard3（RFC 1813 §3.3.2）：Check bool + ObjCtime NFSTime；Check=false 时仅写 4 字节判别值 0
    SattrGuardCheck bool `json:"sattr_guard_check,omitempty"`
    SattrGuardCtimeSecs uint32 `json:"sattr_guard_ctime_secs,omitempty"`
    SattrGuardCtimeNsecs uint32 `json:"sattr_guard_ctime_nsecs,omitempty"`
}

// AuthSysInfo 表示 RFC 5531 §9.2 auth_sys 凭证。
type AuthSysInfo struct {
    Stamp uint32 `json:"stamp,omitempty"`
    MachineName string `json:"machine_name,omitempty"` // 默认 "trafficgen"；工程限制 ≤255 字节（与 Linux knfsd 一致，非 RFC 强制）
    UID uint32 `json:"uid,omitempty"`
    GID uint32 `json:"gid,omitempty"`
    Groups []uint32 `json:"groups,omitempty"`
}
```

### 3.5 字段语义补充

- **Opcode 范围**：3-39 为 NFSv4.0 合法操作（RFC 7530 §16 / RFC 7531 §6.1）；40-62 为 NFSv4.1+ 引入（RFC 5661/5663），Validate 不报错但生成时直接写入 opcode 字段，本设计的自动补全流程（§4.1）不使用这些操作；0/1/2 与 63+ 非法，Validate 报错 "invalid opcode (must be 3-62)"。
- **Filehandle 长度**：0 ≤ len ≤ 128（NFS4_FHSIZE） / 64（NFS3_FHSIZE）。超出 Validate 报错。
- **MountFilehandle 长度**：0 ≤ len ≤ 64（NFS3_FHSIZE），默认 16×0x01。
- **Stateid.Other**：12 字节固定长度。user 必须提供 12 字节（可用 base64 或 hex string）。不足或超长 → Validate 报错 "stateid other must be 12 bytes"（遵循 RFC 7531 §3 严格 12 字节语义）。
- **Clientid**：8 字节 uint64。0 = "未分配"，在 SET_CLIENTID call 本身中使用 0 是合法的。
- **Seqid 语义**：uint32。0 = 初始值。回绕（4294967295 → 0）在 NFSv4 中是协议规范行为。**seqid 按 state-owner 独立维护**（RFC 7530 §8.2.2/§8.2.5/§8.2.8）：open-owner（OPEN/OPEN_CONFIRM/OPEN_DOWNGRADE/CLOSE）共享同一序列；lock-owner（LOCK/LOCKU）共享另一序列。不同 owner 的 seqid 序列相互独立。
- **Data**：byte slice。0 字节合法（空 WRITE）。MSS 分段在 Plan 阶段处理。
- **ResultStatus** vs **ReplyStatus**：ResultStatus 是全局默认，ReplyStatus 是单 op 覆盖。ReplyStatus=0 时用 ResultStatus，ReplyStatus≠0 时用 ReplyStatus。
- **RPCAcceptState/RPCRejectState**：指针语义，nil = 走默认成功路径（MSG_ACCEPTED + SUCCESS）。非 nil 时合成 RPC 层错误 reply，NFS 层 status 不返回。若 user 配置了非 nil 的 RPCAcceptState 但未配置 rpc_mismatch_low/high（AcceptState=2 时需要），Validate 报错。
- **OpenReplyStateid**：user 显式配置的 OPEN reply stateid，用于后续 op 引用。**引用机制定义**：当 OPEN op 显式配置 OpenReplyStateid 且同一 COMPOUND（或后续 COMPOUND）内存在 stateid 字段值为全 0 的 op 时，Plan 将该 op 的 stateid 改写为 OpenReplyStateid 的字节值（含 seqid 与 other 12 字节）；若 user 显式提供了非全 0 的 stateid，则不改写（user 值优先）。Plan 不自动合成 OPEN reply 的 stateid（合成 reply 时 stateid 按 user 配置或全 0 原样回显，见 §6 S12）。
- **OpStatus**：per-op 失败注入字段。nil = 默认 NFS4_OK；非 0 时该 op 在 COMPOUND reply 中失败，oparray 截断至该 op（含），后续 op 不返回。
- **NFSv3 procedure 范围**：NFS 主程序（100003）procedure 0-21 合法；procedure 22+ Validate 不报错（透传），用于构造 RPC PROC_UNAVAIL 测试（§9.1/T-148，需配合 rpc_accept_state=3）。MOUNT 程序（100005）procedure 6+ Validate 报错（§2.3/T-136）。
- **UDP RPC 消息最大长度**：UDP 上整个 RPC 消息最大 65507 字节（65535 IP datagram - 8 UDP header - 20 IP header），超出 Validate 报错 "UDP RPC message exceeds 65507 bytes"（T141）。
- **NFSOp.program 默认 100003（NFS）**；MOUNT 时 100005。NFS 使用端口 2049，MOUNT 真实协议应使用 mountd 端口（通常 635 或经 rpcbind 111 查询），本设计为简化合成流量将 MOUNT 与 NFS 共用同一 TCP 连接（端口 2049），属已知偏离（见 §9.8 #1）。

---

## 4. 状态机

### 4.1 NFSv4.0 会话状态机

```
[初始]
  │
  ▼
SETCLIENTID (COMPOUND, opcode=35) ──► (REPLY, 含 clientid + setclientid_confirm)
  │
  ▼
SETCLIENTID_CONFIRM (COMPOUND, opcode=36, clientid + verf)
  │
  ▼
[客户端身份已建立]
  │
  │  ┌─── 用户配置的 Ops 序列 ───┐
  │  │                            │
  │  ▼                            │
  │ PUTFH / PUTROOTFH (COMPOUND)  │
  │  │                            │
  │  ▼                            │
  │ LOOKUP / GETATTR / OPEN /     │
  │ OPEN_CONFIRM (新 open-owner) /│
  │ READ / WRITE / CREATE /       │
  │ REMOVE / RENAME / READDIR /   │
  │ SETATTR / LOCK / LOCKU /      │
  │ CLOSE (COMPOUND)              │
  │  │                            │
  │  └────────────────────────────┘
  │
  ▼
TCP FIN（本设计不追加 DESTROY_CLIENTID，会话拆除由 TCP FIN 表达）
```

**状态机规则**：

1. **SETCLIENTID / SETCLIENTID_CONFIRM 自动补全**：Plan 阶段在 Ops 头部自动插入 SETCLIENTID（opcode=35）与 SETCLIENTID_CONFIRM（opcode=36），除非 user 在 Ops 中已显式包含 opcode=35（则不重复插入 SETCLIENTID；但仍检查 SETCLIENTID_CONFIRM 是否存在，未包含则自动追加）。SETCLIENTID 的 `client.verifier` 由 Plan 生成（默认 8 字节随机），`client.id` 默认 "trafficgen-client-{session序号}"（多会话区分），`callback.program` 默认 0，`callback.netid`/`addr` 默认空串，`callback_ident` 默认 0。SETCLIENTID_CONFIRM 的 `clientid` 取自 SETCLIENTID reply 的 clientid，`verifier` 取自 SETCLIENTID reply 的 `setclientid_confirm`。

2. **PUTROOTFH 自动补全**：如果 user 的第一个 COMPOUND 中含 PUTFH/PUTROOTFH/LOOKUP/GETATTR 等需要当前 fh 的 operation，但 user 没配置 PUTFH/PUTROOTFH，Plan 在该 COMPOUND 头部自动插入 PUTROOTFH（RFC 7530 §16.24）。

3. **OPEN_CONFIRM 自动补全**：NFSv4.0 中，新的 open-owner 首次 OPEN 后必须 OPEN_CONFIRM（opcode=20）确认（RFC 7530 §16.18）。Plan 检测到 OPEN 且 open-owner 是首次出现（同 clientid+owner 在前序 ops 中未出现）时，自动在 OPEN 后追加 OPEN_CONFIRM，seqid 沿用 open-owner 的 seqid 序列（OPEN seqid=1 → OPEN_CONFIRM seqid=2）。若 user 已显式配置 OPEN_CONFIRM，则不重复补全。OPEN_CONFIRM 的 open_stateid 取自 OPEN reply，确认后的 stateid 用于后续 READ/WRITE/CLOSE。

   > **合成流量确定性说明**：本设计按 RFC 7530 §16.18.4 要求：OPEN_CONFIRM seqid = OPEN seqid + 1。真实协议中 OPEN_CONFIRM 的 open_stateid 取自 OPEN reply（不是 OPEN call 中的 stateid），且服务端在 OPEN reply 中递增 stateid.seqid。本设计不模拟服务端递增 stateid 的交互过程，而是直接沿用 OPEN call seqid + 1 的确定性计算，以保证合成流量的可观察性。**OPEN_CONFIRM 自动补全适用于所有新 open-owner 的首次 OPEN，包括 §6.12 S12 场景**（S12 的 argarray length 已含补全后的 OPEN_CONFIRM，LOCK 的 open_seqid 相应为 2）。

4. **stateid 一致性**：stateid 一致性由用户负责（§1.4 规则 5 已声明）。Plan 的合成 reply 回显 user 配置的 stateid；user 在后续 op 中显式配置非全 0 stateid 时原样透传。全 0 stateid 是合法的匿名 READ/WRITE/SETATTR（§2.6 特殊 stateid），Plan 不自动改写——但若 user 通过 `OpenReplyStateid` 显式声明引用（见 §3.5），Plan 会将同 COMPOUND 内值为全 0 的 stateid 改写为所引用的 OPEN reply stateid 字节。

5. **Seqid 语义**：seqid 按 state-owner 独立维护（RFC 7530 §8.2.2/§8.2.5/§8.2.8）：
   - open-owner：OPEN / OPEN_CONFIRM / OPEN_DOWNGRADE / CLOSE 共享同一 open-owner 的 seqid 序列。
   - lock-owner：LOCK / LOCKU 共享同一 lock-owner 的 seqid 序列。
   - 不同 owner 的 seqid 序列相互独立（如 §6.8 示例：OPEN seqid=1（open-owner）→ LOCK seqid=1（lock-owner）→ LOCKU seqid=2（lock-owner）→ CLOSE seqid=2（open-owner，接续 OPEN seqid=1））。
   - Plan 默认按 owner 维护独立计数器，user 未显式提供 Seqid 时自动递增对应 owner 的序列。

6. **不使用 EXCHANGE_ID/CREATE_SESSION/DESTROY_SESSION**：这些是 NFSv4.1 操作（opcode 42/43/44），在 v4.0 中不存在。本设计不自动补全它们。user 若显式配置 opcode=42/43/44，Validate 不报错（透传），但生成的 COMPOUND 在 minorversion=0 下会被真实 v4.0 服务端拒绝（NFS4ERR_OP_ILLEGAL）。

7. **NFSv4 NULL (proc=0) 不嵌入 COMPOUND**：NFSv4 NULL 是独立 RPC procedure，不应嵌入 COMPOUND 内。user 显式配置 procedure=0 时 Plan 直接生成 NULL call/reply，call/reply 无 NFS 层 body。

### 4.2 NFSv3 会话状态机

```
[初始]
  │
  ▼
MOUNT (Program=100005, Proc=1) ──► (REPLY, 返回 fh3)
  │
  ▼
[已挂载]
  │
  │  ┌─── 用户配置的 Ops 序列 ───┐
  │  │                            │
  │  ▼                            │
  │ GETATTR / LOOKUP / READ /     │
  │ WRITE / CREATE / REMOVE /     │
  │ RENAME / READDIR / READDIRPLUS│
  │  (Program=100003, Proc=*)     │
  │  │                            │
  │  ▼                            │
  │ UMOUNT (Program=100005, Proc=3)│
  │  │                            │
  │  └────────────────────────────┘
  │
  ▼
[已卸载]
  │
  ▼
TCP FIN
```

**状态机规则**：

1. **MOUNT/UMOUNT 自动补全**：Plan 在 Ops 头部自动插入 MOUNT（除非用户已在 Ops 中显式配置 Program=100005 Procedure=1），尾部自动插入 UMOUNT（除非用户显式配置 Procedure=3）。

2. **MOUNT 返回的 fh3**：trafficgen 生成的 MOUNT reply 用 NFSConfig.MountFilehandle（默认全 0x01，16 字节）。后续 GETATTR/LOOKUP 等 procedure 默认用该 fh3 作为参数，除非用户显式提供 filehandle。

3. **无状态**：NFSv3 是无状态协议，服务端不维护客户端 session。但 UDP 场景下每个 RPC 仍需 XID 配对，Plan 保证 call/reply XID 一致。

4. **MOUNT/NFS 同连接偏离**：真实 NFSv3 客户端先经 rpcbind（端口 111）查 mountd 端口（通常 635），在独立 TCP 连接上完成 MNT，再在另一条连接（2049）上做 NFS 操作；本设计为简化合成流量，将 MOUNT + NFS + UMOUNT 都放在同一 4-tuple（端口 2049）上（详见 §9.8 已知偏离 #1）。

5. **MOUNT 协议的 NULL/DUMP/EXPORT/UMNTALL 不参与自动补全流程**：user 显式配置时透传，Plan 不自动插入头部/尾部。user 显式配置 Procedure=0（MOUNT NULL）时也不重复插入 proc=1（MOUNT）——MOUNT 自动补全仅当头部没有任何 Program=100005 的 op 时才插入 proc=1。

### 4.3 多会话状态机 (Sessions > 1)

```
[Session 1]  [Session 2]  ...  [Session N]
   │              │                │
   │ 独立 4-tuple (源端口递增)      │
   │              │                │
   ▼              ▼                ▼
SETCLIENTID   SETCLIENTID    SETCLIENTID
SETCLIENTID_  SETCLIENTID_   SETCLIENTID_
  CONFIRM       CONFIRM        CONFIRM
...            ...              ...
TCP FIN       TCP FIN          TCP FIN
```

**多会话规则**：

1. **独立 4-tuple**：每个会话独立 SrcPort，从 SessionsSrcPortBase 开始递增 SessionsSrcPortStep。默认 SrcPort=随机（ephemeral 49152-65535）。

2. **独立 XID 序列**：每个会话从 XIDBase 开始，独立递增。

3. **独立 clientid**：
   - **默认规则**：op 内 clientid=0 视为"按会话分配"，Plan 为每个会话分配独立 clientid。clientid 是 uint64，XIDBase 是 uint32，clientid 默认偏移基础为 `uint64(0x10000) * uint64(i+1) + 1`（session i 从 0 起）：session 0/1/2 = 0x10001/0x20001/0x30001，避开 0 与各会话互不相同。reply 的 clientid = call 的 clientid 期望值（合成流量中 reply 由 Plan 生成）。
   - **SETCLIENTID reply 的 clientid 合成规则**（与 §10.4 对齐）：**call 侧与 reply 侧使用同一取值规则**——user 显式配置该会话 clientid（op 内 clientid≠0）时，SETCLIENTID reply 回显 user 值；user 未显式配置（clientid=0）时，reply 用默认公式 `0x10000*(i+1)+1` 计算出的会话 clientid。该规则对合成 reply 唯一确定，不允许两处取不同值。
   - **显式 clientid**：user 在 op 内显式配置 clientid≠0 时，视为"该会话使用此 clientid"，跨会话校验：若 Sessions>1 且多个会话显式配置相同 clientid，Validate 报错 "duplicate clientid across sessions"。单会话内不限制。
   - **SETCLIENTID owner 区分**：自动补全的 SETCLIENTID 的 `client.id` 字段默认 "trafficgen-client-{session序号}"（每会话不同），模拟多客户端并发。user 显式配置 id 时使用 user 值。

4. **生成顺序**：Plan 按会话序号顺序生成，会话间不交错（本设计不实现 Interleave 交错模式，§9.8 已登记为扩展点）。

---

## 5. Plan 输出

### 5.1 单会话 TCP 包序列

NFSConfig 单会话（Sessions=1, Transport=tcp）的 Plan 输出：

```
1. TCP 3-way handshake
   - SYN (up): clientSeq=随机, flags=0x02, options=[MSS, WinScale, SACK, Timestamp]
   - SYN-ACK (down): serverSeq=随机, flags=0x12, options=[MSS, WinScale, SACK, Timestamp]
   - ACK (up): seq=clientSeq+1, ack=serverSeq+1, flags=0x10

2. 对每个 NFSOp 生成 call + reply:
   a. RPC CALL (up, PSH-ACK):
      - payload = RecordMark(0x80000000 | len) + XID + Type(0) + RPCVer(2) +
                  Program + ProgVersion + Procedure + Credentials + Verifier +
                  procedure-specific args
      - 若 payload > MSS，分多个段：每段 PSH-ACK（包括中间段和最后段，因为每段都需要推送用户数据给应用层）
   b. RPC REPLY (down, PSH-ACK):
      - payload = RecordMark(0x80000000 | len) + XID(echo) + Type(1) +
                  ReplyState(0=MSG_ACCEPTED) + Verifier + AcceptState(0=SUCCESS) +
                  procedure-specific result（含 NFS status + 结果）
      - 若 payload > MSS，同样分多段

3. TCP 3-way teardown
   - FIN (up): flags=0x11
   - FIN-ACK (down): flags=0x11
   - ACK (up): flags=0x10
```

**MSS 分段规则**（继承 socks5/RFC 793 PSH 语义）：

- 默认 MSS=1460 字节（DefaultMSS）。
- 单个 RPC call/reply 的 payload 超过 MSS 时，按 MSS 切分为多个 PSH-ACK 段，**每段（包括中间段和最后段）都带 PSH+ACK**（PSH 用于通知接收端立即将数据交给应用层，符合 RFC 793 §3.1 PSH 语义）。
- 每段 seq 递增 len(seg)。
- 整个 RPC 消息的 RecordMark 字段在第一段开头，不会被分割。

### 5.2 单会话 UDP 包序列（仅 NFSv3）

```
对每个 NFSOp 生成 call + reply:
   a. RPC CALL (up, UDP):
      - payload = XID + Type(0) + RPCVer(2) + Program + ProgVersion + Procedure +
                  Credentials + Verifier + args
      - 无 RecordMark（UDP 是数据报，无需分帧）
      - 整个 payload 单个 UDP 包，不分段
   b. RPC REPLY (down, UDP):
      - 类似，无 RecordMark
```

**UDP 长度上限**：UDP 数据报最大 65507 字节（IP datagram 65535 - IP header 20 - UDP header 8）。任一 RPC call 或 reply 的 payload 超出此限时 Validate 报错 "UDP RPC message exceeds 65507 bytes"（T141）。RFC 1813 NFSv3/UDP 协议不支持 IP 分片，real-server 会丢弃过大的 datagram。

### 5.3 多会话包序列

Sessions=N 时，Plan 生成 N 个独立 flow（N 个 FlowID），每个 flow 按 §5.1 顺序生成完整包序列。FlowID 格式：`{srcIP}-{dstIP}-{srcPort}-{dstPort}`，srcPort 按会话序号递增。

### 5.4 包序号 (PacketIndex)

每个会话内 PacketIndex 从 0 单调递增。多会话场景下，各会话独立计数（FlowID 区分）。

### 5.5 TCP 序号规则

- 客户端 ISN：随机（RFC 6528），除非 spec.TCP.InitialSeq 非零。
- 服务端 ISN：随机。
- 每次 PSH-ACK/ACK/FIN 后 seq 递增 len(payload)（SYN/FIN 占 1 字节）。
- 滑动窗口：默认 65535，可由 spec.TCP.WindowSize 覆盖。

### 5.6 时间戳规则

- 第一个包 Timestamp = time.Now()。
- 后续包 Timestamp 按 spec.PktInterval 递增（默认 0，即同一时刻）。
- reply 时间戳 = 对应 call 时间戳（reply 与 call 同时刻生成，不模拟服务端处理延迟）。
- 不模拟 RTT 重传（留作扩展点）。

---

## 6. 包序列场景（HexDump S1-S15）

本章给出 15 个完整 HexDump 逐字节场景。所有字段大端字节序（BE），Length 字段 = 实际字节数。RPC/NFS 默认 BE。HexDump 仅显示 RPC/NFS 层 payload（含 4 字节 RecordMark），不含 TCP/IP 头部。所有 XID 假定 base=0x00000001；clientid 假定 0x0000000000003039 (=12345)；stateid.other 假定 12 字节全 0。

### S1. NULL（NFSv3 proc 0，最简单的 RPC 往返）

**Config**：`{"version":3, "ops":[{"program":100003,"prog_version":3,"procedure":0}]}`

**CALL payload（40 字节，含 RM）**：

```
Offset  Hex                                  ASCII
0000    80 00 00 28                          ....        RM=0x80000028 (LAST=1, len=40)
0004    00 00 00 01                          ....        XID=1
0008    00 00 00 00                          ....        Type=0 (CALL)
000C    00 00 00 02                          ....        RPC Version=2
0010    00 01 86 A3                          ....        Program=100003 (NFS)
0014    00 00 00 03                          ....        Version=3
0018    00 00 00 00                          ....        Procedure=0 (NULL)
001C    00 00 00 00                          ....        Credentials Flavor=0 (AUTH_NONE)
0020    00 00 00 00                          ....        Credentials Body Length=0
0024    00 00 00 00                          ....        Verifier Flavor=0
0028    00 00 00 00                          ....        Verifier Body Length=0
```

**RM 长度核算**：RPC CALL 头 40 字节（XID 4 + Type 4 + RPCVer 4 + Prog 4 + ProgVer 4 + Proc 4 + CredFlavor 4 + CredLen 4 + VerfFlavor 4 + VerfLen 4）+ 无 NFS body = 40 = 0x28。NULL call 无 Cred Body/Verf Body（空 cred/verf 仅各含 flavor + length 两个 4 字节字段）。

**REPLY payload（28 字节，含 RM）**：

```
0000    80 00 00 18                          ....        RM=0x80000018 (LAST=1, len=24)
0004    00 00 00 01                          ....        XID=1 (echo)
0008    00 00 00 01                          ....        Type=1 (REPLY)
000C    00 00 00 00                          ....        Reply State=0 (MSG_ACCEPTED)
0010    00 00 00 00                          ....        Verifier Flavor=0
0014    00 00 00 00                          ....        Verifier Body Length=0
0018    00 00 00 00                          ....        Accept State=0 (SUCCESS)
```

**RM 长度核算**：RPC REPLY 头 24 字节（XID 4 + Type 4 + ReplyState 4 + VerfFlavor 4 + VerfLen 4 + AcceptState 4）= 24 = 0x18。

**关键校验点**：
- NULL call/reply 无 NFS 层 body。
- Accept State=0 (SUCCESS)。

### S2. GETATTR（NFSv3 proc 1，filehandle=1 字节 0x01）

**Config**：`{"version":3, "ops":[{"program":100003,"prog_version":3,"procedure":1,"filehandle":"AAE="}]}` （filehandle=1 字节 0x01，长度=1，需 3 字节填充）

**CALL payload（48 字节，含 RM）**：

```
0000    80 00 00 30                          ....        RM (len=48)
0004    00 00 00 01                          ....        XID=1
0008    00 00 00 00                          ....        Type=0 (CALL)
000C    00 00 00 02                          ....        RPC Ver=2
0010    00 01 86 A3                          ....        Program=100003
0014    00 00 00 03                          ....        Version=3
0018    00 00 00 01                          ....        Procedure=1 (GETATTR)
001C    00 00 00 00                          ....        Cred Flavor=0
0020    00 00 00 00                          ....        Cred Body Len=0
0024    00 00 00 00                          ....        Verf Flavor=0
0028    00 00 00 00                          ....        Verf Body Len=0
002C    00 00 00 01                          ....        filehandle length=1
0030    01                                   .           fh data=0x01
0031    00 00 00                             ...         XDR padding (3 字节)
```

**RM 长度核算**：RPC CALL 头 40 字节 + GETATTR3args（fh length 4 + fh data 1 + padding 3 = 8 字节）= 48 = 0x30。

**REPLY payload（120 字节，含 RM）**：

```
0000    80 00 00 74                          ....        RM (len=116)
0004    00 00 00 01                          ....        XID=1
0008    00 00 00 01                          ....        Type=1 (REPLY)
000C    00 00 00 00                          ....        Reply State=0 (MSG_ACCEPTED)
0010    00 00 00 00                          ....        Verifier Flavor=0
0014    00 00 00 00                          ....        Verifier Body Len=0
0018    00 00 00 00                          ....        Accept State=0 (SUCCESS)
001C    00 00 00 00                          ....        NFS status=0 (NFS3_OK)
0020    00 00 00 01                          ....        post_op_attr attributes_follow=1
0024    [84 bytes fattr3]                    ....        post_op_attr：fattr3 (84 字节，type=1 NF3REG + ...)（判别 4B + fattr3 84B = 88B）
```

**RM 长度核算**：RPC reply 头 24 字节（RM 不计入自身）+ NFS status 4 + **post_op_attr（判别 4B + fattr3 84B = 88B）** = 116 = 0x74。

**关键校验点**：
- filehandle length=1，data=0x01，3 字节填充对齐 4 字节。
- reply fattr3 总长 84 字节（§2.8）。
- post_op_attr.attributes_follow=1 (XDR bool)。

### S3. SETATTR（NFSv3 proc 2，sattr3 设置 mode=0644）

**Config 摘要**：`procedure=2, filehandle="AAE=", attributes={set_mode:true, mode:420}`（420=0644）

**CALL payload（NFS args 部分，跟随 RPC 头）**：

```
... (RPC 头 40 字节) ...
0028    00 00 00 01                          ....        filehandle length=1
002C    01                                   .           fh data
002D    00 00 00                             ...         padding
0030    [28 bytes sattr3]                    ....        sattr3 (判别联合：仅 set_mode=true 分支带值)
004C    00 00 00 00                          ....        sattrguard3 check=false（4 字节，XDR bool）
```

**sattr3 详细**（28 字节，判别联合编码）+ **sattrguard3**（4 字节）：

```
0030    00 00 00 01                          ....        set_mode=true（判别值 1）
0034    00 00 01 A4                          ..A.        mode=0644 (420)（仅 set_mode=true 才写值）
0038    00 00 00 00                          ....        set_uid=false（判别值 0，不写 uid 值）
003C    00 00 00 00                          ....        set_gid=false（判别值 0，不写 gid 值）
0040    00 00 00 00                          ....        set_size=false（判别值 0，不写 size 值）
0044    00 00 00 00                          ....        set_atime=0 (DONT_CHANGE)（不写 nfstime3）
0048    00 00 00 00                          ....        set_mtime=0 (DONT_CHANGE)（不写 nfstime3）
004C    00 00 00 00                          ....        sattrguard3 check=false（XDR bool，不附 ctime）
```

**长度核算**：sattr3 判别联合 = set_mode(4) + mode(4) + set_uid(4) + set_gid(4) + set_size(4) + set_atime(4) + set_mtime(4) = **28 字节**（false 分支为 void 不写值，RFC 1813 §2.6 `union set_mode3 switch (bool set_it)` / `union set_atime switch (time_how)`）；sattrguard3 check=false 仅 4 字节判别值 0，结束于 0x004C+4 = 0x0050。

**关键校验点**：
- **sattr3 是判别联合（RFC 1813 §2.6）**：mode/uid/gid/size 的 set_it=false 分支为 void，wire 上不存在对应值字段；atime/mtime 的 time_how 判别值 0=DONT_CHANGE（不写值）、1=SET_TO_SERVER_TIME（不写值）、2=SET_TO_CLIENT_TIME（才写 nfstime3 8 字节）。
- 本场景仅 set_mode=true，sattr3 共 28 字节（非固定 52 字节）。
- **sattrguard3 字段**（RFC 1813 §3.3.2）：check=false 时仅 4 字节判别值 0；check=true 时 12 字节（bool 判别值 1 + nfstime3 obj_ctime 8 字节）。本场景默认 check=false。
- reply 含 wcc_data（pre_op_attr + post_op_attr，见 §2.8）。

### S4. LOOKUP（NFSv3 proc 3，dirfh + filename="doc.txt"）

**Config 摘要**：`procedure=3, filehandle="AAE=", filename="doc.txt"` (7 字节)

**CALL args 部分**（RPC CALL 头 40 字节后）：

```
0028    00 00 00 01                          ....        dirfh length=1
002C    01                                   .           dirfh data
002D    00 00 00                             ...         padding
0030    00 00 00 07                          ....        filename length=7
0034    64 6F 63 2E 74 78 74                 doc.txt     filename (7 字节)
003B    00                                   .           padding (1 字节对齐 4)
```

**REPLY args 部分**（LOOKUP3resok，RFC 1813 §3.3.3：object fh 在前、obj_attributes、dir_attributes）：

```
001C    00 00 00 00                          ....        NFS status=0 (NFS3_OK)
0020    00 00 00 04                          ....        object: fh length=4（nfs_fh3 = 长度前缀 + 数据，非 post_op_fh3 联合）
0024    AA BB CC DD                          ....        fh data (4 字节，无 padding)
0028    00 00 00 01                          ....        obj_attributes: post_op_attr attributes_follow=1
002C    [84 bytes fattr3]                    ....        post_op_attr：fattr3 (84 字节)（判别 4B + fattr3 84B = 88B）
0080    00 00 00 00                          ....        dir_attributes: post_op_attr attributes_follow=0（简化合成时判别=0，不附属性）
```

**偏移核算**：object（fh_len 4B @ 0020 + fh_data 4B @ 0024-0027 = 8B）→ obj_attributes（判别 4B @ 0028 + fattr3 84B @ 002C-007F = 88B）→ dir_attributes（判别 4B @ 0080-0083）。**字段顺序为 fh → obj_attributes → dir_attributes（object 在前，不是 post_op_attr 在前）**。

**RM 长度核算**（惯例：RM 不计入自身，同 S2）：RPC reply 头 24 字节 + status 4 + object 8 + obj_attributes 88 + dir_attributes 4 = **128 字节 = 0x80**（payload 含 RM 共 132 字节，HexDump 止于 0x0084）。

**关键校验点**：
- filename "doc.txt" = 7 字节，XDR 填充至 8 字节。
- **LOOKUP3resok 字段顺序：object（裸 nfs_fh3，长度前缀+数据）@ 0020-0027 → obj_attributes（post_op_attr，判别 4B + fattr3 84B）@ 0028-007F → dir_attributes（post_op_attr，判别 4B）@ 0080**（RFC 1813 §3.3.3：fh 在前、属性在后，且含第三字段 dir_attributes，见 §2.2）。

### S5. READ（NFSv3 proc 6，offset=0, count=5, data="hello"）

**Config 摘要**：`procedure=6, filehandle="AAE=", offset=0, count=5`

**CALL args 部分**（RPC CALL 头 40 字节后）：

```
0028    00 00 00 01                          ....        fh length=1
002C    01                                   .           fh data
002D    00 00 00                             ...         padding
0030    00 00 00 00 00 00 00 00              ........    offset=0 (uint64)
0038    00 00 00 05                          ....        count=5
```

**REPLY args 部分**：

```
001C    00 00 00 00                          ....        NFS status=0
0020    00 00 00 01                          ....        post_op_attr attributes_follow=1
0024    [84 bytes fattr3]                    ....        fattr3 (84 字节，type=1 NF3REG + ...)
0078    00 00 00 05                          ....        count=5 (实际读取字节数)
007C    00 00 00 00                          ....        eof=0 (false)
0080    00 00 00 05                          ....        data length=5
0084    68 65 6C 6C 6F                       hello       data="hello"
0089    00 00 00                             ...         padding (3 字节)
```

**关键校验点**：
- offset 是 uint64 (8 字节)，不是 uint32。
- data "hello"=5 字节，填充至 8 字节。
- **post_op_attr（判别 4B + fattr3 84B = 88B）**（fattr3 总长 84 字节，§2.8），其后 count @ 0x0020+88=0x0078。

### S6. WRITE（NFSv3 proc 7，offset=0, stable_how=2, data="hello"）

**Config 摘要**：`procedure=7, filehandle="AAE=", offset=0, count=5, stable_how=2, data="aGVsbG8="`

**CALL args 部分**（RPC CALL 头 40 字节后）：

```
0028    00 00 00 01                          ....        fh length=1
002C    01                                   .           fh data
002D    00 00 00                             ...         padding
0030    00 00 00 00 00 00 00 00              ........    offset=0 (uint64)
0038    00 00 00 05                          ....        count=5
003C    00 00 00 02                          ....        stable_how=2 (FILE_SYNC)
0040    00 00 00 05                          ....        data length=5
0044    68 65 6C 6C 6F                       hello       data="hello"
0049    00 00 00                             ...         padding
```

**REPLY args 部分**：

```
001C    00 00 00 00                          ....        NFS status=0
0020    [92 bytes file_wcc]                  ....        wcc_data = pre_op_attr 判别 4B（不 follow）+ post_op_attr 判别 4B + fattr3 84B
007C    00 00 00 05                          ....        count=5 (写入字节数)
0080    00 00 00 02                          ....        committed=2 (FILE_SYNC)
0084    AA AA AA AA AA AA AA AA              ........    verf data (writeverf3 opaque[8]，8 字节定长，无长度前缀)
```

**wcc_data 偏移核算**：wcc_data = pre_op_attr（判别 4B，不 follow）+ post_op_attr（判别 4B + fattr3 84B）= 92 字节，从 0020 起到 0x0020+92 = 0x007C，故 count @ 007C。

**关键校验点**：
- stable_how=2 (FILE_SYNC4)。
- reply 含 committed + verf。
- **writeverf3 是定长 opaque[8]（RFC 1813 §2.6 `typedef opaque writeverf3[NFS3_WRITEVERFSIZE]`，=8）**：XDR 编码为 8 字节裸数据，**无长度前缀**（不是变长 opaque<>）。
- wcc_data 结构 = pre_op_attr（判别 + 可选 wcc_attr 24B）+ post_op_attr（判别 + 可选 fattr3 84B），本场景 92 字节（§2.8）。

### S7. CREATE（NFSv3 proc 8，name="new.txt", mode=0644）

**Config 摘要**：`procedure=8, filehandle="AAE=", filename="new.txt", attributes={set_mode:true, mode:420}`

**CALL args 部分**（RPC CALL 头 40 字节后）：

```
0028    00 00 00 01                          ....        dirfh length=1
002C    01                                   .           dirfh data
002D    00 00 00                             ...         padding
0030    00 00 00 07                          ....        filename length=7
0034    6E 65 77 2E 74 78 74                 new.txt     filename
003B    00                                   .           padding
003C    [28 bytes sattr3]                    ....        sattr3（判别联合：set_mode=true + mode，其余 false，共 28 字节，见 S3 详细编码）
```

**REPLY args 部分**：

```
001C    00 00 00 00                          ....        NFS status=0
0020    00 00 00 01                          ....        post_op_fh3 handle_follows=1
0024    00 00 00 04                          ....        fh length=4
0028    AA BB CC DD                          ....        fh data
002C    00 00 00 01                          ....        post_op_attr attributes_follow=1
0030    [84 bytes fattr3]                    ....        post_op_attr：fattr3 (type=1 NF3REG, mode=0644)（判别 4B + fattr3 84B = 88B）
0084    [92 bytes dir_wcc]                   ....        wcc_data（pre_op_attr 判别 4B + post_op_attr 判别 4B + fattr3 84B，见 §2.8）
```

**wcc_data 偏移核算**：post_op_attr（判别 4B + fattr3 84B = 88B）从 002C 起到 0x002C+88 = 0x0084，故 dir_wcc @ 0084；dir_wcc 92 字节到 0x0084+92 = 0x00E0。

**关键校验点**：
- reply fattr3.type=1 (NF3REG)，mode=0644。

### S8. REMOVE（NFSv3 proc 12，dirfh + filename）

**Config 摘要**：`procedure=12, filehandle="AAE=", filename="old.txt"`

**CALL args 部分**（RPC CALL 头 40 字节后）：

```
0028    00 00 00 01                          ....        dirfh length=1
002C    01                                   .           dirfh data
002D    00 00 00                             ...         padding
0030    00 00 00 07                          ....        filename length=7
0034    6F 6C 64 2E 74 78 74                 old.txt     filename
003B    00                                   .           padding
```

**REPLY args 部分**：

```
001C    00 00 00 00                          ....        NFS status=0
0020    [92 bytes wcc_data]                  ....        dir wcc_data（pre_op_attr 判别 4B + post_op_attr 判别 4B + fattr3 84B，见 §2.8）
```

### S9. READDIRPLUS（NFSv3 proc 17，cookie=0, cookieverf=8 字节 0, dircount=512, maxcount=8192）

**Config 摘要**：`procedure=17, filehandle="AAE=", cookie=0, cookie_verf="AAAAAAAAAAA=", dir_count=512, max_count=8192`

**CALL args 部分**（RPC CALL 头 40 字节后）：

```
0028    00 00 00 01                          ....        fh length=1
002C    01                                   .           fh data
002D    00 00 00                             ...         padding
0030    00 00 00 00 00 00 00 00              ........    cookie=0 (uint64)
0038    00 00 00 00 00 00 00 00              ........    cookieverf3 (8 字节全 0，opaque[8]，与 Config base64 "AAAAAAAAAAA=" 一致)
0040    00 00 02 00                          ....        dircount=512
0044    00 00 20 00                          ....        maxcount=8192
```

**REPLY args 部分**（简化，空目录；READDIRPLUS3resok = post_op_attr + cookieverf3 + dirlistplus3，eof 仅存在 dirlistplus3 内层）：

```
001C    00 00 00 00                          ....        NFS status=0 (NFS3_OK)
0020    00 00 00 01                          ....        post_op_attr attributes_follow=1
0024    [84 bytes fattr3]                    ....        post_op_attr：dir fattr3 (84 字节，见 §2.8)（判别 4B + fattr3 84B = 88B）
0078    00 00 00 00 00 00 00 00              ........    cookieverf3 (8 字节全 0，回显 call，opaque[8] 无长度前缀)
0080    00 00 00 00                          ....        dirlistplus3 entries length=0 (空目录，XDR 数组长度)
0084    00 00 00 01                          ....        dirlistplus3 eof=1 (true)（eof 是 dirlistplus3 内部布尔，RFC 1813 §3.3.17；READDIRPLUS3resok 无外层 eof）
```

**偏移核算**：post_op_attr（判别 4B + fattr3 84B = 88B）从 0020 起到 0x0020+88 = 0x0078，故 cookieverf3 @ 0078（8B）→ entries length @ 0080 → dirlistplus3 eof @ 0084。

**RM 长度核算**（惯例：RM 不计入自身，同 S2）：RPC reply 头 24 字节 + status 4 + post_op_attr 88 + cookieverf3 8 + entries length 4 + eof 4 = **132 字节 = 0x84**（payload 含 RM 共 136 字节，HexDump 止于 0x0088）。

**关键校验点**：
- **procedure=17（READDIRPLUS，不是 proc=16 READDIR）**：READDIRPLUS 的 args 含 dircount + maxcount 两个 count 字段（READDIR 仅单一 count，RFC 1813 §3.3.16/§3.3.17）。
- cookieverf3 是 8 字节 opaque[8]（无长度前缀），call 与 reply 均为 8 字节全 0（Config base64 `"AAAAAAAAAAA="` 解码为 8×00），reply 回显 call。
- **readdir3resok/READDIRPLUS3resok 只有 dirlist3/dirlistplus3 内层一个 eof**（RFC 1813 §3.3.16/§3.3.17：`struct READDIR3resok { post_op_attr dir_attributes; cookieverf3 cookieverf; dirlist3 reply; };`、`struct dirlist3 { entry3 entries<>; bool eof; };`），**不存在 resok 外层 eof**。v2.0.2 曾按 r2 误判补出"外层 eof"，v2.0.3 已撤销该反向修复（详见 §11.9 C-2）。
- READDIRPLUS reply 在 post_op_attr 之后含 cookieverf3，然后才是 dirlistplus3（entries length + 内层 eof），reply 止于 0x0088。

### S10. COMMIT（NFSv3 proc 21，offset=0, count=4096）

**Config 摘要**：`procedure=21, filehandle="AAE=", offset=0, count=4096`

**CALL args 部分**（RPC CALL 头 40 字节后）：

```
0028    00 00 00 01                          ....        fh length=1
002C    01                                   .           fh data
002D    00 00 00                             ...         padding
0030    00 00 00 00 00 00 00 00              ........    offset=0 (uint64)
0038    00 00 10 00                          ....        count=4096
```

**REPLY args 部分**：

```
001C    00 00 00 00                          ....        NFS status=0
0020    [92 bytes file_wcc]                  ....        wcc_data（pre_op_attr 判别 4B + post_op_attr 判别 4B + fattr3 84B，见 §2.8）
007C    BB BB BB BB BB BB BB BB              ........    verf data（writeverf3 opaque[8]，8 字节定长，无长度前缀）
```

**关键校验点**：
- **writeverf3 是定长 opaque[8]（RFC 1813 §2.6）**：8 字节裸数据，无长度前缀（与 S6 一致）。
- wcc_data 92 字节（§2.8），从 0020 起到 0x007C，故 verf @ 007C。

### S11. NFSv4 COMPOUND（PUTROOTFH + GETATTR）

**Config**：`{"version":4, "ops":[{"procedure":1, "compound_ops":[{"opcode":24},{"opcode":9,"attr_mask":[16,2,0]}]}]}`

PUTROOTFH (opcode=24)，GETATTR (opcode=9) attr_mask=[0x10, 0x02, 0x00] (size+mode)。

**CALL payload（含 RM）**：

```
0000    80 00 00 4C                          ....        RM (len=76)
0004    00 00 00 01                          ....        XID=1
0008    00 00 00 00                          ....        Type=0 (CALL)
000C    00 00 00 02                          ....        RPC Ver=2
0010    00 01 86 A3                          ....        Program=100003 (NFS)
0014    00 00 00 04                          ....        Version=4
0018    00 00 00 01                          ....        Procedure=1 (COMPOUND)
001C    00 00 00 00                          ....        Cred Flavor=0
0020    00 00 00 00                          ....        Cred Body Len=0
0024    00 00 00 00                          ....        Verf Flavor=0
0028    00 00 00 00                          ....        Verf Body Len=0
002C    00 00 00 00                          ....        tag length=0 (空 tag)
0030    00 00 00 00                          ....        minorversion=0
0034    00 00 00 02                          ....        argarray length=2
0038    00 00 00 18                          ....        op #1 opcode=24 (PUTROOTFH)
003C    00 00 00 09                          ....        op #2 opcode=9 (GETATTR)
0040    00 00 00 03                          ....        attr_mask bitmap length=3
0044    00 00 00 10                          ....        word 0 = 0x10 (FATTR4_SIZE=4)
0048    00 00 00 02                          ....        word 1 = 0x02 (FATTR4_MODE=33)
004C    00 00 00 00                          ....        word 2 = 0x00
```

**RM 长度核算**：RPC call 头（XID+Type+RPCVer+Program+Version+Procedure+CredFlavor+CredLen+VerfFlavor+VerfLen = 40 字节，RM 不计入自身）+ COMPOUND body（tag_len 4 + minorversion 4 + argarray_len 4 + op1 PUTROOTFH 4 + op2 GETATTR [opcode 4 + bitmap_len 4 + 3 words 12] = 36 字节）= 76 = 0x4C。

**REPLY payload（含 RM）**：

```
0000    80 00 00 54                          ....        RM (len=84)
0004    00 00 00 01                          ....        XID=1
0008    00 00 00 01                          ....        Type=1 (REPLY)
000C    00 00 00 00                          ....        Reply State=0 (MSG_ACCEPTED)
0010    00 00 00 00                          ....        Verifier Flavor=0
0014    00 00 00 00                          ....        Verifier Body Len=0
0018    00 00 00 00                          ....        Accept State=0 (SUCCESS)
001C    00 00 00 00                          ....        status=0 (NFS4_OK)
0020    00 00 00 00                          ....        tag length=0
0024    00 00 00 02                          ....        resarray length=2
0028    00 00 00 18                          ....        op #1 opcode=24 (PUTROOTFH)
002C    00 00 00 00                          ....        op #1 op_status=0 (NFS4_OK)
0030    00 00 00 09                          ....        op #2 opcode=9 (GETATTR)
0034    00 00 00 00                          ....        op #2 op_status=0 (NFS4_OK)
0038    00 00 00 03                          ....        GETATTR result: fattr4.attrmask bitmap length=3（回显 call 的 attr_mask）
003C    00 00 00 10                          ....        word 0 = 0x10 (FATTR4_SIZE=4)
0040    00 00 00 02                          ....        word 1 = 0x02 (FATTR4_MODE=33)
0044    00 00 00 00                          ....        word 2 = 0x00
0048    00 00 00 0C                          ....        fattr4.attr_vals length=12（变长 opaque<> 的长度前缀，RFC 7531 §3）
004C    00 00 00 00 00 00 00 10              ........    attr 4 FATTR4_SIZE: size=16 (uint64 8B)
0054    00 00 01 FF                          ....        attr 33 FATTR4_MODE: mode=0x1FF (0777)（uint32 4B）
```

**RM 长度核算**：RPC reply 头 24 字节（RM 不计入自身）+ COMPOUND reply body（status 4 + tag_len 4 + resarray_len 4 + op1[opcode+op_status=8] + op2[opcode+op_status=8] = 28 字节）+ GETATTR result（attrmask：bitmap_len 4 + 3 words 12 = 16B；attr_vals：长度前缀 4 + size 8 + mode 4 = 16B；合计 32 字节）= 24+28+32 = 84 = 0x54。HexDump 中 0038-0057 为 GETATTR result 完整字节（fattr4 共 32B：bitmap4 16B + attrlist4 16B），REPLY RM = 0x80000054 (len=84)。

**GETATTR result 合成规则**：reply attrs 按 call attr_mask 的位序合成——fattr4.attrmask 严格回显 call 的 attr_mask 全部 word（3 words 12B，含尾部 0 word 时保留原样，见 §7.5 T-140）；随后 **fattr4.attr_vals 是变长 opaque（attrlist4<>），必须带 4 字节长度前缀**（RFC 7531 §3 `struct fattr4 { bitmap4 attrmask; attrlist4 attr_vals; };`，attrlist4 = `typedef opaque attrlist4<>;`），长度 = 各置位属性 XDR 编码值字节数之和（本文档示例：FATTR4_SIZE=attr 4 → uint64 8B；FATTR4_MODE=attr 33 → uint32 4B，共 12B），其后按位序拼接属性值并 4 字节对齐填充（12 恰好对齐，无需填充）。attr 值由 builder 按位序生成（word 0 bit 4 → size、word 1 bit 1 → mode）。

**关键校验点**：
- opcode=24 是 PUTROOTFH（不是 23），opcode=9 是 GETATTR。
- minorversion=0。
- PUTROOTH 无参数，opcode 后直接是下一个 op。
- attr_mask bitmap length=3 (3 个 uint32 word)。
- RPC Procedure=1 (COMPOUND)，不是 opcode=24。
- **REPLY 顺序**：顶层 status @ 001C 在 tag @ 0020 之前（RFC 7531 §15.2.3，CALL 是 tag 在前、REPLY 是 status 在前，见 §2.7）。

### S12. NFSv4 COMPOUND（OPEN + LOCK + LOCKU + CLOSE）

**Config**：`{"version":4, "ops":[{"procedure":1, "compound_ops":[{"opcode":24},{"opcode":15,"name":"f"},{"opcode":18,"seqid":1,"share_access":2,"share_deny":0,"owner":{"clientid":12345,"owner":"AQ=="},"openhow":{"type":"unchecked"},"claim":{"type":"null"}},{"opcode":12,"lock_type":1,"reclaim":false,"offset":0,"length":100,"new_lock_owner":true,"open_to_lock_owner":{"open_seqid":2,"open_stateid":{"seqid":0,"other":"AAAAAAAAAAAAAAAA"},"lock_seqid":1,"lock_owner":{"clientid":12345,"owner":"AQ=="}}},{"opcode":14,"lock_type":1,"seqid":2,"stateid":{"seqid":0,"other":"AAAAAAAAAAAAAAAA"},"offset":0,"length":100},{"opcode":4,"seqid":3,"open_stateid":{"seqid":0,"other":"AAAAAAAAAAAAAAAA"}}]}]}`

PUTROOTFH (24) → LOOKUP (15) "f" → OPEN (18) seqid=1 → [OPEN_CONFIRM (20) seqid=2，§4.1 规则 3 自动补全] → LOCK (12) open_seqid=2 → LOCKU (14) seqid=2 → CLOSE (4) seqid=3

> **说明**：user 配置的 LOCK open_to_lock_owner.open_seqid 应为 2（OPEN_CONFIRM 补全后 open-owner 序列为 OPEN=1 → OPEN_CONFIRM=2 → CLOSE=3，RFC 7530 §16.18.4）。若 user 配置 open_seqid=1，与补全后的 open-owner 序列冲突，Validate 报错 "open_seqid must follow OPEN_CONFIRM sequence"。

**CALL COMPOUND args 部分**（RPC CALL 头 40 字节后，tag 从 0028 起）：

```
0028    00 00 00 00                          ....        tag length=0
002C    00 00 00 00                          ....        minorversion=0
0030    00 00 00 07                          ....        argarray length=7（OPEN_CONFIRM 由 §4.1 规则 3 自动补全，见说明）

0034    00 00 00 18                          ....        op #1 opcode=24 (PUTROOTFH)
0038    00 00 00 0F                          ....        op #2 opcode=15 (LOOKUP)
003C    00 00 00 01                          ....        LOOKUP name length=1
0040    66                                   f           name="f"
0041    00 00 00                             ...         padding

0044    00 00 00 12                          ....        op #3 opcode=18 (OPEN)
0048    00 00 00 01                          ....        seqid=1
004C    00 00 00 02                          ....        share_access=2 (WRITE)
0050    00 00 00 00                          ....        share_deny=0
0054    [open_owner4: clientid uint64 + owner opaque]    owner
0054    00 00 00 00 00 00 30 39              ........    clientid=12345 (uint64, 8 字节)
005C    00 00 00 01                          ....        owner length=1
0060    01                                   .           owner data=0x01
0061    00 00 00                             ...         padding
0064    [openflag4: opentype4 判别 + createhow4]         openhow（RFC 7531 §5.2，见说明）
0064    00 00 00 01                          ....        opentype=1 (OPEN4_CREATE)（openflag4 的判别字段是 opentype4）
0068    00 00 00 00                          ....        createhow4.createmode=0 (UNCHECKED4)
006C    00 00 00 00                          ....        createattrs: fattr4.attrmask bitmap length=0（空 fattr4）
0070    00 00 00 00                          ....        createattrs: fattr4.attr_vals length=0
0074    [open_claim4: claim_type + component4 file]      claim（CLAIM_NULL 分支含 component4 file，RFC 7531 §5.2）
0074    00 00 00 00                          ....        claim_type=0 (CLAIM_NULL)
0078    00 00 00 01                          ....        component4 file: length=1
007C    66                                   f           file data="f"
007D    00 00 00                             ...         padding

0080    00 00 00 14                          ....        op #4 opcode=20 (OPEN_CONFIRM，自动补全)
0084    [stateid4: open_stateid]                         open_stateid（取自 OPEN reply 合成 stateid，见说明）
0084    00 00 00 00                          ....        open_stateid.seqid=0
0088    00 00 00 00 00 00 00 00 00 00 00 00  ........    other (12 字节全 0)
0094    00 00 00 02                          ....        seqid=2（OPEN seqid 1 + 1，RFC 7530 §16.18.4）

0098    00 00 00 0C                          ....        op #5 opcode=12 (LOCK)
009C    00 00 00 01                          ....        lock_type=1 (WRITE_LT)
00A0    00 00 00 00                          ....        reclaim=false
00A4    00 00 00 00 00 00 00 00              ........    offset=0
00AC    00 00 00 00 00 00 00 64              ........    length=100
00B4    00 00 00 01                          ....        new_lock_owner=1 (true)
00B8    [open_to_lock_owner4]                            open_owner 分支
00B8    00 00 00 02                          ....        open_seqid=2（OPEN_CONFIRM 后 open-owner seqid=2）
00BC    [stateid4: seqid + other[12]]                    open_stateid
00BC    00 00 00 00                          ....        open_stateid.seqid=0
00C0    00 00 00 00 00 00 00 00 00 00 00 00  ........    other (12 字节全 0)
00CC    00 00 00 01                          ....        lock_seqid=1
00D0    [lock_owner4: clientid + owner]                  lock_owner
00D0    00 00 00 00 00 00 30 39              ........    clientid=12345
00D8    00 00 00 01                          ....        owner length=1
00DC    01                                   .           owner data
00DD    00 00 00                             ...         padding

00E0    00 00 00 0E                          ....        op #6 opcode=14 (LOCKU)
00E4    00 00 00 01                          ....        lock_type=1
00E8    00 00 00 02                          ....        seqid=2
00EC    [stateid4]                                       stateid
00EC    00 00 00 00                          ....        stateid.seqid=0
00F0    00 00 00 00 00 00 00 00 00 00 00 00  ........    other
00FC    00 00 00 00 00 00 00 00              ........    offset=0
0104    00 00 00 00 00 00 00 64              ........    length=100

010C    00 00 00 04                          ....        op #7 opcode=4 (CLOSE)
0110    00 00 00 03                          ....        seqid=3（open-owner 序列：OPEN=1 → OPEN_CONFIRM=2 → CLOSE=3）
0114    [stateid4: open_stateid]                         open_stateid
0114    00 00 00 00                          ....        open_stateid.seqid=0
0118    00 00 00 00 00 00 00 00 00 00 00 00  ........    other (12 字节)
```

**CALL 偏移核算**：COMPOUND body 从 tag @ 0028 起到 0x0124 = 252 字节（tag 4 + minorversion 4 + argarray_len 4 + PUTROOTFH 4 + LOOKUP [4+4+1+3] 12 + OPEN [4+4+4+4+8+4+1+3+4+4+4+4+4+4+1+3] 60 + OPEN_CONFIRM [4+16+4] 24 + LOCK [4+4+4+8+8+4+4+16+4+8+4+1+3] 72 + LOCKU [4+4+4+16+8+8] 44 + CLOSE [4+4+16] 24 = 252 = 0xFC）；加 RPC CALL 头 40 字节 = 292 字节，CALL RM = 0x80000124 (len=292)。其中 OPEN 块 60 字节构成：opcode 4 + seqid 4 + share_access 4 + share_deny 4 + owner [clientid 8 + owner_len 4 + data 1 + pad 3] 16 + openhow [opentype 4 + createmode 4 + createattrs 8] 16 + claim [claim_type 4 + file len 4 + data 1 + pad 3] 12。

**OPEN_CONFIRM 自动补全说明**（与 §4.1 规则 3 一致）：本场景 OPEN 的 open-owner（clientid=12345 + owner=0x01）是首次出现，Plan 自动在 OPEN 后追加 OPEN_CONFIRM（opcode=20），argarray length = 6 + 1 = 7；OPEN_CONFIRM 的 open_stateid 取自 OPEN reply 的合成 stateid（全 0 回显），seqid=2（OPEN seqid 1 + 1）；补全后 open-owner 序列为 OPEN=1 → OPEN_CONFIRM=2 → CLOSE=3，故 LOCK 的 open_to_lock_owner4.open_seqid=2、CLOSE seqid=3。

**OPEN reply 合成 stateid 说明**（M-3）：本场景 OPEN_CONFIRM @ 0084 与 CLOSE @ 0114 的 open_stateid 均为全 0（seqid=0 + other 12×00），其来源是 **OPEN reply 的合成 stateid**：未配置 `OpenReplyStateid`（§3.5）时，合成 reply 的 OPEN stateid 为全 0 回显（与 §9.5 #2 登记一致，不模拟服务端递增 stateid）。若 user 配置了 `OpenReplyStateid`，则 OPEN_CONFIRM/CLOSE 引用该值（§3.5 引用机制）。

**openhow 编码说明**（C-5）：openflag4 的判别字段是 **opentype4**（0=OPEN4_NOCREATE / 1=OPEN4_CREATE，RFC 7531 §5.2），unchecked/guarded/exclusive 是**内层 createhow4** 的 createmode4 值（0/1/2），**不能直接当 openflag4 判别写**。type="unchecked"（本场景）→ opentype=1 + createmode=0 + createattrs（空 fattr4 = bitmap_len 0 + attr_vals_len 0，共 8 字节），openhow 块共 16 字节（0x64-0x73）；type="guarded" → opentype=1 + createmode=1 + createattrs；type="exclusive" → opentype=1 + createmode=2 + createmode 后 verifier4 8 字节（createattrs 不存在）；type="nocreate" → 仅 opentype=0 判别 4 字节，无 createhow4。

**关键校验点**：
- **open_claim4 的 CLAIM_NULL 分支含 component4 file（RFC 7531 §5.2：case CLAIM_NULL: component4 file;）**：claim_type @ 0074 后是 file 字段（len 4 @ 0078 + 'f' 1 + pad 3，至 0x7F）。文件名由 OPEN 自身携带（RFC 7530 §16.18.2），与是否先 LOOKUP 无关。v2.0.2 曾按 r2 误判删除该字段，v2.0.3 已恢复（详见 §11.9 C-1）。
- **openflag4 判别字段是 opentype4 不是 createmode4**：unchecked/guarded/exclusive 配置一律先写 opentype=1 (OPEN4_CREATE)，再写 createhow4 联合（createmode + createattrs/createverf）；"nocreate" 才写 opentype=0（§3.3.1 NFSOpenHow）。
- LOCK4args 没有 open_stateid/lock_stateid 顶层字段；它们嵌套在 locker4 联合内（new_lock_owner=true → open_to_lock_owner4，false → lock_owner4）。
- CLOSE4args 字段名为 `open_stateid`（类型 stateid4），与 §3.3 一致。
- per-owner seqid：open-owner OPEN=1→OPEN_CONFIRM=2→CLOSE=3；lock-owner LOCK=1→LOCKU=2。

### S13. 多会话/多流关联（3 会话并发）

**Config**：`{"version":4, "sessions":3, "sessions_src_port_base":50000, "sessions_src_port_step":1, "ops":[{"procedure":1, "compound_ops":[{"opcode":24},{"opcode":9,"attr_mask":[16,2,0]}]}]}`

**3 个独立 flow 的 4-tuple**：

| Flow | SrcIP | DstIP | SrcPort | DstPort |
|------|-------|-------|---------|---------|
| 1 | 10.0.0.1 | 10.0.0.2 | 50000 | 2049 |
| 2 | 10.0.0.1 | 10.0.0.2 | 50001 | 2049 |
| 3 | 10.0.0.1 | 10.0.0.2 | 50002 | 2049 |

**3 个独立 SETCLIENTID call 的 client.id**：

| Flow | XID | client.id | reply clientid |
|------|-----|-----------|-----------------|
| 0 | 0x00000001 | "trafficgen-client-0" | 0x0000000000010001 |
| 1 | 0x00000001 | "trafficgen-client-1" | 0x0000000000020001 |
| 2 | 0x00000001 | "trafficgen-client-2" | 0x0000000000030001 |

**clientid 核算**：按 §4.3 默认规则 `0x10000*(i+1)+1`（session i 从 0 起）：session 0 = 0x10001、session 1 = 0x20001、session 2 = 0x30001，8 字节 uint64 大端。client.id 为 0-based（"trafficgen-client-{session序号}"，与 T-179 一致）。

**关键校验点**：
- 3 个独立 FlowID。
- 3 个独立 XID 序列（每会话从 1 开始）。
- 3 个独立 (owner, clientid) 对。
- 包序号各 flow 独立计数。

### S14. AUTH_SYS 认证（auth_flavor=1，machinename="host", uid=65534）

**Config 摘要**：`auth_flavor=1, auth_sys={stamp:1, machine_name:"host", uid:65534, gid:65534, groups:[]}`

**CALL RPC 头（含 auth_sys credentials）**：

```
0000    80 00 00 50                          ....        RM (len=80，≥0x50：NFS body 从 0x44 起且至少 12 字节，见 RM 核算)
0004    00 00 00 01                          ....        XID=1
0008    00 00 00 00                          ....        Type=0 (CALL)
000C    00 00 00 02                          ....        RPC Ver=2
0010    00 01 86 A3                          ....        Program=100003
0014    00 00 00 04                          ....        Version=4
0018    00 00 00 01                          ....        Procedure=1 (COMPOUND)
001C    00 00 00 01                          ....        Cred Flavor=1 (AUTH_SYS)
0020    00 00 00 18                          ....        Cred Body Len=24
0024    00 00 00 01                          ....        stamp=1
0028    00 00 00 04                          ....        machinename length=4
002C    68 6F 73 74                          host        machinename="host"
0030    00 00 FF FE                          ....        uid=65534 (nobody)
0034    00 00 FF FE                          ....        gid=65534
0038    00 00 00 00                          ....        GID count=0
003C    00 00 00 00                          ....        Verifier Flavor=0
0040    00 00 00 00                          ....        Verifier Body Len=0
0044    [COMPOUND args]                      ....        NFS payload
```

**RM 长度核算**：CALL 消息不含 RM 部分 = XID(4) + Type(4) + RPCVer(4) + Prog(4) + Ver(4) + Proc(4) + CredFlavor(4) + CredLen(4) + CredBody(24) + VerfFlavor(4) + VerfLen(4) = **64 字节恰好到 0x40**（VerfLen 自身占据 0x40-0x43），NFS body（COMPOUND args）从 0x44 起。本场景的 COMPOUND body 未展开（见 Config 摘要），最小 COMPOUND body 为 12 字节（tag_len 4 + minorversion 4 + argarray_len 4），故消息总长 ≥ 0x44 + 12 = **80 字节**，RM 至少为 `0x80000050`（len=80）。**RM 标注的 len 必须包含 NFS body，不能只算到 RPC 头**（实际生成时 RM 按完整 COMPOUND body 长度计算）。

**关键校验点**：
- Cred Body Len=24（4 stamp + 4 len + 4 machinename + 4 uid + 4 gid + 4 gid_count = 24）。
- machinename "host"=4 字节，恰好对齐 4 字节无需 padding。
- Verifier 仍为 AUTH_NONE（auth_sys 不带 verifier）。

### S15. 错误处理（NFS4ERR_NOFILEHANDLE，reply_status=10020）

**Config**：`{"version":4, "ops":[{"procedure":1, "compound_ops":[{"opcode":9}], "reply_status":10020}]}`

GETATTR 前未 PUTFH/PUTROOTFH，服务端返回 NFS4ERR_NOFILEHANDLE=10020（注意：10003 是 BAD_COOKIE，10020 才是 NOFILEHANDLE）。

**REPLY payload（含 RM）**：

```
0000    80 00 00 2C                          ....        RM (len=44)
0004    00 00 00 01                          ....        XID=1
0008    00 00 00 01                          ....        Type=1 (REPLY)
000C    00 00 00 00                          ....        Reply State=0 (MSG_ACCEPTED)
0010    00 00 00 00                          ....        Verifier Flavor=0
0014    00 00 00 00                          ....        Verifier Body Len=0
0018    00 00 00 00                          ....        Accept State=0 (SUCCESS)
001C    00 00 27 24                          ..'$'       status=10020 (NFS4ERR_NOFILEHANDLE)
0020    00 00 00 00                          ....        tag length=0
0024    00 00 00 01                          ....        resarray length=1
0028    00 00 00 09                          ....        op #1 opcode=9 (GETATTR)
002C    00 00 27 24                          ..'$'        op #1 op_status=10020
0030    [无 GETATTR result，因 op 失败]
```

**关键校验点**：
- 顶层 status=10020（与失败 op 的 op_status 一致）。
- resarray length=1（仅含失败的 GETATTR op，截断规则）。
- 失败 op 后无 result 字段。
- **REPLY 顺序**：status @ 001C 在 tag @ 0020 之前（RFC 7531 §15.2.3）。

**RM 长度核算**：RPC reply 头 24 字节 + COMPOUND reply body（status 4 + tag_len 4 + resarray_len 4 + op[opcode+op_status=8] = 20 字节）= 44 = 0x2C。

### S16. NFSv3 多参数 procedure 的 CALL args（RENAME / LINK / SYMLINK / MKNOD，v2.0.4 新增）

本场景按 RFC 1813 §3.3.10/§3.3.11/§3.3.14/§3.3.15 展开四个多参数 procedure 的 CALL args 字节（RPC CALL 头 40 字节后，args 从 0028 起；XDR 变长 opaque 均带 4 字节长度前缀 + 4 字节对齐填充）。字段映射见 §2.8 表与 §3.2 NFSOp。

**S16a. RENAME（proc 14）**：`procedure=14, filehandle="AAE=", oldname="a.txt", filehandle2="AQIDBA==", newname="b.txt"`

```
0028    00 00 00 01                          ....        from.dir: fh length=1
002C    01                                   .           from.dir: fh data=0x01
002D    00 00 00                             ...         padding (3 字节)
0030    00 00 00 05                          ....        from.name: length=5
0034    61 2E 74 78 74                       a.txt       from.name="a.txt" (5 字节)
0039    00 00 00                             ...         padding (3 字节)
003C    00 00 00 04                          ....        to.dir: fh length=4
0040    01 02 03 04                          ....        to.dir: fh data=01 02 03 04（Filehandle2）
0044    00 00 00 05                          ....        to.name: length=5
0048    62 2E 74 78 74                       b.txt       to.name="b.txt" (5 字节)
004D    00 00 00                             ...         padding (3 字节)
```

**长度核算**：from 8（fh_len 4 + fh 1 + pad 3）+ from.name 12（len 4 + 5 + pad 3）+ to 8（fh_len 4 + fh 4）+ to.name 12（len 4 + 5 + pad 3）= 40 字节，起于 0028 止于 0x0050；CALL 总长 = 40 + 40 = 80 字节，RM = 0x80000050 (len=80)。字段顺序严格为 `from.dir → from.name → to.dir → to.name`（RENAME3args = diropargs3 from + diropargs3 to，RFC 1813 §3.3.14）。

**S16b. LINK（proc 15）**：`procedure=15, filehandle="AAE=", link_dirfh="AQIDBA==", newname="hardlink"`

```
0028    00 00 00 01                          ....        file: fh length=1
002C    01                                   .           file: fh data=0x01
002D    00 00 00                             ...         padding (3 字节)
0030    00 00 00 04                          ....        link.dir: fh length=4
0034    01 02 03 04                          ....        link.dir: fh data=01 02 03 04（LinkDirFh）
0038    00 00 00 08                          ....        link.name: length=8
003C    68 61 72 64 6C 69 6E 6B              hardlink    link.name="hardlink" (8 字节)
0044    （无 padding，8 恰好对齐 4）
```

**长度核算**：file 8（fh_len 4 + fh 1 + pad 3）+ link.dir 8（fh_len 4 + fh 4）+ link.name 12（len 4 + 8，无 pad）= 28 字节，起于 0028 止于 0x0044；CALL 总长 = 40 + 28 = 68 字节，RM = 0x80000044 (len=68)。字段顺序严格为 `file fh → link.dir → link.name`（LINK3args = nfs_fh3 file + diropargs3 link，RFC 1813 §3.3.15）。

**S16c. SYMLINK（proc 10）**：`procedure=10, filehandle="AAE=", filename="link", symlink_target="/target", attributes={set_mode:true, mode:420}`

```
0028    00 00 00 01                          ....        where.dir: fh length=1
002C    01                                   .           where.dir: fh data=0x01
002D    00 00 00                             ...         padding (3 字节)
0030    00 00 00 04                          ....        where.name: length=4
0034    6C 69 6E 6B                          link        where.name="link" (4 字节)
0038    00 00 00 01                          ....        symlink_attributes: set_mode=true（判别值 1）
003C    00 00 01 A4                          ..A.        mode=0644 (420)
0040    00 00 00 00                          ....        set_uid=false（不写 uid 值）
0044    00 00 00 00                          ....        set_gid=false（不写 gid 值）
0048    00 00 00 00                          ....        set_size=false（不写 size 值）
004C    00 00 00 00                          ....        set_atime=0 (DONT_CHANGE)
0050    00 00 00 00                          ....        set_mtime=0 (DONT_CHANGE)
0054    00 00 00 07                          ....        symlink_data: length=7
0058    2F 74 61 72 67 65 74                 /target     symlink_data="/target" (7 字节，SymlinkTarget)
005F    00                                   .           padding (1 字节)
```

**长度核算**：where 8（fh_len 4 + fh 1 + pad 3）+ where.name 8（len 4 + 4，无 pad）+ symlink_attributes 28（sattr3，仅 set_mode=true，§2.8/S3）+ symlink_data 12（len 4 + 7 + pad 1）= 56 字节，起于 0028 止于 0x0060；CALL 总长 = 40 + 56 = 96 字节，RM = 0x80000060 (len=96)。字段顺序严格为 `where.dir → where.name → symlink_attributes（sattr3 判别联合）→ symlink_data`（SYMLINK3args = diropargs3 where + symlinkdata3 symlink，RFC 1813 §3.3.10）。

**S16d. MKNOD（proc 11，NF3CHR）**：`procedure=11, filehandle="AAE=", filename="dev0", ftype=4, devdata="00000102"（specdata1=0x0000, specdata2=0x0102）, attributes={set_mode:true, mode:0x2060}`

```
0028    00 00 00 01                          ....        where.dir: fh length=1
002C    01                                   .           where.dir: fh data=0x01
002D    00 00 00                             ...         padding (3 字节)
0030    00 00 00 04                          ....        where.name: length=4
0034    64 65 76 30                          dev0        where.name="dev0" (4 字节)
0038    00 00 00 04                          ....        what: ftype3 判别=4 (NF3CHR)（Ftype）
003C    00 00 00 01                          ....        dev_attributes: set_mode=true（判别值 1）
0040    00 00 20 60                          .. `        mode=0x2060
0044    00 00 00 00                          ....        set_uid=false
0048    00 00 00 00                          ....        set_gid=false
004C    00 00 00 00                          ....        set_size=false
0050    00 00 00 00                          ....        set_atime=0 (DONT_CHANGE)
0054    00 00 00 00                          ....        set_mtime=0 (DONT_CHANGE)
0058    00 00 00 00                          ....        spec: specdata1=0（主设备号 4B）
005C    00 00 01 02                          ....        spec: specdata2=0x0102（次设备号 4B，Devdata 8 字节）
```

**长度核算**：where 8（fh_len 4 + fh 1 + pad 3）+ where.name 8（len 4 + 4，无 pad）+ what = ftype 判别 4 + devicedata3（dev_attributes 28 + spec 8）= 40 字节，共 56 字节，起于 0028 止于 0x0060；CALL 总长 = 40 + 56 = 96 字节，RM = 0x80000060 (len=96)。字段顺序严格为 `where.dir → where.name → what.type（ftype3 判别）→ dev_attributes（sattr3）→ spec（specdata3）`（MKNOD3args = diropargs3 where + mknoddata3 what，RFC 1813 §3.3.11；NF3CHR/NF3BLK 分支才写 spec，NF3SOCK/NF3FIFO 分支写 sattr3 pipe_attributes 后无 spec，其余类型为 void）。

**关键校验点**：
- **RENAME/LINK/SYMLINK/MKNOD 的 args 均为多字段固定顺序**：RENAME `from.dir → from.name → to.dir → to.name`；LINK `file → link.dir → link.name`；SYMLINK `where.dir → where.name → symlink_attributes → symlink_data`；MKNOD `where.dir → where.name → ftype → dev_attributes → [spec]`。
- **SYMLINK 的 symlink_data 是 nfspath3 = 变长 opaque<>**：带 4 字节长度前缀（"/target"=7 → 00000007 + 7 字节 + 1 字节填充），不是裸字符串。
- **MKNOD 的 mknoddata3 是判别联合**（判别字段 ftype3）：NF3CHR=4/NF3BLK=3 → devicedata3（sattr3 + specdata3 8B）；NF3SOCK=6/NF3FIFO=7 → 仅 sattr3（pipe_attributes，无 spec）；其余 → void。specdata3 = specdata1（主设备号）+ specdata2（次设备号）各 4 字节。
- **RENAME 的双 diropargs3 / LINK 的 link.dir**：第二个 dirfh 由 Filehandle2（RENAME 的 to.dir）与 LinkDirFh（LINK 的 link.dir）表达，与 Filehandle 严格区分。

---

## 7. 测试用例

测试用例遵循 CLAUDE.md §Testing Policy 8 条强制规则：spec-driven（每条对应 §2-§6 的某个字段/状态机分支/HexDump 场景）、覆盖正向+负向+边界、断言可观察输出（包序列、字节、Direction、Opcode、AcceptState、NFS status）。所有字节断言基于 §1.3 RPC 头部布局与 §2.7 COMPOUND 编码（CALL 偏移：RM=0、XID=4、Type=8、RPCVer=12、Program=16、Version=20、Procedure=24、CredFlavor=28、CredLen=32、CredBody=36、VerfFlavor、VerfLen、VerfBody；REPLY 偏移：RM=0、XID=4、Type=8、ReplyState=12、VerfFlavor=16、VerfLen=20、VerfBody=24、AcceptState=24+verf_len（空 verifier 时 @ 24））。XID 假定 base=1；COMPOUND tag 默认空（length=0）；minorversion 默认 0。

### 7.1 连接测试（T-001 ~ T-020）

| 用例 ID | 场景 | 输入 spec 要点 | 期望包序列 | 期望字节/断言 |
|---------|------|----------------|------------|----------------|
| T-001 | NFSv3 NULL call | version=3, ops=[{program:100003,procedure:0}] | TCP 3-way + NULL call + reply + FIN | CALL RM=0x80000028；XID @ 04-07=01；Type @ 08-0B=00；RPCVer @ 0C-0F=02；Program @ 10-13=00 01 86 A3；Version @ 14-17=03；Procedure @ 18-1B=00 |
| T-002 | NFSv3 NULL reply | 同上 | reply 在 call 之后 | REPLY RM=0x80000018；XID @ 04-07=01（echo）；Type @ 08-0B=01；ReplyState @ 0C-0F=00；AcceptState @ 18-1B=00 |
| T-003 | NFSv4 NULL (proc=0) | version=4, ops=[{procedure:0}] | NULL call+reply（不嵌入 COMPOUND） | 同 T-001 但 Version @ 14-17=04；CALL payload 40B（无 NFS body） |
| T-004 | NFSv4 COMPOUND proc=1 | version=4, ops=[{procedure:1,compound_ops:[{opcode:24}]}] | COMPOUND call+reply | Procedure @ 18-1B=01；CALL body 含 tag(0)+minorversion(0)+argarray |
| T-005 | AUTH_NONE 默认 | 默认（auth_flavor 未设） | call cred=AUTH_NONE | CALL CredFlavor @ 1C-1F=00；CredLen @ 20-23=00 |
| T-006 | AUTH_SYS 基础 | auth_flavor=1, auth_sys={stamp:1,machine_name:"host",uid:65534,gid:65534} | call cred=AUTH_SYS | CredFlavor @ 1C-1F=01；CredLen=0x18=24；stamp @ 24-27=01；machinename len @ 28-2B=04；machinename @ 2C-2F="host"；uid @ 30-33=00 00 FF FE |
| T-007 | AUTH_SYS machinename 填充 | auth_flavor=1, machine_name="abc"（3 字节） | call 含 1 字节零填充 | machinename len=03；data=61 62 63；padding=00 |
| T-008 | AUTH_SYS 默认值 | auth_flavor=1, auth_sys 未设 | Validate 用默认值 | stamp=0；machinename="trafficgen"（10B+2B padding=12B）；uid=0；gid=0 |
| T-009 | AUTH_SYS groups | auth_flavor=1, auth_sys.groups=[1000,2000] | call 含 groups 数组 | gid_count=02；gid1=000003E8；gid2=000007D0 |
| T-010 | AUTH_SYS groups 空数组 | auth_flavor=1, groups=[] | call gid_count=0 | gid_count @ offset=00；CredLen 反映无 groups |
| T-011 | RPCSEC_GSS 拒绝 | auth_flavor=6 | Validate 报错 | 错误消息="RPCSEC_GSS not supported" |
| T-012 | auth_flavor=2 (AUTH_SHORT) | auth_flavor=2 | Validate 报错（未实现） | 错误消息含 "unsupported auth_flavor" |
| T-013 | XID 递增默认 | xid_base=1, xid_incr=1, ops=[NULL,NULL] | 2 个 call XID=1,2 | call1 XID=01；call2 XID=02 |
| T-014 | XID 步长=2 | xid_base=100, xid_incr=2 | 2 个 call XID=100,102 | call1 XID=00000064；call2 XID=00000066 |
| T-015 | XID 不递增 | xid_incr=0, ops=[NULL,NULL] | 2 个 call 同 XID | call1 XID == call2 XID（用于测试 echo 行为） |
| T-016 | XID base=0 | xid_base=0 | call XID=0 | CALL XID @ 04-07=00 00 00 00（合法，XID 是 uint32） |
| T-017 | XID 回绕 | xid_base=0xFFFFFFFF, xid_incr=1, ops=[NULL,NULL] | call1 XID=0xFFFFFFFF；call2 XID=0 | 回绕到 0（uint32 溢出） |
| T-018 | Transport=udp (v3) | version=3, transport="udp" | UDP 数据报（无 RM） | UDP call payload 不含 4B RM，直接以 XID 开头 |
| T-019 | Transport=udp 拒绝 (v4) | version=4, transport="udp" | Validate 报错 | 错误消息="NFSv4 requires TCP (transport=tcp)" |
| T-020 | Transport 默认 tcp | transport 未设 | TCP 流 | TCP 3-way handshake 包存在 |

### 7.2 NFSv3 文件操作（T-021 ~ T-060）

| 用例 ID | 场景 | 输入 spec 要点 | 期望包序列 | 期望字节/断言 |
|---------|------|----------------|------------|----------------|
| T-021 | GETATTR call | version=3, ops=[{procedure:1, filehandle:"AAE="}] | MOUNT+GETATTR+UMOUNT | CALL Procedure @ 18-1B=01；fh len=01；fh data=01；padding=00 00 00 |
| T-022 | GETATTR reply | 同 T-021 | reply 含 fattr3 | REPLY AcceptState=0；NFS status=0；fattr3 84B（type+mode+nlink+uid+gid+size+used+rdev+fsid+fileid+atime+mtime+ctime） |
| T-023 | GETATTR fh 长度 4 | filehandle="01020304" | call fh len=4 | fh len @ 2C-2F=04；fh data @ 30-33=01 02 03 04；无 padding |
| T-024 | GETATTR fh 长度 16 | filehandle=16 字节 0x01 | call fh len=16 | fh len=00000010；fh data 16B；无 padding |
| T-025 | GETATTR fh 长度 64 (NFS3_FHSIZE) | filehandle=64 字节 | Validate 通过 | fh len=00000040 |
| T-026 | GETATTR fh 长度 65 越界 (v3) | filehandle=65 字节 | Validate 报错 | 错误消息="filehandle exceeds NFS3_FHSIZE (64)" |
| T-027 | GETATTR fh 长度 128 (v4) | version=4, PUTFH fh=128 字节 | Validate 通过 | NFS4_FHSIZE=128 |
| T-028 | GETATTR fh 长度 129 越界 (v4) | version=4, PUTFH fh=129 字节 | Validate 报错 | 错误消息="filehandle exceeds NFS4_FHSIZE (128)" |
| T-029 | SETATTR mode | procedure=2, attributes={set_mode:true,mode:0644} | call sattr3 | sattr3 set_mode=01；mode=000001A4（0644 octal）；其余 set 判别值全 0（无值字段）；sattrguard3 check=00（默认 false）；sattr3 总长 28B |
| T-030 | SETATTR uid | procedure=2, attributes={set_uid:true,uid:1000} | call sattr3 | set_mode=00；set_uid=01；uid=000003E8；sattrguard3 check=00 |
| T-031 | SETATTR size | procedure=2, attributes={set_size:true,size:4096} | call sattr3 | set_size=01；size=0000000000001000（uint64）；sattrguard3 check=00 |
| T-032 | SETATTR 不设 mode | procedure=2, attributes={set_uid:true,uid:0} | sattr3 mode 字段判别=0 | set_mode @ sattr3=00；**mode 值字段在 wire 上不存在**（false 分支为 void，RFC 1813 §2.6 union set_mode3） |
| T-033 | SETATTR atime SET_TO_SERVER_TIME（未提供 Secs） | set_atime=true, atime_secs 未提供（默认 0，非哨兵） | sattr3 atime 判别=1 | set_atime=01 (SET_TO_SERVER_TIME，不写 nfstime3)；atime_secs 字段值不写入（**SetAtime=true 且 AtimeSecs 未显式提供 → time_how=1**，§2.8） |
| T-034 | SETATTR atime SET_TO_SERVER_TIME（0xFFFFFFFF） | set_atime=true, atime_secs=0xFFFFFFFF（哨兵值） | atime 判别=1 | set_atime=01 (SET_TO_SERVER_TIME)；secs/nsecs 字段不写入 |
| T-035 | SETATTR atime SET_TO_CLIENT_TIME | set_atime=true, atime_secs=1234567890 | atime 判别=2 | set_atime=02 (SET_TO_CLIENT_TIME)；secs=499602D2；nsecs 默认 0（写入 8 字节 nfstime3） |
| T-035a | SETATTR sattrguard check=true | procedure=2, attributes={set_mode:true,mode:0644, sattr_guard_check:true, sattr_guard_ctime_secs:100, sattr_guard_ctime_nsecs:0} | call 含 12 字节 sattrguard3 | sattrguard3 check=01；obj_ctime.secs=00000064；obj_ctime.nsecs=00000000 |
| T-036 | LOOKUP filename | procedure=3, filehandle:"AAE=", filename:"doc.txt" | call 含 dirfh + filename | dirfh len=01；filename len=07（"doc.txt"）；filename data=64 6F 63 2E 74 78 74；padding=00 |
| T-037 | LOOKUP reply | 同 T-036 | reply 含 fh + post_op_attr | NFS status=0；**字段顺序：object fh（fh_len 4B + fh_data 4B）在 obj_attributes 之前**；obj_attributes 判别=01 + fattr3 84B；dir_attributes 判别=00（LOOKUP3resok 三字段，RFC 1813 §3.3.3，见 S4） |
| T-038 | LOOKUP filename 长度 0 | filename="" | call filename len=0 | filename len=00000000；无 filename data |
| T-039 | LOOKUP filename 长 255 | filename="a"×255 | Validate 通过 | filename len=000000FF |
| T-040 | LOOKUP filename 长 256 (NFS3_MAXNAMLEN) | filename="a"×256 | Validate 报错 | 错误消息="filename exceeds NFS3_MAXNAMLEN (255)" |
| T-041 | ACCESS | procedure=4, access=0x1 (READ) | call access 字段 | access=00000001；reply access bits |
| T-042 | READLINK | procedure=5, filehandle:"AAE=" | call + reply | reply 含 symlink + post_op_attr |
| T-043 | READ offset=0 count=5 | procedure=6, filehandle:"AAE=", offset:0, count:5 | call + reply | call offset=0000000000000000；count=00000005；reply post_op_attr → count=00000005 → eof=0/1 → data="hello"（顺序见 §2.2/S5） |
| T-044 | READ reply data | data="hello" | reply 含 5 字节 data | data len=00000005；data=68 65 6C 6C 6F；padding=00 00 00 |
| T-045 | READ count=0 | procedure=6, count:0 | call + reply | call count=0；reply data len=0 |
| T-046 | READ offset 超出 EOF | offset=0xFFFFFFFF, count=10 | reply status=NFS3_OK(0), eof=true, count=0 | NFS status @ reply=00 00 00 00；eof=01（NFSv3 无 NFS3ERR_EOF，用 eof=true 表达） |
| T-047 | WRITE offset=0 stable=FILE_SYNC | procedure=7, filehandle, offset:0, stable_how:2, data:"hello" | call + reply | call stable_how=2；data len=5；reply count=5；committed=2；verf 8B 无长度前缀；wcc_data 92B |
| T-047a | WRITE count≠len(data) 拒绝 | procedure=7, count=10, data:"hello"（5B） | Validate 报错 | 错误消息="write count must equal data length"（V23a） |
| T-048 | WRITE stable=UNSTABLE | stable_how:0 | call stable_how=0 | stable_how @ call=00；reply committed=0；verf 8B（定长 opaque[8] 无长度前缀） |
| T-049 | WRITE stable=DATA_SYNC | stable_how:1 | call stable_how=1 | stable_how @ call=01 |
| T-050 | WRITE stable_how=3 越界 | stable_how:3 | Validate 报错 | 错误消息="stable_how must be 0/1/2" |
| T-051 | WRITE 空数据 | data:"" | call data len=0 | data len=00000000；reply count=0 |
| T-052 | CREATE | procedure=8, filehandle:"AAE=", filename:"new.txt", attributes:{set_mode:true,mode:0644} | call + reply | call filename len=07；reply post_op_fh3 present |
| T-053 | MKDIR | procedure=9, filename:"newdir" | call + reply | procedure @ 18-1B=09 |
| T-054 | SYMLINK | procedure=10, filehandle:"AAE=", filename:"link", symlink_target:"/target", attributes:{set_mode:true,mode:0644} | call + reply | procedure=0A；**args 顺序 where.dir → where.name → symlink_attributes（sattr3 28B）→ symlink_data（SymlinkTarget 路径，len=00000007 + "/target" 7B + pad 1B）**；CALL RM=0x80000060（96B，见 S16c） |
| T-055 | MKNOD | procedure=11, filehandle:"AAE=", filename:"nod", ftype:4 (NF3CHR), devdata:8 字节（specdata1=0x0000, specdata2=0x0102）, attributes:{set_mode:true,mode:0x2060} | call + reply | procedure=0B；**args 顺序 where.dir → where.name → ftype3 判别=00000004 (NF3CHR) → dev_attributes（sattr3 28B）→ spec（specdata3 8B = specdata1 4B + specdata2 4B，Devdata）**；CALL RM=0x80000060（96B，见 S16d） |
| T-055a | MKNOD ftype=NF3FIFO 无 spec | procedure=11, ftype:7 (NF3FIFO), attributes:{set_mode:true,mode:0x2060} | call + reply | procedure=0B；ftype3 判别=00000007；**NF3FIFO 分支只写 sattr3（pipe_attributes）不写 spec**（RFC 1813 §3.3.11 mknoddata3 case NF3FIFO: sattr3 pipe_attributes） |
| T-055b | MKNOD ftype=0 越界 | procedure=11, ftype:0 | Validate 报错 | 错误消息="ftype must be one of NF3REG(1), NF3DIR(2), NF3BLK(3), NF3CHR(4), NF3LNK(5), NF3SOCK(6), NF3FIFO(7)"（V39） |
| T-056 | REMOVE | procedure=12, filehandle:"AAE=", filename:"old.txt" | call + reply | procedure=0C；reply wcc_data |
| T-057 | RMDIR | procedure=13, filename:"emptydir" | call + reply | procedure=0D |
| T-058 | RENAME | procedure=14, filehandle:"AAE=", oldname:"a.txt", filehandle2:"AQIDBA==", newname:"b.txt" | call + reply | procedure=0E；**args 顺序 from.dir（Filehandle）→ from.name（Oldname）→ to.dir（Filehandle2）→ to.name（Newname）**；from.name len=00000005（"a.txt"）+ pad 3B；to.dir fh len=00000004 + data=01 02 03 04；to.name len=00000005（"b.txt"）+ pad 3B；CALL RM=0x80000050（80B，见 S16a） |
| T-059 | LINK | procedure=15, filehandle:"AAE=", link_dirfh:"AQIDBA==", newname:"hardlink" | call + reply | procedure=0F；**args 顺序 file（Filehandle）→ link.dir（LinkDirFh len=00000004 + data=01 02 03 04）→ link.name（Newname len=00000008 + "hardlink" 8B）**；CALL RM=0x80000044（68B，见 S16b） |
| T-059a | READDIR（proc 16，单一 count） | procedure=16, filehandle:"AAE=", cookie=0, cookie_verf=8×00, max_count=8192 | call + reply | procedure=10（hex）；args 仅单一 count=00002000（无 dircount 字段）；reply 含 cookieverf3 8B + entries length + **唯一一个 eof（dirlist3 内层，RFC 1813 §3.3.16）** |
| T-059b | READDIRPLUS（proc 17，双 count） | procedure=17, filehandle:"AAE=", cookie=0, cookie_verf=8×00, dir_count=512, max_count=8192 | call + reply | procedure=11（hex）；args 含 dircount=00000200 + maxcount=00002000；reply 在 post_op_attr 后含 cookieverf3 8B 再 dirlistplus3（entries + **内层唯一 eof @ 0084**，RFC 1813 §3.3.17；无外层 eof，见 S9） |
| T-060 | FSSTAT/FSINFO/PATHCONF | procedure=18/19/20 | call + reply | procedure 范围 12-14（hex） |

### 7.3 NFSv4 COMPOUND（T-061 ~ T-100）

| 用例 ID | 场景 | 输入 spec 要点 | 期望包序列 | 期望字节/断言 |
|---------|------|----------------|------------|----------------|
| T-061 | COMPOUND argarray=1 | version=4, ops=[{procedure:1,compound_ops:[{opcode:24}]}] | COMPOUND call | CALL minorversion @ offset=00；argarray len=00000001；opcode=00000018 (PUTROOTFH) |
| T-062 | COMPOUND tag 空 | tag 未设 | call tag len=0 | tag len @ body=00000000 |
| T-063 | COMPOUND tag 非空 | tag="nfs4" | call + reply echo | call tag len=04；tag="nfs4"；reply tag len=04；tag="nfs4" |
| T-064 | COMPOUND tag 长 1024 | tag="a"×1024 | Validate 通过 | tag len=00000400 |
| T-065 | COMPOUND tag 长 1025 越界 | tag="a"×1025 | Validate 报错 | 错误消息="COMPOUND tag exceeds 1024 bytes" |
| T-066 | procedure=22 (NFSv3 越界) | version=3, ops=[{program:100003, procedure:22}] | Validate 不报错（透传），生成 call proc=22 | CALL Procedure @ 18-1B=16；reply 为正常 MSG_ACCEPTED+SUCCESS（透传；若需模拟真实服务端行为，配置 rpc_accept_state=3 注入 PROC_UNAVAIL，见 T-148） |
| T-067 | minorversion=0 | version=4, MinorVersion=0 | call minorversion=0 | body minorversion=00000000 |
| T-068 | minorversion=1 拒绝 | MinorVersion=1 | Validate 报错 | 错误消息="only NFSv4.0 (minorversion=0) is supported" |
| T-069 | minorversion=nil | MinorVersion 未设 | 默认 0 | body minorversion=00000000（与 T-067 一致） |
| T-070 | PUTFH | compound_ops:[{opcode:22, filehandle:"AAE="}] | call 含 fh | opcode=00000016；fh len=01；fh data=01；padding 3B |
| T-071 | PUTROOTFH | compound_ops:[{opcode:24}] | call 无参数 | opcode=00000018；无 args |
| T-072 | PUTPUBFH | compound_ops:[{opcode:23}] | call 无参数 | opcode=00000017 |
| T-073 | GETATTR 单 op | compound_ops:[{opcode:9, attr_mask:[0x10,0x02,0]}] (size+mode) | call 含 bitmap | opcode=00000009；bitmap len=3；word0=00000010；word1=00000002；word2=0 |
| T-074 | GETATTR reply attrs | 同 T-073 | reply 含 fattr4 | reply op_status=0；**fattr4 = attrmask（bitmap len=3 + word0=00000010 + word1=00000002 + word2=00000000，严格回显 call 全部 word 含尾部 0）+ attr_vals（长度前缀 0000000C + size 8B @ 004C + mode 4B @ 0054）**；完整 reply RM=0x80000054（84B，见 S11） |
| T-075 | GETFH reply | compound_ops:[{opcode:10}] | reply 含 fh | op_status=0；fh len + fh data |
| T-076 | LOOKUP | compound_ops:[{opcode:15, name:"file.txt"}] | call 含 name | opcode=0000000F；name len=08；name="file.txt" |
| T-077 | LOOKUPP | compound_ops:[{opcode:16}] | call 无参数 | opcode=00000010 |
| T-078 | OPEN CLAIM_NULL | compound_ops:[PUTROOTFH, OPEN{seqid:1, share_access:1, claim:{type:"null"}, openhow:{type:"unchecked"}, owner:{clientid:12345, owner:"o1"}}] | call 含 OPEN args | OPEN opcode=00000012；claim discriminator=00000000 (CLAIM_NULL)；**claim 后含 component4 file（len 4 + data + pad，RFC 7531 §5.2 CLAIM_NULL 分支非 void）**；openhow=opentype 00000001 (OPEN4_CREATE) + createmode 00000000 (UNCHECKED4) + createattrs（bitmap_len 0 + attr_vals_len 0） |
| T-079 | OPEN CLAIM_PREVIOUS | claim:{type:"previous", delegate_type:0} | call claim type=1 | claim discriminator=00000001；delegate_type=00000000（4 字节） |
| T-080 | OPEN CLAIM_DELEGATE_CUR | claim:{type:"delegate_cur", delegate_stateid:{seqid:1, other:12×00}, file:"f"} | call claim type=2 | claim discriminator=00000002；**delegate_cur_info = delegate_stateid4 16B（seqid=00000001 + other 12×00）+ component4 file（len=00000001 + data 66 + pad 000000）**（RFC 7531 §5.2 open_claim_delegate_cur4） |
| T-081 | OPEN CLAIM_DELEGATE_PREV | claim:{type:"delegate_prev", delegate_type:0, file:"f"} | call claim type=3 | claim discriminator=00000003；**file_delegate_prev = component4 file（len=00000001 + data 66 + pad 000000）**（RFC 7531 §5.2） |
| T-082 | OPEN UNCHECKED | openhow:{type:"unchecked"} | openhow 编码 | **opentype=00000001 (OPEN4_CREATE)**；createmode=00000000 (UNCHECKED4)；createattrs 空 fattr4（bitmap_len=00000000 + attr_vals_len=00000000） |
| T-083 | OPEN GUARDED | openhow:{type:"guarded"} | openhow 编码 | **opentype=00000001 (OPEN4_CREATE)**；createmode=00000001 (GUARDED4)；createattrs 空 fattr4（bitmap_len=0 + attr_vals_len=0） |
| T-084 | OPEN EXCLUSIVE | openhow:{type:"exclusive", verifier:"0102030405060708"} | openhow 编码 | **opentype=00000001 (OPEN4_CREATE)**；createmode=00000002 (EXCLUSIVE4)；createverf 8B=01 02 03 04 05 06 07 08（无 createattrs，RFC 7531 §5.2） |
| T-085 | OPEN openhow 缺省 | openhow 未设 | Validate 默认 unchecked + 告警 | 默认值 UNCHECKED4；告警日志 |
| T-086 | OPEN claim 缺省 | claim 未设 | Validate 默认 null + 告警 | 默认 CLAIM_NULL |
| T-087 | OPEN share_access=READ | share_access:1 | call share_access=1 | share_access=00000001 |
| T-088 | OPEN share_access=BOTH | share_access:3 | call share_access=3 | share_access=00000003 (READ+WRITE) |
| T-088a | OPEN share_access=0 越界 | share_access:0 | Validate 报错 | 错误消息="share_access must be 1 (READ), 2 (WRITE), or 3 (BOTH)"（V23b） |
| T-088b | OPEN share_access=4 越界 | share_access:4 | Validate 报错 | 同上（V23b） |
| T-089 | OPEN share_deny=WRITE | share_deny:2 | call share_deny=2 | share_deny=00000002 |
| T-089a | OPEN share_deny=3 (BOTH) | share_deny:3 | call share_deny=3 | share_deny=00000003 (DENY4_BOTH，RFC 7530 §16.17.2 OPEN4_SHARE_DENY_BOTH=3，V23b 合法值含 3) |
| T-089b | OPEN share_deny=4 越界 | share_deny:4 | Validate 报错 | 错误消息="share_deny must be 0 (NONE), 1 (READ), 2 (WRITE), or 3 (BOTH)"（V23b） |
| T-090 | OPEN reply stateid | OPEN 后续 op 用同 stateid | reply 含 stateid | op_status=0；stateid seqid + 12B other |
| T-091 | OPEN_CONFIRM (v4.0) | compound_ops:[OPEN, OPEN_CONFIRM{open_stateid, seqid:2}] | 自动补全 OPEN_CONFIRM | OPEN_CONFIRM opcode=00000014；seqid=2（OPEN seqid 1 + 1，RFC 7530 §16.18.4）；OPEN 后追加的 OPEN_CONFIRM 使 argarray length 含补全后的 op 数 |
| T-092 | OPEN_DOWNGRADE | compound_ops:[OPEN, OPEN_DOWNGRADE{stateid, seqid:2, share_access:1, share_deny:0}] | call 含 stateid | opcode=00000015 |
| T-093 | CLOSE | compound_ops:[OPEN, CLOSE{seqid:3, open_stateid:{...}}] | call 含 open_stateid | CLOSE opcode=00000004；reply 含 final stateid |
| T-094 | READ | compound_ops:[PUTFH, READ{stateid, offset:0, count:4096}] | call 含 stateid+offset+count | READ opcode=00000019；reply 含 eof + data |
| T-095 | WRITE | compound_ops:[PUTFH, WRITE{stateid, offset:0, stable_how:2, data:"hello"}] | call 含 stateid+data | WRITE opcode=00000026；reply count+committed+verf |
| T-096 | COMMIT | compound_ops:[PUTFH, COMMIT{offset:0, count:4096}] | call 含 offset+count | COMMIT opcode=00000005；reply verf 8B |
| T-097 | CREATE | compound_ops:[PUTFH, CREATE{objtype:1, name:"f", attrs:{...}}] | call 含 objtype+name | CREATE opcode=00000006；objtype=1 (NF4REG) |
| T-098 | CREATE objtype 缺省 | CREATE{name:"f"}，objtype 未设 | Validate 默认 NF4REG + 告警 | 默认 1 |
| T-099 | REMOVE | compound_ops:[PUTFH, REMOVE{name:"old"}] | call 含 name | REMOVE opcode=0000001C |
| T-100 | RENAME | compound_ops:[PUTFH, RENAME{oldname:"a", newname:"b"}] | call 含 oldname+newname | RENAME opcode=0000001D |

### 7.4 NFSv4 OPEN+LOCK（T-101 ~ T-130）

| 用例 ID | 场景 | 输入 spec 要点 | 期望包序列 | 期望字节/断言 |
|---------|------|----------------|------------|----------------|
| T-101 | SETCLIENTID 自动补全 | version=4, ops=[{procedure:1,compound_ops:[PUTROOTFH,GETATTR]}] | Plan 头部自动插入 SETCLIENTID | 第 1 个 COMPOUND 含 opcode=00000023 (SETCLIENTID)；client.verifier 8B；client.id 默认 "trafficgen-client-0" |
| T-102 | SETCLIENTID_CONFIRM 自动补全 | 同 T-101 | Plan 头部插入 SETCLIENTID_CONFIRM | 第 2 个 COMPOUND 含 opcode=00000024；clientid 8B；verifier 8B |
| T-103 | SETCLIENTID 显式不重复 | ops 含 opcode=35 | Plan 不重复插入 SETCLIENTID | call 中只有 1 个 opcode=35 |
| T-104 | SETCLIENTID_CONFIRM 显式不重复 | ops 含 opcode=35 + opcode=36 | Plan 不重复插入 | call 中各有 1 个 |
| T-105 | SETCLIENTID_CONFIRM 缺失 | ops 含 opcode=35 但无 opcode=36 | Plan 自动追加 SETCLIENTID_CONFIRM | call 序列含 35 然后 36 |
| T-106 | clientid 默认按会话分配 | sessions=2, op clientid=0 | 每会话独立 clientid | session 0 clientid=0x10001；session 1 clientid=0x20001（`0x10000*(i+1)+1`，§4.3） |
| T-107 | clientid 显式非 0 | op clientid=12345 | call 用 12345 | clientid @ body=00 00 00 00 00 00 30 39 |
| T-108 | clientid 跨会话重复 | sessions=2, 两个 op 都设 clientid=100 | Validate 报错 | 错误消息="duplicate clientid across sessions" |
| T-109 | clientid 单会话重复 | sessions=1, 两个 op 都设 clientid=100 | Validate 通过 | 单会话内不限制 |
| T-110 | LOCK new_lock_owner=true | compound_ops:[OPEN, LOCK{lock_type:1, reclaim:false, offset:0, length:100, new_lock_owner:true, open_to_lock_owner:{open_seqid:2, open_stateid:{...}, lock_seqid:1, lock_owner:{...}}}] | call locker4 discriminator=1 | LOCK opcode=0000000C；locker4 new_lock_owner=01；**open_to_lock_owner4.open_seqid=00000002（open_seqid 必须 =2：OPEN_CONFIRM 补全后 open-owner 序列为 OPEN=1 → OPEN_CONFIRM=2 → CLOSE=3，RFC 7530 §16.18.4；open_seqid=1 与补全序列冲突，Validate 报错，见 §4.1 规则 3/S12 说明）** |
| T-111 | LOCK new_lock_owner=false | LOCK{new_lock_owner:false, lock_owner:{clientid, owner}} | locker4 discriminator=0 | new_lock_owner=00；lock_owner4 字段 |
| T-112 | LOCK lock_type=READ_LT | lock_type:1 | call lock_type=1 | lock_type=00000001 |
| T-113 | LOCK lock_type=WRITE_LT | lock_type:2 | call lock_type=2 | lock_type=00000002 |
| T-114 | LOCK lock_type=READW_LT | lock_type:3 | call lock_type=3 | lock_type=00000003（阻塞读锁） |
| T-115 | LOCK reclaim=true | reclaim:true | call reclaim=1 | reclaim @ call=01（用于 lease 恢复场景） |
| T-116 | LOCK reply stateid | LOCK 成功 | reply 含 lock_stateid | op_status=0；stateid 16B |
| T-117 | LOCKT | LOCKT{lock_type:1, offset:0, length:100, owner:{...}} | call 含 owner | LOCKT opcode=0000000D；reply 含冲突 owner 或无 |
| T-118 | LOCKU | LOCKU{lock_type:1, seqid:2, stateid:{...}, offset:0, length:100} | call 含 stateid | LOCKU opcode=0000000E；reply stateid 16B |
| T-119 | seqid 按 owner 独立 | OPEN(seqid=1, open-owner) → LOCK(seqid=1, lock-owner) → LOCKU(seqid=2, lock-owner) → CLOSE(seqid=2, open-owner) | 4 个 op seqid 序列 | OPEN seqid=1；LOCK seqid=1；LOCKU seqid=2；CLOSE seqid=2 |
| T-120 | seqid 回绕 | seqid=0xFFFFFFFF → 0 | Validate 通过 | uint32 溢出合法 |
| T-121 | DELEGPURGE | compound_ops:[DELEGPURGE{clientid:12345}] | call 含 clientid | DELEGPURGE opcode=00000007；clientid 8B |
| T-122 | DELEGRETURN | DELEGRETURN{delegstateid:{...}} | call 含 stateid | DELEGRETURN opcode=00000008 |
| T-123 | RESTOREFH | compound_ops:[SAVEFH, PUTFH, RESTOREFH] | call RESTOREFH 无参数 | RESTOREFH opcode=0000001F |
| T-124 | SAVEFH | SAVEFH | call 无参数 | SAVEFH opcode=00000020 |
| T-125 | VERIFY | VERIFY{attrs:{...}} | call 含 obj_attr | VERIFY opcode=00000025 |
| T-126 | NVERIFY | NVERIFY{attrs:{...}} | call 含 obj_attr | NVERIFY opcode=00000011 |
| T-127 | SETATTR | SETATTR{stateid:{...}, attrs:{...}} | call 含 stateid+attrs | SETATTR opcode=00000022；reply attrsset bitmap |
| T-128 | SECINFO | SECINFO{name:"file"} | call 含 name | SECINFO opcode=00000021；reply secinfo4 list |
| T-129 | RELEASE_LOCKOWNER | RELEASE_LOCKOWNER{owner:{clientid, owner}} | call 含 owner | RELEASE_LOCKOWNER opcode=00000027 |
| T-130 | RENEW | RENEW{clientid:12345} | call 含 clientid | RENEW opcode=0000001E |

### 7.5 数据类型测试（T-131 ~ T-150）

| 用例 ID | 场景 | 输入 spec 要点 | 期望包序列 | 期望字节/断言 |
|---------|------|----------------|------------|----------------|
| T-131 | stateid4 anonymous | stateid={seqid:0, other:12×0x00} | call 16B stateid | seqid=00000000；other=12×00 |
| T-132 | stateid4 READ bypass | stateid={seqid:0xFFFFFFFF, other:12×0xFF} | call 16B stateid | seqid=FF FF FF FF；other=12×FF |
| T-133 | stateid4 other 11 字节不足 | stateid.other=11 字节 | Validate 报错 | 错误消息="stateid other must be 12 bytes" |
| T-134 | stateid4 other 13 字节超长 | stateid.other=13 字节 | Validate 报错 | 同上 |
| T-135 | stateid4 other 12 字节 | stateid.other=12 字节 | Validate 通过 | other 字段 12B 定长 |
| T-136 | MOUNT proc=6 越界 | version=3, ops=[{program:100005, procedure:6}] | Validate 报错 | 错误消息="MOUNT v3 procedure out of range (0-5)" |
| T-137 | clientid4 uint64 | clientid=0x0000000030393930 | call 8B clientid | clientid @ body=00 00 00 00 30 39 39 30 |
| T-138 | bitmap4 单 word | attr_mask:[0x10] | call bitmap len=1 | bitmap len=00000001；word0=00000010 |
| T-139 | bitmap4 双 word | attr_mask:[0x10,0x02] | call bitmap len=2 | bitmap len=00000002；word0=00000010；word1=00000002 |
| T-140 | bitmap4 三 word | attr_mask:[0x10,0x02,0] | call bitmap len=3 | bitmap len=00000003；含 word2=0（user 配置的尾部 0 word **保留原样**不截断，与 S11/§2.7 一致） |
| T-141 | UDP RPC message exceeds 65507 | version=3, transport="udp", data=65508 字节 | Validate 报错 | 错误消息="UDP RPC message exceeds 65507 bytes" |
| T-142 | UDP RPC message 65507 OK | version=3, transport="udp", payload 刚好 65507 | Validate 通过 | 不报错 |
| T-143 | filename UTF-8 多字节 | filename="文件.txt"（10 字节 UTF-8） | call filename len=10 | filename len=0000000A；data=E6 96 87 E4 BB B6 2E 74 78 74 |
| T-144 | opaque padding 对齐 4 | opaque data 1 字节 | 3 字节零填充 | data @ offset=01；padding=00 00 00 |
| T-145 | opaque padding 对齐 4 (2 字节) | opaque data 2 字节 | 2 字节零填充 | data=02；padding=00 00 |
| T-146 | opaque padding 对齐 4 (3 字节) | opaque data 3 字节 | 1 字节零填充 | data=03；padding=00 |
| T-147 | opaque padding 对齐 4 (4 字节) | opaque data 4 字节 | 无填充 | data=04；无 padding |
| T-148 | NFSv3 proc=22+ PROC_UNAVAIL | version=3, ops=[{program:100003, procedure:22, rpc_accept_state:3}] | Validate 通过，生成 call proc=22，reply AcceptState=3 | CALL Procedure @ 18-1B=16；reply AcceptState=3 (PROC_UNAVAIL)（RPC 层错误由指针字段驱动，见 §9.1 示例 2） |
| T-149 | attrmask word2 非零 | attr_mask=[0,0,0x10] | Validate 报错 | 错误消息="attrmask contains NFSv4.1+ attributes" |
| T-150 | nfstime3 8 字节 | atime={secs:1000, nsecs:500} | call 8B nfstime3 | secs=000003E8；nsecs=000001F4 |

### 7.6 错误处理测试（T-151 ~ T-170）

| 用例 ID | 场景 | 输入 spec 要点 | 期望包序列 | 期望字节/断言 |
|---------|------|----------------|------------|----------------|
| T-151 | ResultStatus 全局 | result_status=13 (NFS4ERR_ACCESS) | 所有 reply NFS status=13 | reply 顶层 status=0000000D；resarray 完整（不截断），每个 op_status=0000000D（§2.7/§9.2） |
| T-152 | ReplyStatus 单 op 覆盖 | op.reply_status=10020 | 该 op reply status=10020 | op_status=00002724 |
| T-153 | ReplyStatus 优先级 | result_status=1, op.reply_status=2 | op 用 reply_status=2 | 顶层 status=2 |
| T-154 | NFS4ERR_NOFILEHANDLE | compound_ops:[GETATTR{...}]（无 PUTFH/PUTROOTFH） | reply status=10020 | 顶层 status=00002724；resarray 截断 |
| T-155 | COMPOUND 截断规则 | compound_ops:[PUTROOTFH, GETATTR{op_status:10025}, READ] | reply resarray=2 | resarray len=00000002；READ 不返回；顶层 status=00002729（=失败 op 的 OpStatus 10025，10025=0x2729，§2.7/§9.2 取低 32 位） |
| T-156 | 单 op 失败 | compound_ops:[GETATTR{op_status:1}] | reply 顶层=1，resarray=1 | 顶层 status=00000001；op_status=00000001 |
| T-157 | 多 op 全部成功 | compound_ops:[PUTROOTFH, GETATTR] | reply resarray=2 | 顶层 status=0；每个 op_status=0 |
| T-158 | RPCAcceptState=PROG_UNAVAIL | rpc_accept_state=1 | reply AcceptState=1 | AcceptState @ 18-1B=01（空 verifier 时 @ 24，即 0x18）；无 NFS body |
| T-159 | RPCAcceptState=PROG_MISMATCH | rpc_accept_state=2, rpc_mismatch_low=2, rpc_mismatch_high=3 | reply AcceptState=2 + 版本范围 | AcceptState=02；随后 low=00000002 + high=00000003（8 字节附带字段，§9.1） |
| T-160 | RPCAcceptState=PROC_UNAVAIL | rpc_accept_state=3 | reply AcceptState=3 | AcceptState=03 |
| T-161 | RPCAcceptState=GARBAGE_ARGS | rpc_accept_state=4 | reply AcceptState=4 | AcceptState=04 |
| T-162 | RPCAcceptState=SYSTEM_ERR | rpc_accept_state=5 | reply AcceptState=5 | AcceptState=05 |
| T-163 | RPCRejectState=RPC_MISMATCH | rpc_reject_state=0, rpc_mismatch_low=2, rpc_mismatch_high=2 | reply MSG_DENIED + RPC_MISMATCH | ReplyState=01；RejectState=00；**low/high = 服务端支持的 RPC 版本范围（RFC 5531 §8），注入 low=high=2 表示服务端仅支持 v2**；low=00000002；high=00000002 |
| T-164 | RPCRejectState=AUTH_ERROR | rpc_reject_state=1, auth_stat=1 (AUTH_BADCRED) | reply MSG_DENIED + AUTH_ERROR | ReplyState=01；RejectState=01；auth_stat=01 |
| T-165 | auth_stat=AUTH_REJECTEDCRED | auth_stat=2 | reply reject | auth_stat=02 |
| T-166 | auth_stat=AUTH_BADVERF | auth_stat=3 | reply reject | auth_stat=03 |
| T-167 | auth_stat=AUTH_TOOWEAK | auth_stat=5 | reply reject | auth_stat=05 |
| T-168 | NFS4ERR_MOVED (10019) | reply_status=10019 | reply status=10019 | 顶层 status=00002723 |
| T-169 | NFS4ERR_RESOURCE (10018) | reply_status=10018 | reply status=10018 | 顶层 status=00002722 |
| T-170 | NFS4ERR_BAD_STATEID (10025) | reply_status=10025 | reply status=10025 | 顶层 status=00002729 |

### 7.7 多会话/多流关联（T-171 ~ T-180）

| 用例 ID | 场景 | 输入 spec 要点 | 期望包序列 | 期望字节/断言 |
|---------|------|----------------|------------|----------------|
| T-171 | sessions=1 默认 | sessions 未设 | 单 TCP 流 | 1 个 FlowID；1 个源端口 |
| T-172 | sessions=2 | sessions=2, sessions_src_port_base=40000, sessions_src_port_step=1 | 2 个独立 TCP 流 | FlowID #1 srcPort=40000；FlowID #2 srcPort=40001 |
| T-173 | sessions=3 | sessions=3 | 3 个独立 TCP 流 | 3 个 FlowID；3 个独立 ISN |
| T-174 | sessions=2 step=10 | sessions_src_port_step=10 | 端口间隔 10 | srcPort=40000, 40010 |
| T-175 | sessions=2 step=0 | sessions=2, sessions_src_port_step=0 | Validate 报错 | 错误消息="sessions_src_port_step must be non-zero when sessions>1" |
| T-176 | sessions=1 step=0 OK | sessions=1, sessions_src_port_step=0 | Validate 通过 | sessions=1 时 step 可为 0 |
| T-177 | 多会话 clientid 独立 | sessions=2, op clientid=0 | 每会话独立 clientid | session 0 clientid=0x10001；session 1 clientid=0x20001 |
| T-178 | 多会话 XID 独立 | sessions=2, xid_base=1 | 每会话 XID 独立递增 | 两会话第一个 call XID 都=1（独立序列） |
| T-179 | 多会话 SETCLIENTID client.id 区分 | sessions=2 | 每会话 client.id 不同 | session 0 id="trafficgen-client-0"；session 1 id="trafficgen-client-1" |
| T-180 | 多会话生成顺序 | sessions=3 | 顺序生成不交错 | session 0 全部包 → session 1 全部包 → session 2 全部包 |

### 7.8 边界测试（T-181 ~ T-190）

| 用例 ID | 场景 | 输入 spec 要点 | 期望包序列 | 期望字节/断言 |
|---------|------|----------------|------------|----------------|
| T-181 | version=0 拒绝 | version=0 | Validate 报错 | 错误消息="version must be 3 or 4" |
| T-182 | version=5 拒绝 | version=5 | Validate 报错 | 同上 |
| T-183 | version=2 拒绝 | version=2 | Validate 报错 | 同上（NFSv2 不支持） |
| T-184 | ops 空数组 | ops=[] | Validate 报错 | 错误消息="ops must not be empty" |
| T-185 | filehandle 长度 0 | filehandle="" | Validate 通过 | fh len=00000000；无 data |
| T-186 | count=0 READ | procedure=6, count=0 | Validate 通过 | call count=0；reply data len=0 |
| T-187 | offset uint64 max | offset=0xFFFFFFFFFFFFFFFF | Validate 通过 | offset 8B 全 FF |
| T-188 | cookie uint64 max | cookie=0xFFFFFFFFFFFFFFFF | Validate 通过 | cookie 8B 全 FF |
| T-189 | seqid uint32 max | seqid=0xFFFFFFFF | Validate 通过 | seqid=FF FF FF FF |
| T-190 | clientid uint64 max | clientid=0xFFFFFFFFFFFFFFFF | Validate 通过 | clientid 8B 全 FF |

### 7.9 集成测试（T-191 ~ T-200）

| 用例 ID | 场景 | 输入 spec 要点 | 期望包序列 | 期望字节/断言 |
|---------|------|----------------|------------|----------------|
| T-191 | NFSv3 完整会话 | version=3, ops=[GETATTR, LOOKUP, READ, WRITE, REMOVE] | MOUNT + 5 ops + UMOUNT | 包序列含 MOUNT call/reply + 5 NFS ops + UMOUNT call/reply |
| T-192 | NFSv4 完整会话 | version=4, ops=[{compound_ops:[PUTROOTFH, GETATTR]}, {compound_ops:[PUTFH, LOOKUP, READ]}] | SETCLIENTID + SETCLIENTID_CONFIRM + 2 COMPOUND | 第 1-2 个 COMPOUND 是 SETCLIENTID/CONFIRM；第 3-4 个是用户配置 |
| T-193 | AUTH_SYS 完整会话 | version=4, auth_flavor=1, ops=[...] | 所有 call 含 AUTH_SYS cred | 每 call CredFlavor=01；CredLen=0x18=24（默认 auth_sys：stamp 4 + machinename "trafficgen" 10+2 padding + uid 4 + gid 4 + gid_count 4） |
| T-194 | 错误注入完整会话 | result_status=10020, ops=[{compound_ops:[GETATTR]}] | COMPOUND reply status=10020 | reply 顶层 status=00002724；resarray=1 |
| T-195 | 多会话完整 | sessions=3, ops=[...] | 3 个独立 TCP 流 × 完整序列 | 3 个 FlowID；每会话含 SETCLIENTID+CONFIRM+用户 ops |
| T-196 | MSS 分段 | data=4000 字节（>1460 MSS） | WRITE call 分多段 PSH-ACK | 段 1 含 RM+RPC 头；段 2/3 含 data；每段 PSH+ACK |
| T-197 | 端到端 PCAP 产出 | 完整 spec | 任务提交 → PCAP 文件 | PCAP 含 TCP 3-way + RPC frames + FIN；tshark 解析为 NFS |
| T-198 | Plan → builder 集成 | TDSConfig JSON → trafficgen 字节流 | 字节流含完整 RPC 帧序列 | 字节流可被 Wireshark NFS dissector 解析 |
| T-199 | broken spec 失败 | ops 含非法 clientid 跨会话重复 | 任务实际失败 | 任务状态=failed；失败原因含 "duplicate clientid" |
| T-200 | 全字段端到端 | 同时配置 auth_sys + 多会话 + 错误注入 + 多 op | 包序列正确 | 每 call CredFlavor=01；每会话独立 clientid；reply status=错误码 |

---

## 8. Validate 规则

`NFSConfig.Validate()` 在 `Plan()` 之前调用，返回错误则拒绝该 FlowSpec。规则按 RFC 7530/7531/1813/5531 与 CLAUDE.md §Testing Policy 推导。

### 8.1 顶层字段范围校验

| # | 规则 | 错误消息 |
|---|------|----------|
| V1 | Version 必须 3 或 4 | "version must be 3 or 4" |
| V2 | Transport 仅 "tcp"（默认）或 "udp"（仅 v3） | "transport must be tcp or udp" |
| V3 | Version=4 时 Transport 必须 "tcp" | "NFSv4 requires TCP (transport=tcp)" |
| V4 | Ops 不为空 | "ops must not be empty" |
| V5 | Sessions ≥ 1 | "sessions must be ≥ 1" |
| V6 | Sessions>1 时 SessionsSrcPortStep ≠ 0 | "sessions_src_port_step must be non-zero when sessions>1" |
| V7 | AuthFlavor 仅 0/1 合法；6 (RPCSEC_GSS) 拒绝 | "RPCSEC_GSS not supported" 或 "unsupported auth_flavor" |
| V8 | MinorVersion nil 或 0 | "only NFSv4.0 (minorversion=0) is supported" |

### 8.2 类型兼容性校验

| # | 规则 | 错误消息 |
|---|------|----------|
| V9 | NFSv3 op 不可设 CompoundOps | "compound_ops only valid for NFSv4 (version=4)" |
| V10 | NFSv4 op 不可设 NFSv3 procedure 参数（Filehandle/Filename/Attributes/Offset/Count/Data 等）作为顶层 NFSOp 字段 | "NFSv3 procedure fields not valid for NFSv4 (use compound_ops)" |
| V11 | NFSv4 op Procedure 默认 1 (COMPOUND)；显式设为非 0/1 时报错（proc=0 是 NULL） | "NFSv4 procedure must be 0 (NULL) or 1 (COMPOUND)" |
| V12 | NFSv3 op 不可设 CompoundOps/Tag/OpStatus | "compound fields only valid for NFSv4" |
| V13 | AuthFlavor=1 时 AuthSys 可 nil（用默认值）；AuthFlavor=0 时 AuthSys 必须为 nil | "auth_sys must be nil when auth_flavor=0" |
| V14 | MOUNT op（Program=100005）仅 NFSv3 合法 | "MOUNT program only valid for NFSv3" |
| V15 | UDP RPC 消息 payload ≤ 65507 字节 | "UDP RPC message exceeds 65507 bytes" |

### 8.3 NFSv4 操作码校验

| # | 规则 | 错误消息 |
|---|------|----------|
| V16 | Opcode 0/1/2 非法 | "invalid opcode (must be 3-62)" |
| V17 | Opcode 63+ 非法 | "invalid opcode (must be 3-62)" |
| V18 | Opcode 40-62 透传不报错（NFSv4.1+ 操作） | （不报错，自动补全流程不使用） |
| V19 | OPEN 缺 claim 字段 → 默认 CLAIM_NULL + 告警 | （告警日志，不报错） |
| V20 | OPEN 缺 openhow 字段 → 默认 UNCHECKED4 + 告警 | （告警日志，不报错） |
| V21 | CREATE 缺 objtype 字段 → 默认 NF4REG + 告警 | （告警日志，不报错） |
| V22 | LOCK 缺 new_lock_owner 字段 → 默认 false | （不报错） |
| V23 | StableHow 仅 0/1/2 合法 | "stable_how must be 0 (UNSTABLE4), 1 (DATA_SYNC4), or 2 (FILE_SYNC4)" |
| V23a | WRITE count 必须等于 len(data)（RFC 1813 WRITE3args / RFC 7531 WRITE4args） | "write count must equal data length" |
| V23b | OPEN 的 share_access 仅 1/2/3 合法（OPEN4_SHARE_ACCESS_READ=1 / WRITE=2 / BOTH=3）；share_deny 仅 0/1/2/3 合法（OPEN4_SHARE_DENY_NONE=0 / READ=1 / WRITE=2 / BOTH=3）；其他值报错（RFC 7530 §16.17.2 原文："the client must specify a value for share_access that is one of OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_ACCESS_WRITE, or OPEN4_SHARE_ACCESS_BOTH. For share_deny, the client must specify one of OPEN4_SHARE_DENY_NONE, OPEN4_SHARE_DENY_READ, OPEN4_SHARE_DENY_WRITE, or OPEN4_SHARE_DENY_BOTH. If the client fails to do this, the server must return NFS4ERR_INVAL"） | "share_access must be 1 (READ), 2 (WRITE), or 3 (BOTH)" / "share_deny must be 0 (NONE), 1 (READ), 2 (WRITE), or 3 (BOTH)" |
| V39 | NFSv3 MKNOD 的 Ftype 仅 1-7 合法（ftype3 枚举 NF3REG=1/NF3DIR=2/NF3BLK=3/NF3CHR=4/NF3LNK=5/NF3SOCK=6/NF3FIFO=7，RFC 1813 §2.5）；其他值报错 | "ftype must be one of NF3REG(1), NF3DIR(2), NF3BLK(3), NF3CHR(4), NF3LNK(5), NF3SOCK(6), NF3FIFO(7)" |

### 8.4 filehandle / stateid / clientid 长度校验

| # | 规则 | 错误消息 |
|---|------|----------|
| V24 | NFSv3 Filehandle 长度 ≤ 64 (NFS3_FHSIZE) | "filehandle exceeds NFS3_FHSIZE (64)" |
| V25 | NFSv4 PUTFH Filehandle 长度 ≤ 128 (NFS4_FHSIZE) | "filehandle exceeds NFS4_FHSIZE (128)" |
| V26 | MountFilehandle 长度 ≤ 64 (NFS3_FHSIZE) | "mount_filehandle exceeds NFS3_FHSIZE (64)" |
| V27 | Stateid.Other 必须 12 字节 | "stateid other must be 12 bytes" |
| V28 | ClientidVerifier 必须 8 字节 | "clientid_verifier must be 8 bytes" |
| V29 | CookieVerf 必须 8 字节 | "cookie_verifier must be 8 bytes" |
| V30 | AttrMask 非零 word 仅 word 0/1（attr 0-63）；word 2+ 非零报错 | "attrmask contains NFSv4.1+ attributes" |
| V31 | NFSv3 filename 长度 ≤ 255 (NFS3_MAXNAMLEN) | "filename exceeds NFS3_MAXNAMLEN (255)" |
| V32 | COMPOUND tag 长度 ≤ 1024 | "COMPOUND tag exceeds 1024 bytes" |
| V33 | MOUNT procedure 范围 0-5（v3） | "MOUNT v3 procedure out of range (0-5)" |
| V34 | NFSv3 NFS procedure 22+ 透传不报错（PROC_UNAVAIL 测试） | （不报错） |
| V35 | AuthSys.MachineName ≤ 255 字节 | "machine_name exceeds 255 bytes" |

### 8.5 跨会话一致性校验

| # | 规则 | 错误消息 |
|---|------|----------|
| V36 | Sessions>1 时多个会话显式配置相同 clientid ≠ 0 报错 | "duplicate clientid across sessions" |
| V37 | 单会话内 clientid 重复不报错 | （不报错） |
| V38 | SETCLIENTID_CONFIRM 必须跟随 SETCLIENTID（自动补全保证） | （不报错，Plan 自动追加） |

---

## 9. 错误处理

### 9.1 RPC 层错误

RPC 层错误由 `NFSOp.RPCAcceptState` / `RPCRejectState` 指针字段控制，nil = 走默认成功路径（MSG_ACCEPTED + SUCCESS）。

**MSG_ACCEPTED + 非 SUCCESS AcceptState**（AcceptState=1-5）：

```
REPLY payload:
  RM (4B) + XID (4B echo) + Type=1 (4B) + ReplyState=0 (4B MSG_ACCEPTED)
  + Verifier Flavor=0 (4B) + Verifier Body Len=0 (4B)
  + AcceptState (4B, 1-5)
  [AcceptState=2 (PROG_MISMATCH) 时：+ low (4B) + high (4B) version 范围]
  [无 NFS body]
```

| AcceptState | 含义 | 触发条件 |
|-------------|------|----------|
| 1 | PROG_UNAVAIL | 服务端不支持该 Program（如 100003） |
| 2 | PROG_MISMATCH | 服务端支持该 Program 但 Version 不匹配；附带 low/high version 范围 |
| 3 | PROC_UNAVAIL | 服务端支持该 Program+Version 但 Procedure 越界（如 NFSv3 proc=22） |
| 4 | GARBAGE_ARGS | RPC 参数解码失败 |
| 5 | SYSTEM_ERR | 服务端内部错误 |

**MSG_DENIED**（ReplyState=1）：

```
REPLY payload:
  RM + XID + Type=1 + ReplyState=1 (MSG_DENIED)
  + RejectState (4B, 0=RPC_MISMATCH / 1=AUTH_ERROR)
  [if RPC_MISMATCH: low (4B) + high (4B)]
  [if AUTH_ERROR: auth_stat (4B, 1-7)]
```

| RejectState | 含义 | 附带字段 |
|-------------|------|----------|
| 0 | RPC_MISMATCH | rpc_mismatch_low + rpc_mismatch_high（**low/high 是服务端支持的 RPC 版本范围**，RFC 5531 §8：reject 表示服务端只支持 low..high 而客户端版本不在其中；通常 low=high=2；**该分支无 auth_stat**） |
| 1 | AUTH_ERROR | auth_stat（1=AUTH_BADCRED, 2=AUTH_REJECTEDCRED, 3=AUTH_BADVERF, 4=AUTH_REJECTEDVERF, 5=AUTH_TOOWEAK, 6=AUTH_INVALIDRESP, 7=AUTH_FAILED；**该分支无 low/high**） |

### 9.2 NFS 层错误

NFS 层错误由 `NFSConfig.ResultStatus`（全局默认）或 `NFSOp.ReplyStatus`（单 op 覆盖）或 `NFSv4CompoundOp.OpStatus`（per-op 失败注入）控制。

**NFSv3 reply 错误**：reply 的 NFS status 字段填错误码（如 NFS3ERR_NOENT=2），结果体按 spec 缩短（如 GETATTR 失败只返回 status，无 fattr3）。

**NFSv4 COMPOUND reply 错误**：

| 情形 | 顶层 status | oparray 内容 | 单 op 的 op_status |
|------|-------------|--------------|---------------------|
| 单 op COMPOUND，ReplyStatus≠0 | = ReplyStatus | 仅含该 op | = ReplyStatus |
| 多 op COMPOUND，所有 op 成功 | NFS4_OK (0) | 含全部 op | 每个 op = NFS4_OK |
| 多 op COMPOUND，第 i 个 op OpStatus≠0 | = 第 i op 的 OpStatus | 仅含 op 1..i（截断） | op 1..i-1 = NFS4_OK，op i = OpStatus |
| ResultStatus≠0（全局，所有 op 正常执行） | = ResultStatus | 含全部 op（不截断） | 每个 op = ResultStatus |

**字段优先级**：`NFSOp.ReplyStatus > NFSConfig.ResultStatus > 默认 0 (NFS4_OK)`。

### 9.3 业务错误

业务错误通过显式配置错误码模拟，不模拟真实文件系统状态机的复杂性（§1.4 规则 1）：

| 业务场景 | 错误码 | 配置方式 |
|----------|--------|----------|
| 文件不存在 | NFS4ERR_NOENT=2 / NFS3ERR_NOENT=2 | reply_status=2 |
| 权限不足 | NFS4ERR_PERM=1 / NFS3ERR_PERM=1 | reply_status=1 |
| 访问拒绝 | NFS4ERR_ACCESS=13 / NFS3ERR_ACCES=13 | reply_status=13 |
| 文件已存在 | NFS4ERR_EXIST=17 / NFS3ERR_EXIST=17 | reply_status=17 |
| 不是目录 | NFS4ERR_NOTDIR=20 | reply_status=20 |
| 是目录 | NFS4ERR_ISDIR=21 | reply_status=21 |
| 参数错误 | NFS4ERR_INVAL=22 | reply_status=22 |
| 只读文件系统 | NFS4ERR_ROFS=30 | reply_status=30 |
| 文件名过长 | NFS4ERR_NAMETOOLONG=63 | reply_status=63 |
| 目录非空 | NFS4ERR_NOTEMPTY=66 | reply_status=66 |
| 旧 filehandle | NFS4ERR_STALE=70 | reply_status=70 |
| 无效 filehandle | NFS4ERR_BADHANDLE=10001 | reply_status=10001 |
| 当前无 filehandle | NFS4ERR_NOFILEHANDLE=10020 | reply_status=10020（GETATTR 前未 PUTFH/PUTROOTFH） |
| 无效 stateid | NFS4ERR_BAD_STATEID=10025 | reply_status=10025 |
| seqid 错误 | NFS4ERR_BAD_SEQID=10026 | reply_status=10026 |
| 文件系统已迁移 | NFS4ERR_MOVED=10019 | reply_status=10019 |
| 资源不足 | NFS4ERR_RESOURCE=10018 | reply_status=10018 |
| 超时（lease 过期） | NFS4ERR_EXPIRED=10011 | reply_status=10011（RENEW 失败场景） |
| 服务端忙（暂时无法处理） | NFS4ERR_DELAY=10008 | reply_status=10008（模拟服务端资源忙，RFC 7530 §13.1.9） |
| cookieverf 不匹配 | NFS4ERR_NOT_SAME=10027 | reply_status=10027（READDIR 场景，RFC 7530 §13.1.9） |
| 旧 stateid | NFS4ERR_OLD_STATEID=10024 | reply_status=10024 |
| stateid 过期 | NFS4ERR_STALE_STATEID=10023 | reply_status=10023 |
| clientid 过期 | NFS4ERR_STALE_CLIENTID=10022 | reply_status=10022 |
| 非法 opcode | NFS4ERR_OP_ILLEGAL=10044 | reply_status=10044 |
| XDR 解码失败 | NFS4ERR_BAD_XDR=10036 | reply_status=10036 |

### 9.4 错误注入示例

**示例 1：NFSv4 GETATTR 前未 PUTFH（NFS4ERR_NOFILEHANDLE）**

```json
{
  "version": 4,
  "ops": [{
    "procedure": 1,
    "compound_ops": [{"opcode": 9, "attr_mask": [16]}],
    "reply_status": 10020
  }]
}
```

生成序列：
1. SETCLIENTID call/reply（自动补全）
2. SETCLIENTID_CONFIRM call/reply（自动补全）
3. COMPOUND call（GETATTR，无 PUTFH/PUTROOTFH）
4. COMPOUND reply（顶层 status=10020，resarray=1，op_status=10020，无 GETATTR result）

**示例 2：RPC PROC_UNAVAIL（NFSv3 proc=22）**

```json
{
  "version": 3,
  "ops": [{
    "program": 100003, "prog_version": 3, "procedure": 22,
    "rpc_accept_state": 3
  }]
}
```

生成序列：
1. MOUNT call/reply（自动补全）
2. NFS call（proc=22，正常生成，透传不报错）
3. NFS reply（MSG_ACCEPTED + AcceptState=3 PROC_UNAVAIL，无 NFS body；AcceptState 由 `rpc_accept_state` 指针字段驱动，nil=成功路径，见 §9.1）
4. UMOUNT call/reply（自动补全）

**示例 3：RPC AUTH_ERROR（认证失败）**

```json
{
  "version": 4,
  "auth_flavor": 1,
  "ops": [{
    "procedure": 1,
    "compound_ops": [{"opcode": 24}],
    "rpc_reject_state": 1,
    "auth_stat": 1
  }]
}
```

生成序列：
1. SETCLIENTID call/reply（自动补全，正常）
2. SETCLIENTID_CONFIRM call/reply（自动补全，正常）
3. COMPOUND call（PUTROOTFH，AUTH_SYS cred）
4. COMPOUND reply（MSG_DENIED + AUTH_ERROR + auth_stat=1 AUTH_BADCRED，无 NFS body）

### 9.5 已知偏离

本设计存在以下已知偏离真实 NFS 协议的行为，登记为扩展点：

1. **MOUNT/NFS 同连接**：真实 NFSv3 客户端先经 rpcbind（端口 111）查 mountd 端口（通常 635），在独立 TCP 连接上完成 MNT，再在另一条连接（2049）上做 NFS 操作；本设计为简化合成流量将 MOUNT + NFS + UMOUNT 都放在同一 4-tuple（端口 2049）上。
2. **OPEN_CONFIRM stateid 不模拟服务端递增**：OPEN_CONFIRM 的 seqid 按 RFC 7530 §16.18.4 要求 = OPEN seqid + 1；差异点在于本设计不模拟服务端在 OPEN reply 中递增 stateid.seqid 的交互过程，open_stateid 由 Plan 确定性合成。
3. **不模拟 RTT 重传**：Plan 不模拟 RPC 超时重传（timeo/retrans），所有 call 假定立即收到 reply。
4. **不实现 NFSv4.1+ pNFS**：不实现 GETDEVICEINFO / LAYOUTGET / LAYOUTRETURN 等布局操作。
5. **不实现回调通道**：CB_COMPOUND (procedure 2) 不生成。
6. **不实现 RPCSEC_GSS**：仅支持 AUTH_NONE 与 AUTH_SYS。
7. **不实现 NFSv4.1 会话机制**：不使用 EXCHANGE_ID/CREATE_SESSION/DESTROY_SESSION（这些是 v4.1 操作，opcode 42/43/44）。
8. **会话间不交错**：多会话场景下 Plan 按会话序号顺序生成，不实现 Interleave 交错模式。
9. **stateid 一致性由用户负责**：Plan 只做透传，不自动改写全 0 stateid。若用户希望后续 op 引用 OPEN reply 的 stateid，需自行配置。
10. **seqid 自动递增仅在 user 未显式提供时**：user 显式提供 Seqid 时使用 user 值，不覆盖。

---

## 10. 扩展字段映射

### 10.1 trafficgen 概念 → NFS 协议对应

| trafficgen 概念 | NFS 对应 | 说明 |
|-----------------|----------|------|
| Flow（流） | NFS 会话（TCP 连接） | 一个 Flow = 一次 TCP 连接 + RPC 帧序列 |
| 子流（SubFlow） | 多会话（Sessions>1） | Flow 内多个独立 4-tuple，每会话独立 clientid/XID |
| 阶段（Phase） | RPC 往返（call + reply） | 每个 NFSOp 是一个阶段 |
| 载荷（Payload） | RPC args/result | 按 procedure/opcode 编码 |
| 校验和 | RPC/NFS 无应用层校验和 | 依赖 TCP 校验和；UDP 有 UDP 校验和 |
| 包长 | RPC RecordMark 字段 | 生成器自动计算 RM = 0x80000000 \| len(msg) |
| 事务 | XID | RPC 事务标识符，reply echo call |
| 鉴权 | AUTH_NONE / AUTH_SYS | flavor + credentials + verifier |
| 状态 | stateid4 + clientid4 + seqid | NFSv4 有状态；NFSv3 无状态 |

### 10.2 PacketConfig Metadata 映射

planner 生成的每个 RPC 帧对应一个 `PacketConfig`，Metadata 字段映射如下：

| Metadata 键 | 来源 | 说明 |
|-------------|------|------|
| `nfs_xid` | §3.2 XIDBase/XIDIncr | XID，写入 RPC 头偏移 4-7（uint32 BE） |
| `nfs_msg_type` | 请求/响应 | 0=CALL（up）/ 1=REPLY（down） |
| `nfs_rpc_version` | 固定 2 | RPC 版本，写入偏移 12-15 |
| `nfs_program` | §3.2 Program | 100003 (NFS) / 100005 (MOUNT)，写入偏移 16-19 |
| `nfs_prog_version` | §3.2 ProgVersion | v3=3 / v4=4，写入偏移 20-23 |
| `nfs_procedure` | §3.2 Procedure | procedure 编号，写入偏移 24-27 |
| `nfs_cred_flavor` | §3.1 AuthFlavor | 0=AUTH_NONE / 1=AUTH_SYS，写入偏移 28-31 |
| `nfs_verifier_flavor` | 默认 0 | Verifier Flavor，写入偏移（Cred 后） |
| `nfs_reply_state` | REPLY 专用 | 0=MSG_ACCEPTED / 1=MSG_DENIED，写入偏移 12-15 |
| `nfs_accept_state` | REPLY 专用 | 0=SUCCESS / 1-5 错误，写入偏移 24+verf_len（空 verifier 时 @ 24-27） |
| `nfs_status` | NFS 层 | NFS4_OK / 错误码；NFSv3 reply 与 NFSv4 COMPOUND reply 顶层 status（NFSv4 在 tag 之前，详见 §2.7），写入 NFS body 起始。ResultStatus≠0 时所有 op 正常执行、oparray 完整、每个 op_status=ResultStatus（不截断，§2.7/§9.2） |
| `nfs_compound_minorversion` | §3.1 MinorVersion | COMPOUND minorversion=0，写入 body 偏移 |
| `nfs_compound_tag` | §3.2 Tag | COMPOUND tag，写入 body 偏移 |
| `nfs_opcode` | §3.3 Opcode | COMPOUND 内 op 编号，写入 oparray 元素 |
| `nfs_op_status` | §3.3 OpStatus | per-op status，写入 reply oparray |
| `nfs_filehandle` | §3.2 Filehandle | filehandle 字节，写入 procedure args |
| `nfs_stateid` | §3.4 NFSStateid | 16B stateid（seqid + 12B other） |
| `nfs_clientid` | §3.3 Clientid | 8B uint64 clientid |
| `nfs_seqid` | §3.3 Seqid | uint32 seqid |
| `nfs_direction` | 请求/响应 | "call"（up）/ "reply"（down） |
| `nfs_session_id` | 多会话 | 会话序号（0-based） |

### 10.3 字段流向

```
NFSConfig ──> planner ──> PacketConfig.Metadata
                              │
                              v
                          builder ──> RPC/NFS PDU bytes
                              │
                              v
                          TCP segment / UDP datagram ──> PCAP
```

planner 从 NFSConfig 读取配置，按 §4 状态机生成每个 RPC 帧的 Metadata；builder 从 Metadata 读取字段值，按 §1.3/§2.7 偏移表写入 RPC 头和 NFS body。

### 10.4 多会话 clientid 分配

planner 内部按会话序号分配独立 clientid（user 未显式提供时）：

```go
func defaultClientID(sessionIdx int) uint64 {
    return uint64(0x10000)*uint64(sessionIdx+1) + 1
    // session 0: 0x0000000000010001
    // session 1: 0x0000000000020001
    // session 2: 0x0000000000030001
}
```

每会话的 SETCLIENTID reply 返回的 clientid 即为该会话的默认 clientid；user 显式配置 clientid≠0 时使用 user 值（该取值规则对 **SETCLIENTID reply 的合成**同样成立，与 §4.3 规则 3 一致：call 侧与 reply 侧同源，user 显式配置时回显 user 值，否则用默认公式）。跨会话校验相同 clientid 由 V36 保证。

### 10.5 XID 生成

```go
func (s *session) nextXID(opIdx int) uint32 {
    base := s.cfg.XIDBase
    if base == 0 {
        base = 1
    }
    incr := s.cfg.XIDIncr
    if incr == 0 {
        return base  // XIDIncr=0 时所有 call 同 XID
    }
    return base + uint32(opIdx)*uint32(incr)
}
```

### 10.6 RPC 头写入

```go
func writeRPCCallHeader(buf *bytes.Buffer, xid, prog, ver, proc uint32, credFlavor uint32, credBody []byte) {
    binary.Write(buf, binary.BigEndian, xid)
    binary.Write(buf, binary.BigEndian, uint32(0))        // Type=CALL
    binary.Write(buf, binary.BigEndian, uint32(2))        // RPC Version=2
    binary.Write(buf, binary.BigEndian, prog)             // Program
    binary.Write(buf, binary.BigEndian, ver)              // Version
    binary.Write(buf, binary.BigEndian, proc)             // Procedure
    binary.Write(buf, binary.BigEndian, credFlavor)       // Cred Flavor
    binary.Write(buf, binary.BigEndian, uint32(len(credBody))) // Cred Body Len
    buf.Write(credBody)
    binary.Write(buf, binary.BigEndian, uint32(0))        // Verifier Flavor=0
    binary.Write(buf, binary.BigEndian, uint32(0))        // Verifier Body Len=0
}
```

### 10.7 9.4.1.38 协议扩展表对应

trafficgen 将 NFS 协议能力映射到 9.4.1.38 协议扩展信息上报（扩展表 #8 `nfsProtRpt`）：

| 扩展表字段 | trafficgen 对应 | 说明 |
|------------|-----------------|------|
| 协议名称 | NFS | Network File System |
| 规范来源 | RFC 7530 (v4.0) / RFC 1813 (v3) / RFC 5531 (ONC RPC) | 三份 RFC 共同定义 |
| 传输层 | TCP / UDP | v4 仅 TCP；v3 可 TCP 或 UDP |
| 默认端口 | 2049 | NFS 标准端口 |
| 支持版本 | NFSv3 + NFSv4.0 | 不实现 v4.1+ |
| 鉴权机制 | AUTH_NONE / AUTH_SYS | 不实现 RPCSEC_GSS |
| 状态模型 | v3 无状态 / v4 有状态 | v4 含 clientid/stateid/seqid |
| 操作模型 | v3 一请求一 procedure / v4 COMPOUND | v4 单 RPC 内串行多 operation |
| 文件句柄来源 | v3 MOUNT 协议 / v4 LOOKUP/OPEN | v4 不需 MOUNT |
| 锁模型 | v3 独立 NLM / v4 内建 LOCK/LOCKT/LOCKU | v4 锁内建于 COMPOUND |
| 字符编码 | v3 字节 / v4 UTF-8 | v4 文件名 UTF-8 (RFC 7530 §14) |
| 会话机制 | v4.0 无 / v4.1 有 | 本设计仅 v4.0（无 CREATE_SESSION） |
| 最大 filehandle | v3 64B (NFS3_FHSIZE) / v4 128B (NFS4_FHSIZE) | Validate 强制 |
| 最大 filename | 255 (NFS3_MAXNAMLEN) | Validate 强制 |
| 最大 UDP 消息 | 65507 字节 | IP datagram 65535 - IP 20 - UDP 8 |

---

## 11. 修订记录

| 版本 | 日期 | 修订内容 |
|------|------|----------|
| v2.0.4 | 2026-08-05 | 修复复审（r4）发现的 8 个问题（0 CRITICAL + 1 HIGH + 3 MEDIUM + 4 LOW）：§3.2 NFSOp 补齐 NFSv3 多参数 procedure 的 Config 字段（RENAME 双 dirfh 双名 / LINK link_dirfh / SYMLINK symlink_target / MKNOD ftype+devdata），新增 §2.8 字段映射表、§6 S16a-S16d 字节级场景、T-054/055/058/059 输入同步；S14 RM 修正（0x40→0x50，消息 ≥80B）；S9 RM 核算文字修正（128→132=0x84）；T-110 open_seqid 1→2 与 §4.1 规则 3/S12 统一；§2.6 匿名 stateid 字节标注补 seqid；T-143 filename len 6→10；S2 标题"4 字节"→"1 字节"；新增 V23b（share_access/share_deny 范围校验，按 RFC 7530 §16.17.2 原文 share_deny 合法值含 BOTH=3）+ V39（MKNOD ftype）+ T-055a/055b/087 负例/088a/088b/089a/089b；详见 §11.10 |
| v2.0.3 | 2026-08-05 | 修复复审（r3）发现的 15 个问题（5 CRITICAL + 3 HIGH + 4 MEDIUM + 3 LOW）：撤销 r2 的两个反向修复（恢复 S12 CLAIM_NULL 的 component4 file、删除 S9 多余的外层 eof）；S11 GETATTR result 补 fattr4 attr_vals 长度前缀（RM 0x50→0x54）；S4 LOOKUP reply 重排为 fh→obj_attributes→dir_attributes；S12 openhow 改为 opentype4 判别 + createhow4（含 createattrs）；time_how 映射与 T-155 hex 修正；详见 §11.9 |
| v2.0.2 | 2026-08-05 | 修复复审（r2）发现的 25 个问题（3 CRITICAL + 7 HIGH + 10 MEDIUM + 5 LOW）：sattr3 判别联合编码整体修正（S3/S7 + §2.8 + T-029~T-035）；RM 长度全部重算（S1/S2 及 S4-S12 CALL 偏移统一 40 字节头）；writeverf3/verf4 去长度前缀（S6/S10）；clientid 三处矛盾统一 0x10000*(i+1)+1；AcceptState 偏移声明修正；S12 纳入 OPEN_CONFIRM 补全；wcc_data 92 字节结构统一；S11 GETATTR result 展开（其中 S12 CLAIM_NULL 删 file、S9 补双 eof 两项为按 r2 误判的反向修复，v2.0.3 §11.9 C-1/C-2 已撤销）；详见 §11.8 |
| v2.0.1 | 2026-08-05 | 修复审计发现的 13 个问题（3 CRITICAL + 4 HIGH + 3 MEDIUM + 3 LOW）：§2.5 操作码表 38-40 映射错误（C1）；§2.7 COMPOUND reply 顺序修正为 status→tag→resarray（C2）；S9 改为 READDIRPLUS（C3）；EXCHANGE_ID=42 修正（H1）；§3.2 NFSAttributes 追加 sattrguard3 字段（H2）；§2.2 READDIR 参数表修正（H3）；S9 reply 补充 cookieverf3（H4）；NFS3ERR_MLINK 值 32→31（M1）；S11 CALL/REPLY RM 值修正（M2）；§4.1 OPEN_CONFIRM 注释措辞修正（M3）；S5 fattr3 字节数标注 80→84（L1）；T-046 期望修正（L2）；CookieVerf 注释精确化（L3） |
| v2.0.0 | 2026-08-05 | 基于 RFC 7530/7531/1813/5531 完整重写：修复 29 个问题（6 CRITICAL + 9 HIGH + 8 MEDIUM + 6 LOW）；新增 200+ 条测试用例（T-001 ~ T-200）；新增 §8 Validate 规则 38 条、§9 错误处理完整表、§10 扩展字段映射、§11 修订记录 |
| v1.1 | 2026-08-01 | 补充 NFSv4 COMPOUND 编码细节、stateid4/clientid4 字段语义、15 个 HexDump 场景初版 |
| v1.0 | 2026-07-30 | 初稿：基于 RFC 7530/1813 编写设计文档，覆盖 NFSv3/v4 基本字段与状态机 |

### 11.1 v2.0.0 修复的 CRITICAL 问题（6 个）

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| C-1 | RPC CALL 头部布局系统性偏移错误（缺失 Verifier 字段、Procedure 偏移错位） | §1.3 重写为 RFC 5531 §8 标准布局：XID=4、Type=8、RPCVer=12、Program=16、Version=20、Procedure=24、CredFlavor=28、CredLen=32、CredBody=36+、VerfFlavor、VerfLen、VerfBody（**空 cred/verf 时 RPC 头共 40 字节：CredBody=36、VerfFlavor=36、VerfLen=40、args 从 44=0x2C 起**） |
| C-2 | NFSv4 COMPOUND 编码错误（tag/minorversion/argarray 顺序混乱） | §2.7 重写为 RFC 7531 §5.2 标准顺序：tag → minorversion → argarray length → [opcode + args]... |
| C-3 | stateid4 other 字段长度错误（误为变长 opaque<>） | §2.6 修正为定长 12 字节 opaque[12]（RFC 7531 §3），无长度前缀 |
| C-4 | clientid4 类型错误（误为 uint32） | §2.6 修正为 uint64（8 字节，RFC 7531 §3 `typedef uint64_t clientid4;`） |
| C-5 | NFS4_FHSIZE / NFS3_FHSIZE 边界错误（误为统一 128） | §2.6/§8.4 区分：NFSv3 ≤64 (NFS3_FHSIZE)、NFSv4 ≤128 (NFS4_FHSIZE)，Validate 分别校验 |
| C-6 | NFS4ERR_NOFILEHANDLE 错误码错误（误用 10003） | §6 S15 修正为 10020（10003 是 BAD_COOKIE，10020 才是 NOFILEHANDLE），§2.9 错误码表同步修正 |

### 11.2 v2.0.0 修复的 HIGH 问题（9 个）

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| H-1 | RPC REPLY 头部布局错误（MSG_ACCEPTED/MSG_DENIED 分支结构缺失） | §1.3 补完整 REPLY 布局：ReplyState → Verifier → AcceptState 或 → RejectState + 附带字段 |
| H-2 | TCP Record Mark 字段语义错误（误为 4B 长度不含标志位） | §1.3 修正为 RFC 5531 §11.B：位 31=LAST_FRAGMENT，位 30-0=段长度；RM = 0x80000000 \| len(msg) |
| H-3 | NFSv3 procedure 范围校验错误（22+ 报错） | §2.2/§8.4 修正：NFS 主程序 procedure 22+ 透传不报错（用于 PROC_UNAVAIL 测试，T-066/T-148）；仅 MOUNT 程序 procedure 6+ 报错（T-136） |
| H-4 | NFSv4 opcode 范围校验错误（41-62 报错） | §2.5/§8.3 修正：opcode 41-62 透传不报错（NFSv4.1+ 操作，自动补全流程不使用）；0/1/2 与 63+ 报错 |
| H-5 | AUTH_SYS credentials 编码错误（machinename 缺长度前缀） | §6 S14 修正为 RFC 5531 §9.2 标准编码：stamp + machinename_len + machinename + padding + uid + gid + gid_count + gids |
| H-6 | COMPOUND oparray 截断规则错误（失败 op 后仍返回后续 op） | §2.7/§6 S15 修正：失败 op 后 resarray 截断至该 op（含），后续 op 不返回；失败 op 无 result 字段 |
| H-7 | seqid 语义错误（误为全局递增） | §3.5/§4.1 修正为按 state-owner 独立维护（RFC 7530 §8.2.2/§8.2.5/§8.8）：open-owner 与 lock-owner 各自独立序列 |
| H-8 | UDP RPC 消息最大长度未校验 | §3.5/§8.2 新增 V15：UDP payload ≤ 65507 字节，超出报错 "UDP RPC message exceeds 65507 bytes"（T-141） |
| H-9 | attrmask word2+ 未校验（NFSv4.1+ 属性混入） | §2.5/§8.4 新增 V30：attrmask 非零 word 仅允许 word 0/1，word 2+ 非零报错 "attrmask contains NFSv4.1+ attributes"（T-149） |

### 11.3 v2.0.0 修复的 MEDIUM 问题（8 个）

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| M-1 | NFSv4 NULL (proc=0) 误嵌入 COMPOUND | §2.4/§4.1 规则 7 明确：NFSv4 NULL 是独立 RPC procedure，不嵌入 COMPOUND；user 配置 procedure=0 时直接生成 NULL call/reply（T-003） |
| M-2 | SETCLIENTID_CONFIRM 自动补全逻辑缺失 | §4.1 规则 1 补完整：ops 含 SETCLIENTID 但无 SETCLIENTID_CONFIRM 时 Plan 自动追加 |
| M-3 | OPEN_CONFIRM 自动补全逻辑缺失 | §4.1 规则 3 补完整：NFSv4.0 新 open-owner 首次 OPEN 后自动追加 OPEN_CONFIRM（seqid 沿用 open-owner 序列） |
| M-4 | PUTROOTFH 自动补全逻辑缺失 | §4.1 规则 2 补完整：第一个 COMPOUND 含需 fh 的 op 但未配置 PUTFH/PUTROOTFH 时自动插入 PUTROOTFH |
| M-5 | MOUNT/UMOUNT 自动补全逻辑缺失 | §4.2 规则 1 补完整：NFSv3 ops 头部自动插入 MOUNT、尾部自动插入 UMOUNT（除非 user 显式配置） |
| M-6 | 多会话 clientid 跨会话校验缺失 | §4.3 规则 3/§8.5 V36 补完整：sessions>1 时多个会话显式配置相同 clientid≠0 报错 "duplicate clientid across sessions"（T-108） |
| M-7 | StableHow 范围未校验 | §8.3 V23 新增：stable_how 仅 0/1/2 合法，3+ 报错（T-050） |
| M-8 | filename 长度未校验 | §8.4 V31 新增：filename ≤ 255 (NFS3_MAXNAMLEN)，超出报错（T-040） |

### 11.4 v2.0.0 修复的 LOW 问题（6 个）

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| L-1 | COMPOUND tag 长度未校验 | §8.4 V32 新增：tag ≤ 1024 字节，超出报错（T-065） |
| L-2 | AuthSys.MachineName 长度未校验 | §8.4 V35 新增：≤ 255 字节（与 Linux knfsd 一致） |
| L-3 | MOUNT procedure 范围未校验 | §8.4 V33 新增：MOUNT v3 procedure 0-5 合法，6+ 报错（T-136） |
| L-4 | XID 回绕未处理 | §3.5 明确：XID 是 uint32，0xFFFFFFFF + 1 = 0 合法（T-017） |
| L-5 | NFSv3 fattr3 长度计算错误（误为 88 字节） | §2.8 修正为 84 字节（nfstime3 是 8 字节非 12 字节） |
| L-6 | RENEW 操作未文档化 | §2.5/§7.4 T-130 补完整：RENEW (opcode=29) 用于维持 lease，仅由 user 显式配置 |

### 11.5 v2.0.0 新增内容

1. **200+ 条测试用例（T-001 ~ T-200）**：§7 按 9 个类别分组，覆盖连接/NFSv3 文件操作/NFSv4 COMPOUND/NFSv4 OPEN+LOCK/数据类型/错误处理/多会话/边界/集成。
2. **§8 Validate 规则 38 条**：按 5 个类别分组（顶层字段范围/类型兼容性/NFSv4 操作码/filehandle-stateid-clientid 长度/跨会话一致性），每条对应 RFC 节号与错误消息。
3. **§9 错误处理完整表**：RPC 层错误（MSG_ACCEPTED 5 种 AcceptState + MSG_DENIED 2 种 RejectState）/ NFS 层错误（COMPOUND 截断规则 + 字段优先级）/ 业务错误（30+ 种错误码场景）/ 3 个错误注入示例 / 10 项已知偏离。
4. **§10 扩展字段映射**：trafficgen 概念 → NFS 协议对应表 / 21 个 PacketConfig Metadata 键 / 字段流向图 / 多会话 clientid 分配函数 / XID 生成函数 / RPC 头写入函数 / 9.4.1.38 协议扩展表 15 项字段对应。
5. **§11 修订记录**：v1.0/v1.1/v2.0.0/v2.0.1 四版变更说明 + 29 个问题修复明细（6C+9H+8M+6L）+ 13 个问题修复明细（3C+4H+3M+3L）+ v2.0.0 新增内容清单。
6. **15 个 HexDump 场景（S1-S15）**：§6 完整字节级 HexDump，覆盖 NFSv3 NULL/GETATTR/SETATTR/LOOKUP/READ/WRITE/CREATE/REMOVE/READDIR/COMMIT + NFSv4 COMPOUND/OPEN+LOCK+LOCKU+CLOSE/多会话/AUTH_SYS/错误处理。

### 11.6 与 v1.1 的兼容性

v2.0.0 是**不兼容重写**：
- RPC 头部偏移全部修正（Procedure 18→24、CredFlavor 1C→28 等）。
- stateid4 other 字段从变长改为定长 12 字节。
- clientid4 从 uint32 改为 uint64。
- NFS4_FHSIZE / NFS3_FHSIZE 区分校验（v3 ≤64 / v4 ≤128）。
- NFS4ERR_NOFILEHANDLE 错误码从 10003 修正为 10020。
- COMPOUND oparray 截断规则修正（失败 op 后不再返回后续 op）。
- seqid 语义从全局递增改为按 state-owner 独立。
- 测试用例编号重新分配（T-001 ~ T-200 vs v1.1 的零散用例）。
- HexDump 场景重新编号（S1-S15 vs v1.1 的部分场景）。
- Validate 规则从无到有（38 条 V1-V38）。

### 11.7 v2.0.1 修复的问题（13 个：3 CRITICAL + 4 HIGH + 3 MEDIUM + 3 LOW）

**CRITICAL（3 个）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| C1 | §2.5 操作码表 38-40 映射错误：WANT_DELEGATION 误标为 38（应为 WRITE=38）、RELEASE_LOCKOWNER 误标为 40（应为 39）、WANT_DELEGATION 是 NFSv4.1 操作（opcode 56）不在 v4.0 范围 | §2.5 修正为 38=WRITE、39=RELEASE_LOCKOWNER，删除 WANT_DELEGATION；3-39 为 v4.0 范围，40-62 为 v4.1+；T-095 WRITE opcode 27→26（hex）、T-129 RELEASE_LOCKOWNER opcode 28→27（hex）同步修正 |
| C2 | COMPOUND reply 编码顺序系统性错误（设计为 tag→status→resarray，RFC 7531 实际为 status→tag→resarray） | §2.7 REPLY 布局改为 status→tag→resarray 并注明 CALL/REPLY 非对称设计；S11 reply（status @ 001C、tag @ 0020）、S15 reply（status @ 001C、tag @ 0020）全部重排；§10.2 nfs_status 条目说明 status 在 tag 之前 |
| C3 | S9 标为 READDIR（proc 16）但使用 READDIRPLUS（proc 17）的双 count（dircount+maxcount）参数格式 | S9 明确改为 READDIRPLUS（proc 17，dircount + maxcount），与 RFC 1813 §3.3.16/§3.3.17 一致 |

**HIGH（4 个）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| H1 | EXCHANGE_ID 误标为 opcode 41（实为 42；41 是 BIND_CONN_TO_SESSION） | §2.5 修正为 EXCHANGE_ID=42、CREATE_SESSION=43、DESTROY_SESSION=44、BIND_CONN_TO_SESSION=41；§1.1/§4.1 规则 6 引用同步修正 |
| H2 | NFSv3 SETATTR3args 缺失 sattrguard3 字段（RFC 1813 §3.3.2） | §3.2 NFSAttributes 追加 SattrGuardCheck/SattrGuardCtimeSecs/SattrGuardCtimeNsecs；S3 CALL 追加 sattrguard3 字节（check=false 时 4 字节）；新增 T-035a 覆盖 check=true 的 12 字节格式 |
| H3 | §2.2 READDIR 参数表错误包含 dircount+maxcount（仅属 READDIRPLUS） | §2.2 修正为 READDIR=count（单字段）；NFSOp 注释明确 READDIR 用 MaxCount 作为 count、READDIRPLUS 用 DirCount=dircount/MaxCount=maxcount |
| H4 | S9 READDIR reply 缺失 cookieverf3 字段 | S9 reply 在 post_op_attr 之后插入 8 字节 cookieverf3，再放置 entries/eof（偏移重算：cookieverf3 @ 0078、value_follows @ 0080、eof @ 0084） |

**MEDIUM（3 个）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| M1 | NFS3ERR_MLINK 错误码值 32 应为 31（RFC 1813 §2.7） | §2.9 修正为 31 |
| M2 | S11 CALL HexDump RM 长度计算错误（76 字节 vs 声明 60 字节） | S11 CALL RM 修正为 0x8000004C（len=76），并附 RM 长度核算；S11 REPLY RM 修正为 0x80000038（len=56，status+tag+resarray+op1+op2+bitmap_len）；S15 REPLY RM 修正为 0x8000002C（len=44） |
| M3 | OPEN_CONFIRM seqid 注释措辞误导（正确行为被标为"简化"） | §4.1 规则 3 注释改为按 RFC 7530 §16.18.4 要求（OPEN_CONFIRM seqid = OPEN seqid + 1），明确与真实交互的差异点在 stateid 而非 seqid |

**LOW（3 个）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| L1 | S5 READ reply fattr3 标注 80 字节应为 84 字节 | S5 reply 修正为 [84 bytes fattr3] 并重算后续偏移（count @ 0078、eof @ 007C、data @ 0080、padding @ 0089）；S2/S4/S7 的 fattr3 标注与偏移同步修正（S7 dir_wcc 0080→0084） |
| L2 | T-046 引用不存在的 NFS3ERR_EOF | T-046 期望列改为 NFS3_OK(0) + eof=true + count=0（v3 用 eof=true 表达 EOF） |
| L3 | NFSOp cookie_verf 注释 v3/v4 类型区分不精确 | §3.2 注释改为 v3: cookieverf3=opaque[8]；v4: verifier4=opaque[8]；§3.3 同步修正 |

### 11.8 v2.0.2 修复的问题（25 个：3 CRITICAL + 7 HIGH + 10 MEDIUM + 5 LOW）

依据复审报告（r2，2026-08-05）修复。**CRITICAL（3 个）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| C-1 | RM 长度系统性少算（S1 CALL 24→40、S1 REPLY 20→24、S2 CALL 36→48；T-001/T-002/T-003 复读错误值） | §6 S1 CALL RM=0x80000028（40B）、S1 REPLY RM=0x80000018（24B）、S2 CALL RM=0x80000030（48B）；S4-S10/S12 CALL args 偏移统一按 RPC 头 40 字节重排（args 从 0028 起）；T-001/T-002/T-003 同步修正；测试 RM 一律按实际 payload 长度计算 |
| C-2 | writeverf3/verf4 误带 4 字节长度前缀 | §6 S6/S10 删除 "verf length" 行，verf 直接 8 字节定长（RFC 1813 §2.6 writeverf3=opaque[NFS3_WRITEVERFSIZE]）；T-047/T-048 补"verf 8B 无长度前缀"字节级断言；S6 verf 偏移改 @ 0084、S10 verf 改 @ 007C |
| C-3 | **sattr3 编码整体错误**（S3/S7 画成固定 52 字节，false 分支也写占位值；RFC 1813 §2.6 实为判别联合：mode/uid/gid/size 的 bool 判别 false=void、atime/mtime 的 time_how 0=DONT_CHANGE/1=SET_TO_SERVER_TIME 不写值、2=SET_TO_CLIENT_TIME 才写 nfstime3） | §2.8 sattr3 重写为判别联合定义并附长度核算（全 false=24B、仅 set_mode=true=28B）；S3/S7 sattr3 改为 28 字节并重算偏移（sattrguard3 @ 004C）；§3.4 补 SetAtime/MtimeSecs → time_how 映射规则；T-032（false 分支无值字段）、T-033（DONT_CHANGE=0 非 2）、T-034（SET_TO_SERVER_TIME=1，0xFFFFFFFF 哨兵）、T-035（SET_TO_CLIENT_TIME=2 非 1）全部修正 |
| C-3b | REPLY AcceptState 偏移声明错误（28 应为 24+verf_len） | §7.1 头部声明改为 "AcceptState=24+verf_len（空 verifier 时 @ 24）"；T-002/T-158 改 @ 18-1B；§10.2 nfs_accept_state 改 24-27 |
| C-4 | clientid 三处矛盾（§4.3=0x20001、§10.4=0x10001、S13=0x10002） | 统一为 `0x10000*(i+1)+1`：session 0/1/2 = 0x10001/0x20001/0x30001；§4.3 公式、§10.4 函数与注释、S13 表（client.id 改 0-based）、T-106/T-177 全部同步 |

**HIGH（7 个）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| H-1 | S12 幽灵 component4（CLAIM_NULL 分支为 void 却多画 4 字节，LOCK 偏移错位） | S12 删除 0060 幽灵行，声明 CLAIM_NULL 无 file 字段（RFC 7531 §5.2）；后续偏移整体重排并附逐段核算 |
| H-2 | S9 cookieverf3 画 AA×8 与 Config（8×00）矛盾 | S9 call/reply cookieverf 均改 8×00（回显 call），附 base64 解码说明 |
| H-3 | wcc_data 长度与结构错误（[36 bytes] 与括号内容 92B 自相矛盾、pre_op_attr 漏 wcc_attr 24B） | §2.8 定义 wcc_data 结构（pre_op_attr 判别 4B + 可选 wcc_attr 24B + post_op_attr 判别 4B + 可选 fattr3 84B）；本设计合成策略 = 92 字节；S6/S7/S8/S10 统一 [92 bytes] 并重算偏移（S6 count @ 007C、S7 dir_wcc @ 0084、S10 verf @ 007C） |
| H-4 | S11 GETATTR reply 无 result 字节 | S11 REPLY 展开完整 result（bitmap_len 3 words + size 8B + mode 4B），RM 改 0x80000050（80B），定义 bitmap 回显 call attr_mask、按位序合成属性值；T-074 同步（**该展开缺 fattr4.attr_vals 的 4 字节长度前缀，v2.0.3 §11.9 C-3 已修正为 RM=0x80000054/84B**） |
| H-5 | REPLY AcceptState 偏移声明错误 | 同 C-3b |
| H-6 | S9 缺 dirlist3 内层 eof | S9 reply 补双 eof：dirlist3 eof @ 0084 + resok eof @ 0088；字段名 "value_follows" 改 "entries length"（v3 无 value_follows）；T-059a/T-059b 同步（**r2 判断错误：readdir3resok 只有 dirlist3 内层一个 eof，补"外层 eof"是反向修复，v2.0.3 §11.9 C-2 已撤销**） |
| H-7 | S12 与 §4.1 规则 3 OPEN_CONFIRM 自动补全冲突 | S12 显式纳入 OPEN_CONFIRM（argarray=7、open_seqid=2、CLOSE seqid=3）；Config 中 open_seqid 改 2 并附校验规则；§4.1 规则 3 补"适用于所有新 open-owner 首次 OPEN 含 S12"；T-091 同步 |

**MEDIUM（10 个）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| M-1 | §2.5 "0/1/2：保留（INVALID_OP, ILLEGAL_OP, ILLEGAL_OP）" 命名错误 | 改为"未分配（0-2 无名称，Validate 拒绝）"；非法 op 由 op_status=NFS4ERR_OP_ILLEGAL 表达，删除"自动转为 ILLEGAL4"表述（行 185 同步） |
| M-2 | §2.5 表格缺 opcode 40 行 | 表格补 40=WANT_DELEGATION（NFSv4.1，RFC 5661） |
| M-3 | S13 client.id 1-based 与 0-based 矛盾 | S13 表统一 0-based（"trafficgen-client-0/1/2"），与 §4.3/T-179 一致 |
| M-4 | T-148 期望 PROC_UNAVAIL 但输入无 rpc_accept_state | T-148 输入补 rpc_accept_state:3；T-066 期望改"正常透传 + 如需注入见 T-148"；§9.4 示例 2 说明指针字段驱动；§2.2/§3.5 引用同步 |
| M-5 | §2.2 READ 关键返回顺序错误 | 改为 "post_op_attr, count, eof, data"（RFC 1813 read3resok 顺序，与 S5 HexDump 一致）；T-043 同步 |
| M-6 | §9.1 MSG_ACCEPTED 布局缺 PROG_MISMATCH 的 low/high | 布局补 "AcceptState=2 时 + low(4B) + high(4B)"；T-159 输入补 rpc_mismatch_low/high 并断言字节 |
| M-7 | bitmap 尾部 0 word 规范化未定义 | §6 S11 result 规则 + T-140 明确"尾部 0 word 保留原样不截断" |
| M-8 | WRITE count≠len(data) 未校验 | §8.3 新增 V23a（"write count must equal data length"）+ 负向测试 T-047a |
| M-9 | ResultStatus≠0 多 op 行为表行混乱 | §2.7/§9.2 统一为"顶层 status=ResultStatus、resarray 完整、每个 op_status=ResultStatus（不截断）"；§10.2 nfs_status 条目同步；T-151 补 resarray 完整断言 |
| M-10 | OpenReplyStateid 引用接线未定义 | §3.5 定义机制：同 COMPOUND 内全 0 stateid 改写为所引用 OPEN reply stateid 字节，user 显式非全 0 优先；§4.1 规则 4 同步 |

**LOW（5 个）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| L-1 | T-006 "CredLen=18 (24B)" 进制混写、T-193 "CredLen=18+" 含糊 | 统一写 "CredLen=0x18=24"；T-193 给确定值（默认 auth_sys 24 字节） |
| L-2 | §5.6 reply 时间戳未定义 | 补 "reply 时间戳 = 对应 call 时间戳" |
| L-3 | MOUNT proc=0 显式配置时头部补全行为含糊 | §4.2 规则 5 明确"显式 proc=0 时不重复插入 proc=1" |
| L-4 | §2.5 表格缺 opcode 40 行 | 同 M-2 |
| L-5 | T-155 未断言失败 op 的顶层 status | T-155 补断言 "顶层 status=00002719（=失败 op 的 OpStatus 10025）"（**该 hex 值本身有误：10025=0x2729 非 0x2719，v2.0.3 §11.9 H-2 已修正**） |

### 11.9 v2.0.3 修复的问题（15 个：5 CRITICAL + 3 HIGH + 4 MEDIUM + 3 LOW）

依据复审报告（r3，2026-08-05）修复。本次修复前先对照 RFC 原文核实了 r2 报告中的两处 RFC 判断（S12 CLAIM_NULL、S9 eof），发现 r2 判断错误、v2.0.2 因此做了"反向修复"，v2.0.3 予以撤销。**CRITICAL（5 个）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| C-1 | **撤销反向修复**：r2 误判"open_claim4 的 CLAIM_NULL 分支为 void"，v2.0.2 据此删除 S12 OPEN 的 file 字段并重排偏移（RM=0x80000110）；经 RFC 7531 §5.2 原文核实 `case CLAIM_NULL: component4 file;` **非 void**（文件名由 OPEN 自身携带，RFC 7530 §16.18.2），v2.0.1 原版画 file 字段是正确的 | S12 恢复 CLAIM_NULL 的 component4 file（len 4 + 'f' 1 + pad 3，@ 0078-007F）；按 C-5 统一核算重排全部偏移（OPEN 块 60B、LOCK @ 0098、LOCKU @ 00E0、CLOSE @ 010C）；CALL RM=0x80000124（292B）；§3.3.1 NFSClaim 注释同步；§11.8 H-1 标注为反向修复 |
| C-2 | **撤销反向修复**：r2 误判"S9 缺 dirlist3 内层 eof"，v2.0.2 据此补成双 eof（dirlist3 @ 0084 + resok 外层 @ 0088）；经 RFC 1813 §3.3.16/§3.3.17 原文核实 `READDIR3resok = post_op_attr + cookieverf3 + dirlist3`、`dirlist3 = entry3 entries<> + bool eof`，**只有 dirlist3 内层一个 eof，无 resok 外层 eof** | S9 reply 删除外层 eof 行（0088），保留 dirlist3/dirlistplus3 内层 eof @ 0084；REPLY 总长 132B=0x84 不变（外层 eof 本就是多余 4B，v2.0.2 的 136B 长度声明未落成 HexDump 行）；§2.2 表 READDIR/READDIRPLUS 关键返回改为 "dir_attributes, cookieverf, dirlist3/dirlistplus3（entries<> + 内层 eof）"；T-059a/T-059b 删除"双 eof"断言；§11.8 H-6 标注为反向修复 |
| C-3 | S11 GETATTR result 的 fattr4 编码缺 attrlist4 长度前缀：v2.0.2 按 r2 H-4 展开为"bitmap 3 words + size 8B + mode 4B"（28B），但 RFC 7531 §3 `struct fattr4 { bitmap4 attrmask; attrlist4 attr_vals; };` 中 attrlist4 = `typedef opaque attrlist4<>;` 是**变长 opaque，XDR 必须带 4 字节长度前缀** | §2.8 新增 fattr4 编码定义（bitmap4 + attrlist4 长度前缀 + 值 + 对齐）；S11 REPLY 在 bitmap（0x38-0x47）后补 `attr_vals length=12 (0x0000000C)` @ 0048 行，size 改 @ 004C-0053、mode 改 @ 0054-0057；REPLY 总长 84B，RM=0x80000050→**0x80000054**；T-074 断言同步（bitmap words 逐值 + attr_vals_len=0x0C + RM=0x54）；§11.8 H-4 标注"缺 attr_vals 长度前缀" |
| C-4 | S4 LOOKUP3resok 字段顺序画反且漏字段：v2.0.2 画成 status → post_op_attr(fattr3 88B) → post_op_fh3；RFC 1813 §3.3.3 原文 `struct LOOKUP3resok { nfs_fh3 object; post_op_attr obj_attributes; post_op_attr dir_attributes; };`——**object (fh) 在前、属性在后，且还有第三字段 dir_attributes**（object 是裸 nfs_fh3，非 post_op_fh3 联合） | S4 REPLY 重排：status 4B @ 001C → object（fh_len 4 + fh_data 4）@ 0020-0027 → obj_attributes（判别 4B @ 0028 + fattr3 84B @ 002C-007F）→ dir_attributes（判别 4B @ 0080，简化合成=0）；REPLY 总长 128B；T-037 补"fh 在 obj_attributes 之前"顺序断言；§2.2 LOOKUP 关键返回改为 "filehandle, post_op_obj_attr, post_op_dir_attr" |
| C-5 | S12 openhow 编码错误：v2.0.2 把 createmode4 当 openflag4 判别值写（wire 上是 opentype=0=NOCREATE，与配置 type:"unchecked" 的 create 语义矛盾；T-084 exclusive 会写出**非法 opentype=2**）；RFC 7531 §5.2 `union openflag4 switch (opentype4 opentype)` 判别是 opentype4（OPEN4_NOCREATE=0/OPEN4_CREATE=1），unchecked/guarded/exclusive 是内层 createhow4 的 createmode4（0/1/2），**UNCHECKED4/GUARDED4 分支还携带 fattr4 createattrs** | §3.3.1 NFSOpenHow 重写：type 增加 "nocreate"（→opentype=0 无 how）；"unchecked/guarded/exclusive" → opentype=1 (OPEN4_CREATE) + createhow4{mode, createattrs/createverf}；S12 openhow 块改为 opentype=1 @ 0064 + createmode=0 @ 0068 + createattrs（空 fattr4 = bitmap_len 0 @ 006C + attr_vals_len 0 @ 0070）共 16B；T-082~T-084 断言改为 opentype 判别 + createmode + createattrs/createverf 字节；T-078 同步 |

**HIGH（3 个）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| H-1 | T-033 与 §2.8 time_how 映射直接矛盾：§2.8 规定"SetAtime=true 且 AtimeSecs 未提供 → time_how=1 (SET_TO_SERVER_TIME)"，T-033 却断言未提供 → set_atime=00 (DONT_CHANGE)，两条期望互相矛盾 | 按 §2.8 语义修正 T-033（未提供 → set_atime=01），并将"SetAtime=true 且 AtimeSecs 未提供 → time_how=1"的说明补进 §3.4 注释；理由：DONT_CHANGE 表示"不设置时间"，与 set_atime=true 的本意相悖（RFC 1813 §2.6 time_how 语义）；T-034（0xFFFFFFFF 哨兵 → 1）保持不变，两者同属映射规则同一分支 |
| H-2 | T-155 顶层 status hex 值错误：10025 = 0x2729，文档写 0x00002719 | T-155 断言改为 00002729；§2.7 补"错误码取低 32 位说明"（10025 低 32 位即 10025=0x2729，bit 深度不改变字节值）；§11.8 L-5 补注"hex 值本身有误，v2.0.3 修正" |
| H-3 | T-080/T-081 只断言联合判别值，未断言分支字段字节——CLAIM_DELEGATE_CUR/PREV 的实现缺陷无法被测出 | T-080 补断言 delegate_stateid4 16B（seqid + other 12B）+ component4 file（len+data+pad）字节；T-081 补断言 file_delegate_prev（component4 len+data+pad）字节；§3.3.1 NFSClaim 补 File 字段与分支注释（按 RFC 7531 §5.2 open_claim_delegate_cur4 = stateid4 delegate_stateid + component4 file） |

**MEDIUM（4 个）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| M-1 | §9.1 MSG_DENIED 的 RPC_MISMATCH low/high 语义未标注（RFC 5531 §8：low/high = 服务端支持的 RPC 版本范围）；T-163 未断言该语义；§1.3 未说明 RPC_MISMATCH 与 AUTH_ERROR 分支互斥 | T-163 期望补 "low/high = 服务端支持的 RPC 版本范围，注入 low=high=2 表示仅支持 v2"；§9.1 表补分支互斥说明（RPC_MISMATCH 无 auth_stat、AUTH_ERROR 无 low/high）；§1.3 布局后补互斥注释 |
| M-2 | §4.3 与 §10.4 对 SETCLIENTID reply 的 clientid 取值来源规定不一致（§4.3 只规定 call 侧，§10.4 说 reply 默认即会话 clientid） | §4.3 规则 3 补 "SETCLIENTID reply 的 clientid 合成规则同 call 侧：user 显式配置该会话 clientid 时 reply 回显 user 值，否则用默认公式"，与 §10.4 对齐 |
| M-3 | §6 S12 未定义 OPEN reply 的合成 stateid（OPEN_CONFIRM/CLOSE 全 0 的来源） | S12 补"OPEN reply 合成 stateid 说明"：未配置 OpenReplyStateid → 全 0 回显（§3.5/§9.5 #2）；配置后 OPEN_CONFIRM/CLOSE 引用该值；§3.5 引用处补 "见 §6 S12" |
| M-4 | T-074 未断言 bitmap 三个 word 值（word2=0 是否保留），且 reply RM 依赖错误布局（见 C-3） | T-074 补断言 "attrmask 严格回显 call 全部 word：word0=00000010 + word1=00000002 + word2=00000000（含尾部 0 word，与 T-140/S11 一致）"；§6 S11 合成规则明确 "GETATTR reply 的 bitmap 严格回显 call 的 attr_mask 全部 word（含尾部 0）" |

**LOW（3 个）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| L-1 | §11.1 "CredBody=36+" 与 §11.8 "40 字节头" 两种表述并存，args 起点易误算 | §11.1 C-1 补一句 "空 cred/verf 时 RPC 头共 40 字节（CredBody=36、VerfFlavor=36、VerfLen=40、args=44=0x2C）"，统一表述 |
| L-2 | §2.9 错误码表缺常用码（NFS4ERR_DELAY=10008、NFS4ERR_RETRY_UNCACHED_REP=10009 等）；NFS4ERR_NOT_SAME=10027 已有表无用例 | §2.9 补 NFS4ERR_DELAY=10008 行；§9.3 业务错误表补 NFS4ERR_DELAY=10008（服务端忙）与 NFS4ERR_NOT_SAME=10027（READDIR cookieverf 不匹配）两行 |
| L-3 | S5/S2/S4 的 fattr3 "84B/88B" 表述分裂（[84 bytes fattr3] 与 post_op_attr "判别 4B + 84B = 88B" 并存） | S2/S5/S4 reply 统一标注 "post_op_attr（判别 4B + fattr3 84B = 88B）"；S4 重排后偏移标注（0080 起）与 §2.8 定义自洽 |

**v2.0.3 修复流程教训**：本次 C-1/C-2 的根因是 r2 复审报告自身有两处 RFC 判断错误，v2.0.2 未对照 RFC 原文验证直接执行。已确立流程规则：**修复必须"以 RFC 原文为准、以复审报告为参考"，对复审报告的每个"新发现"先 WebFetch 核实 RFC 原文再动手**（本版 C-1/C-2/C-3/C-4/C-5 均先核实 RFC 7531 §5.2/§3、RFC 1813 §3.3.3/§3.3.16/§3.3.17 原文后修复）。

### 11.10 v2.0.4 修复的问题（8 个：0 CRITICAL + 1 HIGH + 3 MEDIUM + 4 LOW）

依据复审报告（r4，2026-08-05）修复。本次修复前对照 RFC 原文核实了全部 8 个新发现（RFC 1813 §2.5/§3.3.10/§3.3.11/§3.3.14/§3.3.15、RFC 7530 §16.17.2、RFC 7531 §5.2），其中 **L-4 的"share_deny 合法值 0/1/2"建议与 RFC 7530 原文不符——share_deny 还有 OPEN4_SHARE_DENY_BOTH=3（RFC 7530 §16.17.2 原文："the client must specify one of OPEN4_SHARE_DENY_NONE, OPEN4_SHARE_DENY_READ, OPEN4_SHARE_DENY_WRITE, or OPEN4_SHARE_DENY_BOTH"），按 RFC 原文修正为 0-3 并补正例 T-089a**。

**HIGH（1 个）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| H-1 | NFSv3 多参数 procedure 的 Config 字段缺失：RENAME（双 fh 双名）、LINK（link_dirfh）、SYMLINK（target）、MKNOD（ftype/devdata）的 args 无法表达，T-054/055/058/059 输入与 Config 结构脱节 | §3.2 NFSOp 新增 v3 专用字段：`Oldname`/`Newname`（RENAME 的 from.name/to.name、LINK 的 link.name）、`Filehandle2`（RENAME 的 to.dir 第二个 dirfh）、`LinkDirFh`（LINK 的 link.dir）、`SymlinkTarget`（SYMLINK 的 symlink_data 路径）、`Ftype uint32` + `Devdata [8]byte`（MKNOD 的 mknoddata3.type 判别 + specdata3，仅 NF3CHR/NF3BLK 写）；§2.2 表四行参数按 RFC 1813 §3.3.10/§3.3.11/§3.3.14/§3.3.15 更新；§2.8 新增"v3 多参数 procedure 的 Config 字段映射"表（SYMLINK=Filehandle+Filename+Attributes+SymlinkTarget、MKNOD=Filehandle+Filename+Ftype+Attributes+Devdata、RENAME=Filehandle+Oldname+Filehandle2+Newname、LINK=Filehandle+LinkDirFh+Newname）；§6 新增 S16a-S16d 四个字节级 CALL args 场景（RENAME 80B/RM=0x80000050、LINK 68B/RM=0x80000044、SYMLINK 96B/RM=0x80000060、MKNOD-NF3CHR 96B/RM=0x80000060，逐字节核算）；T-054/055/058/059 输入改为 Config 字段名并补字节断言与 S16 引用；新增 V39（MKNOD ftype 仅 1-7）+ 负例 T-055b；新增 T-055a（NF3FIFO 分支不写 spec，RFC 1813 §3.3.11 case NF3FIFO: sattr3 pipe_attributes） |

**MEDIUM（3 个）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| M-1 | S14 RM=0x80000040 与自身偏移矛盾：VerfLen @ 0x40、NFS body @ 0x44，消息 ≥80B，RM 应 ≥0x50 | S14 RM 行改为 `80 00 00 50`（len=80）；新增 RM 长度核算段落（RPC 头 64B 恰至 0x40 + 最小 COMPOUND body 12B = 80B，RM 必须包含 NFS body，实际生成按完整 body 计算） |
| M-2 | S9 RM 核算文字错误：24+4+88+8+4+4=132≠128，payload 含 RM 共 136B | S9 RM 核算文字改为 "**132 字节 = 0x84**（payload 含 RM 共 136 字节，HexDump 止于 0x0088）"（HexDump 行本身正确，未改动） |
| M-3 | T-110 输入 open_seqid=1 与 §4.1 规则 3（OPEN_CONFIRM 补全后 open_seqid=2）+ S12 校验规则矛盾 | T-110 输入 open_seqid 1→2，期望补 "open_seqid=00000002（open_seqid 必须 =2：OPEN_CONFIRM 补全后 open-owner 序列 OPEN=1 → OPEN_CONFIRM=2 → CLOSE=3，RFC 7530 §16.18.4；open_seqid=1 与补全序列冲突 Validate 报错，见 §4.1 规则 3/S12 说明）"，与 S12（line 1380）及 v2.0.2 H-7 修复一致 |

**LOW（4 个）**：

| 编号 | 问题 | 修复方式 |
|------|------|----------|
| L-1 | §2.6 匿名 stateid 反引号内 12 字节标"共 16 字节"，缺 seqid 部分 | §2.6 匿名 stateid 改为 "seqid `00 00 00 00` + other 12×`00`，合计 16 字节"，与 READ bypass 行格式统一 |
| L-2 | T-143 "文件.txt" UTF-8 为 10 字节，断言 len=6 与 data hex（10 字节）自相矛盾 | T-143 场景/断言改为 "10 字节 UTF-8"、len=0000000A，data hex 不变（E6 96 87 E4 BB B6 2E 74 78 74） |
| L-3 | S2 标题"filehandle=4 字节 0x01"笔误（Config "AAE=" 解码为 1 字节，正文/HexDump 正确） | S2 标题改为 "filehandle=1 字节 0x01" |
| L-4 | OPEN 的 share_access/share_deny 无 Validate 范围校验、T-087~089 无非法值负例 | 新增 V23b（share_access 仅 1/2/3、share_deny 仅 0/1/2/3，RFC 7530 §16.17.2 原文，非法值服务端返回 NFS4ERR_INVAL）；新增负例 T-088a（share_access=0）/T-088b（share_access=4）/T-089b（share_deny=4）+ 正例 T-089a（share_deny=3 BOTH） |

**修复后复核**：S16a-S16d 的 HexDump 全部逐字节核算（见各场景"长度核算"），RM 与 CALL 总长吻合（80B/68B/96B/96B）；T-054/055/058/059 的断言与 §2.8 字段映射、§3.2 Config 字段一一对应；V23b/V39 与 T-088a/088b/089a/089b/055a/055b 一一对应。


