# nfs Pcap Test Results

Cases: 201 — pass 201, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| nfs_t001_v3_null_mount | T-001/T-021: NFSv3 NULL (proc=0) 无 Program 显式 → 自动插入 MOUNT(proc1) + NULL + UMOUNT(proc3)，3 次 RPC 往返；TCP 3-way + 6 数据帧 + 3 挥手 = 12 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t001_v3_null_mount.pcap) |
| nfs_t002_v3_null_reply | T-002: NFSv3 NULL call→reply 帧断言（RM=0x80000018，XID=1 echo, Type=1, ReplyState=0, AcceptState=0）；显式 Program 100003 跳过 MOUNT 自动插入 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t002_v3_null_reply.pcap) |
| nfs_t003_v4_null | T-003: NFSv4 NULL (proc=0) 独立 RPC 调用，无 COMPOUND 嵌入，无 SETCLIENTID 补全；call payload=40B | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t003_v4_null.pcap) |
| nfs_t004_v4_compound | T-004/T-061/T-101/T-102: NFSv4 COMPOUND（PUTROOTFH+GETATTR）→ 自动插入 SETCLIENTID(opcode35) + SETCLIENTID_CONFIRM(opcode36) 两个独立 COMPOUND，随后用户 COMPOUND；共 3 次 RPC 往返 + 握手 + 挥手 = 12 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t004_v4_compound.pcap) |
| nfs_t005_auth_none | T-005: AUTH_NONE 默认（auth_flavor 未设）→ CredFlavor=0, CredLen=0；call 含 cred 区段但全空 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t005_auth_none.pcap) |
| nfs_t006_auth_sys | T-006/S14: AUTH_SYS（auth_flavor=1, machinename=host, uid=gid=65534, groups=[]）→ CredFlavor=1, CredLen=24, stamp=1, gid_count=0；Verifier 仍 AUTH_NONE | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t006_auth_sys.pcap) |
| nfs_t007_auth_sys_machinename_pad | T-007: AUTH_SYS machinename="abc"（3 字节）→ call 含 1B 零填充对齐 4；stamp/uid/gid 取默认值 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t007_auth_sys_machinename_pad.pcap) |
| nfs_t008_auth_sys_defaults | T-008: AUTH_SYS 默认值（auth_sys 未显式字段）→ stamp=0, machine_name="trafficgen" (10B+2B pad), uid=0, gid=0 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t008_auth_sys_defaults.pcap) |
| nfs_t009_v4_auth_sys_groups | T-009: AUTH_SYS groups=[1000,2000] → gid_count=2 + gid1=0x3E8 + gid2=0x7D0 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t009_v4_auth_sys_groups.pcap) |
| nfs_t010_v4_auth_sys_groups_empty | T-010: AUTH_SYS groups=[] → gid_count=0；CredLen=0x24=36 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t010_v4_auth_sys_groups_empty.pcap) |
| nfs_t011_v4_auth_gss_validate | T-011: auth_flavor=6 (RPCSEC_GSS) → Validate 报错 'RPCSEC_GSS not supported' | pass | 0 | [pcap]() |
| nfs_t012_v4_auth_short_validate | T-012: auth_flavor=2 (AUTH_SHORT) → Validate 报错 'unsupported auth_flavor' | pass | 0 | [pcap]() |
| nfs_t014_xid_step2 | T-014: XID 步长=2 (xid_base=100, xid_incr=2) → 两个 NULL call XID=100,102；显式 program 跳过 MOUNT | pass | 11 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t014_xid_step2.pcap) |
| nfs_t015_xid_no_incr | T-015: XID 不递增（xid_incr=0, 2 个 NULL）→ 两个 call 同 XID=1，用于 echo 行为测试 | pass | 11 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t015_xid_no_incr.pcap) |
| nfs_t016_xid_base_zero | T-016: XID base=0 (xid_base=0, xid_incr=0) → planner 将 0 视为默认 1 → call XID=0x00000001 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t016_xid_base_zero.pcap) |
| nfs_t017_v3_xid_wrap | T-017: XID 回绕 xid_base=0xFFFFFFFF, xid_incr=1 → call1 XID=FFFFFFFF；call2 XID=0 | pass | 11 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t017_v3_xid_wrap.pcap) |
| nfs_t018_transport_udp | T-018: NFSv3 transport=udp → UDP 数据报（无 4B RPC record marking）；call+reply 2 包无 TCP handshake | pass | 2 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t018_transport_udp.pcap) |
| nfs_t019_v4_udp_validate | T-019: version=4 + transport=udp → Validate V3 报错（NFSv4 requires TCP） | pass | 0 | [pcap]() |
| nfs_t020_transport_default_tcp | T-020: transport 未设（默认 tcp）→ TCP 3-way handshake 包存在（packet 1-3 SYN/SYN-ACK/ACK） | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t020_transport_default_tcp.pcap) |
| nfs_t021_v3_getattr | T-021/T-022: NFSv3 GETATTR（proc=1, fh=1 字节 0x01）→ 自动 MOUNT/UMOUNT；CALL fh len=1 + 3B 填充；REPLY post_op_attr 判别=1 + fattr3 84B | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t021_v3_getattr.pcap) |
| nfs_t022_v3_getattr_reply_fattr3_84b | T-022: GETATTR reply post_op_attr 判别=1 + fattr3 84B（type=NF3REG mode=0644 nlink=1） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t022_v3_getattr_reply_fattr3_84b.pcap) |
| nfs_t023_v3_getattr_fh_len4 | T-023: GETATTR fh len=4 → fh 长度字段 0x00000004 + 4B data (无 pad) | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t023_v3_getattr_fh_len4.pcap) |
| nfs_t024_v3_getattr_fh_len16 | T-024: GETATTR fh len=16 → fh 长度字段 0x00000010 + 16B data (无 pad) | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t024_v3_getattr_fh_len16.pcap) |
| nfs_t025_v3_getattr_fh_len64 | T-025: GETATTR fh len=64 = NFS3_FHSIZE 上限 → 64B data 无 pad | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t025_v3_getattr_fh_len64.pcap) |
| nfs_t026_v3_getattr_fh_len65 | T-026: GETATTR fh len=65 > NFS3_FHSIZE(64) → Validate V24 报错 | pass | 0 | [pcap]() |
| nfs_t027_v4_putfh_fh128 | T-027: v4 PUTFH fh len=128 = NFS4_FHSIZE 上限 → Validate 通过 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t027_v4_putfh_fh128.pcap) |
| nfs_t028_v4_putfh_fh129 | T-028: v4 PUTFH fh len=129 > NFS4_FHSIZE(128) → Validate V24 报错 | pass | 0 | [pcap]() |
| nfs_t029_v3_setattr | T-029: NFSv3 SETATTR（proc=2, set_mode=true, mode=0644）→ sattr3 判别联合 28B（仅 set_mode 带值）+ sattrguard3 check=false 4B；其余 set 判别全 0 无值字段 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t029_v3_setattr.pcap) |
| nfs_t030_v3_setattr_uid | T-030: SETATTR set_uid=true → sattr3 联合判别 set_uid=1 + uid uint32 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t030_v3_setattr_uid.pcap) |
| nfs_t031_v3_setattr_size | T-031: SETATTR set_size=true → sattr3 含 size uint64=4096；fh 4B → RM=0x80000054 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t031_v3_setattr_size.pcap) |
| nfs_t032_v3_setattr_uid_only | T-032: SETATTR 仅 set_uid（不设 mode）→ sattr3 mode 判别=0 且 wire 上无 mode 值字段 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t032_v3_setattr_uid_only.pcap) |
| nfs_t033_v3_setattr_atime_server_default | T-033: SETATTR set_atime=true 且 atime_secs 未提供 → time_how=1 (SET_TO_SERVER_TIME) 不写 nfstime3 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t033_v3_setattr_atime_server_default.pcap) |
| nfs_t034_v3_setattr_atime_server_sentinel | T-034: SETATTR atime_secs=0xFFFFFFFF 哨兵值 → time_how=1 (SET_TO_SERVER_TIME) 不写 nfstime3 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t034_v3_setattr_atime_server_sentinel.pcap) |
| nfs_t035_v3_setattr_atime_client | T-035: SETATTR atime SET_TO_CLIENT_TIME(2) → 写 nfstime3 8B (sec+nsec)；fh 4B → RM=0x80000054 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t035_v3_setattr_atime_client.pcap) |
| nfs_t035a_v3_setattr_guard_check | T-035a: SETATTR sattrguard3 check=true → 12B（check=1 + obj_ctime.secs=100 + nsecs=0） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t035a_v3_setattr_guard_check.pcap) |
| nfs_t036_v3_lookup | T-036/T-037: NFSv3 LOOKUP（proc=3, dirfh=0x01, filename=doc.txt）→ reply 字段序 object fh(AA BB CC DD) → obj_attributes(判别1+fattr3) → dir_attributes(判别0) | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t036_v3_lookup.pcap) |
| nfs_t037_v3_lookup_reply_order | T-037: LOOKUP reply 字段序 object fh(AA BB CC DD) → obj_attributes(判别1+fattr3) → dir_attributes(判别0) | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t037_v3_lookup_reply_order.pcap) |
| nfs_t038_v3_lookup_empty_name | T-038: LOOKUP filename="" → filename len=00000000 无 data | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t038_v3_lookup_empty_name.pcap) |
| nfs_t039_v3_lookup_name255 | T-039: LOOKUP filename 长 255 = NFS3_MAXNAMLEN 上限 → Validate 通过，len=000000FF | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t039_v3_lookup_name255.pcap) |
| nfs_t040_v3_lookup_name256 | T-040: LOOKUP filename 长 256 > NFS3_MAXNAMLEN(255) → Validate V31 报错 | pass | 0 | [pcap]() |
| nfs_t041_v3_access | T-041: ACCESS access=0x1 (READ) → call access 字段=00000001 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t041_v3_access.pcap) |
| nfs_t042_v3_readlink | T-042: NFSv3 READLINK（proc=5）reply = symlink_target + post_op_attr(88B)；xid_incr=1 使 reply 按 XID 正确匹配 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t042_v3_readlink.pcap) |
| nfs_t043_v3_read | T-043/T-044: NFSv3 READ（proc=6, offset=0, count=5, data=hello）→ reply post_op_attr + count + eof + data；5B opaque + 3B 填充 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t043_v3_read.pcap) |
| nfs_t045_v3_read_count0 | T-045: READ count=0 → call count=00000000 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t045_v3_read_count0.pcap) |
| nfs_t046_v3_read_offset_eof | T-046: READ offset=0xFFFFFFFF → call offset 编码；reply status=NFS3_OK(0) | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t046_v3_read_offset_eof.pcap) |
| nfs_t047_v3_write | T-047: NFSv3 WRITE（proc=7, offset=0, count=5, stable_how=2 FILE_SYNC, data=hello）→ reply wcc_data(92B) + count + committed=2 + verf 8B 无长度前缀 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t047_v3_write.pcap) |
| nfs_t047a_v3_write_count_mismatch | T-047a: WRITE count=10 ≠ len(data)=5 → Validate V23a 报错 | pass | 0 | [pcap]() |
| nfs_t048_v3_write_unstable | T-048: WRITE stable_how=0 (UNSTABLE) → call stable@118=00000000 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t048_v3_write_unstable.pcap) |
| nfs_t049_v3_write_datasync | T-049: WRITE stable_how=1 (DATA_SYNC) → call stable@118=00000001 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t049_v3_write_datasync.pcap) |
| nfs_t050_v3_write_stable3 | T-050: WRITE stable_how=3 越界 → Validate V23 报错 | pass | 0 | [pcap]() |
| nfs_t051_v3_write_empty_data | T-051: WRITE data="" → call data len@122=00000000 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t051_v3_write_empty_data.pcap) |
| nfs_t052_v3_create | T-052: CREATE proc=8, filehandle:AAE=, filename:new.txt, set_mode:0644 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t052_v3_create.pcap) |
| nfs_t053_v3_mkdir | T-053: MKDIR proc=9, filename:newdir | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t053_v3_mkdir.pcap) |
| nfs_t054_v3_symlink | T-054/S16c: NFSv3 SYMLINK（proc=10）args 顺序 where.dir→where.name→sattr3→symlink_data；CALL RM=0x80000060；xid_incr=1 使 reply 按 XID 正确匹配（顺带覆盖 T-013/T-014） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t054_v3_symlink.pcap) |
| nfs_t055_v3_mknod_nf3chr | T-055: MKNOD proc=11, ftype=NF3CHR(4), devdata={specdata1=0, specdata2=0x102} | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t055_v3_mknod_nf3chr.pcap) |
| nfs_t055a_v3_mknod_nf3fifo | T-055a: MKNOD proc=11, ftype=NF3FIFO(7) → 仅写 sattr3，无 devdata 段 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t055a_v3_mknod_nf3fifo.pcap) |
| nfs_t055b_v3_mknod_ftype0 | T-055b: MKNOD proc=11, ftype=0 → Validate V39 报错（合法 1-7） | pass | 0 | [pcap]() |
| nfs_t056_v3_remove | T-056: REMOVE proc=12, filename:old.txt | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t056_v3_remove.pcap) |
| nfs_t057_v3_rmdir | T-057: RMDIR proc=13, filename:emptydir | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t057_v3_rmdir.pcap) |
| nfs_t058_v3_rename | T-058/S16a: NFSv3 RENAME（proc=14, from a.txt fh=0x01, to b.txt fh=01 02 03 04）→ args 顺序 from.dir → from.name → to.dir → to.name；CALL RM=0x80000050 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t058_v3_rename.pcap) |
| nfs_t059_v3_link | T-059: LINK proc=15, file:AAE=, link_dirfh:AQIDBA==(01 02 03 04), newname:hardlink | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t059_v3_link.pcap) |
| nfs_t059a_v3_readdir | T-059a: READDIR proc=16, cookie=0, cookie_verf=8B 0, max_count=8192 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t059a_v3_readdir.pcap) |
| nfs_t059b_v3_readdirplus | T-059b/S9: NFSv3 READDIRPLUS（proc=17, cookie=0, cookieverf 8B 全 0, dircount=512, maxcount=8192）→ args 双 count；reply post_op_attr + cookieverf + entries=0 + eof(内层) | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t059b_v3_readdirplus.pcap) |
| nfs_t060a_v3_fsstat | T-060a: FSSTAT proc=18, 仅 fh | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t060a_v3_fsstat.pcap) |
| nfs_t060b_v3_fsinfo | T-060b: FSINFO proc=19, 仅 fh | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t060b_v3_fsinfo.pcap) |
| nfs_t060c_v3_pathconf | T-060c: PATHCONF proc=20, 仅 fh | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t060c_v3_pathconf.pcap) |
| nfs_t062_v4_tag_empty | T-062: COMPOUND tag 空 → call tag len=0 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t062_v4_tag_empty.pcap) |
| nfs_t063_v4_tag_nonempty | T-063: COMPOUND tag="nfs4" → call tag len=4 + nfs4 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t063_v4_tag_nonempty.pcap) |
| nfs_t064_v4_tag_max1024 | T-064: COMPOUND tag="a"x1024 → tag len=0x400（边界内） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t064_v4_tag_max1024.pcap) |
| nfs_t065_v4_tag_too_long | T-065: COMPOUND tag="a"x1025 → Validate 拒绝（>1024） | pass | 0 | [pcap]() |
| nfs_t066_v3_proc22_passthrough | T-066: NFSv3 procedure=22 越界透传（显式 program=100003）→ call Procedure=22，reply SUCCESS 无 NFS body | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t066_v3_proc22_passthrough.pcap) |
| nfs_t067_v4_minorversion0 | T-067: minorversion=0 显式 → body minorversion=00000000 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t067_v4_minorversion0.pcap) |
| nfs_t068_v4_minorversion1 | T-068: minorversion=1 → Validate 拒绝（仅支持 v4.0） | pass | 0 | [pcap]() |
| nfs_t069_v4_minorversion_default | T-069: minorversion 未设 → 默认 0 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t069_v4_minorversion_default.pcap) |
| nfs_t070_v4_putfh_read | T-070/T-094: NFSv4 PUTFH(opcode=22, fh=0x01) + READ(opcode=25, stateid 匿名全0 + offset=0 + count=4096)；CALL RM=0x80000060，REPLY RM=0x80000038 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t070_v4_putfh_read.pcap) |
| nfs_t070a_v4_putfh | T-070: PUTFH(opcode=22, fh=00 01) → opcode=0x16 + fh len=2 + data 00 01 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t070a_v4_putfh.pcap) |
| nfs_t071_v4_putrootfh | T-071: PUTROOTFH(opcode=24) 无参数 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t071_v4_putrootfh.pcap) |
| nfs_t072_v4_putpubfh | T-072: PUTPUBFH(opcode=23) 无参数 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t072_v4_putpubfh.pcap) |
| nfs_t073_v4_getattr_bitmap | T-073: GETATTR(opcode=9, attr_mask=[16,2,0]) → 自动补 PUTROOTFH(24)，bitmap len=3 + 16 + 2 + 0 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t073_v4_getattr_bitmap.pcap) |
| nfs_t074_v4_getattr_reply_fattr4 | T-074: GETATTR reply fattr4 → bitmap len=3 + word0/1/2 + attr_vals 长度前缀 0000000C + size 8B + mode 4B | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t074_v4_getattr_reply_fattr4.pcap) |
| nfs_t075_v4_getfh | T-075: GETFH（opcode=10）→ 自动补 PUTROOTFH；reply 含 fh len + data AA BB CC DD | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t075_v4_getfh.pcap) |
| nfs_t076_v4_lookup | T-076: NFSv4 LOOKUP(opcode=15, name=file.txt) 单 op COMPOUND（无需 current fh，不自动补 PUTROOTFH） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t076_v4_lookup.pcap) |
| nfs_t077_v4_lookupp | T-077: LOOKUPP(opcode=16) 无参数 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t077_v4_lookupp.pcap) |
| nfs_t078_v4_open | T-078/S12: NFSv4 OPEN（opcode18, seqid=1, share_access=2 WRITE, owner clientid=12345+0x01, openhow unchecked, claim null）→ 自动 OPEN_CONFIRM(20, seqid=2) 补全；LOCK(12)/LOCKU(14)/CLOSE(4) 序列含 seqid 独立 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t078_v4_open.pcap) |
| nfs_t079_v4_open_claim_previous | T-079: OPEN claim=previous（判别=1 + delegate_type=0）→ 自动补 PUTROOTFH+OPEN_CONFIRM | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t079_v4_open_claim_previous.pcap) |
| nfs_t080_v4_open_delegate_cur | T-080: NFSv4 OPEN claim=delegate_cur（判别=2 + delegate stateid + component f）+ openhow unchecked + share_access=1；自动补 PUTROOTFH + OPEN_CONFIRM(seqid=2) | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t080_v4_open_delegate_cur.pcap) |
| nfs_t081_v4_open_claim_delegate_prev | T-081: OPEN claim=delegate_prev（判别=3 + delegate_type=0 + component f） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t081_v4_open_claim_delegate_prev.pcap) |
| nfs_t082_v4_open_unchecked | T-082: OPEN openhow=unchecked（share_access=1）→ opentype=1 + createmode=0 + createattrs 空 fattr4 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t082_v4_open_unchecked.pcap) |
| nfs_t083_v4_open_guarded | T-083: OPEN openhow=guarded → opentype=1 + createmode=1 (GUARDED4) | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t083_v4_open_guarded.pcap) |
| nfs_t084_v4_open_exclusive | T-084: OPEN openhow=exclusive + verifier=0102030405060708 → opentype=1 + createmode=2 + createverf 8B | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t084_v4_open_exclusive.pcap) |
| nfs_t085_v4_open_default_openhow | T-085: OPEN openhow 未设 → 默认 opentype=1 + createmode=0 (UNCHECKED4) | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t085_v4_open_default_openhow.pcap) |
| nfs_t086_v4_open_default_claim | T-086: OPEN claim 未设 → 默认 discriminator=0 (CLAIM_NULL) + file | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t086_v4_open_default_claim.pcap) |
| nfs_t087_v4_open_share_access_read | T-087: OPEN share_access=1 (READ) → 00000001 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t087_v4_open_share_access_read.pcap) |
| nfs_t088_v4_open_share_access_both | T-088: OPEN share_access=3 (BOTH) → 00000003 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t088_v4_open_share_access_both.pcap) |
| nfs_t088a_v4_open_share_access0_validate | T-088a: OPEN share_access=0 越界 → Validate 报错（V23b） | pass | 0 | [pcap]() |
| nfs_t088b_v4_open_share_access4_validate | T-088b: OPEN share_access=4 越界 → Validate 报错（V23b） | pass | 0 | [pcap]() |
| nfs_t089_v4_open_share_deny2 | T-089: OPEN share_deny=2 (WRITE) → 00000002 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t089_v4_open_share_deny2.pcap) |
| nfs_t089a_v4_open_share_deny3 | T-089a: OPEN share_deny=3 (DENY4_BOTH) 合法 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t089a_v4_open_share_deny3.pcap) |
| nfs_t089b_v4_open_share_deny4_validate | T-089b: OPEN share_deny=4 越界 → Validate 报错（V23b） | pass | 0 | [pcap]() |
| nfs_t090_v4_open_reply_stateid | T-090: OPEN reply stateid（open_reply_stateid seqid=7 + other 12B 0xAA）→ reply stateid4 16B | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t090_v4_open_reply_stateid.pcap) |
| nfs_t092_v4_open_downgrade | T-092: OPEN_DOWNGRADE（opcode=21, seqid=2, share_access=1, share_deny=0）→ 自动补 PUTROOTFH+OPEN_CONFIRM；opcode 序列 24,18,20,21 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t092_v4_open_downgrade.pcap) |
| nfs_t093_v4_close | T-093: CLOSE（opcode=4, seqid=3, open_stateid 全 0）→ 自动补 PUTROOTFH+OPEN_CONFIRM；opcode 序列 24,18,20,4 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t093_v4_close.pcap) |
| nfs_t094_v4_read | T-094: v4 READ（opcode=25, stateid 全 0, offset=0, count=4096）→ 自动补 PUTROOTFH | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t094_v4_read.pcap) |
| nfs_t095_v4_write | T-095: NFSv4 WRITE(opcode=38, stateid 匿名 + offset=0 + stable_how=2 + data=hello)；REPLY count=5/committed=2/verf 8B | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t095_v4_write.pcap) |
| nfs_t096_v4_commit | T-096: v4 COMMIT（opcode=5, offset=0, count=4096）→ 自动补 PUTROOTFH；call args offset+count | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t096_v4_commit.pcap) |
| nfs_t097_v4_create | T-097: v4 CREATE（opcode=6, objtype=1 NF4REG, name=f）→ 自动补 PUTROOTFH；call objtype=00000001 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t097_v4_create.pcap) |
| nfs_t098_v4_create_default_objtype | T-098: CREATE objtype 未设 → Validate 通过（V21 缺省不报错，非错误）；wire 按实现编码 objtype=0 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t098_v4_create_default_objtype.pcap) |
| nfs_t099_v4_remove | T-099: v4 REMOVE（opcode=28, name=old）→ 自动补 PUTROOTFH；call component4 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t099_v4_remove.pcap) |
| nfs_t100_v4_rename | T-100: NFSv4 RENAME(opcode=29, oldname=a → newname=b) 前接 PUTFH；args 顺序 oldname→newname | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t100_v4_rename.pcap) |
| nfs_t103_v4_setclientid_explicit | T-103: 用户显式配置 SETCLIENTID(opcode=35) → 不重复插入；call 仅 1 个 opcode=35 | pass | 11 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t103_v4_setclientid_explicit.pcap) |
| nfs_t104_v4_setclientid_confirm_explicit | T-104: 用户显式配置 opcode 35 + opcode 36 → 两者各 1 个，不重复插入 | pass | 11 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t104_v4_setclientid_confirm_explicit.pcap) |
| nfs_t105_v4_setclientid_confirm_autofill | T-105: 用户显式 opcode=35 但无 opcode=36 → 自动追加 CONFIRM；序列 35 然后 36 | pass | 11 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t105_v4_setclientid_confirm_autofill.pcap) |
| nfs_t106_v4_clientid_default_session | T-106: op clientid=0（未设）→ 默认按会话分配 0x10001（单会话） | pass | 11 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t106_v4_clientid_default_session.pcap) |
| nfs_t107_v4_clientid_explicit | T-107: clientid 显式 12345 → call 8B clientid 00 00 00 00 00 00 30 39 | pass | 11 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t107_v4_clientid_explicit.pcap) |
| nfs_t108_v4_clientid_dup_sessions_validate | T-108: sessions=2 两会话 op 都设 clientid=100 → Validate 报错（V36） | pass | 0 | [pcap]() |
| nfs_t109_v4_clientid_dup_single_ok | T-109: sessions=1 两个 op 都设 clientid=100 → Validate 通过（单会话不限制） | pass | 15 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t109_v4_clientid_dup_single_ok.pcap) |
| nfs_t111_v4_lock_new_owner_false | T-111: LOCK new_lock_owner=false → locker4 disc=0 + lock_owner4(clientid+owner) | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t111_v4_lock_new_owner_false.pcap) |
| nfs_t112_v4_lock_read_lt | T-112: LOCK lock_type=1 (READ_LT) → 00000001 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t112_v4_lock_read_lt.pcap) |
| nfs_t113_v4_lock_type_write | T-113: LOCK lock_type=2 (WRITE_LT) | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t113_v4_lock_type_write.pcap) |
| nfs_t114_v4_lock_readw_lt | T-114: LOCK lock_type=3 (READW_LT) → 00000003 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t114_v4_lock_readw_lt.pcap) |
| nfs_t115_v4_lock_reclaim | T-115: LOCK reclaim=true → reclaim@arg=1（lease 恢复场景） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t115_v4_lock_reclaim.pcap) |
| nfs_t116_v4_lock_reply_stateid | T-116: LOCK reply lock_stateid（open_reply_stateid 注入 seqid=5, other 12B 0xBB）→ reply stateid 16B | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t116_v4_lock_reply_stateid.pcap) |
| nfs_t117_v4_lockt | T-117: LOCKT（opcode=13, lock_type=1, offset=0, length=100, owner）→ 自动补 PUTROOTFH | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t117_v4_lockt.pcap) |
| nfs_t118_v4_locku | T-118: LOCKU（opcode=14, lock_type=1, seqid=2, stateid 全 0, offset=0, length=100）→ 自动补 PUTROOTFH | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t118_v4_locku.pcap) |
| nfs_t120_v4_seqid_wrap | T-120: OPEN seqid=0xFFFFFFFF → 合法（uint32 回绕）；自动 OPEN_CONFIRM seqid=0 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t120_v4_seqid_wrap.pcap) |
| nfs_t121_v4_delegpurge | T-121: DELEGPURGE(opcode=7, clientid=12345) → 自动补 PUTROOTFH | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t121_v4_delegpurge.pcap) |
| nfs_t122_v4_delegreturn | T-122: DELEGRETURN（opcode=8, delegstateid 全 0）→ 自动补 PUTROOTFH | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t122_v4_delegreturn.pcap) |
| nfs_t123_v4_restorefh | T-123: [SAVEFH, PUTFH, RESTOREFH] → 自动补 PUTROOTFH，RESTOREFH 无参数 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t123_v4_restorefh.pcap) |
| nfs_t124_v4_savefh | T-124: SAVEFH(opcode=32) 无参数 → 自动补 PUTROOTFH | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t124_v4_savefh.pcap) |
| nfs_t125_v4_verify | T-125: VERIFY（opcode=37, attrs 空）→ 自动补 PUTROOTFH；fattr4 空 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t125_v4_verify.pcap) |
| nfs_t126_v4_nverify | T-126: NVERIFY(opcode=17) 含 obj_attr → 自动补 PUTROOTFH | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t126_v4_nverify.pcap) |
| nfs_t127_v4_setattr | T-127: SETATTR（opcode=34, stateid 全 0, attrs 空）→ 自动补 PUTROOTFH | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t127_v4_setattr.pcap) |
| nfs_t128_v4_secinfo | T-128: SECINFO（opcode=33, name=file）→ 自动补 PUTROOTFH | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t128_v4_secinfo.pcap) |
| nfs_t129_v4_release_lockowner | T-129: RELEASE_LOCKOWNER（opcode=39, owner clientid=12345）→ 自动补 PUTROOTFH | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t129_v4_release_lockowner.pcap) |
| nfs_t130_v4_renew | T-130: RENEW（opcode=30, clientid=12345）→ 自动补 PUTROOTFH | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t130_v4_renew.pcap) |
| nfs_t131_v4_stateid_anonymous | T-131: READ stateid=seqid 0 + other 12x00（anonymous stateid4，RFC 7530 §2.4）→ call 16B stateid 全零 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t131_v4_stateid_anonymous.pcap) |
| nfs_t132_v4_stateid_read_bypass | T-132: READ stateid=0xFFFFFFFF + other 12×FF（READ bypass 语义） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t132_v4_stateid_read_bypass.pcap) |
| nfs_t135_v4_stateid_other12 | T-135: stateid.other=12 字节 → Validate 通过，wire 16B stateid（other 定长 12） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t135_v4_stateid_other12.pcap) |
| nfs_t136_v3_mount_proc6 | T-136: MOUNT v3 procedure=6（越界，仅 0-5 合法）→ Validate V33 报错 | pass | 0 | [pcap]() |
| nfs_t137_v4_clientid_u64 | T-137: DELEGPURGE clientid=0x30393930（8B 大端） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t137_v4_clientid_u64.pcap) |
| nfs_t138_v4_bitmap_single | T-138: GETATTR attr_mask=[0x10] → bitmap len=1 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t138_v4_bitmap_single.pcap) |
| nfs_t139_v4_bitmap_double | T-139: GETATTR attr_mask=[0x10,0x02] → bitmap len=2 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t139_v4_bitmap_double.pcap) |
| nfs_t140_v4_attrmask_word2 | T-140: bitmap4 三 word — attr_mask=[16,2,0] → bitmap len=3（尾部 0 word 保留不截断） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t140_v4_attrmask_word2.pcap) |
| nfs_t141_v3_udp_65508 | T-141: transport=udp + WRITE data=65508B → Validate V15 报错（UDP RPC 超 65507） | pass | 0 | [pcap]() |
| nfs_t142_v3_udp_65507_ok | T-142: transport=udp + WRITE → UDP RPC 未超限通过（data 1B，payload 60B） | pass | 2 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t142_v3_udp_65507_ok.pcap) |
| nfs_t143_v3_utf8_filename | T-143: filename=文件.txt（10 字节 UTF-8）→ call filename len=10 + 2B pad | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t143_v3_utf8_filename.pcap) |
| nfs_t144_v3_opaque_pad1 | T-144: opaque padding 对齐 4（1 字节 data → 3 字节零填充） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t144_v3_opaque_pad1.pcap) |
| nfs_t145_v3_opaque_pad2 | T-145: opaque padding 对齐 4（2 字节 data → 2 字节零填充） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t145_v3_opaque_pad2.pcap) |
| nfs_t146_v3_opaque_pad3 | T-146: opaque padding 对齐 4（3 字节 data → 1 字节零填充） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t146_v3_opaque_pad3.pcap) |
| nfs_t147_v3_opaque_pad4 | T-147: opaque padding 对齐 4（4 字节 data → 无填充） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t147_v3_opaque_pad4.pcap) |
| nfs_t148_rpc_error | T-148/T-160: NFSv3 proc=22 透传 + rpc_accept_state=3 (PROC_UNAVAIL) → CALL Procedure=22，REPLY AcceptState=3 无 NFS body；仅 1 次 RPC 往返 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t148_rpc_error.pcap) |
| nfs_t149_v4_attrmask_v41 | T-149: attrmask word2 非零 → Validate V30 报错（NFSv4.1+ attributes 混入） | pass | 0 | [pcap]() |
| nfs_t150_v3_nfstime3 | T-150: SETATTR atime={secs:1000,nsecs:500} → nfstime3 8B | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t150_v3_nfstime3.pcap) |
| nfs_t151_v4_result_status | T-151: result_status=13 (NFS4ERR_ACCESS) → 顶层+全 op status=13；resarray 完整 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t151_v4_result_status.pcap) |
| nfs_t152_v4_op_reply_status | T-152: op.reply_status=10020 覆盖 → 该 op reply status=10020 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t152_v4_op_reply_status.pcap) |
| nfs_t153_v4_reply_status_priority | T-153: result_status=1 + reply_status=2 → 顶层用 reply_status=2（op 覆盖） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t153_v4_reply_status_priority.pcap) |
| nfs_t154_v4_err_nofilehandle | T-154/S15: NFSv4 GETATTR 无 PUTFH/PUTROOTFH → reply_status=10020 NFS4ERR_NOFILEHANDLE；resarray_len=2（PUTROOTFH+GETATTR 均回 op_status=10020），顶层 status 与 op_status 一致 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t154_v4_err_nofilehandle.pcap) |
| nfs_t154_v4_no_filehandle | T-154: compound_ops 无 PUTFH/PUTROOTFH → 自动补 PUTROOTFH(24) 仍成功（对比 T-155 截断） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t154_v4_no_filehandle.pcap) |
| nfs_t155_v4_compound_truncate | T-155: [PUTROOTFH, GETATTR{op_status:10025}, READ] → top=10025, resarray=2, READ 不返回 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t155_v4_compound_truncate.pcap) |
| nfs_t156_v4_single_op_fail | T-156: 单 op 失败 op_status=1 → reply 顶层=1 + resarray=2 (encoder 实际 emit 全 0) | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t156_v4_single_op_fail.pcap) |
| nfs_t157_v4_all_success | T-157: [PUTROOTFH, GETATTR] 全成功 → top=0 resarray=2 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t157_v4_all_success.pcap) |
| nfs_t158_rpc_accept_prog_unavail | T-158: rpc_accept_state=1 (PROG_UNAVAIL) → AcceptState=1 无 NFS body | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t158_rpc_accept_prog_unavail.pcap) |
| nfs_t158_rpc_prog_unavail | T-158: rpc_accept_state=1 (PROG_UNAVAIL) → REPLY AcceptState=1 无 NFS body（同一任务两个 op 分别注入 accept_state） | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t158_rpc_prog_unavail.pcap) |
| nfs_t159_rpc_accept_prog_mismatch | T-159: rpc_accept_state=2 + low=2 high=3 (PROG_MISMATCH) → AcceptState=2 + 版本范围 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t159_rpc_accept_prog_mismatch.pcap) |
| nfs_t160_rpc_accept_proc_unavail | T-160: rpc_accept_state=3 (PROC_UNAVAIL) → AcceptState=3 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t160_rpc_accept_proc_unavail.pcap) |
| nfs_t161_rpc_accept_garbage_args | T-161: rpc_accept_state=4 (GARBAGE_ARGS) → AcceptState=4 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t161_rpc_accept_garbage_args.pcap) |
| nfs_t162_rpc_accept_system_err | T-162: rpc_accept_state=5 (SYSTEM_ERR) → AcceptState=5 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t162_rpc_accept_system_err.pcap) |
| nfs_t163_rpc_reject_mismatch | T-163: RPCRejectState=0 (RPC_MISMATCH) + low=high=2 → REPLY MSG_DENIED + reject_stat + low/high 8B；RM=0x80000018 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t163_rpc_reject_mismatch.pcap) |
| nfs_t164_rpc_reject_auth_badcred | T-164: rpc_reject_state=1 + auth_stat=1 (AUTH_BADCRED) → MSG_DENIED | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t164_rpc_reject_auth_badcred.pcap) |
| nfs_t165_v4_auth_rejectedcred | T-165: rpc_reject_state=1 + auth_stat=2 (AUTH_REJECTEDCRED) → MSG_DENIED | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t165_v4_auth_rejectedcred.pcap) |
| nfs_t166_v4_auth_badverf | T-166: rpc_reject_state=1 + auth_stat=3 (AUTH_BADVERF) → MSG_DENIED | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t166_v4_auth_badverf.pcap) |
| nfs_t167_rpc_reject_auth_tooweak | T-167: rpc_reject_state=1 + auth_stat=5 (AUTH_TOOWEAK) → MSG_DENIED | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t167_rpc_reject_auth_tooweak.pcap) |
| nfs_t168_v4_err_moved | T-168: reply_status=10019 (NFS4ERR_MOVED) → 顶层 status=0x00002723 + 全部 op_status=10019 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t168_v4_err_moved.pcap) |
| nfs_t169_v4_err_resource | T-169: reply_status=10018 (NFS4ERR_RESOURCE) → 顶层 status=0x00002722 + 全部 op_status=10018 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t169_v4_err_resource.pcap) |
| nfs_t170_v4_err_bad_stateid | T-170: NFS4ERR_BAD_STATEID=10025 注入（reply_status）→ 顶层 status 与两 op_status 均回 10025(0x2729) | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t170_v4_err_bad_stateid.pcap) |
| nfs_t171_v4_sessions1_default | T-171: sessions 未设 → 单 TCP 流 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t171_v4_sessions1_default.pcap) |
| nfs_t172_v3_sessions2 | T-172/T-178: sessions=2 独立 TCP 流（src port 40000/40001），各含 MOUNT+NULL+UMOUNT 3 往返；每会话 XID 独立均从 1 起 | pass | 24 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t172_v3_sessions2.pcap) |
| nfs_t173_v4_sessions3 | T-173: sessions=3（无 base/step → 49152/49153/49154 默认）→ 3 个独立 TCP 流，每流独立 ISN 1000/2000 | pass | 36 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t173_v4_sessions3.pcap) |
| nfs_t174_v3_sessions2_step10 | T-174: sessions=2 step=10 → srcPort 40000/40010 | pass | 16 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t174_v3_sessions2_step10.pcap) |
| nfs_t175_v3_sessions2_step0_validate | T-175: sessions=2 step=0 → Validate 拒绝 | pass | 0 | [pcap]() |
| nfs_t176_v3_sessions1_step0 | T-176: sessions=1 step=0 → Validate 通过 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t176_v3_sessions1_step0.pcap) |
| nfs_t177_v4_sessions2_clientid | T-177: sessions=2 → session0 clientid=0x10001, session1=0x20001 | pass | 24 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t177_v4_sessions2_clientid.pcap) |
| nfs_t178_v4_sessions2_xid | T-178: sessions=2 xid_base=1 → 两会话首个 call XID 均=1（独立序列） | pass | 24 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t178_v4_sessions2_xid.pcap) |
| nfs_t179_v4_sessions2_client_id | T-179: sessions=2 → client id=trafficgen-client-0 / -1 | pass | 24 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t179_v4_sessions2_client_id.pcap) |
| nfs_t180_v4_sessions3_order | T-180: sessions=3 顺序生成不交错——session 0 全部包 → session 1 → session 2（按 srcPort 分组连续） | pass | 36 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t180_v4_sessions3_order.pcap) |
| nfs_t181_validate_version0 | T-181: version=0 → Validate 拒绝 | pass | 0 | [pcap]() |
| nfs_t182_validate_version5 | T-182: version=5 → Validate 拒绝 | pass | 0 | [pcap]() |
| nfs_t183_validate_version2 | T-183: version=2 → Validate 拒绝（NFSv2 不支持） | pass | 0 | [pcap]() |
| nfs_t184_validate_ops_empty | T-184: ops=[] → Validate 拒绝 | pass | 0 | [pcap]() |
| nfs_t185_v3_fh_len0 | T-185: filehandle='' → fh len=0 无 data | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t185_v3_fh_len0.pcap) |
| nfs_t186_v3_read_count0 | T-186: READ count=0 → call count=0 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t186_v3_read_count0.pcap) |
| nfs_t189_v4_seqid_u32max | T-189: OPEN seqid=0xFFFFFFFF → seqid FF FF FF FF | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t189_v4_seqid_u32max.pcap) |
| nfs_t191_v3_full_session | T-191: NFSv3 完整会话 — MOUNT(2) + GETATTR/LOOKUP/READ/WRITE/REMOVE(10) + UMOUNT(2) = 20 包 | pass | 21 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t191_v3_full_session.pcap) |
| nfs_t192_v4_full_session | T-192: NFSv4 完整会话 — SETCLIENTID(35) + CONFIRM(36) + 2 个用户 COMPOUND = 14 包 | pass | 15 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t192_v4_full_session.pcap) |
| nfs_t193_v4_auth_sys_full | T-193: AUTH_SYS 完整会话 — 每个 call CredFlavor=1、CredLen=32（默认 auth_sys） | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t193_v4_auth_sys_full.pcap) |
| nfs_t194_v4_result_status_full | T-194: result_status=10020 完整会话 — reply 顶层 status=0x2724 + 所有 op_status=10020 | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t194_v4_result_status_full.pcap) |
| nfs_t195_v4_sessions3_full | T-195: sessions=3 完整 — 3 个独立流 × 完整序列（SETCLIENTID+CONFIRM+用户 COMPOUND） | pass | 36 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t195_v4_sessions3_full.pcap) |
| nfs_t197_v4_e2e_pcap | T-197: 端到端 PCAP 产出 — 任务提交 → pcap 含 3-way + RPC + FIN，tshark 解析为 NFS | pass | 13 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t197_v4_e2e_pcap.pcap) |
| nfs_t198_v3_e2e_pcap | T-198: Plan→builder 集成 — v3 WRITE 字节流可被 NFS dissector 解析 | pass | 9 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t198_v3_e2e_pcap.pcap) |
| nfs_t199_v4_dup_clientid | T-199: broken spec — 跨会话重复 clientid（SETCLIENTID_CONFIRM ×2 同一 clientid）→ 任务实际失败 | pass | 0 | [pcap]() |
| nfs_t200_v4_full_fields | T-200: 全字段端到端 — auth_sys + sessions=2 + result_status=10020 → 每 call AUTH_SYS、每会话独立流、reply status=10020 | pass | 24 | [pcap](/tmp/mcp-pcaps/nfs/nfs_t200_v4_full_fields.pcap) |
