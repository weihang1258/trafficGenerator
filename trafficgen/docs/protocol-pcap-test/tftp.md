# tftp Pcap Test Results

Cases: 226 — pass 226, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| tftp-auto-append-off | T-044: auto_append_final_block=false 无选项流 → 无 0 字节末块（非 RFC 合规负向），5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-auto-append-off.pcap) |
| tftp-blksize65464-max | T-042/S13b: blksize=65464（最大）DATA 65468B ≤ UDP 上限 → 自动追加，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-blksize65464-max.pcap) |
| tftp-blksize8-min | T-041/S13b: blksize=8（最小）→ OACK → ACK#0 → DATA#1(8B) → 自动追加，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-blksize8-min.pcap) |
| tftp-blocks-65535-short | T-048: blocks_count=65535（short-circuit 首包） | pass | 131071 | [pcap](/tmp/mcp-pcaps/tftp/tftp-blocks-65535-short.pcap) |
| tftp-concurrent-8flows-100blk | T-161: 8 流并发每流 100 块 → 1616 包 | pass | 1624 | [pcap](/tmp/mcp-pcaps/tftp/tftp-concurrent-8flows-100blk.pcap) |
| tftp-concurrent-8flows-retx | T-168: 8 流重传 → 56 包 | pass | 56 | [pcap](/tmp/mcp-pcaps/tftp/tftp-concurrent-8flows-retx.pcap) |
| tftp-concurrent-8flows-tid | T-169: 8 流 TID 变更 → 96 包 | pass | 0 | [pcap]() |
| tftp-concurrent-8flows-ws4 | T-167: 8 流 windowsize=4 → 80 包 | pass | 80 | [pcap](/tmp/mcp-pcaps/tftp/tftp-concurrent-8flows-ws4.pcap) |
| tftp-concurrent-tid-derived | T-166: 多流 server_tid=0 → 各自派生互异（4-tuple 互异） | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-concurrent-tid-derived.pcap) |
| tftp-data-header-ff | T-132: DATA 头字节精确 `00 03 00 01` + 512×0xFF（516B，udp.length=524），7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-data-header-ff.pcap) |
| tftp-e2e-blksize-65464 | T-158: E2E blksize=65464 → 6 包（UDP Len 65476 ≤ 65507） | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-blksize-65464.pcap) |
| tftp-e2e-bps | T-220: bps 限速 100 块流生成正确 | pass | 203 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-bps.pcap) |
| tftp-e2e-checksum-ip | T-148: E2E UDP 校验和与 IP 头完整可解析 | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-checksum-ip.pcap) |
| tftp-e2e-direction | T-154: E2E Direction 标记（RRQ=up, DATA=down, ACK=up） | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-direction.pcap) |
| tftp-e2e-direction-count | T-219: 方向统计 up=3/down=2（RRQ+2 ACK up, 2 DATA down） | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-direction-count.pcap) |
| tftp-e2e-dstport-1069 | T-221: E2E 显式 dst_port=1069 | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-dstport-1069.pcap) |
| tftp-e2e-error-propagate | T-143: E2E 错误注入传播 → 2 包 | pass | 2 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-error-propagate.pcap) |
| tftp-e2e-gre | T-214: tftp + GRE 隧道封装共存 | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-gre.pcap) |
| tftp-e2e-metadata | T-153: E2E metadata 可观察性（TID 确定性派生） | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-metadata.pcap) |
| tftp-e2e-mixed-dns | T-215: tftp + dns 混合互不干扰 | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-mixed-dns.pcap) |
| tftp-e2e-multiflow | T-144: E2E 3 流 → 9 包单 PCAP | pass | 15 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-multiflow.pcap) |
| tftp-e2e-no-final-block | T-159: E2E 半标准流（auto_append=false）→ 3 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-no-final-block.pcap) |
| tftp-e2e-retransmit | T-150: E2E 重传流 → 9 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-retransmit.pcap) |
| tftp-e2e-rrq-short | T-141: E2E RRQ 短文件 → 3 包 | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-rrq-short.pcap) |
| tftp-e2e-tcp-reject | T-155: E2E tftp + tcp 并存 → 任务失败 | pass | 0 | [pcap]() |
| tftp-e2e-tidchange | T-149: E2E TID 变更流 → 12 包 | pass | 12 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-tidchange.pcap) |
| tftp-e2e-tshark-errdecode | T-210: tshark 错误码解析（code=1） | pass | 2 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-tshark-errdecode.pcap) |
| tftp-e2e-tshark-recognize | T-208: tshark 协议识别 + 无 malformed | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-tshark-recognize.pcap) |
| tftp-e2e-tshark-winsize | T-211: tshark windowsize 选项解析（值=4） | pass | 10 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-tshark-winsize.pcap) |
| tftp-e2e-udp-checksum | T-148: E2E UDP 校验和与 IP 头（tshark 完整解析，无 malformed） | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-udp-checksum.pcap) |
| tftp-e2e-validate-fail | T-147: E2E filename 空 → 任务失败 | pass | 0 | [pcap]() |
| tftp-e2e-vlan | T-213: tftp + VLAN 头共存 | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-vlan.pcap) |
| tftp-e2e-windowsize4 | T-145: E2E windowsize=4 → 15 包窗口序列 | pass | 15 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-windowsize4.pcap) |
| tftp-e2e-wrq-oack | T-142: E2E WRQ + OACK → 6 包（含自动追加） | pass | 6 | [pcap](/tmp/mcp-pcaps/tftp/tftp-e2e-wrq-oack.pcap) |
| tftp-error1-19b | T-134: ERROR(1) 字节精确（默认映射 File not found，19B） | pass | 2 | [pcap](/tmp/mcp-pcaps/tftp/tftp-error1-19b.pcap) |
| tftp-final-block-zero | T-018: FinalBlockZero 显式 0 字节末块（blocks_count=2，跳过自动追加），5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-final-block-zero.pcap) |
| tftp-http-coexist-reject | T-102: tftp + http 并存 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-matrix-allopts-retx-err | T-196: 全选项+重传+ERROR 组合 → 8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-matrix-allopts-retx-err.pcap) |
| tftp-matrix-allopts-tid | T-205: 全选项 + TID 变更 → 14 包 | pass | 12 | [pcap](/tmp/mcp-pcaps/tftp/tftp-matrix-allopts-tid.pcap) |
| tftp-matrix-blk65464-ws2 | T-198: blksize=65464 + windowsize=2 → 8 包 | pass | 8 | [pcap](/tmp/mcp-pcaps/tftp/tftp-matrix-blk65464-ws2.pcap) |
| tftp-matrix-blk8-ws2 | T-197: blksize=8 + windowsize=2 → 8 包（含自动追加） | pass | 8 | [pcap](/tmp/mcp-pcaps/tftp/tftp-matrix-blk8-ws2.pcap) |
| tftp-matrix-ws1-equiv | T-201: windowsize=1 与无选项等价 → 5 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-matrix-ws1-equiv.pcap) |
| tftp-multiflow-100flows-tuple-unique | T-217: 100 流 UDP 4-tuple 唯一性（src_port 自动递增） | pass | 300 | [pcap](/tmp/mcp-pcaps/tftp/tftp-multiflow-100flows-tuple-unique.pcap) |
| tftp-multiflow-3flows-9pkt | T-106/S11: 3 流并发（strategy_fc flows=3），每流 RRQ→DATA→ACK，4-tuple 互异 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-multiflow-3flows-9pkt.pcap) |
| tftp-multiflow-3flows-interleave | T-107/S12: 3 流交错（strategy_fc flows=3），每流 PacketIndex 连续 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-multiflow-3flows-interleave.pcap) |
| tftp-multiflow-error-flow | T-123: 3 流含 1 ERROR 流（error_code=1 立即）→ 8 包，错误流独立终止 | pass | 6 | [pcap](/tmp/mcp-pcaps/tftp/tftp-multiflow-error-flow.pcap) |
| tftp-multiflow-retransmit-flow | T-125: 3 流含重传流（retransmit_blocks=[1]）→ 13 包 | pass | 21 | [pcap](/tmp/mcp-pcaps/tftp/tftp-multiflow-retransmit-flow.pcap) |
| tftp-multiflow-same-filename | T-175: 3 流同 filename=x.bin → 3 独立会话 | pass | 15 | [pcap](/tmp/mcp-pcaps/tftp/tftp-multiflow-same-filename.pcap) |
| tftp-multiflow-srcip-skip | T-109: 多流不同 src_ip（策略层不支持，跳过注明） | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-multiflow-srcip-skip.pcap) |
| tftp-multiflow-tidchange-flow | T-124: 3 流含 TID 变更流（server_tid_change）→ 18 包 | pass | 0 | [pcap]() |
| tftp-oack-blksize-15b | T-128: OACK 字节精确（blksize=1428 单选项，15B） | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-oack-blksize-15b.pcap) |
| tftp-oack-multiopt-35b | T-137: 多选项 OACK 字节精确 `00 06 blksize\0 512\0 timeout\0 5\0 tsize\0 1024\0`（35B：2+12+10+11），7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-oack-multiopt-35b.pcap) |
| tftp-oack-timeout-13b | T-129: OACK 字节精确（timeout=10 单选项，13B） | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-oack-timeout-13b.pcap) |
| tftp-oack-tsize-13b | T-130: OACK 字节精确（tsize=2048 单选项，13B，RRQ 模式） | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-oack-tsize-13b.pcap) |
| tftp-regress-blocks-65536-wrap | T-222: blocks_count=65536 + wrap → 首包 Block#=1 | pass | 131073 | [pcap](/tmp/mcp-pcaps/tftp/tftp-regress-blocks-65536-wrap.pcap) |
| tftp-regress-blocks-wrap-seq | T-049: 65536 块回绕 short-circuit（首 2 块） | pass | 131073 | [pcap](/tmp/mcp-pcaps/tftp/tftp-regress-blocks-wrap-seq.pcap) |
| tftp-regress-err0-inject | T-227: ErrorCode=0 + ErrorAfterBlock=1 → 注入 ERROR(0) | pass | 4 | [pcap](/tmp/mcp-pcaps/tftp/tftp-regress-err0-inject.pcap) |
| tftp-regress-err0-noinject | T-228: ErrorCode=0 + ErrorAfterBlock=0 不注入 → 正常传输 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-regress-err0-noinject.pcap) |
| tftp-regress-err5-term | T-230: ERROR code=5 普通注入终止 | pass | 4 | [pcap](/tmp/mcp-pcaps/tftp/tftp-regress-err5-term.pcap) |
| tftp-regress-err8-map | T-233: ERROR code=8 映射 "Failed to negotiate options" | pass | 2 | [pcap](/tmp/mcp-pcaps/tftp/tftp-regress-err8-map.pcap) |
| tftp-regress-filename-255 | T-234: filename=255×a 生成正常 | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-regress-filename-255.pcap) |
| tftp-regress-include-oack | T-235: IncludeOACK=true 空 OACK = 2 字节 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-regress-include-oack.pcap) |
| tftp-regress-rrq-client-tsize | T-224: RRQ + client_tsize=1024 → 自动追加 DATA#3(0B) | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-regress-rrq-client-tsize.pcap) |
| tftp-regress-rrq-dual-tsize | T-226: RRQ 双 tsize → ClientTSize 优先 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-regress-rrq-dual-tsize.pcap) |
| tftp-regress-rrq-fbz-tsize | T-236: RRQ + client_tsize + final_block_zero → 9 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-regress-rrq-fbz-tsize.pcap) |
| tftp-regress-rrq-server-tsize | T-225: RRQ + server_tsize=1024 → 自动追加 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-regress-rrq-server-tsize.pcap) |
| tftp-regress-tid-4000 | T-241: server_tid=4000 注册端口 → 通过 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-regress-tid-4000.pcap) |
| tftp-rrq-14bytes | T-126: RRQ 字节精确 `00 01 a.bin\0 octet\0`（14B：2+6+6），3 包 | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-14bytes.pcap) |
| tftp-rrq-3opts-autofull | T-010/S7: blksize+timeout+tsize 三选项（顺序 blksize→timeout→tsize）+ 4 满块 + 自动追加，13 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-3opts-autofull.pcap) |
| tftp-rrq-all4opts | T-176: 全选项 RRQ（blksize+timeout+tsize+windowsize）→ OACK(4) → ACK#0 → 窗口 DATA#1#2 → ACK#2 → 自动追加，8 包 | pass | 8 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-all4opts.pcap) |
| tftp-rrq-all4opts-tidchange | T-205: 全选项 + TID 变更（OACK 旧 TID 60000 → DATA#3 起新 TID 61000 + ERROR(5)）+ 自动追加，13 包 | pass | 12 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-all4opts-tidchange.pcap) |
| tftp-rrq-allopts-retransmit-error | T-196: 全选项 + 重传 [1] + ERROR(1) after_block=2，blocks=2 → RRQ 4 选项 → OACK → ACK#0 → DATA#1(重传)/ACK#1 → DATA#2/ACK#2 → ERROR(1)，9 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-allopts-retransmit-error.pcap) |
| tftp-rrq-allzero-options-no-oack | T-067: 全零选项（blksize=0+timeout=0+tsize 双 0+windowsize=0）→ RRQ 无选项、无 OACK → DATA#1(512B) → 自动追加 DATA#2(0B)，5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-allzero-options-no-oack.pcap) |
| tftp-rrq-blksize-1428 | T-005/S3: blksize=1428 协商 → OACK → ACK#0 → 2 满块 → 自动追加 DATA#3(0B)，9 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-blksize-1428.pcap) |
| tftp-rrq-blksize-default-no-option | T-054: blksize=0（省略）→ 不发送 blksize 选项、无 OACK，DATA=512B，5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-blksize-default-no-option.pcap) |
| tftp-rrq-blksize-retransmit | T-192: blksize + 重传 [1] → RRQ 带 blksize 选项 → OACK → ACK#0 → DATA#1(重传)/ACK#1 → DATA#2/ACK#2 → 自动追加 DATA#3(0B)/ACK#3，9 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-blksize-retransmit.pcap) |
| tftp-rrq-blksize-timeout | T-178: blksize+timeout 两选项 → OACK(2) → ACK#0 → 锁步 → 自动追加，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-blksize-timeout.pcap) |
| tftp-rrq-blksize-tsize | T-179: blksize+tsize 两选项 → OACK(2, tsize 回 ServerTSize=1024) → ACK#0 → 锁步 → 自动追加，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-blksize-tsize.pcap) |
| tftp-rrq-blksize-winsize | T-180: blksize+windowsize 两选项 → OACK(2) → ACK#0 → 窗口 DATA#1#2 → ACK#2 → 自动追加，8 包 | pass | 8 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-blksize-winsize.pcap) |
| tftp-rrq-blksize65464-winsize2 | T-198: blksize=65464（最大）+ windowsize=2 → DATA 65464B×2 → ACK#2 → 自动追加，8 包 | pass | 8 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-blksize65464-winsize2.pcap) |
| tftp-rrq-blksize65535-append-wrap | T-051: 自动追加推至 65536（开 wrap）→ Block#0 末块（short-circuit 语义） | pass | 131075 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-blksize65535-append-wrap.pcap) |
| tftp-rrq-blksize8-winsize2 | T-197: blksize=8（最小）+ windowsize=2 → DATA 8B×2 → ACK#2 → 自动追加 DATA#3(0B)，8 包 | pass | 8 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-blksize8-winsize2.pcap) |
| tftp-rrq-blocks-65535-head | T-048/S13c: blocks_count=65535 首块 Block#=1（short-circuit 首包断言，不生成全部） | pass | 131071 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-blocks-65535-head.pcap) |
| tftp-rrq-blocks65536-parse | T-222/C1: blocks_count=65536 可解析（uint32）+ wrap 合法通过 | pass | 131075 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-blocks65536-parse.pcap) |
| tftp-rrq-defaults | T-012: 默认值（mode=read/octet/dst_port=69）→ RRQ 仅 filename → DATA#1(512B)/ACK#1 → DATA#2(0B)/ACK#2，5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-defaults.pcap) |
| tftp-rrq-derive-filesource-1024 | T-059: BlocksCount 显式 2 + 0xCC 模式（层链等价：FileSource 推导不可达 → 显式 blocks_count 2 表达 ceil(1024/512)） | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-derive-filesource-1024.pcap) |
| tftp-rrq-double-tsize | T-226: RRQ 双 tsize 非零（Client=512, Server=1024）→ 判定 Client=512 → RRQ(`tsize\0 0\0`) → OACK(`tsize\0 1024\0`) → DATA#1 → 自动追加，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-double-tsize.pcap) |
| tftp-rrq-dstport-1069 | T-103/T-221: dst_port=1069 显式 → RRQ 发往 1069，后续 DATA 用 TID（非 1069），5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-dstport-1069.pcap) |
| tftp-rrq-empty-data-tsize512 | T-058: client_tsize=512 判定 → 自动追加 0 字节末块 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-empty-data-tsize512.pcap) |
| tftp-rrq-empty-pattern-bc1 | T-060: data_payload_pattern 空 + blocks_count=1 → 确定性 0x00..0xFF 模式 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-empty-pattern-bc1.pcap) |
| tftp-rrq-error-after-finalzero | T-105: error_after_block=2 + final_block_zero=true 组合（ERROR 终止，末块不生成） | pass | 6 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error-after-finalzero.pcap) |
| tftp-rrq-error-suppress-append | T-034: ERROR(1) 于块 3 后注入（3×512=1536=TSize）抑制自动追加 → ERROR 终止，8 包 | pass | 8 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error-suppress-append.pcap) |
| tftp-rrq-error-truncated | T-028: ERROR 消息 300×A 截断至 255B+\0（总 260B，udp.length=268），4 包 | pass | 4 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error-truncated.pcap) |
| tftp-rrq-error0-client | T-024/S8d: 客户端取消 ERROR(0) 自定义消息（ErrorCode=0+EAB=1 注入意图），4 包 | pass | 4 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error0-client.pcap) |
| tftp-rrq-error0-server-mid | T-036/T-227/T-240: code=0 server 中途注入（ErrorCode=0+EAB=1 → 注入 ErrCode=0，默认 ErrMsg Not defined），4 包 | pass | 4 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error0-server-mid.pcap) |
| tftp-rrq-error1-after-2 | T-029: ERROR 于 ACK#2 后注入（EAB=2）→ DATA#1/2 + ACK#1 → ERROR(1) 终止，6 包 | pass | 6 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error1-after-2.pcap) |
| tftp-rrq-error1-custom-msg | T-037: ErrMsg 覆盖默认（Custom\0）→ RRQ → ERROR(1, Custom)，2 包 | pass | 2 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error1-custom-msg.pcap) |
| tftp-rrq-error1-immediate | T-021/S8a: RRQ 后立即 ERROR(1) 默认消息，2 包 | pass | 2 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error1-immediate.pcap) |
| tftp-rrq-error2-immediate | T-031: ErrorAfterBlock=0 + ErrorCode>0 + BlocksCount>0 → 无 DATA 直接 ERROR(2)，2 包 | pass | 2 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error2-immediate.pcap) |
| tftp-rrq-error2-mid | T-022: RRQ 中途 ERROR(2)（ACK#3 后注入，ERROR 优先于自动追加），8 包 | pass | 8 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error2-mid.pcap) |
| tftp-rrq-error3-default-msg | T-038: ERROR 空 ErrMsg → 默认映射（Disk full or allocation exceeded）→ RRQ → ERROR(3)，2 包 | pass | 2 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error3-default-msg.pcap) |
| tftp-rrq-error4-default | T-025: ERROR 空消息 → 默认映射 Illegal TFTP operation，2 包 | pass | 2 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error4-default.pcap) |
| tftp-rrq-error5-client-terminate | T-030/T-230: 客户端主动 code=5 独立注入仍终止（非 TID 校验场景）→ DATA#1 → ACK#1 → ERROR(5) up，4 包 | pass | 4 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error5-client-terminate.pcap) |
| tftp-rrq-error5-default | T-027: ERROR code=5 默认映射 Unknown transfer ID（20B 含\0，总 24B），2 包 | pass | 2 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error5-default.pcap) |
| tftp-rrq-error7-after-oack | T-040: ERROR 注入于 RRQ+OACK 后（code=7, EAB=0）→ RRQ → OACK → ERROR(7)，无 ACK#0，3 包 | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error7-after-oack.pcap) |
| tftp-rrq-error8-default | T-026/T-135: ERROR code=8 默认映射 Failed to negotiate options，2 包 | pass | 2 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-error8-default.pcap) |
| tftp-rrq-filename-255 | T-234: filename=255×'a' 边界（trafficgen 限制）→ Validate 通过、RRQ 正常生成，5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-filename-255.pcap) |
| tftp-rrq-filename-backslash | T-047: filename 含反斜杠 dir\file.bin → 保留 \ 字符，5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-filename-backslash.pcap) |
| tftp-rrq-filename-slash | T-046: filename 含路径分隔符 /etc/passwd → 保留原样，5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-filename-slash.pcap) |
| tftp-rrq-final-zero-first | T-052: 首块即 0 字节末块（final_block_zero=true, blocks_count=1）→ DATA#1(0B) → ACK#1，3 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-final-zero-first.pcap) |
| tftp-rrq-finalzero-no-dup-append | T-019: FinalBlockZero + 自动追加不重复（client_tsize=1024, blocks_count=2, 末块显式 0B）→ 7 包，无 DATA#3 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-finalzero-no-dup-append.pcap) |
| tftp-rrq-full-13pkts | T-069/S15a: RRQ 完整流程 blksize=1024+timeout=5+tsize → 4 满块 → 自动追加，13 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-full-13pkts.pcap) |
| tftp-rrq-include-oack-empty | T-016/T-064: IncludeOACK=true 无选项 → 空 OACK `00 06`（2 字节）+ ACK#0 + 自动追加，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-include-oack-empty.pcap) |
| tftp-rrq-include-oack-wrq-empty | T-189: 无选项 + IncludeOACK=true（WRQ 空 OACK `00 06`） | pass | 4 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-include-oack-wrq-empty.pcap) |
| tftp-rrq-max-request-324 | T-065: filename=255 + 全 4 选项 = 324B < 512 通过 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-max-request-324.pcap) |
| tftp-rrq-mode-case-m1 | T-238/M1: mode=READ + transfer_mode=NetAscii 大小写不敏感，输出归一小写 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-mode-case-m1.pcap) |
| tftp-rrq-multiblock-append | T-002/T-043: RRQ 多块 + 自动追加（client_tsize=1024 判定 TSize → tsize 选项 → 空 OACK → ACK#0 → 2 满块 → DATA#3(0B)），9 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-multiblock-append.pcap) |
| tftp-rrq-multiopt-44b | T-136: 多选项 RRQ 字节精确（blksize=512+timeout=5+tsize=0，44B）→ OACK → ACK#0 → 自动追加，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-multiopt-44b.pcap) |
| tftp-rrq-netascii-hello | T-003: netascii 模式（小写 mode 字段）+ Hello 5B→循环填满 512B → RRQ → DATA#1(512B) → ACK#1 → DATA#2(0B)/ACK#2，5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-netascii-hello.pcap) |
| tftp-rrq-oack-winsize-15b | T-131: OACK windowsize 字节精确 `00 06 windowsize\0 4\0`（15B）+ 窗口传输 + 自动追加，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-oack-winsize-15b.pcap) |
| tftp-rrq-optorder-fixed | T-199: 选项顺序固定性（输入字段乱序 → 输出恒 blksize→timeout→tsize→windowsize），7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-optorder-fixed.pcap) |
| tftp-rrq-optorder-oack-match | T-200: OACK 选项顺序与 RRQ 一致（blksize→timeout→tsize→windowsize），7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-optorder-oack-match.pcap) |
| tftp-rrq-opts-error1-immediate | T-190: 选项 + ErrorAfterBlock=0 → RRQ → OACK → ERROR(1)，无 ACK#0，3 包 | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-opts-error1-immediate.pcap) |
| tftp-rrq-opts-error1-mid | T-191: 选项 + ErrorAfterBlock=1 → RRQ → OACK → ACK#0 → DATA#1/ACK#1 → ERROR(2)，6 包 | pass | 6 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-opts-error1-mid.pcap) |
| tftp-rrq-opts-finalzero | T-193: 选项 + FinalBlockZero → OACK → ACK#0 → DATA#1 → DATA#2(0B) 显式末块，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-opts-finalzero.pcap) |
| tftp-rrq-opts-noappend | T-194: 选项 + AutoAppendFinalBlock=false → OACK 后正常块，无自动追加，5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-opts-noappend.pcap) |
| tftp-rrq-opts-noinclude-oack | T-188: 选项 + IncludeOACK=false → OACK 仍出现（选项触发），7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-opts-noinclude-oack.pcap) |
| tftp-rrq-pattern-cycle | T-061: DataPayloadPattern [0x01,0x02] 循环填充 → DATA#1/2 → 自动追加，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-pattern-cycle.pcap) |
| tftp-rrq-reject-oack-code8 | T-035/S8c: 客户端拒绝 OACK（blksize=65464+ERROR(8,up)）RFC 2347 完整流程，3 包 | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-reject-oack-code8.pcap) |
| tftp-rrq-retransmit-error | T-033: RRQ 重传 [2] + error_code=1 after_block=3，blocks=3 → RRQ → DATA#1/ACK#1 → DATA#2(重传)/ACK#2 → DATA#3/ACK#3 → ERROR(1)，8 包 | pass | 8 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-retransmit-error.pcap) |
| tftp-rrq-retransmit-first-block | T-117: RRQ 首块重传 [1]，blocks=2 → RRQ → DATA#1(重传)/ACK#1 → DATA#2/ACK#2 → 自动追加，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-retransmit-first-block.pcap) |
| tftp-rrq-retransmit-multi | T-114: RRQ 重传多块 [1,3]，blocks=4 → RRQ → DATA#1(重传)/ACK#1 → DATA#2/ACK#2 → DATA#3(重传)/ACK#3 → DATA#4/ACK#4 → 自动追加，11 包 | pass | 11 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-retransmit-multi.pcap) |
| tftp-rrq-retransmit-single | T-113: RRQ 重传单块 [2]，blocks=3 → RRQ → DATA#1/ACK#1 → DATA#2(重传字节等价)/ACK#2 → DATA#3/ACK#3 → 自动追加 DATA#4(0B)/ACK#4，9 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-retransmit-single.pcap) |
| tftp-rrq-retransmit-timing | T-231: 重传时序合规（S10/RFC 1350 §6）→ DATA#2 仅重传版本 1 次，前无原 ACK#2 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-retransmit-timing.pcap) |
| tftp-rrq-retransmit-tsize-append | T-116: 重传 + client_tsize → RRQ 带 tsize → OACK 空 → ACK#0 → DATA#1/ACK#1 → DATA#2(重传)/ACK#2 → 自动追加 DATA#3(0B)/ACK#3，9 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-retransmit-tsize-append.pcap) |
| tftp-rrq-retransmit-wire-bytes | T-115: 重传字节与源块相同 → DATA#2(重传) 字节 = 无重传时 DATA#2 字节（AA 填充 512B） | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-retransmit-wire-bytes.pcap) |
| tftp-rrq-server-tid-4000-registered | T-241/M2/M7: server_tid=4000 注册端口合法（1024-65535） | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-server-tid-4000-registered.pcap) |
| tftp-rrq-server-tsize-append | T-225: RRQ+server_tsize 判定（ClientTSize=0→改判 ServerTSize=1024）→ RRQ(`tsize\0 0\0`) → OACK(`tsize\0 1024\0`) → 2 满块 → 自动追加，9 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-server-tsize-append.pcap) |
| tftp-rrq-short-aa100 | T-001/S1: RRQ octet 单块（pattern 循环填满 512B，禁用自动追加）→ DATA#1 → ACK#1，3 包 | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-short-aa100.pcap) |
| tftp-rrq-single-full-block | T-053: 单块 512B 满块 → 自动追加 0 字节终止块（R1-CRITICAL-3），7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-single-full-block.pcap) |
| tftp-rrq-tid-change-12pkts | T-110/T-111/T-112/S9: TID 变更迁移完整序列（60000→61000@块3）+ ERROR(5) 不终止 + 自动追加，12 包 | pass | 12 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-tid-change-12pkts.pcap) |
| tftp-rrq-timeout-10 | T-006/S4: timeout=10 协商 → OACK → ACK#0 → 满块 → 自动追加，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-timeout-10.pcap) |
| tftp-rrq-timeout-tsize | T-181: timeout+tsize 两选项 → OACK(2) → ACK#0 → 锁步 → 自动追加，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-timeout-tsize.pcap) |
| tftp-rrq-timeout-winsize | T-182: timeout+windowsize 两选项 → OACK(2) → ACK#0 → 窗口 DATA#1#2 → ACK#2 → 自动追加，8 包 | pass | 8 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-timeout-winsize.pcap) |
| tftp-rrq-timeout-zero-no-option | T-055: timeout=0 → 不发送 timeout 选项、无 OACK，5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-timeout-zero-no-option.pcap) |
| tftp-rrq-tsize-double-zero-no-option | T-056: client_tsize=0 + server_tsize=0 → 不发送 tsize 选项、无 OACK，5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-tsize-double-zero-no-option.pcap) |
| tftp-rrq-tsize-send-rule | T-237/H6: RRQ tsize 发送规则（server_tsize=2048 → RRQ 含 tsize=0，OACK 回显 2048） | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-tsize-send-rule.pcap) |
| tftp-rrq-tsize-server-2048 | T-007/S5a: RRQ tsize 协商（RRQ 恒 0，OACK 回 ServerTSize=2048）+ 4 满块 + 自动追加，13 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-tsize-server-2048.pcap) |
| tftp-rrq-tsize-winsize | T-183: tsize+windowsize 两选项 → OACK(2) → ACK#0 → 窗口 DATA#1#2 → ACK#2 → 自动追加，8 包 | pass | 8 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-tsize-winsize.pcap) |
| tftp-rrq-tsize0-client | T-063: RRQ client_tsize=1024 → tsize 选项值恒 0；ServerTSize=0 → OACK 空(00 06) | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-tsize0-client.pcap) |
| tftp-rrq-uppercase-normalize | T-013: 大写 mode/transfer_mode 输入 → 归一化小写 octet，5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-uppercase-normalize.pcap) |
| tftp-rrq-vlan-100 | T-213: VLAN 封装共存（vlan_id=100, priority=5）→ RRQ 含 VLAN 头，TFTP 载荷不受影响，5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-vlan-100.pcap) |
| tftp-rrq-winsize1-lockstep | T-201: windowsize=1 锁步等价（RFC 7440）→ 每 DATA 紧跟 ACK，9 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-winsize1-lockstep.pcap) |
| tftp-rrq-winsize1-lockstep-explicit | T-020: windowsize=1 显式（RFC 7440 锁步等价）→ 每 DATA 一 ACK + 自动追加，13 包 | pass | 13 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-winsize1-lockstep-explicit.pcap) |
| tftp-rrq-winsize2-tsize | T-122: windowsize=2 + server_tsize=2048 组合（窗口 ACK + tsize 自动追加） | pass | 11 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-winsize2-tsize.pcap) |
| tftp-rrq-winsize4-append | T-120/R1-HIGH-5: windowsize=4 + client_tsize=2048 自动追加（10 包） | pass | 10 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-winsize4-append.pcap) |
| tftp-rrq-winsize4-blocks8 | T-009/S6: windowsize=4 → 窗口内 4 DATA 后 ACK#4 → 8 满块 → 自动追加 DATA#9(0B)，15 包 | pass | 15 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-winsize4-blocks8.pcap) |
| tftp-rrq-winsize4-error | T-118: windowsize=4 + ERROR(1) after_block=4，blocks=6 → RRQ → OACK → ACK#0 → DATA#1-4 → ACK#4 → ERROR(1)（窗口末 ACK#4 后终止），8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-winsize4-error.pcap) |
| tftp-rrq-winsize4-partial-window | T-121: 末窗口不足 windowsize（4 窗口 + 6 块，末窗口 2 块）+ 自动追加 | pass | 13 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-winsize4-partial-window.pcap) |
| tftp-rrq-winsize4-retransmit | T-119: windowsize=4 + 重传 [3]，blocks=8 → RRQ → OACK → ACK#0 → DATA#1-4(#3 重传)→ACK#4 → DATA#5-8 → ACK#8 → 自动追加 DATA#9(0B)/ACK#9，15 包 | pass | 15 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-winsize4-retransmit.pcap) |
| tftp-rrq-winsize65535-wrap | T-202/S13d: windowsize=65535 + wrap（blocks_count=70000）→ 次窗口 4465 块 Block# 0..4464 → 自动追加，70007 包 | pass | 70007 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-winsize65535-wrap.pcap) |
| tftp-rrq-winsize65535-wrap2 | T-203: windowsize=65535 + 回绕跨窗口（blocks_count=131070）→ 次窗口 Block# 0..65534 → ACK#65534 → 自动追加，131077 包 | pass | 131077 | [pcap](/tmp/mcp-pcaps/tftp/tftp-rrq-winsize65535-wrap2.pcap) |
| tftp-server-tid-1024-boundary | T-083: server_tid=1024（registered 端口下界）合法 → 数据面用 1024，5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-server-tid-1024-boundary.pcap) |
| tftp-server-tid-explicit | T-014: server_tid=60000 显式 → 数据面用 60000 而非 69，5 包 | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-server-tid-explicit.pcap) |
| tftp-tid-conflict-batch | T-108/V22: 多流同 server_tid=60000 → strategy 创建拒绝 | pass | 0 | [pcap]() |
| tftp-tid-deterministic | T-015: ServerTID 确定性生成（FNV-1a(FlowID)，端口 49152-65535 且 ≠69） | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-tid-deterministic.pcap) |
| tftp-tidchange-errorcode0 | T-239/M3: ServerTIDChange + error_code=0 合法（不触发互斥） | pass | 12 | [pcap](/tmp/mcp-pcaps/tftp/tftp-tidchange-errorcode0.pcap) |
| tftp-udp-length-accounting | T-139: UDP 数据报长度核算 RRQ=8+14=22 / DATA=8+516=524，3 包 | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-udp-length-accounting.pcap) |
| tftp-validate-t050-append-push-65536 | T-050: 自动追加推至 65536 未开 wrap → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t071-empty-filename | T-071: filename 空字符串 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t072-filename-nul | T-072: filename 含 NUL 字节 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t073-invalid-mode | T-073: mode 非法 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t074-invalid-transfer-mode | T-074: transfer_mode 非法 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t075-mail-deprecated | T-075: transfer_mode=mail（RFC 1350 废弃） → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t076-error-code-9 | T-076: error_code=9（>RFC 上限 8） → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t077-blksize-7 | T-077: blksize=7（<RFC 2348 下限 8） → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t078-blksize-65465 | T-078: blksize=65465（>RFC 2348 上限 65464） → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t079-timeout-256 | T-079: timeout=256（>RFC 2348 上限 255）→ Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t080-windowsize-0-valid | T-080: windowsize=0 合法（0=不发送选项，impl V6 + tftp_test.go） | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-validate-t080-windowsize-0-valid.pcap) |
| tftp-validate-t081-windowsize-65536 | T-081: windowsize=65536（>RFC 7440 上限 65535）→ Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t082-server-tid-80 | T-082: server_tid=80（知名端口 <1024）→ Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t082-server-tid-wellknown | T-082: server_tid=80 知名端口 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t083-server-tid-1024 | T-083: server_tid=1024 合法边界（registered 端口下界） | pass | 5 | [pcap](/tmp/mcp-pcaps/tftp/tftp-validate-t083-server-tid-1024.pcap) |
| tftp-validate-t084-eab-exceeds | T-084: error_after_block=5 > blocks_count=2 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t085-eab-no-blocks-count | T-085: error_after_block=3 但 blocks_count=0（derive 不可判定）→ Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t086-eab-no-payload | T-086: error_after_block=2 但无 payload 源 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t087-retransmit-out-of-range | T-087: retransmit_blocks=[99] 越界 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t088-retransmit-zero | T-088: retransmit_blocks=[0]（块号最小 1）→ Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t089-tidchange-errorcode-mutex | T-089: server_tid_change + error_code>0 互斥 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t090-tidchange-retransmit | T-090: server_tid_change + retransmit_blocks 互斥 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t090-tidchange-retransmit-mutex | T-090: server_tid_change + retransmit_blocks 互斥 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t092-tidchange-atblock-0 | T-092: server_tid_change_at_block=0 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t093-tidchange-atblock-99 | T-093: server_tid_change_at_block=99 > blocks_count=4 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t093-tidchange-atblock-exceed | T-093: server_tid_change_at_block > blocks_count → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t094-server-tid-new-80 | T-094: server_tid_new=80（知名端口 <1024）→ Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t094-tidnew-wellknown | T-094: server_tid_new=80 知名端口 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t095-tid-new-equals-tid | T-095: server_tid_new == server_tid（迁移无意义）→ Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t095-tidnew-equals-tid | T-095: server_tid_new == server_tid → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t096-blocks-65536-no-wrap | T-096: blocks_count=65536 未开 wrap → Validate 拒绝（uint32 解析无溢出） | pass | 0 | [pcap]() |
| tftp-validate-t097-blocks-0-no-payload | T-097: blocks_count=0 且无 payload 源 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t099-finalzero-no-blocks | T-099: final_block_zero=true 但 blocks_count=0 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t100-autoappend-no-payload | T-100: auto_append=true + blocks_count=0 + 无 payload 源 → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-validate-t101-tcp-mutex | T-101: TFTP 与 TCP 子配置共存 → Validate 拒绝（V20 UDP-only） | pass | 0 | [pcap]() |
| tftp-validate-t104-error-afterblock-retransmit | T-104: error_after_block 与 retransmit_blocks 重叠（同块 3）→ 通过（组合合法） | pass | 8 | [pcap](/tmp/mcp-pcaps/tftp/tftp-validate-t104-error-afterblock-retransmit.pcap) |
| tftp-validate-t223-blocks-65536-nowrap | T-223/C1: blocks_count=65536 未开 wrap → Validate 拒绝 | pass | 0 | [pcap]() |
| tftp-wrq-14bytes | T-127/T-133: WRQ 14B 字节精确 `00 02 a.bin\0 octet\0` + ACK#0 4B，4 包 | pass | 4 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-14bytes.pcap) |
| tftp-wrq-all4opts | T-177: 全选项 WRQ（blksize+timeout+tsize+windowsize）→ OACK(4) → 窗口 DATA#1#2 → ACK#2 → 自动追加，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-all4opts.pcap) |
| tftp-wrq-all4opts-partial | T-195: 全选项 WRQ + client_tsize 判定 + 窗口 + 自动追加（末窗口部分块），9 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-all4opts-partial.pcap) |
| tftp-wrq-append-zero-4b | T-140: WRQ+tsize=512 → OACK → DATA#1 → 自动追加 DATA#2 仅头 4B `00 03 00 02`，6 包 | pass | 6 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-append-zero-4b.pcap) |
| tftp-wrq-blksize-512 | T-011: WRQ+OACK（无 ACK#0）→ DATA#1 满块 → 自动追加 DATA#2(0B)，6 包 | pass | 6 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-blksize-512.pcap) |
| tftp-wrq-blksize-only-oack | T-184: 单选项 blksize（WRQ）→ OACK(1) → DATA（无 ACK#0） | pass | 4 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-blksize-only-oack.pcap) |
| tftp-wrq-error3-mid | T-023/S8b: WRQ 中途 ERROR(3) 默认消息 33B，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-error3-mid.pcap) |
| tftp-wrq-error4-client-immediate | T-032: ErrorSide=client + WRQ → WRQ → ERROR(4) up，无 ACK#0，2 包 | pass | 2 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-error4-client-immediate.pcap) |
| tftp-wrq-finalzero | T-068: WRQ 空选项 + FinalBlockZero 显式末块 → WRQ → ACK#0 → DATA#1(512B)/ACK#1 → DATA#2(0B)/ACK#2，6 包 | pass | 6 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-finalzero.pcap) |
| tftp-wrq-include-oack-empty | T-017: IncludeOACK=true + 无选项（WRQ 空 OACK `00 06`）→ WRQ → OACK → DATA#1(512B) → ACK#1 → DATA#2(0B)/ACK#2，6 包 | pass | 6 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-include-oack-empty.pcap) |
| tftp-wrq-multiblock-append | T-045: WRQ 自动追加（client_tsize=1024 判定 TSize, blocks_count=2）→ WRQ+OACK → DATA/ACK×2 → DATA#3(0B)/ACK#3，8 包 | pass | 8 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-multiblock-append.pcap) |
| tftp-wrq-multiopt-47b | T-138: 多选项 WRQ 字节精确 `00 02 a.bin\0 octet\0 blksize\0 512\0 timeout\0 5\0 tsize\0 1024\0`（47B），6 包 | pass | 6 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-multiopt-47b.pcap) |
| tftp-wrq-oack-error6 | T-039: WRQ+OACK 后 ERROR(6)（无 ACK#0），3 包 | pass | 3 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-oack-error6.pcap) |
| tftp-wrq-short-noappend | T-070/S15b: WRQ 完整上传 3 满块 + 自动追加（末块满块），8 包 | pass | 8 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-short-noappend.pcap) |
| tftp-wrq-timeout-only | T-185: 单选项 timeout（WRQ）→ OACK(1) → DATA#1（无 ACK#0）→ 自动追加，6 包 | pass | 6 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-timeout-only.pcap) |
| tftp-wrq-tsize-client-2048 | T-008/S5b: WRQ tsize=2048（ClientTSize）→ OACK（无 ACK#0）→ 4 满块 → 自动追加，12 包 | pass | 12 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-tsize-client-2048.pcap) |
| tftp-wrq-tsize-only | T-186: 单选项 tsize（WRQ）→ OACK(1) → DATA#1（无 ACK#0）→ 自动追加，6 包 | pass | 6 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-tsize-only.pcap) |
| tftp-wrq-tsize-winsize-append | T-204: tsize+windowsize 自动追加边界（windowsize=2, blocks_count=4, client_tsize=2048）→ 末窗口后 0 字节末块，10 包 | pass | 10 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-tsize-winsize-append.pcap) |
| tftp-wrq-tsize-zero-oack-server | T-057: WRQ tsize=0（ClientTSize=0, ServerTSize=1024）→ WRQ(`tsize\0 0\0`) → OACK(`tsize\0 1024\0`) → DATA#1 → ACK#1 → DATA#2(0B)/ACK#2，6 包 | pass | 6 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-tsize-zero-oack-server.pcap) |
| tftp-wrq-upload-bb200 | T-004/S2: WRQ 上传单块（禁用自动追加）→ ACK#0 → DATA#1 → ACK#1，4 包 | pass | 4 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-upload-bb200.pcap) |
| tftp-wrq-winsize-only | T-187: 单选项 windowsize（WRQ）→ OACK(1) → 窗口 DATA#1#2 → ACK#2 → 自动追加，7 包 | pass | 7 | [pcap](/tmp/mcp-pcaps/tftp/tftp-wrq-winsize-only.pcap) |
