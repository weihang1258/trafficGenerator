# PCAP Parser 测试点细化

> 输入来源：`tools/enum_results/pcapparser.md`（365 场景）+ 源码 13 文件。
> 类型规则：纯函数/直接喂构造字节（frame/gopacket.Packet/byte slice）= **REAL**；构造内存 PCAP（`writePcap`/`pcapgo` 写 temp 文件）端到端跑 `Parse`/`ParsePacket` = **SIMULATED**；依赖真实 NIC/内核/多 GB 文件 = **MANUAL**。
> 构造辅助已存在：`writePcap`, `buildTCPFrame`, `buildTCPFrameWin`, `buildUDPFrame`, `buildIPv6UDPFrame`, `buildSYN`(带 TCP options), `buildFrag`, `buildTLSClientHello`。

---

## 组件: parser.go — Parse / openPcapReader / Options.batchSize / sortFlowStates / feedReassembledToAssembler / forwardPackets / forwardFlow / ProtocolDistJSON

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| P1.1-POS | P1.1 | TestParse_NilOptionsDefaults | `Parse(path, nil)`, 1 帧 TCP SYN pcap | err==nil; analysis.PacketCount==1; analysis.FlowCount==1 | SIMULATED | 复用 TestAuditFix_ParseNilOptions 形态 |
| P1.2-NEG | P1.2 | TestParse_OpenMissingFile | path=`/no/such/x.pcap` | err 含 "open pcap"; analysis==nil | REAL | 仅坏路径，无需构造 PCAP |
| P1.3-NEG | P1.3 | TestParse_CorruptPcapHeader | temp 文件写入 4 字节坏 magic(0xDEAD BEEF)+20 字节填充 | err 含 "parse pcap header" 或 "unsupported"; analysis==nil | SIMULATED | 构造坏 header 文件 |
| P1.4-NEG | P1.4 | TestParse_UnsupportedLinkType | `pcapgo.WriteFileHeader(65535, layers.LinkTypeRaw)` + 1 帧裸 IP | err 含 "unsupported link type"; analysis==nil | SIMULATED | DLT_RAW 非 Ethernet |
| P1.5-NEG | P1.5 | TestParse_PayloadsPathUnwritable | 1 帧 pcap + `PayloadsPath="/no/dir/x.payloads"` | err 含 "create payloads file"; analysis==nil | REAL | 坏路径 |
| P1.6-POS | P1.6 | TestParse_EOFNormalExit | 3 帧 TCP pcap，全部可读 | err==nil; PacketCount==3; FlowCount==期望; 所有 flow 已 finalize(DurationUs>0) | SIMULATED | 正常 EOF 退出 |
| P1.7-NEG | P1.7 | TestParse_TruncatedRecordMidStream | 写 pcap 全局头+1 条完整记录+第 2 条仅 8 字节截断 | err 含 "read packet at offset"; analysis==nil | SIMULATED | 手写截断 pcap 字节 |
| P1.8-BR1 | P1.8 | TestParse_NonFirstFragUnknownGroup | 仅 1 条非首分片(IP frag offset>0, 无前置首分片) | 产出 1 个 `raw\|<offset>` 合成流; 该包 FragGroupID 非空; 无 TCP/UDP 流被创建 | SIMULATED | fragFlowMap 查询失败回落 raw |
| P1.9-POS | P1.9 | TestParse_NonFirstFragJoinsFlow | 首分片(offset0,MF=1) + 非首分片(offset>0,MF=0) 同组 | 两包归入同一流(该流 PacketCount==2); 重组完成 | SIMULATED | fragFlowMap 命中 |
| P1.10-BR1 | P1.10 | TestParse_UnknownL2RawFlow | 1 帧 STP/LLDP(EtherType=0x0806 以外的非 IP/ARP) | 1 个 `raw\|<offset>` 流; FlowModel.L4Protocol==""; 包被索引(PacketCount==1) | SIMULATED | L2-only 合成流 |
| P1.11-POS | P1.11 | TestParse_FirstFragSeedsFragFlowMap | 首分片(TCP,offset0,MF=1)+非首分片(offset>0,MF=0) | 非首分片加入首分片所在 TCP 流(非 raw); FlowModel.L4Protocol=="tcp" | SIMULATED | 与 P1.9 互证 seeding |
| P1.12-BR1 | P1.12 | TestParse_FirstFragRawKeyNotSeeded | 首分片但 L3 proto 非 TCP/UDP(如 ICMP)→l4Proto=""→key raw | fragFlowMap 未被播种; 两分片各成 raw 流(2 个 raw 流) | SIMULATED | `strings.HasPrefix(key,"raw\|")` 跳过 seeding |
| P1.13-POS | P1.13 | TestParse_NewFlowCreation | 1 帧 TCP SYN(10.0.0.1:1234→10.0.0.2:80) | FlowCount==1; FlowKey=="6\|10.0.0.1:1234\|10.0.0.2:80"; SrcIP/DstIP/SrcPort/DstPort 字段正确; OffsetLayout 非空 JSON 含 l2_start/l3_start | SIMULATED | 新建 FlowState |
| P1.14-POS | P1.14 | TestParse_ExistingFlowContinues | 同 5-tuple 两包(SYN+ACK) | FlowCount==1; 该流 PacketCount==2 | SIMULATED | 复用现有 FlowState |
| P1.15-POS | P1.15 | TestParse_TCPNonFragStatsRecorded | SYN+SYN-ACK+ACK 三次握手 pcap | HandshakeStatus=="complete"; FlagsSummary 含 "syn","ack" | SIMULATED | recordTCPStats 被调用 |
| P1.16-BR1 | P1.16 | TestParse_FragTCPSkipsStats | 全分片 TCP 数据(无握手),首包即分片 | TCP 流被创建; RetransCount==0; HandshakeStatus=="none"; FlagsSummary 不含 syn; 但 C2SLength>0(重组后入流) | SIMULATED | `fragGroupID!=""` 跳过 recordTCPStats |
| P1.17-POS | P1.17 | TestParse_FragReassemblyAttempted | 2 分片 UDP 重组 | 1 个 UDP 流; PacketCount==2; 首分片端口被采到 | SIMULATED | AddFragment 被调用 |
| P1.18-POS | P1.18 | TestParse_FragReassemblyComplete | 2 分片 TCP(首+尾)无握手 | 重组后 feedReassembledToAssembler 被触发; TCP 流 c2s 流含数据; C2SLength>0 | SIMULATED | reassembled!=nil 分支 |
| P1.19-BR1 | P1.19 | TestParse_FragReassemblyIncomplete | 仅首分片(MF=1)无尾分片 | 无重组完成; 流仍存在; Parse 不报错; Flush 丢弃该组 | SIMULATED | reassembled==nil |
| P1.20-POS | P1.20 | TestParse_NonFragTCPAssembled | SYN+SYN-ACK+ACK+data+FIN | c2sStream 非空; C2SLength==len(data); ReassemblyComplete==true | SIMULATED | asm.assemble 路径 |
| P1.21-BR1 | P1.21 | TestParse_TCPNoTCPLayerDefensive | 构造 IP proto=TCP 但 TCP 头截断的畸形帧(gopacket 不产 TCP layer) | 不 panic; 不进入 assembler; (l4Proto 实际为"" → 归 raw) | SIMULATED | 防御分支,记录行为 |
| P1.22-BR1 | P1.22 | TestParse_TCPNoNetworkLayerDefensive | 构造无 IP 层的帧 | 不 panic; nl==nil 跳过 assemble | SIMULATED | 防御分支 |
| P1.23-POS | P1.23 | TestParse_UDPPayloadTrigramIndexed | 1 帧 UDP payload="MAGICPAYLOAD" | analysis.Trigram.Search("MAGIC") 返回≥1 条且 FlowID==该 UDP 流 ID; Dir=="c2s"或"s2c" | SIMULATED | UDP payload 入 trigram |
| P1.24-BR1 | P1.24 | TestParse_UDPNoPayloadSkipped | 1 帧 UDP 空 payload | Trigram.SegmentCount==0; L7Protocol==""; 流存在 | SIMULATED | `len(payload)==0` 跳过 |
| P1.25-POS | P1.25 | TestParse_UDPL7FirstPacket | UDP→53 DNS query pcap | L7Protocol=="dns"; L7QueryName==查询域名; l7Parsed 仅一次 | SIMULATED | 首包 L7 解析 |
| P1.26-BR1 | P1.26 | TestParse_UDPL7ParsedOnce | 同 UDP/DNS 流 2 包都有 payload | L7QueryName 来自首包; 第二包不重解析(观察:L7Metadata 不被覆盖为空) | SIMULATED | `l7Parsed==true` 跳过 |
| P1.27-NEG | P1.27 | TestParse_UDPL7NoMatch | UDP→随机高端口 + 随机 payload | L7Protocol==""; l7Parsed 保持 false | SIMULATED | ParseStream 返回 nil |
| P1.28-POS | P1.28 | TestParse_PacketByteCountGlobal | 3 帧 pcap(已知长度) | PacketCount==3; ByteCount==ΣcapturedLen | SIMULATED | 全局计数 |
| P1.29-POS | P1.29 | TestParse_ProtocolDistUpdate | 1 TCP+1 UDP+1 ICMP+1 ARP pcap | ProtocolDist["tcp"]==1,["udp"]==1,["icmp"]==1,["arp"]==1; ProtocolDistJSON 含四者 | SIMULATED | `l4Proto!=""` |
| P1.30-BR1 | P1.30 | TestParse_ProtocolDistSkipsEmptyL4 | 1 帧纯 L2(STP) | ProtocolDist 无 tcp/udp/icmp/arp 键; PacketCount==1 | SIMULATED | `l4Proto==""` 跳过 |
| P1.31-POS | P1.31 | TestParse_FirstTsUsFirstPacket | 2 帧 ts=100us,200us | analysis.FirstTsUs==100; LastTsUs==200 | SIMULATED | PacketCount==1 信号 |
| P1.32-BR1 | P1.32 | TestParse_FirstTsUsEarlierLater | 2 帧 ts=200us,100us(乱序时间戳) | FirstTsUs==100(被更晚到达的更早 ts 更新); LastTsUs==200 | SIMULATED | 验证 ts=0 不是哨兵的注释意图 |
| P1.33-POS | P1.33 | TestParse_LastTsUsUpdate | 3 帧 ts=50,10,90 | LastTsUs==90 | SIMULATED | max 更新 |
| P1.34-POS | P1.34 | TestParse_BatchDrainMidStream | 1 TCP 流 3 包 + `BatchSize=2` + PacketSink 计数 | sink 至少收到 1 批(2 包)在 finalize 前; analysis.Packets 为空(sink 消费) | SIMULATED | `pendingPacketCount()>=batchSize` |
| P1.35-NEG | P1.35 | TestParse_PacketSinkErrorFails | `BatchSize=1` + 2 包 + PacketSink 返回 err | Parse 返回 err; analysis==nil | SIMULATED | sink 失败传播 |
| P1.36-POS | P1.36 | TestParse_PacketSinkSuccess | sink 不报错 + 多包 | Parse err==nil; sink 收到总包数==PacketCount | SIMULATED | 与 P1.35 对照 |
| P1.37-POS | P1.37 | TestParse_PacketSinkReceivesBatches | PacketSink 累计所有批次 | Σsink 批次包数==PacketCount; analysis.Packets 为空 | SIMULATED | `PacketSink!=nil` |
| P1.38-BR1 | P1.38 | TestParse_NoSinkPacketsRetained | 不设 PacketSink + 3 包 | analysis.Packets 长度==3; 含全部 RawOffset | SIMULATED | `PacketSink==nil` append |
| P1.39-POS | P1.39 | TestForwardPackets_EmptyBatch | 直接调 `forwardPackets(opts, analysis, nil)` | 返回 nil; analysis.Packets 长度不变 | REAL | `len(batch)==0` 早返 |
| P1.40-POS | P1.40 | TestParse_FlowSinkReceives | FlowSink 累计 + 2 流 | sink 收到 2 个 FlowModel; analysis.Flows 为空 | SIMULATED | `FlowSink!=nil` |
| P1.41-BR1 | P1.41 | TestParse_NoFlowSinkFlowsRetained | 不设 FlowSink + 2 流 | analysis.Flows 长度==2 | SIMULATED | `FlowSink==nil` append |
| P1.42-POS | P1.42 | TestParse_FlushStaleIPFragments | 仅 1 个不完整分片组(首分片 MF=1) | Parse 不报错; 该组分片被 Flush 丢弃(无可重组流); 不 panic | SIMULATED | `fragReassembler.Flush()` |
| P1.43-POS | P1.43 | TestParse_FlushAssemblerNoFIN | TCP 数据流无 FIN/RST | ReassemblyComplete==true(flushAll 强制完成); C2SLength>0 | SIMULATED | `asm.flushAll()` |
| P1.44-POS | P1.44 | TestParse_FlowsSortedDeterministically | 3 流 FirstTsUs=300,100,200 | analysis.Flows 按 FirstTsUs 升序[100,200,300]; 重复运行顺序一致 | SIMULATED | sortFlowStates |
| P1.45-POS | P1.45 | TestParse_C2SStreamFlushedWithData | TCP→80 "GET / HTTP/1.1\r\nHost: x\r\n\r\n" | trigram 含 c2s segment; L7Protocol=="http"; C2SLength>0 | SIMULATED | c2s flush |
| P1.46-BR1 | P1.46 | TestParse_C2SStreamEmpty | TCP 纯 ACK(无 c2s payload) | 无 c2s trigram segment; C2SLength==0 | SIMULATED | `len(buf)==0` |
| P1.47-BR1 | P1.47 | TestParse_C2SStreamNil | 仅 s2c 方向有数据(SYN-ACK 起始捕获) | c2sStream==nil; 不索引 c2s; 仅 s2c 有 segment | SIMULATED | `c2sStream==nil` |
| P1.48-POS | P1.48 | TestParse_TCPL7C2SSuccess | TCP→80 GET 请求流 | L7Protocol=="http"; L7Method=="GET"; L7Host=="x"; C2SBodyOffset>0 | SIMULATED | c2s L7 命中 |
| P1.49-BR1 | P1.49 | TestParse_TCPL7C2SNoMatch | TCP→80 加密/随机字节流 | L7Protocol==""; L7Method=="" | SIMULATED | res==nil |
| P1.50-POS | P1.50 | TestParse_S2CStreamFlushed | TCP s2c="HTTP/1.1 200 OK\r\n..." | s2c trigram segment 存在; L7Protocol=="http"; S2CLength>0 | SIMULATED | s2c flush |
| P1.51-POS | P1.51 | TestParse_FinalizeForwardsRemaining | `BatchSize=100` + 3 包 + 无 sink | analysis.Packets 长度==3(finalize 时 drain 剩余) | SIMULATED | `fs.finalize()` rem |
| P1.52-NEG | P1.52 | TestParse_FinalizePacketSinkError | `BatchSize=100`+3 包+PacketSink 返回 err | Parse 返回 err(finalize 阶段 forwardPackets 失败) | SIMULATED | finalize sink 失败 |
| P1.53-NEG | P1.53 | TestParse_FinalizeFlowSinkError | FlowSink 返回 err | Parse 返回 err(forwardFlow 失败) | SIMULATED | finalize flow sink 失败 |
| P1.54-POS | P1.54 | TestParse_TrigramPersistSuccess | UDP pcap + `TrigramIndexPath=temp.trigram` | 文件存在; LoadFromFile 成功; loaded.Search("payload") 命中; TrigramWriteError==nil | SIMULATED | 复用 TestAuditFix_TrigramDiskFile |
| P1.55-BR1 | P1.55 | TestParse_TrigramPersistFailureNonFatal | 有效 pcap + `TrigramIndexPath="/no/dir/x.trigram"` | Parse err==nil(非致命); analysis.TrigramWriteError!=nil; 内存 Trigram 仍可 Search 命中 | SIMULATED | 写盘失败回退内存 |
| P1.56-BR1 | P1.56 | TestParse_TrigramNoPath | 不设 TrigramIndexPath | 无 .trigram 文件; analysis.Trigram 非 nil(内存) | SIMULATED | `TrigramIndexPath==""` |
| P1.57-BR1 | P1.57 | TestParse_TrigramNilIndexDefensive | (构造 analysis.Trigram=nil 路径不可达,验证条件不进) | 备注说明:Trigram 在 Parse 内必非 nil,分支不可达 | REAL | 防御分支,记录不可达 |
| P2.1-NEG | P2.1 | TestOpenPcapReader_TooSmall | 3 字节文件 | err 含 "file too small to be a pcap: 3 bytes" | SIMULATED | 包内测试 unexported |
| P2.2-NEG | P2.2 | TestOpenPcapReader_SeekFails | `os.Pipe()` 写 4 字节(不可 Seek) | err 含 "seek pcap start" | SIMULATED | 非可 seek 文件 |
| P2.3-NEG | P2.3 | TestOpenPcapReader_GzipRejected | 文件头 0x1f 0x8b + 填充 | err 含 "gzipped pcap not supported" | SIMULATED | gzip magic |
| P2.4-NEG | P2.4 | TestOpenPcapReader_PcapngLE | 文件头 0x0A 0x0D 0x0D 0x0A | err 含 "pcapng not supported" | SIMULATED | pcapng LE |
| P2.5-NEG | P2.5 | TestOpenPcapReader_PcapngBE | 文件头 0x0D 0x0A 0x0A 0x0D | err 含 "pcapng not supported" | SIMULATED | pcapng BE |
| P2.6-NEG | P2.6 | TestOpenPcapReader_BadMagic | 0xDE 0xAD 0xBE 0xEF + 20 字节填充 | err 含 "parse pcap header" | SIMULATED | pcapgo.NewReader 失败 |
| P2.7-POS | P2.7 | TestOpenPcapReader_LowSnaplenRaised | `WriteFileHeader(1500, Ethernet)` pcap | 返回 snaplen==65535(被抬高) | SIMULATED | `Snaplen()<65535` |
| P2.8-BR1 | P2.8 | TestOpenPcapReader_HighSnaplenPreserved | `WriteFileHeader(65535, Ethernet)` pcap | 返回 snaplen==65535(未改) | SIMULATED | `Snaplen()>=65535` |
| P2.9-POS | P2.9 | TestOpenPcapReader_Success | 正常 1 帧 pcap | 返回 reader 非 nil; linkType==Ethernet; snaplen==65535; err==nil | SIMULATED | 与 P1.6 互证 |
| P3.1-POS | P3.1 | TestOptions_BatchSizeDefault | `(*Options)(nil)`, `&Options{}`, `BatchSize:0`, `BatchSize:-1` | 全部返回 1000 | REAL | nil/零/负 |
| P3.2-POS | P3.2 | TestOptions_BatchSizeCustom | `&Options{BatchSize:50}` | 返回 50 | REAL | 正值 |
| P4.1-POS | P4.1 | TestSortFlowStates_Empty | 空 map | 返回长度 0 切片 | REAL | |
| P4.2-POS | P4.2 | TestSortFlowStates_Single | 1 个 FlowState | 长度 1 | REAL | |
| P4.3-BR1 | P4.3 | TestSortFlowStates_TiebreakByID | 2 流 FirstTsUs 相同, ID "b","a" | 顺序 [a,b](ID 升序) | REAL | 时间戳相等回退 ID |
| P4.4-POS | P4.4 | TestSortFlowStates_ByTimestamp | 2 流 FirstTsUs=200,100 | 顺序 [100,200] | REAL | 时间戳升序 |
| P5.1-BR1 | P5.1 | TestFeedReassembled_NonTCP | 直接调 feedReassembledToAssembler,重组 UDP 帧 | flows map 不变(早返); 无新流 | REAL | `l4Proto!="tcp"` |
| P5.2-BR1 | P5.2 | TestFeedReassembled_NoNetworkLayer | 构造无 IP 层重组帧 | 早返; 无新流 | REAL | 防御 |
| P5.3-BR1 | P5.3 | TestFeedReassembled_EmptyKey | 重组帧 L3 未知→computeFlowKey="" | 早返; 无新流 | REAL | `key==""` |
| P5.4-POS | P5.4 | TestParse_FullyFragmentedFirstPacketIsFrag | **PCAP 首包即 TCP 分片**(无握手,首帧=首分片 offset0 MF=1,次帧=尾分片) | TCP 流被创建; c2s 流含重组后 payload "Hello Fragmented Only"; C2SLength>0 | SIMULATED | **首包即分片**关键测试;复用 TestAuditFix_FullyFragmentedTCP |
| P5.5-POS | P5.5 | TestParse_FragJoinsExistingFlow | 非分片 SYN 先建流,随后分片数据 | 分片归入已存在流; 总流数==1 | SIMULATED | `ok==true` |
| P5.6-BR1 | P5.6 | TestFeedReassembled_NoTCPLayerDefensive | 构造 l4Proto="tcp" 但无 TCP layer 的重组帧 | 早返; 不调用 assemble | REAL | 防御 |
| P5.7-POS | P5.7 | TestFeedReassembled_TCPFedToAssembler | 重组 TCP 帧含 TCP layer | asm.assemble 被调用(c2s 流产生数据) | SIMULATED | 与 P5.4 互证 |
| P6.1-POS | P6.1 | TestProtocolDistJSON_Marshal | `ProtocolDist{"tcp":2,"udp":1}` | JSON 反序列化回 map 值相等 | REAL | |
| P6.2-NEG | P6.2 | TestProtocolDistJSON_Empty | 空 map | 返回 "{}" | REAL | 空 map 序列化 |
| P-MAN1 | P1(real capture) | TestManual_RealCaptureParse | 真实 NIC 抓包文件 | 见 MANUAL 说明 | MANUAL | 真实抓包文件解析 |
| P-MAN2 | P1(huge file) | TestManual_HugePcapBoundedMemory | 多 GB pcap + PacketSink | 见 MANUAL 说明 | MANUAL | 超大文件内存 |

---

## 组件: flow.go — 流键/FlowState/recordTCPStats/formatTCPOptions/flushStreams/finalize/extractFields/computeFlowKey/payloadHash/detectAnomaly

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| F1.1-POS | F1.1 | TestCompareEndpoints_IPDiffer | a.IP="1.1.1.1", b.IP="2.2.2.2" | 返回 strings.Compare 结果(-1 或 1) | REAL | |
| F1.2-POS | F1.2 | TestCompareEndpoints_PortLess | 同 IP, a.Port=10,b.Port=20 | 返回 -1 | REAL | |
| F1.3-POS | F1.3 | TestCompareEndpoints_PortGreater | 同 IP, a.Port=20,b.Port=10 | 返回 1 | REAL | |
| F1.4-POS | F1.4 | TestCompareEndpoints_Equal | 同 IP 同 port | 返回 0 | REAL | |
| F2.1-POS | F2.1 | TestFlowKeyTCPUDP_NormalOrder | ipA:1234→ipB:80 proto=6 | key=="6\|10.0.0.1:1234\|10.0.0.2:80" | REAL | a<=b |
| F2.2-POS | F2.2 | TestFlowKeyTCPUDP_ReversedOrder | ipB:80→ipA:1234 proto=6 | key 与 F2.1 相同(归一化交换) | REAL | a>b 交换 |
| F3.1-POS | F3.1 | TestFlowKeyICMP_NormalOrder | srcIP<=dstIP,type=8,id=1 | key=="1\|<min>\|<max>\|8\|1" | REAL | |
| F3.2-POS | F3.2 | TestFlowKeyICMP_ReversedOrder | srcIP>dstIP | IP 交换归一; type/id 不变 | REAL | |
| F4.1-POS | F4.1 | TestFlowKeyARP_NormalOrder | senderIP<=targetIP,op=1 | key=="arp\|1\|<min>\|<max>" | REAL | |
| F4.2-POS | F4.2 | TestFlowKeyARP_ReversedOrder | senderIP>targetIP | IP 交换归一 | REAL | |
| F5.1-POS | F5.1 | TestClassifyDirection_ClientSrc | src==firstSrcIP&&port==firstSrcPort | 返回 "c2s" | REAL | |
| F5.2-POS | F5.2 | TestClassifyDirection_OtherSrc | src!=firstSrc | 返回 "s2c" | REAL | |
| F6.1-POS | F6.1 | TestAddPacket_C2SCounts | pkt.Direction="c2s", Length=100 | C2SPackets==1; C2SBytes==100; PacketCount==1 | REAL | 直接构造 FlowState |
| F6.2-POS | F6.2 | TestAddPacket_S2CCounts | pkt.Direction="s2c" | S2CPackets==1; S2CBytes==100 | REAL | |
| F6.3-BR1 | F6.3 | TestAddPacket_FirstTsUsDecreases | FirstTsUs 初值=200, 入包 ts=100 | FirstTsUs 更新为 100 | REAL | 乱序时间戳 |
| F6.4-POS | F6.4 | TestAddPacket_LastTsUsIncreases | ts=300 > LastTsUs=100 | LastTsUs==300 | REAL | |
| F6.5-BR1 | F6.5 | TestAddPacket_TsInRange | ts 在 [First,Last] 之间 | First/Last 不变 | REAL | |
| F7.1-POS | F7.1 | TestDrainPackets_NonEmpty | packets=[p1,p2] | 返回 [p1,p2]; 之后 fs.packets==nil | REAL | |
| F7.2-BR1 | F7.2 | TestDrainPackets_Empty | packets=nil | 返回 nil | REAL | |
| F8.1-NEG | F8.1 | TestSetL7_NilResultNoop | res=nil | L7Protocol 不变(空) | REAL | |
| F8.2-POS | F8.2 | TestSetL7_ProtocolSet | res.Protocol="http" | FlowModel.L7Protocol=="http" | REAL | |
| F8.3-POS | F8.3 | TestSetL7_MetadataMarshal | res.Metadata={"status":"200"} | L7Metadata==`{"status":"200"}` | REAL | |
| F8.4-BR1 | F8.4 | TestSetL7_MetadataMarshalFail | res.Metadata 含不可序列化值(如 chan) | L7Metadata 保持空 | REAL | 构造 map[string]any{"x":make(chan int)} |
| F8.5-POS | F8.5 | TestSetL7_MethodSet | Metadata["method"]="GET" | L7Method=="GET" | REAL | |
| F8.6-POS | F8.6 | TestSetL7_HostSet | Metadata["host"]="x.com" | L7Host=="x.com" | REAL | |
| F8.7-POS | F8.7 | TestSetL7_SNIOverridesHost | Metadata 同时有 host 和 sni | L7Host==sni(覆盖 host) | REAL | TLS SNI 覆盖 |
| F8.8-POS | F8.8 | TestSetL7_QueryNameSet | Metadata["query_name"]="a.com" | L7QueryName=="a.com" | REAL | DNS |
| F8.9-POS | F8.9 | TestSetL7_C2SBodyOffsets | dir="c2s", BodyOffset=4,BodyLength=10 | C2SBodyOffset==4; C2SBodyLength==10 | REAL | |
| F8.10-POS | F8.10 | TestSetL7_S2CBodyOffsets | dir="s2c" | S2CBodyOffset/S2CBodyLength 设值 | REAL | |
| F8.11-BR1 | F8.11 | TestSetL7_UnknownDirNoOffset | dir="xyz" | Body offsets 不被设置 | REAL | 既非 c2s 也非 s2c |
| F9.1-POS | F9.1 | TestSetStream_C2S | dir="c2s", s=&reassemblyStream{} | fs.c2sStream==s | REAL | |
| F9.2-POS | F9.2 | TestSetStream_S2C | dir="s2c"(或任意非 c2s) | fs.s2cStream==s | REAL | |
| F10.1-POS | F10.1 | TestSeqLess_NormalLess | a=100,b=200 | true | REAL | |
| F10.2-POS | F10.2 | TestSeqLess_NormalGreater | a=200,b=100 | false | REAL | |
| F10.3-POS | F10.3 | TestSeqLess_Wraparound | a=4294967200,b=100 | true(int32 回绕) | REAL | |
| F10.4-POS | F10.4 | TestSeqLess_WraparoundReverse | a=100,b=4294967200 | false | REAL | |
| F11.1-POS | F11.1 | TestSeqInRange_InRange | a=150,min=100,max=200 | true | REAL | |
| F11.2-NEG | F11.2 | TestSeqInRange_BelowMin | a=50,min=100 | false | REAL | |
| F11.3-NEG | F11.3 | TestSeqInRange_AboveMax | a=250,max=200 | false | REAL | |
| F12.0-POS | F12.1 | TestRecordTCPStats_FlagsCountInit | 首次调 recordTCPStats | flagsCount 非 nil(经 finalize 后 FlagsSummary 非空) | REAL | 初始化 map |
| F12.2-POS | F12.2 | TestRecordTCPStats_SYNNoACK | tcpSYN=true,tcpACK=false,seq=100 | sawSYN==true; C2SInitSeq==100; finalize FlagsSummary 含 "syn" | REAL | 客户端 SYN |
| F12.3-POS | F12.3 | TestRecordTCPStats_SYNACK | tcpSYN&&tcpACK,seq=200 | sawSYNACK==true; S2CInitSeq==200 | REAL | 服务端 SYN-ACK |
| F12.4-POS | F12.4 | TestRecordTCPStats_OptionsRecordedFirstSYN | 首个 SYN 带 MSS=1460,WS=7,SACK,kinds=[2,3,4] | MSS==1460; WindowScale==7; TCPOptions=="[2,3,4]" | REAL | **TCP 统计非零**关键 |
| F12.5-BR1 | F12.5 | TestRecordTCPStats_OptionsNotReRecorded | 第二个 SYN 带 MSS=999 | MSS 仍==1460(不覆盖); tcpOptionsRecorded==true | REAL | 仅记一次 |
| F12.6-POS | F12.6 | TestRecordTCPStats_ACKAfterSYNACK | sawSYNACK 后 ACK 包 | sawACKAfterSYN==true; finalize HandshakeStatus=="complete" | REAL | 第三步握手 |
| F12.7-BR1 | F12.7 | TestRecordTCPStats_ACKBeforeSYNACK | ACK 但未 sawSYNACK | sawACKAfterSYN 保持 false; flagsCount["ack"] 仍++ | REAL | 早 ACK |
| F12.8-POS | F12.8 | TestRecordTCPStats_ACKFlagCount | tcpACK=true | finalize FlagsSummary 含 "ack" 计数 | REAL | |
| F12.9-POS | F12.9 | TestRecordTCPStats_FINFlagCount | tcpFIN=true | FlagsSummary 含 "fin" | REAL | |
| F12.10-POS | F12.10 | TestRecordTCPStats_RSTFlagCount | tcpRST=true | FlagsSummary 含 "rst" | REAL | |
| F12.11-POS | F12.11 | TestRecordTCPStats_PSHFlagCount | tcpPSH=true | FlagsSummary 含 "psh" | REAL | |
| F12.12-POS | F12.12 | TestRecordTCPStats_SeqMin | 第二包 seq 小于首包 | seqMin==较小值; finalize SeqRange[0]==较小值 | REAL | seq<min 分支 |
| F12.13-POS | F12.13 | TestRecordTCPStats_SeqMax | 第二包 seq 大于首包 | seqMax==较大值; SeqRange[1]==较大值 | REAL | seq>max 分支 |
| F12.14-POS | F12.14 | TestRecordTCPStats_SeqSeenSet | 任意 TCP 包后 | SeqRange 非空(observable seqSeen 后果) | REAL | 折入 F12.12/13 可观测 |
| F12.15-POS | F12.15 | TestRecordTCPStats_C2SRetransOOO | dir="c2s" | 用 c2sNextSeq/c2sSeqSeen 跟踪 | REAL | c2s 方向 |
| F12.16-POS | F12.16 | TestRecordTCPStats_S2CRetransOOO | dir="s2c" | 用 s2cNextSeq/s2cSeqSeen | REAL | s2c 方向 |
| F12.17-POS | F12.17 | TestRecordTCPStats_FirstInDir | 方向首包 seq=100,payload=10 | nextSeq==110; seen==true | REAL | `!*seen` |
| F12.18-POS | F12.18 | TestRecordTCPStats_RetransDetected | 首包 seq=100,len=10; 次包 seq=95(<110) | RetransCount==1 | REAL | **重传检测** |
| F12.19-POS | F12.19 | TestRecordTCPStats_OutOfOrderDetected | 首包 seq=100,len=10; 次包 seq=200(>110) | OutOfOrderCount==1; nextSeq 更新为 200+len | REAL | **乱序检测** |
| F12.20-POS | F12.20 | TestRecordTCPStats_InOrderDelivery | 次包 seq==nextSeq | RetransCount==0; OutOfOrderCount==0; nextSeq 前进 | REAL | seq==next |
| F12.21-POS | F12.21 | TestRecordTCPStats_WindowMin | window=512 < 之前 | winMin==512; finalize WindowRange[0]==512 | REAL | |
| F12.22-POS | F12.22 | TestRecordTCPStats_WindowMax | window=8192 > 之前 | winMax==8192; WindowRange[1]==8192 | REAL | |
| F12.23-POS | F12.23 | TestRecordTCPStats_WindowSeenSet | 任意 TCP 包 | WindowRange 非空 | REAL | winSeen 后果 |
| F12-INTG-POS | F12(端到端) | TestParse_TCPStatsNonZero_Integration | **PCAP: SYN(MSS=1460,WS=7,SACK)+SYN-ACK+ACK+data(window=8192)+重传(同 seq)+乱序(跳 seq)** | MSS==1460; WindowScale==7; TCPOptions 非空含 2,3,4; RetransCount>=1; OutOfOrderCount>=1; WindowRange 非空且含 8192; FlagsSummary 非空 | SIMULATED | **TCP 统计非零核心集成测试**:6 字段全断言非零;含重传+乱序;复用/扩展 TestAuditFix_TCPStatsPopulated |
| F13.1-POS | F13.1 | TestFormatTCPOptions_Empty | nil | "[]" | REAL | |
| F13.2-POS | F13.2 | TestFormatTCPOptions_Single | [2] | "[2]" | REAL | |
| F13.3-POS | F13.3 | TestFormatTCPOptions_Multiple | [2,3,4] | "[2,3,4]" | REAL | |
| F13.4-POS | F13.4 | TestFormatTCPOptions_Dedup | [2,2,3] | "[2,3]" | REAL | 去重保序 |
| F14.1-BR1 | F14.1 | TestFlushStreams_NonTCP | L4Protocol="udp" 的 FlowState | 直接 return; StreamFile 不变 | REAL | 非 TCP |
| F14.2-POS | F14.2 | TestFlushStreams_C2SAppendOK | TCP 流,c2sStream 有数据,payloadsWriter=temp 文件 | C2SOffset==0; C2SLength==len(buf); ReassemblyComplete==true | REAL | appendStream 成功 |
| F14.3-NEG | F14.3 | TestFlushStreams_C2SAppendFail | payloadsWriter 用已关闭文件 | appendStream 错误早返; C2SOffset 不设; s2c 被跳过 | REAL | 写错误 |
| F14.4-BR1 | F14.4 | TestFlushStreams_C2SNil | c2sStream==nil | 跳过 c2s; 不 panic | REAL | |
| F14.5-POS | F14.5 | TestFlushStreams_S2CAppendOK | s2cStream 有数据 | S2COffset/S2CLength 设值 | REAL | |
| F14.6-NEG | F14.6 | TestFlushStreams_S2CAppendFail | s2c 写失败 | 早返; s2cGap 保持 false | REAL | |
| F14.7-POS | F14.7 | TestFlushStreams_NoGaps | 两流无 gapDetected | ReassemblyComplete==true; GapInfo=="" | REAL | |
| F14.8-BR1 | F14.8 | TestFlushStreams_GapC2SOnly | c2sStream.gapDetected=true | ReassemblyComplete==false; GapInfo=="seq gap in c2s" | REAL | |
| F14.9-BR1 | F14.9 | TestFlushStreams_GapS2COnly | s2cStream.gapDetected=true | GapInfo=="seq gap in s2c" | REAL | |
| F14.10-BR1 | F14.10 | TestFlushStreams_GapBoth | 两方向都 gap | GapInfo=="seq gap in c2s, s2c" | REAL | |
| F15.1-POS | F15.1 | TestFinalize_DurationUs | FirstTsUs=100,LastTsUs=500 | DurationUs==400 | REAL | |
| F15.2-POS | F15.2 | TestFinalize_OffsetLayoutMarshal | layout 含字段 | OffsetLayout 非空 JSON 含 l3_start 等 | REAL | |
| F15.3-BR1 | F15.3 | TestFinalize_OffsetLayoutMarshalFail | (layout 正常不可失败;覆盖 default "{}" 难达) | 备注说明:OffsetLayout 字段均可序列化,失败分支不可达 | REAL | 防御 |
| F15.4-POS | F15.4 | TestFinalize_TCPStatsCalled | TCP 流 | HandshakeStatus 非空 | REAL | finalizeTCPStats 被调 |
| F15.5-POS | F15.5 | TestFinalize_DrainsRemaining | packets=[p1] 未 drain | 返回 rem=[p1]; 之后 packets 空 | REAL | |
| F16.1-BR1 | F16.1 | TestFinalizeTCPStats_NonTCP | L4Protocol="udp" | 直接 return; HandshakeStatus=="" | REAL | |
| F16.2-POS | F16.2 | TestFinalizeTCPStats_CompleteHandshake | sawSYN&&sawSYNACK&&sawACKAfterSYN | HandshakeStatus=="complete" | REAL | |
| F16.3-POS | F16.3 | TestFinalizeTCPStats_PartialHandshake | 仅 sawSYN(无 SYN-ACK/ACK) | HandshakeStatus=="partial" | REAL | 覆盖 SYN-only / SYN-ACK-only / 无 ACK |
| F16.4-POS | F16.4 | TestFinalizeTCPStats_NoHandshake | 无 SYN 无 SYN-ACK(中途捕获纯数据) | HandshakeStatus=="none" | REAL | |
| F16.5-POS | F16.5 | TestFinalizeTCPStats_FlagsSummaryMarshal | flagsCount={"syn":1,"ack":2} | FlagsSummary==`{"ack":2,"syn":1}`(或等价 map) | REAL | |
| F16.6-BR1 | F16.6 | TestFinalizeTCPStats_FlagsCountNil | flagsCount==nil(无 TCP 标志包) | FlagsSummary=="" | REAL | |
| F16.7-POS | F16.7 | TestFinalizeTCPStats_SeqRangeMarshal | seqSeen=true,seqMin=100,seqMax=200 | SeqRange=="[100,200]" | REAL | |
| F16.8-BR1 | F16.8 | TestFinalizeTCPStats_NoSeqSeen | seqSeen==false | SeqRange=="" | REAL | |
| F16.9-POS | F16.9 | TestFinalizeTCPStats_WindowRangeMarshal | winSeen=true,winMin=512,winMax=8192 | WindowRange 非空且含 512,8192 | REAL | **WindowRange 非零** |
| F16.10-BR1 | F16.10 | TestFinalizeTCPStats_NoWindowSeen | winSeen==false | WindowRange=="" | REAL | |
| F17.1-POS | F17.1 | TestExtractFields_IPv4 | Eth/IPv4/TCP gopacket 包 | srcIP/dstIP==ipA/ipB; ipVersion==4; ipID 正确 | REAL | 构造包字节 |
| F17.2-POS | F17.2 | TestExtractFields_IPv4Fragmented | IPv4 MF=1,FragOffset=0 | fragGroupID=="<id>\|src\|dst\|6"; fragOffset==0; fragFirst==true; l4Proto=="tcp" | REAL | |
| F17.3-BR1 | F17.3 | TestExtractFields_IPv4NonFragmented | IPv4 MF=0,FragOffset=0 | fragGroupID==""; fragFirst==false | REAL | |
| F17.4-POS | F17.4 | TestExtractFields_FragL4RecoveryTCP | 分片 IPv4 Protocol=TCP | l4Proto=="tcp" | REAL | |
| F17.5-POS | F17.5 | TestExtractFields_FragL4RecoveryUDP | 分片 IPv4 Protocol=UDP | l4Proto=="udp" | REAL | |
| F17.6-BR1 | F17.6 | TestExtractFields_FragL4Unknown | 分片 IPv4 Protocol=ICMP | l4Proto==""(将得 raw key) | REAL | |
| F17.7-POS | F17.7 | TestExtractFields_FirstFragPortsExtracted | 首分片 payload>=4 字节(含 TCP 端口) | srcPort/dstPort 从 payload 前 4 字节解析正确 | REAL | |
| F17.8-BR1 | F17.8 | TestExtractFields_FirstFragPortsTooShort | 首分片 payload<4 字节 | srcPort/dstPort==0(将得 raw key) | REAL | |
| F17.9-POS | F17.9 | TestExtractFields_IPv6 | Eth/IPv6/UDP 包 | ipVersion==6; srcIP/dstIP 正确 | REAL | |
| F17.10-BR1 | F17.10 | TestExtractFields_NoNetworkLayer | 仅 Ethernet 无 IP | srcIP/dstIP==nil; ipVersion==0 | REAL | |
| F17.11-POS | F17.11 | TestExtractFields_TCP | TCP layer | l4Proto=="tcp"; 端口/seq/window/flags 正确; payload 提取 | REAL | |
| F17.12-POS | F17.12 | TestExtractFields_TCPSYNOptionsParsed | SYN 带 MSS/WS/SACK options | tcpOptionKinds==[2,3,4]; tcpMSS/tcpWindowScale/tcpSACK 设值 | REAL | **SYN options 解析** |
| F17.13-POS | F17.13 | TestExtractFields_MSSValidLen | MSS OptionData 2 字节 | tcpMSS==期望值 | REAL | |
| F17.14-BR1 | F17.14 | TestExtractFields_MSSInvalidLen | MSS OptionData 1 字节 | tcpMSS==0(跳过) | REAL | |
| F17.15-POS | F17.15 | TestExtractFields_WindowScaleValidLen | WS OptionData 1 字节 | tcpWindowScale==期望值 | REAL | |
| F17.16-BR1 | F17.16 | TestExtractFields_WindowScaleInvalidLen | WS OptionData 2 字节 | tcpWindowScale==-1(默认未改) | REAL | |
| F17.17-POS | F17.17 | TestExtractFields_SACKPermitted | kind=4 option | tcpSACK==true | REAL | |
| F17.18-BR1 | F17.18 | TestExtractFields_TCPSYNFalseNoOpts | 非 SYN 包 | tcpOptionKinds==nil | REAL | |
| F17.19-POS | F17.19 | TestExtractFields_UDP | UDP layer | l4Proto=="udp"; 端口/payload 正确 | REAL | |
| F17.20-BR1 | F17.20 | TestExtractFields_NoTransportLayer | ICMP/ARP/分片(无 transport) | 端口==0; payload 来自 ICMP/ARP 分支 | REAL | |
| F17.21-POS | F17.21 | TestExtractFields_ICMPv4 | ICMPv4 echo 包 | l4Proto=="icmp"; icmpType/icmpID 正确 | REAL | |
| F17.22-BR1 | F17.22 | TestExtractFields_ICMPv4AssertFail | (类型断言失败难构造) | 备注说明:正常解码可断言成功 | REAL | 防御 |
| F17.23-POS | F17.23 | TestExtractFields_ARP | ARP request 包 | l4Proto=="arp"; arpOp==1 | REAL | |
| F17.24-BR1 | F17.24 | TestExtractFields_ARPAssertFail | (类型断言失败难构造) | 备注说明:防御 | REAL | |
| F17.25-POS | F17.25 | TestExtractFields_ARPv4Sender | SourceProtAddress 4 字节 | arpSenderIP 正确 | REAL | |
| F17.26-BR1 | F17.26 | TestExtractFields_ARPNonIPv4Sender | SourceProtAddress 非 4 字节 | arpSenderIP==nil | REAL | |
| F17.27-POS | F17.27 | TestExtractFields_ARPv4Target | DstProtAddress 4 字节 | arpTargetIP 正确 | REAL | |
| F17.28-BR1 | F17.28 | TestExtractFields_ARPNonIPv4Target | DstProtAddress 非 4 字节 | arpTargetIP==nil | REAL | |
| F18.1-POS | F18.1 | TestComputeFlowKey_TCP | l4Proto="tcp" | 返回 flowKeyTCPUDP(...,6) | REAL | |
| F18.2-POS | F18.2 | TestComputeFlowKey_UDP | l4Proto="udp" | 返回 flowKeyTCPUDP(...,17) | REAL | |
| F18.3-POS | F18.3 | TestComputeFlowKey_ICMP | l4Proto="icmp" | 返回 flowKeyICMP | REAL | |
| F18.4-POS | F18.4 | TestComputeFlowKey_ARP | l4Proto="arp" | 返回 flowKeyARP | REAL | |
| F18.5-NEG | F18.5 | TestComputeFlowKey_Unknown | l4Proto="" | 返回 "" | REAL | |
| F19.1-POS | F19.1 | TestPayloadHash_Empty | []byte{} | 返回 "" | REAL | |
| F19.2-POS | F19.2 | TestPayloadHash_NonEmpty | []byte("abc") | 返回 hex(sha256("abc")) | REAL | 可与标准库对比 |
| F20.1-POS | F20.1 | TestDetectAnomaly_Truncated | capturedLen=60,originalLen=100 | "truncated" | REAL | |
| F20.2-POS | F20.2 | TestDetectAnomaly_Oversize | frameLen=2000 | "oversize" | REAL | |
| F20.3-POS | F20.3 | TestDetectAnomaly_Undersize | frameLen=40 | "undersize" | REAL | |
| F20.4-POS | F20.4 | TestDetectAnomaly_Normal | frameLen=100,captured==original | "" | REAL | |

---

## 组件: direction.go — updateDirection / setClient

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| D1.1-BR1 | D1.1 | TestUpdateDirection_AlreadyLocked | dirLocked=true 的 FlowState | 直接 return; DirStatus 保持 "classified" | REAL | |
| D1.2-POS | D1.2 | TestUpdateDirection_TCPSYNClient | tcpSYN&&!tcpACK,src=client | setClient 后 Client==src; DirMethod=="syn"; DirStatus=="classified"; dirLocked==true | REAL | |
| D1.3-POS | D1.3 | TestUpdateDirection_TCPSYNACKCorrects | tcpSYN&&tcpACK(SYN-ACK 起始捕获) | Client==dst(被 SYN-ACK 纠正); Server==src | REAL | 纠正首包猜测 |
| D1.4-BR1 | D1.4 | TestUpdateDirection_TCPNonHandshake | TCP 包无 SYN | DirStatus 保持 "uncertain"; dirLocked==false | REAL | |
| D1.5-POS | D1.5 | TestUpdateDirection_UDPSrcWellKnown | UDP src=53,dst=ephemeral | Client==dst; Server==src:53; DirMethod=="port" | REAL | DNS 响应 |
| D1.6-POS | D1.6 | TestUpdateDirection_UDPDstWellKnown | UDP dst=53,src=ephemeral | Client==src; Server==dst:53 | REAL | DNS 查询 |
| D1.7-BR1 | D1.7 | TestUpdateDirection_UDPBothWellKnown | UDP 两端都 53(或都非知名) | DirStatus 保持 "uncertain"; 不锁定 | REAL | 无 hint |
| D1.8-BR1 | D1.8 | TestUpdateDirection_NonTCPUDP | l4Proto="icmp" | DirStatus 保持 "uncertain" | REAL | |
| D1-INTG-POS | D1(端到端) | TestParse_DirectionSYNACKStart | PCAP 首包=SYN-ACK(捕获起自 SYN-ACK) | Client 被纠正为 SYN-ACK 的 dst; serverPort 被纠正为真实服务端口; 后续 c2s/s2c 分类正确 | SIMULATED | 集成:校准 serverPort 影响 L7 hint |

---

## 组件: reassembly.go — reassemblyStream / reassemblyFactory / netIPFromEndpoint / portFromEndpoint

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| R1.1-POS | R1.1 | TestReassemblyStream_GapDetected | Reassembly{Skip:1} | gapDetected==true | REAL | |
| R1.2-POS | R1.2 | TestReassemblyStream_NoGap | Reassembly{Skip:0,Bytes:b} | gapDetected==false; buf 含 b | REAL | |
| R1.3-BR1 | R1.3 | TestReassemblyStream_EmptySegment | Reassembly{Bytes:nil} | buf 长度不变 | REAL | |
| R1.4-POS | R1.4 | TestReassemblyStream_NonEmpty | Reassembly{Bytes:[]byte("abc")} | buf=="abc" | REAL | |
| R1.5-POS | R1.5 | TestReassemblyStream_MultipleSegments | []Reassembly{r1,r2} | buf 含两段拼接 | REAL | for 循环 |
| R2.1-POS | R2.1 | TestReassemblyStream_Complete | 调 ReassemblyComplete() | complete==true | REAL | |
| R3.1-POS | R3.1 | TestNullStream_ReassembledNoop | nullStream.Reassembled(seg) | 无 panic;无副作用 | REAL | |
| R3.2-POS | R3.2 | TestNullStream_CompleteNoop | nullStream.ReassemblyComplete() | 无 panic | REAL | |
| R4.1-BR1 | R4.1 | TestReassemblyFactory_NilIP | netFlow endpoint 非 4/16 字节 | 返回 nullStreamInstance | REAL | |
| R4.2-BR1 | R4.2 | TestReassemblyFactory_FlowNotFound | flows map 无此 key | 返回 nullStreamInstance | REAL | |
| R4.3-POS | R4.3 | TestReassemblyFactory_C2SDirection | 流存在,src==client | 返回 reassemblyStream dir="c2s"; fs.c2sStream 已设 | REAL | |
| R4.4-POS | R4.4 | TestReassemblyFactory_S2CDirection | src!=client | dir="s2c"; fs.s2cStream 已设 | REAL | |
| R5.1-POS | R5.1 | TestNetIPFromEndpoint_IPv4 | 4 字节 endpoint | 返回 4 字节 net.IP | REAL | |
| R5.2-POS | R5.2 | TestNetIPFromEndpoint_IPv6 | 16 字节 endpoint | 返回 16 字节 net.IP | REAL | |
| R5.3-NEG | R5.3 | TestNetIPFromEndpoint_NonIP | 6 字节(MAC)endpoint | 返回 nil | REAL | |
| R6.1-POS | R6.1 | TestPortFromEndpoint_Valid | 2 字节 endpoint | 返回 BigEndian.Uint16 值 | REAL | |
| R6.2-NEG | R6.2 | TestPortFromEndpoint_InvalidLen | 非 2 字节 | 返回 0 | REAL | |

---

## 组件: fragment.go — FragmentReassembler (AddFragment / tryReassemble / Flush)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| FR1.1-POS | FR1.1 | TestAddFragment_NewGroup | 首次 key | groups[key] 被创建; totalPayloadLen==-1 | REAL | 直接调,查内部 |
| FR1.2-POS | FR1.2 | TestAddFragment_ExistingGroup | 同 key 二次 | 复用 group | REAL | |
| FR1.3-NEG | FR1.3 | TestAddFragment_L3StartBeyondFrame | l3Start+4>len(frame) | 返回 nil | REAL | |
| FR1.4-NEG | FR1.4 | TestAddFragment_IHLInvalid | ihl<20 或 l3Start+ihl>len | 返回 nil | REAL | |
| FR1.5-NEG | FR1.5 | TestAddFragment_IpPayloadInvalid | ipPayloadLen<0 或超 frame | 返回 nil | REAL | |
| FR1.6-POS | FR1.6 | TestAddFragment_FirstFragStoresBase | fragOffsetBytes==0 | g.firstFrag==frame; g.l3Start 设值 | REAL | |
| FR1.7-BR1 | FR1.7 | TestAddFragment_NonFirstFrag | fragOffsetBytes>0 | firstFrag 保持 nil | REAL | |
| FR1.8-POS | FR1.8 | TestAddFragment_LastFragSetsTotal | MF=0 | totalPayloadLen==offset+len(payload) | REAL | |
| FR1.9-BR1 | FR1.9 | TestAddFragment_NotLastFrag | MF=1 | totalPayloadLen==-1 | REAL | |
| FR1.10-POS | FR1.10 | TestAddFragment_ReassembleAttemptAllMet | firstFrag+totalLen+未重组 | tryReassemble 被触发 | REAL | |
| FR1.11-BR1 | FR1.11 | TestAddFragment_ReassembleMissingFirst | 无首分片 | 不尝试重组 | REAL | |
| FR1.12-BR1 | FR1.12 | TestAddFragment_ReassembleTotalUnknown | totalPayloadLen<=0 | 不尝试 | REAL | |
| FR1.13-BR1 | FR1.13 | TestAddFragment_AlreadyReassembled | g.reassembled==true | 不重复重组 | REAL | |
| FR1.14-POS | FR1.14 | TestAddFragment_ReassembleSucceeds | 完整 2 分片 | 返回重组帧(非 nil); g.reassembled==true | REAL | |
| FR1.15-BR1 | FR1.15 | TestAddFragment_ReassembleFailsGap | 缺中间分片 | 返回 nil; reassembled 保持 false | REAL | |
| FR2.1-NEG | FR2.1 | TestTryReassemble_GapInOffsets | offsets 不连续 | 返回 nil | REAL | |
| FR2.2-NEG | FR2.2 | TestTryReassemble_MissingTail | cursor!=totalPayloadLen | 返回 nil | REAL | |
| FR2.3-POS | FR2.3 | TestTryReassemble_ContiguousAllPresent | 完整连续分片 | 返回重组帧; IP total length/flags/checksum 已更新 | REAL | 校验 IP 头字段 |
| FR2.4-POS | FR2.4 | TestTryReassemble_SingleFragmentGroup | 单分片 offset0 MF=0 | 重组"成功"返回帧(等同输入语义) | REAL | |
| FR3.1-POS | FR3.1 | TestFlush_IncompleteGroups | 1 个未完成组 | 返回 1; groups 被清空 | REAL | |
| FR3.2-POS | FR3.2 | TestFlush_AllCompleted | 1 个已完成组 | 返回 0; groups 清空 | REAL | |
| FR3.3-POS | FR3.3 | TestFlush_NoGroups | 空 map | 返回 0 | REAL | |
| FR-INTG-POS | FR(端到端) | TestParse_FirstPacketIsFragment_NoHandshake | **PCAP 首包即分片**(无握手,首帧=首分片,次帧=尾分片,TCP data) | TCP 流被创建; c2s 流含重组 payload; C2SLength>0 | SIMULATED | **首包即分片**关键;与 P5.4 同一场景的 FR 视角;复用 TestAuditFix_FullyFragmentedTCP |

---

## 组件: offset.go — ExtractOffsetLayout

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| O1.1-POS | O1.1 | TestExtractOffset_Ethernet | Eth/IPv4/TCP 包 | L2Start==0; DstMAC==0; SrcMAC==6 | REAL | |
| O1.2-POS | O1.2 | TestExtractOffset_Dot1Q | Eth/Dot1Q/IPv4/TCP 包 | VlanTCO==14(VLAN TCI 偏移) | REAL | VLAN |
| O1.3-POS | O1.3 | TestExtractOffset_IPv4 | 含 IPv4 | L3Start==14; SrcIP==26; DstIP==30; TTL==22; IPID==18 | REAL | |
| O1.4-POS | O1.4 | TestExtractOffset_IPv6 | Eth/IPv6/UDP 包 | L3Start==14; L4Protocol=="ipv6" | REAL | |
| O1.5-POS | O1.5 | TestExtractOffset_TCP | 含 TCP | L4Start 正确; SrcPort/DstPort/Seq/Ack/Window/TCPFlags 偏移正确 | REAL | |
| O1.6-POS | O1.6 | TestExtractOffset_UDP | 含 UDP | L4Start 正确; SrcPort/DstPort 偏移正确 | REAL | |
| O1.7-POS | O1.7 | TestExtractOffset_ICMPv4 | Eth/IPv4/ICMPv4 包 | L4Start 正确; L4Protocol=="icmp" | REAL | |
| O1.8-POS | O1.8 | TestExtractOffset_ARP | Eth/ARP 包 | L4Start==14; L4Protocol=="arp" | REAL | |
| O1.9-BR1 | O1.9 | TestExtractOffset_UnknownLayer | 含未知 layer 类型 | 该 layer 无偏移记录(不 panic) | REAL | |
| O1.10-POS | O1.10 | TestExtractOffset_MultiLayerVLAN | Eth+Dot1Q+IPv4+TCP | 各层偏移累加正确; VlanTCO/L3Start/L4Start 均设值 | REAL | |
| O1.11-NEG | O1.11 | TestExtractOffset_NoLayers | 空 gopacket.Packet(无 layer) | 所有字段==-1(newOffsetLayout 默认) | REAL | |

---

## 组件: payload.go — payloadsWriter (newPayloadsWriter / appendStream / close)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| PW1.1-BR1 | PW1.1 | TestNewPayloadsWriter_EmptyPath | path="" | 返回 (nil,nil) | REAL | 重组禁用 |
| PW1.2-NEG | PW1.2 | TestNewPayloadsWriter_CreateFail | path="/no/dir/x.payloads" | err 含 "create payloads file"; nil | REAL | |
| PW1.3-POS | PW1.3 | TestNewPayloadsWriter_Success | temp path | 返回非 nil writer; offset==0 | REAL | |
| PW2.1-BR1 | PW2.1 | TestAppendStream_NilWriter | w==nil | 返回 (0,len(data),nil) | REAL | |
| PW2.2-BR1 | PW2.2 | TestAppendStream_NilFile | w.file==nil | 返回 (0,len(data),nil) | REAL | 防御 |
| PW2.3-BR1 | PW2.3 | TestAppendStream_EmptyData | data=[]byte{} | 返回 (offset,0,nil) | REAL | 纯 ACK |
| PW2.4-NEG | PW2.4 | TestAppendStream_WriteFail | 已关闭文件 | 返回 (0,0,err 含 "write payloads") | REAL | |
| PW2.5-POS | PW2.5 | TestAppendStream_Success | data="abc" | 返回 (offset,3,nil); w.offset 前进 3 | REAL | |
| PW3.1-BR1 | PW3.1 | TestPayloadsClose_NilWriter | w==nil | 返回 nil | REAL | |
| PW3.2-POS | PW3.2 | TestPayloadsClose_Success | 正常 writer | 返回 nil; 文件已关闭(再写报错) | REAL | |
| PW3.3-NEG | PW3.3 | TestPayloadsClose_AlreadyClosed | 二次 close | 返回非 nil 错误(文件已关闭) | REAL | |

---

## 组件: trigram.go — TrigramIndex (AddSegment / Search / linearSearch / WriteToFile / LoadFromFile)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| T1.1-POS | T1.1 | TestNewTrigramIndex_Empty | NewTrigramIndex() | Postings 非 nil 空 map; Segments==nil; SegmentCount()==0 | REAL | |
| T2.1-BR1 | T2.1 | TestAddSegment_ShortData | data="ab"(2 字节) | segment 存入(SegmentCount==1); Postings 为空(无 trigram); linearSearch 仍可命中 | REAL | |
| T2.2-POS | T2.2 | TestAddSegment_Exactly3Bytes | data="abc" | 1 个 trigram posting | REAL | |
| T2.3-POS | T2.3 | TestAddSegment_ManyBytes | data="abcdef" | 多个 trigram,各带 offset | REAL | |
| T2.4-POS | T2.4 | TestAddSegment_DuplicateTrigrams | data="aaaa" | Postings['aaa'] 多条 posting(不同 offset) | REAL | |
| T3.1-NEG | T3.1 | TestSearch_EmptyPattern | pattern=[]byte{} | 返回 nil | REAL | |
| T3.2-POS | T3.2 | TestSearch_ShortPatternLinear | pattern="ab"(<3) | 走 linearSearch 命中 | REAL | |
| T3.3-NEG | T3.3 | TestSearch_RarestTrigramZeroPostings | pattern 含不存在 trigram | 返回 nil(bestCount==0 break) | REAL | |
| T3.4-POS | T3.4 | TestSearch_FirstTrigramRarest | pattern 首三字节最稀有 | 用最小 postings 命中 | REAL | |
| T3.5-POS | T3.5 | TestSearch_LaterTrigramRarest | pattern 后段三字节更稀有 | bestCount 更新为更小 | REAL | |
| T3.6-POS | T3.6 | TestSearch_PatternFound | 索引含 pattern | 返回 TrigramMatch 带正确 Offset/FlowID/Dir | REAL | |
| T3.7-BR1 | T3.7 | TestSearch_TrigramHitNoMatch | trigram 命中但段内无 pattern | 返回 nil(false positive 过滤) | REAL | |
| T3.8-POS | T3.8 | TestSearch_MultipleOccurrencesSameSeg | 段内 pattern 出现 2 次 | 返回 2 条 match(不同 offset) | REAL | |
| T3.9-POS | T3.9 | TestSearch_FoundInMultipleSegments | 多段含 pattern | 每段≥1 match | REAL | |
| T4.1-NEG | T4.1 | TestLinearSearch_NoSegments | 空 index | 返回 nil | REAL | |
| T4.2-POS | T4.2 | TestLinearSearch_Found | 段含 pattern | 命中 | REAL | |
| T4.3-BR1 | T4.3 | TestLinearSearch_NotFound | 段不含 | 跳过 | REAL | |
| T4.4-POS | T4.4 | TestLinearSearch_MultipleOccurrences | 多次出现 | 多 match | REAL | |
| T5.1-NEG | T5.1 | TestTrigramWriteToFile_CreateFail | path="/no/dir/x.trigram" | 返回 (0,err) | REAL | |
| T5.2-NEG | T5.2 | TestTrigramWriteToFile_GobFail | (gob 编码 []byte/map 正常不失败) | 备注说明:结构可序列化,失败分支不可达 | REAL | 防御 |
| T5.3-BR1 | T5.3 | TestTrigramWriteToFile_StatFail | (Stat 失败时 size=0 但文件已写) | 返回 (0,nil) 或 (size,nil); 不报错 | REAL | Stat 错误被丢弃 |
| T5.4-POS | T5.4 | TestTrigramWriteToFile_Success | temp path + 含 segment | 返回 (size>0,nil); 文件存在 | REAL | |
| T6.1-NEG | T6.1 | TestTrigramLoadFromFile_OpenFail | path 不存在 | 返回 nil,err | REAL | |
| T6.2-NEG | T6.2 | TestTrigramLoadFromFile_DecodeFail | 文件内容非 gob | 返回 nil,err | REAL | |
| T6.3-POS | T6.3 | TestTrigramLoadFromFile_Success | 有效 .trigram 文件 | 返回 index; Segments/Postings 还原 | REAL | |
| T-RT-POS | T5/T6(往返) | TestTrigramIndex_WriteLoadRoundTrip | 构造 index(多 segment+多 trigram+重复)→WriteToFile→LoadFromFile | loaded.SegmentCount==原; loaded.Search(pattern) 结果与原 index 完全一致(同 FlowID/Dir/Offset/SegLen); SortedTrigrams 相同 | REAL | **往返一致**关键测试 |

---

## 组件: search.go — Search / matchPacket / filterFlows / MatchPreview / matchFlowMatcher / ipMatch / decodePayloadFilter

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| S1.1-NEG | S1.1 | TestSearch_NilQueryDefensive | query=nil(直接调) | 备注说明:会 panic,调用方必须非 nil;不构造测试 | REAL | 防御,记录契约 |
| S1.2-POS | S1.2 | TestSearch_FlowFilterAllMatch | FlowFilter 匹配所有候选 | 返回全部候选流 | REAL | |
| S1.3-NEG | S1.3 | TestSearch_FlowFilterNoneMatch | FlowFilter 无匹配 | 返回空结果 | REAL | |
| S1.4-POS | S1.4 | TestSearch_NoFlowFilter | FlowFilter==nil | 所有流为候选 | REAL | |
| S1.5-POS | S1.5 | TestSearch_PayloadFilterDecodeOK | PayloadFilter hex 有效 | trigram 搜索命中; payloadHits 非空 | REAL | |
| S1.6-NEG | S1.6 | TestSearch_PayloadFilterDecodeFail | PayloadFilter hex 奇数长度 | 返回 nil,err 含 "odd hex" | REAL | |
| S1.7-POS | S1.7 | TestSearch_PayloadTrigramHits | payload 命中 | 候选收窄到命中流 | REAL | |
| S1.8-NEG | S1.8 | TestSearch_PayloadNoHits | trigram 无命中 | 返回空结果 | REAL | |
| S1.9-BR1 | S1.9 | TestSearch_PayloadFlowNotInHits | 流不在 hit set | 被排除 | REAL | |
| S1.10-POS | S1.10 | TestSearch_PayloadFlowInHits | 流在 hit set | 保留 | REAL | |
| S1.11-BR1 | S1.11 | TestSearch_NoPayloadFilter | Payload==nil | 无 payload 过滤 | REAL | |
| S1.12-POS | S1.12 | TestSearch_PacketFilterAvailable | PacketFilter + packets | 构建 packetsByFlow | REAL | |
| S1.13-POS | S1.13 | TestSearch_PacketFilterDirection | PacketFilter.Direction | matchPacket 各字段 | REAL | |
| S1.14-POS | S1.14 | TestSearch_PacketFilterHasMatches | 流有匹配包 | 流保留 | REAL | |
| S1.15-NEG | S1.15 | TestSearch_PacketFilterNoMatches | 流无匹配包 | 流排除 | REAL | |
| S1.16-BR1 | S1.16 | TestSearch_PacketFilterPacketsNil | PacketFilter!=nil 但 packets==nil | 跳过包过滤;所有流通过此阶段 | REAL | |
| S1.17-BR1 | S1.17 | TestSearch_NoPacketFilter | PacketFilter==nil | 无包过滤 | REAL | |
| S1.18-POS | S1.18 | TestSearch_LimitZeroReturnAll | Limit<=0 | 返回全部候选 | REAL | |
| S1.19-POS | S1.19 | TestSearch_PositiveLimit | Limit=2,候选 5 | 返回 2 条 | REAL | |
| S1.20-BR1 | S1.20 | TestSearch_NegativeOffsetClamped | Offset=-5 | skip 钳为 0 | REAL | |
| S1.21-POS | S1.21 | TestSearch_OffsetSkips | Offset=2,候选 5 | 跳过前 2 | REAL | |
| S1.22-POS | S1.22 | TestSearch_LimitReachedStops | results 达 limit | break | REAL | |
| S1.23-POS | S1.23 | TestSearch_PayloadHitsAttached | payloadHits 非空 | r.Matches 设值 | REAL | |
| S1.24-POS | S1.24 | TestSearch_PacketResultsAttached | packetsByFlow 非空 | r.Packets 设值 | REAL | |
| S2.1-NEG | S2.1 | TestMatchPacket_DirectionMismatch | f.Dir="c2s",p.Dir="s2c" | false | REAL | |
| S2.2-NEG | S2.2 | TestMatchPacket_L4Mismatch | f.L4="tcp",p.L4="udp" | false | REAL | |
| S2.3-NEG | S2.3 | TestMatchPacket_AnomalyMismatch | f.Anomaly="truncated",p.Anomaly="" | false | REAL | |
| S2.4-NEG | S2.4 | TestMatchPacket_TimeBeforeStart | p.ts < f.TimeStartUs | false | REAL | |
| S2.5-NEG | S2.5 | TestMatchPacket_TimeAfterEnd | p.ts > f.TimeEndUs | false | REAL | |
| S2.6-POS | S2.6 | TestMatchPacket_AllMatch | 全字段匹配或通配 | true | REAL | |
| S3.1-NEG | S3.1 | TestFilterFlows_Empty | 空 flows | 空 slice | REAL | |
| S3.2-NEG | S3.2 | TestFilterFlows_ProtocolMismatch | f.Protocol="tcp",fl.L4="udp" | 排除 | REAL | |
| S3.3-NEG | S3.3 | TestFilterFlows_SrcIPMismatch | f.SrcIP 精确不等 | 排除 | REAL | |
| S3.4-NEG | S3.4 | TestFilterFlows_DstIPMismatch | f.DstIP 精确不等 | 排除 | REAL | |
| S3.5-NEG | S3.5 | TestFilterFlows_SrcPortMismatch | f.SrcPort 不等 | 排除 | REAL | |
| S3.6-NEG | S3.6 | TestFilterFlows_DstPortMismatch | f.DstPort 不等 | 排除 | REAL | |
| S3.7-NEG | S3.7 | TestFilterFlows_L7TypeMismatch | f.L7Type 不等 | 排除 | REAL | |
| S3.8-POS | S3.8 | TestFilterFlows_AllMatch | 全匹配 | 保留 | REAL | |
| S3-CIDR-NEG | S3(IP/CIDR) | TestFilterFlows_CIDRNotSupported | FlowFilter.SrcIP="10.0.0.0/24", 流 SrcIP="10.0.0.1" | **不匹配**(filterFlows 用 `!=` 精确字符串比较,CIDR 不展开); 流被排除 | REAL | **filterFlows 无 CIDR**:与 matchFlowMatcher 不同函数,各自 CIDR 行为测试 |
| S3-CIDR-POS | S3(IP/CIDR) | TestFilterFlows_ExactStringMatch | FlowFilter.SrcIP="10.0.0.0/24", 流 SrcIP 字面=="10.0.0.0/24" | 匹配(字面相等) | REAL | 证明是字面比较而非 CIDR |
| S4.1-NEG | S4.1 | TestMatchPreview_Empty | 空 flows | nil | REAL | |
| S4.2-POS | S4.2 | TestMatchPreview_FlowMatches | matcher 全匹配 | hits 含流 ID | REAL | |
| S4.3-BR1 | S4.3 | TestMatchPreview_FlowFails | matcher 不匹配 | continue; hits 不含 | REAL | |
| S5.1-NEG | S5.1 | TestMatchFlowMatcher_ProtocolMismatch | m.Protocol="tcp",f.L4="udp" | false | REAL | |
| S5.2-NEG | S5.2 | TestMatchFlowMatcher_SrcPortMismatch | m.SrcPort 不等 | false | REAL | |
| S5.3-NEG | S5.3 | TestMatchFlowMatcher_DstPortMismatch | m.DstPort 不等 | false | REAL | |
| S5.4-NEG | S5.4 | TestMatchFlowMatcher_SrcIPMismatch | m.SrcIP 精确不等 | false | REAL | |
| S5.5-NEG | S5.5 | TestMatchFlowMatcher_DstIPMismatch | m.DstIP 精确不等 | false | REAL | |
| S5.6-POS | S5.6 | TestMatchFlowMatcher_AllMatch | 全匹配 | true | REAL | |
| S5-CIDR-POS | S5/S6(CIDR) | TestMatchFlowMatcher_CIDRMatch | m.SrcIP="10.0.0.0/8", f.SrcIP="10.0.0.1" | **true**(ipMatch 走 CIDR) | REAL | **matchFlowMatcher CIDR**:与 filterFlows 不同函数 |
| S5-CIDR-NEG | S5/S6(CIDR) | TestMatchFlowMatcher_CIDRNoMatch | m.SrcIP="192.168.0.0/16", f.SrcIP="10.0.0.1" | false | REAL | |
| S6.1-POS | S6.1 | TestIPMatch_CIDRValidMatch | spec="10.0.0.0/24",candidate="10.0.0.5" | true | REAL | |
| S6.2-NEG | S6.2 | TestIPMatch_CIDRValidNoMatch | candidate="10.1.0.5" | false | REAL | |
| S6.3-NEG | S6.3 | TestIPMatch_InvalidCIDR | spec="10.0.0.0/33" | false(ParseCIDR err) | REAL | |
| S6.4-NEG | S6.4 | TestIPMatch_UnparseableCandidate | candidate="not-an-ip" | false | REAL | |
| S6.5-POS | S6.5 | TestIPMatch_Exact | spec="10.0.0.1",candidate="10.0.0.1" | true; 不同则 false | REAL | |
| S7.1-NEG | S7.1 | TestDecodePayloadFilter_Nil | p==nil | 返回 nil,nil | REAL | |
| S7.2-POS | S7.2 | TestDecodePayloadFilter_PlainText | Encoding="ascii" | 返回 Contains 原样 | REAL | |
| S7.3-BR1 | S7.3 | TestDecodePayloadFilter_HexEmptyNeedle | Encoding="hex",Contains 空 | 返回 nil,nil(或空) | REAL | |
| S7.4-NEG | S7.4 | TestDecodePayloadFilter_HexOddLength | Contains="abc"(3 字符) | err 含 "odd hex length" | REAL | |
| S7.5-NEG | S7.5 | TestDecodePayloadFilter_HexInvalidChar | Contains="0xYZ"(含非法) | err 含 "invalid hex character" | REAL | |
| S7.6-POS | S7.6 | TestDecodePayloadFilter_HexValid | Contains="48656c6c6f" | 返回 []byte("Hello") | REAL | |

---

## 组件: dynamic.go — ParsePacket / fileCache / decoderForLinkType / buildLayerRecords / layerName / populateFields / tcpFlagsString / netHw / netIPStr

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| DY1.1-POS | DY1.1 | TestOpenCached_AlreadyCached | 同 path 二次调用 | 返回缓存句柄(不新开;可观测:句柄指针相同) | REAL | 包内测试 |
| DY1.2-NEG | DY1.2 | TestOpenCached_OpenFail | path 不存在 | err 含 "open pcap for re-parse" | REAL | |
| DY1.3-POS | DY1.3 | TestOpenCached_OpenSuccess | temp pcap path | 返回非 nil file; 缓存命中 | REAL | |
| DY2.1-POS | DY2.1 | TestCloseCachedFile_Cached | 已缓存 path | 句柄关闭; map 删除 | REAL | |
| DY2.2-BR1 | DY2.2 | TestCloseCachedFile_NotCached | 未缓存 path | 无副作用 | REAL | |
| DY3.1-NEG | DY3.1 | TestParsePacket_InvalidLength | length<=0 | err 含 "invalid packet length" | REAL | |
| DY3.2-NEG | DY3.2 | TestParsePacket_UnsupportedLinkType | linkType=LinkTypeRaw | err 含 "unsupported link type" | REAL | |
| DY3.3-NEG | DY3.3 | TestParsePacket_FileOpenFail | pcapPath 不存在 | err 含 "open pcap for re-parse" | REAL | |
| DY3.4-NEG | DY3.4 | TestParsePacket_ReadAtFail | rawOffset 超过文件末尾 | err 含 "read packet bytes at" | SIMULATED | 需 temp pcap 文件 |
| DY3.5-POS | DY3.5 | TestParsePacket_Success | temp pcap + 正确 rawOffset/length | 返回 []LayerRecord 非空; 含 eth/ipv4/tcp | SIMULATED | 集成:从 Parse 取 RawOffset 再 ParsePacket |
| DY3-INTG-POS | DY3(端到端) | TestParse_ParsePacketRoundTrip | 构造 pcap→Parse 取每包 RawOffset/Length→ParsePacket | 每包 LayerRecords 的 src_ip/dst_ip/端口 与 Parse 产出的 FlowModel 一致 | SIMULATED | RawOffset 算术往返 |
| DY4.1-POS | DY4.1 | TestDecoderForLinkType_Ethernet | LinkTypeEthernet | 返回 LayerTypeEthernet,nil | REAL | |
| DY4.2-NEG | DY4.2 | TestDecoderForLinkType_NonEthernet | LinkTypeRaw | 返回 err 含 "supports Ethernet only" | REAL | |
| DY5.1-NEG | DY5.1 | TestBuildLayerRecords_EmptyPacket | 无 layer 的 packet | 返回 nil/空 slice | REAL | |
| DY5.2-POS | DY5.2 | TestBuildLayerRecords_SingleLayer | 仅 Ethernet | 1 条 record | REAL | |
| DY5.3-POS | DY5.3 | TestBuildLayerRecords_MultiLayer | Eth+IPv4+TCP | 多 record,各 Range 偏移正确 | REAL | |
| DY5.4-BR1 | DY5.4 | TestBuildLayerRecords_UnknownLayer | 含未知 layer | 仍产 record(Layer 名为 LayerType.String); Fields/Offsets 空 | REAL | |
| DY6.1-POS | DY6.1 | TestLayerName_Ethernet | *layers.Ethernet | "eth" | REAL | |
| DY6.2-POS | DY6.2 | TestLayerName_Dot1Q | *layers.Dot1Q | "dot1q" | REAL | |
| DY6.3-POS | DY6.3 | TestLayerName_IPv4 | *layers.IPv4 | "ipv4" | REAL | |
| DY6.4-POS | DY6.4 | TestLayerName_IPv6 | *layers.IPv6 | "ipv6" | REAL | |
| DY6.5-POS | DY6.5 | TestLayerName_TCP | *layers.TCP | "tcp" | REAL | |
| DY6.6-POS | DY6.6 | TestLayerName_UDP | *layers.UDP | "udp" | REAL | |
| DY6.7-POS | DY6.7 | TestLayerName_ICMPv4 | *layers.ICMPv4 | "icmp" | REAL | |
| DY6.8-POS | DY6.8 | TestLayerName_ARP | *layers.ARP | "arp" | REAL | |
| DY6.9-BR1 | DY6.9 | TestLayerName_Unknown | 未知 layer | layer.LayerType().String() | REAL | |
| DY7.1-POS | DY7.1 | TestPopulateFields_Ethernet | Ethernet layer | Fields dst_mac/src_mac/ether_type; Offsets dst_mac/src_mac 设值 | REAL | |
| DY7.2-POS | DY7.2 | TestPopulateFields_Dot1Q | Dot1Q layer | Fields vlan_id/priority; Offsets vlan_tco | REAL | |
| DY7.3-POS | DY7.3 | TestPopulateFields_IPv4 | IPv4 layer | Fields src_ip/dst_ip/ttl/protocol/ip_id/dscp/ecn; 全 IP Offsets 设值 | REAL | |
| DY7.4-POS | DY7.4 | TestPopulateFields_IPv6 | IPv6 layer | Fields src_ip/dst_ip/hop_limit/next_header; 无 Offsets | REAL | |
| DY7.5-POS | DY7.5 | TestPopulateFields_TCP | TCP layer | Fields src_port/dst_port/seq/ack/window/flags; 全 TCP Offsets | REAL | |
| DY7.6-POS | DY7.6 | TestPopulateFields_UDP | UDP layer | Fields src_port/dst_port/length; port Offsets | REAL | |
| DY7.7-POS | DY7.7 | TestPopulateFields_ICMPv4 | ICMPv4 layer | Fields type/code/id/seq; 无 Offsets | REAL | |
| DY7.8-POS | DY7.8 | TestPopulateFields_ARP | ARP layer | Fields operation/sender_hw/sender_ip/target_hw/target_ip | REAL | |
| DY7.9-BR1 | DY7.9 | TestPopulateFields_Unknown | 未知 layer | Fields/Offsets 保持空 map | REAL | |
| DY8.1-POS | DY8.1 | TestTCPFlagsString_FIN | FIN set | "FIN" | REAL | |
| DY8.2-POS | DY8.2 | TestTCPFlagsString_SYN | SYN set | "SYN" | REAL | |
| DY8.3-POS | DY8.3 | TestTCPFlagsString_RST | RST set | "RST" | REAL | |
| DY8.4-POS | DY8.4 | TestTCPFlagsString_PSH | PSH set | "PSH" | REAL | |
| DY8.5-POS | DY8.5 | TestTCPFlagsString_ACK | ACK set | "ACK" | REAL | |
| DY8.6-POS | DY8.6 | TestTCPFlagsString_URG | URG set | "URG" | REAL | |
| DY8.7-POS | DY8.7 | TestTCPFlagsString_Multiple | SYN+ACK | "SYN,ACK" | REAL | |
| DY8.8-POS | DY8.8 | TestTCPFlagsString_None | 无标志 | "none" | REAL | |
| DY9.1-POS | DY9.1 | TestNetHw_6Bytes | 6 字节 | "aa:bb:cc:dd:ee:ff" 格式 | REAL | |
| DY9.2-BR1 | DY9.2 | TestNetHw_OtherLen | 非 6 字节 | hex "%x" | REAL | |
| DY10.1-POS | DY10.1 | TestNetIPStr_4Bytes | 4 字节 | IPv4 dotted-quad | REAL | |
| DY10.2-POS | DY10.2 | TestNetIPStr_16Bytes | 16 字节 | IPv6 字符串 | REAL | |
| DY10.3-BR1 | DY10.3 | TestNetIPStr_OtherLen | 其他长度 | hex "%x" | REAL | |
| DY-MAN1 | DY3(real kernel) | TestManual_RealKernelRawOffsetRoundTrip | 真实内核抓包 pcap | 见 MANUAL 说明 | MANUAL | 真实内核抓包 RawOffset 往返 |

---

## 组件: plugin.go — Registry (NewRegistry / Register / Find / ParseStream)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| PL1.1-POS | PL1.1 | TestNewRegistry_DefaultParsers | NewRegistry() | 含 http/dns/tls parser(Find(80,...)非 nil, Find(53,...)非 nil, Find(443,...)非 nil) | REAL | |
| PL2.1-POS | PL2.1 | TestRegister_OneParser | 注册自定义 parser | Find 能命中 | REAL | |
| PL2.2-NEG | PL2.2 | TestRegister_NilParserDefensive | 注册 nil parser | 备注说明:Find 调 CanParse 会 panic;记录防御缺口 | REAL | 防御 gap |
| PL3.1-POS | PL3.1 | TestFind_FirstMatch | 首个 parser CanParse=true | 返回该 parser(短路) | REAL | |
| PL3.2-NEG | PL3.2 | TestFind_NoMatch | 无 parser 匹配 | 返回 nil | REAL | |
| PL3.3-NEG | PL3.3 | TestFind_EmptyRegistry | 空 registry | 返回 nil | REAL | |
| PL4.1-NEG | PL4.1 | TestParseStream_NoParserFound | port/sample 无匹配 | 返回 nil | REAL | |
| PL4.2-POS | PL4.2 | TestParseStream_ParseSucceeds | http port 80 + GET | 返回 L7Result{Protocol:"http"} | REAL | |
| PL4.3-NEG | PL4.3 | TestParseStream_ParseError | parser.Parse 返回 err | 返回 nil | REAL | 构造 mock parser |
| PL4.4-NEG | PL4.4 | TestParseStream_ParseNilResult | parser.Parse 返回 nil,nil | 返回 nil | REAL | 构造 mock parser |

---

## 组件: l7_parsers.go — httpParser / dnsParser / tlsParser / TLS helpers / parseDNS

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| L7.1.1-POS | L7.1.1 | TestHTTPCanParse_WellKnownPort | port=80 | true; 同理 8080/8000/8081 | REAL | |
| L7.1.2-POS | L7.1.2 | TestHTTPCanParse_MethodPrefix | port=12345,sample="GET / HTTP/1.1" | true | REAL | |
| L7.1.3-POS | L7.1.3 | TestHTTPCanParse_ResponseStatusLine | sample="HTTP/1.1 200 OK" | true | REAL | |
| L7.1.4-NEG | L7.1.4 | TestHTTPCanParse_NoMatch | port=12345,sample="\x00\x01..." | false | REAL | |
| L7.2.1-BR1 | L7.2.1 | TestHTTPParse_NoHeaderBoundary | stream="GET /" (无 \r\n\r\n) | BodyOffset==0; BodyLength==0 | REAL | |
| L7.2.2-POS | L7.2.2 | TestHTTPParse_BodyPresent | "GET / HTTP/1.1\r\nHost: x\r\n\r\nbody" | BodyOffset==headerLen+4; BodyLength==4 | REAL | |
| L7.2.3-BR1 | L7.2.3 | TestHTTPParse_NoBodyEndsAtBlankLine | "GET / HTTP/1.1\r\nHost: x\r\n\r\n" | BodyOffset/BodyLength==0 | REAL | |
| L7.2.4-BR1 | L7.2.4 | TestHTTPParse_EmptyHeaderBlock | stream="" | Protocol=="http"; Metadata 空 | REAL | |
| L7.2.5-POS | L7.2.5 | TestHTTPParse_ResponseStatusLine | "HTTP/1.1 200 OK\r\n\r\n" | Metadata["status"]=="200"; Metadata["reason"]=="OK" | REAL | |
| L7.2.6-POS | L7.2.6 | TestHTTPParse_RequestLine | "GET /a/b HTTP/1.1\r\n\r\n" | Metadata["method"]=="GET"; Metadata["uri"]=="/a/b" | REAL | **L7 method 具体值** |
| L7.2.7-POS | L7.2.7 | TestHTTPParse_HostHeader | "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" | Metadata["host"]=="example.com" | REAL | **L7 Host 具体值** |
| L7.2.8-BR1 | L7.2.8 | TestHTTPParse_HeaderNoColon | header 行无冒号 | 跳过(不 panic) | REAL | |
| L7.2.9-BR1 | L7.2.9 | TestHTTPParse_RequestLineGarbage | first="GARBAGE"(无空格) | 无 method/uri; Metadata 部分空 | REAL | |
| L7.3.1-POS | L7.3.1 | TestDNSCanParse_Port53 | port=53 | true; 同理 5353 | REAL | |
| L7.3.2-NEG | L7.3.2 | TestDNSCanParse_OtherPort | port=1234 | false | REAL | |
| L7.4.1-POS | L7.4.1 | TestDNSParse_ValidWithQuestions | 合法 DNS query payload(含 Questions) | Metadata["query_name"]==域名; Metadata["query_type"]==类型; Metadata["rcode"]==0 | REAL | **L7 DNS query_name 具体值** |
| L7.4.2-BR1 | L7.4.2 | TestDNSParse_ValidNoQuestions | 合法 DNS 无 Questions | 仅 rcode 设值; query_name 不存在 | REAL | |
| L7.4.3-BR1 | L7.4.3 | TestDNSParse_InvalidMessage | 非 DNS payload | Protocol=="dns"; Metadata 空 | REAL | parseDNS 返回 nil |
| L7.5.1-POS | L7.5.1 | TestTLSCanParse_Port443 | port=443 | true | REAL | |
| L7.5.2-POS | L7.5.2 | TestTLSCanParse_SignatureNon443 | port=8443,sample[0]=0x16,[1]=0x03 | true | REAL | |
| L7.5.3-NEG | L7.5.3 | TestTLSCanParse_NoMatch | port=1234,sample 无 TLS 签名 | false | REAL | |
| L7.6.1-POS | L7.6.1 | TestTLSParse_SNI | ClientHello 含 SNI | Metadata["sni"]=="example.com" | REAL | **L7 SNI 具体值** |
| L7.6.2-POS | L7.6.2 | TestTLSParse_Version | ClientHello version=0x0303 | Metadata["version"]=="TLS 1.2" | REAL | **L7 version 具体值** |
| L7.6.3-POS | L7.6.3 | TestTLSParse_CipherSuites | ClientHello 含 cipher 0xc02f | Metadata["cipher_suites"] 含 "c02f" | REAL | **L7 cipher 具体值** |
| L7.6.4-POS | L7.6.4 | TestTLSParse_CertChainLen | Certificate 消息 | Metadata["cert_chain_length"]>0 | REAL | |
| L7.6.5-BR1 | L7.6.5 | TestTLSParse_NoMetadata | 加密/非握手流 | Metadata 空; Protocol=="tls" | REAL | |
| L7.7.1-BR1 | L7.7.1 | TestExtractTLSMetadata_ShortStream | stream<5 字节 | 返回空 meta | REAL | |
| L7.7.2-BR1 | L7.7.2 | TestExtractTLSMetadata_TruncatedRecord | recLen>body | recLen 钳为 len(body); 不 panic | REAL | |
| L7.7.3-POS | L7.7.3 | TestExtractTLSMetadata_HandshakeRecord | recType=0x16 | parseTLSHandshake 被调; SNI/version 提取 | REAL | |
| L7.7.4-BR1 | L7.7.4 | TestExtractTLSMetadata_NonHandshakeRecord | recType=0x17 | 跳过; meta 空 | REAL | |
| L7.7.5-POS | L7.7.5 | TestExtractTLSMetadata_MultipleRecords | ClientHello+Certificate 两 record | SNI + CertChainLen 都提取 | REAL | |
| L7.8.1-BR1 | L7.8.1 | TestParseTLSHandshake_IncompleteHeader | body<4 字节 | 不解析; meta 不变 | REAL | |
| L7.8.2-BR1 | L7.8.2 | TestParseTLSHandshake_TruncatedMsg | hsLen>len(msg) | hsLen 钳为 len(msg); 不 panic | REAL | |
| L7.8.3-POS | L7.8.3 | TestParseTLSHandshake_ClientHello | hsType=0x01 | parseClientHello 被调; SNI/version 提取 | REAL | |
| L7.8.4-POS | L7.8.4 | TestParseTLSHandshake_Certificate | hsType=0x0B | CertChainLen 设值 | REAL | |
| L7.8.5-BR1 | L7.8.5 | TestParseTLSHandshake_OtherType | hsType=0x02(ServerHello) | 跳过; meta 不变 | REAL | |
| L7.9.1-BR1 | L7.9.1 | TestParseClientHello_TooShort | hs<35 字节 | return; meta 不变 | REAL | |
| L7.9.2-BR1 | L7.9.2 | TestParseClientHello_SessionIDExtendsPastBuf | sidLen 越界 | return | REAL | |
| L7.9.3-BR1 | L7.9.3 | TestParseClientHello_CipherLenFieldPastBuf | csLen 字段越界 | return | REAL | |
| L7.9.4-BR1 | L7.9.4 | TestParseClientHello_CipherDataPastBuf | csLen 数据越界 | return | REAL | |
| L7.9.5-BR1 | L7.9.5 | TestParseClientHello_CompressionPastBuf | cmLen 越界 | return | REAL | |
| L7.9.6-BR1 | L7.9.6 | TestParseClientHello_ExtLenFieldPastBuf | extLen 字段越界 | return | REAL | |
| L7.9.7-BR1 | L7.9.7 | TestParseClientHello_ExtDataPastBuf | extEnd>len(hs) | extEnd 钳为 len(hs) | REAL | |
| L7.9.8-POS | L7.9.8 | TestParseClientHello_SNIExtension | ext type 0x0000 | meta.SNI==期望域名 | REAL | |
| L7.9.9-POS | L7.9.9 | TestParseClientHello_SupportedVersionsTLS13 | ext 0x002b 含 0x0304 | meta.Version=="TLS 1.3"(覆盖 handshake-level) | REAL | **TLS 1.3 检测** |
| L7.9.10-BR1 | L7.9.10 | TestParseClientHello_OtherExtension | ext 非 SNI/supported_versions | 跳过 | REAL | |
| L7.9.11-BR1 | L7.9.11 | TestParseClientHello_ExtTruncatedMidParse | p+extDataLen>extEnd | break 退出 extension 循环 | REAL | |
| L7.10.1-BR1 | L7.10.1 | TestParseCertificate_TooShort | hs<3 字节 | return | REAL | |
| L7.10.2-BR1 | L7.10.2 | TestParseCertificate_ListLenExceedsData | listLen>len(hs)-3 | listLen 钳为 len(hs)-3 | REAL | |
| L7.10.3-POS | L7.10.3 | TestParseCertificate_Success | 合法 Certificate 消息 | meta.CertChainLen==listLen | REAL | |
| L7.11.1-POS | L7.11.1 | TestTLSVersionString_SSL3 | 0x0300 | "SSL 3.0" | REAL | |
| L7.11.2-POS | L7.11.2 | TestTLSVersionString_TLS10 | 0x0301 | "TLS 1.0" | REAL | |
| L7.11.3-POS | L7.11.3 | TestTLSVersionString_TLS11 | 0x0302 | "TLS 1.1" | REAL | |
| L7.11.4-POS | L7.11.4 | TestTLSVersionString_TLS12 | 0x0303 | "TLS 1.2" | REAL | |
| L7.11.5-POS | L7.11.5 | TestTLSVersionString_TLS13 | 0x0304 | "TLS 1.3" | REAL | |
| L7.11.6-BR1 | L7.11.6 | TestTLSVersionString_Other | 0x1234 | "0x1234" | REAL | |
| L7.12.1-NEG | L7.12.1 | TestParseDNS_TooShort | payload<12 字节 | 返回 nil | REAL | |
| L7.12.2-NEG | L7.12.2 | TestParseDNS_DecodeFail | 非法 DNS 字节 | 返回 nil | REAL | |
| L7.12.3-POS | L7.12.3 | TestParseDNS_Valid | 合法 DNS | 返回 *layers.DNS; Questions 可读 | REAL | |
| L7-INTG-POS | L7(端到端) | TestParse_L7MetadataViaParse | 三流 pcap: TCP→80 GET / Host:ex.com; UDP→53 DNS query "ex.com"; TCP→443 TLS ClientHello SNI=ex.com | HTTP 流: L7Protocol=="http",L7Method=="GET",L7Host=="ex.com"; DNS 流: L7Protocol=="dns",L7QueryName=="ex.com"; TLS 流: L7Protocol=="tls",L7Host=="ex.com"(SNI),L7Metadata 含 version/cipher_suites | SIMULATED | **L7 端到端集成**:三种协议具体元数据值经 Parse 落入 FlowModel |

---

## 组件: reparse.go — Reparse / NeedsReparse

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RE1.1-POS | RE1.1 | TestReparse_DelegatesToParse | 1 帧 pcap + opts | Reparse 结果与 Parse 一致(FlowCount/PacketCount 相同); FlowModel.ParserVersion=="1.0.0" | SIMULATED | |
| RE2.1-POS | RE2.1 | TestNeedsReparse_VersionMatch | storedVersion==ParserVersion | false | REAL | |
| RE2.2-POS | RE2.2 | TestNeedsReparse_VersionMismatch | storedVersion="0.9.0" | true | REAL | |

---

## 汇总

- 真实(REAL): 419 个
- 模拟(SIMULATED): 73 个
- 手动(MANUAL): 3 个
- 合计: 495 个测试点

### MANUAL 测试点清单

| 测试点ID | 测试函数名 | 一句话原因 |
|---|---|---|
| P-MAN1 | TestManual_RealCaptureParse | 需真实 NIC(enp135s0f0np0)抓取多样真实流量(TLS/HTTP/DNS/ARP/ICMP)的 .pcap,验证解析器对非合成帧的正确性——合成 PCAP 无法覆盖真实协议栈的字段组合与时序。 |
| P-MAN2 | TestManual_HugePcapBoundedMemory | 需多 GB pcap 验证流式解析内存有界(RSS 不随文件增长),合成测试无法廉价生成 GB 级输入且 RSS 须真实 OS 计量。 |
| DY-MAN1 | TestManual_RealKernelRawOffsetRoundTrip | 需真实内核抓包产生的 pcap,验证 RawOffset 字节算术(pcapGlobalHeaderLen=24 + pcapRecordHeaderLen=16)对内核写入的记录布局精确映射——合成 pcap 的记录布局由测试库决定,无法证明对真实内核产物成立。 |

### MANUAL 详细命令与预期

**P-MAN1 — 真实抓包文件解析**
- 为何无法自动测:依赖物理 NIC + 真实协议栈产生的多样流量(ARP/ICMP/TCP 握手/TLS/HTTP/DNS 同时存在),合成帧无法复现真实字段组合与封装细节。
- 手动命令:
  ```
  sudo tcpdump -i enp135s0f0np0 -w /tmp/real.pcap -c 5000
  # 同时在另一终端:curl https://example.com; dig example.com; ping -c3 1.1.1.1
  go test -run TestManual_RealCaptureParse -tags manual -v
  # 测试内调用 Parse("/tmp/real.pcap", &Options{PcapAssetID:"real"})
  ```
- 预期可观测:Parse 无错;analysis.PacketCount==5000;ProtocolDist 含 tcp/udp/icmp/arp 至少各≥1;存在 HandshakeStatus=="complete" 的 TCP 流;analysis.Flows 非空;DurationUs>0。

**P-MAN2 — 超大文件内存有界**
- 为何无法自动测:需多 GB pcap 验证流式(不聚合)内存有界;单元测试无法廉价生成 GB 级输入,且 RSS 须读 `/proc/self/status` 真实计量。
- 手动命令:
  ```
  # 生成大 pcap(循环合并 5000 包的小 pcap 到 ~2GB)
  for i in $(seq 1 200000); do cat /tmp/small.pcap >> /tmp/huge.pcap 2>/dev/null; done
  # 或:tcpreplay --intf1=enp135s0f0np0 --mbps=1000 /tmp/small.pcap 同时 tcpdump -w /tmp/huge.pcap
  go test -run TestManual_HugePcapBoundedMemory -tags manual -v
  # 测试内:设 PacketSink 计数;解析前/中/后读 VmRSS
  ```
- 预期可观测:Parse 完成;PacketCount 巨大(>百万);VmRSS 峰值 < 500MB(不随文件线性增长);sink 收到包总数==PacketCount;analysis.Packets 为空(未在内存聚合)。

**DY-MAN1 — 真实内核抓包 RawOffset 往返**
- 为何无法自动测:验证 RawOffset 字节算术对**真实内核写入**的 pcap 记录布局(全局头 24B + 每包记录头 16B + 数据)精确映射;合成 pcap 由 pcapgo 写入,布局由测试库决定,无法证明对真实内核产物成立。
- 手动命令:
  ```
  sudo tcpdump -i enp135s0f0np0 -w /tmp/real.pcap -c 100
  go test -run TestManual_RealKernelRawOffsetRoundTrip -tags manual -v
  # 测试内:Parse 取每个 pm.RawOffset/pm.Length,调
  # ParsePacket("/tmp/real.pcap", pm.RawOffset, int(pm.Length), layers.LinkTypeEthernet)
  ```
- 预期可观测:每个包 ParsePacket 返回非空 []LayerRecord;LayerRecords 的 src_ip/dst_ip/端口 与 Parse 产出的 FlowModel 字段逐包一致;无 "read packet bytes at" 错误;无偏移错位。
