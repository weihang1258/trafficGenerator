# 协议规划器 测试点细化

> 来源: tcp_extra_planners.md / udp.md / http.md / dns_icmp_arp.md
> 规划器产出 PacketConfig 流; 测试点断言**实际产出的包序列** (包数/每包 L2-L4 字段/payload/方向/序号), 不只断言"无错误"。
> ID 格式: `<场景tag>-POS` (正例) / `-NEG` (异常/失败) / `-BR1` (分支)。
> 已知 bug 测试点采用**失败测试先行**: 先断言坏行为复现 bug, 修复后断言好行为。

## 组件: tcp.go Validate (42-63)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| T1-NEG | T1 | TestTCPValidate_InvalidSrcIP | spec.SrcIP="256.1.1.1" | err!=nil, err.Error()=="invalid source IP: 256.1.1.1" | REAL | net.ParseIP 拒绝超范围八位组 |
| T1-NEG2 | T1 | TestTCPValidate_NonIPSrc | spec.SrcIP="not-an-ip" | err!=nil, contains "invalid source IP: not-an-ip" | REAL | |
| T2-POS | T2 | TestTCPValidate_EmptySrcIP | spec.SrcIP="" | err==nil (空 IP 跳过校验) | REAL | |
| T3-NEG | T3 | TestTCPValidate_InvalidDstIP | spec.DstIP="300.0.0.1" | err!=nil, contains "invalid destination IP" | REAL | |
| T4-POS | T4 | TestTCPValidate_EmptyDstIP | spec.DstIP="" | err==nil | REAL | |
| T5-NEG | T5 | TestTCPValidate_SrcPortZero | spec.SrcPort=0, DstPort=443 | err!=nil, contains "source port is required" | REAL | SrcPort 校验先于 DstPort |
| T6-NEG | T6 | TestTCPValidate_DstPortZero | spec.SrcPort=12345, DstPort=0 | err!=nil, contains "destination port is required" | REAL | |
| T7-POS | T7 | TestTCPValidate_AllValid | SrcIP="10.0.0.1",DstIP="10.0.0.2",SrcPort=2000,DstPort=80 | err==nil | REAL | 正例唯一返回 nil 的路径 |
| T7-BR1 | T7 | TestTCPValidate_ShortCircuitSrcFirst | SrcIP="bad1",DstIP="bad2" | err contains "invalid source IP" (SrcIP 先返回) | REAL | 短路确认 |

## 组件: tcp.go synOptions (69-76)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| T8-POS | T8 | TestTCPSynOptions_MSS1460 | mss=1460 | len(opts)==2; opts[0].Kind==TCPOptMSS, opts[0].Data==[]byte{0x05,0xb4}; opts[1].Kind==TCPOptSACKPermit | REAL | MSS 在前, SACK-Permit 在后 |
| T8-BR1 | T8 | TestTCPSynOptions_MSSMax | mss=65535 | opts[0].Data==[]byte{0xff,0xff} | REAL | 边界 |
| T9-POS | T9 | TestTCPSynOptions_MSSZero | mss=0 | len(opts)==1; opts[0].Kind==TCPOptSACKPermit; 无 MSS 选项 | REAL | 零 MSS 跳过 |

## 组件: tcp.go Plan 入口 (78-81)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| T10-NEG | T10 | TestTCPPlan_ValidateFail | spec.SrcPort=0 | 返回 (nil, err); 无 channel 创建 | REAL | |
| T11-POS | T11 | TestTCPPlan_ValidatePass | 有效 spec | 返回 (non-nil chan, nil); cap(chan)==256 | REAL | |

## 组件: tcp.go Plan goroutine -- 默认值 (91-125)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| T12-POS | T12 | TestTCPPlan_ConfigNilDefaults | spec.TCP=nil | 含握手(SYN Seq=1000,Flags=0x02)+终止; SYN MSS 选项=1460; 所有握手/终止包 WindowSize=65535 | REAL | 默认 Handshake/Termination=true, MSS=1460, WindowSize=65535 |
| T13-POS | T13 | TestTCPPlan_ConfigProvided | spec.TCP=&TCPConfig{Handshake:true,Termination:false,MSS:512,WindowSize:16384} | SYN MSS 选项=512; 包 WindowSize=16384; 无终止包 | REAL | |
| T14-POS | T14 | TestTCPPlan_WinSizeNonZero | spec.TCP.WindowSize=32768 | 所有包 L4.WindowSize==32768 | REAL | |
| T15-POS | T15 | TestTCPPlan_WinSizeZeroFallback | spec.TCP.WindowSize=0 | L4.WindowSize==65535 (回退字面常量) | REAL | |
| T16-POS | T16 | TestTCPPlan_TTLNonZero | spec.TTL=128 | 所有包 L3.TTL==128 | REAL | |
| T17-POS | T17 | TestTCPPlan_TTLZeroDefault | spec.TTL=0 | 所有包 L3.TTL==64 (DefaultTTL) | REAL | |

## 组件: tcp.go Plan goroutine -- 握手分支 (130-205)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| T18-POS | T18 | TestTCPPlan_HandshakeThreePackets | Handshake=true, Payload=nil, Termination=false | 恰好 3 包, 方向序列 [up,down,up], Flags [0x02,0x12,0x10] | REAL | 三向握手 |
| T18a-POS | T18a | TestTCPPlan_SYNPacketFields | Handshake=true | 包0: PacketIndex=0, direction="up", Flags=0x02, Seq=1000, Ack=0, WindowSize=winSize, TCPOptions=synOpts(非nil), L2.SrcMAC/DstMAC=spec, L3.SrcIP/DstIP=spec, L4.SrcPort/DstPort=spec, EtherType=0x0800, L3.Protocol=6, L3.IPID=1 | REAL | 断言每字段真实值 |
| T18b-POS | T18b | TestTCPPlan_SYNACKPacketFields | Handshake=true | 包1: PacketIndex=1, direction="down", Flags=0x12, Seq=2000, Ack=1001, TCPOptions=synOpts, MACs/IPs/ports 交换, L3.IPID=2 | REAL | |
| T18c-POS | T18c | TestTCPPlan_HandshakeACKFields | Handshake=true | 包2: PacketIndex=2, direction="up", Flags=0x10, Seq=1001, Ack=2001, TCPOptions=nil, L3.IPID=3 | REAL | 握手 ACK 无 TCP 选项 |
| T19-POS | T19 | TestTCPPlan_HandshakeDisabled | Handshake=false, Payload=nil, Termination=false | 0 包, channel 立即关闭; clientSeq 保持 1000 未变 | REAL | |

## 组件: tcp.go Plan goroutine -- 数据分段 (208-273)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| T20-POS | T20 | TestTCPPlan_DataPayloadPresent | spec.Payload=[]byte("hello") | 出现 DATA 包, Payload=="hello", Flags=0x18(PSH\|ACK) | REAL | |
| T21-POS | T21 | TestTCPPlan_NoData | spec.Payload=nil | 无 DATA/数据ACK 包, packetIndex 不进入数据块 | REAL | |
| T22-POS | T22 | TestTCPPlan_MSSZeroFallbackInData | spec.TCP.MSS=0, Payload=3000B | segmentSize=1460(DefaultMSS), 3 段 [1460,1460,80] | REAL | |
| T23-POS | T23 | TestTCPPlan_MSSNonZeroInData | spec.TCP.MSS=512, Payload=1500B | segmentSize=512, 3 段 [512,512,476] | REAL | |
| T24-POS | T24 | TestTCPPlan_PayloadLessThanMSS | Payload=100B, MSS=1460 | 1 段 segmentSize=100, 2 包(1 DATA+1 ACK) | REAL | |
| T25-POS | T25 | TestTCPPlan_PayloadEqualsMSS | Payload=1460B, MSS=1460 | 1 段 segmentSize=1460, 2 包 | REAL | 相等不分段 |
| T26-POS | T26 | TestTCPPlan_PayloadGreaterThanMSS | Payload=3000B, MSS=1460 | 3 段 [1460,1460,80], 6 包 | REAL | |
| T26a-POS | T26a | TestTCPPlan_DataSegmentFields | Payload="hello" | DATA 包: direction="up", Flags=0x18, Seq=clientSeq, Ack=serverSeq, Payload=payload[:seg]; 发送后 clientSeq+=seg | REAL | |
| T26b-POS | T26b | TestTCPPlan_DataACKFields | Payload="hello" | 数据 ACK: direction="down", Flags=0x10, Seq=serverSeq, Ack=clientSeq(更新后), WindowSize=winSize | REAL | **修正枚举 M6**: 实际代码第 268 行设了 WindowSize=winSize, 非 0 |
| T27-POS | T27 | TestTCPPlan_LargePayload | Payload=100000B, MSS=1460 | 69 段, 138 包 (138<256 不阻塞) | REAL | |

## 组件: tcp.go Plan goroutine -- 终止分支 (276-373)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| T28-POS | T28 | TestTCPPlan_TerminationFourPackets | Termination=true, Handshake=false, Payload=nil | 恰好 4 包, 方向 [up,down,down,up], Flags [0x11,0x10,0x11,0x10] | REAL | 四次挥手 |
| T28a-POS | T28a | TestTCPPlan_ClientFINFields | Termination=true | FIN 包: direction="up", Flags=0x11(FIN\|ACK), Seq=clientSeq, Ack=serverSeq, WindowSize=winSize; 发送后 clientSeq++ | REAL | |
| T28b-POS | T28b | TestTCPPlan_ServerACKofFINFields | Termination=true | ACK: direction="down", Flags=0x10, Seq=serverSeq, Ack=clientSeq(更新后), WindowSize=winSize | REAL | **修正 M6**: WindowSize=winSize 非 0 |
| T28c-POS | T28c | TestTCPPlan_ServerFINFields | Termination=true | FIN: direction="down", Flags=0x11, Seq=serverSeq, Ack=clientSeq, WindowSize=winSize; 发送后 serverSeq++ | REAL | |
| T28d-POS | T28d | TestTCPPlan_ClientACKofServerFINFields | Termination=true | ACK: direction="up", Flags=0x10, Seq=clientSeq, Ack=serverSeq(更新后), WindowSize=winSize; 之后 packetIndex 不再 ++ | REAL | **修正 M6**: WindowSize=winSize; 最后操作不递增 packetIndex(M5) |
| T29-POS | T29 | TestTCPPlan_TerminationDisabled | Termination=false, Handshake=false, Payload=nil | 0 包 | REAL | |

## 组件: tcp.go Plan goroutine -- 组合场景 (T30-T37)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| T30-POS | T30 | TestTCPPlan_FullFlow | Handshake=true,Payload=100B,Termination=true | 总包数==9 (3+2+4); PacketIndex 0..8 连续无间断 | REAL | 默认场景 |
| T31-POS | T31 | TestTCPPlan_OnlyHandshake | Handshake=true,Payload=nil,Termination=false | 总包数==3 | REAL | |
| T32-POS | T32 | TestTCPPlan_HandshakePlusData | Handshake=true,Payload=100B,Termination=false | 总包数==5 (3+2) | REAL | |
| T33-POS | T33 | TestTCPPlan_HandshakePlusTermination | Handshake=true,Payload=nil,Termination=true | 总包数==7 (3+4) | REAL | |
| T34-POS | T34 | TestTCPPlan_EmptyFlow | Handshake=false,Payload=nil,Termination=false | 总包数==0, channel 立即关闭 | REAL | |
| T35-POS | T35 | TestTCPPlan_NoHandshakeWithData | Handshake=false,Payload="data",Termination=false | 总包数==2 | REAL | 非真实但需测 |
| T36-POS | T36 | TestTCPPlan_NoHandshakeWithTermination | Handshake=false,Payload=nil,Termination=true | 总包数==4 | REAL | |
| T37-POS | T37 | TestTCPPlan_NoHandshakeDataTerm | Handshake=false,Payload="data",Termination=true | 总包数==6 (2+4) | REAL | |

## 组件: tcp.go -- 缺失/错误场景 (M1-M6, E1-E12)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| M1-NEG | M1 (ctx 取消泄漏) | TestTCPPlan_ContextCancelGoroutineLeak | ctx 已 cancel 后调用 Plan, 不读 channel | **已知 bug**: goroutine 从不检查 ctx.Done()。失败测试先行: 断言 cancel 后 goroutine 在 1s 内退出 (runtime.NumGoroutine 回落或 done 信号); 当前会失败(仍跑完) | REAL | 所有 send 是裸发送无 select |
| E12-NEG | E12 (channel 满泄漏) | TestTCPPlan_BlockedSendGoroutineLeak | Payload 使包数>256, 读 0 包后 cancel ctx | **已知 bug**: 256 包填满后 goroutine 永久阻塞在 send。断言 2s 后 goroutine 仍存活(NumGoroutine 未回落); 修复后应退出 | REAL | 无 ctx.Done 退出路径 |
| M2-NEG | M2 (VLAN 丢失) | TestTCPPlan_VLANNotPropagated | spec.VLAN=&VLAN{ID:100,Priority:3} | **已知 bug**: 所有包 L2.VLAN==nil (零值)。失败测试先行: 断言 L2.VLAN.ID==100 (当前失败) | REAL | L2Config 字面量省略 VLAN |
| M3-POS | M3 | TestTCPPlan_CountDurationBPSIgnored | spec.Count=100, spec.Duration=10, spec.BPS="200k", Payload=10B | 无论 Count/Duration/BPS, 规划器产生固定包数 (3+2+4=9) | REAL | Plan 中从不读取这些字段 |
| M4-POS | M4 | TestTCPPlan_InitRegistrationCommented | 无输入, 检查全局 registry | protocol.Get("tcp")==nil (注册被注释); 但 NewPlanner().Name()=="tcp" 可用 | REAL | 第 381 行 Register 被注释 |
| M5-POS | M5 | TestTCPPlan_LastACKNoPacketIndexInc | 启用终止, 读所有包 | 最后一个 ACK 后 channel 关闭; 该包 PacketIndex 为最大值, 不再递增(良性) | REAL | 与之前包递增模式不一致 |
| E1-POS | E1 | TestTCPPlan_PayloadExactMSSMultiple | Payload=2920B (1460*2), MSS=1460 | 恰好 2 段 [1460,1460], 4 包, 无余数 | REAL | |
| E2-POS | E2 | TestTCPPlan_PayloadSingleByte | Payload=1B, MSS=1460 | 1 段 segmentSize=1, 2 包 | REAL | |
| E3-POS | E3 | TestTCPPlan_MSSMinimum | MSS=1, Payload=1000B | 1000 段, 每段 1B payload, 2000 包 (会阻塞 256 缓冲) | REAL | 需并发消费 channel |
| E4-POS | E4 | TestTCPPlan_MSSLarge | MSS=65535, Payload=100000B | 2 段 [65535,34465], 4 包 | REAL | |
| E5-POS | E5 | TestTCPPlan_PayloadMSSPlusOne | Payload=1461B, MSS=1460 | 2 段 [1460,1], 4 包 | REAL | |
| E6-POS | E6 | TestTCPPlan_BothIPsEmpty | SrcIP="",DstIP="",SrcPort=100,DstPort=200 | flowID=="--100-200"; 所有包 L3.SrcIP=="" L3.DstIP=="" | REAL | |
| E7-POS | E7 | TestTCPPlan_SrcIPOnly | SrcIP="10.0.0.1",DstIP="" | flowID=="10.0.0.1--100-200"; DstIP 为空 | REAL | |
| E8-POS | E8 | TestTCPPlan_DstIPOnly | SrcIP="",DstIP="10.0.0.2" | flowID=="-10.0.0.2-100-200"; SrcIP 为空 | REAL | |
| E9-POS | E9 | TestTCPPlan_IPv6Addresses | SrcIP="::1",DstIP="fe80::1" | err==nil; flowID=="::1-fe80::1-100-200"; 但 EtherType 仍 0x0800(IPv4, 非 0x86DD) | REAL | 规划器不拒 IPv6, 但 L2 硬编码 IPv4 |
| E10-POS | E10 | TestTCPPlan_MaxPort | SrcPort=65535,DstPort=65535 | err==nil; 包 L4.SrcPort==65535 DstPort==65535 | REAL | uint16 边界 |
| E11-POS | E11 | TestTCPPlan_ConfigAllZero | spec.TCP=&TCPConfig{false,false,0,0,0,0,0} | Handshake/Termination=false; MSS 回退 1460; winSize 回退 65535 | REAL | |

## 组件: udp.go Validate (31-49)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| U1-POS | U1 | TestUDPValidate_ValidSrcIP | SrcIP="192.168.1.1",其它有效 | err==nil | REAL | |
| U2-NEG | U2 | TestUDPValidate_InvalidSrcIP | SrcIP="not-an-ip" | err contains "invalid source IP: not-an-ip" | REAL | |
| U3-POS | U3 | TestUDPValidate_EmptySrcIP | SrcIP="" | err==nil (跳过) | REAL | |
| U4-POS | U4 | TestUDPValidate_ValidDstIP | DstIP="10.0.0.1" | err==nil | REAL | |
| U5-NEG | U5 | TestUDPValidate_InvalidDstIP | DstIP="bad-address" | err contains "invalid destination IP" | REAL | |
| U6-POS | U6 | TestUDPValidate_EmptyDstIP | DstIP="" | err==nil (跳过) | REAL | |
| U7-NEG | U7 | TestUDPValidate_SrcPortZero | SrcPort=0 | err contains "source port is required" | REAL | |
| U9-NEG | U9 | TestUDPValidate_DstPortZero | SrcPort=12345,DstPort=0 | err contains "destination port is required" | REAL | |
| U11-NEG | U11 | TestUDPValidate_SrcIPCheckedFirst | SrcIP="bad1",DstIP="bad2" | err contains "invalid source IP" (SrcIP 先) | REAL | 短路 |
| U13-NEG | U13 | TestUDPValidate_BothPortsZero | SrcPort=0,DstPort=0 | err contains "source port is required" (SrcPort 先) | REAL | 短路 |
| U14-NEG | U14 | TestUDPValidate_OnlyDstPortZero | SrcPort=12345,DstPort=0 | err contains "destination port is required" | REAL | |
| U15-POS | U15 | TestUDPValidate_AllValid | 全字段有效 | err==nil | REAL | |

## 组件: udp.go Plan 入口 (52-55)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| U16-NEG | U16 | TestUDPPlan_ValidateFail | SrcPort=0 | 返回 (nil, err) | REAL | |
| U17-POS | U17 | TestUDPPlan_ValidatePass | 有效 spec | 返回 (non-nil chan, nil); cap==256 | REAL | |

## 组件: udp.go Plan goroutine (59-118)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| U18-POS | U18 | TestUDPPlan_TTLDefault | spec.TTL=0 | L3.TTL==64 | REAL | |
| U19-POS | U19 | TestUDPPlan_TTLMin | spec.TTL=1 | L3.TTL==1 | REAL | |
| U21-POS | U21 | TestUDPPlan_TTLMax | spec.TTL=255 | L3.TTL==255 | REAL | uint8 边界 |
| U22-POS | U22 | TestUDPPlan_UDPNilOnePacket | spec.UDP=nil | 仅 1 包 (request), direction="up" | REAL | nil 短路 && |
| U23-POS | U23 | TestUDPPlan_ResponseFalseOnePacket | spec.UDP=&UDPConfig{Response:false} | 仅 1 包 | REAL | |
| U24-POS | U24 | TestUDPPlan_ResponseTrueTwoPackets | spec.UDP=&UDPConfig{Response:true} | 2 包: request(up) + response(down) | REAL | |
| U25-POS | U25 | TestUDPPlan_FlowIDNormal | SrcIP="1.1.1.1",DstIP="2.2.2.2",SrcPort=100,DstPort=200 | flowID=="1.1.1.1-2.2.2.2-100-200" | REAL | |
| U26-POS | U26 | TestUDPPlan_FlowIDEmptySrcIP | SrcIP="" | flowID=="-2.2.2.2-100-200" | REAL | |
| U27-POS | U27 | TestUDPPlan_FlowIDEmptyDstIP | DstIP="" | flowID=="1.1.1.1--100-200" | REAL | |
| U28-POS | U28 | TestUDPPlan_FlowIDBothEmpty | SrcIP="",DstIP="" | flowID=="--100-200" | REAL | |
| U29-POS | U29 | TestUDPPlan_IPIDNoResponse | spec.UDP.Response=false | request 包 L3.IPID==1 | REAL | |
| U30-POS | U30 | TestUDPPlan_IPIDWithResponse | spec.UDP.Response=true | request IPID==1, response IPID==2 | REAL | |
| U31-POS | U31 | TestUDPPlan_RequestDirectionFields | 有效 spec | request: direction="up", L2.SrcMAC=spec.SrcMAC, L2.DstMAC=spec.DstMAC, L3/IPs/ports 正向 | REAL | |
| U32-POS | U32 | TestUDPPlan_ResponseDirectionFields | spec.UDP.Response=true | response: direction="down", MACs 交换, IPs 交换, ports 交换 | REAL | |
| U33-POS | U33 | TestUDPPlan_PayloadNil | spec.Payload=nil | request.Payload==nil | REAL | |
| U34-POS | U34 | TestUDPPlan_PayloadEmpty | spec.Payload=[]byte{} | request.Payload 为空切片 (len==0) | REAL | |
| U35-POS | U35 | TestUDPPlan_PayloadSharedRef | spec.Payload=[]byte("hello") | request.Payload=="hello"; 共享底层数组: Plan 后修改 spec.Payload[0]='X', 已发送包 Payload[0] 也变 'X' | REAL | 引用非副本 |
| U36-POS | U36 | TestUDPPlan_MACsBothEmpty | SrcMAC="",DstMAC="" | L2.SrcMAC=="", L2.DstMAC=="" | REAL | |
| U37-POS | U37 | TestUDPPlan_MACsBothSet | SrcMAC="aa:bb:cc:dd:ee:ff",DstMAC="00:11:22:33:44:55" | response 时 MACs 交换 | REAL | |
| U38-POS | U38 | TestUDPPlan_OnlySrcMAC | 仅 SrcMAC 设 | response: SrcMAC=DstMAC(orig 空), DstMAC=SrcMAC | REAL | |
| U39-POS | U39 | TestUDPPlan_OnlyDstMAC | 仅 DstMAC 设 | response: SrcMAC=DstMAC, DstMAC=SrcMAC(orig 空) | REAL | |
| U40-POS | U40 | TestUDPPlan_SharedTimestamp | 有效 spec | request/response Timestamp 完全相同 (单一 time.Now()) | REAL | |
| U41-POS | U41 | TestUDPPlan_L4Protocol | 有效 spec | L4.Protocol=="udp" (硬编码) | REAL | |
| U42-POS | U42 | TestUDPPlan_L3Protocol | 有效 spec | L3.Protocol==17 (硬编码) | REAL | |
| U43-POS | U43 | TestUDPPlan_EtherType | 有效 spec | L2.EtherType==0x0800 (硬编码 IPv4) | REAL | |
| U49-POS | U49 | TestUDPPlan_ChannelCloseOnePacket | spec.UDP=nil | 读 1 包后 channel 关闭 (range 退出) | REAL | |
| U50-POS | U50 | TestUDPPlan_ChannelCloseTwoPackets | spec.UDP.Response=true | 读 2 包后 channel 关闭 | REAL | |

## 组件: udp.go -- 上下文取消 (U44-U48)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| U46-NEG | U46 (ctx 取消泄漏) | TestUDPPlan_ContextCancelIgnored | ctx 已 cancel 后调用 Plan, 读所有包 | **已知 bug**: goroutine 不检查 ctx.Done(), 仍发送全部包。失败测试先行: 断言 cancel 后不再发送 (当前失败, 仍发完) | REAL | 无 select |
| U47-NEG | U47 (channel 满泄漏) | TestUDPPlan_BlockedSendLeak | ctx cancel + 不读 channel | UDP 仅 1-2 包, 256 缓冲不会满; 但 goroutine 仍不响应 cancel。断言 cancel 后 goroutine 退出 (当前: 退出因为包少, 但非因 cancel) | REAL | UDP 包少, 泄漏风险低但 ctx 仍被忽略 |

## 组件: http.go Validate (32-51)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| H1-POS | H1 | TestHTTPValidate_ValidIPs | SrcIP="192.168.1.1",DstIP="192.168.1.2",DstPort=80 | err==nil | REAL | |
| H2-NEG | H2 | TestHTTPValidate_InvalidSrcIP | SrcIP="invalid" | err contains "invalid source IP: invalid" | REAL | 短路, DstIP 不校验 |
| H3-NEG | H3 | TestHTTPValidate_InvalidDstIP | DstIP="invalid" | err contains "invalid destination IP" | REAL | |
| H4-POS | H4 | TestHTTPValidate_BothIPsEmpty | SrcIP="",DstIP="" | err==nil | REAL | |
| H5-POS | H5 | TestHTTPValidate_OneIPEmpty | SrcIP="",DstIP="10.0.0.1" | err==nil | REAL | |
| H6-NEG | H6 | TestHTTPValidate_PartialIP | SrcIP="192.168.1" | err contains "invalid source IP" | REAL | |
| H7-POS | H7 | TestHTTPValidate_DstPortDefaultLocal | spec.DstPort=0 | err==nil; 但调用者 spec.DstPort 仍为 0 (Validate 修改局部副本) | REAL | pass-by-value |
| H7-NEG | H7 (DstPort bug) | TestHTTPPlan_DstPortZeroNotDefaulted | spec.DstPort=0, 通过 Plan 读包 | **已知 bug**: 所有包 L4.DstPort==0 (非 80)。失败测试先行: 断言 DstPort==80 (当前失败) | REAL | Validate 的 spec.DstPort=80 不影响 Plan 用的原 spec |

## 组件: http.go Plan 入口 (54-57)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| H8-NEG | H8 | TestHTTPPlan_ValidateFail | 无效 IP | 返回 (nil, err) | REAL | |
| H9-POS | H9 | TestHTTPPlan_ValidatePass | 有效 spec | 返回 (non-nil chan, nil); cap==256 | REAL | |

## 组件: http.go Plan goroutine -- 默认值 (68-99)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| H10-POS | H10 | TestHTTPPlan_ConfigNilDefaults | spec.HTTP=nil | 请求包 Payload 含 "GET / HTTP/1.1" | REAL | 默认 Method=GET, URI=/ |
| H11-POS | H11 | TestHTTPPlan_ConfigProvided | spec.HTTP=&HTTPConfig{Method:"POST",URI:"/api"} | 请求 Payload 含 "POST /api HTTP/1.1" | REAL | |
| H12-POS | H12 | TestHTTPPlan_TransactionsDefault | httpConfig.Transactions=0 | transactions=1, 总 11 包 (3+2+4) | REAL | |
| H13-POS | H13 | TestHTTPPlan_TransactionsMultiple | httpConfig.Transactions=5 | 5 请求-响应对, 总 17 包 (3+10+4) | REAL | 同连接无重握手 |
| H14-POS | H14 | TestHTTPPlan_TTLDefault | spec.TTL=0 | L3.TTL==64 | REAL | |
| H15-POS | H15 | TestHTTPPlan_TTLProvided | spec.TTL=128 | L3.TTL==128 | REAL | |
| H16-POS | H16 | TestHTTPPlan_IPIDSequential | 有效 spec | IPIDs 按包序递增 [1,2,3,...] | REAL | |
| H18-POS | H18 | TestHTTPPlan_DFDefault | spec.Flags=0, spec.FragOffset=0 | 所有包 L3.Flags==IPFlagDF(0x02) (L3Base 默认) | REAL | L3Base 行为 |
| H20-POS | H20 | TestHTTPPlan_TOSOverrides | spec.TOS=0xB8 | L3.DSCP==0x2E(46), L3.ECN==0x00 | REAL | L3Base: TOS 覆盖 DSCP/ECN |
| H55-POS | H55 | TestHTTPPlan_TransactionsZero | httpConfig.Transactions=0 | transactions=1, 11 包 | REAL | |
| H56-POS | H56 | TestHTTPPlan_TransactionsNegative | httpConfig.Transactions=-5 | transactions=1, 11 包 | REAL | |
| H58-POS | H58 | TestHTTPPlan_MinPacketCount | 任意有效 spec | 最少 11 包 (3+2*1+4) | REAL | 无少于 11 的路径 |
| H62-POS | H62 | TestHTTPPlan_AllPacketsSameTimestamp | transactions=5 | 所有包 Timestamp 完全相同 | REAL | 单一 time.Now() |

## 组件: http.go Plan goroutine -- 握手 (103-173)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| H21-POS | H21 | TestHTTPPlan_SYNPacketFields | 有效 spec | 包0: PacketIndex=0, direction="up", Flags=0x02, Seq=1000, L3.Protocol=6, L4.Protocol="tcp", WindowSize=65535, L3.IPID=1 | REAL | |
| H22-POS | H22 | TestHTTPPlan_EmptyMACs | SrcMAC="",DstMAC="" | L2.SrcMAC=="", L2.DstMAC=="" | REAL | 无 MAC 校验 |
| H24-POS | H24 | TestHTTPPlan_SYNACKFields | 有效 spec | 包1: direction="down", Flags=0x12, Seq=2000, Ack=1001, MACs/IPs/ports 交换, IPID=2 | REAL | |
| H25-POS | H25 | TestHTTPPlan_HandshakeACKFields | 有效 spec | 包2: direction="up", Flags=0x10, Seq=1001, Ack=2001, IPID=3 | REAL | |

## 组件: http.go Plan goroutine -- 事务循环 (176-230)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| H27-POS | H27 | TestHTTPPlan_SingleTransaction | transactions=1 | 1 请求(up, Flags=0x18) + 1 响应(down, Flags=0x18) | REAL | |
| H28-POS | H28 | TestHTTPPlan_MultipleTransactions | transactions=5 | 10 事务包; clientSeq 随每请求 payload 长度递增, serverSeq 随每响应递增 | REAL | |
| H29-POS | H29 | TestHTTPPlan_RequestPayloadFields | Method="POST",Body="data" | 请求: direction="up", Flags=0x18, Payload 含 "POST", "Content-Length: 4", "data" | REAL | |
| H30-POS | H30 | TestHTTPPlan_ResponsePayloadFields | 有效 spec | 响应: direction="down", Flags=0x18, Payload 含 "HTTP/1.1 200 OK" | REAL | |
| H31-POS | H31 | TestHTTPPlan_ClientSeqOverflow | clientSeq 接近 2^32-1, 大 body | clientSeq += uint32(len) 静默回绕 (Go 无符号溢出定义) | REAL | TCP 32 位序号回绕合法 |

## 组件: http.go Plan goroutine -- 终止 (234-329)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| H32-POS | H32 | TestHTTPPlan_ClientFINFields | 有效 spec | FIN: direction="up", Flags=0x11, Seq=clientSeq, Ack=serverSeq | REAL | |
| H33-POS | H33 | TestHTTPPlan_ServerACKofFIN | 有效 spec | ACK: direction="down", Flags=0x10, Seq=serverSeq, Ack=clientSeq | REAL | |
| H34-POS | H34 | TestHTTPPlan_ServerFINFields | 有效 spec | FIN: direction="down", Flags=0x11, Seq=serverSeq, Ack=clientSeq | REAL | |
| H35-POS | H35 | TestHTTPPlan_ClientACKofServerFIN | 有效 spec | ACK: direction="up", Flags=0x10, Seq=clientSeq, Ack=serverSeq | REAL | |
| H36-POS | H36 | TestHTTPPlan_ChannelCloseAfterGoroutine | 有效 spec | 所有包发完后 channel 关闭 (defer close) | REAL | |

## 组件: http.go -- 上下文取消 (H37-H42)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| H38-NEG | H38 (ctx 取消泄漏) | TestHTTPPlan_ContextCancelLeak | ctx cancel + 不读 channel | **已知 bug**: goroutine 不检查 ctx.Done()。失败测试先行: 断言 cancel 后 goroutine 1s 内退出 (当前失败) | REAL | |
| H39-NEG | H39 (channel 满泄漏) | TestHTTPPlan_TransactionBufferFullLeak | transactions=200 (>256 包), 读 0 包 + cancel | **已知 bug**: 256 包填满后 goroutine 永久阻塞。断言 2s 后仍存活; 修复后应退出 | REAL | 无背压机制 |
| H42-NEG | H42 (closed channel panic) | TestHTTPPlan_SendOnClosedChannelPanic | 调用方提前关闭返回的 channel | goroutine 在 configChan<- 处 panic (send on closed channel), 无 recover | REAL | 未处理的 panic |

## 组件: http.go buildHTTPRequest (335-361)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| H43-POS | H43 | TestBuildHTTPRequest_EmptyMethodDefaultsGET | config.Method="" | 返回以 "GET " 开头; 且 config.Method 被改为 "GET" (副作用) | REAL | 指针接收者修改调用者 |
| H44-POS | H44 | TestBuildHTTPRequest_EmptyURIDefaultsRoot | config.URI="" | 返回含 " / HTTP/1.1"; config.URI 被改为 "/" | REAL | 副作用 |
| H45-POS | H45 | TestBuildHTTPRequest_CustomHeaders | Headers={"Accept":"application/json","X-Custom":"v"} | 返回含两行 header (顺序非确定, 分别断言存在) | REAL | Go map 顺序随机 |
| H46-POS | H46 | TestBuildHTTPRequest_NilHeaders | Headers=nil | 返回无自定义 header | REAL | range nil 安全 |
| H47-POS | H47 | TestBuildHTTPRequest_EmptyHeaders | Headers=map[string]string{} | 返回无自定义 header | REAL | |
| H48-POS | H48 | TestBuildHTTPRequest_BodyAddsContentLength | Body="{\"key\":\"value\"}" | 返回含 "Content-Length: 15\r\n" | REAL | |
| H49-POS | H49 | TestBuildHTTPRequest_NoBodyNoContentLength | Body="" | 返回无 "Content-Length" | REAL | |
| H50-POS | H50 | TestBuildHTTPRequest_BodyAppended | Body="payload_data" | 返回 body 在空行后: "...HTTP/1.1\r\nHost: localhost\r\n\r\npayload_data" | REAL | |
| H52-NEG | H52 | TestBuildHTTPRequest_CRLFInjection | Method="GET\r\nX-Injected: true" | 返回含注入 header (无消毒) | REAL | 安全测试点 |

## 组件: http.go buildHTTPResponse (364-377)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| H53-POS | H53 | TestBuildHTTPResponse_KeepAlive | config.KeepAlive=true | 返回含 "Connection: keep-alive\r\n" | REAL | |
| H54-POS | H54 | TestBuildHTTPResponse_NoKeepAlive | config.KeepAlive=false | 返回无 "Connection" header | REAL | |

## 组件: http.go -- VLAN 传播 (H61)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| H61-NEG | H61 (VLAN 丢失) | TestHTTPPlan_VLANNotPropagated | spec.VLAN=&VLAN{ID:100,Priority:3} | **已知 bug**: 所有包 L2.VLAN==nil。失败测试先行: 断言 L2.VLAN.ID==100 (当前失败) | REAL | L2Config 字面量省略 VLAN |

## 组件: dns.go Validate (39-66)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| D1-POS | D1 | TestDNSValidate_ValidSrcIP | SrcIP="192.168.1.1" | err==nil | REAL | |
| D2-NEG | D2 | TestDNSValidate_InvalidSrcIP | SrcIP="not-an-ip" | err contains "invalid source IP" | REAL | |
| D3-POS | D3 | TestDNSValidate_EmptySrcIP | SrcIP="" | err==nil | REAL | |
| D4-POS | D4 | TestDNSValidate_ValidDstIP | DstIP="10.0.0.1" | err==nil | REAL | |
| D5-NEG | D5 | TestDNSValidate_InvalidDstIP | DstIP="bad" | err contains "invalid destination IP" | REAL | |
| D6-POS | D6 | TestDNSValidate_EmptyDstIP | DstIP="" | err==nil | REAL | |
| D7-POS | D7 | TestDNSValidate_DstPortDefaultLocal | spec.DstPort=0 | err==nil; 调用者 spec.DstPort 仍为 0 (局部副本) | REAL | pass-by-value |
| D7-NEG | D7 (DstPort bug) | TestDNSPlan_DstPortZeroNotDefaulted | spec.DstPort=0, 通过 Plan 读包 | **已知 bug**: 查询包 L4.DstPort==0 (非 53)。失败测试先行: 断言 DstPort==53 (当前失败) | REAL | 与 HTTP 同类 bug |
| D8-POS | D8 | TestDNSValidate_DstPortExplicit | spec.DstPort=5353 | err==nil; port 保持 5353 | REAL | |
| D9-NEG | D9 | TestDNSValidate_ConfigNil | spec.DNS=nil | err contains "DNS config is required" | REAL | |
| D10-NEG | D10 | TestDNSValidate_DomainEmpty | spec.DNS=&DNSConfig{Domain:""} | err contains "domain is required" | REAL | |
| D11-POS | D11 | TestDNSValidate_AllValid | 全字段有效 | err==nil | REAL | |

## 组件: dns.go Plan 入口 (69-72)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| D12-NEG | D12 | TestDNSPlan_ValidateFail | spec.DNS=nil | 返回 (nil, err) | REAL | |
| D13-POS | D13 | TestDNSPlan_ValidatePass | 有效 spec | 返回 (non-nil chan, nil); cap==256 | REAL | |

## 组件: dns.go Plan goroutine (76-139)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| D14-POS | D14 | TestDNSPlan_TTLDefault | spec.TTL=0 | L3.TTL==64 | REAL | |
| D15-POS | D15 | TestDNSPlan_TTLProvided | spec.TTL=128 | L3.TTL==128 | REAL | |
| D16-POS | D16 | TestDNSPlan_QueryPacketFields | 有效 spec | 包0: PacketIndex=0, direction="up", L4.Protocol="udp", L3.Protocol=17, L2.EtherType=0x0800, Payload 为 DNS query 字节 (含 0x1234 TxID, 0x0100 flags) | REAL | 无条件发送 |
| D17-POS | D17 | TestDNSPlan_ResponseEnabled | spec.DNS.Response=true, ResponseIP="1.2.3.4" | 包1: direction="down", MACs/IPs/ports 交换, Payload 含 DNS response 字节 (含 1.2.3.4) | REAL | |
| D18-POS | D18 | TestDNSPlan_ResponseDisabled | spec.DNS.Response=false | 仅 1 包, channel 关闭 | REAL | |

## 组件: dns.go -- 上下文取消 (D19-D20)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| D19-NEG | D19-D20 | TestDNSPlan_ContextCancelIgnored | ctx cancel 后调用 Plan, 读所有包 | **已知 bug**: goroutine 不检查 ctx.Done(), 仍发送。失败测试先行: 断言 cancel 后不发 (当前失败) | REAL | |

## 组件: dns.go buildDNSResponse (172-213)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| D21-POS | D21 | TestBuildDNSResponse_ValidIPv4 | responseIP="8.8.8.8", queryType=TypeA | 响应 payload 末尾含 4 字节 [8,8,8,8] | REAL | |
| D22-POS | D22 | TestBuildDNSResponse_InvalidIPFallback | responseIP="bad" | 回退到 127.0.0.1, payload 含 [127,0,0,1] | REAL | |
| D22-BR1 | D22 | TestBuildDNSResponse_EmptyIPFallback | responseIP="" | 回退到 127.0.0.1 | REAL | |
| D23-NEG | D23 (AAAA bug) | TestBuildDNSResponse_IPv6AAAA_Malformed | responseIP="2001:db8::1", queryType=TypeAAAA(28) | **已知 bug**: ip.To4() 返回 nil, ipBytes 为 nil, append 不加 RDATA 字节; answer RDLENGTH 仍为 4 但实际 0 字节。失败测试先行: 断言 RDATA 为 16 字节 IPv6 (当前失败) | REAL | AAAA 响应畸形 |

## 组件: dns.go splitLabels (230-248)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| D24-POS | D24 | TestSplitLabels_Normal | "example.com" | ["example","com"] | REAL | |
| D25-POS | D25 | TestSplitLabels_SingleLabel | "localhost" | ["localhost"] | REAL | |
| D26-POS | D26 | TestSplitLabels_EmptyString | "" | [] (空切片) | REAL | |
| D27-POS | D27 | TestSplitLabels_TrailingDot | "example.com." | ["example","com"] (无空尾标) | REAL | |
| D28-NEG | D28 (连续点 bug) | TestSplitLabels_ConsecutiveDotsDropped | "example..com" | **潜在 bug**: 返回 ["example","com"] (空标签被丢弃, 应编码为 0x00)。失败测试先行: 断言含空标签 (当前失败) | REAL | DNS 线格式要求空标签 |

## 组件: dns.go encodeDomainName (216-227)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| D30-POS | D30 | TestEncodeDomainName_Normal | ["example","com"] | []byte{7,'e','x','a','m','p','l','e',3,'c','o','m',0} | REAL | null 终止符 |
| D31-POS | D31 | TestEncodeDomainName_EmptyLabels | [] | []byte{0} (仅根终止符) | REAL | |

## 组件: icmp.go Validate (34-46)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| I1-POS | I1 | TestICMPValidate_ValidSrcIP | SrcIP="10.0.0.1" | err==nil | REAL | |
| I2-NEG | I2 | TestICMPValidate_InvalidSrcIP | SrcIP="bad" | err contains "invalid source IP" | REAL | |
| I3-POS | I3 | TestICMPValidate_EmptySrcIP | SrcIP="" | err==nil | REAL | |
| I4-POS | I4 | TestICMPValidate_ValidDstIP | DstIP="10.0.0.2" | err==nil | REAL | |
| I5-NEG | I5 | TestICMPValidate_InvalidDstIP | DstIP="bad" | err contains "invalid destination IP" | REAL | |
| I6-POS | I6 | TestICMPValidate_EmptyDstIP | DstIP="" | err==nil | REAL | |
| I7-POS | I7 | TestICMPValidate_AllValid | 全字段有效 | err==nil | REAL | |

## 组件: icmp.go Plan (49-139)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| I8-NEG | I8 | TestICMPPlan_ValidateFail | SrcIP="bad" | 返回 (nil, err) | REAL | |
| I9-POS | I9 | TestICMPPlan_ValidatePass | 有效 spec | 返回 (non-nil chan, nil); cap==256 | REAL | |
| I10-POS | I10 | TestICMPPlan_TTLDefault | spec.TTL=0 | L3.TTL==64 | REAL | |
| I11-POS | I11 | TestICMPPlan_TTLProvided | spec.TTL=255 | L3.TTL==255 | REAL | |
| I12-POS | I12 | TestICMPPlan_ConfigNilDefaults | spec.ICMP=nil | 包0 Metadata["icmp_type"]==8, Metadata["icmp_code"]==0; Payload 含 Type=8,Code=0,Seq=1,Data="ping" | REAL | 默认 EchoRequest |
| I13-POS | I13 | TestICMPPlan_ConfigProvided | spec.ICMP=&ICMPConfig{Type:3,Code:0,Sequence:42,Data:[]byte("custom")} | Metadata["icmp_type"]==3; Payload 含 Type=3, Seq=42, Data="custom" | REAL | |
| I14-POS | I14 | TestICMPPlan_EchoRequestSent | 任意有效 spec | 包0: PacketIndex=0, direction="up", L4.Protocol="icmp", L3.Protocol=1, L2.EtherType=0x0800, Payload 为 ICMP 字节 | REAL | 无条件发送 |
| I15-POS | I15 | TestICMPPlan_TypeEchoRequestGetsReply | spec.ICMP.Type=8 | 包1: PacketIndex=1, direction="down", Metadata["icmp_type"]==0(EchoReply), Payload 含 Type=0 | REAL | |
| I16-POS | I16 | TestICMPPlan_TypeNotEchoNoReply | spec.ICMP.Type=3 | 仅 1 包, 无响应 | REAL | |
| I17-POS | I17 | TestICMPPlan_TypeEchoReplyPrimary | spec.ICMP.Type=0 | 仅 1 包 Type=0; Type 0 != TypeEchoRequest(8), 无响应 | REAL | |

## 组件: icmp.go calculateChecksum (169-183)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| I19-POS | I19 | TestICMPChecksum_EvenLength | 8 字节标准 ICMP 头 | checksum 为正确 1 补码和 (与已知值比对) | REAL | |
| I20-POS | I20 | TestICMPChecksum_OddLength | 9 字节 (头+1 数据) | 末字节作零填充字高字节; checksum 正确 | REAL | |
| I21-POS | I21 | TestICMPChecksum_Empty | []byte{} | sum==0, ^uint16(0)==0xFFFF | REAL | |
| I22-POS | I22 | TestICMPChecksum_SingleByte | []byte{0x08} | sum==0x0800, ^uint16(0x0800)==0xF7FF | REAL | |

## 组件: icmp.go -- 上下文取消 (I18)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| I18-NEG | I18 | TestICMPPlan_ContextCancelIgnored | ctx cancel 后调用 Plan, 读所有包 | **已知 bug**: goroutine 不检查 ctx.Done()。失败测试先行: 断言 cancel 后不发 (当前失败) | REAL | |

## 组件: arp.go Validate (35-54)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| A1-POS | A1 | TestARPValidate_ValidSrcIP | SrcIP="192.168.1.1" | err==nil | REAL | |
| A2-NEG | A2 | TestARPValidate_InvalidSrcIP | SrcIP="bad" | err contains "invalid source IP" | REAL | |
| A3-POS | A3 | TestARPValidate_EmptySrcIP | SrcIP="" | err==nil | REAL | |
| A4-POS | A4 | TestARPValidate_ValidDstIP | DstIP="192.168.1.2" | err==nil | REAL | |
| A5-NEG | A5 | TestARPValidate_InvalidDstIP | DstIP="bad" | err contains "invalid destination IP" | REAL | |
| A6-POS | A6 | TestARPValidate_EmptyDstIP | DstIP="" | err==nil | REAL | |
| A7-NEG | A7 | TestARPValidate_ConfigNil | spec.ARP=nil | err contains "ARP config is required" | REAL | |
| A8-POS | A8 | TestARPValidate_AllValid | 全字段有效 | err==nil | REAL | |

## 组件: arp.go Plan (57-148)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| A9-NEG | A9 | TestARPPlan_ValidateFail | spec.ARP=nil | 返回 (nil, err) | REAL | |
| A10-POS | A10 | TestARPPlan_ValidatePass | 有效 spec | 返回 (non-nil chan, nil); cap==16 (ARP 缓冲区小) | REAL | |
| A11-POS | A11 | TestARPPlan_ConfigNilDefaults | spec.ARP=nil (防御性, 不可达) | 默认 Operation=1 (Request) | REAL | Validate 已挡, 但 goroutine 仍有 nil 检查 |
| A12-POS | A12 | TestARPPlan_ConfigProvided | spec.ARP=&ARPConfig{Operation:2} | 使用 Operation=2 | REAL | |
| A13-POS | A13 | TestARPPlan_RequestPacketFields | 有效 spec | 包0: PacketIndex=0, direction="up", L2.DstMAC=="ff:ff:ff:ff:ff:ff", L2.EtherType==0x0806, L3.Protocol==0, L4.Protocol=="arp", Payload 28 字节, Metadata["arp_operation"]==Operation | REAL | 无条件发送 |
| A14-POS | A14 | TestARPPlan_OperationRequestGetsReply | spec.ARP.Operation=1 | 包1: PacketIndex=1, direction="down", Metadata["arp_operation"]==2(Reply), Payload 28 字节, MACs 交换 | REAL | |
| A15-POS | A15 | TestARPPlan_OperationReplyOnly | spec.ARP.Operation=2 | 仅 1 包, 无回复 | REAL | |

## 组件: arp.go -- 上下文取消 (A16)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| A16-NEG | A16 | TestARPPlan_ContextCancelIgnored | ctx cancel 后调用 Plan, 读所有包 | **已知 bug**: goroutine 不检查 ctx.Done()。失败测试先行: 断言 cancel 后不发 (当前失败) | REAL | |

## 组件: arp.go buildARPPacket (151-211)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| A17-POS | A17 | TestBuildARPPacket_OperationFromSpec | spec.ARP.Operation=2 | 字节[6:8]==[]byte{0x00,0x02} | REAL | |
| A18-POS | A18 | TestBuildARPPacket_OperationDefault | spec.ARP=nil | 字节[6:8]==[]byte{0x00,0x01} (Request) | REAL | |
| A19-POS | A19 | TestBuildARPPacket_SrcMACValid | SrcMAC="00:11:22:33:44:55" | 字节[8:14]==[]byte{0x00,0x11,0x22,0x33,0x44,0x55} | REAL | |
| A20-POS | A20 | TestBuildARPPacket_SrcMACInvalid | SrcMAC="invalid" | 字节[8:14]==全零 (ParseMAC 错误静默丢弃) | REAL | |
| A20-BR1 | A20 | TestBuildARPPacket_SrcMACEmpty | SrcMAC="" | 字节[8:14]==全零 | REAL | |
| A21-POS | A21 | TestBuildARPPacket_SrcIPValid | SrcIP="10.0.0.1" | 字节[14:18]==[]byte{10,0,0,1} | REAL | |
| A22-POS | A22 | TestBuildARPPacket_SrcIPEmpty | SrcIP="" | 字节[14:18]==全零 | REAL | |
| A23-POS | A23 | TestBuildARPPacket_SrcIPv6 | SrcIP="::1" | srcIP.To4()==nil, 字节[14:18]==全零 | REAL | ARP 硬编码 IPv4 |
| A24-POS | A24 | TestBuildARPPacket_TargetMACValid | spec.ARP.TargetMAC="aa:bb:cc:dd:ee:ff" | 字节[18:24]==该 MAC | REAL | |
| A25-POS | A25 | TestBuildARPPacket_TargetMACAbsent | spec.ARP.TargetMAC="" | 字节[18:24]==全零 | REAL | 请求标准 |
| A26-POS | A26 | TestBuildARPPacket_TargetMACInvalid | spec.ARP.TargetMAC="bad" | 字节[18:24]==全零 (静默丢弃) | REAL | |
| A27-POS | A27 | TestBuildARPPacket_TargetIPValid | DstIP="10.0.0.2" | 字节[24:28]==[]byte{10,0,0,2} | REAL | |
| A28-POS | A28 | TestBuildARPPacket_TargetIPEmpty | DstIP="" | 字节[24:28]==全零 | REAL | |
| A29-POS | A29 | TestBuildARPPacket_TargetIPv6 | DstIP="2001:db8::1" | dstIP.To4()==nil, 字节[24:28]==全零 | REAL | |

## 组件: arp.go buildARPReply (214-266)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| A30-POS | A30 | TestBuildARPReply_SenderMACValid | DstMAC="aa:bb:cc:dd:ee:ff" | 字节[8:14]==该 MAC (取自 spec.DstMAC) | REAL | |
| A31-POS | A31 | TestBuildARPReply_SenderMACEmpty | DstMAC="" | 字节[8:14]==全零 | REAL | |
| A32-POS | A32 | TestBuildARPReply_SenderIPValid | DstIP="10.0.0.2" | 字节[14:18]==[]byte{10,0,0,2} | REAL | |
| A33-POS | A33 | TestBuildARPReply_SenderIPEmpty | DstIP="" | 字节[14:18]==全零 | REAL | |
| A34-POS | A34 | TestBuildARPReply_SenderIPv6 | DstIP="::1" | dstIP.To4()==nil, 字节[14:18]==全零 | REAL | |
| A35-POS | A35 | TestBuildARPReply_TargetMACValid | SrcMAC="00:11:22:33:44:55" | 字节[18:24]==该 MAC (取自 spec.SrcMAC) | REAL | |
| A36-POS | A36 | TestBuildARPReply_TargetMACEmpty | SrcMAC="" | 字节[18:24]==全零 | REAL | |
| A37-POS | A37 | TestBuildARPReply_TargetIPValid | SrcIP="10.0.0.1" | 字节[24:28]==[]byte{10,0,0,1} | REAL | |
| A38-POS | A38 | TestBuildARPReply_TargetIPEmpty | SrcIP="" | 字节[24:28]==全零 | REAL | |
| A39-POS | A39 | TestBuildARPReply_TargetIPv6 | SrcIP="::1" | srcIP.To4()==nil, 字节[24:28]==全零 | REAL | |

## 组件: 跨层集成 -- planner -> Builder (端到端)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| INT-TCP-POS | 集成 | TestIntegration_TCPPlanToBuilder | TCP 完整流 spec | Plan 输出每包经 core.Builder.Build 生成字节; 帧以 DstMAC 开头, EtherType=0x0800, IPv4 头 protocol=6, TCP 头含正确 port/seq/ack; 无 error | REAL | planner->builder 端到端 |
| INT-HTTP-POS | 集成 | TestIntegration_HTTPPlanToBuilder | HTTP spec (transactions=2) | Build 输出含 HTTP 请求 payload 的 TCP 数据段字节; "GET / HTTP/1.1" 可在帧中定位 | REAL | |
| INT-DNS-POS | 集成 | TestIntegration_DNSPlanToBuilder | DNS spec | Build 输出 UDP 帧 (EtherType 0x0800, IP proto 17, UDP 头), DNS query 字节在 UDP payload 中 | REAL | |
| INT-ICMP-POS | 集成 | TestIntegration_ICMPPlanToBuilder | ICMP spec | Build 输出 ICMP 帧; ICMP checksum 字段与 calculateChecksum 一致; Type/Code/Seq 正确 | REAL | |
| INT-ARP-POS | 集成 | TestIntegration_ARPPlanToBuilder | ARP spec | Build 输出 ARP 帧 (EtherType 0x0806, 无 IP 头), 28 字节 ARP payload; 不含 20 字节 IPv4 头 | REAL | ARP 跳过 L3 |
| INT-VLAN-NEG | 集成 | TestIntegration_VLANFrameMissing | spec.VLAN 设, TCP/HTTP Plan->Build | **已知 bug**: 产出的以太网帧无 802.1Q tag (VLAN 未传播)。失败测试先行: 断言帧含 0x8100 TPID (当前失败) | REAL | 跨 planner+builder 的 VLAN 缺失 |

## 组件: 真实发包 (MANUAL)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| MAN-TCP-001 | TCP 真实发包 | TestTCP_RealNICPacketSequence | 完整 TCP 流, 发送到 enp135s0f0np0 | tcpdump 应见 SYN->SYN-ACK->ACK->DATA->ACK->FIN->ACK->FIN->ACK | MANUAL | 依赖真实网卡/内核. 命令: `sudo tcpdump -i enp135s0f0np0 -X -c 20 'tcp'`. 预期: 9 帧按序, Flags 序列正确 |
| MAN-TCP-002 | TCP 实时分段时序 | TestTCP_RealWireSegmentation | 1MB payload 多分段, 发送到网卡 | tcpdump 见连续分段, 序号连续, 帧间间隔合理 | MANUAL | 依赖真实线缆时序. 命令: `sudo tcpdump -i enp135s0f0np0 -vvv -c 200 'tcp'`. 预期: ~69 段, 序号无跳变 |
| MAN-UDP-001 | UDP 真实发包 | TestUDP_RealNICPacket | UDP 请求+响应, 发送到网卡 | tcpdump 见 2 个 UDP 包 (请求+响应) | MANUAL | 依赖真实网卡. 命令: `sudo tcpdump -i enp135s0f0np0 -X -c 10 'udp'`. 预期: 2 帧, ports 正反向 |
| MAN-HTTP-001 | HTTP 真实发包 | TestHTTP_RealNICPacket | HTTP 多事务, 发送到网卡 | tcpdump 见完整 TCP 流含 HTTP payload | MANUAL | 依赖真实网卡. 命令: `sudo tcpdump -i enp135s0f0np0 -X -c 50 'tcp port 80'`. 预期: "GET / HTTP/1.1" 在数据段 |
| MAN-DNS-001 | DNS 真实发包 | TestDNS_RealNICPacket | DNS 查询+响应, 发送到网卡 | tcpdump 见 2 个 UDP 包: DNS query + response | MANUAL | 依赖真实网卡. 命令: `sudo tcpdump -i enp135s0f0np0 -X -c 10 'udp port 53'`. 预期: TxID 0x1234, 域名编码可见 |
| MAN-ICMP-001 | ICMP 真实发包 | TestICMP_RealNICPacket | ICMP Echo Request, 发送到网卡 | tcpdump 见 ICMP Echo Request + Reply | MANUAL | 依赖真实网卡+内核响应. 命令: `sudo tcpdump -i enp135s0f0np0 -X -c 10 'icmp'`. 预期: Type 8 request, Type 0 reply |
| MAN-ARP-001 | ARP 真实发包 | TestARP_RealNICPacket | ARP Request, 发送到网卡 | tcpdump 见 ARP Request + Reply | MANUAL | 依赖真实网卡. 命令: `sudo tcpdump -i enp135s0f0np0 -X -c 10 'arp'`. 预期: Operation 1 request, 2 reply |
| MAN-ARP-002 | ARP 广播验证 | TestARP_RealWireBroadcast | ARP Request, 发送到网卡 | tcpdump -e 见目标 MAC 为 ff:ff:ff:ff:ff:ff | MANUAL | 依赖真实以太网广播. 命令: `sudo tcpdump -i enp135s0f0np0 -e -c 5 'arp'`. 预期: DstMAC 广播 |
| MAN-VLAN-001 | VLAN 真实发包 | TestVLAN_RealWire8021Q | spec.VLAN 设, 发送到网卡 | tcpdump -e 见 802.1Q tag (0x8100) -- 当前不会见 (bug) | MANUAL | 依赖真实网卡 802.1Q. 命令: `sudo tcpdump -i enp135s0f0np0 -e -c 5 'vlan'`. 预期: 当前无 VLAN tag (bug 证实); 修复后应见 tag ID 100 |

## 汇总

- 真实(REAL): 260 个
- 模拟(SIMULATED): 0 个
- 手动(MANUAL): 9 个
- 合计: 269 个测试点

> 说明: 规划器逻辑全部为纯内存 Go 代码 (产 PacketConfig 流), 可用 `go test -race` + `go vet` 全自动验证, 故无 SIMULATED。SIMULATED 仅在需模拟外部依赖 (DB/Writer/时钟注入) 时使用, 规划器无此类依赖。
> 按 ID 前缀分布: T=49, U=43, H=52, D=31, I=22, A=40, M=5, E=12, INT=6, MAN=9。

### MANUAL 测试点列表 (ID + 原因)

| ID | 原因 |
|---|---|
| MAN-TCP-001 | 依赖真实网卡/内核 TCP 栈, 需 tcpdump 在线缆上抓取 9 帧握手-数据-挥手序列 |
| MAN-TCP-002 | 依赖真实线缆时序, 验证 1MB 多分段的实际帧间间隔与序号连续性 |
| MAN-UDP-001 | 依赖真实网卡, 需 tcpdump 确认 UDP 请求/响应包在线缆可观测 |
| MAN-HTTP-001 | 依赖真实网卡, 需 tcpdump 确认 HTTP TCP 流含 HTTP payload |
| MAN-DNS-001 | 依赖真实网卡, 需 tcpdump 确认 DNS 二进制 query/response 在线缆正确 |
| MAN-ICMP-001 | 依赖真实网卡+内核 ICMP 响应, 需 tcpdump 确认 Echo Reply 可观测 |
| MAN-ARP-001 | 依赖真实网卡, 需 tcpdump 确认 ARP request/reply 在线缆可观测 |
| MAN-ARP-002 | 依赖真实以太网广播, 需 tcpdump -e 确认 DstMAC=ff:ff:ff:ff:ff:ff |
| MAN-VLAN-001 | 依赖真实网卡 802.1Q 硬件, 需 tcpdump -e 确认 802.1Q tag (当前 bug 证实无 tag) |

### 关键修正 (相对枚举)

1. **TCP M6 不成立**: 枚举称数据 ACK/终止 ACK 的 WindowSize=0, 但实际代码 (tcp.go 第 268/321/370 行) 均设 `WindowSize: winSize`。测试点 T26b-POS/T28b-POS/T28d-POS 断言 WindowSize=winSize (正确行为), 非 0。
2. **DNS DstPort 同 HTTP bug**: 枚举 D7 称 DstPort 改为 53, 但 Validate 是 pass-by-value, Plan 用原 spec.DstPort=0。新增 D7-NEG 断言此 bug。
3. **VLAN 丢失是全规划器 bug**: 枚举仅标 TCP(M2)/HTTP(H61), 但 UDP/DNS/ICMP/ARP 的 L2Config 同样省略 VLAN。INT-VLAN-NEG 跨层覆盖; TCP/HTTP 各有独立 NEG 测试点。
