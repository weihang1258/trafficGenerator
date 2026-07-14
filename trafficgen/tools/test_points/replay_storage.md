# 回放 + 存储层 测试点细化

> 标准测试帧约定（字节补丁引擎测试统一使用）：Eth(14)+IPv4(20)+TCP(20) 共 54 字节。
> L2Start=0, DstMAC=0, SrcMAC=6, EthType=12; L3Start=14, DSCPECN=15, IPID=18, TTL=22, Proto=23, IPChecksum=24, SrcIP=26, DstIP=30; L4Start=34, SrcPort=34, DstPort=36, Seq=38, Ack=42, DataOff=46, TCPFlags=47, Window=48, TCPChecksum=50。
> 初始值: src_mac=11:22:33:44:55:66, dst_mac=aa:bb:cc:dd:ee:ff, src_ip=10.0.0.1, dst_ip=10.0.0.2, src_port=1234, dst_port=80, seq=1000, ack=2000, ttl=64, ip_id=1, window=65535, flags=0x02(SYN)。
> OffsetLayout{L2Start:0,DstMAC:0,SrcMAC:6,L3Start:14,SrcIP:26,DstIP:30,TTL:22,DSCPECN:15,IPID:18,L4Start:34,SrcPort:34,DstPort:36,Seq:38,Ack:42,Window:48,TCPFlags:47,L4Protocol:"tcp"}。
> 校验和验证统一用 gopacket 重新解析补丁后字节，断言 IP/TCP checksum 字段 == 重算值（合法）。

## 组件: replay/planner.go (PlanReplay / Plan 主流程)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RP1-POS | RP1 | TestPlanReplay_ValidJSON | 合法 ReplaySpec JSON, DB 中存在 ready asset, 无 flow | err==nil, 返回 channel 非 nil, drain 后 channel 关闭且无 packet (零流) | SIMULATED | SQLite 内存库 + 临时 pcap 文件 |
| RP2-NEG | RP2 | TestPlanReplay_InvalidJSON | `{bad json` | err 包含 "unmarshal replay spec", channel==nil | REAL | 不触 DB, 可传 nil db |
| RP4-NEG | RP4 | TestPlan_AssetNotFound | spec.PcapAssetID 不存在 | err 包含 "pcap asset" 且 wrapping gorm.ErrRecordNotFound | SIMULATED | |
| RP4-NEG2 | RP4 | TestPlan_AssetWrongUser | asset 属 userB, 传入 userID=userA | err 包含 "pcap asset" 且 ErrRecordNotFound (WHERE user_id 过滤) | SIMULATED | 用户隔离核心断言 |
| RP6-NEG | RP6 | TestPlan_AssetStatusImporting | asset.Status="importing" | err 包含 "not ready" 且 "importing" | SIMULATED | |
| RP7-NEG | RP7 | TestPlan_AssetStatusError | asset.Status="error" | err 包含 "not ready" 且 "error" | SIMULATED | |
| RP8-NEG | RP8 | TestPlan_AssetStatusReindexing | asset.Status="reindexing" | err 包含 "not ready" 且 "reindexing" | SIMULATED | |
| RP10-NEG | RP10 | TestPlan_ListFlowsDBError | DB 关闭后调用 | err 包含 "load flows" | SIMULATED | 关闭 DB 触发查询失败 |
| RP11-BR1 | RP11 | TestPlan_ZeroFlows | asset ready, flows=0, packets=2 | err==nil, channel 关闭后收到 0 个 packet | SIMULATED | flowMap 为空, packet 全被 skip |
| RP12-BR1 | RP12 | TestPlan_DirStatusUncertainWarns | flow.DirStatus="uncertain" | 用 zaptest/observer 捕获日志, 断言 Warn 日志包含 "direction uncertain" 且 flow.ID; channel 仍正常产出 packet | SIMULATED | 日志可观测 |
| RP13-BR2 | RP13 | TestPlan_DirStatusClassifiedNoWarn | flow.DirStatus="classified" | zap observer 无 "direction uncertain" 日志 | SIMULATED | |
| RP15-NEG | RP15 | TestPlan_BadOffsetLayoutJSON | flow.OffsetLayout="bad" | err 包含 "layout" | SIMULATED | |
| RP16-NEG | RP16 | TestPlan_RuleResolveError | rewrites 含 endpoint 规则 strategy 为空 | err 包含 "flow" 且 "endpoint" | SIMULATED | |
| RP18-NEG | RP18 | TestPlan_ListPacketsDBError | DB 关闭后 ListAllPacketsByAsset 失败 | err 包含 "load packets" | SIMULATED | |
| RP19-BR1 | RP19 | TestPlan_ChecksumModeDefault | spec.ChecksumMode="" | 产出 cfg.Metadata["_checksum_mode"]=="recompute" | SIMULATED | |
| RP20-BR2 | RP20 | TestPlan_ChecksumModePreserve | spec.ChecksumMode="preserve" | cfg.Metadata["_checksum_mode"]=="preserve" | SIMULATED | |
| RP21-POS | RP21 | TestPlan_PacerOriginal | speed.Mode="original" | cfg.Metadata["_pacer"] 是 *TimestampPacer 且 multiplier==1.0 | SIMULATED | |
| RP22-BR1 | RP22 | TestPlan_PacerBPS | speed.Mode="bps", BPS="200k" | _pacer 是 *TokenBucketPacer | SIMULATED | |
| RP23-BR2 | RP23 | TestPlan_PacerMax | speed.Mode="max" | _pacer 是 MaxPacer{} | SIMULATED | |
| RP24-BR3 | RP24 | TestPlan_PacerEmpty | speed.Mode="" | _pacer 是 MaxPacer{} | SIMULATED | |
| RP26-NEG | RP26 | TestPlan_OpenPcapFileMissing | asset.StoragePath 指向不存在的文件 | err==nil (goroutine 内部错误), channel 关闭, 0 packet; Error 日志包含 "open pcap file failed" | SIMULATED | 错误在 goroutine 内, 用 observer 断言日志 |
| RP27-BR1 | RP27 | TestPlan_LoopZeroCappedToOne | Loop=0, packets=2 | 仅产出 2 个 packet (capped to 1 pass), 非 infinite | SIMULATED | |
| RP28-POS | RP28 | TestPlan_LoopThree | Loop=3, packets=2, 无 flowScaling | 产出 6 个 packet; 第 3-4 个 ts = 原ts+pcapDuration, 第 5-6 个 ts = 原ts+2*pcapDuration | SIMULATED | 断言 loopBase 推进 |
| RP30-BR1 | RP30 | TestPlan_PcapDurationMultiPacket | packets=2, ts 差 1000us | 第 2 轮 packet ts 比第 1 轮对应 packet ts 大 1000us (loopBase+=pcapDuration) | SIMULATED | |
| RP31-BR2 | RP31 | TestPlan_PcapDurationZeroPackets | packets=0 | channel 关闭, 0 packet, 无死循环 | SIMULATED | |
| RP32-BR3 | RP32 | TestPlan_PcapDurationSinglePacket | packets=1, Loop=2 | 产出 2 packet, 第 2 个 ts==第 1 个 ts (pcapDuration=0, loopBase 不变) | SIMULATED | |
| RP34-NEG | RP34 | TestPlan_FlowScalingConflictAbort | FlowScaling.SrcIP 设 inc, rewrites 含 field rule target=src_ip | channel 关闭, 0 packet, Error 日志包含 "flow scaling conflict" | SIMULATED | checkFlowScalingConflict 在 goroutine 内 |
| RP46-POS | RP46/RP49 | TestPlan_SerialInterleaveOrder | FlowScaling.Count=2 Interleave="serial", 2 packets 1 flow | 产出 4 packet, 顺序: clone0-pkt0, clone0-pkt1, clone1-pkt0, clone1-pkt1; 断言 src_ip 按 clone0 值×2 再 clone1 值×2 | SIMULATED | 串行: clone 外层, packet 内层 |
| RP47-BR1 | RP47 | TestPlan_StackModeOrder | FlowScaling.Count=2 Interleave="stack", 2 packets | 产出 4 packet, 顺序: pkt0-clone0, pkt0-clone1, pkt1-clone0, pkt1-clone1; 断言相邻两包 src_ip 分别为 clone0/clone1 值 | SIMULATED | 栈式: packet 外层, clone 内层 |
| RP48-BR2 | RP48 | TestPlan_SerialNoClonesFallsBackStack | Interleave="serial" 但 FlowScaling=nil | 走 stack 分支, 产出 len(packets) 个 packet, 无 clone | SIMULATED | serial 但无 clone -> stack |
| RP43-POS | RP43/RP161 | TestPlan_PerRoundCloneRegeneration | FlowScaling.Count=1 SeqOffset fixed=1000, Loop=2, 1 packet | 产出 2 packet; 两轮的 packet 都有 seq patch (origSeq+1000); 第 2 轮 ts = 原ts+pcapDuration; 证明每轮 generateClones 重新调用并应用 clone patch | SIMULATED | 每轮 clone 重新生成, 断言两轮均有 clone patch + loopBase 推进 |
| RP51-POS | RP51/RP-C1 | TestPlan_SerialCtxCancel | serial 模式, ctx 在发出首包后 cancel | channel 关闭, 已发出包数 < 总数; ctx.Err()==context.Canceled | SIMULATED | |
| RP55-POS | RP55/RP-C2 | TestPlan_StackCtxCancel | stack 模式, ctx 在发出首包后 cancel | channel 关闭, 不再产出 | SIMULATED | |
| RP58-BR1 | RP58 | TestPlan_StackFlowLookupMiss | pkt.FlowID 不在 flowMap | 该 packet 被 skip (continue), 不产出, 其余正常 | SIMULATED | |
| RP60-NEG | RP60 | TestPlan_StackReadAtFail | pkt.RawOffset 指向 EOF | 该 packet 被 skip, 其余正常产出 | SIMULATED | ReadAt 失败 continue |
| RP62-BR1 | RP62 | TestPlan_StackCloneMode | stackCloneCount=2, 1 packet | 产出 2 packet, 分别带 clone0/clone1 的 src_ip patch | SIMULATED | |
| RP63-BR2 | RP63 | TestPlan_StackNoClone | FlowScaling=nil, 1 packet | 产出 1 packet, 仅 basePatches 无 clone patch | SIMULATED | |
| RP-C6-BR | RP-C6 | TestPlan_CtxCancelBeforeGoroutine | ctx 在 Plan 返回前已 cancel | channel 非 nil, drain 后关闭, 0 packet (goroutine 内首检 ctx 后 return) | SIMULATED | |

## 组件: replay/planner.go (emitPacket / emitReplayCfg)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RP-E1-BR | RP-E1 | TestEmitPacket_FlowLookupMiss | pkt.FlowID 不在 flowMap | 返回 true (skip), 不读 pcap, 不发 channel | REAL | 直接调 emitPacket, 传 mock pcapFile |
| RP-E2-BR | RP-E2 | TestEmitPacket_ReadAtFail | pcapFile.ReadAt 返回 err | 返回 true (skip), 不发 channel | REAL | 用 bytes.Reader 包 ReadAt 失败 |
| RP-E4-POS | RP-E4 | TestEmitPacket_SeqOffsetApplied | clone.SeqOffset=1000, raw seq=0x1000 | 产出 cfg 的 patches 含 seq patch, Bytes == origSeq+1000 | REAL | |
| RP-E6-NEG | RP-E6 | TestEmitPacket_EmitCancelPropagate | emitReplayCfg 返回 false (ctx cancel) | emitPacket 返回 false | REAL | |
| RP-F1-POS | RP-F1 | TestEmitReplayCfg_SendSuccess | buffered out channel | 返回 true, cfg 写入 channel, Metadata 含 _replay/_raw/_patches/_checksum_mode/_layout/_pacer/_task_id | REAL | |
| RP-F2-NEG | RP-F2 | TestEmitReplayCfg_CtxCancel | ctx 已 cancel, out 不读 | 返回 false, channel 无写入 | REAL | select 走 ctx.Done |
| RP-F-BR1 | RP-E6 | TestEmitReplayCfg_MetadataFields | 正常发送 | 断言 cfg.FlowID/Direction(mapDirection 结果)/Timestamp==pkt.ts+loopBase/ClassID 全部非零且等于期望 | REAL | 断言可观测字段非零 |

## 组件: replay/planner.go (buildFlowContexts)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RP-B1-POS | RP-B1 | TestBuildFlowContexts_ZeroFlows | flows=[] | 返回空 map, err==nil | REAL | |
| RP-B3-POS | RP-B3 | TestBuildFlowContexts_ValidLayout | flow.OffsetLayout=合法 JSON | flowMap[flow.ID].layout.SrcIP 等于 JSON 中值 | REAL | |
| RP-B4-NEG | RP-B4 | TestBuildFlowContexts_BadLayoutJSON | flow.OffsetLayout="bad" | err 包含 "layout" | REAL | |
| RP-B5-BR | RP-B5 | TestBuildFlowContexts_DefaultLayout | flow.OffsetLayout="" | layout 所有字段==-1 (默认), flowMap 含该 flow | REAL | 断言 -1 而非零值 |
| RP-B7-NEG | RP-B7 | TestBuildFlowContexts_FlowPatchError | rewrites 含冲突 field 规则 | err 包含 "flow" | REAL | computeFlowPatches 冲突 |
| RP-B9-BR | RP-B9 | TestBuildFlowContexts_RuleNotMatch | rule.Match 不匹配 flow | flowCtx.endpointRules/offsetRules/macmapRules 为空 | REAL | |
| RP-B10-POS | RP-B10 | TestBuildFlowContexts_EndpointRule | kind=endpoint, strategy=fixed value | endpointRules 长度 1, target/value 正确 | REAL | |
| RP-B11-NEG | RP-B11 | TestBuildFlowContexts_EndpointStrategyFail | kind=endpoint, strategy=空 | err 包含 "endpoint" | REAL | |
| RP-B12-POS | RP-B12 | TestBuildFlowContexts_OffsetRule | kind=field apply=offset target=seq delta=1000 | offsetRules 长度 1, delta==1000 | REAL | apply:offset 收集 |
| RP-B13-NEG | RP-B13 | TestBuildFlowContexts_OffsetDeltaFail | kind=field apply=offset strategy=空 | err 包含 "offset" | REAL | |
| RP-B14-BR | RP-B14 | TestBuildFlowContexts_FieldNonOffset | kind=field apply=set target=ttl | offsetRules 为空 (走 flowPatches), flowPatches 含 ttl patch | REAL | 非 offset 不进 offsetRules |
| RP-B15-POS | RP-B15 | TestBuildFlowContexts_MacmapRule | kind=macmap | macmapRules 长度 1 | REAL | |
| RP-B16-BR | RP-B16 | TestBuildFlowContexts_UnknownKind | kind=unknown | 无 endpoint/offset/macmap 规则收集 (switch 静默跳过), err==nil | REAL | |

## 组件: replay/planner.go (assemblePatches / offsetValuePatch / macmapPatches / mapDirection)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RP-A1-POS | RP-A1 | TestAssemblePatches_AllTypes | flowCtx 含 flowPatches+endpointRules+offsetRules+macmapRules, raw=标准帧 | 返回 patches 含所有四类, 顺序: flow -> endpoint -> offset -> macmap | REAL | 断言各类型 patch 存在 |
| RP-A3-BR | RP-A3 | TestAssemblePatches_EndpointErrorSkip | endpointPatch 返回 err (layout.SrcIP=-1) | 该 endpoint 被 skip, 其余 patch 仍在 | REAL | |
| RP-A5-BR | RP-A5 | TestAssemblePatches_OffsetValueSkip | offsetValuePatch 返回 ok=false (layout.Seq=-1) | 该 offset 被 skip | REAL | |
| RP-A8-POS | RP-A8 | TestAssemblePatches_MacmapBothMACs | raw 两 MAC 均在 mapping | macmapPatches 返回 2 patch, assemble 含两条 l2 patch | REAL | |
| RP-O1-BR | RP-O1 | TestOffsetValuePatch_FieldSpecMiss | target=unknown | 返回 ok=false | REAL | |
| RP-O2-BR | RP-O2 | TestOffsetValuePatch_OffsetNegative | target=seq 但 layout.Seq=-1 | 返回 false | REAL | |
| RP-O3-BR | RP-O3 | TestOffsetValuePatch_OutOfBounds | layout.Seq+4 > len(raw) | 返回 false | REAL | |
| RP-O4-POS | RP-O4 | TestOffsetValuePatch_UInt32Seq | raw seq=1000, delta=100 | patch.Bytes == BE(1100), Layer=="l4", Offset==layout.Seq | REAL | 断言 per-packet orig+delta |
| RP-O5-POS | RP-O5 | TestOffsetValuePatch_UInt16Window | raw window=100, delta=50, target=window | patch.Bytes == BE(150) | REAL | width=2 |
| RP-O6-BR | RP-O6 | TestOffsetValuePatch_Width1Unsupported | target=ttl (width=1), delta=10 | 返回 false (width 1 不支持 offset) | REAL | |
| RP-O7-POS | RP-O7 | TestOffsetValuePatch_UInt32Wrap | raw seq=0xFFFFFFFF, delta=1 | patch.Bytes == BE(0x00000000) | REAL | uint32 自然回绕 |
| RP-O8-POS | RP-O8 | TestOffsetValuePatch_UInt16Wrap | raw window=0xFFFF, delta=1, target=window | patch.Bytes == BE(0x0000) | REAL | uint16 回绕 |
| RP-O-DELTA | RP-O4 | TestOffsetValuePatch_PerPacketDeltaVaries | 同一 offsetRule, 两包 raw seq=1000/2000, delta=100 | patch1.Bytes==BE(1100), patch2.Bytes==BE(2100) | REAL | 核心: per-packet 原值+delta, 流内 delta 不变 |
| RP-M1-POS | RP-M1 | TestMacmapPatches_SrcMatch | raw src_mac=11:22:33:44:55:66, mapping 含该 MAC->aa:aa:aa:aa:aa:aa | 返回 1 patch, Field=src_mac, Bytes==aa:aa:aa:aa:aa:aa, Layer=l2 | REAL | |
| RP-M2-BR | RP-M2 | TestMacmapPatches_SrcNoMatch | src MAC 不在 mapping | 无 src patch | REAL | |
| RP-M3-BR | RP-M3 | TestMacmapPatches_InvalidMACValue | mapping 值="notamac" | 无 patch (ParseMAC 失败 skip) | REAL | |
| RP-M4-BR | RP-M4 | TestMacmapPatches_SrcOffsetNeg | layout.SrcMAC=-1 | 无 src patch | REAL | |
| RP-M5-BR | RP-M5 | TestMacmapPatches_SrcOutOfBounds | layout.SrcMAC+6 > len(raw) | 无 src patch | REAL | |
| RP-M6-POS | RP-M6 | TestMacmapPatches_DstMatch | dst MAC 在 mapping | 返回 dst_mac patch | REAL | |
| RP-M11-POS | RP-M11 | TestMacmapPatches_BothMatch | 两 MAC 均在 mapping | 返回 2 patch (src+dst) | REAL | |
| RP-M12-POS | RP-M12 | TestMacmapPatches_NoneMatch | 两 MAC 均不在 mapping | 返回空 slice | REAL | |
| RP-D1-POS | RP-D1 | TestMapDirection_C2S | "c2s" | 返回 "up" | REAL | |
| RP-D2-POS | RP-D2 | TestMapDirection_S2C | "s2c" | 返回 "down" | REAL | |
| RP-D3-BR | RP-D3 | TestMapDirection_Empty | "" | 返回 "" | REAL | |
| RP-D4-BR | RP-D4 | TestMapDirection_Unknown | "unknown" | 返回 "unknown" (原样) | REAL | |

## 组件: replay/rewriter.go (ApplyPatches — 字节补丁引擎 + checksum)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RW1-POS | RW1 | TestApplyPatches_Empty | raw=标准帧, patches=[] | out==raw 副本; checksumMode=recompute 时 IP/TCP checksum 被重算且 gopacket 校验合法 | REAL | |
| RW2-POS | RW2 | TestApplyPatches_SinglePatch | patch: Offset=26(SrcIP), Bytes=10.0.0.99 | out[26:30]==10.0.0.99; gopacket 解析 IP SrcIP==10.0.0.99; IP checksum 合法 | REAL | 断言具体字段值 + gopacket 重验 |
| RW3-NEG | RW3 | TestApplyPatches_NegativeOffset | patch.Offset=-1 | 返回 err 包含 "out of bounds" | REAL | |
| RW4-NEG | RW4 | TestApplyPatches_OverflowBounds | patch.Offset=50, len(Bytes)=4 (frame 54) | 返回 err (50+4>54 false; 用 Offset=52 len=4 -> 56>54 err) | REAL | |
| RW5-BR | RW5 | TestApplyPatches_L3Flag | patch Layer=l3 (src_ip) | out SrcIP 改; IP+TCP checksum 均重算, gopacket 双校验合法 | REAL | touchedL3 触发两者 |
| RW6-BR | RW6 | TestApplyPatches_L4Flag | patch Layer=l4 (seq) | out Seq 改; IP checksum 不重算(touchedL3 false, preserve 模式), TCP checksum 重算; gopacket TCP 校验合法 | REAL | |
| RW7-BR | RW7 | TestApplyPatches_L2Flag | patch Layer=l2 (src_mac), preserve 模式 | out MAC 改; IP/TCP checksum 均不重算, 保持原值; gopacket 解析 MAC 正确 | REAL | |
| RW9-POS | RW9 | TestApplyPatches_RecomputeNoPatch | checksumMode=recompute, patches=[] | IP checksum 重算, TCP checksum 重算, gopacket 双校验合法 | REAL | |
| RW10-POS | RW10 | TestApplyPatches_PreserveL3 | checksumMode=preserve, L3 patch (dst_ip) | IP checksum 重算, TCP checksum 重算, gopacket 双校验合法 | REAL | touchedL3 触发两者 |
| RW11-POS | RW11 | TestApplyPatches_PreserveL4 | checksumMode=preserve, L4 patch (seq) | IP checksum 不重算(保持原), TCP checksum 重算; gopacket TCP 校验合法, IP 校验仍合法(原值未动) | REAL | touchedL4 仅触发 L4 |
| RW12-POS | RW12 | TestApplyPatches_PreserveL2Only | checksumMode=preserve, 仅 L2 patch | IP/TCP checksum 均不重算, 保持原值; gopacket 解析 MAC 改 | REAL | preserve + 仅 MAC = 保持坏 checksum 异常 |
| RW13-POS | RW13 | TestApplyPatches_PreserveNoPatch | checksumMode=preserve, patches=[] | IP/TCP checksum 均保持原值 (不重算) | REAL | preserve + 无 patch = 保持原 checksum |
| RW15-POS | RW15 | TestApplyPatches_RecomputeL2Only | checksumMode=recompute, 仅 L2 patch | IP+TCP checksum 均重算 (mode 强制), gopacket 双校验合法 | REAL | recompute 总是重算 |
| RW16-NEG | RW16 | TestApplyPatches_MidLoopOOB | 2 patch, 第 2 个 OOB | 返回 err, out 副本丢弃 (调用方拿不到部分结果) | REAL | |
| RW17-POS | RW17 | TestApplyPatches_SameOffsetLastWins | 2 patch 同 Offset=26, 不同 Bytes | out[26:30]==第 2 个 patch 的 Bytes | REAL | |
| RW-IP-POS | RW2 | TestApplyPatches_IPFieldPatch | patch src_ip=192.168.1.1 (Offset=26) | gopacket 解析 IP.SrcIP==192.168.1.1, DstIP 不变==10.0.0.2, IP checksum 合法 | REAL | 字段值断言 |
| RW-PORT-POS | RW2 | TestApplyPatches_PortPatch | patch dst_port=443 (Offset=36, 2 bytes BE) | gopacket TCP.DstPort==443, SrcPort 不变==1234, TCP checksum 合法 | REAL | |
| RW-MAC-POS | RW2 | TestApplyPatches_MACPatch | patch src_mac=de:ad:be:ef:00:01 (Offset=6) | gopacket Eth.SrcMAC==de:ad:be:ef:00:01 | REAL | |
| RW-SEQ-POS | RW2 | TestApplyPatches_SeqPatch | patch seq=0xdeadbeef (Offset=38, 4 bytes BE) | gopacket TCP.Seq==0xdeadbeef, TCP checksum 合法 | REAL | |
| RW-TTL-POS | RW2 | TestApplyPatches_TTLPatch | patch ttl=128 (Offset=22, 1 byte) | gopacket IP.TTL==128, IP checksum 合法 | REAL | |
| RW-DSCP-POS | RW2 | TestApplyPatches_DSCPPatch | dscp=46 -> Bytes=[46<<2=0xb8] (Offset=15) | gopacket IP TOS byte==0xb8 (DSCP=46), IP checksum 合法 | REAL | DSCP 高 6 位 |
| RW-ECN-POS | RW2 | TestApplyPatches_ECNPatch | ecn=3 -> Bytes=[3&0x03=0x03] (Offset=15) | TOS byte==0x03, IP checksum 合法 | REAL | ECN 低 2 位 |
| RW-IPID-POS | RW2 | TestApplyPatches_IPIDPatch | ip_id=0xabcd (Offset=18, 2 bytes BE) | gopacket IP.ID==0xabcd, IP checksum 合法 | REAL | |

## 组件: replay/rule.go (matchRule)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RU1-NEG | RU1 | TestMatchRule_ProtocolMismatch | m.Protocol="udp", flow.L4Protocol="tcp" | 返回 false | REAL | |
| RU2-POS | RU2 | TestMatchRule_ProtocolMatch | m.Protocol="tcp", flow="tcp" | 继续 IP 检查 (结合 IP 配置断言 true) | REAL | |
| RU4-POS | RU4 | TestMatchRule_BothIPPairMatch | m.SrcIP=10.0.0.1, DstIP=10.0.0.2, flow 同 | 返回 true | REAL | |
| RU5-NEG | RU5 | TestMatchRule_BothIPNoPair | m.SrcIP=A DstIP=B, flow SrcIP=C DstIP=D | 返回 false | REAL | |
| RU6-POS | RU6 | TestMatchRule_IPCrossMatch | m.SrcIP=A DstIP=B, flow SrcIP=B DstIP=A (反向) | 返回 true (pair2) | REAL | 双向匹配 |
| RU7-NEG | RU7 | TestMatchRule_OnlySrcIPFail | m.SrcIP=A (DstIP 空), flow.SrcIP=C flow.DstIP=C | 返回 false | REAL | |
| RU11-POS | RU11 | TestMatchRule_NoIPSet | m.SrcIP="" DstIP="" | 跳过 IP 检查 (结合 port 断言) | REAL | |
| RU12-POS | RU12 | TestMatchRule_BothPortPair | m.SrcPort=1234 DstPort=80, flow 同 | 返回 true | REAL | |
| RU13-NEG | RU13 | TestMatchRule_BothPortNoPair | m.SrcPort=1 DstPort=2, flow SrcPort=3 DstPort=4 | 返回 false | REAL | |
| RU14-POS | RU14 | TestMatchRule_PortCrossMatch | m.SrcPort=80 DstPort=1234, flow SrcPort=1234 DstPort=80 | 返回 true (pair2) | REAL | |
| RU19-POS | RU19 | TestMatchRule_NoPortSet | m 全空 | 返回 true (全 wildcard) | REAL | |
| RU20-POS | RU20 | TestMatchRule_AllWildcard | m 全零/空 | 返回 true | REAL | |
| RU-CIDR-POS | RU22 | TestMatchRule_CIDRMatch | m.SrcIP="10.0.0.0/8", flow.SrcIP="10.1.2.3" | ipMatch true -> matchRule true | REAL | CIDR 在 matchRule 内 |

## 组件: replay/rule.go (ipMatch)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RU21-POS | RU21 | TestIPMatch_Exact | pattern="10.0.0.1", ipStr="10.0.0.1" | true | REAL | |
| RU22-POS | RU22 | TestIPMatch_CIDRMatch | pattern="10.0.0.0/8", ipStr="10.1.2.3" | true | REAL | |
| RU23-NEG | RU23 | TestIPMatch_CIDRNoMatch | pattern="10.0.0.0/8", ipStr="192.168.1.1" | false | REAL | |
| RU24-NEG | RU24 | TestIPMatch_InvalidCIDR | pattern="notacidr", ipStr="10.0.0.1" | false | REAL | |
| RU25-NEG | RU25 | TestIPMatch_InvalidIP | pattern="10.0.0.0/8", ipStr="notanip" | false | REAL | |
| RU26-NEG | RU26 | TestIPMatch_EmptyPattern | pattern="", ipStr="10.0.0.1" | false | REAL | |

## 组件: replay/rule.go (fieldSpecFor)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RU28-POS | RU28 | TestFieldSpecFor_SrcIP | layout.SrcIP=26, target="src_ip" | spec.offset==26, layer=="l3", width==4 | REAL | |
| RU30-POS | RU30 | TestFieldSpecFor_SrcPort | layout.SrcPort=34, target="src_port" | offset==34, layer=="l4", width==2 | REAL | |
| RU32-POS | RU32 | TestFieldSpecFor_SrcMAC | target="src_mac" | layer=="l2", width==6 | REAL | |
| RU34-POS | RU34 | TestFieldSpecFor_TTL | target="ttl" | layer=="l3", width==1 | REAL | |
| RU35-POS | RU35 | TestFieldSpecFor_DSCP | target="dscp" | offset==layout.DSCPECN, layer=="l3", width==1 | REAL | |
| RU36-POS | RU36 | TestFieldSpecFor_ECN | target="ecn" | offset==layout.DSCPECN (与 dscp 同字节) | REAL | |
| RU38-POS | RU38 | TestFieldSpecFor_Seq | target="seq" | layer=="l4", width==4 | REAL | |
| RU42-NEG | RU42 | TestFieldSpecFor_Unknown | target="unknown" | ok==false | REAL | |

## 组件: replay/rule.go (encodeValue)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RU43-POS | RU43 | TestEncodeValue_MAC | target="src_mac", value="aa:bb:cc:dd:ee:ff" | 返回 6 字节 [0xaa..0xff] | REAL | |
| RU44-NEG | RU44 | TestEncodeValue_InvalidMAC | value="notamac" | err 包含 "invalid MAC" | REAL | |
| RU45-POS | RU45 | TestEncodeValue_IPv4 | target="src_ip", value="10.0.0.1" | 返回 4 字节 [10,0,0,1] | REAL | |
| RU46-NEG | RU46 | TestEncodeValue_InvalidIP | value="notanip" | err 包含 "invalid IP" | REAL | |
| RU47-NEG | RU47 | TestEncodeValue_IPv6 | value="::1" | err 包含 "IPv6 not supported" | REAL | |
| RU49-POS | RU49 | TestEncodeValue_Port | target="src_port", value="80" | 返回 2 字节 BE [0x00,0x50] | REAL | |
| RU52-POS | RU52 | TestEncodeValue_TTL | value="64" | 返回 [0x40] | REAL | |
| RU55-POS | RU55 | TestEncodeValue_DSCP | value="46" | 返回 [46<<2=0xb8] | REAL | 高 6 位 |
| RU57-POS | RU57 | TestEncodeValue_ECN | value="3" | 返回 [3&0x03=0x03] | REAL | 低 2 位 |
| RU59-POS | RU59 | TestEncodeValue_Seq | value="1000" | 返回 4 字节 BE(1000) | REAL | |
| RU63-POS | RU63 | TestEncodeValue_Window | value="65535" | 返回 2 字节 BE [0xff,0xff] | REAL | |
| RU64-NEG | RU64 | TestEncodeValue_Unknown | target="unknown" | err 包含 "unsupported target" | REAL | |

## 组件: replay/rule.go (resolveStrategyValue)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RU65-POS | RU65 | TestResolveStrategyValue_Fixed | strategy="fixed", Value="10.0.0.1" | 返回 "10.0.0.1", nil | REAL | |
| RU66-NEG | RU66 | TestResolveStrategyValue_FixedNil | strategy="fixed", Value=nil | err 包含 "missing value" | REAL | |
| RU67-POS | RU67 | TestResolveStrategyValue_FixedInt | strategy="fixed", Value=42 | 返回 "42" | REAL | |
| RU68-POS | RU68 | TestResolveStrategyValue_List | strategy="list", List=["a","b"] | 返回 "a" (首元素) | REAL | |
| RU69-NEG | RU69 | TestResolveStrategyValue_ListEmpty | strategy="list", List=[] | err 包含 "list strategy empty" | REAL | |
| RU70-NEG | RU70 | TestResolveStrategyValue_Inc | strategy="inc" | err 包含 "not supported" | REAL | flow-level 不支持 inc |
| RU72-NEG | RU72 | TestResolveStrategyValue_Unknown | strategy="unknown" | err 包含 "not supported" | REAL | |

## 组件: replay/rule.go (computeFlowPatches — 冲突检测)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RU73-POS | RU73 | TestComputeFlowPatches_NoRules | rules=[] | 返回空 patches, nil | REAL | |
| RU74-BR | RU74 | TestComputeFlowPatches_RuleNotMatch | rule.Match 不匹配 flow | 返回空 patches | REAL | |
| RU77-POS | RU77 | TestComputeFlowPatches_SameFieldSameValue | 2 规则同 target=ttl 同值 | 幂等, patches 仅 1 条, 无 err | REAL | |
| RU78-NEG | RU78 | TestComputeFlowPatches_SameFieldDiffValue | 2 规则同 target=ttl 不同值 | err 包含 "conflict" 且 "set to both" | REAL | |
| RU79-POS | RU79 | TestComputeFlowPatches_DSCPThenECN | 先 dscp=46 后 ecn=3 (同 TOS 字节) | 合并, patches 1 条, Bytes[0]==0xb8\|0x03==0xbb | REAL | TOS 合并 |
| RU80-POS | RU80 | TestComputeFlowPatches_ECNThenDSCP | 先 ecn=3 后 dscp=46 | 合并, Bytes[0]==(0xb8)\|(0x03)==0xbb | REAL | 反向合并 |
| RU84-NEG | RU84 | TestComputeFlowPatches_DiffFieldSameOffset | 2 不同字段同 offset (非 dscp/ecn) | err 包含 "conflict" 且 "overlap" | REAL | |
| RU85-POS | RU85 | TestComputeFlowPatches_NewFieldNewOffset | 2 规则不同字段不同 offset | patches 2 条 | REAL | |

## 组件: replay/rule.go (applyIPMap / lookupIPMap / translateCIDR — ipmap CIDR)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RU88-POS | RU88 | TestApplyIPMap_SrcExact | mapping={"10.0.0.1":"192.168.1.1"}, flow.SrcIP=10.0.0.1, layout.SrcIP=26 | 返回 1 patch, Field=src_ip, Bytes==[192,168,1,1] | REAL | |
| RU89-BR | RU89 | TestApplyIPMap_SrcNotFound | flow.SrcIP 不在 mapping | 无 src patch | REAL | |
| RU90-BR | RU90 | TestApplyIPMap_SrcLayoutNeg | layout.SrcIP=-1 | 无 src patch | REAL | |
| RU91-NEG | RU91 | TestApplyIPMap_EncodeFail | mapping 值="notanip" | err 包含 "ipmap src" | REAL | |
| RU96-POS | RU96 | TestApplyIPMap_BothFound | src+dst 均在 mapping | 返回 2 patch | REAL | |
| RU97-NEG | RU97 | TestLookupIPMap_InvalidIP | ipStr="notanip" | 返回 "", false | REAL | |
| RU98-POS | RU98 | TestLookupIPMap_ExactMatch | mapping={"10.0.0.1":"11.0.0.1"}, ipStr="10.0.0.1" | 返回 "11.0.0.1", true | REAL | exact 快速路径 |
| RU100-POS | RU100 | TestLookupIPMap_CIDRKeyMatch | mapping={"10.0.0.0/8":"192.168.0.0/16"}, ipStr="10.0.0.5" | 返回 "192.168.0.5", true (网段平移保偏移) | REAL | lookupIPMap 调 translateCIDR |
| RU101-BR | RU101 | TestLookupIPMap_NonCIDRKey | mapping 含非 CIDR key "foo" | skip 该 key, 继续遍历 | REAL | |
| RU102-BR | RU102 | TestLookupIPMap_CIDRNotContain | mapping={"10.0.0.0/8":...}, ipStr="192.168.1.1" | 不匹配, 继续找 | REAL | |
| RU103-POS | RU103 | TestLookupIPMap_MostSpecificWins | mapping={"10.0.0.0/8":"a","10.0.0.0/24":"b"}, ipStr="10.0.0.5" | 返回 "b" (/24 更具体) | REAL | 最长前缀 |
| RU104-BR | RU104 | TestLookupIPMap_LessSpecificSkipped | 同上但 ipStr="10.0.1.5" | 返回 "a" (仅 /8 匹配) | REAL | |
| RU106-NEG | RU106 | TestLookupIPMap_NoMatch | ipStr 不在任何 CIDR | 返回 "", false | REAL | |
| RU107-NEG | RU107 | TestLookupIPMap_EmptyMapping | mapping={} | 返回 "", false | REAL | |
| RU108-POS | RU108 | TestTranslateCIDR_TargetIsIP | ip=10.0.0.5, srcCIDR=10.0.0.0/8, targetSpec="192.168.1.1" (单 IP 非 CIDR) | 返回 "192.168.1.1" | REAL | target 非 CIDR |
| RU109-POS | RU109 | TestTranslateCIDR_TargetNotIPNotCIDR | targetSpec="hostname" | 返回 "hostname" 原样 | REAL | |
| RU110-BR | RU110 | TestTranslateCIDR_IPv6 | ip=IPv6, target="192.168.0.0/16" | 返回 target 的 IP string (v4==nil 分支) | REAL | |
| RU112-POS | RU112 | TestTranslateCIDR_HostOffsetPreserved | ip=10.0.0.5, src=10.0.0.0/8, target=192.168.0.0/16 | 返回 "192.168.0.5" (host 偏移 5 保留) | REAL | 核心: 网段平移保偏移 |
| RU113-POS | RU113 | TestTranslateCIDR_DstSmaller | ip=10.0.0.5, src=/8, target=/24 (dstHostBits<srcHostBits) | hostOffset 截断到 dst host bits, 返回值在 target/24 范围内 | REAL | 偏移受限 |
| RU114-POS | RU114 | TestTranslateCIDR_DstLarger | ip=10.0.0.5, src=/24, target=/8 | 全 host offset 保留 | REAL | |
| RU115-POS | RU115 | TestTranslateCIDR_SrcSlash0 | src=/0 (srcHostBits=32) | hostOffset=全 32 位, newIP=dstBase\|hostOffset | REAL | |
| RU116-POS | RU116 | TestTranslateCIDR_SrcSlash32 | ip=10.0.0.5, src=/32 (单 IP) | hostOffset=0, newIP=dstBase | REAL | |

## 组件: replay/rule.go (maskLowBits)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RU117-POS | RU117 | TestMaskLowBits_Zero | n=0 | 返回 0 | REAL | |
| RU118-POS | RU118 | TestMaskLowBits_32 | n=32 | 返回 0xFFFFFFFF | REAL | |
| RU119-POS | RU119 | TestMaskLowBits_8 | n=8 | 返回 0xFF | REAL | |
| RU120-POS | RU120 | TestMaskLowBits_16 | n=16 | 返回 0xFFFF | REAL | |

## 组件: replay/rule.go (genFlowPatches / genFieldPatches / resolveOffsetDelta / endpointPatch)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RU121-POS | RU121 | TestGenFlowPatches_IPMap | kind=ipmap | 委托 applyIPMap, 返回 IP patch | REAL | |
| RU122-POS | RU122 | TestGenFlowPatches_PortmapSrc | kind=portmap, mapping 含 src port | 返回 src_port patch | REAL | |
| RU125-BR | RU125 | TestGenFlowPatches_PortmapSrcNotInMap | src port 不在 mapping | 无 src patch | REAL | |
| RU130-POS | RU130 | TestGenFlowPatches_Macmap | kind=macmap | 返回 nil (per-packet 处理) | REAL | |
| RU131-POS | RU131 | TestGenFlowPatches_Field | kind=field apply=set | 委托 genFieldPatches, 返回 patch | REAL | |
| RU132-POS | RU132 | TestGenFlowPatches_Endpoint | kind=endpoint | 返回 nil (per-packet) | REAL | |
| RU133-NEG | RU133 | TestGenFlowPatches_UnknownKind | kind=unknown | err 包含 "unknown rule kind" | REAL | |
| RU134-POS | RU134 | TestGenFieldPatches_ApplyOffsetSkipped | rule.Apply="offset" | 返回 nil, nil (genFieldPatches 跳过 apply:offset) | REAL | 核心: apply:offset 必须跳过 (已知 bug 曾不跳过) |
| RU135-NEG | RU135 | TestGenFieldPatches_FieldSpecMiss | target=unknown | err 包含 "unsupported target" | REAL | |
| RU136-NEG | RU136 | TestGenFieldPatches_OffsetNeg | target=seq, layout.Seq=-1 | err 包含 "absent in this flow's layout" | REAL | |
| RU137-NEG | RU137 | TestGenFieldPatches_StrategyFail | strategy=空 | err (resolveStrategyValue) | REAL | |
| RU138-NEG | RU138 | TestGenFieldPatches_EncodeFail | target=src_ip, value="bad" | err (encodeValue) | REAL | |
| RU139-POS | RU139 | TestGenFieldPatches_Success | target=ttl, fixed value=128 | 返回 1 patch, Bytes==[0x80] | REAL | |
| RU140-NEG | RU140 | TestResolveOffsetDelta_StrategyFail | strategy=空 | 返回 0, err | REAL | |
| RU141-NEG | RU141 | TestResolveOffsetDelta_ParseFail | value="abc" | 返回 0, err 包含 "offset delta" | REAL | |
| RU142-POS | RU142 | TestResolveOffsetDelta_Valid | value="1000" | 返回 uint32(1000) | REAL | |
| RU143-BR | RU143 | TestResolveOffsetDelta_TruncateOverflow | value="4294967296" (2^32) | ParseUint 成功, uint32 截断为 0 | REAL | |
| RU144-POS | RU144 | TestEndpointPatch_ClientIP_C2S | dir="c2s", target="client_ip", value=10.9.9.9 | offset=layout.SrcIP, patch Layer=l3, Bytes==10.9.9.9 | REAL | |
| RU145-POS | RU145 | TestEndpointPatch_ClientIP_S2C | dir="s2c", target="client_ip" | offset=layout.DstIP | REAL | |
| RU146-POS | RU146 | TestEndpointPatch_ServerIP_C2S | dir="c2s", target="server_ip" | offset=layout.DstIP | REAL | |
| RU147-POS | RU147 | TestEndpointPatch_ServerIP_S2C | dir="s2c", target="server_ip" | offset=layout.SrcIP | REAL | |
| RU152-NEG | RU152 | TestEndpointPatch_UnknownTarget | target="unknown" | err 包含 "unsupported endpoint target" | REAL | |
| RU153-NEG | RU153 | TestEndpointPatch_OffsetNeg | layout.SrcIP=-1, target=client_ip c2s | err 包含 "offset absent" | REAL | |
| RU154-NEG | RU154 | TestEndpointPatch_IPv6 | newVal=IPv6 | err 包含 "not IPv4" | REAL | |
| RU155-NEG | RU155 | TestEndpointPatch_PortTarget | target="client_port" | err 包含 "port patching not supported via IP path" | REAL | |

## 组件: replay/flowscaling.go (generateClones / resolveCloneStr / resolveClonePort / resolveCloneSeq)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| FS1-POS | FS1 | TestGenerateClones_Nil | fs=nil | 返回 nil, nil | REAL | |
| FS2-POS | FS2 | TestGenerateClones_CountLEZero | fs.Count=0 | 返回 nil, nil | REAL | |
| FS4-POS | FS4 | TestGenerateClones_Count5 | fs.Count=5, 全 fixed | 返回 len==5, clones[k].Index==k | REAL | clone 数断言 |
| FS5-NEG | FS5 | TestGenerateClones_SrcIPFail | SrcIP.Strategy=inc Range=[] | err 包含 "clone 0 src_ip" | REAL | |
| FS11-NEG | FS11 | TestGenerateClones_SeqOffsetFail | SeqOffset strategy 异常 | err 包含 "seq_offset" | REAL | |
| FS12-POS | FS12 | TestGenerateClones_AllResolved | 全字段 fixed | clones[0] 各字段非零, 符合 fixed 值 | REAL | 断言字段非零 |
| FS9-BR | FS9 | TestGenerateClones_SrcMACErrorIgnored | SrcMAC strategy 异常 | err 被忽略, srcMAC="" (不报错) | REAL | MAC 失败静默 |
| FS14-POS | FS14 | TestResolveCloneStr_Fixed | strategy=fixed, Value="1.2.3.4" | 返回 "1.2.3.4" | REAL | |
| FS15-POS | FS15 | TestResolveCloneStr_FixedNil | strategy=fixed, Value=nil | 返回 "", nil | REAL | |
| FS16-NEG | FS16 | TestResolveCloneStr_IncNoRange | strategy=inc, Range=[] | err 包含 "inc strategy needs range" | REAL | |
| FS17-POS | FS17 | TestResolveCloneStr_IncIPStep0 | strategy=inc, Range=["10.0.0.1","10.0.0.10"], step=0, isIP=true, k=2 | step 被设为 1, 返回 "10.0.0.3" | REAL | step=0 默认 1 |
| FS18-POS | FS18 | TestResolveCloneStr_IncIPStep5 | step=5, k=2, isIP=true, start=10.0.0.1 | 返回 "10.0.0.11" (1+2*5) | REAL | |
| FS19-NEG | FS19 | TestResolveCloneStr_IncIPInvalid | start="notanip", isIP=true | err (incIP) | REAL | |
| FS20-POS | FS20 | TestResolveCloneStr_IncNumeric | isIP=false, start="1000", step=10, k=2 | 返回 "1020" | REAL | |
| FS21-BR | FS21 | TestResolveCloneStr_IncNonNumeric | isIP=false, start="abc", step=1 | 返回 "abc" 原样 (ParseInt 失败) | REAL | |
| FS22-NEG | FS22 | TestResolveCloneStr_RandomNoRange | strategy=random, Range=[] | err 包含 "random strategy needs range" | REAL | |
| FS23-POS | FS23 | TestResolveCloneStr_RandomIP | strategy=random, IP range, seed=42, k=0 | 返回 [lo,hi] 内 IP, 确定性 (同 seed+k 同值) | REAL | |
| FS27-POS | FS27 | TestResolveCloneStr_List | strategy=list, List=["a","b","c"], k=5 | 返回 List[5%3=2]=="c" | REAL | |
| FS28-POS | FS28 | TestResolveCloneStr_ListSingle | List=["x"], k=99 | 返回 "x" (99%1=0) | REAL | |
| FS29-NEG | FS29 | TestResolveCloneStr_Unknown | strategy=unknown | err 包含 "unsupported strategy" | REAL | |
| FS30-NEG | FS30 | TestResolveClonePort_StrFail | strategy 异常 | 返回 0, err | REAL | |
| FS31-BR | FS31 | TestResolveClonePort_Empty | 返回 "" | 返回 0, nil | REAL | |
| FS32-POS | FS32 | TestResolveClonePort_Valid | 返回 "8080" | 返回 8080, nil | REAL | |
| FS33-NEG | FS33 | TestResolveClonePort_Overflow | 返回 "99999" | err (ParseUint 16 位溢出) | REAL | |
| FS35-POS | FS35 | TestResolveCloneSeq_Fixed | strategy=fixed, Value=1000 | 返回 1000, nil | REAL | |
| FS36-POS | FS36 | TestResolveCloneSeq_FixedNil | Value=nil | 返回 0, nil | REAL | |
| FS37-NEG | FS37 | TestResolveCloneSeq_FixedBad | Value="abc" | 返回 0, parse err | REAL | |
| FS41-NEG | FS41 | TestIncIP_Invalid | ipStr="notanip" | err | REAL | |
| FS42-NEG | FS42 | TestIncIP_IPv6 | ipStr="::1" | err 包含 "not IPv4" | REAL | |
| FS43-POS | FS43 | TestIncIP_Normal | "10.0.0.1", n=5 | "10.0.0.6" | REAL | |
| FS44-POS | FS44 | TestIncIP_Wrap | "255.255.255.255", n=1 | "0.0.0.0" (uint32 回绕) | REAL | |
| FS46-POS | FS46 | TestRandomInRange_IPSwap | lo > hi (IP) | 交换 lo/hi, 返回范围内 | REAL | |
| FS48-NEG | FS48 | TestRandomInRange_NumericLoFail | lo="abc" | err | REAL | |

## 组件: replay/flowscaling.go (clonePatches / seqOffsetPatch / checkFlowScalingConflict)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| FS55-POS | FS55 | TestClonePatches_SrcIP | clone.SrcIP="10.0.0.99", layout.SrcIP=26 | 返回 src_ip patch, Bytes==[10,0,0,99], Layer=l3 | REAL | |
| FS56-BR | FS56 | TestClonePatches_SrcIPLayoutNeg | layout.SrcIP=-1 | 无 src_ip patch | REAL | |
| FS58-BR | FS58 | TestClonePatches_SrcIPEmpty | clone.SrcIP="" | 无 src_ip patch | REAL | |
| FS62-POS | FS62 | TestClonePatches_SrcPort | clone.SrcPort=5000 | 返回 src_port patch, Bytes==BE(5000), Layer=l4 | REAL | |
| FS64-BR | FS64 | TestClonePatches_SrcPortZero | clone.SrcPort=0 | 无 src_port patch | REAL | 0 表未配置 |
| FS68-POS | FS68 | TestClonePatches_SrcMAC | clone.SrcMAC="de:ad:be:ef:00:01" | 返回 src_mac patch | REAL | |
| FS-FULL-POS | FS55 | TestClonePatches_AllFields | clone 全字段填充 | 返回 6 patch (src/dst ip/port/mac) | REAL | |
| FS74-BR | FS74 | TestSeqOffsetPatch_Zero | clone.SeqOffset=0 | 返回 false (无 patch) | REAL | |
| FS75-BR | FS75 | TestSeqOffsetPatch_LayoutNeg | SeqOffset=1000, layout.Seq=-1 | 返回 false | REAL | |
| FS76-BR | FS76 | TestSeqOffsetPatch_OutOfBounds | layout.Seq+4 > len(raw) | 返回 false | REAL | |
| FS77-POS | FS77 | TestSeqOffsetPatch_Valid | raw seq=1000, SeqOffset=1000 | patch.Bytes==BE(2000), Field=seq, Layer=l4 | REAL | per-packet orig+offset |
| FS78-POS | FS78 | TestSeqOffsetPatch_Wrap | raw seq=0xFFFFFFFF, SeqOffset=1 | patch.Bytes==BE(0x00000000) | REAL | uint32 回绕 |
| FS79-POS | FS79 | TestCheckFlowScalingConflict_Nil | fs=nil | 返回 nil | REAL | |
| FS87-NEG | FS87 | TestCheckFlowScalingConflict_FieldVaried | fs.SrcIP.Strategy=inc, rule kind=field target=src_ip | err 包含 "FlowScaling varies src_ip" | REAL | 冲突检测 |
| FS88-POS | FS88 | TestCheckFlowScalingConflict_FieldNotVaried | rule target=ttl, fs.SrcIP varied | 返回 nil (ttl 未被 vary) | REAL | |
| FS89-NEG | FS89 | TestCheckFlowScalingConflict_EndpointVaried | fs.SrcIP varied, rule kind=endpoint target=client_ip | err 包含 "endpoint rule sets" | REAL | endpoint 映射到 src_ip |
| FS90-POS | FS90 | TestCheckFlowScalingConflict_EndpointNotVaried | endpoint target=client_ip, fs.DstIP varied (非 src) | 返回 nil | REAL | |
| FS92-POS | FS92 | TestCheckFlowScalingConflict_MappingAllowed | fs.SrcIP varied, rule kind=ipmap | 返回 nil (mapping 允许共存) | REAL | mapping 不冲突 |

## 组件: replay/pacing.go (NewPacer / MaxPacer / TimestampPacer / TokenBucketPacer / PPSPacer)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| PA1-POS | PA1 | TestNewPacer_Original | Mode="original" | 返回 *TimestampPacer, multiplier==1.0 | REAL | |
| PA2-POS | PA2 | TestNewPacer_Multiplier | Mode="multiplier", Multiplier=1.5 | *TimestampPacer, multiplier==1.5 | REAL | |
| PA3-BR | PA3 | TestNewPacer_MultiplierZero | Multiplier=0 | multiplier 被设为 1.0 | REAL | |
| PA4-BR | PA4 | TestNewPacer_MultiplierNeg | Multiplier=-1 | multiplier==1.0 | REAL | |
| PA5-POS | PA5 | TestNewPacer_BPS | Mode="bps", BPS="200k" | *TokenBucketPacer, bps=="200k" | REAL | |
| PA6-POS | PA6 | TestNewPacer_PPS | Mode="pps", PPS=1000 | *PPSPacer, pps==1000 | REAL | |
| PA7-POS | PA7 | TestNewPacer_Max | Mode="max" | MaxPacer{} | REAL | |
| PA8-BR | PA8 | TestNewPacer_Empty | Mode="" | MaxPacer{} | REAL | |
| PA9-BR | PA9 | TestNewPacer_Unknown | Mode="random" | MaxPacer{} (default) | REAL | |
| PA10-POS | PA10 | TestTimestampPacer_FirstCallInit | 首次 Wait | 立即返回 nil, init=true, firstTsUs/startWall 被设 | REAL | |
| PA12-BR | PA12 | TestTimestampPacer_LateAbsorbDrift | scheduled 在过去 (pkt ts 早) | 立即返回, drift 累加 (无 catch-up burst) | REAL | 用注入 clock |
| PA13-POS | PA13 | TestTimestampPacer_CtxCancelDuringSleep | scheduled 在未来, ctx cancel | 返回 ctx.Err() | REAL | |
| PA15-POS | PA15 | TestTimestampPacer_Multiplier2x | multiplier=2.0, 两包 ts 差 1ms | 第 2 包 sleep ≈2ms (加倍) | REAL | 用注入 clock 测实际 sleep 时长 |
| PA20-POS | PA20 | TestMaxPacer_AlwaysNil | 任意输入 | 返回 nil | REAL | |
| PA22-BR | PA22 | TestTokenBucketPacer_BadBPS | bps="bad" | bucket=nil, Wait 返回 nil (不限速) | REAL | |
| PA23-BR | PA23 | TestTokenBucketPacer_BPSLEZero | bps 解析=0 | bucket=nil, 不限速 | REAL | |
| PA26-BR | PA26 | TestTokenBucketPacer_NilBucketNoLimit | bucket=nil | 返回 nil (不限速) | REAL | |
| PA28-POS | PA28 | TestTokenBucketPacer_CtxCancel | bucket 存在, ctx cancel | 返回 ctx.Err() | REAL | |
| PA29-POS | PA29 | TestTokenBucketPacer_ConcurrentOnce | N goroutine 首次 Wait | sync.Once 确保 init 仅一次, 无 panic | REAL | -race |
| PA31-BR | PA31 | TestPPSPacer_ZeroPPS | pps=0 | interval=0, 返回 nil (不限速) | REAL | |
| PA32-POS | PA32 | TestPPSPacer_Interval1000PPS | pps=1000 | interval==1ms | REAL | |
| PA33-BR | PA33 | TestPPSPacer_IntervalLEZero | pps=0 -> interval=0 | 返回 nil | REAL | |
| PA35-POS | PA35 | TestPPSPacer_CtxCancel | interval>0, ctx cancel | 返回 ctx.Err() | REAL | |
| PA36-POS | PA36 | TestPPSPacer_ConcurrentAggregateRate | pps=1000, 8 worker 各调 Wait 100 次, 测总耗时 | 实际聚合 PPS ≈1000 (±10%), 而非 8000; 证明 mutex 串行化跨 worker | REAL | 核心: 测聚合 PPS vs 配置, 非仅 -race |
| PA37-POS | PA37 | TestPPSPacer_FractionalPPS | pps=0.5 | interval==2s | REAL | |

## 组件: replay/checksum.go (setIPChecksum / setL4Checksum)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| CS1-BR | CS1 | TestSetIPChecksum_L3Neg | layout.L3Start=-1 | no-op, frame 不变 | REAL | |
| CS2-BR | CS2 | TestSetIPChecksum_TooShort | l3+20 > len(frame) | no-op | REAL | |
| CS3-POS | CS3 | TestSetIPChecksum_Normal | 标准帧 L3Start=14 | frame[24:26] == 手算 ones-complement sum; gopacket IP 校验合法 | REAL | |
| CS5-BR | CS5 | TestSetIPChecksum_WithOptions | IHL>5 (有 IP 选项) | 仍只算 20 字节 (忽略 options), checksum 基于前 20 字节 | REAL | 已知限制 |
| CS6-BR | CS6 | TestSetL4Checksum_L3Neg | l3=-1 | no-op | REAL | |
| CS7-BR | CS7 | TestSetL4Checksum_L4Neg | l4=-1 | no-op | REAL | |
| CS8-BR | CS8 | TestSetL4Checksum_L4OutOfBounds | l4>=len(frame) | no-op | REAL | |
| CS9-POS | CS9 | TestSetL4Checksum_TCP | L4Protocol="tcp" | proto=6, cksumOff=l4+16, frame[50:52] 重算; gopacket TCP 校验合法 | REAL | |
| CS10-POS | CS10 | TestSetL4Checksum_UDP | L4Protocol="udp" | proto=17, cksumOff=l4+6; gopacket UDP 校验合法 | REAL | |
| CS11-BR | CS11 | TestSetL4Checksum_ICMP | L4Protocol="icmp" | no-op (无伪首部) | REAL | |
| CS14-BR | CS14 | TestSetL4Checksum_CksumOOB | cksumOff+2 > len(frame) | no-op | REAL | |
| CS16-BR | CS16 | TestSetL4Checksum_PartialFrame | l3+20 > len(frame) | 跳过伪首部 IP, 仅算 L4 | REAL | |
| CS17-POS | CS17 | TestSetL4Checksum_EvenLen | l4Len 偶数 | 无 padding, checksum 合法 | REAL | |
| CS18-POS | CS18 | TestSetL4Checksum_OddLen | l4Len 奇数 (加 1 字节 payload) | pad 0, checksum 合法; gopacket 校验通过 | REAL | |
| CS19-POS | CS19 | TestSetL4Checksum_EmptyPayload | l4Len=20 (仅 header) | 只算伪首部+header, checksum 合法 | REAL | |
| CS20-POS | CS20 | TestSetL4Checksum_ZeroedThenRecomputed | TCP checksum 原=0 | 先清零再重算, 新值非零且合法 | REAL | |

## 组件: storage/pcap_repository.go (CreateAsset / GetAsset / GetAssetByHash / UpdateAsset)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| ST1-POS | ST1 | TestCreateAsset_Success | 合法 asset | err==nil, DB 可查到 | SIMULATED | SQLite 内存 |
| ST2-NEG | ST2 | TestCreateAsset_DupKey | 同 ID 二次 Create | err (主键冲突) | SIMULATED | |
| ST3-POS | ST3 | TestGetAsset_UserMatch | asset 属 userA, 查 userA | 返回 asset, 字段非零 | SIMULATED | |
| ST4-NEG | ST4 | TestGetAsset_NotFound | 不存在 ID | gorm.ErrRecordNotFound | SIMULATED | |
| ST5-NEG | ST5 | TestGetAsset_WrongUser | asset 属 userA, 查 userB | ErrRecordNotFound (WHERE user_id 过滤) | SIMULATED | 用户隔离 |
| ST7-POS | ST7 | TestGetAssetByHash_Found | userA+hash 匹配 | 返回 asset | SIMULATED | |
| ST8-NEG | ST8 | TestGetAssetByHash_NotFound | hash 不存在 | ErrRecordNotFound | SIMULATED | |
| ST-ISOL-NEG | ST8 | TestGetAssetByHash_WrongUser | hash 存在但属 userB, 查 userA | ErrRecordNotFound | SIMULATED | GetAssetByHash 用户隔离 |
| ST9-POS | ST9 | TestUpdateAsset_Save | 修改 asset 字段后 Save | DB 中字段更新 | SIMULATED | |

## 组件: storage/pcap_repository.go (UpdateAssetStatus — 状态机)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| ST11-NEG | ST11 | TestUpdateAssetStatus_NotFound | 不存在 ID | err (ErrRecordNotFound) | SIMULATED | |
| ST13-POS | ST13 | TestUpdateAssetStatus_ImportingToReady | current=importing -> ready | err==nil, DB status==ready, parse_error 被清空 | SIMULATED | 合法迁移 |
| ST14-POS | ST14 | TestUpdateAssetStatus_ImportingToError | importing -> error | err==nil, status==error, parse_error 写入 | SIMULATED | |
| ST15-NEG | ST15 | TestUpdateAssetStatus_ImportingToReindexing | importing -> reindexing | err 包含 "illegal status transition" | SIMULATED | 非法 |
| ST16-NEG | ST16 | TestUpdateAssetStatus_ReadyToImporting | ready -> importing | err "illegal" (阻止 rewind) | SIMULATED | 非法 |
| ST17-POS | ST17 | TestUpdateAssetStatus_ReadyToError | ready -> error | err==nil | SIMULATED | |
| ST18-POS | ST18 | TestUpdateAssetStatus_ReadyToReindexing | ready -> reindexing | err==nil | SIMULATED | |
| ST19-POS | ST19 | TestUpdateAssetStatus_ErrorToReindexing | error -> reindexing | err==nil (retry) | SIMULATED | |
| ST20-POS | ST20 | TestUpdateAssetStatus_ErrorToImporting | error -> importing | err==nil (reparse) | SIMULATED | |
| ST21-POS | ST21 | TestUpdateAssetStatus_ErrorToReady | error -> ready | err==nil, parse_error 清空 | SIMULATED | |
| ST22-POS | ST22 | TestUpdateAssetStatus_EmptyToImporting | current="" -> importing | err==nil (新 asset) | SIMULATED | |
| ST23-NEG | ST23 | TestUpdateAssetStatus_EmptyToReady | current="" -> ready | err "illegal" (新 asset 必须先 importing) | SIMULATED | 非法 |
| ST13-SELF-POS | ST13 | TestUpdateAssetStatus_SelfTransition | importing -> importing | err==nil (自迁移允许) | SIMULATED | |

## 组件: storage/pcap_repository.go (ListAssets / DeleteAsset / DeleteAssetComplete / DeleteAssetFlowsAndPackets)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| ST26-POS | ST26 | TestListAssets_AllStatus | status="", userA 有 3 asset | total==3, 返回 3 条 | SIMULATED | |
| ST27-POS | ST27 | TestListAssets_FilterStatus | status="ready" | 仅返回 ready asset | SIMULATED | |
| ST-LIST-ISOL | ST26 | TestListAssets_UserIsolation | userA 2 asset, userB 1 asset, 查 userA | 仅返回 userA 的 2 条 | SIMULATED | WHERE user_id |
| ST31-BR | ST31 | TestListAssets_SizeZero | page=1, size=0 | 返回空列表, total 仍正确 | SIMULATED | LIMIT 0 |
| ST32-NEG | ST32 | TestListAssets_PageZero | page=0, size=10 | offset=-10, 返回错误或空 (SQL 负 offset) | SIMULATED | 边界 |
| ST33-POS | ST33 | TestDeleteAsset_Success | 存在 asset | err==nil, DB 查不到 | SIMULATED | |
| ST35-NEG | ST35 | TestDeleteAssetComplete_NotFound | 不存在 ID | 返回 err, 无文件删除 | SIMULATED | |
| ST39-POS | ST39 | TestDeleteAssetComplete_Full | asset+flows+packets+3 磁盘文件 | DB 中 asset/flows/packets 全删; 3 文件被 os.Remove; 返回 asset 含路径 | SIMULATED | 原子+磁盘删除 |
| ST36-NEG | ST36 | TestDeleteAssetComplete_TxPacketsFail | 用 gorm callback 注入 PacketModel Delete 失败 | 事务回滚, asset/flows/packets 仍在 DB (未删); 返回 err | SIMULATED | 事务回滚 |
| ST37-NEG | ST37 | TestDeleteAssetComplete_TxFlowsFail | 注入 FlowModel Delete 失败 | 事务回滚, 全部仍在; 返回 err | SIMULATED | |
| ST40-BR | ST40 | TestDeleteAssetComplete_EmptyStoragePath | StoragePath="" | 跳过该文件删除, 其余正常 | SIMULATED | |
| ST43-BR | ST43 | TestDeleteAssetComplete_FileNotExist | 磁盘文件已不存在 | os.IsNotExist -> 无 warn 日志 | SIMULATED | |
| ST44-BR | ST44 | TestDeleteAssetComplete_FileRemoveFail | 文件存在但 os.Remove 失败 (模拟只读) | warn 日志, 仍返回 asset (非致命) | SIMULATED | |
| ST47-NEG | ST47 | TestDeleteAssetFlowsAndPackets_PacketsFail | 注入 packet delete 失败 | 事务回滚, flows/packets 仍在 | SIMULATED | |
| ST49-POS | ST49 | TestDeleteAssetFlowsAndPackets_Success | 有 flows+packets | 全删, err==nil | SIMULATED | |

## 组件: storage/pcap_repository.go (CountReplayReferences — 查 StrategyModel + TaskModel)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| ST50-NEG | ST50 | TestCountReplayReferences_StrategyQueryFail | DB 关闭 | 返回 0, err | SIMULATED | |
| ST52-BR | ST52 | TestCountReplayReferences_MalformedStrategyConfig | strategy.Config="bad" | skip, 不报错, count 不增 | SIMULATED | 容错 |
| ST53-POS | ST53 | TestCountReplayReferences_StrategyMatch | strategy protocol=replay, config.pcap_asset_id==assetID | count==1 | SIMULATED | 查 StrategyModel |
| ST54-BR | ST54 | TestCountReplayReferences_StrategyNoMatch | config.pcap_asset_id != assetID | count 不增 | SIMULATED | |
| ST51-BR | ST51 | TestCountReplayReferences_EmptyStrategyConfig | strategy.Config="" | skip | SIMULATED | |
| ST55-NEG | ST55 | TestCountReplayReferences_TaskQueryFail | DB 关闭 (tasks 查询) | 返回 0, err | SIMULATED | |
| ST56-BR | ST56 | TestCountReplayReferences_EmptyBatchConfig | task.BatchConfig="" | skip | SIMULATED | |
| ST57-BR | ST57 | TestCountReplayReferences_MalformedBatch | BatchConfig="bad" | skip, 不报错 | SIMULATED | 容错 |
| ST58-BR | ST58 | TestCountReplayReferences_ClassNotReplay | class.Type="tcp" | skip | SIMULATED | |
| ST61-POS | ST61 | TestCountReplayReferences_TaskMatch | task pending/running, batch 含 replay class pcap_asset_id==assetID | count==1 (每 task 最多 +1) | SIMULATED | 查 TaskModel |
| ST61-BR | ST61 | TestCountReplayReferences_TaskBreakInner | task 含多个 replay class 同 assetID | count 仅 +1 (break inner) | SIMULATED | |
| ST62-POS | ST62 | TestCountReplayReferences_None | 无任何引用 | count==0 | SIMULATED | |
| ST63-POS | ST63 | TestCountReplayReferences_Multiple | 2 strategy + 1 task 引用 | count==3 | SIMULATED | |
| ST-TASK-STATUS-BR | ST61 | TestCountReplayReferences_TaskStatusFilter | task status=completed (非 pending/running) 引用 assetID | count 不增 (仅查 pending/running) | SIMULATED | WHERE status IN |

## 组件: storage/pcap_repository.go (Flow / Packet CRUD + 用户隔离)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| ST64-POS | ST64 | TestCreateFlows_Empty | flows=[] | 返回 nil | SIMULATED | |
| ST65-NEG | ST65 | TestCreateFlows_Fail | DB 关闭 | err | SIMULATED | |
| ST66-POS | ST66 | TestCreateFlows_Success | 1500 flows | err==nil, CountFlowsByAsset==1500 | SIMULATED | CreateInBatches |
| ST67-NEG | ST67 | TestListFlowsByAsset_CountFail | DB 关闭 | err | SIMULATED | |
| ST69-POS | ST69 | TestListFlowsByAsset_Success | 有 flows | 返回 flows+total, 按 first_ts_us ASC | SIMULATED | |
| ST-LISTFLOWS-ISOL | ST69 | TestListFlowsByAsset_UserIsolation | flow 属 userB, 查 userA | 返回 0 条 (WHERE user_id) | SIMULATED | 用户隔离 |
| ST70-POS | ST70 | TestGetFlow_UserMatch | flow 属 userA | 返回 flow | SIMULATED | |
| ST72-NEG | ST72 | TestGetFlow_WrongUser | flow 属 userB, 查 userA | ErrRecordNotFound | SIMULATED | 用户隔离 |
| ST73-NEG | ST73 | TestCountFlowsByAsset_Fail | DB 关闭 | 0, err | SIMULATED | |
| ST-COUNTFLOWS-ISOL | ST74 | TestCountFlowsByAsset_UserIsolation | flow 属 userB, 查 userA | count==0 | SIMULATED | |
| ST75-POS | ST75 | TestCreatePackets_Empty | packets=[] | nil | SIMULATED | |
| ST76-NEG | ST76 | TestCreatePackets_Fail | DB 关闭 | err | SIMULATED | |
| ST78-NEG | ST78 | TestListPacketsByFlow_CountFail | DB 关闭 | err | SIMULATED | |
| ST80-POS | ST80 | TestListPacketsByFlow_Success | 有 packets | 按 index_in_flow ASC | SIMULATED | |
| ST-LISTPKT-FLOW-ISOL | ST80 | TestListPacketsByFlow_UserIsolation | packet 属 userB, 查 userA | 0 条 | SIMULATED | 用户隔离 |
| ST82-NEG | ST82 | TestListPacketsByAsset_FindFail | DB 关闭 | err | SIMULATED | |
| ST83-POS | ST83 | TestListPacketsByAsset_Success | 有 packets | 按 timestamp_us ASC | SIMULATED | |
| ST-LISTPKT-ASSET-ISOL | ST83 | TestListPacketsByAsset_UserIsolation | packet 属 userB, 查 userA | 0 条 | SIMULATED | 用户隔离 |
| ST85-POS | ST85 | TestListAllPacketsByAsset_Success | 有 packets | 按 raw_offset ASC (文件序) | SIMULATED | |
| ST-LISTALL-ISOL | ST85 | TestListAllPacketsByAsset_UserIsolation | packet 属 userB, 查 userA | 0 条 | SIMULATED | 用户隔离 |
| ST86-POS | ST86 | TestGetPacket_UserMatch | packet 属 userA | 返回 packet | SIMULATED | |
| ST87-NEG | ST87 | TestGetPacket_NotFound | 不存在 | ErrRecordNotFound | SIMULATED | |
| ST-GETPKT-ISOL | ST87 | TestGetPacket_WrongUser | packet 属 userB, 查 userA | ErrRecordNotFound | SIMULATED | 用户隔离 |
| ST88-NEG | ST88 | TestCountPacketsByAsset_Fail | DB 关闭 | 0, err | SIMULATED | |
| ST-COUNTPKT-ISOL | ST89 | TestCountPacketsByAsset_UserIsolation | packet 属 userB, 查 userA | count==0 | SIMULATED | 用户隔离 |

## 组件: storage/pcap_repository.go (SearchFlows)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| ST90-BR | ST90 | TestSearchFlows_ColumnNotAllowlisted | filters={"drop_col":"x"} | 该列被 skip (无注入) | SIMULATED | 防注入 |
| ST91-BR | ST91 | TestSearchFlows_EmptyValue | filters={"src_ip":""} | skip 空值 | SIMULATED | |
| ST92-POS | ST92 | TestSearchFlows_StringValue | filters={"src_ip":"10.0.0.1"} | 仅返回 src_ip=10.0.0.1 的 flow | SIMULATED | |
| ST94-POS | ST94 | TestSearchFlows_EmptyFilters | filters={} | 返回全部 (无过滤) | SIMULATED | |
| ST95-NEG | ST95 | TestSearchFlows_CountFail | DB 关闭 | err | SIMULATED | |
| ST97-POS | ST97 | TestSearchFlows_Success | 多过滤 | 返回 flows+total | SIMULATED | |
| ST-SEARCH-ISOL | ST97 | TestSearchFlows_UserIsolation | flow 属 userB, 查 userA | 0 条 (WHERE user_id) | SIMULATED | 用户隔离 |

## 组件: storage/db.go (NewDBWithAdmin / initAdminUser / Close / Ping)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| DB2-POS | DB2 | TestNewDBWithAdmin_SQLite | cfg.Type="sqlite", path=":memory:" | 返回 DB 非 nil, err==nil; AutoMigrate 已建表 | SIMULATED | 内存库 |
| DB3-NEG | DB3 | TestNewDBWithAdmin_UnsupportedType | cfg.Type="" | err 包含 "unsupported database type" | REAL | |
| DB4-NEG | DB4 | TestNewDBWithAdmin_Mysql | cfg.Type="mysql" | err "unsupported" | REAL | v1 不支持 |
| DB7-NEG | DB7 | TestNewDBWithAdmin_AutoMigrateFail | 注入 migrate 失败 | err 包含 "auto migrate" | SIMULATED | |
| DB8-BR | DB8 | TestNewDBWithAdmin_NoAdmin | adminCfg=nil | 跳过 admin init, 返回 DB | SIMULATED | |
| DB10-POS | DB10 | TestNewDBWithAdmin_AllSuccess | sqlite + adminCfg | 返回 DB, admin 已建 | SIMULATED | |
| DB12-POS | DB12 | TestInitAdminUser_ExistsMatch | admin 存在密码匹配 | 返回 nil, 不改密码 | SIMULATED | |
| DB13-POS | DB13 | TestInitAdminUser_ExistsMismatch | admin 存在密码不匹配 | 密码被更新 (bcrypt 验证新密码) | SIMULATED | |
| DB16-POS | DB16 | TestInitAdminUser_CreateNew | admin 不存在 | 创建 admin, DB 可查 | SIMULATED | |
| DB16-NEG | DB16 | TestInitAdminUser_CreateFail | 注入 Create 失败 | err 包含 "create admin user" | SIMULATED | |
| DB20-POS | DB20 | TestClose_Success | 正常 DB | Close 返回 nil | SIMULATED | |
| DB23-POS | DB23 | TestPing_Success | 正常 DB | Ping 返回 nil | SIMULATED | |
| DB24-POS | DB24 | TestIsConnected_True | 正常 DB | 返回 true | SIMULATED | |
| DB25-POS | DB25 | TestIsConnected_False | DB 关闭后 | 返回 false | SIMULATED | |

## 组件: storage/db.go (GetSettings / SaveSettings / CountActiveTasks / CountTasksByProtocol)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| DB26-POS | DB26 | TestGetSettings_Exists | 已有 default 行 | 返回该行 | SIMULATED | |
| DB27-POS | DB27 | TestGetSettings_SeedDefault | 无 default 行 | 种子并返回 MaxTasks==100, BufferSize==4096, LogLevel=="info" | SIMULATED | 断言非零默认值 |
| DB28-NEG | DB28 | TestGetSettings_SeedCreateFail | 注入 Create 失败 | err | SIMULATED | |
| DB30-POS | DB30 | TestSaveSettings_Success | 合法 settings | err==nil, id=="default" | SIMULATED | |
| DB32-POS | DB32 | TestCountActiveTasks_Success | 2 running+1 pending+2 completed | count==3 (仅 running+pending) | SIMULATED | |
| DB34-POS | DB34 | TestCountTasksByProtocol_Success | 多 protocol task | map 含各 protocol 计数 | SIMULATED | |

## 组件: storage/models.go (AutoMigrate + 唯一索引)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| STM4-POS | STM4 | TestAutoMigrate_AllSuccess | 正常 sqlite | err==nil, 各表存在 | SIMULATED | |
| STM3-NEG | STM3 | TestAutoMigrate_UniqueIndexFail | 注入 Exec 失败 | err 包含 "user_hash unique index" | SIMULATED | |
| STM-UNIQUE-POS | STM3 | TestAutoMigrate_UniqueUserHashIndex | 同 user_id+file_hash 二次 Create | 第二次 Create 失败 (唯一索引) | SIMULATED | (user_id,file_hash) 唯一索引 |
| STM-DEDUP-POS | STM3 | TestConcurrentImportDedup | 2 goroutine 同时 CreateAsset 同 user_id+file_hash | 仅 1 成功, 1 失败 (唯一约束); GetAssetByHash 返回成功的那条 | SIMULATED | 并发导入去重, -race |
| STM-COMPOSITE-POS | STM2 | TestAutoMigrate_CompositeIndex | 查询 ListPacketsByFlow | 走 idx_pkt_flow_seq 索引 (EXPLAIN 含该索引) | SIMULATED | 复合索引存在 |

## 组件: 跨层集成 (planner -> rewriter -> checksum 端到端)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| INT-REPLAY-POS | RP3+RW2+CS3 | TestReplayE2E_FieldRewriteAndChecksum | DB ready asset + pcap 含 1 TCP 包, rewrite: field src_ip=192.168.1.1 | drain channel 取 cfg; ApplyPatches(cfg._raw, cfg._patches, layout, mode); gopacket 解析补丁后字节: SrcIP==192.168.1.1, DstIP 不变, IP+TCP checksum 合法 | SIMULATED | 端到端: planner->rewriter->checksum |
| INT-REPLAY-IPMAP-POS | RP3+RU88 | TestReplayE2E_IPMapCIDR | rewrite: ipmap {"10.0.0.0/8":"192.168.0.0/16"}, flow src_ip=10.0.0.5 | 补丁后 SrcIP==192.168.0.5 (网段平移保偏移); checksum 合法 | SIMULATED | ipmap CIDR 端到端 |
| INT-REPLAY-OFFSET-POS | RP3+RU134 | TestReplayE2E_ApplyOffsetSeq | rewrite: field target=seq apply=offset fixed=1000, 两包 origSeq=1000/2000 | 补丁后 seq 分别=2000/3000 (per-packet orig+delta); checksum 合法 | SIMULATED | apply:offset 端到端 |
| INT-REPLAY-CLONE-POS | RP46+FS4 | TestReplayE2E_FlowScalingClone | FlowScaling.Count=3 SrcIP inc, 1 包 | 产出 3 packet, src_ip 分别=10.0.0.1/2/3; seq 各加 clone.SeqOffset | SIMULATED | flowscaling 端到端 |
| INT-REPLAY-CTX-POS | RP-C1 | TestReplayE2E_CtxCancel | ctx 在 N 包后 cancel | 已产出 < 总数, channel 关闭, 无死锁 | SIMULATED | -race |
| INT-REPLAY-USERID-NEG | RP4 | TestReplayE2E_UserIsolation | asset 属 userB, Plan 传 userID=userA | err 包含 "pcap asset" (GetAsset WHERE user_id 过滤) | SIMULATED | userID 参数端到端隔离 |

## 组件: 真实物理资源 (MANUAL)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| MAN-NIC-1 | 真实回放 | Manual_ReplayToPhysicalNIC | ready asset + replay spec, 输出到 enp135s0f0np0 | 1.无法自动测:依赖真实 NIC/内核 AF_PACKET 发包到线缆。2.命令: `tcpdump -i enp135s0f0np0 -nn -c 50 -w /tmp/replay.pcap &` 后启动回放任务, 再 `tcpdump -r /tmp/replay.pcap -nn \| head`。3.预期: 抓包看到 src_ip=192.168.1.1 (rewrite 后), 包数≈pcap 包数×loop, MAC 为网卡真实 MAC | MANUAL | 真实发包到物理网卡 |
| MAN-NIC-2 | 真实回放 | Manual_ReplayDualPortRouting | dual port group (enp135s0f0np0 + enp135s0f0np1), c2s 上行 s2c 下行 | 1.无法自动测:依赖双物理 NIC + 线缆。2.命令: 两口同时 `tcpdump -i <nic> -nn -w /tmp/up.pcap &` / `/tmp/down.pcap &`。3.预期: up.pcap 仅 c2s 方向包, down.pcap 仅 s2c 方向包 | MANUAL | 真实双口路由 |
| MAN-PPS-1 | 真实限速精度 | Manual_PPSPacerWirePrecision | pps=1000, 输出物理网卡, 60 秒 | 1.无法自动测:真实 PPS 精度需线缆抓包统计。2.命令: `tcpdump -i enp135s0f0np0 -nn -c 60000 -w /tmp/pps.pcap &` 60 秒后 `tcpdump -r /tmp/pps.pcap \| wc -l`。3.预期: 包数≈60000 (1000pps×60s, ±5%); 跨 worker 聚合不超 1000pps | MANUAL | 真实 PPS 限速精度 |
| MAN-BPS-1 | 真实限速精度 | Manual_TokenBucketWirePrecision | bps="8M", 输出物理网卡, 30 秒 | 1.无法自动测:真实 BPS 精度需线缆字节统计。2.命令: `tcpdump -i enp135s0f0np0 -nn -w /tmp/bps.pcap &` 30 秒后 `tcpdump -r /tmp/bps.pcap \| wc -c`。3.预期: 字节≈3MB (1MB/s×30s, ±10%) | MANUAL | 真实 BPS 限速精度 |
| MAN-TS-1 | 真实限速精度 | Manual_TimestampPacerWirePrecision | speed.Mode="original", pcap 跨度 10s, 输出物理网卡 | 1.无法自动测:真实时间戳 pacing 精度需线缆抓包时间戳对比。2.命令: `tcpdump -i enp135s0f0np0 -nn -tt -w /tmp/ts.pcap &` 后 `tcpdump -r /tmp/ts.pcap -tt \| awk '{print $1}'`。3.预期: 相邻包时间间隔与 pcap 原始间隔一致 (±5%), 无 catch-up burst | MANUAL | 真实时间戳 pacing 精度 |
| MAN-CLONE-1 | 真实回放 | Manual_FlowScalingCloneWire | FlowScaling.Count=10, 输出物理网卡 | 1.无法自动测:多 clone 发包到线缆。2.命令: `tcpdump -i enp135s0f0np0 -nn -w /tmp/clone.pcap &` 后 `tcpdump -r /tmp/clone.pcap -nn \| awk '{print $3}' \| sort -u \| wc -l`。3.预期: 出现 10 个不同 src_ip (10 个 clone), 每个流量均等 | MANUAL | 真实多 clone 回放 |

## 汇总

- 真实(REAL): 268 个
- 模拟(SIMULATED): 149 个
- 手动(MANUAL): 6 个
- 合计: 423 个测试点

### MANUAL 测试点清单

| ID | 一句话原因 |
|---|---|
| MAN-NIC-1 | 真实回放到物理网卡 enp135s0f0np0, 需 tcpdump 线缆抓包验证 rewrite 后字段实际发出 |
| MAN-NIC-2 | 真实双物理 NIC 双口路由 (c2s/s2c 分流), 需两口同时抓包验证方向 |
| MAN-PPS-1 | PPSPacer 真实 PPS 限速精度, 需线缆抓包统计实际包率 (进程内聚合测试 PA36 仅测逻辑互斥, 不证线缆精度) |
| MAN-BPS-1 | TokenBucketPacer 真实 BPS 限速精度, 需线缆抓包统计实际字节率 |
| MAN-TS-1 | TimestampPacer 真实时间戳 pacing 精度, 需线缆抓包时间戳与 pcap 原始间隔对比 |
| MAN-CLONE-1 | 真实多 clone 回放到线缆, 需抓包验证 10 个不同 src_ip 实际发出且均等 |
