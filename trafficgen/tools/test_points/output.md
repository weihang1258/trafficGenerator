# 输出层 测试点细化

## PCAPWriter (`/home/weihang/trafficGenerator/trafficgen/internal/output/pcap.go`)

### NewPCAPWriter

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| P1-POS | P1 | TestPCAPWriter_New_Valid | 合法临时路径 | 返回 `(*PCAPWriter, nil)`；文件已创建且 size >= 24(pcap header)；head 24 字节 magic=0xa1b2c3d4(小端) | REAL | |
| P2-NEG | P2 | TestPCAPWriter_New_InvalidPath | 不可写路径(/proc/x.pcap) | 返回 `(nil, error)`，error 含 "failed to create pcap file:" 前缀 | REAL | |
| P3-NEG | P3 | TestPCAPWriter_New_WriteHeaderFail | 路径有效但 writeGlobalHeader 失败（模拟 os.Create 成功但 bw.Write 失败） | 文件被 Close，返回 `(nil, error)` | SIMULATED | 用文件描述符注入 Writer 失败；或用只写 0 字节的 fake io.Writer 模拟 bufio 失败 |

### writeGlobalHeader

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| P4-POS | P4 | TestPCAPWriter_WriteHeader | NewPCAPWriter 成功后检查写入 | 用 gopacket/pcapgo 读取文件头：magic=v1.0, major=2, minor=4, snapLen=65535, linkType=Ethernet(1) | REAL | |
| P5-NEG | P5 | TestPCAPWriter_WriteHeader_Fail | 模拟 bw.Write 返回 error | 返回 error | SIMULATED | 用 bufio Writer 包装有限 bytes.Buffer（比如 buf size=10）触发写入失败 |

### Write

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| P6-POS | P6 | TestPCAPWriter_Write_Normal | 3 个包 [][]byte{{0x01,0x02}, {0x03,0x04,0x05}, {0x06}} | 返回 nil；Written() == (2+16)+(3+16)+(1+16)=54；用 pcapgo 读取文件可解析出各包 caplen/len/data 正确 | REAL | |
| P7-NEG | P7 | TestPCAPWriter_Write_Closed | Close 后再次 Write | 返回 error 含 "pcap writer closed" | REAL | |
| P8-NEG | P8 | TestPCAPWriter_Write_HeaderWriteFail | 模拟 bw.Write(buf[:]) 在第 2 个包失败 | 返回 error；Written() 只递增了第 1 个包的部分 | SIMULATED | 用有限 bufio 触发 |
| P9-NEG | P9 | TestPCAPWriter_Write_BodyWriteFail | 模拟 bw.Write(packet) 在第 2 个包失败 | 返回 error；Written() 只递增到 header(16) 但未计入包体 | SIMULATED | 用有限 bufio 触发 |
| P10-BR1 | P10 | TestPCAPWriter_Write_Empty | [][]byte{} 或 nil | 返回 nil；Written() == 0 | REAL | |
| P10-BR2 | P10 | TestPCAPWriter_Write_SinglePacket | 1 个 nil 子元素 [][]byte{nil} | len(nil) == 0，caplen=0 记录被写入 | REAL | |

### WriteTimed

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| P11-POS | P11 | TestPCAPWriter_WriteTimed_ExplicitTS | Packets 各带不同 Timestamp(t1, t2, t3) | 用 pcapgo 读取文件的记录头，各包 ts 精确匹配 t1/t2/t3 | REAL | |
| P12-BR1 | P12 | TestPCAPWriter_WriteTimed_ZeroTS | 部分包 Timestamp=0 | 零值包获得 time.Now()（断言 ts 接近当前时间） | REAL | 时间断言精度放宽到 5s |
| P12-BR2 | P12 | TestPCAPWriter_WriteTimed_MixedTS | 部分显式 TS + 部分零值 | 显式 TS 包时间精确匹配，零值包接近当前时间 | REAL | |
| P13-NEG | P13 | TestPCAPWriter_WriteTimed_Closed | Close 后调用 WriteTimed | 返回 error 含 "pcap writer closed" | REAL | |
| P14-NEG | P14 | TestPCAPWriter_WriteTimed_HeaderFail | 类似 P8 | 返回 error | SIMULATED | |
| P15-NEG | P15 | TestPCAPWriter_WriteTimed_BodyFail | 类似 P9 | 返回 error | SIMULATED | |
| P16-BR1 | P16 | TestPCAPWriter_WriteTimed_Empty | []TimedPacket{} 或 nil | 返回 nil；Written() == 0 | REAL | |

### Close

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| P17-POS | P17 | TestPCAPWriter_Close_Normal | 写入数据后 Close | 返回 nil；文件完整可被 pcapgo 读取所有包 | REAL | |
| P18-NEG1 | P18 | TestPCAPWriter_Close_FlushFail | 模拟 Flush 失败 | 返回 flush 的 error | SIMULATED | 用有限的 bufio 写入然后强制 Close，Flush 可能失败 |
| P19-NEG2 | P19 | TestPCAPWriter_Close_SyncFail | 模拟 fsync 失败(用虚假 *os.File) | 返回 sync error | SIMULATED | 用 os.NewFile 封装只读 fd 等 trick |
| P20-NEG3 | P20 | TestPCAPWriter_Close_CloseFail | 模拟 file.Close 失败 | 返回 close error | SIMULATED | |
| P21-NEG4 | P21 | TestPCAPWriter_Close_MultiFail | Flush/Sync/Close 全部失败 | 返回 flush error（首 error 优先） | SIMULATED | |
| P22-BR1 | P22 | TestPCAPWriter_Close_Double | Close 两次 | 第二次返回 nil（幂等） | REAL | |
| P23-BR2 | P23 | TestPCAPWriter_Close_NilBuf | 构造 bw=nil 的 writer（通过外部 Set） | 不 panic，跳过 Flush | REAL | 难以自然构造，只用 Remove-Pointer 手法 |

### Path / Written

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| P24-POS | P24 | TestPCAPWriter_Path | NewPCAPWriter(tpath) | Path() == tpath | REAL | |
| P25-POS | P25 | TestPCAPWriter_Written | 写入 3 个包各 10 byte | Written() == 3*(10+16) == 78 | REAL | |

---

## RotatingPCAPWriter (`pcap.go`)

### NewRotatingPCAPWriter

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| R1-POS | R1 | TestRotatingWriter_New_Valid | 合法 basePath, maxSize=1MB, maxFiles=3 | 返回 `(*RotatingPCAPWriter, nil)`；首个文件已创建 | REAL | |
| R2-NEG | R2 | TestRotatingWriter_New_RotateFail | 不可写目录/只读路径 | 返回 `(nil, error)` | REAL | |

### Rotating.Write

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| R3-POS | R3 | TestRotatingWriter_Write_Normal | 写入 < maxSize 的数据 | 返回 nil；写入当前文件；不产生新文件 | REAL | |
| R4-POS | R4 | TestRotatingWriter_Write_Rotate | 写入超 maxSize 的数据(先写 500 再写 500 maxSize=800) | 触发轮转；生成 2 个文件；文件名含时间戳+序号 | REAL | |
| R5-BR1 | R5 | TestRotatingWriter_Write_SelfRecover | 令 current=nil（模拟前置故障）后 Write | 自动恢复；rotate 创建新文件；写入成功 | REAL | 存根后直接设 w.current = nil |
| R6-NEG1 | R6 | TestRotatingWriter_Write_RotateFail | 写入超阈值但 rotate 失败（磁盘满） | 返回 rotate 的 error；current 保持 nil | SIMULATED | |
| R7-NEG2 | R7 | TestRotatingWriter_Write_InnerWriteFail | 模拟 inner.Write 失败 | 返回 error；currentSize 不递增 | SIMULATED | |
| R8-BR2 | R8 | TestRotatingWriter_Write_Empty | 空包列表 | 返回 nil；无新文件创建；size 不变 | REAL | |

### Rotating.Close

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| R9-POS | R9 | TestRotatingWriter_Close_Normal | 写入后 Close | 返回 nil | REAL | |
| R10-BR1 | R10 | TestRotatingWriter_Close_NilCurrent | 从未写入（current=nil） | 返回 nil（无操作） | REAL | |
| R11-NEG1 | R11 | TestRotatingWriter_Close_InnerCloseFail | 模拟 inner.Close 返回 error | 返回 error | SIMULATED | |

### rotate

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| R12-POS | R12 | TestRotatingRotate_Normal | 有旧文件且 close 成功，新文件创建成功 | 返回 nil；旧文件被关闭；新文件成为 current；maxFiles=3 时旧文件未被删除（未超限） | REAL | |
| R13-POS1 | R13 | TestRotatingRotate_OldCloseWarn | 旧文件 close 失败但新文件创建成功 | 返回 nil；warn 日志输出；新文件正常创建 | REAL | 验证 zap.L() 中有 warn 记录 |
| R13-POS2 | R13 | TestRotatingRotate_OldCloseWarn_MaxFiles | 同上且 maxFiles>0 | enforceMaxFiles 执行 | REAL | |
| R14-NEG1 | R14 | TestRotatingRotate_NewFileFail | 旧文件 close 失败 + 新文件创建失败 | 返回 NewPCAPWriter 的 error；current 保持 nil | SIMULATED | |
| R15-BR1 | R15 | TestRotatingRotate_FirstCall | 首次调用（无旧文件） | 跳过旧文件关闭；新文件创建成功 | REAL | |
| R16-NEG2 | R16 | TestRotatingRotate_FirstCallFail | 首次调用但新文件创建失败 | 返回 error；current 保持 nil | REAL | |
| R17-POS2 | R17 | TestRotatingRotate_EnforceMaxFiles | maxFiles=2, 已 3 个文件时 rotate | 3 个文件排序后删除最旧的 1 个；保留 2 个最新 | REAL | 用时间戳+序号验证排序 |
| R18-BR2 | R18 | TestRotatingRotate_MaxFilesZero | maxFiles=0（禁用） | 不执行 enforceMaxFiles | REAL | |

### enforceMaxFiles

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| R19-BR1 | R19 | TestRotatingEnforce_UnderLimit | 2 个文件, maxFiles=3 | 无文件被删除 | REAL | |
| R20-BR2 | R20 | TestRotatingEnforce_GlobError | 极长/含非法字符的 basePath | 返回（无操作） | REAL | |
| R21-POS | R21 | TestRotatingEnforce_DeleteExcess | 5 个文件, maxFiles=2 | 删除最旧的 3 个；仅保留 2 个最新文件 | REAL | 用 os.Stat 验证删除 |
| R22-POS1 | R22 | TestRotatingEnforce_DeleteFail | 5 个文件, maxFiles=2, 其中一个 os.Remove 失败（只读权限） | 继续删除其余文件；warn 日志记录每个失败 | REAL | chmod 移除写权限再试；或 mock os.Remove |

---

## InterfaceWriter (`interface.go`)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| I1-POS | I1 | TestInterfaceWriter_New_Valid | 有效接口名（如 lo） | 返回 `(*InterfaceWriter, nil)` | SIMULATED | 需要 lo 接口存在；若没有则跳过 |
| I2-NEG | I2 | TestInterfaceWriter_New_Invalid | 不存在的接口名 "nonexist0" | 返回 `(nil, error)` | REAL | |
| I3-POS | I3 | TestInterfaceWriter_Write_Normal | 3 个包，handle 打开 | 返回 nil；w.sent == 3 | SIMULATED | 用模拟 handle 或在 lo 接口写入 |
| I4-NEG1 | I4 | TestInterfaceWriter_Write_Closed | Close 后 Write | 返回 error 含 "interface writer closed" | REAL | |
| I5-BR1 | I5 | TestInterfaceWriter_Write_PartialFail | 部分包 WritePacketData 失败 | 返回 firstErr；w.sent 只计数成功包；w.errors 计数失败包 | SIMULATED | 用 mock handle 使第 2 个包失败 |
| I6-BR2 | I6 | TestInterfaceWriter_Write_AllFail | 所有包都失败 | 返回 firstErr；w.sent 不变=0；w.errors==len(packets) | SIMULATED | |
| I7-BR3 | I7 | TestInterfaceWriter_Write_Empty | nil 或空切片 | 返回 nil；w.sent 不变 | REAL | |
| I8-POS | I8 | TestInterfaceWriter_Close_Normal | handle 打开 | 返回 nil；handle 被设为 nil | SIMULATED | |
| I9-BR1 | I9 | TestInterfaceWriter_Close_AlreadyClosed | handle 已 nil | 返回 nil | REAL | |
| I10-BR2 | I10 | TestInterfaceWriter_Close_Double | 两次 Close | 第二次返回 nil | REAL | |
| I11-POS | I11 | TestInterfaceWriter_Stats_WithDuration | 写入、等待后调用 Stats | 返回 map 含 PPS>0 | SIMULATED | |
| I12-BR1 | I12 | TestInterfaceWriter_Stats_ZeroDuration | 创建后立即 Stats | PPS==0 | REAL | |
| I13-POS | I13 | TestInterfaceWriter_InjectPacket | gopacket 合法包 | 委托 Write，sent 递增 | SIMULATED | |

---

## BatchInterfaceWriter (`interface.go`)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| B1-POS | B1 | TestBatchWriter_New_Valid | batchSize=10, flushInterval=100ms | 返回有效 writer；flushLoop goroutine 已启动；定时器已设置 | SIMULATED | |
| B2-NEG | B2 | TestBatchWriter_New_InvalidIface | 不存在接口名 | 返回 `(nil, error)` | REAL | |
| B3-POS1 | B3 | TestBatchWriter_Write_BelowBatchSize | 写入 3 个包, batchSize=10 | 返回 nil；内部 batch 大小=3；未触发 flush | REAL | |
| B4-POS2 | B4 | TestBatchWriter_Write_ExactBatchSize | 写入 3 个包, batchSize=3 | 触发 flushLocked；batch 清空 | SIMULATED | |
| B5-POS3 | B5 | TestBatchWriter_Write_MultipleFlush | 写入 25 个包, batchSize=10 | 触发 3 次 flush（10+10+5）；全部处理 | SIMULATED | |
| B6-NEG | B6 | TestBatchWriter_Write_FlushError | flushLocked 返回 error | Write 返回该 error；剩余包不继续处理 | SIMULATED | |
| B7-POS | B7 | TestBatchWriter_FlushLoop_Done | Close 关闭 done channel | flushLoop goroutine 退出；wg.Done | SIMULATED | |
| B8-POS | B8 | TestBatchWriter_FlushLoop_TimerFlush | flushChan 收到信号，flush 成功 | flush 执行；timer 重置 | SIMULATED | |
| B9-BR1 | B9 | TestBatchWriter_FlushLoop_TimerFlushFail | flushChan 信号 + flushLocked 失败 | warn 日志输出；timer 重置；loop 继续 | SIMULATED | |
| B10-BR2 | B10 | TestBatchWriter_FlushLoop_DoneBeforeTimer | Close 和 timer 回调竞争 | timer 回调检测 done→直接返回；不发送到 flushChan | SIMULATED | |
| B11-BR3 | B11 | TestBatchWriter_FlushLoop_ChanFull | flushChan 满 | 走 default，drop 该 tick | SIMULATED | |
| B12-BR4 | B12 | TestBatchWriter_FlushLoop_AfterLoopExit | flushLoop 已退出后 timer 回调 | 回调 detect done→return | SIMULATED | |
| B13-BR5 | B13 | TestBatchWriter_FlushLocked_EmptyBatch | 空 batch | 返回 nil | REAL | |
| B14-NEG1 | B14 | TestBatchWriter_FlushLocked_NilHandle | handle 已 nil（write-after-close） | 返回 error；batch 清空 | SIMULATED | |
| B15-POS | B15 | TestBatchWriter_FlushLocked_Normal | 非空 batch, 所有写成功 | 返回 nil；sent 递增；batch 清空 | SIMULATED | |
| B16-BR6 | B16 | TestBatchWriter_FlushLocked_PartialFail | 部分写成功部分失败 | 返回 firstErr；sent 计成功；errors 计失败；batch 清空 | SIMULATED | |
| B17-BR7 | B17 | TestBatchWriter_FlushLocked_AllFail | 全部写失败 | 返回 firstErr；sent 不变；errors 累计；batch 清空 | SIMULATED | |
| B18-POS | B18 | TestBatchWriter_Close_Normal | 正常 Close | 返回 nil | SIMULATED | |
| B19-NEG1 | B19 | TestBatchWriter_Close_FlushLockedFails | flushLocked 返回 error | flushLocked 的 error 被返回（优先于 closeErr） | SIMULATED | |
| B20-NEG2 | B20 | TestBatchWriter_Close_CloseFails | InterfaceWriter.Close 返回 error | 返回 closeErr（flushLocked nil 时） | SIMULATED | |
| B21-BR8 | B21 | TestBatchWriter_Close_Double | 两次 Close | 第二次幂等（once.Do）| SIMULATED | |
| B22-BR9 | B22 | TestBatchWriter_Close_TimerRace | 并发 timer 和 Close | 无 panic；timer.Stop 安全 | SIMULATED | |

---

## MultiWriter (`output.go`)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| M1-POS | M1 | TestMultiWriter_New_Multiple | 3 个 mock Writer | 返回包含 3 个 writer | REAL | |
| M2-BR1 | M2 | TestMultiWriter_New_Empty | 0 个 writer | 返回 empty slice | REAL | |
| M3-POS | M3 | TestMultiWriter_Write_AllOK | 3 个 mock Writer 全部成功 | 返回 nil；每个 writer.Write 都被调用 | REAL | |
| M4-BR1 | M4 | TestMultiWriter_Write_SomeFail | 第 1 个失败，第 2 个成功，第 3 个失败 | 返回 lastErr(第 3 个的 error)；所有 writer.Write 均被调用 | REAL | |
| M5-BR2 | M5 | TestMultiWriter_Write_AllFail | 全部失败 | 返回最后一个 error | REAL | |
| M6-BR3 | M6 | TestMultiWriter_Write_NoWriters | 空 MultiWriter.Write | 返回 nil | REAL | |
| M7-POS | M7 | TestMultiWriter_Close_AllOK | 全部 Close 成功 | 返回 nil | REAL | |
| M8-BR1 | M8 | TestMultiWriter_Close_SomeFail | 部分 Close 失败 | 返回最后 error；所有 Close 被调用 | REAL | |
| M9-BR2 | M9 | TestMultiWriter_Close_AllFail | 全部 Close 失败 | 返回最后 error | REAL | |
| M10-BR3 | M10 | TestMultiWriter_Close_NoWriters | 空 MultiWriter.Close | 返回 nil | REAL | |
| M11-POS | M11 | TestMultiWriter_AddWriter | 添加一个新 Writer | writers 长度+1 | REAL | |

---

## Manager (`output.go`)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| G1-POS | G1 | TestManager_New | 创建 Manager | 返回空 map | REAL | |
| G2-POS | G2 | TestManager_Register_New | 新名字 "a" + mock Writer | 注册成功；Get("a") 返回该 writer | REAL | |
| G3-BR1 | G3 | TestManager_Register_Overwrite | 先注册 "a"=w1，再注册 "a"=w2 | Get("a") 返回 w2（覆盖） | REAL | |
| G4-POS | G4 | TestManager_Get_Exists | 已注册 "b" | Get("b") 返回 (writer, true) | REAL | |
| G5-BR1 | G5 | TestManager_Get_NotExists | 未注册 "nonexist" | Get("nonexist") 返回 (nil, false) | REAL | |
| G17-POS | G17 | TestManager_List_Multiple | 注册 "a","b","c" | List() 返回包含 3 个名字的 slice | REAL | |
| G18-BR1 | G18 | TestManager_List_Empty | 无注册 | List() 返回空 string slice | REAL | |
| G6-POS | G6 | TestManager_Write_Exists | "a" 已注册, Write 成功 | 返回 nil | REAL | |
| G7-NEG1 | G7 | TestManager_Write_WriteFail | "a" 已注册, Write 失败 | 返回 error | REAL | |
| G8-NEG2 | G8 | TestManager_Write_NotExists | "nonexist" | 返回 error 含 "writer not found" | REAL | |
| G9-POS | G9 | TestManager_WriteAll_AllOK | 全部成功 | 返回 nil | REAL | |
| G10-BR1 | G10 | TestManager_WriteAll_SomeFail | 部分失败 | 返回最后 error；所有 writer.Write 被调用 | REAL | |
| G11-BR2 | G11 | TestManager_WriteAll_AllFail | 全部失败 | 返回最后 error | REAL | |
| G12-BR3 | G12 | TestManager_WriteAll_Empty | 空 map | 返回 nil | REAL | |
| G13-POS | G13 | TestManager_Close_Normal | 全部 Close 成功 | 返回 nil；map 被清空 | REAL | |
| G14-BR1 | G14 | TestManager_Close_SomeFail | 部分 Close 失败 | 返回最后 error；map 清空（即使在 error 后仍执行 delete） | REAL | |
| G15-BR2 | G15 | TestManager_Close_AllFail | 全部 Close 失败 | 返回最后 error；map 清空 | REAL | |
| G16-BR3 | G16 | TestManager_Close_Empty | 空 map | 返回 nil | REAL | |

---

## OutputWorker (`output.go`)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| O1-POS | O1 | TestOutputWorker_New | id=1, packetChan, writer, wg | 返回 OutputWorker；ctx/cancel 已创建 | REAL | |
| O2-POS | O2 | TestOutputWorker_Start | 正常 OutputWorker | 启动 goroutine；wg.Add(1) | REAL | |
| O3-POS | O3 | TestOutputWorker_Stop | 运行中调用 Stop | cancel 被调用；goroutine 通过 ctx.Done() 退出 | REAL | 断言 select 收到 ctx.Done |
| O10-NEG | O10 | TestOutputWorker_GetStats_DataRace | 并发 run() 和 GetStats() | **可能有 data race** — 需用 -race 检测 | REAL | w.stats 无锁读取；若 -race 发现竞争需修复 |
| O4-POS | O4 | TestOutputWorker_Run_CtxCancel | 上下文取消 | goroutine 退出；wg.Done 被调用 | REAL | |
| O5-POS1 | O5 | TestOutputWorker_Run_ChanClosed | packetChan 关闭 | goroutine 退出；wg.Done 被调用 | REAL | |
| O6-POS2 | O6 | TestOutputWorker_Run_PacketOK | 收到包，writer.Write 成功 | PacketsWritten += len(packets)；BytesWritten += sum(len(p)) | REAL | |
| O7-BR1 | O7 | TestOutputWorker_Run_WriteFail | 收到包，writer.Write 失败 | Errors++；PacketsWritten/BytesWritten 不递增；循环继续 | REAL | |
| O8-BR2 | O8 | TestOutputWorker_Run_CtxAndPacket | 同时 ctx 取消 + 包可用 | select 随机选择：ctx=>exit；packet=>处理后退出 | REAL | |
| O9-POS | O9 | TestOutputWorker_Run_DeferAlways | 任何退出路径 | defer wg.Done 始终执行 | REAL | |

---

## 汇总

| 类型 | 数量 |
|------|------|
| 真实(REAL) | 67 |
| 模拟(SIMULATED) | 34 |
| 手动(MANUAL) | 0 |
| **合计** | **101 个测试点** |

输出层组件不涉及手动测试——PCAPWriter 写入文件和轮转可用临时文件验证；InterfaceWriter/BatchInterfaceWriter 虽是网卡操作但逻辑部分可用 mock 替代；如确需验证**真实 AF_PACKET 内核行为**（如多队列分流、硬件时间戳），则应标记 MANUAL 并添加说明。

**MANUAL 说明**：OutputWorker.GetStats w.stats 无锁读取发现潜在 data race（O10-NEG）。若需要同时修改引擎集成测试核查该处。若验证真实网卡 PPS/PPSPacer 精度或内核 AF_PACKET 发包行为，需用户手动，但输出层本身的逻辑测试已全覆盖。