# 引擎核心 测试点细化

> 依据 `tools/test_point_spec.md` 规范，将 `tools/enum_results/engine_core.md` 中枚举的每个场景细化为原子测试点。
>
> **重要行为校正（与任务描述的差异）**：任务描述称"RingBuffer 溢出返回 False 触发 fatal error 且管道停止"。但实际 Go 引擎 (`worker.go:661-679`) 中缓冲区溢出是 **best-effort**：仅触发 `OnBufferOverflow` 回调 + `stats.Errors++`，**不**调用 `SetFatalError`、**不**停止管道、**不**调用 `FailTask`，且仍调用 `OnPacketWritten` 以保证任务完成。这是 memory 中记录的已修复 bug "buffer-overflow-stall(CRITICAL)" 的修复后行为（注释见 `worker.go:661-667`）。因此溢出相关测试点 (OW23-OW28, RB6/RB7) 断言 best-effort 行为，而非 fatal error。`SetFatalError`/`GetFatalError` (E135-E138) 是独立的外部 API，引擎内部从不自动调用。
>
> **类型分类原则**：
> - REAL：纯逻辑/内存/数据结构/状态机/校验/解析（builder, validate, convert, tuple, RingBuffer/PacketBuffer/TokenBucket 数学, NewEngine, 状态机方法）。可用 `go test -race`+`go vet` 全自动断言真实行为。
> - SIMULATED：需注入 mock planner / fake writer / fake pacer 的集成路径（worker.processTask, SubmitTask 端到端, OutputWorker.writePacket 路由）。仍在进程内用 -race/vet 自动跑。
> - MANUAL：真实发包到物理 NIC / 真实线缆 PPS-BPS 精度 / 真实多进程调度时序 / 真实双端口网卡。

## 组件: Engine (engine.go) — NewEngine / RegisterPlanner

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| E1-POS | E1 | TestNewEngine_ZeroConfig | EngineConfig 全零 | planners/rateLimiters/taskStore/outputWriters/dualWriters 均 non-nil 空 map；running=false；taskChan/configChan/packetChan=nil；replayPlanner=nil；buildFunc=nil | REAL | 直接断言字段非 nil 且为空 |
| E2-NEG | E2 | TestNewEngine_NegativeConfig | EngineConfig{ConfigWorkers:-1,PacketWorkers:-1,...} | 不 panic；map 仍正常初始化 | REAL | 负值被接受（Start 时才决定 worker 数） |
| E3-POS | E3 | TestNewEngine_NoReplayPlanner | 默认 config | replayPlanner==nil | REAL | |
| E4-POS | E4 | TestNewEngine_NoBuildFunc | 默认 config | buildFunc==nil（Start 时填默认） | REAL | |
| E8-POS | E8 | TestRegisterPlanner_FirstRegistration | 注册 mockPlanner{name:"tcp"} | ListProtocols() 含 "tcp"；再次 Name() 返回 "tcp" | REAL | |
| E9-BR1 | E9 | TestRegisterPlanner_DuplicateOverwrites | 先注册 tcp planner A，再注册 tcp planner B | ListProtocols 仅 1 个 "tcp"；Get 行为=B | REAL | 覆盖语义，旧值丢失 |
| E10-NEG | E10 | TestRegisterPlanner_NilPanics | RegisterPlanner(nil) | panic（nil 接口方法调用 .Name()） | REAL | 用 defer/recover 断言 panic 发生 |

## 组件: Engine (engine.go) — RegisterDualWriter / Unregister / GetDualWriter

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| E13-POS | E13 | TestRegisterDualWriter_Valid | taskID="t1", c2s=fakeW{}, s2c=fakeW{} | GetDualWriter("t1") 返回非 nil；.C2S/.S2C 指向传入实例 | REAL | |
| E14-NEG | E14 | TestRegisterDualWriter_NilFields | c2s=nil, s2c=nil | 存入 map；GetDualWriter 返回非 nil 但 C2S/S2C 均 nil | REAL | |
| E15-NEG | E15 | TestRegisterDualWriter_OverwriteLeaksOld | 先注册 (c2s=W1), 再注册 (c2s=W2) 同 taskID | GetDualWriter.C2S==W2；W1.Close 从未被调用（leak）；用 W1 记录 Close 调用次数断言 ==0 | SIMULATED | 失败测试先行：复现 bug（旧 writer 未 Close），再断言当前行为/或证明 leak 待修 |
| E16-BR1 | E16 | TestRegisterDualWriter_EmptyTaskID | taskID="" | GetDualWriter("") 返回非 nil | REAL | |
| E17-POS | E17 | TestUnregisterDualWriter_Existing | 注册后 Unregister("t1") | dualWriters 中删除；C2S.Close 与 S2C.Close 各被调用 1 次 | SIMULATED | fake writer 计数 Close |
| E18-NEG | E18 | TestUnregisterDualWriter_NonExistent | Unregister("nope") | ok=false 路径；无 Close 调用；无 panic | SIMULATED | |
| E19-BR1 | E19 | TestUnregisterDualWriter_NilDWInMap | 手动塞 dualWriters["t"]=nil 后 Unregister | 不 panic（dw!=nil 检查） | REAL | 同包测试直接操作 map |
| E20-BR2 | E20 | TestUnregisterDualWriter_NilC2S | C2S=nil, S2C=W | Unregister 后 S2C.Close 调用 1 次，C2S 无 Close 调用（nil 检查） | SIMULATED | |
| E21-BR3 | E21 | TestUnregisterDualWriter_NilS2C | C2S=W, S2C=nil | C2S.Close 调用 1 次，S2C 无 Close | SIMULATED | |
| E22-NEG | E22 | TestUnregisterDualWriter_C2SClosePanics_StopsS2C | C2S=panicW, S2C=trackW | C2S.Close panic；recover 后断言 S2C.Close 调用次数==0（未关闭） | SIMULATED | 失败测试先行：证明 panic 中断后续 Close（待修或确认为已知行为） |
| E23-POS | E23 | TestGetDualWriter_Existing | 注册后 Get | 返回指针相同 | REAL | |
| E24-NEG | E24 | TestGetDualWriter_NonExistent | GetDualWriter("nope") | 返回 nil | REAL | |

## 组件: Engine (engine.go) — Start

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| E25-POS | E25 | TestStart_ValidConfig | ConfigWorkers=2,PW=2,OW=2,BufferSize=16,QueueSize=8 | running=true；len(configWorkers/packetWorkers/outputWorkers)==2；taskChan/configChan/packetChan 非 nil 且 cap==8/16/16；buffer 非 nil；startWallClock 非零 | REAL | Start 后立即 Stop 清理 |
| E26-NEG | E26 | TestStart_DoubleStart | Start 两次 | 第二次返回 "engine already running" | REAL | |
| E27-BR1 | E27 | TestStart_ZeroConfigWorkers | ConfigWorkers=0 | len(configWorkers)==0；其它 worker 正常；running=true | REAL | |
| E28-BR2 | E28 | TestStart_ZeroPacketWorkers | PacketWorkers=0 | len(packetWorkers)==0 | REAL | |
| E29-BR3 | E29 | TestStart_ZeroOutputWorkers | OutputWorkers=0 | len(outputWorkers)==0 | REAL | |
| E30-BR1 | E30 | TestStart_ReplayOrderPreserve_ClampsPW4to1 | ReplayOrderPreserve=true, PacketWorkers=4 | len(packetWorkers)==1（钳制） | REAL | 断言实际启动 worker 数，非配置值 |
| E31-BR2 | E31 | TestStart_ReplayOrderPreserve_PW0Stays0 | ReplayOrderPreserve=true, PacketWorkers=0 | len(packetWorkers)==0（pw>1 为 false，不钳制） | REAL | |
| E32-BR3 | E32 | TestStart_ReplayOrderPreserve_PW1Stays1 | ReplayOrderPreserve=true, PacketWorkers=1 | len(packetWorkers)==1 | REAL | |
| E33-BR1 | E33 | TestStart_NilBuildFunc_Default64Bytes | buildFunc=nil，提交 1 个 config（mockPlanner Count=1） | 输出 packet 长度==64 且全零 | SIMULATED | 需 mockPlanner 驱动一包观察默认 buildFunc |
| E34-POS | E34 | TestStart_RegisteredBuildFuncUsed | SetBuildFunc 返回 []byte{0xAB} | 输出 packet==[]byte{0xAB} | SIMULATED | |
| E35-NEG | E35 | TestStart_GetProcessCPUTimeFailure | 正常 Start（无法强制 Getrusage 失败） | engine 仍 running=true；startCPUTime 可能 0 但不 abort | SIMULATED | 备注：Getrusage 失败不可注入；仅能断言"成功时 startCPUTime 非 0、失败时不 abort"——后者不可直接触发，标注为已知限制 |
| E36-BR1 | E36 | TestStart_BufferSizeZero | BufferSize=0 | buffer 非 nil；combinedBuffer.size==0；Put 必返回 false | REAL | |
| E37-BR2 | E37 | TestStart_MaxBufferBytesZero | MaxBufferBytes=0 | combinedBuffer.maxBytes==0（无字节上限） | REAL | |
| E38-BR3 | E38 | TestStart_QueueSizeZero | QueueSize=0 | cap(taskChan)==0, cap(configChan)==0, cap(packetChan)==0（无缓冲） | REAL | |
| E39-BR1 | E39 | TestStart_OnTaskDoneErr_FailsTask | mockPlanner.Plan 返回 err | onTaskDone(taskID, err, 0) 触发；FailTask 被调用；status=="failed"；OnTaskFailed 触发 | SIMULATED | |
| E40-BR2 | E40 | TestStart_OnTaskDoneNil_SetsTotalConfigs | mockPlanner 正常 Plan N 包 | onTaskDone(taskID, nil, N) 触发；SetTaskTotalConfigs 设 totalConfigs=N | SIMULATED | |

## 组件: Engine (engine.go) — Stop

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| E41-POS | E41 | TestStop_Normal | Start(PW=2,CW=2,OW=2) 后 Stop | running=false；wg.Wait 返回（不阻塞）；configChan/packetChan 已 close；buffer.Close 后 Put 返回 false | REAL | |
| E42-BR1 | E42 | TestStop_AlreadyStopped | Stop 两次 | 第二次立即返回（running 已 false） | REAL | |
| E43-BR2 | E43 | TestStop_NeverStarted | 未 Start 直接 Stop | 立即返回，无 panic | REAL | |
| E44-BR3 | E44 | TestStop_NilBuffer | 手动 e.buffer=nil 后 Stop | 不 panic（nil 检查） | REAL | 同包测试 |
| E45-BR1 | E45 | TestStop_NoOutputWriters | outputWriters 空 | 空循环无 Close；不 panic | SIMULATED | |
| E46-BR2 | E46 | TestStop_NilWriterInMap | outputWriters["t"]=nil | nil 检查跳过；不 panic | SIMULATED | |
| E47-BR3 | E47 | TestStop_NoDualWriters | dualWriters 空 | 空循环；不 panic | SIMULATED | |
| E48-NEG | E48 | TestStop_WriterClosePanics_StopsRest | writers=[panicW, trackW] | panicW.Close panic；recover 后 trackW.Close 调用次数==0 | SIMULATED | 失败测试先行：证明后续 writer 未关闭 |
| E49-BR1 | E49 | TestStop_DuplicateWritersSameTask | outputWriters["t"]=W1, outputWriters["t2"]=W2（同 task 两 ID） | map 遍历两者均 Close（各 1 次） | SIMULATED | |

## 组件: Engine (engine.go) — SubmitTask

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| E50-POS | E50 | TestSubmitTask_Normal | running 引擎 + 合法 TCP task（mockPlanner 已注册） | 返回 nil；taskStore 中 status=="running"；StartedAt 非零；taskChan 收到 task | SIMULATED | |
| E51-NEG | E51 | TestSubmitTask_NotRunning | 未 Start | 返回 "engine not running" | REAL | |
| E52-NEG | E52 | TestSubmitTask_InvalidName | task.Name="" | 返回 "task validation failed: task name is required" | REAL | |
| E53-POS | E53 | TestSubmitTask_MaxTasksZeroUnlimited | SetMaxTasks(0)；用阻塞 mockPlanner 提交 50 个 | 全部返回 nil；ActiveTaskCount()==50 | SIMULATED | 需阻塞 planner 防止任务完成 |
| E54-NEG | E54 | TestSubmitTask_MaxTasksReached | SetMaxTasks(5)；阻塞 planner 占 5 槽；第 6 个 | 第 6 个返回 "max_tasks limit reached (5 active)" | SIMULATED | |
| E55-POS | E55 | TestSubmitTask_BatchPerClassBPS | batch 2 class，BPS="1M"/"500k" | GetRateLimiter("taskID:c1") 与 ("taskID:c2") 均 non-nil；rateBytesPerSec 分别 125000/62500 | SIMULATED | |
| E56-BR1 | E56 | TestSubmitTask_BatchClassBPSEmpty | class BPS="" | 该 class 无 rate limiter（GetRateLimiter 返回 nil） | SIMULATED | |
| E57-NEG | E57 | TestSubmitTask_BatchClassBPSInvalid | class BPS="abc" | 返回 "class X invalid bps ...: ..."；任务未入队 | REAL | ParseBPS 在入队前调用 |
| E58-BR1 | E58 | TestSubmitTask_SingleBPSEmpty | task.Spec.BPS="" | 无 rate limiter 创建 | SIMULATED | |
| E59-NEG | E59 | TestSubmitTask_SingleBPSParseError | BPS="xyz" | 返回 "invalid bps ..." | REAL | |
| E60-BR2 | E60 | TestSubmitTask_SingleBPSZero | BPS="0" | bps==0，不创建 limiter（bps>0 检查） | SIMULATED | |
| E61-BR3 | E61 | TestSubmitTask_SingleClassIDEmpty | ClassID="" | limiter 键==task.ID | SIMULATED | |
| E62-POS | E62 | TestSubmitTask_SingleClassIDSet | ClassID="cX" | limiter 键=="cX" | SIMULATED | |
| E63-BR1 | E63 | TestSubmitTask_BatchDurationZero | Batch.Global.DurationSeconds=0 | taskCtx 为 WithCancel（无 deadline）；taskCtx.Deadline()==false | SIMULATED | |
| E64-POS | E64 | TestSubmitTask_BatchDurationDeadline | DurationSeconds=1 | taskCtx 有 deadline；~1s 后 taskCtx.Err()==DeadlineExceeded | SIMULATED | 用短 deadline 加速 |
| E65-NEG | E65 | TestSubmitTask_QueueFull | QueueSize=1；填满 taskChan（阻塞 planner）后第 2 个 | 5s 超时返回 "task queue full"；status=="failed" | SIMULATED | 用阻塞 planner 占满队列；可缩短超时加速 |
| E66-BR1 | E66 | TestSubmitTask_LogsSubmitted | 合法 task | zap test observer 捕获 "task submitted" 日志含 task_id+protocol | SIMULATED | 用 zaptest/observer |

## 组件: Engine (engine.go) — StopTask

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| E67-POS | E67 | TestStopTask_ExistingRunning | 阻塞 planner 占住的任务 | cancel() 调用；status=="stopped"；CompletedAt 非零 | SIMULATED | |
| E68-NEG | E68 | TestStopTask_NotFound | StopTask("nope") | 返回 "task not found: nope" | REAL | |
| E69-BR1 | E69 | TestStopTask_AlreadyCompleted | 任务已完成后（已从 store 删除）StopTask | 返回 "task not found" | SIMULATED | |
| E70-BR2 | E70 | TestStopTask_AlreadyStopped | 已 StopTask 的任务再 StopTask | cancel() 幂等；status 仍=="stopped"（覆写同值）；无 panic | SIMULATED | |
| E71-NEG | E71 | TestStopTask_NilCancelCrash | 同包构造 taskEntry{cancel:nil} 后 StopTask | panic（nil CancelFunc 调用） | REAL | 失败测试先行；备注：公开 API 路径 cancel 恒非 nil，仅同包可构造此状态 |

## 组件: Engine (engine.go) — SetTaskTotalConfigs (状态机)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| E72-POS | E72 | TestSetTaskTotalConfigs_Normal | entry.writtenPackets=0; Set(100) | totalConfigs=100；status 仍 "running"；不触发 OnTaskComplete | REAL | 同包直接构造 entry |
| E73-NEG | E73 | TestSetTaskTotalConfigs_NotInStore | Set("nope", 100) | 立即返回；无副作用 | REAL | |
| E74-BR1 | E74 | TestSetTaskTotalConfigs_CountZeroCompletes | count=0 | status=="completed"；Progress==100；store 删除；OnTaskComplete 触发；cleanupTaskRateLimiters 调用 | REAL | |
| E75-BR2 | E75 | TestSetTaskTotalConfigs_AlreadyComplete | count=50, writtenPackets=50 | 立即 completed；OnTaskComplete 触发 | REAL | |
| E76-BR3 | E76 | TestSetTaskTotalConfigs_WrittenExceeds | count=50, writtenPackets=60 | written>=count → completed | REAL | |
| E77-POS | E77 | TestSetTaskTotalConfigs_NoCompletion | count=100, written=30 | status 仍 "running"；totalConfigs=100；不触发 OnTaskComplete | REAL | |
| E78-BR1 | E78 | TestSetTaskTotalConfigs_OnTaskCompleteNil | OnTaskComplete=nil | 跳过回调；status 仍正确变更 | REAL | |
| E79-BR2 | E79 | TestSetTaskTotalConfigs_CleansRateLimiters | 注册 rateLimiters["t"] 与 ["t:c1"] 后 count=0 完成 | 两者均从 rateLimiters 删除 | REAL | |
| E80-POS | E80 | TestCleanupTaskRateLimiters_ExactKey | rateLimiters["t"]=tb | cleanup 后 rateLimiters 无 "t" | REAL | |
| E81-BR1 | E81 | TestCleanupTaskRateLimiters_PrefixKeys | rateLimiters["t:c1"],["t:c2"],["other:c1"] | 删除 "t:c1","t:c2"；保留 "other:c1" | REAL | 前缀扫描 |
| E82-BR2 | E82 | TestCleanupTaskRateLimiters_None | 无相关键 | no-op；不 panic | REAL | |

## 组件: Engine (engine.go) — OnPacketWritten (状态机)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| E83-POS | E83 | TestOnPacketWritten_Normal | totalConfigs=100, written=0→1 | writtenPackets=1；status "running"；不触发 OnTaskComplete | REAL | |
| E84-NEG | E84 | TestOnPacketWritten_NotInStore | OnPacketWritten("nope") | 立即返回；无 panic | REAL | |
| E85-BR1 | E85 | TestOnPacketWritten_StatusStopped | entry.status="stopped" | 提前返回；writtenPackets 不增（在检查后）；不触发完成 | REAL | |
| E86-BR2 | E86 | TestOnPacketWritten_ReachesTotal | totalConfigs=10, written=9→10 | status=="completed"；store 删除；OnTaskComplete 触发；cleanup 调用 | REAL | |
| E87-BR3 | E87 | TestOnPacketWritten_TotalConfigsZero | totalConfigs=0 | 不做完成检查；writtenPackets++；不触发 OnProgress | REAL | |
| E88-POS | E88 | TestOnPacketWritten_ProgressOnePercent | totalConfigs=100, written 0→1 | OnProgress 触发，progress==1.0 | REAL | |
| E89-BR1 | E89 | TestOnPacketWritten_ProgressUnderOnePercent | totalConfigs=1000, written 0→1 (0.1%) | OnProgress 不触发 | REAL | |
| E90-BR2 | E90 | TestOnPacketWritten_ProgressExactly100 | totalConfigs=10, written 9→10 | OnProgress 触发（newProgress==100 特例）+ OnTaskComplete | REAL | |
| E91-BR3 | E91 | TestOnPacketWritten_OnProgressNil | OnProgress=nil | 跳过回调；status.Progress 仍更新 | REAL | |
| E92-BR1 | E92 | TestOnPacketWritten_OnTaskCompleteNil | OnTaskComplete=nil；触达 total | 跳过回调；status 仍 completed | REAL | |

## 组件: Engine (engine.go) — FailTask (状态机)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| E93-POS | E93 | TestFailTask_Normal | running 任务 | status=="failed"；Error==errMsg；CompletedAt 非零；store 删除；cleanup 调用 | REAL | |
| E94-NEG | E94 | TestFailTask_NotInStore | FailTask("nope", ...) | 立即返回 | REAL | |
| E95-BR1 | E95 | TestFailTask_AlreadyStopped | status="stopped" 的任务 | 提前返回；status 仍 "stopped"（不被覆写为 failed） | REAL | 已修复 bug（见 memory） |
| E96-BR2 | E96 | TestFailTask_AlreadyCompleted | 已完成（store 已删除） | 返回（not found 路径） | REAL | |
| E97-POS | E97 | TestFailTask_OnTaskFailedFires | OnTaskFailed 设 | OnTaskFailed(taskID, errMsg) 触发，errMsg 透传 | REAL | |
| E98-BR1 | E98 | TestFailTask_OnTaskCompleteAfterFailed | OnTaskComplete 设 | OnTaskFailed 先触发，随后 OnTaskComplete 触发（均 1 次） | REAL | |
| E99-BR2 | E99 | TestFailTask_OnTaskFailedNil | OnTaskFailed=nil | 跳过；OnTaskComplete 仍触发（若设） | REAL | |
| E100-BR3 | E100 | TestFailTask_OnTaskCompleteNil | OnTaskComplete=nil | 跳过；OnTaskFailed 仍触发（若设） | REAL | |

## 组件: Engine (engine.go) — GetTaskStatus / ActiveTaskCount / RangeTaskStore

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| E101-POS | E101 | TestGetTaskStatus_Existing | store 中有任务 | 返回 status 指针；TaskID 匹配 | REAL | |
| E102-NEG | E102 | TestGetTaskStatus_NonExistent | GetTaskStatus("nope") | 返回 nil, error "task not found" | REAL | |
| E103-POS | E103 | TestActiveTaskCount_Zero | 空 store | 返回 0 | REAL | |
| E104-BR1 | E104 | TestActiveTaskCount_500 | 塞 500 entry | 返回 500 | REAL | |
| E105-POS | E105 | TestRangeTaskStore_AllTrue | fn 恒 true | 遍历全部；调用次数==len(store) | REAL | |
| E106-BR1 | E106 | TestRangeTaskStore_FalseEarly | fn 第 2 个返回 false | 仅调用 2 次 | REAL | |
| E107-NEG | E107 | TestRangeTaskStore_FnPanic_ReleasesLock | fn panic | panic 传播（recover 捕获）；之后 GetTaskStatus 不死锁（defer RUnlock 已释放锁） | REAL | 校正枚举：defer 确保锁释放，非"RLock 永不释放" |

## 组件: Engine (engine.go) — GetPackets / GetBufferStatus

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| E108-NEG | E108 | TestGetPackets_NilBuffer | e.buffer=nil | 返回 nil | REAL | |
| E109-POS | E109 | TestGetPackets_Delegates | buffer 有包；Get(10,"up") | 返回 buffer.Get 的结果 | REAL | |
| E110-NEG | E110 | TestGetBufferStatus_NilBuffer | e.buffer=nil | 返回 nil | REAL | |
| E111-POS | E111 | TestGetBufferStatus_Delegates | buffer set | 返回 buffer.Status() map | REAL | |

## 组件: Engine (engine.go) — SetClassRateLimit / GetRateLimiter

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| E112-POS | E112 | TestSetClassRateLimit_1Mbps | bps=1000000 | GetRateLimiter 非 nil；rate==125000（bps/8）；burst==65536 | REAL | 断言真实 rate 值非零 |
| E113-BR1 | E113 | TestSetClassRateLimit_BpsZero | bps=0 | rateBytesPerSec 守卫为 1（<1 时设 1）；limiter.rate==1（非 0 即非 unlimited） | REAL | 守卫防 truncation→0→unlimited |
| E114-BR2 | E114 | TestSetClassRateLimit_BpsOneToSeven | bps=4 | rateBytesPerSec=4/8=0→守卫为 1；limiter.rate==1 | REAL | |
| E115-BR3 | E115 | TestSetClassRateLimit_BpsEight | bps=8 | rateBytesPerSec=1；limiter.rate==1 | REAL | |
| E116-BR1 | E116 | TestSetClassRateLimit_EmptyClassID | classID="" | 存入 map[""]；GetRateLimiter("") 非 nil | REAL | |
| E117-NEG | E117 | TestSetClassRateLimit_OverwriteLeaks | 同 classID 设两次 | 新 bucket 替换旧；旧 bucket 无清理（GC 回收）；GetRateLimiter 返回新实例 | REAL | 失败测试先行：minor leak（无 Close 概念，仅内存） |
| E118-POS | E118 | TestGetRateLimiter_Existing | 已 Set | 返回同一 bucket 指针 | REAL | |
| E119-NEG | E119 | TestGetRateLimiter_NonExistent | GetRateLimiter("nope") | 返回 nil | REAL | |

## 组件: Engine (engine.go) — GetCPUUsage / SetMaxTasks

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| E120-POS | E120 | TestGetCPUUsage_OneCoreBusy | Start 后跑 CPU 密集循环 | 返回 >0（约 100，容差大） | REAL | Getrusage 进程内可测 |
| E121-BR1 | E121 | TestGetCPUUsage_StartWallClockZero | 未 Start | 返回 0 | REAL | |
| E122-BR2 | E122 | TestGetCPUUsage_GetrusageFails | 无法强制失败 | 不可直接触发；标注已知限制（getProcessCPUTime 不可注入） | SIMULATED | 备注：仅能间接断言"成功路径返回非零" |
| E123-BR3 | E123 | TestGetCPUUsage_ElapsedZero | elapsed<=0 | 返回 0（理论上难触发，因 time.Since>0） | REAL | 备注：边界，难稳定触发 |
| E124-POS | E124 | TestGetCPUUsage_TwoCoresBusy | 起 2 goroutine 跑 CPU 循环 | 返回 ~200（>150） | REAL | 多核负载 |
| E125-BR1 | E125 | TestGetCPUUsage_Idle | Start 后 sleep | 返回接近 0（<10） | REAL | |
| E126-POS | E126 | TestSetMaxTasks_Ten | SetMaxTasks(10) | maxTasks.Load()==10；提交第 11 个被拒 | REAL | |
| E127-BR1 | E127 | TestSetMaxTasks_Zero | SetMaxTasks(0) | maxTasks==0（unlimited） | REAL | |
| E128-BR2 | E128 | TestSetMaxTasks_Negative | SetMaxTasks(-1) | 钳为 0；maxTasks==0 | REAL | |

## 组件: Engine (engine.go) — writePacketsTo / GetStats / SetFatalError

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| E129-POS | E129 | TestWritePacketsTo_TimedWriter | w 实现 TimedWriter | 调用 WriteTimedPackets([]PacketOutput{out})；返回其 error | SIMULATED | fake writer 记录调用 |
| E130-BR1 | E130 | TestWritePacketsTo_PlainWriter | w 仅实现 WritePackets | 调用 WritePackets([][]byte{out.Data})；Timestamp 被剥离 | SIMULATED | |
| E131-NEG | E131 | TestWritePacketsTo_NilWriterPanics | w=nil | panic（nil 接口方法 WritePackets） | REAL | 失败测试先行；备注：调用方恒先 nil 检查，此为防御性 |
| E132-POS | E132 | TestGetStats_NoWorkers | 全零 worker | config_workers/packet_workers/output_workers 各字段==0；buffer 子 map | REAL | |
| E133-BR1 | E133 | TestGetStats_WorkersRunning | Start 后驱动若干包 | 聚合 packets/errors 跨 worker 求和正确 | SIMULATED | |
| E134-BR2 | E134 | TestGetStats_NilBuffer | e.buffer=nil | stats["buffer"]==nil | REAL | |
| E135-BR1 | E135 | TestSetFatalError_Nil | SetFatalError(nil) | GetFatalError()==nil | REAL | |
| E136-POS | E136 | TestSetFatalError_NonNil | SetFatalError(errX) | GetFatalError()==errX | REAL | |
| E137-NEG | E137 | TestGetFatalError_None | 未 Set | 返回 nil | REAL | |
| E138-POS | E138 | TestGetFatalError_Stored | Set 后 Get | 返回存储的 error | REAL | |

## 组件: ConfigWorker (worker.go) — run()

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| CW1-POS | CW1 | TestConfigWorkerRun_ReceivesTask | taskChan 发 1 task | 信号量获取；spawn goroutine；processTask 被调用（mock 记录） | SIMULATED | |
| CW2-BR1 | CW2 | TestConfigWorkerRun_CtxCancelled | cancel worker ctx | run() 退出；wg.Done 调用 | SIMULATED | 确认 worker 主循环响应 ctx.Done |
| CW3-BR2 | CW3 | TestConfigWorkerRun_TaskChanClosed | close(taskChan) | run() 退出（!ok 分支） | SIMULATED | |
| CW4-BR3 | CW4 | TestConfigWorkerRun_SemaphoreFull | sem 容量 4，发 5 task | 第 5 个阻塞直到前 4 个之一释放槽；最终全处理 | SIMULATED | |
| CW5-NEG | CW5 | TestConfigWorkerRun_GoroutinePanic | processTask panic | defer 释放 sem+wg.Done 仍执行（recover 内）；wg.Wait 不阻塞 | SIMULATED | 失败测试先行：验证 panic 不泄漏 sem/wg |

## 组件: ConfigWorker (worker.go) — processTask (单协议)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| CW6-POS | CW6 | TestProcessTask_BatchDispatches | task.Batch!=nil | 调用 processBatchTask（mock 记录） | SIMULATED | |
| CW7-POS | CW7 | TestProcessTask_NormalSingleProtocol | tcp task + mockPlanner Count=5 | onTaskDone(nil, 5)；configChan 收到 5 个 config；每个 config.ClassID==task.ClassID；Metadata["task_id"]==task.ID | SIMULATED | |
| CW8-NEG | CW8 | TestProcessTask_UnknownProtocol | protocol="xyz" | Errors++；onTaskDone(err "unknown protocol: xyz", 0) | SIMULATED | |
| CW9-NEG | CW9 | TestProcessTask_ValidationFails | mockPlanner.Validate 返回 err | Errors++；onTaskDone("validation failed: ...", 0) | SIMULATED | |
| CW10-NEG | CW10 | TestProcessTask_PlanningFails | mockPlanner.Plan 返回 err | Errors++；onTaskDone("planning failed: ...", 0) | SIMULATED | |
| CW11-BR1 | CW11 | TestProcessTask_NilTaskCtxFallsBack | task.Ctx=nil | 使用 worker ctx；Plan 收到非 nil ctx | SIMULATED | |
| CW12-BR2 | CW12 | TestProcessTask_TaskCtxUsed | task.Ctx=set | Plan 收到 task.Ctx（可标记） | SIMULATED | |
| CW13-BR3 | CW13 | TestProcessTask_VLANPropagatedFromSpec | task.Spec.VLAN set, config.L2.VLAN=nil | 转发的 config.L2.VLAN==task.Spec.VLAN | SIMULATED | 已修复 bug（见 memory ARP/VLAN） |
| CW14-BR1 | CW14 | TestProcessTask_VLANNotOverwritten | config.L2.VLAN 已 set, spec.VLAN 也 set | config.L2.VLAN 保持原值（不被覆写） | SIMULATED | |
| CW15-BR2 | CW15 | TestProcessTask_MetadataNilInitialized | config.Metadata=nil | 转发前 Metadata 被初始化为 map 并含 task_id+interface | SIMULATED | |
| CW16-BR3 | CW16 | TestProcessTask_MetadataNotReinitialized | config.Metadata 已 set | 不被重新初始化（仅追加键） | SIMULATED | |
| CW17-POS | CW17 | TestProcessTask_CtxCancelledMidForwarding_Drains | mockPlanner 产生 10 config 忽略 ctx；收 1 个后 cancel taskCtx | 剩余 config 被排空（planner goroutine 不阻塞/不泄漏）；onTaskDone("task cancelled", 1) | SIMULATED | 失败测试先行：验证 drain 防泄漏；对应"规划器不响应 ctx"的兜底 |
| CW18-POS | CW18 | TestProcessTask_NormalCompletion | mockPlanner Count=3 | onTaskDone(nil, 3)；TasksProcessed++；PacketsGenerated+=3 | SIMULATED | |
| CW19-BR1 | CW19 | TestProcessTask_ZeroConfigs | mockPlanner Count=0 | onTaskDone(nil, 0) | SIMULATED | |
| CW20-BR2 | CW20 | TestProcessTask_OnTaskDoneNil | onTaskDone=nil | 跳过所有回调；无 panic | SIMULATED | |
| CW21-NEG | CW21 | TestProcessTask_PlannerBlocksStalls | mockPlanner.Plan 阻塞（不 close chan） | configChan <- 永久阻塞；pipeline stall（用超时断言无 onTaskDone） | SIMULATED | 已知限制：规划器阻塞无法被引擎打破 |

## 组件: ConfigWorker (worker.go) — processBatchTask

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| CW22-POS | CW22 | TestProcessBatchTask_AllClassesSucceed | 2 synth class, FlowCount=2 each | configChan 收到 4 config；每个 ClassID=="taskID:classID"；onTaskDone(nil, 4) | SIMULATED | |
| CW23-BR1 | CW23 | TestProcessBatchTask_NilTaskCtxFallsBack | task.Ctx=nil | 用 worker ctx | SIMULATED | |
| CW24-BR2 | CW24 | TestProcessBatchTask_ZeroClasses | Batch.Classes=[] | classWg.Wait 立即返回；onTaskDone(nil, 0) | SIMULATED | |
| CW25-NEG | CW25 | TestProcessBatchTask_ReplayNoPlanner | replay class, replayPlanner=nil | 跳过；flowFailures+=1 | SIMULATED | |
| CW26-POS | CW26 | TestProcessBatchTask_ReplayPlannerSet | replay class + fake replayPlanner | 调用 PlanReplay；config 标 ClassID=taskID:classID | SIMULATED | |
| CW27-NEG | CW27 | TestProcessBatchTask_ReplayPlanFails | PlanReplay 返回 err | 跳过；flowFailures+=1 | SIMULATED | |
| CW28-BR1 | CW28 | TestProcessBatchTask_ReplayForwardingCancelled | cancel taskCtx 中途 | 排空 configChan；返回（无 onTaskDone 二次错误） | SIMULATED | |
| CW29-NEG | CW29 | TestProcessBatchTask_UnknownProtocolClass | class.Type="xyz" | 跳过；flowFailures+=class.FlowCount | SIMULATED | |
| CW30-BR3 | CW30 | TestProcessBatchTask_BPSEmptyNotPropagated | class.BPS="" | spec.BPS 不变（保持 mapToFlowSpec 结果） | SIMULATED | |
| CW31-BR1 | CW31 | TestProcessBatchTask_BPSPropagated | class.BPS="1M" | spec.BPS=="1M" | SIMULATED | |
| CW32-NEG | CW32 | TestProcessBatchTask_FlowValidationFails | 1 flow Validate 失败 | 该 flow 跳过；flowFailures+=1；其它 flow 继续 | SIMULATED | |
| CW33-NEG | CW33 | TestProcessBatchTask_FlowPlanningFails | 1 flow Plan 失败 | 该 flow 跳过；flowFailures+=1 | SIMULATED | |
| CW34-BR2 | CW34 | TestProcessBatchTask_FlowForwardingCancelled | cancel taskCtx 中途 | 排空该 flow configChan；返回 | SIMULATED | |
| CW35-NEG | CW35 | TestProcessBatchTask_AllFlowsFailed | 全 flow 失败 | onTaskDone("all N flows failed", count) | SIMULATED | |
| CW36-BR1 | CW36 | TestProcessBatchTask_SomeFlowsFailed | 部分 fail 部分 ok | onTaskDone(nil, count)（非全失败） | SIMULATED | |
| CW37-BR2 | CW37 | TestProcessBatchTask_DurationDeadlineExceeded | taskCtx.DeadlineExceeded | onTaskDone(nil, count)（正常完成语义） | SIMULATED | |
| CW38-BR3 | CW38 | TestProcessBatchTask_ExplicitCancel | taskCtx.Canceled | onTaskDone("task cancelled", count) | SIMULATED | |
| CW39-POS | CW39 | TestProcessBatchTask_NormalCompletion | 全 ok，ctx 无 err | onTaskDone(nil, count) | SIMULATED | |
| CW40-NEG | CW40 | TestProcessBatchTask_TotalFlowsZero_AllFailGuardNotTriggered | totalFlows=0, flowFailures=0 | 不触发 all-failed guard；onTaskDone(nil, 0) | SIMULATED | 边界 |
| CW41-BR1 | CW41 | TestProcessBatchTask_TotalFlowsPositive_AllFail | totalFlows>0, flowFailures>=totalFlows | guard 触发；onTaskDone("all N flows failed", count) | SIMULATED | |
| CW42-BR2 | CW42 | TestProcessBatchTask_OnTaskDoneNil | onTaskDone=nil | 跳过 terminal-state 报告 | SIMULATED | |

## 组件: PacketWorker (worker.go) — run() / processConfig

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| PW1-POS | PW1 | TestPacketWorkerRun_ReceivesConfig | configChan 发 1 config | processConfig 调用；packetChan 收到包 | SIMULATED | |
| PW2-BR1 | PW2 | TestPacketWorkerRun_CtxCancelled | cancel worker ctx | run() 退出；wg.Done | SIMULATED | 确认主循环响应 ctx |
| PW3-BR2 | PW3 | TestPacketWorkerRun_ConfigChanClosed | close(configChan) | run() 退出（!ok） | SIMULATED | |
| PW4-POS | PW4 | TestProcessConfig_Normal | buildFunc 返回 100B | 限速后 packetChan 收到 100B 包；PacketsGenerated++ | SIMULATED | |
| PW5-NEG | PW5 | TestProcessConfig_NilBuildFunc | buildFunc=nil | 静默返回；packetChan 无包；无 error 计数 | SIMULATED | |
| PW6-NEG | PW6 | TestProcessConfig_BuildFails | buildFunc 返回 err | Errors++；packetChan 无包 | SIMULATED | |
| PW7-POS | PW7 | TestProcessConfig_PacerUsed | Metadata["_pacer"]=fakePacer{} | 调用 pacer.Wait；不查 TokenBucket；fakePacer 记录 Wait 调用 | SIMULATED | pacer 优先于 token bucket |
| PW8-NEG | PW8 | TestProcessConfig_PacerWaitErr | fakePacer.Wait 返回 err（ctx 取消） | 返回；packetChan 无包；不调用 limiter | SIMULATED | |
| PW9-BR1 | PW9 | TestProcessConfig_TokenBucketUsed | 无 pacer, engine!=nil, ClassID="c1" | 调用 GetRateLimiter("c1").Wait | SIMULATED | |
| PW10-BR2 | PW10 | TestProcessConfig_NoPacerEmptyClassID | 无 pacer, ClassID="" | 不限速；直接发送 | SIMULATED | |
| PW11-BR3 | PW11 | TestProcessConfig_NoPacerNilEngine | engine=nil | 不限速；直接发送 | SIMULATED | |
| PW12-BR1 | PW12 | TestProcessConfig_NoLimiterForClassID | ClassID="nope"（无 limiter） | 不限速；直接发送 | SIMULATED | |
| PW13-NEG | PW13 | TestProcessConfig_TokenBucketWaitErr | limiter.Wait 返回 ctx.Err() | 返回；packetChan 无包 | SIMULATED | |
| PW14-NEG | PW14 | TestProcessConfig_CtxCancelledWhileSending | 发 packetChan 前 cancel ctx | 返回；packetChan 无包 | SIMULATED | |
| PW15-POS | PW15 | TestProcessConfig_Sent IncrementsCounter | 正常发送 | PacketsGenerated++（断言值+1） | SIMULATED | |
| PW16-BR1 | PW16 | TestProcessConfig_PacketChanFull | packetChan 满 | 阻塞直到槽或 ctx 取消（用超时断言行为） | SIMULATED | |

## 组件: OutputWorker (worker.go) — run() / writePacket

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| OW1-POS | OW1 | TestOutputWorkerRun_ReceivesPacket | packetChan 发 1 包 | writePacket 调用；buffer 收到包 | SIMULATED | |
| OW2-BR1 | OW2 | TestOutputWorkerRun_CtxCancelled | cancel worker ctx | run() 退出；wg.Done | SIMULATED | 确认主循环响应 ctx |
| OW3-BR2 | OW3 | TestOutputWorkerRun_PacketChanClosed | close(packetChan) | run() 退出（!ok） | SIMULATED | |
| OW4-POS | OW4 | TestWritePacket_DualWriter_C2SDirection | Direction="up"；dualWriter 注册 | 写入 C2S writer；C2S 收到 1 包；S2C 收到 0 包；buffer 收到；OnPacketWritten 触发 | SIMULATED | |
| OW5-NEG | OW5 | TestWritePacket_EngineNil | engine=nil | 跳过 writer 路由；仍 buffer.Put；仍 OnPacketWritten 不触发（engine nil） | SIMULATED | |
| OW6-NEG | OW6 | TestWritePacket_MetadataNil | out.Metadata=nil | 跳过路由；仍 buffer.Put | SIMULATED | |
| OW7-NEG | OW7 | TestWritePacket_TaskIDMissing | Metadata 无 task_id | 跳过路由；仍 buffer.Put | SIMULATED | |
| OW8-BR1 | OW8 | TestWritePacket_DualWriter_UpDirection | Direction="up" | 用 C2S writer | SIMULATED | |
| OW9-BR1 | OW9 | TestWritePacket_DualWriter_DownDirection | Direction="down" | 用 S2C writer | SIMULATED | |
| OW10-BR2 | OW10 | TestWritePacket_DualWriter_EmptyDirection | Direction="" | 默认用 C2S | SIMULATED | |
| OW11-BR3 | OW11 | TestWritePacket_DualWriter_NilC2S | C2S=nil, Direction="up" | 跳过写（nil 检查）；仍 buffer+OnPacketWritten | SIMULATED | |
| OW12-BR3 | OW12 | TestWritePacket_DualWriter_NilS2C | S2C=nil, Direction="down" | 跳过写；仍 buffer+OnPacketWritten | SIMULATED | |
| OW13-NEG | OW13 | TestWritePacket_DualWriterWriteFails_NoCallback | dualWriter write 返回 err, OnOutputError=nil | FailTask 调用；UnregisterDualWriter 调用；Errors++ | SIMULATED | |
| OW14-BR1 | OW14 | TestWritePacket_DualWriterWriteFails_WithCallback | OnOutputError 设 | OnOutputError 触发；不调 FailTask | SIMULATED | |
| OW15-BR2 | OW15 | TestWritePacket_DualWriterWriteFails_NoCallback_FailsTask | OnOutputError=nil | FailTask+UnregisterDualWriter | SIMULATED | 与 OW13 同义，强调无回调路径 |
| OW16-POS | OW16 | TestWritePacket_SingleWriterFound | outputWriters[taskID]=fakeW | 写入 fakeW；fakeW 收到 1 包 | SIMULATED | |
| OW17-NEG | OW17 | TestWritePacket_SingleWriterNotFound | 无 dualWriter, 无 outputWriters[taskID] | 跳过写；仍 buffer+OnPacketWritten | SIMULATED | |
| OW18-NEG | OW18 | TestWritePacket_SingleWriterWriteFails_NoCallback | write err, OnOutputError=nil | FailTask+UnregisterOutputWriter；Errors++ | SIMULATED | |
| OW19-BR1 | OW19 | TestWritePacket_SingleWriterWriteFails_WithCallback | OnOutputError 设 | OnOutputError 触发；不 FailTask | SIMULATED | |
| OW20-BR2 | OW20 | TestWritePacket_SingleWriterWriteFails_NoCallback | OnOutputError=nil | FailTask+UnregisterOutputWriter | SIMULATED | |
| OW21-NEG | OW21 | TestWritePacket_NilBuffer | buffer=nil | 跳过 buffer 存储；不 panic；OnPacketWritten 仍触发（若 metadata 有 task_id） | SIMULATED | |
| OW22-POS | OW22 | TestWritePacket_BufferPutSucceeds | buffer 有空槽 | buffer.Put 返回 true；PacketsGenerated++ | SIMULATED | |
| OW23-NEG | OW23 | TestWritePacket_BufferOverflow_NoFatal | buffer 满（size=0 或填满） | buffer.Put 返回 false；Errors++；OnBufferOverflow 触发；**不**调 SetFatalError；**不**调 FailTask；**不**停管道；OnPacketWritten 仍触发 | SIMULATED | 校正任务描述：溢出是 best-effort，非 fatal |
| OW24-BR1 | OW24 | TestWritePacket_Overflow_OnBufferOverflowFires | OnBufferOverflow 设 | 回调触发，参数 taskID + dropped=1 | SIMULATED | |
| OW25-BR2 | OW25 | TestWritePacket_Overflow_NoCallback | OnBufferOverflow=nil | 跳过回调；不 panic | SIMULATED | |
| OW26-NEG | OW26 | TestWritePacket_EngineNil_SkipsOnPacketWritten | engine=nil, metadata nil | 不触发 OnPacketWritten | SIMULATED | |
| OW27-NEG | OW27 | TestWritePacket_MetadataNoTaskID_SkipsOnPacketWritten | metadata 无 task_id | 不触发 OnPacketWritten | SIMULATED | |
| OW28-BR1 | OW28 | TestWritePacket_OnPacketWrittenAlwaysFires_EvenOverflow | buffer 溢出 | OnPacketWritten 仍触发（保证任务完成计数不卡死） | SIMULATED | 已修复 bug（buffer-overflow-stall）：溢出不阻塞完成 |

## 组件: Builder (builder.go) — Build / l4Length

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| B1-POS | B1 | TestBuild_TCP_NoVLAN | L4.Protocol="tcp", 无 VLAN, payload=4B | len(packet)==14+20+20+4=58；etherType@12==0x0800；IP proto@9==6 | REAL | 断言真实长度与字段 |
| B2-POS | B2 | TestBuild_UDP_NoVLAN | L4="udp", payload=4B | len==14+20+8+4=46；proto@9==17 | REAL | |
| B3-BR1 | B3 | TestBuild_VLANPresent | L2.VLAN set | len==18+20+20+payload；TPID@12==0x8100 | REAL | |
| B4-BR2 | B4 | TestBuild_EtherTypeZero_DefaultIPv4 | EtherType=0 | effectiveEtherType==0x0800；l3Len==20 | REAL | |
| B5-BR3 | B5 | TestBuild_EtherTypeARP | EtherType=0x0806 | l3Len==0（无 IPv4 头）；packet 长度==14+l4Len+payload | REAL | |
| B6-BR1 | B6 | TestBuild_ARP_WithVLAN | EtherType=0x0806, VLAN set | len==18+l4Len+payload；l3Len==0 | REAL | |
| B7-BR2 | B7 | TestBuild_ICMP | L4.Protocol="icmp" | l4Len==0；payload 承载 ICMP 数据；len==14+20+0+len(payload) | REAL | |
| B8-BR3 | B8 | TestBuild_EmptyPayload | payload=nil | len==l2Len+l3Len+l4Len | REAL | |
| B9-NEG | B9 | TestBuild_EmptyConfig | 全零 PacketConfig | 不 panic；len==14+20+0=34（默认 protocol 空→l4Len 0） | REAL | |
| B10-BR1 | B10 | TestBuild_L3LenZero_NonIPv4 | EtherType=ARP | writeL3 跳过；无 IPv4 头写入 | REAL | |
| B11-BR2 | B11 | TestBuild_L4LenZero_ICMP | L4="icmp" | writeL4 跳过 | REAL | |
| B12-BR3 | B12 | TestBuild_ZeroLengthPacket | 全零 + 无 payload | make([]byte,34)；无 panic | REAL | |
| B13-BR1 | B13 | TestBuild_TCP_WithOptions | L4="tcp", TCPOptions=[MSS 4B] | l4Len==20+8=28（4B MSS+4B NOP 对齐）；dataOffset==(28)/4=7 | REAL | |
| B14-BR2 | B14 | TestBuild_UDP_Len8 | L4="udp" | l4Len==8 | REAL | |
| B15-POS | B15 | TestL4Length_TCP | L4="tcp", opts=[] | 返回 20+0=20 | REAL | |
| B16-POS | B16 | TestL4Length_UDP | L4="udp" | 返回 8 | REAL | |
| B17-POS | B17 | TestL4Length_ICMP | L4="icmp" | 返回 0 | REAL | |
| B18-BR1 | B18 | TestL4Length_Empty | L4.Protocol="" | 返回 0（default） | REAL | |

## 组件: Builder (builder.go) — writeL2

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| B19-NEG | B19 | TestWriteL2_DstMACEmpty | DstMAC="" | dst[0:6] 全零 | REAL | |
| B20-NEG | B20 | TestWriteL2_DstMACInvalid | DstMAC="zz:zz" | 警告；dst[0:6] 全零 | REAL | |
| B21-POS | B21 | TestWriteL2_DstMACValid | DstMAC="aa:bb:cc:dd:ee:ff" | dst[0:6]==aa:bb:cc:dd:ee:ff | REAL | |
| B22-NEG | B22 | TestWriteL2_SrcMACEmpty | SrcMAC="" | dst[6:12] 全零 | REAL | |
| B23-NEG | B23 | TestWriteL2_SrcMACInvalid | SrcMAC="bad" | 警告；src 全零 | REAL | |
| B24-POS | B24 | TestWriteL2_SrcMACValid | SrcMAC="11:22:33:44:55:66" | dst[6:12]==11:22:33:44:55:66 | REAL | |
| B25-BR1 | B25 | TestWriteL2_EtherTypeZero_DefaultIPv4 | EtherType=0 | dst[12:14]==0x0800 | REAL | |
| B26-BR2 | B26 | TestWriteL2_EtherTypeARP | EtherType=0x0806 | dst[12:14]==0x0806 | REAL | |
| B27-BR3 | B27 | TestWriteL2_VLANPresent | VLAN={ID:100,Priority:0} | dst[12:14]==0x8100；tag==100；etherType@16 | REAL | |
| B28-BR1 | B28 | TestWriteL2_VLANPriority7 | VLAN={Priority:7,ID:1} | tag bits 15-13==7（tag==(7<<13)|1） | REAL | |
| B29-BR2 | B29 | TestWriteL2_VLANID4095 | VLAN={ID:4095} | tag&0x0FFF==4095 | REAL | |
| B30-POS | B30 | TestWriteL2_NoVLAN | VLAN=nil | etherType@12；无 0x8100 | REAL | |

## 组件: Builder (builder.go) — writeL3 / L3Base

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| B31-POS | B31 | TestWriteL3_Normal | 正常 config | dst[0]==0x45；checksum@10 非 0；TTL@8==配置或 64 | REAL | |
| B32-BR1 | B32 | TestWriteL3_IPIDZero_FallsBackToSeq | IPID=0, L4.Seq=0x12345 | ipID@4==0x2345（Seq&0xFFFF） | REAL | |
| B33-BR2 | B33 | TestWriteL3_IPIDSet | IPID=0x1234 | ipID@4==0x1234 | REAL | |
| B34-BR3 | B34 | TestWriteL3_TTLZero_Default64 | TTL=0 | dst[8]==64 | REAL | |
| B35-BR1 | B35 | TestWriteL3_TTL255 | TTL=255 | dst[8]==255 | REAL | |
| B36-NEG | B36 | TestWriteL3_SrcIPEmpty | SrcIP="" | 伪头 src 全零；ip[12:16]==0 | REAL | |
| B37-NEG | B37 | TestWriteL3_SrcIPInvalid | SrcIP="bad" | 警告；ip[12:16]==0 | REAL | |
| B38-POS | B38 | TestWriteL3_SrcIPValid | SrcIP="192.168.1.1" | ip[12:16]==192,168,1,1 | REAL | |
| B39-BR2 | B39 | TestWriteL3_SrcIPIsIPv6 | SrcIP="::1" | To4()==nil；ip[12:16]==0（跳过） | REAL | |
| B40-NEG | B40 | TestWriteL3_DstIPEmpty | DstIP="" | ip[16:20]==0 | REAL | |
| B41-NEG | B41 | TestWriteL3_DstIPInvalid | DstIP="bad" | 警告；ip[16:20]==0 | REAL | |
| B42-POS | B42 | TestWriteL3_DstIPValid | DstIP="10.0.0.1" | ip[16:20]==10,0,0,1 | REAL | |
| B43-BR2 | B43 | TestWriteL3_DstIPIsIPv6 | DstIP="::1" | ip[16:20]==0 | REAL | |
| B44-BR3 | B44 | TestWriteL3_DSCPECN | DSCP=63, ECN=3 | dst[1]==(63<<2)|3==0xFF | REAL | |
| B45-BR1 | B45 | TestWriteL3_FlagsDF | Flags=0x2, FragOffset=0 | bytes[6:8]==(0x2<<13) | REAL | |
| B46-BR2 | B46 | TestWriteL3_ProtoTCP | Protocol=6 | dst[9]==6 | REAL | |
| B47-BR3 | B47 | TestWriteL3_ProtoUDP | Protocol=17 | dst[9]==17 | REAL | |
| B48-POS | B48 | TestL3Base_DefaultDF | Flags=0, FragOffset=0 | Flags==IPFlagDF(0x02) | REAL | |
| B49-BR1 | B49 | TestL3Base_ExplicitFlags | Flags=0x01 | Flags==0x01（不加默认 DF） | REAL | |
| B50-BR2 | B50 | TestL3Base_ExplicitFragOffset | Flags=0, FragOffset=0x100 | Flags==0（不加 DF） | REAL | |
| B51-BR3 | B51 | TestL3Base_TOSZero | spec.TOS=0 | DSCP/ECN 取自 spec.DSCP/ECN | REAL | |
| B52-BR1 | B52 | TestL3Base_TOSOverrides | spec.TOS=0x80 | DSCP==0x80>>2==32；ECN==0x80&3==0 | REAL | |

## 组件: Builder (builder.go) — writeTCP / writeUDP / encodeTCPOptions

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| B53-BR1 | B53 | TestWriteTCP_WindowZero_Default65535 | WindowSize=0 | dst[14:16]==65535 | REAL | |
| B54-POS | B54 | TestWriteTCP_Window65535 | WindowSize=65535 | dst[14:16]==65535 | REAL | |
| B55-BR2 | B55 | TestWriteTCP_NoOptions | TCPOptions=[] | dataOffset==5；dst[12]==0x50；无 options | REAL | |
| B56-BR3 | B56 | TestWriteTCP_OptionsPresent | opts=[MSS 4B] | dataOffset==(20+8)/4==7；dst[12]==0x70；options 写入 | REAL | |
| B57-POS | B57 | TestWriteTCP_ChecksumComputed | 正常 TCP+payload | dst[16:18] 为非零有效校验和（用独立校验和函数验证） | REAL | |
| B58-BR1 | B58 | TestWriteTCP_UrgentPointerZero | 任意 | dst[18:20]==0 | REAL | |
| B59-POS | B59 | TestWriteUDP_Normal | payload=4B | dst[4:6]==12（8+4）；8 字节头 | REAL | |
| B60-BR2 | B60 | TestWriteUDP_ZeroPayload | payload=nil | dst[4:6]==8 | REAL | |
| B61-POS | B61 | TestWriteUDP_ChecksumComputed | 正常 | dst[6:8] 有效校验和 | REAL | |
| B62-POS | B62 | TestEncodeTCPOptions_Empty | opts=[] | 返回 []（len%4==0，不补 NOP） | REAL | |
| B63-BR1 | B63 | TestEncodeTCPOptions_KindEnd | opts=[{Kind:0}] | 返回 []byte{0}；len==1→补 NOP 到 4 → []byte{0,1,1,1} | REAL | |
| B64-BR2 | B64 | TestEncodeTCPOptions_KindNOP | opts=[{Kind:1}] | 返回 []byte{1}→补齐 []byte{1,1,1,1} | REAL | |
| B65-POS | B65 | TestEncodeTCPOptions_Regular | opts=[{Kind:2,Data:[0x05,0xb4]}] | 返回 [2,4,0x05,0xb4]（len 4 已对齐） | REAL | |
| B66-BR3 | B66 | TestEncodeTCPOptions_NotAligned | opts=[{Kind:2,Data:[0x05,0xb4,0x01]}]（3B data→total 5B） | 末尾补 3 个 NOP 到 8B | REAL | |
| B67-BR1 | B67 | TestEncodeTCPOptions_Multiple | opts=[{Kind:2,Data:2B},{Kind:1}] | 按序序列化+对齐 | REAL | |
| B68-BR2 | B68 | TestEncodeTCPOptions_MSS | opts=[{Kind:2,Data:[0x05,0xb4]}] | [0x02,0x04,0x05,0xb4] | REAL | |
| B69-POS | B69 | TestCalcTCPChecksum_Normal | 正常 config+header+payload | 校验和与独立实现一致 | REAL | |
| B70-NEG | B70 | TestCalcTCPChecksum_SrcIPEmpty | SrcIP="" | 伪头 src 全零；不 panic | REAL | |
| B71-NEG | B71 | TestCalcTCPChecksum_SrcIPInvalid | SrcIP="bad" | 警告；伪头 src 全零 | REAL | |
| B72-NEG | B72 | TestCalcTCPChecksum_DstIPEmpty | DstIP="" | 伪头 dst 全零 | REAL | |
| B73-NEG | B73 | TestCalcTCPChecksum_DstIPInvalid | DstIP="bad" | 警告；dst 全零 | REAL | |
| B74-BR1 | B74 | TestCalcTCPChecksum_OddPayload | payload len 奇数 | 末字节 <<8 处理；校验和正确 | REAL | |
| B75-BR2 | B75 | TestCalcTCPChecksum_EvenPayload | payload len 偶数 | 正常配对；校验和正确 | REAL | |
| B76-BR3 | B76 | TestCalcTCPChecksum_SkipsChecksumField | header 含校验和字段 | offset 16 被跳过（不参与求和） | REAL | |
| B77-NEG | B77 | TestCalcTCPChecksum_HeaderUnder18 | header <18B | 不 panic（边界检查 i+2<=len） | REAL | |
| B78-POS | B78 | TestCalcUDPChecksum_Normal | 正常 | 校验和正确 | REAL | |
| B79-NEG | B79 | TestCalcUDPChecksum_SrcIPEmpty | SrcIP="" | 伪头 src 全零 | REAL | |
| B80-NEG | B80 | TestCalcUDPChecksum_SrcIPInvalid | SrcIP="bad" | 警告；零 | REAL | |
| B81-NEG | B81 | TestCalcUDPChecksum_DstIPEmpty | DstIP="" | dst 全零 | REAL | |
| B82-NEG | B82 | TestCalcUDPChecksum_DstIPInvalid | DstIP="bad" | 警告；零 | REAL | |
| B83-BR1 | B83 | TestCalcUDPChecksum_OddPayload | payload 奇数 | 末字节 <<8 | REAL | |
| B84-BR2 | B84 | TestCalcUDPChecksum_EvenPayload | payload 偶数 | 正常配对 | REAL | |
| B85-BR3 | B85 | TestCalcUDPChecksum_IPv6Src | SrcIP="::1" | To4()==nil；伪头 src 全零 | REAL | |

## 组件: RingBuffer (buffer.go) — NewRingBuffer / Put / Get / GetBatch / Len/Bytes/Status/Close

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| RB1-POS | RB1 | TestNewRingBuffer_Normal | size=1024, maxBytes=0 | size==1024；maxBytes==0；tokens/burst 不适用；Len()==0 | REAL | |
| RB2-NEG | RB2 | TestNewRingBuffer_SizeZero | size=0 | Put 必返回 false（count>=size 即 0>=0） | REAL | |
| RB3-NEG | RB3 | TestNewRingBuffer_SizeNegative_Panics | size=-1 | panic（make([][]byte,-1)） | REAL | 失败测试先行 |
| RB4-POS | RB4 | TestPut_Normal | size=10, 空 | Put 返回 true；Len()==1；Bytes==len(pkt) | REAL | |
| RB5-NEG | RB5 | TestPut_Closed | Close() 后 Put | 返回 false | REAL | |
| RB6-NEG | RB6 | TestPut_Full | size=3, 填满后 Put | 返回 false；Len 仍 3 | REAL | |
| RB7-NEG | RB7 | TestPut_ByteLimitExceeded | size=10, maxBytes=5, Put 3B 后再 Put 3B | 第二次返回 false | REAL | |
| RB8-BR1 | RB8 | TestPut_MaxBytesZero_NoLimit | maxBytes=0 | 无字节限制；Put 大包仍 true | REAL | |
| RB9-BR2 | RB9 | TestPut_ExactlyFills_WrapsTail | size=3, Put 3 包 | tail 回绕到 0；第 4 个 Put false | REAL | |
| RB10-BR3 | RB10 | TestPut_NilPacket | Put(nil) | 返回 true；count++；bytes 不变（len(nil)==0） | REAL | |
| RB11-POS | RB11 | TestPut_ConcurrentSafe | 100 goroutine 各 Put 100 次 | -race 无竞争；最终 Len==size（满后丢弃）；无 panic | REAL | 并发正确性：-race + 总数守恒 |
| RB12-POS | RB12 | TestGet_Normal | 非空 buffer | 返回 packet, true；Len-- | REAL | |
| RB13-NEG | RB13 | TestGet_Closed | Close 后 Get | 返回 nil, false | REAL | |
| RB14-NEG | RB14 | TestGet_Empty | 空 buffer | 返回 nil, false | REAL | |
| RB15-BR1 | RB15 | TestGet_WrapAround | head 在末尾时 Get | head 回绕到 0；返回正确包 | REAL | |
| RB16-BR2 | RB16 | TestGet_SlotFreedForGC | Get 后 | buffer[head]==nil（释放引用） | REAL | |
| RB17-POS | RB17 | TestGetBatch_MaxLessThanCount | size=10, 填 5, GetBatch(3) | 返回 3 包；Len==2 | REAL | |
| RB18-NEG | RB18 | TestGetBatch_Closed | Close 后 | 返回 nil | REAL | |
| RB19-NEG | RB19 | TestGetBatch_Empty | 空 | 返回 nil | REAL | |
| RB20-BR1 | RB20 | TestGetBatch_MaxGreaterThanCount | 填 3, GetBatch(10) | 返回 3（capped） | REAL | |
| RB21-BR2 | RB21 | TestGetBatch_MaxEqualsCount | 填 3, GetBatch(3) | 返回 3 | REAL | |
| RB22-BR3 | RB22 | TestGetBatch_MaxZero | 填 3, GetBatch(0) | 返回空 slice（n=0） | REAL | |
| RB23-NEG | RB23 | TestGetBatch_NegativeNonEmpty_Panics | 填 3, GetBatch(-1) | n=min(-1,3)=-1；make([][]byte,-1) panic | REAL | 失败测试先行；校正枚举：空 buffer 时提前返回 nil 不 panic，仅非空 buffer panic |
| RB24-BR1 | RB24 | TestGetBatch_WrapAround | head 近末尾, GetBatch 跨回绕 | 顺序返回正确包 | REAL | |
| RB25-POS | RB25 | TestGetBatch_ConcurrentSafe | N goroutine Put + GetBatch | -race 无竞争；总数守恒 | REAL | 并发正确性 |
| RB26-POS | RB26 | TestLen_Empty | 空 | 0 | REAL | |
| RB27-BR1 | RB27 | TestLen_500 | 填 500 | 500 | REAL | |
| RB28-POS | RB28 | TestBytes_Empty | 空 | 0 | REAL | |
| RB29-BR1 | RB29 | TestBytes_1000 | 填累计 1000B | 1000 | REAL | |
| RB30-POS | RB30 | TestIsFull_Empty | 空 | false | REAL | |
| RB31-BR1 | RB31 | TestIsFull_Full | 满 | true | REAL | |
| RB32-POS | RB32 | TestStatus_Normal | 填 5/10 | count=5,size=10,full=false | REAL | |
| RB33-POS | RB33 | TestClose_Open | Close | closed=true（Put 返回 false） | REAL | |
| RB34-BR1 | RB34 | TestClose_AlreadyClosed | Close 两次 | no-op；不 panic | REAL | |

## 组件: PacketBuffer (buffer.go) — NewPacketBuffer / Put / Get / Status / Close

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| PB1-POS | PB1 | TestNewPacketBuffer_AllEnabled | EnableUp/Down/Combined=true | 三个 ring buffer 非 nil | REAL | |
| PB2-BR1 | PB2 | TestNewPacketBuffer_UpDisabled | EnableUp=false | upBuffer==nil；其余非 nil | REAL | |
| PB3-BR2 | PB3 | TestNewPacketBuffer_DownDisabled | EnableDown=false | downBuffer==nil | REAL | |
| PB4-BR3 | PB4 | TestNewPacketBuffer_CombinedDisabled | EnableCombined=false | combinedBuffer==nil | REAL | |
| PB5-NEG | PB5 | TestNewPacketBuffer_AllDisabled | 全 false | 三 buffer 均 nil | REAL | |
| PB6-POS | PB6 | TestPut_UpAllEnabled | direction="up" | upBuffer+combinedBuffer 各 +1；返回 true | REAL | |
| PB7-POS | PB7 | TestPut_DownAllEnabled | direction="down" | downBuffer+combinedBuffer 各 +1；返回 true | REAL | |
| PB8-BR1 | PB8 | TestPut_DefaultDirection | direction="default" | 仅 combinedBuffer +1；返回 true | REAL | |
| PB9-BR1 | PB9 | TestPut_UpDisabled | direction="up", up 禁用 | 仅 combined +1；返回 false（success 跟踪 up） | REAL | |
| PB10-BR2 | PB10 | TestPut_DownDisabled | direction="down", down 禁用 | 仅 combined +1；返回 false | REAL | |
| PB11-BR3 | PB11 | TestPut_UpCombinedDisabled | direction="up", combined 禁用 | 仅 up +1；返回 true | REAL | |
| PB12-NEG | PB12 | TestPut_DefaultCombinedDisabled | direction="default", combined 禁用 | 无写入；返回 false | REAL | |
| PB13-BR1 | PB13 | TestPut_UpNilBuffer | upBuffer=nil | nil 检查；combined 仍 Put | REAL | |
| PB14-BR2 | PB14 | TestPut_UpBufferFull | up 满, combined 空 | up 失败, combined 成功；返回 false | REAL | |
| PB15-BR3 | PB15 | TestPut_UpFailsCombinedSucceeds | up.Put false, combined.Put true | 返回 false（跟踪 primary up） | REAL | |
| PB16-BR1 | PB16 | TestPut_UpSucceedsCombinedFails | up.Put true, combined.Put false | 返回 true（跟踪 primary up） | REAL | |
| PB17-POS | PB17 | TestGet_UpEnabled | mode="up" | 返回 upBuffer.GetBatch | REAL | |
| PB18-POS | PB18 | TestGet_DownEnabled | mode="down" | 返回 downBuffer.GetBatch | REAL | |
| PB19-POS | PB19 | TestGet_CombinedEnabled | mode="combined" | 返回 combinedBuffer.GetBatch | REAL | |
| PB20-NEG | PB20 | TestGet_UpDisabled | mode="up", up 禁用 | 返回 nil | REAL | |
| PB21-NEG | PB21 | TestGet_UnknownMode | mode="xyz" | 返回 nil | REAL | |
| PB22-BR2 | PB22 | TestGet_BufferEmpty | mode="up", 空 | 空 slice | REAL | |
| PB23-POS | PB23 | TestStatus_AllEnabled | 全启用 | 含 up/down/combined 三子 map | REAL | |
| PB24-BR1 | PB24 | TestStatus_UpDisabled | up 禁用 | 无 up 键 | REAL | |
| PB25-NEG | PB25 | TestStatus_AllDisabled | 全禁用 | 空 map | REAL | |
| PB26-POS | PB26 | TestClose_AllExist | 三 buffer 存在 | 三者 closed（Put 返回 false） | REAL | |
| PB27-BR1 | PB27 | TestClose_NilUp | upBuffer=nil | 跳过；不 panic | REAL | |
| PB28-BR2 | PB28 | TestClose_NilCombined | combinedBuffer=nil | 跳过；不 panic | REAL | |

## 组件: TokenBucket (buffer.go) — NewTokenBucket / Allow / Wait / SetRate

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| TB1-POS | TB1 | TestNewTokenBucket_Normal | rate=1000, burst=65536 | tokens==65536；lastTime 非 0；rate/burst 正确 | REAL | 同包断言字段 |
| TB2-BR1 | TB2 | TestNewTokenBucket_RateZero | rate=0 | rate==0（unlimited 语义） | REAL | |
| TB3-POS | TB3 | TestAllow_RateZero_AlwaysTrue | rate=0, n=任意 | 始终 true | REAL | |
| TB4-POS | TB4 | TestAllow_EnoughTokens | burst=1000, n=500 | true；tokens 减 500 | REAL | |
| TB5-NEG | TB5 | TestAllow_NotEnough | burst=100, n=200（无补充） | false | REAL | |
| TB6-BR1 | TB6 | TestAllow_TokensCappedToBurst | 长时补充后 | tokens 不超 burst | REAL | |
| TB7-BR2 | TB7 | TestAllow_FirstCallAfterIdle_Capped | 设 lastTime 很久前 | tokens 补充后 cap 到 burst | REAL | |
| TB8-BR3 | TB8 | TestAllow_NZero | n=0 | true（tokens>=0） | REAL | |
| TB9-NEG | TB9 | TestAllow_NGreaterThanBurst_FromEmpty | burst=100, 清空后 n=200 | false（n>burst 永不满足） | REAL | |
| TB10-BR1 | TB10 | TestAllow_NGreaterThanBurst_Full | burst=100, 满, n=150 | 一次 true（tokens 100→-50？实际 100>=150 false）→ 校正：n>burst 永不 true；此场景应 false | REAL | 校正枚举：n>burst 时即使满也 false（100>=150 不成立） |
| TB11-BR2 | TB11 | TestAllow_NegativeElapsed | 同包设 lastTime=未来（clock skew） | elapsed 负；tokens 减少；返回值反映减少后 | REAL | 失败测试先行：clock skew 行为 |
| TB12-NEG | TB12 | TestAllow_LargeElapsedOverflow | 同包设 lastTime 极久远 | (elapsed*rate) 可能溢出 int64；断言不 panic + 行为可预测 | REAL | 失败测试先行：已知潜在溢出 bug |
| TB13-POS | TB13 | TestWait_Normal | rate 足够补充 | 最终返回 nil | REAL | |
| TB14-BR1 | TB14 | TestWait_AllowImmediate | tokens 充足 | 立即 nil | REAL | |
| TB15-NEG | TB15 | TestWait_CtxCancelled | ctx cancel | 返回 ctx.Err() | REAL | |
| TB16-BR2 | TB16 | TestWait_PollingLoop | tokens 不足但可补充 | 10ms 轮询；最终 nil | REAL | |
| TB17-POS | TB17 | TestSetRate_50000 | SetRate(50000) | rate==50000 | REAL | |
| TB18-BR1 | TB18 | TestSetRate_Zero | SetRate(0) | rate==0（禁用限速） | REAL | |

## 组件: TupleGenerator (tuple_generator.go) — Next / genIP

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| TG1-POS | TG1 | TestNext_EmptyConfig | 空 TupleConfig, index=0 | "","",0,0 | REAL | |
| TG2-POS | TG2 | TestNext_ValidConfig | fixed IPs/ports, index=0 | 返回首值 | REAL | |
| TG3-NEG | TG3 | TestNext_NegativeIndex | index=-1 | 各子函数用 -1；不 panic；返回可预测值 | REAL | |
| TG4-POS | TG4 | TestGenIP_FixedString | strategy="fixed", Value="1.1.1.1" | "1.1.1.1" | REAL | |
| TG5-NEG | TG5 | TestGenIP_FixedNonString | Value=42（非 string） | "" | REAL | |
| TG6-BR1 | TG6 | TestGenIP_EmptyStrategy | strategy="" | 同 fixed | REAL | |
| TG7-POS | TG7 | TestGenIP_ListNonEmpty | List=["a","b"], index=3 | List[3%2]==List[1]=="b" | REAL | |
| TG8-NEG | TG8 | TestGenIP_ListEmpty | List=[] | "" | REAL | |
| TG9-NEG | TG9 | TestGenIP_IncRangeLT2 | Range=[1 elem] | "" | REAL | |
| TG10-NEG | TG10 | TestGenIP_IncStartInvalid | Range=["bad","1.1.1.2"] | "" | REAL | |
| TG11-NEG | TG11 | TestGenIP_IncEndLTStart | Range=["1.1.1.5","1.1.1.1"] | "" | REAL | |
| TG12-POS | TG12 | TestGenIP_IncValid | Range=["1.1.1.1","1.1.1.3"], index=1, step=1 | "1.1.1.2" | REAL | |
| TG13-BR2 | TG13 | TestGenIP_IncStepZero | step=0 | 默认 1 | REAL | |
| TG14-BR3 | TG14 | TestGenIP_IncStepZeroDefault | step=0, index=2 | offset=2 | REAL | |
| TG15-BR1 | TG15 | TestGenIP_IncLargeIndex_Wraps | count=3, index=5 | offset=5%3=2 | REAL | |
| TG16-NEG | TG16 | TestGenIP_IncOverflow | start 近 uint32 上限, offset 大 | start+offset 回绕（uint32 wrap）；断言回绕后值 | REAL | 失败测试先行：已知 silent wrap bug |
| TG17-NEG | TG17 | TestGenIP_RandRangeLT2 | Range=[1 elem] | "" | REAL | |
| TG18-NEG | TG18 | TestGenIP_RandStartInvalid | Range=["bad","1.1.1.2"] | "" | REAL | |
| TG19-NEG | TG19 | TestGenIP_RandEndLTStart | Range=["1.1.1.5","1.1.1.1"] | "" | REAL | |
| TG20-POS | TG20 | TestGenIP_RandValid | Range=["1.1.1.1","1.1.1.10"], Seed=42, index=0 | 结果在 [1.1.1.1,1.1.1.10]；可复现 | REAL | |
| TG21-BR1 | TG21 | TestGenIP_RandSeedZero | Seed=0, index=0 | 可复现（同 index 同结果） | REAL | |
| TG22-BR2 | TG22 | TestGenIP_DefaultStrategy | strategy="bogus" | "" | REAL | |
| TG23-POS | TG23 | TestGenPort_FixedFloat64 | Value=float64(8080) | 8080 | REAL | |
| TG24-BR1 | TG24 | TestGenPort_FixedInt | Value=int(80) | 80 | REAL | |
| TG25-NEG | TG25 | TestGenPort_FixedNil | Value=nil | 0 | REAL | |
| TG26-BR2 | TG26 | TestGenPort_EmptyStrategy | strategy="" | 同 fixed | REAL | |
| TG27-POS | TG27 | TestGenPort_ListNonEmpty | List=["80","443"], index=1 | 443 | REAL | |
| TG28-NEG | TG28 | TestGenPort_ListEmpty | List=[] | 0 | REAL | |
| TG29-NEG | TG29 | TestGenPort_IncRangeLT2 | Range=[1 elem] | 0 | REAL | |
| TG30-NEG | TG30 | TestGenPort_IncEndLTStart | Range=[80,79] | 0 | REAL | |
| TG31-BR1 | TG31 | TestGenPort_IncStepZero | step=0 | 默认 1 | REAL | |
| TG32-BR2 | TG32 | TestGenPort_IncLargeIndex_Wraps | count=10, index=12 | (12*1)%10=2 | REAL | |
| TG33-POS | TG33 | TestGenPort_IncValid | Range=[80,89], index=1 | 81 | REAL | |
| TG34-NEG | TG34 | TestGenPort_RandRangeLT2 | Range=[1 elem] | 0 | REAL | |
| TG35-NEG | TG35 | TestGenPort_RandEndLTStart | Range=[80,79] | 0 | REAL | |
| TG36-POS | TG36 | TestGenPort_RandValid | Range=[80,89], Seed=42, index=0 | 结果在 [80,89]；可复现 | REAL | |
| TG37-BR2 | TG37 | TestGenPort_DefaultStrategy | strategy="bogus" | 0 | REAL | |
| TG38-POS | TG38 | TestIpToU32_Valid | "192.168.1.1" | 0xC0A80101, true | REAL | |
| TG39-NEG | TG39 | TestIpToU32_NotFourParts | "invalid" | 0, false | REAL | |
| TG40-NEG | TG40 | TestIpToU32_OctetOverflow | "256.0.0.1" | 0, false | REAL | |
| TG41-NEG | TG41 | TestIpToU32_Octet999 | "10.0.0.999" | 0, false | REAL | |
| TG42-POS | TG42 | TestToPort_Float64 | float64(8080) | 8080 | REAL | |
| TG43-BR1 | TG43 | TestToPort_Float64Overflow | float64(70000) | 70000%65536==4464 | REAL | |
| TG44-POS | TG44 | TestToPort_Int | int(80) | 80 | REAL | |
| TG45-BR2 | TG45 | TestToPort_StringNumeric | "443" | 443 | REAL | |
| TG46-NEG | TG46 | TestToPort_StringInvalid | "abc" | 0 | REAL | |
| TG47-NEG | TG47 | TestToPort_Nil | nil | 0 | REAL | |
| TG48-POS | TG48 | TestAsString_String | "hello" | "hello" | REAL | |
| TG49-BR1 | TG49 | TestAsString_Float64 | float64(42) | "42" | REAL | |
| TG50-NEG | TG50 | TestAsString_Nil | nil | "<nil>" | REAL | |

## 组件: Validate (validate.go) — ValidateConfigRanges

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| V1-POS | V1 | TestValidateConfigRanges_AllValid | 全字段合法 | nil | REAL | |
| V2-NEG | V2 | TestValidateConfigRanges_DSCPNeg | dscp=-1 | "dscp -1 invalid" | REAL | |
| V3-NEG | V3 | TestValidateConfigRanges_DSCPOver | dscp=64 | "dscp 64 invalid" | REAL | |
| V4-NEG | V4 | TestValidateConfigRanges_ECNNeg | ecn=-1 | "ecn -1 invalid" | REAL | |
| V5-NEG | V5 | TestValidateConfigRanges_ECNOver | ecn=4 | "ecn 4 invalid" | REAL | |
| V6-NEG | V6 | TestValidateConfigRanges_VLANIDNeg | vlan_id=-1 | "vlan_id -1 invalid" | REAL | |
| V7-NEG | V7 | TestValidateConfigRanges_VLANIDOver | vlan_id=4096 | "vlan_id 4096 invalid" | REAL | |
| V8-NEG | V8 | TestValidateConfigRanges_VLANPriorityNeg | vlan_priority=-1 | "vlan_priority -1 invalid" | REAL | |
| V9-NEG | V9 | TestValidateConfigRanges_VLANPriorityOver | vlan_priority=8 | "vlan_priority 8 invalid" | REAL | |
| V10-NEG | V10 | TestValidateConfigRanges_FlagsNeg | flags=-1 | "flags -1 invalid" | REAL | |
| V11-NEG | V11 | TestValidateConfigRanges_FlagsOver | flags=8 | "flags 8 invalid" | REAL | |
| V12-NEG | V12 | TestValidateConfigRanges_FragOffsetNeg | frag_offset=-1 | "frag_offset -1 invalid" | REAL | |
| V13-NEG | V13 | TestValidateConfigRanges_FragOffsetOver | frag_offset=8192 | "frag_offset 8192 invalid" | REAL | |
| V14-NEG | V14 | TestValidateConfigRanges_TTLNeg | ttl=-1 | "ttl -1 invalid" | REAL | |
| V15-NEG | V15 | TestValidateConfigRanges_TTLOver | ttl=256 | "ttl 256 invalid" | REAL | |
| V16-NEG | V16 | TestValidateConfigRanges_TOSNeg | tos=-1 | "tos -1 invalid" | REAL | |
| V17-NEG | V17 | TestValidateConfigRanges_TOSOver | tos=256 | "tos 256 invalid" | REAL | |
| V18-NEG | V18 | TestValidateConfigRanges_SrcPortNeg | src_port=-1 | "src_port -1 invalid" | REAL | |
| V19-NEG | V19 | TestValidateConfigRanges_SrcPortOver | src_port=65536 | "src_port 65536 invalid" | REAL | |
| V20-NEG | V20 | TestValidateConfigRanges_DstPortNeg | dst_port=-1 | "dst_port -1 invalid" | REAL | |
| V21-NEG | V21 | TestValidateConfigRanges_DstPortOver | dst_port=65536 | "dst_port 65536 invalid" | REAL | |
| V22-BR1 | V22 | TestValidateConfigRanges_MissingFields | 空 map | nil（getInt 返回 0，0 在范围内） | REAL | |

## 组件: Validate (validate.go) — ValidateProtocolSubConfigs

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| V23-POS | V23 | TestValidateProtocolSubConfigs_TCPValid | tcp.mss=1460 | nil | REAL | |
| V24-NEG | V24 | TestValidateProtocolSubConfigs_TCPMSSNeg | tcp.mss=-1 | "tcp.mss -1 invalid" | REAL | |
| V25-NEG | V25 | TestValidateProtocolSubConfigs_TCPMSSOver | tcp.mss=65536 | "tcp.mss 65536 invalid" | REAL | |
| V26-NEG | V26 | TestValidateProtocolSubConfigs_TCPWinNeg | tcp.window_size=-1 | "tcp.window_size -1 invalid" | REAL | |
| V27-BR1 | V27 | TestValidateProtocolSubConfigs_TCPNoSub | protocol="tcp", 无 tcp 子 map | nil（ok=false 跳过） | REAL | |
| V28-NEG | V28 | TestValidateProtocolSubConfigs_DNSQTypeNeg | dns.query_type=-1 | "dns.query_type -1 invalid" | REAL | |
| V29-NEG | V29 | TestValidateProtocolSubConfigs_DNSQTypeOver | dns.query_type=65536 | "dns.query_type 65536 invalid" | REAL | |
| V30-NEG | V30 | TestValidateProtocolSubConfigs_ICMPTypeNeg | icmp.type=-1 | "icmp.type -1 invalid" | REAL | |
| V31-NEG | V31 | TestValidateProtocolSubConfigs_ICMPTypeOver | icmp.type=256 | "icmp.type 256 invalid" | REAL | |
| V32-NEG | V32 | TestValidateProtocolSubConfigs_ICMPCodeNeg | icmp.code=-1 | "icmp.code -1 invalid" | REAL | |
| V33-NEG | V33 | TestValidateProtocolSubConfigs_ICMPCodeOver | icmp.code=256 | "icmp.code 256 invalid" | REAL | |
| V34-NEG | V34 | TestValidateProtocolSubConfigs_ICMPSeqNeg | icmp.sequence=-1 | "icmp.sequence -1 invalid" | REAL | |
| V35-NEG | V35 | TestValidateProtocolSubConfigs_ICMPSeqOver | icmp.sequence=65536 | "icmp.sequence 65536 invalid" | REAL | |
| V36-NEG | V36 | TestValidateProtocolSubConfigs_ARPOpNeg | arp.operation=-1 | "arp.operation -1 invalid" | REAL | |
| V37-NEG | V37 | TestValidateProtocolSubConfigs_ARPOpOver | arp.operation=65536 | "arp.operation 65536 invalid" | REAL | |
| V38-BR1 | V38 | TestValidateProtocolSubConfigs_HTTP | protocol="http" | nil（无校验） | REAL | |
| V39-BR2 | V39 | TestValidateProtocolSubConfigs_Unknown | protocol="xyz" | nil（无 case） | REAL | |
| V40-BR3 | V40 | TestValidateProtocolSubConfigs_SubWrongType | cfg["tcp"]="string" | nil（ok=false） | REAL | |

## 组件: Validate (validate.go) — ValidateFlowSpec

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| V41-POS | V41 | TestValidateFlowSpec_Empty | 全零空 | nil | REAL | |
| V42-NEG | V42 | TestValidateFlowSpec_SrcIPInvalid | SrcIP="bad" | "invalid src_ip" | REAL | |
| V43-POS | V43 | TestValidateFlowSpec_SrcIPValid | SrcIP="1.1.1.1" | nil | REAL | |
| V44-NEG | V44 | TestValidateFlowSpec_DstIPInvalid | DstIP="bad" | "invalid dst_ip" | REAL | |
| V45-POS | V45 | TestValidateFlowSpec_DstIPValid | DstIP="1.1.1.1" | nil | REAL | |
| V46-NEG | V46 | TestValidateFlowSpec_SrcMACInvalid | SrcMAC="bad" | "invalid src_mac" | REAL | |
| V47-POS | V47 | TestValidateFlowSpec_SrcMACValid | SrcMAC="aa:bb:cc:dd:ee:ff" | nil | REAL | |
| V48-NEG | V48 | TestValidateFlowSpec_DstMACInvalid | DstMAC="bad" | "invalid dst_mac" | REAL | |
| V49-POS | V49 | TestValidateFlowSpec_DstMACValid | DstMAC="aa:bb:cc:dd:ee:ff" | nil | REAL | |
| V50-BR1 | V50 | TestValidateFlowSpec_VLANNil | VLAN=nil | nil（跳过） | REAL | |
| V51-NEG | V51 | TestValidateFlowSpec_VLANIDOver | VLAN.ID=5000 | "vlan_id 5000 invalid" | REAL | |
| V52-BR2 | V52 | TestValidateFlowSpec_VLANID4095 | VLAN.ID=4095 | nil | REAL | |
| V53-NEG | V53 | TestValidateFlowSpec_VLANPriorityOver | VLAN.Priority=8 | "vlan_priority 8 invalid" | REAL | |
| V54-NEG | V54 | TestValidateFlowSpec_DSCPOver | DSCP=64 | "dscp 64 invalid" | REAL | |
| V55-POS | V55 | TestValidateFlowSpec_DSCPZero | DSCP=0 | nil | REAL | |
| V56-NEG | V56 | TestValidateFlowSpec_ECNOver | ECN=4 | "ecn 4 invalid" | REAL | |
| V57-BR1 | V57 | TestValidateFlowSpec_TCPNil | TCP=nil | nil（无 MSS 检查） | REAL | |
| V58-BR2 | V58 | TestValidateFlowSpec_TCPMSSZero | TCP.MSS=0 | nil（用默认） | REAL | |
| V59-NEG | V59 | TestValidateFlowSpec_TCPMSSTooSmall | TCP.MSS=100 | "mss 100 too small" | REAL | |
| V60-BR3 | V60 | TestValidateFlowSpec_TCPMSSMin | TCP.MSS=536 | nil | REAL | |
| V61-POS | V61 | TestValidateFlowSpec_TCPMSSValid | TCP.MSS=1460 | nil | REAL | |

## 组件: Validate (validate.go) — ValidateTask / ValidateBatchSpec / validateReplaySpec

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| V62-POS | V62 | TestValidateTask_ValidTCP | 合法 TCP task | nil | REAL | |
| V63-NEG | V63 | TestValidateTask_NameEmpty | Name="" | "task name is required" | REAL | |
| V64-BR1 | V64 | TestValidateTask_Batch | task.Batch!=nil | 委托 ValidateBatchSpec | REAL | |
| V65-NEG | V65 | TestValidateTask_InvalidProtocol | protocol="xyz" | "invalid protocol: xyz" | REAL | |
| V66-NEG | V66 | TestValidateTask_ProtocolTCP_SpecInvalid | tcp + 非法 spec | "invalid spec: ..." | REAL | |
| V67-NEG | V67 | TestValidateTask_ProtocolEmpty | protocol="" | "invalid protocol: " | REAL | |
| V68-POS | V68 | TestValidateBatchSpec_Valid | 合法 batch | nil | REAL | |
| V69-NEG | V69 | TestValidateBatchSpec_EmptyClasses | Classes=[] | "batch must contain at least one traffic class" | REAL | |
| V70-NEG | V70 | TestValidateBatchSpec_DuplicateClassID | 两个 class ID="c1" | "class[1] c1: duplicate class id" | REAL | |
| V71-NEG | V71 | TestValidateBatchSpec_ClassIDEmpty | class.ID="" | "class[0]: id is required" | REAL | |
| V72-NEG | V72 | TestValidateBatchSpec_InvalidType | type="xyz" | "class[0] X: invalid type xyz" | REAL | |
| V73-POS | V73 | TestValidateBatchSpec_ReplayValid | 合法 replay class | nil | REAL | |
| V74-NEG | V74 | TestValidateBatchSpec_ReplayMissingSpec | replay class, Replay=nil | "class[0] X: replay class missing 'replay' spec" | REAL | |
| V75-NEG | V75 | TestValidateBatchSpec_ReplayInvalidSpec | Replay=bad JSON | 包装 validateReplaySpec err | REAL | |
| V76-NEG | V76 | TestValidateBatchSpec_FlowCountZero | FlowCount=0 | "flow_count must be > 0" | REAL | |
| V77-NEG | V77 | TestValidateBatchSpec_FlowCountNeg | FlowCount=-1 | "flow_count must be > 0" | REAL | |
| V78-NEG | V78 | TestValidateBatchSpec_ConfigRangesInvalid | dscp=64 in config | 包装 ValidateConfigRanges err | REAL | |
| V79-NEG | V79 | TestValidateBatchSpec_SubConfigInvalid | tcp.mss=65536 | 包装 ValidateProtocolSubConfigs err | REAL | |
| V80-NEG | V80 | TestValidateBatchSpec_FlowSpecInvalid | 非法 IP | 包装 ValidateFlowSpec err | REAL | |
| V81-BR1 | V81 | TestValidateBatchSpec_ReplayFlowCountIgnored | replay class, FlowCount=0 | nil（replay 不检查 FlowCount） | REAL | |
| V82-POS | V82 | TestValidateReplaySpec_Valid | 全字段合法 | nil | REAL | |
| V83-NEG | V83 | TestValidateReplaySpec_InvalidJSON | 非法 JSON | "invalid replay spec JSON" | REAL | |
| V84-NEG | V84 | TestValidateReplaySpec_NoPcapAssetID | pcap_asset_id="" | "replay spec missing pcap_asset_id" | REAL | |
| V85-BR1 | V85 | TestValidateReplaySpec_SpeedOriginal | mode="original" | nil | REAL | |
| V86-BR2 | V86 | TestValidateReplaySpec_SpeedMultiplier | mode="multiplier" | nil | REAL | |
| V87-BR3 | V87 | TestValidateReplaySpec_SpeedBPS | mode="bps", BPS="1M" | nil | REAL | |
| V88-BR1 | V88 | TestValidateReplaySpec_SpeedPPS | mode="pps", PPS=100 | nil | REAL | |
| V89-BR2 | V89 | TestValidateReplaySpec_SpeedMax | mode="max" | nil | REAL | |
| V90-BR3 | V90 | TestValidateReplaySpec_SpeedEmpty | mode="" | nil | REAL | |
| V91-NEG | V91 | TestValidateReplaySpec_SpeedBogus | mode="bogus" | "invalid speed mode" | REAL | |
| V92-NEG | V92 | TestValidateReplaySpec_BPSModeNoValue | mode="bps", BPS="" | "bps mode requires a bps value" | REAL | |
| V93-NEG | V93 | TestValidateReplaySpec_PPSModeZero | mode="pps", PPS=0 | "pps mode requires pps > 0" | REAL | |
| V94-NEG | V94 | TestValidateReplaySpec_PPSModeNeg | mode="pps", PPS=-1 | "pps mode requires pps > 0" | REAL | |
| V95-BR1 | V95 | TestValidateReplaySpec_DirectionSingle | direction="single" | nil | REAL | |
| V96-BR2 | V96 | TestValidateReplaySpec_DirectionDual | direction="dual" | nil | REAL | |
| V97-BR3 | V97 | TestValidateReplaySpec_DirectionEmpty | direction="" | nil | REAL | |
| V98-NEG | V98 | TestValidateReplaySpec_DirectionBogus | direction="bogus" | "invalid direction" | REAL | |
| V99-BR1 | V99 | TestValidateReplaySpec_ChecksumRecompute | checksum_mode="recompute" | nil | REAL | |
| V100-BR2 | V100 | TestValidateReplaySpec_ChecksumPreserve | checksum_mode="preserve" | nil | REAL | |
| V101-BR3 | V101 | TestValidateReplaySpec_ChecksumEmpty | checksum_mode="" | nil | REAL | |
| V102-NEG | V102 | TestValidateReplaySpec_ChecksumBogus | checksum_mode="bogus" | "invalid checksum_mode" | REAL | |

## 组件: Convert (convert.go) — generateTaskID / APIRequestToTask / ParseBPS

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| SC1-POS | SC1 | TestGenerateTaskID_Format | 调用 | 前缀 "task-" + 16 hex 字符；两次调用不同（高概率） | REAL | |
| SC2-POS | SC2 | TestAPIRequestToTask_AllFields | 全字段 | Task.ID 非空；Name/Desc/Protocol/Spec/Interface 透传 | REAL | |
| SC3-BR1 | SC3 | TestAPIRequestToTask_EmptyStrings | 空字符串 | ID 仍生成；其余空 | REAL | |
| SC4-POS | SC4 | TestParseBPS_Empty | "" | 0, nil | REAL | |
| SC5-POS | SC5 | TestParseBPS_100k | "100k" | 100000, nil | REAL | |
| SC6-BR1 | SC6 | TestParseBPS_100K | "100K" | 100000, nil | REAL | |
| SC7-POS | SC7 | TestParseBPS_1M | "1M" | 1000000, nil | REAL | |
| SC8-BR2 | SC8 | TestParseBPS_1m | "1m" | 1000000, nil | REAL | |
| SC9-POS | SC9 | TestParseBPS_1G | "1G" | 1000000, nil→校正 1000000000, nil | REAL | 校正枚举：1G=10^9 |
| SC10-BR3 | SC10 | TestParseBPS_1g | "1g" | 1000000000, nil | REAL | |
| SC11-BR1 | SC11 | TestParseBPS_NoSuffix | "100" | 100, nil | REAL | |
| SC12-NEG | SC12 | TestParseBPS_abc | "abc" | 0, error | REAL | |
| SC13-NEG | SC13 | TestParseBPS_1kk | "1kk" | 剥 'k'→"1k"→ParseInt("1k") err→0, error | REAL | 失败测试先行 |
| SC14-BR2 | SC14 | TestParseBPS_Zero | "0" | 0, nil | REAL | |
| SC15-NEG | SC15 | TestParseBPS_Decimal | "1.5M" | ParseInt("1.5") err→0, error | REAL | |

## 组件: ConfigWorker/Engine — ctx 取消路径（确认并分别测试）

> 任务要求确认：worker 主循环响应 ctx.Done()（已知协议规划器可能不响应，但 worker 主循环应响应）。以下分别测试 ConfigWorker/PacketWorker/OutputWorker 主循环的 ctx 响应，以及规划器不响应时的 drain 兜底。

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| CTX1-POS | CW2 | TestConfigWorker_CtxDone_Exits | cancel worker ctx | run() 退出；wg.Wait 不阻塞 | SIMULATED | 主循环响应 ctx |
| CTX2-POS | PW2 | TestPacketWorker_CtxDone_Exits | cancel worker ctx | run() 退出；wg.Wait 不阻塞 | SIMULATED | 主循环响应 ctx |
| CTX3-POS | OW2 | TestOutputWorker_CtxDone_Exits | cancel worker ctx | run() 退出；wg.Wait 不阻塞 | SIMULATED | 主循环响应 ctx |
| CTX4-POS | CW17 | TestProcessTask_CtxCancel_PlannerIgnores_DrainsAndReports | mockPlanner 忽略 ctx 持续产 10 config；收 1 后 cancel taskCtx | drain 完成剩余（planner goroutine 退出无泄漏）；onTaskDone("task cancelled", 1) | SIMULATED | 规划器不响应 ctx 的兜底：drain 防阻塞泄漏 |
| CTX5-POS | CW34 | TestProcessBatchTask_CtxCancel_FlowForwardingDrains | cancel taskCtx 中途转发 | 排空该 flow configChan；goroutine 退出 | SIMULATED | |
| CTX6-POS | PW14 | TestProcessConfig_CtxCancel_WhileRateLimitWait | limiter.Wait 阻塞时 cancel ctx | Wait 返回 ctx.Err()；packetChan 无包 | SIMULATED | |

## 组件: 并发正确性（共享状态/共享速率）— N worker 聚合可观测行为

> 任务要求：TokenBucket/共享速率必须测 N worker 下**实际聚合吞吐** vs 配置速率，不能只测 -race 无竞争。PPSPacer 属 replay 模块（此处用 fake shared pacer 验证引擎 pacer 调度接线）。

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| CONC1-POS | RC4/RC15 | TestSharedTokenBucket_NWorkers_AggregateRate | PacketWorkers=4, 单 class BPS="10M"（1.25MB/s）, 1000 包×1000B=1MB | 总 elapsed ≈ 0.8s（[0.6s,1.5s]）；聚合吞吐 ≈1.25MB/s；**不**是 4×1.25MB/s（即 elapsed 不 <0.3s） | REAL | 失败测试先行：复现"共享 bucket 无互斥则 N×速率"bug；-race 干净 |
| CONC2-POS | RC1 | TestTaskStore_ConcurrentAccess | N goroutine 并发 StopTask/GetTaskStatus/OnPacketWritten/SubmitTask | -race 无竞争；状态机一致性（无 double-complete） | SIMULATED | |
| CONC3-POS | RC2/RC3 | TestOutputWriters_ConcurrentRegisterRead | 并发 Register/Unregister/GetDualWriter + OutputWorker 读 | -race 无竞争 | SIMULATED | |
| CONC4-POS | RC12/RC14 | TestRingBuffer_ConcurrentPutGet_Aggregate | 4 producer + 4 consumer 各 1000 包 | -race 无竞争；总放入==总取出+丢弃（守恒） | REAL | 并发正确性：守恒而非仅无竞争 |
| CONC5-POS | RC13 | TestRingBuffer_ConcurrentClose | 并发 Close + Put/Get | -race 无竞争；Close 后 Put 返回 false | REAL | |
| CONC6-POS | RC16 | TestConfigWorker_Stop_WaitGroupRace | Start 后发 task，立即 Stop | wg.Wait 不提前返回（goroutine 完成后才 Done）；无 panic | SIMULATED | 失败测试先行：wg.Add(1) 在 goroutine 内可能的 race |
| CONC7-POS | RC17 | TestOnTaskDone_Concurrent_CallbackOrdering | 多 task 并发完成 | -race 无竞争；回调各自触发（顺序不保证） | SIMULATED | |
| CONC8-POS | RC18 | TestSubmitStopRace_TaskCancelledBeforeRun | Submit 后立即 StopTask | 任务被 cancel；不 panic；不 double-complete | SIMULATED | |
| CONC9-POS | RC23 | TestStopDuringSubmit_NoClosedChanPanic | 并发 SubmitTask + Stop | 不 panic（send on closed channel）；-race 干净 | SIMULATED | 失败测试先行：复现 RC23 closed-channel panic |
| CONC10-POS | RC24 | TestStop_Idempotent_DoubleStop | Stop 两次 | 第二次 no-op；不 panic（double close 检查） | REAL | |
| CONC11-POS | RC19 | TestSetTotalConfigs_OnPacketWritten_ConcurrentCompletion | 并发调用 SetTaskTotalConfigs + OnPacketWritten | 完成幂等（仅一次 OnTaskComplete）；-race 干净 | SIMULATED | |
| CONC12-POS | PW7 | TestSharedPacer_NWorkers_AggregateRate_Fake | PacketWorkers=4, 注入同一 fake shared pacer（模拟 PPS 限速）到每包 Metadata["_pacer"] | fake pacer.Wait 调用总次数==包数；aggregate 速率受 pacer 限制（fake pacer 记录调用间隔）；-race 干净 | SIMULATED | 验证引擎 pacer 调度接线；真实 PPSPacer 聚合精度属 replay 模块 REAL 测试 |

## 组件: 集成（端到端：submit → worker → buffer/writer）

> 驱动完整管道 ConfigWorker→PacketWorker→OutputWorker，断言 buffer/writer 收到正确包数和内容。

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| INT1-POS | E50/CW18/PW4/OW22 | TestIntegration_SingleProtocol_PacketsReachBuffer | mockPlanner Count=20 + buildFunc 返回可识别 payload；Submit 后等完成 | buffer.Get(20,"combined") 返回 20 包；每包含 buildFunc 输出；OnTaskComplete 触发 | SIMULATED | 端到端：planner→config→packet→output→buffer |
| INT2-POS | E55/CW22 | TestIntegration_Batch_PerClassRateLimitersAndTagging | batch 2 class FlowCount=2；等完成 | 每包 config.ClassID=="taskID:classID"；rateLimiters 含两键；buffer 收 4 包 | SIMULATED | |
| INT3-POS | OW16 | TestIntegration_SingleWriter_ReceivesPackets | RegisterOutputWriter(taskID,fakeW)；Submit Count=10 | fakeW 收到 10 包；每包 bytes==buildFunc 输出 | SIMULATED | |
| INT4-POS | OW4/OW9 | TestIntegration_DualWriter_RoutingByDirection | RegisterDualWriter(c2s,s2c)；mockPlanner 产 5 "up"+5 "down" | c2s 收 5，s2c 收 5 | SIMULATED | |
| INT5-POS | OW23/OW28 | TestIntegration_BufferOverflow_TaskStillCompletes | BufferSize=2；Submit Count=50 | OnBufferOverflow 触发；任务仍 completed（OnPacketWritten 即使溢出仍计数） | SIMULATED | 已修复 bug：溢出不阻塞完成 |
| INT6-POS | RC4/CONC1 | TestIntegration_NWorkers_SharedRateAggregate | 见 CONC1 | 聚合吞吐==配置速率 | REAL | 端到端共享速率 |
| INT7-POS | E30 | TestIntegration_ReplayOrderPreserve_PWClampedToOne | ReplayOrderPreserve=true, PacketWorkers=4 | len(packetWorkers)==1；端到端包序保持（PacketIndex 单调） | REAL | 断言实际 worker 数 + 保序 |
| INT8-POS | CW17/CTX4 | TestIntegration_CtxCancelMidTask_DrainsAndFails | Submit 后立即 StopTask | onTaskDone("task cancelled")；FailTask 不覆写 "stopped"；无 goroutine 泄漏（goroutine 计数前后一致） | SIMULATED | |
| INT9-POS | CW8/CW10 | TestIntegration_PlannerError_PropagatesToFailTask | mockPlanner.Plan 返回 err | FailTask 调用；status=="failed"；OnTaskFailed 触发；errMsg 含 "planning failed" | SIMULATED | 失败路径端到端：planner err → FailTask |
| INT10-POS | CW9 | TestIntegration_ValidationError_PropagatesToFailTask | mockPlanner.Validate 返回 err | FailTask；status=="failed"；OnTaskFailed 触发 | SIMULATED | |
| INT11-POS | OW13/OW18 | TestIntegration_OutputWriterError_FailsTask | fakeW.WritePackets 返回 err | FailTask + UnregisterOutputWriter；OnTaskFailed 触发 | SIMULATED | |
| INT12-POS | E74 | TestIntegration_EmptyBatch_CompletesWithZero | mockPlanner Count=0 / 空 batch | onTaskDone(nil,0)；SetTaskTotalConfigs(count=0) 立即 completed | SIMULATED | 边界：0 包任务正常完成 |
| INT13-NEG | E52 | TestIntegration_InvalidSpec_RejectedAtSubmit | task.Name="" 或非法 spec | Submit 返回 error；任务未入队；taskStore 无此 task | SIMULATED | 失败路径：验证错误不进管道 |
| INT14-POS | E50 | TestIntegration_TaskStatusTransitions | Submit → 等完成 | status: running→completed；Progress 0→100；CompletedAt 非零 | SIMULATED | |
| INT15-POS | E88 | TestIntegration_ProgressCallback_Fires | Submit Count=100；OnProgress 记录 | OnProgress 多次触发；progress 单调递增；最终==100 | SIMULATED | |

## 组件: 真实环境 (MANUAL)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| MAN1-POS | 真实发包 | TestManual_RealNIC_Emission | Engine + InterfaceWriter(enp135s0f0np0)，Submit TCP task Count=100 | 抓包应看到 100 个 Ethernet 帧；`sudo tcpdump -i enp135s0f0np0 -c 100 -e -w /tmp/real.pcap`；`tcpdump -r /tmp/real.pcap \| wc -l`==100 | MANUAL | 依赖真实 NIC + 内核 AF_PACKET；无法在 go test 自动化 |
| MAN2-POS | 真实线缆速率精度 | TestManual_RealWire_RateLimitPrecision | BPS="1M"，1000 包×1000B | 抓包测实际线速 ≈1Mbps（125000B/s±10%）；`sudo tcpdump -i enp135s0f0np0 -w /tmp/rate.pcap & sleep 10; kill %1; tcpdump -r /tmp/rate.pcap -ttt \| awk`算 BPS；iperf3 对照 | MANUAL | 真实 PPS/BPS 精度需线缆+抓包；进程内 elapsed 测量属 REAL(CONC1) |
| MAN3-POS | 真实双端口网卡路由 | TestManual_RealDualPort_Routing | InterfaceWriter(iface1)+InterfaceWriter(iface2) 作 DualWriter；c2s/s2c 方向包 | iface1 抓到 c2s 包，iface2 抓到 s2c 包；`sudo tcpdump -i iface1 -c N & sudo tcpdump -i iface2 -c M` | MANUAL | 依赖两块物理网卡 |
| MAN4-POS | 真实多进程调度时序 | TestManual_RealMultiprocessScheduling_OrderOnWire | PacketWorkers>1（关闭 ReplayOrderPreserve），Submit 多 flow | 线缆上包序反映多 worker 交错（非严格按 PacketIndex）；`sudo tcpdump -i enp135s0f0np0 -w /tmp/order.pcap; tcpdump -r /tmp/order.pcap`检查乱序 | MANUAL | 真实 OS 多进程调度时序无法在单进程 go test 复现；保序逻辑（单 worker）的进程内验证属 REAL(INT7) |

## 汇总

- 真实(REAL): 435 个
- 模拟(SIMULATED): 149 个
- 手动(MANUAL): 4 个
- 合计: 588 个测试点

### MANUAL 测试点清单（ID + 一句话原因）

- **MAN1-POS**（真实发包到物理 NIC）：依赖真实网卡 enp135s0f0np0 与内核 AF_PACKET，go test 无法发送真实以太网帧到线缆，须用 tcpdump 抓包验证 100 帧到达。
- **MAN2-POS**（真实线缆速率精度）：1Mbps 限速的实际线缆精度须用 tcpdump/iperf3 在物理链路上测量，进程内 elapsed 测量（CONC1）只能近似聚合吞吐而非真实线速。
- **MAN3-POS**（真实双端口网卡路由）：c2s/s2c 路由到两块物理网卡须在两块真实 NIC 上同时抓包验证，进程内只能用 fake writer 验证路由逻辑（INT4）。
- **MAN4-POS**（真实多进程调度时序）：PacketWorkers>1 在真实 OS 多进程调度下的线缆包序交错时序无法在单进程 go test 复现，保序的进程内验证属 INT7（REAL）。
