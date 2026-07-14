Now I have all seven files loaded. Let me compile the complete enumeration.

---

# ENGINE COMPONENT -- SCENARIO ENUMERATION

## ENGINE (`engine.go`)

### NewEngine -- Construction

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E1 | Engine | NewEngine | config={0,0,0,0,0,0,false} | All maps initialized, channels nil, running=false, replayPlanner=nil, buildFunc=nil | Line 138-147 |
| E2 | Engine | NewEngine | All-negative config | Negative values accepted (maps are fine) | 138-147 |
| E3 | Engine | NewEngine | replayPlanner omitted | Stays nil (no registration) | 141 |
| E4 | Engine | NewEngine | buildFunc omitted | Stays nil | 142 |

### RegisterPlanner

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E8 | Engine | RegisterPlanner | First registration for name | planner stored in map | 151 |
| E9 | Engine | RegisterPlanner | Duplicate name | Overwrites previous entry | 151 |
| E10 | Engine | RegisterPlanner | nil planner | nil pointer dereference on .Name() -- CRASH | 151 |

### RegisterDualWriter / UnregisterDualWriter / GetDualWriter

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E13 | Engine | RegisterDualWriter | Valid c2s, s2c | Stored in dualWriters[taskID] | 178-180 |
| E14 | Engine | RegisterDualWriter | nil c2s or nil s2c | Stored with nil field | 178-180 |
| E15 | Engine | RegisterDualWriter | Overwrite existing taskID | Replaces, old writer leaked (no Close) | 178-180 |
| E16 | Engine | RegisterDualWriter | Empty taskID | Stored under "" | 178-180 |
| E17 | Engine | UnregisterDualWriter | Existing taskID | Deletes from map, both writers Closed | 186-198 |
| E18 | Engine | UnregisterDualWriter | Non-existent taskID | ok=false, no Close, returns | 187 |
| E19 | Engine | UnregisterDualWriter | dw=nil in map | No Close (nil check on dw) | 191 |
| E20 | Engine | UnregisterDualWriter | dw.C2S=nil | No panic (nil check) | 192-193 |
| E21 | Engine | UnregisterDualWriter | dw.S2C=nil | No panic (nil check) | 195-196 |
| E22 | Engine | UnregisterDualWriter | dw.C2S.Close panics | S2C never closed | 193 |
| E23 | Engine | GetDualWriter | Existing taskID | Returns writer | 203-205 |
| E24 | Engine | GetDualWriter | Non-existent taskID | Returns nil | 203-205 |

### Start

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E25 | Engine | Start | First call, valid config | All workers started, running=true, channels created | 236-319 |
| E26 | Engine | Start | Double start | Returns "engine already running" | 237-238 |
| E27 | Engine | Start | ConfigWorkers=0 | No config workers created | 257-258 |
| E28 | Engine | Start | PacketWorkers=0 | No packet workers created | 287-288 |
| E29 | Engine | Start | OutputWorkers=0 | No output workers created | 297-298 |
| E30 | Engine | Start | ReplayOrderPreserve=true, PacketWorkers=4 | Clamped to 1 | 284-285 |
| E31 | Engine | Start | ReplayOrderPreserve=true, PacketWorkers=0 | Stays 0 (no workers) | 284-285 |
| E32 | Engine | Start | ReplayOrderPreserve=true, PacketWorkers=1 | Stays 1 | 284-285 |
| E33 | Engine | Start | buildFunc=nil | Default stub used (64 bytes of zeros) | 275-279 |
| E34 | Engine | Start | buildFunc=registered | Registered func used | 274 |
| E35 | Engine | Start | getProcessCPUTime fails | startCPUTime stays 0, doesn't abort | 309-311 |
| E36 | Engine | Start | BufferSize=0 | Zero-size ring buffer (all Puts fail) | 250-254 |
| E37 | Engine | Start | MaxBufferBytes=0 | Unlimited bytes in ring buffer | 250-254 |
| E38 | Engine | Start | QueueSize=0 | Unbuffered channels (synchronous send) | 245-247 |
| E39 | Engine | Start | ConfigWorker.onTaskDone fires with err | Engine.FailTask called | 262-267 |
| E40 | Engine | Start | ConfigWorker.onTaskDone fires with nil err | Engine.SetTaskTotalConfigs called | 262-267 |

### Stop

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E41 | Engine | Stop | Normal stop, all workers running | taskChan+ctx cancelled, workers stopped, wg.Wait, channels closed, buffer+writers closed | 323-394 |
| E42 | Engine | Stop | Already stopped | Returns immediately (running=false) | 324-325 |
| E43 | Engine | Stop | Never started | Returns immediately (running=false) | 324-325 |
| E44 | Engine | Stop | buffer=nil | nil check prevented panic | 355-356 |
| E45 | Engine | Stop | No output writers | Empty loop, no Close | 362-373 |
| E46 | Engine | Stop | Writer in outputWriters is nil | nil check prevents panic | 370-371 |
| E47 | Engine | Stop | No dual writers | Empty loop, no Close | 376-392 |
| E48 | Engine | Stop | Writer.Close panics | Subsequent writers/duals not closed | 370-373 |
| E49 | Engine | Stop | Multiple output writers for same task (duplicate) | Both closed (map iteration) | 362-373 |

### SubmitTask

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E50 | Engine | SubmitTask | Normal single-protocol task | task queued, status="running", return nil | 398-483 |
| E51 | Engine | SubmitTask | Engine not running | Returns "engine not running" | 399-400 |
| E52 | Engine | SubmitTask | Invalid task (name="") | Returns "task validation failed: task name is required" | 404-405 |
| E53 | Engine | SubmitTask | maxTasks=0 (unlimited), 500 tasks | All submitted | 409 |
| E54 | Engine | SubmitTask | maxTasks=5, 5 active, 6th submitted | Returns "max_tasks limit reached" | 409-410 |
| E55 | Engine | SubmitTask | Batch task with per-class BPS | Per-class rate limiters created | 416-430 |
| E56 | Engine | SubmitTask | Batch task, class BPS="" | No rate limiter for that class (continue) | 421 |
| E57 | Engine | SubmitTask | Batch task, class BPS invalid | Returns error, task not submitted | 423-425 |
| E58 | Engine | SubmitTask | Single task, BPS="" | No rate limiter created | 431 |
| E59 | Engine | SubmitTask | Single task, BPS parse error | Returns error | 432-434 |
| E60 | Engine | SubmitTask | Single task, BPS=0 | No rate limiter (bps > 0 check) | 436 |
| E61 | Engine | SubmitTask | Single task, ClassID="" | Uses task.ID as key | 439 |
| E62 | Engine | SubmitTask | Single task, ClassID set | Uses ClassID as key | 438 |
| E63 | Engine | SubmitTask | Batch task, DurationSeconds=0 | No deadline, cancel-only context | 449-452 |
| E64 | Engine | SubmitTask | Batch task, DurationSeconds=10 | Deadline context, auto-cancels after 10s | 450 |
| E65 | Engine | SubmitTask | Task queue full (5s timeout) | Returns "task queue full" | 477-481 |
| E66 | Engine | SubmitTask | Successful submission | Zap log "task submitted" | 471-476 |

### StopTask

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E67 | Engine | StopTask | Existing running task | cancel(), status="stopped", CompletedAt set | 486-501 |
| E68 | Engine | StopTask | Non-existent taskID | Returns "task not found" | 491-492 |
| E69 | Engine | StopTask | Task already completed | deleted from store, returns "not found" | 491-492 |
| E70 | Engine | StopTask | Task already stopped | cancel() again (safe, no-op), status overwritten to "stopped" | 495-496 |
| E71 | Engine | StopTask | entry.cancel=nil | nil dereference -- CRASH | 495 |

### SetTaskTotalConfigs

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E72 | Engine | SetTaskTotalConfigs | Normal: count=100, written=0 | totalConfigs=100, no completion | 508-513 |
| E73 | Engine | SetTaskTotalConfigs | Task not in store | Returns immediately | 509-511 |
| E74 | Engine | SetTaskTotalConfigs | count=0 | Completes immediately (0 configs planned) | 518-531 |
| E75 | Engine | SetTaskTotalConfigs | count=50, writtenPackets=50 | Already complete, fires OnTaskComplete | 518-531 |
| E76 | Engine | SetTaskTotalConfigs | count=50, writtenPackets=60 | Written >= count, completes | 518-531 |
| E77 | Engine | SetTaskTotalConfigs | count=100, written=30 | No completion, stores totalConfigs | 532 |
| E78 | Engine | SetTaskTotalConfigs | OnTaskComplete=nil | Skips callback | 527-528 |
| E79 | Engine | SetTaskTotalConfigs | completion fires | cleanupTaskRateLimiters called | 525 |

### cleanupTaskRateLimiters

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E80 | Engine | cleanupTaskRateLimiters | taskID exists as key | Deleted | 542 |
| E81 | Engine | cleanupTaskRateLimiters | taskID:classID keys exist | All deleted via prefix scan | 544-547 |
| E82 | Engine | cleanupTaskRateLimiters | No rate limiters for task | No-op | 542-548 |

### OnPacketWritten

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E83 | Engine | OnPacketWritten | Normal: written=50, total=100 | Increments, no completion | 554-560 |
| E84 | Engine | OnPacketWritten | Task not in store | Returns | 555-558 |
| E85 | Engine | OnPacketWritten | Task status="stopped" | Returns early, no progress | 562-564 |
| E86 | Engine | OnPacketWritten | written >= totalConfigs | Completes, fires OnTaskComplete | 566-578 |
| E87 | Engine | OnPacketWritten | totalConfigs=0 (not yet set) | No completion check, no progress | 581 |
| E88 | Engine | OnPacketWritten | Progress >= 1% change | Fires OnProgress | 585-590 |
| E89 | Engine | OnPacketWritten | Progress < 1% change | Skips OnProgress | 585 |
| E90 | Engine | OnPacketWritten | Progress hits exactly 100% | Fires OnProgress (newProgress==100) | 585 |
| E91 | Engine | OnPacketWritten | OnProgress=nil | Skips callback | 588-589 |
| E92 | Engine | OnPacketWritten | OnTaskComplete=nil | Skips callback | 575-576 |

### FailTask

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E93 | Engine | FailTask | Normal: running task | status="failed", errMsg set, callbacks fire | 598-631 |
| E94 | Engine | FailTask | Task not in store | Returns | 600-603 |
| E95 | Engine | FailTask | Task already stopped | Returns early (don't overwrite "stopped") | 610-612 |
| E96 | Engine | FailTask | Task already completed (deleted) | "not found" | 601-603 |
| E97 | Engine | FailTask | OnTaskFailed fires | errMsg propagated | 624-625 |
| E98 | Engine | FailTask | OnTaskComplete fires after OnTaskFailed | Both callbacks fire | 628-629 |
| E99 | Engine | FailTask | OnTaskFailed=nil | Skips | 624 |
| E100 | Engine | FailTask | OnTaskComplete=nil | Skips | 628 |

### GetTaskStatus / ActiveTaskCount / RangeTaskStore

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E101 | Engine | GetTaskStatus | Existing task | Returns status | 638-642 |
| E102 | Engine | GetTaskStatus | Non-existent task | Returns error | 640 |
| E103 | Engine | ActiveTaskCount | 0 tasks | Returns 0 | 660-662 |
| E104 | Engine | ActiveTaskCount | 500 tasks | Returns 500 | 660-662 |
| E105 | Engine | RangeTaskStore | fn returns true for all | Iterates all | 648-656 |
| E106 | Engine | RangeTaskStore | fn returns false early | Iteration stops | 652-653 |
| E107 | Engine | RangeTaskStore | fn panics | RLock never released | 649 |

### GetPackets / GetBufferStatus

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E108 | Engine | GetPackets | buffer=nil, any count/mode | Returns nil | 667-668 |
| E109 | Engine | GetPackets | buffer set, count=10, mode="up" | Delegates to buffer.Get | 670 |
| E110 | Engine | GetBufferStatus | buffer=nil | Returns nil | 675-676 |
| E111 | Engine | GetBufferStatus | buffer set | Returns buffer status map | 678 |

### SetClassRateLimit / GetRateLimiter

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E112 | Engine | SetClassRateLimit | bps=1000000 (1Mbps) | rateBytesPerSec=125000, burst=65536 | 687-696 |
| E113 | Engine | SetClassRateLimit | bps=0 | rateBytesPerSec=0, bucket with rate=0 (unlimited) | 687-688 |
| E114 | Engine | SetClassRateLimit | bps=1-7 | rateBytesPerSec=1 (guarded from zero) | 689-691 |
| E115 | Engine | SetClassRateLimit | bps=8 | rateBytesPerSec=1 | 687 |
| E116 | Engine | SetClassRateLimit | classID="" | Empty key (valid) | 693-696 |
| E117 | Engine | SetClassRateLimit | Overwrite existing classID | Replaces bucket, old leaked | 695 |
| E118 | Engine | GetRateLimiter | Existing classID | Returns bucket | 700-703 |
| E119 | Engine | GetRateLimiter | Non-existent classID | Returns nil | 703 |

### GetCPUUsage

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E120 | Engine | GetCPUUsage | Normal, 1 core busy | Returns ~100 | 717-731 |
| E121 | Engine | GetCPUUsage | startWallClock.IsZero() | Returns 0 | 718-719 |
| E122 | Engine | GetCPUUsage | getProcessCPUTime fails | Returns 0 | 722 |
| E123 | Engine | GetCPUUsage | elapsed <= 0 | Returns 0 | 726-727 |
| E124 | Engine | GetCPUUsage | 2 cores busy | Returns ~200 | 729-730 |
| E125 | Engine | GetCPUUsage | Idle engine | Returns ~0 | 729-730 |

### SetMaxTasks

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E126 | Engine | SetMaxTasks | n=10 | maxTasks=10 | 735-738 |
| E127 | Engine | SetMaxTasks | n=0 | maxTasks=0 (unlimited) | 735-738 |
| E128 | Engine | SetMaxTasks | n=-1 | Clamped to 0 | 735-736 |

### writePacketsTo (helper)

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E129 | Engine | writePacketsTo | w implements TimedWriter | Calls WriteTimedPackets | 94-95 |
| E130 | Engine | writePacketsTo | w does not implement TimedWriter | Calls WritePackets (strips timestamp) | 97 |
| E131 | Engine | writePacketsTo | w=nil | nil pointer dereference -- CRASH | 94 |

### GetStats

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E132 | Engine | GetStats | No workers (all zero) | Zeroed stats for all worker types | 749-796 |
| E133 | Engine | GetStats | Workers running | Aggregated stats across all workers | 756-791 |
| E134 | Engine | GetStats | buffer=nil | buffer key=nil | 793 |

### SetFatalError / GetFatalError

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| E135 | Engine | SetFatalError | nil error | Stores nil | 804-805 |
| E136 | Engine | SetFatalError | non-nil error | Stores error | 804-805 |
| E137 | Engine | GetFatalError | No error | Returns nil | 810-812 |
| E138 | Engine | GetFatalError | Error stored | Returns error | 810-811 |

---

## CONFIG WORKER (`worker.go`)

### run()

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| CW1 | ConfigWorker | run | Normal: task received | Acquires sem, spawns goroutine | 106-125 |
| CW2 | ConfigWorker | run | ctx cancelled | Returns (goroutine exits) | 107-108 |
| CW3 | ConfigWorker | run | taskChan closed (!ok) | Returns (goroutine exits) | 109-111 |
| CW4 | ConfigWorker | run | Semaphore at capacity (4) | Blocks until slot freed | 114 |
| CW5 | ConfigWorker | run | Goroutine panics | wg.Done never called (defer only releases sem) | 117-123 |

### processTask

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| CW6 | ConfigWorker | processTask | Batch task (task.Batch!=nil) | Dispatches to processBatchTask | 131-133 |
| CW7 | ConfigWorker | processTask | Normal single-protocol task | Proceeds through protocol lookup | 136-225 |
| CW8 | ConfigWorker | processTask | Unknown protocol | Logs error, fires onTaskDone(err,0) | 143-154 |
| CW9 | ConfigWorker | processTask | Validation fails | Logs error, fires onTaskDone(err,0) | 157-167 |
| CW10 | ConfigWorker | processTask | Planning fails | Logs error, fires onTaskDone(err,0) | 177-187 |
| CW11 | ConfigWorker | processTask | task.Ctx=nil | Falls back to worker context | 171-172 |
| CW12 | ConfigWorker | processTask | task.Ctx=set | Uses task context | 170 |
| CW13 | ConfigWorker | processTask | VLAN in spec, not in config | Propagates spec.VLAN to L2.VLAN | 196-197 |
| CW14 | ConfigWorker | processTask | VLAN already in config | Not overwritten | 196 |
| CW15 | ConfigWorker | processTask | Metadata nil | Initialized to empty map | 199-201 |
| CW16 | ConfigWorker | processTask | Metadata already set | Not re-initialized | 199 |
| CW17 | ConfigWorker | processTask | taskCtx cancelled during forwarding | Drains remaining configs, fires onTaskDone("task cancelled", count) | 206-215 |
| CW18 | ConfigWorker | processTask | Normal completion | Fires onTaskDone(nil, count) | 221-224 |
| CW19 | ConfigWorker | processTask | Zero configs produced | Fires onTaskDone(nil, 0) | 221-224 |
| CW20 | ConfigWorker | processTask | onTaskDone=nil | Skips all callbacks (safe) | 150, 163, 212, 223 |
| CW21 | ConfigWorker | processTask | planner.Plan blocks indefinitely | configChan <- blocks, pipeline stalls | 216 |

### processBatchTask

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| CW22 | ConfigWorker | processBatchTask | Normal: all classes succeed | Configs forwarded, onTaskDone(nil, count) | 234-401 |
| CW23 | ConfigWorker | processBatchTask | task.Ctx=nil | Falls back to worker context | 240-241 |
| CW24 | ConfigWorker | processBatchTask | Zero classes | No-op, classWg.Wait returns, fires onTaskDone(nil,0) | 248, 380 |
| CW25 | ConfigWorker | processBatchTask | Replay class, replayPlanner=nil | Skips, increments flowFailures | 264-268 |
| CW26 | ConfigWorker | processBatchTask | Replay class, replayPlanner set | Calls PlanReplay | 274 |
| CW27 | ConfigWorker | processBatchTask | Replay plan fails | Skips, increments flowFailures | 275-278 |
| CW28 | ConfigWorker | processBatchTask | Replay config forwarding cancelled | Drains remaining, returns | 287-291 |
| CW29 | ConfigWorker | processBatchTask | Unknown protocol class | Skips, increments flowFailures by FlowCount | 300-307 |
| CW30 | ConfigWorker | processBatchTask | BPS="", not propagated | spec.BPS unchanged | 315-316 |
| CW31 | ConfigWorker | processBatchTask | BPS="1M", propagated | spec.BPS="1M" | 315-316 |
| CW32 | ConfigWorker | processBatchTask | Flow validation fails | Skips one flow, increments flowFailures | 328-336 |
| CW33 | ConfigWorker | processBatchTask | Flow planning fails | Skips one flow, increments flowFailures | 338-349 |
| CW34 | ConfigWorker | processBatchTask | Flow config forwarding cancelled | Drains, returns | 365-371 |
| CW35 | ConfigWorker | processBatchTask | All flows failed | onTaskDone("all N flows failed", count) | 391-393 |
| CW36 | ConfigWorker | processBatchTask | Some flows failed, some succeeded | onTaskDone(nil, count) | 398-399 |
| CW37 | ConfigWorker | processBatchTask | Duration deadline exceeded (ctx.DeadlineExceeded) | onTaskDone(nil, count) -- normal completion | 394-395 |
| CW38 | ConfigWorker | processBatchTask | Explicit cancel (ctx.Canceled) | onTaskDone("task cancelled", count) | 396-397 |
| CW39 | ConfigWorker | processBatchTask | Normal completion, no error | onTaskDone(nil, count) | 398-399 |
| CW40 | ConfigWorker | processBatchTask | totalFlows=0 (no classes at all) | all-flows-failed guard not triggered (totalFlows=0, flowFailures=0) | 391-392 |
| CW41 | ConfigWorker | processBatchTask | totalFlows > 0, all failures | Guard triggers correctly | 392-393 |
| CW42 | ConfigWorker | processBatchTask | onTaskDone=nil | Skips all | 390 |

---

## PACKET WORKER (`worker.go`)

### run()

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| PW1 | PacketWorker | run | Normal: config received | processConfig called | 462-471 |
| PW2 | PacketWorker | run | ctx cancelled | Returns | 464-465 |
| PW3 | PacketWorker | run | configChan closed | Returns | 466-468 |

### processConfig

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| PW4 | PacketWorker | processConfig | Normal: build succeeds | Rate limited, sent to packetChan | 477-524 |
| PW5 | PacketWorker | processConfig | buildFunc=nil | Silent return, no error | 477-478 |
| PW6 | PacketWorker | processConfig | Build fails | Error counter, return | 481-489 |
| PW7 | PacketWorker | processConfig | Pacer in Metadata, Wait succeeds | Uses pacer, not token bucket | 495-502 |
| PW8 | PacketWorker | processConfig | Pacer.Wait returns error (ctx cancelled) | Returns without sending | 499-500 |
| PW9 | PacketWorker | processConfig | No pacer, engine!=nil, ClassID!="" | Uses TokenBucket rate limiter | 503-508 |
| PW10 | PacketWorker | processConfig | No pacer, engine!=nil, ClassID="" | No rate limiting | 503 |
| PW11 | PacketWorker | processConfig | No pacer, engine=nil | No rate limiting | 503 |
| PW12 | PacketWorker | processConfig | No limiter found for ClassID | No rate limiting | 503-504 |
| PW13 | PacketWorker | processConfig | TokenBucket.Wait returns err (ctx cancelled) | Returns without sending | 505-506 |
| PW14 | PacketWorker | processConfig | ctx cancelled while sending to packetChan | Returns without sending | 519-520 |
| PW15 | PacketWorker | processConfig | Successfully sent to packetChan | PacketsGenerated counter incremented | 522-523 |
| PW16 | PacketWorker | processConfig | packetChan is full | Blocks until slot available or ctx cancelled | 519-523 |

---

## OUTPUT WORKER (`worker.go`)

### run()

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| OW1 | OutputWorker | run | Normal: packet received | writePacket called | 588-597 |
| OW2 | OutputWorker | run | ctx cancelled | Returns | 589-590 |
| OW3 | OutputWorker | run | packetChan closed | Returns | 591-593 |

### writePacket

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| OW4 | OutputWorker | writePacket | Normal: dual-writer, C2S direction | Writes to C2S writer, buffers, notifies | 610-689 |
| OW5 | OutputWorker | writePacket | engine=nil | Skips writer routing, still buffers | 615 |
| OW6 | OutputWorker | writePacket | out.Metadata=nil | Skips writer routing, still buffers | 615 |
| OW7 | OutputWorker | writePacket | taskID missing from Metadata | Skips writer routing, still buffers | 616 |
| OW8 | OutputWorker | writePacket | DualWriter found, "up"/"c2s" direction | Uses C2S writer | 619 |
| OW9 | OutputWorker | writePacket | DualWriter found, "down"/"s2c" direction | Uses S2C writer | 620-621 |
| OW10 | OutputWorker | writePacket | DualWriter found, empty direction | Uses C2S (default) | 619 |
| OW11 | OutputWorker | writePacket | DualWriter C2S=nil | Skips write (nil check) | 623 |
| OW12 | OutputWorker | writePacket | DualWriter S2C=nil | Skips write (nil check) | 623 |
| OW13 | OutputWorker | writePacket | DualWriter write fails | Error, fires OnOutputError or FailTask+UnregisterDualWriter | 624-632 |
| OW14 | OutputWorker | writePacket | DualWriter write fails, OnOutputError set | Callback fires, no FailTask | 627-628 |
| OW15 | OutputWorker | writePacket | DualWriter write fails, OnOutputError not set | FailTask+UnregisterDualWriter called | 630-631 |
| OW16 | OutputWorker | writePacket | Single writer found | Writes to single writer | 638-656 |
| OW17 | OutputWorker | writePacket | Single writer not found | Skips (no writer for this task) | 638-639 |
| OW18 | OutputWorker | writePacket | Single writer write fails | Error, fires OnOutputError or FailTask+UnregisterOutputWriter | 643-653 |
| OW19 | OutputWorker | writePacket | Single writer write fails, OnOutputError set | Callback fires, no FailTask | 648-649 |
| OW20 | OutputWorker | writePacket | Single writer write fails, OnOutputError not set | FailTask+UnregisterOutputWriter called | 651-652 |
| OW21 | OutputWorker | writePacket | buffer=nil | Skips buffer storage | 669 |
| OW22 | OutputWorker | writePacket | buffer.Put succeeds | Normal flow | 670 |
| OW23 | OutputWorker | writePacket | buffer.Put fails (overflow) | Warns, fires OnBufferOverflow | 670-678 |
| OW24 | OutputWorker | writePacket | buffer overflow, OnBufferOverflow set | Callback fires with taskID | 673-676 |
| OW25 | OutputWorker | writePacket | buffer overflow, OnBufferOverflow not set | Skips callback | 673 |
| OW26 | OutputWorker | writePacket | engine=nil, metadata nil | Skips OnPacketWritten | 685 |
| OW27 | OutputWorker | writePacket | metadata missing task_id | Skips OnPacketWritten | 686 |
| OW28 | OutputWorker | writePacket | OnPacketWritten always fires | Even on buffer overflow | 685-688 |

---

## BUILDER (`builder.go`)

### Build

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| B1 | Builder | Build | TCP config, no VLAN | l2Len=14, l3Len=20, l4Len=20+opts, full packet | 61-97 |
| B2 | Builder | Build | UDP config, no VLAN | l2Len=14, l3Len=20, l4Len=8, full packet | 61-97 |
| B3 | Builder | Build | VLAN present | l2Len=18 | 77-78 |
| B4 | Builder | Build | EtherType=0 (default) | Treated as IPv4, l3Len=20 | 70-71 |
| B5 | Builder | Build | EtherType=ARP (0x0806) | l3Len=0, no IPv4 header | 73-74 |
| B6 | Builder | Build | EtherType=ARP, VLAN present | l2Len=18, l3Len=0 | 73-78 |
| B7 | Builder | Build | ICMP (L4.Protocol=icmp) | l4Len=0, payload carries ICMP data | 107 |
| B8 | Builder | Build | Empty payload | total = l2Len + l3Len + l4Len | 80 |
| B9 | Builder | Build | Empty config (all zeros) | Zero MACs, IPs, Seq=0, handles gracefully | 62-97 |
| B10 | Builder | Build | l3Len=0 (non-IPv4) | writeL3 skipped | 88-89 |
| B11 | Builder | Build | l4Len=0 (ICMP) | writeL4 skipped | 91-92 |
| B12 | Builder | Build | Zero-length packet | make([]byte, 0), no layers written | 80-82 |
| B13 | Builder | Build | L4.Protocol="tcp", TCPOptions present | l4Len includes options | 102-103 |
| B14 | Builder | Build | L4.Protocol="udp" | l4Len=8 | 105 |

### l4Length

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| B15 | Builder | l4Length | "tcp" | 20 + len(encodeTCPOptions(options)) | 102-103 |
| B16 | Builder | l4Length | "udp" | 8 | 105 |
| B17 | Builder | l4Length | "icmp" | 0 | 107 |
| B18 | Builder | l4Length | "" (empty) | 0 (default case) | 107 |

### writeL2

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| B19 | Builder | writeL2 | DstMAC="" | All zeros in dst MAC field | 113-114 |
| B20 | Builder | writeL2 | DstMAC invalid | Warns, zeros in dst MAC field | 114-115 |
| B21 | Builder | writeL2 | DstMAC valid, len=6 | Written to dst[0:6] | 117-118 |
| B22 | Builder | writeL2 | SrcMAC="" | All zeros in src MAC field | 120-121 |
| B23 | Builder | writeL2 | SrcMAC invalid | Warns, zeros in src MAC field | 121-122 |
| B24 | Builder | writeL2 | SrcMAC valid, len=6 | Written to dst[6:12] | 124-125 |
| B25 | Builder | writeL2 | EtherType=0 | Defaults to EtherTypeIPv4 (0x0800) | 128-129 |
| B26 | Builder | writeL2 | EtherType=0x0806 | Uses ARP ethertype | 128-129 |
| B27 | Builder | writeL2 | VLAN present | 802.1Q tag: TPID=0x8100, tag+EtherType | 131-136 |
| B28 | Builder | writeL2 | VLAN with priority=7 | Priority encoded in tag bits 15-13 | 134 |
| B29 | Builder | writeL2 | VLAN with ID=4095 | Max ID in tag | 134 |
| B30 | Builder | writeL2 | No VLAN | Standard EtherType at offset 12 | 138 |

### writeL3

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| B31 | Builder | writeL3 | Normal config | Version=4, IHL=5, checksum computed | 143-185 |
| B32 | Builder | writeL3 | IPID=0 | Falls back to config.L4.Seq & 0xFFFF | 149-150 |
| B33 | Builder | writeL3 | IPID=0x1234 | Uses IPID directly | 148 |
| B34 | Builder | writeL3 | TTL=0 | Defaults to 64 | 156-157 |
| B35 | Builder | writeL3 | TTL=255 | Uses 255 | 155 |
| B36 | Builder | writeL3 | SrcIP="" | 0.0.0.0 in header | 162-163 |
| B37 | Builder | writeL3 | SrcIP invalid | Warns, zeros | 163-164 |
| B38 | Builder | writeL3 | SrcIP valid IPv4 | Written to dst[12:16] | 166-170 |
| B39 | Builder | writeL3 | SrcIP is IPv6 | To4() returns nil, skipped | 167-168 |
| B40 | Builder | writeL3 | DstIP="" | 0.0.0.0 in header | 172-173 |
| B41 | Builder | writeL3 | DstIP invalid | Warns, zeros | 173-174 |
| B42 | Builder | writeL3 | DstIP valid IPv4 | Written to dst[16:20] | 176-180 |
| B43 | Builder | writeL3 | DstIP is IPv6 | To4() returns nil, skipped | 177-178 |
| B44 | Builder | writeL3 | DSCP=63, ECN=3 | Combined in byte 1 | 145 |
| B45 | Builder | writeL3 | Flags=0x2 (DF), FragOffset=0 | Encoded in bytes 6-7 | 153 |
| B46 | Builder | writeL3 | Protocol=6 (TCP) | Written to byte 9 | 160 |
| B47 | Builder | writeL3 | Protocol=17 (UDP) | Written to byte 9 | 160 |

### L3Base

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| B48 | Builder | L3Base | Flags=0, FragOffset=0 | Default DF flag set | 37-38 |
| B49 | Builder | L3Base | Flags=0x01, FragOffset=0 | Uses explicit flags (no default DF) | 37 |
| B50 | Builder | L3Base | Flags=0, FragOffset=0x100 | Uses explicit frag offset (no DF) | 37 |
| B51 | Builder | L3Base | spec.TOS=0 | DSCP/ECN from spec.DSCP/ECN | 51 |
| B52 | Builder | L3Base | spec.TOS=0x80 | Overrides DSCP/ECN from TOS byte | 52-53 |

### writeTCP

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| B53 | Builder | writeTCP | WindowSize=0 | Defaults to 65535 | 211-212 |
| B54 | Builder | writeTCP | WindowSize=65535 | Use as-is | 210 |
| B55 | Builder | writeTCP | No TCP options | dataOffset=5, no options in header | 200-201 |
| B56 | Builder | writeTCP | TCP options present | dataOffset=(20+len(opts))/4, options appended | 200-201, 216 |
| B57 | Builder | writeTCP | Checksum computed | Pseudo-header + TCP header + payload | 219 |
| B58 | Builder | writeTCP | Urgent pointer | Always 0 (not configurable) | 215 |

### writeUDP

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| B59 | Builder | writeUDP | Normal | 8-byte header, length = 8+payload | 224-230 |
| B60 | Builder | writeUDP | Zero-length payload | Length=8 | 227 |
| B61 | Builder | writeUDP | Checksum computed | Pseudo-header + UDP header + payload | 228 |

### encodeTCPOptions

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| B62 | Builder | encodeTCPOptions | Empty options | Empty buffer, then NOP-padded to 4-byte (or empty if already aligned) | 236-249 |
| B63 | Builder | encodeTCPOptions | Kind=0 (End) | Single byte, no length | 238-239 |
| B64 | Builder | encodeTCPOptions | Kind=1 (NOP) | Single byte, no length | 238-239 |
| B65 | Builder | encodeTCPOptions | Regular option | Kind + Length(2+len(Data)) + Data | 242-244 |
| B66 | Builder | encodeTCPOptions | Options not 4-byte aligned | NOP padding appended | 246-248 |
| B67 | Builder | encodeTCPOptions | Multiple options | All serialized in order | 237-244 |
| B68 | Builder | encodeTCPOptions | Kind=2 (MSS) with 2-byte data | 0x02 0x04 + data | 242-244 |

### calculateTCPChecksum

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| B69 | Builder | calculateTCPChecksum | Normal TCP | Correct checksum returned | 267-335 |
| B70 | Builder | calculateTCPChecksum | SrcIP="" | Zeros in pseudo-header | 273-274 |
| B71 | Builder | calculateTCPChecksum | SrcIP invalid | Warns, zeros | 273-274 |
| B72 | Builder | calculateTCPChecksum | DstIP="" | Zeros in pseudo-header | 284-285 |
| B73 | Builder | calculateTCPChecksum | DstIP invalid | Warns, zeros | 285-286 |
| B74 | Builder | calculateTCPChecksum | Odd-length payload | Last byte shifted left 8 | 327-328 |
| B75 | Builder | calculateTCPChecksum | Even-length payload | Normal pair processing | 324-325 |
| B76 | Builder | calculateTCPChecksum | Checksum field skipped | Offset 16 skipped in header loop | 315-316 |
| B77 | Builder | calculateTCPChecksum | Header < 18 bytes | Bound check prevents panic | 318-319 |

### calculateUDPChecksum

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| B78 | Builder | calculateUDPChecksum | Normal UDP | Correct checksum returned | 338-403 |
| B79 | Builder | calculateUDPChecksum | SrcIP="" | Zeros in pseudo-header | 344-345 |
| B80 | Builder | calculateUDPChecksum | SrcIP invalid | Warns, zeros | 344-345 |
| B81 | Builder | calculateUDPChecksum | DstIP="" | Zeros in pseudo-header | 354-355 |
| B82 | Builder | calculateUDPChecksum | DstIP invalid | Warns, zeros | 355-356 |
| B83 | Builder | calculateUDPChecksum | Odd-length payload | Last byte shifted left 8 | 395-396 |
| B84 | Builder | calculateUDPChecksum | Even-length payload | Normal pair processing | 392-393 |
| B85 | Builder | calculateUDPChecksum | IPv6 srcIP | To4() returns nil, pseudo-header zeros | 348-349 |

---

## RING BUFFER (`buffer.go`)

### NewRingBuffer

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| RB1 | RingBuffer | NewRingBuffer | size=1024, maxBytes=0 | Unlimited bytes, 1024 slots | 25-31 |
| RB2 | RingBuffer | NewRingBuffer | size=0 | No slots, every Put fails | 27 |
| RB3 | RingBuffer | NewRingBuffer | size=-1 | Panic: make([][]byte, -1) -- CRASH | 27 |

### Put

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| RB4 | RingBuffer | Put | Normal: slot available | Appended, returns true | 34-61 |
| RB5 | RingBuffer | Put | Buffer closed | Returns false | 35-36 |
| RB6 | RingBuffer | Put | Buffer full (count >= size) | Returns false | 43-44 |
| RB7 | RingBuffer | Put | Byte limit exceeded (maxBytes > 0) | Returns false | 48-49 |
| RB8 | RingBuffer | Put | maxBytes=0 | No byte limit check | 48 |
| RB9 | RingBuffer | Put | Exactly fills the buffer | tail wraps to 0 | 56 |
| RB10 | RingBuffer | Put | nil packet | Stored, count increments, bytes unchanged (len(nil)==0) | 55-58 |
| RB11 | RingBuffer | Put | Concurrent Put/Get | Thread-safe via mutex | 39-40 |

### Get

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| RB12 | RingBuffer | Get | Normal: non-empty | Returns packet, true | 64-83 |
| RB13 | RingBuffer | Get | Buffer closed | Returns nil, false | 65-66 |
| RB14 | RingBuffer | Get | Buffer empty | Returns nil, false | 72-73 |
| RB15 | RingBuffer | Get | Wrap-around (head at end) | head wraps to 0 | 78 |
| RB16 | RingBuffer | Get | Slot freed for GC | buffer[head] set to nil | 77 |

### GetBatch

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| RB17 | RingBuffer | GetBatch | Normal: max < count | Returns max packets | 86-113 |
| RB18 | RingBuffer | GetBatch | Buffer closed | Returns nil | 87-88 |
| RB19 | RingBuffer | GetBatch | Buffer empty | Returns nil | 94-95 |
| RB20 | RingBuffer | GetBatch | max > count | Returns all (capped at count) | 99-100 |
| RB21 | RingBuffer | GetBatch | max == count | Returns all | 99-100 |
| RB22 | RingBuffer | GetBatch | max = 0 | Returns empty slice | 98-99 |
| RB23 | RingBuffer | GetBatch | max < 0 | n = min(negative, count) = negative, make([][]byte, negative) -- CRASH | 98-99 |
| RB24 | RingBuffer | GetBatch | Wrap-around during batch | Sequential slots, head wraps | 106-107 |
| RB25 | RingBuffer | GetBatch | Concurrent Put/GetBatch | Thread-safe | 91-92 |

### Len / Bytes / IsFull / Status / Close

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| RB26 | RingBuffer | Len | Empty | 0 | 116-119 |
| RB27 | RingBuffer | Len | 500 packets | 500 | 119 |
| RB28 | RingBuffer | Bytes | Empty | 0 | 123-126 |
| RB29 | RingBuffer | Bytes | 1000 bytes total | 1000 | 126 |
| RB30 | RingBuffer | IsFull | Empty | false | 137 |
| RB31 | RingBuffer | IsFull | 100% full | true | 138 |
| RB32 | RingBuffer | Status | Normal | count, size, bytes, max_bytes, full | 142-152 |
| RB33 | RingBuffer | Close | Open | closed=true | 131 |
| RB34 | RingBuffer | Close | Already closed | No-op (atomic store) | 131 |

---

## PACKET BUFFER (`buffer.go`)

### NewPacketBuffer

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| PB1 | PacketBuffer | NewPacketBuffer | All enabled | Three ring buffers created | 175-193 |
| PB2 | PacketBuffer | NewPacketBuffer | Up disabled | upBuffer=nil | 182-183 |
| PB3 | PacketBuffer | NewPacketBuffer | Down disabled | downBuffer=nil | 185-186 |
| PB4 | PacketBuffer | NewPacketBuffer | Combined disabled | combinedBuffer=nil | 188-189 |
| PB5 | PacketBuffer | NewPacketBuffer | All disabled | Three nil buffers | 182-189 |

### Put

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| PB6 | PacketBuffer | Put | direction="up", all enabled | upBuffer.Put + combinedBuffer.Put | 203-208 |
| PB7 | PacketBuffer | Put | direction="down", all enabled | downBuffer.Put + combinedBuffer.Put | 210-215 |
| PB8 | PacketBuffer | Put | direction="default"/other | combinedBuffer.Put only | 218-219 |
| PB9 | PacketBuffer | Put | direction="up", up disabled | combinedBuffer.Put only, success=false | 204-205 |
| PB10 | PacketBuffer | Put | direction="down", down disabled | combinedBuffer.Put only, success=false | 211-212 |
| PB11 | PacketBuffer | Put | direction="up", combined disabled | upBuffer.Put only, success tracks up | 203-208 |
| PB12 | PacketBuffer | Put | direction="default", combined disabled | No write at all, returns false | 218-219 |
| PB13 | PacketBuffer | Put | direction="up", upBuffer=nil | nil check, combinedBuffer.Put still runs | 204-205 |
| PB14 | PacketBuffer | Put | direction="up", upBuffer full | up fails, combined may succeed | 203-208 |
| PB15 | PacketBuffer | Put | upBuffer.Put fails, combinedBuffer.Put succeeds | Returns false (success tracks primary) | 203-208 |
| PB16 | PacketBuffer | Put | upBuffer.Put succeeds, combinedBuffer.Put fails | Returns true (success tracked primary) | 203-208 |

### Get

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| PB17 | PacketBuffer | Get | mode="up", enabled | Returns upBuffer.GetBatch(count) | 233-235 |
| PB18 | PacketBuffer | Get | mode="down", enabled | Returns downBuffer.GetBatch(count) | 237-239 |
| PB19 | PacketBuffer | Get | mode="combined", enabled | Returns combinedBuffer.GetBatch(count) | 241-243 |
| PB20 | PacketBuffer | Get | mode="up", disabled | buffer=nil, returns nil | 234-235, 247-248 |
| PB21 | PacketBuffer | Get | mode="unknown" | buffer=nil, returns nil | 247-248 |
| PB22 | PacketBuffer | Get | mode="up", buffer empty | empty slice from GetBatch | 251 |

### Status / Close

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| PB23 | PacketBuffer | Status | All enabled | Three status submaps | 256-272 |
| PB24 | PacketBuffer | Status | Up disabled | No up status | 261-262 |
| PB25 | PacketBuffer | Status | All disabled | Empty map | 261-269 |
| PB26 | PacketBuffer | Close | All buffers exist | All three closed | 275-288 |
| PB27 | PacketBuffer | Close | upBuffer=nil | Skipped | 279-280 |
| PB28 | PacketBuffer | Close | combinedBuffer=nil | Skipped | 285-286 |

---

## TOKEN BUCKET (`buffer.go`)

### NewTokenBucket

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| TB1 | TokenBucket | NewTokenBucket | rate=1000, burst=65536 | tokens=65536, lastTime=now | 300-307 |
| TB2 | TokenBucket | NewTokenBucket | rate=0 | Initially unlimited | 301 |

### Allow

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| TB3 | TokenBucket | Allow | rate=0, any n | Always returns true | 315-316 |
| TB4 | TokenBucket | Allow | Enough tokens | Tokens consumed, returns true | 329-331 |
| TB5 | TokenBucket | Allow | Not enough tokens | Returns false | 334 |
| TB6 | TokenBucket | Allow | Tokens exceed burst | Capped to burst | 325-326 |
| TB7 | TokenBucket | Allow | First call after long idle | Large token addition, capped to burst | 319-326 |
| TB8 | TokenBucket | Allow | n=0 | Always returns true (tokens >= 0) | 329 |
| TB9 | TokenBucket | Allow | n > burst | Can never succeed from empty -- returns false | 329 |
| TB10 | TokenBucket | Allow | n > burst, bucket full | Succeeds once, then empty | 329-331 |
| TB11 | TokenBucket | Allow | Negative elapsed time (clock skew) | tokens decreases (negative addition), then checked | 320-324 |
| TB12 | TokenBucket | Allow | Very large elapsed time * rate | Potential int64 overflow | 324 |

### Wait

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| TB13 | TokenBucket | Wait | Normal: eventually allowed | Returns nil | 339-351 |
| TB14 | TokenBucket | Wait | Allow succeeds immediately | Returns nil | 340-341 |
| TB15 | TokenBucket | Wait | ctx cancelled | Returns ctx.Err() | 344-345 |
| TB16 | TokenBucket | Wait | 10ms polling loop | Retries every 10ms | 347 |

### SetRate

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| TB17 | TokenBucket | SetRate | rate=50000 | Updates rate | 355-357 |
| TB18 | TokenBucket | SetRate | rate=0 | Disables limiting | 355-357 |

---

## TUPLE GENERATOR (`tuple_generator.go`)

### Next

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| TG1 | TupleGenerator | Next | Empty config, index=0 | "", "", 0, 0 | 25-31 |
| TG2 | TupleGenerator | Next | Valid config, index=0 | First values | 25-31 |
| TG3 | TupleGenerator | Next | index=negative | Negative index used in all sub-functions | 25-31 |

### genIP

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| TG4 | | genIP | strategy="fixed", Value=string | Returns string | 37-38 |
| TG5 | | genIP | strategy="fixed", Value=non-string | Returns "" | 39-40 |
| TG6 | | genIP | strategy="" (default) | Same as "fixed" | 36 |
| TG7 | | genIP | strategy="list", non-empty | Cycles via index%len | 42-44 |
| TG8 | | genIP | strategy="list", empty list | Returns "" | 42-43 |
| TG9 | | genIP | strategy="inc", Range=[2] | Returns "" (range < 2) | 47-48 |
| TG10 | | genIP | strategy="inc", start invalid | Returns "" | 50-52 |
| TG11 | | genIP | strategy="inc", end < start | Returns "" | 52 |
| TG12 | | genIP | strategy="inc", valid | Computes u32ToIP(start + offset) | 55-60 |
| TG13 | | genIP | strategy="inc", step=0 | Defaults to 1 | 57-58 |
| TG14 | | genIP | strategy="inc", step=0 | Step defaults to 1 | 57-58 |
| TG15 | | genIP | strategy="inc", large index | Wraps via modulo | 60 |
| TG16 | | genIP | strategy="inc", start+offset overflow uint32 | Wraps (silent) | 60 |
| TG17 | | genIP | strategy="rand", Range=[2] | Returns "" | 63-64 |
| TG18 | | genIP | strategy="rand", start invalid | Returns "" | 66-68 |
| TG19 | | genIP | strategy="rand", end < start | Returns "" | 68 |
| TG20 | | genIP | strategy="rand", valid | Random within range, seeded with Seed+index | 71-72 |
| TG21 | | genIP | strategy="rand", Seed=0 | Reproducible per index | 71 |
| TG22 | | genIP | default strategy | Returns "" | 74 |

### genPort

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| TG23 | | genPort | strategy="fixed", float64 value | toPort(float64) | 82 |
| TG24 | | genPort | strategy="fixed", int value | toPort(int) | 82 |
| TG25 | | genPort | strategy="fixed", nil value | 0 | 82 |
| TG26 | | genPort | strategy="" (default) | Same as "fixed" | 81 |
| TG27 | | genPort | strategy="list", non-empty | Cycles via index%len | 84-86 |
| TG28 | | genPort | strategy="list", empty list | 0 | 84-85 |
| TG29 | | genPort | strategy="inc", Range=[2] | 0 | 89-90 |
| TG30 | | genPort | strategy="inc", end < start | 0 | 94 |
| TG31 | | genPort | strategy="inc", step=0 | Defaults to 1 | 99-100 |
| TG32 | | genPort | strategy="inc", large index | Wraps via modulo | 102 |
| TG33 | | genPort | strategy="inc", valid | Computes start + (index*step)%count | 102 |
| TG34 | | genPort | strategy="rand", Range=[2] | 0 | 104-105 |
| TG35 | | genPort | strategy="rand", end < start | 0 | 109 |
| TG36 | | genPort | strategy="rand", valid | Random within range, seeded | 112-113 |
| TG37 | | genPort | default strategy | 0 | 115 |

### ipToU32

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| TG38 | | ipToU32 | "192.168.1.1" | 0xC0A80101, true | 120-134 |
| TG39 | | ipToU32 | "invalid" (not 4 parts) | 0, false | 122-123 |
| TG40 | | ipToU32 | "256.0.0.1" | 0, false | 128 |
| TG41 | | ipToU32 | "10.0.0.999" | 0, false | 128 |

### toPort

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| TG42 | | toPort | float64(8080) | 8080 | 144 |
| TG43 | | toPort | float64(70000) | Overflow: 70000%65536 = 4464 | 144 |
| TG44 | | toPort | int(80) | 80 | 146 |
| TG45 | | toPort | string("443") | 443 | 148-149 |
| TG46 | | toPort | string("invalid") | 0 (parse error) | 149 |
| TG47 | | toPort | nil | 0 | 152 |

### asString

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| TG48 | | asString | string("hello") | "hello" | 158 |
| TG49 | | asString | float64(42) | "42" | 160 |
| TG50 | | asString | nil | "<nil>" | 163 |

---

## VALIDATION (`validate.go`)

### ValidateConfigRanges

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| V1 | Validate | ValidateConfigRanges | All valid (0-63, 0-3, etc.) | nil | 12-48 |
| V2 | Validate | ValidateConfigRanges | dscp=-1 | "dscp -1 invalid" | 12-13 |
| V3 | Validate | ValidateConfigRanges | dscp=64 | "dscp 64 invalid" | 12-13 |
| V4 | Validate | ValidateConfigRanges | ecn=-1 | "ecn -1 invalid" | 15-16 |
| V5 | Validate | ValidateConfigRanges | ecn=4 | "ecn 4 invalid" | 15-16 |
| V6 | Validate | ValidateConfigRanges | vlan_id=-1 | "vlan_id -1 invalid" | 18-19 |
| V7 | Validate | ValidateConfigRanges | vlan_id=4096 | "vlan_id 4096 invalid" | 18-19 |
| V8 | Validate | ValidateConfigRanges | vlan_priority=-1 | "vlan_priority -1 invalid" | 21-22 |
| V9 | Validate | ValidateConfigRanges | vlan_priority=8 | "vlan_priority 8 invalid" | 21-22 |
| V10 | Validate | ValidateConfigRanges | flags=-1 | "flags -1 invalid" | 26-27 |
| V11 | Validate | ValidateConfigRanges | flags=8 | "flags 8 invalid" | 26-27 |
| V12 | Validate | ValidateConfigRanges | frag_offset=-1 | "frag_offset -1 invalid" | 30-31 |
| V13 | Validate | ValidateConfigRanges | frag_offset=8192 | "frag_offset 8192 invalid" | 30-31 |
| V14 | Validate | ValidateConfigRanges | ttl=-1 | "ttl -1 invalid" | 34-35 |
| V15 | Validate | ValidateConfigRanges | ttl=256 | "ttl 256 invalid" | 34-35 |
| V16 | Validate | ValidateConfigRanges | tos=-1 | "tos -1 invalid" | 37-38 |
| V17 | Validate | ValidateConfigRanges | tos=256 | "tos 256 invalid" | 37-38 |
| V18 | Validate | ValidateConfigRanges | src_port=-1 | "src_port -1 invalid" | 42-43 |
| V19 | Validate | ValidateConfigRanges | src_port=65536 | "src_port 65536 invalid" | 42-43 |
| V20 | Validate | ValidateConfigRanges | dst_port=-1 | "dst_port -1 invalid" | 45-46 |
| V21 | Validate | ValidateConfigRanges | dst_port=65536 | "dst_port 65536 invalid" | 45-46 |
| V22 | Validate | ValidateConfigRanges | Missing fields | getInt returns 0, all pass (0 is in range) | 12-48 |

### ValidateProtocolSubConfigs

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| V23 | Validate | ValidateProtocolSubConfigs | protocol="tcp", valid sub | nil | 59-66 |
| V24 | Validate | ValidateProtocolSubConfigs | protocol="tcp", mss=-1 | "tcp.mss -1 invalid" | 60-61 |
| V25 | Validate | ValidateProtocolSubConfigs | protocol="tcp", mss=65536 | "tcp.mss 65536 invalid" | 60-61 |
| V26 | Validate | ValidateProtocolSubConfigs | protocol="tcp", window_size=-1 | "tcp.window_size -1 invalid" | 63-64 |
| V27 | Validate | ValidateProtocolSubConfigs | protocol="tcp", no tcp sub | Skipped (ok=false) | 59 |
| V28 | Validate | ValidateProtocolSubConfigs | protocol="dns", query_type=-1 | "dns.query_type -1 invalid" | 69-70 |
| V29 | Validate | ValidateProtocolSubConfigs | protocol="dns", query_type=65536 | "dns.query_type 65536 invalid" | 69-70 |
| V30 | Validate | ValidateProtocolSubConfigs | protocol="icmp", type=-1 | "icmp.type -1 invalid" | 75-76 |
| V31 | Validate | ValidateProtocolSubConfigs | protocol="icmp", type=256 | "icmp.type 256 invalid" | 75-76 |
| V32 | Validate | ValidateProtocolSubConfigs | protocol="icmp", code=-1 | "icmp.code -1 invalid" | 78-79 |
| V33 | Validate | ValidateProtocolSubConfigs | protocol="icmp", code=256 | "icmp.code 256 invalid" | 78-79 |
| V34 | Validate | ValidateProtocolSubConfigs | protocol="icmp", sequence=-1 | "icmp.sequence -1 invalid" | 81-82 |
| V35 | Validate | ValidateProtocolSubConfigs | protocol="icmp", sequence=65536 | "icmp.sequence 65536 invalid" | 81-82 |
| V36 | Validate | ValidateProtocolSubConfigs | protocol="arp", operation=-1 | "arp.operation -1 invalid" | 87-88 |
| V37 | Validate | ValidateProtocolSubConfigs | protocol="arp", operation=65536 | "arp.operation 65536 invalid" | 87-88 |
| V38 | Validate | ValidateProtocolSubConfigs | protocol="http" | nil (no validation) | 92-93 |
| V39 | Validate | ValidateProtocolSubConfigs | protocol="unknown" | nil (no switch case) | 95 |
| V40 | Validate | ValidateProtocolSubConfigs | sub exists but wrong type | ok=false, no validation | 59 |

### ValidateFlowSpec

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| V41 | Validate | ValidateFlowSpec | Empty spec (all zero/empty) | nil | 103-152 |
| V42 | Validate | ValidateFlowSpec | SrcIP invalid | "invalid src_ip" | 104-106 |
| V43 | Validate | ValidateFlowSpec | SrcIP valid | nil | 104-106 |
| V44 | Validate | ValidateFlowSpec | DstIP invalid | "invalid dst_ip" | 109-111 |
| V45 | Validate | ValidateFlowSpec | DstIP valid | nil | 109-111 |
| V46 | Validate | ValidateFlowSpec | SrcMAC invalid | "invalid src_mac" | 116-118 |
| V47 | Validate | ValidateFlowSpec | SrcMAC valid | nil | 116-118 |
| V48 | Validate | ValidateFlowSpec | DstMAC invalid | "invalid dst_mac" | 121-123 |
| V49 | Validate | ValidateFlowSpec | DstMAC valid | nil | 121-123 |
| V50 | Validate | ValidateFlowSpec | VLAN=nil | Skipped | 128 |
| V51 | Validate | ValidateFlowSpec | VLAN.ID=5000 | "vlan_id 5000 invalid" | 129-130 |
| V52 | Validate | ValidateFlowSpec | VLAN.ID=4095 | nil (valid) | 129-130 |
| V53 | Validate | ValidateFlowSpec | VLAN.Priority=8 | "vlan_priority 8 invalid" | 132-133 |
| V54 | Validate | ValidateFlowSpec | DSCP=64 | "dscp 64 invalid" | 138-139 |
| V55 | Validate | ValidateFlowSpec | DSCP=0 | nil (valid) | 138-139 |
| V56 | Validate | ValidateFlowSpec | ECN=4 | "ecn 4 invalid" | 141-142 |
| V57 | Validate | ValidateFlowSpec | TCP=nil | no MSS check | 147 |
| V58 | Validate | ValidateFlowSpec | TCP.MSS=0 | nil (use default) | 147 |
| V59 | Validate | ValidateFlowSpec | TCP.MSS=100 | "mss 100 too small (must be 0 or >= 536)" | 147-148 |
| V60 | Validate | ValidateFlowSpec | TCP.MSS=536 | nil (minimum valid) | 147-148 |
| V61 | Validate | ValidateFlowSpec | TCP.MSS=1460 | nil (valid) | 147-148 |

### ValidateTask

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| V62 | Validate | ValidateTask | Valid TCP task | nil | 94-122 |
| V63 | Validate | ValidateTask | Name="" | "task name is required" | 95-96 |
| V64 | Validate | ValidateTask | Batch task | Delegates to ValidateBatchSpec | 100-101 |
| V65 | Validate | ValidateTask | Invalid protocol "xyz" | "invalid protocol: xyz" | 113-114 |
| V66 | Validate | ValidateTask | Protocol="tcp", spec invalid | Wraps ValidateFlowSpec error | 117-118 |
| V67 | Validate | ValidateTask | Protocol="" | "invalid protocol: " (not in map) | 113-114 |

### ValidateBatchSpec

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| V68 | Validate | ValidateBatchSpec | Valid batch | nil | 125-174 |
| V69 | Validate | ValidateBatchSpec | Empty classes | "batch must contain at least one traffic class" | 126-127 |
| V70 | Validate | ValidateBatchSpec | Duplicate class ID | "class[N] X: duplicate class id" | 138-139 |
| V71 | Validate | ValidateBatchSpec | Class ID="" | "class[N]: id is required" | 135-136 |
| V72 | Validate | ValidateBatchSpec | Invalid type "xyz" | "class[N] X: invalid type xyz" | 142-143 |
| V73 | Validate | ValidateBatchSpec | Replay class, valid | Passes through | 147-154 |
| V74 | Validate | ValidateBatchSpec | Replay class, missing spec | "class[N] X: replay class missing 'replay' spec" | 148-149 |
| V75 | Validate | ValidateBatchSpec | Replay class, invalid spec | Wraps validateReplaySpec error | 151-152 |
| V76 | Validate | ValidateBatchSpec | FlowCount=0 | "class[N] X: flow_count must be > 0" | 156-157 |
| V77 | Validate | ValidateBatchSpec | FlowCount=-1 | "class[N] X: flow_count must be > 0" | 156-157 |
| V78 | Validate | ValidateBatchSpec | Config ranges invalid | Wraps ValidateConfigRanges error | 161-162 |
| V79 | Validate | ValidateBatchSpec | Sub-config invalid | Wraps ValidateProtocolSubConfigs error | 165-166 |
| V80 | Validate | ValidateBatchSpec | FlowSpec invalid | Wraps ValidateFlowSpec error | 170-171 |
| V81 | Validate | ValidateBatchSpec | Replay class, FlowCount ignored | FlowCount not checked for replay | 156 |

### validateReplaySpec

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| V82 | Validate | validateReplaySpec | Valid: all fields present | nil | 181-224 |
| V83 | Validate | validateReplaySpec | Invalid JSON | "invalid replay spec JSON" | 193-194 |
| V84 | Validate | validateReplaySpec | pcap_asset_id="" | "replay spec missing pcap_asset_id" | 196-197 |
| V85 | Validate | validateReplaySpec | Speed mode "original" | nil | 200 |
| V86 | Validate | validateReplaySpec | Speed mode "multiplier" | nil | 200 |
| V87 | Validate | validateReplaySpec | Speed mode "bps" | nil | 200 |
| V88 | Validate | validateReplaySpec | Speed mode "pps" | nil | 200 |
| V89 | Validate | validateReplaySpec | Speed mode "max" | nil | 200 |
| V90 | Validate | validateReplaySpec | Speed mode "" | nil | 200-201 |
| V91 | Validate | validateReplaySpec | Speed mode "bogus" | "invalid speed mode" | 203 |
| V92 | Validate | validateReplaySpec | bps mode, no BPS value | "bps mode requires a bps value" | 205-206 |
| V93 | Validate | validateReplaySpec | pps mode, PPS=0 | "pps mode requires pps > 0" | 208-209 |
| V94 | Validate | validateReplaySpec | pps mode, PPS=-1 | "pps mode requires pps > 0" | 208-209 |
| V95 | Validate | validateReplaySpec | Direction "single" | nil | 212 |
| V96 | Validate | validateReplaySpec | Direction "dual" | nil | 212 |
| V97 | Validate | validateReplaySpec | Direction "" | nil | 212-213 |
| V98 | Validate | validateReplaySpec | Direction "bogus" | "invalid direction" | 215 |
| V99 | Validate | validateReplaySpec | ChecksumMode "recompute" | nil | 218 |
| V100 | Validate | validateReplaySpec | ChecksumMode "preserve" | nil | 218 |
| V101 | Validate | validateReplaySpec | ChecksumMode "" | nil | 218-219 |
| V102 | Validate | validateReplaySpec | ChecksumMode "bogus" | "invalid checksum_mode" | 221 |

---

## CONVERT (`convert.go`)

### generateTaskID

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| SC1 | Convert | generateTaskID | Always | "task-" + 16 hex chars | 14-16 |

### APIRequestToTask

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| SC2 | Convert | APIRequestToTask | All fields provided | Task with ID, name, desc, protocol, spec, iface | 20-29 |
| SC3 | Convert | APIRequestToTask | Empty strings | All empty except auto-generated ID | 20-29 |

### ParseBPS

| # | Component | Function | Input | Expected | Code branch |
|---|-----------|----------|-------|----------|-------------|
| SC4 | Convert | ParseBPS | "" | 0, nil | 62-63 |
| SC5 | Convert | ParseBPS | "100k" | 100000, nil | 70-71 |
| SC6 | Convert | ParseBPS | "100K" | 100000, nil | 70-71 |
| SC7 | Convert | ParseBPS | "1M" | 1000000, nil | 74-75 |
| SC8 | Convert | ParseBPS | "1m" | 1000000, nil | 74-75 |
| SC9 | Convert | ParseBPS | "1G" | 1000000000, nil | 78-79 |
| SC10 | Convert | ParseBPS | "1g" | 1000000000, nil | 78-79 |
| SC11 | Convert | ParseBPS | "100" (no suffix) | 100, nil | 67-68 |
| SC12 | Convert | ParseBPS | "abc" | 0, error | 83 |
| SC13 | Convert | ParseBPS | "1kk" | Strips 'k' -> "1k", then ParseInt("1k") fails -> error | 71, 83 |
| SC14 | Convert | ParseBPS | "0" | 0, nil | 83 |
| SC15 | Convert | ParseBPS | "1.5M" | ParseInt("1.5") fails -> error | 83 |

---

## CONCURRENCY / RACE CONDITIONS (cross-cutting)

| # | Component | Description | Impact |
|---|-----------|-------------|--------|
| RC1 | Engine | `taskStore` accessed from ConfigWorker (onTaskDone), OutputWorker (OnPacketWritten), Engine API (StopTask, GetTaskStatus) -- protected by taskMu mutex | Safe |
| RC2 | Engine | `outputWriters` accessed from OutputWorker (read) and Register/Unregister (write) -- protected by outputMu | Safe |
| RC3 | Engine | `dualWriters` accessed from OutputWorker (read via GetDualWriter) and Register/Unregister -- protected by outputMu | Safe |
| RC4 | Engine | `rateLimiters` accessed from PacketWorker (read via GetRateLimiter) and SubmitTask/cleanup (write) -- protected by rateMu | Safe |
| RC5 | Engine | `running` atomic.Bool -- safe | Safe |
| RC6 | Engine | `fatalError` atomic.Value -- safe | Safe |
| RC7 | Engine | `maxTasks` atomic.Int64 -- safe | Safe |
| RC8 | ConfigWorker | `stats` accessed from worker goroutine and GetStats -- protected by atomic | Safe |
| RC9 | ConfigWorker | `configChan` write from multiple goroutines (processTask, processBatchTask) -- channel is concurrent-safe | Safe |
| RC10 | PacketWorker | `stats` accessed from worker goroutine and GetStats -- protected by atomic | Safe |
| RC11 | OutputWorker | `stats` accessed from worker goroutine and GetStats -- protected by atomic | Safe |
| RC12 | RingBuffer | `mu` protects all mutable state -- safe | Safe |
| RC13 | RingBuffer | `closed` atomic.Bool -- safe | Safe |
| RC14 | PacketBuffer | `mu` protects all buffer access -- safe | Safe |
| RC15 | TokenBucket | `mu` protects tokens/lastTime -- safe | Safe |
| RC16 | Engine | **Stop() race**: Stop closes taskChan, then cancels context, then calls Stop() on workers. If a ConfigWorker is in the middle of spawning a goroutine (between selecting task and wg.Add(1) for the goroutine), the wg.Add(1) in the goroutine may race with wg.Wait() in Stop. The goroutine's wg.Add(1) at line 116 is called AFTER the semaphore is acquired (line 114), but BEFORE the goroutine's wg.Done() is deferred. If Stop() hits wg.Wait() between spawning the goroutine and the goroutine calling wg.Add(1), Wait returns before the goroutine finishes (or even starts). | **RACE**: wg.Add(1) in goroutine at line 116 can race with wg.Wait() at line 348 |
| RC17 | Engine | `onTaskDone` callback invoked from spawned goroutine without synchronization -- can race with itself | Callback ordering not guaranteed |
| RC18 | Engine | **SubmitTask/StopTask race**: SubmitTask stores entry, then sends to taskChan. If StopTask is called immediately after, it finds the entry in store and cancels, but the task hasn't been picked up by ConfigWorker yet. The task is cancelled before processing starts. | Task is cancelled without ever running -- acceptable |
| RC19 | Engine | SetTaskTotalConfigs and OnPacketWritten both check for completion; they run in different goroutines and both hold taskMu. The completion check is idempotent (delete from store). | Safe |
| RC20 | Engine | **outputMu.Close deadlock**: UnregisterOutputWriter closes writer OUTSIDE the lock (line 231). But Stop() collects writers under the lock then closes outside. No deadlock. | Safe |
| RC21 | ConfigWorker | processBatchTask: multiple goroutines write to `configCount` (atomic) and `flowFailures` (atomic) -- safe | Safe |
| RC22 | ConfigWorker | processBatchTask: multiple goroutines write to `configChan` (channel) -- safe | Safe |
| RC23 | Engine | **Stop() during SubmitTask**: If SubmitTask is called concurrently with Stop(), SubmitTask may pass the `running` check (line 399) before Stop() sets running=false, then try to send to taskChan which is closed by Stop (line 331). Send on closed channel panics. | **RACE**: Send on closed channel -- CRASH |
| RC24 | Engine | **Stop() during Stop()**: Double-close of taskChan, ctx cancellation, channel close -- all are idempotent or panic on double-close. | **Double-close channels**: calling close(e.taskChan) twice panics. But Stop() returns early if !running (line 324), so double call is safe. |
| RC25 | Engine | **Stop() during OnTaskDone callback**: OnTaskDone calls SetTaskTotalConfigs or FailTask, which hold taskMu. Stop() calls wg.Wait() which blocks until all goroutines complete. No deadlock because taskMu is released before wg.Wait() in Stop(). | Safe |

---

## SUMMARY OF FINDINGS

### Potential Bugs Found

1. **BUG: GetBatch with max < 0 panics** (RB23) -- `GetBatch(-1)` on an empty buffer: `n = min(-1, 0) = -1`, then `make([][]byte, -1)` panics. Occurs if an external caller passes a negative count.

2. **BUG: Double-Stop races with SubmitTask** (RC23) -- If `Stop()` is called while `SubmitTask` is in progress, the `taskChan` may be closed between the `running` check and the `select` send, causing a panic on send to closed channel.

3. **BUG: wg.Add race in ConfigWorker.run** (RC16) -- The `wg.Add(1)` at line 116 is called inside the spawned goroutine, not in the select loop. If `Stop()` calls `wg.Wait()` between lines 114 and 116, the Wait may return before the goroutine calls `wg.Add(1)`, causing a race or incomplete task processing.

4. **BUG: Duplicate RegisterDualWriter leaks** (E15) -- Registering a new DualPortWriter for an existing taskID overwrites the old entry without closing the old writers. The old PacketWriter instances are leaked (file handles not closed).

5. **BUG: Duplicate SetClassRateLimit leaks** (E116) -- Setting a rate limit for an existing classID overwrites the old bucket without any cleanup. Minor memory leak.

6. **BUG: TokenBucket Allow int64 overflow** (TB12) -- `(elapsed * tb.rate) / int64(time.Second)` can overflow int64 if elapsed is very large (e.g. after a long idle period). On overflow, the result wraps to negative, which would decrease tokens instead of increasing them.

7. **BUG: genIP "inc" with start+offset overflow** (TG16) -- `start + offset` can overflow uint32, wrapping to a small IP instead of producing the expected large IP.