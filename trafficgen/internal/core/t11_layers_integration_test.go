// T11 集成测试（P2c-3）：layers config → engine.SubmitTask → worker 按 per-task
// planner 分发 → ChainPlanner 驱动 → Builder 字节输出 → writer。
// 外部测试包（core_test）：core 内包测试不能 import layers（layers import
// core，import cycle）；而层链工厂正是 main.go 注入引擎的
// layers.BuildLayersPlanner，必须从外部引用真实实现。
//
// 与 P2c-1 的单元测试（BuildLayersPlanner 直接 Plan）互补：单元测试证明
// planner 产包，集成测试驱动完整 engine 流水线，断言写出的真实以太网帧
// 字节内容。
//
// 字节断言（TCP 段，RFC 793 大端序，偏移含 eth 头 14B）：
//   eth[12:14] = 0x0800（IPv4）；ip[23] = 6（TCP）；ip[30:34] = dst 10.0.0.2
//   tcp 段首（eth14+ip20 后）：src 端口偏移 34:36、dst 端口 36:38、
//   seq 38:42、ack 42:46、off/flags 46:48（flags 在 47：SYN=0x02、ACK=0x10）、
//   window 48:50。
//
// 也断言 layer config 贯穿到字节：window_size:8192 → tcp 窗口字段
// （偏移 48:50）= 0x2000（uint16 大端）。
//
// 负向（fail-loudly）：未实现生成器的层链（tftp 未注册进 layers 注册表，
// 也无 ChainPlanner 生成器）在 SubmitTask 时同步失败——策略层已校验过的链，
// 在 engine 提交时仍要再拦一道（防 config 被带外编辑/手工构造后静默空流）。
// 拦截点：BuildLayersPlanner → ValidateLayers 注册表 V1 检查（tftp 不在
// registry → "layers: unknown layer"）或生成器 precheck（已注册但无生成器的
// 层 → "layers: generator not implemented"）。
package core_test

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 空导入：http/dns 协议包的 init() 反向注册终结层层生成器
	// （RegisterHTTPGenerator / RegisterLayerGenerator），与 main.go 接线一致。
	// 不导入则多层链 [ip→tcp→http] / [ip→udp→dns] 在提交时报
	// "generator not registered"（分层设计：layers 不依赖协议包）。
	_ "github.com/trafficgen/trafficgen/internal/protocol/dns"
	_ "github.com/trafficgen/trafficgen/internal/protocol/http"
)

// frameWriter 捕获 writer 收到的完整帧（字节断言用），实现 core.PacketWriter。
type frameWriter struct {
	mu     sync.Mutex
	frames [][]byte
}

func (w *frameWriter) WritePackets(packets [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.frames = append(w.frames, packets...)
	return nil
}

func (w *frameWriter) Close() error { return nil }

func (w *frameWriter) snapshot() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([][]byte, len(w.frames))
	for i, f := range w.frames {
		out[i] = append([]byte(nil), f...)
	}
	return out
}

// be reads n big-endian bytes at offset off of frame (字节断言小工具)。
func be(frame []byte, off, n int) uint64 {
	var v uint64
	for i := 0; i < n; i++ {
		v = v<<8 | uint64(frame[off+i])
	}
	return v
}

// waitForFrames waits until the writer has received at least n frames.
// Writer flush can lag the task-completed status flip (drain is async), so
// snapshotting once right after waitTaskCompleted can see 0 frames from a
// task that actually produced packets — poll, don't assume.
func waitForFrames(t *testing.T, fw *frameWriter, n int, timeout time.Duration) [][]byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f := fw.snapshot(); len(f) >= n {
			return f
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("writer received %d frames, want >= %d (within %v)", len(fw.snapshot()), n, timeout)
	return nil
}

// taskOutcome records engine task failures via the OnTaskFailed callback.
// FailTask deletes the task from the store BEFORE firing OnTaskFailed, so a
// task can vanish from GetTaskStatus while a poll is between calls — the
// callback is the only signal that survives deletion. waitTaskCompleted uses
// it to distinguish "completed (deleted)" from "failed (deleted)": a failed
// task ALWAYS lands in this map (FailTask → OnTaskFailed, engine.go), so a
// task missing from the store without a failure record is genuinely complete.
type taskOutcome struct {
	mu     sync.Mutex
	failed map[string]string // taskID -> error message
}

func newTaskOutcome() *taskOutcome {
	return &taskOutcome{failed: map[string]string{}}
}

func (o *taskOutcome) recordFailure(id, errMsg string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.failed[id] = errMsg
}

func (o *taskOutcome) failure(id string) (string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	msg, ok := o.failed[id]
	return msg, ok
}

// waitTaskCompleted waits until the task either completes successfully or
// fails. A failure is detected via the OnTaskFailed callback (taskOutcome) —
// polling GetTaskStatus alone is unreliable because FailTask removes the task
// from the store, making "failed" indistinguishable from "completed" once the
// store entry is gone. Status reads go through RangeTaskStore (whose callback
// runs under the store lock): GetTaskStatus returns a pointer to the shared
// TaskStatus, so reading fields off it after the lock is released races with
// the output workers that mutate status under the write lock.
func waitTaskCompleted(t *testing.T, e *core.Engine, out *taskOutcome, id string, timeout time.Duration) {
	t.Helper()
	statusOf := func() string {
		var s string
		e.RangeTaskStore(func(tid string, status *core.TaskStatus) bool {
			if tid == id {
				s = status.Status
				return false
			}
			return true
		})
		return s
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if msg, ok := out.failure(id); ok {
			t.Fatalf("task %s failed: %s", id, msg)
		}
		switch statusOf() {
		case "completed":
			return
		case "failed", "stopped":
			// Failed/stopped tasks are removed from the store right after the
			// status is set (FailTask/StopTask delete under the same lock), so
			// the callback usually records them first; this branch is the
			// in-window catch.
			if msg, ok := out.failure(id); ok {
				t.Fatalf("task %s ended with status %q (error=%s)", id, statusOf(), msg)
			}
			t.Fatalf("task %s ended with status %q", id, statusOf())
		case "":
			// Task removed from store. If it had failed, OnTaskFailed would
			// have recorded it above — absence without a record means it
			// completed and was cleaned up.
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if msg, ok := out.failure(id); ok {
		t.Fatalf("task %s failed: %s", id, msg)
	}
	t.Fatalf("task %s not completed within %v (last status=%q)", id, timeout, statusOf())
}

// newT11Engine builds an engine wired exactly like the production binary:
// layers.BuildLayersPlanner factory + real Builder, writing to fw. It also
// wires OnTaskFailed into out so tests can distinguish task failure from
// completion (see waitTaskCompleted).
func newT11Engine(t *testing.T, pw int) (*core.Engine, *frameWriter, *taskOutcome) {
	t.Helper()
	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: pw, OutputWorkers: pw,
		BufferSize: 8192, QueueSize: 256,
	})
	e.SetLayerPlannerFactory(layers.BuildLayersPlanner)
	e.SetBuildFunc(core.NewBuilder().Build)
	out := newTaskOutcome()
	e.OnTaskFailed = out.recordFailure
	fw := &frameWriter{}
	e.RegisterOutputWriter("t11-"+t.Name(), fw)
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { e.Stop() })
	return e, fw, out
}

// TestT11_LayersChainDrivesRealBytes: 完整流水线（submit → per-task planner
// 分发 → ChainPlanner 驱动 → Builder）必须把层链配置落成真实以太网帧，
// 字节断言逐字段校验（CRITICAL-1 的集成面：单层 [tcp] 链此前在此路径
// 静默产出 0 包）。
func TestT11_LayersChainDrivesRealBytes(t *testing.T) {
	e, fw, out := newT11Engine(t, 1)
	if err := e.SubmitTask(core.Task{
		ID: "t11-" + t.Name(), Name: "t11", Protocol: "tcp", ClassID: "t11-" + t.Name(),
		Spec: core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 12345, DstPort: 80,
			Count: 1,
		},
		Layers: json.RawMessage(`[{"tcp":{"window_size":8192}}]`),
	}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitTaskCompleted(t, e, out, "t11-"+t.Name(), 5*time.Second)

	frames := waitForFrames(t, fw, 1, 5*time.Second)
	frame := frames[0]
	if len(frame) < 54 {
		t.Fatalf("frame too short: %d bytes (< 54: eth14+ip20+tcp20)", len(frame))
	}
	if got := be(frame, 12, 2); got != 0x0800 {
		t.Errorf("eth ethertype = %#04x, want 0x0800", got)
	}
	if got := frame[23]; got != 6 {
		t.Errorf("ip protocol = %d, want 6 (tcp)", got)
	}
	if got := be(frame, 30, 4); got != 0x0a000002 {
		t.Errorf("ip dst = %#08x, want 10.0.0.2", got)
	}
	if got := be(frame, 34, 2); got != 12345 {
		t.Errorf("tcp src port = %d, want 12345", got)
	}
	if got := be(frame, 36, 2); got != 80 {
		t.Errorf("tcp dst port = %d, want 80", got)
	}
	// 首帧必须是 SYN（链生成器从握手开始；若首段不是握手，层链驱动已破坏）。
	if got := frame[47] & 0x02; got == 0 {
		t.Errorf("first segment flags = %#02x, want SYN set", frame[47])
	}
	// Layer config 必须贯穿到字节：window_size:8192 → 偏移 48:50。
	if got := be(frame, 48, 2); got != 8192 {
		t.Errorf("tcp window = %d, want 8192 (layer config lost before bytes)", got)
	}
}

// TestT11_MultiWorkerPerTaskDispatch: 多 packet worker 并发 dispatch 时，各自
// 的 per-task planner 必须互不干扰——错误地回退到协议名 planner（合成链）会
// 全部产出同一窗口值，两个任务的字节区分将失败。
func TestT11_MultiWorkerPerTaskDispatch(t *testing.T) {
	e, fw, out := newT11Engine(t, 2)
	base := "t11-" + t.Name()
	e.RegisterOutputWriter(base+"-a", fw)
	e.RegisterOutputWriter(base+"-b", fw)
	tasks := []core.Task{
		{ID: base + "-a", Name: "a", Protocol: "tcp", ClassID: base,
			Spec: core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1000, DstPort: 80, Count: 1},
			Layers: json.RawMessage(`[{"tcp":{"window_size":2048}}]`)},
		{ID: base + "-b", Name: "b", Protocol: "tcp", ClassID: base,
			Spec: core.FlowSpec{SrcIP: "10.0.0.3", DstIP: "10.0.0.4", SrcPort: 2000, DstPort: 443, Count: 1},
			Layers: json.RawMessage(`[{"tcp":{"window_size":8192}}]`)},
	}
	for _, task := range tasks {
		if err := e.SubmitTask(task); err != nil {
			t.Fatalf("submit %s: %v", task.ID, err)
		}
	}
	waitTaskCompleted(t, e, out, base+"-a", 5*time.Second)
	waitTaskCompleted(t, e, out, base+"-b", 5*time.Second)

	frames := waitForFrames(t, fw, 4, 5*time.Second)
	seenA, seenB := 0, 0
	for _, frame := range frames {
		// 最小 TCP 帧 = eth14+ip20+tcp20 = 54B；短于 54 的帧无法安全读取
		// 窗口字段（be(frame,48,2) 需 len≥50），直接跳过。
		if len(frame) < 54 {
			continue
		}
		switch sp := be(frame, 34, 2); sp {
		case 1000:
			if got := be(frame, 48, 2); got != 2048 {
				t.Errorf("task-a window = %d, want 2048 (per-task planner cross-talk)", got)
			}
			seenA++
		case 2000:
			if got := be(frame, 48, 2); got != 8192 {
				t.Errorf("task-b window = %d, want 8192 (per-task planner cross-talk)", got)
			}
			seenB++
		}
	}
	if seenA == 0 || seenB == 0 {
		t.Errorf("flow packets missing: a=%d b=%d (one task never dispatched)", seenA, seenB)
	}
}

// TestT11_HTTPChainEndToEnd: 多层链 [ip→tcp→http]（补全自 {"http":{}}）走完整
// 流水线必须产出真实 TCP 握手 + HTTP 数据段。数据段字节：HTTP/1.1 响应
// 状态行（请求首帧即 SYN 之后的第一个上行段）。完整 HTTP 事务（interleaved）
// = 握手 3 段 + 请求 + 响应 + 终止。
func TestT11_HTTPChainEndToEnd(t *testing.T) {
	e, fw, out := newT11Engine(t, 1)
	if err := e.SubmitTask(core.Task{
		ID: "t11-" + t.Name(), Name: "http", Protocol: "http", ClassID: "t11-" + t.Name(),
		Spec: core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 8080, Count: 1},
		Layers: json.RawMessage(`[{"http":{"method":"POST","uri":"/x","version":"1.1"}}]`),
	}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitTaskCompleted(t, e, out, "t11-"+t.Name(), 5*time.Second)

	frames := waitForFrames(t, fw, 6, 5*time.Second)
	// 首帧必须是以 10.0.0.1:40000 → 10.0.0.2:8080 的 SYN。
	f0 := frames[0]
	if len(f0) < 54 {
		t.Fatalf("first frame too short: %d bytes", len(f0))
	}
	if got := be(f0, 12, 2); got != 0x0800 {
		t.Errorf("eth ethertype = %#04x, want 0x0800", got)
	}
	if got := f0[23]; got != 6 {
		t.Errorf("ip protocol = %d, want 6 (tcp)", got)
	}
	if got := be(f0, 30, 4); got != 0x0a000002 {
		t.Errorf("ip dst = %#08x, want 10.0.0.2", got)
	}
	if got := be(f0, 34, 2); got != 40000 {
		t.Errorf("tcp src port = %d, want 40000", got)
	}
	if got := be(f0, 36, 2); got != 8080 {
		t.Errorf("tcp dst port = %d, want 8080", got)
	}
	if f0[47]&0x02 == 0 {
		t.Errorf("first segment flags = %#02x, want SYN set", f0[47])
	}
	// 握手之后（第 4 段起）必须出现 HTTP 报文段：数据段长度 > 20（eth14+ip20+tcp20）。
	// HTTP/1.1 POST 请求行是上行段。扫描所有帧，找到含 "POST" 的段（上行方向
	// src 端口 40000），验证 http 层配置贯穿到字节。
	foundPOST := false
	for _, frame := range frames {
		if len(frame) < 54 {
			continue
		}
		if be(frame, 34, 2) != 40000 { // 上行段：src port 40000
			continue
		}
		// 数据段 = tcp 段首之后（eth14+ip20+tcp20=54）是 HTTP 负载。
		if len(frame) > 54 && string(frame[54:]) != "" && len(frame[54:]) >= 4 {
			if s := string(frame[54:]); len(s) >= 4 && s[:4] == "POST" {
				foundPOST = true
				break
			}
		}
	}
	if !foundPOST {
		t.Error("no HTTP POST request segment found in upstream frames (http layer bytes never emitted)")
	}
	// 响应方向：下行段 src 端口 8080 应含 "HTTP/1.1"。
	foundResp := false
	for _, frame := range frames {
		if len(frame) < 54 {
			continue
		}
		if be(frame, 34, 2) != 8080 {
			continue
		}
		if len(frame) > 54 && len(frame[54:]) >= 9 && string(frame[54:][:9]) == "HTTP/1.1 " {
			foundResp = true
			break
		}
	}
	if !foundResp {
		t.Error("no HTTP/1.1 response segment found in downstream frames")
	}
}

// TestT11_DNSChainEndToEnd: 多层链 [ip→udp→dns]（补全自 {"dns":{}}）走完整
// 流水线必须产出真实 UDP DNS 请求段。UDP 帧最小 42B（eth14+ip20+udp8），
// DNS 头 12B 起。{"dns":{}} 无 is_response → 仅请求包（legacy dns.go:301
// 的 IsResponse gate；is_response 不在层 schema 字段表，V9 拒绝未知字段，
// 须经 flat spec 配置）。
func TestT11_DNSChainEndToEnd(t *testing.T) {
	e, fw, out := newT11Engine(t, 1)
	if err := e.SubmitTask(core.Task{
		ID: "t11-" + t.Name(), Name: "dns", Protocol: "dns", ClassID: "t11-" + t.Name(),
		Spec: core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 53, Count: 1},
		Layers: json.RawMessage(`[{"dns":{}}]`),
	}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitTaskCompleted(t, e, out, "t11-"+t.Name(), 5*time.Second)

	frames := waitForFrames(t, fw, 1, 5*time.Second)
	f0 := frames[0]
	if len(f0) < 42 {
		t.Fatalf("first frame too short: %d bytes (< 42: eth14+ip20+udp8)", len(f0))
	}
	if got := be(f0, 12, 2); got != 0x0800 {
		t.Errorf("eth ethertype = %#04x, want 0x0800", got)
	}
	if got := f0[23]; got != 17 {
		t.Errorf("ip protocol = %d, want 17 (udp)", got)
	}
	if got := be(f0, 34, 2); got != 50000 {
		t.Errorf("udp src port = %d, want 50000", got)
	}
	if got := be(f0, 36, 2); got != 53 {
		t.Errorf("udp dst port = %d, want 53 (dns default)", got)
	}
	// DNS 头（udp 负载，偏移 42 起）：42:44 txid，44:46 flags（0x0100 =
	// RD 位）。RD 是 16 位 flags 字的 bit8（RFC 1035 §4.1.1）→ 落在高字节
	// （偏移 44），低字节（偏移 45）为 0。
	if got := f0[44] & 0x01; got != 1 {
		t.Errorf("dns flags high byte = %#02x, want RD bit set (0x01)", f0[44])
	}
}

// TestT11_UnimplementedGeneratorLayerFailsSubmit: 未实现生成器的层链必须在
// SubmitTask 同步失败（fail-loudly），绝不能静默生成空流。
// 选型说明：tftp 是独立协议包，有 legacy 字节构建，但既不在 layers 注册表
// 也无 ChainPlanner 生成器——tftp 不入注册表则 V1 拦截；若未来某协议接入
// 注册表但暂无生成器，precheck 拦截（"layers: generator not implemented"）。
// 若 tftp 将来接入公共层，此测试需换一个仍未接入的协议层。
func TestT11_UnimplementedGeneratorLayerFailsSubmit(t *testing.T) {
	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 8192, QueueSize: 256,
	})
	e.SetLayerPlannerFactory(layers.BuildLayersPlanner)
	out := newTaskOutcome()
	e.OnTaskFailed = out.recordFailure
	fw := &frameWriter{}
	e.RegisterOutputWriter("t11-neg-"+t.Name(), fw)
	e.RegisterOutputWriter("t11-neg-ok-"+t.Name(), fw)
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	err := e.SubmitTask(core.Task{
		ID: "t11-neg-" + t.Name(), Name: "neg", Protocol: "tftp", ClassID: "t11-neg-" + t.Name(),
		Spec: core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 69, DstPort: 2000, Count: 1},
		Layers: json.RawMessage(`[{"tftp":{}}]`),
	})
	if err == nil {
		t.Fatal("submit succeeded for tftp layer chain (want synchronous failure)")
	}
	if !strings.Contains(err.Error(), "layers:") {
		t.Errorf("error %q not prefixed with layers:", err)
	}
	// 失败的任务绝不能进入流水线：writer 收不到任何包。
	if got := len(fw.snapshot()); got != 0 {
		t.Errorf("failed task still wrote %d packets", got)
	}
	// 失败后 engine 仍可用：合法的 layers 任务必须照常跑。
	if err := e.SubmitTask(core.Task{
		ID: "t11-neg-ok-" + t.Name(), Name: "neg-ok", Protocol: "tcp", ClassID: "t11-neg-" + t.Name(),
		Spec: core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Count: 1},
		Layers: json.RawMessage(`[{"tcp":{}}]`),
	}); err != nil {
		t.Fatalf("submit valid task after failure: %v", err)
	}
	waitTaskCompleted(t, e, out, "t11-neg-ok-"+t.Name(), 5*time.Second)
	if got := len(fw.snapshot()); got == 0 {
		t.Fatal("valid task after failed submit wrote 0 packets")
	}
}
