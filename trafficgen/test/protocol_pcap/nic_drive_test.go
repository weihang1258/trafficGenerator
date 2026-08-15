package protocolpcap

// nic_drive_test.go: 阶段二——真实 NIC 抓包验证。
//
// 经 MCP flowb_generate_traffic(output_type=port_group) 让引擎把帧从
// enp135s0f0np0 物理发出（TX 计数 + pcap 注入实测可见），tcpdump 在
// 发包接口本身上抓包（用户确认无需组网，仅验证功能），再用与阶段一
// 相同的 VerifyPcap（tshark 断言）核对 NIC 驱动实际发出的字节。
// 语义：引擎 → pcap.OpenLive 注入 → 网卡驱动 → 线上字节。
//
// 运行（需 root）：
//
//	NIC_RUN=1 go test -timeout 0 -run TestNICDrive ./test/protocol_pcap/ -v
//	NIC_RUN=1 NIC_PROTO=tcp go test ...           # 单协议
//	NIC_RUN=1 NIC_MAX=3 go test ...               # 冒烟（按协议字典序取前 3 个协议）
//	NIC_RUN=1 NIC_CASE=modbus_xxx go test ...     # 单用例调试
//
// 前置条件：
//   - 发包网卡已建端口组（REST POST /api/v1/port-groups）。
//   - 发包网卡 TX offload 关闭（ethtool -K <tx> tso off gso off），
//     保证线上字节 = 引擎帧（checksum 不被硬件改写）。
//   - tcpdump / tshark 在 PATH 中。

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	nicTXIf = "enp135s0f0np0" // 发包接口（端口组内；抓包也在本接口进行）
	nicPGID = "9c007853-8908-4e7c-9a6a-d26ccd2a6a44"
	// 引擎帧默认 src MAC（线上字节原样）：c2s=01，s2c=02。
	// 双向帧都在发包口可见（pcap 注入 + 驱动出口双路径），过滤必须
	// 同时匹配两个方向，否则漏掉应答帧、破坏按方向断言。
	frameMAC  = "02:00:00:00:00:01" // 引擎帧默认 src_mac（c2s 方向）
	frameMAC2 = "02:00:00:00:00:02" // 引擎帧默认 src_mac（s2c 方向）
	nicCapDir = "/tmp/mcp-nic-pcaps" // NIC 抓包落盘目录
)

var (
	nicProto = os.Getenv("NIC_PROTO")
	nicMax   = atoiEnv("NIC_MAX")
	nicProbe = os.Getenv("NIC_CASE") // 单用例 ID 调试（NIC_CASE=xxx 即启用）
)

func atoiEnv(k string) int {
	v := os.Getenv(k)
	if v == "" {
		return 0
	}
	n := 0
	fmt.Sscanf(v, "%d", &n)
	return n
}

// nicSelection 每协议取代表性子集：核心会话路径 + 负路径各一，最多 NIC_MAX。
// 主路径采用确定性等距采样（均匀覆盖 index 空间），避免对无 default-id
// 协议的奇偶采样偏斜。
//
// 强制纳入 L2 覆盖用例（spec 顶层 src_mac/dst_mac 非引擎默认 MAC）：
// 这些帧的 eth.src 会被过滤漏抓（整包不落盘），等距采样可能永远选不中
// 它们（如 doip_eid_from_dstmac，picked idx 49，step 21 取 0/21/42/63），
// 使「帧发出但漏抓 → 空 pcap 显式 fail」这条守卫路径不可达。强制纳入
// 保证该守卫每次全量运行都被实测（空 pcap fail 是预期、可诊断）。
func nicSelection(t *testing.T, cases map[string][]Case) []job2 {
	var jobs []job2
	for proto, cs := range cases {
		if nicProto != "" && proto != nicProto {
			continue
		}
		var picked []Case
		var neg []Case
		var l2 []Case
		for _, c := range cs {
			if nicProbe != "" {
				if c.ID == nicProbe {
					picked = []Case{c}
					break
				}
				continue
			}
			if c.Expect.ExpectError {
				if len(neg) < 2 {
					neg = append(neg, c)
				}
				continue
			}
			if hasL2Override(c) {
				l2 = append(l2, c)
				continue
			}
			picked = append(picked, c)
		}
		if nicProbe != "" {
			if len(picked) > 0 {
				jobs = append(jobs, job2{proto, []Case{picked[0]}})
			}
			continue
		}
		// 主路径：等距采样最多 4 条（均匀覆盖用例 index 空间）。
		var main []Case
		if n := len(picked); n > 0 {
			step := (n + 3) / 4
			if step < 1 {
				step = 1
			}
			for i := 0; i < n; i += step {
				main = append(main, picked[i])
				if len(main) >= 4 {
					break
				}
			}
		}
		// L2 覆盖用例：取第一个（保证「漏抓守卫」路径可达）。已含在
		// 采样内（l2 不参与等距），避免与主路径重复。
		for _, l := range l2[:min1(len(l2), 1)] {
			main = append(main, l)
		}
		// 负路径 1 个（有则取）；这些不发包（预期 MCP 拒绝）。
		for _, nc := range neg[:min1(len(neg), 1)] {
			main = append(main, nc)
		}
		if len(main) > 0 {
			jobs = append(jobs, job2{proto, main})
		}
	}
	// 协议按字典序排序：Go map 迭代序随机，NIC_MAX 截断取前 N 个 job
	// 必须确定（否则冒烟每次跑不同协议子集、无法复现）。
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].proto < jobs[j].proto })
	if nicMax > 0 && len(jobs) > nicMax {
		jobs = jobs[:nicMax]
	}
	return jobs
}

// hasL2Override 报告用例 spec 顶层是否覆盖了引擎默认 MAC（src_mac
// 02:00:00:00:00:01 / dst_mac 02:00:00:00:00:02）。覆盖后帧的 eth.src
// 不匹配默认抓包过滤器，需 overrideMACs 扩展过滤，否则整包漏抓。
func hasL2Override(c Case) bool {
	return len(overrideMACs(c)) > 0
}

// overrideMACs 返回用例 spec 顶层覆盖引擎默认值的 src_mac/dst_mac
// （去重、跳过空串与默认值）。doip 的 direction=down 会把覆盖后的
// dst_mac 当作帧源 MAC（MAC 交换），故两者都需纳入抓包过滤器。
func overrideMACs(c Case) []string {
	var spec map[string]any
	if err := json.Unmarshal(c.SpecJSON, &spec); err != nil {
		return nil
	}
	var out []string
	for _, f := range []struct{ key, def string }{
		{"src_mac", "02:00:00:00:00:01"},
		{"dst_mac", "02:00:00:00:00:02"},
	} {
		if v, ok := spec[f.key].(string); ok && v != "" && v != f.def {
			dup := false
			for _, e := range out {
				if e == v {
					dup = true
					break
				}
			}
			if !dup {
				out = append(out, v)
			}
		}
	}
	return out
}

func min1(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type job2 struct {
	proto string
	cases []Case
}

// captureStart 在发包接口上启动 tcpdump，抓取引擎帧（默认两个方向
// src MAC + 用例 L2 覆盖 MAC）的帧。失败必须暴露（stderr 透传 + 错误
// 返回）：tcpdump 静默失败曾导致空 pcap 被误判为「没收到帧」。
//
// 等待 stderr 出现 "listening" 再返回：BPF 过滤 attach 完成前任务可能
// 已跑完（任务毫秒级完成），造成空抓包假阴性。tcpdump 的启动信息
// （含 listening）走 stderr，stdout 为空；用 StderrPipe 读取并同时
// 透传到 os.Stderr（exec.Cmd 同一 writer 不能同时接 StderrPipe 和
// Stderr）。
//
// 过滤 = 默认 c2s/s2c 源 MAC + 用例覆盖 MAC（见 overrideMACs）。L2
// 覆盖用例（如 doip_eid_from_dstmac）帧源 MAC 为覆盖值，不加进过滤
// 会整包漏抓、空 pcap 误判 fail（此前为「显式 fail、可诊断」，
// 现可真实抓到并核对 eth.src）。
func captureStart(path string, c Case) (*exec.Cmd, error) {
	macs := []string{frameMAC, frameMAC2}
	macs = append(macs, overrideMACs(c)...)
	expr := "ether src " + macs[0]
	for _, m := range macs[1:] {
		expr += " or ether src " + m
	}
	cmd := exec.Command("tcpdump", "-i", nicTXIf, "-w", path, "-U", "-s", "0",
		"-Z", "root", expr)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start tcpdump: %w", err)
	}
	// stderr 透传 + 等待 listening 就绪（tcpdump 启动信息走 stderr）。
	// goroutine 必须持续读完整个 stderr（读到 EOF）：若读完 listening 就
	// return，之后 tcpdump 写 stderr 无读者 → 管道写阻塞 → tcpdump 卡住
	// 不再抓包（实测 0 帧假阴性）。listening 仅是信号，不终止读取。
	listening := make(chan struct{}, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			fmt.Fprintln(os.Stderr, sc.Text())
			if strings.Contains(sc.Text(), "listening") {
				select {
				case listening <- struct{}{}:
				default:
				}
			}
		}
	}()
	select {
	case <-listening:
	case <-time.After(5 * time.Second):
		// 超时：先 SIGINT 给 1s 优雅期（缓冲落盘、stderr 统计写完），
		// 再 Kill 兜底；二者都 Wait 收割避免僵尸进程。残留的 goroutine
		// 读 stderr 到 EOF 自然退出，无泄漏。
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			_ = cmd.Process.Kill()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
		}
		return nil, fmt.Errorf("tcpdump did not reach listening state within 5s")
	}
	// listening 后 tcpdump 仍需约 1.5s 才能真正开始把包写入 pcap 文件
	// （实测：0.3s→0 帧、1s→1/2 帧、1.5s→2/2 帧；BPF 在 listening 前
	// 已 attach，"received by filter" 计数但未落盘）。任务毫秒级完成，
	// 必须等 tcpdump 完全就绪再发起，否则全部帧在就绪前发出 → 0 帧。
	time.Sleep(2 * time.Second)
	return cmd, nil
}

// captureStop 停抓并等待 tcpdump 退出、把缓冲写盘。SIGINT 让 tcpdump
// 优雅退出（flush 缓冲 → 写完整统计到 stderr → 退出）；3s 超时后 Kill
// 兜底（Kill 会丢弃未落盘缓冲，故仅在挂死时使用）。
func captureStop(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
}

// nicRunCasePortGroup 经 MCP 用 port_group 输出真实发包，返回任务结果。
// 与 RunCase 共用 generate+poll 逻辑，仅输出类型与结果路径不同。
func (r *Runner) nicRunCasePortGroup(ctx context.Context, c Case, timeout time.Duration) *CaseResult {
	res := &CaseResult{CaseID: c.ID, Proto: c.Proto, Summary: c.Summary, Status: "error"}
	args := map[string]any{
		"task_name":   fmt.Sprintf("nic-%s-%s", c.Proto, c.ID),
		"protocol":    c.Proto,
		"config":      json.RawMessage(c.SpecJSON),
		"output_type": "port_group",
		"output_config": map[string]any{
			"port_group_id": nicPGID,
		},
	}
	if c.StrategyFC != nil {
		args["strategy_flow_control"] = map[string]any{
			"type":  c.StrategyFC.Type,
			"value": c.StrategyFC.Value,
		}
	}
	raw, err := r.Client.CallTool(ctx, "flowb_generate_traffic", args)
	if err != nil {
		if c.Expect.ExpectError {
			if ec := c.Expect.ErrorContains; ec != "" && !strings.Contains(err.Error(), ec) {
				res.Status = "fail"
				res.Err = fmt.Sprintf("expected error containing %q, got: %v", ec, err)
				return res
			}
			res.Status = "pass"
			return res
		}
		res.Err = err.Error()
		return res
	}
	var gres generateResult
	if err := json.Unmarshal(raw, &gres); err != nil {
		res.Err = fmt.Sprintf("parse generate_traffic result: %v (raw=%s)", err, raw)
		return res
	}
	res.TaskID = gres.TaskID
	if gres.TaskID == "" {
		res.Err = "no task_id in generate_traffic result"
		return res
	}
	// 轮询到终态，与 RunCase 相同。
	deadline := time.Now().Add(timeout)
	for {
		raw, err = r.Client.CallTool(ctx, "flowb_get_task_progress", map[string]any{"task_id": gres.TaskID})
		if err != nil {
			res.Err = fmt.Sprintf("poll task %s: %v", gres.TaskID, err)
			return res
		}
		var rawProgress struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &rawProgress); err != nil {
			res.Err = fmt.Sprintf("parse progress result: %v (raw=%s)", err, raw)
			return res
		}
		var pres progressResult
		if err := json.Unmarshal(rawProgress.Data, &pres); err != nil {
			res.Err = fmt.Sprintf("parse progress data: %v (raw=%s)", err, rawProgress.Data)
			return res
		}
		switch pres.Status {
		case "completed":
			if c.Expect.ExpectError {
				res.Status = "fail"
				res.Err = "expected task to error (Validate-negative) but it completed successfully"
				return res
			}
			res.Status = "pass"
			return res
		case "error", "failed", "stopped":
			if c.Expect.ExpectError {
				msg := pres.ErrorMessage
				if ec := c.Expect.ErrorContains; ec != "" && !strings.Contains(msg, ec) {
					res.Status = "fail"
					res.Err = fmt.Sprintf("expected error containing %q, got: %s", ec, msg)
					return res
				}
				res.Status = "pass"
				res.Err = ""
				return res
			}
			res.Err = fmt.Sprintf("task %s ended %s: %s", gres.TaskID, pres.Status, pres.ErrorMessage)
			return res
		}
		if ctx.Err() != nil {
			res.Err = fmt.Sprintf("context cancelled while polling task %s: %v", gres.TaskID, ctx.Err())
			return res
		}
		if time.Now().After(deadline) {
			res.Err = fmt.Sprintf("task %s not terminal after %v (status=%s)", gres.TaskID, timeout, pres.Status)
			return res
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestNICDrive 驱动 NIC 真实发包 + tcpdump 抓包 + VerifyPcap 核对。
func TestNICDrive(t *testing.T) {
	if os.Getenv("NIC_RUN") != "1" {
		t.Skip("set NIC_RUN=1 to run the NIC capture driver")
	}
	cases := loadCases(t)
	jobs := nicSelection(t, cases)
	if len(jobs) == 0 {
		t.Fatal("no cases selected")
	}
	t.Logf("NIC drive: %d job(s), %d cases", len(jobs), countCases(jobs))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	r, err := NewRunner(ctx, envEndpoint, envAPIKey, envPcapRoot)
	if err != nil {
		t.Fatalf("connect MCP: %v", err)
	}
	defer r.Close()

	if err := os.MkdirAll(nicCapDir, 0755); err != nil {
		t.Fatal(err)
	}

	pass, fail, errCount := 0, 0, 0
	// 抓包必须全串行：同一接口并发 tcpdump 会互抢帧，破坏单用例
	// 包序/包数断言（VerifyPcap 按 packet 索引核对）。协议之间也串行
	// （过滤只匹配引擎默认 MAC，不区分协议，并发会互相污染）。
	for _, j := range jobs {
		for _, c := range j.cases {
			// 负路径用例：MCP 拒绝即 pass，不发包、不抓包。
			if c.Expect.ExpectError {
				res := r.nicRunCasePortGroup(ctx, c, envTimeout)
				if res.Status == "pass" {
					pass++
					t.Logf("[%s] %s: PASS (validate-negative)", res.Proto, res.CaseID)
				} else {
					fail++
					t.Errorf("[%s] %s: %s", res.Proto, res.CaseID, res.Err)
				}
				continue
			}
			// 先抓包，再发起任务；任务完成（= 全部帧已物理发出）后停抓。
			pcap := filepath.Join(nicCapDir, c.Proto, c.ID+".pcap")
			if err := os.MkdirAll(filepath.Dir(pcap), 0755); err != nil {
				errCount++
				t.Errorf("[%s] %s: mkdir: %v", c.Proto, c.ID, err)
				continue
			}
			capCmd, cerr := captureStart(pcap, c)
			if cerr != nil {
				errCount++
				t.Errorf("[%s] %s: %v", c.Proto, c.ID, cerr)
				continue
			}
			res := r.nicRunCasePortGroup(ctx, c, envTimeout)
			// 任务 completed 时帧可能刚进内核接收环，tcpdump 用户态还没
			// 来得及读盘（实测立即 SIGINT → 7 received / 0 captured）。
			// 留 2s 读盘窗口再停抓（变体 5：最后帧后 2s SIGINT → 2/2）。
			time.Sleep(2 * time.Second)
			captureStop(capCmd)
			// tcpdump -U 每包落盘，停抓后留少量 flush 时间。
			time.Sleep(300 * time.Millisecond)
			if res.Status == "pass" {
				// 空 pcap 守卫：0 帧 = 帧未发出或被过滤全漏。VerifyPcap 对空
				// pcap 无断言空转，会掩盖「completed 但 0 包」的假阳性。
				if n := pcapCount(pcap); n <= 0 {
					res.Status = "fail"
					res.Err = fmt.Sprintf("no frames captured on %s (count=%d)", nicTXIf, n)
				} else if probs := VerifyPcap(pcap, c); len(probs) > 0 {
					res.Status = "fail"
					res.Err = "verify: " + joinProbs(probs)
				} else {
					res.PacketCount = n
				}
			}
			switch res.Status {
			case "pass":
				pass++
			case "fail":
				fail++
			default:
				errCount++
			}
			if res.Status != "pass" {
				t.Errorf("[%s] %s: %s", res.Proto, res.CaseID, res.Err)
			} else {
				t.Logf("[%s] %s: PASS (%d pkts)", res.Proto, res.CaseID, res.PacketCount)
			}
		}
	}

	t.Logf("NIC RESULT: %d pass, %d fail, %d error (of %d)", pass, fail, errCount, pass+fail+errCount)
	if fail+errCount > 0 {
		t.Fatalf("%d NIC cases failed", fail+errCount)
	}
}

func countCases(jobs []job2) int {
	n := 0
	for _, j := range jobs {
		n += len(j.cases)
	}
	return n
}

// pcapCount 读取抓到的包数；失败返回 -1。
func pcapCount(path string) int {
	if n, err := pcapPacketCount(path); err == nil {
		return n
	}
	return -1
}
