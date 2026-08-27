package pcaptest

// capture.go: NIC 抓包编排，供 MCP 工具的 flowb_run_protocol_case/suite 在
// server 进程内起 tcpdump 抓真实线上帧（output_type=port_group 验证），
// 与 test/protocol_pcap 的 NIC 驱动共用同一套时序与 MAC 过滤扩展逻辑。
//
// 前置条件（与 nic_drive_test.go 相同）：
//   - 发包网卡已建端口组（REST POST /api/v1/port-groups）。
//   - 发包网卡 TX offload 关闭（ethtool -K <tx> tso off gso off），
//     保证线上字节 = 引擎帧（checksum 不被硬件改写）。
//   - tcpdump 在 PATH 中。

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	// FrameMAC / FrameMAC2 是引擎帧默认 src MAC（线上字节原样）：c2s=01、
	// s2c=02。双向帧都在发包口可见（pcap 注入 + 驱动出口双路径），抓包
	// 过滤必须同时匹配两个方向，否则漏掉应答帧、破坏按方向断言。
	FrameMAC  = "02:00:00:00:00:01" // 引擎帧默认 src_mac（c2s 方向）
	FrameMAC2 = "02:00:00:00:00:02" // 引擎帧默认 src_mac（s2c 方向）

	// CaptureDefaultDir 是未显式指定 pcap_path 时的抓包落盘根目录。
	CaptureDefaultDir = "/tmp/mcp-nic-pcaps"

	// captureWait 是 tcpdump 从 listening（BPF attach）到真正开始把包写入
	// pcap 文件的建立期（实测：0.3s→0 帧、1s→1/2 帧、1.5s→2/2 帧）。
	// 任务毫秒级完成，必须等 tcpdump 完全就绪再发起，否则全部帧在就绪前
	// 发出 → 0 帧假阴性。
	captureWait = 2 * time.Second

	// captureListeningTimeout 是等待 tcpdump 打印 "listening"（stderr）的
	// 上限；超过则终止（SIGINT→1s→Kill 兜底）并报错，避免静默挂起。
	captureListeningTimeout = 5 * time.Second

	// captureStopGrace 是 SIGINT 后等待 tcpdump 优雅退出（flush 缓冲、写
	// 完整统计到 stderr）的上限；超时后 Kill 兜底（Kill 丢弃未落盘缓冲，
	// 仅在挂死时使用）。
	captureStopGrace = 3 * time.Second
)

// OverrideMACs 返回用例 spec 顶层覆盖引擎默认值的 src_mac/dst_mac（去重、
// 跳过空串与默认值）。doip 的 direction=down 会把覆盖后的 dst_mac 当作帧
// 源 MAC（MAC 交换），故两者都需纳入抓包过滤器。
func OverrideMACs(c Case) []string {
	var spec map[string]any
	if err := json.Unmarshal(c.SpecJSON, &spec); err != nil {
		return nil
	}
	var out []string
	for _, f := range []struct{ key, def string }{
		{"src_mac", FrameMAC},
		{"dst_mac", FrameMAC2},
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

// HasL2Override 报告用例 spec 顶层是否覆盖了引擎默认 MAC。覆盖后帧的
// eth.src 不匹配默认抓包过滤器，需 OverrideMACs 扩展过滤，否则整包漏抓。
func HasL2Override(c Case) bool {
	return len(OverrideMACs(c)) > 0
}

// CaptureFilterExpr 构造 tcpdump BPF 过滤器 = 默认 c2s/s2c 源 MAC + 用例
// 覆盖 MAC。L2 覆盖用例（如 doip_eid_from_dstmac）帧源 MAC 为覆盖值，不加
// 进过滤会整包漏抓、空 pcap 误判 fail。
func CaptureFilterExpr(c Case) string {
	macs := []string{FrameMAC, FrameMAC2}
	macs = append(macs, OverrideMACs(c)...)
	expr := "ether src " + macs[0]
	for _, m := range macs[1:] {
		expr += " or ether src " + m
	}
	return expr
}

// StartCapture 在 iface 上启动 tcpdump 抓取用例帧（默认两方向 src MAC +
// 用例 L2 覆盖 MAC）到 path。失败必须暴露（stderr 透传 + 错误返回）：
// tcpdump 静默失败曾导致空 pcap 被误判为「没收到帧」。
//
// 等待 stderr 出现 "listening" 再返回：BPF 过滤 attach 完成前任务可能已跑
// 完（任务毫秒级完成），造成空抓包假阴性。tcpdump 的启动信息（含
// listening）走 stderr；goroutine 必须持续读完整个 stderr（读到 EOF），
// 否则后续 tcpdump 写 stderr 无读者 → 管道写阻塞 → tcpdump 卡住不再抓包。
func StartCapture(iface, path string, c Case) (*exec.Cmd, error) {
	cmd := exec.Command("tcpdump", "-i", iface, "-w", path, "-U", "-s", "0",
		"-Z", "root", CaptureFilterExpr(c))
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start tcpdump: %w", err)
	}
	// stderr 透传 + 等待 listening 就绪；listening 仅是信号，不终止读取。
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
	case <-time.After(captureListeningTimeout):
		// 超时：先 SIGINT 给 1s 优雅期（缓冲落盘、stderr 统计写完），再 Kill
		// 兜底；二者都 Wait 收割避免僵尸进程。残留 goroutine 读 stderr 到 EOF
		// 自然退出，无泄漏。
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			_ = cmd.Process.Kill()
			select {
			case <-done:
			case <-time.After(captureStopGrace):
			}
		}
		return nil, fmt.Errorf("tcpdump did not reach listening state within 5s")
	}
	// listening 后仍需约 1.5-2s 才能真正开始落盘（BPF 在 listening 前已
	// attach，"received by filter" 计数但未写入文件）。等待就绪再发起任务。
	time.Sleep(captureWait)
	return cmd, nil
}

// StopCapture 停抓并等待 tcpdump 退出、把缓冲写盘。SIGINT 让 tcpdump 优雅
// 退出（flush 缓冲 → 写完整统计到 stderr → 退出）；超时后 Kill 兜底。
func StopCapture(cmd *exec.Cmd) {
	StopCaptureContext(context.Background(), cmd)
}

func StopCaptureContext(ctx context.Context, cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-done
	case <-time.After(captureStopGrace):
		_ = cmd.Process.Kill()
		<-done
	}
}
