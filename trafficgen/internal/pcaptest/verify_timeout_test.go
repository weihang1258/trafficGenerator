package pcaptest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRunTshark_TimedOut_ReturnsError 验证 RunTshark 对挂死的 tshark
// （dissector 死循环：进程存活但不输出）不会永久阻塞，而在 RunTsharkTimeout
// 内超时返回错误。回归锚点：2026-08 实测 RunTshark 无超时，一个挂死 tshark
// 让整个用例卡死、测试 22m 超时。
//
// 用一个"伪 tshark"脚本来模拟挂死，不依赖真实 tshark 行为。自包含直接
// 子进程：`exec sleep` 的写法派生孙进程，Go 的 CommandContext 超时只杀直接
// 子进程，孤儿孙进程持有 stdout 管道会继续让 cmd.Run() 阻塞（这正是 2026-08
// 回归里真实挂死 tshark 卡死整条链路的原因）。故用 `read` 阻塞在 stdin——
// 不 spawn 子进程，超时杀掉直接子进程即关闭管道，cmd.Run() 立刻返回。
func TestRunTshark_TimedOut_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	// 伪 tshark：不 stdout 不 stderr 输出、挂死（模拟 dissector 死循环）。
	// 用短超时让测试快速通过（PCAPTEST_TSHARK_TIMEOUT_MS 覆盖默认 30s）。
	script := filepath.Join(dir, "tshark")
	// `tail -f /dev/null`：自包含直接子进程，永不退出、无输出、不 spawn 孙
	// 进程。CommandContext 超时杀掉该直接子进程后管道即关闭、cmd.Run() 返回。
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec tail -f /dev/null\n"), 0o755); err != nil {
		t.Fatalf("write fake tshark: %v", err)
	}
	old := strings.Split(os.Getenv("PATH"), ":")
	t.Setenv("PATH", dir+":"+strings.Join(old, ":"))
	// 覆盖 RunTsharkTimeout 为很短的时长，避免等 30s
	t.Setenv("PCAPTEST_TSHARK_TIMEOUT_MS", "200")

	start := time.Now()
	_, err := RunTshark("/tmp/does-not-exist.pcap", []string{"-T", "fields", "-e", "frame.number"}, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("RunTshark on hung tshark: got nil error, want timeout error (elapsed %s)", elapsed)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error %q does not mention timeout", err)
	}
	// 挂死的 tshark 必须在超时后返回，不能阻塞
	if elapsed >= 10*time.Second {
		t.Errorf("RunTshark blocked for %s; expected timeout near the configured limit", elapsed)
	}
}
