package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// initialize 必须把 serverInstructions 带给每个客户端（MCP 标准位置）：
// 缺了它模型只能从散落的工具描述里拼工作流（外部审查问题 2，2026-10-04）。
func TestInitializeCarriesServerInstructions(t *testing.T) {
	srv := newTransportTestServer(t)
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	go func() { _ = srv.mcpServer.Run(ctx, st) }() // Run 阻塞到传输关闭
	// 无 config 参数的服务器由 NewServer 构造时已注册工具；直接连。
	sc, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sc.Close()
	// Connect 完成的 initialize 握手结果里的 instructions 即服务端下发值。
	got := sc.InitializeResult()
	if got == nil {
		t.Fatal("nil initialize result")
	}
	if !strings.Contains(got.Instructions, "STANDARD FLOW") ||
		!strings.Contains(got.Instructions, "64 KB") ||
		!strings.Contains(got.Instructions, "uploads/pcaps") {
		t.Fatalf("instructions missing flow/threshold/upload: %.200s", got.Instructions)
	}
}
