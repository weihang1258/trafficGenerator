package mcp

import (
	"context"
	"encoding/json"
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
	// 层形态约束 + 禁探 REST（2026-10-05 客户端失败 1/2 的服务端消歧）。
	for _, want := range []string{"ONE layer key per array element", "no REST API"} {
		if !strings.Contains(got.Instructions, want) {
			t.Errorf("instructions missing %q: %.400s", want, got.Instructions)
		}
	}
}

// config 描述必须写明 layers 每元素恰好一键（失败 1：模型把 ip/tcp/http
// 挤进一个元素，描述里只有正确示例没有约束句与反例，模型无从自查）。
func TestConfigDescriptionsStateLayerShapeRule(t *testing.T) {
	srv := newTransportTestServer(t)
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	go func() { _ = srv.mcpServer.Run(ctx, st) }()
	sc, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sc.Close()
	resp, err := sc.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	for _, name := range []string{"flowb_manage_strategies", "flowb_generate_traffic"} {
		var schema interface{}
		for _, tl := range resp.Tools {
			if tl.Name == name {
				schema = tl.InputSchema
				break
			}
		}
		if schema == nil {
			t.Fatalf("tool %q not advertised", name)
		}
		b, err := json.Marshal(schema)
		if err != nil {
			t.Fatal(err)
		}
		// 规则写在 config 属性的描述里（结构体 tag），不在工具描述里。
		if !strings.Contains(string(b), "EXACTLY ONE layer key") {
			t.Errorf("%s input schema missing the one-key-per-element rule", name)
		}
	}
}
