package mcp

// 入参类型契约测试：工具声明里写的是什么类型，MCP 的 schema 校验就按什么
// 类型卡，而校验发生在 handler 之前 —— 声明错了，参数对外等于不可用，
// handler 里的正确逻辑永远跑不到。
//
// 2026-11-23 客户端报告问题 2 就是这个形状：run_protocol_case 的 spec_json
// 声明成 json.RawMessage，go-sdk 推出来的 schema 是
// {"type":["null","array"],"items":{"type":"integer","minimum":0,
// "maximum":255}} —— 一个字节数组。于是对象和 JSON 字符串两种自然写法都被
// 拒，只有 byte 数组能过。内部测试一直直接赋结构体字段、从不经过 wire，
// 所以整个测试套件都没发现。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// inputSchemaOf 连上内存传输，取出指定工具的输入 schema 并解成 map。
func inputSchemaOf(t *testing.T, srv *Server, tool string) map[string]interface{} {
	t.Helper()
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	go func() { _ = srv.mcpServer.Run(ctx, st) }()
	sc, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { sc.Close() })
	resp, err := sc.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	for _, tl := range resp.Tools {
		if tl.Name != tool {
			continue
		}
		b, err := json.Marshal(tl.InputSchema)
		if err != nil {
			t.Fatalf("marshal schema: %v", err)
		}
		var m map[string]interface{}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("unmarshal schema: %v", err)
		}
		return m
	}
	t.Fatalf("tool %q not advertised", tool)
	return nil
}

// propertyOf 取出某个入参属性的 schema。
func propertyOf(t *testing.T, schema map[string]interface{}, name string) map[string]interface{} {
	t.Helper()
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("schema has no properties")
	}
	raw, ok := props[name]
	if !ok {
		t.Fatalf("schema has no %q property", name)
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		t.Fatalf("%q property is not an object", name)
	}
	return m
}

// assertObjectProperty 断言属性对外声明为 JSON 对象（不是字符串/数组）。
func assertObjectProperty(t *testing.T, schema map[string]interface{}, name string) {
	t.Helper()
	p := propertyOf(t, schema, name)
	got, _ := p["type"].(string)
	if got != "object" {
		b, _ := json.Marshal(p)
		t.Fatalf("%q is advertised with type %q, want \"object\" — callers sending a "+
			"JSON object will be rejected by schema validation before the handler runs "+
			"(schema: %s)", name, got, b)
	}
	if _, isArray := p["items"]; isArray {
		t.Errorf("%q declares an `items` schema; an object property must not", name)
	}
}

// TestRunProtocolCase_SpecJSONIsObject 覆盖自动生成 schema（结构体 tag）
// 推导出的类型。
func TestRunProtocolCase_SpecJSONIsObject(t *testing.T) {
	srv := newTransportTestServer(t)
	schema := inputSchemaOf(t, srv, "flowb_run_protocol_case")
	assertObjectProperty(t, schema, "spec_json")
}

// TestRunProtocolCase_SpecJSONObjectAccepted 走真实 wire：发一个对象形状的
// spec_json，校验不得在 schema 层就把它打回。这里不关心任务是否成功（测试
// 环境没有该协议的语料），只关心报错**不是**类型校验错误。
func TestRunProtocolCase_SpecJSONObjectAccepted(t *testing.T) {
	srv := newTransportTestServer(t)
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	go func() { _ = srv.mcpServer.Run(ctx, st) }()
	sc, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sc.Close()

	args := map[string]interface{}{
		"case_id": "probe-case",
		"proto":   "arp",
		"spec_json": map[string]interface{}{
			"layers": []interface{}{
				map[string]interface{}{"eth": map[string]interface{}{"src_mac": "aa:bb:cc:dd:ee:01"}},
				map[string]interface{}{"arp": map[string]interface{}{"operation": 1}},
			},
		},
		"output_type": "pcap",
		// 本测试只关心 schema 层放不放行，不关心任务跑多久 —— 1 秒超时
		// 让它尽快进终态。
		"timeout_s": 1,
	}
	res, err := sc.CallTool(ctx, &mcp.CallToolParams{Name: "flowb_run_protocol_case", Arguments: args})
	if err != nil {
		// 业务错误（例如语料缺失）是正常结果；类型校验错误不是。
		if strings.Contains(err.Error(), "properties/spec_json") {
			t.Fatalf("spec_json object rejected by schema validation: %v", err)
		}
		return
	}
	if res != nil && res.IsError {
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok && strings.Contains(tc.Text, "properties/spec_json") {
				t.Fatalf("spec_json object rejected by schema validation: %s", tc.Text)
			}
		}
	}
}

// TestRunProtocolCase_SpecJSONStringRejected 断言字符串形式被明确拒绝，且
// 错误信息说的是"要 object"——不是反过来要求字节数组。
func TestRunProtocolCase_SpecJSONStringRejected(t *testing.T) {
	srv := newTransportTestServer(t)
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	go func() { _ = srv.mcpServer.Run(ctx, st) }()
	sc, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sc.Close()

	args := map[string]interface{}{
		"case_id":   "probe-case",
		"proto":     "arp",
		"spec_json": `{"layers":[{"arp":{}}]}`,
	}
	res, err := sc.CallTool(ctx, &mcp.CallToolParams{Name: "flowb_run_protocol_case", Arguments: args})
	if err == nil && (res == nil || !res.IsError) {
		t.Fatalf("a JSON *string* was accepted for spec_json; it must be a JSON object")
	}
	if err != nil && !strings.Contains(err.Error(), "properties/spec_json") {
		return // 业务错误，不是 schema 拦截
	}
	msg := ""
	if res != nil {
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				msg += tc.Text
			}
		}
	}
	if msg != "" && !strings.Contains(msg, `want "object"`) {
		t.Fatalf("rejection message does not tell the caller to send an object: %s", msg)
	}
}
