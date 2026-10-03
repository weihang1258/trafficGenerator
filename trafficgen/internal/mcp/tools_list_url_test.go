package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// 工具暴露面按传输通道实时生成（用户裁定，规则 13.27 延伸）：
//   - HTTP：tools/list 时按请求 scheme://host[:port] 注入上传端点的**具体
//     URL**——客户端的大模型不知道自己的连接地址，描述里给拼装示例是大忌；
//   - stdio：同宿客户端只用 file_path，不注入上传提示（无 HTTP 端点可指）。
//   - 上传端点无鉴权（key 不会给到模型；资产 UUID 即能力凭证，与下载同款）。

// TestToolsListHTTPInjectsConcreteUploadURL：HTTP 拉取 tools/list，描述里
// 必须是可照抄的具体 URL（含本请求的 host:port），无任何鉴权头字样。
func TestToolsListHTTPInjectsConcreteUploadURL(t *testing.T) {
	env := setupMCPTest(t)
	ts, session := newHTTPTestServer(t, env, "test-key", nil)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	var desc string
	for _, tl := range res.Tools {
		if tl.Name == "flowb_manage_pcaps" {
			desc = tl.Description
		}
	}
	if desc == "" {
		t.Fatalf("flowb_manage_pcaps not in tools/list")
	}
	if !strings.Contains(desc, ts.URL+"/uploads/pcaps") {
		t.Errorf("description lacks concrete upload URL %s:\n%s", ts.URL+"/uploads/pcaps", desc)
	}
	if strings.Contains(desc, "{{") || strings.Contains(desc, "scheme://host") {
		t.Errorf("description contains assembly placeholder (大忌):\n%s", desc)
	}
	if strings.Contains(desc, "X-MCP-Key") {
		t.Errorf("upload hint mentions an auth key the model can never have:\n%s", desc)
	}
}

// TestToolsListStdioNoUploadHint：stdio（无 HTTP 请求上下文）描述里不得
// 出现上传端点——同宿客户端没有可指的地址，file_path 即全部。
func TestToolsListStdioNoUploadHint(t *testing.T) {
	env := setupMCPTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	_, err := env.srv.MCP().Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	for _, tl := range res.Tools {
		if tl.Name == "flowb_manage_pcaps" && strings.Contains(tl.Description, "/uploads/pcaps") {
			t.Errorf("stdio description carries upload hint without a resolvable base:\n%s", tl.Description)
		}
	}
}

// TestUploadEndpointNoAuth：上传端点挂载后无 X-MCP-Key 也能用（key 不会
// 给到模型）；非 POST 仍 405。
func TestUploadEndpointNoAuth(t *testing.T) {
	env := setupMCPTest(t)
	hs, err := NewHTTPServer(env.srv, "127.0.0.1:0", "some-key", nil)
	if err != nil {
		t.Fatalf("new http server: %v", err)
	}
	ts := httptest.NewServer(hs.srv.Handler)
	defer ts.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "up.pcap")
	if err != nil {
		t.Fatal(err)
	}
	pcapPath := filepath.Join(t.TempDir(), "up.pcap")
	writeTestPcap(t, pcapPath)
	b, err := os.ReadFile(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	fw.Write(b)
	mw.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/uploads/pcaps", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	// 故意不带任何鉴权头。
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("no-auth upload status = %d, want 200: %s", resp.StatusCode, b)
	}
	var asset map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&asset); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if id, _ := asset["ID"].(string); id == "" {
		t.Errorf("asset ID missing: %v", asset)
	}

	getResp, err := http.Get(ts.URL + "/uploads/pcaps")
	if err != nil {
		t.Fatal(err)
	}
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", getResp.StatusCode)
	}
}

// 提示注入必须无状态：SDK 的 tools/list 返回注册时共享的 Tool 指针，
// 直接 += 会把提示累积写回共享状态（第二次拉取翻倍）。连续两次拉取，
// 第二次的提示必须恰好一次。
func TestToolsListHintNotAccumulated(t *testing.T) {
	env := setupMCPTest(t)
	ts, session := newHTTPTestServer(t, env, "test-key", nil)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	count := func() int {
		res, err := session.ListTools(ctx, nil)
		if err != nil {
			t.Fatalf("list tools: %v", err)
		}
		for _, tl := range res.Tools {
			if tl.Name == "flowb_manage_pcaps" {
				return strings.Count(tl.Description, "/uploads/pcaps")
			}
		}
		t.Fatal("manage_pcaps missing")
		return 0
	}
	if n := count(); n != 1 {
		t.Fatalf("first tools/list: hint count = %d, want 1", n)
	}
	if n := count(); n != 1 {
		t.Fatalf("second tools/list: hint count = %d, want 1 (shared Tool state must not accumulate)", n)
	}
}
