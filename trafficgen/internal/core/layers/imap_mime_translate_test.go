package layers_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// D-IMAP-1 P5 修复：层翻译分支（translateTerminalConfig case "imap"）经
// JSON 往返解码进 core.IMAPConfig；IMAPAttachment.Data 是 []byte，JSON
// 语义下只认 base64 文本——附件 "data" 裸文本（如 "up-body"）非法 base64
// 即整包解码失败，spec.IMAP 留 nil，生成器走默认空会话（T-051/52/80 实测
// 7 包空流）。mime_body 经链即死，扁平同输入却正常（parseIMAPMIMEBody
// 直解 []byte(raw)），层/扁平双轨分叉。
//
// 本文件三测试：A/B 走 BuildLayersPlanner→Plan 黑盒（失败先行，当前红）；
// C 锁扁平真相（当前绿，修后回归锚）。

// imapWireDown 用层链 JSON 走完整 ChainPlanner→Plan，返回全部下行载荷拼接。
func imapWireDown(t *testing.T, imapCfg map[string]interface{}) string {
	t.Helper()
	chain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 14000, "dst_port": 143}},
		map[string]interface{}{"imap": imapCfg},
	}
	raw, err := json.Marshal(chain)
	if err != nil {
		t.Fatalf("marshal chain: %v", err)
	}
	p, err := layers.BuildLayersPlanner("imap", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 14000, DstPort: 143}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var b strings.Builder
	for pkt := range ch {
		if pkt.Direction == "down" {
			b.Write(pkt.Payload)
		}
	}
	return b.String()
}

func mimeFetchCmd(mime map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"tag": "A003", "cmd": "FETCH 1 BODY[]",
		"responses": []interface{}{"* 1 FETCH (BODY[] {0})", "A003 OK FETCH completed"},
		"mime_body": mime,
	}
}

// A【层/扁平分叉】：附件 "data" 裸文本经层链必须存活（base64 编码上線）。
func TestTranslate_MIMEDataTextSurvives(t *testing.T) {
	mime := map[string]interface{}{
		"headers": []interface{}{"From: a@b.c"}, "boundary": "b-159", "text": "up",
		"attachments": []interface{}{map[string]interface{}{
			"filename": "u.txt", "content_type": "text/plain", "data": "up-body",
		}},
	}
	wire := imapWireDown(t, map[string]interface{}{
		"banner": "* OK IMAP ready",
		"commands": []interface{}{
			map[string]interface{}{"tag": "A001", "cmd": "LOGIN alice secret", "responses": []interface{}{"A001 OK LOGIN completed"}},
			mimeFetchCmd(mime),
		},
	})
	if !strings.Contains(wire, `filename="u.txt"`) {
		t.Fatalf("layer mime_body dropped (want attachment filename on wire), down=%q", wire)
	}
	want := base64.StdEncoding.EncodeToString([]byte("up-body"))
	if !strings.Contains(wire, want) {
		t.Fatalf("layer mime_body data lost (want base64 %q on wire), down=%q", want, wire)
	}
}

// B【data_b64 语义对齐】：长 data_b64 经 constructMIMEBody 按 RFC 2045
// §6.8 折 76 行后上線（imap 构造器 wrapBase64：行间插 CRLF；与 SMTP
// DataB64 逐字对照——那是 smtp 构造器语义，本协议以自家构造器为准）。
// 断：附件文件名在線 + 去 CRLF 拼回后与输入逐字一致。
func TestTranslate_MIMEDataB64Verbatim(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("A", 200)))
	if len(b64) < 76 || strings.Contains(b64, "\r\n") {
		t.Fatalf("bad fixture: want single-line b64 >76 chars, got len=%d", len(b64))
	}
	mime := map[string]interface{}{
		"headers": []interface{}{"From: a@b.c"}, "boundary": "b-200", "text": "big",
		"attachments": []interface{}{map[string]interface{}{
			"filename": "big.bin", "content_type": "application/octet-stream", "data_b64": b64,
		}},
	}
	wire := imapWireDown(t, map[string]interface{}{
		"banner": "* OK IMAP ready",
		"commands": []interface{}{
			map[string]interface{}{"tag": "A001", "cmd": "LOGIN alice secret", "responses": []interface{}{"A001 OK LOGIN completed"}},
			mimeFetchCmd(mime),
		},
	})
	if !strings.Contains(wire, `filename="big.bin"`) {
		t.Fatalf("layer mime_body dropped (want attachment filename on wire)")
	}
	flat := strings.ReplaceAll(wire, "\r\n", "")
	if !strings.Contains(flat, b64) {
		t.Fatalf("layer data_b64 content lost after CRLF-strip (want %d-char string), wire=%q", len(b64), wire)
	}
}

// C【扁平真相锚】：同输入走扁平 parse，data 裸文本即 []byte(raw)（修后回归锚）。
func TestParse_MIMEDataTextDecodes(t *testing.T) {
	spec := core.MapToFlowSpec(map[string]interface{}{
		"imap": map[string]interface{}{
			"commands": []interface{}{map[string]interface{}{
				"tag": "A003", "cmd": "FETCH 1 BODY[]",
				"responses": []interface{}{"* 1 FETCH (BODY[] {0})"},
				"mime_body": map[string]interface{}{
					"attachments": []interface{}{map[string]interface{}{
						"filename": "u.txt", "content_type": "text/plain", "data": "up-body",
					}},
				},
			}},
		},
	}, "imap")
	if len(spec.ValidationErrors) > 0 {
		t.Fatalf("ValidationErrors: %v", spec.ValidationErrors)
	}
	if spec.IMAP == nil || len(spec.IMAP.Commands) != 1 {
		t.Fatalf("flat parse lost commands: %+v", spec.IMAP)
	}
	mb := spec.IMAP.Commands[0].MIMEBody
	if mb == nil || len(mb.Attachments) != 1 {
		t.Fatalf("flat parse lost mime_body: %+v", spec.IMAP.Commands[0])
	}
	if got := string(mb.Attachments[0].Data); got != "up-body" {
		t.Fatalf("flat data = %q, want %q", got, "up-body")
	}
}
