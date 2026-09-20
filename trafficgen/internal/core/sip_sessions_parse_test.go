package core

import (
	"encoding/json"
	"strings"
	"testing"
)

// D-SIP-2 补强批红例（9.49 复合编排，T-SIP-87 首跑抓出）：sessions 内
// per-session medias/interleave 必须从层 config 解析——ParseSIPSessions
// 此前只接了 Media 单流，Medias 多流与 Interleave 被静默丢弃（RTP 不发射）。
// parse 层红例（planner 层直构 spec 绕过 parse，测不到此处）。
func TestParseSIPSessionsPerSessionMedias(t *testing.T) {
	raw := `[{"src_port": 22001,
	          "dialog": [{"method": "INVITE", "uri": "sip:conf@20.0.0.1", "emit_media": true}],
	          "medias": [{"direction": "up", "frames": 2}, {"direction": "down", "frames": 2}],
	          "interleave": true}]`
	var arr []interface{}
	if err := json.Unmarshal([]byte(raw), &arr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sess := ParseSIPSessions(arr)
	if len(sess) != 1 {
		t.Fatalf("sessions=%d want 1", len(sess))
	}
	if len(sess[0].Medias) != 2 {
		t.Fatalf("per-session medias=%d want 2 (parse dropped medias)", len(sess[0].Medias))
	}
	if sess[0].Medias[0].Direction != "up" || sess[0].Medias[1].Direction != "down" {
		t.Fatalf("media directions broken: %q/%q", sess[0].Medias[0].Direction, sess[0].Medias[1].Direction)
	}
	if !sess[0].Interleave {
		t.Fatalf("per-session interleave dropped by parse")
	}
	if !strings.Contains(sess[0].Dialog[0].URI, "conf") {
		t.Fatalf("dialog parse broken: %v", sess[0].Dialog)
	}
}
