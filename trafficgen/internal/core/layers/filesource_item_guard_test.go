package layers_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// 第11轮反馈 1：item 级 file_source 未知键必须在 create 校验即报——
// 此前顶层已报但嵌套 item（goose.data[]/mqtt.messages[] 等）仍静默吞。
func TestFileSourceItemLevelUnknownKeyRejected(t *testing.T) {
	cases := []struct{ name, proto, chain string }{
		{"goose.data[]", "goose", `[{"eth":{}},{"goose":{"gocb_ref":"C","dat_set":"D","tal_ms":1,"conf_rev":1,"data":[{"type":"octet_string","file_source":{"zzz_bogus":"x"}}]}}]`},
		{"mqtt.messages[]", "mqtt", `[{"ip":{}},{"tcp":{}},{"mqtt":{"messages":[{"topic":"t","file_source":{"zzz_bogus":"x"}}]}}]`},
		{"imap.commands[]", "imap", `[{"ip":{}},{"tcp":{}},{"imap":{"commands":[{"cmd":"A001 LOGIN u p","file_source":{"zzz_bogus":"x"}}]}}]`},
		{"rtmp.data[]", "rtmp", `[{"ip":{}},{"rtmp":{"data":[{"direction":"up","file_source":{"zzz_bogus":"x"}}]}}]`},
		{"socks5.data[]", "socks5", `[{"ip":{}},{"tcp":{}},{"socks5":{"data":[{"direction":"up","file_source":{"zzz_bogus":"x"}}]}}]`},
		{"xmpp.messages[]", "xmpp", `[{"ip":{}},{"tcp":{}},{"xmpp":{"messages":[{"direction":"up","file_source":{"zzz_bogus":"x"}}]}}]`},
		{"rdp.data_events[]", "rdp", `[{"ip":{}},{"tcp":{}},{"rdp":{"data_events":[{"type":"cliprdr_format_list","channel":"cliprdr","file_source":{"zzz_bogus":"x"}}]}}]`},
		{"sctp.chunks[]", "sctp", `[{"ip":{}},{"sctp":{"chunks":[{"tsn":1,"file_source":{"zzz_bogus":"x"}}]}}]`},
		{"sip.media", "sip", `[{"ip":{}},{"udp":{}},{"sip":{"dialog":[{"method":"INVITE","direction":"up","emit_media":true}],"media":{"enabled":true,"file_source":{"zzz_bogus":"x"}}}}]`},
		{"顶层对照（已生效）", "http", `[{"ip":{}},{"tcp":{}},{"http":{"method":"POST","uri":"/u","file_source":{"zzz_bogus":"x"}}}]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := layers.ValidateLayers(json.RawMessage(c.chain), c.proto)
			if err == nil || !strings.Contains(err.Error(), "zzz_bogus") {
				t.Fatalf("item 级未知键应报错点名 zzz_bogus, got %v", err)
			}
		})
	}
}
