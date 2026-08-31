package pcaptest

import "testing"

func TestIsMalformedWhitelistedScopesProtocolCasesAndFlags(t *testing.T) {
	tests := []struct {
		name   string
		caseID string
		flag   string
		want   bool
	}{
		{"known rtmp artifact", "rtmp-connect-play-basic", "Loop in AMF dissection", true},
		{"unknown rtmp case", "rtmp-future-case", "Loop in AMF dissection", false},
		{"wrong rtmp malformed flag", "rtmp-connect-play-basic", "[Malformed Packet: TCP]", false},
		{"composite rtmp malformed flag", "rtmp-connect-play-basic", "Loop in AMF dissection; unexpected bytes", false},
		{"known xmpp artifact", "xmpp-stream-basic", "Closing an unopened tag", true},
		{"known tls artifact", "tls-handshake-basic", "[Malformed Packet: TLS]", true},
		// J 组 over-TLS 用例的伪影渲染在多次生成间不稳定（单条 BER Error /
		// 多条逗号拼接 / 泛化 "Malformed Packet (Exception occurred)"），
		// 逐次实际捕获的值都要命中。
		{"tls single BER error", "pop3_over_tls", "BER Error: Sequence expected but class:CONTEXT(2) Primitive tag:27 was unexpected", true},
		{"tls multi-expert BER errors", "pop3_over_tls",
			"BER Error: Wrong field in SEQUENCE: expected class:UNIVERSAL(0) tag:16(SEQUENCE) but found class:UNIVERSAL(0) tag:18,BER Error: SEQUENCE is 12 too many bytes long", true},
		{"tls flag with ws suffix", "mqtt_over_tls", "[Malformed Packet: TLS],_ws.malformed", true},
		{"tls multi-expert on socks5", "socks5_over_tls",
			"BER Error: Wrong field in SEQUENCE: expected class:UNIVERSAL(0) tag:16(SEQUENCE) but found class:CONTEXT(2) tag:0,BER Error: SEQUENCE is 6 too many bytes long", true},
		{"tls generic exception flag", "mqtt_over_tls", "_ws.malformed", false},
		{"tls BER error on non-whitelisted case", "ftps_over_tls", "BER Error: Wrong field in SEQUENCE", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsMalformedWhitelisted(tc.caseID, tc.flag); got != tc.want {
				t.Fatalf("IsMalformedWhitelisted(%q, %q) = %v, want %v", tc.caseID, tc.flag, got, tc.want)
			}
		})
	}
}
