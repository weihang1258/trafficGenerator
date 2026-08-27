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
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsMalformedWhitelisted(tc.caseID, tc.flag); got != tc.want {
				t.Fatalf("IsMalformedWhitelisted(%q, %q) = %v, want %v", tc.caseID, tc.flag, got, tc.want)
			}
		})
	}
}
