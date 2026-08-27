package pcaptest

import (
	"os"
	"strings"
	"testing"
)

func TestCheckExpertInfoKnownDissectorArtifacts(t *testing.T) {
	tests := []struct {
		caseID string
		path   string
	}{
		{"rtmp-connect-play-basic", "/tmp/mcp-pcaps/rtmp/rtmp-connect-play-basic.pcap"},
		{"xmpp-stream-basic", "/tmp/mcp-pcaps/xmpp/xmpp-stream-basic.pcap"},
		{"tls-handshake-basic", "/tmp/mcp-pcaps/tls/tls-handshake-basic.pcap"},
	}
	for _, tc := range tests {
		t.Run(tc.caseID, func(t *testing.T) {
			if _, err := os.Stat(tc.path); err != nil {
				t.Skipf("pcap not present: %s", tc.path)
			}
			if problems := CheckExpertInfo(tc.path, tc.caseID, nil); len(problems) != 0 {
				t.Fatalf("known dissector artifact was not whitelisted: %s", strings.Join(problems, "; "))
			}
		})
	}
}
