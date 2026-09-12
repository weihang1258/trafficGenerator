package ftp

import (
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// D-FTP-4 T-FTP-19/20 failing-first：EPSV/EPRT 信令端口解析。
// 现状 parsePASVPort/parsePORTPort 对 229/EPRT 行返回 0（探针实测）。
func TestParseEPSVPort(t *testing.T) {
	cases := []struct {
		name     string
		response string
		want     uint16
	}{
		{"standard", "229 Entering Extended Passive Mode (|||50010|)", 50010},
		{"high_port", "229 Entering Extended Passive Mode (|||65535|)", 65535},
		{"low_port", "229 Entering Extended Passive Mode (|||1|)", 1},
		{"no_tuple", "229 Entering Extended Passive Mode", 0},
		{"empty", "", 0},
		{"overflow", "229 Entering Extended Passive Mode (|||99999999999999999999|)", 0},
		{"not_229", "227 Entering Passive Mode (20,0,0,1,195,80)", 0},
		{"multiline_continuation", "229-Welcome\r\n229 Entering Extended Passive Mode (|||50010|)", 50010},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseEPSVPort(tc.response); got != tc.want {
				t.Errorf("parseEPSVPort(%q)=%d, want %d", tc.response, got, tc.want)
			}
		})
	}
}

func TestParseEPRTPort(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want uint16
	}{
		{"v6_standard", "EPRT |2|2001:db8::1|50011|", 50011},
		{"v6_high", "EPRT |2|::1|65535|", 65535},
		{"v4_af1_not_supported", "EPRT |1|10,0,0,1|50011|", 0}, // af=1 记 C 类不做
		{"bad_af", "EPRT |3|2001:db8::1|50011|", 0},
		{"missing_segment", "EPRT |2|2001:db8::1|", 0},
		{"overflow", "EPRT |2|2001:db8::1|99999999999999999999|", 0},
		{"lowercase", "eprt |2|2001:db8::1|50011|", 50011},
		{"no_match", "PORT 10,0,0,1,78,17", 0},
		{"empty", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseEPRTPort(tc.cmd); got != tc.want {
				t.Errorf("parseEPRTPort(%q)=%d, want %d", tc.cmd, got, tc.want)
			}
		})
	}
}

func TestScanTxForDataPort_EPSVEPRT(t *testing.T) {
	epsv := []core.FTPCommand{
		{Cmd: "EPSV", Response: "229 Entering Extended Passive Mode (|||50010|)"},
	}
	if got := scanTxForDataPort(epsv, false); got != 50010 {
		t.Errorf("passive EPSV scan = %d, want 50010", got)
	}
	eprt := []core.FTPCommand{
		{Cmd: "EPRT |2|2001:db8::1|50011|", Response: "200 EPRT ok"},
	}
	if got := scanTxForDataPort(eprt, true); got != 50011 {
		t.Errorf("active EPRT scan = %d, want 50011", got)
	}
	// last-wins：同事务 227+229 并存时后者赢。
	both := []core.FTPCommand{
		{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,80)"},
		{Cmd: "EPSV", Response: "229 Entering Extended Passive Mode (|||50010|)"},
	}
	if got := scanTxForDataPort(both, false); got != 50010 {
		t.Errorf("passive last-wins = %d, want 50010", got)
	}
}
