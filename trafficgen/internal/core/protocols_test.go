package core

import (
	"sort"
	"testing"
)

// TestAllowedProtocolsStable locks the authoritative admission set. It exists
// so the single source cannot drift silently: if a future change adds or
// removes a name, this test forces the maintainer to update the expected list
// here too, which documents the intent (a new protocol is being admitted, or a
// negative-only placeholder is rightly being re-categorized).
//
// Update this list deliberately alongside allowedProtocols. Do not add names
// for protocols that are still negative-only placeholders (ams/bacnet/igmp/
// ospf/isis/pim/...) — they must keep being rejected until a real planner is
// registered, else their *_neg_unregistered cases flip to a false pass.
func TestAllowedProtocolsStable(t *testing.T) {
	want := []string{
		"a2a", "amqp", "arp", "bgp", "cflow", "coap", "cql", "dameng",
		"dhcp", "dhcpv6", "dnp3", "dns", "doip", "drda", "enip", "fins",
		"ftp", "gbt32960", "goose", "gre", "grpc", "gtp", "h323", "hds",
		"hls", "http", "http_flv", "icmp", "icmpv6", "iec104", "igmp", "ike",
		"ike_nat_t", "imap", "isis", "jt808", "jt809", "jtt905", "kingbase", "l2tp",
		"ldap", "ldp", "mcp", "mcpprotocol", "mdns", "mms", "modbus",
		"mongodb", "moxa", "mpls", "mqtt", "mysql", "nfs", "ngap", "ntp",
		"opcua", "openvpn", "ospf", "pcep", "pim", "pop3", "postgresql", "pppoe", "pptp",
		"radius", "rdp", "redis", "replay", "rip", "rtmfp", "rtmp", "rtsp",
		"s7", "sctp", "shadowsocks", "sip", "smb", "smtp", "snmp", "socks5",
		"someip", "srv6", "ssdp", "ssh", "stun", "sv", "syslog", "tcp",
		"tds", "telnet", "tftp", "thrift", "tls", "tns", "udp", "vmess",
		"vnc", "wireguard", "xmpp",
		// B4 封装类：layer/planner 注册后准入（占位用例同步替换）。
		"vxlan", "nvgre", "geneve",
		// B5 消息中间件：layer/planner 注册后准入（占位用例同步替换）。
		"openwire", "ams", "swarm", "gnutella",
		// B6（77-gbt）：layer/planner 注册后准入（占位用例同步替换）。
		"gbt",
		// B6（76-getwork）：layer/planner 注册后准入（占位用例同步替换）。
		"getwork",
		// B6（75-stratum）：layer/planner 注册后准入（占位用例同步替换）。
		"stratum",
		// 73-ethmining：layer/planner 注册后准入（占位用例同步替换为 32 语义用例）。
		"ethmining",
		// 69-nmea：layer/planner 注册后准入（占位用例同步替换为 80 语义用例）。
		"nmea",
		// 64-cwmp：layer/planner 注册后准入（占位用例同步替换为 150 语义用例）。
		"cwmp",
	}
	sort.Strings(want)

	got := make([]string, 0, len(want))
	for k := range allowedProtocols {
		got = append(got, k)
	}
	sort.Strings(got)

	if len(got) != len(want) {
		t.Fatalf("allowedProtocols has %d entries, expected %d\nmissing: %v\nextra: %v",
			len(got), len(want), diff(want, got), diff(got, want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("allowedProtocols mismatch at %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// TestNegativeOnlyPlaceholdersRejected ensures protocols that exist ONLY as
// negative-path placeholders (unimplemented, *_neg_unregistered) are NOT
// admitted. This is the guard that keeps a half-implemented protocol from
// flipping its "should be rejected" case to a false pass.
func TestNegativeOnlyPlaceholdersRejected(t *testing.T) {
	negativeOnly := []string{
		"bacnet", "dcerpc", "doh", "dtls", "edp",
		"hl7",
		"kerberos", "megaco", "mmse", "ntlm", "ocsp",
		"onvif", "spnego", "sstp",
		"xmrmining",
	}
	for _, name := range negativeOnly {
		if IsAllowedProtocol(name) {
			t.Errorf("%s is a negative-only placeholder and must remain rejected, but IsAllowedProtocol returned true", name)
		}
	}
	if IsAllowedProtocol("nosuchproto") {
		t.Errorf("nosuchproto must remain rejected")
	}
}

func diff(a, b []string) []string {
	ab := map[string]bool{}
	for _, x := range a {
		ab[x] = true
	}
	var out []string
	for _, x := range b {
		if !ab[x] {
			out = append(out, x)
		}
	}
	return out
}
