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
		"a2a", "amqp", "arp", "bacnet", "bgp", "cflow", "coap", "cql", "dameng",
		"dhcp", "dhcpv6", "dnp3", "dns", "doip", "drda", "enip", "fins",
		"ftp", "gbt32960", "goose", "gre", "grpc", "gtp", "h323", "hds",
		"hl7", "hls", "http", "http_flv", "icmp", "icmpv6", "iec104", "igmp", "ike",
		"ike_nat_t", "imap", "isis", "jt808", "jt809", "jtt905", "l2tp",
		"ldap", "ldp", "mcp", "mcpprotocol", "mdns", "megaco", "mms", "modbus",
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
		// 66-doh：layer/planner 注册后准入（占位用例同步替换为 110 语义用例）。
		"doh",
		// 67-onvif：layer/planner 注册后准入（占位用例同步替换为 95 语义用例）。
		"onvif",
		// 64-cwmp：layer/planner 注册后准入（占位用例同步替换为 150 语义用例）。
		"cwmp",
		// 71-mmse（D-MMSE-1）：layer/planner 注册后准入（占位用例同步替换
		// 为 100 语义用例）。
		"mmse",
		// 72-edp（D-EDP-1）：layer/planner 注册后准入（占位用例同步替换
		// 为 89 语义用例）。
		"edp",
		// 74-xmrmining（D-XMR-1）：layer/planner 注册后准入（占位用例同步
		// 替换为 64 语义用例）。
		"xmrmining",
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
		// D-KINGBASE-1 裁定1：协议身份退役（唯一形态 = postgresql 层
		// dialect=kingbase）——must remain rejected，防复活。
		"kingbase",
		// D-BACNET-1：bacnet 已注册 layer/planner，摘出 negativeOnly
		// （97 语义用例落地——契约 §1）。edp/mmse/hl7/megaco 先例。
		"dcerpc", "dtls",
		// D-EDP-1：edp 已注册 layer/planner，摘出 negativeOnly（89 语义
		// 用例落地，占位例随之移除——契约 §1）。mmse/hl7/megaco 先例。
		// D-MMSE-1：mmse 已注册 layer/planner，摘出 negativeOnly（100 语义
		// 用例 P5 落地，占位例随之移除——契约 §1）。hl7/megaco 先例。
		"kerberos", "ntlm", "ocsp",
		"spnego", "sstp",
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
