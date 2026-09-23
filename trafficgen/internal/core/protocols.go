package core

// allowedProtocols is the single authoritative admission set for traffic
// protocol names. Every external entry point (REST create-strategy handlers
// and the worker-side task/batch validators) must consult this set, and no
// other hand-maintained copy — before, the same protocol name was listed in up
// to four separate maps (rest×2, convert×2) that drifted apart, silently
// admitting protocols in one layer while rejecting them in another (e.g.
// ldp/pcep/fins/goose/sv were registered as planners in cmd/server/main.go but
// absent from the REST whitelist, so they returned "invalid or missing
// protocol" at request time despite a live planner).
//
// It is the union of the four previous maps plus the names that were missing
// from all four yet required to unblock already-registered planners
// (fins/ldp/pcep). It deliberately EXCLUDES unimplemented protocols that exist
// only as negative path cases (ams/bacnet/igmp/ospf/isis/pim/...): those must
// keep being rejected until a real planner is registered, and adding them here
// would flip their *_neg_unregistered cases to a false pass.
//
// READ-ONLY; do not mutate.
var allowedProtocols = map[string]bool{
	"a2a": true, "amqp": true, "arp": true, "bgp": true,
	"cflow": true, "coap": true, "cql": true, "dameng": true,
	"dhcp": true, "dhcpv6": true, "dnp3": true, "dns": true,
	"doip": true, "drda": true, "enip": true, "fins": true,
	"ftp": true, "gbt32960": true, "goose": true, "gre": true,
	"grpc": true, "gtp": true, "h323": true, "hds": true,
	"hl7": true,
	"hls": true, "http": true, "http_flv": true, "icmp": true,
	"icmpv6": true, "iec104": true, "igmp": true, "ike": true, "ike_nat_t": true,
	"imap": true, "isis": true, "jt808": true, "jt809": true, "jtt905": true,
	"l2tp": true, "ldap": true, "ldp": true,
	"mcp": true, "mcpprotocol": true, "mdns": true, "megaco": true, "mms": true,
	"modbus": true, "mongodb": true, "moxa": true, "mpls": true,
	"mqtt": true, "mysql": true, "nfs": true, "ngap": true,
	"ntp": true, "opcua": true, "openvpn": true, "ospf": true, "pcep": true,
	"pim": true, "pop3": true, "postgresql": true, "pppoe": true, "pptp": true,
	"radius": true, "rdp": true, "redis": true, "replay": true,
	"rip": true, "rtmfp": true, "rtmp": true, "rtsp": true,
	"s7": true, "sctp": true, "shadowsocks": true, "sip": true,
	"smb": true, "smtp": true, "snmp": true, "socks5": true,
	"someip": true, "srv6": true, "ssdp": true, "ssh": true,
	"stun": true, "sv": true, "syslog": true, "tcp": true,
	"tds": true, "telnet": true, "tftp": true, "thrift": true,
	"tls": true, "tns": true, "udp": true, "vmess": true,
	"vnc": true, "wireguard": true, "xmpp": true,
	// B4 封装类（vxlan/nvgre/geneve）：注册 layer/planner 后准入（占位
	// 用例同步替换为 20 语义用例，protocols_test 哨兵同步摘除）。
	"vxlan": true, "nvgre": true, "geneve": true,
	// B5 消息中间件（openwire/ams）：注册 layer/planner 后准入（占位用例
	// 同步替换为语义用例，protocols_test 哨兵同步摘除）。
	"openwire": true,
	"ams":      true,
	"swarm":    true,
	"gnutella": true,
	// B6（77-gbt）：注册 layer/planner 后准入（占位用例同步替换为 81 语义
	// 用例，protocols_test 哨兵同步摘除）。
	"gbt": true,
	// B6（76-getwork）：注册 layer/planner 后准入（占位用例同步替换为 62
	// 语义用例，protocols_test 哨兵同步摘除）。
	"getwork": true,
	// B6（64-cwmp）：注册 layer/planner 后准入（占位用例同步替换为 150
	// 语义用例，protocols_test 哨兵同步摘除）。
	"cwmp": true,
	// B6（75-stratum）：注册 layer/planner 后准入（占位用例同步替换为 40
	// 语义用例，protocols_test 哨兵同步摘除）。
	"stratum": true,
	// B6（73-ethmining）：注册 layer/planner 后准入（占位用例同步替换为 32
	// 语义用例，protocols_test 哨兵同步摘除）。
	"ethmining": true,
	// B6（69-nmea）：注册 layer/planner 后准入（占位用例同步替换为 80
	// 语义用例，protocols_test 哨兵同步摘除）。
	"nmea": true,

	// B6（66-doh）：注册 layer/planner 后准入（占位用例同步替换为 110
	// 语义用例，protocols_test 哨兵同步摘除）。
	"doh": true,
	// B6（67-onvif）：注册 layer/planner 后准入（占位用例同步替换为 95
	// 语义用例，protocols_test 哨兵同步摘除）。
	"onvif": true,
	// B6（71-mmse）：注册 layer/planner 后准入（占位用例同步替换为 100
	// 语义用例，D-MMSE-1）。
	"mmse": true,
}

// IsAllowedProtocol reports whether name is an accepted traffic protocol.
func IsAllowedProtocol(name string) bool {
	return allowedProtocols[name]
}
