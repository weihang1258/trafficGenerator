package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/grpc"
	_ "github.com/trafficgen/trafficgen/internal/protocol/gtp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ike"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ike_nat_t"
	_ "github.com/trafficgen/trafficgen/internal/protocol/imap"
	_ "github.com/trafficgen/trafficgen/internal/protocol/l2tp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mysql"
	_ "github.com/trafficgen/trafficgen/internal/protocol/openvpn"
	_ "github.com/trafficgen/trafficgen/internal/protocol/pop3"
	_ "github.com/trafficgen/trafficgen/internal/protocol/rdp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/redis"
	_ "github.com/trafficgen/trafficgen/internal/protocol/shadowsocks"
	_ "github.com/trafficgen/trafficgen/internal/protocol/smtp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ssh"
	_ "github.com/trafficgen/trafficgen/internal/protocol/vmess"
	_ "github.com/trafficgen/trafficgen/internal/protocol/wireguard"
)

// TestChainEquivalence_Batch2 verifies that for the 16 smoke-only protocols
// (chain generator exists, main.go still registers legacy), the chain path
// produces structurally identical output to the legacy path from the same
// (mapToFlowSpec-preprocessed) FlowSpec. This is the evidence gate for the
// T4.1 batch-2 flip: a protocol must pass here BEFORE its main.go
// registration is switched to NewChainPlanner.
//
// Each spec is built via the flat cfg → mapToFlowSpec pipeline (the same
// path the API uses for every task), then both NewChainPlanner(name).Plan
// and <name>.NewPlanner().Plan receive the result. Schema defaults
// (DstPort, TCP sub-config, MSS, etc.) thus apply symmetrically.
func TestChainEquivalence_Batch2(t *testing.T) {
	cases := []struct {
		proto      string
		flat       map[string]interface{}
		legacyPlan func(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error)
	}{
		{
			proto: "grpc",
			flat: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				// 显式 dst_port 8604：避免 universal-default 兜底分歧（链路
				// 默认 8604，legacy spec.DstPort=80 直传，端口默认行为由
				// flat_dstport_default_test.go 锁定）。
				"dst_port": float64(8604),
				"tcp": map[string]interface{}{
					"initial_seq": float64(1000),
				},
				"grpc": map[string]interface{}{
					"service": "telemetry.Telemetry",
					"method":  "Subscribe",
					"request_messages": []interface{}{
						[]interface{}{float64(0x0a), float64(0x01), float64(0x01)},
					},
				},
			},
			legacyPlan: grpcPlan,
		},
		{
			proto: "gtp",
			flat: map[string]interface{}{
				"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
				// 显式 dst_port：universal-default 兜底修复后链路对裸配置
				// 默认 2152（legacy gtp planner 无 dst_port==0→DefaultPort
				// 之外的默认，mapToFlowSpec 泄漏的 80 双方曾同为 80）。
				// 端口默认行为由 flat_dstport_default_test.go 单独锁定。
				"dst_port": float64(2152),
				"gtp":      map[string]interface{}{"mode": "u", "version": float64(1), "teid": float64(0x1234)},
			},
			legacyPlan: gtpPlan,
		},
		{
			proto: "ike",
			flat: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				// 显式 dst_port 500：避免 universal-default 兜底分歧（链路
				// 默认 500，legacy spec.DstPort=80 直传，端口默认行为由
				// flat_dstport_default_test.go 锁定）。
				"dst_port": float64(500),
				"tcp":      map[string]interface{}{"initial_seq": float64(1000)},
				"ike":      map[string]interface{}{"role": "initiator"},
			},
			legacyPlan: ikePlan,
		},
		{
			proto: "l2tp",
			flat: map[string]interface{}{
				"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
				"src_port": float64(1701), "dst_port": float64(1701),
				"tcp":  map[string]interface{}{"initial_seq": float64(1000)},
				"l2tp": map[string]interface{}{"role": "lac", "scenario": "tunnel_with_data"},
			},
			legacyPlan: l2tpPlan,
		},
		{
			proto: "mysql",
			flat: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				// 显式 dst_port 3306：避免 universal-default 兜底分歧（链路
				// 默认 3306，legacy spec.DstPort=80 直传，端口默认行为由
				// flat_dstport_default_test.go 锁定）。
				"dst_port": float64(3306),
				"tcp":      map[string]interface{}{"initial_seq": float64(1000)},
				"mysql": map[string]interface{}{
					"username": "root",
					"commands": []interface{}{map[string]interface{}{"opcode": float64(0x01), "body": ""}},
				},
			},
			legacyPlan: mysqlPlan,
		},
		{
			proto: "openvpn",
			flat: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				// 显式 dst_port 1194：避免 universal-default 兜底分歧（链路
				// 默认 1194，legacy spec.DstPort=80 直传，端口默认行为由
				// flat_dstport_default_test.go 锁定）。
				"dst_port": float64(1194),
				"tcp":      map[string]interface{}{"initial_seq": float64(1000)},
				"openvpn":  map[string]interface{}{},
			},
			legacyPlan: openvpnPlan,
		},
		{
			proto: "pop3",
			flat: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				// 显式 dst_port 110：避免 universal-default 兜底分歧（链路
				// 默认 110，legacy spec.DstPort=80 直传，端口默认行为由
				// flat_dstport_default_test.go 锁定）。
				"dst_port": float64(110),
				"tcp":      map[string]interface{}{"initial_seq": float64(1000)},
				"pop3": map[string]interface{}{
					"banner": "+OK POP3 server ready",
					"commands": []interface{}{
						map[string]interface{}{"cmd": "USER alice", "response": "+OK"},
						map[string]interface{}{"cmd": "PASS secret", "response": "+OK"},
						map[string]interface{}{"cmd": "QUIT", "response": "+OK"},
					},
				},
			},
			legacyPlan: pop3Plan,
		},
		{
			proto: "imap",
			flat: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				// 显式 dst_port 143：避免 universal-default 兜底分歧（链路
				// 默认 143，legacy spec.DstPort=80 直传，端口默认行为由
				// flat_dstport_default_test.go 锁定）。
				"dst_port": float64(143),
				"tcp":      map[string]interface{}{"initial_seq": float64(1000)},
				"imap": map[string]interface{}{
					"banner": "* OK IMAP4rev1 ready",
					"commands": []interface{}{
						map[string]interface{}{"tag": "A001", "cmd": "LOGIN alice secret", "responses": []interface{}{"A001 OK LOGIN completed"}},
						map[string]interface{}{"cmd": "NOOP", "responses": []interface{}{"A002 OK NOOP completed"}},
					},
				},
			},
			legacyPlan: imapPlan,
		},
		{
			proto: "rdp",
			flat: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				// 显式 dst_port 3389：避免 universal-default 兜底分歧（链路
				// 默认 3389，legacy spec.DstPort=80 直传，端口默认行为由
				// flat_dstport_default_test.go 锁定）。
				"dst_port": float64(3389),
				"tcp":      map[string]interface{}{"initial_seq": float64(1000)},
				"rdp":      map[string]interface{}{"scenario": "full_session"},
			},
			legacyPlan: rdpPlan,
		},
		{
			proto: "redis",
			flat: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				// 显式 dst_port 6379：避免 universal-default 兜底分歧（链路
				// 默认 6379，legacy spec.DstPort=80 直传，端口默认行为由
				// flat_dstport_default_test.go 锁定）。
				"dst_port": float64(6379),
				"tcp":      map[string]interface{}{"initial_seq": float64(1000)},
				"redis": map[string]interface{}{
					"commands": []interface{}{map[string]interface{}{"args": []interface{}{"PING"}, "auto_reply": "pong"}},
				},
			},
			legacyPlan: redisPlan,
		},
		{
			proto: "shadowsocks",
			flat: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				// 显式 dst_port 8388：避免 universal-default 兜底分歧（链路
				// 默认 8388，legacy planner spec.DstPort=80 直传，端口默认
				// 行为由 flat_dstport_default_test.go 锁定）。
				"dst_port":    float64(8388),
				"tcp":         map[string]interface{}{"initial_seq": float64(1000)},
				"shadowsocks": map[string]interface{}{},
			},
			legacyPlan: shadowsocksPlan,
		},
		{
			proto: "smtp",
			flat: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(50000),
				"dst_port": float64(25),
				"tcp":      map[string]interface{}{"initial_seq": float64(1000)},
				"smtp": map[string]interface{}{
					"banner": "220 mail.example.org ESMTP",
					"dialog": []interface{}{
						map[string]interface{}{"cmd": "HELO client.example.org", "response": "250 mail.example.org"},
						map[string]interface{}{"cmd": "QUIT", "response": "221 2.0.0 Bye"},
					},
				},
			},
			legacyPlan: smtpPlan,
		},
		{
			proto: "ssh",
			flat: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				// 显式 dst_port 22：避免 universal-default 兜底分歧（链路默认
				// 22，legacy spec.DstPort=80 直传，端口默认行为由
				// flat_dstport_default_test.go 锁定）。
				"dst_port": float64(22),
				"tcp":      map[string]interface{}{"initial_seq": float64(1000)},
				"ssh": map[string]interface{}{
					"scenario":       "exec",
					"client_version": "SSH-2.0-trafficgen_test",
				},
			},
			legacyPlan: sshPlan,
		},
		{
			proto: "vmess",
			flat: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				// 显式 dst_port 443：避免 universal-default 兜底分歧（链路默认
				// 443，legacy spec.DstPort=80 直传，端口默认行为由
				// flat_dstport_default_test.go 锁定）。
				"dst_port": float64(443),
				"tcp":      map[string]interface{}{"initial_seq": float64(1000)},
				"vmess":    map[string]interface{}{"uuid": "b831381d-6324-4d53-ad4f-8f5f45c30851", "port": float64(443)},
			},
			legacyPlan: vmessPlan,
		},
		{
			proto: "wireguard",
			flat: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12346),
				// 显式 dst_port 51820：避免 universal-default 兜底分歧
				//（链路默认 51820，legacy spec.DstPort=80 直传，端口默认
				// 行为由 flat_dstport_default_test.go 锁定）。
				"dst_port": float64(51820),
			},
			legacyPlan: wireguardPlan,
		},
		{
			proto: "ike_nat_t",
			flat: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				// 显式 dst_port 4500：避免 universal-default 兜底分歧
				//（链路默认 4500，legacy spec.DstPort=80 直传，端口默认
				// 行为由 flat_dstport_default_test.go 锁定）。
				"dst_port":    float64(4500),
				"tcp":         map[string]interface{}{"initial_seq": float64(1000)},
				"ike_nat_t": map[string]interface{}{},
			},
			legacyPlan: ikeNatTPlan,
		},
	}
	for _, c := range cases {
		t.Run(c.proto, func(t *testing.T) {
			spec := legacySpecJSON(c.proto, c.flat)
			chainCh, err := layers.NewChainPlanner(c.proto).Plan(context.Background(), spec)
			if err != nil {
				t.Fatalf("chain Plan err: %v", err)
			}
			var chainPkts []core.PacketConfig
			for p := range chainCh {
				chainPkts = append(chainPkts, p)
			}
			if len(chainPkts) == 0 {
				t.Fatalf("chain produced 0 packets for %s", c.proto)
			}
			legacyCh, err := c.legacyPlan(context.Background(), spec)
			if err != nil {
				t.Fatalf("legacy Plan err: %v", err)
			}
			var legacyPkts []core.PacketConfig
			for p := range legacyCh {
				legacyPkts = append(legacyPkts, p)
			}
			assertPacketStreamsEqual(t, c.proto, chainPkts, legacyPkts)
		})
	}
}

// assertPacketStreamsEqual compares two packet streams structurally:
// count, direction, L4 protocol/flags/ports, and seq/ack as RELATIVE
// offsets from each stream's own ISN base. The server-side ISN (SYN-ACK
// seq) is rand.Uint32() on both paths (legacy and chain call rand
// independently), so absolute seq/ack can never match — but the DELTAS
// must: pkt[i].seq - baseSeq is deterministic given a fixed client ISN.
// Random nonce/salt/IV fields in protocols with crypto (IKE, Shadowsocks,
// VMess, WireGuard) are non-deterministic by design — both legacy and
// chain seed them with crypto/rand, so payload LENGTH is compared, not
// payload bytes. The 12 batch-1 protocols (TFTP/MODBUS/...) have no
// crypto fields and are compared byte-for-byte in EventsMatchLegacyPlan.
func assertPacketStreamsEqual(t *testing.T, proto string, chain, legacy []core.PacketConfig) {
	t.Helper()
	if len(chain) != len(legacy) {
		t.Fatalf("%s: chain packets = %d, legacy = %d", proto, len(chain), len(legacy))
	}
	// ISN bases. Both client and server ISNs are randomized by rand.Uint32
	// in legacy and chain independently, so the absolute 32-bit seq/ack
	// values will never match. We compare each packet's seq/ack DELTA from
	// its own stream's first up and first down seq, which is deterministic
	// given a fixed client ISN (= spec.TCP.InitialSeq, 0 = random — both
	// sides seed from rand.Uint32 in that case too). The SYN (pkt[0], up)
	// has ack=0 by TCP spec, and pkt[1] (SYN-ACK, down) carries the
	// server ISN in its seq field — that becomes our serverBase.
	var chainClient, chainServer, legacyClient, legacyServer uint32
	for i := range chain {
		if chain[i].Direction == "up" && chainClient == 0 {
			chainClient = chain[i].L4.Seq
		}
		if chain[i].Direction == "down" && chainServer == 0 {
			chainServer = chain[i].L4.Seq
		}
	}
	for i := range legacy {
		if legacy[i].Direction == "up" && legacyClient == 0 {
			legacyClient = legacy[i].L4.Seq
		}
		if legacy[i].Direction == "down" && legacyServer == 0 {
			legacyServer = legacy[i].L4.Seq
		}
	}
	relSeq := func(base, v uint32) uint32 { return v - base }
	for i := range chain {
		c, l := chain[i], legacy[i]
		if c.Direction != l.Direction {
			t.Errorf("%s pkt[%d]: Direction chain=%q legacy=%q", proto, i, c.Direction, l.Direction)
		}
		if c.L4.Protocol != l.L4.Protocol {
			t.Errorf("%s pkt[%d]: L4 proto chain=%q legacy=%q", proto, i, c.L4.Protocol, l.L4.Protocol)
		}
		if c.L4.Flags != l.L4.Flags {
			t.Errorf("%s pkt[%d]: L4 flags chain=%#x legacy=%#x", proto, i, c.L4.Flags, l.L4.Flags)
		}
		// Up packets carry client-relative seq; down packets carry
		// server-relative seq (serverSeq never re-bases mid-stream).
		// ACK relative-compared against serverBase is only meaningful when
		// ack != 0: the SYN (and any SYN-ACK in protocols whose legacy
		// planner emits ack=0 there too) carries ack=0 by TCP spec, and
		// 0 minus a random server base is garbage on both sides.
		if c.Direction == "up" {
			if relSeq(chainClient, c.L4.Seq) != relSeq(legacyClient, l.L4.Seq) {
				t.Errorf("%s pkt[%d]: L4 seq (client-rel) chain=%d legacy=%d", proto, i,
					relSeq(chainClient, c.L4.Seq), relSeq(legacyClient, l.L4.Seq))
			}
			if c.L4.Ack != 0 || l.L4.Ack != 0 {
				if relSeq(chainServer, c.L4.Ack) != relSeq(legacyServer, l.L4.Ack) {
					t.Errorf("%s pkt[%d]: L4 ack (server-rel) chain=%d legacy=%d", proto, i,
						relSeq(chainServer, c.L4.Ack), relSeq(legacyServer, l.L4.Ack))
				}
			}
		} else {
			if relSeq(chainServer, c.L4.Seq) != relSeq(legacyServer, l.L4.Seq) {
				t.Errorf("%s pkt[%d]: L4 seq (server-rel) chain=%d legacy=%d", proto, i,
					relSeq(chainServer, c.L4.Seq), relSeq(legacyServer, l.L4.Seq))
			}
			if c.L4.Ack != 0 || l.L4.Ack != 0 {
				if relSeq(chainClient, c.L4.Ack) != relSeq(legacyClient, l.L4.Ack) {
					t.Errorf("%s pkt[%d]: L4 ack (client-rel) chain=%d legacy=%d", proto, i,
						relSeq(chainClient, c.L4.Ack), relSeq(legacyClient, l.L4.Ack))
				}
			}
		}
		if c.L4.SrcPort != l.L4.SrcPort || c.L4.DstPort != l.L4.DstPort {
			t.Errorf("%s pkt[%d]: L4 ports chain=%d→%d legacy=%d→%d",
				proto, i, c.L4.SrcPort, c.L4.DstPort, l.L4.SrcPort, l.L4.DstPort)
		}
		if len(c.Payload) != len(l.Payload) {
			t.Errorf("%s pkt[%d]: payload length chain=%d legacy=%d (crypto-random bytes differ by design)",
				proto, i, len(c.Payload), len(l.Payload))
		}
	}
}
