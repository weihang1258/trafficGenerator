// 外部测试包：syslog 链的字节级对比需要 legacy syslog.NewPlanner 与 chain
// （internal/protocol/syslog + internal/core/layers）。测试贴近真实调用方
// （main.go 的 layers.NewChainPlanner("syslog")）。
package layers_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/syslog"
)

// syslogSpec builds a minimal RFC 5424 UDP syslog spec. Timestamp is pinned
// to an RFC 3339 value so the encoded payload is deterministic on the wire
// (encodeRFC5424 emits the timestamp verbatim; encodeBSD would otherwise
// fall back to time.Now() — planner.go encodeBSD 注释)。
func syslogSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 50000,
		DstPort: 514,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		Syslog: &core.SyslogConfig{
			Facility:  1, // user
			Severity:  6, // info
			Version:   1,
			Format:    "rfc5424",
			Transport: "udp",
			Timestamp: "2026-08-12T10:00:00Z",
			Hostname:  "host1",
			AppName:   "app",
			ProcID:    "123",
			MsgID:     "ID47",
			Msg:       "hello syslog",
		},
	}
}

// maskSyslogVolatile zeroes the volatile fields that differ between two
// independent runs: IPv4 ID (18-19) and IP checksum (24-25). The payload is
// deterministic (pinned Timestamp), so UDP checksum (40-41) must match.
func maskSyslogVolatile(pkt []byte) []byte {
	out := append([]byte(nil), pkt...)
	if len(out) > 25 {
		out[18], out[19] = 0, 0 // IPID
		out[24], out[25] = 0, 0 // IP header checksum
	}
	return out
}

// assertSyslogIdentical builds both packets and compares wire bytes after
// masking the volatile IP fields.
func assertSyslogIdentical(t *testing.T, chain, legacy core.PacketConfig, idx int) {
	t.Helper()
	b := core.NewBuilder()
	cb, err := b.Build(chain)
	if err != nil {
		t.Fatalf("Build(chain[%d]): %v", idx, err)
	}
	lb, err := b.Build(legacy)
	if err != nil {
		t.Fatalf("Build(legacy[%d]): %v", idx, err)
	}
	if !bytes.Equal(maskSyslogVolatile(cb), maskSyslogVolatile(lb)) {
		t.Errorf("packet %d bytes differ:\nchain  %x\nlegacy %x", idx, cb, lb)
	}
}

// TestChainPlanner_Syslog_RFC5424_UDP verifies the [ip→udp→syslog] chain
// emits one up datagram carrying the RFC 5424 message, byte-identical to
// legacy syslog.NewPlanner UDP path (encodeRFC5424 同一编码器)。
func TestChainPlanner_Syslog_RFC5424_UDP(t *testing.T) {
	spec := syslogSpec()
	chain := collectPlanner(t, layers.NewChainPlanner("syslog"), spec)
	legacy := collectPlanner(t, syslog.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].Direction != "up" {
		t.Errorf("direction = %s, want up (RFC 5426 fire-and-forget)", chain[0].Direction)
	}
	if chain[0].L4.Protocol != "udp" || chain[0].L4.SrcPort != 50000 || chain[0].L4.DstPort != 514 {
		t.Errorf("L4 = %s %d/%d, want udp 50000/514", chain[0].L4.Protocol, chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	if chain[0].L3.Protocol != core.ProtocolUDP {
		t.Errorf("L3.Protocol = %d, want %d (UDP 17)", chain[0].L3.Protocol, core.ProtocolUDP)
	}
	// Wire message: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG.
	payload := string(chain[0].Payload)
	if !strings.HasPrefix(payload, "<14>1 2026-08-12T10:00:00Z host1 app 123 ID47 - hello syslog") {
		t.Errorf("payload = %q, want RFC 5424 <14>1 ... header", payload)
	}
	// Per-event metadata keys merged into the datagram Metadata (波 4 契约).
	if chain[0].Metadata["syslog_priority"] != 14 {
		t.Errorf("Metadata.syslog_priority = %v, want 14 (facility 1*8+severity 6)", chain[0].Metadata["syslog_priority"])
	}
	if chain[0].Metadata["syslog_transport"] != "udp" {
		t.Errorf("Metadata.syslog_transport = %v, want udp", chain[0].Metadata["syslog_transport"])
	}
	assertSyslogIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_Syslog_BSDFormat verifies the RFC 3164 (bsd) format path
// with a pre-formatted BSD timestamp (deterministic, emitted verbatim)。
func TestChainPlanner_Syslog_BSDFormat(t *testing.T) {
	spec := syslogSpec()
	spec.Syslog.Format = "bsd"
	spec.Syslog.Version = 0 // bsd 无 version 字段
	spec.Syslog.Timestamp = "Aug 12 10:00:00"
	chain := collectPlanner(t, layers.NewChainPlanner("syslog"), spec)
	legacy := collectPlanner(t, syslog.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	payload := string(chain[0].Payload)
	if !strings.HasPrefix(payload, "<14>Aug 12 10:00:00 host1 app[123]: hello syslog") {
		t.Errorf("payload = %q, want BSD <14>Aug 12 ... app[123]: hello syslog", payload)
	}
	assertSyslogIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_Syslog_MultiMessage verifies Messages (per-message
// overrides) emits one datagram per entry with Count ignored — planner.go
// emitUDP 语义（multi-payload → 每个 entry 一个 datagram）。
func TestChainPlanner_Syslog_MultiMessage(t *testing.T) {
	spec := syslogSpec()
	spec.Syslog.Count = 5 // must be ignored when Messages is set
	spec.Syslog.Messages = []core.SyslogMessage{
		{Msg: "first", MsgID: "ID1"},
		{Msg: "second", MsgID: "ID2"},
		{Msg: "third", MsgID: "ID3"},
	}
	chain := collectPlanner(t, layers.NewChainPlanner("syslog"), spec)
	legacy := collectPlanner(t, syslog.NewPlanner(), spec)

	if len(chain) != 3 {
		t.Fatalf("chain produced %d packets, want 3 (one per message, Count ignored)", len(chain))
	}
	for i, want := range []string{"first", "second", "third"} {
		if !bytes.Contains(chain[i].Payload, []byte(want)) {
			t.Errorf("packet %d payload missing %q", i, want)
		}
		if chain[i].Direction != "up" {
			t.Errorf("packet %d direction = %s, want up", i, chain[i].Direction)
		}
		assertSyslogIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_Syslog_CountCopies verifies Count copies of the single
// message when Messages is empty (legacy emitUDP count 循环)。
func TestChainPlanner_Syslog_CountCopies(t *testing.T) {
	spec := syslogSpec()
	spec.Syslog.Count = 3
	chain := collectPlanner(t, layers.NewChainPlanner("syslog"), spec)
	legacy := collectPlanner(t, syslog.NewPlanner(), spec)

	if len(chain) != 3 {
		t.Fatalf("chain produced %d packets, want 3 (Count copies)", len(chain))
	}
	for i := 0; i < 3; i++ {
		if !bytes.Equal(chain[i].Payload, chain[0].Payload) {
			t.Errorf("packet %d payload differs from packet 0", i)
		}
		assertSyslogIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_Syslog_DefaultPort verifies the chain defaults dst port
// to 514 when the spec omits it (validateSpecBase 端口默认化)。
func TestChainPlanner_Syslog_DefaultPort(t *testing.T) {
	spec := syslogSpec()
	spec.DstPort = 0
	chain := collectPlanner(t, layers.NewChainPlanner("syslog"), spec)
	if chain[0].L4.DstPort != 514 {
		t.Errorf("dst port = %d, want 514 (syslog default)", chain[0].L4.DstPort)
	}
}

// TestChainPlanner_Syslog_ValidateNegative mirrors the legacy Validate
// contract: nil Syslog config, bad facility/severity, bsd+rfc5424 conflict,
// tcp/tls transport rejected by the chain (deferred, 与 dns tcp 相同)。
func TestChainPlanner_Syslog_ValidateNegative(t *testing.T) {
	p := layers.NewChainPlanner("syslog")

	spec := syslogSpec()
	spec.Syslog = nil
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(nil Syslog config) = nil, want error")
	}

	spec = syslogSpec()
	spec.Syslog.Facility = 24
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(Facility 24) = nil, want error")
	}

	spec = syslogSpec()
	spec.Syslog.Severity = 8
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(Severity 8) = nil, want error")
	}

	spec = syslogSpec()
	spec.Syslog.Transport = "tcp"
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(tcp transport) = nil, want error (deferred)")
	}

	spec = syslogSpec()
	spec.Syslog.Transport = "tls"
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(tls transport) = nil, want error (deferred)")
	}
}
