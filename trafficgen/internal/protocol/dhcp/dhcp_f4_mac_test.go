package dhcp

// F4-bis regression tests: server-reply (down-direction) source MAC must be a
// valid non-zero server MAC.
//
// RFC 2131 §4.1: a server reply (OFFER/ACK/NAK) carries the server
// interface's hardware address as the Ethernet source — never all-zero
// and never broadcast (broadcast is a destination-only address on
// Ethernet). When the user does not configure the server MAC, the
// planner must fall back to a non-zero default (DefaultServerMAC),
// not emit an all-zero or broadcast source.
//
// The server MAC is mapped differently by role:
//   role=client: server MAC = spec.DstMAC (request destination)
//   role=server: server MAC = spec.SrcMAC  (server's own interface)
//
// The earlier F4 fix made the source non-zero but semantically wrong:
// role=client used BroadcastMAC as the source (invalid), and role=server
// swapped src/dst so the source became the client MAC (and the
// destination became empty/all-zero). These tests lock in the correct
// behavior.

import (
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestF4_ServerReplyEmptyServerMAC_NonZeroSource verifies the core finding:
// when the server MAC is not configured (empty), every down-direction
// (server reply) packet has a NON-ZERO Ethernet source MAC. Pre-fix the
// source was all-zero (original bug) or BroadcastMAC/client-MAC (semantically
// wrong patch); it must now be DefaultServerMAC.
func TestF4_ServerReplyEmptyServerMAC_NonZeroSource(t *testing.T) {
	p := NewPlanner()
	scenarios := []struct {
		name string
		spec core.FlowSpec
	}{
		{
			name: "role-client_dstmac-empty",
			spec: core.FlowSpec{
				SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
				SrcMAC: "aa:bb:cc:dd:ee:ff",
				// DstMAC (server MAC) intentionally EMPTY.
				DstMAC: "",
				DHCP: &core.DHCPConfig{Role: "client", Xid: 0xA1B2C3D4, Messages: []core.DHCPMessage{
					{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
				}},
			},
		},
		{
			name: "role-server_srcmac-empty",
			spec: core.FlowSpec{
				SrcIP: "192.168.1.1", DstIP: "192.168.1.100",
				// SrcMAC (server MAC) intentionally EMPTY.
				SrcMAC: "",
				DstMAC: "aa:bb:cc:dd:ee:ff",
				DHCP: &core.DHCPConfig{Role: "server", Xid: 0xA1B2C3D4, Messages: []core.DHCPMessage{
					{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
				}},
			},
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			configs := drain(mustPlan(t, p, sc.spec))
			if len(configs) == 0 {
				t.Fatalf("%s: expected at least 1 packet, got 0", sc.name)
			}
			sawDown := false
			for i, c := range configs {
				if c.Direction != "down" {
					continue
				}
				sawDown = true
				if c.L2.SrcMAC == "" || c.L2.SrcMAC == "00:00:00:00:00:00" {
					t.Errorf("%s: down packet[%d] L2.SrcMAC = %q (all-zero) — want non-zero server MAC", sc.name, i, c.L2.SrcMAC)
				}
				if c.L2.SrcMAC == BroadcastMAC {
					t.Errorf("%s: down packet[%d] L2.SrcMAC = BroadcastMAC — broadcast is a destination-only address; want a server MAC (e.g. %q)", sc.name, i, DefaultServerMAC)
				}
			}
			if !sawDown {
				t.Fatalf("%s: no down-direction packet emitted", sc.name)
			}
		})
	}
}

// TestF4_ServerReplyEmptyServerMAC_FallsBackToDefault verifies that when
// the server MAC is unconfigured, the reply source is exactly
// DefaultServerMAC (02:00:00:00:00:02), not broadcast or the client MAC.
func TestF4_ServerReplyEmptyServerMAC_FallsBackToDefault(t *testing.T) {
	p := NewPlanner()
	// role=client: server MAC = spec.DstMAC (empty).
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "",
		DHCP: &core.DHCPConfig{Role: "client", Xid: 0xA1B2C3D4, Messages: []core.DHCPMessage{
			{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		}},
	}
	configs := drain(mustPlan(t, p, spec))
	for i, c := range configs {
		if c.Direction != "down" {
			continue
		}
		if c.L2.SrcMAC != DefaultServerMAC {
			t.Errorf("down packet[%d] L2.SrcMAC = %q, want DefaultServerMAC %q", i, c.L2.SrcMAC, DefaultServerMAC)
		}
	}
}

// TestF4_ServerReplyConfiguredServerMACRespected verifies the non-empty
// path: when the server MAC IS configured, the reply uses it verbatim
// (the fallback must not clobber an explicit value).
func TestF4_ServerReplyConfiguredServerMACRespected(t *testing.T) {
	p := NewPlanner()
	const serverMAC = "11:22:33:44:55:66"
	const clientMAC = "aa:bb:cc:dd:ee:ff"

	// role=client: server MAC = spec.DstMAC.
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: clientMAC, DstMAC: serverMAC,
		DHCP: &core.DHCPConfig{Role: "client", Xid: 0xA1B2C3D4, Messages: []core.DHCPMessage{
			{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		}},
	}
	configs := drain(mustPlan(t, p, spec))
	for i, c := range configs {
		if c.Direction != "down" {
			continue
		}
		if c.L2.SrcMAC != serverMAC {
			t.Errorf("role=client down packet[%d] L2.SrcMAC = %q, want configured server MAC %q", i, c.L2.SrcMAC, serverMAC)
		}
		if c.L2.DstMAC != clientMAC {
			t.Errorf("role=client down packet[%d] L2.DstMAC = %q, want client MAC %q", i, c.L2.DstMAC, clientMAC)
		}
	}
}

// TestF4_ServerRoleReplyNoSwap verifies that for role=server the reply
// source is spec.SrcMAC (server) and destination is spec.DstMAC (client)
// — i.e. the down-branch must NOT swap for role=server. Pre-fix the
// unconditional swap made the source the client MAC and (when SrcMAC was
// empty) left the destination all-zero.
func TestF4_ServerRoleReplyNoSwap(t *testing.T) {
	p := NewPlanner()
	const serverMAC = "11:22:33:44:55:66"
	const clientMAC = "aa:bb:cc:dd:ee:ff"
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.100",
		SrcMAC: serverMAC, DstMAC: clientMAC,
		DHCP: &core.DHCPConfig{Role: "server", Xid: 0xA1B2C3D4, Messages: []core.DHCPMessage{
			{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		}},
	}
	configs := drain(mustPlan(t, p, spec))
	for i, c := range configs {
		if c.Direction != "down" {
			continue
		}
		if c.L2.SrcMAC != serverMAC {
			t.Errorf("role=server down packet[%d] L2.SrcMAC = %q, want server MAC %q (no swap)", i, c.L2.SrcMAC, serverMAC)
		}
		if c.L2.DstMAC != clientMAC {
			t.Errorf("role=server down packet[%d] L2.DstMAC = %q, want client MAC %q (no swap)", i, c.L2.DstMAC, clientMAC)
		}
	}
}

// TestF4_ServerRoleEmptySrcMAC_NonZeroDestination verifies that for
// role=server with an empty server MAC, the reply DESTINATION is also
// non-zero (pre-fix the unconditional swap made msgDstMAC = srcMAC = "",
// an all-zero destination frame).
func TestF4_ServerRoleEmptySrcMAC_NonZeroDestination(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.100",
		SrcMAC: "", DstMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{Role: "server", Xid: 0xA1B2C3D4, Messages: []core.DHCPMessage{
			{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		}},
	}
	configs := drain(mustPlan(t, p, spec))
	for i, c := range configs {
		if c.Direction != "down" {
			continue
		}
		if c.L2.DstMAC == "" || c.L2.DstMAC == "00:00:00:00:00:00" {
			t.Errorf("role=server down packet[%d] L2.DstMAC = %q (all-zero) — want non-zero client MAC", i, c.L2.DstMAC)
		}
	}
}
