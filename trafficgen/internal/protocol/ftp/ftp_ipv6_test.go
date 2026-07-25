package ftp_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/ftp"
)

// TestFTPDataChannel_IPv6Parent verifies the FTP data-channel sub-flow uses
// IPv6 EtherType (0x86DD) when the parent spec uses IPv6 addresses. This is
// the regression guard for the IPv6-aware EtherTypeFor path used by
// core.EmitSubFlow (internal/core/subflow.go:198) which derives EtherType
// from the parent's SrcIP.
//
// Symmetric with internal/protocol/sip/sip_rtp_test.go:TestSIPMedia_IPv6Parent.
func TestFTPDataChannel_IPv6Parent(t *testing.T) {
	p := ftp.NewPlanner()
	spec := core.FlowSpec{
		SrcIP:    "2001:db8::1",
		DstIP:    "2001:db8::2",
		SrcPort:  20000,
		DstPort:  21,
		TCP:      &core.TCPConfig{InitialSeq: 1000},
		FTP: &core.FTPConfig{
			Banner: "220 Welcome",
			Commands: []core.FTPCommand{
				{Cmd: "RETR /file.bin", Response: "150", EmitDataChannel: true},
				{Cmd: "", Response: "226"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:      "passive",
				Direction: "down",
				Payload:   "X",
			},
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err=%v", err)
	}
	var dataPackets []core.PacketConfig
	for c := range ch {
		// Filter control-channel packets: those have one port equal to 21
		// (the well-known FTP control port). Data-channel packets have
		// neither port equal to 21.
		if c.L4.SrcPort != 21 && c.L4.DstPort != 21 {
			dataPackets = append(dataPackets, c)
		}
	}
	if len(dataPackets) == 0 {
		t.Fatalf("no data-channel packets emitted")
	}
	for i, c := range dataPackets {
		if c.L2.EtherType != 0x86DD {
			t.Errorf("data[%d] EtherType=%#x, want 0x86DD (IPv6)", i, c.L2.EtherType)
		}
	}
}
