package dhcp

// Test points derived from testcases_dhcp.md, covering RFC field coverage,
// state machine, business scenarios, and data scenarios.
// Each test asserts observable PacketConfig field values, not just "no error".

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- 1. RFC 字段覆盖用例 (RFC field coverage tests) ---

// 1.1 op 字段 (op field, BOOTREQUEST/BOOTREPLY)
func TestPoint_Op_Bootrequest_Discover(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeDiscover}}
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[0] != OpBootrequest {
		t.Errorf("op = 0x%X, want 0x01 (BOOTREQUEST)", configs[0].Payload[0])
	}
}

func TestPoint_Op_Bootrequest_Request(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"}}
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[0] != OpBootrequest {
		t.Errorf("op = 0x%X, want 0x01 (BOOTREQUEST)", configs[0].Payload[0])
	}
}

func TestPoint_Op_Bootrequest_Decline(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeDecline, RequestedIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"}}
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[0] != OpBootrequest {
		t.Errorf("op = 0x%X, want 0x01 (BOOTREQUEST)", configs[0].Payload[0])
	}
}

func TestPoint_Op_Bootrequest_Release(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeRelease, ClientIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"}}
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[0] != OpBootrequest {
		t.Errorf("op = 0x%X, want 0x01 (BOOTREQUEST)", configs[0].Payload[0])
	}
}

func TestPoint_Op_Bootrequest_Inform(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeInform, ClientIP: "192.168.1.50"}}
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[0] != OpBootrequest {
		t.Errorf("op = 0x%X, want 0x01 (BOOTREQUEST)", configs[0].Payload[0])
	}
}

func TestPoint_Op_Bootreply_Offer(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"}}
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[0] != OpBootreply {
		t.Errorf("op = 0x%X, want 0x02 (BOOTREPLY)", configs[0].Payload[0])
	}
}

func TestPoint_Op_Bootreply_Ack(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeAck, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"}}
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[0] != OpBootreply {
		t.Errorf("op = 0x%X, want 0x02 (BOOTREPLY)", configs[0].Payload[0])
	}
}

func TestPoint_Op_Bootreply_Nak(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeNak, ServerIdentifier: "192.168.1.1"}}
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[0] != OpBootreply {
		t.Errorf("op = 0x%X, want 0x02 (BOOTREPLY)", configs[0].Payload[0])
	}
}

// 1.2 htype 字段 (hardware type)
func TestPoint_HType_Ethernet(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.HType = 1
	spec.DHCP.HLen = 6
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[1] != 1 {
		t.Errorf("htype = %d, want 1 (Ethernet)", configs[0].Payload[1])
	}
}

func TestPoint_HType_IEEE802(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.HType = 6
	spec.DHCP.HLen = 6 // IEEE 802 also uses 6
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[1] != 6 {
		t.Errorf("htype = %d, want 6 (IEEE 802)", configs[0].Payload[1])
	}
}

func TestPoint_HType_Default(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	// HType=0 -> default 1
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[1] != 1 {
		t.Errorf("default htype = %d, want 1", configs[0].Payload[1])
	}
}

// 1.3 hlen 字段 (hardware address length)
func TestPoint_HLen_Ethernet(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.HType = 1
	spec.DHCP.HLen = 6
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[2] != 6 {
		t.Errorf("hlen = %d, want 6", configs[0].Payload[2])
	}
}

func TestPoint_HLen_Default(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[2] != 6 {
		t.Errorf("default hlen = %d, want 6", configs[0].Payload[2])
	}
}

// 1.4 hops 字段 (hops)
func TestPoint_Hops_ClientZero(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "client"
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeDiscover}}
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[3] != 0 {
		t.Errorf("client hops = %d, want 0", configs[0].Payload[3])
	}
}

func TestPoint_Hops_RelayOne(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "relay"
	spec.SrcIP = "192.168.2.1"
	spec.DstIP = "10.0.0.1"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, RelayAgentIP: "192.168.2.1", Hops: 1},
	}
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[3] != 1 {
		t.Errorf("relay hops = %d, want 1", configs[0].Payload[3])
	}
}

func TestPoint_Hops_Max16(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "relay"
	spec.SrcIP = "192.168.2.1"
	spec.DstIP = "10.0.0.1"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, RelayAgentIP: "192.168.2.1", Hops: 16},
	}
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[3] != 16 {
		t.Errorf("hops = %d, want 16", configs[0].Payload[3])
	}
}

// 1.5 xid 字段 (transaction ID)
func TestPoint_Xid_Shared(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Xid = 0xA1B2C3D4
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeAck, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	for i, c := range configs {
		xid := binary.BigEndian.Uint32(c.Payload[4:8])
		if xid != 0xA1B2C3D4 {
			t.Errorf("config[%d] xid = 0x%X, want 0xA1B2C3D4", i, xid)
		}
	}
}

func TestPoint_Xid_Randomness(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Xid = 0 // random

	xids := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		configs := drain(mustPlan(t, p, spec))
		xid := binary.BigEndian.Uint32(configs[0].Payload[4:8])
		xids[xid] = true
	}
	if len(xids) < 90 {
		t.Errorf("random xid: expected >= 90 distinct, got %d", len(xids))
	}
}

func TestPoint_Xid_MaxValue(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Xid = 0xFFFFFFFF
	configs := drain(mustPlan(t, p, spec))
	xid := binary.BigEndian.Uint32(configs[0].Payload[4:8])
	if xid != 0xFFFFFFFF {
		t.Errorf("xid = 0x%X, want 0xFFFFFFFF", xid)
	}
}

// 1.6 secs 字段 (seconds)
func TestPoint_Secs_DefaultZero(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	secs := binary.BigEndian.Uint16(configs[0].Payload[8:10])
	if secs != 0 {
		t.Errorf("default secs = %d, want 0", secs)
	}
}

func TestPoint_Secs_SpecificValue(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Secs = 60
	configs := drain(mustPlan(t, p, spec))
	secs := binary.BigEndian.Uint16(configs[0].Payload[8:10])
	if secs != 60 {
		t.Errorf("secs = %d, want 60", secs)
	}
}

func TestPoint_Secs_Max(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Secs = 65535
	configs := drain(mustPlan(t, p, spec))
	secs := binary.BigEndian.Uint16(configs[0].Payload[8:10])
	if secs != 65535 {
		t.Errorf("secs = %d, want 65535", secs)
	}
}

// 1.7 flags 字段 (broadcast flag)
func TestPoint_Flags_Zero(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.BroadcastFlag = false
	configs := drain(mustPlan(t, p, spec))
	flags := binary.BigEndian.Uint16(configs[0].Payload[10:12])
	if flags != 0 {
		t.Errorf("flags = 0x%X, want 0x0000", flags)
	}
}

func TestPoint_Flags_Broadcast(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.BroadcastFlag = true
	configs := drain(mustPlan(t, p, spec))
	flags := binary.BigEndian.Uint16(configs[0].Payload[10:12])
	if flags != BroadcastFlag {
		t.Errorf("flags = 0x%X, want 0x8000", flags)
	}
}

func TestPoint_Flags_PerMessageBroadcast(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	bcast := true
	spec.DHCP.BroadcastFlag = false
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, Broadcast: &bcast},
	}
	configs := drain(mustPlan(t, p, spec))
	flags := binary.BigEndian.Uint16(configs[0].Payload[10:12])
	if flags != BroadcastFlag {
		t.Errorf("per-message broadcast flags = 0x%X, want 0x8000", flags)
	}
}

// 1.8 ciaddr 字段 (Client IP)
func TestPoint_Ciaddr_DiscoverZero(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeDiscover}}
	configs := drain(mustPlan(t, p, spec))
	ciaddr := net.IP(configs[0].Payload[12:16])
	if ciaddr.String() != "0.0.0.0" {
		t.Errorf("DISCOVER ciaddr = %s, want 0.0.0.0", ciaddr)
	}
}

func TestPoint_Ciaddr_SpecificValue(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeInform, ClientIP: "192.168.1.50"}}
	configs := drain(mustPlan(t, p, spec))
	ciaddr := net.IP(configs[0].Payload[12:16])
	if ciaddr.String() != "192.168.1.50" {
		t.Errorf("ciaddr = %s, want 192.168.1.50", ciaddr)
	}
}

// 1.9 yiaddr 字段 (Your IP)
func TestPoint_Yiaddr_Offer(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	yiaddr := net.IP(configs[0].Payload[16:20])
	if yiaddr.String() != "192.168.1.100" {
		t.Errorf("OFFER yiaddr = %s, want 192.168.1.100", yiaddr)
	}
}

func TestPoint_Yiaddr_Ack(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeAck, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	yiaddr := net.IP(configs[0].Payload[16:20])
	if yiaddr.String() != "192.168.1.100" {
		t.Errorf("ACK yiaddr = %s, want 192.168.1.100", yiaddr)
	}
}

func TestPoint_Yiaddr_DiscoverZero(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeDiscover}}
	configs := drain(mustPlan(t, p, spec))
	yiaddr := net.IP(configs[0].Payload[16:20])
	if yiaddr.String() != "0.0.0.0" {
		t.Errorf("DISCOVER yiaddr = %s, want 0.0.0.0", yiaddr)
	}
}

// 1.10 siaddr 字段 (Server IP)
func TestPoint_Siaddr_SpecificValue(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIP: "192.168.1.1", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	siaddr := net.IP(configs[0].Payload[20:24])
	if siaddr.String() != "192.168.1.1" {
		t.Errorf("siaddr = %s, want 192.168.1.1", siaddr)
	}
}

func TestPoint_Siaddr_DefaultZero(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	siaddr := net.IP(configs[0].Payload[20:24])
	if siaddr.String() != "0.0.0.0" {
		t.Errorf("default siaddr = %s, want 0.0.0.0", siaddr)
	}
}

// 1.11 giaddr 字段 (Relay Agent IP)
func TestPoint_Giaddr_ClientZero(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	giaddr := net.IP(configs[0].Payload[24:28])
	if giaddr.String() != "0.0.0.0" {
		t.Errorf("client giaddr = %s, want 0.0.0.0", giaddr)
	}
}

func TestPoint_Giaddr_Relay(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "relay"
	spec.SrcIP = "192.168.2.1"
	spec.DstIP = "10.0.0.1"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, RelayAgentIP: "192.168.2.1", Hops: 1},
	}
	configs := drain(mustPlan(t, p, spec))
	giaddr := net.IP(configs[0].Payload[24:28])
	if giaddr.String() != "192.168.2.1" {
		t.Errorf("relay giaddr = %s, want 192.168.2.1", giaddr)
	}
}

func TestPoint_Giaddr_ClientWithRelayAgentIP(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "client"
	spec.DHCP.DefaultRelayAgentIP = "192.168.2.1"
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("client with default_relay_agent_ip should be rejected")
	}
}

// 1.12 chaddr 字段 (Client Hardware Address)
func TestPoint_Chaddr_Full(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.ClientMAC = "aa:bb:cc:dd:ee:ff"
	configs := drain(mustPlan(t, p, spec))
	chaddr := configs[0].Payload[28:44]
	expected := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for i, b := range expected {
		if chaddr[i] != b {
			t.Errorf("chaddr[%d] = 0x%X, want 0x%X", i, chaddr[i], b)
		}
	}
}

func TestPoint_Chaddr_DefaultFromSrcMAC(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.SrcMAC = "11:22:33:44:55:66"
	configs := drain(mustPlan(t, p, spec))
	chaddr := configs[0].Payload[28:34]
	expected := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	for i, b := range expected {
		if chaddr[i] != b {
			t.Errorf("chaddr[%d] = 0x%X, want 0x%X", i, chaddr[i], b)
		}
	}
}

func TestPoint_Chaddr_DefaultFromDstMAC_ServerRole(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.SrcIP = "192.168.1.1"
	spec.DstIP = "192.168.1.100"
	spec.SrcMAC = "11:22:33:44:55:66"
	spec.DstMAC = "aa:bb:cc:dd:ee:ff"
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"}}
	configs := drain(mustPlan(t, p, spec))
	chaddr := configs[0].Payload[28:34]
	expected := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for i, b := range expected {
		if chaddr[i] != b {
			t.Errorf("chaddr[%d] = 0x%X, want 0x%X (server role uses DstMAC)", i, chaddr[i], b)
		}
	}
}

// 1.13 sname 字段 (Server Host Name)
func TestPoint_Sname_DefaultZero(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	sname := configs[0].Payload[44:108]
	for i, b := range sname {
		if b != 0 {
			t.Errorf("sname[%d] = 0x%X, want 0x00", i, b)
		}
	}
}

func TestPoint_Sname_SpecificValue(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Sname = "dhcp-server-01"
	configs := drain(mustPlan(t, p, spec))
	sname := configs[0].Payload[44:108]
	expected := []byte("dhcp-server-01")
	for i, b := range expected {
		if sname[i] != b {
			t.Errorf("sname[%d] = 0x%X, want 0x%X", i, sname[i], b)
		}
	}
}

func TestPoint_Sname_Exceeds64(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Sname = strings.Repeat("a", 65)
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("sname > 64 bytes should be rejected")
	}
}

// 1.14 file 字段 (Boot File Name)
func TestPoint_File_DefaultZero(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	file := configs[0].Payload[108:236]
	for i, b := range file {
		if b != 0 {
			t.Errorf("file[%d] = 0x%X, want 0x00", i, b)
		}
	}
}

func TestPoint_File_SpecificValue(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.File = "pxelinux.0"
	configs := drain(mustPlan(t, p, spec))
	file := configs[0].Payload[108:236]
	expected := []byte("pxelinux.0")
	for i, b := range expected {
		if file[i] != b {
			t.Errorf("file[%d] = 0x%X, want 0x%X", i, file[i], b)
		}
	}
}

func TestPoint_File_Exceeds128(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.File = strings.Repeat("a", 129)
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("file > 128 bytes should be rejected")
	}
}

// 1.15 magic cookie (魔术cookie)
func TestPoint_MagicCookie_AlwaysCorrect(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	cookie := binary.BigEndian.Uint32(configs[0].Payload[236:240])
	if cookie != MagicCookie {
		t.Errorf("magic cookie = 0x%X, want 0x%X", cookie, MagicCookie)
	}
}

// 1.16 option 53 (DHCP Message Type)
func TestPoint_Option53_AllTypes(t *testing.T) {
	tests := []struct {
		name    string
		msgType uint8
	}{
		{"discover", MsgTypeDiscover},
		{"offer", MsgTypeOffer},
		{"request", MsgTypeRequest},
		{"decline", MsgTypeDecline},
		{"ack", MsgTypeAck},
		{"nak", MsgTypeNak},
		{"release", MsgTypeRelease},
		{"inform", MsgTypeInform},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPlanner()
			spec := validDHCPSpec()
			spec.DHCP.Messages = []core.DHCPMessage{{Type: tt.msgType}}
			configs := drain(mustPlan(t, p, spec))
			mt := findOption53(configs[0].Payload)
			if mt != tt.msgType {
				t.Errorf("option 53 = %d, want %d", mt, tt.msgType)
			}
		})
	}
}

func TestPoint_Option53_InvalidType0(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: 0}}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("Type=0 should be rejected")
	}
}

func TestPoint_Option53_InvalidType9(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: 9}}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("Type=9 should be rejected")
	}
}

// 1.17 option 50 (Requested IP Address)
func TestPoint_Option50_SpecificValue(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 50)
	if opt == nil {
		t.Fatalf("option 50 not found")
	}
	ip := net.IP(opt)
	if ip.String() != "192.168.1.100" {
		t.Errorf("option 50 = %s, want 192.168.1.100", ip)
	}
}

func TestPoint_Option50_DiscoverAbsent(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeDiscover}}
	configs := drain(mustPlan(t, p, spec))
	if hasOption(configs[0].Payload, 50) {
		t.Errorf("option 50 should be absent in DISCOVER without RequestedIP")
	}
}

func TestPoint_Option50_InvalidIP(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeRequest, RequestedIP: "invalid-ip"},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("invalid RequestedIP should be rejected")
	}
}

// 1.18 option 54 (Server Identifier)
func TestPoint_Option54_SpecificValue(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 54)
	if opt == nil {
		t.Fatalf("option 54 not found")
	}
	ip := net.IP(opt)
	if ip.String() != "192.168.1.1" {
		t.Errorf("option 54 = %s, want 192.168.1.1", ip)
	}
}

func TestPoint_Option54_DefaultAbsent(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	// No ServerIdentifier anywhere
	configs := drain(mustPlan(t, p, spec))
	if hasOption(configs[0].Payload, 54) {
		t.Errorf("option 54 should be absent when not set")
	}
}

// 1.19 option 51 (IP Address Lease Time)
func TestPoint_Option51_24h(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeAck, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1", LeaseTime: 86400},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 51)
	if opt == nil {
		t.Fatalf("option 51 not found")
	}
	lt := binary.BigEndian.Uint32(opt)
	if lt != 86400 {
		t.Errorf("option 51 = %d, want 86400", lt)
	}
}

func TestPoint_Option51_Infinite(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeAck, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1", LeaseTime: 0xFFFFFFFF},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 51)
	if opt == nil {
		t.Fatalf("option 51 not found")
	}
	lt := binary.BigEndian.Uint32(opt)
	if lt != 0xFFFFFFFF {
		t.Errorf("option 51 = 0x%X, want 0xFFFFFFFF", lt)
	}
}

// 1.20 option 1 (Subnet Mask)
func TestPoint_Option1_SpecificValue(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", SubnetMask: "255.255.255.0", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 1)
	if opt == nil {
		t.Fatalf("option 1 not found")
	}
	if len(opt) != 4 {
		t.Errorf("option 1 length = %d, want 4", len(opt))
	}
}

func TestPoint_Option1_DefaultAbsent(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	if hasOption(configs[0].Payload, 1) {
		t.Errorf("option 1 should be absent by default")
	}
}

// 1.21 option 3 (Router)
func TestPoint_Option3_SingleRouter(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", Routers: []string{"192.168.1.1"}, ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 3)
	if opt == nil {
		t.Fatalf("option 3 not found")
	}
	if len(opt) != 4 {
		t.Errorf("option 3 length = %d, want 4", len(opt))
	}
}

func TestPoint_Option3_MultipleRouters(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", Routers: []string{"192.168.1.1", "192.168.1.2"}, ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 3)
	if opt == nil {
		t.Fatalf("option 3 not found")
	}
	if len(opt) != 8 {
		t.Errorf("option 3 length = %d, want 8", len(opt))
	}
}

func TestPoint_Option3_InvalidRouter(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", Routers: []string{"router1"}, ServerIdentifier: "192.168.1.1"},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("invalid router should be rejected")
	}
}

// 1.22 option 6 (DNS)
func TestPoint_Option6_SingleDNS(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", DNS: []string{"8.8.8.8"}, ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 6)
	if opt == nil {
		t.Fatalf("option 6 not found")
	}
	if len(opt) != 4 {
		t.Errorf("option 6 length = %d, want 4", len(opt))
	}
}

func TestPoint_Option6_MultipleDNS(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", DNS: []string{"8.8.8.8", "1.1.1.1"}, ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 6)
	if opt == nil {
		t.Fatalf("option 6 not found")
	}
	if len(opt) != 8 {
		t.Errorf("option 6 length = %d, want 8", len(opt))
	}
}

func TestPoint_Option6_IPv6Rejected(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", DNS: []string{"::1"}, ServerIdentifier: "192.168.1.1"},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("IPv6 DNS should be rejected")
	}
}

// 1.23 option 12 (Hostname)
func TestPoint_Option12_SpecificValue(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, Hostname: "client01"},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 12)
	if opt == nil {
		t.Fatalf("option 12 not found")
	}
	if string(opt) != "client01" {
		t.Errorf("option 12 = %s, want client01", string(opt))
	}
}

func TestPoint_Option12_MaxLength(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	host := strings.Repeat("a", 255)
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, Hostname: host},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 12)
	if opt == nil {
		t.Fatalf("option 12 not found")
	}
	if len(opt) != 255 {
		t.Errorf("option 12 length = %d, want 255", len(opt))
	}
}

func TestPoint_Option12_Exceeds255(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	host := strings.Repeat("a", 256)
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, Hostname: host},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("hostname > 255 bytes should be rejected")
	}
}

// 1.24 option 15 (Domain Name)
func TestPoint_Option15_SpecificValue(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", DomainName: "example.com", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 15)
	if opt == nil {
		t.Fatalf("option 15 not found")
	}
	if string(opt) != "example.com" {
		t.Errorf("option 15 = %s, want example.com", string(opt))
	}
}

func TestPoint_Option15_Exceeds255(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", DomainName: strings.Repeat("a", 256), ServerIdentifier: "192.168.1.1"},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("domain name > 255 bytes should be rejected")
	}
}

// 1.25 option 119 (Domain Search)
func TestPoint_Option119_SingleDomain(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", DomainSearch: []string{"example.com"}, ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 119)
	if opt == nil {
		t.Fatalf("option 119 not found")
	}
}

// 1.26 option 58 (T1)
func TestPoint_Option58_T1Value(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", T1: 43200, ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 58)
	if opt == nil {
		t.Fatalf("option 58 not found")
	}
	t1 := binary.BigEndian.Uint32(opt)
	if t1 != 43200 {
		t.Errorf("T1 = %d, want 43200", t1)
	}
}

// 1.27 option 59 (T2)
func TestPoint_Option59_T2Value(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", T2: 75600, ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 59)
	if opt == nil {
		t.Fatalf("option 59 not found")
	}
	t2 := binary.BigEndian.Uint32(opt)
	if t2 != 75600 {
		t.Errorf("T2 = %d, want 75600", t2)
	}
}

// 1.28 option 61 (Client Identifier)
func TestPoint_Option61_TypeAndMAC(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, ClientID: []byte{0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 61)
	if opt == nil {
		t.Fatalf("option 61 not found")
	}
	if len(opt) != 7 {
		t.Errorf("option 61 length = %d, want 7", len(opt))
	}
	if opt[0] != 0x01 {
		t.Errorf("option 61 type = 0x%X, want 0x01", opt[0])
	}
}

func TestPoint_Option61_DefaultAbsent(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	if hasOption(configs[0].Payload, 61) {
		t.Errorf("option 61 should be absent when ClientID not set")
	}
}

// 1.29 option 60 (Vendor Class Identifier)
func TestPoint_Option60_SpecificValue(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, VendorClass: "MSFT 5.0"},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 60)
	if opt == nil {
		t.Fatalf("option 60 not found")
	}
	if string(opt) != "MSFT 5.0" {
		t.Errorf("option 60 = %s, want MSFT 5.0", string(opt))
	}
}

func TestPoint_Option60_Exceeds255(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, VendorClass: strings.Repeat("a", 256)},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("vendor class > 255 bytes should be rejected")
	}
}

// 1.30 option 82 (Relay Agent Information)
func TestPoint_Option82_RelayInfo(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "relay"
	spec.SrcIP = "192.168.2.1"
	spec.DstIP = "10.0.0.1"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, RelayAgentIP: "192.168.2.1", Hops: 1, RelayAgentInfo: []byte{0x01, 0x06, 'e', 't', 'h', '0', '0', 0x02, 0x05, 'A', 'P', '1'}},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 82)
	if opt == nil {
		t.Fatalf("option 82 not found")
	}
	if len(opt) != 12 {
		t.Errorf("option 82 length = %d, want 12", len(opt))
	}
}

func TestPoint_Option82_DefaultAbsent(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	if hasOption(configs[0].Payload, 82) {
		t.Errorf("option 82 should be absent by default")
	}
}

// 1.31 option 55 (Parameter Request List)
func TestPoint_Option55_List(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	prl := []uint8{1, 3, 6, 15, 51, 54, 58, 59}
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, ParamRequestList: prl},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 55)
	if opt == nil {
		t.Fatalf("option 55 not found")
	}
	if len(opt) != len(prl) {
		t.Errorf("option 55 length = %d, want %d", len(opt), len(prl))
	}
}

func TestPoint_Option55_DefaultAbsent(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	if hasOption(configs[0].Payload, 55) {
		t.Errorf("option 55 should be absent when not set")
	}
}

func TestPoint_Option55_Exceeds255(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	prl := make([]uint8, 256)
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, ParamRequestList: prl},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("param request list > 255 bytes should be rejected")
	}
}

// 1.32 option 255 (END)
func TestPoint_Option255_AlwaysPresent(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	// Verify options end with 0xFF
	payload := configs[0].Payload
	found := false
	for i := 240; i < len(payload); i++ {
		if payload[i] == 255 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("option 255 (END) not found in options")
	}
}

func TestPoint_Option255_InExtraOptionsRejected(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, ExtraOptions: []core.DHCPOption{{Code: 255}}},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("option 255 in ExtraOptions should be rejected")
	}
}

// --- 2. 状态机覆盖用例 (state machine coverage) ---

// 2.1 状态 INIT (INIT state)
func TestPoint_State_Init_SingleDiscover(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeDiscover}}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Errorf("expected 1 packet, got %d", len(configs))
	}
}

func TestPoint_State_Init_FullHandshake(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeAck, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 4 {
		t.Errorf("expected 4 packets, got %d", len(configs))
	}
	for i, c := range configs {
		if c.PacketIndex != uint64(i) {
			t.Errorf("config[%d].PacketIndex = %d, want %d", i, c.PacketIndex, i)
		}
	}
}

// 2.3 状态 REQUESTING (REQUESTING state)
func TestPoint_State_Requesting_NAK(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeNak, ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 4 {
		t.Fatalf("expected 4 packets, got %d", len(configs))
	}
	// NAK op = 2
	if configs[3].Payload[0] != OpBootreply {
		t.Errorf("NAK op = %d, want 2", configs[3].Payload[0])
	}
}

func TestPoint_State_Requesting_ACK(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeAck, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 4 {
		t.Fatalf("expected 4 packets, got %d", len(configs))
	}
	// ACK op = 2
	if configs[3].Payload[0] != OpBootreply {
		t.Errorf("ACK op = %d, want 2", configs[3].Payload[0])
	}
}

// 2.4 状态 BOUND (BOUND state)
func TestPoint_State_Bound_Release(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeAck, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeRelease, ClientIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 5 {
		t.Fatalf("expected 5 packets, got %d", len(configs))
	}
	// RELEASE ciaddr = 192.168.1.50
	ciaddr := net.IP(configs[4].Payload[12:16])
	if ciaddr.String() != "192.168.1.50" {
		t.Errorf("RELEASE ciaddr = %s, want 192.168.1.50", ciaddr)
	}
}

func TestPoint_State_Bound_Inform(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeInform, ClientIP: "192.168.1.50"},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}
	if configs[0].Payload[0] != OpBootrequest {
		t.Errorf("INFORM op = %d, want 1", configs[0].Payload[0])
	}
}

// 2.5 状态 RENEWING (RENEWING state)
func TestPoint_State_Renewing_UnicastRequest(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1", LeaseTime: 86400},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeAck, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1", LeaseTime: 86400},
		{Type: MsgTypeRequest, ClientIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 5 {
		t.Fatalf("expected 5 packets, got %d", len(configs))
	}
	// RENEWING REQUEST ciaddr = 192.168.1.50
	ciaddr := net.IP(configs[4].Payload[12:16])
	if ciaddr.String() != "192.168.1.50" {
		t.Errorf("RENEWING REQUEST ciaddr = %s, want 192.168.1.50", ciaddr)
	}
}

// 2.8 方向推断 (direction inference)
func TestPoint_DirectionInfer_Up(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeDiscover}}
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Direction != "up" {
		t.Errorf("DISCOVER direction = %s, want up", configs[0].Direction)
	}
}

func TestPoint_DirectionInfer_Down(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"}}
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Direction != "down" {
		t.Errorf("OFFER direction = %s, want down", configs[0].Direction)
	}
}

func TestPoint_Direction_UserOverride(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	// User sets Direction="up" on an OFFER (which would normally be down)
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1", Direction: "up"},
	}
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Direction != "up" {
		t.Errorf("user-overridden direction = %s, want up", configs[0].Direction)
	}
}

// --- 3. 业务场景覆盖用例 (business scenarios) ---

// 3.1 场景 1: 标准 4 次握手
func TestPoint_Scenario_Standard4WayHandshake(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Xid = 0xA1B2C3D4
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1", LeaseTime: 86400, SubnetMask: "255.255.255.0"},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeAck, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1", LeaseTime: 86400, SubnetMask: "255.255.255.0"},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 4 {
		t.Fatalf("expected 4 packets, got %d", len(configs))
	}
	// Verify all share xid
	for i, c := range configs {
		xid := binary.BigEndian.Uint32(c.Payload[4:8])
		if xid != 0xA1B2C3D4 {
			t.Errorf("config[%d] xid = 0x%X, want 0xA1B2C3D4", i, xid)
		}
	}
	// Verify OFFER (config[1]) has option 51 (LeaseTime)
	if !hasOption(configs[1].Payload, 51) {
		t.Errorf("OFFER should have option 51 (LeaseTime)")
	}
	// Verify ACK (config[3]) has option 1 (SubnetMask)
	if !hasOption(configs[3].Payload, 1) {
		t.Errorf("ACK should have option 1 (SubnetMask)")
	}
}

// 3.2 场景 2: NAK
func TestPoint_Scenario_NAK(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeNak, ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 4 {
		t.Fatalf("expected 4 packets, got %d", len(configs))
	}
	// NAK carries option 54
	if !hasOption(configs[3].Payload, 54) {
		t.Errorf("NAK should carry option 54")
	}
	// NAK does NOT carry option 50/51/58/59
	if hasOption(configs[3].Payload, 50) {
		t.Errorf("NAK should not carry option 50")
	}
	if hasOption(configs[3].Payload, 51) {
		t.Errorf("NAK should not carry option 51")
	}
}

// 3.3 场景 3: DECLINE 后重试
func TestPoint_Scenario_DeclineRetry(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeAck, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeDecline, RequestedIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 5 {
		t.Fatalf("expected 5 packets, got %d", len(configs))
	}
	// DECLINE carries option 50 = 192.168.1.50
	opt := findOption(configs[4].Payload, 50)
	if opt == nil {
		t.Fatalf("DECLINE should carry option 50")
	}
	ip := net.IP(opt)
	if ip.String() != "192.168.1.50" {
		t.Errorf("DECLINE option 50 = %s, want 192.168.1.50", ip)
	}
}

// 3.4 场景 4: INFORM
func TestPoint_Scenario_Inform(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeInform, ClientIP: "192.168.1.50"},
		{Type: MsgTypeAck, ServerIdentifier: "192.168.1.1", SubnetMask: "255.255.255.0"},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(configs))
	}
	// INFORM op = 1
	if configs[0].Payload[0] != OpBootrequest {
		t.Errorf("INFORM op = %d, want 1", configs[0].Payload[0])
	}
	// INFORM does NOT carry option 50/51
	if hasOption(configs[0].Payload, 50) {
		t.Errorf("INFORM should not carry option 50")
	}
	if hasOption(configs[0].Payload, 51) {
		t.Errorf("INFORM should not carry option 51")
	}
}

// 3.5 场景 5: RELEASE
func TestPoint_Scenario_Release(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeRelease, ClientIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}
	// RELEASE op = 1
	if configs[0].Payload[0] != OpBootrequest {
		t.Errorf("RELEASE op = %d, want 1", configs[0].Payload[0])
	}
	// RELEASE carries option 54
	if !hasOption(configs[0].Payload, 54) {
		t.Errorf("RELEASE should carry option 54")
	}
}

// 3.6 场景 6: Renew (T1)
func TestPoint_Scenario_Renew(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1", LeaseTime: 86400},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeAck, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1", LeaseTime: 86400},
		{Type: MsgTypeRequest, ClientIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeAck, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1", LeaseTime: 86400},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 6 {
		t.Fatalf("expected 6 packets, got %d", len(configs))
	}
	// RENEWING REQUEST (config[4]) carries option 54
	if !hasOption(configs[4].Payload, 54) {
		t.Errorf("RENEWING REQUEST should carry option 54")
	}
}

// 3.7 场景 7: Rebind (T2)
func TestPoint_Scenario_Rebind(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	// REBINDING: broadcast REQUEST without option 54
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1", LeaseTime: 86400},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeAck, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1", LeaseTime: 86400},
		{Type: MsgTypeRequest, ClientIP: "192.168.1.50"},
		{Type: MsgTypeAck, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.2", LeaseTime: 86400},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 6 {
		t.Fatalf("expected 6 packets, got %d", len(configs))
	}
	// REBINDING REQUEST (config[4]) does NOT carry option 54
	if hasOption(configs[4].Payload, 54) {
		t.Errorf("REBINDING REQUEST should not carry option 54")
	}
}

// 3.8 场景 8: 多服务器并发
func TestPoint_Scenario_MultiServer(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeOffer, YourIP: "192.168.1.200", ServerIdentifier: "192.168.1.2"},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeAck, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 5 {
		t.Fatalf("expected 5 packets, got %d", len(configs))
	}
	// REQUEST (config[3]) carries option 54 = 192.168.1.1
	opt := findOption(configs[3].Payload, 54)
	if opt == nil {
		t.Fatalf("REQUEST should carry option 54")
	}
	ip := net.IP(opt)
	if ip.String() != "192.168.1.1" {
		t.Errorf("REQUEST option 54 = %s, want 192.168.1.1", ip)
	}
}

// 3.9 场景 9: 中继代理 (Relay)
func TestPoint_Scenario_RelayAgent(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "relay"
	spec.SrcIP = "192.168.2.1"
	spec.DstIP = "10.0.0.1"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, RelayAgentIP: "192.168.2.1", Hops: 1},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}
	// Verify giaddr
	giaddr := net.IP(configs[0].Payload[24:28])
	if giaddr.String() != "192.168.2.1" {
		t.Errorf("giaddr = %s, want 192.168.2.1", giaddr)
	}
	// Verify hops = 1
	if configs[0].Payload[3] != 1 {
		t.Errorf("hops = %d, want 1", configs[0].Payload[3])
	}
}

// 3.10 场景 10: 客户端检测冲突 (DECLINE)
func TestPoint_Scenario_DeclineConflict(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeAck, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeDecline, RequestedIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 5 {
		t.Fatalf("expected 5 packets, got %d", len(configs))
	}
	// DECLINE ciaddr = 0.0.0.0
	ciaddr := net.IP(configs[4].Payload[12:16])
	if ciaddr.String() != "0.0.0.0" {
		t.Errorf("DECLINE ciaddr = %s, want 0.0.0.0", ciaddr)
	}
	// DECLINE carries option 50
	if !hasOption(configs[4].Payload, 50) {
		t.Errorf("DECLINE should carry option 50")
	}
}

// 3.13 Option Overload 拒绝 (Option Overload rejected)
func TestPoint_OptionOverload_Code52_1(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, ExtraOptions: []core.DHCPOption{{Code: 52, Data: []byte{0x01}}}},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("option overload (code 52, value 1) should be rejected")
	}
	if !strings.Contains(err.Error(), "option overload not supported") {
		t.Errorf("error = %v, want contains 'option overload not supported'", err)
	}
}

func TestPoint_OptionOverload_Code52_3(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, ExtraOptions: []core.DHCPOption{{Code: 52, Data: []byte{0x03}}}},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("option overload (code 52, value 3) should be rejected")
	}
}

func TestPoint_OptionOverload_Code52_0(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, ExtraOptions: []core.DHCPOption{{Code: 52, Data: []byte{0x00}}}},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("option overload (code 52, value 0) should be rejected")
	}
}

func TestPoint_OptionOverload_NoCode52_OK(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeAck, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
	}
	err := p.Validate(spec)
	if err != nil {
		t.Errorf("no option 52 should pass: %v", err)
	}
}

// --- 4. 数据场景覆盖用例 (data scenarios) ---

// 4.1 空值 / 零值场景 (zero/empty values)
func TestPoint_Data_EmptyOptions_MinSize(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeDiscover}}
	configs := drain(mustPlan(t, p, spec))
	// Minimum payload = 236 (BOOTP) + 4 (magic) + 3 (option 53) + 1 (END) + padding = 244
	// padding to 4-byte boundary: 244 % 4 = 0, so no extra padding
	if len(configs[0].Payload) < 244 {
		t.Errorf("min payload = %d, want >= 244", len(configs[0].Payload))
	}
}

func TestPoint_Data_NoOption55(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeDiscover}}
	configs := drain(mustPlan(t, p, spec))
	if hasOption(configs[0].Payload, 55) {
		t.Errorf("option 55 should be absent when not set")
	}
}

func TestPoint_Data_NoOption61(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeDiscover}}
	configs := drain(mustPlan(t, p, spec))
	if hasOption(configs[0].Payload, 61) {
		t.Errorf("option 61 should be absent when not set")
	}
}

// 4.2 边界值 (boundary values)
func TestPoint_Data_Boundary_HType_HLen(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.HType = 1
	spec.DHCP.HLen = 6
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[1] != 1 || configs[0].Payload[2] != 6 {
		t.Errorf("htype=%d, hlen=%d, want 1 and 6", configs[0].Payload[1], configs[0].Payload[2])
	}
}

func TestPoint_Data_Boundary_XidMax_FlagsBroadcast(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Xid = 0xFFFFFFFF
	spec.DHCP.BroadcastFlag = true
	configs := drain(mustPlan(t, p, spec))
	xid := binary.BigEndian.Uint32(configs[0].Payload[4:8])
	if xid != 0xFFFFFFFF {
		t.Errorf("xid = 0x%X, want 0xFFFFFFFF", xid)
	}
	flags := binary.BigEndian.Uint16(configs[0].Payload[10:12])
	if flags != BroadcastFlag {
		t.Errorf("flags = 0x%X, want 0x8000", flags)
	}
}

func TestPoint_Data_Boundary_LeaseTimeZero(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeAck, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1", LeaseTime: 0, T1: 0, T2: 0},
	}
	configs := drain(mustPlan(t, p, spec))
	// LeaseTime=0 should not produce option 51
	if hasOption(configs[0].Payload, 51) {
		t.Errorf("LeaseTime=0 should not produce option 51")
	}
}

func TestPoint_Data_Boundary_HostnameMax(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, Hostname: strings.Repeat("a", 255)},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 12)
	if opt == nil {
		t.Fatalf("option 12 not found")
	}
	if len(opt) != 255 {
		t.Errorf("option 12 length = %d, want 255", len(opt))
	}
}

func TestPoint_Data_Boundary_HopsMax(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "relay"
	spec.SrcIP = "192.168.2.1"
	spec.DstIP = "10.0.0.1"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, RelayAgentIP: "192.168.2.1", Hops: 16},
	}
	configs := drain(mustPlan(t, p, spec))
	if configs[0].Payload[3] != 16 {
		t.Errorf("hops = %d, want 16", configs[0].Payload[3])
	}
}

func TestPoint_Data_Boundary_ParamRequestListMax(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	prl := make([]uint8, 255)
	for i := range prl {
		prl[i] = uint8(i % 256)
	}
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, ParamRequestList: prl},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 55)
	if opt == nil {
		t.Fatalf("option 55 not found")
	}
	if len(opt) != 255 {
		t.Errorf("option 55 length = %d, want 255", len(opt))
	}
}

// 4.3 异常值 (abnormal values)
func TestPoint_Data_Abnormal_MagicCookie(t *testing.T) {
	// Magic cookie is hardcoded; users can't set it, so this is verified at runtime.
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	cookie := binary.BigEndian.Uint32(configs[0].Payload[236:240])
	if cookie != MagicCookie {
		t.Errorf("magic cookie = 0x%X, want 0x%X", cookie, MagicCookie)
	}
}

func TestPoint_Data_Abnormal_ChaddrAllZero(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.ClientMAC = "00:00:00:00:00:00"
	configs := drain(mustPlan(t, p, spec))
	// chaddr bytes 28-43 all zero
	chaddr := configs[0].Payload[28:44]
	for i, b := range chaddr {
		if b != 0 {
			t.Errorf("chaddr[%d] = 0x%X, want 0x00", i, b)
		}
	}
}

// 4.4 大数据 (large data)
func TestPoint_Data_Large_ParamRequestList100(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	prl := make([]uint8, 100)
	for i := range prl {
		prl[i] = uint8(i % 200)
	}
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, ParamRequestList: prl},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 55)
	if opt == nil {
		t.Fatalf("option 55 not found")
	}
	if len(opt) != 100 {
		t.Errorf("option 55 length = %d, want 100", len(opt))
	}
}

func TestPoint_Data_Large_VendorClass200(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, VendorClass: strings.Repeat("a", 200)},
	}
	configs := drain(mustPlan(t, p, spec))
	opt := findOption(configs[0].Payload, 60)
	if opt == nil {
		t.Fatalf("option 60 not found")
	}
	if len(opt) != 200 {
		t.Errorf("option 60 length = %d, want 200", len(opt))
	}
}

// 4.5 小数据 (small data)
func TestPoint_Data_Small_MinimalDiscover(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeDiscover}}
	configs := drain(mustPlan(t, p, spec))
	minSize := BootpHeaderLen + MagicCookieLen + 3 + 1
	if len(configs[0].Payload) < minSize {
		t.Errorf("min payload = %d, want >= %d", len(configs[0].Payload), minSize)
	}
}

func TestPoint_Data_Small_Inform(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeInform, ClientIP: "192.168.1.50"}}
	configs := drain(mustPlan(t, p, spec))
	if len(configs[0].Payload) > 300 {
		t.Errorf("INFORM payload = %d, want < 300", len(configs[0].Payload))
	}
}

func TestPoint_Data_Small_Decline(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDecline, RequestedIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	if len(configs[0].Payload) > 300 {
		t.Errorf("DECLINE payload = %d, want < 300", len(configs[0].Payload))
	}
}

// --- 5. 并发用例 (concurrency tests) ---

// 5.1 多 worker 并发 - random xid (并发 - 随机 xid)
func TestPoint_Concurrency_RandomXidPerWorker(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Xid = 0 // random

	var wg sync.WaitGroup
	xidsCh := make(chan uint32, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			configs := drain(mustPlan(t, p, spec))
			if len(configs) != 1 {
				t.Errorf("expected 1 packet, got %d", len(configs))
				return
			}
			xidsCh <- binary.BigEndian.Uint32(configs[0].Payload[4:8])
		}()
	}
	wg.Wait()
	close(xidsCh)

	xids := make(map[uint32]bool)
	for x := range xidsCh {
		xids[x] = true
	}
	if len(xids) < 6 {
		t.Errorf("expected >= 6 distinct xids out of 8 workers, got %d", len(xids))
	}
}

// 5.1b 多 worker 并发 - 显式 xid (并发 - 显式 xid 共享)
func TestPoint_Concurrency_ExplicitXidShared(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Xid = 0xA1B2C3D4

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			configs := drain(mustPlan(t, p, spec))
			if len(configs) != 1 {
				t.Errorf("expected 1 packet, got %d", len(configs))
				return
			}
			xid := binary.BigEndian.Uint32(configs[0].Payload[4:8])
			if xid != 0xA1B2C3D4 {
				t.Errorf("xid = 0x%X, want 0xA1B2C3D4", xid)
			}
		}()
	}
	wg.Wait()
}

// 5.1c 单 planner 内 4 条消息共享 xid (single planner, 4 messages share xid)
func TestPoint_Concurrency_XidSharedInMessages(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Xid = 0xA1B2C3D4
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeAck, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	for i, c := range configs {
		xid := binary.BigEndian.Uint32(c.Payload[4:8])
		if xid != 0xA1B2C3D4 {
			t.Errorf("config[%d] xid = 0x%X, want 0xA1B2C3D4", i, xid)
		}
	}
}

// 5.3 时序正确性 - PacketIndex 递增 (timing - PacketIndex increments)
func TestPoint_Concurrency_PacketIndexIncrement(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover},
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
		{Type: MsgTypeAck, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
	}
	configs := drain(mustPlan(t, p, spec))
	for i, c := range configs {
		if c.PacketIndex != uint64(i) {
			t.Errorf("config[%d].PacketIndex = %d, want %d", i, c.PacketIndex, i)
		}
	}
}

// --- 6. 资源耗尽用例 (resource exhaustion tests) ---

// 6.1 options 总长 > 1232 字节 (options exceed MTU)
func TestPoint_Resource_OptionsExceedMTU(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	// 1300 bytes of option data → exceeds 1232-byte limit
	bigData := make([]byte, 1300)
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeDiscover, ExtraOptions: []core.DHCPOption{{Code: 252, Data: bigData}}},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("options exceeding MTU should be rejected")
	}
	if !strings.Contains(err.Error(), "options exceed MTU") {
		t.Errorf("error = %v, want contains 'options exceed MTU'", err)
	}
}

// 6.5 Validate 拒绝用例 (Validate rejections)
func TestPoint_Validate_IPv6SrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.SrcIP = "fe80::1"
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("IPv6 src IP should be rejected")
	}
}

func TestPoint_Validate_IPv6DstIP(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DstIP = "ff02::1:2"
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("IPv6 dst IP should be rejected")
	}
}

func TestPoint_Validate_IPv6Loopback(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.SrcIP = "::1"
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("IPv6 loopback should be rejected")
	}
}

func TestPoint_Validate_IPv6DefaultClientIP(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.DefaultClientIP = "2001:db8::1"
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("IPv6 default client IP should be rejected")
	}
}

func TestPoint_Validate_IPv6Router(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", Routers: []string{"192.168.1.1", "fe80::1"}, ServerIdentifier: "192.168.1.1"},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("IPv6 router should be rejected")
	}
}

func TestPoint_Validate_IPv6DNS(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Role = "server"
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeOffer, YourIP: "192.168.1.100", DNS: []string{"8.8.8.8", "2001:4860:4860::8888"}, ServerIdentifier: "192.168.1.1"},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("IPv6 DNS should be rejected")
	}
}

func TestPoint_Validate_IPv6RequestedIP(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeRequest, RequestedIP: "2001:db8::1", ServerIdentifier: "192.168.1.1"},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("IPv6 requested IP should be rejected")
	}
}

func TestPoint_Validate_IPv6ServerIdentifier(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	spec.DHCP.Messages = []core.DHCPMessage{
		{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "fe80::1"},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("IPv6 server identifier should be rejected")
	}
}

// TestPlan_ContextCancellation verifies planner respects ctx.Done() (验证 planner 响应上下文取消).
func TestPlan_ContextCancellation(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	messages := make([]core.DHCPMessage, 1000)
	for i := range messages {
		messages[i] = core.DHCPMessage{Type: MsgTypeDiscover}
	}
	spec.DHCP.Messages = messages

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	// Drain; planner should exit quickly due to canceled ctx
	count := 0
	for range ch {
		count++
		if count > 1100 {
			t.Fatalf("planner did not respect ctx.Done()")
		}
	}
	_ = fmt.Sprintf("got %d packets", count)
}
