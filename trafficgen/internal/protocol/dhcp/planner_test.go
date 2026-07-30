package dhcp

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

// drain collects all configs from the channel (从通道收集所有配置).
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// mustPlan is a helper that fails the test if Plan returns an error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return ch
}

// validDHCPSpec returns a minimal valid DHCP spec for a 4-way handshake (返回最小可用的 DHCP 规格用于4次握手).
func validDHCPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "ff:ff:ff:ff:ff:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Xid:  0xA1B2C3D4,
			Messages: []core.DHCPMessage{
				{Type: MsgTypeDiscover},
			},
		},
	}
}

// TestPlanner_Name verifies planner Name (验证规划器名称).
func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if p.Name() != "dhcp" {
		t.Errorf("Name() = %s, want dhcp", p.Name())
	}
}

// TestPlanner_Validate validates basic planner behavior (验证基础行为).
func TestPlanner_Validate(t *testing.T) {
	p := NewPlanner()

	tests := []struct {
		name    string
		spec    core.FlowSpec
		wantErr bool
	}{
		{
			name:    "valid spec",
			spec:    validDHCPSpec(),
			wantErr: false,
		},
		{
			name: "missing DHCP config",
			spec: core.FlowSpec{
				SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
			},
			wantErr: true,
		},
		{
			name: "IPv6 src ip rejected",
			spec: core.FlowSpec{
				SrcIP: "fe80::1", DstIP: "255.255.255.255",
				DHCP: &core.DHCPConfig{
					Messages: []core.DHCPMessage{{Type: MsgTypeDiscover}},
				},
			},
			wantErr: true,
		},
		{
			name: "IPv6 dst ip rejected",
			spec: core.FlowSpec{
				SrcIP: "0.0.0.0", DstIP: "ff02::1:2",
				DHCP: &core.DHCPConfig{
					Messages: []core.DHCPMessage{{Type: MsgTypeDiscover}},
				},
			},
			wantErr: true,
		},
		{
			name: "empty messages rejected",
			spec: core.FlowSpec{
				SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
				DHCP: &core.DHCPConfig{
					Messages: []core.DHCPMessage{},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid message type rejected",
			spec: core.FlowSpec{
				SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
				DHCP: &core.DHCPConfig{
					Messages: []core.DHCPMessage{{Type: 9}},
				},
			},
			wantErr: true,
		},
		{
			name: "option overload (code 52) rejected",
			spec: core.FlowSpec{
				SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
				DHCP: &core.DHCPConfig{
					Messages: []core.DHCPMessage{
						{
							Type:         MsgTypeDiscover,
							ExtraOptions: []core.DHCPOption{{Code: 52, Data: []byte{0x01}}},
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestPlan_DORA verifies the standard 4-way handshake (验证标准4次握手 DISCOVER→OFFER→REQUEST→ACK).
func TestPlan_DORA(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "ff:ff:ff:ff:ff:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Xid:  0xA1B2C3D4,
			Messages: []core.DHCPMessage{
				{Type: MsgTypeDiscover},
				{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1", LeaseTime: 86400},
				{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
				{Type: MsgTypeAck, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1", LeaseTime: 86400},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 4 {
		t.Fatalf("expected 4 packets, got %d", len(configs))
	}

	// Verify packet indices increment (验证包序号递增)
	for i, c := range configs {
		if c.PacketIndex != uint64(i) {
			t.Errorf("config[%d].PacketIndex = %d, want %d", i, c.PacketIndex, i)
		}
	}

	// Verify directions (验证方向)
	expectedDirs := []string{"up", "down", "up", "down"}
	for i, c := range configs {
		if c.Direction != expectedDirs[i] {
			t.Errorf("config[%d].Direction = %s, want %s", i, c.Direction, expectedDirs[i])
		}
	}

	// Verify all share same xid (验证所有包共享同一 xid)
	for i, c := range configs {
		xid := binary.BigEndian.Uint32(c.Payload[4:8])
		if xid != 0xA1B2C3D4 {
			t.Errorf("config[%d] xid = 0x%X, want 0xA1B2C3D4", i, xid)
		}
	}

	// Verify op codes (验证操作码)
	expectedOps := []byte{OpBootrequest, OpBootreply, OpBootrequest, OpBootreply}
	for i, c := range configs {
		op := c.Payload[0]
		if op != expectedOps[i] {
			t.Errorf("config[%d] op = %d, want %d", i, op, expectedOps[i])
		}
	}

	// Verify magic cookie (验证魔术cookie)
	for i, c := range configs {
		cookie := binary.BigEndian.Uint32(c.Payload[236:240])
		if cookie != MagicCookie {
			t.Errorf("config[%d] magic cookie = 0x%X, want 0x%X", i, cookie, MagicCookie)
		}
	}

	// Verify option 53 in each packet (验证每包的 option 53)
	expectedTypes := []byte{MsgTypeDiscover, MsgTypeOffer, MsgTypeRequest, MsgTypeAck}
	for i, c := range configs {
		mt := findOption53(c.Payload)
		if mt != expectedTypes[i] {
			t.Errorf("config[%d] option 53 = %d, want %d", i, mt, expectedTypes[i])
		}
	}

	// Verify OFFER (config[1]) yiaddr = 192.168.1.100
	offeriP := net.IP(configs[1].Payload[16:20])
	if offeriP.String() != "192.168.1.100" {
		t.Errorf("OFFER yiaddr = %s, want 192.168.1.100", offeriP)
	}

	// Verify ACK (config[3]) yiaddr = 192.168.1.100
	ackIP := net.IP(configs[3].Payload[16:20])
	if ackIP.String() != "192.168.1.100" {
		t.Errorf("ACK yiaddr = %s, want 192.168.1.100", ackIP)
	}
}

// TestPlan_NAKPath verifies the NAK path (验证 NAK 路径).
func TestPlan_NAKPath(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Xid:  0x11223344,
			Messages: []core.DHCPMessage{
				{Type: MsgTypeDiscover},
				{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
				{Type: MsgTypeRequest, RequestedIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
				{Type: MsgTypeNak, ServerIdentifier: "192.168.1.1"},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 4 {
		t.Fatalf("expected 4 packets, got %d", len(configs))
	}

	// Verify NAK op = 2 (BOOTREPLY)
	if configs[3].Payload[0] != OpBootreply {
		t.Errorf("NAK op = %d, want %d", configs[3].Payload[0], OpBootreply)
	}

	// Verify NAK option 53 = 6
	mt := findOption53(configs[3].Payload)
	if mt != MsgTypeNak {
		t.Errorf("NAK option 53 = %d, want %d", mt, MsgTypeNak)
	}

	// Verify NAK direction = down
	if configs[3].Direction != "down" {
		t.Errorf("NAK direction = %s, want down", configs[3].Direction)
	}
}

// TestPlan_Release verifies RELEASE message (验证 RELEASE 消息).
func TestPlan_Release(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.50", DstIP: "192.168.1.1",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Xid:  0xAAAAAAAA,
			Messages: []core.DHCPMessage{
				{Type: MsgTypeDiscover},
				{Type: MsgTypeOffer, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
				{Type: MsgTypeRequest, RequestedIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
				{Type: MsgTypeAck, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
				{Type: MsgTypeRelease, ClientIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 5 {
		t.Fatalf("expected 5 packets, got %d", len(configs))
	}

	// Verify RELEASE op = 1 (BOOTREQUEST)
	release := configs[4]
	if release.Payload[0] != OpBootrequest {
		t.Errorf("RELEASE op = %d, want %d", release.Payload[0], OpBootrequest)
	}

	// Verify RELEASE option 53 = 7
	mt := findOption53(release.Payload)
	if mt != MsgTypeRelease {
		t.Errorf("RELEASE option 53 = %d, want %d", mt, MsgTypeRelease)
	}

	// Verify RELEASE ciaddr = 192.168.1.50
	ciaddr := net.IP(release.Payload[12:16])
	if ciaddr.String() != "192.168.1.50" {
		t.Errorf("RELEASE ciaddr = %s, want 192.168.1.50", ciaddr)
	}

	// Verify RELEASE direction = up
	if release.Direction != "up" {
		t.Errorf("RELEASE direction = %s, want up", release.Direction)
	}
}

// TestPlan_Inform verifies INFORM message (验证 INFORM 消息).
func TestPlan_Inform(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.50", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Xid:  0x99998888,
			Messages: []core.DHCPMessage{
				{Type: MsgTypeInform, ClientIP: "192.168.1.50"},
				{Type: MsgTypeAck, ServerIdentifier: "192.168.1.1"},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(configs))
	}

	// Verify INFORM op = 1
	inform := configs[0]
	if inform.Payload[0] != OpBootrequest {
		t.Errorf("INFORM op = %d, want %d", inform.Payload[0], OpBootrequest)
	}

	// Verify INFORM option 53 = 8
	mt := findOption53(inform.Payload)
	if mt != MsgTypeInform {
		t.Errorf("INFORM option 53 = %d, want %d", mt, MsgTypeInform)
	}

	// Verify INFORM ciaddr = 192.168.1.50
	ciaddr := net.IP(inform.Payload[12:16])
	if ciaddr.String() != "192.168.1.50" {
		t.Errorf("INFORM ciaddr = %s, want 192.168.1.50", ciaddr)
	}

	// Verify INFORM does NOT carry option 50 (Requested IP)
	if hasOption(inform.Payload, 50) {
		t.Errorf("INFORM should not carry option 50 (Requested IP)")
	}
	// Verify INFORM does NOT carry option 51 (Lease Time)
	if hasOption(inform.Payload, 51) {
		t.Errorf("INFORM should not carry option 51 (Lease Time)")
	}
}

// TestPlan_Renew verifies RENEWING (unicast REQUEST with server identifier) (验证续约: 单播 REQUEST).
func TestPlan_Renew(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.50", DstIP: "192.168.1.1",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Xid:  0xBBBBBBBB,
			Messages: []core.DHCPMessage{
				{Type: MsgTypeDiscover},
				{Type: MsgTypeOffer, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1", LeaseTime: 86400},
				{Type: MsgTypeRequest, RequestedIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
				{Type: MsgTypeAck, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1", LeaseTime: 86400},
				// RENEWING: unicast REQUEST with ciaddr=current IP and option 54=server IP
				{Type: MsgTypeRequest, ClientIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
				{Type: MsgTypeAck, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1", LeaseTime: 86400},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 6 {
		t.Fatalf("expected 6 packets, got %d", len(configs))
	}

	// Verify the RENEWING REQUEST (config[4]) has ciaddr = 192.168.1.50
	renewReq := configs[4]
	ciaddr := net.IP(renewReq.Payload[12:16])
	if ciaddr.String() != "192.168.1.50" {
		t.Errorf("RENEWING REQUEST ciaddr = %s, want 192.168.1.50", ciaddr)
	}

	// Verify option 54 = 192.168.1.1
	if !hasOption(renewReq.Payload, 54) {
		t.Errorf("RENEWING REQUEST should carry option 54 (Server Identifier)")
	}
}

// TestPlan_Decline verifies DECLINE message (验证 DECLINE 消息).
func TestPlan_Decline(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Xid:  0xCCCCCCCC,
			Messages: []core.DHCPMessage{
				{Type: MsgTypeDiscover},
				{Type: MsgTypeOffer, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
				{Type: MsgTypeRequest, RequestedIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
				{Type: MsgTypeAck, YourIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
				{Type: MsgTypeDecline, RequestedIP: "192.168.1.50", ServerIdentifier: "192.168.1.1"},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 5 {
		t.Fatalf("expected 5 packets, got %d", len(configs))
	}

	decline := configs[4]

	// Verify DECLINE op = 1
	if decline.Payload[0] != OpBootrequest {
		t.Errorf("DECLINE op = %d, want %d", decline.Payload[0], OpBootrequest)
	}

	// Verify DECLINE option 53 = 4
	mt := findOption53(decline.Payload)
	if mt != MsgTypeDecline {
		t.Errorf("DECLINE option 53 = %d, want %d", mt, MsgTypeDecline)
	}

	// Verify DECLINE carries option 50 (Requested IP)
	if !hasOption(decline.Payload, 50) {
		t.Errorf("DECLINE should carry option 50 (Requested IP)")
	}

	// Verify DECLINE carries option 54 (Server Identifier)
	if !hasOption(decline.Payload, 54) {
		t.Errorf("DECLINE should carry option 54 (Server Identifier)")
	}
}

// TestPlan_Starvation verifies multiple DISCOVERs for starvation scenario (验证地址耗尽场景).
func TestPlan_Starvation(t *testing.T) {
	p := NewPlanner()
	messages := make([]core.DHCPMessage, 100)
	for i := range messages {
		messages[i] = core.DHCPMessage{Type: MsgTypeDiscover}
	}
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role:     "client",
			Messages: messages,
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 100 {
		t.Fatalf("expected 100 packets, got %d", len(configs))
	}

	// Verify all DISCOVER use src port 68 and dst port 67
	for i, c := range configs {
		if c.L4.SrcPort != ClientPort {
			t.Errorf("config[%d] SrcPort = %d, want %d", i, c.L4.SrcPort, ClientPort)
		}
		if c.L4.DstPort != ServerPort {
			t.Errorf("config[%d] DstPort = %d, want %d", i, c.L4.DstPort, ServerPort)
		}
	}
}

// TestPlan_RelayAgent verifies relay agent scenario (验证中继代理场景).
func TestPlan_RelayAgent(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.2.1", DstIP: "10.0.0.1",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "relay",
			Xid:  0x12345678,
			Messages: []core.DHCPMessage{
				{
					Type:           MsgTypeDiscover,
					RelayAgentIP:   "192.168.2.1",
					Hops:           1,
					RelayAgentInfo: []byte{0x01, 0x06, 'e', 't', 'h', '0', '0', 0x02, 0x05, 'A', 'P', '1'},
				},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	c := configs[0]

	// Verify relay uses both ports = 67
	if c.L4.SrcPort != ServerPort {
		t.Errorf("relay SrcPort = %d, want %d", c.L4.SrcPort, ServerPort)
	}
	if c.L4.DstPort != ServerPort {
		t.Errorf("relay DstPort = %d, want %d", c.L4.DstPort, ServerPort)
	}

	// Verify giaddr = 192.168.2.1
	giaddr := net.IP(c.Payload[24:28])
	if giaddr.String() != "192.168.2.1" {
		t.Errorf("giaddr = %s, want 192.168.2.1", giaddr)
	}

	// Verify hops = 1
	if c.Payload[3] != 1 {
		t.Errorf("hops = %d, want 1", c.Payload[3])
	}

	// Verify option 82 is present
	if !hasOption(c.Payload, 82) {
		t.Errorf("relay should carry option 82")
	}
}

// TestPlan_ClientMACDefault verifies ClientMAC defaults to spec.SrcMAC (验证 ClientMAC 默认值).
func TestPlan_ClientMACDefault(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role:     "client",
			Messages: []core.DHCPMessage{{Type: MsgTypeDiscover}},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	// chaddr (bytes 28-33) should be aa:bb:cc:dd:ee:ff
	chaddr := configs[0].Payload[28:34]
	expected := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for i, b := range chaddr {
		if b != expected[i] {
			t.Errorf("chaddr[%d] = 0x%X, want 0x%X", i, b, expected[i])
		}
	}

	// chaddr[6:16] should be zero
	for i, b := range configs[0].Payload[34:44] {
		if b != 0 {
			t.Errorf("chaddr[6+%d] = 0x%X, want 0x00", i, b)
		}
	}
}

// TestPlan_RandomXid verifies random xid generation when Xid=0 (验证随机 xid 生成).
func TestPlan_RandomXid(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role:     "client",
			Xid:      0, // random
			Messages: []core.DHCPMessage{{Type: MsgTypeDiscover}},
		},
	}

	// Run Plan 100 times, collect xids, verify no duplicates
	xids := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		configs := drain(mustPlan(t, p, spec))
		if len(configs) != 1 {
			t.Fatalf("expected 1 packet, got %d", len(configs))
		}
		xid := binary.BigEndian.Uint32(configs[0].Payload[4:8])
		if xid == 0 {
			t.Errorf("random xid should not be 0")
		}
		xids[xid] = true
	}

	// Allow some collisions due to randomness; just verify we got many distinct values
	if len(xids) < 90 {
		t.Errorf("expected at least 90 distinct xids out of 100, got %d", len(xids))
	}
}

// TestPlan_Concurrent verifies concurrent Plan calls don't race (验证并发 Plan 调用无竞态).
func TestPlan_Concurrent(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			configs := drain(mustPlan(t, p, spec))
			if len(configs) != 1 {
				t.Errorf("expected 1 packet, got %d", len(configs))
			}
		}()
	}
	wg.Wait()
}

// --- helpers ---

// findOption53 returns the value of option 53 (DHCP Message Type) or 0 if not found.
func findOption53(payload []byte) byte {
	return findOption(payload, 53)[0]
}

// findOption returns the data of the given option code, or nil if not found.
func findOption(payload []byte, code uint8) []byte {
	if len(payload) < 240 {
		return nil
	}
	// options start at offset 240
	i := 240
	for i < len(payload) {
		c := payload[i]
		if c == 0 {
			i++
			continue
		}
		if c == 255 {
			return nil // END
		}
		if i+1 >= len(payload) {
			return nil
		}
		l := payload[i+1]
		if int(c) == int(code) {
			return payload[i+2 : i+2+int(l)]
		}
		i += 2 + int(l)
	}
	return nil
}

// hasOption returns true if the option is present.
func hasOption(payload []byte, code uint8) bool {
	return findOption(payload, code) != nil
}

// TestPlan_BroadcastFlag verifies broadcast flag is encoded (验证广播标志编码).
func TestPlan_BroadcastFlag(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role:          "client",
			BroadcastFlag: true,
			Messages:      []core.DHCPMessage{{Type: MsgTypeDiscover}},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	// flags at bytes 10-11, expect 0x8000
	flags := binary.BigEndian.Uint16(configs[0].Payload[10:12])
	if flags != BroadcastFlag {
		t.Errorf("flags = 0x%X, want 0x%X", flags, BroadcastFlag)
	}
}

// TestPlan_SecondsField verifies secs field is encoded (验证 secs 字段编码).
func TestPlan_SecondsField(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role:     "client",
			Secs:     60,
			Messages: []core.DHCPMessage{{Type: MsgTypeDiscover}},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	secs := binary.BigEndian.Uint16(configs[0].Payload[8:10])
	if secs != 60 {
		t.Errorf("secs = %d, want 60", secs)
	}
}

// TestPlan_MagicCookie verifies magic cookie is always 0x63825363 (验证魔术cookie).
func TestPlan_MagicCookie(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	cookie := binary.BigEndian.Uint32(configs[0].Payload[236:240])
	if cookie != MagicCookie {
		t.Errorf("magic cookie = 0x%X, want 0x%X", cookie, MagicCookie)
	}
}

// TestPlan_OptionEnd verifies options end with 0xFF (END) (验证选项以 END 结尾).
func TestPlan_OptionEnd(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	// Find END (0xFF) in options
	payload := configs[0].Payload
	if len(payload) < 240 {
		t.Fatalf("payload too short: %d", len(payload))
	}

	// Scan from offset 240 until END
	i := 240
	for i < len(payload) {
		c := payload[i]
		if c == 0 { // PAD
			i++
			continue
		}
		if c == 255 { // END
			break
		}
		if i+1 >= len(payload) {
			t.Fatalf("truncated option at offset %d", i)
		}
		l := int(payload[i+1])
		i += 2 + l
	}
	if i >= len(payload) || payload[i] != 255 {
		t.Errorf("options do not end with END (0xFF)")
	}
}

// TestPlan_HType verifies hardware type encoding (验证硬件类型编码).
func TestPlan_HType(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role:     "client",
			HType:    1,
			HLen:     6,
			Messages: []core.DHCPMessage{{Type: MsgTypeDiscover}},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	if configs[0].Payload[1] != 1 {
		t.Errorf("htype = %d, want 1", configs[0].Payload[1])
	}
	if configs[0].Payload[2] != 6 {
		t.Errorf("hlen = %d, want 6", configs[0].Payload[2])
	}
}

// TestPlan_MinimalPayload verifies minimum DHCP payload size (验证最小 DHCP 载荷大小).
// Minimum DHCP packet = 236 (BOOTP) + 4 (magic) + 3 (option 53) + 1 (END) = 244 bytes
func TestPlan_MinimalPayload(t *testing.T) {
	p := NewPlanner()
	spec := validDHCPSpec()
	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	minSize := BootpHeaderLen + MagicCookieLen + 3 + 1 // 244
	if len(configs[0].Payload) < minSize {
		t.Errorf("payload size = %d, want >= %d", len(configs[0].Payload), minSize)
	}
}

// TestPlan_OptionOverloadRejected verifies option 52 is rejected (验证 option 52 被拒绝).
func TestPlan_OptionOverloadRejected(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Messages: []core.DHCPMessage{
				{
					Type:         MsgTypeDiscover,
					ExtraOptions: []core.DHCPOption{{Code: 52, Data: []byte{0x01}}},
				},
			},
		},
	}

	err := p.Validate(spec)
	if err == nil {
		t.Fatalf("Validate should reject option overload (code 52)")
	}
	if !strings.Contains(err.Error(), "option overload not supported") {
		t.Errorf("error = %v, want contains 'option overload not supported'", err)
	}
}

// TestPlan_OptionENDRejected verifies option 255 in ExtraOptions is rejected (验证 option 255 在 ExtraOptions 中被拒绝).
func TestPlan_OptionENDRejected(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Messages: []core.DHCPMessage{
				{
					Type:         MsgTypeDiscover,
					ExtraOptions: []core.DHCPOption{{Code: 255, Data: nil}},
				},
			},
		},
	}

	err := p.Validate(spec)
	if err == nil {
		t.Fatalf("Validate should reject option 255 END in ExtraOptions")
	}
}

// TestPlan_OptionSubnetMask verifies option 1 (Subnet Mask) encoding (验证 option 1 子网掩码编码).
func TestPlan_OptionSubnetMask(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "server",
			Messages: []core.DHCPMessage{
				{
					Type:             MsgTypeOffer,
					YourIP:           "192.168.1.100",
					SubnetMask:       "255.255.255.0",
					ServerIdentifier: "192.168.1.1",
				},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	opt := findOption(configs[0].Payload, 1)
	if opt == nil {
		t.Fatalf("option 1 (Subnet Mask) not found")
	}
	if len(opt) != 4 {
		t.Errorf("option 1 length = %d, want 4", len(opt))
	}
	expected := []byte{255, 255, 255, 0}
	for i, b := range opt {
		if b != expected[i] {
			t.Errorf("option 1 byte[%d] = %d, want %d", i, b, expected[i])
		}
	}
}

// TestPlan_OptionRouters verifies option 3 (Router) encoding (验证 option 3 路由器编码).
func TestPlan_OptionRouters(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "server",
			Messages: []core.DHCPMessage{
				{
					Type:             MsgTypeOffer,
					YourIP:           "192.168.1.100",
					Routers:          []string{"192.168.1.1", "192.168.1.2"},
					ServerIdentifier: "192.168.1.1",
				},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	opt := findOption(configs[0].Payload, 3)
	if opt == nil {
		t.Fatalf("option 3 (Router) not found")
	}
	if len(opt) != 8 {
		t.Errorf("option 3 length = %d, want 8", len(opt))
	}
}

// TestPlan_OptionDNS verifies option 6 (DNS) encoding (验证 option 6 DNS 编码).
func TestPlan_OptionDNS(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "server",
			Messages: []core.DHCPMessage{
				{
					Type:             MsgTypeOffer,
					YourIP:           "192.168.1.100",
					DNS:              []string{"8.8.8.8", "1.1.1.1"},
					ServerIdentifier: "192.168.1.1",
				},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	opt := findOption(configs[0].Payload, 6)
	if opt == nil {
		t.Fatalf("option 6 (DNS) not found")
	}
	if len(opt) != 8 {
		t.Errorf("option 6 length = %d, want 8", len(opt))
	}
}

// TestPlan_OptionLeaseTime verifies option 51 (Lease Time) encoding (验证 option 51 租期编码).
func TestPlan_OptionLeaseTime(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "server",
			Messages: []core.DHCPMessage{
				{
					Type:             MsgTypeOffer,
					YourIP:           "192.168.1.100",
					LeaseTime:        86400,
					ServerIdentifier: "192.168.1.1",
				},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	opt := findOption(configs[0].Payload, 51)
	if opt == nil {
		t.Fatalf("option 51 (Lease Time) not found")
	}
	if len(opt) != 4 {
		t.Errorf("option 51 length = %d, want 4", len(opt))
	}
	lt := binary.BigEndian.Uint32(opt)
	if lt != 86400 {
		t.Errorf("option 51 value = %d, want 86400", lt)
	}
}

// TestPlan_OptionServerIdentifier verifies option 54 (Server Identifier) encoding (验证 option 54 服务器标识编码).
func TestPlan_OptionServerIdentifier(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "server",
			Messages: []core.DHCPMessage{
				{
					Type:             MsgTypeOffer,
					YourIP:           "192.168.1.100",
					ServerIdentifier: "192.168.1.1",
				},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	opt := findOption(configs[0].Payload, 54)
	if opt == nil {
		t.Fatalf("option 54 (Server Identifier) not found")
	}
	if len(opt) != 4 {
		t.Errorf("option 54 length = %d, want 4", len(opt))
	}
	expected := net.ParseIP("192.168.1.1").To4()
	for i, b := range opt {
		if b != expected[i] {
			t.Errorf("option 54 byte[%d] = %d, want %d", i, b, expected[i])
		}
	}
}

// TestPlan_OptionParamRequestList verifies option 55 (Parameter Request List) encoding (验证 option 55 参数请求列表编码).
func TestPlan_OptionParamRequestList(t *testing.T) {
	p := NewPlanner()
	prl := []uint8{1, 3, 6, 15, 51, 54, 58, 59}
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Messages: []core.DHCPMessage{
				{
					Type:             MsgTypeDiscover,
					ParamRequestList: prl,
				},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	opt := findOption(configs[0].Payload, 55)
	if opt == nil {
		t.Fatalf("option 55 (Parameter Request List) not found")
	}
	if len(opt) != len(prl) {
		t.Errorf("option 55 length = %d, want %d", len(opt), len(prl))
	}
	for i, b := range opt {
		if b != prl[i] {
			t.Errorf("option 55 byte[%d] = %d, want %d", i, b, prl[i])
		}
	}
}

// TestPlan_OptionHostname verifies option 12 (Hostname) encoding (验证 option 12 主机名编码).
func TestPlan_OptionHostname(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Messages: []core.DHCPMessage{
				{
					Type:     MsgTypeDiscover,
					Hostname: "client01",
				},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	opt := findOption(configs[0].Payload, 12)
	if opt == nil {
		t.Fatalf("option 12 (Hostname) not found")
	}
	if string(opt) != "client01" {
		t.Errorf("option 12 = %s, want client01", string(opt))
	}
}

// TestPlan_OptionVendorClass verifies option 60 (Vendor Class) encoding (验证 option 60 厂商类别编码).
func TestPlan_OptionVendorClass(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Messages: []core.DHCPMessage{
				{
					Type:        MsgTypeDiscover,
					VendorClass: "MSFT 5.0",
				},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	opt := findOption(configs[0].Payload, 60)
	if opt == nil {
		t.Fatalf("option 60 (Vendor Class) not found")
	}
	if string(opt) != "MSFT 5.0" {
		t.Errorf("option 60 = %s, want MSFT 5.0", string(opt))
	}
}

// TestPlan_OptionClientID verifies option 61 (Client ID) encoding (验证 option 61 客户端标识编码).
func TestPlan_OptionClientID(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Messages: []core.DHCPMessage{
				{
					Type:     MsgTypeDiscover,
					ClientID: []byte{0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
				},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	opt := findOption(configs[0].Payload, 61)
	if opt == nil {
		t.Fatalf("option 61 (Client ID) not found")
	}
	if len(opt) != 7 {
		t.Errorf("option 61 length = %d, want 7", len(opt))
	}
	if opt[0] != 0x01 {
		t.Errorf("option 61 type = 0x%X, want 0x01", opt[0])
	}
}

// TestPlan_OptionRelayAgentInfo verifies option 82 (Relay Agent Info) encoding (验证 option 82 中继代理信息编码).
func TestPlan_OptionRelayAgentInfo(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.2.1", DstIP: "10.0.0.1",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "relay",
			Messages: []core.DHCPMessage{
				{
					Type:           MsgTypeDiscover,
					RelayAgentIP:   "192.168.2.1",
					Hops:           1,
					RelayAgentInfo: []byte{0x01, 0x06, 'V', 'L', 'A', 'N', '1', '0', '0'},
				},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	opt := findOption(configs[0].Payload, 82)
	if opt == nil {
		t.Fatalf("option 82 (Relay Agent Info) not found")
	}
	if len(opt) != 9 {
		t.Errorf("option 82 length = %d, want 9", len(opt))
	}
}

// TestPlan_SnameField verifies sname field encoding (验证 sname 字段编码).
func TestPlan_SnameField(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role:     "client",
			Sname:    "dhcp-server-01",
			Messages: []core.DHCPMessage{{Type: MsgTypeDiscover}},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	// sname at bytes 44-107
	sname := configs[0].Payload[44:108]
	expected := []byte("dhcp-server-01")
	for i, b := range expected {
		if sname[i] != b {
			t.Errorf("sname[%d] = 0x%X, want 0x%X", i, sname[i], b)
		}
	}
	// bytes after the string should be 0
	for i, b := range sname[len(expected):] {
		if b != 0 {
			t.Errorf("sname[%d] = 0x%X, want 0x00", len(expected)+i, b)
		}
	}
}

// TestPlan_FileField verifies file field encoding (验证 file 字段编码).
func TestPlan_FileField(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role:     "client",
			File:     "pxelinux.0",
			Messages: []core.DHCPMessage{{Type: MsgTypeDiscover}},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	// file at bytes 108-235
	file := configs[0].Payload[108:236]
	expected := []byte("pxelinux.0")
	for i, b := range expected {
		if file[i] != b {
			t.Errorf("file[%d] = 0x%X, want 0x%X", i, file[i], b)
		}
	}
}

// TestPlan_ChaddrField verifies chaddr field encoding (验证 chaddr 字段编码).
func TestPlan_ChaddrField(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role:      "client",
			ClientMAC: "11:22:33:44:55:66",
			Messages:  []core.DHCPMessage{{Type: MsgTypeDiscover}},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	// chaddr at bytes 28-43
	chaddr := configs[0].Payload[28:44]
	expected := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for i, b := range expected {
		if chaddr[i] != b {
			t.Errorf("chaddr[%d] = 0x%X, want 0x%X", i, chaddr[i], b)
		}
	}
}

// TestPlan_DefaultRole verifies default Role = client (验证默认角色为 client).
func TestPlan_DefaultRole(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			// Role empty -> default "client"
			Messages: []core.DHCPMessage{{Type: MsgTypeDiscover}},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	if configs[0].L4.SrcPort != ClientPort {
		t.Errorf("default Role=client SrcPort = %d, want %d", configs[0].L4.SrcPort, ClientPort)
	}
	if configs[0].L4.DstPort != ServerPort {
		t.Errorf("default Role=client DstPort = %d, want %d", configs[0].L4.DstPort, ServerPort)
	}
}

// TestPlan_DefaultMessages verifies default Messages = [{Type:1}] when nil (验证 Messages 缺省值).
func TestPlan_DefaultMessages(t *testing.T) {
	// Empty Messages is rejected by Validate; need explicit message.
	// But nil DHCPConfig entirely is also rejected.
	// Test with empty Messages -> should error.
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("empty Messages should be rejected")
	}
}

// TestPlan_ExtraOptions verifies extra options are encoded (验证额外选项编码).
func TestPlan_ExtraOptions(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Messages: []core.DHCPMessage{
				{
					Type: MsgTypeDiscover,
					ExtraOptions: []core.DHCPOption{
						{Code: 252, Data: []byte("http://proxy.example.com/wpad.dat")},
					},
				},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	opt := findOption(configs[0].Payload, 252)
	if opt == nil {
		t.Fatalf("option 252 (WPAD) not found")
	}
	if string(opt) != "http://proxy.example.com/wpad.dat" {
		t.Errorf("option 252 = %s, want http://proxy.example.com/wpad.dat", string(opt))
	}
}

// TestPlan_OptionsExceedMTU verifies that options exceeding MTU are rejected (验证 options 超过 MTU 被拒绝).
func TestPlan_OptionsExceedMTU(t *testing.T) {
	p := NewPlanner()
	// Create a message with extra options exceeding 1232 bytes
	bigData := make([]byte, 1300)
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Messages: []core.DHCPMessage{
				{
					Type: MsgTypeDiscover,
					ExtraOptions: []core.DHCPOption{
						{Code: 252, Data: bigData},
					},
				},
			},
		},
	}

	err := p.Validate(spec)
	if err == nil {
		t.Errorf("options exceeding MTU should be rejected")
	}
	if !strings.Contains(err.Error(), "options exceed MTU") {
		t.Errorf("error = %v, want contains 'options exceed MTU'", err)
	}
}

// TestPlan_HLenInconsistent verifies HType=1 with HLen!=6 is rejected (验证 HType=1 但 HLen!=6 被拒绝).
func TestPlan_HLenInconsistent(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role:     "client",
			HType:    1,
			HLen:     8, // Ethernet requires HLen=6
			Messages: []core.DHCPMessage{{Type: MsgTypeDiscover}},
		},
	}

	err := p.Validate(spec)
	if err == nil {
		t.Errorf("HType=1 with HLen=8 should be rejected")
	}
}

// TestPlan_HostnameExceeds255 verifies hostname > 255 bytes is rejected (验证 hostname > 255 字节被拒绝).
func TestPlan_HostnameExceeds255(t *testing.T) {
	p := NewPlanner()
	longHost := strings.Repeat("a", 256)
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "client",
			Messages: []core.DHCPMessage{
				{Type: MsgTypeDiscover, Hostname: longHost},
			},
		},
	}

	err := p.Validate(spec)
	if err == nil {
		t.Errorf("hostname > 255 bytes should be rejected")
	}
}

// TestPlan_RoleServer verifies Role=server uses ports 67/68 (验证 Role=server 端口).
func TestPlan_RoleServer(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.100",
		SrcMAC: "11:22:33:44:55:66", DstMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "server",
			Messages: []core.DHCPMessage{
				{Type: MsgTypeOffer, YourIP: "192.168.1.100", ServerIdentifier: "192.168.1.1"},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	if configs[0].L4.SrcPort != ServerPort {
		t.Errorf("server SrcPort = %d, want %d", configs[0].L4.SrcPort, ServerPort)
	}
	if configs[0].L4.DstPort != ClientPort {
		t.Errorf("server DstPort = %d, want %d", configs[0].L4.DstPort, ClientPort)
	}
	if configs[0].Direction != "down" {
		t.Errorf("OFFER direction = %s, want down", configs[0].Direction)
	}
}

// TestPlan_XidBoundary verifies xid boundary values (验证 xid 边界值).
func TestPlan_XidBoundary(t *testing.T) {
	tests := []struct {
		name string
		xid  uint32
	}{
		{"min", 0x00000001},
		{"max", 0xFFFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPlanner()
			spec := core.FlowSpec{
				SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
				SrcMAC: "aa:bb:cc:dd:ee:ff",
				DHCP: &core.DHCPConfig{
					Role:     "client",
					Xid:      tt.xid,
					Messages: []core.DHCPMessage{{Type: MsgTypeDiscover}},
				},
			}

			configs := drain(mustPlan(t, p, spec))
			if len(configs) != 1 {
				t.Fatalf("expected 1 packet, got %d", len(configs))
			}
			got := binary.BigEndian.Uint32(configs[0].Payload[4:8])
			if got != tt.xid {
				t.Errorf("xid = 0x%X, want 0x%X", got, tt.xid)
			}
		})
	}
}

// TestPlan_OptionT1T2 verifies option 58 (T1) and option 59 (T2) encoding (验证 option 58/59 编码).
func TestPlan_OptionT1T2(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role: "server",
			Messages: []core.DHCPMessage{
				{
					Type:             MsgTypeOffer,
					YourIP:           "192.168.1.100",
					ServerIdentifier: "192.168.1.1",
					LeaseTime:        86400,
					T1:               43200,
					T2:               75600,
				},
			},
		},
	}

	configs := drain(mustPlan(t, p, spec))
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}

	opt58 := findOption(configs[0].Payload, 58)
	if opt58 == nil {
		t.Fatalf("option 58 (T1) not found")
	}
	t1 := binary.BigEndian.Uint32(opt58)
	if t1 != 43200 {
		t.Errorf("T1 = %d, want 43200", t1)
	}

	opt59 := findOption(configs[0].Payload, 59)
	if opt59 == nil {
		t.Fatalf("option 59 (T2) not found")
	}
	t2 := binary.BigEndian.Uint32(opt59)
	if t2 != 75600 {
		t.Errorf("T2 = %d, want 75600", t2)
	}
}

// TestPlan_InferredDirection verifies direction inference from message type (验证方向推断).
func TestPlan_InferredDirection(t *testing.T) {
	tests := []struct {
		msgType  uint8
		expected string
	}{
		{MsgTypeDiscover, "up"},
		{MsgTypeOffer, "down"},
		{MsgTypeRequest, "up"},
		{MsgTypeDecline, "up"},
		{MsgTypeAck, "down"},
		{MsgTypeNak, "down"},
		{MsgTypeRelease, "up"},
		{MsgTypeInform, "up"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("type_%d", tt.msgType), func(t *testing.T) {
			p := NewPlanner()
			spec := core.FlowSpec{
				SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
				SrcMAC: "aa:bb:cc:dd:ee:ff",
				DHCP: &core.DHCPConfig{
					Role:     "client",
					Messages: []core.DHCPMessage{{Type: tt.msgType}},
				},
			}
			configs := drain(mustPlan(t, p, spec))
			if len(configs) != 1 {
				t.Fatalf("expected 1 packet, got %d", len(configs))
			}
			if configs[0].Direction != tt.expected {
				t.Errorf("type %d direction = %s, want %s", tt.msgType, configs[0].Direction, tt.expected)
			}
		})
	}
}
