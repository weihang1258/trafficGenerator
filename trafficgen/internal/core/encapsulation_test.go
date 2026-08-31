package core

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// 三封装协议共用内层帧构造器/fixture 校验的单测（逻辑与 nvgre 包内已提交
// 实现一致；此处锁定 core 侧副本，防移植漂移）。

func TestBuildEncapEthernetFrameIPv4(t *testing.T) {
	fix := &EncapEthernetFixture{
		SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01",
		EtherType: "ipv4", SrcIP: "172.16.1.1", DstIP: "172.16.1.2",
		Payload: []byte("inner-01"),
	}
	b, err := BuildEncapEthernetFrame(fix)
	if err != nil {
		t.Fatalf("ipv4: %v", err)
	}
	if len(b) != 14+20+8 {
		t.Fatalf("len %d, want 42", len(b))
	}
	if !bytes.Equal(b[0:6], []byte{2, 0xbb, 0, 0, 0, 1}) || !bytes.Equal(b[6:12], []byte{2, 0xaa, 0, 0, 0, 1}) {
		t.Errorf("MAC order wrong (dst first): % x", b[0:12])
	}
	if !bytes.Equal(b[12:14], []byte{0x08, 0x00}) {
		t.Errorf("EtherType % x", b[12:14])
	}
	if hdr := b[14:34]; !encapVerifyIPv4Checksum(hdr) {
		t.Errorf("inner IPv4 checksum invalid: % x", hdr)
	}
	if b[14+9] != EncapInnerProtoIPv4 {
		t.Errorf("inner proto %d, want %d", b[14+9], EncapInnerProtoIPv4)
	}
	if !bytes.Equal(b[26:30], []byte{172, 16, 1, 1}) || !bytes.Equal(b[30:34], []byte{172, 16, 1, 2}) {
		t.Errorf("inner addrs % x / % x", b[26:30], b[30:34])
	}
	if string(b[34:]) != "inner-01" {
		t.Errorf("payload %q", b[34:])
	}
}

func TestBuildEncapEthernetFrameIPv6(t *testing.T) {
	fix := &EncapEthernetFixture{
		SrcMAC: "02:aa::11", EtherType: "ipv6", SrcIP: "fc00::1", DstIP: "fc00::2",
		Payload: []byte("v6"),
	}
	// SrcMAC 故意写非法值验证校验先行……不——本测试针对 v6 布局，改用合法值。
	fix.SrcMAC = "02:aa:00:00:00:11"
	fix.DstMAC = "02:bb:00:00:00:11"
	b, err := BuildEncapEthernetFrame(fix)
	if err != nil {
		t.Fatalf("ipv6: %v", err)
	}
	if len(b) != 14+40+2 {
		t.Fatalf("len %d, want 56", len(b))
	}
	if !bytes.Equal(b[12:14], []byte{0x86, 0xdd}) {
		t.Errorf("EtherType % x", b[12:14])
	}
	if v := b[14] >> 4; v != 6 {
		t.Errorf("version %d", v)
	}
	if pl := binary.BigEndian.Uint16(b[14+4 : 14+6]); pl != 2 {
		t.Errorf("payload len %d, want 2", pl)
	}
	if b[14+6] != EncapInnerIPv6NoNextHdr {
		t.Errorf("next header %d, want 59", b[14+6])
	}
	if b[14+7] != 64 {
		t.Errorf("hop limit %d", b[14+7])
	}
}

func TestBuildEncapEthernetFrameVLAN(t *testing.T) {
	fix := &EncapEthernetFixture{
		SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01",
		EtherType: "vlan_ipv4", VLANID: 100, VLANPriority: 3,
		SrcIP: "172.16.1.1", DstIP: "172.16.1.2", Payload: []byte("p"),
	}
	b, err := BuildEncapEthernetFrame(fix)
	if err != nil {
		t.Fatalf("vlan_ipv4: %v", err)
	}
	if len(b) != 18+20+1 {
		t.Fatalf("len %d, want 39", len(b))
	}
	if !bytes.Equal(b[12:16], []byte{0x81, 0x00, 0x60, 0x64}) { // PCP3<<13|VID100
		t.Errorf("vlan tag % x, want 81 00 60 64", b[12:16])
	}
	if !bytes.Equal(b[16:18], []byte{0x08, 0x00}) {
		t.Errorf("post-VLAN EtherType % x", b[16:18])
	}

	// vlan_ipv6 + TCI 边界 0xEFFF（PCP7/VID4095）。
	fix6 := &EncapEthernetFixture{
		SrcMAC: "02:aa:00:00:00:11", DstMAC: "02:bb:00:00:00:11",
		EtherType: "vlan_ipv6", VLANID: 4095, VLANPriority: 7,
		SrcIP: "fc00::1", DstIP: "fc00::2", Payload: []byte("p"),
	}
	b, err = BuildEncapEthernetFrame(fix6)
	if err != nil {
		t.Fatalf("vlan_ipv6: %v", err)
	}
	if !bytes.Equal(b[12:16], []byte{0x81, 0x00, 0xef, 0xff}) {
		t.Errorf("vlan_ipv6 TCI % x, want ef ff", b[12:16])
	}
}

func TestBuildEncapEthernetFrameEmptyPayload(t *testing.T) {
	fix := &EncapEthernetFixture{
		SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01",
		EtherType: "ipv4", SrcIP: "172.16.1.1", DstIP: "172.16.1.2",
	}
	b, err := BuildEncapEthernetFrame(fix)
	if err != nil {
		t.Fatalf("empty payload: %v", err)
	}
	if len(b) != 34 {
		t.Errorf("len %d, want 34 (完整 Ethernet header 仍存在)", len(b))
	}
}

func encapVerifyIPv4Checksum(hdr []byte) bool {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum == 0xffff
}

func TestValidateEncapFixtureRejections(t *testing.T) {
	valid := func() *EncapEthernetFixture {
		return &EncapEthernetFixture{SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01",
			EtherType: "ipv4", SrcIP: "172.16.1.1", DstIP: "172.16.1.2"}
	}
	cases := []struct {
		name string
		mut  func(f *EncapEthernetFixture)
	}{
		{"bad src mac", func(f *EncapEthernetFixture) { f.SrcMAC = "nope" }},
		{"bad dst mac len", func(f *EncapEthernetFixture) { f.DstMAC = "02:bb:00:00:00" }},
		{"bad ether type", func(f *EncapEthernetFixture) { f.EtherType = "gre" }},
		{"vid overflow", func(f *EncapEthernetFixture) { f.EtherType = "vlan_ipv4"; f.VLANID = 4096 }},
		{"pcp overflow", func(f *EncapEthernetFixture) { f.EtherType = "vlan_ipv4"; f.VLANPriority = 8 }},
		{"family v6type v4addr", func(f *EncapEthernetFixture) { f.EtherType = "ipv6" }},
		{"family v4type v6addr", func(f *EncapEthernetFixture) { f.SrcIP = "fc00::1" }},
		{"unparseable ip", func(f *EncapEthernetFixture) { f.SrcIP = "not-an-ip" }},
		{"payload overflow", func(f *EncapEthernetFixture) { f.Payload = make([]byte, 0xffff) }},
	}
	for _, c := range cases {
		f := valid()
		c.mut(f)
		err := ValidateEncapFixture(f, "vxlan")
		if err == nil {
			t.Errorf("%s: want error", c.name)
		}
	}
	// UDP 载体（vxlan/geneve：8B UDP + 8B 隧道基础头）下的真实上界是
	// 0xffff-50-l3Len；42 开销会放进会回绕的 payload（回归：先 42 后 50）。
	{
		fix := valid()
		fix.Payload = make([]byte, 0xffff-42-20) // 旧 42 开销下合法、真实越界
		if err := ValidateEncapFixture(fix, "vxlan"); err == nil {
			t.Errorf("payload %d: want error (IPv4 total length wrap under UDP carrier)", len(fix.Payload))
		}
	}
	// 合法边界不拒：VID 0/4095、PCP 7、广播/组播 MAC、空 payload。
	legal := []*EncapEthernetFixture{
		valid(),
		{SrcMAC: "ff:ff:ff:ff:ff:ff", DstMAC: "01:00:5e:00:00:01", EtherType: "ipv4", SrcIP: "172.16.1.1", DstIP: "172.16.1.2"},
		{SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01", EtherType: "vlan_ipv4", VLANID: 4095, VLANPriority: 7, SrcIP: "172.16.1.1", DstIP: "172.16.1.2"},
		{SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01", EtherType: "vlan_ipv4", VLANID: 0, SrcIP: "172.16.1.1", DstIP: "172.16.1.2"},
	}
	for i, f := range legal {
		if err := ValidateEncapFixture(f, "vxlan"); err != nil {
			t.Errorf("legal %d: unexpected error %v", i, err)
		}
	}
	if err := ValidateEncapFixture(nil, "vxlan"); err != nil {
		t.Errorf("nil fixture must pass (empty-config default)")
	}
}
