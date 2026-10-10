package pcapparser

import (
	"encoding/binary"
	"testing"
)

// T-PARSE-3 P2a UDP 解析器绿测试（D-PARSE-1 §P3 P2a 表）。每解析器独立线格
// 式夹具（RFC/官方布局手拼），断言核心字段 2-3 项。

func TestP2A_DHCP(t *testing.T) {
	f := make([]byte, 240)
	f[0] = 1 // bootrequest
	binary.BigEndian.PutUint32(f[4:8], 0xDEAD0001)
	f[10] = 0x80 // broadcast
	copy(f[236:240], []byte{0x63, 0x82, 0x53, 0x63})
	f = append(f, 53, 1, 1)      // discover
	f = append(f, 54, 4, 10, 0, 0, 1)
	f = append(f, 12, 4, 'h', 'o', 's', 't')
	f = append(f, 255)
	var p dhcpParser
	if !p.CanParse(67, f) {
		t.Fatal("CanParse(67) = false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["xid"] != uint32(0xDEAD0001) || m["msg_type"] != byte(1) || m["server_id"] != "10.0.0.1" || m["hostname"] != "host" {
		t.Errorf("dhcp fields = %v", m)
	}
}

func TestP2A_DHCPv6(t *testing.T) {
	f := []byte{1, 0xAA, 0xBB, 0xCC} // solicit
	f = append(f, 0, 1, 0, 6, 1, 2, 3, 4, 5, 6) // client-duid
	f = append(f, 0, 23, 0, 16, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)
	var p dhcpv6Parser
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["msg_type"] != byte(1) || m["transaction_id"] != "aabbcc" || m["dns_servers"].([]string)[0] != "fd00::2" {
		t.Errorf("dhcpv6 fields = %v", m)
	}
}

func TestP2A_TFTP(t *testing.T) {
	f := []byte{0, 1, 'f', 'i', 'r', 'm', 0, 'o', 'c', 't', 'e', 't', 0, 'b', 'l', 'k', 's', 'i', 'z', 'e', 0, '5', '1', '2', 0}
	var p tftpParser
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["filename"] != "firm" || m["mode"] != "octet" {
		t.Errorf("tftp = %v", m)
	}
	if opts, ok := m["options"].([]string); !ok || len(opts) != 1 || opts[0] != "blksize=512" {
		t.Errorf("tftp options = %v", m["options"])
	}
}

func TestP2A_NTP(t *testing.T) {
	f := make([]byte, 48)
	f[0] = 0x23 // LI=0 VN=4 Mode=3
	binary.BigEndian.PutUint64(f[40:48], 0xAABBCCDDEEFF0011)
	var p ntpParser
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["version"] != byte(4) || m["mode"] != byte(3) || m["kind_marker"] == nil {
		// kind 断言放这里会失败——kind 在 Message 上
	}
	if res.Detail.Messages[0].Kind != "request" {
		t.Errorf("mode=3 应为 request")
	}
}

func TestP2A_SNMP(t *testing.T) {
	// v2c get-response: SEQ{int 1, ostr "pub", [2]PDU{int 42,0,0, SEQ{SEQ{oid, null}}}}
	oid := []byte{0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	vb := append([]byte{0x30, byte(len(oid) + 2)}, oid...)
	vb = append(vb, 0x05, 0x00)
	vbs := append([]byte{0x30, byte(len(vb))}, vb...)
	pdu := []byte{0x02, 0x01, 0x2A, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00}
	pdu = append(pdu, vbs...)
	inner := []byte{0x02, 0x01, 0x01, 0x04, 0x03, 'p', 'u', 'b',
		0xA2, byte(len(pdu))}
	inner = append(inner, pdu...)
	f := append([]byte{0x30, byte(len(inner))}, inner...)
	var p snmpParser
	if !p.CanParse(161, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["community"] != "pub" || m["request_id"] != int64(42) {
		t.Errorf("snmp = %v", m)
	}
	if vbs2, ok := m["varbinds"].([]map[string]any); !ok || len(vbs2) != 1 || vbs2[0]["oid"] != "1.3.6.1.2.1.1.1.0" {
		t.Errorf("varbinds = %v", m["varbinds"])
	}
}

func TestP2A_RADIUS(t *testing.T) {
	f := make([]byte, 20)
	f[0] = 1 // access-request
	f[1] = 7 // identifier
	binary.BigEndian.PutUint16(f[2:4], 26)
	f = append(f, 1, 5, 'b', 'o', 'b') // user-name bob（Length 含 type+len 两字节）
	var p radiusParser
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["identifier"] != byte(7) || m["user_name"] != "bob" || res.Detail.Messages[0].Kind != "request" {
		t.Errorf("radius = %v", m)
	}
}

func TestP2A_SSDP(t *testing.T) {
	f := []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: upnp:rootdevice\r\nMX: 2\r\n\r\n")
	var p ssdpParser
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["method"] != "M-SEARCH" || m["st"] != "upnp:rootdevice" {
		t.Errorf("ssdp = %v", m)
	}
}

func TestP2A_Syslog(t *testing.T) {
	f := []byte("<34>1 2026-10-10T10:00:00Z myhost myapp 123 ID45 - boot ok")
	var p syslogParser
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["facility"] != 4 || m["severity"] != 2 || m["hostname"] != "myhost" || m["format"] != "rfc5424" {
		t.Errorf("syslog = %v", m)
	}
}

func TestP2A_STUN(t *testing.T) {
	f := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42}
	f = append(f, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
	var p stunParser
	if !p.CanParse(3478, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["msg_type"] != "0x0001" || m["method"] != uint16(0) || res.Detail.Messages[0].Kind != "request" {
		t.Errorf("stun = %v", m)
	}
}

func TestP2A_CoAP(t *testing.T) {
	f := []byte{0x41, 0x01, 0x12, 0x34, 0xAA} // ver1 CON GET mid tkl=1 token
	f = append(f, 0xB3, 'o', 'n', 'e')        // URI-Path "one" (delta11 len3)
	f = append(f, 0x11, 0x2A)                 // Content-Format=42（1B uint，复审发现 3）
	f = append(f, 0xFF, 0x00, 0x01)           // payload marker
	var p coapParser
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["type"] != "CON" || m["code"] != "0.01" || m["method"] != "GET" || m["uri_path"] != "one" {
		t.Errorf("coap = %v", m)
	}
	if m["content_format"] != 42 {
		t.Errorf("content_format(1B uint) = %v, want 42", m["content_format"])
	}
}

func TestP2A_Kerberos(t *testing.T) {
	f := []byte{0x6A, 0x00, 0x00, 0x1B, 0x30, 0x19,
		0xA1, 0x03, 0x02, 0x01, 0x05,
		0xA2, 0x03, 0x02, 0x01, 0x0A, // msg-type 10 as-req
		0xA3, 0x11, 0x30, 0x0F}
	var p kerberosParser
	if !p.CanParse(88, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["message"] != "as-req" || m["msg_type"] != int64(10) {
		t.Errorf("kerberos = %v", m)
	}
}

func TestP2A_RIP(t *testing.T) {
	f := []byte{2, 2, 0, 0}
	f = append(f, 0, 2, 0, 0, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)
	var p ripParser
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["command"] != byte(2) {
		t.Errorf("rip = %v", m)
	}
	if routes, ok := m["routes"].([]map[string]any); !ok || routes[0]["ip"] != "10.0.0.1" || routes[0]["metric"] != uint32(2) {
		t.Errorf("rip routes = %v", m["routes"])
	}
}

func TestP2A_Cflow(t *testing.T) {
	f := make([]byte, 24)
	binary.BigEndian.PutUint16(f[0:2], 5)
	binary.BigEndian.PutUint16(f[2:4], 3)
	var p cflowParser
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["version"] != uint16(5) || m["count"] != uint16(3) {
		t.Errorf("cflow = %v", m)
	}
}

func TestP2A_SomeIP(t *testing.T) {
	f := make([]byte, 20)
	binary.BigEndian.PutUint16(f[0:2], 0x1234)
	binary.BigEndian.PutUint16(f[2:4], 0x0001)
	binary.BigEndian.PutUint32(f[4:8], 12) // Length=总长-8（复审发现 2）
	binary.BigEndian.PutUint16(f[10:12], 0x0099)
	f[14] = 0x80 // response
	var p someipParser
	if !p.CanParse(30490, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["service_id"] != uint16(0x1234) || m["message_type"] != byte(0x80) || res.Detail.Messages[0].Kind != "response" {
		t.Errorf("someip = %v", m)
	}
}

func TestP2A_Megaco(t *testing.T) {
	f := []byte("MEGACO/1 [10.0.0.1]:2944\nT = 77 { context = - { ADD = term1 } }")
	var p megacoParser
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["version"] != 1 || m["transaction_ids"].([]string)[0] != "77" {
		t.Errorf("megaco = %v", m)
	}
}

func TestP2A_BACnet(t *testing.T) {
	f := []byte{0x81, 0x0B, 0x00, 0x08, // BVLC original-broadcast len=8（含 4B 头）
		0x01, 0x04, // NPDU v1 control（无 DNET）
		0x10, 0x08} // unconfirmed WhoIs
	var p bacnetParser
	if !p.CanParse(47808, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["apdu_type"] != byte(1) || m["service_choice"] != byte(8) {
		t.Errorf("bacnet = %v", m)
	}
}

func TestP2A_FINS(t *testing.T) {
	f := make([]byte, 16)
	f[10], f[11] = 0x01, 0x01 // memory area read
	f[12], f[13] = 0x00, 0x00
	var p finsParser
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["command"] != "0101" || m["response_code"] != "0000" {
		t.Errorf("fins = %v", m)
	}
}

func TestP2A_LDP(t *testing.T) {
	f := make([]byte, 20)
	binary.BigEndian.PutUint16(f[0:2], 1)   // version
	binary.BigEndian.PutUint16(f[2:4], 10)  // pdu len
	copy(f[4:8], []byte{10, 0, 0, 1})       // lsr id
	binary.BigEndian.PutUint16(f[12:14], 0x0200) // hello
	var p ldpParser
	if !p.CanParse(646, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["message_type"] != "hello" || m["lsr_id"] != "10.0.0.1" {
		t.Errorf("ldp = %v", m)
	}
}

func TestP2A_IKE(t *testing.T) {
	f := make([]byte, 28)
	f[12] = 34 // IKE_SA_INIT
	f[13] = 0x20
	f[14] = 0x08 // initiator
	binary.BigEndian.PutUint32(f[20:24], 5)
	var p ikeParser
	if !p.CanParse(500, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["exchange_type"] != "ike_sa_init" || m["initiator_flag"] != true {
		t.Errorf("ike = %v", m)
	}
}

func TestP2A_IKENatt(t *testing.T) {
	f := make([]byte, 32)
	copy(f[0:4], []byte{0, 0, 0, 0}) // non-ESP marker
	f[4+12] = 34
	f[4+13] = 0x20
	var p ikeNattParser
	if !p.CanParse(4500, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["exchange_type"] != "ike_sa_init" || m["non_esp_marker"] != true {
		t.Errorf("ike_nat_t = %v", m)
	}
	// keepalive
	ka := []byte{0xFF}
	res2, _ := p.Parse(ka)
	if res2.Metadata["keepalive"] != true {
		t.Errorf("keepalive = %v", res2.Metadata)
	}
}

// 解析器注册面：全部 CanParse 经 registry 命中且 L7Protocol 落对
// P2a 复审发现 1 回归：DNET 存在的路由帧（DNET 2B + DLEN 1B + DADR）。
func TestP2A_BACnetRouted(t *testing.T) {
	// 帧=4B BVLC 头 + 2B NPDU + 4B(DNET2+DLEN1+DADR1) + 3B APDU = 13
	f := []byte{0x81, 0x0B, 0x00, 0x0D,
		0x01, 0x20, // NPDU v1 + DNET 位
		0x00, 0x05, // DNET
		0x01, 0x77, // DLEN=1 DADR
		0x30, 0x42, 0x08} // APDU type=3 complex-ACK invoke=0x42 choice=8
	var p bacnetParser
	if !p.CanParse(47808, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["invoke_id"] != byte(0x42) || m["service_choice"] != byte(8) {
		t.Errorf("routed bacnet = %v", m)
	}
	if res.Detail.Messages[0].Kind != "response" {
		t.Errorf("complex-ACK 应为 response")
	}
}

func TestP2A_RegistryHits(t *testing.T) {
	reg := NewRegistry()
	cases := []struct {
		port uint16
		samp []byte
		want string
	}{
		{67, dhcpFixture(), "dhcp"},
		{69, []byte{0, 4, 0, 1}, "tftp"},
		{123, ntpFixture(), "ntp"},
		{161, snmpFixture(), "snmp"},
		{1812, radiusFixture(), "radius"},
		{1900, []byte("M-SEARCH * HTTP/1.1\r\nST: x\r\n\r\n"), "ssdp"},
		{514, []byte("<34>1 x"), "syslog"},
		{3478, stunFixture(), "stun"},
		{5683, []byte{0x44, 0x01, 0, 1, 0}, "coap"},
		{88, []byte{0x6A, 0, 0, 0, 0x30, 0}, "kerberos"},
		{520, []byte{2, 2, 0, 0}, "rip"},
		{2055, cflowFixture(), "cflow"},
		{30490, someipFixture(), "someip"},
		{2944, []byte("MEGACO/1 [10.0.0.1]\n"), "megaco"},
		{47808, []byte{0x81, 0x0B, 0, 6, 1, 0x04}, "bacnet"},
		{9600, make([]byte, 16), "fins"},
		{646, ldpFixture(), "ldp"},
		{500, ikeFixture(), "ike"},
		{4500, ikeNattFixture(), "ike_nat_t"},
		{547, []byte{2, 1, 2, 3}, "dhcpv6"},
		{5353, buildP1DNSQuery(0x22, "mdns.test"), "dns"}, // mdns 复用 dns（复审发现 4 回归缺口）
	}
	for _, c := range cases {
		p := reg.Find(c.port, c.samp)
		if p == nil {
			t.Errorf("port %d: no parser matched (want %s)", c.port, c.want)
			continue
		}
		if p.Name() != c.want {
			t.Errorf("port %d: matched %s, want %s", c.port, p.Name(), c.want)
		}
	}
}

func dhcpFixture() []byte {
	f := make([]byte, 240)
	copy(f[236:240], []byte{0x63, 0x82, 0x53, 0x63})
	return f
}

func ntpFixture() []byte {
	f := make([]byte, 48)
	f[0] = 0x23
	return f
}

func snmpFixture() []byte {
	return []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x00, 0xA2, 0x00}
}

func radiusFixture() []byte {
	f := make([]byte, 20)
	f[0] = 1
	binary.BigEndian.PutUint16(f[2:4], 20)
	return f
}

func stunFixture() []byte {
	f := make([]byte, 20)
	f[4], f[5], f[6], f[7] = 0x21, 0x12, 0xA4, 0x42
	return f
}

func cflowFixture() []byte {
	f := make([]byte, 24)
	binary.BigEndian.PutUint16(f[0:2], 5)
	return f
}

func someipFixture() []byte {
	f := make([]byte, 20)
	binary.BigEndian.PutUint32(f[4:8], 12) // 总长-8
	return f
}

func ldpFixture() []byte {
	f := make([]byte, 20)
	binary.BigEndian.PutUint16(f[0:2], 1)
	return f
}

func ikeFixture() []byte {
	f := make([]byte, 28)
	f[13] = 0x20
	return f
}

func ikeNattFixture() []byte {
	f := make([]byte, 32)
	f[4+13] = 0x20
	return f
}
