package pcapparser

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// T-PARSE-4 P2b TCP 解析器绿测试（D-PARSE-1 §P3 P2b 表）+ 跨流关联回归。

func buildTCPSeg(t *testing.T, sport, dport layers.TCPPort, seq uint32, payload []byte) [][]byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: sport, DstPort: dport, PSH: true, ACK: true, Seq: seq, Window: 65535}
	tcp.SetNetworkLayerForChecksum(ipv4)
	if err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
		ipv4, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return [][]byte{buf.Bytes()}
}

func TestP2B_SMTP(t *testing.T) {
	var smtp smtpParser
	res, _ := smtp.Parse([]byte("220 mail.test ESMTP\r\nEHLO cli.test\r\n250-OK\r\nMAIL FROM:<a@t>\r\nRCPT TO:<b@t>\r\n"))
	m := res.Detail.Messages[0].Fields
	if m["banner"] != "220 mail.test ESMTP" || m["user_name"] == "x" {
		_ = m
	}
	if m["banner"] != "220 mail.test ESMTP" {
		t.Errorf("banner = %v", m["banner"])
	}
	if cmds, ok := m["commands"].([]string); !ok || len(cmds) != 3 || cmds[0] != "EHLO" {
		t.Errorf("commands = %v", m["commands"])
	}
	if res.Metadata["helo"] != "cli.test" {
		t.Errorf("helo = %v", res.Metadata["helo"])
	}
}

func TestP2B_POP3(t *testing.T) {
	var p pop3Parser
	res, _ := p.Parse([]byte("+OK ready\r\nuser bob\r\nPASS x\r\nSTAT\r\n"))
	m := res.Detail.Messages[0].Fields
	if m["banner"] != "+OK ready" {
		t.Errorf("banner = %v", m["banner"])
	}
	if cmds, ok := m["commands"].([]string); !ok || len(cmds) != 3 {
		t.Errorf("commands = %v", m["commands"])
	}
}

func TestP2B_IMAP(t *testing.T) {
	var p imapParser
	res, _ := p.Parse([]byte("* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\na1 LOGIN u p\r\n"))
	m := res.Detail.Messages[0].Fields
	if m["tags"].([]string)[0] != "a1" {
		t.Errorf("tags = %v", m["tags"])
	}
	if m["commands"].([]string)[0] != "LOGIN" {
		t.Errorf("commands = %v", m["commands"])
	}
	if m["capability_line"] == nil {
		t.Errorf("capability_line 缺")
	}
}

func TestP2B_RTSP(t *testing.T) {
	var p rtspParser
	res, _ := p.Parse([]byte("OPTIONS rtsp://x/ RTSP/1.0\r\nCSeq: 1\r\n\r\nRTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: abc123\r\nTransport: RTP/AVP;server_port=5004-5005\r\n\r\n"))
	m := res.Detail.Messages[0].Fields
	if m["methods"].([]string)[0] != "OPTIONS" {
		t.Errorf("methods = %v", m["methods"])
	}
	if res.Metadata["last_status"] != 200 {
		t.Errorf("last_status = %v", res.Metadata["last_status"])
	}
	if m["sessions"].([]string)[0] != "abc123" {
		t.Errorf("sessions = %v", m["sessions"])
	}
	if res.Detail.Extra["sdp_media"] == nil && res.Detail.Extra["transports"] == nil {
		t.Errorf("transports 缺")
	}
}

func TestP2B_SIP(t *testing.T) {
	var p sipParser
	res, _ := p.Parse([]byte("INVITE sip:b@t SIP/2.0\r\nCall-ID: abc@def\r\n\r\nv=0\r\nc=IN IP4 10.0.0.9\r\nm=audio 5004 RTP/AVP 0\r\n"))
	m := res.Detail.Messages[0].Fields
	if m["methods"].([]string)[0] != "INVITE" || m["call_ids"].([]string)[0] != "abc@def" {
		t.Errorf("sip = %v", m)
	}
	if res.Detail.Extra["sdp_connection"] == nil {
		t.Errorf("sdp_connection 缺")
	}
}

func TestP2B_SSH(t *testing.T) {
	var p sshParser
	banner := []byte("SSH-2.0-OpenSSH_9.0\r\n")
	f := append(banner, []byte{0, 0, 0, 20, 20}...) // KEXINIT：len=20 + type=20
	f = append(f, make([]byte, 16)...)                 // cookie
	f = append(f, 0, 0, 0, 3, 'd', 'i', 'f')           // kex list
	f = append(f, 0, 0, 0, 3, 'r', 's', 'a')
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["banner"] != "SSH-2.0-OpenSSH_9.0" {
		t.Errorf("banner = %v", m["banner"])
	}
	if m["kex_algorithms"].([]string)[0] != "dif" {
		t.Errorf("kex = %v", m["kex_algorithms"])
	}
}

func TestP2B_LDAP(t *testing.T) {
	// bind_request: SEQ{int 1, [APPLICATION 0]{int 3, name "", auth simple ""}}
	body := []byte{0x02, 0x01, 0x01, // messageID 1
		0x60, 0x07, // bind_request app0 len7（version3+name2+auth2，长度含自身头外内容）
		0x02, 0x01, 0x03, // version 3
		0x04, 0x00, // name ""
		0x80, 0x00} // simple auth ""
	f := append([]byte{0x30, byte(len(body))}, body...)
	var p ldapParser
	if !p.CanParse(389, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["message_id"] != int64(1) || m["protocol_op"] != "bind_request" || m["ldap_version"] != int64(3) {
		t.Errorf("ldap = %v", m)
	}
}

func TestP2B_SOCKS5(t *testing.T) {
	var p socks5Parser
	res, _ := p.Parse([]byte{5, 1, 0, 5, 1, 0, 1, 10, 0, 0, 1, 0x1F, 0x90})
	m := res.Detail.Messages[0].Fields
	if m["cmd"] != "connect" || m["dst_addr"] != "10.0.0.1" || m["dst_port"] != uint16(8080) {
		t.Errorf("socks5 = %v", m)
	}
}

func TestP2B_DoIP(t *testing.T) {
	f := []byte{2, 0xFD, 0x80, 0x01, 0, 0, 0, 4, 0x0E, 0x80, 0x0E, 0x81}
	var p doipParser
	if !p.CanParse(13400, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["payload_type_name"] != "diagnostic" || m["source_address"] != uint16(0x0E80) {
		t.Errorf("doip = %v", m)
	}
}

func TestP2B_Stratum(t *testing.T) {
	var p stratumParser
	res, _ := p.Parse([]byte("{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n{\"id\":1,\"result\":true}\n"))
	if len(res.Detail.Messages) != 2 {
		t.Fatalf("messages = %d, want 2", len(res.Detail.Messages))
	}
	if res.Detail.Messages[0].Kind != "request" || res.Detail.Messages[1].Kind != "response" {
		t.Errorf("kinds = %v/%v", res.Detail.Messages[0].Kind, res.Detail.Messages[1].Kind)
	}
}

func TestP2B_gRPC(t *testing.T) {
	var p grpcParser
	f := make([]byte, 24+9)
	copy(f, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	f[24+3] = 4 // SETTINGS
	var g grpcParser
	_ = g
	if !p.CanParse(443, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if fc, ok := m["frame_counts"].(map[string]int); !ok || fc["settings"] != 1 {
		t.Errorf("frame_counts = %v", m["frame_counts"])
	}
}

func TestP2B_Telnet(t *testing.T) {
	var p telnetParser
	f := []byte{0xFF, 0xFD, 24, 'l', 'o', 'g', 'i', 'n', ':', ' '}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	cmds := m["iac_commands"].([]map[string]any)
	if len(cmds) != 1 || cmds[0]["option_name"] != "terminal-type" {
		t.Errorf("telnet = %v", m)
	}
}

func TestP2B_RTMP(t *testing.T) {
	f := make([]byte, 1+1536*2+12)
	f[0] = 3
	f[1+1536*2] = 0x00 // fmt=0 csid=2
	var p rtmpParser
	if !p.CanParse(1935, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["handshake_version"] != byte(3) {
		t.Errorf("rtmp = %v", m)
	}
}

func TestP2B_H323(t *testing.T) {
	f := []byte{3, 0, 0, 8, // TPKT len8
		8, 0, 0, 0x05} // Q.931 disc + CRV + setup
	var p h323Parser
	if !p.CanParse(1720, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["q931_messages"].([]string)[0] != "setup" {
		t.Errorf("h323 = %v", m)
	}
}

func TestP2B_PPTP(t *testing.T) {
	f := make([]byte, 16)
	binary.BigEndian.PutUint16(f[0:2], 16) // length
	binary.BigEndian.PutUint32(f[4:8], 0x1A2B3C4D)
	binary.BigEndian.PutUint16(f[8:10], 8) // outgoing-call-rep
	binary.BigEndian.PutUint16(f[12:14], 0x1234) // Call ID @12（RFC 2637 §3.2.7，复审发现 1）
	var p pptpParser
	if !p.CanParse(1723, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if cm, ok := m["control_messages"].([]map[string]any); !ok || cm[0]["control_name"] != "outgoing_call_rep" || cm[0]["call_id"] != uint16(0x1234) {
		t.Errorf("pptp = %v", m["control_messages"])
	}
}

func TestP2B_VNC(t *testing.T) {
	var p vncParser
	res, _ := p.Parse([]byte("RFB 003.008\n\x02\x00\x02"))
	m := res.Detail.Messages[0].Fields
	if m["protocol_version"] != "RFB 003.008" {
		t.Errorf("vnc = %v", m)
	}
}

func TestP2B_RDP(t *testing.T) {
	f := []byte{3, 0, 0, 0x0B, 11, 0xE0, 0, 0, 0, 0, 2} // TPKT + CR + 协商
	var p rdpParser
	if !p.CanParse(3389, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if ct, ok := m["cotp_types"].([]string); !ok || ct[0] != "connection-request" {
		t.Errorf("rdp = %v", m["cotp_types"])
	}
}

func TestP2B_Gnutella(t *testing.T) {
	f := []byte("GNUTELLA CONNECT/0.6\r\nUser-Agent: t\r\n\r\n")
	guid := make([]byte, 16)
	f = append(f, guid...)
	f = append(f, 0x80, 8, 0) // query
	f = append(f, 0, 0, 0, 4)
	f = append(f, 1, 2, 3, 4)
	var p gnutellaParser
	if !p.CanParse(6346, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["handshake_line"] != "GNUTELLA CONNECT/0.6" {
		t.Errorf("gnutella handshake = %v", m["handshake_line"])
	}
	if ds, ok := m["descriptors"].([]map[string]any); !ok || ds[0]["type"] != "query" {
		t.Errorf("descriptors = %v", m["descriptors"])
	}
}

// 跨流关联（D-PARSE-1 §跨流关联）：FTP PASV → 数据流 RelatedFlowID。
func TestP2B_FTPAssociation(t *testing.T) {
	// 控制流：FTP PASV 通告端口 200*256+100 = 51300
	ctlFrames := buildTCPSeg(t, 1234, 21, 1, []byte("227 Entering Passive Mode (10,0,0,2,200,100)\r\n"))
	// 数据流：客户端 → 10.0.0.2:51300
	dataFrames := buildTCPSeg(t, 5555, 51300, 1, []byte("DATA"))
	frames := append(ctlFrames, dataFrames...)
	path := writePcap(t, frames, []time.Time{time.UnixMicro(1), time.UnixMicro(2)})
	analysis, err := Parse(path, &Options{PcapAssetID: "a", UserID: "u"})
	if err != nil {
		t.Fatal(err)
	}
	var ctl, data *storage.FlowModel
	for i := range analysis.Flows {
		if analysis.Flows[i].L7Protocol == "ftp" {
			ctl = &analysis.Flows[i]
		} else if strings.Contains(analysis.Flows[i].FlowKey, "51300") || analysis.Flows[i].DstPort == 51300 || analysis.Flows[i].SrcPort == 51300 {
			data = &analysis.Flows[i]
		}
	}
	if ctl == nil {
		t.Fatalf("控制流未识别为 ftp: %+v", analysis.Flows)
	}
	if data == nil {
		t.Fatalf("数据流未找到")
	}
	if data.RelatedFlowID != ctl.ID || data.RelatedRole != "data" {
		t.Errorf("关联 = %q/%q, want ctl.ID/data", data.RelatedFlowID, data.RelatedRole)
	}
	if ctl.RelatedRole != "control" {
		t.Errorf("控制流角色 = %q, want control", ctl.RelatedRole)
	}
	_ = fmt.Sprintf("")
	fmt.Printf("[dbg] ftp l7=%q detail_len=%d\n", ctl.L7Protocol, len(ctl.L7Detail))
}

func TestP2B_Shadowsocks(t *testing.T) {
	var p shadowsocksParser
	res, _ := p.Parse([]byte{1, 10, 0, 0, 1, 0x1F, 0x90, 0xDE, 0xAD})
	m := res.Detail.Messages[0].Fields
	if m["atyp"] != byte(1) || m["dst_addr"] != "10.0.0.1" || m["dst_port"] != uint16(8080) {
		t.Errorf("shadowsocks = %v", m)
	}
}

func TestP2B_VMess(t *testing.T) {
	f := make([]byte, 20)
	f[16] = 1
	f[18] = 0x30
	var p vmessParser
	if !p.CanParse(10086, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["version"] != byte(1) || m["payload_len"] != 20 {
		t.Errorf("vmess = %v", m)
	}
	// 签名收紧负例（复审发现 4）：dataLen 高字节非 0 不识别
	bad := make([]byte, 20)
	bad[16] = 1
	bad[17] = 0xAA
	if p.CanParse(10086, bad) {
		t.Errorf("vmess 弱签名误吞 unknown 流")
	}
}

// P2b 注册面：TCP 解析器全量命中
// P2b 复审发现 2 回归：EDP 弱签名必须有端口门禁（护 unknown 兜底契约）
func TestP2B_EDPPortGate(t *testing.T) {
	var p edpParser
	f := []byte{5, 3, 0}
	if p.CanParse(9999, f) {
		t.Errorf("EDP 无端口门禁误吞 unknown 流")
	}
	if !p.CanParse(4472, f) {
		t.Errorf("EDP 引擎端口 4472 应识别")
	}
}

// P2b 复审发现 3 回归：RTSP 签名行首锚定（HTTP 体含 RTSP 字样不劫持）
func TestP2B_RTSPNoHijack(t *testing.T) {
	reg := NewRegistry()
	httpBody := []byte("GET /player HTTP/1.1\r\nX-Player: RTSP/1.0 tuning\r\nHost: x\r\n\r\n")
	if p := reg.Find(80, httpBody); p.Name() != "http" {
		t.Errorf("RTSP 劫持 HTTP: %s", p.Name())
	}
	// 正面：真 RTSP 请求行仍识别
	if p := reg.Find(8554, []byte("DESCRIBE rtsp://x RTSP/1.0\r\nCSeq: 1\r\n\r\n")); p == nil || p.Name() != "rtsp" {
		t.Errorf("rtsp 正面识别失败")
	}
}

func TestP2B_RegistryHits(t *testing.T) {
	reg := NewRegistry()
	cases := []struct {
		port uint16
		samp []byte
		want string
	}{
		{25, []byte("220 mail.test\r\n"), "smtp"},
		{110, []byte("+OK ready\r\n"), "pop3"},
		{143, []byte("* OK [CAPABILITY IMAP4rev1]\r\n"), "imap"},
		{554, []byte("OPTIONS rtsp://x RTSP/1.0\r\nCSeq: 1\r\n\r\n"), "rtsp"},
		{5060, []byte("INVITE sip:b@t SIP/2.0\r\nCall-ID: 1\r\n\r\n"), "sip"},
		{22, []byte("SSH-2.0-OpenSSH\r\n"), "ssh"},
		{23, []byte{0xFF, 0xFD, 24}, "telnet"},
		{389, []byte{0x30, 0x05, 0x02, 0x01, 0x01, 0x60, 0x00}, "ldap"},
		{3389, []byte{3, 0, 0, 4}, "rdp"},
		{5900, []byte("RFB 003.008\n"), "vnc"},
		{1935, []byte{3, 0, 0}, "rtmp"},
		{1720, []byte{3, 0, 0, 6, 8, 0, 0, 5}, "h323"},
		{1723, pptpFixture2(), "pptp"},
		{1080, []byte{5, 1, 0}, "socks5"},
		{8388, []byte{5, 1, 0}, "shadowsocks"},
		{10086, vmessFixture(), "vmess"},
		{6346, []byte("GNUTELLA CONNECT/0.6\r\n\r\n"), "gnutella"},
		{13400, []byte{2, 0xFD, 0x80, 0x01, 0, 0, 0, 0}, "doip"},
		{443, append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), make([]byte, 9)...), "grpc"},
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
	// 注册序：rtsp/sip/grpc 在 http 前且 http 不被端口外签名劫持
	if p := reg.Find(80, []byte("GET / HTTP/1.1\r\n\r\n")); p.Name() != "http" {
		t.Errorf("http 劫持检查: %s", p.Name())
	}
}

func pptpFixture2() []byte {
	f := make([]byte, 16)
	binary.BigEndian.PutUint32(f[4:8], 0x1A2B3C4D)
	return f
}

func vmessFixture() []byte {
	f := make([]byte, 20)
	f[16] = 1
	f[18] = 0x30 // dataLen（签名收紧后须 >=0x18）
	return f
}
