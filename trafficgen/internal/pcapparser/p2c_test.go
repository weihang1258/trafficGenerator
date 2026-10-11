package pcapparser

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// T-PARSE-5 P2c 货架协议解析器绿测试（D-PARSE-1 §P3 P2c 表）。夹具按规范
// 布局手拼，断言核心字段。

func TestP2C_BGP(t *testing.T) {
	f := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0, 29, 1, // len 29 + OPEN
		4, 0xFD, 0xE8, // version 4, AS 65000
		0, 30, // hold 30
		10, 0, 0, 1,
		0, 4} // capabilities len（补到 OPEN 最小帧长 29）
	var p bgpParser
	if !p.CanParse(179, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["version"] != byte(4) || m["my_as"] != uint16(65000) || m["hold_time"] != uint16(30) {
		t.Errorf("bgp = %v", m)
	}
	if res.Detail.Messages[0].Fields["message_types"].([]string)[0] != "open" {
		t.Errorf("types = %v", m["message_types"])
	}
}

func TestP2C_Modbus(t *testing.T) {
	f := []byte{0x12, 0x34, 0, 0, 0, 6, 5, 3, 0, 0, 0, 2}
	var p modbusParser
	if !p.CanParse(502, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["transaction_id"] != uint16(0x1234) || m["unit_id"] != byte(5) || m["function_code"] != byte(3) {
		t.Errorf("modbus = %v", m)
	}
}

func TestP2C_Redis(t *testing.T) {
	var p redisParser
	res, _ := p.Parse([]byte("*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"))
	m := res.Detail.Messages[0].Fields
	if cmds, ok := m["commands"].([]string); !ok || len(cmds) == 0 || cmds[0] != "SET" {
		t.Errorf("redis commands = %v", m["commands"])
	}
}

func TestP2C_MySQL(t *testing.T) {
	f := []byte{0x2A, 0, 0, 0, 10}
	f = append(f, []byte("8.0.32\x00")...)
	var p mysqlParser
	if !p.CanParse(3306, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["server_version"] != "8.0.32" {
		t.Errorf("mysql version = %v", m["server_version"])
	}
}

func TestP2C_PostgreSQL(t *testing.T) {
	f := []byte{0, 0, 0, 30, 0, 3, 0, 0} // startup
	f = append(f, []byte("user\x00bob\x00database\x00db1\x00\x00")...)
	var p postgresqlParser
	if !p.CanParse(5432, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["user"] != "bob" || m["database"] != "db1" {
		t.Errorf("pg startup = %v", m)
	}
	// 消息面
	q := append([]byte{'Q', 0, 0, 0, 11}, []byte("SELECT 1\x00")...)
	res2, _ := p.Parse(q)
	if res2.Detail.Messages[0].Fields["message_type"] != "query" {
		t.Errorf("pg message = %v", res2.Detail.Messages[0].Fields)
	}
}

func TestP2C_IEC104(t *testing.T) {
	f := []byte{0x68, 0x04, 0x07, 0x00, 0x00, 0x00} // STARTDT_ACT U-format
	var p iec104Parser
	if !p.CanParse(2404, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["format"] != "U" || m["u_function"] != "startdt_act" {
		t.Errorf("iec104 = %v", m)
	}
}

func TestP2C_DNP3(t *testing.T) {
	f := []byte{0x05, 0x64, 0x05, 0xC9, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00}
	var p dnp3Parser
	if !p.CanParse(20000, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["dst_addr"] != uint16(1) || m["src_addr"] != uint16(2) {
		t.Errorf("dnp3 = %v", m)
	}
}

func TestP2C_SMB(t *testing.T) {
	f := []byte{0, 0, 0, 100, 0xFE, 'S', 'M', 'B', 0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0}
	var p smbParser
	if !p.CanParse(445, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["dialect"] != "smb2" || m["command_name"] != "negotiate" {
		t.Errorf("smb = %v", m)
	}
	// smb1 面：command @8（NetBIOS4+FFSMB4 之后，复审发现 5）
	smb1 := []byte{0, 0, 0, 50, 0xFF, 'S', 'M', 'B', 0x72}
	if smb1cmd := func() byte {
		r, _ := p.Parse(smb1)
		return r.Detail.Messages[0].Fields["command"].(byte)
	}(); smb1cmd != 0x72 {
		t.Errorf("smb1 command = %#v, want 0x72", smb1cmd)
	}
}

func TestP2C_NFS(t *testing.T) {
	f := make([]byte, 36)
	binary.BigEndian.PutUint32(f[0:4], 0x80000020) // record mark
	binary.BigEndian.PutUint32(f[4:8], 0xAA)   // xid
	binary.BigEndian.PutUint32(f[8:12], 0)      // call
	binary.BigEndian.PutUint32(f[12:16], 2)     // rpc ver
	binary.BigEndian.PutUint32(f[16:20], 100003) // nfs program
	binary.BigEndian.PutUint32(f[20:24], 3)    // nfs v3
	binary.BigEndian.PutUint32(f[24:28], 6)    // proc read
	var p nfsParser
	if !p.CanParse(2049, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["xid"] != uint32(0xAA) || m["nfs_version"] != uint32(3) || m["proc"] != uint32(6) {
		t.Errorf("nfs = %v", m)
	}
}

func TestP2C_HL7(t *testing.T) {
	f := []byte{0x0B}
	f = append(f, []byte("MSH|^~\\&|APP|FAC|REC|RFAC|20261010||ADT^A01|MSG1|P|1")...)
	f = append(f, 0x1C, 0x0D)
	var p hl7Parser
	if !p.CanParse(2575, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["sending_app"] != "APP" || m["message_type"] != "ADT^A01" {
		t.Errorf("hl7 = %v", m)
	}
}

func TestP2C_OPCUA(t *testing.T) {
	f := []byte("HEL")
	f = append(f, 'F', 0, 0, 0, 0)
	var p opcuaParser
	if !p.CanParse(4840, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	if res.Detail.Messages[0].Fields["message_type"] != "HEL" {
		t.Errorf("opcua = %v", res.Detail.Messages[0].Fields)
	}
}

func TestP2C_AMQP(t *testing.T) {
	f := []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}
	f = append(f, 1, 0, 0, 0, 0, 0, 0x0C) // method frame ch0 size12
	var p amqpParser
	if !p.CanParse(5672, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["protocol_minor"] != byte(1) || m["frame_type"] != "method" {
		t.Errorf("amqp = %v", m)
	}
}

func TestP2C_CQL(t *testing.T) {
	f := []byte{0x04, 0, 0, 0, 0x05, 0, 0, 0, 0} // v4 flags stream=0 opcode=OPTIONS
	f = append(f, []byte{0x01}...)
	f = append(f, []byte("cqlv4\x00")...)
	var p cqlParser
	if !p.CanParse(9042, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["version"] != byte(4) || m["opcode_name"] != "options" || res.Detail.Messages[0].Kind != "request" {
		t.Errorf("cql = %v", m)
	}
}

func TestP2C_TDS(t *testing.T) {
	f := []byte{0x12, 1, 0, 40, 0, 0, 1, 0}
	var p tdsParser
	if !p.CanParse(1433, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["packet_type"] != "prelogin" || m["spid"] != uint16(0) {
		t.Errorf("tds = %v", m)
	}
}

func TestP2C_Thrift(t *testing.T) {
	f := []byte{0, 0, 0, 5, 0x80, 0x01, 0, 1, 0} // framed len5 + version 0x8001 + call
	var p thriftParser
	if !p.CanParse(9090, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["framed"] != true || m["message_type"] != 1 || m["version"] != 1 {
		t.Errorf("thrift = %v", m)
	}
}

func TestP2C_MongoDB(t *testing.T) {
	f := make([]byte, 16)
	binary.LittleEndian.PutUint32(f[0:4], 32)
	binary.LittleEndian.PutUint32(f[4:8], 7)     // request id
	binary.LittleEndian.PutUint32(f[12:16], 2013) // OP_MSG 小端
	var p mongodbParser
	if !p.CanParse(27017, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["request_id"] != uint32(7) || res.Detail.Messages[0].Kind != "request" {
		t.Errorf("mongodb = %v", m)
	}
}

func TestP2C_PCEP(t *testing.T) {
	f := []byte{0x01, 0x00, 0x00, 0x04} // ver0 type=open len4
	var p pcepParser
	if !p.CanParse(8181, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["message_name"] != "open" || res.Detail.Messages[0].Kind != "request" {
		t.Errorf("pcep = %v", m)
	}
}

func TestP2C_NTLM(t *testing.T) {
	f := append([]byte("NTLMSSP\x00"), 1, 0, 0, 0)
	var p ntlmParser
	if !p.CanParse(445, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	if res.Detail.Messages[0].Fields["message_type"] != "negotiate" {
		t.Errorf("ntlm = %v", res.Detail.Messages[0].Fields)
	}
}

func TestP2C_SPNEGO(t *testing.T) {
	f := []byte{0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02}
	var p spnegoParser
	if !p.CanParse(445, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	if res.Detail.Messages[0].Fields["neg_token_init"] != true {
		t.Errorf("spnego = %v", res.Detail.Messages[0].Fields)
	}
}

func TestP2C_NMEA(t *testing.T) {
	var p nmeaParser
	sentence := "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,47.0,M,,"
	xor := byte(0)
	for i := 1; i < len(sentence); i++ {
		xor ^= sentence[i]
	}
	res, _ := p.Parse([]byte(sentence + "*" + strings.ToUpper(strings.TrimPrefix(fmt.Sprintf("%02x", xor), "0x")) + "\r\n"))
	sents := res.Detail.Messages[0].Fields["sentences"].([]map[string]any)
	if len(sents) != 1 || sents[0]["sentence_type"] != "GPGGA" || sents[0]["checksum_ok"] != true {
		t.Errorf("nmea = %v", sents)
	}
}

func TestP2C_GBT32960(t *testing.T) {
	f := []byte{0x23, 0x23, 0x01, 0x00} // vehicle login 下发
	f = append(f, []byte("LSVNA12345A678901")...) // VIN 17 @4:21
	f = append(f, 0x01)                            // enc @21
	f = append(f, 0, 5, 0, 0x42)
	var p gbt32960Parser
	if !p.CanParse(10020, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["command_name"] != "vehicle_login" || res.Detail.Messages[0].Kind != "request" {
		t.Errorf("gbt32960 = %v", m)
	}
	if m["vin"] != "LSVNA12345A678901" {
		t.Errorf("vin = %v", m["vin"])
	}
}

func TestP2C_JT808(t *testing.T) {
	f := []byte{0x7E, 0x01, 0x00, 0x00, 0x05, 0x01, 0x79, 0x12, 0x34, 0x56, 0x78, 0x90, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x7B}
	var p jt808Parser
	if !p.CanParse(7611, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["message_id"] != uint16(0x0100) || m["phone"] != "017912345678" + "90"[:0] || res.Detail.Messages[0].Kind != "request" {
		t.Errorf("jt808 = %v", m)
	}
}

func TestP2C_JT809(t *testing.T) {
	// 引擎线格式（buildFrame）：5B + MsgLength4 + SN4 + MsgID2 + Center4 + ver3 + CRC2 + 5D
	f := make([]byte, 30)
	f[0] = 0x5B
	binary.BigEndian.PutUint32(f[1:5], 30) // 整帧总长
	binary.BigEndian.PutUint32(f[5:9], 99) // sn
	binary.BigEndian.PutUint16(f[9:11], 0x1205)
	f[29] = 0x5D
	var p jt809Parser
	if !p.CanParse(8812, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["msg_id"] != uint16(0x1205) || m["msg_sn"] != uint32(99) {
		t.Errorf("jt809 = %v", m)
	}
}

func TestP2C_JTT905(t *testing.T) {
	f := make([]byte, 16)
	f[0] = 0x7E
	var p jtt905Parser
	if !p.CanParse(10700, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	if res.Detail.Messages[0].Fields["payload_len"] != 16 {
		t.Errorf("jtt905 = %v", res.Detail.Messages[0].Fields)
	}
}

func TestP2C_Moxa(t *testing.T) {
	f := []byte{1, 2, 3, 4, 0x90, 0, 0, 0}
	var p moxaParser
	if !p.CanParse(4800, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	if res.Detail.Messages[0].Fields["magic"] != "01020304" {
		t.Errorf("moxa = %v", res.Detail.Messages[0].Fields)
	}
}

func TestP2C_Dameng(t *testing.T) {
	f := make([]byte, 12)
	binary.BigEndian.PutUint32(f[0:4], 12)
	var p damengParser
	if !p.CanParse(5236, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	if res.Detail.Messages[0].Fields["length"] != uint32(12) {
		t.Errorf("dameng = %v", res.Detail.Messages[0].Fields)
	}
}

func TestP2C_TNS(t *testing.T) {
	f := []byte{0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00} // connect
	var p tnsParser
	if !p.CanParse(1521, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	if res.Detail.Messages[0].Fields["packet_type"] != "connect" {
		t.Errorf("tns = %v", res.Detail.Messages[0].Fields)
	}
}

func TestP2C_DRDA(t *testing.T) {
	f := []byte{0x00, 0x0A, 0xD0, 0x00, 0x00, 0x31, 0x00, 0x00, 0x10, 0x61} // ACCSEC correl=0x0031 codepoint=0x1061
	var p drdaParser
	if !p.CanParse(446, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["codepoint"] != "accsec" || m["correlation_id"] != uint16(0x0031) {
		t.Errorf("drda = %v", m)
	}
}

func TestP2C_ENIP(t *testing.T) {
	f := make([]byte, 24)
	binary.BigEndian.PutUint16(f[0:2], 4) // register session
	binary.BigEndian.PutUint16(f[2:4], 20)
	var p enipParser
	if !p.CanParse(44818, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["command_name"] != "register_session" {
		t.Errorf("enip = %v", m)
	}
}

func TestP2C_S7(t *testing.T) {
	f := []byte{3, 0, 0, 0x1A, // TPKT len26
		3, 0xF0, 0x80, // COTP DT（LI=3：LI+type+EOT）
		0x32, 1, 0, 0, // S7: protocol id + rosctr 1 request + pdu ref
		0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0xF0, 0, 0, 1, 0, 1, 0x12}
	var p s7Parser
	if !p.CanParse(102, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["rosctr_name"] != "request" {
		t.Errorf("s7 = %v", m)
	}
	// mms 不与 s7 抢（同端口区分面）
	var m2 mmsParser
	if m2.CanParse(102, f) {
		t.Errorf("mms 误抢 s7 载荷")
	}
}

func TestP2C_AMS(t *testing.T) {
	// 引擎 wire profile：Length(4,=总长-4) | Version1 | Type | Flags2 |
	// SessionID4 | CorrelationID8 | Payload | AE 5A
	f := make([]byte, 30)
	binary.BigEndian.PutUint32(f[0:4], 26)
	f[4] = 1
	f[5] = 2 // type
	binary.BigEndian.PutUint32(f[8:12], 0x55)
	f[28], f[29] = 0xAE, 0x5A
	var p amsParser
	if !p.CanParse(61616, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["type"] != byte(2) || m["session_id"] != uint32(0x55) {
		t.Errorf("ams = %v", m)
	}
	// openwire 首字节 0x01 与 ams 长度高位 0x00 天然区分（复审确认面）：
	// ams 门禁对 openwire 形状（首字节 1）恒否——长度高位非 0 不满足 ==len-4
	var p2 openwireParser
	owf := make([]byte, 20)
	owf[0] = 1
	if !p2.CanParse(61616, owf) {
		t.Errorf("openwire 反而不识别（回归面）")
	}
	if p.CanParse(61616, owf) {
		t.Errorf("ams 误吞 openwire 形状")
	}
}

func TestP2C_OpenWire(t *testing.T) {
	f := []byte{1, 0, 0, 0, 0, 5, 0, 0, 0, 0}
	var p openwireParser
	if !p.CanParse(61616, f) {
		t.Fatal("CanParse false")
	}
	res, _ := p.Parse(f)
	m := res.Detail.Messages[0].Fields
	if m["wire_format_info_type"] != byte(1) || m["marshal_version"] != byte(5) {
		t.Errorf("openwire = %v", m)
	}
}

// P2c 注册面：端口全量命中 + unknown 兜底契约（弱签名不越权）
func TestP2C_RegistryHits(t *testing.T) {
	reg := NewRegistry()
	cases := []struct {
		port uint16
		samp []byte
		want string
	}{
		{179, bgpFixture(), "bgp"},
		{502, []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1}, "modbus"},
		{6379, []byte("+PONG\r\n"), "redis"},
		{3306, []byte{0x2A, 0, 0, 0, 10, 0x39, 0}, "mysql"},
		{5432, []byte{0, 0, 0, 8, 0, 3, 0, 0}, "postgresql"},
		{2404, []byte{0x68, 4, 7, 0, 0, 0}, "iec104"},
		{20000, []byte{5, 0x64, 5, 0, 0, 0, 0, 0, 0, 0}, "dnp3"},
		{445, []byte{0, 0, 0, 100, 0xFE, 'S', 'M', 'B'}, "smb"},
		{2049, nfsFixture(), "nfs"},
		{2575, []byte{0x0B, 'M', 'S', 'H', 0x7C, 0x1C, 0x0D, 0x00}, "hl7"},
		{4840, []byte("OPNF\x00\x00\x00\x00"), "opcua"},
		{5672, []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}, "amqp"},
		{9042, []byte{0x04, 0, 0, 0, 0, 0, 0, 0x05, 0}, "cql"},
		{1433, []byte{0x12, 1, 0, 40, 0, 0, 1, 0}, "tds"},
		{9090, []byte{0, 0, 0, 5, 0x80, 1, 0, 1, 0}, "thrift"},
		{27017, mongoFixture(), "mongodb"},
		{8181, []byte{0, 1, 0, 4}, "pcep"},
		{10020, []byte{0x23, 0x23, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "gbt32960"},
		{7611, []byte{0x7E, 1, 0, 0, 5, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x7E}, "jt808"},
		{8812, jt809Fixture(), "jt809"},
		{10700, make([]byte, 16), "jtt905"},
		{4800, make([]byte, 8), "moxa"},
		{5236, make([]byte, 12), "dameng"},
		{1521, []byte{0, 16, 0, 0, 1, 0, 0, 0}, "tns"},
		{446, []byte{0, 10, 0xD0, 0, 0, 1}, "drda"},
		{44818, enipFixture(), "enip"},
		{102, s7Fixture(), "s7"},
		{61616, amsFixture(), "ams"},
		{61616, []byte{1, 0, 0, 0, 0, 5, 0, 0, 0, 0}, "openwire"},
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
	// unknown 兜底契约：非协议端口的二进制流必须落 unknown 而非误标
	if p := reg.Find(17767, []byte{5, 3, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9}); p != nil {
		t.Errorf("unknown 端口被 %s 误吞（兜底契约破坏）", p.Name())
	}
}

func bgpFixture() []byte {
	f := make([]byte, 19)
	for i := 0; i < 16; i++ {
		f[i] = 0xFF
	}
	f[16], f[17] = 0, 19 // marker 后 length=19（keepalive 最小帧长）
	f[18] = 4
	return f
}

func nfsFixture() []byte {
	f := make([]byte, 36)
	binary.BigEndian.PutUint32(f[0:4], 0x80000020)
	binary.BigEndian.PutUint32(f[16:20], 100003)
	return f
}

func mongoFixture() []byte {
	f := make([]byte, 16)
	binary.LittleEndian.PutUint32(f[12:16], 2013)
	return f
}

func jt809Fixture() []byte {
	f := make([]byte, 30)
	f[0] = 0x5B
	f[29] = 0x5D
	return f
}

func enipFixture() []byte {
	f := make([]byte, 24)
	binary.BigEndian.PutUint16(f[0:2], 4)
	return f
}

func s7Fixture() []byte {
	f := []byte{3, 0, 0, 0x1A, 3, 0xF0, 0x80, 0x32}
	return append(f, make([]byte, 18)...)
}

func amsFixture() []byte {
	f := make([]byte, 30)
	binary.BigEndian.PutUint32(f[0:4], 26)
	f[4] = 1
	f[28], f[29] = 0xAE, 0x5A
	return f
}

var _ = strings.HasPrefix
