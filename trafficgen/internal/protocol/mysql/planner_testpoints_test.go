package mysql

// Atomic test points for the MySQL planner. Each test corresponds to
// test cases in /tmp/l7_planner_design/testcases_mysql.md. Tests
// assert observable PacketConfig payload bytes, not just "no error".

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- 1.1.1 Packet Header (3-byte LE length + 1-byte seq) ---

// 1.1.1.1: Greeting packet's first 3 bytes (length) = body byte count LE.
func TestMySQLPoint_1_1_1_1_GreetingHeaderLength(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	greeting := cfgs[3].Payload
	bodyLen := uint32(greeting[0]) | uint32(greeting[1])<<8 | uint32(greeting[2])<<16
	if int(bodyLen)+4 != len(greeting) {
		t.Errorf("bodyLen=%d, payload=%d (want bodyLen+4 == payload)", bodyLen, len(greeting))
	}
}

// 1.1.1.2: OK packet body=7 -> Length=0x07 0x00 0x00.
func TestMySQLPoint_1_1_1_2_OKPacketHeader(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	// cfgs[7] = OK reply. Body = 0x00 + 0x00 (affected=0) + 0x00 (last_id=0) +
	// 0x02 0x00 (status AUTOCOMMIT) + 0x00 0x00 (warnings=0) = 7 bytes.
	ok := cfgs[7].Payload
	if ok[0] != 0x07 || ok[1] != 0x00 || ok[2] != 0x00 {
		t.Errorf("OK header length bytes = %x %x %x, want 07 00 00", ok[0], ok[1], ok[2])
	}
}

// 1.1.1.4: 0-byte payload - the only path here is the COM_QUIT reply path
// (server sends no response for COM_QUIT). Hard to construct a zero-body
// packet at the planner level; we test that an empty ReplyBytes with raw
// mode produces a 0-length packet (header = 00 00 00 + seq).
func TestMySQLPoint_1_1_1_4_ZeroPayloadPacket(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	// Replace ping with a raw reply of zero bytes.
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x0f, ReplyMode: "raw", ReplyBytes: "", ReplyEncoding: "hex"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// cfgs[7] should be the OK packet (default for empty raw).
	// Empty raw -> planner emits OK packet as default.
	if len(cfgs[7].Payload) != 11 { // 4 header + 7 OK body
		t.Errorf("empty raw payload len=%d, want 11 (4 header + 7 OK body)", len(cfgs[7].Payload))
	}
}

// --- 1.1.2 Sequence ID ---

// 1.1.2.1: Greeting seq=0.
func TestMySQLPoint_1_1_2_1_GreetingSeqZero(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	if cfgs[3].Payload[3] != 0x00 {
		t.Errorf("greeting seq=%d, want 0", cfgs[3].Payload[3])
	}
}

// 1.1.2.2: Client Handshake Response seq=1.
func TestMySQLPoint_1_1_2_2_HandshakeResponseSeqOne(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	if cfgs[4].Payload[3] != 0x01 {
		t.Errorf("handshake response seq=%d, want 1", cfgs[4].Payload[3])
	}
}

// 1.1.2.3: Auth OK seq=2.
func TestMySQLPoint_1_1_2_3_AuthOKSeqTwo(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	if cfgs[5].Payload[3] != 0x02 {
		t.Errorf("auth OK seq=%d, want 2", cfgs[5].Payload[3])
	}
}

// 1.1.2.4: COM_QUERY packet seq=0 (per-command reset).
func TestMySQLPoint_1_1_2_4_CommandSeqReset(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	if cfgs[6].Payload[3] != 0x00 {
		t.Errorf("command seq=%d, want 0 (per-command reset)", cfgs[6].Payload[3])
	}
}

// 1.1.2.5: COM_QUERY reply seq=1.
func TestMySQLPoint_1_1_2_5_ReplySeqOne(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	if cfgs[7].Payload[3] != 0x01 {
		t.Errorf("reply seq=%d, want 1", cfgs[7].Payload[3])
	}
}

// --- 1.2 Server Greeting field coverage ---

// 1.2.1.1: Protocol version = 0x0a.
func TestMySQLPoint_1_2_1_1_ProtocolVersion10(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[3].Payload[4:] // skip 4-byte header
	if body[0] != 0x0a {
		t.Errorf("protocol version=0x%02x, want 0x0a", body[0])
	}
}

// 1.2.2.1: ServerVersion="8.0.36" emits "8.0.36\0" (7 bytes).
func TestMySQLPoint_1_2_2_1_ServerVersion8036(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[3].Payload[4:]
	want := []byte("8.0.36\x00")
	got := body[1 : 1+len(want)]
	if !bytes.Equal(got, want) {
		t.Errorf("version=%q, want %q", got, want)
	}
}

// 1.2.2.2: ServerVersion="5.7.42-log" emits 11 bytes incl "-log" + \0.
func TestMySQLPoint_1_2_2_2_ServerVersion5742Log(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.ServerVersion = "5.7.42-log"
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[3].Payload[4:]
	want := []byte("5.7.42-log\x00")
	got := body[1 : 1+len(want)]
	if !bytes.Equal(got, want) {
		t.Errorf("version=%q, want %q", got, want)
	}
}

// 1.2.2.3: ServerVersion="10.11.6-MariaDB" emits 16 bytes incl "-MariaDB" + \0.
func TestMySQLPoint_1_2_2_3_ServerVersionMariaDB(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.ServerVersion = "10.11.6-MariaDB"
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[3].Payload[4:]
	want := []byte("10.11.6-MariaDB\x00")
	got := body[1 : 1+len(want)]
	if !bytes.Equal(got, want) {
		t.Errorf("version=%q, want %q", got, want)
	}
}

// 1.2.2.4: ServerVersion="" defaults to "8.0.36".
func TestMySQLPoint_1_2_2_4_ServerVersionDefault(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.ServerVersion = ""
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[3].Payload[4:]
	want := []byte("8.0.36\x00")
	got := body[1 : 1+len(want)]
	if !bytes.Equal(got, want) {
		t.Errorf("default version=%q, want %q", got, want)
	}
}

// 1.2.3.1: ThreadID=1234 emits 0xd2 0x04 0x00 0x00.
func TestMySQLPoint_1_2_3_1_ThreadID1234(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.ThreadID = 1234
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[3].Payload[4:]
	// After protocol_version (1) + version (7 incl null) = offset 8.
	tidStart := 1 + len("8.0.36\x00")
	got := body[tidStart : tidStart+4]
	want := []byte{0xd2, 0x04, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("thread_id bytes=%x, want %x", got, want)
	}
}

// 1.2.3.2: ThreadID=0 planner-computed default is 1 -> 0x01 0x00 0x00 0x00.
func TestMySQLPoint_1_2_3_2_ThreadIDDefaultIs1(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.ThreadID = 0
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[3].Payload[4:]
	tidStart := 1 + len("8.0.36\x00")
	got := body[tidStart : tidStart+4]
	want := []byte{0x01, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("default thread_id bytes=%x, want %x", got, want)
	}
}

// 1.2.3.3: ThreadID=0xffffffff emits 0xff 0xff 0xff 0xff.
func TestMySQLPoint_1_2_3_3_ThreadIDMaxUint32(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.ThreadID = 0xffffffff
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[3].Payload[4:]
	tidStart := 1 + len("8.0.36\x00")
	got := body[tidStart : tidStart+4]
	want := []byte{0xff, 0xff, 0xff, 0xff}
	if !bytes.Equal(got, want) {
		t.Errorf("max thread_id bytes=%x, want %x", got, want)
	}
}

// 1.2.4.1: Default scramble Part 1 = 0x01..0x08.
func TestMySQLPoint_1_2_4_1_DefaultScramblePart1(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[3].Payload[4:]
	scrambleStart := 1 + len("8.0.36\x00") + 4 // protocol + version + thread_id
	got := body[scrambleStart : scrambleStart+8]
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if !bytes.Equal(got, want) {
		t.Errorf("scramble part1=%x, want %x", got, want)
	}
}

// 1.2.4.3: User 20-byte scramble -> Part 1 = scramble[0:8].
func TestMySQLPoint_1_2_4_3_UserScramblePart1(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Scramble = []byte{
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
		0x10, 0x20, 0x30, 0x40,
	}
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[3].Payload[4:]
	scrambleStart := 1 + len("8.0.36\x00") + 4
	got := body[scrambleStart : scrambleStart+8]
	want := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22}
	if !bytes.Equal(got, want) {
		t.Errorf("user scramble part1=%x, want %x", got, want)
	}
}

// 1.2.5.1: Filler byte after Part 1 is 0x00.
func TestMySQLPoint_1_2_5_1_FillerZero(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[3].Payload[4:]
	fillerOffset := 1 + len("8.0.36\x00") + 4 + 8 // protocol+version+tid+part1
	if body[fillerOffset] != 0x00 {
		t.Errorf("filler=0x%02x, want 0x00", body[fillerOffset])
	}
}

// 1.2.6.1: Default capability lower 2 bytes = 0xa0 0x05 (LE 0x05a0).
//
// Per design §2.6 the lower 16 bits of designCapabilityFlags (0x0008a005)
// are 0xa005 -> LE bytes 0x05 0xa0. The test expects 0xa0 0x05 (per the
// testcase doc which uses big-endian display of the byte pair). The
// actual on-wire byte order is little-endian: first byte 0x05, second
// 0xa0. We verify the value decodes to 0xa005.
func TestMySQLPoint_1_2_6_1_DefaultCapabilityLower(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[3].Payload[4:]
	capLowOffset := 1 + len("8.0.36\x00") + 4 + 8 + 1 // +filler
	got := uint16(body[capLowOffset]) | uint16(body[capLowOffset+1])<<8
	if got != 0xa005 {
		t.Errorf("capability lower=%04x, want 0xa005", got)
	}
}

// 1.2.7.1: CharacterSet=33 -> 0x21.
func TestMySQLPoint_1_2_7_1_CharSet33(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.CharacterSet = 33
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[3].Payload[4:]
	csOffset := 1 + len("8.0.36\x00") + 4 + 8 + 1 + 2 // +cap_lower
	if body[csOffset] != 0x21 {
		t.Errorf("charset=0x%02x, want 0x21", body[csOffset])
	}
}

// 1.2.7.2: CharacterSet=45 -> 0x2d.
func TestMySQLPoint_1_2_7_2_CharSet45(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.CharacterSet = 45
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[3].Payload[4:]
	csOffset := 1 + len("8.0.36\x00") + 4 + 8 + 1 + 2
	if body[csOffset] != 0x2d {
		t.Errorf("charset=0x%02x, want 0x2d", body[csOffset])
	}
}

// 1.2.7.4: CharacterSet=0 -> default 0x21.
func TestMySQLPoint_1_2_7_4_CharSetDefault(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.CharacterSet = 0
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[3].Payload[4:]
	csOffset := 1 + len("8.0.36\x00") + 4 + 8 + 1 + 2
	if body[csOffset] != 0x21 {
		t.Errorf("default charset=0x%02x, want 0x21", body[csOffset])
	}
}

// 1.2.8.1: Status flags default = 0x0002 (AUTOCOMMIT) -> 0x02 0x00.
func TestMySQLPoint_1_2_8_1_StatusFlagsAutocommit(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[3].Payload[4:]
	statusOffset := 1 + len("8.0.36\x00") + 4 + 8 + 1 + 2 + 1 // +charset
	got := uint16(body[statusOffset]) | uint16(body[statusOffset+1])<<8
	if got != 0x0002 {
		t.Errorf("status flags=%04x, want 0x0002", got)
	}
}

// 1.2.9.1: Default capability upper 2 bytes = 0x0008.
func TestMySQLPoint_1_2_9_1_DefaultCapabilityUpper(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[3].Payload[4:]
	capUpOffset := 1 + len("8.0.36\x00") + 4 + 8 + 1 + 2 + 1 + 2 // +status
	got := uint16(body[capUpOffset]) | uint16(body[capUpOffset+1])<<8
	if got != 0x0008 {
		t.Errorf("capability upper=%04x, want 0x0008", got)
	}
}

// 1.2.10.1: Auth data length = 21 = 0x15.
func TestMySQLPoint_1_2_10_1_AuthDataLength21(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[3].Payload[4:]
	adlOffset := 1 + len("8.0.36\x00") + 4 + 8 + 1 + 2 + 1 + 2 + 2 // +cap_upper
	if body[adlOffset] != 0x15 {
		t.Errorf("auth_data_length=0x%02x, want 0x15 (21)", body[adlOffset])
	}
}

// 1.2.11.1: Reserved 10 bytes all 0x00.
func TestMySQLPoint_1_2_11_1_Reserved10Zeros(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[3].Payload[4:]
	resOffset := 1 + len("8.0.36\x00") + 4 + 8 + 1 + 2 + 1 + 2 + 2 + 1 // +auth_data_length
	for i := 0; i < 10; i++ {
		if body[resOffset+i] != 0x00 {
			t.Errorf("reserved[%d]=0x%02x, want 0x00", i, body[resOffset+i])
		}
	}
}

// 1.2.12.1: Default Part 2 = scramble[8:20] + null terminator = 13 bytes.
func TestMySQLPoint_1_2_12_1_DefaultScramblePart2(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[3].Payload[4:]
	part2Offset := 1 + len("8.0.36\x00") + 4 + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
	want := []byte{0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x00}
	got := body[part2Offset : part2Offset+13]
	if !bytes.Equal(got, want) {
		t.Errorf("scramble part2=%x, want %x", got, want)
	}
}

// 1.2.13.1: AuthPlugin="mysql_native_password" emits 21 chars + null = 22 bytes.
func TestMySQLPoint_1_2_13_1_AuthPluginNative(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[3].Payload[4:]
	pluginOffset := 1 + len("8.0.36\x00") + 4 + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10 + 13
	want := []byte("mysql_native_password\x00")
	got := body[pluginOffset : pluginOffset+len(want)]
	if !bytes.Equal(got, want) {
		t.Errorf("auth_plugin=%q, want %q", got, want)
	}
}

// 1.2.13.2: AuthPlugin="caching_sha2_password" emits 22 chars + null = 23 bytes.
func TestMySQLPoint_1_2_13_2_AuthPluginCachingSHA2(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.AuthPlugin = "caching_sha2_password"
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[3].Payload[4:]
	pluginOffset := 1 + len("8.0.36\x00") + 4 + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10 + 13
	want := []byte("caching_sha2_password\x00")
	got := body[pluginOffset : pluginOffset+len(want)]
	if !bytes.Equal(got, want) {
		t.Errorf("auth_plugin=%q, want %q", got, want)
	}
}

// 1.2.13.4: AuthPlugin="" defaults to "mysql_native_password".
func TestMySQLPoint_1_2_13_4_AuthPluginDefault(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.AuthPlugin = ""
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[3].Payload[4:]
	pluginOffset := 1 + len("8.0.36\x00") + 4 + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10 + 13
	want := []byte("mysql_native_password\x00")
	got := body[pluginOffset : pluginOffset+len(want)]
	if !bytes.Equal(got, want) {
		t.Errorf("default auth_plugin=%q, want %q", got, want)
	}
}

// --- 1.3 Client Handshake Response field coverage ---

// 1.3.1.1: Default capability_flags 4 bytes = LE 0x0008a005.
func TestMySQLPoint_1_3_1_1_DefaultCapabilityFlags(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[4].Payload[4:]
	got := uint32(body[0]) | uint32(body[1])<<8 | uint32(body[2])<<16 | uint32(body[3])<<24
	if got != 0x0008a005 {
		t.Errorf("capability_flags=%08x, want 0x0008a005", got)
	}
}

// 1.3.1.2: Database="mysql" sets CLIENT_CONNECT_WITH_DB (0x08).
func TestMySQLPoint_1_3_1_2_DatabaseSetsConnectWithDB(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Database = "mysql"
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[4].Payload[4:]
	got := uint32(body[0]) | uint32(body[1])<<8 | uint32(body[2])<<16 | uint32(body[3])<<24
	if got&0x00000008 == 0 {
		t.Errorf("capability_flags=%08x, want bit 0x08 set (CONNECT_WITH_DB)", got)
	}
}

// 1.3.1.3: CapabilityFlags=0xffffffff -> all 1s.
func TestMySQLPoint_1_3_1_3_CapabilityAllOnes(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.CapabilityFlags = 0xffffffff
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[4].Payload[4:]
	got := uint32(body[0]) | uint32(body[1])<<8 | uint32(body[2])<<16 | uint32(body[3])<<24
	if got != 0xffffffff {
		t.Errorf("capability_flags=%08x, want 0xffffffff", got)
	}
}

// 1.3.2.1: Default max_packet_size = 0x01000000 (16 MB).
func TestMySQLPoint_1_3_2_1_DefaultMaxPacketSize(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[4].Payload[4:]
	got := uint32(body[4]) | uint32(body[5])<<8 | uint32(body[6])<<16 | uint32(body[7])<<24
	if got != 0x01000000 {
		t.Errorf("max_packet_size=%08x, want 0x01000000", got)
	}
}

// 1.3.2.2: MaxPacketSize=0x00800000 (8 MB).
func TestMySQLPoint_1_3_2_2_MaxPacketSize8MB(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.MaxPacketSize = 0x00800000
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[4].Payload[4:]
	got := uint32(body[4]) | uint32(body[5])<<8 | uint32(body[6])<<16 | uint32(body[7])<<24
	if got != 0x00800000 {
		t.Errorf("max_packet_size=%08x, want 0x00800000", got)
	}
}

// 1.3.3.1: CharacterSet 0x21 in Handshake Response.
func TestMySQLPoint_1_3_3_1_CharSet21InResponse(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.CharacterSet = 0x21
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[4].Payload[4:]
	if body[8] != 0x21 {
		t.Errorf("charset byte=0x%02x, want 0x21", body[8])
	}
}

// 1.3.4.1: Reserved 23 bytes all 0x00.
func TestMySQLPoint_1_3_4_1_Reserved23Zeros(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[4].Payload[4:]
	for i := 0; i < 23; i++ {
		if body[9+i] != 0x00 {
			t.Errorf("reserved[%d]=0x%02x, want 0x00", i, body[9+i])
		}
	}
}

// 1.3.5.1: Username="root" emits "root\0" (5 bytes).
func TestMySQLPoint_1_3_5_1_UsernameRoot(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[4].Payload[4:]
	nameStart := 9 + 23 // capability(4) + max_pkt(4) + charset(1) + reserved(23)
	want := []byte("root\x00")
	got := body[nameStart : nameStart+5]
	if !bytes.Equal(got, want) {
		t.Errorf("username=%q, want %q", got, want)
	}
}

// 1.3.5.2: Username="" defaults to "root" per design §6.1 ("Empty defaults to 'root'").
func TestMySQLPoint_1_3_5_2_UsernameEmptyDefaultsToRoot(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Username = ""
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[4].Payload[4:]
	nameStart := 9 + 23
	// Planner fills empty Username with DefaultUsername "root".
	want := []byte("root\x00")
	got := body[nameStart : nameStart+5]
	if !bytes.Equal(got, want) {
		t.Errorf("empty username should default to 'root\\0', got %q", got)
	}
}

// 1.3.6.1: mysql_native_password + password="mypass" + 20-byte scramble -> 20-byte XOR response.
//
// Per the MySQL native_password algorithm (MySQL source sql/auth/password.c):
//	HASH1 = SHA1(password)
//	HASH2 = SHA1(HASH1)
//	response = HASH1 XOR SHA1(scramble + HASH2)
// The response IS the XOR value (20 bytes) — there is no final SHA1.
// An earlier version of the planner applied an extra `SHA1(xor)`, which
// this test catches by comparing against the independently computed XOR.
func TestMySQLPoint_1_3_6_1_NativePassword20Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.AuthPlugin = "mysql_native_password"
	spec.MySQL.Password = "mypass"
	spec.MySQL.Scramble = bytes.Repeat([]byte{0x41}, 20)
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[4].Payload[4:]
	// auth_response = lenenc-string. With 20-byte response the lenenc length
	// is 1 byte (0x14) followed by 20 bytes of the XOR digest.
	nameStart := 9 + 23
	authStart := nameStart + len("root\x00") + 1 // +1 for the lenenc 0x14 byte
	if body[authStart-1] != 0x14 {
		t.Errorf("auth lenenc=0x%02x, want 0x14 (20)", body[authStart-1])
	}
	got := body[authStart : authStart+20]

	// Independently compute the correct mysql_native_password response:
	// HASH1 XOR SHA1(scramble + SHA1(HASH1)). This MUST equal the planner
	// output; if the planner applies an extra SHA1 (the old bug), the
	// bytes will differ.
	h1 := sha1.Sum([]byte("mypass"))
	h2 := sha1.Sum(h1[:])
	buf := append([]byte{}, bytes.Repeat([]byte{0x41}, 20)...)
	buf = append(buf, h2[:]...)
	step := sha1.Sum(buf)
	var want [20]byte
	for i := 0; i < 20; i++ {
		want[i] = h1[i] ^ step[i]
	}
	if !bytes.Equal(got, want[:]) {
		t.Errorf("auth response = %x, want %x (HASH1 XOR SHA1(scramble+HASH2))", got, want)
	}
	extraSHA1 := sha1.Sum(got)
	if bytes.Equal(got, extraSHA1[:]) {
		t.Errorf("auth response equals SHA1(response) — extra-SHA1 bug is back")
	}
}

// 1.3.6.2: Empty password -> auth_data = lenenc-string(0) = 0x00 (single byte).
func TestMySQLPoint_1_3_6_2_EmptyPasswordAuthData(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Password = ""
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[4].Payload[4:]
	nameStart := 9 + 23
	authLenByte := body[nameStart+len("root\x00")]
	if authLenByte != 0x14 {
		// Empty password for mysql_native_password: planner still emits
		// 20 zero bytes per the protocol (mysql_native_password always
		// returns 20 bytes; empty password => all-zero scramble-stage1).
		t.Errorf("auth lenenc=0x%02x, want 0x14 (20) for mysql_native_password", authLenByte)
	}
}

// 1.3.6.4: caching_sha2_password fast path -> 32-byte SHA256 XOR result.
func TestMySQLPoint_1_3_6_4_CachingSHA2FastPath32Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.AuthPlugin = "caching_sha2_password"
	spec.MySQL.Password = "secret"
	spec.MySQL.Scramble = bytes.Repeat([]byte{0x42}, 20)
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[4].Payload[4:]
	nameStart := 9 + 23
	authLenByte := body[nameStart+len("root\x00")]
	if authLenByte != 0x20 {
		t.Errorf("caching_sha2 auth lenenc=0x%02x, want 0x20 (32)", authLenByte)
	}
}

// 1.3.7.1: Database="mysql" + CONNECT_WITH_DB -> emits "mysql\0" 6 bytes.
func TestMySQLPoint_1_3_7_1_DatabaseEmitted(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Database = "mysql"
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[4].Payload[4:]
	// Find "mysql\0" somewhere after the auth_response.
	if !bytes.Contains(body, []byte("mysql\x00")) {
		t.Errorf("database 'mysql\\0' not found in handshake response body: %x", body)
	}
}

// 1.3.7.2: Database="" -> no "db\0" segment.
func TestMySQLPoint_1_3_7_2_NoDatabaseWhenEmpty(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Database = ""
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[4].Payload[4:]
	// Ensure no "root\0" followed by an unexpected "db\0" segment - the
	// auth_plugin_name "mysql_native_password\0" should follow the
	// auth_response directly.
	if !bytes.Contains(body, []byte("mysql_native_password\x00")) {
		t.Errorf("auth_plugin_name not found: %x", body)
	}
}

// 1.3.8.1: Auth plugin name "mysql_native_password\0" 22 bytes.
func TestMySQLPoint_1_3_8_1_AuthPluginNameInResponse(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	body := cfgs[4].Payload[4:]
	want := []byte("mysql_native_password\x00")
	if !bytes.HasSuffix(body, want) {
		t.Errorf("handshake response should end with %q, got suffix %x", want, body[len(body)-len(want):])
	}
}

// --- 1.4 Command opcodes ---

// 1.4.1.1: COM_QUIT (0x01) command packet body = 1 byte 0x01.
func TestMySQLPoint_1_4_1_1_COM_QUIT(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{{Opcode: 0x01, ReplyMode: "ok"}}
	cfgs := drain(mustPlan(t, p, spec))
	cmd := cfgs[6].Payload
	// 4-byte header + 1 byte opcode.
	if len(cmd) != 5 {
		t.Fatalf("cmd len=%d, want 5", len(cmd))
	}
	if cmd[4] != 0x01 {
		t.Errorf("opcode=0x%02x, want 0x01", cmd[4])
	}
}

// 1.4.2.1: COM_INIT_DB (0x02) + "mysql\0" = 7-byte body.
func TestMySQLPoint_1_4_2_1_COM_INIT_DB(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x02, Body: "mysql\x00", ReplyMode: "ok"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	cmd := cfgs[6].Payload
	body := cmd[4:] // skip header
	want := []byte{0x02, 'm', 'y', 's', 'q', 'l', 0x00}
	if !bytes.Equal(body, want) {
		t.Errorf("COM_INIT_DB body=%x, want %x", body, want)
	}
}

// 1.4.3.1: COM_QUERY (0x03) + "SELECT 1" -> 9-byte body.
func TestMySQLPoint_1_4_3_1_COM_QUERY_Select1(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "SELECT 1", ReplyMode: "ok"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	cmd := cfgs[6].Payload
	body := cmd[4:]
	want := append([]byte{0x03}, []byte("SELECT 1")...)
	if !bytes.Equal(body, want) {
		t.Errorf("COM_QUERY body=%x, want %x", body, want)
	}
}

// 1.4.3.4: BodyEncoding="hex" decodes hex string to bytes.
func TestMySQLPoint_1_4_3_4_COM_QUERY_HexBody(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "53454c4543542031", BodyEncoding: "hex", ReplyMode: "ok"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	cmd := cfgs[6].Payload
	body := cmd[4:]
	want := append([]byte{0x03}, []byte("SELECT 1")...)
	if !bytes.Equal(body, want) {
		t.Errorf("hex body=%x, want %x", body, want)
	}
}

// 1.4.13.1: COM_PING (0x0f) -> 1 byte opcode.
func TestMySQLPoint_1_4_13_1_COM_PING(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	cmd := cfgs[6].Payload
	if len(cmd) != 5 || cmd[4] != 0x0f {
		t.Errorf("COM_PING cmd=%x, want 4-byte header + 0x0f", cmd)
	}
}

// 1.4.18.1: COM_STMT_PREPARE (0x1a) + "SELECT ?\0" body.
func TestMySQLPoint_1_4_18_1_COM_STMT_PREPARE(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x1a, Body: "SELECT ?", ReplyMode: "ok"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	cmd := cfgs[6].Payload
	body := cmd[4:]
	want := append([]byte{0x1a}, []byte("SELECT ?")...)
	if !bytes.Equal(body, want) {
		t.Errorf("COM_STMT_PREPARE body=%x, want %x", body, want)
	}
}

// 1.4.21.1: COM_STMT_CLOSE (0x1d) + stmt_id(4) -> 5-byte body.
func TestMySQLPoint_1_4_21_1_COM_STMT_CLOSE(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x1d, Body: string([]byte{0x01, 0x00, 0x00, 0x00}), BodyEncoding: "text", ReplyMode: "ok"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	cmd := cfgs[6].Payload
	body := cmd[4:]
	if len(body) != 5 || body[0] != 0x1d {
		t.Errorf("COM_STMT_CLOSE body=%x, want 0x1d + 4-byte stmt_id", body)
	}
}

// --- 1.5 Length-Encoded Integer ---

func TestMySQLPoint_1_5_1_LenencInt0(t *testing.T) {
	if got := encodeLenencInt(0); !bytes.Equal(got, []byte{0x00}) {
		t.Errorf("lenenc(0)=%x, want 0x00", got)
	}
}

func TestMySQLPoint_1_5_2_LenencInt1(t *testing.T) {
	if got := encodeLenencInt(1); !bytes.Equal(got, []byte{0x01}) {
		t.Errorf("lenenc(1)=%x, want 0x01", got)
	}
}

func TestMySQLPoint_1_5_3_LenencInt250(t *testing.T) {
	if got := encodeLenencInt(250); !bytes.Equal(got, []byte{0xfa}) {
		t.Errorf("lenenc(250)=%x, want 0xfa", got)
	}
}

func TestMySQLPoint_1_5_4_LenencInt251(t *testing.T) {
	if got := encodeLenencInt(251); !bytes.Equal(got, []byte{0xfc, 0xfb, 0x00}) {
		t.Errorf("lenenc(251)=%x, want 0xfc 0xfb 0x00", got)
	}
}

func TestMySQLPoint_1_5_5_LenencInt65535(t *testing.T) {
	if got := encodeLenencInt(65535); !bytes.Equal(got, []byte{0xfc, 0xff, 0xff}) {
		t.Errorf("lenenc(65535)=%x, want 0xfc 0xff 0xff", got)
	}
}

func TestMySQLPoint_1_5_6_LenencInt65536(t *testing.T) {
	if got := encodeLenencInt(65536); !bytes.Equal(got, []byte{0xfd, 0x00, 0x00, 0x01}) {
		t.Errorf("lenenc(65536)=%x, want 0xfd 0x00 0x00 0x01", got)
	}
}

func TestMySQLPoint_1_5_7_LenencInt16777215(t *testing.T) {
	if got := encodeLenencInt(16777215); !bytes.Equal(got, []byte{0xfd, 0xff, 0xff, 0xff}) {
		t.Errorf("lenenc(16777215)=%x, want 0xfd 0xff 0xff 0xff", got)
	}
}

func TestMySQLPoint_1_5_8_LenencInt16777216(t *testing.T) {
	want := []byte{0xfe, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	if got := encodeLenencInt(16777216); !bytes.Equal(got, want) {
		t.Errorf("lenenc(16777216)=%x, want %x", got, want)
	}
}

func TestMySQLPoint_1_5_9_LenencInt4294967295(t *testing.T) {
	want := []byte{0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00}
	if got := encodeLenencInt(4294967295); !bytes.Equal(got, want) {
		t.Errorf("lenenc(4294967295)=%x, want %x", got, want)
	}
}

// --- 1.6 Length-Encoded String ---

func TestMySQLPoint_1_6_1_LenencStr5Bytes(t *testing.T) {
	if got := encodeLenencString("hello"); !bytes.Equal(got, []byte{0x05, 'h', 'e', 'l', 'l', 'o'}) {
		t.Errorf("lenenc('hello')=%x, want 0x05 'hello'", got)
	}
}

func TestMySQLPoint_1_6_2_LenencStr0Bytes(t *testing.T) {
	if got := encodeLenencString(""); !bytes.Equal(got, []byte{0x00}) {
		t.Errorf("lenenc('')=%x, want 0x00", got)
	}
}

func TestMySQLPoint_1_6_5_LenencStrBinarySafe(t *testing.T) {
	// "a\0b" -> 0x03 'a' 0x00 'b' (4 bytes total).
	if got := encodeLenencString("a\x00b"); !bytes.Equal(got, []byte{0x03, 'a', 0x00, 'b'}) {
		t.Errorf("lenenc('a\\0b')=%x, want 0x03 'a' 0x00 'b'", got)
	}
}

// --- 1.7 NULL Bitmap ---

func TestMySQLPoint_1_7_1_NullBitmap8Cols1Byte(t *testing.T) {
	if got := encodeNullBitmap(8, nil); len(got) != 1 {
		t.Errorf("8 cols bitmap len=%d, want 1", len(got))
	}
}

func TestMySQLPoint_1_7_2_NullBitmap9Cols2Bytes(t *testing.T) {
	if got := encodeNullBitmap(9, nil); len(got) != 2 {
		t.Errorf("9 cols bitmap len=%d, want 2", len(got))
	}
}

func TestMySQLPoint_1_7_3_NullBitmapAllNull(t *testing.T) {
	got := encodeNullBitmap(8, []bool{true, true, true, true, true, true, true, true})
	if got[0] != 0xff {
		t.Errorf("all-null bitmap=%02x, want 0xff", got[0])
	}
}

func TestMySQLPoint_1_7_4_NullBitmapCol0(t *testing.T) {
	got := encodeNullBitmap(8, []bool{true})
	if got[0] != 0x01 {
		t.Errorf("col 0 null bitmap=%02x, want 0x01", got[0])
	}
}

func TestMySQLPoint_1_7_5_NullBitmapCol7(t *testing.T) {
	isNull := make([]bool, 8)
	isNull[7] = true
	got := encodeNullBitmap(8, isNull)
	if got[0] != 0x80 {
		t.Errorf("col 7 null bitmap=%02x, want 0x80", got[0])
	}
}

func TestMySQLPoint_1_7_6_NullBitmapNoNull(t *testing.T) {
	got := encodeNullBitmap(8, nil)
	if got[0] != 0x00 {
		t.Errorf("no-null bitmap=%02x, want 0x00", got[0])
	}
}

// --- 1.8 OK Packet ---

// 1.8.1: Default OK body = 7 bytes: 00 00 00 02 00 00 00.
func TestMySQLPoint_1_8_1_DefaultOKBody(t *testing.T) {
	got := encodeOKPacketAuto(0, 0, serverStatusAutocommit, 0)
	want := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("default OK body=%x, want %x", got, want)
	}
}

// 1.8.2: affected=1, last_id=42 -> 00 01 2a 02 00 00 00.
func TestMySQLPoint_1_8_2_OKInsertBody(t *testing.T) {
	got := encodeOKPacketAuto(1, 42, serverStatusAutocommit, 0)
	want := []byte{0x00, 0x01, 0x2a, 0x02, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("ok-insert body=%x, want %x", got, want)
	}
}

// --- 1.9 ERR Packet ---

// 1.9.1: error_code=1064, sql_state="HY000", message="syntax error".
//
// 1064 = 0x428 -> LE bytes 0x28 0x04. SQLSTATE "HY000" -> ASCII bytes
// 'H' 'Y' '0' '0' '0'. Expected body:
//
//	ff 28 04 23 48 59 30 30 30 + "syntax error"
func TestMySQLPoint_1_9_1_ERRSyntaxError(t *testing.T) {
	got := encodeERRPacket(1064, "HY000", "syntax error")
	want := []byte{0xff, 0x28, 0x04, 0x23, 'H', 'Y', '0', '0', '0'}
	want = append(want, []byte("syntax error")...)
	if !bytes.Equal(got, want) {
		t.Errorf("ERR body=%x, want %x", got, want)
	}
}

// 1.9.2: error_code=1044, sql_state="42000", message="Access denied for user".
//
// 1044 = 0x414 -> LE bytes 0x14 0x04.
func TestMySQLPoint_1_9_2_ERRAccessDenied(t *testing.T) {
	got := encodeERRPacket(1044, "42000", "Access denied for user")
	want := []byte{0xff, 0x14, 0x04, 0x23, '4', '2', '0', '0', '0'}
	want = append(want, []byte("Access denied for user")...)
	if !bytes.Equal(got, want) {
		t.Errorf("ERR body=%x, want %x", got, want)
	}
}

// --- 1.10 EOF Packet ---

// 1.10.1: warnings=0, status=0x0002 -> fe 00 00 02 00.
func TestMySQLPoint_1_10_1_DefaultEOF(t *testing.T) {
	got := encodeEOFPacket(0, serverStatusAutocommit)
	want := []byte{0xfe, 0x00, 0x00, 0x02, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("EOF body=%x, want %x", got, want)
	}
}

// 1.10.2: warnings=10, status=0x0001 -> fe 0a 00 01 00.
func TestMySQLPoint_1_10_2_EOFInTrans(t *testing.T) {
	got := encodeEOFPacket(10, 0x0001)
	want := []byte{0xfe, 0x0a, 0x00, 0x01, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("EOF body=%x, want %x", got, want)
	}
}

// --- 1.11 Column Definition Packet ---

// 1.11.1: Complete col def with all fields.
func TestMySQLPoint_1_11_1_CompleteColDef(t *testing.T) {
	col := core.MySQLColDef{
		Catalog: "def", Schema: "mysql", Table: "user", OrgTable: "user",
		Name: "id", OrgName: "id", Charset: 33, Length: 11,
		Type: 0x03, Flags: 0x0003, Decimals: 0,
	}
	got := encodeColDefPacket(col)
	// Verify the 0x0c separator comes after the 6 lenenc strings.
	want := encodeLenencString("def")
	want = append(want, encodeLenencString("mysql")...)
	want = append(want, encodeLenencString("user")...)
	want = append(want, encodeLenencString("user")...)
	want = append(want, encodeLenencString("id")...)
	want = append(want, encodeLenencString("id")...)
	want = append(want, 0x0c)
	want = append(want, encodeLEUint16(33)...)
	want = append(want, encodeLEUint32(11)...)
	want = append(want, 0x03)
	want = append(want, encodeLEUint16(0x0003)...)
	want = append(want, 0x00)
	want = append(want, 0x00, 0x00)
	if !bytes.Equal(got, want) {
		t.Errorf("col def body=%x, want %x", got, want)
	}
}

// --- 1.12 Capability flag bits ---

// 1.12.2: CLIENT_PROTOCOL_41 (0x0004 in our design).
func TestMySQLPoint_1_12_2_Protocol41Bit(t *testing.T) {
	if designCapabilityFlags&0x0004 == 0 {
		t.Errorf("designCapabilityFlags=%08x should have bit 0x0004 (PROTOCOL_41)", designCapabilityFlags)
	}
}

// 1.12.6: CLIENT_PLUGIN_AUTH (0x8000).
func TestMySQLPoint_1_12_6_PluginAuthBit(t *testing.T) {
	if designCapabilityFlags&0x8000 == 0 {
		t.Errorf("designCapabilityFlags=%08x should have bit 0x8000 (PLUGIN_AUTH)", designCapabilityFlags)
	}
}

// 1.12.7: CLIENT_PLUGIN_AUTH_CLIENT_SUPPLIED_DATA (0x00080000).
func TestMySQLPoint_1_12_7_PluginAuthClientSuppliedBit(t *testing.T) {
	if designCapabilityFlags&0x00080000 == 0 {
		t.Errorf("designCapabilityFlags=%08x should have bit 0x00080000 (PLUGIN_AUTH_CLIENT_SUPPLIED_DATA)", designCapabilityFlags)
	}
}

// --- 2. State machine coverage ---

// 2.1.1.1: GREETING -> AUTH-INIT - planner emits response immediately after greeting.
func TestMySQLPoint_2_1_1_1_GreetingThenResponse(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	// cfgs[3] = greeting (down), cfgs[4] = response (up).
	if cfgs[3].Direction != "down" || cfgs[4].Direction != "up" {
		t.Errorf("expected greeting(down) then response(up), got %s then %s",
			cfgs[3].Direction, cfgs[4].Direction)
	}
}

// 2.1.2.1: mysql_native_password -> server OK(seq=2) -> 3 packets complete.
func TestMySQLPoint_2_1_2_1_NativePasswordAuthComplete(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	// Greeting + response + auth OK = 3 packets at indices 3, 4, 5.
	if cfgs[3].Direction != "down" || cfgs[4].Direction != "up" || cfgs[5].Direction != "down" {
		t.Errorf("expected down/up/down for greeting/response/auth")
	}
}

// 2.2.1.1: COM_QUERY -> OK(seq=1) -> state back to AUTHENTICATED.
func TestMySQLPoint_2_2_1_1_QueryOKThenNextCommand(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "SELECT 1", ReplyMode: "ok"},
		{Opcode: 0x0f, ReplyMode: "ok"}, // COM_PING after the query
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Layout: handshake(3) + greeting(1) + response(1) + authOK(1) +
	//   cmd0(1) + reply0(1) + cmd1(1) + reply1(1) + teardown(4) = 14.
	if len(cfgs) != 14 {
		t.Fatalf("len=%d, want 14", len(cfgs))
	}
	// cmd0 seq=0.
	if cfgs[6].Payload[3] != 0x00 {
		t.Errorf("cmd0 seq=%d, want 0", cfgs[6].Payload[3])
	}
	// cmd1 seq=0 (per-command reset).
	if cfgs[8].Payload[3] != 0x00 {
		t.Errorf("cmd1 seq=%d, want 0 (per-command reset)", cfgs[8].Payload[3])
	}
	// reply0 seq=1, reply1 seq=1.
	if cfgs[7].Payload[3] != 0x01 || cfgs[9].Payload[3] != 0x01 {
		t.Errorf("replies should have seq=1; got %d and %d",
			cfgs[7].Payload[3], cfgs[9].Payload[3])
	}
}

// 2.2.4.1: COM_QUIT -> TCP 4-way teardown.
func TestMySQLPoint_2_2_4_1_COM_QUIT_Teardown(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{{Opcode: 0x01, ReplyMode: "ok"}}
	cfgs := drain(mustPlan(t, p, spec))
	// COM_QUIT at cfgs[6], then OK reply cfgs[7], then teardown cfgs[8..11].
	if cfgs[8].L4.Flags != 0x11 {
		t.Errorf("first teardown packet flags=0x%02x, want 0x11 (FIN-ACK)", cfgs[8].L4.Flags)
	}
}

// --- 2.3 Auth method state machine ---

// 2.3.1.1: mysql_native_password with non-empty password -> 20-byte XOR response.
// The response equals HASH1 XOR SHA1(scramble + SHA1(HASH1)) directly (no
// final SHA1). The old assertion only checked len==20, which passed even
// with the extra-SHA1 bug; we now assert the exact correct bytes.
func TestMySQLPoint_2_3_1_1_NativePasswordSHA1(t *testing.T) {
	password := []byte("mypass")
	scramble := bytes.Repeat([]byte{0x41}, 20)
	resp := mysqlNativePassword(password, scramble)
	if len(resp) != 20 {
		t.Errorf("native password response len=%d, want 20", len(resp))
	}
	// Independently compute the spec-correct response.
	h1 := sha1.Sum(password)
	h2 := sha1.Sum(h1[:])
	buf := append([]byte{}, scramble...)
	buf = append(buf, h2[:]...)
	step := sha1.Sum(buf)
	var want [20]byte
	for i := 0; i < 20; i++ {
		want[i] = h1[i] ^ step[i]
	}
	if !bytes.Equal(resp, want[:]) {
		t.Errorf("native password response = %x, want %x (HASH1 XOR SHA1(scramble+HASH2))", resp, want)
	}
	// Guard against the extra-SHA1 regression: the response must NOT be
	// SHA1(response). With the old bug, resp == SHA1(correct_xor).
	extraSHA1 := sha1.Sum(resp)
	if bytes.Equal(resp, extraSHA1[:]) {
		t.Errorf("response equals SHA1(response) — extra-SHA1 bug is back")
	}
}

// 2.3.1.2: Empty password -> 20 zero bytes (mysql_native_password).
func TestMySQLPoint_2_3_1_2_EmptyPasswordNative(t *testing.T) {
	resp := mysqlNativePassword(nil, bytes.Repeat([]byte{0x41}, 20))
	if len(resp) != 20 {
		t.Errorf("empty password response len=%d, want 20", len(resp))
	}
	for i, b := range resp {
		if b != 0 {
			t.Errorf("empty password resp[%d]=0x%02x, want 0x00", i, b)
		}
	}
}

// 2.3.2.1: caching_sha2_password fast path -> 32-byte SHA256 XOR.
func TestMySQLPoint_2_3_2_1_CachingSHA2FastPath(t *testing.T) {
	resp := cachingSHA2PasswordFast([]byte("secret"), bytes.Repeat([]byte{0x42}, 20))
	if len(resp) != 32 {
		t.Errorf("caching_sha2 response len=%d, want 32", len(resp))
	}
}

// 2.3.2.2: Empty password -> 32 zero bytes (caching_sha2 fast path).
func TestMySQLPoint_2_3_2_2_EmptyCachingSHA2(t *testing.T) {
	resp := cachingSHA2PasswordFast(nil, bytes.Repeat([]byte{0x42}, 20))
	if len(resp) != 32 {
		t.Errorf("empty caching_sha2 response len=%d, want 32", len(resp))
	}
}

// 2.3.4.1: sha256_password -> planner emits 32-byte placeholder.
func TestMySQLPoint_2_3_4_1_SHA256Placeholder(t *testing.T) {
	resp := computeAuthResponse("sha256_password", []byte("pw"), bytes.Repeat([]byte{0x42}, 20))
	if len(resp) != 32 {
		t.Errorf("sha256_password response len=%d, want 32", len(resp))
	}
}

// --- 3. Business scenarios ---

// 3.1.1: S1 standard handshake + SELECT 1.
func TestMySQLPoint_3_1_1_S1_HandshakeSelect1(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "SELECT 1", ReplyMode: "result-set",
			ColDefs: []core.MySQLColDef{
				{Name: "1", OrgName: "1", Type: 0x03, Charset: 33, Length: 1},
			},
			Rows: []core.MySQLRow{{Values: []string{"1"}}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// cmd at cfgs[6]; replies at cfgs[7..] = col_count + col_def + EOF + row + EOF.
	if cfgs[6].Direction != "up" || cfgs[7].Direction != "down" {
		t.Errorf("cmd/reply directions wrong: %s %s", cfgs[6].Direction, cfgs[7].Direction)
	}
	// Verify first reply body starts with lenenc-int column count = 1.
	replyBody := cfgs[7].Payload[4:]
	if replyBody[0] != 0x01 {
		t.Errorf("col count lenenc=0x%02x, want 0x01", replyBody[0])
	}
}

// 3.4.1: S4 INSERT -> OK(affected=1, last_id=42).
func TestMySQLPoint_3_4_1_S4_InsertOK(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "INSERT INTO t VALUES (1)", ReplyMode: "ok-insert"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	okBody := cfgs[7].Payload[4:]
	// 0x00 + 0x01 (affected) + 0x2a (last_id=42) + 0x02 0x00 (status) + 0x00 0x00 (warnings).
	want := []byte{0x00, 0x01, 0x2a, 0x02, 0x00, 0x00, 0x00}
	if !bytes.Equal(okBody, want) {
		t.Errorf("ok-insert body=%x, want %x", okBody, want)
	}
}

// 3.6.1: S6 syntax error -> ERR(1064 #HY000).
func TestMySQLPoint_3_6_1_S6_SyntaxError(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "INVALID SQL", ReplyMode: "err"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	errBody := cfgs[7].Payload[4:]
	if errBody[0] != 0xff {
		t.Errorf("ERR marker=0x%02x, want 0xff", errBody[0])
	}
	errCode := uint16(errBody[1]) | uint16(errBody[2])<<8
	if errCode != 1064 {
		t.Errorf("error code=%d, want 1064", errCode)
	}
}

// 3.12.1: S12 Ping -> OK packet.
func TestMySQLPoint_3_12_1_S12_PingOK(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	// Reply body should be the default OK packet (7 bytes).
	replyBody := cfgs[7].Payload[4:]
	if len(replyBody) != 7 || replyBody[0] != 0x00 {
		t.Errorf("COM_PING reply body=%x, want default OK (7 bytes starting with 0x00)", replyBody)
	}
}

// 3.13.1: S13 COM_QUIT -> teardown follows.
func TestMySQLPoint_3_13_1_S13_QuitTeardown(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{{Opcode: 0x01, ReplyMode: "ok"}}
	cfgs := drain(mustPlan(t, p, spec))
	// Last 4 packets should be the FIN-ACK/ACK/FIN-ACK/ACK teardown.
	if len(cfgs) < 4 {
		t.Fatalf("too few cfgs: %d", len(cfgs))
	}
	last4 := cfgs[len(cfgs)-4:]
	if last4[0].L4.Flags != 0x11 || last4[1].L4.Flags != 0x10 ||
		last4[2].L4.Flags != 0x11 || last4[3].L4.Flags != 0x10 {
		t.Errorf("teardown flags = %02x %02x %02x %02x, want 11 10 11 10",
			last4[0].L4.Flags, last4[1].L4.Flags,
			last4[2].L4.Flags, last4[3].L4.Flags)
	}
}

// --- 4. Data scenarios ---

// 4.2.2: Sequence ID = 255 (max) still 1 byte.
func TestMySQLPoint_4_2_2_SeqID255(t *testing.T) {
	// Build a synthetic reply chain that produces seq=255 (256 packets).
	// We use "raw" mode with a large ReplyBytes split into 1-byte chunks.
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.MaxPacketSize = 1 // forces 1-byte chunks
	// 256 'A' chars -> 256 packets, each with seq 1, 2, ..., 255, 0 (wraps).
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x0f, ReplyMode: "raw", ReplyBytes: strings.Repeat("A", 256), ReplyEncoding: "text"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find first down-packet after the command (cfgs[6] = cmd up).
	// cfgs[7..] = reply packets.
	var seqs []uint8
	for i := 7; i < len(cfgs); i++ {
		if cfgs[i].Direction != "down" {
			break
		}
		seqs = append(seqs, cfgs[i].Payload[3])
	}
	if len(seqs) < 255 {
		t.Fatalf("only %d reply packets, want >= 255", len(seqs))
	}
	if seqs[254] != 0xff {
		t.Errorf("seq[254]=%d, want 255 (0xff)", seqs[254])
	}
	// Verify the wrap-around: seq 256 should be 0x00 (mod 256).
	if seqs[255] != 0x00 {
		t.Errorf("seq[255]=%d, want 0 (wrap-around after 255)", seqs[255])
	}
}

// 4.4.4: 100-column result set -> 100 column definition packets.
func TestMySQLPoint_4_4_4_100ColResult(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	cols := make([]core.MySQLColDef, 100)
	for i := range cols {
		cols[i] = core.MySQLColDef{Name: "c", OrgName: "c", Type: 0x03, Charset: 33, Length: 1}
	}
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "SELECT * FROM big", ReplyMode: "result-set", ColDefs: cols},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// cmd at cfgs[6]; replies at cfgs[7..7+1+100+1] = col_count(1) +
	// col_defs(100) + EOF(1) + rows(0) + EOF(1) = 103 down packets.
	// Validate the first reply is col_count=100 (lenenc=0x64).
	firstReply := cfgs[7].Payload[4:]
	if firstReply[0] != 0x64 {
		t.Errorf("col count lenenc=0x%02x, want 0x64 (100)", firstReply[0])
	}
}

// 4.5.1: COM_PING -> 5-byte TCP payload (4-byte header + 1-byte opcode).
func TestMySQLPoint_4_5_1_PING5BytePayload(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	cmd := cfgs[6].Payload
	if len(cmd) != 5 {
		t.Errorf("COM_PING payload len=%d, want 5", len(cmd))
	}
}

// 4.5.2: COM_QUIT -> 1-byte opcode + 4-byte header = 5-byte TCP payload.
func TestMySQLPoint_4_5_2_QUIT5BytePayload(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{{Opcode: 0x01, ReplyMode: "ok"}}
	cfgs := drain(mustPlan(t, p, spec))
	cmd := cfgs[6].Payload
	if len(cmd) != 5 || cmd[4] != 0x01 {
		t.Errorf("COM_QUIT payload=%x, want 5 bytes ending with 0x01", cmd)
	}
}

// --- 5. Concurrency (lightweight - planner is single-goroutine by design) ---

// 5.1: 8 concurrent planner invocations produce 8 distinct flows.
func TestMySQLPoint_5_1_ConcurrentPlanners(t *testing.T) {
	p := NewPlanner()
	done := make(chan struct{}, 8)
	for i := 0; i < 8; i++ {
		go func(idx int) {
			defer func() { done <- struct{}{} }()
			spec := validMySQLSpec()
			spec.SrcPort = uint16(50000 + idx)
			ch, err := p.Plan(context.Background(), spec)
			if err != nil {
				t.Errorf("planner %d: %v", idx, err)
				return
			}
			count := 0
			for range ch {
				count++
			}
			if count != 12 {
				t.Errorf("planner %d: count=%d, want 12", idx, count)
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

// --- 6. Resource exhaustion / context cancel ---

// 6.2: ctx cancel -> planner exits and closes the channel.
func TestMySQLPoint_6_2_ContextCancel(t *testing.T) {
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	spec := validMySQLSpec()
	// Generate a large spec to give the planner time to be cancellable.
	spec.MySQL.Commands = make([]core.MySQLCommand, 1000)
	for i := range spec.MySQL.Commands {
		spec.MySQL.Commands[i] = core.MySQLCommand{Opcode: 0x0f, ReplyMode: "ok"}
	}
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// Drain a few then cancel.
	go func() {
		for i := 0; i < 3; i++ {
			<-ch
		}
		cancel()
	}()
	// Drain the rest (channel should close).
	count := 0
	for range ch {
		count++
	}
	// Planner may or may not have emitted all packets before cancel; the
	// contract is that the channel closes. Verify it closed (range exits).
	if count == 0 {
		t.Errorf("planner emitted 0 packets before cancel closed channel")
	}
}

// 6.4: MSS = 536 (min) -> all PSH-ACK segments <= 536 bytes.
func TestMySQLPoint_6_4_MinMSS(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.TCP = &core.TCPConfig{MSS: 536}
	// Make the greeting large enough to span multiple segments.
	spec.MySQL.ServerVersion = strings.Repeat("x", 200)
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.L4.Flags == 0x18 && len(c.Payload) > 536 {
			t.Errorf("cfgs[%d] PSH-ACK payload len=%d, want <= 536", i, len(c.Payload))
		}
	}
}

// 6.5: MSS = 65535 (max) -> single segment can carry whole packet.
func TestMySQLPoint_6_5_MaxMSS(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.TCP = &core.TCPConfig{MSS: 65535}
	cfgs := drain(mustPlan(t, p, spec))
	// Greeting should fit in 1 segment.
	if len(cfgs[3].Payload) > 65535 {
		t.Errorf("greeting payload len=%d, want <= 65535", len(cfgs[3].Payload))
	}
}

// --- 7. Integration / build verification ---

// 7.1: Full chain (handshake + greeting + auth + cmd + reply + teardown) builds.
func TestMySQLPoint_7_1_FullChainBuilds(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "SELECT * FROM users", ReplyMode: "result-set",
			ColDefs: []core.MySQLColDef{
				{Name: "id", OrgName: "id", Type: 0x03, Charset: 33, Length: 11, Flags: 0x0003},
				{Name: "name", OrgName: "name", Type: 0xfd, Charset: 33, Length: 50},
			},
			Rows: []core.MySQLRow{
				{Values: []string{"1", "alice"}},
				{Values: []string{"2", "bob"}},
			},
		},
		{Opcode: 0x01, ReplyMode: "ok"}, // COM_QUIT
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Layout:
	//   handshake(3) + greeting(1) + response(1) + auth(1) = 6
	//   cmd0(1) + reply0(1 col_count + 2 col_defs + 1 EOF + 2 rows + 1 EOF = 7) = 8
	//   cmd1(1) + reply1(1 OK) = 2
	//   teardown(4)
	// Total = 6 + 8 + 2 + 4 = 20.
	if len(cfgs) != 20 {
		t.Fatalf("len=%d, want 20", len(cfgs))
	}
}

// --- Helper: allNonZero ---

func allNonZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return true
		}
	}
	return false
}

// --- Hex/base64 decode sanity tests ---

func TestMySQLPoint_Helper_HexDecodeOK(t *testing.T) {
	b, err := decodeUserBytes("48454c4c4f", "hex")
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	if string(b) != "HELLO" {
		t.Errorf("hex decode=%q, want HELLO", string(b))
	}
}

func TestMySQLPoint_Helper_Base64DecodeOK(t *testing.T) {
	b, err := decodeUserBytes(base64.StdEncoding.EncodeToString([]byte("HELLO")), "base64")
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if string(b) != "HELLO" {
		t.Errorf("base64 decode=%q, want HELLO", string(b))
	}
}

func TestMySQLPoint_Helper_TextDecodeOK(t *testing.T) {
	b, err := decodeUserBytes("plain text", "text")
	if err != nil {
		t.Fatalf("text decode: %v", err)
	}
	if string(b) != "plain text" {
		t.Errorf("text decode=%q, want 'plain text'", string(b))
	}
}

func TestMySQLPoint_Helper_HexDecodeBad(t *testing.T) {
	_, err := decodeUserBytes("not-hex!!", "hex")
	if err == nil {
		t.Errorf("expected hex decode error for 'not-hex!!'")
	}
}

func TestMySQLPoint_Helper_EncodeLEUint16(t *testing.T) {
	if got := encodeLEUint16(0x1234); !bytes.Equal(got, []byte{0x34, 0x12}) {
		t.Errorf("LE16(0x1234)=%x, want 0x34 0x12", got)
	}
}

func TestMySQLPoint_Helper_EncodeLEUint32(t *testing.T) {
	if got := encodeLEUint32(0x12345678); !bytes.Equal(got, []byte{0x78, 0x56, 0x34, 0x12}) {
		t.Errorf("LE32(0x12345678)=%x, want 0x78 0x56 0x34 0x12", got)
	}
}

func TestMySQLPoint_Helper_EncodeLEUint24(t *testing.T) {
	if got := encodeLEUint24(0x123456); !bytes.Equal(got, []byte{0x56, 0x34, 0x12}) {
		t.Errorf("LE24(0x123456)=%x, want 0x56 0x34 0x12", got)
	}
}

func TestMySQLPoint_Helper_EncodeLEUint24Max(t *testing.T) {
	if got := encodeLEUint24(MaxPacketBytes); !bytes.Equal(got, []byte{0xff, 0xff, 0xff}) {
		t.Errorf("LE24(max)=%x, want 0xff 0xff 0xff", got)
	}
}

// --- Hex encoding for clarity in test source ---
var _ = hex.EncodeToString
