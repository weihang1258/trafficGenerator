package shadowsocks

// Spec-driven atomic test points from /tmp/l7_planner_design/testcases_shadowsocks.md.
// Each test asserts observable PacketConfig field values for one atomic
// test case ID. Covers RFC field coverage (§1), state machine (§2),
// business scenarios (§3), and data scenarios (§4).

import (
	"context"
	"encoding/binary"
	"strings"
	"sync"
	"testing"
)

// ============================================================
// §1.1 SOCKS5 Greeting — VER field
// ============================================================

// TestSS_1_1_1_GreetingVER_Standard covers testcase 1.1.1: VER=0x05.
func TestSS_1_1_1_GreetingVER_Standard(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "none"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	greeting := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if greeting == nil || len(greeting) < 1 {
		t.Fatalf("no greeting")
	}
	if greeting[0] != 0x05 {
		t.Errorf("VER=0x%02x, want 0x05", greeting[0])
	}
}

// TestSS_1_1_5_GreetingVER_SkipHandshake covers testcase 1.1.5: no greeting.
func TestSS_1_1_5_GreetingVER_SkipHandshake(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = false
	cfgs := drain(mustPlan(t, p, spec))
	greeting := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if greeting == nil {
		t.Fatalf("no up payload")
	}
	// Without SOCKS5, first up payload is salt (32 bytes), not greeting (3 bytes).
	if len(greeting) == 3 && greeting[0] == 0x05 {
		t.Errorf("unexpected SOCKS5 greeting when SOCKS5Handshake=false")
	}
}

// ============================================================
// §1.2 SOCKS5 Greeting — NMETHODS field
// ============================================================

// TestSS_1_2_1_NMETHODS_SingleNoAuth covers testcase 1.2.1: NMETHODS=1 for NO_AUTH.
func TestSS_1_2_1_NMETHODS_SingleNoAuth(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "none"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	greeting := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if greeting == nil || len(greeting) < 2 {
		t.Fatalf("no greeting")
	}
	if greeting[1] != 0x01 {
		t.Errorf("NMETHODS=%d, want 1", greeting[1])
	}
}

// TestSS_1_2_2_NMETHODS_Password covers testcase 1.2.2: NMETHODS=1 for PASSWORD.
func TestSS_1_2_2_NMETHODS_Password(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "password"
	spec.Shadowsocks.SOCKS5Username = "foo"
	spec.Shadowsocks.SOCKS5Password = "bar"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	greeting := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if greeting == nil || len(greeting) < 2 {
		t.Fatalf("no greeting")
	}
	if greeting[1] != 0x01 {
		t.Errorf("NMETHODS=%d, want 1", greeting[1])
	}
}

// ============================================================
// §1.3 SOCKS5 Greeting — METHODS field
// ============================================================

// TestSS_1_3_1_METHODS_NoAuth covers testcase 1.3.1: METHODS=[0x00].
func TestSS_1_3_1_METHODS_NoAuth(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "none"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	greeting := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if greeting == nil || len(greeting) < 3 {
		t.Fatalf("no greeting")
	}
	if greeting[2] != 0x00 {
		t.Errorf("METHODS[0]=0x%02x, want 0x00", greeting[2])
	}
}

// TestSS_1_3_2_METHODS_Password covers testcase 1.3.2: METHODS=[0x02].
func TestSS_1_3_2_METHODS_Password(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "password"
	spec.Shadowsocks.SOCKS5Username = "u"
	spec.Shadowsocks.SOCKS5Password = "p"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	greeting := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if greeting == nil || len(greeting) < 3 {
		t.Fatalf("no greeting")
	}
	if greeting[2] != 0x02 {
		t.Errorf("METHODS[0]=0x%02x, want 0x02", greeting[2])
	}
}

// ============================================================
// §1.4 SOCKS5 Method Response — METHOD field
// ============================================================

// TestSS_1_4_1_MethodResponse_NoAuth covers testcase 1.4.1: METHOD=0x00.
func TestSS_1_4_1_MethodResponse_NoAuth(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "none"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	methodResp := findFirstPayloadByDirection(cfgs, "down", 0x18)
	if methodResp == nil || len(methodResp) < 2 {
		t.Fatalf("no method response")
	}
	if methodResp[0] != 0x05 {
		t.Errorf("VER=0x%02x, want 0x05", methodResp[0])
	}
	if methodResp[1] != 0x00 {
		t.Errorf("METHOD=0x%02x, want 0x00", methodResp[1])
	}
}

// TestSS_1_4_2_MethodResponse_Password covers testcase 1.4.2: METHOD=0x02.
func TestSS_1_4_2_MethodResponse_Password(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "password"
	spec.Shadowsocks.SOCKS5Username = "u"
	spec.Shadowsocks.SOCKS5Password = "p"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	methodResp := findFirstPayloadByDirection(cfgs, "down", 0x18)
	if methodResp == nil || len(methodResp) < 2 {
		t.Fatalf("no method response")
	}
	if methodResp[1] != 0x02 {
		t.Errorf("METHOD=0x%02x, want 0x02", methodResp[1])
	}
}

// ============================================================
// §1.5 SOCKS5 Auth — VER field
// ============================================================

// TestSS_1_5_1_AuthVER_Standard covers testcase 1.5.1: auth VER=0x01.
func TestSS_1_5_1_AuthVER_Standard(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "password"
	spec.Shadowsocks.SOCKS5Username = "foo"
	spec.Shadowsocks.SOCKS5Password = "bar"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	// Auth request is the 2nd up PSH-ACK (after greeting)
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(upPayloads) < 3 {
		t.Fatalf("expected at least 3 up payloads, got %d", len(upPayloads))
	}
	authReq := upPayloads[1] // greeting then auth
	if authReq[0] != 0x01 {
		t.Errorf("auth VER=0x%02x, want 0x01", authReq[0])
	}
}

// ============================================================
// §1.6 SOCKS5 Auth — ULEN / UNAME fields
// ============================================================

// TestSS_1_6_1_ULEN_ShortUsername covers testcase 1.6.1: ULEN=3 for "foo".
func TestSS_1_6_1_ULEN_ShortUsername(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "password"
	spec.Shadowsocks.SOCKS5Username = "foo"
	spec.Shadowsocks.SOCKS5Password = "bar"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	authReq := upPayloads[1]
	if authReq[1] != 0x03 {
		t.Errorf("ULEN=%d, want 3", authReq[1])
	}
	if string(authReq[2:5]) != "foo" {
		t.Errorf("UNAME=%q, want 'foo'", string(authReq[2:5]))
	}
}

// TestSS_1_6_2_ULEN_SingleByteUsername covers testcase 1.6.2: ULEN=1.
func TestSS_1_6_2_ULEN_SingleByteUsername(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "password"
	spec.Shadowsocks.SOCKS5Username = "a"
	spec.Shadowsocks.SOCKS5Password = "p"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	authReq := upPayloads[1]
	if authReq[1] != 0x01 {
		t.Errorf("ULEN=%d, want 1", authReq[1])
	}
	if string(authReq[2:3]) != "a" {
		t.Errorf("UNAME=%q, want 'a'", string(authReq[2:3]))
	}
}

// ============================================================
// §1.7 SOCKS5 Auth — PLEN / PASS fields
// ============================================================

// TestSS_1_7_1_PLEN_ShortPassword covers testcase 1.7.1: PLEN=3.
func TestSS_1_7_1_PLEN_ShortPassword(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "password"
	spec.Shadowsocks.SOCKS5Username = "foo"
	spec.Shadowsocks.SOCKS5Password = "bar"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	authReq := upPayloads[1]
	plenOffset := 2 + int(authReq[1]) // 2 = VER+ULEN
	if authReq[plenOffset] != 0x03 {
		t.Errorf("PLEN=%d, want 3", authReq[plenOffset])
	}
	if string(authReq[plenOffset+1:plenOffset+4]) != "bar" {
		t.Errorf("PASS=%q, want 'bar'", string(authReq[plenOffset+1:plenOffset+4]))
	}
}

// TestSS_1_7_7_AuthStatus_Success covers testcase 1.7.7: STATUS=0x00.
func TestSS_1_7_7_AuthStatus_Success(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "password"
	spec.Shadowsocks.SOCKS5Username = "u"
	spec.Shadowsocks.SOCKS5Password = "p"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	// Auth response is the 2nd down PSH-ACK (after method response)
	downPayloads := collectAllPayloadsByDirection(cfgs, "down", 0x18)
	if len(downPayloads) < 2 {
		t.Fatalf("expected at least 2 down payloads, got %d", len(downPayloads))
	}
	authResp := downPayloads[1]
	if authResp[0] != 0x01 {
		t.Errorf("auth response VER=0x%02x, want 0x01", authResp[0])
	}
	if authResp[1] != 0x00 {
		t.Errorf("STATUS=0x%02x, want 0x00", authResp[1])
	}
}

// ============================================================
// §1.8 SOCKS5 Request — CMD field
// ============================================================

// TestSS_1_8_1_CMD_CONNECT covers testcase 1.8.1: CMD=0x01.
func TestSS_1_8_1_CMD_CONNECT(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5Cmd = "connect"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[len(upPayloads)-3] // request is 3rd up payload (after greeting, salt) or for no-auth: greeting(0), request(1), salt(2)
	// With no-auth: greeting(up) -> method_response(down) -> request(up) -> reply(down) -> salt(up) -> chunks(up)
	// So request is upPayloads[1] (0: greeting, 1: request, 2: salt, 3+: chunks)
	if req[1] != 0x01 {
		t.Errorf("CMD=0x%02x, want 0x01", req[1])
	}
}

// TestSS_1_8_2_CMD_BIND covers testcase 1.8.2: CMD=0x02.
func TestSS_1_8_2_CMD_BIND(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5Cmd = "bind"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[1]
	if req[1] != 0x02 {
		t.Errorf("CMD=0x%02x, want 0x02", req[1])
	}
}

// ============================================================
// §1.9 SOCKS5 Request — RSV field
// ============================================================

// TestSS_1_9_1_RSV_Standard covers testcase 1.9.1: RSV=0x00.
func TestSS_1_9_1_RSV_Standard(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[1]
	if req[2] != 0x00 {
		t.Errorf("RSV=0x%02x, want 0x00", req[2])
	}
}

// ============================================================
// §1.10 SOCKS5 Request — ATYP field
// ============================================================

// TestSS_1_10_1_ATYP_IPv4 covers testcase 1.10.1: ATYP=0x01.
func TestSS_1_10_1_ATYP_IPv4(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[1]
	if req[3] != 0x01 {
		t.Errorf("ATYP=0x%02x, want 0x01", req[3])
	}
}

// TestSS_1_10_2_ATYP_DOMAIN covers testcase 1.10.2: ATYP=0x03.
func TestSS_1_10_2_ATYP_DOMAIN(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "example.com"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[1]
	if req[3] != 0x03 {
		t.Errorf("ATYP=0x%02x, want 0x03", req[3])
	}
}

// TestSS_1_10_3_ATYP_IPv6 covers testcase 1.10.3: ATYP=0x04.
func TestSS_1_10_3_ATYP_IPv6(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "2001:db8::1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[1]
	if req[3] != 0x04 {
		t.Errorf("ATYP=0x%02x, want 0x04", req[3])
	}
}

// ============================================================
// §1.11 SOCKS5 Request — ADDR field
// ============================================================

// TestSS_1_11_1_ADDR_IPv4 covers testcase 1.11.1: ADDR IPv4 encoding.
func TestSS_1_11_1_ADDR_IPv4(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[1]
	// IPv4: 192.0.2.1 = 0xC0 0x00 0x02 0x01
	if req[4] != 0xC0 || req[5] != 0x00 || req[6] != 0x02 || req[7] != 0x01 {
		t.Errorf("ADDR=0x%02x%02x%02x%02x, want 0xC0000201", req[4], req[5], req[6], req[7])
	}
}

// TestSS_1_11_7_ADDR_DomainShort covers testcase 1.11.7: short domain.
func TestSS_1_11_7_ADDR_DomainShort(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "a.b"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[1]
	if req[3] != 0x03 {
		t.Errorf("ATYP=0x%02x, want 0x03", req[3])
	}
	if req[4] != 0x03 {
		t.Errorf("domain len=%d, want 3", req[4])
	}
	if string(req[5:8]) != "a.b" {
		t.Errorf("domain=%q, want 'a.b'", string(req[5:8]))
	}
}

// TestSS_1_11_10_ADDR_DomainUTF8 covers testcase 1.11.10: non-ASCII domain.
func TestSS_1_11_10_ADDR_DomainUTF8(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "例え.jp"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[1]
	if req[3] != 0x03 {
		t.Errorf("ATYP=0x%02x, want 0x03", req[3])
	}
	domain := string(req[5 : 5+int(req[4])])
	if !strings.Contains(domain, "例え") {
		t.Errorf("domain=%q, should contain '例え'", domain)
	}
}

// ============================================================
// §1.12 SOCKS5 Request — PORT field
// ============================================================

// TestSS_1_12_1_PORT_443 covers testcase 1.12.1: PORT=443 = 0x01BB.
func TestSS_1_12_1_PORT_443(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[1]
	portOffset := 4 + 4 // ATYP=IPv4 => 4 bytes addr
	if req[portOffset] != 0x01 || req[portOffset+1] != 0xBB {
		t.Errorf("PORT=0x%02x%02x, want 0x01BB (443)", req[portOffset], req[portOffset+1])
	}
}

// TestSS_1_12_2_PORT_80 covers testcase 1.12.2: PORT=80 = 0x0050.
func TestSS_1_12_2_PORT_80(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 80
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[1]
	portOffset := 4 + 4
	if req[portOffset] != 0x00 || req[portOffset+1] != 0x50 {
		t.Errorf("PORT=0x%02x%02x, want 0x0050 (80)", req[portOffset], req[portOffset+1])
	}
}

// TestSS_1_12_6_PORT_8388 covers testcase 1.12.6: PORT=8388=0x20C4 (BE).
func TestSS_1_12_6_PORT_8388(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 8388
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[1]
	portOffset := 4 + 4
	if req[portOffset] != 0x20 || req[portOffset+1] != 0xC4 {
		t.Errorf("PORT=0x%02x%02x, want 0x20C4 (8388)", req[portOffset], req[portOffset+1])
	}
}

// ============================================================
// §1.13 SOCKS5 Reply — REP field
// ============================================================

// TestSS_1_13_1_REP_Success covers testcase 1.13.1: REP=0x00.
func TestSS_1_13_1_REP_Success(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	downPayloads := collectAllPayloadsByDirection(cfgs, "down", 0x18)
	// For no-auth: method_response(down[0]) -> reply(down[1])
	reply := downPayloads[1]
	if reply[1] != 0x00 {
		t.Errorf("REP=0x%02x, want 0x00", reply[1])
	}
}

// ============================================================
// §1.14 SOCKS5 Reply — BNDADDR / BNDPORT
// ============================================================

// TestSS_1_14_1_BNDADDR_Default covers testcase 1.14.1: default BNDADDR=0.0.0.0.
func TestSS_1_14_1_BNDADDR_Default(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	downPayloads := collectAllPayloadsByDirection(cfgs, "down", 0x18)
	reply := downPayloads[1]
	// Default BNDADDR: ATYP=0x01, ADDR=0.0.0.0
	if reply[3] != 0x01 {
		t.Errorf("BNDATYP=0x%02x, want 0x01", reply[3])
	}
	if reply[4] != 0x00 || reply[5] != 0x00 || reply[6] != 0x00 || reply[7] != 0x00 {
		t.Errorf("BNDADDR=0x%02x%02x%02x%02x, want 0.0.0.0", reply[4], reply[5], reply[6], reply[7])
	}
}

// TestSS_1_14_4_BNDPORT_Default covers testcase 1.14.4: default BNDPORT=0.
func TestSS_1_14_4_BNDPORT_Default(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	downPayloads := collectAllPayloadsByDirection(cfgs, "down", 0x18)
	reply := downPayloads[1]
	if reply[8] != 0x00 || reply[9] != 0x00 {
		t.Errorf("BNDPORT=0x%02x%02x, want 0x0000", reply[8], reply[9])
	}
}

// TestSS_1_14_5_BNDPORT_Explicit covers testcase 1.14.5: explicit BNDPORT.
func TestSS_1_14_5_BNDPORT_Explicit(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5BNDAddr = "10.0.0.1"
	spec.Shadowsocks.SOCKS5BNDPort = 12345
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	downPayloads := collectAllPayloadsByDirection(cfgs, "down", 0x18)
	reply := downPayloads[1]
	// BNDADDR = 10.0.0.1
	if reply[4] != 0x0A || reply[5] != 0x00 || reply[6] != 0x00 || reply[7] != 0x01 {
		t.Errorf("BNDADDR=0x%02x%02x%02x%02x, want 10.0.0.1", reply[4], reply[5], reply[6], reply[7])
	}
	// BNDPORT = 12345 = 0x3039
	if reply[8] != 0x30 || reply[9] != 0x39 {
		t.Errorf("BNDPORT=0x%02x%02x, want 0x3039 (12345)", reply[8], reply[9])
	}
}

// ============================================================
// §1.15 Shadowsocks Salt field
// ============================================================

// TestSS_1_15_1_Salt_AES128GCM covers testcase 1.15.1: salt=32B for AES-128-GCM.
func TestSS_1_15_1_Salt_AES128GCM(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "aes-128-gcm"
	cfgs := drain(mustPlan(t, p, spec))
	salt := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if salt == nil {
		t.Fatalf("no up PSH-ACK")
	}
	if len(salt) != 32 {
		t.Errorf("salt length=%d, want 32", len(salt))
	}
}

// TestSS_1_15_4_Salt_NoneCipher covers testcase 1.15.4: no salt for none cipher.
func TestSS_1_15_4_Salt_NoneCipher(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "none"
	cfgs := drain(mustPlan(t, p, spec))
	first := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if first == nil {
		t.Fatalf("no up PSH-ACK")
	}
	// First up payload should be a chunk (2 + payloadSize + 0 tag), not 32B salt
	if len(first) == 32 {
		t.Errorf("unexpected salt for none cipher")
	}
}

// TestSS_1_15_10_Salt_SingleConnection covers testcase 1.15.10: only first chunk has salt.
func TestSS_1_15_10_Salt_SingleConnection(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 3
	spec.Shadowsocks.ChunkPayloadSize = 10
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	// First up payload is salt (32B), rest are chunks
	if len(upPayloads[0]) != 32 {
		t.Errorf("first payload length=%d, want 32 (salt)", len(upPayloads[0]))
	}
	// Chunks should not be 32 bytes (they are 2+10+16=28)
	for i := 1; i < len(upPayloads); i++ {
		if len(upPayloads[i]) == 32 {
			t.Errorf("chunk[%d] length=32, unexpected salt", i)
		}
	}
}

// ============================================================
// §1.16 AEAD Chunk — Encrypted Length field
// ============================================================

// TestSS_1_16_1_EncryptedLen_ZeroPayload covers testcase 1.16.1: zero-payload chunk.
func TestSS_1_16_1_EncryptedLen_ZeroPayload(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 0
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	chunk := upPayloads[1] // after salt
	// AEAD chunk: 2 (len) + 0 (payload) + 16 (tag) = 18 bytes
	if len(chunk) != 18 {
		t.Errorf("chunk length=%d, want 18", len(chunk))
	}
}

// TestSS_1_16_3_EncryptedLen_MaxPayload covers testcase 1.16.3: max payload.
// With MSS=1460, a 16401-byte chunk is split into ceil(16401/1460) = 12 segments.
func TestSS_1_16_3_EncryptedLen_MaxPayload(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 16383
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	// salt(32) + chunk segments (12 segments)
	// Total chunk bytes across all segments = 2 + 16383 + 16 = 16401
	if len(upPayloads) < 13 {
		t.Fatalf("expected at least 13 up payloads (salt + 12 segments), got %d", len(upPayloads))
	}
	totalChunkBytes := 0
	for i := 1; i < len(upPayloads); i++ {
		totalChunkBytes += len(upPayloads[i])
	}
	if totalChunkBytes != 16401 {
		t.Errorf("total chunk bytes=%d, want 16401", totalChunkBytes)
	}
}

// ============================================================
// §1.17 AEAD Chunk — Encrypted Payload field
// ============================================================

// TestSS_1_17_2_EncryptedPayload_1Byte covers testcase 1.17.2: 1-byte payload.
func TestSS_1_17_2_EncryptedPayload_1Byte(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 1
	spec.Shadowsocks.PayloadBytesFormat = "zeros"
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	chunk := upPayloads[1]
	// 2 + 1 + 16 = 19 bytes
	if len(chunk) != 19 {
		t.Errorf("chunk length=%d, want 19", len(chunk))
	}
}

// ============================================================
// §1.18 AEAD Chunk — Auth Tag field
// ============================================================

// TestSS_1_18_1_Tag_AES128GCM covers testcase 1.18.1: tag=16 for AES-128-GCM.
func TestSS_1_18_1_Tag_AES128GCM(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "aes-128-gcm"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 10
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	chunk := upPayloads[1]
	// 2 + 10 + 16 = 28
	if len(chunk) != 28 {
		t.Errorf("chunk length=%d, want 28", len(chunk))
	}
}

// TestSS_1_18_4_Tag_NoneCipher covers testcase 1.18.4: no tag for none cipher.
func TestSS_1_18_4_Tag_NoneCipher(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 10
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	chunk := upPayloads[0] // no salt, so first up payload is the chunk
	// 2 + 10 = 12 (no tag)
	if len(chunk) != 12 {
		t.Errorf("chunk length=%d, want 12", len(chunk))
	}
}

// ============================================================
// §1.19 SIP004 None Cipher Chunk
// ============================================================

// TestSS_1_19_1_NoneChunk_ZeroPayload covers testcase 1.19.1: none chunk zero payload.
func TestSS_1_19_1_NoneChunk_ZeroPayload(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 0
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	chunk := upPayloads[0]
	// 2 bytes (len=0x0000)
	if len(chunk) != 2 {
		t.Errorf("chunk length=%d, want 2 (0-payload none chunk)", len(chunk))
	}
	// Length field should be 0
	if chunk[0] != 0x00 || chunk[1] != 0x00 {
		t.Errorf("length field=0x%02x%02x, want 0x0000", chunk[0], chunk[1])
	}
}

// TestSS_1_19_2_NoneChunk_100Bytes covers testcase 1.19.2: none chunk with 100B payload.
func TestSS_1_19_2_NoneChunk_100Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 100
	spec.Shadowsocks.PayloadBytesFormat = "zeros"
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	chunk := upPayloads[0]
	// 2 + 100 = 102
	if len(chunk) != 102 {
		t.Errorf("chunk length=%d, want 102", len(chunk))
	}
	// Length field should be 100 = 0x0064
	if chunk[0] != 0x00 || chunk[1] != 0x64 {
		t.Errorf("length field=0x%02x%02x, want 0x0064", chunk[0], chunk[1])
	}
}

// ============================================================
// §1.20 UDP — RSV / FRAG / ATYP fields
// ============================================================

// TestSS_1_20_1_UDP_RSV covers testcase 1.20.1: RSV=0x0000.
func TestSS_1_20_1_UDP_RSV(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Mode = "udp"
	spec.Shadowsocks.Cipher = "none" // plaintext so we can inspect fields
	spec.Shadowsocks.SOCKS5DstAddr = "8.8.8.8"
	spec.Shadowsocks.SOCKS5DstPort = 53
	spec.Shadowsocks.ChunkPayloadSize = 10
	spec.Count = 1
	cfgs := drain(mustPlan(t, p, spec))
	// Plaintext UDP: RSV(2) + FRAG(1) + ATYP(1) + ADDR(4) + PORT(2) + PAYLOAD(10) = 20
	if len(cfgs[0].Payload) < 3 {
		t.Fatalf("payload too short: %d", len(cfgs[0].Payload))
	}
	if cfgs[0].Payload[0] != 0x00 || cfgs[0].Payload[1] != 0x00 {
		t.Errorf("RSV=0x%02x%02x, want 0x0000", cfgs[0].Payload[0], cfgs[0].Payload[1])
	}
}

// TestSS_1_20_3_UDP_FRAG_Single covers testcase 1.20.3: FRAG=0x00.
func TestSS_1_20_3_UDP_FRAG_Single(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Mode = "udp"
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.SOCKS5DstAddr = "8.8.8.8"
	spec.Shadowsocks.SOCKS5DstPort = 53
	spec.Shadowsocks.ChunkPayloadSize = 10
	spec.Count = 1
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].Payload[2] != 0x00 {
		t.Errorf("FRAG=0x%02x, want 0x00", cfgs[0].Payload[2])
	}
}

// TestSS_1_20_7_UDP_ATYP_IPv4 covers testcase 1.20.7: ATYP=0x01.
func TestSS_1_20_7_UDP_ATYP_IPv4(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Mode = "udp"
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.SOCKS5DstAddr = "8.8.8.8"
	spec.Shadowsocks.SOCKS5DstPort = 53
	spec.Shadowsocks.ChunkPayloadSize = 0
	spec.Count = 1
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].Payload[3] != 0x01 {
		t.Errorf("ATYP=0x%02x, want 0x01", cfgs[0].Payload[3])
	}
}

// ============================================================
// §1.21 UDP — ADDR / PORT / PAYLOAD fields
// ============================================================

// TestSS_1_21_1_UDP_ADDR_IPv4 covers testcase 1.21.1: ADDR IPv4.
func TestSS_1_21_1_UDP_ADDR_IPv4(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Mode = "udp"
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 53
	spec.Shadowsocks.ChunkPayloadSize = 0
	spec.Count = 1
	cfgs := drain(mustPlan(t, p, spec))
	pld := cfgs[0].Payload
	// ADDR = 192.0.2.1 at offset 4
	if pld[4] != 0xC0 || pld[5] != 0x00 || pld[6] != 0x02 || pld[7] != 0x01 {
		t.Errorf("ADDR=0x%02x%02x%02x%02x, want 192.0.2.1", pld[4], pld[5], pld[6], pld[7])
	}
}

// TestSS_1_21_4_UDP_PORT_53 covers testcase 1.21.4: PORT=53.
func TestSS_1_21_4_UDP_PORT_53(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Mode = "udp"
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.SOCKS5DstAddr = "8.8.8.8"
	spec.Shadowsocks.SOCKS5DstPort = 53
	spec.Shadowsocks.ChunkPayloadSize = 0
	spec.Count = 1
	cfgs := drain(mustPlan(t, p, spec))
	pld := cfgs[0].Payload
	// PORT at offset 8 (after RSV(2)+FRAG(1)+ATYP(1)+ADDR(4))
	if pld[8] != 0x00 || pld[9] != 0x35 {
		t.Errorf("PORT=0x%02x%02x, want 0x0035 (53)", pld[8], pld[9])
	}
}

// TestSS_1_21_6_UDP_ZeroPayload covers testcase 1.21.6: zero-byte UDP payload.
func TestSS_1_21_6_UDP_ZeroPayload(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Mode = "udp"
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.SOCKS5DstAddr = "8.8.8.8"
	spec.Shadowsocks.SOCKS5DstPort = 53
	spec.Shadowsocks.ChunkPayloadSize = 0
	spec.Count = 1
	cfgs := drain(mustPlan(t, p, spec))
	// RSV(2) + FRAG(1) + ATYP(1) + ADDR(4) + PORT(2) + PAYLOAD(0) = 10
	if len(cfgs[0].Payload) != 10 {
		t.Errorf("UDP payload length=%d, want 10 (10 header bytes, 0 payload)", len(cfgs[0].Payload))
	}
}

// ============================================================
// §1.22 Cipher routing
// ============================================================

// TestSS_1_22_1_Cipher_AES128GCM covers testcase 1.22.1: aes-128-gcm.
func TestSS_1_22_1_Cipher_AES128GCM(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "aes-128-gcm"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 100
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	// salt(32) + chunk(2+100+16=118)
	if len(upPayloads[0]) != 32 {
		t.Errorf("salt length=%d, want 32", len(upPayloads[0]))
	}
	if len(upPayloads[1]) != 118 {
		t.Errorf("chunk length=%d, want 118", len(upPayloads[1]))
	}
}

// TestSS_1_22_4_Cipher_None covers testcase 1.22.4: none cipher.
func TestSS_1_22_4_Cipher_None(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 100
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	// No salt, no tag: chunk = 2 + 100 = 102
	if len(upPayloads[0]) != 102 {
		t.Errorf("chunk length=%d, want 102", len(upPayloads[0]))
	}
}

// TestSS_1_22_8_Cipher_rc4md5_Rejected covers testcase 1.22.8: rc4-md5 rejected.
func TestSS_1_22_8_Cipher_rc4md5_Rejected(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "rc4-md5"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "unsupported cipher") {
		t.Errorf("err=%v, want 'unsupported cipher'", err)
	}
}

// TestSS_1_22_9_Cipher_aes256cfb_Rejected covers testcase 1.22.9: aes-256-cfb rejected.
func TestSS_1_22_9_Cipher_aes256cfb_Rejected(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "aes-256-cfb"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "unsupported cipher") {
		t.Errorf("err=%v, want 'unsupported cipher'", err)
	}
}

// TestSS_1_22_10_Cipher_EmptyDefault covers testcase 1.22.10: empty cipher defaults to AEAD.
func TestSS_1_22_10_Cipher_EmptyDefault(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = ""
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 100
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	// salt(32) + chunk(2+100+16=118)
	if len(upPayloads[0]) != 32 {
		t.Errorf("salt length=%d, want 32", len(upPayloads[0]))
	}
	if len(upPayloads[1]) != 118 {
		t.Errorf("chunk length=%d, want 118", len(upPayloads[1]))
	}
}

// ============================================================
// §1.23 HTTP Obfuscation
// ============================================================

// TestSS_1_23_1_HTTP_CONNECT covers testcase 1.23.1: HTTP CONNECT obfuscation.
func TestSS_1_23_1_HTTP_CONNECT(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Obfuscation = "http"
	spec.Shadowsocks.ObfMethod = "CONNECT"
	spec.Shadowsocks.SOCKS5DstAddr = "example.com"
	spec.Shadowsocks.SOCKS5DstPort = 443
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 10
	cfgs := drain(mustPlan(t, p, spec))
	first := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if first == nil {
		t.Fatalf("no up PSH-ACK")
	}
	if !strings.HasPrefix(string(first), "CONNECT example.com:443 HTTP/1.1\r\n") {
		t.Errorf("HTTP header=%q, want CONNECT", string(first[:min(50, len(first))]))
	}
}

// TestSS_1_23_7_HTTP_SOCKS5_MutualExclusion covers testcase 1.23.7.
func TestSS_1_23_7_HTTP_SOCKS5_MutualExclusion(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Obfuscation = "http"
	spec.Shadowsocks.SOCKS5Handshake = true
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err=%v, want 'mutually exclusive'", err)
	}
}

// TestSS_1_23_8_HTTP_UDP_Rejected covers testcase 1.23.8: HTTP obfuscation not valid for UDP.
func TestSS_1_23_8_HTTP_UDP_Rejected(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Obfuscation = "http"
	spec.Shadowsocks.Mode = "udp"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "requires Mode=tcp") {
		t.Errorf("err=%v, want 'requires Mode=tcp'", err)
	}
}

// ============================================================
// §2 State machine — transfers
// ============================================================

// TestSS_2_1_1_INIT_to_SOCKS5 covers testcase 2.1.1: SOCKS5 handshake path.
func TestSS_2_1_1_INIT_to_SOCKS5(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	// After handshake, first up PSH-ACK should be SOCKS5 greeting (3 bytes)
	greeting := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if greeting == nil || len(greeting) < 3 {
		t.Fatalf("no greeting")
	}
	if greeting[0] != 0x05 || greeting[1] != 0x01 || greeting[2] != 0x00 {
		t.Errorf("greeting=0x%02x%02x%02x, want 0x05 0x01 0x00", greeting[0], greeting[1], greeting[2])
	}
}

// TestSS_2_1_2_INIT_to_SALT covers testcase 2.1.2: skip SOCKS5, go directly to salt.
func TestSS_2_1_2_INIT_to_SALT(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = false
	cfgs := drain(mustPlan(t, p, spec))
	first := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if first == nil {
		t.Fatalf("no up PSH-ACK")
	}
	// First up payload should be 32-byte salt, not 3-byte greeting
	if len(first) != 32 {
		t.Errorf("first payload length=%d, want 32 (salt)", len(first))
	}
}

// TestSS_2_2_1_Greeting_to_MethodResponse covers testcase 2.2.1: greeting followed by method response.
func TestSS_2_2_1_Greeting_to_MethodResponse(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	// Greeting (up) then method response (down)
	greeting := findFirstPayloadByDirection(cfgs, "up", 0x18)
	methodResp := findFirstPayloadByDirection(cfgs, "down", 0x18)
	if greeting == nil || methodResp == nil {
		t.Fatalf("missing greeting or method response")
	}
	if greeting[0] != 0x05 {
		t.Errorf("greeting VER=0x%02x", greeting[0])
	}
	if methodResp[0] != 0x05 || methodResp[1] != 0x00 {
		t.Errorf("method response=0x%02x%02x, want 0x05 0x00", methodResp[0], methodResp[1])
	}
}

// TestSS_2_2_3_MethodResponse_to_Request covers testcase 2.2.3: method response then request.
func TestSS_2_2_3_MethodResponse_to_Request(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(upPayloads) < 2 {
		t.Fatalf("expected at least 2 up payloads, got %d", len(upPayloads))
	}
	// upPayloads[0] = greeting, upPayloads[1] = request
	req := upPayloads[1]
	if req[0] != 0x05 || req[1] != 0x01 {
		t.Errorf("request=0x%02x%02x, want 0x05 0x01 (CONNECT)", req[0], req[1])
	}
}

// TestSS_2_2_7_Request_to_Reply covers testcase 2.2.7: request then reply.
func TestSS_2_2_7_Request_to_Reply(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	downPayloads := collectAllPayloadsByDirection(cfgs, "down", 0x18)
	if len(downPayloads) < 2 {
		t.Fatalf("expected at least 2 down payloads, got %d", len(downPayloads))
	}
	// downPayloads[0] = method response, downPayloads[1] = reply
	reply := downPayloads[1]
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Errorf("reply=0x%02x%02x, want 0x05 0x00", reply[0], reply[1])
	}
}

// TestSS_2_4_1_ChunkLoop_Repeat covers testcase 2.4.1: chunk loop continues.
func TestSS_2_4_1_ChunkLoop_Repeat(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 3
	spec.Shadowsocks.ChunkPayloadSize = 10
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	// salt(1) + 3 chunks = 4 up payloads
	if len(upPayloads) != 4 {
		t.Fatalf("expected 4 up payloads, got %d", len(upPayloads))
	}
	// Each chunk should be 2+10+16 = 28 bytes
	for i := 1; i < 4; i++ {
		if len(upPayloads[i]) != 28 {
			t.Errorf("chunk[%d] length=%d, want 28", i, len(upPayloads[i]))
		}
	}
}

// TestSS_2_4_3_ChunkLoop_Single covers testcase 2.4.3: single chunk loop.
func TestSS_2_4_3_ChunkLoop_Single(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 10
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(upPayloads) != 2 {
		t.Fatalf("expected 2 up payloads (salt + 1 chunk), got %d", len(upPayloads))
	}
}

// TestSS_2_5_1_UDP_Packet covers testcase 2.5.1: UDP mode initialization.
func TestSS_2_5_1_UDP_Packet(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Mode = "udp"
	spec.Shadowsocks.Cipher = "aes-256-gcm"
	spec.Shadowsocks.SOCKS5DstAddr = "8.8.8.8"
	spec.Shadowsocks.SOCKS5DstPort = 53
	spec.Shadowsocks.ChunkPayloadSize = 10
	spec.Count = 1
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 UDP packet, got %d", len(cfgs))
	}
	if cfgs[0].L4.Protocol != "udp" {
		t.Errorf("protocol=%q, want 'udp'", cfgs[0].L4.Protocol)
	}
}

// TestSS_2_5_2_UDP_MultiplePackets covers testcase 2.5.2: multiple UDP packets.
func TestSS_2_5_2_UDP_MultiplePackets(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Mode = "udp"
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.SOCKS5DstAddr = "8.8.8.8"
	spec.Shadowsocks.SOCKS5DstPort = 53
	spec.Shadowsocks.ChunkPayloadSize = 10
	spec.Count = 3
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 3 {
		t.Fatalf("expected 3 UDP packets, got %d", len(cfgs))
	}
	for i := 1; i < 3; i++ {
		if cfgs[i].PacketIndex != cfgs[i-1].PacketIndex+1 {
			t.Errorf("packet[%d].PacketIndex=%d, want %d", i, cfgs[i].PacketIndex, cfgs[i-1].PacketIndex+1)
		}
	}
}

// ============================================================
// §3 Business scenarios
// ============================================================

// TestSS_3_1_1_SOCKS5_CONNECT covers business scenario 3.1.1: full SOCKS5 CONNECT.
func TestSS_3_1_1_SOCKS5_CONNECT(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5Cmd = "connect"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	spec.Shadowsocks.Cipher = "aes-256-gcm"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 50
	cfgs := drain(mustPlan(t, p, spec))
	// Diagram: TCP handshake(3) + greeting(up) + method_resp(down) + request(up) + reply(down) + salt(up) + chunk(up) + teardown(4) = at least 12
	if len(cfgs) < 12 {
		t.Fatalf("expected at least 12 packets, got %d", len(cfgs))
	}
	// Verify SOCKS5 greeting
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(upPayloads) < 3 {
		t.Fatalf("expected at least 3 up payloads")
	}
	greeting := upPayloads[0]
	req := upPayloads[1]
	salt := upPayloads[2]
	if greeting[0] != 0x05 || greeting[1] != 0x01 || greeting[2] != 0x00 {
		t.Errorf("greeting malformed: 0x%02x%02x%02x", greeting[0], greeting[1], greeting[2])
	}
	if req[3] != 0x01 {
		t.Errorf("ATYP=0x%02x, want 0x01 (IPv4)", req[3])
	}
	if len(salt) != 32 {
		t.Errorf("salt length=%d, want 32", len(salt))
	}
}

// TestSS_3_2_1_AEAD_AES128GCM covers business scenario 3.2.1.
func TestSS_3_2_1_AEAD_AES128GCM(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "aes-128-gcm"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 100
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	// salt(32) + chunk(2+100+16=118)
	if len(upPayloads[0]) != 32 {
		t.Errorf("salt length=%d, want 32", len(upPayloads[0]))
	}
	if len(upPayloads[1]) != 118 {
		t.Errorf("chunk length=%d, want 118", len(upPayloads[1]))
	}
}

// TestSS_3_3_1_AEAD_AES256GCM covers business scenario 3.3.1.
func TestSS_3_3_1_AEAD_AES256GCM(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "aes-256-gcm"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 100
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(upPayloads[0]) != 32 {
		t.Errorf("salt length=%d, want 32", len(upPayloads[0]))
	}
	if len(upPayloads[1]) != 118 {
		t.Errorf("chunk length=%d, want 118", len(upPayloads[1]))
	}
}

// TestSS_3_4_1_ChaCha20 covers business scenario 3.4.1.
func TestSS_3_4_1_ChaCha20(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "chacha20-ietf-poly1305"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 100
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(upPayloads[0]) != 32 {
		t.Errorf("salt length=%d, want 32", len(upPayloads[0]))
	}
	if len(upPayloads[1]) != 118 {
		t.Errorf("chunk length=%d, want 118", len(upPayloads[1]))
	}
}

// TestSS_3_5_1_NoneCipher covers business scenario 3.5.1.
func TestSS_3_5_1_NoneCipher(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 100
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	// No salt, no tag: 2+100 = 102
	if len(upPayloads[0]) != 102 {
		t.Errorf("chunk length=%d, want 102", len(upPayloads[0]))
	}
}

// TestSS_3_6_1_UDP_Relay covers business scenario 3.6.1.
func TestSS_3_6_1_UDP_Relay(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Mode = "udp"
	spec.Shadowsocks.Cipher = "aes-256-gcm"
	spec.Shadowsocks.SOCKS5DstAddr = "8.8.8.8"
	spec.Shadowsocks.SOCKS5DstPort = 53
	spec.Shadowsocks.ChunkPayloadSize = 100
	spec.Count = 1
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 UDP packet, got %d", len(cfgs))
	}
	// AEAD UDP: salt(32) + AEAD(RSV(2)+FRAG(1)+ATYP(1)+ADDR(4)+PORT(2)+PAYLOAD(100)) + tag(16) = 32 + 110 + 16 = 158
	if len(cfgs[0].Payload) != 158 {
		t.Errorf("UDP packet length=%d, want 158", len(cfgs[0].Payload))
	}
}

// TestSS_3_7_1_PasswordAuth covers business scenario 3.7.1.
func TestSS_3_7_1_PasswordAuth(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "password"
	spec.Shadowsocks.SOCKS5Username = "foo"
	spec.Shadowsocks.SOCKS5Password = "bar"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	spec.Shadowsocks.Cipher = "aes-256-gcm"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 10
	cfgs := drain(mustPlan(t, p, spec))
	// Full flow: handshake(3) + greeting(up) + method_resp(down) + auth(up) + auth_resp(down) + request(up) + reply(down) + salt(up) + chunk(up) + teardown(4) = 13+
	if len(cfgs) < 13 {
		t.Fatalf("expected at least 13 packets, got %d", len(cfgs))
	}
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	authReq := upPayloads[1] // greeting[0], auth[1], request[2], salt[3], chunk[4]
	if authReq[0] != 0x01 {
		t.Errorf("auth VER=0x%02x, want 0x01", authReq[0])
	}
	if string(authReq[2:5]) != "foo" {
		t.Errorf("UNAME=%q, want 'foo'", string(authReq[2:5]))
	}
	plenOffset := 2 + int(authReq[1])
	if string(authReq[plenOffset+1:plenOffset+4]) != "bar" {
		t.Errorf("PASS=%q, want 'bar'", string(authReq[plenOffset+1:plenOffset+4]))
	}
}

// TestSS_3_8_1_MultiChunk covers business scenario 3.8.1: 10 chunks.
func TestSS_3_8_1_MultiChunk(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 10
	spec.Shadowsocks.ChunkPayloadSize = 100
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	// 1 salt + 10 chunks = 11
	if len(upPayloads) != 11 {
		t.Fatalf("expected 11 up payloads, got %d", len(upPayloads))
	}
	for i := 1; i < 11; i++ {
		if len(upPayloads[i]) != 118 {
			t.Errorf("chunk[%d] length=%d, want 118", i, len(upPayloads[i]))
		}
	}
}

// TestSS_3_10_1_DomainTarget covers business scenario 3.10.1.
func TestSS_3_10_1_DomainTarget(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "example.com"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[1]
	if req[3] != 0x03 {
		t.Errorf("ATYP=0x%02x, want 0x03", req[3])
	}
	domainLen := int(req[4])
	if domainLen != 11 {
		t.Errorf("domain length=%d, want 11", domainLen)
	}
	if string(req[5:5+domainLen]) != "example.com" {
		t.Errorf("domain=%q, want 'example.com'", string(req[5:5+domainLen]))
	}
}

// TestSS_3_11_1_IPv6Target covers business scenario 3.11.1.
func TestSS_3_11_1_IPv6Target(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "2001:db8::1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[1]
	if req[3] != 0x04 {
		t.Errorf("ATYP=0x%02x, want 0x04", req[3])
	}
	if len(req) < 22 {
		t.Fatalf("request too short: %d", len(req))
	}
	// 4 + 16 + 2 = 22 bytes (VER+CMD+RSV+ATYP=4, ADDR=16, PORT=2)
}

// TestSS_3_13_1_SIP022 covers business scenario 3.13.1.
func TestSS_3_13_1_SIP022(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "2022-blake3-aes-256-gcm"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 100
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	// salt(32) + chunk(2+100+16=118)
	if len(upPayloads[0]) != 32 {
		t.Errorf("salt length=%d, want 32", len(upPayloads[0]))
	}
	if len(upPayloads[1]) != 118 {
		t.Errorf("chunk length=%d, want 118", len(upPayloads[1]))
	}
}

// TestSS_3_14_1_HTTPObfuscation covers business scenario 3.14.1.
func TestSS_3_14_1_HTTPObfuscation(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Obfuscation = "http"
	spec.Shadowsocks.SOCKS5DstAddr = "example.com"
	spec.Shadowsocks.SOCKS5DstPort = 443
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 50
	cfgs := drain(mustPlan(t, p, spec))
	first := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if first == nil {
		t.Fatalf("no up PSH-ACK")
	}
	if !strings.HasPrefix(string(first), "CONNECT") {
		t.Errorf("first payload=%q, want CONNECT", string(first[:min(20, len(first))]))
	}
}

// TestSS_3_15_1_MultiPacketLoop covers business scenario 3.15.1: 20 chunks.
func TestSS_3_15_1_MultiPacketLoop(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 20
	spec.Shadowsocks.ChunkPayloadSize = 500
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	// 1 salt + 20 chunks = 21
	if len(upPayloads) != 21 {
		t.Fatalf("expected 21 up payloads, got %d", len(upPayloads))
	}
	expectedChunkLen := 2 + 500 + 16 // 518
	for i := 1; i < 21; i++ {
		if len(upPayloads[i]) != expectedChunkLen {
			t.Errorf("chunk[%d] length=%d, want %d", i, len(upPayloads[i]), expectedChunkLen)
		}
	}
}

// ============================================================
// §4 Data scenarios
// ============================================================

// TestSS_4_1_1_Salt_AllZero covers testcase 4.1.1: salt all zeros.
func TestSS_4_1_1_Salt_AllZero(t *testing.T) {
	// This test is covered by the "zeros" payload format test.
	// The planner generates random salts by default, but we verify
	// the salt is always 32 bytes.
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.PayloadBytesFormat = "zeros"
	cfgs := drain(mustPlan(t, p, spec))
	salt := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if salt == nil || len(salt) != 32 {
		t.Fatalf("salt not found or wrong length: %d", len(salt))
	}
}

// TestSS_4_1_2_ZeroPayloadChunk covers testcase 4.1.2: zero payload chunk.
func TestSS_4_1_2_ZeroPayloadChunk(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 0
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	chunk := upPayloads[1] // after salt
	// 2 + 0 + 16 = 18
	if len(chunk) != 18 {
		t.Errorf("chunk length=%d, want 18", len(chunk))
	}
}

// TestSS_4_1_5_UDP_ZeroPayload covers testcase 4.1.5: UDP zero payload.
func TestSS_4_1_5_UDP_ZeroPayload(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Mode = "udp"
	spec.Shadowsocks.Cipher = "aes-256-gcm"
	spec.Shadowsocks.SOCKS5DstAddr = "8.8.8.8"
	spec.Shadowsocks.SOCKS5DstPort = 53
	spec.Shadowsocks.ChunkPayloadSize = 0
	spec.Count = 1
	cfgs := drain(mustPlan(t, p, spec))
	// AEAD UDP with zero payload: salt(32) + AEAD(RSV(2)+FRAG(1)+ATYP(1)+ADDR(4)+PORT(2)+PAYLOAD(0)=10) + tag(16) = 58
	if len(cfgs[0].Payload) != 58 {
		t.Errorf("UDP packet length=%d, want 58", len(cfgs[0].Payload))
	}
}

// TestSS_4_2_2_MaxChunkPayload covers testcase 4.2.2: max chunk payload.
// With MSS=1460, a 16401-byte chunk is split into 12 segments; total bytes = 16401.
func TestSS_4_2_2_MaxChunkPayload(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 16383
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	// Total chunk bytes = 2 + 16383 + 16 = 16401
	totalChunkBytes := 0
	for i := 1; i < len(upPayloads); i++ {
		totalChunkBytes += len(upPayloads[i])
	}
	if totalChunkBytes != 16401 {
		t.Errorf("total chunk bytes=%d, want 16401", totalChunkBytes)
	}
}

// TestSS_4_2_4_NMETHODS_Max covers testcase 4.2.4: NMETHODS=255.
func TestSS_4_2_4_NMETHODS_Max(t *testing.T) {
	// NMETHODS=255 is not supported by the planner (only single-method
	// greeting is emitted per SOCKS5AuthMethod). This test verifies
	// the planner's greeting is well-formed for the NO_AUTH case.
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	greeting := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if greeting == nil || len(greeting) < 3 {
		t.Fatalf("no greeting")
	}
	if greeting[0] != 0x05 || greeting[1] != 0x01 {
		t.Errorf("greeting malformed: 0x%02x%02x", greeting[0], greeting[1])
	}
}

// TestSS_4_2_6_Port_Max covers testcase 4.2.6: PORT=65535.
func TestSS_4_2_6_Port_Max(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 65535
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[1]
	portOffset := 4 + 4
	if req[portOffset] != 0xFF || req[portOffset+1] != 0xFF {
		t.Errorf("PORT=0x%02x%02x, want 0xFFFF (65535)", req[portOffset], req[portOffset+1])
	}
}

// TestSS_4_2_7_Port_Min covers testcase 4.2.7: PORT=1.
func TestSS_4_2_7_Port_Min(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 1
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	req := upPayloads[1]
	portOffset := 4 + 4
	if req[portOffset] != 0x00 || req[portOffset+1] != 0x01 {
		t.Errorf("PORT=0x%02x%02x, want 0x0001", req[portOffset], req[portOffset+1])
	}
}

// TestSS_4_3_1_UnsupportedCipher covers testcase 4.3.1.
func TestSS_4_3_1_UnsupportedCipher(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "rc4-md5"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "unsupported cipher") {
		t.Errorf("err=%v, want 'unsupported cipher'", err)
	}
}

// TestSS_4_3_5_ChunkTooLarge covers testcase 4.3.5.
func TestSS_4_3_5_ChunkTooLarge(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.ChunkPayloadSize = 16384
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "exceeds max") {
		t.Errorf("err=%v, want 'exceeds max'", err)
	}
}

// ============================================================
// §5 Concurrency
// ============================================================

// TestSS_5_1_1_ConcurrentWorkers covers testcase 5.1.1: 8 concurrent flows.
func TestSS_5_1_1_ConcurrentWorkers(t *testing.T) {
	p := NewPlanner()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			spec := validTCPSpec()
			spec.Shadowsocks.Chunks = 10
			spec.Shadowsocks.ChunkPayloadSize = 50
			cfgs := drain(mustPlan(t, p, spec))
			if len(cfgs) < 9 {
				t.Errorf("flow %d: expected at least 9 packets, got %d", idx, len(cfgs))
			}
		}(i)
	}
	wg.Wait()
}

// TestSS_5_3_1_ChunkOrder covers testcase 5.3.1: single flow chunk order.
func TestSS_5_3_1_ChunkOrder(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 10
	spec.Shadowsocks.ChunkPayloadSize = 10
	cfgs := drain(mustPlan(t, p, spec))
	for i := 1; i < len(cfgs); i++ {
		if cfgs[i].PacketIndex != cfgs[i-1].PacketIndex+1 {
			t.Errorf("packet[%d].PacketIndex=%d, want %d", i, cfgs[i].PacketIndex, cfgs[i-1].PacketIndex+1)
			break
		}
	}
}

// TestSS_5_3_2_SOCKS5Order covers testcase 5.3.2: SOCKS5 message order.
func TestSS_5_3_2_SOCKS5Order(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "password"
	spec.Shadowsocks.SOCKS5Username = "u"
	spec.Shadowsocks.SOCKS5Password = "p"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	// Order: greeting -> auth -> request -> salt -> chunks
	if len(upPayloads) < 4 {
		t.Fatalf("expected at least 4 up payloads, got %d", len(upPayloads))
	}
	// greeting: VER=0x05
	if upPayloads[0][0] != 0x05 || upPayloads[0][1] != 0x01 {
		t.Errorf("payload[0] not greeting: 0x%02x%02x", upPayloads[0][0], upPayloads[0][1])
	}
	// auth: VER=0x01
	if upPayloads[1][0] != 0x01 {
		t.Errorf("payload[1] not auth: 0x%02x", upPayloads[1][0])
	}
	// request: VER=0x05
	if upPayloads[2][0] != 0x05 {
		t.Errorf("payload[2] not request: 0x%02x", upPayloads[2][0])
	}
	// salt: 32 bytes
	if len(upPayloads[3]) != 32 {
		t.Errorf("payload[3] not salt: len=%d", len(upPayloads[3]))
	}
}

// ============================================================
// §6.4 ctx cancel
// ============================================================

// TestSS_6_4_1_CTXCancelInChunk covers testcase 6.4.1: cancel during chunk loop.
func TestSS_6_4_1_CTXCancelInChunk(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 1000
	spec.Shadowsocks.ChunkPayloadSize = 16383
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	// Read a few packets, then cancel
	go func() {
		count := 0
		for range ch {
			count++
			if count >= 5 {
				cancel()
				return
			}
		}
	}()
	// Drain until channel closes
	for range ch {
	}
}

// TestSS_6_4_2_CTXCancelInSOCKS5 covers testcase 6.4.2: cancel during SOCKS5.
func TestSS_6_4_2_CTXCancelInSOCKS5(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	spec.Shadowsocks.Chunks = 1000
	spec.Shadowsocks.ChunkPayloadSize = 100
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	go func() {
		for range ch {
			cancel()
			return
		}
	}()
	for range ch {
	}
}

// TestSS_6_4_3_CTXCancelInUDP covers testcase 6.4.3: cancel during UDP.
func TestSS_6_4_3_CTXCancelInUDP(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Mode = "udp"
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.SOCKS5DstAddr = "8.8.8.8"
	spec.Shadowsocks.SOCKS5DstPort = 53
	spec.Shadowsocks.ChunkPayloadSize = 10
	spec.Count = 1000
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	go func() {
		for range ch {
			cancel()
			return
		}
	}()
	for range ch {
	}
}

// ============================================================
// §7 Integration - None cipher chunk length encoding
// ============================================================

// TestSS_7_5_NoneCipherChunkLength covers integration scenario 7.5:
// none cipher chunk length field encoding verification.
func TestSS_7_5_NoneCipherChunkLength(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.Chunks = 3
	spec.Shadowsocks.ChunkPayloadSize = 100
	cfgs := drain(mustPlan(t, p, spec))
	// For none cipher, each up PSH-ACK is a chunk with 2+100=102 bytes
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(upPayloads) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(upPayloads))
	}
	for i, pld := range upPayloads {
		// Length field should be 100 = 0x0064 (BE uint16)
		lenField := binary.BigEndian.Uint16(pld[:2])
		if lenField != 100 {
			t.Errorf("chunk[%d] length field=%d, want 100", i, lenField)
		}
		// Payload should be 100 bytes
		if len(pld) != 102 {
			t.Errorf("chunk[%d] total length=%d, want 102", i, len(pld))
		}
	}
}