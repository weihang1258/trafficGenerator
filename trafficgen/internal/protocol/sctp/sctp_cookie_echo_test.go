package sctp

// D-SCTP-1 隔离复审 F2（2026-09-21）：COOKIE-ECHO 必须逐字节回显 INIT-ACK
// 携带的 Cookie（RFC 4960 §5.2.1/§5.2.2）。此前全库无此断言（复审实证
// "legacy 单测钉" 声明失实）——本测试补钉。cookie 每关联随机，但回显
// 一致性是确定性契约。

import (
	"bytes"
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestPlanCookieEchoMatchesINITACK(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 12345, DstPort: 5000,
		SCTP: &core.SCTPConfig{},
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var initAck, cookieEcho []byte
	i := 0
	for pkt := range ch {
		switch i {
		case 1: // INIT-ACK
			initAck = pkt.Payload
		case 2: // COOKIE-ECHO
			cookieEcho = pkt.Payload
		}
		i++
	}
	if len(initAck) < 56 || len(cookieEcho) < 36 {
		t.Fatalf("short handshake payloads: initAck=%d cookieEcho=%d", len(initAck), len(cookieEcho))
	}
	// INIT-ACK chunk：[0:4] 头 + [4:20] 固定面 + [20:24] cookie 参数头
	// (type 7, len 36) + [24:56] cookie 32B。COOKIE-ECHO chunk：[0:4] 头
	// + [4:36] cookie 32B。
	cookie := initAck[24:56]
	if !bytes.Equal(cookie, cookieEcho[4:36]) {
		t.Fatalf("COOKIE-ECHO does not echo INIT-ACK cookie:\n init-ack: %x\n echo:    %x", cookie, cookieEcho[4:36])
	}
	// 参数头：type 7（Cookie Param, RFC 4960 §3.3.2.1）+ len 36。
	if initAck[20] != 0 || initAck[21] != 7 || initAck[22] != 0 || initAck[23] != 36 {
		t.Fatalf("INIT-ACK cookie param header = %x, want 0007 0024", initAck[20:24])
	}
	if cookieEcho[0] != 10 || cookieEcho[2] != 0 || cookieEcho[3] != 36 {
		t.Fatalf("COOKIE-ECHO header = %x, want 0a 00 00 24", cookieEcho[:4])
	}
}
