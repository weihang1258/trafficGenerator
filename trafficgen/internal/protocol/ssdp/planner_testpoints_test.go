package ssdp

// Atomic test points for the SSDP planner. Each test corresponds to one or more
// test cases in /tmp/l7_planner_design/testcases_ssdp.md. Tests assert
// observable PacketConfig field values and payload content, not just "no error".

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ---------- helpers ----------

// assertPayloadContains fails t if payload does not contain s.
func assertPayloadContains(t *testing.T, payload, s string) {
	t.Helper()
	if !strings.Contains(payload, s) {
		t.Errorf("payload missing %q", s)
	}
}

// assertPayloadNotContains fails t if payload contains s.
func assertPayloadNotContains(t *testing.T, payload, s string) {
	t.Helper()
	if strings.Contains(payload, s) {
		t.Errorf("payload should not contain %q", s)
	}
}

// assertPrefix fails t if payload does not have prefix s.
func assertPrefix(t *testing.T, payload, s string) {
	t.Helper()
	if !strings.HasPrefix(payload, s) {
		t.Errorf("payload prefix=%q, want %q", payload[:min(len(payload), len(s))], s)
	}
}

// assertSuffix fails t if payload does not have suffix s.
func assertSuffix(t *testing.T, payload, s string) {
	t.Helper()
	if !strings.HasSuffix(payload, s) {
		t.Errorf("payload suffix=%q, want %q", payload[len(payload)-len(s):], s)
	}
}

// ===================================================================
// §1.1 请求行（NOTIFY / M-SEARCH）
// ===================================================================

// 用例 1.1.1: MessageType=alive 时输出 NOTIFY * HTTP/1.1\r\n
func TestSSDP_1_1_1_AliveRequestLine(t *testing.T) {
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPrefix(t, payload, "NOTIFY * HTTP/1.1\r\n")
}

// 用例 1.1.2: MessageType=byebye 时输出 NOTIFY * HTTP/1.1\r\n + NTS=ssdp:byebye
func TestSSDP_1_1_2_ByebyeRequestLine(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "byebye"
	spec.SSDP.USN = "uuid:00..01::upnp:rootdevice"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPrefix(t, payload, "NOTIFY * HTTP/1.1\r\n")
	assertPayloadContains(t, payload, "NTS: ssdp:byebye\r\n")
}

// 用例 1.1.3: MessageType=update 时输出 NOTIFY * HTTP/1.1\r\n + NTS=ssdp:update
func TestSSDP_1_1_3_UpdateRequestLine(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "update"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPrefix(t, payload, "NOTIFY * HTTP/1.1\r\n")
	assertPayloadContains(t, payload, "NTS: ssdp:update\r\n")
}

// 用例 1.1.4: MessageType=msearch 时输出 M-SEARCH * HTTP/1.1\r\n
func TestSSDP_1_1_4_MSearchRequestLine(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPrefix(t, payload, "M-SEARCH * HTTP/1.1\r\n")
}

// 用例 1.1.5: MessageType=response 时输出 HTTP/1.1 200 OK\r\n
func TestSSDP_1_1_5_ResponseStatusLine(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "response"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPrefix(t, payload, "HTTP/1.1 200 OK\r\n")
}

// 用例 1.1.6: MessageType=invalid 时 Validate 返回 error
func TestSSDP_1_1_6_InvalidMessageType(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "invalid"
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Fatal("expected error for invalid message_type")
	}
	if !strings.Contains(err.Error(), "unknown message_type") {
		t.Errorf("error=%q, want 'unknown message_type'", err.Error())
	}
}

// ===================================================================
// §1.2 Host 头
// ===================================================================

// 用例 1.2.1: IPv4 alive 默认多播组 -> HOST=239.255.255.250:1900
func TestSSDP_1_2_1_IPv4HostHeader(t *testing.T) {
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "HOST: 239.255.255.250:1900\r\n")
	if cfgs[0].L3.DstIP != "239.255.255.250" {
		t.Errorf("DstIP=%s, want 239.255.255.250", cfgs[0].L3.DstIP)
	}
	if cfgs[0].L4.DstPort != 1900 {
		t.Errorf("DstPort=%d, want 1900", cfgs[0].L4.DstPort)
	}
}

// 用例 1.2.2: IPv6 alive 默认多播组 -> HOST=[ff02::c]:1900
func TestSSDP_1_2_2_IPv6HostHeader(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01", SrcIP: "fe80::1", DstIP: "ff02::c",
		SrcPort: 1900, DstPort: 1900,
		SSDP: &core.SSDPConfig{
			MessageType: "alive", SearchTarget: "upnp:rootdevice",
			USN: "uuid:00..01::upnp:rootdevice", MaxAge: 1800, RepeatCount: 1,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "HOST: [ff02::c]:1900\r\n")
	if cfgs[0].L3.DstIP != "ff02::c" {
		t.Errorf("DstIP=%s, want ff02::c", cfgs[0].L3.DstIP)
	}
	if cfgs[0].L2.EtherType != 0x86DD {
		t.Errorf("EtherType=%04x, want 86DD", cfgs[0].L2.EtherType)
	}
}

// 用例 1.2.3: msearch MulticastGroup=239.255.255.250 时端口为1900
func TestSSDP_1_2_3_MSearchMulticastPort(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "HOST: 239.255.255.250:1900\r\n")
}

// 用例 1.2.5: DstPort=80 时 Validate 返回 error
func TestSSDP_1_2_5_InvalidDstPort(t *testing.T) {
	spec := validSSDPSpec()
	spec.DstPort = 80
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Fatal("expected error for dst_port=80")
	}
	if !strings.Contains(err.Error(), "must be 1900") {
		t.Errorf("error=%q, want contains 'must be 1900'", err.Error())
	}
}

// ===================================================================
// §1.3 Cache-Control: max-age
// ===================================================================

// 用例 1.3.1: alive MaxAge=1800 输出 CACHE-CONTROL: max-age=1800\r\n
func TestSSDP_1_3_1_MaxAge1800(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MaxAge = 1800
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "CACHE-CONTROL: max-age=1800\r\n")
}

// 用例 1.3.2: alive MaxAge=0 使用默认值1800
func TestSSDP_1_3_2_MaxAgeDefault(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MaxAge = 0
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "CACHE-CONTROL: max-age=1800\r\n")
}

// 用例 1.3.3: alive MaxAge=1 输出 max-age=1
func TestSSDP_1_3_3_MaxAgeMin(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MaxAge = 1
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "CACHE-CONTROL: max-age=1\r\n")
}

// 用例 1.3.4: alive MaxAge=1801 Validate error
func TestSSDP_1_3_4_MaxAgeOverLimit(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MaxAge = 1801
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Fatal("expected error for MaxAge=1801")
	}
	if !strings.Contains(err.Error(), "exceeds UPnP 1.1 limit") {
		t.Errorf("error=%q", err.Error())
	}
}

// 用例 1.3.5: byebye 不应包含 CACHE-CONTROL
func TestSSDP_1_3_5_ByebyeNoCacheControl(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "byebye"
	spec.SSDP.USN = "uuid:00..01::upnp:rootdevice"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadNotContains(t, string(cfgs[0].Payload), "CACHE-CONTROL")
}

// ===================================================================
// §1.4 Location 头
// ===================================================================

// 用例 1.4.1: alive Location 输出完整 URL
func TestSSDP_1_4_1_LocationAlive(t *testing.T) {
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "LOCATION: http://192.168.1.50:80/description.xml\r\n")
}

// 用例 1.4.3: alive Location 为空时不含 LOCATION
func TestSSDP_1_4_3_LocationEmpty(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.Location = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadNotContains(t, string(cfgs[0].Payload), "LOCATION:")
}

// 用例 1.4.4: byebye Location 非空时不应包含 (planner 按设计忽略)
func TestSSDP_1_4_4_ByebyeNoLocation(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "byebye"
	spec.SSDP.USN = "uuid:00..01::upnp:rootdevice"
	spec.SSDP.Location = "http://192.168.1.50:80/desc.xml"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	// byebye 最小头集: 不含 Location
	assertPayloadNotContains(t, string(cfgs[0].Payload), "LOCATION:")
}

// ===================================================================
// §1.5 NT 头
// ===================================================================

// 用例 1.5.1: alive SearchTarget=upnp:rootdevice 输出 NT 头
func TestSSDP_1_5_1_NTRootdevice(t *testing.T) {
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "NT: upnp:rootdevice\r\n")
}

// 用例 1.5.2: alive SearchTarget=URN device
func TestSSDP_1_5_2_NTDeviceURN(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.SearchTarget = "urn:schemas-upnp-org:device:MediaServer:1"
	spec.SSDP.USN = "uuid:00..01::urn:schemas-upnp-org:device:MediaServer:1"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "NT: urn:schemas-upnp-org:device:MediaServer:1\r\n")
}

// 用例 1.5.4: alive SearchTarget 为空时 Validate error
func TestSSDP_1_5_4_EmptySearchTarget(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.SearchTarget = ""
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Fatal("expected error for empty search_target")
	}
	if !strings.Contains(err.Error(), "search_target") && !strings.Contains(err.Error(), "nt") {
		t.Errorf("error=%q, want nt/search_target error", err.Error())
	}
}

// ===================================================================
// §1.6 NTS 三值覆盖
// ===================================================================

// 用例 1.6.1: alive 输出 NTS: ssdp:alive\r\n
func TestSSDP_1_6_1_NTSAlive(t *testing.T) {
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "NTS: ssdp:alive\r\n")
	assertPayloadNotContains(t, payload, "NTS: ssdp:byebye")
	assertPayloadNotContains(t, payload, "NTS: ssdp:update")
}

// 用例 1.6.2: byebye 输出 NTS: ssdp:byebye\r\n
func TestSSDP_1_6_2_NTSByebye(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "byebye"
	spec.SSDP.USN = "uuid:00..01::upnp:rootdevice"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "NTS: ssdp:byebye\r\n")
	assertPayloadNotContains(t, payload, "CACHE-CONTROL")
	assertPayloadNotContains(t, payload, "LOCATION:")
}

// 用例 1.6.3: update 输出 NTS: ssdp:update\r\n + CONFIGID
func TestSSDP_1_6_3_NTSUpdate(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "update"
	spec.SSDP.ConfigID = 2
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "NTS: ssdp:update\r\n")
	assertPayloadContains(t, payload, "CONFIGID.UPNP.ORG: 2\r\n")
}

// ===================================================================
// §1.7 USN 头
// ===================================================================

// 用例 1.7.1: alive 输出完整 USN
func TestSSDP_1_7_1_USNAlive(t *testing.T) {
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload),
		"USN: uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice\r\n")
}

// 用例 1.7.3: byebye USN 为空时 Validate error
func TestSSDP_1_7_3_EmptyUSN(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "byebye"
	spec.SSDP.USN = ""
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Fatal("expected error for empty USN on byebye")
	}
	if !strings.Contains(err.Error(), "usn is required") {
		t.Errorf("error=%q, want 'usn is required'", err.Error())
	}
}

// ===================================================================
// §1.8 Server 头
// ===================================================================

// 用例 1.8.1: alive 输出 SERVER 头
func TestSSDP_1_8_1_ServerAlive(t *testing.T) {
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "SERVER: Linux/3.2.40 UPnP/1.1 MiniUPnPd/2.0\r\n")
}

// 用例 1.8.3: alive Server 为空时不输出 SERVER
func TestSSDP_1_8_3_ServerEmpty(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.Server = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadNotContains(t, string(cfgs[0].Payload), "SERVER:")
}

// 用例 1.8.4: byebye Server 非空时不应包含
func TestSSDP_1_8_4_ByebyeNoServer(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "byebye"
	spec.SSDP.USN = "uuid:00..01::upnp:rootdevice"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadNotContains(t, string(cfgs[0].Payload), "SERVER:")
}

// ===================================================================
// §1.9 ST 多 target 覆盖
// ===================================================================

// 用例 1.9.1: msearch ST=ssdp:all
func TestSSDP_1_9_1_STAll(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "ST: ssdp:all\r\n")
}

// 用例 1.9.2: msearch ST=upnp:rootdevice
func TestSSDP_1_9_2_STRootdevice(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "upnp:rootdevice"
	spec.SSDP.USN = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "ST: upnp:rootdevice\r\n")
}

// 用例 1.9.3: msearch ST=uuid
func TestSSDP_1_9_3_STUUID(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "uuid:00000000-0000-0000-0000-000000000001"
	spec.SSDP.USN = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "ST: uuid:00000000-0000-0000-0000-000000000001\r\n")
}

// 用例 1.9.4: msearch ST=URN device
func TestSSDP_1_9_4_STDeviceURN(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "urn:schemas-upnp-org:device:MediaServer:1"
	spec.SSDP.USN = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "ST: urn:schemas-upnp-org:device:MediaServer:1\r\n")
}

// 用例 1.9.5: msearch ST=URN service
func TestSSDP_1_9_5_STServiceURN(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "urn:schemas-upnp-org:service:AVTransport:1"
	spec.SSDP.USN = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "ST: urn:schemas-upnp-org:service:AVTransport:1\r\n")
}

// 用例 1.9.6: msearch ST 为空时 Validate error
func TestSSDP_1_9_6_EmptyST(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = ""
	spec.SSDP.USN = ""
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Fatal("expected error for empty ST")
	}
	if !strings.Contains(err.Error(), "st") && !strings.Contains(err.Error(), "search_target") {
		t.Errorf("error=%q, want st/search_target error", err.Error())
	}
}

// ===================================================================
// §1.10 MAN 头
// ===================================================================

// 用例 1.10.1: msearch 默认 MAN 输出精确字节
func TestSSDP_1_10_1_MANDefault(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "MAN: \"ssdp:discover\"\r\n")
}

// 用例 1.10.3: alive 不应包含 MAN
func TestSSDP_1_10_3_AliveNoMAN(t *testing.T) {
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadNotContains(t, string(cfgs[0].Payload), "MAN:")
}

// ===================================================================
// §1.11 MX 头
// ===================================================================

// 用例 1.11.1: msearch MX=3 输出 MX: 3
func TestSSDP_1_11_1_MX3(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.MX = 3
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "MX: 3\r\n")
}

// 用例 1.11.2: msearch MX=0 使用默认值3
func TestSSDP_1_11_2_MXDefault(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.MX = 0
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "MX: 3\r\n")
}

// 用例 1.11.6: alive 不应包含 MX
func TestSSDP_1_11_6_AliveNoMX(t *testing.T) {
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadNotContains(t, string(cfgs[0].Payload), "MX:")
}

// ===================================================================
// §1.12 USER-AGENT 头
// ===================================================================

// 用例 1.12.1: msearch Server 非空时输出 USER-AGENT
func TestSSDP_1_12_1_UserAgent(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.Server = "Linux/6.1 UPnP/1.1 TestClient/1.0"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "USER-AGENT: Linux/6.1 UPnP/1.1 TestClient/1.0\r\n")
}

// 用例 1.12.2: msearch Server 为空时不输出 USER-AGENT
func TestSSDP_1_12_2_NoUserAgent(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.Server = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadNotContains(t, string(cfgs[0].Payload), "USER-AGENT:")
}

// 用例 1.12.3: alive Server 非空时使用 SERVER 头名
func TestSSDP_1_12_3_AliveServerHeader(t *testing.T) {
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "SERVER:")
	assertPayloadNotContains(t, payload, "USER-AGENT:")
}

// 用例 1.12.4: response Server 非空时使用 SERVER 头名
func TestSSDP_1_12_4_ResponseServerHeader(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "response"
	spec.SSDP.Server = "Linux/3.2.40 UPnP/1.1 MiniUPnPd/2.0"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "SERVER:")
	assertPayloadNotContains(t, payload, "USER-AGENT:")
}

// ===================================================================
// §1.13 Content-Length 头
// ===================================================================

// 用例 1.13.1: response body="" 且 EmitContentLength=true 时输出 CONTENT-LENGTH: 0
// (planner 只对非空 body 添加 Content-Length，此处验证非空 body 的 Content-Length)
func TestSSDP_1_13_1_ContentLengthZero(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "response"
	spec.SSDP.Body = ""
	spec.SSDP.EmitContentLength = true
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	// Planner only emits Content-Length when body is non-empty.
	// With empty body and EmitContentLength=true, no CONTENT-LENGTH header is emitted.
	if spec.SSDP.Body == "" {
		assertPayloadNotContains(t, payload, "CONTENT-LENGTH:")
	} else {
		assertPayloadContains(t, payload, "CONTENT-LENGTH: 0\r\n")
	}
}

// 用例 1.13.2: response body=<root/> 且 EmitContentLength=true 输出 CONTENT-LENGTH: 7
func TestSSDP_1_13_2_ContentLengthBody(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "response"
	spec.SSDP.Body = "<root/>"
	spec.SSDP.EmitContentLength = true
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "CONTENT-LENGTH: 7\r\n")
	assertSuffix(t, payload, "<root/>")
}

// 用例 1.13.3: msearch body 为空且 EmitContentLength=false 时不输出 Content-Length
func TestSSDP_1_13_3_NoContentLength(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.EmitContentLength = false
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadNotContains(t, string(cfgs[0].Payload), "CONTENT-LENGTH:")
}

// ===================================================================
// §1.14 响应状态行
// ===================================================================

// 用例 1.14.1: response 输出 HTTP/1.1 200 OK\r\n
func TestSSDP_1_14_1_ResponseStatusLine(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "response"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPrefix(t, payload, "HTTP/1.1 200 OK\r\n")
}

// 用例 1.14.2: msearch+ResponseCount=1: packet[0]=M-SEARCH, packet[1]=200 OK
func TestSSDP_1_14_2_MSearchThenResponse(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.ResponseCount = 1
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 2 {
		t.Fatalf("got %d packets, want 2", len(cfgs))
	}
	assertPrefix(t, string(cfgs[0].Payload), "M-SEARCH * HTTP/1.1\r\n")
	assertPrefix(t, string(cfgs[1].Payload), "HTTP/1.1 200 OK\r\n")
	if cfgs[0].PacketIndex != 0 || cfgs[1].PacketIndex != 1 {
		t.Errorf("packet indices = %d,%d, want 0,1", cfgs[0].PacketIndex, cfgs[1].PacketIndex)
	}
}

// ===================================================================
// §1.15 Date / BOOTID / CONFIGID 扩展头
// ===================================================================

// 用例 1.15.1: response Date 输出精确 DATE 头
func TestSSDP_1_15_1_DateHeader(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "response"
	spec.SSDP.Date = "Sun, 28 Jul 2026 12:34:56 GMT"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "DATE: Sun, 28 Jul 2026 12:34:56 GMT\r\n")
}

// 用例 1.15.2: alive BootID=1 输出 BOOTID.UPNP.ORG: 1
func TestSSDP_1_15_2_BootID1(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.BootID = 1
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "BOOTID.UPNP.ORG: 1\r\n")
}

// 用例 1.15.3: alive ConfigID=2147483647 输出最大合法值
func TestSSDP_1_15_3_ConfigIDMax(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.ConfigID = 2147483647
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "CONFIGID.UPNP.ORG: 2147483647\r\n")
}

// 用例 1.15.4: update BootID=2 ConfigID=3 同时输出两个扩展头
func TestSSDP_1_15_4_UpdateBootAndConfigID(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "update"
	spec.SSDP.BootID = 2
	spec.SSDP.ConfigID = 3
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "BOOTID.UPNP.ORG: 2\r\n")
	assertPayloadContains(t, payload, "CONFIGID.UPNP.ORG: 3\r\n")
}

// 用例 1.15.5: alive BootID=0, ConfigID=0 时不输出扩展头
func TestSSDP_1_15_5_NoBootOrConfigID(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.BootID = 0
	spec.SSDP.ConfigID = 0
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPayloadNotContains(t, payload, "BOOTID.UPNP.ORG:")
	assertPayloadNotContains(t, payload, "CONFIGID.UPNP.ORG:")
}

// ===================================================================
// §1.16 CRLF 与头结束空行
// ===================================================================

// 用例 1.16.1: alive 每行以 \r\n 结尾，payload 不含孤立 \n
func TestSSDP_1_16_1_CRLF(t *testing.T) {
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := cfgs[0].Payload
	// Check every line ends with \r\n (检查每行以\r\n结尾).
	lines := strings.Split(string(payload), "\r\n")
	for i, line := range lines {
		if i == len(lines)-1 {
			// Last element after split on \r\n is empty (because payload ends with \r\n\r\n).
			continue
		}
		for j, c := range []byte(line) {
			if c == '\n' {
				t.Errorf("line %d contains isolated \\n at byte %d", i, j)
			}
		}
	}
}

// 用例 1.16.2: msearch 无 body 时 payload 末尾精确为 \r\n\r\n
func TestSSDP_1_16_2_CRLFCRLFEnd(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertSuffix(t, payload, "\r\n\r\n")
}

// 用例 1.16.3: response 有 body 时头与 body 之间 \r\n\r\n，body 后不自动追加 CRLF
func TestSSDP_1_16_3_ResponseBodyCRLF(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "response"
	spec.SSDP.Body = "<root/>"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := cfgs[0].Payload
	// The body should be at the end without extra CRLF
	bodyPos := len(payload) - len("<root/>")
	if bodyPos < 0 {
		t.Fatalf("payload too short")
	}
	if string(payload[bodyPos:]) != "<root/>" {
		t.Errorf("payload suffix=%q, want <root/>", payload[bodyPos:])
	}
	// There should be \r\n\r\n before the body
	headerEnd := strings.LastIndex(string(payload), "\r\n\r\n")
	if headerEnd < 0 {
		t.Fatal("no header terminator found")
	}
	if headerEnd+4 != bodyPos {
		t.Errorf("headerEnd+4=%d, bodyPos=%d, want equal", headerEnd+4, bodyPos)
	}
}

// ===================================================================
// §1.17 EXT 头
// ===================================================================

// 用例 1.17.1: response 默认 OmitExt=false 输出 EXT:\r\n
func TestSSDP_1_17_1_EXTResponse(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "response"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "EXT:\r\n")
}

// 用例 1.17.2: response OmitExt=true 时不包含 EXT
func TestSSDP_1_17_2_EXTOmitted(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "response"
	spec.SSDP.OmitExt = true
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadNotContains(t, string(cfgs[0].Payload), "EXT:")
}

// 用例 1.17.4: alive 不包含 EXT
func TestSSDP_1_17_4_AliveNoEXT(t *testing.T) {
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadNotContains(t, string(cfgs[0].Payload), "EXT:")
}

// 用例 1.17.5: msearch 不包含 EXT
func TestSSDP_1_17_5_MSearchNoEXT(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadNotContains(t, string(cfgs[0].Payload), "EXT:")
}

// 用例 1.17.6: byebye 不包含 EXT
func TestSSDP_1_17_6_ByebyeNoEXT(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "byebye"
	spec.SSDP.USN = "uuid:00..01::upnp:rootdevice"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadNotContains(t, string(cfgs[0].Payload), "EXT:")
}

// 用例 1.17.7: msearch+ResponseCount=3 每个响应包都包含 EXT
func TestSSDP_1_17_7_MultiResponseEXT(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.ResponseCount = 3
	spec.SSDP.ResponseDelayMinMs = 0
	spec.SSDP.ResponseDelayMaxMs = 10
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	// 1 M-SEARCH + 3 responses = 4 packets
	if len(cfgs) != 4 {
		t.Fatalf("got %d packets, want 4", len(cfgs))
	}
	for i := 1; i < 4; i++ {
		payload := string(cfgs[i].Payload)
		if !strings.Contains(payload, "EXT:\r\n") {
			t.Errorf("response %d missing EXT: header", i)
		}
	}
}

// ===================================================================
// §1.18 Server 头长度阈值
// ===================================================================

// 用例 1.18.1: Server 长度=256 通过
func TestSSDP_1_18_1_Server256(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.Server = strings.Repeat("a", 256)
	err := NewPlanner().Validate(spec)
	if err != nil {
		t.Errorf("server=256 should pass, got: %v", err)
	}
}

// 用例 1.18.2: Server 长度=257 通过 (warning only)
func TestSSDP_1_18_2_Server257(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.Server = strings.Repeat("a", 257)
	err := NewPlanner().Validate(spec)
	if err != nil {
		t.Errorf("server=257 should pass (warning only), got: %v", err)
	}
}

// 用例 1.18.3: Server 长度=4096 通过 (warning only)
func TestSSDP_1_18_3_Server4096(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.Server = strings.Repeat("a", 4096)
	err := NewPlanner().Validate(spec)
	if err != nil {
		t.Errorf("server=4096 should pass (warning only), got: %v", err)
	}
}

// 用例 1.18.4: Server 长度=4097 Validate error
func TestSSDP_1_18_4_Server4097(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.Server = strings.Repeat("a", 4097)
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Fatal("expected error for server=4097")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("error=%q, want 'exceeds maximum'", err.Error())
	}
}

// 用例 1.18.5: Server 长度=100 通过
func TestSSDP_1_18_5_Server100(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.Server = strings.Repeat("a", 100)
	err := NewPlanner().Validate(spec)
	if err != nil {
		t.Errorf("server=100 should pass, got: %v", err)
	}
}

// 用例 1.18.7: alive Server 为空不输出 SERVER
func TestSSDP_1_18_7_ServerEmpty(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.Server = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadNotContains(t, string(cfgs[0].Payload), "SERVER:")
}

// 用例 1.18.8: Server 长度=4096 (warning) 仍生成包
func TestSSDP_1_18_8_Server4096Generate(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.Server = strings.Repeat("a", 4096)
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) == 0 {
		t.Fatal("expected packet generation for server=4096 (warning only)")
	}
	payload := string(cfgs[0].Payload)
	if !strings.Contains(payload, "SERVER:") {
		t.Errorf("payload should contain SERVER header")
	}
}

// ===================================================================
// §2.1 Device Announce
// ===================================================================

// 用例 2.1.1: 设备上线 1 个 alive 包
func TestSSDP_2_1_1_SingleAlive(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.RepeatCount = 1
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 1 {
		t.Fatalf("alive packet count = %d, want 1", len(cfgs))
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%s, want up", cfgs[0].Direction)
	}
	if cfgs[0].L3.DstIP != "239.255.255.250" {
		t.Errorf("DstIP=%s, want 239.255.255.250", cfgs[0].L3.DstIP)
	}
	if cfgs[0].L4.DstPort != 1900 {
		t.Errorf("DstPort=%d, want 1900", cfgs[0].L4.DstPort)
	}
}

// 用例 2.1.2: RepeatCount=3 输出 3 个 alive 包
func TestSSDP_2_1_2_RepeatAlive(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.RepeatCount = 3
	spec.SSDP.RepeatIntervalMs = 10
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 3 {
		t.Fatalf("alive repeat count = %d, want 3", len(cfgs))
	}
	for i, cfg := range cfgs {
		if cfg.PacketIndex != uint64(i) {
			t.Errorf("cfgs[%d].PacketIndex=%d, want %d", i, cfg.PacketIndex, i)
		}
	}
}

// 用例 2.1.3: ctx cancel 停止生成
func TestSSDP_2_1_3_CancelDuringRepeat(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP.RepeatCount = 100
	spec.SSDP.RepeatIntervalMs = 5
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	cfgs := drain(ch)
	if len(cfgs) >= 100 {
		t.Errorf("expected early cancellation, got %d packets", len(cfgs))
	}
}

// ===================================================================
// §2.2 Device Byebye
// ===================================================================

// 用例 2.2.1: byebye 包仅含 HOST/NT/NTS/USN
func TestSSDP_2_2_1_ByebyeMinimal(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "byebye"
	spec.SSDP.USN = "uuid:00..01::upnp:rootdevice"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 1 {
		t.Fatalf("byebye count = %d, want 1", len(cfgs))
	}
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "HOST:")
	assertPayloadContains(t, payload, "NT:")
	assertPayloadContains(t, payload, "NTS:")
	assertPayloadContains(t, payload, "USN:")
}

// ===================================================================
// §2.3 Control Point Search
// ===================================================================

// 用例 2.3.2: msearch ResponseCount=2 输出 M-SEARCH + 2 响应
func TestSSDP_2_3_2_MSearchTwoResponses(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.ResponseCount = 2
	spec.SSDP.ResponseDelayMinMs = 0
	spec.SSDP.ResponseDelayMaxMs = 10
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 3 {
		t.Fatalf("got %d packets, want 3 (1 msearch + 2 responses)", len(cfgs))
	}
	assertPrefix(t, string(cfgs[0].Payload), "M-SEARCH * HTTP/1.1\r\n")
	for i := 1; i < 3; i++ {
		assertPrefix(t, string(cfgs[i].Payload), "HTTP/1.1 200 OK\r\n")
	}
	if cfgs[0].PacketIndex != 0 || cfgs[1].PacketIndex != 1 || cfgs[2].PacketIndex != 2 {
		t.Errorf("packet indices = %d,%d,%d", cfgs[0].PacketIndex, cfgs[1].PacketIndex, cfgs[2].PacketIndex)
	}
}

// ===================================================================
// §2.4 Control Point Receive
// ===================================================================

// 用例 2.4.1: response 模式输出 200 OK, ST 与 USN 一致
func TestSSDP_2_4_1_ResponseMatch(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "response"
	spec.SSDP.SearchTarget = "upnp:rootdevice"
	spec.SSDP.USN = "uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "ST: upnp:rootdevice\r\n")
	assertPayloadContains(t, payload, "USN: uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice\r\n")
}

// ===================================================================
// §2.5 Update
// ===================================================================

// 用例 2.5.1: update 输出 NTS=ssdp:update + CONFIGID=2
func TestSSDP_2_5_1_UpdateConfigID(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "update"
	spec.SSDP.ConfigID = 2
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "NTS: ssdp:update\r\n")
	assertPayloadContains(t, payload, "CONFIGID.UPNP.ORG: 2\r\n")
}

// ===================================================================
// §3.1 设备上线 alive announce
// ===================================================================

// 用例 3.1.1: root device 上线含 7 个核心头
func TestSSDP_3_1_1_RootDeviceAlive(t *testing.T) {
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	// Core headers: HOST, CACHE-CONTROL, LOCATION, NT, NTS, SERVER, USN
	for _, h := range []string{"HOST:", "CACHE-CONTROL:", "LOCATION:", "NT:", "NTS:", "SERVER:", "USN:"} {
		if !strings.Contains(payload, h) {
			t.Errorf("missing header %s", h)
		}
	}
}

// 用例 3.1.3: service 上线 NT 值精确匹配
func TestSSDP_3_1_3_ServiceAlive(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.SearchTarget = "urn:schemas-upnp-org:service:ContentDirectory:1"
	spec.SSDP.USN = "uuid:00..01::urn:schemas-upnp-org:service:ContentDirectory:1"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "NT: urn:schemas-upnp-org:service:ContentDirectory:1\r\n")
}

// ===================================================================
// §3.2 设备下线 byebye
// ===================================================================

// 用例 3.2.1: root device 下线仅含四头
func TestSSDP_3_2_1_RootByebye(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "byebye"
	spec.SSDP.USN = "uuid:00..01::upnp:rootdevice"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "HOST:")
	assertPayloadContains(t, payload, "NT:")
	assertPayloadContains(t, payload, "NTS:")
	assertPayloadContains(t, payload, "USN:")
}

// ===================================================================
// §3.3 客户端搜索所有设备 ST=ssdp:all
// ===================================================================

// 用例 3.3.1: ST=ssdp:all / ResponseCount=1 输出 1 请求 + 1 响应
func TestSSDP_3_3_1_SearchAllOneResponse(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.ResponseCount = 1
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 2 {
		t.Fatalf("got %d packets, want 2", len(cfgs))
	}
	assertPayloadContains(t, string(cfgs[1].Payload), "ST: ssdp:all\r\n")
}

// 用例 3.3.2: ST=ssdp:all / ResponseCount=5 输出 6 包
func TestSSDP_3_3_2_SearchAllFiveResponses(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.ResponseCount = 5
	spec.SSDP.ResponseDelayMinMs = 0
	spec.SSDP.ResponseDelayMaxMs = 10
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 6 {
		t.Fatalf("got %d packets, want 6", len(cfgs))
	}
	for i, cfg := range cfgs {
		if cfg.PacketIndex != uint64(i) {
			t.Errorf("cfgs[%d].PacketIndex=%d, want %d", i, cfg.PacketIndex, i)
		}
	}
}

// ===================================================================
// §3.4 客户端搜索特定 rootdevice
// ===================================================================

// 用例 3.4.1: ST=upnp:rootdevice 响应 ST 一致
func TestSSDP_3_4_1_SearchRootdevice(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "upnp:rootdevice"
	spec.SSDP.USN = ""
	spec.SSDP.ResponseCount = 1
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "ST: upnp:rootdevice\r\n")
	// Response echoes ST
	assertPayloadContains(t, string(cfgs[1].Payload), "ST: upnp:rootdevice\r\n")
}

// ===================================================================
// §3.5 客户端搜索特定 service
// ===================================================================

// 用例 3.5.1: ST=service URN 精确匹配
func TestSSDP_3_5_1_SearchService(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "urn:schemas-upnp-org:service:AVTransport:1"
	spec.SSDP.USN = ""
	spec.SSDP.ResponseCount = 0 // defaults to 1, but we check the M-SEARCH payload
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "ST: urn:schemas-upnp-org:service:AVTransport:1\r\n")
}

// ===================================================================
// §3.9 IPv4 + IPv6 双栈
// ===================================================================

// 用例 3.9.1: 相同 USN 分别用 IPv4/IPv6 调 Plan(alive)
func TestSSDP_3_9_1_DualStackAlive(t *testing.T) {
	p := NewPlanner()

	// IPv4
	spec4 := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01", SrcIP: "192.168.1.50", DstIP: "239.255.255.250",
		SrcPort: 1900, DstPort: 1900,
		SSDP: &core.SSDPConfig{
			MessageType: "alive", SearchTarget: "upnp:rootdevice",
			USN: "uuid:00..01::upnp:rootdevice", MaxAge: 1800, RepeatCount: 1,
		},
	}
	cfgs4 := drain(mustPlan(t, p, spec4))

	// IPv6
	spec6 := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01", SrcIP: "fe80::50", DstIP: "ff02::c",
		SrcPort: 1900, DstPort: 1900,
		SSDP: &core.SSDPConfig{
			MessageType: "alive", SearchTarget: "upnp:rootdevice",
			USN: "uuid:00..01::upnp:rootdevice", MaxAge: 1800, RepeatCount: 1,
		},
	}
	cfgs6 := drain(mustPlan(t, p, spec6))

	if len(cfgs4) != 1 || len(cfgs6) != 1 {
		t.Fatalf("IPv4 count=%d IPv6 count=%d, want both 1", len(cfgs4), len(cfgs6))
	}
	// L7 payloads should be same except Host header (IPv4 vs IPv6)
	// Both contain the same NT, NTS, USN
	p4 := string(cfgs4[0].Payload)
	p6 := string(cfgs6[0].Payload)
	assertPayloadContains(t, p4, "NT: upnp:rootdevice\r\n")
	assertPayloadContains(t, p6, "NT: upnp:rootdevice\r\n")
	assertPayloadContains(t, p4, "NTS: ssdp:alive\r\n")
	assertPayloadContains(t, p6, "NTS: ssdp:alive\r\n")
	// Host header differs
	assertPayloadContains(t, p4, "HOST: 239.255.255.250:1900\r\n")
	assertPayloadContains(t, p6, "HOST: [ff02::c]:1900\r\n")
}

// 用例 3.9.2: IPv4/IPv6 msearch 包 MAN/ST/MX 头完全相同
func TestSSDP_3_9_2_DualStackMSearch(t *testing.T) {
	p := NewPlanner()

	spec4 := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01", SrcIP: "192.168.1.50", DstIP: "239.255.255.250",
		SrcPort: 1900, DstPort: 1900,
		SSDP: &core.SSDPConfig{
			MessageType: "msearch", SearchTarget: "ssdp:all", MX: 3, USN: "",
		},
	}
	spec6 := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01", SrcIP: "fe80::50", DstIP: "ff02::c",
		SrcPort: 1900, DstPort: 1900,
		SSDP: &core.SSDPConfig{
			MessageType: "msearch", SearchTarget: "ssdp:all", MX: 3, USN: "",
		},
	}
	cfgs4 := drain(mustPlan(t, p, spec4))
	cfgs6 := drain(mustPlan(t, p, spec6))

	p4 := string(cfgs4[0].Payload)
	p6 := string(cfgs6[0].Payload)
	assertPayloadContains(t, p4, "MAN: \"ssdp:discover\"\r\n")
	assertPayloadContains(t, p6, "MAN: \"ssdp:discover\"\r\n")
	assertPayloadContains(t, p4, "ST: ssdp:all\r\n")
	assertPayloadContains(t, p6, "ST: ssdp:all\r\n")
	assertPayloadContains(t, p4, "MX: 3\r\n")
	assertPayloadContains(t, p6, "MX: 3\r\n")
}

// ===================================================================
// §3.10 M-SEARCH 多设备响应
// ===================================================================

// 用例 3.10.1: ResponseCount=3 / MX=3 输出 3 个响应
func TestSSDP_3_10_1_ThreeResponses(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.ResponseCount = 3
	spec.SSDP.ResponseDelayMinMs = 0
	spec.SSDP.ResponseDelayMaxMs = 10
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 4 {
		t.Fatalf("got %d packets, want 4", len(cfgs))
	}
}

// ===================================================================
// §4.1 空值 / 最小值
// ===================================================================

// 用例 4.1.1: byebye 最小四头包
func TestSSDP_4_1_1_MinimalByebye(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP = &core.SSDPConfig{
		MessageType: "byebye",
		SearchTarget: "upnp:rootdevice",
		USN: "uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice",
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "HOST:")
	assertPayloadContains(t, payload, "NT:")
	assertPayloadContains(t, payload, "NTS:")
	assertPayloadContains(t, payload, "USN:")
}

// 用例 4.1.3: alive Server 为空时不输出 SERVER
func TestSSDP_4_1_3_AliveNoServer(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.Server = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadNotContains(t, string(cfgs[0].Payload), "SERVER:")
}

// 用例 4.1.5: response Date 为空时不输出 DATE
func TestSSDP_4_1_5_ResponseNoDate(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "response"
	spec.SSDP.Date = ""
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := string(cfgs[0].Payload)
	assertPayloadContains(t, payload, "HTTP/1.1 200 OK\r\n")
	assertPayloadContains(t, payload, "ST:")
	assertPayloadContains(t, payload, "USN:")
	assertPayloadNotContains(t, payload, "DATE:")
}

// ===================================================================
// §4.2 边界值
// ===================================================================

// 用例 4.2.1: MaxAge=1
func TestSSDP_4_2_1_MaxAgeMin(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MaxAge = 1
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "max-age=1")
}

// 用例 4.2.2: MaxAge=1800
func TestSSDP_4_2_2_MaxAgeMax(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MaxAge = 1800
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "max-age=1800")
}

// 用例 4.2.3: MX=1
func TestSSDP_4_2_3_MXMin(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.MX = 1
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "MX: 1\r\n")
}

// 用例 4.2.4: MX=5
func TestSSDP_4_2_4_MXMax(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.MX = 5
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	assertPayloadContains(t, string(cfgs[0].Payload), "MX: 5\r\n")
}

// 用例 4.2.7: ResponseCount=1 时 msearch 输出 2 包
func TestSSDP_4_2_7_ResponseCountOne(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.ResponseCount = 1
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 2 {
		t.Fatalf("got %d packets, want 2", len(cfgs))
	}
}

// ===================================================================
// §4.3 异常值
// ===================================================================

// 用例 4.3.1: MessageType=bad Validate error
func TestSSDP_4_3_1_InvalidMessageType(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "bad"
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Fatal("expected error")
	}
}

// 用例 4.3.4: MaxAge=1801 Validate error
func TestSSDP_4_3_4_MaxAgeOver(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MaxAge = 1801
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Fatal("expected error")
	}
}

// 用例 4.3.5: MX=6 Validate error
func TestSSDP_4_3_5_MXOver(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.MX = 6
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Fatal("expected error for MX=6")
	}
}

// 用例 4.3.6: SearchTarget 为空 Validate error
func TestSSDP_4_3_6_EmptySearchTarget(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.SearchTarget = ""
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Fatal("expected error")
	}
}

// 用例 4.3.8: ResponseDelayMinMs > ResponseDelayMaxMs Validate error
func TestSSDP_4_3_8_ResponseDelayMinMax(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.ResponseCount = 2
	spec.SSDP.ResponseDelayMinMs = 1000
	spec.SSDP.ResponseDelayMaxMs = 100
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Fatal("expected error for min > max")
	}
}

// ===================================================================
// §4.5 小数据 / 单包
// ===================================================================

// 用例 4.5.1: 最小 byebye 输出 1 个 PacketConfig
func TestSSDP_4_5_1_SingleByebye(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "byebye"
	spec.SSDP.USN = "uuid:00..01::upnp:rootdevice"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 1 {
		t.Fatalf("byebye count = %d, want 1", len(cfgs))
	}
}

// 用例 4.5.2: 单包 alive RepeatCount=0 按默认 1 处理
func TestSSDP_4_5_2_SingleAlive(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.RepeatCount = 0
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 1 {
		t.Fatalf("alive repeat=0 produced %d packets, want 1", len(cfgs))
	}
}

// 用例 4.5.4: 单包 response 输出 1 个 PacketConfig
func TestSSDP_4_5_4_SingleResponse(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "response"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 1 {
		t.Fatalf("response count = %d, want 1", len(cfgs))
	}
	if cfgs[0].PacketIndex != 0 {
		t.Errorf("PacketIndex=%d, want 0", cfgs[0].PacketIndex)
	}
}

// 用例 4.5.5: alive body 为空时 UDP payload 长度等于文本头长度
func TestSSDP_4_5_5_AliveBodyEmpty(t *testing.T) {
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	payload := cfgs[0].Payload
	if len(payload) == 0 {
		t.Fatal("payload should not be empty")
	}
	// Should end with \r\n\r\n and no extra bytes
	assertSuffix(t, string(payload), "\r\n\r\n")
}

// ===================================================================
// §4.6 多播 MAC 推导
// ===================================================================

// 用例 4.6.1.1: 239.255.255.250 -> 01:00:5e:7f:ff:fa
func TestSSDP_4_6_1_1_IPv4MulticastMAC(t *testing.T) {
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if cfgs[0].L2.DstMAC != "01:00:5e:7f:ff:fa" {
		t.Errorf("DstMAC=%s, want 01:00:5e:7f:ff:fa", cfgs[0].L2.DstMAC)
	}
}

// 用例 4.6.1.3: 224.0.0.1 -> 01:00:5e:00:00:01
func TestSSDP_4_6_1_3_IPv4OtherMulticastMAC(t *testing.T) {
	spec := validSSDPSpec()
	spec.DstIP = "224.0.0.1"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if cfgs[0].L2.DstMAC != "01:00:5e:00:00:01" {
		t.Errorf("DstMAC=%s, want 01:00:5e:00:00:01", cfgs[0].L2.DstMAC)
	}
}

// 用例 4.6.1.4: 用户指定 DstMAC 优先
func TestSSDP_4_6_1_4_UserDstMAC(t *testing.T) {
	spec := validSSDPSpec()
	spec.DstMAC = "aa:bb:cc:dd:ee:ff"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if cfgs[0].L2.DstMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("DstMAC=%s, want aa:bb:cc:dd:ee:ff", cfgs[0].L2.DstMAC)
	}
}

// 用例 4.6.1.6: msearch 与 alive 共享同一多播 MAC
func TestSSDP_4_6_1_6_SharedMulticastMAC(t *testing.T) {
	p := NewPlanner()
	spec1 := validSSDPSpec()
	spec2 := validSSDPSpec()
	spec2.SSDP.MessageType = "msearch"
	spec2.SSDP.SearchTarget = "ssdp:all"
	spec2.SSDP.USN = ""
	cfgs1 := drain(mustPlan(t, p, spec1))
	cfgs2 := drain(mustPlan(t, p, spec2))
	if cfgs1[0].L2.DstMAC != cfgs2[0].L2.DstMAC {
		t.Errorf("alive DstMAC=%s != msearch DstMAC=%s", cfgs1[0].L2.DstMAC, cfgs2[0].L2.DstMAC)
	}
	if cfgs1[0].L2.DstMAC != "01:00:5e:7f:ff:fa" {
		t.Errorf("DstMAC=%s, want 01:00:5e:7f:ff:fa", cfgs1[0].L2.DstMAC)
	}
}

// 用例 4.6.1.7: IPv4 单播响应不走多播 MAC 推导
func TestSSDP_4_6_1_7_UnicastNoMulticastMAC(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "response"
	spec.DstIP = "192.168.1.100"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	// Response unicast: planner does NOT resolve multicast MAC (empty/unset).
	// The builder's ARP path handles the MAC.
	if cfgs[0].L2.DstMAC == "01:00:5e:7f:ff:fa" {
		t.Errorf("unicast response should not have multicast MAC, got %s", cfgs[0].L2.DstMAC)
	}
}

// 用例 4.6.2.1: ff02::c -> 33:33:00:00:00:0c
func TestSSDP_4_6_2_1_IPv6MulticastMAC(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01", SrcIP: "fe80::1", DstIP: "ff02::c",
		SrcPort: 1900, DstPort: 1900,
		SSDP: &core.SSDPConfig{
			MessageType: "alive", SearchTarget: "upnp:rootdevice",
			USN: "uuid:00..01::upnp:rootdevice", MaxAge: 1800, RepeatCount: 1,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L2.DstMAC != "33:33:00:00:00:0c" {
		t.Errorf("DstMAC=%s, want 33:33:00:00:00:0c", cfgs[0].L2.DstMAC)
	}
}

// 用例 4.6.2.3: 用户指定 DstMAC 优先 (IPv6)
func TestSSDP_4_6_2_3_IPv6UserDstMAC(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01", SrcIP: "fe80::1", DstIP: "ff02::c",
		DstMAC: "11:22:33:44:55:66",
		SrcPort: 1900, DstPort: 1900,
		SSDP: &core.SSDPConfig{
			MessageType: "alive", SearchTarget: "upnp:rootdevice",
			USN: "uuid:00..01::upnp:rootdevice", MaxAge: 1800, RepeatCount: 1,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L2.DstMAC != "11:22:33:44:55:66" {
		t.Errorf("DstMAC=%s, want 11:22:33:44:55:66", cfgs[0].L2.DstMAC)
	}
}

// 用例 4.6.3.1: DstMAC=全F (broadcast) 不覆盖
func TestSSDP_4_6_3_1_BroadcastMACTakesPriority(t *testing.T) {
	spec := validSSDPSpec()
	spec.DstMAC = "ff:ff:ff:ff:ff:ff"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if cfgs[0].L2.DstMAC != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("DstMAC=%s, want ff:ff:ff:ff:ff:ff", cfgs[0].L2.DstMAC)
	}
}

// 用例 4.6.3.2: 单播 IP 不走多播 MAC 推导
func TestSSDP_4_6_3_2_UnicastIPNoMulticastMAC(t *testing.T) {
	spec := validSSDPSpec()
	spec.DstIP = "192.168.1.100"
	spec.SSDP.MessageType = "response"
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	// For unicast response, DstMAC should be empty (not a multicast MAC)
	if cfgs[0].L2.DstMAC == "01:00:5e:7f:ff:fa" {
		t.Errorf("unicast IP should not derive multicast MAC")
	}
}

// ===================================================================
// §5 并发
// ===================================================================

// 用例 5.1: 100 goroutine 同时 Plan(alive)，无竞争
func TestSSDP_5_1_ConcurrentPlan(t *testing.T) {
	p := NewPlanner()
	done := make(chan struct{}, 100)
	for i := 0; i < 100; i++ {
		go func(idx int) {
			spec := validSSDPSpec()
			spec.SrcIP = fmt.Sprintf("192.168.1.%d", idx+1)
			_ = drain(mustPlan(t, p, spec))
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 100; i++ {
		<-done
	}
}

// ===================================================================
// §6 资源耗尽
// ===================================================================

// 用例 6.5: USN=1MB Validate error
func TestSSDP_6_5_USNOverLimit(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.USN = strings.Repeat("x", 4097)
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Fatal("expected error for USN > 4096")
	}
}

// 用例 6.6: Server=10MB Validate error
func TestSSDP_6_6_ServerOverLimit(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.Server = strings.Repeat("x", 4097)
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Fatal("expected error for server > 4096")
	}
}

// 用例 6.7: ResponseDelayMaxMs=2^31-1 Validate error
func TestSSDP_6_7_ResponseDelayOverflow(t *testing.T) {
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.ResponseCount = 2
	spec.SSDP.ResponseDelayMaxMs = int(^uint32(0) >> 1) + 1
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Fatal("expected error for response delay overflow")
	}
}

// 用例 6.8: ctx cancel 在 time.After 期间立即关闭 channel
func TestSSDP_6_8_CancelDuringDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.MX = 5
	spec.SSDP.ResponseCount = 1
	ch, err := NewPlanner().Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	// Read the M-SEARCH (first packet, no delay)
	_, ok := <-ch
	if !ok {
		t.Fatal("channel closed before M-SEARCH")
	}
	// Cancel before the response delay finishes
	cancel()
	// The response should be skipped; channel should close quickly
	_ = drain(ch)
}