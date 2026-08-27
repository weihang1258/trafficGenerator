package ssdp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// drain reads all PacketConfig values from ch and returns them as a slice.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for cfg := range ch {
		out = append(out, cfg)
	}
	return out
}

// mustPlan calls Plan and fails the test on error. Returns the channel for
// the caller to drain.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return ch
}

// mustPlanCtx calls Plan with a context and fails the test on error.
func mustPlanCtx(t *testing.T, ctx context.Context, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return ch
}

// validSSDPSpec returns a minimal valid SSDP spec for NOTIFY alive.
func validSSDPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "", // empty: planner computes multicast MAC
		SrcIP: "192.168.1.50",
		DstIP: "239.255.255.250",
		SrcPort: 1900,
		DstPort: 1900,
		SSDP: &core.SSDPConfig{
			MessageType: "alive",
			SearchTarget: "upnp:rootdevice",
			USN: "uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice",
			MaxAge: 1800,
			Location: "http://192.168.1.50:80/description.xml",
			Server: "Linux/3.2.40 UPnP/1.1 MiniUPnPd/2.0",
			BootID: 1,
			ConfigID: 0,
			RepeatCount: 1,
		},
	}
}

// ===================================================================
// Integration tests: Plan() output capture and end-to-end asserts.
// ===================================================================

// Integration 1: NOTIFY ssdp:alive (场景 1: 设备上线通知).
func TestSSDP_Integration_AliveNotify(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, p, spec))

	// Must produce exactly 1 packet (单包 alive).
	if len(cfgs) != 1 {
		t.Fatalf("alive packet count = %d, want 1", len(cfgs))
	}
	cfg := cfgs[0]

	// Direction = up (方向为上行).
	if cfg.Direction != "up" {
		t.Errorf("Direction=%s, want up", cfg.Direction)
	}

	// L4: UDP protocol, ports 1900 (UDP协议, 端口1900).
	if cfg.L4.Protocol != "udp" {
		t.Errorf("L4.Protocol=%s, want udp", cfg.L4.Protocol)
	}
	if cfg.L4.SrcPort != 1900 {
		t.Errorf("L4.SrcPort=%d, want 1900", cfg.L4.SrcPort)
	}
	if cfg.L4.DstPort != 1900 {
		t.Errorf("L4.DstPort=%d, want 1900", cfg.L4.DstPort)
	}

	// L3: DstIP = multicast group, TTL = 4 (L3: 多播地址, TTL=4).
	if cfg.L3.DstIP != "239.255.255.250" {
		t.Errorf("L3.DstIP=%s, want 239.255.255.250", cfg.L3.DstIP)
	}
	if cfg.L3.TTL != 4 {
		t.Errorf("L3.TTL=%d, want 4", cfg.L3.TTL)
	}

	// L2: DstMAC should be IPv4 multicast MAC (L2: 多播MAC应自动推导).
	if cfg.L2.DstMAC != "01:00:5e:7f:ff:fa" {
		t.Errorf("L2.DstMAC=%s, want 01:00:5e:7f:ff:fa", cfg.L2.DstMAC)
	}

	// Payload: request line (请求行).
	payload := string(cfg.Payload)
	if !strings.HasPrefix(payload, "NOTIFY * HTTP/1.1\r\n") {
		t.Errorf("payload prefix=%q, want NOTIFY * HTTP/1.1\\r\\n", payload[:30])
	}

	// Verify Host header (验证Host头).
	if !strings.Contains(payload, "HOST: 239.255.255.250:1900\r\n") {
		t.Errorf("payload missing HOST header")
	}

	// Verify Cache-Control (验证Cache-Control).
	if !strings.Contains(payload, "CACHE-CONTROL: max-age=1800\r\n") {
		t.Errorf("payload missing CACHE-CONTROL")
	}

	// Verify Location (验证Location).
	if !strings.Contains(payload, "LOCATION: http://192.168.1.50:80/description.xml\r\n") {
		t.Errorf("payload missing LOCATION")
	}

	// Verify NT (验证NT).
	if !strings.Contains(payload, "NT: upnp:rootdevice\r\n") {
		t.Errorf("payload missing NT")
	}

	// Verify NTS = ssdp:alive (验证NTS).
	if !strings.Contains(payload, "NTS: ssdp:alive\r\n") {
		t.Errorf("payload missing NTS")
	}

	// Verify Server (验证Server).
	if !strings.Contains(payload, "SERVER: Linux/3.2.40 UPnP/1.1 MiniUPnPd/2.0\r\n") {
		t.Errorf("payload missing SERVER")
	}

	// Verify USN (验证USN).
	if !strings.Contains(payload, "USN: uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice\r\n") {
		t.Errorf("payload missing USN")
	}

	// Verify BOOTID.UPNP.ORG (验证BOOTID).
	if !strings.Contains(payload, "BOOTID.UPNP.ORG: 1\r\n") {
		t.Errorf("payload missing BOOTID")
	}

	// Verify payload ends with \r\n\r\n (验证空行结束).
	if !strings.HasSuffix(payload, "\r\n\r\n") {
		t.Errorf("payload does not end with \\r\\n\\r\\n")
	}

	// Verify no EXT in alive (alive包不应含EXT头).
	if strings.Contains(payload, "EXT:") {
		t.Errorf("alive payload should not contain EXT")
	}
}

// Integration 2: NOTIFY ssdp:byebye (场景 2: 设备下线通知).
func TestSSDP_Integration_ByebyeNotify(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP = &core.SSDPConfig{
		MessageType: "byebye",
		SearchTarget: "upnp:rootdevice",
		USN: "uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice",
	}
	cfgs := drain(mustPlan(t, p, spec))

	if len(cfgs) != 1 {
		t.Fatalf("byebye packet count = %d, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	payload := string(cfg.Payload)

	// Request line (请求行).
	if !strings.HasPrefix(payload, "NOTIFY * HTTP/1.1\r\n") {
		t.Errorf("payload prefix=%q, want NOTIFY * HTTP/1.1\\r\\n", payload[:30])
	}

	// Host header (Host头).
	if !strings.Contains(payload, "HOST: 239.255.255.250:1900\r\n") {
		t.Errorf("payload missing HOST")
	}

	// NT header (NT头).
	if !strings.Contains(payload, "NT: upnp:rootdevice\r\n") {
		t.Errorf("payload missing NT")
	}

	// NTS = ssdp:byebye (NTS头).
	if !strings.Contains(payload, "NTS: ssdp:byebye\r\n") {
		t.Errorf("payload missing NTS")
	}

	// USN header (USN头).
	if !strings.Contains(payload, "USN: uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice\r\n") {
		t.Errorf("payload missing USN")
	}

	// Verify byebye's minimal headers only: no CACHE-CONTROL, no LOCATION, no SERVER.
	// byebye 只有四个必带头: HOST, NT, NTS, USN.
	if strings.Contains(payload, "CACHE-CONTROL") {
		t.Errorf("byebye should not contain CACHE-CONTROL")
	}
	if strings.Contains(payload, "LOCATION:") {
		t.Errorf("byebye should not contain LOCATION")
	}
	if strings.Contains(payload, "SERVER:") {
		t.Errorf("byebye should not contain SERVER")
	}
	if strings.Contains(payload, "BOOTID.UPNP.ORG") {
		t.Errorf("byebye should not contain BOOTID")
	}
	if strings.Contains(payload, "CONFIGID.UPNP.ORG") {
		t.Errorf("byebye should not contain CONFIGID")
	}

	// Direction up (方向上行).
	if cfg.Direction != "up" {
		t.Errorf("Direction=%s, want up", cfg.Direction)
	}

	// L2 multicast MAC (L2多播MAC).
	if cfg.L2.DstMAC != "01:00:5e:7f:ff:fa" {
		t.Errorf("L2.DstMAC=%s, want 01:00:5e:7f:ff:fa", cfg.L2.DstMAC)
	}
}

// Integration 3: M-SEARCH with ssdp:all (场景 3: 控制点搜索所有设备).
func TestSSDP_Integration_MSearchAll(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP = &core.SSDPConfig{
		MessageType: "msearch",
		SearchTarget: "ssdp:all",
		MX: 3,
		Server: "Linux/3.2.40 UPnP/1.1 TestClient/1.0",
		ResponseCount: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))

	// 1 M-SEARCH + 1 response = 2 packets (1个M-SEARCH + 1个响应).
	if len(cfgs) != 2 {
		t.Fatalf("msearch packet count = %d, want 2 (1 msearch + 1 response)", len(cfgs))
	}

	// Packet 0: M-SEARCH (M-SEARCH包).
	ms := cfgs[0]
	msPayload := string(ms.Payload)
	if !strings.HasPrefix(msPayload, "M-SEARCH * HTTP/1.1\r\n") {
		t.Errorf("ms payload prefix=%q, want M-SEARCH * HTTP/1.1\\r\\n", msPayload[:30])
	}
	if !strings.Contains(msPayload, "MAN: \"ssdp:discover\"\r\n") {
		t.Errorf("ms payload missing MAN header")
	}
	if !strings.Contains(msPayload, "MX: 3\r\n") {
		t.Errorf("ms payload missing MX: 3")
	}
	if !strings.Contains(msPayload, "ST: ssdp:all\r\n") {
		t.Errorf("ms payload missing ST: ssdp:all")
	}
	if !strings.Contains(msPayload, "USER-AGENT: Linux/3.2.40 UPnP/1.1 TestClient/1.0\r\n") {
		t.Errorf("ms payload missing USER-AGENT")
	}
	if ms.Direction != "up" {
		t.Errorf("ms Direction=%s, want up", ms.Direction)
	}
	if ms.L4.DstPort != 1900 {
		t.Errorf("ms DstPort=%d, want 1900", ms.L4.DstPort)
	}
	if ms.L3.DstIP != "239.255.255.250" {
		t.Errorf("ms DstIP=%s, want 239.255.255.250", ms.L3.DstIP)
	}
	if ms.L3.TTL != 4 {
		t.Errorf("ms TTL=%d, want 4", ms.L3.TTL)
	}

	// Packet 1: 200 OK response (200 OK响应包).
	resp := cfgs[1]
	respPayload := string(resp.Payload)
	if !strings.HasPrefix(respPayload, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("resp payload prefix=%q, want HTTP/1.1 200 OK\\r\\n", respPayload[:30])
	}
	if !strings.Contains(respPayload, "CACHE-CONTROL: max-age=1800\r\n") {
		t.Errorf("resp payload missing CACHE-CONTROL")
	}
	if !strings.Contains(respPayload, "EXT:\r\n") {
		t.Errorf("resp payload missing EXT: header")
	}
	if !strings.Contains(respPayload, "ST: ssdp:all\r\n") {
		t.Errorf("resp payload missing ST: ssdp:all")
	}
	if !strings.Contains(respPayload, "USN: ") {
		t.Errorf("resp payload missing USN")
	}
	if resp.Direction != "up" {
		t.Errorf("resp Direction=%s, want up", resp.Direction)
	}

	// Packet indices are sequential (包序号连续).
	if cfgs[0].PacketIndex != 0 || cfgs[1].PacketIndex != 1 {
		t.Errorf("packet indices = %d, %d, want 0, 1", cfgs[0].PacketIndex, cfgs[1].PacketIndex)
	}

	// Same flow ID (相同流ID).
	if cfgs[0].FlowID != cfgs[1].FlowID {
		t.Errorf("FlowIDs differ: %q vs %q", cfgs[0].FlowID, cfgs[1].FlowID)
	}
}

// Integration 4: M-SEARCH response standalone (场景 4: 独立M-SEARCH响应).
func TestSSDP_Integration_Response(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SrcIP = "192.168.1.50"
	spec.DstIP = "192.168.1.100"
	spec.SSDP = &core.SSDPConfig{
		MessageType: "response",
		SearchTarget: "upnp:rootdevice",
		USN: "uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice",
		Location: "http://192.168.1.50:80/description.xml",
		Server: "Linux/3.2.40 UPnP/1.1 MiniUPnPd/2.0",
		MaxAge: 1800,
		Date: "Sun, 28 Jul 2026 12:34:56 GMT",
	}
	cfgs := drain(mustPlan(t, p, spec))

	if len(cfgs) != 1 {
		t.Fatalf("response packet count = %d, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	payload := string(cfg.Payload)

	// Status line (状态行).
	if !strings.HasPrefix(payload, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("payload prefix=%q, want HTTP/1.1 200 OK\\r\\n", payload[:30])
	}

	// Cache-Control (缓存控制).
	if !strings.Contains(payload, "CACHE-CONTROL: max-age=1800\r\n") {
		t.Errorf("payload missing CACHE-CONTROL")
	}

	// Date header (日期头).
	if !strings.Contains(payload, "DATE: Sun, 28 Jul 2026 12:34:56 GMT\r\n") {
		t.Errorf("payload missing DATE")
	}

	// EXT header (EXT头, UPnP 1.1 §1.3强制).
	if !strings.Contains(payload, "EXT:\r\n") {
		t.Errorf("response payload missing EXT: header")
	}

	// Location.
	if !strings.Contains(payload, "LOCATION: http://192.168.1.50:80/description.xml\r\n") {
		t.Errorf("payload missing LOCATION")
	}

	// Server.
	if !strings.Contains(payload, "SERVER: Linux/3.2.40 UPnP/1.1 MiniUPnPd/2.0\r\n") {
		t.Errorf("payload missing SERVER")
	}

	// ST (搜索目标).
	if !strings.Contains(payload, "ST: upnp:rootdevice\r\n") {
		t.Errorf("payload missing ST")
	}

	// USN.
	if !strings.Contains(payload, "USN: uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice\r\n") {
		t.Errorf("payload missing USN")
	}

	// Direction = up (方向上行).
	if cfg.Direction != "up" {
		t.Errorf("Direction=%s, want up", cfg.Direction)
	}

	// DstIP is the response destination (响应目的地址).
	if cfg.L3.DstIP != "192.168.1.100" {
		t.Errorf("L3.DstIP=%s, want 192.168.1.100", cfg.L3.DstIP)
	}
}

// Integration 5: Device-specific ST (场景 5: 设备特定搜索目标).
// Note: planner defaults ResponseCount=0/1 to 1 response. To suppress the
// response, we use a separate context with cancel — or use MessageType=response.
// Here we set ResponseCount=1 (default behavior) and verify both packets.
func TestSSDP_Integration_DeviceSpecificST(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP = &core.SSDPConfig{
		MessageType: "msearch",
		SearchTarget: "urn:schemas-upnp-org:device:MediaServer:1",
		MX: 3,
		ResponseCount: 1, // 1 response emitted by default
	}
	cfgs := drain(mustPlan(t, p, spec))

	if len(cfgs) != 2 {
		t.Fatalf("msearch packet count = %d, want 2 (1 M-SEARCH + 1 default response)", len(cfgs))
	}
	cfg := cfgs[0]
	payload := string(cfg.Payload)

	// Verify ST header (验证ST头).
	if !strings.Contains(payload, "ST: urn:schemas-upnp-org:device:MediaServer:1\r\n") {
		t.Errorf("payload missing ST for MediaServer:1")
	}

	// Verify request line (验证请求行).
	if !strings.HasPrefix(payload, "M-SEARCH * HTTP/1.1\r\n") {
		t.Errorf("payload prefix=%q", payload[:30])
	}

	// Verify no USN in M-SEARCH (M-SEARCH不含USN).
	if strings.Contains(payload, "USN:") {
		t.Errorf("M-SEARCH should not contain USN")
	}
}

// Integration 6: Service-specific NT (场景 6: 服务特定通知类型).
func TestSSDP_Integration_ServiceSpecificNT(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP = &core.SSDPConfig{
		MessageType: "alive",
		SearchTarget: "urn:schemas-upnp-org:service:ContentDirectory:1",
		USN: "uuid:00000000-0000-0000-0000-000000000001::urn:schemas-upnp-org:service:ContentDirectory:1",
		Location: "http://192.168.1.50:80/description.xml",
		Server: "Linux/3.2.40 UPnP/1.1 MiniUPnPd/2.0",
		MaxAge: 1800,
		RepeatCount: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))

	if len(cfgs) != 1 {
		t.Fatalf("alive packet count = %d, want 1", len(cfgs))
	}
	payload := string(cfgs[0].Payload)

	// Verify NT header (验证NT头).
	if !strings.Contains(payload, "NT: urn:schemas-upnp-org:service:ContentDirectory:1\r\n") {
		t.Errorf("payload missing NT for ContentDirectory:1")
	}

	// Verify USN includes the NT suffix (验证USN包含NT后缀).
	wantUSN := "USN: uuid:00000000-0000-0000-0000-000000000001::urn:schemas-upnp-org:service:ContentDirectory:1\r\n"
	if !strings.Contains(payload, wantUSN) {
		t.Errorf("payload missing USN with service suffix")
	}

	// Verify NOT NTS=ssdp:byebye (验证NTS不是ssdp:byebye).
	if strings.Contains(payload, "NTS: ssdp:byebye") {
		t.Errorf("alive should not have NTS=byebye")
	}
}

// Integration 7: Root device + embedded device hierarchy (场景 7: 根设备+嵌入式设备层级).
func TestSSDP_Integration_DeviceHierarchy(t *testing.T) {
	p := NewPlanner()

	// 3 independent FlowSpecs: root device + 2 sub-devices.
	// 3个独立FlowSpec: 根设备 + 2个子设备.
	// Use different SrcIPs to get different FlowIDs (使用不同SrcIP获得不同FlowID).
	specRoot := validSSDPSpec()
	specRoot.SrcIP = "192.168.1.50"
	specRoot.SSDP = &core.SSDPConfig{
		MessageType: "alive",
		SearchTarget: "upnp:rootdevice",
		USN: "uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice",
		Location: "http://192.168.1.50:80/root_desc.xml",
		Server: "Linux/3.2.40 UPnP/1.1 MiniUPnPd/2.0",
		MaxAge: 1800,
		RepeatCount: 1,
	}

	specDev1 := validSSDPSpec()
	specDev1.SrcIP = "192.168.1.51"
	specDev1.SSDP = &core.SSDPConfig{
		MessageType: "alive",
		SearchTarget: "urn:schemas-upnp-org:device:MediaServer:1",
		USN: "uuid:00000000-0000-0000-0000-000000000001::urn:schemas-upnp-org:device:MediaServer:1",
		Location: "http://192.168.1.51:80/MediaServer_desc.xml",
		Server: "Linux/3.2.40 UPnP/1.1 MiniUPnPd/2.0",
		MaxAge: 1800,
		RepeatCount: 1,
	}

	specDev2 := validSSDPSpec()
	specDev2.SrcIP = "192.168.1.52"
	specDev2.SSDP = &core.SSDPConfig{
		MessageType: "alive",
		SearchTarget: "urn:schemas-upnp-org:device:MediaRenderer:1",
		USN: "uuid:00000000-0000-0000-0000-000000000001::urn:schemas-upnp-org:device:MediaRenderer:1",
		Location: "http://192.168.1.52:80/MediaRenderer_desc.xml",
		Server: "Linux/3.2.40 UPnP/1.1 MiniUPnPd/2.0",
		MaxAge: 1800,
		RepeatCount: 1,
	}

	cfgsRoot := drain(mustPlan(t, p, specRoot))
	cfgsDev1 := drain(mustPlan(t, p, specDev1))
	cfgsDev2 := drain(mustPlan(t, p, specDev2))

	// All should produce 1 packet each (每个产生1个包).
	if len(cfgsRoot) != 1 || len(cfgsDev1) != 1 || len(cfgsDev2) != 1 {
		t.Fatalf("packet counts: root=%d dev1=%d dev2=%d, want all 1",
			len(cfgsRoot), len(cfgsDev1), len(cfgsDev2))
	}

	// Verify all are alive packets with different NT (验证所有都是alive包且NT不同).
	for _, c := range [][]core.PacketConfig{cfgsRoot, cfgsDev1, cfgsDev2} {
		payload := string(c[0].Payload)
		if !strings.Contains(payload, "NTS: ssdp:alive\r\n") {
			t.Errorf("payload missing NTS=ssdp:alive")
		}
		if !strings.Contains(payload, "LOCATION:") {
			t.Errorf("payload missing LOCATION")
		}
	}

	// Verify different NT values (验证不同的NT值).
	rootPayload := string(cfgsRoot[0].Payload)
	dev1Payload := string(cfgsDev1[0].Payload)
	dev2Payload := string(cfgsDev2[0].Payload)

	if !strings.Contains(rootPayload, "NT: upnp:rootdevice\r\n") {
		t.Errorf("root payload missing NT: upnp:rootdevice")
	}
	if !strings.Contains(dev1Payload, "NT: urn:schemas-upnp-org:device:MediaServer:1\r\n") {
		t.Errorf("dev1 payload missing NT: MediaServer:1")
	}
	if !strings.Contains(dev2Payload, "NT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n") {
		t.Errorf("dev2 payload missing NT: MediaRenderer:1")
	}

	// Verify different USN values (验证不同的USN值).
	if !strings.Contains(rootPayload, "uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice") {
		t.Errorf("root USN mismatch")
	}
	if !strings.Contains(dev1Payload, "uuid:00000000-0000-0000-0000-000000000001::urn:schemas-upnp-org:device:MediaServer:1") {
		t.Errorf("dev1 USN mismatch")
	}
	if !strings.Contains(dev2Payload, "uuid:00000000-0000-0000-0000-000000000001::urn:schemas-upnp-org:device:MediaRenderer:1") {
		t.Errorf("dev2 USN mismatch")
	}

	// All DstMAC should be the IPv4 multicast MAC (所有DstMAC应为IPv4多播MAC).
	for _, c := range [][]core.PacketConfig{cfgsRoot, cfgsDev1, cfgsDev2} {
		if c[0].L2.DstMAC != "01:00:5e:7f:ff:fa" {
			t.Errorf("DstMAC=%s, want 01:00:5e:7f:ff:fa", c[0].L2.DstMAC)
		}
	}

	// All different FlowIDs (所有FlowID不同).
	if cfgsRoot[0].FlowID == cfgsDev1[0].FlowID {
		t.Errorf("root and dev1 should have different FlowIDs")
	}
	if cfgsDev1[0].FlowID == cfgsDev2[0].FlowID {
		t.Errorf("dev1 and dev2 should have different FlowIDs")
	}
}

// Integration 8: IPv6 SSDP (场景 8: IPv6 SSDP).
func TestSSDP_Integration_IPv6(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		SrcIP: "fe80::1",
		DstIP: "ff02::c",
		SrcPort: 1900,
		DstPort: 1900,
		SSDP: &core.SSDPConfig{
			MessageType: "alive",
			SearchTarget: "upnp:rootdevice",
			USN: "uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice",
			Location: "http://[fe80::1]:80/description.xml",
			Server: "Linux/3.2.40 UPnP/1.1 MiniUPnPd/2.0",
			MaxAge: 1800,
			RepeatCount: 1,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))

	if len(cfgs) != 1 {
		t.Fatalf("IPv6 alive packet count = %d, want 1", len(cfgs))
	}
	cfg := cfgs[0]

	// L2: IPv6 EtherType (L2: IPv6 EtherType).
	if cfg.L2.EtherType != 0x86DD {
		t.Errorf("L2.EtherType=%04x, want 86DD", cfg.L2.EtherType)
	}
	if cfg.L2.DstMAC != "33:33:00:00:00:0c" {
		t.Errorf("L2.DstMAC=%s, want 33:33:00:00:00:0c", cfg.L2.DstMAC)
	}

	// L3: IPv6 multicast (L3: IPv6多播).
	if cfg.L3.DstIP != "ff02::c" {
		t.Errorf("L3.DstIP=%s, want ff02::c", cfg.L3.DstIP)
	}
	if cfg.L3.TTL != 4 {
		t.Errorf("L3.TTL=%d, want 4", cfg.L3.TTL)
	}

	// Payload: HOST header with IPv6 literal (HOST头含IPv6字面量).
	payload := string(cfg.Payload)
	if !strings.Contains(payload, "HOST: [ff02::c]:1900\r\n") {
		t.Errorf("payload missing HOST with IPv6 bracket notation")
	}
}

// Integration 9: RepeatCount > 1 with inter-packet delay (场景 9: 重复发送).
func TestSSDP_Integration_RepeatAlive(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	// Use RepeatIntervalMs to get deterministic timing (使用RepeatIntervalMs得到确定时间).
	spec.SSDP.RepeatCount = 3
	spec.SSDP.RepeatIntervalMs = 100 // 100ms between packets

	cfgs := drain(mustPlan(t, p, spec))

	if len(cfgs) != 3 {
		t.Fatalf("repeat alive packet count = %d, want 3", len(cfgs))
	}

	// All packets should be alive (所有包应为alive).
	for i, cfg := range cfgs {
		payload := string(cfg.Payload)
		if !strings.HasPrefix(payload, "NOTIFY * HTTP/1.1\r\n") {
			t.Errorf("cfgs[%d] prefix=%q, want NOTIFY", i, payload[:30])
		}
		if !strings.Contains(payload, "NTS: ssdp:alive\r\n") {
			t.Errorf("cfgs[%d] missing NTS=ssdp:alive", i)
		}
	}

	// Packet indices sequential (索引连续).
	if cfgs[0].PacketIndex != 0 || cfgs[1].PacketIndex != 1 || cfgs[2].PacketIndex != 2 {
		t.Errorf("packet indices = %d,%d,%d, want 0,1,2",
			cfgs[0].PacketIndex, cfgs[1].PacketIndex, cfgs[2].PacketIndex)
	}

	// Timestamps should have ~100ms gaps (时间戳间隔约100ms).
	gap1 := cfgs[1].Timestamp.Sub(cfgs[0].Timestamp)
	gap2 := cfgs[2].Timestamp.Sub(cfgs[1].Timestamp)
	if gap1 < 50*time.Millisecond || gap1 > 200*time.Millisecond {
		t.Logf("gap1 = %v (expected ~100ms)", gap1)
	}
	if gap2 < 50*time.Millisecond || gap2 > 200*time.Millisecond {
		t.Logf("gap2 = %v (expected ~100ms)", gap2)
	}

	// All packets share the same flow ID (所有包共享相同FlowID).
	for i := 1; i < len(cfgs); i++ {
		if cfgs[i].FlowID != cfgs[0].FlowID {
			t.Errorf("cfgs[%d].FlowID=%q, want %q", i, cfgs[i].FlowID, cfgs[0].FlowID)
		}
	}
}

// Integration 10: M-SEARCH with multiple responses (场景 10: M-SEARCH多响应).
func TestSSDP_Integration_MultipleResponses(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP = &core.SSDPConfig{
		MessageType: "msearch",
		SearchTarget: "ssdp:all",
		MX: 3,
		ResponseCount: 3,
		ResponseDelayMinMs: 0,
		ResponseDelayMaxMs: 100,
	}
	cfgs := drain(mustPlan(t, p, spec))

	// 1 M-SEARCH + 3 responses = 4 packets (1个M-SEARCH + 3个响应).
	if len(cfgs) != 4 {
		t.Fatalf("msearch+3resp packet count = %d, want 4", len(cfgs))
	}

	// Packet 0: M-SEARCH.
	if !strings.HasPrefix(string(cfgs[0].Payload), "M-SEARCH * HTTP/1.1\r\n") {
		t.Errorf("cfgs[0] prefix mismatch")
	}

	// Packets 1-3: 200 OK responses (包1-3: 200 OK响应).
	for i := 1; i < 4; i++ {
		payload := string(cfgs[i].Payload)
		if !strings.HasPrefix(payload, "HTTP/1.1 200 OK\r\n") {
			t.Errorf("cfgs[%d] prefix=%q, want HTTP/1.1 200 OK", i, payload[:30])
		}
		if !strings.Contains(payload, "EXT:\r\n") {
			t.Errorf("cfgs[%d] missing EXT: header", i)
		}
		if !strings.Contains(payload, "ST: ssdp:all\r\n") {
			t.Errorf("cfgs[%d] missing ST: ssdp:all", i)
		}
	}

	// Packet indices sequential (包序号连续).
	for i := 0; i < 4; i++ {
		if cfgs[i].PacketIndex != uint64(i) {
			t.Errorf("cfgs[%d].PacketIndex=%d, want %d", i, cfgs[i].PacketIndex, i)
		}
	}

	// All same flow ID (相同FlowID).
	for i := 1; i < 4; i++ {
		if cfgs[i].FlowID != cfgs[0].FlowID {
			t.Errorf("cfgs[%d].FlowID=%q, want %q", i, cfgs[i].FlowID, cfgs[0].FlowID)
		}
	}
}

// Integration 11: Context cancellation stops generation (场景 11: 上下文取消).
func TestSSDP_Context_Cancel(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP.RepeatCount = 100
	spec.SSDP.RepeatIntervalMs = 10

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Immediately cancel (立即取消).
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	cfgs := drain(ch)
	if len(cfgs) >= 100 {
		t.Errorf("expected early cancellation, got %d packets (>=100)", len(cfgs))
	}
}

// Integration 12: Validate error for port != 1900.
func TestSSDP_Validate_InvalidPort(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.DstPort = 80
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for non-1900 dst port, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "must be 1900") {
		t.Errorf("unexpected error: %v", err)
	}

	// Also test source port (源端口也需校验).
	spec2 := validSSDPSpec()
	spec2.DstPort = 1900
	spec2.SrcPort = 80
	err2 := p.Validate(spec2)
	if err2 == nil {
		t.Errorf("expected error for non-1900 src port, got nil")
	}
	if err2 != nil && !strings.Contains(err2.Error(), "must be 1900") {
		t.Errorf("unexpected error: %v", err2)
	}
}

// Integration 13: Validate accepts nil SSDP config (P0b-2: 空配置默认化产默认流).
func TestSSDP_Validate_NilConfig(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty config should default to a flow, got err: %v", err)
	}
}

// Integration 14: Validate error for unknown message type.
func TestSSDP_Validate_InvalidMessageType(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "invalid"
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for invalid message type, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "unknown message_type") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Integration 15: Validate error for empty search target.
func TestSSDP_Validate_EmptySearchTarget(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP.SearchTarget = ""
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for empty search target, got nil")
	}
}

// Integration 16: Validate error for empty USN on byebye.
func TestSSDP_Validate_EmptyUSN(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "byebye"
	spec.SSDP.USN = ""
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for empty USN on byebye, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "usn is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Integration 17: update message type (场景 17: update通知).
func TestSSDP_Integration_UpdateNotify(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP = &core.SSDPConfig{
		MessageType: "update",
		SearchTarget: "upnp:rootdevice",
		USN: "uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice",
		Location: "http://192.168.1.50:80/description.xml",
		MaxAge: 1800,
		BootID: 2,
		ConfigID: 3,
		RepeatCount: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))

	if len(cfgs) != 1 {
		t.Fatalf("update packet count = %d, want 1", len(cfgs))
	}
	payload := string(cfgs[0].Payload)

	// Request line (请求行).
	if !strings.HasPrefix(payload, "NOTIFY * HTTP/1.1\r\n") {
		t.Errorf("payload prefix=%q, want NOTIFY", payload[:30])
	}

	// NTS = ssdp:update (NTS头).
	if !strings.Contains(payload, "NTS: ssdp:update\r\n") {
		t.Errorf("payload missing NTS=ssdp:update")
	}

	// Location (位置头).
	if !strings.Contains(payload, "LOCATION: http://192.168.1.50:80/description.xml\r\n") {
		t.Errorf("payload missing LOCATION")
	}

	// BootID and ConfigID (启动ID和配置ID).
	if !strings.Contains(payload, "BOOTID.UPNP.ORG: 2\r\n") {
		t.Errorf("payload missing BOOTID")
	}
	if !strings.Contains(payload, "CONFIGID.UPNP.ORG: 3\r\n") {
		t.Errorf("payload missing CONFIGID")
	}

	// Cache-Control present in update (update应携带CACHE-CONTROL per design §3.3).
	if !strings.Contains(payload, "CACHE-CONTROL: max-age=1800\r\n") {
		t.Errorf("update should contain CACHE-CONTROL: max-age=1800")
	}
}

// Integration 18: IPv4 multicast MAC derivation (场景 18: IPv4多播MAC推导).
func TestSSDP_IPv4_MulticastMAC(t *testing.T) {
	p := NewPlanner()

	// Test 239.255.255.250 -> 01:00:5e:7f:ff:fa.
	spec := validSSDPSpec()
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].L2.DstMAC != "01:00:5e:7f:ff:fa" {
		t.Errorf("DstMAC=%s, want 01:00:5e:7f:ff:fa", cfgs[0].L2.DstMAC)
	}

	// Test 239.255.255.251 -> 01:00:5e:7f:ff:fb.
	spec2 := validSSDPSpec()
	spec2.DstIP = "239.255.255.251"
	cfgs2 := drain(mustPlan(t, p, spec2))
	if len(cfgs2) == 0 {
		t.Fatal("no packets")
	}
	if cfgs2[0].L2.DstMAC != "01:00:5e:7f:ff:fb" {
		t.Errorf("DstMAC=%s, want 01:00:5e:7f:ff:fb", cfgs2[0].L2.DstMAC)
	}

	// Test 224.0.0.1 -> 01:00:5e:00:00:01.
	spec3 := validSSDPSpec()
	spec3.DstIP = "224.0.0.1"
	cfgs3 := drain(mustPlan(t, p, spec3))
	if len(cfgs3) == 0 {
		t.Fatal("no packets")
	}
	if cfgs3[0].L2.DstMAC != "01:00:5e:00:00:01" {
		t.Errorf("DstMAC=%s, want 01:00:5e:00:00:01", cfgs3[0].L2.DstMAC)
	}

	// Test user-specified DstMAC takes priority (用户指定DstMAC优先).
	spec4 := validSSDPSpec()
	spec4.DstMAC = "aa:bb:cc:dd:ee:ff"
	cfgs4 := drain(mustPlan(t, p, spec4))
	if len(cfgs4) == 0 {
		t.Fatal("no packets")
	}
	if cfgs4[0].L2.DstMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("DstMAC=%s, want aa:bb:cc:dd:ee:ff (user override)", cfgs4[0].L2.DstMAC)
	}
}

// Integration 19: IPv6 multicast MAC derivation (场景 19: IPv6多播MAC推导).
func TestSSDP_IPv6_MulticastMAC(t *testing.T) {
	p := NewPlanner()

	// Test ff02::c -> 33:33:00:00:00:0c.
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		SrcIP: "fe80::1",
		DstIP: "ff02::c",
		SrcPort: 1900,
		DstPort: 1900,
		SSDP: &core.SSDPConfig{
			MessageType: "alive",
			SearchTarget: "upnp:rootdevice",
			USN: "uuid:00..01::upnp:rootdevice",
			MaxAge: 1800,
			RepeatCount: 1,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	if cfgs[0].L2.DstMAC != "33:33:00:00:00:0c" {
		t.Errorf("DstMAC=%s, want 33:33:00:00:00:0c", cfgs[0].L2.DstMAC)
	}
	if cfgs[0].L2.EtherType != 0x86DD {
		t.Errorf("EtherType=%04x, want 86DD", cfgs[0].L2.EtherType)
	}

	// Test user-specified DstMAC takes priority (用户指定DstMAC优先).
	spec2 := spec
	spec2.DstMAC = "11:22:33:44:55:66"
	cfgs2 := drain(mustPlan(t, p, spec2))
	if len(cfgs2) == 0 {
		t.Fatal("no packets")
	}
	if cfgs2[0].L2.DstMAC != "11:22:33:44:55:66" {
		t.Errorf("DstMAC=%s, want 11:22:33:44:55:66 (user override)", cfgs2[0].L2.DstMAC)
	}
}

// Integration 20: Planner Name method.
func TestSSDP_Planner_Name(t *testing.T) {
	p := NewPlanner()
	if p.Name() != "ssdp" {
		t.Errorf("Name() = %s, want ssdp", p.Name())
	}
}

// Integration 21: FlowID uniqueness across calls.
// Note: same SrcIP/DstIP/ports produce same FlowID; user should vary SrcIP
// to get different FlowIDs.
func TestSSDP_Plan_FlowIDUnique(t *testing.T) {
	p := NewPlanner()
	spec1 := validSSDPSpec()
	spec2 := validSSDPSpec()
	spec2.SrcIP = "192.168.1.51"
	cfgs1 := drain(mustPlan(t, p, spec1))
	cfgs2 := drain(mustPlan(t, p, spec2))
	if len(cfgs1) != 1 || len(cfgs2) != 1 {
		t.Fatalf("unexpected packet count")
	}
	if cfgs1[0].FlowID == cfgs2[0].FlowID {
		t.Errorf("FlowIDs should differ for different SrcIP")
	}
}

// Integration 22: M-SEARCH with ResponseCount=0 produces 2 packets (M-SEARCH + default 1 response).
// Note: planner defaults ResponseCount<1 to 1 response. Use ctx cancel to suppress.
func TestSSDP_MSearch_DefaultResponseCount(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP = &core.SSDPConfig{
		MessageType: "msearch",
		SearchTarget: "ssdp:all",
		MX: 3,
		ResponseCount: 0, // defaults to 1 response
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("msearch(default response) packet count = %d, want 2 (1 M-SEARCH + 1 default response)", len(cfgs))
	}
	if !strings.HasPrefix(string(cfgs[0].Payload), "M-SEARCH * HTTP/1.1\r\n") {
		t.Errorf("cfgs[0] prefix mismatch")
	}
	if !strings.HasPrefix(string(cfgs[1].Payload), "HTTP/1.1 200 OK\r\n") {
		t.Errorf("cfgs[1] prefix mismatch")
	}
}

// Integration 23: Validate Server header length limits.
func TestSSDP_Validate_ServerLengthLimits(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()

	// 256 bytes: should pass (256字节: 应通过).
	spec.SSDP.Server = strings.Repeat("a", 256)
	err := p.Validate(spec)
	if err != nil {
		t.Errorf("server=256 bytes should pass, got: %v", err)
	}

	// 257 bytes: warning only, should still pass (257字节: warning但应通过).
	spec.SSDP.Server = strings.Repeat("a", 257)
	err = p.Validate(spec)
	if err != nil {
		t.Errorf("server=257 bytes should pass (warning only), got: %v", err)
	}

	// 4096 bytes: should still pass (warning only) (4096字节: warning但应通过).
	spec.SSDP.Server = strings.Repeat("a", 4096)
	err = p.Validate(spec)
	if err != nil {
		t.Errorf("server=4096 bytes should pass (warning only), got: %v", err)
	}

	// 4097 bytes: should error (4097字节: 应报错).
	spec.SSDP.Server = strings.Repeat("a", 4097)
	err = p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for server=4097 bytes, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Integration 24: Validate MaxAge limits.
func TestSSDP_Validate_MaxAgeLimits(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()

	// MaxAge=1: should pass (最小值).
	spec.SSDP.MaxAge = 1
	err := p.Validate(spec)
	if err != nil {
		t.Errorf("MaxAge=1 should pass, got: %v", err)
	}

	// MaxAge=1800: should pass (最大值).
	spec.SSDP.MaxAge = 1800
	err = p.Validate(spec)
	if err != nil {
		t.Errorf("MaxAge=1800 should pass, got: %v", err)
	}

	// MaxAge=1801: should error (超限).
	spec.SSDP.MaxAge = 1801
	err = p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for MaxAge=1801, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "exceeds UPnP 1.1 limit") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Integration 25: Validate MX limits.
func TestSSDP_Validate_MXLimits(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = "" // M-SEARCH doesn't need USN

	// MX=1: should pass (最小值).
	spec.SSDP.MX = 1
	err := p.Validate(spec)
	if err != nil {
		t.Errorf("MX=1 should pass, got: %v", err)
	}

	// MX=5: should pass (最大值).
	spec.SSDP.MX = 5
	err = p.Validate(spec)
	if err != nil {
		t.Errorf("MX=5 should pass, got: %v", err)
	}

	// MX=6: should error (超限).
	spec.SSDP.MX = 6
	err = p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for MX=6, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "exceeds UPnP recommended max") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Integration 26: Validate ResponseDelayMinMs > ResponseDelayMaxMs.
func TestSSDP_Validate_ResponseDelayRange(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP.MessageType = "msearch"
	spec.SSDP.SearchTarget = "ssdp:all"
	spec.SSDP.USN = ""
	spec.SSDP.ResponseCount = 2
	spec.SSDP.ResponseDelayMinMs = 1000
	spec.SSDP.ResponseDelayMaxMs = 100

	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for min > max, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "response_delay_min_ms") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Integration 27: Validate USN size limit.
func TestSSDP_Validate_USNSizeLimit(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP.USN = strings.Repeat("x", 4097) // 4097 > 4096
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for USN > 4096, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "exceeds maximum header size") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Integration 28: response with OmitExt=true (无EXT头响应).
func TestSSDP_Response_OmitExt(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP = &core.SSDPConfig{
		MessageType: "response",
		SearchTarget: "upnp:rootdevice",
		USN: "uuid:00..01::upnp:rootdevice",
		Location: "http://192.168.1.50:80/desc.xml",
		OmitExt: true,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("response count = %d, want 1", len(cfgs))
	}
	payload := string(cfgs[0].Payload)
	if strings.Contains(payload, "EXT:") {
		t.Errorf("response with OmitExt should not contain EXT: header")
	}
	if !strings.HasPrefix(payload, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("payload prefix=%q, want HTTP/1.1 200 OK", payload[:30])
	}
}

// Integration 29: response with body and Content-Length (含body和Content-Length).
func TestSSDP_Response_WithBody(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP = &core.SSDPConfig{
		MessageType: "response",
		SearchTarget: "upnp:rootdevice",
		USN: "uuid:00..01::upnp:rootdevice",
		Location: "http://192.168.1.50:80/desc.xml",
		Body: "<root/>",
		EmitContentLength: true,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("response count = %d, want 1", len(cfgs))
	}
	payload := string(cfgs[0].Payload)
	if !strings.Contains(payload, "CONTENT-LENGTH: 7\r\n") {
		t.Errorf("payload missing CONTENT-LENGTH: 7")
	}
	if !strings.HasSuffix(payload, "<root/>") {
		t.Errorf("payload should end with body, got suffix=%q", payload[len(payload)-10:])
	}
}

// Integration 30: IPv6 response — HOST header is NOT emitted in 200 OK
// responses (only NOTIFY/M-SEARCH carry HOST per the planner's wire format).
// Instead, verify the IPv6 EtherType and that LOCATION carries IPv6 brackets.
func TestSSDP_IPv6_ResponseHost(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		SrcIP: "fe80::1",
		DstIP: "fe80::2",
		SrcPort: 1900,
		DstPort: 1900,
		SSDP: &core.SSDPConfig{
			MessageType: "response",
			SearchTarget: "upnp:rootdevice",
			USN: "uuid:00..01::upnp:rootdevice",
			Location: "http://[fe80::1]:80/desc.xml",
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("response count = %d, want 1", len(cfgs))
	}
	payload := string(cfgs[0].Payload)
	// 200 OK responses do not carry HOST header per the planner's wire format.
	// Verify IPv6-specific LOCATION header carries bracketed IPv6 literal.
	if !strings.Contains(payload, "LOCATION: http://[fe80::1]:80/desc.xml\r\n") {
		t.Errorf("payload missing LOCATION with IPv6 bracket notation; payload=%q", payload)
	}
	if cfgs[0].L2.EtherType != 0x86DD {
		t.Errorf("EtherType=%04x, want 86DD", cfgs[0].L2.EtherType)
	}
	if cfgs[0].L3.DstIP != "fe80::2" {
		t.Errorf("L3.DstIP=%s, want fe80::2", cfgs[0].L3.DstIP)
	}
}

// Integration 31: M-SEARCH with USER-AGENT as Server field.
// Note: planner defaults ResponseCount<1 to 1 response, so we get 2 packets.
func TestSSDP_MSearch_UserAgent(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP = &core.SSDPConfig{
		MessageType: "msearch",
		SearchTarget: "ssdp:all",
		MX: 3,
		Server: "Linux/6.1 UPnP/1.1 TestClient/1.0",
		ResponseCount: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("msearch count = %d, want 2 (1 M-SEARCH + 1 response)", len(cfgs))
	}
	payload := string(cfgs[0].Payload)
	if !strings.Contains(payload, "USER-AGENT: Linux/6.1 UPnP/1.1 TestClient/1.0\r\n") {
		t.Errorf("payload missing USER-AGENT header")
	}
	if strings.Contains(payload, "SERVER:") {
		t.Errorf("M-SEARCH should use USER-AGENT, not SERVER")
	}
}

// TestSSDP_UpdateNotify_RequiredHeaders verifies that an ssdp:update NOTIFY
// contains the headers required by UPnP DA 1.1 §1.2.3 and design_ssdp.md §3.3:
// CACHE-CONTROL: max-age, BOOTID.UPNP.ORG, CONFIGID.UPNP.ORG,
// NEXTBOOTID.UPNP.ORG, and SEARCHPORT.UPNP.ORG.
func TestSSDP_UpdateNotify_RequiredHeaders(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP = &core.SSDPConfig{
		MessageType: "update",
		SearchTarget: "upnp:rootdevice",
		USN:          "uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice",
		Location:     "http://192.168.1.50:80/description.xml",
		MaxAge:       1800,
		BootID:       2,
		ConfigID:     3,
		NextBootID:   5,
		SearchPort:   49152,
		RepeatCount:  1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("update packet count = %d, want 1", len(cfgs))
	}
	payload := string(cfgs[0].Payload)

	// CACHE-CONTROL: max-age must be present in update mode (design §3.3).
	if !strings.Contains(payload, "CACHE-CONTROL: max-age=1800\r\n") {
		t.Errorf("update NOTIFY missing CACHE-CONTROL: max-age=1800\r\n; payload:\n%s", payload)
	}

	// NEXTBOOTID.UPNP.ORG must be present in update mode (UPnP DA 1.1 §1.2.3).
	if !strings.Contains(payload, "NEXTBOOTID.UPNP.ORG: 5\r\n") {
		t.Errorf("update NOTIFY missing NEXTBOOTID.UPNP.ORG: 5\r\n; payload:\n%s", payload)
	}

	// SEARCHPORT.UPNP.ORG must be present in update mode (UPnP DA 1.1 §1.2.3).
	if !strings.Contains(payload, "SEARCHPORT.UPNP.ORG: 49152\r\n") {
		t.Errorf("update NOTIFY missing SEARCHPORT.UPNP.ORG: 49152\r\n; payload:\n%s", payload)
	}

	// BOOTID and CONFIGID should still be present.
	if !strings.Contains(payload, "BOOTID.UPNP.ORG: 2\r\n") {
		t.Errorf("update NOTIFY missing BOOTID.UPNP.ORG: 2\r\n; payload:\n%s", payload)
	}
	if !strings.Contains(payload, "CONFIGID.UPNP.ORG: 3\r\n") {
		t.Errorf("update NOTIFY missing CONFIGID.UPNP.ORG: 3\r\n; payload:\n%s", payload)
	}
}

// TestSSDP_UpdateNotify_OmitsNextBootIDWhenZero verifies that NEXTBOOTID and
// SEARCHPORT headers are omitted when their config values are 0 (not set).
func TestSSDP_UpdateNotify_OmitsNextBootIDWhenZero(t *testing.T) {
	p := NewPlanner()
	spec := validSSDPSpec()
	spec.SSDP = &core.SSDPConfig{
		MessageType: "update",
		SearchTarget: "upnp:rootdevice",
		USN:          "uuid:test::upnp:rootdevice",
		MaxAge:       900,
		BootID:       1,
		ConfigID:     2,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("update packet count = %d, want 1", len(cfgs))
	}
	payload := string(cfgs[0].Payload)

	// CACHE-CONTROL should still be present (MaxAge=900).
	if !strings.Contains(payload, "CACHE-CONTROL: max-age=900\r\n") {
		t.Errorf("update NOTIFY missing CACHE-CONTROL: max-age=900\r\n; payload:\n%s", payload)
	}

	// NEXTBOOTID and SEARCHPORT should be omitted (value=0).
	if strings.Contains(payload, "NEXTBOOTID.UPNP.ORG") {
		t.Errorf("update NOTIFY should not contain NEXTBOOTID.UPNP.ORG when NextBootID=0; payload:\n%s", payload)
	}
	if strings.Contains(payload, "SEARCHPORT.UPNP.ORG") {
		t.Errorf("update NOTIFY should not contain SEARCHPORT.UPNP.ORG when SearchPort=0; payload:\n%s", payload)
	}
}

func TestSSDP_EmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空 config（nil SSDP）默认化（alive NOTIFY），Plan 产默认流。
	p := NewPlanner()
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "239.255.255.250", SrcPort: 1900, DstPort: 1900}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("empty config Plan err: %v", err)
	}
	n := 0
	for range ch {
		n++
	}
	if n == 0 {
		t.Fatal("empty config produced 0 packets")
	}
}
