package swarm

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func cfg() *core.SwarmConfig { return &core.SwarmConfig{} }

func mustFrame(t *testing.T, e *core.SwarmEvent, c *core.SwarmConfig, session uint64, stream uint32) []byte {
	t.Helper()
	f, err := BuildEventFrame(e, c, session, stream)
	if err != nil {
		t.Fatalf("BuildEventFrame(%s): %v", e.Kind, err)
	}
	return f
}

// §3.1 Discovery：Magic SWD1、Length=45+endpoints、Version/Kind、Nonce、
// NodeID 32B、Endpoint AF|Port|Addr、FrameEnd。
func TestDiscoveryFrame(t *testing.T) {
	nodeID, _ := hex.DecodeString(defaultNodeID)
	// endpoint Address 是 4/16 字节的裸文本（AF 决定宽度）。
	ep := core.SwarmEndpoint{AddressFamily: 1, Port: 1634, Address: []byte{10, 0, 0, 9}}
	f, err := BuildDiscoveryFrame(discPing, 0x1122334455667788, nodeID, []core.SwarmEndpoint{ep})
	if err != nil {
		t.Fatalf("BuildDiscoveryFrame: %v", err)
	}
	want := hex.EncodeToString([]byte("SWD1")) + "0034" + "01" + "01" + "1122334455667788" + defaultNodeID + "01" + "01" + "0662" + "0a000009" + "ae5a"
	if got := hex.EncodeToString(f); got != want {
		t.Fatalf("discovery ping = %s, want %s", got, want)
	}
	if len(f) != 58 { // magic4 + Length2 + 52
		t.Fatalf("discovery frame = %d bytes, want 58", len(f))
	}
	// pong kind 0x02。
	f2, err := BuildDiscoveryFrame(discPong, 1, nodeID, nil)
	if err != nil {
		t.Fatalf("pong: %v", err)
	}
	if f2[7] != discPong || hex.EncodeToString(f2[0:4]) != hex.EncodeToString([]byte("SWD1")) {
		t.Fatalf("pong header wrong: %x", f2[:8])
	}
	// endpoint AF 非法拒绝。
	if _, err := BuildDiscoveryFrame(discPing, 1, nodeID, []core.SwarmEndpoint{{AddressFamily: 7}}); err == nil {
		t.Fatalf("invalid endpoint AF must be rejected")
	}
}

// §3.2 Storage：Magic SWS1、Length=26+N（不含自身）、SessionID/StreamID/
// CorrelationID 头、最小帧 26。
func TestStorageFrameHeader(t *testing.T) {
	f := mustFrame(t, &core.SwarmEvent{Kind: "ping", CorrelationID: 7}, cfg(), 9, 3)
	want := hex.EncodeToString([]byte("SWS1")) + "0000001a" + "01" + "30" + "0001" +
		"0000000000000009" + "00000003" + "0000000000000007" + "ae5a"
	if got := hex.EncodeToString(f); got != want {
		t.Fatalf("ping frame = %s, want %s", got, want)
	}
	if len(f) != 34 { // magic4 + Length4 + 26
		t.Fatalf("min frame = %d bytes, want 34", len(f))
	}
}

// §4 HELLO：profile/capability/node_id/nonce；HELLO_OK 回显 + 限制。
func TestHelloFrames(t *testing.T) {
	f := mustFrame(t, &core.SwarmEvent{Kind: "hello", Nonce: 1}, cfg(), 0, 0)
	// TLV 头 6B：profile 22 + capability 21 + node_id 38 + nonce 14 = 95 → Length 121=0x79
	want := hex.EncodeToString([]byte("SWS1")) + "00000079" + "01" + "10" + "0001" +
		"0000000000000000" + "00000000" + "0000000000000000" +
		"0001" + "00000010" + hex.EncodeToString([]byte("swarm_storage_v1")) +
		"0002" + "0000000f" + hex.EncodeToString([]byte(defaultCapability)) +
		"0003" + "00000020" + defaultNodeID +
		"0004" + "00000008" + "0000000000000001" + "ae5a"
	if got := hex.EncodeToString(f); got != want {
		t.Fatalf("hello frame = %s, want %s", got, want)
	}
	ok := mustFrame(t, &core.SwarmEvent{Kind: "hello_ok"}, cfg(), 0, 0)
	// TLV 头 6B：profile 22 + max_frame 10 + session_limit 8 + heartbeat 8 = 48 → Length 74=0x4a
	wantOK := hex.EncodeToString([]byte("SWS1")) + "0000004a" + "01" + "11" + "0002" +
		"0000000000000000" + "00000000" + "0000000000000000" +
		"0001" + "00000010" + hex.EncodeToString([]byte("swarm_storage_v1")) +
		"0011" + "00000004" + "00001000" +
		"0010" + "00000002" + "0008" +
		"0012" + "00000002" + "0000" + "ae5a"
	if got := hex.EncodeToString(ok); got != wantOK {
		t.Fatalf("hello_ok frame = %s, want %s", got, wantOK)
	}
}

// §4 STORE/STORE_OK：chunk_address 32B + chunk_size + chunk_payload；
// size != payload 长度拒绝。
func TestStoreFrames(t *testing.T) {
	payload := strings.Repeat("A", 64)
	f := mustFrame(t, &core.SwarmEvent{Kind: "store", CorrelationID: 5, ChunkSize: 64, Payload: []byte(payload)}, cfg(), 1, 1)
	if hex.EncodeToString(f[0:4]) != hex.EncodeToString([]byte("SWS1")) || f[9] != kindStore {
		t.Fatalf("store header wrong: %x", f[:8])
	}
	// chunk_size 0 → 从 payload 推导（64）。
	f2 := mustFrame(t, &core.SwarmEvent{Kind: "store", CorrelationID: 5, Payload: []byte(payload)}, cfg(), 1, 1)
	if hex.EncodeToString(f) != hex.EncodeToString(f2) {
		t.Fatalf("derived size must match explicit 64")
	}
	// 显式 size 与 payload 不一致 → 生成期错误。
	_, err := BuildEventFrame(&core.SwarmEvent{Kind: "store", CorrelationID: 7, ChunkSize: 10, Payload: []byte("abc")}, cfg(), 1, 1)
	if err == nil || !strings.Contains(err.Error(), "chunk") {
		t.Fatalf("size mismatch must be rejected: %v", err)
	}
}

// §4 RETRIEVE/CHUNK：地址携带、CHUNK 分片 TLV + fragment flag。
func TestRetrieveChunkFrames(t *testing.T) {
	r := mustFrame(t, &core.SwarmEvent{Kind: "retrieve", CorrelationID: 8}, cfg(), 1, 2)
	// TLV 头 6B：Length = 26 + 38 = 64 = 0x40
	if got := hex.EncodeToString(r[4:8]); got != "00000040" {
		t.Fatalf("retrieve length = %s, want 00000040", got)
	}
	c := mustFrame(t, &core.SwarmEvent{Kind: "chunk", CorrelationID: 8, FragmentIndex: 0, FragmentCount: 2,
		Sequence: 1, Payload: []byte("hello")}, cfg(), 1, 2)
	// fragment flag 0x0008 | response 0x0002 = 0x000a（flags 在 [10:12]）
	if c[10] != 0x00 || c[11] != 0x0a {
		t.Fatalf("chunk flags = %x, want 000a", c[10:12])
	}
	if !strings.Contains(hex.EncodeToString(c), "0044" + "00000002" + "0000") {
		t.Fatalf("fragment index TLV missing: %s", hex.EncodeToString(c))
	}
}

// §4 MANIFEST + MESSAGE_ACK + ERROR。
func TestManifestAckErrorFrames(t *testing.T) {
	m := mustFrame(t, &core.SwarmEvent{Kind: "manifest", CorrelationID: 3, ManifestRoot: defaultManifestRoot,
		ManifestEntry: []byte{0xde, 0xad}}, cfg(), 1, 1)
	if !strings.Contains(hex.EncodeToString(m), "0030" + "00000020" + defaultManifestRoot) {
		t.Fatalf("manifest root TLV missing")
	}
	a := mustFrame(t, &core.SwarmEvent{Kind: "message_ack", AckFor: 42, AckStatus: 0}, cfg(), 1, 1)
	if !strings.Contains(hex.EncodeToString(a), "0042" + "00000008" + "000000000000002a") {
		t.Fatalf("ack_for TLV missing")
	}
	e := mustFrame(t, &core.SwarmEvent{Kind: "error", ErrorCode: 5, ErrorText: "no"}, cfg(), 1, 1)
	if !strings.Contains(hex.EncodeToString(e), "00f0" + "00000002" + "0005") {
		t.Fatalf("error_code TLV missing")
	}
}

// §3/§7 边界：显式 Type/Flags 覆盖、frame_max 守卫、uint64 corr。
func TestOverridesAndFrameMax(t *testing.T) {
	f := mustFrame(t, &core.SwarmEvent{Kind: "ping", Type: 0x7f, Flags: 0x0002}, cfg(), 1, 1)
	if f[9] != 0x7f || f[10] != 0x00 || f[11] != 0x02 {
		t.Fatalf("override type/flags = %x", f[9:12])
	}
	big := &core.SwarmConfig{FrameMax: 32}
	frame, err := BuildEventFrame(&core.SwarmEvent{Kind: "hello"}, big, 0, 0)
	if err != nil {
		t.Fatalf("hello build: %v", err)
	}
	if err := CheckFrameMax(frame, 32); err == nil {
		t.Fatalf("hello must exceed frame_max 32")
	}
	if err := CheckFrameMax(frame, 0); err != nil {
		t.Fatalf("default frame_max must accept: %v", err)
	}
}

func anchorErr(t *testing.T, c *core.SwarmConfig, anchors ...string) error {
	t.Helper()
	err := ValidateConfig(c)
	if err == nil {
		t.Fatalf("expected rejection containing %v, got nil", anchors)
	}
	for _, a := range anchors {
		if !strings.Contains(err.Error(), a) {
			t.Fatalf("error %q missing anchor %q", err.Error(), a)
		}
	}
	return err
}

// §5 状态机正例：握手 + 会话 + 双流交织 + 分片 + 确认。
func TestValidateHappyPath(t *testing.T) {
	c := &core.SwarmConfig{Connections: []core.SwarmConnection{{
		Events: []core.SwarmEvent{{Kind: "hello"}, {Kind: "hello_ok"}, {Kind: "auth"}, {Kind: "auth_ok"}},
		Sessions: []core.SwarmSession{{SessionID: 1,
			Events: []core.SwarmEvent{{Kind: "open_session"}, {Kind: "open_ok"}},
			Streams: []core.SwarmStream{
				{StreamID: 1, Events: []core.SwarmEvent{
					{Kind: "store", CorrelationID: 1, ChunkSize: 2, Payload: []byte("ab"), DeliveryMode: 1, MessageID: 11},
					{Kind: "message_ack", AckFor: 11},
				}},
				{StreamID: 2, Events: []core.SwarmEvent{
					{Kind: "retrieve", CorrelationID: 2},
					{Kind: "chunk", CorrelationID: 2, FragmentIndex: 0, FragmentCount: 2, Payload: []byte("x")},
					{Kind: "chunk", CorrelationID: 2, FragmentIndex: 1, FragmentCount: 2, Payload: []byte("y")},
				}},
			}}},
	}}}
	if err := ValidateConfig(c); err != nil {
		t.Fatalf("happy path rejected: %v", err)
	}
	// discovery 平面。
	if err := ValidateConfig(&core.SwarmConfig{Discovery: &core.SwarmDiscovery{
		Events: []core.SwarmEvent{{Kind: "ping", Nonce: 1}, {Kind: "pong", Nonce: 1}}}}); err != nil {
		t.Fatalf("discovery rejected: %v", err)
	}
}

// §5/§9 负例矩阵（锚词 = 用例契约）。
func TestValidateNegatives(t *testing.T) {
	hs := func() []core.SwarmEvent {
		return []core.SwarmEvent{{Kind: "hello"}, {Kind: "hello_ok"}, {Kind: "auth"}, {Kind: "auth_ok"}}
	}
	sessN := func(ev ...core.SwarmEvent) *core.SwarmConfig {
		return &core.SwarmConfig{Connections: []core.SwarmConnection{{
			Events: hs(), Sessions: []core.SwarmSession{{SessionID: 1, Events: ev}}},
		}}
	}
	// 首帧非 hello。
	anchorErr(t, &core.SwarmConfig{Connections: []core.SwarmConnection{{
		Events: []core.SwarmEvent{{Kind: "auth"}}}}}, "hello")
	// auth 未完成即 open_session。
	anchorErr(t, &core.SwarmConfig{Connections: []core.SwarmConnection{{
		Events:   []core.SwarmEvent{{Kind: "hello"}, {Kind: "hello_ok"}},
		Sessions: []core.SwarmSession{{SessionID: 1, Events: []core.SwarmEvent{{Kind: "open_session"}}}}}}}, "auth", "session")
	// session 未开先 store。
	anchorErr(t, &core.SwarmConfig{Connections: []core.SwarmConnection{{
		Events:   hs(),
		Sessions: []core.SwarmSession{{SessionID: 1, Events: []core.SwarmEvent{{Kind: "store", CorrelationID: 1, Payload: []byte("x")}}}}}}}, "session")
	// chunk 无 pending retrieve。
	anchorErr(t, sessN([]core.SwarmEvent{{Kind: "open_session"}, {Kind: "open_ok"},
		{Kind: "chunk", CorrelationID: 9}}...), "correlation", "chunk")
	// store_ok 无 pending store。
	anchorErr(t, sessN([]core.SwarmEvent{{Kind: "open_session"}, {Kind: "open_ok"},
		{Kind: "store_ok", CorrelationID: 1}}...), "correlation")
	// ack 未知 message。
	anchorErr(t, sessN([]core.SwarmEvent{{Kind: "open_session"}, {Kind: "open_ok"},
		{Kind: "message_ack", AckFor: 9}}...), "ack", "correlation")
	// ack-required 未确认。
	anchorErr(t, sessN([]core.SwarmEvent{{Kind: "open_session"}, {Kind: "open_ok"},
		{Kind: "store", CorrelationID: 1, Payload: []byte("x"), DeliveryMode: 1}}...), "ack")
	// 分片 index 越界。
	anchorErr(t, sessN([]core.SwarmEvent{{Kind: "open_session"}, {Kind: "open_ok"},
		{Kind: "retrieve", CorrelationID: 2},
		{Kind: "chunk", CorrelationID: 2, FragmentIndex: 3, FragmentCount: 2}}...), "fragment", "reassembly")
	// 分片重复 index。
	anchorErr(t, sessN([]core.SwarmEvent{{Kind: "open_session"}, {Kind: "open_ok"},
		{Kind: "retrieve", CorrelationID: 2},
		{Kind: "chunk", CorrelationID: 2, FragmentIndex: 0, FragmentCount: 2},
		{Kind: "chunk", CorrelationID: 2, FragmentIndex: 0, FragmentCount: 2}}...), "fragment")
	// chunk size 不一致。
	anchorErr(t, sessN([]core.SwarmEvent{{Kind: "open_session"}, {Kind: "open_ok"},
		{Kind: "store", CorrelationID: 1, ChunkSize: 10, Payload: []byte("abc")}}...), "chunk", "length")
	// close 后业务帧。
	anchorErr(t, sessN([]core.SwarmEvent{{Kind: "open_session"}, {Kind: "open_ok"},
		{Kind: "close"}, {Kind: "close_ok"}, {Kind: "ping"}}...), "session")
	// session id 0。
	anchorErr(t, &core.SwarmConfig{Connections: []core.SwarmConnection{{
		Events:   hs(),
		Sessions: []core.SwarmSession{{Events: []core.SwarmEvent{{Kind: "open_session"}}}}}}}, "session")
	// discovery 平面混入 storage kind。
	anchorErr(t, &core.SwarmConfig{Discovery: &core.SwarmDiscovery{
		Events: []core.SwarmEvent{{Kind: "store"}}}}, "frame", "transport")
	// 双平面混装。
	anchorErr(t, &core.SwarmConfig{Discovery: &core.SwarmDiscovery{Events: []core.SwarmEvent{{Kind: "ping"}}},
		Connections: []core.SwarmConnection{{Events: []core.SwarmEvent{{Kind: "hello"}}}}}, "transport")
	// node_id 非法。
	anchorErr(t, &core.SwarmConfig{NodeIDHex: "zz", Discovery: &core.SwarmDiscovery{
		Events: []core.SwarmEvent{{Kind: "ping"}}}}, "node")
	// 未知 profile。
	anchorErr(t, &core.SwarmConfig{Profile: "bogus"}, "profile")
	// 空事件。
	anchorErr(t, &core.SwarmConfig{Connections: []core.SwarmConnection{{}}}, "hello")
}

// §8/§9 wire_fault 与端口/空配置校验。
func TestValidateWireFaultAndPort(t *testing.T) {
	for kind, anchor := range map[string]string{
		"bad_magic":      "frame",
		"bad_version":    "version",
		"unknown_kind":   "frame",
		"reserved_flags": "frame",
		"length_overrun": "length",
		"bad_frame_end":  "frame",
	} {
		c := &core.SwarmConfig{WireFault: kind, Discovery: &core.SwarmDiscovery{
			Events: []core.SwarmEvent{{Kind: "ping"}}}}
		anchorErr(t, c, anchor)
	}
	if err := ValidateConfig(&core.SwarmConfig{WireFault: "nope", Discovery: &core.SwarmDiscovery{
		Events: []core.SwarmEvent{{Kind: "ping"}}}}); err == nil {
		t.Fatalf("unknown wire_fault must be rejected")
	}
	if err := ValidateSpec(&core.FlowSpec{Swarm: &core.SwarmConfig{}, DstPort: 1635}); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("port validation = %v", err)
	}
	// 空配置（双平面皆空）必须拒绝——无法安全默认化（默认平面取决于
	// 载体链），静默 0 包是被禁止的。
	err := ValidateSpec(&core.FlowSpec{Swarm: &core.SwarmConfig{}})
	if err == nil || !strings.Contains(err.Error(), "hello") {
		t.Fatalf("empty swarm config must be rejected: %v", err)
	}
}

// 生成器：平面/载体错配拒绝。
func TestGeneratePlaneMismatch(t *testing.T) {
	g := &SwarmGenerator{}
	// udp 链 + storage 配置 → 拒绝。
	err := g.Generate(t.Context(), &layers.GenRequest{
		Chain:   []layers.Layer{{Name: "ip"}, {Name: "udp"}, {Name: "swarm"}},
		Meta:    layers.FlowMeta{Swarm: &core.SwarmConfig{Connections: []core.SwarmConnection{{Events: []core.SwarmEvent{{Kind: "hello"}}}}}},
		EmitMsg: func(layers.MessageEvent) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "transport") {
		t.Fatalf("udp chain with storage config must be rejected: %v", err)
	}
	// tcp 链 + discovery 配置 → 拒绝。
	err = g.Generate(t.Context(), &layers.GenRequest{
		Chain:   []layers.Layer{{Name: "ip"}, {Name: "tcp"}, {Name: "swarm"}},
		Meta:    layers.FlowMeta{Swarm: &core.SwarmConfig{Discovery: &core.SwarmDiscovery{Events: []core.SwarmEvent{{Kind: "ping"}}}}},
		EmitMsg: func(layers.MessageEvent) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "transport") {
		t.Fatalf("tcp chain with discovery config must be rejected: %v", err)
	}
}

// 生成器冒烟：discovery 逐 datagram 发射、storage 带 SrcPort 会话边界。
func TestGenerateEvents(t *testing.T) {
	g := &SwarmGenerator{}
	var evs []layers.MessageEvent
	dc := &core.SwarmConfig{Discovery: &core.SwarmDiscovery{SrcPort: 42052,
		Events: []core.SwarmEvent{{Kind: "ping", Nonce: 1}, {Kind: "pong", Nonce: 1}}}}
	if err := g.generateEvents(t.Context(), func(e layers.MessageEvent) error {
		evs = append(evs, e)
		return nil
	}, dc); err != nil {
		t.Fatalf("discovery generate: %v", err)
	}
	if len(evs) != 2 || !evs[0].Up || evs[1].Up || evs[0].SrcPort != 42052 {
		t.Fatalf("discovery events = %+v", evs)
	}
	evs = nil
	sc := &core.SwarmConfig{Connections: []core.SwarmConnection{{SrcPort: 42053,
		Events: []core.SwarmEvent{{Kind: "hello"}, {Kind: "hello_ok"}}}}}
	if err := g.generateEvents(t.Context(), func(e layers.MessageEvent) error {
		evs = append(evs, e)
		return nil
	}, sc); err != nil {
		t.Fatalf("storage generate: %v", err)
	}
	if len(evs) != 2 || !evs[0].Up || evs[1].Up || evs[0].SrcPort != 42053 {
		t.Fatalf("storage events = %+v", evs)
	}
}
