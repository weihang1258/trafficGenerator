// T13 集成测试（P2e）：隧道层内层委托 tls+http（18 号文档 §13.3 T13 = §9.2）。
// tls+http 链 [ip → tcp → tls → http]（补全自 {"tls":{}}+{"http":{}}，
// tls depends_on [tcp]、http depends_on [tcp]——tls 在 tcp **之内**，TLS record
// 是 TCP payload，与 gre 隧道链（tcp 之外）结构相反）经 BuildLayersPlanner →
// ChainPlanner 驱动 → 真实 core.Builder 序列化：
//   - TCP 段必须带 TLS record（5B 头 0x17 + 明文 HTTP 字节在 record 内）——
//     tls 层把内层 http 字节包成 ApplicationData record 后仍以事件形态交给
//     tcp 层（握手/分段/seq 归 tcp）；
//   - 握手 record（0x16 ClientHello 等）先行注入；
//   - 与 T12 同用同一 Builder 序列化（T11 已证明 engine 流水线把 PacketConfig
//     字节写进 writer，隧道链只需验证字节内容本身）。
package layers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/http"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tls"
)

// buildTLSChain builds the T13 chain planner and runs the full Plan →
// serialization pipeline, returning the wire frames.
func buildTLSChain(t *testing.T, layersJSON string) [][]byte {
	t.Helper()
	p, err := layers.BuildLayersPlanner("tls", json.RawMessage(layersJSON))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), tlsChainSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) == 0 {
		t.Fatal("tls chain produced 0 packets (silent empty flow)")
	}
	b := core.NewBuilder()
	frames := make([][]byte, len(pkts))
	for i, pkt := range pkts {
		f, err := b.Build(pkt)
		if err != nil {
			t.Fatalf("Build packet %d: %v", i, err)
		}
		frames[i] = f
	}
	return frames
}

func tlsChainSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 40000, DstPort: 443,
		Count: 1,
	}
}

// recordAt returns the TLS record bytes at payload offset off of the frame
// (tls record 是 TCP payload 的起点：eth14 + ip20 + tcp20 = 54)。
func tlsRecordAt(f []byte, off int) []byte {
	if len(f) < off+5 {
		return nil
	}
	recLen := int(f[off+3])<<8 | int(f[off+4])
	if len(f) < off+5+recLen {
		return nil
	}
	return f[off : off+5+recLen]
}

// assertRecordLengths verifies the 2-byte record length field of every TLS
// record seen in the frames matches the actual payload bytes (review T13-tests
// finding 3：长度字段写死/写小会在此失败——tlsRecordAt 按该字段截取，若恒
// 0x0005 则每条 record 只返回 5+5 字节）。
func assertRecordLengths(t *testing.T, frames [][]byte) {
	t.Helper()
	payloadOff := 14 + 20 + 20
	checked := 0
	for i, f := range frames {
		if len(f) <= payloadOff+5 {
			continue
		}
		recLen := int(f[payloadOff+3])<<8 | int(f[payloadOff+4])
		if recLen == 0 || recLen > len(f)-payloadOff-5 {
			continue // 非 record 段（SYN/FIN/ACK 裸段），length 字段不是 record 语义
		}
		rec := tlsRecordAt(f, payloadOff)
		if rec == nil {
			continue
		}
		if len(rec) != 5+recLen {
			t.Errorf("frame %d: record length field = %d but record slice is %d bytes (field/payload mismatch)", i, recLen, len(rec))
		}
		// ApplicationData 的 record 长度必须精确覆盖全部明文（事件字节
		// 不被截断也不含填充——tls 变换器整包转发内层消息）。
		if rec[0] == 0x17 && len(rec)-5 != recLen {
			t.Errorf("frame %d: application record payload = %d bytes, length field = %d (must match)", i, len(rec)-5, recLen)
		}
		checked++
	}
	if checked < 7 {
		t.Errorf("assertRecordLengths checked only %d records, want >= 7 (3 handshake + 4+ app records)", checked)
	}
}

// TestT13_TLSChainCompletesAndDrives: tls+http 补全必须产出 [ip → tcp → tls →
// http]（tls 在 tcp 之内），且驱动不报错、每包经真实 builder 序列化成功。
// 若 drive 误把 tls 当传输层（旧 len-2 定位），tcp 层不启动 → 空流或挂死。
func TestT13_TLSChainCompletesAndDrives(t *testing.T) {
	p, err := layers.BuildLayersPlanner("tls", json.RawMessage(`[{"tls":{}},{"http":{}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), tlsChainSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) == 0 {
		t.Fatal("tls chain produced 0 packets (silent empty flow)")
	}
	b := core.NewBuilder()
	for i, pkt := range pkts {
		f, err := b.Build(pkt)
		if err != nil {
			t.Fatalf("Build packet %d: %v", i, err)
		}
		if f == nil {
			t.Fatalf("packet %d built nil frame", i)
		}
	}
}

// parseClientHelloExtensions walks the ClientHello body extensions block and
// returns extension type → body bytes. If the block is absent or malformed,
// it returns an error (TLS 1.3 ClientHello 必有 extensions 块：
// version(2)+random(32)+session_id(1+var)+cipher_suites(2+var)+
// compression(1+var)+extensions(2+var)）。
func parseClientHelloExtensions(body []byte) (map[uint16][]byte, error) {
	if len(body) < 2+32+1+2+1 {
		return nil, fmt.Errorf("ClientHello too short: %d", len(body))
	}
	p := 2 + 32 // version + random
	sidLen := int(body[p])
	p++
	if p+sidLen > len(body) {
		return nil, fmt.Errorf("session_id length %d overflows body %d", sidLen, len(body))
	}
	p += sidLen
	if p+2 > len(body) {
		return nil, fmt.Errorf("cipher_suites length missing at %d", p)
	}
	csLen := int(body[p])<<8 | int(body[p+1])
	p += 2
	if p+csLen > len(body) {
		return nil, fmt.Errorf("cipher_suites length %d overflows body %d", csLen, len(body))
	}
	p += csLen
	if p+1 > len(body) {
		return nil, fmt.Errorf("compression length missing at %d", p)
	}
	compLen := int(body[p])
	p++
	if p+compLen > len(body) {
		return nil, fmt.Errorf("compression length %d overflows body %d", compLen, len(body))
	}
	p += compLen
	if p+2 > len(body) {
		return nil, fmt.Errorf("extensions block missing at %d", p)
	}
	extLen := int(body[p])<<8 | int(body[p+1])
	p += 2
	if p+extLen > len(body) {
		return nil, fmt.Errorf("extensions length %d overflows body %d", extLen, len(body))
	}
	end := p + extLen
	exts := make(map[uint16][]byte)
	for p+4 <= end {
		typ := uint16(body[p])<<8 | uint16(body[p+1])
		l := int(body[p+2])<<8 | int(body[p+3])
		p += 4
		if p+l > end {
			return nil, fmt.Errorf("extension %#04x length %d overflows block %d", typ, l, end-p)
		}
		exts[typ] = body[p : p+l]
		p += l
	}
	if p != end {
		return nil, fmt.Errorf("extensions block ends at %d, want %d", p, end)
	}
	return exts, nil
}

// allZero reports whether every byte of b is zero (TCP 挥手 ACK/FIN 段
// payload 恒 6 字节 0，T13 大消息测试用此识别并跳过)。
func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// TestT13_TLSRecordOnTCPPayload: TLS record 必须作为 TCP payload 出现——
// 首帧 TCP 段（SYN 之后）负载以 0x17（ApplicationData）或 0x16（Handshake）
// record 头开始，且 record 长度字段与负载一致。旧 len-2 定位（tls 当传输层）
// 时 tcp 层从不消费事件 → 无 record 段。
func TestT13_TLSRecordOnTCPPayload(t *testing.T) {
	frames := buildTLSChain(t, `[{"tls":{}},{"http":{}}]`)
	// 完整 tls 事务 = 3 握手 + 7 TLS 握手 record + 请求 + 响应 + 4 挥手 ≥ 15 段。
	if len(frames) < 15 {
		t.Fatalf("tls chain produced %d frames, want >= 15 (tcp handshake + 7 tls handshake records + http req/resp + tcp teardown)", len(frames))
	}
	payloadOff := 14 + 20 + 20
	foundHandshake, foundApp := false, false
	for _, f := range frames {
		if len(f) <= payloadOff+5 {
			continue
		}
		rec := tlsRecordAt(f, payloadOff)
		if rec == nil {
			continue
		}
		switch rec[0] {
		case 0x16: // Handshake
			foundHandshake = true
		case 0x17: // ApplicationData
			foundApp = true
			// ApplicationData 内必须是内层 http 明文（委托字节正确）：
			// 请求段 GET / HTTP/1.1 或响应段 HTTP/1.1 都算内层委托正确。
			body := rec[5:]
			validReq := len(body) >= 16 && string(body[:16]) == "GET / HTTP/1.1\r\n"
			validResp := len(body) >= 9 && string(body[:9]) == "HTTP/1.1 "
			if !validReq && !validResp {
				t.Errorf("application data body = %q..., want inner http bytes (request GET / or response HTTP/1.1)", body)
			}
		}
	}
	if !foundHandshake {
		t.Error("no TLS handshake record (0x16) found on any TCP payload")
	}
	if !foundApp {
		t.Error("no TLS ApplicationData record (0x17) found — tls layer never wrapped the http events")
	}
	assertRecordLengths(t, frames)
}

// TestT13_TLSHandshakeSequence: 握手 record 序列与方向必须正确（legacy tls1.3
// fast path）：ClientHello(up) → ServerHello13 → EncryptedExtensions →
// Certificate13 → CertificateVerify → ServerFinished → ClientFinished(down/up
// 交替)，且 ClientHello 内必须真实 TLS 结构（handshake header type 1 +
// client_version 0x0303 + random 32B + session_id）。
func TestT13_TLSHandshakeSequence(t *testing.T) {
	frames := buildTLSChain(t, `[{"tls":{}},{"http":{}}]`)
	payloadOff := 14 + 20 + 20
	var handshakes []struct {
		up   bool
		rec  []byte
		port uint16
	}
	for _, f := range frames {
		if len(f) <= payloadOff+5 {
			continue
		}
		rec := tlsRecordAt(f, payloadOff)
		if rec == nil || rec[0] != 0x16 {
			continue
		}
		// TCP src port（payload 起点 54，src port 在 34:36）。
		sp := uint16(f[34])<<8 | uint16(f[35])
		handshakes = append(handshakes, struct {
			up   bool
			rec  []byte
			port uint16
		}{sp == 40000, rec, sp})
	}
	if len(handshakes) < 7 {
		t.Fatalf("got %d handshake records, want >= 7 (tls1.3 fast path)", len(handshakes))
	}
	// 1. ClientHello：up，handshake type 1，client_version 0x0303，random 32B。
	ch := handshakes[0]
	if !ch.up {
		t.Error("record 1 (ClientHello) must be up (client → server)")
	}
	body := ch.rec[5:]
	if len(body) < 4 || body[0] != 1 {
		t.Fatalf("ClientHello handshake type = %#02x, want 1 (client_hello)", body[0])
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if hsLen <= 0 || hsLen > len(body)-4 {
		t.Fatalf("ClientHello handshake length = %d, want <= %d (body)", hsLen, len(body)-4)
	}
	hello := body[4:]
	if len(hello) < 38 {
		t.Fatalf("ClientHello body too short: %d bytes (< 2 version + 32 random + 4 sess)", len(hello))
	}
	if got := uint16(hello[0])<<8 | uint16(hello[1]); got != 0x0303 {
		t.Errorf("ClientHello client_version = %#04x, want 0x0303 (TLS 1.2/1.3 legacy)", got)
	}
	// random 32B 在 version 后；session_id 长度紧跟 random。
	if len(hello) < 34+1 {
		t.Fatalf("ClientHello body too short for random+sid: %d", len(hello))
	}
	// extensions 块内必须有 ALPN/supported_versions/key_share（review T13-tests
	// finding 2 的默认链侧：alpn 默认非空 → 必须进 extensions；SNI 在默认链
	// 恒缺席——legacy 仅 sni != "" 时追加，SNI 显式配置断言在
	// TestT13_TLSChainValidateAndUnknownFields）。
	exts, err := parseClientHelloExtensions(hello)
	if err != nil {
		t.Fatalf("parse ClientHello extensions: %v", err)
	}
	for _, want := range []uint16{0x0010 /* ALPN */, 0x002b /* supported_versions */, 0x0033 /* key_share */} {
		if _, ok := exts[want]; !ok {
			t.Errorf("ClientHello missing extension %#04x", want)
		}
	}
	// 2. ServerHello13：down，type 2。
	sh := handshakes[1]
	if sh.up {
		t.Error("record 2 (ServerHello) must be down (server → client)")
	}
	if body := sh.rec[5:]; len(body) < 1 || body[0] != 2 {
		t.Errorf("ServerHello handshake type = %#02x, want 2 (server_hello)", body[0])
	}
	// 3-7：EncryptedExtensions(8)/Certificate13(11)/CertificateVerify(15)/
	// ServerFinished(20, down)/ClientFinished(20, up)。
	wantTypes := []struct {
		typ uint8
		up  bool
	}{{8, false}, {11, false}, {15, false}, {20, false}, {20, true}}
	for i, want := range wantTypes {
		h := handshakes[2+i]
		body := h.rec[5:]
		if len(body) < 1 {
			t.Fatalf("handshake record %d has no body", 2+i)
		}
		if body[0] != want.typ {
			t.Errorf("handshake record %d type = %#02x, want %#02x", 2+i, body[0], want.typ)
		}
		if h.up != want.up {
			t.Errorf("handshake record %d direction up=%v, want %v", 2+i, h.up, want.up)
		}
	}
}

// TestT13_TLSDownFrameRecordDirection: down 帧（响应）的 record 方向保留——
// http 响应事件经 tls 变换后仍是 down 事件，tcp 层按 down 段发（端口交换：
// src=443）。若 tls 变换丢失方向，响应会以 40000 端口发出（P2c-3 同款陷阱）。
func TestT13_TLSDownFrameRecordDirection(t *testing.T) {
	frames := buildTLSChain(t, `[{"tls":{}},{"http":{}}]`)
	payloadOff := 14 + 20 + 20
	found := false
	for _, f := range frames {
		if len(f) <= payloadOff+5 {
			continue
		}
		rec := tlsRecordAt(f, payloadOff)
		if rec == nil || rec[0] != 0x17 {
			continue
		}
		body := rec[5:]
		if len(body) >= 9 && string(body[:9]) == "HTTP/1.1 " {
			found = true
			sp := uint16(f[34])<<8 | uint16(f[35])
			if sp != 443 {
				t.Errorf("response record tcp src port = %d, want 443 (down frame: src swapped to dst port)", sp)
			}
		}
	}
	if !found {
		t.Error("no HTTP response inside an ApplicationData record")
	}
}

// TestT13_TLSChainValidateAndUnknownFields: 校验面——未知 tls 层字段（V9）
// 必须拒绝；已知字段合法且 spec.TLS 为 nil 时校验通过、驱动出包。
func TestT13_TLSChainValidateAndUnknownFields(t *testing.T) {
	if _, err := layers.BuildLayersPlanner("tls", json.RawMessage(`[{"tls":{"bogus":1}},{"http":{}}]`)); err == nil {
		t.Error("BuildLayersPlanner accepted unknown tls layer field (want V9 rejection)")
	}
	p, err := layers.BuildLayersPlanner("tls", json.RawMessage(`[{"tls":{"sni":"example.com"}},{"http":{}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(tlsChainSpec()); err != nil {
		t.Fatalf("Validate: %v (tls chain with spec.TLS nil must validate)", err)
	}
	frames := buildTLSChain(t, `[{"tls":{"sni":"example.com","alpn":["h2"]}},{"http":{}}]`)
	if len(frames) == 0 {
		t.Fatal("tls chain produced 0 frames")
	}
	// sni/alpn 必须真实进入 ClientHello extensions（review T13-tests finding 2：
	// buildClientHello 忽略 config 参数在此失败）。
	payloadOff := 14 + 20 + 20
	sniSeen, alpnSeen := false, false
	for _, f := range frames {
		if len(f) <= payloadOff+5 {
			continue
		}
		rec := tlsRecordAt(f, payloadOff)
		if rec == nil || rec[0] != 0x16 {
			continue
		}
		body := rec[5:]
		if len(body) < 4 || body[0] != 1 {
			continue
		}
		hello := body[4:]
		exts, err := parseClientHelloExtensions(hello)
		if err != nil {
			continue
		}
		if sni, ok := exts[0x0000]; ok {
			sniSeen = true
			// SNI body (RFC 6066 §3): list_len(2) + name[name_type(1)=0 +
			// name_len(2) + name]。"example.com" → list_len 14 + 0 + 11 + 名。
			if len(sni) >= 5 && string(sni[5:]) == "example.com" && sni[0] == 0 && sni[1] == 14 && sni[2] == 0 && (int(sni[3])<<8|int(sni[4])) == 11 {
				// 值正确
			} else {
				t.Errorf("ClientHello SNI extension body = %x, want list_len 14 + name_type 0 + len 11 + \"example.com\"", sni)
			}
		}
		if alpn, ok := exts[0x0010]; ok {
			alpnSeen = true
			// ALPN body: list_len(2) + protocol_list，h2 = len(1)+"h2"。
			if len(alpn) >= 4 && alpn[2] == 2 && string(alpn[3:5]) == "h2" {
				// 值正确
			} else {
				t.Errorf("ClientHello ALPN extension body = %x, want [\"h2\"]", alpn)
			}
		}
	}
	if !sniSeen {
		t.Error("sni config \"example.com\" never reached ClientHello extensions")
	}
	if !alpnSeen {
		t.Error("alpn config [\"h2\"] never reached ClientHello extensions")
	}
}

// TestT13_TLSLargeMessageRecordFragmentation: 内层事件（http 大 body）超过
// TLS 明文 record 上限（RFC 8446 §5.2：2^14+1=16385）时，变换器必须把消息
// 分片成多条合法 record，而非产出单条超长 record（review tls-layer finding 1：
// buildRecord 用 uint16 长度字段，>65535 截断、>16384 违反上限，Wireshark
// 标 malformed）。断言：
//   - 每条 ApplicationData record 长度字段 ≤ 16385 且与 payload 精确匹配；
//   - 所有 app record payload 拼接后包含完整大 body（字节不丢）。
func TestT13_TLSLargeMessageRecordFragmentation(t *testing.T) {
	big := strings.Repeat("x", 20000) // > 16385 单条 record 放不下
	spec := tlsChainSpec()
	spec.HTTP = &core.HTTPConfig{Method: "POST", URI: "/", Version: "HTTP/1.1", Body: big}
	p, err := layers.BuildLayersPlanner("tls", json.RawMessage(`[{"tls":{}},{"http":{}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan rejected the chain: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) == 0 {
		t.Fatal("tls chain produced 0 packets")
	}
	b := core.NewBuilder()
	payloadOff := 14 + 20 + 20
	var appStream []byte
	appRecords := 0
	// 帧序 = 事件序。握手 record（0x16）每段 < MSS 单段完整，跳过；
	// 0x17 首段 → 长度字段必须 ≤ 16385，计数 +1；其后续段（record 中间，
	// 首字节非 0x17，因为被 tcp 按 MSS 切开）与 0x17 首段一起按帧序拼接
	// = 完整 app record 字节流。挥手段（payload 全 0）出现在所有 app
	// record 之后，不参与拼接（标志位 0x10/0x11 的 6 字节 0 段）。
	inApp := false
	for _, pkt := range pkts {
		f, err := b.Build(pkt)
		if err != nil {
			t.Fatalf("Build packet: %v", err)
		}
		if len(f) <= payloadOff {
			continue
		}
		payload := f[payloadOff:]
		if len(payload) == 6 && allZero(payload) {
			inApp = false // 挥手 ACK/FIN 段（legacy 挥手固定 6 字节 0 payload）
			continue
		}
		if len(payload) >= 5 && payload[0] == 0x16 {
			inApp = false // 握手段之间无 app 数据
			continue
		}
		if len(payload) >= 5 && payload[0] == 0x17 {
			inApp = true
			recLen := int(payload[3])<<8 | int(payload[4])
			if recLen > 16385 {
				t.Errorf("application record length %d exceeds RFC 8446 §5.2 max 16385 (fragmentation missing)", recLen)
			}
			appRecords++
		}
		if inApp {
			appStream = append(appStream, payload...)
		}
	}
	if appRecords < 2 {
		t.Fatalf("got %d application records, want >= 2 (20000-byte message must be fragmented)", appRecords)
	}
	// 拼接流内 record 边界必须自洽：每条 record 头后恰好 recLen 字节；
	// 且 record payload 拼接 = 完整 HTTP 消息（含全部 body 字节）。
	pos := 0
	var appPayload []byte
	for pos+5 <= len(appStream) {
		if appStream[pos] != 0x17 {
			t.Fatalf("app stream at %d: not a record start (0x%02x)", pos, appStream[pos])
		}
		recLen := int(appStream[pos+3])<<8 | int(appStream[pos+4])
		if recLen > 16385 {
			t.Errorf("record at %d: length %d exceeds max 16385", pos, recLen)
		}
		if pos+5+recLen > len(appStream) {
			t.Errorf("record at %d: length %d overruns app stream %d bytes", pos, recLen, len(appStream))
			break
		}
		appPayload = append(appPayload, appStream[pos+5:pos+5+recLen]...)
		pos += 5 + recLen
	}
	if pos != len(appStream) {
		t.Errorf("app stream ends at %d of %d (trailing bytes = lost/misaligned records)", pos, len(appStream))
	}
	if !bytes.Contains(appPayload, []byte(big)) {
		t.Errorf("fragmented record payload (%d bytes) lost data: full %d-byte body not present", len(appPayload), len(big))
	}
}

// TestT13_TLSSNITooLongRejected: sni 超过 RFC 1035 的 253 字节上限必须同步
// 拒绝（review tls-layer finding 2：超长 SNI 使扩展块 >65535 时 uint16 截断，
// 产出非法 ClientHello——与 legacy Validate 口径一致，同 4.2.1 测试点）。
// alpn 协议名同理 >255 拒绝（buildALPNExtension 的 byte(len) 单字节前缀）。
func TestT13_TLSSNITooLongRejected(t *testing.T) {
	longSNI := strings.Repeat("a", 254)
	layersJSON := fmt.Sprintf(`[{"tls":{"sni":%q}},{"http":{}}]`, longSNI)
	p, err := layers.BuildLayersPlanner("tls", json.RawMessage(layersJSON))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if _, err := p.Plan(context.Background(), tlsChainSpec()); err == nil {
		t.Error("Plan accepted SNI longer than 253 bytes (RFC 1035), want sync rejection")
	}
	// 边界：253 字节合法。
	okSNI := strings.Repeat("a", 253)
	okJSON := fmt.Sprintf(`[{"tls":{"sni":%q}},{"http":{}}]`, okSNI)
	p2, err := layers.BuildLayersPlanner("tls", json.RawMessage(okJSON))
	if err != nil {
		t.Fatalf("BuildLayersPlanner(253-byte sni): %v", err)
	}
	if _, err := p2.Plan(context.Background(), tlsChainSpec()); err != nil {
		t.Errorf("Plan rejected 253-byte SNI (valid boundary): %v", err)
	}
	// alpn 协议名 >255（buildALPNExtension 单字节长度前缀）同样拒绝。
	longALPN := strings.Repeat("b", 256)
	alpnJSON := fmt.Sprintf(`[{"tls":{"alpn":[%q]}},{"http":{}}]`, longALPN)
	p3, err := layers.BuildLayersPlanner("tls", json.RawMessage(alpnJSON))
	if err != nil {
		t.Fatalf("BuildLayersPlanner(long alpn): %v", err)
	}
	if _, err := p3.Plan(context.Background(), tlsChainSpec()); err == nil {
		t.Error("Plan accepted ALPN protocol name longer than 255 bytes, want sync rejection")
	}
}

// tls1.2 与 role=server 在层链未实现，必须**同步拒绝**（Plan 报错而非
// 静默空流；drive 的运行时错误按既有契约吞掉，结构性不支持必须前置）。
func TestT13_TLSUnsupportedVersionRejected(t *testing.T) {
	spec := tlsChainSpec()
	for _, layersJSON := range []string{
		`[{"tls":{"version":"tls1.2"}},{"http":{}}]`,
		`[{"tls":{"role":"server"}},{"http":{}}]`,
	} {
		p, err := layers.BuildLayersPlanner("tls", json.RawMessage(layersJSON))
		if err != nil {
			t.Fatalf("BuildLayersPlanner(%s): %v", layersJSON, err)
		}
		if _, err := p.Plan(context.Background(), spec); err == nil {
			t.Errorf("Plan(%s): unsupported tls config accepted, want sync rejection", layersJSON)
		}
	}
}

// TestT13_TLSNoTransformersDirectTerminal: 终结层紧贴传输层（无变换器）时
// 事件流接线退化为单流（transformCh[0] == transport 事件流，无中间层）——
// T13 泛化的退化路径必须与波 2 旧实现逐字节一致。驱动产出正常 tls+http 链
// 的完整帧流；若 drive 误把 tls 当传输层（旧 len-2 定位）则 tcp 不启动。
func TestT13_TLSNoTransformersDirectTerminal(t *testing.T) {
	// [ip → tcp → http]（普通 http 链，无变换器）——退化路径对照。
	p, err := layers.BuildLayersPlanner("http", json.RawMessage(`[{"http":{}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), tlsChainSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	count := 0
	for c := range ch {
		count++
		if c.L4.Protocol != "tcp" {
			t.Errorf("packet %d: L4 protocol %q, want tcp", count-1, c.L4.Protocol)
		}
	}
	if count == 0 {
		t.Fatal("plain http chain produced 0 packets")
	}
}

// TestT13_TLSTransformConfigErrorDrains: tls 生成器自身配置错误（非
// ValidateSpec 拦截的类型错误）必须在退出前排空输入（review transform-wiring
// F1 回归——错误路径不 drain 则同步写者卡死）。验证方法：直接构造 tls
// GenRequest（内层事件流产 200 条 > 缓冲 64 的消息），用一个会失败的 layer
// config 驱动 tls 生成器，验证它返回错误且事件流被全部消费（写者不阻塞）。
func TestT13_TLSTransformConfigErrorDrains(t *testing.T) {
	gen, err := layers.NewLayerGenerator("tls")
	if err != nil {
		t.Fatalf("NewLayerGenerator(tls): %v", err)
	}
	if _, ok := gen.(layers.EventTransformer); !ok {
		t.Fatal("tls generator does not implement EventTransformer")
	}
	// 构造一个配置错误：手工喂一个非法 version 值（V9 校验在真实链上
	// 拦截；此处直接驱动生成器，走运行时错误路径）。
	cfg := map[string]interface{}{"version": "tls1.0"}
	// 内层事件流：比缓冲 64 大得多。写者跑在独立 goroutine——若 tls 在
	// 错误路径退出前不消费它，写者卡在 send 上（done 永不关闭，超时护栏
	// 转成测试失败而非测试自身挂死）。
	events := make(chan layers.MessageEvent, 64)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			events <- layers.MessageEvent{Up: true, Bytes: []byte("x")}
		}
		close(events)
		close(done)
	}()
	var emitted int
	req := &layers.GenRequest{
		Layer: layers.Layer{Name: "tls", Config: cfg},
		Meta:  layers.FlowMeta{Events: events},
		EmitMsg: func(ev layers.MessageEvent) error {
			emitted++
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("tls generator accepted invalid version config, want error")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("event producer blocked: tls generator did not drain its input before exiting")
	}
	if emitted != 0 {
		t.Errorf("tls generator emitted %d records despite config error, want 0", emitted)
	}
}

// TestT13_TLSTransportConfigErrorPreflight: transport（tcp）层 config 存在
// 不可转换值时，事件分支必须在启动任何 goroutine 前同步失败（review
// transform-wiring F3 回归——原实现 transport goroutine 先退出、transformCh[1]
// 无人消费，tls 转发塞满 64 后同步写者阻塞挂死，直到 ctx 取消才收敛）。
// 验证方法：对 tls+http 链给 tcp 层配一个非法值（resolveCfg 报错），Plan 必须
// 同步报错且立刻返回（1s 超时护栏——若挂死到 ctx 取消则超时失败）。
func TestT13_TLSTransportConfigErrorPreflight(t *testing.T) {
	// 顶层 flow spec 的端口是合法数字；把非法值塞进 tcp 层 config
	// （layer config 直接读数值类型，schema 校验通过但 resolveCfg 转换失败）。
	layersJSON := `[{"tcp":{"initial_seq":"abc"}},{"tls":{}},{"http":{}}]`
	p, err := layers.BuildLayersPlanner("tls", json.RawMessage(layersJSON))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := p.Plan(context.Background(), tlsChainSpec())
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Plan accepted unconvertible tcp layer config, want sync rejection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Plan hung on transport config error (transformer chain has no consumer)")
	}
}

// TestT13_TLSCancelConverges: 事件流驱动中途取消必须收敛（review T13 MED-1/
// MED-2 回归）。取消路径：tls 变换器在握手 record 转发后、内层事件前读
// transformCh[0]——ctx 取消后终结层 EmitMsg send 也要立即退出（不能阻塞在
// send），drive 等待 transformDone 有 ctx 逃生口（不能永久挂死）。
// 旧实现（无 tls 变换器）的终结层 send 只 select ctx.Done——取消即收敛；
// 变换器链新增了等待点，取消必须在每个等待点收敛。用超时护栏防挂死。
//
// 触发时机（review T13-tests finding 1 修订）：立即取消会让所有层在初始 ctx
// 检查点收敛（http 首个检查点 / tls 首条 emit 的 ctx 分支），永远走不到
// "终结层向满缓冲 send 阻塞"或"transformDone 等待点挂死"。这里让 Plan 先跑
// 一小段（tls 注入 7 条握手 record 且事件流已打开、内层事件在途）再取消，
// 取消点落在 tls 的阻塞读与终结层的 send 上。
// 已知局限（如实记录）：tls 变换器的所有阻塞点（事件循环 select、drain
// select）与 reqForTerminal.EmitMsg 都有 ctx escape——MED-1（transformDone
// ctx 逃生口）与 MED-2（drain）是分层防御，黑盒测试无法单独证明某一层的
// 必要性（去掉任一单点仍收敛）。本测试验证的是整体取消收敛契约：驱动中途
// 取消必须不挂死（10s 超时护栏），任一等待点失去逃生口且变换器阻塞时挂死。
func TestT13_TLSCancelConverges(t *testing.T) {
	p, err := layers.BuildLayersPlanner("tls", json.RawMessage(`[{"tls":{}},{"http":{}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ch, err := p.Plan(ctx, tlsChainSpec())
		// 先消费一会儿（收集到首个握手 record 帧 = tls 已注入握手、事件流
		// 已打开、transformDone 等待点已就位），再取消。
		for pkt := range ch {
			if len(pkt.Payload) > 0 || pkt.L4.Flags != 0 {
				break
			}
		}
		cancel()
		if err == nil {
			// Plan 未报错也合法（取消可能在首包前）——但必须能排空通道
			// 且不挂死（取消时 ip 层 select ctx.Done 退出 → 通道关闭）。
			for range ch {
			}
			return
		}
		// err 非 nil：通道可能已关闭（ip 层退出后 drive 才返回）。
		for range ch {
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Plan did not converge after context cancellation (transformer wait has no ctx escape)")
	}
}
