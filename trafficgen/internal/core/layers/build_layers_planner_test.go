// 外部测试包：BuildLayersPlanner 是 main.go 注入引擎的层链工厂（P2c 层链
// 驱动生成），这里用真实 factory 验证"单层链 → 补全 → 产包 → config 保留"。
// 引 protocol/tcp 触发注册（layer_gen.go 的 tcp→layers 依赖使内层包无法测试）。
package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dns"
	_ "github.com/trafficgen/trafficgen/internal/protocol/http"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mqtt"
	_ "github.com/trafficgen/trafficgen/internal/protocol/pop3"
	_ "github.com/trafficgen/trafficgen/internal/protocol/socks5"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tcp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/thrift"
)

func TestBuildLayersPlanner_ThriftLayerConfigFlowsIntoSpec(t *testing.T) {
	p, err := layers.BuildLayersPlanner("thrift", json.RawMessage(`[{"thrift":{"messages":[{"type":"CALL","method":"add","seqid":1,"args":[{"id":1,"type":"I32","value":1},{"id":2,"type":"I32","value":2}]},{"type":"REPLY","method":"add","seqid":1,"result":[{"id":0,"type":"I32","value":3}]}]}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) != 9 {
		t.Fatalf("thrift chain produced %d packets, want 9", len(pkts))
	}
	var payload string
	for _, pkt := range pkts {
		payload += string(pkt.Payload)
	}
	if !strings.Contains(payload, "add") {
		t.Fatalf("payload %q does not contain translated method add", payload)
	}
	if strings.Contains(payload, "ping") {
		t.Fatalf("payload %q contains default ping after layer translation", payload)
	}
}

func TestBuildLayersPlanner_ThriftLayerConfigDecodeError(t *testing.T) {
	p, err := layers.BuildLayersPlanner("thrift", json.RawMessage(`[{"thrift":{"messages":[{"type":"CALL","method":"add","unknown":true}]}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000}); err == nil || !strings.Contains(err.Error(), "thrift layer config decode") {
		t.Fatalf("Validate error = %v, want thrift layer config decode", err)
	}
}

// 回归——单层豁免链 [{"tcp":{}}] 经 BuildLayersPlanner 必须补全成
// [ip, tcp] 并实际产包。旧实现把未补全的用户链直传 ChainPlanner，Plan 的
// drive 找不到 ip 层报 "no ip layer"，错误被驱动 goroutine 吞掉 → 任务
// 报 completed 且 0 包（静默空流）。补全必须发生在 factory 内（链要驱动
// 生成），不能留到 Plan 再补（单层豁免链的补全被 V4 拒绝，Plan 无法识别
// 豁免条件）。
func TestBuildLayersPlanner_SingleLayerChainGeneratesPackets(t *testing.T) {
	p, err := layers.BuildLayersPlanner("tcp", json.RawMessage(`[{"tcp":{}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 80,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) == 0 {
		t.Fatal("single-layer [tcp] chain produced 0 packets (CRITICAL-1: silent empty flow)")
	}
}

// TestBuildLayersPlanner_PreservesLayerConfig: 补全必须保留用户链的层
// config——单层链 [{"tcp":{"window_size":8192}}] 的窗口必须出现在所有
// 包的 L4 上。旧豁免路径（completeSynthesized）从裸协议名重建链，config
// 全丢 → 静默生成 schema 默认（65535）的包。
func TestBuildLayersPlanner_PreservesLayerConfig(t *testing.T) {
	p, err := layers.BuildLayersPlanner("tcp", json.RawMessage(`[{"tcp":{"window_size":8192}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 80,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) == 0 {
		t.Fatal("single-layer [tcp] chain produced 0 packets")
	}
	for i := range pkts {
		if pkts[i].L4.WindowSize != 8192 {
			t.Errorf("packet %d window = %d, want 8192 (layer config lost in completion)", i, pkts[i].L4.WindowSize)
		}
	}
}

// ---- P2c-3 失败测试：终结层配置翻译（layers config → spec.HTTP/spec.DNS）----
// T11 集成测试捕获的 production gap：validate_layers.go:112-115 记录的
// "validated-but-not-yet-effective"——http/dns 生成器按契约读
// req.Meta.HTTP/req.Meta.DNS（generator.go:30-33 "Generators read values from
// here, never from the raw FlowSpec"），但没有任何路径把 layers 数组中的
// 终结层 config 字段翻译进 spec.HTTP/spec.DNS，导致 {"http":{"method":"POST"}}
// 静默回退 GET /、{"dns":{}} 验证失败 "DNS config is required"。

// TestBuildLayersPlanner_HTTPLayerConfigFlowsIntoSpec: 层 config 的
// method/uri/version/headers/body 必须翻译进 spec.HTTP，并落到生成的
// 报文字节（生成器读 req.Meta.HTTP = spec.HTTP）。
func TestBuildLayersPlanner_HTTPLayerConfigFlowsIntoSpec(t *testing.T) {
	p, err := layers.BuildLayersPlanner("http", json.RawMessage(`[{"http":{
		"method":"POST","uri":"/x","version":"1.1",
		"headers":{"X-Test":"1"},"body":"hello"}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 40000, DstPort: 8080,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) < 6 {
		t.Fatalf("http chain produced %d packets, want >= 6", len(pkts))
	}
	var reqBody []byte
	var respPort uint16
	for i, pkt := range pkts {
		if pkt.Direction == "up" && len(pkt.Payload) > 0 {
			reqBody = pkt.Payload
		}
		if pkt.Direction == "down" && len(pkt.Payload) > 0 {
			respPort = pkt.L4.SrcPort
		}
		_ = i
	}
	if reqBody == nil {
		t.Fatal("no upstream data segment found (http bytes never emitted)")
	}
	if !strings.Contains(string(reqBody), "POST /x HTTP/1.1\r\n") {
		t.Errorf("request line = %q, want POST /x HTTP/1.1 (method/uri/version lost)", string(reqBody))
	}
	if !strings.Contains(string(reqBody), "X-Test: 1\r\n") {
		t.Errorf("request = %q, want user header X-Test: 1 (headers lost)", string(reqBody))
	}
	if !strings.Contains(string(reqBody), "hello") {
		t.Errorf("request = %q, want body hello (body lost)", string(reqBody))
	}
	// down 数据段端口必须交换（legacy http.go:330：响应 src = spec.DstPort）。
	if respPort == 0 {
		t.Error("no downstream data segment found")
	} else if respPort != 8080 {
		t.Errorf("response src port = %d, want 8080 (down direction ports not swapped)", respPort)
	}
}

// TestBuildLayersPlanner_DNSLayerConfigFlowsIntoSpec: 层 config 的
// query_type/name 必须翻译进 spec.DNS 并落到查询字节（DNS 头 QTYPE 字段）。
// 同时验证翻译发生在协议级 validator 之前：{"dns":{}} 补全链必须能通过
// Validate（旧实现 spec.DNS 为 nil 报 "DNS config is required"）。
// 无 is_response 时只产查询包（legacy dns.go:301 的 IsResponse gate；
// is_response 不在层 schema 字段表，V9 拒绝未知字段，须经 flat spec 配置）。
func TestBuildLayersPlanner_DNSLayerConfigFlowsIntoSpec(t *testing.T) {
	p, err := layers.BuildLayersPlanner("dns", json.RawMessage(`[{"dns":{"query_type":28,"name":"www.example.com"}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	// Validate 必须通过（worker.go:218 planner.Validate(task.Spec) 在 Plan
	// 之前运行；dns validator 要求 spec.DNS 非 nil）。
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 53}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v (layer config not translated into spec.DNS before validator)", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) < 1 {
		t.Fatalf("dns chain produced 0 packets")
	}
	// 查询包：udp 负载（42B 帧 = eth14+ip20+udp8，DNS 头 12B 起）。
	// DNS 问题段 QTYPE 在头 12B 之后：name 长度前缀 + name + 2B type + 2B class。
	if len(pkts[0].Payload) < 12+14+4 {
		t.Fatalf("query payload too short: %d bytes", len(pkts[0].Payload))
	}
	pld := pkts[0].Payload
	if got := pld[12]; got != 3 {
		t.Errorf("name first label length = %d, want 3 (www)", got)
	}
	// name 之后：2B QTYPE + 2B QCLASS。name 编码 = 03 77 77 77 07 65 78 61 6d
	// 70 6c 65 03 63 6f 6d 00（16B）；QTYPE 偏移 12+16+1=29（先长度 0x1c 再
	// 值；同验证字面量：offset 28=00 29=1c 30=00 31=01）。
	if got := uint16(pld[12+16+1])<<8 | uint16(pld[12+16+1+1]); got != 28 {
		t.Errorf("query type = %d, want 28 (AAAA) (layer config query_type lost)", got)
	}
}

// TestBuildLayersPlanner_FlatSpecWinsOverLayerConfig: 策略同时带 flat 协议
// 子映射（spec.HTTP 非 nil）与 layers 数组时，flat 优先——层 config 被
// 忽略、不合并（P2c-3 翻译的 flat-authoritative 语义锁定）。若误改成
// "层字段覆盖 flat"，行为会依赖两者出现顺序，无法解释。
func TestBuildLayersPlanner_FlatSpecWinsOverLayerConfig(t *testing.T) {
	p, err := layers.BuildLayersPlanner("http", json.RawMessage(`[{"http":{"method":"POST","uri":"/layer"}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 8080,
		HTTP: &core.HTTPConfig{Method: "PUT", URI: "/flat", Version: "HTTP/1.0"},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var reqBody []byte
	for c := range ch {
		if c.Direction == "up" && len(c.Payload) > 0 {
			reqBody = c.Payload
		}
	}
	if reqBody == nil || !strings.Contains(string(reqBody), "PUT /flat HTTP/1.0\r\n") {
		t.Errorf("request = %q, want PUT /flat HTTP/1.0 (flat spec must win over layer config)", string(reqBody))
	}
}

// TestBuildLayersPlanner_SchemaDefaultsTranslate: 显式配置缺失时翻译必须
// 填入 schema 默认值（{"http":{}} → GET /、{"dns":{}} → query_type 1）。
// 生成器按契约读 Meta，不读层 config——默认值必须随翻译落进 spec，
// 否则空链仍产出零值行为。
func TestBuildLayersPlanner_SchemaDefaultsTranslate(t *testing.T) {
	p, err := layers.BuildLayersPlanner("http", json.RawMessage(`[{"http":{}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 8080,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var reqBody []byte
	for c := range ch {
		if c.Direction == "up" && len(c.Payload) > 0 {
			reqBody = c.Payload
		}
	}
	if reqBody == nil || !strings.Contains(string(reqBody), "GET / HTTP/1.1") {
		t.Errorf("request = %q, want GET / HTTP/1.1 (schema defaults not translated)", string(reqBody))
	}
}

// TestBuildLayersPlanner_POP3LayerConfigFlowsIntoSpec: pop3 层 config
// （banner/commands）必须翻译成 spec.POP3——pop3 生成器按契约读 Meta.POP3，
// 层 config 不翻译则空配置生成 0 载荷（J 组 POP3S：[tcp,tls,pop3] 链）。
func TestBuildLayersPlanner_POP3LayerConfigFlowsIntoSpec(t *testing.T) {
	p, err := layers.BuildLayersPlanner("pop3", json.RawMessage(`[{"pop3":{"banner":"+OK ready","commands":[{"cmd":"USER bob","response":"+OK bob"}]}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 110}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var payloads []string
	for c := range ch {
		if len(c.Payload) > 0 {
			payloads = append(payloads, string(c.Payload))
		}
	}
	foundBanner, foundCmd := false, false
	for _, pl := range payloads {
		if strings.Contains(pl, "+OK ready") {
			foundBanner = true
		}
		if strings.Contains(pl, "USER bob") {
			foundCmd = true
		}
	}
	if !foundBanner {
		t.Errorf("banner missing from payloads: %q (layer config not translated into spec.POP3)", payloads)
	}
	if !foundCmd {
		t.Errorf("USER command missing from payloads: %q", payloads)
	}
}

// TestBuildLayersPlanner_MQTTLayerConfigFlowsIntoSpec: mqtt 层 config
// （client_id）必须翻译成 spec.MQTT——mqtt 生成器按契约读 Meta.MQTT
// （J 组 MQTTS：[tcp,tls,mqtt] 链）。
func TestBuildLayersPlanner_MQTTLayerConfigFlowsIntoSpec(t *testing.T) {
	p, err := layers.BuildLayersPlanner("mqtt", json.RawMessage(`[{"mqtt":{"client_id":"tls-client-9"}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 8883}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var connect []byte
	for c := range ch {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 0x10 {
			connect = c.Payload
			break
		}
	}
	if connect == nil {
		t.Fatalf("no MQTT CONNECT frame emitted")
	}
	// CONNECT variable header: protocol name "MQTT" at offset 2 (after the
	// 2-byte remaining length; short header fits one byte).
	if !strings.Contains(string(connect), "tls-client-9") {
		t.Errorf("CONNECT = %q, want client_id tls-client-9 (layer config not translated into spec.MQTT)", connect)
	}
}

// TestBuildLayersPlanner_TLSOptionalNotAutoInserted: mqtt/pop3 的 tls
// OptionalOn 永不自动补——[mqtt] 单层链生成普通 mqtt（无 tls 层），
// MQTTS 必须显式写 [tcp,tls,mqtt]。
func TestBuildLayersPlanner_TLSOptionalNotAutoInserted(t *testing.T) {
	for _, name := range []string{"mqtt", "pop3"} {
		completed, err := layers.ValidateLayers(json.RawMessage(`[{"`+name+`":{}}]`), name)
		if err != nil {
			t.Fatalf("%s: ValidateLayers: %v", name, err)
		}
		if strings.Contains(completed, "tls") {
			t.Errorf("%s: chain %q unexpectedly contains tls (OptionalOn must not auto-complete)", name, completed)
		}
	}
}

// TestBuildLayersPlanner_SOCKS5LayerConfigFlowsIntoSpec: socks5 层 config
// （version/auth_method/dst_addr）必须翻译成 spec.Socks——socks5 生成器按
// 契约读 Meta.Socks，greeting/request 字节由层 config 驱动（J 组
// SOCKS5-over-TLS：[tcp,tls,socks5] 链）。
func TestBuildLayersPlanner_SOCKS5LayerConfigFlowsIntoSpec(t *testing.T) {
	p, err := layers.BuildLayersPlanner("socks5", json.RawMessage(`[{"socks5":{"auth_method":"password","username":"alice","password":"secret","dst_addr":"target.example.com","dst_port":8080}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 1080}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var payloads []string
	for c := range ch {
		if len(c.Payload) > 0 {
			payloads = append(payloads, string(c.Payload))
		}
	}
	// greeting `05 01 02`（password 方法），auth 请求含 "alice"/"secret"，
	// request 含域名 target.example.com。
	if len(payloads) == 0 {
		t.Fatal("no payloads emitted")
	}
	if payloads[0] != "\x05\x01\x02" {
		t.Errorf("greeting = %q, want \\x05\\x01\\x02 (auth_method password not translated)", payloads[0])
	}
	joined := strings.Join(payloads, "|")
	if !strings.Contains(joined, "alice") || !strings.Contains(joined, "secret") {
		t.Errorf("auth request missing credentials in payloads: %q", payloads)
	}
	if !strings.Contains(joined, "target.example.com") {
		t.Errorf("request missing dst_addr in payloads: %q", payloads)
	}
}

// TestBuildLayersPlanner_SOCKS5TLSOptionalNotAutoInserted: socks5 的 tls
// OptionalOn 永不自动补——[socks5] 单层链生成普通 socks5（无 tls 层），
// SOCKS5-over-TLS 必须显式写 [tcp,tls,socks5]。
func TestBuildLayersPlanner_SOCKS5TLSOptionalNotAutoInserted(t *testing.T) {
	completed, err := layers.ValidateLayers(json.RawMessage(`[{"socks5":{}}]`), "socks5")
	if err != nil {
		t.Fatalf("ValidateLayers: %v", err)
	}
	if strings.Contains(completed, "tls") {
		t.Errorf("chain %q unexpectedly contains tls (OptionalOn must not auto-complete)", completed)
	}
}
