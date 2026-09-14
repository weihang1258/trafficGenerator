package tls

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// TLSGenerator is the tls tunnel-layer generator in event-transform mode
// (tls 事件变换器, P2e T13)。tls 在 transport **之内**（TLS record 是 TCP
// payload，链 [ip → tcp → tls → http]）——它不产 PacketConfig，而是把终结层
// 报文事件流（http 请求/响应字节）变换为 TLS record 事件流（方向保留），
// 由 tcp 层生成器消费（握手/分段/seq 推进全部归 tcp，与普通 http 链同款）。
//
// 驱动契约（drive 事件分支）：经普通 Generate 驱动——读 req.Meta.Events
// （内层终结层事件流），经 req.EmitMsg 转发变换后事件。握手 record 序列
// 在消费内层事件前注入（legacy tls1.3 fast path，planner.go:415-488 同款：
// ClientHello → ServerHello13 → EncryptedExtensions → Certificate13 →
// CertificateVerify → ServerFinished → ClientFinished），内层事件逐条包成
// ApplicationData record 转发。事件流关闭 = 内层数据结束，变换器退出。
//
// 与 legacy 的差异（结构所致，已接受）：
//   - 只实现 tls1.3（schema 默认）快速路径；tls1.0/1.1/1.2 同步拒绝
//     （层链未移植 legacy 的 ServerHello12 分支，不产错误版本字节）。
//   - 只支持 role=client（legacy 也无 role 反转路径；server 模式同步拒绝）。
//   - 不读 spec.TLS（flat tls 配置不作用于链路径）：握手参数（sni/alpn/
//     cipher 等）由 tls 层 config 驱动，与 gre 隧道链的"层 config 是接口"
//     语义一致。
//   - PSK/AlertPath/OCSPStapling/证书不注入（层 schema 无对应字段，T13 不
//     扩展；buildClientHello 以 nil/默认调用，record 结构与 legacy 默认一致）。
type TLSGenerator struct{}

// Name returns "tls".
func (g *TLSGenerator) Name() string { return "tls" }

// GenEvents is unimplemented for the tls layer (tls 是事件变换器，不是终结
// 层——事件由内层终结层产出，tls 只变换转发，经 EventTransformer 标记驱动)。
func (g *TLSGenerator) GenEvents() layers.EventGenerator { return nil }

// TransformEvents marks this generator as an event transformer (事件变换器
// 标记，assertEventWiring 据此允许 tls 位于终结层与 transport 之间)。
func (g *TLSGenerator) TransformEvents() bool { return true }

// Generate consumes the inner terminal event stream (req.Meta.Events),
// prepends the TLS 1.3 handshake record sequence, and forwards every inner
// message wrapped in an ApplicationData record (direction preserved).
func (g *TLSGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	// 结构性错误必须在**退出前排空输入**（review transform-wiring F1）：
	// 本生成器是 transformCh[0] 的唯一消费者——同步写者（终结层主线程）在
	// 满缓冲（64）时永久阻塞，不消费则 drive 死锁（与 MED-2 同款纪律）。
	// 真实链上 version/role 由 ValidateSpec 同步拒绝（chain_planner.go），
	// 但生成器独立防御层不可少——直接驱动或校验脱节时同样不能死锁。
	drain := func() error {
		events := req.Meta.Events
		for events != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			select {
			case _, ok := <-events:
				if !ok {
					return nil
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	if req.EmitMsg == nil {
		return fmt.Errorf("tls generator: EmitMsg is nil (tls is an event transformer; the inner terminal layer's events must be forwarded outward)")
	}
	if req.Layer.Name != "tls" {
		return fmt.Errorf("tls generator: layer name %q, want \"tls\"", req.Layer.Name)
	}
	cfg := req.Layer.Config
	version := tlsConfigString(cfg, "version")
	if version == "" {
		version = "tls1.3"
	}
	legacyVersion, err := tlsLegacyVersion(version)
	if err != nil {
		drain()
		return err
	}
	role := tlsConfigString(cfg, "role")
	if role == "" {
		role = "client"
	}
	if role != "client" {
		drain()
		return fmt.Errorf("tls generator: role %q not supported in the layer chain yet (only \"client\" emits the client-side handshake)", role)
	}
	sni := tlsConfigString(cfg, "sni")
	alpn := tlsConfigStrings(cfg, "alpn")
	if len(alpn) == 0 {
		alpn = []string{"h2", "http/1.1"}
	}
	// 握手 record 序列（legacy tls1.3 fast path，planner.go:415-488 同款）。
	cipherSuites := []uint16{cipherTLS13AES128GCM256, cipherTLS13AES256GCM384, cipherTLS13CHACHA20POLY1305}
	supportedGroups := []uint16{groupX25519, groupSecp256r1, groupSecp384r1}
	sigAlgs := []uint16{sigECDSA256r1, sigRSA256PSS, sigRSA256}
	steps := []layers.MessageEvent{
		{Up: true, Bytes: buildRecord(contentTypeHandshake, legacyVersion,
			buildClientHello(legacyVersion, sni, cipherSuites, supportedGroups, sigAlgs, alpn, nil, false, false, version))},
		{Up: false, Bytes: buildRecord(contentTypeHandshake, legacyVersion, buildServerHello13(cipherSuites[0], supportedGroups[0]))},
		{Up: false, Bytes: buildRecord(contentTypeHandshake, legacyVersion, buildEncryptedExtensions(alpn[0]))},
		{Up: false, Bytes: buildRecord(contentTypeHandshake, legacyVersion, buildCertificate13(nil, false))},
		{Up: false, Bytes: buildRecord(contentTypeHandshake, legacyVersion, buildCertificateVerify(sigECDSA256r1, 64))},
		{Up: false, Bytes: buildRecord(contentTypeHandshake, legacyVersion, buildFinished(32))},
		{Up: true, Bytes: buildRecord(contentTypeHandshake, legacyVersion, buildFinished(32))},
	}
	emit := func(ev layers.MessageEvent) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return req.EmitMsg(ev)
	}
	for _, ev := range steps {
		if err := emit(ev); err != nil {
			drain()
			return err
		}
	}
	// 内层终结层事件流（http 请求/响应）：字节包成 ApplicationData record
	// 后转发（方向保留）。事件流关闭 = 内层数据结束，变换器退出。
	// 单条 record 明文上限 2^14+1（RFC 8446 §5.2）：内层消息超限时按
	// 16385 字节分片成多条 record（review tls-layer finding 1——原实现
	// 整包单 record，>65535 时 buildRecord 的 uint16 长度截断、>16384 违
	// 反上限，Wireshark 标 malformed）。分片 record 均为同一方向同一
	// 消息，tcp 层按 MSS 再切段，字节顺序不变。
	events := req.Meta.Events
	for events != nil {
		var ev layers.MessageEvent
		var ok bool
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok = <-events:
			if !ok {
				events = nil
				continue
			}
		}
		payload := ev.Bytes
		if len(payload) == 0 {
			// 空消息（如空请求体）仍产出一条空 record，保持事件
			// 一一对应（legacy 语义：空 payload 事件 = 一条数据段）。
			record := buildRecord(contentTypeApplicationData, legacyVersion, payload)
			if err := emit(layers.MessageEvent{Up: ev.Up, Bytes: record}); err != nil {
				drain()
				return err
			}
			continue
		}
		for len(payload) > 0 {
			n := len(payload)
			if n > maxPlaintextRecord {
				n = maxPlaintextRecord
			}
			record := buildRecord(contentTypeApplicationData, legacyVersion, payload[:n])
			if err := emit(layers.MessageEvent{Up: ev.Up, Bytes: record}); err != nil {
				drain()
				return err
			}
			payload = payload[n:]
		}
	}
	return nil
}

// maxPlaintextRecord is the maximum plaintext length of a TLS record
// (RFC 8446 §5.2: 2^14+1). Messages larger than this MUST be split into
// multiple records.
const maxPlaintextRecord = 16385

// tlsLegacyVersion resolves the layer config version to the TLS record
// legacy_version. Only tls1.3 is implemented in the layer chain (RFC 8446:
// legacy_version 0x0303 for TLS 1.3 records).
func tlsLegacyVersion(version string) (uint16, error) {
	switch version {
	case "tls1.3":
		return protocolVersionTLS12, nil
	default:
		return 0, fmt.Errorf("tls generator: version %q not supported in the layer chain yet (only \"tls1.3\")", version)
	}
}

// tlsConfigString reads a string layer config field (schema V9 已保证类型
// 合法，这里只做防御性读取；nil/缺失 → ""）。
func tlsConfigString(cfg map[string]interface{}, key string) string {
	s, _ := cfg[key].(string)
	return s
}

// tlsConfigStrings reads a list layer config field (schema 类型 "list" 经
// JSON 解码为 []interface{}）。
func tlsConfigStrings(cfg map[string]interface{}, key string) []string {
	raw, ok := cfg[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func init() {
	// 反向注册 tls 隧道层生成器工厂（layers 包不依赖 tls 包；注册后
	// BuildLayersPlanner("tls", ...) 的 newGenerator 可实例化 tls 层）。
	layers.RegisterLayerGenerator("tls", func() (layers.LayerGenerator, error) {
		return &TLSGenerator{}, nil
	})
	layers.RegisterLayerValidator("tls", validateTLSSpec)
}

// validateTLSSpec is the tls tunnel-layer spec validator (D-TLS-1 §5,
// http validateHTTPSpec 同款：复用 legacy Planner.Validate（IP 格式 +
// MSS 下界 + 版本枚举/role/SNI/AlertPath/PSK），再把 spec.TCP 握手/挥手
// pin true——legacy tls.go 恒产握手/挥手（Plan :244 handshake/termination
// 默认 true，spec.TCP nil 时更是恒 true），spec.TCP 零值 false 会让 tcp
// 层生成器跳过握手/挥手。
//
// 注意：只做"校验 + 握手 pin"，不碰 spec.TLS——tls 层 config 的
// version/sni/alpn/role 由生成器在 drive 期直接读 req.Layer.Config
// （:80-101），没有"回填 spec.TLS 供生成器读"这一步（与 http 的
// translateTerminalConfig→Meta.HTTP 直传不同）。链上 spec.TLS 恒 nil
// 是合法态（legacy planner.go:227 同款默认兜底：nil → tls1.3）。
func validateTLSSpec(spec *core.FlowSpec) error {
	if err := (&Planner{}).Validate(*spec); err != nil {
		return err
	}
	if spec.TCP == nil {
		spec.TCP = &core.TCPConfig{}
	}
	spec.TCP.Handshake = true
	spec.TCP.Termination = true
	return nil
}
