package layers

import "fmt"

// DefaultRegistry returns the built-in layer registry (层注册表，§4.4)。
// 字段默认值与现有实现对齐（strategy_convert.go / types.go）。
// 完整字段表见实现计划；此处先注册公共层与常用协议层。
func DefaultRegistry() *Registry {
	r := NewRegistry()

	// ---- 网络层（ip）----
	// §4.4: ip 是传输层/隧道层的硬依赖底座，无 depends_on、无 optional_on。
	r.Register(LayerSchema{Name: "ip", Category: CategoryNetwork,
		Fields: map[string]FieldSchema{
			"src":     {Type: "ip", Default: "10.0.0.1"},
			"dst":     {Type: "ip", Default: "20.0.0.1"},
			"ttl":     {Type: "uint8", Default: uint8(64), Min: 0, Max: 255},
			"dscp":    {Type: "uint8", Default: uint8(0), Min: 0, Max: 63},
			"ecn":     {Type: "uint8", Default: uint8(0), Min: 0, Max: 3},
			"frag_offset": {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
		},
	})

	// ---- 二层层（L2）----
	r.Register(LayerSchema{Name: "eth", Category: CategoryL2,
		Fields: map[string]FieldSchema{
			"src_mac": {Type: "mac"},
			"dst_mac": {Type: "mac"},
		},
	})
	r.Register(LayerSchema{Name: "vlan", Category: CategoryL2,
		DependsOn:  []string{"eth"},   // vlan 垫在 eth 上（缺了自动补）
		OptionalOn: []string{"eth"},   // 可选底座：默认不启用
		Fields: map[string]FieldSchema{
			"id":       {Type: "uint16", Default: uint16(0), Min: 0, Max: 4095},
			"priority": {Type: "uint8", Default: uint8(0), Min: 0, Max: 7},
		},
	})

	// ---- 传输层（transport）----
	r.Register(LayerSchema{Name: "tcp", Category: CategoryTransport,
		DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"src_port":    {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535}, // 0 = 由上层决定
			"dst_port":    {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"mss":         {Type: "uint16", Default: uint16(1460), Min: 536, Max: 65535},
			"window_size": {Type: "uint16", Default: uint16(65535), Min: 0, Max: 65535},
			"handshake":   {Type: "bool", Default: true},
			"termination": {Type: "bool", Default: true},
			"rst":         {Type: "bool", Default: false},
			"initial_seq": {Type: "uint32", Default: uint32(0)},
		},
	})
	r.Register(LayerSchema{Name: "udp", Category: CategoryTransport,
		DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"src_port": {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"dst_port": {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
		},
	})

	// ---- 终结层（terminal）----
	r.Register(LayerSchema{Name: "http", Category: CategoryTerminal,
		DependsOn:  []string{"tcp"},
		OptionalOn: []string{"tls"}, // 可选底座：默认不启用 → {"http":{}} 生成 http 非 https
		Fields: map[string]FieldSchema{
			"method":  {Type: "string", Default: "GET"},
			"uri":     {Type: "string", Default: "/"},
			"version": {Type: "string", Default: "1.1"},
			"headers": {Type: "map", Default: map[string]interface{}{}},
			"body":    {Type: "string", Default: ""},
		},
	})
	r.Register(LayerSchema{Name: "dns", Category: CategoryTerminal,
		DependsOn:   []string{"udp"}, // 默认 udp；用户显式写 tcp 层覆盖（补全时替代）
		TransportOn: []string{"udp", "tcp"}, // 支持的传输层，第一个 = 默认（须与 DependsOn[0] 一致）
		OptionalOn:  []string{"tls"},
		Fields: map[string]FieldSchema{
			"query_type": {Type: "uint16", Default: uint16(1), Min: 0, Max: 65535},
			"name":       {Type: "string", Default: "example.com"},
		},
	})
	// ---- 波 4：ntp/snmp/syslog（udp 终结层，配置经 FlowMeta 直传生成器，
	// 不落层 config——协议配置字段繁多且 ValidateLayerConfig 拒绝未知字段）。
	r.Register(LayerSchema{Name: "ntp", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
	})
	r.Register(LayerSchema{Name: "snmp", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
	})
	r.Register(LayerSchema{Name: "syslog", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
	})
	// ---- 波 5：mdns/dhcp/dhcpv6/ssdp/rip（udp 终结层，多播/广播目标经
	// MessageEvent.DstIP/DstMAC 覆盖；配置经 FlowMeta 直传生成器）。
	r.Register(LayerSchema{Name: "mdns", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
	})
	r.Register(LayerSchema{Name: "dhcp", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
	})
	r.Register(LayerSchema{Name: "dhcpv6", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
	})
	r.Register(LayerSchema{Name: "ssdp", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
	})
	r.Register(LayerSchema{Name: "rip", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
	})
	// ---- P4a：tftp（udp 终结层，配置经 FlowMeta 直传生成器——协议字段
	// 繁多（mode/filename/blksize/error_code/server_tid...）不落层 config，
	// ValidateLayerConfig 拒绝未知字段）。
	r.Register(LayerSchema{Name: "tftp", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
	})
	// ---- P4a：enip（tcp 终结层，首个 tcp 载体协议。ENIP 命令即数据段
	// （无握手/终止），TCP 语义（握手/seq-ack/挥手）交给 tcp 层生成器；
	// 配置（commands/io_data/session_count...）繁多不落层 config（layers
	// 数组条目零负载），经 flat 键 spec.ENIP 携带、FlowMeta 直传生成器。
	// UDP I/O 帧不支持（chain 无 UDP 混合流，生成器显式拒绝 IOData）。
	r.Register(LayerSchema{Name: "enip", Category: CategoryTerminal,
		DependsOn: []string{"tcp"},
	})
	// ---- P4a：a2a（tcp 终结层。HTTP/JSON-RPC over TCP——命令即数据段，
	// TCP 语义（握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器；配置
	// （tasks/auth/http/tcp...）繁多不落层 config（layers 数组条目零负载），
	// 经 spec.Payload（A2AConfig JSON）携带、FlowMeta.Payload 直传生成器。
	r.Register(LayerSchema{Name: "a2a", Category: CategoryTerminal,
		DependsOn: []string{"tcp"},
	})
	// ---- P4a：dnp3（tcp 终结层。IEEE 1815-2012——scenario 展开为链路层
	// 帧序列，TCP 语义（握手/seq-ack/挥手）交给 tcp 层生成器；配置
	// （scenario/objects/link_fcb...）繁多不落层 config（layers 数组条目
	// 零负载），经 spec.DNP3 flat 键携带、FlowMeta 直传生成器。UDP 传输
	// 与 multi_outstation 多流展开不支持（生成器显式拒绝）。
	r.Register(LayerSchema{Name: "dnp3", Category: CategoryTerminal,
		DependsOn: []string{"tcp"},
	})
	// ---- P4a：doip（tcp 终结层。ISO 13400-2 DoIP——routing activation /
	// diagnostic messages / alive check / generic nack 阶段逐报文事件，
	// 0x36 TransferData 协议级分段复刻（legacy doip.go:677-701 同款），
	// TCP 语义（握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器；配置
	// （protocol_version/activation/messages/alive_check...）繁多不落层
	// config（layers 数组条目零负载），经 spec.DoIP flat 键携带、FlowMeta
	// 直传生成器。UDP 阶段（Discovery/EntityStatus/PowerMode）与激活失败
	// 提前终止不支持（生成器显式拒绝）。
	r.Register(LayerSchema{Name: "doip", Category: CategoryTerminal,
		DependsOn: []string{"tcp"},
	})
	// ---- P4a：gbt32960（tcp 终结层。GB/T 32960.3-2016——车辆/平台状态机
	// 展开为逐消息事件（0x01 登入 → 0x0C 确认 → 0x02 上报 ×N → 0x04 登出，
	// 0x08 控制/0x03 补报 按序插入；平台侧 0x05/0x0B 心跳 ×N/0x06），wire
	// 字节由 buildMessage 纯函数产出），TCP 语义（握手/seq-ack/挥手）交给
	// tcp 层生成器；配置（role/vin/reports/remote_control/heartbeat...）繁多
	// 不落层 config（layers 数组条目零负载），经 spec.GBT32960 flat 键携带、
	// FlowMeta 直传生成器。
	r.Register(LayerSchema{Name: "gbt32960", Category: CategoryTerminal,
		DependsOn: []string{"tcp"},
	})
	r.Register(LayerSchema{Name: "ftp", Category: CategoryTerminal,
		DependsOn:  []string{"tcp"},
		OptionalOn: []string{"tls"},
		Fields: map[string]FieldSchema{
			"username": {Type: "string", Default: "anonymous"},
			"password": {Type: "string", Default: "anonymous"},
		},
	})
	r.Register(LayerSchema{Name: "smtp", Category: CategoryTerminal,
		DependsOn:  []string{"tcp"},
		OptionalOn: []string{"tls"},
		Fields: map[string]FieldSchema{
			"from": {Type: "string", Default: "sender@example.com"},
			"to":   {Type: "string", Default: "recipient@example.com"},
		},
	})

	// ---- 隧道层（tunnel）----
	r.Register(LayerSchema{Name: "tls", Category: CategoryTunnel,
		DependsOn: []string{"tcp"},
		// InnerRequired 为空 = 内层可以是任意终结层，不用补。
		Fields: map[string]FieldSchema{
			"version": {Type: "string", Default: "tls1.3"},
			"sni":     {Type: "string", Default: ""},
			"alpn":    {Type: "list", Default: []interface{}{}},
			"role":    {Type: "string", Default: "client"},
		},
	})
	r.Register(LayerSchema{Name: "gre", Category: CategoryTunnel,
		DependsOn:     []string{"ip"},  // 外层 ip 自动补
		InnerRequired: []string{"ip"},  // 内层必须从 ip 开始，缺了自动补内层 ip
		Fields: map[string]FieldSchema{
			"key":      {Type: "uint32", Default: uint32(0)},
			"checksum": {Type: "bool", Default: false},
			"sequence": {Type: "bool", Default: false},
		},
	})

	// ---- 二层层：mpls / pppoe（占位，P2 补字段）----
	r.Register(LayerSchema{Name: "mpls", Category: CategoryL2})
	r.Register(LayerSchema{Name: "pppoe", Category: CategoryL2})

	return r
}

// Verify registry contents at init (defensive: catches typo'd depends_on).
func init() {
	r := DefaultRegistry()
	for _, name := range r.List() {
		s, _ := r.Get(name)
		for _, dep := range append(append([]string{}, s.DependsOn...), s.InnerRequired...) {
			if !r.Has(dep) {
				panic(fmt.Sprintf("layers: schema %q references unknown layer %q", name, dep))
			}
		}
	}
}
