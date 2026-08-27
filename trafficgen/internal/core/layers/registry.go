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
			"src":         {Type: "ip", Default: "10.0.0.1"},
			"dst":         {Type: "ip", Default: "20.0.0.1"},
			"ttl":         {Type: "uint8", Default: uint8(64), Min: 0, Max: 255},
			"dscp":        {Type: "uint8", Default: uint8(0), Min: 0, Max: 63},
			"ecn":         {Type: "uint8", Default: uint8(0), Min: 0, Max: 3},
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
		DependsOn:  []string{"eth"}, // vlan 垫在 eth 上（缺了自动补）
		OptionalOn: []string{"eth"}, // 可选底座：默认不启用
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

	// ---- S7comm (tcp 终结层) ----
	r.Register(LayerSchema{Name: "s7", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "102"},
		Fields: map[string]FieldSchema{
			"transport": {Type: "string", Default: ""},
			"sessions":  {Type: "int", Default: 0, Min: 0, Max: 0},
			"pdu_ref":   {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"pdu_size":  {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"commands":  {Type: "list", Default: []interface{}{}},
		}})
	r.Register(LayerSchema{Name: "http", Category: CategoryTerminal,
		DependsOn:       []string{"tcp"},
		OptionalOn:      []string{"tls"}, // 可选底座：默认不启用 → {"http":{}} 生成 http 非 https
		TransformEvents: true,            // http_flv 链 [ip→tcp→http→http_flv] 中 http 充当事件变换器
		Fields: map[string]FieldSchema{
			"method":  {Type: "string", Default: "GET"},
			"uri":     {Type: "string", Default: "/"},
			"version": {Type: "string", Default: "1.1"},
			"headers": {Type: "map", Default: map[string]interface{}{}},
			"body":    {Type: "string", Default: ""},
		},
		// http 家族目的端口落在 tcp 层（DefaultDstPort=80，strategy_convert
		// 同款）；声明 tcp.dst_port 供 layers 数组路径（未显式写端口）补齐。
		FieldContract: map[string]string{"tcp.dst_port": "80"},
	})
	r.Register(LayerSchema{Name: "dns", Category: CategoryTerminal,
		DependsOn:   []string{"udp"},        // 默认 udp；用户显式写 tcp 层覆盖（补全时替代）
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
	// ---- P4a：mcp（tcp 终结层。MCP 会话（JSON-RPC 2.0）——initialize →
	// 请求/响应序列 → 可选挥手，三传输（stdio/http_sse/streamable）均单
	// TCP 连接：stdio 逐行 JSON，HTTP 模式为 HTTP 帧（GET/POST/DELETE +
	// SSE push），TCP 语义（握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器；
	// streamable 的 DELETE/204 是应用层帧（带内，非挥手）。配置
	// （transport/requests/responses/notifications/rounds...）繁多不落层
	// config（layers 数组条目零负载），经 spec.MCP flat 键携带、FlowMeta
	// 直传生成器；目的端口默认 stdio→22 / HTTP→8081（validateSpecBase）。
	r.Register(LayerSchema{Name: "mcp", Category: CategoryTerminal,
		DependsOn: []string{"tcp"},
	})
	// ---- P4a：modbus（tcp 终结层。Modbus TCP——事务序列展开为逐帧事件
	// （每事务 request MBAP 帧 + 可选 response MBAP 帧，共享 TID），wire
	// 字节由 buildRequestPDU/buildResponsePDU/BuildMBAPFrame 纯函数产出；
	// 响应可由 ResponseMode / broadcast suppress / Force Listen Only 抑制），
	// TCP 语义（握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器；配置
	// （transactions/unit_id/suppress_broadcast/shared_tid_space...）繁多不
	// 落层 config（layers 数组条目零负载），经 spec.MODBUS flat 键携带、
	// FlowMeta 直传生成器；目的端口默认 502（validateSpecBase）；多流展开
	// （master_count/flow_count > 1）不支持（生成器 + validator 双拒绝）。
	r.Register(LayerSchema{Name: "modbus", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "502"},
		Fields: map[string]FieldSchema{
			"unit_id":            {Type: "uint8", Default: uint8(1), Min: 0, Max: 255},
			"suppress_broadcast": {Type: "bool", Default: false},
			"master_count":       {Type: "int", Default: 0},
			"flow_count":         {Type: "int", Default: 0},
			"shared_tid_space":   {Type: "bool", Default: false},
		},
	})
	// ---- P4a：mqtt（tcp 终结层。MQTT 3.1.1/5.0——一次 flow = 一个
	// 4-tuple 上一条连接 + 一个 client_id 的完整会话：CONNECT → CONNACK →
	// [SUBSCRIBE/SUBACK]×N → [PUBLISH/QoS ack 交换]×N → [PINGREQ/PINGRESP]
	// → [Will 发布] → [DISCONNECT]，wire 字节由 build* 纯函数产出），TCP
	// 语义（握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器；配置
	// （version/client_id/subscriptions/messages/will/connect_ack_code...）
	// 繁多不落层 config（layers 数组条目零负载），经 spec.MQTT flat 键携带、
	// FlowMeta 直传生成器；目的端口默认 1883（validateSpecBase）；多流展开
	// （sessions[] 每项独立 4-tuple + 自动递增 srcPort）不支持（生成器 +
	// validator 双拒绝）。
	r.Register(LayerSchema{Name: "mqtt", Category: CategoryTerminal,
		DependsOn: []string{"tcp"},
		Fields: map[string]FieldSchema{
			"version":                     {Type: "int", Default: 0, Min: 0, Max: 0},
			"client_id":                   {Type: "string", Default: ""},
			"keep_alive":                  {Type: "int", Default: 60, Min: 0, Max: 0},
			"clean_session":               {Type: "bool", Default: true},
			"username":                    {Type: "string", Default: ""},
			"password":                    {Type: "string", Default: ""},
			"will":                        {Type: "object"},
			"connect_ack_code":            {Type: "int", Default: 0, Min: 0, Max: 0},
			"connect_ack_session_present": {Type: "bool", Default: false},
			"subscriptions":               {Type: "list", Default: []interface{}{}},
			"messages":                    {Type: "list", Default: []interface{}{}},
			"ping_after_messages":         {Type: "bool", Default: false},
			"disconnect":                  {Type: "bool", Default: true},
			"disconnect_reason":           {Type: "int", Default: 0, Min: 0, Max: 0},
			"sessions":                    {Type: "list", Default: []interface{}{}},
			"properties":                  {Type: "list", Default: []interface{}{}},
			"connack_properties":          {Type: "list", Default: []interface{}{}},
		}})
	// ---- P4a：nfs（双载体终结层。NFSv3/v4 RPC——每 op 一个调用/回复对
	// （buildCall/buildReply 纯函数产出），MOUNT 程序（v3）与
	// SETCLIENTID/PUTROOTFH/OPEN_CONFIRM（v4）自动插入同 legacy；默认
	// tcp 载体（RFC 5531 记录标记 RM 帧，DependsOn[0] 与 TransportOn[0]
	// 一致），用户显式写 udp 层覆盖（补全时替代；UDP 载体 = 裸 RPC 数据报），
	// TCP 语义（握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器；配置
	// （version/transport/ops/auth_flavor...）繁多不落层 config（layers 数组
	// 条目零负载），经 spec.Metadata["nfs"]（flat 键 nfs 的 JSON 解码子 map）
	// 携带、FlowMeta 直传生成器；目的端口默认 2049（validateSpecBase）；
	// 多流展开（sessions > 1 自动递增 srcPort）不支持（生成器 + validator
	// 双拒绝）；载体与 transport 一致性由 ValidateSpec 结构性校验
	// （chain_planner.go nfsTransportFromMetadata）。
	r.Register(LayerSchema{Name: "coap", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
		Fields: map[string]FieldSchema{
			"method":                  {Type: "string", Default: ""},
			"path":                    {Type: "list", Default: []interface{}{}},
			"query":                   {Type: "list", Default: []interface{}{}},
			"payload":                 {Type: "list", Default: []interface{}{}},
			"content_format":          {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"accept":                  {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"confirmable":             {Type: "bool", Default: false},
			"token":                   {Type: "list", Default: []interface{}{}},
			"token_length":            {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"message_id":              {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"version":                 {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"code":                    {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"response":                {Type: "bool", Default: false},
			"response_code":           {Type: "string", Default: ""},
			"response_payload":        {Type: "list", Default: []interface{}{}},
			"response_content_format": {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"response_blocks":         {Type: "list", Default: []interface{}{}},
			"block1":                  {Type: "object"},
			"block2":                  {Type: "object"},
			"observe":                 {Type: "object"},
			"retransmit":              {Type: "object"},
			"error_code":              {Type: "string", Default: ""},
			"error_payload":           {Type: "list", Default: []interface{}{}},
			"error_responses":         {Type: "list", Default: []interface{}{}},
			"uri_max_length":          {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"tokens":                  {Type: "list", Default: []interface{}{}},
			"message_ids":             {Type: "list", Default: []interface{}{}},
			"session_src_ips":         {Type: "list", Default: []interface{}{}},
			"session_src_ports":       {Type: "list", Default: []interface{}{}},
		}})
	r.Register(LayerSchema{Name: "stun", Category: CategoryTerminal,
		DependsOn:   []string{"udp"},
		TransportOn: []string{"udp", "tcp"},
	})
	// ---- P4a：rtmfp（udp 终结层。Adobe RTMFP——Real-Time Media Flow
	// Protocol，UDP 承载的实时音视频/数据流协议，握手 → cookie/session →
	// 可靠/不可靠消息 → 分片/ACK/重传 → 保活 → 关闭，wire 字节由 build*
	// 纯函数产出），UDP 语义（数据报/checksum）交给 udp 层生成器；配置
	// 经 spec.RTMFP flat 键携带、FlowMeta 直传生成器；目的端口默认 1935。
	r.Register(LayerSchema{Name: "rtmfp", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
	})
	// ---- wireguard（udp 终结层。WireGuard——Noise_IKpsk2 发送发起/响应/
	// cookie/传输数据报文序列）。UDP 语义（数据报/checksum）交给 udp 层
	// 生成器；配置经 spec.WireGuard flat 键携带、FlowMeta 直传生成器（tftp
	// 重放模式：生成器复用 legacy Plan）；目的端口默认 51820。
	r.Register(LayerSchema{Name: "wireguard", Category: CategoryTerminal,
		DependsOn:     []string{"udp"},
		FieldContract: map[string]string{"udp.dst_port": "51820"}, // 用户显式非标准端口优先，不强制
	})
	// ---- l2tp（udp 终结层。L2TPv2/v3——LAC/LNS 间 UDP 隧道控制消息 + PPP
	// 数据帧序列，wire 字节由 buildControlMessage/buildDataMessage 纯函数
	// 产出）。UDP 语义交给 udp 层生成器；配置经 spec.L2TP flat 键携带、
	// FlowMeta 直传生成器（tftp 重放模式）；源/目的端口 Plan 内默认 1701。
	r.Register(LayerSchema{Name: "l2tp", Category: CategoryTerminal,
		DependsOn:     []string{"udp"},
		FieldContract: map[string]string{"udp.dst_port": "1701"}, // RFC 2661 默认 1701；用户显式非标准端口优先，不强制
	})
	// ---- gtp（udp 终结层。GTP-U/GTP-C——UDP 承载的隧道协议，GTP header +
	// 内层 IP 包，wire 字节由 buildGTPMessage/buildInnerIPv4Packet 纯函数
	// 产出）。UDP 语义交给 udp 层生成器；配置经 spec.GTP flat 键携带、
	// FlowMeta 直传生成器（tftp 重放模式）；目的端口按 Mode 默认
	// （u=2152/c=2123，Plan 内 resolve，无固定 FieldContract）。
	r.Register(LayerSchema{Name: "gtp", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
	})
	// ---- ike（udp 终结层。IKEv1/v2——UDP 承载的密钥交换协议：IKE 消息序列
	// + 可选 ESP 数据面，wire 字节由 buildIKEMessageBytes 纯函数产出）。UDP
	// 语义交给 udp 层生成器；配置经 spec.IKE flat 键携带、FlowMeta 直传
	// 生成器（tftp 重放模式）；目的端口默认 500（RFC 7296 §1.2）。
	r.Register(LayerSchema{Name: "ike", Category: CategoryTerminal,
		DependsOn:     []string{"udp"},
		FieldContract: map[string]string{"udp.dst_port": "500"}, // RFC 7296 默认 500；用户显式非标准端口须为 0/500（ike Validate 强制），不强制覆盖
	})
	// ---- ike_nat_t（udp 终结层。IKEv2 NAT-T——端口浮动 + Non-ESP Marker 的
	// NAT 穿透变体，wire 字节由 buildIKENATTMessage 纯函数产出）。UDP 语义
	// 交给 udp 层生成器；配置经 spec.IKENATT flat 键携带、FlowMeta 直传
	// 生成器（tftp 重放模式）；目的端口默认 4500（RFC 3948 NATTPort）。
	r.Register(LayerSchema{Name: "ike_nat_t", Category: CategoryTerminal,
		DependsOn:     []string{"udp"},
		FieldContract: map[string]string{"udp.dst_port": "4500"}, // RFC 3948 默认 4500；用户显式非标准端口优先，不强制
	})
	// ---- amqp（tcp 终结层。AMQP 0-9-1——高级消息队列协议，TCP 承载的
	// 消息队列 wire 协议，8-byte protocol header → METHOD/HEADER/BODY/
	// HEARTBEAT frame 序列，frame layout 为
	// FrameType(1)|Channel(2)|Size(4)|Payload(Size)|FrameEnd(0xCE)，wire
	// 字节由 build* 纯函数产出），TCP 语义（握手/seq-ack/挥手/MSS 分段）交给
	// tcp 层生成器；配置（profile/frame_max/channel_max/heartbeat/connections/
	// events...）繁多不落层 config（layers 数组条目零负载），经 spec.AMQP flat
	// 键携带、FlowMeta 直传生成器；目的端口默认 5672。
	r.Register(LayerSchema{Name: "amqp", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "5672"},
		Fields: map[string]FieldSchema{
			"profile":     {Type: "string", Default: ""},
			"frame_max":   {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"channel_max": {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"heartbeat":   {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"connections": {Type: "list", Default: []interface{}{}},
			"wire_fault":  {Type: "string", Default: ""},
		},
	})
	// ---- http_flv（http 终结层。HTTP-FLV——HTTP/1.1 GET 承载 FLV 字节流，
	// 9-byte FLV header + PreviousTagSize0 + tag 序列，script/audio/video
	// 三类 tag + AMF0/AAC/AVC 编码，wire 字节由 build* 纯函数产出），HTTP
	// 语义（请求/响应/头）交给 http 层生成器；配置（tags/flags...）繁多不落层
	// config（layers 数组条目零负载），经 spec.HTTPFLV flat 键携带、FlowMeta
	// 直传生成器；http 层默认 dst_port=80。
	r.Register(LayerSchema{Name: "http_flv", Category: CategoryTerminal,
		DependsOn: []string{"http"},
		// 数组中的 http_flv 条目零负载——声明字段表为空会拒绝用户写的
		// {"http_flv":{"flags":..,"rounds":..}} 配置。与其它经 spec.* 直传的
		// 协议（stun/dns 同款）不同，http_flv 的 flat 配置直接落在该层 config
		// 上（strategy_convert http_flv 分支写 layer config），所以声明以下
		// 字段让 ValidateLayerConfig 放行；值在校验器/生成器中解析。
		Fields: map[string]FieldSchema{
			"flags":      {Type: "uint8", Default: uint8(0)},
			"rounds":     {Type: "int", Default: 0},
			"tags":       {Type: "list", Default: []interface{}{}},
			"wire_fault": {Type: "string", Default: ""},
		},
		// http 家族直接承载层 http，但目的端口落在 tcp 层（http 生成器读
		// tcp 层 dst_port）；FieldContract 声明 tcp.dst_port=80 供通用应用
		// 补齐未显式写的端口。
		FieldContract: map[string]string{"tcp.dst_port": "80"},
	})
	r.Register(LayerSchema{Name: "hls", Category: CategoryTerminal,
		DependsOn: []string{"http"},
		Fields: map[string]FieldSchema{
			"profile":    {Type: "string", Default: "rfc8216_v7"},
			"wire_fault": {Type: "string", Default: ""},
		},
		FieldContract: map[string]string{"tcp.dst_port": "80"},
	})
	r.Register(LayerSchema{Name: "hds", Category: CategoryTerminal,
		DependsOn: []string{"http"},
		Fields: map[string]FieldSchema{
			"profile":    {Type: "string", Default: "hds_http1"},
			"wire_fault": {Type: "string", Default: ""},
		},
		FieldContract: map[string]string{"tcp.dst_port": "80"},
	})
	r.Register(LayerSchema{Name: "opcua", Category: CategoryTerminal, DependsOn: []string{"tcp"}, Fields: map[string]FieldSchema{
		"security_mode":    {Type: "string", Default: "none"},
		"read":             {Type: "bool", Default: true},
		"close":            {Type: "bool", Default: true},
		"skip_channel":     {Type: "bool", Default: false},
		"bad_message_size": {Type: "bool", Default: false},
		"bad_length":       {Type: "bool", Default: false},
	}})
	r.Register(LayerSchema{Name: "mms", Category: CategoryTerminal, DependsOn: []string{"tcp"}})
	r.Register(LayerSchema{Name: "moxa", Category: CategoryTerminal, DependsOn: []string{"tcp"}})
	r.Register(LayerSchema{Name: "someip", Category: CategoryTerminal, DependsOn: []string{"udp"}, TransportOn: []string{"udp", "tcp"}})
	r.Register(LayerSchema{Name: "drda", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "446"},
		Fields: map[string]FieldSchema{
			"transport":        {Type: "string", Default: ""},
			"session_start":    {Type: "int", Default: 0, Min: 0, Max: 0},
			"ccsid":            {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"correlator_start": {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"correlator_inc":   {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"security_user":    {Type: "string", Default: ""},
			"security_token":   {Type: "list", Default: []interface{}{}},
			"rdb_name":         {Type: "string", Default: ""},
			"sql":              {Type: "object"},
			"dss_segments":     {Type: "list", Default: []interface{}{}},
		}})
	r.Register(LayerSchema{Name: "thrift", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "9090"},
		Fields: map[string]FieldSchema{
			"transport": {Type: "string", Default: ""},
			"messages":  {Type: "list", Default: []interface{}{}},
		}})
	r.Register(LayerSchema{Name: "tns", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "1521"}})
	r.Register(LayerSchema{Name: "mongodb", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "27017"},
		Fields: map[string]FieldSchema{
			"messages":         {Type: "list", Default: []interface{}{}},
			"sessions":         {Type: "list", Default: []interface{}{}},
			"bson_fixture_hex": {Type: "string", Default: ""},
			"wire_fault":       {Type: "object"},
		}})
	r.Register(LayerSchema{Name: "dameng", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "5236"}})
	r.Register(LayerSchema{Name: "postgresql", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		// P0a: postgresql 提为共享 PG v3 wire 层（kingbase 作其 dialect 变体，
		// 不当独立层）。FieldContract 声明"直接承载层" tcp 的 dst_port 契约值：
		// dialect=postgresql → 5432；dialect=kingbase → 54321（effectiveFieldContract
		// 据 dialect 覆盖，见 chain_planner.go）。值 = 常量，变体只改常量不破性质。
		FieldContract: map[string]string{"tcp.dst_port": "5432"},
		Fields: map[string]FieldSchema{
			"dialect":      {Type: "string", Default: "postgresql"},
			"wire_profile": {Type: "string", Default: "postgresql_v3"},
			"events":       {Type: "list", Default: []interface{}{}},
			"sessions":     {Type: "list", Default: []interface{}{}},
			// wire_fault is a negative-test fault object {"kind":..., "value":...}.
			// Default nil (NOT "") so completedConfig omits it: an injected "" would
			// survive the JSON round-trip as WireFault='""' and be mis-read as a
			// fault by the validator.
			"wire_fault": {Type: "object"},
		},
	})
	r.Register(LayerSchema{Name: "cql", Category: CategoryTerminal, DependsOn: []string{"tcp"}})
	r.Register(LayerSchema{Name: "iec104", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "2404"},
		Fields: map[string]FieldSchema{
			"transport":       {Type: "string", Default: ""},
			"role":            {Type: "string", Default: ""},
			"common_address":  {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"startdt":         {Type: "bool", Default: false},
			"stopdt":          {Type: "bool", Default: false},
			"events":          {Type: "list", Default: []interface{}{}},
			"commands":        {Type: "list", Default: []interface{}{}},
			"type_id":         {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"cause":           {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"ioa":             {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"value":           {Type: "int", Default: 0, Min: 0, Max: 0},
			"siq":             {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"qds":             {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"diq":             {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"sco":             {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"dco":             {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"qoi":             {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"select":          {Type: "bool", Default: false},
			"time":            {Type: "string", Default: ""},
			"max_apdu_length": {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"repeat":          {Type: "int", Default: 0, Min: 0, Max: 0},
		}})
	r.Register(LayerSchema{Name: "goose", Category: CategoryTerminal, DependsOn: []string{"eth"}})
	r.Register(LayerSchema{Name: "sv", Category: CategoryTerminal, DependsOn: []string{"eth"}})
	r.Register(LayerSchema{Name: "bgp", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "179"},
		Fields: map[string]FieldSchema{
			"transport":    {Type: "string", Default: ""},
			"version":      {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"asn":          {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"hold_time":    {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"identifier":   {Type: "string", Default: ""},
			"marker":       {Type: "list", Default: []interface{}{}},
			"length":       {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"wire_profile": {Type: "string", Default: ""},
			"capabilities": {Type: "list", Default: []interface{}{}},
			"update":       {Type: "list", Default: []interface{}{}},
			"notification": {Type: "list", Default: []interface{}{}},
		}})
	// ---- B3：ldp（双载体终结层。RFC 5036——UDP/646 discovery Hello 与
	// TCP/646 session（Initialization/KeepAlive/Address/Label*/Notification）
	// 逐事件产出，wire 字节由 build* 纯函数产出），默认 udp，用户显式写
	// tcp 层覆盖（补全时替代）；配置经 spec.LDP flat 键携带、FlowMeta 直传
	// 生成器；目的端口默认 646。
	r.Register(LayerSchema{Name: "ldp", Category: CategoryTerminal,
		DependsOn:   []string{"udp"},
		TransportOn: []string{"udp", "tcp"},
	})
	// ---- B3：pcep（tcp 终结层。RFC 5440——Open/Keepalive/PCReq/PCRep/
	// PCNtf/PCErr 逐报文事件，wire 字节由 build* 纯函数产出），TCP 语义
	// （握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器；配置经 spec.PCEP
	// flat 键携带、FlowMeta 直传生成器；目的端口默认 4189。
	r.Register(LayerSchema{Name: "pcep", Category: CategoryTerminal, DependsOn: []string{"tcp"}})
	// ---- B3：cflow（udp 终结层。RFC 3954 NetFlow v9 与 RFC 7011 IPFIX——
	// Export Packet/Message 含 header、Template/Data/Options Set、IPv4/IPv6
	// flow record 与 enterprise IE，wire 字节由 build* 纯函数产出），UDP
	// 语义（数据报/checksum）交给 udp 层生成器；配置经 spec.CFlow flat 键
	// 携带、FlowMeta 直传生成器；目的端口默认 2055（v9）/4739（IPFIX）。
	r.Register(LayerSchema{Name: "cflow", Category: CategoryTerminal, DependsOn: []string{"udp"}})
	// ---- P4a：fins（UDP/TCP 终结层，FINS 命令帧由协议生成器构造）。
	r.Register(LayerSchema{Name: "fins", Category: CategoryTerminal,
		DependsOn:   []string{"udp"},
		TransportOn: []string{"udp", "tcp"},
	})
	r.Register(LayerSchema{Name: "nfs", Category: CategoryTerminal,
		DependsOn:   []string{"tcp"},        // 默认 tcp；用户显式写 udp 层覆盖（补全时替代）
		TransportOn: []string{"tcp", "udp"}, // 支持的传输层，第一个 = 默认（须与 DependsOn[0] 一致）
		Fields: map[string]FieldSchema{
			"version":                {Type: "int", Default: 0, Min: 0, Max: 0},
			"transport":              {Type: "string", Default: ""},
			"auth_flavor":            {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"auth_sys":               {Type: "object"},
			"xid_base":               {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"xid_incr":               {Type: "int", Default: 0, Min: 0, Max: 0},
			"ops":                    {Type: "list", Default: []interface{}{}},
			"sessions":               {Type: "int", Default: 0, Min: 0, Max: 0},
			"sessions_src_port_base": {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"sessions_src_port_step": {Type: "int", Default: 0, Min: 0, Max: 0},
			"result_status":          {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"direction":              {Type: "string", Default: ""},
			"mount_filehandle":       {Type: "list", Default: []interface{}{}},
			"minorversion":           {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
		}})
	// ---- P4a：smb（tcp 终结层。MS-SMB2——会话状态机展开为逐 PDU 事件
	// （NEGOTIATE → SESSION_SETUP → TREE_CONNECT → CREATE → Operations →
	// CLOSE → TREE_DISCONNECT → LOGOFF，Include*/ErrorOnCommand/
	// EncryptionRequired 门控与 legacy Plan 逐命令一致，wire 字节由
	// buildSMB2Header + build*Body 纯函数产出），TCP 语义（握手/seq-ack/
	// 挥手/MSS 分段）交给 tcp 层生成器；配置（transport/dialects/operations/
	// error_on_command...）繁多不落层 config（layers 数组条目零负载），经
	// spec.SMB flat 键携带、FlowMeta 直传生成器；目的端口默认 445
	// （transport=netbios → 139，validateSpecBase，strategy_convert 同款）。
	r.Register(LayerSchema{Name: "smb", Category: CategoryTerminal,
		DependsOn: []string{"tcp"},
		Fields: map[string]FieldSchema{
			"transport":                         {Type: "string", Default: ""},
			"dialects":                          {Type: "list", Default: []interface{}{}},
			"selected_dialect":                  {Type: "string", Default: ""},
			"client_capabilities":               {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"server_capabilities":               {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"security_mode":                     {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"signing_required":                  {Type: "bool", Default: false},
			"auth_mechanism":                    {Type: "string", Default: ""},
			"username":                          {Type: "string", Default: ""},
			"domain":                            {Type: "string", Default: ""},
			"password":                          {Type: "string", Default: ""},
			"security_blob":                     {Type: "list", Default: []interface{}{}},
			"auth_rounds":                       {Type: "int", Default: 0, Min: 0, Max: 0},
			"tree_connect_share":                {Type: "string", Default: ""},
			"share_type":                        {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"file_path":                         {Type: "string", Default: ""},
			"create_disposition":                {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"access_mask":                       {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"file_attributes":                   {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"share_access":                      {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"create_options":                    {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"operations":                        {Type: "list", Default: []interface{}{}},
			"preauth_integrity_hash_algorithms": {Type: "list", Default: []interface{}{}},
			"encryption_algorithm":              {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"encryption_required":               {Type: "bool", Default: false},
			"max_transact_size":                 {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"max_read_size":                     {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"max_write_size":                    {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"include_negotiate":                 {Type: "bool", Default: true},
			"include_auth":                      {Type: "bool", Default: true},
			"include_tree_connect":              {Type: "bool", Default: true},
			"include_teardown":                  {Type: "bool", Default: true},
			"error_response_status":             {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"error_on_command":                  {Type: "string", Default: ""},
		}})
	// ---- P4a：tds（tcp 终结层。MS-TDS——PRELOGIN → Login7 → Login response
	// → sessions（SQL Batch / RPC / TransMgr / Attention）逐报文事件，wire
	// 字节由 build* 纯函数产出；Login response 等 down 报文按 cfg.PacketSize
	// 应用层分片（BuildTableResponsePackets，T-148）保留），TCP 语义
	// （握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器；配置（version/
	// packet_size/sessions/mars/login...）繁多不落层 config（layers 数组条目
	// 零负载），经 spec.Payload（TDSConfig JSON，strategy_convert.go tds case
	// 同款）携带、FlowMeta.Payload 直传生成器；目的端口默认 1433
	// （validateSpecBase）。
	r.Register(LayerSchema{Name: "tds", Category: CategoryTerminal,
		DependsOn: []string{"tcp"},
		Fields: map[string]FieldSchema{
			"version":       {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"packet_size":   {Type: "int", Default: 0, Min: 0, Max: 0},
			"encrypt_mode":  {Type: "int", Default: 0, Min: 0, Max: 0},
			"mars":          {Type: "bool", Default: false},
			"app_name":      {Type: "string", Default: ""},
			"server_name":   {Type: "string", Default: ""},
			"client_name":   {Type: "string", Default: ""},
			"user_name":     {Type: "string", Default: ""},
			"password":      {Type: "string", Default: ""},
			"database":      {Type: "string", Default: ""},
			"language":      {Type: "string", Default: ""},
			"interface_lib": {Type: "string", Default: ""},
			"client_lcid":   {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"feature_exts":  {Type: "list", Default: []interface{}{}},
			"login":         {Type: "object"},
			"sessions":      {Type: "list", Default: []interface{}{}},
		}})
	r.Register(LayerSchema{Name: "ftp", Category: CategoryTerminal,
		DependsOn:  []string{"tcp"},
		OptionalOn: []string{"tls"},
		Fields: map[string]FieldSchema{
			"username": {Type: "string", Default: "anonymous"},
			"password": {Type: "string", Default: "anonymous"},
		},
	})
	r.Register(LayerSchema{Name: "smtp", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		OptionalOn:    []string{"tls"},
		FieldContract: map[string]string{"tcp.dst_port": "25"}, // RFC 5321 §3.1；用户显式非标准端口优先（提交 587 / SMTPS 465），不强制
		Fields: map[string]FieldSchema{
			"from": {Type: "string", Default: "sender@example.com"},
			"to":   {Type: "string", Default: "recipient@example.com"},
		},
	})
	r.Register(LayerSchema{Name: "redis", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "6379"}, // RFC 默认 6379；用户显式非标准端口优先，不强制
	})
	r.Register(LayerSchema{Name: "pop3", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		OptionalOn:    []string{"tls"},
		FieldContract: map[string]string{"tcp.dst_port": "110"}, // RFC 1939 默认 110；用户显式非标准端口优先（POP3S 995），不强制
	})
	r.Register(LayerSchema{Name: "imap", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		OptionalOn:    []string{"tls"},
		FieldContract: map[string]string{"tcp.dst_port": "143"}, // RFC 3501 默认 143；用户显式非标准端口优先（IMAPS 993），不强制
	})
	r.Register(LayerSchema{Name: "mysql", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "3306"}, // MySQL 默认 3306；用户显式非标准端口优先，不强制
	})
	r.Register(LayerSchema{Name: "grpc", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "8604"}, // gRPC telemetry_8604 惯例；用户显式非标准端口优先，不强制（gRPC 本身不强制端口）
	})
	r.Register(LayerSchema{Name: "ssh", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "22"}, // SSH IANA 22；用户显式非标准端口优先，不强制
	})
	r.Register(LayerSchema{Name: "rdp", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "3389"}, // RDP 默认 3389（MS-RDPBCGR §1.3）；用户显式写 3389 不强制，写其它值由 rdp Validate 拒绝
	})

	// ---- 隧道层（tunnel）----
	r.Register(LayerSchema{Name: "tls", Category: CategoryTunnel,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "443"},
		// InnerRequired 为空 = 内层可以是任意终结层，不用补。
		Fields: map[string]FieldSchema{
			"version": {Type: "string", Default: "tls1.3"},
			"sni":     {Type: "string", Default: ""},
			"alpn":    {Type: "list", Default: []interface{}{}},
			"role":    {Type: "string", Default: "client"},
		},
	})
	r.Register(LayerSchema{Name: "gre", Category: CategoryTunnel,
		DependsOn:     []string{"ip"},                         // 外层 ip 自动补
		FieldContract: map[string]string{"ip.protocol": "47"}, // GRE IPPROTO=47
		InnerRequired: []string{"ip"},                         // 内层必须从 ip 开始，缺了自动补内层 ip
		Fields: map[string]FieldSchema{
			"key":      {Type: "uint32", Default: uint32(0)},
			"checksum": {Type: "bool", Default: false},
			"sequence": {Type: "bool", Default: false},
		},
	})

	// ---- 二层层：mpls / pppoe（占位，P2 补字段）----
	// 注意：不能照搬 gre 隧道表达——MPLS 线上格式是 Eth + 标签栈 + 内层 IP
	// （无外层 IP 头，RFC 3031/3032），DependsOn:["ip"] 会补出错误的外层
	// IP 头；core builder 从 L2Config.MPLS 原生写标签栈，链式表达需要新的
	// shim 层机制，属 P2 工作项。未写生成器 → 链式配置干净拒绝
	// （generator not implemented），legacy planner 路径不受影响。
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

// dialectFieldContract overrides a layer's schema FieldContract value when its
// `dialect` field selects a content/port variant (design §1.3
// "变体改父层契约值 · 已定案 (a)"). The variant is NOT its own layer; it
// changes the CONTRACT VALUE of the parent layer without breaking "值=常量".
// For postgresql: dialect=kingbase → tcp.dst_port 54321 (vs 5432).
var dialectFieldContract = map[string]map[string]map[string]string{
	"postgresql": {
		"kingbase": {"tcp.dst_port": "54321"},
	},
}

// EffectiveFieldContract resolves a layer's FieldContract with dialect
// overrides applied. It returns the schema's FieldContract unchanged when the
// layer has no dialect-selected variant. The returned map is a fresh copy so
// callers may read it freely. nil when the schema declares no FieldContract.
func (r *Registry) EffectiveFieldContract(l Layer) map[string]string {
	s, ok := r.Get(l.Name)
	if !ok || s.FieldContract == nil {
		return nil
	}
	// Import cycle-free: layer config "dialect" may be a raw string or the
	// schema default (native string). presence-checked.
	out := make(map[string]string, len(s.FieldContract))
	for k, v := range s.FieldContract {
		out[k] = v
	}
	overrides, ok := dialectFieldContract[l.Name]
	if !ok {
		return out
	}
	dialect, _ := l.Config["dialect"].(string)
	if dialect == "" {
		return out
	}
	if ov, ok := overrides[dialect]; ok {
		for k, v := range ov {
			out[k] = v
		}
	}
	return out
}
