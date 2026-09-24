package layers

import (
	"fmt"
	"sync"
)

// defaultRegistryOnce builds the built-in registry exactly once. T23 profiled
// DefaultRegistry as 32% of chain-path allocation — it was rebuilt (100+
// Register calls) on every Plan. The registry is read-only after construction
// (Get/Has/List only); callers needing a custom registry build their own via
// NewRegistry.
var (
	defaultRegistryOnce sync.Once
	defaultRegistry     *Registry
)

// DefaultRegistry returns the built-in layer registry (层注册表，§4.4)。
// 字段默认值与现有实现对齐（strategy_convert.go / types.go）。
// 完整字段表见实现计划；此处先注册公共层与常用协议层。
func DefaultRegistry() *Registry {
	defaultRegistryOnce.Do(buildDefaultRegistry)
	return defaultRegistry
}

func buildDefaultRegistry() {
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
			// D-SRV6-1：IPv6 hop-by-hop 扩展头选项列表（RFC 8200 §4.3，
			// [{type,value}]）。经 ValidateSpec 回填 spec.HopByHop，由
			// finalEmit/raw-IP 驱动写入 L3（builder 装配 NH=0 链）。
			"hop_by_hop": {Type: "object"},
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
			// concurrent: 事件模式按 SrcPort 维护并发连接状态（mms 多会话）。
			"concurrent": {Type: "bool", Default: false},
			// retransmit: 开启 TCP 重传模拟（T3.3）。数据段/ACK 发射同步
			// 驱动 TCPRetransmissionStateMachine（SendSegment/OnACK），数据
			// 阶段结束后对未确认段（FlightSize>0）补发重传段（dup PSH-ACK），
			// 模拟丢包恢复。false = 关闭（默认，字节流与 legacy 一致）。
			"retransmit": {Type: "bool", Default: false},
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
			// D-HTTP-1 重走步骤 1：顶层 http 迁入层（5→21 键）。headers 旧键
			// 保留（读时回退 request_headers）；新增键类型与缺省见 §7 步骤 1 表。
			"request_headers":            {Type: "map", Default: map[string]interface{}{}},
			"body_b64":                   {Type: "string", Default: ""},
			"keep_alive":                 {Type: "bool", Default: false},
			"transactions":               {Type: "int", Default: 0},
			"response_headers":           {Type: "map", Default: map[string]interface{}{}},
			"response_body":              {Type: "string", Default: ""},
			"response_body_b64":          {Type: "string", Default: ""},
			"response_status_code":       {Type: "int", Default: 0},
			"response_status_text":       {Type: "string", Default: ""},
			"response_content_encoding":  {Type: "string", Default: ""},
			"request_content_encoding":   {Type: "string", Default: ""},
			"request_transfer_encoding":  {Type: "string", Default: ""},
			"response_transfer_encoding": {Type: "string", Default: ""},
			"chunk_size":                 {Type: "int", Default: 0},
			"pipelined":                  {Type: "bool", Default: false},
			"file_source":                {Type: "object"},
		},
		// http 家族目的端口落在 tcp 层（DefaultDstPort=80，strategy_convert
		// 同款）；声明 tcp.dst_port 供 layers 数组路径（未显式写端口）补齐。
		FieldContract: map[string]string{"tcp.dst_port": "80"},
	})
	r.Register(LayerSchema{Name: "dns", Category: CategoryTerminal,
		DependsOn:   []string{"udp"},        // 默认 udp；用户显式写 tcp 层覆盖（补全时替代）
		TransportOn: []string{"udp", "tcp"}, // 支持的传输层，第一个 = 默认（须与 DependsOn[0] 一致）
		OptionalOn:  []string{"tls"},
		// D-DNS-1：层 14 键（顶层 dns 子映射迁入；字段名对齐 DNSConfig
		// json tag——flat `rcode`→`response_code` 防传输层 RCODE 混淆）。
		// 缺席键走默认：name=example.com / query_type=1 / udp_payload_size
		// 4096 经生成器回退；txid=0=0x1234 回退 / ttl=0=300 回退沿 legacy。
		Fields: map[string]FieldSchema{
			"name":             {Type: "string", Default: "example.com"},
			"query_type":       {Type: "uint16", Default: uint16(1), Min: 0, Max: 65535},
			"txid":             {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"is_response":      {Type: "bool", Default: false},
			"response_ip":      {Type: "string", Default: ""},
			"edns0_enabled":    {Type: "bool", Default: false},
			"udp_payload_size": {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535}, // 0=4096 回退沿 legacy
			"dnssec_ok":        {Type: "bool", Default: false},
			"transport":        {Type: "string", Default: ""},
			"response_code":    {Type: "uint8", Default: uint8(0), Min: 0, Max: 15},
			"ttl":              {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"questions":        {Type: "object"},
			"answers":          {Type: "object"},
			"authority":        {Type: "object"},
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
	// streamable 的 DELETE/204 是应用层帧（带内，非挥手）。目的端口默认
	// stdio→22 / HTTP→8081（validateSpecBase；HTTP 形缺省修正由 translate
	// 分支在翻译后补，用户显式 tcp.dst_port 优先）。
	//
	// D-MCP-1：层 config 收 MCPConfig 同名 21 键（M1-E1 删 think_time 死
	// 字段后）。一律不设 Default：零值即设计缺省（transport 空走 stdio、
	// protocol_version 空 2024-11-05、Shutdown nil=true、caps 空 {}，
	// 16-mcp-design §4.3），且 completedConfig 缺省注入会把 RawMessage 字段
	// 污染成非 nil——破坏"caps 缺省=省略字段"的线形。嵌套对象/数组/RawMessage
	// V9 只验顶层键存在，值语义归翻译分支 JSON 往返解码 + validator
	// （pop3/smtp/imap 同款）。tls 底座组合 [ip,tcp,tls,mcp] 未验（M2 另立，
	// 不登 OptionalOn，不挡开工）。
	r.Register(LayerSchema{Name: "mcp", Category: CategoryTerminal,
		DependsOn: []string{"tcp"},
		Fields: map[string]FieldSchema{
			"transport":           {Type: "string"},
			"base_url":            {Type: "string"},
			"session_id":          {Type: "string"},
			"protocol_version":    {Type: "string"},
			"client_info":         {Type: "object"},
			"server_info":         {Type: "object"},
			"client_capabilities": {Type: "object"},
			"server_capabilities": {Type: "object"},
			"requests":            {Type: "list"},
			"responses":           {Type: "list"},
			"notifications":       {Type: "list"},
			"auth":                {Type: "object"},
			"state":               {Type: "object"},
			"parts":               {Type: "list"},
			"metadata":            {Type: "object"},
			"push_notification":   {Type: "object"},
			"id_counter":          {Type: "int"}, // 负值由 mcp validator Rule 8/9 拒（锚词 id_counter/rounds must be >= 0）
			"rounds":              {Type: "int"},
			"shutdown":            {Type: "bool"}, // nil=true 语义：不设 Default，缺省不进 config map
			"context_id":          {Type: "string"},
			"parent_id":           {Type: "string"},
		},
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
		DependsOn:  []string{"tcp"},
		OptionalOn: []string{"tls"}, // MQTTS：显式写 tls 层启用，默认不启用（J 组组合层）
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
			"disconnect_reason":           {Type: "int"}, // nil = 不发（缺省不进 config map；Default 0 会被解码成非 nil *int，误触 5.0-only 校验）
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
	// ---- openvpn（udp 终结层。OpenVPN——UDP 承载的加密隧道协议，P_CONTROL/
	// P_DATA 数据报序列，wire 字节由 build* 纯函数产出）。UDP 语义交给 udp 层
	// 生成器；配置经 spec.OpenVPN flat 键携带、FlowMeta 直传生成器（tftp 重放
	// 模式）。default proto=udp（端口 1194）；proto=tcp 链上不支持（OpenVPN-
	// over-TCP 用 2 字节长度前缀 + TLS 包裹，udp 层无等价物）——validator 显式
	// 拒绝 TCP 模式。
	r.Register(LayerSchema{Name: "openvpn", Category: CategoryTerminal,
		DependsOn:     []string{"udp"},
		FieldContract: map[string]string{"udp.dst_port": "1194"}, // OpenVPN 默认 1194；用户显式非标准端口优先，不强制
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
	// gbt（BIP 22/23 getblocktemplate/submitblock JSON-RPC over HTTP）：终结层
	// 事件已含完整 HTTP 帧（请求/响应钉死头序），http 层以透传变换器转发
	// （identity transformer）。全部协议配置经 spec.GBT（顶层 "gbt" 子映射）
	// 注入，层 config 恒空；8332 端口经 FieldContract 供通用应用补齐。
	r.Register(LayerSchema{Name: "gbt", Category: CategoryTerminal,
		DependsOn:     []string{"http"},
		FieldContract: map[string]string{"tcp.dst_port": "8332"},
	})
	// cwmp（TR-069 CPE WAN Management Protocol，64-cwmp v2.2.2）：终结层
	// 事件已含完整 HTTP 帧（SOAP 1.1 envelope、HTTP 头序、digest 认证），
	// http 层以透传变换器转发（identity transformer）。D-CWMP-1：配置迁入
	// cwmp 层（B6 顶层 "cwmp" 子映射注入形已判死）；六键=CWMPConfig 顶层
	// 同名（sessions/flows 列表、auth 对象——V9 只验顶层键存在，嵌套值语义
	// 归 translate JSON 往返 + validator，smtp/ftp 同款）；7547 端口经
	// FieldContract 供通用应用补齐。
	r.Register(LayerSchema{Name: "cwmp", Category: CategoryTerminal,
		DependsOn:     []string{"http"},
		FieldContract: map[string]string{"tcp.dst_port": "7547"},
		Fields: map[string]FieldSchema{
			"profile":    {Type: "string", Default: ""},
			"namespace":  {Type: "string", Default: ""},
			"concurrent": {Type: "bool", Default: false},
			"sessions":   {Type: "list", Default: []interface{}{}},
			"flows":      {Type: "list", Default: []interface{}{}},
			"auth":       {Type: "object"},
		},
	})
	// stratum（比特币 Stratum v1）：终结层事件为行式 JSON（LF 边界、紧凑
	// 形态），[tcp→stratum] 直连（ip 层由依赖补全自动插入）。协议配置经
	// spec.Stratum（顶层 "stratum" 子映射）注入，层 config 恒空；3333 端口
	// 经 FieldContract 供通用应用补齐。无 stratum dissector，断言全走
	// tcp.payload/frames（设计 §2 实测基线）。
	r.Register(LayerSchema{Name: "stratum", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "3333"},
	})
	// ethmining（以太坊挖矿 stratum 协议，EthereumStratum/1.0.0）：终结层
	// 事件为行式 JSON（LF 边界、紧凑形态），[tcp→ethmining] 直连（ip 层由依
	// 赖补全自动插入）。协议配置经 spec.ETHMining（顶层 "ethmining" 子映射）
	// 注入，层 config 恒空；4444 端口经 FieldContract 供通用应用补齐（非默认
	// 端口 3353 由用户显式覆盖，正例 22）。无 ethmining dissector，断言全
	// 走 tcp.payload/frames（设计 §2 实测基线）。
	r.Register(LayerSchema{Name: "ethmining", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "4444"},
	})
	// nmea（海用电子设备数据交换标准，NMEA 0183 v4.10 sentence 明文协议）：
	// 终结层事件为完整句子字节（$ 地址 + 逗号字段 + *XX XOR + CRLF），
	// [tcp→nmea]/[udp→nmea] 双载体（默认 tcp；用户显式写 udp 层时补全替代，
	// 会话级 transport:"udp" 多载体 fixture 同理）。协议配置经 spec.NMEA
	// （顶层 "nmea" 子映射）注入，层 config 恒空；10110 端口经 FieldContract
	// 供通用应用补齐（非默认端口 4001 由用户显式覆盖，正例 42）。无 nmea
	// dissector，断言全走 tcp.payload/udp.payload/frames（设计 §1④ 实测基线）。
	r.Register(LayerSchema{Name: "nmea", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		TransportOn:   []string{"tcp", "udp"},
		FieldContract: map[string]string{"tcp.dst_port": "10110", "udp.dst_port": "10110"},
	})
	// getwork（Bitcoin legacy getwork JSON-RPC over HTTP）：终结层事件已含
	// 完整 HTTP 帧（请求/响应钉死头序），http 层以透传变换器转发（identity
	// transformer）。全部协议配置经 spec.GetWork（顶层 "getwork" 子映射）注入，
	// 层 config 恒空；8332 端口经 FieldContract 供通用应用补齐。
	r.Register(LayerSchema{Name: "getwork", Category: CategoryTerminal,
		DependsOn:     []string{"http"},
		FieldContract: map[string]string{"tcp.dst_port": "8332"},
	})
	// doh（DNS over HTTPS / RFC 8484，66-doh v2.2.1）：终结层事件已含完整
	// HTTP 帧（POST body / GET base64url 查询参数两种映射 + 2xx/非 2xx 响应
	// 钉死头序），http 层以透传变换器转发（identity transformer）。全部协议
	// 配置经 spec.DOH（顶层 "doh" 子映射）注入，层 config 恒空；主 profile
	// doh_http1_plain 明文端口 80 经 FieldContract 供通用应用补齐（非默认
	// 端口 8080 由用户显式覆盖）。响应帧 Content-Type: application/dns-message
	// 时 tshark 自动内层解码 dns.*（testcase §1 实测基线）。
	r.Register(LayerSchema{Name: "doh", Category: CategoryTerminal,
		DependsOn:     []string{"http"},
		FieldContract: map[string]string{"tcp.dst_port": "80"},
	})
	// onvif（ONVIF Core Spec Ver. 26.06，67-onvif v2.1.1）：终结层事件已含
	// 完整 HTTP 帧（SOAP 1.2 POST + 2xx/4xx/5xx 响应），http 层以透传变换
	// 器转发。全部协议配置经 spec.ONVIF（顶层 "onvif" 子映射）注入，层 config
	// 恒空；目的端口 80 由 FieldContract 补齐（非默认端口由用户显式覆盖）。
	r.Register(LayerSchema{Name: "onvif", Category: CategoryTerminal,
		DependsOn:     []string{"http"},
		FieldContract: map[string]string{"tcp.dst_port": "80"},
	})
	r.Register(LayerSchema{Name: "opcua", Category: CategoryTerminal, DependsOn: []string{"tcp"}, Fields: map[string]FieldSchema{
		"security_mode":    {Type: "string", Default: "none"},
		"read":             {Type: "list", Default: []interface{}{}},
		"write":            {Type: "list", Default: []interface{}{}},
		"browse":           {Type: "list", Default: []interface{}{}},
		"subscription":     {Type: "object"},
		"sessions":         {Type: "int", Default: 0, Min: 0, Max: 0},
		"error_inject":     {Type: "object"},
		"close":            {Type: "bool", Default: true},
		"skip_channel":     {Type: "bool", Default: false},
		"bad_message_size": {Type: "bool", Default: false},
		"bad_length":       {Type: "bool", Default: false},
	}})
	r.Register(LayerSchema{Name: "mms", Category: CategoryTerminal, DependsOn: []string{"tcp"}, Fields: map[string]FieldSchema{
		"iedName":                 {Type: "string"},
		"objects":                 {Type: "list", Default: []interface{}{}},
		"enableRead":              {Type: "bool", Default: false},
		"enableWrite":             {Type: "bool", Default: false},
		"enableInformationReport": {Type: "bool", Default: false},
		"enableGetNameList":       {Type: "bool", Default: false},
		"enableIdentify":          {Type: "bool", Default: false},
		"multiSession":            {Type: "list", Default: []interface{}{}},
		"association":             {Type: "object"},
		"sequence":                {Type: "object"},
		"errorClassName":          {Type: "string"},
		"errorValue":              {Type: "int", Default: 0, Min: 0, Max: 255},
	}})
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
	r.Register(LayerSchema{Name: "megaco", Category: CategoryTerminal,
		DependsOn:   []string{"udp"},        // 默认 udp（RFC 3525 Annex D.1）；用户显式写 tcp 层覆盖（Annex D.2 TPKT 成帧）
		TransportOn: []string{"udp", "tcp"}, // 双载体：udp 一数据报一消息 / tcp TPKT 定界+MSS 分段重组
		// D-MEGACO-1：megaco（RFC 3525 / ITU-T H.248.1 文本编码）终结层七键
		// + 双 carrier 端口契约（megaco-v1-text 2944；mgcp 别名 2427 由用户
		// 显式写，carrier 块域校验放行，见 chain_planner.go）。
		FieldContract: map[string]string{"udp.dst_port": "2944", "tcp.dst_port": "2944"},
		Fields: map[string]FieldSchema{
			"profile":  {Type: "string", Default: ""}, // megaco_v1_text（默认）| mgcp_alias
			"encoding": {Type: "string", Default: ""}, // text（默认）| ber（仅声明，本期不产 BER 载荷→validator 拒）
			// 起始行 Version 1*2DIGIT；缺席=缺省 1（Default 0 = V9"未写"）。
			// 显式 0 的实际语义 = 采用缺省版本（V9 skip-0 使 schema 面不报
			// 范围错——复评 U3 证伪旧注释"[1,99] 覆盖显式 0"；planner 面
			// 0 渲染为 1，线上与缺席完全同值）——契约 §6 "0 拒绝"以书面
			// 豁免登记（D-MEGACO-1 F6 表），Min 1/Max 99 只执法显式 1..99
			// 之外的非零值（如 100）。
			"version":    {Type: "int", Default: 0, Min: 1, Max: 99},
			"token_form": {Type: "string", Default: ""}, // long（默认）| abbrev
			"whitespace": {Type: "string", Default: ""}, // "" 单空格 SEP | cr | comment | lwsp
			"sessions":   {Type: "list", Default: []interface{}{}},
			"wire_fault": {Type: "string", Default: ""}, // 闭环 31 值枚举（D-MEGACO-1 §7 表）；""=无故障
		},
	})
	r.Register(LayerSchema{Name: "hl7", Category: CategoryTerminal,
		DependsOn:   []string{"tcp"}, // TCP-only 载体（D-HL7-1 裁定2，MLLP over 字节流）
		TransportOn: []string{"tcp"}, // 单载体：udp/缺 tcp 链块即拒
		// D-HL7-1：hl7（HL7 v2.x MLLP）终结层八键 + 端口契约（IANA hl7
		// 2575；显式非默认端口合法，裁定3）。
		FieldContract: map[string]string{"tcp.dst_port": "2575"},
		Fields: map[string]FieldSchema{
			"profile":         {Type: "string", Default: ""},  // mllp（唯一；缺省）
			"version":         {Type: "string", Default: ""},  // 2.3/2.4/2.5（缺省）/2.8
			"field_separator": {Type: "string", Default: ""},  // 1 字符（缺省 "|"）
			"encoding_chars":  {Type: "string", Default: ""},  // 恰 4 字符（缺省 "^~\&"）
			"ack_mode":        {Type: "string", Default: ""},  // auto（缺省）/null/AA/AE/AR
			"concurrent":      {Type: "bool", Default: false}, // 双会话交错回放
			"sessions":        {Type: "list", Default: []interface{}{}},
			"wire_fault":      {Type: "string", Default: ""}, // 闭环 33 值枚举（D-HL7-1 §7 表）；""=无故障
		},
	})
	// mmse（WAP-209 MMSEncapsulation，71-mmse v2.1.0）：终结层事件是完整
	// HTTP 帧（透明变换器，D-MMSE-1 裁定2——http 族第 5 协议）。DependsOn
	// http（自身依赖 tcp）使补全恒供给 http+tcp——缺 http 结构不可达（
	// carrier_no_http 书面豁免；validate_layers 预检为纵深位）。五键=
	// MMSEConfig 顶层同名（V9 只验顶层键存在，嵌套值语义归 translate 严格
	// 解码 + validator）；80 端口经 FieldContract 供通用应用补齐。
	r.Register(LayerSchema{Name: "mmse", Category: CategoryTerminal,
		DependsOn:     []string{"http"},
		FieldContract: map[string]string{"tcp.dst_port": "80"},
		Fields: map[string]FieldSchema{
			"profile":     {Type: "string", Default: ""},  // mmse_http_v1（缺省）/mmse_http_v6
			"mms_version": {Type: "string", Default: ""},  // 1.0/1.1/1.2（缺省）/1.3（线码 N-1）
			"concurrent":  {Type: "bool", Default: false}, // 双会话交错回放（C-1）
			"sessions":    {Type: "list", Default: []interface{}{}},
			"wire_fault":  {Type: "string", Default: ""}, // 闭环 55 值枚举（契约 §7 表）；""=无故障
		},
	})
	r.Register(LayerSchema{Name: "edp", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "4472"},
		Fields: map[string]FieldSchema{
			"profile":    {Type: "string", Default: ""},  // edp_tcp_plain_v1（缺省）/ edp_ipv6_v1
			"concurrent": {Type: "bool", Default: false}, // 双会话交错回放（v2.1 C-2 翻案）
			"sessions":   {Type: "list", Default: []interface{}{}},
			"wire_fault": {Type: "string", Default: ""}, // 28 值枚举（D-EDP-1 §7 表）；""=无故障
		},
	})
	r.Register(LayerSchema{Name: "xmrmining", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "18081"},
		Fields: map[string]FieldSchema{
			"profile":    {Type: "string", Default: ""},  // xmrmining_stratum_v1（缺省）/ xmrmining_job_legacy_v1 / xmrmining_ipv6_v1
			"concurrent": {Type: "bool", Default: false}, // 双矿机交错回放（v2.0.1 C-07 翻案）
			"sessions":   {Type: "list", Default: []interface{}{}},
			"wire_fault": {Type: "string", Default: ""}, // 39 值枚举（D-XMR-1 §7 表）；""=无故障
		},
	})
	r.Register(LayerSchema{Name: "bacnet", Category: CategoryTerminal,
		DependsOn:     []string{"udp"},
		TransportOn:   []string{"udp"},                            // BACnet/IP 仅 UDP 载体（Annex J）——transport-dup 检查据此报 carrier 锚词
		FieldContract: map[string]string{"udp.dst_port": "47808"}, // BACnet/IP Annex J 标准端口（tshark 自动解码依赖）
		Fields: map[string]FieldSchema{
			"profile":    {Type: "string", Default: ""},  // bacnet_ip_v1 主档（informational）
			"concurrent": {Type: "bool", Default: false}, // 多客户端交错回放（v2.1 C-1）
			"sessions":   {Type: "list", Default: []interface{}{}},
			"wire_fault": {Type: "string", Default: ""}, // 42 值枚举（D-BACNET-1 §7 表）；""=无故障
		},
	})
	r.Register(LayerSchema{Name: "dcerpc", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		TransportOn:   []string{"tcp"},                          // DCE/RPC v5 over TCP——CL/udp 不产生（transport-dup 检查据此报 carrier 锚词）
		FieldContract: map[string]string{"tcp.dst_port": "135"}, // EPM 标准端口（tshark 自动解码依赖）
		Fields: map[string]FieldSchema{
			"concurrent": {Type: "bool", Default: false}, // 多会话交错回放
			"sessions":   {Type: "list", Default: []interface{}{}},
			"wire_fault": {Type: "string", Default: ""}, // 32 值枚举（D-DCERPC-1 §7 表）；""=无故障
		},
	})
	r.Register(LayerSchema{Name: "dtls", Category: CategoryTerminal,
		DependsOn:     []string{"udp"},
		TransportOn:   []string{"udp"},                           // DTLS 仅 UDP 载体（RFC 6347 datagram 语义）——transport-dup 检查据此报 carrier 锚词
		FieldContract: map[string]string{"udp.dst_port": "4433"}, // DTLS 惯用端口（tshark 自动解码依赖）
		Fields: map[string]FieldSchema{
			"sessions":   {Type: "list", Default: []interface{}{}},
			"wire_fault": {Type: "string", Default: ""}, // 6 值枚举（D-DTLS-1 §10 表）；""=无故障
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
	// D-GOOSE-1：层 config 收 GOOSEConfig 同名 18 用户键，一律不设 Default
	// （fins 16 键同款——dns 14 键带 Default 是例外非先例：dns 走"缺席=
	// 全默认合法"语义，goose 走"缺席=validator 拒绝"语义；无 static——
	// GOOSEConfig 无此字段、无生成器消费，为 P1 矩阵幽灵键已删除）。
	// 无界字段（string/bool/object：gocb_ref/dat_set/data 等）走 V9
	// Min==0&&Max==0 跳过口径，非法值由 protocolValidator 拒收。
	// L2-only 业务键全关动态（allowlist 不加 goose 行；eth 行既有不动）。
	r.Register(LayerSchema{Name: "goose", Category: CategoryTerminal, DependsOn: []string{"eth"},
		Fields: map[string]FieldSchema{
			"appid":         {Type: "uint16", Min: 0, Max: 0x3fff},
			"gocb_ref":      {Type: "string"},
			"dat_set":       {Type: "string"},
			"go_id":         {Type: "string"},
			"tal_ms":        {Type: "uint32", Min: 0, Max: 4294967295},
			"conf_rev":      {Type: "uint32", Min: 0, Max: 4294967295},
			"start_stnum":   {Type: "uint32", Min: 0, Max: 4294967295},
			"start_sqnum":   {Type: "uint32", Min: 0, Max: 4294967295},
			"test":          {Type: "bool"},
			"nds_com":       {Type: "bool"},
			"boolean":       {Type: "bool"},
			"data":          {Type: "list"},
			"event_seq":     {Type: "list"},
			"count":         {Type: "int", Min: 0, Max: 1000000},
			"dst_mac":       {Type: "mac"},
			"vlan_enabled":  {Type: "bool"},
			"vlan_id":       {Type: "uint16", Min: 0, Max: 4095},
			"vlan_priority": {Type: "uint8", Min: 0, Max: 7},
		},
	})
	// D-SV-1：sv 层 15 业务键（L2-only 终结层，[eth,sv] 链）。一律无
	// Default（决策 F：validator 必填项 svID/confRev 与 Default 语义冲突，
	// goose 同款）；appid 注册完整语义域 [0x4000,0x7fff]（决策 A1，goose
	// appid [0,0x3fff] 同款——V9 create-time 先火，锚词对真实执法门）；
	// period_us 无界（V9 Min==0&&Max==0 跳过口径，pacing 死键 C 类不改）。
	r.Register(LayerSchema{Name: "sv", Category: CategoryTerminal, DependsOn: []string{"eth"},
		Fields: map[string]FieldSchema{
			"sv_id":             {Type: "string"},
			"dat_set":           {Type: "string"},
			"appid":             {Type: "uint16", Min: 0x4000, Max: 0x7fff},
			"conf_rev":          {Type: "uint32", Min: 0, Max: 4294967295},
			"samples_per_cycle": {Type: "uint16", Min: 0, Max: 65535},
			"smp_synch":         {Type: "uint8", Min: 0, Max: 255},
			"smp_rate":          {Type: "uint16", Min: 0, Max: 65535},
			"period_us":         {Type: "int"},
			"data":              {Type: "list"},
			"count":             {Type: "int", Min: 0, Max: 1000000},
			"dst_mac":           {Type: "mac"},
			"double_send":       {Type: "bool"},
			"vlan_enabled":      {Type: "bool"},
			"vlan_id":           {Type: "uint16", Min: 0, Max: 4095},
			"vlan_priority":     {Type: "uint8", Min: 0, Max: 7},
		},
	})
	// ---- P3 T5：路由协议终结层。igmp/ospf/pim 是 raw-IP [ip→<proto>] 链（无
	// tcp/udp 传输层，IP 协议号 2/89/103 由 transportProtocol 按终结层名解析）；
	// isis 是 L2-only [eth→isis] 链（LLC 载体）。配置经 FlowMeta.IGMP/OSPF/PIM/
	// ISIS 直传终结层生成器（字段表仅供链校验/展示，全量语义在生成器内）。
	r.Register(LayerSchema{Name: "igmp", Category: CategoryTerminal, DependsOn: []string{"ip"},
		FieldContract: map[string]string{"ip.protocol": "2"}, // RFC 1112/2236/3376 IGMP IPPROTO=2
	})
	r.Register(LayerSchema{Name: "ospf", Category: CategoryTerminal, DependsOn: []string{"ip"},
		FieldContract: map[string]string{"ip.protocol": "89"}, // RFC 2328 OSPF IPPROTO=89
	})
	r.Register(LayerSchema{Name: "pim", Category: CategoryTerminal, DependsOn: []string{"ip"},
		FieldContract: map[string]string{"ip.protocol": "103"}, // RFC 7761 PIM IPPROTO=103
	})
	r.Register(LayerSchema{Name: "isis", Category: CategoryTerminal, DependsOn: []string{"eth"}})
	// D-ARP-1：arp 层 5 业务键（L2-only 终结层，[eth,arp] 链，RFC 826）。
	// 无 Default（goose 决策 F 同款——缺省在生成器侧补：sender_ip=10.0.0.1/
	// target_ip=10.0.0.2/MAC←eth 层）。operation 注册语义域 [1,2]（V9
	// create-time 先火，锚词对真实执法门）；IP 承载混入由 V-carrier 通用门
	// 拒（complete.go DependsOn eth 自动获得）。
	r.Register(LayerSchema{Name: "arp", Category: CategoryTerminal, DependsOn: []string{"eth"},
		Fields: map[string]FieldSchema{
			"operation":  {Type: "uint16", Min: 1, Max: 2},
			"sender_mac": {Type: "mac"},
			"sender_ip":  {Type: "string"},
			"target_mac": {Type: "mac"},
			"target_ip":  {Type: "string"},
		},
	})
	// D-ICMPV6-1：icmpv6 raw-IP 终结层（[ip,icmpv6]，RFC 4443）。6 业务键
	// 无 Default（决策 F；缺省语义在 translate 镜像 parse：type 128/code
	// 0/seq 1/data "ping"）；FieldContract 声明 ip.protocol=58（igmp=2 同款
	// 框架块）；type 128/129 与 code 0 约束留 layer validator（V9 数值域
	// 只做类型界）。
	r.Register(LayerSchema{Name: "icmpv6", Category: CategoryTerminal, DependsOn: []string{"ip"},
		FieldContract: map[string]string{"ip.protocol": "58"},
		Fields: map[string]FieldSchema{
			"type":       {Type: "uint8", Min: 0, Max: 255},
			"code":       {Type: "uint8", Min: 0, Max: 255},
			"identifier": {Type: "uint16", Min: 0, Max: 65535},
			"sequence":   {Type: "uint16", Min: 0, Max: 65535},
			"data":       {Type: "string"},
			"pattern":    {Type: "list"},
		},
	})
	// D-ICMP-1：icmp 层 6 业务键（raw-IP 终结层，[ip,icmp] 链，RFC 792——
	// icmpv6 对称）。无 Default（缺省 translate 镜像 flat parse：type 8/
	// code 0/seq 1/data "ping"，决策 D1）；FieldContract ip.protocol=1
	//（IPPROTO_ICMP）。file_source 不映射（③ C 类）。
	r.Register(LayerSchema{Name: "icmp", Category: CategoryTerminal, DependsOn: []string{"ip"},
		FieldContract: map[string]string{"ip.protocol": "1"},
		Fields: map[string]FieldSchema{
			"type":       {Type: "uint8", Min: 0, Max: 255},
			"code":       {Type: "uint8", Min: 0, Max: 255},
			"identifier": {Type: "uint16", Min: 0, Max: 65535},
			"sequence":   {Type: "uint16", Min: 0, Max: 65535},
			"data":       {Type: "string"},
			"pattern":    {Type: "list"},
		},
	})
	// D-H323-1：h323 raw 自驱终层（[ip,h323]，ITU-T H.225.0/Q.931）。10 键
	// 无 Default（决策 F；缺省语义在 translate 镜像 parse：role caller/
	// scenario full/crv 0x2584/display Administrator/calls 1/dst_port 1720/
	// media·ras 子映射缺省）；无跨层 FieldContract（端口住本层，1.2 已批
	// 偏离）；role/scenario/calls/display 约束留 layer validator（复用
	// legacy Validate 8 锚词零新文案）。
	r.Register(LayerSchema{Name: "h323", Category: CategoryTerminal, DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"role":         {Type: "string"},
			"scenario":     {Type: "string"},
			"crv":          {Type: "uint16", Min: 0, Max: 65535},
			"display_name": {Type: "string"},
			"calls":        {Type: "uint16", Min: 0, Max: 65535},
			"rewrite_addr": {Type: "bool"},
			"src_port":     {Type: "uint16", Min: 0, Max: 65535},
			"dst_port":     {Type: "uint16", Min: 0, Max: 65535},
			"media":        {Type: "object"},
			"ras":          {Type: "object"},
		},
	})
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
	// D-FINS-1：层 config 收 FINSConfig 同名 16 用户键，一律不设 Default
	// （mcp 决策 F 谱系：缺省单一真相在代码——GCT=2/ICF 0x81·0xC1/SID 递增/
	// 默认 DM 读由 GetConfig/生成器 resolve 承担）。read_areas 仅 0104 合法，
	// 语义校验归 fins.Validate。
	r.Register(LayerSchema{Name: "fins", Category: CategoryTerminal,
		DependsOn:   []string{"udp"},
		TransportOn: []string{"udp", "tcp"},
		Fields: map[string]FieldSchema{
			"transport":   {Type: "string"},
			"commands":    {Type: "list"},
			"sessions":    {Type: "int", Min: 0, Max: 1000000},
			"sid":         {Type: "uint8", Min: 0, Max: 255},
			"sid_auto":    {Type: "bool"},
			"icf":         {Type: "uint8", Min: 0, Max: 255},
			"gct":         {Type: "uint8", Min: 0, Max: 255},
			"dna":         {Type: "uint8", Min: 0, Max: 255},
			"da1":         {Type: "uint8", Min: 0, Max: 255},
			"da2":         {Type: "uint8", Min: 0, Max: 255},
			"sna":         {Type: "uint8", Min: 0, Max: 255},
			"sa1":         {Type: "uint8", Min: 0, Max: 255},
			"sa2":         {Type: "uint8", Min: 0, Max: 255},
			"handshake":   {Type: "bool"},
			"termination": {Type: "bool"},
			"read_areas":  {Type: "list"},
		},
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
			// FTP 链化：业务字段全进 ftp 层（顶层 ftp 键已删）。banner/
			// commands/data_channel 是老形状字段（D-FTP-1 前）；sessions/
			// transactions 是多会话形状。值语义归 planner；层字段动态名单
			// 见 layerDynAllowlist，ftp 业务字段动态走 spec.FTP。
			"banner":       {Type: "string", Default: ""},
			"sessions":     {Type: "list", Default: []interface{}{}},
			"transactions": {Type: "list", Default: []interface{}{}},
			"commands":     {Type: "list", Default: []interface{}{}},
			"data_channel": {Type: "object"},
		},
	})
	r.Register(LayerSchema{Name: "smtp", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		OptionalOn:    []string{"tls"},
		FieldContract: map[string]string{"tcp.dst_port": "25"}, // RFC 5321 §3.1；用户显式非标准端口优先（提交 587 / SMTPS 465），不强制
		Fields: map[string]FieldSchema{
			// D-SMTP-1：banner/dialog/email 三键（SMTPConfig 同名；email/
			// dialog 是嵌套对象/数组，V9 只验顶层键存在，值语义归翻译分支
			// JSON 往返解码 + validator）。from/to 孤儿已删（§5）。
			"banner": {Type: "string", Default: ""},
			"dialog": {Type: "list", Default: []interface{}{}},
			"email":  {Type: "object"},
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
		Fields: map[string]FieldSchema{
			"banner":   {Type: "string", Default: ""},
			"commands": {Type: "list", Default: []interface{}{}},
			"mailbox":  {Type: "object"},
		},
	})
	r.Register(LayerSchema{Name: "imap", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		OptionalOn:    []string{"tls"},
		FieldContract: map[string]string{"tcp.dst_port": "143"}, // RFC 3501 默认 143；用户显式非标准端口优先（IMAPS 993），不强制
		Fields: map[string]FieldSchema{
			// D-IMAP-1：banner/commands/idle/pipelined_commands/
			// allow_utf8_mailbox 五键（IMAPConfig 同名；commands/idle/
			// mime_body 是嵌套对象/数组，V9 只验顶层键存在，值语义归翻译
			// 分支 JSON 往返解码 + validator）。
			"banner":             {Type: "string", Default: ""},
			"commands":           {Type: "list", Default: []interface{}{}},
			"idle":               {Type: "object"},
			"pipelined_commands": {Type: "bool", Default: false},
			"allow_utf8_mailbox": {Type: "bool", Default: false},
		},
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
	r.Register(LayerSchema{Name: "vmess", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "443"}, // VMess 默认 443（V2Ray 惯例）；用户显式非标准端口优先，不强制
	})
	r.Register(LayerSchema{Name: "shadowsocks", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "8388"}, // Shadowsocks 默认 8388；用户显式非标准端口优先，不强制
	})
	r.Register(LayerSchema{Name: "socks5", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		OptionalOn:    []string{"tls"},                           // SOCKS5-over-TLS：显式写 tls 层启用，默认不启用（J 组组合层）
		FieldContract: map[string]string{"tcp.dst_port": "1080"}, // SOCKS 默认 1080；用户显式非标准端口优先，不强制
		Fields: map[string]FieldSchema{
			"version":     {Type: "string", Default: ""},
			"auth_method": {Type: "string", Default: ""},
			"username":    {Type: "string", Default: ""},
			"password":    {Type: "string", Default: ""},
			"cmd":         {Type: "string", Default: ""},
			"dst_addr":    {Type: "string", Default: ""},
			"dst_port":    {Type: "int"},
			"rep":         {Type: "int"},
			"bnd_addr":    {Type: "string", Default: ""},
			"bnd_port":    {Type: "int"},
			"user_id":     {Type: "string", Default: ""},
			"data":        {Type: "list", Default: []interface{}{}},
			"udp":         {Type: "object"},
		},
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
			// D-TLS-2: cert 嵌套对象（5 子键全可选，缺席/缺键填默认）。
			// object 型无标量 V9 边界（Min/Max 全 0 跳过数值检查）；
			// 动态对象走 checkLayerDynObjects 下钻（subject/san 开），
			// 结构化校验在 chain_planner.go tls 结构性段。
			"cert": {Type: "object"},
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

	// ---- B4 封装类（vxlan / nvgre / geneve）----
	// vxlan（udp 终结层。RFC 7348——8-byte VXLAN 头（I flag 0x08 + VNI
	// 24-bit）+ 内层 Ethernet 帧，wire 字节由 vxlan 生成器产出）。UDP 语义
	// 交给 udp 层生成器；配置经 spec.VXLAN flat 键携带、FlowMeta 直传生成
	// 器（gtp 同款）；目的端口 4789（IANA 指派，FieldContract 默认）。
	r.Register(LayerSchema{Name: "vxlan", Category: CategoryTerminal,
		DependsOn:     []string{"udp"},
		FieldContract: map[string]string{"udp.dst_port": "4789"},
	})
	// nvgre（raw-IP 终结层。RFC 7637——生成器自产完整包：外层 IP proto 47 +
	// GRE 头（K=1、ProtocolType 0x6558 TEB、Key=VSID<<8|FlowID，经
	// L2Config.GRE 由 builder writeGRE 序列化）+ 内层 Ethernet 帧 payload。
	// 与设计稿 [ip,gre,nvgre] 的文档化分歧：gre 隧道层生成器要求内层包链
	// （req.Inner 产 L3/L4 包）且 ProtocolType 限 0x0800/0x0806/0x86DD，
	// NVGRE 的内层是裸 Ethernet 帧——无法复用，故 [ip,nvgre] 直连、由
	// nvgre 生成器自写外层 IP + L2.GRE。无传输层、无端口概念。
	r.Register(LayerSchema{Name: "nvgre", Category: CategoryTerminal,
		DependsOn: []string{"ip"},
	})
	// srv6（raw-IP 终结层。RFC 8754——IPv6 扩展头 SRH（NH=43/Routing
	// Type=4），非独立传输层：每 flow 产 frames 帧 IPv6+SRH(+HBH)+内层
	// L4/载荷完整包，wire 由 legacy srv6 Planner 复用产出（SRV6Generator
	// 包装）。与 nvgre 同构：无传输层、无端口概念（内层端口是 SRH 载荷
	// 语义，住层内 inner_src_port/inner_dst_port，0 回退 spec 逐流值）。
	// D-SRV6-1：层 config 收 SRv6Config 同名 16 用户键，一律不设 Default
	// （mcp 决策 F 先例：SegmentList 缺省 [] 会污染空层"VR-02 必拒"线形；
	// 零值即设计缺省 SL=len-1/LE=len-1|len-2/reduced 按 seg_type/frames 1/
	// dir up 由生成器 resolve* 承担）。指针三态（segments_left_ptr 等）由
	// ParseSRv6ConfigFromMap 从同名标量键派生，非独立用户键。
	r.Register(LayerSchema{Name: "srv6", Category: CategoryTerminal,
		DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"src_ipv6":         {Type: "string"},
			"dst_ipv6":         {Type: "string"},
			"segment_list":     {Type: "list"},
			"segments_left":    {Type: "uint8", Min: 0, Max: 255}, // 显式 0=终节点视角；缺席=len-1（指针三态）
			"last_entry":       {Type: "uint8", Min: 0, Max: 255},
			"reduced":          {Type: "bool"},
			"flags":            {Type: "uint8", Min: 0, Max: 255}, // RFC 8754 §2.1 全 0 硬约束，非零由 VR-08 拒
			"tag":              {Type: "uint16", Min: 0, Max: 65535},
			"seg_type":         {Type: "string"},
			"payload_protocol": {Type: "string"},
			"inner_payload":    {Type: "object"}, // 字符串=原文字节 | 字节数组（getByteSlice 双形）
			"inner_src_port":   {Type: "uint16", Min: 0, Max: 65535},
			"inner_dst_port":   {Type: "uint16", Min: 0, Max: 65535},
			"tlv":              {Type: "list"},
			"frames":           {Type: "int", Min: 0, Max: 1000000}, // 负值由 V9 范围门拒（先于 VR-21）
			"direction":        {Type: "string"},
		},
	})
	// geneve（udp 终结层。RFC 8926——8-byte GENEVE 基础头（Ver/OptLen +
	// OAM/Critical flags + Protocol Type + VNI）+ 4-byte-unit options + 内层
	// Ethernet 帧，wire 字节由 geneve 生成器产出）。UDP 语义交给 udp 层生成
	// 器；配置经 spec.Geneve flat 键携带、FlowMeta 直传生成器；目的端口
	// 6081（IANA 指派，FieldContract 默认）。
	r.Register(LayerSchema{Name: "geneve", Category: CategoryTerminal,
		DependsOn:     []string{"udp"},
		FieldContract: map[string]string{"udp.dst_port": "6081"},
	})

	// ---- B5 消息中间件（openwire）----
	// openwire（tcp 终结层。ActiveMQ OpenWire——[4B length][1B type]
	// loose 命令序列，wire 字节由 openwire 生成器产出）。TCP 语义交给 tcp
	// 层生成器（握手/MSS 分段/挥手/事件级 SrcPort 会话边界）；配置经
	// spec.OpenWire flat 键携带、FlowMeta 直传生成器；目的端口 61616
	//（ActiveMQ 默认，FieldContract 默认；tshark 走启发式识别——每连接
	// 首命令必须是 WireFormatInfo）。连接声明显式 src_ip/dst_ip 时生成器
	// 自产完整包（双栈用例，ldp dual_adjacency 分支同款）。
	r.Register(LayerSchema{Name: "openwire", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "61616"},
		Fields: map[string]FieldSchema{
			"profile": {Type: "string", Default: "activemq_openwire_v12"},
		},
	})

	// ---- B5 消息中间件（ams）----
	// ams（tcp 终结层。ActiveMQ Management Service——本项目 AMS wire
	// profile：Length|Version|Type|Flags|SessionID|CorrelationID|TLV|
	// FrameEnd(ae5a)，wire 字节由 ams 生成器产出；tshark 无该协议
	// dissector——61616 上的 openwire 启发式不会命中 AMS 帧字节（magic
	// 检查不匹配），断言走 TCP 字段与帧字节）。TCP 语义交给 tcp 层生成器；
	// 配置经 spec.AMS flat 键携带、FlowMeta 直传生成器；目的端口 61616
	//（FieldContract 默认）。连接声明显式 src_ip/dst_ip 时生成器自产完整包
	//（双栈/多流用例，openwire 自驱分支同款）。
	r.Register(LayerSchema{Name: "ams", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "61616"},
		Fields: map[string]FieldSchema{
			"profile": {Type: "string", Default: "ams_management_v1"},
		},
	})

	// ---- B5 消息中间件（swarm）----
	// swarm（双承载终结层。UDP discovery SWD1 datagram + TCP storage SWS1
	// frame——本项目 wire profile，wire 字节由 swarm 生成器产出；tshark 无
	// 该协议 dissector，断言走 TCP/UDP 字段与帧字节）。ldp 同款 TransportOn
	// 双载体：DependsOn udp（discovery 链），storage 链显式写 tcp；配置经
	// spec.Swarm flat 键携带、FlowMeta 直传生成器；目的端口 1634（设计 §2，
	// FieldContract 默认）。连接声明显式 src_ip/dst_ip 时生成器自产完整包
	//（双栈用例，B5 自驱分支同款）。
	r.Register(LayerSchema{Name: "swarm", Category: CategoryTerminal,
		DependsOn:     []string{"udp"},
		TransportOn:   []string{"udp", "tcp"},
		FieldContract: map[string]string{"udp.dst_port": "1634", "tcp.dst_port": "1634"},
		Fields: map[string]FieldSchema{
			"profile": {Type: "string", Default: "swarm_storage_v1"},
		},
	})

	// ---- B5 消息中间件（gnutella）----
	// gnutella（tcp 终结层。Gnutella 0.6 HTTP-like 握手 + 23B 二进制消息
	//（MessageID|Descriptor|TTL|Hops|PayloadLength LE），wire 字节由
	// gnutella 生成器产出；tshark 无该协议 dissector，断言走 TCP 字段与
	// 帧字节）。配置经 spec.Gnutella flat 键携带、FlowMeta 直传生成器；
	// 目的端口 6346（FieldContract 默认）。连接声明显式 src_ip/dst_ip 时
	// 生成器自产完整包（B5 自驱分支同款）。
	r.Register(LayerSchema{Name: "gnutella", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "6346"},
		Fields: map[string]FieldSchema{
			"profile": {Type: "string", Default: "gnutella_v060"},
		},
	})

	// ---- D-MPLS-1：mpls 终层自驱（[ip,mpls]，RFC 3031/3032）----
	// 原 shim 层设想（CategoryL2 占位）已裁定否决：A1 终层自驱替代（h323
	// 机器整包 relay——legacy planner 自产 Eth+标签栈+内层 IP/TCP/UDP 完整
	// 包，builder 强制 0x8847/0x8848 原生写栈）。8 键无 Default（决策 F：
	// parse 零缺省，缺省全在 legacy Plan 内填）；端口住本层（1.2 已批
	// 偏离，h323 同款）；label 20bit/TC 3bit/S 栈底约束留 legacy Validate
	// （10 锚词零新文案）。pppoe 仍为占位（后续 P-PIPE）。
	r.Register(LayerSchema{Name: "mpls", Category: CategoryTerminal, DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"labels":        {Type: "list"},
			"multicast":     {Type: "bool"},
			"inner_proto":   {Type: "uint8", Min: 0, Max: 255},
			"src_port":      {Type: "uint16", Min: 0, Max: 65535},
			"dst_port":      {Type: "uint16", Min: 0, Max: 65535},
			"frames":        {Type: "uint16", Min: 0, Max: 65535},
			"direction":     {Type: "string"},
			"inner_payload": {Type: "string"},
		},
	})
	r.Register(LayerSchema{Name: "ngap", Category: CategoryTerminal, DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"global_ran_node_id": {Type: "object"},
			"supported_ta_list":  {Type: "list"},
			"default_paging_drx": {Type: "uint8", Min: 0, Max: 3},
			"amf_name":           {Type: "string"},
			"ran_ue_ngap_id":     {Type: "uint32", Min: 0, Max: 4294967295},
			"amf_ue_ngap_id":     {Type: "uint32", Min: 0, Max: 4294967295},
			"initial_ue_message": {Type: "bool"},
			"initial_nas":        {Type: "string"},
			"downlink_nas":       {Type: "string"},
			"uplink_nas":         {Type: "string"},
			"pdu_session_setup":  {Type: "object"},
			"ue_context_release": {Type: "bool"},
			"src_port":           {Type: "uint16", Min: 0, Max: 65535},
			"dst_port":           {Type: "uint16", Min: 0, Max: 65535},
		},
	})
	r.Register(LayerSchema{Name: "telnet", Category: CategoryTerminal, DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"banner":        {Type: "string"},
			"dialog":        {Type: "list"},
			"terminal_type": {Type: "string"},
			"window_cols":   {Type: "uint16", Min: 0, Max: 65535},
			"window_rows":   {Type: "uint16", Min: 0, Max: 65535},
			"file_source":   {Type: "object"},
			"scenario":      {Type: "string"},
			"username":      {Type: "string"},
			"password":      {Type: "string"},
			"commands":      {Type: "list"},
			"src_port":      {Type: "uint16", Min: 0, Max: 65535},
			"dst_port":      {Type: "uint16", Min: 0, Max: 65535},
		},
	})
	r.Register(LayerSchema{Name: "sip", Category: CategoryTerminal, DependsOn: []string{"ip"},
		OptionalOn: []string{"tls"}, // D-SIP-2 WP-D：SIPS——显式写 tls 层启用（事件面）
		Fields: map[string]FieldSchema{
			"dialog":     {Type: "list"},
			"media":      {Type: "object"},
			"sessions":   {Type: "list"},   // D-SIP-2 WP-A：多会话结构（与 dialog 互斥，语义层判死）
			"medias":     {Type: "list"},   // D-SIP-2 WP-B：多流媒体（与 media 互斥，语义层判死）
			"interleave": {Type: "bool"},   // D-SIP-2 WP-B：媒体流内信令交错调度
			"nat":        {Type: "object"}, // D-SIP-2 WP-C：RFC 3581 rport/received 合成开关
			"src_port":   {Type: "uint16", Min: 0, Max: 65535},
			"dst_port":   {Type: "uint16", Min: 0, Max: 65535},
		},
	})
	r.Register(LayerSchema{Name: "radius", Category: CategoryTerminal, DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"code":                {Type: "uint8", Min: 0, Max: 255},
			"identifier":          {Type: "uint8", Min: 0, Max: 255},
			"authenticator":       {Type: "string"},
			"attributes":          {Type: "list"},
			"response_code":       {Type: "uint8", Min: 0, Max: 255},
			"response_attributes": {Type: "list"},
			"rounds":              {Type: "uint16", Min: 0, Max: 65535},
			"src_port":            {Type: "uint16", Min: 0, Max: 65535},
			"dst_port":            {Type: "uint16", Min: 0, Max: 65535},
		},
	})
	// ldap（tcp 终结层。RFC 4511——BER TLV 消息面：bind 匿名/simple、search
	// （scope 三枚举+Filter CHOICE present/equality+AttributeSelection）+
	// unbind，消息按 MSS 分段，wire 字节由 ldap 生成器 raw 自驱产出
	// （D-LDAP-1 裁定1，radius 对称：legacy 自建 TCP 握手/挥手原样保留）。
	// Fields 登记消费面 15 键（LDAPConfig 全字段）；端口 389 由生成器
	// Plan 缺省（链路径无端口位，0-keep 名单+validateBaseDstPortHandled
	// 豁免）。startTLS/SASL/其余 Filter CHOICE=B′ 注记。
	r.Register(LayerSchema{Name: "ldap", Category: CategoryTerminal, DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"rounds":          {Type: "int", Min: 0, Max: 100000},
			"message_id_base": {Type: "uint16", Min: 0, Max: 65535},
			"version":         {Type: "int", Min: 0, Max: 255},
			"bind_dn":         {Type: "string"},
			"bind_password":   {Type: "string"},
			"search_base_dn":  {Type: "string"},
			"search_scope":    {Type: "int", Min: 0, Max: 255},
			"size_limit":      {Type: "int", Min: 0, Max: 2147483647},
			"time_limit":      {Type: "int", Min: 0, Max: 2147483647},
			"filter_type":     {Type: "string"},
			"search_filter":   {Type: "string"},
			"filter_value":    {Type: "string"},
			"attributes":      {Type: "list"},
			"result_code":     {Type: "uint8", Min: 0, Max: 255},
			"unbind":          {Type: "bool"},
		},
	})
	// rtmp（tcp 终结层。Adobe RTMP——C0/C1/S0/S1/S2/C2 握手（1536B 随机+
	// 回显）+chunk（fmt0 基本头+11B 消息头）+AMF0 命令（connect/
	// createStream/play|publish）+协议控制四消息+音视频数据面，wire 字节由
	// rtmp 生成器 raw 自驱产出（D-RTMP-1 裁定1，ldap 对称：legacy 自建 TCP
	// 握手/挥手原样保留）。Fields 登记消费面 5 键（data 项内子键随 list 项）；
	// 端口 1935 由生成器 Plan 缺省（0-keep+validateBaseDstPortHandled 豁免）。
	// AMF3/chunk fmt1-3/其余命令族=B′ 注记。
	r.Register(LayerSchema{Name: "rtmp", Category: CategoryTerminal, DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"app":         {Type: "string"},
			"tc_url":      {Type: "string"},
			"command":     {Type: "string"},
			"stream_name": {Type: "string"},
			"data":        {Type: "list"}, // 项：direction/msg_type/chunk_stream_id/payload(_b64)
		},
	})
	// rtsp（tcp 终结层。RFC 2326——文本 dialog（OPTIONS/DESCRIBE/SETUP/
	// PLAY/TEARDOWN，CSeq/Session 头自动补全）+可选 RTP 媒体子流（emit_media
	// 触发，RTSPMedia 描述），wire 字节由 rtsp 生成器 raw 自驱产出
	// （D-RTSP-1 裁定1，ldap/rtmp 对称：legacy 自建 TCP 握手/挥手原样保留）。
	// Fields 登记消费面 2 键；控制通道 554 由 validateSpecBase DstPort
	// switch 缺省（dns→53 同款，legacy setDefaultDstPort 链路径等价）。
	r.Register(LayerSchema{Name: "rtsp", Category: CategoryTerminal, DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"dialog": {Type: "list"}, // 项：method/uri/status_code/status_text/headers/body/direction/emit_media
			"media":  {Type: "object"},
		},
	})
	// pptp（tcp 终结层。RFC 2637——TCP 控制面（1723，15 消息族：SCCRQ/
	// SCCRP/OCRQ/OCRP/SLI/CCRQ/CCDN/StopRQ/RP/ECRQ/RP/ICRQ/ICRP/ICCN/WEN）
	// +GRE 增强头数据面（16B 头+PPP 帧内嵌 IPv4），wire 字节由 pptp 生成器
	// raw 自驱产出（D-PPTP-1 裁定1，四连协议对称：legacy 自建 TCP 握手/
	// 挥手原样保留）。Fields 登记 parsePPTPConfig 顶层 51 键（1.12 消费面
	// 逐键；inner_ip=object 内嵌 7 子键 srv6 先例）；控制通道 1723 由生成器
	// Plan :404 缺省（0-keep+validateBaseDstPortHandled 豁免）。ICRQ 族
	// PAC 现网形/MS 缺省= B′ 注记。
	r.Register(LayerSchema{Name: "pptp", Category: CategoryTerminal, DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"role":                {Type: "string"},
			"scenario":            {Type: "string"},
			"calls":               {Type: "int", Min: 0, Max: 65535},
			"echo":                {Type: "bool"},
			"version":             {Type: "uint16", Min: 0, Max: 65535},
			"framing_caps":        {Type: "uint32", Min: 0, Max: 4294967295},
			"bearer_caps":         {Type: "uint32", Min: 0, Max: 4294967295},
			"max_channels":        {Type: "uint16", Min: 0, Max: 65535},
			"firmware_revision":   {Type: "uint16", Min: 0, Max: 65535},
			"host_name":           {Type: "string"},
			"vendor_name":         {Type: "string"},
			"scrp_result":         {Type: "uint8", Min: 0, Max: 255},
			"scrp_error":          {Type: "uint8", Min: 0, Max: 255},
			"scrp_framing_caps":   {Type: "uint32", Min: 0, Max: 4294967295},
			"scrp_bearer_caps":    {Type: "uint32", Min: 0, Max: 4294967295},
			"scrp_firmware_rev":   {Type: "uint16", Min: 0, Max: 65535},
			"call_id":             {Type: "uint16", Min: 0, Max: 65535},
			"peer_call_id":        {Type: "uint16", Min: 0, Max: 65535},
			"call_serial":         {Type: "uint16", Min: 0, Max: 65535},
			"min_bps":             {Type: "uint32", Min: 0, Max: 4294967295},
			"max_bps":             {Type: "uint32", Min: 0, Max: 4294967295},
			"bearer_type":         {Type: "uint32", Min: 0, Max: 4294967295},
			"framing_type":        {Type: "uint32", Min: 0, Max: 4294967295},
			"window_size":         {Type: "uint16", Min: 0, Max: 65535},
			"packet_delay":        {Type: "uint16", Min: 0, Max: 65535},
			"phone_number":        {Type: "string"},
			"dialed_number":       {Type: "string"},
			"dialing_number":      {Type: "string"},
			"sub_address":         {Type: "string"},
			"ocrp_result":         {Type: "uint8", Min: 0, Max: 255},
			"ocrp_error":          {Type: "uint8", Min: 0, Max: 255},
			"cause_code":          {Type: "uint16", Min: 0, Max: 65535},
			"connect_speed":       {Type: "uint32", Min: 0, Max: 4294967295},
			"ocrp_window_size":    {Type: "uint16", Min: 0, Max: 65535},
			"ocrp_delay":          {Type: "uint16", Min: 0, Max: 65535},
			"physical_channel_id": {Type: "uint32", Min: 0, Max: 4294967295},
			"send_accm":           {Type: "uint32", Min: 0, Max: 4294967295},
			"receive_accm":        {Type: "uint32", Min: 0, Max: 4294967295},
			"sli_count":           {Type: "int", Min: 0, Max: 65535},
			"sli_peer_call_id":    {Type: "uint16", Min: 0, Max: 65535},
			"stop_result":         {Type: "uint8", Min: 0, Max: 255},
			"stop_reason":         {Type: "uint8", Min: 0, Max: 255},
			"stop_error":          {Type: "uint8", Min: 0, Max: 255},
			"ccdn_result":         {Type: "uint8", Min: 0, Max: 255},
			"ccdn_error":          {Type: "uint8", Min: 0, Max: 255},
			"ccdn_cause":          {Type: "uint8", Min: 0, Max: 255},
			"wen":                 {Type: "bool"},
			"incoming_call":       {Type: "bool"},
			"data_frames":         {Type: "int", Min: 0, Max: 1000000},
			"down_data_frames":    {Type: "int", Min: 0, Max: 1000000},
			"inner_ip":            {Type: "object"}, // 内嵌 7 子键：src_ip/dst_ip/proto/src_port/dst_port/ttl/payload（srv6 inner_payload 先例）
		},
	})
	// vnc（tcp 终结层。RFC 6143 RFB——TCP 5900 服务器先发言：版本协商
	// 12B→安全握手（Tight 16 默认/VNC 2/None 1 三路径）→ServerInit→客户端
	// 6 消息→FBU 循环→拆链，wire 字节由 vnc 生成器 raw 自驱产出（D-VNC-1
	// 裁定1，五连协议对称：legacy 自建 TCP 握手/挥手原样保留）。Fields 登记
	// parseVNCConfig 顶层 26 键（1.12 消费面逐键：19 标量+3 object+4 list）；
	// 控制通道 5900 由生成器 Plan :561 缺省（0-keep+validateBaseDstPortHandled
	// 豁免，pptp 模式）。security_type=枚举(1/2/16)不带范围（V9 区间会误伤，
	// planner Validate 锚）；encodings 含负值伪编码（-240 等）不带范围；
	// challenge_seed/response_seed uint64 无界。
	r.Register(LayerSchema{Name: "vnc", Category: CategoryTerminal, DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"security_type":           {Type: "int"},
			"auth_result":             {Type: "int", Min: 0, Max: 2},
			"auth_reason":             {Type: "string"},
			"share_desktop":           {Type: "bool"},
			"width":                   {Type: "int", Min: 1, Max: 65535},
			"height":                  {Type: "int", Min: 1, Max: 65535},
			"server_name":             {Type: "string"},
			"pixel_format":            {Type: "object"}, // 10 子键：bits_per_pixel/depth/big_endian/true_color/red_max/green_max/blue_max/red_shift/green_shift/blue_shift
			"interaction_caps":        {Type: "object"}, // 4 子键：server_msg_types/client_msg_types/encoding_types/caps[]（记录 code/vendor/name）
			"key_events":              {Type: "list"},   // 记录：down/key
			"client_set_pixel_format": {Type: "bool"},
			"client_set_encodings":    {Type: "bool"},
			"encodings":               {Type: "list"}, // 含负值伪编码（-240 等），V9 不带范围
			"rounds":                  {Type: "int", Min: 1, Max: 1000000},
			"pointer_x":               {Type: "int", Min: 0, Max: 65535},
			"pointer_y":               {Type: "int", Min: 0, Max: 65535},
			"pointer_button":          {Type: "int", Min: 0, Max: 255},
			"fbu_update_interval":     {Type: "int", Min: 1, Max: 1000000},
			"initial_fbu":             {Type: "list"}, // rect 记录 7 键：x/y/width/height/encoding/hextile_tile_data/xcursor_blob
			"update_rects":            {Type: "list"}, // rect 记录同 initial_fbu
			"bell":                    {Type: "bool"},
			"set_colour_map_entries":  {Type: "object"}, // 2 子键：first/colors
			"server_cut_text":         {Type: "string"},
			"client_cut_text":         {Type: "string"},
			"challenge_seed":          {Type: "uint64"},
			"response_seed":           {Type: "uint64"},
		},
	})
	// xmpp（tcp 终结层。RFC 6120——TCP 5222 XML 流会话：流开启→features→
	// SASL 认证（PLAIN/DIGEST-MD5/SCRAM-SHA-1/ANONYMOUS 四枚举）→流重启→
	// 资源绑定→会话建立→presence→messages→流关闭，wire 字节由 xmpp 生成器
	// raw 自驱产出（D-XMPP-1 裁定1，六连协议对称：legacy 自建 TCP 握手/挥手
	// 原样保留）。Fields 登记 parseXmppConfig 顶层 9 键（1.12 消费面逐键：
	// 7 标量+presence bool+messages list 记录 3 键 direction/to/body）；
	// 控制通道 5222 由链路径 DstPort switch 缺省（**legacy Plan 无内部缺省**，
	// 缺省住 flat setDefaultDstPort :944——xmpp 与 pptp 唯一差异，rtsp 式
	// 必选）。auth_mechanism=枚举无范围（planner Validate 锚）。
	r.Register(LayerSchema{Name: "xmpp", Category: CategoryTerminal, DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"from":           {Type: "string"},
			"jid":            {Type: "string"},
			"resource":       {Type: "string"},
			"stream_id":      {Type: "string"},
			"auth_mechanism": {Type: "string"}, // 枚举 PLAIN/DIGEST-MD5/SCRAM-SHA-1/ANONYMOUS，planner 锚
			"username":       {Type: "string"},
			"password":       {Type: "string"},
			"presence":       {Type: "bool"},
			"messages":       {Type: "list"}, // 记录：direction/to/body
		},
	})
	// sctp（tcp 终结层。RFC 4960——SCTP 自成 L4（IP proto 132）：公共头
	// （src/dst 端口+VerificationTag）+4 路握手（INIT VTag=0→INIT-ACK 带
	// Cookie→COOKIE-ECHO→COOKIE-ACK）+DATA（TSN/SID/SSN/PPID，分片 B/E/
	// middle flags）+HEARTBEAT（主路径/AltPath 多宿主子流）+SHUTDOWN 三路
	// 或 ABORT 突断，wire 字节由 sctp 生成器 raw 自驱产出（D-SCTP-1 裁定1，
	// 八连协议对称：legacy 全消息面原样保留）。Fields 登记 parse 6 键+
	// **src_port/dst_port 补位（1.12：SCTP 端口无层可住必须立项——tcp/udp
	// 层不适用于 proto 132，端口住本层经 translate 回填 spec）**；无协议级
	// 缺省（flat 同口径不静默改 80）。fragment_size V9 区间 [16,1e6]：显式
	// 0 过 V9（无分叉缺省）、负值/1-15 被拒（Validate 下界 16 同口径）。
	r.Register(LayerSchema{Name: "sctp", Category: CategoryTerminal, DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"verification_tag": {Type: "uint32", Min: 0, Max: 4294967295},
			"initiate_tag":     {Type: "uint32", Min: 0, Max: 4294967295},
			"chunks":           {Type: "list"},   // 记录 7 键：tsn/sid/ssn/ppid/data（双形 string/字节数组）/direction/file_source
			"heartbeats":       {Type: "object"}, // 2 子键：count/alt_path（4 键 alt_src_ip/alt_dst_ip/alt_src_mac/alt_dst_mac）
			"abort":            {Type: "bool"},
			"fragment_size":    {Type: "int", Min: 16, Max: 1000000},
			"src_port":         {Type: "uint16", Min: 0, Max: 65535},
			"dst_port":         {Type: "uint16", Min: 0, Max: 65535},
		},
	})
	// jt808（tcp 终结层。JT/T 808-2019——TCP 长连接 3 握手+0x7e 定界帧
	// （XOR 校验+0x7d 转义）+13 型消息面+双流水号空间+4 自动绑定+分包
	// （bit14+pkgNum/pkgTotal，体长 10 位上界 1023），wire 字节由 jt808
	// 生成器 raw 自驱产出（D-JT808-1 裁定1，九连协议对称：legacy 全消息
	// 面 wrap PlanWithConfig——legacy Plan 硬错，唯一入口）。端口=legacy
	// 内部缺省 7611（vnc/pptp 变体：无 switch case、无协议层端口字段）。
	// Fields 登记 parse 18 键：17 标量+procedures list（V9 不下探，嵌套
	// 语义锚=ValidateConfig：phone 12 位/auth 鉴权码必备/车牌互斥/
	// ACKFlag≤3/注册结果≤4）。范围只设 ValidateConfig 真校验键（
	// encrypt_flag 0-1/license_color 0-9 上界——6/7/8 由 planner 枚举锚拒，
	// V9 是超集面）+uint16/uint32 位宽面；registration_result 顶层不设
	// 范围（ValidateConfig 只查 procedures 内指针覆盖值，顶层 0-255 全合
	// 法——诚实注记）。
	r.Register(LayerSchema{Name: "jt808", Category: CategoryTerminal, DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"phone":               {Type: "string"}, // ^\d{12}$，ValidateConfig 锚
			"version":             {Type: "string"}, // 枚举 2011/2013/2019，planner 锚
			"encrypt_flag":        {Type: "int", Min: 0, Max: 1},
			"license_color":       {Type: "int", Min: 0, Max: 9}, // 枚举 0-5,9，planner 锚
			"license_plate":       {Type: "string"},
			"province_id":         {Type: "uint16", Min: 0, Max: 65535},
			"city_id":             {Type: "uint16", Min: 0, Max: 65535},
			"manufacturer_id":     {Type: "string"}, // ≤5 ASCII，planner 锚
			"terminal_model":      {Type: "string"}, // ≤20B，planner 锚
			"terminal_id":         {Type: "string"}, // ≤7B，planner 锚
			"terminal_type":       {Type: "int"},    // 语义 0-2 ValidateConfig 不查——诚实不设范围
			"initial_sn":          {Type: "uint16", Min: 0, Max: 65535},
			"platform_initial_sn": {Type: "uint16", Min: 0, Max: 65535},
			"auth_code":           {Type: "string"}, // ≤16B GBK，planner 锚
			"imei":                {Type: "string"},
			"software_version":    {Type: "string"},
			"registration_result": {Type: "int"},  // 顶层不设范围（见上）
			"procedures":          {Type: "list"}, // 13 键：type/ack_flag/location_data/response_sn/response_msg_id/registration_result/auth_code/imei/software_version/text/text_flag/params/property_data
		},
	})
	// jt809（tcp 终结层。JT/T 809-2019——双 TCP 链路（主 8812 下级→上级
	// 0x1xxx + 从 8813 上级→下级 0x9xxx，同 GroupID 关联）+5B/转义/CRC16
	// 信封（22B/30B 版本条件头）+16 型链路管理族，wire 字节由 jt809 生成器
	// raw 自驱产出（D-JT809-1 裁定1/3；容器族 0x1200-0x1600/0x9200-0x9600
	// B′ 不编排）。端口=主链 8812 内部缺省+mapToFlowSpec case（jt808 80
	// 穿透教训移植）；从链 8813=生成器合成面。Fields 登记 parse 14 键：
	// 12 标量+procedures/slave_procedures 双 list（V9 不下探，嵌套语义锚=
	// ValidateConfig：gnss 区间/version_flag≤2/password≤8/16 型枚举/链路
	// 归属/Result≤4/ErrorCode·ReasonCode≤2）。
	r.Register(LayerSchema{Name: "jt809", Category: CategoryTerminal, DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"gnss_center_id":      {Type: "uint32", Min: 0, Max: 999999999}, // ValidateConfig 锚
			"user_id":             {Type: "uint32", Min: 0, Max: 4294967295},
			"password":            {Type: "string"}, // ≤8 pad，planner 锚
			"version_flag":        {Type: "int", Min: 0, Max: 2},
			"version_bytes":       {Type: "string"}, // 6 hex，planner 锚
			"encrypt_flag":        {Type: "int", Min: 0, Max: 1},
			"encrypt_key":         {Type: "uint32", Min: 0, Max: 4294967295},
			"time_sec":            {Type: "uint64"}, // 0=now（Unix 秒），上界不设（诚实注记）
			"down_link_ip":        {Type: "string"}, // ≤32 pad，planner 锚
			"down_link_port":      {Type: "uint16", Min: 0, Max: 65535},
			"initial_sn":          {Type: "uint32", Min: 0, Max: 4294967295},
			"platform_initial_sn": {Type: "uint32", Min: 0, Max: 4294967295},
			"procedures":          {Type: "list"}, // 8 键：type/verify_code/result/password/down_link_ip/down_link_port/error_code/reason_code
			"slave_procedures":    {Type: "list"}, // 同 procedures 8 键；非空即开从链 TCP
		},
	})
	// jtt905（tcp 终结层。JT/T 905.2-2014 出租汽车 ISU——单 TCP（缺省
	// 10700）+7E 信封（808 族线面复用，XOR+转义；DataLength=纯体长无版本
	// 位——金向量 0x0023 实证）+5 型消息面（0x0B03 签到/0x0B04 签退/
	// 0x0002 心跳/0x0001·0x8001 通用应答）+position 可选块，wire 字节由
	// jtt905 生成器 raw 自驱产出（D-JTT905-1 裁定1-3；legacy 虚构
	// 0x1001/0x1002 与 GBK 体面废弃）。端口=10700 内部缺省+mapToFlowSpec
	// case（jt808 80 穿透教训移植）。Fields 登记 parse 25 键：24 标量+
	// procedures list（V9 不下探，嵌套语义锚=ValidateConfig：isu_id 12 位/
	// plate≤6 ASCII/Result 0-2/BCD 位数族）。position 为 object 键
	// （getByteSlice 无关，直接 map 直传）。
	r.Register(LayerSchema{Name: "jtt905", Category: CategoryTerminal, DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"isu_id":                    {Type: "string"}, // 12 位数字 BCD6，planner 锚
			"initial_sn":                {Type: "uint16", Min: 0, Max: 65535},
			"platform_initial_sn":       {Type: "uint16", Min: 0, Max: 65535},
			"business_license":          {Type: "string"}, // ≤16 ASCII，planner 锚
			"qualification_code":        {Type: "string"}, // ≤19 ASCII，planner 锚
			"plate_no":                  {Type: "string"}, // ≤6 ASCII，planner 锚
			"position":                  {Type: "object"}, // 0x0200 基础位 7 键
			"taximeter_k_value":         {Type: "string"}, // 4 位 BCD，planner 锚
			"on_duty_power_on_time":     {Type: "string"}, // 12 位 yyyyMMddHHmm，planner 锚
			"on_duty_power_off_time":    {Type: "string"},
			"on_duty_mileage":           {Type: "string"}, // 6 位 BCD，planner 锚
			"on_duty_operation_mileage": {Type: "string"},
			"train_number":              {Type: "string"}, // 4 位
			"timing_time":               {Type: "string"}, // 6 位
			"total_amount":              {Type: "string"}, // 6 位
			"card_amount":               {Type: "string"}, // 6 位
			"card_count":                {Type: "string"}, // 4 位
			"on_duty_mileage_between":   {Type: "string"}, // 4 位
			"total_mileage":             {Type: "string"}, // 8 位
			"total_operation_mileage":   {Type: "string"}, // 8 位
			"unit_price":                {Type: "string"}, // 4 位
			"total_operations":          {Type: "uint32", Min: 0, Max: 4294967295},
			"sign_type":                 {Type: "int", Min: 0, Max: 255},
			"procedures":                {Type: "list"}, // 4 键：type/result/reply_sn/reply_msg_id
			"heartbeat_count":           {Type: "int", Min: 0, Max: 1000},
		},
	})
	// pppoe（eth 终结层。RFC 2516——Discovery（PADI/PADO/PADR/PADS，EtherType
	// 0x8863）+ 会话（LCP/Auth/数据，EtherType 0x8864）+ PADT 终止，wire 字节
	// 由 pppoe 生成器 raw 自驱产出（D-PPPOE-1 裁定1，帧无外层 IP 头，ip 层
	// 值=内层 IPv4 语义）。Fields 只登记消费面 16 键（1.12）：14 消费键 +
	// padt + sessions；wire 键 code/ppp_protocol/payload_length/discovery_
	// tags 是 builder 专属不进 Fields。sessions[] 与顶层行为 6 键互斥由
	// schema/semantic 判死（9.49）。
	r.Register(LayerSchema{Name: "pppoe", Category: CategoryTerminal,
		DependsOn: []string{"ip"},
		Fields: map[string]FieldSchema{
			"session_id":     {Type: "uint16", Min: 0, Max: 65535},
			"skip_discovery": {Type: "bool"},
			"ac_name":        {Type: "string"},
			"service_name":   {Type: "string"},
			"cookie":         {Type: "object"}, // 字符串=原文字节 | 字节数组（getByteSlice 双形）
			"mru":            {Type: "uint16", Min: 0, Max: 65535},
			"magic_number":   {Type: "uint32", Min: 0, Max: 4294967295},
			"auth":           {Type: "string"},
			"username":       {Type: "string"},
			"password":       {Type: "string"},
			"data_frames":    {Type: "int", Min: 0, Max: 1000000},
			"data_payload":   {Type: "object"}, // 同 cookie 双形
			"inner_proto":    {Type: "uint8", Min: 0, Max: 255},
			"data_direction": {Type: "string"},
			"padt":           {Type: "bool"}, // 缺省 true（RFC 2516 §5.6），指针三态
			"sessions":       {Type: "list"}, // 每项一完整生命周期（9.49）
		},
	})

	defaultRegistry = r
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
