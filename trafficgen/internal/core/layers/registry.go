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
		Fields: map[string]FieldSchema{
			"leap_indicator":  {Type: "uint8"},
			"version":         {Type: "uint8"},
			"mode":            {Type: "uint8"},
			"stratum":         {Type: "uint8"},
			"poll":            {Type: "uint8"},
			"precision":       {Type: "int8"},
			"root_delay":      {Type: "uint32"},
			"root_dispersion": {Type: "uint32"},
			"reference_id":    {Type: "string"},
			"ref_timestamp":   {Type: "uint64"},
			"origin_ts":       {Type: "uint64"},
			"receive_ts":      {Type: "uint64"},
			"transmit_ts":     {Type: "uint64"},
			"key_id":          {Type: "uint32"},
			"mac":             {Type: "list"},
			"extensions":      {Type: "list"},
			"is_response":     {Type: "bool"},
			"poll_interval":   {Type: "int"},
			"repeat_count":    {Type: "int"},
			"sequence":        {Type: "string"},
			"implementation":  {Type: "string"},
			"request_code":    {Type: "uint16"},
			"association_id":  {Type: "uint16"},
			"offset":          {Type: "int"},
			"error":           {Type: "uint16"},
			"more":            {Type: "bool"},
			"status_word":     {Type: "uint16"},
			"control_data":    {Type: "object"},
		},
	})
	r.Register(LayerSchema{Name: "snmp", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
		Fields: map[string]FieldSchema{
			"version":                    {Type: "uint8"},
			"community":                  {Type: "string"},
			"user_name":                  {Type: "string"},
			"auth_protocol":              {Type: "string"},
			"auth_password":              {Type: "string"},
			"priv_protocol":              {Type: "string"},
			"priv_password":              {Type: "string"},
			"authoritative_engine_id":    {Type: "string"},
			"authoritative_engine_boots": {Type: "uint32"},
			"authoritative_engine_time":  {Type: "uint32"},
			"pdu_type":                   {Type: "uint8"},
			"request_id":                 {Type: "uint32"},
			"non_repeaters":              {Type: "uint8"},
			"max_repetitions":            {Type: "uint8"},
			"var_binds":                  {Type: "list"},
			"is_response":                {Type: "bool"},
			"response_error":             {Type: "uint8"},
			"response_error_index":       {Type: "uint8"},
			"response_values":            {Type: "list"},
			"enterprise":                 {Type: "string"},
			"agent_addr":                 {Type: "string"},
			"generic_trap":               {Type: "uint8"},
			"specific_trap":              {Type: "uint8"},
			"time_stamp":                 {Type: "uint32"},
			"poll_interval":              {Type: "int"},
			"repeat_count":               {Type: "int"},
			"engine_id_override":         {Type: "string"},
			"max_size":                   {Type: "uint32"},
			"context_name":               {Type: "string"},
		},
	})
	r.Register(LayerSchema{Name: "syslog", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
	})
	// ---- 波 5：mdns/dhcp/dhcpv6/ssdp/rip（udp 终结层，多播/广播目标经
	// MessageEvent.DstIP/DstMAC 覆盖；配置经 FlowMeta 直传生成器）。
	r.Register(LayerSchema{Name: "mdns", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
		Fields: map[string]FieldSchema{
			"mode":                   {Type: "string"},
			"questions":              {Type: "list"},
			"answers":                {Type: "list"},
			"authorities":            {Type: "list"},
			"additionals":            {Type: "list"},
			"probing_repeat":         {Type: "int"},
			"probing_interval":       {Type: "int"},
			"probing_jitter_max":     {Type: "int"},
			"probing_jitter_seed":    {Type: "int"},
			"announcing_repeat":      {Type: "int"},
			"announcing_interval":    {Type: "int"},
			"response_delay":         {Type: "int"},
			"multicast_group":        {Type: "string"},
			"force_unicast_response": {Type: "bool"},
			"cache_flush":            {Type: "bool"},
			"default_ttl":            {Type: "uint32"},
			"tc":                     {Type: "bool"},
		},
	})
	r.Register(LayerSchema{Name: "dhcp", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
		Fields: map[string]FieldSchema{
			"role":                       {Type: "string"},
			"xid":                        {Type: "uint32"},
			"scenario":                   {Type: "string"},
			"messages":                   {Type: "list"},
			"client_mac":                 {Type: "string"},
			"h_type":                     {Type: "uint8"},
			"h_len":                      {Type: "uint8"},
			"broadcast_flag":             {Type: "bool"},
			"secs":                       {Type: "uint16"},
			"sname":                      {Type: "string"},
			"file":                       {Type: "string"},
			"default_client_ip":          {Type: "string"},
			"default_your_ip":            {Type: "string"},
			"default_server_ip":          {Type: "string"},
			"default_relay_agent_ip":     {Type: "string"},
			"default_server_identifier":  {Type: "string"},
			"default_lease_time":         {Type: "uint32"},
			"default_t1":                 {Type: "uint32"},
			"default_t2":                 {Type: "uint32"},
			"default_subnet_mask":        {Type: "string"},
			"default_routers":            {Type: "list"},
			"default_dns":                {Type: "list"},
			"default_domain_name":        {Type: "string"},
			"default_hostname":           {Type: "string"},
			"default_domain_search":      {Type: "list"},
			"default_client_id":          {Type: "list"},
			"default_requested_ip":       {Type: "string"},
			"default_param_request_list": {Type: "list"},
			"default_vendor_class":       {Type: "string"},
			"default_relay_agent_info":   {Type: "list"},
		},
	})
	r.Register(LayerSchema{Name: "dhcpv6", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
		Fields: map[string]FieldSchema{
			"messages":                   {Type: "list"},
			"scenario":                   {Type: "string"},
			"client_duid":                {Type: "object"},
			"server_duid":                {Type: "object"},
			"relay_config":               {Type: "object"},
			"default_leased_addr":        {Type: "string"},
			"default_iaid":               {Type: "uint32"},
			"default_preferred_lifetime": {Type: "uint32"},
			"default_valid_lifetime":     {Type: "uint32"},
			"default_t1":                 {Type: "uint32"},
			"default_t2":                 {Type: "uint32"},
			"default_preference":         {Type: "uint8"},
			"default_status_code":        {Type: "uint16"},
			"default_status_message":     {Type: "string"},
			"default_oro":                {Type: "list"},
			"default_dns_servers":        {Type: "list"},
			"default_dns_search":         {Type: "list"},
			"default_sntp_servers":       {Type: "list"},
			"default_info_refresh_time":  {Type: "uint32"},
		},
	})
	r.Register(LayerSchema{Name: "ssdp", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
	})
	r.Register(LayerSchema{Name: "rip", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
	})
	// D-TFTP-1：tftp（udp 终结层；层 23 键对齐 core.TFTPConfig json
	// 标签——键名=标签名。data_payload_pattern 实测为 hex 字符串
	// （getByteSlice 原样字节）→ string；retransmit_blocks → list；
	// 其余按 Go 类型：uint16/uint32/bool/*bool（*bool 无范围，显式
	// 0=false/缺席=nil 语义走翻译侧 getBoolPtr）。
	r.Register(LayerSchema{Name: "tftp", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
		Fields: map[string]FieldSchema{
			"mode":                       {Type: "string", Default: ""},
			"filename":                   {Type: "string", Default: ""},
			"transfer_mode":              {Type: "string", Default: ""},
			"blksize":                    {Type: "uint16", Default: uint16(0), Min: 0, Max: 65464},
			"timeout":                    {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"client_tsize":               {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"server_tsize":               {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"server_tid":                 {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"error_code":                 {Type: "uint8", Default: uint8(0), Min: 0, Max: 255},
			"error_msg":                  {Type: "string", Default: ""},
			"error_after_block":          {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"error_side":                 {Type: "string", Default: ""},
			"blocks_count":               {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"auto_append_final_block":    {Type: "bool"},
			"final_block_zero":           {Type: "bool", Default: false},
			"wrap_block_number":          {Type: "bool", Default: false},
			"data_payload_pattern":       {Type: "string", Default: ""},
			"include_oack":               {Type: "bool", Default: false},
			"retransmit_blocks":          {Type: "list", Default: []interface{}{}},
			"server_tid_change":          {Type: "bool", Default: false},
			"server_tid_change_at_block": {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"server_tid_new":             {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"windowsize":                 {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
		},
	})
	// ---- P4a：enip（tcp 终结层，首个 tcp 载体协议。ENIP 命令即数据段
	// （无握手/终止），TCP 语义（握手/seq-ack/挥手）交给 tcp 层生成器。
	// D-ENIP-1（G-ENIP-3）：业务键住 enip 层 config（六键，与
	// parseENIPConfig/parseENIPCommands/parseENIPIOData 消费键同名）；顶层
	// `enip` 子映射由 CheckProtoFlat presence 判死，层链是唯一配置真相。
	// 命令内键名以 parseENIPCommands 消费的蛇形键为准（generateFromLayer
	// 复用同一解析器，零语义分叉）。端口契约 tcp.dst_port=44818（缺省补齐，
	// modbus :135-136 同款）。UDP I/O 帧与多单元展开不支持（生成器显式拒绝，
	// 不静默缩水）。
	r.Register(LayerSchema{Name: "enip", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "44818"},
		Fields: map[string]FieldSchema{
			"transport":     {Type: "string"}, // "tcp"/"udp"（udp 由生成器拒绝：链单载体）
			"scenario":      {Type: "string"}, // full/discovery_only/io_only/forward_open_only/custom
			"commands":      {Type: "list"},   // ENIPCommand 数组（parseENIPCommands 消费键）
			"io_data":       {Type: "object"}, // ENIPIOData（链上由生成器拒绝——UDP I/O 面）
			"session_count": {Type: "int"},    // >1 由生成器拒绝（多单元展开 = G-ENIP-1）
			"flow_count":    {Type: "int"},    // 同上
		},
	})
	// ---- P4a：a2a（tcp 终结层。HTTP/JSON-RPC over TCP——命令即数据段，
	// TCP 语义（握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器；配置
	// （tasks/auth/http/tcp...）繁多不落层 config（layers 数组条目零负载），
	// 经 spec.Payload（A2AConfig JSON）携带、FlowMeta.Payload 直传生成器。
	r.Register(LayerSchema{Name: "a2a", Category: CategoryTerminal,
		DependsOn: []string{"tcp"},
		Fields: map[string]FieldSchema{
			"baseUrl":       {Type: "string"},
			"agentCardPath": {Type: "string"},
			"discover":      {Type: "bool"},
			"agentCard":     {Type: "object"},
			"tasks":         {Type: "list", Required: true},
			"auth":          {Type: "object"},
			"http":          {Type: "object"},
			"tcp":           {Type: "object"},
			"flowControl":   {Type: "object"},
		},
	})
	// ---- P4a：dnp3（tcp 终结层。IEEE 1815-2012——scenario 展开为链路层
	// 帧序列，TCP 语义（握手/seq-ack/挥手）交给 tcp 层生成器；配置
	// （scenario/objects/link_fcb...）繁多不落层 config（layers 数组条目
	// 零负载），经 spec.DNP3 flat 键携带、FlowMeta 直传生成器。UDP 传输
	// 与 multi_outstation 多流展开不支持（生成器显式拒绝）。
	r.Register(LayerSchema{Name: "dnp3", Category: CategoryTerminal,
		DependsOn: []string{"tcp"},
		Fields: map[string]FieldSchema{
			"link_type":                 {Type: "string"},
			"transport":                 {Type: "string"},
			"src_addr":                  {Type: "uint16"},
			"dst_addr":                  {Type: "uint16"},
			"link_fcb":                  {Type: "uint8"},
			"link_fc":                   {Type: "uint8"},
			"app_seq":                   {Type: "uint8"},
			"app_func":                  {Type: "string"},
			"app_func_code":             {Type: "uint8"},
			"app_con":                   {Type: "uint8"},
			"objects":                   {Type: "list"},
			"scenario":                  {Type: "string"},
			"is_event":                  {Type: "bool"},
			"is_unsolicited":            {Type: "bool"},
			"confirm_required":          {Type: "bool"},
			"iin":                       {Type: "uint16"},
			"iin_class1":                {Type: "bool"},
			"iin_class2":                {Type: "bool"},
			"iin_class3":                {Type: "bool"},
			"iin_already_executing":     {Type: "bool"},
			"iin_event_buffer_overflow": {Type: "bool"},
			"iin_need_time":             {Type: "bool"},
			"iin_device_trouble":        {Type: "bool"},
			"iin_local_control":         {Type: "bool"},
			"iin_broadcast":             {Type: "bool"},
			"iin_device_restart":        {Type: "bool"},
			"iin_config_corrupt":        {Type: "bool"},
			"iin_object_unknown":        {Type: "bool"},
			"iin_parameter_error":       {Type: "bool"},
			"iin_func_not_supported":    {Type: "bool"},
			"multi_outstation":          {Type: "object"},
			"handshake":                 {Type: "bool"},
			"termination":               {Type: "bool"},
			"mss":                       {Type: "uint16"},
			"think_time":                {Type: "int"},
			"malformed_crc":             {Type: "bool"},
			"malformed_length":          {Type: "uint8"},
			"unknown_object":            {Type: "bool"},
			"unknown_func":              {Type: "bool"},
		},
	})
	// D-DOIP-1：doip（tcp 终结层；层十键——业务七键（契约 §15.3：
	// protocol_version/logical_address/tester_address/activation/messages/
	// alive_check/generic_nack）+ UDP 三键在册。三键必须可表达，否则负例
	// #20–#22 命中 `unknown field` 而非契约锚词「<key> … not supported」
	// （enip io_data/transport 先例：在册 = 走链级预检/生成器拒绝，锚词
	// 到位）。字节片（oem_specific/user_data）由扁平 getByteSlice/
	// getHexBytes 承接双语义（原文字节/hex/数字数组），JSON 往返会误读——
	// srv6 inner_payload/tftp data_payload_pattern 同陷阱，翻译侧复用扁平
	// parseDoIPConfig 单一真相。vin/eid/gid **不入册**：死配置（校验嵌在
	// 已删的 Discovery 块 doip.go:62-88，生成器 layer_gen.go 零读取），
	// 入册会造出「写了被静默忽略」面（契约 §1.12 不许登记保留）——未入册
	// 即 unknown field 响亮拒绝。端口契约 tcp.dst_port=13400（缺省补齐，
	// enip :44818 同款）。顶层 `doip` 子映射由 CheckProtoFlat presence
	// 判死，层链是唯一配置真相。
	r.Register(LayerSchema{Name: "doip", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		TransportOn:   []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "13400"},
		Fields: map[string]FieldSchema{
			"protocol_version": {Type: "uint8", Min: 0, Max: 255},
			"logical_address":  {Type: "uint16", Min: 0, Max: 65535},
			"tester_address":   {Type: "uint16", Min: 0, Max: 65535},
			"activation":       {Type: "object"},
			"messages":         {Type: "list"},
			"alive_check":      {Type: "object"},
			"generic_nack":     {Type: "object"},
			"discovery":        {Type: "object"},
			"entity_status":    {Type: "object"},
			"power_mode":       {Type: "object"},
		},
	})
	// ---- P4a：gbt32960（tcp 终结层。GB/T 32960.3-2016——车辆/平台状态机
	// 展开为逐消息事件（0x01 登入 → 0x0C 确认 → 0x02 上报 ×N → 0x04 登出，
	// 0x08 控制/0x03 补报 按序插入；平台侧 0x05/0x0B 心跳 ×N/0x06），wire
	// 字节由 buildMessage 纯函数产出），TCP 语义（握手/seq-ack/挥手）交给
	// tcp 层生成器。层 config 全量收 GBT32960Config 同名 28 键（数值键一律
	// 声明 int/uint8 不设界——serial/计数值域由 validator V7/V30/V35 执法，
	// 层 V9 不抢；bool 键不设 Default：缺省 nil 走生成器回退语义——
	// completedConfig 缺省注入会污染"缺省=省略"线形，mcp 同款教训）。
	// 嵌套对象/数组（alarm_data/remote_control/platform_login/reports/…）
	// V9 只验顶层键存在，值语义归翻译分支解析 + validator。
	r.Register(LayerSchema{Name: "gbt32960", Category: CategoryTerminal,
		DependsOn:   []string{"tcp"},
		TransportOn: []string{"tcp"},
		Fields: map[string]FieldSchema{
			"role":                            {Type: "string"},
			"vin":                             {Type: "string"},
			"vin_pad_byte":                    {Type: "uint8"},
			"sim":                             {Type: "string"},
			"encrypt_rule":                    {Type: "string"},
			"login_serial_number":             {Type: "int"},
			"logout_serial_number":            {Type: "int"},
			"rechargeable_subsys_count":       {Type: "int"},
			"rechargeable_subsys_code_length": {Type: "int"},
			"rechargeable_subsys_codes":       {Type: "list"},
			"login_time":                      {Type: "string"},
			"logout_time":                     {Type: "string"},
			"reports":                         {Type: "list"},
			"reissue_reports":                 {Type: "list"},
			"alarm_data":                      {Type: "object"},
			"remote_control":                  {Type: "object"},
			"platform_login":                  {Type: "object"},
			"platform_id":                     {Type: "string"},
			"platform_domain":                 {Type: "string"},
			"set_platform_domain":             {Type: "string"},
			"connect_id":                      {Type: "string"},
			"is_trans_battery_data":           {Type: "bool"},
			"heartbeat_count":                 {Type: "int"},
			"response_flags":                  {Type: "string"},
			"status_change_trace":             {Type: "list"},
			"custom_fields":                   {Type: "string"},
			"inject_bcc_error":                {Type: "bool"},
			"bcc_error_index":                 {Type: "int"},
		},
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
	// 纯函数产出），UDP 语义（数据报/checksum）交给 udp 层生成器；业务键
	// 住 rtmfp 层条目（D-RTMFP-1：层链唯一真相，translateTerminalConfig
	// 经 JSON 严格往返解码为 core.RTMFPConfig），FlowMeta 直传生成器；
	// 目的端口默认 1935。Fields 表为本层键名白名单（ValidateLayerConfig
	// 凭它放行 sessions[] 等嵌套值；值语义在 planner 校验器）。
	r.Register(LayerSchema{Name: "rtmfp", Category: CategoryTerminal,
		DependsOn:   []string{"udp"},
		TransportOn: []string{"udp"}, // RTMFP 仅 UDP 载体——transport-dup 检查据此报 carrier 锚词
		Fields: map[string]FieldSchema{
			"profile":            {Type: "string", Default: ""},
			"role":               {Type: "string", Default: ""},
			"keepalive_interval": {Type: "int", Default: 0, Min: 0, Max: 0},
			"ping_count":         {Type: "int", Default: 0, Min: 0, Max: 0},
			"wire_fault":         {Type: "object"},
			"sessions":           {Type: "list", Default: []interface{}{}},
		},
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
		Fields: map[string]FieldSchema{
			"version":             {Type: "uint8"},
			"role":                {Type: "string"},
			"local_tunnel_id":     {Type: "uint16"},
			"peer_tunnel_id":      {Type: "uint16"},
			"local_session_id":    {Type: "uint16"},
			"peer_session_id":     {Type: "uint16"},
			"local_session_id_32": {Type: "uint32"},
			"peer_session_id_32":  {Type: "uint32"},
			"host_name":           {Type: "string"},
			"vendor_name":         {Type: "string"},
			"firmware_rev":        {Type: "uint16"},
			"framing_caps":        {Type: "string"},
			"bearer_caps":         {Type: "string"},
			"receive_window_size": {Type: "uint16"},
			"initial_ns":          {Type: "uint16"},
			"tie_breaker":         {Type: "list"},
			"protocol_version":    {Type: "string"},
			"cookie":              {Type: "string"},
			"scenarios":           {Type: "list"},
			"hello_interval":      {Type: "int"},
			"ppp_frames":          {Type: "list"},
			"custom_avps":         {Type: "list"},
			"result_code":         {Type: "uint16"},
			"error_code":          {Type: "uint16"},
			"error_message":       {Type: "string"},
			"scenario":            {Type: "string"},
			"inner_ip":            {Type: "string"},
		},
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
		Fields: map[string]FieldSchema{
			"proto":                  {Type: "string"},
			"version":                {Type: "string"},
			"key_id":                 {Type: "uint8"},
			"session_id":             {Type: "uint64"},
			"tls_auth":               {Type: "bool"},
			"tls_crypt":              {Type: "bool"},
			"tls_crypt_v2":           {Type: "bool"},
			"data_cipher":            {Type: "string"},
			"ncp_disable":            {Type: "bool"},
			"tls_version":            {Type: "string"},
			"tls_role":               {Type: "string"},
			"sni":                    {Type: "string"},
			"mssfix":                 {Type: "uint16"},
			"tls_auth_hmac":          {Type: "list"},
			"tls_crypt_wrapped_key":  {Type: "list"},
			"data_payload":           {Type: "list"},
			"data_packet_count":      {Type: "int"},
			"perform_soft_reset":     {Type: "bool"},
			"static_key_mode":        {Type: "bool"},
			"key_direction":          {Type: "uint8"},
			"static_key":             {Type: "list"},
			"auth_user_pass":         {Type: "bool"},
			"auth_user":              {Type: "string"},
			"auth_pass":              {Type: "string"},
			"auth_alg":               {Type: "string"},
			"fragment_size":          {Type: "uint16"},
			"keepalive_ping":         {Type: "uint16"},
			"keepalive_ping_restart": {Type: "uint16"},
			"exit_notify_count":      {Type: "uint8"},
			"exit_notify_interval":   {Type: "uint16"},
			"tun_mtu":                {Type: "uint16"},
			"inner_ip_packets":       {Type: "list"},
		},
	})
	// ---- gtp（udp 终结层。GTP-U/GTP-C——UDP 承载的隧道协议，GTP header +
	// 内层 IP 包，wire 字节由 buildGTPMessage/buildInnerIPv4Packet 纯函数
	// 产出）。UDP 语义交给 udp 层生成器；配置经 spec.GTP flat 键携带、
	// FlowMeta 直传生成器（tftp 重放模式）；目的端口按 Mode 默认
	// （u=2152/c=2123，Plan 内 resolve，无固定 FieldContract）。
	r.Register(LayerSchema{Name: "gtp", Category: CategoryTerminal,
		DependsOn: []string{"udp"},
		Fields: map[string]FieldSchema{
			"mode":              {Type: "string"},
			"version":           {Type: "uint8"},
			"pt":                {Type: "uint8"},
			"teid":              {Type: "uint32"},
			"sequence_present":  {Type: "bool"},
			"npdu_present":      {Type: "bool"},
			"extension_present": {Type: "bool"},
			"extension_type":    {Type: "uint8"},
			"extension_data":    {Type: "list"},
			"sequence":          {Type: "uint16"},
			"npdu_value":        {Type: "uint8"},
			"inner_proto":       {Type: "string"},
			"inner_src_ip":      {Type: "string"},
			"inner_dst_ip":      {Type: "string"},
			"inner_ttl":         {Type: "uint8"},
			"inner_ipid":        {Type: "uint16"},
			"inner_payload":     {Type: "string"},
			"tcp_options":       {Type: "object"},
			"frames":            {Type: "list"},
			"scenarios":         {Type: "list"},
			"direction":         {Type: "string"},
		},
	})
	// ---- ike（udp 终结层。IKEv1/v2——UDP 承载的密钥交换协议：IKE 消息序列
	// + 可选 ESP 数据面，wire 字节由 buildIKEMessageBytes 纯函数产出）。UDP
	// 语义交给 udp 层生成器；配置经 spec.IKE flat 键携带、FlowMeta 直传
	// 生成器（tftp 重放模式）；目的端口默认 500（RFC 7296 §1.2）。
	r.Register(LayerSchema{Name: "ike", Category: CategoryTerminal,
		DependsOn:     []string{"udp"},
		FieldContract: map[string]string{"udp.dst_port": "500"}, // RFC 7296 默认 500；用户显式非标准端口须为 0/500（ike Validate 强制），不强制覆盖
		Fields: map[string]FieldSchema{
			"version_major":           {Type: "uint8"},
			"version_minor":           {Type: "uint8"},
			"role":                    {Type: "string"},
			"scenario":                {Type: "string"},
			"initiator_spi":           {Type: "list"},
			"responder_spi":           {Type: "list"},
			"messages":                {Type: "list"},
			"child_sas":               {Type: "list"},
			"default_auth_method":     {Type: "string"},
			"default_dh_group":        {Type: "uint16"},
			"default_nonce_size":      {Type: "int"},
			"default_proposal":        {Type: "object"},
			"dpd_count":               {Type: "int"},
			"eap_only":                {Type: "bool"},
			"encrypt_mode":            {Type: "string"},
			"fault_injection":         {Type: "object"},
			"fragmentation_supported": {Type: "bool"},
			"fragment_threshold":      {Type: "int"},
			"opaque_key_seed":         {Type: "string"},
			"retransmit_count":        {Type: "int"},
			"start_message_id":        {Type: "uint32"},
			"strict":                  {Type: "bool"},
			"allow_null_auth":         {Type: "bool"},
		},
	})
	// ---- ike_nat_t（udp 终结层。IKEv2 NAT-T——端口浮动 + Non-ESP Marker 的
	// NAT 穿透变体，wire 字节由 buildIKENATTMessage 纯函数产出）。UDP 语义
	// 交给 udp 层生成器；配置经 spec.IKENATT flat 键携带、FlowMeta 直传
	// 生成器（tftp 重放模式）；目的端口默认 4500（RFC 3948 NATTPort）。
	r.Register(LayerSchema{Name: "ike_nat_t", Category: CategoryTerminal,
		DependsOn:     []string{"udp"},
		FieldContract: map[string]string{"udp.dst_port": "4500"}, // RFC 3948 默认 4500；用户显式非标准端口优先，不强制
		Fields: map[string]FieldSchema{
			"dialog":                 {Type: "list"},
			"count":                  {Type: "int"},
			"direction":              {Type: "string"},
			"initiator_spi":          {Type: "list"},
			"responder_spi":          {Type: "list"},
			"keepalive":              {Type: "bool"},
			"interval":               {Type: "int"},
			"timeout":                {Type: "int"},
			"backoff":                {Type: "int"},
			"max_retransmits":        {Type: "int"},
			"retransmit":             {Type: "bool"},
			"nat_detected_on_source": {Type: "bool"},
			"nat_detected_on_dest":   {Type: "bool"},
			"nat_detection":          {Type: "string"},
			"port_float":             {Type: "bool"},
			"udp_encap_esp":          {Type: "object"},
			"child_sa":               {Type: "object"},
		},
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
	// D-HDS-1（G-HDS-1）：配置迁 hds 层（顶层 "hds" 子映射 presence 判死，
	// CheckProtoFlat 同款文案）。业务键=HDSConfig 顶层同名（profile/
	// keep_alive/manifest/sessions，wire_fault 负例注入口未消费 G-HDS-2）；
	// V9 只验顶层键存在，嵌套值语义归 translate JSON 往返 + validator
	// （cwmp 同款）；80 端口经 FieldContract 供通用应用补齐。
	r.Register(LayerSchema{Name: "hds", Category: CategoryTerminal,
		DependsOn: []string{"http"},
		Fields: map[string]FieldSchema{
			"profile":    {Type: "string", Default: "hds_http1"},
			"keep_alive": {Type: "bool", Default: false},
			"manifest":   {Type: "object"},
			"sessions":   {Type: "list", Default: []interface{}{}},
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
		Fields: map[string]FieldSchema{
			"concurrent": {Type: "bool"},
			"sessions":   {Type: "list"},
			"wire_fault": {Type: "object"},
		},
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
	// 形态），[tcp→stratum] 直连（ip 层由依赖补全自动插入）。配置住 stratum
	// 层条目（顶层 "stratum" 子映射由 CheckProtoFlat presence 判死，D-STRATUM-1
	// G-ST-4）；3333 端口经 FieldContract 供通用应用补齐。无 stratum
	// dissector，断言全走 tcp.payload/frames（设计 §2 实测基线）。
	r.Register(LayerSchema{Name: "stratum", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "3333"},
		// Fields = 层 config 键白名单（ValidateLayerConfig V9 拒绝未知键）。
		// 五键与 core.StratumConfig 的 json tag 一一对应：嵌套值语义（事件
		// 级 27+ 键）归 translate 的严格 JSON 往返 + planner 校验，V9 只看
		// 顶层键是否存在（xmrmining/bgp 同款）。sessions Default 保持
		// []interface{}{}（空层 {} 与显式 sessions:[] 同落生成器缺省基线流）。
		Fields: map[string]FieldSchema{
			"profile":    {Type: "string", Default: ""},  // 信息性（stratum_v1 / stratum_ipv6_v1 / stratum_bip310_ext）
			"concurrent": {Type: "bool", Default: false}, // 多会话交错回放（tcp 层须同时 concurrent:true）
			"extensions": {Type: "list", Default: []interface{}{}},
			"sessions":   {Type: "list", Default: []interface{}{}},
			"wire_fault": {Type: "string", Default: ""}, // 11 值枚举（设计 §7）；""=无故障
		}})
	// ethmining（以太坊挖矿 stratum 协议，EthereumStratum/1.0.0）：终结层
	// 事件为行式 JSON（LF 边界、紧凑形态），[tcp→ethmining] 直连（ip 层由依
	// 赖补全自动插入）。配置住 ethmining 层四键（D-ETHMINING-1 P4：events
	// 面进层，顶层 "ethmining" 子映射由 CheckProtoFlat 判死）；4444 端口经
	// FieldContract 供通用应用补齐（非默认端口 3353 由用户显式覆盖，正例
	// 22）。无 ethmining dissector，断言全走 tcp.payload/frames（设计 §2
	// 实测基线）。
	//
	// sessions/wire_fault 缺省 nil（非 []interface{}{}）：completedConfig 对
	// nil Default 不落键，"缺键"（→ ETHMiningConfig.Sessions nil → 生成器
	// P0b 缺省基线会话）与"显式 sessions: []"（→ 空切片 → 生成器同走缺省）
	// 二态语义由层生成器自身判定（bgp :1225 同款理由）。
	r.Register(LayerSchema{Name: "ethmining", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "4444"},
		Fields: map[string]FieldSchema{
			"profile":    {Type: "string", Default: ""}, // ethmining_stratum_v1（缺省）/ethmining_ipv6_v1/ethmining_hex_prefix_v1（信息性）
			"hex_prefix": {Type: "string", Default: ""}, // ""（spec 缺省无前缀）/ "0x"（方言变体；其余值 validator 拒）
			"sessions":   {Type: "list"},
			"wire_fault": {Type: "string", Default: ""}, // 10 值枚举（设计 §7 表）；""=无故障
		},
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
		Fields: map[string]FieldSchema{
			"concurrent":  {Type: "bool"},
			"sessions":    {Type: "list"},
			"pack":        {Type: "list"},
			"wire_fault":  {Type: "string"},
			"termination": {Type: "string"},
		},
	})
	// getwork（Bitcoin legacy getwork JSON-RPC over HTTP）：终结层事件已含
	// 完整 HTTP 帧（请求/响应钉死头序），http 层以透传变换器转发（identity
	// transformer）。全部协议配置经 spec.GetWork（顶层 "getwork" 子映射）注入，
	// 层 config 恒空；8332 端口经 FieldContract 供通用应用补齐。
	r.Register(LayerSchema{Name: "getwork", Category: CategoryTerminal,
		DependsOn:     []string{"http"},
		FieldContract: map[string]string{"tcp.dst_port": "8332"},
		Fields: map[string]FieldSchema{
			"concurrent": {Type: "bool"},
			"sessions":   {Type: "list"},
			"wire_fault": {Type: "object"},
		},
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
		Fields: map[string]FieldSchema{
			"profile":    {Type: "string"},
			"method":     {Type: "string"},
			"uri":        {Type: "string"},
			"concurrent": {Type: "bool"},
			"sessions":   {Type: "list"},
			"wire_fault": {Type: "string"},
		},
	})
	// onvif（ONVIF Core Spec Ver. 26.06，67-onvif v2.1.1）：终结层事件已含
	// 完整 HTTP 帧（SOAP 1.2 POST + 2xx/4xx/5xx 响应），http 层以透传变换
	// 器转发。全部协议配置经 spec.ONVIF（顶层 "onvif" 子映射）注入，层 config
	// 恒空；目的端口 80 由 FieldContract 补齐（非默认端口由用户显式覆盖）。
	r.Register(LayerSchema{Name: "onvif", Category: CategoryTerminal,
		DependsOn:     []string{"http"},
		FieldContract: map[string]string{"tcp.dst_port": "80"},
		Fields: map[string]FieldSchema{
			"profile":      {Type: "string"},
			"soap_version": {Type: "string"},
			"charset":      {Type: "string"},
			"content_type": {Type: "string"},
			"concurrent":   {Type: "bool"},
			"sessions":     {Type: "list"},
			"wire_fault":   {Type: "string"},
		},
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
	r.Register(LayerSchema{Name: "moxa", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		// D-MOXA-1 G-MOXA-1：moxa 层两键（契约 §12.1 旧键去向表——顶层 moxa
		// 子映射迁 layers[i].moxa）。stream 是块剧本（[]MOXAStreamBlock，
		// 元素 direction/payload/payload_b64）；sessions 是结构选择器
		// （>1 由 planner/生成器双拒，V9 Min/Max 双 0 = 无界跳过 → 锚词
		// 归 validator）。
		// Default nil（NOT []interface{}{}）：completedConfig 对 nil Default
		// 不落键——"stream 缺键"（→ 默认单块 "hello"）与"显式 stream: []"
		// （→ 空 stream 拒绝）二态必须可分（bgp events 同款）。
		// sessions 同列：nil Default 使"空层 config"（completedConfig 后
		// len==0）与"写了 sessions"可分——前者走 P0b-2 默认流（translate
		// 留 spec.MOXA nil），后者必须到 validator（N-3 锚词）。
		Fields: map[string]FieldSchema{
			"stream":   {Type: "list"},
			"sessions": {Type: "int", Min: 0, Max: 0},
		}})
	r.Register(LayerSchema{Name: "someip", Category: CategoryTerminal, DependsOn: []string{"udp"}, TransportOn: []string{"udp", "tcp"}})
	r.Register(LayerSchema{Name: "drda", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "446"},
		Fields: map[string]FieldSchema{
			"transport":        {Type: "string", Default: ""},
			"association":      {Type: "string", Default: ""},
			"ccsid":            {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"correlator_start": {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"correlator_inc":   {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
			"security_user":    {Type: "string", Default: ""},
			"security_token":   {Type: "list", Default: []interface{}{}},
			"rdb_name":         {Type: "string", Default: ""},
			"sql":              {Type: "object"},
			"dss_segments":     {Type: "list", Default: []interface{}{}},
			"dss_length":       {Type: "int", Default: 0},
			"sessions":         {Type: "list", Default: []interface{}{}},
		}})
	r.Register(LayerSchema{Name: "thrift", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "9090"},
		Fields: map[string]FieldSchema{
			"transport": {Type: "string", Default: ""},
			"messages":  {Type: "list", Default: []interface{}{}},
		}})
	r.Register(LayerSchema{Name: "tns", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "1521"},
		// D-TNS-1 G-TNS-1：tns 层四键（设计 §2.1/§2.2）——events（事件序列）/
		// sessions（多会话 `{src_port, events[]}`）/ checksum_mode（v1 只认
		// ""/disabled）/ wire_fault（负例注入口，非线上字段）。events/sessions
		// 数组缺省 nil（NOT []interface{}{}）：completedConfig 对 nil Default
		// 不落键，"events 缺键"（→ TNSConfig.Events nil）与"显式 events: []"
		// （→ 空切片 → validator 报 at least one event）才可区分（bgp :1225
		// 同款理由）。checksum_mode 缺省 ""（validator 接受 ""/"disabled"）；
		// wire_fault 缺省 nil（dameng 同款：注入 "" 会被误读为故障）。
		// reconnect 死字段（G-TNS-11）不注册——层内写它由 V9 unknown field
		// 判死，顶层旧键由 CheckProtoFlat 判死。
		Fields: map[string]FieldSchema{
			"events":        {Type: "list"},
			"sessions":      {Type: "list"},
			"checksum_mode": {Type: "string", Default: ""},
			"wire_fault":    {Type: "object"},
		}})
	// D-MONGODB-1（#87）：mongodb 层三键 = MongoDBConfig 顶层同名（messages/
	// sessions/wire_fault 业务键）。V9 只验顶层键存在，嵌套值语义归
	// translateTerminalConfig JSON 往返 + validator（dameng/bgp 同款）。
	// 层级 bson_fixture_hex 死字段（G-MONGO-8 D2）已删——生成器零读取
	// （被消费的是**消息级**同名键，builder.go buildInsertBody），留着等于
	// "配上不生效"；删后层内再写该键由 V9 报 unknown field。
	// FieldContract tcp.dst_port=27017（validateSpecBase DstPort switch 承接；
	// 设计 §2.1 无强制等于校验——显式非 27017 被尊重）。
	r.Register(LayerSchema{Name: "mongodb", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "27017"},
		Fields: map[string]FieldSchema{
			"messages":   {Type: "list", Default: []interface{}{}},
			"sessions":   {Type: "list", Default: []interface{}{}},
			"wire_fault": {Type: "object"},
		}})
	r.Register(LayerSchema{Name: "dameng", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		// D-DAMENG-1：TCP-only 终结层（DM8 经 TCP 5236；链夹 udp 判死走
		// complete.go 通用 tcp-only 逻辑 `rides tcp only (carrier)`——
		// DependsOn=[tcp] 且无 udp ⟹ tcpOnly 自动成立）。
		TransportOn:   []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "5236"},
		Fields: map[string]FieldSchema{
			// D-DAMENG-1 G-DM-2：dameng 层五键（§2.1/§2.2 层内配置键）。
			// wire_profile/wire_fault 字符串走 completedConfig 缺省回填；
			// events/sessions 数组缺省 []interface{}{}（postgresql 同款）；
			// payload_size 缺省 ""（validator 仅接受 profile_minimum_nonempty）。
			"wire_profile": {Type: "string", Default: ""},
			"events":       {Type: "list", Default: []interface{}{}},
			"sessions":     {Type: "list", Default: []interface{}{}},
			"payload_size": {Type: "string", Default: ""},
			// wire_fault 否定测试故障对象 {"kind":..., "value":...}——
			// Default nil（NOT "") so completedConfig omits it: an injected
			// "" would survive the JSON round-trip as WireFault='""' and be
			// mis-read as a fault (postgresql 同款理由)。
			"wire_fault": {Type: "object"},
		}})
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
	r.Register(LayerSchema{Name: "kerberos", Category: CategoryTerminal,
		DependsOn:   []string{"udp"},
		TransportOn: []string{"udp", "tcp"}, // 双载体：udp 一数据报一消息 / tcp 4B BE record 长度分帧（RFC 4120 §6，裁定1/7）——transport-dup 检查据此放行单载体、拒双载体并存
		// D-KERBEROS-1：KDC 惯用端口 88 双载体同契约（tshark kerberos
		// dissector 自动解码依赖）。
		FieldContract: map[string]string{"udp.dst_port": "88", "tcp.dst_port": "88"},
		Fields: map[string]FieldSchema{
			"sessions":   {Type: "list", Default: []interface{}{}},
			"wire_fault": {Type: "string", Default: ""}, // 6 值枚举（D-KERBEROS-1 §10 表）；""=无故障
		},
	})
	// ntlm（MS-NLMP NTLMv2 三消息）：裁定 N1——`DependsOn ["tcp"]`（唯一载体；
	// tcp 层管握手/seq-ack/挥手/MSS 分段，NTLMSSP 消息可跨 segment）+
	// `OptionalOn ["http"]`（显式写 [ip,tcp,http,ntlm] 才启用可选底座；框架
	// 0c355be 把 OptionalOn 计入终结层底座豁免）+ `TransportOn ["tcp"]`（NTLM
	// 无 UDP 语义，udp 零值）。两 profile 均由 ntlm 层自封帧（smb2：SMB2
	// SESSION_SETUP SecurityBuffer；http-negotiate：HTTP 401/Negotiate 头），
	// http 底座仅作透传（http 层 isHTTPRPCInner 含 NTLM）。
	// 无 FieldContract：目的端口按 profile 两档（smb2→445 / http-negotiate→80），
	// 常量形对双端口 profile 不适用（smb 无 FieldContract 先例）——端口缺省
	// 走 chain_planner/strategy_convert 的 profile 分支。
	r.Register(LayerSchema{Name: "ntlm", Category: CategoryTerminal,
		DependsOn:   []string{"tcp"},
		OptionalOn:  []string{"http"},
		TransportOn: []string{"tcp"},
		Fields: map[string]FieldSchema{
			"profile":                      {Type: "string", Default: ""}, // smb2（缺省档）/ http-negotiate
			"version":                      {Type: "string", Default: ""}, // ntlmv2（正例唯一档）
			"outer":                        {Type: "string", Default: ""}, // none（缺省）/ spnego
			"flags":                        {Type: "object"},
			"target_info":                  {Type: "object"},
			"ntlmv2_response":              {Type: "object"},
			"mic":                          {Type: "bool", Default: false},
			"encrypted_random_session_key": {Type: "int", Default: 0, Min: 0, Max: 65535},
			"sessions":                     {Type: "list", Default: []interface{}{}},
			"wire_fault":                   {Type: "string", Default: ""}, // 6 值枚举（D-NTLM-1 §2/§10 表）；""=无故障
		},
	})
	r.Register(LayerSchema{Name: "sstp", Category: CategoryTerminal,
		DependsOn: []string{"tls"}, // HTTPS 载体：缺 tls 层自动补全（[ip,tcp,sstp] → [ip,tcp,tls,sstp]）；validate_layers 预检在补全前拦裸 TCP/UDP 形
		// D-SSTP-1：HTTPS 载体端口 443 同 tls 层 FieldContract 值（tshark
		// tls dissector 自动解码依赖）；SSTP 不另用 UDP 端口（契约 §2/§5）。
		FieldContract: map[string]string{"tcp.dst_port": "443"},
		Fields: map[string]FieldSchema{
			// version 无 schema 默认（指针三态：缺席 = 0x10；显式 0/他值拒）。
			"version": {Type: "int"},
			// events[] 单连接短形 / sessions[] 多连接形（sessions 优先；
			// 二者并存且都非空 = 双权威拒）。值语义归 planner + 生成器
			//（V9 只验层键形状，嵌套值走严格解码——dtls/kerberos 同款）。
			"events":     {Type: "list", Default: []interface{}{}},
			"sessions":   {Type: "list", Default: []interface{}{}},
			"wire_fault": {Type: "string", Default: ""}, // 6 值枚举（契约 §2/§11）；""=无故障
		},
	})
	// D-OCSP-1：ocsp 终结层双 profile（62-ocsp §11.4 裁定1——A 方案）：
	// DependsOn ["tcp"]（裸 TCP 默认可达）+ OptionalOn ["http"]（0c355be 联
	// 动：dependedOn 含 OptionalOn，"[ip,tcp,http,ocsp]" 与 "[ip,tcp,ocsp]"
	// 双链可达——http 层用户显式写才启用）+ TransportOn ["tcp"]（L4 纯度）。
	// FieldContract tcp.dst_port=80（tshark 自动解码依赖；裸 TCP 8080
	// fixture 显式写端口）。
	r.Register(LayerSchema{Name: "ocsp", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		OptionalOn:    []string{"http"}, // HTTP profile 用户显式写 http 层启用
		TransportOn:   []string{"tcp"},  // L4 载体（http 是变换层，非载体）
		FieldContract: map[string]string{"tcp.dst_port": "80"},
		Fields: map[string]FieldSchema{
			"profile":             {Type: "string", Default: ""}, // http-post/http-get/tcp；"" = 有 http 层→http-post，否则 tcp
			"hash_algorithm":      {Type: "string", Default: ""}, // sha1（缺省）/sha256
			"request_count":       {Type: "int", Default: 0, Min: 0, Max: 256},
			"nonce":               {Type: "map", Default: map[string]interface{}{}},
			"cert_status":         {Type: "string", Default: ""}, // good（缺省）/revoked/unknown
			"signed_request":      {Type: "bool", Default: false},
			"signature_algorithm": {Type: "string", Default: ""},
			"version":             {Type: "int", Default: 0},
			"certs":               {Type: "bool", Default: false},
			"response_extensions": {Type: "bool", Default: false},
			"single_extensions":   {Type: "bool", Default: false},
			"responder_id":        {Type: "string", Default: ""}, // bykey（缺省）/byname
			"produced_at":         {Type: "string", Default: ""},
			"this_update":         {Type: "string", Default: ""},
			"next_update":         {Type: "string", Default: ""},
			"sessions":            {Type: "list", Default: []interface{}{}},
			"wire_fault":          {Type: "string", Default: ""}, // 6 值枚举（62-ocsp §2 表）；""=无故障
		},
	})
	// spnego（RFC 4178 GSS-API 协商，D-SPNEGO-1 裁定1）：`DependsOn ["tcp"]`
	// （唯一载体；tcp 层管握手/seq-ack/挥手/MSS 分段，DER token 可跨
	// segment）+ `OptionalOn ["http"]`（显式写 [ip,tcp,http,spnego] 才启
	// 用可选底座；框架 0c355be 把 OptionalOn 计入终结层底座豁免；ntlm
	// 同构）+ `TransportOn ["tcp"]`（SPNEGO 无 UDP 语义，udp 零值——
	// kerberos 双载体的区别点）。FieldContract `tcp.dst_port`=445（裸
	// TCP 档缺省；HTTP 档 80 由 http 层 FieldContract 供给；fixture 显式
	// 写端口时均不生效——门1 §13）。
	// http 底座仅作透传（http 层 isHTTPRPCInner 含 SPNEGO）。
	r.Register(LayerSchema{Name: "spnego", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		OptionalOn:    []string{"http"},
		TransportOn:   []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "445"},
		Fields: map[string]FieldSchema{
			"profile":        {Type: "string", Default: ""}, // tcp（缺省档）/ http
			"negotiation":    {Type: "string", Default: ""}, // init_resp（缺省）/ init_targ
			"mech_types":     {Type: "list", Default: []interface{}{}},
			"supported_mech": {Type: "string", Default: ""},
			"neg_result":     {Type: "int", Default: 0}, // 0..3（RFC 4178 §4.2.2）；targ 档 0..2 由 validator 按 negotiation 档校验（层 schema 不按档分支）
			"req_flags":      {Type: "int", Default: 0}, // ContextFlags 32-bit 位掩码（RFC 4178 §4.2.1 bit0..bit6； §12 只作结构覆盖面，不建行为面）
			"neg_hints":      {Type: "object"},
			"mech_token":     {Type: "object"},
			"response_token": {Type: "object"},
			"mech_list_mic":  {Type: "object"},
			"sessions":       {Type: "list", Default: []interface{}{}},
			"wire_fault":     {Type: "string", Default: ""}, // 6 值枚举（D-SPNEGO-1 §2/§12 表）；""=无故障
		},
	})
	r.Register(LayerSchema{Name: "cql", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "9042"},
		Fields: map[string]FieldSchema{
			"wire_profile": {Type: "string", Default: ""},
			"events":       {Type: "list", Default: []interface{}{}},
			"sessions":     {Type: "list", Default: []interface{}{}},
			// wire_fault is a negative-test fault object {"kind":...,"value":...}.
			// Default nil (NOT "") so completedConfig omits it: an injected ""
			// would survive the JSON round-trip as WireFault='""' and be
			// mis-read as a fault by the validator (postgresql 同款).
			"wire_fault": {Type: "object"},
		},
	})
	// D-IEC104-1 P4（G-IEC104-2 幽灵键裁决）：role/startdt/stopdt 在
	// builder/planner/layer_gen 三处零消费（design §8 幽灵键表实测），
	// G-IEC104-2 裁定=删除，不接线；`repeat` 同为零消费（负例探针形锚词
	// 实际来自 max_apdu_length 守卫），删除。`transport` 保留（planner.go:19
	// 载体守卫有消费，单测 iec104_test.go:172 已覆）；value 保留（I 帧
	// NVA/DCO/SCO 体有消费，builder.go:64/74/84）。
	r.Register(LayerSchema{Name: "iec104", Category: CategoryTerminal, DependsOn: []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "2404"},
		Fields: map[string]FieldSchema{
			"transport":       {Type: "string", Default: ""},
			"common_address":  {Type: "uint16", Default: uint16(0), Min: 0, Max: 65535},
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
	//
	// D-IGMP-1：igmp 层 15 业务键对齐 core.IGMPConfig json 标签（routing.go
	// 12-28；键名=标签名）。无 Default（决策 F；缺省语义在生成器侧——空配置
	// → v1 general query，layer_gen.go:60-63），V9 数值域只做类型界（s_flag/
	// qrv/qqic 的位域语义与 profile/kind 互斥留 planner.go:103-129）；records/
	// sources/events 为结构数组，元素级校验归 Planner.Validate（§10 锚词表）；
	// wire_fault 为故障注入块（protocol/checksum 两 kind 在 planner.go:56-63
	// 拒，record/source_count 经记录/源数校验拒；块内未知键不进执法面）。
	r.Register(LayerSchema{Name: "igmp", Category: CategoryTerminal, DependsOn: []string{"ip"},
		FieldContract: map[string]string{"ip.protocol": "2"}, // RFC 1112/2236/3376 IGMP IPPROTO=2
		Fields: map[string]FieldSchema{
			"profile":           {Type: "string"},
			"kind":              {Type: "string"},
			"group":             {Type: "string"},
			"max_response_time": {Type: "uint8", Min: 0, Max: 255},
			"max_response_code": {Type: "uint8", Min: 0, Max: 255},
			"s_flag":            {Type: "uint8", Min: 0, Max: 255},
			"qrv":               {Type: "uint8", Min: 0, Max: 255},
			"qqic":              {Type: "uint8", Min: 0, Max: 255},
			"records":           {Type: "list"},
			"sources":           {Type: "list"},
			"source_count":      {Type: "uint16", Min: 0, Max: 65535},
			"checksum_mode":     {Type: "string"},
			"wire_fault":        {Type: "object"},
			"address_family":    {Type: "string"},
			"events":            {Type: "list"},
		},
	})
	// D-OSPF-1：ospf 层 23 业务键对齐 core.OSPFConfig json 标签（routing.go
	// :66-90；键名=标签名）。无 Default（决策 F；缺省语义在生成器侧——空层
	// config 不落 spec.OSPF，生成器 P0b-2 缺省 hello，layer_gen.go:27）；V9
	// 数值域只做类型界（version=3 / packet_type=unknown 等语义拒留
	// planner.go:24/:54，锚词 version/type）；events/neighbors/requests/lsas/
	// lsa_headers 为结构数组，元素级校验归 Planner.Validate（§6 锚词表）；
	// wire_fault 为故障注入块（carrier/declared_length/area_id 三 kind 在
	// planner.go:41/:73/:66 拒；块内未知键不进执法面）；flags 为 DBD 三标志
	// 对象（OSPFDDFlags）。
	r.Register(LayerSchema{Name: "ospf", Category: CategoryTerminal, DependsOn: []string{"ip"},
		FieldContract: map[string]string{"ip.protocol": "89"}, // RFC 2328 OSPF IPPROTO=89
		Fields: map[string]FieldSchema{
			"version":                  {Type: "uint8", Min: 0, Max: 255},
			"packet_type":              {Type: "string"},
			"router_id":                {Type: "string"},
			"area_id":                  {Type: "string"},
			"profile":                  {Type: "string"},
			"auth_type":                {Type: "uint16", Min: 0, Max: 65535},
			"checksum_mode":            {Type: "string"},
			"network_mask":             {Type: "string"},
			"hello_interval":           {Type: "uint16", Min: 0, Max: 65535},
			"dead_interval":            {Type: "uint32", Min: 0, Max: 4294967295},
			"options":                  {Type: "uint8", Min: 0, Max: 255},
			"priority":                 {Type: "uint8", Min: 0, Max: 255},
			"designated_router":        {Type: "string"},
			"backup_designated_router": {Type: "string"},
			"neighbors":                {Type: "list"},
			"interface_mtu":            {Type: "uint16", Min: 0, Max: 65535},
			"flags":                    {Type: "object"},
			"dd_sequence":              {Type: "uint32", Min: 0, Max: 4294967295},
			"lsa_headers":              {Type: "list"},
			"requests":                 {Type: "list"},
			"lsas":                     {Type: "list"},
			"events":                   {Type: "list"},
			"wire_fault":               {Type: "object"},
		},
	})
	// D-PIM-1 G-PIM-1：pim 层 4 业务键 = core.PIMConfig json 标签（routing.go
	// :174-179；键名=标签名），无 Default（缺省语义在生成器侧——空层
	// {} 翻译出零配置，生成器无 events 拒 "pim: no events configured"，
	// §5.5 Honest 注：pim 无空配置默认流）。wire_fault 为顶层故障注入块
	// （planner.go:39 拒 checksum/length/type/address 四值）；events 为结构
	// 数组，元素级校验归 Planner.Validate（§7 锚词表）。此前空字段表使层内
	// 业务键 V9 判 unknown field（P4 阻塞项）。
	r.Register(LayerSchema{Name: "pim", Category: CategoryTerminal, DependsOn: []string{"ip"},
		FieldContract: map[string]string{"ip.protocol": "103"}, // RFC 7761 PIM IPPROTO=103
		Fields: map[string]FieldSchema{
			"profile":       {Type: "string"},
			"checksum_mode": {Type: "string"},
			"events":        {Type: "list"},
			"wire_fault":    {Type: "object"},
		},
	})
	// D-ISIS-1：isis L2-only 终结层（[eth,isis]，LLC/EtherType 双载体，ISO
	// 10589）。业务键登记为 22 键（= core.ISISConfig json 标签全量，routing.go
	// :271-294 实测；键名=标签名，layer config → JSON 往返解码单一真相）；
	// 嵌套 tlvs/events 为结构数组（元素级语义由 Planner.Validate 拒，V9 只做
	// 结构放行），llc/wire_fault 为 object。全部无 Default（goose/arp 同款——
	// 缺省语义在生成器/planner 侧：level→l1、pdu_type→lan_hello、
	// wire_profile→iso10589_llc）。无 FieldContract（无端口/IP 载体）。
	r.Register(LayerSchema{Name: "isis", Category: CategoryTerminal, DependsOn: []string{"eth"},
		Fields: map[string]FieldSchema{
			"wire_profile":       {Type: "string"},
			"level":              {Type: "string"},
			"pdu_type":           {Type: "string"},
			"system_id":          {Type: "string"},
			"holding_timer":      {Type: "int", Min: 0, Max: 65535},
			"priority":           {Type: "int", Min: 0, Max: 255},
			"lan_id":             {Type: "string"},
			"tlvs":               {Type: "list"},
			"lsp_id":             {Type: "string"},
			"remaining_lifetime": {Type: "int", Min: 0, Max: 65535},
			"sequence":           {Type: "int", Min: 0, Max: 4294967295},
			"partition":          {Type: "int", Min: 0, Max: 1},
			"circuit_type":       {Type: "int", Min: 0, Max: 3},
			"checksum_mode":      {Type: "string"},
			"address_profile":    {Type: "string"},
			"area_addresses":     {Type: "list"},
			"start_lsp_id":       {Type: "string"},
			"end_lsp_id":         {Type: "string"},
			"events":             {Type: "list"},
			"checksum":           {Type: "int", Min: 0, Max: 65535},
			"llc":                {Type: "object"},
			"wire_fault":         {Type: "object"},
		},
	})
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
			// D-BGP-1 G-BGP-5：事件面进层（postgresql 同款——V9 只验顶层键
			// 存在，嵌套值语义归 translate JSON 往返 + validator）。Default
			// 保持 nil（NOT []interface{}{}）：completedConfig 对 nil Default
			// 不落键，"events 缺键"（→ BGPConfig.Events nil → 默认 6 事件流，
			// layer_gen.go:52-57）与"显式 events: []"（→ 空切片 → connect-only）
			// 才可区分（postgresql wire_fault 同款理由）。
			"events":   {Type: "list"},
			"sessions": {Type: "list"},
		}})
	// ---- B3：ldp（双载体终结层。RFC 5036——UDP/646 discovery Hello 与
	// TCP/646 session（Initialization/KeepAlive/Address/Label*/Notification）
	// 逐事件产出，wire 字节由 build* 纯函数产出），默认 udp，用户显式写
	// tcp 层覆盖（补全时替代）；配置经 spec.LDP flat 键携带、FlowMeta 直传
	// 生成器；目的端口默认 646。
	r.Register(LayerSchema{Name: "ldp", Category: CategoryTerminal,
		DependsOn:   []string{"udp"},
		TransportOn: []string{"udp", "tcp"},
		Fields: map[string]FieldSchema{
			"transport":           {Type: "string"},
			"wire_profile":        {Type: "string"},
			"carrier":             {Type: "string"},
			"events":              {Type: "list"},
			"sessions":            {Type: "list"},
			"adjacencies":         {Type: "list"},
			"lsr_id":              {Type: "string"},
			"label_space":         {Type: "uint16"},
			"hold_time":           {Type: "uint16"},
			"targeted":            {Type: "bool"},
			"keepalive_time":      {Type: "uint16"},
			"label_control":       {Type: "string"},
			"label_advertisement": {Type: "string"},
			"fault_kind":          {Type: "string"},
		},
	})
	// ---- B3：pcep（tcp 终结层。RFC 5440——Open/Keepalive/PCReq/PCRep/
	// PCNtf/PCErr 逐报文事件，wire 字节由 build* 纯函数产出），TCP 语义
	// （握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器；配置经 spec.PCEP
	// flat 键携带、FlowMeta 直传生成器；目的端口默认 4189。
	r.Register(LayerSchema{Name: "pcep", Category: CategoryTerminal, DependsOn: []string{"tcp"}})
	// ---- B3：cflow（udp 终结层。RFC 3954 NetFlow v9 与 RFC 7011 IPFIX——
	// Export Packet/Message 含 header、Template/Data/Options Set、IPv4/IPv6
	// flow record 与 enterprise IE，wire 字节由 build* 纯函数产出），UDP
	// 语义（数据报/checksum）交给 udp 层生成器；配置住 cflow 层 15 键
	// （D-CFLOW-1 P4：层条目经 JSON 往返严格解码为 core.CFlowConfig，
	// 未知键在翻译期拒；嵌套 templates/records/exporters/sessions/options/
	// sets/wire_fault 为结构化对象/数组，无 strategy 键不走动态门）；
	// 目的端口默认 2055（v9）/4739（IPFIX）。
	r.Register(LayerSchema{Name: "cflow", Category: CategoryTerminal,
		DependsOn:   []string{"udp"},
		TransportOn: []string{"udp"}, // cflow 仅 UDP 载体（RFC 3954/7011 数据报）——transport-dup 检查据此报 carrier 锚词（bacnet/dtls 先例，G-CFLOW-4）
		Fields: map[string]FieldSchema{
			"profile":               {Type: "string"},
			"version":               {Type: "uint16"},
			"source_id":             {Type: "uint32"},
			"sequence":              {Type: "uint32"},
			"sys_uptime":            {Type: "uint32"},
			"observation_domain_id": {Type: "uint32"},
			"export_time":           {Type: "uint32"},
			"unix_secs":             {Type: "uint32"},
			"templates":             {Type: "list"},
			"records":               {Type: "list"},
			"sets":                  {Type: "list"},
			"options":               {Type: "object"},
			"exporters":             {Type: "list"},
			"sessions":              {Type: "list"},
			"wire_fault":            {Type: "object"},
		}})
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
			"previous_session_id":               {Type: "string"},
			"client_guid":                       {Type: "string"},
			"server_guid":                       {Type: "string"},
			"file_id":                           {Type: "string"},
			"error_response_status":             {Type: "uint32", Default: uint32(0), Min: 0, Max: 4294967295},
			"error_on_command":                  {Type: "string", Default: ""},
		}})
	// ---- P4a：tds（tcp 终结层。MS-TDS——PRELOGIN → Login7 → Login response
	// → sessions（SQL Batch / RPC / TransMgr / Attention）逐报文事件，wire
	// 字节由 build* 纯函数产出；Login response 等 down 报文按 cfg.PacketSize
	// 应用层分片（BuildTableResponsePackets，T-148）保留），TCP 语义
	// （握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器；层条目
	// layers[].tds 是唯一配置住处（D-TDS-1：translateTerminalConfig 的
	// tds case 搬层条目 JSON 进 spec.Payload，生成器只读
	// FlowMeta.Payload）；目的端口默认 1433（validateSpecBase）。
	r.Register(LayerSchema{Name: "tds", Category: CategoryTerminal,
		DependsOn:   []string{"tcp"},
		TransportOn: []string{"tcp"},
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
		Fields: map[string]FieldSchema{
			"version":            {Type: "int"},
			"skip_hello":         {Type: "bool"},
			"username":           {Type: "string"},
			"password":           {Type: "string"},
			"select_db":          {Type: "int"},
			"client_name":        {Type: "string"},
			"commands":           {Type: "list"},
			"subscribe_to":       {Type: "list"},
			"subscribe_patterns": {Type: "list"},
			"publish_messages":   {Type: "list"},
			"pipeline_size":      {Type: "int"},
		},
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
		Fields: map[string]FieldSchema{
			"server_version":     {Type: "string"},
			"thread_id":          {Type: "uint32"},
			"auth_plugin":        {Type: "string"},
			"username":           {Type: "string"},
			"password":           {Type: "string"},
			"scramble":           {Type: "string"},
			"database":           {Type: "string"},
			"capability_flags":   {Type: "uint32"},
			"max_packet_size":    {Type: "uint32"},
			"character_set":      {Type: "uint8"},
			"commands":           {Type: "list"},
			"server_bypass_auth": {Type: "bool"},
		},
	})
	r.Register(LayerSchema{Name: "grpc", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "8604"}, // gRPC telemetry_8604 惯例；用户显式非标准端口优先，不强制（gRPC 本身不强制端口）
		Fields: map[string]FieldSchema{
			"service":                {Type: "string"},
			"method":                 {Type: "string"},
			"authority":              {Type: "string"},
			"scheme":                 {Type: "string"},
			"call_type":              {Type: "string"},
			"request_messages":       {Type: "list"},
			"request_messages_b64":   {Type: "list"},
			"response_messages":      {Type: "list"},
			"response_messages_b64":  {Type: "list"},
			"response_status":        {Type: "int"},
			"response_message":       {Type: "string"},
			"timeout":                {Type: "string"},
			"metadata":               {Type: "object"},
			"pings":                  {Type: "int"},
			"encoding":               {Type: "string"},
			"accept_encoding":        {Type: "string"},
			"user_agent":             {Type: "string"},
			"header_table_size":      {Type: "uint32"},
			"initial_window":         {Type: "uint32"},
			"max_concurrent_streams": {Type: "uint32"},
			"max_frame_size":         {Type: "uint32"},
		},
	})
	r.Register(LayerSchema{Name: "ssh", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "22"}, // SSH IANA 22；用户显式非标准端口优先，不强制
	})
	r.Register(LayerSchema{Name: "rdp", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "3389"}, // RDP 默认 3389（MS-RDPBCGR §1.3）；用户显式写 3389 不强制，写其它值由 rdp Validate 拒绝
		Fields: map[string]FieldSchema{
			"security_layer":                  {Type: "string"},
			"requested_protocols":             {Type: "uint32"},
			"restricted_admin":                {Type: "bool"},
			"redirected_auth":                 {Type: "bool"},
			"cookie":                          {Type: "string"},
			"client_name":                     {Type: "string"},
			"client_build":                    {Type: "uint32"},
			"keyboard_layout":                 {Type: "uint32"},
			"keyboard_type":                   {Type: "uint32"},
			"keyboard_sub_type":               {Type: "uint32"},
			"keyboard_function_key":           {Type: "uint32"},
			"desktop_width":                   {Type: "uint16"},
			"desktop_height":                  {Type: "uint16"},
			"color_depth":                     {Type: "uint16"},
			"high_color_depth":                {Type: "uint16"},
			"supported_color_depths":          {Type: "uint16"},
			"connection_type":                 {Type: "uint8"},
			"server_selected_protocol":        {Type: "uint32"},
			"encryption_methods":              {Type: "uint32"},
			"ext_encryption_methods":          {Type: "uint32"},
			"domain":                          {Type: "string"},
			"user_name":                       {Type: "string"},
			"password":                        {Type: "string"},
			"alternate_shell":                 {Type: "string"},
			"working_dir":                     {Type: "string"},
			"channels":                        {Type: "list"},
			"auto_logon":                      {Type: "bool"},
			"info_unicode":                    {Type: "bool"},
			"info_logon_notify":               {Type: "bool"},
			"info_compression":                {Type: "bool"},
			"code_page":                       {Type: "uint32"},
			"flags2":                          {Type: "uint16"},
			"skip_mcs_channel_join":           {Type: "bool"},
			"skip_security_exchange":          {Type: "bool"},
			"skip_license":                    {Type: "bool"},
			"skip_capability":                 {Type: "bool"},
			"force_rdp_version":               {Type: "uint32"},
			"encryption_level":                {Type: "uint32"},
			"encryption_method":               {Type: "uint32"},
			"server_random":                   {Type: "list"},
			"server_cert_version":             {Type: "uint32"},
			"security_exchange_rsa_key_bytes": {Type: "int"},
			"scenario":                        {Type: "string"},
			"data_events":                     {Type: "list"},
			"server_responses":                {Type: "list"},
		},
	})
	r.Register(LayerSchema{Name: "vmess", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "443"}, // VMess 默认 443（V2Ray 惯例）；用户显式非标准端口优先，不强制
	})
	r.Register(LayerSchema{Name: "shadowsocks", Category: CategoryTerminal,
		DependsOn:     []string{"tcp"},
		FieldContract: map[string]string{"tcp.dst_port": "8388"}, // Shadowsocks 默认 8388；用户显式非标准端口优先，不强制
		Fields: map[string]FieldSchema{
			"mode":                 {Type: "string"},
			"cipher":               {Type: "string"},
			"socks5_handshake":     {Type: "bool"},
			"socks5_auth_method":   {Type: "string"},
			"socks5_username":      {Type: "string"},
			"socks5_password":      {Type: "string"},
			"socks5_cmd":           {Type: "string"},
			"socks5_dst_addr":      {Type: "string"},
			"socks5_dst_port":      {Type: "uint16"},
			"socks5_bnd_addr":      {Type: "string"},
			"socks5_bnd_port":      {Type: "uint16"},
			"chunks":               {Type: "int"},
			"chunk_payload_size":   {Type: "int"},
			"obfuscation":          {Type: "string"},
			"obf_method":           {Type: "string"},
			"obf_headers":          {Type: "object"},
			"payload_bytes_format": {Type: "string"},
			"frag":                 {Type: "uint8"},
			"file_source":          {Type: "object"},
		},
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
		// 生成器直接读层 config 三键（layer_gen.go greConfigUint32/Bool），
		// 不走 spec.GRE 翻译（flat spec.GRE 不作用于链路径）；KeyPresent
		// 由 key!=0 派生（RFC 2890 Key 域语义）。
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
		Fields: map[string]FieldSchema{
			"vsid":       {Type: "uint32"},
			"flow_id":    {Type: "uint16"},
			"ttl":        {Type: "uint8"},
			"inner":      {Type: "object"},
			"datagrams":  {Type: "list"},
			"wire_fault": {Type: "object"},
		},
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
		Fields: map[string]FieldSchema{
			"vni":           {Type: "uint32"},
			"version":       {Type: "uint8"},
			"oam":           {Type: "bool"},
			"critical":      {Type: "bool"},
			"protocol_type": {Type: "uint16"},
			"options":       {Type: "list"},
			"inner":         {Type: "object"},
			"datagrams":     {Type: "list"},
			"wire_fault":    {Type: "object"},
		},
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
			"profile":     {Type: "string", Default: "activemq_openwire_v12"},
			"wire_format": {Type: "object"},
			"connections": {Type: "list"},
			"wire_fault":  {Type: "string"},
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
			"profile":        {Type: "string", Default: "ams_management_v1"},
			"frame_max":      {Type: "uint32"},
			"heartbeat":      {Type: "uint16"},
			"client_name":    {Type: "string"},
			"auth_method":    {Type: "string"},
			"credential_ref": {Type: "string"},
			"session_limit":  {Type: "uint16"},
			"connections":    {Type: "list"},
			"wire_fault":     {Type: "string"},
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
			"profile":        {Type: "string", Default: "gnutella_v060"},
			"frame_max":      {Type: "uint32"},
			"client_headers": {Type: "object"},
			"server_headers": {Type: "object"},
			"connections":    {Type: "list"},
			"wire_fault":     {Type: "string"},
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
