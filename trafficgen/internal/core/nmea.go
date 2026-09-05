package core

// NMEA（海用电子设备数据交换标准，NMEA 0183 v4.10/IEEE 61162-1 sentence，
// 单向传感器通知流 over TCP/UDP）配置类型。字段名对齐
// docs/protocol-designs/69-nmea-{design,testcase}.md v2.0.0：sessions[]
// 事件编排会话（每事件 = 一笔"产出一句话"事件：talker+type+checksum+
// fields 逐字段数组），pack 相邻句子合并单段，wire_fault 注入负例故障
// （31 值枚举与设计 §6/§7/用例 §5 表三方同序）。[tcp→nmea]/[udp→nmea] 双
// 载体终结层（TransportOn=[tcp,udp]，默认 tcp；会话级 transport 覆盖载体）。

// NMEAConfig is the flow's nmea terminal-layer configuration.
type NMEAConfig struct {
	// Concurrent enables interleaved multi-session replay: session events
	// are emitted round-robin (per event index) instead of session-by-
	// session (设计 §4⑦ AIS/GPS 网关多设备并发，正例 45)。The tcp layer
	// must also set {"concurrent": true} to keep independent connections
	// per SrcPort.
	Concurrent bool           `json:"concurrent,omitempty"`
	Sessions   []NMEASession  `json:"sessions,omitempty"`
	// Pack merges adjacent sentence bytes into one TCP segment (多句粘连
	// 单段正例；缺省 false = 每句一段）。
	Pack bool `json:"pack,omitempty"`
	// WireFault injects one negative-path fault (31 kinds, design §7 — 与
	// §7 表/用例 §5 表三方同序): missing_dollar|missing_crlf|lf_only|
	// truncated_tcp|udp_truncated|udp_cross_datagram|start_bang|
	// unknown_talker|unknown_type|talker_p_standard|field_count_short|
	// field_count_extra|lat_over|lon_over|minutes_over|direction_char|
	// time_out_of_range|date_out_of_range|status_char|gsa_mode_char|
	// gsa_fix_type|sentence_length|checksum_mismatch|checksum_hex_width|
	// proprietary_no_checksum|gsv_seq_correlation|carrier_layer_missing|
	// carrier_conflict|port_undeclared|address_family_mismatch|propagation.
	WireFault string `json:"wire_fault,omitempty"`
	// Termination selects the close shape for all sessions ("rst" = single-sided
	// RST; default = graceful FIN). Per-session Termination overrides this.
	Termination string `json:"termination,omitempty"`
}

// NMEASession is one device→collector connection: ordered event list (one
// sentence per event). Session identity across connections is the
// SrcPort/DstPort override; Transport overrides the chain carrier ("udp").
// Termination selects the close shape ("rst" = single-sided RST, default =
// graceful FIN handled by the tcp layer).
type NMEASession struct {
	SrcPort uint16 `json:"src_port,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`
	// Transport overrides the layer-chain carrier for this session ("udp"
	// on a tcp chain = 多载体 fixture，正例 43；carrier_conflict 负例用
	// 同一声明触发拒绝）。
	Transport string `json:"transport,omitempty"`
	// Termination selects the close shape: "" (default FIN) or "rst"
	// (RST 异常中断正例 46)。
	Termination string        `json:"termination,omitempty"`
	Events      []NMEAEvent   `json:"events,omitempty"`
}

// NMEAEvent is one "produce one sentence" event: talker (2 ASCII, §3.2
// 值域表）+ type （支持集 {GGA,RMC,GSA,GSV,VTG,GLL,ZDA} 或专有 $P 形态）+
// checksum (true=计算 *hh；false=无校验和，仅标准句型）+ fields（按句型字段
// 序的字符串数组，空字段保留为空串——占位逗号保留）。
type NMEAEvent struct {
	Kind string `json:"kind,omitempty"` // "sentence"（唯一合法 kind）
	// PackNext merges this sentence's bytes with the NEXT event's sentence
	// into one TCP segment (多句粘连单段；both must be same direction —
	// NMEA 恒上行）。
	PackNext bool `json:"pack_next,omitempty"`
	// Talker is the 2-char talker ID (GP/GN/GL/II/...，§3.2 值域表）。专有句
	// 用 "P"+厂商：Talker="P", MfrID=3 字符。
	Talker string `json:"talker,omitempty"`
	// Type is the 3-char sentence type (GGA/RMC/GSA/GSV/VTG/GLL/ZDA）。
	Type string `json:"type,omitempty"`
	// MfrID is the 3-char manufacturer ID for $P proprietary sentences
	// (Talker="P" 时必填）。
	MfrID string `json:"mfr_id,omitempty"`
	// Checksum selects the checksum form: true (default) = 计算 *hh；
	// false = 无校验和直接 CRLF（仅标准句型合法，§3.3)。
	Checksum *bool `json:"checksum,omitempty"`
	// ChecksumValue pins the emitted checksum hex explicitly (观测模式：
	// wire_fault checksum_mismatch 的观测态正例 48 用 *6A；nil = 自动计算）。
	ChecksumValue string `json:"checksum_value,omitempty"`
	// Fields is the per-type field array in §3.4 order (empty string =
	// 空字段占位，逗号保留）。
	Fields []string `json:"fields,omitempty"`
	// SplitAt is an optional byte offset hint driving TCP cross-segment cut
	// position (跨段四形态正例 31-34：1/20/67/69)。
	SplitAt *int `json:"split_at,omitempty"`
}
