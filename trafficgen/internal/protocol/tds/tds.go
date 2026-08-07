// Package tds: tds.go — the TDS protocol planner (design doc §10 mapping).
//
// One flow = one TCP connection carrying the TDS session lifecycle:
//
//	TCP handshake → PRELOGIN → Login7 → Login Response → sessions
//	(SQL Batch / RPC / TransMgr / Attention) → TCP FIN
//
// The planner emits both directions: client requests ("up") and the
// simulated server response ("down") so the complete byte stream is
// observable in a pcap (spec §10: "一个 Flow = 一次 TCP 连接 +
// PRELOGIN/LOGIN7 + 会话请求序列").
//
// The TDSConfig JSON is carried in FlowSpec.Payload (a2a-style); when
// Payload is empty a default configuration is used.
package tds

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TCP flags (mirror internal/protocol/pptp).
const (
	tcpSYN    = 0x02
	tcpSYNACK = 0x12
	tcpACK    = 0x10
	tcpPSHACK = 0x18
	tcpFINACK = 0x11

	DefaultTTL = 64
	DefaultMSS = 1460
)

// Planner implements the TDS protocol planner.
type Planner struct{}

// NewPlanner creates a new TDS planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string {
	return "tds"
}

// configFromSpec extracts the TDSConfig from a FlowSpec. When Payload is
// empty a default config is used; otherwise Payload must be valid TDSConfig
// JSON.
func configFromSpec(spec core.FlowSpec) (*TDSConfig, error) {
	cfg := &TDSConfig{}
	if len(spec.Payload) > 0 {
		if err := json.Unmarshal(spec.Payload, cfg); err != nil {
			return nil, fmt.Errorf("tds: invalid config JSON in payload: %w", err)
		}
	}
	applyDefaults(cfg)
	return cfg, nil
}

// applyDefaults fills zero-valued config fields with the design defaults.
func applyDefaults(cfg *TDSConfig) {
	if cfg.Version == 0 {
		cfg.Version = TDSVersion74
	}
	if cfg.PacketSize == 0 {
		cfg.PacketSize = DefaultPacketSize
	}
	if cfg.AppName == "" {
		cfg.AppName = "trafficgen"
	}
	if cfg.ServerName == "" {
		cfg.ServerName = "MSSQLServer"
	}
	if cfg.ClientName == "" {
		cfg.ClientName = "trafficgen-host"
	}
	if cfg.UserName == "" {
		cfg.UserName = "sa"
	}
	if cfg.Password == "" {
		cfg.Password = "password"
	}
	if cfg.InterfaceLib == "" {
		cfg.InterfaceLib = "ODBC"
	}
	if cfg.ClientLCID == 0 {
		cfg.ClientLCID = 0x0409
	}
}

// Validate validates a TDS flow spec (design §8). All V-TDS-xxx rules.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("invalid source IP: %s", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("invalid destination IP: %s", spec.DstIP)
		}
	}
	cfg, err := configFromSpec(spec)
	if err != nil {
		return err
	}
	return ValidateConfig(cfg)
}

// ValidateConfig validates a TDSConfig directly (design §8).
func ValidateConfig(cfg *TDSConfig) error {
	// V-01: version legal
	switch cfg.Version {
	case TDSVersion71, TDSVersion72, TDSVersion73A, TDSVersion73B, TDSVersion74:
	default:
		return fmt.Errorf("tds: invalid version 0x%08x (V-TDS-001)", uint32(cfg.Version))
	}
	// V-02: packet size range
	if cfg.PacketSize < 512 || cfg.PacketSize > 32767 {
		return fmt.Errorf("tds: invalid packet_size %d (512..32767, V-TDS-002)", cfg.PacketSize)
	}
	// V-03: sessions >= 1
	if len(cfg.Sessions) == 0 {
		return fmt.Errorf("tds: at least one session required (V-TDS-003)")
	}
	// V-37: MARS prerequisite
	if !cfg.MarsEnabled && len(cfg.Sessions) > 1 {
		return fmt.Errorf("tds: multiple sessions require mars=true (V-TDS-038)")
	}
	// V-15: features only TDS 7.4
	if len(cfg.FeatureExts) > 0 && cfg.Version != TDSVersion74 {
		return fmt.Errorf("tds: feature_exts require TDS 7.4 (V-TDS-015)")
	}
	for _, fe := range cfg.FeatureExts {
		// V-16: known feature ids
		switch fe.ID {
		case 0x01, 0x02, 0x04, 0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0D, 0x0E, 0x0F, 0x10:
		default:
			return fmt.Errorf("tds: unknown feature id 0x%02x (V-TDS-016)", fe.ID)
		}
		// V-17: feature data hex
		if fe.Data != "" {
			if _, err := hex.DecodeString(fe.Data); err != nil {
				return fmt.Errorf("tds: feature %02x data not hex: %w (V-TDS-017)", fe.ID, err)
			}
		}
		// V-18: feature ack_data hex (spec §3.14 FeatureAckData 可自定义)
		if fe.AckData != "" {
			if _, err := hex.DecodeString(fe.AckData); err != nil {
				return fmt.Errorf("tds: feature %02x ack_data not hex: %w (V-TDS-018)", fe.ID, err)
			}
		}
	}
	// Login field caps (V-07..V-13).
	fields := []struct {
		name  string
		value string
	}{
		{"app_name", cfg.AppName},
		{"user_name", cfg.UserName},
		{"password", cfg.Password},
		{"server_name", cfg.ServerName},
		{"database", cfg.Database},
		{"language", cfg.Language},
		{"interface_lib", cfg.InterfaceLib},
		{"client_name", cfg.ClientName},
	}
	for _, f := range fields {
		if len([]rune(f.value)) > MaxLoginFieldChars {
			return fmt.Errorf("tds: %s %d chars > %d (V-TDS-007)", f.name, len([]rune(f.value)), MaxLoginFieldChars)
		}
	}
	// Session validation.
	for _, s := range cfg.Sessions {
		if len(s.Requests) == 0 {
			return fmt.Errorf("tds: session %q has no requests (V-TDS-004)", s.ID)
		}
		// V-35: TransactionID must be 0 OR an earlier request must BEGIN a
		// transaction (so the descriptor is meaningful). Track whether any
		// SQL Batch or TM_BEGIN_XACT in this session starts a transaction.
		seenBegin := false
		for ri, r := range s.Requests {
			switch r.Type {
			case RequestSQLBatch:
				if r.Sql == nil {
					return fmt.Errorf("tds: session %q request %d type=sql_batch but sql missing (V-TDS-006)", s.ID, ri)
				}
				if len(r.Sql.Statements) == 0 {
					return fmt.Errorf("tds: session %q request %d sql has no statements (V-TDS-020)", s.ID, ri)
				}
				for _, st := range r.Sql.Statements {
					if st.Text == "" {
						return fmt.Errorf("tds: session %q request %d empty SQL text (V-TDS-020)", s.ID, ri)
					}
					if txnBegins(st.Text) {
						seenBegin = true
					}
				}
			case RequestRPC:
				if r.Rpc == nil {
					return fmt.Errorf("tds: session %q request %d type=rpc but rpc missing (V-TDS-006)", s.ID, ri)
				}
				if r.Rpc.ProcName != "" && r.Rpc.ProcID != nil {
					return fmt.Errorf("tds: session %q request %d ProcName and ProcID mutually exclusive (V-TDS-024)", s.ID, ri)
				}
				if r.Rpc.ProcID != nil && *r.Rpc.ProcID > 15 {
					return fmt.Errorf("tds: session %q request %d ProcID %d > 15 (V-TDS-023)", s.ID, ri, *r.Rpc.ProcID)
				}
				if len(r.Rpc.ProcName) > MaxProcNameBytes {
					return fmt.Errorf("tds: session %q request %d ProcName %d bytes > %d (V-TDS-022)", s.ID, ri, len(r.Rpc.ProcName), MaxProcNameBytes)
				}
				for _, pr := range r.Rpc.Params {
					if err := validateParam(pr); err != nil {
						return fmt.Errorf("tds: session %q request %d param %q: %w", s.ID, ri, pr.Name, err)
					}
				}
			case RequestTransMgr:
				if r.TransMgr == nil {
					return fmt.Errorf("tds: session %q request %d type=trans_mgr but trans_mgr missing (V-TDS-006)", s.ID, ri)
				}
				// V-33: legal RequestType
				switch r.TransMgr.RequestType {
				case TMGetDTCAddr, TMPropagateXact, TMBeginXact, TMPromoteXact,
					TMCommitXact, TMRollbackXact, TMSaveXact:
				default:
					return fmt.Errorf("tds: session %q request %d unknown request_type %d (V-TDS-034)", s.ID, ri, r.TransMgr.RequestType)
				}
				// V-34: TM_SAVE_XACT needs non-empty name payload
				if r.TransMgr.RequestType == TMSaveXact && r.TransMgr.Payload == "" {
					return fmt.Errorf("tds: TM_SAVE_XACT requires a payload (V-TDS-035)")
				}
				if r.TransMgr.RequestType == TMBeginXact {
					seenBegin = true
				}
			case RequestAttention:
				// V-39: attention has no body — nothing to check here.
			default:
				return fmt.Errorf("tds: session %q request %d invalid type %q (V-TDS-005)", s.ID, ri, r.Type)
			}
		}
		if s.TransactionID != 0 && !seenBegin {
			return fmt.Errorf("tds: session %q transaction_id set but no BEGIN TRAN/TM_BEGIN_XACT before it (V-TDS-036)", s.ID)
		}
	}
	return nil
}

// validateParam validates one RPC parameter (V-24..V-31).
// 白名单必须与 encodeTypeInfoAndValue (builder_rpc.go) 支持的类型集合一致
// （修复 N5: 此前两处不一致——validate 拒绝 encode 支持的类型，err 信息与
// 实际行为矛盾）。decimal/numeric 随 N3 一并纳入。
func validateParam(p ParamSpec) error {
	switch p.Type {
	case "int", "int4", "bigint", "int8", "smallint", "int2", "tinyint", "int1",
		"bit", "varchar", "bigvarchar", "nvarchar", "bignvarchar", "varbinary",
		"decimal", "numeric",
		"xml", "json", "udt", "uniqueidentifier", "guid", "intn":
	default:
		return fmt.Errorf("unsupported param type %q (V-TDS-025)", p.Type)
	}
	if p.MaxLen != nil && !p.Max {
		if p.Type == "varchar" || p.Type == "bigvarchar" || p.Type == "varbinary" {
			if *p.MaxLen > 8000 {
				return fmt.Errorf("%s max_len %d > 8000 without max (V-TDS-026)", p.Type, *p.MaxLen)
			}
		}
		if p.Type == "nvarchar" || p.Type == "bignvarchar" {
			if *p.MaxLen > 4000 {
				return fmt.Errorf("%s max_len %d > 4000 without max (V-TDS-026)", p.Type, *p.MaxLen)
			}
		}
	}
	// V-26/V-27: decimal/numeric Precision ≤ 38 且 Scale ≤ Precision。
	// 与 encodeTypeInfoAndValue (builder_rpc.go) 的校验保持一致（双保险：
	// 校验在规划阶段即失败，encode 阶段再次防御）。
	if p.Type == "decimal" || p.Type == "numeric" {
		if p.Precision != nil && *p.Precision > 38 {
			return fmt.Errorf("decimal/numeric precision %d > 38 (V-TDS-027)", *p.Precision)
		}
		if p.Precision != nil && p.Scale != nil && *p.Scale > *p.Precision {
			return fmt.Errorf("decimal/numeric scale %d > precision %d (V-TDS-028)", *p.Scale, *p.Precision)
		}
	}
	return nil
}

// txnBegins 报告 SQL 文本是否开启一个事务
// (BEGIN TRAN / BEGIN TRANSACTION / BEGIN TRANSACTION name)。
// upperTrim 仅转大写不去空白，故此处字面量也保持大写、且显式覆盖
// 带尾随空格/分号的常见写法——此前误用小写字面量导致永远返回 false
// (V-TDS-036 因此对任何显式 BEGIN 都误报"无 BEGIN")。
func txnBegins(text string) bool {
	upper := upperTrim(text)
	return upper == "BEGIN TRAN" || upper == "BEGIN TRANSACTION" ||
		upper == "BEGIN TRAN " || upper == "BEGIN TRANSACTION " ||
		upper == "BEGIN" || upper == "BEGIN;"
}

func upperTrim(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out = append(out, c)
	}
	return string(out)
}

// Plan generates the TDS flow: TCP handshake, PRELOGIN, Login7, Login
// Response, sessions, teardown (design §6 S1-S15).
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = DefaultPort
	}
	cfg, err := configFromSpec(spec)
	if err != nil {
		return nil, err
	}
	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		select {
		case <-ctx.Done():
			return
		default:
		}

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
		now := time.Now()
		ttl := spec.TTL
		if ttl == 0 {
			ttl = DefaultTTL
		}
		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		spid := uint16(0)
		if cfg.MarsEnabled {
			spid = 0x0042 // shared SPID across MARS sessions (S12)
		}
		senderSeq := uint32(0)
		if spec.TCP != nil {
			senderSeq = spec.TCP.InitialSeq
		}
		peerSeq := uint32(0x1000)
		packetIndex := uint64(0)
		var ipID uint16 = 0x1000

		emit := func(direction string, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte) {
			l3 := core.L3Base(spec.SrcIP, spec.DstIP, 6, ttl, ipID, spec)
			ipID++
			if direction == "down" {
				l3 = core.L3Base(spec.DstIP, spec.SrcIP, 6, ttl, ipID, spec)
				ipID++
			}
			l4 := core.L4Config{
				Protocol:   "tcp",
				SrcPort:    srcPort,
				DstPort:    dstPort,
				Seq:        seq,
				Ack:        ack,
				Flags:      flags,
				WindowSize: 65535,
			}
			if flags == tcpSYN || flags == tcpSYNACK {
				l4.TCPOptions = synOptions(mss)
			}
			cfgOut := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    spec.SrcMAC,
					DstMAC:    spec.DstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3:      l3,
				L4:      l4,
				Payload: payload,
			}
			if direction == "down" {
				cfgOut.L2.SrcMAC = spec.DstMAC
				cfgOut.L2.DstMAC = spec.SrcMAC
			}
			select {
			case configChan <- cfgOut:
			case <-ctx.Done():
			}
			packetIndex++
		}

		emitData := func(direction string, srcPort, dstPort uint16, seq uint32, peer uint32, payload []byte) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				emit(direction, srcPort, dstPort, seq, peer, tcpPSHACK, seg)
				seq += uint32(len(seg))
			}
		}

		up := func(payload []byte) {
			emitData("up", spec.SrcPort, spec.DstPort, senderSeq, peerSeq, payload)
			senderSeq += uint32(len(payload))
		}
		down := func(payload []byte) {
			emitData("down", spec.DstPort, spec.SrcPort, peerSeq, senderSeq, payload)
			peerSeq += uint32(len(payload))
		}

		// --- TCP handshake ---
		emit("up", spec.SrcPort, spec.DstPort, senderSeq, 0, tcpSYN, nil)
		senderSeq++
		emit("down", spec.DstPort, spec.SrcPort, peerSeq, senderSeq, tcpSYNACK, nil)
		peerSeq++
		emit("up", spec.SrcPort, spec.DstPort, senderSeq, peerSeq, tcpACK, nil)

		// --- PRELOGIN (S1) ---
		prelogin := buildPreLoginPacket(cfg, packetIDFor(1))
		up(prelogin)
		// Server PRELOGIN response: mirror the options.
		down(buildPreLoginResponse(cfg))

		// --- Login7 (S2) ---
		login := buildLogin7Packet(cfg)
		up(login)
		down(buildLoginResponse(cfg))

		// --- Sessions ---
		// MARS: OutstandingRequestCount 是动态值——该连接上当前活动的请求
		// 总数 (spec §4.4 MARS 状态机: "每条消息的 OutstandingRequestCount =
		// 当前该连接上活动请求数")。trafficgen 的 MARS 模型将所有 session 视
		// 为并发活动 (spec S12 / T-186 / T-192: 2 会话交错时
		// OutstandingRequestCount=2，3 会话时=3)，因此每条请求的 outstanding
		// 等于该连接上活动的 session 数量。
		//
		// 修复 Bug 4 (HIGH): 此前为静态 sessIdx+1 (会话 A=1, 会话 B=2)，与
		// T-186 (两会话均=2) / T-192 (三会话均=3) 不符，且不是"活动请求数"
		// 的真实语义。改为动态 len(cfg.Sessions) 后，2 会话时 A/B 请求均为
		// 2 (两个 session 同时活动)，3 会话时均为 3。
		// 非 MARS (AutoCommit): 严格按 spec §2.5 / §3.2.4 固定为 1。
		computeOutstanding := func() uint32 {
			if cfg.MarsEnabled {
				return uint32(len(cfg.Sessions))
			}
			return 1
		}
		for _, sess := range cfg.Sessions {
			txnDesc := sess.TransactionID
			sessOutstanding := computeOutstanding()
			for ri, req := range sess.Requests {
				switch req.Type {
				case RequestSQLBatch:
					payload, err := buildSQLBatchRequest(cfg, req.Sql, txnDesc, sessOutstanding, spid)
					if err != nil {
						continue
					}
					up(payload)
					down(buildSQLBatchResponse(cfg, &req, ri))
				case RequestRPC:
					payload, err := buildRPCRequest(cfg, req.Rpc, txnDesc, sessOutstanding, spid)
					if err != nil {
						continue
					}
					up(payload)
					down(buildRPCResponse(cfg, &req, ri))
				case RequestTransMgr:
					payload, err := buildTransMgrRequest(cfg, req.TransMgr, txnDesc, sessOutstanding, spid)
					if err != nil {
						continue
					}
					up(payload)
					down(buildTransMgrResponse(cfg, req.TransMgr))
				case RequestAttention:
					up(BuildAttention(spid, packetIDFor(1)))
					down(buildAttentionResponse())
				}
			}
		}

		// --- TCP teardown ---
		emit("up", spec.SrcPort, spec.DstPort, senderSeq, peerSeq, tcpFINACK, nil)
		senderSeq++
		emit("down", spec.DstPort, spec.SrcPort, peerSeq, senderSeq, tcpFINACK, nil)
	}()

	return configChan, nil
}

// packetIDFor returns the 1-based packet id (mod 256).
func packetIDFor(n int) byte { return byte(n & 0xFF) }

// segmentByMSS splits payload into MSS-sized segments.
func segmentByMSS(payload []byte, mss int) [][]byte {
	if mss <= 0 || len(payload) <= mss {
		return [][]byte{payload}
	}
	var out [][]byte
	for len(payload) > mss {
		out = append(out, payload[:mss])
		payload = payload[mss:]
	}
	if len(payload) > 0 {
		out = append(out, payload)
	}
	return out
}

// synOptions builds the TCP SYN options (MSS).
// 返回 []core.TCPOption 以匹配 core.L4Config.TCPOptions 的类型
// (core.TCPOption{Kind, Data})。此前返回 []byte 与 L4Config 字段类型不符，
// 属于编译期遗留错误 (与本次 4 个 bug 修复无关，但阻塞 vet)。
func synOptions(mss uint16) []core.TCPOption {
	return []core.TCPOption{{
		Kind: core.TCPOptMSS,
		Data: []byte{byte(mss >> 8), byte(mss)},
	}}
}

// --- PRELOGIN packet builders (S1) ---

func buildPreLoginPacket(cfg *TDSConfig, packetID byte) []byte {
	// VERSION 数据 = UL_VERSION(4B BE) + US_SUBBUILD(2B BE) 共 6 字节
	// (spec §3.1 / MS-TDS 4.1 示例: 09 00 00 00 00 00)。此前误写成
	// 8 字节 (4B + 4B) 且 subbuild 取值 0x00000100，与规范不符
	// (PL_OPTION_LENGTH 会写成 0x0008 而非 0x0006)。
	version := uint32(0x09000000) // major=9
	verData := make([]byte, 6)
	putBE32(verData[0:4], version)
	putBE16(verData[4:6], 0x0000) // US_SUBBUILD
	opts := []PreLoginOption{
		{Token: PLVersion, Data: verData},
		{Token: PLEncryption, Data: []byte{byte(cfg.EncryptMode)}},
		{Token: PLInstOpt, Data: []byte{0}},
		{Token: PLThreadID, Data: []byte{0xB8, 0x0D, 0x00, 0x00}},
	}
	if cfg.MarsEnabled {
		opts = append(opts, PreLoginOption{Token: PLMARS, Data: []byte{0x01}})
	} else {
		opts = append(opts, PreLoginOption{Token: PLMARS, Data: []byte{0x00}})
	}
	return BuildPreLogin(opts, StatusEOM, 0, packetID)
}

func buildPreLoginResponse(cfg *TDSConfig) []byte {
	// Server response: VERSION + ENCRYPTION + TERMINATOR (S1).
	// 同上: VERSION 数据为 6 字节 (UL_VERSION 4B BE + US_SUBBUILD 2B BE)。
	version := uint32(0x09000000)
	verData := make([]byte, 6)
	putBE32(verData[0:4], version)
	putBE16(verData[4:6], 0x0000) // US_SUBBUILD
	enc := byte(EncryptOff)
	if cfg.EncryptMode == EncryptRequired {
		enc = EncryptOn
	}
	opts := []PreLoginOption{
		{Token: PLVersion, Data: verData},
		{Token: PLEncryption, Data: []byte{enc}},
	}
	return BuildPreLoginResponse(opts, StatusEOM, 0, 1)
}

// --- LOGIN7 packet builder (S2) ---

func buildLogin7Packet(cfg *TDSConfig) []byte {
	mac := [6]byte{0x00, 0x50, 0x8B, 0xE2, 0xB7, 0x8F}
	optFlags1 := byte(0xE0)
	optFlags2 := byte(0x03)
	typeFlags := byte(0x00)
	optFlags3 := byte(0x00)
	if cfg.Login != nil {
		if cfg.Login.OptionFlags1 != nil {
			optFlags1 = *cfg.Login.OptionFlags1
		}
		if cfg.Login.OptionFlags2 != nil {
			optFlags2 = *cfg.Login.OptionFlags2
		}
		if cfg.Login.TypeFlags != nil {
			typeFlags = *cfg.Login.TypeFlags
		}
		if cfg.Login.OptionFlags3 != nil {
			optFlags3 = *cfg.Login.OptionFlags3
		}
	}
	// FeatureExt data (TDS 7.4). 当 FeatureExt 非空时，LOGIN7 OptionFlags3 的
	// fExtension (bit4, 0x10) 必须置位 (spec §3.2 / MS-TDS §2.2.6.4:
	// "fExtension: Specifies whether ibExtension/cbExtension fields are used.
	//  1 = ibExtension/cbExtension fields are used")。否则服务器会按
	// ibUnused/cbUnused 解析偏移表，FeatureExt 数据被忽略，导致特性协商失败。
	//
	// 修复 Bug 5 (HIGH): 此前注释要求调用者 (LoginSpec.OptionFlags3) 手工置
	// fExtension 位，但 Validate 与默认配置路径均未置位，使得 FeatureExts 非空
	// 时服务器无法读取 ibExtension/cbExtension。现改为构建侧自动置位，保证
	// "FeatureExts 非空 → fExtension=1 → 服务器解析 FeatureExt" 链路闭合。
	var fe []byte
	if cfg.Version == TDSVersion74 {
		for _, f := range cfg.FeatureExts {
			fe = append(fe, f.ID)
			var data []byte
			if f.Data != "" {
				data, _ = hex.DecodeString(f.Data)
			}
			l := make([]byte, 4)
			binary.LittleEndian.PutUint32(l, uint32(len(data)))
			fe = append(fe, l...)
			fe = append(fe, data...)
		}
		fe = append(fe, 0xFF)
	}
	// FeatureExts 非空时自动置 fExtension bit4 (0x10)，使服务器读取
	// ibExtension/cbExtension 偏移表项 (spec §3.2 OptionFlags3 LSB 序)。
	if len(cfg.FeatureExts) > 0 {
		optFlags3 |= 0x10
	}
	return BuildLogin7(
		cfg.Version, cfg.PacketSize, 0x00000100,
		optFlags1, optFlags2, typeFlags, optFlags3,
		cfg.ClientLCID,
		cfg.ClientName, cfg.UserName, cfg.Password,
		cfg.AppName, cfg.ServerName,
		cfg.InterfaceLib, cfg.Language, cfg.Database,
		mac, fe,
	)
}

// --- Login response (S2) ---

func buildLoginResponse(cfg *TDSConfig) []byte {
	var tokens []byte
	// ENVCHANGE Type 1 Database.
	tokens = append(tokens, BuildEnvChange(1, EnvChangeBVarChar("master"), EnvChangeBVarChar("master"))...)
	// INFO 5701.
	info1, _ := BuildErrorInfo(TokenInfo, 5701, 2, 0, "Changed database context to 'master'.", "", "", 0, true)
	tokens = append(tokens, info1...)
	// ENVCHANGE Type 7 Collation.
	col := append([]byte{5}, DefaultCollation[:]...)
	tokens = append(tokens, BuildEnvChange(7, col, EnvChangeEmptyValue())...)
	// ENVCHANGE Type 2 Language.
	tokens = append(tokens, BuildEnvChange(2, EnvChangeBVarChar("us_english"), EnvChangeEmptyValue())...)
	// ENVCHANGE Type 4 Packet Size.
	ps := fmt.Sprintf("%d", cfg.PacketSize)
	tokens = append(tokens, BuildEnvChange(4, EnvChangeBVarChar(ps), EnvChangeBVarChar(ps))...)
	// INFO 5703.
	info2, _ := BuildErrorInfo(TokenInfo, 5703, 1, 0, "Changed language setting to us_english.", "", "", 0, true)
	tokens = append(tokens, info2...)
	// LOGINACK.
	laVersion := loginAckVersion(cfg.Version)
	tokens = append(tokens, BuildLoginAck(1, laVersion, "Microsoft SQL Server", 0)...)
	// FEATUREEXTACK when TDS 7.4.
	//
	// 修复 Bug 6 (HIGH): 此前 FEATUREEXTACK 对每个 FeatureId 一律回写长度
	// 为 0 的 FeatureAckData (4B 长度字段全 0)。但 spec §3.14 定义
	// FeatureAckOpt = (FeatureId(1B) FeatureAckDataLen(4B LE) FeatureAckData)
	// 允许自定义回执数据 (如 SESSIONRECOVERY 的 SessionStateDataSet、
	// FEDAUTH 的 Nonce+Signature、COLUMNENCRYPTION 的版本等)。现支持
	// FeatureExt.AckData 字段携带自定义 hex 回执数据；为空时保持 0 长度。
	if cfg.Version == TDSVersion74 && len(cfg.FeatureExts) > 0 {
		var ack []byte
		ack = append(ack, TokenFeatureExtAck)
		for _, f := range cfg.FeatureExts {
			ack = append(ack, f.ID)
			var ackData []byte
			if f.AckData != "" {
				ackData, _ = hex.DecodeString(f.AckData)
			}
			l := make([]byte, 4)
			binary.LittleEndian.PutUint32(l, uint32(len(ackData)))
			ack = append(ack, l...)
			ack = append(ack, ackData...)
		}
		ack = append(ack, 0xFF)
		tokens = append(tokens, ack...)
	}
	// DONE (DONE_FINAL).
	done, _ := BuildDone(TokenDone, DONEFinal, 0, 0, true)
	tokens = append(tokens, done...)
	return BuildTableResponsePacket(tokens, 0, 1)
}

// loginAckVersion returns the server→client TDSVersion (spec footnote 72:
// 7.4 = 0x74000004).
func loginAckVersion(v TDSVersion) uint32 {
	switch v {
	case TDSVersion71:
		return 0x07010000
	case TDSVersion72:
		return 0x72090002
	case TDSVersion73A:
		return 0x730A0003
	case TDSVersion73B:
		return 0x730B0003
	default:
		return 0x74000004
	}
}

// --- SQL Batch request/response (S3/S4/S5/S11) ---

func buildSQLBatchRequest(cfg *TDSConfig, sql *SqlBatchSpec, txnDesc uint64, outstanding uint32, spid uint16) ([]byte, error) {
	var text string
	for _, st := range sql.Statements {
		if text != "" {
			text += ";"
		}
		text += st.Text
	}
	return BuildSQLBatch(text, true, txnDesc, outstanding, StatusEOM, spid, 1), nil
}

// buildSQLBatchResponse synthesizes the server response for a SQL batch:
// one result set (COLMETADATA + ROW) per SELECT-ish statement, DONE with
// DONE_MORE for all but the last statement.
func buildSQLBatchResponse(cfg *TDSConfig, req *RequestSpec, ri int) []byte {
	var tokens []byte
	sql := req.Sql
	for i, st := range sql.Statements {
		if isSelect(st.Text) {
			// COLMETADATA: one INT4 column "c".
			cm := BuildColMetadata([]ColMetadataColumn{
				{UserType: 0, Flags: 0, TypeInfo: []byte{TypeInt4}, ColName: "c"},
			}, false)
			tokens = append(tokens, cm...)
			// ROW: value = statement index+1.
			val := make([]byte, 4)
			binary.LittleEndian.PutUint32(val, uint32(i+1))
			tokens = append(tokens, BuildRow(val)...)
		}
		status := uint16(DONECount)
		if i < len(sql.Statements)-1 {
			status |= DONEMore
		}
		rc := int64(1)
		if st.ExpectRows > 0 {
			rc = int64(st.ExpectRows)
		}
		done, _ := BuildDone(TokenDone, status, 0, rc, true)
		tokens = append(tokens, done...)
	}
	return BuildTableResponsePacket(tokens, 0, byte(1+(ri%255)))
}

// isSelect reports whether the SQL text looks like a SELECT statement.
// Only statements whose first non-blank keyword is "SELECT" (case-insensitive)
// qualify; "SET NOCOUNT ON"/"SHOW"/"SHUTDOWN"/"SAVE TRAN" etc. do NOT produce
// a result set (修复 N2: 此前仅匹配首非空白字符=='S'，误判上述语句)。
func isSelect(text string) bool {
	u := upperTrim(text)
	for i := 0; i < len(u); i++ {
		c := u[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		return strings.HasPrefix(u[i:], "SELECT")
	}
	return false
}

// --- RPC request/response (S6/S7/S13/S14) ---

func buildRPCRequest(cfg *TDSConfig, rpc *RpcSpec, txnDesc uint64, outstanding uint32, spid uint16) ([]byte, error) {
	return BuildRPCRequest(*rpc, true, txnDesc, outstanding, StatusEOM, spid, 1)
}

// buildRPCResponse synthesizes the server response for an RPC: DONEINPROC +
// RETURNSTATUS + DONEPROC (S6/S7).
func buildRPCResponse(cfg *TDSConfig, req *RequestSpec, ri int) []byte {
	var tokens []byte
	di, _ := BuildDone(TokenDoneInProc, DONEMore|DONECount, 0xC1, 1, true)
	tokens = append(tokens, di...)
	tokens = append(tokens, BuildReturnStatus(0)...)
	dp, _ := BuildDone(TokenDoneProc, DONEFinal, 0xE0, 0, true)
	tokens = append(tokens, dp...)
	return BuildTableResponsePacket(tokens, 0, byte(1+(ri%255)))
}

// --- TransMgrReq request/response (S11) ---

func buildTransMgrRequest(cfg *TDSConfig, tm *TransMgrSpec, txnDesc uint64, outstanding uint32, spid uint16) ([]byte, error) {
	return BuildTransMgrReq(tm.RequestType, tm.Payload, txnDesc, outstanding, StatusEOM, spid, 1)
}

// buildTransMgrResponse synthesizes the ENVCHANGE response for a
// transaction-manager request (S11): BEGIN→Type 8, COMMIT→Type 9,
// ROLLBACK→Type 10.
func buildTransMgrResponse(cfg *TDSConfig, tm *TransMgrSpec) []byte {
	var tokens []byte
	switch tm.RequestType {
	case TMBeginXact:
		tokens = append(tokens, BuildEnvChange(8, EnvChangeTranValue(1), EnvChangeEmptyValue())...)
	case TMCommitXact:
		tokens = append(tokens, BuildEnvChange(9, EnvChangeEmptyValue(), EnvChangeTranValue(1))...)
	case TMRollbackXact:
		tokens = append(tokens, BuildEnvChange(10, EnvChangeEmptyValue(), EnvChangeTranValue(1))...)
	}
	done, _ := BuildDone(TokenDone, DONEFinal, 0, 0, true)
	tokens = append(tokens, done...)
	return BuildTableResponsePacket(tokens, 0, 1)
}

// --- Attention response (S10) ---

func buildAttentionResponse() []byte {
	done, _ := BuildDone(TokenDone, DONEAttn, 0, 0, true)
	return BuildTableResponsePacket(done, 0, 1)
}
