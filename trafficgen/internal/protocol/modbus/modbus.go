// Package modbus implements the Modbus TCP protocol planner.
// Modbus TCP is an industrial control protocol on TCP port 502.
//
// Each transaction = one request PDU + one response PDU, framed by the
// 7-byte MBAP header (Transaction ID + Protocol ID + Length + Unit ID).
//
// The planner emits:
//  1. TCP 3-way handshake (SYN, SYN+ACK, ACK)
//  2. N transactions, each: request → response (or exception response)
//  3. TCP 4-way teardown (FIN, FIN+ACK, FIN+ACK, ACK)
//
// Reference: Modbus.org MB-ASYM-TCP V1.1b3 / MODICON PI-MBUS-300 Rev. J
package modbus

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultPort (默认端口) is the canonical Modbus TCP port.
	DefaultPort = 502

	// DefaultTTL (默认TTL) used when spec.TTL is zero.
	DefaultTTL = 64

	// DefaultMSS (默认MSS) mirrors internal/protocol/tcp.DefaultMSS (1460).
	DefaultMSS = 1460

	// MBAPHeaderLen (MBAP头部长度) is the fixed 7-byte MBAP header size.
	MBAPHeaderLen = 7

	// ProtocolID (协议标识符) is always 0x0000 for Modbus.
	ProtocolID = 0x0000

	// MaxPDULen (最大PDU长度) per Modbus spec §2.6.
	MaxPDULen = 253

	// MaxTotalLen (最大总长度) MBAP + PDU.
	MaxTotalLen = 260

	// MaxUnitID (最大Unit ID) before reserved range.
	MaxUnitID = 247
)

// Planner implements the Modbus TCP protocol planner.
type Planner struct{}

// NewPlanner creates a new Modbus TCP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "modbus" }

// Validate validates a Modbus TCP flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.MODBUS == nil {
		return fmt.Errorf("modbus: MODBUS config is required")
	}

	cfg := spec.MODBUS

	// Validate top-level fields
	if cfg.MasterCount < 0 || cfg.MasterCount > 1000 {
		return fmt.Errorf("modbus: master_count must be 1-1000")
	}
	if cfg.FlowCount < 0 || cfg.FlowCount > 100 {
		return fmt.Errorf("modbus: flow_count must be 1-100")
	}

	// V-001: UnitID must be 0-247 (248-255 reserved).
	if cfg.UnitID != nil && *cfg.UnitID > MaxUnitID {
		return fmt.Errorf("modbus: unit_id %d is reserved (0-247)", *cfg.UnitID)
	}

	// Validate transactions if non-nil and non-empty
	if len(cfg.Transactions) > 0 {
		for i, tx := range cfg.Transactions {
			if err := p.validateOperation(&tx, cfg); err != nil {
				return fmt.Errorf("modbus: transaction %d: %w", i, err)
			}
		}
	}

	return nil
}

// Plan generates packet configs for a Modbus TCP flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	cfg := spec.MODBUS
	if cfg == nil {
		cfg = &core.MODBUSConfig{}
	}

	// Default values
	masterCount := cfg.MasterCount
	if masterCount <= 0 {
		masterCount = 1
	}
	flowCount := cfg.FlowCount
	if flowCount <= 0 {
		flowCount = 1
	}

	// Build transaction list; nil → inject 1 default transaction
	transactions := cfg.Transactions
	if transactions == nil {
		transactions = []core.MODBUSOperation{{FunctionCode: 0x03, Quantity: 1}}
	}

	go func() {
		defer close(configChan)

		for m := 0; m < masterCount; m++ {
			for f := 0; f < flowCount; f++ {
				if err := p.planFlow(ctx, spec, cfg, transactions, configChan, m, f, flowCount); err != nil {
					return
				}
			}
		}
	}()

	return configChan, nil
}

// supportedFCs (支持的功能码集合) §1.3
var supportedFCs = map[uint8]struct{}{
	0x01: {}, 0x02: {}, 0x03: {}, 0x04: {}, 0x05: {}, 0x06: {},
	0x07: {}, 0x08: {}, 0x0B: {}, 0x0C: {}, 0x0F: {}, 0x10: {},
	0x11: {}, 0x14: {}, 0x15: {}, 0x16: {}, 0x17: {}, 0x18: {}, 0x2B: {},
}

// exceptionCodes (合法异常码集合) §2.5
var exceptionCodes = map[uint8]struct{}{
	0x01: {}, 0x02: {}, 0x03: {}, 0x04: {}, 0x05: {}, 0x06: {},
	0x07: {}, 0x08: {}, 0x0A: {}, 0x0B: {},
}

// writeFCs (纯写功能码) §4.4
var writeFCs = map[uint8]struct{}{
	0x05: {}, 0x06: {}, 0x0F: {}, 0x10: {}, 0x15: {}, 0x16: {},
}

// readFCs (读类功能码，广播时拒绝)
var readFCs = map[uint8]struct{}{
	0x01: {}, 0x02: {}, 0x03: {}, 0x04: {}, 0x07: {}, 0x08: {},
	0x0B: {}, 0x0C: {}, 0x11: {}, 0x14: {}, 0x17: {}, 0x18: {}, 0x2B: {},
}

// validateOperation validates a single Modbus operation.
func (p *Planner) validateOperation(op *core.MODBUSOperation, cfg *core.MODBUSConfig) error {
	fc := op.FunctionCode

	// V-103: exemption path for unsupported FC + ExceptionCode != 0
	// This check must come before V-102 because FC with high bit set
	// are allowed in exemption path (e.g., 0x99 | 0x80 = 0x99 idempotent)
	if _, ok := supportedFCs[fc]; !ok {
		if op.ExceptionCode != 0 {
			// Exemption: validate exception code is legal
			if _, ok2 := exceptionCodes[op.ExceptionCode]; !ok2 {
				return fmt.Errorf("invalid exception code 0x%02X", op.ExceptionCode)
			}
			return nil
		}
		// V-102: FC high bit must not be set (only for non-exemption)
		if fc&0x80 != 0 {
			return fmt.Errorf("function code high bit must not be set")
		}
		return fmt.Errorf("unsupported function code 0x%02X", fc)
	}

	// V-102: FC high bit must not be set (for supported FCs)
	if fc&0x80 != 0 {
		return fmt.Errorf("function code high bit must not be set")
	}

	// V-122: validate exception code (0x00 means unset, is valid)
	if op.ExceptionCode != 0 {
		if _, ok := exceptionCodes[op.ExceptionCode]; !ok {
			return fmt.Errorf("invalid exception code 0x%02X", op.ExceptionCode)
		}
	}

	// V-120: ExceptionCode and ResponseValues are mutually exclusive
	if op.ExceptionCode != 0 && len(op.ResponseValues) > 0 {
		return fmt.Errorf("exception_code and response_values are mutually exclusive")
	}

	// V-002: broadcast + read FC validation
	unitID := getUnitID(cfg)
	if unitID == 0 {
		if _, ok := writeFCs[fc]; !ok {
			return fmt.Errorf("broadcast (unit_id=0) is only valid for write function codes")
		}
	}

	switch fc {
	case 0x01, 0x02:
		// §8.3: quantity=0 is semantically illegal; a legal exception code
		// backs it (request still carries quantity=0 on the wire).
		if op.Quantity < 1 || op.Quantity > 2000 {
			if op.ExceptionCode != 0 {
				return nil
			}
			return fmt.Errorf("quantity must be 1-2000")
		}
	case 0x03, 0x04:
		if op.Quantity < 1 || op.Quantity > 125 {
			if op.ExceptionCode != 0 {
				return nil
			}
			return fmt.Errorf("quantity must be 1-125")
		}
	case 0x05:
		// V-116: WriteValue validation
		if op.ExceptionCode == 0 {
			wv := op.WriteValue
			if wv != 0 && wv != 1 && wv != 0xFF00 && wv != 0x0000 {
				return fmt.Errorf("write_value must be 0/1/0xFF00/0x0000 or set exception_code")
			}
		}
	case 0x0F:
		if op.Quantity < 1 || op.Quantity > 1968 {
			if op.ExceptionCode != 0 {
				return nil
			}
			return fmt.Errorf("quantity must be 1-1968")
		}
		// V-111: Values length must be ceil(quantity/8)
		expectedLen := (int(op.Quantity) + 7) / 8
		if len(op.Values) != expectedLen {
			return fmt.Errorf("values length must be ceil(quantity/8)")
		}
	case 0x10:
		if op.Quantity < 1 || op.Quantity > 123 {
			if op.ExceptionCode != 0 {
				return nil
			}
			return fmt.Errorf("quantity must be 1-123")
		}
		// V-112: Values length must be quantity*2
		if len(op.Values) != int(op.Quantity)*2 {
			return fmt.Errorf("values length must be quantity*2")
		}
	case 0x08:
		// V-117: SubFunction 0x0000-0x0015, 0x0005-0x0009 reserved
		if op.SubFunction > 0x0015 {
			return fmt.Errorf("sub_function must be 0x0000-0x0015")
		}
		if op.SubFunction >= 0x0005 && op.SubFunction <= 0x0009 {
			return fmt.Errorf("sub_function 0x0005-0x0009 reserved")
		}
	case 0x0B, 0x0C, 0x11:
		// No additional data fields
	case 0x14:
		// V-114: Validate items (each item is 7 bytes: RefType(1)+File(2)+Record(2)+RecLen(2))
		if len(op.Values) > 0 {
			if len(op.Values)%7 != 0 {
				return fmt.Errorf("values length for FC 0x14 must be a multiple of 7")
			}
			for i := 0; i < len(op.Values); i += 7 {
				recLen := binary.BigEndian.Uint16(op.Values[i+5 : i+7])
				if recLen < 1 {
					return fmt.Errorf("record length must be >= 1")
				}
			}
		}
	case 0x15:
		// V-115: Validate items (each item: RefType(1)+File(2)+Record(2)+RecLen(2)+Data)
		// For FC 0x15, Values already includes the outer Byte Count as first byte.
		// Items start at offset 1.
		if len(op.Values) > 0 {
			if len(op.Values) < 2 {
				return fmt.Errorf("FC 0x15 values must contain byte count + items")
			}
			outerByteCount := int(op.Values[0])
			if outerByteCount+1 != len(op.Values) {
				return fmt.Errorf("FC 0x15 outer byte count mismatch: %d vs %d", outerByteCount, len(op.Values)-1)
			}
			// Validate dynamic stepping starting after outer BC
			idx := 1
			for idx < len(op.Values) {
				if idx+7 > len(op.Values) {
					return fmt.Errorf("item length mismatch")
				}
				if op.Values[idx] != 0x06 {
					return fmt.Errorf("FC 0x15 item must start with Reference Type=0x06")
				}
				recLen := binary.BigEndian.Uint16(op.Values[idx+5 : idx+7])
				if recLen < 1 {
					return fmt.Errorf("record length must be >= 1")
				}
				itemLen := 7 + int(recLen)*2
				if idx+itemLen > len(op.Values) {
					return fmt.Errorf("item length mismatch")
				}
				idx += itemLen
			}
			if idx != len(op.Values) {
				return fmt.Errorf("item length mismatch")
			}
		}
	case 0x16:
		// No additional validation needed
	case 0x17:
		// V-109, V-110: ReadQuantity and WriteQuantity must be explicit.
		// §8.3: a legal exception code backs semantically illegal values
		// (request keeps the explicit quantities on the wire).
		if op.ReadQuantity < 1 || op.ReadQuantity > 125 {
			if op.ExceptionCode != 0 {
				return nil
			}
			return fmt.Errorf("read_quantity must be explicit and 1-125")
		}
		if op.WriteQuantity < 1 || op.WriteQuantity > 121 {
			if op.ExceptionCode != 0 {
				return nil
			}
			return fmt.Errorf("write_quantity must be explicit and 1-121")
		}
		// V-113: Values length must be WriteQuantity*2
		if len(op.Values) != int(op.WriteQuantity)*2 {
			return fmt.Errorf("values length must be write_quantity*2")
		}
	case 0x18:
		// V-119: FIFO Count validation (from ResponseValues).
		// RV layout: Byte Count(2) + FIFO Count(2) + Values(2N); with
		// ExceptionCode backing, the checks are skipped (§8.3).
		if op.ExceptionCode == 0 && len(op.ResponseValues) > 0 {
			if len(op.ResponseValues) < 4 {
				return fmt.Errorf("response_values length must match FIFO count")
			}
			fifoCount := binary.BigEndian.Uint16(op.ResponseValues[2:4])
			if fifoCount > 31 {
				return fmt.Errorf("FIFO count exceeds 31")
			}
			valueBytes := len(op.ResponseValues) - 4 // after FIFO Count
			if valueBytes != int(fifoCount)*2 {
				return fmt.Errorf("response_values length must match FIFO count")
			}
		}
	case 0x2B:
		// V-118: MEI Type must be 0x000E
		if op.SubFunction&0xFF00 != 0 {
			return fmt.Errorf("FC 0x2B sub_function high byte must be 0")
		}
		if op.SubFunction != 0x000E {
			return fmt.Errorf("FC 0x2B sub_function must be 0x000E")
		}
	}

	// ResponseValues must satisfy the FC-specific length formula (§8.4).
	// Exception-backed ops skip the check (the §8.3 backing applies).
	if op.ExceptionCode == 0 {
		if err := validateResponseValues(op); err != nil {
			return err
		}
	}

	return nil
}

// getUnitID returns the effective Unit ID (default 1 if nil).
func getUnitID(cfg *core.MODBUSConfig) uint8 {
	if cfg.UnitID == nil {
		return 1
	}
	return *cfg.UnitID
}

// getResponseMode returns the effective response mode.
func getResponseMode(op *core.MODBUSOperation) string {
	if op.ResponseMode == "" {
		return "normal"
	}
	return op.ResponseMode
}

// planFlow generates packets for a single Modbus TCP flow (一个主站+一个流).
//
// Packet sequence (TCP 携带 MBAP 帧):
//
//   1. TCP 三次握手: SYN(up) → SYN-ACK(down) → ACK(up)
//   2. 每个事务: 请求 PSH-ACK(up) + 响应 PSH-ACK(down)
//      响应可由 ResponseMode / broadcast suppress / Force Listen Only 抑制
//   3. TCP 四次挥手: FIN-ACK(up) → ACK(down) → FIN-ACK(down) → ACK(up)
//
// Seq 推进规则 (与 sip/rtsp 一致):
//   - SYN/SYN-ACK 各消耗 1 个序号 (SYN flag 占用 1B 序号空间)
//   - 数据包 PSH-ACK 按 payload 长度推进 clientSeq/serverSeq
//   - FIN/FIN-ACK 各消耗 1 个序号
//
// flowID 使用 4-tuple 格式 ("srcIP-dstIP-srcPort-dstPort"),与 sip/rtsp 一致,
// 保证 PacketWorker 按流分组 + 重排序器按流识别.
//
// TID (MBAP Transaction ID) 策略:
//   - SharedTIDSpace=true: 全局计数器,每事务 +1 (跨 master/flow)
//   - SharedTIDSpace=false (默认): 每流独立计数器,从 0 开始
//
// ctx 取消检查: 每次向 configChan 发送前用 select 探测 ctx.Done(),
// 任一握手/事务/挥手包发射前均可被取消.
func (p *Planner) planFlow(ctx context.Context, spec core.FlowSpec, cfg *core.MODBUSConfig,
	transactions []core.MODBUSOperation, configChan chan<- core.PacketConfig, masterIdx, flowIdx, flowCount int) error {

	// ---- 4-tuple 解析 ----
	srcIP := spec.SrcIP
	dstIP := spec.DstIP
	srcPort := spec.SrcPort
	dstPort := spec.DstPort
	if dstPort == 0 {
		dstPort = DefaultPort
	}

	// ---- 唯一 4-tuple 派生 ----
	// 每个 master×flow 组合必须拥有独立的 srcPort,否则 PacketWorker 会把
	// 多个流当成同一连接,导致 Seq/Ack/TID 交错污染.
	// 派生规则: baseSrcPort + (masterIdx * flowCount + flowIdx),
	// 其中 baseSrcPort = spec.SrcPort (显式) 或 20000 (默认,ephemeral 区段).
	// uint16 wrap 自然处理,溢出回绕由原子递增的语义承担.
	baseSrcPort := spec.SrcPort
	if baseSrcPort == 0 {
		baseSrcPort = 20000
	}
	srcPort = baseSrcPort + uint16(masterIdx*flowCount+flowIdx)

	// ---- flowID: 4-tuple 格式,与 sip/rtsp 对齐 ----
	flowID := fmt.Sprintf("%s-%s-%d-%d", srcIP, dstIP, srcPort, dstPort)

	// ---- L2/L3/L4 参数 ----
	effectiveTTL := spec.TTL
	if effectiveTTL == 0 {
		effectiveTTL = DefaultTTL
	}
	winSize := uint16(65535)

	// ---- ISN (RFC 6528 随机初始序号) ----
	// user 可通过 spec.TCP.InitialSeq 覆盖以获得可复现的测试流
	clientSeq := uint32(0)
	if spec.TCP != nil {
		clientSeq = spec.TCP.InitialSeq
	}
	if clientSeq == 0 {
		clientSeq = rand.Uint32()
	}
	serverSeq := rand.Uint32()

	// ---- IPID 计数器: 随机初始 + 每包 +1 ----
	ipID := uint16(rand.Uint32())
	nextIPID := func() uint16 {
		id := ipID
		ipID++
		return id
	}

	// ---- 时间戳 + packetIndex (与 sip/rtsp 对齐) ----
	now := time.Now()
	packetIndex := uint64(0)

	// ---- TID 策略 ----
	// SharedTIDSpace=true → 全局共享计数器 (跨 master+flow 单调递增)
	// SharedTIDSpace=false → 每流独立 (从 0 开始)
	var localTID uint16 // 当 SharedTIDSpace=false 时使用
	getTID := func() uint16 {
		if cfg.SharedTIDSpace {
			return nextGlobalTID()
		}
		t := localTID
		localTID++
		return t
	}

	// ---- emit 闭包 ----
	// 封装一次 L2/L3/L4 头构造 + 计数推进 + ctx 探测 + configChan 发送.
	// flags=0x02 或 0x12 (SYN/SYN-ACK) 时携带 MSS/WinScale/SACK 选项.
	emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16,
		seq, ack uint32, flags uint8, payload []byte) {

		l3 := core.L3Base(srcIP, dstIP, 6, effectiveTTL, nextIPID(), spec)
		l4 := core.L4Config{
			Protocol:   "tcp",
			SrcPort:    srcPort,
			DstPort:    dstPort,
			Seq:        seq,
			Ack:        ack,
			Flags:      flags,
			WindowSize: winSize,
		}
		if flags == 0x02 || flags == 0x12 {
			l4.TCPOptions = synOptions(DefaultMSS)
		}
		cfg := core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: packetIndex,
			Direction:   direction,
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    srcMAC,
				DstMAC:    dstMAC,
				EtherType: core.EtherTypeFor(srcIP),
			},
			L3:      l3,
			L4:      l4,
			Payload: payload,
		}
		select {
		case <-ctx.Done():
			return
		case configChan <- cfg:
			packetIndex++
		}
	}

	// ---- TCP 三次握手 ----
	// SYN (client → server)
	emit("up", spec.SrcMAC, spec.DstMAC, srcIP, dstIP, srcPort, dstPort, clientSeq, 0, 0x02, nil)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	clientSeq++ // SYN 占用 1 个序号
	// SYN-ACK (server → client)
	emit("down", spec.DstMAC, spec.SrcMAC, dstIP, srcIP, dstPort, srcPort, serverSeq, clientSeq, 0x12, nil)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	serverSeq++ // SYN 占用 1 个序号
	// ACK (client → server)
	emit("up", spec.SrcMAC, spec.DstMAC, srcIP, dstIP, srcPort, dstPort, clientSeq, serverSeq, 0x10, nil)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// ---- N 个 Modbus 事务 ----
	// 每个事务: 请求 PSH-ACK(up) + 响应 PSH-ACK(down,除非 shouldGenerateResponse 返回 false)
	// 每个事务只调用 getTID() 一次,req 和 resp 共享同一 TID (§2.3 事务匹配语义).
	unitID := getUnitID(cfg)
	for _, tx := range transactions {
		// 构建请求 PDU → MBAP 帧 (req 与 resp 共享同一 TID)
		reqPDU := buildRequestPDU(&tx)
		txTID := getTID()
		reqFrame := BuildMBAPFrame(txTID, unitID, reqPDU)

		// 请求 (client → server): PSH-ACK
		emit("up", spec.SrcMAC, spec.DstMAC, srcIP, dstIP, srcPort, dstPort,
			clientSeq, serverSeq, 0x18, reqFrame)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		clientSeq += uint32(len(reqFrame))

		// 响应 (server → client): PSH-ACK (除非抑制),复用同一 TID
		if shouldGenerateResponse(&tx, cfg) {
			respPDU := buildResponsePDU(&tx)
			respFrame := BuildMBAPFrame(txTID, unitID, respPDU)
			emit("down", spec.DstMAC, spec.SrcMAC, dstIP, srcIP, dstPort, srcPort,
				serverSeq, clientSeq, 0x18, respFrame)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			serverSeq += uint32(len(respFrame))
		}
	}

	// ---- TCP 四次挥手 ----
	// Client FIN-ACK
	emit("up", spec.SrcMAC, spec.DstMAC, srcIP, dstIP, srcPort, dstPort, clientSeq, serverSeq, 0x11, nil)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	clientSeq++ // FIN 占用 1 个序号
	// Server ACK
	emit("down", spec.DstMAC, spec.SrcMAC, dstIP, srcIP, dstPort, srcPort, serverSeq, clientSeq, 0x10, nil)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Server FIN-ACK
	emit("down", spec.DstMAC, spec.SrcMAC, dstIP, srcIP, dstPort, srcPort, serverSeq, clientSeq, 0x11, nil)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	serverSeq++ // FIN 占用 1 个序号
	// Client ACK
	emit("up", spec.SrcMAC, spec.DstMAC, srcIP, dstIP, srcPort, dstPort, clientSeq, serverSeq, 0x10, nil)

	return ctx.Err()
}

// shouldGenerateResponse determines if a response should be generated.
func shouldGenerateResponse(op *core.MODBUSOperation, cfg *core.MODBUSConfig) bool {
	// ResponseMode=no_response → no response
	if getResponseMode(op) == "no_response" {
		return false
	}

	// Diagnostic sub-function 0x0004 Force Listen Only Mode: the slave
	// enters listen-only and sends NO response (§3.3.6 / §4.1).
	if op.FunctionCode == 0x08 && op.SubFunction == 0x0004 {
		return false
	}

	// Broadcast + SuppressBroadcast=true → no response (including exceptions)
	unitID := getUnitID(cfg)
	if unitID == 0 && cfg.SuppressBroadcast {
		return false
	}

	return true
}

// validateResponseValues cross-checks the length of a ResponseValues
// override against the FC-specific formula (§8.4). Returns nil when the
// override is absent (planner auto-construction handles the FC).
func validateResponseValues(op *core.MODBUSOperation) error {
	if len(op.ResponseValues) == 0 {
		return nil
	}
	switch op.FunctionCode {
	case 0x01, 0x02:
		if len(op.ResponseValues) != 1+(int(op.Quantity)+7)/8 {
			return fmt.Errorf("response_values length for FC 0x%02X must be 1 + ceil(quantity/8)", op.FunctionCode)
		}
	case 0x03, 0x04:
		if len(op.ResponseValues) != 1+int(op.Quantity)*2 {
			return fmt.Errorf("response_values length for FC 0x%02X must be 1 + quantity*2", op.FunctionCode)
		}
	case 0x07:
		if len(op.ResponseValues) != 1 {
			return fmt.Errorf("response_values length for FC 0x07 must be 1 (exception status)")
		}
	case 0x0B:
		if len(op.ResponseValues) != 4 {
			return fmt.Errorf("response_values length for FC 0x0B must be 4 (status + event count)")
		}
	case 0x0C:
		if len(op.ResponseValues) < 7 {
			return fmt.Errorf("response_values length for FC 0x0C must be 1 + 6 + N")
		}
	case 0x0F, 0x10:
		if len(op.ResponseValues) != 4 {
			return fmt.Errorf("response_values length for FC 0x%02X must be 4 (address + quantity)", op.FunctionCode)
		}
	case 0x11:
		if len(op.ResponseValues) < 2 {
			return fmt.Errorf("response_values length for FC 0x11 must be 2 + N (slave id + run indicator)")
		}
	case 0x14:
		// Outer Byte Count(1) + items; every item = 2 + 2*RL (R3-C1).
		items := op.ResponseValues[1:]
		if len(items)%2 != 0 {
			return fmt.Errorf("response_values length for FC 0x14 must be 1 + sum(item lengths)")
		}
		for i := 0; i+1 < len(items); {
			itemLen := 2 + 2*(int(items[i])-1)
			if itemLen < 2 || i+itemLen > len(items) {
				return fmt.Errorf("response_values length for FC 0x14 must be 1 + sum(item lengths)")
			}
			i += itemLen
		}
	case 0x15:
		// Echo of the request: outer Byte Count(1) + items; formula
		// 1 + Σ(7+2×RL) (§8.4 R4-C1). The override is optional — when
		// present it must at least carry a Byte Count + one item.
		if len(op.ResponseValues) < 2 {
			return fmt.Errorf("response_values length for FC 0x15 must be 1 + sum(7+2*record_length)")
		}
	case 0x17:
		if len(op.ResponseValues) != 1+int(op.ReadQuantity)*2 {
			return fmt.Errorf("response_values length for FC 0x17 must be 1 + read_quantity*2")
		}
	case 0x18:
		// V-119 already validates the FIFO layout; skip here (Byte Count
		// is recomputed by the planner).
	default:
		// 0x05/0x06/0x16 echo, 0x08 sub-function specific, 0x2B MEI.
	}
	return nil
}

// buildRequestPDU builds the request PDU for a Modbus operation.
func buildRequestPDU(op *core.MODBUSOperation) []byte {
	// §1.3 exemption path: unsupported FC → request bytes are passed
	// through verbatim (FC only when no Values are configured).
	if _, ok := supportedFCs[op.FunctionCode]; !ok {
		if len(op.Values) > 0 {
			pdu := make([]byte, 1+len(op.Values))
			pdu[0] = op.FunctionCode
			copy(pdu[1:], op.Values)
			return pdu
		}
		return []byte{op.FunctionCode}
	}

	// If ExceptionCode is set, build normal request PDU (per §4.1 design point 4)
	// The response will be replaced with exception PDU.

	switch op.FunctionCode {
	case 0x01, 0x02:
		return buildReadBitsRequest(op)
	case 0x03, 0x04:
		return buildReadRegistersRequest(op)
	case 0x05:
		return buildWriteSingleCoilRequest(op)
	case 0x06:
		return buildWriteSingleRegisterRequest(op)
	case 0x07:
		return []byte{0x07}
	case 0x08:
		return buildDiagnosticRequest(op)
	case 0x0B:
		return []byte{0x0B}
	case 0x0C:
		return []byte{0x0C}
	case 0x0F:
		return buildWriteMultipleCoilsRequest(op)
	case 0x10:
		return buildWriteMultipleRegistersRequest(op)
	case 0x11:
		return []byte{0x11}
	case 0x14:
		return buildReadFileRecordsRequest(op)
	case 0x15:
		return buildWriteFileRecordsRequest(op)
	case 0x16:
		return buildMaskWriteRegisterRequest(op)
	case 0x17:
		return buildReadWriteMultipleRegistersRequest(op)
	case 0x18:
		return buildReadFIFORequest(op)
	case 0x2B:
		return buildMEIRequest(op)
	default:
		return []byte{op.FunctionCode}
	}
}

// buildResponsePDU builds the response PDU for a Modbus operation.
func buildResponsePDU(op *core.MODBUSOperation) []byte {
	// Exception response: FC|0x80 + ExceptionCode (§3.4; idempotent when
	// bit7 is already set, e.g. the exemption path's 0x99|0x80=0x99).
	if op.ExceptionCode != 0 {
		return []byte{op.FunctionCode | 0x80, op.ExceptionCode}
	}

	switch op.FunctionCode {
	case 0x01, 0x02:
		return buildReadBitsResponse(op)
	case 0x03, 0x04:
		return buildReadRegistersResponse(op)
	case 0x05, 0x06:
		return buildRequestPDU(op) // echo
	case 0x07:
		return buildReadExceptionStatusResponse(op)
	case 0x08:
		return buildDiagnosticResponse(op)
	case 0x0B:
		return buildCommEventCounterResponse(op)
	case 0x0C:
		return buildCommEventLogResponse(op)
	case 0x0F, 0x10:
		return buildWriteMultipleResponse(op)
	case 0x11:
		return buildReportServerIDResponse(op)
	case 0x14:
		return buildReadFileRecordsResponse(op)
	case 0x15:
		return buildWriteFileRecordsResponse(op)
	case 0x16:
		return buildRequestPDU(op) // echo
	case 0x17:
		return buildReadWriteMultipleRegistersResponse(op)
	case 0x18:
		return buildReadFIFOResponse(op)
	case 0x2B:
		return buildMEIResponse(op)
	default:
		return buildRequestPDU(op) // echo
	}
}

// --- Request PDU builders ---

func buildReadBitsRequest(op *core.MODBUSOperation) []byte {
	pdu := make([]byte, 5)
	pdu[0] = op.FunctionCode
	binary.BigEndian.PutUint16(pdu[1:3], op.StartingAddress)
	binary.BigEndian.PutUint16(pdu[3:5], op.Quantity)
	return pdu
}

func buildReadRegistersRequest(op *core.MODBUSOperation) []byte {
	pdu := make([]byte, 5)
	pdu[0] = op.FunctionCode
	binary.BigEndian.PutUint16(pdu[1:3], op.StartingAddress)
	binary.BigEndian.PutUint16(pdu[3:5], op.Quantity)
	return pdu
}

func buildWriteSingleCoilRequest(op *core.MODBUSOperation) []byte {
	pdu := make([]byte, 5)
	pdu[0] = op.FunctionCode
	binary.BigEndian.PutUint16(pdu[1:3], op.StartingAddress)
	// §2.3: 0/1 remap to 0x0000/0xFF00 at Plan time; other values pass
	// through as configured (legal when an ExceptionCode backs them).
	val := op.WriteValue
	if val == 1 {
		val = 0xFF00
	}
	binary.BigEndian.PutUint16(pdu[3:5], val)
	return pdu
}

func buildWriteSingleRegisterRequest(op *core.MODBUSOperation) []byte {
	pdu := make([]byte, 5)
	pdu[0] = op.FunctionCode
	binary.BigEndian.PutUint16(pdu[1:3], op.StartingAddress)
	binary.BigEndian.PutUint16(pdu[3:5], op.WriteValue)
	return pdu
}

func buildDiagnosticRequest(op *core.MODBUSOperation) []byte {
	// FC + SubFunction(2) + Values
	pdu := make([]byte, 3+len(op.Values))
	pdu[0] = op.FunctionCode
	binary.BigEndian.PutUint16(pdu[1:3], op.SubFunction)
	copy(pdu[3:], op.Values)
	return pdu
}

func buildWriteMultipleCoilsRequest(op *core.MODBUSOperation) []byte {
	pdu := make([]byte, 6+len(op.Values))
	pdu[0] = op.FunctionCode
	binary.BigEndian.PutUint16(pdu[1:3], op.StartingAddress)
	binary.BigEndian.PutUint16(pdu[3:5], op.Quantity)
	pdu[5] = uint8(len(op.Values)) // Byte Count
	copy(pdu[6:], op.Values)
	return pdu
}

func buildWriteMultipleRegistersRequest(op *core.MODBUSOperation) []byte {
	pdu := make([]byte, 6+len(op.Values))
	pdu[0] = op.FunctionCode
	binary.BigEndian.PutUint16(pdu[1:3], op.StartingAddress)
	binary.BigEndian.PutUint16(pdu[3:5], op.Quantity)
	pdu[5] = uint8(len(op.Values)) // Byte Count
	copy(pdu[6:], op.Values)
	return pdu
}

func buildReadFileRecordsRequest(op *core.MODBUSOperation) []byte {
	// Values already contains the request data items (7 bytes each)
	// PDU = FC + Byte Count + Items
	pdu := make([]byte, 2+len(op.Values))
	pdu[0] = op.FunctionCode
	pdu[1] = uint8(len(op.Values)) // Byte Count = len(Items)
	copy(pdu[2:], op.Values)
	return pdu
}

func buildWriteFileRecordsRequest(op *core.MODBUSOperation) []byte {
	// Values already contains the request data (Byte Count + Items)
	// PDU = FC + Byte Count + Items
	pdu := make([]byte, 1+len(op.Values))
	pdu[0] = op.FunctionCode
	copy(pdu[1:], op.Values)
	return pdu
}

func buildMaskWriteRegisterRequest(op *core.MODBUSOperation) []byte {
	pdu := make([]byte, 7)
	pdu[0] = op.FunctionCode
	binary.BigEndian.PutUint16(pdu[1:3], op.StartingAddress)
	binary.BigEndian.PutUint16(pdu[3:5], op.MaskAnd)
	binary.BigEndian.PutUint16(pdu[5:7], op.MaskOr)
	return pdu
}

func buildReadWriteMultipleRegistersRequest(op *core.MODBUSOperation) []byte {
	writeAddr := op.WriteAddress
	if writeAddr == 0 {
		// Fallback: StartingAddress + WriteQuantity (uint16 wrap)
		writeAddr = op.StartingAddress + op.WriteQuantity
	}
	pdu := make([]byte, 10+len(op.Values))
	pdu[0] = op.FunctionCode
	binary.BigEndian.PutUint16(pdu[1:3], op.ReadAddress)
	binary.BigEndian.PutUint16(pdu[3:5], op.ReadQuantity)
	binary.BigEndian.PutUint16(pdu[5:7], writeAddr)
	binary.BigEndian.PutUint16(pdu[7:9], op.WriteQuantity)
	pdu[9] = uint8(len(op.Values)) // Write Byte Count
	copy(pdu[10:], op.Values)
	return pdu
}

func buildReadFIFORequest(op *core.MODBUSOperation) []byte {
	pdu := make([]byte, 3)
	pdu[0] = op.FunctionCode
	binary.BigEndian.PutUint16(pdu[1:3], op.StartingAddress)
	return pdu
}

func buildMEIRequest(op *core.MODBUSOperation) []byte {
	pdu := make([]byte, 2+len(op.Values))
	pdu[0] = op.FunctionCode
	pdu[1] = uint8(op.SubFunction & 0xFF) // MEI Type
	copy(pdu[2:], op.Values)
	return pdu
}

// --- Response PDU builders ---

func buildReadBitsResponse(op *core.MODBUSOperation) []byte {
	if len(op.ResponseValues) > 0 {
		pdu := make([]byte, 1+len(op.ResponseValues))
		pdu[0] = op.FunctionCode
		copy(pdu[1:], op.ResponseValues)
		return pdu
	}
	// §3.3.1/§4.5: default bit data is all zeros (length-correct zeros).
	byteCount := (int(op.Quantity) + 7) / 8
	pdu := make([]byte, 2+byteCount)
	pdu[0] = op.FunctionCode
	pdu[1] = uint8(byteCount)
	return pdu
}

func buildReadRegistersResponse(op *core.MODBUSOperation) []byte {
	if len(op.ResponseValues) > 0 {
		pdu := make([]byte, 1+len(op.ResponseValues))
		pdu[0] = op.FunctionCode
		copy(pdu[1:], op.ResponseValues)
		return pdu
	}
	// §3.3.2/§4.5: default register values are all zeros.
	byteCount := int(op.Quantity) * 2
	pdu := make([]byte, 2+byteCount)
	pdu[0] = op.FunctionCode
	pdu[1] = uint8(byteCount)
	return pdu
}

func buildReadExceptionStatusResponse(op *core.MODBUSOperation) []byte {
	if len(op.ResponseValues) > 0 {
		pdu := make([]byte, 1+len(op.ResponseValues))
		pdu[0] = op.FunctionCode
		copy(pdu[1:], op.ResponseValues)
		return pdu
	}
	return []byte{op.FunctionCode, 0x00}
}

func buildDiagnosticResponse(op *core.MODBUSOperation) []byte {
	if len(op.ResponseValues) > 0 {
		pdu := make([]byte, 1+len(op.ResponseValues))
		pdu[0] = op.FunctionCode
		copy(pdu[1:], op.ResponseValues)
		return pdu
	}
	// §3.3.6: sub-function 0x0000 Return Query Data echoes the request;
	// other sub-functions return counters — inject via ResponseValues.
	return buildDiagnosticRequest(op)
}

func buildCommEventCounterResponse(op *core.MODBUSOperation) []byte {
	if len(op.ResponseValues) > 0 {
		pdu := make([]byte, 1+len(op.ResponseValues))
		pdu[0] = op.FunctionCode
		copy(pdu[1:], op.ResponseValues)
		return pdu
	}
	// Default: Status=0xFFFF, EventCount=0
	return []byte{op.FunctionCode, 0xFF, 0xFF, 0x00, 0x00}
}

func buildCommEventLogResponse(op *core.MODBUSOperation) []byte {
	if len(op.ResponseValues) > 0 {
		pdu := make([]byte, 1+len(op.ResponseValues))
		pdu[0] = op.FunctionCode
		copy(pdu[1:], op.ResponseValues)
		return pdu
	}
	// §3.3.8 default: Byte Count=6, Status=0xFFFF, EventCount=0,
	// MessageCount=0, Events empty (Byte Count = 6 + 0).
	return []byte{op.FunctionCode, 0x06, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}
}

func buildWriteMultipleResponse(op *core.MODBUSOperation) []byte {
	pdu := make([]byte, 5)
	pdu[0] = op.FunctionCode
	binary.BigEndian.PutUint16(pdu[1:3], op.StartingAddress)
	binary.BigEndian.PutUint16(pdu[3:5], op.Quantity)
	return pdu
}

func buildReportServerIDResponse(op *core.MODBUSOperation) []byte {
	if len(op.ResponseValues) > 0 {
		pdu := make([]byte, 1+len(op.ResponseValues))
		pdu[0] = op.FunctionCode
		copy(pdu[1:], op.ResponseValues)
		return pdu
	}
	// Default: Slave ID=0x01, Run Indicator=0xFF
	return []byte{op.FunctionCode, 0x01, 0xFF}
}

func buildReadFileRecordsResponse(op *core.MODBUSOperation) []byte {
	if len(op.ResponseValues) > 0 {
		pdu := make([]byte, 1+len(op.ResponseValues))
		pdu[0] = op.FunctionCode
		copy(pdu[1:], op.ResponseValues)
		return pdu
	}
	// §3.3.12: response items are File Response Length(1) + RefType(1) +
	// Record Data; no auto-derivable default → empty Byte Count=0.
	return []byte{op.FunctionCode, 0x00}
}

func buildWriteFileRecordsResponse(op *core.MODBUSOperation) []byte {
	if len(op.ResponseValues) > 0 {
		pdu := make([]byte, 1+len(op.ResponseValues))
		pdu[0] = op.FunctionCode
		copy(pdu[1:], op.ResponseValues)
		return pdu
	}
	return buildRequestPDU(op) // echo
}

func buildReadWriteMultipleRegistersResponse(op *core.MODBUSOperation) []byte {
	if len(op.ResponseValues) > 0 {
		pdu := make([]byte, 1+len(op.ResponseValues))
		pdu[0] = op.FunctionCode
		copy(pdu[1:], op.ResponseValues)
		return pdu
	}
	// §3.3.15/§4.5: default read register values are all zeros.
	byteCount := int(op.ReadQuantity) * 2
	pdu := make([]byte, 2+byteCount)
	pdu[0] = op.FunctionCode
	pdu[1] = uint8(byteCount)
	return pdu
}

func buildReadFIFOResponse(op *core.MODBUSOperation) []byte {
	if len(op.ResponseValues) > 0 {
		// §3.3.16 / R4-H4: Byte Count is recomputed by the planner as
		// 2 + 2×FIFO Count, so a user-supplied stale Byte Count in the
		// ResponseValues cannot produce an inconsistent frame.
		fifoCount := binary.BigEndian.Uint16(op.ResponseValues[2:4])
		pdu := make([]byte, 1+len(op.ResponseValues))
		pdu[0] = op.FunctionCode
		binary.BigEndian.PutUint16(pdu[1:3], uint16(2+2*int(fifoCount)))
		copy(pdu[3:], op.ResponseValues[2:])
		return pdu
	}
	// §3.3.16 default: Byte Count=2, FIFO Count=0.
	return []byte{op.FunctionCode, 0x00, 0x02, 0x00, 0x00}
}

func buildMEIResponse(op *core.MODBUSOperation) []byte {
	if len(op.ResponseValues) > 0 {
		pdu := make([]byte, 1+len(op.ResponseValues))
		pdu[0] = op.FunctionCode
		copy(pdu[1:], op.ResponseValues)
		return pdu
	}
	// §3.3.17 default: MEI Type=0x0E, Read Device ID Code=0x01,
	// Conformity=0x01, More Follows=0x00, Next Object ID=0x00,
	// Object Count=1, Object {ID=0x00, Len=0x00, Value=empty}.
	return []byte{op.FunctionCode, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00}
}

// --- 流规划辅助函数 ---

// globalTIDCounter 全局原子计数器,用于 SharedTIDSpace=true 模式下跨
// master/flow 的 TID 全局单调递增. uint16 wrap-around 由原子加法自然处理.
// 不需要初始化值 (从 0 开始,与 per-flow 计数器行为一致).
var globalTIDCounter uint32

// nextGlobalTID 取下一个全局 TID 并返回其 uint16 表示.
// SharedTIDSpace 模式下所有流的每个事务共享这个递增序列,
// 保证跨流的事务匹配可见性与 Wireshark 解析一致性.
// 首次调用返回 0 (与 per-flow localTID 行为对齐),通过 atomic.Add 返回
// 前减去 1 实现: post-increment 返回 N,则实际 TID = N-1.
func nextGlobalTID() uint16 {
	return uint16(atomic.AddUint32(&globalTIDCounter, 1)) - 1
}

// synOptions 构造 SYN/SYN-ACK 携带的 TCP 选项: MSS + Window Scale + SACK-Permitted.
// 与 sip.go / rtsp.go 的 synOptions 一致,镜像 protocol/tcp.DefaultMSS (1460),
// 复制到本包以避免循环导入.
// RFC 879 floor = 536; 1460 是以太网友好的常用值.
func synOptions(mss uint16) []core.TCPOption {
	if mss == 0 {
		mss = DefaultMSS
	}
	opts := make([]core.TCPOption, 0, 3)
	opts = append(opts, core.TCPOption{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptWinScale, Data: []byte{0x07}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptSACKPermit})
	return opts
}
