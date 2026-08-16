// Package enip implements the EtherNet/IP (ENIP) protocol planner.
// See types.go for data structures.
package enip

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultPort is the ENIP/TCP and ENIP/UDP port (IANA: 44818).
	DefaultPort = 44818

	// ENIP header size (24 bytes fixed).
	enipHeaderLen = 24

	// DefaultTTL and MSS.
	DefaultTTL = 64
	DefaultMSS = 1460
	MinMSS     = 536

	// TCP flags (mirror internal/protocol/rtsp).
	tcpSYN    = 0x02
	tcpSYNACK = 0x12
	tcpACK    = 0x10
	tcpPSHACK = 0x18
	tcpFINACK = 0x11
)

// --- ENIP Command constants (§2.2) ---
const (
	CmdNop             = 0x0000
	CmdListServices    = 0x0004
	CmdListIdentity    = 0x0063
	CmdListInterfaces  = 0x0064
	CmdRegisterSession = 0x0065
	CmdUnRegisterSession = 0x0066
	CmdSendRRData      = 0x006F
	CmdSendUnitData    = 0x0070
	CmdIndicateStatus  = 0x0072
	CmdCancel          = 0x0073
)

// --- ENIP Status constants (§2.3) ---
const (
	StatusSuccess              = 0x00000000
	StatusInvalidCommand       = 0x00000001
	StatusInsufficientMemory   = 0x00000002
	StatusIncorrectData        = 0x00000003
	StatusInvalidSessionHandle = 0x00000064
	StatusInvalidLength        = 0x00000065
	StatusUnsupportedProtocol  = 0x00000069
)

// --- CPF TypeID constants (§2.4.1) ---
const (
	TypeIDNullAddress        = 0x0000
	TypeIDListIdentityResp   = 0x000C
	TypeIDConnectionAddress  = 0x00A1
	TypeIDConnectedData      = 0x00B1
	TypeIDUnconnectedData    = 0x00B2
	TypeIDListServicesResp   = 0x0100
	TypeIDSockaddrO2T        = 0x8000
	TypeIDSockaddrT2O        = 0x8001
	TypeIDSequencedAddress   = 0x8002
)

// --- CIP Service constants (§2.5) ---
const (
	CIPGetAttributesAll      = 0x01
	CIPSetAttributesAll      = 0x02
	CIPGetAttributeList      = 0x03
	CIPSetAttributeList      = 0x04
	CIPReset                 = 0x05
	CIPStart                 = 0x06
	CIPStop                  = 0x07
	CIPCreate                = 0x08
	CIPDelete                = 0x09
	CIPMultipleServicePacket = 0x0A
	CIPApplyAttributes       = 0x0D
	CIPGetAttributeSingle    = 0x0E
	CIPSetAttributeSingle    = 0x10
	CIPFindNextObjectInstance = 0x11
	CIPRestore               = 0x15
	CIPSave                  = 0x16
	CIPNOP                   = 0x17
	CIPGetMember             = 0x18
	CIPSetMember             = 0x19
	CIPInsertMember          = 0x1A
	CIPRemoveMember          = 0x1B
	CIPGroupSync             = 0x1C
	CIPGetConnectionPointMemberList = 0x1D
	CIPForwardClose          = 0x4E
	CIPUnconnectedSend       = 0x52
	CIPForwardOpen           = 0x54
	CIPGetConnectionData     = 0x56
	CIPSearchConnectionData  = 0x57
	CIPGetConnectionOwner    = 0x5A
	CIPLargeForwardOpen      = 0x5B
)

// --- EPATH Segment constants (§2.7) ---
const (
	epathSegClass8bit         = 0x20
	epathSegClass16bit        = 0x21
	epathSegClass32bit        = 0x22
	epathSegInstance8bit      = 0x24
	epathSegInstance16bit     = 0x25
	epathSegInstance32bit     = 0x26
	epathSegMember8bit        = 0x28
	epathSegMember16bit       = 0x29
	epathSegConnectionPoint8bit  = 0x2C
	epathSegConnectionPoint16bit = 0x2D
	epathSegAttribute8bit     = 0x30
	epathSegAttribute16bit    = 0x31
	epathSegAttribute32bit    = 0x32
	epathSegService8bit       = 0x38
	epathSegService16bit      = 0x39
)

// --- Known commands set for validation ---
var knownCommands = map[uint16]bool{
	CmdNop:             true,
	CmdListServices:    true,
	CmdListIdentity:    true,
	CmdListInterfaces:  true,
	CmdRegisterSession: true,
	CmdUnRegisterSession: true,
	CmdSendRRData:      true,
	CmdSendUnitData:    true,
	CmdIndicateStatus:  true,
	CmdCancel:          true,
}

// --- Known CPF TypeIDs for validation ---
var knownCPFTypeIDs = map[uint16]bool{
	TypeIDNullAddress:       true,
	TypeIDListIdentityResp:  true,
	TypeIDConnectionAddress: true,
	TypeIDConnectedData:     true,
	TypeIDUnconnectedData:   true,
	TypeIDListServicesResp:  true,
	TypeIDSockaddrO2T:       true,
	TypeIDSockaddrT2O:     true,
	TypeIDSequencedAddress:  true,
}

// knownCIPServices is the set of CIP service codes accepted by V-112
// (design §8.2 V-112: CIPService 必须为已知服务码或 0).
// Covers Common Services (§2.5.1), Connection Manager services (§2.5.2)
// and PCCC/Logix services (§2.5.3).
var knownCIPServices = map[uint8]bool{
	CIPGetAttributesAll:      true,
	CIPSetAttributesAll:      true,
	CIPGetAttributeList:      true,
	CIPSetAttributeList:      true,
	CIPReset:                 true,
	CIPStart:                 true,
	CIPStop:                  true,
	CIPCreate:                true,
	CIPDelete:                true,
	CIPMultipleServicePacket: true,
	CIPApplyAttributes:       true,
	CIPGetAttributeSingle:    true,
	CIPSetAttributeSingle:    true,
	CIPFindNextObjectInstance: true,
	CIPRestore:               true,
	CIPSave:                  true,
	CIPNOP:                   true,
	CIPGetMember:             true,
	CIPSetMember:             true,
	CIPInsertMember:          true,
	CIPRemoveMember:          true,
	CIPGroupSync:             true,
	CIPGetConnectionPointMemberList: true,
	CIPForwardClose:          true,
	CIPUnconnectedSend:       true,
	CIPForwardOpen:           true,
	CIPGetConnectionData:     true,
	CIPSearchConnectionData:  true,
	CIPGetConnectionOwner:    true,
	CIPLargeForwardOpen:      true,
	0x4B:                     true, // Execute PCCC (§2.5.3)
	0x4C:                     true, // Read Tag (CIP_READ)
	0x4D:                     true, // Write Tag (CIP_WRITE)
	0x53:                     true, // Write Tag Fragmented (CIP_WRITE_FRAG)
	0x55:                     true, // List Tags (CIP_LIST_TAGS)
}

// Planner implements the ENIP protocol planner.
type Planner struct{}

// NewPlanner creates a new ENIP planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string {
	return "enip"
}

// Validate validates an ENIP flow spec.
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
	if spec.ENIP == nil {
		return fmt.Errorf("enip config is required")
	}
	cfg := spec.ENIP

	if cfg.Scenario != "" && cfg.Scenario != "full" && cfg.Scenario != "discovery_only" &&
		cfg.Scenario != "io_only" && cfg.Scenario != "forward_open_only" && cfg.Scenario != "custom" {
		return fmt.Errorf("enip: unknown scenario %q", cfg.Scenario)
	}
	if cfg.Transport != "" && cfg.Transport != "tcp" && cfg.Transport != "udp" {
		return fmt.Errorf("enip: transport must be tcp or udp, got %q", cfg.Transport)
	}
	if spec.DstPort != 0 && spec.DstPort != DefaultPort {
		return fmt.Errorf("enip: dst_port must be %d", DefaultPort)
	}
	// V-005/V-006（设计 §8.1）：SessionCount 1-1000、FlowCount 1-100。
	// 0 视为默认 1（未配置）；负数与超上限拒绝（否则 Plan 内循环静默
	// 不展开，任务以 0 包完成）。
	if cfg.SessionCount < 0 || cfg.SessionCount > 1000 {
		return fmt.Errorf("enip: session_count %d out of range (1-1000)", cfg.SessionCount)
	}
	if cfg.FlowCount < 0 || cfg.FlowCount > 100 {
		return fmt.Errorf("enip: flow_count %d out of range (1-100)", cfg.FlowCount)
	}

	for i, cmd := range cfg.Commands {
		if err := validateCommand(&cmd, i); err != nil {
			return err
		}
	}

	// M-3 (design §3.7/§8.2 V-114): Forward_Close 的 ConnectionPath 必须与同一
	// 连接的 Forward_Open 字节级一致。同一 flow 内按 (ConnSerialNum,
	// OrigVendorID, OrigSerialNum) 三元组配对（与 Forward_Close 定位连接的
	// 方式一致）；配对的 Forward_Open 未显式配置路径时使用其默认路径。
	// 若无配对 Forward_Open（独立 Forward_Close 场景），无法比对，跳过
	// （最小版实现，见报告说明）。
	for i, cmd := range cfg.Commands {
		if cmd.CIPService != CIPForwardClose {
			continue
		}
		if cmd.ConnSerialNum == 0 || cmd.OrigVendorID == 0 || cmd.OrigSerialNum == 0 {
			continue // 三元组不全，已由 validateCommand 拒绝
		}
		for j, open := range cfg.Commands {
			if open.CIPService != CIPForwardOpen && open.CIPService != CIPLargeForwardOpen {
				continue
			}
			if open.ConnSerialNum != cmd.ConnSerialNum || open.OrigVendorID != cmd.OrigVendorID ||
				open.OrigSerialNum != cmd.OrigSerialNum {
				continue
			}
			closePath := cmd.ConnectionPath
			if len(closePath) == 0 {
				closePath = EncodeCIPPath(0x04, 1, 0, 2, 3)
			}
			openPath := open.ConnectionPath
			if len(openPath) == 0 {
				openPath = EncodeCIPPath(0x04, 1, 0, 2, 3)
			}
			if string(closePath) != string(openPath) {
				return fmt.Errorf("enip command[%d]: Forward_Close connection path % X mismatches Forward_Open (command[%d]) path % X",
					i, closePath, j, openPath)
			}
			break
		}
	}

	if cfg.IOData != nil {
		io := cfg.IOData
		if io.FrameCount <= 0 {
			return fmt.Errorf("enip: io frame_count must be > 0")
		}
		if io.FrameSize > 65465 {
			return fmt.Errorf("enip: frame_size exceeds 65465")
		}
		// H-1（设计 §3.6/§5.5，T-110）：I/O 发包（O→T）需要 O→T Connection
		// ID；o2t_connection_id=0 时无法生成合法数据帧，直接拒绝。
		// （不能回退到 t2o_connection_id：T2O 是 originator 接收用的 ID。）
		// 仅当未配置 from_response（SourceCommandIndex==nil）时校验——若配置了
		// from_response，o2t 值由计划期响应提取填充，静态 0 合理。
		if io.SourceCommandIndex == nil && io.O2TConnectionID == 0 {
			return fmt.Errorf("enip: io o2t_connection_id is required for I/O data frames (cannot fall back to t2o_connection_id)")
		}
	}

	return nil
}

// hasCPFItemType reports whether any CPF item carries the given type_id.
func hasCPFItemType(items []core.CPFItem, typeID uint16) bool {
	for _, item := range items {
		if item.TypeID == typeID {
			return true
		}
	}
	return false
}

// validateCommand validates a single ENIP command.
func validateCommand(cmd *core.ENIPCommand, idx int) error {
	if !knownCommands[cmd.Command] {
		return fmt.Errorf("enip command[%d]: unknown command 0x%04X", idx, cmd.Command)
	}

	// V-101 (design §8.2): 0x0072/0x0073 是 trafficgen 模拟扩展，OpENer 不
	// 实现（收到返回 0x0001 Invalid Command），客户端场景使用会不兼容。
	// 校验通道没有 warning 通道（Validate 接口仅返回 error），按 M-5 指示
	// "没有就报告说明，不做大改"：静默接受，由用户自行判断使用场景。

	// Command-specific validation
	switch cmd.Command {
	case CmdRegisterSession:
		if len(cmd.CPFItems) > 0 {
			return fmt.Errorf("enip command[%d]: RegisterSession must not carry CPF", idx)
		}
		if cmd.ProtocolVersion != 1 {
			return fmt.Errorf("enip command[%d]: protocol_version must be 1, got %d", idx, cmd.ProtocolVersion)
		}
		if cmd.OptionFlag != 0 {
			return fmt.Errorf("enip command[%d]: option_flag must be 0", idx)
		}
		// V-085 (design §7.3 T-085): RegisterSession 的 payload 仅能携带
		// 4 字节会话数据（ProtocolVersion+OptionFlag，见 §4.2.1 S4），
		// 其余长度不可编码、必须拒绝。
		if len(cmd.Payload) > 0 && len(cmd.Payload) != 4 {
			return fmt.Errorf("enip command[%d]: payload must be 4 bytes", idx)
		}
	case CmdUnRegisterSession:
		if len(cmd.CPFItems) > 0 || len(cmd.Payload) > 0 {
			return fmt.Errorf("enip command[%d]: UnRegisterSession must not carry payload or CPF", idx)
		}
	case CmdListServices, CmdListIdentity, CmdListInterfaces:
		if len(cmd.CPFItems) > 0 {
			return fmt.Errorf("enip command[%d]: %s request must not carry CPF", idx, cmdName(cmd.Command))
		}
	case CmdSendRRData:
		// 设计 §4.3/V-105：SendRRData 的 CPF 项可由 planner 自动推导——
		// 有 CIPService 时自动加 Null(0x0000)+Unconnected(0x00B2)；
		// 响应模拟（Direction=down）可直接用 Payload 携带完整 CIP 响应字节
		// （from_response 提取依赖此形式，见 §5.6.1）。用户显式提供
		// CPFItems 时必须满足 2-4 项且含必需项，校验交给下方 CPF 项循环。
		// 仅当三者皆无（无 CIPService、无用户 CPF、无 Payload）时拒绝。
		if cmd.CIPService == 0 && len(cmd.CPFItems) < 2 && len(cmd.Payload) == 0 {
			return fmt.Errorf("enip command[%d]: SendRRData requires at least 2 CPF items, a cip_service, or a payload", idx)
		}
		// V-092 (design §7.3 T-092)：SendRRData 携带 Unconnected Data item
		// 即声明了 CIP 消息，必须给出 cip_service；cip_service=0（无 CIP
		// 消息）却携带 Unconnected Data 无法编码，必须拒绝。
		if cmd.CIPService == 0 && hasCPFItemType(cmd.CPFItems, TypeIDUnconnectedData) {
			return fmt.Errorf("enip command[%d]: cip_service required for SendRRData with Unconnected Data", idx)
		}
	case CmdSendUnitData:
		// Validate has Connection Address + Connected Data
		hasAddr, hasData := false, false
		for _, item := range cmd.CPFItems {
			if item.TypeID == TypeIDConnectionAddress {
				hasAddr = true
			}
			if item.TypeID == TypeIDConnectedData {
				hasData = true
			}
		}
		if !hasAddr {
			return fmt.Errorf("enip command[%d]: SendUnitData requires Connection Address item", idx)
		}
		if !hasData {
			return fmt.Errorf("enip command[%d]: SendUnitData requires Connected Data item", idx)
		}
	}

	// V-090/V-091 (design §7.3 T-090/091)：session_handle 仅支持固定值或
	// from_response 回读（§5.6.1），inc/rand 等流内可变策略无法被
	// 会话状态机处理，必须拒绝。策略字符串由转换层透传
	// （ENIPCommand.SessionHandleStrategy，json:"-"）。
	if s := cmd.SessionHandleStrategy; s != "" && s != "fixed" && s != "from_response" {
		return fmt.Errorf("enip command[%d]: session_handle strategy must be fixed or from_response, got %q", idx, s)
	}

	// Validate CPF items
	for j, item := range cmd.CPFItems {
		if !knownCPFTypeIDs[item.TypeID] {
			return fmt.Errorf("enip command[%d] CPF item[%d]: unknown type_id 0x%04X", idx, j, item.TypeID)
		}
		switch item.TypeID {
		case TypeIDNullAddress:
			if item.Length != 0 || len(item.Data) > 0 {
				return fmt.Errorf("enip command[%d] CPF item[%d]: Null Address must have zero length", idx, j)
			}
		case TypeIDConnectionAddress:
			if item.Length != 4 || len(item.Data) != 4 {
				return fmt.Errorf("enip command[%d] CPF item[%d]: Connection Address data must be 4 bytes", idx, j)
			}
		case TypeIDUnconnectedData:
			if item.Length < 2 || len(item.Data) < 2 {
				return fmt.Errorf("enip command[%d] CPF item[%d]: Unconnected Data must be >= 2 bytes", idx, j)
			}
		case TypeIDConnectedData:
			if item.Length < 2 {
				return fmt.Errorf("enip command[%d] CPF item[%d]: Connected Data must be >= 2 bytes", idx, j)
			}
		case TypeIDSockaddrO2T, TypeIDSockaddrT2O:
			if item.Length != 16 || len(item.Data) != 16 {
				return fmt.Errorf("enip command[%d] CPF item[%d]: Sockaddr Info length must be 16", idx, j)
			}
		}
	}

	// V-112 (design §8.2): CIPService 必须为已知服务码或 0（无 CIP 消息）。
	if cmd.CIPService != 0 && !knownCIPServices[cmd.CIPService] {
		return fmt.Errorf("enip command[%d]: unknown cip_service 0x%02X", idx, cmd.CIPService)
	}

	// M-6 (design §5.1 原则 3)：ENIPCommand.Length 由 planner 自动计算
	// （buildENIPPacket 恒用 len(payload)），用户无需填写，validator 不校验。

	// Validate CIP service-specific fields
	if cmd.CIPService == CIPForwardOpen || cmd.CIPService == CIPLargeForwardOpen {
		if cmd.ConnSerialNum == 0 {
			return fmt.Errorf("enip command[%d]: connection_serial_number required for Forward_Open", idx)
		}
		if cmd.OrigVendorID == 0 {
			return fmt.Errorf("enip command[%d]: originator_vendor_id required for Forward_Open", idx)
		}
		if cmd.OrigSerialNum == 0 {
			return fmt.Errorf("enip command[%d]: originator_serial_number required for Forward_Open", idx)
		}
		transportClass := cmd.TransportClassTrigger & 0x0F
		if transportClass > 3 {
			return fmt.Errorf("enip command[%d]: invalid transport class %d (must be 0-3)", idx, transportClass)
		}
		// Per spec V-119: bit 12 of Forward_Open's 2-byte Connection Parameters must be 0 (Reserved).
		// LargeForwardOpen uses 4-byte params with different bit layout (see spec §3.5.2).
		if cmd.CIPService == CIPForwardOpen {
			if cmd.O2TConnParams&0x1000 != 0 {
				return fmt.Errorf("enip command[%d]: reserved bit (bit 12) in o2t_connection_parameters must be 0", idx)
			}
			if cmd.T2OConnParams&0x1000 != 0 {
				return fmt.Errorf("enip command[%d]: reserved bit (bit 12) in t2o_connection_parameters must be 0", idx)
			}
		}
		// Per spec V-118: RPI must be > 0.
		if cmd.O2TRPI == 0 || cmd.T2ORPI == 0 {
			return fmt.Errorf("enip command[%d]: RPI must be > 0", idx)
		}
		// Per spec V-116: ConnectionTimeoutMultiplier must be 0-7.
		if cmd.ConnectionTimeoutMultiplier > 7 {
			return fmt.Errorf("enip command[%d]: timeout_multiplier must be 0-7, got %d", idx, cmd.ConnectionTimeoutMultiplier)
		}
	}

	if cmd.CIPService == CIPForwardClose {
		if cmd.ConnSerialNum == 0 {
			return fmt.Errorf("enip command[%d]: Forward_Close requires connection_serial_number", idx)
		}
	}

	if cmd.CIPService == CIPMultipleServicePacket {
		if len(cmd.SubRequests) == 0 {
			return fmt.Errorf("enip command[%d]: Multiple_Service_Packet requires sub_requests", idx)
		}
		if len(cmd.SubRequests) > 64 {
			return fmt.Errorf("enip command[%d]: sub_requests exceeds limit of 64", idx)
		}
	}

	// V-120 (design §7.3 T-120)：ConnectionPathSize 必须以字（16 位）为单位，
	// 等于 ⌈len(ConnectionPath)/2⌉（EPATH 奇数长时补零成字）。显式填写
	// 与实际路径不符时无法编码，必须拒绝。0（未填）由 planner 自动计算。
	if len(cmd.ConnectionPath) > 0 && cmd.ConnectionPathSize != 0 &&
		cmd.ConnectionPathSize != uint8((len(cmd.ConnectionPath)+1)/2) {
		return fmt.Errorf("enip command[%d]: connection_path_size mismatch", idx)
	}

	return nil
}

// cmdName returns the command name for logging.
func cmdName(cmd uint16) string {
	switch cmd {
	case CmdNop:
		return "Nop"
	case CmdListServices:
		return "ListServices"
	case CmdListIdentity:
		return "ListIdentity"
	case CmdListInterfaces:
		return "ListInterfaces"
	case CmdRegisterSession:
		return "RegisterSession"
	case CmdUnRegisterSession:
		return "UnRegisterSession"
	case CmdSendRRData:
		return "SendRRData"
	case CmdSendUnitData:
		return "SendUnitData"
	case CmdIndicateStatus:
		return "IndicateStatus"
	case CmdCancel:
		return "Cancel"
	default:
		return fmt.Sprintf("Unknown(0x%04X)", cmd)
	}
}

// --- Plan implementation (§3, §4.3, §6) ---

// Plan generates ENIP packet configs from a flow spec.
// Implements the core.Planner interface. Each ENIPCommand in cfg.Commands
// is emitted as one TCP segment (or one UDP datagram for I/O data).
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	cfg := spec.ENIP

	// from_response 配置合法性校验（H-2，设计 §5.6.1/T-117/T-118）：
	// 在启动 goroutine 前完成，出错直接返回 error（错误可被任务管道感知，
	// 不会以"completed with 0 packets"吞掉）。
	if err := validateFromResponseConfig(cfg); err != nil {
		return nil, err
	}

	// Apply defaults
	dstPort := spec.DstPort
	if dstPort == 0 {
		dstPort = DefaultPort
	}
	ttl := spec.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}

	configChan := make(chan core.PacketConfig, 256)

	// 多会话/多流展开（设计 §7.5 T-161~T-179 + §6.13 S12 + §6.14 S13）：
	// 总单元数 = sessionCount × flowCount，每单元是一份独立的会话状态机
	// （SessionHandle、TCP 序列号、响应表、packetIndex）与独立 4-tuple。
	// 逐单元派生（§6.14 S13 的 2 步交错由 +2u 表达；单元 0 与单单元场景
	// 字节级一致，既有用例零回归）：
	//   - SessionHandle/ConnSerialNum +u（T-162/163/164/165/174/175）；
	//   - O2T/T2O ConnectionID +2u（S13：包 1 O2T=1/T2O=2，包 2 O2T=3/T2O=4）；
	//   - down Forward_Open 响应 payload 的 O2T/T2O/serial 同步派生，
	//     from_response 提取得到逐单元不同 ConnectionID（T-168/170/173）；
	//   - TCP 每单元 srcPort = 显式 srcPort + u（T-169 独立 4-tuple）；
	//     UDP 共享 4-tuple（T-170，ConnectionID 区分流）；
	//   - SenderContext：默认全局递增（跨会话跨流连续，T-161/176）；
	//     显式值 +u（T-177 每单元独立）。
	sessionCount := cfg.SessionCount
	if sessionCount <= 0 {
		sessionCount = 1
	}
	flowCount := cfg.FlowCount
	if flowCount <= 0 {
		flowCount = 1
	}

	// senderCtxCounter 是 Plan 调用内共享的 SenderContext 全局递增计数器
	// （R43 默认策略 = 全局 inc，T-161/176）：跨会话、跨流连续递增。
	// SenderContextPtr 显式强制时不参与计数。planUnit 接收指针，
	// 逐单元读取并推进（每命令 +1）。
	var senderCtxCounter uint64

	go func() {
		defer close(configChan)

		for s := 0; s < sessionCount; s++ {
			for f := 0; f < flowCount; f++ {
				u := s*flowCount + f // 单元序号（0 起）
				if ctx.Err() != nil {
					return
				}
				p.planUnit(ctx, spec, cfg, configChan, u, flowCount, sessionCount, &senderCtxCounter)
			}
		}
	}()

	return configChan, nil
}

// planUnit 生成一个会话×流单元的完整命令序列 + I/O 帧（§7.5 展开的
// 单单元逻辑）。u 是单元序号（0 = 首单元，保持单单元场景字节级一致）。
// senderCtxCounter 是 Plan 调用级共享的全局 SenderContext 计数器指针。
func (p *Planner) planUnit(ctx context.Context, spec core.FlowSpec, cfg *core.ENIPConfig,
	configChan chan<- core.PacketConfig, u, flowCount, sessionCount int,
	senderCtxCounter *uint64) {

	// Apply defaults
	dstPort := spec.DstPort
	if dstPort == 0 {
		dstPort = DefaultPort
	}
	srcPort := spec.SrcPort
	ttl := spec.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	// T-169（多会话 TCP 4-tuple 独立）：每单元 srcPort = 显式 srcPort + u。
	// 仅 TCP 展开（多流 UDP 共享 4-tuple，T-170：所有流用同一 srcPort）；
	// down 方向端口交换仍基于单元 srcPort。
	transport := cfg.Transport
	if transport == "" {
		transport = "tcp"
	}
	l4Proto := "tcp"
	if transport == "udp" {
		l4Proto = "udp"
	} else {
		srcPort = srcPort + uint16(u)
	}

	flowID := fmt.Sprintf("enip-%s-%s-%d-%d", spec.SrcIP, spec.DstIP, srcPort, dstPort)
	now := time.Now()
	packetIndex := uint64(0)
	// 每单元独立 SessionHandle 状态机：T-162/163/174 要求 8 个会话 8 个
	// 独立 SessionHandle、UnRegisterSession 匹配本会话句柄。
	sessionHandle := uint32(0)

	// TCP 序列号：与 DNP3/MQTT/LDAP 一致，每条命令按方向携带当前 Seq
	// 并递增（无显式三次握手，ENIP 命令即数据段）。clientSeq 是 up 方向
	// 的 Seq，serverSeq 是 down 方向的 Seq；对端 Ack = 本方向下一期望
	// 序列号（已消费字节数 + 1）。可复现：spec.TCP.InitialSeq 覆盖客户端
	// 初始序列号（与 LDAP/MQTT 相同约定）。
	clientSeq := uint32(0)
	if spec.TCP != nil {
		clientSeq = spec.TCP.InitialSeq
	}
	if clientSeq == 0 {
		clientSeq = uint32(rand.Uint32())
	}
	serverSeq := uint32(rand.Uint32())
	// 每包序列号推进：Flags 含 SYN(0x02)/FIN(0x01) 时 +1，否则 +len(payload)。
	advanceSeq := func(seq *uint32, flags uint8, payloadLen int) {
		if flags&0x03 != 0 {
			*seq++
		} else {
			*seq += uint32(payloadLen)
		}
	}

	// responseTable 是 (source_command_index → 该命令的响应数据) 两级索引
	// 的单元内实现（H-2，设计 §5.6.1）：本单元的命令 i 的响应（含
	// 24B ENIP 头）记录在 responseTable[i]，后续命令通过
	// (flow_id, source_command_index) 定位提取字段。每单元独立响应表 =
	// 多会话/多流 from_response 隔离（T-172/173，不交叉引用）。
	responseTable := make(map[int][]byte)

	// 循环 i 从 0 到 len-1 正向构建；提取 from_response 时使用
	// 响应表（responseTable[srcIdx]），正向顺序保证引用目标（更早命令）
	// 已构建。
	for i, cmd := range cfg.Commands {
		if ctx.Err() != nil {
			return
		}

		// 多单元值派生（§6.14 S13 + T-162~T-177）：在 from_response 注入
		// 之前复制并平移本单元专属字段（显式值 + 单元偏移）。单元 0
		// 偏移全为 0，字节级等于单单元行为。派生字段：
		//   - SessionHandle/ConnSerialNum：+u（T-162/164/174/175）；
		//   - O2T/T2O ConnectionID：+2u（S13 交错）；
		//   - SenderContext：显式值 +u（T-177 每单元独立）。
		cmdCopy := cmd
		cmdCopy.ConnSerialNum = cmd.ConnSerialNum + uint16(u)
		cmdCopy.O2TConnID = cmd.O2TConnID + uint32(2*u)
		cmdCopy.T2OConnID = cmd.T2OConnID + uint32(2*u)
		if cmd.SenderContext != 0 {
			cmdCopy.SenderContext = cmd.SenderContext + uint64(u)
		}
		// 响应方向命令（down/response）的 SessionHandle +u（T-162/163/174）：
		// RegisterSession 响应与 UnRegisterSession 响应随单元平移，各会话
		// 独立句柄。请求方向命令保持用户显式值不变（up 请求如
		// UnRegisterSession 可携带已注册句柄，T-015/T-174 依赖）。
		if cmd.Direction == "down" || cmd.Direction == "response" {
			cmdCopy.SessionHandle = cmd.SessionHandle + uint32(u)
		}
		// down Forward_Open 响应 payload 随单元派生（T-168/170/173）：
		// 响应的 O2T/T2O/ConnSerial 与请求侧同步平移（+2u/+2u/+u），
		// 否则 from_response 从各单元响应提取到相同的 ConnectionID，
		// 多流无法区分。仅当 payload 是标准成功响应（MR 头 reply=0xD4、
		// GeneralStatus=0、AddStatusSize=0，body ≥10B）时派生；其他
		// payload（错误响应等）保持原样。u=0 时字节级不变。
		cmdCopy.Payload = deriveForwardOpenResponsePayload(cmd.Payload, u)

		// from_response 注入（H-2）：若本命令配置了
		// FromResponseField/SourceCommandIndex，先从引用命令的响应
		// 提取字段值，注入到命令副本（cmdCopy）后再构建。
		// 优先级：FromResponseField 注入值 > cmd.SessionHandle 显式值 >
		// 单元级 sessionHandle。响应表按 (flow_id, source_command_index)
		// 定位，本单元内隔离（设计 §5.6.1 + T-172/173）。
		if cmd.FromResponseField != "" && cmd.SourceCommandIndex >= 0 &&
			cmd.SourceCommandIndex < len(cfg.Commands) {
			if resp := responseTable[cmd.SourceCommandIndex]; len(resp) > 0 {
				if val, ok := extractFromResponse(resp, cmd.FromResponseField); ok {
					switch cmd.FromResponseField {
					case "session_handle":
						cmdCopy.SessionHandle = val
					case "o2t_connection_id":
						cmdCopy.O2TConnID = val
					case "t2o_connection_id":
						cmdCopy.T2OConnID = val
					case "connection_serial_number":
						cmdCopy.ConnSerialNum = uint16(val)
					}
				}
			}
		}

		// Update session handle from the most recent RegisterSession response
		if cmdCopy.Command == CmdRegisterSession && sessionHandle == 0 {
			// For request: SessionHandle must be 0 (unregistered).
			// For response (direction=down): SessionHandle is in cmd.SessionHandle.
			if cmdCopy.SessionHandle != 0 {
				sessionHandle = cmdCopy.SessionHandle
			}
		}

		// Build the ENIP packet payload。SenderContext 计数经 Plan 级共享
		// 指针推进（R43 默认全局递增，T-161/176）。
		enipMsg := buildENIPPacket(&cmdCopy, sessionHandle, cfg, *senderCtxCounter)

		// 记录响应数据：若本命令是响应方向（Direction=down/response），
		// 将构建的响应报文（含 24B ENIP 头）存入响应表，供后续命令
		// from_response 提取（H-2）。
		if cmdCopy.Direction == "down" || cmdCopy.Direction == "response" {
			responseTable[i] = enipMsg
		}

		// Determine direction: default "up" (client→server).
		// ListIdentity/ListServices/ListInterfaces responses and RegisterSession
		// responses use "down".
		direction := "up"
		if cmdCopy.Direction == "down" || cmdCopy.Direction == "response" {
			direction = "down"
		}

		srcP, dstP := srcPort, dstPort
		if direction == "down" {
			srcP, dstP = dstPort, srcPort
		}

		// 序列号：up 用 clientSeq，down 用 serverSeq；Ack = 对端当前
		// Seq（已接收字节后）。flags=PSH+ACK，数据段语义（无握手）。
		seq := clientSeq
		ack := serverSeq
		flags := uint8(tcpPSHACK)
		if direction == "down" {
			seq = serverSeq
			ack = clientSeq
		}
		select {
		case configChan <- core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: packetIndex,
			Direction:   direction,
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    spec.SrcMAC,
				DstMAC:    spec.DstMAC,
				EtherType: core.EtherTypeFor(spec.SrcIP),
			},
			L3: core.L3Base(spec.SrcIP, spec.DstIP, l4ProtoNumber(l4Proto), ttl, uint16(i+1), spec),
			L4: core.L4Config{
				Protocol:   l4Proto,
				SrcPort:    srcP,
				DstPort:    dstP,
				Seq:        seq,
				Ack:        ack,
				Flags:      flags,
				WindowSize: 65535,
			},
			Payload: enipMsg,
		}:
		case <-ctx.Done():
			return
		}
		if l4Proto == "tcp" {
			if direction == "up" {
				advanceSeq(&clientSeq, flags, len(enipMsg))
			} else {
				advanceSeq(&serverSeq, flags, len(enipMsg))
			}
		}
		packetIndex++
		*senderCtxCounter++
	}

	// Emit I/O data frames if configured
	if cfg.IOData != nil {
		// H-2（设计 §5.6.1）：IOData.SourceCommandIndex 指向本单元内
		// Forward_Open 响应（方向 down），I/O 帧的 O→T Connection ID
		// 从该响应 CIP body offset 0 提取。单元隔离：响应表按本单元
		// 命令序列索引。
		io := *cfg.IOData
		io.O2TConnectionID = io.O2TConnectionID + uint32(2*u)
		if io.SourceCommandIndex != nil && *io.SourceCommandIndex >= 0 &&
			*io.SourceCommandIndex < len(cfg.Commands) {
			if resp := responseTable[*io.SourceCommandIndex]; len(resp) > 0 {
				if val, ok := extractFromResponse(resp, "o2t_connection_id"); ok {
					io.O2TConnectionID = val
				}
			}
		}
		ioFrames := buildIODataFrames(&io, sessionHandle)
		for _, frame := range ioFrames {
			if ctx.Err() != nil {
				return
			}
			select {
			case configChan <- core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   "up",
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    spec.SrcMAC,
					DstMAC:    spec.DstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3: core.L3Base(spec.SrcIP, spec.DstIP, 17, ttl, uint16(packetIndex+1), spec),
				L4: core.L4Config{
					Protocol: "udp",
					SrcPort:  srcPort,
					DstPort:  dstPort,
				},
				Payload: frame,
			}:
			case <-ctx.Done():
				return
			}
			packetIndex++
		}
	}
}

// fromResponseFields 是 from_response 支持的提取字段名（设计 §5.6.1 表）。
var fromResponseFields = map[string]bool{
	"session_handle":           true,
	"o2t_connection_id":        true,
	"t2o_connection_id":        true,
	"connection_serial_number": true,
}

// validFromResponseField 返回字段名是否为合法的 from_response 字段。
func validFromResponseField(field string) bool {
	return fromResponseFields[field]
}

// validateFromResponseConfig 校验所有命令及 IOData 的 from_response 配置
// （H-2，设计 §5.6.1 + T-117/T-118）：
//   - FromResponseField 必须是合法字段名；
//   - SourceCommandIndex 必须指向本 flow 内存在的命令（0 ≤ idx < len，
//     且不能指向自己）；
//   - 引用目标命令必须是响应方向命令（Direction=down/response），
//     因为响应数据只从响应方向命令记录。
//
// 引用目标必须是本 flow 内的命令（同一 cfg.Commands 切片），天然满足
// "flow 隔离"：不同 flow 的 Plan 调用使用各自的 cfg 副本。
func validateFromResponseConfig(cfg *core.ENIPConfig) error {
	for i, cmd := range cfg.Commands {
		if cmd.FromResponseField == "" {
			continue
		}
		if !validFromResponseField(cmd.FromResponseField) {
			return fmt.Errorf("enip command[%d]: unknown from_response field %q", i, cmd.FromResponseField)
		}
		if cmd.SourceCommandIndex < 0 || cmd.SourceCommandIndex >= len(cfg.Commands) {
			return fmt.Errorf("enip command[%d]: source_command_index %d out of range (0-%d)",
				i, cmd.SourceCommandIndex, len(cfg.Commands)-1)
		}
		if cmd.SourceCommandIndex == i {
			return fmt.Errorf("enip command[%d]: source_command_index must not point to itself", i)
		}
		if cmd.SourceCommandIndex > i {
			// 正向构建顺序要求引用目标（响应命令）必须先于引用者构建，
			// 否则响应表为空，提取静默失败。
			return fmt.Errorf("enip command[%d]: source_command_index %d must reference an earlier command (forward references unsupported)",
				i, cmd.SourceCommandIndex)
		}
		src := cfg.Commands[cmd.SourceCommandIndex]
		if src.Direction != "down" && src.Direction != "response" {
			return fmt.Errorf("enip command[%d]: source_command_index %d is not a response-direction command",
				i, cmd.SourceCommandIndex)
		}
		if cmd.FromResponseField != "session_handle" {
			// o2t/t2o/conn_serial 从 Forward_Open 响应 CIP body 提取，
			// 要求源命令的 Payload 是完整 CIP 响应：MR 头(4B: replyService+
			// reserved+GeneralStatus+AddStatusSize) + body(至少 10B:
			// O2T 4B + T2O 4B + ConnSerial 2B)。该 Payload 被 builder 包进
			// Unconnected Data Item，提取时定位到 item 数据起点。
			if src.Command != CmdSendRRData || len(src.Payload) < 14 {
				return fmt.Errorf("enip command[%d]: source_command_index %d (field %q) requires a SendRRData response payload of at least 14 bytes, got %d",
					i, cmd.SourceCommandIndex, cmd.FromResponseField, len(src.Payload))
			}
		}
	}
	if cfg.IOData != nil && cfg.IOData.SourceCommandIndex != nil {
		idx := *cfg.IOData.SourceCommandIndex
		if idx < 0 || idx >= len(cfg.Commands) {
			return fmt.Errorf("enip io_data: source_command_index %d out of range (0-%d)",
				idx, len(cfg.Commands)-1)
		}
		src := cfg.Commands[idx]
		if src.Direction != "down" && src.Direction != "response" {
			return fmt.Errorf("enip io_data: source_command_index %d is not a response-direction command",
				idx)
		}
		if src.Command != CmdSendRRData || len(src.Payload) < 14 {
			return fmt.Errorf("enip io_data: source_command_index %d requires a SendRRData response payload of at least 14 bytes, got %d",
				idx, len(src.Payload))
		}
	}
	return nil
}

// extractFromResponse 从响应报文（含 24B ENIP 头）中提取 from_response
// 字段值（H-2，设计 §5.6.1 表）：
//
//	| 字段 | 提取位置 | 偏移 | 大小 |
//	| session_handle | 响应 ENIP 头 SessionHandle | 4 | 4B LE |
//	| o2t_connection_id | Forward_Open 响应 CIP body | 0 | 4B LE |
//	| t2o_connection_id | Forward_Open 响应 CIP body | 4 | 4B LE |
//	| connection_serial_number | Forward_Open 响应 CIP body | 8 | 2B LE |
//
// Forward_Open 响应 CIP body 偏移从 Message Router 响应数据起算（4B MR 头
// 之后，见 §3.6；§5.6.1 的偏移即从 CIP body 起算）。提取前校验响应
// General Status=0（成功），错误响应不得作为 Connection ID 来源
// （§5.6.1 前置条件）。
func extractFromResponse(resp []byte, field string) (uint32, bool) {	if len(resp) < enipHeaderLen {
		return 0, false
	}
	switch field {
	case "session_handle":
		return binary.LittleEndian.Uint32(resp[4:8]), true
	case "o2t_connection_id", "t2o_connection_id", "connection_serial_number":
		// 定位 Forward_Open 响应：ENIP 头(24) + SendRRData 前缀(6) +
		// CPF ItemCount(2) + Item1 头(4) + Item2 头(4)。
		// 完整响应 = 24 + 6 + 2 + 4 + 4 + MR 头(4) + CIP body。
		// CIP body 从 offset 44 开始（MR 头之前是 Unconnected Data Item
		// 数据，其前 4 字节是 MR 头）。O2T=body[0:4]、T2O=body[4:8]、
		// ConnSerial=body[8:10]。
		const bodyStart = enipHeaderLen + 6 + 2 + 4 + 4 + 4
		if len(resp) < bodyStart+10 {
			return 0, false
		}
		// 前置条件（§5.6.1）：仅当响应 General Status=0 时提取有效。
		// MR 头位于 item 数据起点：replyService(1)+Reserved(1)+
		// GeneralStatus(1)+AddStatusSize(1)+AddStatus(N*2)。
		// GeneralStatus 在 resp[bodyStart-4+2]。
		if resp[bodyStart-2] != 0 { // GeneralStatus != 0 → 错误响应
			return 0, false
		}
		// 仅支持 AddStatusSize=0 的成功响应（§3.6 成功响应 26B body 无
		// Additional Status；AddStatusSize≠0 时 CIP body 位置偏移，无法
		// 按固定偏移提取，返回不可用）。
		if resp[bodyStart-1] != 0 { // AddStatusSize != 0
			return 0, false
		}
		switch field {
		case "o2t_connection_id":
			return binary.LittleEndian.Uint32(resp[bodyStart : bodyStart+4]), true
		case "t2o_connection_id":
			return binary.LittleEndian.Uint32(resp[bodyStart+4 : bodyStart+8]), true
		case "connection_serial_number":
			return uint32(binary.LittleEndian.Uint16(resp[bodyStart+8 : bodyStart+10])), true
		}
	}
	return 0, false
}

// deriveForwardOpenResponsePayload 将 down 方向 Forward_Open 响应 payload
// （MR 头 + CIP body，不含 ENIP 头）按单元偏移派生：O2T/T2O +2u、
// ConnSerial +u（§6.14 S13 交错，T-168/170/173）。仅当 payload 是标准
// 成功响应形状时派生：MR 头 4B（replyService=0xD4、Reserved、GeneralStatus=0、
// AddStatusSize=0）+ body ≥10B（O2T 4B + T2O 4B + ConnSerial 2B）。
// 其他形状（错误响应、自定义 payload）保持原样；u=0 恒返回原 payload。
func deriveForwardOpenResponsePayload(payload []byte, u int) []byte {
	if u == 0 || len(payload) < 14 {
		return payload
	}
	if payload[0] != 0xD4 || payload[2] != 0 || payload[3] != 0 {
		return payload // 非标准成功响应（reply/GeneralStatus/AddStatusSize 不符）
	}
	derived := make([]byte, len(payload))
	copy(derived, payload)
	binary.LittleEndian.PutUint32(derived[4:8], binary.LittleEndian.Uint32(payload[4:8])+uint32(2*u))
	binary.LittleEndian.PutUint32(derived[8:12], binary.LittleEndian.Uint32(payload[8:12])+uint32(2*u))
	binary.LittleEndian.PutUint16(derived[12:14], binary.LittleEndian.Uint16(payload[12:14])+uint16(u))
	return derived
}

// l4ProtoNumber returns the IP protocol number for TCP/UDP.
func l4ProtoNumber(proto string) uint8 {
	if proto == "udp" {
		return 17
	}
	return 6 // TCP
}

// buildENIPPacket constructs a full 24-byte ENIP header + payload for one command.
// senderCtxCounter 是 flow 内 SenderContext 递增计数器（M-1，设计 §6.13
// S12）：SenderContext 未显式设置时，默认值从 1 开始随每条命令递增，
// 用于追踪请求-响应对应。
func buildENIPPacket(cmd *core.ENIPCommand, sessionHandle uint32, cfg *core.ENIPConfig, senderCtxCounter uint64) []byte {
	// Use cmd.SessionHandle if set (explicit value), else default to sessionHandle
	sh := sessionHandle
	if cmd.SessionHandle != 0 {
		sh = cmd.SessionHandle
	}

	// Build payload based on command type
	var payload []byte
	switch cmd.Command {
	case CmdNop:
		payload = cmd.Payload
	case CmdListServices:
		payload = nil // Request has no payload
	case CmdListIdentity:
		payload = nil // Request has no payload
	case CmdListInterfaces:
		payload = nil // Request has no payload
	case CmdRegisterSession:
		// Per spec V-102/T-120b, ProtocolVersion must be 1; default to 1 if unset.
		pv := cmd.ProtocolVersion
		if pv == 0 {
			pv = 1
		}
		payload = BuildRegisterSessionPayload(pv, cmd.OptionFlag)
	case CmdUnRegisterSession:
		payload = nil
	case CmdSendRRData:
		// Build CIP data for the CIPService
		cipData := buildCIPDataForCommand(cmd, cfg)
		items := []core.CPFItem{
			{TypeID: TypeIDNullAddress, Length: 0, Data: nil},
			{TypeID: TypeIDUnconnectedData, Length: uint16(len(cipData)), Data: cipData},
		}
		// 用户 CPF 追加到自动生成的必需项之后，不能替换必需项。
		items = append(items, cmd.CPFItems...)
		payload = BuildSendRRDataPayload(cmd.InterfaceHandle, cmd.Timeout, items)
	case CmdSendUnitData:
		items := append([]core.CPFItem(nil), cmd.CPFItems...)
		// H-2：from_response 注入的 O2T ConnID（cmd.O2TConnID）覆盖用户
		// Connection Address Item 数据（设计 §5.6.1：I/O 命令用响应提取的
		// O2T Connection ID）。
		if cmd.O2TConnID != 0 && cmd.FromResponseField == "o2t_connection_id" {
			for j := range items {
				if items[j].TypeID == TypeIDConnectionAddress {
					items[j].Data = u32LE(cmd.O2TConnID)
					items[j].Length = 4
				}
			}
		}
		payload = BuildSendRRDataPayload(cmd.InterfaceHandle, cmd.Timeout, items)
	case CmdIndicateStatus:
		payload = cmd.Payload
	case CmdCancel:
		payload = cmd.Payload
	}

	// Build the 24-byte ENIP header.
	// M-1/M-2：SenderContext 取值优先级：
	//   1) senderCtxPtr（用户显式强制，包括 0）→ 采用该值；
	//   2) SenderContext != 0（用户显式值）→ 采用；
	//   3) 其余 → flow 内递增默认值（从 1 开始，逐命令 +1），NOP 除外
	//      （NOP 保活固定 0）。
	var senderCtx uint64
	switch {
	case cmd.SenderContextPtr != nil:
		senderCtx = *cmd.SenderContextPtr
	case cmd.SenderContext != 0:
		senderCtx = cmd.SenderContext
	case cmd.Command == CmdNop:
		senderCtx = 0
	default:
		senderCtx = (senderCtxCounter & 0x00000000FFFFFFFF) + 1
	}
	// 报文 = 24B ENIP 头 + payload（ENIP 头 Length 字段=len(payload)）。
	// 修复：原实现直接返回 BuildENIPHeader(...)（仅 24B 头），未拼接 payload，
	// 导致所有带 payload 的命令（NOP/RegisterSession/SendRRData/...）只有头。
	hdr := BuildENIPHeader(cmd.Command, uint16(len(payload)), sh, cmd.Status, senderCtx, cmd.Options)
	if len(payload) == 0 {
		return hdr
	}
	msg := make([]byte, 0, len(hdr)+len(payload))
	msg = append(msg, hdr...)
	msg = append(msg, payload...)
	return msg
}

// buildCIPDataForCommand builds the CIP data portion for a SendRRData command.
func buildCIPDataForCommand(cmd *core.ENIPCommand, cfg *core.ENIPConfig) []byte {
	switch cmd.CIPService {
	case CIPForwardOpen:
		connPath := cmd.ConnectionPath
		if len(connPath) == 0 {
			// Default: Assembly + Instance + Connection Points
			connPath = EncodeCIPPath(0x04, 1, 0, 2, 3)
		}
		body := BuildForwardOpenBody(
			cmd.PriorityTimeTick, cmd.TimeoutTicks,
			cmd.O2TConnID, cmd.T2OConnID,
			cmd.ConnSerialNum, cmd.OrigVendorID, cmd.OrigSerialNum,
			cmd.ConnectionTimeoutMultiplier,
			cmd.O2TRPI, cmd.T2ORPI,
			uint16(cmd.O2TConnParams), uint16(cmd.T2OConnParams),
			cmd.TransportClassTrigger,
			connPath,
		)
		// CIP header: Service + RequestPathSize + PaddedRequestPath(Connection Manager, Instance 1)
		reqPath, pathSize := EncodePaddedCIPPath(0x06, 1, 0)
		cip := make([]byte, 0, 2+len(reqPath)+len(body))
		cip = append(cip, CIPForwardOpen, pathSize)
		cip = append(cip, reqPath...)
		cip = append(cip, body...)
		return cip

	case CIPLargeForwardOpen:
		connPath := cmd.ConnectionPath
		if len(connPath) == 0 {
			connPath = EncodeCIPPath(0x04, 1, 0, 2, 3)
		}
		body := BuildLargeForwardOpenBody(
			cmd.PriorityTimeTick, cmd.TimeoutTicks,
			cmd.O2TConnID, cmd.T2OConnID,
			cmd.ConnSerialNum, cmd.OrigVendorID, cmd.OrigSerialNum,
			cmd.ConnectionTimeoutMultiplier,
			cmd.O2TRPI, cmd.T2ORPI,
			cmd.O2TConnParams, cmd.T2OConnParams,
			cmd.TransportClassTrigger,
			connPath,
		)
		reqPath, pathSize := EncodePaddedCIPPath(0x06, 1, 0)
		cip := make([]byte, 0, 2+len(reqPath)+len(body))
		cip = append(cip, CIPLargeForwardOpen, pathSize)
		cip = append(cip, reqPath...)
		cip = append(cip, body...)
		return cip

	case CIPForwardClose:
		connPath := cmd.ConnectionPath
		if len(connPath) == 0 {
			connPath = EncodeCIPPath(0x04, 1, 0, 2, 3)
		}
		body := BuildForwardCloseBody(
			cmd.PriorityTimeTick, cmd.TimeoutTicks,
			cmd.ConnSerialNum, cmd.OrigVendorID, cmd.OrigSerialNum,
			connPath,
		)
		reqPath, pathSize := EncodePaddedCIPPath(0x06, 1, 0)
		cip := make([]byte, 0, 2+len(reqPath)+len(body))
		cip = append(cip, CIPForwardClose, pathSize)
		cip = append(cip, reqPath...)
		cip = append(cip, body...)
		return cip

	case CIPMultipleServicePacket:
		return BuildMultipleServicePacket(cmd.ClassID, cmd.InstanceID, cmd.SubRequests)

	case CIPGetAttributeSingle, CIPGetAttributesAll, CIPReset, CIPStart, CIPStop, CIPNOP:
		reqPath, pathSize := EncodePaddedCIPPath(cmd.ClassID, cmd.InstanceID, cmd.AttributeID)
		return append([]byte{cmd.CIPService, pathSize}, reqPath...)

	case CIPSetAttributeSingle, CIPSetAttributesAll, CIPApplyAttributes, CIPRestore, CIPSave:
		reqPath, pathSize := EncodePaddedCIPPath(cmd.ClassID, cmd.InstanceID, cmd.AttributeID)
		cip := make([]byte, 0, 2+len(reqPath)+len(cmd.Payload))
		cip = append(cip, cmd.CIPService, pathSize)
		cip = append(cip, reqPath...)
		cip = append(cip, cmd.Payload...)
		return cip

	case CIPGetAttributeList, CIPSetAttributeList:
		// Get: Payload = AttrIDs 列表（每 2B LE 一个 ID），count = len/2。
		// Set: Payload = AttrID(2B LE) + 属性数据（类型相关，Identity STRING
		// 为 2B 长度前缀 + 数据）的混合结构（设计 §3.10；Wireshark
		// dissect_cip_set_attribute_list_req 按 att_count 读取 AttrID 后由
		// dissect_cip_attribute 按属性类型消费数据，AttrID 后无 DataSize
		// 字段）。count = 前段纯 AttrID 个数。
		reqPath, pathSize := EncodePaddedCIPPath(cmd.ClassID, cmd.InstanceID, 0)
		cip := make([]byte, 0, 64)
		cip = append(cip, cmd.CIPService, pathSize)
		cip = append(cip, reqPath...)
		if cmd.CIPService == CIPGetAttributeList {
			attrCount := uint16(len(cmd.Payload) / 2)
			cip = append(cip, u16LE(attrCount)...)
			cip = append(cip, cmd.Payload...)
			return cip
		}
		// Set_Attribute_List: Payload 以 AttrID 开头；对偶数长度取整后
		// 与整体一致即视为纯 AttrID 列表（get 风格），否则按
		// AttrID+数据 混合结构：count=1 个 AttrID + 原始数据。
		attrCount := uint16(1)
		if len(cmd.Payload) > 0 && len(cmd.Payload)%2 == 0 {
			attrCount = uint16(len(cmd.Payload) / 2)
		}
		cip = append(cip, u16LE(attrCount)...)
		cip = append(cip, cmd.Payload...)
		return cip

	default:
		// Generic: use cmd.Payload directly if set
		if len(cmd.Payload) > 0 {
			return cmd.Payload
		}
		reqPath, pathSize := EncodePaddedCIPPath(cmd.ClassID, cmd.InstanceID, cmd.AttributeID)
		return append([]byte{cmd.CIPService, pathSize}, reqPath...)
	}
}

// buildIODataFrames builds ENIP SendUnitData frames for I/O data.
// 这是发包（originator→target 的 O→T 方向）路径：SendUnitData 的
// Connection Address Item (0x00A1) 必须携带 O→T Connection ID（设计
// §3.6/§5.5）：O2T Connection ID 是 Target 在 O→T 方向接收数据、即
// Originator 发送时使用的 ID。T2O 是 originator 接收（target→originator）
// 用的 ID，不能回退使用（H-1）。
func buildIODataFrames(io *core.ENIPIOData, sessionHandle uint32) [][]byte {
	if io.FrameCount <= 0 {
		return nil
	}
	frames := make([][]byte, 0, io.FrameCount)
	seq := io.SequenceStart
	step := io.SequenceStep
	if step == 0 {
		step = 1
	}
	// O2TConnectionID 必须非零；originator 发送 I/O 数据帧必须知道
	// target 分配给 O→T 方向的 Connection ID（Forward_Open 响应 offset 0）。
	if io.O2TConnectionID == 0 {
		return nil
	}
	connID := io.O2TConnectionID
	for i := 0; i < io.FrameCount; i++ {
		// Connected Data Item: payload 直接作为内容（pcap 回归 2026-08：
		// UDP I/O 帧不再带 2B SequenceCounter 前缀——未注册 connid 的
		// UDP I/O 被 Wireshark 按 CIP Message Router 解析，seq+payload
		// 会构成伪显式消息 → [Malformed Packet: CIP]；见
		// BuildConnectedDataItem 注释）。ConnectionID 在 0x00A1 item。
		frameData := io.Payload
		if len(frameData) == 0 && io.FrameSize > 0 {
			frameData = make([]byte, io.FrameSize)
		}
		connData := BuildConnectedDataItem(seq, frameData)
		items := []core.CPFItem{
			{TypeID: TypeIDConnectionAddress, Length: 4, Data: u32LE(connID)},
			{TypeID: TypeIDConnectedData, Length: uint16(len(connData)), Data: connData},
		}
		payload := BuildSendRRDataPayload(0, 0, items)
		msg := BuildENIPHeader(CmdSendUnitData, uint16(len(payload)), sessionHandle, 0, uint64(i+1), 0)
		// 修复：原实现只拼了 24B ENIP 头，未拼接 SendRRData payload，
		// 导致 I/O 帧恒为 24 字节、CPF 数据丢失。
		frame := make([]byte, 0, len(msg)+len(payload))
		frame = append(frame, msg...)
		frame = append(frame, payload...)
		frames = append(frames, frame)
		seq += step
	}
	return frames
}

// Avoid unused imports in some configurations.
var _ = strings.Contains
