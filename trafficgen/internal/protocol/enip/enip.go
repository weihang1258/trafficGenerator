// Package enip implements the EtherNet/IP (ENIP) protocol planner.
// See types.go for data structures.
package enip

import (
	"context"
	"encoding/binary"
	"fmt"
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
	srcPort := spec.SrcPort
	ttl := spec.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		select {
		case <-ctx.Done():
			return
		default:
		}

		flowID := fmt.Sprintf("enip-%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
		now := time.Now()
		packetIndex := uint64(0)
		sessionHandle := uint32(0)
		// senderCtxCounter 是 flow 内 SenderContext 递增计数器（M-1，设计
		// §6.13 S12）：每条命令默认 SenderContext = 起始值 + 已发包数。
		senderCtxCounter := uint64(0)

		// responseTable 是 (source_command_index → 该命令的响应数据) 两级索引
		// 的 flow 内实现（H-2，设计 §5.6.1）：本 flow 的命令 i 的响应（含
		// 24B ENIP 头）记录在 responseTable[i]，后续命令通过
		// (flow_id, source_command_index) 定位提取字段。
		responseTable := make(map[int][]byte)

		// 循环 i 从 0 到 len-1 正向构建；提取 from_response 时使用
		// 响应表（responseTable[srcIdx]），正向顺序保证引用目标（更早命令）
		// 已构建。
		for i, cmd := range cfg.Commands {
			if ctx.Err() != nil {
				return
			}

			// from_response 注入（H-2）：若本命令配置了
			// FromResponseField/SourceCommandIndex，先从引用命令的响应
			// 提取字段值，注入到命令副本（cmdCopy）后再构建。
			// 优先级：FromResponseField 注入值 > cmd.SessionHandle 显式值 >
			// flow 级 sessionHandle。响应表按 (flow_id, source_command_index)
			// 定位，本 flow 内隔离（设计 §5.6.1）。
			cmdCopy := cmd
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

			// Build the ENIP packet payload
			enipMsg := buildENIPPacket(&cmdCopy, sessionHandle, cfg, senderCtxCounter)

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

			// Determine transport protocol: TCP for explicit, UDP for I/O (Class 0/1).
			transport := cfg.Transport
			if transport == "" {
				transport = "tcp"
			}
			l4Proto := "tcp"
			if transport == "udp" {
				l4Proto = "udp"
			}

			srcP, dstP := srcPort, dstPort
			if direction == "down" {
				srcP, dstP = dstPort, srcPort
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
					Protocol: l4Proto,
					SrcPort:  srcP,
					DstPort:  dstP,
				},
				Payload: enipMsg,
			}:
			case <-ctx.Done():
				return
			}
			packetIndex++
			senderCtxCounter++
		}

		// Emit I/O data frames if configured
		if cfg.IOData != nil {
			// H-2（设计 §5.6.1）：IOData.SourceCommandIndex 指向本 flow 内
			// Forward_Open 响应（方向 down），I/O 帧的 O→T Connection ID
			// 从该响应 CIP body offset 0 提取。flow 隔离：响应表按本 flow
			// 命令序列索引。
			io := *cfg.IOData
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
	}()

	return configChan, nil
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
func extractFromResponse(resp []byte, field string) (uint32, bool) {
	if len(resp) < enipHeaderLen {
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
		// Build attribute list request
		cip := make([]byte, 0, 64)
		reqPath, pathSize := EncodePaddedCIPPath(cmd.ClassID, cmd.InstanceID, 0)
		cip = append(cip, cmd.CIPService, pathSize)
		cip = append(cip, reqPath...)
		// Attribute IDs from Payload (each 2B LE)
		attrCount := uint16(len(cmd.Payload) / 2)
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
		// Connected Data Item: 2B SequenceCounter + payload (per spec §2.4.1)
		// ConnectionID belongs in the Connection Address Item (0x00A1), not here.
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
