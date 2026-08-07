// Package ngap implements the NGAP (Next Generation Application Protocol,
// 5G核心网信令协议) planner for trafficgen.
//
// NGAP is defined in 3GPP TS 38.413 and runs over SCTP (端口 38412,
// PPID=60). It carries signaling between gNB (基站, gNodeB) and AMF
// (接入管理功能, Access and Mobility Management Function) in the 5G
// core network (5GC, 5G核心网).
//
// Transport (传输层):
//   - SCTP (流控制传输协议, Stream Control Transmission Protocol, RFC 4960)
//   - Default port: 38412 (AMF, 接入管理功能)
//   - PPID: 60 (0x3C, per 3GPP TS 38.413)
//   - 4-way handshake: INIT → INIT-ACK → COOKIE-ECHO → COOKIE-ACK
//   - 3-way teardown: SHUTDOWN → SHUTDOWN-ACK → SHUTDOWN-COMPLETE
//
// Signaling procedures (信令流程) emitted by the planner:
//  1. NG Setup (NG建立, procedureCode=21): gNB→AMF NGSetupRequest, AMF→gNB NGSetupResponse
//  2. InitialUEMessage (初始UE消息, procedureCode=15): gNB→AMF, carries first NAS-PDU
//  3. DownlinkNASTransport (下行NAS传输, procedureCode=4): AMF→gNB
//  4. UplinkNASTransport (上行NAS传输, procedureCode=46): gNB→AMF
//  5. PDUSessionResourceSetupRequest/Response (PDU会话资源建立, procedureCode=29)
//  6. UEContextReleaseCommand/Complete (UE上下文释放, procedureCode=41)
//
// NGAP-PDU structure (NGAP协议数据单元结构, ASN.1 PER encoded):
//
//	NGAP-PDU ::= CHOICE {
//	    initiatingMessage    (0, 初始消息),
//	    successfulOutcome    (1, 成功结果),
//	    unsuccessfulOutcome  (2, 失败结果)
//	}
//
// Each PDU carries: procedureCode (流程码, 1 byte), criticality (关键性, 1 byte),
// and a ProtocolIE-Container (协议信息元素容器) with a list of ProtocolIE-Field entries.
//
// Encoding (编码): Simplified ASN.1 PER — structurally valid NGAP-PDU frames
// that DPI systems and protocol analyzers recognize, but not full-compliance
// with 3GPP TS 38.413 encoding rules (e.g., no constraint-based length
// determinants). Sufficient for traffic generation and testing.
//
// Reference pcap (参考抓包): SCTP_NAS.pcap — single InitialUEMessage packet
// with Registration Request NAS-PDU (MCC=460 China, MNC=01 China Unicom).
package ngap

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultPort (默认端口) is the canonical NGAP port per 3GPP TS 38.413.
	DefaultPort = 38412

	// DefaultTTL (默认TTL) used when spec.TTL is zero.
	DefaultTTL = 64

	// PPID_NGAP (NGAP载荷协议标识) is the SCTP Payload Protocol Identifier
	// for NGAP per 3GPP TS 38.413 §2.
	PPID_NGAP = 60

	// SID (流标识) for non-access-stratum signaling per 3GPP TS 38.412.
	SID_NAS = 1

	// --- SCTP chunk types (SCTP块类型, RFC 4960 §3.2) ---
	ChunkDATA          = 0
	ChunkINIT          = 1
	ChunkINITAck       = 2
	ChunkCOOKIEEcho    = 10
	ChunkCOOKIEAck     = 11
	ChunkSHUTDOWN      = 7
	ChunkSHUTDOWNAck   = 8
	ChunkSHUTDOWNComplete = 14

	// DATA chunk flags (DATA块标志): B+E (beginning+end) for complete messages.
	ChunkFlagBeginEnd = 0x03

	// --- NGAP-PDU choice types (NGAP-PDU选择类型) ---
	PDUInitiatingMessage    = 0 // initiatingMessage (初始消息)
	PDUSuccessfulOutcome    = 1 // successfulOutcome (成功结果)
	PDUUnsuccessfulOutcome  = 2 // unsuccessfulOutcome (失败结果)

	// --- NGAP procedure codes (NGAP流程码, 3GPP TS 38.413 §9.2) ---
	ProcDownlinkNASTransport       = 4  // 下行NAS传输
	ProcNGSetup                    = 21 // NG建立
	ProcPDUSessionResourceSetup    = 29 // PDU会话资源建立
	ProcUEContextRelease           = 41 // UE上下文释放
	ProcUplinkNASTransport         = 46 // 上行NAS传输
	ProcInitialUEMessage           = 15 // 初始UE消息

	// --- NGAP criticality values (关键性, 3GPP TS 38.413 §9.1) ---
	CritReject = 0 // reject (拒绝)
	CritIgnore = 1 // ignore (忽略)
	CritNotify = 2 // notify (通知)

	// --- NGAP ProtocolIE IDs (协议信息元素标识) ---
	IEID_AMFName                   = 1   // AMF名称
	IEID_NASPDU                    = 38  // NAS-PDU
	IEID_RRCEstablishmentCause     = 90  // RRC建立原因
	IEID_UEContextRequest          = 112 // UE上下文请求
	IEID_UserLocationInfo          = 121 // 用户位置信息
	IEID_GlobalRANNodeID           = 72  // 全局RAN节点标识
	IEID_SupportedTAList           = 83  // 支持的TA列表
	IEID_DefaultPagingDRX          = 21  // 默认寻呼DRX
	IEID_RANUENGAPID               = 85  // RAN-UE-NGAP-ID
	IEID_AMFUENGAPID               = 10  // AMF-UE-NGAP-ID
	IEID_PDUSessionResourceSetupListSUReq = 77 // PDU会话资源建立列表SUReq
	IEID_PDUSessionResourceSetupListSURes = 78 // PDU会话资源建立列表SURes

	// --- Default PLMN values (默认PLMN值) ---
	DefaultMCC = 460 // China (中国)
	DefaultMNC = 1   // China Unicom (中国联通)

	// --- DRX values (DRX非连续接收值) ---
	DRXvrf128  = 0
	DRXvrf256  = 1
	DRXvrf512  = 2
	DRXvrf1024 = 3
)

// Planner implements the NGAP protocol planner.
type Planner struct{}

// NewPlanner creates a new NGAP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "ngap" }

// Validate validates an NGAP flow spec (验证NGAP流配置).
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if ip := net.ParseIP(spec.SrcIP); ip == nil {
			return fmt.Errorf("ngap: invalid SrcIP %q", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if ip := net.ParseIP(spec.DstIP); ip == nil {
			return fmt.Errorf("ngap: invalid DstIP %q", spec.DstIP)
		}
	}
	// NGAP only supports IPv4 (SCTP IPv6 path not implemented in planner).
	if spec.SrcIP != "" {
		if ip := net.ParseIP(spec.SrcIP); ip.To4() == nil {
			return fmt.Errorf("ngap: SrcIP %s is IPv6; only IPv4 is supported", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if ip := net.ParseIP(spec.DstIP); ip.To4() == nil {
			return fmt.Errorf("ngap: DstIP %s is IPv6; only IPv4 is supported", spec.DstIP)
		}
	}
	// Port validation (端口校验).
	if spec.SrcPort >= 65535 {
		return fmt.Errorf("ngap: SrcPort %d out of range", spec.SrcPort)
	}
	if spec.DstPort >= 65535 {
		return fmt.Errorf("ngap: DstPort %d out of range", spec.DstPort)
	}
	// NGAPConfig validation.
	ngap := spec.NGAP
	if ngap == nil {
		return nil // minimal: SCTP handshake only
	}
	// GlobalRANNodeID PLMN (全局RAN节点标识的PLMN校验).
	if ngap.GlobalRANNodeID != nil {
		g := ngap.GlobalRANNodeID
		if g.PLMNMCC < 0 || g.PLMNMCC > 999 {
			return fmt.Errorf("ngap: GlobalRANNodeID.PLMNMCC %d out of range [0,999]", g.PLMNMCC)
		}
		if g.PLMNMNC < 0 || g.PLMNMNC > 999 {
			return fmt.Errorf("ngap: GlobalRANNodeID.PLMNMNC %d out of range [0,999]", g.PLMNMNC)
		}
	}
	// SupportedTAList (支持的TA列表校验).
	for i, ta := range ngap.SupportedTAList {
		if ta.PLMNMCC < 0 || ta.PLMNMCC > 999 {
			return fmt.Errorf("ngap: SupportedTAList[%d].PLMNMCC %d out of range [0,999]", i, ta.PLMNMCC)
		}
		if ta.PLMNMNC < 0 || ta.PLMNMNC > 999 {
			return fmt.Errorf("ngap: SupportedTAList[%d].PLMNMNC %d out of range [0,999]", i, ta.PLMNMNC)
		}
	}
	// PDUSessionSetup (PDU会话建立校验).
	if ngap.PDUSessionSetup != nil {
		ps := ngap.PDUSessionSetup
		if ps.PDUSessionID < 0 || ps.PDUSessionID > 255 {
			return fmt.Errorf("ngap: PDUSessionSetup.PDUSessionID %d out of range [0,255]", ps.PDUSessionID)
		}
		if ps.SST < 0 || ps.SST > 255 {
			return fmt.Errorf("ngap: PDUSessionSetup.SST %d out of range [0,255]", ps.SST)
		}
	}
	// DRX validation (DRX校验).
	if ngap.DefaultPagingDRX < 0 || ngap.DefaultPagingDRX > 3 {
		return fmt.Errorf("ngap: DefaultPagingDRX %d out of range [0,3]", ngap.DefaultPagingDRX)
	}
	// NAS-PDU length checks (NAS-PDU长度校验).
	if len(ngap.InitialNAS) > 4096 {
		return fmt.Errorf("ngap: InitialNAS too long (%d bytes, max 4096)", len(ngap.InitialNAS))
	}
	if len(ngap.UplinkNAS) > 4096 {
		return fmt.Errorf("ngap: UplinkNAS too long (%d bytes, max 4096)", len(ngap.UplinkNAS))
	}
	if len(ngap.DownlinkNAS) > 4096 {
		return fmt.Errorf("ngap: DownlinkNAS too long (%d bytes, max 4096)", len(ngap.DownlinkNAS))
	}
	return nil
}

// Plan generates packet configs for an NGAP flow (生成NGAP流的包配置).
// The planner emits: SCTP 4-way handshake → NGAP signaling → SCTP 3-way teardown.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		sctpConfig := spec.SCTP
		if sctpConfig == nil {
			sctpConfig = &core.SCTPConfig{}
		}

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		// Resolve NGAP config with defaults (解析NGAP配置及默认值).
		ngap := spec.NGAP
		if ngap == nil {
			ngap = &core.NGAPConfig{}
		}
		ranUE := ngap.RANUENGAPID
		if ranUE == 0 {
			ranUE = 1
		}
		amfUE := ngap.AMFUENGAPID
		if amfUE == 0 {
			amfUE = 1
		}
		amfName := ngap.AMFName
		if amfName == "" {
			amfName = "AMF-TEST-01"
		}
		pagingDRX := ngap.DefaultPagingDRX

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		// SCTP verification tags (SCTP验证标签, RFC 4960 §5.1.1).
		clientVerTag := sctpConfig.VerificationTag
		if clientVerTag == 0 {
			clientVerTag = randNonZeroTag()
		}
		serverVerTag := sctpConfig.InitiateTag
		if serverVerTag == 0 {
			serverVerTag = randNonZeroTag()
		}

		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(rand.Uint32())
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		// TSN per direction (每方向传输序列号, RFC 6525 §5.1).
		clientTSN := rand.Uint32()
		serverTSN := rand.Uint32()

		// emitSCTP (发送SCTP包) builds and sends one SCTP packet.
		emitSCTP := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, verTag uint32, chunks []byte) {
			l3 := core.L3Base(srcIP, dstIP, core.ProtocolSCTP, effectiveTTL, nextIPID(), spec)
			cfg := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3: l3,
				L4: core.L4Config{
					Protocol: "sctp",
					SrcPort:  srcPort,
					DstPort:  dstPort,
					Ack:      verTag, // VerificationTag stored in Ack slot
				},
				Payload: chunks,
			}
			select {
			case <-ctx.Done():
				return
			case configChan <- cfg:
			}
			packetIndex++
		}

		// emitNGAP (发送NGAP消息) wraps an NGAP-PDU in an SCTP DATA chunk
		// and sends it in the given direction. The NGAP message is the
		// user payload of the SCTP DATA chunk with PPID=60 (NGAP).
		emitNGAP := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, verTag uint32, tsn *uint32, ngapPDU []byte) {
			dataChunk := buildDATAChunk(*tsn, SID_NAS, 0, PPID_NGAP, ngapPDU)
			*tsn++
			emitSCTP(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, verTag, dataChunk)
		}

		// --- SCTP 4-way handshake (SCTP四步握手, RFC 4960) ---
		// INIT (client → server, VerificationTag=0 per RFC 4960 §5.1.1).
		emitSCTP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
			spec.SrcPort, spec.DstPort, 0,
			buildINITChunk(clientVerTag, clientTSN))

		// INIT-ACK (server → client, VerificationTag=client's tag from INIT).
		cookie := make([]byte, 32)
		rand.Read(cookie)
		emitSCTP("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
			spec.DstPort, spec.SrcPort, clientVerTag,
			buildINITAckChunk(serverVerTag, serverTSN, cookie))

		// COOKIE-ECHO (client → server, VerificationTag=server's tag from INIT-ACK).
		emitSCTP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
			spec.SrcPort, spec.DstPort, serverVerTag,
			buildCOOKIEEchoChunk(cookie))

		// COOKIE-ACK (server → client, VerificationTag=client's tag).
		emitSCTP("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
			spec.DstPort, spec.SrcPort, clientVerTag,
			buildCOOKIEAckChunk())

		// --- NGAP signaling (NGAP信令) ---
		// 1. NG Setup procedure (NG建立流程, procedureCode=21).
		// Always emitted — the fundamental gNB↔AMF association setup.
		{
			ngSetupReq := buildNGSetupRequest(ngap, pagingDRX)
			emitNGAP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
				spec.SrcPort, spec.DstPort, serverVerTag, &clientTSN, ngSetupReq)

			ngSetupResp := buildNGSetupResponse(amfName)
			emitNGAP("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
				spec.DstPort, spec.SrcPort, clientVerTag, &serverTSN, ngSetupResp)
		}

		// 2. InitialUEMessage (初始UE消息, procedureCode=15).
		if ngap.InitialUEMessage {
			nas := ngap.InitialNAS
			if nas == nil {
				nas = buildDefaultNASPDU(ranUE)
			}
			initUE := buildInitialUEMessage(ranUE, amfUE, nas)
			emitNGAP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
				spec.SrcPort, spec.DstPort, serverVerTag, &clientTSN, initUE)
		}

		// 3. DownlinkNASTransport (下行NAS传输, procedureCode=4).
		if len(ngap.DownlinkNAS) > 0 {
			dlNAS := buildDownlinkNASTransport(ranUE, amfUE, ngap.DownlinkNAS)
			emitNGAP("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
				spec.DstPort, spec.SrcPort, clientVerTag, &serverTSN, dlNAS)
		}

		// 4. UplinkNASTransport (上行NAS传输, procedureCode=46).
		if len(ngap.UplinkNAS) > 0 {
			ulNAS := buildUplinkNASTransport(ranUE, amfUE, ngap.UplinkNAS)
			emitNGAP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
				spec.SrcPort, spec.DstPort, serverVerTag, &clientTSN, ulNAS)
		}

		// 5. PDU Session Resource Setup (PDU会话资源建立, procedureCode=29).
		if ngap.PDUSessionSetup != nil {
			psReq := buildPDUSessionSetupRequest(ranUE, amfUE, ngap.PDUSessionSetup)
			emitNGAP("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
				spec.DstPort, spec.SrcPort, clientVerTag, &serverTSN, psReq)

			psResp := buildPDUSessionSetupResponse(ranUE, amfUE, ngap.PDUSessionSetup)
			emitNGAP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
				spec.SrcPort, spec.DstPort, serverVerTag, &clientTSN, psResp)
		}

		// 6. UE Context Release (UE上下文释放, procedureCode=41).
		if ngap.UEContextRelease {
			// UEContextReleaseCommand (AMF→gNB, initiatingMessage).
			releaseCmd := buildUEContextReleaseCommand(ranUE, amfUE)
			emitNGAP("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
				spec.DstPort, spec.SrcPort, clientVerTag, &serverTSN, releaseCmd)

			// UEContextReleaseComplete (gNB→AMF, successfulOutcome).
			releaseComplete := buildUEContextReleaseComplete(ranUE, amfUE)
			emitNGAP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
				spec.SrcPort, spec.DstPort, serverVerTag, &clientTSN, releaseComplete)
		}

		// --- SCTP 3-way teardown (SCTP三步挥手, RFC 4960 §9.2) ---
		shutdownTSN := serverTSN
		if shutdownTSN > 0 {
			shutdownTSN-- // last TSN acked = highest received - 1
		}
		emitSCTP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
			spec.SrcPort, spec.DstPort, serverVerTag,
			buildSHUTDOWNChunk(shutdownTSN))

		emitSCTP("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
			spec.DstPort, spec.SrcPort, clientVerTag,
			buildSHUTDOWNAckChunk())

		emitSCTP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
			spec.SrcPort, spec.DstPort, serverVerTag,
			buildSHUTDOWNCompleteChunk())
	}()

	return configChan, nil
}

// --- SCTP chunk building helpers (SCTP块构造辅助函数, RFC 4960 §3.2) ---
// These mirror the SCTP planner's helpers — inlined to avoid import cycle.

// buildChunk writes a generic SCTP chunk header (Type + Flags + Length) and
// pads the value to a 4-byte boundary (填充到4字节边界) per RFC 4960 §3.2.
// The Length field includes the 4-byte header but NOT the padding.
func buildChunk(chunkType uint8, flags uint8, value []byte) []byte {
	length := uint16(4 + len(value))
	padded := (length + 3) &^ 3
	buf := make([]byte, padded)
	buf[0] = chunkType
	buf[1] = flags
	binary.BigEndian.PutUint16(buf[2:4], length)
	copy(buf[4:], value)
	return buf
}

// buildINITChunk builds an INIT chunk (type 1). Value: InitiateTag(4) +
// aRwnd(4) + OS(2) + MIS(2) + InitialTSN(4) = 16 bytes.
func buildINITChunk(initiateTag, initialTSN uint32) []byte {
	value := make([]byte, 16)
	binary.BigEndian.PutUint32(value[0:4], initiateTag)
	binary.BigEndian.PutUint32(value[4:8], 65535) // aRwnd (接收窗口)
	binary.BigEndian.PutUint16(value[8:10], 10)   // OS (出站流数, outbound streams)
	binary.BigEndian.PutUint16(value[10:12], 10)  // MIS (入站流数, max inbound streams)
	binary.BigEndian.PutUint32(value[12:16], initialTSN)
	return buildChunk(ChunkINIT, 0, value)
}

// buildINITAckChunk builds an INIT-ACK chunk (type 2). Same fixed layout as
// INIT, followed by a State Cookie parameter (type 7).
func buildINITAckChunk(initiateTag, initialTSN uint32, cookie []byte) []byte {
	value := make([]byte, 16+4+len(cookie))
	binary.BigEndian.PutUint32(value[0:4], initiateTag)
	binary.BigEndian.PutUint32(value[4:8], 65535)
	binary.BigEndian.PutUint16(value[8:10], 10)
	binary.BigEndian.PutUint16(value[10:12], 10)
	binary.BigEndian.PutUint32(value[12:16], initialTSN)
	// State Cookie param (状态Cookie参数): Type=7, Length=4+len(cookie)
	binary.BigEndian.PutUint16(value[16:18], 7)
	binary.BigEndian.PutUint16(value[18:20], uint16(4+len(cookie)))
	copy(value[20:], cookie)
	return buildChunk(ChunkINITAck, 0, value)
}

// buildCOOKIEEchoChunk builds a COOKIE-ECHO chunk (type 10).
func buildCOOKIEEchoChunk(cookie []byte) []byte {
	return buildChunk(ChunkCOOKIEEcho, 0, cookie)
}

// buildCOOKIEAckChunk builds a COOKIE-ACK chunk (type 11). No value.
func buildCOOKIEAckChunk() []byte {
	return buildChunk(ChunkCOOKIEAck, 0, nil)
}

// buildDATAChunk builds a DATA chunk (type 0) with B+E flags (complete message).
// Value: TSN(4) + SID(2) + SSN(2) + PPID(4) + user data.
func buildDATAChunk(tsn uint32, sid, ssn uint16, ppid uint32, data []byte) []byte {
	value := make([]byte, 12+len(data))
	binary.BigEndian.PutUint32(value[0:4], tsn)
	binary.BigEndian.PutUint16(value[4:6], sid)
	binary.BigEndian.PutUint16(value[6:8], ssn)
	binary.BigEndian.PutUint32(value[8:12], ppid)
	copy(value[12:], data)
	return buildChunk(ChunkDATA, ChunkFlagBeginEnd, value)
}

// buildSHUTDOWNChunk builds a SHUTDOWN chunk (type 7). Value: highest TSN ack(4).
func buildSHUTDOWNChunk(highestTSN uint32) []byte {
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value[0:4], highestTSN)
	return buildChunk(ChunkSHUTDOWN, 0, value)
}

// buildSHUTDOWNAckChunk builds a SHUTDOWN-ACK chunk (type 8). No value.
func buildSHUTDOWNAckChunk() []byte {
	return buildChunk(ChunkSHUTDOWNAck, 0, nil)
}

// buildSHUTDOWNCompleteChunk builds a SHUTDOWN-COMPLETE chunk (type 14). No value.
func buildSHUTDOWNCompleteChunk() []byte {
	return buildChunk(ChunkSHUTDOWNComplete, 0, nil)
}

// randNonZeroTag returns a random non-zero 32-bit verification tag.
// RFC 4960 §5.1.1 requires the tag to be non-zero.
func randNonZeroTag() uint32 {
	for {
		t := rand.Uint32()
		if t != 0 {
			return t
		}
	}
}

// --- NGAP-PDU encoding (NGAP-PDU编码, simplified ASN.1 PER) ---

// buildNGAPInitiating builds an initiatingMessage (初始消息) NGAP-PDU.
// Layout: choice(1)=0 + procedureCode(1) + criticality(1) + IE-container.
func buildNGAPInitiating(procCode uint8, criticality uint8, ies []byte) []byte {
	pdu := []byte{
		byte(PDUInitiatingMessage), // choice: initiatingMessage
		procCode,                   // procedureCode (流程码)
		criticality,                // criticality (关键性)
	}
	pdu = append(pdu, ies...)
	return pdu
}

// buildNGAPSuccess builds a successfulOutcome (成功结果) NGAP-PDU.
// Layout: choice(1)=1 + procedureCode(1) + criticality(1) + IE-container.
func buildNGAPSuccess(procCode uint8, criticality uint8, ies []byte) []byte {
	pdu := []byte{
		byte(PDUSuccessfulOutcome), // choice: successfulOutcome
		procCode,                   // procedureCode
		criticality,                // criticality
	}
	pdu = append(pdu, ies...)
	return pdu
}

// buildIEContainer builds a ProtocolIE-Container (协议信息元素容器).
// Layout: count(2, big-endian) + ProtocolIE-Field entries concatenated.
func buildIEContainer(ies [][]byte) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(ies)))
	for _, ie := range ies {
		buf = append(buf, ie...)
	}
	return buf
}

// buildIE builds a ProtocolIE-Field (协议信息元素字段).
// Layout: id(2) + criticality(1) + value-length(1) + value(N).
// Length uses single-byte encoding (值 < 128, fits in 7 bits).
func buildIE(id uint16, criticality uint8, value []byte) []byte {
	ie := make([]byte, 4+len(value))
	binary.BigEndian.PutUint16(ie[0:2], id)
	ie[2] = criticality
	ie[3] = byte(len(value))
	copy(ie[4:], value)
	return ie
}

// --- NGAP value encoding (NGAP值编码) ---

// encodePLMN encodes a PLMN Identity (PLMN标识, 3 bytes) from MCC+MNC.
// 3GPP TS 38.413 §9.3.1.1: nibble layout = MCC1 MCC2 | MNC3 MCC3 | MNC1 MNC2.
// Example: MCC=460, MNC=01 → 0x64 0xf0 0x10.
func encodePLMN(mcc, mnc int) []byte {
	mccDigits := [3]byte{
		byte(mcc % 10),
		byte((mcc / 10) % 10),
		byte((mcc / 100) % 10),
	}
	plmn := make([]byte, 3)
	plmn[0] = (mccDigits[1] << 4) | mccDigits[0] // MCC digit 2 | MCC digit 1
	if mnc < 100 {
		// 2-digit MNC: MNC3 (high nibble) + MCC3 (low nibble).
		// MNC3 is filled with 0xF (padding per 3GPP TS 23.003).
		mnc1 := byte(mnc % 10)
		mnc2 := byte((mnc / 10) % 10)
		plmn[1] = (0xF << 4) | mccDigits[2]
		plmn[2] = (mnc1 << 4) | mnc2
	} else {
		// 3-digit MNC: MNC3 + MCC3, MNC1 + MNC2.
		mnc1 := byte(mnc % 10)
		mnc2 := byte((mnc / 10) % 10)
		mnc3 := byte((mnc / 100) % 10)
		plmn[1] = (mnc3 << 4) | mccDigits[2]
		plmn[2] = (mnc1 << 4) | mnc2
	}
	return plmn
}

// encodeBCD3 encodes a 3-digit integer as BCD (3 nibbles, little-endian).
func encodeBCD3(n int) [3]byte {
	return [3]byte{
		byte(n % 10),
		byte((n / 10) % 10),
		byte((n / 100) % 10),
	}
}

// encodeRANUENGAPID encodes RAN-UE-NGAP-ID as a 4-byte big-endian integer.
func encodeRANUENGAPID(id uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, id)
	return buf
}

// encodeAMFUENGAPID encodes AMF-UE-NGAP-ID (simplified, 2 bytes big-endian).
func encodeAMFUENGAPID(id uint32) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(id))
	return buf
}

// encodeGlobalGNBID encodes GlobalRANNodeID for a gNB (全局RAN节点标识).
// Choice byte 0 (globalGNB-ID, 全局gNB标识) + PLMN(3) + gNB-ID BIT STRING.
func encodeGlobalGNBID(mcc, mnc int, gnbID uint32) []byte {
	plmn := encodePLMN(mcc, mnc)
	gnbIDBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(gnbIDBytes, gnbID)
	// gNB-ID encoding: BIT STRING length(1)=4 bytes + value(4)
	enc := []byte{
		0x00,                      // choice: globalGNB-ID
		0x08, byte(len(plmn) + 5), // PLMN + gNB-ID BIT STRING (length prefix + value)
	}
	enc = append(enc, plmn...)
	enc = append(enc, 0x04) // BIT STRING length: 4 bytes (32 bits)
	enc = append(enc, gnbIDBytes...)
	return enc
}

// encodeSupportedTAList encodes a list of SupportedTA-Item (支持的跟踪区项).
// SEQUENCE OF: count(1) + [PLMN(3) + TAC-list(3)] for each item.
func encodeSupportedTAList(tas []core.NGAPSupportedTA) []byte {
	if len(tas) == 0 {
		// Default: one TA with default PLMN and TAC=1.
		tas = []core.NGAPSupportedTA{{PLMNMCC: DefaultMCC, PLMNMNC: DefaultMNC, TACs: []uint32{1}}}
	}
	var buf []byte
	buf = append(buf, byte(len(tas))) // SEQUENCE OF count
	for _, ta := range tas {
		plmn := encodePLMN(ta.PLMNMCC, ta.PLMNMNC)
		buf = append(buf, plmn...)
		// BroadcastPLMN List (广播PLMN列表): 1 entry matching the TA's PLMN.
		buf = append(buf, 0x01) // count=1
		buf = append(buf, plmn...)
		// TAC List (TAC列表): count + TACs.
		tacs := ta.TACs
		if len(tacs) == 0 {
			tacs = []uint32{1}
		}
		buf = append(buf, byte(len(tacs)))
		for _, tac := range tacs {
			buf = append(buf, byte(tac>>16), byte(tac>>8), byte(tac))
		}
	}
	return buf
}

// encodeNASPDU encodes a NAS-PDU as a length-prefixed octet string (NAS-PDU长度前缀编码).
func encodeNASPDU(nas []byte) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(nas)))
	buf = append(buf, nas...)
	return buf
}

// encodePDUSessionSetupTransfer encodes a simplified PDUSessionResourceSetupRequestTransfer.
// Contains S-NSSAI (SST + SD) and a simplified transfer payload.
func encodePDUSessionSetupTransfer(ps *core.NGAPPDUSessionSetup) []byte {
	sst := ps.SST
	if sst == 0 {
		sst = 1 // default: eMBB
	}
	sd := ps.SD
	if sd == 0 {
		sd = 1
	}
	// S-NSSAI: SST(1) + SD(3) = 4 bytes
	snssai := []byte{byte(sst), byte(sd >> 16), byte(sd >> 8), byte(sd)}
	// Transfer: simplified structure with S-NSSAI + filler
	transfer := []byte{0x00, 0x04} // length of S-NSSAI
	transfer = append(transfer, snssai...)
	// Add PDUSessionID and simplified transfer data
	transfer = append(transfer, byte(ps.PDUSessionID))
	// Filler to make it look like a real transfer (填充数据)
	transfer = append(transfer, 0x00, 0x01, 0x02, 0x03)
	return transfer
}

// --- NGAP message builders (NGAP消息构造器) ---

// buildNGSetupRequest builds NGSetupRequest (NG建立请求, procedureCode=21).
// IEs: GlobalRANNodeID(72) + SupportedTAList(83) + DefaultPagingDRX(21).
func buildNGSetupRequest(ngap *core.NGAPConfig, pagingDRX int) []byte {
	// Resolve gNB parameters (解析gNB参数).
	mcc := DefaultMCC
	mnc := DefaultMNC
	gnbID := uint32(1)
	if ngap.GlobalRANNodeID != nil {
		g := ngap.GlobalRANNodeID
		if g.PLMNMCC != 0 || g.PLMNMNC != 0 {
			mcc = g.PLMNMCC
			mnc = g.PLMNMNC
		}
		if g.GNBID != 0 {
			gnbID = g.GNBID
		}
	}
	taList := ngap.SupportedTAList
	if len(taList) == 0 {
		taList = []core.NGAPSupportedTA{{PLMNMCC: DefaultMCC, PLMNMNC: DefaultMNC, TACs: []uint32{1}}}
	}
	ies := [][]byte{
		buildIE(IEID_GlobalRANNodeID, CritReject, encodeGlobalGNBID(mcc, mnc, gnbID)),
		buildIE(IEID_SupportedTAList, CritReject, encodeSupportedTAList(taList)),
		buildIE(IEID_DefaultPagingDRX, CritIgnore, []byte{byte(pagingDRX)}),
	}
	return buildNGAPInitiating(ProcNGSetup, CritReject, buildIEContainer(ies))
}

// buildNGSetupResponse builds NGSetupResponse (NG建立响应, procedureCode=21).
// IEs: AMFName(1).
func buildNGSetupResponse(amfName string) []byte {
	ies := [][]byte{
		buildIE(IEID_AMFName, CritReject, []byte(amfName)),
	}
	return buildNGAPSuccess(ProcNGSetup, CritIgnore, buildIEContainer(ies))
}

// buildInitialUEMessage builds InitialUEMessage (初始UE消息, procedureCode=15).
// IEs: RAN-UE-NGAP-ID(85) + NAS-PDU(38) + UserLocationInfo(121) +
//
//	RRCEstablishmentCause(90) + UEContextRequest(112).
func buildInitialUEMessage(ranUE, amfUE uint32, nasPDU []byte) []byte {
	ies := [][]byte{
		buildIE(IEID_RANUENGAPID, CritReject, encodeRANUENGAPID(ranUE)),
		buildIE(IEID_NASPDU, CritReject, encodeNASPDU(nasPDU)),
		buildIE(IEID_UserLocationInfo, CritReject, buildUserLocationInfo()),
		buildIE(IEID_RRCEstablishmentCause, CritIgnore, buildRRCEstablishmentCause(4)), // mo-Data
		buildIE(IEID_UEContextRequest, CritIgnore, []byte{0x00}),                        // requested
	}
	return buildNGAPInitiating(ProcInitialUEMessage, CritIgnore, buildIEContainer(ies))
}

// buildDownlinkNASTransport builds DownlinkNASTransport (下行NAS传输, procedureCode=4).
// IEs: AMF-UE-NGAP-ID(10) + RAN-UE-NGAP-ID(85) + NAS-PDU(38).
func buildDownlinkNASTransport(ranUE, amfUE uint32, nasPDU []byte) []byte {
	ies := [][]byte{
		buildIE(IEID_AMFUENGAPID, CritReject, encodeAMFUENGAPID(amfUE)),
		buildIE(IEID_RANUENGAPID, CritReject, encodeRANUENGAPID(ranUE)),
		buildIE(IEID_NASPDU, CritReject, encodeNASPDU(nasPDU)),
	}
	return buildNGAPInitiating(ProcDownlinkNASTransport, CritIgnore, buildIEContainer(ies))
}

// buildUplinkNASTransport builds UplinkNASTransport (上行NAS传输, procedureCode=46).
// IEs: AMF-UE-NGAP-ID(10) + RAN-UE-NGAP-ID(85) + NAS-PDU(38).
func buildUplinkNASTransport(ranUE, amfUE uint32, nasPDU []byte) []byte {
	ies := [][]byte{
		buildIE(IEID_AMFUENGAPID, CritReject, encodeAMFUENGAPID(amfUE)),
		buildIE(IEID_RANUENGAPID, CritReject, encodeRANUENGAPID(ranUE)),
		buildIE(IEID_NASPDU, CritReject, encodeNASPDU(nasPDU)),
	}
	return buildNGAPInitiating(ProcUplinkNASTransport, CritIgnore, buildIEContainer(ies))
}

// buildPDUSessionSetupRequest builds PDUSessionResourceSetupRequest (PDU会话资源建立请求).
// IEs: AMF-UE-NGAP-ID(10) + RAN-UE-NGAP-ID(85) + PDUSessionResourceSetupListSUReq(77).
func buildPDUSessionSetupRequest(ranUE, amfUE uint32, ps *core.NGAPPDUSessionSetup) []byte {
	setupList := buildPDUSessionSetupList(ps, true)
	ies := [][]byte{
		buildIE(IEID_AMFUENGAPID, CritReject, encodeAMFUENGAPID(amfUE)),
		buildIE(IEID_RANUENGAPID, CritReject, encodeRANUENGAPID(ranUE)),
		buildIE(IEID_PDUSessionResourceSetupListSUReq, CritReject, setupList),
	}
	return buildNGAPInitiating(ProcPDUSessionResourceSetup, CritReject, buildIEContainer(ies))
}

// buildPDUSessionSetupResponse builds PDUSessionResourceSetupResponse (PDU会话资源建立响应).
// IEs: AMF-UE-NGAP-ID(10) + RAN-UE-NGAP-ID(85) + PDUSessionResourceSetupListSURes(78).
func buildPDUSessionSetupResponse(ranUE, amfUE uint32, ps *core.NGAPPDUSessionSetup) []byte {
	setupList := buildPDUSessionSetupList(ps, false)
	ies := [][]byte{
		buildIE(IEID_AMFUENGAPID, CritReject, encodeAMFUENGAPID(amfUE)),
		buildIE(IEID_RANUENGAPID, CritReject, encodeRANUENGAPID(ranUE)),
		buildIE(IEID_PDUSessionResourceSetupListSURes, CritReject, setupList),
	}
	return buildNGAPSuccess(ProcPDUSessionResourceSetup, CritIgnore, buildIEContainer(ies))
}

// buildPDUSessionSetupList builds a simplified PDUSessionResourceSetupList
// (PDU会话资源建立列表). Contains one session entry with PDUSessionID + transfer data.
func buildPDUSessionSetupList(ps *core.NGAPPDUSessionSetup, isRequest bool) []byte {
	sessionID := ps.PDUSessionID
	if sessionID == 0 {
		sessionID = 1
	}
	transfer := encodePDUSessionSetupTransfer(ps)
	// PDUSessionResourceSetupItem: PDUSessionID(1) + transfer-length(2) + transfer
	var item []byte
	item = append(item, byte(sessionID))
	item = append(item, byte(len(transfer)>>8), byte(len(transfer)))
	item = append(item, transfer...)
	// SEQUENCE OF: count(1) + items
	return append([]byte{0x01}, item...)
}

// buildUEContextReleaseCommand builds UEContextReleaseCommand (UE上下文释放命令).
// initiatingMessage with AMF-UE-NGAP-ID(10) + RAN-UE-NGAP-ID(85).
func buildUEContextReleaseCommand(ranUE, amfUE uint32) []byte {
	ies := [][]byte{
		buildIE(IEID_AMFUENGAPID, CritReject, encodeAMFUENGAPID(amfUE)),
		buildIE(IEID_RANUENGAPID, CritReject, encodeRANUENGAPID(ranUE)),
	}
	return buildNGAPInitiating(ProcUEContextRelease, CritReject, buildIEContainer(ies))
}

// buildUEContextReleaseComplete builds UEContextReleaseComplete (UE上下文释放完成).
// successfulOutcome with AMF-UE-NGAP-ID(10) + RAN-UE-NGAP-ID(85).
func buildUEContextReleaseComplete(ranUE, amfUE uint32) []byte {
	ies := [][]byte{
		buildIE(IEID_AMFUENGAPID, CritReject, encodeAMFUENGAPID(amfUE)),
		buildIE(IEID_RANUENGAPID, CritReject, encodeRANUENGAPID(ranUE)),
	}
	return buildNGAPSuccess(ProcUEContextRelease, CritIgnore, buildIEContainer(ies))
}

// --- Helper message builders (辅助消息构造器) ---

// buildUserLocationInfo builds a simplified UserLocationInformationNR IE value.
// Contains NR-CGI (nR-CGI, NR小区全局标识) + TAI (跟踪区标识) with default PLMN.
func buildUserLocationInfo() []byte {
	plmn := encodePLMN(DefaultMCC, DefaultMNC)
	nrCGI := make([]byte, 0, 8)
	nrCGI = append(nrCGI, plmn...)
	nrCGI = append(nrCGI, 0x00, 0x00, 0x00, 0x21) // nR-CellIdentity (NR小区标识)
	tai := make([]byte, 0, 6)
	tai = append(tai, plmn...)
	tai = append(tai, 0x00, 0x00, 0x01) // TAC=1 (跟踪区码)
	// UserLocationInformationNR: choice(1) + NR-CGI-len(1) + NR-CGI + TAI-len(1) + TAI
	info := []byte{0x01} // choice: userLocationInformationNR
	info = append(info, byte(len(nrCGI)))
	info = append(info, nrCGI...)
	info = append(info, byte(len(tai)))
	info = append(info, tai...)
	return info
}

// buildRRCEstablishmentCause builds an RRC Establishment Cause (RRC建立原因).
// cause=4 (mo-Data, 移动终端发起的数据) is the most common.
func buildRRCEstablishmentCause(cause int) []byte {
	return []byte{byte(cause)}
}

// buildDefaultNASPDU builds a minimal Registration Request NAS-PDU (默认注册请求NAS-PDU).
// This mirrors the structure from the reference pcap (SCTP_NAS.pcap):
// 7e 00 41 79 <MCC/MNC/identity> <capabilities> <NSSAI>
func buildDefaultNASPDU(ranUE uint32) []byte {
	// 5GS Registration Request (5GS注册请求) with SUCI (用户隐藏标识符).
	plmn := encodePLMN(DefaultMCC, DefaultMNC)
	nas := []byte{
		0x7e, // Extended protocol discriminator (扩展协议鉴别器): 5GMM
		0x00, // Security header type (安全头类型): plain
		0x41, // Message type (消息类型): Registration request (注册请求)
		0x79, // Registration type (注册类型) + FOR bit: initial registration
		0x00, // NAS key set identifier (NAS密钥集标识)
	}
	// 5GS mobile identity (5GS移动标识): SUCI (用户隐藏标识符).
	nas = append(nas, byte(13+len(plmn))) // length of mobile identity
	nas = append(nas, 0x01)               // type: SUCI
	nas = append(nas, plmn...)
	nas = append(nas, 0x00, 0x00) // routing indicator (路由指示器)
	nas = append(nas, 0x00)       // protection scheme (保护方案): NULL
	nas = append(nas, 0x00)       // home network public key identifier (归属网络公钥标识)
	// MSIN (移动用户识别号): encoded from ranUE, up to 10 digits.
	msin := fmt.Sprintf("%010d", uint64(ranUE)%10000000000)
	nas = append(nas, []byte(msin)...)
	// 5GMM capability (5GMM能力): minimal.
	nas = append(nas, 0x10, 0x01, 0x00)
	// UE security capability (UE安全能力).
	nas = append(nas, 0x2e, 0x04, 0x80, 0xa0, 0x80, 0x00)
	// Requested NSSAI (请求的网络切片标识).
	nas = append(nas, 0x2f, 0x05, 0x04, 0x01, 0x00, 0x00, 0x01)
	return nas
}
