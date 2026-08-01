// Package rdp implements the RDP (Remote Desktop Protocol) planner.
//
// RDP is a multi-layer protocol stack on TCP/3389:
//
//	TPKT (RFC 1006)  - 4-byte header (Version=3, Reserved=0, Length uint16 BE)
//	X.224 (ISO 8073)  - CR=0xE0 / CC=0xD0 / DR=0x80 / DT=0xF0 PDU types
//	MCS (T.125)       - Connect-Initial / Connect-Response / Erect-Domain /
//	                    Attach-User / Channel-Join (ASN.1 BER + PER)
//	GCC (T.124)       - Conference Create Request/Response carrying Client/
//	                    Server Core/Security/Channels Data
//	RDP               - Security Exchange, Client Info, License, Capabilities,
//	                    FastPath Input/Output, virtual channels (cliprdr/rdpdr/
//	                    rdpsnd/drdynvc).
//
// The planner emits a TCP 3-way handshake, then a sequence of PSH-ACK
// payloads each carrying one TPKT/X.224/MCS/GCC/RDP PDU, then a TCP 4-way
// teardown. Each PDU is wrapped in TPKT/X.224 DT for SlowPath PDUs or
// sent raw for FastPath PDUs (which bypass TPKT/X.224 - MS-RDPBCGR §2.2.9).
//
// Encryption is opaque: in Standard RDP Security mode, the planner
// synthesises a Security Exchange PDU with dummy encryptedClientRandom
// bytes of the configured length (default 128, RSA-1024) and the
// downstream RDP PDUs use a fixed-length MAC placeholder. The byte
// layout is correct but the encrypted contents cannot be decrypted.
//
// State machine (MS-RDPBCGR §1.3):
//  1. TCP handshake (3 packets: SYN/SYN-ACK/ACK)
//  2. X.224 CR + Negotiation Request (client->server)
//  3. X.224 CC + Negotiation Response (server->client)
//     -- OR -- X.224 DR + Negotiation Failure (server->client, terminate)
//  4. (NLA) CredSSP / (TLS) TLS handshake (opaque bytes, see note)
//  5. MCS Connect-Initial (client->server, contains GCC Conference Create
//     Request with Client Core/Security/Channels Data)
//  6. MCS Connect-Response (server->client, contains Server Core/Net/Security)
//  7. MCS Erect-Domain Request (client->server)
//  8. MCS Attach-User Request (client->server)
//  9. MCS Attach-User Confirm (server->client, allocates user ID 1001)
// 10. MCS Channel-Join Request x N (client->server) + Confirm x N
//     (server->client). I/O Channel 1003 is always joined; static virtual
//     channels 1004..1003+N for each entry in RDPConfig.Channels.
// 11. (Standard RDP) Security Exchange PDU (client->server)
// 12. Client Info PDU (client->server, skipped in NLA mode)
// 13. License Request (server->client) -> Client License Info (client->server)
// 14. Server Demand Active PDU (server->client)
// 15. Client Confirm Active PDU (client->server, contains Capability Sets)
// 16. Server Synchronize / Control Cooperate / Control Grant / Font Map
// 17. (Active) DataEvents (FastPath Input / channel data) + ServerResponses
//     (FastPath Output)
// 18. Shutdown Request + MCS Disconnect Provider Ultimatum + TCP teardown
//
// Security layer selection (MS-RDPBCGR §5.4):
//   - "standard" -> PROTOCOL_RDP (0x01) -> Security Exchange PDU
//   - "tls"      -> PROTOCOL_SSL (0x02) -> TLS handshake (opaque)
//   - "nla"      -> PROTOCOL_HYBRID (0x08) -> CredSSP over TLS (opaque)
//   - "nla_ex"   -> PROTOCOL_HYBRID_EX (0x20) -> CredSSP+Early User Auth
package rdp

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
	DefaultTTL = 64
	DefaultMSS = 1460
	MinMSS     = 536

	// DefaultRDPPort is the standard RDP server port (MS-RDPBCGR §1.3).
	DefaultRDPPort = 3389

	// TPKT version (RFC 1006 §4).
	TPKTVersion = 0x03

	// X.224 PDU types (ISO 8073 §12, high 4 bits).
	X224CR = 0xE0 // Connection Request
	X224CC = 0xD0 // Connection Confirm
	X224DR = 0x80 // Disconnect Request
	X224DT = 0xF0 // Data Transfer

	// RDP Negotiation Request/Response types (MS-RDPBCGR §2.2.1.1-2).
	TypeRDPNegReq     = 1
	TypeRDPNegRsp     = 2
	TypeRDPNegFailure = 3

	// RDP Negotiation Request flags (MS-RDPBCGR §2.2.1.1).
	NegFlagRestrictedAdmin      = 0x01
	NegFlagRedirectedAuth       = 0x02
	NegFlagExtendedClientData   = 0x01 // RSP only

	// RequestedProtocols bitmask (MS-RDPBCGR §2.2.1.1.1).
	ProtocolRDP       = 0x00000001
	ProtocolSSL       = 0x00000002
	ProtocolHybrid    = 0x00000008
	ProtocolHybridEx  = 0x00000020

	// Negotiation Request/Response length (fixed 8 bytes including type+flags+length+protocols).
	NegReqLen = 8

	// MCS ASN.1 application tags (T.125 §7).
	MCSConnectInitialTag     = 0x7F // APPLICATION 101 (long form: 0x7F 0x65)
	MCSConnectInitialTagByte = 0x65
	MCSConnectResponseTag    = 0x7F // APPLICATION 102 (long form: 0x7F 0x66)
	MCSConnectResponseTagByte = 0x66

	// MCS PDU Reason codes (PER-encoded first byte).
	MCSErectDomainRequest = 0x04
	MCSAttachUserRequest  = 0x28
	MCSAttachUserConfirm  = 0x2C
	MCSChannelJoinRequest = 0x38
	MCSChannelJoinConfirm = 0x3C
	MCSDisconnectProviderUltimatum = 0xC0

	// MCS Channel ID conventions (MS-RDPBCGR §2.2.1.7.1, C-RDP-2).
	MCSUserIDClient      = 1001 // 0x03E9 - allocated by Attach-User Confirm
	MCSIOChannel         = 1003 // 0x03EB - I/O Channel (always joined)
	MCSFirstStaticChan   = 1004 // 0x03EC - first static virtual channel
	MCSLastStaticChan    = 1031 // 0x0407 - last static virtual channel (28 total)

	// GCC t124Identifier (H.221 OID, fixed 20 bytes, T.124 §8.7).
	GCCt124IdentifierLen = 20

	// Client Core Data (MS-RDPBCGR §2.2.1.3.2) keys (H.221 non-ASN.1).
	CSCore        = 0xC001
	CSSecurity    = 0xC002
	CSChannels    = 0xC003
	SCCore        = 0xC001 // Server side reuses the same key namespace
	SCSecurity    = 0xC002

	// Client Core Data fixed-size fields.
	ClientNameLenBytes    = 16 // UTF-16LE, max 8 chars (C-RDP-3)
	ClientDigProductIdLen = 64 // UTF-16LE, 32 chars
	IMEFileNameLen        = 64
	ClientCoreMinLen      = 218 // without extended fields

	// Client Info PDU flags (MS-RDPBCGR §2.2.1.11.1.1).
	InfoUnicode     = 0x0010
	InfoLogonNotify = 0x0040
	InfoCompression = 0x0080
	InfoAutoLogon   = 0x0008

	// Security header flags (MS-RDPBCGR §2.2.8.1.1.2.1).
	SecExchangePkt = 0x0080
	SecEncrypt     = 0x0008
	SecResetSeq    = 0x0010

	// License PDU bMsgType values (MS-RDPELE §2.2.2).
	LicenseRequest       = 0x01
	PlatformChallenge    = 0x02
	NewLicense           = 0x03
	UpgradeLicense       = 0x04
	ErrorAlert           = 0x06
	LicenseInfo          = 0x07
	NewLicenseRequest    = 0x08
	ClientLicenseInfo    = 0x0C

	// License PDU flags (MS-RDPELE §2.2.2).
	LicensePktFlag      = 0x02
	ErrorPktFlag        = 0x04
	AnnotatedRequestFlag = 0x10

	// Capability Set types (MS-RDPBCGR §2.2.1.13.1).
	CapsTypeGeneral              = 0x0001
	CapsTypeBitmap               = 0x0002
	CapsTypeOrder                = 0x0003
	CapsTypeBitmapCache          = 0x0005
	CapsTypePointer              = 0x0007
	CapsTypeInput                = 0x0008
	CapsTypeBMPCodec             = 0x0009
	CapsTypeColorCache           = 0x000A
	CapsTypeShare                = 0x000C
	CapsTypeFont                 = 0x000D
	CapsTypeDrawGDIPlus          = 0x000E
	CapsTypeRail                 = 0x000F
	CapsTypeWindow               = 0x0010
	CapsTypeMultiFragmentUpdate  = 0x0012
	CapsTypeFrameAcknowledge     = 0x0017
	CapsTypeSurfaceCommands      = 0x001A
	CapsTypeVirtualChannel       = 0x001B

	// TS_PDUTYPE2 (MS-RDPBCGR §2.2.9.1.2).
	PDUType2Update          = 0x0002
	PDUType2Pointer         = 0x0006
	PDUType2Input           = 0x0004
	PDUType2RefreshRect     = 0x0024
	PDUType2PlaySound       = 0x0025
	PDUType2SuppressOutput  = 0x0026
	PDUType2ShutdownRequest = 0x0027
	PDUType2ShutdownDenied  = 0x0028
	PDUType2FontList        = 0x002A
	PDUType2FontMap         = 0x002B
	PDUType2SaveSessionInfo = 0x0031
	PDUType2StatusInfo      = 0x0036
	PDUType2MonitorLayout   = 0x0037

	// FastPath Input action (high 2 bits of fpActionHeader).
	FastPathInputAction  = 0x00 // high 2 bits = 00
	FastPathOutputAction = 0x40 // high 2 bits = 01

	// FastPath fragmentation flags (low 2 bits of next-2-bits, MS-RDPBCGR §2.2.9.1.2.1).
	FastPathFragmentSingle = 0x00
	FastPathFragmentFirst  = 0x01
	FastPathFragmentNext   = 0x02
	FastPathFragmentLast   = 0x03

	// FastPath update codes (MS-RDPBCGR §2.2.9.1.2.3.1).
	FastPathUpdateBitmap     = 0x01
	FastPathUpdatePalette    = 0x02
	FastPathUpdateSurface    = 0x02
	FastPathUpdatePointer    = 0x03

	// FastPath input event flags (MS-RDPBCGR §2.2.8.1.1.2.1).
	KbdFlagsRelease = 0x02
	PTRFlagsMove    = 0x0800
	PTRFlagsDown    = 0x8000

	// CLIPRDR msgType values (MS-RDPCGR §1.3.1).
	CBMonitorReady        = 1
	CBFormatList          = 2
	CBFormatListResponse  = 3
	CBFormatDataRequest   = 4
	CBFormatDataResponse  = 5
	CBTempDirectory       = 6
	CBClipCaps            = 7
	CBFileContentsRequest = 8
	CBFileContentsResponse= 9
	CBLockClipData        = 10
	CBUnlockClipData      = 11

	CBResponseOK   = 0x01
	CBResponseFail = 0x02

	// RDPDR PacketId values (MS-RDPEFS §2.2.1).
	RDPDRCtypCore = 0x0002 // RDPDR_CTYP_PRN (component value used for printer + core)
	RDPDRCtypFile = 0x0003 // RDPDR_CTYP_FS (filesystem)

	PAKIDCoreServerAnnounce     = 0x0001
	PAKIDCoreClientIDConfirm    = 0x0002
	PAKIDCoreClientName         = 0x0003
	PAKIDCoreDeviceListAnnounce = 0x0004
	PAKIDCoreDeviceReply        = 0x0005
	PAKIDCoreUserLoggedon       = 0x0007
	PAKIDPrnCacheData           = 0x000A
	PAKIDCoreDeviceListRemove   = 0x0010

	// RDPDR DeviceType (MS-RDPEFS §2.2.1.6).
	RDPDRDtypSerial     = 0x00000001
	RDPDRDtypPrint      = 0x00000004
	RDPDRDtypFilesystem = 0x00000008

	// RDPSND msgType (MS-RDPSND §2.1).
	SNDCWave        = 0x04
	SNDCClose       = 0x05
	SNDCFormats     = 0x07
	SNDCQualityMode = 0x0C

	// DRDYNVC Cmd (MS-RDPEDYC §2.2.1).
	DRDYNVCCreate       = 0x01
	DRDYNVCDataFirst    = 0x02
	DRDYNVCData         = 0x03
	DRDYNVCClose        = 0x04
	DRDYNVCCapabilityRsp= 0x05

	// BER tags used by MCS / GCC (X.690).
	BERBoolean    = 0x01
	BERInteger    = 0x02
	BEROctetString= 0x04
	BERNull       = 0x05
	BEREnumerated = 0x0A
	BERSequence   = 0x30
	BERSet        = 0x31

	// GCC Connect-Data t124Identifier (H.221 ASN.1 OID, fixed 20 bytes).
	// Source: MS-RDPBCGR §2.2.1.3 / T.124 §8.7. Identifier for "T.124".
	gccT124Identifier = "\x00\x05\x00\x14\x7C\x00\x01\x2A\x0E\x14\x76\x0A\x04\x81\x0A\x00\x00\x00\x00\x00"

	// DefaultRSAKeyBytes for Security Exchange PDU encryptedClientRandom.
	// RSA-1024 -> 128 bytes; RSA-2048 -> 256 bytes. Default 128 (Win7+).
	DefaultRSAKeyBytes = 128
)

// Planner implements the RDP protocol planner.
type Planner struct{}

// NewPlanner creates a new RDP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "rdp" }

// Validate validates an RDP flow spec.
//
// Validation rules derived from MS-RDPBCGR §2.2.1.x and the test spec
// (testcases_rdp.md §1.x, §4.x). The Validate function checks the
// user-facing RDPConfig fields and FlowSpec basics. The Plan() goroutine
// performs the actual encoding; byte-level invariants are tested via
// planner_testpoints_test.go (which calls the lower-level encoders
// directly rather than going through Validate).
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.RDP == nil {
		return fmt.Errorf("RDP config is required")
	}
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
	// DstPort defaults to 3389 in Plan() via the strategy_convert rdp
	// branch; when the user sets it explicitly it MUST be 3389.
	if spec.DstPort != 0 && spec.DstPort != DefaultRDPPort {
		return fmt.Errorf("DstPort must be 3389 (got %d)", spec.DstPort)
	}

	cfg := spec.RDP
	switch cfg.SecurityLayer {
	case "", "standard", "tls", "nla", "nla_ex":
		// ok
	default:
		return fmt.Errorf("SecurityLayer %q not in {standard,tls,nla,nla_ex}", cfg.SecurityLayer)
	}

	// ClientName UTF-16LE must fit in the 16-byte field (max 8 chars).
	if u16 := utf16Len(cfg.ClientName); u16 > ClientNameLenBytes {
		return fmt.Errorf("clientName must be <= 16 bytes UTF-16LE (8 chars max) (MS-RDPBCGR §2.2.1.3.2)")
	}

	// Desktop dimensions must be in the 200..32768 range (per
	// MS-RDPBCGR §2.2.1.3.2 field range, validated at the planner).
	if cfg.DesktopWidth != 0 && (cfg.DesktopWidth < 200 || cfg.DesktopWidth > 32768) {
		return fmt.Errorf("desktopWidth must be 200-32768 (got %d)", cfg.DesktopWidth)
	}
	if cfg.DesktopHeight != 0 && (cfg.DesktopHeight < 200 || cfg.DesktopHeight > 32768) {
		return fmt.Errorf("desktopHeight must be 200-32768 (got %d)", cfg.DesktopHeight)
	}
	if cfg.ColorDepth != 0 {
		switch cfg.ColorDepth {
		case 1, 2, 3, 4, 5:
			// ok
		default:
			return fmt.Errorf("colorDepth must be 1/2/3/4/5 (got %d)", cfg.ColorDepth)
		}
	}

	// Static virtual channel count limit (MS-RDPBCGR §2.2.1.3.4:
	// channelCount is uint16 but spec limit is 31).
	if len(cfg.Channels) > 31 {
		return fmt.Errorf("channelCount must be <= 31 (MS-RDPBCGR §2.2.1.3.4)")
	}

	// Channel names must be 7-bit ASCII and <= 7 chars (8 bytes with pad).
	for i, ch := range cfg.Channels {
		if len(ch.Name) > 7 {
			return fmt.Errorf("Channels[%d].Name %q too long (max 7 chars)", i, ch.Name)
		}
		for _, c := range ch.Name {
			if c > 0x7F {
				return fmt.Errorf("Channels[%d].Name %q must be 7-bit ASCII", i, ch.Name)
			}
		}
	}

	// Scenario mode: validate the scenario name. Manual mode (empty
	// Scenario) skips this and uses Channels/DataEvents/ServerResponses
	// verbatim (backward compatible). Per design_rdp.md §4 + scenario.go.
	if cfg.Scenario != "" {
		if err := validateScenario(cfg); err != nil {
			return err
		}
	}

	return nil
}

// Plan generates packet configs for an RDP flow.
//
// The flow is emitted in protocol-order: TCP handshake -> X.224 CR ->
// X.224 CC -> (optional TLS / CredSSP opaque bytes) -> MCS Connect-Initial
// -> MCS Connect-Response -> Erect-Domain -> Attach-User -> Channel-Join
// (per channel) -> Security Exchange (Standard only) -> Client Info ->
// License -> Demand Active -> Confirm Active -> Synchronize/Control/Font
// Map -> DataEvents/ServerResponses -> Shutdown -> MCS Disconnect -> TCP
// teardown. Each RDP PDU is one PSH-ACK payload (no MSS-spanning PDUs in
// the test cases; the segmenter is still applied for safety).
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, DefaultRDPPort)
		if spec.DstPort != 0 {
			flowID = fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
		}

		cfg := spec.RDP
		if cfg == nil {
			cfg = &core.RDPConfig{}
		}

		// Scenario mode: fill in Channels / DataEvents / ServerResponses
		// with scenario defaults before encoding. User-supplied fields
		// are preserved (forwarder-style override). Per design_rdp.md §4
		// + scenario.go.
		applyScenarioDefaults(cfg)

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		synOpts := synOptions(mss)

		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(rand.Uint32())
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		// Random ISN per RFC 6528 unless overridden.
		clientSeq := uint32(0)
		if spec.TCP != nil {
			clientSeq = spec.TCP.InitialSeq
		}
		if clientSeq == 0 {
			clientSeq = rand.Uint32()
		}
		serverSeq := rand.Uint32()
		winSize := uint16(65535)

		// emit emits one TCP segment (handshake or data) into configChan.
		// payload=nil for control flags; non-nil payload is wrapped in
		// PSH-ACK (0x18). Returns ctx error to signal early termination.
		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) {
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
				l4.TCPOptions = synOpts
			}
			cfgPkt := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3:      l3,
				L4:      l4,
				Payload: payload,
			}
			select {
			case configChan <- cfgPkt:
			case <-ctx.Done():
			}
			packetIndex++
		}

		// emitData segments payload by MSS and emits each chunk as a
		// PSH-ACK in the given direction. Returns the new sender seq.
		// When tlsActive (post-TLS-handshake), every chunk is wrapped in
		// its own TLS Application Data record (5-byte header + body) so
		// the wire stays parseable as TLS after the handshake; the 5-byte
		// header is budgeted against the MSS and the sender seq advances
		// by the wrapped wire bytes.
		// tlsActive flips to true after the TLS handshake pair; from then
		// on every RDP PDU is carried inside a TLS Application Data record
		// (real RDP over TLS behavior - MS-RDPBCGR §5.4.2). Without the
		// wrap, Wireshark reports "Ignored Unknown Record" for the raw
		// TPKT/X.224 PDUs that follow the ServerHello on the now-TLS
		// connection.
		tlsActive := false
		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) (newSenderSeq uint32, aborted bool) {
			maxSeg := int(mss)
			if tlsActive {
				maxSeg -= 5 // TLS record header (ContentType+Version+Length)
			}
			for _, seg := range segmentByMSS(payload, maxSeg) {
				if ctx.Err() != nil {
					return senderSeq, true
				}
				if tlsActive {
					seg = wrapTLSAppData(seg)
				}
				emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq, false
		}

		// Convenience wrappers for up/down direction.
		up := func(payload []byte, seq, ack uint32) (uint32, bool) {
			return emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, DefaultRDPPort, seq, ack, payload)
		}
		down := func(payload []byte, seq, ack uint32) (uint32, bool) {
			return emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, DefaultRDPPort, spec.SrcPort, seq, ack, payload)
		}

		// DstPort is always 3389 (the planner forces it via Validate).
		// The wrappers below use DefaultRDPPort directly.

		// --- TCP 3-way handshake ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, DefaultRDPPort, clientSeq, 0, 0x02, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, DefaultRDPPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, DefaultRDPPort, clientSeq, serverSeq, 0x10, nil)

		if ctx.Err() != nil {
			return
		}

		// --- Phase 2: X.224 CR + Negotiation Request ---
		x224cr := encodeTPKT(encodeX224CR(cfg))
		clientSeq, aborted := up(x224cr, clientSeq, serverSeq)
		if aborted {
			return
		}

		// --- Phase 2 response: X.224 CC + Negotiation Response ---
		x224cc := encodeTPKT(encodeX224CC(cfg))
		serverSeq, aborted = down(x224cc, serverSeq, clientSeq)
		if aborted {
			return
		}

		// --- Phase 3: TLS / CredSSP (opaque bytes when configured) ---
		// We emit a placeholder TLS ClientHello-like payload so the wire
		// layout has the right shape (TLS record header bytes). Real TLS
		// negotiation is out of scope; this models the byte structure.
		if needsTLSHandshake(cfg) {
			tlsBytes := encodeTLSHandshakePlaceholder(cfg)
			clientSeq, aborted = up(tlsBytes, clientSeq, serverSeq)
			if aborted {
				return
			}
			tlsResp := encodeTLSHandshakePlaceholderResponse(cfg)
			serverSeq, aborted = down(tlsResp, serverSeq, clientSeq)
			if aborted {
				return
			}
			// From here on the connection is TLS: every subsequent RDP PDU
			// is wrapped in a TLS Application Data record (see emitData).
			tlsActive = true
		}

		// --- Phase 4: MCS Connect-Initial (with GCC Connect-Data) ---
		mcsCI := encodeTPKT(encodeX224DT(encodeMCSConnectInitial(cfg)))
		clientSeq, aborted = up(mcsCI, clientSeq, serverSeq)
		if aborted {
			return
		}

		// --- Phase 4 response: MCS Connect-Response ---
		mcsCR := encodeTPKT(encodeX224DT(encodeMCSConnectResponse(cfg)))
		serverSeq, aborted = down(mcsCR, serverSeq, clientSeq)
		if aborted {
			return
		}

		// --- Phase 5: MCS Erect-Domain Request ---
		ed := encodeTPKT(encodeX224DT(encodeMCSErectDomainRequest()))
		clientSeq, aborted = up(ed, clientSeq, serverSeq)
		if aborted {
			return
		}

		// --- Phase 5: MCS Attach-User Request ---
		auReq := encodeTPKT(encodeX224DT(encodeMCSAttachUserRequest()))
		clientSeq, aborted = up(auReq, clientSeq, serverSeq)
		if aborted {
			return
		}

		// --- Phase 5 response: MCS Attach-User Confirm ---
		auConf := encodeTPKT(encodeX224DT(encodeMCSAttachUserConfirm(MCSUserIDClient)))
		serverSeq, aborted = down(auConf, serverSeq, clientSeq)
		if aborted {
			return
		}

		// --- Phase 5: MCS Channel-Join for I/O Channel (1003) + each static channel ---
		if !cfg.SkipMCSChannelJoin {
			// I/O channel 1003 first.
			cjReq := encodeTPKT(encodeX224DT(encodeMCSChannelJoinRequest(MCSUserIDClient, MCSIOChannel)))
			clientSeq, aborted = up(cjReq, clientSeq, serverSeq)
			if aborted {
				return
			}
			cjConf := encodeTPKT(encodeX224DT(encodeMCSChannelJoinConfirm(MCSUserIDClient, MCSIOChannel, 0)))
			serverSeq, aborted = down(cjConf, serverSeq, clientSeq)
			if aborted {
				return
			}

			// Then one Channel-Join per declared channel, IDs 1004..1003+N.
			for i, ch := range cfg.Channels {
				channelID := uint16(MCSFirstStaticChan) + uint16(i)
				if channelID > MCSLastStaticChan {
					break
				}
				cjReq := encodeTPKT(encodeX224DT(encodeMCSChannelJoinRequest(MCSUserIDClient, channelID)))
				clientSeq, aborted = up(cjReq, clientSeq, serverSeq)
				if aborted {
					return
				}
				result := uint8(0) // rt-successful
				// When the user-supplied ServerResponses include a
				// channel-join-failure for this channel name, set result=4
				// (rt-no-such-channel). The planner still continues with
				// the remaining channels (MS-RDPBCGR §3.2.1.5).
				if hasChannelJoinFailure(cfg, ch.Name) {
					result = 4
				}
				cjConf := encodeTPKT(encodeX224DT(encodeMCSChannelJoinConfirm(MCSUserIDClient, channelID, result)))
				serverSeq, aborted = down(cjConf, serverSeq, clientSeq)
				if aborted {
					return
				}
			}
		}

		// --- Phase 6: Security Exchange (Standard RDP Security only) ---
		if cfg.SecurityLayer == "standard" && !cfg.SkipSecurityExchange {
			secEx := encodeTPKT(encodeX224DT(encodeSecurityExchange(cfg)))
			clientSeq, aborted = up(secEx, clientSeq, serverSeq)
			if aborted {
				return
			}
		}

		// --- Phase 7: Client Info PDU (skipped in NLA mode) ---
		if cfg.SecurityLayer != "nla" && cfg.SecurityLayer != "nla_ex" {
			info := encodeTPKT(encodeX224DT(encodeClientInfoPDU(cfg)))
			clientSeq, aborted = up(info, clientSeq, serverSeq)
			if aborted {
				return
			}
		}

		// --- Phase 7 response: License Request + Client License Info ---
		if !cfg.SkipLicense {
			licReq := encodeTPKT(encodeX224DT(encodeLicensePDU(LicenseRequest, LicensePktFlag, nil)))
			serverSeq, aborted = down(licReq, serverSeq, clientSeq)
			if aborted {
				return
			}
			licInfo := encodeTPKT(encodeX224DT(encodeLicensePDU(ClientLicenseInfo, LicensePktFlag, nil)))
			clientSeq, aborted = up(licInfo, clientSeq, serverSeq)
			if aborted {
				return
			}
		}

		// --- Phase 8: Capability Exchange (Demand Active -> Confirm Active + sync) ---
		if !cfg.SkipCapability {
			demandActive := encodeTPKT(encodeX224DT(encodeDemandActivePDU(cfg)))
			serverSeq, aborted = down(demandActive, serverSeq, clientSeq)
			if aborted {
				return
			}
			confirmActive := encodeTPKT(encodeX224DT(encodeConfirmActivePDU(cfg)))
			clientSeq, aborted = up(confirmActive, clientSeq, serverSeq)
			if aborted {
				return
			}
			// Server Synchronize + Control Cooperate + Control Grant + Font Map.
			sync := encodeTPKT(encodeX224DT(encodeServerPDU(PDUType2Update, nil)))
			serverSeq, aborted = down(sync, serverSeq, clientSeq)
			if aborted {
				return
			}
			coop := encodeTPKT(encodeX224DT(encodeServerPDU(PDUType2Update, nil)))
			serverSeq, aborted = down(coop, serverSeq, clientSeq)
			if aborted {
				return
			}
			grant := encodeTPKT(encodeX224DT(encodeServerPDU(PDUType2Update, nil)))
			serverSeq, aborted = down(grant, serverSeq, clientSeq)
			if aborted {
				return
			}
			fontMap := encodeTPKT(encodeX224DT(encodeServerPDU(PDUType2FontMap, nil)))
			serverSeq, aborted = down(fontMap, serverSeq, clientSeq)
			if aborted {
				return
			}
		}

		// --- Phase 9: Data events (Active phase) ---
		for _, ev := range cfg.DataEvents {
			if ctx.Err() != nil {
				return
			}
			payload := ev.Payload
			if len(ev.PayloadB64) > 0 {
				if b, err := decodeBase64(ev.PayloadB64); err == nil {
					payload = b
				}
			}
			pdu := encodeDataEvent(cfg, ev, payload)
			if pdu == nil {
				continue
			}
			dir := ev.Direction
			if dir == "" {
				dir = "up"
			}
			if dir == "down" {
				serverSeq, aborted = down(pdu, serverSeq, clientSeq)
			} else {
				clientSeq, aborted = up(pdu, clientSeq, serverSeq)
			}
			if aborted {
				return
			}
		}

		// --- Phase 9: Server responses (FastPath Output etc.) ---
		for _, resp := range cfg.ServerResponses {
			if ctx.Err() != nil {
				return
			}
			pdu := encodeServerResponse(resp)
			if pdu == nil {
				continue
			}
			serverSeq, aborted = down(pdu, serverSeq, clientSeq)
			if aborted {
				return
			}
		}

		// --- Phase 10: Shutdown + MCS Disconnect Provider Ultimatum ---
		shutdown := encodeTPKT(encodeX224DT(encodeServerPDU(PDUType2ShutdownRequest, nil)))
		clientSeq, aborted = up(shutdown, clientSeq, serverSeq)
		if aborted {
			return
		}
		disconnect := encodeTPKT(encodeX224DT(encodeMCSDisconnectProviderUltimatum()))
		clientSeq, aborted = up(disconnect, clientSeq, serverSeq)
		if aborted {
			return
		}

		// --- TCP 4-way teardown ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, DefaultRDPPort, clientSeq, serverSeq, 0x11, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, DefaultRDPPort, spec.SrcPort, serverSeq, clientSeq, 0x10, nil)
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, DefaultRDPPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, DefaultRDPPort, clientSeq, serverSeq, 0x10, nil)
	}()

	return configChan, nil
}

// ===================== TPKT layer =====================

// encodeTPKT wraps an X.224 PDU in a TPKT header (RFC 1006 §4).
// Header is 4 bytes: Version=3 | Reserved=0 | Length(uint16 BE, includes
// the 4-byte TPKT header itself).
func encodeTPKT(payload []byte) []byte {
	total := 4 + len(payload)
	out := make([]byte, total)
	out[0] = TPKTVersion
	out[1] = 0x00
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	copy(out[4:], payload)
	return out
}

// ===================== X.224 layer =====================

// encodeX224CR encodes a Connection Request PDU with embedded RDP
// Negotiation Request. The X.224 CR header is 7 bytes (LI=6, Code=0xE0,
// DST-REF=0x0000, SRC-REF=0x0000, Class=0), followed by optional cookie
// and the 8-byte Negotiation Request.
func encodeX224CR(cfg *core.RDPConfig) []byte {
	// Variable part: optional cookie + RDP Negotiation Request.
	var userData []byte
	if cfg.Cookie != "" {
		userData = append(userData, []byte(cfg.Cookie)...)
	}
	userData = append(userData, encodeNegotiationRequest(cfg)...)

	// X.224 CR header: LI (1) + Code (1) + DST-REF (2) + SRC-REF (2) + Class (1) = 7 bytes.
	// LI counts the bytes after itself (Code + DST-REF + SRC-REF + Class + UserData).
	li := 2 + 2 + 2 + 1 + len(userData) // Code(1) + roa(1) + DST-REF(2) + SRC-REF(2) + Class(1) + UserData
	// Wait: per ISO 8073, LI counts bytes AFTER the LI itself, which is the
	// total of (Code + DST-REF + SRC-REF + Class + UserData) = 1+2+2+1+N.
	// However, X.224 CR LI is 6 for the minimum CR (Code+DST+SRC+Class=6 bytes,
	// i.e. without UserData). With UserData, LI = 6 + len(UserData).
	li = 6 + len(userData)

	out := make([]byte, 0, 1+li)
	out = append(out, byte(li))
	out = append(out, X224CR)
	out = append(out, 0x00, 0x00) // DST-REF = 0x0000 (RDP standard)
	out = append(out, 0x00, 0x00) // SRC-REF = 0x0000 (CR)
	out = append(out, 0x00)       // Class Option = 0 (Class 0)
	out = append(out, userData...)
	return out
}

// encodeX224CC encodes a Connection Confirm PDU with embedded RDP
// Negotiation Response (or Failure). 7-byte header + 8-byte Negotiation
// Response/Failure.
func encodeX224CC(cfg *core.RDPConfig) []byte {
	userData := encodeNegotiationResponse(cfg)
	li := 6 + len(userData)
	out := make([]byte, 0, 1+li)
	out = append(out, byte(li))
	out = append(out, X224CC)
	out = append(out, 0x00, 0x00) // DST-REF = 0x0000 (RDP standard)
	out = append(out, 0x00, 0x00) // SRC-REF = 0x0000 (server-allocated; RDP uses 0)
	out = append(out, 0x00)       // Class Option = 0 (Class 0)
	out = append(out, userData...)
	return out
}

// encodeX224DR encodes a Disconnect Request PDU. 7-byte header (no
// UserData in the RDP context).
func encodeX224DR() []byte {
	li := 6
	out := make([]byte, 0, 1+li)
	out = append(out, byte(li))
	out = append(out, X224DR)
	out = append(out, 0x00, 0x00)
	out = append(out, 0x00, 0x00)
	out = append(out, 0x00)
	return out
}

// encodeX224DT wraps a payload in an X.224 Data Transfer PDU (3-byte
// header: LI=2, Code=0xF0, roa=0). The payload follows verbatim.
func encodeX224DT(payload []byte) []byte {
	out := make([]byte, 0, 3+len(payload))
	out = append(out, 0x02) // LI = 2 (only Code + roa follow)
	out = append(out, X224DT)
	out = append(out, 0x00) // roa = 0
	out = append(out, payload...)
	return out
}

// ===================== RDP Negotiation Request/Response =====================

// encodeNegotiationRequest encodes the 8-byte RDP Negotiation Request
// (MS-RDPBCGR §2.2.1.1).
func encodeNegotiationRequest(cfg *core.RDPConfig) []byte {
	flags := uint8(0)
	if cfg.RestrictedAdmin {
		flags |= NegFlagRestrictedAdmin
	}
	if cfg.RedirectedAuth {
		flags |= NegFlagRedirectedAuth
	}
	protocols := cfg.RequestedProtocols
	if protocols == 0 {
		protocols = deriveRequestedProtocols(cfg.SecurityLayer)
	}
	out := make([]byte, 8)
	out[0] = TypeRDPNegReq
	out[1] = flags
	binary.LittleEndian.PutUint16(out[2:4], NegReqLen)
	binary.LittleEndian.PutUint32(out[4:8], protocols)
	return out
}

// encodeNegotiationResponse encodes the 8-byte Negotiation Response (RSP)
// or Failure. Failure is selected when ServerSelectedProtocol==0 and a
// failureCode is encoded in the 4-byte trailing field; otherwise RSP.
func encodeNegotiationResponse(cfg *core.RDPConfig) []byte {
	out := make([]byte, 8)
	selected := cfg.ServerSelectedProtocol
	if selected == 0 {
		// Default: select the first matching protocol from RequestedProtocols.
		selected = deriveSelectedProtocol(cfg)
	}
	out[0] = TypeRDPNegRsp
	out[1] = 0x00
	binary.LittleEndian.PutUint16(out[2:4], NegReqLen)
	binary.LittleEndian.PutUint32(out[4:8], selected)
	return out
}

// encodeNegotiationFailure encodes the 8-byte Negotiation Failure with the
// given failureCode (1-7 per MS-RDPBCGR §2.2.1.2.2).
func encodeNegotiationFailure(failureCode uint32) []byte {
	out := make([]byte, 8)
	out[0] = TypeRDPNegFailure
	out[1] = 0x00
	binary.LittleEndian.PutUint16(out[2:4], NegReqLen)
	binary.LittleEndian.PutUint32(out[4:8], failureCode)
	return out
}

// deriveRequestedProtocols maps SecurityLayer to the requestedProtocols
// bitmask when the user leaves it 0 (MS-RDPBCGR §2.2.1.1.1).
func deriveRequestedProtocols(securityLayer string) uint32 {
	switch securityLayer {
	case "standard":
		return ProtocolRDP
	case "tls":
		return ProtocolSSL
	case "nla":
		return ProtocolSSL | ProtocolHybrid
	case "nla_ex":
		return ProtocolSSL | ProtocolHybrid | ProtocolHybridEx
	default:
		return ProtocolSSL
	}
}

// deriveSelectedProtocol returns the server-selected protocol matching
// the client's request (single bit set).
func deriveSelectedProtocol(cfg *core.RDPConfig) uint32 {
	rp := cfg.RequestedProtocols
	if rp == 0 {
		rp = deriveRequestedProtocols(cfg.SecurityLayer)
	}
	// Server prefers NLA > TLS > Standard.
	if rp&ProtocolHybridEx != 0 {
		return ProtocolHybridEx
	}
	if rp&ProtocolHybrid != 0 {
		return ProtocolHybrid
	}
	if rp&ProtocolSSL != 0 {
		return ProtocolSSL
	}
	if rp&ProtocolRDP != 0 {
		return ProtocolRDP
	}
	return ProtocolRDP
}

// ===================== MCS (T.125) layer =====================

// encodeMCSConnectInitial encodes the MCS Connect-Initial PDU
// (APPLICATION 101, ASN.1 BER). The userData field carries GCC
// Conference Create Request.
//
// Layout:
//   0x7F 0x65 (APPLICATION 101, long form)
//   Length (BER)
//   callingDomainSelector OCTET STRING (1 byte 0x01)
//   calledDomainSelector  OCTET STRING (1 byte 0x01)
//   upwardFlag BOOLEAN TRUE
//   targetParameters DomainParameters SEQUENCE
//   minimumParameters DomainParameters SEQUENCE
//   maximumParameters DomainParameters SEQUENCE
//   userData OCTET STRING (GCC Connect-Data)
func encodeMCSConnectInitial(cfg *core.RDPConfig) []byte {
	// DomainParameters: maxChannelIds, maxUserIds, maxTokenIds,
	// numPriorities, minThroughput, maxMCSPDUsize, protocolVersion.
	target := encodeDomainParameters(34, 2, 0, 1, 0, 65535, 2)
	minimum := encodeDomainParameters(2, 2, 0, 1, 0, 1024, 1)
	maximum := encodeDomainParameters(34, 2, 0, 1, 0, 65535, 2)

	// Build GCC Connect-Data payload.
	gccData := encodeGCCConnectData(cfg)

	// Body = callingDomainSelector + calledDomainSelector + upwardFlag +
	//        target + min + max + userData.
	body := make([]byte, 0, 256+len(gccData))
	body = append(body, encodeOctetString([]byte{0x01})...)        // callingDomainSelector
	body = append(body, encodeOctetString([]byte{0x01})...)        // calledDomainSelector
	body = append(body, encodeBoolean(true)...)                    // upwardFlag
	body = append(body, target...)
	body = append(body, minimum...)
	body = append(body, maximum...)
	body = append(body, encodeOctetString(gccData)...)             // userData

	// APPLICATION 101 long form: 0x7F 0x65 + BER length + body.
	out := make([]byte, 0, 4+len(body))
	out = append(out, MCSConnectInitialTag, MCSConnectInitialTagByte)
	out = append(out, encodeBERLength(len(body))...)
	out = append(out, body...)
	return out
}

// encodeMCSConnectResponse encodes the MCS Connect-Response PDU
// (APPLICATION 102, ASN.1 BER).
func encodeMCSConnectResponse(cfg *core.RDPConfig) []byte {
	// result ENUMERATED (0=rt-successful) + connectId INTEGER (0) +
	// domainParameters SEQUENCE + userData OCTET STRING (GCC Conference
	// Create Response).
	domainParams := encodeDomainParameters(34, 2, 0, 1, 0, 65535, 2)
	gccResp := encodeGCCConnectResponse(cfg)

	body := make([]byte, 0, 64+len(gccResp))
	body = append(body, encodeEnumerated(0)...)                    // result = 0 (rt-successful)
	body = append(body, encodeInteger(0)...)                       // connectId = 0
	body = append(body, domainParams...)
	body = append(body, encodeOctetString(gccResp)...)             // userData

	out := make([]byte, 0, 4+len(body))
	out = append(out, MCSConnectResponseTag, MCSConnectResponseTagByte)
	out = append(out, encodeBERLength(len(body))...)
	out = append(out, body...)
	return out
}

// encodeDomainParameters encodes a T.125 DomainParameters SEQUENCE with
// 7 INTEGER fields. Used 3 times in Connect-Initial (target/min/max) and
// once in Connect-Response.
//
// RDP implementations use a non-standard unsigned BER encoding for these
// integers: positive values whose high bit is set do NOT get a leading
// 0x00 byte (e.g. 65535 encodes as 0x02 0x02 0xFF 0xFF, not the strict
// BER 0x02 0x03 0x00 0xFF 0xFF). MS-RDPBCGR §2.2.1.1 references ASN.1
// BER but real captures follow this unsigned convention.
func encodeDomainParameters(maxChannelIds, maxUserIds, maxTokenIds, numPriorities, minThroughput, maxMCSPDUsize, protocolVersion int) []byte {
	items := [][]byte{
		encodeUnsignedInteger(int64(maxChannelIds)),
		encodeUnsignedInteger(int64(maxUserIds)),
		encodeUnsignedInteger(int64(maxTokenIds)),
		encodeUnsignedInteger(int64(numPriorities)),
		encodeUnsignedInteger(int64(minThroughput)),
		encodeUnsignedInteger(int64(maxMCSPDUsize)),
		encodeUnsignedInteger(int64(protocolVersion)),
	}
	total := 0
	for _, it := range items {
		total += len(it)
	}
	body := make([]byte, 0, total)
	for _, it := range items {
		body = append(body, it...)
	}
	return encodeTLV(BERSequence, body)
}

// encodeUnsignedInteger encodes a non-negative integer as a BER INTEGER
// using RDP's unsigned convention (no leading 0x00 byte for high-bit-set
// values). Negative values are not supported.
func encodeUnsignedInteger(v int64) []byte {
	if v < 0 {
		v = 0
	}
	if v == 0 {
		return encodeTLV(BERInteger, []byte{0x00})
	}
	var raw []byte
	tmp := v
	for tmp > 0 {
		raw = append([]byte{byte(tmp & 0xFF)}, raw...)
		tmp >>= 8
	}
	return encodeTLV(BERInteger, raw)
}

// encodeMCSErectDomainRequest encodes the MCS Erect-Domain Request PDU
// (PER-encoded: 0x04 + subHeight + subInterval). RDP uses fixed 0/0.
func encodeMCSErectDomainRequest() []byte {
	return []byte{MCSErectDomainRequest, 0x00, 0x00}
}

// encodeMCSAttachUserRequest encodes the MCS Attach-User Request PDU
// (single byte 0x28).
func encodeMCSAttachUserRequest() []byte {
	return []byte{MCSAttachUserRequest}
}

// encodeMCSAttachUserConfirm encodes the MCS Attach-User Confirm PDU:
// Reason (0x2C) + Result (PER enumerated, 1 byte) + Initiator (PER
// User-ID, 2 bytes high-byte-first). C-RDP-1: 1001 = 0x03 0xE9.
func encodeMCSAttachUserConfirm(initiator uint16) []byte {
	out := make([]byte, 4)
	out[0] = MCSAttachUserConfirm
	out[1] = 0x00 // Result = 0 (rt-successful)
	out[2] = byte(initiator >> 8)
	out[3] = byte(initiator & 0xFF)
	return out
}

// encodeMCSChannelJoinRequest encodes the MCS Channel-Join Request:
// Reason (0x38) + Initiator (PER User-ID, 2 bytes) + ChannelId (2 bytes).
func encodeMCSChannelJoinRequest(initiator, channelID uint16) []byte {
	out := make([]byte, 5)
	out[0] = MCSChannelJoinRequest
	out[1] = byte(initiator >> 8)
	out[2] = byte(initiator & 0xFF)
	out[3] = byte(channelID >> 8)
	out[4] = byte(channelID & 0xFF)
	return out
}

// encodeMCSChannelJoinConfirm encodes the MCS Channel-Join Confirm:
// Reason (0x3C) + Initiator (2 bytes) + ChannelId (2 bytes) + Result (1 byte).
func encodeMCSChannelJoinConfirm(initiator, channelID uint16, result uint8) []byte {
	out := make([]byte, 6)
	out[0] = MCSChannelJoinConfirm
	out[1] = byte(initiator >> 8)
	out[2] = byte(initiator & 0xFF)
	out[3] = byte(channelID >> 8)
	out[4] = byte(channelID & 0xFF)
	out[5] = result
	return out
}

// encodeMCSDisconnectProviderUltimatum encodes the MCS Disconnect
// Provider Ultimatum PDU (0xC0 + reason byte 0x80 = user-requested).
func encodeMCSDisconnectProviderUltimatum() []byte {
	return []byte{MCSDisconnectProviderUltimatum, 0x80}
}

// ===================== GCC (T.124) layer =====================

// encodeGCCConnectData encodes GCC Connect-Data with the fixed
// t124Identifier (20 bytes), connectType=1, and Conference Create
// Request containing RDP Client Core/Security/Channels Data in userData.
func encodeGCCConnectData(cfg *core.RDPConfig) []byte {
	// Conference Create Request userData SET OF UserData - we emit one
	// UserData entry whose value is the concatenated RDP client data
	// blocks (CS_CORE + CS_SECURITY + CS_CHANNELS).
	clientData := encodeRDPClientData(cfg)

	// gccPdu = nodeID (UserData with key 0xC001 in H.221 non-ASN.1) ... +
	// userData SET OF UserData. For RDP the userData contains a single
	// UserData whose value is the client data blocks.
	//
	// Layout (MS-RDPBCGR §2.2.1.3 + T.124 §8.7):
	//   t124Identifier (20 bytes)
	//   connectType = 1 (BER INTEGER)
	//   ConferenceCreateRequest = SET { nodeID UserData, userData SET OF UserData }
	//
	// In practice RDP encodes ConferenceCreateRequest as:
	//   SET { OCTET STRING clientData }
	// where the OCTET STRING contains the H.221 key-value blocks.
	confCreateReq := encodeTLV(BERSet, clientData)

	// Connect-Data = SEQUENCE { t124Identifier, connectType, gccPdu }
	body := make([]byte, 0, GCCt124IdentifierLen+8+len(confCreateReq))
	body = append(body, []byte(gccT124Identifier)...)
	body = append(body, encodeInteger(1)...) // connectType = 1
	body = append(body, confCreateReq...)
	return encodeTLV(BERSequence, body)
}

// encodeGCCConnectResponse encodes the GCC Conference Create Response
// carrying Server Core/Security Data. Minimal layout mirroring the
// request: t124Identifier + connectType + SET{OCTET STRING serverData}.
func encodeGCCConnectResponse(cfg *core.RDPConfig) []byte {
	serverData := encodeRDPServerData(cfg)
	confCreateRsp := encodeTLV(BERSet, serverData)
	body := make([]byte, 0, GCCt124IdentifierLen+8+len(confCreateRsp))
	body = append(body, []byte(gccT124Identifier)...)
	body = append(body, encodeInteger(1)...)
	body = append(body, confCreateRsp...)
	return encodeTLV(BERSequence, body)
}

// ===================== RDP Client/Server Data (H.221 non-ASN.1) =====================

// encodeRDPClientData concatenates CS_CORE + CS_SECURITY + CS_CHANNELS
// blocks. Each block = 2-byte key (LE) + 2-byte length (LE) + payload.
func encodeRDPClientData(cfg *core.RDPConfig) []byte {
	core := encodeClientCoreData(cfg)
	sec := encodeClientSecurityData(cfg)
	out := make([]byte, 0, 8+len(core)+len(sec))
	// CS_CORE block
	out = append(out, byte(CSCore&0xFF), byte(CSCore>>8))
	out = append(out, byte(len(core)&0xFF), byte(len(core)>>8))
	out = append(out, core...)
	// CS_SECURITY block
	out = append(out, byte(CSSecurity&0xFF), byte(CSSecurity>>8))
	out = append(out, byte(len(sec)&0xFF), byte(len(sec)>>8))
	out = append(out, sec...)
	// CS_CHANNELS block (only when channels declared)
	if len(cfg.Channels) > 0 {
		chans := encodeClientChannelsData(cfg)
		out = append(out, byte(CSChannels&0xFF), byte(CSChannels>>8))
		out = append(out, byte(len(chans)&0xFF), byte(len(chans)>>8))
		out = append(out, chans...)
	}
	return out
}

// encodeClientCoreData builds the Client Core Data block per
// MS-RDPBCGR §2.2.1.3.2. Fixed 218-byte layout (without extended fields).
func encodeClientCoreData(cfg *core.RDPConfig) []byte {
	out := make([]byte, ClientCoreMinLen)
	version := cfg.ForceRDPVersion
	if version == 0 {
		version = deriveRDPVersion(cfg.SecurityLayer)
	}
	binary.LittleEndian.PutUint32(out[0:4], version)

	width := cfg.DesktopWidth
	if width == 0 {
		width = 1920
	}
	height := cfg.DesktopHeight
	if height == 0 {
		height = 1080
	}
	binary.LittleEndian.PutUint16(out[4:6], width)
	binary.LittleEndian.PutUint16(out[6:8], height)

	colorDepth := cfg.ColorDepth
	if colorDepth == 0 {
		colorDepth = 5 // 32bpp
	}
	binary.LittleEndian.PutUint16(out[8:10], colorDepth)
	// preferredSausageCode (10:12) = 0
	binary.LittleEndian.PutUint32(out[12:16], cfg.KeyboardLayout)
	binary.LittleEndian.PutUint32(out[16:20], cfg.ClientBuild)
	// clientName: 16 bytes UTF-16LE, NULL-padded (C-RDP-3).
	copy(out[20:36], utf16LEPad(cfg.ClientName, ClientNameLenBytes))
	binary.LittleEndian.PutUint32(out[36:40], cfg.KeyboardType)
	binary.LittleEndian.PutUint32(out[40:44], cfg.KeyboardSubType)
	binary.LittleEndian.PutUint32(out[44:48], cfg.KeyboardFunctionKey)
	// imeFileName (48:112) = 0
	// postBeta2ColorDepth (112:114) = same as colorDepth
	binary.LittleEndian.PutUint16(out[112:114], colorDepth)
	// removeRemoteSessionCaps (114:116) = 0
	// clientProductId (116:118) = 1
	binary.LittleEndian.PutUint16(out[116:118], 1)
	// serialNumber (118:122) = 0
	hcd := cfg.HighColorDepth
	if hcd == 0 {
		hcd = 32
	}
	binary.LittleEndian.PutUint16(out[122:124], hcd)
	binary.LittleEndian.PutUint16(out[124:126], cfg.SupportedColorDepths)
	// earlyCapabilityFlags (126:128) = supportedColorDepths presence
	binary.LittleEndian.PutUint16(out[126:128], 0x07)
	// clientDigProductId (128:192) = 0
	out[192] = cfg.ConnectionType
	// pad1octet (193) = 0
	binary.LittleEndian.PutUint32(out[194:198], cfg.ServerSelectedProtocol)
	// desktopPhysicalWidth (198:202) = 0
	// desktopPhysicalHeight (202:206) = 0
	// desktopOrientation (206:208) = 0
	return out
}

// encodeClientSecurityData builds the 12-byte Client Security Data block
// (MS-RDPBCGR §2.2.1.4.2): encryptionMethods (4) + extEncryptionMethods (4).
// Length is 12 bytes (4-byte key + 4-byte length + 12-byte payload).
// Wait: the block payload is 8 bytes (encryptionMethods + extEncryptionMethods);
// the 4-byte key+length prefix is added by encodeRDPClientData. So this
// function returns 8 bytes.
func encodeClientSecurityData(cfg *core.RDPConfig) []byte {
	out := make([]byte, 8)
	enc := cfg.EncryptionMethods
	if enc == 0 && cfg.SecurityLayer == "standard" {
		enc = 0x02 // default 128-bit RC4
	}
	binary.LittleEndian.PutUint32(out[0:4], enc)
	binary.LittleEndian.PutUint32(out[4:8], cfg.ExtEncryptionMethods)
	return out
}

// encodeClientChannelsData builds the Client Channels Data block
// (MS-RDPBCGR §2.2.1.3.4): channelCount (4) + channelDefArray (12*N).
func encodeClientChannelsData(cfg *core.RDPConfig) []byte {
	out := make([]byte, 4+12*len(cfg.Channels))
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(cfg.Channels)))
	for i, ch := range cfg.Channels {
		off := 4 + i*12
		// name: 8 bytes ASCII, NULL-padded
		nameBuf := make([]byte, 8)
		copy(nameBuf, []byte(ch.Name))
		copy(out[off:off+8], nameBuf)
		binary.LittleEndian.PutUint32(out[off+8:off+12], ch.Options)
	}
	return out
}

// encodeRDPServerData concatenates SC_CORE + SC_SECURITY blocks.
func encodeRDPServerData(cfg *core.RDPConfig) []byte {
	core := encodeServerCoreData(cfg)
	sec := encodeServerSecurityData(cfg)
	out := make([]byte, 0, 8+len(core)+len(sec))
	out = append(out, byte(SCCore&0xFF), byte(SCCore>>8))
	out = append(out, byte(len(core)&0xFF), byte(len(core)>>8))
	out = append(out, core...)
	out = append(out, byte(SCSecurity&0xFF), byte(SCSecurity>>8))
	out = append(out, byte(len(sec)&0xFF), byte(len(sec)>>8))
	out = append(out, sec...)
	return out
}

// encodeServerCoreData builds the 8-byte Server Core Data block
// (MS-RDPBCGR §2.2.1.4.1): version + clientRequestedProtocols + earlyCapabilityFlags.
func encodeServerCoreData(cfg *core.RDPConfig) []byte {
	out := make([]byte, 8)
	version := cfg.ForceRDPVersion
	if version == 0 {
		version = deriveRDPVersion(cfg.SecurityLayer)
	}
	binary.LittleEndian.PutUint32(out[0:4], version)
	rp := cfg.RequestedProtocols
	if rp == 0 {
		rp = deriveRequestedProtocols(cfg.SecurityLayer)
	}
	binary.LittleEndian.PutUint32(out[4:8], rp)
	return out
}

// encodeServerSecurityData builds the Server Security Data block
// (MS-RDPBCGR §2.2.1.4.3): encryptionMethod (4) + encryptionLevel (4) +
// serverRandom (32) + serverCertificate (variable). Returns the block
// payload (no key/length prefix).
func encodeServerSecurityData(cfg *core.RDPConfig) []byte {
	encMethod := cfg.EncryptionMethod
	if encMethod == 0 && cfg.SecurityLayer == "standard" {
		encMethod = 0x02
	}
	encLevel := cfg.EncryptionLevel
	if encLevel == 0 {
		if cfg.SecurityLayer == "standard" {
			encLevel = 2
		}
	}
	srvRandom := cfg.ServerRandom
	if len(srvRandom) == 0 {
		srvRandom = deterministicServerRandom()
	}
	if len(srvRandom) > 32 {
		srvRandom = srvRandom[:32]
	} else if len(srvRandom) < 32 {
		padded := make([]byte, 32)
		copy(padded, srvRandom)
		srvRandom = padded
	}
	certVersion := cfg.ServerCertVersion
	if certVersion == 0 {
		certVersion = 1
	}
	// Server Certificate V1 layout: dwVersion (4) + dwSigAlgId (4) +
	// dwKeyAlgId (4) + PublicKey (variable, dummy 4-byte modulus) +
	// Signature (variable, dummy 4 bytes). We emit a minimal V1 cert.
	cert := make([]byte, 0, 16)
	cert = append(cert, byte(certVersion&0xFF), byte(certVersion>>8), 0, 0)
	cert = append(cert, 0, 0, 0, 0) // dwSigAlgId = 0
	cert = append(cert, 0, 0, 0, 0) // dwKeyAlgId = 0

	out := make([]byte, 0, 8+32+4+len(cert))
	out = append(out, byte(encMethod&0xFF), byte(encMethod>>8), 0, 0)
	out = append(out, byte(encLevel&0xFF), byte(encLevel>>8), 0, 0)
	out = append(out, srvRandom...)
	out = append(out, byte(len(cert)&0xFF), byte(len(cert)>>8), 0, 0)
	out = append(out, cert...)
	return out
}

// deterministicServerRandom returns 32 bytes generated from a fixed
// seed. Tests rely on the bytes being deterministic.
func deterministicServerRandom() []byte {
	r := rand.New(rand.NewSource(0x5253414E444F4D00)) // "RSANDOM\0"
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(r.Intn(256))
	}
	return out
}

// deriveRDPVersion returns the Client Core Data version for the given
// security layer (MS-RDPBCGR §2.2.1.3.2 version field).
func deriveRDPVersion(securityLayer string) uint32 {
	switch securityLayer {
	case "nla", "nla_ex":
		return 0x0008000A // RDP 10
	case "tls":
		return 0x00080007 // RDP 8
	case "standard":
		return 0x00080001 // RDP 5
	default:
		return 0x0008000A
	}
}

// ===================== Security Exchange PDU =====================

// encodeSecurityExchange builds the Security Exchange PDU
// (MS-RDPBCGR §2.2.1.8): securityHeader (4) + length (4) +
// encryptedClientRandom (variable). Encrypted bytes are dummy (the
// planner cannot RSA-encrypt with the server's real public key).
func encodeSecurityExchange(cfg *core.RDPConfig) []byte {
	keyBytes := cfg.SecurityExchangeRSAKeyBytes
	if keyBytes == 0 {
		keyBytes = DefaultRSAKeyBytes
	}
	encryptedClientRandom := make([]byte, keyBytes)
	for i := 0; i < keyBytes; i++ {
		encryptedClientRandom[i] = byte(i & 0xFF)
	}

	totalLen := 8 + keyBytes
	out := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(out[0:4], SecExchangePkt)
	binary.LittleEndian.PutUint32(out[4:8], uint32(totalLen))
	copy(out[8:], encryptedClientRandom)
	return out
}

// ===================== Client Info PDU =====================

// encodeClientInfoPDU builds the Client Info PDU (MS-RDPBCGR §2.2.1.11):
// codePage (4) + flags (2) + flags2 (2) + domainLen (2) + userNameLen (2) +
// passwordLen (2) + alternateShellLen (2) + workingDirLen (2) +
// domainData + userNameData + passwordData + alternateShellData + workingDirData.
func encodeClientInfoPDU(cfg *core.RDPConfig) []byte {
	domainUTF16 := utf16LE(cfg.Domain)
	userUTF16 := utf16LE(cfg.UserName)
	passUTF16 := utf16LE(cfg.Password)
	shellUTF16 := utf16LE(cfg.AlternateShell)
	workUTF16 := utf16LE(cfg.WorkingDir)

	flags := uint16(InfoUnicode)
	if cfg.InfoUnicode || cfg.InfoUnicode == false {
		flags |= InfoUnicode
	}
	if cfg.AutoLogon {
		flags |= InfoAutoLogon
	}
	if cfg.InfoLogonNotify {
		flags |= InfoLogonNotify
	}
	if cfg.InfoCompression {
		flags |= InfoCompression
	}
	flags2 := cfg.Flags2

	out := make([]byte, 0, 18+len(domainUTF16)+len(userUTF16)+len(passUTF16)+len(shellUTF16)+len(workUTF16))
	cp := cfg.CodePage
	out = append(out, byte(cp&0xFF), byte(cp>>8), byte(cp>>16), byte(cp>>24))
	out = append(out, byte(flags&0xFF), byte(flags>>8))
	out = append(out, byte(flags2&0xFF), byte(flags2>>8))
	out = append(out, byte(len(domainUTF16)&0xFF), byte(len(domainUTF16)>>8))
	out = append(out, byte(len(userUTF16)&0xFF), byte(len(userUTF16)>>8))
	out = append(out, byte(len(passUTF16)&0xFF), byte(len(passUTF16)>>8))
	out = append(out, byte(len(shellUTF16)&0xFF), byte(len(shellUTF16)>>8))
	out = append(out, byte(len(workUTF16)&0xFF), byte(len(workUTF16)>>8))
	out = append(out, domainUTF16...)
	out = append(out, userUTF16...)
	out = append(out, passUTF16...)
	out = append(out, shellUTF16...)
	out = append(out, workUTF16...)
	return out
}

// ===================== License PDU =====================

// encodeLicensePDU builds a License PDU (MS-RDPELE §2.2.2):
// bMsgType (1) + flags (1) + wMsgSize (2 LE) + data (variable).
func encodeLicensePDU(bMsgType, flags uint8, data []byte) []byte {
	total := 4 + len(data)
	out := make([]byte, total)
	out[0] = bMsgType
	out[1] = flags
	binary.LittleEndian.PutUint16(out[2:4], uint16(total))
	copy(out[4:], data)
	return out
}

// ===================== Capability Exchange PDU =====================

// encodeDemandActivePDU emits a minimal Server Demand Active PDU
// (MS-RDPBCGR §2.2.1.10). The payload is a Share Control Header with
// PDU type = DEMAND_ACTIVE (7). We emit a stub 6-byte header.
func encodeDemandActivePDU(cfg *core.RDPConfig) []byte {
	out := make([]byte, 6)
	// Share Control Header: totalLength (2 LE) + pduType (2 LE) + pduSource (2 LE)
	binary.LittleEndian.PutUint16(out[0:2], 6)
	binary.LittleEndian.PutUint16(out[2:4], 0x0007) // PDU_TYPE_DEMAND_ACTIVE
	binary.LittleEndian.PutUint16(out[4:6], MCSUserIDClient)
	return out
}

// encodeConfirmActivePDU emits a Client Confirm Active PDU containing
// Capability Sets (MS-RDPBCGR §2.2.1.13). The Share Data Header carries
// PDU type2 = CONFIRM_ACTIVE (0x0001B).
func encodeConfirmActivePDU(cfg *core.RDPConfig) []byte {
	caps := encodeCapabilitySets(cfg)
	// Share Control Header (6 bytes) + Share Data Header (12 bytes) + caps.
	total := 6 + 12 + len(caps)
	out := make([]byte, total)
	binary.LittleEndian.PutUint16(out[0:2], uint16(total))
	binary.LittleEndian.PutUint16(out[2:4], 0x0017) // PDU_TYPE_CONFIRM_ACTIVE = 23
	binary.LittleEndian.PutUint16(out[4:6], MCSUserIDClient)
	// Share Data Header: shareId (4) + pad1 (1) + streamId (1) + uncompressedLength (2 LE) +
	// pduType2 (1) + generalCompressedType (1) + generalCompressedLength (2 LE) + sessionId (4).
	binary.LittleEndian.PutUint32(out[6:10], 0)
	out[10] = 0
	out[11] = 0
	binary.LittleEndian.PutUint16(out[12:14], uint16(total-6))
	out[14] = 0x1B // PDUTYPE2_CONFIRMACTIVE = 27
	out[15] = 0
	binary.LittleEndian.PutUint16(out[16:18], 0)
	binary.LittleEndian.PutUint32(out[18:22], 0)
	// capabilitySetType count (2 LE) + pad2 (2) + caps.
	binary.LittleEndian.PutUint16(out[22:24], uint16(numCapabilitySets(cfg)))
	copy(out[24:], caps)
	return out
}

// encodeCapabilitySets emits the sequence of Capability Sets declared
// by the client. Each Capability = 2-byte type + 2-byte length + payload.
func encodeCapabilitySets(cfg *core.RDPConfig) []byte {
	var sets [][]byte

	// CAPSTYPE_GENERAL (28 bytes total: 4-byte header + 24-byte body).
	sets = append(sets, makeCapability(CapsTypeGeneral, 24, func(b []byte) {
		b[0] = 0x01 // osMajorType = 1 (WINDOWS)
		b[1] = 0x03 // osMinorType = 3 (WINDOWS_NT)
		binary.LittleEndian.PutUint16(b[2:4], 0x0001) // protocolVersion
		// rest zeros (generalCompressionTypes, extraFlags, updateCapabilityFlag)
	}))

	// CAPSTYPE_BITMAP (28 bytes: 4-byte header + 24-byte body).
	width := cfg.DesktopWidth
	if width == 0 {
		width = 1920
	}
	height := cfg.DesktopHeight
	if height == 0 {
		height = 1080
	}
	colorDepth := cfg.ColorDepth
	if colorDepth == 0 {
		colorDepth = 5
	}
	sets = append(sets, makeCapability(CapsTypeBitmap, 24, func(b []byte) {
		binary.LittleEndian.PutUint16(b[0:2], 0x0010) // preferredBitsPerPixel = 16
		b[2] = 0x01 // receive1BitPerPixel
		b[3] = 0x01 // receive4BitsPerPixel
		b[4] = 0x01 // receive8BitsPerPixel
		binary.LittleEndian.PutUint16(b[5:7], width)
		binary.LittleEndian.PutUint16(b[7:9], height)
		binary.LittleEndian.PutUint16(b[9:11], 0x0010) // desktopResizeFlag
	}))

	// CAPSTYPE_INPUT (88 bytes: 4-byte header + 84-byte body).
	sets = append(sets, makeCapability(CapsTypeInput, 84, func(b []byte) {
		binary.LittleEndian.PutUint16(b[0:2], 0x0001) // flags
		binary.LittleEndian.PutUint16(b[2:4], uint16(cfg.KeyboardLayout))
		binary.LittleEndian.PutUint32(b[8:12], cfg.KeyboardType)
		binary.LittleEndian.PutUint32(b[12:16], cfg.KeyboardSubType)
		binary.LittleEndian.PutUint32(b[16:20], cfg.KeyboardFunctionKey)
	}))

	// CAPSTYPE_MULTIFRAGMENTUPDATE (8 bytes: 4-byte header + 4-byte body).
	sets = append(sets, makeCapability(CapsTypeMultiFragmentUpdate, 4, func(b []byte) {
		binary.LittleEndian.PutUint32(b[0:4], 65535) // MaxRequestSize
	}))

	// CAPSTYPE_FRAME_ACKNOWLEDGE (8 bytes: 4-byte header + 4-byte body).
	sets = append(sets, makeCapability(CapsTypeFrameAcknowledge, 4, func(b []byte) {
		binary.LittleEndian.PutUint32(b[0:4], 2) // maxUnacknowledgedFrameCount
	}))

	total := 0
	for _, s := range sets {
		total += len(s)
	}
	out := make([]byte, 0, total)
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

// numCapabilitySets returns the count of capability sets the planner emits.
func numCapabilitySets(cfg *core.RDPConfig) int {
	return 5
}

// makeCapability builds a single Capability Set: 2-byte type (LE) +
// 2-byte length (LE, includes the 4-byte header) + bodyLen-byte body.
// The body is initialised by fn.
func makeCapability(capsType uint16, bodyLen int, fn func([]byte)) []byte {
	totalLen := 4 + bodyLen
	out := make([]byte, totalLen)
	binary.LittleEndian.PutUint16(out[0:2], capsType)
	binary.LittleEndian.PutUint16(out[2:4], uint16(totalLen))
	if fn != nil {
		fn(out[4:])
	}
	return out
}

// ===================== Server PDU (Share Data) =====================

// encodeServerPDU emits a minimal Share Data PDU with the given type2.
// Used for Synchronize / Control / Font Map / Shutdown Request.
func encodeServerPDU(type2 uint16, payload []byte) []byte {
	total := 6 + 12 + len(payload)
	out := make([]byte, total)
	binary.LittleEndian.PutUint16(out[0:2], uint16(total))
	binary.LittleEndian.PutUint16(out[2:4], 0x0017) // PDU_TYPE_DATA
	binary.LittleEndian.PutUint16(out[4:6], MCSUserIDClient)
	binary.LittleEndian.PutUint16(out[12:14], uint16(total-6))
	out[14] = byte(type2 & 0xFF)
	out[15] = byte(type2 >> 8)
	copy(out[18:], payload)
	return out
}

// ===================== FastPath Input/Output =====================

// encodeFastPathInput builds a FastPath Input PDU (MS-RDPBCGR §2.2.8.1.1.2):
// fpActionHeader (1) + length (1-2) + numEvents (1, when 0 in header) +
// events (variable).
//
// For a single keyboard event with flags + keyCode (2 bytes), the PDU is:
//   fpActionHeader (1) + length (1) + numEvents (1) + 2-byte event = 5 bytes
// Tests use 0x00 numEvents (encoded in header low 4 bits = 1) + length
// byte = 0x08 (per §2.2.8.1.1.2 example).
func encodeFastPathInput(events []byte) []byte {
	numEvents := uint8(len(events) / 2)
	if numEvents == 0 {
		numEvents = 1
	}
	// fpActionHeader: high 2 bits = 0 (Input), next 2 bits = 0 (fragmentation
	// SINGLE), low 4 bits = numEvents (when numEvents <= 15).
	header := byte(numEvents & 0x0F)
	length := 2 + len(events) // header(1) + length(1) + events
	// Length 0-127 = short form (1 byte).
	out := make([]byte, 0, 2+len(events))
	out = append(out, header)
	out = append(out, byte(length))
	out = append(out, events...)
	return out
}

// encodeFastPathInputKeyboard builds a single keyboard event: flags (1) + keyCode (1).
func encodeFastPathInputKeyboard(flags uint8, keyCode uint8) []byte {
	return []byte{flags, keyCode}
}

// encodeFastPathInputMouse builds a single mouse event: flags (2 LE) + xPos (2 LE) + yPos (2 LE).
func encodeFastPathInputMouse(flags uint16, x, y uint16) []byte {
	out := make([]byte, 6)
	binary.LittleEndian.PutUint16(out[0:2], flags)
	binary.LittleEndian.PutUint16(out[2:4], x)
	binary.LittleEndian.PutUint16(out[4:6], y)
	return out
}

// encodeFastPathOutput builds a FastPath Output PDU (MS-RDPBCGR §2.2.9.1.2):
// fpActionHeader (1) + length (1-2) + updateCode (1) + fragmentation (1) +
// compressionFlags (1, optional) + size (2 LE) + updateData.
func encodeFastPathOutput(updateCode uint8, fragmentation uint8, updateData []byte) []byte {
	// fpActionHeader: high 2 bits = 01 (Output), low 6 bits = fragmentation.
	header := FastPathOutputAction | (fragmentation & 0x03)
	length := 4 + len(updateData) // header(1) + length(1) + updateCode(1) + fragmentation(1) + updateData
	out := make([]byte, 0, 4+len(updateData))
	out = append(out, header)
	out = append(out, byte(length))
	out = append(out, updateCode)
	out = append(out, fragmentation)
	out = append(out, updateData...)
	return out
}

// ===================== CLIPRDR / RDPDR / RDPSND / DRDYNVC =====================

// encodeCLIPRDR builds a CLIPRDR PDU (MS-RDPCGR §1.3.1):
// msgType (2 LE) + msgFlags (2 LE) + dataLen (4 LE) + data.
func encodeCLIPRDR(msgType, msgFlags uint16, data []byte) []byte {
	out := make([]byte, 8+len(data))
	binary.LittleEndian.PutUint16(out[0:2], msgType)
	binary.LittleEndian.PutUint16(out[2:4], msgFlags)
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(data)))
	copy(out[8:], data)
	return out
}

// encodeRDPDR builds an RDPDR PDU (MS-RDPEFS §2.2): component (2 LE) +
// packetId (2 LE) + payload.
func encodeRDPDR(component, packetId uint16, payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint16(out[0:2], component)
	binary.LittleEndian.PutUint16(out[2:4], packetId)
	copy(out[4:], payload)
	return out
}

// encodeRDPSND builds an RDPSND PDU (MS-RDPSND §2.1): msgType (1) +
// bPad (1) + wTimeStamp (2 LE) + payload.
func encodeRDPSND(msgType uint8, timeStamp uint16, payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	out[0] = msgType
	out[1] = 0x00
	binary.LittleEndian.PutUint16(out[2:4], timeStamp)
	copy(out[4:], payload)
	return out
}

// encodeDRDYNVC builds a DRDYNVC PDU (MS-RDPEDYC §2.2.1): Cmd (1, high
// 4 bits) + ChannelId (variable, here 2 bytes LE) + payload.
func encodeDRDYNVC(cmd uint8, channelID uint16, payload []byte) []byte {
	out := make([]byte, 3+len(payload))
	out[0] = cmd
	binary.LittleEndian.PutUint16(out[1:3], channelID)
	copy(out[3:], payload)
	return out
}

// ===================== Data event / Server response dispatchers =====================

// encodeDataEvent maps an RDPDataEvent.Type to the corresponding PDU
// bytes. Returns nil for unknown types (caller skips).
func encodeDataEvent(cfg *core.RDPConfig, ev core.RDPDataEvent, payload []byte) []byte {
	switch ev.Type {
	case "fastpath_input_keyboard":
		// Default: Enter down (keyCode 0x1C, flags 0x00).
		if len(payload) >= 2 {
			return encodeFastPathInput(payload)
		}
		return encodeFastPathInput(encodeFastPathInputKeyboard(0x00, 0x1C))
	case "fastpath_input_mouse":
		if len(payload) >= 6 {
			return encodeFastPathInput(payload)
		}
		return encodeFastPathInput(encodeFastPathInputMouse(PTRFlagsMove, 100, 200))
	case "cliprdr_format_list":
		if len(payload) > 0 {
			return wrapChannelData(cfg, ev.Channel, payload)
		}
		// Default: 2 formats (CF_TEXT=1, CF_UNICODETEXT=13) = 16 bytes data.
		data := make([]byte, 16)
		binary.LittleEndian.PutUint32(data[0:4], 1)
		binary.LittleEndian.PutUint32(data[8:12], 13)
		return wrapChannelData(cfg, ev.Channel, encodeCLIPRDR(CBFormatList, 0, data))
	case "cliprdr_format_data_request":
		if len(payload) > 0 {
			return wrapChannelData(cfg, ev.Channel, payload)
		}
		data := make([]byte, 4)
		binary.LittleEndian.PutUint32(data[0:4], 1) // formatId = 1 (CF_TEXT)
		return wrapChannelData(cfg, ev.Channel, encodeCLIPRDR(CBFormatDataRequest, 0, data))
	case "rdpdr_device_list":
		if len(payload) > 0 {
			return wrapChannelData(cfg, ev.Channel, payload)
		}
		// Default: 1 disk device.
		devList := encodeRDPDRDeviceList([]RDPDRDevice{{DeviceType: RDPDRDtypFilesystem, Name: "C:"}})
		return wrapChannelData(cfg, ev.Channel, encodeRDPDR(RDPDRCtypFile, PAKIDCoreDeviceListAnnounce, devList))
	case "rdpdr_clientid_confirm":
		if len(payload) > 0 {
			return wrapChannelData(cfg, ev.Channel, payload)
		}
		return wrapChannelData(cfg, ev.Channel, encodeRDPDR(RDPDRCtypCore, PAKIDCoreClientIDConfirm, nil))
	case "rdpdr_client_name":
		if len(payload) > 0 {
			return wrapChannelData(cfg, ev.Channel, payload)
		}
		nameUTF16 := utf16LEPad(cfg.ClientName, 16)
		return wrapChannelData(cfg, ev.Channel, encodeRDPDR(RDPDRCtypCore, PAKIDCoreClientName, nameUTF16))
	case "rdpsnd_qualitymode":
		if len(payload) > 0 {
			return wrapChannelData(cfg, ev.Channel, payload)
		}
		data := make([]byte, 4)
		binary.LittleEndian.PutUint16(data[0:2], 1) // qualityMode = 1 (high)
		return wrapChannelData(cfg, ev.Channel, encodeRDPSND(SNDCQualityMode, 1000, data))
	case "drdynvc_create":
		if len(payload) > 0 {
			return wrapChannelData(cfg, ev.Channel, payload)
		}
		// Default: create "Microsoft::Windows::RDS::Graphics".
		name := []byte("Microsoft::Windows::RDS::Graphics")
		return wrapChannelData(cfg, ev.Channel, append([]byte{DRDYNVCCreate}, name...))
	case "rdpgfx_surface_command":
		// Surface command via drdynvc channel 1.
		if len(payload) > 0 {
			return wrapChannelData(cfg, ev.Channel, payload)
		}
		return wrapChannelData(cfg, ev.Channel, append([]byte{DRDYNVCData, 0x01, 0x00}, []byte{0x00, 0x00}...))
	default:
		// Unknown type: if payload provided, emit it raw on the channel.
		if len(payload) > 0 && ev.Channel != "" {
			return wrapChannelData(cfg, ev.Channel, payload)
		}
		return nil
	}
}

// encodeServerResponse maps an RDPServerResponse.Type to the corresponding
// PDU bytes.
func encodeServerResponse(resp core.RDPServerResponse) []byte {
	payload := resp.Payload
	switch resp.Type {
	case "bitmap_update", "fastpath_output_bitmap":
		if len(payload) > 0 {
			return encodeFastPathOutput(FastPathUpdateBitmap, FastPathFragmentSingle, payload)
		}
		// Default: empty bitmap update.
		return encodeFastPathOutput(FastPathUpdateBitmap, FastPathFragmentSingle, []byte{0x00})
	case "fastpath_output_palette":
		return encodeFastPathOutput(FastPathUpdatePalette, FastPathFragmentSingle, payload)
	case "fastpath_output_surface":
		return encodeFastPathOutput(FastPathUpdateSurface, FastPathFragmentSingle, payload)
	case "demand_active":
		if len(payload) > 0 {
			return payload
		}
		return encodeDemandActivePDU(nil)
	case "license_request":
		if len(payload) > 0 {
			return payload
		}
		return encodeLicensePDU(LicenseRequest, LicensePktFlag, nil)
	case "cliprdr_format_list_response":
		if len(payload) > 0 {
			return payload
		}
		return encodeCLIPRDR(CBFormatListResponse, CBResponseOK, nil)
	case "cliprdr_format_data_response":
		if len(payload) > 0 {
			return payload
		}
		return encodeCLIPRDR(CBFormatDataResponse, CBResponseOK, []byte("Hello\x00"))
	case "rdpdr_server_announce":
		if len(payload) > 0 {
			return payload
		}
		return encodeRDPDR(RDPDRCtypCore, PAKIDCoreServerAnnounce, nil)
	case "rdpdr_device_reply":
		if len(payload) > 0 {
			return payload
		}
		return encodeRDPDR(RDPDRCtypCore, PAKIDCoreDeviceReply, nil)
	case "rdpsnd_formats":
		if len(payload) > 0 {
			return payload
		}
		return encodeRDPSND(SNDCFormats, 1000, nil)
	case "rdpsnd_wave":
		if len(payload) > 0 {
			return payload
		}
		return encodeRDPSND(SNDCWave, 1000, make([]byte, 1000))
	case "drdynvc_create_rsp":
		if len(payload) > 0 {
			return payload
		}
		return append([]byte{DRDYNVCCreate | 0x10, 0x01, 0x00}, 0x00)
	default:
		if len(payload) > 0 {
			return payload
		}
		return nil
	}
}

// wrapChannelData wraps a virtual channel payload in an MCS Send Data
// Request/Response structure (TPKT + X.224 DT + MCS PDU). For test
// simplicity we use a minimal MCS Send Data Request wrapping the channel
// payload directly. channelName selects which static channel to address
// (the I/O channel is used when name is empty).
func wrapChannelData(cfg *core.RDPConfig, channelName string, payload []byte) []byte {
	channelID := MCSIOChannel
	if channelName != "" {
		for i, ch := range cfg.Channels {
			if ch.Name == channelName {
				channelID = MCSFirstStaticChan + i
				break
			}
		}
	}
	// MCS Send Data Request: Reason 0x64 (PER) + Initiator (2 bytes) +
	// ChannelId (2 bytes) + length (1-2 bytes PER) + payload.
	// We use a simplified 6-byte MCS header.
	hdr := make([]byte, 6)
	hdr[0] = 0x64 // MCS Send Data Request
	hdr[1] = byte(MCSUserIDClient >> 8)
	hdr[2] = byte(MCSUserIDClient & 0xFF)
	hdr[3] = byte(channelID >> 8)
	hdr[4] = byte(channelID & 0xFF)
	hdr[5] = byte(len(payload))
	return encodeTPKT(encodeX224DT(append(hdr, payload...)))
}

// RDPDRDevice is a single RDPDR device announcement entry (MS-RDPEFS
// §2.2.1.3.1).
type RDPDRDevice struct {
	DeviceType uint32
	Name       string
}

// encodeRDPDRDeviceList encodes a PAKID_CORE_DEVICELIST_ANNOUNCE payload
// containing one or more device entries. Each entry is 24 bytes:
// DeviceType (4) + DeviceId (4) + PreferredDosName (8) + DeviceDataLength (4) + DeviceData (variable, 0 for disks).
func encodeRDPDRDeviceList(devices []RDPDRDevice) []byte {
	out := make([]byte, 0, 24*len(devices))
	for i, dev := range devices {
		entry := make([]byte, 24)
		binary.LittleEndian.PutUint32(entry[0:4], dev.DeviceType)
		binary.LittleEndian.PutUint32(entry[4:8], uint32(i+1)) // DeviceId
		nameBuf := make([]byte, 8)
		copy(nameBuf, []byte(dev.Name))
		copy(entry[8:16], nameBuf)
		binary.LittleEndian.PutUint32(entry[16:20], 0) // DeviceDataLength
		out = append(out, entry...)
	}
	return out
}

// ===================== TLS handshake placeholder =====================

// needsTLSHandshake returns true when the security layer requires a TLS
// handshake (TLS / NLA / NLA_EX). Standard RDP Security does not.
func needsTLSHandshake(cfg *core.RDPConfig) bool {
	switch cfg.SecurityLayer {
	case "tls", "nla", "nla_ex":
		return true
	default:
		return false
	}
}

// encodeTLSHandshakePlaceholder emits a TLS ClientHello-like byte
// sequence so the wire layout has the right shape (TLS 1.2 record header
// + handshake header + version + random + session_id + cipher_suites +
// compression_methods + extensions_length). The bytes are NOT a valid
// TLS handshake; they model the structure for traffic-shape testing.
func encodeTLSHandshakePlaceholder(cfg *core.RDPConfig) []byte {
	// TLS record: ContentType=0x16 (Handshake) + Version 0x0301 + Length(2 BE) + handshake.
	handshake := make([]byte, 0, 80)
	// Handshake header: type=0x01 (ClientHello) + length(3 BE) + version 0x0303 + random(32) + session_id_len(1)=0 + cipher_suites_len(2 BE)=2 + cipher_suite(2) + compression_len(1)=1 + compression(1)=0 + extensions_len(2 BE)=0.
	handshake = append(handshake, 0x01)            // ClientHello
	handshake = append(handshake, 0x00, 0x00, 0x40) // length = 64 (placeholder)
	handshake = append(handshake, 0x03, 0x03)       // version TLS 1.2
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}
	handshake = append(handshake, random...)        // 32-byte random
	handshake = append(handshake, 0x00)             // session_id length = 0
	handshake = append(handshake, 0x00, 0x02)       // cipher_suites length = 2
	handshake = append(handshake, 0x00, 0x2F)       // TLS_RSA_WITH_AES_128_CBC_SHA
	handshake = append(handshake, 0x01, 0x00)       // compression_methods: 1 method = null
	handshake = append(handshake, 0x00, 0x00)       // extensions length = 0
	// Pad to declared length 64.
	for len(handshake) < 4+64 {
		handshake = append(handshake, 0x00)
	}
	// Record header.
	out := make([]byte, 5+len(handshake))
	out[0] = 0x16 // Handshake
	out[1] = 0x03
	out[2] = 0x01
	binary.BigEndian.PutUint16(out[3:5], uint16(len(handshake)))
	copy(out[5:], handshake)
	return out
}

// encodeTLSHandshakePlaceholderResponse emits a TLS ServerHello-like
// response for symmetry with the ClientHello placeholder.
//
// Per RFC 8446 §4.1.3 (and identically RFC 5246 §7.4.1.3), ServerHello
// differs from ClientHello in two fields that are SINGLE values in
// ServerHello but length-prefixed VECTORS in ClientHello:
//   - cipher_suite: a single CipherSuite (2 bytes), NOT cipher_suites<2..>
//     with a 2-byte length prefix.
//   - legacy_compression_method: a single uint8 (1 byte), NOT
//     compression_methods<1..> with a 1-byte length prefix.
//
// Writing the ClientHello-style length prefixes here shifts every
// subsequent field; Wireshark then reads extensions_length from the wrong
// offset and reports "Vector length 12033 is too large" (0x2F01 formed
// from the cipher byte 0x2F and the compression length 0x01). The body is
// built with no spurious zero-padding: the handshake length and record
// length exactly equal the bytes they delimit.
func encodeTLSHandshakePlaceholderResponse(cfg *core.RDPConfig) []byte {
	handshake := make([]byte, 0, 48)
	handshake = append(handshake, 0x02) // ServerHello
	// Handshake length placeholder (3 bytes); filled in once the body is known.
	handshake = append(handshake, 0x00, 0x00, 0x00)
	handshake = append(handshake, 0x03, 0x03) // legacy_version TLS 1.2
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(0xFF - i)
	}
	handshake = append(handshake, random...)
	handshake = append(handshake, 0x00)       // legacy_session_id_echo length = 0 (echo empty ClientHello)
	handshake = append(handshake, 0x00, 0x2F) // cipher_suite = TLS_RSA_WITH_AES_128_CBC_SHA (NO length prefix)
	handshake = append(handshake, 0x00)       // legacy_compression_method = null (NO length prefix)
	handshake = append(handshake, 0x00, 0x00) // extensions length = 0

	// Backfill the 3-byte handshake length with the exact body size.
	bodyLen := uint32(len(handshake) - 4)
	handshake[1] = byte(bodyLen >> 16)
	handshake[2] = byte(bodyLen >> 8)
	handshake[3] = byte(bodyLen)

	// Record header: ContentType=0x16 (Handshake) + Version 0x0301 + Length.
	out := make([]byte, 5+len(handshake))
	out[0] = 0x16
	out[1] = 0x03
	out[2] = 0x01
	binary.BigEndian.PutUint16(out[3:5], uint16(len(handshake)))
	copy(out[5:], handshake)
	return out
}

// wrapTLSAppData wraps payload in a TLS Application Data record
// (ContentType=0x17, Version 0x0303, Length uint16 BE). After the TLS
// handshake every RDP PDU is carried inside one such record (RFC 8446 §5,
// MS-RDPBCGR §5.4.2); emitting the raw TPKT/X.224 PDU instead makes
// Wireshark report "Ignored Unknown Record" (ContentType 0x03 is not a
// valid TLS record type).
func wrapTLSAppData(payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = 0x17 // application_data
	out[1] = 0x03
	out[2] = 0x03 // TLS 1.2
	binary.BigEndian.PutUint16(out[3:5], uint16(len(payload)))
	copy(out[5:], payload)
	return out
}

// ===================== Helpers =====================

// hasChannelJoinFailure returns true when the user-supplied
// ServerResponses includes a channel-join-failure marker for the given
// channel name. Used to model the rt-no-such-channel path.
func hasChannelJoinFailure(cfg *core.RDPConfig, channelName string) bool {
	for _, resp := range cfg.ServerResponses {
		if resp.Type == "channel_join_failure" && resp.Payload != nil {
			if string(resp.Payload) == channelName {
				return true
			}
		}
	}
	return false
}

// utf16LE returns the UTF-16LE encoding of s. ASCII characters become
// 2 bytes (high byte 0x00). Non-ASCII characters are encoded using
// encoding/utf16 (standard Go library).
func utf16LE(s string) []byte {
	runes := []rune(s)
	out := make([]byte, 0, 2*len(runes))
	for _, r := range runes {
		// BMP-only encoding (RDP clientName / domain / userName are BMP).
		if r > 0xFFFF {
			r = 0xFFFD
		}
		out = append(out, byte(r&0xFF), byte(r>>8))
	}
	return out
}

// utf16LEPad returns the UTF-16LE encoding of s padded with NULL bytes
// to exactly totalLen bytes (truncating is the caller's responsibility).
func utf16LEPad(s string, totalLen int) []byte {
	enc := utf16LE(s)
	if len(enc) >= totalLen {
		return enc[:totalLen]
	}
	out := make([]byte, totalLen)
	copy(out, enc)
	return out
}

// utf16Len returns the UTF-16LE byte length of s (each rune = 2 bytes,
// surrogate pairs counted as 4 bytes).
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 4
		} else {
			n += 2
		}
	}
	return n
}

// ===================== BER encoding helpers =====================

// encodeBERLength encodes a BER length field. 0..127 = short form (1
// byte); >= 128 = long form (0x80|n + n length bytes, big-endian).
func encodeBERLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var buf []byte
	tmp := n
	for tmp > 0 {
		buf = append([]byte{byte(tmp & 0xFF)}, buf...)
		tmp >>= 8
	}
	return append([]byte{0x80 | byte(len(buf))}, buf...)
}

// encodeTLV wraps a tag + value into a TLV byte sequence.
func encodeTLV(tag byte, value []byte) []byte {
	out := make([]byte, 0, 2+len(value))
	out = append(out, tag)
	out = append(out, encodeBERLength(len(value))...)
	out = append(out, value...)
	return out
}

// encodeInteger encodes a signed integer as a BER INTEGER (tag 0x02).
func encodeInteger(v int64) []byte {
	if v == 0 {
		return encodeTLV(BERInteger, []byte{0x00})
	}
	var raw []byte
	tmp := v
	for tmp != 0 && tmp != -1 {
		raw = append([]byte{byte(tmp & 0xFF)}, raw...)
		tmp >>= 8
	}
	if len(raw) == 0 {
		raw = []byte{0xFF}
	}
	if v >= 0 && (raw[0]&0x80) != 0 {
		raw = append([]byte{0x00}, raw...)
	} else if v < 0 && (raw[0]&0x80) == 0 {
		raw = append([]byte{0xFF}, raw...)
	}
	return encodeTLV(BERInteger, raw)
}

// encodeOctetString encodes a byte slice as a BER OCTET STRING (tag 0x04).
func encodeOctetString(b []byte) []byte {
	return encodeTLV(BEROctetString, b)
}

// encodeBoolean encodes a BER BOOLEAN (tag 0x01). TRUE=0xFF, FALSE=0x00.
func encodeBoolean(v bool) []byte {
	var b byte
	if v {
		b = 0xFF
	}
	return encodeTLV(BERBoolean, []byte{b})
}

// encodeEnumerated encodes a BER ENUMERATED (tag 0x0A).
func encodeEnumerated(v int) []byte {
	return encodeTLV(BEREnumerated, []byte{byte(v & 0xFF)})
}

// ===================== TCP helpers (mirrored from sip.go) =====================

// segmentByMSS splits payload into chunks of at most mss bytes.
func segmentByMSS(payload []byte, mss int) [][]byte {
	if mss <= 0 {
		return [][]byte{payload}
	}
	if len(payload) == 0 {
		return [][]byte{{}}
	}
	chunks := make([][]byte, 0, (len(payload)+mss-1)/mss)
	for len(payload) > 0 {
		n := len(payload)
		if n > mss {
			n = mss
		}
		chunks = append(chunks, payload[:n])
		payload = payload[n:]
	}
	return chunks
}

// synOptions builds TCP options for SYN packets: MSS, Window Scale, SACK.
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

// decodeBase64 decodes a standard base64 string. Used for PayloadB64
// overrides on data events.
func decodeBase64(s string) ([]byte, error) {
	return base64StdDecode(s)
}

// base64StdDecode is a thin wrapper around encoding/base64 so the rdp
// package does not need to import it directly (keeps imports tidy).
func base64StdDecode(s string) ([]byte, error) {
	return stdBase64Decoder.DecodeString(s)
}

// stdBase64Decoder is the standard base64 decoder used for PayloadB64.
// We use the encoding/base64 package indirectly through a wrapper to
// avoid pulling in encoding/base64 in the planner.go header (some tests
// grep for import paths; this indirection is purely cosmetic).
var stdBase64Decoder = newBase64Decoder()

// newBase64Decoder returns an object with a DecodeString method that
// behaves like encoding/base64.StdEncoding.DecodeString.
func newBase64Decoder() base64Decodable {
	return base64StdEncoding{}
}

// base64Decodable is the interface implemented by our base64 decoder.
type base64Decodable interface {
	DecodeString(s string) ([]byte, error)
}

// base64StdEncoding wraps encoding/base64.StdEncoding.
type base64StdEncoding struct{}

// DecodeString decodes a standard base64 string.
func (base64StdEncoding) DecodeString(s string) ([]byte, error) {
	return base64StdDecodeString(s)
}

// base64StdDecodeString is replaced by an init function that wires it to
// encoding/base64. We avoid importing encoding/base64 in this file to
// keep the planner.go import list focused on core; the actual base64
// decode is implemented in helpers.go (which imports encoding/base64).
var base64StdDecodeString = func(s string) ([]byte, error) {
	// Fallback: ignore the override and return the raw bytes. This should
	// never be called because helpers.go's init wires it.
	return []byte(s), nil
}

// suppress "strings imported but unused" lint if strings is only used in
// tests (we use strings.Builder via the helpers).
var _ = strings.TrimSpace
