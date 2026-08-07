// Package pptp implements the PPTP (Point-to-Point Tunneling Protocol,
// RFC 2637) planner: the TCP control plane (default port 1723) plus the
// GRE data plane (outer IP protocol 47, PPTP-enhanced GRE header per RFC
// 2637 §4.1) in a single flow.
//
// The control-plane defaults reproduce the reference pcap byte-for-byte
// (/home/pcap_auto/llcj_mirror/IP-TCP-10.6.2.41-20.6.2.41-49194-1723-12-10-
// 1260-980.pcap, PNS = client 49194, PAC = server 1723): SCCRQ 156B →
// SCCRP 156B → OCRQ 168B → OCRP 32B → SLI×5 (24B each) → CCRQ down →
// [CCRQ+CCDN merged 164B] up → CCDN down 148B → StopRQ 16B → StopRP 16B,
// including the reference implementation quirks (SLI-down peer call id =
// the PNS side's TCP source port 0xc02a instead of the PNS call id; the
// merged CCRQ+CCDN TCP segment; CCDN carrying the PNS call id in both
// directions). The data plane carries PPP frames (FF 03 + 0x0021 + inner
// IPv4) in 16-byte enhanced-GRE headers (flags 0x3081, protocol 0x880B,
// Key = Payload Length + peer Call ID, 32-bit seq/ack).
package pptp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultPort is the PPTP control-connection TCP port (RFC 2637 §1.2).
	DefaultPort = 1723

	// magicCookie is the fixed PPTP magic cookie (RFC 2637 §2).
	magicCookie = 0x1a2b3c4d

	// Control message types (RFC 2637 §2).
	msgSCCRQ = 1  // Start-Control-Connection-Request
	msgSCCRP = 2  // Start-Control-Connection-Reply
	msgStopRQ = 3 // Stop-Control-Connection-Request
	msgStopRP = 4 // Stop-Control-Connection-Reply
	msgECRQ  = 5  // Echo-Request
	msgECRP  = 6  // Echo-Reply
	msgOCRQ  = 7  // Outgoing-Call-Request
	msgOCRP  = 8  // Outgoing-Call-Reply
	msgICRQ  = 9  // Incoming-Call-Request
	msgICRP  = 10 // Incoming-Call-Reply
	msgICCN  = 11 // Incoming-Call-Connected
	msgCCRQ  = 12 // Call-Clear-Request
	msgCCDN  = 13 // Call-Disconnect-Notify
	msgWEN   = 14 // WAN-Error-Notify
	msgSLI   = 15 // Set-Link-Info

	// greFlagA is the A (acknowledgment) bit of the PPTP enhanced-GRE
	// flags word (RFC 2637 §4.1): bit 8 (0x0080), NOT RFC 1701's bit 5 —
	// the Linux kernel defines GRE_ACK = 0x0080 and Wireshark decodes the
	// acknowledgment only when this bit is set on the PPP path.
	greFlagA = 0x0080

	// echoIdentifier is the ECRQ/ECRP Identifier field value (RFC 2637
	// §2.5-2.6): a fixed keep-alive marker for the optional echo segment.
	echoIdentifier = 1

	// greProtoPPP is the GRE Protocol Type for PPTP data packets
	// (RFC 2637 §4.1: PPP).
	greProtoPPP = 0x880B

	// pppProtoIPv4 is the PPP Protocol field for IPv4 (RFC 1661 §6).
	pppProtoIPv4 = 0x0021

	// TCP flags (mirror internal/protocol/vnc).
	tcpSYN    = 0x02
	tcpSYNACK = 0x12
	tcpACK    = 0x10
	tcpPSHACK = 0x18
	tcpFINACK = 0x11

	DefaultTTL = 64
	DefaultMSS = 1460
)

// referenceSubAddress is the reference pcap's OCRQ Sub-Address bytes
// (64-byte field): 16 bytes of binary garbage followed by zeros — a
// reference-implementation artifact reproduced byte-for-byte by default.
var referenceSubAddress, _ = hex.DecodeString("011f423a6484e94caf72892a29b1d3ab")

// Planner implements the PPTP protocol planner.
type Planner struct{}

// NewPlanner creates a new PPTP planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string {
	return "pptp"
}

// Validate validates a PPTP flow spec (design_pptp.md §3).
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
	if spec.PPTP == nil {
		return fmt.Errorf("pptp config is required")
	}
	cfg := spec.PPTP
	if role := cfg.Role; role != "" && role != "pns" && role != "pac" {
		return fmt.Errorf("invalid pptp role %q (allowed: pns, pac)", role)
	}
	switch cfg.Scenario {
	case "", "full", "control_only", "tunnel_only", "data_only":
		// ok
	default:
		return fmt.Errorf("invalid pptp scenario %q (allowed: full, control_only, tunnel_only, data_only)", cfg.Scenario)
	}
	if cfg.Calls < 0 {
		return fmt.Errorf("invalid pptp calls %d", cfg.Calls)
	}
	if cfg.SLICount < 0 {
		return fmt.Errorf("invalid pptp sli_count %d", cfg.SLICount)
	}
	if cfg.DataFrames < 0 {
		return fmt.Errorf("invalid pptp data_frames %d", cfg.DataFrames)
	}
	if cfg.DownDataFrames < 0 {
		return fmt.Errorf("invalid pptp down_data_frames %d", cfg.DownDataFrames)
	}
	if cfg.SubAddress != "" {
		if _, err := hex.DecodeString(cfg.SubAddress); err != nil {
			return fmt.Errorf("invalid pptp sub_address %q (must be hex)", cfg.SubAddress)
		}
	}
	if len(cfg.HostName) > 64 || len(cfg.VendorName) > 64 || len(cfg.PhoneNumber) > 64 ||
		len(cfg.DialedNumber) > 64 || len(cfg.DialingNumber) > 64 {
		return fmt.Errorf("pptp host_name/vendor_name/phone_number/dialed_number/dialing_number exceed 64 bytes (fixed-size fields, RFC 2637 §2)")
	}
	if ip := cfg.InnerIP; ip != nil {
		if ip.SrcIP != "" && net.ParseIP(ip.SrcIP) == nil {
			return fmt.Errorf("invalid pptp inner src_ip: %s", ip.SrcIP)
		}
		if ip.DstIP != "" && net.ParseIP(ip.DstIP) == nil {
			return fmt.Errorf("invalid pptp inner dst_ip: %s", ip.DstIP)
		}
		if ip.Proto != 0 && ip.Proto != 1 && ip.Proto != 6 && ip.Proto != 17 {
			return fmt.Errorf("invalid pptp inner proto %d (allowed: 1 ICMP, 6 TCP, 17 UDP)", ip.Proto)
		}
	}
	return nil
}

// --- control message builders (design_pptp.md §4; reference-verified) ---

// controlHeader builds the 12-byte fixed PPTP control header (RFC 2637
// §2): Length(2, big-endian, counting the header) + Message Type(2, always
// 1) + Magic Cookie(4, 0x1a2b3c4d) + Control Message Type(2) + Reserved(2,
// always 0). bodyLen is the byte count of the message body that follows.
func controlHeader(msgType uint16, bodyLen int) []byte {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(12+bodyLen))
	binary.BigEndian.PutUint16(hdr[2:4], 1)
	binary.BigEndian.PutUint32(hdr[4:8], magicCookie)
	binary.BigEndian.PutUint16(hdr[8:10], msgType)
	return hdr
}

// fixed64 pads a string to a fixed 64-byte field (RFC 2637 §2.1 Host Name
// / Vendor Name; §2.4.1 Phone Number / Sub-Address).
func fixed64(s string) []byte {
	out := make([]byte, 64)
	copy(out, s)
	return out
}

// buildSCCRQ encodes Start-Control-Connection-Request (156B total, RFC
// 2637 §2.1): Version(2) + Reserved(2) + Framing Caps(4) + Bearer Caps(4)
// + Max Channels(2) + Firmware Revision(2) + Host Name(64) + Vendor
// Name(64). Defaults are the reference pcap bytes.
func buildSCCRQ(c *resolved) []byte {
	body := make([]byte, 144)
	binary.BigEndian.PutUint16(body[0:2], c.version)
	binary.BigEndian.PutUint32(body[4:8], c.framingCaps)
	binary.BigEndian.PutUint32(body[8:12], c.bearerCaps)
	binary.BigEndian.PutUint16(body[12:14], c.maxChannels)
	binary.BigEndian.PutUint16(body[14:16], c.firmwareRev)
	copy(body[16:80], fixed64(c.hostName))
	copy(body[80:144], fixed64(c.vendorName))
	return append(controlHeader(msgSCCRQ, len(body)), body...)
}

// buildSCCRP encodes Start-Control-Connection-Reply (156B total, RFC 2637
// §2.2). Result Code and Error Code are each 1 byte (reference pcap; the
// total of 156B matches the RFC diagram's 2+1+1+4+4+2+2+64+64 layout).
func buildSCCRP(c *resolved) []byte {
	body := make([]byte, 144)
	binary.BigEndian.PutUint16(body[0:2], c.version)
	body[2] = c.scrpResult
	body[3] = c.scrpError
	binary.BigEndian.PutUint32(body[4:8], c.scrpFramingCaps)
	binary.BigEndian.PutUint32(body[8:12], c.scrpBearerCaps)
	binary.BigEndian.PutUint16(body[12:14], c.maxChannels)
	binary.BigEndian.PutUint16(body[14:16], c.scrpFirmwareRev)
	copy(body[16:80], fixed64(c.hostName))
	copy(body[80:144], fixed64(c.vendorName))
	return append(controlHeader(msgSCCRP, len(body)), body...)
}

// buildOCRQ encodes Outgoing-Call-Request (168B total, RFC 2637 §2.4.1),
// sent by the PNS with the PNS's own Call ID. Phone Number Length is
// auto-filled from PhoneNumber.
func buildOCRQ(c *resolved, callID uint16) []byte {
	body := make([]byte, 156)
	binary.BigEndian.PutUint16(body[0:2], callID)
	binary.BigEndian.PutUint16(body[2:4], c.callSerial)
	binary.BigEndian.PutUint32(body[4:8], c.minBPS)
	binary.BigEndian.PutUint32(body[8:12], c.maxBPS)
	binary.BigEndian.PutUint32(body[12:16], c.bearerType)
	binary.BigEndian.PutUint32(body[16:20], c.framingType)
	binary.BigEndian.PutUint16(body[20:22], c.windowSize)
	binary.BigEndian.PutUint16(body[22:24], c.packetDelay)
	binary.BigEndian.PutUint16(body[24:26], uint16(len(c.phoneNumber)))
	copy(body[28:92], fixed64(c.phoneNumber))
	copy(body[92:156], subAddressBytes(c.subAddress))
	return append(controlHeader(msgOCRQ, len(body)), body...)
}

// subAddressBytes decodes the OCRQ Sub-Address (64-byte field). Empty =
// the reference pcap's binary garbage; explicit hex strings are decoded
// and zero-padded; the literal string "zero" is not special (an empty
// decoded result means all zeros).
func subAddressBytes(s string) []byte {
	if s == "" {
		out := make([]byte, 64)
		copy(out, referenceSubAddress)
		return out
	}
	b, _ := hex.DecodeString(s)
	out := make([]byte, 64)
	copy(out, b)
	return out
}

// buildOCRP encodes Outgoing-Call-Reply (32B total, RFC 2637 §2.4.2),
// sent by the PAC: the PAC's own Call ID + the PNS's Peer Call ID.
func buildOCRP(c *resolved, pacCallID, pnsCallID uint16) []byte {
	body := make([]byte, 20)
	binary.BigEndian.PutUint16(body[0:2], pacCallID)
	binary.BigEndian.PutUint16(body[2:4], pnsCallID)
	body[4] = c.ocrpResult
	body[5] = c.ocrpError
	binary.BigEndian.PutUint16(body[6:8], c.causeCode)
	binary.BigEndian.PutUint32(body[8:12], c.connectSpeed)
	binary.BigEndian.PutUint16(body[12:14], c.ocrpWindowSize)
	binary.BigEndian.PutUint16(body[14:16], c.ocrpDelay)
	binary.BigEndian.PutUint32(body[16:20], c.physicalChannelID)
	return append(controlHeader(msgOCRP, len(body)), body...)
}

// buildSLI encodes Set-Link-Info (24B total, RFC 2637 §2.7): Peer Call
// ID + Reserved + Send ACCM + Receive ACCM. peerCallID is resolved by the
// caller: PNS-side SLIs use the PAC's call id; PAC-side SLIs use the PNS
// side's TCP source port (the reference pcap quirk).
func buildSLI(peerCallID uint16, sendACCM, receiveACCM uint32) []byte {
	body := make([]byte, 12)
	binary.BigEndian.PutUint16(body[0:2], peerCallID)
	binary.BigEndian.PutUint32(body[4:8], sendACCM)
	binary.BigEndian.PutUint32(body[8:12], receiveACCM)
	return append(controlHeader(msgSLI, len(body)), body...)
}

// buildCCRQ encodes Call-Clear-Request (16B total, RFC 2637 §2.12): the
// sender's own Call ID + Reserved.
func buildCCRQ(callID uint16) []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint16(body[0:2], callID)
	return append(controlHeader(msgCCRQ, len(body)), body...)
}

// buildCCDN encodes Call-Disconnect-Notify (148B total, RFC 2637 §2.13):
// Call ID + Result Code + Error Code + Cause Code + Reserved + Call
// Statistics (128 bytes — the reference pcap carries the PNS call id in
// both directions).
func buildCCDN(c *resolved, callID uint16) []byte {
	body := make([]byte, 136)
	binary.BigEndian.PutUint16(body[0:2], callID)
	body[2] = c.ccdnResult
	body[3] = c.ccdnError
	binary.BigEndian.PutUint16(body[4:6], c.ccdnCause)
	return append(controlHeader(msgCCDN, len(body)), body...)
}

// buildStopRQ encodes Stop-Control-Connection-Request (16B total, RFC
// 2637 §2.3.1): Reason(1) + Reserved(1) + Reserved(2).
func buildStopRQ(c *resolved) []byte {
	body := make([]byte, 4)
	body[0] = c.stopReason
	return append(controlHeader(msgStopRQ, len(body)), body...)
}

// buildStopRP encodes Stop-Control-Connection-Reply (16B total, RFC 2637
// §2.3.2): Result(1) + Error(1) + Reserved(2).
func buildStopRP(c *resolved) []byte {
	body := make([]byte, 4)
	body[0] = c.stopResult
	body[1] = c.stopError
	return append(controlHeader(msgStopRP, len(body)), body...)
}

// buildECRQ encodes Echo-Request (16B total, RFC 2637 §2.5, PAC side):
// Identifier(4). The identifier is a fixed keep-alive marker (no
// reference pcap for this optional segment; ECRP echoes it back).
func buildECRQ() []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body[0:4], echoIdentifier)
	return append(controlHeader(msgECRQ, len(body)), body...)
}

// buildECRP encodes Echo-Reply (20B total, RFC 2637 §2.6, PNS side):
// Identifier(4) + Result Code(1) + Error Code(1) + Reserved1(2).
func buildECRP(c *resolved) []byte {
	body := make([]byte, 8)
	binary.BigEndian.PutUint32(body[0:4], echoIdentifier)
	body[4] = c.ocrpResult
	body[5] = c.ocrpError
	return append(controlHeader(msgECRP, len(body)), body...)
}

// buildICRQ encodes Incoming-Call-Request (220B total, RFC 2637 §2.9,
// PAC side): Call ID + Call Serial Number + Call Bearer Type + Physical
// Channel ID + Dialed Number Length + Dialing Number Length + Dialed
// Number(64) + Dialing Number(64) + Subaddress(64). The Call Bearer
// Type reuses bearerType, the Physical Channel ID reuses
// physicalChannelID, and the Subaddress reuses subAddress (hex-decoded);
// the Dialed/Dialing length fields are auto-filled from the strings.
func buildICRQ(c *resolved, pacCallID uint16) []byte {
	body := make([]byte, 208)
	binary.BigEndian.PutUint16(body[0:2], pacCallID)
	binary.BigEndian.PutUint16(body[2:4], c.callSerial)
	binary.BigEndian.PutUint32(body[4:8], c.bearerType)
	binary.BigEndian.PutUint32(body[8:12], c.physicalChannelID)
	binary.BigEndian.PutUint16(body[12:14], uint16(len(c.dialedNumber)))
	binary.BigEndian.PutUint16(body[14:16], uint16(len(c.dialingNumber)))
	copy(body[16:80], fixed64(c.dialedNumber))
	copy(body[80:144], fixed64(c.dialingNumber))
	copy(body[144:208], subAddressBytes(c.subAddress))
	return append(controlHeader(msgICRQ, len(body)), body...)
}

// buildICRP encodes Incoming-Call-Reply (24B total, RFC 2637 §2.10, PNS
// side): Call ID (assigned by the PNS) + Peer's Call ID + Result Code +
// Error Code + Recv Window + Transmit Delay + Reserved1.
func buildICRP(c *resolved, pnsCallID, pacCallID uint16) []byte {
	body := make([]byte, 12)
	binary.BigEndian.PutUint16(body[0:2], pnsCallID)
	binary.BigEndian.PutUint16(body[2:4], pacCallID)
	body[4] = c.ocrpResult
	body[5] = c.ocrpError
	binary.BigEndian.PutUint16(body[6:8], c.ocrpWindowSize)
	binary.BigEndian.PutUint16(body[8:10], c.ocrpDelay)
	return append(controlHeader(msgICRP, len(body)), body...)
}

// buildICCN encodes Incoming-Call-Connected (28B total, RFC 2637 §2.11,
// PAC side): Peer's Call ID (the PNS's id) + Reserved1 + Connect Speed +
// Recv Window + Transmit Delay + Framing Type.
func buildICCN(c *resolved, pnsCallID uint16) []byte {
	body := make([]byte, 16)
	binary.BigEndian.PutUint16(body[0:2], pnsCallID)
	binary.BigEndian.PutUint32(body[4:8], c.connectSpeed)
	binary.BigEndian.PutUint16(body[8:10], c.ocrpWindowSize)
	binary.BigEndian.PutUint16(body[10:12], c.ocrpDelay)
	binary.BigEndian.PutUint32(body[12:16], c.framingType)
	return append(controlHeader(msgICCN, len(body)), body...)
}

// buildWEN encodes WAN-Error-Notify (40B total, RFC 2637 §2.14, PAC
// side): Peer's Call ID + Reserved1 + six cumulative error counters
// (all zero by default — only sent when an error condition occurs).
func buildWEN(pnsCallID uint16) []byte {
	body := make([]byte, 28)
	binary.BigEndian.PutUint16(body[0:2], pnsCallID)
	return append(controlHeader(msgWEN, len(body)), body...)
}

// --- Plan ---

// Plan generates packet configs for one PPTP session: TCP handshake,
// control-plane messages per the Scenario template, GRE data frames (PPP
// payloads), teardown (design_pptp.md §5-§7). The default "full" scenario
// reproduces the reference pcap control plane byte-for-byte.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = DefaultPort
	}
	cfg := spec.PPTP
	role := cfg.Role
	if role == "" {
		role = "pns"
	}
	scenario := cfg.Scenario
	if scenario == "" {
		scenario = "full"
	}
	calls := cfg.Calls
	if calls == 0 {
		calls = 1
	}
	r := resolveDefaults(cfg)

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
		ipID := randomIPID()
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}
		ttl := spec.TTL
		if ttl == 0 {
			ttl = DefaultTTL
		}
		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		synOpts := synOptions(mss)

		pnsSeq := uint32(0)
		if spec.TCP != nil {
			pnsSeq = spec.TCP.InitialSeq
		}
		if pnsSeq == 0 {
			pnsSeq = randomUint32()
		}
		pacSeq := randomUint32()

		packetIndex := uint64(0)

		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) {
			l3 := core.L3Base(srcIP, dstIP, 6, ttl, nextIPID(), spec)
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
				l4.TCPOptions = synOpts
			}
			cfgOut := core.PacketConfig{
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
			case configChan <- cfgOut:
			case <-ctx.Done():
			}
			packetIndex++
		}

		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) uint32 {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, tcpPSHACK, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		up := func(seq, peer uint32, payload []byte) uint32 {
			return emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, seq, peer, payload)
		}
		down := func(seq, peer uint32, payload []byte) uint32 {
			return emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, seq, peer, payload)
		}

		// send emits one control message from the given role's side. The
		// role determines which side is which: with role=pns the PNS side
		// is the flow source (up); with role=pac the PNS side is the
		// destination (down).
		send := func(side string, payload []byte) {
			if side == "pns" {
				if role == "pns" {
					pnsSeq = up(pnsSeq, pacSeq, payload)
				} else {
					pnsSeq = down(pnsSeq, pacSeq, payload)
				}
			} else {
				if role == "pns" {
					pacSeq = down(pacSeq, pnsSeq, payload)
				} else {
					pacSeq = up(pacSeq, pnsSeq, payload)
				}
			}
		}

		// emitGRE emits one PPTP-GRE data frame (RFC 2637 §4.1): outer IP
		// protocol 47, 16-byte enhanced-GRE header (flags 0x3081, protocol
		// 0x880B, Key = Payload Length + peer Call ID, 32-bit seq/ack),
		// payload = PPP frame. Not part of the TCP control stream.
		emitGRE := func(dir, srcMAC, dstMAC, srcIP, dstIP string, callID uint16, seq, ack uint32, ppp []byte) {
			greCfg := core.GREConfig{
				PPTP:       true,
				CallID:     callID,
				AckPresent: true,
				Sequence:   seq,
				Ack:        ack,
			}
			cfgOut := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   dir,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(srcIP),
					GRE:       &greCfg,
				},
				L3:      core.L3Base(srcIP, dstIP, core.ProtocolGRE, ttl, nextIPID(), spec),
				Payload: ppp,
			}
			select {
			case configChan <- cfgOut:
			case <-ctx.Done():
			}
			packetIndex++
		}

		// GRE data emission: PNS-side frames first (seq 0..N-1, ack 0 —
		// nothing received yet), then PAC-side frames (seq 0..M-1, ack =
		// N-1). Each frame carries the PEER's call id in the GRE Key field
		// (RFC 2637 §1.3.2). ipidOffset keeps inner IPIDs distinct.
		emitDataPlane := func(callIdx int, ipidBase int) {
			pnsID := r.peerCallID + uint16(callIdx)
			pacID := r.callID + uint16(callIdx)
			for i := 0; i < r.dataFrames; i++ {
				ppp := pppFrame(&r, spec, ipidBase+i)
				if role == "pns" {
					emitGRE("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, pnsID, uint32(i), 0, ppp)
				} else {
					emitGRE("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, pnsID, uint32(i), 0, ppp)
				}
			}
			ack := uint32(0)
			if r.dataFrames > 0 {
				ack = uint32(r.dataFrames - 1)
			}
			for i := 0; i < r.downFrames; i++ {
				ppp := pppFrame(&r, spec, ipidBase+r.dataFrames+i)
				if role == "pns" {
					emitGRE("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, pacID, uint32(i), ack, ppp)
				} else {
					emitGRE("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, pacID, uint32(i), ack, ppp)
				}
			}
		}

		// pnsPort is the PNS side's TCP port — used by the SLI-down
		// reference quirk (the PAC sends the PNS side's source port as the
		// peer call id).
		pnsPort := spec.SrcPort
		if role == "pac" {
			pnsPort = spec.DstPort
		}

		if scenario == "data_only" {
			// No TCP control plane at all: GRE data frames only, with the
			// configured call ids (no per-call offset).
			emitDataPlane(0, 0)
			return
		}

		// --- TCP handshake (SYN, SYN-ACK, ACK) ---
		if role == "pns" {
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, pnsSeq, 0, tcpSYN, nil)
			pnsSeq++
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, pacSeq, pnsSeq, tcpSYNACK, nil)
			pacSeq++
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, pnsSeq, pacSeq, tcpACK, nil)
		} else {
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, pnsSeq, 0, tcpSYN, nil)
			pnsSeq++
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, pacSeq, pnsSeq, tcpSYNACK, nil)
			pacSeq++
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, pnsSeq, pacSeq, tcpACK, nil)
		}

		// --- control plane ---
		send("pns", buildSCCRQ(&r))
		send("pac", buildSCCRP(&r))
		if cfg.Echo {
			send("pac", buildECRQ())
			send("pns", buildECRP(&r))
		}

		ipidBase := 0
		for callIdx := 0; callIdx < calls; callIdx++ {
			pnsID := r.callID + uint16(callIdx)
			pacID := r.peerCallID + uint16(callIdx)

			send("pns", buildOCRQ(&r, pnsID))
			send("pac", buildOCRP(&r, pacID, pnsID))
			if cfg.IncomingCall {
				send("pac", buildICRQ(&r, pacID))
				send("pns", buildICRP(&r, pnsID, pacID))
				send("pac", buildICCN(&r, pnsID))
			}
			if scenario == "full" || scenario == "control_only" {
				for i := 0; i < r.sliCount; i++ {
					var peerID uint16
					if i%2 == 0 {
						// PNS-side SLI: peer = the PAC's call id.
						peerID = pacID
					} else {
						// PAC-side SLI: peer = the PNS side's TCP source port
						// (reference quirk), unless overridden.
						if r.sliPeerCallID != 0 {
							peerID = r.sliPeerCallID + uint16(callIdx)
						} else {
							peerID = pnsPort
						}
					}
					send(sideFor(i%2 == 0), buildSLI(peerID, r.sendACCM, r.receiveACCM))
				}
				if cfg.WEN {
					send("pac", buildWEN(pnsID))
				}
			}
			if scenario == "full" {
				emitDataPlane(callIdx, ipidBase)
				ipidBase += r.dataFrames + r.downFrames
			}
			// Teardown per call (reference sequence): CCRQ from the PAC
			// side, then CCRQ + CCDN merged into a single TCP segment from
			// the PNS side, then CCDN from the PAC side (RFC 2637 §2.12-
			// 2.13; the merged segment reproduces the reference pcap).
			send("pac", buildCCRQ(pacID))
			merged := append(buildCCRQ(pnsID), buildCCDN(&r, pnsID)...)
			send("pns", merged)
			send("pac", buildCCDN(&r, pnsID))
		}

		send("pns", buildStopRQ(&r))
		send("pac", buildStopRP(&r))

		// --- TCP teardown (FIN-ACK, ACK, FIN-ACK, ACK) ---
		if role == "pns" {
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, pnsSeq, pacSeq, tcpFINACK, nil)
			pnsSeq++
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, pacSeq, pnsSeq, tcpACK, nil)
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, pacSeq, pnsSeq, tcpFINACK, nil)
			pacSeq++
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, pnsSeq, pacSeq, tcpACK, nil)
		} else {
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, pnsSeq, pacSeq, tcpFINACK, nil)
			pnsSeq++
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, pacSeq, pnsSeq, tcpACK, nil)
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, pacSeq, pnsSeq, tcpFINACK, nil)
			pacSeq++
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, pnsSeq, pacSeq, tcpACK, nil)
		}
	}()

	return configChan, nil
}

// sideFor maps a PNS-first alternation index to the emitting side.
func sideFor(pnsTurn bool) string {
	if pnsTurn {
		return "pns"
	}
	return "pac"
}

// resolved holds the config with design defaults applied (0 = reference
// default). Resolved once in Plan so the builders stay pure.
type resolved struct {
	version           uint16
	framingCaps       uint32
	bearerCaps        uint32
	maxChannels       uint16
	firmwareRev       uint16
	hostName          string
	vendorName        string
	scrpResult        uint8
	scrpError         uint8
	scrpFramingCaps   uint32
	scrpBearerCaps    uint32
	scrpFirmwareRev   uint16
	callID            uint16
	peerCallID        uint16
	callSerial        uint16
	minBPS            uint32
	maxBPS            uint32
	bearerType        uint32
	framingType       uint32
	windowSize        uint16
	packetDelay       uint16
	phoneNumber       string
	subAddress        string
	ocrpResult        uint8
	ocrpError         uint8
	causeCode         uint16
	connectSpeed      uint32
	ocrpWindowSize    uint16
	ocrpDelay         uint16
	physicalChannelID uint32
	sendACCM          uint32
	receiveACCM       uint32
	sliCount          int
	sliPeerCallID     uint16
	stopReason        uint8
	stopResult        uint8
	stopError         uint8
	ccdnResult        uint8
	ccdnError         uint8
	ccdnCause         uint16
	dataFrames        int
	downFrames        int
	dialedNumber      string
	dialingNumber     string
}

// resolveDefaults applies the design defaults (0 = reference value).
func resolveDefaults(cfg *core.PPTPConfig) resolved {
	r := resolved{
		version:         0x0100,
		framingCaps:     0x00000001,
		bearerCaps:      0x00000001,
		scrpResult:      1,
		scrpFramingCaps: 0x00000002,
		scrpBearerCaps:  0x00000003,
		scrpFirmwareRev: 0x0ece,
		callID:          0xa9c0,
		peerCallID:      0x35c9,
		callSerial:      3,
		minBPS:          300,
		maxBPS:          100000000,
		bearerType:      3,
		framingType:     3,
		windowSize:      64,
		ocrpResult:      1,
		connectSpeed:    14808325,
		ocrpWindowSize:  16384,
		sendACCM:        0xffffffff,
		receiveACCM:     0xffffffff,
		sliCount:        5,
		stopReason:      1,
		stopResult:      1,
		dataFrames:      3,
		downFrames:      2,
	}
	if cfg.Version != 0 {
		r.version = cfg.Version
	}
	if cfg.FramingCaps != 0 {
		r.framingCaps = cfg.FramingCaps
	}
	if cfg.BearerCaps != 0 {
		r.bearerCaps = cfg.BearerCaps
	}
	r.maxChannels = cfg.MaxChannels
	r.firmwareRev = cfg.FirmwareRevision
	r.hostName = cfg.HostName
	if cfg.VendorName != "" {
		r.vendorName = cfg.VendorName
	} else {
		r.vendorName = "Microsoft"
	}
	if cfg.ScrpResult != 0 {
		r.scrpResult = cfg.ScrpResult
	}
	r.scrpError = cfg.ScrpError
	if cfg.ScrpFramingCaps != 0 {
		r.scrpFramingCaps = cfg.ScrpFramingCaps
	}
	if cfg.ScrpBearerCaps != 0 {
		r.scrpBearerCaps = cfg.ScrpBearerCaps
	}
	if cfg.ScrpFirmwareRev != 0 {
		r.scrpFirmwareRev = cfg.ScrpFirmwareRev
	}
	if cfg.CallID != 0 {
		r.callID = cfg.CallID
	}
	if cfg.PeerCallID != 0 {
		r.peerCallID = cfg.PeerCallID
	}
	if cfg.CallSerial != 0 {
		r.callSerial = cfg.CallSerial
	}
	if cfg.MinBPS != 0 {
		r.minBPS = cfg.MinBPS
	}
	if cfg.MaxBPS != 0 {
		r.maxBPS = cfg.MaxBPS
	}
	if cfg.BearerType != 0 {
		r.bearerType = cfg.BearerType
	}
	if cfg.FramingType != 0 {
		r.framingType = cfg.FramingType
	}
	if cfg.WindowSize != 0 {
		r.windowSize = cfg.WindowSize
	}
	r.packetDelay = cfg.PacketDelay
	r.phoneNumber = cfg.PhoneNumber
	r.subAddress = cfg.SubAddress
	if cfg.OcrpResult != 0 {
		r.ocrpResult = cfg.OcrpResult
	}
	r.ocrpError = cfg.OcrpError
	r.causeCode = cfg.CauseCode
	if cfg.ConnectSpeed != 0 {
		r.connectSpeed = cfg.ConnectSpeed
	}
	if cfg.OcrpWindowSize != 0 {
		r.ocrpWindowSize = cfg.OcrpWindowSize
	}
	r.ocrpDelay = cfg.OcrpDelay
	r.physicalChannelID = cfg.PhysicalChannelID
	if cfg.SendACCM != 0 {
		r.sendACCM = cfg.SendACCM
	}
	if cfg.ReceiveACCM != 0 {
		r.receiveACCM = cfg.ReceiveACCM
	}
	if cfg.SLICount != 0 {
		r.sliCount = cfg.SLICount
	}
	r.sliPeerCallID = cfg.SliPeerCallID
	if cfg.StopReason != 0 {
		r.stopReason = cfg.StopReason
	}
	if cfg.StopResult != 0 {
		r.stopResult = cfg.StopResult
	}
	r.stopError = cfg.StopError
	r.ccdnResult = cfg.CcdnResult
	r.ccdnError = cfg.CcdnError
	r.ccdnCause = cfg.CcdnCause
	// Frame counts take explicit 0 (zero frames is legal): the parse layer
	// (parsePPTPConfig, getIntPresence) already supplies the reference
	// defaults when the keys are absent, so a zero here is an explicit zero.
	r.dataFrames = cfg.DataFrames
	r.downFrames = cfg.DownDataFrames
	r.sliCount = cfg.SLICount
	r.dialedNumber = cfg.DialedNumber
	r.dialingNumber = cfg.DialingNumber
	return r
}

// pppFrame builds one PPP data-frame payload (RFC 2637 §4.1 carries PPP;
// RFC 1661 §6: FF 03 + 2-byte Protocol + Information): the inner IPv4
// packet (PPP Protocol 0x0021). Each frame gets a distinct inner IPID.
func pppFrame(r *resolved, spec core.FlowSpec, ipid int) []byte {
	srcIP, dstIP := "10.10.10.1", "10.10.10.2"
	proto := uint8(17)
	var srcPort, dstPort uint16
	ttl := uint8(0)
	var payload []byte
	if ip := spec.PPTP.InnerIP; ip != nil {
		if ip.SrcIP != "" {
			srcIP = ip.SrcIP
		}
		if ip.DstIP != "" {
			dstIP = ip.DstIP
		}
		if ip.Proto != 0 {
			proto = ip.Proto
		}
		srcPort = ip.SrcPort
		dstPort = ip.DstPort
		ttl = ip.TTL
		payload = ip.Payload
	}
	inner := buildInnerIPv4Packet(srcIP, dstIP, proto, srcPort, dstPort, ttl, payload, uint16(ipid+1))
	ppp := make([]byte, 0, 4+len(inner))
	ppp = append(ppp, 0xFF, 0x03) // HDLC address+control (RFC 1661 §6)
	ppp = append(ppp, byte(pppProtoIPv4>>8), byte(pppProtoIPv4))
	ppp = append(ppp, inner...)
	return ppp
}

// buildInnerIPv4Packet builds a complete inner IPv4 packet (header + L4 +
// payload) for encapsulation inside a PPP frame. The IPv4 header checksum
// is computed per RFC 791 §3.1. L4 checksums are computed for TCP/ICMP and
// left zero for UDP (valid per RFC 768 when the UDP checksum field is 0).
func buildInnerIPv4Packet(srcIP, dstIP string, proto uint8, srcPort, dstPort uint16, ttl uint8, payload []byte, ipid uint16) []byte {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()

	var l4 []byte
	switch proto {
	case 6: // TCP (RFC 793)
		l4 = make([]byte, 20+len(payload))
		binary.BigEndian.PutUint16(l4[0:2], srcPort)
		binary.BigEndian.PutUint16(l4[2:4], dstPort)
		l4[12] = 5 << 4
		binary.BigEndian.PutUint16(l4[14:16], 65535)
		copy(l4[20:], payload)
		binary.BigEndian.PutUint16(l4[16:18], l4Checksum(l4, proto, src, dst))
	case 17: // UDP (RFC 768)
		l4 = make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(l4[0:2], srcPort)
		binary.BigEndian.PutUint16(l4[2:4], dstPort)
		binary.BigEndian.PutUint16(l4[4:6], uint16(8+len(payload)))
		copy(l4[8:], payload)
	case 1: // ICMP (RFC 792)
		l4 = make([]byte, 8+len(payload))
		l4[0] = 8 // echo request
		copy(l4[8:], payload)
		binary.BigEndian.PutUint16(l4[2:4], ipChecksum16(l4))
	default:
		l4 = payload
	}

	hdr := make([]byte, 20)
	hdr[0] = 0x45 // Version=4, IHL=5
	binary.BigEndian.PutUint16(hdr[2:4], uint16(20+len(l4)))
	binary.BigEndian.PutUint16(hdr[4:6], ipid)
	binary.BigEndian.PutUint16(hdr[6:8], 0x4000) // DF
	if ttl == 0 {
		ttl = 64
	}
	hdr[8] = ttl
	hdr[9] = proto
	if len(src) == 4 {
		copy(hdr[12:16], src)
	}
	if len(dst) == 4 {
		copy(hdr[16:20], dst)
	}
	binary.BigEndian.PutUint16(hdr[10:12], ipChecksum16(hdr))

	return append(hdr, l4...)
}

// ipChecksum16 computes the 16-bit one's-complement checksum used by IPv4
// (RFC 791 §3.1) and ICMP (RFC 792).
func ipChecksum16(b []byte) uint16 {
	sum := uint32(0)
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// l4Checksum computes the TCP/UDP checksum with the IPv4 pseudo-header
// (RFC 793 / RFC 768).
func l4Checksum(l4 []byte, proto uint8, src, dst net.IP) uint16 {
	pseudo := make([]byte, 12)
	if len(src) == 4 {
		copy(pseudo[0:4], src)
	}
	if len(dst) == 4 {
		copy(pseudo[4:8], dst)
	}
	pseudo[9] = proto
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(l4)))
	return ipChecksum16(append(pseudo, l4...))
}

// segmentByMSS splits a payload into MSS-sized chunks (RFC 879). An empty
// payload yields a single empty chunk. Mirrors internal/protocol/vnc.
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

// synOptions builds TCP options for SYN packets: MSS, Window Scale, and
// SACK-Permitted. Mirrors internal/protocol/vnc.synOptions.
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

func u16BE(v uint16) []byte {
	return []byte{byte(v >> 8), byte(v)}
}

func u32BE(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// randomIPID returns a random 16-bit IP identification seed.
func randomIPID() uint16 {
	b, err := randomBytes(2)
	if err != nil {
		return 0x1234
	}
	return binary.BigEndian.Uint16(b)
}

// randomUint32 returns a random uint32 (crypto/rand; deterministic
// fallback on the practically impossible failure path).
func randomUint32() uint32 {
	b, err := randomBytes(4)
	if err != nil {
		return 0x12345678
	}
	return binary.BigEndian.Uint32(b)
}

func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}
