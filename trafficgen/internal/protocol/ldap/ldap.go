// Package ldap implements the LDAP (RFC 4511) protocol planner.
package ldap

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultPort is the LDAP TCP port (RFC 4511, IANA: ldap/tcp 389).
	DefaultPort = 389

	// MaxMessageID is the largest messageID the planner will emit
	// (RFC 4511 §4.1.1 INTEGER must be positive; 2-byte values keep the
	// wire minimal).
	MaxMessageID = 0x7FFF

	// BER primitive tags (RFC 4511 §4.1.1).
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagEnumerated  = 0x0a
	tagBoolean     = 0x01
	tagSimpleAuth  = 0x80 // authentication simple [0]
	tagPresent     = 0x87 // filter present [7]
	tagEquality    = 0xa3 // filter equalityMatch [3]

	// protocolOp application tags (RFC 4511 §4.1.1 / §4.2-4.5).
	opBindRequest   = 0x60
	opBindResponse  = 0x61
	opUnbindRequest = 0x42
	opSearchRequest = 0x63
	opSearchEntry   = 0x64
	opSearchDone    = 0x65

	// TCP flags (mirror internal/protocol/rtsp).
	tcpSYN    = 0x02
	tcpSYNACK = 0x12
	tcpACK    = 0x10
	tcpPSHACK = 0x18
	tcpFINACK = 0x11

	DefaultTTL = 64
	DefaultMSS = 1460
	MinMSS     = 536
)

// defaultAttributes mirrors the reference pcap searchRequest's 15 RootDSE
// attributes (RFC 4512 §3.4): the AD client queried the RootDSE for all of
// these, in this order.
var defaultAttributes = []string{
	"subschemaSubentry", "dsServiceName", "namingContexts",
	"defaultNamingContext", "schemaNamingContext", "configurationNamingContext",
	"rootDomainNamingContext", "supportedControl", "supportedLDAPVersion",
	"supportedLDAPPolicies", "supportedSASLMechanisms", "dnsHostName",
	"ldapServiceName", "serverName", "supportedCapabilities",
}

// Planner implements the LDAP protocol planner.
type Planner struct{}

// NewPlanner creates a new LDAP planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string {
	return "ldap"
}

// Validate validates an LDAP flow spec.
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
	if spec.LDAP == nil {
		return fmt.Errorf("ldap config is required")
	}
	cfg := spec.LDAP

	if cfg.Version != 0 && cfg.Version != 2 && cfg.Version != 3 {
		return fmt.Errorf("ldap: invalid version %d (allowed: 2, 3)", cfg.Version)
	}
	if cfg.SearchScope < 0 || cfg.SearchScope > 2 {
		return fmt.Errorf("ldap: invalid scope %d (allowed: 0, 1, 2)", cfg.SearchScope)
	}
	if ft := cfg.FilterType; ft != "" && ft != "present" && ft != "equality" {
		return fmt.Errorf("ldap: invalid filter type %q (allowed: present, equality)", ft)
	}
	if cfg.ResultCode > 127 {
		return fmt.Errorf("ldap: result_code %d out of ENUMERATED range (0-127)", cfg.ResultCode)
	}
	if cfg.SizeLimit < 0 {
		return fmt.Errorf("ldap: size_limit must be >= 0")
	}
	if cfg.TimeLimit < 0 {
		return fmt.Errorf("ldap: time_limit must be >= 0")
	}
	rounds := cfg.Rounds
	if rounds <= 0 {
		rounds = 1
	}
	base := int(cfg.MessageIDBase)
	if base == 0 {
		base = 1
	}
	if maxID := base + 3*(rounds-1) + 2; maxID > MaxMessageID {
		return fmt.Errorf("ldap: message id %d exceeds 0x7FFF", maxID)
	}
	return nil
}

// --- BER encoding (reference-pcap-derived; see design_ldap.md §3) ---

// berInt encodes an INTEGER with minimal byte count, prepending a zero byte
// when the top bit would otherwise be a sign bit.
func berInt(n int) []byte {
	if n < 0 {
		n = 0
	}
	var body []byte
	for tmp := n; tmp > 0; tmp >>= 8 {
		body = append([]byte{byte(tmp)}, body...)
	}
	if len(body) == 0 {
		body = []byte{0}
	}
	if body[0]&0x80 != 0 {
		body = append([]byte{0x00}, body...)
	}
	return append([]byte{tagInteger, byte(len(body))}, body...)
}

// berWrap encodes a constructed value. The reference pcap (Active Directory
// client) uses the 0x84+4-byte long form for every constructed value — even
// when the content fits short form — so we mirror that for deterministic
// wire bytes.
func berWrap(tag byte, content []byte) []byte {
	out := make([]byte, 0, 6+len(content))
	out = append(out, tag, 0x84, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(out[2:6], uint32(len(content)))
	return append(out, content...)
}

// berPrim encodes a primitive value with minimal length: short form below
// 128 bytes, 0x84 long form beyond (reference encoder behavior).
func berPrim(tag byte, content []byte) []byte {
	out := make([]byte, 0, 2+len(content))
	if len(content) < 128 {
		out = append(out, tag, byte(len(content)))
	} else {
		out = append(out, tag, 0x84, 0, 0, 0, 0)
		binary.BigEndian.PutUint32(out[2:6], uint32(len(content)))
	}
	return append(out, content...)
}

func berOctet(s string) []byte     { return berPrim(tagOctetString, []byte(s)) }
func berEnum(n int) []byte         { return berPrim(tagEnumerated, []byte{byte(n)}) }
func berBoolFalse() []byte         { return []byte{tagBoolean, 1, 0x00} }

// --- message builders (design_ldap.md §4) ---

// buildLDAPMessage wraps a protocolOp into an LDAPMessage (RFC 4511
// §4.1.1): SEQUENCE { messageID INTEGER, protocolOp }.
func buildLDAPMessage(mid int, opTag byte, opContent []byte) []byte {
	body := append(berInt(mid), berWrap(opTag, opContent)...)
	return berWrap(0x30, body)
}

// ldapResult is the LDAPResult SEQUENCE body (RFC 4511 §4.1.9): resultCode
// ENUMERATED + matchedDN LDAPDN + diagnosticMessage.
func ldapResult(cfg *core.LDAPConfig) []byte {
	out := berEnum(int(cfg.ResultCode))
	out = append(out, berOctet("")...)
	out = append(out, berOctet("")...)
	return out
}

// versionOf returns the effective LDAP version (default 3).
func versionOf(cfg *core.LDAPConfig) int {
	if cfg.Version != 0 {
		return cfg.Version
	}
	return 3
}

// attributesOf returns the searchRequest AttributeSelection. nil (field
// absent in JSON) defaults to the reference pcap's 15 RootDSE attributes;
// an explicitly empty slice requests no attributes.
func attributesOf(cfg *core.LDAPConfig) []string {
	if cfg.Attributes == nil {
		return defaultAttributes
	}
	return cfg.Attributes
}

// buildBindRequest encodes a bindRequest (RFC 4511 §4.2.1): version
// INTEGER + name LDAPDN + simple [0] authentication. SASL is not modeled
// (the reference pcap's GSS-API messages are Kerberos ciphertext).
func buildBindRequest(mid int, cfg *core.LDAPConfig) []byte {
	content := berInt(versionOf(cfg))
	content = append(content, berOctet(cfg.BindDN)...)
	content = append(content, berPrim(tagSimpleAuth, []byte(cfg.BindPassword))...)
	return buildLDAPMessage(mid, opBindRequest, content)
}

// buildBindResponse encodes a bindResponse (RFC 4511 §4.2.2): LDAPResult.
func buildBindResponse(mid int, cfg *core.LDAPConfig) []byte {
	return buildLDAPMessage(mid, opBindResponse, ldapResult(cfg))
}

// buildFilter encodes the RFC 4511 §4.5.1.7 Filter CHOICE: present [7]
// (default, reference pcap) or equalityMatch [3]. equalityMatch is an
// implicit-tagged AttributeValueAssertion, so its content is the
// attributeDescription + assertionValue OCTET STRINGs directly (no
// nested SEQUENCE).
func buildFilter(cfg *core.LDAPConfig) []byte {
	name := cfg.SearchFilter
	if name == "" {
		name = "objectclass"
	}
	if cfg.FilterType == "equality" {
		assertion := append(berOctet(name), berOctet(cfg.FilterValue)...)
		return berWrap(tagEquality, assertion)
	}
	return berPrim(tagPresent, []byte(name))
}

// buildSearchRequest encodes a searchRequest (RFC 4511 §4.5.1):
// baseObject + scope + derefAliases + sizeLimit + timeLimit + typesOnly +
// filter + attributes.
func buildSearchRequest(mid int, cfg *core.LDAPConfig) []byte {
	content := berOctet(cfg.SearchBaseDN)
	content = append(content, berEnum(cfg.SearchScope)...)
	content = append(content, berEnum(0)...) // derefAliases: neverDerefAliases
	content = append(content, berInt(cfg.SizeLimit)...)
	content = append(content, berInt(cfg.TimeLimit)...)
	content = append(content, berBoolFalse()...) // typesOnly
	content = append(content, buildFilter(cfg)...)
	attrs := make([]byte, 0, 64)
	for _, name := range attributesOf(cfg) {
		attrs = append(attrs, berOctet(name)...)
	}
	content = append(content, berWrap(0x30, attrs)...)
	return buildLDAPMessage(mid, opSearchRequest, content)
}

// buildSearchResEntry encodes a searchResEntry (RFC 4511 §4.5.2):
// objectName + PartialAttributeList. Each requested attribute gets one
// PartialAttribute whose value is the attribute name itself (deterministic
// synthetic data).
func buildSearchResEntry(mid int, cfg *core.LDAPConfig) []byte {
	partials := make([]byte, 0, 64)
	for _, name := range attributesOf(cfg) {
		partial := append(berOctet(name), berWrap(0x31, berOctet(name))...)
		partials = append(partials, berWrap(0x30, partial)...)
	}
	content := berOctet(cfg.SearchBaseDN)
	content = append(content, berWrap(0x30, partials)...)
	return buildLDAPMessage(mid, opSearchEntry, content)
}

// buildSearchResDone encodes a searchResDone (RFC 4511 §4.5.3): LDAPResult.
func buildSearchResDone(mid int, cfg *core.LDAPConfig) []byte {
	return buildLDAPMessage(mid, opSearchDone, ldapResult(cfg))
}

// buildUnbind encodes an unbindRequest (RFC 4511 §4.3): the op is the
// literal NULL bytes 42 00 (reference pcap: ... 09 81 42 00).
func buildUnbind(mid int) []byte {
	body := append(berInt(mid), 0x42, 0x00)
	return berWrap(0x30, body)
}

// --- Plan ---

// Plan generates packet configs for an LDAP flow: one TCP session with a
// SYN/SYN-ACK/ACK handshake, Rounds bind/search exchanges, an optional
// final unbindRequest, then a 4-way FIN teardown. Each LDAP message is
// emitted as PSH-ACK data segments (MSS-sized).
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	cfg := spec.LDAP

	// Apply defaults here too: Validate sees a value copy, so defaults
	// applied there are lost for Plan.
	if spec.DstPort == 0 {
		spec.DstPort = DefaultPort
	}
	rounds := cfg.Rounds
	if rounds <= 0 {
		rounds = 1
	}
	base := int(cfg.MessageIDBase)
	if base == 0 {
		base = 1
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

		// Random ISN per RFC 6528. User can override the client ISN via
		// spec.TCP.InitialSeq for reproducible tests.
		clientSeq := uint32(0)
		if spec.TCP != nil {
			clientSeq = spec.TCP.InitialSeq
		}
		if clientSeq == 0 {
			clientSeq = randomUint32()
		}
		serverSeq := randomUint32()

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
					EtherType: core.EtherTypeFor(spec.SrcIP),
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

		// emitData segments payload by MSS and emits each chunk as a
		// PSH-ACK in the given direction, advancing the sender's seq.
		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) uint32 {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, tcpPSHACK, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		// --- TCP handshake (SYN, SYN-ACK, ACK) ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, tcpSYN, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, tcpSYNACK, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, tcpACK, nil)

		// --- signaling exchanges (design_ldap.md §7.2) ---
		for r := 0; r < rounds; r++ {
			rb := base + 3*r
			// bindRequest (up) → bindResponse (down)
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, buildBindRequest(rb, cfg))
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, buildBindResponse(rb, cfg))
			// searchRequest (up) → searchResEntry + searchResDone (down)
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, buildSearchRequest(rb+1, cfg))
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, buildSearchResEntry(rb+1, cfg))
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, buildSearchResDone(rb+1, cfg))
		}

		// unbindRequest once after the last round (reference pcap: single
		// unbind at session end).
		if cfg.Unbind == nil || *cfg.Unbind {
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, buildUnbind(base+3*(rounds-1)+2))
		}

		// --- TCP teardown (FIN-ACK, ACK, FIN-ACK, ACK) ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, tcpFINACK, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, tcpACK, nil)
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, tcpFINACK, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, tcpACK, nil)
	}()

	return configChan, nil
}

// segmentByMSS splits a payload into MSS-sized chunks (RFC 879). An empty
// payload yields a single empty chunk. Mirrors internal/protocol/rtsp.
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
// SACK-Permitted. Mirrors internal/protocol/rtsp.synOptions.
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

// randomIPID returns a random 16-bit IP identification seed.
func randomIPID() uint16 {
	b, err := randomBytes(2)
	if err != nil {
		return 0x1234
	}
	return binary.BigEndian.Uint16(b)
}

// randomUint32 returns a random uint32 (crypto/rand; deterministic fallback
// on the practically impossible failure path).
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
