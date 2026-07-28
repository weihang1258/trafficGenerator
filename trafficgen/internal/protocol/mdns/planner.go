// Package mdns implements the mDNS (Multicast DNS, 多播 DNS) protocol planner
// (RFC 6762, RFC 6763). mDNS is a service discovery protocol that uses
// standard DNS wire format over UDP multicast (port 5353, 224.0.0.251/ff02::fb).
package mdns

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

// mDNS constants (mDNS 常量).
const (
	DefaultTTL = 4500 // Default TTL in seconds (RR TTL, 默认 TTL 秒数)

	// mDNS well-known ports (mDNS 知名端口).
	MDNSPort = 5353

	// Multicast (多播) addresses.
	MulticastIPv4 = "224.0.0.251"
	MulticastIPv6 = "ff02::fb"

	// Multicast (多播) MAC addresses.
	MulticastMACIPv4 = "01:00:5E:00:00:FB"
	MulticastMACIPv6 = "33:33:00:00:00:FB"

	// DNS header flags (DNS 头部标志).
	FlagQuery uint16 = 0x0000 // QR=0, OP=0, AA=0, TC=0, RD=0, RA=0, RCODE=0
	FlagResponse uint16 = 0x8400 // QR=1, OP=0, AA=1, TC=0, RD=0, RA=0, RCODE=0

	// Cache-flush (缓存刷新) bit: OR with class.
	CacheFlushBit = uint16(0x8000)

	// Class IN (Internet, 互联网).
	ClassIN = uint16(1)

	// Default values (默认值).
	DefaultProbingRepeat = 3
	DefaultProbingInterval = 250 // ms
	DefaultProbingJitterMax = 250 // ms
	DefaultAnnouncingRepeat = 2
	DefaultAnnouncingInterval = 1000 // ms
	DefaultResponseDelayMin = 20 // ms
	DefaultResponseDelayMax = 120 // ms

	// Max TTL per RFC 6762 (最大 TTL 值).
	MaxTTL = uint32(2147483647) // 2^31-1

	// Max label length per RFC 1035 §3.1 (最大标签长度).
	MaxLabelLen = 63

	// Max QName encoded length (最大 QName 编码长度).
	MaxQNameLen = 255

	// Max TXT entry length (最大 TXT entry 长度).
	MaxTXTEntryLen = 255

	// Max ProbingJitterMax per RFC 6762 §8.1 (最大抖动).
	MaxProbingJitterMax = 250

	// IPv4 multicast MAC prefix (IPv4 多播 MAC 前缀).
	// 01:00:5E + lower 23 bits of 224.0.0.251 = 01:00:5E:00:00:FB
	// IPv6 multicast MAC prefix (IPv6 多播 MAC 前缀).
	// 33:33 + lower 32 bits of ff02::fb = 33:33:00:00:00:FB
)

// RR type constants (RR 类型常量).
const (
	TypeA = 1
	TypeAAAA = 28
	TypeCNAME = 5
	TypePTR = 12
	TypeSRV = 33
	TypeTXT = 16
	TypeANY = 255
	TypeNSEC = 47
)

// Planner implements the mDNS protocol planner.
type Planner struct{}

// NewPlanner creates a new mDNS planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "mdns" }

// Validate validates an mDNS flow spec. Read-only: never modifies spec.
// Default-value filling happens in Plan(), not here.
func (p *Planner) Validate(spec core.FlowSpec) error {
	// Validate IP addresses (校验 IP 地址).
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("mdns: invalid source IP: %s", spec.SrcIP)
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("mdns: invalid destination IP: %s", spec.DstIP)
	}

	// Check source IP vs multicast group consistency (检查源 IP 与多播组一致性).
	if spec.SrcIP != "" && spec.DstIP != "" {
		srcIsV4 := net.ParseIP(spec.SrcIP).To4() != nil
		dstIsV4 := net.ParseIP(spec.DstIP).To4() != nil
		if srcIsV4 != dstIsV4 {
			return fmt.Errorf("mdns: source IP (%s) and destination IP (%s) must be same IP version", spec.SrcIP, spec.DstIP)
		}
	}

	// Port validation (端口校验): all modes must use 5353 per RFC 6762 §5.4.
	if spec.SrcPort != 0 && spec.SrcPort != MDNSPort {
		return fmt.Errorf("mdns: source port must be %d (RFC 6762 §5.4)", MDNSPort)
	}
	if spec.DstPort != 0 && spec.DstPort != MDNSPort {
		return fmt.Errorf("mdns: destination port must be %d, not %d (RFC 6762 §5.4)", MDNSPort, spec.DstPort)
	}

	// If MDNS config is nil, that's fine — defaults will be used (如果 MDNS 配置为 nil 则使用默认值).
	if spec.MDNS == nil {
		return nil
	}
	m := spec.MDNS

	// Validate mode (校验模式).
	mode := m.Mode
	if mode == "" {
		mode = "query"
	}
	switch mode {
	case "query", "response", "probe", "announce", "goodbye":
		// valid
	default:
		return fmt.Errorf("mdns: unknown mode %q (must be query/response/probe/announce/goodbye)", m.Mode)
	}

	// Mode-specific validations (模式特定校验).
	switch mode {
	case "query", "probe":
		if len(m.Questions) == 0 {
			return fmt.Errorf("mdns: %s mode requires at least one question", mode)
		}
	case "response":
		if len(m.Answers) == 0 {
			return fmt.Errorf("mdns: response mode requires at least one answer")
		}
	case "announce":
		if len(m.Answers) == 0 {
			return fmt.Errorf("mdns: announce mode requires at least one answer")
		}
	case "goodbye":
		if len(m.Answers) == 0 {
			return fmt.Errorf("mdns: goodbye mode requires at least one answer")
		}
	}

	// Validate questions (校验问题).
	for i, q := range m.Questions {
		if q.Name != "" && strings.HasPrefix(q.Name, ".") {
			return fmt.Errorf("mdns: Questions[%d].Name %q has leading dot", i, q.Name)
		}
		if q.Name != "" {
			if err := validateQName(q.Name); err != nil {
				return fmt.Errorf("mdns: Questions[%d].Name %q: %w", i, q.Name, err)
			}
		}
		if q.Type == 0 {
			return fmt.Errorf("mdns: Questions[%d].Type is 0 (invalid)", i)
		}
		if q.Type == 65535 {
			// ANY (255=ANY is the real ANY; 65535 is META) - treat as valid
		} else if q.Type > 65534 {
			return fmt.Errorf("mdns: Questions[%d].Type %d is unknown", i, q.Type)
		} else if q.Type >= 65281 && q.Type <= 65534 {
			// Reserved QTYPE range per IANA (保留 QTYPE 范围, 65281-65534)
			return fmt.Errorf("mdns: Questions[%d].Type %d is reserved", i, q.Type)
		}
		if q.Class != 0 && q.Class != 1 && q.Class != 0x8000 && q.Class != 0x8001 {
			if q.Class == 3 {
				return fmt.Errorf("mdns: Questions[%d].Class %d (CH) is not supported in mDNS, only IN (class 1)", i, q.Class)
			}
			return fmt.Errorf("mdns: Questions[%d].Class %d is not supported in mDNS, only IN (class 1)", i, q.Class)
		}
	}

	// Validate answers (校验回答).
	for i, rr := range m.Answers {
		if err := validateRR(i, rr, "Answers"); err != nil {
			return err
		}
	}

	// Validate authorities (校验权威).
	for i, rr := range m.Authorities {
		if err := validateRR(i, rr, "Authorities"); err != nil {
			return err
		}
	}

	// Validate additionals (校验附加).
	for i, rr := range m.Additionals {
		if err := validateRR(i, rr, "Additionals"); err != nil {
			return err
		}
	}

	// Validate probing parameters (校验探测参数).
	if m.ProbingJitterMax > MaxProbingJitterMax {
		return fmt.Errorf("mdns: ProbingJitterMax %d exceeds max %d (RFC 6762 §8.1)", m.ProbingJitterMax, MaxProbingJitterMax)
	}
	if m.ProbingJitterMax < 0 {
		return fmt.Errorf("mdns: ProbingJitterMax must be non-negative")
	}

	// Validate MulticastGroup (校验多播组).
	if m.MulticastGroup != "" {
		if err := validateMulticastGroup(m.MulticastGroup, spec.SrcIP); err != nil {
			return err
		}
	}

	// TC bit only valid in response modes (TC 位仅对响应模式有效).
	if m.TC && mode != "response" && mode != "announce" && mode != "goodbye" {
		return fmt.Errorf("mdns: TC bit only valid in response modes")
	}

	return nil
}

// validateRR validates a single resource record (校验单个资源记录).
func validateRR(idx int, rr core.MDNSResourceRecord, section string) error {
	if rr.Name != "" && strings.HasPrefix(rr.Name, ".") {
		return fmt.Errorf("mdns: %s[%d].Name %q has leading dot", section, idx, rr.Name)
	}
	if rr.Name != "" {
		if err := validateQName(rr.Name); err != nil {
			return fmt.Errorf("mdns: %s[%d].Name %q: %w", section, idx, rr.Name, err)
		}
	}
	if rr.Type == 0 {
		return fmt.Errorf("mdns: %s[%d].Type is 0 (invalid)", section, idx)
	}
	if rr.Type == 65535 {
		// ANY is valid but not typical in answers
	} else if rr.Type > 65534 {
		return fmt.Errorf("mdns: %s[%d].Type %d is unknown", section, idx, rr.Type)
	}
	if rr.TTL > MaxTTL {
		return fmt.Errorf("mdns: %s[%d].TTL %d exceeds max %d", section, idx, rr.TTL, MaxTTL)
	}

	// Validate RDATA per type (按类型校验 RDATA).
	switch rr.Type {
	case TypeA, TypeAAAA:
		if rr.IPAddress == "" {
			return fmt.Errorf("mdns: %s[%d] A/AAAA record requires IPAddress", section, idx)
		}
		ip := net.ParseIP(rr.IPAddress)
		if ip == nil {
			return fmt.Errorf("mdns: %s[%d] invalid IP address %q", section, idx, rr.IPAddress)
		}
		if rr.Type == TypeA && ip.To4() == nil {
			return fmt.Errorf("mdns: %s[%d] A record requires IPv4 address, got %q", section, idx, rr.IPAddress)
		}
		if rr.Type == TypeAAAA && ip.To4() != nil {
			return fmt.Errorf("mdns: %s[%d] AAAA record requires IPv6 address, got %q", section, idx, rr.IPAddress)
		}
	case TypePTR, TypeCNAME:
		// DomainName is optional for PTR/CNAME - check if empty
		// (empty is allowed for some edge cases)
	case TypeSRV:
		if rr.Target == "" {
			return fmt.Errorf("mdns: %s[%d] SRV record requires Target", section, idx)
		}
		if err := validateQName(rr.Target); err != nil {
			return fmt.Errorf("mdns: %s[%d] SRV Target %q: %w", section, idx, rr.Target, err)
		}
	case TypeTXT:
		for j, entry := range rr.TXTEntries {
			if len(entry) > MaxTXTEntryLen {
				return fmt.Errorf("mdns: %s[%d] TXTEntries[%d] exceeds %d bytes", section, idx, j, MaxTXTEntryLen)
			}
		}
	case TypeNSEC:
		if rr.RawRDATA != nil {
			// RawRDATA overrides typed fields, pass through
			break
		}
		if rr.NSECNextName == "" {
			return fmt.Errorf("mdns: %s[%d] NSEC record requires NSECNextName", section, idx)
		}
		if len(rr.NSECTypes) == 0 {
			return fmt.Errorf("mdns: %s[%d] NSEC record requires non-empty NSECTypes", section, idx)
		}
		// Validate NSEC types (校验 NSEC 类型).
		seen := make(map[uint16]bool)
		for _, t := range rr.NSECTypes {
			if t == 0 || t > 65535 {
				return fmt.Errorf("mdns: %s[%d] NSECTypes contains invalid type %d", section, idx, t)
			}
			seen[t] = true
		}
		// Check for duplicates (检查重复).
		if len(seen) != len(rr.NSECTypes) {
			// Warn but accept (重复 type 会被去重).
		}
	}

	return nil
}

// validateQName validates a domain name for QName encoding (校验 QName 域名编码).
// The root name "." is a valid QName representing the root zone (根域).
func validateQName(name string) error {
	if name == "" {
		return fmt.Errorf("empty qname")
	}
	// The root name "." is a valid QName (encoding: single 0x00 byte).
	if name == "." {
		return nil
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("leading dot in qname")
	}
	labels := splitLabels(name)
	totalLen := 0
	for _, label := range labels {
		if len(label) > MaxLabelLen {
			return fmt.Errorf("label length %d exceeds %d", len(label), MaxLabelLen)
		}
		totalLen += 1 + len(label) // length prefix + label bytes
	}
	totalLen += 1 // null terminator
	if totalLen > MaxQNameLen {
		return fmt.Errorf("qname total length exceeds %d", MaxQNameLen)
	}
	return nil
}

// validateMulticastGroup validates the multicast group (校验多播组).
func validateMulticastGroup(group, srcIP string) error {
	parsed := net.ParseIP(group)
	if parsed == nil {
		return fmt.Errorf("mdns: invalid multicast group %q", group)
	}
	if parsed.To4() != nil {
		// IPv4: must be 224.0.0.251 for mDNS
		if group != MulticastIPv4 {
			return fmt.Errorf("mdns: non-mDNS multicast group %q (must be %s)", group, MulticastIPv4)
		}
		if srcIP != "" {
			src := net.ParseIP(srcIP)
			if src != nil && src.To4() == nil {
				return fmt.Errorf("mdns: IPv6 source %s with IPv4 multicast group %s", srcIP, group)
			}
		}
	} else {
		// IPv6: must be ff02::fb for mDNS
		if group != MulticastIPv6 {
			return fmt.Errorf("mdns: non-mDNS multicast group %q (must be %s)", group, MulticastIPv6)
		}
		if srcIP != "" {
			src := net.ParseIP(srcIP)
			if src != nil && src.To4() != nil {
				return fmt.Errorf("mdns: IPv4 source %s with IPv6 multicast group %s", srcIP, group)
			}
		}
	}
	return nil
}

// Plan generates packet configs for an mDNS flow. Returns a channel that
// yields PacketConfig values in wire order. The channel is closed when
// generation completes or when ctx is cancelled.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	out := make(chan core.PacketConfig, 256)

	go func() {
		defer close(out)

		m := spec.MDNS
		if m == nil {
			m = &core.MDNSConfig{}
		}

		// Effective defaults (有效默认值).
		mode := m.Mode
		if mode == "" {
			mode = "query"
		}

		// Default TTL (默认 TTL).
		defaultTTL := m.DefaultTTL
		if defaultTTL == 0 {
			defaultTTL = DefaultTTL
		}

		// Resolve multicast destination (解析多播目标地址).
		isIPv6 := false
		if spec.SrcIP != "" {
			isIPv6 = net.ParseIP(spec.SrcIP).To4() == nil
		}
		dstIP := m.MulticastGroup
		if dstIP == "" {
			if isIPv6 {
				dstIP = MulticastIPv6
			} else {
				dstIP = MulticastIPv4
			}
		}
		dstMAC := multicastDstMAC(dstIP)

		// Effective TTL (有效 TTL): mDNS requires TTL=255 (RFC 6762 §11).
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 || effectiveTTL != 255 {
			effectiveTTL = 255
		}

		// Effective ports (有效端口): mDNS requires port 5353.
		srcPort := spec.SrcPort
		if srcPort == 0 {
			srcPort = MDNSPort
		}
		dstPort := spec.DstPort
		if dstPort == 0 {
			dstPort = MDNSPort
		}

		// Flow ID (流 ID).
		flowID := fmt.Sprintf("%s-%s-%d-%d-%d", spec.SrcIP, dstIP, srcPort, dstPort, time.Now().UnixNano())

		// IP ID (IP 标识).
		ipID := uint16(rand.Uint32())
		packetIndex := uint64(0)
		now := time.Now()

		// Determine repeat count and interval (确定重复次数和间隔).
		var repeatCount int
		var intervalMs int
		var jitterMax int
		var jitterSeed int64
		var payLoadFunc func() []byte
		forceTTL0 := false
		var cacheFlush bool

		switch mode {
		case "query":
			repeatCount = 1
			intervalMs = 0
			payLoadFunc = func() []byte {
				return buildMDNSMessage(m, mode, false, defaultTTL)
			}
		case "response":
			repeatCount = 1
			intervalMs = m.ResponseDelay
			payLoadFunc = func() []byte {
				return buildMDNSMessage(m, mode, false, defaultTTL)
			}
		case "probe":
			repeatCount = m.ProbingRepeat
			if repeatCount == 0 {
				repeatCount = DefaultProbingRepeat
			}
			intervalMs = m.ProbingInterval
			if intervalMs == 0 {
				intervalMs = DefaultProbingInterval
			}
			jitterMax = m.ProbingJitterMax
			jitterSeed = m.ProbingJitterSeed
			payLoadFunc = func() []byte {
				return buildMDNSMessage(m, mode, false, defaultTTL)
			}
		case "announce":
			repeatCount = m.AnnouncingRepeat
			if repeatCount == 0 {
				repeatCount = DefaultAnnouncingRepeat
			}
			intervalMs = m.AnnouncingInterval
			if intervalMs == 0 {
				intervalMs = DefaultAnnouncingInterval
			}
			payLoadFunc = func() []byte {
				return buildMDNSMessage(m, mode, false, defaultTTL)
			}
		case "goodbye":
			repeatCount = 1
			intervalMs = 0
			forceTTL0 = true
			payLoadFunc = func() []byte {
				return buildMDNSMessage(m, mode, true, defaultTTL)
			}
		}
		_ = forceTTL0 // forceTTL0 is passed into buildMDNSMessage via payLoadFunc closure

		// Determine cache-flush (确定缓存刷新).
		if m.CacheFlush != nil {
			cacheFlush = *m.CacheFlush
		} else {
			switch mode {
			case "announce", "goodbye":
				cacheFlush = true
			default:
				cacheFlush = false
			}
		}

		// Build the payload once for non-probe modes (对非探测模式预构建负载).
		// For probe mode, we rebuild each time because the message is the same
		// but we need to handle the cache-flush per spec.
		_ = cacheFlush // Used by buildMDNSMessage via m.CacheFlush

		// Create a random source for jitter if needed (创建抖动随机源).
		var rng *rand.Rand
		if jitterSeed != 0 {
			rng = rand.New(rand.NewSource(jitterSeed))
		}

		// Emit packets (发送数据包).
		for i := 0; i < repeatCount; i++ {
			// Check context cancellation before each packet (在发送每个数据包前检查上下文取消).
			select {
			case <-ctx.Done():
				return
			default:
			}

			packetTime := now
			if intervalMs > 0 && i > 0 {
				jitter := 0
				if jitterMax > 0 {
					if rng != nil {
						jitter = rng.Intn(jitterMax + 1)
					} else {
						jitter = rand.Intn(jitterMax + 1)
					}
				}
				delay := time.Duration(intervalMs+jitter) * time.Millisecond
				packetTime = now.Add(delay)
				// Context-aware sleep (上下文感知睡眠). Sleep for the delay duration
				// but exit early if the context is cancelled.
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return
				}
				timer.Stop()
			} else if mode == "response" && intervalMs > 0 {
				// Response delay (响应延迟).
				delay := time.Duration(intervalMs) * time.Millisecond
				packetTime = now.Add(delay)
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return
				}
				timer.Stop()
			}

			payload := payLoadFunc()

			cfg := core.PacketConfig{
				FlowID: flowID,
				PacketIndex: packetIndex,
				Direction: "up",
				Timestamp: packetTime,
				L2: core.L2Config{
					SrcMAC: spec.SrcMAC,
					DstMAC: dstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3: core.L3Base(spec.SrcIP, dstIP, 17, effectiveTTL, ipID, spec),
				L4: core.L4Config{
					Protocol: "udp",
					SrcPort: srcPort,
					DstPort: dstPort,
				},
				Payload: payload,
			}

			// Handle GroupID (处理 GroupID).
			if spec.GroupID != nil && spec.GroupID.Strategy != "" {
				if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
					cfg.Metadata = map[string]interface{}{"group_id": g}
				}
			}

			select {
			case out <- cfg:
				packetIndex++
				ipID++
				now = packetTime
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, nil
}

// buildMDNSMessage constructs the complete mDNS binary message (构建完整的 mDNS 二进制消息).
func buildMDNSMessage(m *core.MDNSConfig, mode string, forceTTL0 bool, defaultTTL uint32) []byte {
	// Determine flags (确定标志).
	flags := FlagQuery
	isResponse := false
	switch mode {
	case "response", "announce", "goodbye":
		flags = FlagResponse
		isResponse = true
	}

	// Apply TC bit (应用 TC 位).
	if m.TC && isResponse {
		flags |= 0x0200 // TC bit
	}

	// Determine cache-flush (确定缓存刷新).
	cacheFlush := false
	if m.CacheFlush != nil {
		cacheFlush = *m.CacheFlush
	} else {
		switch mode {
		case "announce", "goodbye":
			cacheFlush = true
		}
	}

	// Count sections (统计各节).
	qdCount := uint16(len(m.Questions))
	anCount := uint16(len(m.Answers))
	nsCount := uint16(len(m.Authorities))
	arCount := uint16(len(m.Additionals))

	// DNS header (12 bytes) (DNS 头部, 12 字节).
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x0000) // Transaction ID (事务 ID): MUST be 0
	binary.BigEndian.PutUint16(header[2:4], flags) // Flags (标志)
	binary.BigEndian.PutUint16(header[4:6], qdCount) // QDCOUNT
	binary.BigEndian.PutUint16(header[6:8], anCount) // ANCOUNT
	binary.BigEndian.PutUint16(header[8:10], nsCount) // NSCOUNT
	binary.BigEndian.PutUint16(header[10:12], arCount) // ARCOUNT

	// Build message (构建消息).
	result := make([]byte, 0, 512)
	result = append(result, header...)

	// Question section (问题节).
	for _, q := range m.Questions {
		result = append(result, encodeQName(q.Name)...)
		qtype := make([]byte, 2)
		binary.BigEndian.PutUint16(qtype, q.Type)
		result = append(result, qtype...)

		qclass := q.Class
		if qclass == 0 {
			qclass = ClassIN
		}
		// Apply ForceUnicastResponse (应用强制单播响应).
		if m.ForceUnicastResponse {
			qclass |= CacheFlushBit
		}
		qclassBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(qclassBytes, qclass)
		result = append(result, qclassBytes...)
	}

	// Answer section (回答节).
	for _, rr := range m.Answers {
		result = append(result, encodeResourceRecord(rr, forceTTL0, defaultTTL, cacheFlush)...)
	}

	// Authority section (权威节).
	for _, rr := range m.Authorities {
		result = append(result, encodeResourceRecord(rr, forceTTL0, defaultTTL, cacheFlush)...)
	}

	// Additional section (附加节).
	for _, rr := range m.Additionals {
		result = append(result, encodeResourceRecord(rr, forceTTL0, defaultTTL, cacheFlush)...)
	}

	return result
}

// encodeResourceRecord serializes a single resource record (序列化单个资源记录).
func encodeResourceRecord(rr core.MDNSResourceRecord, forceTTL0 bool, defaultTTL uint32, cacheFlush bool) []byte {
	result := make([]byte, 0, 64)

	// NAME (名字).
	result = append(result, encodeQName(rr.Name)...)

	// TYPE (类型).
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, rr.Type)
	result = append(result, typeBytes...)

	// CLASS (类): apply cache-flush bit (应用缓存刷新位).
	class := rr.Class
	if class == 0 {
		class = ClassIN
	}
	if cacheFlush {
		class |= CacheFlushBit
	}
	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(classBytes, class)
	result = append(result, classBytes...)

	// TTL (生存时间).
	ttl := rr.TTL
	if forceTTL0 {
		ttl = 0
	} else if ttl == 0 {
		ttl = defaultTTL
	}
	ttlBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ttlBytes, ttl)
	result = append(result, ttlBytes...)

	// RDATA (记录数据).
	rdata := encodeRDATA(rr)
	rdLen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLen, uint16(len(rdata)))
	result = append(result, rdLen...)
	result = append(result, rdata...)

	return result
}

// encodeRDATA serializes the RDATA for a resource record (序列化资源记录的 RDATA).
func encodeRDATA(rr core.MDNSResourceRecord) []byte {
	// RawRDATA overrides typed fields (RawRDATA 覆盖类型化字段).
	if rr.RawRDATA != nil {
		return rr.RawRDATA
	}

	switch rr.Type {
	case TypeA:
		ip := net.ParseIP(rr.IPAddress)
		if ip != nil && ip.To4() != nil {
			return []byte(ip.To4())
		}
		return []byte{0, 0, 0, 0}

	case TypeAAAA:
		ip := net.ParseIP(rr.IPAddress)
		if ip != nil && ip.To4() == nil {
			return []byte(ip.To16())
		}
		return make([]byte, 16)

	case TypePTR, TypeCNAME:
		return encodeQName(rr.DomainName)

	case TypeSRV:
		rdata := make([]byte, 0, 12)
		prio := make([]byte, 2)
		binary.BigEndian.PutUint16(prio, rr.Priority)
		rdata = append(rdata, prio...)
		weight := make([]byte, 2)
		binary.BigEndian.PutUint16(weight, rr.Weight)
		rdata = append(rdata, weight...)
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, rr.Port)
		rdata = append(rdata, port...)
		rdata = append(rdata, encodeQName(rr.Target)...)
		return rdata

	case TypeTXT:
		rdata := make([]byte, 0, len(rr.TXTEntries)*64)
		for _, entry := range rr.TXTEntries {
			rdata = append(rdata, byte(len(entry)))
			rdata = append(rdata, []byte(entry)...)
		}
		return rdata

	case TypeNSEC:
		return encodeNSECRDATA(rr)

	default:
		return nil
	}
}

// encodeNSECRDATA serializes NSEC RDATA per RFC 4034 §4 (序列化 NSEC RDATA).
func encodeNSECRDATA(rr core.MDNSResourceRecord) []byte {
	// NSECNextName (QName encoding) (NSEC 下一个域名, QName 编码).
	rdata := encodeQName(rr.NSECNextName)

	// Deduplicate and sort types (去重并排序类型).
	seen := make(map[uint16]bool)
	unique := make([]uint16, 0, len(rr.NSECTypes))
	for _, t := range rr.NSECTypes {
		if !seen[t] {
			seen[t] = true
			unique = append(unique, t)
		}
	}
	// Sort by type (按类型排序).
	for i := 0; i < len(unique); i++ {
		for j := i + 1; j < len(unique); j++ {
			if unique[i] > unique[j] {
				unique[i], unique[j] = unique[j], unique[i]
			}
		}
	}

	// Group by window (按窗口分组).
	// Window N covers types [N*256, N*256+255].
	windowMap := make(map[uint16][]uint16)
	var windows []uint16
	for _, t := range unique {
		w := t / 256
		windowMap[w] = append(windowMap[w], t)
		if len(windows) == 0 || windows[len(windows)-1] != w {
			windows = append(windows, w)
		}
	}
	// Sort windows (排序窗口).
	for i := 0; i < len(windows); i++ {
		for j := i + 1; j < len(windows); j++ {
			if windows[i] > windows[j] {
				windows[i], windows[j] = windows[j], windows[i]
			}
		}
	}

	// Build each window block (构建每个窗口块).
	for _, w := range windows {
		types := windowMap[w]
		// Determine bitmap length (确定位图长度).
		maxType := types[len(types)-1]
		bitmapLen := (maxType%256)/8 + 1
		if bitmapLen < 1 {
			bitmapLen = 1
		}
		if bitmapLen > 32 {
			bitmapLen = 32
		}

		// Build bitmap (构建位图).
		bitmap := make([]byte, bitmapLen)
		for _, t := range types {
			offset := t % 256
			byteIdx := offset / 8
			bitIdx := 7 - (offset % 8)
			if byteIdx < uint16(bitmapLen) {
				bitmap[byteIdx] |= 1 << bitIdx
			}
		}

		// Trim trailing zero bytes (裁剪尾部零字节).
		for bitmapLen > 1 && bitmap[bitmapLen-1] == 0 {
			bitmapLen--
		}
		bitmap = bitmap[:bitmapLen]

		// WindowNumber (窗口号).
		rdata = append(rdata, byte(w))
		// BitmapLength (位图长度).
		rdata = append(rdata, byte(bitmapLen))
		// TypeBitmap (类型位图).
		rdata = append(rdata, bitmap...)
	}

	return rdata
}

// encodeQName encodes a domain name as a DNS QName (编码域名为 DNS QName 格式).
func encodeQName(name string) []byte {
	if name == "" || name == "." {
		return []byte{0}
	}
	result := make([]byte, 0)
	labels := splitLabels(name)
	for _, label := range labels {
		result = append(result, byte(len(label)))
		result = append(result, []byte(label)...)
	}
	result = append(result, 0)
	return result
}

// splitLabels splits a domain name into labels (将域名分割为标签).
func splitLabels(domain string) []string {
	labels := make([]string, 0)
	start := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if i > start {
				labels = append(labels, domain[start:i])
			}
			start = i + 1
		}
	}
	if start < len(domain) {
		labels = append(labels, domain[start:])
	}
	return labels
}

// multicastDstMAC returns the multicast MAC for the given IP (返回给定 IP 的多播 MAC).
func multicastDstMAC(dstIP string) string {
	parsed := net.ParseIP(dstIP)
	if parsed != nil && parsed.To4() == nil {
		return MulticastMACIPv6
	}
	return MulticastMACIPv4
}