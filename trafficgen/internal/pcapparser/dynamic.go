package pcapparser

import (
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LayerRecord is the structured view of a single layer within a packet (§17.7),
// produced on demand by ParsePacket for the "view single packet" endpoint. It
// is NOT stored -- it is regenerated each query from the pcap bytes at RawOffset.
type LayerRecord struct {
	// Layer is the layer name: "eth"|"ipv4"|"tcp"|"udp"|"icmp"|"arp"|"dot1q"|...
	Layer string `json:"layer"`
	// Fields holds the layer's field values for display (e.g. src_ip, dst_port,
	// tcp_flags). Values are JSON-friendly (string/int/bool).
	Fields map[string]any `json:"fields"`
	// Offsets maps field name -> absolute byte offset within the frame, for the
	// "view" consumer (full per-layer offsets, vs FlowModel.OffsetLayout which
	// only carries patchable fields).
	Offsets map[string]int `json:"offsets"`
	// Range is the [start,end) byte range of this layer within the frame.
	Range [2]int `json:"range"`
}

// knownExtractFields is the vocabulary of layer field names populateFields can
// emit (extract/extract_bulk 未知字段一次报全的"已知面"，13.30 引申). Any
// requested field outside this set is reported in the response's
// unknown_fields instead of being silently dropped.
var knownExtractFields = map[string]bool{}

func init() {
	for _, f := range []string{
		// eth
		"dst_mac", "src_mac", "ether_type",
		// dot1q
		"vlan_id", "priority", "vlan_tco",
		// ipv4/ipv6
		"src_ip", "dst_ip", "ttl", "protocol", "ip_id", "dscp", "ecn", "hop_limit", "next_header",
		// tcp
		"src_port", "dst_port", "seq", "ack", "window", "flags",
		// udp
		"length",
		// icmp/icmpv6（含内嵌解码面）
		"type", "code", "id", "seq",
		"embedded_src_ip", "embedded_dst_ip", "embedded_protocol", "embedded_src_port", "embedded_dst_port",
		// arp
		"operation", "sender_hw", "sender_ip", "target_hw", "target_ip",
		// dns（自研解码层）
		"txid", "qr", "opcode", "rcode", "qdcount", "ancount", "nscount", "arcount",
		"questions", "answers", "authority", "additionals", "decode_error",
	} {
		knownExtractFields[f] = true
	}
}

// KnownExtractField reports whether name is in the extract field vocabulary.
func KnownExtractField(name string) bool { return knownExtractFields[name] }

// fileCache caches open *os.File handles keyed by pcap path, so ParsePacket
// doesn't re-open the file per call (§13: "pcap handle 缓存"). Files are opened
// read-only and kept open for the engine's lifetime; the OS reclaims them on
// process exit. A mutex guards the map; ReadAt on a *os.File is goroutine-safe
// (no shared file-offset state, kernel handles concurrent pread).
var fileCache = struct {
	mu sync.Mutex
	m  map[string]*os.File
}{m: make(map[string]*os.File)}

// openCached returns a cached read-only handle to path, opening it on first use.
func openCached(path string) (*os.File, error) {
	fileCache.mu.Lock()
	defer fileCache.mu.Unlock()
	if f, ok := fileCache.m[path]; ok {
		return f, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pcap for re-parse: %w", err)
	}
	fileCache.m[path] = f
	return f, nil
}

// CloseCachedFile removes a path from the cache and closes its handle. Called
// when a pcap asset is deleted so its file handle is released.
func CloseCachedFile(path string) {
	fileCache.mu.Lock()
	defer fileCache.mu.Unlock()
	if f, ok := fileCache.m[path]; ok {
		f.Close()
		delete(fileCache.m, path)
	}
}

// ParsePacket re-parses a single packet on demand (§13). It reads `length` bytes
// at `rawOffset` from the pcap file and decodes them with gopacket, returning a
// LayerRecord per layer. linkType comes from PcapAssetModel.LinkType (constant
// per pcap, avoids re-reading the pcap header). Microsecond-level latency.
func ParsePacket(pcapPath string, rawOffset int64, length int, linkType layers.LinkType) ([]LayerRecord, error) {
	if length <= 0 {
		return nil, fmt.Errorf("invalid packet length %d", length)
	}
	// Validate the decoder before touching the file so an unsupported link type
	// fails fast (and a bogus path doesn't surface a confusing file error first).
	decoder, err := decoderForLinkType(linkType)
	if err != nil {
		return nil, err
	}
	f, err := openCached(pcapPath)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, length)
	if _, err := f.ReadAt(buf, rawOffset); err != nil {
		return nil, fmt.Errorf("read packet bytes at %d: %w", rawOffset, err)
	}
	pkt := gopacket.NewPacket(buf, decoder, gopacket.Default)
	return buildLayerRecords(pkt), nil
}

// decoderForLinkType maps a pcap link type to its gopacket first-layer decoder.
// v1 supports Ethernet; other link types are rejected (consistent with Parse).
func decoderForLinkType(lt layers.LinkType) (gopacket.Decoder, error) {
	switch lt {
	case layers.LinkTypeEthernet:
		return layers.LayerTypeEthernet, nil
	default:
		return nil, fmt.Errorf("unsupported link type %d: v1 supports Ethernet only", lt)
	}
}

// buildLayerRecords walks a packet's layers and produces a LayerRecord per
// layer with display fields, per-field offsets, and the layer's byte range.
// DNS（UDP/53/5353）统一走自研解码出 "dns" 层记录（D-PARSE-1 裁定3）：替换
// gopacket 的 DNS 层（大响应/EDNS DecodeFailure 已实测）与 DecodeFailure 层。
func buildLayerRecords(pkt gopacket.Packet) []LayerRecord {
	var records []LayerRecord
	offset := 0
	udpPayload := []byte(nil)
	udpDNSPort := false
	for _, layer := range pkt.Layers() {
		start := offset
		contents := layer.LayerContents()
		end := start + len(contents)
		// 自研 DNS 层替换：gopacket 解码成功（*layers.DNS）或失败
		//（DecodeFailure）都换成自己的记录
		if udpDNSPort {
			if _, isDNS := layer.(*layers.DNS); isDNS || layer.LayerType() == gopacket.LayerTypeDecodeFailure {
				if rec, ok := dnsLayerRecord(udpPayload, start, end); ok {
					records = append(records, rec)
					offset = end
					continue
				}
			}
		}
		rec := LayerRecord{
			Layer:   layerName(layer),
			Fields:  map[string]any{},
			Offsets: map[string]int{},
			Range:   [2]int{start, end},
		}
		populateFields(pkt, &rec, layer, start)
		if udp, ok := layer.(*layers.UDP); ok {
			udpPayload = udp.Payload
			dp, sp := uint16(udp.DstPort), uint16(udp.SrcPort)
			udpDNSPort = dp == 53 || sp == 53 || dp == 5353 || sp == 5353
		}
		records = append(records, rec)
		offset = end
	}
	return records
}

// dnsLayerRecord decodes DNS payload via the self-developed wire decoder into
// a "dns" LayerRecord (字段面与流级 dnsMessageFields 同形).
func dnsLayerRecord(payload []byte, start, end int) (LayerRecord, bool) {
	rec := LayerRecord{
		Layer:   "dns",
		Fields:  map[string]any{},
		Offsets: map[string]int{},
		Range:   [2]int{start, end},
	}
	m, err := decodeDNSWire(payload)
	if err != nil {
		rec.Fields["decode_error"] = err.Error()
		return rec, true
	}
	for k, v := range dnsMessageFields(m) {
		rec.Fields[k] = v
	}
	return rec, true
}

// layerName returns a short display name for a layer.
func layerName(layer gopacket.Layer) string {
	switch layer.(type) {
	case *layers.Ethernet:
		return "eth"
	case *layers.Dot1Q:
		return "dot1q"
	case *layers.IPv4:
		return "ipv4"
	case *layers.IPv6:
		return "ipv6"
	case *layers.TCP:
		return "tcp"
	case *layers.UDP:
		return "udp"
	case *layers.ICMPv4:
		return "icmp"
	case *layers.ARP:
		return "arp"
	default:
		return layer.LayerType().String()
	}
}

// populateFields fills the LayerRecord's Fields and Offsets for display, using
// the same field-offset knowledge as extractOffsetLayout plus the field VALUES
// (for viewing). Offsets are absolute (layer start + field-relative offset).
func populateFields(pkt gopacket.Packet, rec *LayerRecord, layer gopacket.Layer, start int) {
	switch v := layer.(type) {
	case *layers.Ethernet:
		rec.Fields["dst_mac"] = v.DstMAC.String()
		rec.Fields["src_mac"] = v.SrcMAC.String()
		rec.Fields["ether_type"] = fmt.Sprintf("0x%04x", uint16(v.EthernetType))
		rec.Offsets["dst_mac"] = start + 0
		rec.Offsets["src_mac"] = start + 6
	case *layers.Dot1Q:
		rec.Fields["vlan_id"] = v.VLANIdentifier
		rec.Fields["priority"] = v.Priority
		rec.Offsets["vlan_tco"] = start + 0
	case *layers.IPv4:
		rec.Fields["src_ip"] = v.SrcIP.String()
		rec.Fields["dst_ip"] = v.DstIP.String()
		rec.Fields["ttl"] = v.TTL
		rec.Fields["protocol"] = uint8(v.Protocol)
		rec.Fields["ip_id"] = v.Id
		rec.Fields["dscp"] = v.TOS >> 2
		rec.Fields["ecn"] = v.TOS & 0x03
		rec.Offsets["src_ip"] = start + 12
		rec.Offsets["dst_ip"] = start + 16
		rec.Offsets["ttl"] = start + 8
		rec.Offsets["dscp_ecn"] = start + 1
		rec.Offsets["ip_flags_frag"] = start + 6
		rec.Offsets["ip_id"] = start + 4
	case *layers.IPv6:
		rec.Fields["src_ip"] = v.SrcIP.String()
		rec.Fields["dst_ip"] = v.DstIP.String()
		rec.Fields["hop_limit"] = v.HopLimit
		rec.Fields["next_header"] = uint8(v.NextHeader)
		rec.Fields["dscp"] = v.TrafficClass >> 2
		rec.Fields["ecn"] = v.TrafficClass & 0x03
	case *layers.TCP:
		rec.Fields["src_port"] = uint16(v.SrcPort)
		rec.Fields["dst_port"] = uint16(v.DstPort)
		rec.Fields["seq"] = v.Seq
		rec.Fields["ack"] = v.Ack
		rec.Fields["window"] = v.Window
		rec.Fields["flags"] = tcpFlagsString(v)
		rec.Offsets["src_port"] = start + 0
		rec.Offsets["dst_port"] = start + 2
		rec.Offsets["seq"] = start + 4
		rec.Offsets["ack"] = start + 8
		rec.Offsets["window"] = start + 14
		rec.Offsets["tcp_flags"] = start + 13
	case *layers.UDP:
		rec.Fields["src_port"] = uint16(v.SrcPort)
		rec.Fields["dst_port"] = uint16(v.DstPort)
		rec.Fields["length"] = v.Length
		rec.Offsets["src_port"] = start + 0
		rec.Offsets["dst_port"] = start + 2
	case *layers.ICMPv4:
		rec.Fields["type"] = v.TypeCode.Type()
		rec.Fields["code"] = v.TypeCode.Code()
		rec.Fields["id"] = v.Id
		rec.Fields["seq"] = v.Seq
		// 差错报文内嵌原始 IP 头（RFC 792：type 3/5/11/12 载荷=原 IP 头+8B）
		if t := v.TypeCode.Type(); t == 3 || t == 5 || t == 11 || t == 12 {
			if emb := decodeEmbeddedIPv4(v.Payload); emb != nil {
				for k, val := range emb {
					rec.Fields[k] = val
				}
			}
		}
	case *layers.ICMPv6:
		// D-PARSE-1 P0：ICMPv6 字段（此前 get_packet 无 icmpv6 面）
		rec.Fields["type"] = v.TypeCode.Type()
		rec.Fields["code"] = v.TypeCode.Code()
		if echo, ok := pkt.Layer(layers.LayerTypeICMPv6Echo).(*layers.ICMPv6Echo); ok {
			rec.Fields["id"] = echo.Identifier
			rec.Fields["seq"] = echo.SeqNumber
		}
	case *layers.SCTP:
		rec.Fields["src_port"] = uint16(v.SrcPort)
		rec.Fields["dst_port"] = uint16(v.DstPort)
	case *layers.ARP:
		rec.Fields["operation"] = v.Operation
		rec.Fields["sender_hw"] = netHw(v.SourceHwAddress)
		rec.Fields["sender_ip"] = netIPStr(v.SourceProtAddress)
		rec.Fields["target_hw"] = netHw(v.DstHwAddress)
		rec.Fields["target_ip"] = netIPStr(v.DstProtAddress)
	}
}

// decodeEmbeddedIPv4 parses the original IPv4 header embedded in an ICMP
// error message payload (RFC 792 §2: "internet header + 64 bits of original
// data datagram"). Returns nil when the payload is too short. Fields: src_ip,
// dst_ip, protocol, and src_port/dst_port when the embedded L4 is TCP/UDP.
func decodeEmbeddedIPv4(payload []byte) map[string]any {
	if len(payload) < 20 || payload[0]>>4 != 4 {
		return nil
	}
	ihl := int(payload[0]&0x0f) * 4
	if ihl < 20 || len(payload) < ihl {
		return nil
	}
	out := map[string]any{
		"embedded_src_ip": net.IP(payload[12:16]).String(),
		"embedded_dst_ip": net.IP(payload[16:20]).String(),
		"embedded_protocol": payload[9],
	}
	if proto := payload[9]; proto == 6 || proto == 17 {
		if len(payload) >= ihl+4 {
			out["embedded_src_port"] = uint16(payload[ihl])<<8 | uint16(payload[ihl+1])
			out["embedded_dst_port"] = uint16(payload[ihl+2])<<8 | uint16(payload[ihl+3])
		}
	}
	return out
}

// tcpFlagsString renders the TCP flags as a compact string (e.g. "SYN,ACK").
func tcpFlagsString(t *layers.TCP) string {
	var s string
	add := func(set bool, name string) {
		if set {
			if s != "" {
				s += ","
			}
			s += name
		}
	}
	add(t.FIN, "FIN")
	add(t.SYN, "SYN")
	add(t.RST, "RST")
	add(t.PSH, "PSH")
	add(t.ACK, "ACK")
	add(t.URG, "URG")
	if s == "" {
		s = "none"
	}
	return s
}

// netHw renders a raw hardware address byte slice as a MAC string.
func netHw(b []byte) string {
	if len(b) == 6 {
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
	}
	return fmt.Sprintf("%x", b)
}

// netIPStr renders a raw protocol address byte slice (4 or 16 bytes) as an IP.
func netIPStr(b []byte) string {
	switch len(b) {
	case 4, 16:
		// Copy so net.IP doesn't alias the caller's slice; String() formats
		// 4-byte as dotted-quad and 16-byte as IPv6.
		ip := make(net.IP, len(b))
		copy(ip, b)
		return ip.String()
	default:
		return fmt.Sprintf("%x", b)
	}
}
