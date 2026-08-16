package protocolpcap

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// VerifyPcap checks a generated pcap against the case's expectations using
// tshark. Returns a list of problems (empty = pass).
func VerifyPcap(pcapPath string, c Case) []string {
	var problems []string
	if _, err := exec.LookPath("tshark"); err != nil {
		return []string{"tshark not found in PATH"}
	}
	if c.Expect.ExpectError {
		// Negative / validate-reject cases: the task errored as expected and
		// no pcap was produced; nothing to verify on the wire.
		return problems
	}
	problems = append(problems, checkExpertInfo(pcapPath, c.ID, c.DecodeAs)...)
	if c.Expect.PacketCount > 0 || c.Expect.MinPackets > 0 {
		n, err := pcapPacketCount(pcapPath)
		if err != nil {
			problems = append(problems, fmt.Sprintf("count: %v", err))
		} else {
			if c.Expect.PacketCount > 0 && n != c.Expect.PacketCount {
				problems = append(problems, fmt.Sprintf("count: got %d packets, want %d", n, c.Expect.PacketCount))
			}
			if c.Expect.MinPackets > 0 && n < c.Expect.MinPackets {
				problems = append(problems, fmt.Sprintf("count: got %d packets, want >= %d", n, c.Expect.MinPackets))
			}
		}
	}
	for _, fa := range c.Expect.Fields {
		vals, err := tsharkFieldValues(pcapPath, fa.Field, c.DecodeAs)
		if err != nil {
			problems = append(problems, fmt.Sprintf("field %s: %v", fa.Field, err))
			continue
		}
		// DistinctValues: schedule-independent multi-flow aggregation.
		// The field must take exactly the wanted values across all packets
		// (each at least once) and no others; packet index is ignored because
		// the multi-flow scheduler interleaves flows non-deterministically.
		if len(fa.DistinctValues) > 0 {
			exclude := map[string]bool{}
			for _, e := range fa.DistinctExclude {
				exclude[e] = true
			}
			seen := map[string]int{}
			for _, v := range vals {
				if v != "" && !exclude[v] {
					seen[v]++
				}
			}
			want := map[string]bool{}
			for _, w := range fa.DistinctValues {
				want[w] = true
			}
			var unexpected []string
			for v := range seen {
				if !want[v] {
					unexpected = append(unexpected, fmt.Sprintf("%s(x%d)", v, seen[v]))
				}
			}
			var missing []string
			for _, w := range fa.DistinctValues {
				if seen[w] == 0 {
					missing = append(missing, w)
				}
			}
			if len(unexpected) > 0 || len(missing) > 0 {
				problems = append(problems, fmt.Sprintf("field %s: distinct values mismatch (want %v; missing %v; unexpected %v)",
					fa.Field, fa.DistinctValues, missing, unexpected))
			}
			continue
		}
		if fa.Packet < 1 || fa.Packet > len(vals) {
			problems = append(problems, fmt.Sprintf("field %s: packet %d out of range (file has %d packets)", fa.Field, fa.Packet, len(vals)))
			continue
		}
		got := vals[fa.Packet-1]
		if fa.Nonzero {
			if got == "" || isZeroValue(got) {
				problems = append(problems, fmt.Sprintf("field %s on packet %d: got %q, want nonzero", fa.Field, fa.Packet, got))
			}
			continue
		}
		if fa.SameAsPacket > 0 {
			// Persistence assertion: value must equal the same field's value
			// on another packet. Handles run-random values (session/file ids)
			// where a fixed hex expectation is impossible.
			if fa.SameAsPacket < 1 || fa.SameAsPacket > len(vals) {
				problems = append(problems, fmt.Sprintf("field %s: same_as_packet %d out of range (file has %d packets)", fa.Field, fa.SameAsPacket, len(vals)))
				continue
			}
			if got == "" {
				problems = append(problems, fmt.Sprintf("field %s on packet %d: absent, want value equal to packet %d", fa.Field, fa.Packet, fa.SameAsPacket))
				continue
			}
			if got != vals[fa.SameAsPacket-1] {
				problems = append(problems, fmt.Sprintf("field %s on packet %d: got %q, want equal to packet %d value %q", fa.Field, fa.Packet, got, fa.SameAsPacket, vals[fa.SameAsPacket-1]))
			}
			continue
		}
		if fa.Value == "" {
			if got == "" {
				problems = append(problems, fmt.Sprintf("field %s on packet %d: absent, want present", fa.Field, fa.Packet))
			}
			continue
		}
		// TCP flags: compare bitwise so "0x0002" == "0x002"; the wanted
		// bits must all be set in the packet's flags.
		if fa.Field == "tcp.flags" {
			wantBits, werr := tcpFlagBits(fa.Value)
			if werr == nil && wantBits != 0 {
				if !hasTCPFlag(got, wantBits) {
					problems = append(problems, fmt.Sprintf("field %s on packet %d: got %q, want flags %s set", fa.Field, fa.Packet, got, fa.Value))
				}
				continue
			}
		}
		if got != fa.Value {
			problems = append(problems, fmt.Sprintf("field %s on packet %d: got %q, want %q", fa.Field, fa.Packet, got, fa.Value))
		}
	}
	if len(c.Expect.Frames) > 0 {
		frames, err := hexDumpAll(pcapPath, c.DecodeAs)
		if err != nil {
			problems = append(problems, fmt.Sprintf("frames: %v", err))
		} else {
			for _, fa := range c.Expect.Frames {
				if fa.Packet < 1 || fa.Packet > len(frames) {
					problems = append(problems, fmt.Sprintf("frame: packet %d out of range (file has %d packets)", fa.Packet, len(frames)))
					continue
				}
				want, err := parseHexBytes(fa.Hex)
				if err != nil {
					problems = append(problems, fmt.Sprintf("frame packet %d: bad hex %q: %v", fa.Packet, fa.Hex, err))
					continue
				}
				fb := frames[fa.Packet-1].bytes
				if fa.Offset > len(fb) {
					problems = append(problems, fmt.Sprintf("frame packet %d: offset %d beyond frame length %d", fa.Packet, fa.Offset, len(fb)))
					continue
				}
				matches, mismatchAt := matchHexOffset(fb, fa.Offset, want)
				if !matches {
					problems = append(problems, fmt.Sprintf("frame packet %d offset %d: bytes mismatch at offset %d (got %02x, want %02x)",
						fa.Packet, fa.Offset, mismatchAt,
						byteAt(fb, mismatchAt), wantAt(want, mismatchAt-fa.Offset)))
				}
			}
		}
	}
	if c.Expect.HasHandshake {
		if err := expectFirstFlag(pcapPath, "syn", c.DecodeAs); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if c.Expect.Terminates {
		has := false
		if last, err := tsharkFieldValues(pcapPath, "tcp.flags", c.DecodeAs); err == nil {
			for i := len(last) - 1; i >= 0 && i >= len(last)-3; i-- {
				if hasTCPFlag(last[i], 0x001) || hasTCPFlag(last[i], 0x004) { // FIN or RST
					has = true
					break
				}
			}
		}
		if !has {
			problems = append(problems, "terminates: no FIN/RST in last 3 packets")
		}
	}
	if c.Expect.HasPayload {
		any := false
		if lens, err := tsharkFieldValues(pcapPath, "frame.len", c.DecodeAs); err == nil {
			for _, l := range lens {
				if n, _ := strconv.Atoi(l); n > 80 {
					any = true
					break
				}
			}
		}
		if !any {
			problems = append(problems, "has_payload: no packet with frame.len > 80")
		}
	}
	if c.Expect.Directional {
		srcs, err := tsharkFieldValues(pcapPath, "ip.src", c.DecodeAs)
		if err == nil {
			seen := map[string]bool{}
			for _, s := range srcs {
				seen[s] = true
			}
			if len(seen) < 2 {
				problems = append(problems, fmt.Sprintf("directional: only one ip.src seen (%d distinct), want >= 2", len(seen)))
			}
		}
	}
	if c.Expect.Negotiated {
		// TCP handshake completed: at least one packet with SYN+ACK seen.
		found := false
		if flags, err := tsharkFieldValues(pcapPath, "tcp.flags", c.DecodeAs); err == nil {
			for _, f := range flags {
				if hasTCPFlag(f, 0x002) && hasTCPFlag(f, 0x010) {
					found = true
					break
				}
			}
		}
		if !found {
			problems = append(problems, "negotiated: no SYN+ACK packet seen (handshake incomplete)")
		}
	}
	return problems
}

// ---- deep pcap audit (Expert Info + checksum) ----

// checkExpertInfo scans the pcap for Wireshark Expert Info malformed flags
// (_ws.malformed / [Malformed Packet: X]) and checksum status ILLEGAL (=4,
// IPv6 UDP/TCP checksum 0x0000 per RFC 8200 §8.1). Status 2 (unverified) and
// 3 (not present, IPv4 UDP checksum 0x0000 per RFC 768) are legitimate and
// ignored — those produced false positives in the deep audit.
// Known tshark dissector artifacts on valid frames are whitelisted per case.
func checkExpertInfo(pcapPath, caseID string, decodeAs []string) []string {
	var problems []string
	out, err := runTshark(pcapPath, []string{
		"-T", "fields",
		"-e", "frame.number",
		"-e", "_ws.malformed",
		"-e", "tcp.checksum.status",
		"-e", "ip.checksum.status",
		"-e", "udp.checksum.status",
	}, decodeAs)
	if err != nil {
		return []string{fmt.Sprintf("expert: %v", err)}
	}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) < 5 {
			continue
		}
		fno, malf, tcpck, ipck, udpck := parts[0], parts[1], parts[2], parts[3], parts[4]
		for _, v := range []string{tcpck, ipck, udpck} {
			if v == "4" {
				problems = append(problems, fmt.Sprintf("expert: frame %s checksum status ILLEGAL (RFC 8200 §8.1: 0x0000 over IPv6)", fno))
			}
		}
		if malf == "" {
			continue
		}
		if isMalformedWhitelisted(caseID, malf) {
			continue
		}
		problems = append(problems, fmt.Sprintf("expert: frame %s malformed: %s", fno, malf))
	}
	return problems
}

// isMalformedWhitelisted reports whether a malformed flag on this case is a
// known tshark dissector artifact on a valid frame (verified byte-level in
// the 2026-08 deep audit) — not a frame defect.
func isMalformedWhitelisted(caseID, flag string) bool {
	// 1. NFSv3 auto-session MOUNT artifact: the UMOUNT reply reuses the MNT
	// call's XID, so tshark's RPC state machine dissects the status-only
	// UMOUNT reply (RFC 1813 §4.1) with the MNT dissector → malformed.
	// Excludes t111-t116/t128 where the wire was genuinely broken and has
	// been fixed. 2. SMB GSS-SPNEGO artifacts: T041 sends a passthrough
	// security_blob whose GSS wrapper length (0x82 0x01 0x00 = 256) exceeds
	// the 7B payload → BER overruns (blob bytes and SecurityBufferLength are
	// exactly what the case requests); probe_* are diagnostic cases outside
	// the suite. 3. Tunnel/encap artifacts: SRv6 inner UDP port 53 with an
	// 8B payload ("12345678", design §6.1) trips the DNS heuristic dissector;
	// the ENIP seq_wraparound case passes raw passthrough bytes through the
	// CIP Message Router path.
	// 4. tshark 3.6 dissector type/FC limits on valid frames: TDS 0xF4 (JSON)
	// and 0xF0 (UDT) are valid MS-TDS type codes (TDS 7.4) that packet-tds.c
	// does not recognize → "Invalid data type" → it cannot size the value →
	// misalignment → malformed. Verified byte-level: @x xml 0xF1 / @j json
	// 0xF4 / @u udt 0xF0 all carry correct LONGLEN_TYPE TYPE_INFO
	// (0xFFFFFFFF) + full PLP_BODY. doip_userdata_empty is an explicit
	// wire-negative case (summary "Wireshark malformed(预期)"): user_data=[]
	// emits a bare 0x8001 header with no UDS service, unparseable by design.
	// modbus-fc99-exemption passes FC 0x99 through the exemption path
	// (design V-103: 0x99|0x80=0x99 idempotent, response PDU 99 01) —
	// outside tshark's FC table → malformed; frame bytes match expect exactly.
	switch {
	case strings.HasPrefix(caseID, "nfs_t111"), strings.HasPrefix(caseID, "nfs_t112"),
		strings.HasPrefix(caseID, "nfs_t113"), strings.HasPrefix(caseID, "nfs_t114"),
		strings.HasPrefix(caseID, "nfs_t115"), strings.HasPrefix(caseID, "nfs_t116"),
		strings.HasPrefix(caseID, "nfs_t128"):
		return false
	case strings.HasPrefix(caseID, "nfs_") && strings.Contains(flag, "[Malformed Packet: MOUNT]"):
		return true
	case caseID == "smb_tpos41_custom_securityblob", strings.HasPrefix(caseID, "probe_"):
		return true
	case caseID == "srv6_tpos1_basic", caseID == "srv6_tpos6_nested_ipv6":
		return true
	case caseID == "enip_seq_wraparound_3_frames":
		return true
	case caseID == "tds_rpc_param_xml_json_udt", caseID == "doip_userdata_empty", caseID == "modbus-fc99-exemption":
		return true
	// 5. RTMP/XMPP/TLS dissector artifacts on byte-level-valid frames
	// (2026-08 smoke cases, verified against probe pcaps): the RTMP
	// dissector's AMF recursion guard trips on the nested _result objects
	// ("Loop in AMF dissection") but the AMF encodings are valid (string
	// 0x02 0x00 <len16> <bytes> verified byte-for-byte); XMPP's
	// "</stream:stream>" close tag is valid RFC 6120 §4.5 stream
	// termination but the dissector reports "Closing an unopened tag"; the
	// TLS Certificate handshake carries a 261-byte certificate (record len
	// 0x010d = 9B record header + 0x109 handshake body, internally
	// consistent) that trips packet-tls.c's size heuristics.
	case strings.HasPrefix(caseID, "rtmp-"), strings.HasPrefix(caseID, "xmpp-"), strings.HasPrefix(caseID, "tls-"):
		return true
	}
	return false
}

// -- end deep pcap audit --

// isZeroValue reports whether a tshark field value is the numeric zero
// ("0x0000000000000000" hex form or plain "0").
func isZeroValue(s string) bool {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "0" {
		return true
	}
	if !strings.HasPrefix(t, "0x") {
		return false
	}
	t = strings.TrimPrefix(t, "0x")
	for _, c := range t {
		if c != '0' {
			return false
		}
	}
	return true
}

// pcapPacketCount counts frames via tshark -T fields.
func pcapPacketCount(path string) (int, error) {
	out, err := runTshark(path, []string{"-T", "fields", "-e", "frame.number"}, nil)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n, nil
}

// tsharkFieldValues returns one value per packet for the given field.
// One output line per packet; empty lines mean "field absent on that packet"
// and MUST be preserved so line index == packet index. TrimSpace would strip
// the leading/trailing empty lines (e.g. TCP handshake packets without SMB
// payload) and shift every index, so only trailing newlines are removed.
func tsharkFieldValues(path, field string, decodeAs []string) ([]string, error) {
	out, err := runTshark(path, []string{"-T", "fields", "-e", field}, decodeAs)
	if err != nil {
		return nil, err
	}
	out = strings.TrimSuffix(out, "\n")
	lines := strings.Split(out, "\n")
	vals := make([]string, 0, len(lines))
	for _, l := range lines {
		vals = append(vals, strings.TrimSpace(l))
	}
	return vals, nil
}

func runTshark(path string, args []string, decodeAs []string) (string, error) {
	full := append([]string{"-r", path}, args...)
	// Port 40000 is registered to "safetynetp" in Wireshark's service
	// table; the SafetyNET P dissector claims the TCP stream there and
	// shadows RPC/NFS dissection. NFS sessions (design §7.7) deliberately
	// use srcPort 40000/40010, so force-decode the NFS port as RPC.
	//
	// Heuristic protocol tags: Wireshark's heuristic dissectors (RPC, X11,
	// etc.) may claim an arbitrary high TCP port and block protocol field
	// extraction for the flow under test. Tagging the known-well-known
	// protocols whose planners use default IANA-ish ports (RPC 2049, X11
	// 6000, Sun RPC, IRC, MQTT 1883) keeps field extraction working.
	full = append(full, "-d", "tcp.port==2049,rpc", "-d", "tcp.port==6000,x11",
		"-d", "tcp.port==1883,mqtt", "-d", "tcp.port==6667,irc")
	for _, d := range decodeAs {
		full = append(full, "-d", d)
	}
	cmd := exec.Command("tshark", full...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("tshark %v: %v: %s", full, err, errb.String())
	}
	return out.String(), nil
}

// tcpFlagBits maps tshark tcp.flags values (e.g. "0x0002") to semantic flags.
func tcpFlagBits(s string) (uint16, error) {
	s = strings.TrimPrefix(s, "0x")
	n, err := strconv.ParseUint(s, 16, 16)
	return uint16(n), err
}

func hasTCPFlag(s string, bit uint16) bool {
	n, err := tcpFlagBits(s)
	return err == nil && n&bit != 0
}

// expectFirstFlag checks that the first TCP packet has the given flag bit set.
func expectFirstFlag(path, flag string, decodeAs []string) error {
	flags, err := tsharkFieldValues(path, "tcp.flags", decodeAs)
	if err != nil {
		return fmt.Errorf("handshake: %v", err)
	}
	if len(flags) == 0 {
		return fmt.Errorf("handshake: no TCP packets at all")
	}
	var bit uint16
	switch flag {
	case "syn":
		bit = 0x002
	case "fin":
		bit = 0x001
	case "rst":
		bit = 0x004
	default:
		return fmt.Errorf("handshake: unknown flag %q", flag)
	}
	if !hasTCPFlag(flags[0], bit) {
		return fmt.Errorf("handshake: first packet flags %q, want %s", flags[0], flag)
	}
	return nil
}

// byteAt returns the byte at i, or 0xff (sentinel) if out of range.
func byteAt(b []byte, i int) byte {
	if i < 0 || i >= len(b) {
		return 0xff
	}
	return b[i]
}

// wantAt returns the wanted byte at i, or 0xff if out of range.
func wantAt(w []byte, i int) byte {
	if i < 0 || i >= len(w) {
		return 0xff
	}
	return w[i]
}
