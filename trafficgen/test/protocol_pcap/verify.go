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
		vals, err := tsharkFieldValues(pcapPath, fa.Field)
		if err != nil {
			problems = append(problems, fmt.Sprintf("field %s: %v", fa.Field, err))
			continue
		}
		if fa.Packet < 1 || fa.Packet > len(vals) {
			problems = append(problems, fmt.Sprintf("field %s: packet %d out of range (file has %d packets)", fa.Field, fa.Packet, len(vals)))
			continue
		}
		got := vals[fa.Packet-1]
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
	if c.Expect.HasHandshake {
		if err := expectFirstFlag(pcapPath, "syn"); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if c.Expect.Terminates {
		has := false
		if last, err := tsharkFieldValues(pcapPath, "tcp.flags"); err == nil {
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
		if lens, err := tsharkFieldValues(pcapPath, "frame.len"); err == nil {
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
		srcs, err := tsharkFieldValues(pcapPath, "ip.src")
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
		if flags, err := tsharkFieldValues(pcapPath, "tcp.flags"); err == nil {
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

// pcapPacketCount counts frames via tshark -T fields.
func pcapPacketCount(path string) (int, error) {
	out, err := runTshark(path, []string{"-T", "fields", "-e", "frame.number"})
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
func tsharkFieldValues(path, field string) ([]string, error) {
	out, err := runTshark(path, []string{"-T", "fields", "-e", field})
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	vals := make([]string, 0, len(lines))
	for _, l := range lines {
		vals = append(vals, strings.TrimSpace(l))
	}
	return vals, nil
}

func runTshark(path string, args []string) (string, error) {
	full := append([]string{"-r", path}, args...)
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
func expectFirstFlag(path, flag string) error {
	flags, err := tsharkFieldValues(path, "tcp.flags")
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
