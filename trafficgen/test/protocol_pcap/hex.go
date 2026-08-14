package protocolpcap

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// hexInfo is one frame's parsed hex dump (tshark -x output).
type hexInfo struct {
	frameNo int
	bytes   []byte
}

// parseTsharkHex parses `tshark -x` output. Each frame's hex dump is a series
// of "NNNN  bb bb ...  ascii" lines; a new frame starts when the offset column
// resets to 0000 (or a non-dump line separates frames).
func parseTsharkHex(out string) []hexInfo {
	var frames []hexInfo
	var cur *hexInfo
	var skipUntilNewFrame bool
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			// Blank line is a real frame separator: clear both cur and
			// any pending Reassembled-TCP skip so the next 0000-prefixed
			// hex block is recognized as a new frame.
			cur = nil
			skipUntilNewFrame = false
			continue
		}
		// Non-dump lines (e.g. "Frame 1: ...") separate frames.
		if !isHexDumpLine(trimmed) {
			// "Reassembled TCP (N bytes):" preamble is followed by a 0000-
			// prefixed hex block representing the desegmented payload, NOT a
			// new frame. Skip its hex lines until we see the next real
			// frame separator (blank line or "Frame ...").
			if strings.HasPrefix(trimmed, "Reassembled ") {
				cur = nil
				skipUntilNewFrame = true
				continue
			}
			cur = nil
			skipUntilNewFrame = false
			continue
		}
		if skipUntilNewFrame {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			cur = nil
			continue
		}
		off, err := strconv.ParseUint(fields[0], 16, 32)
		if err != nil {
			cur = nil
			continue
		}
		if off == 0 || cur == nil {
			frames = append(frames, hexInfo{frameNo: len(frames) + 1})
			cur = &frames[len(frames)-1]
		}
		// Parse the hex byte columns. tshark -x lines have exactly 16 byte
		// columns (fewer on the final line) followed by an ASCII gutter. The
		// gutter may contain tokens that look like 2-char hex (e.g. "00" in
		// "00 OK", "2e" in ".0.0"), so counting columns is required -- a
		// length check alone would swallow gutter bytes as frame data.
		n := 0
		for _, f := range fields[1:] {
			if n >= 16 {
				break
			}
			if len(f) != 2 {
				break
			}
			b, err := strconv.ParseUint(f, 16, 8)
			if err != nil {
				break
			}
			cur.bytes = append(cur.bytes, byte(b))
			n++
		}
	}
	return frames
}

func isHexDumpLine(s string) bool {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return false
	}
	// tshark -x offset column: 4 hex digits up to offset 0xffff, 5 digits
	// (00000, 00010, ...) once the frame exceeds 65535 bytes.
	if n := len(fields[0]); n < 4 || n > 5 {
		return false
	}
	if _, err := strconv.ParseUint(fields[0], 16, 32); err != nil {
		return false
	}
	// Only the first data token must look like hex; the ASCII gutter at the
	// end of the line can contain arbitrary characters (e.g. a 2-char "..").
	_, err := strconv.ParseUint(fields[1], 16, 8)
	return err == nil
}

// hexDumpAll returns one hexInfo per frame in the pcap.
func hexDumpAll(path string) ([]hexInfo, error) {
	// Disable TCP desegmentation so each segment appears as its own frame.
	// Without this, tshark -x appends "Reassembled TCP (N bytes)" blocks to
	// frames carrying partial segments; the parser would then treat those
	// 0000-prefixed hex blocks as new frames, shifting every subsequent
	// FrameAssert.Packet index by the number of segmented frames in the flow.
	cmd := exec.Command("tshark", "-r", path, "-x", "-o", "tcp.desegment_tcp_streams:false")
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("tshark -x: %v: %s", err, errb.String())
	}
	return parseTsharkHex(out.String()), nil
}

// parseHexBytes converts a hex dump string like "02 00 00 00 00 01" or
// "020000000001" into bytes. Spaces/newlines are ignored.
func parseHexBytes(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\t' {
			return -1
		}
		return r
	}, s)
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex string length %d", len(s))
	}
	out := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		b, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("bad hex byte %q: %v", s[i:i+2], err)
		}
		out = append(out, byte(b))
	}
	return out, nil
}

// matchHexPrefix reports whether frameBytes starts with the wanted prefix.
// A zero-length wanted prefix matches only the start-of-frame (offset 0).
func matchHexPrefix(frameBytes, want []byte) (bool, int) {
	limit := len(want)
	if limit > len(frameBytes) {
		limit = len(frameBytes)
	}
	for i := 0; i < limit; i++ {
		if frameBytes[i] != want[i] {
			return false, i
		}
	}
	return true, limit
}

// matchHexOffset reports whether frameBytes[offset:] starts with want.
// When want extends past the end of the frame (truncated match), it fails and
// reports the frame length as the mismatch point. Returns (matched, index).
func matchHexOffset(frameBytes []byte, offset int, want []byte) (bool, int) {
	if offset < 0 || offset > len(frameBytes) {
		return false, offset
	}
	// want may be empty, matching an empty range at offset.
	n := 0
	for n < len(want) && offset+n < len(frameBytes) {
		if frameBytes[offset+n] != want[n] {
			return false, offset + n
		}
		n++
	}
	if n < len(want) {
		return false, len(frameBytes) // want extends past frame end
	}
	return true, offset + n
}
