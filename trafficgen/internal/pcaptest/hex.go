package pcaptest

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// HexInfo is one frame's parsed hex dump (tshark -x output).
type HexInfo struct {
	FrameNo int
	Bytes   []byte
}

// ParseTsharkHex parses `tshark -x` output. Each frame's hex dump is a series
// of "NNNN  bb bb ...  ascii" lines; a new frame starts when the offset column
// resets to 0000 (or a non-dump line separates frames).
func ParseTsharkHex(out string) []HexInfo {
	var frames []HexInfo
	var cur *HexInfo
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
			// tshark -x appends extra hex blocks after a frame's own dump:
			// dissector extraction labels like "Reassembled TCP (N bytes):"
			// (desegmented payload), "Decompressed Header (N bytes):" (HPACK),
			// "Unchunked RTMP (N bytes):" (RTMP chunk re-assembly) and
			// "NTLMSSP / GSSAPI Data (N bytes):" (HTTP auth token extraction)
			// are each followed by a 0000-prefixed hex block that does NOT
			// represent a new frame. They all share the generic "<text>
			// (N bytes):" label form — match that, not per-dissector prefixes.
			// The packet boundary label "Frame (N bytes):" starts a REAL
			// frame's dump, so it resets (never triggers) the skip.
			if isExtractBlockLabel(trimmed) && !strings.HasPrefix(trimmed, "Frame ") {
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
			frames = append(frames, HexInfo{FrameNo: len(frames) + 1})
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
			cur.Bytes = append(cur.Bytes, byte(b))
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

// isExtractBlockLabel reports whether the line is a dissector extraction
// block label of the generic form "<text> (N bytes):" (N ≥ 0, unit "byte"
// or "bytes"): Reassembled TCP / Decompressed Header / Unchunked RTMP /
// NTLMSSP / GSSAPI Data all share this shape.
func isExtractBlockLabel(s string) bool {
	if !strings.HasSuffix(s, "):") {
		return false
	}
	open := strings.LastIndexByte(s, '(')
	if open < 0 {
		return false
	}
	inner := s[open+1 : len(s)-2] // between "(" and "):"
	sp := strings.IndexByte(inner, ' ')
	if sp <= 0 {
		return false
	}
	num, unit := inner[:sp], inner[sp+1:]
	if unit != "byte" && unit != "bytes" {
		return false
	}
	if num == "" {
		return false
	}
	for i := 0; i < len(num); i++ {
		if num[i] < '0' || num[i] > '9' {
			return false
		}
	}
	return true
}

// HexDumpAll returns one HexInfo per frame in the pcap.
func HexDumpAll(path string, decodeAs []string) ([]HexInfo, error) {
	// Disable TCP desegmentation so each segment appears as its own frame.
	// Without this, tshark -x appends "Reassembled TCP (N bytes)" blocks to
	// frames carrying partial segments; the parser would then treat those
	// 0000-prefixed hex blocks as new frames, shifting every subsequent
	// FrameAssert.Packet index by the number of segmented frames in the flow.
	full := []string{"-r", path, "-x", "-o", "tcp.desegment_tcp_streams:false"}
	for _, d := range decodeAs {
		full = append(full, "-d", d)
	}
	timeout := RunTsharkTimeout
	if v := os.Getenv("PCAPTEST_TSHARK_TIMEOUT_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			timeout = time.Duration(ms) * time.Millisecond
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "tshark", full...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("tshark -x: timed out after %s (dissector hang; killed)", timeout)
		}
		return nil, fmt.Errorf("tshark -x: %v: %s", err, errb.String())
	}
	return ParseTsharkHex(out.String()), nil
}

// ParseHexBytes converts a hex dump string like "02 00 00 00 00 01" or
// "020000000001" into bytes. Spaces/newlines are ignored.
func ParseHexBytes(s string) ([]byte, error) {
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

// MatchHexPrefix reports whether frameBytes starts with the wanted prefix.
// A zero-length wanted prefix matches only the start-of-frame (offset 0).
func MatchHexPrefix(frameBytes, want []byte) (bool, int) {
	if len(want) > len(frameBytes) {
		return false, len(frameBytes)
	}
	for i := range want {
		if frameBytes[i] != want[i] {
			return false, i
		}
	}
	return true, len(want)
}

// MatchHexOffset reports whether frameBytes[offset:] starts with want.
// When want extends past the end of the frame (truncated match), it fails and
// reports the frame length as the mismatch point. Returns (matched, index).
func MatchHexOffset(frameBytes []byte, offset int, want []byte) (bool, int) {
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
