package rtmfp

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// RTMFP wire format constants.
const (
	MarkerData    byte = 0x0C
	MarkerControl byte = 0x0E

	KindHello          byte = 0x01
	KindHelloAck       byte = 0x02
	KindCookie         byte = 0x03
	KindSessionConfirm byte = 0x04
	KindReliable       byte = 0x05
	KindUnreliable     byte = 0x06
	KindFragment       byte = 0x07
	KindAck            byte = 0x08
	KindPing           byte = 0x09
	KindPong           byte = 0x0A
	KindClose          byte = 0x0B
	KindError          byte = 0x0C

	// HeaderMinLen is the minimum valid RTMFP message header length.
	HeaderMinLen = 16
)

// kindCode maps event kind strings to wire byte codes.
func kindCode(kind string) (byte, error) {
	switch kind {
	case "hello":
		return KindHello, nil
	case "hello_ack":
		return KindHelloAck, nil
	case "cookie":
		return KindCookie, nil
	case "session_confirm":
		return KindSessionConfirm, nil
	case "reliable", "retransmit":
		return KindReliable, nil
	case "unreliable":
		return KindUnreliable, nil
	case "fragment":
		return KindFragment, nil
	case "ack":
		return KindAck, nil
	case "ping":
		return KindPing, nil
	case "pong":
		return KindPong, nil
	case "close":
		return KindClose, nil
	case "error":
		return KindError, nil
	default:
		return 0, fmt.Errorf("rtmfp: unknown kind %q", kind)
	}
}

// resolveBody returns the payload bytes for an event: message_b64 takes
// precedence over message; if both are empty, returns nil.
func resolveBody(message, messageB64 string) []byte {
	if messageB64 != "" {
		if b, err := base64.StdEncoding.DecodeString(messageB64); err == nil {
			return b
		}
		// fallback to text if base64 is invalid
	}
	if message != "" {
		return []byte(message)
	}
	return nil
}

// cookieBytes derives a deterministic cookie from sessionID.
func cookieBytes(sessionID uint32) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], sessionID)
	binary.BigEndian.PutUint32(b[4:8], sessionID^0xDEADBEEF)
	return b
}

// buildHeader builds a common RTMFP message header (16 bytes). Marker is data
// (0x0C) for reliable/unreliable/close/error, control (0x0E) for the rest.
func buildHeader(kind byte, sessionID, flowID, sequence uint32, payloadLen int) []byte {
	marker := MarkerControl
	if kind == KindReliable || kind == KindUnreliable || kind == KindFragment || kind == KindClose || kind == KindError {
		marker = MarkerData
	}
	totalLen := HeaderMinLen + payloadLen
	buf := make([]byte, totalLen)
	buf[0] = marker
	buf[1] = kind
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint32(buf[4:8], sessionID)
	binary.BigEndian.PutUint32(buf[8:12], flowID)
	binary.BigEndian.PutUint32(buf[12:16], sequence)
	return buf
}

// buildHello builds a hello message (handshake init).
func buildHello(sessionID uint32) []byte {
	return buildHeader(KindHello, sessionID, 0, 0, 0)
}

// buildHelloAck builds a hello_ack message.
func buildHelloAck(sessionID uint32) []byte {
	return buildHeader(KindHelloAck, sessionID, 0, 0, 0)
}

// buildCookie builds a cookie message with a deterministic cookie payload.
func buildCookie(sessionID uint32, cookie string) []byte {
	var payload []byte
	if cookie != "" {
		b, err := hex.DecodeString(cookie)
		if err == nil && len(b) > 0 {
			payload = b
		}
	}
	if len(payload) == 0 {
		payload = cookieBytes(sessionID)
	}
	hdr := buildHeader(KindCookie, sessionID, 0, 0, len(payload))
	copy(hdr[HeaderMinLen:], payload)
	return hdr
}

// buildSessionConfirm builds a session_confirm message.
func buildSessionConfirm(sessionID uint32) []byte {
	return buildHeader(KindSessionConfirm, sessionID, 0, 0, 0)
}

// buildReliable builds a reliable data message.
func buildReliable(sessionID, flowID, sequence uint32, body []byte) []byte {
	hdr := buildHeader(KindReliable, sessionID, flowID, sequence, len(body))
	copy(hdr[HeaderMinLen:], body)
	return hdr
}

// buildUnreliable builds an unreliable data message.
func buildUnreliable(sessionID, flowID uint32, body []byte) []byte {
	hdr := buildHeader(KindUnreliable, sessionID, flowID, 0, len(body))
	copy(hdr[HeaderMinLen:], body)
	return hdr
}

// buildFragment builds a fragment message. The fragment payload contains:
// fragment_index(4) + fragment_count(4) + total_length(4) + fragment_data.
func buildFragment(sessionID, flowID, sequence uint32, idx, count, totalLen uint32, data []byte) []byte {
	fragPayload := make([]byte, 12+len(data))
	binary.BigEndian.PutUint32(fragPayload[0:4], idx)
	binary.BigEndian.PutUint32(fragPayload[4:8], count)
	binary.BigEndian.PutUint32(fragPayload[8:12], totalLen)
	copy(fragPayload[12:], data)
	hdr := buildHeader(KindFragment, sessionID, flowID, sequence, len(fragPayload))
	copy(hdr[HeaderMinLen:], fragPayload)
	return hdr
}

// buildAck builds an ACK message. The payload contains:
// ranges_count(2) + [start(4)+end(4)]...
func buildAck(sessionID, flowID, sequence uint32, ranges [][2]uint32) []byte {
	payloadLen := 2 + len(ranges)*8
	hdr := buildHeader(KindAck, sessionID, flowID, sequence, payloadLen)
	binary.BigEndian.PutUint16(hdr[HeaderMinLen:HeaderMinLen+2], uint16(len(ranges)))
	for i, r := range ranges {
		off := HeaderMinLen + 2 + i*8
		binary.BigEndian.PutUint32(hdr[off:off+4], r[0])
		binary.BigEndian.PutUint32(hdr[off+4:off+8], r[1])
	}
	return hdr
}

// buildPing builds a ping message.
func buildPing(sessionID uint32) []byte {
	return buildHeader(KindPing, sessionID, 0, 0, 0)
}

// buildPong builds a pong message.
func buildPong(sessionID uint32) []byte {
	return buildHeader(KindPong, sessionID, 0, 0, 0)
}

// buildClose builds a close message.
func buildClose(sessionID uint32) []byte {
	return buildHeader(KindClose, sessionID, 0, 0, 0)
}

// buildError builds an error message (kind=error, marker=0x0C).
func buildError(sessionID uint32, body []byte) []byte {
	if len(body) == 0 {
		body = []byte("rtmfp error")
	}
	hdr := buildHeader(KindError, sessionID, 0, 0, len(body))
	copy(hdr[HeaderMinLen:], body)
	return hdr
}
