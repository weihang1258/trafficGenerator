// Package tftp implements TFTP wire-format packet construction.
package tftp

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

// buildRRQWRQ builds an RRQ (opcode 1) or WRQ (opcode 2) packet per RFC 1350
// §4 and RFC 2347 §2. Layout:
//   opcode(2) + filename\0 + mode\0 + [option\0 value\0]...
//
// Options are appended in the fixed order blksize → timeout → tsize →
// windowsize (§5.2). Only non-zero options are emitted (blksize=0 means
// "use default 512, do not send the option").
func buildRRQWRQ(opcode uint16, filename, mode string, opts wireOptions) []byte {
	// Pre-compute total length to avoid reallocation.
	length := 2 + len(filename) + 1 + len(mode) + 1
	for i := 0; i < numOptions; i++ {
		if opts.set[i] {
			length += len(optionNames[i]) + 1 + len(opts.values[i]) + 1
		}
	}
	buf := make([]byte, 0, length)
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, opcode)
	buf = append(buf, b...)
	buf = append(buf, filename...)
	buf = append(buf, 0)
	buf = append(buf, mode...)
	buf = append(buf, 0)
	for i := 0; i < numOptions; i++ {
		if opts.set[i] {
			buf = append(buf, optionNames[i]...)
			buf = append(buf, 0)
			buf = append(buf, opts.values[i]...)
			buf = append(buf, 0)
		}
	}
	return buf
}

// buildDATA builds a DATA packet (opcode 3) per RFC 1350 §4.
// Layout: opcode(2) + Block#(2) + Data(0..blksize).
// blockNum is the wire Block# (already wrapped if WrapBlockNumber=true).
func buildDATA(blockNum uint16, data []byte) []byte {
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(buf[0:2], OpDATA)
	binary.BigEndian.PutUint16(buf[2:4], blockNum)
	copy(buf[4:], data)
	return buf
}

// buildACK builds an ACK packet (opcode 4) per RFC 1350 §4.
// Layout: opcode(2) + Block#(2).
// blockNum is the wire Block# being acknowledged.
func buildACK(blockNum uint16) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], OpACK)
	binary.BigEndian.PutUint16(buf[2:4], blockNum)
	return buf
}

// buildERROR builds an ERROR packet (opcode 5) per RFC 1350 §4.
// Layout: opcode(2) + ErrCode(2) + ErrMsg\0.
// ErrMsg is truncated to MaxErrMsgBytes and always NUL-terminated.
func buildERROR(errCode uint8, errMsg string) []byte {
	if len(errMsg) > MaxErrMsgBytes {
		errMsg = errMsg[:MaxErrMsgBytes]
	}
	buf := make([]byte, 4+len(errMsg)+1)
	binary.BigEndian.PutUint16(buf[0:2], OpERROR)
	// L-3 修复：用 binary.BigEndian.PutUint16 替代手动字节拼装(buf[2]=0; buf[3]=errCode)，
	// 保证 ErrCode 高字节为 0 的语义显式且符合其余 builder 的编码风格。
	binary.BigEndian.PutUint16(buf[2:4], uint16(errCode))
	copy(buf[4:], errMsg)
	buf[len(buf)-1] = 0 // NUL terminator
	return buf
}

// buildOACK builds an OACK packet (opcode 6) per RFC 2347 §2.
// Layout: opcode(2) + [option\0 value\0]...
// No filename/mode fields. Only the server-accepted option subset is emitted.
func buildOACK(opts wireOptions) []byte {
	length := 2
	for i := 0; i < numOptions; i++ {
		if opts.set[i] {
			length += len(optionNames[i]) + 1 + len(opts.values[i]) + 1
		}
	}
	buf := make([]byte, 0, length)
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, OpOACK)
	buf = append(buf, b...)
	for i := 0; i < numOptions; i++ {
		if opts.set[i] {
			buf = append(buf, optionNames[i]...)
			buf = append(buf, 0)
			buf = append(buf, opts.values[i]...)
			buf = append(buf, 0)
		}
	}
	return buf
}

// wireOptions holds the option values to be written on the wire, in the
// fixed output order (blksize → timeout → tsize → windowsize). set[i]=false
// means the option is omitted (not negotiated).
type wireOptions struct {
	set    [numOptions]bool
	values [numOptions]string
}

// setBlkSize sets the blksize option value (RFC 2348).
func (w *wireOptions) setBlkSize(v uint16) {
	w.set[optBlkSize] = true
	w.values[optBlkSize] = strconv.FormatUint(uint64(v), 10)
}

// setTimeout sets the timeout option value (RFC 2349).
func (w *wireOptions) setTimeout(v uint8) {
	w.set[optTimeout] = true
	w.values[optTimeout] = strconv.FormatUint(uint64(v), 10)
}

// setTSize sets the tsize option value (RFC 2349).
func (w *wireOptions) setTSize(v uint32) {
	w.set[optTSize] = true
	w.values[optTSize] = strconv.FormatUint(uint64(v), 10)
}

// setWindowSize sets the windowsize option value (RFC 7440).
func (w *wireOptions) setWindowSize(v uint16) {
	w.set[optWindow] = true
	w.values[optWindow] = strconv.FormatUint(uint64(v), 10)
}

// validateRRQLength returns an error if the built RRQ/WRQ exceeds the RFC
// 2347 maximum request packet size of 512 octets. trafficgen does not
// truncate (§3.2); this is a defensive check callers may use to report.
func validateRRQLength(pkt []byte) error {
	const maxRequest = 512
	if len(pkt) > maxRequest {
		return fmt.Errorf("tftp: request packet %d bytes exceeds RFC 2347 max %d", len(pkt), maxRequest)
	}
	return nil
}
