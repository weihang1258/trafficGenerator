// Package nfs — XDR decoding helpers for NFSv3 / NFSv4 / RPC.
//
// The decoder is used by parser tests to round-trip the encoded bytes.
// The encoders in builder.go are the source of truth; the parser is the
// inverse for primitives the tests need to assert.
package nfs

import (
	"encoding/binary"
	"fmt"
)

// parser is a low-level XDR reader.
type parser struct {
	b []byte
	i int
}

func newParser(b []byte) *parser { return &parser{b: b} }

func (p *parser) remaining() int { return len(p.b) - p.i }

func (p *parser) err(msg string) error {
	return fmt.Errorf("nfs parser: %s at offset %d (remaining %d)", msg, p.i, p.remaining())
}

func (p *parser) readU32() (uint32, error) {
	if p.remaining() < 4 {
		return 0, p.err("readU32 underflow")
	}
	v := binary.BigEndian.Uint32(p.b[p.i : p.i+4])
	p.i += 4
	return v, nil
}

func (p *parser) readU64() (uint64, error) {
	if p.remaining() < 8 {
		return 0, p.err("readU64 underflow")
	}
	v := binary.BigEndian.Uint64(p.b[p.i : p.i+8])
	p.i += 8
	return v, nil
}

func (p *parser) readBytes(n int) ([]byte, error) {
	if p.remaining() < n {
		return nil, p.err("readBytes underflow")
	}
	out := p.b[p.i : p.i+n]
	p.i += n
	return out, nil
}

// readOpaque reads a length-prefixed opaque + XDR padding.
func (p *parser) readOpaque() ([]byte, error) {
	n, err := p.readU32()
	if err != nil {
		return nil, err
	}
	if int(n) > p.remaining() {
		return nil, p.err("opaque length exceeds buffer")
	}
	data, err := p.readBytes(int(n))
	if err != nil {
		return nil, err
	}
	// Skip padding to 4-byte boundary
	pad := int((4 - (n % 4)) % 4)
	if pad > 0 {
		if _, err := p.readBytes(pad); err != nil {
			return nil, err
		}
	}
	return data, nil
}

// readFixedOpaque reads a fixed-length opaque array (no length prefix).
func (p *parser) readFixedOpaque(n int) ([]byte, error) {
	data, err := p.readBytes(n)
	if err != nil {
		return nil, err
	}
	pad := (4 - (n % 4)) % 4
	if pad > 0 {
		if _, err := p.readBytes(pad); err != nil {
			return nil, err
		}
	}
	return data, nil
}

// readString reads a length-prefixed XDR string.
func (p *parser) readString() (string, error) {
	b, err := p.readOpaque()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ReadOpaqueLen reads the length prefix of an XDR opaque and returns
// (payloadStartOffset, payloadLen). Returns (-1, -1) on underflow.
// The offset is relative to the start of b.
func ReadOpaqueLen(b []byte) (int, int) {
	if len(b) < 4 {
		return -1, -1
	}
	n := int(binary.BigEndian.Uint32(b[0:4]))
	if n < 0 || n > len(b)-4 {
		return -1, -1
	}
	return 4, n
}

// ReadOpaqueLenNoAdvance reads the length prefix of an XDR opaque and
// returns just the payload length (or -1 on underflow), without
// advancing any cursor.
func ReadOpaqueLenNoAdvance(b []byte) int {
	if len(b) < 4 {
		return -1
	}
	n := int(binary.BigEndian.Uint32(b[0:4]))
	if n < 0 || n > len(b)-4 {
		return -1
	}
	return n
}

// SkipOpaque returns the byte offset just past a length-prefixed XDR
// opaque starting at b[0:] (4-byte length + payload + padding), or -1
// on underflow.
func SkipOpaque(b []byte) int {
	n := ReadOpaqueLenNoAdvance(b)
	if n < 0 {
		return -1
	}
	pad := (4 - (n % 4)) % 4
	return 4 + n + pad
}

// readStateid reads a 16-byte stateid4 (4-byte seqid + 12-byte other).
func (p *parser) readStateid() (*NFSStateid, error) {
	seqid, err := p.readU32()
	if err != nil {
		return nil, err
	}
	other, err := p.readFixedOpaque(12)
	if err != nil {
		return nil, err
	}
	var o [12]byte
	copy(o[:], other)
	return &NFSStateid{Seqid: seqid, Other: o}, nil
}

// readNFSTime3 reads an nfstime3 (4-byte secs + 4-byte nsecs).
func (p *parser) readNFSTime3() (secs, nsecs uint32, err error) {
	secs, err = p.readU32()
	if err != nil {
		return 0, 0, err
	}
	nsecs, err = p.readU32()
	if err != nil {
		return 0, 0, err
	}
	return
}

// --- Record mark / RPC header parsers ---

// ParseRecordMark decodes a 4-byte big-endian RM. Returns the RM and the
// payload length encoded in it. For UDP the caller passes payload=nil.
func ParseRecordMark(b []byte) (rm uint32, fragLen uint32, err error) {
	if len(b) < 4 {
		return 0, 0, fmt.Errorf("nfs parser: record mark underflow (got %d bytes)", len(b))
	}
	rm = binary.BigEndian.Uint32(b[0:4])
	fragLen = rm & 0x7FFFFFFF
	return rm, fragLen, nil
}

// RPCCallHeader is the parsed RPC CALL header.
type RPCCallHeader struct {
	XID         uint32
	Type        uint32
	RPCVersion  uint32
	Program     uint32
	Version     uint32
	Procedure   uint32
	CredFlavor  uint32
	CredBodyLen uint32
	CredBody    []byte
	VerfFlavor  uint32
	VerfBodyLen uint32
	VerfBody    []byte
}

// ParseRPCCallHeader parses the RPC CALL header (40 bytes minimum, plus
// optional cred/verf bodies). Returns the header and the offset of the
// NFS body (procedure-specific args).
func ParseRPCCallHeader(b []byte) (*RPCCallHeader, int, error) {
	p := newParser(b)
	h := &RPCCallHeader{}
	var err error
	if h.XID, err = p.readU32(); err != nil {
		return nil, 0, err
	}
	if h.Type, err = p.readU32(); err != nil {
		return nil, 0, err
	}
	if h.RPCVersion, err = p.readU32(); err != nil {
		return nil, 0, err
	}
	if h.Program, err = p.readU32(); err != nil {
		return nil, 0, err
	}
	if h.Version, err = p.readU32(); err != nil {
		return nil, 0, err
	}
	if h.Procedure, err = p.readU32(); err != nil {
		return nil, 0, err
	}
	if h.CredFlavor, err = p.readU32(); err != nil {
		return nil, 0, err
	}
	if h.CredBodyLen, err = p.readU32(); err != nil {
		return nil, 0, err
	}
	if h.CredBody, err = p.readBytes(int(h.CredBodyLen)); err != nil {
		return nil, 0, err
	}
	if h.VerfFlavor, err = p.readU32(); err != nil {
		return nil, 0, err
	}
	if h.VerfBodyLen, err = p.readU32(); err != nil {
		return nil, 0, err
	}
	if h.VerfBody, err = p.readBytes(int(h.VerfBodyLen)); err != nil {
		return nil, 0, err
	}
	return h, p.i, nil
}

// RPCReplyHeader is the parsed RPC REPLY header.
type RPCReplyHeader struct {
	XID          uint32
	Type         uint32
	ReplyState   uint32
	VerfFlavor   uint32
	VerfBodyLen  uint32
	VerfBody     []byte
	AcceptState  uint32 // valid only when ReplyState == MSG_ACCEPTED
	RejectState  uint32 // valid only when ReplyState == MSG_DENIED
	MismatchLow  uint32
	MismatchHigh uint32
	AuthStat     uint32
}

// ParseRPCReplyHeader parses the RPC REPLY header. Returns the header
// and the offset of the NFS body.
func ParseRPCReplyHeader(b []byte) (*RPCReplyHeader, int, error) {
	p := newParser(b)
	h := &RPCReplyHeader{}
	var err error
	if h.XID, err = p.readU32(); err != nil {
		return nil, 0, err
	}
	if h.Type, err = p.readU32(); err != nil {
		return nil, 0, err
	}
	if h.ReplyState, err = p.readU32(); err != nil {
		return nil, 0, err
	}
	if h.ReplyState == RPCMsgAccepted {
		// Verifier is part of accepted_reply only (RFC 5531 §9.2);
		// denied_reply carries no verifier.
		if h.VerfFlavor, err = p.readU32(); err != nil {
			return nil, 0, err
		}
		if h.VerfBodyLen, err = p.readU32(); err != nil {
			return nil, 0, err
		}
		if h.VerfBody, err = p.readBytes(int(h.VerfBodyLen)); err != nil {
			return nil, 0, err
		}
	}
	switch h.ReplyState {
	case RPCMsgAccepted:
		if h.AcceptState, err = p.readU32(); err != nil {
			return nil, 0, err
		}
		if h.AcceptState == RPCProgMismatch {
			if h.MismatchLow, err = p.readU32(); err != nil {
				return nil, 0, err
			}
			if h.MismatchHigh, err = p.readU32(); err != nil {
				return nil, 0, err
			}
		}
	case RPCMsgDenied:
		if h.RejectState, err = p.readU32(); err != nil {
			return nil, 0, err
		}
		if h.RejectState == RPCMismatch {
			if h.MismatchLow, err = p.readU32(); err != nil {
				return nil, 0, err
			}
			if h.MismatchHigh, err = p.readU32(); err != nil {
				return nil, 0, err
			}
		} else if h.RejectState == RPCAuthError {
			if h.AuthStat, err = p.readU32(); err != nil {
				return nil, 0, err
			}
		}
	default:
		return nil, 0, p.err("invalid reply_state")
	}
	return h, p.i, nil
}

// --- NFSv3 reply parsers ---

// NFS3GETATTRRes is the parsed GETATTR3 reply.
type NFS3GETATTRRes struct {
	Status uint32
	// post_op_attr (RFC 1813 §3.3.2): union switch (bool attributes_follow)
	AttrPresent bool
	Fattr3      []byte // 84 bytes when present
}

// ParseNFS3GETATTRRes parses a GETATTR3 reply (NFS status + post_op_attr).
func ParseNFS3GETATTRRes(b []byte) (*NFS3GETATTRRes, error) {
	p := newParser(b)
	r := &NFS3GETATTRRes{}
	var err error
	if r.Status, err = p.readU32(); err != nil {
		return nil, err
	}
	if r.AttrPresent, err = p.readBool(); err != nil {
		return nil, err
	}
	if r.AttrPresent {
		if r.Fattr3, err = p.readFixedOpaque(84); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// NFS3READRes is the parsed READ3 reply.
type NFS3READRes struct {
	Status      uint32
	AttrPresent bool
	Fattr3      []byte
	Count       uint32
	EOF         bool
	Data        []byte
}

// ParseNFS3READRes parses a READ3 reply.
func ParseNFS3READRes(b []byte) (*NFS3READRes, error) {
	p := newParser(b)
	r := &NFS3READRes{}
	var err error
	if r.Status, err = p.readU32(); err != nil {
		return nil, err
	}
	if r.AttrPresent, err = p.readBool(); err != nil {
		return nil, err
	}
	if r.AttrPresent {
		if r.Fattr3, err = p.readFixedOpaque(84); err != nil {
			return nil, err
		}
	}
	if r.Count, err = p.readU32(); err != nil {
		return nil, err
	}
	if r.EOF, err = p.readBool(); err != nil {
		return nil, err
	}
	if r.Data, err = p.readOpaque(); err != nil {
		return nil, err
	}
	return r, nil
}

// NFS3WRITERes is the parsed WRITE3 reply.
type NFS3WRITERes struct {
	Status    uint32
	WCCSize   int
	Count     uint32
	Committed uint32
	Verf      [8]byte
}

// ParseNFS3WRITERes parses a WRITE3 reply (status + wcc_data + count +
// committed + verf).
func ParseNFS3WRITERes(b []byte) (*NFS3WRITERes, error) {
	p := newParser(b)
	r := &NFS3WRITERes{}
	var err error
	if r.Status, err = p.readU32(); err != nil {
		return nil, err
	}
	// Skip wcc_data (pre_op_attr discriminant + post_op_attr discriminant
	// + optional fattr3). 92 bytes when both discriminants are 0/1 with
	// a default fattr3. The total may vary; consume what's there until
	// we hit the next 4-byte field (count).
	// Read pre_op_attr discriminant
	preFollow, err := p.readU32()
	if err != nil {
		return nil, err
	}
	if preFollow != 0 {
		// wcc_attr = size(8) + mtime(8) + ctime(8) = 24 bytes
		if _, err := p.readFixedOpaque(24); err != nil {
			return nil, err
		}
	}
	// post_op_attr discriminant
	postFollow, err := p.readU32()
	if err != nil {
		return nil, err
	}
	if postFollow != 0 {
		if _, err := p.readFixedOpaque(84); err != nil {
			return nil, err
		}
	}
	if r.Count, err = p.readU32(); err != nil {
		return nil, err
	}
	if r.Committed, err = p.readU32(); err != nil {
		return nil, err
	}
	verf, err := p.readFixedOpaque(8)
	if err != nil {
		return nil, err
	}
	copy(r.Verf[:], verf)
	return r, nil
}

// NFS3LOOKUPRes is the parsed LOOKUP3 reply.
type NFS3LOOKUPRes struct {
	Status        uint32
	ObjectFH      []byte
	ObjAttrFollow bool
	ObjFattr3     []byte
	DirAttrFollow bool
}

// ParseNFS3LOOKUPRes parses a LOOKUP3 reply. Order per RFC 1813 §3.3.3:
// object fh, obj_attributes, dir_attributes.
func ParseNFS3LOOKUPRes(b []byte) (*NFS3LOOKUPRes, error) {
	p := newParser(b)
	r := &NFS3LOOKUPRes{}
	var err error
	if r.Status, err = p.readU32(); err != nil {
		return nil, err
	}
	if r.ObjectFH, err = p.readOpaque(); err != nil {
		return nil, err
	}
	if r.ObjAttrFollow, err = p.readBool(); err != nil {
		return nil, err
	}
	if r.ObjAttrFollow {
		if r.ObjFattr3, err = p.readFixedOpaque(84); err != nil {
			return nil, err
		}
	}
	if r.DirAttrFollow, err = p.readBool(); err != nil {
		return nil, err
	}
	return r, nil
}

// --- NFSv4 COMPOUND reply parsers ---

// Compound4Res is the parsed COMPOUND4res structure.
type Compound4Res struct {
	Status uint32
	Tag    string
	ResOps []ParsedResOp
}

// ParsedResOp is a single operation result.
type ParsedResOp struct {
	Opcode   uint32
	OpStatus uint32
	// Result bytes (opaque to the parser; tests inspect via offsets)
	Result []byte
}

// ParseCompound4Res parses a COMPOUND4res payload.
func ParseCompound4Res(b []byte) (*Compound4Res, error) {
	p := newParser(b)
	r := &Compound4Res{}
	var err error
	if r.Status, err = p.readU32(); err != nil {
		return nil, err
	}
	if r.Tag, err = p.readString(); err != nil {
		return nil, err
	}
	count, err := p.readU32()
	if err != nil {
		return nil, err
	}
	r.ResOps = make([]ParsedResOp, 0, count)
	for i := uint32(0); i < count; i++ {
		op := ParsedResOp{}
		if op.Opcode, err = p.readU32(); err != nil {
			return nil, err
		}
		if op.OpStatus, err = p.readU32(); err != nil {
			return nil, err
		}
		// When OpStatus != 0, the result body is empty (truncation).
		// Otherwise we record the remaining bytes; the caller is expected
		// to know the format for the given opcode.
		if op.OpStatus == 0 && p.remaining() > 0 {
			// Don't consume — leave the slice reference for caller inspection.
			// Mark length with a sentinel via ResultStart so tests can locate.
			op.Result = p.b[p.i : p.i+p.remaining()]
		}
		r.ResOps = append(r.ResOps, op)
	}
	return r, nil
}

// ParseCompound4Args parses a COMPOUND4args payload (the CALL side).
// Returns the tag, minorversion, and one ParsedArgOp per argarray entry.
//
// Each ParsedArgOp.Args is the remaining bytes from that op's position
// onward (the parser does not decode per-op argument formats, so it
// cannot delimit where one op's args end and the next op begins). Callers
// that need precise per-op arguments must either place the op of interest
// last in the compound or decode the known-length prefix themselves.
func ParseCompound4Args(b []byte) (tag string, minorversion uint32, ops []ParsedArgOp, err error) {
	p := newParser(b)
	if tag, err = p.readString(); err != nil {
		return "", 0, nil, err
	}
	if minorversion, err = p.readU32(); err != nil {
		return "", 0, nil, err
	}
	count, err := p.readU32()
	if err != nil {
		return "", 0, nil, err
	}
	ops = make([]ParsedArgOp, 0, count)
	for i := uint32(0); i < count; i++ {
		op := ParsedArgOp{}
		if op.Opcode, err = p.readU32(); err != nil {
			return "", 0, nil, err
		}
		// The args start here; record the remaining-bytes view without
		// consuming so the caller can inspect (and so the loop can read
		// the next opcode). Args may overlap when more than one op
		// follows — callers must delimit.
		op.Args = p.b[p.i:]
		ops = append(ops, op)
	}
	return tag, minorversion, ops, nil
}

// ParsedArgOp is a single arg op (opcode + raw remaining bytes).
type ParsedArgOp struct {
	Opcode uint32
	Args   []byte
}

// --- Helpers ---

// readBool reads a 4-byte XDR bool (0=false, 1=true).
func (p *parser) readBool() (bool, error) {
	v, err := p.readU32()
	if err != nil {
		return false, err
	}
	return v != 0, nil
}

// ReadBitmap4 reads a bitmap4 (length + words).
func ReadBitmap4(b []byte) ([]uint32, int, error) {
	p := newParser(b)
	n, err := p.readU32()
	if err != nil {
		return nil, 0, err
	}
	words := make([]uint32, n)
	for i := uint32(0); i < n; i++ {
		w, err := p.readU32()
		if err != nil {
			return nil, 0, err
		}
		words[i] = w
	}
	return words, p.i, nil
}
