// Package nfs — XDR encoding helpers for NFSv3 / NFSv4 / RPC.
//
// All multi-byte fields are big-endian. The encoding follows RFC 4506
// (XDR), RFC 5531 (RPC), RFC 1813 (NFSv3), RFC 7530/7531 (NFSv4.0).
package nfs

import (
	"encoding/binary"
	"fmt"
)

// --- Low-level XDR primitive writers ---

func w32(buf []byte, v uint32) {
	binary.BigEndian.PutUint32(buf, v)
}

func w64(buf []byte, v uint64) {
	binary.BigEndian.PutUint64(buf, v)
}

// appendU32 appends a 4-byte big-endian uint32.
func appendU32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

// appendU64 appends an 8-byte big-endian uint64.
func appendU64(b []byte, v uint64) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)
	return append(b, tmp[:]...)
}

// appendOpaque appends a length-prefixed byte string with XDR 4-byte
// alignment padding.
func appendOpaque(b []byte, data []byte) []byte {
	n := uint32(len(data))
	b = appendU32(b, n)
	b = append(b, data...)
	// Pad to 4-byte boundary
	pad := int((4 - (n % 4)) % 4)
	for i := 0; i < pad; i++ {
		b = append(b, 0)
	}
	return b
}

// appendFixedOpaque appends a fixed-length byte array (no length prefix)
// with XDR 4-byte alignment padding.
func appendFixedOpaque(b, data []byte) []byte {
	b = append(b, data...)
	pad := (4 - (len(data) % 4)) % 4
	for i := 0; i < pad; i++ {
		b = append(b, 0)
	}
	return b
}

// appendString appends a length-prefixed XDR string.
func appendString(b []byte, s string) []byte {
	return appendOpaque(b, []byte(s))
}

// --- Filehandle / stateid encoders ---

// appendFilehandle encodes an nfs_fh3 (length-prefixed) or NFSv4 fh
// (length-prefixed). The semantics are the same on the wire.
func appendFilehandle(b []byte, fh []byte) []byte {
	return appendOpaque(b, fh)
}

// appendStateid encodes a stateid4 (4-byte seqid + 12-byte other, no
// length prefix on other).
func appendStateid(b []byte, s *NFSStateid) []byte {
	if s == nil {
		// Anonymous stateid: seqid=0, other=12 0x00
		var zero [12]byte
		b = appendU32(b, 0)
		return append(b, zero[:]...)
	}
	b = appendU32(b, s.Seqid)
	return append(b, s.Other[:]...)
}

// appendStateidBytes encodes a 16-byte stateid (seqid+other) given the
// raw bytes.
func appendStateidBytes(b []byte, raw []byte) []byte {
	if len(raw) < 16 {
		raw = append(raw, make([]byte, 16-len(raw))...)
	}
	return append(b, raw[:16]...)
}

// --- NFSv3 attribute encoders ---

// encodeNFSTime3 encodes an nfstime3 (4-byte seconds + 4-byte nseconds).
func encodeNFSTime3(b []byte, secs, nsecs uint32) []byte {
	b = appendU32(b, secs)
	return appendU32(b, nsecs)
}

// encodeFattr3 encodes a fattr3 (84 bytes, RFC 1813 §2.6).
func encodeFattr3(b []byte, typeVal, mode, nlink, uid, gid uint32,
	size, used, fsid, fileid uint64,
	atimeSecs, atimeNsecs, mtimeSecs, mtimeNsecs, ctimeSecs, ctimeNsecs uint32,
	rdev1, rdev2 uint32) []byte {
	b = appendU32(b, typeVal)
	b = appendU32(b, mode)
	b = appendU32(b, nlink)
	b = appendU32(b, uid)
	b = appendU32(b, gid)
	b = appendU64(b, size)
	b = appendU64(b, used)
	b = appendU32(b, rdev1)
	b = appendU32(b, rdev2)
	b = appendU64(b, fsid)
	b = appendU64(b, fileid)
	b = encodeNFSTime3(b, atimeSecs, atimeNsecs)
	b = encodeNFSTime3(b, mtimeSecs, mtimeNsecs)
	return encodeNFSTime3(b, ctimeSecs, ctimeNsecs)
}

// defaultFattr3 returns a fattr3 with sensible defaults (type=NF3REG,
// mode=0644, all sizes/times zero).
func defaultFattr3() []byte {
	buf := make([]byte, 0, 84)
	buf = encodeFattr3(buf,
		NF3REG, 0644, 1, 0, 0, // type, mode, nlink, uid, gid
		0, 0, 0, 0, // size, used, fsid, fileid
		0, 0, 0, 0, 0, 0, // times
		0, 0) // rdev
	return buf
}

// encodeWccData encodes wcc_data with pre_op_attr.discriminant=0
// (no follow) and post_op_attr.discriminant=1 + a default fattr3.
// Total = 4 + 4 + 84 = 92 bytes (§2.8 / S6).
func encodeWccData(b []byte) []byte {
	b = appendU32(b, 0) // pre_op_attr.attributes_follow = 0
	b = appendU32(b, 1) // post_op_attr.attributes_follow = 1
	return append(b, defaultFattr3()...)
}

// encodeSattr3 encodes a sattr3 (RFC 1813 §2.6). The returned length
// depends on which set_xxx fields are present.
func encodeSattr3(b []byte, a *NFSAttributes) []byte {
	if a == nil {
		// All fields DONT_CHANGE/false → 24 bytes: set_mode(4)
		// set_uid(4) set_gid(4) set_size(4) set_atime(4) set_mtime(4).
		// Pre-fix this branch emitted only 4 bytes, so tshark read the
		// following bytes as the rest of the sattr3 and flagged
		// [Malformed Packet: NFS].
		b = appendU32(b, 0) // set_mode
		b = appendU32(b, 0) // set_uid
		b = appendU32(b, 0) // set_gid
		b = appendU32(b, 0) // set_size
		b = appendU32(b, 0) // set_atime (time_how = SET_TO_SERVER_TIME)
		b = appendU32(b, 0) // set_mtime (time_how = SET_TO_SERVER_TIME)
		return b
	}
	// set_mode
	b = appendU32(b, boolToUint32(a.SetMode))
	if a.SetMode {
		b = appendU32(b, a.Mode)
	}
	// set_uid
	b = appendU32(b, boolToUint32(a.SetUid))
	if a.SetUid {
		b = appendU32(b, a.Uid)
	}
	// set_gid
	b = appendU32(b, boolToUint32(a.SetGid))
	if a.SetGid {
		b = appendU32(b, a.Gid)
	}
	// set_size
	b = appendU32(b, boolToUint32(a.SetSize))
	if a.SetSize {
		b = appendU64(b, a.Size)
	}
	// set_atime (time_how): nil/unset pointer = SET_TO_SERVER_TIME
	// (per §2.8 / v2.0.4 design), sentinel 0xFFFFFFFF = SET_TO_SERVER_TIME,
	// otherwise SET_TO_CLIENT_TIME.
	b = appendU32(b, timeHowFor(a.SetAtime, a.AtimeSecs))
	if a.SetAtime && shouldWriteClientTime(a.AtimeSecs) {
		b = encodeNFSTime3(b, *a.AtimeSecs, derefOrZero(a.AtimeNsecs))
	}
	// set_mtime (time_how)
	b = appendU32(b, timeHowFor(a.SetMtime, a.MtimeSecs))
	if a.SetMtime && shouldWriteClientTime(a.MtimeSecs) {
		b = encodeNFSTime3(b, *a.MtimeSecs, derefOrZero(a.MtimeNsecs))
	}
	return b
}

// timeHowFor maps NFSAttributes (Set + *Secs) to the time_how discriminant
// per §2.8:
//
//	SetAtime=false                    → 0 (DONT_CHANGE)
//	SetAtime=true, AtimeSecs=nil      → 1 (SET_TO_SERVER_TIME, v2.0.4 design)
//	SetAtime=true, AtimeSecs=0xFFFFFFFF → 1 (SET_TO_SERVER_TIME)
//	SetAtime=true, AtimeSecs=other    → 2 (SET_TO_CLIENT_TIME)
func timeHowFor(set bool, secs *uint32) uint32 {
	if !set {
		return TimeHowDONT_CHANGE
	}
	if secs == nil {
		return TimeHowSET_TO_SERVER_TIME
	}
	if *secs == 0xFFFFFFFF {
		return TimeHowSET_TO_SERVER_TIME
	}
	return TimeHowSET_TO_CLIENT_TIME
}

// shouldWriteClientTime returns true when the user-provided Secs value
// maps to SET_TO_CLIENT_TIME (i.e., not nil and not the 0xFFFFFFFF sentinel).
// The caller must check this *after* confirming SetAtime/SetMtime is true.
func shouldWriteClientTime(secs *uint32) bool {
	if secs == nil {
		return false
	}
	return *secs != 0xFFFFFFFF
}

// derefOrZero returns *p if p is non-nil, else 0.
func derefOrZero(p *uint32) uint32 {
	if p == nil {
		return 0
	}
	return *p
}

// encodeSattrGuard3 encodes SETATTR3's sattrguard3 (RFC 1813 §3.3.2).
// check=false → 4 bytes; check=true → 4 + 8 = 12 bytes.
func encodeSattrGuard3(b []byte, a *NFSAttributes) []byte {
	if a == nil || !a.SattrGuardCheck {
		return appendU32(b, 0)
	}
	b = appendU32(b, 1)
	return encodeNFSTime3(b, a.SattrGuardCtimeSecs, a.SattrGuardCtimeNsecs)
}

func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// --- NFSv4 attribute encoders ---

// encodeBitmap4 encodes a bitmap4 (length + word array) per RFC 7531 §3.
func encodeBitmap4(b []byte, words []uint32) []byte {
	b = appendU32(b, uint32(len(words)))
	for _, w := range words {
		b = appendU32(b, w)
	}
	return b
}

// encodeAttrList4 encodes an attrlist4 (length-prefixed opaque + padding).
func encodeAttrList4(b []byte, data []byte) []byte {
	n := uint32(len(data))
	b = appendU32(b, n)
	b = append(b, data...)
	pad := int((4 - (n % 4)) % 4)
	for i := 0; i < pad; i++ {
		b = append(b, 0)
	}
	return b
}

// encodeFattr4AttrVals synthesizes an attrlist4 body from a bitmap + a
// function that returns the XDR value bytes for each set bit. The
// function is called for every set bit in order (low bit to high bit,
// across words).
func encodeFattr4AttrVals(words []uint32, attrValue func(attrNum uint32) []byte) []byte {
	body := make([]byte, 0, 64)
	for wIdx, w := range words {
		for bit := uint32(0); bit < 32; bit++ {
			if w&(1<<bit) != 0 {
				attrNum := uint32(wIdx)*32 + bit
				body = append(body, attrValue(attrNum)...)
			}
		}
	}
	return body
}

// defaultAttr4Value returns a synthesized XDR value for a few common
// attributes. Unknown attributes produce 4 zero bytes.
func defaultAttr4Value(attrNum uint32) []byte {
	switch attrNum {
	case 4: // FATTR4_SIZE (uint64)
		var tmp [8]byte
		binary.BigEndian.PutUint64(tmp[:], 16)
		return tmp[:]
	case 33: // FATTR4_MODE (uint32)
		return []byte{0, 0, 1, 0xFF} // 0x1FF = 0777
	default:
		// Default: 4 zero bytes — covers uint32 attributes and provides a
		// reasonable length for unknown bits.
		return []byte{0, 0, 0, 0}
	}
}

// --- NFSv3 reply result encoders ---

// encodePostOpAttr encodes a post_op_attr with attributes_follow=1 and a
// default fattr3 (88 bytes total). For attributes_follow=0, just write
// the discriminant (4 bytes).
func encodePostOpAttr(b []byte, present bool) []byte {
	if !present {
		return appendU32(b, 0)
	}
	b = appendU32(b, 1)
	return append(b, defaultFattr3()...)
}

// encodePostOpFH3 encodes a post_op_fh3 (RFC 1813 §3.3.4 union). When
// present, the body is nfs_fh3 = length + data + padding.
func encodePostOpFH3(b []byte, fh []byte) []byte {
	if fh == nil {
		return appendU32(b, 0)
	}
	b = appendU32(b, 1)
	return appendFilehandle(b, fh)
}

// --- Authentication encoders ---

// encodeAuthNone encodes AUTH_NONE credentials: flavor + body length (0).
func encodeAuthNone(b []byte) []byte {
	b = appendU32(b, AuthFlavorNone)
	return appendU32(b, 0)
}

// encodeAuthSys encodes AUTH_SYS credentials (RFC 5531 §9.2).
// Body = stamp(4) + machinename(len+data+pad) + uid(4) + gid(4) + aux_gids(count + n*4).
func encodeAuthSys(b []byte, info *AuthSysInfo) []byte {
	if info == nil {
		info = &AuthSysInfo{MachineName: "trafficgen"}
	}
	mn := []byte(info.MachineName)
	groups := info.Groups
	if groups == nil {
		groups = []uint32{}
	}
	body := make([]byte, 0, 32+len(mn))
	body = appendU32(body, info.Stamp)
	body = appendOpaque(body, mn)
	body = appendU32(body, info.UID)
	body = appendU32(body, info.GID)
	body = appendU32(body, uint32(len(groups)))
	for _, g := range groups {
		body = appendU32(body, g)
	}
	b = appendU32(b, AuthFlavorSys)
	b = appendU32(b, uint32(len(body)))
	return append(b, body...)
}

// --- RPC header encoders ---

// encodeRPCCallHeader encodes the RPC CALL header up to (but not
// including) the procedure-specific NFS arguments. Returns the bytes
// prepended to the caller-supplied nfsBody.
func encodeRPCCallHeader(b []byte, xid, program, version, procedure uint32,
	authFlavor uint32, authSys *AuthSysInfo) []byte {
	b = appendU32(b, xid)        // XID
	b = appendU32(b, RPCCall)    // Type = CALL
	b = appendU32(b, RPCVersion) // RPC version = 2
	b = appendU32(b, program)
	b = appendU32(b, version)
	b = appendU32(b, procedure)
	// Credentials
	if authFlavor == AuthFlavorSys {
		b = encodeAuthSys(b, authSys)
	} else {
		b = encodeAuthNone(b)
	}
	// Verifier (always AUTH_NONE for now)
	return encodeAuthNone(b)
}

// encodeRPCReplyHeaderAccepted encodes the RPC REPLY header for the
// MSG_ACCEPTED branch up to the AcceptState field. After this header the
// caller writes AcceptState + optional low/high + NFS body.
func encodeRPCReplyHeaderAccepted(b []byte, xid uint32) []byte {
	b = appendU32(b, xid)            // XID
	b = appendU32(b, RPCReply)       // Type = REPLY
	b = appendU32(b, RPCMsgAccepted) // ReplyState
	return encodeAuthNone(b)         // Verifier = AUTH_NONE
}

// encodeRPCReplyHeaderDenied encodes the RPC REPLY header for the
// MSG_DENIED branch up to the RejectState field. After this header the
// caller writes RejectState + (mismatch_info | auth_stat).
//
// Per RFC 5531 §9.2 (reply_body), the verifier field is part of
// accepted_reply ONLY; denied_reply carries no verifier: msg_type +
// reply_stat + reject_stat + (mismatch_info | auth_stat). The verifier
// was previously appended here, shifting RejectState/low/high by 8 bytes
// and making the reply unparseable by tshark (T-163..T-166).
func encodeRPCReplyHeaderDenied(b []byte, xid uint32) []byte {
	b = appendU32(b, xid)
	b = appendU32(b, RPCReply)
	b = appendU32(b, RPCMsgDenied)
	return b // No verifier in denied_reply (RFC 5531 §9.2)
}

// --- NFSv4 COMPOUND encoders ---

// encodeCompound4Args encodes COMPOUND4args (RFC 7531 §5.2):
//
//	tag(utf8str_cs) + minorversion(uint32) + argarray<nfs_argop4>
func encodeCompound4Args(b []byte, tag string, minorversion uint32, ops []encodedOp) []byte {
	b = appendString(b, tag)
	b = appendU32(b, minorversion)
	b = appendU32(b, uint32(len(ops)))
	for _, op := range ops {
		b = appendU32(b, op.Opcode)
		b = append(b, op.Args...)
	}
	return b
}

// encodedOp pairs an opcode with its XDR-encoded arguments.
type encodedOp struct {
	Opcode uint32
	Args   []byte
}

// --- COMPOUND reply encoders ---

// encodeCompound4Res encodes COMPOUND4res (RFC 7531 §15.2.3):
//
//	status(nfsstat4) + tag(utf8str_cs) + resarray<nfs_resop4>
//
// truncatedCount: number of ops that should appear in resarray (caller
// computed from OpStatus and truncation rule §2.7).
func encodeCompound4Res(b []byte, status uint32, tag string,
	resOps []encodedResOp) []byte {
	b = appendU32(b, status)
	b = appendString(b, tag)
	b = appendU32(b, uint32(len(resOps)))
	for _, op := range resOps {
		b = appendU32(b, op.Opcode)
		b = appendU32(b, op.OpStatus)
		if op.Result != nil {
			b = append(b, op.Result...)
		}
	}
	return b
}

type encodedResOp struct {
	Opcode   uint32
	OpStatus uint32
	Result   []byte // nil if OpStatus != 0 (truncated)
}

// --- NFSv4 per-op argument encoders ---

// encodeOPPUTFH: PUTFH (22) → fh
func encodeOPPUTFH(args []byte, fh []byte) []byte {
	return appendFilehandle(args, fh)
}

// encodeOPPUTROOTFH / encodeOPPUTPUBFH: no args
func encodeOPNoArgs() []byte { return nil }

// encodeOPGETATTR: GETATTR (9) → bitmap4
func encodeOPGETATTR(args []byte, mask []uint32) []byte {
	return encodeBitmap4(args, mask)
}

// encodeOPLOOKUP: LOOKUP (15) → component4 (name)
func encodeOPLOOKUP(args []byte, name string) []byte {
	return appendString(args, name)
}

// encodeOPLOOKUPP: no args
func encodeOPLOOKUPP() []byte { return nil }

// encodeOPREAD: READ (25) → stateid4 + offset(uint64) + count(uint32)
func encodeOPREAD(args []byte, stateid *NFSStateid, offset uint64, count uint32) []byte {
	args = appendStateid(args, stateid)
	args = appendU64(args, offset)
	return appendU32(args, count)
}

// encodeOPWRITE: WRITE (38) → stateid4 + offset(uint64) + stable(uint32) + data(opaque)
func encodeOPWRITE(args []byte, stateid *NFSStateid, offset uint64, stable uint32, data []byte) []byte {
	args = appendStateid(args, stateid)
	args = appendU64(args, offset)
	args = appendU32(args, stable)
	return appendOpaque(args, data)
}

// encodeOPCOMMIT: COMMIT (5) → offset(uint64) + count(uint32)
func encodeOPCOMMIT(args []byte, offset uint64, count uint32) []byte {
	args = appendU64(args, offset)
	return appendU32(args, count)
}

// encodeOPSETATTR: SETATTR (34) → stateid4 + fattr4
func encodeOPSETATTR(args []byte, stateid *NFSStateid, attrs *NFSAttributes) []byte {
	args = appendStateid(args, stateid)
	return encodeFattr4(args, attrs)
}

// encodeOPREMOVE: REMOVE (28) → component4
func encodeOPREMOVE(args []byte, name string) []byte {
	return appendString(args, name)
}

// encodeOPRENAME: RENAME (29) → oldname(component4) + newname(component4)
func encodeOPRENAME(args []byte, oldname, newname string) []byte {
	args = appendString(args, oldname)
	return appendString(args, newname)
}

// encodeOPLINK: LINK (11) → newdir(stateid) + newname(component4)
func encodeOPLINK(args []byte, newdirFh []byte, newname string) []byte {
	args = appendFilehandle(args, newdirFh)
	return appendString(args, newname)
}

// encodeOPACCESS: ACCESS (3) → access(uint32)
func encodeOPACCESS(args []byte, access uint32) []byte {
	return appendU32(args, access)
}

// encodeOPCLOSE: CLOSE (4) → seqid(uint32) + open_stateid(stateid4)
func encodeOPCLOSE(args []byte, seqid uint32, stateid *NFSStateid) []byte {
	args = appendU32(args, seqid)
	return appendStateid(args, stateid)
}

// encodeOPOPEN: OPEN (18) → seqid + share_access + share_deny + owner +
// openhow + claim. Per RFC 7531 §5.2 OPEN4args.
func encodeOPOPEN(args []byte, op *NFSv4CompoundOp) []byte {
	args = appendU32(args, op.Seqid)
	args = appendU32(args, op.ShareAccess)
	args = appendU32(args, op.ShareDeny)

	// open_owner4 = clientid(uint64) + owner(opaque)
	if op.Owner != nil {
		args = appendU64(args, op.Owner.Clientid)
		args = appendOpaque(args, op.Owner.Owner)
	} else {
		args = appendU64(args, op.Clientid)
		args = appendOpaque(args, nil)
	}

	// openflag4 (RFC 7531 §5.2) — discriminant opentype4:
	//   0 = OPEN4_NOCREATE → 4 bytes
	//   1 = OPEN4_CREATE → createhow4(createmode4 + body)
	args = encodeOpenflag4(args, op.OpenHow)

	// open_claim4 (RFC 7531 §5.2) — discriminant claim_type4:
	//   0 = CLAIM_NULL: component4 file
	//   1 = CLAIM_PREVIOUS: open_delegation_type4
	//   2 = CLAIM_DELEGATE_CUR: stateid4 + component4 file
	//   3 = CLAIM_DELEGATE_PREV: component4 file
	return encodeOpenClaim4(args, op.Claim, op.Name)
}

// encodeOpenflag4 encodes the openflag4 union (RFC 7531 §5.2).
func encodeOpenflag4(b []byte, oh *NFSOpenHow) []byte {
	if oh == nil {
		// Default: UNCHECKED4 (opentype=1 + createmode=0 + empty
		// fattr4 createattrs) per §3.3.1 / V20 / S12.
		b = appendU32(b, OpenTypeCREATE)
		b = appendU32(b, CreatemodeUNCHECKED4)
		return encodeFattr4(b, nil)
	}
	switch oh.Type {
	case "nocreate":
		return appendU32(b, OpenTypeNOCREATE)
	case "unchecked", "guarded", "exclusive":
		b = appendU32(b, OpenTypeCREATE)
		mode := uint32(CreatemodeUNCHECKED4)
		switch oh.Type {
		case "guarded":
			mode = CreatemodeGUARDED4
		case "exclusive":
			mode = CreatemodeEXCLUSIVE4
		}
		b = appendU32(b, mode)
		if mode == CreatemodeEXCLUSIVE4 {
			// createverf4 (8 bytes), no createattrs
			return append(b, oh.Verifier[:]...)
		}
		// createattrs: empty fattr4
		return encodeFattr4(b, nil)
	default:
		// Unknown type: fall back to NOCREATE (safer than auto-create).
		return appendU32(b, OpenTypeNOCREATE)
	}
}

// encodeOpenClaim4 encodes open_claim4. For CLAIM_NULL the file is
// supplied separately (in op.Name). For other claims, the file is read
// from claim.File.
func encodeOpenClaim4(b []byte, c *NFSClaim, name string) []byte {
	if c == nil {
		// Default CLAIM_NULL: write discriminant 0 + component4 file from name
		b = appendU32(b, ClaimNULL)
		return appendString(b, name)
	}
	switch c.Type {
	case "null":
		b = appendU32(b, ClaimNULL)
		return appendString(b, name)
	case "previous":
		b = appendU32(b, ClaimPREVIOUS)
		return appendU32(b, c.DelegateType)
	case "delegate_cur":
		b = appendU32(b, ClaimDELEGATE_CUR)
		b = appendStateid(b, c.DelegateStateid)
		return appendString(b, c.File)
	case "delegate_prev":
		// open_claim_delegate_prev4 = delegate_type + file_delegate_prev
		// (component4) (RFC 7531 §5.2)
		b = appendU32(b, ClaimDELEGATE_PREV)
		b = appendU32(b, c.DelegateType)
		return appendString(b, c.File)
	}
	// Unknown → default null
	b = appendU32(b, ClaimNULL)
	return appendString(b, name)
}

// encodeOPLOCK: LOCK (12) → locktype + reclaim + offset + length + locker
func encodeOPLOCK(args []byte, op *NFSv4CompoundOp) []byte {
	args = appendU32(args, op.LockType)
	if op.Reclaim {
		args = appendU32(args, 1)
	} else {
		args = appendU32(args, 0)
	}
	args = appendU64(args, op.Offset)
	args = appendU64(args, op.Length)
	// locker4: new_lock_owner (bool) — true → open_to_lock_owner4,
	// false → lock_owner4.
	if op.NewLockOwner {
		args = appendU32(args, 1)
		if op.OpenToLockOwner != nil {
			olo := op.OpenToLockOwner
			args = appendU32(args, olo.OpenSeqid)
			args = appendStateid(args, olo.OpenStateid)
			args = appendU32(args, olo.LockSeqid)
			if olo.LockOwner != nil {
				args = appendU64(args, olo.LockOwner.Clientid)
				args = appendOpaque(args, olo.LockOwner.Owner)
			} else {
				args = appendU64(args, 0)
				args = appendOpaque(args, nil)
			}
		}
	} else {
		// new_lock_owner=false → lock_owner4 = clientid(uint64) +
		// state_owner4{seqid(uint32), owner(opaque)} (RFC 7530 §16.10.2).
		// Pre-fix the seqid was missing and the branch wrote a stateid4
		// (16B), so tshark consumed the clientid/owner bytes as the
		// stateid and hit EOF (t111 frame 8 evidence).
		args = appendU32(args, 0)
		if op.LockOwner != nil {
			args = appendU64(args, op.LockOwner.Clientid)
			args = appendU32(args, op.LockOwner.Seqid)
			args = appendOpaque(args, op.LockOwner.Owner)
		} else {
			args = appendU64(args, 0)
			args = appendU32(args, 1)
			args = appendOpaque(args, nil)
		}
	}
	return args
}

// encodeOPLOCKT: LOCKT (13) → locktype + offset + length + owner
func encodeOPLOCKT(args []byte, op *NFSv4CompoundOp) []byte {
	args = appendU32(args, op.LockType)
	args = appendU64(args, op.Offset)
	args = appendU64(args, op.Length)
	if op.Owner != nil {
		args = appendU64(args, op.Owner.Clientid)
		return appendOpaque(args, op.Owner.Owner)
	}
	args = appendU64(args, 0)
	return appendOpaque(args, nil)
}

// encodeOPLOCKU: LOCKU (14) → locktype + seqid + stateid + offset + length
func encodeOPLOCKU(args []byte, op *NFSv4CompoundOp) []byte {
	args = appendU32(args, op.LockType)
	args = appendU32(args, op.Seqid)
	args = appendStateid(args, op.Stateid)
	args = appendU64(args, op.Offset)
	return appendU64(args, op.Length)
}

// encodeOPCREATE: CREATE (6) → objtype + name + attrs(fattr4)
func encodeOPCREATE(args []byte, op *NFSv4CompoundOp) []byte {
	args = appendU32(args, op.ObjType)
	args = appendString(args, op.Name)
	return encodeFattr4(args, op.Attrs)
}

// encodeOPSETCLIENTID: SETCLIENTID (35) → client + callback + callback_ident
func encodeOPSETCLIENTID(args []byte, op *NFSv4CompoundOp) []byte {
	if op.Client != nil {
		args = append(args, op.Client.Verifier[:]...)
		args = appendString(args, op.Client.Id)
	} else {
		var zero [8]byte
		args = append(args, zero[:]...)
		args = appendString(args, "")
	}
	if op.Callback != nil {
		args = appendU32(args, op.Callback.Program)
		args = appendString(args, op.Callback.NetID)
		args = appendString(args, op.Callback.Addr)
	} else {
		args = appendU32(args, 0)
		args = appendString(args, "")
		args = appendString(args, "")
	}
	return appendU32(args, op.CallbackIdent)
}

// encodeOPSETCLIENTID_CONFIRM: SETCLIENTID_CONFIRM (36) → clientid + verifier
func encodeOPSETCLIENTID_CONFIRM(args []byte, op *NFSv4CompoundOp) []byte {
	args = appendU64(args, op.Clientid)
	return append(args, op.ClientidVerifier[:]...)
}

// encodeOPDELEGPURGE: DELEGPURGE (7) → clientid
func encodeOPDELEGPURGE(args []byte, op *NFSv4CompoundOp) []byte {
	return appendU64(args, op.Clientid)
}

// encodeOPDELEGRETURN: DELEGRETURN (8) → stateid
func encodeOPDELEGRETURN(args []byte, op *NFSv4CompoundOp) []byte {
	return appendStateid(args, op.Stateid)
}

// encodeOPRENEW: RENEW (30) → clientid
func encodeOPRENEW(args []byte, op *NFSv4CompoundOp) []byte {
	return appendU64(args, op.Clientid)
}

// encodeOPRELEASE_LOCKOWNER: RELEASE_LOCKOWNER (39) → lock_owner
func encodeOPRELEASE_LOCKOWNER(args []byte, op *NFSv4CompoundOp) []byte {
	if op.Owner != nil {
		args = appendU64(args, op.Owner.Clientid)
		return appendOpaque(args, op.Owner.Owner)
	}
	args = appendU64(args, 0)
	return appendOpaque(args, nil)
}

// encodeOPREADDIR: READDIR (26) → cookie(uint64) + cookieverf(opaque[8]) +
// maxcount(uint32) + bitmap(bitmap4) per RFC 7531 §15.2.5.
func encodeOPREADDIR(args []byte, op *NFSv4CompoundOp) []byte {
	args = appendU64(args, op.Cookie)
	args = append(args, op.CookieVerf[:]...)
	args = appendU32(args, op.Count)
	return encodeBitmap4(args, op.AttrMask)
}

// encodeOPVERIFY: VERIFY (37) → fattr4
func encodeOPVERIFY(args []byte, op *NFSv4CompoundOp) []byte {
	return encodeFattr4(args, op.Attrs)
}

// encodeOPNVERIFY: NVERIFY (17) → fattr4
func encodeOPNVERIFY(args []byte, op *NFSv4CompoundOp) []byte {
	return encodeFattr4(args, op.Attrs)
}

// encodeOPSECINFO: SECINFO (33) → name
func encodeOPSECINFO(args []byte, op *NFSv4CompoundOp) []byte {
	return appendString(args, op.Name)
}

// encodeOPGETFH / READLINK / GETATTR reply result encoders follow in the
// nfs.go file. The above are arg encoders consumed by the CALL side.

// --- Result encoders for COMPOUND reply operations ---

// resultGETATTR: returns a fattr4 (bitmap + attr_vals) that mirrors the
// call's attr_mask. Uses defaultAttr4Value for each set bit.
func resultGETATTR(callWords []uint32) []byte {
	buf := make([]byte, 0, 32)
	buf = encodeBitmap4(buf, callWords)
	vals := encodeFattr4AttrVals(callWords, defaultAttr4Value)
	return encodeAttrList4(buf, vals)
}

// resultGETFH: returns an opaque fh (length + data + padding).
func resultGETFH(fh []byte) []byte {
	if fh == nil {
		fh = []byte{0x01}
	}
	return appendOpaque(nil, fh)
}

// resultStateid: returns a stateid4 = seqid(4) + other[12].
func resultStateid(s *NFSStateid) []byte {
	return appendStateid(nil, s)
}

// resultChangeInfo: change_info4 = bool atomic(4) + changeid4 before(8)
// + changeid4 after(8) = 20 bytes (RFC 7530 §15.1). Pre-fix this wrote
// only 16 bytes (missing the atomic discriminant), so tshark read the
// following result fields 4 bytes early and flagged [Malformed Packet:
// NFS] (t093 frame 9 evidence).
func resultChangeInfo() []byte {
	buf := make([]byte, 0, 20)
	buf = appendU32(buf, 1) // atomic = true
	buf = appendU64(buf, 0) // changeid before
	buf = appendU64(buf, 0) // changeid after
	return buf
}

// resultOpen: OPEN4resok = stateid4 + change_info4 + result flags +
// attrset (bitmap4) + open_delegation4 (RFC 7530 §16.17.3). The
// delegation is always OPEN_DELEGATE_NONE (4-byte discriminant, no
// follow-on data); the attrset is an empty bitmap. Total =
// 16 + 20 + 4 + 4 + 4 = 48 bytes. Pre-fix this branch reused the
// call's input stateid (the reply echoed the 16-byte request stateid,
// not the server-allocated one), so tshark read the following ops'
// bytes as change_info/rflags/delegation and hit EOF (t093 frame 9
// evidence).
func resultOpen(st *NFSStateid) []byte {
	buf := make([]byte, 0, 48)
	buf = appendStateid(buf, st)
	// append — NOT rebind: resultChangeInfo returns a fresh slice, so
	// assigning it to buf would discard the stateid already appended.
	buf = append(buf, resultChangeInfo()...)
	buf = appendU32(buf, 0) // result flags: 0x00000000
	buf = encodeBitmap4(buf, nil)
	buf = appendU32(buf, 0) // open_delegation4 type = OPEN_DELEGATE_NONE
	return buf
}

// resultCreate: CREATE4resok = change_info4 + newfh (fh4) + attrsset
// (bitmap4) (RFC 7530 §16.1.3). The newfh defaults to a 1-byte 0x01
// handle; attrsset is an empty bitmap.
func resultCreate() []byte {
	buf := make([]byte, 0, 40)
	buf = resultChangeInfo()
	buf = appendFilehandle(buf, []byte{0x01})
	return encodeBitmap4(buf, nil)
}

// resultRemoveRename: REMOVE4resok / RENAME4resok = change_info4 x2
// (RFC 7530 §16.24.3 / §16.26.3).
func resultRemoveRename() []byte {
	buf := make([]byte, 0, 40)
	buf = resultChangeInfo()
	return append(buf, resultChangeInfo()...)
}

// resultSetattr: SETATTR4resok = attrsset (bitmap4) — empty bitmap.
func resultSetattr() []byte {
	return encodeBitmap4(nil, nil)
}

// resultSecinfo: SECINFO4resok = secinfo4<> (RFC 7530 §16.33.2). Each
// entry: flavor4 + union { flavor_info4 = secinfo_style4 + payload }.
// AUTH_NONE (flavor 0) and AUTH_SYS (flavor 1, machine name opaque) are
// emitted as the two common flavors; SECINFO_STYLE4_PARENT = 0.
func resultSecinfo() []byte {
	buf := make([]byte, 0, 40)
	buf = appendU32(buf, 2) // secinfo4 count
	// AUTH_NONE: flavor + union (secinfo_style4, no payload).
	buf = appendU32(buf, AuthFlavorNone)
	buf = appendU32(buf, 0) // SECINFO_STYLE4_PARENT
	// AUTH_SYS: machine name opaque.
	buf = appendU32(buf, AuthFlavorSys)
	buf = appendU32(buf, 0) // SECINFO_STYLE4_PARENT
	buf = appendOpaque(buf, []byte("trafficgen"))
	return buf
}

// encodeOPOpenDowngrade: OPEN_DOWNGRADE4args = open_stateid4 + seqid4 +
// share_access4 + share_deny4 (RFC 7530 §16.19.2). Pre-fix the
// encoder had no case, so the op emitted zero args and tshark read the
// next op's bytes as its stateid (t092 frame evidence).
func encodeOPOpenDowngrade(args []byte, op *NFSv4CompoundOp) []byte {
	args = appendStateid(args, op.OpenStateid)
	args = appendU32(args, op.Seqid)
	args = appendU32(args, op.ShareAccess)
	return appendU32(args, op.ShareDeny)
}

// encodeOPOpenConfirm: OPEN_CONFIRM4args = open_stateid4 + seqid4
// (RFC 7530 §16.18.2 — stateid FIRST, unlike CLOSE4args which is
// seqid first). Pre-fix this reused encodeOPCLOSE, which wrote
// seqid first and hit a misparse in tshark.
func encodeOPOpenConfirm(args []byte, op *NFSv4CompoundOp) []byte {
	args = appendStateid(args, op.OpenStateid)
	return appendU32(args, op.Seqid)
}

// resultSetClientID: SETCLIENTID4res = clientid4(uint64) +
// setclientid_confirm4(verifier4 = opaque[8]).
func resultSetClientID(clientid uint64, verf [8]byte) []byte {
	buf := make([]byte, 0, 16)
	buf = appendU64(buf, clientid)
	return append(buf, verf[:]...)
}

// resultREAD: eof(bool) + data(opaque)
func resultREAD(eof bool, data []byte) []byte {
	buf := make([]byte, 0, 16)
	if eof {
		buf = appendU32(buf, 1)
	} else {
		buf = appendU32(buf, 0)
	}
	return appendOpaque(buf, data)
}

// resultWRITE: count(uint32) + committed(uint32) + verf(opaque[8])
func resultWRITE(count, committed uint32, verf [8]byte) []byte {
	buf := make([]byte, 0, 16)
	buf = appendU32(buf, count)
	buf = appendU32(buf, committed)
	return append(buf, verf[:]...)
}

// resultCOMMIT: COMMIT4res = status + verifier4 = opaque[8] (no length
// prefix). RFC 7531 §15.2.7 / S10.
func resultCOMMIT(verf [8]byte) []byte {
	return append([]byte(nil), verf[:]...)
}

// resultREADDIR: reply with empty entries + eof=true. entries length=0,
// eof=1.
func resultREADDIR(eof bool) []byte {
	buf := make([]byte, 0, 8)
	buf = appendU32(buf, 0) // entries length = 0
	if eof {
		buf = appendU32(buf, 1)
	} else {
		buf = appendU32(buf, 0)
	}
	return buf
}

// --- High-level NFSv4 fattr4 encoder ---

// encodeFattr4 encodes a fattr4 (RFC 7531 §3): bitmap4 + attrlist4.
func encodeFattr4(b []byte, a *NFSAttributes) []byte {
	// For a nil / empty attributes, emit an empty fattr4
	// (bitmap_len=0 + attr_vals_len=0 = 8 bytes).
	if a == nil {
		return encodeFattr4Empty(b)
	}
	// Build bitmap + values. For simplicity we map the NFSAttributes onto
	// the FATTR4_SIZE + FATTR4_MODE bits. The bitmap is always exactly
	// 2 words (word0 = SIZE bit if SetSize, word1 = MODE bit if SetMode).
	words := make([]uint32, 0, 2)
	if a.SetSize {
		words = append(words, 1<<4) // FATTR4_SIZE
	}
	if a.SetMode {
		// pad to 2 words if needed
		if len(words) < 1 {
			words = append(words, 0)
		}
		words = append(words, 1<<1) // FATTR4_MODE
	}
	if len(words) == 0 {
		return encodeFattr4Empty(b)
	}
	// Pad to 2 words
	for len(words) < 2 {
		words = append(words, 0)
	}
	b = encodeBitmap4(b, words)
	vals := encodeFattr4AttrVals(words, defaultAttr4Value)
	return encodeAttrList4(b, vals)
}

func encodeFattr4Empty(b []byte) []byte {
	return encodeAttrList4(encodeBitmap4(b, nil), nil)
}

// --- Utility ---

// recordMark returns the TCP record mark for a payload of length n.
func recordMark(n int) uint32 {
	return 0x80000000 | uint32(n)
}

// validateAuthFlavor returns nil if the flavor is supported.
func validateAuthFlavor(flavor uint32) error {
	switch flavor {
	case AuthFlavorNone, AuthFlavorSys:
		return nil
	case AuthFlavorGSS:
		return fmt.Errorf("RPCSEC_GSS not supported")
	case AuthFlavorShort:
		return fmt.Errorf("unsupported auth_flavor: %d", flavor)
	default:
		return fmt.Errorf("unsupported auth_flavor: %d", flavor)
	}
}
