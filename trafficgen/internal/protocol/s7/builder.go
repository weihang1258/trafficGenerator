package s7

import (
	"encoding/binary"
	"fmt"
)

// S7COMM function codes.
const (
	funcSetup     = 0xf0
	funcReadVar   = 0x04
	funcWriteVar  = 0x05
	funcKeepalive = 0xfa
)

// s7Header prepends TPKT + COTP + the fixed S7COMM header prefix up to the
// rosctr byte. The returned slice is length len(headerPrefix)+1 and the caller
// continues appending redid/pduref/parlg/datlg and, for responses, errcls/errcod.
func s7header(rosctr byte) []byte {
	// TPKT(4, len patched by finalize) + COTP DT(3: 02 f0 80) + S7 protid(1: 32) + rosctr.
	// Body offset map: [7]=protid(0x32), [8]=rosctr, [9:11]=redid, [11:13]=pduref,
	// [13:15]=parlg, [15:17]=datlg; ack-data adds errcls[17], errcod[18].
	return []byte{0x03, 0x00, 0x00, 0x00, 0x02, 0xf0, 0x80, 0x32, rosctr}
}

// BuildConnectConfirm builds the full COTP Connect Confirm (CC) that echoes the
// CR's source reference as the destination reference and repeats the TPDU/TSAP
// parameters (design §3.3). The standalone planner previously emitted a 6-byte
// stub (`06 d0 00 00 00 01 00`) that tshark could not role-resolve as a real CC.
func BuildConnectConfirm() []byte {
	return []byte{0x03, 0x00, 0x00, 0x16, 0x11, 0xd0, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02}
}

// readValueForItem synthesizes the value bytes a Read Ack_Data echoes back for
// one item. Deterministic and per-item so multi-item reads produce distinct
// results (design §6 S6 example uses 0x1234 for item0; the two-item variant
// carries 0x1234/0x5678). Element-count*bytes is filled by cycling the seed.
func readValueForItem(item S7Item) []byte {
	// Seed from the item's (db, address) so item0 stays 0x1234 and later items
	// drift. item0 = DB1 addr0 → off=1 → no shift applied below (off==1 is the
	// first item's identity, kept stable).
	v := []byte{0x12, 0x34}
	off := item.DBNumber
	if item.Address > 0 {
		off += uint16(item.Address)
	}
	if off > 1 {
		v[0] += byte(off << 1)
		v[1] += byte(off << 2)
	}
	n := item.Length
	if n == 0 {
		n = 1
	}
	out := make([]byte, 0, int(n)*2)
	for len(out) < int(n)*2 {
		out = append(out, v...)
	}
	return out[: int(n)*2]
}

// finalize patches the TPKT total-length field (bytes 2-3, big-endian) from the
// final body length.
func finalize(body []byte) {
	binary.BigEndian.PutUint16(body[2:4], uint16(len(body)))
}

func BuildConnectionRequest(cfg *S7Config) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("s7: config is nil")
	}
	return []byte{0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02}, nil
}

// BuildSetup builds the Setup communication job (response=false) or its ack
// (response=true). The request negotiates the configured PDU size (default
// 480); the response echoes the function/AmQ and returns the smaller PDU 240.
func BuildSetup(cfg *S7Config, response bool) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("s7: config is nil")
	}
	ref := cfg.PDURef
	if ref == 0 {
		ref = 1
	}
	pduLen := uint16(480)
	if response {
		pduLen = 240
	}
	body := s7header(rosctrJob)
	body = append(body, 0x00, 0x00, byte(ref>>8), byte(ref), 0x00, 0x08, 0x00, 0x00) // redid, pduref, parlg=8, datlg=0
	if response {
		body[8] = rosctrAckData
		body = append(body, 0x00, 0x00) // errcls, errcod
	}
	// param(8B): func, reserved1, maxamq_calling(2), maxamq_called(2), pdu_length(2)
	body = append(body, funcSetup, 0x00, 0x00, 0x01, 0x00, 0x01, byte(pduLen>>8), byte(pduLen))
	finalize(body)
	return body, nil
}

// itemSpec encodes one S7ANY variable specification (the bytes that begin each
// item in a Read/Write param list).
func itemSpec(item S7Item) []byte {
	addr := item.Address*8 + uint32(item.Bit)
	return []byte{
		0x12, 0x0a,                      // variable spec type + length of following address spec
		0x10,                            // syntax id S7ANY
		item.TransportSize,               // transport size
		byte(item.Length >> 8), byte(item.Length),
		byte(item.DBNumber >> 8), byte(item.DBNumber),
		item.Area,
		byte(addr >> 16), byte(addr >> 8), byte(addr),
	}
}

// BuildRead builds a Read Var job request.
func BuildRead(cfg *S7Config, cmd S7Command) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("s7: config is nil")
	}
	if err := validateCommand(cmd); err != nil {
		return nil, err
	}
	ref := cmd.PDURef
	if ref == 0 {
		ref = cfg.PDURef + 1
	}
	if ref == 0 {
		ref = 1
	}
	body := s7header(rosctrJob)
	body = append(body, 0x00, 0x00, byte(ref>>8), byte(ref), 0x00, 0x0e, 0x00, 0x01, funcReadVar, byte(len(cmd.Items)))
	for _, item := range cmd.Items {
		body = append(body, itemSpec(item)...)
	}
	body = append(body, terminator) // read jobs carry one trailing data byte (datlg=1)
	finalize(body)
	return body, nil
}

// BuildWrite builds a Write Var job request carrying per-item value bytes.
func BuildWrite(cfg *S7Config, cmd S7Command) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("s7: config is nil")
	}
	if err := validateCommand(cmd); err != nil {
		return nil, err
	}
	ref := cmd.PDURef
	if ref == 0 {
		ref = cfg.PDURef
	}
	if ref == 0 {
		ref = 1
	}
	body := s7header(rosctrJob)
	// data section: per item [returncode(0)] + transport_size + length + value
	data := []byte{}
	for i := range cmd.Items {
		itemVal := []byte{}
		if i < len(cmd.Value) {
			itemVal = cmd.Value[i]
		}
		sz := cmd.Items[i].TransportSize
		ln := uint16(len(itemVal))
		if ln == 0 {
			ln = 1
		}
		data = append(data, 0x00, sz, byte(ln>>8), byte(ln))
		data = append(data, itemVal...)
	}
	body = append(body, 0x00, 0x00, byte(ref>>8), byte(ref), 0x00, 0x0e, byte(len(data)>>8), byte(len(data)), funcWriteVar, byte(len(cmd.Items)))
	for _, item := range cmd.Items {
		body = append(body, itemSpec(item)...)
	}
	body = append(body, data...)
	finalize(body)
	return body, nil
}

// BuildReadAck builds the Ack_Data response to a Read Var job. The parameter
// echoes func/itemcount; the data section carries per-item result tuples.
func BuildReadAck(cfg *S7Config, cmd S7Command) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("s7: config is nil")
	}
	ref := cmd.PDURef
	if ref == 0 {
		ref = cfg.PDURef + 1
	}
	if ref == 0 {
		ref = 1
	}
	// header: redid, pduref(echo), parlg=2, datlg(patched), errcls, errcod
	body := s7header(rosctrAckData)
	body = append(body, 0x00, 0x00, byte(ref>>8), byte(ref), 0x00, 0x02, 0x00, 0x00, 0x00, 0x00)
	body = append(body, funcReadVar, byte(len(cmd.Items)))
	data := []byte{}
	for i := range cmd.Items {
		itemVal := []byte(nil)
		if i < len(cmd.Value) {
			itemVal = cmd.Value[i]
		}
		if len(itemVal) == 0 {
			itemVal = readValueForItem(cmd.Items[i])
		}
		sz := cmd.Items[i].TransportSize
		ln := uint16(len(itemVal))
		if ln == 0 {
			ln = 1
			itemVal = []byte{0x00}
		}
		data = append(data, 0xff, sz, byte(ln>>8), byte(ln))
		data = append(data, itemVal...)
	}
	binary.BigEndian.PutUint16(body[15:17], uint16(len(data)))
	body = append(body, data...)
	finalize(body)
	return body, nil
}

// BuildWriteAck builds the Ack_Data response to a Write Var job. The parameter
// is just the Write function code; the data section is the return code per item.
func BuildWriteAck(cfg *S7Config, cmd S7Command) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("s7: config is nil")
	}
	ref := cmd.PDURef
	if ref == 0 {
		ref = cfg.PDURef
	}
	if ref == 0 {
		ref = 1
	}
	// header: redid, pduref(echo), parlg=1, datlg=len(data)=2, errcls, errcod
	body := s7header(rosctrAckData)
	body = append(body, 0x00, 0x00, byte(ref>>8), byte(ref), 0x00, 0x01, 0x00, 0x02, 0x00, 0x00)
	body = append(body, funcWriteVar)
	body = append(body, 0x00, 0x00) // write ack data: per-item return code 0x00
	finalize(body)
	return body, nil
}

// BuildKeepalive builds the keep-alive job (ROSCTR=1, parlg=1, func=0xfa). It
// has no response.
func BuildKeepalive(cfg *S7Config) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("s7: config is nil")
	}
	body := s7header(rosctrJob)
	ref := cfg.PDURef
	body = append(body, 0x00, 0x00, byte(ref>>8), byte(ref), 0x00, 0x01, 0x00, 0x00, funcKeepalive)
	finalize(body)
	return body, nil
}

// BuildErrorAck builds an Ack_Data response carrying an error class/code.
func BuildErrorAck(cfg *S7Config, cmd S7Command) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("s7: config is nil")
	}
	ref := cmd.PDURef
	if ref == 0 {
		ref = cfg.PDURef
	}
	if ref == 0 {
		ref = 1
	}
	errcls, errcod := byte(0x04), byte(0x01)
	if cmd.ErrClass != nil {
		errcls = *cmd.ErrClass
	}
	if cmd.ErrCode != nil {
		errcod = *cmd.ErrCode
	}
	body := s7header(rosctrAckData)
	body = append(body, 0x00, 0x00, byte(ref>>8), byte(ref), 0x00, 0x01, 0x00, 0x00, errcls, errcod) // parlg=1, datlg=0
	body = append(body, funcWriteVar)
	finalize(body)
	return body, nil
}

// BuildReadSZL builds a Read SZL job (ROSCTR=7 Userdata). The param section is
// a fixed Userdata request header carrying szl_id/szl_index; the data section
// carries the SZL item data.
func BuildReadSZL(cfg *S7Config, cmd S7Command) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("s7: config is nil")
	}
	ref := cmd.PDURef
	if ref == 0 {
		ref = cfg.PDURef
	}
	if ref == 0 {
		ref = 1
	}
	body := s7header(rosctrUserdata)
	// param(8B), datlg(8B)
	body = append(body, 0x00, 0x00, byte(ref>>8), byte(ref), 0x00, 0x08, 0x00, 0x08)
	// Userdata func header: request header id 0x12, then SZL param block.
	body = append(body, 0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, byte(cmd.SzlIndex))
	// data: returncode, transportsize, length, szl_id, index
	body = append(body, 0xff, 0x09, 0x00, 0x04, byte(cmd.SzlID>>8), byte(cmd.SzlID), 0x00, byte(cmd.SzlIndex))
	finalize(body)
	return body, nil
}

// BuildReadSZLAck builds the Read SZL response (ROSCTR=7 Userdata) echoing the
// requested szl_id with one SZL entry.
func BuildReadSZLAck(cfg *S7Config, cmd S7Command) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("s7: config is nil")
	}
	ref := cmd.PDURef
	if ref == 0 {
		ref = cfg.PDURef
	}
	if ref == 0 {
		ref = 1
	}
	body := s7header(rosctrUserdata)
	// param(12B), datlg(patched)
	body = append(body, 0x00, 0x00, byte(ref>>8), byte(ref), 0x00, 0x0c, 0x00, 0x00)
	body = append(body, 0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00)
	// data: returncode, transportsize, length(=48=0x30), szl_id, index
	body = append(body, 0xff, 0x09, 0x00, 0x30, byte(cmd.SzlID>>8), byte(cmd.SzlID), 0x00, byte(cmd.SzlIndex))
	// pad the SZL block to fill datlg=56
	for len(body) < 7+10+12+56 {
		body = append(body, 0x00)
	}
	binary.BigEndian.PutUint16(body[15:17], uint16(len(body)-7-10-12))
	finalize(body)
	return body, nil
}

const terminator = 0x00

func validateCommand(cmd S7Command) error {
	if cmd.ROSCTR != 0 && cmd.ROSCTR != rosctrJob && cmd.ROSCTR != rosctrAckData && cmd.ROSCTR != rosctrUserdata {
		return fmt.Errorf("s7: invalid rosctr %d", cmd.ROSCTR)
	}
	items := cmd.Items
	if len(items) > 0 {
		for _, item := range items {
			if !validArea(item.Area) {
				return fmt.Errorf("s7: invalid area 0x%02x", item.Area)
			}
			if item.Address > 0xFFFF {
				return fmt.Errorf("s7: invalid address %d", item.Address)
			}
			if item.Bit > 7 {
				return fmt.Errorf("s7: invalid bit %d", item.Bit)
			}
			if item.Length == 0 {
				return fmt.Errorf("s7: length must be > 0")
			}
		}
	}
	return nil
}

func validArea(area uint8) bool {
	switch area {
	case 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x1c, 0x1d:
		return true
	}
	return false
}
