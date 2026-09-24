// Package dcerpc builder：DCE/RPC v5 over TCP 组帧权威（D-DCERPC-1 契约 v2.0.0）。
// 16B common header + 七型 PDU + auth trailer + callWalker 单解析权威。
// 端序：整数按 drep fixture LE；UUID 混合端序（MS-RPCE §2.2.1.1.1）。
package dcerpc

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// PDU packet types（C706 §12.5.3.1；产生域七型）。
const (
	ptRequest     = 0
	ptResponse    = 2
	ptFault       = 3
	ptBind        = 11
	ptBindAck     = 12
	ptAlterCtx    = 14
	ptAlterCtxRes = 15
)

// Packet flags。
const (
	pfcFirstFrag = 0x01
	pfcLastFrag  = 0x02
	pfcObjUUID   = 0x80 // C706 §12.4：0x20=PFC_DID_NOT_EXECUTE，Object UUID=0x80
)

// uuidEncode parses a canonical UUID string to 16 wire bytes（MS/AD 混合端序：
// 前 3 组 LE、后 2 组原序）。编解码权威单点——用例逐字节钉（正例 48）。
func uuidEncode(s string) ([]byte, error) {
	h := strings.ReplaceAll(strings.ToLower(s), "-", "")
	if len(h) != 32 {
		return nil, fmt.Errorf("dcerpc: uuid %q must be 32 hex digits", s)
	}
	raw := make([]byte, 16)
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("dcerpc: uuid %q has non-hex character", s)
		}
		raw[i] = byte(v)
	}
	out := make([]byte, 16)
	// D1 4B LE、D2/D3 各 2B LE、D4 原序。
	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	out[4], out[5] = raw[5], raw[4]
	out[6], out[7] = raw[7], raw[6]
	copy(out[8:], raw[8:])
	return out, nil
}

func le16(b []byte, v int) []byte { return binary.LittleEndian.AppendUint16(b, uint16(v)) }
func le32(b []byte, v int64) []byte {
	return binary.LittleEndian.AppendUint32(b, uint32(v))
}

func stubBytes(hexStr string) ([]byte, error) {
	if hexStr == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("dcerpc: stub %q has non-hex character", hexStr)
	}
	return b, nil
}

// versionVec 取 [major, minor]（缺字段由 validator 拒——uuid_version_missing）。
func versionVec(v []int) (byte, byte) {
	if len(v) >= 2 {
		return byte(v[0]), byte(v[1])
	}
	return 0, 0
}

// commonHeader renders the fixed 16-byte header（LE 整数，drep 恒 10000000）。
func commonHeader(ptype, flags byte, fragLen, authLen int, callID uint32) []byte {
	b := make([]byte, 16)
	b[0], b[1] = 5, 0
	b[2], b[3] = ptype, flags
	b[4], b[5], b[6], b[7] = 0x10, 0, 0, 0
	binary.LittleEndian.PutUint16(b[8:], uint16(fragLen))
	binary.LittleEndian.PutUint16(b[10:], uint16(authLen))
	binary.LittleEndian.PutUint32(b[12:], callID)
	return b
}

// authTrailer renders pad + verifier（credentials opaque bytes）。
func authTrailer(a *core.DCERPCAuth) ([]byte, error) {
	creds, err := stubBytes(a.Credentials)
	if err != nil {
		return nil, err
	}
	b := make([]byte, a.Pad)
	b = append(b, byte(a.Type), byte(a.Level), byte(a.Pad), 0)
	b = le16(b, a.ContextID)
	return append(b, creds...), nil
}

// authLenOf 计 verifier 语义长度（MS-RPCE 2.2.2.1.1：AUTH VERIFIER =
// 6B 头 [pad_len/type/level/reserved/ctx_id u16] + AuthValue；pad 不计）。
func authLenOf(a *core.DCERPCAuth) int {
	creds, _ := stubBytes(a.Credentials)
	return len(creds) + 6
}

// assocGroupOf 取 bind/alter 事件的关联组（缺省 0）。
func assocGroupOf(ev *core.DCERPCEvent) uint32 {
	if ev.AssocGroup != nil {
		return uint32(*ev.AssocGroup)
	}
	return 0
}

// buildContextList renders context elements（BIND/ALTER_CTX 共用）。
func buildContextList(ctxs []core.DCERPCContext) ([]byte, error) {
	var b []byte
	for _, c := range ctxs {
		b = le16(b, c.ContextID)
		b = append(b, byte(len(c.Syntaxes)), 0)
		ab, err := uuidEncode(c.Abstract)
		if err != nil {
			return nil, err
		}
		b = append(b, ab...)
		if len(c.AbstractVersion) < 2 {
			return nil, fmt.Errorf("dcerpc: context %d abstract_version missing (uuid)", c.ContextID)
		}
		b = append(b, byte(c.AbstractVersion[0]), byte(c.AbstractVersion[1]), 0, 0)
		for _, s := range c.Syntaxes {
			ub, err := uuidEncode(s.UUID)
			if err != nil {
				return nil, err
			}
			b = append(b, ub...)
			mj, mi := versionVec(s.Version)
			b = append(b, mj, mi, 0, 0)
		}
	}
	return b, nil
}

// buildBind renders BIND(11)/ALTER_CONTEXT(14) client PDU。
func buildBind(ev *core.DCERPCEvent, ptype byte, callID uint32) ([]byte, error) {
	mx, mr := ev.MaxXmit, ev.MaxRecv
	if mx == 0 {
		mx = 5840
	}
	if mr == 0 {
		mr = 5840
	}
	body := le16(nil, mx)
	body = le16(body, mr)
	ag := 0
	if ev.AssocGroup != nil {
		ag = *ev.AssocGroup
	}
	body = le32(body, int64(ag))
	body = append(body, byte(len(ev.Contexts)), 0)
	body = le16(body, 0)
	list, err := buildContextList(ev.Contexts)
	if err != nil {
		return nil, err
	}
	body = append(body, list...)
	fragLen := 16 + len(body)
	var authLen int
	var trailer []byte
	if ev.Auth != nil {
		t, err := authTrailer(ev.Auth)
		if err != nil {
			return nil, err
		}
		trailer = t
		authLen = authLenOf(ev.Auth)
		fragLen += len(t)
	}
	out := commonHeader(ptype, pfcFirstFrag|pfcLastFrag, fragLen, authLen, callID)
	out = append(out, body...)
	return append(out, trailer...), nil
}

// buildBindAck renders BIND_ACK(12)/ALTER_CONTEXT_RESP(15) server PDU。
func buildBindAck(r *core.DCERPCRespond, ptype byte, callID uint32, assocGroup uint32) ([]byte, error) {
	// C706 §12.5.4.2 header_t：mx(2) mr(2) assoc_group(4) + secondary——
	// BIND_ACK 携 sec_addr；ALTER_CONTEXT_RESP sec_addr_len=0 但 assoc 仍在。
	body := le16(nil, 5840)
	body = le16(body, 5840)
	body = le32(body, int64(assocGroup))
	// sec_addr_len 两型恒写：BIND_ACK 携串，ALTER_CONTEXT_RESP 置 0。
	sec := []byte(r.Secondary)
	if ptype != ptBindAck {
		sec = nil
	}
	body = le16(body, len(sec))
	body = append(body, sec...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	body = le16(body, len(r.Results))
	body = le16(body, 0)
	for _, res := range r.Results {
		body = le16(body, res.Result)
		body = le16(body, res.Reason)
		if res.UUID == "" {
			return nil, fmt.Errorf("dcerpc: result for context %d missing transfer uuid", res.ContextID)
		}
		ub, err := uuidEncode(res.UUID)
		if err != nil {
			return nil, err
		}
		body = append(body, ub...)
		mj, mi := versionVec(res.Version)
		body = append(body, mj, mi, 0, 0)
	}
	out := commonHeader(ptype, pfcFirstFrag|pfcLastFrag, 16+len(body), 0, callID)
	return append(out, body...), nil
}

// buildCallBody renders REQUEST/RESPONSE/FAULT body 前缀。
func buildCallBody(r *core.DCERPCRespond, ev *core.DCERPCEvent, ptype byte) []byte {
	switch ptype {
	case ptRequest:
		ah := 0
		if ev != nil && ev.AllocHint != nil {
			ah = *ev.AllocHint
		}
		cid := 0
		if ev != nil && ev.ContextID != nil {
			cid = *ev.ContextID
		}
		op := 0
		if ev != nil && ev.Opnum != nil {
			op = *ev.Opnum
		}
		body := le32(nil, int64(ah))
		body = le16(body, cid)
		return le16(body, op)
	default: // response/fault
		ah := 0
		if r != nil && r.AllocHint != nil {
			ah = *r.AllocHint
		}
		cid := 0
		if ev != nil && ev.ContextID != nil {
			cid = *ev.ContextID
		}
		cc := 0
		if r != nil {
			cc = r.CancelCount
		}
		body := le32(nil, int64(ah))
		body = le16(body, cid)
		body = append(body, byte(cc), 0)
		if ptype == ptFault {
			st := 0
			if r != nil && r.Status != nil {
				st = *r.Status
			}
			body = le32(body, int64(st))
			body = le32(body, 0)
		}
		return body
	}
}

// buildCallPDU renders one REQUEST/RESPONSE/FAULT frame（含分片与 auth）。
func buildCallPDU(ev *core.DCERPCEvent, r *core.DCERPCRespond, ptype byte, callID uint32, stub []byte, flags byte) ([]byte, error) {
	body := buildCallBody(r, ev, ptype)
	if ptype == ptRequest && ev != nil && ev.ObjectUUID != "" {
		ou, err := uuidEncode(ev.ObjectUUID)
		if err != nil {
			return nil, err
		}
		body = append(body, ou...)
		flags |= pfcObjUUID
	}
	body = append(body, stub...)
	var authLen int
	var trailer []byte
	auth := ev.Auth
	if ptype != ptRequest && r != nil {
		auth = r.Auth
	}
	if auth != nil {
		t, err := authTrailer(auth)
		if err != nil {
			return nil, err
		}
		trailer = t
		authLen = authLenOf(auth)
	}
	fragLen := 16 + len(body) + len(trailer)
	out := commonHeader(ptype, flags, fragLen, authLen, callID)
	out = append(out, body...)
	return append(out, trailer...), nil
}

// splitStub 均分 stub 为 n 片（裁定7：每片自含完整头）。
func splitStub(stub []byte, n int) [][]byte {
	if n <= 1 {
		return [][]byte{stub}
	}
	pieces := make([][]byte, n)
	base := len(stub) / n
	rem := len(stub) % n
	off := 0
	for i := 0; i < n; i++ {
		size := base
		if i < rem {
			size++
		}
		pieces[i] = stub[off : off+size]
		off += size
	}
	return pieces
}

// callWalker：call_id 单解析权威（bacnet invokeWalker 先例）。
type callWalker struct{ ctr int }

func (w *callWalker) request(declared *int) uint32 {
	if declared != nil {
		v := uint32(*declared)
		if int(v) > w.ctr {
			w.ctr = int(v)
		}
		return v
	}
	w.ctr++
	return uint32(w.ctr)
}

// frame is one wire frame with transport direction.
type frame struct {
	up    bool
	bytes []byte
}

// buildEventFrames renders one event's frames（up=client，down=server）。
func buildEventFrames(ev *core.DCERPCEvent, w *callWalker) ([]frame, error) {
	var out []frame
	switch ev.Kind {
	case "bind", "alter_ctx":
		pt := byte(ptBind)
		if ev.Kind == "alter_ctx" {
			pt = ptAlterCtx
		}
		cid := w.request(ev.CallID)
		up, err := buildBind(ev, pt, cid)
		if err != nil {
			return nil, err
		}
		out = append(out, frame{up: true, bytes: up})
		if r := ev.Respond; r != nil {
			rid := cid
			if r.CallID != nil {
				rid = uint32(*r.CallID)
			}
			pt2 := byte(ptBindAck)
			if r.Ack == "alter_ctx_resp" {
				pt2 = byte(ptAlterCtxRes)
			}
			down, err := buildBindAck(r, pt2, rid, assocGroupOf(ev))
			if err != nil {
				return nil, err
			}
			out = append(out, frame{up: false, bytes: down})
		}
	case "request":
		cid := w.request(ev.CallID)
		stub, err := stubBytes(ev.Stub)
		if err != nil {
			return nil, err
		}
		for i, piece := range splitStub(stub, ev.Fragments) {
			flags := byte(pfcFirstFrag | pfcLastFrag)
			if ev.Fragments > 1 {
				flags = 0
				if i == 0 {
					flags |= pfcFirstFrag
				}
				if i == ev.Fragments-1 {
					flags |= pfcLastFrag
				}
			}
			up, err := buildCallPDU(ev, nil, ptRequest, cid, piece, flags)
			if err != nil {
				return nil, err
			}
			out = append(out, frame{up: true, bytes: up})
		}
		if r := ev.Respond; r != nil {
			rid := cid
			if r.CallID != nil {
				rid = uint32(*r.CallID)
			}
			rstub, err := stubBytes(r.Stub)
			if err != nil {
				return nil, err
			}
			for i, piece := range splitStub(rstub, r.Fragments) {
				flags := byte(pfcFirstFrag | pfcLastFrag)
				if r.Fragments > 1 {
					flags = 0
					if i == 0 {
						flags |= pfcFirstFrag
					}
					if i == r.Fragments-1 {
						flags |= pfcLastFrag
					}
				}
				pt := byte(ptResponse)
				if r.Ack == "fault" {
					pt = byte(ptFault)
				}
				down, err := buildCallPDU(ev, r, pt, rid, piece, flags)
				if err != nil {
					return nil, err
				}
				out = append(out, frame{up: false, bytes: down})
			}
		}
	default:
		return nil, fmt.Errorf("dcerpc: unknown event kind %q", ev.Kind)
	}
	return out, nil
}

// DCERPCGenerator generates DCE/RPC events（edp 同构）。
type DCERPCGenerator struct{}

func (g *DCERPCGenerator) Name() string { return "dcerpc" }

// GenEvents marks this generator as a terminal event producer。
func (g *DCERPCGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent satisfies the producer marker only。
func (g *DCERPCGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("dcerpc generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func buildSessionGroups(sess *core.DCERPCSession) ([][]layers.MessageEvent, error) {
	var out [][]layers.MessageEvent
	w := &callWalker{}
	for i := range sess.Events {
		frs, err := buildEventFrames(&sess.Events[i], w)
		if err != nil {
			return nil, err
		}
		var group []layers.MessageEvent
		for _, f := range frs {
			group = append(group, layers.MessageEvent{Up: f.up, Bytes: f.bytes})
		}
		out = append(out, group)
	}
	return out, nil
}

func (g *DCERPCGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("dcerpc generator: EmitMsg is nil")
	}
	cfg := req.Meta.DCERPC
	if cfg == nil {
		cfg = &core.DCERPCConfig{}
	}
	// 会话级 dst_port：0=继承链级（FieldContract 135）；dynamic 会话显式。
	sessionPort := func(si int) uint16 {
		if si < len(cfg.Sessions) {
			return cfg.Sessions[si].DstPort
		}
		return 0
	}
	emitSession := func(ev layers.MessageEvent, si int) error {
		ev.DstPort = sessionPort(si)
		if si < len(cfg.Sessions) {
			ev.SrcPort = cfg.Sessions[si].SrcPort
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return req.EmitMsg(ev)
	}
	if cfg.Concurrent {
		perSession := make([][][]layers.MessageEvent, len(cfg.Sessions))
		maxLen := 0
		for si := range cfg.Sessions {
			groups, err := buildSessionGroups(&cfg.Sessions[si])
			if err != nil {
				return err
			}
			perSession[si] = groups
			if len(groups) > maxLen {
				maxLen = len(groups)
			}
		}
		for j := 0; j < maxLen; j++ {
			for si := range perSession {
				if j >= len(perSession[si]) {
					continue
				}
				for _, ev := range perSession[si][j] {
					if err := emitSession(ev, si); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	for si := range cfg.Sessions {
		groups, err := buildSessionGroups(&cfg.Sessions[si])
		if err != nil {
			return err
		}
		for _, group := range groups {
			for _, ev := range group {
				if err := emitSession(ev, si); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func init() {
	layers.RegisterLayerGenerator("dcerpc", func() (layers.LayerGenerator, error) {
		return &DCERPCGenerator{}, nil
	})
	layers.RegisterLayerValidator("dcerpc", func(spec *core.FlowSpec) error {
		p := Planner{}
		return p.Validate(*spec)
	})
}
