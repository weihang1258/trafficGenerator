// Package megaco layer generator: walks sessions, emits one MessageEvent
// per megaco message (UDP = one datagram, TCP = one TPKT-framed PDU).
// transactionId "auto" is replaced with a per-session counter starting at 1;
// "same_as_request:<i>" is resolved to the i-th request's id of the session.
package megaco

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// MegacoGenerator is the megaco terminal-layer generator.
type MegacoGenerator struct{}

func (g *MegacoGenerator) Name() string { return "megaco" }

// sessionRun is the per-session generation state.
type sessionRun struct {
	idx        int
	sess       core.MegacoSession
	ctrlSeq    uint32
	ackSeq     uint32
	requestIDs []uint32 // request transactionIds in emission order
	eventsSeen int
	srcIP      string // flow source IP（mId 派生回退，D-MEGACO-1 修 pickMid）
}

// empty-config default flow (P0b baseline): one MG→MGC SC(Restart) registration
// pair on UDP/2944. The minimal legal Megaco message for both sides.
func defaultFlow() *core.MegacoConfig {
	return &core.MegacoConfig{
		Profile:   "megaco_v1_text",
		Encoding:  "text",
		Version:   1,
		TokenForm: "long",
		Sessions: []core.MegacoSession{{
			Role: "mg",
			Events: []core.MegacoEvent{
				{
					Kind: "message", Direction: "c2s",
					Transactions: []core.MegacoTransaction{{
						Type: "request",
						Actions: []core.MegacoAction{{
							Context: "-",
							Commands: []core.MegacoCommand{{
								Name: "ServiceChange", Termination: "ROOT",
								Descriptor: &core.MegacoDescriptor{
									Services: &core.MegacoServices{
										Method: "Restart", Reason: "901 Cold Boot",
										Profile: "ResGW/1",
									},
								},
							}},
						}},
					}},
				},
				{
					Kind: "message", Direction: "s2c",
					Transactions: []core.MegacoTransaction{{
						Type: "reply",
						Actions: []core.MegacoAction{{
							Context: "-",
							Commands: []core.MegacoCommand{{
								Name: "ServiceChange", Termination: "ROOT",
								Descriptor: &core.MegacoDescriptor{
									Services: &core.MegacoServices{Profile: "ResGW/1"},
								},
							}},
						}},
					}},
				},
			},
		}},
	}
}

func (g *MegacoGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("megaco generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.Megaco
	if cfg == nil || len(cfg.Sessions) == 0 {
		cfg = defaultFlow()
	}
	form := cfg.TokenForm
	if form == "" {
		form = "long"
	}
	dstIP := req.Meta.DstIP

	runs := make([]*sessionRun, len(cfg.Sessions))
	for i, s := range cfg.Sessions {
		runs[i] = &sessionRun{idx: i, sess: s, srcIP: req.Meta.SrcIP}
	}

	emit := func(ev layers.MessageEvent) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return req.EmitMsg(ev)
	}

	concurrent := false
	for _, s := range cfg.Sessions {
		if s.Concurrent {
			concurrent = true
			break
		}
	}
	if concurrent {
		// Round-robin per event index (single-association order preserved
		// because we walk each session's events in order at its own index).
		maxLen := 0
		for _, r := range runs {
			if len(r.sess.Events) > maxLen {
				maxLen = len(r.sess.Events)
			}
		}
		tcpCarrier := isTCPCarrier(req)
		for j := 0; j < maxLen; j++ {
			for _, r := range runs {
				if j >= len(r.sess.Events) {
					continue
				}
				if err := emitSessionEvent(cfg, r, r.sess.Events[j], form, dstIP, tcpCarrier, emit); err != nil {
					return err
				}
			}
		}
		return nil
	}
	tcpCarrier := isTCPCarrier(req)
	for _, r := range runs {
		if err := emitSessionEvents(cfg, r, form, dstIP, tcpCarrier, emit); err != nil {
			return err
		}
	}
	return nil
}

// emitSessionEvents walks one session's events in order and emits one
// MessageEvent per megaco message.
func emitSessionEvents(cfg *core.MegacoConfig, r *sessionRun, form, dstIP string, tcpCarrier bool, emit func(layers.MessageEvent) error) error {
	for _, ev := range r.sess.Events {
		if err := emitSessionEvent(cfg, r, ev, form, dstIP, tcpCarrier, emit); err != nil {
			return err
		}
	}
	return nil
}

func emitSessionEvent(cfg *core.MegacoConfig, r *sessionRun, ev core.MegacoEvent, form, dstIP string, tcpCarrier bool, emit func(layers.MessageEvent) error) error {
	// Resolve transactionIds for this message.
	txs := make([]core.MegacoTransaction, len(ev.Transactions))
	for i, tx := range ev.Transactions {
		rx, err := resolveTransactionID(tx, r)
		if err != nil {
			return fmt.Errorf("megaco: sessions[%d].events[%d].transactions[%d]: %w", r.idx, r.eventsSeen, i, err)
		}
		txs[i] = rx
		r.eventsSeen++
	}

	// Pick the mId per direction (per role flip; design §5.1). D-MEGACO-1 修：
	// 空显式值按角色+地址派生（role=mg：mid=[src_ip]/peer=[dst_ip]；
	// role=mgc 对调），旧版 s2c 空 peer_mid 错落 mid 本身。
	mid := pickMid(r.sess, ev.Direction, r.srcIP, dstIP)
	body := BuildMessageText(cfg, versionFor(cfg), mid, txs, form)

	// wire_fault 在 validator 即拒（D-MEGACO-1 裁定：所有负例以 task error
	// 呈现，绝不落线）；此处防御性再拒（防绕过 Validate 直驱）。
	if wf := ev.WireFault; wf == "" {
		wf = cfg.WireFault
		if wf != "" {
			return fmt.Errorf("megaco: sessions[%d]: wire fault %q rejected at generation (validator gate missed)", r.idx, wf)
		}
	}

	// TCP carrier prepends RFC 1006 TPKT 4B header (version=0x03, reserved=0x00,
	// 16-bit big-endian length = 4+message_length), Annex D.2 SHALL. UDP carrier
	// is raw bytes (no framing).
	if tcpCarrier {
		body = string(WrapTPKT([]byte(body)))
	}

	up := ev.Direction != "s2c"
	// Per-session port overrides (handoff uses src_port increment; user can
	// override dst_port for non-default megaco peers). r.sess.DstPort/SrcPort
	// take precedence over the chain-level defaults; the chain plan applies
	// them on the L4 layer (UDP/TCP) at emit time.
	dstPort := r.sess.DstPort
	srcPort := r.sess.SrcPort
	return emit(layers.MessageEvent{
		Up:      up,
		Bytes:   []byte(body),
		DstIP:   dstIP,
		DstPort: dstPort,
		SrcPort: srcPort,
	})
}

// isTCPCarrier detects whether the megaco layer rides TCP (Annex D.2 TPKT
// framing) or UDP (Annex D.1 raw datagram). The chain shape is the carrier
// truth: megaco 的直接外层（链上 megaco 的前一层）是 tcp 即 TCP 载体，
// udp 即 UDP 载体（FieldContract 双 carrier 同值 2944，见 registry 行）。
func isTCPCarrier(req *layers.GenRequest) bool {
	if req == nil {
		return false
	}
	for i, l := range req.Chain {
		if l.Name == "megaco" && i > 0 {
			return req.Chain[i-1].Name == "tcp"
		}
	}
	return false
}

// resolveTransactionID replaces "auto" / "same_as_request:<i>" with concrete
// numeric ids. Explicit numeric strings (boundary cases) are passed through.
func resolveTransactionID(tx core.MegacoTransaction, r *sessionRun) (core.MegacoTransaction, error) {
	switch tx.Type {
	case "request":
		if tx.ID == "" || tx.ID == "auto" {
			r.ctrlSeq++
			tx.ID = strconv.FormatUint(uint64(r.ctrlSeq), 10)
		}
		// Remember the request id for later same_as_request: references.
		if v, err := strconv.ParseUint(tx.ID, 10, 32); err == nil {
			r.requestIDs = append(r.requestIDs, uint32(v))
		}
		return tx, nil
	case "reply", "pending":
		if strings.HasPrefix(tx.ID, "same_as_request:") {
			idxStr := strings.TrimPrefix(tx.ID, "same_as_request:")
			idx, err := strconv.Atoi(idxStr)
			if err != nil {
				return tx, fmt.Errorf("same_as_request: invalid index %q", idxStr)
			}
			if idx < 0 || idx >= len(r.requestIDs) {
				return tx, fmt.Errorf("same_as_request:%d out of range (have %d requests)", idx, len(r.requestIDs))
			}
			tx.ID = strconv.FormatUint(uint64(r.requestIDs[idx]), 10)
		}
		if tx.ID == "" {
			// MG may set id to "auto" for an error reply with id 0.
			if tx.Type == "reply" {
				tx.ID = "0"
			} else {
				return tx, fmt.Errorf("pending transaction missing id")
			}
		}
		return tx, nil
	}
	return tx, nil
}

// pickMid picks the message's mId per direction with the role flip (design
// §5.1/§6): c2s（MG→MGC 侧发起方）用 role 实体的 mid，s2c 用对端 peer_mid。
// 显式值优先；空值按角色+地址派生：role=mg → mid=[src_ip]、peer_mid=[dst_ip]；
// role=mgc 对调（MGC 是发起方）。dstIP 由调用侧经 sessionRun.sess.DstPort
// 之外的参数传入——这里用闭包外的 dstIP。
func pickMid(s core.MegacoSession, direction, srcIP string, dstIP string) string {
	role := s.Role
	if role == "" {
		role = "mg"
	}
	selfMid, peerMid := s.Mid, s.PeerMid
	if selfMid == "" {
		if role == "mg" {
			selfMid = "[" + srcIP + "]"
		} else {
			selfMid = "[" + dstIP + "]"
		}
	}
	if peerMid == "" {
		if role == "mg" {
			peerMid = "[" + dstIP + "]"
		} else {
			peerMid = "[" + srcIP + "]"
		}
	}
	if direction == "s2c" {
		return peerMid
	}
	return selfMid
}

func versionFor(cfg *core.MegacoConfig) int {
	if cfg.Version == 0 {
		return 1
	}
	return cfg.Version
}

// GenEvents marks this generator as a message event producer.
func (g *MegacoGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker. Events flow through GenRequest.EmitMsg only.
func (g *MegacoGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("megaco generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("megaco", func() (layers.LayerGenerator, error) {
		return &MegacoGenerator{}, nil
	})
	layers.RegisterLayerValidator("megaco", func(spec *core.FlowSpec) error {
		return Validate(*spec)
	})
}
