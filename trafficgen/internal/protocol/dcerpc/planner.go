// Package dcerpc planner：负例校验（32 wire_fault 一行一注入——设计 §7
// 处置表）+ 状态机走查（bound/accepted/call open 三面）。bacnet planner 同构。
package dcerpc

import (
	"fmt"

	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner is the layer-validator entry type（coap 同款）。
type Planner struct{}

// Validate checks a dcerpc flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error { return validateSpec(spec) }

// validateSpec: cfg == nil（bare {"dcerpc":{}} 层或缺键）通过：空事件流走
// TCP 空连接（框架旧行为）。
func validateSpec(spec core.FlowSpec) error {
	cfg := spec.DCERPC
	if cfg == nil {
		return nil
	}
	if cfg.WireFault != "" {
		return validateWireFault(cfg.WireFault)
	}
	for si := range cfg.Sessions {
		if err := validateSession(fmt.Sprintf("sessions[%d]", si), &cfg.Sessions[si]); err != nil {
			return err
		}
	}
	return nil
}

func validateWireFault(kind string) error {
	anchor, err := core.DescribeDCERPCWireFault(kind)
	if err != nil {
		return err
	}
	return fmt.Errorf("dcerpc: wire fault %s: negative-path injection rejected (anchor %s)", kind, anchor)
}

// validateUUID checks the canonical 8-4-4-4-12 form（uuidEncode 权威同规则）。
func validateUUID(ep, field, s string) error {
	h := strings.ReplaceAll(strings.ToLower(s), "-", "")
	if len(h) != 32 {
		return fmt.Errorf("%s: %s %q is not a 32-hex-digit UUID (uuid)", ep, field, s)
	}
	for i := 0; i < len(h); i++ {
		if strings.IndexByte("0123456789abcdef", h[i]) < 0 {
			return fmt.Errorf("%s: %s %q has non-hex character (uuid)", ep, field, s)
		}
	}
	return nil
}

func validateAuth(ep string, a *core.DCERPCAuth) error {
	if a.Pad < 0 || a.Pad > 3 {
		return fmt.Errorf("%s: auth pad %d out of range 0-3 (trailer)", ep, a.Pad)
	}
	if a.Type < 0 || a.Type > 255 {
		return fmt.Errorf("%s: auth type %d out of range 0-255 (trailer)", ep, a.Type)
	}
	if a.Level < 0 || a.Level > 6 {
		return fmt.Errorf("%s: auth level %d out of range 0-6 (trailer)", ep, a.Level)
	}
	if a.Credentials != "" {
		if _, err := stubBytes(a.Credentials); err != nil {
			return fmt.Errorf("%s: auth credentials %q has non-hex character (verifier)", ep, a.Credentials)
		}
	}
	return nil
}

func validateContexts(ep string, ctxs []core.DCERPCContext) (map[int]bool, error) {
	seen := map[int]bool{}
	for i := range ctxs {
		c := &ctxs[i]
		if c.ContextID < 0 || c.ContextID > 65535 {
			return nil, fmt.Errorf("%s: context_id %d out of u16 range (context)", ep, c.ContextID)
		}
		if seen[c.ContextID] {
			return nil, fmt.Errorf("%s: context_id %d duplicated within one bind (context)", ep, c.ContextID)
		}
		seen[c.ContextID] = true
		if err := validateUUID(ep, fmt.Sprintf("contexts[%d].abstract", i), c.Abstract); err != nil {
			return nil, err
		}
		if len(c.AbstractVersion) < 2 {
			return nil, fmt.Errorf("%s: contexts[%d] abstract_version missing [major,minor] (uuid)", ep, i)
		}
		if len(c.Syntaxes) == 0 {
			return nil, fmt.Errorf("%s: contexts[%d] needs at least one transfer syntax (syntax)", ep, i)
		}
		for j := range c.Syntaxes {
			if err := validateUUID(ep, fmt.Sprintf("contexts[%d].syntaxes[%d].uuid", i, j), c.Syntaxes[j].UUID); err != nil {
				return nil, err
			}
			if len(c.Syntaxes[j].Version) < 2 {
				return nil, fmt.Errorf("%s: contexts[%d].syntaxes[%d] version missing [major,minor] (uuid)", ep, i, j)
			}
		}
	}
	return seen, nil
}

func validateSession(ep string, sess *core.DCERPCSession) error {
	bound := sess.Prebound
	accepted := map[int]bool{}
	w := &callWalker{}
	open := []uint32{}
	usedCall := map[uint32]bool{}
	rejected := map[int]bool{}
	for i := range sess.Events {
		ep2 := fmt.Sprintf("%s.events[%d]", ep, i)
		ev := &sess.Events[i]
		switch ev.Kind {
		case "bind", "alter_ctx":
			if ev.Kind == "alter_ctx" && !bound {
				return fmt.Errorf("%s: alter_ctx before bind on a non-prebound session (state)", ep2)
			}
			seen, err := validateContexts(ep2, ev.Contexts)
			if err != nil {
				return err
			}
			if ev.MaxXmit < 0 || ev.MaxXmit > 65535 {
				return fmt.Errorf("%s: max_xmit %d out of u16 range (width)", ep2, ev.MaxXmit)
			}
			if ev.MaxRecv < 0 || ev.MaxRecv > 65535 {
				return fmt.Errorf("%s: max_recv %d out of u16 range (width)", ep2, ev.MaxRecv)
			}
			if ev.AssocGroup != nil && (*ev.AssocGroup < 0 || *ev.AssocGroup > 4294967295) {
				return fmt.Errorf("%s: assoc_group %d outside the u32 domain (width)", ep2, *ev.AssocGroup)
			}
			if ev.Auth != nil {
				if err := validateAuth(ep2+".auth", ev.Auth); err != nil {
					return err
				}
			}
			cid := w.request(ev.CallID)
			if usedCall[cid] {
				return fmt.Errorf("%s: call_id %d reused while transaction open (call)", ep2, cid)
			}
			usedCall[cid] = true
			if r := ev.Respond; r != nil {
				if r.CallID != nil {
					ov := uint32(*r.CallID)
					if ov != cid {
						return fmt.Errorf("%s: respond call_id %d does not match open call %d (call)", ep2, ov, cid)
					}
				}
				// D-DCERPC-1 P6 修轮（终审 F4）：bind/alter_ctx 的 respond 只许
				// bind_ack 或 alter_ctx_resp——拼错/他型（response/fault）不再
				// 静默渲染成 BIND_ACK（builder 按 ack=="alter_ctx_resp" 选型）。
				if r.Ack != "" && r.Ack != "bind_ack" && r.Ack != "alter_ctx_resp" {
					return fmt.Errorf("%s: respond ack %q is not bind_ack/alter_ctx_resp for a bind (state)", ep2, r.Ack)
				}
				// BIND_ACK/ALTER_CTX_RESP 线上无 auth trailer（buildBindAck 恒
				// auth_len=0）——携 auth 的 ack 型 respond 同步拒，不静默丢弃。
				if r.Auth != nil {
					return fmt.Errorf("%s: respond auth is not produced on a bind_ack/alter_ctx_resp (state)", ep2)
				}
				if r.Secondary != "" && len(r.Secondary) > 255 {
					return fmt.Errorf("%s: secondary address %q too long (length)", ep2, r.Secondary)
				}
				for _, res := range r.Results {
					if !seen[res.ContextID] {
						return fmt.Errorf("%s: respond result references context %d not offered in this bind (context)", ep2, res.ContextID)
					}
					if res.Result < 0 || res.Result > 2 {
						return fmt.Errorf("%s: result %d outside valid domain 0-2 (context)", ep2, res.Result)
					}
					if res.Result == 0 {
						accepted[res.ContextID] = true
						delete(rejected, res.ContextID)
					} else {
						rejected[res.ContextID] = true
						delete(accepted, res.ContextID)
					}
					if res.UUID == "" || len(res.Version) < 2 {
						return fmt.Errorf("%s: respond result for context %d missing transfer uuid/version (uuid)", ep2, res.ContextID)
					}
					if err := validateUUID(ep2, "respond.result.uuid", res.UUID); err != nil {
						return err
					}
				}
			}
			bound = true
		case "request":
			if !bound {
				return fmt.Errorf("%s: request before bind on a non-prebound session (state)", ep2)
			}
			cid := 0
			if ev.ContextID != nil {
				cid = *ev.ContextID
			}
			if cid < 0 || cid > 65535 {
				return fmt.Errorf("%s: context_id %d out of u16 range (context)", ep2, cid)
			}
			if sess.Prebound {
				accepted[cid] = true // prebound 声明面：引用即 accepted
			}
			if rejected[cid] && !accepted[cid] {
				return fmt.Errorf("%s: request uses context %d whose bind result was rejection (syntax)", ep2, cid)
			}
			if !accepted[cid] {
				return fmt.Errorf("%s: request references context %d never accepted (context)", ep2, cid)
			}
			if ev.Opnum != nil && (*ev.Opnum < 0 || *ev.Opnum > 65535) {
				return fmt.Errorf("%s: opnum %d out of u16 range (width)", ep2, *ev.Opnum)
			}
			if ev.AllocHint != nil && *ev.AllocHint < 0 {
				return fmt.Errorf("%s: alloc_hint %d is negative (hint)", ep2, *ev.AllocHint)
			}
			if ev.ObjectUUID != "" {
				if err := validateUUID(ep2, "object_uuid", ev.ObjectUUID); err != nil {
					return err
				}
			}
			if ev.Auth != nil {
				if err := validateAuth(ep2+".auth", ev.Auth); err != nil {
					return err
				}
			}
			callID := w.request(ev.CallID)
			if usedCall[callID] {
				return fmt.Errorf("%s: call_id %d reused while transaction open (call)", ep2, callID)
			}
			usedCall[callID] = true
			open = append(open, callID)
			if r := ev.Respond; r != nil {
				rid := callID
				if r.CallID != nil {
					rid = uint32(*r.CallID)
					found := false
					for _, x := range open {
						if x == rid {
							found = true
							break
						}
					}
					if !found {
						return fmt.Errorf("%s: respond call_id %d matches no open call (call)", ep2, rid)
					}
				}
				switch r.Ack {
				case "response", "fault":
				default:
					return fmt.Errorf("%s: respond ack %q is not response/fault for a request (state)", ep2, r.Ack)
				}
				if r.AllocHint != nil && *r.AllocHint < 0 {
					return fmt.Errorf("%s: respond alloc_hint %d is negative (hint)", ep2, *r.AllocHint)
				}
				if r.Status != nil && (*r.Status < 0 || *r.Status > 4294967295) {
					return fmt.Errorf("%s: fault status %d outside the u32 domain (width)", ep2, *r.Status)
				}
				if r.Fragments < 0 {
					return fmt.Errorf("%s: fragments %d is negative (fragment)", ep2, r.Fragments)
				}
				if r.Auth != nil {
					if err := validateAuth(ep2+".respond.auth", r.Auth); err != nil {
						return err
					}
				}
				for j, x := range open {
					if x == rid {
						open = append(open[:j], open[j+1:]...)
						break
					}
				}
			}
		default:
			return fmt.Errorf("%s: unknown event kind %q", ep2, ev.Kind)
		}
	}
	return nil
}
