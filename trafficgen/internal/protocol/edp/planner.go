// Package edp planner: negative-path validation (28 wire_fault kinds per
// design §7 — contract v2.1.0 枚举) plus structural config checks. Every
// rejected spec must surface as a task error — never a completed/0-packet
// or transport-shell fake success.
//
// D-EDP-1 裁定4：wire_fault 是负例注入口（闭环 28 值）——已知值即 validator
// 拒 + 主锚词（B6 注入模型：hl7/mmse/megaco 同款，validator 拒绝即负例
// 期望的 task error）；未知值同样拒（"not a known negative-path kind"）。
// 裁定4 处置：28 值全部走注入通道（validator 即拒），其中
// remainlen_mismatch/remainlen_truncated/remainlen_5byte/layer_chain 四值
// builder 恒正确编码/结构不可达，为书面豁免行（自然面守卫不存在）；其余
// 24 值同时存在自然面守卫（下方 validate* 函数同条件执法同一锚词族）。
package edp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// wireFaultAnchors maps each wire_fault kind to its error_contains anchor
// (契约 §7 表主锚词钉死，28 值 1:1 同序).
var wireFaultAnchors = map[string]string{
	core.EDPWireFaultTypeUnknown:          "type",
	core.EDPWireFaultTypeUnimplemented:    "type",
	core.EDPWireFaultRemainlenMismatch:    "remainlen",
	core.EDPWireFaultRemainlenTruncated:   "truncat",
	core.EDPWireFaultRemainlen5Byte:       "remainlen",
	core.EDPWireFaultConnProtocolName:     "protocol",
	core.EDPWireFaultConnVersion:          "version",
	core.EDPWireFaultConnFlag:             "flag",
	core.EDPWireFaultSavedataFormat:       "format",
	core.EDPWireFaultBinDescNoDsID:        "ds_id",
	core.EDPWireFaultBinDescInvalid:       "desc",
	core.EDPWireFaultBinDescOver:          "desc",
	core.EDPWireFaultBinOver3MB:           "length",
	core.EDPWireFaultStateNoConnect:       "connect",
	core.EDPWireFaultStateAfterReject:     "state",
	core.EDPWireFaultStateAfterDisconnect: "state",
	core.EDPWireFaultCmdidCorrelation:     "cmdid",
	core.EDPWireFaultMsgidCorrelation:     "msg_id",
	core.EDPWireFaultJsonInvalid:          "json",
	core.EDPWireFaultJsonOverU16:          "json",
	core.EDPWireFaultLayerChain:           "layer",
	core.EDPWireFaultCarrierUDP:           "carrier",
	core.EDPWireFaultPortConflict:         "port",
	core.EDPWireFaultAuthDevidEmpty:       "devid",
	core.EDPWireFaultAuthAPIKeyEmpty:      "apikey",
	core.EDPWireFaultAuthUserIDEmpty:      "userid",
	core.EDPWireFaultAuthAuthInfoEmpty:    "authinfo",
	core.EDPWireFaultConnackRTNRange:      "rtn",
}

// rejectWireFault converts a wire_fault injection into its task error.
func rejectWireFault(where, fault string) error {
	anchor, ok := wireFaultAnchors[fault]
	if !ok {
		return fmt.Errorf("%s wire_fault %q is not a known negative-path kind", where, fault)
	}
	return fmt.Errorf("%s wire fault %q injected (%s)", where, fault, anchor)
}

// EDPPlanner validates EDP session configuration and enforces the state machine.
type EDPPlanner struct{}

// Validate checks the EDP configuration against the design contract (D-EDP-1).
func (p *EDPPlanner) Validate(spec core.FlowSpec) error {
	cfg := spec.EDP
	if cfg == nil {
		return nil // no edp layer, nothing to validate
	}

	// Profile validation（契约 §1：edp_tcp_plain_v1 主 profile / edp_ipv6_v1
	// 仅外层 v6；edp_encrypt_boundary 为边界声明，不设语义配置）。
	switch cfg.Profile {
	case "", "edp_tcp_plain_v1", "edp_ipv6_v1":
	default:
		return fmt.Errorf("edp: unknown profile %q (edp_tcp_plain_v1/edp_ipv6_v1)", cfg.Profile)
	}

	// wire_fault injection（config 级）。
	if cfg.WireFault != "" {
		return rejectWireFault("edp:", cfg.WireFault)
	}

	// port_conflict 自然面守卫（裁定3：同 fixture 端口一致性——会话级
	// dst_port 显式声明彼此不一致即拒；builder 逐会话取各自 DstPort）。
	seenPort := uint16(0)
	for i := range cfg.Sessions {
		if p := cfg.Sessions[i].DstPort; p != 0 {
			if seenPort != 0 && p != seenPort {
				return fmt.Errorf("edp: session[%d] dst_port %d conflicts with session dst_port %d (port_conflict) (port)", i, p, seenPort)
			}
			seenPort = p
		}
	}

	for i := range cfg.Sessions {
		if err := validateSession(cfg, &cfg.Sessions[i], i); err != nil {
			return err
		}
	}
	return nil
}

// validateSession checks one session: structure + state machine + events.
func validateSession(cfg *core.EDPConfig, s *core.EDPSession, i int) error {
	where := fmt.Sprintf("edp: session[%d]", i)
	if len(s.Events) == 0 {
		return fmt.Errorf("%s has no events", where)
	}
	// state_no_connect 自然面守卫：connect 必为首条业务报文（§5 状态机）。
	if s.Events[0].Kind != "connect" {
		return fmt.Errorf("%s first event must be 'connect' — got %q (state_no_connect) (connect)", where, s.Events[0].Kind)
	}

	// 状态机走查（§5）：rtn≠0 后禁业务帧（state_after_reject）、DISCONNECT
	// 后禁业务帧（state_after_disconnect）。
	closed := false
	for j := range s.Events {
		ev := &s.Events[j]
		evWhere := fmt.Sprintf("%s event[%d]", where, j)
		if closed {
			return fmt.Errorf("%s: no business frames after a rejecting CONNRESP (rtn≠0) or DISCONNECT (state)", evWhere)
		}
		if err := validateEvent(s, ev, i, j); err != nil {
			return err
		}
		if ev.Kind == "connect" && ev.ConnackRtn != nil && *ev.ConnackRtn != 0 {
			closed = true
		}
		if ev.Kind == "disconnect" {
			closed = true
		}
	}
	return nil
}

// validateEvent checks one event's fields against the contract.
func validateEvent(s *core.EDPSession, ev *core.EDPEvent, si, ei int) error {
	where := fmt.Sprintf("edp: session[%d] event[%d]", si, ei)

	// direction 值域（契约 §6：up 缺省 / down）。
	if ev.Direction != "" && ev.Direction != "up" && ev.Direction != "down" {
		return fmt.Errorf("%s direction %q invalid (up/down)", where, ev.Direction)
	}

	// event 级 wire_fault 注入（覆盖 config 级语义，同 reject 模型）。
	if ev.WireFault != "" {
		return rejectWireFault(where+":", ev.WireFault)
	}

	switch ev.Kind {
	case "connect":
		switch ev.Auth {
		case "", "devid":
			// 方式 1：devid + apikey（auth_devid_empty/auth_apikey_empty
			// 自然面守卫 + 注入锚 devid/apikey）。
			if ev.Devid == "" {
				return fmt.Errorf("%s connect requires devid (auth_devid_empty) (devid)", where)
			}
			if ev.APIKey == "" {
				return fmt.Errorf("%s connect requires apikey (auth_apikey_empty) (apikey)", where)
			}
			if err := checkU16Str(where, "devid", ev.Devid, "devid"); err != nil {
				return err
			}
			if err := checkU16Str(where, "apikey", ev.APIKey, "apikey"); err != nil {
				return err
			}
		case "userid":
			// 方式 2：userid + authinfo（auth_userid_empty/auth_authinfo_empty
			// 自然面守卫 + 注入锚 userid/authinfo）。
			if ev.UserID == "" {
				return fmt.Errorf("%s connect userid mode requires userid (auth_userid_empty) (userid)", where)
			}
			if ev.AuthInfo == "" {
				return fmt.Errorf("%s connect userid mode requires authinfo (auth_authinfo_empty) (authinfo)", where)
			}
			if err := checkU16Str(where, "userid", ev.UserID, "userid"); err != nil {
				return err
			}
			if err := checkU16Str(where, "authinfo", ev.AuthInfo, "authinfo"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s auth %q invalid (devid/userid)", where, ev.Auth)
		}
		// connack_rtn 值域 0–9（契约 §3.3 返回码表；越域 = connack_rtn 负例）。
		if ev.ConnackRtn != nil && (*ev.ConnackRtn < 0 || *ev.ConnackRtn > 9) {
			return fmt.Errorf("%s connack_rtn %d out of range 0-9 (connack_rtn) (rtn)", where, *ev.ConnackRtn)
		}

	case "savedata":
		// format 值域 0x01–0x05（format_flag 自然面守卫）。
		if ev.Format < 0x01 || ev.Format > 0x05 {
			return fmt.Errorf("%s savedata format 0x%02x out of range 0x01-0x05 (format_flag) (format)", where, ev.Format)
		}
		// devid 仅在 flag bit7 置位时必填（§3.5：本设备连接上报时可不带）。
		if ev.DevidFlag != 0 && ev.Devid == "" {
			return fmt.Errorf("%s savedata devid_flag set but devid empty (auth_devid_empty) (devid)", where)
		}
		if err := checkU16Str(where, "devid", ev.Devid, "devid"); err != nil {
			return err
		}
		switch ev.Format {
		case 0x02:
			// type2：desc 必含 ds_id 且为合法 JSON 对象；wire 口径
			// desc ≥65536 / bin ≥3MB 即拒（N1 口径注：SDK 严格 > 与 wire ≥
			// 差异，本 validator 按 wire 拒）。
			if ev.Desc == "" {
				return fmt.Errorf("%s savedata type2 requires desc (bin_desc_no_dsid) (desc)", where)
			}
			var obj map[string]interface{}
			if err := json.Unmarshal([]byte(ev.Desc), &obj); err != nil {
				return fmt.Errorf("%s savedata type2 desc is not a valid JSON object (bin_desc_invalid) (desc)", where)
			}
			if _, ok := obj["ds_id"]; !ok {
				return fmt.Errorf("%s savedata type2 desc lacks ds_id field (bin_desc_no_dsid) (ds_id)", where)
			}
			if len(ev.Desc) >= 65536 {
				return fmt.Errorf("%s savedata type2 desc length %d ≥ 65536 (bin_desc_over) (desc)", where, len(ev.Desc))
			}
			bin, err := decodeB64(ev.BinB64)
			if err != nil {
				return fmt.Errorf("%s savedata type2 bin_b64 invalid base64: %v", where, err)
			}
			if len(bin) >= 3*1024*1024 {
				return fmt.Errorf("%s savedata type2 bin length %d ≥ 3MB (bin_over_3mb) (length)", where, len(bin))
			}
		default:
			// types 1/3/4/5：json ≤65535（u16 前缀上界；65,535/65,534 邻位
			// 为合法正例，>65,535 = json_over_u16 负例）。
			if len(ev.JSONStr) > 65535 {
				return fmt.Errorf("%s savedata json length %d exceeds u16 bound 65535 (json_over_u16) (json)", where, len(ev.JSONStr))
			}
			if ev.JSONStr != "" && ev.Format != 0x05 {
				var v interface{}
				if err := json.Unmarshal([]byte(ev.JSONStr), &v); err != nil {
					return fmt.Errorf("%s savedata type%d json is not valid JSON (json_invalid) (json)", where, ev.Format)
				}
			}
		}

	case "pushdata":
		if ev.Devid == "" {
			return fmt.Errorf("%s pushdata requires devid", where)
		}
		if err := checkU16Str(where, "devid", ev.Devid, "devid"); err != nil {
			return err
		}
		if _, err := decodeB64(ev.DataB64); err != nil {
			return fmt.Errorf("%s pushdata data_b64 invalid base64: %v", where, err)
		}

	case "cmdreq":
		if ev.CmdID == "" {
			return fmt.Errorf("%s cmdreq requires cmdid (cmdid) (cmdid)", where)
		}
		if err := checkU16Str(where, "cmdid", ev.CmdID, "cmdid"); err != nil {
			return err
		}
		if _, err := decodeB64(ev.ReqB64); err != nil {
			return fmt.Errorf("%s cmdreq req_b64 invalid base64: %v", where, err)
		}
		if _, err := decodeB64(ev.RespB64); err != nil {
			return fmt.Errorf("%s cmdreq resp_b64 invalid base64: %v", where, err)
		}

	case "ping":
		// 无附加字段（§3.4 最小 2 字节帧）。

	case "disconnect":
		// 无附加字段（§3.9 最小形态）。

	default:
		return fmt.Errorf("%s kind %q invalid (connect/savedata/pushdata/cmdreq/ping/disconnect) (type)", where, ev.Kind)
	}
	return nil
}

// checkU16Str guards a u16-length-prefixed identifier field (design §8
// 标识符上界 65,535B——超界时 builder uint16 截断产前缀与字节不符的静默
// 坏帧，validator 即拒——§5 不得静默产出）。
func checkU16Str(where, field, val, anchor string) error {
	if len(val) > 65535 {
		return fmt.Errorf("%s %s length %d exceeds u16 bound 65535 (length)", where, field, len(val))
	}
	return nil
}

// decodeB64 decodes a base64 string; empty input decodes to nil (legal).
func decodeB64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}
