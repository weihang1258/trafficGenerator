// Package bacnet planner：负例校验（42 wire_fault 一行一注入——设计 §6/§7
// 与用例 §5 三方同序）+ 会话状态机（§5：确认事务 Invoke 配对、响应前置
// 请求）+ 值域走查（对象/属性/优先级/错误域/NPDU 修饰）。每个被拒 spec
// 必须传播为 task error——绝不产出 completed/0-packet 或只剩 UDP 外壳的
// 假成功。
//
// 处置表（D-BACNET-1 P4 据实勘误）：15 自然守卫在 validateSession 状态机
// 与值域走查真拒绝；27 仅注入/结构不可达经 validateWireFault 分发拒
// （15+27=42 可复算）。勘误注记：state_iam_no_whois / state_cov_no_subscribe
// 不设自然守卫——正例 31（独立 I-Am 能力宣告）与正例 23（单帧 COV 通知）
// 钉死 UDP 无连接下设备自发宣告/跨回放窗订阅存续为合法形态，守卫只走
// wire_fault 注入通道。
package bacnet

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// wireFaultAnchors maps each of the 42 sanctioned single-injection faults to
// its 主锚词 (用例 §5 表 56-97 逐行——error_contains asserts this literal).
var wireFaultAnchors = map[string]string{
	"bvlc_type":                       "type",
	"bvlc_function":                   "function",
	"bvlc_secure":                     "secure",
	"bvlc_length_min":                 "length",
	"bvlc_length_mismatch":            "length",
	"bvlc_length_forwarded":           "length",
	"npdu_version":                    "version",
	"npdu_dest_missing":               "dnet",
	"npdu_src_len_zero":               "snet",
	"npdu_reserved_bits":              "control",
	"npdu_no_message_type":            "control",
	"npdu_dlen_invalid":               "dlen",
	"apdu_type_invalid":               "apdu",
	"apdu_header_confirmed":           "header",
	"apdu_header_simpleack":           "header",
	"service_confirmed_unimplemented": "service",
	"service_unconfirmed_invalid":     "service",
	"tag_lvt_mismatch":                "lvt",
	"tag_open_unmatched":              "tag",
	"tag_boolean_lvt":                 "tag",
	"tag_context_number":              "tag",
	"object_type_overflow":            "object",
	"object_instance_overflow":        "instance",
	"object_iam_not_device":           "object",
	"property_id_vendor":              "property",
	"property_index_negative":         "property",
	"priority_range":                  "priority",
	"error_class_range":               "error",
	"invoke_mismatch":                 "invoke",
	"invoke_reuse":                    "invoke",
	"segment_extra_fields":            "segment",
	"segment_missing_fields":          "segment",
	"segment_window_zero":             "window",
	"segment_sequence_skip":           "sequence",
	"carrier_layer_missing":           "carrier",
	"carrier_tcp":                     "carrier",
	"port_undeclared":                 "port",
	"address_family_mismatch":         "family",
	"address_family_derived":          "address",
	"state_ack_no_request":            "state",
	"state_iam_no_whois":              "state",
	"state_cov_no_subscribe":          "state",
}

// Planner is the layer-validator entry type (coap 同款：层校验器经
// (&Planner{}).Validate 调用).
type Planner struct{}

// Validate checks a bacnet flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error { return validateSpec(spec) }

// validateSpec: cfg == nil（bare {"bacnet":{}} 层或缺键）通过：生成器发
// 8B 最小帧基线（正例 2 形态）。
func validateSpec(spec core.FlowSpec) error {
	cfg := spec.BACNET
	if cfg == nil {
		return nil
	}
	if cfg.WireFault != "" {
		if err := validateWireFault(cfg.WireFault); err != nil {
			return err
		}
	}
	// 会话间 dst_port 一致性（裁定：会话级覆盖必须彼此一致——edp/xmrmining
	// port_conflict 守卫同款）.
	dst := uint16(0)
	for i := range cfg.Sessions {
		if p := cfg.Sessions[i].DstPort; p != 0 {
			if dst != 0 && dst != p {
				return fmt.Errorf("bacnet: sessions[%d] dst_port %d conflicts with earlier session dst_port %d (port)", i, p, dst)
			}
			dst = p
		}
	}
	for si := range cfg.Sessions {
		if err := validateSession(&cfg.Sessions[si], si); err != nil {
			return err
		}
	}
	return nil
}

// validateSession walks one session's events: state machine (§5) + value
// domains. Tracked: open confirmed transactions (invoke → pending).
func validateSession(sess *core.BACNETSession, si int) error {
	prefix := fmt.Sprintf("bacnet: sessions[%d]", si)
	open := map[int]bool{}
	var inv invokeWalker
	for ei := range sess.Events {
		ev := &sess.Events[ei]
		ep := fmt.Sprintf("%s.events[%d] (%s)", prefix, ei, ev.Kind)
		if ev.WireFault != "" {
			return fmt.Errorf("%s: wire fault %s: negative-path injection rejected", ep, ev.WireFault)
		}
		if err := validateNPDU(ep, ev.NPDU); err != nil {
			return err
		}
		switch ev.Kind {
		case "who_is", "who_has":
			if ev.Low != nil {
				if *ev.Low < 0 || *ev.Low > 4194303 {
					return fmt.Errorf("%s: low limit %d out of device-instance range 0-4194303 (object)", ep, *ev.Low)
				}
			}
			if ev.High != nil {
				if *ev.High < 0 || *ev.High > 4194303 {
					return fmt.Errorf("%s: high limit %d out of device-instance range 0-4194303 (object)", ep, *ev.High)
				}
			}
			if ev.Kind == "who_has" {
				if err := validateObjectID(ep, ev.ObjectType, ev.Instance); err != nil {
					return err
				}
				if ev.ObjectName != "" {
					if len(ev.ObjectName) > 65532 {
						return fmt.Errorf("%s: object_name exceeds CharacterString capacity (lvt)", ep)
					}
				}
			}
			if ev.RespondIAM {
				if err := validateIAM(ep, ev, sess); err != nil {
					return err
				}
			}
		case "i_am":
			if err := validateIAM(ep, ev, sess); err != nil {
				return err
			}
		case "i_have":
			if ev.DeviceInstance < 0 || ev.DeviceInstance > 4194303 {
				return fmt.Errorf("%s: device_instance %d out of range 0-4194303 (instance)", ep, ev.DeviceInstance)
			}
			if err := validateObjectID(ep, ev.ObjectType, ev.Instance); err != nil {
				return err
			}
		case "read_property", "write_property":
			if err := validateObjectID(ep, ev.ObjectType, ev.Instance); err != nil {
				return err
			}
			if ev.Property > 511 {
				return fmt.Errorf("%s: property %d is vendor-private (>511) without a vendor declaration (property)", ep, ev.Property)
			}
			if ev.ArrayIndex != nil && *ev.ArrayIndex < 0 {
				return fmt.Errorf("%s: array index %d is negative (property)", ep, *ev.ArrayIndex)
			}
			if ev.Priority != nil && (*ev.Priority < 1 || *ev.Priority > 16) {
				return fmt.Errorf("%s: priority %d out of range 1-16 (priority)", ep, *ev.Priority)
			}
			if ev.Value != nil {
				if err := validateBACNETValue(ep+".value", ev.Value); err != nil {
					return err
				}
			}
			// SEG=0 却声明 window（segment_extra_fields 自然面）。
			if ev.WindowSize > 0 {
				return fmt.Errorf("%s: window_size declared on unsegmented request (segment)", ep)
			}
			id := inv.request(ev.InvokeID)
			if open[id] {
				return fmt.Errorf("%s: invoke id %d reused while transaction open (invoke)", ep, id)
			}
			open[id] = true
			if err := validateRespond(ep, ev.Respond); err != nil {
				return err
			}
		case "rpm":
			if len(ev.Reads) == 0 {
				return fmt.Errorf("%s: rpm needs at least one read specification", ep)
			}
			for ri, r := range ev.Reads {
				if err := validateObjectID(fmt.Sprintf("%s.reads[%d]", ep, ri), r.ObjectType, r.Instance); err != nil {
					return err
				}
				for pi, p := range r.Props {
					if p.Property > 511 {
						return fmt.Errorf("%s.reads[%d].props[%d]: property %d is vendor-private (property)", ep, ri, pi, p.Property)
					}
					if p.ArrayIndex != nil && *p.ArrayIndex < 0 {
						return fmt.Errorf("%s.reads[%d].props[%d]: array index %d is negative (property)", ep, ri, pi, *p.ArrayIndex)
					}
				}
			}
			if ev.WindowSize > 0 {
				return fmt.Errorf("%s: window_size declared on unsegmented request (segment)", ep)
			}
			id := inv.request(ev.InvokeID)
			if open[id] {
				return fmt.Errorf("%s: invoke id %d reused while transaction open (invoke)", ep, id)
			}
			open[id] = true
			if err := validateRespond(ep, ev.Respond); err != nil {
				return err
			}
		case "subscribe_cov":
			if err := validateObjectID(ep, ev.ObjectType, ev.Instance); err != nil {
				return err
			}
			if ev.Lifetime != nil && (*ev.Lifetime < 0 || *ev.Lifetime > 65535) {
				return fmt.Errorf("%s: lifetime %d out of u16 range (property)", ep, *ev.Lifetime)
			}
			if ev.WindowSize > 0 {
				return fmt.Errorf("%s: window_size declared on unsegmented request (segment)", ep)
			}
			id := inv.request(ev.InvokeID)
			if open[id] {
				return fmt.Errorf("%s: invoke id %d reused while transaction open (invoke)", ep, id)
			}
			open[id] = true
			if err := validateRespond(ep, ev.Respond); err != nil {
				return err
			}
		case "dcc":
			if ev.Duration != nil && (*ev.Duration < 0 || *ev.Duration > 65535) {
				return fmt.Errorf("%s: duration %d out of u16 range (property)", ep, *ev.Duration)
			}
			if ev.Disable != nil && (*ev.Disable < 0 || *ev.Disable > 2) {
				return fmt.Errorf("%s: disable %d out of enum range 0-2 (property)", ep, *ev.Disable)
			}
			if ev.WindowSize > 0 {
				return fmt.Errorf("%s: window_size declared on unsegmented request (segment)", ep)
			}
			id := inv.request(ev.InvokeID)
			if open[id] {
				return fmt.Errorf("%s: invoke id %d reused while transaction open (invoke)", ep, id)
			}
			open[id] = true
			if err := validateRespond(ep, ev.Respond); err != nil {
				return err
			}
		case "cov_notification":
			if ev.InitiatingDevice < 0 || ev.InitiatingDevice > 4194303 {
				return fmt.Errorf("%s: initiating_device %d out of range (instance)", ep, ev.InitiatingDevice)
			}
			if err := validateObjectID(ep, ev.ObjectType, ev.Instance); err != nil {
				return err
			}
			if ev.TimeRemaining < 0 || ev.TimeRemaining > 65535 {
				return fmt.Errorf("%s: time_remaining %d out of u16 range (property)", ep, ev.TimeRemaining)
			}
			for ci, cv := range ev.CovValues {
				if cv.Value == nil {
					return fmt.Errorf("%s.cov_values[%d]: value required", ep, ci)
				}
				if err := validateBACNETValue(fmt.Sprintf("%s.cov_values[%d]", ep, ci), cv.Value); err != nil {
					return err
				}
			}
		case "error":
			if ev.ServiceChoice <= 0 {
				return fmt.Errorf("%s: standalone error needs service_choice (header)", ep)
			}
			if !validErrorClass(ev.ErrClass) {
				return fmt.Errorf("%s: error_class %d out of valid domain 0-7/64-65535 (error)", ep, ev.ErrClass)
			}
			id, ok := pendingInvoke(open, ev.InvokeID)
			if !ok {
				return fmt.Errorf("%s: %s", ep, responseStateErr(ev.InvokeID, len(open) > 0))
			}
			if ev.InvokeID != nil && *ev.InvokeID != id {
				return fmt.Errorf("%s: error invoke %d does not match open transaction invoke %d (invoke)", ep, *ev.InvokeID, id)
			}
			delete(open, id)
		case "reject":
			if ev.RejectReason > 7 && ev.RejectReason < 64 {
				return fmt.Errorf("%s: reject_reason %d out of valid domain 0-7/64-255 (tag)", ep, ev.RejectReason)
			}
			id, ok := pendingInvoke(open, ev.InvokeID)
			if !ok {
				return fmt.Errorf("%s: %s", ep, responseStateErr(ev.InvokeID, len(open) > 0))
			}
			if ev.InvokeID != nil && *ev.InvokeID != id {
				return fmt.Errorf("%s: reject invoke %d does not match open transaction invoke %d (invoke)", ep, *ev.InvokeID, id)
			}
			delete(open, id)
		case "abort":
			if ev.AbortReason > 11 && ev.AbortReason < 64 {
				return fmt.Errorf("%s: abort_reason %d out of valid domain 0-11/64-255 (tag)", ep, ev.AbortReason)
			}
			id, ok := pendingInvoke(open, ev.InvokeID)
			if !ok {
				return fmt.Errorf("%s: %s", ep, responseStateErr(ev.InvokeID, len(open) > 0))
			}
			if ev.InvokeID != nil && *ev.InvokeID != id {
				return fmt.Errorf("%s: abort invoke %d does not match open transaction invoke %d (invoke)", ep, *ev.InvokeID, id)
			}
			delete(open, id)
		case "segmented_request":
			if ev.WindowSize == 0 {
				return fmt.Errorf("%s: segmented request needs a proposed window size 1-255, got 0 (window)", ep)
			}
			if ev.Value != nil {
				if err := validateBACNETValue(ep+".value", ev.Value); err != nil {
					return err
				}
			}
			id := inv.request(ev.InvokeID)
			if open[id] {
				return fmt.Errorf("%s: invoke id %d reused while transaction open (invoke)", ep, id)
			}
			open[id] = true
		case "segmented_ack":
			id, ok := pendingInvoke(open, ev.InvokeID)
			if !ok {
				return fmt.Errorf("%s: %s", ep, responseStateErr(ev.InvokeID, len(open) > 0))
			}
			if ev.InvokeID != nil && *ev.InvokeID != id {
				return fmt.Errorf("%s: segmented_ack invoke %d does not match open transaction invoke %d (invoke)", ep, *ev.InvokeID, id)
			}
			if ev.WindowSize == 0 {
				return fmt.Errorf("%s: segmented_ack needs a proposed window size 1-255, got 0 (window)", ep)
			}
			delete(open, id)
		case "register_foreign_device":
			if ev.TTL < 0 || ev.TTL > 65535 {
				return fmt.Errorf("%s: ttl %d out of u16 range (property)", ep, ev.TTL)
			}
			if err := validateRespond(ep, ev.Respond); err != nil {
				return err
			}
		case "write_bdt", "read_bdt", "read_fdt":
			bdtForm := ev.Kind != "read_fdt"
			for ti := range ev.Entries {
				if err := validateTableEntry(fmt.Sprintf("%s.entries[%d]", ep, ti), &ev.Entries[ti], bdtForm); err != nil {
					return err
				}
			}
			if err := validateRespond(ep, ev.Respond); err != nil {
				return err
			}
			if err := validateRespondEntries(ep, ev.Respond, bdtForm); err != nil {
				return err
			}
		case "delete_fdt":
			if len(ev.Entries) != 1 {
				return fmt.Errorf("%s: delete_fdt needs exactly one entry", ep)
			}
			if err := validateTableEntry(fmt.Sprintf("%s.entries[0]", ep), &ev.Entries[0], false); err != nil {
				return err
			}
			if err := validateRespond(ep, ev.Respond); err != nil {
				return err
			}
			if err := validateRespondEntries(ep, ev.Respond, false); err != nil {
				return err
			}
		case "distribute_broadcast", "forwarded_npdu":
			if ev.Inner == nil || ev.Inner.Kind != "who_is" {
				return fmt.Errorf("%s: inner payload must be a who_is event", ep)
			}
			if ev.Kind == "forwarded_npdu" && ev.FwdIP == "" {
				return fmt.Errorf("%s: forwarded_npdu needs the original source address (fwd_ip)", ep)
			}
		case "router_discovery", "raw_npdu":
			// Vendor-defined NLM（mt ≥ 0x80）契约声明不产生（D-3⑤）——
			// 声明的边界在配置面强制（终审 F3）。
			if ev.NetMsgType >= 0x80 {
				return fmt.Errorf("%s: vendor-defined network message type %d is not produced (control)", ep, ev.NetMsgType)
			}
			for _, n := range ev.Nets {
				if n < 0 || n > 65535 {
					return fmt.Errorf("%s: net %d out of u16 range (dnet)", ep, n)
				}
			}
			if ev.Respond != nil {
				for _, n := range ev.Respond.Nets {
					if n < 0 || n > 65535 {
						return fmt.Errorf("%s: respond net %d out of u16 range (dnet)", ep, n)
					}
				}
			}
		default:
			return fmt.Errorf("%s: unknown event kind %q", ep, ev.Kind)
		}
	}
	return nil
}

// responseStateErr distinguishes the two response-side natural faces:
// declared invoke with open transactions present = invoke mismatch (负例 84);
// no open transaction at all = ACK without a preceding request (负例 95).
func responseStateErr(declared *int, anyOpen bool) string {
	if declared != nil && anyOpen {
		return fmt.Sprintf("response invoke %d matches no open transaction (invoke)", *declared)
	}
	return "response event with no open confirmed request (state)"
}

// validateNPDU checks the per-event NPDU decoration（§3.2 域）.
func validateNPDU(ep string, npdu *core.BACNETNPDU) error {
	if npdu == nil {
		return nil
	}
	if npdu.Priority < 0 || npdu.Priority > 3 {
		return fmt.Errorf("%s: npdu priority %d out of range 0-3 (control)", ep, npdu.Priority)
	}
	if npdu.Dest != nil {
		if npdu.Dest.Net < 1 || npdu.Dest.Net > 65535 {
			return fmt.Errorf("%s: npdu dest net %d out of range 1-65535 (dnet)", ep, npdu.Dest.Net)
		}
	}
	if npdu.Src != nil {
		if npdu.Src.Net < 1 || npdu.Src.Net > 65535 {
			return fmt.Errorf("%s: npdu src net %d out of range 1-65535 (snet)", ep, npdu.Src.Net)
		}
		// SLEN=0 非法（源长度不能为空——npdu_src_len_zero 自然面）。
		if npdu.Src.IP == "" || npdu.Src.Port == 0 {
			return fmt.Errorf("%s: npdu src specifier without a 6-byte B/IP address (SLEN=0 is illegal) (snet)", ep)
		}
	}
	return nil
}

// validateBACNETValue 整数域守卫（135 §3.4 最短式 1-4B 值域；终审 F2 配套
// ——渲染错误=空流契约要求守卫住同步校验器）。
func validateBACNETValue(ep string, v *core.BACNETValue) error {
	switch v.Type {
	case "int":
		n, err := valueAsInt64(v.Value)
		if err != nil {
			return fmt.Errorf("%s: %v (tag)", ep, err)
		}
		if n < -2147483648 || n > 2147483647 {
			return fmt.Errorf("%s: int value %d outside the signed 4-octet domain (tag)", ep, n)
		}
	case "unsigned", "enumerated":
		n, err := valueAsInt64(v.Value)
		if err != nil {
			return fmt.Errorf("%s: %v (tag)", ep, err)
		}
		if n < 0 || n > 4294967295 {
			return fmt.Errorf("%s: %s value %d outside the unsigned 4-octet domain (tag)", ep, v.Type, n)
		}
	}
	return nil
}

func valueAsInt64(v interface{}) (int64, error) {
	switch n := v.(type) {
	case float64:
		return int64(n), nil
	case int:
		return int64(n), nil
	}
	return 0, fmt.Errorf("value must be a number")
}

func validateObjectID(ep string, objType, instance int) error {
	if objType < 0 || objType > 1023 {
		return fmt.Errorf("%s: object type %d overflows the 10-bit field 0-1023 (object)", ep, objType)
	}
	if instance < 0 || instance > 4194303 {
		return fmt.Errorf("%s: object instance %d overflows the 22-bit field 0-4194303 (instance)", ep, instance)
	}
	return nil
}

func validateIAM(ep string, ev *core.BACNETEvent, sess *core.BACNETSession) error {
	ins := effectiveIAM(ev, sess)
	if ins.deviceInstance < 0 || ins.deviceInstance > 4194303 {
		return fmt.Errorf("%s: device_instance %d overflows the 22-bit field (instance)", ep, ins.deviceInstance)
	}
	switch ins.maxAPDU {
	case 50, 128, 206, 480, 1024, 1476:
	default:
		return fmt.Errorf("%s: max_apdu %d is not one of 50/128/206/480/1024/1476 (object)", ep, ins.maxAPDU)
	}
	if ins.segmentation < 0 || ins.segmentation > 3 {
		return fmt.Errorf("%s: segmentation %d out of enum range 0-3 (object)", ep, ins.segmentation)
	}
	if ins.vendorID < 0 || ins.vendorID > 65535 {
		return fmt.Errorf("%s: vendor_id %d out of u16 range (object)", ep, ins.vendorID)
	}
	return nil
}

func validateTableEntry(ep string, e *core.BACNETTableEntry, bdt bool) error {
	if e.IP == "" {
		return fmt.Errorf("%s: entry needs an IP (carrier)", ep)
	}
	if e.Port == 0 {
		return fmt.Errorf("%s: entry needs a port (port)", ep)
	}
	if bdt && e.Mask != "" {
		if len(e.Mask) != 8 {
			return fmt.Errorf("%s: bdt mask %q must be 4 bytes as 8 hex characters (length)", ep, e.Mask)
		}
		for i := 0; i < 8; i++ {
			if hexNibble(e.Mask[i]) < 0 {
				return fmt.Errorf("%s: bdt mask %q has non-hex character (length)", ep, e.Mask)
			}
		}
	}
	if !bdt {
		if e.TTL < 0 || e.TTL > 65535 {
			return fmt.Errorf("%s: fdt ttl %d out of u16 range (property)", ep, e.TTL)
		}
	}
	return nil
}

// validateRespond checks the respond sub-object domains (entries 校验在
// 调用点按事件形态分派——BDT 带掩码 / FDT 带 TTL).
func validateRespond(ep string, r *core.BACNETRespond) error {
	if r == nil {
		return nil
	}
	for _, res := range r.Results {
		for pi, pv := range res.Props {
			if pv.Value != nil {
				if err := validateBACNETValue(fmt.Sprintf("%s.results.props[%d]", ep, pi), pv.Value); err != nil {
					return err
				}
			}
		}
	}
	if r.Value != nil {
		if err := validateBACNETValue(ep+".value", r.Value); err != nil {
			return err
		}
	}
	if r.Result != nil && (*r.Result < 0 || *r.Result > 65535) {
		return fmt.Errorf("%s: bvlc result code %d out of u16 range (length)", ep, *r.Result)
	}
	if r.Window != 0 && (r.Window < 1 || r.Window > 255) {
		return fmt.Errorf("%s: respond window %d out of range 1-255 (window)", ep, r.Window)
	}
	if r.Error != nil && !validErrorClass(r.Error.Class) {
		return fmt.Errorf("%s: respond error_class %d out of valid domain 0-7/64-65535 (error)", ep, r.Error.Class)
	}
	if r.Reject != nil && (*r.Reject > 7 && *r.Reject < 64) {
		return fmt.Errorf("%s: respond reject reason %d out of valid domain (tag)", ep, *r.Reject)
	}
	if r.Abort != nil && (*r.Abort > 11 && *r.Abort < 64) {
		return fmt.Errorf("%s: respond abort reason %d out of valid domain (tag)", ep, *r.Abort)
	}
	switch r.Ack {
	case "", "simple", "complex":
	default:
		return fmt.Errorf("%s: respond ack %q must be simple|complex (service)", ep, r.Ack)
	}
	return nil
}

// validateRespondEntries validates respond.entries in the given table form
// (bdt=掩码表 / fdt=存活表)——read_bdt/read_fdt/write_bdt 调用点分派.
func validateRespondEntries(ep string, r *core.BACNETRespond, bdt bool) error {
	if r == nil {
		return nil
	}
	for i := range r.Entries {
		if err := validateTableEntry(fmt.Sprintf("%s.respond.entries[%d]", ep, i), &r.Entries[i], bdt); err != nil {
			return err
		}
	}
	return nil
}

// validErrorClass: 0-7 与 64-65535（设计 §3.6 组合约束值域）.
func validErrorClass(c int) bool {
	return (c >= 0 && c <= 7) || (c >= 64 && c <= 65535)
}

// validateWireFault dispatches the 42 sanctioned single-injection faults
// (设计 §6 枚举/§7 表；each error carries the row's 主锚词 so error_contains
// matches). 27 仅注入值在此分发拒；15 自然守卫值同时由 validateSession 对
// 裸坏输入拒（处置表 15+27=42 可复算）。
func validateWireFault(kind string) error {
	anchor, ok := wireFaultAnchors[kind]
	if !ok {
		return fmt.Errorf("bacnet: unknown wire_fault kind %q", kind)
	}
	return fmt.Errorf("bacnet: wire fault %s: negative-path injection rejected (anchor %s)", kind, anchor)
}
