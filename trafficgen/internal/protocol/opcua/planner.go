package opcua

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

type Planner struct{}

func (Planner) Name() string { return "opcua" }

func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.OPCUA
	if cfg == nil {
		// P0b-2：空配置默认化并产默认流（security none + read + close）。
		return nil
	}
	mode := cfg.SecurityMode
	if mode == "" {
		mode = "none"
	}
	if mode != "none" && mode != "sign" {
		return fmt.Errorf("opcua: security_mode %q invalid", cfg.SecurityMode)
	}
	if cfg.Transport != "" && cfg.Transport != "tcp" {
		return fmt.Errorf("opcua: transport %q invalid", cfg.Transport)
	}
	// 负例锚点（case 权威）：线故障注入必须拒绝，不允许产流。
	if cfg.BadMessageSize {
		return fmt.Errorf("opcua: MessageSize is invalid")
	}
	if cfg.BadLength {
		return fmt.Errorf("opcua: String length is invalid")
	}
	if cfg.SkipChannel && (len(cfg.Read) > 0 || len(cfg.Write) > 0 || len(cfg.Browse) > 0) {
		return fmt.Errorf("opcua: secureChannel is required before MSG service")
	}
	if cfg.Sessions < 0 || cfg.Sessions > 100 {
		return fmt.Errorf("opcua: sessions %d out of range", cfg.Sessions)
	}
	for _, op := range append(append(append([]core.OPCUANodeRead{}, cfg.Read...), cfg.Write...), cfg.Browse...) {
		if len(op.NodeIDs) == 0 {
			return fmt.Errorf("opcua: service operation requires at least one node id")
		}
		for _, nid := range op.NodeIDs {
			if _, err := parseFourByteNodeID(nid); err != nil {
				return err
			}
		}
	}
	if cfg.Subscription != nil {
		for _, nid := range cfg.Subscription.MonitoredNodes {
			if _, err := parseFourByteNodeID(nid); err != nil {
				return err
			}
		}
	}
	return nil
}

// serviceResult is the response status injected by error_inject (0 = good).
func serviceResult(cfg *core.OPCUAConfig) uint32 {
	if cfg.ErrorInject == nil {
		return 0
	}
	switch cfg.ErrorInject.Op {
	case "bad_node":
		return 0x80340000 // BadNodeIdUnknown
	case "denied":
		return 0x801F0000 // BadUserAccessDenied
	}
	return 0
}

// uaExchange is one request/response service pair with its TypeId node ids.
type uaExchange struct {
	reqServiceID  uint16
	respServiceID uint16
	req, resp     []byte
}

// servicePairs resolves the configured service operations into wire bodies.
// The response carries the injected service status in its result array.
func servicePairs(cfg *core.OPCUAConfig) ([]uaExchange, error) {
	var out []uaExchange
	handle := uint32(2)
	status := serviceResult(cfg)
	add := func(reqID, respID uint16, req, resp []byte) {
		out = append(out, uaExchange{reqID, respID, req, resp})
	}
	switch {
	case cfg.Subscription != nil:
		sub := cfg.Subscription
		add(787, 788, createSubRequestBody(handle, sub), createSubResponseBody(handle, 0, sub))
		handle++
		reqM, n, err := createMonRequestBody(handle, sub)
		if err != nil {
			return nil, err
		}
		add(751, 752, reqM, createMonResponseBody(n, handle, status))
		handle++
		add(791, 792, setPubModeRequestBody(handle), setPubModeResponseBody(handle, 0))
		handle++
		// Publish with a notification, then the keep-alive publish
		// (case opcua_subscribe note: SetPublishingMode, Publish with a
		// notification, Publish keep-alive).
		publishes := sub.PublishCount
		if publishes == 0 {
			publishes = 1
		}
		if publishes > 2 {
			publishes = 2
		}
		for i := 0; i < publishes; i++ {
			// First publish carries the notification (status 0 →
			// DataChangeNotification); a final keep-alive publish carries an
			// empty notificationData.
			respStatus := uint32(0)
			if sub.KeepAlive && i == publishes-1 && publishes > 1 {
				respStatus = 1 // non-zero → empty notificationData branch
			}
			add(826, 827, publishRequestBody(handle), publishResponseBody(handle, respStatus))
			handle++
		}
	case len(cfg.Write) > 0:
		for _, op := range cfg.Write {
			req, _, err := writeRequestBody(handle, op)
			if err != nil {
				return nil, err
			}
			add(673, 674, req, writeResponseBody(len(op.NodeIDs), handle, status))
			handle++
		}
	case len(cfg.Browse) > 0:
		for _, op := range cfg.Browse {
			req, _, err := browseRequestBody(handle, op)
			if err != nil {
				return nil, err
			}
			add(527, 528, req, browseResponseBody(len(op.NodeIDs), handle, status))
			handle++
		}
	default:
		n := cfg.Sessions
		if n == 0 {
			if len(cfg.Read) == 0 {
				// No service configured (hello_ack/open_sign): no MSG pairs.
				return out, nil
			}
			n = 1
		}
		for i := 0; i < n; i++ {
			ops := cfg.Read
			if len(ops) == 0 {
				// sessions=N without read ops: a single-node read per session.
				ops = []core.OPCUANodeRead{{NodeIDs: []string{"ns=0;i=2253"}, AttributeID: 13}}
			}
			req, _, err := readRequestBody(handle, ops)
			if err != nil {
				return nil, err
			}
			add(631, 632, req, readResponseBody(len(ops[0].NodeIDs), handle, status))
			handle++
		}
	}
	return out, nil
}

// buildEvents produces the application-level message frames (no TCP
// handshake/teardown — the tcp layer owns those in the event-mode chain).
func buildEvents(cfg *core.OPCUAConfig) ([]struct {
	Up    bool
	Bytes []byte
}, error) {
	var out []struct {
		Up    bool
		Bytes []byte
	}
	add := func(up bool, b []byte) {
		out = append(out, struct {
			Up    bool
			Bytes []byte
		}{up, b})
	}

	const (
		channelID = uint32(1) // server-assigned after OPN
		tokenID   = uint32(0x3e8)
	)
	hel, _ := BuildHEL("")
	add(true, hel)
	ack, _ := BuildACK()
	add(false, ack)
	opn, _ := BuildOPN(0, cfg.SecurityMode)
	add(true, opn)
	opnResp, _ := BuildOPN(channelID, cfg.SecurityMode)
	add(false, opnResp)

	pairs, err := servicePairs(cfg)
	if err != nil {
		return nil, err
	}
	seq := uint32(2)
	reqID := uint32(2)
	for _, p := range pairs {
		req, err := BuildMSG(channelID, tokenID, seq, reqID, p.reqServiceID, p.req)
		if err != nil {
			return nil, err
		}
		add(true, req)
		seq++
		reqID++
		resp, err := BuildMSG(channelID, tokenID, seq, reqID, p.respServiceID, p.resp)
		if err != nil {
			return nil, err
		}
		add(false, resp)
		seq++
		reqID++
	}

	if cfg.Close {
		clo, _ := BuildCLO(channelID, tokenID, seq, reqID)
		add(true, clo)
		cloResp, _ := BuildCLO(channelID, tokenID, seq+1, reqID+1)
		add(false, cloResp)
	}
	return out, nil
}
