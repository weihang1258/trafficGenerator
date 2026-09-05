// Package cwmp generator: walks sessions (concurrent = round-robin per
// transaction index, like gbt; sequential = session by session) and emits
// one MessageEvent per transaction side. Each event carries the COMPLETE
// HTTP frame bytes (request line / status line / pinned headers / body)
// and, when the session/flow carries endpoint overrides, the resolved
// {dstIP, dstPort} L3/L4 stamp; the http layer (identity forward-transformer
// — see internal/protocol/http/layer_gen.go) forwards them verbatim and the
// tcp layer owns segmentation, handshake, and teardown. (The connKey
// {src, dstIP, dst} generalization is the engine-side counterpart, tracked
// as the波 6 TODO in internal/core/layers/generator.go.)
//
// Flow correlation (design §5): the driven_by-anchored side connections are
// emitted right after the matching main-session transaction; their final
// event carries CloseConn=true to signal the (future) tcp teardown hook
// before the main session's next transaction. Per-session state tracks the
// pending ACS request method + id (correlation), the auto-increment cwmp:ID
// counter, and Set-Cookie/Cookie echo.
package cwmp

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// CWMPGenerator is the cwmp terminal-layer generator ([ip→tcp→http→cwmp]).
type CWMPGenerator struct{}

// Name returns "cwmp".
func (g *CWMPGenerator) Name() string { return "cwmp" }

// sessionRun is the per-session generation state.
type sessionRun struct {
	// idx is the session's index in cfg.Sessions (error messages and the
	// flows[] driven_by anchor reference it).
	idx int
	sess core.CWMPSession
	// lastWasUP is the HTTP alternation cursor (validator mirror): every
	// transaction is one frame; the flexible kinds (acs_request/
	// acs_response/fault) take the direction opposite the previous frame.
	lastWasUP bool
	// autoIDCtr is the per-session cwmp:ID auto-increment counter (idCounter
	// in design §3.5 — start "1"; increments on request-side frames only,
	// same kinds the validator counts).
	autoIDCtr int
	// pendingReqID/Kind track the in-flight request awaiting a response —
	// the response's echoed id must match (Table 4/10 correlation).
	pendingReqID   string
	pendingReqKind string
	// pendingACSRequestMethod is the ACS method awaiting its CPE response
	// (either shape: direct POST or riding a response body).
	pendingACSRequestMethod string
	// cookie holds the Set-Cookie value echoed on subsequent requests.
	cookie string
}

// Generate walks the sessions' transactions and emits one MessageEvent per
// transaction side. Sequential mode walks session by session; concurrent
// mode interleaves round-robin per transaction index (设计 §5 并发会话,
// 例 `cwmp_concurrent_sessions` 双 CPE 四元组交错).
func (g *CWMPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("cwmp generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.CWMP
	if cfg == nil {
		cfg = &core.CWMPConfig{}
	}
	sessions := cfg.Sessions
	if len(sessions) == 0 {
		// 空配置默认流（P0b）：基线单 CPE 会话——Inform(2 PERIODIC) →
		// InformResponse → 空 POST → 204。TCP 11 包（3 握手 + 2 事务对 +
		// 1 空 POST + 1 204 + 4 挥手）。
		sessions = []core.CWMPSession{{
			Role: "cpe",
			Transactions: []core.CWMPTransaction{
				{Kind: "inform", ID: "1", Events: []core.CWMPSOAPEvent{{Code: "2 PERIODIC"}}},
				{Kind: "inform_response", ID: "1"},
				{Kind: "empty_post"},
				{Kind: "empty_response"},
			},
		}}
	}

	namespace := cfg.Namespace
	if namespace == "" {
		namespace = FixtureNamespace
	}
	dstIP := req.Meta.DstIP
	dstPort := uint16(req.Meta.DstPort)
	if dstPort == 0 {
		dstPort = 7547 // IANA CWMP well-known port (FieldContract default).
	}

	runs := make([]*sessionRun, len(sessions))
	for i, s := range sessions {
		cp := s
		if cp.DeviceID == nil {
			cp.DeviceID = &core.CWMPDeviceID{}
			*cp.DeviceID = FixtureDeviceID()
		}
		runs[i] = &sessionRun{idx: i, sess: cp}
	}

	emit := func(ev layers.MessageEvent) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return req.EmitMsg(ev)
	}

	walkSession := func(runIndex int, run *sessionRun) error {
		for ti := range run.sess.Transactions {
			tx := run.sess.Transactions[ti]
			if err := g.emitTransaction(ctx, run, &tx, ti, namespace, dstIP, dstPort, cfg, emit); err != nil {
				return err
			}
			// 紧跟被 driven_by 锚定的事务：插入 flows 块（设计 §5 副连接
			// 插入位置 = DownloadResponse 之后、主会话下一事务之前）。
			if flows := cfg.Flows; len(flows) > 0 {
				for fi := range flows {
					fl := &flows[fi]
					if fl.DrivenBy == nil {
						continue
					}
					if fl.DrivenBy.Session != runIndex {
						continue
					}
					if fl.DrivenBy.Transaction != tx.Kind {
						continue
					}
					if err := g.emitFlow(ctx, run, fl, dstIP, emit); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}

	// emitAnchoredFlows emits the side-connection flow block for each flow
	// anchored to session runIndex's transaction index j (concurrent path:
	// one tx at a time, so the anchor must fire per-tx, not after a whole
	// session walk).
	emitAnchoredFlows := func(runIndex int, txKind string) error {
		if flows := cfg.Flows; len(flows) > 0 {
			for fi := range flows {
				fl := &flows[fi]
				if fl.DrivenBy == nil {
					continue
				}
				if fl.DrivenBy.Session != runIndex || fl.DrivenBy.Transaction != txKind {
					continue
				}
				if err := g.emitFlow(ctx, runs[runIndex], fl, dstIP, emit); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if cfg.Concurrent {
		maxLen := 0
		for _, r := range runs {
			if len(r.sess.Transactions) > maxLen {
				maxLen = len(r.sess.Transactions)
			}
		}
		for j := 0; j < maxLen; j++ {
			for runIndex, r := range runs {
				if j >= len(r.sess.Transactions) {
					continue
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				tx := r.sess.Transactions[j]
				if err := g.emitTransaction(ctx, r, &tx, j, namespace, dstIP, dstPort, cfg, emit); err != nil {
					return err
				}
				if err := emitAnchoredFlows(runIndex, tx.Kind); err != nil {
					return err
				}
			}
		}
	} else {
		for runIndex, r := range runs {
			if err := walkSession(runIndex, r); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitTransaction builds one transaction's HTTP frame(s) and emits the
// matching MessageEvent.
func (g *CWMPGenerator) emitTransaction(
	ctx context.Context,
	run *sessionRun,
	tx *core.CWMPTransaction,
	ti int,
	namespace, dstIP string,
	dstPort uint16,
	cfg *core.CWMPConfig,
	emit func(layers.MessageEvent) error,
) error {
	role := run.sess.Role
	if role == "" {
		role = "cpe"
	}
	srcPort := run.sess.SrcPort
	if srcPort == 0 {
		// 终结层 chain 路径下 spec.SrcPort 由 chain planner 注入到 tcp 层
		// config（spec→tcp.dst_port 同款），事件级 SrcPort 覆盖 = 0 时让 tcp
		// 层回退 cfg.srcPort（保留现有单连接路径字节级不变）。多会话用 session
		// 显式 SrcPort；零值 = 链层默认。
		srcPort = 0
	}
	// Per-session endpoint overrides (acs_cr reverse connections target the
	// CPE; CR sessions carry explicit DstIP/DstPort).
	txDstIP := run.sess.DstIP
	if txDstIP == "" {
		txDstIP = dstIP
	}
	txDstPort := run.sess.DstPort
	if txDstPort == 0 {
		txDstPort = dstPort
	}

	// Connection header: keep-alive unless the transaction's Close flag is
	// set or this is the final transaction in the session.
	conn := "keep-alive"
	if tx.Close || ti == len(run.sess.Transactions)-1 {
		conn = "close"
	}

	// Host header (bracketed for IPv6).
	host := bracketHost(txDstIP) + ":" + strconvI(uint64(txDstPort))

	// kind 归一（validator 同款）：具名 ACS 请求/响应族折叠到
	// acs_request/acs_response（method = 具名 kind / 去 _response 后缀）。
	kind := tx.Kind
	method := ""
	if isACSRequestKind(kind) {
		method = kind
		kind = "acs_request"
	} else if isACSResponseKind(kind) {
		method = strings.TrimSuffix(kind, "_response")
		kind = "acs_response"
	} else if kind == "acs_request" || kind == "acs_response" || kind == "cpe_response" {
		method = tx.Method
	}

	// nextAutoID 推进自动 id 计数并返回新值（仅请求侧帧计数——validator 的
	// idCounter 同步：inform/empty_post/上报/acs_request（两形状）/
	// acs_response·fault 的 UP 形状）。
	nextAutoID := func() string {
		run.autoIDCtr++
		return strconvI(uint64(run.autoIDCtr))
	}
	autoID := strconvI(uint64(run.autoIDCtr) + 1)
	reqID := tx.ID
	if reqID == "" {
		reqID = autoID
	}

	switch kind {
	case "inform":
		if reqID == autoID {
			reqID = nextAutoID()
		}
		body := BuildEnvelope(namespace, reqID, BuildInformPayload(
			ifaceDevice(run.sess.DeviceID),
			tx.Events,
			tx.MaxEnvelopes,
			tx.CurrentTime,
			tx.RetryCount,
			tx.ParameterList,
		))
		ev := layers.MessageEvent{
			Up:    true,
			Bytes: buildSOAPRequest("POST", run.sess.URI, host, reqID, body, run.cookie, tx, conn),
		}
		setEventEndpoint(&ev, srcPort, txDstIP, txDstPort)
		if err := emit(ev); err != nil {
			return err
		}
		run.pendingReqID = reqID
		run.pendingReqKind = "inform"
		run.lastWasUP = true
		return nil

	case "inform_response":
		// 响应内嵌的 CPE 默认 InformResponse 形状（MaxEnvelopes=1）。
		respID := tx.ForID
		if respID == "" {
			respID = run.pendingReqID
		}
		body := BuildEnvelope(namespace, respID, BuildInformResponsePayload(tx.MaxEnvelopes))
		ev := layers.MessageEvent{
			Up:    false,
			Bytes: buildSOAPResponse(200, "text/xml; charset=\"utf-8\"", body, tx.SetCookie, "", conn),
		}
		setEventEndpoint(&ev, srcPort, txDstIP, txDstPort)
		if err := emit(ev); err != nil {
			return err
		}
		if tx.SetCookie != "" {
			run.cookie = tx.SetCookie
		}
		run.pendingReqKind = ""
		run.pendingReqID = ""
		run.lastWasUP = false
		return nil

	case "acs_request":
		// 弹性方向（validator 同款）：跟在 DOWN 帧后 = CPE 直接 POST
		// （设计 §6 范例）；跟在 UP 帧后 = 内嵌响应体下发（§4 场景②）。
		if method == "" {
			return fmt.Errorf("cwmp: sessions[%d].transactions[%d]: acs_request missing method", run.idx, ti)
		}
		return emitACSRequest(ctx, run, tx, method, !run.lastWasUP, namespace, host, srcPort, txDstIP, txDstPort, conn, emit)

	case "acs_response":
		// 弹性方向：跟在 UP 帧后 = DOWN 响应（形状 a）；跟在 DOWN 帧后 =
		// CPE POST 对内嵌下发 ACS 请求的响应（形状 b）。
		return emitACSResponse(ctx, run, tx, method, run.lastWasUP, namespace, host, srcPort, txDstIP, txDstPort, conn, emit)

	case "empty_post":
		body := []byte{}
		ev := layers.MessageEvent{
			Up:    true,
			Bytes: BuildRequest("POST", run.sess.URI, host, "", run.cookie, "", SOAPActionOmit, body, "", nil, conn),
		}
		setEventEndpoint(&ev, srcPort, txDstIP, txDstPort)
		if err := emit(ev); err != nil {
			return err
		}
		run.pendingReqID = nextAutoID()
		run.pendingReqKind = "empty_post"
		run.lastWasUP = true
		return nil

	case "empty_response":
		// 204 空响应（§3.3 必须 204；设计 §5：204 只有在应答空 POST 时才终止）。
		ev := layers.MessageEvent{
			Up:    false,
			Bytes: buildSOAPResponse(204, "", nil, "", "", conn),
		}
		setEventEndpoint(&ev, srcPort, txDstIP, txDstPort)
		if err := emit(ev); err != nil {
			return err
		}
		run.pendingReqID = ""
		run.pendingReqKind = ""
		run.lastWasUP = false
		return nil

	case "empty_ok":
		// 200 空体（Connection Request 200 终止路径；CR 成功应答即 200 无体）。
		ev := layers.MessageEvent{
			Up:    false,
			Bytes: buildSOAPResponse(200, "", nil, "", "", conn),
		}
		setEventEndpoint(&ev, srcPort, txDstIP, txDstPort)
		if err := emit(ev); err != nil {
			return err
		}
		return nil

	case "connection_request":
		ev := layers.MessageEvent{
			Up:    true,
			Bytes: BuildConnectionRequest(run.sess.URI, host),
		}
		setEventEndpoint(&ev, srcPort, txDstIP, txDstPort)
		run.lastWasUP = true
		run.pendingReqKind = "connection_request"
		return emit(ev)

	case "auth_challenge":
		// 401 挑战（ac_cr reverse connection 路径；§3.2.2）。
		challenge := tx.WWWAuthenticate
		if challenge == "" {
			challenge = DefaultChallenge()
		}
		ev := layers.MessageEvent{
			Up:    false,
			Bytes: buildSOAPResponse(401, "", nil, "", challenge, conn),
		}
		setEventEndpoint(&ev, srcPort, txDstIP, txDstPort)
		run.lastWasUP = false
		run.pendingReqKind = ""
		return emit(ev)

	case "connection_request_authorized":
		// CR 重发 GET + Authorization（挑战后）。
		var auth string
		if cfg.Auth != nil {
			auth = DigestAuthorizationHeader(*cfg.Auth, tx.WWWAuthenticate, "GET", run.sess.URI)
		} else if tx.Authorization != "" {
			auth = tx.Authorization
		}
		ev := layers.MessageEvent{
			Up:    true,
			Bytes: BuildRequest("GET", run.sess.URI, host, auth, run.cookie, "", SOAPActionOmit, nil, "", nil, conn),
		}
		setEventEndpoint(&ev, srcPort, txDstIP, txDstPort)
		run.lastWasUP = true
		run.pendingReqKind = "connection_request"
		return emit(ev)

	case "transfer_complete", "autonomous_transfer_complete", "request_download":
		var inner string
		switch tx.Kind {
		case "transfer_complete":
			inner = BuildTransferCompletePayload(tx.CommandKey, tx.FaultCode, tx.FaultString, tx.StartTime, tx.CompleteTime)
		case "autonomous_transfer_complete":
			inner = BuildAutonomousTransferCompletePayload(
				tx.AnnounceURL, tx.TransferURL, tx.IsDownload, tx.FileType,
				tx.FileSize, tx.TargetFileName, tx.FaultCode, tx.FaultString,
				tx.StartTime, tx.CompleteTime,
			)
		case "request_download":
			inner = BuildRequestDownloadPayload(tx.FileType, tx.FileTypeArg)
		}
		if reqID == autoID {
			reqID = nextAutoID()
		}
		body := BuildEnvelope(namespace, reqID, inner)
		ev := layers.MessageEvent{
			Up:    true,
			Bytes: buildSOAPRequest("POST", run.sess.URI, host, reqID, body, run.cookie, tx, conn),
		}
		setEventEndpoint(&ev, srcPort, txDstIP, txDstPort)
		if err := emit(ev); err != nil {
			return err
		}
		run.pendingReqID = reqID
		run.pendingReqKind = tx.Kind
		run.lastWasUP = true
		return nil

	case "transfer_complete_response", "autonomous_transfer_complete_response", "request_download_response":
		respID := tx.ForID
		if respID == "" {
			respID = run.pendingReqID
		}
		// 响应 body：空 Response 元素（cwmp-1-2.xsd 校准）。
		method := strings.TrimSuffix(tx.Kind, "_response")
		body := BuildEnvelope(namespace, respID, BuildStatusResponsePayload(pascalMethod(method), 0))
		ev := layers.MessageEvent{
			Up:    false,
			Bytes: buildSOAPResponse(200, "text/xml", body, "", "", conn),
		}
		setEventEndpoint(&ev, srcPort, txDstIP, txDstPort)
		run.lastWasUP = false
		run.pendingReqKind = ""
		run.pendingReqID = ""
		return emit(ev)

	case "fault":
		// Fault（§3.4：bare Client/Server + 固定 faultstring）。弹性方向：
		// 跟在 UP 帧后 = DOWN 500 应答（含 Inform-Fault 终止路径）；跟在
		// DOWN 帧后 = CPE POST 对内嵌下发 ACS 请求的 Fault 应答（#36）。
		respID := tx.ForID
		if respID == "" {
			respID = run.pendingReqID
		}
		body := BuildEnvelope(namespace, respID, BuildFaultPayload(tx.Fault))
		if run.lastWasUP {
			ev := layers.MessageEvent{
				Up:    false,
				Bytes: buildSOAPResponse(500, "text/xml", body, "", "", conn),
			}
			setEventEndpoint(&ev, srcPort, txDstIP, txDstPort)
			run.lastWasUP = false
			run.pendingReqKind = ""
			run.pendingReqID = ""
			return emit(ev)
		}
		ev := layers.MessageEvent{
			Up:    true,
			Bytes: buildSOAPRequest("POST", run.sess.URI, host, respID, body, run.cookie, tx, conn),
		}
		setEventEndpoint(&ev, srcPort, txDstIP, txDstPort)
		run.lastWasUP = true
		run.pendingReqID = nextAutoID()
		run.pendingReqKind = "acs_response:fault"
		return emit(ev)
	}

	return fmt.Errorf("cwmp: sessions[%d].transactions[%d]: unknown kind %q", run.idx, ti, tx.Kind)
}

func isACSRequestKind(k string) bool {
	switch k {
	case "get_parameter_values", "get_parameter_names", "set_parameter_values",
		"get_parameter_attributes", "set_parameter_attributes", "add_object",
		"delete_object", "factory_reset", "get_rpc_methods", "download",
		"upload", "schedule_download", "schedule_upload", "reboot", "kicked":
		return true
	}
	return false
}

func isACSResponseKind(k string) bool {
	switch k {
	case "get_parameter_values_response", "get_parameter_names_response",
		"set_parameter_values_response", "get_parameter_attributes_response",
		"set_parameter_attributes_response", "add_object_response",
		"delete_object_response", "factory_reset_response",
		"get_rpc_methods_response", "download_response", "upload_response",
		"schedule_download_response", "schedule_upload_response", "reboot_response",
		"kicked_response":
		return true
	}
	return false
}

// emitACSRequest sends one ACS request frame. dirUp picks the shape:
// true = CPE direct POST (design §6 canonical example — the request frame
// itself); false = the request rides the HTTP response body answering the
// pending CPE POST (§4 场景② AcsRequests — a 200 with the request envelope).
// Both shapes leave the request pending its CPE response.
func emitACSRequest(
	ctx context.Context,
	run *sessionRun,
	tx *core.CWMPTransaction,
	method string,
	dirUp bool,
	namespace, host string,
	srcPort uint16, dstIP string, dstPort uint16,
	conn string,
	emit func(layers.MessageEvent) error,
) error {
	_ = ctx
	id := tx.ID
	if id == "" {
		run.autoIDCtr++
		id = strconvI(uint64(run.autoIDCtr))
	}
	var inner string
	switch tx.Method {
	case "get_parameter_values":
		inner = BuildGetParameterValuesPayload(tx.ParameterNames)
	case "get_parameter_names":
		inner = BuildGetParameterNamesPayload(tx.ParameterPath, tx.NextLevel)
	case "set_parameter_values":
		inner = BuildSetParameterValuesPayload(tx.ParameterList, tx.ParameterKey)
	case "get_parameter_attributes":
		inner = BuildGetParameterAttributesPayload(tx.ParameterNames)
	case "set_parameter_attributes":
		inner = BuildSetParameterAttributesPayload(tx.ParameterList)
	case "add_object":
		inner = BuildAddObjectPayload(tx.ObjectName, tx.ParameterKey)
	case "delete_object":
		inner = BuildDeleteObjectPayload(tx.ObjectName, tx.ParameterKey)
	case "factory_reset":
		inner = `<cwmp:FactoryReset/>`
	case "get_rpc_methods":
		inner = BuildGetRPCMethodsPayload()
	case "download", "upload":
		inner = BuildDownloadPayload(tx.Method, tx.CommandKey, tx.FileType, tx.URL, tx.Username, tx.Password, tx.FileSize, tx.TargetFileName, tx.DelaySeconds)
	case "schedule_download":
		inner = BuildScheduleDownloadPayload(tx.CommandKey, tx.FileType, tx.URL, tx.Username, tx.Password, tx.FileSize, tx.TargetFileName, tx.StartTime, tx.CompleteTime, tx.SuccessURL, tx.FailureURL, tx.MaxRetries)
	case "schedule_upload":
		inner = BuildScheduleUploadPayload(tx.CommandKey, tx.FileType, tx.URL, tx.Username, tx.Password, tx.StartTime, tx.CompleteTime)
	case "reboot":
		inner = `<cwmp:Reboot>` + xelem("CommandKey", tx.CommandKey) + `</cwmp:Reboot>`
	case "kicked":
		inner = BuildKickedPayload(tx.CommandKey)
	}
	body := BuildEnvelope(namespace, id, inner)
	var ev layers.MessageEvent
	if dirUp {
		ev = layers.MessageEvent{
			Up:    true,
			Bytes: buildSOAPRequest("POST", run.sess.URI, host, id, body, run.cookie, tx, conn),
		}
	} else {
		// 内嵌响应体下发：200 应答未决 UP POST，body 即 ACS 请求 envelope。
		ev = layers.MessageEvent{
			Up:    false,
			Bytes: buildSOAPResponse(200, "text/xml; charset=\"utf-8\"", body, tx.SetCookie, "", conn),
		}
		if tx.SetCookie != "" {
			run.cookie = tx.SetCookie
		}
	}
	setEventEndpoint(&ev, srcPort, dstIP, dstPort)
	if err := emit(ev); err != nil {
		return err
	}
	run.pendingReqID = id
	if dirUp {
		run.pendingReqKind = "acs_request:" + method
	} else {
		run.pendingReqKind = "acs_riding:" + method
	}
	run.pendingACSRequestMethod = method
	run.lastWasUP = dirUp
	return nil
}

// emitACSResponse sends the response to the pending ACS request. dirUp picks
// the shape: false = DOWN 200 answering a direct CPE POST of the request
// (shape a); true = CPE POST carrying the response to a request that rode a
// response body (shape b — the response envelope echoes the riding
// request's id via for_id/pendingReqID).
func emitACSResponse(
	ctx context.Context,
	run *sessionRun,
	tx *core.CWMPTransaction,
	method string,
	dirUp bool,
	namespace, host string,
	srcPort uint16, dstIP string, dstPort uint16,
	conn string,
	emit func(layers.MessageEvent) error,
) error {
	_ = ctx
	respID := tx.ForID
	if respID == "" {
		respID = run.pendingReqID
	}
	if method == "" {
		method = run.pendingACSRequestMethod
	}
	var inner string
	switch method {
	case "get_parameter_values":
		inner = BuildMethodPayload("GetParameterValuesResponse", BuildParameterList("ParameterList", tx.ParameterList))
	case "get_parameter_names":
		inner = BuildGetParameterNamesResponsePayload(tx.ParameterList)
	case "set_parameter_values":
		inner = BuildStatusResponsePayload("SetParameterValuesResponse", tx.Status)
	case "get_parameter_attributes":
		inner = BuildGetParameterAttributesResponsePayload(tx.ParameterList)
	case "set_parameter_attributes":
		// cwmp-1-2.xsd: 空 <SetParameterAttributesResponse/> 元素。
		inner = `<cwmp:SetParameterAttributesResponse/>`
	case "add_object":
		inner = BuildAddObjectResponsePayload(tx.InstanceNumber, tx.Status)
	case "delete_object":
		inner = BuildStatusResponsePayload("DeleteObjectResponse", tx.Status)
	case "factory_reset":
		inner = `<cwmp:FactoryResetResponse/>`
	case "get_rpc_methods":
		inner = BuildGetRPCMethodsResponsePayload()
	case "download":
		inner = BuildTransferResponsePayload("DownloadResponse", tx.Status, tx.StartTime, tx.CompleteTime)
	case "upload":
		inner = BuildTransferResponsePayload("UploadResponse", tx.Status, tx.StartTime, tx.CompleteTime)
	case "schedule_download":
		inner = BuildScheduleDownloadResponsePayload(tx.Status, tx.StartTime)
	case "schedule_upload":
		inner = BuildScheduleUploadResponsePayload(tx.Status, tx.StartTime)
	case "reboot":
		inner = BuildStatusResponsePayload("RebootResponse", 0)
	case "kicked":
		inner = BuildKickedResponsePayload(tx.KickURL, tx.RequestID)
	}
	body := BuildEnvelope(namespace, respID, inner)
	var ev layers.MessageEvent
	if dirUp {
		// 形状 b：CPE POST 应答内嵌下发的 ACS 请求；envelope id 回带
		// 该请求的 id（for_id/pendingReqID），该 POST 自身进入未决。
		ev = layers.MessageEvent{
			Up:    true,
			Bytes: buildSOAPRequest("POST", run.sess.URI, host, respID, body, run.cookie, tx, conn),
		}
	} else {
		ev = layers.MessageEvent{
			Up:    false,
			Bytes: buildSOAPResponse(200, "text/xml", body, tx.SetCookie, "", conn),
		}
		if tx.SetCookie != "" {
			run.cookie = tx.SetCookie
		}
	}
	setEventEndpoint(&ev, srcPort, dstIP, dstPort)
	if err := emit(ev); err != nil {
		return err
	}
	if dirUp {
		run.pendingReqID = tx.ID
		if run.pendingReqID == "" {
			run.autoIDCtr++
			run.pendingReqID = strconvI(uint64(run.autoIDCtr))
		}
		run.pendingReqKind = "acs_response:" + method
	} else {
		run.pendingReqID = ""
		run.pendingReqKind = ""
	}
	run.pendingACSRequestMethod = ""
	run.lastWasUP = dirUp
	return nil
}

// emitFlow renders the side connection's HTTP frame(s) for one flow
// (http_get/http_put) anchored to a main-session transfer transaction.
// The final event carries CloseConn=true so the tcp layer tears the
// side four-tuple down before the main session's next transaction.
func (g *CWMPGenerator) emitFlow(
	ctx context.Context,
	run *sessionRun,
	fl *core.CWMPFlow,
	flowDstIP string,
	emit func(layers.MessageEvent) error,
) error {
	host := bracketHost(fl.Host) + ":" + strconvI(uint64(fl.Port))
	uri := fl.URI
	if uri == "" {
		uri = "/"
	}
	method := "GET"
	if fl.Kind == "http_put" {
		method = "PUT"
	}
	var body []byte
	if fl.FileB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(fl.FileB64)
		if err != nil {
			return fmt.Errorf("cwmp: flows: file_b64 invalid base64: %w", err)
		}
		body = raw
	}
	ev := layers.MessageEvent{
		Up:    true,
		Bytes: BuildRequest(method, uri, host, "", "", "application/octet-stream", SOAPActionOmit, body, "", nil, "close"),
	}
	setEventEndpoint(&ev, fl.SrcPort, fl.Host, fl.Port)
	if err := emit(ev); err != nil {
		return err
	}
	// 副连接的 200 终止帧（文件下载服务端 / 上传对端响应）。
	resp := buildSOAPResponse(200, "application/octet-stream", body, "", "", "close")
	ev2 := layers.MessageEvent{
		Up:        false,
		Bytes:     resp,
		CloseConn: true,
	}
	setEventEndpoint(&ev2, fl.SrcPort, fl.Host, fl.Port)
	return emit(ev2)
}

// buildSOAPRequest renders a SOAP POST request with the optional tx-level
// HTTP overrides (HTTPMethod / SoapAction / ContentType / TransferEncoding
// / Authorization / Cookie / ContentLengthOverride).
func buildSOAPRequest(method, uri, host, id string, body []byte, cookie string, tx *core.CWMPTransaction, conn string) []byte {
	m := method
	if tx != nil && tx.HTTPMethod != "" {
		m = tx.HTTPMethod
	}
	ct := "text/xml; charset=\"utf-8\""
	if tx != nil && tx.ContentType != "" {
		ct = tx.ContentType
	}
	sa := ""
	if tx != nil && tx.SoapAction != nil {
		sa = *tx.SoapAction
	}
	te := ""
	if tx != nil && tx.TransferEncoding != "" {
		te = tx.TransferEncoding
	}
	auth := ""
	if tx != nil && tx.Authorization != "" {
		auth = tx.Authorization
	}
	ck := cookie
	if tx != nil && tx.Cookie != "" {
		ck = tx.Cookie
	}
	var cl *int
	if tx != nil && tx.ContentLengthOverride != nil {
		cl = tx.ContentLengthOverride
	}
	return BuildRequest(m, uri, host, auth, ck, ct, sa, body, te, cl, conn)
}

// buildSOAPResponse renders a SOAP response (delegates to BuildResponse;
// tx-level HTTPStatus/Location/SetCookie overrides are applied by callers
// that carry the transaction — emitACSResponse injects them via its own
// BuildResponse call sites).
func buildSOAPResponse(status int, contentType string, body []byte, setCookie, wwwAuth, conn string) []byte {
	return BuildResponse(status, contentType, setCookie, wwwAuth, "", body, "", conn)
}

// setEventEndpoint stamps the event with the connection's {src, dstIP, dst}
// so the generalized TCPGenerator (波 6) can build a four-tuple-aware
// connection state. srcPort=0 falls back to the resolved cfg value inside
// the tcp event loop.
func setEventEndpoint(ev *layers.MessageEvent, srcPort uint16, dstIP string, dstPort uint16) {
	if srcPort != 0 {
		ev.SrcPort = srcPort
	}
	if dstIP != "" {
		ev.OverrideDstIP = true
		ev.DstIP = dstIP
	}
	if dstPort != 0 {
		ev.DstPort = dstPort
	}
}

// bracketHost brackets IPv6 literals in the Host header.
func bracketHost(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

// ifaceDevice resolves a session's DeviceID (falling back to a per-call
// fixture when nil).
func ifaceDevice(d *core.CWMPDeviceID) core.CWMPDeviceID {
	if d == nil {
		return FixtureDeviceID()
	}
	return *d
}

// strconvI renders a uint64 as decimal.
func strconvI(v uint64) string { return strconv.FormatUint(v, 10) }

// GenEvents marks this generator as a message event producer.
func (g *CWMPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker. Events flow through GenRequest.EmitMsg only.
func (g *CWMPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("cwmp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("cwmp", func() (layers.LayerGenerator, error) {
		return &CWMPGenerator{}, nil
	})
	layers.RegisterLayerValidator("cwmp", func(spec *core.FlowSpec) error {
		return Validate(*spec)
	})
}
