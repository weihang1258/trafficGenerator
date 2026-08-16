package a2a

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner implements the A2A protocol planner.
type Planner struct{}

// NewPlanner creates a new A2A planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "a2a" }

// Validate validates an A2A flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("a2a: invalid source IP: %s", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("a2a: invalid destination IP: %s", spec.DstIP)
		}
	}
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("a2a: MSS %d too small (min %d per RFC 879)", spec.TCP.MSS, MinMSS)
		}
	}

	var cfg *A2AConfig
	// Try to parse config from Payload
	if len(spec.Payload) > 0 {
		if err := json.Unmarshal(spec.Payload, &cfg); err != nil {
			return fmt.Errorf("a2a: invalid config JSON in Payload: %w", err)
		}
	}
	if cfg == nil {
		return fmt.Errorf("a2a: config is required (set Payload to A2AConfig JSON)")
	}
	// cfg.TCP.MSS takes precedence over spec.TCP.MSS in Plan, so enforce the
	// RFC 879 minimum on it as well.
	if cfg.TCP.MSS > 0 && cfg.TCP.MSS < MinMSS {
		return fmt.Errorf("a2a: MSS %d too small (min %d per RFC 879)", cfg.TCP.MSS, MinMSS)
	}

	// V2: Validate method names
	for i, task := range cfg.Tasks {
		method := task.Method
		if method == "" {
			method = DefaultMethod
		}
		if !ValidMethods[method] {
			return fmt.Errorf("a2a validate: V2: method %q not in valid set", method)
		}

		// V8: Streaming consistency
		if task.Streaming {
			if !StreamingMethods[method] {
				return fmt.Errorf("a2a validate: V8: Streaming=true but Method=%q is not a streaming method", method)
			}
		} else {
			if !SyncMethods[method] {
				return fmt.Errorf("a2a validate: V8: Streaming=false but Method=%q is not a sync method", method)
			}
		}

		// V1: Task state validation
		if task.Response.Error == nil {
			var taskObj A2ATaskObject
			if err := json.Unmarshal(task.Response.Result, &taskObj); err == nil {
				if taskObj.Status.State != "" && !ValidTaskStates[taskObj.Status.State] {
					return fmt.Errorf("a2a validate: V1: invalid task state %q", taskObj.Status.State)
				}
			}
		}

		// V4: Part kind validation
		for j, part := range task.Message.Parts {
			if part.Kind != "text" && part.Kind != "data" && part.Kind != "file" {
				return fmt.Errorf("a2a validate: V4: Part kind=%q not in {text,data,file} at task[%d].parts[%d]", part.Kind, i, j)
			}
			if part.Kind == "text" && (len(part.Data) > 0 || part.File != nil) {
				return fmt.Errorf("a2a validate: V4: text Part has extra fields at task[%d].parts[%d]", i, j)
			}
			if part.Kind == "data" && (part.Text != "" || part.File != nil) {
				return fmt.Errorf("a2a validate: V4: data Part has extra fields at task[%d].parts[%d]", i, j)
			}
			if part.Kind == "file" && (part.Text != "" || len(part.Data) > 0) {
				return fmt.Errorf("a2a validate: V4: file Part has extra fields at task[%d].parts[%d]", i, j)
			}
			// V4: Kind=file 时 File 必须非 nil，否则生成的 JSON 缺少 file
			// 字段，违反 spec（FileWithBytes/FileWithUri 至少要有一个）。
			if part.Kind == "file" && part.File == nil {
				return fmt.Errorf("a2a validate: V4: file Part at task[%d].parts[%d] must carry a non-nil File", i, j)
			}
			// N3 修复：FileWithBytes 与 FileWithUri 至少满足其一。spec §2.6
			// FilePart required=[file,kind]，file 子对象在 schema anyOf 下
			// 必含 bytes 或 uri。此前实现只校验 File 非 nil，漏掉两个子字段
			// 都为空的退化情形，会输出 {"file":{}} 这种违反 anyOf 的报文。
			if part.Kind == "file" && part.File != nil && part.File.Bytes == "" && part.File.URI == "" {
				return fmt.Errorf("a2a validate: V4: file Part at task[%d].parts[%d] must carry Bytes or URI (FileWithBytes/FileWithUri)", i, j)
			}
		}

		// V7: Message validation
		if method == MethodMessageSend || method == MethodMessageStream {
			if task.Message.MessageID == "" {
				return fmt.Errorf("a2a validate: V7: Message.messageId is required")
			}
			if task.Message.Role != "user" && task.Message.Role != "agent" {
				return fmt.Errorf("a2a validate: V7: Message.role must be user or agent, got %q", task.Message.Role)
			}
			if len(task.Message.Parts) == 0 {
				return fmt.Errorf("a2a validate: V7: Message.parts must have at least 1 element")
			}
			if task.Message.Kind != "" && task.Message.Kind != DefaultMessageKind {
				return fmt.Errorf("a2a validate: V7: Message.kind must be %q", DefaultMessageKind)
			}
		}

		// V8: RequestID (JSON-RPC envelope id) is required. An explicit JSON
		// "null" is allowed: it models the -32600 response to a request that
		// carried no id (JSON-RPC 2.0 §6.11.2, design doc T004).
		if len(task.RequestID) == 0 {
			return fmt.Errorf("a2a validate: V8: RequestID (JSON-RPC id) is required")
		}

		// V12: length constraints per §2.10.
		if err := validateTaskLengths(task); err != nil {
			return err
		}

		// V8: TaskID requirements for task management methods
		if method == MethodTasksGet || method == MethodTasksCancel ||
			method == MethodTasksResubscribe || method == MethodTasksPushNotificationConfigGet {
			if task.TaskID == "" {
				return fmt.Errorf("a2a validate: V8: TaskID is required for method %q", method)
			}
		}
		if method == MethodTasksPushNotificationConfigSet {
			if task.TaskID == "" {
				return fmt.Errorf("a2a validate: V8: TaskID is required for method %q", method)
			}
			if task.PushNotificationConfig == nil {
				return fmt.Errorf("a2a validate: V8: PushNotificationConfig is required for method %q", method)
			}
		}

		// V5: PushNotificationConfig validation
		if task.PushNotificationConfig != nil {
			if task.PushNotificationConfig.URL == "" {
				return fmt.Errorf("a2a validate: V5: PushNotificationConfig.URL is required")
			}
			if task.PushNotificationConfig.Authentication != nil {
				if len(task.PushNotificationConfig.Authentication.Schemes) == 0 {
					return fmt.Errorf("a2a validate: V5: Authentication.Schemes must be non-empty")
				}
				for k, scheme := range task.PushNotificationConfig.Authentication.Schemes {
					if scheme == "" {
						return fmt.Errorf("a2a validate: V5: Authentication.Schemes[%d] is empty", k)
					}
				}
			}
		}

		// V9: SSE event validation
		// N5 修复：拆为两段——先确认是流式方法，再确认 SSEEvents 非空，最后
		// 进入子规则。两段分开让错误消息能精确定位"该流式却无事件"与"事件
		// 内容非法"两类不同问题，也避免 `task.Streaming && len(...)>0` 复合
		// 条件在只满足一半时静默跳过整个块。
		if task.Streaming {
			if len(task.SSEEvents) > 0 {
				firstKind := task.SSEEvents[0].Kind
				if firstKind != "task" && firstKind != "message" {
					return fmt.Errorf("a2a validate: V9: first SSE event kind must be task or message, got %q", firstKind)
				}
				lastState := ""
				for j, ev := range task.SSEEvents {
					if ev.Kind != "task" && ev.Kind != "message" && ev.Kind != "status-update" && ev.Kind != "artifact-update" {
						return fmt.Errorf("a2a validate: V9: invalid SSE event kind %q at event[%d]", ev.Kind, j)
					}
					if ev.Kind == "task" && ev.Task == nil {
						return fmt.Errorf("a2a validate: V9: task event missing Task object at event[%d]", j)
					}
					if ev.Kind == "message" && ev.Message == nil {
						return fmt.Errorf("a2a validate: V9: message event missing Message object at event[%d]", j)
					}
					if ev.Kind == "status-update" {
						if ev.StatusUpdate == nil {
							return fmt.Errorf("a2a validate: V9: status-update event missing Status at event[%d]", j)
						}
						if ev.StatusUpdate.TaskID == "" || ev.StatusUpdate.ContextID == "" {
							return fmt.Errorf("a2a validate: V9: status-update event missing taskId/contextId at event[%d]", j)
						}
					}
					if ev.Kind == "artifact-update" {
						if ev.ArtifactUpdate == nil || len(ev.ArtifactUpdate.Artifact.Parts) == 0 {
							return fmt.Errorf("a2a validate: V9: artifact-update event missing Artifact.Parts at event[%d]", j)
						}
						if ev.ArtifactUpdate.TaskID == "" || ev.ArtifactUpdate.ContextID == "" {
							return fmt.Errorf("a2a validate: V9: artifact-update event missing taskId/contextId at event[%d]", j)
						}
					}

					// V10: state transition legality per §4.2. Track the last
					// observed state across task/status-update events; every
					// transition must be listed in §4.2, except "any non-terminal
					// -> unknown" (abnormal: taskId expired) which §4.2 lists as
					// legal.
					var state string
					switch ev.Kind {
					case "task":
						if ev.Task != nil {
							state = ev.Task.Status.State
						}
					case "status-update":
						if ev.StatusUpdate != nil {
							state = ev.StatusUpdate.Status.State
						}
					}
					if state != "" && lastState != "" {
						legal := validTaskTransitions[lastState][state] ||
							(state == TaskStateUnknown && !IsTerminalState(lastState))
						if !legal {
							return fmt.Errorf("a2a validate: V10: illegal state transition %q -> %q at event[%d]", lastState, state, j)
						}
					}
					if state != "" {
						lastState = state
					}
				}
				last := task.SSEEvents[len(task.SSEEvents)-1]
				if last.Kind == "status-update" && !last.StatusUpdate.Final {
					return fmt.Errorf("a2a validate: V9: last status-update event must have Final=true")
				}
			}
		}

		// V16: result/error mutual exclusion
		// N1 修复：A2ATaskResponse.Result 加了 omitempty 后，"未设置"的形态
		// 有三种——空 RawMessage（len==0）、纯空白、字面 JSON null。三者均视
		// 为"未设置"，不与 Error 互斥冲突。只有携带实际 JSON 值（对象/数组
		// 等）的 Result 才与 Error 冲突。此前实现仅判 len>0，对 `null` 误报。
		if task.Response.Error != nil && isResultSet(task.Response.Result) {
			return fmt.Errorf("a2a validate: V16: result and error are mutually exclusive")
		}

		// V11: Error code validation
		if task.Response.Error != nil {
			validCodes := map[int]bool{
				-32700: true, -32600: true, -32601: true,
				-32602: true, -32603: true, -32001: true,
				-32002: true, -32003: true,
				-32004: true, -32005: true,
				-32006: true, -32007: true,
			}
			if !validCodes[task.Response.Error.Code] {
				return fmt.Errorf("a2a validate: V11: invalid error code %d", task.Response.Error.Code)
			}
		}
	}

	// V6: AgentCard validation
	if cfg.AgentCard != nil {
		card := cfg.AgentCard
		if card.Name == "" {
			return fmt.Errorf("a2a validate: V6: AgentCard.Name is required")
		}
		if card.Description == "" {
			return fmt.Errorf("a2a validate: V6: AgentCard.Description is required")
		}
		if card.URL == "" {
			return fmt.Errorf("a2a validate: V6: AgentCard.URL is required")
		}
		if card.Version == "" {
			return fmt.Errorf("a2a validate: V6: AgentCard.Version is required")
		}
		if card.ProtocolVersion == "" {
			return fmt.Errorf("a2a validate: V6: AgentCard.ProtocolVersion is required")
		}
		if card.Capabilities == nil {
			return fmt.Errorf("a2a validate: V6: AgentCard.Capabilities is required")
		}
		// V12: skills 0-1024 元素（空数组合法，T019/T173）。
		if len(card.DefaultInputModes) == 0 {
			return fmt.Errorf("a2a validate: V6: AgentCard.DefaultInputModes is required")
		}
		if len(card.DefaultOutputModes) == 0 {
			return fmt.Errorf("a2a validate: V6: AgentCard.DefaultOutputModes is required")
		}
		// V12: AgentCard length constraints per §2.10 (name/version 1-128
		// bytes, description 0-4096 bytes, skills 0-1024 elements).
		if len(card.Name) > 128 {
			return fmt.Errorf("a2a validate: V12: AgentCard.Name exceeds 128 bytes")
		}
		if len(card.Version) > 128 {
			return fmt.Errorf("a2a validate: V12: AgentCard.Version exceeds 128 bytes")
		}
		if len(card.Description) > 4096 {
			return fmt.Errorf("a2a validate: V12: AgentCard.Description exceeds 4096 bytes")
		}
		if len(card.Skills) > 1024 {
			return fmt.Errorf("a2a validate: V12: AgentCard.Skills exceeds 1024 elements")
		}
		// V6: when Security is non-empty, SecuritySchemes must contain the
		// corresponding scheme keys.
		for j, req := range card.Security {
			for schemeName := range req {
				if _, ok := card.SecuritySchemes[schemeName]; !ok {
					return fmt.Errorf("a2a validate: V6: Security[%d] references scheme %q not present in SecuritySchemes", j, schemeName)
				}
			}
		}
		for j, skill := range card.Skills {
			if skill.ID == "" {
				return fmt.Errorf("a2a validate: V6: Skill[%d].ID is required", j)
			}
			if skill.Name == "" {
				return fmt.Errorf("a2a validate: V6: Skill[%d].Name is required", j)
			}
			if skill.Description == "" {
				return fmt.Errorf("a2a validate: V6: Skill[%d].Description is required", j)
			}
		}
	}

	return nil
}

// isResultSet 报告 A2ATaskResponse.Result 是否携带了实际 JSON 值。
// "未设置"的三种形态：空 RawMessage、纯空白、字面 JSON null（含前后空白）。
// N1 修复引入：Result 加 omitempty 后，用户显式写 "result": null 不再被
// V16 误判为与 error 互斥（null 表示"无 result"，与 error 可共存）。
func isResultSet(r json.RawMessage) bool {
	trimmed := bytes.TrimSpace(r)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

// maxPartTextLen is the 1MB upper bound for Part.text (design doc §2.10).
const maxPartTextLen = 1 << 20

// validateTaskLengths enforces V12 length constraints per design doc §2.10:
// taskId/contextId/messageId 1-128 bytes, parts 1-1024 elements, Part.text
// 0-1MB. The JSON-RPC id string is capped at 128 bytes (integers must be >= 0).
//
// id 类型白名单（spec §2.10 + JSON-RPC §6.11.2）：
//   - string（≤128 字节）
//   - integer（≥0）
//   - 显式 null（§6.11.2，用于无 id 请求的 parse-error 响应）
//
// 其余类型（object/array/bool/float）一律拒绝。此前实现只尝试 string 与
// json.Number，二者都失败时静默放行，导致非法 id 类型进入下游。
func validateTaskLengths(task A2ATask) error {
	// JSON-RPC id: string <= 128 bytes; integer >= 0; explicit null allowed.
	trimmed := bytes.TrimSpace(task.RequestID)
	if len(trimmed) == 0 {
		// V8 已校验 RequestID 必须存在，这里防御性返回。
		return fmt.Errorf("a2a validate: V12: JSON-RPC id is required")
	}
	if bytes.Equal(trimmed, []byte("null")) {
		// 显式 null：§6.11.2 允许，跳过长度校验。
	} else {
		var idStr string
		if err := json.Unmarshal(task.RequestID, &idStr); err == nil {
			if len(idStr) > 128 {
				return fmt.Errorf("a2a validate: V12: JSON-RPC id string exceeds 128 bytes")
			}
		} else {
			var idNum json.Number
			if err := json.Unmarshal(task.RequestID, &idNum); err == nil {
				n, err := idNum.Int64()
				if err != nil {
					// 浮点数或超出 int64 范围：spec 限定 integer，拒绝。
					return fmt.Errorf("a2a validate: V12: JSON-RPC id must be an integer (got %s)", string(idNum))
				}
				if n < 0 {
					return fmt.Errorf("a2a validate: V12: JSON-RPC id integer must be >= 0")
				}
			} else {
				// 既不是 string 也不是 number：object/array/bool 等非法类型。
				return fmt.Errorf("a2a validate: V12: JSON-RPC id must be a string <= 128 bytes, an integer >= 0, or null")
			}
		}
	}
	if len(task.TaskID) > 128 {
		return fmt.Errorf("a2a validate: V12: taskId exceeds 128 bytes")
	}
	if len(task.Message.MessageID) > 128 {
		return fmt.Errorf("a2a validate: V12: messageId exceeds 128 bytes")
	}
	if len(task.Message.ContextID) > 128 {
		return fmt.Errorf("a2a validate: V12: contextId exceeds 128 bytes")
	}
	if len(task.Message.Parts) > 1024 {
		return fmt.Errorf("a2a validate: V12: Message.parts exceeds 1024 elements")
	}
	for i, part := range task.Message.Parts {
		if part.Kind == "text" && len(part.Text) > maxPartTextLen {
			return fmt.Errorf("a2a validate: V12: Part.text at parts[%d] exceeds 1MB", i)
		}
	}
	return nil
}

// Plan generates packet configs for an A2A flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		// ctx 取消时立即退出，避免在消费者停止读取后阻塞于 configChan <- cfg。
		// 此前实现完全忽略 ctx，导致取消/超时后 goroutine 泄漏。
		if ctx.Err() != nil {
			return
		}

		var cfg *A2AConfig
		// Parse config from Payload
		if len(spec.Payload) > 0 {
			_ = json.Unmarshal(spec.Payload, &cfg)
		}
		if cfg == nil {
			return
		}

		// Default A2ATCP fields per design doc §5.7: Handshake/Termination
		// 默认 true。使用 *bool 以区分"未设置"（nil→默认 true）与"显式 false"。
		// 此前实现用 bool 零值 false 表示"未设置"，导致显式 false 被强制覆盖为 true。
		tcpCfg := cfg.TCP
		handshake := true
		if tcpCfg.Handshake != nil {
			handshake = *tcpCfg.Handshake
		}
		termination := true
		if tcpCfg.Termination != nil {
			termination = *tcpCfg.Termination
		}

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		mss := uint16(DefaultMSS)
		if cfg.TCP.MSS > 0 {
			mss = cfg.TCP.MSS
		} else if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		synOpts := synOptions(mss)

		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(rand.Uint32())
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		clientSeq := uint32(0)
		if cfg.TCP.InitialSeq != 0 {
			clientSeq = cfg.TCP.InitialSeq
		} else if spec.TCP != nil {
			clientSeq = spec.TCP.InitialSeq
		}
		if clientSeq == 0 {
			clientSeq = rand.Uint32()
		}
		serverSeq := rand.Uint32()

		winSize := uint16(65535)
		if spec.TCP != nil && spec.TCP.WindowSize > 0 {
			winSize = spec.TCP.WindowSize
		}

		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) {
			l3 := core.L3Base(srcIP, dstIP, 6, effectiveTTL, nextIPID(), spec)
			l4 := core.L4Config{
				Protocol:   "tcp",
				SrcPort:    srcPort,
				DstPort:    dstPort,
				Seq:        seq,
				Ack:        ack,
				Flags:      flags,
				WindowSize: winSize,
			}
			if flags == 0x02 || flags == 0x12 {
				l4.TCPOptions = synOpts
			}
			pc := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(srcIP),
				},
				L3:      l3,
				L4:      l4,
				Payload: payload,
			}
			select {
			case configChan <- pc:
			case <-ctx.Done():
				// ctx 取消：放弃剩余包，goroutine 将在调用方 return 后退出。
			}
			packetIndex++
		}

		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) uint32 {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		// --- TCP handshake ---
		if handshake {
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
			clientSeq++
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
			serverSeq++
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
		}

		// --- Agent Card discovery ---
		if cfg.Discover && cfg.AgentCard != nil {
			path := cfg.AgentCardPath
			if path == "" {
				path = DefaultAgentCardPath
			}
			req := buildAgentCardRequest(cfg, path, spec.DstIP)
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, []byte(req))

			respBody, _ := json.Marshal(cfg.AgentCard)
			resp := buildHTTPResponse(cfg, 200, "OK", "application/json", respBody, false)
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, []byte(resp))

			if tcpCfg.ACKPolicy != "lazy" {
				emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
			}
		}

		// --- Tasks ---
		for taskIdx, task := range cfg.Tasks {
			method := task.Method
			if method == "" {
				method = DefaultMethod
			}

			isLastTask := taskIdx == len(cfg.Tasks)-1
			isStreaming := task.Streaming

			// Build request
			reqBody := buildJSONRPCRequest(cfg, task, method)
			accept := cfg.HTTP.Accept
			if accept == "" {
				accept = DefaultAccept
			}
			if isStreaming {
				accept = "text/event-stream"
			}
			connection := cfg.HTTP.Connection
			if connection == "" {
				connection = DefaultConnection
			}
			if isLastTask && termination {
				connection = "close"
			}

			req := buildA2ARequest(cfg, method, reqBody, accept, connection, spec.DstIP)
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, []byte(req))

			// Build response
			if isStreaming {
				// SSE response: full HTTP response with
				// Content-Type: text/event-stream and chunked framing
				// (design doc §6.2 S3/S6, §10.6 #4). The data: lines are the
				// body; status code honors A2ATaskResponse.StatusCode.
				sseBody := buildSSEResponse(cfg, task)
				statusCode := task.Response.StatusCode
				if statusCode == 0 {
					statusCode = 200
				}
				resp := buildHTTPResponse(cfg, statusCode, statusTextFor(statusCode), "text/event-stream", sseBody, true)
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, []byte(resp))
			} else {
				var respBody []byte
				if task.Response.Error != nil {
					errObj := map[string]any{
						"code":    task.Response.Error.Code,
						"message": task.Response.Error.Message,
					}
					if task.Response.Error.Data != nil {
						errObj["data"] = task.Response.Error.Data
					}
					// BUG-2 fix: resolveIDForOutput substitutes the default
					// "req-001" only when the RequestID is truly absent
					// (RawMessage is empty). An explicit JSON null is
					// preserved as-is per JSON-RPC 2.0 §6.11.2 so the
					// response carries "id":null rather than missing id
					// or a fabricated string.
					rawID := unmarshalID(task.RequestID)
					resolvedID := resolveIDForOutput(rawID)
					respMap := map[string]any{
						"jsonrpc": "2.0",
						"error":   errObj,
						"id":      resolvedID,
					}
					respBody, _ = json.Marshal(respMap)
				} else {
					rawID := unmarshalID(task.RequestID)
					resolvedID := resolveIDForOutput(rawID)
					respMap := map[string]any{
						"jsonrpc": "2.0",
						"result":  json.RawMessage(task.Response.Result),
						"id":      resolvedID,
					}
					respBody, _ = json.Marshal(respMap)
				}
				statusCode := task.Response.StatusCode
				if statusCode == 0 {
					statusCode = 200
				}
				resp := buildHTTPResponse(cfg, statusCode, statusTextFor(statusCode), "application/json", respBody, false)
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, []byte(resp))
			}

			if tcpCfg.ACKPolicy != "lazy" {
				emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
			}
		}

		// --- TCP teardown ---
		// Design doc §6.1 #4: FIN-ACK (up) -> FIN-ACK (down) -> ACK (up),
		// 3 packets with the intermediate ACK merged into the FIN.
		if termination {
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil)
			clientSeq++
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil)
			serverSeq++
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
		}
	}()

	return configChan, nil
}

// unmarshalID returns the JSON-RPC id preserved as json.RawMessage.
//
// Three cases, per JSON-RPC 2.0 §6 / §6.11.2:
//  1. RawMessage is empty (len == 0) — the spec treats "no id" as an
//     invalid request; callers substitute a synthetic default (req-001).
//     We return an empty RawMessage so the caller can distinguish "absent".
//  2. RawMessage is the literal JSON null — explicitly allowed by
//     §6.11.2 for parse-error responses to id-less requests. We return
//     json.RawMessage("null") so it serializes as the JSON null literal,
//     NOT as Go's nil which json.Marshal would omit entirely from the
//     output object (violating JSON-RPC 2.0 §6 "id MUST be present").
//  3. RawMessage is a valid JSON literal (string/number) — return it
//     unchanged so the caller can embed it as a raw value in the response.
func unmarshalID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		// No id present at all: signal callers to substitute default.
		return json.RawMessage(nil)
	}
	// Detect literal null without unmarshaling (avoids losing the
	// distinction between "explicit null" and "missing").
	trimmed := bytes.TrimSpace(id)
	if bytes.Equal(trimmed, []byte("null")) {
		return json.RawMessage("null")
	}
	return id
}

// resolveIDForOutput takes the RawMessage returned by unmarshalID and
// produces the final id value for embedding in a JSON-RPC envelope:
//   - Empty (len==0, i.e. RequestID was absent) → synthetic default
//     "req-001" per Validate's V8 rule that every request must carry an id.
//   - Literal null → passed through unchanged, serialized as JSON null
//     per JSON-RPC 2.0 §6.11.2.
//   - Any other value (string/number) → returned unchanged.
//
// The function returns a json.RawMessage so it can be embedded in a
// map[string]any that will be json.Marshal'd; the raw form preserves
// the original JSON representation (including null).
func resolveIDForOutput(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage(`"req-001"`)
	}
	return id
}

// buildAgentCardRequest builds the HTTP GET request for Agent Card discovery.
func buildAgentCardRequest(cfg *A2AConfig, path, dstIP string) string {
	var sb strings.Builder
	version := cfg.HTTP.Version
	if version == "" {
		version = DefaultHTTPVersion
	}
	sb.WriteString(fmt.Sprintf("GET %s %s\r\n", path, version))
	sb.WriteString(fmt.Sprintf("Host: %s\r\n", bracketHost(dstIP)))
	if !hasHeader(cfg.HTTP.ExtraHeaders, "Accept") {
		sb.WriteString("Accept: application/json\r\n")
	}
	ua := cfg.HTTP.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}
	if !hasHeader(cfg.HTTP.ExtraHeaders, "User-Agent") {
		sb.WriteString(fmt.Sprintf("User-Agent: %s\r\n", ua))
	}
	conn := cfg.HTTP.Connection
	if conn == "" {
		conn = DefaultConnection
	}
	if !hasHeader(cfg.HTTP.ExtraHeaders, "Connection") {
		sb.WriteString(fmt.Sprintf("Connection: %s\r\n", conn))
	}
	for k, v := range cfg.HTTP.ExtraHeaders {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	sb.WriteString("\r\n")
	return sb.String()
}

// requestPath extracts the request path from the configured BaseURL
// (AgentCard.url, e.g. https://agent.example.com/a2a -> /a2a). Falls back
// to /a2a when BaseURL is unset or carries no path.
func requestPath(cfg *A2AConfig) string {
	if cfg.BaseURL != "" {
		if u, err := url.Parse(cfg.BaseURL); err == nil && u.Path != "" {
			return u.Path
		}
	}
	return "/a2a"
}

// buildA2ARequest builds the HTTP POST request with JSON-RPC body.
func buildA2ARequest(cfg *A2AConfig, method string, body []byte, accept, connection, dstIP string) string {
	var sb strings.Builder
	version := cfg.HTTP.Version
	if version == "" {
		version = DefaultHTTPVersion
	}
	path := requestPath(cfg)
	// API key in query: append ?name=value to the request path (design doc
	// T096). in=cookie maps to a Cookie header; in=header to a custom header.
	if cfg.Auth.Scheme == "apikey" && cfg.Auth.APIKey != "" &&
		strings.EqualFold(cfg.Auth.APIKeyIn, "query") {
		name := cfg.Auth.APIKeyName
		if name == "" {
			name = DefaultAPIKeyName
		}
		if strings.Contains(path, "?") {
			path += "&"
		} else {
			path += "?"
		}
		path += url.QueryEscape(name) + "=" + url.QueryEscape(cfg.Auth.APIKey)
	}
	sb.WriteString(fmt.Sprintf("POST %s %s\r\n", path, version))
	sb.WriteString(fmt.Sprintf("Host: %s\r\n", bracketHost(dstIP)))
	if !hasHeader(cfg.HTTP.ExtraHeaders, "Content-Type") {
		sb.WriteString("Content-Type: application/json\r\n")
	}
	if !hasHeader(cfg.HTTP.ExtraHeaders, "Accept") {
		sb.WriteString(fmt.Sprintf("Accept: %s\r\n", accept))
	}
	if !hasHeader(cfg.HTTP.ExtraHeaders, "Content-Length") {
		sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}
	ua := cfg.HTTP.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}
	if !hasHeader(cfg.HTTP.ExtraHeaders, "User-Agent") {
		sb.WriteString(fmt.Sprintf("User-Agent: %s\r\n", ua))
	}
	if !hasHeader(cfg.HTTP.ExtraHeaders, "Connection") {
		sb.WriteString(fmt.Sprintf("Connection: %s\r\n", connection))
	}

	// Authorization header
	authHeader := buildAuthHeader(cfg.Auth)
	if authHeader != "" && !hasHeader(cfg.HTTP.ExtraHeaders, "Authorization") &&
		!hasHeader(cfg.HTTP.ExtraHeaders, "Cookie") {
		sb.WriteString(authHeader + "\r\n")
	}

	for k, v := range cfg.HTTP.ExtraHeaders {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	sb.WriteString("\r\n")
	sb.Write(body)
	return sb.String()
}

// buildAuthHeader builds the Authorization (or API key) header based on
// auth config. API keys in "query" are handled by the caller (URL param).
func buildAuthHeader(auth A2AAuth) string {
	switch auth.Scheme {
	case "bearer", "oauth2", "openIdConnect":
		if auth.Token != "" {
			return fmt.Sprintf("Authorization: Bearer %s", auth.Token)
		}
	case "basic":
		if auth.Username != "" || auth.Password != "" {
			cred := base64.StdEncoding.EncodeToString([]byte(auth.Username + ":" + auth.Password))
			return fmt.Sprintf("Authorization: Basic %s", cred)
		}
	case "apikey":
		if auth.APIKey != "" {
			name := auth.APIKeyName
			if name == "" {
				name = DefaultAPIKeyName
			}
			in := auth.APIKeyIn
			if in == "" {
				in = DefaultAPIKeyIn
			}
			switch in {
			case "header", "":
				return fmt.Sprintf("%s: %s", name, auth.APIKey)
			case "cookie":
				return fmt.Sprintf("Cookie: %s=%s", name, auth.APIKey)
			}
			// "query" is handled by buildA2ARequest (URL parameter)
		}
	}
	return ""
}

// hasHeader reports whether headers contains a header with the given name
// (case-insensitive per RFC 7230 §3.2).
func hasHeader(headers map[string]string, name string) bool {
	for k := range headers {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

// buildHTTPResponse builds an HTTP response.
//
// 当 isChunked=true 时，按 RFC 7230 §4.1 对 body 进行 chunked 传输编码：
// 整个 body 作为一个 chunk 输出（`<hex 长度>\r\n<body>\r\n`），并以结束
// chunk `0\r\n\r\n` 收尾。此前实现仅写入 Transfer-Encoding 头但 body
// 原样输出，导致 Wireshark 将其识别为格式错误的 chunked body。
func buildHTTPResponse(cfg *A2AConfig, statusCode int, statusText, contentType string, body []byte, isChunked bool) string {
	var sb strings.Builder
	version := cfg.HTTP.Version
	if version == "" {
		version = DefaultHTTPVersion
	}
	if statusText == "" {
		statusText = statusTextFor(statusCode)
	}
	sb.WriteString(fmt.Sprintf("%s %d %s\r\n", version, statusCode, statusText))
	if !hasHeader(cfg.HTTP.ExtraHeaders, "Content-Type") {
		sb.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	}
	if isChunked {
		if !hasHeader(cfg.HTTP.ExtraHeaders, "Transfer-Encoding") {
			sb.WriteString("Transfer-Encoding: chunked\r\n")
		}
		if !hasHeader(cfg.HTTP.ExtraHeaders, "Cache-Control") {
			sb.WriteString("Cache-Control: no-cache\r\n")
		}
	} else {
		if !hasHeader(cfg.HTTP.ExtraHeaders, "Content-Length") {
			sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		}
	}
	conn := cfg.HTTP.Connection
	if conn == "" {
		conn = DefaultConnection
	}
	if !hasHeader(cfg.HTTP.ExtraHeaders, "Connection") {
		sb.WriteString(fmt.Sprintf("Connection: %s\r\n", conn))
	}
	for k, v := range cfg.HTTP.ExtraHeaders {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	sb.WriteString("\r\n")
	if isChunked {
		// chunked body: 一个数据 chunk + 结束 chunk。
		// 零长度 body 仍需输出结束 chunk，保持帧结构完整。
		if len(body) > 0 {
			sb.WriteString(fmt.Sprintf("%x\r\n", len(body)))
			sb.Write(body)
			sb.WriteString("\r\n")
		}
		sb.WriteString("0\r\n\r\n")
	} else {
		sb.Write(body)
	}
	return sb.String()
}

// buildJSONRPCRequest builds the JSON-RPC request body.
func buildJSONRPCRequest(cfg *A2AConfig, task A2ATask, method string) []byte {
	params := make(map[string]any)

	switch method {
	case MethodMessageSend, MethodMessageStream:
		msg := task.Message
		if msg.Kind == "" {
			msg.Kind = DefaultMessageKind
		}
		msgMap := messageToMap(msg)
		params["message"] = msgMap
		if task.Configuration != nil {
			cfgMap := map[string]any{}
			if len(task.Configuration.AcceptedOutputModes) > 0 {
				cfgMap["acceptedOutputModes"] = task.Configuration.AcceptedOutputModes
			}
			if task.Configuration.Blocking != nil {
				cfgMap["blocking"] = *task.Configuration.Blocking
			}
			if task.Configuration.HistoryLength != nil {
				cfgMap["historyLength"] = *task.Configuration.HistoryLength
			}
			if task.Configuration.PushNotificationConfig != nil {
				cfgMap["pushNotificationConfig"] = pushNotificationConfigToMap(*task.Configuration.PushNotificationConfig)
			}
			params["configuration"] = cfgMap
		}
	case MethodTasksGet:
		params["id"] = task.TaskID
		if task.HistoryLength > 0 {
			params["historyLength"] = task.HistoryLength
		}
	case MethodTasksCancel:
		params["id"] = task.TaskID
	case MethodTasksResubscribe:
		params["id"] = task.TaskID
	case MethodTasksPushNotificationConfigSet:
		params["taskId"] = task.TaskID
		if task.PushNotificationConfig != nil {
			params["pushNotificationConfig"] = pushNotificationConfigToMap(*task.PushNotificationConfig)
		}
	case MethodTasksPushNotificationConfigGet:
		params["id"] = task.TaskID
	}

	// ParamsMetadata 嵌套到 params.metadata 子对象（A2A spec：params 下的
	// metadata 字段）。此前实现把每个 key 展开到 params 顶层，会污染
	// message/id/taskId 等标准字段。
	if len(task.ParamsMetadata) > 0 {
		params["metadata"] = task.ParamsMetadata
	}

	// BUG-1 fix: resolveIDForOutput preserves an explicit JSON null
	// (RawMessage "null") instead of replacing it with "req-001".
	// Only an empty/absent RequestID falls back to the synthetic default.
	reqID := resolveIDForOutput(unmarshalID(task.RequestID))

	req := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      reqID,
	}
	b, _ := json.Marshal(req)
	return b
}

// buildSSEResponse builds the SSE stream response body.
func buildSSEResponse(cfg *A2AConfig, task A2ATask) []byte {
	var sb strings.Builder
	// BUG-1 fix: resolveIDForOutput preserves an explicit JSON null
	// (RawMessage "null") instead of replacing it with "req-001".
	// Only an empty/absent RequestID falls back to the synthetic default.
	reqID := resolveIDForOutput(unmarshalID(task.RequestID))

	for _, ev := range task.SSEEvents {
		var result map[string]any
		switch ev.Kind {
		case "task":
			if ev.Task != nil {
				result = taskObjectToMap(*ev.Task)
			}
		case "message":
			if ev.Message != nil {
				result = messageToMap(*ev.Message)
			}
		case "status-update":
			if ev.StatusUpdate != nil {
				result = statusUpdateToMap(*ev.StatusUpdate)
			}
		case "artifact-update":
			if ev.ArtifactUpdate != nil {
				result = artifactUpdateToMap(*ev.ArtifactUpdate)
			}
		}
		if result == nil {
			continue
		}
		resp := map[string]any{
			"jsonrpc": "2.0",
			"id":      reqID,
			"result":  result,
		}
		b, _ := json.Marshal(resp)
		sb.WriteString("data: ")
		sb.Write(b)
		sb.WriteString("\n\n")
	}

	return []byte(sb.String())
}

// messageToMap converts A2AMessage to map.
func messageToMap(msg A2AMessage) map[string]any {
	m := map[string]any{
		"role":      msg.Role,
		"parts":     partsToMaps(msg.Parts),
		"messageId": msg.MessageID,
		"kind":      msg.Kind,
	}
	if msg.Kind == "" {
		m["kind"] = DefaultMessageKind
	}
	if msg.TaskID != "" {
		m["taskId"] = msg.TaskID
	}
	if msg.ContextID != "" {
		m["contextId"] = msg.ContextID
	}
	if len(msg.ReferenceTaskIDs) > 0 {
		m["referenceTaskIds"] = msg.ReferenceTaskIDs
	}
	if len(msg.Extensions) > 0 {
		m["extensions"] = msg.Extensions
	}
	if len(msg.Metadata) > 0 {
		m["metadata"] = msg.Metadata
	}
	return m
}

// partsToMaps converts []A2APart to []map[string]any.
func partsToMaps(parts []A2APart) []map[string]any {
	out := make([]map[string]any, len(parts))
	for i, p := range parts {
		m := map[string]any{"kind": p.Kind}
		switch p.Kind {
		case "text":
			m["text"] = p.Text
		case "data":
			m["data"] = p.Data
		case "file":
			if p.File != nil {
				fm := map[string]any{}
				if p.File.Name != "" {
					fm["name"] = p.File.Name
				}
				if p.File.MimeType != "" {
					fm["mimeType"] = p.File.MimeType
				}
				if p.File.Bytes != "" {
					fm["bytes"] = p.File.Bytes
				}
				if p.File.URI != "" {
					fm["uri"] = p.File.URI
				}
				m["file"] = fm
			}
		}
		if len(p.Metadata) > 0 {
			m["metadata"] = p.Metadata
		}
		out[i] = m
	}
	return out
}

// taskObjectToMap converts A2ATaskObject to map.
func taskObjectToMap(t A2ATaskObject) map[string]any {
	m := map[string]any{
		"id":        t.ID,
		"contextId": t.ContextID,
		"status":    taskStatusToMap(t.Status),
		"kind":      t.Kind,
	}
	if t.Kind == "" {
		m["kind"] = DefaultTaskKind
	}
	if len(t.Artifacts) > 0 {
		arts := make([]map[string]any, len(t.Artifacts))
		for i, a := range t.Artifacts {
			arts[i] = artifactToMap(a)
		}
		m["artifacts"] = arts
	}
	if len(t.History) > 0 {
		hist := make([]map[string]any, len(t.History))
		for i, h := range t.History {
			hist[i] = messageToMap(h)
		}
		m["history"] = hist
	}
	if len(t.Metadata) > 0 {
		m["metadata"] = t.Metadata
	}
	return m
}

// taskStatusToMap converts A2ATaskStatus to map.
func taskStatusToMap(s A2ATaskStatus) map[string]any {
	m := map[string]any{
		"state": s.State,
	}
	if s.Message != nil {
		m["message"] = messageToMap(*s.Message)
	}
	if s.Timestamp != "" {
		m["timestamp"] = s.Timestamp
	}
	return m
}

// artifactToMap converts A2AArtifact to map.
func artifactToMap(a A2AArtifact) map[string]any {
	m := map[string]any{
		"artifactId": a.ArtifactID,
		"parts":      partsToMaps(a.Parts),
	}
	if a.Name != "" {
		m["name"] = a.Name
	}
	if a.Description != "" {
		m["description"] = a.Description
	}
	if len(a.Extensions) > 0 {
		m["extensions"] = a.Extensions
	}
	if len(a.Metadata) > 0 {
		m["metadata"] = a.Metadata
	}
	return m
}

// statusUpdateToMap converts A2ATaskStatusUpdateEvent to map.
func statusUpdateToMap(e A2ATaskStatusUpdateEvent) map[string]any {
	m := map[string]any{
		"taskId":    e.TaskID,
		"contextId": e.ContextID,
		"kind":      e.Kind,
		"status":    taskStatusToMap(e.Status),
		"final":     e.Final,
	}
	if e.Kind == "" {
		m["kind"] = DefaultStatusUpdateKind
	}
	if len(e.Metadata) > 0 {
		m["metadata"] = e.Metadata
	}
	return m
}

// artifactUpdateToMap converts A2ATaskArtifactUpdateEvent to map.
func artifactUpdateToMap(e A2ATaskArtifactUpdateEvent) map[string]any {
	m := map[string]any{
		"taskId":    e.TaskID,
		"contextId": e.ContextID,
		"kind":      e.Kind,
		"artifact":  artifactToMap(e.Artifact),
		"append":    e.Append,
		"lastChunk": e.LastChunk,
	}
	if e.Kind == "" {
		m["kind"] = DefaultArtifactUpdateKind
	}
	if len(e.Metadata) > 0 {
		m["metadata"] = e.Metadata
	}
	return m
}

// pushNotificationConfigToMap converts A2APushNotificationConfig to map.
func pushNotificationConfigToMap(p A2APushNotificationConfig) map[string]any {
	m := map[string]any{
		"url": p.URL,
	}
	if p.ID != "" {
		m["id"] = p.ID
	}
	if p.Token != "" {
		m["token"] = p.Token
	}
	if p.Authentication != nil {
		auth := map[string]any{
			"schemes": p.Authentication.Schemes,
		}
		if p.Authentication.Credentials != "" {
			auth["credentials"] = p.Authentication.Credentials
		}
		m["authentication"] = auth
	}
	return m
}

// segmentByMSS splits payload into chunks of at most mss bytes.
func segmentByMSS(payload []byte, mss int) [][]byte {
	if mss <= 0 {
		return [][]byte{payload}
	}
	if len(payload) == 0 {
		return [][]byte{{}}
	}
	chunks := make([][]byte, 0, (len(payload)+mss-1)/mss)
	for len(payload) > 0 {
		n := len(payload)
		if n > mss {
			n = mss
		}
		chunks = append(chunks, payload[:n])
		payload = payload[n:]
	}
	return chunks
}

// synOptions builds TCP options for SYN packets.
func synOptions(mss uint16) []core.TCPOption {
	if mss == 0 {
		mss = DefaultMSS
	}
	opts := make([]core.TCPOption, 0, 3)
	opts = append(opts, core.TCPOption{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptWinScale, Data: []byte{0x07}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptSACKPermit})
	return opts
}

// bracketHost wraps IPv6 literals in brackets.
func bracketHost(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

// statusTextFor returns the reason phrase for the given status code.
func statusTextFor(code int) string {
	switch code {
	case 100:
		return "Continue"
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 500:
		return "Internal Server Error"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	}
	return fmt.Sprintf("Status %d", code)
}

// MinMSS is the minimum acceptable MSS per RFC 879.
const MinMSS = 536
