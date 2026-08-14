package smb

// layer_gen.go: SMB terminal-layer generator (smb 终结层层生成器, P4a)。
// 一次 flow = 一个 4-tuple 上的完整 SMB2 会话：NEGOTIATE → SESSION_SETUP →
// TREE_CONNECT → CREATE → Operations → CLOSE → TREE_DISCONNECT → LOGOFF
// （legacy Plan smb.go:69-335 逐命令同序）。每个 PDU 一个"报文事件"（方向 +
// 完整 wire 字节：NBSS(4) + 可选 TRANSFORM_HEADER(52) + SMB2 头(64) + 体），
// 构建字节由 buildSMB2Header / buildNBSSHeader / buildTransformHeader /
// build*RequestBody/ResponseBody 纯函数产出（复用，不重写）。事件模式
// （http 波 2 方案 A 同款）：TCP 语义（握手/seq-ack/挥手/MSS 分段）交给
// tcp 层生成器。
//
// 与 legacy Plan（smb.go:69-335）的差异（文档化 divergence）：
//   - legacy 自产 TCP 握手（3 包）与挥手（3 包：FIN up → FIN down → ACK up，
//     smb.go:310-317）——事件模式不产：tcp 层生成器负责（防双握手）。握手/
//     挥手开关由 tcp 层 schema 默认 true 执行，validator 强制校准 true
//     （legacy smb.go 恒产握手/挥手，从不读 spec.TCP.Handshake/Termination，
//     语义一致）。链上挥手是 TCPGenerator 标准 4 包（FIN|ACK up → ACK down
//     → FIN|ACK down → ACK up），与 legacy 3 包挥手为层模型意图的文档化
//     分歧（modbus/dnp3/doip 链测试同款断言形状）。
//   - legacy RST 挥手（spec.TCP.RST=true → 单 RST 包）：链上 tcp 层终止不
//     支持 RST 开关，生成器忽略 spec.TCP.RST（TCP 层语义见 tcp 层生成器）。
//   - legacy 的 MSS 分段（emitPayloadMSS 按 spec.TCP.MSS 切数据段，smb.go:93-97
//     默认 1460）在链上由 tcp 层生成器执行，生成器不预分段（事件 = 完整
//     PDU）。
//   - 逐包 Timestamp：legacy 恒 now（smb.go:99）；链上由 ChainPlanner 统一
//     回填（chain_planner.go:400），事件流不产。
//   - 握手 seq：legacy 随机 ISN（smb.go:108-109 randUint32）；链上由 tcp 层
//     生成器持有，事件流不产。
//   - 多流展开不存在（smb 无 Sessions 概念——单会话恒一个 flow），无需
//     拒绝检查（modbus/nfs 的拒绝纪律不适用）。
//   - 源端口：legacy Plan 用 spec.SrcPort 原值（0 也上包，smb.go:41 同款）——
//     validateSpecBase 对 smb 分支不默认化 srcPort，与 legacy 一致（modbus/
//     mqtt/nfs 同款）。
//   - 目的端口默认化：legacy 无 Plan 内默认（spec.DstPort 原值上包）；
//     strategy_convert.go:931-947 与 validateSpecBase 同款默认（direct →
//     445、netbios → 139），生成器不再默认。
//   - NBSS 前缀：legacy emitSMB2PDU 恒 useNBSS=true（emit.go:124-127，direct
//     与 netbios 两模式均带 4B NBSS 头）；生成器事件同样恒带 NBSS 前缀。
//     Transport 字段在生成器内只影响 validateSpecBase 的目的端口（netbios
//     → 139），不影响 wire 字节。
//   - SessionId：legacy 经包级原子 nextSessionID()（smb.go:63-66）分配，事件
//     生成与 legacy 对比时两运行各自消耗一个计数值——SessionId 字段（SMB2
//     头偏移 40-47）不可预测，字节对比须掩码该字段（modbus SharedTIDSpace、
//     mqtt autoClientID 同款先例：共享计数器的字段不做逐字节对比）。
//   - ClientGuid/ServerGuid/FileId：applyDefaults 对零值随机化（validate.go:
//     199-205/312-314）——测试须显式设置确定性值；fakeSalt 用
//     time.Now().UnixNano()（builder.go:101-111）→ PreauthIntegrityHashAlgorithms
//     非空时 NEGOTIATE 请求盐字节非确定，测试须掩码盐区。
//
// 生成器内部顺序与 legacy Plan（smb.go:69-335）逐命令一致，IncludeNegotiate/
// IncludeAuth/IncludeTreeConnect/IncludeTeardown 门控、ErrorOnCommand 错误
// 注入语义（negotiate/session_setup/tree_connect 错误跳过后续阶段、
// create 错误仍走完整拆解、read/write/close 错误中断 ops 循环、
// tree_disconnect/logoff 错误响应后拆解继续）、EncryptionRequired →
// TRANSFORM_HEADER 包裹（认证完成后）、SigningRequired → FlagSigned +
// 签名占位字节——全部复刻；事件方向/字节与 legacy 数据帧（flags=0x18
// PSH-ACK payload）一一对应。

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// SMBGenerator is the smb terminal-layer generator.
type SMBGenerator struct{}

// Name returns "smb".
func (g *SMBGenerator) Name() string { return "smb" }

// sessionState is the per-session SMB2 state, mirroring smbSessionState
// (smb.go:323-335) minus the packet-emission fields (seq/ttl/ipid/flowID)。
type sessionState struct {
	messageID       uint64
	sessionID       uint64
	treeID          uint32
	treeIDCounter   uint32
	fileID          [16]byte
	dialectRev      uint16
	encryptRequired bool
}

// Generate produces one message event per SMB2 PDU in legacy Plan order
// (smb.go:69-335 逐命令同序：NEGOTIATE → SESSION_SETUP → TREE_CONNECT →
// CREATE → Operations → CLOSE → TREE_DISCONNECT → LOGOFF，Include* 门控与
// ErrorOnCommand 错误注入语义同款)。TCP 层生成器负责握手/seq-ack/挥手/
// MSS 分段。
func (g *SMBGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("smb generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	if req.Meta.SMB == nil {
		return fmt.Errorf("smb generator: no config (spec.smb required)")
	}
	// 默认化（legacy Plan smb.go:86 applyDefaults 同款；值拷贝——不污染
	// FlowMeta 的共享配置）。
	wcfg := applyDefaults(req.Meta.SMB)

	// 会话状态（smb.go:112-122 同款：messageID 0 起、fileID 用默认化后的值、
	// dialectRev 由 SelectedDialect 解析）。
	sess := &sessionState{
		messageID: 0,
		fileID:    wcfg.FileId,
	}
	dialectRev, _ := parseDialect(wcfg.SelectedDialect)
	sess.dialectRev = dialectRev

	stopAfter := wcfg.ErrorOnCommand

	// emitOne 发射单个 PDU 事件（up=request、down=response），字节构建与
	// legacy emitSMB2PDU（emit.go:105-140）逐字节一致：NBSS(4) + 可选
	// TRANSFORM_HEADER(52) + SMB2 头(64) + 体。messageID 在 response 发射
	// 后递增（BUG #5 语义：request/response 共用同一 MessageId）。
	emitPDU := func(up bool, cmd uint16, status uint32, flags uint32, body []byte) error {
		creditCharge := creditChargeFor(sess.dialectRev)
		hdr := buildSMB2Header(cmd, creditCharge, status, flags,
			sess.messageID, sess.treeID, sess.sessionID)
		pdu := make([]byte, 0, len(hdr)+len(body))
		pdu = append(pdu, hdr...)
		pdu = append(pdu, body...)
		if sess.encryptRequired {
			th := buildTransformHeader(uint32(len(pdu)), sess.sessionID)
			pdu = append(th, pdu...)
		}
		nbss := buildNBSSHeader(len(pdu))
		pdu = append(nbss, pdu...)
		if err := g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: pdu}); err != nil {
			return err
		}
		if !up {
			sess.messageID++
		}
		return nil
	}
	// pair 发射 request + response 对；errResp 非零时响应 Status 返回
	// ErrorResponseStatus（legacy 各 emit*PDU 的 errorResponse 语义）。
	// reqFlags/respFlags 分开传：响应恒带 FlagServerToRedir（smbFlags 同款
	// ——echo/flush 的 legacy emitLightweightPDU 也经 smbFlags(isResponse,
	// signingRequired) 计算，调用方只传各自方向的标志即可）。
	pair := func(cmd uint16, reqBody, respBody []byte, reqFlags, respFlags uint32, errResp bool) error {
		if err := emitPDU(true, cmd, 0, reqFlags, reqBody); err != nil {
			return err
		}
		respStatus := StatusSuccess
		if errResp {
			respStatus = wcfg.ErrorResponseStatus
		}
		if err := emitPDU(false, cmd, respStatus, respFlags, respBody); err != nil {
			return err
		}
		return nil
	}
	signFlags := smbFlags(false, wcfg.SigningRequired)
	respSignFlags := smbFlags(true, wcfg.SigningRequired)
	// --- NEGOTIATE（emitNegotiatePDU emit_session.go:14-70 同款）---
	negotiateErrored := false
	if boolPtr(wcfg.IncludeNegotiate, true) {
		errResp := stopAfter == "negotiate"
		negotiateErrored = errResp

		dialects := make([]uint16, 0, len(wcfg.Dialects))
		for _, d := range wcfg.Dialects {
			if dv, err := parseDialect(d); err == nil {
				dialects = append(dialects, dv)
			}
		}
		preauth := wcfg.PreauthIntegrityHashAlgorithms
		encAlgs := []uint16{wcfg.EncryptionAlgorithm}
		reqBody := buildNegotiateRequestBody(dialects, wcfg.SecurityMode,
			wcfg.ClientCapabilities, wcfg.ClientGuid, preauth, encAlgs)

		var respBody []byte
		if errResp {
			respBody = buildNegotiateErrorResponseBody()
		} else {
			respBody = buildNegotiateResponseBody(sess.dialectRev, wcfg.SecurityMode,
				wcfg.ServerGuid, wcfg.ServerCapabilities, wcfg.MaxTransactSize,
				wcfg.MaxReadSize, wcfg.MaxWriteSize, buildGSSAPIBlob(wcfg.AuthMechanism))
		}
		if err := pair(CmdNegotiate, reqBody, respBody, signFlags, respSignFlags, errResp); err != nil {
			return err
		}
	}

	// --- SESSION_SETUP（emitSessionSetupPDUs emit_session.go:73-164 同款：
	// 逐轮 request/response；ntlm 非末轮 response 为 StatusMoreProcessingRequired
	// + NTLMSSP Challenge；错误注入只在末轮响应生效）---
	authErrored := false
	if !negotiateErrored && boolPtr(wcfg.IncludeAuth, true) {
		errResp := stopAfter == "session_setup"
		authErrored = errResp
		for round := 0; round < wcfg.AuthRounds; round++ {
			isLastRound := round == wcfg.AuthRounds-1

			var secBlob []byte
			if len(wcfg.SecurityBlob) > 0 {
				secBlob = wcfg.SecurityBlob
			} else {
				switch wcfg.AuthMechanism {
				case "ntlm":
					switch round {
					case 0:
						secBlob = buildNTLMSSPNegotiateBlob()
					case 1:
						secBlob = buildNTLMSSPAuthBlob()
					default:
						secBlob = []byte{}
					}
				case "kerberos":
					secBlob = buildGSSAPIBlob("kerberos")
				case "anonymous", "guest":
					secBlob = buildGSSAPIBlob(wcfg.AuthMechanism)
				default:
					secBlob = buildGSSAPIBlob("ntlm")
				}
			}

			reqBody := buildSessionSetupRequestBody(0, uint8(wcfg.SecurityMode), 0x01,
				0, secBlob, wcfg.PreviousSessionId)
			if err := emitPDU(true, CmdSessionSetup, 0, signFlags, reqBody); err != nil {
				return err
			}
			// 首轮 request 后分配 SessionId（emit_session.go:123-125 同款）。
			if round == 0 {
				sess.sessionID = nextSessionID()
			}

			respStatus := StatusSuccess
			if errResp && isLastRound {
				respStatus = wcfg.ErrorResponseStatus
			} else if !isLastRound && wcfg.AuthMechanism == "ntlm" {
				respStatus = StatusMoreProcessingRequired
			}
			var respBody []byte
			if errResp && isLastRound {
				respBody = buildSessionSetupErrorResponseBody()
			} else {
				var respBlob []byte
				var sessionFlags uint16
				if wcfg.EncryptionRequired {
					sessionFlags = 0x04 // EncryptData bit
				}
				if wcfg.AuthMechanism == "ntlm" && !isLastRound {
					respBlob = buildNTLMSSPChallengeBlob()
				}
				respBody = buildSessionSetupResponseBody(sessionFlags, respBlob)
			}
			if err := emitPDU(false, CmdSessionSetup, respStatus, respSignFlags, respBody); err != nil {
				return err
			}
		}
		// H-3 修复（emit_session.go:157-163 同款）：认证完成后若
		// EncryptionRequired 且 dialect > SMB3.0，后续信令 PDU 全部以
		// TRANSFORM_HEADER 包裹（NEGOTIATE 与 SESSION_SETUP 自身不加密）。
		if wcfg.EncryptionRequired && sess.dialectRev > DialectSMB3_0 {
			sess.encryptRequired = true
		}
	}

	// --- TREE_CONNECT（emitTreeConnectPDU emit_session.go:167-212 同款；
	// treeID 在 request 与 response 之间赋值——response 头携带新 treeID，
	// request 头携带旧值——故不能走 pair()，须拆两步）---
	treeErrored := false
	if !negotiateErrored && !authErrored && boolPtr(wcfg.IncludeTreeConnect, true) {
		errResp := stopAfter == "tree_connect"
		treeErrored = errResp

		reqBody := buildTreeConnectRequestBody(wcfg.TreeConnectShare)
		if err := emitPDU(true, CmdTreeConnect, 0, signFlags, reqBody); err != nil {
			return err
		}
		if !errResp {
			sess.treeIDCounter++
			sess.treeID = sess.treeIDCounter
		}
		var respBody []byte
		if errResp {
			respBody = buildTreeConnectErrorResponseBody()
		} else {
			respBody = buildTreeConnectResponseBody(wcfg.ShareType, 0, 0, 0x001F1FFF)
		}
		respStatus := StatusSuccess
		if errResp {
			respStatus = wcfg.ErrorResponseStatus
		}
		if err := emitPDU(false, CmdTreeConnect, respStatus, respSignFlags, respBody); err != nil {
			return err
		}
	}

	// --- CREATE + Operations（smb.go:183-284 同款门控：create 错误 → 仅
	// CREATE 对，拆解走完整 teardown；ops 循环错误 → break 后仍补 CLOSE）---
	if !negotiateErrored && !authErrored && !treeErrored {
		createErrored := false
		if stopAfter == "create" {
			createErrored = true
			reqBody := buildCreateRequestBody(2, wcfg.AccessMask, wcfg.FileAttributes,
				uint32(wcfg.ShareAccess), uint32(wcfg.CreateDisposition), wcfg.CreateOptions,
				wcfg.FilePath)
			if err := pair(CmdCreate, reqBody, buildCreateErrorResponseBody(), signFlags, respSignFlags, true); err != nil {
				return err
			}
		} else {
			reqBody := buildCreateRequestBody(2, wcfg.AccessMask, wcfg.FileAttributes,
				uint32(wcfg.ShareAccess), uint32(wcfg.CreateDisposition), wcfg.CreateOptions,
				wcfg.FilePath)
			if err := pair(CmdCreate, reqBody, buildCreateResponseBody(0, 1, sess.fileID), signFlags, respSignFlags, false); err != nil {
				return err
			}

			// Operations 循环（smb.go:199-272 同款：read/write/close 支持
			// 错误注入，注入后 break；其余命令恒成功路径）。
			opsErrored := false
			closeOpEmitted := false
			for _, op := range wcfg.Operations {
				opErrored := false
				switch op.OpType {
				case "read":
					errResp := stopAfter == "read"
					opErrored = errResp
					fileID := sess.fileID
					if op.FileId != ([16]byte{}) {
						fileID = op.FileId
					}
					reqBody := buildReadRequestBody(op.Length, op.Offset, fileID, op.MinimumCount)
					var respBody []byte
					if errResp {
						respBody = buildReadErrorResponseBody()
					} else {
						respBody = buildReadResponseBody(op.Length, makeReadData(op.Length))
					}
					if err := pair(CmdRead, reqBody, respBody, signFlags, respSignFlags, errResp); err != nil {
						return err
					}
				case "write":
					errResp := stopAfter == "write"
					opErrored = errResp
					fileID := sess.fileID
					if op.FileId != ([16]byte{}) {
						fileID = op.FileId
					}
					data := op.Data
					if len(data) == 0 && op.DataB64 != "" {
						if decoded, err := base64.StdEncoding.DecodeString(op.DataB64); err == nil {
							data = decoded
						}
					}
					reqBody := buildWriteRequestBody(uint32(len(data)), op.Offset, fileID, data, op.Flags)
					var respBody []byte
					if errResp {
						respBody = buildWriteErrorResponseBody()
					} else {
						respBody = buildWriteResponseBody(uint32(len(data)))
					}
					if err := pair(CmdWrite, reqBody, respBody, signFlags, respSignFlags, errResp); err != nil {
						return err
					}
				case "close":
					closeOpEmitted = true
					errResp := stopAfter == "close"
					opErrored = errResp
					if err := pair(CmdClose, buildCloseRequestBody(sess.fileID), buildCloseResponseBody(), signFlags, respSignFlags, errResp); err != nil {
						return err
					}
				case "query_directory":
					fileName := op.FileName
					if fileName == "" {
						fileName = "*"
					}
					infoClass := op.InfoClass
					if infoClass == 0 {
						infoClass = 37
					}
					reqBody := buildQueryDirectoryRequestBody(sess.fileID, infoClass, fileName, 4096)
					if err := pair(CmdQueryDirectory, reqBody, buildQueryDirectoryResponseBody([]byte{}), signFlags, respSignFlags, false); err != nil {
						return err
					}
				case "query_info":
					infoType := op.InfoType
					fileInfoClass := op.FileInfoClass
					if fileInfoClass == 0 {
						fileInfoClass = 4
					}
					reqBody := buildQueryInfoRequestBody(infoType, fileInfoClass, 40, 0, sess.fileID, nil)
					if err := pair(CmdQueryInfo, reqBody, buildQueryInfoResponseBody([]byte{}), signFlags, respSignFlags, false); err != nil {
						return err
					}
				case "lock":
					flags := op.Flags
					if flags == 0 {
						flags = 0x02
					}
					length := op.Length
					if length == 0 {
						length = 4096
					}
					lockEl := buildLockElement(op.Offset, uint64(length), flags)
					reqBody := buildLockRequestBody(sess.fileID, lockEl)
					if err := pair(CmdLock, reqBody, buildLightweightBody(), signFlags, respSignFlags, false); err != nil {
						return err
					}
				case "ioctl":
					reqBody := buildIOCTLRequestBody(0x00060194, sess.fileID, make([]byte, 8))
					if err := pair(CmdIOCTL, reqBody, buildLightweightBody(), signFlags, respSignFlags, false); err != nil {
						return err
					}
				case "echo":
					body := buildLightweightBody()
					// emitLightweightPDU（emit_misc.go:186-214 同款）：
					// 请求/响应使用各自的签名标志（echo/flush 走
					// signingRequired 参数而非 cfg.SigningRequired 全量）。
					upFlags := smbFlags(false, wcfg.SigningRequired)
					downFlags := smbFlags(true, wcfg.SigningRequired)
					if err := emitPDU(true, CmdEcho, 0, upFlags, body); err != nil {
						return err
					}
					if err := emitPDU(false, CmdEcho, StatusSuccess, downFlags, body); err != nil {
						return err
					}
				case "flush":
					body := buildFlushRequestBody(sess.fileID)
					upFlags := smbFlags(false, wcfg.SigningRequired)
					downFlags := smbFlags(true, wcfg.SigningRequired)
					if err := emitPDU(true, CmdFlush, 0, upFlags, body); err != nil {
						return err
					}
					if err := emitPDU(false, CmdFlush, StatusSuccess, downFlags, buildLightweightBody()); err != nil {
						return err
					}
				}
				// §4.2（smb.go:267-271 同款）：错误注入后跳过后续操作。
				if opErrored {
					opsErrored = true
					break
				}
			}

			// §4 state machine（smb.go:277-282 同款）：Operations 后 CLOSE
			// 是强制拆解，除非 CLOSE 已发射（错误命令或显式 close 操作）。
			closeAlreadyEmitted := (opsErrored && stopAfter == "close") || closeOpEmitted
			if !closeAlreadyEmitted {
				if err := pair(CmdClose, buildCloseRequestBody(sess.fileID), buildCloseResponseBody(), signFlags, respSignFlags, false); err != nil {
					return err
				}
			}
		}
		_ = createErrored
	}

	// --- Teardown（smb.go:287-305 同款：tree_connect/session_setup 错误时
	// 跳过 TREE_DISCONNECT（无 TreeId）；tree_disconnect/logoff 错误 = 请求
	// 正常生成、响应返回错误，之后拆解继续）---
	if boolPtr(wcfg.IncludeTeardown, true) && !negotiateErrored {
		if !treeErrored && !authErrored {
			treeDiscErr := stopAfter == "tree_disconnect"
			if err := pair(CmdTreeDisconnect, buildLightweightBody(), buildLightweightBody(), signFlags, respSignFlags, treeDiscErr); err != nil {
				return err
			}
		}
		logoffErr := stopAfter == "logoff"
		if err := pair(CmdLogoff, buildLightweightBody(), buildLightweightBody(), signFlags, respSignFlags, logoffErr); err != nil {
			return err
		}
	}

	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks)。
func (g *SMBGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *SMBGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *SMBGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("smb generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// configFromMeta resolves the *SMBConfig from the flow metadata (GetConfig
// 同款三形态：*SMBConfig / map[string]interface{} / json.RawMessage；core 无法
// import 本包，经 spec.SMB 原样传递)。nil 时返回显式错误（SMB 链必须有 smb
// 配置，不产任何事件）。
func configFromMeta(v interface{}) (*SMBConfig, error) {
	switch c := v.(type) {
	case nil:
		return nil, fmt.Errorf("smb generator: no config (spec.smb required)")
	case *SMBConfig:
		return c, nil
	case map[string]interface{}:
		cfg, err := smbConfigFromJSONMap(c)
		if err != nil {
			return nil, fmt.Errorf("smb generator: invalid smb config: %w", err)
		}
		return cfg, nil
	case json.RawMessage:
		var cfg SMBConfig
		if err := json.Unmarshal(c, &cfg); err != nil {
			return nil, fmt.Errorf("smb generator: invalid smb config: %w", err)
		}
		return &cfg, nil
	default:
		return nil, fmt.Errorf("smb generator: unsupported smb config type %T", v)
	}
}

// smbConfigFromJSONMap round-trips a JSON-decoded map through encoding/json
// into an *SMBConfig (nfs nfsConfigFromJSONMap 同款)。SMBConfig 全字段带
// json tag，strategy converter 产出的键精确匹配；GUID 类键（client_guid/
// server_guid/file_id）以 32 字符 hex 字符串出现（parseSMBConfig 的
// parseGUIDString 语义），encoding/json 的 [16]byte 解码只收数字数组不收
// 字符串 → 先手工解码为字节数组再回填。
func smbConfigFromJSONMap(m map[string]interface{}) (*SMBConfig, error) {
	// 拷贝入参：map 可能被调用方复用，不在原 map 上改写。
	m2 := make(map[string]interface{}, len(m)+3)
	for k, v := range m {
		m2[k] = v
	}
	for _, key := range [...]string{"client_guid", "server_guid", "file_id"} {
		s, ok := m2[key].(string)
		if !ok {
			continue
		}
		g, ok := parseHexGUID(s)
		if !ok {
			continue // 非法 hex：交给 json 解码报错（[16]byte 不收字符串）
		}
		arr := make([]interface{}, 16)
		for i, b := range g {
			arr[i] = b
		}
		m2[key] = arr
	}
	raw, err := json.Marshal(m2)
	if err != nil {
		return nil, err
	}
	var cfg SMBConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// parseHexGUID decodes a 32-hex-char GUID string (optionally with "-"
// separators) into 16 bytes; ok=false on invalid input（strategy_convert
// parseGUIDString 同款语义）。
func parseHexGUID(s string) ([16]byte, bool) {
	var g [16]byte
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return g, false
	}
	for i := 0; i < 16; i++ {
		hi, hOK := hexValue(s[2*i])
		lo, lOK := hexValue(s[2*i+1])
		if !hOK || !lOK {
			return g, false
		}
		g[i] = byte(hi<<4 | lo)
	}
	return g, true
}

func hexValue(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	default:
		return 0, false
	}
}

func init() {
	layers.RegisterLayerGenerator("smb", func() (layers.LayerGenerator, error) {
		return &SMBGenerator{}, nil
	})
	layers.RegisterLayerValidator("smb", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 握手/挥手校准进 spec.TCP（modbus/mqtt layer_gen.go 同款陷阱）：
		// legacy smb.go 恒产 TCP 握手/挥手（smb.go:127-134/310-317 无开关，
		// 从不读 spec.TCP.Handshake/Termination）——spec.TCP 零值 false
		// 必须写默认 true，否则 tcp 层生成器跳过握手/挥手（链测试 spec.TCP
		// 只设 InitialSeq 即复现：applySpecToChain 把零值 false 直落层 config）。
		// 与 legacy 语义一致：smb 链上的握手/挥手不可关（legacy 亦无此表达）。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
