// tools_testdrive.go: MCP 协议测试驱动工具。把「取例→生成→轮询终态→
// 校验→报告」整条回路收进 server 进程，任何 MCP 客户端（go test、Claude
// Code、外部工具）调用 flowb_run_protocol_case / flowb_run_protocol_suite
// 都跑同一套断言（CLAUDE.md "所有测试经 MCP 执行"）。
//
// 与 test/protocol_pcap 的驱动测试关系：go test 从 cases/*.json 加载用例
// 后把数据逐一喂给 flowb_run_protocol_suite；校验全部由本工具在 server
// 侧完成（VerifyPcap/tshark），测试只断言返回的 pass/fail 统计。
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/api/rest"
	"github.com/trafficgen/trafficgen/internal/pcaptest"
)

// runCaseInput 是 flowb_run_protocol_case 的入参。spec_json 与 expect 与
// test/protocol_pcap 的 Case schema 一致（pcaptest.Case），output_type /
// output_config 控制走 pcap 文件还是 port_group 真实发包。
type runCaseInput struct {
	Proto          string             `json:"proto" jsonschema:"protocol name (registry name, e.g. tcp/tftp/modbus); optional when the case resolves from the server's cases corpus"`
	CaseID         string             `json:"case_id" jsonschema:"case identifier (used in task naming + pcap path); with spec_json omitted the case loads from the server's protocol cases corpus (case_id alone runs a regression case)"`
	SpecJSON       json.RawMessage    `json:"spec_json" jsonschema:"generate_traffic config (strategy config, protocol-specific layers/spec); OPTIONAL — omit to load the named case from the corpus"`
	CaseDir        string             `json:"case_dir,omitempty" jsonschema:"override the corpus directory for this lookup (default: mcp.protocol_cases_dir config, then ./cases)"`
	OutputType     string             `json:"output_type" jsonschema:"output type: pcap or port_group (default pcap)"`
	OutputConfig   *outputConfigInput `json:"output_config,omitempty" jsonschema:"output configuration (pcap_path for pcap; port_group_id for port_group)"`
	StrategyFC     *flowControlInput  `json:"strategy_flow_control,omitempty" jsonschema:"optional strategy-level flow control (multi-flow cases)"`
	TaskFC         *flowControlInput  `json:"task_flow_control,omitempty" jsonschema:"optional task-level flow control"`
	DecodeAs       []string           `json:"decode_as,omitempty" jsonschema:"extra tshark -d decode directives"`
	Expect         caseExpectInput    `json:"expect" jsonschema:"verification expectations (tshark assertions + behavior)"`
	TimeoutSeconds int                `json:"timeout_s,omitempty" jsonschema:"max wait for terminal state (default 60, max 300)"`
	// NICCapture 仅 output_type=port_group 时生效；enabled 时工具在发包前
	// 于 iface 起 tcpdump 抓包、结束后用 VerifyPcap 核对抓到的线上帧。
	NICCapture *nicCaptureInput `json:"nic_capture,omitempty" jsonschema:"NIC capture orchestration (port_group only)"`
}

// caseExpectInput 是 pcaptest.Expect 的入参镜像（expect 走 MCP 入参而非
// 从 case 文件读取，调用方直接把用例期望传进来）。
type caseExpectInput struct {
	PacketCount   int                    `json:"packet_count,omitempty"`
	MinPackets    int                    `json:"min_packets,omitempty"`
	Fields        []pcaptest.FieldAssert `json:"fields,omitempty"`
	Frames        []pcaptest.FrameAssert `json:"frames,omitempty"`
	HasHandshake  bool                   `json:"has_handshake,omitempty"`
	HasPayload    bool                   `json:"has_payload,omitempty"`
	Negotiated    bool                   `json:"negotiated,omitempty"`
	Terminates    bool                   `json:"terminates,omitempty"`
	Directional   bool                   `json:"directional,omitempty"`
	Notes         []string               `json:"notes,omitempty"`
	ExpectError   bool                   `json:"expect_error,omitempty"`
	ErrorContains string                 `json:"error_contains,omitempty"`
}

// nicCaptureInput 控制 NIC 真实发包时的抓包编排。
type nicCaptureInput struct {
	Enabled bool   `json:"enabled" jsonschema:"enable tcpdump capture during port_group output"`
	Iface   string `json:"iface,omitempty" jsonschema:"capture interface (default enp135s0f0np0)"`
}

// runCaseOutput 是 flowb_run_protocol_case 的返回：单用例 verdict（pass/
// fail/error）、观察到的包数与抓包路径、失败原因。
type runCaseOutput struct {
	CaseID      string   `json:"case_id"`
	Proto       string   `json:"proto"`
	Summary     string   `json:"summary,omitempty"`
	Status      string   `json:"status"` // "pass" | "fail" | "error"
	Reason      string   `json:"reason,omitempty"`
	PacketCount int      `json:"packet_count,omitempty"`
	PcapPath    string   `json:"pcap_path,omitempty"`
	TaskID      string   `json:"task_id,omitempty"`
	Failures    []string `json:"failures,omitempty"`
	DurationMs  int64    `json:"duration_ms"`
}

func (s *Server) registerTestDriveTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_run_protocol_case",
			Description: "Drive one protocol test case: generate traffic (strategy+task+start), poll to terminal, then verify the output (pcap file or NIC capture) with tshark assertions. Returns a pass/fail/error verdict with failure details. For expect_error cases the tool asserts the generation/task is REJECTED (error message must contain error_contains).",
		},
		s.handleRunProtocolCase,
	)
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_run_protocol_suite",
			Description: "Load all (or one protocol's) cases from a cases JSON directory and drive each through flowb_run_protocol_case, aggregating the verdicts. Returns total/pass/fail/error counts plus per-case results. Responses above 64 KB are auto-exported: the reply becomes a small receipt {written_to, bytes, export_id, download_url} — fetch with curl and read the file locally. NIC capture (real wire) is enabled per-case via nic_capture when output_type=port_group.",
		},
		s.handleRunProtocolSuite,
	)
}

// toPcaptestCase converts the MCP input into a pcaptest.Case for VerifyPcap.
func (in *runCaseInput) toPcaptestCase() pcaptest.Case {
	return pcaptest.Case{
		ID:         in.CaseID,
		Proto:      in.Proto,
		SpecJSON:   in.SpecJSON,
		DecodeAs:   in.DecodeAs,
		StrategyFC: pcFc(in.StrategyFC),
		TaskFC:     pcFc(in.TaskFC),
		Expect: pcaptest.Expect{
			PacketCount:   in.Expect.PacketCount,
			MinPackets:    in.Expect.MinPackets,
			Fields:        in.Expect.Fields,
			Frames:        in.Expect.Frames,
			HasHandshake:  in.Expect.HasHandshake,
			HasPayload:    in.Expect.HasPayload,
			Negotiated:    in.Expect.Negotiated,
			Terminates:    in.Expect.Terminates,
			Directional:   in.Expect.Directional,
			Notes:         in.Expect.Notes,
			ExpectError:   in.Expect.ExpectError,
			ErrorContains: in.Expect.ErrorContains,
		},
	}
}

// runOneCase drives a single case (the core shared by the case tool and the
// suite tool): generate -> poll -> (optional NIC capture) -> verify -> verdict.
// c is the pcaptest.Case; outType/path override the per-case defaults.
func (s *Server) runOneCase(ctx context.Context, req *mcp.CallToolRequest, toolName string, c pcaptest.Case, outType string, path string, portGroupID string, timeout time.Duration, nic *nicCaptureInput, taskFC *flowControlInput) runCaseOutput {
	start := time.Now()

	if outType == "" {
		outType = "pcap"
	}
	if outType != "pcap" && outType != "port_group" {
		return runCaseOutput{
			CaseID:     c.ID,
			Proto:      c.Proto,
			Summary:    c.Summary,
			Status:     "error",
			Reason:     fmt.Sprintf("unsupported output_type %q (want pcap or port_group)", outType),
			DurationMs: time.Since(start).Milliseconds(),
		}
	}
	if outType == "port_group" {
		return s.runOneCasePortGroup(ctx, req, toolName, c, portGroupID, timeout, nic, start, taskFC)
	}
	return s.runOneCasePcap(ctx, req, toolName, c, path, timeout, start, taskFC)
}

// outConfig returns an outputConfigInput for pcap output (creates the parent
// dir so the pcap writer can open the file).
func outConfig(path string) *outputConfigInput {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	return &outputConfigInput{PcapPath: path}
}

// negErrMatch reports whether an error message matches the expect_error
// expectations. Empty ErrorContains matches any error.
func negErrMatch(expect pcaptest.Expect, msg string) bool {
	ec := expect.ErrorContains
	return ec == "" || strings.Contains(msg, ec)
}

// flushPcapWriter closes (and flushes) the pcap writer for a task, if any.
// UnregisterOutputWriter removes the map entry first, then closes the writer
// outside the lock; a repeat call no-ops on the missing entry. Safe to call
// after REST's onEngineTaskComplete already closed it.
//
// Why the tool needs this at all: onEngineTaskComplete writes the DB status
// "completed" BEFORE it loops UnregisterOutputWriter, so a caller that reacts
// to DB "completed" can read the pcap while its 256KB bufio buffer is still
// unflushed (writes + fsync only happen in Close). The extra unregister here
// makes the file consistent before verification, in both production (REST owns
// the callback) and test envs (tool-driven).
func (s *Server) flushPcapWriter(engineTaskID string) {
	s.engine.UnregisterOutputWriter(engineTaskID)
	s.engine.UnregisterDualWriter(engineTaskID)
}

func (s *Server) stopRun(_ context.Context, run genRun) {
	if run.TaskID == "" {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	taskH := rest.NewTaskHandlerWithCallbacks(s.db, s.engine, nil, false)
	_, _ = s.callHandler(cleanupCtx, nil, run.TaskID, nil, taskH.Stop)
	engineTaskID := run.TaskID + "-" + run.StrategyID
	_ = s.engine.StopTask(engineTaskID)
	s.flushPcapWriter(engineTaskID)
}

func (s *Server) cleanupCreatedRun(ctx context.Context, run genRun) {
	if run.TaskID != "" {
		s.stopRun(ctx, run)
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		taskH := rest.NewTaskHandlerWithCallbacks(s.db, s.engine, nil, false)
		_, _ = s.callHandler(cleanupCtx, nil, run.TaskID, nil, taskH.Delete)
	}
	if run.StrategyID != "" {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		strategyH := rest.NewStrategyHandler(s.db)
		_, _ = s.callHandler(cleanupCtx, nil, run.StrategyID, nil, strategyH.Delete)
	}
}

func (s *Server) runOneCasePcap(ctx context.Context, req *mcp.CallToolRequest, toolName string, c pcaptest.Case, path string, timeout time.Duration, start time.Time, taskFC *flowControlInput) runCaseOutput {
	res := runCaseOutput{CaseID: c.ID, Proto: c.Proto, Summary: c.Summary, Status: "error"}
	taskName := fmt.Sprintf("%s-%s", c.Proto, c.ID)

	// 负向用例：生成或任务被拒即 pass（断言 error_contains 子串）。expect 只
	// 校验拒绝路径，不产生 pcap；VerifyPcap 对 ExpectError 直接返回空问题。
	run := s.createAndRunStrategy(ctx, req, toolName, taskName, c.Proto, mapString(c.SpecJSON), stratFC(c.StrategyFC), taskFC, "pcap", outConfig(path))
	if run.Err != nil {
		if !c.Expect.ExpectError {
			s.cleanupCreatedRun(ctx, run)
		}
		if c.Expect.ExpectError && negErrMatch(c.Expect, run.Err.Error()) {
			res.Status = "pass"
			res.Reason = "validate-negative: rejected as expected"
		} else if c.Expect.ExpectError {
			res.Status = "fail"
			res.Reason = fmt.Sprintf("rejected but error %q does not contain %q", run.Err.Error(), c.Expect.ErrorContains)
		} else {
			res.Status = "error"
			res.Reason = "generate: " + run.Err.Error()
		}
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	res.TaskID = run.TaskID

	status, errMsg, err := s.waitForTaskTerminal(ctx, run.TaskID, time.Now().Add(timeout))
	if err != nil {
		// Engine task IDs are {taskID}-{strategyID}; stopping the parent UUID
		// alone hits "task not found", leaving the underlying engine task
		// running (and its writer/flows un-cleaned). Stop the composite ID.
		s.cleanupCreatedRun(ctx, run)
		res.Status = "error"
		res.Reason = "poll: " + err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	switch status {
	case "completed":
		if c.Expect.ExpectError {
			s.cleanupCreatedRun(ctx, run)
			res.Status = "fail"
			res.Reason = "expected task to be rejected but it completed"
			res.DurationMs = time.Since(start).Milliseconds()
			return res
		}
	case "error", "failed":
		if c.Expect.ExpectError {
			s.cleanupCreatedRun(ctx, run)
			if negErrMatch(c.Expect, errMsg) {
				res.Status = "pass"
				res.Reason = "validate-negative: rejected as expected"
			} else {
				res.Status = "fail"
				res.Reason = fmt.Sprintf("rejected but error %q does not contain %q", errMsg, c.Expect.ErrorContains)
			}
			res.DurationMs = time.Since(start).Milliseconds()
			return res
		}
		s.cleanupCreatedRun(ctx, run)
		res.Status = "error"
		res.Reason = fmt.Sprintf("task ended %s: %s", status, errMsg)
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	case "stopped":
		s.cleanupCreatedRun(ctx, run)
		res.Status = "error"
		res.Reason = "task stopped/cancelled before verification"
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	// 关掉 pcap writer 落盘（bufio 256KB 缓冲 + fsync 只在 Close 做）。生产
	// 里 REST onEngineTaskComplete 也会关，但它在 DB 置 completed 之后才关 —
	// 若仅等 DB 状态就读文件会读到未 flush 的空目录项。这里幂等再关一次。
	s.flushPcapWriter(run.TaskID + "-" + run.StrategyID)

	res.PcapPath = path
	if _, err := os.Stat(path); err != nil {
		res.Status = "error"
		res.Reason = fmt.Sprintf("task completed but pcap not found at %s: %v", path, err)
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	if n, err := pcaptest.PacketCount(path); err == nil {
		res.PacketCount = n
	}
	if probs := pcaptest.VerifyPcap(path, c); len(probs) > 0 {
		res.Status = "fail"
		res.Reason = "verify"
		res.Failures = probs
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	res.Status = "pass"
	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

func (s *Server) runOneCasePortGroup(ctx context.Context, req *mcp.CallToolRequest, toolName string, c pcaptest.Case, portGroupID string, timeout time.Duration, nic *nicCaptureInput, start time.Time, taskFC *flowControlInput) runCaseOutput {
	res := runCaseOutput{CaseID: c.ID, Proto: c.Proto, Summary: c.Summary, Status: "error"}
	taskName := fmt.Sprintf("%s-%s", c.Proto, c.ID)
	if portGroupID == "" {
		res.Reason = "port_group output requires port_group_id"
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	oc := &outputConfigInput{PortGroupID: portGroupID}

	var run genRun
	var taskH *rest.TaskHandler
	if c.Expect.ExpectError {
		run = s.createAndRunStrategy(ctx, req, toolName, taskName, c.Proto, mapString(c.SpecJSON), stratFC(c.StrategyFC), taskFC, "port_group", oc)
	} else {
		run, taskH = s.createStrategyAndTask(ctx, req, toolName, taskName, c.Proto, mapString(c.SpecJSON), stratFC(c.StrategyFC), taskFC, "port_group", oc)
	}
	if run.Err != nil {
		if !c.Expect.ExpectError {
			s.cleanupCreatedRun(ctx, run)
		}
		if c.Expect.ExpectError && negErrMatch(c.Expect, run.Err.Error()) {
			res.Status = "pass"
			res.Reason = "validate-negative: rejected as expected"
		} else if c.Expect.ExpectError {
			res.Status = "fail"
			res.Reason = fmt.Sprintf("rejected but error %q does not contain %q", run.Err.Error(), c.Expect.ErrorContains)
		} else {
			res.Status = "error"
			res.Reason = "generate: " + run.Err.Error()
		}
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	res.TaskID = run.TaskID

	iface := ""
	if nic != nil {
		iface = nic.Iface
	}
	if iface == "" {
		iface = "enp135s0f0np0"
	}

	// NIC 抓包编排：先起 tcpdump（等待 listening+就绪），任务完成（=全部帧
	// 已物理发出）后停抓，再对抓到的线上帧跑 VerifyPcap。负向用例在此已
	// return，不会走到抓包。
	capturePath := filepath.Join(pcaptest.CaptureDefaultDir, c.Proto, pcaptest.CasePcapName(c.ID, c.Expect.ExpectError))
	captureEnabled := nic != nil && nic.Enabled
	var capCmd *exec.Cmd
	if captureEnabled {
		if err := os.MkdirAll(filepath.Dir(capturePath), 0755); err != nil {
			s.cleanupCreatedRun(ctx, run)
			res.Reason = "mkdir capture dir: " + err.Error()
			res.DurationMs = time.Since(start).Milliseconds()
			return res
		}
		cmd, err := pcaptest.StartCapture(iface, capturePath, c)
		if err != nil {
			s.cleanupCreatedRun(ctx, run)
			res.Reason = err.Error()
			res.DurationMs = time.Since(start).Milliseconds()
			return res
		}
		capCmd = cmd
	}
	if !c.Expect.ExpectError {
		if err := s.startStrategyTask(ctx, req, toolName, taskH, run.TaskID); err != nil {
			if captureEnabled {
				// StopCapture already handles a live cmd; the tcpdump would
				// otherwise be left running on this start-failure path.
				pcaptest.StopCapture(capCmd)
			}
			s.cleanupCreatedRun(ctx, run)
			res.Reason = "start: " + err.Error()
			res.DurationMs = time.Since(start).Milliseconds()
			return res
		}
	}

	status, errMsg, err := s.waitForTaskTerminal(ctx, run.TaskID, time.Now().Add(timeout))
	if captureEnabled {
		// 成功任务给 tcpdump 一个读盘窗口；取消或超时则立即进入可取消清理。
		captureCtx := ctx
		if err != nil {
			var cancel context.CancelFunc
			captureCtx, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()
		}
		if err == nil {
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
		pcaptest.StopCaptureContext(captureCtx, capCmd)
		if err == nil {
			select {
			case <-ctx.Done():
			case <-time.After(300 * time.Millisecond):
			}
		}
	}
	if err != nil {
		s.cleanupCreatedRun(ctx, run)
		res.Status = "error"
		res.Reason = "poll: " + err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	switch status {
	case "completed":
		if c.Expect.ExpectError {
			s.cleanupCreatedRun(ctx, run)
			res.Status = "fail"
			res.Reason = "expected task to be rejected but it completed"
			res.DurationMs = time.Since(start).Milliseconds()
			return res
		}
	case "error", "failed":
		if c.Expect.ExpectError {
			s.cleanupCreatedRun(ctx, run)
			if negErrMatch(c.Expect, errMsg) {
				res.Status = "pass"
				res.Reason = "validate-negative: rejected as expected"
			} else {
				res.Status = "fail"
				res.Reason = fmt.Sprintf("rejected but error %q does not contain %q", errMsg, c.Expect.ErrorContains)
			}
			res.DurationMs = time.Since(start).Milliseconds()
			return res
		}
		s.cleanupCreatedRun(ctx, run)
		res.Status = "error"
		res.Reason = fmt.Sprintf("task ended %s: %s", status, errMsg)
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	case "stopped":
		s.cleanupCreatedRun(ctx, run)
		res.Status = "error"
		res.Reason = "task stopped/cancelled before verification"
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	if !captureEnabled {
		// 未抓包：无可核对帧。调用方仅需生成验证（冒烟），pass 语义=任务
		// 成功完成。
		res.Status = "pass"
		res.Reason = "generated on " + iface + " (no capture)"
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}

	// 空 pcap 守卫：0 帧 = 帧未发出或被过滤全漏。VerifyPcap 对空 pcap 无
	// 断言空转，会掩盖「completed 但 0 包」的假阳性。
	res.PcapPath = capturePath
	n := pcapCountFile(capturePath)
	if n <= 0 {
		res.Status = "fail"
		res.Reason = fmt.Sprintf("no frames captured on %s (count=%d)", iface, n)
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	res.PacketCount = n
	if probs := pcaptest.VerifyPcap(capturePath, c); len(probs) > 0 {
		res.Status = "fail"
		res.Reason = "verify"
		res.Failures = probs
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	res.Status = "pass"
	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

// pcapCountFile returns the pcap frame count, or -1 if it can't be read.
func pcapCountFile(path string) int {
	if n, err := pcaptest.PacketCount(path); err == nil {
		return n
	}
	return -1
}

func (s *Server) handleRunProtocolCase(ctx context.Context, req *mcp.CallToolRequest, in runCaseInput) (*mcp.CallToolResult, runCaseOutput, error) {
	start := time.Now()
	// 前置校验在工具入口集中做，便于 suite 汇总时区分「入参错（error）」
	// 与用例失败（fail）。
	switch {
	case in.CaseID == "":
		s.auditLog(req, "flowb_run_protocol_case", 0, "error", "missing case_id")
		return nil, runCaseOutput{}, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "case_id is required"}
	case !safeCaseComponent(in.CaseID) || (in.Proto != "" && !safeCaseComponent(in.Proto)):
		s.auditLog(req, "flowb_run_protocol_case", 0, "error", "unsafe path component")
		return nil, runCaseOutput{}, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "proto and case_id must be simple path components"}
	}
	// P1-12（2026-10-05 客户端复测）：spec_json 省略 → 从服务端协议语料按
	// case_id 解析（此前语料对 MCP 不可达、spec_json 必填，回归入口完全
	// 不可用）。入参显式给出的字段优先，语料补齐 spec/expect/fc/decode_as。
	if len(in.SpecJSON) == 0 {
		cc, err := s.loadCorpusCase(in.CaseDir, in.Proto, in.CaseID)
		if err != nil {
			s.auditLog(req, "flowb_run_protocol_case", 0, "error", err.Error())
			return nil, runCaseOutput{}, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: err.Error()}
		}
		if in.Proto == "" {
			in.Proto = cc.Proto
		}
		in.SpecJSON = cc.SpecJSON
		if len(in.DecodeAs) == 0 {
			in.DecodeAs = cc.DecodeAs
		}
		if in.StrategyFC == nil {
			in.StrategyFC = fcFromPcaptest(cc.StrategyFC)
		}
		if in.TaskFC == nil {
			in.TaskFC = fcFromPcaptest(cc.TaskFC)
		}
		if in.Expect.empty() {
			in.Expect = expectToInput(cc.Expect)
		}
	}
	if in.Proto == "" {
		s.auditLog(req, "flowb_run_protocol_case", 0, "error", "missing proto")
		return nil, runCaseOutput{}, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "proto is required (or resolvable from the cases corpus via case_id)"}
	}
	if in.OutputType != "" && in.OutputType != "pcap" && in.OutputType != "port_group" {
		s.auditLog(req, "flowb_run_protocol_case", 0, "error", "unsupported output_type")
		return nil, runCaseOutput{}, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "output_type must be pcap or port_group"}
	}
	outType := in.OutputType
	if outType == "" {
		outType = "pcap"
	}
	timeout := defaultCaseTimeout(in.TimeoutSeconds)

	c := in.toPcaptestCase()
	var path string
	var pgid string
	if outType == "pcap" {
		if in.OutputConfig != nil {
			path = in.OutputConfig.PcapPath
		}
		if path == "" {
			path = suiteCasePcapPath("", in.Proto, in.CaseID, in.Expect.ExpectError)
		}
		path = resolvePcapOutputPath(path)
	} else {
		if in.OutputConfig != nil {
			pgid = in.OutputConfig.PortGroupID
		}
	}
	res := s.runOneCase(ctx, req, "flowb_run_protocol_case", c, outType, path, pgid, timeout, in.NICCapture, in.TaskFC)

	s.auditLog(req, "flowb_run_protocol_case", time.Since(start), res.Status, res.Reason)
	return nil, res, nil
}

// defaultCaseTimeout normalizes a case timeout (default 60s, max 300s).
func defaultCaseTimeout(secs int) time.Duration {
	if secs <= 0 {
		return 60 * time.Second
	}
	if secs > 300 {
		secs = 300
	}
	return time.Duration(secs) * time.Second
}

func safeCaseComponent(s string) bool {
	return s != "" && s != "." && s != ".." && filepath.Base(s) == s && !strings.ContainsAny(s, `/\\`)
}

// suiteCasePcapPath resolves the per-case output path for suite pcap runs.
// PcapPath on the suite's output_config is a ROOT directory; each case derives
// <root>/<proto>/<case_id>.pcap under it. This keeps distinct cases in distinct
// files (no cross-case overwrite) while honoring the caller-chosen root.
// expect_error 用例预期空包（至多 writer 建文件时的 24B 头），文件名带
// .neg 标记（pcaptest.CasePcapName），与正例落盘文件一眼可分。
func suiteCasePcapPath(root, proto, caseID string, expectError bool) string {
	if root == "" {
		root = "/tmp/mcp-pcaps"
	}
	return filepath.Join(root, proto, pcaptest.CasePcapName(caseID, expectError))
}

func resolvePcapOutputPath(path string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) || strings.HasPrefix(path, "pcap/") || strings.HasPrefix(path, "pcap\\") {
		return path
	}
	return filepath.Join("pcap", path)
}

// mapString converts a JSON RawMessage into the map[string]interface{} shape
// createAndRunStrategy expects for the strategy config. Invalid JSON returns
// nil (validation downstream reports the specific error).
func mapString(raw json.RawMessage) map[string]interface{} {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

// stratFC converts a pcaptest.StrategyFC into the MCP flowControlInput shape.
func stratFC(fc *pcaptest.StrategyFC) *flowControlInput {
	if fc == nil {
		return nil
	}
	return &flowControlInput{Type: fc.Type, Value: fc.Value}
}

// pcFc converts an MCP flowControlInput into the pcaptest.StrategyFC shape.
func fcInput(fc *pcaptest.StrategyFC) *flowControlInput {
	if fc == nil {
		return nil
	}
	return &flowControlInput{Type: fc.Type, Value: fc.Value}
}

func pcFc(fc *flowControlInput) *pcaptest.StrategyFC {
	if fc == nil {
		return nil
	}
	return &pcaptest.StrategyFC{Type: fc.Type, Value: fc.Value}
}

// ---------------------------------------------------------------------------
// flowb_run_protocol_suite
// ---------------------------------------------------------------------------

// suiteInput 是 flowb_run_protocol_suite 的入参：从 cases 目录加载用例后
// 并行驱动，聚合结果。case_dir 默认 cases/（test/protocol_pcap/cases）。
type suiteInput struct {
	CaseDir    string `json:"case_dir,omitempty" jsonschema:"directory of cases/*.json files (default cases/)"`
	Proto      string `json:"proto,omitempty" jsonschema:"filter to one protocol (empty = all)"`
	OutputType string `json:"output_type" jsonschema:"pcap or port_group"`
	// OutputConfig 应用于无 per-case 覆盖的用例（port_group 需要
	// port_group_id；pcap 时 path 默认派生）。
	OutputConfig   *outputConfigInput `json:"output_config,omitempty" jsonschema:"output configuration (port_group_id for port_group)"`
	Parallel       int                `json:"parallel,omitempty" jsonschema:"max concurrent cases (default 4, max 16)"`
	MaxCases       int                `json:"max_cases,omitempty" jsonschema:"cap on cases run (0 = no cap)"`
	TimeoutSeconds int                `json:"timeout_s,omitempty" jsonschema:"per-case timeout (default 60, max 300)"`
	NICCapture     *nicCaptureInput   `json:"nic_capture,omitempty" jsonschema:"NIC capture config (port_group only; enabled per-case)"`
}

// suiteResult 聚合所有用例的 verdict。
type suiteResult struct {
	Total   int             `json:"total"`
	Pass    int             `json:"pass"`
	Fail    int             `json:"fail"`
	Error   int             `json:"error"`
	PerCase []runCaseOutput `json:"per_case,omitempty"`
	// Export carries the {written_to, bytes, export_id, download_url}
	// receipt when the per-case detail exceeded the inline threshold
	// (auto-export, user ruling 2026-10-03); PerCase is then nil — the
	// full JSON (summary included) is in the file behind the link.
	Export map[string]interface{} `json:"export,omitempty"`
}

// exportSuiteDetail moves per-case detail into a server-managed export
// when the marshaled suite result would flood the model context. The
// summary counters stay inline either way.
func (s *Server) exportSuiteDetail(res *suiteResult) {
	raw, err := json.Marshal(res)
	if err != nil || len(raw) <= maxInlineResponseBytes {
		return
	}
	receipt, werr := writeExportFile("protocol_suite-"+uuid.NewString()[:8]+".json", raw)
	if werr != nil {
		return // degrade to inline rather than fail a finished suite run
	}
	var m map[string]interface{}
	if json.Unmarshal(receipt, &m) != nil {
		return
	}
	res.Export = m
	res.PerCase = nil
}

func (s *Server) handleRunProtocolSuite(ctx context.Context, req *mcp.CallToolRequest, in suiteInput) (*mcp.CallToolResult, suiteResult, error) {
	start := time.Now()
	if in.OutputType == "" {
		s.auditLog(req, "flowb_run_protocol_suite", 0, "error", "missing output_type")
		return nil, suiteResult{}, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "output_type is required"}
	}
	if in.OutputType != "pcap" && in.OutputType != "port_group" {
		s.auditLog(req, "flowb_run_protocol_suite", 0, "error", "unsupported output_type")
		return nil, suiteResult{}, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "output_type must be pcap or port_group"}
	}
	if in.OutputType == "port_group" {
		pgid := ""
		if in.OutputConfig != nil {
			pgid = in.OutputConfig.PortGroupID
		}
		if pgid == "" {
			s.auditLog(req, "flowb_run_protocol_suite", 0, "error", "port_group output requires output_config.port_group_id")
			return nil, suiteResult{}, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "port_group output requires output_config.port_group_id"}
		}
	}
	dir := s.casesDir(in.CaseDir)
	if dir == "" {
		dir = "cases"
	}
	if !filepath.IsAbs(dir) {
		// 相对路径对照 MCP 进程工作目录解析（与 test/protocol_pcap 的
		// loadCases 相同：优先绝对路径，否则 CLI 相对 cases）。
		if _, err := os.Stat(dir); err != nil {
			if abs, aerr := filepath.Abs(dir); aerr == nil {
				if _, err2 := os.Stat(abs); err2 == nil {
					dir = abs
				}
			}
		}
	}

	cases, err := loadSuiteCases(dir, in.Proto, in.MaxCases)
	if err != nil {
		s.auditLog(req, "flowb_run_protocol_suite", time.Since(start), "error", "load cases: "+err.Error())
		return nil, suiteResult{}, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "load cases: " + err.Error()}
	}
	if len(cases) == 0 {
		s.auditLog(req, "flowb_run_protocol_suite", time.Since(start), "error", "no cases loaded")
		return nil, suiteResult{Total: 0}, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "no cases loaded from " + dir}
	}

	parallel := in.Parallel
	if parallel <= 0 {
		parallel = 4
	}
	if parallel > 16 {
		parallel = 16
	}
	timeout := defaultCaseTimeout(in.TimeoutSeconds)

	var wg sync.WaitGroup
	sem := make(chan struct{}, parallel)
	results := make([]runCaseOutput, len(cases))
	ictx, cancel := context.WithCancel(ctx)
	defer cancel()

	for i, c := range cases {
		c := c
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ictx.Done():
				results[i] = runCaseOutput{CaseID: c.ID, Proto: c.Proto, Status: "error", Reason: "cancelled: " + ictx.Err().Error()}
				return
			}
			defer func() { <-sem }()

			outType := c.Output
			if outType == "" {
				outType = in.OutputType
			}
			var path string
			pgid := ""
			if in.OutputConfig != nil {
				pgid = in.OutputConfig.PortGroupID
			}
			if outType == "pcap" {
				path = suiteCasePcapPath("", c.Proto, c.ID, c.Expect.ExpectError)
				if in.OutputConfig != nil && in.OutputConfig.PcapPath != "" {
					path = suiteCasePcapPath(in.OutputConfig.PcapPath, c.Proto, c.ID, c.Expect.ExpectError)
				}
				path = resolvePcapOutputPath(path)
			}
			ec := pcaptest.Expect{
				PacketCount:   c.Expect.PacketCount,
				MinPackets:    c.Expect.MinPackets,
				Fields:        c.Expect.Fields,
				Frames:        c.Expect.Frames,
				HasHandshake:  c.Expect.HasHandshake,
				HasPayload:    c.Expect.HasPayload,
				Negotiated:    c.Expect.Negotiated,
				Terminates:    c.Expect.Terminates,
				Directional:   c.Expect.Directional,
				Notes:         c.Expect.Notes,
				ExpectError:   c.Expect.ExpectError,
				ErrorContains: c.Expect.ErrorContains,
			}
			// 负路径 + NIC 抓包互斥原则：expect_error 用例不发包，NIC 抓包
			// 器不会有帧可抓；suite 对这类用例禁用 NIC capture。
			nic := in.NICCapture
			if c.Expect.ExpectError {
				nic = nil
			}
			results[i] = s.runOneCase(ctx, req, "flowb_run_protocol_suite",
				pcaptest.Case{ID: c.ID, Proto: c.Proto, Summary: c.Summary, SpecJSON: c.SpecJSON, DecodeAs: c.DecodeAs, StrategyFC: c.StrategyFC, TaskFC: c.TaskFC, Expect: ec},
				outType, path, pgid, timeout, nic, fcInput(c.TaskFC))
		}()
	}
	wg.Wait()

	res := suiteResult{PerCase: results}
	for _, r := range results {
		res.Total++
		switch r.Status {
		case "pass":
			res.Pass++
		case "fail":
			res.Fail++
		default:
			res.Error++
		}
	}
	s.auditLog(req, "flowb_run_protocol_suite", time.Since(start), "success",
		fmt.Sprintf("total=%d pass=%d fail=%d error=%d", res.Total, res.Pass, res.Fail, res.Error))
	s.exportSuiteDetail(&res)
	return nil, res, nil
}

// loadSuiteCases 从 dir 读取 cases/*.json，可选按 proto 过滤、cap 截断。
// 文件按 case 解组失败即整体报错（CLAUDE.md：用例 JSON 必须直接可消费，
// 静默跳过会掩盖坏用例）。
func loadSuiteCases(dir, proto string, maxCases int) ([]pcaptest.Case, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		files = append(files, filepath.Join(dir, e.Name()))
	}
	sort.Strings(files)

	var out []pcaptest.Case
	seen := make(map[string]string)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		var cases []pcaptest.Case
		if err := json.Unmarshal(raw, &cases); err != nil {
			return nil, fmt.Errorf("parse %s: %w", f, err)
		}
		for _, c := range cases {
			if proto != "" && c.Proto != proto {
				continue
			}
			if !safeCaseComponent(c.ID) || !safeCaseComponent(c.Proto) {
				return nil, fmt.Errorf("case %s has unsafe proto or case_id", f)
			}
			key := c.Proto + "\x00" + c.ID
			if previous, ok := seen[key]; ok {
				return nil, fmt.Errorf("duplicate case key %s/%s in %s and %s", c.Proto, c.ID, previous, f)
			}
			seen[key] = f
			out = append(out, c)
		}
		if maxCases > 0 && len(out) >= maxCases {
			out = out[:maxCases]
			break
		}
	}
	return out, nil
}

// casesDir 解析协议语料目录（P1-12）：显式入参 > mcp.protocol_cases_dir
// 配置 > ./cases（cwd 相对，与 suite 历史缺省一致）。
func (s *Server) casesDir(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if s.config != nil && s.config.ProtocolCasesDir != "" {
		return s.config.ProtocolCasesDir
	}
	return "cases"
}

// loadCorpusCase 从语料目录按 case_id 解析单个用例（proto 可空=全库搜）。
// 复用 loadSuiteCases 的加载与校验（坏用例整体报错，不静默跳过）。
func (s *Server) loadCorpusCase(dirOverride, proto, caseID string) (pcaptest.Case, error) {
	dir := s.casesDir(dirOverride)
	cases, err := loadSuiteCases(dir, proto, 0)
	if err != nil {
		return pcaptest.Case{}, fmt.Errorf("resolve case %q: %w", caseID, err)
	}
	for _, c := range cases {
		if c.ID == caseID {
			return c, nil
		}
	}
	return pcaptest.Case{}, fmt.Errorf(
		"case %q not found in corpus dir %s (proto filter %q); list available cases with flowb_run_protocol_suite (dry listing) or pass spec_json explicitly",
		caseID, dir, proto)
}

// fcFromPcaptest 反向转换：语料用例的流控 → 工具入参流控。
func fcFromPcaptest(fc *pcaptest.StrategyFC) *flowControlInput {
	if fc == nil {
		return nil
	}
	return &flowControlInput{Type: fc.Type, Value: fc.Value}
}

// expectToInput 反向转换：语料用例的期望 → 工具入参期望（字段一一对应，
// 与 toPcaptestCase 的正向映射互为镜像——新增字段两边同步）。
func expectToInput(e pcaptest.Expect) caseExpectInput {
	return caseExpectInput{
		PacketCount:   e.PacketCount,
		MinPackets:    e.MinPackets,
		Fields:        e.Fields,
		Frames:        e.Frames,
		HasHandshake:  e.HasHandshake,
		HasPayload:    e.HasPayload,
		Negotiated:    e.Negotiated,
		Terminates:    e.Terminates,
		Directional:   e.Directional,
		Notes:         e.Notes,
		ExpectError:   e.ExpectError,
		ErrorContains: e.ErrorContains,
	}
}

// empty 报告入参期望是否完全未给（全零值）——未给时语料期望生效。
func (e caseExpectInput) empty() bool {
	return e.PacketCount == 0 && e.MinPackets == 0 && len(e.Fields) == 0 && len(e.Frames) == 0 &&
		!e.HasHandshake && !e.HasPayload && !e.Negotiated && !e.Terminates && !e.Directional &&
		len(e.Notes) == 0 && !e.ExpectError && e.ErrorContains == ""
}
