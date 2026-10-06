package mcp

// tools_testdrive_test.go: flowb_run_protocol_case / flowb_run_protocol_suite
// 的 spec 派生自测。用例 JSON（cases/*.json）通过 loadSuiteCases 消费后喂
// flowb_run_protocol_suite；与 test/protocol_pcap 驱动共用同一套校验
// （internal/pcaptest），go test 与 MCP 客户端跑同一断言集（CLAUDE.md
// "所有测试经 MCP 执行"）。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/api/rest"
	"github.com/trafficgen/trafficgen/internal/pcaptest"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// setupTestDriveEnv assembles a test MCP server with the REAL ARP planner and
// production-equivalent REST callbacks registered on the engine. This mirrors
// production: REST's TaskHandler owns the engine callbacks, so DB task status
// advances to completed/failed — exactly what waitForTaskTerminal's DB-poll
// relies on. Without these callbacks the DB would stay "running" forever and
// the tool's terminal wait would spin to deadline (the original race this env
// was designed to prevent).
//
// tcp+arp coverage: tcp goes through the mock planner (negative / no-pcap
// paths), arp through the real builder (pcap parseable by tshark).
func setupTestDriveEnv(t *testing.T) *testMCPEnv {
	env := setupMCPTestWithRealBuilder(t)
	// Register the production-equivalent REST callbacks (created with
	// registerCallbacks=true) so the DB task status advances to terminal.
	// This is safe: the engine has exactly one OnTaskComplete slot and this
	// runs once at setup time (single-threaded), not per-case.
	rest.NewTaskHandlerWithCallbacks(env.db, env.eng, nil, true)
	return env
}

// TestRunProtocolCase_InvalidParams 验证工具入参校验（前置校验在入口集中
// 做，suite 依赖它区分"入参错(error)"与"用例失败(fail)"）。
func TestRunProtocolCase_InvalidParams(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	spec := json.RawMessage(`{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]}`)
	cases := []struct {
		name string
		in   runCaseInput
	}{
		{"missing proto", runCaseInput{Proto: "", CaseID: "c1", SpecJSON: spec, OutputType: "pcap"}},
		{"missing case_id", runCaseInput{Proto: "arp", CaseID: "", SpecJSON: spec, OutputType: "pcap"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := env.srv.handleRunProtocolCase(context.Background(), nil, tc.in)
			if err == nil {
				t.Fatalf("want InvalidParams error, got nil")
			}
			if !strings.Contains(err.Error(), "required") && !strings.Contains(err.Error(), "spec_json") {
				t.Errorf("error %q does not mention missing field", err)
			}
		})
	}
	// P1-12：spec_json 必填契约已退役——空 spec_json 现在走语料解析；
	// 解析失败时给指路报错，不再是 "spec_json is required"。
	_, _, err := env.srv.handleRunProtocolCase(context.Background(), nil, runCaseInput{
		Proto: "arp", CaseID: "c2", SpecJSON: nil, OutputType: "pcap",
	})
	if err == nil {
		t.Fatalf("empty spec_json with unresolvable corpus must error")
	}
	if strings.Contains(err.Error(), "spec_json is required") {
		t.Errorf("retired contract error leaked: %v", err)
	}
}

// TestRunProtocolCase_ExpectError_Pass 验证负向用例：生成被拒（Validate
// 报错）即 pass。此路径不产生 pcap，可完全离线（mock planner 亦可）。
func TestRunProtocolCase_RejectsUnknownOutputType(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	_, _, err := env.srv.handleRunProtocolCase(context.Background(), nil, runCaseInput{
		Proto:      "arp",
		CaseID:     "bad-output-type",
		SpecJSON:   json.RawMessage(`{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]}`),
		OutputType: "bogus",
	})
	if err == nil {
		t.Fatal("want InvalidParams for unknown output_type, got nil")
	}
	if !strings.Contains(err.Error(), "output_type") {
		t.Errorf("error %q should mention output_type", err)
	}
}

func TestRunProtocolCase_ExpectError_Pass(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	// arp 层 sender_ip 格式非法触发 validator 拒绝（D-ARP-1 裁定4 锚）。
	_, out, err := env.srv.handleRunProtocolCase(context.Background(), nil, runCaseInput{
		Proto:  "arp",
		CaseID: "neg_arp_no_config",
		SpecJSON: json.RawMessage(
			`{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01"}},{"arp":{"sender_ip":"not-an-ip"}}]}`), // validator 报 invalid sender_ip
		OutputType:   "pcap",
		OutputConfig: &outputConfigInput{PcapPath: filepath.Join(env.tmp, "neg.pcap")},
		Expect: caseExpectInput{
			ExpectError:   true,
			ErrorContains: "invalid sender_ip",
		},
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if out.Status != "pass" {
		t.Fatalf("status = %q, want pass (rejected as expected); reason=%q", out.Status, out.Reason)
	}
	if !strings.Contains(out.Reason, "rejected as expected") {
		t.Errorf("reason %q should note rejection", out.Reason)
	}
}

// TestRunProtocolCase_ExpectError_ErrorContainsMismatch 验证负向用例对错误
// 子串的断言：错误信息不含 error_contains → fail（而非 pass，也非 error）。
func TestRunProtocolCase_ExpectError_ErrorContainsMismatch(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	_, out, err := env.srv.handleRunProtocolCase(context.Background(), nil, runCaseInput{
		Proto:  "arp",
		CaseID: "neg_arp_wrong_substr",
		SpecJSON: json.RawMessage(
			`{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01"}},{"arp":{"sender_ip":"not-an-ip"}}]}`), // validator 拒绝，但错误信息不是 error_contains → fail（子串失配）
		OutputType: "pcap",
		Expect: caseExpectInput{
			ExpectError:   true,
			ErrorContains: "some-other-message",
		},
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if out.Status != "fail" {
		t.Fatalf("status = %q, want fail (error did not contain expected substring); reason=%q", out.Status, out.Reason)
	}
	if !strings.Contains(out.Reason, "does not contain") {
		t.Errorf("reason %q should note the substring mismatch", out.Reason)
	}
}

// TestRunProtocolCase_ExpectError_NeverRejected 验证负向用例但任务实际成功
// （配置合法）→ fail：期望被拒绝但完成，不能误报 pass。
func TestRunProtocolCase_ExpectError_NeverRejected(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	// 合法 arp 配置：任务会完成，但用例期望被拒。
	_, out, err := env.srv.handleRunProtocolCase(context.Background(), nil, runCaseInput{
		Proto:        "arp",
		CaseID:       "neg_arp_but_valid_config",
		SpecJSON:     json.RawMessage(`{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]}`),
		OutputType:   "pcap",
		OutputConfig: &outputConfigInput{PcapPath: filepath.Join(env.tmp, "never-rej.pcap")},
		Expect:       caseExpectInput{ExpectError: true, ErrorContains: "x"},
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if out.Status != "fail" {
		t.Fatalf("status = %q, want fail (task completed but expected rejection); reason=%q", out.Status, out.Reason)
	}
}

// TestRunProtocolCase_PositivePcap_Arp 验证 pcap 输出 happy path：任务完成
// 生成 2 个 ARP 帧（request+reply），tshark 断言通过（single expectations）。
func TestRunProtocolCase_PositivePcap_Arp(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	pcapPath := filepath.Join(env.tmp, "arp-ok.pcap")
	_, out, err := env.srv.handleRunProtocolCase(context.Background(), nil, runCaseInput{
		Proto:        "arp",
		CaseID:       "arp_pos_ok",
		SpecJSON:     json.RawMessage(`{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]}`),
		OutputType:   "pcap",
		OutputConfig: &outputConfigInput{PcapPath: pcapPath},
		Expect: caseExpectInput{
			PacketCount: 2,
			Fields: []pcaptest.FieldAssert{
				{Field: "arp.opcode", Packet: 1, Value: "1"},
				{Field: "arp.opcode", Packet: 2, Value: "2"},
			},
		},
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if out.Status != "pass" {
		t.Fatalf("status = %q, want pass; reason=%q failures=%v", out.Status, out.Reason, out.Failures)
	}
	if _, err := os.Stat(pcapPath); err != nil {
		t.Fatalf("pcap %s not written: %v", pcapPath, err)
	}
	if out.PacketCount != 2 {
		t.Errorf("packet_count = %d, want 2", out.PacketCount)
	}
}

// TestRunProtocolCase_VerifyFailure 验证校验失败语义：tshark 断言期望与
// 实际不符 → fail（如期望 2 帧但实际 packet 3 处字段断言越界 / 数值不符）。
func TestRunProtocolCase_VerifyFailure(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	// 期望 PacketCount=3 但 ARP request+reply 只有 2 帧 → VerifyPcap 报
	// count 不匹配 → fail。
	_, out, err := env.srv.handleRunProtocolCase(context.Background(), nil, runCaseInput{
		Proto:        "arp",
		CaseID:       "arp_verify_fail",
		SpecJSON:     json.RawMessage(`{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]}`),
		OutputType:   "pcap",
		OutputConfig: &outputConfigInput{PcapPath: filepath.Join(env.tmp, "vfail.pcap")},
		Expect:       caseExpectInput{PacketCount: 3},
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if out.Status != "fail" {
		t.Fatalf("status = %q, want fail (verify mismatch); reason=%q", out.Status, out.Reason)
	}
	if len(out.Failures) == 0 {
		t.Errorf("expected failures list to name count mismatch")
	}
}

// TestRunProtocolCase_PortGroupMissingID 验证 port_group 输出但缺
// port_group_id → 用例级 fail（error，带 reason），不 panic。
func TestRunProtocolCase_PortGroupMissingID(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	_, out, err := env.srv.handleRunProtocolCase(context.Background(), nil, runCaseInput{
		Proto:        "arp",
		CaseID:       "arp_nic_nopgid",
		SpecJSON:     json.RawMessage(`{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]}`),
		OutputType:   "port_group", // 无 OutputConfig.PortGroupID
		OutputConfig: &outputConfigInput{},
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	// 这是用例自身错误（缺依赖），不是入参错——工具仍返回 result 而非 error。
	if out.Status != "error" {
		t.Fatalf("status = %q, want error (missing port_group_id); reason=%q", out.Status, out.Reason)
	}
	if !strings.Contains(out.Reason, "port_group_id") {
		t.Errorf("reason %q should require port_group_id", out.Reason)
	}
}

// TestRunProtocolSuite_RequiresOutputType 验证 suite 入参校验：缺 output_type
// 直接返回 InvalidParams error（区别于单个用例 fail）。
func TestRunProtocolSuite_RequiresOutputType(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	_, _, err := env.srv.handleRunProtocolSuite(context.Background(), nil, suiteInput{
		CaseDir: filepath.Join(env.tmp, "cases"),
	})
	if err == nil {
		t.Fatalf("want InvalidParams for missing output_type, got nil")
	}
	if !strings.Contains(err.Error(), "output_type") {
		t.Errorf("error %q should mention output_type", err)
	}
}

// TestRunProtocolSuite_PortGroupRequiresID 验证 port_group 输出必须有
// output_config.port_group_id。
func TestRunProtocolSuite_PortGroupRequiresID(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	dir := filepath.Join(env.tmp, "cases")
	os.MkdirAll(dir, 0755)
	writeSuiteCase(t, dir, "arp_basic.json", `[{"id":"s1","proto":"arp","spec_json":{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]},"expect":{"packet_count":2}}]`)

	_, _, err := env.srv.handleRunProtocolSuite(context.Background(), nil, suiteInput{
		CaseDir:      dir,
		Proto:        "arp",
		OutputType:   "port_group",
		OutputConfig: &outputConfigInput{},
	})
	if err == nil {
		t.Fatalf("want InvalidParams for port_group without port_group_id, got nil")
	}
	if !strings.Contains(err.Error(), "port_group_id") {
		t.Errorf("error %q should require port_group_id", err)
	}
}

// TestRunProtocolSuite_NoCases 验证加载 0 用例 → InvalidParams error。
func TestRunProtocolSuite_NoCases(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	dir := filepath.Join(env.tmp, "cases")
	os.MkdirAll(dir, 0755)
	_, _, err := env.srv.handleRunProtocolSuite(context.Background(), nil, suiteInput{
		CaseDir:    dir,
		OutputType: "pcap",
	})
	if err == nil {
		t.Fatalf("want InvalidParams for no cases, got nil")
	}
	if !strings.Contains(err.Error(), "no cases") {
		t.Errorf("error %q should mention no cases", err)
	}
}

// TestRunProtocolSuite_BadCaseJSON 验证坏了用例 JSON 整体报错，不静默跳过
// 坏用例（CLAUDE.md）。
func TestRunProtocolSuite_BadCaseJSON(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	dir := filepath.Join(env.tmp, "cases")
	os.MkdirAll(dir, 0755)
	writeSuiteCase(t, dir, "bad.json", `{"not":"an array"}`)
	writeSuiteCase(t, dir, "good.json", `[{"id":"s1","proto":"arp","spec_json":{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]},"expect":{"packet_count":2}}]`)

	_, _, err := env.srv.handleRunProtocolSuite(context.Background(), nil, suiteInput{
		CaseDir:    dir,
		OutputType: "pcap",
	})
	if err == nil {
		t.Fatalf("want error for bad case JSON, got nil")
	}
	if !strings.Contains(err.Error(), "bad.json") {
		t.Errorf("error %q should name the offending file", err)
	}
}

// TestRunProtocolSuite_AggregatesPassFail 验证 suite 汇总：混合 pass / fail /
// expect_error 用例的计数与 per_case 归属正确（断言可观察输出，不只结构）。
func TestRunProtocolSuite_AggregatesPassFail(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	dir := filepath.Join(env.tmp, "cases")
	os.MkdirAll(dir, 0755)
	// pass：合法 arp 2 帧
	writeSuiteCase(t, dir, "arp_ok.json",
		`[{"id":"a1","proto":"arp","spec_json":{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]},"expect":{"packet_count":2}}]`)
	// fail：期望 3 帧实为 2 帧
	writeSuiteCase(t, dir, "arp_bad.json",
		`[{"id":"a2","proto":"arp","spec_json":{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]},"expect":{"packet_count":3}}]`)
	// expect_error pass：缺 arp{} → 拒绝
	writeSuiteCase(t, dir, "arp_neg.json",
		`[{"id":"a3","proto":"arp","spec_json":{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01"}},{"arp":{"sender_ip":"not-an-ip"}}]},"expect":{"expect_error":true,"error_contains":"invalid sender_ip"}}]`)

	_, out, err := env.srv.handleRunProtocolSuite(context.Background(), nil, suiteInput{
		CaseDir:    dir,
		Proto:      "arp",
		OutputType: "pcap",
		Parallel:   2,
	})
	if err != nil {
		t.Fatalf("handle suite: %v", err)
	}
	if out.Total != 3 {
		t.Errorf("total = %d, want 3", out.Total)
	}
	if out.Pass != 2 {
		t.Errorf("pass = %d, want 2 (a1 ok + a3 neg-rejected)", out.Pass)
	}
	if out.Fail != 1 {
		t.Errorf("fail = %d, want 1 (a2 count mismatch)", out.Fail)
	}
	if out.Error != 0 {
		t.Errorf("error = %d, want 0", out.Error)
	}
	// per_case 卡位归属
	statuses := map[string]string{}
	for _, pc := range out.PerCase {
		statuses[pc.CaseID] = pc.Status
	}
	if statuses["a1"] != "pass" || statuses["a3"] != "pass" || statuses["a2"] != "fail" {
		t.Errorf("per_case statuses = %v, want a1=pass a3=pass a2=fail", statuses)
	}
}

// TestRunProtocolSuite_ProtoFilter 验证 proto 过滤：只跑指定协议用例。
func TestRunProtocolSuite_ProtoFilter(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	dir := filepath.Join(env.tmp, "cases")
	os.MkdirAll(dir, 0755)
	writeSuiteCase(t, dir, "arp.json",
		`[{"id":"a1","proto":"arp","spec_json":{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]},"expect":{"packet_count":2}},
		  {"id":"t1","proto":"tcp","spec_json":{"layers":[{"tcp":{}}]},"expect":{"packet_count":1}}]`)

	// 只跑 tcp：载入器应过滤掉 arp 用例。
	_, out, err := env.srv.handleRunProtocolSuite(context.Background(), nil, suiteInput{
		CaseDir:    dir,
		Proto:      "tcp",
		OutputType: "pcap",
	})
	if err != nil {
		t.Fatalf("handle suite: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("total = %d, want 1 (only tcp)", out.Total)
	}
	if out.PerCase[0].CaseID != "t1" || out.PerCase[0].Proto != "tcp" {
		t.Errorf("per_case[0] = %+v, want t1/tcp", out.PerCase[0])
	}
}

// TestRunProtocolSuite_MaxCases 验证 max_cases 截断。
func TestRunProtocolSuite_MaxCases(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	dir := filepath.Join(env.tmp, "cases")
	os.MkdirAll(dir, 0755)
	// 3 个 arp 用例（按文件名序 a-t）
	for i := 1; i <= 3; i++ {
		writeSuiteCase(t, dir, strings.Repeat("a", i)+".json",
			`[{"id":"c`+string(rune('0'+i))+`","proto":"arp","spec_json":{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]},"expect":{"packet_count":2}}]`)
	}

	_, out, err := env.srv.handleRunProtocolSuite(context.Background(), nil, suiteInput{
		CaseDir:    dir,
		Proto:      "arp",
		OutputType: "pcap",
		MaxCases:   2,
	})
	if err != nil {
		t.Fatalf("handle suite: %v", err)
	}
	if out.Total != 2 {
		t.Errorf("total = %d, want 2 (capped by max_cases)", out.Total)
	}
}

// TestRunProtocolSuite_CarriesSummary 验证 per_case 结果带 summary（文档生成的
// 人读索引依赖它；此前 runOneCase 构造 result 时丢了 Summary 字段）。
func TestRunProtocolSuite_CarriesSummary(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	dir := filepath.Join(env.tmp, "cases")
	os.MkdirAll(dir, 0755)
	writeSuiteCase(t, dir, "arp_sum.json",
		`[{"id":"a1","proto":"arp","summary":"ARP 请求+响应","spec_json":{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]},"expect":{"packet_count":2}}]`)

	_, out, err := env.srv.handleRunProtocolSuite(context.Background(), nil, suiteInput{
		CaseDir:    dir,
		Proto:      "arp",
		OutputType: "pcap",
	})
	if err != nil {
		t.Fatalf("handle suite: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("total = %d, want 1", out.Total)
	}
	if out.PerCase[0].Summary != "ARP 请求+响应" {
		t.Errorf("per_case[0].summary = %q, want the case summary to flow through", out.PerCase[0].Summary)
	}
}

// writeSuiteCase 写一个 case 文件（cases 目录结构：一文件一 JSON 数组）。
func writeSuiteCase(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// 确保 runCaseInput 的 PCAP happy path 在真实 builder 下能解析。
func TestRunProtocolCase_TimeoutZero_Defaults(t *testing.T) {
	if d := defaultCaseTimeout(0); d != 60*time.Second {
		t.Errorf("defaultCaseTimeout(0) = %v, want 60s", d)
	}
	if d := defaultCaseTimeout(500); d != 300*time.Second {
		t.Errorf("defaultCaseTimeout(500) = %v, want 300s (max clamp)", d)
	}
}

// ---------------------------------------------------------------------------
// 负例防线：外部 stopped 终态不得被当作 validator 拒绝
// ---------------------------------------------------------------------------
//
// 背景（CLAUDE.md 负例契约）：expect_error 用例只有在「planner/validator 真正
// 拒绝」时才允许 pass；外部 stop（用户 stop_all / 超时兜底 / 资源回收）不是
// 校验拒绝。先前实现把 stopped 与 error/failed 并到同一分支，且空
// error_contains 匹配任意消息，导致一个被外部 stop 的 expect_error 任务被
// 误报为 "validate-negative: rejected as expected"（绿色假通过）。
//
// 本测试走真实停止路径（slow planner 保持 running → flowb_manage_tasks stop）
// 而非直接 UPDATE DB：既复现误报，也锁死「外部停止≠校验拒绝」的契约。

// waitForDBStatus polls the DB until the task row reaches want.
func waitForDBStatus(t *testing.T, env *testMCPEnv, taskID, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var tm storage.TaskModel
		if err := env.db.First(&tm, "id = ?", taskID).Error; err == nil && tm.Status == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("task %s never reached status %q (poll timeout)", taskID, want)
}

// TestRunProtocolCase_ExpectError_StoppedNotPass 验证负用例被外部停止时
// 不得报 pass。stopped = 调用方主动中止，不是 validator 拒绝，报 pass 会把
// 一个未经验证的用例标绿。评论：真实停止路径复现（见正文 § "外部停止"）。
func TestRunProtocolCase_ExpectError_StoppedNotPass(t *testing.T) {
	env := setupMCPTestWithPlanner(t, &slowMCPPlanner{name: "tcp", delay: 100 * time.Millisecond})
	defer env.cleanup()

	// 在 goroutine 中运行 suite case；等它创建并启动任务后，通过 REST Stop
	// 将同一个任务置为 stopped，再观察最终 verdict。
	resultCh := make(chan struct {
		out runCaseOutput
		err error
	}, 1)
	go func() {
		_, out, err := env.srv.handleRunProtocolCase(context.Background(), nil, runCaseInput{
			Proto:          "tcp",
			CaseID:         "neg_but_stopped",
			SpecJSON:       json.RawMessage(`{"layers":[{"tcp":{}}]}`),
			StrategyFC:     &flowControlInput{Type: "flows", Value: 1000},
			OutputType:     "pcap",
			OutputConfig:   &outputConfigInput{PcapPath: env.tmp + "/stop-neg.pcap"},
			Expect:         caseExpectInput{ExpectError: true, ErrorContains: ""},
			TimeoutSeconds: 5,
		})
		resultCh <- struct {
			out runCaseOutput
			err error
		}{out: out, err: err}
	}()

	var task storage.TaskModel
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := env.db.Where("name = ?", "tcp-neg_but_stopped").First(&task).Error; err == nil && task.Status == "running" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if task.ID == "" || task.Status != "running" {
		t.Fatalf("case task did not reach running: id=%q status=%q", task.ID, task.Status)
	}

	// 通过 REST stop（而非直接改结果）制造真实 stopped 终态。
	// OBS-2：用例任务现归内部测试账户所有，stop 须以同一身份调用。
	stopCtx := withRunAsUser(context.Background(), env.srv.internalTestUserID, env.srv.internalTestUsername)
	taskH := rest.NewTaskHandlerWithCallbacks(env.db, env.eng, nil, false)
	if _, stopErr := env.srv.callHandler(stopCtx, nil, task.ID, nil, taskH.Stop); stopErr != nil {
		t.Fatalf("stop task: %v", stopErr)
	}

	var result struct {
		out runCaseOutput
		err error
	}
	select {
	case result = <-resultCh:
	case <-time.After(10 * time.Second):
		t.Fatal("case did not return after task was stopped")
	}
	if result.err != nil {
		t.Fatalf("handle: %v", result.err)
	}
	if result.out.Status == "pass" {
		t.Fatalf("status = pass: externally-stopped task must not count as validator rejection (reason=%q)", result.out.Reason)
	}
	// 期望显式：外部 stop 属于「任务异常收尾」，报 error 而非 fail（两者都不
	// 是 pass；此处锁死 error，避免未来又退化成 pass）。
	if result.out.Status != "error" {
		t.Fatalf("status = %q, want error (externally stopped); reason=%q", result.out.Status, result.out.Reason)
	}
	if !strings.Contains(result.out.Reason, "stopped") {
		t.Errorf("reason %q should mention the stopped terminal state", result.out.Reason)
	}
}

// ---------------------------------------------------------------------------
// suite 输出路径唯一性：同 proto+case_id 的并发用例不得共写一个 pcap 文件
// ---------------------------------------------------------------------------
//
// 背景：suite 按 (proto, case_id) 派生出 /tmp/mcp-pcaps/{proto}/{case_id}.pcap；
// 若一个用例目录里出现重复 (proto, case_id)，两个 writer 会 os.Create 同一
// 路径互相覆盖，一个任务读到另一个任务的 pcap → 假 pass/fail。
// 契约：负载用例必须在加载阶段就拒绝重复键（返回明确错误），而不是静默
// 并发共写。这与「用户必须先修通自己的 cases 目录」一致。

// TestRunProtocolSuite_DuplicateCaseKeyRejected 验证 suite loader 在发现
// 重复 (proto, case_id) 时整体报错，不静默并发共写同一 pcap 路径。
func TestRunProtocolSuite_DuplicateCaseKeyRejected(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	dir := filepath.Join(env.tmp, "cases")
	os.MkdirAll(dir, 0755)
	// 两个文件、两个用例，但 (proto, case_id) 都相同。
	writeSuiteCase(t, dir, "a.json",
		`[{"id":"dup","proto":"arp","spec_json":{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]},"expect":{"packet_count":2}}]`)
	writeSuiteCase(t, dir, "b.json",
		`[{"id":"dup","proto":"arp","spec_json":{"arp":{"operation":2}},"expect":{"packet_count":2}}]`)

	_, _, err := env.srv.handleRunProtocolSuite(context.Background(), nil, suiteInput{
		CaseDir:    dir,
		Proto:      "arp",
		OutputType: "pcap",
	})
	if err == nil {
		t.Fatal("want suite to reject duplicate (proto,case_id) keys, got nil")
	}
	if !strings.Contains(err.Error(), "dup") {
		t.Errorf("error %q should name the duplicate case id", err)
	}
}

func TestRunProtocolSuite_UnsafeCasePathRejected(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	dir := filepath.Join(env.tmp, "cases")
	os.MkdirAll(dir, 0755)
	writeSuiteCase(t, dir, "escape.json",
		`[{"id":"../../outside","proto":"arp","spec_json":{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]},"expect":{"packet_count":2}}]`)

	_, _, err := env.srv.handleRunProtocolSuite(context.Background(), nil, suiteInput{
		CaseDir:    dir,
		Proto:      "arp",
		OutputType: "pcap",
		OutputConfig: &outputConfigInput{
			PcapPath: filepath.Join(env.tmp, "pcaps"),
		},
	})
	if err == nil {
		t.Fatal("want suite to reject unsafe case path component, got nil")
	}
	if !strings.Contains(err.Error(), "unsafe") {
		t.Errorf("error %q should identify unsafe path component", err)
	}
}

func TestResolvePcapOutputPath(t *testing.T) {
	if got := resolvePcapOutputPath("case.pcap"); got != filepath.Join("pcap", "case.pcap") {
		t.Fatalf("relative path = %q, want pcap/case.pcap", got)
	}
	if got := resolvePcapOutputPath(filepath.Join("/tmp", "case.pcap")); got != filepath.Join("/tmp", "case.pcap") {
		t.Fatalf("absolute path = %q, want unchanged", got)
	}
}

// P1-12（2026-10-05 客户端复测）：case_id 唯参即可运行语料回归——spec_json
// 省略时从语料目录解析（case_dir > mcp.protocol_cases_dir 配置 > ./cases），
// 期望/流控/decode_as 随语料生效；入参显式字段优先。
func TestRunProtocolCase_CorpusResolution(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()
	corpus := "../../test/protocol_pcap/cases"

	// 负例用例仅凭 case_id 运行：生成被拒（mss 校验）→ verdict pass。
	_, out, err := env.srv.handleRunProtocolCase(context.Background(), nil, runCaseInput{
		CaseID:  "tcp-validate-mss-too-small",
		CaseDir: corpus,
	})
	if err != nil {
		t.Fatalf("case_id-only run: %v", err)
	}
	if out.Status != "pass" {
		t.Errorf("negative corpus case must pass on rejection, got %s: %s", out.Status, out.Reason)
	}
	if out.Proto != "tcp" {
		t.Errorf("proto must be filled from the corpus case, got %q", out.Proto)
	}
}

// 语料未命中 → 指路报错（旧契约 "spec_json is required" 必须退役）。
func TestRunProtocolCase_CorpusMissGuidance(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()
	_, _, err := env.srv.handleRunProtocolCase(context.Background(), nil, runCaseInput{
		Proto: "arp", CaseID: "no_such_case_anywhere", CaseDir: "../../test/protocol_pcap/cases",
	})
	if err == nil {
		t.Fatal("want corpus-miss error")
	}
	if strings.Contains(err.Error(), "spec_json is required") {
		t.Errorf("old contract error leaked: %v", err)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("want not-found guidance, got: %v", err)
	}
}

// P1-12：schema 层不得把 proto/spec_json/output_type/expect 标为 required
// ——case_id 唯参是契约入口，required 挡在 jsonschema 校验则 handler 放宽
// 全白搭（线上实测踩中：invopop 把无 omitempty 字段全部标 required）。
func TestRunCaseSchemaAllowsCaseIDOnly(t *testing.T) {
	srv := newTransportTestServer(t)
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	go func() { _ = srv.mcpServer.Run(ctx, st) }()
	sc, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sc.Close()
	resp, err := sc.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	var schema interface{}
	for _, tl := range resp.Tools {
		if tl.Name == "flowb_run_protocol_case" {
			schema = tl.InputSchema
			break
		}
	}
	if schema == nil {
		t.Fatal("flowb_run_protocol_case not advertised")
	}
	b, _ := json.Marshal(schema)
	var parsed struct {
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"proto", "spec_json", "output_type", "expect"} {
		for _, r := range parsed.Required {
			if r == banned {
				t.Errorf("%q must not be required (case_id-only entry), required=%v", banned, parsed.Required)
			}
		}
	}
}

// 内部测试标记契约（用户指令 2026-10-06）：测试用工具必须在 tools/list 的
// Description 前部明确标记"内部测试专用，客户端正常业务场景勿用"——远程
// LLM 客户端只看描述选工具，标记缺失就会把回归驱动当业务入口。
func TestTestDriveToolsMarkedInternalTest(t *testing.T) {
	srv := newTransportTestServer(t)
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	go func() { _ = srv.mcpServer.Run(ctx, st) }()
	sc, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sc.Close()
	resp, err := sc.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	const marker = "INTERNAL TEST ONLY"
	descriptions := map[string]string{}
	for _, tl := range resp.Tools {
		descriptions[tl.Name] = tl.Description
	}
	for _, name := range []string{"flowb_run_protocol_case", "flowb_run_protocol_suite"} {
		d, ok := descriptions[name]
		if !ok {
			t.Fatalf("%s not advertised", name)
		}
		if !strings.Contains(d, marker) {
			t.Errorf("%s description must carry %q marker, got: %s", name, marker, d)
		}
		if !strings.Contains(d, "客户端正常") {
			t.Errorf("%s description must carry the Chinese 客户端正常业务场景勿用 notice, got: %s", name, d)
		}
	}
	// 业务工具不得被误标（标记只属于测试工具面）。
	for _, name := range []string{"flowb_generate_traffic", "flowb_manage_pcaps"} {
		if d := descriptions[name]; strings.Contains(d, marker) {
			t.Errorf("business tool %s must NOT carry the internal-test marker", name)
		}
	}
}

// OBS-2（2026-10-06 客户端反馈）：内部回归产物（策略/任务/资产）全落共享
// admin 服务账户，客户端 list 看到我们的 b9-tns-*/vnc-v1_* 内部用例名。
// 回归驱动必须在专用内部账户（flowb-internal-test）下创建产物，与客户端
// 数据隔离——不是改名脱敏。
func TestTestDriveArtifactsUnderInternalUser(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()
	srv := env.srv
	if err := srv.ensureInternalTestUser(); err != nil {
		t.Fatalf("ensure internal test user: %v", err)
	}
	if srv.internalTestUserID == "" || srv.internalTestUserID == srv.serviceUserID {
		t.Fatalf("internal test user not distinct: internal=%q service=%q", srv.internalTestUserID, srv.serviceUserID)
	}

	pcapPath := filepath.Join(env.tmp, "arp-obs2.pcap")
	_, out, err := srv.handleRunProtocolCase(context.Background(), nil, runCaseInput{
		Proto:        "arp",
		CaseID:       "arp_obs2",
		SpecJSON:     json.RawMessage(`{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{"operation":1}}]}`),
		OutputType:   "pcap",
		OutputConfig: &outputConfigInput{PcapPath: pcapPath},
		Expect:       caseExpectInput{PacketCount: 2},
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if out.Status != "pass" {
		t.Fatalf("status = %q, want pass; reason=%q", out.Status, out.Reason)
	}

	var task storage.TaskModel
	if err := env.db.Where("name = ?", "arp-arp_obs2").First(&task).Error; err != nil {
		t.Fatalf("load created task: %v", err)
	}
	if task.UserID != srv.internalTestUserID {
		t.Errorf("task user_id = %q, want internal test user %q (service %q must stay clean)",
			task.UserID, srv.internalTestUserID, srv.serviceUserID)
	}
	var strat storage.StrategyModel
	if err := env.db.Where("name = ?", "arp-arp_obs2").First(&strat).Error; err != nil {
		t.Fatalf("load created strategy: %v", err)
	}
	if strat.UserID != srv.internalTestUserID {
		t.Errorf("strategy user_id = %q, want internal test user %q", strat.UserID, srv.internalTestUserID)
	}
}

// 复审 F1（HIGH）：stopRun/cleanupCreatedRun 原以裸 Background（服务账户）
// 清理，而回归产物现归内部测试账户——用户域 Stop/Delete 全 404，错误路径
// 产物永久残留。清理身份必须跟随创建 ctx 的 runAs 覆盖；generate_traffic
//（服务账户产物）的清理不得被误伤。
func TestCleanupCreatedRunFollowsRunAsIdentity(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()
	srv := env.srv
	if err := srv.ensureInternalTestUser(); err != nil {
		t.Fatalf("ensure internal test user: %v", err)
	}

	newRun := func(ownerUser, suffix string) genRun {
		strat := &storage.StrategyModel{ID: uuid.New().String(), UserID: ownerUser, Name: "cln-" + suffix, Protocol: "tcp", Config: `{"layers":[{"ip":{"src":"10.0.0.1","dst":"10.0.0.2"}},{"tcp":{}}]}`}
		if err := env.db.Create(strat).Error; err != nil {
			t.Fatalf("seed strategy: %v", err)
		}
		task := &storage.TaskModel{ID: uuid.New().String(), UserID: ownerUser, Name: "cln-" + suffix, Status: "running", StrategyIDs: `["` + strat.ID + `"]`}
		if err := env.db.Create(task).Error; err != nil {
			t.Fatalf("seed task: %v", err)
		}
		return genRun{TaskID: task.ID, StrategyID: strat.ID}
	}
	rowExists := func(table, id string) bool {
		var n int64
		env.db.Table(table).Where("id = ?", id).Count(&n)
		return n > 0
	}

	// 内部账户产物 + runAs ctx → 两行都必须被清掉。
	internalRun := newRun(srv.internalTestUserID, "internal")
	srv.cleanupCreatedRun(withRunAsUser(context.Background(), srv.internalTestUserID, srv.internalTestUsername), internalRun)
	if rowExists("tasks", internalRun.TaskID) || rowExists("strategies", internalRun.StrategyID) {
		t.Error("internal-user run not cleaned: identity must follow the runAs ctx (was 404 as service user)")
	}

	// 服务账户产物 + 无 runAs 的普通 ctx → 业务清理路径不得被误伤。
	serviceRun := newRun(srv.serviceUserID, "service")
	srv.cleanupCreatedRun(context.Background(), serviceRun)
	if rowExists("tasks", serviceRun.TaskID) || rowExists("strategies", serviceRun.StrategyID) {
		t.Error("service-user run not cleaned: plain ctx must keep service identity")
	}
}
