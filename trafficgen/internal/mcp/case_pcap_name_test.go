package mcp

// case_pcap_name_test.go：pcap 文件名 .neg 标记（预期空包负例）契约测试。
//
// 用户要求：测试预期是空包（expect_error）的用例，落盘 pcap 名必须带标记，
// 与正例一眼可分。命名唯一真相是 pcaptest.CasePcapName —— suite 工具
// （suiteCasePcapPath 双调用点）、单用例工具（显式 pcap_path 缺省派生）、
// go-test 驱动（driver.go RunCase）、离线校验器（verify_all_test.go）、
// 离线层链执行器（layer_chain_suite_test.go runChainCase）、NIC 抓包路径
// 都必须走它，禁止手拼 ".pcap"。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/pcaptest"
)

func TestCasePcapName_MarkerContract(t *testing.T) {
	if got := pcaptest.CasePcapName("mqtt_t089_version_3", true); got != "mqtt_t089_version_3.neg.pcap" {
		t.Errorf("neg name = %q, want mqtt_t089_version_3.neg.pcap", got)
	}
	if got := pcaptest.CasePcapName("mqtt_s1_connect_basic", false); got != "mqtt_s1_connect_basic.pcap" {
		t.Errorf("pos name = %q, want mqtt_s1_connect_basic.pcap", got)
	}
	// 同一 ID 正负两态文件名必须不同（防共写覆盖）。
	if pcaptest.CasePcapName("x", true) == pcaptest.CasePcapName("x", false) {
		t.Error("neg and positive names collide")
	}
}

func TestSuiteCasePcapPath_NegMarker(t *testing.T) {
	neg := suiteCasePcapPath("/root", "mqtt", "mqtt_t089_version_3", true)
	if neg != filepath.Join("/root", "mqtt", "mqtt_t089_version_3.neg.pcap") {
		t.Errorf("suite neg path = %q", neg)
	}
	pos := suiteCasePcapPath("/root", "mqtt", "mqtt_s1_connect_basic", false)
	if pos != filepath.Join("/root", "mqtt", "mqtt_s1_connect_basic.pcap") {
		t.Errorf("suite pos path = %q", pos)
	}
	// 默认 root 回退口径不变。
	if got := suiteCasePcapPath("", "mqtt", "a", false); got != filepath.Join("/tmp/mcp-pcaps", "mqtt", "a.pcap") {
		t.Errorf("default root = %q", got)
	}
}

// TestRunProtocolSuite_NegPcapLandsMarked：端到端——suite 里 expect_error
// 用例被拒后留下的 header-only 文件必须落在 *.neg.pcap，正例落在 *.pcap，
// 且两者都不落到对方的名字上。
func TestRunProtocolSuite_NegPcapLandsMarked(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	dir := filepath.Join(env.tmp, "cases")
	os.MkdirAll(dir, 0755)
	writeSuiteCase(t, dir, "arp.json",
		`[{"id":"neg_marked","proto":"arp","spec_json":{},"expect":{"expect_error":true,"error_contains":"ARP config is required"}},
		  {"id":"pos_ok","proto":"arp","spec_json":{"arp":{"operation":1}},"expect":{"packet_count":2}}]`)
	pcapRoot := filepath.Join(env.tmp, "pcaps")

	_, out, err := env.srv.handleRunProtocolSuite(context.Background(), nil, suiteInput{
		CaseDir:      dir,
		OutputType:   "pcap",
		OutputConfig: &outputConfigInput{PcapPath: pcapRoot},
		Parallel:     2,
	})
	if err != nil {
		t.Fatalf("handle suite: %v", err)
	}
	if out.Pass != 2 {
		t.Fatalf("pass = %d, want 2; per_case=%+v", out.Pass, out.PerCase)
	}
	negPath := filepath.Join(pcapRoot, "arp", "neg_marked.neg.pcap")
	posPath := filepath.Join(pcapRoot, "arp", "pos_ok.pcap")
	if _, err := os.Stat(negPath); err != nil {
		t.Errorf("marked neg pcap missing at %s: %v", negPath, err)
	}
	if _, err := os.Stat(posPath); err != nil {
		t.Errorf("positive pcap missing at %s: %v", posPath, err)
	}
	// 旧名（无标记）不得再产生。
	for _, stale := range []string{
		filepath.Join(pcapRoot, "arp", "neg_marked.pcap"),
		filepath.Join(pcapRoot, "arp", "pos_ok.neg.pcap"),
	} {
		if _, err := os.Stat(stale); err == nil {
			t.Errorf("stale unmarked path still produced: %s", stale)
		}
	}
	// per_case 回报的 pcap_path 与落盘名一致。
	for _, pc := range out.PerCase {
		if pc.CaseID == "pos_ok" && pc.PcapPath != "" && !strings.HasSuffix(pc.PcapPath, "pos_ok.pcap") {
			t.Errorf("pos pcap_path = %q", pc.PcapPath)
		}
	}
}

// TestRunProtocolCase_NegDefaultPathMarked：单用例工具不传 pcap_path 时，
// 缺省派生路径同样带 .neg 标记（handleRunProtocolCase → suiteCasePcapPath）。
func TestRunProtocolCase_NegDefaultPathMarked(t *testing.T) {
	env := setupTestDriveEnv(t)
	defer env.cleanup()

	_, out, err := env.srv.handleRunProtocolCase(context.Background(), nil, runCaseInput{
		Proto:      "arp",
		CaseID:     "neg_default_path",
		SpecJSON:   json.RawMessage(`{}`),
		OutputType: "pcap",
		Expect:     caseExpectInput{ExpectError: true, ErrorContains: "ARP config is required"},
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if out.Status != "pass" {
		t.Fatalf("status = %q, want pass; reason=%q", out.Status, out.Reason)
	}
}
