package protocolpcap

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// env-configurable knobs (defaults suit the dev setup).
var (
	envEndpoint = getenv("MCP_ENDPOINT", DefaultEndpoint)
	envAPIKey   = getenv("MCP_API_KEY", DefaultAPIKey)
	envPcapRoot = getenv("PCAP_ROOT", "/tmp/mcp-pcaps")
	envCasesDir = getenv("CASES_DIR", "cases")
	// Doc dir defaults to repo-root docs/protocol-pcap-test (repo root is
	// two levels up from the test package dir).
	envDocDir   = getenv("DOC_DIR", filepath.Join("..", "..", "docs", "protocol-pcap-test"))
	envTimeout  = 60 * time.Second
	envParallel = 4
	envPerProto = "" // e.g. "tcp" limits to one protocol
	envMaxCases = 0  // >0 limits total cases (smoke)
	envForce    = false
)

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func init() {
	if v := os.Getenv("CASE_TIMEOUT_S"); v != "" {
		var s int
		fmt.Sscanf(v, "%d", &s)
		envTimeout = time.Duration(s) * time.Second
	}
	if v := os.Getenv("CASE_PARALLEL"); v != "" {
		fmt.Sscanf(v, "%d", &envParallel)
	}
	envPerProto = os.Getenv("CASE_PROTO")
	if v := os.Getenv("CASE_MAX"); v != "" {
		fmt.Sscanf(v, "%d", &envMaxCases)
	}
	envForce = os.Getenv("CASE_FORCE") == "1"
}

// loadCases reads all cases/<proto>.json files and returns them keyed by
// protocol. The loader is kept so the test can count/discover cases before
// handing the directory to flowb_run_protocol_suite (the actual loading and
// verification happens server-side in that tool).
func loadCases(t *testing.T) map[string][]Case {
	casesDir := envCasesDir
	if !filepath.IsAbs(casesDir) && !dirExists(casesDir) {
		casesDir = "cases"
	}
	files, err := filepath.Glob(filepath.Join(casesDir, "*.json"))
	if err != nil {
		t.Fatalf("glob cases: %v", err)
	}
	cases := map[string][]Case{}
	for _, f := range files {
		proto := filepath.Base(f)
		proto = proto[:len(proto)-len(".json")]
		if envPerProto != "" && proto != envPerProto {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var cs []Case
		if err := json.Unmarshal(b, &cs); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		cases[proto] = cs
	}
	return cases
}

// resolveCasesDir returns the absolute cases directory the suite tool should
// read (the tool resolves relative paths against the MCP server's cwd, so the
// test passes an explicit absolute path).
func resolveCasesDir() string {
	casesDir := envCasesDir
	if !filepath.IsAbs(casesDir) && !dirExists(casesDir) {
		casesDir = "cases"
	}
	if abs, err := filepath.Abs(casesDir); err == nil {
		return abs
	}
	return casesDir
}

func buildSuiteArgs(caseDir string) map[string]any {
	args := map[string]any{
		"case_dir":      caseDir,
		"output_type":   "pcap",
		"output_config": map[string]any{"pcap_path": envPcapRoot},
		"parallel":      envParallel,
		"timeout_s":     int(envTimeout.Seconds()),
		"max_cases":     envMaxCases,
	}
	if envPerProto != "" {
		args["proto"] = envPerProto
	}
	return args
}

// suiteToolResult mirrors flowb_run_protocol_suite's JSON payload.
type suiteToolResult struct {
	Total   int             `json:"total"`
	Pass    int             `json:"pass"`
	Fail    int             `json:"fail"`
	Error   int             `json:"error"`
	PerCase []suiteToolCase `json:"per_case,omitempty"`
}

// suiteToolCase mirrors flowb_run_protocol_case's per-case verdict JSON.
type suiteToolCase struct {
	CaseID      string   `json:"case_id"`
	Proto       string   `json:"proto"`
	Summary     string   `json:"summary,omitempty"`
	Status      string   `json:"status"`
	Reason      string   `json:"reason,omitempty"`
	PacketCount int      `json:"packet_count,omitempty"`
	PcapPath    string   `json:"pcap_path,omitempty"`
	TaskID      string   `json:"task_id,omitempty"`
	Failures    []string `json:"failures,omitempty"`
	DurationMs  int64    `json:"duration_ms"`
}

// runSuiteViaMCP drives flowb_run_protocol_suite through the MCP server and
// returns the tool's aggregate results. All case loading, traffic generation,
// terminal polling, and tshark verification happen server-side (CLAUDE.md
// "所有测试经 MCP 执行"); this test only asserts the returned statistics.
func runSuiteViaMCP(ctx context.Context, t *testing.T) (*suiteToolResult, error) {
	r, err := NewRunner(ctx, envEndpoint, envAPIKey, envPcapRoot)
	if err != nil {
		return nil, fmt.Errorf("connect MCP: %w", err)
	}
	defer r.Close()

	if _, err := r.Client.CallTool(ctx, "flowb_query_system", map[string]any{"action": "health"}); err != nil {
		return nil, fmt.Errorf("MCP health check failed: %w", err)
	}
	// full suite（全部/数千用例）串行经一次 HTTP 往返完成，默认 2m 单请求超时
	// 不够。按用例数预算：未设上限时给足 30m 兜底，有上限时按批次估（外层
	// ctx 仍兜底）。
	reqTimeout := 30 * time.Minute
	if envMaxCases > 0 {
		parallel := envParallel
		if parallel < 1 {
			parallel = 1
		}
		reqTimeout = envTimeout * time.Duration(max(1, envMaxCases/parallel+1))
	}
	r.Client.SetTimeout(reqTimeout)

	args := buildSuiteArgs(resolveCasesDir())
	raw, err := r.Client.CallTool(ctx, "flowb_run_protocol_suite", args)
	if err != nil {
		return nil, fmt.Errorf("run suite: %w", err)
	}
	var out suiteToolResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse suite result: %w (raw=%s)", err, raw)
	}
	return &out, nil
}

// TestProtocolPcapDrive is the main driver test. It feeds the cases directory
// to the MCP server's flowb_run_protocol_suite tool, which loads the cases,
// generates traffic, writes pcap files, runs tshark verification, and returns
// aggregate pass/fail/error stats. This test asserts only those tool-returned
// stats, so go test and any MCP client (Claude Code / external tools) run the
// exact same assertions (CLAUDE.md "所有测试经 MCP 执行").
//
// Usage:
//
//	go test -run TestProtocolPcapDrive ./test/protocol_pcap/ -v -timeout 3600s
//	CASE_PROTO=tcp go test -run TestProtocolPcapDrive ./test/protocol_pcap/ -v
//	CASE_MAX=5 CASE_PROTO=tcp go test ... # smoke
//
// The full suite (~2100 cases) needs -timeout 3600s: the server-side suite
// takes 7-10+ minutes, and go test's default 10m budget panics mid-run
// (test timed out after 10m0s) even though the client timeout is ample.
func TestProtocolPcapDrive(t *testing.T) {
	cases := loadCases(t)
	if len(cases) == 0 {
		t.Fatal("no case files found under " + envCasesDir)
	}
	total := 0
	for _, cs := range cases {
		total += len(cs)
	}
	t.Logf("loaded %d cases across %d protocols", total, len(cases))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	out, err := runSuiteViaMCP(ctx, t)
	if err != nil {
		t.Fatalf("suite via MCP: %v", err)
	}

	// Convert tool verdicts into the doc-writing format.
	results := make([]*CaseResult, len(out.PerCase))
	for i, pc := range out.PerCase {
		res := &CaseResult{
			CaseID:      pc.CaseID,
			Proto:       pc.Proto,
			Summary:     pc.Summary,
			Status:      pc.Status,
			TaskID:      pc.TaskID,
			PcapAbsPath: pc.PcapPath,
			PacketCount: pc.PacketCount,
		}
		if pc.PcapPath != "" {
			if rel, derr := filepath.Rel(envPcapRoot, pc.PcapPath); derr == nil {
				res.PcapRelPath = rel
			} else {
				res.PcapRelPath = pc.PcapPath
			}
		}
		if pc.Status != "pass" {
			switch {
			case len(pc.Failures) > 0:
				res.Err = pc.Reason + ": " + joinProbs(pc.Failures)
			case pc.Reason != "":
				res.Err = pc.Reason
			default:
				res.Err = "status " + pc.Status
			}
		}
		results[i] = res
	}

	byProto := map[string][]*CaseResult{}
	for _, res := range results {
		byProto[res.Proto] = append(byProto[res.Proto], res)
	}
	if err := writeDocs(byProto, out.Pass, out.Fail, out.Error, out.Total); err != nil {
		t.Errorf("write docs: %v", err)
	}

	t.Logf("RESULT: %d pass, %d fail, %d error (of %d)", out.Pass, out.Fail, out.Error, out.Total)
	for proto, rs := range byProto {
		t.Logf("  %-8s %d/%d", proto, countStatus(rs, "pass"), len(rs))
	}
	for _, res := range results {
		if res.Status != "pass" {
			t.Errorf("[%s] %s: %s", res.Proto, res.CaseID, res.Err)
		}
	}
	if out.Fail+out.Error > 0 {
		t.Fatalf("%d cases failed verification or errored", out.Fail+out.Error)
	}
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
func TestResolveCasesDirUsesLoaderFallback(t *testing.T) {
	old := envCasesDir
	defer func() { envCasesDir = old }()
	envCasesDir = "missing"

	got := resolveCasesDir()
	want, err := filepath.Abs("cases")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("resolveCasesDir() = %q, want loader fallback %q", got, want)
	}
}

func TestBuildSuiteArgsPassesPcapRoot(t *testing.T) {
	oldRoot, oldProto, oldParallel, oldTimeout, oldMax := envPcapRoot, envPerProto, envParallel, envTimeout, envMaxCases
	defer func() {
		envPcapRoot, envPerProto, envParallel, envTimeout, envMaxCases = oldRoot, oldProto, oldParallel, oldTimeout, oldMax
	}()
	envPcapRoot = filepath.Join(t.TempDir(), "pcaps")
	envPerProto = "arp"
	envParallel = 3
	envTimeout = 17 * time.Second
	envMaxCases = 9

	args := buildSuiteArgs("/tmp/cases")
	output, ok := args["output_config"].(map[string]any)
	if !ok {
		t.Fatalf("output_config = %#v, want object", args["output_config"])
	}
	if output["pcap_path"] != envPcapRoot {
		t.Fatalf("output_config.pcap_path = %#v, want %q", output["pcap_path"], envPcapRoot)
	}
	if args["case_dir"] != "/tmp/cases" || args["proto"] != "arp" || args["parallel"] != 3 || args["max_cases"] != 9 {
		t.Fatalf("unexpected suite args: %#v", args)
	}
}

func countStatus(rs []*CaseResult, s string) int {
	n := 0
	for _, r := range rs {
		if r.Status == s {
			n++
		}
	}
	return n
}

func joinProbs(ps []string) string {
	s := ""
	for i, p := range ps {
		if i > 0 {
			s += "; "
		}
		s += p
	}
	return s
}

// writeDocs writes one markdown report per protocol plus a summary index.
func writeDocs(byProto map[string][]*CaseResult, pass, fail, errCount, total int) error {
	if err := os.MkdirAll(envDocDir, 0755); err != nil {
		return err
	}
	var protos []string
	for p := range byProto {
		protos = append(protos, p)
	}
	sort.Strings(protos)

	// Summary index.
	var idx strings.Builder
	idx.WriteString("# Protocol Pcap Test Results\n\n")
	idx.WriteString(fmt.Sprintf("Run at %s — %d total cases, %d pass, %d fail, %d error\n\n",
		time.Now().Format("2006-01-02 15:04:05"), total, pass, fail, errCount))
	idx.WriteString("| Protocol | Cases | Pass | Fail | Error |\n")
	idx.WriteString("|----------|-------|------|------|-------|\n")
	for _, p := range protos {
		rs := byProto[p]
		idx.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d |\n",
			p, len(rs), countStatus(rs, "pass"), countStatus(rs, "fail"), countStatus(rs, "error")))
	}
	idx.WriteString("\n")
	if err := os.WriteFile(filepath.Join(envDocDir, "SUMMARY.md"), []byte(idx.String()), 0644); err != nil {
		return err
	}

	// Per-protocol reports.
	for _, p := range protos {
		rs := byProto[p]
		sort.Slice(rs, func(i, j int) bool { return rs[i].CaseID < rs[j].CaseID })
		var b strings.Builder
		b.WriteString(fmt.Sprintf("# %s Pcap Test Results\n\n", p))
		b.WriteString(fmt.Sprintf("Cases: %d — pass %d, fail %d, error %d\n\n",
			len(rs), countStatus(rs, "pass"), countStatus(rs, "fail"), countStatus(rs, "error")))
		b.WriteString("| Case | Summary | Status | Packets | Pcap |\n")
		b.WriteString("|------|---------|--------|---------|------|\n")
		for _, r := range rs {
			pcapLink := fmt.Sprintf("`%s`", r.PcapRelPath)
			if r.Status == "pass" {
				pcapLink = fmt.Sprintf("[pcap](%s)", r.PcapRelPath)
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %s |\n",
				r.CaseID, sanitize(r.Summary), r.Status, r.PacketCount, pcapLink))
		}
		// Failure detail section.
		nFail := 0
		for _, r := range rs {
			if r.Status != "pass" {
				nFail++
			}
		}
		if nFail > 0 {
			b.WriteString("\n## Failures\n\n")
			for _, r := range rs {
				if r.Status == "pass" {
					continue
				}
				b.WriteString(fmt.Sprintf("### %s — %s\n\n%s\n\n", r.CaseID, r.Summary, r.Err))
			}
		}
		if err := os.WriteFile(filepath.Join(envDocDir, p+".md"), []byte(b.String()), 0644); err != nil {
			return err
		}
	}
	return nil
}

func sanitize(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
