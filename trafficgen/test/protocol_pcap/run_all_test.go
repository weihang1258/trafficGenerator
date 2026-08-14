package protocolpcap

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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

// loadCases reads all cases/<proto>.json files. The cases dir defaults to the
// package's own cases/ directory (test cwd is the package dir).
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

// TestProtocolPcapDrive is the main driver test. It connects to the MCP
// server, runs each case (concurrently, bounded by envParallel), verifies
// each pcap with tshark, and writes docs/protocol-pcap-test/<proto>.md.
//
// Usage:
//
//	go test -run TestProtocolPcapDrive ./test/protocol_pcap/ -v
//	CASE_PROTO=tcp go test -run TestProtocolPcapDrive ./test/protocol_pcap/ -v
//	CASE_MAX=5 CASE_PROTO=tcp go test ... # smoke
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

	r, err := NewRunner(ctx, envEndpoint, envAPIKey, envPcapRoot)
	if err != nil {
		t.Fatalf("connect MCP: %v", err)
	}
	defer r.Close()

	if _, err := r.Client.CallTool(ctx, "flowb_query_system", map[string]any{"action": "health"}); err != nil {
		t.Fatalf("MCP health check failed: %v", err)
	}

	type job struct {
		proto string
		c     Case
	}
	var jobs []job
	for proto, cs := range cases {
		for _, c := range cs {
			if envMaxCases > 0 && len(jobs) >= envMaxCases {
				break
			}
			jobs = append(jobs, job{proto, c})
		}
		if envMaxCases > 0 && len(jobs) >= envMaxCases {
			break
		}
	}

	results := make([]*CaseResult, len(jobs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, envParallel)
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = r.RunCase(ctx, j.c, envTimeout)
		}(i, j)
	}
	wg.Wait()

	// Verify pcaps and classify.
	pass, fail, errCount := 0, 0, 0
	byProto := map[string][]*CaseResult{}
	for i, res := range results {
		byProto[res.Proto] = append(byProto[res.Proto], res)
		switch res.Status {
		case "pass":
			// Validate-negative cases have no pcap to verify; they passed
			// because the task errored as expected.
			if jobs[i].c.Expect.ExpectError {
				pass++
				continue
			}
			if probs := VerifyPcap(res.PcapAbsPath, jobs[i].c); len(probs) == 0 {
				pass++
				res.Status = "pass"
			} else {
				res.Status = "fail"
				res.Err = "verify: " + joinProbs(probs)
				fail++
			}
		case "fail":
			fail++
		default:
			errCount++
		}
	}

	if err := writeDocs(byProto, pass, fail, errCount, total); err != nil {
		t.Errorf("write docs: %v", err)
	}

	t.Logf("RESULT: %d pass, %d fail, %d error (of %d)", pass, fail, errCount, total)
	for proto, rs := range byProto {
		t.Logf("  %-8s %d/%d", proto, countStatus(rs, "pass"), len(rs))
	}
	for _, res := range results {
		if res.Status != "pass" {
			t.Errorf("[%s] %s: %s", res.Proto, res.CaseID, res.Err)
		}
	}
	if fail+errCount > 0 {
		t.Fatalf("%d cases failed verification or errored", fail+errCount)
	}
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
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

var _ = context.Background
