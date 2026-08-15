package protocolpcap

import (
	"encoding/json"
	"strings"
	"testing"
)

// nicSelection 采样逻辑单测：不依赖 MCP/NIC（无需 NIC_RUN）。
// 覆盖 hasL2Override 判定与 L2 覆盖用例强制纳入采样。

func TestHasL2Override(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want bool
	}{
		{"dst mac default", `{"src_ip":"10.0.0.1","dst_mac":"02:00:00:00:00:02"}`, false},
		{"src mac default", `{"src_ip":"10.0.0.1","src_mac":"02:00:00:00:00:01"}`, false},
		{"dst mac override", `{"src_ip":"10.0.0.1","dst_mac":"00:11:22:33:44:55"}`, true},
		{"src mac override", `{"src_ip":"10.0.0.1","src_mac":"00:aa:bb:cc:dd:ee"}`, true},
		{"empty mac ignored", `{"src_ip":"10.0.0.1","dst_mac":""}`, false},
		{"no mac fields", `{"src_ip":"10.0.0.1","dst_ip":"20.0.0.1"}`, false},
		{"malformed spec", `not-json{`, false},
	}
	for _, tc := range cases {
		c := Case{SpecJSON: json.RawMessage(tc.spec)}
		if got := hasL2Override(c); got != tc.want {
			t.Errorf("%s: hasL2Override=%v want %v", tc.name, got, tc.want)
		}
	}
}

// TestOverrideMACs 验证抓包过滤器扩展列表：覆盖 MAC 应全部纳入（抓包
// 才能捕获 L2 覆盖用例的帧），默认值/空串忽略，重复值去重。
func TestOverrideMACs(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want []string
	}{
		{"defaults only", `{"src_mac":"02:00:00:00:00:01","dst_mac":"02:00:00:00:00:02"}`, nil},
		{"dst override", `{"dst_mac":"00:11:22:33:44:55"}`, []string{"00:11:22:33:44:55"}},
		{"src override", `{"src_mac":"00:aa:bb:cc:dd:ee"}`, []string{"00:aa:bb:cc:dd:ee"}},
		{"both override", `{"src_mac":"00:aa:bb:cc:dd:ee","dst_mac":"00:11:22:33:44:55"}`,
			[]string{"00:aa:bb:cc:dd:ee", "00:11:22:33:44:55"}},
		{"same value deduped", `{"src_mac":"00:11:22:33:44:55","dst_mac":"00:11:22:33:44:55"}`,
			[]string{"00:11:22:33:44:55"}},
		{"empty ignored", `{"src_mac":"","dst_mac":"00:11:22:33:44:55"}`, []string{"00:11:22:33:44:55"}},
		{"malformed empty", `not-json{`, nil},
	}
	for _, tc := range cases {
		c := Case{SpecJSON: json.RawMessage(tc.spec)}
		got := overrideMACs(c)
		if len(got) != len(tc.want) {
			t.Errorf("%s: overrideMACs=%v want %v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: overrideMACs=%v want %v", tc.name, got, tc.want)
				break
			}
		}
	}
}

// TestNicSelection_ForcesL2OverrideCase 用真实 doip 用例验证：L2 覆盖
// 用例（doip_eid_from_dstmac）虽不在等距采样点（idx 49, step 21），
// 仍被强制纳入。
func TestNicSelection_ForcesL2OverrideCase(t *testing.T) {
	cases := loadCases(t)
	doip, ok := cases["doip"]
	if !ok {
		t.Fatal("no doip cases")
	}
	jobs := nicSelection(t, map[string][]Case{"doip": doip})
	if len(jobs) != 1 {
		t.Fatalf("want 1 job, got %d", len(jobs))
	}
	var ids []string
	for _, c := range jobs[0].cases {
		ids = append(ids, c.ID)
	}
	joined := strings.Join(ids, ",")
	if !strings.Contains(joined, "doip_eid_from_dstmac") {
		t.Errorf("L2-override case not forced into selection; got %v", ids)
	}
}

// TestNicSelection_MaxOneSmoke 验证 NIC_MAX=1 冒烟下（文档推荐）首个
// 选中用例不是 L2 覆盖用例——L2 覆盖用例整包漏抓会空 pcap 必红，
// 冒烟应选可抓帧的用例。
func TestNicSelection_MaxOneSmoke(t *testing.T) {
	cases := loadCases(t)
	modbus, ok := cases["modbus"]
	if !ok {
		t.Fatal("no modbus cases")
	}
	jobs := nicSelection(t, map[string][]Case{"modbus": modbus})
	if len(jobs) != 1 || len(jobs[0].cases) < 1 {
		t.Fatalf("want 1 job with cases, got %d jobs", len(jobs))
	}
	first := jobs[0].cases[0]
	if hasL2Override(first) {
		t.Errorf("smoke first case %s has L2 override; NIC_MAX=1 smoke would always fail (frames filtered out)", first.ID)
	}
	if first.Expect.ExpectError {
		t.Errorf("smoke first case %s is a negative case; smoke should pick a capturing case", first.ID)
	}
}

// TestNicSelection_NicProbePicksExactCase 验证 NIC_CASE 单用例模式精确
// 命中（含 expect_error 用例）。
func TestNicSelection_NicProbePicksExactCase(t *testing.T) {
	old := nicProbe
	defer func() { nicProbe = old }()
	nicProbe = "tcp-handshake-basic"
	cases := loadCases(t)
	jobs := nicSelection(t, cases)
	if len(jobs) != 1 || len(jobs[0].cases) != 1 || jobs[0].cases[0].ID != "tcp-handshake-basic" {
		t.Fatalf("nicProbe did not select exactly tcp-handshake-basic, got %+v", jobs)
	}
}

// TestNicSelection_MaxCapsJobs 验证 NIC_MAX 截断作用于 job 数，且 job
// 序按协议字典序确定（Go map 迭代序随机，截断必须可复现）。
func TestNicSelection_MaxCapsJobs(t *testing.T) {
	old := nicMax
	defer func() { nicMax = old }()
	nicMax = 3
	cases := loadCases(t)
	jobs := nicSelection(t, cases)
	if len(jobs) != 3 {
		t.Errorf("NIC_MAX=3: want 3 jobs, got %d", len(jobs))
	}
	// 字典序断言：job[0] < job[1] < job[2]。
	for i := 1; i < len(jobs); i++ {
		if jobs[i-1].proto >= jobs[i].proto {
			t.Errorf("jobs not sorted: %s >= %s", jobs[i-1].proto, jobs[i].proto)
		}
	}
	// 确定性：两次调用结果一致。
	jobs2 := nicSelection(t, cases)
	for i := range jobs {
		if jobs[i].proto != jobs2[i].proto {
			t.Errorf("nondeterministic job order: %s vs %s", jobs[i].proto, jobs2[i].proto)
		}
	}
}
