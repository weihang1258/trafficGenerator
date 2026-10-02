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

// TestOverrideMACs 验证抓包过滤词列表：覆盖 MAC 应全部纳入（抓包
// 才能捕获 L2 覆盖用例的帧），默认值/空串忽略，重复去重；动态 MAC
// 展开 range/list/value 候选 + inc/rand 首字节 BPF 测试（genMAC 输出
// =首字节+低 3 字节，中间两字节清零）。
func TestOverrideMACs(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want []string
	}{
		{"defaults only", `{"src_mac":"02:00:00:00:00:01","dst_mac":"02:00:00:00:00:02"}`, nil},
		{"dst override", `{"dst_mac":"00:11:22:33:44:55"}`, []string{"ether src 00:11:22:33:44:55"}},
		{"src override", `{"src_mac":"00:aa:bb:cc:dd:ee"}`, []string{"ether src 00:aa:bb:cc:dd:ee"}},
		{"both override", `{"src_mac":"00:aa:bb:cc:dd:ee","dst_mac":"00:11:22:33:44:55"}`,
			[]string{"ether src 00:11:22:33:44:55", "ether src 00:aa:bb:cc:dd:ee"}},
		{"same value deduped", `{"src_mac":"00:11:22:33:44:55","dst_mac":"00:11:22:33:44:55"}`,
			[]string{"ether src 00:11:22:33:44:55"}},
		{"empty ignored", `{"src_mac":"","dst_mac":"00:11:22:33:44:55"}`, []string{"ether src 00:11:22:33:44:55"}},
		{"malformed empty", `not-json{`, nil},
		// eth 层配置覆盖（arp/goose/sv 等 L2 族）：src/dst 都纳入（应答帧
		// 把层 dst_mac 当帧源）。
		{"eth layer src+dst", `{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01","dst_mac":"aa:bb:cc:dd:ee:02"}},{"arp":{}}]}`,
			[]string{"ether src aa:bb:cc:dd:ee:01", "ether src aa:bb:cc:dd:ee:02"}},
		{"eth layer defaults skipped", `{"layers":[{"eth":{"src_mac":"02:00:00:00:00:01"}},{"arp":{}}]}`, nil},
		{"any-layer _mac collected", `{"layers":[{"vlan":{"src_mac":"aa:bb:cc:dd:ee:01"}},{"arp":{}}]}`,
			[]string{"ether src aa:bb:cc:dd:ee:01"}},
		{"non-mac keys ignored", `{"layers":[{"arp":{"sender_ip":"1.2.3.4","opcode":1}}]}`, nil},
		{"top+layer deduped", `{"src_mac":"aa:bb:cc:dd:ee:01","layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01"}}]}`,
			[]string{"ether src aa:bb:cc:dd:ee:01"}},
		// arp 显式 sender_mac/target_mac：帧 eth.src 直接取该 MAC
		// （arp_t3_explicit_addrs 形状）。
		{"arp sender/target mac", `{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:01"}},{"arp":{"sender_mac":"11:22:33:44:55:66","target_mac":"66:55:44:33:22:11"}}]}`,
			[]string{"ether src 11:22:33:44:55:66", "ether src 66:55:44:33:22:11", "ether src aa:bb:cc:dd:ee:01"}},
		// 动态 MAC（sv_mac_dyn_*）：候选展开 + inc/rand 首字节 BPF 测试。
		{"eth layer dynamic range", `{"layers":[{"eth":{"src_mac":{"strategy":"inc","range":["aa:00:00:00:00:01","aa:00:00:00:00:02"],"step":1}}},{"sv":{}}]}`,
			[]string{"ether src aa:00:00:00:00:01", "ether src aa:00:00:00:00:02", "ether[6] = 0xaa"}},
		{"eth layer dynamic list+value", `{"layers":[{"eth":{"src_mac":{"list":["aa:00:00:00:00:03"]},"dst_mac":{"value":"aa:00:00:00:00:04"}}},{"sv":{}}]}`,
			[]string{"ether src aa:00:00:00:00:03", "ether src aa:00:00:00:00:04"}},
		{"dynamic rand firstbyte", `{"layers":[{"eth":{"src_mac":{"strategy":"rand","range":["aa:00:00:00:00:01","aa:00:00:00:00:ff"],"seed":7}}},{"sv":{}}]}`,
			[]string{"ether src aa:00:00:00:00:01", "ether src aa:00:00:00:00:ff", "ether[6] = 0xaa"}},
		{"dynamic default range skipped", `{"layers":[{"eth":{"src_mac":{"strategy":"inc","range":["02:00:00:00:00:01","02:00:00:00:00:02"]}}}]}`,
			[]string{"ether[6] = 0x02"}},
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

// TestNicSelection_ForcesL2OverrideCase 用真实 arp 用例验证：eth 层 MAC
// 覆盖用例（arp_t1_baseline_pair，{"eth":{"src_mac":"aa:..."} }）虽不在
// 等距采样点，仍被强制纳入（漏抓守卫路径可达）。历史注记：旧守卫钉
// doip_eid_from_dstmac（顶层 dst_mac），D-DOIP-1 115→80 重写后该用例
// 退役，L2 覆盖代表转到 arp 的 eth 层形状。
func TestNicSelection_ForcesL2OverrideCase(t *testing.T) {
	cases := loadCases(t)
	arp, ok := cases["arp"]
	if !ok {
		t.Fatal("no arp cases")
	}
	jobs := nicSelection(t, map[string][]Case{"arp": arp})
	if len(jobs) != 1 {
		t.Fatalf("want 1 job, got %d", len(jobs))
	}
	var ids []string
	for _, c := range jobs[0].cases {
		ids = append(ids, c.ID)
	}
	joined := strings.Join(ids, ",")
	if !strings.Contains(joined, "arp_t1_baseline_pair") {
		t.Errorf("eth-layer L2-override case not forced into selection; got %v", ids)
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

// TestNicSelection_SkipWindow 验证 NIC_SKIP 窗口推进：skip 在字典序
// 排序后、NIC_MAX 截断前生效（skip+max 构成批次窗口）；越界报空不
// 静默全量重跑（越界重跑会让批次脚本把同一批当新批再跑一遍）。
func TestNicSelection_SkipWindow(t *testing.T) {
	oldSkip, oldMax := nicSkip, nicMax
	defer func() { nicSkip, nicMax = oldSkip, oldMax }()
	cases := loadCases(t)
	full := nicSelection(t, cases)
	if len(full) < 4 {
		t.Fatalf("need >=4 protos for window test, got %d", len(full))
	}
	// skip=2：窗口从 full[2] 起。
	nicSkip = 2
	got := nicSelection(t, cases)
	if len(got) != len(full)-2 || got[0].proto != full[2].proto {
		t.Errorf("skip=2: want start %s, got len=%d start=%v", full[2].proto, len(got), got[0].proto)
	}
	// skip=1 + max=2：恰好 full[1..2]（窗口推进 + 截断组合）。
	nicSkip, nicMax = 1, 2
	got = nicSelection(t, cases)
	if len(got) != 2 || got[0].proto != full[1].proto || got[1].proto != full[2].proto {
		t.Errorf("skip=1,max=2: want [%s %s], got %v", full[1].proto, full[2].proto, got)
	}
	// skip 越界：空结果（调用方 no cases selected 即失败），绝不静默全量。
	nicSkip, nicMax = len(full)+5, 0
	if got := nicSelection(t, cases); len(got) != 0 {
		t.Errorf("skip beyond end: want 0 jobs, got %d (silent full rerun)", len(got))
	}
}
