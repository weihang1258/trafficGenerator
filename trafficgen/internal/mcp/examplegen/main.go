// Command examplegen derives per-protocol LLM examples from the verified
// cases corpus (test/protocol_pcap/cases/*.json) into an embeddable JSON.
//
// 选择规则（每协议 ≤5 条，贪心字段多样性）：
//  1. simplest：事务例档优先（含响应语义的正常业务场景排前——一问一答
//     才是正常业务；语料只有单向例的协议维持单向），档内层最少、字段键
//     总数最少——LLM 拿来即用的最小可跑配置；
//  2. 多流例保底：示例集必含至少一个 flows>1 的已验证多流例（必然携带
//     动态 strategy 字段），LLM 照抄改 N，不从单流静态示例试错；
//  3. 逐轮挑"相对已收录带来最多新协议层键"的用例（headers/body/
//     transactions 等常用定制字段必须在示例里可见），直到无新键或达上限。
//
// 单条 config 超 6KB 跳过（控制内嵌体积与 LLM 上下文）。示例来自 cases
// 全量 sweep 验证过的真值——LLM 复制形状即可一次调用成功，无需试错。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type caseFile struct {
	ID       string          `json:"id"`
	Proto    string          `json:"proto"`
	Summary  string          `json:"summary"`
	SpecJSON json.RawMessage `json:"spec_json"`
	Expect   struct {
		ExpectError bool `json:"expect_error"`
		PacketCount int  `json:"packet_count"`
		MinPackets  int  `json:"min_packets"`
	} `json:"expect"`
}

type example struct {
	Protocol    string          `json:"protocol"`
	CaseID      string          `json:"case_id"`
	Summary     string          `json:"summary"`
	Config      json.RawMessage `json:"config"`
	FlowControl string          `json:"flow_control_note,omitempty"`
	Packets     int             `json:"packets"` // 事务档判定输入：缺省事务例（无 opt-out 键且 ≥2 包）
}

type envelope struct {
	Generated int               `json:"generated"`
	Protocols map[string][]exam `json:"protocols"`
}
type exam = example

func complexity(spec json.RawMessage) (int, error) {
	var m struct {
		Layers []map[string]json.RawMessage `json:"layers"`
	}
	if err := json.Unmarshal(spec, &m); err != nil {
		return 0, err
	}
	score := len(m.Layers)
	for _, l := range m.Layers {
		score += len(l)
	}
	return score, nil
}

func flowNote(spec json.RawMessage) string {
	v := multiFlowValue(spec)
	if v > 1 {
		return fmt.Sprintf("flows=%d（%d 条流并发）", v, v)
	}
	return ""
}

// multiFlowValue returns the flow_control value (0 when absent).
func multiFlowValue(cfg json.RawMessage) int {
	var m struct {
		FlowControl *struct {
			Value int `json:"value"`
		} `json:"flow_control"`
	}
	json.Unmarshal(cfg, &m)
	if m.FlowControl != nil {
		return m.FlowControl.Value
	}
	return 0
}

// txTier：事务例档（排序用）。语料自证不逐协议硬编码——两路信号任一命中
// 即事务档：① config 携带响应/事务语义键（txSignal）；② **缺省事务例**：
// 正例 expect.packet_count ≥ 2 且 config 不带纯请求 opt-out 键（query_only/
// request_only）。②覆盖 D-DNS-2/D-SNMP-2/D-NTP-2 反转后的缺省一问一答例
// （如 snmp_get_default_transaction、ntp_client_default_transaction）——
// 它们不带任何显式响应键，靠包数自证；opt-out 键排除多流纯查询例
// （dns flows=2 查询例包数同为 2，但配置声明了 query_only）。
func txTier(e exam) bool {
	if txSignal(e.Config) {
		return true
	}
	return e.Packets >= 2 && !hasOptOutKey(e.Config)
}

// hasOptOutKey reports whether the config carries an explicit one-sided
// switch (query_only / request_only) in any layer config.
func hasOptOutKey(cfg json.RawMessage) bool {
	var m struct {
		Layers []map[string]json.RawMessage `json:"layers"`
	}
	if json.Unmarshal(cfg, &m) != nil {
		return false
	}
	for _, layer := range m.Layers {
		for _, raw := range layer {
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil {
				continue
			}
			if _, ok := fields["query_only"]; ok {
				return true
			}
			if _, ok := fields["request_only"]; ok {
				return true
			}
		}
	}
	return false
}

// txSignal：config 是否携带响应/事务语义（is_response、response_code、
// reply/replies、多步 procedures 含 response/reply/ack、transactions/
// sessions）。语料含事务例的协议，默认示例应选正常业务场景（请求+响应），
// 而不是纯请求的半边场景（提示词实测 P1-①：dns 默认示例只有 query 没有
// response——一问一答才是正常业务）。语料只有单向例的协议（路由通告/
// 日志上报/隧道封装）行为不变——单向即其正常场景，由语料自证，不逐协议
// 硬编码。
func txSignal(cfg json.RawMessage) bool {
	var m struct {
		Layers []map[string]json.RawMessage `json:"layers"`
	}
	if json.Unmarshal(cfg, &m) != nil {
		return false
	}
	for _, layer := range m.Layers {
		for _, raw := range layer {
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil {
				continue
			}
			for _, k := range []string{"is_response", "response_code", "responses", "reply", "replies", "transactions", "sessions"} {
				if _, ok := fields[k]; ok {
					return true
				}
			}
			if p, ok := fields["procedures"]; ok {
				var procs []map[string]interface{}
				if json.Unmarshal(p, &procs) == nil && len(procs) >= 2 {
					for _, pr := range procs {
						t := strings.ToLower(fmt.Sprint(pr["type"]))
						if strings.Contains(t, "response") || strings.Contains(t, "reply") || strings.Contains(t, "ack") {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func Generate(casesDir string) ([]byte, error) {
	files, err := filepath.Glob(filepath.Join(casesDir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no case files under %s", casesDir)
	}
	protos := map[string][]exam{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var cases []caseFile
		if err := json.Unmarshal(raw, &cases); err != nil {
			continue // 非用例数组文件（如元数据）跳过
		}
		for _, c := range cases {
			if c.Expect.ExpectError || len(c.SpecJSON) == 0 || len(c.SpecJSON) > 6<<10 {
				continue
			}
			pk := c.Expect.PacketCount
			if c.Expect.MinPackets > pk {
				// packet_count 与 min_packets 两断言口径取大者：min_packets 例
				// （如 openvpn 握手交换）此前落 0 丢事务档。
				pk = c.Expect.MinPackets
			}
			protos[c.Proto] = append(protos[c.Proto], exam{
				Protocol: c.Proto, CaseID: c.ID, Summary: c.Summary,
				Config: c.SpecJSON, FlowControl: flowNote(c.SpecJSON),
				Packets: pk,
			})
		}
	}
	out := map[string][]exam{}
	for proto, exs := range protos {
		// 排序：事务例档优先，同档内 complexity 升序。simplest 规则只在
		// 同档内生效——含响应语义的例永远排在纯请求例之前。
		sort.Slice(exs, func(i, j int) bool {
			if ti, tj := txTier(exs[i]), txTier(exs[j]); ti != tj {
				return ti
			}
			si, _ := complexity(exs[i].Config)
			sj, _ := complexity(exs[j].Config)
			return si < sj
		})
		// 每协议 ≤4 条，贪心补充多样性：每轮挑"相对已收录集合带来最多
		// 新协议层键"的用例，直到无新键或达上限。仅挑 simplest 会把
		// headers/body/transactions 等常用定制字段全部隐藏——LLM 写非
		// 默认配置被迫再查 schema（用户实测反馈）。多流例若带新键自然
		// 入选，flow_control 注记在收录时统一附加。
		var picked []exam
		seen := map[string]bool{}
		pick := func(e exam) {
			if seen[e.CaseID] {
				return
			}
			seen[e.CaseID] = true
			e.FlowControl = flowNote(e.Config)
			picked = append(picked, e)
		}
		protoKeys := func(cfg json.RawMessage) map[string]bool {
			keys := map[string]bool{}
			var m struct {
				Layers []map[string]json.RawMessage `json:"layers"`
			}
			if json.Unmarshal(cfg, &m) != nil {
				return keys
			}
			// 协议层 = 最内层（层链有序，外层为 ip/tcp 等脚手架）；
			// 多样性比较的是层内字段键，不是层名。
			if len(m.Layers) > 0 {
				var inner map[string]json.RawMessage
				for _, v := range m.Layers[len(m.Layers)-1] {
					if json.Unmarshal(v, &inner) == nil {
						for k := range inner {
							keys[k] = true
						}
					}
				}
			}
			return keys
		}
		covered := map[string]bool{}
		if len(exs) > 0 {
			pick(exs[0]) // simplest 的多流注记由 pick 统一附加
			for k := range protoKeys(exs[0].Config) {
				covered[k] = true
			}
		}
		// P1-②：示例集必须含至少一个多流正例——能通过 sweep 的多流例必然
		// 已把变化字段写成动态 strategy 对象（静态四元组 + flows>1 会被
		// 引擎拒绝），LLM 照抄它改 N 即可，不必从单流静态示例试错。
		hasMulti := false
		for _, e := range picked {
			if multiFlowValue(e.Config) > 1 {
				hasMulti = true
				break
			}
		}
		if !hasMulti {
			for _, e := range exs {
				if seen[e.CaseID] {
					continue
				}
				if multiFlowValue(e.Config) > 1 {
					pick(e)
					for k := range protoKeys(e.Config) {
						covered[k] = true
					}
					break
				}
			}
		}
		for len(picked) < 5 {
			best, bestNew := -1, 0
			for i, e := range exs[1:] {
				if seen[e.CaseID] {
					continue
				}
				newKeys := 0
				for k := range protoKeys(e.Config) {
					if !covered[k] {
						newKeys++
					}
				}
				if newKeys > bestNew {
					best, bestNew = i, newKeys
				}
			}
			if best < 0 {
				break
			}
			e := exs[1+best]
			pick(e)
			for k := range protoKeys(e.Config) {
				covered[k] = true
			}
		}
		out[proto] = picked
	}
	names := make([]string, 0, len(out))
	for k := range out {
		names = append(names, k)
	}
	sort.Strings(names)
	env := envelope{Generated: len(out), Protocols: out}
	b, err := json.MarshalIndent(env, "", " ")
	if err != nil {
		return nil, err
	}
	_ = names
	return b, nil
}

func main() {
	cases := flag.String("cases", "test/protocol_pcap/cases", "cases directory")
	out := flag.String("out", "internal/mcp/layer_examples.json", "output JSON path")
	flag.Parse()
	b, err := Generate(*cases)
	if err != nil {
		fmt.Fprintln(os.Stderr, "examplegen:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "examplegen write:", err)
		os.Exit(1)
	}
	var probe struct {
		Generated int `json:"generated"`
	}
	json.Unmarshal(b, &probe)
	fmt.Printf("examplegen: wrote %s (%d protocols)\n", *out, probe.Generated)
}
