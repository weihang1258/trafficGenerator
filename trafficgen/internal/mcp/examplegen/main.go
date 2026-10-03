// Command examplegen derives per-protocol LLM examples from the verified
// cases corpus (test/protocol_pcap/cases/*.json) into an embeddable JSON.
//
// 选择规则（每协议 ≤5 条，贪心字段多样性）：
//  1. simplest：层最少、字段键总数最少的正例（expect_error=false）——
//     LLM 拿来即用的最小可跑配置；
//  2. 逐轮挑"相对已收录带来最多新协议层键"的用例（多流例带新键自然
//     入选），直到无新键或达上限（≤5）——headers/body/transactions 等常用
//     定制字段必须在示例里可见（LLM 实测反馈，详见 main_test）。
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
)

type caseFile struct {
	ID       string          `json:"id"`
	Proto    string          `json:"proto"`
	Summary  string          `json:"summary"`
	SpecJSON json.RawMessage `json:"spec_json"`
	Expect   struct {
		ExpectError bool `json:"expect_error"`
	} `json:"expect"`
}

type example struct {
	Protocol    string          `json:"protocol"`
	CaseID      string          `json:"case_id"`
	Summary     string          `json:"summary"`
	Config      json.RawMessage `json:"config"`
	FlowControl string          `json:"flow_control_note,omitempty"`
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
	var m struct {
		FlowControl *struct {
			Type  string `json:"type"`
			Value int    `json:"value"`
		} `json:"flow_control"`
	}
	json.Unmarshal(spec, &m)
	if m.FlowControl != nil && m.FlowControl.Value > 1 {
		return fmt.Sprintf("%s=%d（%d 条流并发）", m.FlowControl.Type, m.FlowControl.Value, m.FlowControl.Value)
	}
	return ""
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
			protos[c.Proto] = append(protos[c.Proto], exam{
				Protocol: c.Proto, CaseID: c.ID, Summary: c.Summary,
				Config: c.SpecJSON, FlowControl: flowNote(c.SpecJSON),
			})
		}
	}
	out := map[string][]exam{}
	for proto, exs := range protos {
		sort.Slice(exs, func(i, j int) bool {
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
