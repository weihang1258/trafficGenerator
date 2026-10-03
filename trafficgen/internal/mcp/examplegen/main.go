// Command examplegen derives per-protocol LLM examples from the verified
// cases corpus (test/protocol_pcap/cases/*.json) into an embeddable JSON.
//
// 选择规则（每协议 ≤2 条）：
//  1. simplest：层最少、字段键总数最少的正例（expect_error=false）——
//     LLM 拿来即用的最小可跑配置；
//  2. flow_example：flow_control.flows > 1 的正例（多流语义展示），
//     与 simplest 不同条时才收录。
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
	Generated int                `json:"generated"`
	Protocols map[string][]exam  `json:"protocols"`
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
		var picked []exam
		if len(exs) > 0 {
			exs[0].FlowControl = flowNote(exs[0].Config) // simplest 的多流注记保留
			picked = append(picked, exs[0])
		}
		for _, e := range exs[1:] {
			if n := flowNote(e.Config); n != "" {
				picked = append(picked, e)
				break
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
