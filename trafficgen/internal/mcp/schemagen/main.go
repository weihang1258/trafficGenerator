// Command schemagen generates MCP description constants from schemas/v1.
// Source of truth: trafficgen/schemas/v1/*.json title/description fields.
// Output: internal/mcp/schema_descriptions_generated.go (package mcp).
// Run: go run ./internal/mcp/schemagen (from trafficgen/).
// CI fails if the generated file is stale (regenerate + git diff --exit-code).
package main

import (
	"fmt"
	"go/format"
	"os"
	"sort"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core/schema"
)

var files = []struct {
	file   string
	const_ string
}{
	{"v1/strategy.json", "strategy"},
	{"v1/task.json", "task"},
	{"v1/batch.json", "batch"},
	{"v1/defs.json", "defs"},
	{"v1/layers.json", "layers"},
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "schemagen:", err)
		os.Exit(1)
	}
}

func run() error {
	var b strings.Builder
	b.WriteString("// Code generated from trafficgen/schemas/v1 by internal/mcp/schemagen. DO NOT EDIT.\n")
	b.WriteString("// Descriptions below come from schema title/description fields (single truth).\n")
	b.WriteString("package mcp\n\n")
	for _, f := range files {
		entries, err := schema.Descriptions(f.file)
		if err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
		b.WriteString("// schema " + f.file + " flattened title/description table.\n")
		b.WriteString("var schemaDocs" + title(f.const_) + " = map[string]string{\n")
		for _, e := range entries {
			text := e.Title
			if e.Description != "" {
				text += ": " + e.Description
			}
			b.WriteString("\t" + quote(e.Path) + ": " + quote(text) + ",\n")
		}
		b.WriteString("}\n\n")
	}
	// Curated Config-field blurb: every hint is asserted by tools_schema_test.go.
	// Wording changes require updating the schema descriptions they summarize.
	b.WriteString(configBlurb())
	out := "internal/mcp/schema_descriptions_generated.go"
	if err := os.WriteFile(out, []byte(b.String()), 0644); err != nil {
		return err
	}
	if err := gofmtFile(out); err != nil {
		return err
	}
	fmt.Println("wrote", out)
	return nil
}

// configBlurb emits the shared Config-field help text assembled from schema
// docs. It preserves every substring the MCP schema tests assert
// (tools_schema_test.go). Layer-chain is the ONLY accepted format: the engine
// rejects top-level flat fields (core.CheckProtoFlat) and top-level protocol
// sub-configs, so advertising them here made LLM first calls fail by
// construction (user-tested feedback). Defaults live in the per-layer schema
// view (flowb_query_layers), not in this blurb.
func configBlurb() string {
	lines := []string{
		"// schemaConfigBlurb is the Config-field help shared by strategy and",
		"// workflow tools. Assembled from schema docs; every hint below is",
		"// asserted by internal/mcp/tools_schema_test.go — do not trim.",
		"const schemaConfigBlurb = \"strategy config. \" +",
		"\t\"layer-chain is the only accepted format (flat config is gone): {\\\"layers\\\":[{\\\"ip\\\":{\\\"src\\\":\\\"10.0.0.1\\\",\\\"dst\\\":\\\"20.0.0.1\\\"}},\" +",
		"\t\"{\\\"udp\\\":{\\\"dst_port\\\":53}},{\\\"dns\\\":{\\\"name\\\":\\\"a.com\\\"}}],\\\"flow_control\\\":{\\\"type\\\":\\\"flows\\\",\\\"value\\\":1}} — \" +",
		"\t\"EACH layers element must hold EXACTLY ONE layer key (merging layers into one element, e.g. \" +",
		"\t\"{\\\"layers\\\":[{\\\"ip\\\":{...},\\\"tcp\\\":{...}}]}, is rejected with 'each layer entry must contain exactly one layer name') — \" +",
		"\t\"ordered layers, outermost (L2/L3) first; protocol inferred from outermost non-scaffolding layer, \" +",
		"\t\"explicit protocol must match. \" +",
		"\t\"Only schema-declared fields accepted: unknown fields rejected (all reported at once), \" +",
		"\t\"hard depends_on auto-completed. \" +",
		"\t\"ALWAYS call flowb_query_layers action=examples for the target protocol BEFORE composing a config — \" +",
		"\t\"it returns verified copy-paste examples (field names like ip.src / http.response_status_code \" +",
		"\t\"come from there, do not guess); action=schema lists fields/types/defaults/depends_on. \" +",
		"\t\"Top-level src_ip/dst_ip/src_port/dst_port/count are rejected (flat config is gone). \" +",
		"\t\"group_id {strategy,value/range/list/step/seed/pattern}: fixed/inc/rand/pattern/list \" +",
		"\t\"bind same-id flows to one worker.\"",
		"",
	}
	return strings.Join(lines, "\n")
}

func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func quote(s string) string {
	return fmt.Sprintf("%q", s)
}

// gofmtFile formats the generated file so `gofmt -l` stays clean even as
// entry lengths change. The generator must stay self-formatting: CI checks
// both staleness (regenerate + git diff) and formatting.
func gofmtFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	formatted, err := format.Source(raw)
	if err != nil {
		return err
	}
	return os.WriteFile(path, formatted, 0644)
}
