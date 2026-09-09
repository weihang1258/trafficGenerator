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
// (tools_schema_test.go): src_port/dst_port, src_ip/dst_ip defaults,
// 02:00:00:00:00:01 MAC, 0x08/DF/0x20/tcpdump, layers/depends_on/flowb_query_layers,
// group_id strategies, tcp mss/initial_seq, http sub-map keys.
func configBlurb() string {
	lines := []string{
		"// schemaConfigBlurb is the Config-field help shared by strategy and",
		"// workflow tools. Assembled from schema docs; every hint below is",
		"// asserted by internal/mcp/tools_schema_test.go — do not trim.",
		"const schemaConfigBlurb = \"strategy config. \" +",
		"\t\"Two formats: (1) layer-chain: {\\\"layers\\\":[{\\\"ip\\\":{}},{\\\"tcp\\\":{}},{\\\"http\\\":{}}]} — \" +",
		"\t\"ordered layers outermost (L2) first; presence switches to layer-chain validation; \" +",
		"\t\"only schema-declared fields (flowb_query_layers lists fields/defaults/depends_on, \" +",
		"\t\"unknown rejected; hard depends_on auto-completed; protocol inferred from outermost \" +",
		"\t\"non-scaffolding layer, explicit protocol must match. \" +",
		"\t\"(2) flat: src_ip=10.0.0.1, dst_ip=20.0.0.1, src_port=12345, dst_port=80 (DNS 53), \" +",
		"\t\"src_mac=02:00:00:00:00:01, dst_mac=02:00:00:00:00:02, ttl=64, dscp=0x08 (CS1, TOS 0x20), \" +",
		"\t\"ip_flags=DF=1; explicit 0/empty honored. \" +",
		"\t\"http sub-map {method,uri,version,request_headers,body,body_b64,keep_alive,transactions,\" +",
		"\t\"think_time,response_*}; tcp sub-map {mss,initial_seq,handshake,termination,window_size} \" +",
		"\t\"(mss default 1460, min 536; initial_seq pins client ISN). \" +",
		"\t\"group_id {strategy,value/range/list/step/seed/pattern}: fixed/inc/rand/pattern/list \" +",
		"\t\"bind same-id flows to one worker. tcpdump: ip[1] & 0xfc == 0x20.\"",
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
