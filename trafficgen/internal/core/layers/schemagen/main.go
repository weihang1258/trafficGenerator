// Command schemagen dumps the layer registry (layers.DefaultRegistry) to
// schemas/v1/generated/layers.generated.json.
//
// Source of truth: internal/core/layers/registry.go Register calls.
// Output: schemas/v1/generated/layers.generated.json (committed; CI fails
// when stale: regenerate + git diff --exit-code).
// Run: go run ./internal/core/layers/schemagen (from trafficgen/).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type fieldJSON struct {
	Type       string      `json:"type"`
	Default    interface{} `json:"default,omitempty"`
	Min        int64       `json:"min,omitempty"`
	Max        int64       `json:"max,omitempty"`
	Required   bool        `json:"required,omitempty"`
	Deprecated bool        `json:"deprecated,omitempty"`
}

type layerJSON struct {
	Category      string               `json:"category"`
	DependsOn     []string             `json:"depends_on,omitempty"`
	TransportOn   []string             `json:"transport_on,omitempty"`
	OptionalOn    []string             `json:"optional_on,omitempty"`
	InnerRequired []string             `json:"inner_required,omitempty"`
	FieldContract map[string]string    `json:"field_contract,omitempty"`
	Constraints   []string             `json:"constraints,omitempty"`
	Fields        map[string]fieldJSON `json:"fields"`
}

type generatedFile struct {
	Generator string               `json:"$generator"`
	Layers    map[string]layerJSON `json:"layers"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "layers-schemagen:", err)
		os.Exit(1)
	}
}

func run() error {
	reg := layers.DefaultRegistry()
	out := generatedFile{
		Generator: "internal/core/layers/schemagen (source: layers.DefaultRegistry)",
		Layers:    make(map[string]layerJSON, len(reg.List())),
	}
	for _, name := range reg.List() {
		s, ok := reg.Get(name)
		if !ok {
			continue
		}
		lj := layerJSON{
			Category:      s.Category.String(),
			DependsOn:     append([]string(nil), s.DependsOn...),
			TransportOn:   append([]string(nil), s.TransportOn...),
			OptionalOn:    append([]string(nil), s.OptionalOn...),
			InnerRequired: append([]string(nil), s.InnerRequired...),
			Fields:        make(map[string]fieldJSON, len(s.Fields)),
		}
		if len(s.FieldContract) > 0 {
			lj.FieldContract = s.FieldContract
		}
		for _, c := range s.Constraints {
			lj.Constraints = append(lj.Constraints, string(c))
		}
		for fname, f := range s.Fields {
			lj.Fields[fname] = fieldJSON{
				Type: f.Type, Default: f.Default,
				Min: f.Min, Max: f.Max,
				Required: f.Required, Deprecated: f.Deprecated,
			}
		}
		out.Layers[name] = lj
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	names := reg.List()
	sort.Strings(names)
	outPath := "schemas/v1/generated/layers.generated.json"
	if err := os.MkdirAll("schemas/v1/generated", 0755); err != nil {
		return err
	}
	if err := os.WriteFile(outPath, raw, 0644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d layers)\n", outPath, len(names))
	return nil
}
