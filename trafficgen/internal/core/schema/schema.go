// Package schema is the single Go validation entry for strategy/task/batch
// configs. It embeds the hand-maintained JSON Schemas in schemas/v1 (the
// machine-readable contract per docs/CORE_MEMORY.md §13) and validates shape;
// semantic checks that JSON Schema cannot express (protocol allowlist, layer
// inference, network formats, cross-field conflicts) run in the same entry so
// REST, MCP and tests share one order and one message set.
//
// Rule: schema rejects malformed shape; Go rejects semantically invalid
// content. Both run through this package — never hand-rolled in handlers.
package schema

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	tgschemas "github.com/trafficgen/trafficgen/schemas"
)

// schemasFS is the embedded schemas/v1 tree (single truth, CORE_MEMORY §13).
var schemasFS = tgschemas.FS

// schema files embedded from trafficgen/schemas/v1.
const (
	fileDefs     = "v1/defs.json"
	fileStrategy = "v1/strategy.json"
)

var (
	loadOnce     sync.Once
	loadErr      error
	strategyRule *jsonschema.Resolved
	defsDoc      map[string]any
)

// FieldError is one validation failure with a JSON-path location.
type FieldError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (e *FieldError) Error() string {
	if e.Path == "" {
		return e.Message
	}
	return e.Path + ": " + e.Message
}

// ValidationErrors is the ordered list of failures for one config.
type ValidationErrors []*FieldError

func (errs ValidationErrors) Error() string {
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		msgs = append(msgs, e.Error())
	}
	return strings.Join(msgs, "; ")
}

// load resolves strategy.json with defs.json $defs inlined, so no cross-file
// loader is needed: the single merged document resolves in-tree.
func load() error {
	loadOnce.Do(func() {
		defsRaw, err := schemasFS.ReadFile(fileDefs)
		if err != nil {
			loadErr = fmt.Errorf("schema: read defs.json: %w", err)
			return
		}
		if err := json.Unmarshal(defsRaw, &defsDoc); err != nil {
			loadErr = fmt.Errorf("schema: parse defs.json: %w", err)
			return
		}
		doc, err := mergedStrategyDoc()
		if err != nil {
			loadErr = fmt.Errorf("schema: merge strategy+defs: %w", err)
			return
		}
		raw, err := json.Marshal(doc)
		if err != nil {
			loadErr = fmt.Errorf("schema: re-encode merged strategy: %w", err)
			return
		}
		raw = inlineRefs(raw)
		var sch jsonschema.Schema
		if err := json.Unmarshal(raw, &sch); err != nil {
			loadErr = fmt.Errorf("schema: parse strategy.json: %w", err)
			return
		}
		strategyRule, loadErr = sch.Resolve(&jsonschema.ResolveOptions{})
		if loadErr != nil {
			loadErr = fmt.Errorf("schema: resolve strategy.json: %w", loadErr)
		}
	})
	return loadErr
}

// inlineRefs rewrites cross-file "defs.json#/$defs/x" refs to in-document
// "#/$defs/x" after mergedStrategyDoc inlines the definitions.
func inlineRefs(raw []byte) []byte {
	return []byte(strings.ReplaceAll(string(raw), `"defs.json#/$defs/`, `"#/$defs/`))
}

// mergedStrategyDoc returns strategy.json with defs.json $defs inlined under
// $defs, so "defs.json#/$defs/x" refs resolve in-document via inlineRefs.
func mergedStrategyDoc() (map[string]any, error) {
	stratRaw, err := schemasFS.ReadFile(fileStrategy)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(stratRaw, &doc); err != nil {
		return nil, err
	}
	defs, ok := defsDoc["$defs"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema: defs.json has no $defs")
	}
	own, _ := doc["$defs"].(map[string]any)
	merged := make(map[string]any, len(defs)+len(own))
	for k, v := range defs {
		merged[k] = v
	}
	for k, v := range own {
		merged[k] = v
	}
	doc["$defs"] = merged
	return doc, nil
}

// ValidateStrategyShape validates the shape of a strategy request document
// {"name","mode","protocol","config","flow_control"} against strategy.json.
// It returns nil when the shape is valid, else the ordered field errors.
// Semantic checks (protocol allowlist, layer inference, ranges, conflicts)
// are separate functions in semantic.go and run after this in ValidateStrategy.
func ValidateStrategyShape(doc map[string]any) ValidationErrors {
	if err := load(); err != nil {
		return ValidationErrors{{Message: err.Error()}}
	}
	if err := strategyRule.Validate(doc); err != nil {
		return splitError(err)
	}
	return nil
}

// splitError flattens a (possibly joined) schema error into field errors.
// jsonschema-go joins branch errors with newlines; keep each line as one
// entry so callers get stable, countable failures.
func splitError(err error) ValidationErrors {
	var out ValidationErrors
	for _, line := range strings.Split(err.Error(), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, &FieldError{Message: shortError(line)})
		}
	}
	if len(out) == 0 {
		out = append(out, &FieldError{Message: err.Error()})
	}
	return out
}

// shortError strips the "validating <schema-id>: validating <json-pointer>: ..."
// prefix chain down to the leaf message so callers and users see the cause
// (e.g. `pattern: "zz" does not match ...` instead of the full pointer path).
// Pointers vary with schema layout; the leaf message is the stable contract.
func shortError(msg string) string {
	markers := []string{"pattern: ", "maximum: ", "minimum: ", "enum: ", "required: ", "const: ", "minLength: ", "maxLength: ", "exclusiveMinimum: ", "not: ", "anyOf: ", "oneOf: ", "multipleOf: "}
	best := -1
	for _, m := range markers {
		if i := lastIndex(msg, m); i > best {
			best = i
		}
	}
	if best >= 0 {
		return msg[best:]
	}
	if i := lastIndex(msg, ": "); i >= 0 && i+2 < len(msg) {
		return msg[i+2:]
	}
	return msg
}

func lastIndex(s, sub string) int {
	for i := len(s) - len(sub); i >= 0; i-- {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
