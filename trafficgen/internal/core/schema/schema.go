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
	fileTask     = "v1/task.json"
	fileBatch    = "v1/batch.json"
)

var (
	loadOnce     sync.Once
	loadErr      error
	strategyRule *jsonschema.Resolved
	taskRule     *jsonschema.Resolved
	batchRule    *jsonschema.Resolved
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

// load resolves strategy/task/batch schemas with shared $defs inlined, so no
// cross-file loader is needed: each merged document resolves in-tree.
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
		if strategyRule, loadErr = resolveMerged(fileStrategy, "strategy.json"); loadErr != nil {
			return
		}
		if taskRule, loadErr = resolveMerged(fileTask, "task.json"); loadErr != nil {
			return
		}
		if batchRule, loadErr = resolveMerged(fileBatch, "batch.json"); loadErr != nil {
			return
		}
	})
	return loadErr
}

// resolveMerged inlines shared $defs into one schema file and resolves it.
func resolveMerged(file, label string) (*jsonschema.Resolved, error) {
	doc, err := mergedDoc(file)
	if err != nil {
		return nil, fmt.Errorf("schema: merge %s: %w", label, err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("schema: re-encode merged %s: %w", label, err)
	}
	raw = inlineRefs(raw)
	raw = inlineBatchRef(raw)
	var sch jsonschema.Schema
	if err := json.Unmarshal(raw, &sch); err != nil {
		return nil, fmt.Errorf("schema: parse %s: %w", label, err)
	}
	r, err := sch.Resolve(&jsonschema.ResolveOptions{})
	if err != nil {
		return nil, fmt.Errorf("schema: resolve %s: %w", label, err)
	}
	return r, nil
}

// inlineBatchRef rewrites the task->batch cross-file ref to the in-document
// batch subschema inlined under $defs by mergedDoc.
func inlineBatchRef(raw []byte) []byte {
	return []byte(strings.ReplaceAll(string(raw), `"batch.json"`, `"#/$defs/batch"`))
}

// inlineRefs rewrites cross-file "defs.json#/$defs/x" refs to in-document
// "#/$defs/x" after mergedStrategyDoc inlines the definitions.
func inlineRefs(raw []byte) []byte {
	return []byte(strings.ReplaceAll(string(raw), `"defs.json#/$defs/`, `"#/$defs/`))
}

// mergedStrategyDoc returns strategy.json with defs.json $defs inlined under
// $defs, so "defs.json#/$defs/x" refs resolve in-document via inlineRefs.
func mergedStrategyDoc() (map[string]any, error) {
	return mergedDoc(fileStrategy)
}

// mergedDoc inlines shared $defs into one schema file. For task.json it also
// inlines batch.json as the "batch" $def so the task->batch ref stays in-tree.
func mergedDoc(file string) (map[string]any, error) {
	raw, err := schemasFS.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	defs, ok := defsDoc["$defs"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema: defs.json has no $defs")
	}
	own, _ := doc["$defs"].(map[string]any)
	merged := make(map[string]any, len(defs)+len(own)+1)
	for k, v := range defs {
		merged[k] = v
	}
	for k, v := range own {
		merged[k] = v
	}
	if file == fileTask {
		batchRaw, err := schemasFS.ReadFile(fileBatch)
		if err != nil {
			return nil, err
		}
		var batchDoc map[string]any
		if err := json.Unmarshal(batchRaw, &batchDoc); err != nil {
			return nil, err
		}
		// Drop the subdocument's own $id/$schema: inlined refs must resolve
		// against the root document's $defs, not a nested base URI scope.
		delete(batchDoc, "$id")
		delete(batchDoc, "$schema")
		merged["batch"] = batchDoc
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

// ValidateTaskShape validates {"name","strategy_ids"|"batch","output_type",
// "output_config","flow_control"} against task.json (batch inlined).
func ValidateTaskShape(doc map[string]any) ValidationErrors {
	if err := load(); err != nil {
		return ValidationErrors{{Message: err.Error()}}
	}
	if err := taskRule.Validate(doc); err != nil {
		return splitError(err)
	}
	return nil
}

// ValidateBatchShape validates {"classes","global"} against batch.json.
func ValidateBatchShape(doc map[string]any) ValidationErrors {
	if err := load(); err != nil {
		return ValidationErrors{{Message: err.Error()}}
	}
	if err := batchRule.Validate(doc); err != nil {
		return splitError(err)
	}
	return nil
}

// DocEntry is one title+description pair from the schemas, keyed by JSON path.
type DocEntry struct {
	Path        string `json:"path"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// Descriptions returns the flattened title/description table for one schema
// file (strategy, task, batch, defs). Paths use JSON-pointer-ish segments
// (properties/<name>, $defs/<name>). MCP jsonschema tags, REST docs and the
// frontend derive their human text from here — never a second hand-written copy.
func Descriptions(file string) ([]DocEntry, error) {
	if err := load(); err != nil {
		return nil, err
	}
	raw, err := schemasFS.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("schema: read %s: %w", file, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("schema: parse %s: %w", file, err)
	}
	var out []DocEntry
	walkDocs("", doc, &out)
	return out, nil
}

// DescriptionMap returns path->"title: description" for one schema file.
func DescriptionMap(file string) (map[string]string, error) {
	entries, err := Descriptions(file)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		text := e.Title
		if e.Description != "" {
			text += ": " + e.Description
		}
		m[e.Path] = text
	}
	return m, nil
}

func walkDocs(path string, v any, out *[]DocEntry) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	if t, _ := m["title"].(string); t != "" {
		d, _ := m["description"].(string)
		*out = append(*out, DocEntry{Path: path, Title: t, Description: d})
	}
	for _, key := range []string{"properties", "$defs"} {
		if sub, ok := m[key].(map[string]any); ok {
			for name, val := range sub {
				walkDocs(path+"/"+key+"/"+name, val, out)
			}
		}
	}
	if items, ok := m["items"].(map[string]any); ok {
		walkDocs(path+"/items", items, out)
	}
}
