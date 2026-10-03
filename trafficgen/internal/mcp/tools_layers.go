package mcp

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/trafficgen/trafficgen/internal/core/layers"
)

//go:embed layer_examples.json
var layerExamplesJSON []byte

// layerFieldView is the JSON-safe view of one schema field (说明书字段)。
type layerFieldView struct {
	Type       string      `json:"type"`
	Default    interface{} `json:"default,omitempty"`
	Min        int64       `json:"min,omitempty"`
	Max        int64       `json:"max,omitempty"`
	Required   bool        `json:"required,omitempty"`
	Deprecated bool        `json:"deprecated,omitempty"`
}

// layerSchemaView is the JSON-safe view of one layer 说明书, built from
// layers.LayerSchema. It exists because LayerSchema carries Go-typed defaults
// (uint8/uint16/uint32) that encode as raw numbers: json.Marshal on the Go
// structs emits the unquoted number forms ("1460", "1") that LLMs reliably
// parse, while numbers would be ambiguous between ports and enums.
type layerSchemaView struct {
	Name        string                    `json:"name"`
	Category    string                    `json:"category"`
	DependsOn   []string                  `json:"depends_on,omitempty"`
	TransportOn []string                  `json:"transport_on,omitempty"`
	OptionalOn  []string                  `json:"optional_on,omitempty"`
	Constraints []string                  `json:"constraints,omitempty"`
	Fields      map[string]layerFieldView `json:"fields"`
	Inner       []layerSchemaView         `json:"inner,omitempty"` // CategoryTunnel only
}

// buildLayerSchemaView converts a registered LayerSchema into the JSON-safe
// view. The default is copied out of the registry so callers can't mutate it.
func buildLayerSchemaView(s layers.LayerSchema) layerSchemaView {
	v := layerSchemaView{
		Name:        s.Name,
		Category:    s.Category.String(),
		DependsOn:   append([]string(nil), s.DependsOn...),
		TransportOn: append([]string(nil), s.TransportOn...),
		OptionalOn:  append([]string(nil), s.OptionalOn...),
		Fields:      make(map[string]layerFieldView, len(s.Fields)),
	}
	for _, c := range s.Constraints {
		v.Constraints = append(v.Constraints, string(c))
	}
	for k, f := range s.Fields {
		v.Fields[k] = layerFieldView{Type: f.Type, Default: f.Default, Min: f.Min, Max: f.Max, Required: f.Required, Deprecated: f.Deprecated}
	}
	return v
}

// withTunnelInner attaches the tunnel layer's InnerRequired layers as nested
// "inner" views, so LLM clients learn what a tunnel may carry without a
// second lookup. Layers not in the registry cannot appear (registry init
// panics on unknown InnerRequired references).
func withTunnelInner(reg *layers.Registry, s layers.LayerSchema, view layerSchemaView) layerSchemaView {
	if s.Category != layers.CategoryTunnel {
		return view
	}
	for _, inner := range s.InnerRequired {
		if is, ok := reg.Get(inner); ok {
			view.Inner = append(view.Inner, buildLayerSchemaView(is))
		}
	}
	return view
}

// buildLayerSchemaViews converts a full registry to sorted views, with tunnel
// inner-required layers attached as nested "inner" entries.
func buildLayerSchemaViews(reg *layers.Registry) []layerSchemaView {
	views := make([]layerSchemaView, 0, len(reg.List()))
	for _, name := range reg.List() {
		s, ok := reg.Get(name)
		if !ok {
			continue
		}
		views = append(views, withTunnelInner(reg, s, buildLayerSchemaView(s)))
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Name < views[j].Name })
	return views
}

type queryLayersInput struct {
	Action string `json:"action,omitempty" jsonschema:"operation: schema (default; layer registry) | examples (verified per-protocol configs an LLM can copy verbatim)"`
	Layer  string `json:"layer,omitempty" jsonschema:"schema action: layer name to look up (e.g. ip/tcp/http). Empty = list all registered layers."`
	Proto  string `json:"protocol,omitempty" jsonschema:"examples action: protocol name (e.g. modbus/http/dns). Empty = all protocols."`
}

type queryLayersOutput struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

// configEnvelopeDoc 顶层配置契约：LLM 只看字段表学不会的骨架知识——
// layers 有序链 + flow_control 信封 + 引用示例。
type configEnvelopeDoc struct {
	Format       string   `json:"format"`
	TopLevelKeys []string `json:"top_level_keys"`
	FlowControl  string   `json:"flow_control"`
	SeeAlso      string   `json:"see_also"`
}

func (s *Server) registerLayerTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name: "flowb_query_layers",
			Description: "Query the layer-chain layer registry + verified examples. " +
				"action=schema (default): list every layer with category, dependencies, and configurable fields with defaults; pass 'layer' for one layer's full field table. " +
				"action=examples: verified per-protocol layer-chain configs (from the tested case corpus) — pass 'protocol' (e.g. modbus) to get copy-paste-ready configs; ALWAYS fetch examples for the target protocol before composing a new task config. " +
				"Live view of the same registry dumped to schemas/v1/generated/layers.generated.json." + autoExportNote,
			OutputSchema: manageOutputSchema(),
		},
		s.handleQueryLayers,
	)
}

// queryLayersPayload 是 handler 的纯逻辑核（无 Server 依赖，单测直调）。
func queryLayersPayload(in queryLayersInput) (string, interface{}, error) {
	reg := layers.DefaultRegistry()
	switch in.Action {
	case "", "schema":
		var data interface{}
		if in.Layer == "" {
			data = buildLayerSchemaViews(reg)
		} else {
			schema, ok := reg.Get(in.Layer)
			if !ok {
				return "", nil, &jsonrpc.Error{
					Code:    jsonrpc.CodeInvalidParams,
					Message: fmt.Sprintf("unknown layer %q (see flowb_query_layers with no args for the full list)", in.Layer),
				}
			}
			data = withTunnelInner(reg, schema, buildLayerSchemaView(schema))
		}
		return "query_layers", data, nil
	case "examples":
		var env struct {
			Generated int                      `json:"generated"`
			Protocols map[string][]interface{} `json:"protocols"`
		}
		if err := json.Unmarshal(layerExamplesJSON, &env); err != nil {
			return "", nil, fmt.Errorf("embedded examples corrupt: %w", err)
		}
		envelope := configEnvelopeDoc{
			Format:       `{"layers":[{outermost}...{innermost}],"flow_control":{"type":"flows","value":N}}`,
			TopLevelKeys: []string{"layers", "flow_control"},
			FlowControl:  "flows=N 生成 N 条并发流（N>1 时包级交织，断言请用聚合视角）；省略 = 单流",
			SeeAlso:      "action=examples&protocol=<proto> 取该协议已验证配置；unknown field 会被严格拒绝",
		}
		if in.Proto != "" {
			exs, ok := env.Protocols[in.Proto]
			if !ok || len(exs) == 0 {
				return "", nil, &jsonrpc.Error{
					Code:    jsonrpc.CodeInvalidParams,
					Message: fmt.Sprintf("no verified examples for protocol %q (action=examples with no protocol lists all)", in.Proto),
				}
			}
			return "examples", map[string]interface{}{"envelope": envelope, "protocol": in.Proto, "examples": exs}, nil
		}
		return "examples", map[string]interface{}{"envelope": envelope, "generated": env.Generated, "protocols": env.Protocols}, nil
	default:
		return "", nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: fmt.Sprintf("invalid action %q (schema | examples)", in.Action),
		}
	}
}

func (s *Server) handleQueryLayers(ctx context.Context, req *mcp.CallToolRequest, in queryLayersInput) (*mcp.CallToolResult, queryLayersOutput, error) {
	start := time.Now()
	action, data, err := queryLayersPayload(in)
	if err != nil {
		s.auditLog(req, "flowb_query_layers", time.Since(start), "error", err.Error())
		return nil, queryLayersOutput{}, err
	}
	raw, err := json.Marshal(data)
	if err != nil {
		s.auditLog(req, "flowb_query_layers", time.Since(start), "error", err.Error())
		return nil, queryLayersOutput{}, err
	}
	s.auditLog(req, "flowb_query_layers", time.Since(start), "success", "")
	// rawData round-trips the marshaled view through interface{}: the SDK
	// marshals the output struct itself, and a json.RawMessage would be
	// re-encoded as base64. interface{} preserves the JSON payload.
	// schema/examples with no layer/protocol filter dump the whole
	// registry (~MB) — above the inline threshold the payload becomes a
	// server-managed export with a download link (user ruling 2026-10-03).
	return nil, queryLayersOutput{Action: action, Data: rawData(s.maybeExport("query_layers_"+action, raw))}, nil
}
