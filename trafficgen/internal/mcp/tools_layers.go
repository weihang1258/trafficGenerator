package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/trafficgen/trafficgen/internal/core/layers"
)

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
	Layer string `json:"layer,omitempty" jsonschema:"layer name to look up (e.g. ip/tcp/http). Empty = list all registered layers."`
}

type queryLayersOutput struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (s *Server) registerLayerTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:         "flowb_query_layers",
			Description:  "Query the layer-chain layer registry (层注册表): list every layer with its category, dependencies, and configurable fields with defaults. Live view of the same registry dumped to schemas/v1/generated/layers.generated.json (shape: schemas/v1/layers.json). Use this before creating or updating a strategy with a 'layers' config. Pass 'layer' to look up one layer's full field table; omit it to list all.",
			OutputSchema: manageOutputSchema(),
		},
		s.handleQueryLayers,
	)
}

func (s *Server) handleQueryLayers(ctx context.Context, req *mcp.CallToolRequest, in queryLayersInput) (*mcp.CallToolResult, queryLayersOutput, error) {
	start := time.Now()
	reg := layers.DefaultRegistry()

	var data interface{}
	if in.Layer == "" {
		data = buildLayerSchemaViews(reg)
	} else {
		schema, ok := reg.Get(in.Layer)
		if !ok {
			s.auditLog(req, "flowb_query_layers", time.Since(start), "error", "unknown layer")
			return nil, queryLayersOutput{}, &jsonrpc.Error{
				Code:    jsonrpc.CodeInvalidParams,
				Message: fmt.Sprintf("unknown layer %q (see flowb_query_layers with no args for the full list)", in.Layer),
			}
		}
		view := withTunnelInner(reg, schema, buildLayerSchemaView(schema))
		data = view
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
	return nil, queryLayersOutput{Action: "query_layers", Data: rawData(raw)}, nil
}
