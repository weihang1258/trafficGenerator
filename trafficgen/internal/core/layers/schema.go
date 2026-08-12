// Package layers implements the layer-chain (层链) configuration model from
// docs/protocol-designs/18-layer-config-design.md (方案 C 分层配置架构).
//
// 核心概念（通俗表达）：
//   - 层（layer）：协议栈中的一级，如 ip、tcp、http
//   - 层链（layer chain）：一条有序的层列表，从外（二层）到内（应用层）
//   - schema（说明书）：每层声明的字段 + 默认值 + 依赖，系统据它补全和生成
//   - 硬依赖（depends_on）：这层下面缺什么就自动补什么（默认启用）
//   - 可选底座（optional_on）：这层可以垫在什么上面，但系统永不自动补，只有用户亲手写才生效
//
// 本文档实现 §3/§4/§5/§7（层注册表、层类型、自动补全算法、校验规则）。
package layers

import "fmt"

// LayerCategory is the role of a layer in the chain (层类型，§5.1).
type LayerCategory int

const (
	// CategoryTerminal: 终结层（最里面那层，应用层）。一个包只能有一个；层链末层必须是终结层。
	CategoryTerminal LayerCategory = iota
	// CategoryTunnel: 隧道层（必须包别人）。不能当末层；内层起点由 InnerRequired 声明。
	CategoryTunnel
	// CategoryTransport: 传输层（只能垫底不能结尾）。不能当末层；一个包只能有一个传输层。
	CategoryTransport
	// CategoryL2: 二层层（物理帧头）。自动补全的终点；只能出现在链最外。
	CategoryL2
	// CategoryNetwork: 网络层（ip）。可以出现在链的任意位置（gre 内外两层 ip），
	// 不受"最外"限制；每个 ip 层是独立实例（§5.3 同层多实例）。
	CategoryNetwork
)

func (c LayerCategory) String() string {
	switch c {
	case CategoryTerminal:
		return "terminal"
	case CategoryTunnel:
		return "tunnel"
	case CategoryTransport:
		return "transport"
	case CategoryL2:
		return "l2"
	case CategoryNetwork:
		return "network"
	}
	return "unknown"
}

// FieldSchema describes one configurable field of a layer (字段说明书)。
type FieldSchema struct {
	// Type is a human-readable type name ("string", "int", "uint16", "bool",
	// "ip", "mac", "list", ...). Used by the P2 parser for conversion and by
	// validation for range checks.
	Type string
	// Default is the schema default value (说明书默认值). 手动配置值 > 默认值 (§8)。
	Default interface{}
	// Min/Max bound numeric ranges (inclusive). 0/0 = no bound.
	Min, Max int64
	// Required marks a field that MUST be present after completion (no default).
	Required bool
	// Deprecated marks a legacy key read for backward compat.
	Deprecated bool
}

// Constraint is a layer-chain-level validation rule (校验规则，§10.2).
type Constraint string

const (
	// ConstraintTerminalUnique: 终结层全链唯一（V2）。
	ConstraintTerminalUnique Constraint = "terminal_unique"
	// ConstraintTransportUnique: 传输层全链唯一（V3）。
	ConstraintTransportUnique Constraint = "transport_unique"
)

// LayerSchema is the per-protocol 说明书 (§4.1)。
type LayerSchema struct {
	// Name is the layer name ("ip", "tcp", "http", ...) — the key used in a
	// layer chain.
	Name string
	// Category is the layer role (终结/隧道/传输/二层).
	Category LayerCategory
	// DependsOn lists hard dependencies (硬依赖): layers that MUST appear
	// outward of this layer; missing ones are auto-inserted during
	// completion (§7.1). If the dependency is a transport layer (tcp/udp),
	// TransportOn (if set) overrides it — see TransportOn.
	DependsOn []string
	// TransportOn lists the transport layers this layer can sit on; the
	// first entry is the default (from DependsOn). If the user explicitly
	// writes a transport layer that is in TransportOn, completion uses it
	// INSTEAD of the default, so no duplicate transport is inserted
	// (§4.4 note: {"dns":{}, "tcp":{}} → [ip → tcp → dns]).
	TransportOn []string
	// OptionalOn lists optional bases (可选底座): layers this layer MAY sit
	// on, but the system NEVER auto-inserts them — only the user's explicit
	// write enables them (§7.1, e.g. http optional_on [tls]).
	OptionalOn []string
	// InnerRequired lists the required innermost-start layers for a tunnel
	// layer; when the direct inner neighbor is not one of these, the first
	// required layer is auto-inserted (§7.3 second pass).
	InnerRequired []string
	// Fields is the field 说明书 keyed by config key.
	Fields map[string]FieldSchema
	// Constraints carries chain-level rules beyond the implicit category
	// rules (terminal unique, transport unique, tunnel-not-terminal, ...).
	Constraints []Constraint
}

// Layer is one entry in a layer chain: the layer name plus its config values.
type Layer struct {
	// Name is the layer name ("ip", "tcp", "http", ...).
	Name string
	// Config is the user-supplied config for this layer (层内字段配置)。
	// nil = no config given (全默认)。
	Config map[string]interface{}
}

// Registry is the layer registry (层注册表)：the collection of all 说明书s.
type Registry struct {
	schemas map[string]LayerSchema
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{schemas: make(map[string]LayerSchema)}
}

// Register adds a schema to the registry. Duplicate layer names are an error.
func (r *Registry) Register(s LayerSchema) error {
	if s.Name == "" {
		return fmt.Errorf("layers: schema with empty name")
	}
	if _, exists := r.schemas[s.Name]; exists {
		return fmt.Errorf("layers: layer already registered: %s", s.Name)
	}
	r.schemas[s.Name] = s
	return nil
}

// Get returns the schema for a layer name.
func (r *Registry) Get(name string) (LayerSchema, bool) {
	s, ok := r.schemas[name]
	return s, ok
}

// Has reports whether the registry knows a layer name.
func (r *Registry) Has(name string) bool {
	_, ok := r.schemas[name]
	return ok
}

// List returns all registered layer names.
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.schemas))
	for n := range r.schemas {
		names = append(names, n)
	}
	return names
}
