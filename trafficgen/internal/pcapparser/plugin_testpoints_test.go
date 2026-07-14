package pcapparser

// Test points for plugin.go, derived from tools/test_points/pcapparser.md
// (components PL1-PL4). REAL tests exercising Registry directly.

import (
	"testing"
)

// --- PL1: NewRegistry ---

func TestNewRegistry_DefaultParsers(t *testing.T) {
	r := NewRegistry()
	// HTTP on port 80.
	p := r.Find(80, nil)
	if p == nil || p.Name() != "http" {
		t.Errorf("Find(80) = %v, want http parser", p)
	}
	// DNS on port 53.
	p = r.Find(53, nil)
	if p == nil || p.Name() != "dns" {
		t.Errorf("Find(53) = %v, want dns parser", p)
	}
	// TLS on port 443.
	p = r.Find(443, nil)
	if p == nil || p.Name() != "tls" {
		t.Errorf("Find(443) = %v, want tls parser", p)
	}
}

// --- PL2: Register ---

func TestRegister_OneParser(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockParser{name: "custom", port: 9999})
	p := r.Find(9999, nil)
	if p == nil || p.Name() != "custom" {
		t.Errorf("Find(9999) = %v, want custom parser", p)
	}
}

// TestRegister_NilParserDefensive: registering a nil parser would cause
// Find to panic on CanParse. This is a gap; documented as defensive.

// --- PL3: Find ---

func TestFind_FirstMatch(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockParser{name: "first", port: 1234})
	r.Register(&mockParser{name: "second", port: 1234})
	p := r.Find(1234, nil)
	if p == nil || p.Name() != "first" {
		t.Errorf("Find(1234) = %v, want first (first registered wins)", p)
	}
}

func TestFind_NoMatch(t *testing.T) {
	r := NewRegistry()
	p := r.Find(30000, nil)
	if p != nil {
		t.Errorf("Find(30000) = %v, want nil", p)
	}
}

func TestFind_EmptyRegistry(t *testing.T) {
	r := &Registry{}
	p := r.Find(80, nil)
	if p != nil {
		t.Errorf("Find(80) on empty registry = %v, want nil", p)
	}
}

// --- PL4: ParseStream ---

func TestParseStream_NoParserFound(t *testing.T) {
	r := NewRegistry()
	res := r.ParseStream(30000, []byte("any"))
	if res != nil {
		t.Errorf("ParseStream(30000) = %+v, want nil", res)
	}
}

func TestParseStream_ParseSucceeds(t *testing.T) {
	r := NewRegistry()
	res := r.ParseStream(80, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if res == nil {
		t.Fatal("ParseStream(80, GET) = nil, want non-nil")
	}
	if res.Protocol != "http" {
		t.Errorf("Protocol = %q, want http", res.Protocol)
	}
}

func TestParseStream_ParseError(t *testing.T) {
	r := &Registry{}
	r.Register(&mockParser{name: "errParser", err: errParseFail})
	res := r.ParseStream(9999, []byte("test"))
	if res != nil {
		t.Errorf("ParseStream with erroring parser = %v, want nil", res)
	}
}

func TestParseStream_ParseNilResult(t *testing.T) {
	r := &Registry{}
	r.Register(&mockParser{name: "nilParser", nilResult: true})
	res := r.ParseStream(9999, []byte("test"))
	if res != nil {
		t.Errorf("ParseStream returning nil,nil = %v, want nil", res)
	}
}

// mockParser for testing Registry.
type mockParser struct {
	name      string
	port      uint16
	err       error
	nilResult bool
}

func (m *mockParser) Name() string { return m.name }

func (m *mockParser) CanParse(port uint16, sample []byte) bool {
	return m.port == port
}

func (m *mockParser) Parse(stream []byte) (*L7Result, error) {
	if m.nilResult {
		return nil, nil
	}
	if m.err != nil {
		return nil, m.err
	}
	return &L7Result{Protocol: m.name, Metadata: map[string]any{}}, nil
}

var errParseFail = &mockParseError{}

type mockParseError struct{}

func (e *mockParseError) Error() string { return "parse failed" }