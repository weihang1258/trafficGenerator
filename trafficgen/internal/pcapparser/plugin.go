package pcapparser

import (
	"github.com/google/gopacket"
)

// ProtocolParser is the L7 protocol parser plugin interface (§14). A parser
// works on a raw byte stream -- for TCP, the reassembled L7 stream; for UDP,
// each packet's payload (an independent L7 message). It extracts protocol
// metadata + the body boundary (e.g. HTTP body after the headers).
type ProtocolParser interface {
	// Name returns the protocol name (http, dns, tls, ...).
	Name() string
	// CanParse reports whether this parser handles the given port (well-known
	// service port hint) and/or byte content. Used to select a parser when the
	// layer type isn't known (TCP reassembled streams have no gopacket layer).
	CanParse(port uint16, sample []byte) bool
	// Parse extracts L7 metadata + body boundary from a byte stream.
	Parse(stream []byte) (*L7Result, error)
}

// L7Result is the output of an L7 parser: protocol metadata for display/filter
// and the body boundary within the stream (for body extraction).
type L7Result struct {
	Protocol   string
	Metadata   map[string]any
	BodyOffset int
	BodyLength int
}

// Registry holds registered L7 parsers, tried in order for stream parsing.
type Registry struct {
	parsers []ProtocolParser
}

// NewRegistry creates a registry seeded with the built-in L7 parsers.
func NewRegistry() *Registry {
	r := &Registry{}
	r.Register(&httpParser{})
	r.Register(&dnsParser{})
	r.Register(&tlsParser{})
	r.Register(&mqttParser{})
	r.Register(&ftpParser{})
	return r
}

// Register adds a parser. Find iterates in registration order and the first
// CanParse match wins — earlier registrations take precedence (HTTP -> DNS ->
// TLS -> MQTT -> FTP); append order is load-bearing for port-less probes.
func (r *Registry) Register(p ProtocolParser) {
	r.parsers = append(r.parsers, p)
}

// Find returns the first parser that can handle the given port + sample bytes,
// or nil if none match.
func (r *Registry) Find(port uint16, sample []byte) ProtocolParser {
	for _, p := range r.parsers {
		if p.CanParse(port, sample) {
			return p
		}
	}
	return nil
}

// ParseStream selects a parser by port + sample and parses the stream. Returns
// nil if no parser matches (raw/unknown L7).
func (r *Registry) ParseStream(port uint16, stream []byte) *L7Result {
	p := r.Find(port, stream)
	if p == nil {
		return nil
	}
	res, err := p.Parse(stream)
	if err != nil || res == nil {
		return nil
	}
	return res
}

// Ensure gopacket import is used (for future layer-type-based detection).
var _ gopacket.LayerType
