// Package testutil provides shared test helpers for protocol test packages.
// Test helpers that are identical across http/ftp/sip/dns test suites live
// here to avoid duplication.
package testutil

import (
	"github.com/trafficgen/trafficgen/internal/core"
)

// EnsureTCP returns spec.TCP, allocating it if nil. The caller must reassign
// the returned pointer to spec.TCP if they want the allocation to persist.
// Used by HTTP/FTP/SIP test packages that need to set TCP fields on a
// FlowSpec whose valid*Spec() helper did not initialize TCP.
func EnsureTCP(spec *core.FlowSpec) *core.TCPConfig {
	if spec.TCP == nil {
		spec.TCP = &core.TCPConfig{}
	}
	return spec.TCP
}
