package core

import "fmt"

// MaxUDPPayloadBytes is the RFC 5426 §6 per-message limit for syslog over
// UDP: 65535 (IP total length) − 20 (IPv4) − 8 (UDP). Single source shared
// by protocol/syslog (validator + generator guard) and core/layers (Plan-time
// pre-check) — layers may not import protocol packages, so the constant and
// its family-exact error text live here (复审发现 5：双份维护防漂移).
const MaxUDPPayloadBytes = 65507

// SyslogUDPLimitError returns the family-canonical over-limit error. The
// wording must stay byte-identical across both enforcement points (13.8).
func SyslogUDPLimitError() error {
	return fmt.Errorf("syslog: encoded message exceeds UDP payload limit %d (RFC 5426 §6)", MaxUDPPayloadBytes)
}
