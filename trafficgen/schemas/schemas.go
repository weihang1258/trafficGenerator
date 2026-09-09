// Package schemas exposes the hand-maintained JSON Schemas in v1 (the
// machine-readable config contract per docs/CORE_MEMORY.md §13) to Go code.
// The JSON files are the single truth; this package only embeds them.
package schemas

import "embed"

// FS carries schemas/v1/*.json. Validators read via FS (never a copy).
//
//go:embed all:v1
var FS embed.FS
