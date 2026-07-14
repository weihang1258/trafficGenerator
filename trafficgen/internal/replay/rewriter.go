package replay

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/pcapparser"
)

// ApplyPatches copies the raw frame, applies each patch at its offset, and
// recomputes checksums as needed (replay design §5/§11).
//
// Checksum rules (§11):
//   - checksumMode="preserve" + no touched L3/L4 fields -> keep original
//     checksums (preserves bad-checksum anomalies).
//   - checksumMode="preserve" + touched L3/L4 -> force recompute (a patched
//     field with a stale checksum is a contradictory packet, not the intended
//     "bad checksum" anomaly).
//   - checksumMode="recompute" (default) -> always recompute (fixes TX-offload
//     bad checksums, produces valid packets).
//   - L2 patches (MAC) never trigger checksum recompute.
func ApplyPatches(raw []byte, patches []Patch, layout pcapparser.OffsetLayout, checksumMode string) ([]byte, error) {
	out := make([]byte, len(raw))
	copy(out, raw)

	touchedL3, touchedL4 := false, false
	for _, p := range patches {
		if p.Offset < 0 || p.Offset+len(p.Bytes) > len(out) {
			return nil, fmt.Errorf("patch %q out of bounds: offset %d len %d (frame %d)", p.Field, p.Offset, len(p.Bytes), len(out))
		}
		copy(out[p.Offset:p.Offset+len(p.Bytes)], p.Bytes)
		switch p.Layer {
		case "l3":
			touchedL3 = true
		case "l4":
			touchedL4 = true
		}
	}

	// Decide whether to recompute. The logic mirrors recomputeChecksums (§11):
	// recompute when mode=recompute, OR any L3/L4 field was patched (regardless
	// of mode, since a patched field with a stale checksum is contradictory).
	if checksumMode == "recompute" || touchedL3 || touchedL4 {
		if touchedL3 || checksumMode == "recompute" {
			setIPChecksum(out, layout)
		}
		if touchedL3 || touchedL4 || checksumMode == "recompute" {
			setL4Checksum(out, layout)
		}
	}
	return out, nil
}
