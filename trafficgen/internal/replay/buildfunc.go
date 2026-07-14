package replay

import (
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/pcapparser"
)

// NewBuildFunc returns a build function that dispatches between synth and
// replay packets (§16.12). For packets with Metadata["_replay"]=true, it
// applies the byte-patches via ApplyPatches; otherwise it delegates to the base
// builder. The engine's SetBuildFunc is called with this wrapper.
func NewBuildFunc(base func(core.PacketConfig) ([]byte, error)) func(core.PacketConfig) ([]byte, error) {
	return func(config core.PacketConfig) ([]byte, error) {
		if isReplay, ok := config.Metadata["_replay"].(bool); ok && isReplay {
			raw, _ := config.Metadata["_raw"].([]byte)
			patches, _ := config.Metadata["_patches"].([]Patch)
			layout, _ := config.Metadata["_layout"].(pcapparser.OffsetLayout)
			mode, _ := config.Metadata["_checksum_mode"].(string)
			if mode == "" {
				mode = "recompute"
			}
			return ApplyPatches(raw, patches, layout, mode)
		}
		return base(config)
	}
}
