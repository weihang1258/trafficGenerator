package fins

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestFINSGeneratorAcceptsMetadataMap(t *testing.T) {
	var events int
	err := (&FINSGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{FINS: map[string]interface{}{
			"transport": "udp",
			"commands": []interface{}{map[string]interface{}{
				"command":     float64(CommandMemoryAreaRead),
				"memory_area": "dm",
				"items":       float64(1),
			}},
		}},
		EmitMsg: func(layers.MessageEvent) error { events++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if events != 2 {
		t.Fatalf("events = %d, want request and response", events)
	}
}
