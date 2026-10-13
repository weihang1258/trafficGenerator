package layers

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestP1TranslateProbe(t *testing.T) {
	r := DefaultRegistry()
	schema, ok := r.Get("rtmp")
	if !ok {
		t.Fatal("rtmp schema missing")
	}
	var user map[string]interface{}
	raw := []byte(`{"data":[{"direction":"up","file_source":{"file_id":"abc"}}]}`)
	if err := json.Unmarshal(raw, &user); err != nil {
		t.Fatal(err)
	}
	cc := completedConfig(schema, user)
	b, _ := json.Marshal(cc)
	fmt.Println("completedConfig:", string(b))
	cfg := core.ParseRTMPConfigFromMap(cc)
	if cfg == nil {
		t.Fatal("cfg nil")
	}
	fmt.Println("Data len:", len(cfg.Data))
	if len(cfg.Data) > 0 {
		fmt.Println("FileSource:", cfg.Data[0].FileSource != nil)
	}
}
