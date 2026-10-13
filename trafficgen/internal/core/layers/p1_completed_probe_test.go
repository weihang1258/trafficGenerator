package layers_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// P1 探针：completedConfig → Parse* 的组合是否丢 file_source。
func TestP1CompletedConfigProbe(t *testing.T) {
	var user map[string]interface{}
	raw := []byte(`{"data":[{"direction":"up","file_source":{"file_id":"abc"}}]}`)
	if err := json.Unmarshal(raw, &user); err != nil {
		t.Fatal(err)
	}
	cfg := core.ParseRTMPConfigFromMap(user)
	if cfg == nil || len(cfg.Data) == 0 {
		t.Fatal("parse 丢 data")
	}
	fmt.Println("rtmp parse(user) FileSource:", cfg.Data[0].FileSource != nil)

	// xmpp 同
	var xu map[string]interface{}
	xraw := []byte(`{"messages":[{"direction":"up","file_source":{"file_id":"abc"}}]}`)
	json.Unmarshal(xraw, &xu)
	xc := core.ParseXmppConfigFromMap(xu)
	if xc == nil || len(xc.Messages) == 0 {
		t.Fatal("parse 丢 messages")
	}
	fmt.Println("xmpp parse(user) FileSource:", xc.Messages[0].FileSource != nil)
}
