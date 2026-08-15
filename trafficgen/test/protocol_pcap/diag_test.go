package protocolpcap

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// 临时诊断：MCP port_group 任务到底发了多少包。
func TestDiagPortGroup(t *testing.T) {
	ctx := context.Background()
	r, err := NewRunner(ctx, envEndpoint, envAPIKey, "/tmp/diag-pcaps")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer r.Close()
	spec := `{"layers":[{"tcp":{}}],"src_ip":"10.0.0.1","dst_ip":"20.0.0.1","src_port":12345,"dst_port":80,"count":1}`
	args := map[string]any{
		"task_name":   "diag-portgroup",
		"protocol":    "tcp",
		"config":      json.RawMessage(spec),
		"output_type": "port_group",
		"output_config": map[string]any{
			"port_group_id": nicPGID,
		},
	}
	raw, err := r.Client.CallTool(ctx, "flowb_generate_traffic", args)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	fmt.Println("DIAG generate:", string(raw))
	var gres generateResult
	if err := json.Unmarshal(raw, &gres); err != nil {
		t.Fatalf("parse: %v", err)
	}
	time.Sleep(2 * time.Second)
	raw, err = r.Client.CallTool(ctx, "flowb_get_task_progress", map[string]any{"task_id": gres.TaskID})
	if err != nil {
		t.Fatalf("progress: %v", err)
	}
	fmt.Println("DIAG progress RAW:", string(raw))
	var rawProgress struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &rawProgress); err != nil {
		t.Fatalf("parse progress: %v", err)
	}
	var pres progressResult
	if err := json.Unmarshal(rawProgress.Data, &pres); err != nil {
		t.Fatalf("parse data: %v", err)
	}
	fmt.Printf("DIAG status=%s packets_sent=%d bytes=%d err=%s\n", pres.Status, pres.PacketsSent, pres.BytesSent, pres.ErrorMessage)
}
