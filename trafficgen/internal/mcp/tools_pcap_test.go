package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// writeTestPcap creates a small pcap file with one TCP packet for MCP tests.
func writeTestPcap(t *testing.T, path string) {
	t.Helper()
	macA, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	macB, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: 1, SYN: true, Window: 65535}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp.SetNetworkLayerForChecksum(ipv4)
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
		ipv4, tcp, gopacket.Payload([]byte("hello")))
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}
	if err := w.WritePacket(ci, buf.Bytes()); err != nil {
		t.Fatalf("write packet: %v", err)
	}
}

// importTestPcap imports a pcap via MCP and returns the asset ID.
func importTestPcap(t *testing.T, env *testMCPEnv) string {
	t.Helper()
	pcapPath := filepath.Join(env.tmp, "test.pcap")
	writeTestPcap(t, pcapPath)

	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action:   "import",
		FilePath: pcapPath,
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	var asset map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &asset); err != nil {
		t.Fatalf("import returned non-object: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	// PcapAssetModel has no JSON tags, so Go uses capitalized field names.
	id, ok := asset["ID"].(string)
	if !ok || id == "" {
		t.Fatalf("import did not return ID: %s", string(asRaw(out.Data)))
	}
	return id
}

func TestMCP_ManagePcaps_ImportAndList(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id := importTestPcap(t, env)

	// List should include the imported asset
	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "list",
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var listData struct {
		Items []map[string]interface{} `json:"items"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(asRaw(out.Data), &listData); err != nil {
		t.Fatalf("list returned non-object: %s (err: %v)", string(asRaw(out.Data)), err)
	}
	if listData.Total < 1 {
		t.Errorf("list.total: got %d, want >= 1", listData.Total)
	}
	found := false
	for _, item := range listData.Items {
		if item["ID"] == id {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("imported asset %s not in list", id)
	}
}

func TestMCP_ManagePcaps_Get(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id := importTestPcap(t, env)

	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "get",
		ID:     id,
	})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var asset map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &asset); err != nil {
		t.Fatalf("get returned non-object: %s", string(asRaw(out.Data)))
	}
	// PcapAssetModel has no JSON tags, so Go uses capitalized field names.
	if asset["ID"] != id {
		t.Errorf("get.id: got %v, want %s", asset["ID"], id)
	}
	if asset["Status"] != "ready" {
		t.Errorf("get.status: got %v, want ready", asset["Status"])
	}
}

func TestMCP_ManagePcaps_ListFlowsAndGetFlow(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id := importTestPcap(t, env)

	// List flows
	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "list_flows",
		ID:     id,
	})
	if err != nil {
		t.Fatalf("list_flows: %v", err)
	}
	var listData struct {
		Items []map[string]interface{} `json:"items"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(asRaw(out.Data), &listData); err != nil {
		t.Fatalf("list_flows returned non-object: %s", string(asRaw(out.Data)))
	}
	if listData.Total < 1 {
		t.Fatalf("list_flows.total: got %d, want >= 1", listData.Total)
	}
	// FlowModel has no JSON tags, so Go uses capitalized field names.
	flowID, _ := listData.Items[0]["ID"].(string)
	if flowID == "" {
		t.Fatal("list_flows item missing ID")
	}

	// Get flow
	_, out2, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "get_flow",
		ID:     id,
		FlowID: flowID,
	})
	if err != nil {
		t.Fatalf("get_flow: %v", err)
	}
	var flow map[string]interface{}
	if err := json.Unmarshal(asRaw(out2.Data), &flow); err != nil {
		t.Fatalf("get_flow returned non-object: %s", string(asRaw(out2.Data)))
	}
	if flow["ID"] != flowID {
		t.Errorf("get_flow.id: got %v, want %s", flow["ID"], flowID)
	}
}

func TestMCP_ManagePcaps_ListPacketsByAssetAndGetPacket(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id := importTestPcap(t, env)

	// List packets by asset
	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "list_packets_by_asset",
		ID:     id,
	})
	if err != nil {
		t.Fatalf("list_packets_by_asset: %v", err)
	}
	var listData struct {
		Items []map[string]interface{} `json:"items"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(asRaw(out.Data), &listData); err != nil {
		t.Fatalf("list_packets_by_asset returned non-object: %s", string(asRaw(out.Data)))
	}
	if listData.Total < 1 {
		t.Fatalf("list_packets_by_asset.total: got %d, want >= 1", listData.Total)
	}
	// PacketModel has no JSON tags, so Go uses capitalized field names.
	packetID, _ := listData.Items[0]["ID"].(string)
	if packetID == "" {
		t.Fatal("list_packets_by_asset item missing ID")
	}

	// Get packet (dynamic re-parse)
	_, out2, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action:   "get_packet",
		ID:       id,
		PacketID: packetID,
	})
	if err != nil {
		t.Fatalf("get_packet: %v", err)
	}
	var getPacket map[string]interface{}
	if err := json.Unmarshal(asRaw(out2.Data), &getPacket); err != nil {
		t.Fatalf("get_packet returned non-object: %s", string(asRaw(out2.Data)))
	}
}

func TestMCP_ManagePcaps_GetPacketPayload(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id := importTestPcap(t, env)

	// List packets to get a packet ID
	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "list_packets_by_asset",
		ID:     id,
	})
	if err != nil {
		t.Fatalf("list_packets_by_asset: %v", err)
	}
	var listData struct {
		Items []map[string]interface{} `json:"items"`
	}
	json.Unmarshal(asRaw(out.Data), &listData)
	if len(listData.Items) == 0 {
		t.Fatal("no packets in asset")
	}
	// PacketModel has no JSON tags, so Go uses capitalized field names.
	packetID, _ := listData.Items[0]["ID"].(string)

	// Get packet payload (binary -> base64)
	_, out2, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action:   "get_packet_payload",
		ID:       id,
		PacketID: packetID,
	})
	if err != nil {
		t.Fatalf("get_packet_payload: %v", err)
	}
	var payload struct {
		PayloadBase64 string `json:"payload_base64"`
		Length        int    `json:"length"`
	}
	if err := json.Unmarshal(asRaw(out2.Data), &payload); err != nil {
		t.Fatalf("get_packet_payload returned non-object: %s", string(asRaw(out2.Data)))
	}
	if payload.Length < 0 {
		t.Errorf("payload.length: got %d, want >= 0", payload.Length)
	}
	// Verify base64 decodes without error
	if _, err := base64.StdEncoding.DecodeString(payload.PayloadBase64); err != nil {
		t.Errorf("payload_base64 invalid: %v", err)
	}

	// P2-⑥：scope=frame 返回整帧字节（Eth+IP+L4+L7），必须严格大于默认
	// 的 L7 payload（fixture 是带完整协议头的包）。
	_, outFrame, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action:   "get_packet_payload",
		ID:       id,
		PacketID: packetID,
		Scope:    "frame",
	})
	if err != nil {
		t.Fatalf("get_packet_payload scope=frame: %v", err)
	}
	var frame struct {
		Length int `json:"length"`
	}
	if err := json.Unmarshal(asRaw(outFrame.Data), &frame); err != nil {
		t.Fatalf("scope=frame returned non-object: %s", string(asRaw(outFrame.Data)))
	}
	if frame.Length <= payload.Length {
		t.Errorf("frame bytes (%d) must exceed L7 payload (%d)", frame.Length, payload.Length)
	}
}

func TestMCP_ManagePcaps_Download(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id := importTestPcap(t, env)

	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "download",
		ID:     id,
	})
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	var dl struct {
		FilePath string `json:"file_path"`
		FileSize int64  `json:"file_size"`
	}
	if err := json.Unmarshal(asRaw(out.Data), &dl); err != nil {
		t.Fatalf("download returned non-object: %s", string(asRaw(out.Data)))
	}
	if dl.FilePath == "" {
		t.Errorf("download.file_path: got empty, want non-empty")
	}
	if dl.FileSize <= 0 {
		t.Errorf("download.file_size: got %d, want > 0", dl.FileSize)
	}
}

func TestMCP_ManagePcaps_Delete(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id := importTestPcap(t, env)

	_, _, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "delete",
		ID:     id,
	})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Verify deletion via get (should fail)
	_, _, err = env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "get",
		ID:     id,
	})
	if err == nil {
		t.Error("get after delete should fail, got nil error")
	}
}

func TestMCP_ManagePcaps_ImportMissingFilePath(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "import",
	})
	if err == nil {
		t.Fatal("expected error for import without file_path, got nil")
	}
}

// TestMCP_ManagePcaps_ImportPathValidation verifies the path-traversal /
// relative-path defenses added to handlePcapImport. Pre-fix, any string was
// accepted and passed to ImportFromPath; this test ensures the LLM cannot
// accidentally point at sensitive files via "../" or relative paths.
func TestMCP_ManagePcaps_ImportPathValidation(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	cases := []struct {
		name string
		path string
	}{
		{"relative", "tmp/test.pcap"},
		{"dot-slash", "./test.pcap"},
		{"dotdot", "/tmp/../etc/passwd"},
		{"dotdot-suffix", "/tmp/foo/../"},
		{"double-slash", "/tmp//test.pcap"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
				Action:   "import",
				FilePath: c.path,
			})
			if err == nil {
				t.Fatalf("path %q: expected error, got nil", c.path)
			}
		})
	}
}

// TestMCP_ManagePcaps_MissingIDPreValidation verifies actions other than
// import/list return InvalidParams when id is empty, BEFORE hitting the DB.
// Pre-fix, an empty id was passed to the REST handler which 404'd with a
// less helpful "record not found" message.
func TestMCP_ManagePcaps_MissingIDPreValidation(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	cases := []struct {
		action string
		extra  managePcapsInput
	}{
		{"get", managePcapsInput{}},
		{"delete", managePcapsInput{}},
		{"list_flows", managePcapsInput{}},
		{"get_flow", managePcapsInput{FlowID: "f1"}},
		{"list_packets", managePcapsInput{FlowID: "f1"}},
		{"get_stream", managePcapsInput{FlowID: "f1"}},
		{"get_body", managePcapsInput{FlowID: "f1"}},
		{"list_packets_by_asset", managePcapsInput{}},
		{"get_packet", managePcapsInput{PacketID: "p1"}},
		{"get_packet_payload", managePcapsInput{PacketID: "p1"}},
		{"search", managePcapsInput{}},
		{"match_preview", managePcapsInput{}},
		{"extract", managePcapsInput{}},
		{"download", managePcapsInput{}},
		{"reparse", managePcapsInput{}},
	}
	for _, c := range cases {
		t.Run(c.action, func(t *testing.T) {
			in := c.extra
			in.Action = c.action
			_, _, err := env.srv.handleManagePcaps(context.Background(), nil, in)
			if err == nil {
				t.Fatalf("action %q with empty id: expected error, got nil", c.action)
			}
		})
	}
}

// TestMCP_ManagePcaps_MissingFlowIDPreValidation verifies flow-scoped actions
// return InvalidParams when flow_id is empty.
func TestMCP_ManagePcaps_MissingFlowIDPreValidation(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	for _, action := range []string{"get_flow", "list_packets", "get_stream", "get_body"} {
		t.Run(action, func(t *testing.T) {
			_, _, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
				Action: action,
				ID:     "some-asset-id",
			})
			if err == nil {
				t.Fatalf("action %q with empty flow_id: expected error, got nil", action)
			}
		})
	}
}

// TestMCP_ManagePcaps_MissingPacketIDPreValidation verifies packet-scoped
// actions return InvalidParams when packet_id is empty.
func TestMCP_ManagePcaps_MissingPacketIDPreValidation(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	for _, action := range []string{"get_packet", "get_packet_payload"} {
		t.Run(action, func(t *testing.T) {
			_, _, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
				Action: action,
				ID:     "some-asset-id",
			})
			if err == nil {
				t.Fatalf("action %q with empty packet_id: expected error, got nil", action)
			}
		})
	}
}

func TestMCP_ManagePcaps_InvalidAction(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	_, _, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "bogus",
	})
	if err == nil {
		t.Fatal("expected error for invalid action, got nil")
	}
}

// listFlowsForTest imports a pcap and returns (assetID, firstFlowID).
func listFlowsForTest(t *testing.T, env *testMCPEnv) (string, string) {
	t.Helper()
	id := importTestPcap(t, env)
	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "list_flows",
		ID:     id,
	})
	if err != nil {
		t.Fatalf("list_flows: %v", err)
	}
	var listData struct {
		Items []map[string]interface{} `json:"items"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(asRaw(out.Data), &listData); err != nil {
		t.Fatalf("list_flows returned non-object: %s", string(asRaw(out.Data)))
	}
	if listData.Total < 1 {
		t.Fatalf("list_flows.total: got %d, want >= 1", listData.Total)
	}
	flowID, _ := listData.Items[0]["ID"].(string)
	if flowID == "" {
		t.Fatal("list_flows item missing ID")
	}
	return id, flowID
}

func TestMCP_ManagePcaps_ListPackets(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id, flowID := listFlowsForTest(t, env)

	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "list_packets",
		ID:     id,
		FlowID: flowID,
	})
	if err != nil {
		t.Fatalf("list_packets: %v", err)
	}
	var listData struct {
		Items []map[string]interface{} `json:"items"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(asRaw(out.Data), &listData); err != nil {
		t.Fatalf("list_packets returned non-object: %s", string(asRaw(out.Data)))
	}
	if listData.Total < 1 {
		t.Errorf("list_packets.total: got %d, want >= 1", listData.Total)
	}
}

func TestMCP_ManagePcaps_GetStream(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id, flowID := listFlowsForTest(t, env)

	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action:    "get_stream",
		ID:        id,
		FlowID:    flowID,
		Direction: "c2s",
	})
	if err != nil {
		t.Fatalf("get_stream: %v", err)
	}
	var stream struct {
		PayloadBase64 string `json:"payload_base64"`
		Length        int    `json:"length"`
	}
	if err := json.Unmarshal(asRaw(out.Data), &stream); err != nil {
		t.Fatalf("get_stream returned non-object: %s", string(asRaw(out.Data)))
	}
	if stream.Length <= 0 {
		t.Errorf("stream.length: got %d, want > 0 (c2s has SYN+payload)", stream.Length)
	}
	decoded, derr := base64.StdEncoding.DecodeString(stream.PayloadBase64)
	if derr != nil {
		t.Fatalf("stream payload_base64 invalid: %v", derr)
	}
	// CRITICAL regression check: the actual content must equal what the pcap
	// handler wrote, NOT a JSON envelope. The pre-fix bug was that empty
	// streams returned the JSON envelope as the payload; the parallel check
	// for non-empty streams is that the decoded bytes are NOT a JSON envelope.
	if len(decoded) != stream.Length {
		t.Errorf("decoded length mismatch: got %d, want %d", len(decoded), stream.Length)
	}
	if len(decoded) > 0 && (decoded[0] == '{' || decoded[0] == '[') {
		t.Errorf("stream payload looks like JSON (envelope leak): %q", decoded)
	}
}

// TestMCP_ManagePcaps_GetStream_Empty verifies the empty-stream path
// (CRITICAL bug regression): when a flow has no data in the requested
// direction, the MCP wrapper must return {payload_base64:"", length:0}, NOT
// a base64-encoded JSON envelope. The pre-fix bug was that the REST handler
// wrote Success(c, []byte{}) -> JSON envelope, and MCP base64-encoded that
// envelope as if it were the actual stream payload.
func TestMCP_ManagePcaps_GetStream_Empty(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id, flowID := listFlowsForTest(t, env)

	// The test pcap has one c2s SYN packet and no s2c data -> s2c stream
	// is empty. Pre-fix, this returned the JSON envelope base64-encoded.
	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action:    "get_stream",
		ID:        id,
		FlowID:    flowID,
		Direction: "s2c",
	})
	if err != nil {
		t.Fatalf("get_stream empty: %v", err)
	}
	var stream struct {
		PayloadBase64 string `json:"payload_base64"`
		Length        int    `json:"length"`
	}
	if err := json.Unmarshal(asRaw(out.Data), &stream); err != nil {
		t.Fatalf("get_stream empty returned non-object: %s", string(asRaw(out.Data)))
	}
	if stream.Length != 0 {
		t.Errorf("empty stream.length: got %d, want 0", stream.Length)
	}
	if stream.PayloadBase64 != "" {
		t.Errorf("empty stream.payload_base64: got %q, want empty", stream.PayloadBase64)
		// Extra check: if it's the JSON envelope, decode + report.
		if decoded, derr := base64.StdEncoding.DecodeString(stream.PayloadBase64); derr == nil {
			t.Errorf("decoded empty-stream payload (should be JSON envelope bug): %s", decoded)
		}
	}
	// P2-⑥：空流必须带指路 note（UDP 流无重组流，TCP 空流=真空载荷），
	// 不能让 LLM 对着空 payload_base64 猜。
	var withNote struct {
		Note string `json:"note"`
	}
	if err := json.Unmarshal(asRaw(out.Data), &withNote); err != nil {
		t.Fatalf("unmarshal note: %v", err)
	}
	if withNote.Note == "" {
		t.Error("empty stream must carry a guidance note")
	}
}

// TestMCP_ManagePcaps_GetBody_Empty is the same regression for GetBody.
func TestMCP_ManagePcaps_GetBody_Empty(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id, flowID := listFlowsForTest(t, env)

	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action:    "get_body",
		ID:        id,
		FlowID:    flowID,
		Direction: "s2c",
	})
	if err != nil {
		t.Fatalf("get_body empty: %v", err)
	}
	var body struct {
		PayloadBase64 string `json:"payload_base64"`
		Length        int    `json:"length"`
	}
	if err := json.Unmarshal(asRaw(out.Data), &body); err != nil {
		t.Fatalf("get_body empty returned non-object: %s", string(asRaw(out.Data)))
	}
	if body.Length != 0 {
		t.Errorf("empty body.length: got %d, want 0", body.Length)
	}
	if body.PayloadBase64 != "" {
		t.Errorf("empty body.payload_base64: got %q, want empty", body.PayloadBase64)
		if decoded, derr := base64.StdEncoding.DecodeString(body.PayloadBase64); derr == nil {
			t.Errorf("decoded empty-body payload (envelope leak): %s", decoded)
		}
	}
}

func TestMCP_ManagePcaps_GetBody(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id, flowID := listFlowsForTest(t, env)

	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action:    "get_body",
		ID:        id,
		FlowID:    flowID,
		Direction: "c2s",
	})
	if err != nil {
		t.Fatalf("get_body: %v", err)
	}
	var body struct {
		PayloadBase64 string `json:"payload_base64"`
		Length        int    `json:"length"`
	}
	if err := json.Unmarshal(asRaw(out.Data), &body); err != nil {
		t.Fatalf("get_body returned non-object: %s", string(asRaw(out.Data)))
	}
	if body.Length < 0 {
		t.Errorf("body.length: got %d, want >= 0", body.Length)
	}
	if _, err := base64.StdEncoding.DecodeString(body.PayloadBase64); err != nil {
		t.Errorf("body payload_base64 invalid: %v", err)
	}
}

func TestMCP_ManagePcaps_Search(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id := importTestPcap(t, env)

	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "search",
		ID:     id,
		Filters: map[string]interface{}{
			"flow_filter": map[string]interface{}{
				"l4_protocol": "tcp",
			},
		},
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	// Search returns a JSON array of {Flow, Matches, Packets} objects.
	var results []map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &results); err != nil {
		t.Fatalf("search returned non-array: %s", string(asRaw(out.Data)))
	}
	if len(results) < 1 {
		t.Errorf("search results: got %d, want >= 1", len(results))
	}
}

func TestMCP_ManagePcaps_MatchPreview(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id := importTestPcap(t, env)

	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "match_preview",
		ID:     id,
		Matcher: map[string]interface{}{
			"src_ip": "10.0.0.1",
			"dst_ip": "10.0.0.2",
		},
	})
	if err != nil {
		t.Fatalf("match_preview: %v", err)
	}
	// MatchPreview returns {count: N, flow_ids: [...]}.
	var preview map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &preview); err != nil {
		t.Fatalf("match_preview returned non-object: %s", string(asRaw(out.Data)))
	}
	count, ok := preview["count"]
	if !ok {
		t.Errorf("match_preview missing 'count' field: %s", string(asRaw(out.Data)))
	}
	if count == nil {
		t.Errorf("match_preview count is nil: %s", string(asRaw(out.Data)))
	}
}

func TestMCP_ManagePcaps_Extract(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id := importTestPcap(t, env)

	// Get a packet ID first
	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "list_packets_by_asset",
		ID:     id,
	})
	if err != nil {
		t.Fatalf("list_packets_by_asset: %v", err)
	}
	var listData struct {
		Items []map[string]interface{} `json:"items"`
	}
	json.Unmarshal(asRaw(out.Data), &listData)
	if len(listData.Items) == 0 {
		t.Fatal("no packets in asset")
	}
	packetID, _ := listData.Items[0]["ID"].(string)

	// Extract src_ip and dst_ip from the packet
	_, out2, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "extract",
		ID:     id,
		ExtractRules: map[string]interface{}{
			"packet_ids": []string{packetID},
			"fields":     []string{"src_ip", "dst_ip"},
		},
	})
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	// Extract returns {items: [...]} or similar. Verify it's a JSON object.
	var extract map[string]interface{}
	if err := json.Unmarshal(asRaw(out2.Data), &extract); err != nil {
		t.Fatalf("extract returned non-object: %s", string(asRaw(out2.Data)))
	}
}

func TestMCP_ManagePcaps_Reparse(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	id := importTestPcap(t, env)

	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "reparse",
		ID:     id,
	})
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	// Reparse returns {message: "reparse complete", ...}. Verify it's a JSON object.
	var reparse map[string]interface{}
	if err := json.Unmarshal(asRaw(out.Data), &reparse); err != nil {
		t.Fatalf("reparse returned non-object: %s", string(asRaw(out.Data)))
	}
}

// TestMCP_ManagePcaps_ExtractBulkAndStreams: 全量提取（用户需求 2026-10-05）
// ——extract_bulk 不需要 packet_ids（flow 级/资产级直接拉），extract_streams
// 不需要逐流调用。
func TestMCP_ManagePcaps_ExtractBulkAndStreams(t *testing.T) {
	env := setupMCPTest(t)
	defer env.cleanup()

	aid := importTestPcap(t, env)

	// 取 flow_id
	_, fl, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "list_flows", ID: aid,
	})
	if err != nil {
		t.Fatalf("list_flows: %v", err)
	}
	var flows struct {
		Items []struct {
			ID string `json:"ID"`
		} `json:"items"`
	}
	if err := json.Unmarshal(asRaw(fl.Data), &flows); err != nil || len(flows.Items) == 0 {
		t.Fatalf("flows: %s (err %v)", string(asRaw(fl.Data))[:200], err)
	}
	fid := flows.Items[0].ID

	// 1) 流级全量字段提取——无 packet_ids
	_, out, err := env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "extract_bulk", ID: aid, FlowID: fid,
		ExtractRules: map[string]interface{}{"fields": []interface{}{"src_ip", "dst_port"}},
	})
	if err != nil {
		t.Fatalf("extract_bulk(flow): %v", err)
	}
	var bulk struct {
		Extracted int                      `json:"extracted"`
		Items     []map[string]interface{} `json:"items"`
	}
	if err := json.Unmarshal(asRaw(out.Data), &bulk); err != nil {
		t.Fatalf("bulk decode: %v (%s)", err, string(asRaw(out.Data))[:200])
	}
	if bulk.Extracted != 1 || len(bulk.Items) != 1 {
		t.Fatalf("extracted = %d items = %d, want 1/1", bulk.Extracted, len(bulk.Items))
	}
	flds := bulk.Items[0]["fields"].(map[string]interface{})
	if flds["src_ip"] != "10.0.0.1" {
		t.Errorf("bulk src_ip = %v, want 10.0.0.1", flds["src_ip"])
	}

	// 2) 资产级全量（无 flow_id）
	_, out, err = env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "extract_bulk", ID: aid,
		ExtractRules: map[string]interface{}{"fields": []interface{}{"src_ip"}},
	})
	if err != nil {
		t.Fatalf("extract_bulk(asset): %v", err)
	}
	if err := json.Unmarshal(asRaw(out.Data), &bulk); err != nil {
		t.Fatalf("asset bulk decode: %v", err)
	}
	if bulk.Extracted != 1 {
		t.Fatalf("asset extracted = %d, want 1", bulk.Extracted)
	}

	// 3) 流文本全量（单流）
	_, out, err = env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "extract_streams", ID: aid, FlowID: fid,
	})
	if err != nil {
		t.Fatalf("extract_streams(flow): %v", err)
	}
	var streams struct {
		Flows int                      `json:"flows"`
		Items []map[string]interface{} `json:"items"`
	}
	if err := json.Unmarshal(asRaw(out.Data), &streams); err != nil {
		t.Fatalf("streams decode: %v (%s)", err, string(asRaw(out.Data))[:200])
	}
	if streams.Flows != 1 {
		t.Errorf("streams flows = %d, want 1", streams.Flows)
	}

	// 4) 资产级流文本（无 flow_id）
	_, out, err = env.srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "extract_streams", ID: aid,
	})
	if err != nil {
		t.Fatalf("extract_streams(asset): %v", err)
	}
	if err := json.Unmarshal(asRaw(out.Data), &streams); err != nil {
		t.Fatalf("asset streams decode: %v", err)
	}
	if streams.Flows != 1 {
		t.Errorf("asset streams flows = %d, want 1", streams.Flows)
	}
}
