package mcp

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/replay"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/auth"
	"github.com/trafficgen/trafficgen/pkg/config"
	"github.com/trafficgen/trafficgen/pkg/netif"
)

// TestMCP_Padding_InspectBytes is a MANUAL inspection test that:
//  1. Generates 3 ARP pcaps (pad_min_frame = default/false/true) to a persistent
//     directory (/tmp/padding-verify/) so a human can open them in Wireshark.
//  2. Reads each pcap back with pcapgo and hexdumps every frame to the test log.
//  3. Verifies byte-level content (not just frame length):
//     - EtherType at bytes 12-13 must be 0x0806 (ARP)
//     - ARP operation at bytes 20-21 must be 1 (request) on frame 0 and 2 (reply) on frame 1
//     - Padding bytes (42..59 for padded frames) must all be zero
//
// This test does NOT delete the pcap files — they stay on disk for manual
// inspection. Skip with -test.run deselect if the directory is unwanted.
func TestMCP_Padding_InspectBytes(t *testing.T) {
	// 落到家目录下唯一的运行子目录：硬编码 /tmp 固定目录会在残留了 root
	// 属主旧产物的机器上撞权限（无法清理/写入别人的文件）。旧产物不删
	// （可能属他人），本轮产物写进 ~/.cache/padding-verify/run-<ts>。
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir: %v", err)
	}
	base := filepath.Join(home, ".cache", "padding-verify")
	outDir := filepath.Join(base, fmt.Sprintf("run-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("mkdir outDir %s: %v", outDir, err)
	}

	cases := []struct {
		name        string
		pad         interface{} // nil=absent, false, true
		wantLen     int
		description string
	}{
		{"default", nil, 60, "absent -> default ON -> padded to 60"},
		{"false", false, 42, "explicit false -> no padding -> natural 42"},
		{"true", true, 60, "explicit true -> padded to 60"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcapPath := filepath.Join(outDir, "arp-"+tc.name+".pcap")
			env := setupMCPRealEnvAt(t, outDir, tc.name)
			// Manually stop engine + close DB, but DO NOT RemoveAll — the
			// pcap files at outDir must stay for manual inspection.
			defer env.eng.Stop()
			defer env.db.Close()

			cfg := map[string]interface{}{
				// D-ARP-1 扁平判死后层链形状（op=1 配对语义保持 2 帧）。
				"layers": []map[string]interface{}{
					{"eth": map[string]interface{}{"src_mac": "aa:bb:cc:dd:ee:01", "dst_mac": "aa:bb:cc:dd:ee:02"}},
					{"arp": map[string]interface{}{"operation": 1}},
				},
			}
			if tc.pad != nil {
				cfg["pad_min_frame"] = tc.pad
			}

			_, out, err := env.srv.handleGenerateTraffic(context.Background(), nil, generateTrafficInput{
				TaskName:   "arp-" + tc.name,
				Protocol:   "arp",
				Config:     cfg,
				OutputType: "pcap",
				OutputConfig: &outputConfigInput{
					PcapPath: pcapPath,
				},
			})
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			select {
			case <-env.done:
			case <-time.After(10 * time.Second):
				t.Fatal("task did not complete")
			}
			env.eng.UnregisterOutputWriter(out.TaskID + "-" + out.StrategyID)

			// Read back and inspect bytes.
			f, err := os.Open(pcapPath)
			if err != nil {
				t.Fatalf("open pcap: %v", err)
			}
			defer f.Close()
			r, err := pcapgo.NewReader(f)
			if err != nil {
				t.Fatalf("pcapgo.NewReader: %v", err)
			}

			t.Logf("=== %s: %s ===", tc.name, tc.description)
			t.Logf("pcap file: %s", pcapPath)

			frameIdx := 0
			for {
				data, ci, err := r.ReadPacketData()
				if err != nil {
					break
				}
				t.Logf("--- frame[%d] len=%d ---", frameIdx, ci.CaptureLength)
				t.Logf("%s", hex.Dump(data))

				// EtherType at bytes 12-13 (after 6-byte dst + 6-byte src MAC).
				et := binary.BigEndian.Uint16(data[12:14])
				if et != 0x0806 {
					t.Errorf("frame[%d] EtherType=0x%04x, want 0x0806 (ARP)", frameIdx, et)
				}

				// ARP op at bytes 20-21 (Eth 14 + ARP header offset 6).
				op := binary.BigEndian.Uint16(data[20:22])
				wantOp := uint16(1) // request on frame 0
				if frameIdx == 1 {
					wantOp = 2 // reply on frame 1
				}
				if op != wantOp {
					t.Errorf("frame[%d] ARP op=%d, want %d", frameIdx, op, wantOp)
				}

				// ARP hardware type at bytes 14-15 must be 1 (Ethernet).
				htype := binary.BigEndian.Uint16(data[14:16])
				if htype != 0x0001 {
					t.Errorf("frame[%d] ARP htype=0x%04x, want 0x0001", frameIdx, htype)
				}

				// For 60-byte padded frames, bytes 42..59 must be zero padding.
				if tc.wantLen == 60 {
					for i := 42; i < 60; i++ {
						if data[i] != 0 {
							t.Errorf("frame[%d] padding byte[%d]=0x%02x, want 0", frameIdx, i, data[i])
						}
					}
				}
				// For 42-byte unpadded frames, no padding bytes should exist.
				if tc.wantLen == 42 && ci.CaptureLength != 42 {
					t.Errorf("frame[%d] len=%d, want 42 (no padding)", frameIdx, ci.CaptureLength)
				}

				frameIdx++
			}
			if frameIdx != 2 {
				t.Fatalf("frame count=%d, want 2 (ARP request + reply)", frameIdx)
			}
		})
	}

	t.Logf("")
	t.Logf("=== Summary — pcap files for manual inspection ===")
	t.Logf("Directory: %s", outDir)
	for _, tc := range cases {
		t.Logf("  arp-%s.pcap — %s", tc.name, tc.description)
	}
	t.Logf("Open with: wireshark %s/arp-*.pcap  OR  tcpdump -nn -e -r %s/arp-default.pcap", outDir, outDir)
}

// setupMCPRealEnvAt creates a test env at a deterministic path (outDir/sub)
// instead of a random MkdirTemp. Used by TestMCP_Padding_InspectBytes which
// must keep the pcap files on disk after the test ends.
func setupMCPRealEnvAt(t *testing.T, outDir, sub string) *testMCPEnv {
	t.Helper()
	tmp := filepath.Join(outDir, "db-"+sub)
	if err := os.MkdirAll(tmp, 0755); err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}
	dbPath := filepath.Join(tmp, "test.db")

	sdb, err := storage.NewDB(&config.DatabaseConfig{Type: "sqlite", SQLite: config.SQLiteConfig{Path: dbPath}})
	if err != nil {
		t.Fatalf("new db: %v", err)
	}

	userID := "svc-user-1"
	sdb.Create(&storage.UserModel{
		ID:           userID,
		Username:     "mcp-test-svc",
		PasswordHash: "test-hash",
		Email:        "mcp@test.local",
		Role:         "user",
		Enabled:      true,
	})

	eng := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	eng.RegisterPlanner(layers.NewChainPlanner("arp")) // D-ARP-1 翻转：链 planner
	eng.SetLayerPlannerFactory(layers.BuildLayersPlanner) // 层链配置经工厂
	eng.SetBuildFunc(replay.NewBuildFunc(core.NewBuilder().Build))

	done := make(chan string, 4)
	eng.OnTaskComplete = func(taskID string) { done <- taskID }
	eng.OnTaskFailed = func(taskID, msg string) { done <- taskID }

	if err := eng.Start(); err != nil {
		eng.Stop()
		sdb.Close()
		t.Fatalf("engine start: %v", err)
	}

	cfg := &config.MCPConfig{
		Enabled:                true,
		ServiceUserID:          "mcp-test-svc",
		ServiceUserRole:        "user",
		ServiceAccountPassword: "test-pass",
		AuditLog:               false,
		Transports:             config.MCPTransports{Stdio: false},
	}
	srv, err := NewServer(cfg, eng, sdb, netif.NewManager())
	if err != nil {
		eng.Stop()
		sdb.Close()
		t.Fatalf("new mcp server: %v", err)
	}
	srv.SetJWTManager(auth.NewJWTManager("test-secret", "test-issuer", 24*time.Hour))

	return &testMCPEnv{
		db:     sdb,
		eng:    eng,
		im:     netif.NewManager(),
		srv:    srv,
		tmp:    tmp,
		done:   done,
		dbPath: dbPath,
	}
}

// Ensure the unused-import linter doesn't complain about fmt if we restructure.
var _ = fmt.Sprintf
