package replay

// Failing-test-first for M1: planner pcap open error must surface as a Plan
// error, not silently close the channel and let processReplayTask report
// "completed" with 0 packets.
//
// Also M6: an asset with status=ready but zero parsed packets must surface
// as a Plan error too. Before the fix, Plan launched a goroutine that iterated
// an empty packet list, closed the channel with 0 configs, and returned nil --
// again causing processReplayTask to report "completed" with 0 packets.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	sqlite "github.com/glebarez/sqlite"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/trafficgen/trafficgen/internal/storage"
	"gorm.io/gorm"
)

// TestPlanner_Plan_PcapOpenErrorSurfaced verifies that when the pcap file
// cannot be opened (deleted/moved/permissions), Plan returns a non-nil error
// immediately. Before the fix, Plan launched a goroutine that opened the file
// and logged+returned on failure, closing the channel with 0 configs and a nil
// error -- causing processReplayTask to report task "completed" with 0 packets.
func TestPlanner_Plan_PcapOpenErrorSurfaced(t *testing.T) {
	planner, db, assetID, _ := setupReplayAsset(t)

	// Corrupt the asset's StoragePath so os.Open fails in the planner.
	if err := db.Model(&storage.PcapAssetModel{}).
		Where("id = ?", assetID).
		Update("storage_path", "/nonexistent/m1-missing.pcap").Error; err != nil {
		t.Fatalf("corrupt asset path: %v", err)
	}

	spec := ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: ""}}
	ch, err := planner.Plan(context.Background(), spec, "t-m1", "c-m1", "u1", nil)
	if err == nil {
		// Drain to let the goroutine exit cleanly (avoid leak on the bug path).
		if ch != nil {
			for range ch {
			}
		}
		t.Fatal("Plan returned nil error for unopenable pcap file (M1: silent completion bug)")
	}
	if ch != nil {
		t.Errorf("Plan returned non-nil channel alongside error")
	}
}

// TestPlanner_Plan_EmptyPcapSurfaced verifies that when an asset is ready but
// has zero parsed packets (parser produced no packets -- e.g. truncated file
// with only a global header, or all packets failed to parse), Plan returns a
// non-nil error. Before the fix, Plan iterated an empty list, closed the
// channel with 0 configs, and returned nil -- causing processReplayTask to
// report the task as "completed" with 0 packets (M6).
func TestPlanner_Plan_EmptyPcapSurfaced(t *testing.T) {
	// Build a pcap file with only the global header (no packets). A valid
	// file the parser can open, but with zero packets inside.
	pcapPath := filepath.Join(t.TempDir(), "empty.pcap")
	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatalf("create empty pcap: %v", err)
	}
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	f.Close()

	// Stand up an asset with status=ready pointing at the empty file. Don't
	// insert any flows/packets -- mirrors a parser run that produced nothing.
	gormDB, _ := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "m6.db")), &gorm.Config{})
	storage.AutoMigrate(gormDB)
	db := &storage.DB{DB: gormDB}
	repo := storage.NewPcapRepository(db)
	asset := &storage.PcapAssetModel{
		ID:          "ast-m6",
		UserID:      "u1",
		Name:        "empty.pcap",
		StoragePath: pcapPath,
		Status:      "ready",
		LinkType:    1,
		PacketCount: 0,
		FlowCount:   0,
	}
	if err := repo.CreateAsset(asset); err != nil {
		t.Fatalf("create asset: %v", err)
	}

	planner := NewReplayPlanner(db)
	spec := ReplaySpec{PcapAssetID: "ast-m6", Speed: ReplaySpeed{Mode: "original"}}
	ch, err := planner.Plan(context.Background(), spec, "t-m6", "c-m6", "u1", nil)
	if err == nil {
		if ch != nil {
			for range ch {
			}
		}
		t.Fatal("Plan returned nil error for empty pcap (M6: silent completion bug)")
	}
	if ch != nil {
		t.Errorf("Plan returned non-nil channel alongside error")
	}
}
