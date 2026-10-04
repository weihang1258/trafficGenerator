package storage

import (
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// assetFixture builds a minimal PcapAssetModel for tests.
func assetFixture(userID, name, hash string) *PcapAssetModel {
	return &PcapAssetModel{
		ID:            uuid.New().String(),
		UserID:        userID,
		Name:          name,
		OriginalFilename: name + ".pcap",
		StoragePath:   "/data/pcaps/" + hash + ".pcap",
		PayloadsPath:  "/data/pcaps/" + hash + ".payloads",
		TrigramIndexPath: "/data/pcaps/" + hash + ".trigram",
		FileHash:      hash,
		FileSize:      1024,
		Status:        "importing",
		LinkType:      1, // DLT_EN10MB
		Snaplen:       65535,
	}
}

func flowFixture(assetID, userID, key string) FlowModel {
	return FlowModel{
		ID:          uuid.New().String(),
		PcapAssetID: assetID,
		UserID:      userID,
		FlowKey:     key,
		L4Protocol:  "tcp",
		IPVersion:   4,
		SrcIP:       "10.0.0.1",
		SrcPort:     1234,
		DstIP:       "10.0.0.2",
		DstPort:     80,
		DirStatus:   "classified",
		PacketCount: 3,
		FirstTsUs:   1000,
	}
}

func packetFixture(assetID, flowID, userID string, idxInFlow int, ts int64) PacketModel {
	return PacketModel{
		ID:          uuid.New().String(),
		PcapAssetID: assetID,
		FlowID:      flowID,
		UserID:      userID,
		RawOffset:   int64(16 + idxInFlow*100),
		Length:      100,
		TimestampUs: ts,
		IndexInFlow: idxInFlow,
		Direction:   "c2s",
		L4Protocol:  "tcp",
		FragOffset:  -1,
	}
}

// TestPcapModels_MigrateAndIndexes verifies AutoMigrate creates the three
// tables and the expected composite index idx_pkt_flow_seq (used for in-flow
// ordered pagination). We query sqlite_master directly because the pure-Go
// SQLite driver does not implement Migrator().GetIndexes().
func TestPcapModels_MigrateAndIndexes(t *testing.T) {
	db, _ := newTestDB(t)

	for _, table := range []string{"pcap_assets", "pcap_flows", "pcap_packets"} {
		if !db.Migrator().HasTable(table) {
			t.Errorf("table %q not created", table)
		}
	}

	// Confirm the composite index exists on pcap_packets.
	var name string
	err := db.Raw(`SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'pcap_packets' AND name = 'idx_pkt_flow_seq'`).Row().Scan(&name)
	if err != nil || name != "idx_pkt_flow_seq" {
		t.Errorf("composite index idx_pkt_flow_seq missing on pcap_packets (err=%v name=%q)", err, name)
	}
}

// TestPcapRepository_AssetCRUD exercises the asset lifecycle: create, get,
// dedup-by-hash, status update, list, and delete with cascade to flows/packets.
func TestPcapRepository_AssetCRUD(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)
	asset := assetFixture("user1", "cap1", "hash1")

	if err := repo.CreateAsset(asset); err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	got, err := repo.GetAsset(asset.ID, "user1")
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	if got.Name != "cap1" || got.Status != "importing" {
		t.Errorf("GetAsset got name=%q status=%q", got.Name, got.Status)
	}

	// Dedup by hash returns the same asset for the same user.
	dup, err := repo.GetAssetByHash("user1", "hash1")
	if err != nil {
		t.Fatalf("GetAssetByHash: %v", err)
	}
	if dup.ID != asset.ID {
		t.Errorf("dedup returned different asset id: got %s want %s", dup.ID, asset.ID)
	}
	// Different user with same hash: not found (user isolation).
	if _, err := repo.GetAssetByHash("user2", "hash1"); err != gorm.ErrRecordNotFound {
		t.Errorf("cross-user hash lookup: want ErrRecordNotFound, got %v", err)
	}

	// Status update.
	if err := repo.UpdateAssetStatus(asset.ID, "ready", ""); err != nil {
		t.Fatalf("UpdateAssetStatus: %v", err)
	}
	got, _ = repo.GetAsset(asset.ID, "user1")
	if got.Status != "ready" {
		t.Errorf("status not updated, got %q", got.Status)
	}

	// Add flows + packets so we can verify delete cascade.
	flows := []FlowModel{flowFixture(asset.ID, "user1", "k1")}
	if err := repo.CreateFlows(flows); err != nil {
		t.Fatalf("CreateFlows: %v", err)
	}
	pkts := []PacketModel{
		packetFixture(asset.ID, flows[0].ID, "user1", 0, 1000),
		packetFixture(asset.ID, flows[0].ID, "user1", 1, 2000),
	}
	if err := repo.CreatePackets(pkts); err != nil {
		t.Fatalf("CreatePackets: %v", err)
	}

	// Cascade delete flows + packets, then the asset row.
	if err := repo.DeleteAssetFlowsAndPackets(asset.ID); err != nil {
		t.Fatalf("DeleteAssetFlowsAndPackets: %v", err)
	}
	if n, _ := repo.CountFlowsByAsset(asset.ID, "user1"); n != 0 {
		t.Errorf("flows remained after cascade: %d", n)
	}
	if n, _ := repo.CountPacketsByAsset(asset.ID, "user1"); n != 0 {
		t.Errorf("packets remained after cascade: %d", n)
	}
	if err := repo.DeleteAsset(asset.ID); err != nil {
		t.Fatalf("DeleteAsset: %v", err)
	}
	if _, err := repo.GetAsset(asset.ID, "user1"); err != gorm.ErrRecordNotFound {
		t.Errorf("asset not deleted: %v", err)
	}
}

// TestPcapRepository_ListAssets verifies user isolation, status filter, and
// pagination on the asset list.
func TestPcapRepository_ListAssets(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)
	for i := 0; i < 3; i++ {
		a := assetFixture("user1", "cap"+string(rune('A'+i)), "h"+string(rune('A'+i)))
		a.Status = "ready"
		repo.CreateAsset(a)
	}
	// Different user.
	repo.CreateAsset(assetFixture("user2", "other", "ho"))

	items, total, err := repo.ListAssets("user1", 1, 10, "")
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Errorf("user1 list: got total=%d items=%d, want 3/3", total, len(items))
	}
	// Status filter.
	items, total, _ = repo.ListAssets("user1", 1, 10, "ready")
	if total != 3 || len(items) != 3 {
		t.Errorf("ready filter: got %d/%d, want 3/3", total, len(items))
	}
	items, total, _ = repo.ListAssets("user1", 1, 10, "error")
	if total != 0 || len(items) != 0 {
		t.Errorf("error filter: got %d/%d, want 0/0", total, len(items))
	}
	// Pagination.
	items, total, _ = repo.ListAssets("user1", 1, 2, "")
	if total != 3 || len(items) != 2 {
		t.Errorf("page1 size2: got %d/%d, want total=3 items=2", total, len(items))
	}
	items, total, _ = repo.ListAssets("user1", 2, 2, "")
	if total != 3 || len(items) != 1 {
		t.Errorf("page2 size2: got %d/%d, want total=3 items=1", total, len(items))
	}
}

// TestPcapRepository_ListPacketsByFlow_Ordering verifies the composite index
// backs in-flow ordered pagination: packets come back in IndexInFlow order
// regardless of insertion order.
func TestPcapRepository_ListPacketsByFlow_Ordering(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)
	asset := assetFixture("user1", "cap", "h")
	asset.Status = "ready"
	repo.CreateAsset(asset)
	flow := flowFixture(asset.ID, "user1", "k")

	// Insert out of order: index 2, 0, 1.
	pkts := []PacketModel{
		packetFixture(asset.ID, flow.ID, "user1", 2, 3000),
		packetFixture(asset.ID, flow.ID, "user1", 0, 1000),
		packetFixture(asset.ID, flow.ID, "user1", 1, 2000),
	}
	if err := repo.CreatePackets(pkts); err != nil {
		t.Fatalf("CreatePackets: %v", err)
	}
	got, total, err := repo.ListPacketsByFlow(flow.ID, "user1", 1, 10)
	if err != nil {
		t.Fatalf("ListPacketsByFlow: %v", err)
	}
	if total != 3 || len(got) != 3 {
		t.Fatalf("got total=%d items=%d, want 3/3", total, len(got))
	}
	for i, p := range got {
		if p.IndexInFlow != i {
			t.Errorf("packet[%d].IndexInFlow=%d, want %d (not ordered)", i, p.IndexInFlow, i)
		}
	}
}

// TestPcapRepository_SearchFlows verifies the flow-level SQL filter narrows by
// indexed columns within an asset.
func TestPcapRepository_SearchFlows(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)
	asset := assetFixture("user1", "cap", "h")
	asset.Status = "ready"
	repo.CreateAsset(asset)

	tcpFlow := flowFixture(asset.ID, "user1", "kt")
	tcpFlow.L7Protocol = "http"
	tcpFlow.L7Method = "GET"
	udpFlow := flowFixture(asset.ID, "user1", "ku")
	udpFlow.L4Protocol = "udp"
	udpFlow.FlowKey = "ku"
	repo.CreateFlows([]FlowModel{tcpFlow, udpFlow})

	// Filter by protocol=tcp.
	got, total, err := repo.SearchFlows(asset.ID, "user1", map[string]interface{}{"l4_protocol": "tcp"}, 1, 10)
	if err != nil {
		t.Fatalf("SearchFlows tcp: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].ID != tcpFlow.ID {
		t.Errorf("tcp filter: got total=%d items=%d, want 1 tcp flow", total, len(got))
	}
	// Filter by L7 method.
	got, total, _ = repo.SearchFlows(asset.ID, "user1", map[string]interface{}{"l7_method": "GET"}, 1, 10)
	if total != 1 || got[0].ID != tcpFlow.ID {
		t.Errorf("l7_method=GET: got total=%d, want 1", total)
	}
	// Empty filter values are skipped -> returns all flows in asset.
	got, total, _ = repo.SearchFlows(asset.ID, "user1", map[string]interface{}{"l7_method": ""}, 1, 10)
	if total != 2 {
		t.Errorf("empty filter: got total=%d, want 2", total)
	}
	// Non-allowlisted column keys are skipped by the allowlist guard. The
	// primary SQL-injection protection is gorm's parameterization (values are
	// `?`-bound) plus its per-clause parenthesization; the allowlist is
	// defense-in-depth so only known column names ever reach the SQL. This test
	// verifies the end-to-end behavior: a crafted non-allowlisted key does not
	// corrupt the result set (no cross-asset leak, no error). A second asset
	// with its own flow is added so the crafted key -- if it ever reached SQL
	// unparenthesized -- would leak that flow into asset's page.
	asset2 := assetFixture("user1", "cap2", "h2")
	asset2.Status = "ready"
	repo.CreateAsset(asset2)
	otherFlow := flowFixture(asset2.ID, "user1", "k2")
	repo.CreateFlows([]FlowModel{otherFlow})
	got, total, _ = repo.SearchFlows(asset.ID, "user1", map[string]interface{}{"1=1 OR pcap_asset_id": asset2.ID}, 1, 10)
	if total != 2 {
		t.Errorf("non-allowlisted filter corrupted result set: got total=%d, want 2", total)
	}
	_ = got
}

// TestPcapRepository_CountReplayReferences verifies the delete reference check:
// a replay strategy whose config JSON references the asset is counted.
func TestPcapRepository_CountReplayReferences(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)

	// Create a replay strategy referencing asset "ast1".
	strat := &StrategyModel{
		ID:        uuid.New().String(),
		UserID:    "user1",
		Name:      "replay1",
		Protocol:  "replay",
		Config:    `{"pcap_asset_id":"ast1","speed":{"mode":"original"}}`,
	}
	if err := db.Create(strat).Error; err != nil {
		t.Fatalf("create strategy: %v", err)
	}

	n, err := repo.CountReplayReferences("ast1")
	if err != nil {
		t.Fatalf("CountReplayReferences: %v", err)
	}
	if n != 1 {
		t.Errorf("references for ast1 = %d, want 1", n)
	}
	n, _ = repo.CountReplayReferences("ast2")
	if n != 0 {
		t.Errorf("references for ast2 = %d, want 0", n)
	}

	// A non-replay strategy with the same asset id must NOT be counted.
	other := &StrategyModel{
		ID:       uuid.New().String(),
		UserID:   "user1",
		Name:     "tcp1",
		Protocol: "tcp",
		Config:   `{"pcap_asset_id":"ast1"}`,
	}
	db.Create(other)
	n, _ = repo.CountReplayReferences("ast1")
	if n != 1 {
		t.Errorf("non-replay strategy counted: references=%d, want 1", n)
	}

	// Robustness: a replay strategy with empty or malformed config must NOT
	// cause CountReplayReferences to error (which would block all deletions).
	// It is simply skipped.
	for _, badConfig := range []string{"", "not json", "{broken"} {
		bad := &StrategyModel{
			ID:       uuid.New().String(),
			UserID:   "user1",
			Name:     "bad",
			Protocol: "replay",
			Config:   badConfig,
		}
		db.Create(bad)
	}
	n, err = repo.CountReplayReferences("ast1")
	if err != nil {
		t.Fatalf("CountReplayReferences errored on malformed config: %v", err)
	}
	if n != 1 {
		t.Errorf("after adding malformed-config strategies, references for ast1 = %d, want 1", n)
	}
}

// TestPcapRepository_UpdateAssetStatus_ClearsError verifies that transitioning
// from "error" (with a parse_error message) to "ready" via UpdateAssetStatus
// CLEARS the stale parse_error, rather than leaving it behind.
func TestPcapRepository_UpdateAssetStatus_ClearsError(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)
	asset := assetFixture("user1", "cap", "h")
	asset.Status = "error"
	asset.ParseError = "bad pcap: truncated"
	if err := repo.CreateAsset(asset); err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	// Reparse succeeds: status -> ready, no new error.
	if err := repo.UpdateAssetStatus(asset.ID, "ready", ""); err != nil {
		t.Fatalf("UpdateAssetStatus: %v", err)
	}
	got, _ := repo.GetAsset(asset.ID, "user1")
	if got.Status != "ready" {
		t.Errorf("status = %q, want ready", got.Status)
	}
	if got.ParseError != "" {
		t.Errorf("parse_error not cleared on success: got %q, want empty", got.ParseError)
	}

	// And setting an error message works too.
	repo.UpdateAssetStatus(asset.ID, "error", "boom")
	got, _ = repo.GetAsset(asset.ID, "user1")
	if got.ParseError != "boom" {
		t.Errorf("parse_error not set: got %q, want boom", got.ParseError)
	}
}

// TestPcapRepository_ListPacketsByAsset_PaginationStable verifies that packets
// sharing the same timestamp_us (common in high-throughput captures) paginate
// deterministically: no row is skipped or duplicated across pages. The id
// tiebreaker in the ORDER BY guarantees a stable total order.
func TestPcapRepository_ListPacketsByAsset_PaginationStable(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)
	asset := assetFixture("user1", "cap", "h")
	asset.Status = "ready"
	repo.CreateAsset(asset)
	flow := flowFixture(asset.ID, "user1", "k")

	// 5 packets ALL with the same timestamp -> would be non-deterministic
	// without the id tiebreaker.
	const N = 5
	pkts := make([]PacketModel, N)
	for i := 0; i < N; i++ {
		pkts[i] = packetFixture(asset.ID, flow.ID, "user1", i, 5000) // same ts
	}
	if err := repo.CreatePackets(pkts); err != nil {
		t.Fatalf("CreatePackets: %v", err)
	}

	// Paginate 2-at-a-time across the 5 packets, collect all IDs.
	seen := map[string]bool{}
	for page := 1; page <= 3; page++ {
		got, _, err := repo.ListPacketsByAsset(asset.ID, "user1", page, 2)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		for _, p := range got {
			if seen[p.ID] {
				t.Errorf("packet %s duplicated across pages (pagination not stable)", p.ID)
			}
			seen[p.ID] = true
		}
	}
	if len(seen) != N {
		t.Errorf("saw %d unique packets across pages, want %d (some skipped)", len(seen), N)
	}
}

// FragOffset=-1 (the sentinel for "not a fragment") by default, and that an
// empty AnomalyFlag round-trips through the DB.
func TestPcapModels_DefaultFragOffset(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)
	asset := assetFixture("user1", "cap", "h")
	asset.Status = "ready"
	repo.CreateAsset(asset)
	flow := flowFixture(asset.ID, "user1", "k")

	p := packetFixture(asset.ID, flow.ID, "user1", 0, 1000)
	p.FragOffset = -1
	p.AnomalyFlag = ""
	repo.CreatePackets([]PacketModel{p})

	got, _, _ := repo.ListPacketsByFlow(flow.ID, "user1", 1, 10)
	if len(got) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(got))
	}
	if got[0].FragOffset != -1 {
		t.Errorf("FragOffset round-trip: got %d, want -1", got[0].FragOffset)
	}
	if got[0].AnomalyFlag != "" {
		t.Errorf("AnomalyFlag round-trip: got %q, want empty", got[0].AnomalyFlag)
	}
}

// TestPcapRepository_ListFlowsByAsset_Pagination creates 5 flows with distinct
// first_ts_us values and verifies pagination (page 1 size 2, page 2 size 2,
// page 3 size 1) and ordering.
func TestPcapRepository_ListFlowsByAsset_Pagination(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)
	asset := assetFixture("user1", "cap", "h")
	asset.Status = "ready"
	repo.CreateAsset(asset)

	// 5 flows with increasing first_ts_us so ordering is deterministic.
	for i := 0; i < 5; i++ {
		f := flowFixture(asset.ID, "user1", "k"+string(rune('A'+i)))
		f.FirstTsUs = int64(1000 + i*100)
		repo.CreateFlows([]FlowModel{f})
	}

	// Page 1 size 2
	items, total, err := repo.ListFlowsByAsset(asset.ID, "user1", 1, 2)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(items) != 2 {
		t.Fatalf("page 1 items = %d, want 2", len(items))
	}
	if items[0].FirstTsUs != 1000 || items[1].FirstTsUs != 1100 {
		t.Errorf("page 1 order: got FirstTsUs %d,%d; want 1000,1100", items[0].FirstTsUs, items[1].FirstTsUs)
	}

	// Page 2 size 2
	items, total, err = repo.ListFlowsByAsset(asset.ID, "user1", 2, 2)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(items) != 2 {
		t.Fatalf("page 2 items = %d, want 2", len(items))
	}
	if items[0].FirstTsUs != 1200 || items[1].FirstTsUs != 1300 {
		t.Errorf("page 2 order: got FirstTsUs %d,%d; want 1200,1300", items[0].FirstTsUs, items[1].FirstTsUs)
	}

	// Page 3 size 2 (only 1 remaining)
	items, total, err = repo.ListFlowsByAsset(asset.ID, "user1", 3, 2)
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(items) != 1 {
		t.Fatalf("page 3 items = %d, want 1", len(items))
	}
	if items[0].FirstTsUs != 1400 {
		t.Errorf("page 3 order: got FirstTsUs %d; want 1400", items[0].FirstTsUs)
	}
}

// TestPcapRepository_ListPacketsByFlow_Pagination creates 5 packets in a flow
// and verifies pagination with page size 2.
func TestPcapRepository_ListPacketsByFlow_Pagination(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)
	asset := assetFixture("user1", "cap", "h")
	asset.Status = "ready"
	repo.CreateAsset(asset)
	flow := flowFixture(asset.ID, "user1", "k")

	pkts := make([]PacketModel, 5)
	for i := 0; i < 5; i++ {
		pkts[i] = packetFixture(asset.ID, flow.ID, "user1", i, int64(1000+i*100))
	}
	if err := repo.CreatePackets(pkts); err != nil {
		t.Fatalf("CreatePackets: %v", err)
	}

	// Page 1 size 2
	items, total, err := repo.ListPacketsByFlow(flow.ID, "user1", 1, 2)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(items) != 2 {
		t.Fatalf("page 1 items = %d, want 2", len(items))
	}
	if items[0].IndexInFlow != 0 || items[1].IndexInFlow != 1 {
		t.Errorf("page 1 order: got IndexInFlow %d,%d; want 0,1", items[0].IndexInFlow, items[1].IndexInFlow)
	}

	// Page 2 size 2
	items, total, err = repo.ListPacketsByFlow(flow.ID, "user1", 2, 2)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(items) != 2 {
		t.Fatalf("page 2 items = %d, want 2", len(items))
	}
	if items[0].IndexInFlow != 2 || items[1].IndexInFlow != 3 {
		t.Errorf("page 2 order: got IndexInFlow %d,%d; want 2,3", items[0].IndexInFlow, items[1].IndexInFlow)
	}

	// Page 3 size 2 (only 1 remaining)
	items, total, err = repo.ListPacketsByFlow(flow.ID, "user1", 3, 2)
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(items) != 1 {
		t.Fatalf("page 3 items = %d, want 1", len(items))
	}
	if items[0].IndexInFlow != 4 {
		t.Errorf("page 3 order: got IndexInFlow %d; want 4", items[0].IndexInFlow)
	}
}

// TestPcapRepository_GetFlow_NotFound verifies that GetFlow returns an error
// for a non-existent flow ID.
func TestPcapRepository_GetFlow_NotFound(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)

	_, err := repo.GetFlow("nonexistent-flow-id", "user1")
	if err != gorm.ErrRecordNotFound {
		t.Errorf("GetFlow: want ErrRecordNotFound, got %v", err)
	}
}

// TestPcapRepository_GetPacket_NotFound verifies that GetPacket returns an
// error for a non-existent packet ID.
func TestPcapRepository_GetPacket_NotFound(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)

	_, err := repo.GetPacket("nonexistent-packet-id", "user1")
	if err != gorm.ErrRecordNotFound {
		t.Errorf("GetPacket: want ErrRecordNotFound, got %v", err)
	}
}

// TestPcapRepository_CreateFlows_EmptySlice verifies that CreateFlows with an
// empty or nil slice returns nil (no error, no-op).
func TestPcapRepository_CreateFlows_EmptySlice(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)

	if err := repo.CreateFlows(nil); err != nil {
		t.Errorf("CreateFlows(nil): %v", err)
	}
	if err := repo.CreateFlows([]FlowModel{}); err != nil {
		t.Errorf("CreateFlows(empty): %v", err)
	}
}

// TestPcapRepository_CreatePackets_EmptySlice verifies that CreatePackets with
// an empty or nil slice returns nil (no error, no-op).
func TestPcapRepository_CreatePackets_EmptySlice(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)

	if err := repo.CreatePackets(nil); err != nil {
		t.Errorf("CreatePackets(nil): %v", err)
	}
	if err := repo.CreatePackets([]PacketModel{}); err != nil {
		t.Errorf("CreatePackets(empty): %v", err)
	}
}

// TestPcapRepository_CountFlowsByAsset_Zero verifies that CountFlowsByAsset
// returns 0 for a non-existent asset.
func TestPcapRepository_CountFlowsByAsset_Zero(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)

	n, err := repo.CountFlowsByAsset("nonexistent-asset", "user1")
	if err != nil {
		t.Fatalf("CountFlowsByAsset: %v", err)
	}
	if n != 0 {
		t.Errorf("count = %d, want 0", n)
	}
}

// TestPcapRepository_CountPacketsByAsset_Zero verifies that CountPacketsByAsset
// returns 0 for a non-existent asset.
func TestPcapRepository_CountPacketsByAsset_Zero(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)

	n, err := repo.CountPacketsByAsset("nonexistent-asset", "user1")
	if err != nil {
		t.Fatalf("CountPacketsByAsset: %v", err)
	}
	if n != 0 {
		t.Errorf("count = %d, want 0", n)
	}
}

// TestPcapRepository_UpdateAsset verifies that UpdateAsset persists changes to
// Name and stats fields, and that the updated values are visible via GetAsset.
func TestPcapRepository_UpdateAsset(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)
	asset := assetFixture("user1", "original", "h")
	asset.Status = "ready"
	if err := repo.CreateAsset(asset); err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	// Modify fields.
	asset.Name = "updated"
	asset.PacketCount = 1000
	asset.ByteCount = 99999
	asset.FlowCount = 42
	asset.Status = "error"
	asset.ParseError = "something went wrong"
	if err := repo.UpdateAsset(asset); err != nil {
		t.Fatalf("UpdateAsset: %v", err)
	}

	got, err := repo.GetAsset(asset.ID, "user1")
	if err != nil {
		t.Fatalf("GetAsset after update: %v", err)
	}
	if got.Name != "updated" {
		t.Errorf("Name = %q, want updated", got.Name)
	}
	if got.PacketCount != 1000 {
		t.Errorf("PacketCount = %d, want 1000", got.PacketCount)
	}
	if got.ByteCount != 99999 {
		t.Errorf("ByteCount = %d, want 99999", got.ByteCount)
	}
	if got.FlowCount != 42 {
		t.Errorf("FlowCount = %d, want 42", got.FlowCount)
	}
	if got.Status != "error" {
		t.Errorf("Status = %q, want error", got.Status)
	}
	if got.ParseError != "something went wrong" {
		t.Errorf("ParseError = %q, want something went wrong", got.ParseError)
	}
}

// TestPcapRepository_ListAllPacketsByAsset verifies that packets are returned
// in raw_offset order (capture file order), regardless of insertion order.
func TestPcapRepository_ListAllPacketsByAsset(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)
	asset := assetFixture("user1", "cap", "h")
	asset.Status = "ready"
	repo.CreateAsset(asset)
	flow := flowFixture(asset.ID, "user1", "k")

	// Insert out of raw_offset order: 300, 100, 200.
	pkts := []PacketModel{
		packetFixture(asset.ID, flow.ID, "user1", 2, 3000),
		packetFixture(asset.ID, flow.ID, "user1", 0, 1000),
		packetFixture(asset.ID, flow.ID, "user1", 1, 2000),
	}
	// Override RawOffset to match the out-of-order pattern.
	pkts[0].RawOffset = 300
	pkts[1].RawOffset = 100
	pkts[2].RawOffset = 200
	if err := repo.CreatePackets(pkts); err != nil {
		t.Fatalf("CreatePackets: %v", err)
	}

	got, err := repo.ListAllPacketsByAsset(asset.ID, "user1")
	if err != nil {
		t.Fatalf("ListAllPacketsByAsset: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d packets, want 3", len(got))
	}
	for i, p := range got {
		expected := int64(100 + i*100)
		if p.RawOffset != expected {
			t.Errorf("packet[%d].RawOffset = %d, want %d (not in raw_offset order)", i, p.RawOffset, expected)
		}
	}
}

// TestPcapRepository_DeleteAsset_NotFound verifies that deleting a non-existent
// asset returns nil (gorm's Delete is idempotent — no rows affected is not an
// error).
func TestPcapRepository_DeleteAsset_NotFound(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)

	if err := repo.DeleteAsset("nonexistent-asset"); err != nil {
		t.Errorf("DeleteAsset(nonexistent): %v, want nil", err)
	}
}
// TestPcapRepository_FullPull_SizeZero: size=0 = 全量拉取（用户裁定
// 2026-10-04，翻页可选）——三个列表方法都不得加 LIMIT。
func TestPcapRepository_FullPull_SizeZero(t *testing.T) {
	db, _ := newTestDB(t)
	repo := NewPcapRepository(db)
	asset := assetFixture("user1", "cap", "h")
	asset.Status = "ready"
	repo.CreateAsset(asset)

	for i := 0; i < 7; i++ {
		f := flowFixture(asset.ID, "user1", "k"+string(rune('A'+i)))
		f.FirstTsUs = int64(1000 + i*100)
		repo.CreateFlows([]FlowModel{f})
	}
	fl := flowFixture(asset.ID, "user1", "pk")
	fl.FirstTsUs = 900
	repo.CreateFlows([]FlowModel{fl})

	// ListFlowsByAsset size=0 → 全部 8 条（分页时单页最多 500，这里走全量分支）。
	items, total, err := repo.ListFlowsByAsset(asset.ID, "user1", 1, 0)
	if err != nil {
		t.Fatalf("flows full pull: %v", err)
	}
	if total != 8 || len(items) != 8 {
		t.Fatalf("flows full pull: total=%d items=%d, want 8/8", total, len(items))
	}

	// ListPacketsByAsset size=0 → 全部（造 3 包验证）。
	var pkts []PacketModel
	for i := 0; i < 3; i++ {
		p := packetFixture(asset.ID, fl.ID, "user1", i, int64(100+i))
		pkts = append(pkts, p)
	}
	repo.CreatePackets(pkts)
	items2, total2, err := repo.ListPacketsByAsset(asset.ID, "user1", 1, 0)
	if err != nil {
		t.Fatalf("packets full pull: %v", err)
	}
	if total2 != 3 || len(items2) != 3 {
		t.Fatalf("packets full pull: total=%d items=%d, want 3/3", total2, len(items2))
	}

	// 分页语义不受影响：size=3 仍只回 3 条。
	items3, _, err := repo.ListFlowsByAsset(asset.ID, "user1", 1, 3)
	if err != nil {
		t.Fatalf("paged: %v", err)
	}
	if len(items3) != 3 {
		t.Fatalf("paged items = %d, want 3", len(items3))
	}
}
