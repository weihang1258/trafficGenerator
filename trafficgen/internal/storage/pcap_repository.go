package storage

import (
	"encoding/json"
	"fmt"
	"os"

	"gorm.io/gorm"
)

// PcapRepository provides database operations for PCAP assets and their
// derived FlowModel/PacketModel tables. The pcap file on disk is the source of
// truth; these tables hold pointers + aggregates (§15/§17).
type PcapRepository struct {
	db *DB
}

// NewPcapRepository creates a new pcap repository.
func NewPcapRepository(db *DB) *PcapRepository {
	return &PcapRepository{db: db}
}

// ---------------- PcapAsset ----------------

// CreateAsset creates a new pcap asset record.
func (r *PcapRepository) CreateAsset(asset *PcapAssetModel) error {
	return r.db.Create(asset).Error
}

// GetAsset retrieves a pcap asset by ID, scoped to the owning user (defense-in-
// depth isolation: a caller passing another user's ID gets ErrRecordNotFound).
func (r *PcapRepository) GetAsset(id, userID string) (*PcapAssetModel, error) {
	var asset PcapAssetModel
	if err := r.db.Where("id = ? AND user_id = ?", id, userID).First(&asset).Error; err != nil {
		return nil, err
	}
	return &asset, nil
}

// GetAssetByHash retrieves a ready/ready-or-error pcap asset by content hash.
// Used for import deduplication (§15.6): a re-upload of the same file returns
// the existing asset. Only matches assets owned by userID for isolation.
func (r *PcapRepository) GetAssetByHash(userID, fileHash string) (*PcapAssetModel, error) {
	var asset PcapAssetModel
	err := r.db.Where("user_id = ? AND file_hash = ?", userID, fileHash).First(&asset).Error
	if err != nil {
		return nil, err
	}
	return &asset, nil
}

// UpdateAsset saves all fields of an asset (status/stats/paths/etc.).
func (r *PcapRepository) UpdateAsset(asset *PcapAssetModel) error {
	return r.db.Save(asset).Error
}

// validStatusTransitions defines the legal status state machine (§15.2):
// importing -> ready|error; ready -> reindexing|error; reindexing -> ready|error;
// error -> reindexing|importing|ready (retry/reparse). Blocks illegal rewinds
// like ready->importing (would mark a ready asset as mid-import with no import
// running, sticking it forever).
var validStatusTransitions = map[string]map[string]bool{
	"importing":  {"ready": true, "error": true, "importing": true},
	"ready":      {"reindexing": true, "error": true},
	"reindexing": {"ready": true, "error": true},
	"error":      {"reindexing": true, "importing": true, "ready": true},
	"":           {"importing": true}, // new asset
}

// UpdateAssetStatus patches the status and parse_error of an asset, enforcing
// the status state machine (§15.2). parseErr is ALWAYS written (empty string
// clears a prior error), so a transition out of "error"/"importing" into "ready"
// does not leave a stale error message. Returns gorm.ErrRecordNotFound if the
// asset doesn't exist, or an error describing the illegal transition.
func (r *PcapRepository) UpdateAssetStatus(id, status, parseErr string) error {
	// Read current status to validate the transition.
	var current PcapAssetModel
	if err := r.db.Select("status").First(&current, "id = ?", id).Error; err != nil {
		return err
	}
	allowed, ok := validStatusTransitions[current.Status]
	if !ok || !allowed[status] {
		return fmt.Errorf("illegal status transition %q -> %q", current.Status, status)
	}
	updates := map[string]interface{}{
		"status":      status,
		"parse_error": parseErr,
	}
	return r.db.Model(&PcapAssetModel{}).Where("id = ?", id).Updates(updates).Error
}

// ListAssets lists pcap assets for a user with pagination. status filters by
// asset status (empty = all). Returns items + total count.
func (r *PcapRepository) ListAssets(userID string, page, size int, status string) ([]PcapAssetModel, int64, error) {
	var assets []PcapAssetModel
	var total int64

	query := r.db.Model(&PcapAssetModel{}).Where("user_id = ?", userID)
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	// size == 0 = 全量拉取（用户裁定 2026-10-04）。
	if size > 0 {
		if err := query.Order("created_at DESC, id DESC").Offset((page - 1) * size).Limit(size).Find(&assets).Error; err != nil {
			return nil, 0, err
		}
	} else if err := query.Order("created_at DESC, id DESC").Find(&assets).Error; err != nil {
		return nil, 0, err
	}
	return assets, total, nil
}

// DeleteAsset deletes a pcap asset record. Does NOT cascade to flows/packets --
// call DeleteAssetFlowsAndPackets first (or use DeleteAssetComplete). Disk files
// are NOT removed here; use DeleteAssetComplete for atomic DB + disk cleanup.
func (r *PcapRepository) DeleteAsset(id string) error {
	return r.db.Delete(&PcapAssetModel{}, "id = ?", id).Error
}

// DeleteAssetComplete atomically deletes an asset's DB records (asset + flows +
// packets in one transaction) and then removes its disk files (.pcap, .payloads,
// .trigram). §15.5 requires "删磁盘文件 + 删 DB 记录" as one operation: if the DB
// delete fails, disk files are left intact (no orphaned files referencing a
// live record); if disk removal fails after the DB commit, the asset is gone
// from the DB so the stale files are harmless leftover (logged, not fatal).
// Returns the asset (with file paths) so the caller can close cached handles.
func (r *PcapRepository) DeleteAssetComplete(id string) (*PcapAssetModel, error) {
	var asset PcapAssetModel
	if err := r.db.First(&asset, "id = ?", id).Error; err != nil {
		return nil, err
	}
	// Transaction: delete packets + flows + asset record atomically.
	if err := r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("pcap_asset_id = ?", id).Delete(&PacketModel{}).Error; err != nil {
			return fmt.Errorf("delete packets: %w", err)
		}
		if err := tx.Where("pcap_asset_id = ?", id).Delete(&FlowModel{}).Error; err != nil {
			return fmt.Errorf("delete flows: %w", err)
		}
		if err := tx.Where("id = ?", id).Delete(&PcapAssetModel{}).Error; err != nil {
			return fmt.Errorf("delete asset: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	// DB commit succeeded -- remove disk files. Best-effort: a failure here
	// leaves harmless stale files (the DB record is gone), so log and continue.
	for _, path := range []string{asset.StoragePath, asset.PayloadsPath, asset.TrigramIndexPath} {
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			// Non-fatal: file may be locked or already gone. Caller can retry.
			fmt.Printf("warn: delete asset file %s: %v\n", path, err)
		}
	}
	return &asset, nil
}

// DeleteAssetFlowsAndPackets removes all FlowModel + PacketModel rows owned by
// an asset. Used on asset delete and on reparse (before re-inserting). Runs in
// a transaction so a partial delete cannot leave orphaned flows/packets.
func (r *PcapRepository) DeleteAssetFlowsAndPackets(assetID string) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("pcap_asset_id = ?", assetID).Delete(&PacketModel{}).Error; err != nil {
			return fmt.Errorf("delete packets: %w", err)
		}
		if err := tx.Where("pcap_asset_id = ?", assetID).Delete(&FlowModel{}).Error; err != nil {
			return fmt.Errorf("delete flows: %w", err)
		}
		return nil
	})
}

// CountReplayReferences counts strategies AND running tasks referencing a pcap
// asset (§15.5/§15.6): a referenced asset cannot be deleted without force.
//
// Strategy references: protocol "replay" with config.pcap_asset_id == assetID.
// Task references: running tasks (status pending/running) whose BatchConfig
// contains a replay class with pcap_asset_id == assetID.
//
// We load + parse JSON in Go (rather than SQL JSON-extract) for two reasons:
// (1) the JSON-extract syntax differs between SQLite and Postgres, and (2)
// json_extract ERRORS on malformed config, which would block ALL deletions if
// even one strategy/task had corrupt config. Go-side parsing tolerates
// malformed config (skips it) and is dialect-agnostic.
func (r *PcapRepository) CountReplayReferences(assetID string) (int64, error) {
	var count int64
	// 1. Strategy references.
	var strategies []StrategyModel
	if err := r.db.Select("config").Where("protocol = ?", "replay").Find(&strategies).Error; err != nil {
		return 0, err
	}
	for _, s := range strategies {
		var cfg struct {
			PcapAssetID string `json:"pcap_asset_id"`
		}
		if s.Config == "" {
			continue
		}
		if err := json.Unmarshal([]byte(s.Config), &cfg); err != nil {
			continue // malformed config: skip rather than fail deletions
		}
		if cfg.PcapAssetID == assetID {
			count++
		}
	}
	// 2. Running-task references (§15.5: "查 TaskModel：有无运行中任务引用").
	var tasks []TaskModel
	if err := r.db.Select("batch_config").Where("status IN ?", []string{"pending", "running"}).Find(&tasks).Error; err != nil {
		return 0, err
	}
	for _, tk := range tasks {
		if tk.BatchConfig == "" {
			continue
		}
		var batch struct {
			Classes []struct {
				Type   string          `json:"type"`
				Replay json.RawMessage `json:"replay"`
			} `json:"classes"`
		}
		if err := json.Unmarshal([]byte(tk.BatchConfig), &batch); err != nil {
			continue // malformed: skip
		}
		for _, c := range batch.Classes {
			if c.Type != "replay" || len(c.Replay) == 0 {
				continue
			}
			var rc struct {
				PcapAssetID string `json:"pcap_asset_id"`
			}
			if err := json.Unmarshal(c.Replay, &rc); err != nil {
				continue
			}
			if rc.PcapAssetID == assetID {
				count++
				break // one match per task is enough
			}
		}
	}
	return count, nil
}

// ---------------- FlowModel ----------------

// CreateFlows batch-inserts flow records. gorm CreateInBatches keeps memory
// bounded for pcaps with many flows. Batch 500, not 1000: SQLite binds every
// column of every row in one statement, and FlowModel has ~54 columns —
// 54×1000 host parameters blows past the 32766 limit (PacketModel is slim at
// ~15, so packets alone never tripped it) — "SQL logic error: too
// many SQL variables" surfaced only on large registrations (P1-17, 15000-flow
// task completed but auto-register failed silently).
func (r *PcapRepository) CreateFlows(flows []FlowModel) error {
	if len(flows) == 0 {
		return nil
	}
	return r.db.CreateInBatches(flows, 500).Error
}

// ListFlowsByAsset lists flows for an asset (scoped to userID) with pagination,
// ordered by first packet timestamp (natural capture order).
func (r *PcapRepository) ListFlowsByAsset(assetID, userID string, page, size int) ([]FlowModel, int64, error) {
	var flows []FlowModel
	var total int64
	query := r.db.Model(&FlowModel{}).Where("pcap_asset_id = ? AND user_id = ?", assetID, userID)
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	// size == 0 = 全量拉取（用户裁定 2026-10-04）。显式守卫——gorm 的
	// Limit(0) 语义不是"无限制"。
	if size > 0 {
		if err := query.Order("first_ts_us ASC, id ASC").Offset((page - 1) * size).Limit(size).Find(&flows).Error; err != nil {
			return nil, 0, err
		}
	} else if err := query.Order("first_ts_us ASC, id ASC").Find(&flows).Error; err != nil {
		return nil, 0, err
	}
	return flows, total, nil
}

// GetFlow retrieves a single flow by ID, scoped to the owning user.
func (r *PcapRepository) GetFlow(flowID, userID string) (*FlowModel, error) {
	var flow FlowModel
	if err := r.db.Where("id = ? AND user_id = ?", flowID, userID).First(&flow).Error; err != nil {
		return nil, err
	}
	return &flow, nil
}

// CountFlowsByAsset returns the number of flows for an asset, scoped to userID.
func (r *PcapRepository) CountFlowsByAsset(assetID, userID string) (int64, error) {
	var count int64
	return count, r.db.Model(&FlowModel{}).Where("pcap_asset_id = ? AND user_id = ?", assetID, userID).Count(&count).Error
}

// ---------------- PacketModel ----------------

// CreatePackets batch-inserts packet records. Batched to bound memory for large
// pcaps (1M+ packets); 500 per batch — see CreateFlows for the SQLite host-
// parameter ceiling (P1-17).
func (r *PcapRepository) CreatePackets(packets []PacketModel) error {
	if len(packets) == 0 {
		return nil
	}
	return r.db.CreateInBatches(packets, 500).Error
}

// ListPacketsByFlow lists packets for a flow (scoped to userID), ordered by
// in-flow index (the composite index idx_pkt_flow_seq serves this). Paginated.
func (r *PcapRepository) ListPacketsByFlow(flowID, userID string, page, size int) ([]PacketModel, int64, error) {
	var packets []PacketModel
	var total int64
	query := r.db.Model(&PacketModel{}).Where("flow_id = ? AND user_id = ?", flowID, userID)
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	// size == 0 = 全量拉取（用户裁定 2026-10-04）。显式守卫——gorm 的
	// Limit(0) 语义不是"无限制"。
	if size > 0 {
		if err := query.Order("index_in_flow ASC, id ASC").Offset((page - 1) * size).Limit(size).Find(&packets).Error; err != nil {
			return nil, 0, err
		}
	} else if err := query.Order("index_in_flow ASC, id ASC").Find(&packets).Error; err != nil {
		return nil, 0, err
	}
	return packets, total, nil
}

// ListPacketsByAsset lists packets for an asset (scoped to userID), ordered by
// capture timestamp. Paginated. Used by the asset packet-list view.
func (r *PcapRepository) ListPacketsByAsset(assetID, userID string, page, size int) ([]PacketModel, int64, error) {
	var packets []PacketModel
	var total int64
	query := r.db.Model(&PacketModel{}).Where("pcap_asset_id = ? AND user_id = ?", assetID, userID)
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	// size == 0 = 全量拉取（用户裁定 2026-10-04）。显式守卫——gorm 的
	// Limit(0) 语义不是"无限制"。
	if size > 0 {
		if err := query.Order("timestamp_us ASC, id ASC").Offset((page - 1) * size).Limit(size).Find(&packets).Error; err != nil {
			return nil, 0, err
		}
	} else if err := query.Order("timestamp_us ASC, id ASC").Find(&packets).Error; err != nil {
		return nil, 0, err
	}
	return packets, total, nil
}

// ListAllPacketsByAsset loads all packets for an asset (scoped to userID) in
// file order (by RawOffset, the byte offset in the pcap). Used by the replay
// planner to emit packets in capture/file order (§13 fidelity).
func (r *PcapRepository) ListAllPacketsByAsset(assetID, userID string) ([]PacketModel, error) {
	var packets []PacketModel
	if err := r.db.Where("pcap_asset_id = ? AND user_id = ?", assetID, userID).Order("raw_offset ASC").Find(&packets).Error; err != nil {
		return nil, err
	}
	return packets, nil
}

// GetPacket retrieves a single packet by ID, scoped to the owning user.
func (r *PcapRepository) GetPacket(packetID, userID string) (*PacketModel, error) {
	var packet PacketModel
	if err := r.db.Where("id = ? AND user_id = ?", packetID, userID).First(&packet).Error; err != nil {
		return nil, err
	}
	return &packet, nil
}

// CountPacketsByAsset returns the number of packets for an asset, scoped to userID.
func (r *PcapRepository) CountPacketsByAsset(assetID, userID string) (int64, error) {
	var count int64
	return count, r.db.Model(&PacketModel{}).Where("pcap_asset_id = ? AND user_id = ?", assetID, userID).Count(&count).Error
}

// flowFilterColumns is the allowlist of FlowModel columns that may appear in a
// SearchFlows filter. Interpolating arbitrary column names into SQL would be an
// injection vector; only these exact names are accepted (value is still
// parameterized).
var flowFilterColumns = map[string]bool{
	"l4_protocol": true, "ip_version": true, "src_ip": true, "dst_ip": true,
	"src_port": true, "dst_port": true, "l7_protocol": true, "l7_method": true,
	"l7_host": true, "l7_query_name": true, "dir_status": true,
}

// SearchFlows runs a flow-level SQL filter (§17.10 FlowFilter), scoped to
// userID. filters is a map of column -> value for exact-match indexed columns.
// Empty values and columns not in the allowlist are skipped (the latter is a
// defensive no-op, never an error, so callers can pass user-supplied filter
// keys directly).
func (r *PcapRepository) SearchFlows(assetID, userID string, filters map[string]interface{}, page, size int) ([]FlowModel, int64, error) {
	var flows []FlowModel
	var total int64
	query := r.db.Model(&FlowModel{}).Where("pcap_asset_id = ? AND user_id = ?", assetID, userID)
	for col, val := range filters {
		if !flowFilterColumns[col] {
			continue
		}
		if s, ok := val.(string); ok && s == "" {
			continue
		}
		query = query.Where(col+" = ?", val)
	}
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	// size == 0 = 全量拉取（用户裁定 2026-10-04）。显式守卫——gorm 的
	// Limit(0) 语义不是"无限制"。
	if size > 0 {
		if err := query.Order("first_ts_us ASC, id ASC").Offset((page - 1) * size).Limit(size).Find(&flows).Error; err != nil {
			return nil, 0, err
		}
	} else if err := query.Order("first_ts_us ASC, id ASC").Find(&flows).Error; err != nil {
		return nil, 0, err
	}
	return flows, total, nil
}
