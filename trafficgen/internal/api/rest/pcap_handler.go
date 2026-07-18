package rest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/pcapparser"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/auth"
)

// PcapHandler exposes PCAP asset management + query endpoints (§15/§19).
type PcapHandler struct {
	repo    *storage.PcapRepository
	db      *storage.DB
	dataDir string // where {id}.pcap / .payloads / .trigram live
}

// NewPcapHandler creates a handler. dataDir defaults to "./data/pcaps".
func NewPcapHandler(db *storage.DB, dataDir string) *PcapHandler {
	if dataDir == "" {
		dataDir = "./data/pcaps"
	}
	return &PcapHandler{repo: storage.NewPcapRepository(db), db: db, dataDir: dataDir}
}

// Import uploads a pcap file, validates it, parses it, and stores the asset +
// derived FlowModel/PacketModel + .payloads (§15.3).
// POST /api/v1/pcaps  (multipart: field "file")
func (h *PcapHandler) Import(c *gin.Context) {
	userID := auth.GetUserID(c)
	file, err := c.FormFile("file")
	if err != nil {
		BadRequest(c, "file is required (multipart field 'file')")
		return
	}
	// Size cap (default 2GB, §15.6).
	if file.Size > 2*1024*1024*1024 {
		BadRequest(c, fmt.Sprintf("file too large: %d bytes (max 2GB)", file.Size))
		return
	}
	// Read + hash for dedup.
	src, err := file.Open()
	if err != nil {
		InternalError(c, "open upload: "+err.Error())
		return
	}
	defer src.Close()
	tmpPath := filepath.Join(h.dataDir, uuid.New().String()+".pcap.tmp")
	if err := os.MkdirAll(h.dataDir, 0o755); err != nil {
		InternalError(c, "mkdir data dir: "+err.Error())
		return
	}
	dst, err := os.Create(tmpPath)
	if err != nil {
		InternalError(c, "create temp file: "+err.Error())
		return
	}
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(dst, hasher), src); err != nil {
		dst.Close()
		os.Remove(tmpPath)
		InternalError(c, "save upload: "+err.Error())
		return
	}
	dst.Close()
	fileHash := hex.EncodeToString(hasher.Sum(nil))

	// Dedup: if an asset with this hash exists for this user, remove temp + return it.
	if existing, err := h.repo.GetAssetByHash(userID, fileHash); err == nil && existing != nil {
		os.Remove(tmpPath)
		Success(c, existing)
		return
	}

	assetID := uuid.New().String()
	pcapPath := filepath.Join(h.dataDir, assetID+".pcap")
	if err := os.Rename(tmpPath, pcapPath); err != nil {
		os.Remove(tmpPath)
		InternalError(c, "finalize pcap file: "+err.Error())
		return
	}
	payloadsPath := filepath.Join(h.dataDir, assetID+".payloads")

	// Create the asset record (importing), then parse.
	asset := &storage.PcapAssetModel{
		ID:            assetID,
		UserID:        userID,
		Name:          file.Filename,
		OriginalFilename: file.Filename,
		StoragePath:   pcapPath,
		PayloadsPath:  payloadsPath,
		FileHash:      fileHash,
		FileSize:      file.Size,
		Status:        "importing",
		LinkType:      1, // DLT_EN10MB
	}
	if err := h.repo.CreateAsset(asset); err != nil {
		// Concurrent-import dedup (§15.6): the (user_id, file_hash) unique index
		// may reject this Create if another goroutine uploaded the same file
		// between our GetAssetByHash check and here. Re-fetch the winner and
		// return it instead of failing.
		if existing, err2 := h.repo.GetAssetByHash(userID, fileHash); err2 == nil && existing != nil {
			os.Remove(pcapPath)
			Success(c, existing)
			return
		}
		os.Remove(pcapPath)
		InternalError(c, "create asset: "+err.Error())
		return
	}

	// Parse (synchronous for v1; async is an optimization for large pcaps).
	analysis, err := pcapparser.Parse(pcapPath, &pcapparser.Options{
		PcapAssetID:  assetID,
		UserID:       userID,
		PayloadsPath: payloadsPath,
	})
	if err != nil {
		h.repo.UpdateAssetStatus(assetID, "error", "parse: "+err.Error())
		BadRequest(c, "parse failed: "+err.Error())
		return
	}
	// Store flows + packets.
	if err := h.repo.CreateFlows(analysis.Flows); err != nil {
		h.repo.UpdateAssetStatus(assetID, "error", "store flows: "+err.Error())
		InternalError(c, "store flows: "+err.Error())
		return
	}
	if err := h.repo.CreatePackets(analysis.Packets); err != nil {
		h.repo.UpdateAssetStatus(assetID, "error", "store packets: "+err.Error())
		InternalError(c, "store packets: "+err.Error())
		return
	}
	// Finalize asset stats.
	asset.Status = "ready"
	asset.PacketCount = analysis.PacketCount
	asset.ByteCount = analysis.ByteCount
	asset.FlowCount = analysis.FlowCount
	asset.DurationUs = analysis.DurationUs()
	asset.Snaplen = int(analysis.Snaplen)
	asset.ProtocolDist = analysis.ProtocolDistJSON()
	asset.ParserVersion = pcapparser.ParserVersion
	if err := h.repo.UpdateAsset(asset); err != nil {
		InternalError(c, "finalize asset: "+err.Error())
		return
	}
	Success(c, asset)
}

// List returns the user's pcap assets (paginated).
// GET /api/v1/pcaps?page=&size=&status=
func (h *PcapHandler) List(c *gin.Context) {
	userID := auth.GetUserID(c)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 200 {
		size = 20
	}
	status := c.Query("status")
	assets, total, err := h.repo.ListAssets(userID, page, size, status)
	if err != nil {
		InternalError(c, "list assets: "+err.Error())
		return
	}
	Success(c, gin.H{"items": assets, "total": total, "page": page, "size": size})
}

// Get returns a single asset's details.
// GET /api/v1/pcaps/:id
func (h *PcapHandler) Get(c *gin.Context) {
	asset, ok := h.getOwnedAsset(c)
	if !ok {
		return
	}
	Success(c, asset)
}

// Delete removes an asset + its flows/packets + disk files (§15.5). Rejects if
// referenced by a replay strategy (unless ?force=true).
// DELETE /api/v1/pcaps/:id
func (h *PcapHandler) Delete(c *gin.Context) {
	asset, ok := h.getOwnedAsset(c)
	if !ok {
		return
	}
	if asset.Status == "reindexing" {
		BadRequest(c, "asset is reindexing; wait for completion")
		return
	}
	// Importing-status delete = cancel-import semantics (§15.5): terminate the
	// (v1 synchronous) parse + clean up half-finished files/records. v1 import
	// is synchronous so the parse has either finished or failed by now; we still
	// allow the delete to clean up any partial state.
	isCancelImport := asset.Status == "importing"
	// Reference check (§15.5): strategies + running tasks.
	if n, _ := h.repo.CountReplayReferences(asset.ID); n > 0 && c.Query("force") != "true" {
		BadRequest(c, fmt.Sprintf("asset referenced by %d replay strateg(ies)/task(s); use ?force=true to invalidate", n))
		return
	}
	// Atomic delete: DB records (asset + flows + packets in one transaction)
	// then disk files (.pcap + .payloads + .trigram). §15.5.
	pcapparser.CloseCachedFile(asset.StoragePath)
	if _, err := h.repo.DeleteAssetComplete(asset.ID); err != nil {
		InternalError(c, "delete asset: "+err.Error())
		return
	}
	if isCancelImport {
		SuccessWithMessage(c, "import cancelled, asset and partial files removed", nil)
	} else {
		SuccessWithMessage(c, "asset deleted", nil)
	}
}

// ListFlows returns a paginated flow list for an asset.
// GET /api/v1/pcaps/:id/flows?page=&size=
func (h *PcapHandler) ListFlows(c *gin.Context) {
	asset, ok := h.getOwnedAsset(c)
	if !ok {
		return
	}
	if !h.requireReady(c, asset) {
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "50"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 500 {
		size = 50
	}
	flows, total, err := h.repo.ListFlowsByAsset(asset.ID, auth.GetUserID(c), page, size)
	if err != nil {
		InternalError(c, "list flows: "+err.Error())
		return
	}
	Success(c, gin.H{"items": flows, "total": total, "page": page, "size": size})
}

// ListPackets returns a paginated packet list for a flow.
// GET /api/v1/pcaps/:id/flows/:fid/packets?page=&size=
func (h *PcapHandler) ListPackets(c *gin.Context) {
	asset, ok := h.getOwnedAsset(c)
	if !ok {
		return
	}
	if !h.requireReady(c, asset) {
		return
	}
	userID := auth.GetUserID(c)
	flowID := c.Param("fid")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "50"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 500 {
		size = 50
	}
	// Verify the flow belongs to this asset (user-scoped query).
	flow, err := h.repo.GetFlow(flowID, userID)
	if err != nil || flow.PcapAssetID != asset.ID {
		NotFound(c, "flow")
		return
	}
	packets, total, err := h.repo.ListPacketsByFlow(flowID, userID, page, size)
	if err != nil {
		InternalError(c, "list packets: "+err.Error())
		return
	}
	Success(c, gin.H{"items": packets, "total": total, "page": page, "size": size})
}

// ListPacketsByAsset returns a paginated packet list for an asset (§17.11),
// ordered by capture timestamp. This is the by-asset view (vs ListPackets which
// is by-flow). GET /api/v1/pcaps/:id/packets?page=&size=
func (h *PcapHandler) ListPacketsByAsset(c *gin.Context) {
	asset, ok := h.getOwnedAsset(c)
	if !ok {
		return
	}
	if !h.requireReady(c, asset) {
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "50"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 500 {
		size = 50
	}
	packets, total, err := h.repo.ListPacketsByAsset(asset.ID, auth.GetUserID(c), page, size)
	if err != nil {
		InternalError(c, "list packets: "+err.Error())
		return
	}
	Success(c, gin.H{"items": packets, "total": total, "page": page, "size": size})
}

// Extract batch-extracts fields from multiple packets in one call (§17.11).
// Avoids N round-trips when a test needs expected field values across many
// packets. POST /api/v1/pcaps/:id/extract
// Body: {"packet_ids":["id1","id2"], "fields":["src_ip","dst_port",...]}
// Returns: [{"packet_id":"id1","fields":{"src_ip":"10.0.0.1",...}}, ...]
func (h *PcapHandler) Extract(c *gin.Context) {
	asset, ok := h.getOwnedAsset(c)
	if !ok {
		return
	}
	if !h.requireReady(c, asset) {
		return
	}
	var req struct {
		PacketIDs []string `json:"packet_ids"`
		Fields    []string `json:"fields"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid extract request: "+err.Error())
		return
	}
	if len(req.PacketIDs) == 0 {
		BadRequest(c, "packet_ids required")
		return
	}
	if len(req.PacketIDs) > 500 {
		BadRequest(c, "too many packet_ids (max 500)")
		return
	}
	userID := auth.GetUserID(c)
	linkType := layersLinkType(asset.LinkType)
	results := make([]gin.H, 0, len(req.PacketIDs))
	for _, pid := range req.PacketIDs {
		pkt, err := h.repo.GetPacket(pid, userID)
		if err != nil || pkt.PcapAssetID != asset.ID {
			results = append(results, gin.H{"packet_id": pid, "error": "not found"})
			continue
		}
		records, err := pcapparser.ParsePacket(asset.StoragePath, pkt.RawOffset, pkt.Length, linkType)
		if err != nil {
			results = append(results, gin.H{"packet_id": pid, "error": err.Error()})
			continue
		}
		// Collect requested fields from all layers.
		fields := gin.H{}
		for _, rec := range records {
			for _, want := range req.Fields {
				if v, ok := rec.Fields[want]; ok {
					fields[want] = v
				}
			}
		}
		results = append(results, gin.H{"packet_id": pid, "fields": fields})
	}
	Success(c, gin.H{"items": results})
}

// GetPacket returns a single packet's full fields via dynamic re-parse (§17.7).
// GET /api/v1/pcaps/:id/packets/:pid
func (h *PcapHandler) GetPacket(c *gin.Context) {
	asset, ok := h.getOwnedAsset(c)
	if !ok {
		return
	}
	if !h.requireReady(c, asset) {
		return
	}
	pid := c.Param("pid")
	pkt, err := h.repo.GetPacket(pid, auth.GetUserID(c))
	if err != nil || pkt.PcapAssetID != asset.ID {
		NotFound(c, "packet")
		return
	}
	records, err := pcapparser.ParsePacket(asset.StoragePath, pkt.RawOffset, pkt.Length, layersLinkType(asset.LinkType))
	if err != nil {
		InternalError(c, "re-parse packet: "+err.Error())
		return
	}
	Success(c, gin.H{"packet": pkt, "layers": records})
}

// Search runs a multi-condition query (§17.10). v1 uses the in-memory trigram
// index rebuilt on demand from the pcap; the DB-backed SQL variant is a future
// optimization. For correctness this re-parses the asset's flows into memory.
// POST /api/v1/pcaps/:id/search
func (h *PcapHandler) Search(c *gin.Context) {
	asset, ok := h.getOwnedAsset(c)
	if !ok {
		return
	}
	if !h.requireReady(c, asset) {
		return
	}
	var req struct {
		FlowFilter   *pcapparser.FlowFilter    `json:"flow_filter"`
		PacketFilter *pcapparser.PacketFilter  `json:"packet_filter"`
		Payload      *pcapparser.PayloadFilter `json:"payload"`
		Scope        string                    `json:"scope"`
		Limit        int                       `json:"limit"`
		Offset       int                       `json:"offset"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid query: "+err.Error())
		return
	}
	// Load flows + rebuild trigram index in memory. (For large assets this is
	// expensive; the production path persists .payloads + .trigram and queries
	// incrementally -- wired in a later tuning pass.)
	var flows []storage.FlowModel
	if err := h.db.Where("pcap_asset_id = ?", asset.ID).Find(&flows).Error; err != nil {
		InternalError(c, "load flows: "+err.Error())
		return
	}
	views := make([]pcapparser.FlowModelView, len(flows))
	idx := pcapparser.NewTrigramIndex()
	for i, f := range flows {
		views[i] = pcapparser.FlowModelView{ID: f.ID, L4Protocol: f.L4Protocol, SrcIP: f.SrcIP, DstIP: f.DstIP, SrcPort: f.SrcPort, DstPort: f.DstPort, L7Protocol: f.L7Protocol}
	}
	// Load packet views only when a packet-level filter is requested (avoids the
	// cost of loading every packet for flow/payload-only queries).
	var packetViews []pcapparser.PacketModelView
	if req.PacketFilter != nil {
		var pkts []storage.PacketModel
		if err := h.db.Where("pcap_asset_id = ?", asset.ID).Find(&pkts).Error; err != nil {
			InternalError(c, "load packets: "+err.Error())
			return
		}
		packetViews = make([]pcapparser.PacketModelView, len(pkts))
		for i, p := range pkts {
			packetViews[i] = pcapparser.PacketModelView{
				ID: p.ID, FlowID: p.FlowID, Direction: p.Direction,
				TimestampUs: p.TimestampUs, L4Protocol: p.L4Protocol, AnomalyFlag: p.AnomalyFlag,
			}
		}
	}
	// Build trigram from .payloads (TCP) + pcap (UDP). For v1 simplicity, only
	// TCP streams are indexed here; UDP payload search falls back to flow filter.
	if asset.PayloadsPath != "" {
		f, err := os.Open(asset.PayloadsPath)
		if err == nil {
			for _, fl := range flows {
				if fl.L4Protocol == "tcp" {
					h.indexStream(idx, f, fl.ID, "c2s", fl.C2SOffset, fl.C2SLength)
					h.indexStream(idx, f, fl.ID, "s2c", fl.S2COffset, fl.S2CLength)
				}
			}
			f.Close()
		}
	}
	results, err := pcapparser.Search(views, packetViews, idx, &pcapparser.SearchQuery{
		FlowFilter: req.FlowFilter, PacketFilter: req.PacketFilter, Payload: req.Payload,
		Scope: req.Scope, Limit: req.Limit, Offset: req.Offset,
	})
	if err != nil {
		BadRequest(c, "search: "+err.Error())
		return
	}
	Success(c, results)
}

// indexStream reads a reassembled stream from .payloads and adds it to the index.
func (h *PcapHandler) indexStream(idx *pcapparser.TrigramIndex, f *os.File, flowID, dir string, offset, length int64) {
	if length <= 0 {
		return
	}
	buf := make([]byte, length)
	if _, err := f.ReadAt(buf, offset); err != nil {
		return
	}
	idx.AddSegment(flowID, dir, buf)
}

// Reparse rebuilds an asset's index after a parser upgrade (§17.12).
// POST /api/v1/pcaps/:id/reparse
func (h *PcapHandler) Reparse(c *gin.Context) {
	asset, ok := h.getOwnedAsset(c)
	if !ok {
		return
	}
	if asset.Status == "reindexing" {
		BadRequest(c, "asset is already reindexing")
		return
	}
	h.repo.UpdateAssetStatus(asset.ID, "reindexing", "")
	// Delete old flows/packets first, then re-parse. This avoids a scenario
	// where Parse truncates .payloads but then fails, leaving corrupted data
	// referenced by stale DB records.
	h.repo.DeleteAssetFlowsAndPackets(asset.ID)
	os.Remove(asset.PayloadsPath)
	analysis, err := pcapparser.Reparse(asset.StoragePath, &pcapparser.Options{
		PcapAssetID:  asset.ID,
		UserID:       asset.UserID,
		PayloadsPath: asset.PayloadsPath,
	})
	if err != nil {
		h.repo.UpdateAssetStatus(asset.ID, "error", "reparse: "+err.Error())
		InternalError(c, "reparse: "+err.Error())
		return
	}
	if err := h.repo.CreateFlows(analysis.Flows); err != nil {
		h.repo.UpdateAssetStatus(asset.ID, "error", "store flows: "+err.Error())
		InternalError(c, "store flows: "+err.Error())
		return
	}
	if err := h.repo.CreatePackets(analysis.Packets); err != nil {
		h.repo.UpdateAssetStatus(asset.ID, "error", "store packets: "+err.Error())
		InternalError(c, "store packets: "+err.Error())
		return
	}
	asset.Status = "ready"
	asset.PacketCount = analysis.PacketCount
	asset.FlowCount = analysis.FlowCount
	asset.ParserVersion = pcapparser.ParserVersion
	h.repo.UpdateAsset(asset)
	SuccessWithMessage(c, "reparse complete", asset)
}

// getOwnedAsset fetches the asset by :id and verifies it belongs to the user.
// GetAsset already filters by user_id at the SQL level (defense-in-depth); the
// explicit check is kept as a second layer.
func (h *PcapHandler) getOwnedAsset(c *gin.Context) (*storage.PcapAssetModel, bool) {
	userID := auth.GetUserID(c)
	asset, err := h.repo.GetAsset(c.Param("id"), userID)
	if err != nil {
		NotFound(c, "pcap asset")
		return nil, false
	}
	if asset.UserID != userID {
		NotFound(c, "pcap asset") // don't reveal existence to other users
		return nil, false
	}
	return asset, true
}

// requireReady returns false (and writes an error) if the asset is not in the
// "ready" state. Query endpoints (flows/packets/search) must not operate on an
// importing/error/reindexing asset -- the data may be incomplete or stale
// (§15.6: importing is "不可用"). Call after getOwnedAsset.
func (h *PcapHandler) requireReady(c *gin.Context, asset *storage.PcapAssetModel) bool {
	if asset.Status != "ready" {
		BadRequest(c, "asset is not ready (status: "+asset.Status+"); wait for import/reparse to complete")
		return false
	}
	return true
}

// GetFlow returns a single flow's full detail (§17.11).
// GET /api/v1/pcaps/:id/flows/:fid
func (h *PcapHandler) GetFlow(c *gin.Context) {
	asset, ok := h.getOwnedAsset(c)
	if !ok {
		return
	}
	if !h.requireReady(c, asset) {
		return
	}
	flowID := c.Param("fid")
	flow, err := h.repo.GetFlow(flowID, auth.GetUserID(c))
	if err != nil || flow.PcapAssetID != asset.ID {
		NotFound(c, "flow")
		return
	}
	Success(c, flow)
}

// GetStream returns reassembled stream bytes from .payloads (§17.11).
// GET /api/v1/pcaps/:id/flows/:fid/stream?dir=c2s&offset=&limit=
func (h *PcapHandler) GetStream(c *gin.Context) {
	asset, ok := h.getOwnedAsset(c)
	if !ok {
		return
	}
	if !h.requireReady(c, asset) {
		return
	}
	flowID := c.Param("fid")
	flow, err := h.repo.GetFlow(flowID, auth.GetUserID(c))
	if err != nil || flow.PcapAssetID != asset.ID {
		NotFound(c, "flow")
		return
	}
	dir := c.DefaultQuery("dir", "c2s")
	var streamOffset, streamLength int64
	switch dir {
	case "c2s":
		streamOffset, streamLength = flow.C2SOffset, flow.C2SLength
	case "s2c":
		streamOffset, streamLength = flow.S2COffset, flow.S2CLength
	default:
		BadRequest(c, "dir must be c2s or s2c")
		return
	}
	if streamLength == 0 || asset.PayloadsPath == "" {
		// Binary endpoint: always return octet-stream, never a JSON envelope.
		// Returning Success(c, []byte{}) here writes a JSON envelope, which
		// MCP's binary wrapper would then base64-encode as if it were the
		// actual stream payload (CRITICAL bug). Empty stream -> empty bytes.
		c.Data(200, "application/octet-stream", []byte{})
		return
	}
	// Optional Range: offset + limit for chunked reads.
	off := streamOffset
	length := streamLength
	if q := c.Query("offset"); q != "" {
		if v, err := strconv.ParseInt(q, 10, 64); err == nil && v >= 0 && v < length {
			off += v
			length -= v
		}
	}
	if q := c.Query("limit"); q != "" {
		if v, err := strconv.ParseInt(q, 10, 64); err == nil && v > 0 && v < length {
			length = v
		}
	}
	f, err := os.Open(asset.PayloadsPath)
	if err != nil {
		InternalError(c, "open payloads: "+err.Error())
		return
	}
	defer f.Close()
	buf := make([]byte, length)
	if _, err := f.ReadAt(buf, off); err != nil {
		InternalError(c, "read stream: "+err.Error())
		return
	}
	c.Data(200, "application/octet-stream", buf)
}

// GetBody returns the highest-layer body (§17.11).
// GET /api/v1/pcaps/:id/flows/:fid/body?dir=c2s
func (h *PcapHandler) GetBody(c *gin.Context) {
	asset, ok := h.getOwnedAsset(c)
	if !ok {
		return
	}
	if !h.requireReady(c, asset) {
		return
	}
	flowID := c.Param("fid")
	flow, err := h.repo.GetFlow(flowID, auth.GetUserID(c))
	if err != nil || flow.PcapAssetID != asset.ID {
		NotFound(c, "flow")
		return
	}
	dir := c.DefaultQuery("dir", "c2s")
	var bodyOffset, bodyLength int64
	switch dir {
	case "c2s":
		bodyOffset, bodyLength = flow.C2SOffset+flow.C2SBodyOffset, flow.C2SBodyLength
	case "s2c":
		bodyOffset, bodyLength = flow.S2COffset+flow.S2CBodyOffset, flow.S2CBodyLength
	default:
		BadRequest(c, "dir must be c2s or s2c")
		return
	}
	if bodyLength == 0 || asset.PayloadsPath == "" {
		// Binary endpoint: always return octet-stream, never a JSON envelope.
		// (See GetStream for the rationale.)
		c.Data(200, "application/octet-stream", []byte{})
		return
	}
	f, err := os.Open(asset.PayloadsPath)
	if err != nil {
		InternalError(c, "open payloads: "+err.Error())
		return
	}
	defer f.Close()
	buf := make([]byte, bodyLength)
	if _, err := f.ReadAt(buf, bodyOffset); err != nil {
		InternalError(c, "read body: "+err.Error())
		return
	}
	c.Data(200, "application/octet-stream", buf)
}

// GetPacketPayload returns a single packet's payload via RawOffset (§17.11).
// GET /api/v1/pcaps/:id/packets/:pid/payload
func (h *PcapHandler) GetPacketPayload(c *gin.Context) {
	asset, ok := h.getOwnedAsset(c)
	if !ok {
		return
	}
	if !h.requireReady(c, asset) {
		return
	}
	pid := c.Param("pid")
	pkt, err := h.repo.GetPacket(pid, auth.GetUserID(c))
	if err != nil || pkt.PcapAssetID != asset.ID {
		NotFound(c, "packet")
		return
	}
	// Read the full packet bytes from the pcap, then slice off the headers.
	// header_len comes from the flow's OffsetLayout (encapsulation-constant).
	flow, err := h.repo.GetFlow(pkt.FlowID, auth.GetUserID(c))
	if err != nil {
		NotFound(c, "flow")
		return
	}
	var layout pcapparser.OffsetLayout
	if flow.OffsetLayout != "" {
		json.Unmarshal([]byte(flow.OffsetLayout), &layout)
	}
	headerLen := 0
	if layout.L4Start >= 0 {
		// L4 header start + 8 (UDP) or variable TCP; approximate with the
		// difference between packet length and payload. For exactness, use the
		// dynamic re-parse path. Here we return the bytes after L4Start+8 for
		// UDP, or the full packet for TCP (caller uses GetPacket for fields).
		headerLen = layout.L4Start + 8
	}
	f, err := os.Open(asset.StoragePath)
	if err != nil {
		InternalError(c, "open pcap: "+err.Error())
		return
	}
	defer f.Close()
	buf := make([]byte, pkt.Length)
	if _, err := f.ReadAt(buf, pkt.RawOffset); err != nil {
		InternalError(c, "read packet: "+err.Error())
		return
	}
	if headerLen > 0 && headerLen < len(buf) {
		buf = buf[headerLen:]
	}
	c.Data(200, "application/octet-stream", buf)
}

// MatchPreview returns the flow IDs matching a FlowMatcher (§17.11). Used by
// the "configure rewrite rule -> verify which flows it hits" workflow.
// POST /api/v1/pcaps/:id/match-preview
func (h *PcapHandler) MatchPreview(c *gin.Context) {
	asset, ok := h.getOwnedAsset(c)
	if !ok {
		return
	}
	if !h.requireReady(c, asset) {
		return
	}
	var matcher pcapparser.FlowMatcher
	if err := c.ShouldBindJSON(&matcher); err != nil {
		BadRequest(c, "invalid matcher: "+err.Error())
		return
	}
	flows, _, err := h.repo.ListFlowsByAsset(asset.ID, auth.GetUserID(c), 1, 100000)
	if err != nil {
		InternalError(c, "load flows: "+err.Error())
		return
	}
	views := make([]pcapparser.FlowModelView, len(flows))
	for i, f := range flows {
		views[i] = pcapparser.FlowModelView{
			ID: f.ID, L4Protocol: f.L4Protocol, SrcIP: f.SrcIP, DstIP: f.DstIP,
			SrcPort: f.SrcPort, DstPort: f.DstPort, L7Protocol: f.L7Protocol,
		}
	}
	hits := pcapparser.MatchPreview(views, matcher)
	Success(c, gin.H{"flow_ids": hits, "count": len(hits)})
}

// Download serves the original pcap file (§17.11).
// GET /api/v1/pcaps/:id/download
func (h *PcapHandler) Download(c *gin.Context) {
	asset, ok := h.getOwnedAsset(c)
	if !ok {
		return
	}
	if !h.requireReady(c, asset) {
		return
	}
	c.FileAttachment(asset.StoragePath, asset.OriginalFilename)
}

// layersLinkType converts the stored int link type to gopacket layers.LinkType.
func layersLinkType(lt int) layers.LinkType {
	return layers.LinkType(lt)
}
