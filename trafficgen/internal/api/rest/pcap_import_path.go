package rest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/pcapparser"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// ImportFromPath imports a pcap from a local file path, bypassing multipart
// upload. Used by the MCP tool flowb_manage_pcaps(action=import) so the LLM
// can import by path without constructing a multipart form.
//
// Same logic as Import: hash for dedup, copy to dataDir, create asset record,
// parse synchronously, store flows + packets, finalize. Returns the ready
// asset on success.
func (h *PcapHandler) ImportFromPath(userID, filePath string) (*storage.PcapAssetModel, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}
	if stat.Size() > 2*1024*1024*1024 {
		return nil, fmt.Errorf("file too large: %d bytes (max 2GB)", stat.Size())
	}

	if err := os.MkdirAll(h.dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir data dir: %w", err)
	}
	tmpPath := filepath.Join(h.dataDir, uuid.New().String()+".pcap.tmp")
	dst, err := os.Create(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(dst, hasher), file); err != nil {
		dst.Close()
		os.Remove(tmpPath)
		return nil, fmt.Errorf("save upload: %w", err)
	}
	dst.Close()
	fileHash := hex.EncodeToString(hasher.Sum(nil))

	// Dedup: return existing asset if same hash already imported for this user.
	if existing, err := h.repo.GetAssetByHash(userID, fileHash); err == nil && existing != nil {
		os.Remove(tmpPath)
		return existing, nil
	}

	assetID := uuid.New().String()
	pcapPath := filepath.Join(h.dataDir, assetID+".pcap")
	if err := os.Rename(tmpPath, pcapPath); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("finalize pcap file: %w", err)
	}
	payloadsPath := filepath.Join(h.dataDir, assetID+".payloads")

	filename := filepath.Base(filePath)
	asset := &storage.PcapAssetModel{
		ID:              assetID,
		UserID:          userID,
		Name:            filename,
		OriginalFilename: filename,
		StoragePath:     pcapPath,
		PayloadsPath:    payloadsPath,
		FileHash:        fileHash,
		FileSize:        stat.Size(),
		Status:          "importing",
		LinkType:        1, // DLT_EN10MB
	}
	if err := h.repo.CreateAsset(asset); err != nil {
		// Concurrent-import dedup: race loser re-fetches the winner.
		if existing, err2 := h.repo.GetAssetByHash(userID, fileHash); err2 == nil && existing != nil {
			os.Remove(pcapPath)
			return existing, nil
		}
		os.Remove(pcapPath)
		return nil, fmt.Errorf("create asset: %w", err)
	}

	analysis, err := pcapparser.Parse(pcapPath, &pcapparser.Options{
		PcapAssetID:  assetID,
		UserID:       userID,
		PayloadsPath: payloadsPath,
	})
	if err != nil {
		h.repo.UpdateAssetStatus(assetID, "error", "parse: "+err.Error())
		return nil, fmt.Errorf("parse failed: %w", err)
	}
	if err := h.repo.CreateFlows(analysis.Flows); err != nil {
		h.repo.UpdateAssetStatus(assetID, "error", "store flows: "+err.Error())
		return nil, fmt.Errorf("store flows: %w", err)
	}
	if err := h.repo.CreatePackets(analysis.Packets); err != nil {
		h.repo.UpdateAssetStatus(assetID, "error", "store packets: "+err.Error())
		return nil, fmt.Errorf("store packets: %w", err)
	}
	asset.Status = "ready"
	asset.PacketCount = analysis.PacketCount
	asset.ByteCount = analysis.ByteCount
	asset.FlowCount = analysis.FlowCount
	asset.DurationUs = analysis.DurationUs()
	asset.Snaplen = int(analysis.Snaplen)
	asset.ProtocolDist = analysis.ProtocolDistJSON()
	asset.ParserVersion = pcapparser.ParserVersion
	if err := h.repo.UpdateAsset(asset); err != nil {
		return nil, fmt.Errorf("finalize asset: %w", err)
	}
	return asset, nil
}
