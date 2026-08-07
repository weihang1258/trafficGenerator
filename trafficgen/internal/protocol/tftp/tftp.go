// Package tftp implements the TFTP (RFC 1350) protocol planner. TFTP runs
// over UDP: the client sends RRQ/WRQ to server port 69, and the server
// picks its own ephemeral TID port for the rest of the transfer.
//
// The planner emits a stream of PacketConfig values that the engine's
// PacketWorker builds into UDP datagrams. Each PacketConfig carries the
// TFTP payload in Payload and L4 source/destination ports in L4Config.
//
// References:
//   - RFC 1350: TFTP Rev.2 (base protocol)
//   - RFC 2347: TFTP Option Extension (OACK)
//   - RFC 2348: TFTP Blocksize Option (blksize)
//   - RFC 2349: TFTP Timeout Interval and Transfer Size Options
//   - RFC 7440: TFTP Windowsize Option (windowsize)
package tftp

import (
	"context"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner implements the TFTP protocol planner.
type Planner struct{}

// NewPlanner creates a new TFTP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "tftp" }

// Validate validates a TFTP flow spec per §8. It applies defaulting (§5.1)
// in-place on a copy of the spec, then checks all field ranges and
// combinations. Errors are returned with a "tftp:" prefix.
//
// Note: the batch-level V22 check (server_tid uniqueness across flows in the
// same batch) cannot be enforced here — Validate only sees one flow. It must
// be enforced by the flow-conversion layer (strategy_convert) that has access
// to the full batch. Per-flow validation here is intentionally pure.
//
// Note: V23 (request packet > 512 octets, §8.1 V23) is a warning-class rule
// and requires a Report channel that this single-error-return Validate
// signature does not provide. Per R2-LOW-2 the path is unreachable under the
// implemented per-field constraints (max filename 255B + 4 options → 324B max),
// so it is retained only as a defensive check via validateRRQLength() in
// builder.go for callers that build raw packets bypassing Validate.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.TFTP == nil {
		return fmt.Errorf("tftp: TFTPConfig is required")
	}
	cfg := *spec.TFTP
	// V20: cross-protocol mutex — TFTP is UDP-only.
	if spec.TCP != nil {
		return fmt.Errorf("tftp: tcp field must not be set (TFTP is UDP-only)")
	}
	if spec.HTTP != nil {
		return fmt.Errorf("tftp: http field must not be set (TFTP is UDP-only)")
	}
	if spec.DNS != nil {
		return fmt.Errorf("tftp: dns field must not be set (TFTP is UDP-only)")
	}
	if spec.FTP != nil {
		return fmt.Errorf("tftp: ftp field must not be set (TFTP is UDP-only)")
	}
	if spec.ICMP != nil {
		return fmt.Errorf("tftp: icmp field must not be set (TFTP is UDP-only)")
	}
	if spec.SCTP != nil {
		return fmt.Errorf("tftp: sctp field must not be set (TFTP is UDP-only)")
	}

	// V1: Mode — empty → "read"; case-insensitive normalize.
	cfg.Mode = lowerASCII(strings.TrimSpace(cfg.Mode))
	if cfg.Mode == "" {
		cfg.Mode = "read"
	}
	if cfg.Mode != "read" && cfg.Mode != "write" {
		return fmt.Errorf("tftp: invalid mode %q (must be read or write)", cfg.Mode)
	}

	// V2: TransferMode — empty → "octet"; case-insensitive normalize.
	cfg.TransferMode = lowerASCII(strings.TrimSpace(cfg.TransferMode))
	if cfg.TransferMode == "" {
		cfg.TransferMode = "octet"
	}
	if cfg.TransferMode == "mail" {
		return fmt.Errorf("tftp: transfer_mode %q is deprecated and unsupported", cfg.TransferMode)
	}
	if cfg.TransferMode != "netascii" && cfg.TransferMode != "octet" {
		return fmt.Errorf("tftp: invalid transfer_mode %q (must be netascii or octet)", cfg.TransferMode)
	}

	// V3: Filename — non-empty, no NUL, ≤ 255 bytes.
	if cfg.Filename == "" {
		return fmt.Errorf("tftp: filename is required")
	}
	if strings.IndexByte(cfg.Filename, 0) >= 0 {
		return fmt.Errorf("tftp: filename must not contain null byte")
	}
	if len(cfg.Filename) > MaxFilenameBytes {
		return fmt.Errorf("tftp: filename exceeds %d bytes", MaxFilenameBytes)
	}

	// §9.3: ErrorMsg must not contain NUL — the wire format terminator is
	// a single 0x00, and an embedded NUL would corrupt the ERROR field
	// (strips any bytes after it because splitCStrings is used downstream).
	if strings.IndexByte(cfg.ErrorMsg, 0) >= 0 {
		return fmt.Errorf("tftp: error_msg must not contain null byte")
	}

	// V4: BlkSize — 0 or 8-65464.
	if cfg.BlkSize != 0 && (cfg.BlkSize < MinBlkSize || cfg.BlkSize > MaxBlkSize) {
		return fmt.Errorf("tftp: blksize %d out of range (8-65464)", cfg.BlkSize)
	}

	// V5: Timeout — 0 or 1-255.
	if cfg.Timeout != 0 && (cfg.Timeout < MinTimeout || cfg.Timeout > MaxTimeout) {
		return fmt.Errorf("tftp: timeout %d out of range (1-255)", cfg.Timeout)
	}

	// V6: WindowSize — 0 or 1-65535.
	if cfg.WindowSize != 0 && (cfg.WindowSize < MinWindowSize || cfg.WindowSize > MaxWindowSize) {
		return fmt.Errorf("tftp: windowsize %d out of range (1-65535)", cfg.WindowSize)
	}

	// V8: ErrorCode — 0-8.
	if cfg.ErrorCode > 8 {
		return fmt.Errorf("tftp: error_code %d out of range (0-8)", cfg.ErrorCode)
	}

	// V10: ErrorSide — empty → "server".
	cfg.ErrorSide = lowerASCII(strings.TrimSpace(cfg.ErrorSide))
	if cfg.ErrorSide == "" {
		cfg.ErrorSide = "server"
	}
	if cfg.ErrorSide != "server" && cfg.ErrorSide != "client" {
		return fmt.Errorf("tftp: invalid error_side %q (must be server or client)", cfg.ErrorSide)
	}

	// V11: ServerTID — 0 or 1024-65535.
	if cfg.ServerTID != 0 && cfg.ServerTID < MinEphemeralPort {
		return fmt.Errorf("tftp: server_tid %d in well-known range (<1024)", cfg.ServerTID)
	}

	// V12/V13: ServerTIDNew + ServerTIDChangeAtBlock.
	if cfg.ServerTIDChange {
		if cfg.ServerTIDNew != 0 && cfg.ServerTIDNew < MinEphemeralPort {
			return fmt.Errorf("tftp: server_tid_new %d in well-known range (<1024)", cfg.ServerTIDNew)
		}
		// V12: ServerTIDNew must differ from ServerTID (T-095).
		if cfg.ServerTID != 0 && cfg.ServerTIDNew != 0 && cfg.ServerTIDNew == cfg.ServerTID {
			return fmt.Errorf("tftp: server_tid_new must differ from server_tid")
		}
		// V15: mutual exclusion with ErrorCode>0 (M3: ErrorCode=0 OK).
		if cfg.ErrorCode > 0 {
			return fmt.Errorf("tftp: server_tid_change and error_code are mutually exclusive")
		}
		// V14: mutual exclusion with RetransmitBlocks.
		if len(cfg.RetransmitBlocks) > 0 {
			return fmt.Errorf("tftp: server_tid_change and retransmit_blocks are mutually exclusive")
		}
		if cfg.ServerTIDChangeAtBlock == 0 {
			return fmt.Errorf("tftp: server_tid_change_at_block must be >= 1")
		}
		// V13: ServerTIDChangeAtBlock must be <= BlocksCount when BlocksCount
		// is explicit (derive case is checked at emit time).
		if cfg.BlocksCount > 0 && cfg.ServerTIDChangeAtBlock > cfg.BlocksCount {
			return fmt.Errorf("tftp: server_tid_change_at_block %d out of range", cfg.ServerTIDChangeAtBlock)
		}
	}

	// V9: ErrorAfterBlock — requires explicit BlocksCount + payload source.
	if cfg.ErrorCode > 0 || (cfg.ErrorCode == 0 && cfg.ErrorAfterBlock > 0) {
		if cfg.ErrorAfterBlock > 0 && cfg.BlocksCount == 0 {
			return fmt.Errorf("tftp: error_after_block requires explicit blocks_count (cannot derive)")
		}
		if cfg.ErrorAfterBlock > cfg.BlocksCount {
			return fmt.Errorf("tftp: error_after_block %d exceeds blocks_count %d", cfg.ErrorAfterBlock, cfg.BlocksCount)
		}
		// V9 (continued): ErrorAfterBlock>0 requires a payload source so
		// DATA blocks can be populated (T-086).
		if cfg.ErrorAfterBlock > 0 && len(cfg.DataPayloadPattern) == 0 && len(spec.Payload) == 0 && spec.FileSource == nil {
			return fmt.Errorf("tftp: error_after_block requires data_payload_pattern or payload source")
		}
	}

	// V14: RetransmitBlocks entries must be in [1, BlocksCount].
	for _, b := range cfg.RetransmitBlocks {
		if b == 0 || b > cfg.BlocksCount {
			return fmt.Errorf("tftp: retransmit_blocks entry %d out of range", b)
		}
	}

	// V16/V17/V18: BlocksCount — uint32; >65535 requires WrapBlockNumber.
	if cfg.BlocksCount > 65535 && !cfg.WrapBlockNumber {
		return fmt.Errorf("tftp: blocks_count %d exceeds uint16 max (set wrap_block_number=true to allow)", cfg.BlocksCount)
	}

	// V19: FinalBlockZero requires explicit BlocksCount.
	if cfg.FinalBlockZero && cfg.BlocksCount == 0 {
		return fmt.Errorf("tftp: final_block_zero requires blocks_count >= 1 (cannot derive)")
	}

	// V16: BlocksCount=0 derive — requires DataPayloadPattern or payload
	// source. Exception (§5.3): ErrorCode>0 with ErrorAfterBlock=0 is an
	// immediate error injection with no DATA blocks at all (T-021/T-032/
	// T-035: RRQ → ERROR / WRQ → ERROR / RRQ → OACK → ERROR), so no
	// payload source is needed to derive a block count.
	if cfg.BlocksCount == 0 {
		immediateError := cfg.ErrorCode > 0 && cfg.ErrorAfterBlock == 0
		if !immediateError && len(cfg.DataPayloadPattern) == 0 && len(spec.Payload) == 0 && spec.FileSource == nil {
			return fmt.Errorf("tftp: blocks_count=0 requires data_payload_pattern or payload source")
		}
	}

	// V18: auto-append pushes blocks to >65535 requires wrap.
	autoAppend := true
	if cfg.AutoAppendFinalBlock != nil {
		autoAppend = *cfg.AutoAppendFinalBlock
	}
	if autoAppend && !cfg.FinalBlockZero {
		// Determine if the last block is a full block (triggers auto-append).
		blkSize := cfg.BlkSize
		if blkSize == 0 {
			blkSize = DefaultBlkSize
		}
		bc := cfg.BlocksCount
		if bc == 0 {
			// BlocksCount=0 → derive produces at least 1 (§5.1: pattern or
			// payload-derived); assume the single generated block is full
			// (buildDataPayload always cycles the pattern to BlkSize bytes
			// unless FinalBlockZero=true, which is already excluded above).
			bc = 1
		}
		// If FinalBlockZero=false and last block is full, auto-append adds 1.
		// For ERROR injection at the last block, auto-append is suppressed (§5.3).
		errAtLast := cfg.ErrorCode > 0 && cfg.ErrorAfterBlock == bc
		if !errAtLast {
			actualBlocks := bc + 1
			if actualBlocks > 65535 && !cfg.WrapBlockNumber {
				return fmt.Errorf("tftp: auto-append pushes blocks_count to %d, set wrap_block_number=true", actualBlocks)
			}
		}
	}

	return nil
}

// Plan generates packet configs for a TFTP flow per §6 HexDump scenarios.
// It emits a stream of PacketConfig values into the returned channel.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	cfg := *spec.TFTP

	// Apply defaults (§5.1) on the local copy.
	if cfg.Mode == "" {
		cfg.Mode = "read"
	} else {
		cfg.Mode = lowerASCII(cfg.Mode)
	}
	if cfg.TransferMode == "" {
		cfg.TransferMode = "octet"
	} else {
		cfg.TransferMode = lowerASCII(cfg.TransferMode)
	}
	// NOTE: cfg.BlkSize is NOT defaulted here. BlkSize=0 means "use default 512
	// on the wire but do NOT send the blksize option" (§5.1 defaulting table).
	// buildRequestOptions/buildOACKOptions treat BlkSize==0 as "option omitted";
	// emit() applies DefaultBlkSize locally for DATA sizing.
	if cfg.ErrorSide == "" {
		cfg.ErrorSide = "server"
	} else {
		cfg.ErrorSide = lowerASCII(cfg.ErrorSide)
	}
	if cfg.ServerTID == 0 {
		cfg.ServerTID = deterministicTID(spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
	}
	if cfg.ServerTIDChange && cfg.ServerTIDNew == 0 {
		// Pick a deterministic TID that differs from ServerTID.
		cfg.ServerTIDNew = deterministicTIDNew(spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, cfg.ServerTID)
	}

	// Resolve BlocksCount (derive if 0, §5.1).
	bc := cfg.BlocksCount
	if bc == 0 {
		blk := cfg.BlkSize
		if blk == 0 {
			blk = DefaultBlkSize
		}
		bc = deriveBlocksCount(ctx, &spec, blk)
	}

	// Determine auto-append flag.
	autoAppend := true
	if cfg.AutoAppendFinalBlock != nil {
		autoAppend = *cfg.AutoAppendFinalBlock
	}

	// Determine if ERROR suppresses auto-append (§5.3 R2-HIGH-2).
	errAtLast := cfg.ErrorCode > 0 && cfg.ErrorAfterBlock == bc

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)
		select {
		case <-ctx.Done():
			return
		default:
		}
		p.emit(ctx, &spec, &cfg, bc, autoAppend, errAtLast, configChan)
	}()

	return configChan, nil
}

// deriveBlocksCount computes BlocksCount when the user left it at 0 (§5.1):
//   - DataPayloadPattern non-empty → 1 block.
//   - FlowSpec.Payload / FileSource provides the data size →
//     BlocksCount = ceil(size / blkSize).
//
// FileSource resolution goes through the engine-injected PayloadCache
// (mirroring the ftp/sip/sctp/http/icmp planners). When the cache is
// absent or the source cannot be resolved, we fall back to 1 block — the
// Validate gate (V16) already rejected specs without any payload source,
// so the fallback only triggers when the file is unreadable at plan time.
// BlocksCount=0 cannot reach here (V16).
func deriveBlocksCount(ctx context.Context, spec *core.FlowSpec, blkSize uint16) uint32 {
	if len(spec.TFTP.DataPayloadPattern) > 0 {
		return 1
	}
	if len(spec.Payload) > 0 {
		return ceilDiv(uint64(len(spec.Payload)), uint64(blkSize))
	}
	if spec.FileSource != nil {
		if pc := core.PayloadCacheFrom(ctx); pc != nil {
			if b, err := pc.GetOrLoad(ctx, *spec.FileSource); err == nil {
				return ceilDiv(uint64(len(b)), uint64(blkSize))
			}
		}
	}
	// Unresolvable file source: Validate allowed it (V16 only requires the
	// source to be set), so degrade to a single full block rather than
	// generating nothing.
	return 1
}

// ceilDiv returns ceil(a/b); b must be non-zero.
func ceilDiv(a, b uint64) uint32 {
	q := a / b
	if a%b != 0 {
		q++
	}
	return uint32(q)
}

// deterministicTID returns a deterministic ephemeral port in 49152-65535
// derived from the flow 4-tuple via FNV-1a (§5.1). The same spec always
// yields the same port (reproducible).
func deterministicTID(srcIP, dstIP string, srcPort, dstPort uint16) uint16 {
	h := fnv.New32a()
	h.Write([]byte(srcIP))
	h.Write([]byte{0})
	h.Write([]byte(dstIP))
	h.Write([]byte{0})
	h.Write([]byte{byte(srcPort >> 8), byte(srcPort)})
	h.Write([]byte{byte(dstPort >> 8), byte(dstPort)})
	v := h.Sum32()
	// Map to 49152-65535 (16384 ports, RFC 6335 dynamic range).
	return uint16(MinDynamicPort + uint16(v%uint32(MaxDynamicPort-MinDynamicPort+1)))
}

// deterministicTIDNew returns a deterministic port for ServerTIDNew that
// differs from ServerTID. It iterates the FNV-1a hash with a salt until a
// distinct port is found.
func deterministicTIDNew(srcIP, dstIP string, srcPort, dstPort, tid uint16) uint16 {
	for salt := uint32(1); salt < 100; salt++ {
		h := fnv.New32a()
		h.Write([]byte(srcIP))
		h.Write([]byte{0})
		h.Write([]byte(dstIP))
		h.Write([]byte{0})
		h.Write([]byte{byte(srcPort >> 8), byte(srcPort)})
		h.Write([]byte{byte(dstPort >> 8), byte(dstPort)})
		h.Write([]byte{byte(tid >> 8), byte(tid)})
		h.Write([]byte{byte(salt)})
		v := h.Sum32()
		cand := uint16(MinDynamicPort + uint16(v%uint32(MaxDynamicPort-MinDynamicPort+1)))
		if cand != tid {
			return cand
		}
	}
	// Fallback: tid+1 (wraps within dynamic range).
	return uint16(MinDynamicPort + uint16((uint32(tid)+1)%uint32(MaxDynamicPort-MinDynamicPort+1)))
}
