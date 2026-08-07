// Package tftp implements the TFTP packet sequence emission logic.
package tftp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// emit drives the full TFTP packet sequence for the given spec into configChan.
// It handles all HexDump scenarios S1-S15 by orchestrating RRQ/WRQ, OACK,
// ACK#0, DATA/ACK pairs, ERROR injection, TID change, retransmits,
// windowsize, and auto-append.
func (p *Planner) emit(
	ctx context.Context,
	spec *core.FlowSpec,
	cfg *core.TFTPConfig,
	bc uint32,
	autoAppend bool,
	errAtLast bool,
	configChan chan<- core.PacketConfig,
) {
	flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
	blkSize := cfg.BlkSize
	if blkSize == 0 {
		blkSize = DefaultBlkSize
	}
	isRead := cfg.Mode == "read"

	var idx uint64

	// V13 防御：BlocksCount=0（derive 场景）推导结果小于 ServerTIDChangeAtBlock
	// 时，TID 变更永远不会触发，整个传输静默产生 0 包（MEDIUM bug）。
	// 修复：改为显式发出 ERROR(0,"Not defined") 包，使问题在抓包中可见。
	if cfg.ServerTIDChange && bc < cfg.ServerTIDChangeAtBlock {
		errPayload := buildERROR(ErrNotDefined, "TID change unachievable: derived blocks < server_tid_change_at_block")
		idx = emitPacket(ctx, configChan, spec, cfg, flowID, idx, "down",
			cfg.ServerTID, spec.SrcPort, errPayload, isRead, 0)
		return
	}

	// Build the RRQ/WRQ options set for the request packet.
	reqOpts := buildRequestOptions(cfg, isRead)
	// Build the OACK options set (server-accepted subset).
	oackOpts := buildOACKOptions(cfg, isRead)
	hasOptions := anyOptionSet(reqOpts)
	hasOACK := hasOptions || cfg.IncludeOACK

	// Build retransmit set for O(1) lookup.
	retransmitSet := make(map[uint32]bool, len(cfg.RetransmitBlocks))
	for _, b := range cfg.RetransmitBlocks {
		retransmitSet[b] = true
	}

	// 1. Emit RRQ or WRQ (up, client → server:69).
	rrqPayload := buildRRQWRQ(opcodeForMode(isRead), cfg.Filename, cfg.TransferMode, reqOpts)
	idx = emitPacket(ctx, configChan, spec, cfg, flowID, idx, "up",
		spec.SrcPort, spec.DstPort, rrqPayload, isRead, 0)

	// 2. OACK (server echoes the accepted option subset, RFC 2347 §2) for
	// both RRQ and WRQ when the request carried options or IncludeOACK=true.
	if hasOACK {
		var oackPayload []byte
		if hasOptions {
			oackPayload = buildOACK(oackOpts)
		} else {
			// IncludeOACK=true with no options → empty OACK (00 06).
			oackPayload = buildOACK(wireOptions{})
		}
		idx = emitPacket(ctx, configChan, spec, cfg, flowID, idx, "down",
			cfg.ServerTID, spec.SrcPort, oackPayload, isRead, 0)
	}

	// 3. Immediate ERROR (§9.2): ErrorCode>0 + ErrorAfterBlock==0 terminates
	// right after the request (after OACK if one was sent). RFC 2347 §2
	// client-rejects-OACK and file-not-found-after-RRQ/WRQ both use this path.
	// No ACK#0 / WRQ-ready ACK is emitted before the ERROR.
	if cfg.ErrorCode > 0 && cfg.ErrorAfterBlock == 0 {
		errPayload := buildERROR(cfg.ErrorCode, errMsgFor(cfg))
		errDir := "down"
		errSrcPort := cfg.ServerTID
		errDstPort := spec.SrcPort
		if cfg.ErrorSide == "client" {
			errDir = "up"
			errSrcPort = spec.SrcPort
			errDstPort = cfg.ServerTID
		}
		idx = emitPacket(ctx, configChan, spec, cfg, flowID, idx, errDir,
			errSrcPort, errDstPort, errPayload, isRead, 0)
		return
	}

	// 4. ACK#0: RRQ+OACK confirms the negotiated options (client → server),
	// or WRQ with no options = "ready to receive" (server → client, RFC 1350 §4).
	if isRead {
		if hasOACK {
			ack0 := buildACK(0)
			idx = emitPacket(ctx, configChan, spec, cfg, flowID, idx, "up",
				spec.SrcPort, cfg.ServerTID, ack0, isRead, 0)
		}
	} else if !hasOACK {
		ack0 := buildACK(0)
		idx = emitPacket(ctx, configChan, spec, cfg, flowID, idx, "down",
			cfg.ServerTID, spec.SrcPort, ack0, isRead, 0)
	}

	// 5. DATA/ACK pairs.
	// In RRQ mode: DATA is down (server→client), ACK is up (client→server).
	// In WRQ mode: DATA is up (client→server), ACK is down (server→client).
	dataDir := "down"
	ackDir := "up"
	if !isRead {
		dataDir = "up"
		ackDir = "down"
	}

	windowSize := cfg.WindowSize
	if windowSize == 0 {
		windowSize = 1
	}

	// Mid-stream ERROR injection point (ErrorAfterBlock>0): after emitting
	// DATA#N + ACK#N the transfer terminates with an ERROR (§4.3). Unified
	// semantics (R1-CRITICAL-2): ErrorCode>0 injects code=ErrorCode;
	// ErrorCode==0 + ErrorAfterBlock>0 injects code=0 (ErrorAfterBlock
	// expresses the injection intent, T-227); ErrorCode==0 + ErrorAfterBlock==0
	// never injects.
	errAfterBlock := uint32(0)
	if cfg.ErrorCode > 0 || (cfg.ErrorCode == 0 && cfg.ErrorAfterBlock > 0) {
		errAfterBlock = cfg.ErrorAfterBlock
	}

	var i uint32
	for i = 1; i <= bc; i++ {
		// TID change: if ServerTIDChange and i == ServerTIDChangeAtBlock,
		// the server (data sender in RRQ) switches to ServerTIDNew starting
		// with this block.
		useTIDNew := cfg.ServerTIDChange && i >= cfg.ServerTIDChangeAtBlock
		dataSrcPort := cfg.ServerTID
		dataDstPort := spec.SrcPort
		if isRead {
			// RRQ: DATA is down (server→client), src=server TID, dst=client.
			if useTIDNew {
				dataSrcPort = cfg.ServerTIDNew
			}
		} else {
			// WRQ: DATA is up (client→server), src=client, dst=server TID.
			dataSrcPort = spec.SrcPort
			dataDstPort = cfg.ServerTID
			if useTIDNew {
				dataDstPort = cfg.ServerTIDNew
			}
		}

		// Build DATA payload for block i.
		data := buildDataPayload(cfg, blkSize, i, bc)
		blockNum := wireBlockNum(i, cfg.WrapBlockNumber)
		dataPkt := buildDATA(blockNum, data)

		// Retransmit: skip the original DATA for retransmitted blocks (S10).
		if retransmitSet[i] {
			// Original is "lost"; only the retransmit appears.
		} else {
			idx = emitPacket(ctx, configChan, spec, cfg, flowID, idx, dataDir,
				dataSrcPort, dataDstPort, dataPkt, isRead, i)
		}

		// TID change: emit ERROR(5) from client to new TID, then ACK to new TID.
		if cfg.ServerTIDChange && i == cfg.ServerTIDChangeAtBlock {
			// Client detects TID change, sends ERROR(5) to the new TID.
			errPayload := buildERROR(ErrUnknownTID, DefaultErrMsg(ErrUnknownTID))
			errDir := "up"
			errSrcPort := spec.SrcPort
			errDstPort := cfg.ServerTIDNew
			idx = emitPacket(ctx, configChan, spec, cfg, flowID, idx, errDir,
				errSrcPort, errDstPort, errPayload, isRead, 0)
		}

		// ACK: send ACK for this block.
		// For windowsize>1, only ACK at window boundaries.
		isWindowBoundary := (i % uint32(windowSize)) == 0
		isLastBlock := i == bc
		if windowSize == 1 || isWindowBoundary || isLastBlock {
			ackPkt := buildACK(blockNum)
			ackSrcPort := spec.SrcPort
			ackDstPort := cfg.ServerTID
			if useTIDNew {
				ackDstPort = cfg.ServerTIDNew
			}
			if !isRead {
				// WRQ: ACK is down (server→client).
				ackSrcPort = cfg.ServerTID
				ackDstPort = spec.SrcPort
				if useTIDNew {
					ackSrcPort = cfg.ServerTIDNew
				}
			}
			// For retransmitted blocks, ACK is emitted after the retransmit DATA.
			idx = emitPacket(ctx, configChan, spec, cfg, flowID, idx, ackDir,
				ackSrcPort, ackDstPort, ackPkt, isRead, i)
		}

		// ERROR injection after this block.
		if errAfterBlock == i {
			errPayload := buildERROR(cfg.ErrorCode, errMsgFor(cfg))
			errDir := "down"
			errSrcPort := cfg.ServerTID
			errDstPort := spec.SrcPort
			if cfg.ErrorSide == "client" {
				errDir = "up"
				errSrcPort = spec.SrcPort
				errDstPort = cfg.ServerTID
				if useTIDNew {
					errDstPort = cfg.ServerTIDNew
				}
			}
			if useTIDNew && cfg.ErrorSide == "server" {
				errSrcPort = cfg.ServerTIDNew
			}
			idx = emitPacket(ctx, configChan, spec, cfg, flowID, idx, errDir,
				errSrcPort, errDstPort, errPayload, isRead, 0)
			// ERROR terminates the transfer (§4.3).
			return
		}
	}

	// 6. Auto-append 0-byte terminator (RFC 1350 §6) if last block was full.
	// L-1 修复：FinalBlockZero 已在条件中排除（!cfg.FinalBlockZero），此时
	// buildDataPayload 恒产出 blkSize 字节（pattern 填充），因此 lastDataLen
	// == blkSize 恒为真，移除冗余条件分支，直接展开。
	if autoAppend && !cfg.FinalBlockZero && !errAtLast {
		// Emit DATA#(bc+1) with 0 bytes.
		appendedBlockNum := wireBlockNum(bc+1, cfg.WrapBlockNumber)
		zeroData := buildDATA(appendedBlockNum, nil)
		dataSrcPort := cfg.ServerTID
		dataDstPort := spec.SrcPort
		if !isRead {
			dataSrcPort = spec.SrcPort
			dataDstPort = cfg.ServerTID
		}
		useTIDNew := cfg.ServerTIDChange && (bc+1) >= cfg.ServerTIDChangeAtBlock
		if useTIDNew {
			if isRead {
				dataSrcPort = cfg.ServerTIDNew
			} else {
				dataDstPort = cfg.ServerTIDNew
			}
		}
		idx = emitPacket(ctx, configChan, spec, cfg, flowID, idx, dataDir,
			dataSrcPort, dataDstPort, zeroData, isRead, bc+1)

		ackPkt := buildACK(appendedBlockNum)
		ackSrcPort := spec.SrcPort
		ackDstPort := cfg.ServerTID
		if useTIDNew {
			ackDstPort = cfg.ServerTIDNew
		}
		if !isRead {
			ackSrcPort = cfg.ServerTID
			ackDstPort = spec.SrcPort
			if useTIDNew {
				ackSrcPort = cfg.ServerTIDNew
			}
		}
		idx = emitPacket(ctx, configChan, spec, cfg, flowID, idx, ackDir,
			ackSrcPort, ackDstPort, ackPkt, isRead, bc+1)
	}
}

// emitPacket sends a single PacketConfig into configChan, respecting context
// cancellation. Returns the next packet index.
func emitPacket(
	ctx context.Context,
	configChan chan<- core.PacketConfig,
	spec *core.FlowSpec,
	cfg *core.TFTPConfig,
	flowID string,
	idx uint64,
	direction string,
	srcPort, dstPort uint16,
	payload []byte,
	isRead bool,
	blockNum uint32,
) uint64 {
	select {
	case <-ctx.Done():
		return idx
	default:
	}
	pc := core.PacketConfig{
		FlowID:      flowID,
		PacketIndex: idx,
		ClassID:     "",
		Direction:   direction,
		L2: core.L2Config{
			SrcMAC:    spec.SrcMAC,
			DstMAC:    spec.DstMAC,
			EtherType: core.EtherTypeFor(spec.SrcIP),
			VLAN:      spec.VLAN,
		},
		L3: core.L3Config{
			SrcIP: spec.SrcIP,
			DstIP: spec.DstIP,
			TTL:   effectiveTTL(spec.TTL),
			DSCP:  spec.DSCP,
			ECN:   spec.ECN,
		},
		L4: core.L4Config{
			Protocol: "udp",
			SrcPort:  srcPort,
			DstPort:  dstPort,
		},
		Payload: payload,
		Metadata: map[string]interface{}{
			"tftp_opcode":   opcodeOf(payload),
			"tftp_block":    blockNum,
			"tftp_filename": cfg.Filename,
		},
	}
	if cfg.ServerTIDChange && blockNum >= cfg.ServerTIDChangeAtBlock && blockNum > 0 {
		pc.Metadata["tftp_server_tid_new"] = cfg.ServerTIDNew
	}
	select {
	case configChan <- pc:
	case <-ctx.Done():
	}
	return idx + 1
}

// opcodeForMode returns the RRQ/WRQ opcode for the given mode.
func opcodeForMode(isRead bool) uint16 {
	if isRead {
		return OpRRQ
	}
	return OpWRQ
}

// opcodeOf extracts the TFTP opcode from a built packet (first 2 bytes, big-endian).
// Returns 0 for nil/short packets.
func opcodeOf(pkt []byte) uint16 {
	if len(pkt) < 2 {
		return 0
	}
	return uint16(pkt[0])<<8 | uint16(pkt[1])
}

// effectiveTTL returns the spec TTL or the default 64.
func effectiveTTL(ttl uint8) uint8 {
	if ttl == 0 {
		return 64
	}
	return ttl
}

// wireBlockNum computes the wire Block# for the given 1-based sequence index i.
// When wrap=true, Block# = (i mod 65536); otherwise Block# = i (caller must
// ensure i ≤ 65535 via Validate).
func wireBlockNum(i uint32, wrap bool) uint16 {
	if wrap {
		return uint16(i % 65536)
	}
	return uint16(i)
}

// errMsgFor returns the ErrMsg to use for an ERROR injection: user-provided
// if non-empty, otherwise the default for the ErrCode (§5.4).
func errMsgFor(cfg *core.TFTPConfig) string {
	if cfg.ErrorMsg != "" {
		return cfg.ErrorMsg
	}
	return DefaultErrMsg(cfg.ErrorCode)
}

// buildDataPayload constructs the DATA payload for block i. The pattern is
// cycled to fill blkSize bytes. When FinalBlockZero=true and i==bc, the
// payload is empty (0 bytes).
func buildDataPayload(cfg *core.TFTPConfig, blkSize uint16, i, bc uint32) []byte {
	if cfg.FinalBlockZero && i == bc {
		return nil
	}
	pattern := cfg.DataPayloadPattern
	if len(pattern) == 0 {
		// Deterministic 0x00..0xFF pattern (§5.1).
		pattern = make([]byte, 256)
		for j := 0; j < 256; j++ {
			pattern[j] = byte(j)
		}
	}
	data := make([]byte, blkSize)
	for j := uint32(0); j < uint32(blkSize); j++ {
		data[j] = pattern[j%uint32(len(pattern))]
	}
	return data
}

// buildRequestOptions builds the wireOptions for the RRQ/WRQ request packet
// per §5.2 (tsize send rules).
func buildRequestOptions(cfg *core.TFTPConfig, isRead bool) wireOptions {
	var opts wireOptions
	if cfg.BlkSize != 0 {
		opts.setBlkSize(cfg.BlkSize)
	}
	if cfg.Timeout != 0 {
		opts.setTimeout(cfg.Timeout)
	}
	// tsize send rules (§5.2):
	// RRQ: ClientTSize>0 || ServerTSize>0 → send tsize\0 0\0
	// WRQ: ClientTSize>0 → send tsize\0 <ClientTSize>\0
	//      ClientTSize==0 && ServerTSize>0 → send tsize\0 0\0
	if isRead {
		if cfg.ClientTSize > 0 || cfg.ServerTSize > 0 {
			opts.setTSize(0)
		}
	} else {
		if cfg.ClientTSize > 0 {
			opts.setTSize(cfg.ClientTSize)
		} else if cfg.ServerTSize > 0 {
			opts.setTSize(0)
		}
	}
	if cfg.WindowSize != 0 {
		opts.setWindowSize(cfg.WindowSize)
	}
	return opts
}

// buildOACKOptions builds the wireOptions for the OACK packet per §5.2
// (tsize echo rules).
func buildOACKOptions(cfg *core.TFTPConfig, isRead bool) wireOptions {
	var opts wireOptions
	if cfg.BlkSize != 0 {
		opts.setBlkSize(cfg.BlkSize)
	}
	if cfg.Timeout != 0 {
		opts.setTimeout(cfg.Timeout)
	}
	// OACK tsize echo rules (§5.2):
	// RRQ: ServerTSize>0 → echo ServerTSize
	// WRQ: ClientTSize>0 → echo ClientTSize
	//      ClientTSize==0 && ServerTSize>0 → echo ServerTSize
	if isRead {
		if cfg.ServerTSize > 0 {
			opts.setTSize(cfg.ServerTSize)
		}
	} else {
		if cfg.ClientTSize > 0 {
			opts.setTSize(cfg.ClientTSize)
		} else if cfg.ServerTSize > 0 {
			opts.setTSize(cfg.ServerTSize)
		}
	}
	if cfg.WindowSize != 0 {
		opts.setWindowSize(cfg.WindowSize)
	}
	return opts
}

// anyOptionSet returns true if any option in the set is marked as present.
func anyOptionSet(opts wireOptions) bool {
	for i := 0; i < numOptions; i++ {
		if opts.set[i] {
			return true
		}
	}
	return false
}
