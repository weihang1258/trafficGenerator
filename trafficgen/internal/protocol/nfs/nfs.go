// Package nfs — Planner: Name, Validate, Plan.
//
// The Planner reads its configuration from core.FlowSpec.Metadata["nfs"]
// (carrying an *NFSConfig). The package helper AttachSpec wires the
// config onto a FlowSpec.
package nfs

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// MetadataKey is the FlowSpec.Metadata key carrying *NFSConfig.
const MetadataKey = "nfs"

// AttachSpec attaches the NFSConfig to a FlowSpec via the Metadata map.
func AttachSpec(spec core.FlowSpec, cfg *NFSConfig) core.FlowSpec {
	if spec.Metadata == nil {
		spec.Metadata = make(map[string]interface{})
	}
	spec.Metadata[MetadataKey] = cfg
	if spec.DstPort == 0 {
		spec.DstPort = DefaultPort
	}
	return spec
}

// GetConfig extracts the *NFSConfig from a FlowSpec. Returns nil when
// no NFS config is present.
func GetConfig(spec core.FlowSpec) *NFSConfig {
	if v, ok := spec.Metadata[MetadataKey]; ok {
		if c, ok := v.(*NFSConfig); ok {
			return c
		}
	}
	return nil
}

// Planner implements the core.ProtocolPlanner interface for NFS.
type Planner struct{}

// NewPlanner returns a new NFS Planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "nfs" }

// Validate validates a NFS flow spec against design §8 rules V1-V38.
func (p *Planner) Validate(spec core.FlowSpec) error {
	cfg := GetConfig(spec)
	if cfg == nil {
		return fmt.Errorf("nfs: config is required (set spec.Metadata[%q])", MetadataKey)
	}
	return validateNFSConfig(cfg)
}

func validateNFSConfig(cfg *NFSConfig) error {
	// V1
	if cfg.Version != 3 && cfg.Version != 4 {
		return fmt.Errorf("nfs: version must be 3 or 4 (got %d)", cfg.Version)
	}
	// V2
	if cfg.Transport != "" && cfg.Transport != "tcp" && cfg.Transport != "udp" {
		return fmt.Errorf("nfs: transport must be tcp or udp (got %q)", cfg.Transport)
	}
	// V3
	if cfg.Version == 4 && cfg.Transport == "udp" {
		return fmt.Errorf("nfs: NFSv4 requires TCP (transport=tcp)")
	}
	// V4
	if len(cfg.Ops) == 0 {
		return fmt.Errorf("nfs: ops must not be empty")
	}
	// V5
	if cfg.Sessions < 0 {
		return fmt.Errorf("nfs: sessions must be >= 1")
	}
	if cfg.Sessions == 0 {
		// Default to 1; treat as valid
	}
	// V6
	if cfg.Sessions > 1 && cfg.SessionsSrcPortStep == 0 {
		return fmt.Errorf("nfs: sessions_src_port_step must be non-zero when sessions>1")
	}
	// V7
	if err := validateAuthFlavor(cfg.AuthFlavor); err != nil {
		return err
	}
	// V8
	if cfg.MinorVersion != nil && *cfg.MinorVersion != 0 {
		return fmt.Errorf("nfs: only NFSv4.0 (minorversion=0) is supported (got %d)", *cfg.MinorVersion)
	}
	// V13
	if cfg.AuthFlavor == AuthFlavorNone && cfg.AuthSys != nil {
		return fmt.Errorf("nfs: auth_sys must be nil when auth_flavor=0")
	}
	// V26
	if len(cfg.MountFilehandle) > NFS3FHSIZE {
		return fmt.Errorf("nfs: mount_filehandle exceeds NFS3_FHSIZE (%d)", NFS3FHSIZE)
	}

	// Walk ops.
	clientidSet := make(map[uint64]int) // clientid -> first session idx
	for i, op := range cfg.Ops {
		if err := validateNFSOp(&op, cfg, i, clientidSet); err != nil {
			return err
		}
	}

	// UDP datagram length cap (V15) — only check the per-op case.
	if cfg.Transport == "udp" {
		if err := validateUDPLength(cfg); err != nil {
			return err
		}
	}
	return nil
}

func validateNFSOp(op *NFSOp, cfg *NFSConfig, opIdx int,
	clientidSet map[uint64]int) error {
	program := op.Program
	if program == 0 {
		program = ProgramNFS
	}
	progVersion := op.ProgVersion
	if progVersion == 0 {
		progVersion = uint32(cfg.Version)
	}

	// V14
	if program == ProgramMount && cfg.Version != 3 {
		return fmt.Errorf("nfs: op[%d]: MOUNT program only valid for NFSv3", opIdx)
	}
	// V33
	if program == ProgramMount && op.Procedure > 5 {
		return fmt.Errorf("nfs: op[%d]: MOUNT v3 procedure out of range (0-5)", opIdx)
	}

	// V9 / V12 — disallow compound fields on NFSv3 and vice versa.
	hasCompound := len(op.CompoundOps) > 0 || op.Tag != ""
	if cfg.Version == 3 && hasCompound {
		return fmt.Errorf("nfs: op[%d]: compound fields only valid for NFSv4", opIdx)
	}
	if cfg.Version == 4 && hasCompound == false {
		// Allow procedure=0 (NFSv4 NULL) without compound_ops.
		if op.Procedure != 0 {
			return fmt.Errorf("nfs: op[%d]: NFSv4 procedure must be 0 (NULL) or 1 (COMPOUND)", opIdx)
		}
	}
	if cfg.Version == 4 && !hasCompound && op.Procedure == 1 {
		return fmt.Errorf("nfs: op[%d]: NFSv4 procedure=1 (COMPOUND) requires compound_ops", opIdx)
	}
	// V10 — for NFSv4, disallow v3-specific fields at the top level
	// (NFSOp.Filehandle, etc. belong in CompoundOps for v4).
	if cfg.Version == 4 {
		if len(op.Filehandle) > 0 || op.Filename != "" || op.Attributes != nil ||
			op.Offset != 0 || op.Count != 0 || len(op.Data) > 0 {
			// V4 may use these only when procedure=0 (NULL); allow.
			if op.Procedure != 0 {
				return fmt.Errorf("nfs: op[%d]: NFSv3 procedure fields not valid for NFSv4 (use compound_ops)", opIdx)
			}
		}
	}

	// V32
	if len(op.Tag) > MaxCompoundTagLen {
		return fmt.Errorf("nfs: op[%d]: COMPOUND tag exceeds %d bytes", opIdx, MaxCompoundTagLen)
	}

	// V24/V25 — filehandle length cap
	maxFH := NFS3FHSIZE
	if cfg.Version == 4 {
		maxFH = NFS4FHSIZE
	}
	if len(op.Filehandle) > maxFH {
		return fmt.Errorf("nfs: op[%d]: filehandle exceeds NFS%d_FHSIZE (%d)", opIdx, cfg.Version, maxFH)
	}
	if len(op.Filehandle2) > maxFH {
		return fmt.Errorf("nfs: op[%d]: filehandle2 exceeds NFS%d_FHSIZE (%d)", opIdx, cfg.Version, maxFH)
	}
	if len(op.LinkDirFh) > maxFH {
		return fmt.Errorf("nfs: op[%d]: link_dirfh exceeds NFS%d_FHSIZE (%d)", opIdx, cfg.Version, maxFH)
	}

	// V31
	if len(op.Filename) > NFS3MaxNamelen {
		return fmt.Errorf("nfs: op[%d]: filename exceeds NFS3_MAXNAMLEN (%d)", opIdx, NFS3MaxNamelen)
	}
	if len(op.Oldname) > NFS3MaxNamelen {
		return fmt.Errorf("nfs: op[%d]: oldname exceeds NFS3_MAXNAMLEN (%d)", opIdx, NFS3MaxNamelen)
	}
	if len(op.Newname) > NFS3MaxNamelen {
		return fmt.Errorf("nfs: op[%d]: newname exceeds NFS3_MAXNAMLEN (%d)", opIdx, NFS3MaxNamelen)
	}
	if len(op.SymlinkTarget) > NFS3MaxNamelen {
		return fmt.Errorf("nfs: op[%d]: symlink_target exceeds NFS3_MAXNAMLEN (%d)", opIdx, NFS3MaxNamelen)
	}

	// V35
	if cfg.AuthSys != nil && len(cfg.AuthSys.MachineName) > 255 {
		return fmt.Errorf("nfs: machine_name exceeds 255 bytes")
	}

	// V23a — write count must equal data length
	if op.Procedure == NFS3ProcWRITE && op.Count != 0 && uint32(len(op.Data)) != op.Count {
		return fmt.Errorf("nfs: op[%d]: write count must equal data length", opIdx)
	}

	// V23 — stable_how
	if op.Procedure == NFS3ProcWRITE && op.StableHow > 2 {
		return fmt.Errorf("nfs: op[%d]: stable_how must be 0 (UNSTABLE4), 1 (DATA_SYNC4), or 2 (FILE_SYNC4)", opIdx)
	}

	// V39
	if op.Procedure == NFS3ProcMKNOD && (op.Ftype < 1 || op.Ftype > 7) {
		return fmt.Errorf("nfs: op[%d]: ftype must be one of NF3REG(1), NF3DIR(2), NF3BLK(3), NF3CHR(4), NF3LNK(5), NF3SOCK(6), NF3FIFO(7)", opIdx)
	}

	// Validate compound ops (V16/V17/V18/V19/V20/V21/V22/V23b).
	for j, cop := range op.CompoundOps {
		if err := validateCompoundOp(&cop, opIdx, j); err != nil {
			return err
		}
		// V36 — clientid uniqueness across sessions
		if cfg.Sessions > 1 && cop.Clientid != 0 {
			if prev, seen := clientidSet[cop.Clientid]; seen && prev != 0 {
				return fmt.Errorf("nfs: op[%d].compound_ops[%d]: duplicate clientid across sessions", opIdx, j)
			}
			clientidSet[cop.Clientid] = 1
		}
	}
	return nil
}

func validateCompoundOp(cop *NFSv4CompoundOp, opIdx, j int) error {
	// V16/V17
	if cop.Opcode < 3 || cop.Opcode > 62 {
		return fmt.Errorf("nfs: op[%d].compound_ops[%d]: invalid opcode (must be 3-62, got %d)", opIdx, j, cop.Opcode)
	}
	// V19 — claim default (not an error)
	// V20 — openhow default (not an error)
	// V21 — objtype default (not an error)
	// V22 — new_lock_owner default (not an error)

	// V23b — OPEN：share_access/share_deny 范围校验 + seqid 必须 > 0
	// （RFC 7530 §16.16 OPEN4args 携带 open_owner4.seqid，用于标识同一
	// open_owner 下的请求序号；seqid=0 属于保留值，NFS4ERR_BAD_SEQID）。
	if cop.Opcode == OP_OPEN {
		if cop.ShareAccess < 1 || cop.ShareAccess > 3 {
			return fmt.Errorf("nfs: op[%d].compound_ops[%d]: share_access must be 1 (READ), 2 (WRITE), or 3 (BOTH)", opIdx, j)
		}
		if cop.ShareDeny > 3 {
			return fmt.Errorf("nfs: op[%d].compound_ops[%d]: share_deny must be 0 (NONE), 1 (READ), 2 (WRITE), or 3 (BOTH)", opIdx, j)
		}
		if cop.Seqid == 0 {
			return fmt.Errorf("nfs: op[%d].compound_ops[%d]: OPEN seqid must be > 0 (RFC 7530 §16.16)", opIdx, j)
		}
	}
	// OPEN_CONFIRM：seqid 必须 > 0（RFC 7530 §16.18 OPEN_CONFIRM 携带
	// seqid = OPEN seqid + 1）。
	if cop.Opcode == OP_OPEN_CONFIRM {
		if cop.Seqid == 0 {
			return fmt.Errorf("nfs: op[%d].compound_ops[%d]: OPEN_CONFIRM seqid must be > 0 (RFC 7530 §16.18)", opIdx, j)
		}
	}
	// LOCK with new_lock_owner=true：open_seqid 与 lock_seqid 都必须 > 0
	// （RFC 7530 §16.10 LOCK4args.open_to_lock_owner4）。
	if cop.Opcode == OP_LOCK && cop.NewLockOwner {
		if cop.OpenToLockOwner == nil {
			return fmt.Errorf("nfs: op[%d].compound_ops[%d]: LOCK new_lock_owner=true requires open_to_lock_owner", opIdx, j)
		}
		if cop.OpenToLockOwner.OpenSeqid == 0 {
			return fmt.Errorf("nfs: op[%d].compound_ops[%d]: LOCK open_seqid must be > 0 (RFC 7530 §16.10)", opIdx, j)
		}
		if cop.OpenToLockOwner.LockSeqid == 0 {
			return fmt.Errorf("nfs: op[%d].compound_ops[%d]: LOCK lock_seqid must be > 0 (RFC 7530 §16.10)", opIdx, j)
		}
	}
	// V23
	if cop.Opcode == OP_WRITE && cop.StableHow > 2 {
		return fmt.Errorf("nfs: op[%d].compound_ops[%d]: stable_how must be 0 (UNSTABLE4), 1 (DATA_SYNC4), or 2 (FILE_SYNC4)", opIdx, j)
	}
	// V30
	if cop.Opcode == OP_GETATTR || cop.Opcode == OP_SETATTR || cop.Opcode == OP_READDIR {
		if len(cop.AttrMask) > 2 {
			for k := 2; k < len(cop.AttrMask); k++ {
				if cop.AttrMask[k] != 0 {
					return fmt.Errorf("nfs: op[%d].compound_ops[%d]: attrmask contains NFSv4.1+ attributes", opIdx, j)
				}
			}
		}
	}
	// V25
	if cop.Opcode == OP_PUTFH && len(cop.Filehandle) > NFS4FHSIZE {
		return fmt.Errorf("nfs: op[%d].compound_ops[%d]: filehandle exceeds NFS4_FHSIZE (%d)", opIdx, j, NFS4FHSIZE)
	}
	// V27
	if cop.Stateid != nil {
		// Other is fixed 12 bytes; structural type enforces this.
	}
	if cop.OpenStateid != nil {
		// Same — structural.
	}
	// V28
	if cop.Opcode == OP_SETCLIENTID_CONFIRM {
		// ClientidVerifier is [8]byte — structural.
	}
	// V29
	// CookieVerf is [8]byte — structural.
	return nil
}

func validateUDPLength(cfg *NFSConfig) error {
	// Estimate per-op payload size. Each op is roughly
	//   RPC header (28B) + NFS body
	// The NFS body varies; we conservatively allow up to UDPMaxPayload
	// for the largest reasonable op (READ with offset+count+fh, ~100B).
	// A precise check is done at Plan time; here we only reject
	// obviously-oversized WRITE data.
	for _, op := range cfg.Ops {
		if op.Procedure == NFS3ProcWRITE {
			// RPC call header (no auth) = 28B, NFS body = fh(8) + offset(8) + count(4) + stable(4) + data(N+pad)
			n := 28 + 8 + 8 + 4 + 4 + len(op.Data)
			n += (4 - (len(op.Data) % 4)) % 4
			if n > UDPMaxPayload {
				return fmt.Errorf("nfs: UDP RPC message exceeds %d bytes", UDPMaxPayload)
			}
		}
	}
	return nil
}

// --- Plan ---

// Plan generates packet configs for an NFS flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	cfg := GetConfig(spec)

	if spec.DstPort == 0 {
		spec.DstPort = DefaultPort
	}

	sessions := cfg.Sessions
	if sessions == 0 {
		sessions = 1
	}
	srcPortBase := cfg.SessionsSrcPortBase
	if srcPortBase == 0 && sessions > 1 {
		srcPortBase = 49152
	}
	step := cfg.SessionsSrcPortStep
	if step == 0 {
		step = 1
	}
	xidBase := cfg.XIDBase
	if xidBase == 0 {
		xidBase = 1
	}
	// XIDIncr=0 is explicitly supported: all calls share the same XID
	// (used for reply-echo behavior tests; T-015). Do NOT coerce to 1.
	xidIncr := cfg.XIDIncr
	transport := cfg.Transport
	if transport == "" {
		transport = "tcp"
	}

	out := make(chan core.PacketConfig, 256)
	go func() {
		defer close(out)
		select {
		case <-ctx.Done():
			return
		default:
		}
		for sess := 0; sess < sessions; sess++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			sessSpec := spec
			if sessions > 1 {
				// Distinct src port per session.
				sessSpec.SrcPort = srcPortBase + uint16(sess)*uint16(step)
			}
			if err := p.planSession(ctx, out, sessSpec, cfg, sess, xidBase, xidIncr, transport); err != nil {
				return
			}
		}
	}()
	return out, nil
}

func (p *Planner) planSession(ctx context.Context, out chan<- core.PacketConfig,
	spec core.FlowSpec, cfg *NFSConfig, sess int,
	xidBase uint32, xidIncr int, transport string) error {

	flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
	now := time.Now()
	pktIndex := uint64(0)
	xid := xidBase
	isTCP := transport == "tcp"

	// Set up clientid allocation for NFSv4 multi-session.
	clientid := uint64(0x10000)*(uint64(sess)+1) + 1

	// Mount filehandle default.
	mountFH := cfg.MountFilehandle
	if mountFH == nil {
		mountFH = make([]byte, 16)
		for i := range mountFH {
			mountFH[i] = 0x01
		}
	}

	// Maintain TCP seq numbers across handshake, data, and teardown.
	clientSeq := uint32(1000)
	serverSeq := uint32(2000)
	if spec.TCP != nil && spec.TCP.InitialSeq != 0 {
		clientSeq = spec.TCP.InitialSeq
	}

	if isTCP {
		// TCP 3-way handshake
		if err := p.emitHandshake(ctx, out, flowID, &pktIndex, spec, now, &clientSeq, &serverSeq); err != nil {
			return err
		}
	}

	// Auto-completion: for NFSv3, prepend MOUNT (proc=1) and append UMOUNT
	// (proc=3) unless user already provided them.
	// For NFSv4, prepend SETCLIENTID + SETCLIENTID_CONFIRM unless user
	// already provided them.
	ops := p.buildOpSequence(cfg, mountFH, sess)

	for i := range ops {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		// Build the call.
		callMsg := p.buildCall(&ops[i], cfg, xid, transport, clientid, sess, spec, mountFH)
		// Build the matching reply.
		replyMsg := p.buildReply(&ops[i], cfg, xid, transport, clientid, sess, spec, mountFH, callMsg)

		// Apply clientid substitution for v4 stateid OpenReplyStateid.
		_ = callMsg // callMsg is the raw bytes; the substitution is done
		// inside buildCall for the body of OPEN/LOCK/CLOSE stateid args.

		// Emit the call as up, reply as down.
		if isTCP {
			p.emitTCPFrame(ctx, out, flowID, &pktIndex, spec, now, "up", callMsg, &clientSeq, &serverSeq)
			p.emitTCPFrame(ctx, out, flowID, &pktIndex, spec, now, "down", replyMsg, &clientSeq, &serverSeq)
		} else {
			p.emitUDP(ctx, out, flowID, &pktIndex, spec, now, "up", callMsg)
			p.emitUDP(ctx, out, flowID, &pktIndex, spec, now, "down", replyMsg)
		}
		xid = uint32(int(xid) + xidIncr)
	}

	if isTCP {
		// TCP teardown
		if err := p.emitTeardown(ctx, out, flowID, &pktIndex, spec, now, &clientSeq, &serverSeq); err != nil {
			return err
		}
	}
	return nil
}

// buildOpSequence returns the effective list of NFSOps including
// auto-inserted MOUNT/UMOUNT (NFSv3) or SETCLIENTID/SETCLIENTID_CONFIRM
// (NFSv4), as well as PUTROOTFH/OPEN_CONFIRM auto-completion for NFSv4.
func (p *Planner) buildOpSequence(cfg *NFSConfig, mountFH []byte, sess int) []NFSOp {
	var out []NFSOp
	if cfg.Version == 4 {
		// Check whether the user already provides SETCLIENTID (opcode=35).
		hasSetClientID := false
		hasSetClientIDConfirm := false
		for _, op := range cfg.Ops {
			for _, c := range op.CompoundOps {
				if c.Opcode == OP_SETCLIENTID {
					hasSetClientID = true
				}
				if c.Opcode == OP_SETCLIENTID_CONFIRM {
					hasSetClientIDConfirm = true
				}
			}
		}
		if !hasSetClientID {
			// Insert synthetic SETCLIENTID + SETCLIENTID_CONFIRM as two
			// SEPARATE COMPOUNDs at the head of the op sequence
			// (§4.1 rule 1 / T-101/T-102: "第 1 个 COMPOUND 含 opcode=35，
			// 第 2 个 COMPOUND 含 opcode=36"). Each op is one RPC
			// round-trip (one call + one reply), so the reply to the
			// SETCLIENTID call carries the clientid/verifier that the
			// CONFIRM call then echoes — splitting them keeps the
			// state-machine semantics observable on the wire.
			// The client.id encodes the session index for multi-session
			// uniqueness.
			clientID := uint64(0x10000)*(uint64(sess)+1) + 1
			var verf [8]byte
			rand.Read(verf[:])
			scid := NFSOp{
				Procedure: NFS4ProcCOMPOUND,
				Tag:       "",
				CompoundOps: []NFSv4CompoundOp{{
					Opcode: OP_SETCLIENTID,
					Client: &NFSClientId{
						Verifier: verf,
						Id:       fmt.Sprintf("trafficgen-client-%d", sess),
					},
					Callback:      &CBCallback{Program: 0, NetID: "", Addr: ""},
					CallbackIdent: 0,
				}},
			}
			out = []NFSOp{scid}
			if !hasSetClientIDConfirm {
				conf := NFSOp{
					Procedure: NFS4ProcCOMPOUND,
					Tag:       "",
					CompoundOps: []NFSv4CompoundOp{{
						Opcode:           OP_SETCLIENTID_CONFIRM,
						Clientid:         clientID,
						ClientidVerifier: verf,
					}},
				}
				out = append(out, conf)
			}
			out = append(out, cfg.Ops...)
		} else if !hasSetClientIDConfirm {
			// Already has SETCLIENTID; append synthetic confirm.
			confirm := NFSOp{Procedure: NFS4ProcCOMPOUND, Tag: ""}
			confirm.CompoundOps = []NFSv4CompoundOp{{
				Opcode:          OP_SETCLIENTID_CONFIRM,
				Clientid:        uint64(0x10000)*(uint64(sess)+1) + 1,
				ClientidVerifier: [8]byte{},
			}}
			out = append([]NFSOp{}, cfg.Ops...)
			out = append(out, confirm)
		} else {
			out = cfg.Ops
		}

		// NFSv4 auto-completion: PUTROOTFH (§4.1 rule 2) before
		// OPEN_CONFIRM (§4.1 rule 3). The order matters — OPEN_CONFIRM
		// may be inserted into the same compound that already had
		// PUTROOTFH prepended.
		out = autoCompletePutRootFH(out)
		out = autoCompleteOpenConfirm(out)
		return out
	}

	// NFSv3
	hasMount := false
	hasUmount := false
	explicitProgram := false
	for _, op := range cfg.Ops {
		if op.Program == ProgramMount && op.Procedure == 1 {
			hasMount = true
		}
		if op.Program == ProgramMount && op.Procedure == 3 {
			hasUmount = true
		}
		// When the user explicitly sets Program on any op (e.g.
		// program:100003 in the S1/S2 HexDump scenarios and T-001), they
		// take full control of the program sequence and MOUNT/UMOUNT
		// auto-insertion is skipped. This reconciles §4.2 rule 1 (auto
		// MOUNT unless an explicit MOUNT op exists) with T-001/T-002/
		// T-003/T-066 and S1/S2, whose configs carry an explicit
		// program:100003 and expect the first call to be the user's op
		// (no MOUNT round-trip). Ops that omit Program (default 100003)
		// still get the full MOUNT + Ops + UMOUNT state machine (§4.2).
		if op.Program != 0 {
			explicitProgram = true
		}
	}
	if explicitProgram {
		// User controls the program sequence. When the user explicitly
		// configured the MOUNT round-trip (Program=100005 proc=1) but
		// no UMOUNT, the UMOUNT trailer is still appended per §4.2
		// rule 1 ("尾部自动插入 UMOUNT 除非用户显式配置 Procedure=3").
		// When the user configured only NFS ops (e.g. program:100003 in
		// S1/S2/T-001), the whole MOUNT/UMOUNT machinery is skipped.
		if hasMount && !hasUmount {
			out = make([]NFSOp, 0, len(cfg.Ops)+1)
			out = append(out, cfg.Ops...)
			out = append(out, NFSOp{
				Program:     ProgramMount,
				ProgVersion: 3,
				Procedure:   3,
				DirPath:     "/",
			})
			return out
		}
		return cfg.Ops
	}
	out = make([]NFSOp, 0, len(cfg.Ops)+2)
	if !hasMount {
		out = append(out, NFSOp{
			Program:     ProgramMount,
			ProgVersion: 3,
			Procedure:   1,
			DirPath:     "/",
		})
	}
	out = append(out, cfg.Ops...)
	if !hasUmount {
		out = append(out, NFSOp{
			Program:     ProgramMount,
			ProgVersion: 3,
			Procedure:   3,
			DirPath:     "/",
		})
	}

	// NFSv3: no NFSv4 auto-completion. PUTROOTFH/OPEN_CONFIRM only
	// apply to NFSv4 (§4.1 rules 2/3).
	return out
}

// needsCurrentFH returns true when the op requires a current filehandle
// to have been established (i.e., it operates on the "current" fh).
// Opcodes that explicitly set the fh (PUTFH/PUTROOTFH/PUTPUBFH) and
// lookups that set the parent fh (LOOKUP) are excluded from triggering
// PUTROOTFH auto-completion. GETFH operates on the saved fh so doesn't
// need a pre-set one. SETCLIENTID/SETCLIENTID_CONFIRM and v4.1 session
// ops do not require a current fh.
func needsCurrentFH(opcode uint32) bool {
	switch opcode {
	case OP_PUTFH, OP_PUTROOTFH, OP_PUTPUBFH,
		OP_LOOKUP, OP_LOOKUPP,
		OP_GETFH,
		OP_SETCLIENTID, OP_SETCLIENTID_CONFIRM,
		OP_EXCHANGE_ID, // never used in v4.0 but included for completeness
		OP_CREATE_SESSION,
		OP_DESTROY_SESSION,
		OP_BIND_CONN_TO_SESSION:
		return false
	}
	return true
}

// autoCompletePutRootFH walks ops and prepends PUTROOTFH to every
// COMPOUND whose ops include any operation that requires a current
// filehandle AND the user did NOT already configure PUTFH/PUTROOTFH/
// PUTPUBFH as the first op of that COMPOUND (§4.1 rule 2).
//
// This is a per-COMPOUND auto-completion: each user-configured
// COMPOUND that operates on a filehandle gets its own PUTROOTFH
// prepended unless it already establishes one.
func autoCompletePutRootFH(ops []NFSOp) []NFSOp {
	for i := range ops {
		op := &ops[i]
		if op.Procedure != NFS4ProcCOMPOUND {
			continue
		}
		if len(op.CompoundOps) == 0 {
			continue
		}
		// Skip if user already supplied PUTFH/PUTROOTFH/PUTPUBFH first.
		first := op.CompoundOps[0].Opcode
		if first == OP_PUTFH || first == OP_PUTROOTFH || first == OP_PUTPUBFH {
			continue
		}
		// Check if any op in this compound needs a current fh.
		needs := false
		for j := range op.CompoundOps {
			if needsCurrentFH(op.CompoundOps[j].Opcode) {
				needs = true
				break
			}
		}
		if !needs {
			continue
		}
		// Insert PUTROOTFH as the first op of this compound.
		newOps := make([]NFSv4CompoundOp, 0, len(op.CompoundOps)+1)
		newOps = append(newOps, NFSv4CompoundOp{Opcode: OP_PUTROOTFH})
		newOps = append(newOps, op.CompoundOps...)
		op.CompoundOps = newOps
	}
	return ops
}

// openOwnerKey identifies a (clientid, owner-bytes) pair.
type openOwnerKey struct {
	clientid uint64
	owner    string
}

func openOwnerKeyFor(cop *NFSv4CompoundOp) openOwnerKey {
	var ownerStr string
	if cop.Owner != nil {
		ownerStr = string(cop.Owner.Owner)
	}
	return openOwnerKey{clientid: cop.Clientid, owner: ownerStr}
}

// autoCompleteOpenConfirm walks ops and injects OPEN_CONFIRM after
// every OPEN that introduces a new open-owner (clientid+owner pair
// not yet seen in this flow).
func autoCompleteOpenConfirm(ops []NFSOp) []NFSOp {
	seen := map[openOwnerKey]bool{}
	for i := range ops {
		op := &ops[i]
		if op.Procedure != NFS4ProcCOMPOUND {
			continue
		}
		newOps := make([]NFSv4CompoundOp, 0, len(op.CompoundOps)+1)
		for j := range op.CompoundOps {
			cop := &op.CompoundOps[j]
			newOps = append(newOps, *cop)
			if cop.Opcode == OP_OPEN {
				key := openOwnerKeyFor(cop)
				if !seen[key] {
					seen[key] = true
					// OPEN_CONFIRM 携带的 open_stateid 应为服务端 OPEN 回复
					// 下发的 stateid（即 NFSOp.OpenReplyStateid），而非客户端
					// 发起 OPEN 时使用的输入 stateid（通常是匿名 stateid 全 0）。
					// 优先复用 op.OpenReplyStateid（H-3）：用户在 NFSOp 上配置
					// 的 OpenReplyStateid 代表服务端响应，OPEN_CONFIRM 必须 echo
					// 该值；若未配置则回退到 cop.OpenStateid 或全 0 匿名 stateid。
					var confirmStateid *NFSStateid
					switch {
					case op.OpenReplyStateid != nil:
						clone := *op.OpenReplyStateid
						confirmStateid = &clone
					case cop.OpenStateid != nil:
						clone := *cop.OpenStateid
						confirmStateid = &clone
					default:
						confirmStateid = &NFSStateid{}
					}
					// RFC 7530 §16.18.4：OPEN_CONFIRM seqid = OPEN seqid + 1。
					var confirmSeqid uint32
					if cop.Seqid > 0 {
						confirmSeqid = cop.Seqid + 1
					} else {
						confirmSeqid = 2
					}
					confirm := NFSv4CompoundOp{
						Opcode:      OP_OPEN_CONFIRM,
						OpenStateid: confirmStateid,
						Seqid:       confirmSeqid,
					}
					newOps = append(newOps, confirm)
				}
			}
		}
		op.CompoundOps = newOps
	}
	return ops
}

// buildCall builds the RPC CALL message bytes (with RM if TCP).
func (p *Planner) buildCall(op *NFSOp, cfg *NFSConfig, xid uint32, transport string,
	clientid uint64, sess int, spec core.FlowSpec, mountFH []byte) []byte {

	program := op.Program
	if program == 0 {
		program = ProgramNFS
	}
	progVersion := op.ProgVersion
	if progVersion == 0 {
		progVersion = uint32(cfg.Version)
	}

	body := make([]byte, 0, 256)
	body = encodeRPCCallHeader(body, xid, program, progVersion, op.Procedure,
		cfg.AuthFlavor, cfg.AuthSys)

	// NFS body
	if program == ProgramMount {
		// MOUNT v3 args: MNT(dirpath) / UMNT(dirpath) / DUMP/EXPORT/UMNTALL/NULL
		switch op.Procedure {
		case 0: // NULL
			// no body
		case 1: // MNT
			body = appendString(body, op.DirPath)
		case 2: // DUMP — no body
		case 3: // UMNT
			body = appendString(body, op.DirPath)
		case 4: // UMNTALL — no body
		case 5: // EXPORT — no body
		}
	} else if cfg.Version == 3 {
		body = encodeNFS3Call(body, op, mountFH)
	} else {
		// NFSv4
		body = encodeNFS4Call(body, op, cfg, clientid, sess)
	}

	// Prepend RM for TCP.
	if transport == "tcp" {
		rm := recordMark(len(body))
		var tmp [4]byte
		binary.BigEndian.PutUint32(tmp[:], rm)
		return append(tmp[:], body...)
	}
	return body
}

// buildReply builds the RPC REPLY message bytes.
func (p *Planner) buildReply(op *NFSOp, cfg *NFSConfig, xid uint32, transport string,
	clientid uint64, sess int, spec core.FlowSpec, mountFH []byte, callMsg []byte) []byte {

	program := op.Program
	if program == 0 {
		program = ProgramNFS
	}

	// RPC-level error injection takes priority.
	if op.RPCRejectState != nil {
		body := make([]byte, 0, 32)
		body = encodeRPCReplyHeaderDenied(body, xid)
		body = appendU32(body, *op.RPCRejectState)
		if *op.RPCRejectState == RPCMismatch {
			low := uint32(2)
			high := uint32(2)
			if op.RPCMismatchLow != nil {
				low = *op.RPCMismatchLow
			}
			if op.RPCMismatchHigh != nil {
				high = *op.RPCMismatchHigh
			}
			body = appendU32(body, low)
			body = appendU32(body, high)
		} else if *op.RPCRejectState == RPCAuthError {
			ast := uint32(AuthBadCred)
			if op.AuthStat != nil {
				ast = *op.AuthStat
			}
			body = appendU32(body, ast)
		}
		return wrapRM(body, transport)
	}
	if op.RPCAcceptState != nil {
		body := make([]byte, 0, 32)
		body = encodeRPCReplyHeaderAccepted(body, xid)
		body = appendU32(body, *op.RPCAcceptState)
		if *op.RPCAcceptState == RPCProgMismatch {
			low := uint32(2)
			high := uint32(2)
			if op.RPCMismatchLow != nil {
				low = *op.RPCMismatchLow
			}
			if op.RPCMismatchHigh != nil {
				high = *op.RPCMismatchHigh
			}
			body = appendU32(body, low)
			body = appendU32(body, high)
		}
		return wrapRM(body, transport)
	}

	// Default: MSG_ACCEPTED + SUCCESS + NFS body.
	body := make([]byte, 0, 256)
	body = encodeRPCReplyHeaderAccepted(body, xid)
	body = appendU32(body, RPCSuccess)

	if program == ProgramMount {
		body = encodeMountReply(body, op)
	} else if cfg.Version == 3 {
		// NFSv3 NULL (proc 0) has a void reply: no NFS status field
		// (RFC 1813 §3.3.1 / S1: REPLY payload = 24 bytes = header +
		// AcceptState only). All other procedures carry the NFS3_OK
		// status word (§6 S2-S16d).
		if op.Procedure != NFS3ProcNULL {
			body = encodeNFS3Reply(body, op, cfg, mountFH)
		}
	} else {
		body = encodeNFS4Reply(body, op, cfg, clientid, sess)
	}
	return wrapRM(body, transport)
}

func wrapRM(body []byte, transport string) []byte {
	if transport != "tcp" {
		return body
	}
	rm := recordMark(len(body))
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], rm)
	return append(tmp[:], body...)
}

// --- NFSv3 call/reply encoders ---

func encodeNFS3Call(b []byte, op *NFSOp, mountFH []byte) []byte {
	procedure := op.Procedure
	fh := op.Filehandle
	if fh == nil {
		fh = mountFH
	}
	switch procedure {
	case NFS3ProcNULL:
		// no body
	case NFS3ProcGETATTR, NFS3ProcREADLINK, NFS3ProcFSSTAT, NFS3ProcFSINFO, NFS3ProcPATHCONF:
		b = appendFilehandle(b, fh)
	case NFS3ProcSETATTR:
		b = appendFilehandle(b, fh)
		b = encodeSattr3(b, op.Attributes)
		b = encodeSattrGuard3(b, op.Attributes)
	case NFS3ProcLOOKUP:
		b = appendFilehandle(b, fh)
		b = appendString(b, op.Filename)
	case NFS3ProcACCESS:
		b = appendFilehandle(b, fh)
		b = appendU32(b, op.Access)
	case NFS3ProcREAD:
		b = appendFilehandle(b, fh)
		b = appendU64(b, op.Offset)
		b = appendU32(b, op.Count)
	case NFS3ProcWRITE:
		b = appendFilehandle(b, fh)
		b = appendU64(b, op.Offset)
		b = appendU32(b, op.Count)
		b = appendU32(b, op.StableHow)
		b = appendOpaque(b, op.Data)
	case NFS3ProcCREATE, NFS3ProcMKDIR:
		b = appendFilehandle(b, fh)
		b = appendString(b, op.Filename)
		b = encodeSattr3(b, op.Attributes)
	case NFS3ProcSYMLINK:
		b = appendFilehandle(b, fh)
		b = appendString(b, op.Filename)
		b = encodeSattr3(b, op.Attributes)
		b = appendString(b, op.SymlinkTarget)
	case NFS3ProcMKNOD:
		b = appendFilehandle(b, fh)
		b = appendString(b, op.Filename)
		b = appendU32(b, op.Ftype)
		// mknoddata3: NF3BLK/NF3CHR → devicedata3 (sattr3 + specdata3 8B)
		//             NF3SOCK/NF3FIFO → pipe_attributes (sattr3)
		//             else → void
		if op.Ftype == NF3BLK || op.Ftype == NF3CHR {
			b = encodeSattr3(b, op.Attributes)
			b = append(b, op.Devdata[:]...)
		} else if op.Ftype == NF3SOCK || op.Ftype == NF3FIFO {
			b = encodeSattr3(b, op.Attributes)
		}
		// else: void
	case NFS3ProcREMOVE, NFS3ProcRMDIR:
		b = appendFilehandle(b, fh)
		b = appendString(b, op.Filename)
	case NFS3ProcRENAME:
		b = appendFilehandle(b, fh)
		b = appendString(b, op.Oldname)
		toFh := op.Filehandle2
		if toFh == nil {
			toFh = fh
		}
		b = appendFilehandle(b, toFh)
		b = appendString(b, op.Newname)
	case NFS3ProcLINK:
		b = appendFilehandle(b, fh)
		linkFh := op.LinkDirFh
		if linkFh == nil {
			linkFh = fh
		}
		b = appendFilehandle(b, linkFh)
		b = appendString(b, op.Newname)
	case NFS3ProcREADDIR:
		b = appendFilehandle(b, fh)
		b = appendU64(b, op.Cookie)
		b = append(b, op.CookieVerf[:]...)
		b = appendU32(b, op.MaxCount)
	case NFS3ProcREADDIRPLUS:
		b = appendFilehandle(b, fh)
		b = appendU64(b, op.Cookie)
		b = append(b, op.CookieVerf[:]...)
		b = appendU32(b, op.DirCount)
		b = appendU32(b, op.MaxCount)
	case NFS3ProcCOMMIT:
		b = appendFilehandle(b, fh)
		b = appendU64(b, op.Offset)
		b = appendU32(b, op.Count)
	default:
		// Unknown / 22+ — pass-through; do not write any body.
	}
	return b
}

func encodeNFS3Reply(b []byte, op *NFSOp, cfg *NFSConfig, mountFH []byte) []byte {
	status := cfg.ResultStatus
	if op.ReplyStatus != 0 {
		status = op.ReplyStatus
	}
	b = appendU32(b, status)
	if status != NFS3OK {
		// Truncated reply body for non-OK. For most procedures the
		// caller only sees the NFS status; we skip the body.
		return b
	}
	procedure := op.Procedure
	switch procedure {
	case NFS3ProcNULL:
		// no body
	case NFS3ProcGETATTR, NFS3ProcFSSTAT, NFS3ProcFSINFO, NFS3ProcPATHCONF:
		b = appendU32(b, 1) // post_op_attr.attributes_follow = 1
		b = append(b, defaultFattr3()...)
	case NFS3ProcSETATTR, NFS3ProcREMOVE, NFS3ProcRMDIR, NFS3ProcCOMMIT:
		// wcc_data (92 bytes): pre_op_attr.discriminant=0 + post_op_attr=1+fattr3
		b = encodeWccData(b)
	case NFS3ProcLOOKUP:
		// LOOKUP3resok = object fh + obj_attributes + dir_attributes
		// (RFC 1813 §3.3.3; S4)
		objFh := []byte{0xAA, 0xBB, 0xCC, 0xDD}
		b = appendFilehandle(b, objFh)
		b = appendU32(b, 1)
		b = append(b, defaultFattr3()...)
		b = appendU32(b, 0) // dir_attributes.attributes_follow = 0
	case NFS3ProcACCESS:
		b = appendU32(b, op.Access)   // supported
		b = appendU32(b, op.Access)   // access (granted)
		b = encodePostOpAttr(b, true)
	case NFS3ProcREADLINK:
		b = appendString(b, op.SymlinkTarget)
		b = encodePostOpAttr(b, true)
	case NFS3ProcREAD:
		// post_op_attr + count + eof + data
		b = appendU32(b, 1)
		b = append(b, defaultFattr3()...)
		b = appendU32(b, op.Count)
		b = appendU32(b, 0) // eof
		b = appendOpaque(b, op.Data)
	case NFS3ProcWRITE:
		// wcc_data + count + committed + verf
		b = encodeWccData(b)
		b = appendU32(b, op.Count)
		b = appendU32(b, op.StableHow)
		var verf [8]byte
		b = append(b, verf[:]...)
	case NFS3ProcCREATE, NFS3ProcMKDIR, NFS3ProcSYMLINK, NFS3ProcMKNOD:
		// post_op_fh3 + post_op_attr + dir_wcc
		newFh := []byte{0xAA, 0xBB, 0xCC, 0xDD}
		b = appendU32(b, 1) // handle_follows
		b = appendFilehandle(b, newFh)
		b = appendU32(b, 1)
		b = append(b, defaultFattr3()...)
		b = encodeWccData(b)
	case NFS3ProcREADDIR:
		// post_op_attr + cookieverf + entries length + eof
		b = appendU32(b, 1)
		b = append(b, defaultFattr3()...)
		b = append(b, op.CookieVerf[:]...)
		b = appendU32(b, 0) // entries length = 0
		b = appendU32(b, 1) // eof = true
	case NFS3ProcREADDIRPLUS:
		b = appendU32(b, 1)
		b = append(b, defaultFattr3()...)
		b = append(b, op.CookieVerf[:]...)
		b = appendU32(b, 0) // entries length = 0
		b = appendU32(b, 1) // eof = true
	}
	return b
}

func encodeMountReply(b []byte, op *NFSOp) []byte {
	status := uint32(0) // MOUNT_OK
	if op.ReplyStatus != 0 {
		status = op.ReplyStatus
	}
	b = appendU32(b, status)
	if status != 0 {
		return b
	}
	switch op.Procedure {
	case 0: // NULL
		// no body
	case 1: // MNT
		// fhstatus3 = status (already written) + fh + auth_flavors<>
		fh := make([]byte, 16)
		for i := range fh {
			fh[i] = 0x01
		}
		b = appendFilehandle(b, fh)
		b = appendU32(b, 0) // auth_flavors<> = empty
	case 2: // DUMP — mountlist<>; emit empty
		b = appendU32(b, 0)
	case 3: // UMNT — void
	case 4: // UMNTALL — void
	case 5: // EXPORT — exports<>; emit empty
		b = appendU32(b, 0)
	}
	return b
}

// --- NFSv4 call/reply encoders ---

func encodeNFS4Call(b []byte, op *NFSOp, cfg *NFSConfig, clientid uint64, sess int) []byte {
	if op.Procedure == NFS4ProcNULL {
		// no NFS body
		return b
	}
	// COMPOUND
	minorversion := uint32(0)
	if cfg.MinorVersion != nil {
		minorversion = *cfg.MinorVersion
	}
	tag := op.Tag

	// 深拷贝 CompoundOps，消除对用户 cfg.Ops 的 mutation 副作用（H-2）：
	// 原实现在下方 clientid 替换和 applyOpenReplyStateid 中直接写入
	// op.CompoundOps[i]，导致首次 Plan 后用户 cfg 中的 CompoundOps 被永久
	// 修改——后续会话（multi-session）或第二次 Plan 会读到被污染的值。
	// 现改为操作本地副本，编码完成后丢弃，不回写到原 op。
	cops := make([]NFSv4CompoundOp, len(op.CompoundOps))
	copy(cops, op.CompoundOps)
	// 对每个 NFSv4CompoundOp 内部的指针字段（NFSStateid、Owner 等）做一层
	// 浅拷贝，使后续若要替换指针也不会写回用户原始对象。
	for i := range cops {
		if cops[i].OpenStateid != nil {
			s := *cops[i].OpenStateid
			cops[i].OpenStateid = &s
		}
		if cops[i].Stateid != nil {
			s := *cops[i].Stateid
			cops[i].Stateid = &s
		}
		if cops[i].OpenToLockOwner != nil {
			olo := *cops[i].OpenToLockOwner
			if olo.OpenStateid != nil {
				s := *olo.OpenStateid
				olo.OpenStateid = &s
			}
			cops[i].OpenToLockOwner = &olo
		}
	}

	// Substitute session clientid (where user left it 0) so the reply
	// side also sees the per-session value. (§10.4 / buildOpSequence)
	for i := range cops {
		if cops[i].Clientid == 0 && needsClientID(cops[i].Opcode) {
			cops[i].Clientid = clientid
		}
	}

	// OpenReplyStateid substitution (§3.5 / §11.8 M-10): when the user
	// configured OpenReplyStateid on this COMPOUND, any subsequent op
	// (within the same COMPOUND) whose stateid is all-zero is rewritten
	// to the OpenReplyStateid bytes. User-provided non-zero stateids are
	// not touched.
	if op.OpenReplyStateid != nil {
		applyOpenReplyStateid(&cops, op.OpenReplyStateid)
	}

	encoded := make([]encodedOp, 0, len(cops))
	for i := range cops {
		args := encodeCompoundOpArgs(&cops[i])
		encoded = append(encoded, encodedOp{Opcode: cops[i].Opcode, Args: args})
	}
	return encodeCompound4Args(b, tag, minorversion, encoded)
}

// applyOpenReplyStateid rewrites all-zero stateids (Stateid or
// OpenStateid) on every op in the COMPOUND to point at the OPEN
// reply stateid supplied by the user via NFSOp.OpenReplyStateid.
func applyOpenReplyStateid(compoundOps *[]NFSv4CompoundOp, openStid *NFSStateid) {
	for i := range *compoundOps {
		cop := &(*compoundOps)[i]
		// OpenStateid field (used by OPEN, CLOSE, OPEN_CONFIRM, OPEN_DOWNGRADE,
		// LOCK's open_to_lock_owner).
		if cop.OpenStateid != nil && isZeroStateid(cop.OpenStateid) {
			clone := *openStid
			cop.OpenStateid = &clone
		} else if cop.OpenStateid == nil && opUsesOpenStateid(cop.Opcode) {
			// Some opcodes (e.g., CLOSE after OPEN) expect an open_stateid
			// but the user may have left it nil. Substitute with the OPEN
			// reply stateid if the opcode requires one.
			clone := *openStid
			cop.OpenStateid = &clone
		}
		// Stateid field (used by READ, WRITE, SETATTR, LOCKU).
		if cop.Stateid != nil && isZeroStateid(cop.Stateid) {
			clone := *openStid
			cop.Stateid = &clone
		}
		// OpenToLockOwner.OpenStateid (LOCK with new_lock_owner=true).
		if cop.NewLockOwner && cop.OpenToLockOwner != nil {
			olo := cop.OpenToLockOwner
			if olo.OpenStateid != nil && isZeroStateid(olo.OpenStateid) {
				clone := *openStid
				olo.OpenStateid = &clone
			} else if olo.OpenStateid == nil {
				clone := *openStid
				olo.OpenStateid = &clone
			}
		}
	}
}

// isZeroStateid returns true when the stateid is the anonymous stateid
// (seqid=0 and other=12 zero bytes).
func isZeroStateid(s *NFSStateid) bool {
	if s.Seqid != 0 {
		return false
	}
	for _, b := range s.Other {
		if b != 0 {
			return false
		}
	}
	return true
}

// opUsesOpenStateid returns true when the opcode has an OpenStateid
// field that should be populated from the OPEN reply.
func opUsesOpenStateid(opcode uint32) bool {
	switch opcode {
	case OP_CLOSE, OP_OPEN_CONFIRM, OP_OPEN_DOWNGRADE:
		return true
	}
	return false
}

// needsClientID returns true when an op participates in clientid flow
// (call side encodes clientid OR reply side returns clientid).
func needsClientID(opcode uint32) bool {
	switch opcode {
	case OP_OPEN, OP_SETCLIENTID_CONFIRM, OP_DELEGPURGE, OP_RENEW:
		return true
	}
	return false
}

func encodeCompoundOpArgs(cop *NFSv4CompoundOp) []byte {
	// The caller (encodeNFS4Call) has already substituted the per-session
	// clientid in cop.Clientid where the user left it 0.
	cid := cop.Clientid
	c := *cop
	// 深拷贝 Owner 指针，避免下方 c.Owner.Clientid = cid 写回用户原始 cfg
	// （H-2 延伸）：c := *cop 是浅拷贝，c.Owner 与 cop.Owner 共享同一
	// *NFSLockOwner，必须独立拷贝才能消除 mutation 副作用。
	if c.Owner != nil {
		ownerCopy := *c.Owner
		c.Owner = &ownerCopy
	}
	switch cop.Opcode {
	case OP_PUTFH:
		return encodeOPPUTFH(nil, cop.Filehandle)
	case OP_PUTROOTFH, OP_PUTPUBFH:
		return nil
	case OP_GETATTR:
		return encodeOPGETATTR(nil, cop.AttrMask)
	case OP_LOOKUP, OP_LOOKUPP, OP_READLINK, OP_GETFH:
		if cop.Opcode == OP_LOOKUP {
			return encodeOPLOOKUP(nil, cop.Name)
		}
		return nil
	case OP_READ:
		return encodeOPREAD(nil, cop.Stateid, cop.Offset, cop.Count)
	case OP_WRITE:
		return encodeOPWRITE(nil, cop.Stateid, cop.Offset, cop.StableHow, cop.Data)
	case OP_COMMIT:
		return encodeOPCOMMIT(nil, cop.Offset, cop.Count)
	case OP_SETATTR:
		return encodeOPSETATTR(nil, cop.Stateid, cop.Attrs)
	case OP_REMOVE:
		return encodeOPREMOVE(nil, cop.Name)
	case OP_RENAME:
		return encodeOPRENAME(nil, cop.Oldname, cop.Newname)
	case OP_LINK:
		return encodeOPLINK(nil, cop.Filehandle, cop.Newname)
	case OP_ACCESS:
		return encodeOPACCESS(nil, cop.Access)
	case OP_CLOSE:
		return encodeOPCLOSE(nil, cop.Seqid, cop.OpenStateid)
	case OP_OPEN:
		if c.Owner == nil {
			c.Owner = &NFSLockOwner{Clientid: cid}
		} else if c.Owner.Clientid == 0 {
			// Mirror cid into op.Owner.Clientid so encodeOPOPEN picks it up.
			c.Owner.Clientid = cid
		}
		return encodeOPOPEN(nil, &c)
	case OP_OPEN_CONFIRM:
		// OPEN_CONFIRM4args = open_stateid4 + seqid4 (RFC 7531 §5.2).
		return encodeOPCLOSE(nil, cop.Seqid, cop.OpenStateid)
	case OP_LOCK:
		return encodeOPLOCK(nil, &c)
	case OP_LOCKT:
		return encodeOPLOCKT(nil, &c)
	case OP_LOCKU:
		return encodeOPLOCKU(nil, &c)
	case OP_CREATE:
		return encodeOPCREATE(nil, &c)
	case OP_SETCLIENTID:
		return encodeOPSETCLIENTID(nil, &c)
	case OP_SETCLIENTID_CONFIRM:
		return encodeOPSETCLIENTID_CONFIRM(nil, &c)
	case OP_DELEGPURGE:
		return encodeOPDELEGPURGE(nil, &c)
	case OP_DELEGRETURN:
		return encodeOPDELEGRETURN(nil, &c)
	case OP_RENEW:
		return encodeOPRENEW(nil, &c)
	case OP_RELEASE_LOCKOWNER:
		return encodeOPRELEASE_LOCKOWNER(nil, &c)
	case OP_READDIR:
		return encodeOPREADDIR(nil, &c)
	case OP_VERIFY:
		return encodeOPVERIFY(nil, &c)
	case OP_NVERIFY:
		return encodeOPNVERIFY(nil, &c)
	case OP_SECINFO:
		return encodeOPSECINFO(nil, &c)
	}
	return nil
}

func encodeNFS4Reply(b []byte, op *NFSOp, cfg *NFSConfig, clientid uint64, sess int) []byte {
	if op.Procedure == NFS4ProcNULL {
		return b
	}
	// Determine top-level status and per-op status/results.
	// Truncation rule §2.7:
	//   - ResultStatus != 0  → top = ResultStatus, all ops present, all op_status = ResultStatus
	//   - OpReplyStatus != 0 → top = OpReplyStatus, all ops present (single op)
	//   - one or more OpStatus != 0 → top = first failing OpStatus, oparray truncated
	top := uint32(0)
	if cfg.ResultStatus != 0 {
		top = cfg.ResultStatus
	}
	if op.ReplyStatus != 0 {
		top = op.ReplyStatus
	}
	tag := op.Tag
	// Compute the resarray.
	ops := make([]encodedResOp, 0, len(op.CompoundOps))
	if top != 0 {
		// Non-zero top status: all ops are emitted with op_status = top.
		for i := range op.CompoundOps {
			cop := &op.CompoundOps[i]
			os := top
			if cop.OpStatus != nil {
				os = *cop.OpStatus
				if os != 0 {
					top = os // S15 / T-155: top status mirrors first failing op
				}
			}
			ops = append(ops, encodedResOp{Opcode: cop.Opcode, OpStatus: os})
		}
		// If we have a per-op ReplyStatus and ops list is non-empty,
		// ensure top status reflects the single-op case.
		if op.ReplyStatus != 0 {
			top = op.ReplyStatus
		}
	} else {
		// Default: scan for first failing op, truncate after it.
		truncateAt := len(op.CompoundOps)
		for i, cop := range op.CompoundOps {
			if cop.OpStatus != nil && *cop.OpStatus != 0 {
				truncateAt = i + 1
				top = *cop.OpStatus
				break
			}
		}
		// Emit successful ops with synthesized result, truncated at first failure.
		for i := 0; i < truncateAt; i++ {
			cop := &op.CompoundOps[i]
			os := uint32(0)
			result := encodeCompoundOpResult(cop, op.OpenReplyStateid, clientid)
			ops = append(ops, encodedResOp{Opcode: cop.Opcode, OpStatus: os, Result: result})
		}
	}
	return encodeCompound4Res(b, top, tag, ops)
}

// encodeCompoundOpResult synthesizes the result body for a single
// op_status=0 resop4 entry. The size / content varies per opcode.
// sessionClientid is the per-session default clientid used when the user
// did not explicitly configure one (§4.3 rule 3: call side and reply
// side must use the same rule — explicit user value echoed, otherwise
// the default 0x10000*(i+1)+1 formula).
func encodeCompoundOpResult(cop *NFSv4CompoundOp, openStateid *NFSStateid, sessionClientid uint64) []byte {
	switch cop.Opcode {
	case OP_GETATTR:
		return resultGETATTR(cop.AttrMask)
	case OP_GETFH:
		fh := cop.Filehandle
		if fh == nil {
			fh = []byte{0xAA, 0xBB, 0xCC, 0xDD}
		}
		return resultGETFH(fh)
	case OP_OPEN, OP_OPEN_CONFIRM, OP_OPEN_DOWNGRADE, OP_CLOSE, OP_LOCK,
		OP_LOCKU, OP_DELEGRETURN:
		// stateid4 = seqid(4) + other[12]; OPEN may use the explicit
		// OpenReplyStateid if user provided one (§3.5). Otherwise the
		// reply stateid is the echo of the user's input stateid
		// (all-zero by default).
		st := openStateid
		if st == nil {
			if cop.OpenStateid != nil {
				st = cop.OpenStateid
			} else if cop.Stateid != nil {
				st = cop.Stateid
			}
		}
		return resultStateid(st)
	case OP_SETCLIENTID:
		// SETCLIENTID4res = clientid4 + setclientid_confirm4
		// (§4.3 rule 3 / §10.4: echo the clientid used by the call —
		// explicit user value if configured, else the session default).
		cid := cop.Clientid
		if cid == 0 {
			cid = sessionClientid
		}
		var verf [8]byte
		if cop.Client != nil {
			verf = cop.Client.Verifier
		}
		return resultSetClientID(cid, verf)
	case OP_READ:
		return resultREAD(false, cop.Data)
	case OP_WRITE:
		var verf [8]byte
		return resultWRITE(cop.Count, cop.StableHow, verf)
	case OP_COMMIT:
		var verf [8]byte
		return resultCOMMIT(verf)
	}
	return nil
}

// --- Packet emission helpers ---

func (p *Planner) emitHandshake(ctx context.Context, out chan<- core.PacketConfig,
	flowID string, pktIndex *uint64, spec core.FlowSpec, now time.Time,
	clientSeq, serverSeq *uint32) error {
	// ISN selection per RFC 6528; spec.TCP.InitialSeq overrides the
	// client ISN for reproducible tests (§5.5).
	if spec.TCP != nil && spec.TCP.InitialSeq != 0 {
		*clientSeq = spec.TCP.InitialSeq
	}
	// Minimal 3-way handshake: SYN, SYN-ACK, ACK. Seq/ack adjusted per
	// the SYN/FIN "consumes 1 sequence number" rule (§5.5).
	hk := [3]core.PacketConfig{
		{
			FlowID: flowID, PacketIndex: *pktIndex, Direction: "up", Timestamp: now,
			L2: core.L2Config{SrcMAC: spec.SrcMAC, DstMAC: spec.DstMAC, EtherType: 0x0800},
			L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, 64, 1, spec),
			L4: core.L4Config{Protocol: "tcp", SrcPort: spec.SrcPort, DstPort: spec.DstPort, Flags: 0x02, Seq: *clientSeq, Ack: 0},
		},
		{
			FlowID: flowID, PacketIndex: *pktIndex + 1, Direction: "down", Timestamp: now,
			L2: core.L2Config{SrcMAC: spec.DstMAC, DstMAC: spec.SrcMAC, EtherType: 0x0800},
			L3: core.L3Base(spec.DstIP, spec.SrcIP, 6, 64, 2, spec),
			L4: core.L4Config{Protocol: "tcp", SrcPort: spec.DstPort, DstPort: spec.SrcPort, Flags: 0x12, Seq: *serverSeq, Ack: *clientSeq + 1},
		},
		{
			FlowID: flowID, PacketIndex: *pktIndex + 2, Direction: "up", Timestamp: now,
			L2: core.L2Config{SrcMAC: spec.SrcMAC, DstMAC: spec.DstMAC, EtherType: 0x0800},
			L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, 64, 3, spec),
			L4: core.L4Config{Protocol: "tcp", SrcPort: spec.SrcPort, DstPort: spec.DstPort, Flags: 0x10, Seq: *clientSeq + 1, Ack: *serverSeq + 1},
		},
	}
	for i := range hk {
		select {
		case out <- hk[i]:
		case <-ctx.Done():
			return fmt.Errorf("cancelled")
		}
	}
	*pktIndex += 3
	// Advance past SYN/SYN-ACK: each side consumed 1 seq number.
	*clientSeq = *clientSeq + 1
	*serverSeq = *serverSeq + 1
	return nil
}

func (p *Planner) emitTeardown(ctx context.Context, out chan<- core.PacketConfig,
	flowID string, pktIndex *uint64, spec core.FlowSpec, now time.Time,
	clientSeq, serverSeq *uint32) error {
	// FIN / FIN-ACK / ACK — use maintained seq/ack values from the session
	// (was hardcoded to 5000 before v2.0.4; now reads tcpClientSeq/tcpServerSeq).
	fin := [3]core.PacketConfig{
		{
			FlowID: flowID, PacketIndex: *pktIndex, Direction: "up", Timestamp: now,
			L2: core.L2Config{SrcMAC: spec.SrcMAC, DstMAC: spec.DstMAC, EtherType: 0x0800},
			L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, 64, 100, spec),
			L4: core.L4Config{Protocol: "tcp", SrcPort: spec.SrcPort, DstPort: spec.DstPort, Flags: 0x11, Seq: *clientSeq, Ack: *serverSeq},
		},
		{
			FlowID: flowID, PacketIndex: *pktIndex + 1, Direction: "down", Timestamp: now,
			L2: core.L2Config{SrcMAC: spec.DstMAC, DstMAC: spec.SrcMAC, EtherType: 0x0800},
			L3: core.L3Base(spec.DstIP, spec.SrcIP, 6, 64, 101, spec),
			L4: core.L4Config{Protocol: "tcp", SrcPort: spec.DstPort, DstPort: spec.SrcPort, Flags: 0x11, Seq: *serverSeq, Ack: *clientSeq + 1},
		},
		{
			FlowID: flowID, PacketIndex: *pktIndex + 2, Direction: "up", Timestamp: now,
			L2: core.L2Config{SrcMAC: spec.SrcMAC, DstMAC: spec.DstMAC, EtherType: 0x0800},
			L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, 64, 102, spec),
			L4: core.L4Config{Protocol: "tcp", SrcPort: spec.SrcPort, DstPort: spec.DstPort, Flags: 0x10, Seq: *clientSeq + 1, Ack: *serverSeq + 1},
		},
	}
	for i := range fin {
		select {
		case out <- fin[i]:
		case <-ctx.Done():
			return fmt.Errorf("cancelled")
		}
	}
	*pktIndex += 3
	return nil
}

func (p *Planner) emitTCPFrame(ctx context.Context, out chan<- core.PacketConfig,
	flowID string, pktIndex *uint64, spec core.FlowSpec, now time.Time, dir string, msg []byte,
	clientSeq, serverSeq *uint32) {
	ipid := uint16(*pktIndex + 1000)
	var seq, ack uint32
	if dir == "up" {
		seq = *clientSeq
		ack = *serverSeq
	} else {
		seq = *serverSeq
		ack = *clientSeq
	}
	pc := core.PacketConfig{
		FlowID:      flowID,
		PacketIndex: *pktIndex,
		Direction:   dir,
		Timestamp:   now,
		L2: core.L2Config{
			SrcMAC:    ifElseStr(dir == "up", spec.SrcMAC, spec.DstMAC),
			DstMAC:    ifElseStr(dir == "up", spec.DstMAC, spec.SrcMAC),
			EtherType: 0x0800,
		},
		L3:      core.L3Base(ifElseStr(dir == "up", spec.SrcIP, spec.DstIP), ifElseStr(dir == "up", spec.DstIP, spec.SrcIP), 6, 64, ipid, spec),
		L4: core.L4Config{
			Protocol: "tcp",
			SrcPort:  ifElseU16(dir == "up", spec.SrcPort, spec.DstPort),
			DstPort:  ifElseU16(dir == "up", spec.DstPort, spec.SrcPort),
			Flags:    0x18, // PSH|ACK
			Seq:      seq,
			Ack:      ack,
		},
		Payload: msg,
	}
	select {
	case out <- pc:
	case <-ctx.Done():
	}
	// Advance seq by payload length (PSH-ACK data frames don't consume extra).
	if dir == "up" {
		*clientSeq += uint32(len(msg))
	} else {
		*serverSeq += uint32(len(msg))
	}
	*pktIndex++
}

func (p *Planner) emitUDP(ctx context.Context, out chan<- core.PacketConfig,
	flowID string, pktIndex *uint64, spec core.FlowSpec, now time.Time, dir string, msg []byte) {
	ipid := uint16(*pktIndex + 1000)
	pc := core.PacketConfig{
		FlowID:      flowID,
		PacketIndex: *pktIndex,
		Direction:   dir,
		Timestamp:   now,
		L2: core.L2Config{
			SrcMAC:    ifElseStr(dir == "up", spec.SrcMAC, spec.DstMAC),
			DstMAC:    ifElseStr(dir == "up", spec.DstMAC, spec.SrcMAC),
			EtherType: 0x0800,
		},
		L3:      core.L3Base(ifElseStr(dir == "up", spec.SrcIP, spec.DstIP), ifElseStr(dir == "up", spec.DstIP, spec.SrcIP), 17, 64, ipid, spec),
		L4: core.L4Config{
			Protocol: "udp",
			SrcPort:  ifElseU16(dir == "up", spec.SrcPort, spec.DstPort),
			DstPort:  ifElseU16(dir == "up", spec.DstPort, spec.SrcPort),
		},
		Payload: msg,
	}
	select {
	case out <- pc:
	case <-ctx.Done():
	}
	*pktIndex++
}

func ifElseStr(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func ifElseU16(cond bool, a, b uint16) uint16 {
	if cond {
		return a
	}
	return b
}

// compile-time interface check
var _ core.ProtocolPlanner = (*Planner)(nil)

// Ensure net package is used (kept for symmetry with other protocol
// packages that import net for IP validation; the spec layer handles
// that here for completeness).
var _ = net.IPv4
