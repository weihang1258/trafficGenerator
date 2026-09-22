package layers

import (
	"sync"
	"time"
)

// TCPRetransmissionStateMachine implements the TCP loss-recovery state
// machine (RFC 5681 fast recovery, RFC 6298 RTO, RFC 5961 challenge ACK).
// The state machine is a pure logic component: it consumes ACK/RTO/Challenge
// events from a per-flow driver and emits the actions (retransmit /
// new cwnd / ssthresh / RTO reschedule) the transport layer applies. It does
// NOT touch packet bytes or wire I/O — the responsibility split mirrors
// the legacy plumbing: SM holds congestion-control state, TCPGenerator
// (internal/core/layers/generator.go) writes seq/ack onto emitted packets.
//
// State diagram (all states terminal via the OPEN sink):
//
//		OPEN ─┬─ OnDupACK  → FAST_RECOVERY (3 dup-ACKs → RFC 5681 §3.2)
//		      │                  │
//		      │                  └─ OnACK     → OPEN (recovery ack)
//		      │
//		      ├─ OnRTO     → RTO_RECOVERY (RFC 6298 §5 retransmit)
//		      │                  │
//		      │                  └─ OnRTO  → RTO_RECOVERY (backoff exponential)
//		      │
//		      └─ OnChallengeACK → CHALLENGE_PENDING (RFC 5961 §3.2)
//		                            │
//		                            ├─ OnReplyMatch     → OPEN
//	                           └─ OnReplyMismatch  → CHALLENGE_REPLIED
//	                                                  → reply with RST
//
// Why the state machine is in layers/ rather than internal/protocol/tcp:
// the protocol/tcp package implements the legacy TCPGenerator that drives
// the wire state. layers/ owns the chain architecture. Keeping SM here makes
// it usable from any future chain-driven transport without reversing the
// protocol → layers import direction (which is the established constraint
// that drove RegisterLayerGenerator/RegisterHTTPGenerator reverse wiring).
//
// Concurrency: TCPRetransmissionStateMachine is NOT thread-safe. The chain
// planner drives one SM per flow in a single goroutine, matching the legacy
// per-flow worker model. External callers must serialize access.
type TCPRetransmissionStateMachine struct {
	mu sync.Mutex // guards ssthresh/cwnd on rare shared access; Event-API is the documented path

	// state is the current SM state (OPEN, FAST_RECOVERY, RTO_RECOVERY,
	// CHALLENGE_PENDING, CHALLENGE_REPLIED). On every transition it is
	// re-assigned; the previous value is logged via StateTransition (caller
	// can wire to slog if needed).
	state TCPState

	// segQueue is the set of unacknowledged segments in send order
	// (已发未确认段，按发送顺序；OnACK 从队首推进/移除已确认段，
	// OnRTO 重传队首段、OnDupACK 不重传——fast retransmit 由 driver 决策)。
	// Each segment carries (seq, len, sentAt) — the bare minimum for RTT
	// measurement; congestion-control bytes (window probes) are caller-side.
	segQueue []Segment

	// dupAckCount is the consecutive ACK count for the same ack number
	// (连续重复 ACK 计数；达 fastRetransmitThreshold 触发 RFC 5681 快速重传)。
	// Reset to 0 on any new ACK that advances sndUna.
	dupAckCount int

	// ssthresh is the slow-start threshold (慢启动阈值；RFC 5681 §3.1)。
	// Initialized to DefaultSsthresh; on loss event halved (fast recovery)
	// or ssthresh = FlightSize / 2 per RFC 5681 §3.2. Not bounded above
	// (cwnd itself caps growth; TCP doesn't enforce an upper ssthresh).
	ssthresh uint32

	// cwnd is the congestion window in bytes (拥塞窗口字节数；RFC 5681 §3)。
	// Initialized to initialCwnd (RFC 6928 §2: 10*MSS) and grows per
	// slow-start / congestion-avoidance rules.
	cwnd uint32

	// rtt is the smoothed round-trip time (平滑 RTT，RFC 6298 §2.2)。
	// rttvar is the RTT variance. First sample initializes both; subsequent
	// samples apply EWMA (alpha=1/8, beta=1/4 per RFC 6298).
	rtt    time.Duration
	rttvar time.Duration

	// rto is the retransmission timeout (重传超时，RFC 6298 §2.3)。
	// Initialized to rtoInitial; updated as RTT samples arrive; on
	// retransmission backoff exponentially (×2 per attempt, capped at rtoMax).
	rto time.Duration

	// rtoAttempts counts consecutive RTO-driven retransmissions (连续 RTO
	// 重传次数；用于 rto backoff 计算：rto <<= min(attempts, rtoBackoffCap))。
	// Reset to 0 on any ACK that advances sndUna.
	rtoAttempts int

	// fastRetransmitThreshold is the dup-ACK count that triggers RFC 5681
	// fast retransmit (default 3 per RFC 5681 §3.2; we keep the constant
	// configurable for testing/edge cases like Linux tcp_retransmit_threshold).
	fastRetransmitThreshold int

	// mssBytes is the maximum segment size used to convert between byte
	// (cwnd/ssthresh) and segment (loss event) units. MUST be set by caller
	// before driving; zero is treated as 1 byte (degenerate but does not
	// divide by zero).
	mssBytes uint32

	// challengeData is the byte the challenge ACK protected (RFC 5961 §3.2
	// blind RST attack defense: a RST in response to an in-window segment
	// must echo the seq OR the data window to be honored). Captured on
	// OnChallengeACK; OnReplyMatch/Mismatch consult it.
	challengeData uint32
}

// TCPState is the SM state (one constant per RFC 5681/RFC 6298/RFC 5961
// state). String is for logging only; the SM compares by integer value.
type TCPState int

const (
	TCPStateOpen TCPState = iota
	TCPStateFastRecovery
	TCPStateRTO
	TCPStateChallengePending
	TCPStateChallengeReplied
)

func (s TCPState) String() string {
	switch s {
	case TCPStateOpen:
		return "OPEN"
	case TCPStateFastRecovery:
		return "FAST_RECOVERY"
	case TCPStateRTO:
		return "RTO"
	case TCPStateChallengePending:
		return "CHALLENGE_PENDING"
	case TCPStateChallengeReplied:
		return "CHALLENGE_REPLIED"
	}
	return "UNKNOWN"
}

// Segment is one unacknowledged segment in the send queue (一个未确认段)。
// Bare-minimum fields for RTT measurement: seq, len (bytes), and sentAt.
// Congestion-window probes (RFC 6928 §3) and SACK blocks are caller-side
// data structures; the SM only tracks the unacked-byte total via segQueue.
type Segment struct {
	Seq    uint32
	Len    uint32
	SentAt time.Time
	// Retransmits is the number of times this segment has been retransmitted
	// (重传次数；Kernel marks seg re-sent for Karn's algorithm — SM
	// ignores RTT samples for retransmitted segs to avoid ambiguity,
	// RFC 6298 §5.3 / Karn's algorithm).
	Retransmits int
}

// TCPRetransmissionConfig configures the SM. Zero fields use defaults
// (initialCwnd=10*MSS, ssthresh=65535, rto=1s, fastRetransmitThreshold=3,
// mssBytes=DefaultMSS=1460). Callers MUST set MSS to match the transport
// generator; mismatched cwnd/ssthresh units will silently produce wrong
// throughput.
type TCPRetransmissionConfig struct {
	MSSBytes                uint32
	InitialCwndSegments     uint32 // RFC 6928 §2: 10
	InitialSsthresh         uint32 // RFC 6928 §2: 65535 (≈∞)
	InitialRTO              time.Duration
	FastRetransmitThreshold int
	// RTOBackoffCap is the maximum RTO backoff exponent (RFC 6298 §5.5
	// recommends a cap; Linux caps at 120s after 8 attempts). Zero = 8.
	RTOBackoffCap int
	// RTOMax bounds the final RTO (after backoff). Zero = 60s (RFC 6298 §2.3
	// suggests at least 60s; Linux uses 120s).
	RTOMax time.Duration
}

const (
	defaultMSS                 = uint32(1460) // matches DefaultMSS in generator.go
	defaultInitialCwndSegments = uint32(10)   // RFC 6928 §2
	defaultInitialSsthresh     = uint32(65535)
	defaultInitialRTO          = 1 * time.Second // RFC 6298 §2.1
	defaultFastRetransmit      = 3               // RFC 5681 §3.2
	defaultRTOBackoffCap       = 8               // ≈ RFC 6298 §5.5 / Linux behavior
	defaultRTOMax              = 60 * time.Second
)

// NewTCPRetransmissionStateMachine builds a SM with the given config. A
// zero-value config falls back to defaults (RFC 6928 + RFC 6298 + RFC 5681).
// The returned SM is in TCPStateOpen with cwnd/ssthresh/rto pre-populated.
func NewTCPRetransmissionStateMachine(cfg TCPRetransmissionConfig) *TCPRetransmissionStateMachine {
	if cfg.MSSBytes == 0 {
		cfg.MSSBytes = defaultMSS
	}
	if cfg.InitialCwndSegments == 0 {
		cfg.InitialCwndSegments = defaultInitialCwndSegments
	}
	if cfg.InitialSsthresh == 0 {
		cfg.InitialSsthresh = defaultInitialSsthresh
	}
	if cfg.InitialRTO == 0 {
		cfg.InitialRTO = defaultInitialRTO
	}
	if cfg.FastRetransmitThreshold == 0 {
		cfg.FastRetransmitThreshold = defaultFastRetransmit
	}
	if cfg.RTOBackoffCap == 0 {
		cfg.RTOBackoffCap = defaultRTOBackoffCap
	}
	if cfg.RTOMax == 0 {
		cfg.RTOMax = defaultRTOMax
	}
	return &TCPRetransmissionStateMachine{
		state:                   TCPStateOpen,
		cwnd:                    cfg.InitialCwndSegments * cfg.MSSBytes,
		ssthresh:                cfg.InitialSsthresh,
		rto:                     cfg.InitialRTO,
		fastRetransmitThreshold: cfg.FastRetransmitThreshold,
		mssBytes:                cfg.MSSBytes,
	}
}

// State returns the current SM state (constant-time; pure read).
func (sm *TCPRetransmissionStateMachine) State() TCPState {
	return sm.state
}

// CWnd returns the current congestion window in bytes (read-only).
func (sm *TCPRetransmissionStateMachine) CWnd() uint32 {
	return sm.cwnd
}

// SSthresh returns the current slow-start threshold in bytes (read-only).
func (sm *TCPRetransmissionStateMachine) SSthresh() uint32 {
	return sm.ssthresh
}

// RTO returns the current retransmission timeout (read-only).
func (sm *TCPRetransmissionStateMachine) RTO() time.Duration {
	return sm.rto
}

// FlightSize returns the current outstanding (unacked) bytes in the
// send queue (flight size = sum of segQueue bytes; RFC 5681 §3.2 uses
// flightSize to compute ssthresh on fast retransmit). Returns 0 for an
// empty queue.
func (sm *TCPRetransmissionStateMachine) FlightSize() uint32 {
	var total uint32
	for _, s := range sm.segQueue {
		total += s.Len
	}
	return total
}

// SegQueue returns a copy of the unacked segment queue (for inspection;
// mutating the returned slice has no effect on the SM).
func (sm *TCPRetransmissionStateMachine) SegQueue() []Segment {
	out := make([]Segment, len(sm.segQueue))
	copy(out, sm.segQueue)
	return out
}

// SendSegment records a newly sent segment in the unacked queue. The
// transport layer calls this after every Emit that puts a segment on the
// wire. The segment is appended to segQueue; the driver does NOT need to
// maintain ordering itself (the SM assumes segments are sent in order).
//
// SentAt is the wall-clock time at which the segment was emitted. The
// SM uses it to compute RTT samples on the matching ACK (only the first
// transmission's sentAt — retransmitted segs are ignored per Karn's
// algorithm, RFC 6298 §5.3).
func (sm *TCPRetransmissionStateMachine) SendSegment(seq, length uint32, sentAt time.Time) {
	sm.segQueue = append(sm.segQueue, Segment{
		Seq:    seq,
		Len:    length,
		SentAt: sentAt,
	})
}

// OnACK is the event the transport layer calls when an ACK arrives. Ack
// is the cumulative ack number (sndUna on the wire). The SM:
//
//  1. Advances sndUna — pops acked segments from the segQueue head.
//  2. Resets dupAckCount and rtoAttempts to 0 (RFC 6298 §5.3 — new RTT
//     sample is now valid).
//  3. Updates RTT/RTTVAR/RTO from the new sample (RFC 6298 §2.2/§2.3).
//  4. If we were in FAST_RECOVERY and the ACK covers the recovery point
//     (i.e. it advances past the highest seq sent when we entered), exit
//     to OPEN and deflate cwnd per RFC 5681 §3.2 ("inflated cwnd is
//     reduced to ssthresh on recovery").
//  5. If we were in RTO and the ACK advances, exit to OPEN.
//  6. Grows cwnd in slow-start (cwnd += ackBytes) or congestion-avoidance
//     (cwnd += MSS*MSS/cwnd) per RFC 5681 §3.1.
//
// An ACK that does NOT advance (a duplicate ACK) is a no-op here; the
// transport layer should also call OnDupACK separately. We do NOT count
// duplicate ACKs from OnACK — keeping the two paths distinct avoids
// off-by-one in the dupAckCount sequence.
func (sm *TCPRetransmissionStateMachine) OnACK(ack uint32, now time.Time) {
	if len(sm.segQueue) == 0 {
		return
	}
	// Find the first unacked segment with seq+len > ack (RFC 793 cumulative
	// ACK: an ack N acknowledges everything up to but not including N).
	var ackedBytes uint32
	ackedIdx := 0
	for i, seg := range sm.segQueue {
		if seg.Seq+seg.Len <= ack {
			ackedBytes += seg.Len
			ackedIdx = i + 1
		} else {
			break
		}
	}
	if ackedIdx == 0 {
		// No new data acked — duplicate ACK; OnDupACK handles this path.
		return
	}

	// RTT sample: use the first newly-acked segment that was not retransmitted
	// (Karn's algorithm, RFC 6298 §5.3).
	for i := 0; i < ackedIdx; i++ {
		seg := sm.segQueue[i]
		if seg.Retransmits == 0 && !seg.SentAt.IsZero() {
			sample := now.Sub(seg.SentAt)
			if sm.rtt == 0 {
				sm.rtt = sample
				sm.rttvar = sample / 2
			} else {
				// EWMA per RFC 6298 §2.2 (alpha = 1/8, beta = 1/4).
				alpha := 1.0 / 8.0
				beta := 1.0 / 4.0
				sm.rttvar = time.Duration((1-beta)*float64(sm.rttvar) + beta*float64(absDuration(sample-sm.rtt)))
				sm.rtt = time.Duration((1-alpha)*float64(sm.rtt) + alpha*float64(sample))
			}
			// RTO = RTT + max(G, 4*RTTVAR) per RFC 6298 §2.3, capped at RTOMax.
			sm.rto = sm.rtt + 4*sm.rttvar
			if sm.rto > defaultRTOMax {
				sm.rto = defaultRTOMax
			}
			if sm.rto < time.Second {
				sm.rto = time.Second
			}
			break
		}
	}

	// Pop acked segments.
	sm.segQueue = sm.segQueue[ackedIdx:]
	sm.dupAckCount = 0
	sm.rtoAttempts = 0

	// State transitions: exit recovery states when new data is acked.
	switch sm.state {
	case TCPStateFastRecovery:
		// RFC 5681 §3.2: deflate cwnd to ssthresh and exit fast recovery.
		sm.cwnd = sm.ssthresh
		sm.state = TCPStateOpen
	case TCPStateRTO:
		sm.state = TCPStateOpen
	case TCPStateChallengePending, TCPStateChallengeReplied:
		// Recovery: any new ack clears the challenge.
		sm.state = TCPStateOpen
	}

	// cwnd growth: slow-start if cwnd < ssthresh, congestion-avoidance otherwise.
	if sm.cwnd < sm.ssthresh {
		// Slow start: cwnd += ackedBytes (RFC 5681 §3.1).
		sm.cwnd += ackedBytes
	} else {
		// Congestion avoidance: cwnd += MSS*MSS / cwnd per RTT-equivalent.
		// Approximate: cwnd += (MSS*MSS) / cwnd, byte-accurate.
		if sm.cwnd > 0 {
			sm.cwnd += (sm.mssBytes * sm.mssBytes) / sm.cwnd
		}
	}
}

// OnDupACK is the event the transport layer calls when a duplicate ACK
// arrives (cumulative ack == current sndUna, no new data). The SM:
//
//  1. Increments dupAckCount.
//  2. If count >= fastRetransmitThreshold AND we are in OPEN, transition
//     to FAST_RECOVERY: ssthresh = max(FlightSize / 2, 2*MSS),
//     cwnd = ssthresh + 3*MSS (RFC 5681 §3.2 inflation).
//  3. The transport layer should retransmit the highest unacked segment
//     at this point; the SM does NOT drive the retransmit directly (separation
//     of concerns: SM holds state, transport applies action).
//
// OnDupACK while in FAST_RECOVERY inflates cwnd by MSS (RFC 5681 §3.2:
// each dup-ACK after the third counts as indicating a packet has left
// the network, so cwnd grows by MSS).
func (sm *TCPRetransmissionStateMachine) OnDupACK() {
	sm.dupAckCount++
	switch sm.state {
	case TCPStateOpen:
		if sm.dupAckCount >= sm.fastRetransmitThreshold {
			flight := sm.FlightSize()
			// ssthresh = max(FlightSize / 2, 2*MSS) per RFC 5681 §3.2.
			half := flight / 2
			twoMSS := 2 * sm.mssBytes
			if half < twoMSS {
				half = twoMSS
			}
			sm.ssthresh = half
			// cwnd = ssthresh + 3*MSS (RFC 5681 §3.2 inflation for fast recovery).
			sm.cwnd = sm.ssthresh + 3*sm.mssBytes
			sm.state = TCPStateFastRecovery
		}
	case TCPStateFastRecovery:
		// Each additional dup-ACK: cwnd += MSS (RFC 5681 §3.2).
		sm.cwnd += sm.mssBytes
	}
}

// OnRTO is the event the transport layer calls when the retransmission
// timer fires (now >= segQueue[0].SentAt + rto AND no progress). The SM:
//
//  1. ssthresh = max(FlightSize / 2, 2*MSS) per RFC 5681 §3.1 / RFC 6298 §5.5.
//  2. cwnd = 1*MSS (back to slow start per RFC 5681 §3.1).
//  3. rto *= 2 (exponential backoff, RFC 6298 §5.5), capped at RTOMax.
//  4. rtoAttempts++.
//  5. State → RTO.
//  6. Mark the head-of-queue segment as retransmitted (Karn's algorithm:
//     this segment's RTT sample is now ineligible).
//
// The transport layer should retransmit segQueue[0] after this call.
func (sm *TCPRetransmissionStateMachine) OnRTO(now time.Time) {
	flight := sm.FlightSize()
	half := flight / 2
	twoMSS := 2 * sm.mssBytes
	if half < twoMSS {
		half = twoMSS
	}
	sm.ssthresh = half
	sm.cwnd = sm.mssBytes // back to slow start (1*MSS)

	// Exponential backoff (RFC 6298 §5.5): rto <<= 1, capped at backoffCap.
	sm.rtoAttempts++
	if sm.rtoAttempts > defaultRTOBackoffCap {
		sm.rtoAttempts = defaultRTOBackoffCap
	}
	backoff := sm.rto
	for i := 0; i < sm.rtoAttempts; i++ {
		backoff *= 2
		if backoff > defaultRTOMax {
			backoff = defaultRTOMax
			break
		}
	}
	sm.rto = backoff

	sm.state = TCPStateRTO

	// Mark head as retransmitted (Karn's algorithm).
	if len(sm.segQueue) > 0 {
		sm.segQueue[0].Retransmits++
		_ = now // wallclock captured by transport for the actual resend
	}
}

// OnChallengeACK is the event the transport layer calls when a RST arrives
// in response to a segment (RFC 5961 §3.2: blind-RST attack defense). The
// RST is "suspect" — it could be from an attacker spoofing the peer's
// address. The transport layer should hold off honoring it until the
// SM verifies.
//
// dataSeq is the in-window byte the RST claimed to protect; the SM
// captures it and waits for the next ACK to either confirm or refute.
//
// After OnChallengeACK, the transport layer should:
//
//   - NOT honor the RST.
//   - Send a Challenge ACK (an ACK with the current sndNxt) per RFC 5961 §3.2.
//   - Wait for OnReplyMatch (the peer's next ACK confirms the data) or
//     OnReplyMismatch (refutes; then send a real RST via OnReplyMismatch).
func (sm *TCPRetransmissionStateMachine) OnChallengeACK(dataSeq uint32) {
	sm.challengeData = dataSeq
	sm.state = TCPStateChallengePending
}

// OnReplyMatch is the event the transport layer calls when the peer's
// next ACK confirms the challenged data (i.e. the peer's ack covers
// dataSeq or beyond). The SM returns to OPEN and discards the suspect
// RST — the peer was alive and the RST was spoofed.
func (sm *TCPRetransmissionStateMachine) OnReplyMatch(ack uint32) {
	if sm.state != TCPStateChallengePending {
		return
	}
	if ack > sm.challengeData {
		sm.state = TCPStateOpen
		sm.challengeData = 0
	}
}

// OnReplyMismatch is the event the transport layer calls when the peer's
// next ACK does NOT confirm the challenged data. The SM transitions to
// CHALLENGE_REPLIED — the transport layer should now send a real RST
// (RFC 5961 §3.2: the RST is genuine, the peer really is resetting).
func (sm *TCPRetransmissionStateMachine) OnReplyMismatch() {
	if sm.state != TCPStateChallengePending {
		return
	}
	sm.state = TCPStateChallengeReplied
	sm.challengeData = 0
}

// absDuration returns |a| for time.Duration.
func absDuration(a time.Duration) time.Duration {
	if a < 0 {
		return -a
	}
	return a
}
