package protocolpcap

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Case is one test case extracted from a protocol design doc §7 table.
type Case struct {
	ID       string          `json:"id"`
	Proto    string          `json:"proto"`
	Summary  string          `json:"summary"`
	SpecJSON json.RawMessage `json:"spec_json"`        // generate_traffic "config" argument
	Output   string          `json:"output,omitempty"` // output_type override ("pcap" default)
	// StrategyFC, when set, is passed as generate_traffic's
	// "strategy_flow_control" argument (e.g. {"type":"flows","value":N} for
	// multi-flow cases). Absent = no strategy flow control.
	StrategyFC *strategyFCInput `json:"strategy_fc,omitempty"`
	// Expect holds verification hints; verified against the pcap by verify.go.
	Expect struct {
		PacketCount  int           `json:"packet_count,omitempty"` // exact expected packet count
		MinPackets   int           `json:"min_packets,omitempty"`
		Fields       []FieldAssert `json:"fields,omitempty"`
		Frames       []FrameAssert `json:"frames,omitempty"`        // raw byte assertions
		HasHandshake bool          `json:"has_handshake,omitempty"` // TCP SYN first packet
		HasPayload   bool          `json:"has_payload,omitempty"`
		Negotiated   bool          `json:"negotiated,omitempty"`
		Terminates   bool          `json:"terminates,omitempty"`
		Directional  bool          `json:"directional,omitempty"` // both directions present
		Notes        []string      `json:"notes,omitempty"`
		// ExpectError: when true, the case is a Validate-negative — the MCP
		// generate_traffic call OR the resulting task is expected to fail/error.
		// A failure is treated as PASS; a successful completion is FAIL.
		ExpectError bool `json:"expect_error,omitempty"`
		// ErrorContains: optional substring that must appear in the error
		// message for an ExpectError case to pass (empty = any error accepted).
		ErrorContains string `json:"error_contains,omitempty"`
	} `json:"expect,omitempty"`
}

// FieldAssert asserts one tshark field value at one packet offset.
type FieldAssert struct {
	Packet int    `json:"packet"`          // 1-based packet index
	Field  string `json:"field"`           // tshark field name, e.g. "tcp.dstport"
	Value  string `json:"value,omitempty"` // exact string value; empty means "field present"
	// SameAsPacket: when > 0, asserts this packet's field value equals the
	// field value on that packet (1-based). Used for persistence assertions on
	// run-random values (e.g. smb2.sesid / smb2.file_id) that cannot carry a
	// fixed hex expectation.
	SameAsPacket int `json:"same_as_packet,omitempty"`
	// Nonzero: when true, asserts the field value is present and not all-zero
	// (hex-number fields like smb2.sesid emit "0x0000000000000000" for zero).
	Nonzero bool `json:"nonzero,omitempty"`
	// DistinctValues: schedule-independent aggregation assertion for multi-flow
	// cases. When non-empty, asserts that across ALL packets the field takes
	// exactly these values (each at least once) and no others. Packet index is
	// ignored — the multi-flow scheduler interleaves flows non-deterministically,
	// so fixed packet positions are meaningless for per-flow values.
	DistinctValues []string `json:"distinct_values,omitempty"`
	// DistinctExclude: values to skip during DistinctValues aggregation (e.g.
	// the server-side port on a bidirectional tcp.srcport scan). Only applies
	// when DistinctValues is non-empty.
	DistinctExclude []string `json:"distinct_exclude,omitempty"`
}

// FrameAssert asserts raw bytes of one frame (tshark -x hex dump).
type FrameAssert struct {
	Packet int    `json:"packet"`           // 1-based packet index
	Offset int    `json:"offset,omitempty"` // byte offset into the frame; default 0
	Hex    string `json:"hex"`              // wanted bytes, e.g. "00 01 63 6f 6e 66 69 67" (prefix match at offset)
}

// strategyFCInput mirrors the MCP flowControlInput shape
// (internal/mcp/tools_strategy.go): {"type":"flows","value":N}.
type strategyFCInput struct {
	Type  string  `json:"type"`
	Value float64 `json:"value"`
}

// CaseResult is the outcome of driving one case through the MCP server.
type CaseResult struct {
	CaseID      string
	Proto       string
	Summary     string
	Status      string // "pass" | "fail" | "error"
	TaskID      string
	PcapAbsPath string
	PcapRelPath string
	PacketCount int
	Err         string
	Notes       []string
}

// GenerateResult is the raw generate_traffic response.
type generateResult struct {
	TaskID     string `json:"task_id"`
	StrategyID string `json:"strategy_id"`
	Status     string `json:"status"`
}

// progressResult is the flowb_get_task_progress response.
type progressResult struct {
	Status       string `json:"status"`
	Progress     int    `json:"progress"`
	PacketsSent  int64  `json:"packets_sent"`
	BytesSent    int64  `json:"bytes_sent"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// Runner drives cases through the MCP server, one generate_traffic call per
// case, and writes each pcap under pcapDir/<proto>/<caseID>.pcap.
type Runner struct {
	Client *Client
	// PcapDir is where pcap files land. Use an absolute path so both the
	// server process and this test process resolve it identically.
	PcapDir string
	mu      sync.Mutex
}

// NewRunner connects a fresh MCP client and returns a Runner.
func NewRunner(ctx context.Context, endpoint, apiKey, pcapDir string) (*Runner, error) {
	c, err := NewClient(ctx, endpoint, apiKey)
	if err != nil {
		return nil, err
	}
	return &Runner{Client: c, PcapDir: pcapDir}, nil
}

// Close closes the underlying MCP client.
func (r *Runner) Close() { r.Client.Close() }

// RunCase drives one case: generate_traffic -> poll -> locate pcap.
// It returns a CaseResult; the pcap is NOT yet verified (verify.go does that).
func (r *Runner) RunCase(ctx context.Context, c Case, timeout time.Duration) *CaseResult {
	res := &CaseResult{CaseID: c.ID, Proto: c.Proto, Summary: c.Summary, Status: "error"}
	outputType := c.Output
	if outputType == "" {
		outputType = "pcap"
	}
	absPath := filepath.Join(r.PcapDir, c.Proto, c.ID+".pcap")
	args := map[string]any{
		"task_name":   fmt.Sprintf("%s-%s", c.Proto, c.ID),
		"protocol":    c.Proto,
		"config":      json.RawMessage(c.SpecJSON),
		"output_type": outputType,
		"output_config": map[string]any{
			"pcap_path": absPath,
		},
	}
	if c.StrategyFC != nil {
		args["strategy_flow_control"] = map[string]any{
			"type":  c.StrategyFC.Type,
			"value": c.StrategyFC.Value,
		}
	}
	raw, err := r.Client.CallTool(ctx, "flowb_generate_traffic", args)
	if err != nil {
		// Validate-negative: MCP call itself rejected the config.
		if c.Expect.ExpectError {
			if ec := c.Expect.ErrorContains; ec != "" && !strings.Contains(err.Error(), ec) {
				res.Status = "fail"
				res.Err = fmt.Sprintf("expected error containing %q, got: %v", ec, err)
				return res
			}
			res.Status = "pass"
			res.Err = ""
			return res
		}
		res.Err = err.Error()
		return res
	}
	var gres generateResult
	if err := json.Unmarshal(raw, &gres); err != nil {
		res.Err = fmt.Sprintf("parse generate_traffic result: %v (raw=%s)", err, raw)
		return res
	}
	res.TaskID = gres.TaskID
	if gres.TaskID == "" {
		res.Err = fmt.Sprintf("no task_id in generate_traffic result: %s", raw)
		return res
	}

	// Poll task progress until terminal state.
	deadline := time.Now().Add(timeout)
	for {
		raw, err = r.Client.CallTool(ctx, "flowb_get_task_progress", map[string]any{"task_id": gres.TaskID})
		if err != nil {
			res.Err = fmt.Sprintf("poll task %s: %v", gres.TaskID, err)
			return res
		}
		var rawProgress struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &rawProgress); err != nil {
			res.Err = fmt.Sprintf("parse progress result: %v (raw=%s)", err, raw)
			return res
		}
		var pres progressResult
		if err := json.Unmarshal(rawProgress.Data, &pres); err != nil {
			res.Err = fmt.Sprintf("parse progress data: %v (raw=%s)", err, rawProgress.Data)
			return res
		}
		switch pres.Status {
		case "completed":
			// Validate-negative: task should have failed but succeeded.
			if c.Expect.ExpectError {
				res.Status = "fail"
				res.Err = "expected task to error (Validate-negative) but it completed successfully"
				return res
			}
			res.Status = "pass"
			res.PacketCount = int(pres.PacketsSent)
			res.PcapRelPath = absPath
			res.PcapAbsPath = absPath
			if _, err := os.Stat(res.PcapAbsPath); err != nil {
				res.Err = fmt.Sprintf("task completed but pcap not found at %s: %v", res.PcapAbsPath, err)
				return res
			}
			// stats.packets_sent is not persisted to the task record, so
			// count actual packets from the pcap file.
			if n, err := pcapPacketCount(res.PcapAbsPath); err == nil {
				res.PacketCount = n
			}
			return res
		case "error", "failed", "stopped":
			// Validate-negative: task ended in error as expected.
			if c.Expect.ExpectError {
				msg := pres.ErrorMessage
				if ec := c.Expect.ErrorContains; ec != "" && !strings.Contains(msg, ec) {
					res.Status = "fail"
					res.Err = fmt.Sprintf("expected error containing %q, got: %s", ec, msg)
					return res
				}
				res.Status = "pass"
				res.Err = ""
				return res
			}
			res.Err = fmt.Sprintf("task %s ended %s: %s", gres.TaskID, pres.Status, pres.ErrorMessage)
			return res
		}
		if ctx.Err() != nil {
			res.Err = fmt.Sprintf("context cancelled while polling task %s: %v", gres.TaskID, ctx.Err())
			return res
		}
		if time.Now().After(deadline) {
			res.Err = fmt.Sprintf("task %s not terminal after %v (status=%s)", gres.TaskID, timeout, pres.Status)
			return res
		}
		time.Sleep(500 * time.Millisecond)
	}
}
