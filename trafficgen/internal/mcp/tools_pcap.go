package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/api/rest"
)

// managePcapsInput covers the 17 PCAP actions. Fields are action-specific;
// only `action` is always required. The LLM fills in whichever fields the
// chosen action needs (documented per-field below).
type managePcapsInput struct {
	Action       string                 `json:"action" jsonschema:"operation: import|list|get|delete|list_flows|get_flow|list_packets|list_packets_by_asset|get_packet|get_packet_payload|get_stream|get_body|search|match_preview|extract|download|reparse"`
	ID           string                 `json:"id,omitempty" jsonschema:"asset id (required for all actions except import/list)"`
	FilePath     string                 `json:"file_path,omitempty" jsonschema:"absolute server-side file path (import only); over HTTP this tool's description carries the concrete upload URL for remote clients"`
	FlowID       string                 `json:"flow_id,omitempty" jsonschema:"flow id (get_flow/list_packets/get_stream/get_body)"`
	PacketID     string                 `json:"packet_id,omitempty" jsonschema:"packet id (get_packet/get_packet_payload)"`
	Direction    string                 `json:"direction,omitempty" jsonschema:"stream direction: c2s|s2c (get_stream/get_body)"`
	Offset       int64                  `json:"offset,omitempty" jsonschema:"byte offset within stream (get_stream, optional)"`
	Limit        int64                  `json:"limit,omitempty" jsonschema:"byte length to read (get_stream, optional)"`
	Filters      map[string]interface{} `json:"filters,omitempty" jsonschema:"search/match_preview/extract filter object (action-specific shape)"`
	ExtractRules map[string]interface{} `json:"extract_rules,omitempty" jsonschema:"extract request {packet_ids, fields} -- fields are layer field names: src_ip, dst_ip, src_port, dst_port, seq, ack, tcp_flags, window, ttl, protocol (NOT model field names like SrcIP/TimestampUs); use get_packet to see available fields"`
	Matcher      map[string]interface{} `json:"matcher,omitempty" jsonschema:"match_preview FlowMatcher object"`
	Force        bool                   `json:"force,omitempty" jsonschema:"force delete even if referenced (delete)"`
	Page         int                    `json:"page,omitempty" jsonschema:"page number (list/list_flows/list_packets, default 1)"`
	Size         int                    `json:"size,omitempty" jsonschema:"page size (list/list_flows/list_packets, default 20/50)"`
	Status       string                 `json:"status,omitempty" jsonschema:"filter by asset status (list)"`
	OutputPath   string                 `json:"output_path,omitempty" jsonschema:"optional — force the FULL result into a file instead of returning it inline (large lists, extracts, stream bodies); the response becomes a small receipt {written_to, bytes, export_id, download_url}. Remote (HTTP): give just a file name like 'flows.json' — the server stores it and the receipt carries a ready download_url. Local (stdio): give an absolute path on this host. Without output_path, responses above 64 KB are auto-exported the same way, so huge results never flood the conversation"`
}

type managePcapsOutput struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (s *Server) registerPcapTools() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:         "flowb_manage_pcaps",
			Description:  "Manage PCAP assets: import/list/get/delete, parse flows/packets, search/extract, download. 17 actions covering the full PCAP lifecycle. Task-generated pcaps are auto-registered here (files up to 64MB; get_task_progress returns the pcap_asset_id) so you can inspect flows/packets and download without extra steps. action=download returns file_path (local/stdio) or an unauthenticated download_url (HTTP) for the pcap file.",
			OutputSchema: manageOutputSchema(),
		},
		s.handleManagePcaps,
	)
}

func (s *Server) handleManagePcaps(ctx context.Context, req *mcp.CallToolRequest, in managePcapsInput) (*mcp.CallToolResult, managePcapsOutput, error) {
	start := time.Now()
	// ID pre-validation: actions other than import/list require an asset ID.
	// Validating here gives a clean InvalidParams error before we construct a
	// handler and hit the DB, and before per-action code has to repeat the
	// check. (Pre-fix, several actions passed an empty :id to the REST handler
	// which 404'd with a less helpful "record not found" message.)
	switch in.Action {
	case "import", "list":
		// no ID required
	default:
		if in.ID == "" {
			s.auditLog(req, "flowb_manage_pcaps", 0, "error", "missing id for action="+in.Action)
			return nil, managePcapsOutput{}, &jsonrpc.Error{
				Code:    jsonrpc.CodeInvalidParams,
				Message: "id is required for action " + in.Action,
			}
		}
	}
	// FlowID pre-validation for flow-scoped actions.
	switch in.Action {
	case "get_flow", "list_packets", "get_stream", "get_body":
		if in.FlowID == "" {
			s.auditLog(req, "flowb_manage_pcaps", 0, "error", "missing flow_id for action="+in.Action)
			return nil, managePcapsOutput{}, &jsonrpc.Error{
				Code:    jsonrpc.CodeInvalidParams,
				Message: "flow_id is required for action " + in.Action,
			}
		}
	}
	// PacketID pre-validation for packet-scoped actions.
	switch in.Action {
	case "get_packet", "get_packet_payload":
		if in.PacketID == "" {
			s.auditLog(req, "flowb_manage_pcaps", 0, "error", "missing packet_id for action="+in.Action)
			return nil, managePcapsOutput{}, &jsonrpc.Error{
				Code:    jsonrpc.CodeInvalidParams,
				Message: "packet_id is required for action " + in.Action,
			}
		}
	}

	h := rest.NewPcapHandler(s.db, "")

	var resp *backendResponse
	var err error

	switch in.Action {
	case "import":
		resp, err = s.handlePcapImport(ctx, h, in)
	case "list":
		q := buildPcapListQuery(in)
		resp, err = s.callHandler(ctx, nil, "", q, h.List)
	case "get":
		resp, err = s.callHandler(ctx, nil, in.ID, nil, h.Get)
	case "delete":
		q := url.Values{}
		if in.Force {
			q.Set("force", "true")
		}
		resp, err = s.callHandler(ctx, nil, in.ID, q, h.Delete)
	case "list_flows":
		q := buildPcapPageQuery(in, 50)
		resp, err = s.callHandler(ctx, nil, in.ID, q, h.ListFlows)
	case "get_flow":
		resp, err = s.callHandlerWithParams(ctx, nil, gin.Params{{Key: "id", Value: in.ID}, {Key: "fid", Value: in.FlowID}}, nil, h.GetFlow)
	case "list_packets":
		q := buildPcapPageQuery(in, 50)
		resp, err = s.callHandlerWithParams(ctx, nil, gin.Params{{Key: "id", Value: in.ID}, {Key: "fid", Value: in.FlowID}}, q, h.ListPackets)
	case "list_packets_by_asset":
		q := buildPcapPageQuery(in, 50)
		resp, err = s.callHandler(ctx, nil, in.ID, q, h.ListPacketsByAsset)
	case "get_packet":
		resp, err = s.callHandlerWithParams(ctx, nil, gin.Params{{Key: "id", Value: in.ID}, {Key: "pid", Value: in.PacketID}}, nil, h.GetPacket)
	case "get_packet_payload":
		resp, err = s.handlePcapBinary(ctx, in.ID, in.PacketID, h.GetPacketPayload)
	case "get_stream":
		resp, err = s.handlePcapStreamBinary(ctx, in.ID, in.FlowID, in, h.GetStream)
	case "get_body":
		resp, err = s.handlePcapBodyBinary(ctx, in.ID, in.FlowID, in, h.GetBody)
	case "search":
		body := mustMarshal(in.Filters)
		resp, err = s.callHandler(ctx, body, in.ID, nil, h.Search)
	case "match_preview":
		body := mustMarshal(in.Matcher)
		resp, err = s.callHandler(ctx, body, in.ID, nil, h.MatchPreview)
	case "extract":
		body := mustMarshal(in.ExtractRules)
		resp, err = s.callHandler(ctx, body, in.ID, nil, h.Extract)
	case "download":
		resp, err = s.handlePcapDownload(ctx, h, in.ID)
	case "reparse":
		resp, err = s.callHandler(ctx, nil, in.ID, nil, h.Reparse)
	default:
		s.auditLog(req, "flowb_manage_pcaps", time.Since(start), "error", "invalid action")
		return nil, managePcapsOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: fmt.Sprintf("invalid action %q", in.Action),
		}
	}

	duration := time.Since(start)
	if err != nil {
		s.auditLog(req, "flowb_manage_pcaps", duration, "error", err.Error())
		return nil, managePcapsOutput{}, err
	}
	if in.OutputPath != "" {
		written, werr := s.applyOutputPath(ctx, in.OutputPath, resp.Data)
		if werr != nil {
			s.auditLog(req, "flowb_manage_pcaps", duration, "error", werr.Error())
			return nil, managePcapsOutput{}, werr
		}
		resp.Data = written
	}

	s.auditLog(req, "flowb_manage_pcaps", duration, "success", "")
	return nil, managePcapsOutput{Action: in.Action, Data: taskDataForTransport(ctx, s.maybeExport(in.Action, resp.Data))}, nil
}

// handlePcapImport reads a local file via ImportFromPath (bypasses multipart).
func (s *Server) handlePcapImport(ctx context.Context, h *rest.PcapHandler, in managePcapsInput) (*backendResponse, error) {
	if in.FilePath == "" {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: "file_path is required for import action",
		}
	}
	// Path validation (defense-in-depth): reject obvious path-traversal patterns
	// and require an absolute path. The MCP server runs on the same host as
	// the trafficgen backend, so file_path is a server-side path -- but we still
	// block "../" sequences and relative paths to prevent the LLM from
	// accidentally pointing at sensitive files via crafted relative paths.
	// This is NOT a complete sandbox (the service account can still read any
	// file the OS user can read) -- it just catches the common cases.
	if !filepath.IsAbs(in.FilePath) {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: "file_path must be an absolute path (got: " + in.FilePath + ")",
		}
	}
	cleaned := filepath.Clean(in.FilePath)
	if cleaned != in.FilePath {
		// filepath.Clean changed the path -> it contained "..", "//", or "./".
		// Reject rather than silently using the cleaned version, so the LLM
		// gets feedback about the suspicious path it sent.
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: "file_path contains suspicious traversal/normalization (got: " + in.FilePath + ")",
		}
	}
	asset, err := h.ImportFromPath(s.serviceUserID, in.FilePath)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: "import failed: " + err.Error(),
		}
	}
	data, _ := json.Marshal(asset)
	return &backendResponse{Code: 0, Data: data}, nil
}

// handlePcapDownload returns the file path + size as JSON (the LLM can then
// read the file directly). We do NOT stream the binary content through MCP.
func (s *Server) handlePcapDownload(ctx context.Context, h *rest.PcapHandler, id string) (*backendResponse, error) {
	// Fetch the asset via the Get handler (reuses ownership + ready checks).
	resp, err := s.callHandler(ctx, nil, id, nil, h.Get)
	if err != nil {
		return nil, err
	}

	// resp.Data is the asset JSON. PcapAssetModel has no JSON tags, so Go
	// uses the capitalized field names. Unmarshal matches field names
	// case-insensitively, so a tagless struct works.
	var asset struct {
		StoragePath      string
		FileSize         int64
		OriginalFilename string
	}
	if err := json.Unmarshal(resp.Data, &asset); err != nil {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "parse asset: " + err.Error()}
	}

	// download_url → the unauthenticated capability link
	// (/downloads/pcaps/<id>/download). taskDataForTransport rewrites it to
	// an absolute URL over HTTP (client-fetchable as-is) and strips it for
	// stdio (same-host clients read file_path directly).
	data, _ := json.Marshal(map[string]interface{}{
		"file_path":         asset.StoragePath,
		"file_size":         asset.FileSize,
		"original_filename": asset.OriginalFilename,
		"download_url":      "/downloads/pcaps/" + id + "/download",
	})
	adapted, _ := json.Marshal(taskDataForTransport(ctx, data))
	return &backendResponse{Code: 0, Data: adapted}, nil
}

// handlePcapBinary calls a binary-returning handler (get_packet_payload) and
// base64-encodes the result. The handler writes via c.Data(200, octet-stream,
// buf); we capture the raw bytes and wrap in {payload_base64, length}.
func (s *Server) handlePcapBinary(ctx context.Context, id, pid string, handler func(*gin.Context)) (*backendResponse, error) {
	params := gin.Params{{Key: "id", Value: id}, {Key: "pid", Value: pid}}
	resp, err := s.callRawHandlerWithParams(ctx, params, nil, handler)
	if err != nil {
		return nil, err
	}
	return wrapBinaryAsBase64(resp.Data), nil
}

// handlePcapStreamBinary calls get_stream with dir/offset/limit query params.
func (s *Server) handlePcapStreamBinary(ctx context.Context, id, flowID string, in managePcapsInput, handler func(*gin.Context)) (*backendResponse, error) {
	q := url.Values{}
	if in.Direction != "" {
		q.Set("dir", in.Direction)
	}
	if in.Offset > 0 {
		q.Set("offset", strconv.FormatInt(in.Offset, 10))
	}
	if in.Limit > 0 {
		q.Set("limit", strconv.FormatInt(in.Limit, 10))
	}
	params := gin.Params{{Key: "id", Value: id}, {Key: "fid", Value: flowID}}
	resp, err := s.callRawHandlerWithParams(ctx, params, q, handler)
	if err != nil {
		return nil, err
	}
	return wrapBinaryAsBase64(resp.Data), nil
}

// handlePcapBodyBinary calls get_body with dir query param.
func (s *Server) handlePcapBodyBinary(ctx context.Context, id, flowID string, in managePcapsInput, handler func(*gin.Context)) (*backendResponse, error) {
	q := url.Values{}
	if in.Direction != "" {
		q.Set("dir", in.Direction)
	}
	params := gin.Params{{Key: "id", Value: id}, {Key: "fid", Value: flowID}}
	resp, err := s.callRawHandlerWithParams(ctx, params, q, handler)
	if err != nil {
		return nil, err
	}
	return wrapBinaryAsBase64(resp.Data), nil
}

// wrapBinaryAsBase64 converts raw binary bytes to a JSON envelope
// {payload_base64, length} so the MCP SDK can marshal it cleanly.
func wrapBinaryAsBase64(raw []byte) *backendResponse {
	b64 := base64.StdEncoding.EncodeToString(raw)
	data, _ := json.Marshal(map[string]interface{}{
		"payload_base64": b64,
		"length":         len(raw),
	})
	return &backendResponse{Code: 0, Data: data}
}

// buildPcapListQuery builds the query params for the list action.
func buildPcapListQuery(in managePcapsInput) url.Values {
	q := url.Values{}
	if in.Page > 0 {
		q.Set("page", strconv.Itoa(in.Page))
	}
	if in.Size > 0 {
		q.Set("size", strconv.Itoa(in.Size))
	}
	if in.Status != "" {
		q.Set("status", in.Status)
	}
	if len(q) == 0 {
		return nil
	}
	return q
}

// buildPcapPageQuery builds page/size query params with a default size hint.
func buildPcapPageQuery(in managePcapsInput, defaultSize int) url.Values {
	q := url.Values{}
	if in.Page > 0 {
		q.Set("page", strconv.Itoa(in.Page))
	}
	if in.Size > 0 {
		q.Set("size", strconv.Itoa(in.Size))
	}
	if len(q) == 0 {
		return nil
	}
	return q
}
