package mcp

import (
	"context"
	"encoding/json"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// manageFilesystemInput covers the 7 filesystem actions. Fields are
// action-specific; only `action` is always required. The LLM fills in
// whichever fields the chosen action needs (documented per-field below).
//
// Path semantics: `path` is a relative path inside the filesystem root
// (e.g. "docs/readme.txt", "sub/dir/"). Absolute paths and paths
// containing ".." that escape the root are rejected by the filesystem
// layer. The "." alias for the root is only valid for list (matches the
// filesystem.List contract).
//
// Read shape: read returns {bytes_base64, length}. The LLM must base64-
// decode the bytes to obtain the file content (binary-safe). This mirrors
// the established pcap payload pattern (see tools_pcap.go §wrapBinaryAsBase64).
type manageFilesystemInput struct {
	Action    string             `json:"action" jsonschema:"operation: upload|read|delete|mkdir|rmdir|list|query"`
	Path      string             `json:"path,omitempty" jsonschema:"relative path inside the filesystem root (e.g. \"docs/readme.txt\"). Required for all actions. For list, \".\" lists the root."`
	Source    *filesystem.FileSource `json:"source,omitempty" jsonschema:"file source (upload only). One of: {file: <relative-or-absolute-path>, literal: <text>, fill: {byte, bytes}, random: {min_bytes, max_bytes, seed}}. file reads from another filesystem entry (relative) or an absolute disk path (outside root). literal is inline text bytes. fill repeats a single byte. random generates random bytes (seed=0 -> crypto-random fresh each call, non-zero -> reproducible)."`
	Recursive bool               `json:"recursive,omitempty" jsonschema:"recursive directory removal (rmdir only). When true, deletes the directory and all files/sub-directories inside it. When false (default), rejects removal of a non-empty directory with ErrNotEmpty."`
}

type manageFilesystemOutput struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (s *Server) registerFilesystemTool() {
	mcp.AddTool(s.mcpServer,
		&mcp.Tool{
			Name:        "flowb_manage_filesystem",
			Description: "Manage the trafficgen content-addressed filesystem: upload/read/delete/mkdir/rmdir/list/query files and directories. upload writes a file from a JSON-described source (literal text, fill byte, random bytes, or another filesystem/disk file). read returns file bytes base64-encoded (binary-safe). delete removes a file (last reference deletes the backing blob). mkdir creates a directory (idempotent). rmdir removes a directory (recursive=true to delete non-empty). list lists entries in a directory. query returns metadata (size, mtime, sha256, is_dir) for a path." + autoExportNote,
			OutputSchema: manageOutputSchema(),
		},
		s.handleManageFilesystem,
	)
}

func (s *Server) handleManageFilesystem(ctx context.Context, req *mcp.CallToolRequest, in manageFilesystemInput) (*mcp.CallToolResult, manageFilesystemOutput, error) {
	start := time.Now()

	if s.filesystem == nil {
		s.auditLog(req, "flowb_manage_filesystem", time.Since(start), "error", "filesystem not configured")
		return nil, manageFilesystemOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: "filesystem not configured on this server",
		}
	}

	// Path pre-validation: every action requires a non-empty path. Validating
	// here gives a clean InvalidParams error before we hit the filesystem,
	// and avoids a less helpful "filesystem: path must not be empty" message
	// from the filesystem layer (which would surface as a generic InternalError
	// because the MCP layer doesn't translate filesystem-layer error strings
	// to HTTP status codes the way the REST handler does).
	if in.Path == "" {
		s.auditLog(req, "flowb_manage_filesystem", time.Since(start), "error", "missing path")
		return nil, manageFilesystemOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: "path is required for action " + in.Action,
		}
	}

	var (
		result interface{}
		err    error
	)

	switch in.Action {
	case "upload":
		if in.Source == nil {
			s.auditLog(req, "flowb_manage_filesystem", time.Since(start), "error", "missing source for upload")
			return nil, manageFilesystemOutput{}, &jsonrpc.Error{
				Code:    jsonrpc.CodeInvalidParams,
				Message: "source is required for action upload",
			}
		}
		err = s.filesystem.Upload(ctx, in.Path, *in.Source)
		if err != nil {
			break
		}
		result = map[string]interface{}{"path": in.Path, "uploaded": true}

	case "read":
		var b []byte
		b, err = s.filesystem.Read(ctx, in.Path)
		if err != nil {
			break
		}
		// Binary-safe envelope: base64-encode the bytes. The LLM consumer
		// must decode `bytes_base64` to obtain the raw file content. This
		// mirrors the established pcap payload pattern (wrapBinaryAsBase64)
		// and avoids corruption of binary payloads that don't round-trip
		// cleanly through JSON-as-text.
		result = map[string]interface{}{
			"bytes_base64": base64.StdEncoding.EncodeToString(b),
			"length":       len(b),
		}

	case "delete":
		err = s.filesystem.Delete(ctx, in.Path)
		if err != nil {
			break
		}
		result = map[string]interface{}{"path": in.Path, "deleted": true}

	case "mkdir":
		err = s.filesystem.Mkdir(ctx, in.Path)
		if err != nil {
			break
		}
		result = map[string]interface{}{"path": in.Path, "created": true}

	case "rmdir":
		err = s.filesystem.Rmdir(ctx, in.Path, filesystem.RmdirOptions{Recursive: in.Recursive})
		if err != nil {
			break
		}
		result = map[string]interface{}{"path": in.Path, "removed": true, "recursive": in.Recursive}

	case "list":
		var entries []filesystem.FileInfo
		entries, err = s.filesystem.List(ctx, in.Path)
		if err != nil {
			break
		}
		result = map[string]interface{}{"path": in.Path, "entries": entries}

	case "query":
		var info filesystem.FileInfo
		info, err = s.filesystem.Query(ctx, in.Path)
		if err != nil {
			break
		}
		result = info

	default:
		s.auditLog(req, "flowb_manage_filesystem", time.Since(start), "error", "invalid action: "+in.Action)
		return nil, manageFilesystemOutput{}, &jsonrpc.Error{
			Code:    jsonrpc.CodeInvalidParams,
			Message: fmt.Sprintf("invalid action %q (want upload|read|delete|mkdir|rmdir|list|query)", in.Action),
		}
	}

	duration := time.Since(start)
	if err != nil {
		// Map filesystem sentinel errors to MCP InvalidParams so the LLM gets
		// a clear actionable error (not a generic InternalError). The REST
		// handler does the same mapping via respondFsError (HTTP 404/409).
		// The MCP layer cannot use HTTP status codes, but the jsonrpc code
		// is what the LLM client surfaces.
		switch {
		case errors.Is(err, filesystem.ErrNotFound),
			errors.Is(err, filesystem.ErrExists),
			errors.Is(err, filesystem.ErrNotEmpty),
			errors.Is(err, filesystem.ErrNotADirectory):
			s.auditLog(req, "flowb_manage_filesystem", duration, "error", err.Error())
			return nil, manageFilesystemOutput{}, &jsonrpc.Error{
				Code:    jsonrpc.CodeInvalidParams,
				Message: err.Error(),
			}
		default:
			s.auditLog(req, "flowb_manage_filesystem", duration, "error", err.Error())
			return nil, manageFilesystemOutput{}, &jsonrpc.Error{
				Code:    jsonrpc.CodeInternalError,
				Message: err.Error(),
			}
		}
	}

	s.auditLog(req, "flowb_manage_filesystem", duration, "success", "")
	// read/list of large content would flood the model context (a whole
	// file arrives base64-inline); above the inline threshold the payload
	// becomes a server-managed export with a download link (user ruling
	// 2026-10-03 — every MCP contract assumes a remote client).
	raw, merr := json.Marshal(result)
	if merr != nil {
		return nil, manageFilesystemOutput{}, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "encode result: " + merr.Error()}
	}
	return nil, manageFilesystemOutput{Action: in.Action, Data: rawData(s.maybeExport("filesystem_"+in.Action, raw))}, nil
}
