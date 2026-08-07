package mcp

import (
	"github.com/trafficgen/trafficgen/internal/core"
)

// buildResponseIndex maps request id -> response bytes (explicit user
// responses). Used for fast lookup during Requests iteration.
func buildResponseIndex(responses []core.MCPMessage) map[int][]byte {
	idx := make(map[int][]byte, len(responses))
	for _, r := range responses {
		if r.Method != "" {
			nb, err := buildNotification(r.Method, r.Params, false)
			if err == nil {
				idx[r.ID] = nb
			}
			continue
		}
		var b []byte
		var err error
		if r.Error != nil {
			b, err = buildErrorResponse(r.ID, r.Error.Code, r.Error.Message, r.Error.Data)
		} else {
			b, err = buildSuccessResponse(r.ID, r.Result)
		}
		if err == nil {
			idx[r.ID] = b
		}
	}
	return idx
}

// synthesizeResponse returns the response bytes for a given request id +
// method. If the user supplied an explicit response, return that;
// otherwise build a default success response keyed by method.
func synthesizeResponse(idx map[int][]byte, reqID int, method string) ([]byte, error) {
	if b, ok := idx[reqID]; ok {
		return b, nil
	}
	switch method {
	case "tools/list":
		return buildToolsListResponse(reqID)
	case "tools/call":
		return buildToolsCallResponse(reqID)
	case "resources/list":
		return buildResourcesListResponse(reqID)
	case "resources/read":
		return buildResourcesReadResponse(reqID)
	case "resources/subscribe":
		return buildSuccessResponse(reqID, map[string]any{})
	case "prompts/list":
		return buildPromptsListResponse(reqID)
	case "prompts/get":
		return buildPromptsGetResponse(reqID)
	case "completion/complete":
		return buildCompletionCompleteResponse(reqID)
	case "logging/setLevel":
		return buildSuccessResponse(reqID, map[string]any{})
	default:
		return buildSuccessResponse(reqID, map[string]any{})
	}
}

// buildToolsListResponse: 3 tools (ping/echo/search) per design §7.4.
func buildToolsListResponse(id int) ([]byte, error) {
	tools := []any{
		map[string]any{
			"name":        "ping",
			"description": "Health check",
			"inputSchema": map[string]any{
				"type":                 "object",
				"properties":           map[string]any{},
				"additionalProperties": false,
			},
		},
		map[string]any{
			"name":        "echo",
			"description": "Echo back the input",
			"inputSchema": map[string]any{
				"type":     "object",
				"properties": map[string]any{"msg": map[string]any{"type": "string"}},
				"required": []any{"msg"},
			},
		},
		map[string]any{
			"name":        "search",
			"description": "Search the knowledge base",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"q":     map[string]any{"type": "string"},
					"limit": map[string]any{"type": "integer", "default": 10},
				},
				"required": []any{"q"},
			},
		},
	}
	return buildSuccessResponse(id, map[string]any{"tools": tools})
}

// buildToolsCallResponse: successful text content (design §7.4).
func buildToolsCallResponse(id int) ([]byte, error) {
	return buildSuccessResponse(id, map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": "pong"},
		},
		"isError": false,
	})
}

// buildResourcesListResponse: 2 sample resources (design §7.5).
func buildResourcesListResponse(id int) ([]byte, error) {
	res := []any{
		map[string]any{
			"uri":         "file:///etc/hosts",
			"name":        "hosts",
			"mimeType":    "text/plain",
			"description": "System hosts file",
		},
		map[string]any{
			"uri":      "config:///app.json",
			"name":     "app config",
			"mimeType": "application/json",
		},
	}
	return buildSuccessResponse(id, map[string]any{
		"resources":  res,
		"nextCursor": "",
	})
}

// buildResourcesReadResponse: text content (design §7.5).
func buildResourcesReadResponse(id int) ([]byte, error) {
	return buildSuccessResponse(id, map[string]any{
		"contents": []any{
			map[string]any{
				"uri":      "file:///etc/hosts",
				"mimeType": "text/plain",
				"text":     "127.0.0.1 localhost\n",
			},
		},
	})
}

// buildPromptsListResponse: 1 sample prompt (design §7.7).
func buildPromptsListResponse(id int) ([]byte, error) {
	prompts := []any{
		map[string]any{
			"name":        "code_review",
			"description": "Review code",
			"arguments": []any{
				map[string]any{
					"name":        "language",
					"description": "Programming language",
					"required":    true,
				},
			},
		},
	}
	return buildSuccessResponse(id, map[string]any{"prompts": prompts})
}

// buildPromptsGetResponse: single user message (design §7.7).
func buildPromptsGetResponse(id int) ([]byte, error) {
	return buildSuccessResponse(id, map[string]any{
		"description": "Review code",
		"messages": []any{
			map[string]any{
				"role":    "user",
				"content": map[string]any{"type": "text", "text": "Review this Go code..."},
			},
		},
	})
}

// buildCompletionCompleteResponse: 3 sample values (design §7.8).
func buildCompletionCompleteResponse(id int) ([]byte, error) {
	return buildSuccessResponse(id, map[string]any{
		"completion": map[string]any{
			"values":  []any{"go", "golang", "google go"},
			"total":   3,
			"hasMore": false,
		},
	})
}