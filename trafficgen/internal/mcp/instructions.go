package mcp

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// serverInstructions is returned to every MCP client in the initialize
// response — the protocol-standard place for the model-facing overview.
// It carries the capability summary and the standard end-to-end flow so
// the model never has to assemble the workflow from scattered tool
// descriptions. Keep in sync with tool behavior (CORE_MEMORY §13.27).
//
// 协议数是运行期算的，不是常量：exposed list = ListProtocols() − udp
// （rest GetProtocols OBS-1 同一口径）。此前是三处硬编码（这里 + 两个
// struct tag）+ 一个测试锁三方，加协议时必须记得同步改四处——编号
// 2026-10-13 客户端审查就是这么漂移的（instructions 125 / tag 123）。
// 现在单一真相是 engine 注册表，数字不会说谎，测试改成校验三方一致。
const serverInstructionsTemplate = `trafficgen (flowB) MCP — network traffic generation and pcap analysis for %d protocols.

STANDARD FLOW
1. flowb_query_layers action=examples for the target protocol — copy a verified config verbatim; never guess field names. action=schema lists every layer's fields/types/defaults.
2. Compose the layer-chain config — ONE layer key per array element: {"layers":[{"ip":{...}},{"tcp":{...}}],"flow_control":{"type":"flows","value":N}}, outermost first (several layer keys inside one element is rejected); the chain must END with a terminal (application) layer, e.g. [{"ip":{...}},{"tcp":{...}},{"http":{...}}] — a chain ending at a bare transport layer is rejected — and submit with flowb_manage_strategies action=create, or inline via flowb_generate_traffic. Flat top-level src_ip/dst_port/count is rejected.
3. flowb_wait_for_task until status=completed (or poll flowb_get_task_progress). Protocol regressions (INTERNAL TEST ONLY / 内部测试专用 — client business scenarios must NOT use these / 客户端正常业务场景勿用): flowb_run_protocol_case / flowb_run_protocol_suite.
4. Completed tasks capture a pcap and auto-register it into the asset library (files >64 MB stay unregistered with a note + import guidance). Use flowb_manage_pcaps to drill down: list (assets) → list_flows (flow stats — spot the suspicious flow) → list_packets (its packets, needs flow_id) → get_packet (full header fields, needs packet_id) → get_packet_payload / get_stream (payload bytes); batch-extract fields with extract (given packet_ids) or extract_bulk (whole flow/asset, no ID enumeration); pull reassembled stream text in bulk with extract_streams; fetch the file via the no-auth download_url. Bulk pulls over 64 KB auto-export to a file with a download link (the receipt carries the row total). Flow stats alone cannot show malformed payloads — continue to the packet/payload actions whenever a flow looks wrong.
5. Bring your own pcap with one step: POST /uploads/pcaps (multipart file=@..., no auth) — the response ID is the asset id for analysis.

RESPONSE RULES
- Pagination is optional: list-style tools return the FULL dataset when page/size are omitted (size=0 also means all); pass size only to cap a page. Oversized results auto-export.
- Responses up to 64 KB return inline; anything larger is auto-exported to a server file and answered with a small receipt {written_to, bytes, export_id, download_url} — fetch it with curl and read locally.
- Remote (HTTP) clients: any output_path you pass is treated as a file name only — the server picks the location; stdio (same-host) clients give an absolute path.
- There is no REST API for you to call — every capability is an MCP tool. The only raw HTTP you ever issue is fetching download_url files and the /uploads/pcaps import (step 5). When a tool call fails, fix the arguments (query_layers examples/schema), never fall back to probing guessed endpoints.
- Manage the trafficgen filesystem with flowb_manage_filesystem (upload/read/list; large reads are auto-exported too). To transfer a specific file over HTTP/FTP/etc: upload once (the receipt returns file_id = content sha256; identical content dedups with existed=true), then reference it in the protocol layer with file_source={file_id: <file_id>} — query accepts sha256=<64-hex> to check existence before uploading a large file.

Admin surface: flowb_manage_port_groups (NIC real-send output), flowb_manage_users / flowb_manage_auth / flowb_manage_profile / flowb_manage_settings / flowb_query_system.`

// exposedProtocolCount is the "N protocols" figure quoted to clients:
// engine.ListProtocols() minus udp — the same exposure rule as rest
// GetProtocols (OBS-1: udp is a chain carrier with no case corpus, still
// usable as a layer config but not advertised as a protocol). Computed from
// the live registry so it can never drift from what the server actually
// serves; nil engine yields 0 (tests constructing a bare Server).
func exposedProtocolCount(e *core.Engine) int {
	if e == nil {
		return 0
	}
	n := 0
	for _, p := range e.ListProtocols() {
		if p != "udp" {
			n++
		}
	}
	return n
}

// serverInstructions renders the initialize-time instructions with the live
// protocol count.
func serverInstructions(e *core.Engine) string {
	return fmt.Sprintf(serverInstructionsTemplate, exposedProtocolCount(e))
}
