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
1. flowb_query_layers action=examples (target protocol) — copy a verified config; action=schema lists fields.
2. Layer-chain config — ONE layer key per array element, outermost first, must END with an application layer (full rule: config schema's EXACTLY ONE note); flat src_ip/dst_port/count rejected. Submit via flowb_generate_traffic or flowb_manage_strategies + tasks.
3. flowb_wait_for_task until completed (or poll flowb_get_task_progress). flowb_run_protocol_case/suite = INTERNAL TEST ONLY / 内部测试专用, 客户端业务勿用.
4. Completed pcap tasks auto-register to the asset library (>64 MB unregistered w/ note). flowb_manage_pcaps drills: list → list_flows → list_packets → get_packet → payload/stream; extract_bulk/extract_streams for bulk; fetch via no-auth download_url. Flow stats can't show malformed payloads — check packets.
5. Bring your own pcap: POST /uploads/pcaps (multipart, no auth) — response ID is the asset id.

RESPONSE RULES
- Omit page/size = FULL dataset; oversized auto-export.
- Up to 64 KB inline; larger → file receipt {written_to, bytes, export_id, download_url} — curl.
- HTTP clients: output_path is a file name only; stdio gives absolute paths.
- There is no REST API for you — MCP tools only; raw HTTP = download_url + step-5 upload. Fix failing calls via query_layers, not probing.
- flowb_manage_filesystem uploads (file_id=sha256, dedup; use file_source={file_id} in layers). Admin: flowb_manage_port_groups (NIC send), users/auth/profile/settings, flowb_query_system.`

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
