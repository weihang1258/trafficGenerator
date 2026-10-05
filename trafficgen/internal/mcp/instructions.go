package mcp

// serverInstructions is returned to every MCP client in the initialize
// response — the protocol-standard place for the model-facing overview.
// It carries the capability summary and the standard end-to-end flow so
// the model never has to assemble the workflow from scattered tool
// descriptions. Keep in sync with tool behavior (CORE_MEMORY §13.27).
const serverInstructions = `trafficgen (flowB) MCP — network traffic generation and pcap analysis for 125 protocols.

STANDARD FLOW
1. flowb_query_layers action=examples for the target protocol — copy a verified config verbatim; never guess field names. action=schema lists every layer's fields/types/defaults.
2. Compose the layer-chain config {"layers":[outermost...innermost],"flow_control":{"type":"flows","value":N}} and submit with flowb_manage_strategies action=create, or inline via flowb_generate_traffic. Flat top-level src_ip/dst_port/count is rejected.
3. flowb_wait_for_task until status=completed (or poll flowb_get_task_progress). Protocol regressions: flowb_run_protocol_case / flowb_run_protocol_suite.
4. Completed tasks capture a pcap and auto-register it into the asset library (files >64 MB stay unregistered with a note + import guidance). Use flowb_manage_pcaps to drill down: list (assets) → list_flows (flow stats — spot the suspicious flow) → list_packets (its packets, needs flow_id) → get_packet (full header fields, needs packet_id) → get_packet_payload / get_stream (payload bytes); batch-extract fields with extract (given packet_ids) or extract_bulk (whole flow/asset, no ID enumeration); pull reassembled stream text in bulk with extract_streams; fetch the file via the no-auth download_url. Bulk pulls over 64 KB auto-export to a file with a download link (the receipt carries the row total). Flow stats alone cannot show malformed payloads — continue to the packet/payload actions whenever a flow looks wrong.
5. Bring your own pcap with one step: POST /uploads/pcaps (multipart file=@..., no auth) — the response ID is the asset id for analysis.

RESPONSE RULES
- Pagination is optional: list-style tools return the FULL dataset when page/size are omitted (size=0 also means all); pass size only to cap a page. Oversized results auto-export.
- Responses up to 64 KB return inline; anything larger is auto-exported to a server file and answered with a small receipt {written_to, bytes, export_id, download_url} — fetch it with curl and read locally.
- Remote (HTTP) clients: any output_path you pass is treated as a file name only — the server picks the location; stdio (same-host) clients give an absolute path.
- Manage the trafficgen filesystem with flowb_manage_filesystem (upload/read/list; large reads are auto-exported too).

Admin surface: flowb_manage_port_groups (NIC real-send output), flowb_manage_users / flowb_manage_auth / flowb_manage_profile / flowb_manage_settings / flowb_query_system.`
