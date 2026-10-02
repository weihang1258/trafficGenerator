# hds Pcap Test Results

Cases: 25 — pass 25, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| hds_afrt_fragment_runs | HDS afrt fragment run table \| pending-suite（先跑后钉：断言/包数沿设计 §8 契约值，P5 suite 复核） | pass | 9 | [pcap](hds/hds_afrt_fragment_runs.pcap) |
| hds_asrt_segment_runs | HDS asrt segment run table \| pending-suite（先跑后钉：断言/包数沿设计 §8 契约值，P5 suite 复核） | pass | 9 | [pcap](hds/hds_asrt_segment_runs.pcap) |
| hds_bootstrap_abst | HDS bootstrap abst box via base64 \| pending-suite（先跑后钉：断言/包数沿设计 §8 契约值，P5 suite 复核） | pass | 9 | [pcap](hds/hds_bootstrap_abst.pcap) |
| hds_bootstrap_generated | HDS generated bootstrap box (no inline base64 → abst/asrt/afrt build path) \| 离线 Plan 实钉（2026-09-28）：包 4 = GET /live/channel.bootstrap，包 5 = 200 application/octet-stream + abst 盒头 0000006f 61627374（111B payload，Content-Length 111）；套件跑法待 P5 suite 复核（帧级 frames 补钉） | pass | 9 | [pcap](hds/hds_bootstrap_generated.pcap) |
| hds_boundary_box | HDS boundary box sizes \| pending-suite（先跑后钉：断言/包数沿设计 §8 契约值，P5 suite 复核） | pass | 9 | [pcap](hds/hds_boundary_box.pcap) |
| hds_fragment_f4f | HDS F4F fragment box \| 离线 Plan 实钉（2026-09-28）：包 5 = 200 video/f4f（mdat 盒）；套件跑法待 P5 suite 复核（frames 补钉） | pass | 9 | [pcap](hds/hds_fragment_f4f.pcap) |
| hds_ipv6 | HDS manifest over IPv6 HTTP \| pending-suite（先跑后钉：断言/包数沿设计 §8 契约值，P5 suite 复核） | pass | 9 | [pcap](hds/hds_ipv6.pcap) |
| hds_keepalive_fragments | HDS keep-alive multi-fragment \| pending-suite（先跑后钉：断言/包数沿设计 §8 契约值，P5 suite 复核） | pass | 11 | [pcap](hds/hds_keepalive_fragments.pcap) |
| hds_live_update | HDS live bootstrap update \| pending-suite（先跑后钉：断言/包数沿设计 §8 契约值，P5 suite 复核） | pass | 11 | [pcap](hds/hds_live_update.pcap) |
| hds_manifest_bootstrap_fragment | HDS full state machine: manifest → bootstrap → fragment \| pending-suite（先跑后钉：断言/包数沿设计 §8 契约值，P5 suite 复核） | pass | 13 | [pcap](hds/hds_manifest_bootstrap_fragment.pcap) |
| hds_manifest_ipv4 | HDS F4M manifest over IPv4 HTTP（D-HDS-1 迁层：业务住 layers[].hds） \| pending-suite（先跑后钉：断言/包数沿设计 §8 契约值，P5 suite 复核） | pass | 9 | [pcap](hds/hds_manifest_ipv4.pcap) |
| hds_mss_reassembly | HDS with MSS segmentation \| 包号/包数已按真机 pcap 实钉（2026-09-28：/tmp/mcp-pcaps/hds/hds_mss_reassembly.pcap，packet 6 http.response.code=200；MSS 例包数 10≥min 8）；其余断言沿设计 §8 | pass | 10 | [pcap](hds/hds_mss_reassembly.pcap) |
| hds_multi_session | HDS two isolated sessions \| pending-suite（先跑后钉：断言/包数沿设计 §8 契约值，P5 suite 复核） | pass | 11 | [pcap](hds/hds_multi_session.pcap) |
| hds_neg_bootstrap | HDS negative: bootstrap missing media | pass | 0 | [pcap]() |
| hds_neg_bootstrap_base64 | HDS negative: invalid base64 bootstrap（设计 §4/§10.2 P4 必含：buildSessionBody 解码前 validateManifest 拦截） | pass | 0 | [pcap]() |
| hds_neg_carrier_no_http | P2判死: [tcp,hds] direct chain (missing http carrier)（M5③） | pass | 0 | [pcap]() |
| hds_neg_flat_count | P2判死: top-level flat count alongside layers（create 路径锚词命中，task 路径另报 manifest-nil 自然守卫——两路均为拒） | pass | 0 | [pcap]() |
| hds_neg_fragment | HDS negative: fragment no fragments | pass | 0 | [pcap]() |
| hds_neg_manifest | HDS negative: empty manifest | pass | 0 | [pcap]() |
| hds_neg_presence_top_level_hds | P2判死: layers + top-level hds sub-config coexist（M5①，空 map 也死；锚词实测由 create 路径 CheckProtoFlat + task 路径 mapToFlowSpec 存量块双路供给） | pass | 0 | [pcap]() |
| hds_neg_session_state | HDS negative: unknown kind | pass | 0 | [pcap]() |
| hds_neg_sessions_empty | HDS negative: empty sessions list（设计 §10.2 P4 必含：sessions 空 pcap 例） | pass | 0 | [pcap]() |
| hds_neg_stray_src_mac | P2判死: top-level src_mac alongside layers（M5②，1.11 白名单；create 路径锚词命中，task 路径被自然守卫 manifest-nil 遮蔽——两路均为拒，非假绿） | pass | 0 | [pcap]() |
| hds_non_default_port | HDS manifest over explicit non-default port 8080 (FieldContract override) \| 离线 Plan 实钉（2026-09-28）：tcp.dst_port=8080 生效、包 4 = GET /live/channel.f4m，包 5 = 200 application/f4m+xml；套件跑法待 P5 suite 复核 | pass | 9 | [pcap](hds/hds_non_default_port.pcap) |
| hds_vod_end | HDS VOD end of stream \| pending-suite（先跑后钉：断言/包数沿设计 §8 契约值，P5 suite 复核） | pass | 9 | [pcap](hds/hds_vod_end.pcap) |
