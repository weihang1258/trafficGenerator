# hds Pcap Test Results

Cases: 17 — pass 17, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| hds_afrt_fragment_runs | HDS afrt fragment run table | pass | 9 | [pcap](hds/hds_afrt_fragment_runs.pcap) |
| hds_asrt_segment_runs | HDS asrt segment run table | pass | 9 | [pcap](hds/hds_asrt_segment_runs.pcap) |
| hds_bootstrap_abst | HDS bootstrap abst box via base64 | pass | 9 | [pcap](hds/hds_bootstrap_abst.pcap) |
| hds_boundary_box | HDS boundary box sizes | pass | 9 | [pcap](hds/hds_boundary_box.pcap) |
| hds_fragment_f4f | HDS F4F fragment box | pass | 9 | [pcap](hds/hds_fragment_f4f.pcap) |
| hds_ipv6 | HDS manifest over IPv6 HTTP | pass | 9 | [pcap](hds/hds_ipv6.pcap) |
| hds_keepalive_fragments | HDS keep-alive multi-fragment | pass | 11 | [pcap](hds/hds_keepalive_fragments.pcap) |
| hds_live_update | HDS live bootstrap update | pass | 11 | [pcap](hds/hds_live_update.pcap) |
| hds_manifest_bootstrap_fragment | HDS full state machine: manifest → bootstrap → fragment | pass | 13 | [pcap](hds/hds_manifest_bootstrap_fragment.pcap) |
| hds_manifest_ipv4 | HDS F4M manifest over IPv4 HTTP | pass | 9 | [pcap](hds/hds_manifest_ipv4.pcap) |
| hds_mss_reassembly | HDS with MSS segmentation | pass | 10 | [pcap](hds/hds_mss_reassembly.pcap) |
| hds_multi_session | HDS two isolated sessions | pass | 11 | [pcap](hds/hds_multi_session.pcap) |
| hds_neg_bootstrap | HDS negative: bootstrap missing media | pass | 0 | [pcap]() |
| hds_neg_fragment | HDS negative: fragment no fragments | pass | 0 | [pcap]() |
| hds_neg_manifest | HDS negative: empty manifest | pass | 0 | [pcap]() |
| hds_neg_session_state | HDS negative: unknown kind | pass | 0 | [pcap]() |
| hds_vod_end | HDS VOD end of stream | pass | 9 | [pcap](hds/hds_vod_end.pcap) |
