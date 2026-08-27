# hls Pcap Test Results

Cases: 24 — pass 24, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| hls_aes128_key | HLS AES-128 key and IV association | pass | 15 | [pcap](hls/hls_aes128_key.pcap) |
| hls_byterange | HLS explicit and implicit byte ranges | pass | 13 | [pcap](hls/hls_byterange.pcap) |
| hls_discontinuity | HLS discontinuity sequence boundary | pass | 9 | [pcap](hls/hls_discontinuity.pcap) |
| hls_empty_and_truncated | HLS empty and truncated playlist rejection boundary | pass | 9 | [pcap](hls/hls_empty_and_truncated.pcap) |
| hls_fmp4_init_map | HLS fragmented MP4 initialization map | pass | 9 | [pcap](hls/hls_fmp4_init_map.pcap) |
| hls_http_errors | HLS explicit HTTP error responses | pass | 15 | [pcap](hls/hls_http_errors.pcap) |
| hls_invalid_tag | HLS invalid tag and attribute rejection boundary | pass | 9 | [pcap](hls/hls_invalid_tag.pcap) |
| hls_ipv6_media | HLS media playlist over IPv6 HTTP | pass | 9 | [pcap](hls/hls_ipv6_media.pcap) |
| hls_live_refresh | HLS live sliding window refresh | pass | 11 | [pcap](hls/hls_live_refresh.pcap) |
| hls_llhls_parts | HLS low-latency parts and preload hint | pass | 9 | [pcap](hls/hls_llhls_parts.pcap) |
| hls_master_basic_ipv4 | HLS master playlist over IPv4 HTTP | pass | 9 | [pcap](hls/hls_master_basic_ipv4.pcap) |
| hls_master_renditions | HLS master audio rendition association | pass | 9 | [pcap](hls/hls_master_renditions.pcap) |
| hls_media_sequence | HLS media sequence and ordered segments | pass | 9 | [pcap](hls/hls_media_sequence.pcap) |
| hls_media_target_duration | HLS media playlist target duration and segments | pass | 9 | [pcap](hls/hls_media_target_duration.pcap) |
| hls_multi_session | HLS two isolated sessions | pass | 13 | [pcap](hls/hls_multi_session.pcap) |
| hls_neg_byterange | Reject invalid HLS byte range | pass | 9 | [pcap](hls/hls_neg_byterange.pcap) |
| hls_neg_key | Reject inconsistent AES key configuration | pass | 11 | [pcap](hls/hls_neg_key.pcap) |
| hls_neg_ll_profile | Reject LL-HLS tags in baseline profile | pass | 9 | [pcap](hls/hls_neg_ll_profile.pcap) |
| hls_neg_missing_extm3u | Reject playlist without EXT-M3U | pass | 9 | [pcap](hls/hls_neg_missing_extm3u.pcap) |
| hls_neg_sequence_regress | Reject live media sequence regression | pass | 11 | [pcap](hls/hls_neg_sequence_regress.pcap) |
| hls_neg_session_state | Reject cross-session HLS state reference | pass | 11 | [pcap](hls/hls_neg_session_state.pcap) |
| hls_neg_target_duration | Reject invalid target duration | pass | 9 | [pcap](hls/hls_neg_target_duration.pcap) |
| hls_uri_encoding | HLS URI query and percent encoding | pass | 9 | [pcap](hls/hls_uri_encoding.pcap) |
| hls_vod_endlist | HLS VOD playlist with ENDLIST | pass | 9 | [pcap](hls/hls_vod_endlist.pcap) |
