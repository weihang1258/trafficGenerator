# http_flv Pcap Test Results

Cases: 15 — pass 15, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| http_flv_audio_aac | AAC sequence header audio tag with SoundFormat=10 | pass | 9 | [pcap](http_flv/http_flv_audio_aac.pcap) |
| http_flv_empty_tag | Empty script tag with DataSize=0, 11+4 bytes on wire | pass | 9 | [pcap](http_flv/http_flv_empty_tag.pcap) |
| http_flv_get_header | IPv4/TCP GET request with URI, Host, HTTP/1.1 | pass | 9 | [pcap](http_flv/http_flv_get_header.pcap) |
| http_flv_header_flags | HTTP 200, Content-Type video/x-flv, FLV header signature | pass | 9 | [pcap](http_flv/http_flv_header_flags.pcap) |
| http_flv_ipv6 | IPv6/TCP, Next Header=6, FLV bytes identical to IPv4 | pass | 9 | [pcap](http_flv/http_flv_ipv6.pcap) |
| http_flv_keep_alive | Two GET/200 transactions on same tcp.stream with keep-alive | pass | 11 | [pcap](http_flv/http_flv_keep_alive.pcap) |
| http_flv_minimal_tags | All three tag types with minimal valid data | pass | 9 | [pcap](http_flv/http_flv_minimal_tags.pcap) |
| http_flv_multi_session | Multiple independent TCP sessions with isolated state | pass | 9 | [pcap](http_flv/http_flv_multi_session.pcap) |
| http_flv_multi_stream | Multiple streams with StreamID=0 | pass | 9 | [pcap](http_flv/http_flv_multi_stream.pcap) |
| http_flv_neg_length_mismatch | Rounds < 0 rejected by validator | pass | 0 | [pcap]() |
| http_flv_neg_truncated_tag | Unknown tag type rejected by validator | pass | 0 | [pcap]() |
| http_flv_neg_validate | Flags with reserved bits rejected by validator | pass | 0 | [pcap]() |
| http_flv_script_tag | AMF0 onMetaData script tag with DataSize and PreviousTagSize | pass | 9 | [pcap](http_flv/http_flv_script_tag.pcap) |
| http_flv_tag_boundary | 24-bit DataSize boundary with DataSizeOverride | pass | 9 | [pcap](http_flv/http_flv_tag_boundary.pcap) |
| http_flv_video_avc | AVC sequence header video tag with keyframe+AVC header | pass | 9 | [pcap](http_flv/http_flv_video_avc.pcap) |
