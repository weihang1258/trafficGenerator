# rtsp Pcap Test Results

Cases: 12 — pass 12, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| rtsp_composite_full_session_media | T-10 复合大场景（9.50）：五方法全序+emit_media+自定义头+SDP body ≥3 类交织 | pass | 18 | [pcap](rtsp/rtsp_composite_full_session_media.pcap) |
| rtsp_describe_sdp_body | T-3 DESCRIBE+SDP body：body 字节透传+Content-Length 自动补 | pass | 9 | [pcap](rtsp/rtsp_describe_sdp_body.pcap) |
| rtsp_direction_explicit | T-9 direction 显式：覆盖方法推断（down 向请求形——server 主动消息合成面） | pass | 9 | [pcap](rtsp/rtsp_direction_explicit.pcap) |
| rtsp_emit_media_rtp | T-8 RTP 媒面子流：PLAY 响应 emit_media=true+media 配置→RTP 包序（legacy emitRTSPMedia 复用） | pass | 16 | [pcap](rtsp/rtsp_emit_media_rtp.pcap) |
| rtsp_headers_custom | T-7 头显式覆盖：headers 自定义 User-Agent 与自动补 CSeq 共存 | pass | 9 | [pcap](rtsp/rtsp_headers_custom.pcap) |
| rtsp_neg_dialog_required | T-11 负例：空 dialog → 锚词 dialog is required（validator 背 door） | pass | 0 | [pcap]() |
| rtsp_options_smoke | T-1 OPTIONS 冒烟（smoke 改写，等价覆盖）：握手3+OPTIONS req/resp+挥手4=9 包；控制通道 554 | pass | 9 | [pcap](rtsp/rtsp_options_smoke.pcap) |
| rtsp_pause_teardown | T-5 PAUSE/TEARDOWN 面：两方法请求/响应序 | pass | 13 | [pcap](rtsp/rtsp_pause_teardown.pcap) |
| rtsp_play_session_full | T-2 play 会话全序（现网形）：OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN 五方法请求响应+Session 头自动补全 | pass | 17 | [pcap](rtsp/rtsp_play_session_full.pcap) |
| rtsp_response_404 | T-4 404 响应面：status_code=404+reason Not Found | pass | 9 | [pcap](rtsp/rtsp_response_404.pcap) |
| rtsp_status_text_default | T-12 status_text 空缺省：status_code=200 无 status_text→reason OK 缺省（rtspReasonPhrase） | pass | 9 | [pcap](rtsp/rtsp_status_text_default.pcap) |
| rtsp_uri_explicit_and_default | T-6 URI 面：DESCRIBE 显式 uri=rtsp://20.0.0.1/media；OPTIONS 缺省构造 rtmp 同族 rtsp://<dstIP>/media | pass | 11 | [pcap](rtsp/rtsp_uri_explicit_and_default.pcap) |
