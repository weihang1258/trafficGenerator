# rtmp Pcap Test Results

Cases: 16 — pass 16, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| rtmp_app_tc_url_custom | T-7 app/tc_url 显式：connect 命令对象属性字节钉（app=live2/tcUrl 显式构造，覆盖自动构造分支） | pass | 20 | [pcap](rtmp/rtmp_app_tc_url_custom.pcap) |
| rtmp_chunk_header_amf0_connect | T-3 chunk 头+AMF0 connect 钉：基本头 03（fmt0 csid3）+消息头 11B（len3+type 0x14+streamID 4B 小端）+02 00 07 connect | pass | 20 | [pcap](rtmp/rtmp_chunk_header_amf0_connect.pcap) |
| rtmp_composite_publish_multi_data | T-12 复合大场景（9.50）：publish+自定义 app/stream+音视频混合数据面 ≥3 类交织 | pass | 22 | [pcap](rtmp/rtmp_composite_publish_multi_data.pcap) |
| rtmp_data_audio | T-8 数据面音频：msg_type=8+csid=4 chunk | pass | 21 | [pcap](rtmp/rtmp_data_audio.pcap) |
| rtmp_data_bidirectional | T-10 数据面双向：up 音频+down 视频各一 chunk（推拉混合面） | pass | 22 | [pcap](rtmp/rtmp_data_bidirectional.pcap) |
| rtmp_data_payload_b64 | T-11 payload 显式 b64：payload_b64 解码字节透传（chunk 数据段 frames 钉） | pass | 21 | [pcap](rtmp/rtmp_data_payload_b64.pcap) |
| rtmp_data_payload_raw | T-16 payload 显式原始串：payload 原文字节透传（getByteSlice 字符串=原文字节语义，pppoe cookie 同款陷阱注记） | pass | 21 | [pcap](rtmp/rtmp_data_payload_raw.pcap) |
| rtmp_data_video | T-9 数据面视频：msg_type=9+csid=6 chunk | pass | 21 | [pcap](rtmp/rtmp_data_video.pcap) |
| rtmp_handshake_segments | T-2 RTMP 握手分段数：C0C1 1537B→2 段（MSS 1460）、S0S1S2 3073B→3 段、C2 1536B→2 段（tshark tcp.len 钉） | pass | 20 | [pcap](rtmp/rtmp_handshake_segments.pcap) |
| rtmp_neg_app_too_long | T-13 负例：app 超 255B → 锚词 App exceeds | pass | 0 | [pcap]() |
| rtmp_neg_command_invalid | T-14 负例：command=pause → 锚词 invalid Command | pass | 0 | [pcap]() |
| rtmp_neg_msg_type_invalid | T-15 负例：data[0].msg_type=5 → 锚词 MsgType | pass | 0 | [pcap]() |
| rtmp_play_session_full | T-1 play 全会话（smoke 改写，等价覆盖）：握手3+RTMP 握手（C0C1/S0S1S2/C2 按 MSS 分段）+connect→窗口三件套→createStream→play 命令序+挥手 | pass | 20 | [pcap](rtmp/rtmp_play_session_full.pcap) |
| rtmp_protocol_control_messages | T-4 协议控制四消息：WindowAckSize(5)/SetPeerBandwidth(6)/StreamBegin(4)/SetChunkSize(1) msgType 逐包 | pass | 20 | [pcap](rtmp/rtmp_protocol_control_messages.pcap) |
| rtmp_publish_mode | T-5 publish 模式：command=publish→第三阶段 02 00 07 publish 替代 play | pass | 20 | [pcap](rtmp/rtmp_publish_mode.pcap) |
| rtmp_stream_name_custom | T-6 stream_name 自定义：play 命令流名参数字节入 AMF0 串 | pass | 20 | [pcap](rtmp/rtmp_stream_name_custom.pcap) |
