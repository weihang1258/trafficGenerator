# ngap Pcap Test Results

Cases: 17 — pass 17, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| ngap_all_procedures | T-NGAP-9: 全可选流程 16 包=4握手+2Setup+1+1+1+2+2+3拆链 | pass | 16 | [pcap](ngap/ngap_all_procedures.pcap) |
| ngap_amf_name | T-NGAP-12: amf_name 自定义 'AMF-EDGE-07'（f6 NGSetupResp PDU hex pin） | pass | 9 | [pcap](ngap/ngap_amf_name.pcap) |
| ngap_default_port | T-NGAP-14: ngap 层无端口键 → dst 缺省 38412（translate 镜像 setDefaultDstPort） | pass | 9 | [pcap](ngap/ngap_default_port.pcap) |
| ngap_dl_nas | T-NGAP-5: DownlinkNASTransport (proc 4, down) | pass | 10 | [pcap](ngap/ngap_dl_nas.pcap) |
| ngap_flat_presence | T-NGAP-2: 顶层 ngap presence 判死（空 map 也死） | pass | 0 | [pcap]() |
| ngap_flat_static_port | T-NGAP-3: ngap 层静态端口+flows=2 拒（12.9，门扩扫 ngap 层） | pass | 0 | [pcap]() |
| ngap_initial_ue | T-NGAP-4: InitialUEMessage (proc 15, up) | pass | 10 | [pcap](ngap/ngap_initial_ue.pcap) |
| ngap_neg_nas_len | T-NGAP-17: initial_nas 4097 字节 → legacy 超长拒 | pass | 0 | [pcap]() |
| ngap_neg_sst | T-NGAP-16: pdu_session_setup.sst=300 → legacy 越界拒 | pass | 0 | [pcap]() |
| ngap_neg_v6 | T-NGAP-13: ip 层 v6 → legacy v4-only 拒 | pass | 0 | [pcap]() |
| ngap_pdu_session | T-NGAP-7: PDUSessionSetup 请求+响应 (proc 29 对) | pass | 11 | [pcap](ngap/ngap_pdu_session.pcap) |
| ngap_port_dyn | T-NGAP-15: ngap.src_port 动态 inc+flows=2（E1 逐流端口池，2 流×9=18 包） | pass | 18 | [pcap](ngap/ngap_port_dyn.pcap) |
| ngap_sctp_setup_basic | 冒烟：SCTP 4路握手+NGSetup对+3路拆链=最小9包（存量等价迁移） | pass | 9 | [pcap](ngap/ngap_sctp_setup_basic.pcap) |
| ngap_ta_drx | T-NGAP-10: global_ran_node_id+supported_ta_list 2 项+default_paging_drx=2（NGSetupReq PER 编码） | pass | 9 | [pcap](ngap/ngap_ta_drx.pcap) |
| ngap_ue_ids | T-NGAP-11: ran_ue_ngap_id/amf_ue_ngap_id 显式（IUE IE 断言面） | pass | 10 | [pcap](ngap/ngap_ue_ids.pcap) |
| ngap_ue_release | T-NGAP-8: UEContextRelease Command+Complete (proc 41 对) | pass | 11 | [pcap](ngap/ngap_ue_release.pcap) |
| ngap_ul_nas | T-NGAP-6: UplinkNASTransport (proc 46, up) | pass | 10 | [pcap](ngap/ngap_ul_nas.pcap) |
