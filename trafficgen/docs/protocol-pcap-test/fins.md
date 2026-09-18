# fins Pcap Test Results

Cases: 45 — pass 45, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| fins_cio_read_word | T-004: CIO 区字读（CIO0 读 1 字），omron.memory.area.read=0xB0（CIO 字码），响应 2 字节数据 | pass | 2 | [pcap](fins/fins_cio_read_word.pcap) |
| fins_cio_write_bit | T-010: CIO 位域写（CIO0 bit3 起写 2 bit ON/OFF），omron.memory.area.read=0x30、address.bits=0x03、numitems=2，写请求数据 01 00，响应无数据 | pass | 2 | [pcap](fins/fins_cio_write_bit.pcap) |
| fins_clock_read_bcd | T-012: Clock Read（0x0701）无参数请求 + BCD 响应（世纪20/年26/月08/日18/时14/分30/秒00/星期02）；Wireshark 对 0x0701 响应不解析结束码，用 FrameAssert 校验 | pass | 2 | [pcap](fins/fins_clock_read_bcd.pcap) |
| fins_combo_sessions_full | 组合流 B（T-32）: UDP 双会话+位写+全键头+down 结束码 | pass | 6 | [pcap](fins/fins_combo_sessions_full.pcap) |
| fins_combo_tcp_seq | 组合流 A（T-31）: TCP 载体+读→写→校时 3 命令+SID 递增 | pass | 13 | [pcap](fins/fins_combo_tcp_seq.pcap) |
| fins_dm_write_word | T-011/T-FINS: 0102 DM 字写（data 4B=2字）+响应回合 | pass | 2 | [pcap](fins/fins_dm_write_word.pcap) |
| fins_down_endcode_1101 | T-25: down 命令携带结束码 0x1101（错误响应面） | pass | 1 | [pcap](fins/fins_down_endcode_1101.pcap) |
| fins_expect_response_false | T-019: expect_response=false → 仅请求 1 包 | pass | 1 | [pcap](fins/fins_expect_response_false.pcap) |
| fins_fill_dm | T-013/T-29: 0103 Fill（模板 ABCD×3，无 DC） | pass | 2 | [pcap](fins/fins_fill_dm.pcap) |
| fins_hr_read_bit | T-009: HR 位域读（H10 的 bit2/3 读 2 bit），omron.memory.area.read=0x32（HR 位码）、address.bits=0x02、numitems=2，响应数据 2 字节 01 00（FrameAssert 校验位数据每 bit 1 字节） | pass | 2 | [pcap](fins/fins_hr_read_bit.pcap) |
| fins_hr_read_word | T-006: HR 保持区字读（H5 读 2 字），omron.memory.area.read=0xB2、address=0x0005、numitems=2，响应数据 4 字节 | pass | 2 | [pcap](fins/fins_hr_read_word.pcap) |
| fins_icf_explicit | T-015': 显式 cfg icf=0x80（与缺省同线） | pass | 2 | [pcap](fins/fins_icf_explicit.pcap) |
| fins_ir_read_word | T-008: IR 索引寄存器字读（IR0 读 1 字），omron.memory.area.read=0xDC（CS1 Index Register） | pass | 2 | [pcap](fins/fins_ir_read_word.pcap) |
| fins_multi_read | T-014/T-30: 0104 双组读（DM+HR） | pass | 2 | [pcap](fins/fins_multi_read.pcap) |
| fins_sessions_neg_area | T-023: 多会话负路径——sessions=2 且命令内存区非法 'xyz_bad'，Validate 必须拒绝（任务失败），禁止 0 包静默通过 | pass | 0 | [pcap]() |
| fins_sessions_three | T-021: 多会话 sessions=3 聚合断言（omron.sid DistinctValues={0x01}；端口全集不作断言，调度无关） | pass | 6 | [pcap](fins/fins_sessions_three.pcap) |
| fins_sessions_two | T-020: 多会话 sessions=2 双流（各 DM D100 读 1 字），每流 SID 独立从 0x01 递增、跨流不串号；聚合断言 + 每流独立 src_port | pass | 4 | [pcap](fins/fins_sessions_two.pcap) |
| fins_sid_auto_incr | T-016: 同会话双命令 SID 递增 01→02 | pass | 4 | [pcap](fins/fins_sid_auto_incr.pcap) |
| fins_sid_fixed | T-017: sid=7 + sid_auto=false → 双命令恒 07 | pass | 4 | [pcap](fins/fins_sid_fixed.pcap) |
| fins_tc_flag_read | T-33: tc_bit 字口径读（区码 0x09 补口） | pass | 2 | [pcap](fins/fins_tc_flag_read.pcap) |
| fins_tc_read_pv | T-007: TC 定时器/计数器 PV 字读（TC0 读 1 字），omron.memory.area.read=0x89（PV 字码） | pass | 2 | [pcap](fins/fins_tc_read_pv.pcap) |
| fins_tcp_read | T-002: FINS/TCP Frame Send 读取（D100 读 2 字），FINS/TCP 头 'FINS' magic+length=26+command=0x00000002+error=0，TCP 9600，带握手；omron.tcp.command 与 omron.command 隔离验证 | pass | 9 | [pcap](fins/fins_tcp_read.pcap) |
| fins_udp_dm_read | T-001: FINS/UDP 内存区读-响应往返（DM D100 读 2 字），请求 ICF=0x81/响应 ICF=0xC1，SID=0x01 回显，10.0.0.1:1234<->20.0.0.1:9600 | pass | 2 | [pcap](fins/fins_udp_dm_read.pcap) |
| fins_udp_ipv6_read | T-003: FINS/UDP 内存区读 over IPv6（2001:db8::1 -> 2001:db8::2:9600，DM D100 读 1 字），FINS 载荷与 IPv4 字节级一致 | pass | 2 | [pcap](fins/fins_udp_ipv6_read.pcap) |
| fins_vn_address_over | T-025/E-04: CIO 地址 7000 越界（上限 6143） | pass | 0 | [pcap]() |
| fins_vn_clock_bcd | T-032/E-09: clock hour=25 BCD 越界 | pass | 0 | [pcap]() |
| fins_vn_data_len | T-030/E-07: 写 2 字 data 仅 3B | pass | 0 | [pcap]() |
| fins_vn_direction | T-38: direction 非法枚举 | pass | 0 | [pcap]() |
| fins_vn_dm_bit | T-028/E-03: DM 位口径（E-03 独立消息） | pass | 0 | [pcap]() |
| fins_vn_dna | T-034: dna=1（恒 0） | pass | 0 | [pcap]() |
| fins_vn_fill_bit | T-28: 0103 位口径拒 | pass | 0 | [pcap]() |
| fins_vn_fill_data_len | 0103 填充模板长度≠2B 拒（E 面补口） | pass | 0 | [pcap]() |
| fins_vn_gct | T-033: gct=3（恒 2） | pass | 0 | [pcap]() |
| fins_vn_icf_cfg | T-26/E-06 cfg 级: cfg icf=0xC1（响应位在请求上） | pass | 0 | [pcap]() |
| fins_vn_icf_cmd | T-026/E-06 命令级: cmd icf=0x83（bit0 置位） | pass | 0 | [pcap]() |
| fins_vn_items_zero | T-029/E-05: items=0 | pass | 0 | [pcap]() |
| fins_vn_presence | T-35: 顶层 fins presence 判死（空 map 也死） | pass | 0 | [pcap]() |
| fins_vn_read_areas_empty | T-27/E-10: 0104 缺 read_areas | pass | 0 | [pcap]() |
| fins_vn_sessions_neg | T-39: sessions=-1 → registry V9 范围门（先于 planner 同义分支） | pass | 0 | [pcap]() |
| fins_vn_sna | T-034 同族: sna=1 | pass | 0 | [pcap]() |
| fins_vn_static_copy | T-36: flows=2 静态四元组拒绝（9.39） | pass | 0 | [pcap]() |
| fins_vn_transport | T-37: transport 非法枚举 | pass | 0 | [pcap]() |
| fins_vn_unknown_cmd | T-027/E-02: 命令 0x0201 不在支持集 | pass | 0 | [pcap]() |
| fins_wr_read_bit | T-34: WR 位读（区码 0x31 补口） | pass | 2 | [pcap](fins/fins_wr_read_bit.pcap) |
| fins_wr_read_word | T-005: WR 工作区字读（W10 读 1 字），omron.memory.area.read=0xB1、address=0x000A | pass | 2 | [pcap](fins/fins_wr_read_word.pcap) |
