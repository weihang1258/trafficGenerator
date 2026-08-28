# fins Pcap Test Results

Cases: 14 — pass 12, fail 0, error 2

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| fins_cio_read_word | T-004: CIO 区字读（CIO0 读 1 字），omron.memory.area.read=0xB0（CIO 字码），响应 2 字节数据 | pass | 2 | [pcap](fins/fins_cio_read_word.pcap) |
| fins_cio_write_bit | T-010: CIO 位域写（CIO0 bit3 起写 2 bit ON/OFF），omron.memory.area.read=0x30、address.bits=0x03、numitems=2，写请求数据 01 00，响应无数据 | pass | 2 | [pcap](fins/fins_cio_write_bit.pcap) |
| fins_clock_read_bcd | T-012: Clock Read（0x0701）无参数请求 + BCD 响应（年26/月08/日18/时14/分30/秒00/星期02，无世纪字段）；Wireshark 对 0x0701 响应不解析结束码，用 FrameAssert 校验 | pass | 2 | [pcap](fins/fins_clock_read_bcd.pcap) |
| fins_hr_read_bit | T-009: HR 位域读（H10 的 bit2/3 读 2 bit），omron.memory.area.read=0x32（HR 位码）、address.bits=0x02、numitems=2，响应数据 2 字节 01 00（FrameAssert 校验位数据每 bit 1 字节） | pass | 2 | [pcap](fins/fins_hr_read_bit.pcap) |
| fins_hr_read_word | T-006: HR 保持区字读（H5 读 2 字），omron.memory.area.read=0xB2、address=0x0005、numitems=2，响应数据 4 字节 | pass | 2 | [pcap](fins/fins_hr_read_word.pcap) |
| fins_ir_read_word | T-008: IR 索引寄存器字读（IR0 读 1 字），omron.memory.area.read=0xDC（CS1 Index Register） | pass | 2 | [pcap](fins/fins_ir_read_word.pcap) |
| fins_sessions_neg_area | T-023: 多会话负路径——sessions=2 且命令内存区非法 'xyz_bad'，Validate 必须拒绝（任务失败），禁止 0 包静默通过 | pass | 0 | [pcap]() |
| fins_sessions_three | T-021: 多会话 sessions=3 聚合断言（omron.sid DistinctValues={0x01}；端口全集不作断言，调度无关） | error | 0 | `` |
| fins_sessions_two | T-020: 多会话 sessions=2 双流（各 DM D100 读 1 字），每流 SID 独立从 0x01 递增、跨流不串号；聚合断言 + 每流独立 src_port | error | 0 | `` |
| fins_tc_read_pv | T-007: TC 定时器/计数器 PV 字读（TC0 读 1 字），omron.memory.area.read=0x89（PV 字码） | pass | 2 | [pcap](fins/fins_tc_read_pv.pcap) |
| fins_tcp_read | T-002: FINS/TCP Frame Send 读取（D100 读 2 字），FINS/TCP 头 'FINS' magic+length=26+command=0x00000002+error=0，TCP 9600，带握手；omron.tcp.command 与 omron.command 隔离验证 | pass | 9 | [pcap](fins/fins_tcp_read.pcap) |
| fins_udp_dm_read | T-001: FINS/UDP 内存区读-响应往返（DM D100 读 2 字），请求 ICF=0x81/响应 ICF=0xC1，SID=0x01 回显，10.0.0.1:1234<->20.0.0.1:9600 | pass | 2 | [pcap](fins/fins_udp_dm_read.pcap) |
| fins_udp_ipv6_read | T-003: FINS/UDP 内存区读 over IPv6（2001:db8::1 -> 2001:db8::2:9600，DM D100 读 1 字），FINS 载荷与 IPv4 字节级一致 | pass | 2 | [pcap](fins/fins_udp_ipv6_read.pcap) |
| fins_wr_read_word | T-005: WR 工作区字读（W10 读 1 字），omron.memory.area.read=0xB1、address=0x000A | pass | 2 | [pcap](fins/fins_wr_read_word.pcap) |

## Failures

### fins_sessions_three — T-021: 多会话 sessions=3 聚合断言（omron.sid DistinctValues={0x01}；端口全集不作断言，调度无关）

task ended failed: output error: [85f76e45-b636-4c68-87a5-d3e03ad3fb7a-b9c25282-f675-4d5e-b807-5177d01e179b: validation failed: fins: sessions (3) multi-stream expansion is not supported on a layer chain (one flow per chain)]

### fins_sessions_two — T-020: 多会话 sessions=2 双流（各 DM D100 读 1 字），每流 SID 独立从 0x01 递增、跨流不串号；聚合断言 + 每流独立 src_port

task ended failed: output error: [4612e25e-554b-4329-a3d5-71a70173a7ea-7d46bb55-6b20-41ec-9ca4-c4dfd98f730e: validation failed: fins: sessions (2) multi-stream expansion is not supported on a layer chain (one flow per chain)]

