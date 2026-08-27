# fins Pcap Test Results

Cases: 14 — pass 0, fail 1, error 13

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| fins_cio_read_word | T-004: CIO 区字读（CIO0 读 1 字），omron.memory.area.read=0xB0（CIO 字码），响应 2 字节数据 | error | 0 | `` |
| fins_cio_write_bit | T-010: CIO 位域写（CIO0 bit3 起写 2 bit ON/OFF），omron.memory.area.read=0x30、address.bits=0x03、numitems=2，写请求数据 01 00，响应无数据 | error | 0 | `` |
| fins_clock_read_bcd | T-012: Clock Read（0x0701）无参数请求 + BCD 响应（世纪20/年26/月08/日18/时14/分30/秒00/星期02）；Wireshark 对 0x0701 响应不解析结束码，用 FrameAssert 校验 | error | 0 | `` |
| fins_hr_read_bit | T-009: HR 位域读（H10 的 bit2/3 读 2 bit），omron.memory.area.read=0x32（HR 位码）、address.bits=0x02、numitems=2，响应数据 2 字节 01 00（FrameAssert 校验位数据每 bit 1 字节） | error | 0 | `` |
| fins_hr_read_word | T-006: HR 保持区字读（H5 读 2 字），omron.memory.area.read=0xB2、address=0x0005、numitems=2，响应数据 4 字节 | error | 0 | `` |
| fins_ir_read_word | T-008: IR 索引寄存器字读（IR0 读 1 字），omron.memory.area.read=0xDC（CS1 Index Register） | error | 0 | `` |
| fins_sessions_neg_area | T-023: 多会话负路径——sessions=2 且命令内存区非法 'xyz_bad'，Validate 必须拒绝（任务失败），禁止 0 包静默通过 | fail | 0 | `` |
| fins_sessions_three | T-021: 多会话 sessions=3 聚合断言（omron.sid DistinctValues={0x01}；端口全集不作断言，调度无关） | error | 0 | `` |
| fins_sessions_two | T-020: 多会话 sessions=2 双流（各 DM D100 读 1 字），每流 SID 独立从 0x01 递增、跨流不串号；聚合断言 + 每流独立 src_port | error | 0 | `` |
| fins_tc_read_pv | T-007: TC 定时器/计数器 PV 字读（TC0 读 1 字），omron.memory.area.read=0x89（PV 字码） | error | 0 | `` |
| fins_tcp_read | T-002: FINS/TCP Frame Send 读取（D100 读 2 字），FINS/TCP 头 'FINS' magic+length=26+command=0x00000002+error=0，TCP 9600，带握手；omron.tcp.command 与 omron.command 隔离验证 | error | 0 | `` |
| fins_udp_dm_read | T-001: FINS/UDP 内存区读-响应往返（DM D100 读 2 字），请求 ICF=0x81/响应 ICF=0xC1，SID=0x01 回显，10.0.0.1:1234<->20.0.0.1:9600 | error | 0 | `` |
| fins_udp_ipv6_read | T-003: FINS/UDP 内存区读 over IPv6（2001:db8::1 -> 2001:db8::2:9600，DM D100 读 1 字），FINS 载荷与 IPv4 字节级一致 | error | 0 | `` |
| fins_wr_read_word | T-005: WR 工作区字读（W10 读 1 字），omron.memory.area.read=0xB1、address=0x000A | error | 0 | `` |

## Failures

### fins_cio_read_word — T-004: CIO 区字读（CIO0 读 1 字），omron.memory.area.read=0xB0（CIO 字码），响应 2 字节数据

generate: invalid or missing protocol: fins

### fins_cio_write_bit — T-010: CIO 位域写（CIO0 bit3 起写 2 bit ON/OFF），omron.memory.area.read=0x30、address.bits=0x03、numitems=2，写请求数据 01 00，响应无数据

generate: invalid or missing protocol: fins

### fins_clock_read_bcd — T-012: Clock Read（0x0701）无参数请求 + BCD 响应（世纪20/年26/月08/日18/时14/分30/秒00/星期02）；Wireshark 对 0x0701 响应不解析结束码，用 FrameAssert 校验

generate: invalid or missing protocol: fins

### fins_hr_read_bit — T-009: HR 位域读（H10 的 bit2/3 读 2 bit），omron.memory.area.read=0x32（HR 位码）、address.bits=0x02、numitems=2，响应数据 2 字节 01 00（FrameAssert 校验位数据每 bit 1 字节）

generate: invalid or missing protocol: fins

### fins_hr_read_word — T-006: HR 保持区字读（H5 读 2 字），omron.memory.area.read=0xB2、address=0x0005、numitems=2，响应数据 4 字节

generate: invalid or missing protocol: fins

### fins_ir_read_word — T-008: IR 索引寄存器字读（IR0 读 1 字），omron.memory.area.read=0xDC（CS1 Index Register）

generate: invalid or missing protocol: fins

### fins_sessions_neg_area — T-023: 多会话负路径——sessions=2 且命令内存区非法 'xyz_bad'，Validate 必须拒绝（任务失败），禁止 0 包静默通过

rejected but error "invalid or missing protocol: fins" does not contain "memory area"

### fins_sessions_three — T-021: 多会话 sessions=3 聚合断言（omron.sid DistinctValues={0x01}；端口全集不作断言，调度无关）

generate: invalid or missing protocol: fins

### fins_sessions_two — T-020: 多会话 sessions=2 双流（各 DM D100 读 1 字），每流 SID 独立从 0x01 递增、跨流不串号；聚合断言 + 每流独立 src_port

generate: invalid or missing protocol: fins

### fins_tc_read_pv — T-007: TC 定时器/计数器 PV 字读（TC0 读 1 字），omron.memory.area.read=0x89（PV 字码）

generate: invalid or missing protocol: fins

### fins_tcp_read — T-002: FINS/TCP Frame Send 读取（D100 读 2 字），FINS/TCP 头 'FINS' magic+length=26+command=0x00000002+error=0，TCP 9600，带握手；omron.tcp.command 与 omron.command 隔离验证

generate: invalid or missing protocol: fins

### fins_udp_dm_read — T-001: FINS/UDP 内存区读-响应往返（DM D100 读 2 字），请求 ICF=0x81/响应 ICF=0xC1，SID=0x01 回显，10.0.0.1:1234<->20.0.0.1:9600

generate: invalid or missing protocol: fins

### fins_udp_ipv6_read — T-003: FINS/UDP 内存区读 over IPv6（2001:db8::1 -> 2001:db8::2:9600，DM D100 读 1 字），FINS 载荷与 IPv4 字节级一致

generate: invalid or missing protocol: fins

### fins_wr_read_word — T-005: WR 工作区字读（W10 读 1 字），omron.memory.area.read=0xB1、address=0x000A

generate: invalid or missing protocol: fins

