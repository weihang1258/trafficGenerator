# modbus Pcap Test Results

Cases: 213 — pass 213, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| modbus-2master-2flow-2tx | T-180: master_count=2 × flow_count=2 × 2 事务 | pass | 44 | [pcap](/tmp/mcp-pcaps/modbus/modbus-2master-2flow-2tx.pcap) |
| modbus-2tx-2flow-combo | T-179: flow_count=2 × 2 事务 = 每流 2 事务 | pass | 22 | [pcap](/tmp/mcp-pcaps/modbus/modbus-2tx-2flow-combo.pcap) |
| modbus-addr-0-min | T-133: StartingAddress=0x0000 最小地址边界 FC=0x03 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-addr-0-min.pcap) |
| modbus-addr-ffff-max | T-134: StartingAddress=0xFFFF 最大地址边界 FC=0x03 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-addr-ffff-max.pcap) |
| modbus-broadcast-read-fc05 | T-094: 广播 UnitID=0 + 读 FC=0x0B (非法 - 应被 Validate 拒绝) | pass | 0 | [pcap]() |
| modbus-broadcast-unit0-exception | T-050: UnitID=0 广播 + 异常响应 → 异常被抑制 (无响应包) | pass | 8 | [pcap](/tmp/mcp-pcaps/modbus/modbus-broadcast-unit0-exception.pcap) |
| modbus-broadcast-unit0-mirror | T-048: UnitID=0 广播无抑制，响应镜像请求 (req/resp) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-broadcast-unit0-mirror.pcap) |
| modbus-broadcast-unit0-suppress | T-049: unit_id=0 broadcast FC=5 write + suppress_broadcast=true, no response packet | pass | 8 | [pcap](/tmp/mcp-pcaps/modbus/modbus-broadcast-unit0-suppress.pcap) |
| modbus-direction-ignored | T-076: Direction=up 已废弃字段被 planner 忽略（行为同未设） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-direction-ignored.pcap) |
| modbus-dstport-1502 | T-177: 显式 dst_port=1502 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-dstport-1502.pcap) |
| modbus-dstport-default-502 | T-176: dst_port 缺省 502 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-dstport-default-502.pcap) |
| modbus-exception-fc01-01 | T-031: FC=1 exception code 1, response PDU 81 01 (3 bytes), request normal | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-exception-fc01-01.pcap) |
| modbus-exception-fc03-02 | T-032: FC=3 exception code 2 (illegal data address), response PDU 83 02, request 03 0000 0001 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-exception-fc03-02.pcap) |
| modbus-exception-fc03-05 | T-035: FC=3 exception code 5 (acknowledge), response PDU 83 05 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-exception-fc03-05.pcap) |
| modbus-exception-fc03-06 | T-036: FC=3 exception code 6 (server device busy), response PDU 83 06 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-exception-fc03-06.pcap) |
| modbus-exception-fc03-07 | T-037: FC=3 exception code 7 (memory parity error), response PDU 83 07 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-exception-fc03-07.pcap) |
| modbus-exception-fc03-08 | T-038: FC=3 exception code 8 (gateway path unavailable), response PDU 83 08 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-exception-fc03-08.pcap) |
| modbus-exception-fc03-0a | T-039: FC=3 exception code 10 (gateway target no response), response PDU 83 0A | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-exception-fc03-0a.pcap) |
| modbus-exception-fc03-0b | T-040: FC=3 exception code 11 (gateway target failed), response PDU 83 0B | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-exception-fc03-0b.pcap) |
| modbus-exception-fc05-03-fc10-04 | T-033+T-034: FC=5 exc 3 response 85 03; FC=16 exc 4 response 90 04 | pass | 11 | [pcap](/tmp/mcp-pcaps/modbus/modbus-exception-fc05-03-fc10-04.pcap) |
| modbus-explicit-srcport-base | T-175: 显式 src_port=40000 两流派生 40000/40001 | pass | 18 | [pcap](/tmp/mcp-pcaps/modbus/modbus-explicit-srcport-base.pcap) |
| modbus-fc01-bit-order-lsb | T-188: FC=0x01 位序 LSB-first（bitval 顺序） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc01-bit-order-lsb.pcap) |
| modbus-fc01-qty1-min | T-121: FC=1 qty=1 minimum, response 01 01 00 (BC=1, default all-zero) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc01-qty1-min.pcap) |
| modbus-fc01-qty2000-max | T-122/T-003: FC=1 qty=2000 max, response BC=250=250, MBAP len=253=253 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc01-qty2000-max.pcap) |
| modbus-fc01-read-coils | T-001/S1: FC=1 read coils, qty=9, response 02 13 01 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc01-read-coils.pcap) |
| modbus-fc02-qty1 | T-004: FC=2 read discrete inputs qty=1, RV=[1], response 02 01 01 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc02-qty1.pcap) |
| modbus-fc02-qty10-bits | T-051: FC=2 Read Discrete Inputs qty=10 (跨 2 字节) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc02-qty10-bits.pcap) |
| modbus-fc02-qty2000-max | T-190: FC=0x02 qty=2000 最大（响应 BC=250） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc02-qty2000-max.pcap) |
| modbus-fc02-read-discrete | T-002: FC=2 read discrete inputs, qty=8 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc02-read-discrete.pcap) |
| modbus-fc03-default-zero | T-006: FC=3 qty=2 default all-zero response 03 04 0000 0000 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc03-default-zero.pcap) |
| modbus-fc03-qty1-min | T-123: FC=0x03 qty=1 最小（响应 BC=2） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc03-qty1-min.pcap) |
| modbus-fc03-qty125-max | T-007: FC=3 qty=125 max, BC=250=250, MBAP len=253=253 (PDU=252B legal upper) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc03-qty125-max.pcap) |
| modbus-fc03-qty125-max-rv | T-026: FC=3 qty=125 显式 RV=250 字节 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc03-qty125-max-rv.pcap) |
| modbus-fc03-read-holding | T-005/S2: FC=3 read holding registers, qty=3, response 4660/22136/39612 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc03-read-holding.pcap) |
| modbus-fc04-base | T-008: FC=4 read input registers qty=1, RV=[171,205], response 04 02 ABCD | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc04-base.pcap) |
| modbus-fc04-qty125-max | T-191: FC=0x04 qty=125 最大（响应 BC=250） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc04-qty125-max.pcap) |
| modbus-fc04-read-input | T-003: FC=4 read input registers, qty=2 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc04-read-input.pcap) |
| modbus-fc05-echo | T-013: FC=5 echo response equals request byte-for-byte | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc05-echo.pcap) |
| modbus-fc05-on-echo-explicit | T-069: FC=0x05 WriteValue=0xFF00 响应 echo 请求 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc05-on-echo-explicit.pcap) |
| modbus-fc05-write-coil | T-009/S3: FC=5 write single coil value=1, response echoes FF00 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc05-write-coil.pcap) |
| modbus-fc05-write-off | T-010/T-142: FC=5 write single coil OFF value=0, wire 05 0064 0000, echo | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc05-write-off.pcap) |
| modbus-fc05-write-off-0000 | T-195: FC=0x05 WriteValue=0x0000 OFF | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc05-write-off-0000.pcap) |
| modbus-fc05-writevalue-0 | T-012: FC=5 write single coil WriteValue=0 mapped to 0 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc05-writevalue-0.pcap) |
| modbus-fc05-writevalue-1 | T-011: FC=5 write single coil WriteValue=1 mapped to 65280, request 05 0064 FF00 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc05-writevalue-1.pcap) |
| modbus-fc05-writevalue-ffff | T-144: FC=0x05 WriteValue=0xFFFF (reject, only 0/0xFF00 valid; use exception instead) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc05-writevalue-ffff.pcap) |
| modbus-fc06-echo | T-015: FC=6 echo response equals request byte-for-byte | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc06-echo.pcap) |
| modbus-fc06-write-register | T-014/S4: FC=6 write single register 4660, response echoes | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc06-write-register.pcap) |
| modbus-fc06-writevalue-ffff | T-143: FC=0x06 WriteValue=0xFFFF 边界 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc06-writevalue-ffff.pcap) |
| modbus-fc07-exc-status-zero | T-017: FC=7 read exception status (RV default all 0), response 07 00 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc07-exc-status-zero.pcap) |
| modbus-fc07-read-exc-status | T-016: FC=7 read exception status, response 165 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc07-read-exc-status.pcap) |
| modbus-fc08-diagnostic | T-018: FC=8 diagnostic sub-function 0, data echo 43707 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc08-diagnostic.pcap) |
| modbus-fc08-sub-0000 | T-149: FC=0x08 SubFunction=0x0000 非法 (query data 0x00) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc08-sub-0000.pcap) |
| modbus-fc08-sub-0001-restart | T-063: FC=0x08 子功能 0x0001 Restart Communications Option | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc08-sub-0001-restart.pcap) |
| modbus-fc08-sub-000a | T-019b: FC=8 SubFunction=10 Clear Counters diagnostic, request/response echo 6B | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc08-sub-000a.pcap) |
| modbus-fc08-sub-000f | T-019c: FC=8 SubFunction=15 Return Bus Message Count, echo with payload data 12 34 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc08-sub-000f.pcap) |
| modbus-fc08-sub-0013-iop | T-064/T-203: FC=0x08 子功能 0x0013 Return IOP Overrun Count 合法 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc08-sub-0013-iop.pcap) |
| modbus-fc08-sub-0015-max | T-150: FC=0x08 子功能 0x0015 最大合法（Get/Clear Modbus Plus Statistics） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc08-sub-0015-max.pcap) |
| modbus-fc0b-0c-event-counter-log | T-054+T-055: FC=11 comm event counter FFFF/0064, FC=12 comm event log BC=10 (R3-H2), TID 0/1 | pass | 11 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc0b-0c-event-counter-log.pcap) |
| modbus-fc0b-multi-tx | T-056: FC=11 Get Comm Event Counter, 3 事务，TID 0/1/2 递增 | pass | 13 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc0b-multi-tx.pcap) |
| modbus-fc0c-events-3ev | T-189: FC=0x0C 3 个事件（每事件 2B 事件类型） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc0c-events-3ev.pcap) |
| modbus-fc0c-events-decoupled | T-056: FC=0x0C EventCount=100 但 Events 4B（长度与数值解耦） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc0c-events-decoupled.pcap) |
| modbus-fc0f-qty1-min | T-124: FC=0x0F qty=1 最小 (BC=1) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc0f-qty1-min.pcap) |
| modbus-fc0f-qty123-unaligned | T-061: FC=15 qty=123 不对齐字节 (BC=16) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc0f-qty123-unaligned.pcap) |
| modbus-fc0f-qty1968-max | T-125: FC=0x0F qty=1968 最大 (BC=246) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc0f-qty1968-max.pcap) |
| modbus-fc0f-write-multi-coils | T-052/S7: FC=15 write multiple coils, 10 coils, values 2 bytes 205 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc0f-write-multi-coils.pcap) |
| modbus-fc10-qty1-min | T-126: FC=0x10 qty=1 最小 (BC=2) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc10-qty1-min.pcap) |
| modbus-fc10-qty123-max | T-127: FC=0x10 qty=123 最大 (BC=246) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc10-qty123-max.pcap) |
| modbus-fc10-write-multi-registers | T-053/S8: FC=16 write multiple registers 2 regs 2571 3085 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc10-write-multi-registers.pcap) |
| modbus-fc11-additional-empty | T-080: FC=17 Report Server ID，response 无 Additional Byte Count（标准无附加） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc11-additional-empty.pcap) |
| modbus-fc11-report-server-id | T-019/S8: FC=17 report server ID, RV=[1,255,170,187], no Byte Count field (R4-H2) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc11-report-server-id.pcap) |
| modbus-fc14-multi-rec-response | T-058b: FC=20 multi-record response, 2 子响应各 RecLen=2 (字节数=4) → total BC=10 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc14-multi-rec-response.pcap) |
| modbus-fc14-multi-record | T-058: FC=20 Read File Record 2 子请求 各 RecLen=2 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc14-multi-record.pcap) |
| modbus-fc14-read-file | T-020: FC=20 read file records, item RefType 06 File 0001 Rec 0000 RL 02, resp FRL=05 data 1234 5678 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc14-read-file.pcap) |
| modbus-fc14-response-offsets | T-186: FC=0x14 响应 File Response Length 偏移布局 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc14-response-offsets.pcap) |
| modbus-fc15-multi-item | T-022: FC=21 write file record 2 items each RecLen=1, outer BC=18=18 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc15-multi-item.pcap) |
| modbus-fc15-write-file | T-021: FC=21 write file record, item RefType 06 File 0001 Rec 0000 RL 02 data 1234 5678 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc15-write-file.pcap) |
| modbus-fc16-mask-and-0000 | T-148: FC=0x16 Mask And=0x0000 Mask Or=0xFFFF | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc16-mask-and-0000.pcap) |
| modbus-fc16-mask-and-ffff | T-146: FC=0x16 Mask And=0xFFFF Mask Or=0x0000 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc16-mask-and-ffff.pcap) |
| modbus-fc16-mask-formula | T-024: FC=22 mask write register A=255 O=1 (documented formula semantics) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc16-mask-formula.pcap) |
| modbus-fc16-mask-write | T-023: FC=22 mask write register AND=242 OR=37, response echoes | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc16-mask-write.pcap) |
| modbus-fc17-bc-readqty | T-028: FC=23 read/write multi registers, ReadQty=10 -> response BC=20=20 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc17-bc-readqty.pcap) |
| modbus-fc17-default-zero | T-061: FC=0x17 ReadQty=2 RV 缺省 → 响应 17 04 0000 0000 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc17-default-zero.pcap) |
| modbus-fc17-quantity-ignored | T-079: FC=0x17 Quantity=999 被忽略（报文同 ReadQty/WriteQty） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc17-quantity-ignored.pcap) |
| modbus-fc17-read-write | T-027: FC=23 read/write registers, read 2 @3, write 2 @20, resp 2571 3085 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc17-read-write.pcap) |
| modbus-fc17-readqty-125-max | T-129: FC=0x17 ReadQty=125 最大（响应 BC=250=0xFA） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc17-readqty-125-max.pcap) |
| modbus-fc17-writeaddr-explicit | T-157: FC=0x17 WriteAddress 显式与 StartingAddress 不同 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc17-writeaddr-explicit.pcap) |
| modbus-fc17-writeaddr-fallback | T-156: FC=0x17 WriteAddress=0 缺省回退到 StartingAddress | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc17-writeaddr-fallback.pcap) |
| modbus-fc17-writeaddr-wrap | T-157: FC=0x17 WriteAddress 回退 uint16 回绕（0xFFFF+3→0x0002） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc17-writeaddr-wrap.pcap) |
| modbus-fc17-writeqty-121-max | T-130: FC=0x17 WriteQty=121 最大（请求 WriteBC=242=0xF2） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc17-writeqty-121-max.pcap) |
| modbus-fc18-fifo-count-0 | T-062: FC=0x18 FIFO Count=0 最小（值字节数=0 自洽） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc18-fifo-count-0.pcap) |
| modbus-fc18-fifo-count-0-min | T-131: FC=0x18 FIFO Count=0 最小（T-062 边界列） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc18-fifo-count-0-min.pcap) |
| modbus-fc18-fifo16-mid | T-029c: FC=24 FIFO Count=16 mid-range boundary | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc18-fifo16-mid.pcap) |
| modbus-fc18-fifo2-min | T-029b: FC=24 FIFO Count=2 minimum | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc18-fifo2-min.pcap) |
| modbus-fc18-fifo31-max | T-030: FC=24 FIFO count=31 max, RV contains 31 registers, FIFO Count=31 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc18-fifo31-max.pcap) |
| modbus-fc18-fifo31-max-rv | T-200: FC=0x18 FIFO Count=31 最大（响应 BC=64=0x40） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc18-fifo31-max-rv.pcap) |
| modbus-fc18-read-fifo | T-029: FC=24 read FIFO queue, count=2, values 1 2 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc18-read-fifo.pcap) |
| modbus-fc2b-conformity-01-basic | T-151: FC=0x2B Conformity Level=0x01 Basic | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc2b-conformity-01-basic.pcap) |
| modbus-fc2b-conformity-03-extended | T-152: FC=0x2B Conformity Level=0x03 Extended | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc2b-conformity-03-extended.pcap) |
| modbus-fc2b-conformity-83-extended-private | T-153: FC=0x2B Conformity Level=0x83 Extended+Private | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc2b-conformity-83-extended-private.pcap) |
| modbus-fc2b-mei-base | T-025: FC=43 MEI Type=14 Read Device Identification, base stream access | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc2b-mei-base.pcap) |
| modbus-fc2b-mei-conformity1 | T-065: FC=43 MEI=14 Conformity Level 1 (stream access 1 obj) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc2b-mei-conformity1.pcap) |
| modbus-fc2b-mei-multi-obj | T-068: FC=43 MEI 多个 Object (VendorName + ProductCode) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc2b-mei-multi-obj.pcap) |
| modbus-fc2b-mei-read-device-id | T-025/S15: FC=43 MEI 14 read device id, object ABCDEF | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc2b-mei-read-device-id.pcap) |
| modbus-fc2b-more-follows-ff-next-05 | T-066/T-068: FC=0x2B More Follows=0xFF + Next Object ID=0x05 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc2b-more-follows-ff-next-05.pcap) |
| modbus-fc2b-object-len-0 | T-154: FC=0x2B Object Length=0（Obj 仅 ID+Len=2B） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc2b-object-len-0.pcap) |
| modbus-fc2b-object-len-255 | T-155: FC=0x2B Object Length=255（Value 255B='A'×255） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc2b-object-len-255.pcap) |
| modbus-fc2b-sub-0015 | T-150: FC=0x2B SubFunction=0x0015 exception (非法) | pass | 0 | [pcap]() |
| modbus-fc99-exemption | T-201/S14: FC=153 exemption path with exc 1, response PDU 99 01 (FC\|128 idempotent) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-fc99-exemption.pcap) |
| modbus-flow-count-4 | T-171: FlowCount=4 独立流 (每流 1 tx) → 4×9=36 packets | pass | 36 | [pcap](/tmp/mcp-pcaps/modbus/modbus-flow-count-4.pcap) |
| modbus-flow2-port-separation | T-168: flow_count=2 两流 srcPort=20000/20001 | pass | 18 | [pcap](/tmp/mcp-pcaps/modbus/modbus-flow2-port-separation.pcap) |
| modbus-flow2-tid-per-flow | T-171: flow_count=2 每流独立 TID（0,1 重复） | pass | 22 | [pcap](/tmp/mcp-pcaps/modbus/modbus-flow2-tid-per-flow.pcap) |
| modbus-master1-flow1-baseline | T-166: master_count=1 × flow_count=1 单流基线 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-master1-flow1-baseline.pcap) |
| modbus-master2-flow2-matrix | T-169: master_count=2 × flow_count=2 = 4 流 srcPort 20000-20003 | pass | 36 | [pcap](/tmp/mcp-pcaps/modbus/modbus-master2-flow2-matrix.pcap) |
| modbus-master2-port-separation | T-167: master_count=2 两 master srcPort=20000/20001 | pass | 18 | [pcap](/tmp/mcp-pcaps/modbus/modbus-master2-port-separation.pcap) |
| modbus-master2-tid-per-master | T-170: master_count=2 每 master TID 独立 0,1 | pass | 22 | [pcap](/tmp/mcp-pcaps/modbus/modbus-master2-tid-per-master.pcap) |
| modbus-master3-port-unique | T-172: master_count=3 三流 srcPort 唯一且连续 | pass | 27 | [pcap](/tmp/mcp-pcaps/modbus/modbus-master3-port-unique.pcap) |
| modbus-mastercount2-2flows | T-161/S11: MasterCount=2, two independent TCP flows (4-tuple), per-flow TID starts at 0 | pass | 18 | [pcap](/tmp/mcp-pcaps/modbus/modbus-mastercount2-2flows.pcap) |
| modbus-mastercount2-flows3 | T-165: MasterCount=2 FlowCount=3 = 6 独立 TCP 流 | pass | 54 | [pcap](/tmp/mcp-pcaps/modbus/modbus-mastercount2-flows3.pcap) |
| modbus-mastercount3-flows | T-162: MasterCount=3 FlowCount=1 三并发 master 独立 TCP 流 (3 SYN) | pass | 27 | [pcap](/tmp/mcp-pcaps/modbus/modbus-mastercount3-flows.pcap) |
| modbus-multi-flow-same-dstport | T-178: flow_count=2 两流 dst_port 同为 502 | pass | 18 | [pcap](/tmp/mcp-pcaps/modbus/modbus-multi-flow-same-dstport.pcap) |
| modbus-r2-fc2b-resp-indep | T-204: FC=0x2B response 独立 req/resp 结构 (req=2B 0E 01, resp 含 objects) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-r2-fc2b-resp-indep.pcap) |
| modbus-r2-fc2b-sub-0013 | T-202: FC=0x2B SubFunction=0x0013 异常响应 (非 Read Device ID) | pass | 0 | [pcap]() |
| modbus-r2-fc2b-sub-0014 | T-203: FC=0x2B SubFunction=0x0014 异常响应 | pass | 0 | [pcap]() |
| modbus-r2-resp-values-indep | T-205: response_values 独立于 values (req 只有 req data, resp 用 RV 字段) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-r2-resp-values-indep.pcap) |
| modbus-r4-bcast-fc01 | T-095b: UnitID=0 + FC=0x01 读线圈 (broadcast+read 非法) | pass | 0 | [pcap]() |
| modbus-r4-bcast-fc02 | T-095c: UnitID=0 + FC=0x02 读离散输入 (broadcast+read 非法) | pass | 0 | [pcap]() |
| modbus-r4-bcast-fc03 | T-095d: UnitID=0 + FC=0x03 读保持寄存器 (broadcast+read 非法) | pass | 0 | [pcap]() |
| modbus-r4-bcast-fc04 | T-095e: UnitID=0 + FC=0x04 读输入寄存器 (broadcast+read 非法) | pass | 0 | [pcap]() |
| modbus-r4-bcast-fc07 | T-095f: UnitID=0 + FC=0x07 读异常状态 (broadcast+read 非法) | pass | 0 | [pcap]() |
| modbus-r4-bcast-fc0b | T-095h: UnitID=0 + FC=0x0B 取事件计数器 (broadcast+read 非法) | pass | 0 | [pcap]() |
| modbus-r4-bcast-fc0c | T-095i: UnitID=0 + FC=0x0C 取事件日志 (broadcast+read 非法) | pass | 0 | [pcap]() |
| modbus-r4-bcast-fc11 | T-095g: UnitID=0 + FC=0x11 报告从站ID (broadcast+read 非法) | pass | 0 | [pcap]() |
| modbus-r4-bcast-fc14 | T-095j: UnitID=0 + FC=0x14 读文件记录 (broadcast+read 非法) | pass | 0 | [pcap]() |
| modbus-r4-bcast-fc17 | T-095k: UnitID=0 + FC=0x17 读写多寄存器 (broadcast+read 非法) | pass | 0 | [pcap]() |
| modbus-r4-bcast-fc18 | T-095l: UnitID=0 + FC=0x18 读 FIFO 队列 (broadcast+read 非法) | pass | 0 | [pcap]() |
| modbus-r4-fc18-fifo-inconsistent | T-119b: FC=0x18 FIFO Count 与值字节数不自洽 (期望 Validate 拒绝) | pass | 0 | [pcap]() |
| modbus-r4-fc2b-sub-000f | T-117b: FC=0x2B SubFunction=0x000F 应被 Validate 拒绝 (合法子功能仅 0x000E) | pass | 0 | [pcap]() |
| modbus-req-resp-directions | T-183: 请求 up 响应 down（同 TID 配对） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-req-resp-directions.pcap) |
| modbus-responsemode-no-response | T-078: ResponseMode=no_response → 不生成响应包 | pass | 8 | [pcap](/tmp/mcp-pcaps/modbus/modbus-responsemode-no-response.pcap) |
| modbus-responsemode-normal-default | T-077: ResponseMode 缺省（normal）→ 生成响应包 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-responsemode-normal-default.pcap) |
| modbus-shared-tid-master2 | T-173: SharedTIDSpace=true master_count=2 全局 TID 递增 0,1 | pass | 18 | [pcap](/tmp/mcp-pcaps/modbus/modbus-shared-tid-master2.pcap) |
| modbus-shared-tid-space-false | T-163: SharedTIDSpace=false 跨 master 各自 TID=0 起始 | pass | 22 | [pcap](/tmp/mcp-pcaps/modbus/modbus-shared-tid-space-false.pcap) |
| modbus-shared-tid-space-true | T-164: SharedTIDSpace=true 跨 master 全局 TID 递增 | pass | 22 | [pcap](/tmp/mcp-pcaps/modbus/modbus-shared-tid-space-true.pcap) |
| modbus-shared-tid-wrap-65538 | T-174: SharedTIDSpace=true 65538 事务全局 TID 回绕到 0 | pass | 131083 | [pcap](/tmp/mcp-pcaps/modbus/modbus-shared-tid-wrap-65538.pcap) |
| modbus-tid-0-first | T-138: 第 1 个事务 TID=0x0000 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-tid-0-first.pcap) |
| modbus-tid-increment-256tx | T-043: 单流 256 个事务 TID 从 0 递增到 255 | pass | 519 | [pcap](/tmp/mcp-pcaps/modbus/modbus-tid-increment-256tx.pcap) |
| modbus-tid-monotonic-3tx | T-139: 单流 3 事务 TID 严格递增 0,1,2 | pass | 13 | [pcap](/tmp/mcp-pcaps/modbus/modbus-tid-monotonic-3tx.pcap) |
| modbus-tid-no-reorder | T-184: 多事务 TID 严格顺序（3 请求 TID=0,1,2） | pass | 13 | [pcap](/tmp/mcp-pcaps/modbus/modbus-tid-no-reorder.pcap) |
| modbus-tid-per-flow-2flows | T-137: SharedTIDSpace=false 每流 TID 从 0 独立递增 | pass | 22 | [pcap](/tmp/mcp-pcaps/modbus/modbus-tid-per-flow-2flows.pcap) |
| modbus-tid-perflow-5tx | T-137: SharedTIDSpace=false 5 事务 TID 0..4 | pass | 17 | [pcap](/tmp/mcp-pcaps/modbus/modbus-tid-perflow-5tx.pcap) |
| modbus-tid-sequence-3tx | T-042/S15: 3 transactions TID 0,1,2 monotonic, req/resp share TID | pass | 13 | [pcap](/tmp/mcp-pcaps/modbus/modbus-tid-sequence-3tx.pcap) |
| modbus-tid-shared-space-2flows | T-140: SharedTIDSpace=true 两流共享全局递增序列 | pass | 18 | [pcap](/tmp/mcp-pcaps/modbus/modbus-tid-shared-space-2flows.pcap) |
| modbus-tid-wrap-65536 | T-044: 65536 个事务 TID 从 65535 回绕到 0 | pass | 131079 | [pcap](/tmp/mcp-pcaps/modbus/modbus-tid-wrap-65536.pcap) |
| modbus-transactions-empty-array | T-075: Transactions=[] 仅 TCP 握手+挥手（0 个 Modbus 请求包） | pass | 7 | [pcap](/tmp/mcp-pcaps/modbus/modbus-transactions-empty-array.pcap) |
| modbus-transactions-nil-default | T-074: Transactions=nil 默认 1 个 FC=0x03 事务（1 请求+1 响应） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-transactions-nil-default.pcap) |
| modbus-tx-order-sequential | T-182: 事务顺序按数组序（FC 3,4,5,6） | pass | 15 | [pcap](/tmp/mcp-pcaps/modbus/modbus-tx-order-sequential.pcap) |
| modbus-unitid-128-mid | T-073: Unit ID=128 中值（MBAP unit=0x80） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-unitid-128-mid.pcap) |
| modbus-unitid-247-max | T-135: Unit ID=247 最大合法 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-unitid-247-max.pcap) |
| modbus-unitid-default-1 | T-045: UnitID=nil 默认 1（MBAP unit 字段=0x01） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-unitid-default-1.pcap) |
| modbus-validate-broadcast-fc01 | T-094: Validate negative — broadcast (unit_id=0) + read FC=1 rejected | pass | 0 | [pcap]() |
| modbus-validate-broadcast-fc03 | T-095: Validate negative — broadcast + FC=3 read rejected | pass | 0 | [pcap]() |
| modbus-validate-exc-00 | T-089: Validate negative — exception_code=0 illegal (zero means unset) | pass | 0 | [pcap]() |
| modbus-validate-exc-09 | T-090: Validate negative — exception_code=9 not in legal set | pass | 0 | [pcap]() |
| modbus-validate-exc-0c | T-091: Validate negative — exception_code=12 not in legal set | pass | 0 | [pcap]() |
| modbus-validate-exc-ff | T-092: Validate negative — exception_code=255 not in legal set | pass | 0 | [pcap]() |
| modbus-validate-fc05-illegal-value | T-111: Validate negative — FC=5 write_value=4660 illegal (must be 0/1/65280/0) | pass | 0 | [pcap]() |
| modbus-validate-fc08-subfn-0016 | T-113: Validate negative — FC=8 sub_function=22 > 21 rejected | pass | 0 | [pcap]() |
| modbus-validate-fc08-subfn-reserved | T-114: Validate negative — FC=8 sub_function=5 reserved rejected | pass | 0 | [pcap]() |
| modbus-validate-fc14-reclen-0 | T-118: Validate negative — FC=20 record_length=0 rejected | pass | 0 | [pcap]() |
| modbus-validate-fc15-bc-mismatch | T-116: Validate negative — FC=21 outer byte count != len-1 rejected | pass | 0 | [pcap]() |
| modbus-validate-fc15-reclen-0 | T-119: Validate negative — FC=21 record_length=0 rejected | pass | 0 | [pcap]() |
| modbus-validate-fc15-reftype-7 | T-115: Validate negative — FC=21 item Reference Type != 6 rejected | pass | 0 | [pcap]() |
| modbus-validate-fc17-readqty-126 | T-106: Validate negative — FC=0x17 ReadQty=126 > 125 拒绝 | pass | 0 | [pcap]() |
| modbus-validate-fc18-fifo-32 | T-112: Validate negative — FC=24 FIFO count=32 > 31 rejected | pass | 0 | [pcap]() |
| modbus-validate-fc2b-highbyte-010e | T-115: Validate negative — FC=0x2B SubFunction 高字节非 0 拒绝 | pass | 0 | [pcap]() |
| modbus-validate-fc2b-mei-000f | T-117b: Validate negative — FC=43 MEI Type=15 not 14 rejected | pass | 0 | [pcap]() |
| modbus-validate-fc2b-sub-0000 | T-116: Validate negative — FC=0x2B SubFunction=0x00 无 MEI Type 拒绝 | pass | 0 | [pcap]() |
| modbus-validate-fc2b-sub-000d | T-117: Validate negative — FC=0x2B SubFunction=0x000D CANopen（CiA 309）拒绝 | pass | 0 | [pcap]() |
| modbus-validate-fc99-exc0 | T-081: Validate negative — FC=0x99 不支持 + ExcCode=0（无豁免路径）拒绝 | pass | 0 | [pcap]() |
| modbus-validate-flowcount-0 | T-180d: Validate negative — flow_count=0 rejected | pass | 0 | [pcap]() |
| modbus-validate-high-bit-fc81 | T-088: Validate negative — FC=129 (supported FC with high bit set) rejected | pass | 0 | [pcap]() |
| modbus-validate-mastercount-0 | T-180b: Validate negative — master_count=0 rejected | pass | 0 | [pcap]() |
| modbus-validate-mastercount-1001 | T-180c: Validate negative — master_count=1001 rejected | pass | 0 | [pcap]() |
| modbus-validate-mutex-exc-rv | T-093: Validate negative — exception_code and response_values mutually exclusive | pass | 0 | [pcap]() |
| modbus-validate-qty-fc01-0 | T-098: Validate negative — FC=1 quantity=0 rejected | pass | 0 | [pcap]() |
| modbus-validate-qty-fc01-2001 | T-099: Validate negative — FC=1 quantity=2001 > 2000 rejected | pass | 0 | [pcap]() |
| modbus-validate-qty-fc03-0 | T-100: Validate negative — FC=3 quantity=0 rejected | pass | 0 | [pcap]() |
| modbus-validate-qty-fc03-126 | T-101: Validate negative — FC=3 quantity=126 > 125 rejected | pass | 0 | [pcap]() |
| modbus-validate-qty-fc0f-0 | T-104: Validate negative — FC=15 quantity=0 rejected | pass | 0 | [pcap]() |
| modbus-validate-qty-fc0f-1969 | T-105: Validate negative — FC=15 quantity=1969 > 1968 rejected | pass | 0 | [pcap]() |
| modbus-validate-qty-fc10-0 | T-102: Validate negative — FC=16 quantity=0 rejected | pass | 0 | [pcap]() |
| modbus-validate-qty-fc10-124 | T-103: Validate negative — FC=16 quantity=124 > 123 rejected | pass | 0 | [pcap]() |
| modbus-validate-unitid-248 | T-096: Validate negative — unit_id=248 reserved/rejected (max 247) | pass | 0 | [pcap]() |
| modbus-validate-unitid-255 | T-097: Validate negative — unit_id=255 reserved, rejected | pass | 0 | [pcap]() |
| modbus-validate-unsupported-fc09 | T-081: Validate negative — FC=9 unsupported (no exemption), Validate rejects | pass | 0 | [pcap]() |
| modbus-validate-unsupported-fc0a | T-082: Validate negative — FC=10 unsupported, rejected | pass | 0 | [pcap]() |
| modbus-validate-unsupported-fc0d | T-083: Validate negative — FC=13 unsupported, rejected | pass | 0 | [pcap]() |
| modbus-validate-unsupported-fc12 | T-084: Validate negative — FC=18 unsupported, rejected | pass | 0 | [pcap]() |
| modbus-validate-unsupported-fc13 | T-085: Validate negative — FC=19 unsupported, rejected | pass | 0 | [pcap]() |
| modbus-validate-unsupported-fc19 | T-086: Validate negative — FC=25 unsupported, rejected | pass | 0 | [pcap]() |
| modbus-validate-unsupported-fc2a | T-087: Validate negative — FC=42 unsupported, rejected | pass | 0 | [pcap]() |
| modbus-validate-values-fc0f-wrong | T-107: Validate negative — FC=15 values length 2 (should be 1 for qty=8) | pass | 0 | [pcap]() |
| modbus-validate-values-fc10 | T-108: Validate negative — FC=16 values length != quantity*2 | pass | 0 | [pcap]() |
| modbus-validate-values-fc17 | T-109: Validate negative — FC=23 values length != write_quantity*2 | pass | 0 | [pcap]() |
| modbus-wire-broadcast-display | T-198: UnitID=0 tshark 显示为 broadcast | pass | 8 | [pcap](/tmp/mcp-pcaps/modbus/modbus-wire-broadcast-display.pcap) |
| modbus-wire-fc01-tshark | T-181: FC=0x01 Read Coils tshark 解析字段级断言 (mbap + pdu) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-wire-fc01-tshark.pcap) |
| modbus-wire-fc11-no-byte-count | T-185: FC=0x11 Report Server ID tshark 解析无 Byte Count (R4-H2 修复) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-wire-fc11-no-byte-count.pcap) |
| modbus-wire-fc15-reftype6 | T-187: FC=0x15 Reference Type=6 多项 tshark 字段断言 | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-wire-fc15-reftype6.pcap) |
| modbus-wire-fc16-echo | T-197: FC=0x16 mask write req/resp echo verify (response 字节与 request 完全一致) | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-wire-fc16-echo.pcap) |
| modbus-wire-mbap-length | T-192: tshark MBAP Length 字段 — 3 种事务长度均与 PDU 一致 | pass | 13 | [pcap](/tmp/mcp-pcaps/modbus/modbus-wire-mbap-length.pcap) |
| modbus-wire-multi-tx-session | T-199: 3 事务完整会话 tshark 识别 TID 序列 | pass | 13 | [pcap](/tmp/mcp-pcaps/modbus/modbus-wire-multi-tx-session.pcap) |
| modbus-wire-pid-unreachable-skip | T-120: Protocol ID 非 0（wire 层）— 不可达，跳过（builder 硬编码 PID=0x0000） | pass | 9 | [pcap](/tmp/mcp-pcaps/modbus/modbus-wire-pid-unreachable-skip.pcap) |
| modbus-wire-tid-sequence | T-193: tshark Transaction ID 字段 — 多事务序列递增 | pass | 13 | [pcap](/tmp/mcp-pcaps/modbus/modbus-wire-tid-sequence.pcap) |
