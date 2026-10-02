# mongodb Pcap Test Results

Cases: 31 — pass 31, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| mongodb_bson_scalar_boundary | #11: BSON 标量边界（空串/false/int32 上下界/null，单键文档多消息） | pass | 12 | [pcap](mongodb/mongodb_bson_scalar_boundary.pcap) |
| mongodb_bson_types | S3: OP_INSERT carrying all supported BSON basic types | pass | 8 | [pcap](mongodb/mongodb_bson_types.pcap) |
| mongodb_empty_boundary | S4: legal minimum five-byte empty BSON selector | pass | 8 | [pcap](mongodb/mongodb_empty_boundary.pcap) |
| mongodb_ipv6 | S5: IPv6 OP_QUERY and OP_REPLY preserve MongoDB header layout | pass | 9 | [pcap](mongodb/mongodb_ipv6.pcap) |
| mongodb_long_document_mss | #17: 大文档 OP_INSERT 跨 MSS 1460 分段（tcp 层重组） | pass | 10 | [pcap](mongodb/mongodb_long_document_mss.pcap) |
| mongodb_message_header | S7: all four little-endian message header fields | pass | 8 | [pcap](mongodb/mongodb_message_header.pcap) |
| mongodb_multi_flow_dynamic | A'/§12.12: flows=3 多流 + ip.src inc / ip.dst rand(seed=42) / tcp.src_port inc （四元组动态对象，静态复制门 §12.9 豁免）；包数 8×N=24 待 suite 先跑后钉 | pass | 24 | [pcap](mongodb/mongodb_multi_flow_dynamic.pcap) |
| mongodb_multi_session | S6: two independent sessions retain request and response correlation | pass | 18 | [pcap](mongodb/mongodb_multi_session.pcap) |
| mongodb_neg_bad_opcode | N4: unknown opcode is rejected | pass | 0 | [pcap]() |
| mongodb_neg_bson_length | N5: BSON length beyond message boundary is rejected | pass | 0 | [pcap]() |
| mongodb_neg_empty_layer | 空层 mongodb:{} —— 层链下显式空配置不静默缺省，validator 报缺消息 | pass | 0 | [pcap]() |
| mongodb_neg_flat_count | P2判死: top-level flat count alongside layers | pass | 0 | [pcap]() |
| mongodb_neg_flat_keys | #26: 顶层扁平键判死（CheckProtoFlat 通用门；src_ip/count/顶层子映射分列三例） | pass | 0 | [pcap]() |
| mongodb_neg_opcode_rejected | A'/G-MONGO-3: numeric opcode 本体拒绝（Validate 同步拒，非空流假成功） | pass | 0 | [pcap]() |
| mongodb_neg_orphan_reply | A'/G-MONGO-3: OP_REPLY 的 responseTo 无对应更早请求（配对守卫） | pass | 0 | [pcap]() |
| mongodb_neg_oversize | N3: messageLength beyond configured limit is rejected | pass | 0 | [pcap]() |
| mongodb_neg_presence_top_level_mongodb | P2判死: layers + top-level mongodb sub-config coexist（M5①，空 map 也死；G-MONGO-6 分支落码后才有执法对象） | pass | 0 | [pcap]() |
| mongodb_neg_short_length | N2: messageLength below header size is rejected | pass | 0 | [pcap]() |
| mongodb_neg_truncated_header | N1: header shorter than 16 bytes is rejected | pass | 0 | [pcap]() |
| mongodb_neg_udp_carrier | N6: UDP carrier is rejected（载体负例：链夹 udp，DependsOn 自动补 tcp → transport duplicated，锚词 tcp） | pass | 0 | [pcap]() |
| mongodb_neg_unknown_layer_field | P2判死: mongodb 层内第 5 个键（V9 unknown field，设计 §2.2） | pass | 0 | [pcap]() |
| mongodb_op_delete_single | S2-③: OP_DELETE 单消息（原子，拆分） | pass | 8 | [pcap](mongodb/mongodb_op_delete_single.pcap) |
| mongodb_op_getmore_single | S2-④: OP_GET_MORE 单消息（原子，拆分） | pass | 8 | [pcap](mongodb/mongodb_op_getmore_single.pcap) |
| mongodb_op_insert_single | S2-①: OP_INSERT 单消息（原子，自 write_ops 拆分） | pass | 8 | [pcap](mongodb/mongodb_op_insert_single.pcap) |
| mongodb_op_killcursors_single | S2-⑤: OP_KILL_CURSORS 单消息（原子，拆分） | pass | 8 | [pcap](mongodb/mongodb_op_killcursors_single.pcap) |
| mongodb_op_update_single | S2-②: OP_UPDATE 单消息（原子，拆分） | pass | 8 | [pcap](mongodb/mongodb_op_update_single.pcap) |
| mongodb_query_reply | S1: OP_QUERY followed by OP_REPLY with responseTo correlation | pass | 9 | [pcap](mongodb/mongodb_query_reply.pcap) |
| mongodb_query_return_fields | #10: OP_QUERY 基本形（returnFieldsSelector 现状声明：struct 无此键） | pass | 8 | [pcap](mongodb/mongodb_query_return_fields.pcap) |
| mongodb_reply_flags | #16(A′): OP_REPLY flags 位面（AwaitCapable bit3） | pass | 9 | [pcap](mongodb/mongodb_reply_flags.pcap) |
| mongodb_request_sequence | #15: 同连接编排 QUERY→REPLY→INSERT→GET_MORE→KILL（§3.15① 载体） | pass | 12 | [pcap](mongodb/mongodb_request_sequence.pcap) |
| mongodb_write_ops | S2: atomic legacy write and cursor operation messages | pass | 12 | [pcap](mongodb/mongodb_write_ops.pcap) |
