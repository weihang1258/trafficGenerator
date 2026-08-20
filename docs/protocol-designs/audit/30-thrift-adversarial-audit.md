# Thrift（跨语言 RPC 框架）三件套对抗审查报告

> 审查日期：2026-08-20  
> 对象：`30-thrift-design.md`、`30-thrift-testcase.md`、`cases/thrift.json`  
> 属性：设计文档阶段审查；无 Go 实现，不执行协议正例 MCP（模型上下文协议）/suite（测试套件）验收。  
> 结论：本轮发现的问题已在文档/JSON 内修正；剩余实现依赖明确标为待实现边界。

## 1. 审查方法

1. 逐字段核对 TBinaryProtocol：strict version/type、method string、seqid、field type/id、STOP、标量宽度、LIST/SET/MAP header、string/binary length、message type。
2. 从设计 §6 错误表和测试策略逐行反查用例：每个正例有 observable 字段/帧/包数；负例仅 expect_error/error_contains。
3. 以脚本加载 JSON，检查 13 个唯一 ID、正负分类、hex（十六进制）字节可解析、帧 offset（偏移）和 TCP length（长度）一致。
4. 复算包会计：有响应=3 握手+2 数据+4 终止=9；ONEWAY=3+1+4=8；两个 flow=18。

## 2. 已确认通过项

### 2.1 线格式与大端

- 所有正例 strict header 以 `80 01 00 {type}` 开头；没有把 unversioned 旧格式混入正向断言。
- 方法名长度、method 字节、seqid 的顺序和大端编码正确。
- field header 使用 1B type + 2B signed field id；STOP 是单独 `00`。
- `I16=-2` 是 `ff fe`，`I32=-3` 是 `ff ff ff fd`，`I64=-4` 是 `ff ff ff ff ff ff ff fc`；DOUBLE 3.5 是 `40 0c 00 00 00 00 00 00`。
- LIST/MAP/SET 的 type/count/entry 顺序均与规范一致；MAP 的 key/value type 各 1B，count 为 i32。
- STRING/BINARY 长度和二进制内容分别可在 S5 帧中定位；BINARY `00 ff` 未被当作文本。

### 2.2 RPC 类型与状态

- S1 CALL type=1→REPLY type=2，method/seqid 相同；S2 EXCEPTION type=3，异常字段 type=6 的 I32 值没有误当头部 type；S3 ONEWAY type=4 无 response。
- S1/S2/S4/S5/S6 均为 9 包；S3 为 8 包；S7 为 18 包。设计、testcase、JSON 三方表格一致。
- S7 使用 strategy_fc flows=2，端口 distinct_values 只声明 12345/12346 与 9090；未假设验证器能表达跨 flow seqid 关联，已列为集成测试边界。

### 2.3 offset 与长度

- IPv4 offset=54、IPv6 offset=74，计算分别为 14+20+20 与 14+40+20。
- S1 request 应用长度：4+4+3+4+4+（1+2+4）+（1+2+4）+1=30；reply：4+4+3+4+（1+2+4）+1=23。
- S3 长度：4+4+6+4+（1+2+4+1）+1=27。
- S4 长度 69、S5 长度 79 与逐字段累加相符；S2 request 33、exception response 49 与字段长度相符。
- frame hex 均可由 `bytes.fromhex` 解析，且 no frame uses a handshake plain value（没有以握手平凡值冒充数据面锚点）。

## 3. 覆盖与负路径审查

| 需求 | 覆盖 | 结果 |
|---|---|---|
| 大端 i16/i32/i64/double | S2/S4/S5 | 通过 |
| string/binary 长度 | S1/S2/S5/S6 | 通过 |
| field headers/type/id/STOP | S1-S5 | 通过 |
| struct/list/set/map | S4，所有均在同一原子目标内可观测 | 通过 |
| CALL/REPLY/EXCEPTION/ONEWAY | S1/S2/S3 | 通过 |
| service method/seqid | S1/S2/S6/S7 | 通过 |
| TCP 9090、IPv4/IPv6 | S1-S5/S7 + S6 | 通过 |
| 边界/截断/非法 type/负 length | N1-N6 | 规划态通过 |
| 终止 | 所有正例 `terminates` | 通过 |
| 多会话 | S7；明确状态隔离待集成断言 | 通过（边界显式） |

负例 JSON 的 `expect` 键集合严格是 `expect_error,error_contains`；没有 packet_count、frames、fields 等会与“任务被拒绝”冲突的断言。`wire_fault` 只在 spec_json（规划配置）内部出现，不泄漏到 expect。

## 4. 修正记录与残留风险

本轮静态复算发现并修正了一个高风险点：若用旧的 `method + message type + seqid` hex，会与 strict binary protocol 冲突；当前 13 个 JSON frame 已统一为 `version_type` strict 头，设计 §2.2 和 testcase §3 同步说明。

仍需实现后验证的风险，不作为当前文档缺陷：

- `wire_fault` 尚无 planner API，负例需先实现可控原始注入，再把错误文本与实际 Validate 错误对齐；
- TCP MSS 分段会改变包数和单帧可见范围，必须做 TCP stream（流重组）断言，不得把每个 segment（分段）当独立 Thrift message；
- TBinaryProtocol 的非 strict read（兼容读取）不等于 strict write，本设计明确只生成 strict write；
- requiredness、默认值、异常类型枚举及多消息 pipeline 依赖 IDL/实现策略，当前没有编造 wire 断言；
- 当前协议未注册、未实现，正例 suite 失败是预期的前置条件，不是本文档验收失败。

## 5. 静态检查记录

执行：

```text
python3 -m json.tool trafficgen/test/protocol_pcap/cases/thrift.json
```

结果：通过；JSON 13 例，ID 唯一。逐例检查：7 正例含 packet_count/fields 或 frames，6 负例只含 expect_error/error_contains。`bytes.fromhex`、长度和 offset 复算通过。

## 6. 结论

设计、测试定义、机器用例和本审计报告已形成闭环，覆盖请求中的官方 TBinaryProtocol 语义；实现尚未开始，因此不虚报运行时通过。最后一轮按“逐字段/长度/字节序/offset、三方同步、原子覆盖、负例语义”复审结果为 **clean（无新问题）**。

### 6.1 三方 ID 锚点

| JSON id | design 场景 | testcase 场景 | packet_count |
|---|---|---|---:|
| `thrift_call_reply` | S1 | T-THRIFT-S1 | 9 |
| `thrift_exception_reply` | S2 | T-THRIFT-S2 | 9 |
| `thrift_oneway_call` | S3 | T-THRIFT-S3 | 8 |
| `thrift_containers` | S4 | T-THRIFT-S4 | 9 |
| `thrift_scalar_types` | S5 | T-THRIFT-S5 | 9 |
| `thrift_ipv6_echo` | S6 | T-THRIFT-S6 | 9 |
| `thrift_multi_sessions` | S7 | T-THRIFT-S7 | 18 |
| `thrift_neg_truncated` | N1/E-06 | N1 | — |
| `thrift_neg_unknown_type` | N2/E-03 | N2 | — |
| `thrift_neg_negative_length` | N3/E-04 | N3 | — |
| `thrift_neg_negative_container_count` | N4/E-05 | N4 | — |
| `thrift_neg_bad_message_type` | N5/E-02 | N5 | — |
| `thrift_neg_bad_port` | N6/E-01 | N6 | — |
