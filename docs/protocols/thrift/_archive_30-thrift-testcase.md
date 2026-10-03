# Apache Thrift（跨语言 RPC 框架）Binary Protocol 测试用例

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/30-thrift-design.md`  
> 机器数据：`trafficgen/test/protocol_pcap/cases/thrift.json`  
> 状态：Thrift 层尚未实现；本文定义未来实现的可执行契约，不代表当前 suite（测试套件）应当通过。

## 1. 测试原则

用例从设计文档 §2、§3、§6 每个线字段和错误行派生。正例逐场景单一目的，必须断言 packet_count（数据包数）、握手/协商/终止和数据面 observable（可观测）字段或 frame（帧字节）；负例只允许 `expect_error` 与 `error_contains`，不对不存在的数据包作断言。JSON 中所有数字/字符串均为未来 planner（规划器）配置，不把规划说明写入可执行 `id`。

IPv4 应用 payload 偏移是 `54`（Eth14 + IPv4 20 + TCP20）；IPv6 是 `74`（Eth14 + IPv6 40 + TCP20）。当前正例均未启用 TCP option/MSS 分段，因此这些偏移可直接复算；启用 MSS 的实现测试必须以重组 TCP payload 后的 Thrift 字节为裁判。

## 2. 用例索引

| # | id | 场景 | 包数 | 覆盖 |
|---:|---|---|---:|---|
| 1 | `thrift_call_reply` | S1 | 9 | CALL/REPLY、strict header、i32、field id |
| 2 | `thrift_exception_reply` | S2 | 9 | CALL/EXCEPTION、message/type、seqid |
| 3 | `thrift_oneway_call` | S3 | 8 | ONEWAY、无响应 |
| 4 | `thrift_containers` | S4 | 9 | LIST/SET/MAP、元素 type/count |
| 5 | `thrift_scalar_types` | S5 | 9 | BOOL/BYTE/DOUBLE/I16/I32/I64/STRING/BINARY |
| 6 | `thrift_ipv6_echo` | S6 | 9 | IPv6 载体、STRING、REPLY |
| 7 | `thrift_multi_sessions` | S7 | 18 | 两条独立 TCP flow（流）/seqid 隔离 |
| 8-13 | `thrift_neg_*` | N1-N6 | — | 截断、非法 type、负长度/count、非法 message type、非法端口 |

## 3. 正例逐项契约

### T-THRIFT-S1 `thrift_call_reply`

- 配置：`add` CALL seqid=1，field 1/2 为 I32 值 1/2；REPLY 同 method/seqid，result field 0 为 3。
- 期望：9 包；TCP 握手、协商、终止均存在；request payload 30B，response 23B；目标端口 9090。
- 帧锚点（offset 54）：CALL 以 `80 01 00 01` 开始，method 长度 `00 00 00 03`、`add`、seqid `00 00 00 01`，两个 type=08 字段和 STOP；REPLY 以 `80 01 00 02` 开始，result field id=0/type=08/value=3。

### T-THRIFT-S2 `thrift_exception_reply`

- 配置：divide CALL seqid=7，参数 1/0；EXCEPTION 同 method/seqid，message=`division by zero`、type=6。
- 期望：9 包；request 33B、response 49B；response strict message type=3，异常 struct 的 id=1 为 STRING、id=2 为 I32。
- 注意：异常 `type=6` 是异常字段的 I32 值，不是 message type；这是专门防止字段层级混淆的 observable 断言。

### T-THRIFT-S3 `thrift_oneway_call`

- 配置：notify ONEWAY seqid=4，STRING field id=1 值 x。
- 期望：8 包；唯一应用数据段长度 27B，以 `80 01 00 04` 开始；绝不生成 REPLY。握手与终止仍由 TCP 层负责。

### T-THRIFT-S4 `thrift_containers`

- 配置：describe CALL seqid=1，LIST<I16>[1,-2]、MAP<STRING,I32>{a:7}、SET<STRING>{x,y}。
- 期望：9 包、request 69B；payload 依次出现 LIST type=15/elem=6/count=2、MAP type=13/key=11/value=8/count=1、SET type=14/elem=11/count=2；count 和 -2 均按大端 i32/i16 读取。

### T-THRIFT-S5 `thrift_scalar_types`

- 配置：一个 scalars CALL，覆盖 BOOL true、BYTE -1、DOUBLE 3.5、I16 -2、I32 -3、I64 -4、STRING x、BINARY `00 ff`。
- 期望：9 包、request 79B；每个 field header 的 TType、i16 ID 和值宽度可由帧锚点重算；BINARY 的长度为 2，payload `00 ff` 不作 UTF-8 替换；DOUBLE 大端 bytes 为 `40 0c 00 00 00 00 00 00`。

### T-THRIFT-S6 `thrift_ipv6_echo`

- 配置：IPv6 `2001:db8::1`→`2001:db8::2`，echo CALL/REPLY seqid=9，STRING hello。
- 期望：9 包；IPv6 源/目的字段可解析，目标端口 9090；应用帧 offset=74，CALL strict header + STRING 长度 5 + hello + STOP。

### T-THRIFT-S7 `thrift_multi_sessions`

- 配置：`strategy_fc` 为 flows=2；每个独立 flow 生成 ping CALL/REPLY seqid=1。
- 期望：18 包（每流 3 握手+2 数据+4 终止）；全局 `tcp.srcport` 仅 12345/12346，`tcp.dstport` 仅 9090；每流方法、seqid、状态不可交叉。当前验证器没有跨流 seqid 关联断言，必须在实现集成测试补充。

## 4. 负例契约

| id | 输入错误 | 仅允许断言 |
|---|---|---|
| `thrift_neg_truncated` | `wire_fault.kind=truncate`，STRING 字节截断 | `expect_error=true`，含 `truncated` |
| `thrift_neg_unknown_type` | field type code 99 | `expect_error=true`，含 `unknown field type` |
| `thrift_neg_negative_length` | STRING 负长度注入 | `expect_error=true`，含 `negative length` |
| `thrift_neg_negative_container_count` | LIST 负 count 注入 | `expect_error=true`，含 `negative container count` |
| `thrift_neg_bad_message_type` | message type=9 | `expect_error=true`，含 `invalid message type` |
| `thrift_neg_bad_port` | dst_port=70000 | `expect_error=true`，含 `port` |

这些负例的原始 wire_fault（线错误注入）目前没有实现入口；实现时必须先补一个失败测试，定义错误落点后再收紧 `error_contains`，不得把规划态注入对象误当作合法 TBinaryProtocol 字段。

## 5. 静态与集成检查

```bash
python3 -m json.tool trafficgen/test/protocol_pcap/cases/thrift.json >/dev/null
python3 - <<'PY'
import json
x=json.load(open('trafficgen/test/protocol_pcap/cases/thrift.json'))
assert len(x) == 13 and len({c['id'] for c in x}) == 13
for c in x:
    if c['expect'].get('expect_error'):
        assert set(c['expect']) <= {'expect_error','error_contains'}
PY
```

实现后执行 `flowb_run_protocol_suite`（协议套件驱动）或等价 API→engine（引擎）→pcap→tshark（Wireshark 命令行解析器）集成测试，并使用 `go test -race -count=1`。在层未注册期间不运行正例冒烟；负例结果也只能在对应 Validate 逻辑落地后验收。

## 6. 待实现边界

严格消息头与上述 hex（十六进制）已依据 TBinaryProtocol 定稿；未定稿内容包括 wire_fault 的 API 形状、最大递归深度/字符串上限、IDL requiredness（字段必需性）、跨消息 pipeline、真实多会话服务状态、MSS 分段后 packet_count 的精确变化、EXCEPTION 的语言绑定扩展字段。这些不进入当前可执行正例 ID，也不伪造字节断言。
