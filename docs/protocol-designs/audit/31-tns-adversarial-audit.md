# TNS（Oracle Net/SQL*Net，Oracle 网络服务）三件套双视角对抗审查

> 审查日期：2026-08-20  
> 审查对象：`docs/protocol-designs/31-tns-design.md`、`docs/protocol-designs/31-tns-testcase.md`、`trafficgen/test/protocol_pcap/cases/tns.json`  
> 审查口径：**文档阶段**。本审查只检查公开 wire（线上）字段是否被准确区分、设计/用例/JSON 是否自洽、断言是否可观察；不检查也不假定 Go planner、builder、validator 或 layer registry（层注册表）已经存在。  
> 状态：代码未实现/未注册属于待实现边界，不作为文档缺陷；本轮文档与机器契约末轮 clean（通过）。

## 1. 审查方法

按两个独立视角逐项复核：

1. **设计逻辑视角**：从 TNS 8 字节头、包类型、DATA flags、事件状态、TCP/IP 包数和配置校验反向推导，检查偏移、字节序、边界和“不确定 payload 不编造”原则。
2. **用例覆盖视角**：从 design 的每个规范锚点、事件、载体、边界和错误行反查 testcase/JSON，检查原子性、正负路径、包数、offset 和断言可观察性。

执行静态检查：

```text
python3 -m json.tool trafficgen/test/protocol_pcap/cases/tns.json
12 个 id 唯一；7 个正例均含 packet_count + fields/frames；5 个负例 expect 仅含 expect_error/error_contains
```

## 2. 设计逻辑视角

### D-01：固定包头布局和字节序一致（通过）

设计 §2.1 明确 `length(0..1) + packet_checksum(2..3) + type(4) + reserved(5) + header_checksum(6..7)`，所有 U16 大端；长度下界 8、上界 65535。testcase §1 和 JSON frame offset 56/58/59/60 与 TNS 起点 54 的推导一致，IPv6 使用 76/78/79/80/82 与起点 74 一致。

### D-02：类型值与状态限制一致（通过）

设计固定 CONNECT/ACCEPT/REFUSE/REDIRECT/DATA 为 `01/02/04/05/06`，并把 ACK/NULL/ABORT 等列为扩展而非当前事件。CONNECT 必须首事件；ACCEPT 后才允许 DATA；REFUSE/REDIRECT 后不得继续 DATA。JSON 正例只使用五种目标类型，负例覆盖未知 type。

### D-03：checksum 语义没有伪造算法（通过）

设计只把 packet/header checksum=0 作为 disabled 基线，将非零算法和协商列为待实现。负例只验证“disabled 与显式非零冲突”，没有声称某个 Oracle 版本的 checksum 算法或用未经来源支持的校验字节。

### D-04：DATA flags 与 TTC/SQL*Net 边界清楚（通过）

设计明确 DATA 包体前两字节为大端 `data_flags`，v1 只允许 0；TTC、SQLNET payload 通过 profile 名表达，不把 profile 名或未经核实的 TTC 类型码写入 wire。正例观察 flags 和事件顺序，负例覆盖非零 flags。

### D-05：IPv4/IPv6、TCP 载体和包数推导一致（通过）

TNS 层链明确依赖 TCP、默认 1521；IPv4/IPv6 仅改变外层 offset。应用事件数 2/4/6 分别推导 9/11/13 包；双 session 为 18 包。设计同时指出 MSS/ACK 合并可能改变实现包数，要求三方同步修订，避免把推导当成永恒 wire 事实。

### D-06：不确定的控制包体被正确隔离（通过）

CONNECT、ACCEPT、REFUSE、REDIRECT 内部字段和重定向地址只由版本化 profile 契约表达，文档明确 profile 不是线上字符串；没有编造 Oracle 版本、连接描述、拒绝码或地址长度。该边界符合本阶段“确定规范字节”和“待实现边界”分离要求。

### D-07：配置负路径覆盖关键边界（通过）

设计错误表 E-01..E-05 分别覆盖 UDP、未知 type、长度、checksum、DATA flags；校验规则要求 planner 计算实际长度并拒绝溢出/截断，不能 0 包成功。JSON 每条错误只返回 `expect_error/error_contains`，未把未来 wire_fault 当合法业务配置。

## 3. 用例覆盖视角

### C-01：公共头字段逐项有可观察断言（通过）

`tns_header_fields` 逐包断言 length 非零、packet checksum、type、reserved、header checksum，并对 DATA 包断言 flags=0；frames 覆盖 length/checksum/type/reserved/header checksum/flags 的固定偏移。其余正例也覆盖 type、length 和 IPv6 偏移。

### C-02：控制事件原子化（通过）

CONNECT→ACCEPT、CONNECT→REFUSE、CONNECT→REDIRECT 分为三个独立正例，且拒绝/重定向后没有 DATA/自动重连的状态要求。每个事件的确定类型值均由字段/frame 观察。

### C-03：TTC/SQL*Net 会话顺序有独立覆盖（通过）

`tns_ttc_sqlnet_session` 单独覆盖 CONNECT、ACCEPT、TTC connect/accept、SQLNET request/response 六事件和四个 DATA flags，避免把“有 DATA”误当作 TTC/SQLNET 事件都工作。payload 内部仍明确为 profile 边界，未伪造 SQL 字节。

### C-04：IPv6 和多会话分别覆盖（通过）

IPv6 case 以 `ipv6.version=6`、地址层端口和 offset 78 的类型字节确认外层差异；multi-session case 以两个源端口 distinct_values 聚合确认独立流，避免交织调度下硬编码全局包号。

### C-05：长度/checksum/flags/载体负例原子覆盖（通过）

五条负例每条只注入一个目标错误并只保留错误断言，涵盖 design §8 全部 E-01..E-05。负例不以“任务不失败”代替稳定错误文本，也不对失败 pcap 作断言。

### C-06：JSON、testcase、design 三方索引一致（通过）

design §7 的 7 正例 + 5 负例与 testcase §3 索引、JSON 12 个唯一 id 一一对应；正例 packet_count 为 9/11/13/18，均有字段或 frame；负例无 packet_count、fields、frames。偏移只出现在允许的 IPv4/IPv6 固定头字段位置。

## 4. 已拒绝的疑似问题

| 疑似问题 | 对抗结论 |
|---|---|
| CONNECT/ACCEPT 的内部包体没有十六进制样例 | 非缺陷：其字段随版本/协商变化；文档明确 profile 是待实现契约，编造样例反而违反需求 |
| JSON 使用 `tns.type` 等未来 dissector 字段名 | 当前阶段可观察性契约；实现接入时若 tshark 字段名不同，按设计 §9 先更新映射，不以未注册代码否定文档 |
| 正例只断言 length 非零而非每个长度常量 | 非缺陷：profile payload 未定稿，固定长度会编造未知包体；设计另要求实现测试验证 length 等于重组实际字节数 |
| multi-session 不硬编码 packet 4/5 的流归属 | 非缺陷：调度交织不确定；distinct_values 是正确的并发/隔离可观察断言 |

## 5. 待实现边界（不阻断文档验收）

- `tns` layer、事件 planner、profile registry、TNS dissector 字段尚未实现；
- 非零 checksum 算法、完整 CONNECT/ACCEPT/REFUSE/REDIRECT payload、TTC/SQLNET 字段和 SQL 解析待后续 wire fixture；
- TNS 分片/跨 TCP segment 重组、MSS 后 packet_count、重定向第二连接、认证/加密、非零 DATA flags 待后续版本；
- `wire_fault` 的注入 API 和稳定错误文本需实现阶段先写 failing test（失败测试）再收紧。

这些项目已在 design §1/§2/§3/§4/§9 和 testcase §5/§7 标示，不应在当前 JSON 中伪装成已实现能力。

## 6. 审查结论与自审记录

- 设计逻辑视角：D-01..D-07，**0 个未修复 finding**。
- 用例覆盖视角：C-01..C-06，**0 个未修复 finding**。
- 自审第 1 轮：逐段核对包头字段、绝对 offset、事件数/包数、正负 JSON schema；发现 testcase 4.1 的文字 `packet 7?` 表述不够精确，已修正为“数据包 6、7”。
- 自审第 2 轮：重新从 JSON 反推 design/testcase 索引、负例键集合和 frame offset；发现并修正无关的临时检查输出，末轮 clean。
- **最终结论：文档三件套审查通过；self-review 2 rounds clean（自审 2 轮，末轮通过）。**

未执行 Go build、unit test、MCP suite 或真实 NIC/pcap 回归，因为当前任务明确为文档阶段且 `tns` 尚未实现；这不是本轮文档验收阻塞项。
