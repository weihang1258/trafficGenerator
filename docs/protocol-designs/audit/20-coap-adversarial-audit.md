# CoAP（受约束应用协议）双视角对抗审查报告

> 审查日期：2026-08-19
> 审查范围：`20-coap-design.md`、`20-coap-testcase.md`、`trafficgen/test/protocol_pcap/cases/coap.json`、共享 `internal/pcaptest` 断言与 MCP 驱动。
> 审查状态：代码逻辑 3 轮、用例覆盖 3 轮；末轮 clean。CoAP 当前未注册/未实现，以下“通过”均不得解释为真实 CoAP pcap 已通过。

## 1. 代码逻辑对抗审查

### C-01：CoAP 当前处于待实现边界

仓库没有 CoAP planner、builder、config、validator、layer registry 注册、FlowSpec/strategy converter 接线或 server planner 注册。16 条 JSON 会在未知层/协议白名单阶段拒绝，不能生成 CoAP pcap。

- 最小失败用例：`coap_con_get`。
- 验收闸门：先注册 UDP Terminal 层和 CoAP generator/validator，再用零配置最小 GET 走通 strategy→task→engine→pcap。
- 负例在接线前只能标记为 blocked/unimplemented，不得声称验证了 CoAP 特定错误文本。

### C-02：共享 `HasPayload` 不是 CoAP 负载判断

`internal/pcaptest/verify.go` 使用 `frame.len > 80`，不能证明 CoAP payload 存在；短合法负载可能失败，无负载但长 Option 也可能伪造通过。

- 最小失败用例：短 POST/Observe/多会话响应带非空 CoAP payload；断言应使用 `coap.payload_length` 或精确 payload bytes。

### C-03：共享 `Directional` 不能验证反向四元组

当前只统计至少两个不同 IPv4 `ip.src`，不验证端口、逐包方向，也没有 IPv6 等价检查。

- 最小失败用例：响应回错端口但仍有两个不同源 IP；当前逻辑会通过。
- 修复契约：增加逐包端点镜像/tuple 断言，或为协议提供显式方向断言。

### C-04：共享聚合断言不能验证跨字段绑定

`DistinctValues` 只比较单字段集合，不能证明 Token、MID、端口和四元组属于同一会话。

- 最小失败用例：交换两个会话的 Token 或 ACK 端口但保持各字段集合不变。
- 修复契约：增加按 flow/tuple 分组的关联断言。

### C-05：负例离线校验旁路

`VerifyPcap` 对 `ExpectError` 直接返回空问题；离线残留 pcap 可能被误判为负例通过。

- 最小失败用例：负例旁放置残留 pcap，验证必须检查拒绝结果/文件不存在，不能直接跳过。

### C-06：MCP/Go case loader 缺少 schema 闸门

当前 loader 未强制唯一 ID、`proto` 与文件名一致、expect 键白名单和文档承诺的固定 ID 集合。

- 最小失败用例：重复 ID、错误 proto、未知 expect 键、错误字段键，必须在 suite 加载阶段报错。

## 2. 原子用例覆盖审查

### C-07：NON case Token/TKL 矛盾

`coap_non_post` 的 token 为 4 字节，但固定头 TKL=2。应改固定头为 TKL=4，或将 token 改为 2 字节。

### C-08：重传未验证完整字节相同

重传 case 只检查固定头、MID、Token、Type/Code，不检查 Options/Payload 全字节。

- 最小失败变异：只改第 3 次重传的 Uri-Path 或 payload，必须失败。

### C-09：多会话不是逐流原子验证

当前仅验证全局 Token/MID/端口集合，不能证明每个 tuple 的请求、响应和 token/MID 绑定。

### C-10：错误响应是综合 case

4.04、4.13、5.00 合并在一个六包 case，未验证请求路径到错误码的映射。

- 必须拆成三个独立 case，各自断言 path、Code、Type、MID、Token 和诊断 payload。

### C-11：Content-Format case 无法证明请求/响应独立

请求和响应都用 50，复制请求 option 的错误实现仍会通过。应使用不同值或明确省略其中一侧。

### C-12：关键关联断言缺失

- DELETE 未断言 Uri-Path；
- IPv6 case 缺响应 Type/MID/Token/反向端点；
- Observe 首 ACK 未断言 MID 回显；
- Block2 未证明方向，未检查块内容；
- Observe/错误序列使用 `min_packets`，额外错误流量可通过。

### C-13：未覆盖的独立原子逻辑

至少缺少：

- Block1 与 2.31 Continue；
- RST、空 ACK 与独立响应；
- TKL=0、TKL=8 和 token 长度不匹配；
- Option 扩展 13/14、保留 nibble=15、截断扩展、逆序 Option；
- 仅 Payload Marker；
- Block SZX=7、Block NUM 溢出；
- Observe 注销、序号回绕、错误终止；
- URI NUL、非法 UTF-8、组合长度边界；
- 每个负路径的独立错误文本和任务失败断言。

### C-14：错误文本契约过窄

文档允许 `token/TKL`、`uri/path` 替代文本，JSON 却只接受 `token` 和 `uri`，合法实现可能被误判失败。

- 最小失败用例：返回 `TKL exceeds maximum` 或 `path exceeds limit`，断言契约应明确允许集合或改为结构化错误码。

## 3. 修复闸门

CoAP 不能标记为完成，除非：

1. C-01 的实现/注册接线完成；
2. C-02~C-06 共享测试驱动缺口有失败测试和修复；
3. C-07~C-14 拆成不可再分的可执行 case；
4. 每个 confirmed finding 先补最小失败用例/断言；
5. 修复后代码逻辑和用例覆盖各重新审查至零 finding；
6. pcap 与 NIC 两种输出有真实可观察结果；
7. DTLS/TCP/TLS/IP 分片等明确非目标继续保持边界声明。

## 4. 审查记录

| 轮次 | 代码逻辑 | 用例覆盖 | 结果 |
|---|---|---|---|
| 1 | 注册、转换、MCP 链路扫描 | RFC/设计覆盖矩阵 | 发现阻断项 |
| 2 | 断言和错误传播复核 | 全 JSON 原子性复核 | 发现确认项 |
| 3 | 全链路待实现边界复核 | 全 JSON、共享断言逐条复核 | clean |
