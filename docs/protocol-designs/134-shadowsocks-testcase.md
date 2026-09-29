# #134 Shadowsocks 测试用例契约

> 版本：v1.0（as-built，2026-09-29）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/shadowsocks.json`（唯一权威）  
> 配套设计：`134-shadowsocks-design.md`

## 1. 测试原则与形状基线

Shadowsocks 当前机器契约只有 **1 个正例、0 个负例**。该用例验证默认 TCP AEAD framing 的可观察结构：TCP 目的端口、32 B salt、34 B AEAD chunk、握手/终止。随机盐和模拟密文按设计不可作固定十六进制断言。

存量 JSON 的 `spec_json` 顶层键为 `{count,dst_port,shadowsocks}`，仍是 flat legacy 形；目标层链形应为 `{layers:[{tcp:...},{shadowsocks:...}]}`，迁移登记为 G-SS-1，本文不改机器契约。pcap/NIC 两种输出必须复用同一条 case 和断言集。

## 2. 原子用例索引（JSON 顺序权威）

| # | ID | 类型 | 场景/依据 | 包数 |
|---:|---|---|---|---:|
| 1 | `shadowsocks_default_tcp` | 正 | SIP003 TCP AEAD 结构；registry 默认端口；代码 `planner.go:441-550` | ≥9（实测结果文档记录 9） |

JSON 摘要原文：`smoke: shadowsocks TCP mode (aes-256-gcm) over port 8388; salt (32B) then one AEAD chunk (34B); encrypted stream is random, only structural assertions`。

## 3. 正例断言契约

### 3.1 `shadowsocks_default_tcp`

输入：

```json
{
  "count": 1,
  "dst_port": 8388,
  "shadowsocks": {}
}
```

期望：

- `min_packets=9`：TCP 三次握手 + salt + 一个 AEAD chunk + TCP 四次挥手。
- `negotiated=true`：TCP 连接握手存在。
- `terminates=true`：TCP FIN 终止存在。
- packet 1：`tcp.dstport=8388`。
- packet 4：`tcp.len=32`，对应默认 `aes-256-gcm` 的 32 B salt。
- packet 5：`tcp.len=34`，对应 `2 B encrypted length + 16 B length tag + 0 B payload + 16 B payload tag`。

实现依据：默认 cipher 为空时 `isAEADCipher` 按 AEAD 处理（`planner.go:121-128`）；salt 固定 32 B（`:483-493`）；没有显式 chunks、payload 或 chunk size 时 chunk size 为 0，但 AEAD framing 仍为 34 B（`:495-542`）；TCP 握手/挥手由 legacy planner 或链上的 TCP 层产生（`layer_gen.go:11-35`）。

## 4. 断言可观察性和随机性边界

本例只断言 `tcp.dstport` 和 `tcp.len`。盐、encrypted length、两个 tag 均随机或模拟随机；即使 `payload_bytes_format` 缺省产生随机 payload，也不应断言任何固定 byte sequence。当前 case 没有 tshark Shadowsocks dissector 依赖，TCP payload 长度是稳定观察面。

`min_packets` 而非精确 `packet_count` 是存量 JSON 机器契约；历史结果文档记录实际 9 包。任何迁移不得擅自把 `min_packets` 放宽或删除，应先以生成器实测重新钉定。

## 5. 负例契约与缺口

当前 JSON 没有 `expect_error` 用例，因此 validator 负路径尚未形成机器契约。覆盖审查要求至少补齐：缺 Shadowsocks 配置、非法 cipher、非法 mode、链上 UDP、HTTP/SOCKS5 互斥、MSS 小于 536、chunk 大于 16383、password 缺失、password/domain 超长、UDP ASSOCIATE/TCP 不合、SOCKS5 目标端口为零。每条负例执行期只能包含 `expect_error` 与 `error_contains`，并验证 task error 传播和零成功 PCAP。

## 6. 五层覆盖审计

| 层 | 当前覆盖 | 缺口 |
|---|---|---|
| 功能 | 默认 TCP AEAD salt/chunk、握手、终止 | SOCKS5 none/password、HTTP obfuscation、cipher none、chunk loop、UDP legacy |
| 性能 | 最小默认 chunk 34 B；TCP 连接 9 包 | 16383 上限、MSS 跨段、大 payload、多流 |
| 数据 | 默认 cipher、随机结构字节 | zeros、none、三类 2022 cipher、payload 分割、边界字段 |
| 地址与流 | 单 IPv4 TCP 流、8388 | IPv6、非默认端口、SOCKS5 IPv4/IPv6/domain；多流 |
| 业务 | raw AEAD 单连接 | SOCKS5 代理协商、HTTP 外观、UDP relay、多会话 |

不适用/待实现：协议层无父子流关联、transaction ID、应用 keep-alive、真实加密验证；这些不能用一条默认 smoke case 冒充覆盖。

## 7. 存量用例审计

| ID | 去向 | 理由/动作 |
|---|---|---|
| `shadowsocks_default_tcp` | **保留，改写形状** | 行为断言与默认实现一致；将 `count/dst_port/shadowsocks` 迁到 `[tcp,shadowsocks]` layer chain 后重跑并重新钉包数。 |

## 8. 缺口登记

| ID | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-SS-1 | 顶层 flat spec 未迁层链 | `cases/shadowsocks.json:6-10` | P4 配置收敛 |
| G-SS-2 | 只有 1 个默认正例，无负例 | cases JSON 仅 1 object | P4 用例扩展 |
| G-SS-3 | 结果文档早于 0417be5，且 pcap 未作为今日证据 | tracked `trafficgen/docs/protocol-pcap-test/shadowsocks.md`，末次 2026-08-27 | P5 复跑 |
| G-SS-4 | UDP legacy 不能通过当前 TCP layer chain | `layer_gen.go:202-207` | P4/P5 载体决策 |
| G-SS-5 | 协议关键字段没有 fixed/inc/rand/list/pattern 逐流策略 | `strategy_convert.go:5249-5276` | P4 动态字段 |
| G-SS-6 | 随机读取错误未上抛；无真实 AEAD 验证 | `planner.go:117,490,686-706` | P4 实现边界 |

## 9. 覆盖反查门建议断言行

1. `spec_json` 顶层只含 `layers`，层序为 `tcp → shadowsocks`；禁止 flat `count/dst_port/shadowsocks`。
2. 默认 case 的第一个 TCP 数据前 salt payload 长度为 32 B，随后 AEAD chunk payload 长度为 34 B。
3. `tcp.dstport=8388`；握手存在；FIN 终止存在；至少 9 包。
4. 加密 payload 只做长度断言，不作固定 hex 断言。
5. `ChunkPayloadSize=16383` 接受、`16384` 拒绝并命中 `exceeds max`。
6. `Mode=udp` layer chain 拒绝且 task 不得以 0 包 completed 假成功。
7. SOCKS5 password 缺 username/password、长度 256、目标端口 0 各命中对应锚词。
8. HTTP obfuscation 与 SOCKS5 同启拒绝；HTTP + UDP 拒绝。
9. IPv4/IPv6 与非默认端口各有可观察 case；pcap/NIC 共用断言。
10. 过期 `shadowsocks.md` 不作为今日复跑通过证据。

## 10. 结果产物核验

`trafficgen/docs/protocol-pcap-test/shadowsocks.md` tracked，记录 1/1 pass、9 包、pcap 链接，但最后提交为 2026-08-27，早于 `0417be5`（2026-09-13）。当前文档轨未运行套件，不把该产物写成今日复跑结论；登记 G-SS-3。

## 11. 修订记录与自审

- v1.0（2026-09-29）：按实现、cases JSON、registry、strategy parser 和旧结果产物建立 as-built 测试契约；未改代码或 cases。
- 自审第 1 轮：逐条复核 JSON ID、输入键、断言值、包数构成与实现路径。
- 自审第 2 轮：复核五层、门1 缺口、负例纯净性、过期产物和 coverage gate 建议；末轮干净。

**自审 2 轮，末轮干净。**
