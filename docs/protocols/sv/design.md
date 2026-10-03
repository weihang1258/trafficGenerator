# SV（IEC 61850-9-2）设计契约（文档轨）

> 版本：v1.1.0（2026-09-30）
> 范围：D1–D8；只描述当前 SV 实现、严格层链形状和已登记缺口，不改 Go 代码。
> 机器契约：`trafficgen/test/protocol_pcap/cases/sv.json`。
> 规范基线：IEC 61850-9-2；IEC 61850-8-1 Annex A；IEEE 802.1Q；ASN.1 BER；实现与落盘 pcap 是当前字节事实源。
> 实现位置：`trafficgen/internal/protocol/sv/sv.go`、`internal/core/layers/registry.go`、`internal/core/builder.go`。

## D1 范围、依据与边界

SV 是以太网二层组播采样值协议，不经过 IP、TCP 或 UDP。本文覆盖当前生成器实际支持的：EtherType `0x88ba`、目标组播 MAC、8 字节 SV 头、BER `savPdu`/ASDU、`int32`/`float32` 数据、可选 quality、`smpCnt` 回绕、`smpSynch`、`confRev`、`smpRate`、`datSet`、VLAN、双重发送和采样周期。

不宣称支持：R-SV/UDP、MMS 控制面、PTP 时钟实现、多 ASDU、加密签名、IP 分片或运行时订阅超时。当前没有 SV 会话/事务/关联数据流；每帧独立发布，§3 的会话编排要求对本协议不适用。

规范字段与现状矩阵：

| 规范/业务点 | 当前代码与行为 | cases | 结论 |
|---|---|---|---|
| L2 直承、EtherType 0x88ba | `sv.go` planner/builder | `sv_4i4v`, `sv_vlan` | 已实现 |
| APPID、Length、Reserve1/2 | BER/frame builder | `sv_smp_seq` | 已实现 |
| svID、smpCnt、confRev、smpSynch、smpRate | `SVConfig` 与 planner | `sv_smp_seq`, `sv_smp_synch_*` | 已实现 |
| 9-2LE 4I+4V 与自定义数据 | `data[]`, int32/float32 | `sv_4i4v`, `sv_custom_dataset` | 已实现 |
| VLAN 与双重发送 | layer config | `sv_vlan`, `sv_double_send` | 已实现 |
| R-SV/IP carrier | validator 拒绝 | `sv_neg_ip_carrier` | 明确不支持 |
| BER 长度/通道坏帧注入 | 当前 cases/harness 无坏帧注入口 | 无可执行正例 | C1 缺口 |

## D2 严格层链与配置权威

唯一目标形状是：

```json
{
  "layers": [
    {"eth": {"src_mac": "aa:bb:cc:dd:ee:03"}},
    {"sv": {
      "sv_id": "xxxxMUnn01",
      "appid": 16384,
      "conf_rev": 1,
      "samples_per_cycle": 4000,
      "smp_synch": 2,
      "smp_rate": 4000,
      "period_us": 250,
      "double_send": false,
      "vlan_enabled": false,
      "data": [{"name": "I_A", "type": "int32", "quality": 0}],
      "count": 3
    }}
  ]
}
```

链首必须是 `eth`，末层是 `sv`；不能出现 `ip`、`tcp`、`udp` 或其他承载层。地址/端口/MAC 等承载字段住对应层：SV 只有 `eth.src_mac`/SV 自身 `dst_mac`，没有 IP 或端口。策略级数量用外层 `strategy_fc: {"type":"flows","value":N}`；当前 SV 的 `sv.count` 是**单流帧预算**，不是流数量。

存量严格审计：30/30 `spec_json` 含 `layers`；17/17 正例无顶层协议字段；唯一顶层 `sv` 的 `sv_vn_presence` 是故意判死负例；`sv_vn_static_copy` 的 `strategy_fc` 是故意触发静态复制拒绝。没有 `src_ip`/`dst_ip`/`src_port`/`dst_port` 顶层残留。

当前 `registry.go` 仍把 `count` 注册在 `sv` 层，因此本轮不把它假装迁到 `flow_control`。迁移计划见 C2；在迁移完成前，文档与 cases 必须明确区分两种数量，禁止把 `count` 解释成 flows。

## D3 线格式、字段与偏移

Ethernet（14B）后可有 VLAN（4B），EtherType 为 `88 ba`。SV 头从 EtherType 后开始，固定 8B：APPID 2B、Length 2B（从 APPID 起计）、Reserve1 2B、Reserve2 2B。所有整数大端。

BER 结构和 tag：`60 savPdu`、`80 noASDU`、`a2 seqASDU`、`30 ASDU`、`80 svID`、`81 datSet`、`82 smpCnt`、`83 confRev`、`84 refrTm`、`85 smpSynch`、`86 smpRate`、`87 seqData`、`88 smpMod`。`seqData` 按 data 顺序编码；带 quality 时每项为 4B 值加 4B quality，float32 为 IEEE-754 单精度大端。

固定可观察约束：`frame.protocols` 为 `eth:ethertype:sv` 或带 VLAN 的 `eth:ethertype:vlan:ethertype:sv`；不存在 IP。APPID 当前合法区间 `0x4000..0x7fff`，confRev >=1，smpSynch 为 0/1/2，samples_per_cycle >=1，svID <=255 字节，数据类型仅 int32/float32。

## D4 状态、周期、数据和输出

每个 SV 配置独立从 `smpCnt=0` 开始，按样本递增，在 `samples_per_cycle` 前回到 0。`double_send=true` 时每个样本连续输出两帧且共享同一 smpCnt。`period_us` 驱动帧间隔；当前实现不提供跨会话控制面，也不维护服务端响应状态。

MAC 动态值由 `eth.src_mac` 的 fixed/inc/list/rand 策略计算，`strategy_fc` 展开独立流；cases 钉住 inc 回绕、list 轮转和 seed=7 rand。SV 业务字段没有逐流动态算法；静态业务字段配合多流会触发静态复制保护，而不是静默复制。

输出验收共用 cases：PCAP 通过 tshark 字段、raw frame offset 和包数校验；NIC 路径复用同一字段契约，需用 tcpdump 验证 0x88ba、组播 MAC、VLAN 和无 IP。当前文档轨只复核 JSON 结构和代码静态事实，未宣称重新跑 suite/NIC。

## D5 接口、数据结构与主流程

`SVConfig` 由层链转换为协议配置；planner 校验必填字段和范围，随后生成器按流/帧序列构造 `PacketConfig`：`eth` 负责 MAC/VLAN，SV 生成 payload，builder 写 `0x88ba` 和 BER APDU。入口保持现有 planner/generator 注册接口，不新增接口。

错误必须在 task 创建/生成前传播，不能以 completed/0 packet 伪装成功。负例锚词见 testcase T4。停止时由通用 pipeline 回收队列和 worker；SV 本身没有长连接资源。

## D6 规范、现网与方案取舍

| 选项 | 方案 A | 方案 B | 当前选择 |
|---|---|---|---|
| 承载 | L2 EtherType 0x88ba（IEC 61850-9-2/常见过程总线） | R-SV over UDP/IP | A；B 明确不支持 |
| 数据 | BER savPdu + seqData（libiec61850/Wireshark 兼容） | 自定义平铺 payload | A，保持可解析线格式 |
| 周期 | 每样本一帧，按 period_us | 聚合多 ASDU | A；多 ASDU 为缺口 |
| 多流 | strategy_fc + 动态 MAC | 静态复制 | A；静态复制拒绝 |

商业设备行为、版本和授权抓包没有进入本轮证据；不把未取证内容写成现网结论。规范字段逐项状态见 D1 矩阵，未实现项进入 C1–C6。

## D7 性能、资源与验收

生成必须流式逐帧处理，不聚合整个流；通用有界队列、ring buffer 和 worker 数约束继续适用。当前没有 SV 专项 benchmark，因此吞吐、并发、内存、队列积压、长跑和 NIC 丢包数字均为待确认，不写成承诺。实现后按六项补测：基线、目标规模、压力上限、长时间、并发交错、资源耗尽/背压；PCAP 与授权 NIC 各验一次。

## D8 错误、冲突、回滚与缺口

非法 APPID、confRev、周期、同步值、svID、data 缺失/类型和 IP carrier 由当前 validator 拒绝。当前设计与代码的已知差异不静默抹平：协议层 `count` 的迁移、BER 坏帧注入、多 ASDU 和 NIC/性能证据分别登记如下。

| 缺口 | 证据 | 计划 |
|---|---|---|
| C1 | Length/APDU 与 seqData 长度错误无法由 cases 注入 | 增加 wire-fault/坏帧入口，再补负例和 task-error 断言 |
| C2 | `sv.count` 仍是层内字段，流数量走 `strategy_fc` | 设计并实现 frame-budget 字段迁移；迁移前保留兼容拒绝/审计，不改语义 |
| C3 | SV 业务字段暂无五类动态策略整格 | 明确支持字段与序号算法后，补 fixed/inc/rand/list/pattern 逐格用例 |
| C4 | 多 ASDU、refrTm、smpMod/gmIdentity 无消费者 | 先补 schema/编码/校验，再补组合矩阵，不在现有 cases 冒充覆盖 |
| C5 | 本轮未跑 PCAP 全量和 NIC | 服务器与 HEAD 同代后全量 suite，再 tcpdump 复验 |
| C6 | 无六项 SV 性能基线 | 实现后按 D7 测吞吐、延迟、内存、CPU、积压、丢包/失败 |

回滚仅撤回后续 SV 实现/迁移提交，保留本契约和当前可执行 cases；本轮不改 Go 实现。

## 设计自审

自审两轮：第一轮逐项核对 D1–D8、严格 `[eth,sv]`、30 条 cases 与顶层键；第二轮复核 BER tag、长度/偏移、count 与 flows 边界及缺口声明。最后一轮干净。
