# HDS（Adobe HTTP Dynamic Streaming，Adobe HTTP 动态流）测试用例契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/47-hds-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/hds.json`
> 状态：`hds` 尚未注册；本文定义实现后的 PCAP（抓包文件）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计文档 §2–§10 逐项派生，共 18 个唯一 ID：13 个目标正例、5 个目标负例。设计期三方 ID、顺序和覆盖必须一致；但当前 JSON **只**保留 `hds_neg_unregistered` 一个占位，因为 `hds` 层尚未在层注册表中注册。占位必须 `expect_error=true` 且 `error_contains="unknown layer"`；不能用 0 包或空 PCAP 冒充 HDS 语义验证。其余 17 个 ID 只写在本文和设计文档，注册后再加入 JSON。

HDS 是 HTTP/TCP 应用层。无 VLAN、IP options、TCP options 时，IPv4 HTTP payload 起点为 offset（偏移）54（Ethernet 14 + IPv4 20 + TCP 20），IPv6 为 74（14 + IPv6 40 + TCP 20）。TCP MSS 分段必须先重组 HTTP，再按 Content-Length 划分 F4M/bootstrap/F4F body；不能把 TCP packet（数据包）边界当作应用消息边界。正例实现后应有 `packet_count` 或 `min_packets`、已注册 `fields` 和稳定 `frames`；负例只允许 `expect_error` 与 `error_contains`。

动态数据（HTTP Date、transaction/session ID、随机地址或未固定的 Base64）不得写死在 `frames.hex`。可复现 fixture 应显式固定 XML、timescale、segment/fragment 编号和 box bytes；否则用 `nonzero`、跨包 `same_as_packet` 或字段关系断言。

## 2. 机器配置示例（实现后目标）

```json
{
  "layers": [{"tcp": {}}, {"http": {}}, {"hds": {}}],
  "src_ip": "192.0.2.47",
  "dst_ip": "198.51.100.47",
  "src_port": 41000,
  "dst_port": 80,
  "hds": {
    "method": "GET",
    "version": "HTTP/1.1",
    "keep_alive": true,
    "manifest": {
      "id": "channel-1",
      "stream_type": "live",
      "uri": "/live/channel.f4m",
      "media": [{"stream_id": "main", "href": "channel", "bitrate": 800, "bootstrap_info_id": "b0", "fragments": [{"segment": 1, "fragment": 1, "timestamp": 0, "duration": 2000, "body": "AAAA"}]}],
      "bootstrap_infos": [{"id": "b0", "profile": "named", "base64": "..."}]
    }
  }
}
```

该块是设计期配置，不是当前可执行正例。`body`/`base64` 在实际 schema（模式）中应使用明确的 bytes/base64 表示，不能把省略号当作合法线上数据。

## 3. 原子用例索引

| # | ID | 类型 | 覆盖 | 实现后断言重点 |
|---:|---|---|---|---|
| 1 | `hds_manifest_ipv4` | 正 | IPv4/TCP/HTTP、F4M manifest | GET URI、200、Content-Type、XML namespace、media/bitrate |
| 2 | `hds_bootstrap_abst` | 正 | inline bootstrap、abst | Base64 解码、box size/type、version、timescale |
| 3 | `hds_asrt_segment_runs` | 正 | asrt segment run | segment 起点、fragments-per-segment、单调性 |
| 4 | `hds_afrt_fragment_runs` | 正 | afrt fragment run | firstFragment、timestamp、duration、discontinuity |
| 5 | `hds_fragment_f4f` | 正 | F4F fragment body | URI 编号、box size/type、mdat payload |
| 6 | `hds_manifest_bootstrap_fragment` | 正 | 三阶段状态机 | manifest→bootstrap→fragment 顺序和关联 |
| 7 | `hds_keepalive_fragments` | 正 | keep-alive 多请求 | 同连接第二个 fragment、独立 Content-Length/响应边界 |
| 8 | `hds_multi_session` | 正 | 多会话隔离 | 两个 4-tuple、run table/timestamp 不串用 |
| 9 | `hds_ipv6` | 正 | IPv6 HTTP/TCP | `ipv6.nxt=6`、应用 bytes 与 IPv4 相同 |
| 10 | `hds_mss_reassembly` | 正 | MSS 跨段重组 | HTTP/F4M/F4F 跨 TCP segment 后内容完整 |
| 11 | `hds_live_update` | 正 | live bootstrap 更新 | asrt/afrt 单调更新、无 timestamp 回退 |
| 12 | `hds_vod_end` | 正 | recorded/VOD 生命周期 | 最后 fragment 后 FIN，无新资源 |
| 13 | `hds_boundary_box` | 正 | size/长度边界 | 最小合法 box、明确可分配上界、size 含 8B header |
| 14 | `hds_neg_manifest` | 负 | XML/manifest malformed | 空、缺 root/namespace/media、截断；`manifest`/`xml` |
| 15 | `hds_neg_bootstrap` | 负 | bootstrap malformed | Base64、box、count、timescale、run 错误；`bootstrap`/`run` |
| 16 | `hds_neg_fragment` | 负 | F4F malformed | box/payload/length/sequence/timestamp 截断；`fragment`/`f4f` |
| 17 | `hds_neg_session_state` | 负 | 状态/引用错误 | 跨 session、keep-alive 回退；`session` |
| 18 | `hds_neg_unregistered` | 负 | 当前层注册前置 | `expect_error=true`、`error_contains=unknown layer` |

## 4. 正例契约（实现后）

1. **`hds_manifest_ipv4`**：一个 IPv4/TCP session，GET `/live/channel.f4m`，响应 200、`Content-Type: application/f4m+xml`，body 以 XML 声明和 `<manifest xmlns="http://ns.adobe.com/f4m/1.0">` 开始，含唯一 id、`streamType=live`、一个 media 和 bootstrapInfo。断言 HTTP method/URI/status、namespace、streamId、正 bitrate 和 bootstrapInfoId；frame offset 54 只固定稳定 XML 前缀。
2. **`hds_bootstrap_abst`**：manifest 的 inline Base64 解码后是 `abst` 根 box，断言 size 包含 8-byte box header、type=`abst`、version=0、timescale>0、box 未越界；不能把 Base64 文本自身当 bootstrap binary。
3. **`hds_asrt_segment_runs`**：bootstrap 含 `asrt`，至少两项递增 segment run；断言 quality count、firstSegment、fragmentsPerSegment 与剩余长度一致，拒绝重叠/回退。frames 固定 `size + asrt` 和可复算的首项，不固定动态 XML。
4. **`hds_afrt_fragment_runs`**：bootstrap 含与 timescale 一致的 `afrt`，两个 fragment run timestamp 单调，duration 非零；另有仅在 `fragmentDuration=0` 时携带 `discontinuityIndicator` 的显式不连续边界项。计数使用 UI32，普通非零 duration 条目不得额外插入 indicator。
5. **`hds_fragment_f4f`**：按 run table 请求 `Seg1-Frag1`，HTTP 200、`video/f4f` 或声明的二进制类型；body 至少含合法 fragment metadata 和 `mdat`，size 覆盖 8-byte header 与 payload。断言 URI 编号、box type/size、非空 payload 和 timestamp/sequence 关联。
6. **`hds_manifest_bootstrap_fragment`**：同一 session 依次完成 manifest GET、bootstrap GET/inline 解析、fragment GET；断言 request 先于 response、bootstrapInfoId 关联、fragment 编号来自 run table。不能只验证三条孤立 HTTP 请求。
7. **`hds_keepalive_fragments`**：`Connection: keep-alive` 的单 TCP session 中连续获取 Frag1、Frag2；断言两个 request/response 顺序、各自 Content-Length/body 边界和 fragment timestamp 单调；第二个 response 不能复用第一个长度。
8. **`hds_multi_session`**：至少两个不同源端口或地址的 session，各有 manifest/bootstrap/run table；断言 4-tuple distinct、streamId/timestamp/quality 独立，不假设调度交织顺序。
9. **`hds_ipv6`**：IPv6 TCP/HTTP manifest 或 fragment session，断言 `ipv6.nxt=6`、地址族和 offset 74；相同 fixture 的 XML/box bytes 不因 IPv6 改变。
10. **`hds_mss_reassembly`**：设置小于 HTTP/F4F body 的 MSS，使 header、XML 或 box 跨多个 TCP payload；重组后断言完整 Content-Length、F4M XML、box size 和 mdat bytes，不能按单包解析。
11. **`hds_live_update`**：live bootstrap 的第二次 update 追加更大的 segment/fragment 编号；断言 asrt/afrt 表单调扩展、timestamp 不回退，且 `refresh_count`/时间上限有界，不生成无限流。
12. **`hds_vod_end`**：`streamType=recorded` 的有限 fragment 序列，最后响应后 TCP FIN；断言无新的 segment/fragment GET，终态不是静默 completed/0 packet。
13. **`hds_boundary_box`**：使用最小合法 box 和明确可分配的较大 payload；断言 size=8+payload、UI32 不溢出、相邻 box 无不可解释尾字节。不要求默认分配 `0xffffffff` 字节。

## 5. 负例契约

实现注册后，前 4 个目标负例必须由 planner/validator 传播为 task error；当前唯一 JSON 条目仍是注册前置占位。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `hds_neg_manifest` | 空 body、缺 `manifest` root/namespace/media、非法 XML、Content-Length/UTF-8 截断 | `manifest` 或 `xml` |
| `hds_neg_bootstrap` | Base64 失败、abst/asrt/afrt size 越界、count/box type/timescale/run 非法 | `bootstrap` 或 `run` |
| `hds_neg_fragment` | F4F box 小于 8B、size 越界、mdat/payload 截断、编号/timestamp 不匹配 | `fragment` 或 `f4f` |
| `hds_neg_session_state` | 跨 session 引用 bootstrap/fragment、keep-alive 状态回退或 TCP 缺失 | `session` |
| `hds_neg_unregistered` | `proto=hds`/`layers` 含未注册 hds | **`unknown layer`** |

负例 `expect` 不得带 packet_count、fields、frames、has_payload 或“空 PCAP 通过”说明。合法 HTTP 404/410 是未来应用事件正例，不等于 planner Validate（校验）失败。

## 6. 三方静态检查

1. 设计 §10、本文 §3、JSON（当前仅占位）中的 ID 拼写和顺序一致；完整契约集合为 18 项，当前机器集合为第 18 项的单项子集。
2. 运行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/hds.json`；检查其唯一 entry 的 `proto` 为 `hds`、`expect_error` 为 true、`error_contains` 精确为 `unknown layer`。
3. 未注册阶段不要求 17 个未放入 JSON 的 ID 出现在套件；注册后必须按本文顺序补齐 13 正例/4 语义负例，并同步设计文档。
4. 正例字段必须来自 `tshark -G fields` 的实际 HTTP/IP/TCP/IPv6 字段；F4M、bootstrap、F4F 未有稳定 dissector（解析器）字段时用重组后的 `frames` 字节，不伪造 `hds.*` 字段。
5. offset 只在无 options 的固定 fixture 中使用 54/74；MSS、多 TCP 包、keep-alive 和多 session 用 stream 语义、方向、端口 distinct 或 `same_as_packet` 验证。
6. box size、string length、run count、Content-Length、mdat payload 均按字段实际长度复算；禁止只断言对象存在或 task completed。

## 7. ID 顺序单一来源

```text
hds_manifest_ipv4
hds_bootstrap_abst
hds_asrt_segment_runs
hds_afrt_fragment_runs
hds_fragment_f4f
hds_manifest_bootstrap_fragment
hds_keepalive_fragments
hds_multi_session
hds_ipv6
hds_mss_reassembly
hds_live_update
hds_vod_end
hds_boundary_box
hds_neg_manifest
hds_neg_bootstrap
hds_neg_fragment
hds_neg_session_state
hds_neg_unregistered
```

## 8. 修订记录

- v1.0.0（2026-08-20）：建立 13 个 HDS 目标正例和 5 个负例契约，覆盖 F4M、abst/asrt/afrt、F4F、HTTP/TCP、状态机、keep-alive、IPv4/IPv6、多会话、MSS 重组、边界和错误传播；当前 JSON 仅保留 `unknown layer` 占位。
