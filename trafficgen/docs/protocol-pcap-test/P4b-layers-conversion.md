# P4b: 用例文件层链写法转换规则

目标：16 个 JSON 用例文件（2057 用例）中 14 个协议文件转换为层链（layers）写法，
使 T15（全部用例经 ChainPlanner 驱动）全绿。srv6（legacy planner）与 probe_smb 不动。

## 转换规则（经探针验证）

1. **加 layers 数组**，保留全部 flat keys（flat keys 经 applySpecToChain 权威覆写层配置，
   探针 p1/p2 已验证字节一致）。层配置写空 `{}`——所有值来自 flat keys。

   | 协议 | layers 写法 |
   |------|-------------|
   | a2a dnp3 doip enip gbt32960 mcp modbus mqtt nfs smb tds | `[{"tcp":{}},{"<proto>":{}}]` |
   | tftp rip | `[{"udp":{}},{"<proto>":{}}]` |
   | tcp | `[{"tcp":{}}]` |

2. **负向用例（expect.expect_error=true）保持 flat 写法不动**——校验走 flat 范围校验，
   error_contains 断言的是 flat 错误消息。

3. **srv6.json / probe_smb.json 不动**（legacy planner / 探针文件）。

4. **包数调整**：
   - tcp：层链 = flat（探针验证 7=7）。
   - smb / a2a：legacy 挥手合并 3 包 → 层链标准 4 包，`packet_total = flat + 1`（探针 28→29）。
   - 其余协议：以 `CASE_PROTO=<proto>` 验证运行的实际包数为准；若仅包数不符且
     差值可由挥手 3→4 解释，按实际值修正；若 PDU 序列/字段断言也失败，说明
     转换本身有误，需查层生成器而非改断言。
   - 只改既有断言（packet_count/min_packets/teardown 区 packet 索引），不新增断言。

5. **验证循环**（每协议）：`cd trafficgen && CASE_PROTO=<proto> env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY PATH=/home/weihang/go/go/bin:$PATH go test -run TestProtocolPcapDrive ./test/protocol_pcap/ -v 2>&1 | tail -60`
   — 直到该协议全部用例 pass。服务已在跑（/tmp/tg-server，勿重启），
   pcap 落 /tmp/mcp-pcaps/<proto>/（按协议隔离，并行不冲突）。

## 分波

- 波 A（7 agent）：smb(279) modbus(213) tftp(226) nfs(201) a2a(185) mqtt(168) gbt32960(105)
- 波 B（7 agent）：enip(135) tds(131) doip(115) rip(71) dnp3(70) mcp(79) tcp(10)

每个 agent = 1 协议（用户纪律），完成后主线程逐个复查 + 全量 T15。
