# CWMP（TR-069）设计契约

> 版本：v2.3.0（现状对账）  日期：2026-10-01
> 状态：已落地登记；本文件与 `trafficgen/test/protocol_pcap/cases/cwmp.json` 的 153 条机器用例对账。本文只描述当前代码实际支持的范围，不把历史规划 ID 当成现状。

## 1. 范围与依赖

实现的是 CWMP SOAP 1.1 over HTTP/1.1 over TCP。层链唯一配置真相为：

```json
{"layers":[{"ip":{"src":"192.0.2.65","dst":"198.51.100.65"}},{"tcp":{"src_port":50065,"dst_port":7547}},{"http":{}},{"cwmp":{"sessions":[]}}]}
```

地址只在 `ip` 层，端口只在 `tcp` 层，HTTP 载体由 `http` 层承载，CWMP 业务只在 `cwmp` 层。顶层仅保留 `layers` 及通用结构性键；顶层 `cwmp` 子映射是专门的负例，不是兼容形状。

依赖链为 `ip → tcp → http → cwmp`。CWMP planner 依赖 HTTP 请求/响应交替、Inform 首事务、SOAP 1.1 envelope、响应 ID 关联及 Download/Upload 的显式流锚点。缺依赖或配置非法时返回 task error，不生成成功 PCAP 或仅外壳流。

规范依据：TR-069 Issue 1 Amendment 6 Corrigendum 1（§3.1–§3.7、Annex A、A.5），SOAP 1.1，RFC 7616，RFC 6265，RFC 7235。SOAP 1.2、HTTPS 解密语义、DU 软件管理及 QueuedTransfers 不在当前实现范围。

## 2. 数据结构与主流程（D-CWMP）

`CWMPConfig` 的业务字段为 `profile`、`namespace`、`concurrent`、`sessions`、`flows`、`auth`。地址和端口不复制到该结构的顶层；会话可带 role、URI、源端口、设备身份与有序 `transactions`。

每个 transaction 是一个事件，不是隐式模板：Inform、InformResponse、empty_post、empty_response、具名 ACS RPC 及其 response、Fault、TransferComplete、AutonomousTransferComplete、RequestDownload、Connection Request 三步均由序列显式声明。planner 先校验配置，再逐 session 校验方向/状态/ID/值域，最后校验 `flows[].driven_by`。

状态约束：

- CPE 会话首事务必须是 Inform；InformResponse 必须回带同一 ID。
- HTTP 请求与响应严格交替；空 POST/204 才结束正常 CWMP 会话。
- Inform 收 8005 Fault 时下一事务必须原样重发 Inform；Inform 收其他 Fault 时终止。
- 非 Inform Fault 是合法事件；Fault 不能响应另一个 response 或 Fault。
- TransferComplete 的 CommandKey 必须来自本会话或前会话已发出的 Download/Upload。
- ACS Connection Request 只能出现在 `role: acs_cr` 会话，成功后与 CPE 会话保持独立四元组。

具名 baseline 方法包括 Get/SetParameterValues、GetParameterNames、Get/SetParameterAttributes、AddObject、DeleteObject、FactoryReset、GetRPCMethods、Download、Upload、ScheduleDownload、ScheduleUpload、Reboot、Kicked。事件码校验覆盖实现子集 `0/1/2/3/4/5/6/7/8/9/10/M Download/M Reboot/M Upload/M ScheduleDownload`；EventStruct 上限 64，DeviceId OUI 必须为六位大写十六进制，相关字符串按规范上限校验。

## 3. 多会话与流关联

`sessions[]` 按块顺序回放；每个会话独立生命周期、ID 游标和四元组。`concurrent: true` 仅表示多个 CPE 会话可交错，不能改变单连接内的事务顺序。

`flows[]` 是 Download/Upload 的独立 HTTP GET/PUT 数据流。每条流必须有独立源端口、host、port 和 `driven_by{session,transaction,field}`；主事务完成后插入副连接，再继续主会话收尾。无锚点、越界 session 或不存在的 transaction 必须拒绝。

## 4. HTTP/SOAP 线格式与边界

SOAP envelope 固定为 SOAP 1.1；CWMP namespace 支持 `cwmp-1-0`、`cwmp-1-1`、`cwmp-1-2`。SOAP 事务使用 POST、`text/xml`、空 SOAPAction；空 HTTP 响应为 204。当前 planner 实际校验 HTTP method、SOAPAction、Content-Type、Content-Length override 和 envelope XML/namespace；Digest 仅校验 qop/algorithm 配置（auth、MD5/MD5-sess），Cookie、302/307、chunked 等不是当前 planner 的已实现线格式能力，不作为已实现承诺。

无 VLAN/IP/TCP options 时 IPv4 应用载荷偏移为 54，IPv6 为 74。TCP 分段不是 SOAP 边界；大 envelope 通过 Content-Length 和重组验证，禁止按未限定长度聚合分配。当前性能目标是流式生成、公共有界队列、每事务 payload 内存；目标规模与六类性能验收（基线、目标规模、压力、长时、并发、资源耗尽）需由 P5 真实 pcap/NIC 运行确认，未运行不宣称完成。

## 5. 错误处理矩阵（C-CWMP）

| 类别 | 代表输入 | 当前结果 |
|---|---|---|
| profile/namespace/carrier | 未知 profile、SOAP 1.2 namespace、TLS-only profile | task error，含 `profile`/`namespace`/`carrier` |
| HTTP wire | 非 POST、非 text/xml、非空 SOAPAction、长度覆盖、坏 XML | task error，含对应 wire 锚词 |
| session/state | 首事务非 Inform、空 POST 后续发事务、错误 role、无 pending | task error，含 `session`/`state`/`sequence` |
| correlation | ID 不匹配、孤立 CommandKey、坏 driven_by | task error，含 `correlation`/`command` |
| value/length | OUI、事件数组、FaultCode、FileType、参数名、CommandKey 越界 | task error，含 `value`/`length`/`parameter` |
| 合法协议事件 | 401、503、合法 Fault、Status=1、8005 重发、FileSize=0 | 正常按剧本生成，不误报配置错误 |

## 6. 当前缺口与明确边界

代码目前是声明式脚本回放，不模拟真实计时器、厂商扩展自动生成、TLS 解密或文件服务器认证。`ChangeDUState`、`GetQueuedTransfers`、`GetAllQueuedTransfers` 不列为当前 baseline；`cwmp_change_du_state_vc` 的实际覆盖是 VALUE CHANGE Inform，而不是 DU RPC。真实商业设备互操作、pcap/NIC 全量运行和吞吐/资源数字属于待 P5 验证项。

## 7. 对账结论

JSON 实测 153 条：110 条正例、43 条负例。所有正例的 `spec_json` 均为严格 `[ip,tcp,http,cwmp]` 层链；唯一带顶层 `cwmp` 的例为 `cwmp_pres_kill_neg`，专门验证顶层配置被拒。负例均使用 `expect_error` 与 `error_contains`，无“成功但 0 包”替代错误传播。

## 8. 审查记录

- 第一轮自审：按 `planner.go` 的 profile/namespace、HTTP 线格式、会话状态、Fault/CommandKey、`flows[].driven_by` 分支逐项回对；未发现设计声明超出当前实现的已实现范围。
- 第二轮自审：按机器 JSON 的 153 条 ID、110/43 分类、层链顶层键和负例错误传播契约复核；确认唯一顶层 `cwmp` 形状仅为 `cwmp_pres_kill_neg`，其余用例均为严格层链。pcap 与 NIC 复用同一 `spec_json`/expect 契约，尚未运行的真实输出验收仍归 P5 待验证边界。
