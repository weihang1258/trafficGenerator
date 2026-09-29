# 协议扩展实现设计文档归档索引

**生成时间**：2026-08-03
**更新日期**：2026-08-25（补充 HTTP-FLV、AMQP 已完成实现）
**对照规范**：9.4.1.38 协议扩展信息上报（32 个扩展协议表）及 `docs/protocol-designs/00-unimplemented-list.md`
**项目已实现协议数**：68 个（见 `internal/protocol/` 目录，`cmd/server/main.go:354-420` 注册；19–77 号为待实现设计契约，不代表 Go 层已注册）
**本次未实现协议数**：71 项（其中 64 项为完整实现范围，7 项为半实现/组合边界）
**本次归档文档总数**：1 个清单 + 134 个设计/用例文档 + 94 个审计文件 = 229 份（审计文件含历史修订版）

---

## 一、文档总览

| 类别 | 文件数 | 总行数 | 说明 |
|------|--------|--------|------|
| 未实现清单 | 1 | 94 | 72 个未实现协议/边界分类与优先级 |
| 设计文档 | 75 | 54,253 | 1–18 既有设计 + 19–77 协议实现方案 |
| 用例文档 | 59 | 10,871 | 19–77 协议对应的测试契约 |
| 审计文档 | 94 | 37,535 | 历史及交叉对抗审计报告（含修订版） |
| **合计** | **229** | **102,753** | 1 清单 + 75 设计 + 59 用例 + 94 审计 |

---

## 二、未实现协议清单

| 文件 | 内容 |
|------|------|
| [`00-unimplemented-list.md`](00-unimplemented-list.md) | 17 个未实现协议按业务领域分组（车联网 5 + 文件传输 3 + 数据库 1 + 路由 1 + 工控 3 + 物联网 1 + 网络 1 + Agent 2），含优先级建议（P0/P1/P2） |
| [`protocol-doc-requirements.md`](protocol-doc-requirements.md) | 协议设计/用例文档需求文档（v1，2026-08-31）：B6 起每协议两份独立文档、规范依据、三向对抗审查、五层覆盖（功能/性能/数据/地址与流/业务）、统一术语表（事件编排会话/多会话展开/流关联/事务）、每协议六步工作法、B6 开工顺序 |

---

## 三、设计文档索引

### 3.1 车联网协议（5 个，2 份文档）

| 文件 | 协议 | 行数 | 测试用例数 | 说明 |
|------|------|------|-----------|------|
| [`01-gbt32960-design.md`](01-gbt32960-design.md) | GBT32960 | 1523 | 89 | GB/T 32960-2016 电动汽车车载终端，TCP 10020 |
| [`02-03-04-jt808-jt809-jtt905-design.md`](02-03-04-jt808-jt809-jtt905-design.md) | JT808 + JT809 + JTT905 | 2123 | 120 | JT/T 808-2019 + JT/T 809-2019 + JT/T 905-2014，三协议合并文档 |

### 3.2 文件传输/共享（3 个，3 份文档）

| 文件 | 协议 | 行数 | 测试用例数 | 说明 |
|------|------|------|-----------|------|
| [`06-tftp-design.md`](06-tftp-design.md) | TFTP | 1329 | 60 | RFC 1350/2347-2349，UDP 69 |
| [`07-smb-design.md`](07-smb-design.md) | SMB | 1581 | 60 | MS-SMB2，TCP 445 |
| [`08-nfs-design.md`](08-nfs-design.md) | NFS | 1717 | 82 | RFC 7530 (v4) / RFC 1813 (v3)，TCP/UDP 2049 |

### 3.3 数据库（1 个）

| 文件 | 协议 | 行数 | 测试用例数 | 说明 |
|------|------|------|-----------|------|
| [`09-tds-design.md`](09-tds-design.md) | TDS | 1835 | 314 | MS-TDS，SQL Server，TCP 1433 |

### 3.4 路由（1 个）

| 文件 | 协议 | 行数 | 测试用例数 | 说明 |
|------|------|------|-----------|------|
| [`10-rip-design.md`](10-rip-design.md) | RIP | 965 | 48 | RFC 2453 (v2) / RFC 1058 (v1)，UDP 520 |

### 3.5 工控（3 个，3 份文档）

| 文件 | 协议 | 行数 | 测试用例数 | 说明 |
|------|------|------|-----------|------|
| [`11-dnp3-design.md`](11-dnp3-design.md) | DNP3 | 1635 | 38 | IEEE 1815-2012，TCP/UDP 20000 |
| [`12-enip-design.md`](12-enip-design.md) | ENIP | 1078 | 40 | ODVA EtherNet/IP，TCP+UDP 44818 |
| [`13-modbus-design.md`](13-modbus-design.md) | MODBUS | 1188 | 50 | Modbus.org / RFC 7540，TCP 502 |

### 3.6 物联网（1 个）

| 文件 | 协议 | 行数 | 测试用例数 | 说明 |
|------|------|------|-----------|------|
| [`14-mqtt-design.md`](14-mqtt-design.md) | MQTT | 1760 | 85 | MQTT v3.1.1 / v5.0，TCP 1883 |

### 3.7 网络（1 个）

| 文件 | 协议 | 行数 | 测试用例数 | 说明 |
|------|------|------|-----------|------|
| [`15-srv6-design.md`](15-srv6-design.md) | SRV6 | 810 | 106 | RFC 8754，IPv6 扩展头 |

### 3.8 Agent 协议（2 个，2 份文档）

| 文件 | 协议 | 行数 | 测试用例数 | 说明 |
|------|------|------|-----------|------|
| [`16-mcp-design.md`](16-mcp-design.md) | MCP（流量协议） | 1755 | 60 | Model Context Protocol spec，HTTP/SSE/stdio 8081 |
| [`17-a2a-design.md`](17-a2a-design.md) | A2A | 1612 | 63 | Agent2Agent spec，HTTP |

### 3.9 配置架构（1 份文档）

| 文件 | 内容 | 行数 | 说明 |
|------|------|------|------|
| [`18-layer-config-design.md`](18-layer-config-design.md) | 方案 C 分层配置架构 | 752 | 层链 + schema + 自动补全 + 递归生成 + 校验 + 迁移（v1.3.0，2026-08-11） |

## 3.10 路由/组播/信令扩展协议（9 个，18 份文档）

| 编号 | 设计与用例 | 协议 | 用例数 | 对抗审计 |
|------|------------|------|--------|----------|
| 36 | [`36-bgp-design.md`](36-bgp-design.md) / [`36-bgp-testcase.md`](36-bgp-testcase.md) | BGP（边界网关协议，RFC 4271） | 19 | [`audit/36-bgp-adversarial-audit.md`](audit/36-bgp-adversarial-audit.md) |
| 37 | [`37-ospf-design.md`](37-ospf-design.md) / [`37-ospf-testcase.md`](37-ospf-testcase.md) | OSPF（开放最短路径优先，RFC 2328） | 20 | [`audit/37-ospf-adversarial-audit.md`](audit/37-ospf-adversarial-audit.md) |
| 38 | [`38-isis-design.md`](38-isis-design.md) / [`38-isis-testcase.md`](38-isis-testcase.md) | ISIS（中间系统到中间系统，ISO 10589） | 25 | [`audit/38-isis-adversarial-audit.md`](audit/38-isis-adversarial-audit.md) |
| 39 | [`39-igmp-design.md`](39-igmp-design.md) / [`39-igmp-testcase.md`](39-igmp-testcase.md) | IGMP（因特网组管理协议，RFC 1112/2236/3376） | 25 | [`audit/39-igmp-adversarial-audit.md`](audit/39-igmp-adversarial-audit.md) |
| 40 | [`40-pim-design.md`](40-pim-design.md) / [`40-pim-testcase.md`](40-pim-testcase.md) | PIM（协议无关组播，RFC 7761） | 24 | [`audit/40-pim-adversarial-audit.md`](audit/40-pim-adversarial-audit.md) |
| 41 | [`41-ldp-design.md`](41-ldp-design.md) / [`41-ldp-testcase.md`](41-ldp-testcase.md) | LDP（标签分发协议，RFC 5036） | 25 | [`audit/41-ldp-adversarial-audit.md`](audit/41-ldp-adversarial-audit.md) |
| 42 | [`42-pcep-design.md`](42-pcep-design.md) / [`42-pcep-testcase.md`](42-pcep-testcase.md) | PCEP（路径计算元素通信协议，RFC 5440） | 24 | [`audit/42-pcep-adversarial-audit.md`](audit/42-pcep-adversarial-audit.md) |
| 43 | [`43-cflow-design.md`](43-cflow-design.md) / [`43-cflow-testcase.md`](43-cflow-testcase.md) | cflow（NetFlow v9/IPFIX，RFC 3954/7011） | 22 | [`audit/43-cflow-adversarial-audit.md`](audit/43-cflow-adversarial-audit.md) |
| 44 | [`44-stun-design.md`](44-stun-design.md) / [`44-stun-testcase.md`](44-stun-testcase.md) | STUN（NAT 会话穿越工具，RFC 5389/8489） | 24 | [`audit/44-stun-adversarial-audit.md`](audit/44-stun-adversarial-audit.md) |

### 3.11 工控/数据库扩展协议（17 个，34 份文档）

| 编号 | 设计与用例 | 协议 | 用例数 | 对抗审计 |
|------|------------|------|--------|----------|
| 19 | [`19-fins-design.md`](19-fins-design.md) / [`19-fins-testcase.md`](19-fins-testcase.md) | FINS（欧姆龙 PLC 通信） | 14 | [`audit/19-fins-adversarial-audit.md`](audit/19-fins-adversarial-audit.md) |
| 20 | [`20-coap-design.md`](20-coap-design.md) / [`20-coap-testcase.md`](20-coap-testcase.md) | CoAP（受约束应用协议，RFC 7252） | 16 | [`audit/20-coap-adversarial-audit.md`](audit/20-coap-adversarial-audit.md) |
| 21 | [`21-s7-design.md`](21-s7-design.md) / [`21-s7-testcase.md`](21-s7-testcase.md) | S7（西门子 S7comm） | 14 | [`audit/21-s7-adversarial-audit.md`](audit/21-s7-adversarial-audit.md) |
| 22 | [`22-iec104-design.md`](22-iec104-design.md) / [`22-iec104-testcase.md`](22-iec104-testcase.md) | IEC104（IEC 60870-5-104） | 16 | [`audit/22-iec104-adversarial-audit.md`](audit/22-iec104-adversarial-audit.md) |
| 23 | [`23-goose-design.md`](23-goose-design.md) / [`23-goose-testcase.md`](23-goose-testcase.md) | GOOSE（IEC 61850 快速事件报文） | 12 | [`audit/23-goose-adversarial-audit.md`](audit/23-goose-adversarial-audit.md) |
| 24 | [`24-sv-design.md`](24-sv-design.md) / [`24-sv-testcase.md`](24-sv-testcase.md) | SV（IEC 61850 采样值） | 12 | [`audit/24-sv-adversarial-audit.md`](audit/24-sv-adversarial-audit.md) |
| 25 | [`25-opcua-design.md`](25-opcua-design.md) / [`25-opcua-testcase.md`](25-opcua-testcase.md) | OPC UA（工业互操作） | 12 | [`audit/25-opcua-adversarial-audit.md`](audit/25-opcua-adversarial-audit.md) |
| 26 | [`26-mms-design.md`](26-mms-design.md) / [`26-mms-testcase.md`](26-mms-testcase.md) | MMS（制造报文规范） | 11 | [`audit/26-mms-adversarial-audit.md`](audit/26-mms-adversarial-audit.md) |
| 27 | [`27-moxa-design.md`](27-moxa-design.md) / [`27-moxa-testcase.md`](27-moxa-testcase.md) | Moxa-Nport（串口服务器协议） | 13 | [`audit/27-moxa-adversarial-audit.md`](audit/27-moxa-adversarial-audit.md) |
| 28 | [`28-someip-design.md`](28-someip-design.md) / [`28-someip-testcase.md`](28-someip-testcase.md) | SOME/IP（车载服务中间件） | 16 | [`audit/28-someip-adversarial-audit.md`](audit/28-someip-adversarial-audit.md) |
| 29 | [`29-drda-design.md`](29-drda-design.md) / [`29-drda-testcase.md`](29-drda-testcase.md) | DRDA（DB2 分布式关系数据库架构） | 10 | [`audit/29-drda-adversarial-audit.md`](audit/29-drda-adversarial-audit.md) |
| 30 | [`30-thrift-design.md`](30-thrift-design.md) / [`30-thrift-testcase.md`](30-thrift-testcase.md) | Thrift（跨语言 RPC 框架） | 13 | [`audit/30-thrift-adversarial-audit.md`](audit/30-thrift-adversarial-audit.md) |
| 31 | [`31-tns-design.md`](31-tns-design.md) / [`31-tns-testcase.md`](31-tns-testcase.md) | TNS（Oracle SQL*Net） | 12 | [`audit/31-tns-adversarial-audit.md`](audit/31-tns-adversarial-audit.md) |
| 32 | [`32-mongodb-design.md`](32-mongodb-design.md) / [`32-mongodb-testcase.md`](32-mongodb-testcase.md) | MongoDB wire protocol | 13 | [`audit/32-mongodb-adversarial-audit.md`](audit/32-mongodb-adversarial-audit.md) |
| 33 | [`33-dameng-design.md`](33-dameng-design.md) / [`33-dameng-testcase.md`](33-dameng-testcase.md) | Dameng（达梦数据库） | 14 | [`audit/33-dameng-adversarial-audit.md`](audit/33-dameng-adversarial-audit.md) |
| 34 | [`34-kingbase-design.md`](34-kingbase-design.md) / [`34-kingbase-testcase.md`](34-kingbase-testcase.md) | KingBase（人大金仓数据库） | 15 | [`audit/34-kingbase-adversarial-audit.md`](audit/34-kingbase-adversarial-audit.md) |
| 35 | [`35-cql-design.md`](35-cql-design.md) / [`35-cql-testcase.md`](35-cql-testcase.md) | CQL（Cassandra 查询语言协议） | 17 | [`audit/35-cql-adversarial-audit.md`](audit/35-cql-adversarial-audit.md) |

### 3.12 流媒体/实时消息扩展协议（33 个，66 份文档）

| 编号 | 设计与用例 | 协议 | 用例数 | 对抗审计 |
|------|------------|------|--------|----------|
| 45 | [`45-http-flv-design.md`](45-http-flv-design.md) / [`45-http-flv-testcase.md`](45-http-flv-testcase.md) | HTTP-FLV（HTTP 传输的 Flash 视频流） | 15 | ✅ 已实现（15/15 pcap 通过） |
| 46 | [`46-hls-design.md`](46-hls-design.md) / [`46-hls-testcase.md`](46-hls-testcase.md) | HLS（HTTP 直播流，RFC 8216） | 24（契约） | ✅ 已实现（24/24 pcap 通过） |
| 47 | [`47-hds-design.md`](47-hds-design.md) / [`47-hds-testcase.md`](47-hds-testcase.md) | HDS（Adobe HTTP 动态流） | 18（契约） | 待审计 |
| 48 | [`48-rtmfp-design.md`](48-rtmfp-design.md) / [`48-rtmfp-testcase.md`](48-rtmfp-testcase.md) | RTMFP（实时消息传输协议） | 24（契约） | ✅ 已实现（24/24 pcap 通过） |
| 49 | [`49-amqp-design.md`](49-amqp-design.md) / [`49-amqp-testcase.md`](49-amqp-testcase.md) | AMQP（高级消息队列协议，AMQP 0-9-1） | 20（契约） | ✅ 已实现（20/20 pcap 通过） |
| 50 | [`50-openwire-design.md`](50-openwire-design.md) / [`50-openwire-testcase.md`](50-openwire-testcase.md) | OpenWire（ActiveMQ 原生线协议） | 24（契约） | 待审计 |
| 51 | [`51-ams-design.md`](51-ams-design.md) / [`51-ams-testcase.md`](51-ams-testcase.md) | AMS（Apache ActiveMQ 管理协议） | 20（契约） | 待审计 |
| 52 | [`52-swarm-design.md`](52-swarm-design.md) / [`52-swarm-testcase.md`](52-swarm-testcase.md) | Swarm（去中心化 P2P 存储协议） | 20（契约） | 待审计 |
| 53 | [`53-gnutella-design.md`](53-gnutella-design.md) / [`53-gnutella-testcase.md`](53-gnutella-testcase.md) | Gnutella（分布式点对点文件检索协议） | 20（契约） | 待审计 |
| 54 | [`54-vxlan-design.md`](54-vxlan-design.md) / [`54-vxlan-testcase.md`](54-vxlan-testcase.md) | VXLAN（虚拟可扩展局域网，RFC 7348） | 20（契约） | 待审计 |
| 55 | [`55-nvgre-design.md`](55-nvgre-design.md) / [`55-nvgre-testcase.md`](55-nvgre-testcase.md) | NVGRE（网络虚拟化 GRE，RFC 7637） | 20（契约） | 待审计 |
| 56 | [`56-geneve-design.md`](56-geneve-design.md) / [`56-geneve-testcase.md`](56-geneve-testcase.md) | GENEVE（通用网络虚拟化封装，RFC 8926） | 20（契约） | 待审计 |
| 57 | [`57-sstp-design.md`](57-sstp-design.md) / [`57-sstp-testcase.md`](57-sstp-testcase.md) | SSTP（安全套接字隧道协议，MS-SSTP） | 20（契约） | 待审计 |
| 58 | [`58-dtls-design.md`](58-dtls-design.md) / [`58-dtls-testcase.md`](58-dtls-testcase.md) | DTLS（数据报传输层安全，RFC 4347/6347） | 20（契约） | 待审计 |
| 59 | [`59-kerberos-design.md`](59-kerberos-design.md) / [`59-kerberos-testcase.md`](59-kerberos-testcase.md) | KERBEROS（Kerberos V5，RFC 4120/6113） | 20（契约） | 待审计 |
| 60 | [`60-ntlm-design.md`](60-ntlm-design.md) / [`60-ntlm-testcase.md`](60-ntlm-testcase.md) | NTLM（NT LAN Manager，MS-NLMP/NTLMv2） | 20（契约） | 待审计 |
| 61 | [`61-spnego-design.md`](61-spnego-design.md) / [`61-spnego-testcase.md`](61-spnego-testcase.md) | SPNEGO（简单和受保护的 GSS-API 协商，RFC 4178） | 20（契约） | 待审计 |
| 62 | [`62-ocsp-design.md`](62-ocsp-design.md) / [`62-ocsp-testcase.md`](62-ocsp-testcase.md) | OCSP（在线证书状态协议，RFC 6960/8954） | 20（契约） | 待审计 |
| 63 | [`63-dcerpc-design.md`](63-dcerpc-design.md) / [`63-dcerpc-testcase.md`](63-dcerpc-testcase.md) | DCERPC（分布式计算环境远程过程调用，DCE/RPC over TCP） | 20（契约） | 待审计 |
| 64 | [`64-cwmp-design.md`](64-cwmp-design.md) / [`64-cwmp-testcase.md`](64-cwmp-testcase.md) | CWMP（CPE WAN 管理协议，TR-069） | 20（契约） | 审查 clean（v2.1） |
| 65 | [`65-bacnet-design.md`](65-bacnet-design.md) / [`65-bacnet-testcase.md`](65-bacnet-testcase.md) | BACnet（楼宇自动化控制网络） | 20（契约） | 待审计 |
| 66 | [`66-doh-design.md`](66-doh-design.md) / [`66-doh-testcase.md`](66-doh-testcase.md) | DOH（DNS over HTTPS，RFC 8484） | 38（契约） | 审查 clean |
| 67 | [`67-onvif-design.md`](67-onvif-design.md) / [`67-onvif-testcase.md`](67-onvif-testcase.md) | ONVIF（网络视频接口论坛） | 32（契约） | 审查 clean |
| 68 | [`68-hl7-design.md`](68-hl7-design.md) / [`68-hl7-testcase.md`](68-hl7-testcase.md) | HL7（医疗信息交换标准） | 25（契约） | 审查 clean |
| 69 | [`69-nmea-design.md`](69-nmea-design.md) / [`69-nmea-testcase.md`](69-nmea-testcase.md) | NMEA（海用电子设备接口） | 20（契约） | 待审计 |
| 70 | [`70-megaco-design.md`](70-megaco-design.md) / [`70-megaco-testcase.md`](70-megaco-testcase.md) | Megaco/H.248（媒体网关控制，含 h248/mgcp/megaco） | 23（契约） | 审查 clean |
| 71 | [`71-mmse-design.md`](71-mmse-design.md) / [`71-mmse-testcase.md`](71-mmse-testcase.md) | MMSE（彩信协议） | 38（契约） | 审查 clean |
| 72 | [`72-edp-design.md`](72-edp-design.md) / [`72-edp-testcase.md`](72-edp-testcase.md) | EDP（物联网设备数据协议） | 39（契约） | 审查 clean |
| 73 | [`73-ethmining-design.md`](73-ethmining-design.md) / [`73-ethmining-testcase.md`](73-ethmining-testcase.md) | ETHMining（以太坊挖矿协议） | 20（契约） | 待审计 |
| 74 | [`74-xmrmining-design.md`](74-xmrmining-design.md) / [`74-xmrmining-testcase.md`](74-xmrmining-testcase.md) | XMRMining（门罗币挖矿协议） | 20（契约） | 待审计 |
| 75 | [`75-stratum-design.md`](75-stratum-design.md) / [`75-stratum-testcase.md`](75-stratum-testcase.md) | Stratum（矿池通信协议） | 20（契约） | 待审计 |
| 76 | [`76-getwork-design.md`](76-getwork-design.md) / [`76-getwork-testcase.md`](76-getwork-testcase.md) | GetWork（比特币工作分配协议） | 20（契约） | 待审计 |
| 77 | [`77-gbt-design.md`](77-gbt-design.md) / [`77-gbt-testcase.md`](77-gbt-testcase.md) | GBT（GetBlockTemplate，比特币区块模板） | 20（契约） | 待审计 |
| 78 | [`78-isis-design.md`](78-isis-design.md) / [`78-isis-testcase.md`](78-isis-testcase.md) | ISIS（IS-IS 路由协议） | 28（13正+15负） | 待审计 |
| 78 | [`78-probe_smb-design.md`](78-probe_smb-design.md) / [`78-probe_smb-testcase.md`](78-probe_smb-testcase.md) | ProbeSMB（SMB 探测） | 12（9正+3负） | 待审计 |
| 79 | [`79-iec104-design.md`](79-iec104-design.md) / [`79-iec104-testcase.md`](79-iec104-testcase.md) | IEC 60870-5-104（电力远动） | 21（12正+9负） | 待审计 |
| 80 | [`80-bgp-design.md`](80-bgp-design.md) / [`80-bgp-testcase.md`](80-bgp-testcase.md) | BGP（边界网关协议） | 43（20正+23负） | 待审计 |
| 81 | [`81-dameng-design.md`](81-dameng-design.md) / [`81-dameng-testcase.md`](81-dameng-testcase.md) | Dameng（达梦数据库） | 34（13正+21负） | 待审计 |
| 82 | [`82-postgresql-design.md`](82-postgresql-design.md) / [`82-postgresql-testcase.md`](82-postgresql-testcase.md) | PostgreSQL（数据库） | 71（51正+20负） | 待审计 |
| 83 | [`83-ospf-design.md`](83-ospf-design.md) / [`83-ospf-testcase.md`](83-ospf-testcase.md) | OSPF（开放最短路径优先） | 24（12正+12负） | 待审计 |
| 84 | [`84-drda-design.md`](84-drda-design.md) / [`84-drda-testcase.md`](84-drda-testcase.md) | DRDA（分布式关系数据库架构） | 13（9正+4负） | 待审计 |
| 85 | [`85-s7-design.md`](85-s7-design.md) / [`85-s7-testcase.md`](85-s7-testcase.md) | S7（西门子工控） | 28（16正+12负） | 待审计 |
| 87 | [`87-mongodb-design.md`](87-mongodb-design.md) / [`87-mongodb-testcase.md`](87-mongodb-testcase.md) | MongoDB（数据库） | 31（18正+13负） | 待审计 |
| 88 | [`88-mms-design.md`](88-mms-design.md) / [`88-mms-testcase.md`](88-mms-testcase.md) | MMS（制造报文规范） | 19（11正+8负） | 待审计 |
| 89 | [`89-stratum-design.md`](89-stratum-design.md) / [`89-stratum-testcase.md`](89-stratum-testcase.md) | Stratum（矿池通信） | 40（29正+11负） | 待审计 |
| 90 | [`90-tns-design.md`](90-tns-design.md) / [`90-tns-testcase.md`](90-tns-testcase.md) | TNS（Oracle 透明网络底层） | 24（14正+10负） | 待审计 |
| 91 | [`91-ethmining-design.md`](91-ethmining-design.md) / [`91-ethmining-testcase.md`](91-ethmining-testcase.md) | ETHMining（以太坊挖矿） | 37（22正+15负） | 待审计 |
| 92 | [`92-moxa-design.md`](92-moxa-design.md) / [`92-moxa-testcase.md`](92-moxa-testcase.md) | MOXA（工控串口转网） | 23（11正+12负） | 待审计 |
| 93 | [`93-a2a-design.md`](93-a2a-design.md) / [`93-a2a-testcase.md`](93-a2a-testcase.md) | A2A（Agent-to-Agent） | 185（153正+32负） | 待审计 |
| 94 | [`94-modbus-design.md`](94-modbus-design.md) / [`94-modbus-testcase.md`](94-modbus-testcase.md) | Modbus TCP（工业控制） | 213（151正+62负） | 待审计 |
| 95 | [`95-dnp3-design.md`](95-dnp3-design.md) / [`95-dnp3-testcase.md`](95-dnp3-testcase.md) | DNP3（电力规约） | 70（50正+20负） | 待审计 |
| 96 | [`96-rip-design.md`](96-rip-design.md) / [`96-rip-testcase.md`](96-rip-testcase.md) | RIP/RIPng（路由信息协议） | 71（52正+19负） | 待审计 |
| 97 | [`97-nvgre-design.md`](97-nvgre-design.md) / [`97-nvgre-testcase.md`](97-nvgre-testcase.md) | NVGRE（网络虚拟化 GRE） | 20（14正+6负） | 待审计 |
| 98 | [`98-pcep-design.md`](98-pcep-design.md) / [`98-pcep-testcase.md`](98-pcep-testcase.md) | PCEP（路径计算通信） | 24（17正+7负） | 待审计 |
| 99 | [`99-ldp-design.md`](99-ldp-design.md) / [`99-ldp-testcase.md`](99-ldp-testcase.md) | LDP（标签分发协议） | 25（14正+11负） | 待审计 |
| 100 | [`100-someip-design.md`](100-someip-design.md) / [`100-someip-testcase.md`](100-someip-testcase.md) | SOME/IP（汽车 SOA） | 16（12正+4负） | 待审计 |
| 101 | [`101-opcua-design.md`](101-opcua-design.md) / [`101-opcua-testcase.md`](101-opcua-testcase.md) | OPC UA（工控统一架构） | 12（10正+2负） | 待审计 |
| 102 | [`102-thrift-design.md`](102-thrift-design.md) / [`102-thrift-testcase.md`](102-thrift-testcase.md) | Thrift（RPC 框架） | 13（7正+6负） | 待审计 |
| 103 | [`103-ftp-design.md`](103-ftp-design.md) / [`103-ftp-testcase.md`](103-ftp-testcase.md) | FTP（文件传输协议） | 141（136正+5负） | 待审计 |
| 104 | [`104-sip-design.md`](104-sip-design.md) / [`104-sip-testcase.md`](104-sip-testcase.md) | SIP（会话发起协议） | 96（87正+9负） | 待审计 |
| 105 | [`105-imap-design.md`](105-imap-design.md) / [`105-imap-testcase.md`](105-imap-testcase.md) | IMAP（邮件访问协议） | 84（65正+19负） | 待审计 |
| 106 | [`106-pop3-design.md`](106-pop3-design.md) / [`106-pop3-testcase.md`](106-pop3-testcase.md) | POP3（邮局协议） | 50（35正+15负） | 待审计 |
| 107 | [`107-smtp-design.md`](107-smtp-design.md) / [`107-smtp-testcase.md`](107-smtp-testcase.md) | SMTP（邮件传输协议） | 43（37正+6负） | 待审计 |
| 108 | [`108-dns-design.md`](108-dns-design.md) / [`108-dns-testcase.md`](108-dns-testcase.md) | DNS（域名解析） | 29（23正+6负） | 待审计 |
| 109 | [`109-radius-design.md`](109-radius-design.md) / [`109-radius-testcase.md`](109-radius-testcase.md) | RADIUS（认证计费） | 25（14正+11负） | 待审计 |
| 110 | [`110-pppoe-design.md`](110-pppoe-design.md) / [`110-pppoe-testcase.md`](110-pppoe-testcase.md) | PPPoE（以太网点对点） | 24（18正+6负） | 待审计 |
| 111 | [`111-ldap-design.md`](111-ldap-design.md) / [`111-ldap-testcase.md`](111-ldap-testcase.md) | LDAP（轻量目录访问） | 22（16正+6负） | 待审计 |
| 112 | [`112-vnc-design.md`](112-vnc-design.md) / [`112-vnc-testcase.md`](112-vnc-testcase.md) | VNC（远程桌面） | 21（17正+4负） | 待审计 |
| 113 | [`113-gre-design.md`](113-gre-design.md) / [`113-gre-testcase.md`](113-gre-testcase.md) | GRE（通用路由封装） | 21（14正+7负） | 待审计 |
| 114 | [`114-pptp-design.md`](114-pptp-design.md) / [`114-pptp-testcase.md`](114-pptp-testcase.md) | PPTP（点对点隧道） | 20（13正+7负） | 待审计 |
| 115 | [`115-telnet-design.md`](115-telnet-design.md) / [`115-telnet-testcase.md`](115-telnet-testcase.md) | Telnet（远程登录） | 17（14正+3负） | 待审计 |
| 116 | [`116-ngap-design.md`](116-ngap-design.md) / [`116-ngap-testcase.md`](116-ngap-testcase.md) | NGAP（5G N2 接口） | 17（12正+5负） | 待审计 |
| 117 | [`117-h323-design.md`](117-h323-design.md) / [`117-h323-testcase.md`](117-h323-testcase.md) | H.323（多媒体通信） | 17（11正+6负） | 待审计 |
| 118 | [`118-rtmp-design.md`](118-rtmp-design.md) / [`118-rtmp-testcase.md`](118-rtmp-testcase.md) | RTMP（实时消息） | 16（13正+3负） | 待审计 |
| 119 | [`119-tls-design.md`](119-tls-design.md) / [`119-tls-testcase.md`](119-tls-testcase.md) | TLS（传输层安全） | 15（9正+6负） | 待审计 |
| 120 | [`120-http_flv-design.md`](120-http_flv-design.md) / [`120-http_flv-testcase.md`](120-http_flv-testcase.md) | HTTP-FLV（流媒体） | 15（12正+3负） | 待审计 |
| 121 | [`121-mpls-design.md`](121-mpls-design.md) / [`121-mpls-testcase.md`](121-mpls-testcase.md) | MPLS（多协议标签交换） | 14（7正+7负） | 待审计 |
| 122 | [`122-rtsp-design.md`](122-rtsp-design.md) / [`122-rtsp-testcase.md`](122-rtsp-testcase.md) | RTSP（实时流协议） | 12（11正+1负） | 待审计 |
| 123 | [`123-arp-design.md`](123-arp-design.md) / [`123-arp-testcase.md`](123-arp-testcase.md) | ARP（地址解析协议） | 12（4正+8负） | 待审计 |
| 124 | [`124-xmpp-design.md`](124-xmpp-design.md) / [`124-xmpp-testcase.md`](124-xmpp-testcase.md) | XMPP（可扩展消息协议） | 11（9正+2负） | 待审计 |
| 125 | [`125-sctp-design.md`](125-sctp-design.md) / [`125-sctp-testcase.md`](125-sctp-testcase.md) | SCTP（流控制传输） | 11（8正+3负） | 待审计 |
| 126 | [`126-icmpv6-design.md`](126-icmpv6-design.md) / [`126-icmpv6-testcase.md`](126-icmpv6-testcase.md) | ICMPv6（IPv6 控制） | 11（5正+6负） | 待审计 |
| 127 | [`127-icmp-design.md`](127-icmp-design.md) / [`127-icmp-testcase.md`](127-icmp-testcase.md) | ICMP（互联网控制） | 8（4正+4负） | 待审计 |
| 128 | [`128-socks5-design.md`](128-socks5-design.md) / [`128-socks5-testcase.md`](128-socks5-testcase.md) | SOCKS5（代理协议） | 2（2正+0负） | 待审计 |
| 129 | [`129-wireguard-design.md`](129-wireguard-design.md) / [`129-wireguard-testcase.md`](129-wireguard-testcase.md) | WireGuard（VPN 隧道） | 1（1正+0负） | 待审计 |
| 130 | [`130-vmess-design.md`](130-vmess-design.md) / [`130-vmess-testcase.md`](130-vmess-testcase.md) | VMESS（V2Ray 代理） | 1（1正+0负） | 待审计 |
| 131 | [`131-syslog-design.md`](131-syslog-design.md) / [`131-syslog-testcase.md`](131-syslog-testcase.md) | Syslog（系统日志） | 1（1正+0负） | 待审计 |
| 132 | [`132-ssh-design.md`](132-ssh-design.md) / [`132-ssh-testcase.md`](132-ssh-testcase.md) | SSH（安全外壳） | 1（1正+0负） | 待审计 |
| 133 | [`133-ssdp-design.md`](133-ssdp-design.md) / [`133-ssdp-testcase.md`](133-ssdp-testcase.md) | SSDP（简单服务发现） | 1（1正+0负） | 待审计 |
| 134 | [`134-shadowsocks-design.md`](134-shadowsocks-design.md) / [`134-shadowsocks-testcase.md`](134-shadowsocks-testcase.md) | Shadowsocks（代理协议） | 1（1正+0负） | 待审计 |
| 135 | [`135-redis-design.md`](135-redis-design.md) / [`135-redis-testcase.md`](135-redis-testcase.md) | Redis（内存数据库） | 1（1正+0负） | 待审计 |
| 136 | [`136-rdp-design.md`](136-rdp-design.md) / [`136-rdp-testcase.md`](136-rdp-testcase.md) | RDP（远程桌面） | 1（1正+0负） | 待审计 |
| 137 | [`137-openvpn-design.md`](137-openvpn-design.md) / [`137-openvpn-testcase.md`](137-openvpn-testcase.md) | OpenVPN（VPN 隧道） | 1（1正+0负） | 待审计 |
| 138 | [`138-ntp-design.md`](138-ntp-design.md) / [`138-ntp-testcase.md`](138-ntp-testcase.md) | NTP（网络时间） | 1（1正+0负） | 待审计 |
| 139 | [`139-mysql-design.md`](139-mysql-design.md) / [`139-mysql-testcase.md`](139-mysql-testcase.md) | MySQL（数据库协议） | 1（1正+0负） | 待审计 |
| 140 | [`140-mdns-design.md`](140-mdns-design.md) / [`140-mdns-testcase.md`](140-mdns-testcase.md) | mDNS（多播 DNS） | 1（1正+0负） | 待审计 |
| 141 | [`141-l2tp-design.md`](141-l2tp-design.md) / [`141-l2tp-testcase.md`](141-l2tp-testcase.md) | L2TP（二层隧道） | 1（1正+0负） | 待审计 |
| 142 | [`142-ike_nat_t-design.md`](142-ike_nat_t-design.md) / [`142-ike_nat_t-testcase.md`](142-ike_nat_t-testcase.md) | IKE-NAT-T（NAT 穿越 IKE） | 1（1正+0负） | 待审计 |
| 143 | [`143-ike-design.md`](143-ike-design.md) / [`143-ike-testcase.md`](143-ike-testcase.md) | IKE（互联网密钥交换） | 1（1正+0负） | 待审计 |
| 144 | [`144-gtp-design.md`](144-gtp-design.md) / [`144-gtp-testcase.md`](144-gtp-testcase.md) | GTP（GPRS 隧道） | 1（1正+0负） | 待审计 |
| 145 | [`145-grpc-design.md`](145-grpc-design.md) / [`145-grpc-testcase.md`](145-grpc-testcase.md) | gRPC（RPC 框架） | 1（1正+0负） | 待审计 |
| 146 | [`146-snmp-design.md`](146-snmp-design.md) / [`146-snmp-testcase.md`](146-snmp-testcase.md) | SNMP（网络管理） | 1（1正+0负） | 待审计 |
| 147 | [`147-dhcpv6-design.md`](147-dhcpv6-design.md) / [`147-dhcpv6-testcase.md`](147-dhcpv6-testcase.md) | DHCPv6（IPv6 地址配置） | 1（1正+0负） | 待审计 |
| 148 | [`148-dhcp-design.md`](148-dhcp-design.md) / [`148-dhcp-testcase.md`](148-dhcp-testcase.md) | DHCP（动态主机配置） | 1（1正+0负） | 待审计 |

| 维度 | 数值 |
|------|------|
| 设计文档数 | 75 + 25（78–102 号补录，86 号空缺）+ 46（103–148 号 as-built 补录）= 147（机读 2026-09-29） |
| 用例文档数 | 59 + 25 + 46 = 137（机读 2026-09-29；103–148 号全部含配对 testcase） |
| 覆盖协议数 | 17 个既有归档协议 + 130 个新增设计协议（19–148 号，86 空缺）+ 配置架构 1 |
| 测试用例总数 | 5,368（`trafficgen/test/protocol_pcap/cases/*.json` 2026-09-28 机读实数） |

---

## 四、审计文档索引

所有审计文档位于 [`audit/`](audit/) 子目录。

### 4.1 审计文档列表

| 文件 | 审计对象 | 行数 | 问题数 | CRITICAL | HIGH | MEDIUM | LOW |
|------|----------|------|--------|----------|------|--------|-----|
| [`01-gbt32960-audit.md`](audit/01-gbt32960-audit.md) | GBT32960 | 756 | 32 | 8 | 9 | 8 | 7 |
| [`02-jt808-audit.md`](audit/02-jt808-audit.md) | JT808 | 631 | 25 | 4 | 7 | 8 | 6 |
| [`03-04-jt809-jtt905-audit.md`](audit/03-04-jt809-jtt905-audit.md) | JT809 + JTT905 | 924 | 36 | 7 | 10 | 11 | 8 |
| [`05-doip-audit.md`](audit/05-doip-audit.md) | DOIP | 850 | 39 | 8 | 11 | 12 | 8 |
| [`06-tftp-audit.md`](audit/06-tftp-audit.md) | TFTP | 690 | 35 | 8 | 10 | 10 | 7 |
| [`07-smb-audit.md`](audit/07-smb-audit.md) | SMB | 747 | 26 | 4 | 7 | 9 | 6 |
| [`08-nfs-audit.md`](audit/08-nfs-audit.md) | NFS | 580 | 28 | 2 | 8 | 10 | 8 |
| [`09-tds-audit.md`](audit/09-tds-audit.md) | TDS | 911 | 43 | 12 | 11 | 12 | 8 |
| [`10-13-rip-modbus-enip-audit.md`](audit/10-13-rip-modbus-enip-audit.md) | RIP + MODBUS + ENIP | 675 | 36 | 9 | 10 | 11 | 6 |
| [`11-15-dnp3-srv6-audit.md`](audit/11-15-dnp3-srv6-audit.md) | DNP3 + SRV6 | 726 | 33 | 4 | 9 | 12 | 8 |
| [`14-mqtt-audit.md`](audit/14-mqtt-audit.md) | MQTT | 510 | 32 | 3 | 8 | 12 | 9 |
| [`16-17-mcp-a2a-audit.md`](audit/16-17-mcp-a2a-audit.md) | MCP + A2A | 1260 | 34 | 4 | 9 | 13 | 8 |
| **合计** | **17 协议** | **~9260** | **399** | **73** | **109** | **128** | **89** |

### 4.2 审计问题统计

| 严重度 | 数量 | 处理建议 |
|--------|------|----------|
| CRITICAL | 73 | 实现前必须修复，否则生成的流量不合规 |
| HIGH | 109 | 实现中修复，影响互操作性 |
| MEDIUM | 128 | 实现后修复，影响测试覆盖度 |
| LOW | 89 | 文档清晰度问题，可批量修复 |
| **总计** | **399** | — |

### 4.3 重点问题分布

| 协议 | CRITICAL 数 | 关键问题类型 |
|------|-------------|--------------|
| TDS | 12 | Type 值错误、密码掩码错误、Login7 偏移错误、缺 Attention Ack |
| GBT32960 | 8 | JT808 字段误植、数据单元结构错误 |
| TFTP | 8 | BlocksCount 语义违反 RFC、TID 变更方向反转 |
| DOIP | 8 | 车辆识别号格式、路由类型枚举错误 |
| JT809/JTT905 | 7 | 链路类型与业务类型混淆 |
| RIP/MODBUS/ENIP | 9 | Modbus PDU 编码、RIP 认证字段、ENIP CIP 路径 |
| JT808 | 4 | 报文头字段、消息体属性 |
| SMB | 4 | 命令枚举、签名计算 |
| MCP/A2A | 4 | JSON-RPC 批量、capability 协商 |
| DNP3/SRV6 | 4 | SRV6 头部编码、DNP3 数据链路层 |
| MQTT | 3 | QoS 2 状态机、遗嘱消息 |
| NFS | 2 | RPC XID、文件句柄 |

---

## 五、优先级实现建议

基于 [`00-unimplemented-list.md`](00-unimplemented-list.md) 的 P0/P1/P2 分级和审计问题数：

### 5.1 P0（优先实现，5 个）

| 协议 | 审计 CRITICAL | 建议修复后实现 |
|------|---------------|----------------|
| MQTT | 3 | CRITICAL 少，可快速进入实现 |
| TFTP | 8 | 修复 BlocksCount 语义 + TID 变更后实现 |
| MODBUS | （合并审计） | 修复 PDU 编码后实现 |
| SMB | 4 | 修复命令枚举后实现 |
| TDS | 12 | CRITICAL 最多，需大量返工 |

### 5.2 P1（车联网批量，5 个）

| 协议 | 审计 CRITICAL | 建议修复后实现 |
|------|---------------|----------------|
| GBT32960 | 8 | 修复 JT808 字段误植后实现 |
| JT808 | 4 | CRITICAL 较少，可较快修复 |
| JT809 | （合并 JT809/JTT905） | 修复链路/业务类型混淆 |
| JTT905 | （合并 JT809/JTT905） | 同上 |
| DOIP | 8 | 修复车辆识别号格式 |

### 5.3 P2（长尾，7 个）

| 协议 | 审计 CRITICAL | 建议修复后实现 |
|------|---------------|----------------|
| NFS | 2 | CRITICAL 少，可较低成本实现 |
| RIP | （合并审计） | 修复认证字段 |
| DNP3 | （合并 DNP3/SRV6） | 修复数据链路层 |
| ENIP | （合并审计） | 修复 CIP 路径 |
| SRV6 | （合并 DNP3/SRV6） | 修复头部编码 |
| MCP（流量） | （合并 MCP/A2A） | 修复 JSON-RPC 批量 |
| A2A | （合并 MCP/A2A） | 修复 capability 协商 |

---

## 六、文档使用说明

### 6.1 实现流程建议

1. **先读清单**：`00-unimplemented-list.md` 了解 17 个协议分类与优先级
2. **选协议**：按 P0 → P1 → P2 顺序选择
3. **读设计**：对应 `NN-<protocol>-design.md`，理解 Config/状态机/包序列
4. **读审计**：对应 `audit/NN-<protocol>-audit.md`，按 P0/P1 修复 CRITICAL/HIGH 问题
5. **修复后重审**：CRITICAL 全部修复后重新审计，确认无新问题
6. **进入实现**：按 CLAUDE.md §Testing Policy 8 条规则编写失败测试 → 实现 → 测试通过

### 6.2 审计方法说明

所有审计遵循 CLAUDE.md §Code Modification & Review Policy 的对抗式审查原则：
- 独立审计员（非设计者）
- 默认"有 bug"除非证据确凿
- 严重度分级：CRITICAL > HIGH > MEDIUM > LOW
- 每个问题含：位置、描述、依据（RFC/规范引用）、修复建议
- 字段覆盖率审计：扩展表字段 vs 设计覆盖
- 测试用例质量审计：CLAUDE.md §Testing Policy 8 条规则逐条对照

### 6.3 文档命名规则

- 设计文档：`NN-<protocol>-design.md`，NN 为 00–77 编号；19–77 为新增协议设计契约，Go 层尚未全部实现。
- 用例文档：`NN-<protocol>-testcase.md`，与对应设计文档同号。
- 审计文档：`NN-<protocol>-adversarial-audit.md`，位于 `audit/` 子目录；旧归档的 `*-audit.md` 文件继续保留。
- 多协议合并文档：`NN-MM-<proto1>-<proto2>-design.md`，审计同命名规则。
- 文档编号与 `00-unimplemented-list.md` 表格编号一致；18 号保留给层链配置架构。

---

## 七、归档元信息

| 项 | 值 |
|----|-----|
| 归档目录 | `/home/weihang/trafficGenerator/docs/protocol-designs/` |
| 审计子目录 | `/home/weihang/trafficGenerator/docs/protocol-designs/audit/` |
| 归档时间 | 2026-08-03 |
| 索引更新时间 | 2026-09-29（补录 103–148 号 46 协议 as-built 契约；142=ike_nat_t、143=ike、146=snmp、147=dhcpv6、148=dhcp） |
| 对照规范 | 9.4.1.38 协议扩展信息上报（32 个扩展协议表） |
| 项目已实现 | 66 个协议 |
| 本次新增 | 105 个协议（设计 + 用例）+ 1 个配置架构设计 |
| 总文档数 | 384 份（1 清单 + 147 设计 + 137 用例 + 99 历史审计；103–148 号 46 协议 2026-09-29 补录；老号新文档双轨并存为既定惯例，如 42/98 pcep） |
| 总行数 | 以当前文件为准 |
| 总测试用例数 | 5,368 条（`trafficgen/test/protocol_pcap/cases/*.json`，2026-09-29 机读） |
| 审计发现问题 | 399 个（73 CRITICAL + 109 HIGH + 128 MEDIUM + 89 LOW） |

---

**归档完成**。本文档为索引，详细内容见各协议设计与审计文档。
