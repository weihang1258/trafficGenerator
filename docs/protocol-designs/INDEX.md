# 协议扩展实现设计文档归档索引

**生成时间**：2026-08-03
**对照规范**：9.4.1.38 协议扩展信息上报（32 个扩展协议表）
**项目已实现协议数**：50 个（见 `internal/protocol/` 目录）
**本次未实现协议数**：17 个
**本次归档文档总数**：1 个清单 + 15 个设计文档 + 12 个审计文档 = 28 份

---

## 一、文档总览

| 类别 | 文件数 | 总行数 | 说明 |
|------|--------|--------|------|
| 未实现清单 | 1 | 94 | 17 个未实现协议分类与优先级 |
| 设计文档 | 15 | ~19000 | 17 个协议的实现方案 + 测试用例（部分协议合并文档） |
| 审计文档 | 12 | ~10000 | 交叉对抗审计报告，发现 370+ 问题 |
| **合计** | **28** | **~29000** | — |

---

## 二、未实现协议清单

| 文件 | 内容 |
|------|------|
| [`00-unimplemented-list.md`](00-unimplemented-list.md) | 17 个未实现协议按业务领域分组（车联网 5 + 文件传输 3 + 数据库 1 + 路由 1 + 工控 3 + 物联网 1 + 网络 1 + Agent 2），含优先级建议（P0/P1/P2） |

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

### 3.9 设计文档合计

| 维度 | 数值 |
|------|------|
| 设计文档数 | 15 |
| 覆盖协议数 | 17 |
| 总行数 | ~19000 |
| 测试用例总数 | ~1175 |

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

- 设计文档：`NN-<protocol>-design.md`，NN 为 00-17 编号
- 审计文档：`NN-<protocol>-audit.md`，位于 `audit/` 子目录
- 多协议合并文档：`NN-MM-<proto1>-<proto2>-design.md`，审计同命名规则
- 文档编号与 `00-unimplemented-list.md` 表格编号一致

---

## 七、归档元信息

| 项 | 值 |
|----|-----|
| 归档目录 | `/home/weihang/trafficGenerator/docs/protocol-designs/` |
| 审计子目录 | `/home/weihang/trafficGenerator/docs/protocol-designs/audit/` |
| 归档时间 | 2026-08-03 |
| 对照规范 | 9.4.1.38 协议扩展信息上报（32 个扩展协议表） |
| 项目已实现 | 50 个协议 |
| 本次新增 | 17 个协议（设计 + 审计） |
| 总文档数 | 28 份（1 清单 + 15 设计 + 12 审计） |
| 总行数 | ~29000 行 |
| 总测试用例数 | ~1175 条 |
| 审计发现问题 | 399 个（73 CRITICAL + 109 HIGH + 128 MEDIUM + 89 LOW） |

---

**归档完成**。本文档为索引，详细内容见各协议设计与审计文档。
