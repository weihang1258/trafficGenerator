# 32-MongoDB 对抗审查报告

> 审查日期：2026-08-20  
> 审查属性：文档阶段审查；Go 实现尚未检查。  
> 对象：`32-mongodb-design.md`、`32-mongodb-testcase.md`、`cases/mongodb.json`

## 1. 审查范围和方法

- 逐字段核对 MongoDB 传统 16 字节 header（消息头）的顺序、宽度、小端序和长度定义；
- 逐 opcode 对照 body（消息体）起点和固定字段；
- 重新计算 BSON（Binary JSON，二进制 JSON）fixture（固定样本）的每级长度、终止符和嵌套偏移；
- 以脚本比较设计、testcase（测试用例文档）、JSON 的 id/包数/负例结构；
- 逐项检查 IPv4/IPv6 frame（帧）offset（偏移）是否从 Ethernet+IP+TCP 头推导；
- 对负例执行“只能 `expect_error` + `error_contains`”审查，避免 0 包假阳性；
- 搜索未实现服务器行为，删除无法从线格式确定的断言。

## 2. 关键线格式复核

### 2.1 Header

`messageLength/requestID/responseTo/opCode` 均为连续 4 字节 little-endian（小端序）；所有固定 fixture 的前 16 字节按此解释。S1 的 `33 00 00 00`=51、`64 00 00 00`=100、`00...`=0、`d4 07 00 00`=2004；S7 的 `3b...`=59、`be...`=190、opcode=2002，未出现高低字节颠倒。

### 2.2 Body 和 BSON

传统 opcode 表覆盖 OP_QUERY/REPLY、INSERT、UPDATE、DELETE、GET_MORE、KILL_CURSORS；未把 OP_MSG 或 OP_COMPRESSED 偷换进正例。BSON 多类型 fixture 的外层长度 101（`0x65`），数组长度 21、嵌入文档长度 8、字符串长度包含终止符，空文档长度 5；二进制 subtype 明确为 generic `0x00`。真实 cursor（游标）分配、查询结果和认证行为均不承诺。

### 2.3 偏移

无 IP/TCP option 的 IPv4 数据段 message 起点=54，IPv6=74。S1 selector 起点=54+16+4+11+4+4=93；INSERT 文档起点是 `54+16+4+11=85`。S3/S4 的 testcase 和 JSON 均使用 offset 85，不误用 89。

## 3. 覆盖和可观察性审查

| 审查项 | 结果 |
|---|---|
| TCP 27017 | 7 个正例均显式设置；UDP 另有负例 |
| header 四字段 | S1/S2/S5/S6/S7 的固定十六进制 + S7 逐字段解释 |
| OP_QUERY/OP_REPLY | IPv4、IPv6、多会话均覆盖；responseTo 配对明确 |
| 原子消息集 | S2 分别覆盖 INSERT/UPDATE/DELETE/GET_MORE/KILL_CURSORS |
| BSON 基础类型 | S3 覆盖 9 类；S4 覆盖合法最小空文档 |
| IPv4/IPv6 | S1-S4/S6-S7 IPv4，S5 IPv6 |
| 多会话 | S6 两条四元组，包数 18 |
| 边界/截断/非法 opcode | N1-N5 + UDP 载体，均为错误传播断言 |
| 服务器行为 | 查询结果、cursor 生命周期、认证、压缩均未虚构 |

## 4. 自审轮次

### Round 1：结构审查

核对 opcode body 长度、BSON 外层/嵌套长度和所有 frame offset；确认 INSERT 文档起点为 IPv4 绝对偏移 85。确认所有负例没有 `packet_count`、`fields` 或 `frames`。

### Round 2：对抗审查

尝试以以下输入反驳契约：空 BSON 长度 4、responseTo 指向不存在请求、未知 opcode、声明长度小于 16、header 截断、BSON 越界、UDP 载体、IPv6 常量偏移。每一项均有明确拒绝条件或单独不变量；没有将服务器的动态 cursor/查询结果写成断言。Round 2 clean。

### Round 3：最终一致性审查

脚本验证 JSON 语法、id 唯一、设计/testcase/JSON 集合与顺序、正例包数、负例 expect 键、所有正例 TCP/27017。Round 3 clean。

## 5. 待实现阶段的独立复核清单

1. builder（构造器）是否实际按 little-endian 写长度并在 body 完成后回填；
2. OP_QUERY 的可选 returnFieldsSelector 是否不会错误附加；
3. OP_REPLY 的 cursorID/numberReturned 是否按 8/4 字节对齐；
4. BSON string 长度是否按 UTF-8 字节计算，数组键是否连续；
5. 错误是否在 planner→task 终态传播，而非 0 包成功；
6. MSS/IP/TCP option 导致偏移变化时，测试是否切换字段断言；
7. 多 session 是否按四元组隔离 requestID/responseTo 关联；
8. 未实现 OP_MSG/OP_COMPRESSED 是否明确拒绝，而非按旧 opcode 解析。

## 6. 结论

文档三件套已通过 3 轮自审，最后一轮 clean；当前不存在已确认的文档级 finding（审查发现）。代码实现开始后，应按上节清单进行独立代码审查和失败优先测试，不得把本报告当作实现已完成的证明。
