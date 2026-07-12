# 引擎实施交接文档 - 真机验证（root 执行）

> 本文档供 root 启动的 Claude 会话阅读。上方已完成全部代码实施，**唯一剩余的是真机发包验证**（需 root 权限，因为发包用 libpcap 原始套接字，抓包用 tcpdump）。
> 阅读此文档后，按"真机验证步骤"执行即可。

---

## 1. 项目背景

FlowB 是高性能网络流量生成器，Go 后端 + Vue 前端。本次工作是对**引擎**（`trafficgen/internal/core/`）做功能完善 + 性能优化，分 4 个 Phase，已全部实施完成并通过单元/集成测试。

## 2. 已完成的工作（4 个 Phase，19 个提交）

工作目录：`/home/weihang/trafficGenerator`，分支 `feat/public-component-system`。

### Phase 1：修 Bug（P0）
- **速率限制接线**：之前 `TokenBucket(0,...)` 无限速，BPS 不生效。现在 SubmitTask 解析 BPS 建桶，PacketWorker 用真实包字节数限速。任务完成自动清理桶。
- **CPU 监控**：之前返回 0。现在用 `syscall.Getrusage` 采集进程 CPU 占用。
- **设置持久化**：之前只在内存。现在存 DB，log_level/max_tasks 立即生效，buffer_size 重启生效。

### Phase 2：混合流量（P0.5 核心）
- **TupleGenerator**：4 元组（源/目的 IP + 端口）生成，IP 字节级递增带进位、端口整数、rand 可复现、list 循环。
- **BatchSpec 流水线**：一个任务多协议并发（TCP+UDP+ICMP 按比例），每类独立限速，共享输出，包自然交织。
- **API 端点**：`POST /api/v1/tasks/batch` 接受 BatchSpec 直接提交。

### Phase 3：参数完善（P1）
- **DSCP/ECN**：TOS 字节可独立控制 DSCP(6位)+ECN(2位)，用于 QoS 测试。
- **IP 分片**：Flags(DF/MF)+FragOffset 可控，可构造分片包。
- **TCP 选项**：SYN 包自动带 MSS+SACK，数据偏移动态计算。
- **参数验证**：VLAN/DSCP/ECN/MSS 范围校验（0=缺省约定）。

### Phase 4：性能优化
- **PCAP 重构**：bufio 缓冲 + 每包独立时间戳 + 单次写 + 仅关闭时 fsync。
- **RingBuffer 去复制**：Put 不再 make+copy，省一次分配+拷贝。
- **Builder 单缓冲**：6→3 分配/包（1 包缓冲 + 2 net.ParseIP）。
- **基准测试 + GC 指标**：`num_gc`/`gc_pause_ms` 加入系统状态。

### 已通过的验证
- `go build ./...` ✅
- `go test ./internal/... -race -short` ✅ 全绿
- `go test ./test/stress/ -short` ✅ 全绿
- `go vet` ✅ 干净
- 服务器启动冒烟测试 ✅（健康检查正常、`batch_config` 列迁移生效、引擎启动）
- 基准：TCP_64 577ns/3allocs、Pipeline ~470k pps（单 worker）

### 已知预先存在问题（非本次引入，无需处理）
- `test/integration` 和 `test/security` 构建失败：`api_test.go:102` 调 `rest.NewServer` 用 5 参，实际签名要 6 参（含 portSched）。这是历史测试不同步，与引擎工作无关。

---

## 3. 真机验证步骤（你需要执行的部分）

**测试网口：`enp135s0f0np0`**（已确认存在）
**管理员凭证：`admin` / `admin`**（来自 `configs/config.yaml`）
**服务器端口：8080**

### 前置准备

```bash
cd /home/weihang/trafficGenerator/trafficgen

# 1. 重新构建服务器二进制（确保是最新代码）
go build -o /tmp/trafficgen-server ./cmd/server/

# 2. 确认有 tcpdump，没有则安装
which tcpdump || yum install -y tcpdump   # 或 apt install -y tcpdump

# 3. 获取测试网口的 MAC（发包源 MAC 用）
cat /sys/class/net/enp135s0f0np0/address
# 记下这个 MAC，下面 SRC_MAC 替换用它，例如 aa:bb:cc:dd:ee:ff
```

### 启动服务器（root，后台）

```bash
/tmp/trafficgen-server serve --config configs/config.yaml > /tmp/tg-server.log 2>&1 &
echo $! > /tmp/tg-server.pid
sleep 3
# 确认健康
curl -s http://localhost:8080/health
# 期望: {"status":"healthy"}
```

### 登录拿 token

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['token'])")
echo "TOKEN=$TOKEN"
# 验证 token 能用
curl -s http://localhost:8080/api/v1/system/status -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# 期望: 看到 cpu_usage / num_gc / gc_pause_ms 字段（cpu_usage 可能接近0，正常）
```

### 创建端口组（绑定测试网口）

```bash
PG_RESP=$(curl -s -X POST http://localhost:8080/api/v1/port-groups \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test-pg","ports":[{"interface":"enp135s0f0np0","weight":1}]}')
echo "$PG_RESP"
PG_ID=$(echo "$PG_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['id'])")
echo "PG_ID=$PG_ID"
```

---

### 测试 A：DSCP + TCP 选项（SYN 带 MSS）

**目标**：发包到网口，抓包验证 TOS 字节 = 0xB8（DSCP 46）、SYN 包带 MSS 选项。

```bash
SRC_MAC=$(cat /sys/class/net/enp135s0f0np0/address)

# 后台抓包（抓 20 个 TCP SYN 包，存文件）
tcpdump -i enp135s0f0np0 -nn -c 20 -w /tmp/dscp-test.pcap 'tcp[tcpflags] & tcp-syn != 0' &
TCPDUMP_PID=$!
sleep 1

# 提交 batch 任务：1 个 TCP 类，DSCP=46，MSS=1460，5 个流
curl -s -X POST http://localhost:8080/api/v1/tasks/batch \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\":\"dscp-test\",
    \"batch\":{
      \"classes\":[{
        \"id\":\"tcp\",\"type\":\"tcp\",\"flow_count\":5,\"bps\":\"10M\",
        \"config\":{
          \"src_ip\":\"10.0.0.1\",\"dst_ip\":\"10.0.0.2\",
          \"src_mac\":\"$SRC_MAC\",\"dst_mac\":\"ff:ff:ff:ff:ff:ff\",
          \"dscp\":46,\"ecn\":0,
          \"tcp\":{\"handshake\":true,\"termination\":false,\"mss\":1460}
        },
        \"tuples\":{
          \"src_ip\":{\"strategy\":\"fixed\",\"value\":\"10.0.0.1\"},
          \"dst_ip\":{\"strategy\":\"fixed\",\"value\":\"10.0.0.2\"},
          \"src_port\":{\"strategy\":\"fixed\",\"value\":12345},
          \"dst_port\":{\"strategy\":\"fixed\",\"value\":80}
        }
      }]
    },
    \"output_type\":\"port_group\",
    \"output_config\":{\"port_group_id\":\"$PG_ID\"}
  }" | python3 -m json.tool

sleep 3
kill $TCPDUMP_PID 2>/dev/null

# 验证：读 pcap，检查 TOS 字节和 TCP 选项
python3 <<'PYEOF'
import struct
with open('/tmp/dscp-test.pcap','rb') as f:
    f.read(24)  # global header
    cnt=0
    for i in range(20):
        hdr=f.read(16)
        if len(hdr)<16: break
        sec,usec,caplen,origlen=struct.unpack('<IIII',hdr)
        pkt=f.read(caplen)
        if len(pkt)<caplen: break
        # Ethernet(14) + IP: TOS is IP byte 1 = pkt[15]
        tos = pkt[15]
        ip_hdr_len = (pkt[14] & 0x0f) * 4
        tcp_off = 14 + ip_hdr_len
        data_offset = (pkt[tcp_off+12] >> 4) * 4
        has_opts = data_offset > 20
        print(f"pkt{i}: TOS=0x{tos:02x} (DSCP={tos>>2}, ECN={tos&3}), TCP data_offset={data_offset} (options={'yes' if has_opts else 'no'})")
        cnt+=1
    print(f"\n共 {cnt} 个 SYN 包")
    # 期望: TOS=0xB8 (DSCP=46), data_offset=28 (MSS+SACK=8字节选项)
PYEOF
```

**期望结果**：每个 SYN 包 `TOS=0xb8 (DSCP=46, ECN=0)`，`data_offset=28`（有选项，MSS 4字节 + SACK 2字节 + 2字节 NOP padding = 8字节 → 20+8=28）。

### 测试 B：混合流量（多协议交织）

**目标**：一个任务同时发 TCP+UDP+ICMP，抓包确认三种协议都出现。

```bash
tcpdump -i enp135s0f0np0 -nn -c 50 -w /tmp/mixed-test.pcap 'tcp or udp or icmp' &
TCPDUMP_PID=$!
sleep 1

curl -s -X POST http://localhost:8080/api/v1/tasks/batch \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\":\"mixed-test\",
    \"batch\":{\"classes\":[
      {\"id\":\"tcp\",\"type\":\"tcp\",\"flow_count\":3,\"bps\":\"5M\",
       \"config\":{\"src_ip\":\"10.0.0.1\",\"dst_ip\":\"10.0.0.2\",\"src_mac\":\"$SRC_MAC\",\"dst_mac\":\"ff:ff:ff:ff:ff:ff\",\"tcp\":{\"handshake\":false,\"termination\":false,\"mss\":1460}},
       \"tuples\":{\"src_ip\":{\"strategy\":\"fixed\",\"value\":\"10.0.0.1\"},\"dst_ip\":{\"strategy\":\"fixed\",\"value\":\"10.0.0.2\"},\"src_port\":{\"strategy\":\"fixed\",\"value\":1000},\"dst_port\":{\"strategy\":\"fixed\",\"value\":80}}},
      {\"id\":\"udp\",\"type\":\"udp\",\"flow_count\":3,\"bps\":\"5M\",
       \"config\":{\"src_ip\":\"10.0.0.3\",\"dst_ip\":\"10.0.0.4\",\"src_mac\":\"$SRC_MAC\",\"dst_mac\":\"ff:ff:ff:ff:ff:ff\"},
       \"tuples\":{\"src_ip\":{\"strategy\":\"fixed\",\"value\":\"10.0.0.3\"},\"dst_ip\":{\"strategy\":\"fixed\",\"value\":\"10.0.0.4\"},\"src_port\":{\"strategy\":\"fixed\",\"value\":2000},\"dst_port\":{\"strategy\":\"fixed\",\"value\":53}}},
      {\"id\":\"icmp\",\"type\":\"icmp\",\"flow_count\":5,\"bps\":\"2M\",
       \"config\":{\"src_ip\":\"10.0.0.5\",\"dst_ip\":\"10.0.0.6\",\"src_mac\":\"$SRC_MAC\",\"dst_mac\":\"ff:ff:ff:ff:ff:ff\",\"icmp\":{\"type\":8,\"code\":0}},
       \"tuples\":{\"src_ip\":{\"strategy\":\"fixed\",\"value\":\"10.0.0.5\"},\"dst_ip\":{\"strategy\":\"fixed\",\"value\":\"10.0.0.6\"},\"src_port\":{\"strategy\":\"fixed\",\"value\":0},\"dst_port\":{\"strategy\":\"fixed\",\"value\":0}}}
    ]},
    \"output_type\":\"port_group\",
    \"output_config\":{\"port_group_id\":\"$PG_ID\"}
  }" | python3 -m json.tool

sleep 3
kill $TCPDUMP_PID 2>/dev/null

# 验证：统计协议分布
tcpdump -r /tmp/mixed-test.pcap -nn 2>/dev/null | awk '{print $3}' | grep -oE 'TCP|UDP|ICMP' | sort | uniq -c
# 期望: TCP、UDP、ICMP 三种都出现（数量>0）
```

### 测试 C：速率限制

**目标**：设 BPS=1M，抓包统计实际发送速率应接近 1Mbps。

```bash
# 抓 5 秒的包
tcpdump -i enp135s0f0np0 -nn -c 2000 -w /tmp/rate-test.pcap 'tcp' &
TCPDUMP_PID=$!
sleep 1

START=$(date +%s%N)
curl -s -X POST http://localhost:8080/api/v1/tasks/batch \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\":\"rate-test\",
    \"batch\":{\"classes\":[{
      \"id\":\"tcp\",\"type\":\"tcp\",\"flow_count\":50,\"bps\":\"1M\",
      \"config\":{\"src_ip\":\"10.0.0.1\",\"dst_ip\":\"10.0.0.2\",\"src_mac\":\"$SRC_MAC\",\"dst_mac\":\"ff:ff:ff:ff:ff:ff\",\"tcp\":{\"handshake\":false,\"termination\":false,\"mss\":1400}},
      \"tuples\":{\"src_ip\":{\"strategy\":\"fixed\",\"value\":\"10.0.0.1\"},\"dst_ip\":{\"strategy\":\"fixed\",\"value\":\"10.0.0.2\"},\"src_port\":{\"strategy\":\"inc\",\"range\":[1000,1099],\"step\":1},\"dst_port\":{\"strategy\":\"fixed\",\"value\":80}}
    }]},
    \"output_type\":\"port_group\",
    \"output_config\":{\"port_group_id\":\"$PG_ID\"}
  }" > /dev/null

sleep 5
END=$(date +%s%N)
kill $TCPDUMP_PID 2>/dev/null

# 统计实际字节/秒
python3 <<'PYEOF'
import struct, os
size = os.path.getsize('/tmp/rate-test.pcap') - 24  # 减全局头
# 粗略：pcap 里每包 16 字节记录头 + 包数据。统计包数和总字节数
with open('/tmp/rate-test.pcap','rb') as f:
    f.read(24)
    n=0; total_bytes=0
    while True:
        hdr=f.read(16)
        if len(hdr)<16: break
        _,_,caplen,_=struct.unpack('<IIII',hdr)
        f.read(caplen)
        n+=1; total_bytes+=caplen
print(f"抓到 {n} 包, 总 {total_bytes} 字节")
print(f"5秒内约 {total_bytes/5/1024:.1f} KB/s = {total_bytes*8/5/1e6:.2f} Mbps (目标 1M)")
PYEOF
```

**期望**：实际速率接近 1Mbps（允许 ±20% 误差，因 burst 和抓包开销）。

### 测试 D：设置持久化 + CPU/GC 监控

```bash
# 1. 改 log_level 为 debug，验证立即生效 + 持久化
curl -s -X PUT http://localhost:8080/api/v1/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"max_tasks":50,"buffer_size":4096,"log_level":"debug"}' | python3 -m json.tool

# 2. 读回确认持久化
curl -s http://localhost:8080/api/v1/settings -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# 期望: log_level=debug, max_tasks=50

# 3. 跑个任务让引擎忙起来，再看系统状态
curl -s http://localhost:8080/api/v1/system/status -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# 期望: cpu_usage > 0（任务运行时）, num_gc > 0, gc_pause_ms 有值
```

---

## 4. 清理

```bash
kill $(cat /tmp/tg-server.pid) 2>/dev/null
rm -f /tmp/dscp-test.pcap /tmp/mixed-test.pcap /tmp/rate-test.pcap /tmp/tg-server.log /tmp/tg-server.pid
```

---

## 5. 验证结果记录

每个测试执行后，把实际结果填到下表（或直接报告）：

| 测试 | 期望 | 实际结果 |
|------|------|---------|
| A: DSCP+TCP选项 | TOS=0xb8, data_offset=28 | |
| B: 混合流量 | TCP/UDP/ICMP 都出现 | |
| C: 速率限制 | 实际 ~1Mbps | |
| D: 设置持久化+监控 | log_level 持久化, cpu_usage>0 | |

## 6. 如果遇到问题

- **服务器起不来**：看 `/tmp/tg-server.log`。常见是端口 8080 被占用（`lsof -i:8080`）或 config 路径。
- **抓不到包**：确认网口名对（`ls /sys/class/net/`），确认服务器以 root 启动（否则 libpcap 无原始套接字权限）。
- **batch 请求 400**：检查 JSON 格式，特别是 `tuples` 的 `value` 数字用 `12345` 不带引号、IP 用字符串。
- **任务卡在 running**：看服务器日志有无错误；确认端口组 ID 正确。
- **DSCP 不生效**：确认 config 里 `"dscp":46`（不是 `tos`），mapToFlowSpec 读的是 `dscp` 字段。

## 7. 关键代码位置（如需调试）

- 速率限制：`internal/core/engine.go` SubmitTask + `worker.go` processConfig
- 混合流量：`internal/core/worker.go` processBatchTask
- DSCP/分片编码：`internal/core/builder.go` writeL3
- TCP 选项：`internal/core/builder.go` writeTCP + encodeTCPOptions
- batch API：`internal/api/rest/task_handler.go` CreateBatch
- PCAP 写入：`internal/output/pcap.go`

---

执行完真机验证后，把结果告诉我（哪些通过、哪些有问题）。如果全部通过，引擎实施就 100% 完成验证。
