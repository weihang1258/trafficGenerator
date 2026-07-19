# E2E 真实抓包测试

这个目录下的 `e2e_capture_test.py` 是真实 NIC 抓包核对脚本，验证 trafficgen
在多 PacketWorker + 多 OutputWorker 配置下包序的正确性。

## 前提条件

1. **server 已启动**：`./server --config configs/config.dev.yaml`（默认 8080 端口）
2. **接口可用**：`enp135s0f0np0` UP（脚本里 `IFACE` 常量可改）
3. **port_group 已创建**：脚本用 `33ddf949-b68a-456a-b32b-195690c29f93`（单 `enp135s0f0np0`），如不同请改脚本里 `PORT_GROUP_ID`
4. **tcpdump + root**：脚本用 `tcpdump -Z root` 保持特权抓包
5. **admin 账号**：脚本用 `admin/admin` 登录

## 运行

```bash
cd trafficgen
python3 test/integration/e2e_capture_test.py
```

## 5 个测试场景

| # | 场景 | 验证点 |
|---|---|---|
| 1 | 单流 TCP | SYN -> SYN-ACK -> ACK -> FIN x4，严格 FIFO |
| 2 | HTTP + Host | 握手 -> GET（含 `Host: www.home.com`）-> 200 OK -> 关闭，包序 + Host 头 |
| 3 | UDP 请求/响应 | 2 个 UDP 包，请求方向先发 |
| 4 | 多 group_id 并发 | 5 条流各自 group_id，每条流内 SYN 在 FIN 前，无跨流交错 |
| 5 | 双向流（4 元组 fallback） | SYN c2s -> SYN-ACK s2c -> ACK c2s -> 数据 c2s -> 响应 s2c -> FIN |

## 输出示例

```
=== Scenario 1: Single TCP flow ===
  captured 7 packets
  flow 10.0.0.1:11111-10.0.0.2:80: ['S', 'S.', '.', 'F.', '.', 'F.', '.']
  result: PASS

=== Scenario 2: HTTP with Host: www.home.com ===
  captured 9 packets
  HTTP GET with Host: www.home.com ✓
  HTTP 200 OK ✓
  SYN@0 SYN-ACK@1 GET@3 200OK@4
  result: PASS
...

============================================================
E2E Summary:
  single_tcp: PASS
  http_host: PASS
  udp: PASS
  multi_group_id: PASS
  bidirectional: PASS
```

## 脚本结构

- `login()` / `api()` — REST 调用封装
- `capture_start(path, filter)` — 启动 tcpdump（`-Z root` 保特权）
- `capture_stop(proc)` — SIGINT 停止
- `parse_pcap(path)` — tcpdump 文本输出解析为 packet 列表（flags/seq/ack/payload）
- `flow_key(p)` — 双向流键（min-max IP:port，src/dst 互换算同一流）
- `test_*()` — 5 个场景，每个建策略+任务+抓包+验证

## 已知限制

- 脚本是 Python，不是 Go test（依赖 tcpdump + 真实 NIC，不适合 CI）
- `port_group_id` 硬编码，换环境需改
- 场景 4 batch 任务 auto-start，必须 capture 包住 create 调用
