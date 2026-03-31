# 发包机使用说明

## 功能概述

这个发包机工具提供了高性能的流量生成能力：

1. **高性能流量生成器** - 多进程流式管线，支持TCP/UDP/HTTP流量生成
2. **批量混合流量生成** - 支持多种协议类型并发生成，可变化参数配置
3. **速率控制** - 支持按类别的字节级速率限制
4. **PCAP缓存** - 自动生成PCAP文件供分析

## 核心特性

### 🚀 多进程流式管线
- **配置生成进程**：异步生成报文配置
- **报文构造进程**：实时构造以太帧
- **本地缓冲**：高效的数据缓存和读取
- **边生成边缓存**：避免内存占用过大

### 🔧 批量混合流量生成
支持多种协议类型并发生成，每个类别可独立配置：
- **TCP流量**：完整的握手、数据传输、挥手过程
- **UDP流量**：简单的请求/响应模式
- **HTTP会话**：HTTP/1.1 keep-alive，多事务支持

### 📊 可变化参数支持
所有参数都支持多种生成策略：
- **固定值**：指定固定参数
- **递增循环**：按步长递增，达到上限后循环
- **随机生成**：在指定范围内随机生成
- **模式递增**：支持模板模式，如 `www{n}.example.com`
- **列表选择**：从预定义列表中随机选择

## 批量混合流量生成

### 基本使用

```python
from 发包工具.发包机 import HighPerformanceTrafficGenerator

# 创建流量生成器
hptg = HighPerformanceTrafficGenerator(
    config_processes=2,    # 配置生成进程数
    packet_processes=2,    # 报文构造进程数
    buffer_size=2048       # 本地缓冲大小
)
hptg.start()

# 批量配置
batch_spec = {
    'classes': [
        {
            'id': 'tcp_bulk',
            'type': 'tcp',
            'bps': '100k',  # 速率限制
            'tuples': {
                'ip_src': {'strategy': 'inc', 'range': '10.0.1.1-10.0.1.10'},
                'ip_dst': {'strategy': 'rand', 'range': '192.168.1.1-192.168.1.254'},
                'sport': {'strategy': 'inc', 'range': [10000, 10100]},
                'dport': {'strategy': 'rand', 'range': [80, 8080]}
            },
            'tcp': {
                'handshake': True,
                'termination': True,
                'mss': 1460,
                'uplink': {'payload_length': 1024},
                'downlink': {'payload_length': 512}
            }
        }
    ],
    'flows': {'count': 20}  # 总流数限制
}

# 启动批量生成
runner = hptg.start_batch_mixed(batch_spec)

# 获取报文
packets = hptg.get_packets(100, mode='combined')

# 停止
runner.stop()
hptg.stop()
```

### 配置参数详解

#### 1. 四元组配置 (tuples)

```python
'tuples': {
    # IP地址配置
    'ip_src': {
        'strategy': 'inc',           # 策略：inc(递增), rand(随机), fixed(固定)
        'range': '10.0.1.1-10.0.1.10',  # IP范围或CIDR
        'step': 1                    # 递增步长
    },
    'ip_dst': {
        'strategy': 'rand',
        'range': '192.168.1.0/24',   # 支持CIDR格式
        'seed': 42                   # 随机种子
    },
    
    # 端口配置
    'sport': {
        'strategy': 'inc',
        'range': [10000, 20000],     # 端口范围
        'step': 1
    },
    'dport': {
        'strategy': 'rand',
        'range': [80, 443, 8080],    # 端口列表
        'seed': 123
    }
}
    },
    
    # 端口配置
    'sport': {
        'strategy': 'inc',
        'range': [10000, 20000],     # 端口范围
        'step': 1
    },
    'dport': {
        'strategy': 'rand',
        'range': [80, 443, 8080],    # 端口列表
        'seed': 123
    }
}
```

#### 2. HTTP配置详解

```python
{
    'id': 'http_web',
    'type': 'http',
    'bps': '50k',
    'tuples': {...},
    'http': {
        # 基本配置
        'handshake': True,
        'termination': True,
        'mss': {'strategy': 'fixed', 'value': 1460},
        'sessions_per_flow': {'range': [1, 3]},
        
        # 域名配置
        'domains': {
            'strategy': 'rand',
            'list': ['www.example.com', 'api.test.com', 'cdn.demo.net']
        },
        
        # URI配置
        'uris': {
            'strategy': 'pattern',
            'pattern': '/page{n}.html',
            'n_range': [1, 1000],
            'step': 1
        },
        
        # HTTP方法
        'methods': ['GET', 'POST'],
        
        # Body配置（重点）
        'body': {
            'strategy': 'mixed',  # 混合模式
            'parts': [
                {
                    'type': 'static',
                    'content': '{"id": '
                },
                {
                    'type': 'increment',
                    'pattern': '{n}',
                    'n_range': [1, 1000],
                    'step': 1
                },
                {
                    'type': 'static',
                    'content': ', "data": "'
                },
                {
                    'type': 'random',
                    'length': 20,
                    'charset': 'abcdefghijklmnopqrstuvwxyz'
                },
                {
                    'type': 'static',
                    'content': '"}'
                }
            ]
        },
        
        # Headers配置
        'headers': {
            'User-Agent': {
                'strategy': 'list',
                'list': ['Mozilla/5.0', 'Chrome/91.0', 'Firefox/89.0']
            },
            'Accept': 'application/json',
            'X-Request-ID': {
                'strategy': 'pattern',
                'pattern': 'req-{n}',
                'n_range': [1, 999999]
            }
        },
        
        # 其他参数
        'ttl': {'strategy': 'random', 'range': [32, 128]},
        'tos': {'strategy': 'fixed', 'value': 0},
        'window': {'strategy': 'random', 'range': [4096, 65535]},
        
        # 思考时间
        'think_time_ms': {'range': [0, 50]}
    }
}
```

#### 3. Body生成策略详解

```python
'body': {
    # 策略1：固定内容
    'strategy': 'fixed',
    'content': 'Hello World'
}

'body': {
    # 策略2：从文件读取
    'strategy': 'file',
    'file_path': '/path/to/template.json'
}

'body': {
    # 策略3：指定数量的随机字符串
    'strategy': 'random_strings',
    'count': 5,
    'length_range': [10, 50],
    'charset': 'abcdefghijklmnopqrstuvwxyz',
    'separator': '\n'
}

'body': {
    # 策略4：模式递增
    'strategy': 'pattern',
    'pattern': 'data{n}',
    'n_range': [1, 1000],
    'step': 1
}

'body': {
    # 策略5：混合模式（推荐）
    'strategy': 'mixed',
    'parts': [
        {'type': 'static', 'content': '{"id":'},
        {'type': 'increment', 'pattern': '{n}', 'n_range': [1, 1000]},
        {'type': 'static', 'content': ',"name":"'},
        {'type': 'random', 'length': 10},
        {'type': 'static', 'content': '"}'}
    ]
}
```

### 内存优化特性

1. **静态内容缓存**：重复的静态内容只存储一次
2. **文件内容缓存**：文件内容读取后缓存复用
3. **配置分离**：动态部分与静态部分分离存储
4. **流式生成**：边生成边发送，避免大量内存占用

### 速率控制

```python
# 按类别设置速率限制
hptg.set_class_rate_limit('tcp_bulk', '100k')  # 100 kbps
hptg.set_class_rate_limit('http_web', '50k')   # 50 kbps

# 清除速率限制
hptg.clear_class_rate_limits()
```

### 完整示例

```python
from 发包工具.发包机 import HighPerformanceTrafficGenerator
import time

# 创建生成器
hptg = HighPerformanceTrafficGenerator(
    config_processes=2,
    packet_processes=2,
    buffer_size=2048
)
hptg.start()

# 复杂批量配置
batch_spec = {
    'classes': [
        {
            'id': 'tcp_bulk',
            'type': 'tcp',
            'bps': '200k',
            'tuples': {
                'ip_src': {'strategy': 'inc', 'range': '10.0.1.1-10.0.1.50'},
                'ip_dst': {'strategy': 'rand', 'range': '192.168.1.0/24', 'seed': 42},
                'sport': {'strategy': 'inc', 'range': [10000, 20000]},
                'dport': {'strategy': 'rand', 'range': [80, 443, 8080]}
            },
            'tcp': {
                'handshake': True,
                'termination': True,
                'mss': 1460,
                'uplink': {'payload_length': 1024},
                'downlink': {'payload_length': 512}
            },
            'rate_limit_fps': 10  # 每秒10个流
        },
        {
            'id': 'http_api',
            'type': 'http',
            'bps': '100k',
            'tuples': {
                'ip_src': {'strategy': 'rand', 'range': '172.16.0.0/16'},
                'sport': {'strategy': 'inc', 'range': [30000, 40000]},
                'dport': {'strategy': 'fixed', 'value': 80}
            },
            'http': {
                'domains': {'strategy': 'list', 'list': ['api.example.com']},
                'uris': {'strategy': 'pattern', 'pattern': '/users/{n}', 'n_range': [1, 1000]},
                'methods': ['GET', 'POST'],
                'body': {
                    'strategy': 'mixed',
                    'parts': [
                        {'type': 'static', 'content': '{"user_id":'},
                        {'type': 'increment', 'pattern': '{n}', 'n_range': [1, 1000]},
                        {'type': 'static', 'content': ',"action":"'},
                        {'type': 'random', 'length': 10},
                        {'type': 'static', 'content': '"}'}
                    ]
                },
                'headers': {
                    'Content-Type': 'application/json',
                    'Authorization': {'strategy': 'pattern', 'pattern': 'Bearer token{n}', 'n_range': [1, 100]}
                }
            }
        }
    ],
    'flows': {'count': 100}  # 总共生成100个流
}

# 启动批量生成
runner = hptg.start_batch_mixed(batch_spec)

# 监控生成状态
for i in range(10):
    status = runner.get_status()
    print(f"已生成流数: {status['total_flows_generated']}")
    time.sleep(1)

# 获取报文
up_packets = hptg.get_packets(500, mode='up')
down_packets = hptg.get_packets(500, mode='down')

print(f"上行报文: {len(up_packets)}")
print(f"下行报文: {len(down_packets)}")

# 停止
runner.stop()
hptg.stop()
```

## 注意事项

1. **内存优化**：使用混合模式的body生成策略，避免重复内容占用大量内存
2. **速率控制**：合理设置bps限制，避免网络拥塞
3. **流数控制**：设置合适的流数限制，避免资源耗尽
4. **文件路径**：确保body中引用的文件路径存在且可读
5. **种子设置**：使用固定种子可重现随机序列，便于调试

## 性能特点

- **并发生成**：多类别流量真正并发生成，非顺序执行
- **内存高效**：静态内容缓存，动态内容按需生成
- **速率精确**：字节级令牌桶限速，精确控制发包速率
- **配置灵活**：所有参数都支持多种生成策略
notepad README.md
