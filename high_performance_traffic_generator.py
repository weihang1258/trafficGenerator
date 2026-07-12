"""
⚠️ 历史参考文件 — 当前程序已全面超越此实现，仅作架构参考留存。

保留原因：
- 多进程流式管线设计思路被 Go 后端继承并增强
- TokenBucket 限速算法、环形缓冲区、报文构造流程等核心逻辑
  在 Go 后端中有对应实现（trafficgen/internal/core/）
- 提供了早期 Python 原型的设计参考价值

当前状态：
- 不再维护，不参与构建/测试
- 上游 Go 后端（trafficgen/）为当前生产代码

高性能流量生成器（多进程流式管线，Windows 兼容）

本模块实现一个"配置→报文"的两级流水线：
- 配置生成进程（生产者）：按任务持续产出"单包构造配置"
- 报文构造进程（消费者/生产者）：消费配置并产出"完整以太帧"
- 主进程本地缓冲：由采集线程将进程间队列中的报文搬运到本地环形缓冲，供 API 按需读取

核心约束：
- 配置生成与报文生成是完全独立的多进程，仅通过队列（缓存）交换数据
- 严格边生成边缓存，不做"全部生成后一次性写入"
- 进程入口为顶层函数，兼容 Windows 的 spawn 启动方式
"""
import os
import time
import struct
import socket
import logging
import random
import uuid
from collections import deque
from typing import Optional, Dict, List, Union
import multiprocessing as mp
from multiprocessing import Process, Queue
import threading

# ---------------------------------
# 源头按类限速：共享 TokenBucket
# ---------------------------------
class SharedTokenBucket:
    """跨进程共享的字节级令牌桶（按 class_id 进行速率整形）

    - 使用 multiprocessing.Value 与 Lock 保证多个报文进程共享同一桶
    - 以字节为单位进行整形（rate_Bps 字节/秒）
    - burst_bytes 控制瞬时突发容量，数值越大越不平滑
    """
    def __init__(self, rate_bps: int, burst_bytes: int = 65536):
        rate_bps = max(0, int(rate_bps or 0))
        rate_Bps = max(1, rate_bps // 8) if rate_bps > 0 else 0
        self.rate_Bps = mp.Value('d', float(rate_Bps))
        self.capacity = mp.Value('d', float(max(1024, int(burst_bytes or 65536))))
        self.tokens = mp.Value('d', float(self.capacity.value))
        self.last_ts = mp.Value('d', time.time())
        self.lock = mp.Lock()

    def wait_for(self, nbytes: int):
        if nbytes <= 0:
            return
        # 0 代表不限速
        if self.rate_Bps.value <= 0:
            return
        while True:
            with self.lock:
                now = time.time()
                elapsed = now - self.last_ts.value
                if elapsed > 0:
                    # 补充令牌
                    self.tokens.value = min(
                        self.capacity.value,
                        self.tokens.value + elapsed * self.rate_Bps.value
                    )
                    self.last_ts.value = now
                if self.tokens.value >= nbytes:
                    self.tokens.value -= nbytes
                    return
                # 计算需要等待的时间
                need_bytes = nbytes - self.tokens.value
                wait_seconds = need_bytes / self.rate_Bps.value if self.rate_Bps.value > 0 else 0.001
            time.sleep(max(wait_seconds, 0.001))


def _parse_bps_to_int(bps_val) -> int:
    """解析 bps 字符串/数值为整数（bits per second）
    支持：'200k', '100M', '1g'，大小写不敏感；或直接传 int
    """
    if bps_val is None:
        return 0
    if isinstance(bps_val, (int, float)):
        return int(bps_val)
    s = str(bps_val).strip().lower()
    if not s:
        return 0
    mult = 1
    if s.endswith('k'):
        mult = 1000; s = s[:-1]
    elif s.endswith('m'):
        mult = 1000 * 1000; s = s[:-1]
    elif s.endswith('g'):
        mult = 1000 * 1000 * 1000; s = s[:-1]
    try:
        base = float(s)
    except Exception:
        return 0
    return int(base * mult)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


class BufferOverflowError(RuntimeError):
    """环形缓冲写入溢出异常"""
    pass

# 全局MAC地址管理器
class GlobalMacManager:
    """全局 MAC 地址管理器
    
    作用：
    - 在父进程中生成默认的源/目的 MAC 地址，仅生成一次并复用
    - 通过线程锁保证并发安全（多线程读取场景）
    
    说明：
    - 子进程不会各自随机生成 MAC；父进程在提交任务时会把"默认 MAC"写入任务，
      子进程直接复用，避免跨进程随机导致的数据不一致。
    """
    
    def __init__(self):
        self._generated_macs = {}
        self._lock = threading.Lock()
        self._default_mac_src = None
        self._default_mac_dst = None
    
    def get_or_generate_mac(self, key: str, is_src: bool = True) -> str:
        """获取或生成 MAC 地址
        
        参数：
          key(str): 逻辑标识，用于从缓存中复用同一条 MAC 值
          is_src(bool): True 生成/获取源 MAC；False 生成/获取目的 MAC
        返回：
          str: 形如 "aa:bb:cc:dd:ee:ff" 的 MAC 字符串
        说明：
          - 线程安全；如已生成会直接复用。
          - 实际默认 MAC 值由 _generate_random_mac() 创建（单播+本地管理位）。
        """
        with self._lock:
            if key in self._generated_macs:
                return self._generated_macs[key]
            
            # 生成新的MAC地址
            if is_src:
                if self._default_mac_src is None:
                    self._default_mac_src = self._generate_random_mac()
                mac = self._default_mac_src
            else:
                if self._default_mac_dst is None:
                    self._default_mac_dst = self._generate_random_mac()
                mac = self._default_mac_dst
            
            self._generated_macs[key] = mac
            return mac
    
    def _generate_random_mac(self) -> str:
        """生成随机 MAC 地址（单播 + 本地管理地址）
        - 清除组播位（LSB=0）
        - 置位本地管理位（bit1=1）
        """
        first = (random.randint(0, 255) & 0xFE) | 0x02
        rest = [random.randint(0, 255) for _ in range(5)]
        octets = [first] + rest
        return ":".join([f"{b:02x}" for b in octets])
    
    def get_default_mac_src(self) -> str:
        """获取默认源MAC地址"""
        if self._default_mac_src is None:
            with self._lock:
                if self._default_mac_src is None:
                    self._default_mac_src = self._generate_random_mac()
        return self._default_mac_src
    
    def get_default_mac_dst(self) -> str:
        """获取默认目的MAC地址"""
        if self._default_mac_dst is None:
            with self._lock:
                if self._default_mac_dst is None:
                    self._default_mac_dst = self._generate_random_mac()
        return self._default_mac_dst

# 全局实例
mac_manager = GlobalMacManager()

# 默认四元组管理器
class DefaultTupleManager:
    """默认四元组管理器
    
    维护默认的 IP 源/目的与源/目的端口。
    当某个流未显式给定这些字段时，规划阶段会回退到此处的默认值。
    """
    
    def __init__(self):
        self._default_ip_src = "192.168.1.100"
        self._default_ip_dst = "192.168.1.200"
        self._default_sport = 1024
        self._default_dport = 80
        self._lock = threading.Lock()
    
    def get_default_ip_src(self) -> str:
        """获取默认源 IP
        返回：str
        """
        return self._default_ip_src
    
    def get_default_ip_dst(self) -> str:
        """获取默认目的 IP
        返回：str
        """
        return self._default_ip_dst
    
    def get_default_sport(self) -> int:
        """获取默认源端口
        返回：int
        """
        return self._default_sport
    
    def get_default_dport(self) -> int:
        """获取默认目的端口
        返回：int
        """
        return self._default_dport
    
    def set_defaults(self, ip_src: str = None, ip_dst: str = None, 
                    sport: int = None, dport: int = None):
        """设置默认四元组
        
        参数：
          ip_src(str|None): 默认源 IP；None 表示保持不变
          ip_dst(str|None): 默认目的 IP；None 表示保持不变
          sport(int|None): 默认源端口；None 表示保持不变
          dport(int|None): 默认目的端口；None 表示保持不变
        返回：None
        """
        with self._lock:
            if ip_src:
                self._default_ip_src = ip_src
            if ip_dst:
                self._default_ip_dst = ip_dst
            if sport:
                self._default_sport = sport
            if dport:
                self._default_dport = dport

# 全局实例
tuple_manager = DefaultTupleManager()

# 报文缓冲区
class PacketBuffer:
    """报文缓冲区（主进程内的环形缓存）
    
    用途：承接采集线程搬运的报文条目，供 `get_packets` 批量读取。
    特性：
      - 使用 deque 实现有界缓冲，入队/出队均为 O(1)
      - 条目结构：{'packet': bytes, 'metadata': dict, 'timestamp': float}
      - 线程安全：读写加锁
      - 满容策略：put() 返回 False（不阻塞），上层可据此触发错误处理
    """
    
    def __init__(self, max_size: int = 10000, max_bytes: int = 0):
        self.buffer = deque(maxlen=max_size)
        self.lock = threading.Lock()
        self.max_size = max_size
        self.max_bytes = int(max_bytes or 0)
        self.current_size = 0
        self.current_bytes = 0
    
    def put(self, packet: bytes, metadata: Dict = None):
        """放入报文
        
        参数：
          packet(bytes): 以太帧二进制
          metadata(dict|None): 元数据（例如 dir/flow_id/packet_index）
        返回：
          bool: True=成功；False=缓冲满
        说明：超过容量将丢弃本次写入并返回 False，以便上层采取"主动报错+停止"的策略。
        """
        with self.lock:
            packet_len = len(packet) if isinstance(packet, (bytes, bytearray)) else 0
            if self.current_size < self.max_size and (self.max_bytes == 0 or self.current_bytes + packet_len <= self.max_bytes):
                item = {
                    'packet': packet,
                    'metadata': metadata or {},
                    'timestamp': time.time()
                }
                self.buffer.append(item)
                self.current_size += 1
                self.current_bytes += packet_len
                return True
            return False

    def put_entry(self, entry: Dict) -> bool:
        """直接写入预构造的条目（不会复制），用于多视图索引共享。
        返回：bool
        说明：只对 max_size 与 max_bytes 做容量校验；若启用 byte 计数，以 entry['packet'] 长度计入。
        """
        if not isinstance(entry, dict) or 'packet' not in entry:
            return False
        packet = entry.get('packet')
        packet_len = len(packet) if isinstance(packet, (bytes, bytearray)) else 0
        with self.lock:
            if self.current_size < self.max_size and (self.max_bytes == 0 or self.current_bytes + packet_len <= self.max_bytes):
                self.buffer.append(entry)
                self.current_size += 1
                self.current_bytes += packet_len
                return True
            return False
    
    def get(self) -> Optional[Dict]:
        """获取单个报文（先进先出）
        
        - 当缓冲为空时返回 None
        - 返回值形如 { 'packet': bytes, 'metadata': dict, 'timestamp': float }
        """
        with self.lock:
            if self.current_size > 0:
                item = self.buffer.popleft()
                self.current_size -= 1
                pkt = item.get('packet') if isinstance(item, dict) else None
                self.current_bytes -= (len(pkt) if isinstance(pkt, (bytes, bytearray)) else 0)
                if self.current_bytes < 0:
                    self.current_bytes = 0
                return item
            return None
    
    def get_batch(self, count: int) -> List[Dict]:
        """批量获取报文
        
        - 最多返回 count 条；若不足则返回当前全部
        - 顺序与入队一致（FIFO）
        """
        with self.lock:
            batch = []
            to_take = min(count, self.current_size)
            for _ in range(to_take):
                if self.current_size > 0:
                    item = self.buffer.popleft()
                    self.current_size -= 1
                    pkt = item.get('packet') if isinstance(item, dict) else None
                    self.current_bytes -= (len(pkt) if isinstance(pkt, (bytes, bytearray)) else 0)
                    if self.current_bytes < 0:
                        self.current_bytes = 0
                    batch.append(item)
            return batch
    
    def size(self) -> int:
        """获取当前缓冲区大小（条目数）"""
        with self.lock:
            return self.current_size
    
    def clear(self):
        """清空缓冲区"""
        with self.lock:
            self.buffer.clear()
            self.current_size = 0
            self.current_bytes = 0

# 配置生成器（多进程）
def config_worker_main(worker_id: int, task_q: Queue, out_q: Queue, stop_event: mp.Event):
    """配置生成进程主函数（生产者）
    
    行为：
      - 从 `task_q` 拉取任务（类型：'tcp_flow' 或 'udp_flow'）。
      - 将 `flow_spec` 按协议展开为"单包配置"（含 L2/L3/L4/payload/metadata）。
      - 逐条写入 `out_q`（严格流式，不聚合）。
    计数：
      - 任务字段 `count` 为"实际包数上限"。当 `count<=0` 或缺失时表示"不限"。
      - 计数包含握手/数据分片/ACK/终止的全部包。
    终止：
      - 收到 {'type': 'stop'} 或 `stop_event` 置位时退出。
    """
    logger.info(f"配置生成进程 {worker_id} 已启动")
    while not stop_event.is_set():
        try:
            task = task_q.get(timeout=0.2)
        except Exception:
            continue
        if not isinstance(task, dict):
            continue
        if task.get('type') == 'stop':
            break
        try:
            if task.get('type') == 'tcp_flow':
                flow_spec = task['flow_spec']
                # 当 count 不存在或 <=0 时，不限制生成包数
                count_raw = task.get('count', None)
                try:
                    if isinstance(count_raw, dict):
                        packet_limit = int(count_raw.get('count', 0)) if count_raw.get('count', 0) > 0 else None
                    else:
                        packet_limit = int(count_raw) if count_raw is not None else None
                except Exception as e:
                    logger.error(f"配置生成进程 {worker_id} count 解析错误: count_raw={count_raw}, type={type(count_raw)}, error={e}")
                    packet_limit = None
                mac_src = task.get('mac_src_default') or mac_manager.get_default_mac_src()
                mac_dst = task.get('mac_dst_default') or mac_manager.get_default_mac_dst()
                for cfg in plan_tcp_flow_packet_configs_iter(flow_spec, mac_src, mac_dst):
                    out_q.put(cfg)
                    if packet_limit is not None and packet_limit > 0:
                        packet_limit -= 1
                        if packet_limit <= 0:
                            break
            elif task.get('type') == 'udp_flow':
                flow_spec = task['flow_spec']
                # 当 count 不存在或 <=0 时，不限制生成包数
                count_raw = task.get('count', None)
                try:
                    if isinstance(count_raw, dict):
                        packet_limit = int(count_raw.get('count', 0)) if count_raw.get('count', 0) > 0 else None
                    else:
                        packet_limit = int(count_raw) if count_raw is not None else None
                except Exception as e:
                    logger.error(f"配置生成进程 {worker_id} count 解析错误: count_raw={count_raw}, type={type(count_raw)}, error={e}")
                    packet_limit = None
                mac_src = task.get('mac_src_default') or mac_manager.get_default_mac_src()
                mac_dst = task.get('mac_dst_default') or mac_manager.get_default_mac_dst()
                for cfg in plan_udp_flow_packet_configs_iter(flow_spec, mac_src, mac_dst):
                    out_q.put(cfg)
                    if packet_limit is not None and packet_limit > 0:
                        packet_limit -= 1
                        if packet_limit <= 0:
                            break
            elif task.get('type') == 'http_session':
                http_spec = task['http_spec']
                # 当 count 不存在或 <=0 时，不限制生成包数
                count_raw = task.get('count', None)
                try:
                    if isinstance(count_raw, dict):
                        packet_limit = int(count_raw.get('count', 0)) if count_raw.get('count', 0) > 0 else None
                    else:
                        packet_limit = int(count_raw) if count_raw is not None else None
                except Exception as e:
                    logger.error(f"配置生成进程 {worker_id} count 解析错误: count_raw={count_raw}, type={type(count_raw)}, error={e}")
                    packet_limit = None
                mac_src = task.get('mac_src_default') or mac_manager.get_default_mac_src()
                mac_dst = task.get('mac_dst_default') or mac_manager.get_default_mac_dst()
                for cfg in plan_http_sessions_iter(http_spec, mac_src, mac_dst):
                    out_q.put(cfg)
                    if packet_limit is not None and packet_limit > 0:
                        packet_limit -= 1
                        if packet_limit <= 0:
                            break
        except Exception as e:
            logger.error(f"配置生成进程 {worker_id} 任务错误: {e}")
            logger.error(f"配置生成进程 {worker_id} 任务详情: {task}")
    logger.info(f"配置生成进程 {worker_id} 已停止")


def packet_worker_main(worker_id: int, in_q: Queue, out_q: Queue, stop_event: mp.Event, rate_limiters: Dict[str, SharedTokenBucket] = None):
    """报文构造进程主函数（消费者/生产者）
    
    行为：
      - 从 `in_q` 获取"单包配置"（dict），调用 `build_packet_from_config_static` 构造以太帧。
      - 将 {'packet': bytes, 'metadata': dict} 放入 `out_q`，以便收集线程获取并分拣。
      - 完全流式处理，逐个配置生成对应报文，不做聚合。
    终止：
      - 收到 {'type': 'stop'} 或 `stop_event` 置位时退出。
    """
    logger.info(f"报文构造进程 {worker_id} 已启动")
    while not stop_event.is_set():
        try:
            cfg = in_q.get(timeout=0.2)
        except Exception:
            continue
        if isinstance(cfg, dict) and cfg.get('type') == 'stop':
            break
        try:
            pkt_bytes = build_packet_from_config_static(cfg)
            meta = cfg.get('metadata', {}) if isinstance(cfg, dict) else {}
            # 源头限速：按类整形
            try:
                class_id = meta.get('class_id') if isinstance(meta, dict) else None
                if rate_limiters and class_id and class_id in rate_limiters:
                    limiter = rate_limiters[class_id]
                    limiter.wait_for(len(pkt_bytes))
            except Exception:
                pass
            out_q.put({'packet': pkt_bytes, 'metadata': meta})
        except Exception as e:
            logger.error(f"报文构造进程 {worker_id} 错误: {e}")
    logger.info(f"报文构造进程 {worker_id} 已停止")


class ConfigGenerator:
    """配置生成器（生产者）
    
    - 维护若干工作进程，每个进程运行 config_worker_main
    - 从 self.task_queue 消费任务，向 out_queue 持续写入"单包配置"
    - 仅负责生成配置，不直接构造报文
    """
    def __init__(self, process_count: int = 2, task_queue: Optional[Queue] = None, out_queue: Optional[Queue] = None):
        """初始化配置生成器
        
        参数：
          process_count(int): 工作进程数量
          task_queue(Queue|None): 任务输入队列；未提供时内部创建（有界）
          out_queue(Queue|None): 配置输出队列；未提供时内部创建（有界）
        """
        self.process_count = process_count
        self.task_queue: Queue = task_queue or mp.Queue(maxsize=1000)
        self.out_queue: Queue = out_queue or mp.Queue(maxsize=1000)
        self.stop_event = mp.Event()
        self.processes: List[Process] = []

    def start(self):
        """启动配置生成进程集
        
        行为：为每个工作进程启动一个 `config_worker_main`，并记录到 self.processes。
        返回：None
        """
        for i in range(self.process_count):
            p = Process(target=config_worker_main, args=(i, self.task_queue, self.out_queue, self.stop_event))
            p.daemon = True
            p.start()
            self.processes.append(p)
        logger.info(f"启动了 {self.process_count} 个配置生成进程")

    def stop(self):
        """停止所有配置生成进程
        
        行为：
          - 置位 stop_event
          - 发送与进程数相同的 stop 任务以唤醒阻塞
          - join 等待一段时间；超时仍存活则 terminate
        返回：None
        """
        self.stop_event.set()
        # 用空任务唤醒阻塞
        try:
            for _ in range(self.process_count):
                self.task_queue.put({'type': 'stop'})
        except Exception:
            pass
        for p in self.processes:
            p.join(timeout=5)
            if p.is_alive():
                p.terminate()
        logger.info("配置生成进程已停止")

    

# 报文构造器（多进程）
class PacketBuilder:
    """报文构造器（消费者/生产者）
    
    - 维护若干工作进程，每个进程运行 packet_worker_main
    - 从 in_queue 消费"单包配置"，构造报文后写入 out_queue
    - 与配置生成解耦，只通过队列交换数据
    """
    def __init__(self, process_count: int = 2, in_queue: Optional[Queue] = None, out_queue: Optional[Queue] = None, rate_limiters: Optional[Dict[str, SharedTokenBucket]] = None):
        """初始化报文构造器
        
        参数：
          process_count(int): 工作进程数量
          in_queue(Queue|None): 单包配置输入队列；未提供时内部创建（有界）
          out_queue(Queue|None): 报文输出队列；未提供时内部创建（有界）
        """
        self.process_count = process_count
        self.in_queue: Queue = in_queue or mp.Queue(maxsize=1000)
        self.out_queue: Queue = out_queue or mp.Queue(maxsize=1000)
        self.stop_event = mp.Event()
        self.rate_limiters: Dict[str, SharedTokenBucket] = rate_limiters or {}
        self.processes: List[Process] = []

    def start(self):
        """启动报文构造进程集
        
        行为：为每个工作进程启动一个 `packet_worker_main`，并记录到 self.processes。
        返回：None
        """
        for i in range(self.process_count):
            p = Process(target=packet_worker_main, args=(i, self.in_queue, self.out_queue, self.stop_event, self.rate_limiters))
            p.daemon = True
            p.start()
            self.processes.append(p)
        logger.info(f"启动了 {self.process_count} 个报文构造进程")

    def stop(self):
        """停止所有报文构造进程
        
        行为：
          - 置位 stop_event
          - 发送与进程数相同的 stop 配置以唤醒阻塞
          - join 等待一段时间；超时仍存活则 terminate
        返回：None
        """
        self.stop_event.set()
        # 用空配置唤醒阻塞
        try:
            for _ in range(self.process_count):
                self.in_queue.put({'type': 'stop'})
        except Exception:
            pass
        for p in self.processes:
            p.join(timeout=5)
            if p.is_alive():
                p.terminate()
        logger.info("报文构造进程已停止")

    

# 高性能流量生成器
class HighPerformanceTrafficGenerator:
    """高性能流量生成器（管线控制器）
    
    组件：
    - ConfigGenerator：消费任务 → 产出"单包配置"到 config_buffer_queue
    - PacketBuilder：消费"单包配置" → 产出"以太帧"到 packet_buffer_queue
    - Collector 线程：把 packet_buffer_queue 的报文搬运到主进程内的 PacketBuffer
    
    使用方式：
    - start()：启动子进程与采集线程
    - submit_tcp_flow/submit_udp_flow：仅提交任务，异步产生报文
    - get_packets()：从本地缓冲读取任意数量的报文（不阻塞生产）
    - stop()：优雅停止所有子进程与采集线程
    
    特点：
    - 严格的"边生成边缓存"，验证缓存存在意义；不会先聚合后一次性入队
    - 仅通过队列在进程间传递数据，互不共享可变状态
    """

    def __init__(self, config_processes: int = 2, packet_processes: int = 2, buffer_size: int = 10000,
                 qsize_config: int = 2000, qsize_packet: int = 2000,
                 enable_up_buffer: bool = True, enable_down_buffer: bool = True, enable_combined_buffer: bool = True):
        """初始化管线控制器
        
        参数：
          config_processes(int): 配置生成进程数
          packet_processes(int): 报文构造进程数
          buffer_size(int): 主进程本地环形缓冲容量（条目数）；若需按字节控制，请在 PacketBuffer 里设置 max_bytes
          qsize_config(int): 配置队列容量上限
          qsize_packet(int): 报文队列容量上限
        说明：各队列/缓冲均为有界，避免无限增长导致内存压力。
        """
        # 进程间队列
        self.config_task_queue: Queue = mp.Queue(maxsize=qsize_config)
        self.config_buffer_queue: Queue = mp.Queue(maxsize=qsize_config)
        self.packet_buffer_queue: Queue = mp.Queue(maxsize=qsize_packet)

        # 按类速率限制器（共享给所有报文进程）
        self._class_rate_limiters: Dict[str, SharedTokenBucket] = {}
        # 生成器与构造器
        self.config_generator = ConfigGenerator(config_processes, self.config_task_queue, self.config_buffer_queue)
        self.packet_builder = PacketBuilder(packet_processes, self.config_buffer_queue, self.packet_buffer_queue, self._class_rate_limiters)

        # 本地缓冲用于 API 提供读取（上/下/合并，可按需启用）
        self.enable_up_buffer = enable_up_buffer
        self.enable_down_buffer = enable_down_buffer
        self.enable_combined_buffer = enable_combined_buffer
        # 统一：只保存一份数据在 combined；方向视图通过索引"引用" combined 条目
        self.up_buffer = PacketBuffer(buffer_size) if enable_up_buffer else None
        self.down_buffer = PacketBuffer(buffer_size) if enable_down_buffer else None
        self.combined_buffer = PacketBuffer(buffer_size) if enable_combined_buffer else None
        # 兼容旧 API：把 combined 暴露为 packet_buffer（默认模式）
        self.packet_buffer = self.combined_buffer
        self.config_processes = config_processes
        self.packet_processes = packet_processes
        self.buffer_size = buffer_size
        self.is_running = False
        self._fatal_error_message: Optional[str] = None

        # 收集线程：把进程间报文队列搬到本地缓冲
        self._collector_stop = threading.Event()
        self._collector_thread: Optional[threading.Thread] = None
        # 每流顺序释放（flow_id + packet_index）
        self._seq_expected: Dict[str, int] = {}
        self._seq_hold: Dict[str, Dict[int, Dict]] = {}

    def _collector_loop(self):
        """采集线程主循环：持续将进程间报文队列的数据搬到主进程缓冲
        
        - 非阻塞停止：通过 _collector_stop Event 退出
        - 失败/超时：忽略并继续尝试
        """
        while not self._collector_stop.is_set():
            try:
                pkt = self.packet_buffer_queue.get(timeout=0.2)
            except Exception:
                continue
            if pkt is None:
                continue
            # 保序释放：可能返回 0..N 个条目
            release_items = self._resequencer_accept(pkt)
            for it in release_items:
                # 统一的 canonical 条目
                entry = it if (isinstance(it, dict) and 'packet' in it) else {'packet': (it if isinstance(it, (bytes, bytearray)) else b''), 'metadata': {}, 'timestamp': time.time()}
                meta = entry.get('metadata', {}) or {}

                def put_or_fail_entry(target_buffer: PacketBuffer, name: str):
                    ok = target_buffer.put_entry(entry)
                    if not ok:
                        # 缓存满，立即报错并停止流水线
                        self._fatal_error_message = (
                            f"缓冲区已满: {name}. 建议: 1) 增大 buffer_size; 2) 降低提交速率或设置较小 count 上限; "
                            f"3) 只启用必要缓冲(enable_*_buffer); 4) 增大 packet_processes 或优化消费者处理。"
                        )
                        logger.error(self._fatal_error_message)
                        # 停止所有组件
                        try:
                            self.stop()
                        except Exception:
                            pass
                        # 退出采集线程
                        self._collector_stop.set()
                        raise BufferOverflowError(self._fatal_error_message)

                # 存储策略：directionless -> 仅 combined；否则 -> 仅方向缓冲
                store = (meta.get('store') or 'combined').lower()
                direction = (meta.get('dir') or '').lower()
                if store == 'combined':
                    if self.combined_buffer is not None:
                        put_or_fail_entry(self.combined_buffer, 'combined')
                else:
                    if direction == 'up' and self.up_buffer is not None:
                        put_or_fail_entry(self.up_buffer, 'up')
                    elif direction == 'down' and self.down_buffer is not None:
                        put_or_fail_entry(self.down_buffer, 'down')

    def _resequencer_accept(self, item: Dict) -> List[Dict]:
        """按 flow_id/packet_index 有序释放条目
        - 若无元数据或索引则原样放行
        - 若索引滞后则缓存；达到期望索引则级联释放
        """
        if not isinstance(item, dict):
            return [item]
        meta = item.get('metadata') or {}
        flow_id = meta.get('flow_id')
        pkt_idx = meta.get('packet_index')
        if flow_id is None or pkt_idx is None:
            return [item]
        expected = self._seq_expected.get(flow_id, 0)
        if pkt_idx == expected:
            out = [item]
            expected += 1
            hold = self._seq_hold.get(flow_id)
            while hold and expected in hold:
                out.append(hold.pop(expected))
                expected += 1
            if hold is not None and len(hold) == 0:
                self._seq_hold.pop(flow_id, None)
            self._seq_expected[flow_id] = expected
            return out
        if pkt_idx > expected:
            self._seq_hold.setdefault(flow_id, {})[pkt_idx] = item
            return []
        # 过序包（pkt_idx < expected）：丢弃并告警
        try:
            logger.warning(f"过序包丢弃 flow_id={flow_id} idx={pkt_idx} expected={expected}")
        except Exception:
            pass
        return []

    def start(self):
        """启动整个流水线（进程 + 采集线程）"""
        self.config_generator.start()
        self.packet_builder.start()
        self._collector_stop.clear()
        self._collector_thread = threading.Thread(target=self._collector_loop, daemon=True)
        self._collector_thread.start()
        self.is_running = True
        logger.info("高性能流量生成器已启动")

    def stop(self):
        """停止整个流水线（进程 + 采集线程）"""
        self.is_running = False
        # 避免采集线程中调用 stop 导致 self-join 阻塞
        if threading.current_thread() is not self._collector_thread:
            self.config_generator.stop()
            self.packet_builder.stop()
        self._collector_stop.set()
        if self._collector_thread:
            self._collector_thread.join(timeout=2)
        logger.info("高性能流量生成器已停止")

    # 任务提交：仅提交，不等待；配置与报文将经由队列逐步流出到本地缓冲
    def submit_tcp_flow(self, flow_spec: Dict, count: int = 0):
        """提交 TCP 流任务（异步）
        
        参数：
          flow_spec(dict): 流规范（参见 plan_tcp_flow_packet_configs_iter）
          count(int): 实际包数上限；<=0 表示不限制
        行为：
          - 将任务入队到 config_task_queue，由配置生成进程异步展开
          - 默认源/目的 MAC 由父进程生成后随任务传递，保证跨进程一致
        返回：None
        """
        # 发生致命错误时直接抛出
        self._ensure_no_fatal()
        # 确保父进程先生成一次默认MAC并复用
        mac_src_default, mac_dst_default = mac_manager.get_default_mac_src(), mac_manager.get_default_mac_dst()
        # 注入 flow_id（未提供则自动生成）
        fs = dict(flow_spec or {})
        if 'flow_id' not in fs or not fs.get('flow_id'):
            fs['flow_id'] = f"flow-{uuid.uuid4()}"
        self.config_task_queue.put({'type': 'tcp_flow', 'flow_spec': fs, 'count': count,
                                    'mac_src_default': mac_src_default, 'mac_dst_default': mac_dst_default})

    def submit_udp_flow(self, flow_spec: Dict, count: int = 0):
        """提交 UDP 流任务（异步）
        
        参数：
          flow_spec(dict): 流规范（参见 plan_udp_flow_packet_configs_iter）
          count(int): 实际包数上限；<=0 表示不限制
        返回：None
        """
        # 发生致命错误时直接抛出
        self._ensure_no_fatal()
        mac_src_default, mac_dst_default = mac_manager.get_default_mac_src(), mac_manager.get_default_mac_dst()
        fs = dict(flow_spec or {})
        if 'flow_id' not in fs or not fs.get('flow_id'):
            fs['flow_id'] = f"flow-{uuid.uuid4()}"
        self.config_task_queue.put({'type': 'udp_flow', 'flow_spec': fs, 'count': count,
                                    'mac_src_default': mac_src_default, 'mac_dst_default': mac_dst_default})

    def submit_http_sessions(self, http_spec: Dict, count: int = 0):
        """提交 HTTP 会话任务（异步）
        
        参数：
          http_spec(dict): 会话规范（参见 plan_http_sessions_iter）
          count(int): 实际包数上限；<=0 表示不限制
        返回：None
        """
        self._ensure_no_fatal()
        mac_src_default, mac_dst_default = mac_manager.get_default_mac_src(), mac_manager.get_default_mac_dst()
        spec = dict(http_spec or {})
        if 'flow_id' not in spec or not spec.get('flow_id'):
            spec['flow_id'] = f"flow-{uuid.uuid4()}"
        self.config_task_queue.put({'type': 'http_session', 'http_spec': spec, 'count': count,
                                    'mac_src_default': mac_src_default, 'mac_dst_default': mac_dst_default})

    # ------------ 按类速率配置 ------------
    def set_class_rate_limit(self, class_id: str, bps: Union[int, str], burst_bytes: int = 65536):
        """设置/更新某类的速率限制（bits per second）
        - 运行中调用立即生效，报文进程共享同一个 limiter
        """
        rate_bps = _parse_bps_to_int(bps)
        if class_id not in self._class_rate_limiters:
            self._class_rate_limiters[class_id] = SharedTokenBucket(rate_bps, burst_bytes)
        else:
            # 简单地替换为新的 limiter（并行情况可轻微抖动）
            self._class_rate_limiters[class_id] = SharedTokenBucket(rate_bps, burst_bytes)

    def clear_class_rate_limits(self):
        self._class_rate_limiters.clear()

    # ------------ 批量混合流量生成 ------------
    def start_batch_mixed(self, batch_spec: Dict) -> 'BatchMixedRunner':
        """启动批量混合流量生成
        
        参数：
          batch_spec(dict): 批量配置规范
            classes: [{'id': 'tcpA', 'type': 'tcp', 'bps': '200k', 'tuples': {...}, 'tcp': {...}}, ...]
            flows: {'count': 0}  # 0=无限；>0=总流数限制
        返回：
          BatchMixedRunner: 喂料器实例，用于控制和状态查询
        """
        runner = BatchMixedRunner(self, batch_spec)
        runner.start()
        return runner

    def get_packets(self, count: Optional[int] = None, mode: str = 'combined') -> List[Dict]:
        """从主进程缓冲批量获取报文
        
        参数：
          count(int|None): 期望获取的数量；None 表示全部可用
        返回：
          List[Dict]: [{ 'packet': bytes, 'metadata': dict, 'timestamp': float }, ...]
        """
        # 发生致命错误时直接抛出
        self._ensure_no_fatal()
        target = (mode or 'combined').lower()
        buf = None
        if target == 'combined':
            buf = self.combined_buffer
        elif target == 'up':
            buf = self.up_buffer
        elif target == 'down':
            buf = self.down_buffer
        else:
            raise ValueError(f"未知的 mode: {mode}. 允许: combined|up|down")
        if buf is None:
            return []
        if count is None:
            count = buf.size()
        return buf.get_batch(count)

    def get_buffer_status(self) -> Dict:
        """获取当前缓冲与队列状态
        
        返回：
          {
            'buffer_size': 环形缓冲容量,
            'current_size': 当前环形缓冲已存条目数,
            'config_queue_depth': 配置队列深度（近似值，跨平台安全）,
            'packet_queue_depth': 报文队列深度（近似值，跨平台安全）,
            'config_processes': 配置进程数,
            'packet_processes': 报文进程数,
            'is_running': 是否已启动
          }
        """
        status = {
            'buffer_size': self.buffer_size,
            'current_size': self.combined_buffer.size() if self.combined_buffer else 0,
            'current_size_up': self.up_buffer.size() if self.up_buffer else 0,
            'current_size_down': self.down_buffer.size() if self.down_buffer else 0,
            'config_queue_depth': _safe_qsize(self.config_buffer_queue),
            'packet_queue_depth': _safe_qsize(self.packet_buffer_queue),
            'config_processes': self.config_processes,
            'packet_processes': self.packet_processes,
            'is_running': self.is_running,
        }
        if self._fatal_error_message:
            status['fatal_error'] = self._fatal_error_message
        return status

    def _ensure_no_fatal(self):
        if self._fatal_error_message:
            raise RuntimeError(self._fatal_error_message)

# ================================
#  以下为报文构造与流规划的实现
# ================================

# -------- 工具函数：队列与基础构造 --------
def _safe_qsize(q: Queue) -> int:
    """跨平台安全获取队列大致长度
    
    参数：
      q(Queue): 目标队列
    返回：
      int: 近似深度；若不支持/异常则返回 0
    说明：
      某些平台（如 Windows 的 multiprocessing.Queue）可能不支持 qsize，需容错。
    """
    try:
        return q.qsize()
    except Exception:
        return 0

# 校验和与基础首部构造
def _checksum(data: bytes) -> int:
    """计算 16 位校验和（大端）
    
    用于 IPv4、TCP/UDP 伪首部等校验计算。
    """
    if len(data) % 2 != 0:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def _mac_to_bytes(mac: str) -> bytes:
    """MAC 字符串（aa:bb:cc:dd:ee:ff）转 bytes"""
    return bytes.fromhex(mac.replace(":", ""))

def _ipv4_to_bytes(ip: str) -> bytes:
    """IPv4 字符串（x.x.x.x）转 bytes（network order）"""
    return socket.inet_aton(ip)

def _build_eth_header(mac_dst: str, mac_src: str, ethertype: int, vlan: Optional[dict]) -> bytes:
    """构造二层以太网首部（可选 802.1Q VLAN）
    
    参数：
      mac_dst/mac_src(str): 目的/源 MAC
      ethertype(int): 上层协议类型（0x0800=IPv4）
      vlan(dict|None): { enable, id, priority, cfi }（若提供 vlan 则默认启用，除非 enable=False）
    返回：bytes
    """
    dst = _mac_to_bytes(mac_dst)
    src = _mac_to_bytes(mac_src)
    if vlan and vlan.get('enable', True):
        vlan_id = int(vlan.get('id', 1))
        vlan_pri = int(vlan.get('priority', 0))
        vlan_cfi = int(vlan.get('cfi', 0))
        tci = (vlan_pri << 13) | (vlan_cfi << 12) | vlan_id
        return dst + src + struct.pack('!HHH', 0x8100, tci, ethertype)
    return dst + src + struct.pack('!H', ethertype)

def _build_ipv4_header(src: str, dst: str, ttl: int, tos: int, proto: int, total_len: int, ip_id: int = None, flags: int = 0) -> bytes:
    """构造 IPv4 首部（无选项）并自动填充头部校验和
    
    参数：
      src/dst(str): 源/目的 IPv4 地址
      ttl(int): 存活时间（8 位）
      tos(int): 服务类型（8 位 DSCP/ECN）
      proto(int): 上层协议号（TCP=6, UDP=17）
      total_len(int): IP 层总长度（IP 头 + 上层头 + 负载）
      ip_id(int|None): 标识；None 时随机
      flags(int): 标志与分段高 3 位（此处仅占位，未含片偏移）
    返回：bytes: IPv4 首部（20 字节）
    """
    ver_ihl = 0x45
    dscp_ecn = tos & 0xFF
    total_length = total_len
    identification = ip_id if ip_id is not None else random.randint(1, 65535)
    flags_frag = (flags & 0x7) << 13
    header = struct.pack('!BBHHHBBH4s4s',
                         ver_ihl, dscp_ecn, total_length,
                         identification, flags_frag,
                         ttl & 0xFF, proto & 0xFF, 0,
                         _ipv4_to_bytes(src), _ipv4_to_bytes(dst))
    csum = _checksum(header)
    header = header[:10] + struct.pack('!H', csum) + header[12:]
    return header

def _build_udp_header(sport: int, dport: int, payload_len: int, src_ip: str, dst_ip: str) -> bytes:
    """构造 UDP 首部并计算校验（含伪首部）
    
    参数：
      sport/dport(int): 源/目的端口
      payload_len(int): UDP 负载长度
      src_ip/dst_ip(str): 源/目的 IPv4
    返回：bytes: UDP 首部（8 字节）
    """
    length = 8 + payload_len
    pseudo = _ipv4_to_bytes(src_ip) + _ipv4_to_bytes(dst_ip) + struct.pack('!BBH', 0, 17, length)
    header = struct.pack('!HHHH', sport, dport, length, 0)
    csum = _checksum(pseudo + header + (b"\x00" * payload_len))
    return struct.pack('!HHHH', sport, dport, length, csum)

def _build_tcp_header(sport: int, dport: int, seq: int, ack: int, flags: int, window: int,
                      src_ip: str, dst_ip: str, payload: bytes = b"", options: bytes = b"", urgent_ptr: int = 0) -> bytes:
    """构造 TCP 首部（可包含对齐填充后的选项）并计算校验（含伪首部）
    
    参数：
      sport/dport(int): 源/目的端口
      seq/ack(int): 序列号/确认号（32 位）
      flags(int): 标志位（SYN=0x02, ACK=0x10, FIN=0x01 等）
      window(int): 窗口大小
      src_ip/dst_ip(str): 源/目的 IPv4
      payload(bytes): 负载，用于校验
      options(bytes): TCP 选项，函数内会按 4 字节对齐
      urgent_ptr(int): 紧急指针
    返回：bytes: TCP 首部（含选项，长度为 4 字节对齐）
    """
    data_offset = (20 + len(options) + 3) // 4
    header_wo_sum = struct.pack('!HHIIHHHH',
                                sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                                ((data_offset & 0xF) << 12) | (flags & 0x1FF),
                                window & 0xFFFF, 0, urgent_ptr & 0xFFFF)
    if options:
        if len(options) % 4 != 0:
            options += b"\x01" * (4 - len(options) % 4)
        header_wo_sum += options
    tcp_len = len(header_wo_sum) + len(payload)
    pseudo = _ipv4_to_bytes(src_ip) + _ipv4_to_bytes(dst_ip) + struct.pack('!BBH', 0, 6, tcp_len)
    csum = _checksum(pseudo + header_wo_sum + payload)
    header = header_wo_sum[:16] + struct.pack('!H', csum) + header_wo_sum[18:]
    return header

def _build_tcp_options(mss: Optional[int], wscale: Optional[int], sack_permitted: bool, ts_val: Optional[int], ts_ecr: Optional[int]) -> bytes:
    """按需组装 TCP 选项，并填充到 4 字节对齐
    
    参数：
      mss(int|None): 最大报文段长度
      wscale(int|None): 窗口缩放（0-14）
      sack_permitted(bool): 是否允许 SACK
      ts_val/ts_ecr(int|None): 时间戳选项（值/回显）
    返回：bytes: 选项序列（已对齐）
    """
    opts = bytearray()
    if mss is not None:
        opts += struct.pack('!BBH', 2, 4, int(mss))
    if sack_permitted:
        opts += struct.pack('!BB', 4, 2)
    if wscale is not None:
        w = max(0, min(14, int(wscale)))
        opts += struct.pack('!BBB', 3, 3, w)
    if ts_val is not None:
        opts += struct.pack('!BBII', 8, 10, int(ts_val) & 0xFFFFFFFF, int(ts_ecr or 0) & 0xFFFFFFFF)
    if len(opts) % 4 != 0:
        opts += b"\x01" * (4 - len(opts) % 4)
    return bytes(opts)

# -------- 报文构造（可被多进程调用的静态函数） --------
def build_packet_from_config_static(cfg: dict) -> bytes:
    """根据"单包配置"构造完整以太帧
    
    参数：
      cfg(dict):
        l2(dict):
          - src(str): 源 MAC
          - dst(str): 目的 MAC
          - vlan(dict|None): 可选 VLAN 配置
        l3(dict):
          - src/dst(str): 源/目的 IPv4
          - ttl(int): 生存时间
          - tos(int): DSCP/ECN
          - id(int|None): IP 标识
          - flags(int): 标志（高 3 位）
        l4(dict):
          - proto(str): 'TCP' 或 'UDP'
          - TCP 时需: sport, dport, seq, ack, flags, window, urgent(optional), mss/wscale/sack/ts_val/ts_ecr(optional)
          - UDP 时需: sport, dport
        payload(bytes): 负载
    返回：bytes: 完整以太帧（L2+L3+L4+payload）
    """
    l4 = cfg.get('l4', {})
    l3 = cfg.get('l3', {})
    l2 = cfg.get('l2', {})
    payload: bytes = cfg.get('payload', b'') or b''

    proto = l4.get('proto', 'TCP').upper()
    ip_proto_num = 6 if proto == 'TCP' else 17 if proto == 'UDP' else 1

    # L4
    if proto == 'UDP':
        udp_hdr = _build_udp_header(l4['sport'], l4['dport'], len(payload), l3['src'], l3['dst'])
        l4_bytes = udp_hdr
    else:
        options = _build_tcp_options(l4.get('mss'), l4.get('wscale'), bool(l4.get('sack', False)), l4.get('ts_val'), l4.get('ts_ecr'))
        tcp_hdr = _build_tcp_header(l4['sport'], l4['dport'], l4.get('seq', 0), l4.get('ack', 0), l4.get('flags', 0x10),
                                    l4.get('window', 65535), l3['src'], l3['dst'], payload, options, l4.get('urgent', 0))
        l4_bytes = tcp_hdr

    # L3 (IPv4 only in this implementation)
    total_len = (20 + len(l4_bytes) + len(payload))
    ip_hdr = _build_ipv4_header(l3['src'], l3['dst'], l3.get('ttl', 64), l3.get('tos', 0), ip_proto_num, total_len,
                                l3.get('id'), l3.get('flags', 0))

    # L2
    eth = _build_eth_header(l2['dst'], l2['src'], 0x0800, l2.get('vlan'))

    return eth + ip_hdr + l4_bytes + payload

# -------- TCP 流规划（将流参数展开为报文级配置） --------
# 兼容批量接口删除，仅保留迭代式流式接口


def plan_tcp_flow_packet_configs_iter(flow_spec: Dict, mac_src_default: str, mac_dst_default: str):
    """TCP 流规划（生成器）
    
    参数：
      flow_spec(dict): 流规范
        - handshake(bool): 是否包含三次握手（默认 True）
        - termination(bool): 是否包含四次挥手（默认 True）
        - mss(int|None): MSS 选项
        - tcp_wscale(int|None): 窗口缩放
        - tcp_sack_permitted(bool): 允许 SACK
        - tcp_ts_val/tcp_ts_ecr(int|None): 时间戳选项
        - uplink(dict): 上行方向配置（字段详见下方）
        - downlink(dict): 下行方向配置（未提供项默认镜像自上行）
          方向配置字段：
            mac_src/mac_dst(str)、ip_src/ip_dst(str)、sport/dport(int)、ttl/tos(int)、vlan(dict)、
            payload(bytes 可选) 或 payload_length(int 可选)
      mac_src_default(str): 默认上行源 MAC（由父进程生成并传递）
      mac_dst_default(str): 默认上行目的 MAC（由父进程生成并传递）
    返回：Iterator[dict]: 连续产出"单包配置"
    说明：
      - 严格流式（逐个 yield），不做整体聚合
      - 未给定的四元组字段将使用 DefaultTupleManager 的默认值
    """
    handshake = bool(flow_spec.get('handshake', True))
    termination = bool(flow_spec.get('termination', True))
    up = flow_spec.get('uplink', {})
    down = flow_spec.get('downlink', {})

    # 解析/填充默认项（只在未指定时使用默认/自动）
    mac_src = up.get('mac_src') or mac_src_default
    mac_dst = up.get('mac_dst') or mac_dst_default
    ip_src = up.get('ip_src') or tuple_manager.get_default_ip_src()
    ip_dst = up.get('ip_dst') or tuple_manager.get_default_ip_dst()
    sport = up.get('sport') or tuple_manager.get_default_sport()
    dport = up.get('dport') or tuple_manager.get_default_dport()

    # 下行若未指定，按上行对称
    mac_src_d = down.get('mac_src') or mac_dst_default
    mac_dst_d = down.get('mac_dst') or mac_src_default
    ip_src_d = down.get('ip_src') or ip_dst
    ip_dst_d = down.get('ip_dst') or ip_src
    sport_d = down.get('sport') or dport
    dport_d = down.get('dport') or sport

    vlan_up = up.get('vlan')
    vlan_down = down.get('vlan')

    # 支持vlan为整数(直接作为vlan id)或字典
    def normalize_vlan(v):
        if v is None:
            return None
        if isinstance(v, dict):
            return v
        if isinstance(v, int):
            return {'id': v, 'enable': True}
        return None

    vlan_up = normalize_vlan(vlan_up)
    vlan_down = normalize_vlan(vlan_down)

    ttl_up = up.get('ttl', 64); tos_up = up.get('tos', 0)
    ttl_down = down.get('ttl', 64); tos_down = down.get('tos', 0)

    def l2(src, dst, vlan):
        return {'src': src, 'dst': dst, 'vlan': vlan}

    def l3(src, dst, ttl, tos):
        return {'src': src, 'dst': dst, 'ttl': ttl, 'tos': tos}

    # 初始序列号
    x = random.randint(0, 0xFFFFFFFF)
    y = random.randint(0, 0xFFFFFFFF)

    directionless = bool(flow_spec.get('directionless', False))
    store_mode = 'combined' if directionless else 'directional'

    def emit(direction: str, l4_fields: dict, payload: bytes = b""):
        if direction == 'up':
            yield {
                'l2': l2(mac_src, mac_dst, vlan_up),
                'l3': l3(ip_src, ip_dst, ttl_up, tos_up),
                'l4': l4_fields,
                'payload': payload,
                'metadata': {
                    'dir': 'up',
                    'flow_id': flow_spec.get('flow_id'),
                    'packet_index': None,
                    'store': store_mode,
                    'class_id': flow_spec.get('class_id')
                }
            }
        else:
            yield {
                'l2': l2(mac_src_d, mac_dst_d, vlan_down),
                'l3': l3(ip_src_d, ip_dst_d, ttl_down, tos_down),
                'l4': l4_fields,
                'payload': payload,
                'metadata': {
                    'dir': 'down',
                    'flow_id': flow_spec.get('flow_id'),
                    'packet_index': None,
                    'store': store_mode,
                    'class_id': flow_spec.get('class_id')
                }
            }

    # 1) 握手
    mss = flow_spec.get('mss')
    wscale = flow_spec.get('tcp_wscale')
    sack = bool(flow_spec.get('tcp_sack_permitted', False))
    ts_val = flow_spec.get('tcp_ts_val'); ts_ecr = flow_spec.get('tcp_ts_ecr')
    pkt_idx = 0
    if handshake:
        for cfg in emit('up',   {'proto': 'TCP', 'sport': sport,   'dport': dport,   'seq': x,   'ack': 0,     'flags': 0x02, 'mss': mss, 'wscale': wscale, 'sack': sack, 'ts_val': ts_val, 'ts_ecr': ts_ecr}):
            cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
        for cfg in emit('down', {'proto': 'TCP', 'sport': sport_d, 'dport': dport_d, 'seq': y,   'ack': (x+1) & 0xFFFFFFFF, 'flags': 0x12, 'mss': mss, 'wscale': wscale, 'sack': sack, 'ts_val': ts_val, 'ts_ecr': ts_ecr}):
            cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
        for cfg in emit('up',   {'proto': 'TCP', 'sport': sport,   'dport': dport,   'seq': (x+1) & 0xFFFFFFFF, 'ack': (y+1) & 0xFFFFFFFF, 'flags': 0x10, 'ts_val': ts_val, 'ts_ecr': ts_ecr}):
            cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
        x = (x + 1) & 0xFFFFFFFF
        y = (y + 1) & 0xFFFFFFFF

    # 2) 数据阶段
    def extract_payload(side: dict) -> bytes:
        """提取方向负载
        - 若 side.payload 存在且非空：
            - bytes/bytearray: 直接使用
            - dict(策略): 用BodyGenerator生成
            - 其他: 转bytes
        - 若 side.payload 缺失或为空：按 side.payload_length 生成随机 bytes
        """
        if side is None:
            return b''
        if 'payload' in side and side['payload']:
            raw = side['payload']
            if isinstance(raw, (bytes, bytearray)):
                try:
                    side['payload_length'] = len(raw)
                except Exception:
                    pass
                return raw
            if isinstance(raw, dict):
                # payload策略字典 -> 用BodyGenerator生成
                try:
                    bg = BodyGenerator(raw, debug_mode=False)
                    data = bg.next_body()
                    try:
                        side['payload_length'] = len(data)
                    except Exception:
                        pass
                    return data
                except Exception:
                    pass
            data = str(raw).encode('utf-8')
            try:
                side['payload_length'] = len(data)
            except Exception:
                pass
            return data
        ln = int(side.get('payload_length', 0) or 0)
        if ln > 0:
            return os.urandom(ln)
        return b''

    up_data = extract_payload(up)
    if up_data:
        seg_size = int(mss) if mss not in (None, 0) else len(up_data)
        if seg_size <= 0:
            seg_size = len(up_data)
        idx = 0
        while idx < len(up_data):
            chunk = up_data[idx: idx + seg_size]
            for cfg in emit('up',   {'proto': 'TCP', 'sport': sport,   'dport': dport,   'seq': x, 'ack': y, 'flags': 0x18, 'ts_val': ts_val, 'ts_ecr': ts_ecr}, chunk):
                cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
            x = (x + len(chunk)) & 0xFFFFFFFF
        for cfg in emit('down', {'proto': 'TCP', 'sport': sport_d, 'dport': dport_d, 'seq': y, 'ack': x, 'flags': 0x10, 'ts_val': ts_val, 'ts_ecr': ts_ecr}):
            cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
        idx += seg_size

    down_data = extract_payload(down)
    if down_data:
        seg_size_d = int(mss) if mss not in (None, 0) else len(down_data)
        if seg_size_d <= 0:
            seg_size_d = len(down_data)
        idx = 0
        while idx < len(down_data):
            chunk = down_data[idx: idx + seg_size_d]
            for cfg in emit('down', {'proto': 'TCP', 'sport': sport_d, 'dport': dport_d, 'seq': y, 'ack': x, 'flags': 0x18, 'ts_val': ts_val, 'ts_ecr': ts_ecr}, chunk):
                cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
            y = (y + len(chunk)) & 0xFFFFFFFF
        for cfg in emit('up',   {'proto': 'TCP', 'sport': sport,   'dport': dport,   'seq': x, 'ack': y, 'flags': 0x10, 'ts_val': ts_val, 'ts_ecr': ts_ecr}):
            cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
        idx += seg_size_d

    # 3) 终止（三包模式：FIN/ACK → FIN/ACK → ACK）
    if termination:
        # 上行：FIN+ACK
        for cfg in emit('up',   {'proto': 'TCP', 'sport': sport,   'dport': dport,   'seq': x,   'ack': y, 'flags': 0x01 | 0x10, 'ts_val': ts_val, 'ts_ecr': ts_ecr}):
            cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
        # 下行：FIN+ACK（对上行 FIN 的确认）
        for cfg in emit('down', {'proto': 'TCP', 'sport': sport_d, 'dport': dport_d, 'seq': y,   'ack': (x+1) & 0xFFFFFFFF, 'flags': 0x01 | 0x10, 'ts_val': ts_val, 'ts_ecr': ts_ecr}):
            cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
        # 上行：ACK 收尾
        for cfg in emit('up',   {'proto': 'TCP', 'sport': sport,   'dport': dport,   'seq': (x+1) & 0xFFFFFFFF, 'ack': (y+1) & 0xFFFFFFFF, 'flags': 0x10, 'ts_val': ts_val, 'ts_ecr': ts_ecr}):
            cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg

# -------- UDP 流规划（简单请求/响应） --------
# 兼容批量接口删除，仅保留迭代式流式接口


def plan_udp_flow_packet_configs_iter(flow_spec: Dict, mac_src_default: str, mac_dst_default: str):
    """UDP 流规划（生成器）
    
    参数：
      flow_spec(dict): 流规范
        - uplink(dict): 上行方向字段（同 TCP 流规划）
        - downlink(dict): 下行方向字段（同 TCP 流规划）
      mac_src_default(str): 默认上行源 MAC
      mac_dst_default(str): 默认上行目的 MAC
    返回：Iterator[dict]: 单包配置（上行 1 包，下行可选 1 包）
    说明：逐条 yield，保证边生成边缓存。
    """
    up = flow_spec.get('uplink', {})
    down = flow_spec.get('downlink', {})

    mac_src = up.get('mac_src') or mac_src_default
    mac_dst = up.get('mac_dst') or mac_dst_default
    ip_src = up.get('ip_src') or tuple_manager.get_default_ip_src()
    ip_dst = up.get('ip_dst') or tuple_manager.get_default_ip_dst()
    sport = up.get('sport') or tuple_manager.get_default_sport()
    dport = up.get('dport') or tuple_manager.get_default_dport()

    mac_src_d = down.get('mac_src') or mac_dst_default
    mac_dst_d = down.get('mac_dst') or mac_src_default
    ip_src_d = down.get('ip_src') or ip_dst
    ip_dst_d = down.get('ip_dst') or ip_src
    sport_d = down.get('sport') or dport
    dport_d = down.get('dport') or sport

    vlan_up = up.get('vlan'); vlan_down = down.get('vlan')

    # 支持vlan为整数(直接作为vlan id)或字典
    def normalize_vlan(v):
        if v is None:
            return None
        if isinstance(v, dict):
            return v
        if isinstance(v, int):
            return {'id': v, 'enable': True}
        return None

    vlan_up = normalize_vlan(vlan_up)
    vlan_down = normalize_vlan(vlan_down)

    ttl_up = up.get('ttl', 64); tos_up = up.get('tos', 0)
    ttl_down = down.get('ttl', 64); tos_down = down.get('tos', 0)

    def l2(src, dst, vlan):
        return {'src': src, 'dst': dst, 'vlan': vlan}
    def l3(src, dst, ttl, tos):
        return {'src': src, 'dst': dst, 'ttl': ttl, 'tos': tos}

    def extract_payload(side: dict) -> bytes:
        """提取方向负载（UDP）
        - 若 side.payload 存在且非空：转 bytes 并自动回填 payload_length
        - 否则：按 payload_length 生成随机 bytes
        """
        if side is None:
            return b''
        if 'payload' in side and side['payload']:
            raw = side['payload']
            data = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode('utf-8')
            try:
                side['payload_length'] = len(data)
            except Exception:
                pass
            return data
        ln = int(side.get('payload_length', 0) or 0)
        return os.urandom(ln) if ln > 0 else b''

    directionless = bool(flow_spec.get('directionless', False))
    store_mode = 'combined' if directionless else 'directional'

    up_data = extract_payload(up)
    down_data = extract_payload(down)
    yield {'l2': l2(mac_src, mac_dst, vlan_up), 'l3': l3(ip_src, ip_dst, ttl_up, tos_up), 'l4': {'proto': 'UDP', 'sport': sport, 'dport': dport}, 'payload': up_data,
           'metadata': {'dir': 'up', 'flow_id': flow_spec.get('flow_id'), 'packet_index': 0, 'store': store_mode, 'class_id': flow_spec.get('class_id')}}
    if down or down_data:
        yield {'l2': l2(mac_src_d, mac_dst_d, vlan_down), 'l3': l3(ip_src_d, ip_dst_d, ttl_down, tos_down), 'l4': {'proto': 'UDP', 'sport': sport_d, 'dport': dport_d}, 'payload': down_data,
               'metadata': {'dir': 'down', 'flow_id': flow_spec.get('flow_id'), 'packet_index': 1, 'store': store_mode, 'class_id': flow_spec.get('class_id')}}

# 旧批量接口删除，改为 submit_* 异步流式接口



# ---------------- HTTP 会话规划（HTTP/1.1 keep-alive，多事务，严格流式） ----------------

def _http_build_request_bytes(req: Dict, host_default: str = None) -> bytes:
    """构造 HTTP/1.1 请求报文字节（含头与可选 body）"""
    method = (req.get('method') or 'GET').upper()
    path = req.get('path') or '/'
    headers = dict(req.get('headers') or {})
    # 兼容 'http.host' 别名
    for k in list(headers.keys()):
        if str(k).lower() == 'http.host' and 'Host' not in headers and 'host' not in {x.lower():1 for x in headers.keys()}:
            headers['Host'] = headers.pop(k)
    body = req.get('body', b'') or b''
    if not body:
        ln = int(req.get('body_length', 0) or 0)
        if ln > 0:
            body = os.urandom(ln)
    # 默认头
    has_host = any(k.lower() == 'host' for k in headers)
    if not has_host:
        headers['Host'] = (host_default or 'example.com')
    if not any(k.lower() == 'connection' for k in headers):
        headers['Connection'] = 'keep-alive'
    if body and not any(k.lower() == 'content-length' for k in headers):
        headers['Content-Length'] = str(len(body))
    # 拼接
    start = f"{method} {path} HTTP/1.1\r\n".encode('ascii')
    hdrs = b"".join(f"{k}: {v}\r\n".encode('ascii') for k, v in headers.items())
    return start + hdrs + b"\r\n" + body


def _http_build_response_bytes(resp: Dict) -> bytes:
    """构造 HTTP/1.1 响应报文字节（含头与可选 body）"""
    status = int(resp.get('status', 200))
    reason = resp.get('reason') or 'OK'
    headers = dict(resp.get('headers') or {})
    body = resp.get('body', b'') or b''
    if not body:
        ln = int(resp.get('body_length', 0) or 0)
        if ln > 0:
            body = os.urandom(ln)
    if not any(k.lower() == 'connection' for k in headers):
        headers['Connection'] = 'keep-alive'
    if not any(k.lower() == 'content-length' for k in headers):
        headers['Content-Length'] = str(len(body))
    start = f"HTTP/1.1 {status} {reason}\r\n".encode('ascii')
    hdrs = b"".join(f"{k}: {v}\r\n".encode('ascii') for k, v in headers.items())
    return start + hdrs + b"\r\n" + body


def plan_http_sessions_iter(http_spec: Dict, mac_src_default: str, mac_dst_default: str):
    """HTTP/1.1 会话规划（生成器，严格流式）
    
    http_spec:
      - handshake(bool): 是否三次握手（默认 True）
      - termination(bool): 是否四次挥手（默认 True）
      - mss(int|None): TCP MSS（用于分段大小）
      - tcp_wscale/tcp_sack_permitted/tcp_ts_val/tcp_ts_ecr: TCP 选项
      - directionless(bool): 是否将所有条目写入 combined 缓冲
      - uplink/downlink(dict): 参照 TCP 流规划（L2/L3/L4 缺省参数）
      - sessions(List[dict]): 多个事务 { request: {...}, response: {...}, think_time_ms?: int }
      - think_time_ms(int|None): 默认事务思考时间（毫秒），每个 session 可覆盖
    逐条 yield 单包配置，metadata 含：app, txn_index, req_or_resp。
    """
    handshake = bool(http_spec.get('handshake', True))
    termination = bool(http_spec.get('termination', True))
    up = http_spec.get('uplink', {})
    down = http_spec.get('downlink', {})

    # 解析/填充默认项
    mac_src = up.get('mac_src') or mac_src_default
    mac_dst = up.get('mac_dst') or mac_dst_default
    ip_src = up.get('ip_src') or tuple_manager.get_default_ip_src()
    ip_dst = up.get('ip_dst') or tuple_manager.get_default_ip_dst()
    sport = up.get('sport') or tuple_manager.get_default_sport()
    dport = up.get('dport') or tuple_manager.get_default_dport()

    mac_src_d = down.get('mac_src') or mac_dst_default
    mac_dst_d = down.get('mac_dst') or mac_src_default
    ip_src_d = down.get('ip_src') or ip_dst
    ip_dst_d = down.get('ip_dst') or ip_src
    sport_d = down.get('sport') or dport
    dport_d = down.get('dport') or sport

    vlan_up = up.get('vlan')
    vlan_down = down.get('vlan')

    # 支持vlan为整数(直接作为vlan id)或字典
    def normalize_vlan(v):
        if v is None:
            return None
        if isinstance(v, dict):
            return v
        if isinstance(v, int):
            return {'id': v, 'enable': True}
        return None

    vlan_up = normalize_vlan(vlan_up)
    vlan_down = normalize_vlan(vlan_down)

    ttl_up = up.get('ttl', 64); tos_up = up.get('tos', 0)
    ttl_down = down.get('ttl', 64); tos_down = down.get('tos', 0)

    def l2(src, dst, vlan):
        return {'src': src, 'dst': dst, 'vlan': vlan}
    def l3(src, dst, ttl, tos):
        return {'src': src, 'dst': dst, 'ttl': ttl, 'tos': tos}

    # 初始序列号
    x = random.randint(0, 0xFFFFFFFF)  # client->server seq
    y = random.randint(0, 0xFFFFFFFF)  # server->client seq

    directionless = bool(http_spec.get('directionless', False))
    store_mode = 'combined' if directionless else 'directional'

    def emit(direction: str, l4_fields: dict, payload: bytes = b"", txn_index: int = -1, rr: str = None):
        meta = {
            'dir': 'up' if direction == 'up' else 'down',
            'flow_id': http_spec.get('flow_id'),
            'packet_index': None,
            'store': store_mode,
            'app': 'http',
            'txn_index': txn_index if txn_index is not None else -1,
            'req_or_resp': rr or '',
            'class_id': http_spec.get('class_id')
        }
        if direction == 'up':
            yield {'l2': l2(mac_src, mac_dst, vlan_up), 'l3': l3(ip_src, ip_dst, ttl_up, tos_up), 'l4': l4_fields, 'payload': payload, 'metadata': meta}
        else:
            yield {'l2': l2(mac_src_d, mac_dst_d, vlan_down), 'l3': l3(ip_src_d, ip_dst_d, ttl_down, tos_down), 'l4': l4_fields, 'payload': payload, 'metadata': meta}

    # 握手与可变参数生成器（仅当未直接给定 sessions 时启用生成器）
    mss = http_spec.get('mss')
    http_gen_for_runtime = None
    sessions_input = http_spec.get('sessions')
    if not sessions_input:
        # 延迟具体化：按策略在配置进程生成 request/response 内容
        http_gen_for_runtime = EnhancedHttpRandomGenerator(http_spec)
        if mss in (None, 0):
            try:
                mss = http_gen_for_runtime.next_mss()
            except Exception:
                mss = None
    wscale = http_spec.get('tcp_wscale')
    sack = bool(http_spec.get('tcp_sack_permitted', False))
    ts_val = http_spec.get('tcp_ts_val'); ts_ecr = http_spec.get('tcp_ts_ecr')
    pkt_idx = 0
    if handshake:
        for cfg in emit('up',   {'proto': 'TCP', 'sport': sport,   'dport': dport,   'seq': x,   'ack': 0,     'flags': 0x02, 'mss': mss, 'wscale': wscale, 'sack': sack, 'ts_val': ts_val, 'ts_ecr': ts_ecr}):
            cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
        for cfg in emit('down', {'proto': 'TCP', 'sport': sport_d, 'dport': dport_d, 'seq': y,   'ack': (x+1) & 0xFFFFFFFF, 'flags': 0x12, 'mss': mss, 'wscale': wscale, 'sack': sack, 'ts_val': ts_val, 'ts_ecr': ts_ecr}):
            cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
        for cfg in emit('up',   {'proto': 'TCP', 'sport': sport,   'dport': dport,   'seq': (x+1) & 0xFFFFFFFF, 'ack': (y+1) & 0xFFFFFFFF, 'flags': 0x10, 'ts_val': ts_val, 'ts_ecr': ts_ecr}):
            cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
        x = (x + 1) & 0xFFFFFFFF
        y = (y + 1) & 0xFFFFFFFF

    # 多事务循环
    if sessions_input:
        sessions = list(sessions_input)
        # think_time_ms: 若为常量则直接使用；若为 dict 则上层已具体化
        default_think_ms = int(http_spec.get('think_time_ms', 0) or 0) if not isinstance(http_spec.get('think_time_ms'), dict) else 0
    else:
        # 根据策略生成 sessions
        # sessions_per_flow: dict{'range':[min,max]} 或者整数/缺省
        n_sessions = 1
        spf = http_spec.get('sessions_per_flow')
        if isinstance(spf, dict) and 'range' in spf:
            try:
                r0, r1 = spf.get('range', [1, 1])
                n_sessions = random.randint(int(r0), int(r1))
            except Exception:
                n_sessions = 1
        elif isinstance(spf, int):
            n_sessions = max(1, spf)
        # 默认思考时间策略
        default_think_ms = 0
        tts = http_spec.get('think_time_ms')
        if isinstance(tts, dict) and 'range' in tts:
            try:
                r0, r1 = tts.get('range', [0, 0])
                default_think_ms = random.randint(int(r0), int(r1))
            except Exception:
                default_think_ms = 0
        elif isinstance(tts, int):
            default_think_ms = max(0, int(tts))

        sessions = []
        for _ in range(n_sessions):
            # 按策略即时生成
            method = http_gen_for_runtime.next_method()
            domain = http_gen_for_runtime.next_domain()
            uri = http_gen_for_runtime.next_uri()
            headers = http_gen_for_runtime.next_headers()
            headers['Host'] = domain
            req_body = http_gen_for_runtime.next_body() if method == 'POST' else b''
            resp_body = http_gen_for_runtime.next_body()
            # 每事务 think_time 可再次按策略波动
            txn_think_ms = default_think_ms
            if isinstance(tts, dict) and 'range' in tts:
                try:
                    r0, r1 = tts.get('range', [0, 0])
                    txn_think_ms = random.randint(int(r0), int(r1))
                except Exception:
                    txn_think_ms = default_think_ms
            sessions.append({
                'request': {'method': method, 'path': uri, 'headers': headers, 'body': req_body},
                'response': {'status': 200, 'reason': 'OK', 'headers': {'Content-Type': 'text/html'}, 'body': resp_body},
                'think_time_ms': txn_think_ms
            })

    def seg_and_ack(direction: str, data: bytes, txn_i: int, rr: str):
        nonlocal x, y, pkt_idx
        if not data:
            return
        seg_size = int(mss) if mss not in (None, 0) else len(data)
        if seg_size <= 0:
            seg_size = len(data)
        idx = 0
        if direction == 'up':
            while idx < len(data):
                chunk = data[idx: idx + seg_size]
                # 发送上行 PSH+ACK
                for cfg in emit('up', {'proto': 'TCP', 'sport': sport, 'dport': dport, 'seq': x, 'ack': y, 'flags': 0x18, 'ts_val': ts_val, 'ts_ecr': ts_ecr}, chunk, txn_i, rr):
                    cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
                x = (x + len(chunk)) & 0xFFFFFFFF
                # 下行 ACK
                for cfg in emit('down', {'proto': 'TCP', 'sport': sport_d, 'dport': dport_d, 'seq': y, 'ack': x, 'flags': 0x10, 'ts_val': ts_val, 'ts_ecr': ts_ecr}, b'', txn_i, rr):
                    cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
                idx += seg_size
        else:
            while idx < len(data):
                chunk = data[idx: idx + seg_size]
                # 发送下行 PSH+ACK
                for cfg in emit('down', {'proto': 'TCP', 'sport': sport_d, 'dport': dport_d, 'seq': y, 'ack': x, 'flags': 0x18, 'ts_val': ts_val, 'ts_ecr': ts_ecr}, chunk, txn_i, rr):
                    cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
                y = (y + len(chunk)) & 0xFFFFFFFF
                # 上行 ACK
                for cfg in emit('up', {'proto': 'TCP', 'sport': sport, 'dport': dport, 'seq': x, 'ack': y, 'flags': 0x10, 'ts_val': ts_val, 'ts_ecr': ts_ecr}, b'', txn_i, rr):
                    cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
                idx += seg_size

    host_default = http_spec.get('host') or ip_dst
    for i, txn in enumerate(sessions):
        req = dict((txn.get('request') or {}))
        resp = dict((txn.get('response') or {}))
        # 构造 request/response 字节
        req_bytes = _http_build_request_bytes(req, host_default)
        for cfg in seg_and_ack('up', req_bytes, i, 'req'):
            yield cfg
        # think_time：默认 0，可被 txn 覆盖
        think_ms = int(txn.get('think_time_ms', default_think_ms) or 0)
        if think_ms > 0:
            try:
                time.sleep(think_ms / 1000.0)
            except Exception:
                pass
        resp_bytes = _http_build_response_bytes(resp)
        for cfg in seg_and_ack('down', resp_bytes, i, 'resp'):
            yield cfg

    # 挥手
    if termination:
        for cfg in emit('up',   {'proto': 'TCP', 'sport': sport,   'dport': dport,   'seq': x,   'ack': y, 'flags': 0x01 | 0x10, 'ts_val': ts_val, 'ts_ecr': ts_ecr}):
            cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
        for cfg in emit('down', {'proto': 'TCP', 'sport': sport_d, 'dport': dport_d, 'seq': y,   'ack': (x+1) & 0xFFFFFFFF, 'flags': 0x01 | 0x10, 'ts_val': ts_val, 'ts_ecr': ts_ecr}):
            cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg
        for cfg in emit('up',   {'proto': 'TCP', 'sport': sport,   'dport': dport,   'seq': (x+1) & 0xFFFFFFFF, 'ack': (y+1) & 0xFFFFFFFF, 'flags': 0x10, 'ts_val': ts_val, 'ts_ecr': ts_ecr}):
            cfg['metadata']['packet_index'] = pkt_idx; pkt_idx += 1; yield cfg


# ================================
#  批量混合流量生成
# ================================

# -------- 四元组生成器（递增回绕/随机） --------
def _ip_to_int(ip: str) -> int:
    """IPv4 字符串转整数（网络字节序）"""
    import struct
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def _int_to_ip(val: int) -> str:
    """整数转 IPv4 字符串（网络字节序）"""
    import struct
    return socket.inet_ntoa(struct.pack("!I", val & 0xFFFFFFFF))


def _parse_ip_range(spec: str):
    """解析 IP 范围或 CIDR
    支持：'192.168.1.1-192.168.1.10' 或 '192.168.1.0/24'
    返回：(start_int, end_int)
    """
    spec = spec.strip()
    if '/' in spec:
        # CIDR
        ip, prefix = spec.split('/', 1)
        prefix_len = int(prefix)
        ip_int = _ip_to_int(ip)
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        network = ip_int & mask
        broadcast = network | (0xFFFFFFFF >> prefix_len)
        return network, broadcast
    elif '-' in spec:
        # 范围
        start_ip, end_ip = spec.split('-', 1)
        return _ip_to_int(start_ip.strip()), _ip_to_int(end_ip.strip())
    else:
        # 单个 IP
        ip_int = _ip_to_int(spec)
        return ip_int, ip_int


class ValueCycler:
    """递增回绕生成器（支持 step 与边界）"""
    def __init__(self, start: int, end: int, step: int = 1):
        self.start = start
        self.end = end
        self.step = max(1, step)
        self.current = start

    def next(self) -> int:
        val = self.current
        self.current += self.step
        if self.current > self.end:
            self.current = self.start
        return val


class ValueRandom:
    """随机生成器（可指定种子复现）"""
    def __init__(self, start: int, end: int, seed: int = None):
        self.start = start
        self.end = end
        self.rng = random.Random(seed)

    def next(self) -> int:
        return self.rng.randint(self.start, self.end)


class TupleGenerator:
    """四元组生成器：支持 IP/端口的递增回绕或随机"""
    def __init__(self, tuple_spec: Dict):
        """
        tuple_spec:
          ip_src: {'strategy': 'inc'|'rand', 'range': '10.0.0.1-10.0.3.254', 'step': 1, 'wrap': True, 'seed': None}
          ip_dst: 同上
          sport: {'strategy': 'inc'|'rand', 'range': [10000, 20000], 'step': 1, 'wrap': True, 'seed': None}
          dport: 同上
        """
        self.ip_src_gen = self._make_ip_generator(tuple_spec.get('ip_src', {}))
        self.ip_dst_gen = self._make_ip_generator(tuple_spec.get('ip_dst', {}))
        self.sport_gen = self._make_port_generator(tuple_spec.get('sport', {}))
        self.dport_gen = self._make_port_generator(tuple_spec.get('dport', {}))

    def _make_ip_generator(self, spec: Dict):
        strategy = spec.get('strategy', 'inc').lower()
        ip_range = spec.get('range', '192.168.1.1-192.168.1.254')
        start, end = _parse_ip_range(ip_range)
        if strategy == 'rand':
            return ValueRandom(start, end, spec.get('seed'))
        else:
            step = spec.get('step', 1)
            return ValueCycler(start, end, step)

    def _make_port_generator(self, spec: Dict):
        strategy = spec.get('strategy', 'inc').lower()
        port_range = spec.get('range', [1024, 65535])
        if isinstance(port_range, (list, tuple)) and len(port_range) >= 2:
            start, end = int(port_range[0]), int(port_range[1])
        else:
            start, end = 1024, 65535
        if strategy == 'rand':
            return ValueRandom(start, end, spec.get('seed'))
        else:
            step = spec.get('step', 1)
            return ValueCycler(start, end, step)

    def next4(self):
        """生成下一组四元组 (ip_src, ip_dst, sport, dport)"""
        return (
            _int_to_ip(self.ip_src_gen.next()),
            _int_to_ip(self.ip_dst_gen.next()),
            self.sport_gen.next(),
            self.dport_gen.next()
        )


# -------- HTTP 随机生成器 --------
class ListRandom:
    """从列表中随机选择"""
    def __init__(self, items: List[str], seed: int = None):
        self.items = list(items) if items else ['default']
        self.rng = random.Random(seed)

    def next(self) -> str:
        return self.rng.choice(self.items)


class PatternIncrementer:
    """模式递增：如 'www{n}.abc.com' 中的 {n} 递增回绕"""
    def __init__(self, pattern: str, n_start: int, n_end: int, step: int = 1):
        self.pattern = pattern
        self.cycler = ValueCycler(n_start, n_end, step)

    def next(self) -> str:
        n = self.cycler.next()
        return self.pattern.replace('{n}', str(n))


class BodyGenerator:
    """Body内容生成器，支持多种策略并优化内存使用"""
    def __init__(self, body_spec: Dict, debug_mode: bool = False):
        self.body_spec = body_spec
        self.debug_mode = debug_mode  # 调试模式：True=包含位置信息，False=不包含
        self._static_parts = {}  # 缓存静态部分
        self._file_cache = {}    # 缓存文件内容
        
    def _get_static_part(self, content: bytes, position: int = None) -> bytes:
        """获取或缓存静态内容
        
        参数：
            content(bytes): 要缓存的内容
            position(int): 在parts中的位置（可选）
        返回：
            bytes: 缓存的内容引用
        """
        # 基于内容的哈希键，确保相同内容只缓存一次
        import hashlib
        content_hash = hashlib.md5(content).hexdigest()[:16]
        
        # 检查是否已有相同内容
        for key, cached_content in self._static_parts.items():
            if cached_content == content:
                return cached_content  # 复用已有内容
        
        # 没有相同内容，创建新键
        if self.debug_mode and position is not None:
            # 调试模式：包含位置信息
            key = f"static_{position}_{content_hash}"
        else:
            # 生产模式：不包含位置信息
            key = f"static_{content_hash}"
        
        if key not in self._static_parts:
            self._static_parts[key] = content
        return self._static_parts[key]
    
    def _get_file_content(self, file_path: str) -> bytes:
        """获取或缓存文件内容"""
        if file_path not in self._file_cache:
            try:
                with open(file_path, 'rb') as f:
                    self._file_cache[file_path] = f.read()
            except Exception as e:
                logger.warning(f"无法读取文件 {file_path}: {e}")
                self._file_cache[file_path] = b''
        return self._file_cache[file_path]
    
    def _generate_random_strings(self, count: int, length_range: List[int], charset: str = None) -> List[str]:
        """生成指定数量的随机字符串"""
        if charset is None:
            charset = ''.join([chr(i) for i in range(32, 127)])  # ASCII可打印字符
        
        strings = []
        for _ in range(count):
            length = random.randint(length_range[0], length_range[1])
            strings.append(''.join(random.choices(charset, k=length)))
        return strings
    
    def next_body(self) -> bytes:
        """根据 body_spec 生成 body 内容"""
        strategy = self.body_spec.get('strategy', 'random').lower()
        
        if strategy == 'fixed':
            # 固定字符串
            content = self.body_spec.get('content', '')
            if isinstance(content, str):
                return content.encode('utf-8')
            elif isinstance(content, bytes):
                return content
            else:
                return b''
                
        elif strategy == 'file':
            # 从文件读取
            file_path = self.body_spec.get('file_path', '')
            return self._get_file_content(file_path)
            
        elif strategy == 'random_strings':
            # 指定数量的随机字符串
            count = self.body_spec.get('count', 1)
            length_range = self.body_spec.get('length_range', [10, 100])
            charset = self.body_spec.get('charset')
            separator = self.body_spec.get('separator', '\n')
            
            strings = self._generate_random_strings(count, length_range, charset)
            return separator.join(strings).encode('utf-8')
            
        elif strategy == 'pattern':
            # 模式递增
            pattern = self.body_spec.get('pattern', 'data{n}')
            n_start = self.body_spec.get('n_start', 1)
            n_end = self.body_spec.get('n_end', 1000)
            step = self.body_spec.get('step', 1)
            
            cycler = ValueCycler(n_start, n_end, step)
            n = cycler.next()
            return pattern.replace('{n}', str(n)).encode('utf-8')
            
        elif strategy == 'mixed':
            # 混合模式：静态部分 + 动态部分
            parts = self.body_spec.get('parts', [])
            result_parts = []
            
            for i, part in enumerate(parts):
                part_type = part.get('type', 'static')
                
                if part_type == 'static':
                    # 静态内容，缓存复用
                    content = part.get('content', '')
                    if isinstance(content, str):
                        content = content.encode('utf-8')
                    
                    # 修复：传递内容和位置，基于内容哈希避免重复
                    result_parts.append(self._get_static_part(content, i))
                    
                elif part_type == 'random':
                    # 随机内容
                    length = part.get('length', 10)
                    charset = part.get('charset')
                    if charset is None:
                        charset = ''.join([chr(i) for i in range(32, 127)])
                    random_str = ''.join(random.choices(charset, k=length))
                    result_parts.append(random_str.encode('utf-8'))
                    
                elif part_type == 'increment':
                    # 递增内容
                    pattern = part.get('pattern', '{n}')
                    n_start = part.get('n_start', 1)
                    n_end = part.get('n_end', 1000)
                    step = part.get('step', 1)
                    
                    cycler = ValueCycler(n_start, n_end, step)
                    n = cycler.next()
                    result_parts.append(pattern.replace('{n}', str(n)).encode('utf-8'))
                    
                elif part_type == 'file':
                    # 文件内容
                    file_path = part.get('file_path', '')
                    result_parts.append(self._get_file_content(file_path))
            
            return b''.join(result_parts)
            
        else:
            # 默认随机模式
            length_range = self.body_spec.get('length_range', [0, 1024])
            is_text = self.body_spec.get('text', False)
            
            if isinstance(length_range, (list, tuple)) and len(length_range) >= 2:
                length = random.randint(length_range[0], length_range[1])
            else:
                length = 0
                
            if length <= 0:
                return b''
                
            if is_text:
                # ASCII 可打印字符
                charset = self.body_spec.get('charset')
                if charset is None:
                    charset = ''.join([chr(i) for i in range(32, 127)])
                return ''.join(random.choices(charset, k=length)).encode('ascii')
            else:
                return os.urandom(length)


class HttpRandomGenerator:
    """HTTP 随机生成器：域名、URI、body"""
    def __init__(self, http_spec: Dict):
        self.domain_gen = self._make_domain_generator(http_spec.get('domains', {}))
        self.uri_gen = self._make_uri_generator(http_spec.get('uris', {}))
        self.method_gen = self._make_method_generator(http_spec.get('methods', ['GET']))
        self.body_gen = BodyGenerator(http_spec.get('body', {}), debug_mode=False)

    def _make_domain_generator(self, spec):
        if spec is None:
            spec = {}
        if isinstance(spec, str):
            return FixedValue(spec)
        if not isinstance(spec, dict):
            spec = {}
        strategy = spec.get('strategy', 'rand').lower()
        domain_list = spec.get('list', [])
        if domain_list and strategy == 'rand':
            return ListRandom(domain_list, spec.get('seed'))
        pattern = spec.get('pattern', 'www{n}.example.com')
        n_range = spec.get('n_range', [1, 1000])
        return PatternIncrementer(pattern, n_range[0], n_range[1])

    def _make_uri_generator(self, spec):
        if spec is None:
            spec = {}
        if isinstance(spec, str):
            return FixedValue(spec)
        if not isinstance(spec, dict):
            spec = {}
        strategy = spec.get('strategy', 'rand').lower()
        uri_list = spec.get('list', ['/'])
        if uri_list and strategy == 'rand':
            return ListRandom(uri_list, spec.get('seed'))
        pattern = spec.get('pattern', '/page{n}.html')
        n_range = spec.get('n_range', [1, 10000])
        return PatternIncrementer(pattern, n_range[0], n_range[1])

    def _make_method_generator(self, methods):
        if methods is None:
            methods = ['GET']
        if isinstance(methods, str):
            return FixedValue(methods)
        if not isinstance(methods, (list, tuple)):
            methods = ['GET']
        return ListRandom(methods or ['GET'])

    def next_domain(self) -> str:
        return self.domain_gen.next()

    def next_uri(self) -> str:
        return self.uri_gen.next()

    def next_method(self) -> str:
        return self.method_gen.next()

    def next_body(self) -> bytes:
        """根据 body_spec 生成 body"""
        return self.body_gen.next_body()


# -------- 批量混合喂料器 --------
class BatchMixedRunner:
    """批量混合流量喂料器
    
    并发运行多个线程，每个类别独立生成流任务并提交到 HPTG，
    实现真正的"混合并发"而非顺序生成。
    """
    def __init__(self, hptg: 'HighPerformanceTrafficGenerator', batch_spec: Dict):
        self.hptg = hptg
        self.spec = batch_spec
        self.stop_event = threading.Event()
        self.threads: List[threading.Thread] = []
        self._total_flows_generated = 0
        self._lock = threading.Lock()

    def start(self):
        """启动各类别的并发喂料线程"""
        classes = self.spec.get('classes', [])
        for cls in classes:
            thread = threading.Thread(target=self._run_class_feeder, args=(cls,), daemon=True)
            thread.start()
            self.threads.append(thread)
        logger.info(f"批量混合喂料器已启动，共 {len(classes)} 个类别")

    def stop(self):
        """停止所有喂料线程并等待队列清空"""
        self.stop_event.set()
        for t in self.threads:
            t.join(timeout=2)
        logger.info("批量混合喂料器已停止")
        
        # 等待队列清空，避免缓冲区溢出
        logger.info("等待队列清空...")
        max_wait = 30  # 最多等待30秒
        wait_count = 0
        while wait_count < max_wait:
            try:
                status = self.hptg.get_buffer_status()
                config_queue = status.get('config_queue_depth', 0)
                packet_queue = status.get('packet_queue_depth', 0)
                
                if config_queue == 0 and packet_queue == 0:
                    logger.info("所有队列已清空")
                    break
                    
                logger.info(f"等待队列清空: 配置队列={config_queue}, 报文队列={packet_queue}")
                time.sleep(1)
                wait_count += 1
                
            except Exception as e:
                logger.warning(f"检查队列状态时出错: {e}")
                break
        
        if wait_count >= max_wait:
            logger.warning("等待队列清空超时，可能存在缓冲区溢出风险")

    def get_status(self) -> Dict:
        """获取喂料状态"""
        with self._lock:
            return {
                'total_flows_generated': self._total_flows_generated,
                'active_threads': sum(1 for t in self.threads if t.is_alive()),
                'is_running': not self.stop_event.is_set()
            }

    def _run_class_feeder(self, cls: Dict):
        """单个类别的喂料循环"""
        class_id = cls.get('id', 'unknown')
        class_type = cls.get('type', 'tcp').lower()
        
        # 设置速率限制（未配置或为0表示不限速；字符串'0'也表示不限速）
        bps = cls.get('bps')
        if bps is not None:
            try:
                self.hptg.set_class_rate_limit(class_id, bps)
            except Exception:
                pass
        
        # 四元组生成器
        tuple_gen = TupleGenerator(cls.get('tuples', {}))
        
        # HTTP 生成器：延后到配置进程再具体化（此处不生成具体会话）
        http_gen = None
        
        # 流计数
        max_flows = int(self.spec.get('flows', {}).get('count', 0) or 0)  # 全局
        class_max_flows = int(cls.get('flows', {}).get('count', 0) or 0)   # 每类
        class_flows = 0
        
        try:
            while not self.stop_event.is_set():
                # 优先检查每条流的限制，再检查全局流数控制
                should_break = False
                
                # 1. 优先检查每类流数限制
                if class_max_flows > 0 and class_flows >= class_max_flows:
                    should_break = True
                
                # 2. 再检查全局流数限制
                if max_flows > 0 and self._total_flows_generated >= max_flows:
                    should_break = True
                
                # 如果任一限制达到，则退出循环
                if should_break:
                    break
                
                # 生成四元组
                ip_src, ip_dst, sport, dport = tuple_gen.next4()
                
                # 构造流规范并提交
                if class_type == 'tcp':
                    flow_spec = self._make_tcp_flow_spec(cls, ip_src, ip_dst, sport, dport, class_id)
                    # 限制每个流的包数，避免配置数量爆炸
                    # 每个TCP流：握手(3) + 数据分片 + ACK + 挥手(3) ≈ 10-20个包
                    self.hptg.submit_tcp_flow(flow_spec, count=20)
                elif class_type == 'udp':
                    flow_spec = self._make_udp_flow_spec(cls, ip_src, ip_dst, sport, dport, class_id)
                    # UDP流：上行(1) + 下行(1) = 2个包
                    self.hptg.submit_udp_flow(flow_spec, count=2)
                elif class_type == 'http':
                    http_spec = self._make_http_spec(cls, ip_src, ip_dst, sport, dport, class_id)
                    # HTTP流：握手(3) + 会话数据 + 挥手(3) ≈ 15-30个包
                    self.hptg.submit_http_sessions(http_spec, count=30)
                
                class_flows += 1
                with self._lock:
                    self._total_flows_generated += 1
                
                # 速率控制（可选）
                rate_limit_fps = cls.get('rate_limit_fps', 0)
                try:
                    rate_limit_fps = int(rate_limit_fps or 0)
                except Exception:
                    rate_limit_fps = 0
                if rate_limit_fps > 0:
                    time.sleep(1.0 / max(1, rate_limit_fps))
                
        except Exception as e:
            logger.error(f"类别 {class_id} 喂料线程错误: {e}")
        
        logger.info(f"类别 {class_id} 喂料线程停止，已生成 {class_flows} 个流")

    def _make_tcp_flow_spec(self, cls: Dict, ip_src: str, ip_dst: str, sport: int, dport: int, class_id: str) -> Dict:
        """构造 TCP 流规范"""
        tcp_base = cls.get('tcp', {})
        flow_spec = dict(tcp_base)
        flow_spec.update({
            'class_id': class_id,
            'uplink': dict(tcp_base.get('uplink', {})),
            'downlink': dict(tcp_base.get('downlink', {}))
        })
        flow_spec['uplink'].update({'ip_src': ip_src, 'ip_dst': ip_dst, 'sport': sport, 'dport': dport})
        return flow_spec

    def _make_udp_flow_spec(self, cls: Dict, ip_src: str, ip_dst: str, sport: int, dport: int, class_id: str) -> Dict:
        """构造 UDP 流规范"""
        udp_base = cls.get('udp', {})
        flow_spec = dict(udp_base)
        flow_spec.update({
            'class_id': class_id,
            'uplink': dict(udp_base.get('uplink', {})),
            'downlink': dict(udp_base.get('downlink', {}))
        })
        flow_spec['uplink'].update({'ip_src': ip_src, 'ip_dst': ip_dst, 'sport': sport, 'dport': dport})
        return flow_spec

    def _make_http_spec(self, cls: Dict, ip_src: str, ip_dst: str, sport: int, dport: int, class_id: str) -> Dict:
        """构造 HTTP 会话规范（仅传递策略与基础L3，具体会话下沉到配置进程生成）"""
        http_base = cls.get('http', {})
        http_spec = {
            'handshake': http_base.get('handshake', True),
            'termination': http_base.get('termination', True),
            'mss': http_base.get('mss'),
            'directionless': http_base.get('directionless', False),
            'class_id': class_id,
            'uplink': dict(http_base.get('uplink', {})),
            'downlink': dict(http_base.get('downlink', {})),
            'methods': http_base.get('methods'),
            'domains': http_base.get('domains'),
            'uris': http_base.get('uris'),
            'headers': http_base.get('headers'),
            'body': http_base.get('body'),
            'sessions_per_flow': http_base.get('sessions_per_flow'),
            'think_time_ms': http_base.get('think_time_ms'),
            'ttl': http_base.get('ttl'),
            'tos': http_base.get('tos'),
            'window': http_base.get('window'),
        }
        # 更新上行参数
        http_spec['uplink'].update({
            'ip_src': ip_src,
            'ip_dst': ip_dst,
            'sport': sport,
            'dport': dport
        })
        # 更新下行参数（如果没有配置，则自动生成反向参数）
        if not http_spec['downlink']:
            http_spec['downlink'] = {
                'ip_src': ip_dst,
                'ip_dst': ip_src,
                'sport': dport,
                'dport': sport,
            }
        else:
            http_spec['downlink'].update({
                'ip_src': ip_dst,
                'ip_dst': ip_src,
                'sport': dport,
                'dport': sport,
            })
        return http_spec

# -------- 通用参数生成器 --------
class ParameterGenerator:
    """通用参数生成器，支持多种策略"""
    def __init__(self, spec: Dict):
        self.spec = spec
        self._generator = self._make_generator()
    
    def _make_generator(self):
        # 如果spec是整数，直接返回固定值
        if isinstance(self.spec, (int, float)):
            return FixedValue(self.spec)
        
        # 如果spec是字典，按策略处理
        if isinstance(self.spec, dict):
            strategy = self.spec.get('strategy', 'fixed').lower()
            
            if strategy == 'fixed':
                return FixedValue(self.spec.get('value'))
            elif strategy == 'random':
                return ValueRandom(
                    self.spec.get('range', [0, 100])[0],
                    self.spec.get('range', [0, 100])[1],
                    self.spec.get('seed')
                )
            elif strategy == 'increment':
                return ValueCycler(
                    self.spec.get('range', [0, 100])[0],
                    self.spec.get('range', [0, 100])[1],
                    self.spec.get('step', 1)
                )
            elif strategy == 'list':
                return ListRandom(
                    self.spec.get('list', []),
                    self.spec.get('seed')
                )
            elif strategy == 'pattern':
                return PatternIncrementer(
                    self.spec.get('pattern', '{n}'),
                    self.spec.get('n_range', [1, 100])[0],
                    self.spec.get('n_range', [1, 100])[1],
                    self.spec.get('step', 1)
                )
        
        # 默认返回固定值
        return FixedValue(self.spec if self.spec is not None else 0)
    
    def next(self):
        return self._generator.next()


class FixedValue:
    """固定值生成器"""
    def __init__(self, value):
        self.value = value
    
    def next(self):
        return self.value


class PayloadGenerator:
    """Payload生成器，支持多种策略"""
    def __init__(self, payload_spec: Dict):
        self.payload_spec = payload_spec
        self._body_gen = BodyGenerator(payload_spec, debug_mode=False) if payload_spec else None
    
    def next_payload(self) -> bytes:
        """生成下一个payload"""
        if not self.payload_spec:
            return b''
        return self._body_gen.next_body()


class HeaderGenerator:
    """HTTP Header生成器"""
    def __init__(self, header_spec: Dict):
        self.header_spec = header_spec
        self._generators = {}

        # 处理 None 或空字典的情况
        if not header_spec:
            return

        for header_name, spec in header_spec.items():
            if isinstance(spec, dict):
                self._generators[header_name] = ParameterGenerator(spec)
            else:
                # 固定值
                self._generators[header_name] = FixedValue(spec)
    
    def next_headers(self) -> Dict[str, str]:
        """生成下一组headers"""
        headers = {}
        for header_name, generator in self._generators.items():
            headers[header_name] = str(generator.next())
        return headers


class EnhancedHttpRandomGenerator:
    """增强的HTTP随机生成器，支持更多可变化参数"""
    def __init__(self, http_spec: Dict):
        self.domain_gen = self._make_domain_generator(http_spec.get('domains', {}))
        self.uri_gen = self._make_uri_generator(http_spec.get('uris', {}))
        self.method_gen = self._make_method_generator(http_spec.get('methods', ['GET']))
        self.body_gen = BodyGenerator(http_spec.get('body', {}), debug_mode=False)
        self.header_gen = HeaderGenerator(http_spec.get('headers', {}))
        
        # 其他参数生成器
        self.ttl_gen = ParameterGenerator(http_spec.get('ttl', {'strategy': 'fixed', 'value': 64}))
        self.tos_gen = ParameterGenerator(http_spec.get('tos', {'strategy': 'fixed', 'value': 0}))
        self.mss_gen = ParameterGenerator(http_spec.get('mss', {'strategy': 'fixed', 'value': 1460}))
        self.window_gen = ParameterGenerator(http_spec.get('window', {'strategy': 'fixed', 'value': 65535}))

    def _make_domain_generator(self, spec):
        if spec is None:
            spec = {}
        if isinstance(spec, str):
            return FixedValue(spec)
        if not isinstance(spec, dict):
            spec = {}
        strategy = spec.get('strategy', 'rand').lower()
        domain_list = spec.get('list', [])
        if domain_list and strategy == 'rand':
            return ListRandom(domain_list, spec.get('seed'))
        pattern = spec.get('pattern', 'www{n}.example.com')
        n_range = spec.get('n_range', [1, 1000])
        return PatternIncrementer(pattern, n_range[0], n_range[1])

    def _make_uri_generator(self, spec):
        if spec is None:
            spec = {}
        if isinstance(spec, str):
            return FixedValue(spec)
        if not isinstance(spec, dict):
            spec = {}
        strategy = spec.get('strategy', 'rand').lower()
        uri_list = spec.get('list', ['/'])
        if uri_list and strategy == 'rand':
            return ListRandom(uri_list, spec.get('seed'))
        pattern = spec.get('pattern', '/page{n}.html')
        n_range = spec.get('n_range', [1, 10000])
        return PatternIncrementer(pattern, n_range[0], n_range[1])

    def _make_method_generator(self, methods: List[str]):
        return ListRandom(methods or ['GET'])

    def next_domain(self) -> str:
        return self.domain_gen.next()

    def next_uri(self) -> str:
        return self.uri_gen.next()

    def next_method(self) -> str:
        return self.method_gen.next()

    def next_body(self) -> bytes:
        return self.body_gen.next_body()
    
    def next_headers(self) -> Dict[str, str]:
        return self.header_gen.next_headers()
    
    def next_ttl(self) -> int:
        return int(self.ttl_gen.next())
    
    def next_tos(self) -> int:
        return int(self.tos_gen.next())
    
    def next_mss(self) -> int:
        return int(self.mss_gen.next())
    
    def next_window(self) -> int:
        return int(self.window_gen.next())
