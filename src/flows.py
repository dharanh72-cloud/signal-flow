"""
flows.py
--------
Shared data structures for grouping raw packets into bidirectional
flows, keyed by the classic 5-tuple. No payload is ever stored here --
only sizes, timestamps, and direction.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field


def flow_key(src_ip, dst_ip, src_port, dst_port, proto):
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (a[0], a[1], b[0], b[1], proto)
    return (b[0], b[1], a[0], a[1], proto)


@dataclass
class PacketRecord:
    timestamp: float
    size: int
    direction: str


@dataclass
class Flow:
    key: tuple
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    proto: str
    label: str = "unknown"
    packets: list[PacketRecord] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    max_concurrent_flows: int = 1

    def add_packet(self, size: int, direction: str, ts: float = None):
        ts = ts if ts is not None else time.time()
        if not self.packets:
            self.start_time = ts
        else:
            self.start_time = min(self.start_time, ts)
        self.packets.append(PacketRecord(timestamp=ts, size=size, direction=direction))
        self.last_seen = ts

    @property
    def duration(self) -> float:
        if len(self.packets) < 2:
            return 0.0
        return self.packets[-1].timestamp - self.packets[0].timestamp

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    def is_idle(self, now: float, timeout: float = 5.0) -> bool:
        return (now - self.last_seen) > timeout


class FlowTable:
    def __init__(self):
        self.flows = {}
        self.client_flow_counts = defaultdict(int)

    def get_or_create(self, src_ip, dst_ip, src_port, dst_port, proto):
        key = flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        if key not in self.flows:
            self.flows[key] = Flow(
                key=key,
                client_ip=src_ip,
                client_port=src_port,
                server_ip=dst_ip,
                server_port=dst_port,
                proto=proto,
            )
            self.client_flow_counts[src_ip] += 1
        return self.flows[key]

    def direction_for(self, flow: Flow, src_ip: str, src_port: int) -> str:
        return "up" if (src_ip, src_port) == (flow.client_ip, flow.client_port) else "down"

    def active_flow_count_for_client(self, client_ip: str) -> int:
        return self.client_flow_counts.get(client_ip, 0)

    def touch_concurrency(self, flow: Flow):
        current = self.active_flow_count_for_client(flow.client_ip)
        if current > flow.max_concurrent_flows:
            flow.max_concurrent_flows = current

    def pop_idle_flows(self, timeout: float = 5.0):
        now = time.time()
        idle_keys = [k for k, f in self.flows.items() if f.is_idle(now, timeout)]
        idle = [self.flows.pop(k) for k in idle_keys]
        for flow in idle:
            self.client_flow_counts[flow.client_ip] = max(
                0, self.client_flow_counts[flow.client_ip] - 1
            )
        return idle

    def all_flows(self):
        return list(self.flows.values())
