#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
大象流 pcap 场景生成器 (scapy 构造, 按时间戳烘焙)

pcap 包序为分块结构 (时间轴上严格顺序):

    背景流块 -> 大象流块 -> 背景流块 -> 大象流块 -> ...

流模型 (背景流 / 大象流各自独立配置):
- 源 IP  : 从配置的范围内随机抽取
- 源 MAC : 从配置的池内随机抽取
- 目的 IP: 固定, 配置指定
- 目的 MAC: 固定, 配置指定 (默认广播 MAC)
- 背景流块: 泊松到达小包 (70% UDP / 30% TCP)。每条流最多 bg-packets-per-flow
  个包 (硬上限) 即切换新流; 新流五元组强制避开最近用过的 (防随机碰撞把
  多条小流粘成伪大象流) —— 高频、少量包、大量流
- 大象流块: 块首随机定源, 块内五元组完全一致 (整块一条流), TCP "PA" 大包
  + FIN 收尾

用法:
    uv run main.py                        # 纯默认参数
    uv run main.py -c config.yaml         # 读配置文件
    uv run main.py -c config.yaml --elephant-pps 20000   # 命令行覆盖

注意: 仅供自有测试环境使用。
"""
from __future__ import annotations

import argparse
import ipaddress
import itertools
import os
import random
import time
from collections import deque

import yaml
from scapy.all import Ether, IP, TCP, UDP
from scapy.utils import PcapWriter

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"     # 目的 MAC 默认值, 不触发 ARP

# --------------------------------------------------------------------------- #
# 池工具
# --------------------------------------------------------------------------- #


def expand_ip_pool(spec: str, cap: int = 4096) -> list[str]:
    """'10.0.0.0/24' 或 '1.1.1.1,8.8.8.8' -> IP 列表 (CIDR 最多展开 cap 个)"""
    if "/" in spec:
        hosts = ipaddress.ip_network(spec, strict=False).hosts()
        pool = [str(h) for h in itertools.islice(hosts, cap)]
        return pool or [spec.split("/")[0]]
    return [s.strip() for s in spec.split(",") if s.strip()]


def check_single_ip(spec: str, name: str) -> str:
    """目的 IP 必须是单个地址"""
    try:
        return str(ipaddress.ip_address(spec))
    except ValueError:
        raise SystemExit(f"[错误] {name} 必须是单个 IP 地址, 当前: {spec}")


def check_mac(mac: str, name: str) -> str:
    if mac.count(":") != 5:
        raise SystemExit(f"[错误] {name} MAC 格式应为 aa:bb:cc:dd:ee:ff, 当前: {mac}")
    return mac.lower()


def mac_to_int(mac: str) -> int:
    return int(mac.replace(":", "").replace("-", ""), 16)


def int_to_mac(v: int) -> str:
    v &= (1 << 48) - 1
    return ":".join(f"{(v >> s) & 0xff:02x}" for s in range(40, -1, -8))


def expand_mac_pool(spec: str, count: int, cap: int = 4096) -> list[str]:
    """基址 + count -> [base, base+1, ...] 连续 MAC 池 (最多 cap 个)"""
    count = max(1, min(count, cap))
    base = mac_to_int(spec)
    return [int_to_mac(base + i) for i in range(count)]


# --------------------------------------------------------------------------- #
# 流标识与报文构造
# --------------------------------------------------------------------------- #


def pick_bg_flow(src_ips: list[str], src_macs: list[str],
                 recent: deque) -> dict:
    """背景流标识: 随机源 IP / 源 MAC + 随机端口 (70% UDP / 30% TCP)。
    强制避开 recent 里最近用过的五元组 —— 防止随机碰撞把多条小流
    粘成同五元组长流 (伪大象流)。池足够大时一次命中, 极端小池最多重试 64 次。"""
    flow = None
    for _ in range(64):
        f = {
            "src_ip": random.choice(src_ips),
            "src_mac": random.choice(src_macs),
            "sport": random.randint(10000, 65000),
            "dport": random.choice((53, 123, 5000)) if random.random() < 0.7
                     else random.choice((80, 443, 22)),
            "udp": random.random() < 0.7,
        }
        key = (f["src_ip"], f["src_mac"], f["sport"], f["dport"], f["udp"])
        if key not in recent:
            flow = f
            recent.append(key)
            break
    return flow or f   # 极端小池 (碰撞 64 次) 时放弃去重


def build_bg_packet(flow: dict, dst_ip: str, dst_mac: str):
    """背景流小包: 70% UDP (DNS/心跳风格) / 30% TCP"""
    if flow["udp"]:
        payload = random.randbytes(random.randint(8, 64))
        return (Ether(dst=dst_mac, src=flow["src_mac"])
                / IP(src=flow["src_ip"], dst=dst_ip)
                / UDP(sport=flow["sport"], dport=flow["dport"]) / payload)
    payload = random.randbytes(random.randint(0, 120))
    return (Ether(dst=dst_mac, src=flow["src_mac"])
            / IP(src=flow["src_ip"], dst=dst_ip)
            / TCP(sport=flow["sport"], dport=flow["dport"], flags="A",
                  seq=random.randint(0, 2**32 - 1)) / payload)


# --------------------------------------------------------------------------- #
# 场景生成: 背景块 / 大象块交替
# --------------------------------------------------------------------------- #


def gen_bg_block(t0: float, t1: float, args, bg: dict):
    """背景流块: [t0, t1) 内泊松到达(指数间隔)。
    每条流最多 bg_packets_per_flow 个包 (每条流在 1..N 内随机, 保证硬上限)
    即切换新流; 新流避开最近 128 条用过的五元组。
    yield (ts, pkt)"""
    recent: deque = deque(maxlen=128)   # 最近用过的五元组, 防碰撞
    flow = pick_bg_flow(bg["src_ips"], bg["src_macs"], recent)
    remain = random.randint(1, max(1, args.bg_packets_per_flow))
    t = t0 + random.expovariate(max(1.0, args.normal_pps))
    while t < t1:
        yield t, build_bg_packet(flow, bg["dst_ip"], bg["dst_mac"])
        remain -= 1
        if remain <= 0:                     # 本流包数用尽 -> 换新流
            flow = pick_bg_flow(bg["src_ips"], bg["src_macs"], recent)
            remain = random.randint(1, max(1, args.bg_packets_per_flow))
        t += random.expovariate(max(1.0, args.normal_pps))


def gen_elephant_block(t0: float, args, el: dict):
    """大象流块: [t0, t0+duration) 内一条固定流 (块首随机定源), 结尾补 FIN"""
    src_ip = random.choice(el["src_ips"])
    src_mac = random.choice(el["src_macs"])
    sport = random.randint(30000, 60000)
    dport = random.choice((80, 443, 445, 8443))  # http/https/smb 风格端口
    seq = 1000
    inter = 1.0 / args.elephant_pps
    end = t0 + args.elephant_duration
    t = t0
    while t < end:
        yield t, (Ether(dst=el["dst_mac"], src=src_mac)
                  / IP(src=src_ip, dst=el["dst_ip"])
                  / TCP(sport=sport, dport=dport, flags="PA", seq=seq)
                  / random.randbytes(args.elephant_size))
        seq += args.elephant_size
        t += inter
    # 收尾 FIN
    yield end, (Ether(dst=el["dst_mac"], src=src_mac)
                / IP(src=src_ip, dst=el["dst_ip"])
                / TCP(sport=sport, dport=dport, flags="FA") / b"")


def build_scenario_events(args, bg: dict, el: dict, stats: dict):
    """交替分块: 背景块(约 interval 秒, ±20% 抖动) -> 大象块(duration 秒) -> ...
    严格时间顺序生成; stats 累计大象流条数"""
    t = 0.0
    while t < args.duration:
        # 背景流块
        gap = args.elephant_interval * random.uniform(0.8, 1.2)
        block_end = min(t + gap, args.duration)
        yield from gen_bg_block(t, block_end, args, bg)
        t = block_end
        if t >= args.duration:
            break
        # 大象流块
        yield from gen_elephant_block(t, args, el)
        stats["bursts"] += 1
        t += args.elephant_duration


def write_pcap(args, bg: dict, el: dict, path: str) -> tuple[int, int]:
    """流式写 pcap (支持 --repeat 拼接); 返回 (总包数, 大象流条数/轮)"""
    base = time.time()
    n_pkts = 0
    stats = {"bursts": 0}
    # 总包数估算: 每周期 = 背景块(interval) + 大象块(duration), 一轮约 duration/cycle 条大象流
    cycle = max(args.elephant_interval + args.elephant_duration, 1e-9)
    n_bursts_est = args.duration / cycle if cycle > 0 else 0
    total_est = (n_bursts_est * args.elephant_pps * args.elephant_duration
                 + args.normal_pps * args.duration * args.elephant_interval / cycle)
    total_est = max(1, total_est * max(1, args.repeat))
    next_progress = 100_000
    w = PcapWriter(path, linktype=1, nano=args.nano)
    w.write_header(None)   # scapy 2.7: 全局头需显式写入
    try:
        for r in range(max(1, args.repeat)):
            offset = r * args.duration          # 每轮场景在时间轴上顺延
            for ts, pkt in build_scenario_events(args, bg, el, stats):
                pkt.time = base + offset + ts
                w.write_packet(pkt)
                n_pkts += 1
                if n_pkts >= next_progress:     # 进度提示 (纯构造也要跑很久)
                    print(f"  ... {n_pkts} pkts "
                          f"({n_pkts / max(1, total_est * args.repeat) * 100:.0f}%)",
                          flush=True)
                    next_progress += 100_000
    finally:
        w.close()
    return n_pkts, stats["bursts"] // max(1, args.repeat)


# --------------------------------------------------------------------------- #
# CLI (优先级: 命令行显式传参 > 配置文件 > 默认值)
# --------------------------------------------------------------------------- #


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="大象流 pcap 场景生成器 (背景块/大象块交替, 时间戳烘焙)",
        epilog="可用 --config config.yaml 提供参数; 命令行显式传参优先")
    p.add_argument("-c", "--config", default=None, metavar="YAML",
                   help="YAML 配置文件 (键名与命令行参数一致)")

    # 背景流: 源随机范围 + 目的固定
    p.add_argument("--bg-src-ip", default="172.16.0.0/16",
                   help="背景流源 IP 随机范围 (CIDR 或逗号分隔)")
    p.add_argument("--bg-src-mac", default="02:00:00:00:01:00",
                   help="背景流源 MAC 池基址")
    p.add_argument("--bg-src-mac-count", type=int, default=256,
                   help="背景流源 MAC 池大小 (默认 256)")
    p.add_argument("--bg-dst-ip", default="10.0.0.1",
                   help="背景流目的 IP (固定)")
    p.add_argument("--bg-dst-mac", default=None,
                   help="背景流目的 MAC (固定); 默认广播 MAC")

    # 大象流: 源随机范围 + 目的固定
    p.add_argument("--el-src-ip", default="172.17.0.0/16",
                   help="大象流源 IP 随机范围 (CIDR 或逗号分隔)")
    p.add_argument("--el-src-mac", default="02:00:00:00:02:00",
                   help="大象流源 MAC 池基址")
    p.add_argument("--el-src-mac-count", type=int, default=64,
                   help="大象流源 MAC 池大小 (默认 64)")
    p.add_argument("--el-dst-ip", default="10.0.0.1",
                   help="大象流目的 IP (固定)")
    p.add_argument("--el-dst-mac", default=None,
                   help="大象流目的 MAC (固定); 默认广播 MAC")

    # 速率与节奏
    p.add_argument("--normal-pps", type=int, default=100,
                   help="背景流速率 pkt/s (默认 100)")
    p.add_argument("--bg-packets-per-flow", type=int, default=8,
                   help="背景流每条流最大包数 (硬上限, 每条流在 1..N 内随机; "
                        "1=每包一条流, 默认 8)")
    p.add_argument("--elephant-pps", type=int, default=8000,
                   help="大象流速率 pkt/s (默认 8000)")
    p.add_argument("--elephant-size", type=int, default=1400,
                   help="大象流载荷字节 (默认 1400)")
    p.add_argument("--elephant-duration", type=float, default=10.0,
                   help="单条大象流持续秒数 (默认 10)")
    p.add_argument("--elephant-interval", type=float, default=30.0,
                   help="背景块时长(即大象流出现间隔)秒数, ±20% 抖动 (默认 30)")
    p.add_argument("-t", "--duration", type=float, default=60.0,
                   help="场景总时长秒数 (默认 60)")
    p.add_argument("--repeat", type=int, default=1,
                   help="场景重复拼接次数, 加长 pcap (默认 1)")
    p.add_argument("--nano", action="store_true",
                   help="pcap 用纳秒时间戳 (默认微秒)")
    p.add_argument("--out-dir", default="dpdk_out", help="输出目录 (默认 dpdk_out)")
    p.add_argument("--seed", type=int, default=None, help="随机种子 (复现用)")

    # --config 两段式解析: 先取 config 路径, 把 YAML 值设为默认值, 再正式解析
    pre = p.parse_args()
    if pre.config:
        try:
            with open(pre.config, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError) as exc:
            p.error(f"读取配置文件失败 {pre.config}: {exc}")
        if not isinstance(cfg, dict):
            p.error(f"配置文件顶层必须是键值映射: {pre.config}")
        valid = {a.dest for a in p._actions} - {"config", "help"}
        overrides = {}
        for k, v in cfg.items():
            dest = str(k).replace("-", "_")
            if dest not in valid:
                p.error(f"配置文件未知参数 '{k}' (可用: {', '.join(sorted(valid))})")
            overrides[dest] = v
        p.set_defaults(**overrides)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if args.duration <= 0:
        args.duration = 60.0
    random.seed(args.seed)

    # 校验并构建背景/大象两套流配置
    bg = {
        "src_ips": expand_ip_pool(args.bg_src_ip),
        "src_macs": expand_mac_pool(check_mac(args.bg_src_mac, "--bg-src-mac"),
                                    args.bg_src_mac_count),
        "dst_ip": check_single_ip(args.bg_dst_ip, "--bg-dst-ip"),
        "dst_mac": check_mac(args.bg_dst_mac, "--bg-dst-mac")
                   if args.bg_dst_mac else BROADCAST_MAC,
    }
    el = {
        "src_ips": expand_ip_pool(args.el_src_ip),
        "src_macs": expand_mac_pool(check_mac(args.el_src_mac, "--el-src-mac"),
                                    args.el_src_mac_count),
        "dst_ip": check_single_ip(args.el_dst_ip, "--el-dst-ip"),
        "dst_mac": check_mac(args.el_dst_mac, "--el-dst-mac")
                   if args.el_dst_mac else BROADCAST_MAC,
    }

    print("背景流 :")
    print(f"  源IP  : {args.bg_src_ip}  ({len(bg['src_ips'])} 个中随机)")
    print(f"  源MAC : {bg['src_macs'][0]} ~ {bg['src_macs'][-1]}  ({len(bg['src_macs'])} 个中随机)")
    print(f"  目的  : {bg['dst_ip']} / {bg['dst_mac']}")
    print("大象流 :")
    print(f"  源IP  : {args.el_src_ip}  ({len(el['src_ips'])} 个中随机)")
    print(f"  源MAC : {el['src_macs'][0]} ~ {el['src_macs'][-1]}  ({len(el['src_macs'])} 个中随机)")
    print(f"  目的  : {el['dst_ip']} / {el['dst_mac']}")
    print(f"背景块 : {args.normal_pps} pkt/s 小包, 每流 ≤{max(1, args.bg_packets_per_flow)} 包, "
          f"约 {args.elephant_interval:.1f}s/块 (±20%)")
    print(f"大象块 : {args.elephant_pps} pkt/s x {args.elephant_size}B, "
          f"持续 {args.elephant_duration:.1f}s, 块内五元组一致 "
          f"(≈{args.elephant_pps * (args.elephant_size + 54) * 8 / 1e6:.0f} Mbps)")
    print(f"场景   : {args.duration:.0f}s x {max(1, args.repeat)} 轮")
    print("-" * 70, flush=True)

    os.makedirs(args.out_dir, exist_ok=True)
    pcap_path = os.path.join(args.out_dir, "scenario.pcap")
    n_pkts, n_bursts = write_pcap(args, bg, el, pcap_path)
    size_mb = os.path.getsize(pcap_path) / 1e6

    print(f"[ok] pcap      : {pcap_path}")
    print(f"[ok] 总包数    : {n_pkts}")
    print(f"[ok] pcap 大小 : {size_mb:.1f} MB")
    print(f"[ok] 大象流    : {n_bursts} 条/轮")
    print("[ok] 回放      : sudo tcpreplay -i <iface> scenario.pcap  (按时间戳原速)")
    if size_mb > 200:
        print("[提醒] pcap 较大, 可减小 --duration / --elephant-pps")


if __name__ == "__main__":
    main()
