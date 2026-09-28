#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rx_monitor.py —— 通过 DPDK telemetry 采集 testpmd 每队列收包统计并绘图

原理:
    dpdk-testpmd 启动时默认开启 telemetry (UNIX 域套接字,
    默认 /var/run/dpdk/rte/dpdk_telemetry.v2)。本脚本轮询
    /ethdev/stats 获取每个端口的 q_ipackets / q_ibytes (按队列),
    求相邻两次采样的差值得到每队列 pps / Bps, 结束后绘制图表。

用法 (在被测接收端 Linux 机器上运行, 与 testpmd 同机):

    # testpmd 正常启动即可 (telemetry 默认开启):
    sudo dpdk-testpmd -l 0-2 -n 4 -a <PCI> -- -i --rx-only

    # 采集 60s, 每秒采样, 输出 rx_stats.png + rx_stats.csv:
    python3 rx_monitor.py -d 60

    # 指定端口 / 采样间隔 / 看字节速率:
    python3 rx_monitor.py -p 0 -i 0.5 --bytes -d 30

    # 无限采集, Ctrl-C 结束并出图:
    python3 rx_monitor.py

注意:
    - 需要 matplotlib: pip3 install matplotlib
    - 套接字由 root 的 testpmd 创建, 一般需要 sudo 运行本脚本
    - 仅统计 RX (q_ipackets / q_ibytes); 丢包看 testpmd 的 imissed/ierrors
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import socket
import sys
import time
from datetime import datetime

DEFAULT_SOCKET = "/var/run/dpdk/rte/dpdk_telemetry.v2"


def find_telemetry_socket(preferred: str) -> str:
    """探测可用的 telemetry 套接字路径。
    新版 DPDK 会创建两个文件:
      dpdk_telemetry.v2          —— 监听 socket, 直连会报 EPROTOTYPE
      dpdk_telemetry.v2.<pid>    —— 实际通信的连接 socket, 应连这个
    优先级: 用户指定 > *.pid 形式 > 默认路径。逐个试连, 能连上即用。"""
    candidates: list[str] = []
    if preferred != DEFAULT_SOCKET:
        candidates.append(preferred)
    # pid 后缀的连接 socket, pid 大的大概率是最近启动的进程
    candidates += sorted(glob.glob(DEFAULT_SOCKET + ".*"),
                         key=lambda p: p.rsplit(".", 1)[-1], reverse=True)
    candidates.append(DEFAULT_SOCKET)

    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect(path)
            return path
        except OSError:
            continue
    return preferred   # 一个都连不上, 返回原值让上层报原始错误


# --------------------------------------------------------------------------- #
# DPDK telemetry 客户端
# --------------------------------------------------------------------------- #


class TelemetryClient:
    """DPDK telemetry v2 套接字客户端 (JSON 请求/应答)"""

    def __init__(self, path: str):
        self.path = path
        self._token = 0

    def _request(self, command: str) -> dict:
        self._token += 1
        req = json.dumps({"action": 0, "command": command,
                          "token": self._token}) + "\n"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect(self.path)
            s.sendall(req.encode())
            buf = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
                try:                       # 应答可能分多次到达
                    return json.loads(buf)
                except json.JSONDecodeError:
                    continue
        raise RuntimeError(f"telemetry 应答不完整: {buf[:200]!r}")

    def ethdev_stats(self) -> dict[int, dict]:
        """返回 {port_id: {"q_ipackets": [...], "q_ibytes": [...],
                           "ipackets": N, "ibytes": N}}"""
        resp = self._request("/ethdev/stats")
        # 应答格式随 DPDK 版本略有差异, 兼容 data / output / 顶层
        for key in ("data", "output"):
            if isinstance(resp, dict) and key in resp:
                resp = resp[key]
                break
        # 此时 resp 应为 {port_id_str: {...stats...}}; 若还包着一层命令名则再剥一层
        if isinstance(resp, dict) and "/ethdev/stats" in resp:
            resp = resp["/ethdev/stats"]

        result: dict[int, dict] = {}
        if not isinstance(resp, dict):
            return result
        for k, v in resp.items():
            try:
                port = int(k)
            except (TypeError, ValueError):
                continue
            if isinstance(v, dict) and "q_ipackets" in v:
                result[port] = v
        return result


# --------------------------------------------------------------------------- #
# 采样与绘图
# --------------------------------------------------------------------------- #


def sample_once(client: TelemetryClient, port_filter: int | None):
    """采一次: 返回 {port: {"q_pkts": [...], "q_bytes": [...]}}"""
    stats = client.ethdev_stats()
    out = {}
    for port, v in stats.items():
        if port_filter is not None and port != port_filter:
            continue
        out[port] = {
            "q_pkts": list(v.get("q_ipackets", [])),
            "q_bytes": list(v.get("q_ibytes", [])),
        }
    return out


def main() -> None:
    p = argparse.ArgumentParser(
        description="采集 testpmd 每队列 RX 统计并绘图 (DPDK telemetry)")
    p.add_argument("-s", "--socket", default=DEFAULT_SOCKET,
                   help=f"telemetry 套接字路径 (默认 {DEFAULT_SOCKET})")
    p.add_argument("-p", "--port", type=int, default=None,
                   help="只看指定端口号 (默认全部)")
    p.add_argument("-i", "--interval", type=float, default=1.0,
                   help="采样间隔秒 (默认 1.0)")
    p.add_argument("-d", "--duration", type=float, default=0,
                   help="采集时长秒, 0=无限直到 Ctrl-C (默认 0)")
    p.add_argument("--bytes", action="store_true",
                   help="图表显示字节速率 Bps (默认包速率 pps)")
    p.add_argument("-o", "--out", default="rx_stats",
                   help="输出文件名前缀 (默认 rx_stats -> rx_stats.png/.csv)")
    args = p.parse_args()

    try:
        import matplotlib
        matplotlib.use("Agg")          # 无显示环境也可出图
        import matplotlib.pyplot as plt
    except ImportError:
        print("[警告] 未安装 matplotlib, 只输出 CSV 不出图 "
              "(pip3 install matplotlib)")
        plt = None

    sock_path = find_telemetry_socket(args.socket)
    if sock_path != args.socket:
        print(f"[信息] 自动选择 telemetry 套接字: {sock_path}")
    client = TelemetryClient(sock_path)
    try:
        first = sample_once(client, args.port)
    except (FileNotFoundError, ConnectionError, socket.error) as exc:
        sys.exit(f"[错误] 连不上 telemetry 套接字 {sock_path}: {exc}\n"
                 f"       请确认 testpmd 已在本机运行; 套接字由 root 创建, "
                 f"通常需要 sudo 运行本脚本。\n"
                 f"       可用 ls /var/run/dpdk/rte/ 查看实际套接字文件, "
                 f"用 -s 指定。")
    if not first:
        sys.exit("[错误] telemetry 里没有找到任何端口统计, 检查 testpmd 状态。")

    ports = sorted(first)
    unit = "Bps" if args.bytes else "pps"
    field = "q_bytes" if args.bytes else "q_pkts"
    print(f"监控端口: {ports}   采样间隔: {args.interval}s   "
          f"单位: {unit}   Ctrl-C 结束并出图")
    print("-" * 60, flush=True)

    # samples[t] = {port: [q0, q1, ...]} (区间速率)
    timestamps: list[float] = []
    samples: list[dict[int, list[float]]] = []
    prev, prev_t = first, time.monotonic()
    t0 = prev_t
    try:
        while True:
            time.sleep(args.interval)
            now_t = time.monotonic()
            cur = sample_once(client, args.port)
            dt = now_t - prev_t
            if dt <= 0:
                continue
            snap: dict[int, list[float]] = {}
            for port in ports:
                q_prev = prev.get(port, {}).get(field, [])
                q_cur = cur.get(port, {}).get(field, [])
                n = max(len(q_prev), len(q_cur))
                snap[port] = [
                    ((q_cur[i] if i < len(q_cur) else 0)
                     - (q_prev[i] if i < len(q_prev) else 0)) / dt
                    for i in range(n)
                ]
            timestamps.append(now_t - t0)
            samples.append(snap)
            total = sum(sum(v) for v in snap.values())
            print(f"[{now_t - t0:7.1f}s] 总{unit}: {total:12,.0f}", flush=True)
            prev, prev_t = cur, now_t
            if args.duration > 0 and now_t - t0 >= args.duration:
                break
    except KeyboardInterrupt:
        print("\n结束采集, 生成图表...")

    if not samples:
        sys.exit("没有采到任何数据。")

    # ---- CSV (逐队列明细) ----
    csv_path = f"{args.out}.csv"
    n_q = max((len(v) for s in samples for v in s.values()), default=0)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        header = ["time_s"]
        for port in ports:
            header += [f"port{port}_q{i}_{unit}" for i in range(n_q)]
        w.writerow(header)
        for t, s in zip(timestamps, samples):
            row = [f"{t:.2f}"]
            for port in ports:
                q = s.get(port, [])
                row += [f"{q[i]:.1f}" if i < len(q) else "0" for i in range(n_q)]
            w.writerow(row)
    print(f"[ok] CSV : {csv_path}")

    # ---- 图表 ----
    if plt is None:
        return
    fig, axes = plt.subplots(len(ports), 1, figsize=(12, 4 * len(ports)),
                             squeeze=False, sharex=True)
    for ax, port in zip(axes[:, 0], ports):
        n_q = max(len(s.get(port, [])) for s in samples)
        for qi in range(n_q):
            series = [s.get(port, [0] * n_q)[qi] if qi < len(s.get(port, []))
                      else 0 for s in samples]
            ax.plot(timestamps, series, label=f"q{qi}", linewidth=1.2)
        total = [sum(s.get(port, [])) for s in samples]
        ax.plot(timestamps, total, color="black", linewidth=2.0,
                linestyle="--", label="total")
        ax.set_title(f"port {port} RX per-queue {unit}")
        ax.set_ylabel(unit)
        ax.grid(alpha=0.3)
        ax.legend(ncol=min(8, n_q + 1), fontsize=8, loc="upper right")
    axes[-1, 0].set_xlabel("time (s)")
    fig.suptitle(f"testpmd RX per-queue stats  "
                 f"({datetime.now():%Y-%m-%d %H:%M:%S}, "
                 f"interval={args.interval}s)")
    fig.tight_layout()
    png_path = f"{args.out}.png"
    fig.savefig(png_path, dpi=150)
    print(f"[ok] 图表: {png_path}")


if __name__ == "__main__":
    main()
