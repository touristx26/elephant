#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap 分析脚本: 读取 pcap, 输出流量概览 / 速率时间线 / 大象流统计 / 背景流统计

分类规则: 线上包长 >= ele-min 的包为大象包, 含大象包的流为大象流,
其余为背景流。只统计大象流与背景流两类信息的数量和速率, 不做块结构分析。

用法:
    uv run analyze_pcap.py                              # 默认分析 dpdk_out/scenario.pcap
    uv run analyze_pcap.py x.pcap --bin 0.5 --top 20   # 自定义分桶/TopN
"""
from __future__ import annotations

import argparse
import os
from collections import Counter, defaultdict

from scapy.all import IP, TCP, UDP, PcapReader


def main() -> None:
    ap = argparse.ArgumentParser(description="pcap 流量分析 (大象流/背景流统计)")
    ap.add_argument("pcap", nargs="?", default="dpdk_out/scenario.pcap",
                    help="pcap 文件路径 (默认 dpdk_out/scenario.pcap)")
    ap.add_argument("--bin", type=float, default=1.0,
                    help="速率时间线分桶秒数 (默认 1.0)")
    ap.add_argument("--top", type=int, default=10,
                    help="背景流 Top N 条数 (默认 10)")
    ap.add_argument("--ele-min", type=int, default=1000,
                    help="大象包判定: 线上字节数 >= 此值 (默认 1000)")
    args = ap.parse_args()

    if not os.path.isfile(args.pcap):
        raise SystemExit(f"[错误] 文件不存在: {args.pcap}")

    # ---------- 扫描 ----------
    # flows: 五元组 -> [包数, 字节, 首包时间, 末包时间, 是否大象流]
    flows: dict[tuple, list] = {}
    bins: dict[int, list] = defaultdict(lambda: [0, 0])   # 桶号 -> [包数, 字节]
    bins_ele: set[int] = set()                            # 含大象包的桶
    n = 0
    total_bytes = 0
    n_ele_pkts = n_ele_bytes = 0
    t_first = t_last = None

    with PcapReader(args.pcap) as r:
        for p in r:
            n += 1
            ts = float(p.time)
            ln = len(p)
            total_bytes += ln
            if t_first is None:
                t_first = ts
            t_last = ts
            bi = int((ts - t_first) // args.bin)
            bins[bi][0] += 1
            bins[bi][1] += ln

            if IP not in p or (TCP not in p and UDP not in p):
                continue
            is_tcp = TCP in p
            l4 = p[TCP] if is_tcp else p[UDP]
            tup = (p[IP].src, p[IP].dst, l4.sport, l4.dport,
                   "TCP" if is_tcp else "UDP")
            is_ele = ln >= args.ele_min
            if is_ele:
                n_ele_pkts += 1
                n_ele_bytes += ln
                bins_ele.add(bi)
            st = flows.get(tup)
            if st is None:
                flows[tup] = [1, ln, ts, ts, is_ele]
            else:
                st[0] += 1
                st[1] += ln
                st[3] = ts
                st[4] = st[4] or is_ele

    if n == 0:
        raise SystemExit("[错误] pcap 中没有包")

    dur = max(t_last - t_first, 1e-9)
    ele_flows = {k: v for k, v in flows.items() if v[4]}
    bg_flows = {k: v for k, v in flows.items() if not v[4]}
    n_bg_pkts = n - n_ele_pkts
    n_bg_bytes = total_bytes - n_ele_bytes

    # ---------- 输出 ----------
    W = 70
    print("=" * W)
    print(f"pcap 分析: {args.pcap}")
    print("=" * W)

    print("\n[1] 总体画像")
    print(f"  总包数      : {n}")
    print(f"  时间跨度    : {dur:.2f} s")
    print(f"  总字节      : {total_bytes / 1e6:.1f} MB")
    print(f"  平均速率    : {n / dur:.0f} pkt/s, "
          f"{total_bytes * 8 / dur / 1e6:.1f} Mbps")
    print(f"  流总数      : {len(flows)} "
          f"(大象流 {len(ele_flows)} / 背景流 {len(bg_flows)})")

    print(f"\n[2] 速率时间线 (bin={args.bin:g}s, '#'≈大象突发)")
    max_bin_pkts = max(v[0] for v in bins.values())
    for bi in sorted(bins):
        pkts, nbytes = bins[bi]
        t0 = bi * args.bin
        bar = "#" * max(1, round(pkts / max_bin_pkts * 30))
        mark = " <== 大象突发" if bi in bins_ele else ""
        print(f"  t={t0:7.2f}s  {pkts:>8} pkts  "
              f"{nbytes * 8 / args.bin / 1e6:>7.1f} Mbps  {bar}{mark}")

    # ---------- 大象流统计 ----------
    print(f"\n[3] 大象流统计 (判定: 包长>={args.ele_min}B)")
    print(f"  流数        : {len(ele_flows)}")
    print(f"  包数        : {n_ele_pkts} ({n_ele_pkts / n * 100:.0f}% 全部包)")
    print(f"  字节        : {n_ele_bytes / 1e6:.1f} MB "
          f"({n_ele_bytes / total_bytes * 100:.0f}% 全部字节)")
    print(f"  平均速率    : {n_ele_pkts / dur:.0f} pkt/s, "
          f"{n_ele_bytes * 8 / dur / 1e6:.1f} Mbps")
    if ele_flows:
        # 突发期速率: 只统计含大象包的桶
        ele_bins = [bins[bi] for bi in sorted(bins_ele)]
        eb_pkts = sum(v[0] for v in ele_bins)
        eb_bytes = sum(v[1] for v in ele_bins)
        eb_time = len(ele_bins) * args.bin
        print(f"  突发期速率  : {eb_pkts / eb_time:.0f} pkt/s, "
              f"{eb_bytes * 8 / eb_time / 1e6:.1f} Mbps "
              f"(按 {len(ele_bins)} 个含大象桶估算)")
        print(f"  明细:")
        for i, (tup, (pkts, nbytes, ts0, ts1, _)) in enumerate(
                sorted(ele_flows.items(), key=lambda x: -x[1][0]), 1):
            span = max(ts1 - ts0, 1e-9)
            print(f"    #{i:<3}{pkts:>8} pkts  {nbytes / 1e6:>7.2f} MB  "
                  f"跨度 {span:6.2f}s  {pkts / span:>8.0f} pkt/s  "
                  f"{tup[0]}:{tup[2]} -> {tup[1]}:{tup[3]} {tup[4]}")

    # ---------- 背景流统计 ----------
    print(f"\n[4] 背景流统计")
    print(f"  流数        : {len(bg_flows)}")
    print(f"  包数        : {n_bg_pkts} ({n_bg_pkts / n * 100:.0f}% 全部包)")
    print(f"  字节        : {n_bg_bytes / 1e6:.1f} MB "
          f"({n_bg_bytes / total_bytes * 100:.0f}% 全部字节)")
    print(f"  平均速率    : {n_bg_pkts / dur:.0f} pkt/s, "
          f"{n_bg_bytes * 8 / dur / 1e6:.1f} Mbps")
    if bg_flows:
        pkts_per_flow = [v[0] for v in bg_flows.values()]
        proto = Counter(k[4] for k in bg_flows)
        print(f"  每流包数    : 平均 {sum(pkts_per_flow) / len(pkts_per_flow):.1f}, "
              f"最大 {max(pkts_per_flow)}, "
              f"总包/流比 {n_bg_pkts}/{len(bg_flows)}")
        dist = Counter(pkts_per_flow)
        print(f"  包数分布    : " + ", ".join(
            f"{k}包x{dist[k]}条" for k in sorted(dist)))
        print(f"  协议分布    : " + ", ".join(
            f"{k} {v}条" for k, v in proto.most_common()))
        top = sorted(bg_flows.items(), key=lambda x: -x[1][0])[:args.top]
        print(f"  Top{len(top)} 背景流:")
        for i, (tup, (pkts, nbytes, ts0, ts1, _)) in enumerate(top, 1):
            print(f"    #{i:<3}{pkts:>8} pkts  {nbytes / 1e3:>8.1f} KB  "
                  f"跨度 {ts1 - ts0:6.2f}s  "
                  f"{tup[0]}:{tup[2]} -> {tup[1]}:{tup[3]} {tup[4]}")
    print()


if __name__ == "__main__":
    main()
