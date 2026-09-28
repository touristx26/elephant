# pktg — 大象流 pcap 场景生成器

基于 [scapy](https://scapy.net/) 构造 pcap:背景流中周期性插入完整的大象流包块。

## pcap 结构

包序按时间轴严格分块:

```
背景流块(约 30s, 100pps 小包) → 大象流块(10s, 8000pps 大包) → 背景流块 → 大象流块 → ...
```

块内包间隔按各自速率烘焙进 pcap 时间戳;用遵循时间戳的回放工具(tcpreplay)原速回放即可重现节奏。

## 流模型

背景流与大象流**各自独立配置**,字段规则一致:

| 字段 | 规则 |
|---|---|
| 源 IP | 从配置范围(`bg-src-ip` / `el-src-ip`,CIDR 或逗号分隔)随机抽取 |
| 源 MAC | 从配置池(`*-src-mac` 基址 + `*-src-mac-count`)随机抽取 |
| 目的 IP | 固定,`bg-dst-ip` / `el-dst-ip` 单个地址 |
| 目的 MAC | 固定,`bg-dst-mac` / `el-dst-mac`(默认广播) |

- **背景流块**: 泊松到达小包(70% UDP DNS/心跳风格 / 30% TCP)。**每条流最多 `bg-packets-per-flow` 个包**(硬上限,每条流在 1..N 内随机)即切换新流,新流五元组强制避开最近 128 条用过的——高频、少量包、大量流,且不会因随机碰撞把小流粘成伪大象流
- **大象流块**: 块首随机定源、**块内五元组完全一致**(整块一条流),TCP "PA" 大包 + FIN 收尾

## 用法

```bash
uv sync                                     # 装依赖 (scapy + pyyaml)
uv run main.py -c config.yaml               # 全部参数走配置文件
uv run main.py -c config.yaml --elephant-pps 20000   # 命令行临时覆盖
```

输出 `<out-dir>/scenario.pcap`(默认 `dpdk_out/`)。

## 回放

用**遵循 pcap 时间戳**的工具,不要用 pktgen(它回放 pcap 是线速排空,时间结构会丢失):

```bash
sudo tcpreplay -i eth0 scenario.pcap            # 按时间戳原速回放
sudo tcpreplay -i eth0 --loop=10 scenario.pcap  # 循环 10 遍拉长测试
```

接收端统计:

```bash
sudo dpdk-testpmd -l 0-2 -n 4 -a <PCI> -- -i --rx-only --stats-period 1
```

## 主要参数

| 参数 | 说明 | 默认 |
|---|---|---|
| `bg-src-ip` / `el-src-ip` | 背景/大象流源 IP 随机范围 | 172.16.0.0/16 / 172.17.0.0/16 |
| `bg-src-mac`(-count) / `el-src-mac`(-count) | 背景/大象流源 MAC 池基址与大小 | 02:...01:00×256 / 02:...02:00×64 |
| `bg-dst-ip` / `el-dst-ip` | 背景/大象流目的 IP(固定) | 10.0.0.1 |
| `bg-dst-mac` / `el-dst-mac` | 背景/大象流目的 MAC(固定) | 广播 |
| `normal-pps` | 背景流速率 pkt/s(泊松) | 100 |
| `bg-packets-per-flow` | 背景流每条流最大包数(1=每包一流) | 8 |
| `elephant-pps` | 大象流速率 pkt/s(均匀,块内五元组一致) | 8000 |
| `elephant-size` | 大象流载荷字节 | 1400 |
| `elephant-duration` | 大象块持续秒数 | 10 |
| `elephant-interval` | 背景块时长(大象出现间隔)秒,±20% 抖动 | 30 |
| `duration` / `repeat` | 一轮时长 / 拼接轮数 | 60 / 1 |
| `seed` | 随机种子(复现) | - |
| `out-dir` | 输出目录 | dpdk_out |

优先级:命令行 > 配置文件 > 默认。

## 注意

- 生成是流式写盘,内存占用与场景长度无关
- 回放速率上限由回放工具决定:tcpreplay 单核可达数 Gbps(大包);更高需求考虑 TRex
- 请仅用于自有测试环境