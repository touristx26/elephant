| 维度                         | 含义             | 常见指标                                    |
| -------------------------- | -------------- | --------------------------------------- |
| **Flow Size**              | Flow 总体规模      | Bytes、Packets                           |
| **Flow Rate**              | Flow 的传输速率     | Average / Peak Throughput               |
| **Flow Duration**          | Flow 持续时间      | Start → End                             |
| **Time-window Volume**     | 某个时间窗口内的流量     | Bytes/s、Packets/s                       |
| **Packet Rate**            | 发包速率           | PPS                                     |
| **Burstiness**             | 流量是否突发         | IAT、Burst size、Peak/Avg ratio           |
| **Flow Identity**          | 如何确定“同一个 flow” | 5-tuple（IP、Port、Protocol）               |
| **Network Resource Usage** | 对网络资源的占用       | Bandwidth、Queue/Buffer、Link utilization |


pcap+pktgen 模式：
- Flow Size 可以保证
- Flow Rate没法保证
- Flow Duration没法保证
- Time-window Volume 无法保证
- Packet Rate 可以保证（`set rate X%` 恒定排空速率，均值恒定；但为端口级恒定速率，突发被抹平）
- Burstiness 可以保证（※存疑：恒定速率排空时突发结构被抹平；全速回放时整个场景退化为一个大脉冲）
- Flow Identity 可以保证
- Network Resource Usage 可以保证（※存疑：恒定速率下链路占用无波动，无法制造队列/缓冲压力的起伏）

lua+pktgen 模式:
- Flow Size 没法精确保证（大象流 size = rate% × duration，由线速百分比折算，受实际协商速率/帧间隙影响；背景流 range 逐包递增元组，每条"流"只有 1 个包，无法构造多包背景流）
- Flow Rate 粗粒度保证（rate 是线速百分比：10G 口 0.001% ≈ 195pps@64B，低于此粒度的低速背景流设不准；且为端口级速率而非每流速率）
- Flow Duration 近似保证（Lua start→pause(N)→stop，pause 为秒级 sleep，精度 ~1s 量级，受统计屏幕刷新影响）
- Time-window Volume 近似保证（窗口内总量 = rate × 窗口长，精度受 rate 折算与 pause 分辨率限制）
- Packet Rate 粗粒度保证（同 Flow Rate：均值可控、百分比粒度；低速不准）
- Burstiness 可以保证（周期 start/stop + ±20% 抖动可构造突发，Peak/Avg 比由两档 rate 决定；但突发内部 IAT 为硬件均匀间隔，非泊松等真实分布）
- Flow Identity 部分保证（大象流五元组固定 ✓；背景流元组按 range 确定性递增——序列可预测、非随机抽取，且流数无法精确控制）
- Network Resource Usage 近似保证（带宽占用随突发起伏 ✓，可用于打队列/缓冲压力；幅度精度受 rate 折算限制）

补充：lua+pktgen 有两个表外硬伤：
1. 载荷为模板随机字节，DPI 无法做应用层识别；
2. 一个 stream 使用固定 packet template 发包，range 模式下五元组逐包递增，
   每条"流"只有 1 个包 —— 发不出大量多包小流，流长分布/流数/到达节奏均不可控，
   无法模拟真实 DPI 业务场景的背景流量（数万条几十~几百包的小流）。

