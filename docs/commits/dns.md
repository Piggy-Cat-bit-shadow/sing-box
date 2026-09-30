# DNS

[当前 DNS 配置](../configuration/dns/index.md)

| Commit | 工作 |
| --- | --- |
| [`a03eb2d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a03eb2d5fb11f40a5632754349f82440f0004e8a) | 将 SOCKS4 目标解析测试收窄到未配置域名解析器的场景，删除把旧缺陷当作预期行为的断言。 |
| [`d676b4a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d676b4a626bdd7cedb759394ace40da0e1b0059f) | 从 DialerOptions 直接推导 SOCKS4 目标解析策略，不再依赖代理服务器是否为域名。 |
| [`9260e8a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9260e8a95c2b07ecea0a3ad6e64b47adb95025ed) | 补充各协议数据传输和 DNS 审计的结论与依据。 |
| [`977f530`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/977f53031f6800ad08d002e090b6bc83a9f47615) | 明确 WireGuard 的两个 DNS 授权边界，不再让语义保持隐含。 |
| [`43ffa93`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/43ffa9334082f87ff866da3536042dab9a1262e4) | SOCKS4 目标地址改用出口自身的解析器，避免误用入站解析结果。 |
| [`d1b7eda`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d1b7edac2a7ca52bb5feadf2a7437325ee78b230) | 停止格式化被日志级别丢弃的逐记录日志行。 |
| [`b6b68b8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b6b68b85a7cfe5b58d6e33a57009a7d5f2222229) | 共享查询失败后重新竞争重试代次。 |
| [`6910cb1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6910cb1af06122c5e0cb2455604554e5d880149c) | 固定住宅链路的 DNS 排序契约，并加入测试保护。 |
