# 住宅代理链路

链路拓扑与配置边界见 [住宅 SOCKS 链路说明](JIEJIE-RESIDENTIAL-CHAIN.md)。

| Commit | 工作 |
| --- | --- |
| [`5c3ae3e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5c3ae3e67fd560b73f94cfaadcfc68f1759e818a) | 按上传和下载各自的写入方选择缓冲区扩容阈值，保留住宅 SOCKS 出站的可选调优，避免另一方向无谓扩容。 |
| [`0068728`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0068728f233d4fcfc2534c9daa379ab98134c600) | 说明住宅代理链路的拓扑、VPS 侧 DNS 解析、TCP 预连接和资源边界。 |
| [`6910cb1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6910cb1af06122c5e0cb2455604554e5d880149c) | 测试住宅用户的 UDP 拒绝规则，以及 VPS 先按 ipv4_only 解析、再转发到住宅 SOCKS5 的规则顺序。 |
| [`10636c7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/10636c702407178a4f24ad2e50a3217d059e5cbd) | 增加可选的 SOCKS5 TCP 预连接和提前扩容配置；前者预先完成握手与认证，后者让链式出口更早扩大复制缓冲区。 |
