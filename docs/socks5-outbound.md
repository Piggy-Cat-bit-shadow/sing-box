# SOCKS5 出站

| Commit | 工作 |
| --- | --- |
| [`5c3ae3e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5c3ae3e67fd560b73f94cfaadcfc68f1759e818a) | 按上传和下载各自的写入方选择缓冲区扩容阈值，保留 SOCKS5 出站的可选调优，避免另一方向无谓扩容。 |
| [`10636c7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/10636c702407178a4f24ad2e50a3217d059e5cbd) | 为 SOCKS5 出站增加默认关闭的 TCP 预连接池和提前扩容选项；预连接提前完成握手与认证，提前扩容用于链式转发。 |
