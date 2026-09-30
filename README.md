# sing-box

**Platforms:** macOS arm64 · Linux amd64

## [Pruning](docs/pruning.md)

**保留：** Direct、Group、HTTP / MASQUE、Shadowsocks、ShadowTLS、VLESS、AnyTLS、Naive、MASQUE Client。  
**移除：** VMess、Trojan、Snell、Hysteria2、TUIC、WireGuard、Tailscale、OpenVPN、OpenConnect、SSH、Tor。

## [MASQUE](docs/masque.md)

围绕 HTTP/3 DATAGRAM 数据面优化发送路径与队列模型。  
Outbound payload 改为 ownership-transfer zero-copy，减少 payload copy 与 per-packet allocation。  
增加 batch enqueue、失败回滚、关闭路径与异步 ownership 校验。

## [Naive](docs/naive.md)

优化 cached payload 到 Cronet 的 owned-buffer handoff 与 framing 路径。  
校正 async read/write buffer lifetime，覆盖 deadline、cancel、close 与 terminal callback 边界。  
减少首包 plaintext copy，并校验 Cronet DNS 与 socket handoff 的实际解析路径。

## [住宅代理链路](docs/residential-proxy.md)

本仓库的住宅 AnyTLS 链路在 VPS 上先将目标域名解析为 IPv4，再通过 SOCKS5 连接住宅出口；住宅用户的 UDP 流量仍被拒绝。
可选的 TCP 预连接会提前完成 SOCKS5 握手和认证，请求到来时只需发起 CONNECT，连接只使用一次。
可选的提前扩容按实际写入方向选择缓冲区阈值，避免另一方向无谓扩容；这些改动没有真实住宅代理链路的延迟或吞吐测试数据。

## [Shadowsocks](docs/shadowsocks.md)

按首包、稳态、上传、下载拆分审计 Shadowsocks 数据路径。  
利用 buffer geometry 与 in-place AEAD 减少 framing copy 和 allocation。  
区分 first-write、steady-state 与 NeedHeadroom 路径，避免将条件性 copy 误计为协议固定开销。

## [DNS](docs/dns.md)

校正 resolver authority 与不同协议的目标解析边界。  
修复 SOCKS4 target resolution、代理端点解析与隧道内 DNS authority 混用问题。  
清理 cache-hit、query options、logging 与结果处理中的 hot-path 固定开销。

## [Other](docs/other.md)

通用修复、性能优化、测试基础设施、构建、CI、跨协议改动与工程维护。  
收录无法自然归入单一协议或裁剪分类的提交。  
包括公共 buffer / ownership、回归测试、mutation、benchmark 与发布链路相关改动。
