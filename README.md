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

## [VLESS / Vision](docs/vless-vision.md)

本 fork 暂无以 VLESS / Vision 为主要改动的独立提交。仓库历史中已有上游的相关提交；涉及 VLESS 的跨协议或构建改动按主要用途列入其他分类。

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
