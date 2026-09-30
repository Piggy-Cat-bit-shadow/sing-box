# sing-box

**平台：** macOS arm64 · Linux amd64

## [构建与完整功能集](docs/BUILD-PROFILES.md)

macOS 客户端与 Linux 服务端都采用 upstream 官方的完整 registry 与 build-tag profile，不再维护本 fork 专属的协议白名单。
upstream 新增协议、endpoint、DNS transport、service 或证书提供者时会被自动继承，无需再手工维护一份 allowlist。
本 fork 只在 upstream 源码之上维护自己的协议、传输、正确性与性能优化。唯一例外是 Clash API：它因控制面架构决策被移除，而非为缩减体积。

## [MASQUE](docs/commits/masque.md)

保留 H2 / H3 MASQUE 与 CONNECT-IP，共用现有 HTTP / QUIC 传输层。  
优化 H3 DATAGRAM 的缓冲区所有权、批量入队与发送路径，减少逐包分配和 payload 拷贝。  
补齐 ADDRESS_ASSIGN、ROUTE_ADVERTISEMENT、DNS_ASSIGN、PREF64、PTB 与 capsule fallback，并覆盖连接复用、取消、失效连接与迁移等生命周期边界。

## [Naive](docs/commits/naive.md)

Linux 服务端提供 Native Naive inbound，macOS 客户端使用 Cronet Naive outbound；服务端不链接 Cronet 客户端栈。  
修正 padding / framing、短写、HTTP/1 与 H2/H3 行为差异，以及异步回调下的缓冲区生命周期。  
保留 UoT、masquerade、目标 ACL 与服务端资源控制，并优化首包向 Cronet 的 owned-buffer handoff。

## [SOCKS5 出站](docs/commits/socks5-outbound.md)

保留住宅出口使用的 SOCKS5 出站，并提供默认关闭的 TCP 预连接与 copy-buffer 调优。  
预连接提前完成 TCP 建连、SOCKS5 握手和认证；请求到达后仅发送 CONNECT，池为空时直接回退到正常建连。  
缓冲区扩容按实际写入方向独立判断，避免无效内存增长。

## [Shadowsocks](docs/commits/shadowsocks.md)

服务端生产链路保留 Shadowsocks 2022，并由 ShadowTLS v3 作为外层传输。  
围绕 buffer geometry、WriterMTU 与原位 AEAD 优化数据面，在预留空间满足条件时避免额外 payload copy。  
首包、稳态传输与 headroom 不足路径分别处理，保持协议语义不变。

## [DNS](docs/commits/dns.md)

区分代理端点解析与最终目标解析的责任边界，避免不同协议复用错误的 DNS authority。  
SOCKS4 目标域名使用目标侧解析策略；住宅 SOCKS 链路在 VPS 侧先解析 IPv4，再交由住宅出口连接。  
同时优化共享查询、缓存命中和日志路径，并以回归测试固定解析顺序与策略边界。

## [Other](docs/commits/other.md)

收录跨协议与公共基础设施改动，包括 buffer ownership、HTTP/3 连接缓存、错误分类、重试边界与通用数据路径修复。  
同时覆盖产品注册表、Native API、构建系统、依赖完整性、CI 与发布链路等工程维护。

---

当前架构与使用说明：[构建配置](docs/BUILD-PROFILES.md) · [服务端](docs/JIEJIE-SERVER.md) · [macOS 客户端](docs/JIEJIE-MACOS-CLIENT.md) · [工程笔记](docs/ENGINEERING-NOTES.md)
