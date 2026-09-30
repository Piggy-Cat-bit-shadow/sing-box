# sing-box

**平台：** macOS arm64 · Linux amd64

## [Pruning](docs/commits/pruning.md)

精简服务端与 macOS 客户端的构建标签、注册表和链接内容，保留各自实际使用的协议能力。

## [MASQUE](docs/commits/masque.md)

优化 CONNECT-IP、CONNECT-UDP、HTTP/3 DATAGRAM、缓冲区所有权和隧道生命周期。

## [Naive](docs/commits/naive.md)

实现 Native Naive 服务端与 Cronet 客户端，并修正 UoT、封装、伪装和资源控制。

## [SOCKS5 出站](docs/commits/socks5-outbound.md)

增加默认关闭的 TCP 预连接与复制缓冲区调优，改善链式转发路径。

## [Shadowsocks](docs/commits/shadowsocks.md)

调整首包与稳态传输的缓冲区布局，减少封装过程中的拷贝。

## [DNS](docs/commits/dns.md)

明确目标解析边界，修复解析策略混用并优化查询路径。

## [Other](docs/commits/other.md)

收录公共缓冲区、跨协议修复、构建、CI、测试与发布维护。

---

当前架构与使用说明：[构建配置](docs/BUILD-PROFILES.md) · [服务端](docs/JIEJIE-SERVER.md) · [macOS 客户端](docs/JIEJIE-MACOS-CLIENT.md) · [工程笔记](docs/ENGINEERING-NOTES.md)
