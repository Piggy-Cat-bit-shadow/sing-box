# sing-box

**平台：** macOS arm64 · Linux amd64

## [Pruning](docs/commits/pruning.md)

按 Linux 服务端与 macOS 客户端分别裁剪构建标签和注册表。<br>
保留各自实际使用的入站、出站、DNS 与 MASQUE 能力。<br>
移除不需要的协议注册、命令和链接依赖，缩小发布构件。<br>
通过构建、符号与启动检查验证裁剪结果，避免误删必需能力。

## [MASQUE](docs/commits/masque.md)

完善 CONNECT-IP、CONNECT-UDP 与 HTTP/2、HTTP/3 隧道行为。<br>
优化 DATAGRAM 批量发送、缓冲区所有权和内存分配。<br>
处理 DNS_ASSIGN、PREF64、PTB 与 capsule 回退的边界。<br>
补充连接生命周期、异常路径和参考互通测试。

## [Naive](docs/commits/naive.md)

实现 Native Naive 服务端与 macOS 的 Cronet 客户端出站。<br>
核对 CONNECT、padding 和 HTTP/1、HTTP/2、HTTP/3 封装行为。<br>
完善 UoT、伪装、目标访问控制与服务端资源限制。<br>
修正异步缓冲区生命周期，并补充协议对照与数据路径测试。

## [SOCKS5 出站](docs/commits/socks5-outbound.md)

增加默认关闭的 TCP 预连接池，提前建连并完成握手、认证。<br>
请求到来后发送 CONNECT；池为空时仍正常建立连接。<br>
复制缓冲区的提前扩容也默认关闭，用于链式转发。<br>
按上传、下载各自的写入端判断扩容，避免另一方向无谓分配。

## [Shadowsocks](docs/commits/shadowsocks.md)

聚焦 Shadowsocks 稳态上传的缓冲区布局。<br>
把原位封装所需的空间上限传给 copy 循环。<br>
空间足够时保持原位写入，避免上传落入复制分支。

## [DNS](docs/commits/dns.md)

明确 SOCKS4 目标域名的解析权归属，避免复用入站结果。<br>
梳理其他协议的 DNS 边界和住宅链路的解析排序。<br>
修复共享查询失败后的重试代次，减少无效日志格式化。<br>
用回归测试固定解析策略与查询路径的行为。

## [Other](docs/commits/other.md)

收录跨协议修复、公共缓冲区与连接所有权改动。<br>
包括通用 HTTP/3 连接缓存、错误分类和重试边界。<br>
记录构建、依赖、CI 与发布链路的工程调整。<br>
也收录相关回归测试、基准测量和能力审计。

---

当前架构与使用说明：[构建配置](docs/BUILD-PROFILES.md) · [服务端](docs/JIEJIE-SERVER.md) · [macOS 客户端](docs/JIEJIE-MACOS-CLIENT.md) · [工程笔记](docs/ENGINEERING-NOTES.md)
