# sing-box · Jiejie Fork

## ✨ 项目特色

### ⚡ 业务感知流量调度

引入通用 `traffic_class`：

- `interactive`
- `realtime`
- `default`
- `bulk`

在上传带宽受限时，优先保护对延迟敏感的交互流量，避免大流量传输把首包和交互请求完全堵住。

AI 流量支持根据节点 / 代理组名称自动识别，包括 ChatGPT、Claude、Gemini、DeepSeek、Grok、Perplexity 等。

Telegram、YouTube 及其他业务也可以通过统一的 `traffic_class` 接入同一套调度体系，而不需要让各个代理协议分别实现 QoS。

---

### 📡 Mihomo 风格智能测速

重新设计 URLTest 测量路径，并对齐 Mihomo `unified-delay` 的核心语义：

**建立线路 → 第一次请求预热 → 第二次请求正式测速**

第一次请求负责完成代理握手、目标连接、TLS、HTTP 会话等冷启动过程，第二次请求复用已经建立的传输路径进行正式计时，使结果更接近线路进入稳定状态后的实际延迟。

URLTest、自动测速、API Delay Test 与 Load Balance 共用统一测量引擎和健康数据，同时限制移动端并发测速造成的额外 Socket、TLS 与内存开销。

---

### ⚖️ Flow-aware Load Balance

新增 fork 专属 `loadbalance` 出站组。

支持：

- `round_robin`
- `consistent_hashing`
- `sticky_sessions`
- URLTest 健康状态过滤

负载均衡以 **Flow / Session** 为单位，而不是逐包切换线路：

- 一个 TCP Flow 生命周期内保持同一节点
- 一个 UDP Session 生命周期内保持同一节点

---

### 🛣️ System Proxy Cooperative Fast Path

针对系统代理路径进行了专门优化。

能够使用 HTTP / SOCKS 系统代理的应用优先经过更轻量的 Mixed / System Proxy 路径，不需要先进入完整的 TUN 包处理流程。

无法使用系统代理的流量继续由 TUN 接管。

```text
System Proxy ─┐
              ├─ Shared Routing / DNS / Outbound Core
TUN ──────────┘
```

两条路径最终汇入同一套核心，因此路由、DNS、出站协议以及大部分共享优化无需重复实现。

System Proxy Fast Path 保持尽量轻量，只负责代理协议边界、目标信息与早期数据交接，不重新复制一套 TUN 的包捕获、协议栈恢复和流重建逻辑。

---

### 🧠 iOS NetworkExtension Low Memory Mode

针对 iOS NetworkExtension 严格的内存环境提供独立低内存路径，而不是简单增加一个运行时开关。

iOS / tvOS Libbox 使用专门的 `with_low_memory` 构建：

- 移动端 Buffer Geometry 从默认 32 KiB 缩小到 16 KiB
- macOS 保持正常 Buffer Geometry，不为桌面平台牺牲不必要的吞吐性能
- iOS Packet Tunnel 默认启用 OOM Protection
- 对 Go Runtime 设置独立 Memory Limit
- 同时监控整个 NetworkExtension 进程的实际 Memory Footprint
- 接入 Darwin Memory Pressure 事件
- 在达到压力阈值或检测到异常内存增长速度时主动释放资源
- 空闲连接、Goroutine 等资源明显收缩后主动归还空闲内存
- 记录 Runtime Memory Diagnostics 与压力状态，便于真实设备调试

内存保护不是只观察 Go Heap。

NetworkExtension 中还存在 Swift、C / CGO、系统框架、网络栈以及其他 Native Allocation，因此项目将 **Go Runtime Memory Limit** 与 **Process-level Footprint Monitoring** 分开处理。

当前策略使用约 50 MiB 的 NetworkExtension fallback / tuning budget，并预留安全余量，用于驱动 GC、压力状态与主动回收逻辑。

该数值是项目针对 NetworkExtension 的保护策略，并不代表 Apple 对所有设备提供固定 50 MiB 的官方内存保证。

**尽量降低常驻内存与并发峰值，并在系统 Jetsam 之前更早发现和释放可回收资源。**

---

### 🌐 Shared Dual-Stack & DNS Core

双栈与 DNS 优化被放在共享核心，而不是绑定到某一个代理协议。

包括：

- IPv4 / IPv6 地址交错与竞争
- A / AAAA 并发查询
- 保留 DNS Rule、Cache、Singleflight 等原有语义
- 网络切换 Generation 隔离
- FakeIP 生命周期与边界处理
- TUN IPv4-mapped IPv6 等异常场景修复
- DNS Transport 生命周期与连接复用改进

双栈拨号逻辑本身保持协议无关，因此 MASQUE、Naive、VLESS、AnyTLS 等不同协议可以共同受益。

---

### 🛡️ Fallback / Masquerade 与主动探测防护

部分服务端协议加入了面向公网部署的 **Fallback / Masquerade** 处理。

当收到未认证请求、普通 HTTP 访问或不符合代理协议预期的探测流量时，可以回落到正常 Web 页面或指定后端，而不是直接暴露代理服务行为。

相关能力覆盖 MASQUE、Native Naive、AnyTLS 等实际部署路径，包括：

- Fallback 页面
- 普通 HTTP / Web Masquerade
- 未认证请求回落
- ALPN 相关 Fallback
- 非预期探测请求的边界处理

目标不是宣称“不可探测”，而是**尽量减少协议服务面对主动探测时暴露出的明显特征**，让节点在公网环境下表现得更接近正常 Web 服务。

---

### 🧩 Protocol Completeness

在保持 upstream 协议能力的基础上，对部分协议进行了修改。

#### MASQUE / CONNECT-IP

- HTTP/2 / HTTP/3
- CONNECT / CONNECT-UDP
- CONNECT-IP
- ADDRESS_ASSIGN
- ROUTE_ADVERTISEMENT
- DNS_ASSIGN
- PREF64
- Capsule fallback
- HTTP/3 DATAGRAM 与生命周期处理
- Masquerade / 非代理请求回落

重点修改了 QUIC / HTTP/3 下的 Buffer Ownership、DATAGRAM 发送路径、连接复用、取消、迁移与异常生命周期。

#### Native Naive

- Native Naive Server
- macOS Cronet Naive Client
- HTTP/1.1 / HTTP/2 / HTTP/3
- Padding / Framing
- UoT
- Masquerade
- ACL 与 Pre-auth Resource Control
- 未认证请求与普通 Web 请求的伪装处理

#### AnyTLS

- Default fallback
- ALPN-specific fallback
- TLS 终止后的回落处理

同时继续完善 SOCKS5、Shadowsocks / ShadowTLS 等实际使用路径。

---

## 📚 更多文档

详细实现与边界说明可查看：

- `docs/FORK-DIFF.md`
- `docs/ENGINEERING-NOTES.md`
- `docs/BUILD-PROFILES.md`
- `docs/fork/traffic-scheduler.md`
- `docs/fork/load-balance.md`
- `docs/naive.md`

---

## ❤️ Credits

本项目基于 [SagerNet/sing-box](https://github.com/SagerNet/sing-box) 开发。

部分测速、负载均衡及相关行为参考了 Mihomo 的成熟实现与语义，并结合 sing-box 的架构重新集成。

---
