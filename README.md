# Jiejie Server Edition

> 基于 [SagerNet/sing-box](https://github.com/SagerNet/sing-box) `testing` 分支的个人
> VPS-only server fork。

---

## 先说在前面

这是我基于 sing-box `testing` 分支折腾的一套**个人 VPS Server Edition**。

主要围绕我自己实际使用的几条服务端协议、Web 伪装、Native NaiveProxy，以及生产构建裁剪
做了一些调整。它不是通用发行版，也不是为了取代上游——上游 sing-box 仍然是完整、通用且
持续维护的项目。这个仓库只是我按自己的服务器拓扑做的一套「小玩具」。

具体一点：

- **产品定位**：VPS-only server。只服务我自己的那台机器，不考虑客户端场景。
- **生产平台**：Linux amd64。
- **生产构建**：`jiejie_server_minimal` 这个 build profile。
- **长期同步**：跟着上游 `testing` 走，fork-specific 的改动尽量集中、可测试，方便以后
  继续 merge。

因为是自用分支，里面的默认值、端口、域名、路由规则都是**照着我的拓扑写的**，不是通用
最佳实践。你要拿去用，请把 `release/jiejie-production-topology.json` 当成一个**示例**读，
而不是当成推荐配置。

## Upstream / 致谢

```text
Upstream: https://github.com/SagerNet/sing-box
```

**这个 fork 里绝大多数东西都来自上游。** 协议实现、路由框架、DNS、TLS、传输层、
sing-quic / quic-go 集成、配置系统、CLI——基础能力全部是 SagerNet/sing-box 的成果。

我做的事情是：在一个已经非常完整的上游项目基础上，按自己服务器的实际拓扑做**定向组合
和扩展**——挑出真正要用的入口和出口，给几个服务端协议补上我需要的伪装、资源边界和
访问控制，然后把这套组合固化成可测试的生产构建。

没有上游，这个仓库不存在。

## 这个 fork 做了什么

| 方向 | 我的 fork |
| --- | --- |
| 产品定位 | VPS-only Server Edition，只服务固定拓扑 |
| 生产平台 | Linux amd64 |
| 生产构建 | `jiejie_server_minimal`（minimal registry，非通用构建） |
| MASQUE / HTTP | Web masquerade + server resource profile + pre-auth limits |
| AnyTLS | native fallback / `fallback_for_alpn` + pre-auth read timeout |
| ShadowTLS | 公网探测流量与服务端上游故障的错误分类 |
| Native Naive | 原生 server + Padding + UoT v1/v2 + masquerade + 目标 ACL |
| 生产裁剪 | 只注册实际使用的协议与服务，其余不进 import graph |
| CI | 两套 server-only workflow（Fast + Linux amd64） |
| 生产拓扑 | Nginx Stream + sing-box + local Web / AdGuard Home |

---

## 为自己的 VPS 做的最小化构建

这一节想讲清楚一件容易被误解的事：**裁剪不是把上游源码目录删掉。**

我没有大面积删上游代码。上游的完整构建能力仍然保留在仓库里——`include/registry.go`
（`!jiejie_server_minimal`）依然是完整的注册表，不带这个 tag 构建出来的还是通用
sing-box。我发布的只是一个**专门的 minimal server profile**。

最终方案是：

```text
build tag
  + minimal registry
  + 不注册
  + 不 import
  + Go linker dead-code elimination
= topology-specific production binary
```

关键点是**注册层面**的裁剪：`include/registry_jiejie_server.go` 不 import 某个包，
那个包就永远不进 import graph，Go linker 自然会把它们全部丢掉。不需要改上游源码，也
不需要维护一堆 `//` 注释掉的注册行。

当前 build tags：

```text
with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0
```

定义在 `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL`，构建脚本和 CI 都从这一个文件读，
避免两处漂移。

### 生产 binary 实际保留的东西

依据 `include/registry_jiejie_server.go`：

**Inbound**（五个入口，就这些）

```text
HTTP        → MASQUE HTTP/2（在 Nginx 后面）+ HTTP/3（UDP/443）
AnyTLS
Native Naive
ShadowTLS
Shadowsocks 2022
```

**Outbound**

```text
direct
SOCKS5（住宅出口 residential-socks）
```

**DNS transport**

```text
udp
local
```

`local` 不是功能选择，是**启动依赖**。`box.go` 无条件用一个 `C.DNSTypeLocal` transport
初始化 DNS transport manager，不注册它每次启动都会失败：

```text
default DNS server fallback: transport type not found: local
```

生产 DNS 实际走本机 AdGuard Home 的 UDP。`tcp` / `tls` / `https` / `hosts` /
`resolved` 都真的不在——顺带也把 D-Bus 依赖挡在二进制外面。

**Endpoint**

```text
none
```

**Service**

```text
none
```

**Certificate provider**

```text
none
```

证书是服务器外部用 acme.sh 管理的，不走 sing-box 的 provider。所以 ACME provider 和
Cloudflare Origin CA provider 都不在——去掉后者顺带也去掉了它为存储接口拉进来的
certmagic 依赖。

### 我自己不用，所以生产包里就没带

再强调一次：这里说的是**生产 minimal binary 不注册 / 不链接**，不是说上游源码不存在。

```text
Hysteria / Hysteria2 / TUIC

VMess / VLESS / Trojan / Snell

TrustTunnel

TUN / WireGuard / Tailscale / OpenVPN / OpenConnect

Clash API

selector / urltest

HTTP outbound
Shadowsocks outbound
ShadowTLS outbound
AnyTLS outbound

Naive outbound
Cronet / Chromium Naive client stack

DoT / DoH / DoQ / QUIC DNS
hosts transport
systemd-resolved

ACME provider
Cloudflare Origin CA provider

其他当前生产拓扑完全没有引用的 endpoint / service
```

**一个必须说清楚的区分：Native Naive 没有被裁掉。**

留下的是 **Native Naive inbound**，它是我这个 fork 的重点工作之一。裁掉的是
**Naive 客户端 / outbound / Cronet 栈**：

```text
protocol/naive/outbound.go  →  //go:build with_naive_outbound
```

所以 server build 只编译 `inbound.go` / `inbound_conn.go`，`go list -deps ./include`
可以确认 cronet 不在依赖里。

连 `block` outbound 都没注册：route 的 `reject` action 会直接返回 `RejectedError`，
根本不会去解析 outbound。这是读源码确认过的，不是猜的。

### 为什么这么裁剪

我的服务器不是通用代理盒子。它只跑固定的一套入口、出口和 DNS，所以没必要让生产
binary 带着完全不用的协议注册和客户端运行时。

好处主要是这些，都是可预期的工程收益，不是性能承诺：

- 依赖图更小，`go list -deps` 一眼能看完
- 发布物更明确：知道最后上传的到底是什么
- 减少无关初始化和可配置面
- 更容易审计：服务器实际能做什么，就是注册表里那几行
- 维护自己的拓扑轻松一些

**我没有做「内存减少 XX%」「性能提高 XX%」这类承诺**，因为仓库里没有对应的受控
benchmark 数字。裁剪的直接收益是复杂度，不是性能。

---

## MASQUE / HTTP 服务端

### Web masquerade

HTTP inbound 支持 `masquerade`。未通过认证的请求和普通 Web 请求可以交给正常的 Web
backend：

```text
浏览器 / 普通 HTTP 请求  →  正常 Web backend
认证通过的 CONNECT / CONNECT-UDP  →  代理数据面
```

目标是**减少额外暴露的代理特征**，让非代理请求回到普通 Web 行为。这不是「无法探测」，
见后面「关于探测面」那一节的说明。

### `server_profile`

加了服务端资源 profile，当前使用：

```text
jiejie-balanced-1g
```

面向大约 1 GiB 的 VPS。它主要控制 header size、concurrent stream count 和 idle
lifetime 这几类参数。

**它不是严格的内存预算**，是一组偏保守的默认值，只在没有显式配置时生效。

### `max_header_bytes`

HTTP server 可以显式限制 request header 大小，HTTP/2 和 HTTP/3 的服务端路径都有对应
处理和覆盖测试。

### `bbr_profile`

暴露 sing-quic 已有的三个 BBR profile：

```text
conservative
standard
aggressive
```

默认 `standard`。**我不宣称 aggressive 一定更快**——没有做过受控的 BBR/CUBIC 对比
benchmark，选 standard 只是因为它是现有默认值。

### `unauthenticated_limits`

这一组限制专门针对**认证前和认证失败**的公共流量：

```text
max_concurrent_per_ip
requests_per_second
burst
idle_timeout
max_tracked_ips
request body bound
```

认证成功之后，连接**不再继续占用这份 pre-auth budget**。这样正常用户不会被自己的
探测流量饿死。

### 来源地址策略

公共 HTTP / MASQUE 服务端默认以**真实的 transport / socket peer** 作为 source
identity，不会因为客户端自己带了 header 就改变：

```text
X-Forwarded-For
Forwarded
X-Real-IP
```

这些 header 不参与默认的 source 判定。

### HTTP/3 服务端策略

当前服务端策略：

```text
0-RTT 不启用
HTTP/3 header limit
application idle timeout
QUIC / H3 正常关闭的分类处理
真实 H3 CONNECT / CONNECT-UDP 测试
```

关于 MASQUE H3 的并发 stream 上限：**未显式配置时走其现有实现逻辑**。仓库最新审计
已经确认，之前文档里「H3 stream cap = 256」的说法并不准确——
`max_concurrent_streams` 只作用于 HTTP/2。所以 README 不做那个承诺。

---

## AnyTLS

AnyTLS 的核心协议用上游 `sing-anytls`，我在服务端接了几层自用需要的东西。

### native fallback

增加了：

```text
fallback
fallback_for_alpn
```

直接接 `sing-anytls` 已有的 fallback handler。非法流量、非 AnyTLS 客户端可以进入指定
的 Web backend，而不是被当成异常。

### ALPN fallback

支持**按 negotiated ALPN 选择不同的 fallback backend**。

这里的语义以当前仓库里经过测试的行为为准：ALPN 命中映射表时走对应 backend，未命中
时走默认 fallback，且要求在启用 TLS 的前提下才生效。

### 首次应用层读取边界

TLS handshake 完成之后，对**首个 application read** 加了一个 pre-auth timeout，使用
现有的 TCP timeout budget。

目的很朴素：避免客户端完成 TLS 之后什么都不发，长期占着连接资源。它是资源生命周期
约束，不是别的什么。

### 日志分类

区分两类情况：

```text
普通 peer disconnect / timeout            →  不刷 ERROR
服务端 backend / dial / network fault     →  保持可见
```

普通公网探测不该把日志刷满 ERROR；但服务器自己出问题的时候，我仍然要看得到。

---

## ShadowTLS

ShadowTLS 的核心协议仍然基于 upstream，我没有重写它。

我的部分主要是运维和日志层面：

```text
v3 公网探测行为验证
peer lifecycle 错误分类
handshake target dial failure 保持可见
ECONNREFUSED / ENETUNREACH / EHOSTUNREACH 等服务器侧故障
  不作为普通探测噪声处理
```

一句话：更适合我这台公网 VPS 的日志和运维习惯。

---

## Native NaiveProxy：这个 fork 里我折腾最多的部分

Native Naive 是这个仓库里我花时间最多、测试也写得最厚的一块。

### Native server

Native Naive 现在是 sing-box 自己的 inbound，**不需要把 Caddy + forwardproxy 作为实际
生产 Naive server**：

```text
生产：sing-box Native Naive inbound
参照：Caddy + klzgrad/forwardproxy（兼容性 reference）
```

我想把 Naive server 收进同一个 sing-box server binary 里，所以保留
Caddy/forwardproxy 作为**协议行为参照**，而不是生产依赖。它是我的 differential 测试
的对照组，不是我要取代的对象。

### HTTP CONNECT

支持标准 CONNECT target，覆盖 H1 / H2，H3 也有对应代码路径和测试。

当前生产 topology 里，**Native Naive 实际只监听 TCP loopback**（`127.0.0.1:28438`，
在 Nginx Stream 后面）。生产**没有**开放 UDP 的 Native Naive 监听。

### Padding

Padding 是**可选协商**：

```text
request 带 Padding          →  使用 Naive padding framing
request 不带 Padding        →  普通 CONNECT byte stream
response Padding header     →  保持 reference-style 行为
随机 padding 范围           →  0..255
```

frame codec 有单测、fuzz 和 benchmark。

### UoT（UDP over TCP）

实现并测试了：

```text
UDP over TCP v1
UDP over TCP v2
```

它们运行在 **HTTP CONNECT over TCP** 之内，所以：

```text
Native Naive 不需要额外占 UDP/443
```

UDP/443 继续留给 MASQUE HTTP/3。

已有专门测试覆盖：多目标 datagram、STUN、IPv6、UoT v1 / v2。

### Web masquerade

Native Naive 自己也支持 Web masquerade。普通浏览器请求、非 CONNECT 请求、认证失败的
请求都可以进入配置好的 Web backend。

认证失败**不会**打开真实 tunnel。顺带一句维护提醒：**不要根据 HTTP status 判断代理
是否开放**——这条在写测试的时候踩过，见 docs。

### HTTP/2 服务端参数

支持：

```text
max_concurrent_streams
idle_timeout
stream_receive_window
connection_receive_window
```

并对缩窄到固定整数类型的参数做了明确的 range validation，避免解析成功但语义溢出。

### HTTP/3 服务端策略

```text
0-RTT off
MaxIncomingStreams 使用 quic-go bounded default
DisablePathManager 保持当前项目选择
BBR 保持当前项目性能选择
TCP / QUIC ALPN 做了隔离处理
没有 QUIC constructor 时返回明确的能力错误，不走 nil panic
```

**我不宣称完整的 Caddy H3 parity。** 仓库文档已经明确列出 H3 differential 仍有未验证
项（packet-level SETTINGS、connection migration、half-close 矩阵等）。

### CONNECT fast-open / flush

CONNECT 的 `200` response 会**显式 flush** 之后再建立后续 tunnel，flush 的结果也纳入
连接建立流程——flush 失败不会被当成成功。

### H1 buffered bytes

保留 `net/http` 在 CONNECT 之后已经预读到 buffer 里的数据，避免早到的 tunnel payload
被丢掉。这是实现细节，但改 Naive 的时候必须知道，所以写在这里。

### Writer / Padding 数据面

短写处理、padding counter、frame codec、异常 buffer 边界，都有明确的 writer-contract
和 codec 测试。内部函数不在这里展开。

### 目标访问控制

这是我觉得比较有特色的一块：

```text
Naive client 指定的目标先 resolve
再按真实解析 IP 做 route ACL
```

默认限制的地址范围：

```text
loopback
RFC1918
link-local
CGNAT
benchmark / documentation / special ranges
VPS self IP
```

注意措辞：这是**针对我自己的生产拓扑做的 ACL 模板**，不是「sing-box 的通用默认安全
策略」。

### UoT 每包目标 Guard

UoT v1 / v2 的 non-connect 形式里，**每个 datagram 可以携带自己的 destination**。也就
是说 session 建立时检查过的那个 magic address，不代表后面每个包的目标。

所以加了 **packet destination guard**：对每个真实 UDP target 重新执行允许 / 拒绝判定，
而不是只信 session 建立时那一次。

一个重要的维护信息：它**只做 allow / reject，不负责为单个 datagram 重新选择不同的
outbound**。别指望用逐包目标去切换出口。

### 自身 VPS 服务的例外

可以给确实需要的本机服务做**端口级最小例外**，当前 fixture 演示的是：

```text
SELF_IP TCP/2222
```

例外必须同时满足 inbound + network + 自身地址 + 具体端口四个条件；只写端口会把
loopback、私网和 link-local 一起放进来。

### 自建 Web 域名的访问

最新进入 HEAD 的一块改动。

从 Naive 访问我自己的 Web 服务（`*.zhuzhu.jiejie12131.top:443`）时，**不直接重新进入
VPS 的 public self-IP:443**，而是：

```text
route override
  → 127.0.0.1:28439
  → isolated Web-only HTTPS ingress
```

同时，代理入口用的 hostname：

```text
riri.zhuzhu.jiejie12131.top
api.zhuzhu.jiejie12131.top
```

会先被 **exact reject**，防止它们顺着 Web suffix override 被改写进去。

这样做的原因是：直接放行 self-IP:443 会让请求重新进入 Nginx Stream 再回到 Naive，
形成自代理递归；而 CONNECT 的 hostname 和隧道内的 TLS SNI 并不绑定，所以「按域名放行
自身 443」并不可靠。

**这是一套针对我自己域名空间的生产路由，不是 sing-box 的通用默认行为。** 域名本身在
仓库 fixture 里已经是公开的，README 不需要额外暴露真实公网 IP。

---

## 关于探测面：尽量像正常网站，但不追求「不可探测」

这个标题就是我的态度。

我做的目标比较朴素：**不主动暴露不必要的代理特征**，让普通浏览器、错误认证和常见
非代理流量尽量落到正常 Web 行为。但协议本身仍有自己的网络特征，**这不是「不可探测」
方案**，我也不打算把它包装成那样。

涉及的地方：

**HTTP / MASQUE masquerade**

```text
未认证 / 普通 Web 请求  →  normal Web backend
```

**Native Naive masquerade**

同样：非代理流量回到 Web。

**AnyTLS fallback**

```text
非 AnyTLS 客户端 / wrong password  →  fallback Web
```

**ShadowTLS**

保持 v3 原有的 handshake / fallback 模型，并对公共探测产生的正常生命周期日志做区分。

**Nginx ALPN front-door guidance**

仓库里有 `docs/JIEJIE-NGINX-ALPN-HARDENING.md`，讲的是：MASQUE H2 的 SNI 只有在客户端
提供 `h2` ALPN 时才应该进 H2-only backend；`http/1.1` 或没有 ALPN 的走普通 Web
backend。

**这是部署侧的 Nginx 指南，不是仓库自动部署的功能。**

### 来源地址 / Forwarded header

公共 HTTP / MASQUE / Native Naive 的路由元数据默认使用**实际 transport peer**，不会
因为客户端自己携带 `X-Forwarded-For` / `Forwarded` / `X-Real-IP` 就改变 source
identity。

---

## 针对 1 GiB VPS 的资源边界

当前做的事情：

```text
server_profile
header size bound
stream bound
idle timeout
unauthenticated per-IP limiter
tracked-IP cap
request body bound
AnyTLS pre-auth read timeout
Native Naive UoT lifecycle / resource 测试
```

需要说清楚：这些是 **admission / lifecycle bounds**，不是严格的「最大内存 XX MB」
保证。它们控制的是「最多同时进来多少、多久不用就回收」，不是精确的内存计量。

---

## 我的生产拓扑

以 `release/jiejie-production-topology.json` 为准：

```text
                 TCP/443
                    │
              Nginx Stream
          ┌─────────┼──────────┐
          │         │          │
       AnyTLS    MASQUE H2   ShadowTLS
       28436       28440       8554
          │                      │
      fallback                 SS2022
          │                    17414
          │                      │
          └────────┬─────────────┘
                   │
              direct / SOCKS5


UDP/443
   │
MASQUE H3


Native Naive
Nginx Stream
   │
127.0.0.1:28438
   │
CONNECT / UoT / masquerade
```

本机其他端口：

```text
127.0.0.1:28437  →  normal Web backend
127.0.0.1:28439  →  self-hosted Web-only HTTPS ingress
127.0.0.1:53     →  AdGuard Home
```

（fixture 里的示例密码不在 README 里展开。）

### Nginx 的角色

这个 fork **没有试图替代整个 TCP/443 front door**。

当前生产设计：

```text
Nginx Stream 继续拥有 TCP/443 和 SNI routing
sing-box 处理 loopback 上的 proxy backends
sing-box MASQUE H3 直接使用 UDP/443
```

这也是为什么**没有把 Native SNI dispatcher 做进 sing-box**——Nginx 已经在做这件事，
而且做得比我塞进 Go 里更好维护。

---

## 我给这个玩具加了不少测试

测试写得有点多，主要是怕以后自己改着改着忘了当初为什么这么做。

当前两套主要 workflow：

```text
Jiejie Fast          （.github/workflows/jiejie-fast.yml）
Linux amd64 server   （.github/workflows/server-linux-amd64.yml）
```

两者都是 **server-only**，不构建客户端产物。检查内容包括：

```text
gofmt
golangci-lint
go vet
unit tests
race tests
production-tag tests
minimal registry audit
production fixture sing-box check
real binary process tests
dependency pruning
```

### Native Naive 的测试重点

```text
官方 NaiveProxy client 兼容性
Caddy + klzgrad/forwardproxy reference differential
H1 raw byte comparison
real HTTP/2 differential
real HTTP/3 client tests
Padding codec
Padding fuzz
CONNECT authority fuzz
UoT v1 / v2
STUN
IPv6
loss / fault injection
concurrency
resource churn
masquerade
目标 ACL
self-hosted Web route
ALPN
0-RTT policy
```

**不说「100% parity」。** 当前仍有未完全验证的部分：H3 的 Caddy differential、部分
half-close 行为、部分 packet-level 行为。这些在 docs 里都标着 NOT-TESTED，README 不
写得比 docs 更强。

---

## 构建产物

当前只发布一个自用方向的生产产品：

```text
Jiejie-VPS-linux-amd64-<version>-<sha>
```

构建用：

```text
Go linker
-trimpath
-s -w
```

不使用：

```text
UPX
external strip
objcopy
packer
```

理由很简单：构建过程简单、可复现，而且我随时知道最后上传的是什么。

---

## 文档导航

主页只负责讲清楚「我改过哪些大块」，细节都在 docs：

| 想看什么 | 看哪个文档 |
| --- | --- |
| fork 与上游的差异总览、同步策略 | `docs/FORK-DIFF.md` |
| 服务端整体设计与部署 | `docs/JIEJIE-SERVER.md` |
| Web masquerade | `docs/FORK-MASQUERADE.md` |
| AnyTLS fallback | `docs/FORK-ANYTLS-FALLBACK.md` |
| Native Naive 使用与设计 | `docs/JIEJIE-NAIVE-SERVER.md` |
| Native Naive 目标 ACL | `docs/JIEJIE-NAIVE-TARGET-ACL.md` |
| Naive HTTP/3 / QUIC 审计 | `docs/JIEJIE-NAIVE-H3-AUDIT.md` |
| 迁移与回滚手册 | `docs/JIEJIE-NAIVE-MIGRATION.md` |
| 探测面边界 | `docs/JIEJIE-PROBE-RESISTANCE-MATRIX.md` |
| 生产 binary 到底提供什么 | `docs/JIEJIE-PRODUCTION-PROTOCOL-MATRIX.md` |
| 自定义配置字段是否真的生效 | `docs/JIEJIE-FIELD-MATRIX.md` |
| Nginx ALPN 加固 | `docs/JIEJIE-NGINX-ALPN-HARDENING.md` |
| 性能测量 | `docs/JIEJIE-BENCHMARK.md` |

如果只读一篇，建议先读 `docs/JIEJIE-PRODUCTION-PROTOCOL-MATRIX.md`——它会把「哪些
验证过、哪些没验证」讲得最直白。

---

## Upstream sync

这个 fork 长期基于 upstream `testing` 同步。

设计目标是**尽量让 fork-specific 的改动集中、可测试**，方便以后继续同步
SagerNet/sing-box：协议实现尽量不动上游文件，需要扩展的地方优先走新增文件、option
解析、注册表和 build tag，而不是散落各处去改核心代码。

同步策略和冲突处理见 `docs/FORK-DIFF.md`。

---

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```

**Jiejie Server Edition 是个人 fork**，与 SagerNet 官方没有关联，也不代表官方发行版。
