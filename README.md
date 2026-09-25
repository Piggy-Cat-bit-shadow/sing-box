# Jiejie Server Edition

基于 [SagerNet/sing-box](https://github.com/SagerNet/sing-box) 的个人服务端 fork。

- 上游分支：`testing`
- 产品范围：Linux amd64 服务端
- 生产 profile：`jiejie_server_minimal`
- 详细设计文档：[`docs/`](docs/)

## Upstream

| 项目 | 值 |
| --- | --- |
| 上游仓库 | https://github.com/SagerNet/sing-box |
| 跟踪分支 | `testing` |
| fork 基线 | `b609f959f5` |
| fork 版本 | `1.15.0-jiejie-masquerade.5` |

本仓库跟踪上游 `testing` 分支，并维护一组服务端改动。协议实现、路由、DNS、TLS
和传输层均来自上游；本仓库增加的是部署相关的服务端行为、注册表裁剪与验证。

## 构建范围（Build Scope）

面向 Linux amd64 的服务端最小化构建。裁剪发生在**注册层面**：minimal registry
不 import 未使用的包，链接器随之丢弃。上游完整构建仍然可用，位于
`include/registry.go`（`!jiejie_server_minimal`）。

生产构建标签：

```text
with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0
```

**保留的 inbound**

```text
HTTP       (MASQUE HTTP/2 与 HTTP/3)
AnyTLS
Native Naive
ShadowTLS
Shadowsocks 2022
```

**保留的 outbound**

```text
direct
SOCKS5
```

**保留的 DNS transport**

```text
udp
local   （box.go 的 DNS transport fallback 在启动时必需）
```

**minimal 生产构建不包含的功能**

| 类别 | 不包含 |
| --- | --- |
| QUIC 代理协议 | Hysteria、Hysteria2、TUIC |
| 代理协议 | VMess、VLESS、Trojan、Snell |
| 客户端运行时 | Naive outbound、Cronet / Chromium 客户端栈 |
| 网络端点 | TUN、WireGuard、Tailscale、OpenVPN、OpenConnect |
| Outbound | HTTP、Shadowsocks、ShadowTLS、AnyTLS、selector、urltest |
| DNS | DoT、DoH、DoQ、hosts、resolved |
| Service | Clash API 及未使用的 service |
| 证书 provider | 未使用的证书 provider |

注意：Native Naive 的 **inbound 保留**，被排除的只是 Naive outbound 与客户端运行时。

## Change Log

### Native Naive

- `45f6686a61` — 加入 Native Naive inbound：认证 CONNECT、可选 Padding 协商、
  Web masquerade。
- `77607290f5` — 暴露 HTTP/2 服务端资源参数（`max_concurrent_streams`、
  `idle_timeout`、收发窗口）。
- `ec1e7ab294` — 将 Native Naive inbound 注册进生产注册表。
- `bbcabc9a2e` — 加入 UoT v1/v2 数据路径及端到端覆盖。
- `c3de03ad48` — UoT 会话结束后释放其占用的资源。
- `568e93f140` — 覆盖 Web masquerade 的非代理请求路径。
- `58985a3759` — 与官方 NaiveProxy 客户端做兼容性验证。
- `c0ba174912` — Linux socket 层验收覆盖；收敛一个 UDP 丢包发现。
- `ce0496a311` — 针对生产 minimal registry 构建的最终验收。
- `d0087e877e` — 独立覆盖 UoT 的各条异常路径。
- `4085c086dc` — HTTP/2 并发、Padding 边界与目标控制审计。
- `23af897bfd` — 不再接受非标准的 `-connect-authority` header。
- `b24e294300` — TLS/ALPN、listener 矩阵与异常生命周期审计。
- `6fd7135235` — v1/v2 往返之外的 UoT 数据面审计。
- `41bd528cb2` — 审计 masquerade 后端实际收到的内容。
- `fb90272a50` — Padding 写路径按标准 `io.Writer` 短写契约处理。
- `eace39c3e6` — 确定性的 Padding codec benchmark。
- `0c83345a3f` — 逐 stream 的认证隔离与 authority 处理。
- `593f634a1a` — CONNECT 保留 `net/http` 已经预读的 tunnel payload。
- `3bbf179078` — UoT 路径插桩；定位到丢包与 hijack 交互的关联。
- `10e1f2a957` — 加入确定性丢包回归测试与真实的 retry 测试。
- `d1f3798a63` — churn 验收标准收紧到 2000 sessions。
- `d4ead1498a` — UoT 会话按逐 datagram 目标执行 ACL；附带 Naive ACL 配置模板。
- `2ec06e451f` — UoT 回归测试在 CI 中实际执行，不再跳过。
- `1dc734f754` — 以故障注入替代 UoT skip；补充 STUN 与 IPv6。
- `d2af551c40` — tunnel 生命周期与 Linux 资源占用覆盖。
- `3c6e0aad37` — 约束 Padding 取值范围，超大值不再导致连接终止。
- `fe57895393` — 恢复完整 Padding 范围，修正 buffer 回归测试。
- `e9d3293806` — CONNECT Padding 协商与 reference 对齐。
- `f2907e79a5` — HTTP CONNECT 边界情况与 reference 对齐。
- `cc9df81f07` — 建立 Caddy / forwardproxy 差分兼容性 harness。
- `83efc0bf00` — 对照 Caddy 的 HTTP/3 审计；固定 Cronet 客户端版本。
- `b32bb58f91` — HTTP/1 tunnel framing 与 reference 对齐。
- `1d66e934f3` — 来源身份默认使用 transport peer。
- `7be29e4ba9` — HTTP/2 option 边界在解码期校验。
- `dccf70987e` — HTTP/3 构造函数缺失时返回规范的能力错误。
- `c630c9775c` — TCP 与 QUIC 的 TLS ALPN 列表相互隔离。
- `9c6052b050` — Native Naive HTTP/3 服务端采用关闭 0-RTT 的策略。
- `34628b6daf` — 覆盖各种 Forwarded header 形态，防止来源伪造。
- `ade5f465c6` — 使用规范的 QUIC 缺失错误；扩大边界覆盖。
- `ece998f21f` — 以字节比对确定 HTTP/1 tunnel framing；去除一个误报的差异。
- `1be7647977` — 在运行时验证 TCP/QUIC ALPN 隔离。
- `9885c45cf6` — 针对 reference 的真实 HTTP/2 差分探针。
- `d480202829` — 测量 H3 stream 上限；标注剩余的 H3 差异。
- `0245deff82` — CONNECT response flush 纳入连接建立流程检查。
- `d921493382` — HTTP/3 incoming stream 数恢复为 quic-go bounded default
  （`MaxIncomingStreams` 不再显式设置）。
- `086aba2a45` — Padding codec 与 CONNECT authority 模糊测试。
- `318dbee27d` — 差分结论与产物表达改为无歧义。

### HTTP / MASQUE

- `d53c867b7d` — inbound masquerade handler：非代理请求落到 Web 后端。
- `f7e51ef60e` — 服务端资源 profile 与 header 限制选项。
- `9771af9f49` — `server_profile` 与 `max_header_bytes` 在运行中的 server 上生效。
- `38491df890` — 未认证资源限制（每 IP 并发、速率、burst、tracked-IP 上限）。
- `7e57fe8c77` — 超限请求不再到达 masquerade 后端。
- `1276eb85a2` — 固定 H3 到 H2 路径上的重放安全不变式。
- `747c62d263` — request body 上限在数据路径上强制执行。
- `cce49f3877` — limiter 过期行为改为实测，不再依赖假设。
- `80ad6df293` — 零错误码的 H3 关闭在连接边界归一化。
- `27cd75af45` — HTTP/3 application idle timeout 强制执行。
- `cd8d702122` — HTTP/3 上强制 request header 限制。
- `0eccef3c40` — 认证先于缺失 handler 的响应。
- `127ae9c3b9` — 未认证名额释放按每次获取幂等。
- `a3cb8abf58` — HTTP/MASQUE 来源身份默认使用 transport peer；
  `X-Forwarded-For` / `Forwarded` / `X-Real-IP` 不再决定来源。
- `2fb3ba6930` — 服务端资源选项边界校验。

### AnyTLS

- `e97ea9ce82` — inbound fallback 后端。
- `3570205356` — fallback 经由配置的后端转发。
- `b1814cd660` — `fallback_for_alpn` 在运行时按协商出的 ALPN 路由。
- `f30f63e0d6` — 以现有 TCP 超时预算约束 TLS 完成后的首个 application read。
- `5ef800316b` — 以实测固定 ALPN 行为。
- `7a5212d8b7` — 修正 ALPN fallback 语义（命中映射、默认 fallback、需启用 TLS）。
- `93fa2708cb` — 认证前探测失败按错误类型分类。
- `1804358ab2` — 服务端故障在日志分类中保持可见，常规 peer 生命周期事件不记为错误。

### ShadowTLS / SS2022

- `20ce0a05ad` — 固定 ShadowTLS v3 探测 fallback 行为。
- `1804358ab2` — peer 生命周期与服务端故障分类分离（同样适用于 AnyTLS）。
- `ec1e7ab294` — Shadowsocks 2022 注册为生产 detour 目标。

### Routing / ACL

- `d4ead1498a` — UoT 非 connect 会话按逐 datagram 目标执行 ACL。
  该 guard 只做 allow/reject，不为单个 datagram 重新选择 outbound。
- `7029722bff` — 为本机管理服务增加受限的 self-target 端口例外，
  不放宽通用目标 ACL。
- `f45e465b83` — 自建 HTTPS 目标改写到一个隔离的 loopback Web ingress，
  避免重新进入公网代理 front door。代理 ingress hostname 在后缀改写之前先被拒绝。
- `189bc6d0ed` — 记录 loopback Web ingress 及其改写顺序。

### Minimal Build / Registry

- `bb5b56a460` — 加入 Jiejie server 构建 profile。
- `98d8ef0cb3` — 注册表层面的 `jiejie_server_minimal` 服务端构建。
- `d8a3c8c222` — fixture 反映真实生产的 inbound detour。
- `9d63f155f2` — 从 minimal 注册表移除仅供测试使用的协议注册。
- `918c1521d8` — minimal 构建的生产运行时集成覆盖。
- `61c05bb63d` — CI 只测试并发布 minimal 生产构建。
- `5ce3c4d675` — 收敛为 VPS-only 服务端产品；移除 iOS / 客户端产品线。
- `0b27085f6a` — 对照生产拓扑审计注册表。

### CI / Validation

- `b21371720a` — version、build-info、构建与打包脚本。
- `d71841fc6e` — Fast workflow：并发控制、缓存与构建 gate。
- `61c05bb63d` — 生产构建选择收敛到 minimal 产物。
- `b49c78ca56` — CI gate 与 Naive 服务端进入生产的状态对齐。
- `142df6d2db` — race detector 覆盖 `./route`。
- `75a32bcd7f` — Naive 差分测试针对固定版本的 reference 运行。
- `4ed6dff200` — Naive HTTP/3 集成测试实际执行，不再跳过。
- `9cce35ec3b` — HTTP/2 差分测试实际在 CI 中运行。
- `a4f22a5949` — 上游 `testing` 同步 merge。

### Documentation / Audit

- `5c620c33a4` — 最初的 Jiejie Server Edition 文档。
- `7c0267f2cc` — Native Naive server、UoT 与 masquerade。
- `8764f6ec61` — VPS 探测面边界。
- `427defcbf7` — 生产协议能力矩阵。
- `5c5440577d` — 审计结论与实测覆盖对齐：删除过期的 H3 结论，将过宽的 PASS
  标签下调为 PARTIAL / NOT-TESTED，并汇总所有未验证项。

## Removed / Superseded Work

列出这些是为了避免以后维护时把旧 commit 误读为当前能力。

- 早期的 iOS / Libbox / IPA 构建实验已由 `5ce3c4d675` 移除，
  该 commit 将 fork 收敛为 VPS-only 服务端产品。
- 早期的 Linux client-full 与 Windows 客户端构建 profile 也在同一次收敛中移除。
- 早期的 HTTP/3 客户端连接池与 fallback/backoff 工作不属于当前服务端范围；
  `http3_connection_pool` 与 `http3_fallback` 已不存在于 option / transport 包中。
- 本历史中的 HTTP/3 客户端相关工作面向的是当前产品已不再发布的客户端。

仍然保留的 HTTP/3 工作仅限于服务端 listener 及其请求处理。

## Maintenance Notes

- **上游同步** —— 从上游 `testing` rebase/merge；fork 改动尽量集中在新增文件、
  option 解析、注册表与 build tag，以缩小冲突面。见
  [`docs/FORK-DIFF.md`](docs/FORK-DIFF.md)。
- **生产标签** —— 从 `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` 读取；
  脚本与 workflow 读同一个文件，避免漂移。
- **注册表改动** —— `include/registry_jiejie_server.go` 中的每一项注册都必须由生产
  拓扑 fixture 支撑；注册表审计测试会在漂移时报错。
- **已知未验证项** —— HTTP/3 Caddy 差分、部分 half-close 矩阵、packet-level H3
  SETTINGS、连接迁移行为，以及受控的 BBR/CUBIC benchmark。这些在文档中标记为
  NOT-TESTED，不应视为已验证。
- **详细文档** —— 架构与审计位于 [`docs/`](docs/)；
  `docs/JIEJIE-PRODUCTION-PROTOCOL-MATRIX.md` 按组件说明验证状态。

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
