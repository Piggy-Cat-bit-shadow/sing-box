# Engineering Notes

本文件只记录当前仍有维护价值的工程结论，不是 changelog，也不是历史审计归档。若描述与当前源码、测试、构建标签、[生产拓扑夹具](../release/jiejie-production-topology.json)或 CI 冲突，以这些当前实现为准；决策过程和旧测量可从 Git history 查询。

## MASQUE

### 架构边界

| 目录 | 职责 |
| --- | --- |
| [`protocol/masque`](../protocol/masque) | endpoint 集成、选项、目标解析、DNS_ASSIGN 策略与状态、PREF64 状态、bootstrap 策略、路由和能力编译。 |
| [`transport/masque`](../transport/masque) | CONNECT-IP 会话、控制 capsule、ADDRESS_ASSIGN、ROUTE_ADVERTISEMENT、IP 包收发、H3 DATAGRAM 与 capsule fallback、包所有权、MTU/PTB 和会话生命周期。 |
| [`transport/http`](../transport/http) | HTTP/1.1、HTTP/2、HTTP/3、CONNECT、QUIC/TLS 建连、拥塞控制、H3 ClientConn 与请求流生命周期。 |

MASQUE 层不另写 QUIC、TLS、拥塞控制或通用 H3 生命周期。DNS_ASSIGN 使用现有 DNS transport，不引入第二套 DNS 引擎；PREF64 当前只维护状态，不等于实现 DNS64。不要为局部微优化打破这些边界。

当前实现、协议语义与证据范围见 [MASQUE](masque.md)；本文件只记录不应被轻易推翻的判断依据。

### 正确性契约与证据范围

- HTTP/3 CONNECT 收到 `200` 后，隧道仍须双向传输；只断言状态码不足以证明生命周期正确。见 [`client_h3_connect_lifecycle_test.go`](../transport/http/client_h3_connect_lifecycle_test.go)。同一 H3 连接复用隧道与 DoH 时，也必须保持隧道可用，见 [`client_h3_same_conn_test.go`](../transport/http/client_h3_same_conn_test.go)。
- CONNECT-IP 必须正确处理地址分配、路由通告和 IP 包收发。H3 DATAGRAM 可用时使用 DATAGRAM；对端不支持时须能走 capsule fallback。IPv6 地址分配和 capsule fallback 的真实端点测试见 [`connect_ip_ipv6_test.go`](../test/jiejie/reference/connect_ip_ipv6_test.go)。
- Packet Too Big 必须回到所属会话，不能广播给其他会话。真实 quic-go `DatagramTooLarge` 触发的 **IPv4 live H3 PTB** 已测试；ICMPv6 PTB 报文形状也有测试。两者都不能代替 **live IPv6 H3 PTB** 的验证。见 [`connect_ip_ptb_live_test.go`](../test/jiejie/reference/connect_ip_ptb_live_test.go) 和 [`packet_too_big_test.go`](../transport/masque/packet_too_big_test.go)。
- 非零 DATAGRAM context ID 已在真实 H3 CONNECT-UDP / CONNECT-IP 隧道中覆盖：不支持的 ID 应被丢弃，后续 context 0 流量仍可在同一隧道中往返。它不再是“未测试”项。见 [`context_id_test.go`](../test/jiejie/reference/context_id_test.go)。
- 当前保留的 QUICHE 检查是 [`quiche_oracle_test.go`](../test/jiejie/reference/quiche_oracle_test.go) 的协议向量/决策表检查。历史 live QUICHE tunnel harness 已删除；向量一致不等于真实互通，也不能声称当前 CI 正在测试 QUICHE live MASQUE tunnel。独立 Go reference module 的隧道测试在 Linux 手动 deep checks 中运行，见 [workflow](../.github/workflows/server-linux-amd64.yml)。

### 已确认缺陷与长期不变式

两项已修复的缺陷都源于同一个结构性错误：**通用的 closed/canceled 判断被放在了 typed QUIC / HTTP3 语义分类之前**。每一种 quic-go error 类型都实现 `Unwrap() -> net.ErrClosed`，与严重程度无关，因此先做通用判断会把协议违规与正常关闭混为一谈。

- **H3 request cancellation（268 / `0x10c` = `H3_REQUEST_CANCELLED`）** 是 stream-local 的预期取消。此前 classifier 只特判 code 0，268 因而落到 unexpected fault，被记为 ERROR。现在按 typed H3 classification 处理，归为预期关闭（TRACE），并且不得影响 shared H3 connection 或其他 multiplexed stream。
- **`quic.TransportError.Unwrap()` 可返回 `net.ErrClosed`**。因此若 `errors.Is(err, net.ErrClosed)` 先于 typed 分类执行，真实的 `PROTOCOL_VIOLATION` 会被静默当成普通关闭而消失。

长期不变式：**typed QUIC / HTTP3 semantic classification 必须优先于 generic closed/canceled classification。**真实的 protocol / transport fault 必须保持 visible。`ApplicationError`、`StatelessResetError`、`VersionNegotiationError` 等类型同样适用；完整分类表见 [MASQUE](masque.md)。

### 已调查但确认非缺陷

- **IdleTimeout**：`IdleTimeoutError` 本来就是预期关闭，其 `Unwrap()` 返回 `net.ErrClosed`，因此 "no recent network activity" 原本已被正确抑制。不需要为它改 classifier。
- **Connection cache**：liveness predicate、stale eviction、replacement isolation 均正常；late failure 不会清除 replacement；stream cancellation 保持 stream-local；reconnect 有严格 coalescing（单 client、单 generation 下恰好一次 replacement dial）。经证据检查：**NO PRODUCT BUG FOUND IN CONNECTION CACHE.** 生产 cache 未因该次事件修改。

以下属于 **evidence gaps，不是已确认缺陷**：~1.84s -> ~30s 的 timeout 机制；NAT rebinding / path migration 的完整生命周期；bootstrap winner 随后 idle 的极窄 race；OpenStream failure 后是否值得增加 connection-level retry。当前没有因为上述任何一项调高 timeout、增加 speculative retry 或重写 connection cache。

### 数据路径与所有权

出站 owned DATAGRAM 路径利用 headroom 原位写入 HTTP/3 Quarter Stream ID，再把缓冲区所有权移交给 QUIC 队列；在 packetization/AEAD 前，原有两次完整 payload copy 降为零。普通复制版 `SendDatagram` 保持原有语义。owned API 的契约是：成功后由接收方恰好释放一次；失败和过大报文时调用方仍持有原缓冲区；关闭时排空队列。见 [`owned_datagram.go`](../transport/http/owned_datagram.go) 和 [`owned_datagram_ownership_test.go`](../transport/masque/owned_datagram_ownership_test.go)。

历史 1280 B 局部基准中，owned 路径约为复制路径的 **2.7 倍**。这是指定机器和夹具上的 dataplane microbenchmark，不能外推为 WAN 吞吐、VPS 稳态内存或丢包场景收益。

入站仍需尊重 quic-go 接收缓冲区、异步 TUN 交接和 buffer lifetime。为去掉最后一次接收侧拷贝而引入跨层引用计数或共享可变暂存区，会增加释放和竞态风险；目前没有 profile 证据支持。**REJECT：**除非所有权契约重设计，且新的 profile 显示这里成为实际瓶颈，否则不追求完全 receive zero-copy。

### 已测量的取舍

| 决定 | 原因 |
| --- | --- |
| KEEP：DATAGRAM 热路径减少逐包分配、预编译路由匹配、批量入队/发送、不可变状态快照、所有权移交 | 它们降低实测开销，且不把 QUIC 内部实现搬到 MASQUE 层。 |
| REJECT：根据一次过大报文持续下调 learned datagram ceiling | 底层有效上限可能随后上升；单向下调会把可恢复路径变成永久拒绝。 |
| REJECT：每会话共享 scratch slice 以省一次入站分配 | DATAGRAM 与 capsule 接收路径可能并发进入同一处理函数，共享可变切片会形成竞态。 |
| NO CHANGE：为几纳秒重写 IP 地址解析或无 profile 依据地缓存 DNS transport | 复杂度、生命周期和跨层耦合没有相应实测收益。 |
| NO CHANGE：在 MASQUE 层重复 quic-go 的 QUIC/batching 逻辑 | 传输层已经负责该语义；复制实现会扩大维护面。 |
| NO CHANGE：给 Linux UDP GSO 分组加固定最小包长 | 现有 Linux loopback/syscall 测量中，小包分组仍有收益；无法分组时已有普通 `sendmmsg` 路径。该结论不是 WAN 速率保证。 |

## Naive

### 两套 codec 与 framing

Native Naive **inbound** codec 在 [`protocol/naive`](../protocol/naive)，macOS 客户端 **outbound** codec 在 fork 的 `cronet-go`。服务器 codec 测试通过不能证明客户端正确；两个自定义实现互通也不能代替与 reference 对照。跨仓库共享的机器可读向量位于 [`test/jiejie/reference/naive_padding_vectors.json`](../test/jiejie/reference/naive_padding_vectors.json)。

padding 必须先抽取，再计算本帧 payload 预算：

```text
padding first
payload_budget = 65536 - 3 - padding
3 + payload + padding <= 65536
writerMTU = 65278, front headroom = 3, rear headroom = 255
```

短写返回 `io.ErrShortWrite`，不能静默截断；只有整帧写成功才推进 padding frame counter。数据路径错误应返回错误，不用 panic 处理正常失败。当前入站实现和写入契约测试分别见 [`inbound_conn.go`](../protocol/naive/inbound_conn.go) 与 [`audit_write_contract_test.go`](../protocol/naive/audit_write_contract_test.go)。HTTP/1 CONNECT 的 payload 是原始字节，即使带 Padding 请求头也不加帧；HTTP/2、HTTP/3 才按协商情况加帧。先前所谓 UoT v2 non-connect 产品 P0 是测试夹具错误，相关传输矩阵现由 [`jiejie_naive_uot_transport_matrix_test.go`](../test/jiejie/jiejie_naive_uot_transport_matrix_test.go) 固定。

### Cronet 异步缓冲区

Cronet read/write 由异步 native callback 完成。Go 缓冲区在回调结束前必须保持 pinned、有效且有明确所有者；success、error、timeout、cancel、close 均需释放正确。缓存首包在几何条件满足时可直接移交，减少明文拷贝；不满足时必须安全回退，不能为省一次 allocation 引入 callback-after-free。

历史缓存首包局部基准约为：64 B `470 → 214 ns`，1400 B `482 → 216 ns`，16 KiB `796 → 215 ns`，`1 → 0 alloc`。它们仅说明对应大小和夹具的 fast path，不代表 64 KiB 等超过阈值的情形，也不是远端吞吐结论。当前实现与安全契约见 [Native Naive](naive.md)。

### QUIC/HTTP3 默认值

Naive H3 服务器不主动启用 0-RTT；未覆盖的 stream limit 和 path manager 行为遵循底层库，除非显式配置。当前设置见 [`inbound_init.go`](../protocol/naive/quic/inbound_init.go)。客户端提供默认、BBR、BBR2、CUBIC、Reno 等拥塞控制选择；可选项不等于统一最优值。Cronet 单/多 engine、receive window、拥塞控制和迁移策略都需要受控的真实网络 A/B，才可据此改默认。现有实验脚本分别为 [`bench-naive-cronet-engine.sh`](../scripts/ci/bench-naive-cronet-engine.sh) 与 [`bench-naive-receive-window.sh`](../scripts/ci/bench-naive-receive-window.sh)。

## 探测、伪装与部署边界

未认证或错误认证连接应避免直接暴露明显的代理认证响应，并在部署支持时进入合理的 masquerade/fallback。**不声称消除协议指纹**：QUIC、HTTP/3 SETTINGS、H3_DATAGRAM 与 Extended CONNECT 等仍可被观察。

Nginx Stream 的 TCP/443 前门、SNI、ALPN 和 HTTP/1.1/no-ALPN 分流属于部署层；sing-box core 不能替代这层配置。UDP/443 的 H3 入口又是另一条路径。现行部署约束见 [`JIEJIE-SERVER.md`](JIEJIE-SERVER.md) 与[生产拓扑夹具](../release/jiejie-production-topology.json)。不要把仓库内测试说成真实 VPS 前门已经按文档部署。

## 上游同步与定制依赖

当前根模块与独立 `test` 模块的 `go.mod` 均将 `github.com/sagernet/sing`、`cronet-go`、`quic-go` 替换为本仓库使用的 fork；reference isolation module 保持独立依赖图。这些 replace 承载现有产品行为，同步 upstream 时不能仅凭上游版本较新就删掉 replace、覆盖补丁，或让 root/test 的完整 replacement target 漂移。检查范围包括两个模块的 `go.mod`/`go.sum`、完整 fork path 与版本，以及 [`check-go-module-integrity.sh`](../scripts/ci/check-go-module-integrity.sh) 的动态模块发现和 parity 检查。

## 维护原则

先确立正确性与回归测试，再用 benchmark/profile 找瓶颈，最后决定优化。实验结论写清 **KEEP、REJECT、NO CHANGE** 及原因；“理论上应更快”不足以改变默认值。所有权与可证明的生命周期优先于名义上的 zero-copy。局部 `ns/op`、`allocs/op` 改善不等于 WAN 吞吐、VPS 长期内存、高 RTT 或丢包性能。

## 当前未闭环的验证边界

- live IPv6 H3 Packet Too Big；现有 ICMPv6 形状测试与 IPv4 live H3 PTB 均不能代替它。
- Google QUICHE live MASQUE tunnel 互通；当前只有协议向量检查，live harness 已删除。
- 真实 WAN 的 PMTU、分片黑洞、移动网络切换与 CGNAT 行为；本地/CI 隧道测试不证明这些部署结果。
- 长时间 VPS 资源稳定性和生产并发上限；局部资源测试与默认流限制不构成真实部署容量结论。
- Cronet 单/多 engine A/B、receive-window 系统扫描，以及 BBR/BBR2/CUBIC/Reno 在受控 RTT、随机丢包和突发丢包下的比较。
- 生产 VPS 自身公网地址是否已纳入目标 ACL，需要部署环境中的真实地址与规则验证；仓库拓扑夹具不能证明现场状态。见 [Native Naive](naive.md) 的 Target ACL 章节。

这些条目描述当前仓库证据的边界，不预断真实部署一定存在缺陷；有可靠测试或现场记录后应更新本节。
