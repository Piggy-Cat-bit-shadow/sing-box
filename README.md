# sing-box

**平台：** macOS arm64 · Linux amd64

同一份 `testing` 源码树构建两个产品，靠 build tags 与 registry 区分能力，不复制协议实现。

## [Fork 差异](docs/FORK-DIFF.md)

当前相对 upstream 仍然存在的差异：MASQUE、AnyTLS fallback、Native Naive、HTTP 资源控制、两端 registry、生产拓扑契约与定制依赖。

## [构建配置](docs/BUILD-PROFILES.md)

一个源码树如何产出两种产品：平台、CGO、build tags、registry、workflow 与能力边界。

## [服务端](docs/JIEJIE-SERVER.md)

Linux amd64 Server Minimal 的产品能力与生产部署契约：TCP/443 前门、UDP/443 H3、loopback 后端、AnyTLS fallback、masquerade 与 residential 链路。

## [macOS 客户端](docs/JIEJIE-MACOS-CLIENT.md)

macOS arm64 客户端包含什么、不包含什么，以及无头运行、Native API 与验证方式。

## [MASQUE](docs/masque.md)

当前 MASQUE 实现：L4 CONNECT / CONNECT-UDP 与 CONNECT-IP endpoint 两条不同的能力路径，H3 生命周期与错误分类，DATAGRAM 所有权，DNS_ASSIGN 与 PREF64。

## [Native Naive](docs/naive.md)

当前 Native Naive 实现：服务端 inbound 与 macOS Cronet outbound、UoT、padding、masquerade、资源控制，以及目标访问控制边界。

## [工程笔记](docs/ENGINEERING-NOTES.md)

记录当前仍有效的架构决策、正确性不变式、性能取舍与尚未闭环的验证边界。

---

配置字段见 `docs/configuration/`；生产拓扑机器可读契约见 `release/jiejie-production-topology.json`。
