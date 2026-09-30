# sing-box

**平台：** macOS arm64 · Linux amd64

## [Pruning](docs/pruning.md)

**保留：** Direct、Group、HTTP / MASQUE、Shadowsocks、ShadowTLS、VLESS、AnyTLS、Naive、MASQUE Client。  
**移除：** VMess、Trojan、Snell、Hysteria2、TUIC、WireGuard、Tailscale、OpenVPN、OpenConnect、SSH、Tor。

## [MASQUE](docs/masque.md)

优化 HTTP/3 DATAGRAM 的发送路径与队列，减少报文拷贝和逐包分配。

出站改为转移缓冲区所有权并批量入队；补充失败回滚、关闭和异步使用场景的测试。

## [Naive](docs/naive.md)

优化缓存首包向 Cronet 的缓冲区移交与封装路径，减少明文拷贝。

修正异步读写的缓冲区生命周期，覆盖超时、取消、关闭及回调结束；核对 Cronet 的 DNS 解析与套接字移交路径。

## [SOCKS5 出站](docs/socks5-outbound.md)

TCP 预连接：默认关闭。预先建连并完成 SOCKS5 握手和认证；请求到来后只需发送 CONNECT，池为空时直接建立新连接。

复制缓冲区调优：默认关闭。链式转发可更早扩容，并按上传、下载各自的写入端分别判断，避免另一方向无谓扩容。

## [Shadowsocks](docs/shadowsocks.md)

分别检查首包、持续传输及上下行的缓冲区使用。

通过合适的缓冲区尺寸和原位 AEAD 加密，减少封装时的拷贝与分配；明确首次写入、持续传输和预留空间不足时的拷贝条件。

## [DNS](docs/dns.md)

明确不同协议中目标域名、代理端点及隧道内域名分别由谁解析。

修正 SOCKS4 目标解析等策略混用问题，减少缓存命中、查询处理和日志记录中的额外开销。

## [Other](docs/other.md)

收录跨协议修复、公共缓冲区与所有权改动，以及测试、基准测量、构建、CI 和发布维护。
