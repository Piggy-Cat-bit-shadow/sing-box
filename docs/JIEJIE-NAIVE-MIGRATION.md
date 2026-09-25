# Native Naive 迁移与回滚手册（准备稿，未执行）

本文准备把生产 Naive 服务端从 **Caddy** 切换为 **sing-box Native Naive**，
并准备回滚步骤。

> **状态：本文中的任何命令都尚未在生产 VPS 上执行。**
> 迁移动作需要人工确认后手动执行。本文不是"已经完成"的记录。

---

## 0. 生产拓扑（切换前后不变的部分）

```
TCP/443   Nginx Stream 持有，按 SNI 分发
            ├─ riri.zhuzhu...    -> 127.0.0.1:28438  (本次新增: Native Naive)
            │                       切换前指向 Caddy 的 Naive 后端
            ├─ api.zhuzhu...     -> 127.0.0.1:28436  anytls-in
            └─ (其他)            -> 现有 Web 后端
UDP/443   sing-box MASQUE H3 持有（masque-h3）
            切换不影响该监听
```

关键约束：

- **Native Naive 只使用 TCP**，`network: "tcp"`，**不新增任何 UDP 监听器**。
- UDP/443 始终归 sing-box MASQUE H3，切换 Naive 不影响它。
- Naive 的 UDP（UoT v1/v2）在 **TCP CONNECT 隧道内**承载，不占用 UDP 端口。
- Nginx Stream 继续持有 TCP/443；**不要**用 sing-box 的 SNI 分发取代它。

---

## 1. 迁移前检查

### 1.1 确认版本与构建一致

```bash
# 生产当前运行的 sing-box
sing-box version
# 期望包含：Tags: with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0

# 本次 CI 构建的产物（在本地校验，不要上传到生产后才发现不一致）
sha256sum sing-box-linux-amd64
cat BUILD-INFO-VPS.txt
```

`BUILD-INFO-VPS.txt` 中的 `core_sha` 必须与本次 CI 运行的 commit 一致。

### 1.2 确认 Naive inbound 配置

```bash
sing-box check -c /etc/sing-box/config.json
# 期望输出为空（无错误）
```

确认配置中：

- 存在 `"tag": "naive-in"` 的 naive inbound；
- `"listen": "127.0.0.1"`（**仅监听 loopback**，由 Nginx Stream 转发；不要监听 0.0.0.0）；
- `"network": "tcp"`；
- `"listen_port"` 未被其他进程占用（见 1.3）。

### 1.3 确认端口无冲突

```bash
ss -lntp | grep -E ':(28436|28438|28437|28440)\b'
# 28436 anytls-in
# 28438 本次 Native Naive 计划端口
# 28437 Web masquerade 后端（必须已被监听，否则 masquerade 会 502）
# 28440 masque-h2
```

如果 28438 已被占用，选择其他空闲端口，并同步修改 Nginx Stream 的转发目标。

### 1.4 确认证书与私钥

```bash
# 证书路径与 server_name 必须与配置一致
openssl x509 -in /path/to/cert.pem -noout -subject -dates -ext subjectAltName
```

确认：

- 证书对 `riri.zhuzhu.jiejie12131.top` 有效且**未过期**；
- sing-box 进程用户对该证书与私钥**有读权限**；
- ALPN 与 Nginx Stream 的配置一致（见 `docs/JIEJIE-NGINX-ALPN-HARDENING.md`）。

> 迁移**不需要**重新签发证书，也**不需要**重新生成用户凭据。

### 1.5 确认 Web masquerade 后端可用

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:28437/
# 期望 200（或该后端正常的响应码）
```

该后端由服务端自己访问，**不经过** sing-box 路由，因此目标 ACL 不会影响它。
若此处不通，masquerade 会返回 502 —— 这是后台服务问题，不是 ACL 问题。

### 1.6 确认现有 Caddy 状态（回滚依赖它）

```bash
systemctl status caddy --no-pager
caddy version
```

**不要**在切换前停止、卸载或删除 Caddy 及其配置。回滚依赖它仍在。

### 1.7 确认目标 ACL 已生效

```bash
grep -n 'naive-in' /etc/sing-box/config.json
```

确认 `route.rules` 中：

1. `{"inbound":["naive-in"],"action":"resolve"}` 排在
2. `{"inbound":["naive-in"],"ip_cidr":[...],"action":"reject"}` **之前**。

顺序颠倒会导致域名目标绕过 IP 限制（见 `docs/JIEJIE-NAIVE-TARGET-ACL.md`）。

### 1.8 确认 VPS 自身公网 IP 的保护策略 —— **待确认项**

见第 5 节。这一项**尚未完成**，因为它需要真实 VPS 的网络信息，而仓库中
没有任何可信来源记录该地址，**不允许猜测**。

### 1.9 确认 SS2022 等内部服务未意外暴露

```bash
ss -lntp | grep -E ':(17414|8554)\b'
# 期望：仅监听 127.0.0.1，而不是 0.0.0.0
```

`ss2022-in`（17414）与 `shadowtls-in`（8554）**必须**只监听 loopback。
若出现 `0.0.0.0`，说明内部服务暴露在公网，属于严重问题，应先修复再迁移。

---

## 2. 独立测试入口验证（切换流量之前）

先让 Native Naive 在一个**独立端口**上运行并直接测试，不碰 Nginx Stream。

```bash
# 1) 用候选配置启动一个独立实例（不替换现有服务）
sing-box run -c /etc/sing-box/config.naive-candidate.json

# 2) 直接从 VPS 本机发起一次认证 CONNECT，确认隧道建立
#    这里用 curl 走 CONNECT，验证认证与隧道，不验证客户端兼容性
curl -sS -x https://<NAIVE_USER>:<NAIVE_PASSWORD>@127.0.0.1:28438 \
     -o /dev/null -w '%{http_code}\n' https://example.com/
```

在 VPS 本机验证 ACL（**这一步必须在切换前做**）：

```bash
# 受限目标：必须失败
curl -sS -x https://<USER>:<PASS>@127.0.0.1:28438 --max-time 8 \
     http://127.0.0.1:28437/ ; echo "exit=$?"
# 期望：非 0 退出码（被拒绝）。

# 域名形式指向受限目标：必须同样失败
curl -sS -x https://<USER>:<PASS>@127.0.0.1:28438 --max-time 8 \
     http://localhost:28437/ ; echo "exit=$?"
# 期望：非 0 退出码。两者行为必须一致，这是本次修复的核心。

# 正常公网目标：必须成功
curl -sS -x https://<USER>:<PASS>@127.0.0.1:28438 -o /dev/null \
     -w '%{http_code}\n' https://example.com/
# 期望：200

# masquerade：普通 HTTPS 客户端（不带代理认证）应看到伪装站点
curl -sk --resolve riri.zhuzhu.jiejie12131.top:28438:127.0.0.1 \
     https://riri.zhuzhu.jiejie12131.top:28438/ | head -c 200
```

记录以上每一条的**实际输出**。任何一条与期望不符，停止迁移。

---

## 3. 切换步骤（需要人工确认后执行）

> 以下为**计划**，本次未执行。

```bash
# 1) 备份当前生效配置
cp /etc/sing-box/config.json /etc/sing-box/config.json.bak.$(date +%F-%H%M%S)

# 2) 备份 Nginx Stream 配置
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.$(date +%F-%H%M%S)

# 3) 写入包含 naive-in 的新配置（先 check 再 reload）
sing-box check -c /etc/sing-box/config.json
systemctl reload sing-box     # reload 优先于 restart，避免中断现有连接

# 4) 把 Nginx Stream 中该 SNI 的转发目标从 Caddy 后端改到 127.0.0.1:28438
#    位置：stream { server { listen 443; proxy_pass <原本的 Caddy 后端>; } }
#    改为：proxy_pass 127.0.0.1:28438;
nginx -t
systemctl reload nginx
```

**顺序很重要**：先让 sing-box 在 28438 上就绪，再改 Nginx。反过来会有一段
无后端的窗口。

---

## 4. 切换后验证

```bash
# 1) 服务健康
systemctl status sing-box --no-pager
journalctl -u sing-box -n 50 --no-pager | grep -i naive

# 2) 真实客户端（官方 naive 客户端或实际订阅客户端）走一遍
#    确认：能打开网页、UDP（如 QUIC/DNS over UDP）可用

# 3) TCP/443 正常，且 UDP/443 未受影响
ss -lunp | grep ':443'
# 期望：sing-box 仍持有 UDP/443（MASQUE H3），未因本次切换改变

# 4) 其他协议未回归
#    AnyTLS    : 用现实客户端连 api.zhuzhu... 域
#    ShadowTLS : 用现实客户端连对应端口
#    SS2022    : 确认仍只监听 loopback（ss -lntp | grep 17414）

# 5) ACL 在真实入口上仍然生效
#    从外部用客户端尝试 CONNECT 127.0.0.1:28437 / localhost:28437
#    两者都必须被拒绝
```

---

## 5. VPS 自身公网 IP 保护 —— **未完成，需要生产信息**

### 为什么需要

客户端 `CONNECT <VPS公网IP>:<port>` 可以绕过"只允许特定来源访问"的限制，
直接触达本机监听在公网接口上的管理服务。当前 ACL 只覆盖私网与特殊用途地址，
**未覆盖 VPS 自身的公网 IP**。

### 为什么没有直接写进配置

仓库中**没有**任何可信来源记录该 VPS 的公网 IPv4/IPv6。根据任务要求，
不允许根据开发机出口 IP 推断，也不允许把示例地址写成真实地址。

### 需要执行的人工步骤

在 VPS 上执行以下命令，记录**真实输出**：

```bash
# 公网 IPv4（若使用 NAT/弹性 IP，这里可能显示内网地址，需以实际入口为准）
ip -4 addr show scope global
curl -4 -sS https://ifconfig.co        # 或运营商控制台/云厂商元数据
curl -6 -sS https://ifconfig.co

# 默认路由使用的源地址
ip -4 route get 1.1.1.1 | awk '{print $7}'
ip -6 route get 2606:4700:4700::1111 | awk '{print $7}'

# 实际监听在公网接口上的服务（这些才是要保护的对象）
ss -lntp | grep -v '127.0.0.1\|\[::1\]'
ss -lunp | grep -v '127.0.0.1\|\[::1\]'
```

### 拿到地址后如何补进配置

在 `route.rules` 中，**紧跟在**已有的 `naive-in` reject 规则之后
（或直接并入其 `ip_cidr` 列表），加入 VPS 自身地址：

```json
{
  "inbound": ["naive-in"],
  "ip_cidr": [
    "<VPS_PUBLIC_IPV4>/32",
    "<VPS_PUBLIC_IPV6>/128"
  ],
  "action": "reject"
}
```

注意事项：

- **多网卡 / 附加公网 IP / NAT 入口**：每一个都可能成为客户端可达的目标，
  需要分别列出。
- **必要业务例外**：如果确有客户端需要回连 VPS 公网地址（例如自建服务），
  在该 reject 规则**之前**为那些具体目标加允许规则，而不是放宽整条 ACL。
- 修改后重新 `sing-box check` 并 reload，再重复第 2 节的验证。
- **不要**把真实地址写进本仓库；生产地址只应存在于生产配置中。

---

## 6. 回滚步骤

回滚的目标是恢复 Caddy 作为该 SNI 的后端。**不需要**重新签发证书，
**不需要**重新生成用户凭据，**不需要**改动 UDP/443。

```bash
# 1) 先把 Nginx Stream 的转发目标改回 Caddy 后端
#    proxy_pass 127.0.0.1:28438;   ->   proxy_pass <原 Caddy 后端>;
nginx -t && systemctl reload nginx

# 2) 确认 Caddy 仍在运行并接管
systemctl status caddy --no-pager
curl -sk --resolve riri.zhuzhu.jiejie12131.top:443:127.0.0.1 \
     https://riri.zhuzhu.jiejie12131.top/ -o /dev/null -w '%{http_code}\n'
# 期望：200

# 3) （可选）停止 sing-box 中的 naive-in
#    如果新配置引入了问题，恢复备份配置再 reload：
cp /etc/sing-box/config.json.bak.<timestamp> /etc/sing-box/config.json
sing-box check -c /etc/sing-box/config.json
systemctl reload sing-box
```

回滚顺序与切换相反：**Nginx 先切回去**，让流量离开新后端，再考虑 sing-box
的配置。

回滚后确认：

- TCP/443 恢复正常；
- UDP/443 未受影响（`ss -lunp | grep ':443'`）；
- SS2022 / ShadowTLS 仍只监听 loopback；
- 没有删除任何证书或凭据。

---

## 7. 明确未执行的部分

- 本手册**没有**在任何生产 VPS 上执行。
- 第 5 节的真实公网 IP 仍待填写；ACL 对 VPS 自身公网地址的保护**尚未生效**。
- 官方 Naive 客户端的公网端到端验证需要在有真实客户端的环境中进行。
- 与 Caddy 的性能对比未执行（见 `docs/JIEJIE-BENCHMARK.md`）。
