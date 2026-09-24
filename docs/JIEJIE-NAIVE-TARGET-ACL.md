# Naive 目标访问控制（Target ACL）

本文说明如何限制 **Naive 客户端** 能通过代理访问的目标地址，以及为什么必须
这样配置。目标是把「客户端请求的代理目标」限制在公网范围，同时**不影响**服务端
自身发起的内部连接（Web masquerade 后端、AnyTLS fallback、本机 DNS 等）。

---

## 1. 为什么需要显式配置

sing-box 的访问控制规则（`ip_cidr`、`ip_is_private` 等）匹配的是
`metadata.DestinationAddresses`。这个字段**只有在 `resolve` 规则动作执行后才会
被填充**。

因此如果目标是一个域名，且在匹配 `ip_cidr` 之前没有执行解析：

- 规则的 IP 条件无法匹配该域名背后的真实地址；
- `direct` outbound 会在**拨号阶段**自行解析域名；
- 结果是客户端可以用 `CONNECT localhost:80` 这类写法，绕过只匹配 IP 的规则，
  访问本机与内网服务。

这不是 Naive 独有的问题，而是 sing-box「路由 + 域名解析」流程的通用语义。
但 Native Naive 替代原 Caddy 服务端后必须保证：**替换不会扩大目标访问范围**。

**实测证据**（`test/jiejie/jiejie_naive_target_acl_test.go`，
`TestJiejieTargetACLDomainTargetWithoutResolveRule`）：

```
control:  domain ok.test reached=true queries=1        # 证明域名解析与隧道在本实例中可用
without a resolve action, CONNECT forbidden.test reached=true,
          forbidden origin connections=1               # 没有 resolve 时，域名绕过了 ip_cidr
```

对照组的存在很重要：它排除了「域名本来就解析失败」这一可能，证明该结果为真绕过。

---

## 2. 推荐的生产配置

在 `route.rules` 中，为 Naive inbound **成对**添加 `resolve` 与 `ip_cidr` 拒绝规则，
并且 **`resolve` 必须排在 IP 规则之前**：

```json
{
  "route": {
    "rules": [
      { "inbound": ["naive-in"], "action": "resolve" },
      {
        "inbound": ["naive-in"],
        "ip_cidr": [
          "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
          "169.254.0.0/16", "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24",
          "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
          "240.0.0.0/4",
          "::1/128", "::/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32"
        ],
        "action": "reject"
      }
    ],
    "final": "direct"
  }
}
```

要点：

| 项目 | 说明 |
| --- | --- |
| 插入位置 | 放在其他规则**之后**，不要插到 `residential` 用户规则之前 |
| 规则顺序 | `resolve` 必须在 `ip_cidr` 拒绝规则**之前**，否则 IP 条件拿不到地址 |
| `inbound` 限定 | 两条规则都限定 `naive-in`，因此**不影响** AnyTLS / MASQUE / ShadowTLS / SS2022 |
| 无需删除旧规则 | 既有的 `{"ip_is_private": true, "outbound": "direct"}` 保持原样即可，它作用于其他 inbound |
| UDP | 同一组规则同时约束 UoT v1/v2 的**每包真实目标**（见第 4 节） |

`release/jiejie-production-topology.json` 已按上述形式更新，并通过
`sing-box check` 校验。

---

## 3. 为什么这样能保证「实际拨号地址」也经过检查

这是本次审计最关键的一点。仅添加 `resolve` 并不足以构成闭环，
真正的保证来自 sing-box 的地址传递机制：

1. `actionResolve` 把解析结果写入 `metadata.DestinationAddresses`；
2. `ConnectionManager.NewConnection` 在 `len(DestinationAddresses) > 0` 时调用
   `dialer.DialSerialNetwork`；
3. `DialSerialNetwork` / `DialSerial` 对列表中的**每个 IP** 调用
   `dialer.DialContext(ctx, network, M.SocksaddrFrom(address, port))` ——
   传入的是**已解析的 IP**，而不是原域名；
4. 因此 outbound **不会二次解析**该域名，拨号目标必然来自被规则检查过的那份列表。

同时，若解析结果同时包含公网与受限地址，拨号只会在这份列表内部按顺序/竞速选择，
不会回退到列表之外的地址，也就不会「因为第一个结果是公网就放行后续的私网连接」。

**DNS 重绑定实测**（`TestJiejieTargetACLRebindingCannotBypass`）：同一域名第一次解析为
允许地址、第二次解析为 loopback，并主动清空 DNS 缓存以强制真实二次解析：

```
rebind.test first  resolution (allowed address) reached=true  queries=1
flushed DNS cache to force a genuine rebind
rebind.test second resolution (loopback)        reached=false queries=2
```

`queries` 从 1 增长到 2，证明第二次确实重新解析，且重新解析得到的受限地址被拒绝。
即：**检查所用地址与实际拨号地址一致**。

---

## 4. UDP / UoT 的每包目标

UoT 有两种承载方式，风险点不同：

- **v2 Connect 模式**：会话头带有固定目标，会话建立时即被检查；
- **v1 与 v2 非 Connect 模式**：会话头里的地址只是**会话标识**，
  之后**每个数据包都各自携带自己的目标地址**。

后者的风险是：会话以某个允许地址通过检查后，后续数据包可以指向**完全不同的**
目标（例如 loopback），而这条路径不会再次经过会话级的路由判定。

本次修复在 `route/packet_destination_guard.go` 中增加了**逐包目标检查**：
对每个数据包解码出的目标重新执行同一套路由规则，被拒绝的数据包直接丢弃。
实现要点：

- 只在 `metadata.UoTDatagramDestinations`（即非 Connect 的 UoT 会话）时启用，
  **其他协议的 UDP 数据面不受影响**；
- 在**读取侧**拦截，因为写入侧存在批量写入快速路径，不能保证所有数据包都经过，
  而读取侧是唯一无法绕过的位置；
- 决策结果按目标做记忆化，允许的数据包在首次之后只有一次 map 查找开销；
- IPv4-mapped IPv6 会先归一化为 IPv4，避免用 `::ffff:127.0.0.1` 换一种写法绕过规则；
- 被拒绝的数据包**丢弃而不报错**，因此同一会话中发往合法目标的数据包不受影响。

实测（`TestJiejieTargetACLUoTV1MultiTargetChecksEachDatagram`，
`TestJiejieTargetACLUoTV2NonConnectMultiTarget`）：同一会话先发往允许目标、再发往 loopback：

```
UoT v1: allowed origin received 1, forbidden received 0
v2 non-connect: allowed datagram delivered=1, forbidden received 0
```

允许目标成功投递，说明检查是**有区分度的**，而不是把所有数据包都拦掉。

---

## 5. 必须保留的服务端内部连接

目标访问控制只应约束**客户端指定的代理目标**，不能误伤**服务端自己发起**的连接：

- Naive / MASQUE 的 Web masquerade 后端（生产为 `127.0.0.1:28437`）；
- AnyTLS fallback（`127.0.0.1:28437`）；
- 本机 AdGuard Home DNS（`127.0.0.1:53`）；
- ShadowTLS handshake 目标。

这些连接由服务端组件直接建立，**不经过 sing-box Router**，因此上面按
`inbound: ["naive-in"]` 限定的规则不会匹配它们。

这一点经过实测确认（`TestJiejieTargetACLDoesNotBreakMasqueradeBackend`）：在
**规则确实拒绝 loopback** 的同一个实例中，masquerade 仍能访问其 loopback 后端
（返回 200，31 字节正文），同时客户端对 loopback 的 `CONNECT` 依然被拒绝。

---

## 6. 验收结果

| 场景 | 结果 |
| --- | --- |
| `CONNECT 127.0.0.1:PORT`（字面 IP） | 拒绝，origin 连接数 0 |
| `CONNECT localhost:PORT` / 域名解析到受限 IP | 拒绝 |
| 无 `resolve` 动作时的域名目标 | **可达（已证实为绕过）**，故 `resolve` 为必需 |
| DNS 重绑定（先公网后 loopback，已清缓存） | 第二次解析后拒绝 |
| IPv6 loopback / ULA / link-local / IPv4-mapped | 全部拒绝（含等价写法） |
| UoT v1 多目标（每包不同目标） | 允许目标投递，受限目标 0 包 |
| UoT v2 Connect | 受限目标 0 包 |
| UoT v2 非 Connect 多目标 | 允许目标投递，受限目标 0 包 |
| 正常公网域名（TCP 与 UDP） | 正常可达 |
| masquerade 后端 loopback | 正常可达（未被误伤） |

---

## 7. 剩余风险（如实说明）

1. **生产规则中的 CIDR 列表未经生产环境验证。**
   上述列表是建议的默认拒绝范围，其中 `192.0.2.0/24`、`203.0.113.0/24`、
   `2001:db8::/32` 属于文档用地址段，`100.64.0.0/10`、`198.18.0.0/15` 等是否需要在
   生产拒绝，应根据实际业务确认。本次**没有**接触生产 VPS。
2. **VPS 自身公网 IP 未纳入拒绝范围。**
   若客户端 `CONNECT` 到 VPS 自己的公网 IP，仍可能触达只应从特定来源访问的
   管理入口。本次规则只覆盖私网/特殊用途地址；是否需要额外拒绝 VPS 自身公网 IP
   取决于该机器上监听公网的管理服务，建议在实际评估后单独添加。
3. **UoT 逐包检查为本次新增的共享模块改动。**
   它只在非 Connect 的 UoT 会话上启用，且已通过完整回归（见下），
   但它是 `protocol/naive` 之外的路由层改动，若后续上游合并需要留意。
4. **未执行的验证：** STUN 端到端、独立 IPv6 UDP origin 的完整往返、
   与 Caddy 的性能对比，本次均未执行。

---

## 8. 回归范围

本次改动（`route/packet_destination_guard.go`、`common/uot/router.go`、
`adapter/inbound.go`，以及配置模板）已通过：

- `test/jiejie` 完整套件（`-run TestJiejie`）；
- `go test -race ./route/... ./route/rule/...`；
- `golangci-lint`（0 issues）；
- 生产构建标签构建 + `sing-box check`；
- UoT 正常多目标用例 `TestJiejieNaiveUoTV1MultipleTargets`（**无规则时应放行多个不同目标**），
  确认逐包检查引入了**零**功能回归。
