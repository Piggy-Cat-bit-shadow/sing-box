# DNS

| Commit | 工作 |
| --- | --- |
| [`d676b4a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d676b4a626bdd7cedb759394ace40da0e1b0059f) | 从 DialerOptions 直接推导 SOCKS4 目标解析策略，不再依赖代理服务器是否为域名。 |
| [`9260e8a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9260e8a95c2b07ecea0a3ad6e64b47adb95025ed) | 补充各协议数据传输和 DNS 审计的结论与依据。 |
| [`977f530`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/977f53031f6800ad08d002e090b6bc83a9f47615) | 明确 WireGuard 的两个 DNS 授权边界，不再让语义保持隐含。 |
| [`43ffa93`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/43ffa9334082f87ff866da3536042dab9a1262e4) | SOCKS4 目标地址改用出口自身的解析器，避免误用入站解析结果。 |
| [`1a529bc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1a529bccdf2aa44679057efbb6f65b3bfe9721ce) | 收紧 dohpath 的 URI 模板子集，并校验模板中的 UTF-8 编码。 |
| [`d9a31d4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d9a31d44918f53224dedf842ff7980e05281cb43) | 拒绝本客户端无法履行的必需 SVCB 键，不再静默忽略此类记录。 |
| [`c047579`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c0475793f533909d19ef7fa261f3a7884aed0a6e) | 将 DoH 能力绑定到真实隧道传输与来源。 |
| [`b196103`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b1961033d42f3eb08b8c33e08c9184f40f07f6b9) | 移除不再使用的 PREF64 清理代码。 |
| [`7e390e7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7e390e7843b4ed73982d01c753c7a0d56a30d2fe) | 通过真实构造流程测试 DNS 分配逻辑。 |
| [`aea2a47`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/aea2a47c24001ad69511fa3d0093a4f30ad38aa7) | 覆盖端点路由、快照一致性与 SVCB 边界的组合场景测试。 |
| [`e93e297`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e93e297aa114d20a0963cb6d74f4b6e579940308) | 将 DNS 快照改为不可变对象，并复用原生 DNS 传输实现。 |
| [`5941c77`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5941c77e11c798619cef64ffcc5c0f27b4ea22fc) | 每次重连重建 bootstrap，修正胜者提升与拥塞控制顺序。 |
| [`c2a2b4f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c2a2b4f6b096ac4b3143afdcfb615a92fa1b1683) | 修正 split-DNS 语义、已有 H3 连接的 DoH 与规范一致性。 |
| [`a6164de`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a6164dead0ab7611f92c9ac0fbc8ebac34fec5e1) | 保留 DNS_ASSIGN 的配置层级，使配置结构与协议语义一致。 |
| [`74e02fa`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/74e02fa07d7f86b8d823018852eb80423791e24e) | 将 bootstrap 恢复与握手竞争逻辑接入端点生命周期。 |
| [`1f698f0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1f698f0e78eb0282283aab367baa96621c1c6e4c) | 记录已实现的 MASQUE DNS 阶段，并划定后续工作范围。 |
| [`f15139c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f15139c6f5b508f666565b1b91563b87da95193b) | 覆盖地址分配与前缀公告两条路径的端到端测试。 |
| [`1d87f0c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1d87f0cf79455c43bb508cd009669c106ecdacd6) | 对 DNS capsule 做模糊测试，并补充泄漏与循环测试。 |
| [`b997373`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b9973735659c7aebb48e0680693624cb50b62200) | 为分配的 resolver 在隧道自身连接上提供 DoH 查询能力。 |
| [`433e1a4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/433e1a444d3d789065410813178ff34d16ada19c) | 在握手完成时竞争 QUIC bootstrap 候选，缩短首包解析延迟。 |
| [`8870623`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8870623cfd4cd4173979c84b122b9ca8c8b216ea) | 增加有界 bootstrap 解析，并加入最后可用结果缓存。 |
| [`71b5406`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/71b54060fad453b5011e5b5dfccb652ec0729a68) | 在运行时真正应用 resolver 优先级，而非仅解析配置。 |
| [`63a358b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/63a358bab9248016d7700d02636f5b07991130c1) | 让参考服务端可以下发地址分配与前缀公告记录。 |
| [`9e5da9e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9e5da9e8c435655766e4a4381168ee514d514b9c) | 增加端点本地的已分配 DNS 传输，避免绕行系统解析器。 |
| [`3ec67e4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3ec67e4af49e935efff7b543376efa8faf4c6fd9) | 将地址分配与前缀公告接入会话状态机与生命周期。 |
| [`6486c05`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6486c050403209166047729e59752ec7d93d10c0) | 实现地址分配与前缀公告两类控制 capsule 的编解码。 |
| [`6274779`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6274779ffa1e1963709f6f3a1df4e7f509179fbe) | 说明三种 DNS 角色与尚未实现的部分，明确当前覆盖边界。 |
| [`d54777d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d54777dd731d45ca1be57a3f3191e19b4d68b173) | 在配置层固定两个 resolver 的边界，避免职责相互渗透。 |
| [`d0b2c27`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d0b2c27ecb503dd910e51da59823e6112a6bf6df) | 增加显式的隧道内域名解析器，并竞争内层 TCP 目标。 |
| [`d1b7eda`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d1b7edac2a7ca52bb5feadf2a7437325ee78b230) | 停止格式化被日志级别丢弃的逐记录日志行。 |
| [`b6b68b8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b6b68b85a7cfe5b58d6e33a57009a7d5f2222229) | 共享查询失败后重新竞争重试代次。 |
