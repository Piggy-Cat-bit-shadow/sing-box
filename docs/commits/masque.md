# MASQUE

[当前 MASQUE 实现与边界](../masque.md)

| Commit | 工作 |
| --- | --- |
| [`9c85c41`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9c85c41719be4da83cfa324ff1db440ea350a1b9) | 测试批量发送时，逐字节检查数据内容和送达顺序。 |
| [`37755cc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/37755ccd928fce1aa2bd0d139d5ecf92ddf936d3) | 补充元数据、队列和内存分配优化的测量结果。 |
| [`f8ff656`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f8ff65642be50e40ce7bf48253449479e8231f27) | 用 100 万个数据包测量内存分配与 GC 后的内存占用。 |
| [`c39ca8e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c39ca8eb819b1985d747b5cb1d7a08bad1e7a540) | 批量提交出站数据报，减少重复加锁与唤醒开销。 |
| [`baa97e9`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/baa97e945601d10f9e6365685fb6e4d6dfc9e7c2) | 改为等待测试服务端的 datagram 循环，不再假定其已启动。 |
| [`dd8b19a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/dd8b19aa5cc3d59d3814393bcd7417e32e835dc7) | 记录零拷贝工作在 CI 上的运行结果与结论。 |
| [`32ae337`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/32ae337e9d5f82c27b27c9a3810f789d93f37660) | 补充零拷贝数据传输的实现和适用范围。 |
| [`4cad551`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4cad5511c67e126a8456656612cc05edda103ed1) | 验证 inbound 路径只产生一次 copy，并定位该 copy 的位置。 |
| [`52d5756`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/52d57568fd794029e04d89e33ab2aad03b580eb4) | 为数据报预留合适的头部空间，避免发送时再次拷贝。 |
| [`1a7b3eb`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1a7b3ebe5dd6e378528b03fdaa0ec82852fc5749) | 让 CONNECT-IP 出站报文走数据报发送路径，并直接移交缓冲区所有权。 |
| [`b8cb5e2`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b8cb5e2cbf2cb15eda638483ab8bc4e361ed2c91) | 将 quic-go 依赖切换到支持缓冲区所有权转移的分支。 |
| [`f907032`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f9070327b7504e14b080e0cd9ba35034eafd31a1) | 补充性能测试结果，并根据结果调整路由方案。 |
| [`d2f645d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d2f645df4e87e07550ac7815dbcc60252f93f7ca) | 测量接收路径，并记录其 slice 保持分配的原因。 |
| [`fad8101`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/fad8101c573cb4aab098ad0aefc4879cdd37f40b) | 测量超限与竞争两条路径，两者结论均为无需改动。 |
| [`864c004`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/864c0048be7022ce2a9576d0a500faca71a6986b) | 通告路由改用二分查找替代线性扫描。 |
| [`0127eee`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0127eee90366726f682989234c04f8ff330e297d) | 记录 datagram 能力无需修改的依据，避免无谓改动。 |
| [`b5a25ed`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b5a25edd84a05e4e831d93461eb381895df5d926) | 移除 datagram 路径上的每包分配，降低稳态开销。 |
| [`0fadfc0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0fadfc021538c3262abd8ddd3634a406d8d0e8ee) | 恢复基于最新协议的连接隧道生命周期管理。 |
| [`bebeb5c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bebeb5c7e3c95f77565d34dcdc653d1b65f9b553) | 记录封闭式能力模型，明确各路径的可用能力集合。 |
| [`1a529bc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1a529bccdf2aa44679057efbb6f65b3bfe9721ce) | 收紧 dohpath 的 URI 模板子集，并校验模板中的 UTF-8 编码。 |
| [`db94a76`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/db94a76b2d9c7e07335c9e40a228de012d80c7bd) | 覆盖能力状态迁移与最终规范边界。 |
| [`d9a31d4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d9a31d44918f53224dedf842ff7980e05281cb43) | 拒绝本客户端无法履行的必需 SVCB 键，不再静默忽略此类记录。 |
| [`c047579`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c0475793f533909d19ef7fa261f3a7884aed0a6e) | 将 DoH 能力绑定到真实隧道传输与来源。 |
| [`b196103`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b1961033d42f3eb08b8c33e08c9184f40f07f6b9) | 移除不再使用的 PREF64 清理代码。 |
| [`2073b63`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2073b634bff82c51f72902feac6aea577261b103) | 固定硬失败级联行为，并修正一处错误的定时器描述。 |
| [`7e390e7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7e390e7843b4ed73982d01c753c7a0d56a30d2fe) | 通过真实构造流程测试 DNS 分配逻辑。 |
| [`c30290f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c30290fbffc62954175fc2371d935cfc0d918889) | 描述四个平面并说明范围限制，划定审计与实现边界。 |
| [`aea2a47`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/aea2a47c24001ad69511fa3d0093a4f30ad38aa7) | 覆盖端点路由、快照一致性与 SVCB 边界的组合场景测试。 |
| [`e93e297`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e93e297aa114d20a0963cb6d74f4b6e579940308) | 将 DNS 快照改为不可变对象，并复用原生 DNS 传输实现。 |
| [`5941c77`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5941c77e11c798619cef64ffcc5c0f27b4ea22fc) | 每次重连重建 bootstrap，修正胜者提升与拥塞控制顺序。 |
| [`c2a2b4f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c2a2b4f6b096ac4b3143afdcfb615a92fa1b1683) | 修正 split-DNS 语义、已有 H3 连接的 DoH 与规范一致性。 |
| [`176721a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/176721a9300aa4137bc56b655a7252513e9d619c) | 拒绝会超出 payload 上限的地址数量，避免越界写入。 |
| [`f119aef`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f119aefa2fca70f92c9b5f2e043668f58b0cba27) | 在深度检查中对目标协议包运行竞态检测。 |
| [`4f74c65`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4f74c65595c77c0128ebd5081064aa6febe25ae2) | 要求具备生产路径后才可称为已实现。 |
| [`05fa733`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/05fa733917eb39a9016ccb1e635c8e78a61f6b07) | 移除失效的选择规则，并对新模型施压测试。 |
| [`a6164de`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a6164dead0ab7611f92c9ac0fbc8ebac34fec5e1) | 保留 DNS_ASSIGN 的配置层级，使配置结构与协议语义一致。 |
| [`74e02fa`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/74e02fa07d7f86b8d823018852eb80423791e24e) | 将 bootstrap 恢复与握手竞争逻辑接入端点生命周期。 |
| [`8700681`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/87006818d839b651f7181185caef6e66ac920871) | 关闭每一个未胜出的 QUIC 竞争尝试，避免连接泄漏。 |
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
| [`6274779`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6274779ffa1e1963709f6f3a1df4e7f509179fbe) | 当时说明三种 DNS 角色、未实现部分及覆盖边界。 |
| [`d54777d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d54777dd731d45ca1be57a3f3191e19b4d68b173) | 在配置层固定两个 resolver 的边界，避免职责相互渗透。 |
| [`d0b2c27`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d0b2c27ecb503dd910e51da59823e6112a6bf6df) | 增加显式的隧道内域名解析器，并竞争内层 TCP 目标。 |
| [`b3218f3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b3218f340b8f543bbf6ac543bea15f00cf409da4) | 补齐 CONNECT-IP 目标编码矩阵，覆盖各类目标形式。 |
| [`a2a7a9a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a2a7a9a30fda815eda42428228854a60f15ab062) | 消除 CONNECT-UDP 延迟激活竞态，保证激活语义确定。 |
| [`ecdc966`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ecdc966ab4ee1f83880a0bbbb380129ecc8ac28b) | 拒绝 CONNECT-IP 模板目标中的反斜杠，防止解析歧义。 |
| [`7d66493`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7d66493bd3e4ac5441dbfe69fa0c7e3fa2eef529) | 让运行时冒烟测试识别 masque 端口占位符。 |
| [`0176c85`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0176c852a0021a8b4c5a98bfef95ecb3264245ff) | 使测试夹具端到端跑通客户端完整路径。 |
| [`0c500d4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0c500d42df809371a0081c99dc56e625e4d8429f) | 修复 ingress 夹具泄漏 goroutine 导致整包挂起的问题。 |
| [`29000a5`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/29000a54a4d046c688a7d125c813b5799f391fb1) | 基准测试路由匹配，并增加客户端 QUIC 拥塞控制选项。 |
| [`6d94da5`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6d94da584f9b5313be08c1d8d6b943a1e03de628) | 会话状态改从不可变快照读取，不再加锁。 |
| [`9739c42`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9739c42a888f5254574bdf2c47048a88dfc8f491) | 入站数据报改为包装而非复制，减少入站内存拷贝。 |
| [`8f1ba42`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8f1ba42a97aec1f38ad70a6c8f1dffe391ab162c) | 拆分客户端与服务端端点注册，使职责边界清晰。 |
| [`143f886`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/143f886e2168dd0906eacfe6b4806e8a7c2b6e5b) | 对端提前断开时释放建立窗口内的 datagram。 |
| [`fd53dbc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/fd53dbcf25dbdd809a0033dd51d553804e5d2be6) | 修正批量系统调用测试，使其在目标平台上通过静态检查。 |
| [`a64e79f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a64e79f0f9ea6b1b090203b71ee24a5cbdde573b) | 保留批量写入接口的测试，防止后续修改意外删除。 |
| [`4ac7723`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4ac7723103aeb1fe2030af5b5034d58e4776a0f5) | 使批量测试满足现代化与未使用代码检查要求。 |
| [`a2bff6b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a2bff6b7c62d48d2b6f4108685edcfc466667355) | 按当时的互操作与 PTB 实测结果校准结论。 |
| [`87d11bd`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/87d11bd2992ef3b7e2a621ea67283dd53a1e04d4) | 明确 packet-too-big 错误属于哪个会话。 |
| [`a07fd54`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a07fd54787705bbf79f969f1c427640053388248) | 精确区分 QUICHE 执行失败的类型，避免笼统归因。 |
| [`c51772f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c51772f6a1004387f5c75eaedab17c6781fc1a87) | 在真实数据报套接字上验证批量发送路径。 |
| [`9d6bfc7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9d6bfc783d08bfd3cb8f69099c51b1ffd55f56e6) | 对超时包装器的批量路径做基准测试。 |
| [`e7f7dde`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e7f7dde6a0457ed075cf43b52a9ca6db9b5aeb76) | 验证批量能力可以穿过 UDP 超时包装器。 |
| [`ff12828`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ff12828a4ded44350b80f0fa9ca9263d239b99ed) | 将 QUICHE 互操作测试移出快速任务，避免拖慢常规 CI。 |
| [`b6a2fbc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b6a2fbcc4be14c376a4da82ec51adbe549d4839d) | 记录互操作执行器的能力限制，说明其适用边界。 |
| [`a9c1860`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a9c18602dab9b97c8627faae5146e1e4c329ccc3) | 区分 QUICHE 停顿与协议不一致两种失败，避免误判。 |
| [`c8e5a65`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c8e5a65f9031198f385702ec209591965092aa1a) | 按当时的实测结果更新验收边界。 |
| [`8a6b333`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8a6b3336773393ad5d92d9464df653cf04e0b8f9) | 增加可重复的 VPS 验收运行器，统一验收流程。 |
| [`60fec08`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/60fec086ebbaac2622e902f88257b20d6fc4109b) | 接入 Google QUICHE 实时互操作测试作为第三方判定。 |
| [`ad40266`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ad4026620a4c613b2c519c2d8bebcdfc4fac0752) | 强制触发真实场景下的报文过大分支，验证处理路径。 |
| [`5f37304`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5f373043a3048822c7312760da8ea0183d506817) | 移除未使用的 GSO 辅助函数并使 Linux 基准通过 errcheck。 |
| [`c7de774`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c7de7747d71348f87c9a6725822c59616641cd08) | 测量 Linux UDP GSO 分组并据此否决一个尺寸阈值。 |
| [`f20e71c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f20e71c728d171638d11ea51d376c6a2c940e88e) | 删除批量能力测试中重复的检查。 |
| [`1a0761e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1a0761e9a2601d7e5318b6af179f8939a9d165c1) | 审计 HTTP/3 MTU 现状而非新增选项，先摸清实际情况。 |
| [`62d5900`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/62d59003e74abb4fb5d886d9aac7e95d7438f3a9) | 在返回成功前完成 CONNECT-UDP 目标建立，保证语义正确。 |
| [`bffd069`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bffd06952dd42067c84cc7f027884a1114987795) | 测试目标套接字是否实际调用批量发送系统接口。 |
| [`b8e7312`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b8e731257bb4b64b509102ee1cc80b7d647864b6) | 测量超时包装器会丢弃批量能力，确认该实现的副作用。 |
| [`01ae0d3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/01ae0d3082890d6f71caf32ebfa864e9f0864a34) | 批量转发目标协议数据包，降低每包处理开销。 |
| [`3b8d99a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3b8d99a216fecbc8cbd0de86bab1a4f7e29f8f66) | H3 ingress datagram 改为包装而非复制，避免入站多余拷贝。 |
| [`ec2b4b9`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ec2b4b91e0f521ba8dbb30e9cd304a8655acf5a2) | 目标转发改用已连接的数据报套接字，简化收发。 |
| [`864be35`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/864be35ebcf150252ddd2512f57c77f6b9aa86bd) | 修正共享 CI 环境中偶发失败的伸缩测试。 |
| [`583bfc8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/583bfc84f38a0f7160deab84484c260bbd7377b8) | 将 QUICHE 判定测试加入参考运行过滤集合。 |
| [`8dedfb4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8dedfb4e3ba1e7bb5dac3ff91eb4fbf366a24d80) | 使新增测试满足格式化与现代化检查要求。 |
| [`4db6f90`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4db6f90f9857215398eb8ddaad56c4c2a46d9d00) | 将 RFC 9931 客户端侧重新归类为范围之外，明确不实现。 |
| [`0dbfc43`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0dbfc43d1e3fd9ddbc8b2363cc81d56c0e9428f6) | 记录 QUICHE 协议向量检查并重新归类客户端侧。 |
| [`36d4048`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/36d404826b9409b0d9a905c2ff82e60c4adf04f0) | 将 Google QUICHE 作为第三个协议判定源接入流程。 |
| [`41a04ce`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/41a04ceb14e13881c5624337f323c74f3a3eea1c) | 固定跨会话策略、控制突发与 IPv6 扩展链行为。 |
| [`e823b43`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e823b4312b37aa96898c1b2f6b53702baee9fb9c) | 完成参考审计并加入 VPS 前检查表，形成闭环。 |
| [`daa4907`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/daa49073e8f42eaeaff246ca76b1305507eedc76) | 补充 CONNECT-UDP 的 IPv6 测试，并修正 RFC 9931 的引用。 |
| [`1dbf363`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1dbf363d49df2270b6edd9418dd6e7ac5baf6d91) | 测量丢包、重复与乱序容忍度，验证数据面健壮性。 |
| [`ba7f62a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ba7f62a4ba852f3faa8f7008d0aa273d22e22234) | 验证报文过大证据链，确认路径发现机制可用。 |
| [`4fc9984`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4fc9984b3992ed3039e7ea29d93949e70cddc535) | capsule 路径允许最大的普通 IPv6 包，避免不必要分片。 |
| [`988df7a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/988df7a35847375f166e3a6c25728491d1ddcc81) | 固定实时标识、零长度数据报与错误语义三类行为。 |
| [`8530321`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8530321703a14b7ae5427aba6570d6b850cba697) | 固定限流来源键以抵御 NAT 重绑定导致的绕过。 |
| [`7bb4342`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7bb43427550aad174fd5a6a9837d9060a22281f6) | 通过测量确认数据来源，避免只检查预设值。 |
| [`7ae42c9`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7ae42c98d47b562131c260b0e999e0f77c1346de) | 在 CI 中有界运行全部模糊测试目标，控制耗时。 |
| [`5434688`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/543468826807688ae878cf30b60ae6d25c088ab2) | 修复模糊测试语料并补充 CONNECT-UDP 路径覆盖。 |
| [`c702497`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c70249783f7d661375ec7910f29a041f1a2ca69a) | 修复参考测试工具的第六版协议控制包解码错误。 |
| [`a819eeb`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a819eeb3feeea280bc16059a9f1967c9a1761cba) | 控制包突发测试改用新版等待组写法。 |
| [`67e55b3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/67e55b387253355041b27c53e495461c7b8c9706) | 记录第三阶段结论并修正此前两处说法。 |
| [`a12e5c2`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a12e5c258c16d39b6ce4cd82487c8deeea5aa1e4) | 双向堵住参考测试的假绿漏洞，确保失败可被发现。 |
| [`429d8b6`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/429d8b6774a1315816dfce828e2090aa1ba84bc9) | 审计 Proxy-Status 并固定认证边界，明确错误上报语义。 |
| [`a7fd9ec`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a7fd9ec116cd3e147f29e1289b6a8ec4cec6abd9) | 测试流辅助函数改用 sync.Once 关闭，避免重复关闭。 |
| [`824cd65`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/824cd658a8d2e5816744a9ccf53faffcdd81c388) | 使跳数递减函数对畸形报文头部安全，不再越界访问。 |
| [`86002b5`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/86002b56f064d541127a48bdaae6ef88cdfa0e98) | 对 IP 包解析器与 capsule 分片做模糊测试，覆盖畸形输入。 |
| [`1325727`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1325727a5625dd2dc58954e5825b7ac66334c6f1) | 锁定 IPv6 扩展头的协议解析行为，防止回归。 |
| [`0cc6074`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0cc6074e3d2d5d444083f168aef76dfa7ae9872f) | 固定可变长度整数边界上的数据报尺寸计算。 |
| [`858284e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/858284e5a0751ba2454697ae441122a82d631857) | 测试发送队列的背压和缓冲区所有权，防止并发问题。 |
| [`c5e2d3e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c5e2d3eb48c1bea13c69420519aa195297fc9c3c) | 测量活动隧道的关闭与资源回收是否彻底。 |
| [`01f20ce`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/01f20ce4e69fac8ea38432cb22959e41f4329f71) | 测量 NAT 重绑定场景下的 QUIC 迁移是否可用。 |
| [`0783a33`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0783a33b3bad284eb4b074ab8734b3341cb5323f) | 验证禁用数据报时的控制包回退路径是否正确。 |
| [`6efcf0a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6efcf0a75f5d2b9d61cfa8581a4c2a44dbc00b1c) | CONNECT-IP ICMP 夹具改用真实服务端网关作为目标。 |
| [`528858c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/528858c4447baba18a176dac74737636ce5b13db) | 参考互操作按用例各自所需的二进制运行。 |
| [`9577b09`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9577b095f89e39825f02065f4206dfa16477ee50) | 使模糊测试种子满足格式化检查要求。 |
| [`762b0ce`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/762b0cede298983f6ec0fceac4b6005c8a82a442) | 补充连接池、隔离机制和模糊测试的覆盖情况。 |
| [`66f0e94`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/66f0e94360bb079f6d7980b22d092b09252af2af) | 对消费对端可控字节的解析器做模糊测试。 |
| [`e4d2f6c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e4d2f6c1afb1008741a137b8c94481e0f8602f16) | 使 Contains 与服务端自身地址的查询结果一致。 |
| [`907dbfb`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/907dbfb991861d2630ac275b9be65380c278e11c) | 记录标准修复与数据报回退的实测结果。 |
| [`b81244b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b81244bdf767f798d4e8509f8e3f3898d9ded89a) | 在真实链路上验证数据报到控制包的回退路径。 |
| [`432b36c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/432b36ce7532ec6e3e27d70249f64334a35dd784) | 记录参考互操作结果与两种 pin 形式的差异。 |
| [`32b1d25`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/32b1d25cbfd12786ffceef4b4cd03f5e9cdfc71a) | 验证与固定参考实现之间的 CONNECT-UDP 与 CONNECT-IP 互操作。 |
| [`e81f849`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e81f849949ac79854c090ef2d068ff9d796d584f) | 从仓库根目录运行带特性标记的协议测试。 |
| [`935ffec`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/935ffeca80dcc48c533de14f9328d9428bd4f148) | 运行目标协议各包与带特性标记的协议测试。 |
| [`d159ec0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d159ec09dfd1e9637c5c559d0630af95aec22923) | 记录参考审计、改动与剩余缺口，形成阶段结论。 |
| [`ab9c9f0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ab9c9f09d9962288cffb1febb63cbd2c67719f7e) | 固定 CONNECT-UDP 请求路径测试语料，覆盖常见形态。 |
| [`e4f847e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e4f847ecf732e8cd580ed1517f34fd3436ec6380) | 将 MASQUE 的 QUIC 调优改为可选开启，避免默认行为变化。 |
| [`a529b68`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a529b68c830ff6a2ffe61cbe9ce5535e401a9c2a) | 限制单个控制 capsule 的条目数量，防止资源耗尽。 |
| [`b656b06`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b656b062f99901406c8360f1358174b480eecfd5) | 以线性时间校验 ROUTE_ADVERTISEMENT 重叠，避免二次复杂度。 |
| [`969909b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/969909bc16a188206f6fb598e6d2b833429f11f5) | 拒绝跨协议重叠的路由公告范围，避免路由冲突。 |
| [`d4ead14`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d4ead1498a30c45b971074ef17282483b1f1a8a1) | 按数据报粒度强制执行目标访问控制，并交付配置。 |
| [`cb567c0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/cb567c0ccd419047056d5ee0644a15ee77580b33) | 补齐未授权探测矩阵，覆盖各类越权尝试。 |
| [`1276eb8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1276eb85a2afa318ba7c6178ee69fdc8caf8bacc) | 测试从 HTTP/3 回退到 HTTP/2 时的重放安全性。 |
| [`0271b14`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0271b145addf40759e6fcae9a83fdec9ae3d4c14) | 连接请求需等待握手完成，避免提前建立连接。 |
| [`9491008`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9491008a97bd5bb636458e32d4aa51e1e0118e51) | 将 http3_fallback 接入 MASQUE 客户端并修正退避生命周期。 |
| [`b836956`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b836956030c132a17133e9ea0144373a5e461686) | 将连接池应用于 MASQUE 隧道客户端，复用既有连接。 |
| [`5dc14cc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5dc14ccc21cfd543294ac790ca0f1099e93bb80b) | 增加目标协议与隧道协议在两种版本下的集成覆盖。 |
