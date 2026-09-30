# Naive

| Commit | 工作 |
| --- | --- |
| [`50bbed4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/50bbed43e0ff4d2a24ccc05e3035199b14633d84) | 记录 Chromium 只解析一次而非两次，纠正此前的重复解析判断。 |
| [`08861f1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/08861f136379ffd178257c405b639ab2008a4dc1) | 记录 CI 运行编号，便于回溯对应轮次的实测结果。 |
| [`751b6b7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/751b6b7f89fd8867c767fe880e2440b2d221cce0) | 记录数据面加固的改动范围与验证结果。 |
| [`f45db77`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f45db770ea80f8d6bdbbd8fb01285401a55677e1) | 测量 cached 首包向 Cronet 的移交路径是否真正零拷贝。 |
| [`228fce7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/228fce76d5d2e9fc1010bd6890e34c291a3e33fe) | 固定带缓冲钉住与提前扩容补丁的 Cronet 依赖分支版本。 |
| [`ebc9a90`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ebc9a903a1cbeb7a494d14e01405e05ab5a140fe) | 修正一处把回退误报为解析失败的模糊测试断言。 |
| [`f7e588c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f7e588c8c13e9e8eba48128bf42cf1c8c4e4489f) | 在真实并发下测试限流器，验证其行为符合预期。 |
| [`56e4de4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/56e4de4fcbb4aaa5bd23b53fad4a33b5405e19f4) | 记录实测的生命周期与新增资源控制。 |
| [`724035c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/724035c763ad37899fa11e793bb9a61e56c3a365) | 移除重复的 idle_timeout 并验证空闲隧道可以存活。 |
| [`c761d6b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c761d6bedd77c483915f1e1cfc718e95617fed5a) | 增加可选的 inbound 连接数与请求阶段限制。 |
| [`a1e7a69`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a1e7a69ba7bd457f639aacc5310fb7e3dd0250a2) | 在真实 socket 上测量 inbound 连接生命周期与资源回收。 |
| [`9325560`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/93255606a984e33f2cb70c4435a89254f211fe31) | 统一推导会话 framing 并为其加保护，避免各处不一致。 |
| [`f477e0a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f477e0a150cb370682f44010fd57f39662a02ca8) | 清空 KNOWN_FAILURES，四条失败均为夹具缺陷而非产品问题。 |
| [`ecaa152`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ecaa152f4d8a856af0d102e212fd66fbf53966cc) | 撤回非连接版本为产品缺陷的错误结论，纠正判断。 |
| [`0864e31`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0864e31c749f70a59f3032670ebb1249f65d209c) | 修正审计台账并使集成测试套件可运行。 |
| [`2e3b614`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2e3b614f2d0821c9f847944816b278bec854c5de) | 固定 byteformats 溢出修复，并校验窗口选项边界。 |
| [`f64638a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f64638a9854cc7eb223a70b1905d0b5c5bc264da) | 跨两个仓库固定客户端编解码契约。 |
| [`6fe3acc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6fe3acce3927d977ea739012a476cd3d41ea45ca) | 固定经审计的客户端编解码实现并纳入版本控制。 |
| [`499eca1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/499eca17a4261f5c940db835032f72dd3096f163) | 记录服务端 HTTP/2 窗口结论并修正其中一处。 |
| [`31b0061`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/31b006164893f041d3950832227e9e2c91fe4857) | 为 loopback-resolve 安全审计加入真实对照组，避免自证。 |
| [`7ebb331`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7ebb331a47e08f086f1f73d24188faccf298eb04) | 使差异测试工具比较错误并对差异强制断言。 |
| [`8d189a4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8d189a463049e1228cfd40ac118d15192612e3e8) | 以单批次测量吞吐并报告真实失败。 |
| [`da34e4c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/da34e4ce71fe1a5a37405f77c6b08d8a6388582a) | 按库的真实边界校验 HTTP/2 接收窗口设置是否合法。 |
| [`ef598d4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ef598d44153a307c6a6e008d7d04e88f1edcd551) | 构建 Naive inbound 时提供真实 TLS 材料，而非占位证书。 |
| [`0943040`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0943040c678d0ded3ca131bdbaee411167221198) | 实际构建并启动原生服务端入站，而非仅解析配置。 |
| [`cc2cce6`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/cc2cce69cd3515eb85955c78d7b58edf6075b089) | 将原生实现声明为生产环境使用的服务端形态。 |
| [`67f35ae`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/67f35aeb605399b752e2c3f6752240a5c63f21d4) | 将原生实现声明为生产环境使用的服务端形态。 |
| [`279720c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/279720cce281e62bc242e2aea8eaec800949704f) | 测试保护条件改以出站而非入站为准，修正判断。 |
| [`3232055`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3232055c4d93f6f90b5b49b000037b194c7122d0) | 修正 Native Naive 的生产拓扑说明，使其与部署一致。 |
| [`378b8b1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/378b8b1464c893635b466634b0f5c7612d479ab9) | 固定原生服务端生产契约并加入测试保护。 |
| [`0a7868b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0a7868b0f0ce13f3f81cbfc65ce91ba98122c8db) | 固定原生服务端生产契约并加入测试保护。 |
| [`fff7d46`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/fff7d46e79804d46cad235b65c8b543eefc8daa1) | 恢复生产环境使用的原生服务端入站注册，纳入正式集合。 |
| [`b3a1f53`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b3a1f53db4d9f8e63df6147d9af81c60043f703a) | 修正文档中关于来源地址字段的错误描述。 |
| [`3d873c4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3d873c4f5b69b8164fe72e257a8f723a0ae7b884) | 脱离生产夹具断言自建站点规则形状。 |
| [`7e71d85`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7e71d858f927efab8d0a446d924b41aadbcfcd91) | 修正过时的原生服务端表述，避免文档误导。 |
| [`3a031ea`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3a031eaeb4c50e06a03ce7e0e917869c771354af) | 在 Linux 快速路径中排除四个已知失败的 Naive UoT 审计。 |
| [`4130117`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4130117ae663a3db90d9239d347eb2d4e14871bb) | 增加可选的单引擎开关，减少实例数量与开销。 |
| [`2e3807e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2e3807e06d7cedebdd8b61bc8755860572196a6a) | 对真实批量路径做基准测试，替代模拟路径。 |
| [`680f5d8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/680f5d89d1c141f07169e22afac7a935c541732b) | 调整生产接收窗口，使其匹配实际链路特征。 |
| [`6678bf3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6678bf3480de4f3a5ac502afec5e25e18c0ea53b) | 首次传输后扩大隧道缓冲区，避免小窗口限制吞吐。 |
| [`419a7e2`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/419a7e2efe627225adbf7e80dffc685d16c85b37) | 修正写入契约夹具中的缓冲区几何设置错误。 |
| [`96eafce`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/96eafce9b9f0ad5fee4c15a223c1baa7d769b465) | 从仓库根目录运行协议单元测试，避免路径相关失败。 |
| [`fc575d9`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/fc575d95943b9de59938e64ea9de600d437c382f) | 运行新增的传输与协议单元测试并纳入流水线。 |
| [`40b6d6f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/40b6d6fcc7f936faf52c6c9b92e8e09a0f20d321) | 用真实拥塞控制校验路径做测试，替代桩实现。 |
| [`55a0e54`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/55a0e54b07d4fdc90e087b20e4b512896ce30fe8) | 记录上游延迟连接握手与关闭竞态，标注待跟进。 |
| [`9654163`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/96541638c3cc5f33a22084b69d4c03119227c0bf) | 未链接协议支持时跳过默认值用例，避免误报失败。 |
| [`72eef31`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/72eef31cf50b509171b01bc301e1ae424b7469cc) | 记录实测的协议差异与分片一致性结论。 |
| [`114a3c3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/114a3c362e0a55223f6b8326d8b5716651a68c94) | 使协议配置测试满足导入分组检查要求。 |
| [`f730f6e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f730f6e50da5b41acd8add4a5cd3ad91af7f9744) | 覆盖协议双向半关闭场景，验证连接收尾正确。 |
| [`b67b3f6`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b67b3f6ae4f291890aef1ab56394f5620dc5d886) | 在运行时触达协议伪首部保护分支，补足覆盖率。 |
| [`f74d925`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f74d9254cdb0809953612c5c3c689ec6d146c988) | 将 QUIC 版本列表固定为与参考实现一致。 |
| [`8ed7051`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8ed7051c62ffb5a157b2d739311bd73523e462db) | 对照参考实现测量服务端默认值配置。 |
| [`242d8c2`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/242d8c2cbaa77ceb1d25d14584b363f7e3e3772d) | 消费零长度填充帧而非返回无进展，避免读循环空转。 |
| [`b16660e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b16660ed1887693f857bdeee11dcdd2d2afa8a57) | 移除验证器中的用户名存在性时序信号。 |
| [`65e2270`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/65e2270028729b8322747321980a6f9fd9c91ae1) | 使带填充的响应分片与参考实现行为保持一致。 |
| [`385383d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/385383dccbebe6966a6e2a30ec19e19487163672) | 真正对固定参考实现运行 HTTP/3 差异测试。 |
| [`ed30baa`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ed30baaeadff7dec160d3fd064ea060dd02bcad7) | 仅在未链接协议支持时跳过隔离用例，避免漏测。 |
| [`14da4c7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/14da4c7e080e4ebccf4c23b191f63e2d592169b9) | 说明静态协商测试的真实范围，避免结论被高估。 |
| [`d6820d0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d6820d0e7a41780bffb36087d2a2ff9b783749f8) | 在同一入站同时承载两种传输时分离协议协商设置。 |
| [`8618312`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8618312690798656992046ec10ff301389b174db) | 增加对照参考实现的协议差异测试用例。 |
| [`1f9014c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1f9014c85431f59f144cab6b70645a3dedc897ff) | 拒绝畸形的连接端口而非强制转换，避免静默取零。 |
| [`59401b4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/59401b422da22d89d2a755f5e2b6234779df5349) | 固定混合地址场景下的访问控制加固行为。 |
| [`2e49e45`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2e49e4508c1277a0a3df126c6e31460058fd2bc8) | 对照参考实现测量大包填充分片行为是否一致。 |
| [`1f05475`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1f0547577e52b020d07f336f10d1a1ebc5f1b135) | 用官方客户端前导驱动伪装路径，贴近真实流量。 |
| [`11fd30d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/11fd30d330f9efb747d0428fb3c27185fc3996e0) | 覆盖隧道双向半关闭场景，验证收尾语义一致。 |
| [`d22dd89`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d22dd89443d8ff27cbbcb6f0061d94f27c869e0e) | 将 QUIC 调优改为可选，使协议默认值与参考一致。 |
| [`497fb92`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/497fb9272c4e6024d6075052faf6a8d9c2152711) | 拆分裸部署与抗探测两种参考配置。 |
| [`aa32bdf`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/aa32bdf7814a3dd179d7404f7bd665028dc6e51d) | 使未认证代理挑战与参考实现一致。 |
| [`bc50e66`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bc50e66ea7663c309fd4fe38176ece9a9797b0d1) | 在两种协议上传导刷新失败，避免数据静默丢弃。 |
| [`2fbab5b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2fbab5b96f47fc1e42e40e31c61f00b7f0254955) | 凭据比较改用常量时间实现，消除时序侧信道。 |
| [`f45e465`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f45e465b83962add246b0783316bccd783ad38e0) | 将 Naive 自建站点流量路由到隔离的本地入口。 |
| [`318dbee`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/318dbee27d176a348adb67b031dfde6a1bdbc157) | 使差异测试结论与产物无歧义，便于复核判定。 |
| [`086aba2`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/086aba2a45fcd36a3f9d7a711200f988bc2b7fd2) | 对填充编解码与连接授权字段做模糊测试。 |
| [`d921493`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d9214933826825916dfbe2ff20dbacb6dd0114ff) | 恢复有界的 QUIC 流默认值，避免资源无上限占用。 |
| [`0245def`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0245deff82209c9e590cb1af93b4a3dd17338439) | 检查连接响应刷新，确保握手应答及时发出。 |
| [`4ed6dff`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4ed6dff200808d50900bfbaa55cdb4db3a35096b) | 真正运行协议集成测试，而非直接跳过。 |
| [`d480202`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d48020282973c8cfbfd55035911d7591be0583c3) | 测量协议流上限并标注剩余的差异项。 |
| [`9885c45`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9885c45cf69c5b327f448a5d1a710a213edb6056) | 增加对照参考实现的真实 HTTP/2 差异探测。 |
| [`1be7647`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1be7647977b61e198de268baefc8dcb57b036fee) | 在运行时验证两种传输的协商隔离是否生效。 |
| [`ece998f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ece998f21f3018de84593d1a65ceb504f7eebab1) | 以字节比较确定 H1 隧道 framing 并移除一处伪差异。 |
| [`ade5f46`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ade5f465c6ee92d497664691dc7155817f3961c1) | 使用规范的 QUIC 缺失错误并扩大边界覆盖。 |
| [`34628b6`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/34628b6daf9ca15d6336fba69da7b723dbc3a190) | 覆盖各种转发头形状以抵御来源伪造。 |
| [`9c6052b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9c6052b050655f666a12eb0678f047a58af0458b) | 原生服务端监听器拒绝早期数据，避免重放风险。 |
| [`c630c97`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c630c9775c3332e309922b4a2700342401b5fdf6) | 隔离两种传输的协商设置，避免相互污染。 |
| [`dccf709`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/dccf70987ed4673f0af7ae8f32ac170cc636223e) | 避免对协议构造函数做空指针调用导致崩溃。 |
| [`7be29e4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7be29e4ba97a0cd8dbb6676cfd8cd99b8b9f1879) | 加固协议选项边界，拒绝越界的配置值。 |
| [`1d66e93`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1d66e934f3f2824b553f60ba762de509906dd7e3) | 不再信任未经验证的转发来源头，防止来源伪造。 |
| [`b32bb58`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b32bb58f91aed02f433a2f00bba7d283067a36e2) | 使隧道分帧行为与参考实现保持一致。 |
| [`7029722`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7029722bff638e4016d3821e05199aa0a3d4e7cb) | 允许连接自身例外而不削弱目标访问控制限制。 |
| [`75a32bc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/75a32bcd7fe7d0b626376c9959529d11b0d42114) | 对固定参考实现运行差异测试，确保结果可比。 |
| [`83efc0b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/83efc0bf00e7b7aa4f910b2e190eb01783c0db71) | 对照参考实现审计协议并固定客户端依赖版本。 |
| [`cc9df81`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/cc9df81f07224600192c6f4e0766ae19f08fe65b) | 增加 Caddy 差异兼容测试工具，支撑对照验证。 |
| [`f2907e7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f2907e79a5d822abe783994ab9f3128d848f6a92) | 使连接方法边界用例与参考实现保持一致。 |
| [`e9d3293`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e9d32938065bdcf39422b6bef07eb4db08d0c8fe) | 使连接填充协商行为与参考实现保持一致，消除差异。 |
| [`fe57895`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/fe578953932b0a7d362cc4eaa5c584552ad7533e) | 恢复完整填充范围并修正缓冲区回归测试。 |
| [`3c6e0aa`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3c6e0aad37868ae1f37efa08ab46e296572f5a98) | 修复随机填充尺寸导致服务端崩溃的问题。 |
| [`d2af551`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d2af551c40c1e3f43ff77036f16618373fe8e6c0) | 覆盖隧道生命周期与 Linux 资源，并修正基准口径。 |
| [`1dc734f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1dc734f7547e8a3201e2113a25d8e80aaf686015) | 以故障注入替换跳过分支，并增加穿透与第六版覆盖。 |
| [`2ec06e4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2ec06e451f9102fc0478eee7873cb63adfd54219) | 使数据报回归测试真正在持续集成中运行。 |
| [`d1f3798`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d1f3798a63a00b16ebcb2103fc79b0deb31d77e0) | 将会话抖动验收设为严格标准，提高门槛。 |
| [`10e1f2a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/10e1f2a957946397add8bf00296c4bf06dd24846) | 使重试测试真实有效并增加确定性丢包回归。 |
| [`3bbf179`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3bbf179078df0347352c32cf2c3d57440b8a3e4e) | 为 UoT 路径加插桩，证明劫持缺陷即那 1% 丢包来源。 |
| [`593f634`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/593f634a1a22991fcc08e283f1a842ee8a9815bd) | 保留标准库在连接建立之后已读取的缓冲字节。 |
| [`b49c78c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b49c78ca56731d6315bae95b45f1be33950ddc09) | 使 CI 门禁与 Naive 服务端已进入生产的事实一致。 |
| [`0c83345`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0c83345a3f31dee52362625372310f267b95b2c4) | 审计每流认证隔离与授权字段处理是否独立。 |
| [`eace39c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/eace39c3e6bce10c612beb40b6fac22f007cd076) | 增加确定性的填充编解码基准测试。 |
| [`fb90272`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/fb90272a50c7bbb0c9b19872f55f6064379840e9) | 在填充写入路径上遵守写入接口契约，避免短写。 |
| [`39833a0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/39833a0e782d8dcdd85bfe430f498ddf32b781dc) | 使审计测试满足持续集成代码检查要求。 |
| [`41bd528`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/41bd528cb277d140e115d34446c8fea446201000) | 审计伪装后端实际收到的内容是否符合预期。 |
| [`6fd7135`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6fd71352353dd1397662a940ba0a82a2b6f4fef1) | 在版本往返之外审计数据面实际行为。 |
| [`b24e294`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b24e2943003bd0f83ec935a51a70e74a7fe12150) | 审计协议协商、监听矩阵与异常生命周期三方面。 |
| [`23af897`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/23af897bfd431af8f8da4915657deb5a62710ffb) | 不再接受非标准的授权头，收敛协议面。 |
| [`4085c08`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4085c086dca72b488d791e421247edc0ce9db8ed) | 审计协议并发、填充边界与目标控制三方面行为。 |
| [`d0087e8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d0087e877e7b6b5543ed18837705d4674dae685b) | 独立覆盖异常路径，避免与正常路径混合测试。 |
| [`ce0496a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ce0496a311791dee5507e339b811dc029b00ec13) | 在生产精简注册表构建上做最终验收验证。 |
| [`c0ba174`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c0ba1749125a4ebd6a5d40d4263a69d4cacfc87a) | 完成套接字验收，并为真实丢包发现划定边界。 |
| [`58985a3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/58985a375992d8ebc85c8dc1136b35463aec50fa) | 验证与官方 NaiveProxy 客户端的真实客户端兼容性。 |
| [`05e24b4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/05e24b42c4f4a85d89613eb88137ce8cda64ad6e) | 以记录目标而非状态码来衡量未授权 CONNECT。 |
| [`7c0267f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7c0267f2cc0f37be02a6be1ac945ba44bb7f1b1c) | 记录原生服务端、数据报与伪装能力的当前状态。 |
| [`776ac9e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/776ac9e9602e033c5cba24d4c6548f5f19ff10bc) | 固定填充帧编解码实现并加入测试保护。 |
| [`7760729`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/77607290f598f4ee2bdf7f22a65d9fed47e04a24) | 使服务端边界可配置，替代硬编码的限制值。 |
| [`8f63bad`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8f63badd0c2fefb1454cde1d51801dedc53af8ef) | 在精简生产 registry 下干净跳过不适用用例。 |
| [`568e93f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/568e93f140ec9522088977219b2a42e93629532d) | 覆盖 Web 伪装并断言真实安全属性，而非表面行为。 |
| [`c3de03a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c3de03ad48bb287fdcba9f1e5a22a3e250e48598) | 验证已结束的会话会释放其占用的资源。 |
| [`bbcabc9`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bbcabc9a2e1818c309c48fb14aa70e179fd299ac) | 验证 UoT v1 与 v2 端到端可用，覆盖两条版本路径。 |
| [`45f6686`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/45f6686a61ab5535235c817133917246573a82c7) | 增加可选填充、网页伪装与合法的连接请求路径支持。 |
