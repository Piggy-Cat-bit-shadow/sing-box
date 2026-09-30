# Other

[当前工程决策](../ENGINEERING-NOTES.md)

| Commit | 工作 |
| --- | --- |
| [`e42cd00`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e42cd00e9cf9434a2d18fcb27c8e67d825da6c75) | 将测试模块使用的 protobuf 标为直接依赖。 |
| [`1d1e399`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1d1e399b321fced101325678c4e3a20e5d156f7b) | 更新构建文档，说明 Clash API 与 Native API 并存及官方标签。 |
| [`332e201`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/332e20194636df4ea0f33c85d01c4d2d6bfe509e) | 在 CI 中验证 Clash API 能力及其与 Native API 的共存行为。 |
| [`76cd68e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/76cd68eaf0b2183856185e2d91583910e4631bc2) | 在官方构建标签中恢复 with_clash_api，使发布构件包含 Clash API。 |
| [`9683953`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/968395304d407821758c7b005b942ed0e6f70a19) | 恢复上游 Clash API，并与 Native API 共用实例状态。 |
| [`d339792`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d339792e41719b6e922f4b81809e996b221cd384) | 从 README 移除重复的完整功能集段落，保留协议索引。 |
| [`8d575c6`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8d575c6c47fe08f41ea2bf6cd82dba69562a7ef1) | 清理 CI、构建脚本和测试中残留的产品注册表裁剪假设。 |
| [`8b6d4e8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8b6d4e8c418e1a3674fcbb1b12a90bf3db6ae8ba) | 修正完整能力验证步骤的 Shell 引号与 Tailscale 包路径。 |
| [`4c39a83`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4c39a835b5560b5f7e1d1f8e6256755bf7a49141) | 将旧 Pruning 架构标为历史，并更新完整注册表的说明与测试。 |
| [`dcd8b10`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/dcd8b10cda0771954a46db83eed384b25ce889d4) | 以完整能力验证取代精简注册表的缺失能力审计。 |
| [`523db47`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/523db47e4fb82e3a82226cc2dd3269abc56d6617) | 移除本 fork 的命令编译裁剪条件，恢复上游完整 CLI。 |
| [`3bab501`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3bab501db725bb4dd24ae4fae5c520d9ef20c437) | 移除产品专用注册表与构建标签白名单，恢复上游完整注册表。 |
| [`2ec210f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2ec210f70f3ae2252c40af27eaaa6a5a8e768a8e) | 合并上游 testing，并处理与 fork 协议和测试改动的差异。 |
| [`c7c5f1c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c7c5f1c03d6a2f1a4bd7546f29a0a000461e32ee) | 在 V2Ray QUIC 中把无状态重置与版本协商失败识别为真实故障。 |
| [`d76e4d1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d76e4d1d63f646ce845b13c1bd4cc1d0a5c77a98) | 改写 README 分类简介，补充当时的产品能力与协议优化概览。 |
| [`7eab0bb`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7eab0bb97ea4ff3bdf5103ac32bd65532d32c3f9) | 按错误类型区分 MASQUE 隧道与 V2Ray QUIC 接受循环的正常结束和故障。 |
| [`d267546`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d26754689839fbd3b91183701167a6491042d4c7) | 补齐 HTTP/3 服务端与 Native Naive 的连接级故障分类和日志。 |
| [`af86de2`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/af86de2c62cdf8cbfc8e0dcd6107347696442564) | 在 HTTP/3 客户端隧道边界保留真实 QUIC 故障，避免被当作正常关闭。 |
| [`98028f7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/98028f7b6e6dd1341780a360abe99ab95f588689) | 将 QUIC 无状态重置和版本协商失败识别为 HTTP/3 故障。 |
| [`a6fcdf9`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a6fcdf95dacc8d87020595bf9c55de65eb0847bd) | 将 README 各分类简介扩写为三至四行，并加入显式换行。 |
| [`1f0cca5`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1f0cca55cd5bb944f8200c1d0132d56ba96fd34d) | 恢复协议优先的 README 首页，并将提交索引移入 docs/commits。 |
| [`02269b6`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/02269b6ef3f1e2e8e124079302d23b3329c64892) | 把 README 恢复为简洁中文布局，重排当时的文档入口。 |
| [`a19f5cb`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a19f5cb24de37945ffdb8c0db5103aec9bd74983) | 整合长期协议文档，删除重复专题文档并更新 Naive 注释引用。 |
| [`ad3c38b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ad3c38b2a3271fbe40f030fb3a99120f979329cb) | 测试 HTTP/3 连接合并、迁移容忍、启动竞态和重试边界。 |
| [`a14ac8d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a14ac8d14c847019ec595c7f184d372960b4cbe2) | 为 HTTP/3 连接增加生命周期代际和缓存决策追踪。 |
| [`83210ce`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/83210cef3dbd61cbdd93d0d67b297b60ec6ab04a) | 先识别 quic-go 的具体错误类型，再处理通用连接关闭错误。 |
| [`ce4170e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ce4170ed8816da067543dd13caa6c4428f2986b9) | 校准文档中的 H3、BBR 与 Native Naive 描述，移除过时文档。 |
| [`841ae59`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/841ae59fcc0e8ca028b41427563efcd82a17dca2) | 测试过期 HTTP/3 连接的驱逐及替换连接之间的隔离。 |
| [`e323a9c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e323a9ce7646ed1b3a55ec70ba755655987da8b9) | 区分 HTTP/3 请求取消与连接失败，避免错误分类混淆两者。 |
| [`ca330b8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ca330b831df2efa21ae7e632d3f1641c1dd8e61c) | 将历史审计与性能结论汇入工程笔记，清理旧文档引用。 |
| [`942d19d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/942d19d243a7a06b81f604e555b866a42abfb494) | 修正模块完整性检查中 `--require-checked` 的判定：已发现但被排除的模块不能算作已检查。 |
| [`947aaa3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/947aaa34041cf94444d1c3e65aa1bd526e32667f) | 将 Go 模块缓存校验接入 Linux 深度检查，并清除过时的“仅深度检查”标记。 |
| [`bfa4755`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bfa47557548121141a119ea884d6830740a59c7a) | 修正 Go 模块检查把依赖下载日志误判为文件变更的问题。 |
| [`ebeda69`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ebeda694b7a258952803918b232e44c10e4f7718) | 加强 SOCKS4 与 Shadowsocks 的回归测试，去除只打印结果却不检查结果的测试。 |
| [`d2ad14d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d2ad14d35da64f6421ba3f0eab3b1faf5bc99ab8) | 在 CI 中检查根模块与嵌套 Go 模块的依赖一致性，提前发现版本和校验和漂移。 |
| [`f240a30`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f240a30d0b2121db0d3c7dfa3e7975ee5c3d089e) | 补齐 test module 的 go.sum，避免独立测试模块无法解析依赖。 |
| [`813905c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/813905c6fba4cc2670f701ba8e514f8002f1f803) | 锁定包含缓存缓冲区移交保护的 sing 依赖版本。 |
| [`dfc7948`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/dfc79488a01d0eb33304793f1e57be57c5005cbf) | 使本地特性适配合并后的上游代码树。 |
| [`1bcb748`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1bcb748a6907b8a0379707a896a15be546de6347) | 修正写入失败时缓存缓冲区的所有权判断。 |
| [`1ba1efb`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1ba1efb97d11cdcaa4460ac934a9be9637413559) | 为批量提交的依赖刷新测试模块校验和文件。 |
| [`4f0b66a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4f0b66aa55797103d87231b8bf9ca66ecef2a38d) | 记录 CI 结果与不稳定测试的处理经验。 |
| [`c9ff7c1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c9ff7c188847fe7164b3dd459d1e57ab0c286c02) | 测试缓存数据是否进入写入方持有的缓冲区。 |
| [`85151e1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/85151e1051c7223dad3680ada0a4cd4c24fb5165) | 锁定提供 WriteOwnedBuffer 接口的 sing 依赖版本。 |
| [`628bea3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/628bea3c5fc14040350b91c157c8423fa1bdf9aa) | 将尺寸匹配的缓存缓冲区直接交给写入方，避免额外拷贝。 |
| [`893829a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/893829a9f93d79efaabb1593879c4c1e632934d7) | 在测试模块中同样固定打过补丁的依赖版本。 |
| [`bcad6b4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bcad6b4d6eb5c7f0cd4334fee07e6345d66f0a7c) | 忽略编译产生的 Go 测试二进制，避免误提交。 |
| [`9e7c859`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9e7c8595575f21f9117c661929a244b362220c8d) | 移除上一提交遗留的测试二进制文件。 |
| [`5194979`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/51949799e1172eafe686956d6a45e1f8e51b7008) | 对真实服务端验证隧道传输上报是否准确。 |
| [`f2528e2`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f2528e22995a4c757aec1166af295cb40b388ca2) | 放宽容易因运行波动而失败的下界检查。 |
| [`0b94490`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0b94490be6bba4c16e41d42531dbc2302a23a5b9) | 为已取消请求的流数量设定上界，防止无界增长。 |
| [`e0279cb`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e0279cbe4d7cc52ec12173986f11dfabb382abfe) | 改为检查流数量，避免依赖不稳定的 goroutine 数量。 |
| [`5c36b93`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5c36b9339dd7aa0c2ba48fe17856746d05be34aa) | 为通用 HTTP/3 请求路径增加资源泄漏测试。 |
| [`96b6595`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/96b65952743d96dd3a16174bff4e7feb6e7ec5a2) | 在同一连接上发起通用 HTTP/3 请求以验证复用。 |
| [`2dbed1c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2dbed1cc844695a517997a2160c9eb7b2540749a) | 检查新移除的协议确实未链接，同时确认规则集仍可使用。 |
| [`0a48110`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0a48110a62abd46c6e26ac820955408c87a60fd4) | 将命令行精简为运行时必需部分，去除调试命令。 |
| [`f991e52`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f991e528f6912036f6f21cc31337a54e168f24a9) | 使测试夹具与审计描述真实产品形态而非示意结构。 |
| [`7fc3a90`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7fc3a9093836a297be2529ba63e06bda2d450c4f) | 记录仅保留原生面板的架构决策与范围边界。 |
| [`62af666`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/62af666c3b445418943fd37e26738e92164ab541) | 同时检查生产注册表是否多注册或漏注册协议。 |
| [`24f0be1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/24f0be15830bc49cd1494d24159fc552f5262ccc) | 将原生接口设为唯一控制面入口，排除其他通路。 |
| [`bdcb054`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bdcb054316227fc7b908166e39d5f85927f6428d) | 让客户端注册表只包含生产环境允许的协议。 |
| [`655adfc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/655adfcf860fc71a054cd3c0d15aa118f49bda37) | 合并后规范化依赖校验和文件，消除多余条目。 |
| [`59f8d31`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/59f8d3173f6563fc72834ebe665e42f7ea4aa077) | 校准测试模块的依赖关系，消除版本漂移。 |
| [`bdc5804`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bdc580410d5bfbb4d647ecc5c06de6d8609fc530) | 使上游新增平台引擎测试适配本分支的类型定义。 |
| [`2fa4838`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2fa483848202a9de07b24af671059a9bbb45b505) | 按项目规范整理守护进程的导入分组顺序。 |
| [`1bc7aa1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1bc7aa1fa55906bec82f0e022c2cbfbba2725b2d) | 基准测试千节点规模下的分组快照查询性能。 |
| [`94d853a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/94d853a9e0026b084a82e1c547599d7e752d05c1) | 记录守护进程接口契约与持续集成的保护范围。 |
| [`92baaee`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/92baaee9d1284e75c508b57d3ac68237faa3ee93) | 在真实二进制上冒烟测试命令接口是否可用。 |
| [`0ec3a3e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0ec3a3e7f348ec57a4befff7aaf1c7a5de40dfeb) | 覆盖重载、停止与并发测试三类控制面操作。 |
| [`302e468`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/302e4684c00873fdc5339c60452e9c8e16ae4933) | 验证地址测试遵守调用方传入的上下文取消信号。 |
| [`e50ba42`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e50ba420ed42b213a4d5876b4a498a70d71f019b) | 在持续集成中固定启动器接口契约，防止回归。 |
| [`88ac203`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/88ac203c7fd1ca13cb50d8526856c481419f4e75) | 启用守护进程命令接口能力，开放控制面通路。 |
| [`d3c6afd`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d3c6afd171fde6455067c8af62e4f722b5c5c9b8) | 实现一元分组与出站快照两类查询接口。 |
| [`a02cd38`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a02cd386cbed7a13ccbda2471a92776cb933633b) | 增加启动器命令接口契约定义，约束控制面调用方式。 |
| [`d695a84`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d695a848acb7ad008293a8016a19d923cd810a89) | 将负窗口测试放到能够实际观察该问题的位置。 |
| [`747ca9e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/747ca9e3d72ddb364a4f79b5d42ae6f21ed9bc09) | 使快速与深度运行不再互相取消，避免误中断。 |
| [`7756ee5`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7756ee51443e75f263f1a94d69f7ee6ab00e49a6) | 对带后缀的开发版本不再 panic，改为正常降级。 |
| [`d6df172`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d6df1723137df1eea0126a703b08481c85a0eec7) | 使新增契约包通过 gofmt 并被格式检查覆盖。 |
| [`8981999`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/89819993c9a48722379e27a2e2a17af4efe15e7b) | 精简产品校验流程，去除冗余检查步骤。 |
| [`0a3993a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0a3993a8c051ea3370627b8ea7742d1201a200dd) | 移除 QUICHE 实时互操作测试，缩短 CI 运行时间。 |
| [`df31ff9`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/df31ff95096fb8b47ce157ec3781da9d98785bf8) | 上游同步后修复测试模块的依赖与校验和。 |
| [`486b7e8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/486b7e8e17dfa327719e3774930ad079a2829bae) | 将守护进程支持移植进入 macOS 客户端核心。 |
| [`7d4ed8f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7d4ed8f9e83e247339be667810551e31fd1f8ab2) | 按设计方式运行实时互操作测试，修正执行方式。 |
| [`e490611`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e490611d7034aebf90824e5dbed3ec6d098e86c3) | 为 QUICHE 互操作提供其真正需要的二进制。 |
| [`9b1d046`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9b1d046e0525314642fa5949a3a956564a88db4b) | 在各自模块中运行 QUICHE 互操作，避免路径串扰。 |
| [`302ea66`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/302ea6615d20c5085155860b4b2b1db78f2ebada) | 为深度路径留出完成时间，而非 45 分钟中止。 |
| [`f692b15`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f692b152ca923deb0e84b81f6ebd6430530a753f) | 从已知不兼容的包中解冻上游默认深度检查。 |
| [`4a31757`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4a3175710dbec6b5ceefb159b7bda2bb7888d557) | 出现已知 jiejie 失败时保持深度检查继续运行。 |
| [`d738f6c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d738f6c73860ce81e6e4e073e910b9cdd62a05fb) | 使 Linux 快速路径构建内核而非运行协议实验。 |
| [`e352830`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e35283074ca6fb4a79b38dfba0b358b534c191af) | 精确说明可复现性保证的范围与前提。 |
| [`18abc22`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/18abc22b1710840a50c91b02306049553a303ff2) | 使 Linux 冒烟测试使用真实 inbound 且不依赖管理 API。 |
| [`c4a37cd`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c4a37cd19e2bfe107ee083a8a3577ccf3f4fb154) | 提供传输层材料以便校验生产拓扑配置。 |
| [`eaf37d6`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/eaf37d6bedc0d9e493798da4526b872322e17a6a) | 校验真实生产拓扑而非上游示例配置。 |
| [`c3c6549`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c3c654978bb2e1865d6a0e37d68f88afb5697555) | 在唯一构建入口脚本中注入版本信息。 |
| [`97b03db`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/97b03dbb3bd1a92f63c467f2d1b09c1bcc4f1868) | 围绕两个产品、两个 workflow、各自一次构建重建流水线。 |
| [`92b10b4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/92b10b4c5a2b2b697bc4d142658d2d91cb2194f5) | 修正审计二进制路径并清理 lint 失败项。 |
| [`90903bf`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/90903bf9cf66dff2e36bb07475d0109fb71f782e) | 从同一提交构建并校验三个发布配置的构件。 |
| [`49579cf`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/49579cf32ff670ed5965c98e94bd88ed098c4bb1) | 将无头模式记录为推荐的 macOS 使用方式。 |
| [`e9257ab`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e9257ab9a15b01914e6286c9e76650a73dfac1da) | 增加无头控制面冒烟测试，覆盖该使用方式。 |
| [`0beecd1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0beecd1d62ee9407c66257f6e4f330dd9e17f83f) | 增加无头运行脚本与按用户启动的 launchd 服务。 |
| [`5648220`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/564822086939bea7b9441407a30c7ebe3fe19c29) | 注册原生接口服务，使网页控制台可以正常访问。 |
| [`87f80e6`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/87f80e6c4b2edcd894547b38c6f50ba5041cf7a9) | 在构建信息文件中记录实际生效的依赖模块版本。 |
| [`3e6e342`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3e6e3423929ef718026635b264fe8169751b59a4) | 记录 macOS 客户端版本的定位、能力范围与使用方式。 |
| [`ea1e57c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ea1e57c3915d798c668fdbfcf419379889053091) | 增加客户端构件发布工作流，自动产出与上传。 |
| [`cbbb442`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/cbbb442a0bdec5eb7e215c09a28f3dfdf82f80cb) | 增加客户端注册表、配置与运行时覆盖。 |
| [`5af8597`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5af859762b56aea6019c4596e5156b9724367378) | 增加精简客户端注册表与对应构建配置。 |
| [`3878204`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/38782043933688db1b340ea5d765846089fcdb0c) | 移除仅开发用的依赖替换并清理静态检查失败。 |
| [`7c07e05`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7c07e056ef35904c97edb7c28e9bed0022378b6e) | 正确执行参考测试的覆盖排除规则。 |
| [`953e0a7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/953e0a729a91ce26b166cb8dd7ca71c1f14a4560) | 固定依赖中报文超时批量修复对应的版本。 |
| [`3e90961`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3e9096146b5a85c98ee7eb8ee9280a4523f583e1) | 固定标准客户端乐观规则相关实现版本。 |
| [`9dc576f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9dc576f7a4946338ec76e8434b3115d9ee81e266) | 修复格式检查路径列表与不稳定的 H3 差异测试。 |
| [`82135b0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/82135b0a4f3bee6838f9f75cf787d9a60091abad) | 防止注册表审计使用错误的构建标签组合。 |
| [`97e1487`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/97e1487782bf3723d84901877a6d8904216597ca) | 连接被拒时关闭底层连接，避免连接悬挂。 |
| [`1bea880`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1bea880f6434c8bfe6a24bd2bfee3be2a0fcf82d) | 在共享传输配置上隔离两种协议的协商设置。 |
| [`dfc8912`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/dfc8912a23f4f4eafaac182aefe489dddee03c2a) | 使头部限制测试不再因预期的流关闭而失败。 |
| [`9a553a7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9a553a7ffb70625e943aa05aff28cc7b3ca829cd) | 测试不同 ALPN 视图共享状态的生命周期和所有权。 |
| [`10191b1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/10191b11c744217f0db20ae894c78dd0d52398fd) | 为共享服务端配置增加传输范围的 ALPN 视图。 |
| [`f62c51e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f62c51eae04f4947b40bf52d617599dfa4ee6c35) | 修复自建连接例外判断中的竞态问题。 |
| [`5c54405`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5c5440577d05af869db9cdc945b4adaf8af9ab0d) | 按当时的证据修正协议审计结论。 |
| [`7e9fd93`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7e9fd93f36bf383e816ab579e50fef2d8cae8ac8) | 合并重复的自建站点实例构造函数。 |
| [`0b27085`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0b27085f6a50cec0226c6702a438ae678f11890c) | 对照生产拓扑审计生产注册表的注册项。 |
| [`7a5212d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7a5212d8b75507059829ba3fbd3f980bd34cecd2) | 修正从未被真正执行的协商回退语义。 |
| [`2fb3ba6`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2fb3ba693097b36fae17d0b5d66cb1073d095cd8) | 校验服务端资源选项边界，拒绝越界配置。 |
| [`1804358`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1804358ab26e77457801bd0c3b69f35820c38481) | 在日志分类中保留服务端故障的可见性。 |
| [`a3cb8ab`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a3cb8abf587cb8b61e4b380ae73c0161104dc082) | 不再信任未经验证的转发来源头，防止来源伪造。 |
| [`9cce35e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9cce35ec3be3c6e1641fcb739af5e912516c2b21) | 真正运行 HTTP/2 差异测试，而非仅保留用例。 |
| [`142df6d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/142df6d2db47d88feb46a8248b4dd3bacbe17690) | 对路由包运行竞态检测，排查并发访问问题。 |
| [`f875e03`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f875e03066948b318a08e81b48ac1b7a5349c8fa) | 首次读取竞态测试改用新版等待组写法。 |
| [`39d84e3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/39d84e379754a2149d565c6464dfdc16bd791ca4) | 将 Jiejie Server Edition 版本号提升到本轮发布线，准备出包。 |
| [`5ef8003`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5ef800316b32d2d9a7f2ff8c90f67c312f166ce7) | 审计并固定协商行为而非凭猜测设定。 |
| [`78ec35b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/78ec35b35c6e66573fb1a673de64f6f1786da8dc) | 使扩展连接测试不依赖特定工具链版本。 |
| [`93fa270`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/93fa2708cb45dddaaac27a5a95f73f1d90860318) | 按类型而非字符串分类认证前探测失败。 |
| [`8764f6e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8764f6ec6170f678ad88bcce1c9ca3b89b56a891) | 记录服务端抗探测边界，明确防护范围。 |
| [`20ce0a0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/20ce0a05ad2639c314f0a367b6de2cb13f4a39d3) | 锁定隧道协议第三版的探测回退行为，防止回归。 |
| [`cd8d702`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/cd8d702122b9968aad247a7cd22de62d280180ab) | 验证请求头限制确实被强制执行并生效。 |
| [`f30f63e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f30f63e0d6eaf8f7d50558ff192d1a0f67c4b791) | 限制 TLS 之后首次应用层读取的大小，防止越界读取。 |
| [`127ae9c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/127ae9c3b973f796084af2903e8da1bfb60a7834) | 使未认证请求的释放按每次获取幂等。 |
| [`27cd75a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/27cd75af451f25c877a0fd7f9bbd265e2f4b3fed) | 执行 HTTP/3 应用层空闲超时，及时回收连接。 |
| [`1e7093c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1e7093c83590941193cae73e8644dd467791972f) | 为仅支持第三版的测试打上特性标记，避免误跑。 |
| [`2da0411`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2da041135c946fce2328a705bd932550d687daf7) | 让上游同步分支运行各项门禁检查。 |
| [`b1814cd`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b1814cd66028e032e780cbb11459fecfe1d920f9) | 验证回退选项在运行时确实按协议协商结果分流。 |
| [`e25753d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e25753db75605c5891f600248796b797cab497cd) | 让清理分支运行各项门禁检查，确保可合并。 |
| [`c45d498`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c45d4987f1785bd4849c044101493b162a7b0f21) | 按切片而非符号链接求和测量库体积。 |
| [`83f5c4b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/83f5c4b280b5b3dca065957d41d8ac1ad563a0d3) | 在构建阶段之间复制而非移动 framework，避免丢失。 |
| [`4cabf7e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4cabf7e5a342b34fcd7f8405dfb6aa8e51c74613) | 单独提取设备切片，因为打包工具无法构建单一切片。 |
| [`a1f0d46`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a1f0d464d39c52089dd2f554259c0ed8974221bc) | 使仅设备构建真正仅含设备，并修正体积读数。 |
| [`172c84e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/172c84e12b3f1a6409453ec74e14a8de52050c6f) | 将精简配置与默认平台标签集对比验证差异。 |
| [`5aa9174`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5aa91743599e5aa97b3a91f0032cab52f7e92811) | 修复首次快速运行暴露的两处 lint 问题。 |
| [`50d4437`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/50d44376f9f1726d599438214ad23de5d81e8449) | 代理入站禁用早期数据，降低重放攻击风险。 |
| [`4b3851d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4b3851d572acb5883b34d0e3881cb8fad754016e) | 发布服务端二进制与独立的完整客户端构件。 |
| [`8be7509`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8be750978bb2e3e0dade4d360ba56579e6fd1a1c) | 发布使用精简配置并对其构件体积设门禁。 |
| [`391c3e7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/391c3e77cfa5c187a6f18a71c50599c4e7ac0103) | 增加可选的 iOS 精简构建配置，用于缩减移动端体积。 |
| [`d0d44d3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d0d44d3f296022281ffe75a091835065c44dd460) | 不再把连接池策略字段表述为调度器，纠正文档说法。 |
| [`4505a04`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4505a043288e87754a9b9fec2b6e4aca5cd277f7) | 移除过时的分支过滤并修正文档漂移。 |
| [`50b1a26`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/50b1a26711f7fbcfcf90f1c2f0997a27a240d741) | UDP 黑洞耗尽连接池时回退到 HTTP/2，保证可用性。 |
| [`1511c1c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1511c1c6a1f18e5a035166a34d7f1759db36c7b5) | 移除连接池槽位平局判定中的索引偏向。 |
| [`a4a5576`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a4a557622964e5d1ceb73f316f479d16c6ddb8a6) | 限制授权映射规模并停止全表限流扫描。 |
| [`1508586`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/150858640ee7be30d54acf5cc6f731dffd9aac97) | 修正被反转的规避状态机逻辑，恢复正确行为。 |
| [`36e8f1c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/36e8f1c1caa08ef783acb1753ccfa5fc70c44cef) | 产出用于本地设备重签名的安装包构件。 |
| [`aceab69`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/aceab69e319b4011805c7af9bf8fc446813790de) | 按平台目录而非工程名称发现应用包，提升健壮性。 |
| [`6535575`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6535575387897fa4f2a4b8df2b5ee1317f6c7d5c) | 增加仅设备精简构建、未签名 IPA 与体积报告。 |
| [`186ef8c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/186ef8cd042f505963adc3966896c4140f7aa01d) | 不再将已解析的依赖锁定文件视为源码改动。 |
| [`60bc790`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/60bc7901dc4f7ae74bd51c3edb4c698183ecb810) | 将平台依赖固定到最早与核心兼容的提交，避免冲突。 |
| [`dc35376`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/dc353761ec567c1de7b2ab7843b16b2c8bfa6597) | 以二进制安全方式检测特性标记并加入断言。 |
| [`8c24461`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8c24461261b3ccd7ff46c94e0a8094fde2b6bd7c) | 不使用 xargs 计算构件哈希，避免参数截断。 |
| [`100c6fd`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/100c6fd6c5fa5bf2bf4e69987ec9dfb85e4ecf40) | 审计隧道实现代码而非文档中的字样。 |
| [`f28fec6`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f28fec6b979686890b00b4c45c51a18180c66cf4) | 增加最小库构建流水线，覆盖该构建形态。 |
| [`ea60f57`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ea60f57540587cc6a2a0bef913e9adf596b25d38) | 在工具链报告之前安装 Go，修正步骤顺序。 |
| [`02f85a2`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/02f85a206036aaacc11db11c8c199571c1615270) | 构建最小库与未签名安装包构件，用于流水线验证。 |
| [`ab1dc45`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ab1dc4516cc81bb4e7b7cd040a1bd0fc49047ad9) | 通过库接口验证客户端协议选项的传递与生效。 |
| [`d5c6b7a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d5c6b7aec31304baeb1c8ea0874ffa54956154ce) | 使完整客户端配置可在发布流水线之外构建。 |
| [`7179495`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7179495e9f74bab15226f80f0aa97f43298e875d) | 增加完整客户端标签组合，覆盖全部功能集。 |
| [`bd9e1ca`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bd9e1ca0a174d8ae52fd42875efbdfcaf3239b87) | 允许集成分支触发 Linux 平台工作流，便于验证。 |
| [`d71841f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d71841fc6e2c4c6337e691736782170983c4de8a) | 增加带并发、缓存与构建门禁的快速 workflow。 |
| [`b213717`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b21371720a203ad3dfecb807381bb3ace7a8df06) | 增加版本、构建信息、构建与打包四类脚本。 |
| [`0e2d6d7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0e2d6d7fd105991c763d1ff5dc737f76e7a7e6cd) | 增加 Windows full-client 构建标签组合，覆盖该平台完整功能集。 |
| [`9080476`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9080476767b6124c4445b505019405613a551bb0) | 修复连接池与探测工作引入的 CI lint 问题。 |
| [`5fc2559`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5fc255981ccd1acf4a80009ef7788c8672f6165a) | 移除退避测试中重复的窗口计时函数定义。 |
| [`583b484`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/583b484896dbfd1c4223b618a8d444db8f80cd98) | 将窗口计时函数移出测试文件以修复非协议构建。 |
| [`4958f8c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4958f8c78a40b08683c20ac1a55129d68fc41c81) | 对照实测的依赖默认值固定服务端配置。 |
| [`e0cd84f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e0cd84f66ec4e443b2646cc7aba287148ff2f6b0) | authority 恢复探测改为单飞，并固定槽位与 authority 分离。 |
| [`bfccf7b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bfccf7b1b4b76638d4ab8a0c372d35e5b6024c54) | 覆盖真实 GOAWAY 排空、槽位替换与活跃计数。 |
| [`d43b9bf`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d43b9bf6a7ff1912b7a9c98d95b729c7d601df5e) | 选择健康且活跃最少的连接池槽位，并支持 GOAWAY 排空。 |
| [`c3e105e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c3e105e1f9a18ade5fd236298671c73603b24495) | 修正限流测试中的导入分组顺序问题。 |
| [`cce49f3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/cce49f387732af8379b5c7d0b73173a2574dd6b2) | 通过基准测试测量限流器的过期处理开销。 |
| [`747c62d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/747c62d263ee59bb77efe0f55589144a70bca3fb) | 验证未认证请求体上限在数据路径上生效。 |
| [`0eccef3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0eccef3c40971458ddacca93143adaa2994519b4) | 在返回 404 之前先做认证，避免泄露路径存在性。 |
| [`778b590`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/778b590231b49bb747f48c6414f156b19b43c105) | 覆盖连接被中断后的连接池恢复行为。 |
| [`20fcde8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/20fcde885401d54d786dccaa154c3937ea1f15a2) | 修正 profile 存在性语义、重放保护、限流顺序与测试隔离。 |
| [`80ad6df`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/80ad6df293223f9c7c0b0fa6ae5327e9fb5b7aad) | 在连接边界规范化零错误码的 H3 关闭。 |
| [`f5f2640`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f5f26405245ea357cb49eb01af8c47b50aaa3139) | 修正 profile 边界、退避生命周期与 H3 关闭日志。 |
| [`2e44b79`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2e44b79763d41c18284716a2800a4d4ca6963acb) | 避免与既有端口保留辅助函数重名，消除冲突。 |
| [`7e57fe8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7e57fe8c77d1e203ba25fb8858219fc9f75915d7) | 阻止超限请求抵达伪装后端，提前拦截。 |
| [`9771af9`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9771af9f493018f8caddfd86ef672bc47a29d0b0) | 使服务端资源与头部限制配置项真正生效，不再被静默忽略。 |
| [`6435a26`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6435a26be740d711ada3920031888943e3f7593f) | 在夹具期望的位置生成证书，修正路径偏差。 |
| [`3b34c98`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3b34c98cb425c6e1bc7460f9f03cdd37993a2531) | 将生产参考审计固定为独立文件，便于复用。 |
| [`61c05bb`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/61c05bb63d5ad9b4e761a513a64378af1c09cdb1) | 发布流程只测试并产出精简版程序。 |
| [`918c152`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/918c1521d8b211307460270c22a65db130f522d2) | 增加生产运行时集成覆盖，验证实际运行行为。 |
| [`d8a3c8c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d8a3c8c222848aacdc9c8559513d87d903598f08) | 使夹具模拟真实的生产入站转发路径。 |
| [`619f39e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/619f39e2db0293a35fa916eaf65d612f6f7dc307) | 只保留精简版生产程序，移除重复的发布文件。 |
| [`98d8ef0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/98d8ef0cb3920bf1265824c519c6199567197257) | 增加最小服务端注册表的构建目标，产出对应构件。 |
| [`8dc3dda`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8dc3ddac6e8d6f31f0b80ade990d4fbbefc02493) | 修复集成与静态检查任务，恢复流水线绿色。 |
| [`3ac1964`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3ac1964ce86a4bea60b18a7128cbe677c0ef15bb) | 在解码阶段校验连接池选项，尽早拒绝非法配置。 |
| [`5c620c3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5c620c33a44dc03d1051d76b822ae97a10cb9788) | 记录服务端版本的定位、范围与发布方式。 |
| [`bb5b56a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bb5b56a4607802635ee9a2e6ba04a34c269d1ad3) | 增加服务端构建配置与实验性构件产出。 |
| [`ba99957`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ba999574d00ab1bdb8262813680a87755630bebf) | 对预期内的伪装与 H3 关闭日志做分类。 |
| [`38491df`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/38491df890b2a1602127e7e49d14e8b56d09ddbc) | 增加未认证请求的资源限制，防止资源耗尽。 |
| [`f7e51ef`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f7e51ef60ebd2f69daa8458924f732095f4db238) | 增加服务端资源限制配置与头部长度限制。 |
| [`fe66acc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/fe66acc7221d8c648a3da88ad5a818499f48da18) | 增加可配置的连接池实现，支持多种复用策略。 |
| [`f547e18`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f547e182bb9ddcb8ada71033f57eca9247b8e88a) | 增加可配置的回退退避策略，支持自定义间隔。 |
| [`e5faf95`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e5faf956b388adffb256b64002ec8980e7c75af9) | 以链接器裁剪选项产出目标平台的生产二进制。 |
| [`04278a8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/04278a8e835859302870e39aba5a8811b2875c21) | 整合生产服务端工作流，统一构建与发布流程。 |
| [`b5b6689`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b5b66895af853317223152ed00ba5431e9648c8a) | 覆盖回退选项与默认关闭行为两类场景。 |
| [`b9453c3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b9453c3b5399743e1d4aaeb20d6072f058b7ff66) | 为特性分支运行构建，便于合并前验证。 |
| [`3570205`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/35702053562c40f417794764a876bf9d09dbef53) | 将回退流量路由到已配置的后端服务处理。 |
| [`c56bf3a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c56bf3a01ee871956fc9e7812dca24d06c0e06d7) | 覆盖认证失败后的回退场景，验证行为一致。 |
| [`e97ea9c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e97ea9ce820fc1951f78350d6008c25bfafd7dbd) | 增加入站回退后端支持，在认证失败时转交其他服务。 |
| [`bc6d84e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bc6d84e1e1a1f624f8d278e8c5ebd15b901dd5d8) | 使用可移植的构建标签，避免平台相关编译失败。 |
| [`d53c867`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d53c867b7dfec24ad51a483ebc73b7a183c9950e) | 增加入站伪装处理器，支撑网页伪装路径。 |
