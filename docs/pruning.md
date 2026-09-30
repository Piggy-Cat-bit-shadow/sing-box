# Pruning

| Commit | 工作 |
| --- | --- |
| [`3cad151`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3cad15190822825e6159d2cf8845a8481f0a2a51) | 记录第三轮链接级裁剪的结果与残余符号依据。 |
| [`aa92534`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/aa9253412105ed17ab9a7fdaa19ebff026c1f6bc) | 在编译期移除产品未使用的 CLI 工具链，缩减构件体积。 |
| [`e3e5c26`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e3e5c268572a1d019854bbb65f452b282b15e4e6) | 停止链接本产品不提供的 QUIC 协议，避免携带无用实现。 |
| [`55960aa`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/55960aa1c270d55abc209dcf1bde7a51e0456cc4) | 记录精简构建、CLI 范围与 gVisor 移除的最终结果。 |
| [`141e3aa`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/141e3aada8bf0bba4a4cecdaf60b8c1d298843a4) | 断言构件已精简，并记录审计重建流程。 |
| [`9986211`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/99862113dacdbf7d987eb6357b07559a398870b7) | 审计精简后的构件，并把 gVisor 断言替换为实际依赖。 |
| [`cd7f20a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/cd7f20a9446fd8d1cdcec19481f5042127ebd7b4) | 移除已无使用者的沙箱依赖，精简平台构件。 |
| [`bb52b69`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bb52b6932df9def0f4052fca87b17bfccd78bf18) | 精简发布的 macOS 核心构件，去除调试与冗余符号。 |
| [`5007c96`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5007c968dcbb5d1dd1c319b50891e13776104991) | 移除已删除的 Clash API 在运行时冒烟测试中的残留引用。 |
| [`2655dce`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2655dcee1b8a668bf07a5ceac94fda9afe5c3c05) | 清理工具链中最后的 with_clash_api 引用，完成移除收尾。 |
| [`0e00635`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0e0063530be0d745722f605a64b5961cf2dcb1cd) | 移除 LXD 守护进程与启动器 RPC 接口，收敛控制面范围。 |
| [`bbfc315`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bbfc31582abe15bef690392d863971dff4f46f4d) | 从 fork 中整体移除 Clash API，改由原生面板提供控制面。 |
| [`d2e3588`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d2e3588a5a6bb6536da42b145a1f9594da85ba54) | 精简服务端配置将 protocol/naive 改为必需项，不再允许裁剪。 |
| [`8a7e90f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8a7e90f8e4c2e598c1d4023e5c1690fb45e26c67) | 使裁剪审计与 Native Naive 的移除保持一致，避免结论失真。 |
| [`f043f6f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f043f6f397701d72cd064812482e9250e48f2cea) | 从精简注册表与拓扑中移除原生服务端相关注册。 |
| [`f9a524d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f9a524d6d34fa5e1c152711278a5348a2f12be23) | 从客户端 workflow 触发器中移除已删除分支。 |
| [`7454a8a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7454a8add993b4e3c03e09ee275e478edc337b0e) | 移除仅服务端需要的最新协议链接，缩减客户端构件。 |
| [`bc1bf62`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bc1bf622230b27223cad4914900e7e8a6fc62432) | 从运行时配置模板中移除服务端配置字段。 |
| [`3b96156`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3b96156862214542ff96331f9018fc09e22671d9) | 移除 jiejie 服务端 profile，收敛为单一服务端形态。 |
| [`ec1e7ab`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ec1e7ab2948a4798739a29d5d5e187a9bec5a1bb) | 为生产环境注册 Native Naive inbound，纳入正式协议集合。 |
| [`2144139`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2144139e7c2447b1f9cb62f9303fc89ea8f83f69) | 从格式检查路径中移除已删除的客户端文件。 |
| [`5ce3c4d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5ce3c4d6759b3f80015928b4943b7c86cca21cf7) | 将 fork 收窄为 VPS 专用，移除 iOS 与客户端产品线。 |
| [`6cc120d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6cc120df6847c0116b91daaec61d89c262f40318) | 修正裁剪审计在 Linux 符号集上的判定，避免误报保留项。 |
| [`9d63f15`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9d63f155f2b2023e9451b1ef79ace043a20e4c29) | 移除仅测试使用的协议注册，缩减生产二进制。 |
