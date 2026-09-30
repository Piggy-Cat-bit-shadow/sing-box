# Pruning

| Commit | 工作 |
| --- | --- |
| [`3cad151`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3cad15190822825e6159d2cf8845a8481f0a2a51) | docs: record the third-round linking-level trim |
| [`aa92534`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/aa9253412105ed17ab9a7fdaa19ebff026c1f6bc) | refactor(macos): compile out the unused CLI toolchains |
| [`e3e5c26`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e3e5c268572a1d019854bbb65f452b282b15e4e6) | refactor(macos): stop linking QUIC protocols this product does not offer |
| [`55960aa`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/55960aa1c270d55abc209dcf1bde7a51e0456cc4) | docs: record the stripped build, the CLI surface, and the gVisor removal |
| [`141e3aa`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/141e3aada8bf0bba4a4cecdaf60b8c1d298843a4) | ci(macos): assert the artifact is stripped, and document the audit rebuild |
| [`9986211`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/99862113dacdbf7d987eb6357b07559a398870b7) | test(macos): audit the stripped artifact and replace the gVisor assertion |
| [`cd7f20a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/cd7f20a9446fd8d1cdcec19481f5042127ebd7b4) | perf(macos): remove the unused gVisor dependency |
| [`bb52b69`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bb52b6932df9def0f4052fca87b17bfccd78bf18) | build(macos): strip the shipped macOS core |
| [`5007c96`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5007c968dcbb5d1dd1c319b50891e13776104991) | docs(ci): drop references to the removed Clash-API runtime smoke |
| [`2655dce`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2655dcee1b8a668bf07a5ceac94fda9afe5c3c05) | chore: drop the last with_clash_api references from tooling |
| [`0e00635`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0e0063530be0d745722f605a64b5961cf2dcb1cd) | refactor(core): remove the LXD daemon and the launcher RPC surface |
| [`bbfc315`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bbfc31582abe15bef690392d863971dff4f46f4d) | refactor(core): remove the Clash API from the fork |
| [`d2e3588`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d2e3588a5a6bb6536da42b145a1f9594da85ba54) | ci(server-minimal): require protocol/naive instead of pruning it |
| [`8a7e90f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8a7e90f8e4c2e598c1d4023e5c1690fb45e26c67) | ci: align the pruning audit with the Native Naive removal |
| [`f043f6f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f043f6f397701d72cd064812482e9250e48f2cea) | fix(server): drop Native Naive from the minimal registry and topology |
| [`f9a524d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f9a524d6d34fa5e1c152711278a5348a2f12be23) | ci: drop the deleted macos-client branch from the client workflow trigger |
| [`7454a8a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7454a8add993b4e3c03e09ee275e478edc337b0e) | build(client): drop the server-only Native Naive HTTP/3 linkage |
| [`bc1bf62`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bc1bf622230b27223cad4914900e7e8a6fc62432) | fix(jiejie): drop server_profile from the runtime fixture template |
| [`3b96156`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3b96156862214542ff96331f9018fc09e22671d9) | cleanup(http): remove jiejie server profile |
| [`ec1e7ab`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ec1e7ab2948a4798739a29d5d5e187a9bec5a1bb) | feat(registry): register the Native Naive inbound for production |
| [`2144139`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2144139e7c2447b1f9cb62f9303fc89ea8f83f69) | fix(ci): drop the deleted client files from FOCUSED_GOFMT_PATHS |
| [`5ce3c4d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5ce3c4d6759b3f80015928b4943b7c86cca21cf7) | refactor!: narrow the fork to VPS-only and remove the iOS/client product lines |
| [`6cc120d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6cc120df6847c0116b91daaec61d89c262f40318) | fix(ci): correct the pruning audit for Linux symbol sets |
| [`9d63f15`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9d63f155f2b2023e9451b1ef79ace043a20e4c29) | refactor(minimal): remove test-only protocol registrations |
