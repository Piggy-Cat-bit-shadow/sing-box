# DNS

| Commit | 工作 |
| --- | --- |
| [`d676b4a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d676b4a626bdd7cedb759394ace40da0e1b0059f) | fix(dialer,socks): derive the SOCKS4 target resolver from DialerOptions |
| [`9260e8a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9260e8a95c2b07ecea0a3ad6e64b47adb95025ed) | docs: record the all-protocol dataplane and DNS audit |
| [`977f530`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/977f53031f6800ad08d002e090b6bc83a9f47615) | docs(wireguard): state the two DNS authorities rather than leaving them implied |
| [`43ffa93`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/43ffa9334082f87ff866da3536042dab9a1262e4) | fix(socks): resolve a SOCKS4 target with the outbound's own resolver |
| [`1a529bc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1a529bccdf2aa44679057efbb6f65b3bfe9721ce) | fix(masque): tighten the dohpath URI-template subset and validate UTF-8 |
| [`d9a31d4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d9a31d44918f53224dedf842ff7980e05281cb43) | fix(masque): reject mandatory SVCB keys this client cannot honour |
| [`c047579`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c0475793f533909d19ef7fa261f3a7884aed0a6e) | fix(masque): bind DoH capability to the real tunnel transport and origin |
| [`b196103`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b1961033d42f3eb08b8c33e08c9184f40f07f6b9) | refactor(masque): remove the unused PREF64 clear path |
| [`7e390e7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7e390e7843b4ed73982d01c753c7a0d56a30d2fe) | test(masque): prove the DNS assignment plane through the real constructor |
| [`aea2a47`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/aea2a47c24001ad69511fa3d0093a4f30ad38aa7) | test(masque): cover endpoint routing, snapshot consistency, SVCB edges |
| [`e93e297`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e93e297aa114d20a0963cb6d74f4b6e579940308) | refactor(masque): immutable DNS snapshots, and reuse native DNS transports |
| [`5941c77`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5941c77e11c798619cef64ffcc5c0f27b4ea22fc) | fix(masque): fresh bootstrap per reconnect, winner promotion, CC ordering |
| [`c2a2b4f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c2a2b4f6b096ac4b3143afdcfb615a92fa1b1683) | fix(masque): split-DNS semantics, existing-H3 DoH, and spec conformance |
| [`a6164de`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a6164dead0ab7611f92c9ac0fbc8ebac34fec5e1) | refactor(masque): preserve the DNS_ASSIGN configuration hierarchy |
| [`74e02fa`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/74e02fa07d7f86b8d823018852eb80423791e24e) | fix(masque): wire bootstrap recovery and handshake racing into the endpoint |
| [`1f698f0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1f698f0e78eb0282283aab367baa96621c1c6e4c) | docs: record the implemented MASQUE DNS phases |
| [`f15139c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f15139c6f5b508f666565b1b91563b87da95193b) | masque: end-to-end tests for the DNS_ASSIGN and PREF64 path |
| [`1d87f0c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1d87f0cf79455c43bb508cd009669c106ecdacd6) | masque: fuzz the DNS capsules, and the leak and cycle tests |
| [`b997373`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b9973735659c7aebb48e0680693624cb50b62200) | protocol/masque: DoH for assigned resolvers on the tunnel's own connection |
| [`433e1a4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/433e1a444d3d789065410813178ff34d16ada19c) | perf(masque): race QUIC bootstrap candidates at handshake completion |
| [`8870623`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8870623cfd4cd4173979c84b122b9ca8c8b216ea) | feat(masque): add bounded bootstrap resolution with a last-known-good cache |
| [`71b5406`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/71b54060fad453b5011e5b5dfccb652ec0729a68) | feat(masque): apply the resolver precedence at runtime |
| [`63a358b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/63a358bab9248016d7700d02636f5b07991130c1) | feat(masque): let the reference server send DNS_ASSIGN and PREF64 |
| [`9e5da9e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9e5da9e8c435655766e4a4381168ee514d514b9c) | feat(masque): add the endpoint-local assigned DNS transport |
| [`3ec67e4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3ec67e4af49e935efff7b543376efa8faf4c6fd9) | feat(masque): wire DNS_ASSIGN and PREF64 into session state |
| [`6486c05`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6486c050403209166047729e59752ec7d93d10c0) | feat(masque): implement DNS_ASSIGN and PREF64 capsule codecs |
| [`6274779`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6274779ffa1e1963709f6f3a1df4e7f509179fbe) | docs(masque): specify the three DNS roles and what remains unimplemented |
| [`d54777d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d54777dd731d45ca1be57a3f3191e19b4d68b173) | test(masque): pin the two resolvers apart at the configuration layer |
| [`d0b2c27`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d0b2c27ecb503dd910e51da59823e6112a6bf6df) | feat(masque): add an explicit inner domain resolver, and race inner TCP targets |
| [`d1b7eda`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d1b7edac2a7ca52bb5feadf2a7437325ee78b230) | perf(dns): stop formatting per-record log lines that the level discards |
| [`b6b68b8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b6b68b85a7cfe5b58d6e33a57009a7d5f2222229) | fix(dns): re-contend for a retry generation after a failed shared lookup |
| [`6910cb1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6910cb1af06122c5e0cb2455604554e5d880149c) | test(jiejie): pin the residential chain DNS ordering contract |
