# MASQUE

| Commit | 工作 |
| --- | --- |
| [`9c85c41`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9c85c41719be4da83cfa324ff1db440ea350a1b9) | test(masque): assert the batch delivers exact bytes, in order |
| [`37755cc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/37755ccd928fce1aa2bd0d139d5ecf92ddf936d3) | docs(masque): record the convergence round (metadata, queueing, allocation) |
| [`f8ff656`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f8ff65642be50e40ce7bf48253449479e8231f27) | test(masque): measure 1M packets for GC retention and allocation |
| [`c39ca8e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c39ca8eb819b1985d747b5cb1d7a08bad1e7a540) | perf(masque): send outbound datagrams in batches |
| [`baa97e9`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/baa97e945601d10f9e6365685fb6e4d6dfc9e7c2) | fix(http): wait for the test server's datagram loop instead of assuming it |
| [`dd8b19a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/dd8b19aa5cc3d59d3814393bcd7417e32e835dc7) | docs(masque): record the CI results for the zero-copy work |
| [`32ae337`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/32ae337e9d5f82c27b27c9a3810f789d93f37660) | docs(masque): record the zero-copy dataplane work |
| [`4cad551`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4cad5511c67e126a8456656612cc05edda103ed1) | test(masque): prove the inbound path costs one copy, and where it is |
| [`52d5756`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/52d57568fd794029e04d89e33ab2aad03b580eb4) | perf(masque): size the packet headroom for the owned DATAGRAM path |
| [`1a7b3eb`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1a7b3ebe5dd6e378528b03fdaa0ec82852fc5749) | perf(masque): send CONNECT-IP packets over the owned DATAGRAM path |
| [`b8cb5e2`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b8cb5e2cbf2cb15eda638483ab8bc4e361ed2c91) | build(quic): point quic-go at the owned-datagram fork |
| [`f907032`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f9070327b7504e14b080e0cd9ba35034eafd31a1) | docs(masque): record the performance round, and revise the route decision |
| [`d2f645d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d2f645df4e87e07550ac7815dbcc60252f93f7ca) | bench(masque): measure the receive path, and record why its slice stays |
| [`fad8101`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/fad8101c573cb4aab098ad0aefc4879cdd37f40b) | bench(masque): measure the oversize and racer paths, both NO CHANGE |
| [`864c004`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/864c0048be7022ce2a9576d0a500faca71a6986b) | perf(masque): match advertised routes by binary search, not linear scan |
| [`0127eee`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0127eee90366726f682989234c04f8ff330e297d) | bench(masque): record why the datagram capability needs no change |
| [`b5a25ed`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b5a25edd84a05e4e831d93461eb381895df5d926) | perf(masque): remove the per-packet allocation from the datagram path |
| [`bebeb5c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bebeb5c7e3c95f77565d34dcdc653d1b65f9b553) | docs(masque): record the sealed capability model |
| [`db94a76`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/db94a76b2d9c7e07335c9e40a228de012d80c7bd) | test(masque): cover capability transitions and the final spec edges |
| [`2073b63`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2073b634bff82c51f72902feac6aea577261b103) | test(masque): pin hard-failure cascade, and correct a wrong timer claim |
| [`c30290f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c30290fbffc62954175fc2371d935cfc0d918889) | docs(masque): describe the four planes, and state the scope limits |
| [`176721a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/176721a9300aa4137bc56b655a7252513e9d619c) | fix(masque): reject address counts that overflow the payload bound |
| [`f119aef`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f119aefa2fca70f92c9b5f2e043668f58b0cba27) | ci(macos): race-test protocol/masque in deep checks |
| [`4f74c65`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4f74c65595c77c0128ebd5081064aa6febe25ae2) | docs(masque): require a production path before calling something implemented |
| [`05fa733`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/05fa733917eb39a9016ccb1e635c8e78a61f6b07) | refactor(masque): remove the dead selection rule, and stress the new model |
| [`8700681`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/87006818d839b651f7181185caef6e66ac920871) | fix(masque): close every non-winning QUIC race attempt |
| [`b3218f3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b3218f340b8f543bbf6ac543bea15f00cf409da4) | test(masque): close the CONNECT-IP target encoding matrix |
| [`a2a7a9a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a2a7a9a30fda815eda42428228854a60f15ab062) | fix(http3): eliminate the CONNECT-UDP deferred activation race |
| [`ecdc966`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ecdc966ab4ee1f83880a0bbbb380129ecc8ac28b) | fix(masque): reject a backslash in a CONNECT-IP template target |
| [`7d66493`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7d66493bd3e4ac5441dbfe69fa0c7e3fa2eef529) | fix(ci): teach the runtime smoke test the masque port placeholder |
| [`0176c85`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0176c852a0021a8b4c5a98bfef95ecb3264245ff) | test(client): make the macOS fixture exercise masque-client end to end |
| [`0c500d4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0c500d42df809371a0081c99dc56e625e4d8429f) | test(masque): stop the ingress fixture leaking a goroutine that hung the package |
| [`29000a5`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/29000a54a4d046c688a7d125c813b5799f391fb1) | test(masque): benchmark route containment, and add the client QUIC congestion control option |
| [`6d94da5`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6d94da584f9b5313be08c1d8d6b943a1e03de628) | perf(masque): read session state from an immutable snapshot, not a mutex |
| [`9739c42`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9739c42a888f5254574bdf2c47048a88dfc8f491) | perf(masque): wrap the H3 ingress datagram instead of copying it |
| [`8f1ba42`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8f1ba42a97aec1f38ad70a6c8f1dffe391ab162c) | refactor(masque): split client and server endpoint registration |
| [`143f886`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/143f886e2168dd0906eacfe6b4806e8a7c2b6e5b) | fix(masque): release setup-window datagrams when the peer disconnects early |
| [`71f0f12`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/71f0f12881d6212f1b2dda436fc9f79f7cb7f885) | docs(masque): record the ready-to-submit upstream branch |
| [`fd53dbc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/fd53dbcf25dbdd809a0033dd51d553804e5d2be6) | style(masque): make the syscall interface assertions lint-clean on Linux |
| [`a64e79f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a64e79f0f9ea6b1b090203b71ee24a5cbdde573b) | fix(masque): keep the syscall test's batch-writer interface assertion |
| [`4ac7723`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4ac7723103aeb1fe2030af5b5034d58e4776a0f5) | style(masque): satisfy modernize and unused in the batch tests |
| [`a2bff6b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a2bff6b7c62d48d2b6f4108685edcfc466667355) | docs(masque): reconcile current interop and PTB evidence |
| [`87d11bd`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/87d11bd2992ef3b7e2a621ea67283dd53a1e04d4) | test(masque): pin packet-too-big session ownership |
| [`a07fd54`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a07fd54787705bbf79f969f1c427640053388248) | test(masque): classify QUICHE execution failures precisely |
| [`4d22f47`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4d22f47677bc8a53285d7dd02793cf4f6e45936c) | docs(masque): close timeout batch forwarding gap |
| [`c51772f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c51772f6a1004387f5c75eaedab17c6781fc1a87) | test(masque): exercise batching over real UDP sockets on Linux |
| [`9d6bfc7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9d6bfc783d08bfd3cb8f69099c51b1ffd55f56e6) | test(masque): benchmark the timeout wrapper batch path |
| [`e7f7dde`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e7f7dde6a0457ed075cf43b52a9ca6db9b5aeb76) | test(masque): verify batching survives UDP timeout wrappers |
| [`ff12828`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ff12828a4ded44350b80f0fa9ca9263d239b99ed) | ci(masque): scope the QUICHE interop tests out of the fast job |
| [`b6a2fbc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b6a2fbcc4be14c376a4da82ec51adbe549d4839d) | docs(masque): record the QUICHE runner limitation |
| [`a9c1860`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a9c18602dab9b97c8627faae5146e1e4c329ccc3) | test(masque): distinguish a QUICHE stall from a protocol disagreement |
| [`c8e5a65`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c8e5a65f9031198f385702ec209591965092aa1a) | docs(masque): update verified acceptance boundaries |
| [`8a6b333`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8a6b3336773393ad5d92d9464df653cf04e0b8f9) | test(masque): add repeatable VPS acceptance runner |
| [`60fec08`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/60fec086ebbaac2622e902f88257b20d6fc4109b) | test(masque): add live Google QUICHE interoperability |
| [`ad40266`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ad4026620a4c613b2c519c2d8bebcdfc4fac0752) | test(masque): force live H3 CONNECT-IP packet-too-big |
| [`5f37304`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5f373043a3048822c7312760da8ea0183d506817) | style(masque): drop unused GSO helpers and satisfy errcheck in the linux bench |
| [`c7de774`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c7de7747d71348f87c9a6725822c59616641cd08) | test(masque): measure Linux UDP GSO grouping and reject a size threshold |
| [`f20e71c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f20e71c728d171638d11ea51d376c6a2c940e88e) | style(masque): drop a redundant type assertion in the batch capability test |
| [`0af10db`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0af10dbbc72c8cc2fee1b23fbf7da90268fee0e5) | docs(masque): record the blocked dependency phases of the perf round |
| [`1a0761e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1a0761e9a2601d7e5318b6af179f8939a9d165c1) | test(masque): audit the HTTP/3 MTU surface instead of adding an option |
| [`62d5900`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/62d59003e74abb4fb5d886d9aac7e95d7438f3a9) | fix(masque): complete CONNECT-UDP target setup before success |
| [`bffd069`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bffd06952dd42067c84cc7f027884a1114987795) | test(masque): assert the target UDP socket reaches the batch syscall path |
| [`b8e7312`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b8e731257bb4b64b509102ee1cc80b7d647864b6) | test(masque): measure that the timeout wrapper drops batch capabilities |
| [`01ae0d3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/01ae0d3082890d6f71caf32ebfa864e9f0864a34) | perf(masque): batch HTTP/3 CONNECT-UDP packet forwarding |
| [`3b8d99a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3b8d99a216fecbc8cbd0de86bab1a4f7e29f8f66) | perf(masque): wrap H3 ingress datagrams instead of copying them |
| [`ec2b4b9`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ec2b4b91e0f521ba8dbb30e9cd304a8655acf5a2) | perf(masque): use connected UDP for CONNECT-UDP |
| [`5c58b10`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5c58b10572be6c6d4bc2486f3d9224de640bdcaf) | [skip actions] docs: organize the README MASQUE section |
| [`864be35`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/864be35ebcf150252ddd2512f57c77f6b9aa86bd) | test(masque): make the overlap-scaling assertion robust on a shared runner |
| [`583bfc8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/583bfc84f38a0f7160deab84484c260bbd7377b8) | ci(masque): add the QUICHE oracle tests to the reference run filter |
| [`8dedfb4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8dedfb4e3ba1e7bb5dac3ff91eb4fbf366a24d80) | style(masque): satisfy gofumpt and modernize on the new tests |
| [`4db6f90`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4db6f90f9857215398eb8ddaad56c4c2a46d9d00) | docs(masque): reclassify the RFC 9931 client-side half as out of scope |
| [`a78d273`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a78d273ac585c631f2696ace63981d81e0abd1a3) | docs(masque): de-duplicate the QUICHE checklist row |
| [`0455e6e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0455e6ec188fe129a7f7e9968d9e842ff89bb0b2) | docs(masque): add the QUICHE vector row to the pre-VPS checklist |
| [`0dbfc43`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0dbfc43d1e3fd9ddbc8b2363cc81d56c0e9428f6) | docs(masque): record the QUICHE protocol-vector check and reclassify the client-side half |
| [`36d4048`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/36d404826b9409b0d9a905c2ff82e60c4adf04f0) | test(masque): add Google QUICHE as a third protocol oracle |
| [`41a04ce`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/41a04ceb14e13881c5624337f323c74f3a3eea1c) | test(masque): pin cross-session policy, control bursts and IPv6 extension chains |
| [`e823b43`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e823b4312b37aa96898c1b2f6b53702baee9fb9c) | docs(masque): close the reference audit and add the pre-VPS checklist |
| [`daa4907`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/daa49073e8f42eaeaff246ca76b1305507eedc76) | test(masque): add CONNECT-UDP IPv6 coverage and correct the RFC 9931 attribution |
| [`1dbf363`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1dbf363d49df2270b6edd9418dd6e7ac5baf6d91) | test(masque): measure loss, duplication and reordering tolerance |
| [`ba7f62a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ba7f62a4ba852f3faa8f7008d0aa273d22e22234) | test(masque): prove the Packet Too Big evidence chain |
| [`4fc9984`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4fc9984b3992ed3039e7ea29d93949e70cddc535) | fix(masque): admit the largest ordinary IPv6 packet on the capsule path |
| [`988df7a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/988df7a35847375f166e3a6c25728491d1ddcc81) | test(masque): pin live context IDs, zero-length datagrams and datagram error semantics |
| [`8530321`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8530321703a14b7ae5427aba6570d6b850cba697) | test(masque): pin the limiter source key against NAT rebinding |
| [`7bb4342`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7bb43427550aad174fd5a6a9837d9060a22281f6) | test(masque): measure source identity instead of asserting it |
| [`7ae42c9`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7ae42c98d47b562131c260b0e999e0f77c1346de) | ci(masque): run every fuzz target in bounded CI |
| [`5434688`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/543468826807688ae878cf30b60ae6d25c088ab2) | test(masque): repair the fuzz corpus and add CONNECT-UDP path coverage |
| [`c702497`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c70249783f7d661375ec7910f29a041f1a2ca69a) | test(masque): fix the reference harness IPv6 capsule decoder |
| [`a819eeb`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a819eeb3feeea280bc16059a9f1967c9a1761cba) | style(masque): use WaitGroup.Go in the control-capsule burst test |
| [`67e55b3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/67e55b387253355041b27c53e495461c7b8c9706) | docs(masque): record the Phase 3 findings and correct two earlier claims |
| [`a12e5c2`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a12e5c258c16d39b6ce4cd82487c8deeea5aa1e4) | ci(masque): close the reference false-green hole in both directions |
| [`429d8b6`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/429d8b6774a1315816dfce828e2090aa1ba84bc9) | test(masque): audit Proxy-Status and pin the authentication boundary |
| [`a7fd9ec`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a7fd9ec116cd3e147f29e1289b6a8ec4cec6abd9) | test(masque): close the test stream helpers with sync.Once |
| [`824cd65`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/824cd658a8d2e5816744a9ccf53faffcdd81c388) | fix(masque): make decrementHopLimit total against malformed IP headers |
| [`86002b5`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/86002b56f064d541127a48bdaae6ef88cdfa0e98) | test(masque): fuzz the IP packet parser and capsule fragmentation |
| [`1325727`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1325727a5625dd2dc58954e5825b7ac66334c6f1) | test(masque): lock IPv6 extension-header protocol resolution |
| [`0cc6074`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0cc6074e3d2d5d444083f168aef76dfa7ae9872f) | test(http3): pin HTTP Datagram size accounting at the varint boundaries |
| [`858284e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/858284e5a0751ba2454697ae441122a82d631857) | test(masque): pin send-queue backpressure and buffer ownership |
| [`c5e2d3e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c5e2d3eb48c1bea13c69420519aa195297fc9c3c) | test(masque): measure active-tunnel shutdown and resource reclamation |
| [`01f20ce`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/01f20ce4e69fac8ea38432cb22959e41f4329f71) | test(masque): measure QUIC migration across NAT rebinding |
| [`0783a33`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0783a33b3bad284eb4b074ab8734b3341cb5323f) | test(masque): prove the CONNECT-IP capsule fallback with datagrams disabled |
| [`6efcf0a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6efcf0a75f5d2b9d61cfa8581a4c2a44dbc00b1c) | test(masque): target the real server gateway in the CONNECT-IP ICMP fixture |
| [`528858c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/528858c4447baba18a176dac74737636ce5b13db) | ci(masque): run the reference interop against the binary each case needs |
| [`9577b09`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9577b095f89e39825f02065f4206dfa16477ee50) | style(masque): satisfy gofumpt on the IPv6 fuzz seed |
| [`762b0ce`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/762b0cede298983f6ec0fceac4b6005c8a82a442) | docs(masque): record the pool, isolation and fuzz coverage |
| [`66f0e94`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/66f0e94360bb079f6d7980b22d092b09252af2af) | test(masque): fuzz the parsers that consume peer-controlled bytes |
| [`e4d2f6c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e4d2f6c1afb1008741a137b8c94481e0f8602f16) | fix(masque): make Contains agree with lookup about the server's own address |
| [`907dbfb`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/907dbfb991861d2630ac275b9be65380c278e11c) | docs(masque): record the RFC 9931 fix and the DATAGRAM fallback results |
| [`b81244b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b81244bdf767f798d4e8509f8e3f3898d9ded89a) | test(masque): prove the H3 DATAGRAM to Capsule fallback on the wire |
| [`432b36c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/432b36ce7532ec6e3e27d70249f64334a35dd784) | docs(masque): record the reference interop results and the two pin forms |
| [`32b1d25`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/32b1d25cbfd12786ffceef4b4cd03f5e9cdfc71a) | test(masque): prove CONNECT-UDP and CONNECT-IP interop with the pinned references |
| [`e81f849`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e81f849949ac79854c090ef2d068ff9d796d584f) | ci(masque): run the QUIC-tagged HTTP tests from the repository root |
| [`935ffec`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/935ffeca80dcc48c533de14f9328d9428bd4f148) | ci(masque): run the MASQUE packages and QUIC-tagged HTTP tests |
| [`d159ec0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d159ec09dfd1e9637c5c559d0630af95aec22923) | docs(masque): record the reference audit, changes and remaining gaps |
| [`ab9c9f0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ab9c9f09d9962288cffb1febb63cbd2c67719f7e) | test(masque): pin the CONNECT-UDP request path corpus |
| [`e4f847e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e4f847ecf732e8cd580ed1517f34fd3436ec6380) | fix(http3): make the MASQUE QUIC tuning opt-in |
| [`a529b68`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a529b68c830ff6a2ffe61cbe9ce5535e401a9c2a) | fix(masque): bound the entries in one control capsule |
| [`b656b06`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b656b062f99901406c8360f1358174b480eecfd5) | fix(masque): validate ROUTE_ADVERTISEMENT overlap in linear time |
| [`969909b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/969909bc16a188206f6fb598e6d2b833429f11f5) | fix(masque): reject overlapping ROUTE_ADVERTISEMENT ranges across protocols |
| [`d4ead14`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d4ead1498a30c45b971074ef17282483b1f1a8a1) | fix(route): enforce target ACL per UoT datagram and ship Naive ACL config |
| [`cb567c0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/cb567c0ccd419047056d5ee0644a15ee77580b33) | test(masque): complete the unauthorised probe matrix |
| [`1276eb8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1276eb85a2afa318ba7c6178ee69fdc8caf8bacc) | test(http): pin the MASQUE replay-safety invariant across the H3->H2 fallback |
| [`0271b14`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0271b145addf40759e6fcae9a83fdec9ae3d4c14) | fix(http3): gate MASQUE CONNECT on handshake completion |
| [`9491008`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9491008a97bd5bb636458e32d4aa51e1e0118e51) | fix(http3): wire http3_fallback into the MASQUE client and fix backoff lifetime |
| [`b836956`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b836956030c132a17133e9ea0144373a5e461686) | feat(http3): apply the connection pool to the MASQUE tunnel client |
| [`5dc14cc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/5dc14ccc21cfd543294ac790ca0f1099e93bb80b) | test: add AnyTLS and MASQUE H2/H3 integration coverage |
