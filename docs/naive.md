# Naive

| Commit | 工作 |
| --- | --- |
| [`50bbed4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/50bbed43e0ff4d2a24ccc05e3035199b14633d84) | docs(naive): record that Chromium resolves once, not twice |
| [`08861f1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/08861f136379ffd178257c405b639ab2008a4dc1) | docs(naive): record the CI run IDs |
| [`751b6b7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/751b6b7f89fd8867c767fe880e2440b2d221cce0) | docs(naive): record the dataplane hardening |
| [`f45db77`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f45db770ea80f8d6bdbbd8fb01285401a55677e1) | bench(naive): measure the cached first payload handoff |
| [`228fce7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/228fce76d5d2e9fc1010bd6890e34c291a3e33fe) | chore(deps): pin the cronet-go branch with pinning and early growth |
| [`ebc9a90`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ebc9a903a1cbeb7a494d14e01405e05ab5a140fe) | fix(naive): correct a fuzz assertion that reported a fallback as a misparse |
| [`f7e588c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f7e588c8c13e9e8eba48128bf42cf1c8c4e4489f) | test(naive): exercise the limiter under real concurrency |
| [`56e4de4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/56e4de4fcbb4aaa5bd23b53fad4a33b5405e19f4) | docs(naive): document the measured lifecycle and the new resource controls |
| [`724035c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/724035c763ad37899fa11e793bb9a61e56c3a365) | fix(naive): drop the duplicate idle_timeout, and prove idle tunnels survive |
| [`c761d6b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c761d6bedd77c483915f1e1cfc718e95617fed5a) | feat(naive): add opt-in inbound connection and request-phase limits |
| [`a1e7a69`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a1e7a69ba7bd457f639aacc5310fb7e3dd0250a2) | test(naive): measure the inbound connection lifecycle over a real socket |
| [`9325560`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/93255606a984e33f2cb70c4435a89254f211fe31) | test(naive): derive session framing everywhere, and guard the derivation |
| [`f477e0a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f477e0a150cb370682f44010fd57f39662a02ca8) | test(naive): empty KNOWN_FAILURES, all four entries were harness bugs |
| [`ecaa152`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ecaa152f4d8a856af0d102e212fd66fbf53966cc) | test(naive): retract the false "UoT v2 non-connect P0 product bug" |
| [`0864e31`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0864e31c749f70a59f3032670ebb1249f65d209c) | docs(naive): correct the audit ledger and make the integration suite runnable |
| [`2e3b614`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2e3b614f2d0821c9f847944816b278bec854c5de) | fix(naive): pin the byteformats overflow fix and guard the window options |
| [`f64638a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f64638a9854cc7eb223a70b1905d0b5c5bc264da) | test(naive): pin the client codec contract across both repositories |
| [`6fe3acc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6fe3acce3927d977ea739012a476cd3d41ea45ca) | build: pin the audited cronet-go Naive client codec |
| [`499eca1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/499eca17a4261f5c940db835032f72dd3096f163) | docs(naive): record the server-side HTTP/2 window findings, including a correction |
| [`31b0061`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/31b006164893f041d3950832227e9e2c91fe4857) | test(naive): give the loopback-resolve security audit real controls |
| [`7ebb331`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7ebb331a47e08f086f1f73d24188faccf298eb04) | test(naive): make the differential harness compare errors and enforce divergences |
| [`8d189a4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8d189a463049e1228cfd40ac118d15192612e3e8) | bench(naive): measure throughput from one batch and report real failures |
| [`da34e4c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/da34e4ce71fe1a5a37405f77c6b08d8a6388582a) | fix(naive): validate HTTP/2 receive windows against the library's real bounds |
| [`ef598d4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ef598d44153a307c6a6e008d7d04e88f1edcd551) | test(server-minimal): supply real TLS material when building the Naive inbound |
| [`0943040`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0943040c678d0ded3ca131bdbaee411167221198) | test(server-minimal): build and start the Native Naive inbound, not just resolve it |
| [`cc2cce6`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/cc2cce69cd3515eb85955c78d7b58edf6075b089) | docs(jiejie): state Native Naive as the production NaiveProxy server |
| [`67f35ae`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/67f35aeb605399b752e2c3f6752240a5c63f21d4) | docs(jiejie): state Native Naive as the production NaiveProxy server |
| [`279720c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/279720cce281e62bc242e2aea8eaec800949704f) | test(jiejie): key the Naive test guard on the OUTBOUND, not the inbound |
| [`3232055`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3232055c4d93f6f90b5b49b000037b194c7122d0) | docs(jiejie): correct the Native Naive production topology |
| [`378b8b1`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/378b8b1464c893635b466634b0f5c7612d479ab9) | test(server-minimal): pin the Native Naive production contract |
| [`0a7868b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0a7868b0f0ce13f3f81cbfc65ce91ba98122c8db) | test(server-minimal): pin the Native Naive production contract |
| [`fff7d46`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/fff7d46e79804d46cad235b65c8b543eefc8daa1) | fix(server-minimal): restore production Native Naive inbound |
| [`b3a1f53`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b3a1f53db4d9f8e63df6147d9af81c60043f703a) | docs(naive): correct a false claim about badhttp.SourceAddress |
| [`3d873c4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3d873c4f5b69b8164fe72e257a8f723a0ae7b884) | test(naive): assert the self-hosted web rule shape without the production fixture |
| [`7e71d85`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7e71d858f927efab8d0a446d924b41aadbcfcd91) | docs: correct stale Native Naive claims |
| [`3a031ea`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3a031eaeb4c50e06a03ce7e0e917869c771354af) | ci: exclude four known-failing Naive UoT audits from the Linux fast path |
| [`4130117`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4130117ae663a3db90d9239d347eb2d4e14871bb) | feat(naive): add an opt-in single Cronet engine switch for macOS |
| [`2e3807e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2e3807e06d7cedebdd8b61bc8755860572196a6a) | test(naive): benchmark the real HTTP/2 bulk path |
| [`680f5d8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/680f5d89d1c141f07169e22afac7a935c541732b) | perf(naive): tune production HTTP/2 receive windows |
| [`6678bf3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6678bf3480de4f3a5ac502afec5e25e18c0ea53b) | perf(naive): grow tunnel buffers after the first transfer |
| [`419a7e2`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/419a7e2efe627225adbf7e80dffc685d16c85b37) | test(naive): fix the buffer geometry in the write-contract fixture |
| [`96eafce`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/96eafce9b9f0ad5fee4c15a223c1baa7d769b465) | ci(naive): run the QUIC unit tests from the repository root |
| [`fc575d9`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/fc575d95943b9de59938e64ea9de600d437c382f) | ci(naive): run the new TLS and QUIC unit tests |
| [`40b6d6f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/40b6d6fcc7f936faf52c6c9b92e8e09a0f20d321) | test(naive): exercise the real QUIC congestion-control validation |
| [`55a0e54`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/55a0e54b07d4fdc90e087b20e4b512896ce30fe8) | docs(naive): record the upstream LazyConn handshake/Close race |
| [`9654163`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/96541638c3cc5f33a22084b69d4c03119227c0bf) | test(naive): skip the H3 defaults cases when QUIC is not linked |
| [`72eef31`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/72eef31cf50b509171b01bc301e1ae424b7469cc) | docs(naive): record the measured HTTP/3 differential and segmentation parity |
| [`114a3c3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/114a3c362e0a55223f6b8326d8b5716651a68c94) | style(naive): satisfy the import grouping check in the QUIC config test |
| [`f730f6e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f730f6e50da5b41acd8add4a5cd3ad91af7f9744) | test(naive): cover HTTP/3 half-close in both directions |
| [`b67b3f6`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b67b3f6ae4f291890aef1ab56394f5620dc5d886) | test(naive): reach the HTTP/3 pseudo-header guard at runtime |
| [`f74d925`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f74d9254cdb0809953612c5c3c689ec6d146c988) | fix(naive): pin the QUIC version list to the reference's |
| [`8ed7051`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8ed7051c62ffb5a157b2d739311bd73523e462db) | test(naive): measure HTTP/3 server defaults against the reference |
| [`242d8c2`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/242d8c2cbaa77ceb1d25d14584b363f7e3e3772d) | fix(naive): consume zero-length padded frames instead of returning no progress |
| [`b16660e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b16660ed1887693f857bdeee11dcdd2d2afa8a57) | fix(naive): remove the username-existence timing signal from the verifier |
| [`65e2270`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/65e2270028729b8322747321980a6f9fd9c91ae1) | fix(naive): align padded response segmentation with forwardproxy |
| [`385383d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/385383dccbebe6966a6e2a30ec19e19487163672) | ci(naive): actually run the HTTP/3 differential against the pinned reference |
| [`ed30baa`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ed30baaeadff7dec160d3fd064ea060dd02bcad7) | test(naive): skip the ALPN isolation cases only when HTTP/3 is not linked |
| [`14da4c7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/14da4c7e080e4ebccf4c23b191f63e2d592169b9) | test(naive): state the real scope of the static ALPN tests |
| [`d6820d0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d6820d0e7a41780bffb36087d2a2ff9b783749f8) | fix(naive): scope TCP and QUIC ALPN on a tcp+udp inbound |
| [`8618312`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8618312690798656992046ec10ff301389b174db) | test(naive): add an HTTP/3 differential against the reference |
| [`1f9014c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1f9014c85431f59f144cab6b70645a3dedc897ff) | fix(naive): refuse a malformed CONNECT port instead of coercing it |
| [`59401b4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/59401b422da22d89d2a755f5e2b6234779df5349) | test(naive): pin the mixed-address ACL hardening |
| [`2e49e45`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2e49e4508c1277a0a3df126c6e31460058fd2bc8) | test(naive): measure large-payload padding segmentation against the reference |
| [`1f05475`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1f0547577e52b020d07f336f10d1a1ebc5f1b135) | test(naive): drive the official client's preamble against the web masquerade |
| [`11fd30d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/11fd30d330f9efb747d0428fb3c27185fc3996e0) | test(naive): cover bidirectional tunnel half-close |
| [`d22dd89`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d22dd89443d8ff27cbbcb6f0061d94f27c869e0e) | fix(naive): make QUIC tuning opt-in so the protocol default is reference-like |
| [`497fb92`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/497fb9272c4e6024d6075052faf6a8d9c2152711) | test(naive): split bare and probe-resistant Caddy references |
| [`aa32bdf`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/aa32bdf7814a3dd179d7404f7bd665028dc6e51d) | fix(naive): align the unauthenticated proxy challenge with the reference |
| [`bc50e66`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bc50e66ea7663c309fd4fe38176ece9a9797b0d1) | fix(naive): propagate tunnel flush failures on HTTP/2 and HTTP/3 |
| [`2fbab5b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2fbab5b96f47fc1e42e40e31c61f00b7f0254955) | fix(naive): use constant-time credential comparison |
| [`f45e465`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f45e465b83962add246b0783316bccd783ad38e0) | fix(jiejie): route Naive self-hosted web traffic to an isolated local ingress |
| [`318dbee`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/318dbee27d176a348adb67b031dfde6a1bdbc157) | test(naive): make the differential verdicts and artifact unambiguous |
| [`086aba2`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/086aba2a45fcd36a3f9d7a711200f988bc2b7fd2) | test(naive): fuzz the padding codec and the CONNECT authority |
| [`d921493`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d9214933826825916dfbe2ff20dbacb6dd0114ff) | fix(naive): restore the bounded QUIC stream default |
| [`0245def`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0245deff82209c9e590cb1af93b4a3dd17338439) | fix(naive): check the CONNECT response flush |
| [`4ed6dff`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4ed6dff200808d50900bfbaa55cdb4db3a35096b) | ci: actually run the Naive HTTP/3 integration tests |
| [`d480202`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d48020282973c8cfbfd55035911d7591be0583c3) | test(naive): measure the H3 stream limit and label the remaining H3 differences |
| [`9885c45`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9885c45cf69c5b327f448a5d1a710a213edb6056) | test(naive): add real HTTP/2 differential probes against the reference |
| [`1be7647`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1be7647977b61e198de268baefc8dcb57b036fee) | test(naive): verify TCP/QUIC ALPN isolation at runtime |
| [`ece998f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ece998f21f3018de84593d1a65ceb504f7eebab1) | test(naive): settle H1 tunnel framing by byte comparison, drop a false divergence |
| [`ade5f46`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ade5f465c6ee92d497664691dc7155817f3961c1) | fix(naive): use the canonical QUIC-absent error and widen bounds coverage |
| [`34628b6`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/34628b6daf9ca15d6336fba69da7b723dbc3a190) | test(naive): cover every forwarded-header shape against source spoofing |
| [`9c6052b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/9c6052b050655f666a12eb0678f047a58af0458b) | fix(naive): refuse 0-RTT on the Native Naive HTTP/3 listener |
| [`c630c97`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c630c9775c3332e309922b4a2700342401b5fdf6) | fix(naive): isolate TCP and QUIC TLS ALPN |
| [`dccf709`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/dccf70987ed4673f0af7ae8f32ac170cc636223e) | fix(naive): do not nil-call the HTTP3 constructor |
| [`7be29e4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7be29e4ba97a0cd8dbb6676cfd8cd99b8b9f1879) | fix(naive): harden HTTP2 option bounds |
| [`1d66e93`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1d66e934f3f2824b553f60ba762de509906dd7e3) | fix(naive): stop trusting unverified forwarded source headers |
| [`b32bb58`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b32bb58f91aed02f433a2f00bba7d283067a36e2) | fix(naive): match reference HTTP1 tunnel framing |
| [`7029722`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7029722bff638e4016d3821e05199aa0a3d4e7cb) | fix(jiejie): allow Naive self SSH without weakening target ACL |
| [`75a32bc`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/75a32bcd7fe7d0b626376c9959529d11b0d42114) | ci: run the Naive differential test against the pinned reference |
| [`83efc0b`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/83efc0bf00e7b7aa4f910b2e190eb01783c0db71) | test(naive): audit HTTP/3 against Caddy and pin the Cronet client version |
| [`cc9df81`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/cc9df81f07224600192c6f4e0766ae19f08fe65b) | test(naive): add Caddy differential compatibility harness |
| [`f2907e7`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f2907e79a5d822abe783994ab9f3128d848f6a92) | test(naive): align HTTP CONNECT edge cases with forwardproxy |
| [`e9d3293`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/e9d32938065bdcf39422b6bef07eb4db08d0c8fe) | fix(naive): align CONNECT padding negotiation with forwardproxy |
| [`fe57895`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/fe578953932b0a7d362cc4eaa5c584552ad7533e) | fix(naive): restore full padding range and correct the buffer regression test |
| [`3c6e0aa`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3c6e0aad37868ae1f37efa08ab46e296572f5a98) | fix(naive): stop a random padding size from panicking the server |
| [`d2af551`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d2af551c40c1e3f43ff77036f16618373fe8e6c0) | test(naive): cover tunnel lifecycle, Linux resources; fix benchmark basis |
| [`1dc734f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/1dc734f7547e8a3201e2113a25d8e80aaf686015) | test(naive): replace the UoT SKIP with fault injection, add STUN and IPv6 |
| [`2ec06e4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/2ec06e451f9102fc0478eee7873cb63adfd54219) | test(naive): make the UoT regression tests actually run in CI |
| [`d1f3798`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d1f3798a63a00b16ebcb2103fc79b0deb31d77e0) | test(naive): make the churn acceptance strict at 2000 sessions |
| [`10e1f2a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/10e1f2a957946397add8bf00296c4bf06dd24846) | test(naive): make the retry test real and add a deterministic loss regression |
| [`3bbf179`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3bbf179078df0347352c32cf2c3d57440b8a3e4e) | test(naive): instrument the UoT path and prove the hijack bug was the 1% loss |
| [`593f634`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/593f634a1a22991fcc08e283f1a842ee8a9815bd) | fix(naive): keep the buffered bytes net/http already read past CONNECT |
| [`b49c78c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b49c78ca56731d6315bae95b45f1be33950ddc09) | ci: bring the CI gates in line with the Naive server being production |
| [`0c83345`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/0c83345a3f31dee52362625372310f267b95b2c4) | test(naive): audit per-stream auth isolation and authority handling |
| [`eace39c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/eace39c3e6bce10c612beb40b6fac22f007cd076) | perf(naive): add deterministic padding codec benchmarks |
| [`fb90272`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/fb90272a50c7bbb0c9b19872f55f6064379840e9) | fix(naive): honour the io.Writer contract in the padding write paths |
| [`39833a0`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/39833a0e782d8dcdd85bfe430f498ddf32b781dc) | style(naive): satisfy the CI linter in the audit tests |
| [`41bd528`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/41bd528cb277d140e115d34446c8fea446201000) | test(naive): audit what the masquerade backend actually receives |
| [`6fd7135`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/6fd71352353dd1397662a940ba0a82a2b6f4fef1) | test(naive): audit UoT data plane beyond the v1/v2 round trips |
| [`b24e294`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b24e2943003bd0f83ec935a51a70e74a7fe12150) | test(naive): audit TLS/ALPN, listener matrix and abnormal lifecycle |
| [`23af897`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/23af897bfd431af8f8da4915657deb5a62710ffb) | fix(naive): stop honouring the non-standard -connect-authority header |
| [`4085c08`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/4085c086dca72b488d791e421247edc0ce9db8ed) | test(naive): audit HTTP/2 concurrency, padding edges and destination control |
| [`d0087e8`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d0087e877e7b6b5543ed18837705d4674dae685b) | test(naive): cover the UoT exception paths independently |
| [`ce0496a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ce0496a311791dee5507e339b811dc029b00ec13) | test(naive): final acceptance on the production minimal registry build |
| [`c0ba174`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c0ba1749125a4ebd6a5d40d4263a69d4cacfc87a) | test(naive): Linux socket acceptance, and bound a real UDP loss finding |
| [`58985a3`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/58985a375992d8ebc85c8dc1136b35463aec50fa) | test(naive): real-client compatibility with the official NaiveProxy client |
| [`05e24b4`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/05e24b42c4f4a85d89613eb88137ce8cda64ad6e) | test(naive): verify unauthorised CONNECT by recording the target, not the status |
| [`7c0267f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7c0267f2cc0f37be02a6be1ac945ba44bb7f1b1c) | docs(naive): document the native Naive server, UoT and masquerade |
| [`776ac9e`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/776ac9e9602e033c5cba24d4c6548f5f19ff10bc) | test(naive): pin the padding frame codec |
| [`7760729`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/77607290f598f4ee2bdf7f22a65d9fed47e04a24) | feat(naive): make the HTTP/2 server bounds configurable |
| [`8f63bad`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/8f63badd0c2fefb1454cde1d51801dedc53af8ef) | test(naive): skip cleanly under the minimal production registry |
| [`568e93f`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/568e93f140ec9522088977219b2a42e93629532d) | test(naive): cover the Web masquerade and assert the real security property |
| [`c3de03a`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/c3de03ad48bb287fdcba9f1e5a22a3e250e48598) | test(naive): prove finished UoT sessions release their resources |
| [`bbcabc9`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/bbcabc9a2e1818c309c48fb14aa70e179fd299ac) | test(naive): prove UoT v1 and v2 work end to end through the inbound |
| [`45f6686`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/45f6686a61ab5535235c817133917246573a82c7) | feat(naive): optional padding, web masquerade, and a valid CONNECT path |
