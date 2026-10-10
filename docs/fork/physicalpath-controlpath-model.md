# PhysicalPath / ControlPath (J-1) and the start-time reachable-leaf dry run (J-2)

Status: IMPLEMENTED. This closes `docs/fork/v016-overnight-implementation-report.md` J-1 and J-2.

## The three things that are not the same

```text
CONTROL PATH  (who SELECTS what - routing control)
  selector / urltest / loadbalance / nested group
      -> at most one leaf committed per flow

PHYSICAL PATH (the transport/proxy hops the traffic ACTUALLY traverses)
  #0 = nearest to this device  ->  #1 middle  ->  #N exit  ->  destination
```

1. the SELECTED OUTBOUND ROOT - what a routing rule chose;
2. the ACTUAL PHYSICAL HOPS - the real encapsulation chain;
3. CONTROL GROUP NODES - a `selector`, a `urltest` or a `loadbalance` SELECTS and then disappears.
   It never wraps a connection, never sees a byte, and is NOT a hop.

A diagnostic that reports (3) as (2), or that reports (2) backwards, describes a path the traffic
does not take. That is worse than no diagnostic.

## Direction: the direction proof, quoted

A configured `detour` is a DEPENDENCY edge. `X.detour = Y` means X consumes Y, so the packet reaches
X first and Y second. The configured field is the DEPENDENCY, not the predecessor.

`common/dialer/detour.go`

```go
func (d *DetourDialer) init() {                              // :57
    dialer, loaded = d.outboundManager.Outbound(d.detour)   // :61  <- Y
    d.dialer = dialer                                        // :77
}
func (d *DetourDialer) DialContext(...) {                    // :80
    return dialer.DialContext(ctx, network, destination)     // :85  <- X asks Y to dial
}
```

`protocol/socks/outbound.go`: the proxy outbound builds its dialer from those options and uses it
only to reach its own SERVER, so its own hop is entered before the dependency is dialled.

```go
outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())  // :134
dialClientDialer := clientDialer(outboundDialer, version, options.ServerOptions.Build()) // :157
client: socks.NewClient(dialClientDialer, ...)                                           // :162
... h.client.DialContext(ctx, network, destination)                                      // :292
```

`route/route.go`: the chain is built consumer-first and the LAST element is the one that is dialled.

```go
chain := []adapter.Outbound{outbound}   // :247
chain = append(chain, outbound)         // :266
leaf := chain[len(chain)-1]             // :899, :956
```

Therefore, in `common/physicalpath`:

```text
Hops[0]            is the outbound the flow's routing selected,
Hops[len(Hops)-1]  is the last dependency reached - the exit.
```

## Files

| file | what it holds |
| --- | --- |
| `common/physicalpath/physicalpath.go` | `Hop`, `Path`, `Unknown`, `Snapshot`, `Resolver`, `Build`. Read-only. |
| `common/physicalpath/leaves.go` | `PathNode`, `Resolver.Hops`, `Resolver.Leaves`, cycle detection. |
| `common/physicalpath/dryrun.go` | `Declarations`, `HopCheck`, `Failure`, `Report`, `ValidateRoots`, the per-node contract. |
| `common/physicalpath/physicalpath_test.go` | the model and dry-run matrix, on fixtures. |
| `adapter/outbound/manager.go` | `lintOutbounds` (the sort, extracted) + `validatePhysicalPaths` (the dry run) + the duplicate-tag guard. |
| `adapter/outbound/manager_physicalpath_test.go` | the start-time contract, through the real `Manager.Start`. |
| `adapter/outbound.go` | the new `adapter.DestinationDNSOwner` capability. |
| `protocol/socks/outbound.go` | implements it, from the same field its dial path reads. |
| `box.go` | `declaredDestinationDNSOwnership` + `EnablePhysicalPathValidation`: the three facts the objects cannot report. |
| `box_physicalpath_test.go` | the same contract through the real configuration loader. |
| `route/physicalpath_route_test.go` | the model and the cursor contract over REAL `group.Selector` / `group.LoadBalance`. |

## Read-only: what `Build` and the dry run physically cannot do

`Resolver` holds a registry lookup, a `Snapshot` and a network name. There is no dialer, no logger,
no context and no clock in it, so a walk cannot dial, log or time anything.

- **No round-robin consumption.** The enumeration reads each group's DECLARED membership
  (`OutboundGroup.All` unioned with `adapter.Referrer.References`), so it calls no selection function
  at all. `Build` may call `Selected(network)` where the snapshot has no opinion, and for every group
  in this tree that is a preview:
  - `Selector.Selected` (selector.go:118) returns the loaded atomic;
  - `URLTest.Selected` (urltest.go:207) reads the selected generation and, when empty, calls
    `URLTestGroup.Select`, which reads the history store and writes nothing back;
  - `LoadBalance.Selected` (loadbalance.go:259) is documented as "a pure preview" and delegates to
    `SelectForFlow(.., commit=false)`; the round-robin branch takes the cursor with `Load()` and only
    advances it with `Add(1)` when `commit` is true (loadbalance.go:337-341).
  A caller that will not accept even that sets `Snapshot.Selections`, or passes `""` to declare the
  member NOT KNOWABLE.
- **No cloning.** Every object the walk visits is the registry's object. `TestTheReportedLeafIsThe
  SelectedLeaf` asserts `require.Same` on it.
- **No invented hop.** Where the leaf is not knowable the walk appends an `Unknown{Node, Position,
  Reason}` and stops there. `Path.Exit()` reports `ok=false` while any unknown is present, so a
  caller cannot mistake a partly-verified path for a verified one.
- **Cycle detection reuses the existing graph.** The walk follows the declared membership and
  `Dependencies()` - the same edge set `adapter/outbound/cross_kind_cycle.go` validates at start -
  and its own descent is the cycle record, which is the shape `route.resolveOutbound` already uses.
  No second graph was introduced.

## Start-time dry run: which checks, and why each is decidable offline

| check | what it catches |
| --- | --- |
| the member exists | a group whose declared member names nothing (see the note on the sort below) |
| it can carry every network its root routes to it | a UDP-only member in a chain a TCP flow takes |
| endpoint participation | a tag claimed by two different objects in the endpoint manager |
| declared `destination_dns_ownership` is implemented | a promise about what the peer receives that the object cannot keep |
| declared ownership has a resolver | the fail-closed path that would break every named destination |

Every node of a detour chain is checked at its own position, not only the exit: a middle hop that
cannot carry the flow makes the whole chain unusable even when the exit can.

### Hooked in, not duplicated

`box_lifecycle*_test.go`, `box_cross_kind_cycle_test.go` and `route/nested_chain_test.go` were read
before anything was added. The decision:

- **extended** `adapter/outbound.Manager.Start`. The sort that already owns "the dependency exists"
  and "the graph is acyclic" was extracted as `lintOutbounds` with the start removed, so the dry run
  runs AFTER it and cannot replace its more precise message; the order it computes is passed to
  `startOutbounds` rather than recomputed.
- **did NOT** add a second traversal to `box.go`. The Box supplies only the three facts the objects
  cannot report: which tags declared `destination_dns_ownership`, how a domain resolver is derived
  for an outbound (through the same `DomainResolverReference` edge `route/reference.go` and
  `common/dialer` use), and whether the network layer configures a default resolver.
- **did NOT** duplicate the cross-kind DNS check. `TestCrossKindDNSCycleIsRefusedAtStartup` and
  `TestCrossKindAcyclicConfigStillStarts` pass unchanged.

## Compatibility decision

**A Manager that was never given the declarations runs exactly as before.** `EnablePhysicalPathValidation`
is what turns the dry run on, and only `box.New` calls it. Every existing manager fixture - including
`startCycleFixture` in `manager_cycle_test.go` - therefore keeps its previous behaviour exactly, which
is why the three existing cycle tests pass unchanged.

Which check refuses which configuration:

| configuration | refused by | message |
| --- | --- | --- |
| a declared dependency that names nothing | the pre-existing sort | `dependency[ghost] not found for outbound[sel]` |
| a declared cycle | the pre-existing sort | `circular outbound dependency: first -> second -> first` |
| two objects under one tag | the NEW guard in `lintOutbounds` | `duplicate outbound tag in the start graph: ts` |
| a member that exists and cannot carry the flow | the dry run | `outbound/sel -> sel -> udp-only -> hop #0 udp-only: this outbound carries udp and cannot serve the tcp flow routed through it` |
| a declared owner that cannot honour it | the dry run | `... but outbound type trojan does not implement it ...` |

The first two rows are the honest answer to "does the currently-unselected member fail Start": a
missing member tag ALREADY failed Start before this work, because the sort reads a group's member list
through `Dependencies()`. The dry run adds the two rows below them, plus per-network, endpoint and
ownership validation, none of which the sort can perform because it materialises no member.

**No configuration that starts today is newly refused**, with one deliberate exception:
`destination_dns_ownership` on an outbound type that does not implement it. That field is a
fork-only option added in the same release cycle, so no configuration predating it can contain it,
and the behaviour it replaces is a silent violation of the promise the field states.

### A latent panic found and fixed

Chasing the endpoint-collision test found a real defect in the start-order sort: it marks a node
started by TAG and stops when the number of started tags equals the number of NODES. Two objects
under one tag satisfy that count with one unvisited, and the code that then reports a dependency
problem dereferenced the nil result. Measured: `invalid memory address or nil pointer dereference`
inside `lintOutbounds`, not an error. `TestDuplicateMemberTagIsRefusedRatherThanCrashingTheSort`
pins the replacement.

## Test matrix and what each test pins

### `common/physicalpath` (model, on fixtures)

| test | pins |
| --- | --- |
| `TestDirectSingleLeafIsOneHop` | a leaf with no dependency is one hop at position 0; `ControlPath` empty |
| `TestDetourTwoHopIsConsumerFirst` | `h2.detour=h1` reports `[h2, h1]` - the ORDER |
| `TestDetourThreeHopKeepsTheOrder` | `[h3, h2, h1]` - the full descent, not the two ends |
| `TestEndpointLeafIsMarkedAsAnEndpoint` | `IsEndpoint`, not `IsGroup`, for an `adapter.Endpoint` |
| `TestOutboundToEndpointKeepsTheEndpointLast` | outbound -> endpoint: the endpoint is the exit |
| `TestMasqueEndpointLeafIsAPhysicalHopAndNotAGroup` | a MASQUE endpoint is a physical hop |
| `TestSelectorToLeafDropsTheGroupFromThePhysicalPath` | a selector is not a hop; it IS the control path |
| `TestSelectorToLoadBalanceToLeafKeepsOnlyTheLeaf` | two control levels, one hop, `ControlOwner` = innermost |
| `TestNestedGroupToLeafResolvesToTheInnermostLeaf` | 3 control nodes, 2 hops |
| `TestGroupWithDetourKeepsBothChainsDistinct` | `ControlPath != PhysicalPath` |
| `TestHopZeroIsTheNearestEntryForTheWholeMatrix` | hop #0 is the entry for six topologies, and no hop is ever a group |
| `TestControlPathOrderIsNotPacketOrder` | the two lists differ in content AND length |
| `TestTheReportedLeafIsTheSelectedLeaf` | reported == committed == the registry's object (`require.Same`) |
| `TestTwoFlowsAdvanceTheSelectorCursorExactlyTwice` | a preview consumes nothing; a pinned snapshot asks nothing; two flows are two |
| `TestBuildNeverCallsADialingMethod` | no dial, no `AttachConnection` |
| `TestAnUnresolvableDependencyIsUnknownAndNotInvented` | the missing hop is absent; `Exit()` is false |
| `TestASnapshotCanSayTheLeafIsNotKnowable` | `""` means unknown, not "read the live object" |
| `TestASnapshotNamingAMissingMemberIsUnknownRatherThanAFalseHop` | a snapshot cannot inject a hop |
| `TestAMultiErrorPathReportsTheCorrectHopAndTag` | the failure names hop #3, not the root |
| `TestACycleIsReportedNamingTheWholeChain` | `first -> second -> first` |
| `TestACycleThroughAGroupIsReported` | `sel -> sel` |
| `TestAMissingRootIsUnknownNotAnError` | a fact about the registry, not a walk failure |
| `TestCycleDetectionUsesIdentityNotTag` | two objects sharing a tag are not a cycle |

### `common/physicalpath` (dry run, on fixtures)

| test | pins |
| --- | --- |
| `TestDryRunEnumeratesTheUnselectedMembersToo` | every member of every nested group is a leaf |
| `TestDryRunFailsForAnUnselectedMemberThatDoesNotExist` | root/route/hop/leaf/reason all present |
| `TestDryRunAcceptsALegalMixedGroup` | the negative control: a legal group passes |
| `TestDryRunFailsForAMemberThatCannotCarryWhatTheGroupRoutes` | the network contract |
| `TestDryRunReportsDestinationDNSOwnershipOnAnIncapableType` | declaration vs capability, and the resolver requirement |
| `TestDryRunFailsForACollidingEndpointTag` | a shadowed endpoint, and the coherent cases |
| `TestDryRunCycleIsReportedWithTheChain` | a cycle in an unselected branch |
| `TestDryRunLeavesTakeNoSelectionPreview` | even a preview is absent from the enumeration |
| `TestReportErrNamesEveryOffendingRoute` | every defect in one start, not one per start |
| `TestHopStringRendersPositionTagAndOwner` | the rendering an operator reads |

### `adapter/outbound` (start time, real `Manager.Start`)

| test | pins |
| --- | --- |
| `TestStartRefusesAGroupWhoseUnselectedMemberDoesNotExist` | fails at Start (via the pre-existing sort) |
| `TestStartRefusesAGroupWhoseUnselectedMemberCannotCarryTheFlow` | fails at Start (via the dry run) - unselected member, current one healthy |
| `TestStartAcceptsAGroupWhoseMembersAreAllUsable` | the negative control |
| `TestStartRefusesAMemberThatCannotCarryTheRoutedNetwork` | the same, flat |
| `TestStartRefusesACycleInAnUnselectedBranch` | the cycle is refused whichever member is selected |
| `TestStartRefusesDestinationDNSOwnershipOnAnIncapableType` | refused with the declaration, starts without it |
| `TestStartRefusesAnEndpointWhoseTagIsShadowedByAnOutbound` | two objects, one tag |
| `TestDuplicateMemberTagIsRefusedRatherThanCrashingTheSort` | the panic above, replaced by an error |
| `TestNoDryRunWithoutTheDeclarationsKeepsTheManagerUnchanged` | the compatibility rule |
| `TestStartupCycleCheckStillRunsBeforeTheDryRun` | the sort's message is preserved |
| `TestTheDryRunConsumesNoRotationOnARealStart` | startup consumes no rotation and takes no preview |

### `box_test` (the real config loader)

| test | pins |
| --- | --- |
| `TestLegalPhysicalPathConfigurationStillStarts` | no new rejection for a legal group |
| `TestPhysicalPathDryRunRefusesAnUnusableUnselectedMember` | `network: "udp"` member + TCP flow fails `box.Start()` |
| `TestDestinationDNSOwnershipOnACapableTypeStarts` | SOCKS + resolver + the flag starts |
| `TestDestinationDNSOwnershipOnAnIncapableTypeIsRefusedAtStart` | trojan + the flag is refused |

### `route` (real `group.Selector` / `group.LoadBalance`)

| test | pins |
| --- | --- |
| `TestControlGroupIsNotAPhysicalHopThroughRealGroups` | 1 hop, 2 control nodes, over the real groups |
| `TestTheReportedExitIsTheDialedMemberThroughRealGroups` | reported exit == dialled member |
| `TestPhysicalPathTakesNoSelectionPreviewThroughRealGroups` | `CommittedSelections()` unchanged by a walk |
| `TestTwoFlowsAdvanceTheCursorExactlyTwiceWithAPreviewInBetween` | preview 0, walk 0, two flows 2 |
| `TestPhysicalPathReportsAnUnknownMemberRatherThanInventingOneOnRealGroups` | a snapshot-declared unknown |
| `TestPhysicalPathReportsAMemberlessGroupAsUnknownOnRealGroups` | a group with no candidate for the network |

## Reverse-break evidence

Driver: `C:\Deepseek\内核\mutate_physicalpath.py`, run as
`python mutate_physicalpath.py C:\Deepseek\内核\wC C:\Deepseek\内核\_scratch_physicalpath`. Every
mutation is applied to a FRESH copy of the tree and the original bytes are restored and verified
afterwards. The real worktree was never mutated.

```text
[RED]     mutation A: a control group is recorded as a physical hop
            --- FAIL: TestSelectorToLeafDropsTheGroupFromThePhysicalPath (0.00s)
            Messages:   	a selector is NOT a physical hop: it never wraps a connection and never sees a byte
            --- FAIL: TestSelectorToLoadBalanceToLeafKeepsOnlyTheLeaf (0.00s)
            --- FAIL: TestNestedGroupToLeafResolvesToTheInnermostLeaf (0.00s)
            --- FAIL: TestHopZeroIsTheNearestEntryForTheWholeMatrix (0.00s)

[RED]     mutation B: the packet order is reversed
            --- FAIL: TestDetourTwoHopIsConsumerFirst (0.00s)
            Messages:   	packet order is the CONSUMER first: h2 asks h1 to dial, so h1 is reached second
            --- FAIL: TestDetourThreeHopKeepsTheOrder (0.00s)
            --- FAIL: TestOutboundToEndpointKeepsTheEndpointLast (0.00s)

[RED]     mutation C: a preview consumes a round-robin slot (fixture)
            --- FAIL: TestTwoFlowsAdvanceTheSelectorCursorExactlyTwice (0.00s)
            Messages:   	a preview must consume nothing: the committed cursor is untouched

[RED]     mutation D: a control group is recorded as a physical hop, over REAL groups
            --- FAIL: TestControlGroupIsNotAPhysicalHopThroughRealGroups (0.00s)
            Error:      	"[#0 sel[selector] GROUP-NOT-A-HOP #1 lb[loadbalance] GROUP-NOT-A-HOP
                            selected-by sel #2 A[recording] selected-by lb]" should have 1 item(s)
            --- FAIL: TestPhysicalPathTakesNoSelectionPreviewThroughRealGroups (0.00s)

[RED]     mutation E: a preview consumes a real LoadBalance round-robin slot
            --- FAIL: TestPhysicalPathTakesNoSelectionPreviewThroughRealGroups (0.00s)
            Messages:   	a diagnostic must not move the cursor: a preview that spent a slot would hand
                            the next flow a different member than the one just reported

all mutations red; every restore byte-identical
```

Mutation E mutates `protocol/group/loadbalance.go`'s `Selected` to pass `commit=true`, i.e. it makes
the REAL group's preview consume its real cursor. That is the strongest available form of the third
reverse-break: the cursor arithmetic is asserted against `CommittedSelections()`, not a fixture's
counter.

## What this does NOT do

- **No per-hop status, error ownership or MTU block.** That is J-3 and is untouched.
- **No HTTP CONNECT destination DNS ownership.** J-4 is untouched: `protocol/http/outbound.go` still
  writes its own authority and still sends a hostname. The dry run therefore reports
  `does not implement it` for an `http` outbound that declares the flag, which is the honest report
  and is pinned by the fixture test. The precise next step is J-4's own: apply the
  `resolveDestinationForDownstream` shape there, add `DestinationDNSOwnership()` to the HTTP
  outbound, and the dry run accepts it with no change to this code.
- **No `type: chain`.** Not added, and not wanted.
- **No per-hop timers, probes or health workers.** Nothing here starts a goroutine or a timer; the
  walk has no clock.
- **The unselected-member failure for a MISSING tag is the pre-existing sort's.** Reported honestly
  above rather than claimed as new.

## Next step

J-3 on top of this: a read-only `PhysicalPathStatus` that returns the hops `Build` produces, each
with `state`, `selected_leaf`, `last_error` and `generation` read from the existing
`adapter.Lifecycle` / resource walk, plus the three-layer MTU block, reporting `UNKNOWN` with a
reason wherever the kernel cannot know a value. No probe and no timer.
