# Apple UI RC checklist

For the TestFlight validation round. Every item is an **observable behaviour**, not an impression:
each one either happens or does not, and the failure is described so it can be recognised when it
happens rather than argued about afterwards.

The UI fork was audited against these; the code review that cleared them, and what it could not clear,
is in the round's report. What follows is what has to be seen on a device.

## iOS

### Cold launch and the three primaries

```text
[ ] cold launch lands on Home, with the profile card at the top and the accessory at the bottom
[ ] tapping Tools shows Tools; tapping More shows More/Settings; tapping Home returns
[ ] the accessory (start control / status) is present on all three primaries exactly once -
    two copies, or none, is a failure
[ ] the Tools badge reflects unread reports and failed sessions; opening Tools does not clear it
    on its own (only reading does)
```

### Child navigation (Logs) - the state machine this round changed

```text
[ ] Home -> (shortcut) Logs opens Logs with a back button
[ ] back from Logs returns to the TOOLS root, not to Home
[ ] while Logs is open, switching to Home and back to Tools shows Logs again (a tab keeps its stack)
[ ] an interactive swipe-back from Logs leaves the selection on Tools - then tapping Logs again
    opens it again (it must not be "already selected but not shown")
[ ] launch with Logs already selected (deep link / screenshot mode) shows Logs once the root
    appears, with a working back button
[ ] tapping the Logs shortcut twice does not push Logs twice (no double back button)
[ ] with Logs open, tapping its own tab does not reset the stack
```

### Settings notification

```text
[ ] from the LOG page's menu, Remote Control moves to More AND opens the Remote Control page
    (the failure this guards: the tab moves, the page does not open)
[ ] the same from any other tab while Home or Tools is on screen
[ ] doing it twice in a row opens it once, not twice
[ ] after it opens, back returns to the Settings root
[ ] the App/Core notifications land on the Settings root (they name sections of the root, so no
    further push is expected)
```

### Tunnel life cycle on the page

```text
[ ] Start -> the accessory shows Connecting, then Connected, with no duplicated controls
[ ] while switching, the page's controls are disabled and re-enable when the switch finishes
[ ] Stop -> the accessory returns to the start control
[ ] Reasserting (network change with the tunnel up) is visible and then clears
[ ] with the tunnel connected, toggling the system proxy updates the card and survives a relaunch
[ ] a profile switch while connected reloads the service and the status returns to Connected
[ ] during a start/stop, Home's controls and the Tools/More pages stay responsive
```

### The three primaries' contents

```text
[ ] Home: profile card, clash mode card (when connected and enabled), shortcuts, traffic cards,
    HTTP proxy card, status card, connections card - per the dashboard card configuration
[ ] Home card configuration changes take effect after returning to Home
[ ] Tools: each conditional row appears exactly when its condition holds -
      Tailscale/OpenConnect/OpenVPN endpoint rows (none / one / several),
      the unread badge (0 / >0), a failed session marker, USB/IP servers (none / some),
      and every static tool row
[ ] Tools rows open their page; the ones that present a sheet present it once
[ ] More: App, Core, Packet Tunnel, On Demand Rules, Profile Override, Remote Control, Sponsors,
    Documentation, Source Code, Rate on App Store - each opens its page
[ ] no row anywhere requires a second tap to respond
```

### Groups, connections and the pickers

```text
[ ] Groups: no groups / one group / many; expand and collapse; URL test runs and shows latency
[ ] a selected member is visibly selected and an unselected one is visibly unselected
[ ] Connections: empty, one, many; active and closed; long domain, IPv4, IPv6, long inbound name,
    long chain, large totals, long duration - no overlap, no clipping, divider between rows
[ ] tapping a connection opens its detail; closing it from the context menu removes it
[ ] the connection list updates while it is on screen without losing scroll position
[ ] Profile picker: the selected profile is marked; switching updates the list, the Home card and
    the tunnel; the edit/QR/share/export/delete actions behave as before
[ ] Outbound picker, Tailscale exit-node picker, font picker and terminal theme picker show which
    option is selected and which are not
```

### Remote control mode

```text
[ ] entering remote mode hides the local-only rows and the dashboard reflects the remote state
[ ] a remote connection appears, the uptime updates, and disconnecting returns to local
[ ] the tab bar and the child navigation keep working in remote mode
[ ] the log page's remote menu works before and after a disconnect
```

### Presentation

```text
[ ] Chinese and English: long profile names, long group and member names, long connection domains
    - no clipping, no truncation mid-glyph, no row overlap, no misaligned icon
[ ] Light and Dark
[ ] default text size and the largest accessibility text size: rows grow instead of overlapping,
    and every control's tap target remains reachable
[ ] rotation on iPad, and split view at half width
```

## macOS

```text
[ ] the sidebar lists its destinations and the detail column shows the selection
[ ] Groups and Connections appear and disappear with the tunnel state, as before
[ ] the detail column at narrow, normal and very wide window widths: content centred, inset
    consistent, ONE scrollbar (two means a nested scroll view), nothing clipped at the
    maximum width
[ ] the toolbar keeps: start/stop, the remote-control picker, disconnect, dashboard items
[ ] entering and leaving remote mode updates the sidebar and the detail column together
[ ] Settings: the notification opens the requested page; opening two different pages in a row
    works; leaving Settings for another destination and returning resets the path as it did before
[ ] the log page: search, pause, level, clear, save, clipboard, share, remote menu
[ ] menu bar item and window resizing behave as before
[ ] Chinese and English, Light and Dark, and the largest text size
```

## Cross-cutting

```text
[ ] no control anywhere acts twice for one tap (a duplicated push or a doubled action)
[ ] no page is reachable only by a control that does not respond
[ ] the app icon, name, bundle identifier and App Group are the shipped ones
[ ] starting and stopping the tunnel repeatedly (5x) leaves no visible drift in the UI
[ ] backgrounding and returning to a child page restores what was on screen
```

## Why these are the items

Each one corresponds to something the code review could establish *should* hold, or could not
establish at all:

- the child-navigation items are the state machine this round rewrote; its mapping is executed by
  `scripts/dev/check-hako-primary-route.sh`, but "a swipe-back leaves the selection on the parent"
  is a SwiftUI behaviour that only a running app can answer;
- the settings-notification items are the path this round fixed - a request that used to be lost
  when the page did not exist yet;
- the tunnel-life-cycle items are the states the disabled gate applies to;
- the presentation items are the ones no diff can settle: locale density, clipping and Dynamic Type
  are properties of rendered text.
