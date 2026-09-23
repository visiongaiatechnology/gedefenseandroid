# GeDefense Mobile UI / Safe-Area Design — 0.16.0-beta.1

## Visual direction

The beta UI uses the GeDefense identity as a real design system rather than a decorative skin:

- obsidian / graphite base with low-noise atmospheric grid
- layered translucent panels with inner sheen and restrained blue/gold edge light
- metallic-gold brand/action accents
- cyan / electric-blue protection and live-traffic accents
- green only for verified healthy state
- red reserved for enforcement/error attention states
- custom dependency-free line icons rather than font-dependent emoji/symbols
- shield-centered protection hero with low-cost animated energy arcs
- persistent five-item bottom navigation: Home, Activity, Security, Evidence, More
- compact status pills for transport mode and BLOCK / CORRELATE / ANNOTATE authority

The implementation uses Android platform APIs and Kotlin only. No AndroidX, Compose, external font/icon package, image loader or third-party UI runtime was added.

## Information hierarchy

### Home

1. Brand/header and live state
2. Protection hero with transport-mode badge
3. Four primary health/intelligence metrics
4. Quick actions
5. Session XDR 2x2 metric grid
6. Mode explanation

In Full Flow mode the primary count is **Threat vectors active**, not "routes ready". Selective Shield retains the route count wording.

### Activity

Threat-feed cards are deliberately compact and visually encode authority:

- `ROUTE_BLOCK` -> red BLOCK icon/pill
- `CORRELATE_ONLY` -> gold correlation icon/pill
- `ANNOTATE_ONLY` -> blue annotation icon/pill

The UI may describe policy, but it may never promote correlate/annotate data into enforcement semantics.

### Security

The surface is a local security observatory:

- Integrity Guard with authenticated baseline state
- Malware & App Risk Scanner with bounded risk cards
- Live Full-Flow Traffic per app with bytes, flows, threat counters, countries and visible DNS names
- Country Analytics with Top-3 local prefix-derived destinations and proportional bars
- 24-hour Android traffic totals with per-app RX/TX bars

### XDR Security Center

The XDR surface is deliberately split into two modes:

- **Findings** is the operational view: correlated incidents, severity, score, recommendation, quarantine action and a direct forensic drill-down.
- **Forensics** is the diagnostic view: detector raw score, XDR correlation score, exact score recipe, structured finding weights, signer/APK hashes, installer/source, threat-intelligence matches and an evidence timeline that marks counted versus context-only events.

The two scores must never be visually collapsed into one value. A detector score describes the originating sensor; the XDR score describes correlation across evidence.

### Evidence

Policy, Threat Index, Evidence Ledger, Sync and System Integrity share one visual grammar and preserve deterministic fingerprints and authenticated evidence as technical details rather than decorative status claims.

## Safe-area contract

The full-screen `CyberBackgroundView` may render behind system bars and camera-cutout regions. Interactive UI may not.

`MainActivity` computes safe content insets from both:

1. `WindowInsets.systemWindowInset*`
2. `DisplayCutout.safeInset*`

For each side the larger inset wins. The content shell receives top/left/right safe padding; the bottom navigation receives the navigation/gesture bottom inset. This handles:

- centered hole-punch cameras
- left/right offset hole-punch cameras
- wide notches
- landscape side cutouts
- gesture navigation
- classic three-button navigation
- OEM status-bar height differences

`LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES` is safe because only the decorative background may enter the cutout region. Interactive content is explicitly inset back into the safe rectangle.

## Responsive rules

- No screen content assumes a particular pixel width.
- Main surfaces use match-parent width with density-independent padding.
- Home metric cards use weighted two-column rows on normal phones.
- Below `360dp`, Home metric cards stack vertically.
- Quick actions use weighted rows rather than fixed button widths.
- Traffic/country rows use weighted labels and progress bars instead of fixed text columns.
- Text wraps and action controls use minimum heights rather than fixed heights.
- Configuration recreation recalculates the narrow/normal layout from `screenWidthDp`.
- Scrollable content retains bottom breathing room above the persistent navigation bar.

## Required device tests

| Class | Examples to cover | Gate |
|---|---|---|
| Small phone | ~320-359dp width | No clipped cards or horizontal overflow |
| Normal phone | ~360-411dp width | Two-column Home grid remains readable |
| Large phone | 412dp+ | No excessive fixed-width gaps |
| Center hole-punch | Pixel/Galaxy style | Header begins below camera/status region |
| Offset hole-punch | left/right camera | Header does not slide under cutout |
| Notch | narrow and wide | Safe top inset is respected |
| Gesture nav | bottom gesture pill | Bottom nav remains fully tappable |
| 3-button nav | classic navbar | Bottom nav stays above system buttons |
| Landscape | side cutout/status bar | Left/right safe insets are respected |
| Font scale | 1.0 / 1.15 / 1.3 / 1.5 | No critical controls clipped |
| Rotation | portrait -> landscape -> portrait | Navigation and safe-area layout rebuild cleanly |

## Non-goal

The visual redesign does not change packet enforcement semantics. `ROUTE_BLOCK`, `CORRELATE_ONLY` and `ANNOTATE_ONLY` authority remain defined by the threat-intelligence policy layer. UI labels and colors must never imply that annotation-only or correlate-only data is actively blocked.

## 0.6.2 visual composition invariants

- Protection-state energy is rendered only inside the hero stage. Active protection may animate; inactive protection remains visually calm.
- The GeDefense PNG shield stays transparent and is never baked onto a colored bitmap background.
- Standard cards use neutral glass borders. Semantic colors are reserved for icon wells, thin accent rules, status pills and critical states.
- BLOCK uses red, CORRELATE uses gold, ANNOTATE uses blue. These semantics must never be inferred from decorative color alone.
- Typography uses system sans-serif roles only: medium for display/title/metrics, regular for support copy, monospace only for hashes and fingerprints.
- Bottom navigation uses a small gold focus rail and icon/label color shift instead of a large solid selected tab.
- All screens remain inside the cutout-safe shell; decorative background and hero energy can draw edge-to-edge, interactive content cannot.

## 0.6.3 spacing and atlas invariants

- Adaptive horizontal gutters are 22dp on common 350-389dp phones, 24dp at 390-429dp, 27dp at 430-519dp and 30dp on larger layouts; narrower devices retain an 18dp floor.
- Major cards are separated by 18-22dp depending on width. Nested rows stay visually grouped and do not inherit the larger section gap.
- The Data-Flow Atlas is an offline custom `View`; no tile provider, WebView, map SDK or network geocoder may be introduced.
- Live routes are bounded to 12 visual arcs and aggregate only existing local app/country telemetry.
- Destination points are country-level GeoIP anchors and must be disclosed as such; the UI may never imply exact server coordinates.
- Device origin defaults to an approximate country centroid. Optional coarse location is quantized before display and is never persisted as an exact pin or uploaded.
- Decorative map/hero resources may be richer than standard cards, but all controls and text remain inside the normal safe-area content gutters.

## TITAN / managed-device visual mode

TITAN appears under More and has two explicit visual states. In Standard Mode, the screen uses a spacious status hero, a three-tile command deck and separate provisioning-method cards instead of dense nested paragraphs. QR/managed-device provisioning, ADB provisioning and Xiaomi/HyperOS guidance are visually separated; long commands use monospace and remain independently copyable. Capability rows are standalone cards so labels can wrap without colliding with status badges.

When Android actually reports GeDefense as Device Owner, `TitanVisualMode` activates an app-wide managed-device treatment: `TitanManagedBanner` sits above the primary content shell, common panels/navigation gain controlled gold/cyan managed accents and `CyberBackgroundView` adds a bounded TITAN atmospheric layer. The treatment is state-driven and disappears if Device Owner is no longer effective. It never grants policy authority by itself.

The Xiaomi/HyperOS assistant may show the OEM path `Settings -> Additional settings -> Enterprise mode` and Xiaomi-specific enterprise activation context, but must state that Xiaomi Enterprise Mode does not itself make GeDefense Android Device Owner. Android managed-device provisioning or the eligible ADB DPC flow remains required.

Destructive controls (wipe threshold, managed uninstall, CA trust-anchor installation) always require a second explicit confirmation. Effective state badges are sourced from Android readback, not optimistic button state. TITAN animation uses the same adaptive UI-performance governor and may reduce decorative cadence without reducing security sensor cadence.


## 0.17 information architecture

- **Start** keeps the existing protection hero and fast actions, with one compact **Current Analysis** card for live scan progress and the highest-priority malware findings.
- **Activity** remains the event / traffic operational timeline.
- **Protection** owns VPN state, protection mode, Always-on / Kill Switch resilience, firewall, Port Sentinel, integrity and threat-intelligence health.
- **Analysis** owns malware scanning, findings, XDR correlation, behavioral analysis, network discovery, Evidence and forensic trust state.
- **System** owns hardening posture, TITAN, Android permissions/setup and runtime/platform health.

The bottom navigation uses a fixed visual height. Gesture/navigation insets are represented as external bottom margin rather than internal glass padding, keeping the dock visually slim while preserving touch safety.

## Resilience and power UX

- Protection surfaces expose Android Always-on, Kill Switch, adaptive power-governor state and cumulative successful Full Flow recoveries separately.
- Recovery Self-Test is a deliberate operator action, disabled unless Full Flow is active and Android Kill Switch/Lockdown is confirmed.
- Hidden/background windows perform no decorative frame polling. Animation cadence is a presentation budget only and never represents reduced protection.
- Live Activity retains detailed foreground telemetry; background byte counters may be coalesced without suppressing flow-open/close or block events.



## 0.20 management and trust UX

TITAN Light uses the TITAN visual language with cyan LIGHT status while full managed-device TITAN retains the gold/managed treatment. App findings below the review threshold are removed from actionable findings but remain available to XDR correlation. Elevated app cards and XDR incidents can expose a signer-bound approval action. The Home header includes “powered by VisionGaiaTechnology”; System includes the Support VGT page.
