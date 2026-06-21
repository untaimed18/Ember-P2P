# Ember — Proposed Settings & Options Plan

**Status:** Proposed / for review. No code has been written for these yet; several depend on decisions noted at the bottom.
**Context:** Ember is a Tauri (Rust) + SvelteKit desktop P2P client (eD2K / KAD + the Ember Noise transport) that runs in the background and seeds. The options below target the biggest gaps: OS integration, bandwidth control, notifications, and privacy.
**Effort legend:** S = small (established pattern, few files) · M = medium (new task/logic or plugin wiring) · L = large (cross-cutting, networking, higher risk).

---

## Quick reference

| Feature | Category | Effort | New dependency |
| --- | --- | --- | --- |
| Start with the OS (auto-launch) | OS/Window | M | `tauri-plugin-autostart` |
| Start minimized to tray | OS/Window | S | — |
| Remember window size & position | OS/Window | M | `tauri-plugin-window-state` |
| Default landing tab on launch | OS/Window | S | — |
| Download-complete notification (+ sound) | Notifications | M | `tauri-plugin-notification` |
| Bandwidth scheduler | Bandwidth | M/L | — |
| Alternate "turtle" limits + quick toggle | Bandwidth | S/M | `tauri-plugin-global-shortcut` (only if hotkey) |
| Low-disk-space guard | Transfers | M | — (uses `fs2`) |
| Pre-allocate disk space | Transfers | M | — (uses `fs2`) |
| Bind to a specific network interface/IP | Privacy/Net | L | — (uses `socket2`) |
| SOCKS5 / HTTP proxy | Privacy/Net | L | proxy crate(s) TBD |
| Require obfuscation (encrypted-only) | Privacy/Net | M | — |
| Clear-on-exit | Privacy/Net | M | — |
| Auto-update preferences (+ channel) | Updates | M | — (uses existing updater) |
| Accent color | UI/UX | S/M | — |
| UI density / scaling | UI/UX | S/M | — |
| Confirmation toggles | UI/UX | S | — |
| Open log folder button | Diagnostics | S | — (uses `opener`) |
| Log verbosity setting | Diagnostics | S–M | — |

---

## Common "add a setting" recipe

Almost every item below reuses this pattern (recently exercised with `launch_maximized`), so it is not repeated per feature:

- **Backend:** add a field to `AppSettings` in `src-tauri/src/types.rs` with `#[serde(default …)]` (plus a `default_*()` fn for non-`bool` defaults), update the `Default` impl, and add range checks in `validate_settings` (`src-tauri/src/commands/settings.rs`) for bounded values.
- **Launch-time vs live:** launch-time behavior (like `launch_maximized`) is applied in `lib.rs` `.setup()` after config load; live behavior is applied in the network task's `NetworkCommand::UpdateSettings` handler.
- **Frontend:** add the field to the `AppSettings` interface (`src/lib/types/index.ts`), a control in the relevant section of `src/routes/settings/+page.svelte` (plus numeric clamps in its `validateSettings`), and `*_label` / `*_hint` keys in `messages/en.json` + `messages/es.json`, then recompile Paraglide.
- **New OS capability / command:** add the Tauri plugin (`Cargo.toml` + JS package + `builder.plugin(...)` in `lib.rs`) and grant permissions in `src-tauri/capabilities/default.json`; new `#[tauri::command]`s must be registered in the `invoke_handler!` list and wrapped in `src/lib/api/*.ts`.
- **Migration safety:** `AppSettings` is `#[serde(deny_unknown_fields)]`, so any field **rename** needs `#[serde(alias = "old_name")]` (the `launch_fullscreen` lesson). Pure additions are safe via `#[serde(default)]`.
- **Verification per change:** `cargo check` / `cargo test`, `npm run check`, and a Paraglide recompile.

---

## Phase 1 — OS integration & window

Best value-to-effort and thematically consistent with the recent `launch_maximized` work.

### Start with the OS (auto-launch) — M, new dep `tauri-plugin-autostart`
Add the plugin plus an `autostart_enabled` setting. Toggling must call the plugin's enable/disable command (the OS registration is the source of truth), not merely persist a flag. Add the permission in `capabilities/default.json`. Pair with an `autostart_minimized` sub-option.

### Start minimized to tray — S
Add `start_minimized`; in `lib.rs` `.setup()`, if set, skip showing the window (or hide it immediately) so it boots straight to the tray.
**Decision:** interaction with `launch_maximized` — maximize the still-hidden window so it is correct when later shown from the tray.

### Remember window size & position — M, new dep `tauri-plugin-window-state`
Plugin auto-saves/restores window geometry on launch.
**Conflict to resolve:** window-state can also restore the *maximized* state, overlapping `launch_maximized`. Options: (a) keep both with a precedence rule (apply `launch_maximized` only when no saved maximized state exists), or (b) fold "maximized" into window-state and reframe the toggle as "restore last window state vs always maximize."

### Default landing tab on launch — S
Add `default_route` (`/transfers`, `/search`, …); the root layout / `+layout.ts` redirects on first load. Pure frontend.

---

## Phase 2 — Notifications

### Download-complete notification (+ optional sound) — M, new dep `tauri-plugin-notification`
Add the plugin and permissions. New settings: `notifications_enabled` (global) and `notify_on_download_complete`. Emit a native notification from the transfer-completion path (the network task already detects completion). Optional: bundle a sound asset with a `notification_sound` toggle. This can also upgrade `friend_online_notifications` from an in-app toast to a real OS notification.

---

## Phase 3 — Bandwidth & transfers

### Bandwidth scheduler — M/L
New settings: a list of rules `{ days, start, end, up_limit, down_limit }` (stored as JSON within `AppSettings`). A lightweight scheduler task (spawned in `lib.rs`) flips `BandwidthLimiter` limits when a rule window opens/closes. Reuses the existing limiter; main work is the rule model, the UI editor, and tests for boundary/overlap cases.

### Alternate "turtle" limits + quick toggle — S/M
Add `alt_limits_enabled`, `alt_up_limit`, `alt_down_limit`. A command + tray-menu entry (and optional global shortcut) flips between normal and alternate limits via `BandwidthLimiter`. Small if the hotkey is skipped.

### Low-disk-space guard — M
Add `min_free_space_gib`. Use `fs2` (already a dependency) to query free space on the download volume; in the download scheduler, refuse to start / auto-pause when below the threshold and surface a toast/notification.
**Decision:** check interval, and which volume to watch (download vs temp/part folder).

### Pre-allocate disk space — M
Add `preallocate_files`; call `fs2::FileExt::allocate` when creating a part file.
**Risk:** behavior differs across filesystems (NTFS vs others) and interacts with sparse part files — needs testing to avoid forcing full up-front writes where true preallocation is unsupported.

---

## Phase 4 — Privacy & network (highest effort/risk)

### Bind to a specific network interface/IP — L
Add `bind_address` (a dropdown of detected interfaces). Thread the chosen local IP into every outbound socket creation (eD2K TCP/UDP, KAD UDP, QUIC/Ember, reqwest). `socket2` is already present.
**Risk:** many call sites; must gracefully handle the bound IP disappearing (e.g., a VPN drop).

### SOCKS5 / HTTP proxy — L
Add `proxy_url` / auth settings. reqwest supports proxies easily, **but** raw eD2K/KAD sockets and UDP do not — SOCKS5 UDP-associate is complex and much peer traffic is UDP/KAD.
**Recommended scoping:** phase it as "proxy HTTP/relay/rendezvous traffic first," clearly labeling that core eD2K/KAD will not tunnel without major additional work.

### Require obfuscation (encrypted-only) — M
Add `require_obfuscation`; in the handshake/accept paths, reject unencrypted connections when set. Builds on the existing `obfuscation_enabled`.
**Risk:** can silently cut off legacy peers — call out the consequence in the hint text.

### Clear-on-exit — M
Add `clear_on_exit` choices (e.g., search history). Hook the existing `RunEvent::Exit` / shutdown sequence in `lib.rs` to wipe the selected stores before the process ends.

---

## Phase 5 — Updates

### Auto-update preferences — M
Add `auto_check_updates`, `auto_download`, and `update_channel` (stable/beta), wired into the existing `updater` store/flow.
**Implication:** channels require publishing a second `latest.json` endpoint and selecting it by setting — affects the release pipeline.

---

## Phase 6 — UI/UX polish (mostly frontend)

### Accent color — S/M
Add `accent_color`, applied by overriding the `--accent` CSS variable (theming already runs through CSS vars + a `theme` store). Add a swatch/color picker in General.

### UI density / scaling — S/M
Add `ui_density` (comfortable/compact) and/or `ui_scale`, applied via a root class or a CSS `font-size`/`zoom` variable. Mostly CSS.

### Confirmation toggles — S
Add e.g. `confirm_transfer_removal`; gate the existing `ConfirmDialog` calls on the setting.

---

## Phase 7 — Diagnostics (quick wins)

### Open log folder button — S
New command using the `opener` crate (already a dependency) to reveal the log directory from `storage::paths`. Add a button in the About/General section.

### Log verbosity setting — S (startup-only) / M (live)
Add `log_level`. Easy version: read it at startup to build the `EnvFilter` in `lib.rs` (instead of env only). Live-reload version requires a `tracing_subscriber` reload layer (more work). Recommend startup-only first.

---

## Decisions needed before building
- **Window state vs `launch_maximized`:** keep both with a precedence rule, or replace the toggle with "restore last window state"?
- **Proxy scope:** HTTP/relay-only (realistic) vs attempt full eD2K/KAD tunneling (large, possibly infeasible for UDP)?
- **Notifications:** also migrate `friend_online_notifications` to native OS notifications, or only add download-complete?
- **Hotkeys:** global shortcut for turtle mode (adds `tauri-plugin-global-shortcut`) or tray-menu only?
- **Update channels:** is the release pipeline able to publish a separate beta `latest.json`?

## Suggested sequencing
1. **Phase 1 + Phase 7** (OS/window + diagnostics) — high value, low risk, consistent with recent work.
2. **Phase 2** (notifications) — small, satisfying, reusable plumbing.
3. **Phase 3** (bandwidth/disk) — strong P2P value, moderate effort.
4. **Phase 6 + Phase 5** (polish + update preferences).
5. **Phase 4** (privacy/network) — highest effort/risk; benefits from the settings infrastructure maturing first.
