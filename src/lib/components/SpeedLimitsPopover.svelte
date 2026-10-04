<script lang="ts">
  import { tick, untrack } from 'svelte';
  import { get } from 'svelte/store';
  import { goto } from '$app/navigation';
  import { listen } from '@tauri-apps/api/event';
  import * as m from '$lib/paraglide/messages';
  import { portal } from '$lib/actions/portal';
  import { appSettings, setAppSettings } from '$lib/stores/settings';
  import { getSettings, setQuickLimits, type QuickLimitsPatch } from '$lib/api/settings';
  import { getRuntimeStatus } from '$lib/api/system';
  import { translateError } from '$lib/i18n';
  import { addToast } from '$lib/stores/toast';
  import type { AppSettings, RuntimeStatus } from '$lib/types';
  import SpeedInput from './SpeedInput.svelte';
  import ToggleSwitch from './ToggleSwitch.svelte';

  let {
    open = $bindable(false),
    anchor,
  }: {
    open?: boolean;
    /** What the popover sits above, and where focus returns on close. */
    anchor: HTMLElement | undefined;
  } = $props();

  type Limits = { up: number; down: number; altUp: number; altDown: number };

  function limitsOf(s: AppSettings): Limits {
    return {
      up: s.max_upload_speed,
      down: s.max_download_speed,
      altUp: s.alt_max_upload_speed,
      altDown: s.alt_max_download_speed,
    };
  }

  let popoverEl = $state<HTMLDivElement>();
  let altOn = $state(false);
  let draft = $state<Limits>({ up: 0, down: 0, altUp: 0, altDown: 0 });
  /** What the draft was seeded from, so a change saved elsewhere only replaces
   *  the fields not edited here. */
  let baseline = $state<Limits>({ up: 0, down: 0, altUp: 0, altDown: 0 });
  let loaded = $state(false);
  let saving = $state(false);
  let scheduleLabel = $state<string | null>(null);
  let placement = $state({ bottom: 0, right: 0 });

  const dirty = $derived(
    draft.up !== baseline.up
      || draft.down !== baseline.down
      || draft.altUp !== baseline.altUp
      || draft.altDown !== baseline.altDown,
  );

  function seed(s: AppSettings) {
    const next = limitsOf(s);
    const keys = Object.keys(next) as (keyof Limits)[];
    for (const key of keys) {
      if (!loaded || draft[key] === baseline[key]) draft[key] = next[key];
    }
    baseline = next;
    altOn = s.alt_speed_enabled;
    loaded = true;
  }

  function place() {
    if (!anchor) return;
    const r = anchor.getBoundingClientRect();
    placement = {
      bottom: Math.max(8, window.innerHeight - r.top + 6),
      right: Math.max(8, window.innerWidth - r.right),
    };
  }

  function scheduleText(status: RuntimeStatus): string | null {
    if (status.alt_speed || !status.schedule) return null;
    return status.schedule.label || m.schedule_unnamed_rule();
  }

  async function load() {
    loaded = false;
    const cached = get(appSettings);
    if (cached) seed(cached);
    try {
      const latest = await getSettings();
      setAppSettings(latest);
      seed(get(appSettings) ?? latest);
    } catch (e) {
      if (!cached) {
        addToast('error', translateError(e, m.statusbar_limits_save_failed()));
        open = false;
      }
    }
    getRuntimeStatus()
      .then((status) => (scheduleLabel = scheduleText(status)))
      .catch(() => (scheduleLabel = null));
  }

  async function save(patch: QuickLimitsPatch) {
    saving = true;
    try {
      const saved = await setQuickLimits(patch);
      setAppSettings(saved);
      // Written fields are now the baseline; anything else edited stays a draft.
      const next = limitsOf(saved);
      baseline = next;
      if (patch.max_upload_speed !== undefined) draft.up = next.up;
      if (patch.max_download_speed !== undefined) draft.down = next.down;
      if (patch.alt_max_upload_speed !== undefined) draft.altUp = next.altUp;
      if (patch.alt_max_download_speed !== undefined) draft.altDown = next.altDown;
      altOn = saved.alt_speed_enabled;
      return true;
    } catch (e) {
      addToast('error', translateError(e, m.statusbar_limits_save_failed()));
      const cached = get(appSettings);
      if (cached) altOn = cached.alt_speed_enabled;
      return false;
    } finally {
      saving = false;
    }
  }

  function toggleAlt(on: boolean) {
    // The set of limits the switch hides drops its unapplied edits: Apply
    // must not save numbers that are no longer on screen.
    if (on) {
      draft.up = baseline.up;
      draft.down = baseline.down;
    } else {
      draft.altUp = baseline.altUp;
      draft.altDown = baseline.altDown;
    }
    void save({ alt_speed_enabled: on });
  }

  async function apply() {
    if (!dirty || saving) return;
    const patch: QuickLimitsPatch = {};
    if (draft.up !== baseline.up) patch.max_upload_speed = draft.up;
    if (draft.down !== baseline.down) patch.max_download_speed = draft.down;
    if (draft.altUp !== baseline.altUp) patch.alt_max_upload_speed = draft.altUp;
    if (draft.altDown !== baseline.altDown) patch.alt_max_download_speed = draft.altDown;
    if (await save(patch)) close();
  }

  function close(refocus = true) {
    if (!open) return;
    open = false;
    if (refocus) anchor?.focus();
  }

  function openSettings() {
    close(false);
    void goto('/settings?section=bandwidth').catch((e) => console.warn('SpeedLimitsPopover: navigation failed', e));
  }

  $effect(() => {
    if (!open) return;
    // Only `open` is a dependency. Seeding reads the draft, and tracking it
    // would reload the saved values over every keystroke.
    return untrack(setUp);
  });

  $effect(() => {
    if (open && anchor) untrack(place);
  });

  function setUp() {
    place();
    void load();
    void tick().then(() => popoverEl?.querySelector<HTMLElement>('[role="switch"]')?.focus());

    const onKey = (e: KeyboardEvent) => {
      if (e.isComposing) return;
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        close();
      } else if (e.key === 'Enter' && e.target instanceof HTMLInputElement && popoverEl?.contains(e.target)) {
        e.preventDefault();
        void apply();
      }
    };
    const outside = (t: EventTarget | null) =>
      !(t instanceof Node && (popoverEl?.contains(t) || anchor?.parentElement?.contains(t)));
    const onPointer = (e: PointerEvent) => {
      if (outside(e.target)) close(false);
    };
    const onFocusIn = (e: FocusEvent) => {
      if (outside(e.target)) close(false);
    };
    const onReflow = () => place();
    window.addEventListener('keydown', onKey, true);
    window.addEventListener('pointerdown', onPointer, true);
    window.addEventListener('focusin', onFocusIn, true);
    window.addEventListener('resize', onReflow);

    const unsubscribe = appSettings.subscribe((s) => {
      if (s && loaded && !saving) seed(s);
    });
    let unlisten: (() => void) | null = null;
    let live = true;
    listen<RuntimeStatus>('ember:runtime-status', (event) => {
      scheduleLabel = scheduleText(event.payload);
    })
      .then((fn) => { if (live) unlisten = fn; else fn(); })
      .catch(() => {});

    return () => {
      live = false;
      unlisten?.();
      unsubscribe();
      window.removeEventListener('keydown', onKey, true);
      window.removeEventListener('pointerdown', onPointer, true);
      window.removeEventListener('focusin', onFocusIn, true);
      window.removeEventListener('resize', onReflow);
    };
  }
</script>

<div use:portal data-a11y-no-inert>
  {#if open}
    <div
      bind:this={popoverEl}
      class="limits-popover"
      style:bottom="{placement.bottom}px"
      style:right="{placement.right}px"
      role="dialog"
      aria-label={m.statusbar_limits_title()}
    >
      <div class="limits-header">
        <span class="limits-title">{m.statusbar_limits_title()}</span>
      </div>

      <div class="limits-alt">
        <div class="limits-alt-text">
          <span id="limits-alt-label" class="limits-alt-title">{m.statusbar_limits_alt()}</span>
          <span class="limits-alt-hint">{m.statusbar_limits_alt_hint()}</span>
        </div>
        <ToggleSwitch
          bind:checked={altOn}
          disabled={!loaded || saving}
          ariaLabelledby="limits-alt-label"
          onchange={toggleAlt}
        />
      </div>

      <p class="limits-section">
        {altOn ? m.statusbar_limits_alt_section() : m.statusbar_limits_normal_section()}
      </p>
      <div class="limits-inputs">
        {#if altOn}
          <SpeedInput bind:value={draft.altUp} label={m.statusbar_limits_upload()} idScope="limits-alt" />
          <SpeedInput bind:value={draft.altDown} label={m.statusbar_limits_download()} idScope="limits-alt" />
        {:else}
          <SpeedInput bind:value={draft.up} label={m.statusbar_limits_upload()} idScope="limits-normal" />
          <SpeedInput bind:value={draft.down} label={m.statusbar_limits_download()} idScope="limits-normal" />
        {/if}
      </div>

      {#if scheduleLabel && !altOn}
        <p class="limits-note" role="status">{m.statusbar_limits_schedule_note({ rule: scheduleLabel })}</p>
      {/if}

      <div class="limits-actions">
        <button type="button" class="ghost" onclick={openSettings}>{m.statusbar_limits_more()}</button>
        <button type="button" class="primary" disabled={!dirty || saving} onclick={() => void apply()}>
          {m.statusbar_limits_apply()}
        </button>
      </div>
    </div>
  {/if}
</div>

<style>
  .limits-popover {
    position: fixed;
    z-index: 10000;
    width: 320px;
    max-width: calc(100vw - 16px);
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding: 14px;
    background: var(--ctx-surface);
    border: 1px solid var(--ctx-border);
    border-radius: var(--radius-lg);
    box-shadow: var(--ctx-shadow);
    font-size: var(--font-size-md);
    animation: limits-pop-in 120ms ease-out;
  }

  @keyframes limits-pop-in {
    from { opacity: 0; transform: translateY(4px); }
    to { opacity: 1; transform: translateY(0); }
  }

  @media (prefers-reduced-motion: reduce) {
    .limits-popover { animation: none; }
  }

  .limits-title {
    font-weight: 600;
    color: var(--text-primary);
  }

  .limits-alt {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--ctx-divider);
  }

  .limits-alt-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .limits-alt-title {
    color: var(--text-primary);
  }

  .limits-alt-hint,
  .limits-section,
  .limits-note {
    margin: 0;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
  }

  .limits-note {
    color: var(--warning);
  }

  .limits-inputs {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .limits-actions {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
</style>
