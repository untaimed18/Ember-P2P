<script lang="ts">
  import { onMount } from 'svelte';
  import { fly } from 'svelte/transition';
  import { cubicOut } from 'svelte/easing';
  import { prefersReducedMotion } from 'svelte/motion';
  import { goto } from '$app/navigation';
  import ChatConversation from '$lib/components/ChatConversation.svelte';
  import {
    chatTabs,
    activeChatTab,
    chatDockOpen,
    closeTab,
    setActiveTab,
    closeDock,
    cycleTab,
    openChat,
    focusNextUnread,
  } from '$lib/stores/chatTabs';
  import {
    unreadCounts,
    onlineFriends,
    friendsList,
    fileOffers,
    friendLabel,
    friendNames,
    acceptIncomingFileOffer,
    clearFileOffer,
  } from '$lib/stores/friends';
  import { appSettings } from '$lib/stores/settings';
  import { toastError, toastSuccess } from '$lib/stores/toast';
  import { formatBytes } from '$lib/utils';
  import { translateError } from '$lib/i18n';
  import * as m from '$lib/paraglide/messages';
  import { plural } from '$lib/plural';
  import IconX from '$lib/components/IconX.svelte';
  import { shortcutModAria } from '$lib/platform';
  import {
    clampDockWidth,
    maxDockWidth,
    preferredDockWidth,
    DOCK_WIDTH_DEFAULT,
    DOCK_WIDTH_MIN,
  } from '$lib/dockWidth';
  import { defaultSwitcherRow, filterSwitcherRows, searchNeedle } from '$lib/dockSearch';
  import { dockBack, popOutChat, showInMainWindow } from '$lib/chatPopout';

  /** Drawn as the whole of the popped-out chat window rather than as a panel
   *  over the main window: always open, full size, and closing it docks the
   *  chat back into the main window. */
  let { windowed = false }: { windowed?: boolean } = $props();
  let open = $derived(windowed || $chatDockOpen);

  /**
   * How wide the dock is, in pixels, remembered per device.
   *
   * It used to be `min(420px, 40vw)` and nothing else — a fixed panel on every
   * window, at a size chosen for a glance at one line rather than for the
   * thing people actually do in it, with no way to change it.
   */
  const DOCK_WIDTH_KEY = 'ember.chatDock.width.v1';

  /** Svelte runs transitions through the Web Animations API, which the global
   *  reduced-motion rule in `app.css` does not reach — so it is checked here. */
  const dockTransition = () => ({
    x: prefersReducedMotion.current ? 0 : 24,
    duration: prefersReducedMotion.current || windowed ? 0 : 180,
    easing: cubicOut,
  });

  /** The window as the clamp needs to see it. Zero before the DOM exists,
   *  which `maxDockWidth` treats as "no measurement" rather than "no room". */
  function viewport(): number {
    return typeof window === 'undefined' ? 0 : window.innerWidth;
  }

  function loadPreferredWidth(): number {
    try {
      if (typeof localStorage === 'undefined') return DOCK_WIDTH_DEFAULT;
      return preferredDockWidth(localStorage.getItem(DOCK_WIDTH_KEY));
    } catch {
      return DOCK_WIDTH_DEFAULT;
    }
  }

  /** What the user asked for, and what is saved. The window only ever limits
   *  what is drawn: narrowing it past this must not rewrite the preference, or
   *  widening it again would not bring the dock back to where they left it. */
  let preferredWidth = $state(loadPreferredWidth());
  let viewportWidth = $state(viewport());
  let dockWidth = $derived(clampDockWidth(preferredWidth, viewportWidth));
  let dockWidthMax = $derived(maxDockWidth(viewportWidth));
  let resizing = $state(false);

  function persistDockWidth() {
    try {
      if (typeof localStorage === 'undefined') return;
      localStorage.setItem(DOCK_WIDTH_KEY, String(preferredWidth));
    } catch {
      // Quota exceeded / private mode. The width holds for this session.
    }
  }

  /** `persist` is false mid-drag: writing on every pointer move would put a
   *  synchronous `localStorage` write inside the frame doing the resizing. */
  function setDockWidth(px: number, persist = true) {
    viewportWidth = viewport();
    preferredWidth = clampDockWidth(px, viewportWidth);
    if (persist) persistDockWidth();
  }

  /** The drag's one write. Also reached when the dock closes mid-drag: the
   *  handle leaves the DOM with the pointer still down, so neither `pointerup`
   *  nor its own `lostpointercapture` ever arrives to end it. */
  function finishResize() {
    if (!resizing) return;
    resizing = false;
    persistDockWidth();
  }

  function onResizeStart(e: PointerEvent) {
    if (e.pointerType === 'mouse' && e.button !== 0) return;
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    resizing = true;
    // Or the drag selects the transcript it is dragging across.
    e.preventDefault();
  }

  function onResizeMove(e: PointerEvent) {
    if (!resizing) return;
    // The dock is anchored to the right edge, so its width is simply how far
    // the pointer is from that edge — no need to track where the drag began.
    setDockWidth(window.innerWidth - e.clientX, false);
  }

  function onResizeEnd(e: PointerEvent) {
    if (!resizing) return;
    finishResize();
    const handle = e.currentTarget as HTMLElement;
    if (handle.hasPointerCapture(e.pointerId)) handle.releasePointerCapture(e.pointerId);
  }

  /** The separator is focusable, so it answers the keys a separator should:
   *  arrows nudge, Home/End go to the extremes, Enter restores the default. */
  function onResizeKeydown(e: KeyboardEvent) {
    const step = e.shiftKey ? 64 : 16;
    // Left grows it, because the dock opens leftwards from the right edge.
    if (e.key === 'ArrowLeft') setDockWidth(dockWidth + step);
    else if (e.key === 'ArrowRight') setDockWidth(dockWidth - step);
    else if (e.key === 'Home') setDockWidth(dockWidthMax);
    else if (e.key === 'End') setDockWidth(DOCK_WIDTH_MIN);
    else if (e.key === 'Enter' || e.key === ' ') setDockWidth(DOCK_WIDTH_DEFAULT);
    else return;
    e.preventDefault();
    e.stopPropagation();
  }

  let panelEl: HTMLDivElement | undefined = $state();
  let returnFocusEl: HTMLElement | null = null;
  let acceptingOffer: string | null = $state(null);
  let chatDisabled = $derived($appSettings?.friend_chat_disabled === true);
  let pendingOffers = $derived($fileOffers);

  /**
   * The conversation switcher: search box over one flat list.
   *
   * It replaces a horizontal tab strip, which was the wrong shape for the
   * number of things it had to hold. Tabs floor at 96px and the dock defaults
   * to 420px, so about three were ever visible while the store allows fifty —
   * and nothing brought the rest back. `Ctrl+Tab` set the active tab without
   * scrolling the strip to it, so it switched to a conversation that was not on
   * screen; an unread badge on tab twelve was as invisible as the tab. A
   * vertical list is not subject to that: every conversation is reachable by
   * scrolling, and by typing two letters of a name once there are enough of
   * them for scrolling to be the wrong answer too.
   */
  let switcherOpen = $state(false);
  let query = $state('');
  /** Highlighted row, by hash, or null for none. Mouse hover sets it too, so
   *  nothing destructive may hang off it — see the `Delete` handler. Held by
   *  identity rather than position so a row leaving the list or a re-sort
   *  cannot leave the highlight past the end or move it onto someone else. */
  let activeHash = $state<string | null>(null);
  let switcherEl: HTMLDivElement | undefined = $state();
  let searchEl: HTMLInputElement | undefined = $state();
  let switchBtnEl: HTMLButtonElement | undefined = $state();

  const LISTBOX_ID = 'chat-dock-switcher-list';

  type SwitcherRow = {
    /** `open` rows are conversations already in the dock; `friend` rows start
     *  a new one. The distinction drives the close button and the section. */
    kind: 'open' | 'friend';
    hash: string;
    name: string;
    /** `name` as drawn: with a short hash when it could pass for another
     *  friend's. `name` stays bare for search and for the tab it opens. */
    label: string;
    online: boolean;
    unread: number;
  };

  function isOnline(hash: string): boolean {
    return $onlineFriends.has(hash.toLowerCase());
  }

  let openRows = $derived<SwitcherRow[]>(
    $chatTabs.map((tab) => ({
      kind: 'open' as const,
      hash: tab.hash,
      name: tab.name,
      label: friendLabel(tab.hash, tab.name, $friendNames),
      online: isOnline(tab.hash),
      unread: $unreadCounts.get(tab.hash) ?? 0,
    })),
  );

  /**
   * Friends without an open conversation, so the list never offers to "start"
   * something that is already three rows above under Open.
   *
   * Online first, then by name — the order the old picker used, kept because it
   * answers the question people actually open this to ask.
   */
  let friendRows = $derived<SwitcherRow[]>(
    chatDisabled
      ? []
      : [...$friendsList]
          .filter(
            (f) => !$chatTabs.some((t) => t.hash === f.user_hash.toLowerCase()),
          )
          .map((f) => {
            const hash = f.user_hash.toLowerCase();
            return {
              kind: 'friend' as const,
              hash,
              name: f.nickname?.trim() || $friendNames.get(hash) || `${hash.slice(0, 8)}\u2026`,
              label: friendLabel(hash, f.nickname, $friendNames),
              online: isOnline(f.user_hash),
              unread: 0,
            };
          })
          .sort((a, b) => {
            if (a.online !== b.online) return a.online ? -1 : 1;
            return a.name.localeCompare(b.name);
          }),
  );

  let needle = $derived(searchNeedle(query));
  let shownOpen = $derived(filterSwitcherRows(openRows, needle));
  let shownFriends = $derived(filterSwitcherRows(friendRows, needle));
  /** One index space over both sections, so the arrow keys cross the section
   *  heading the way the eye does. */
  let rows = $derived([...shownOpen, ...shownFriends]);
  /** Position of the highlight in `rows`, or -1 for none. */
  let activeIndex = $derived(
    activeHash === null ? -1 : rows.findIndex((r) => r.hash === activeHash),
  );

  function highlight(index: number) {
    activeHash = rows[index]?.hash ?? null;
  }

  let activeTab = $derived(
    $activeChatTab ? $chatTabs.find((t) => t.hash === $activeChatTab) ?? null : null,
  );
  let activeTabLabel = $derived(
    activeTab ? friendLabel(activeTab.hash, activeTab.name, $friendNames) : '',
  );

  /**
   * Unread in conversations that are open but not on screen.
   *
   * The dock shows one conversation at a time, so without this the only signal
   * that another one is waiting was a badge on a tab that had usually scrolled
   * out of the strip. Clicking it goes to that conversation rather than merely
   * reporting the number, which is what makes it an answer instead of a nag.
   */
  let unreadElsewhere = $derived(
    openRows.reduce((sum, r) => (r.hash === $activeChatTab ? sum : sum + r.unread), 0),
  );
  let unreadElsewhereLabel = $derived(
    plural(unreadElsewhere, {
      one: m.chat_dock_unread_elsewhere_one,
      few: () => m.chat_dock_unread_elsewhere_few({ count: unreadElsewhere }),
      other: () => m.chat_dock_unread_elsewhere_other({ count: unreadElsewhere }),
    }),
  );

  function openSwitcher() {
    switcherOpen = true;
    query = '';
    activeHash = null;
    // Deferred: the input does not exist until this state change renders.
    requestAnimationFrame(() => searchEl?.focus());
  }

  function closeSwitcher(restoreFocus = true) {
    if (!switcherOpen) return;
    switcherOpen = false;
    activeHash = null;
    if (restoreFocus) switchBtnEl?.focus();
  }

  function toggleSwitcher() {
    if (switcherOpen) closeSwitcher();
    else openSwitcher();
  }

  function activateRow(row: SwitcherRow) {
    if (row.kind === 'open') {
      setActiveTab(row.hash);
    } else {
      if (chatDisabled) return;
      openChat(row.hash, row.name);
    }
    closeSwitcher();
  }

  /** Close an open conversation from inside the list, keeping the list open —
   *  tidying up several at once is the reason to be in here. */
  function closeRow(row: SwitcherRow) {
    if (row.kind !== 'open') return;
    closeTab(row.hash);
    // The dock collapses when the last conversation goes, and a switcher over a
    // dock that is no longer there would have nothing behind it.
    if ($chatTabs.length === 0) closeSwitcher(false);
    else searchEl?.focus();
  }

  function onSearchKeydown(e: KeyboardEvent) {
    // WebKit reports the Enter that commits an IME composition as keyCode 229
    // with `isComposing` already false.
    if (e.isComposing || e.keyCode === 229) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (rows.length === 0) return;
      const step = e.key === 'ArrowDown' ? 1 : -1;
      // From "no highlight", Down opens at the top and Up at the bottom, which
      // is how every other list in the app answers those keys.
      highlight(
        activeIndex === -1
          ? step === 1
            ? 0
            : rows.length - 1
          : (activeIndex + step + rows.length) % rows.length,
      );
      return;
    }
    if (e.key === 'Home' || e.key === 'End') {
      if (rows.length === 0) return;
      e.preventDefault();
      highlight(e.key === 'Home' ? 0 : rows.length - 1);
      return;
    }
    if (e.key === 'Enter') {
      // Nothing highlighted takes the best match, so the whole gesture is
      // "type two letters, press Enter" without an arrow key in between.
      const row = rows[activeIndex] ?? defaultSwitcherRow(rows, needle);
      if (!row) return;
      e.preventDefault();
      activateRow(row);
      return;
    }
    if (e.key === 'Delete') {
      // Delete only, never Backspace: `activeIndex` follows mouse hover, so
      // Backspace closing a conversation would fire while someone is fixing a
      // typo. Same reasoning as the recent-search list in `SearchBar`.
      const row = rows[activeIndex];
      if (!row || row.kind !== 'open') return;
      e.preventDefault();
      closeRow(row);
    }
  }

  function onSearchInput() {
    // Typing means the query is being edited, not the list navigated. Dropping
    // the highlight also disarms Delete for a row the pointer merely passed.
    activeHash = null;
  }

  function isTypingTarget(t: EventTarget | null): boolean {
    if (!(t instanceof HTMLElement)) return false;
    const tag = t.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
    if (t.isContentEditable) return true;
    return false;
  }

  $effect(() => {
    if (!open) {
      closeSwitcher(false);
      finishResize();
    }
  });

  // Activate the dock as a focus context so screen readers announce
  // it as a landmark and focus lands somewhere useful. We bail early if
  // the dock is closed so the rest of the app keeps full focus.
  $effect(() => {
    if (open && panelEl) {
      const active = typeof document !== 'undefined' ? document.activeElement : null;
      if (active instanceof HTMLElement && active !== document.body) {
        returnFocusEl = active;
      }
      // Defer focus until after the slide-in transition lands; an
      // immediate `focus()` during the same frame the panel mounts
      // can be vetoed by the browser.
      requestAnimationFrame(() => panelEl?.focus());
    }
    return () => {
      if (!open && returnFocusEl) {
        const el = returnFocusEl;
        returnFocusEl = null;
        requestAnimationFrame(() => {
          if (typeof document !== 'undefined' && document.contains(el)) el.focus();
        });
      }
    };
  });

  // Global hotkeys, scoped to "dock is open". Esc closes the switcher and then
  // the dock (tabs are preserved either way); Ctrl+Tab cycles conversations;
  // Ctrl+W closes the active one; Ctrl+K opens the switcher. Ctrl+Tab is
  // intercepted only when the dock is open so it doesn't fight with the
  // OS-level browser tab cycle in the rest of the app.
  function onKeydown(e: KeyboardEvent) {
    if (!open) return;
    // An open modal owns the keyboard. Its handlers sit on the dialog element
    // and let the event bubble to this window listener, so without this guard
    // one Escape both dismisses the dialog and collapses the dock behind it,
    // Ctrl+W closes a conversation behind a confirm, and Ctrl+K pulls focus
    // out of the dialog.
    if (typeof document !== 'undefined' && document.querySelector('[aria-modal="true"]')) {
      return;
    }
    // Something closer to the target already answered the key — for Escape,
    // page chrome such as the recent-search dropdown, column menus, clearing a
    // filter. Don't answer it a second time.
    if (e.defaultPrevented) return;
    // Esc — close the dock. Allowed even from inputs because users
    // press it instinctively to dismiss overlays.
    if (e.key === 'Escape') {
      if (switcherOpen) {
        e.preventDefault();
        closeSwitcher();
        return;
      }
      // A stray Escape dismisses a panel; it should not close a window.
      if (windowed) return;
      e.preventDefault();
      closeDock();
      return;
    }
    if (!(e.ctrlKey || e.metaKey)) return;
    if (e.key === 'Tab') {
      // Tab cycling shouldn't fire while typing in an input — users
      // need the regular Tab semantics to escape the textarea — but
      // Ctrl+Tab is the universal cycle gesture, so honour it
      // everywhere inside the dock.
      e.preventDefault();
      cycleTab(e.shiftKey ? -1 : 1);
      return;
    }
    if (e.key === 'k' || e.key === 'K') {
      // The find-anything gesture, and the reason the list can be long: with
      // fifty conversations allowed, typing a name has to beat scrolling to it.
      //
      // Shared with the Channels page, whose room search answers it unless
      // focus is in here. That page listens on `document`, ahead of this
      // `window` listener, and claims the key with `preventDefault` — which the
      // `defaultPrevented` guard above turns into this branch standing down.
      e.preventDefault();
      if (switcherOpen) searchEl?.focus();
      else openSwitcher();
      return;
    }
    if ((e.key === 'w' || e.key === 'W') && !isTypingTarget(e.target)) {
      // Ctrl+W is "close window" in the OS, but here it's "close
      // conversation" — the dock isn't a real window so we can safely
      // repurpose it. Disabled while typing so a user mid-message doesn't lose
      // their conversation by reflex.
      e.preventDefault();
      const active = $activeChatTab;
      if (active) closeTab(active);
      return;
    }
  }

  // A window narrowed past the stored width would otherwise leave the dock
  // covering the app with no way back except widening the window again. Only
  // the drawn width follows; the preference comes back when the window does.
  function onWindowResize() {
    viewportWidth = viewport();
  }

  // A panel that only Escape can dismiss is one users leave open by accident —
  // it covers the conversation behind it. `pointerdown` rather than `click` so
  // it is gone before whatever was clicked underneath reacts.
  function onPointerDown(e: PointerEvent) {
    if (!switcherOpen) return;
    const target = e.target;
    if (!(target instanceof Node)) return;
    if (switcherEl?.contains(target) || switchBtnEl?.contains(target)) return;
    closeSwitcher(false);
  }

  onMount(() => {
    window.addEventListener('keydown', onKeydown);
    window.addEventListener('resize', onWindowResize);
    window.addEventListener('pointerdown', onPointerDown, true);
    onWindowResize();
    return () => {
      window.removeEventListener('keydown', onKeydown);
      window.removeEventListener('resize', onWindowResize);
      window.removeEventListener('pointerdown', onPointerDown, true);
    };
  });

  function handleNewChat() {
    if (chatDisabled || $friendsList.length === 0) {
      closeSwitcher(false);
      if (windowed) {
        showInMainWindow('/friends');
        return;
      }
      void goto('/friends').catch((e) => console.warn('Failed to open Friends page:', e));
      return;
    }
    if (switcherOpen) searchEl?.focus();
    else openSwitcher();
  }

  function goToUnread() {
    if (!focusNextUnread()) return;
    closeSwitcher(false);
  }

  async function acceptDockOffer(offer: (typeof pendingOffers)[number]) {
    const key = `${offer.user_hash}:${offer.file_hash}`;
    if (acceptingOffer) return;
    acceptingOffer = key;
    try {
      const res = await acceptIncomingFileOffer(offer);
      toastSuccess(
        res?.already_queued
          ? m.search_already_queued_name({ name: offer.file_name })
          : m.friends_offer_accepted({ name: offer.file_name }),
      );
    } catch (e) {
      toastError(translateError(e));
    } finally {
      acceptingOffer = null;
    }
  }
</script>

{#if open}
  <!--
    No backdrop overlay: the dock is intentionally non-modal so the
    user can keep clicking through to /friends, /transfers, /library
    while a conversation stays alive on the right side of the
    screen. Dismissal is via the explicit close-X, the Esc hotkey,
    or the Ctrl+/ toggle in the sidebar — all signposted by tooltips
    and keyboard hints.
  -->
  <!--
    `role="complementary"` (rather than `dialog`) is the right
    landmark for a persistent panel that supports — but doesn't
    interrupt — the main page. `aria-modal` only carries meaning on
    dialog/alertdialog, so we omit it here. `aria-keyshortcuts`
    nudges screen readers to announce the Esc/Ctrl+/ dismiss
    affordance, which is the only escape hatch now that there's no
    backdrop to click.
  -->
  <div
    class="chat-dock"
    class:resizing
    class:windowed
    style={windowed ? undefined : `width: ${dockWidth}px`}
    bind:this={panelEl}
    role={windowed ? 'main' : 'complementary'}
    aria-label={m.chat_dock_aria_label()}
    aria-keyshortcuts={windowed ? undefined : `Escape ${shortcutModAria()}+/`}
    tabindex="-1"
    transition:fly={dockTransition()}
  >
    {#if !windowed}
    <!--
      A real separator rather than a decorative grip: it is focusable and
      answers arrows, so the panel can be sized without a pointer at all.
      `touch-action: none` in the stylesheet is what stops a touch drag here
      scrolling the page instead of resizing.
    -->
    <!-- A focusable `separator` carrying `aria-value*` is the WAI-ARIA window
         splitter, which *is* a widget — the rules below assume `separator`
         is always the decorative kind and cannot tell the two apart. -->
    <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
    <div
      class="dock-resize"
      role="separator"
      aria-orientation="vertical"
      aria-label={m.chat_dock_resize()}
      aria-valuenow={dockWidth}
      aria-valuemin={DOCK_WIDTH_MIN}
      aria-valuemax={dockWidthMax}
      title={m.chat_dock_resize_title()}
      tabindex="0"
      onpointerdown={onResizeStart}
      onpointermove={onResizeMove}
      onpointerup={onResizeEnd}
      onpointercancel={onResizeEnd}
      onlostpointercapture={onResizeEnd}
      ondblclick={() => setDockWidth(DOCK_WIDTH_DEFAULT)}
      onkeydown={onResizeKeydown}
    ></div>
    {/if}

    <!--
      One header naming the conversation on screen, in place of a strip of
      tabs. It is the switcher's trigger, so the thing that says where you are
      is also the thing that takes you elsewhere.
    -->
    <div class="dock-head">
      <button
        type="button"
        class="dock-current"
        class:open={switcherOpen}
        bind:this={switchBtnEl}
        aria-haspopup="listbox"
        aria-expanded={switcherOpen}
        aria-controls={LISTBOX_ID}
        aria-keyshortcuts={`${shortcutModAria()}+K`}
        title={m.chat_dock_switcher_label()}
        onclick={toggleSwitcher}
      >
        {#if activeTab}
          <!-- Named, not decorative: the header says nothing else about whether
               the friend is reachable, so hiding the dot hides the state. -->
          <span
            class="dock-presence"
            class:online={isOnline(activeTab.hash)}
            role="img"
            aria-label={isOnline(activeTab.hash)
              ? m.chat_online_label()
              : m.chat_offline_label()}
            title={isOnline(activeTab.hash)
              ? m.chat_online_label()
              : m.chat_offline_label()}
          ></span>
          <span class="dock-current-name"><bdi dir="auto">{activeTabLabel}</bdi></span>
        {:else}
          <span class="dock-current-name dock-current-none">{m.chat_dock_none_selected()}</span>
        {/if}
        <svg
          class="dock-chevron"
          viewBox="0 0 16 16"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          <path d="M4 6.5l4 4 4-4"/>
        </svg>
      </button>

      {#if activeTab}
        <span class="dock-encrypted" role="img" title={m.chat_encrypted_title()} aria-label={m.chat_encrypted_aria()}>
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <rect x="3.5" y="7" width="9" height="6.5" rx="1.5"/>
            <path d="M5.5 7V5.5a2.5 2.5 0 0 1 5 0V7"/>
          </svg>
        </span>
      {/if}

      {#if unreadElsewhere > 0}
        <!-- A count that goes somewhere. Without this the only report of a
             waiting conversation was a badge on a tab that had scrolled away. -->
        <button
          type="button"
          class="dock-elsewhere"
          title={unreadElsewhereLabel}
          aria-label={unreadElsewhereLabel}
          onclick={goToUnread}
        >
          {unreadElsewhere > 99 ? '99+' : unreadElsewhere}
        </button>
      {/if}

      <button
        type="button"
        class="dock-new"
        title={m.chat_dock_new_chat()}
        aria-label={m.chat_dock_new_chat()}
        onclick={handleNewChat}
      >
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <line x1="8" y1="3" x2="8" y2="13"/>
          <line x1="3" y1="8" x2="13" y2="8"/>
        </svg>
      </button>
      {#if !windowed}
        <button
          type="button"
          class="dock-new"
          title={m.chat_dock_pop_out()}
          aria-label={m.chat_dock_pop_out()}
          onclick={popOutChat}
        >
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M9 2.5h4.5V7"/>
            <path d="M13.5 2.5L8 8"/>
            <path d="M12 9.5v3a1 1 0 01-1 1H3.5a1 1 0 01-1-1V5a1 1 0 011-1h3"/>
          </svg>
        </button>
      {/if}
      <button
        type="button"
        class="dock-close"
        title={windowed ? m.chat_window_close() : m.chat_dock_close_title()}
        aria-label={windowed ? m.chat_window_close() : m.chat_dock_close_aria()}
        onclick={windowed ? () => void dockBack() : closeDock}
      >
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M3.5 3.5l9 9M12.5 3.5l-9 9"/>
        </svg>
      </button>
    </div>

    <div class="dock-body">
      {#if switcherOpen}
        <!--
          A filtered listbox driven from the search field, which keeps focus:
          the rows are announced through `aria-activedescendant` rather than by
          moving focus into them, so typing and navigating are the same gesture.
        -->
        <div class="dock-switcher" bind:this={switcherEl}>
          <div class="dock-search">
            <input
              bind:this={searchEl}
              bind:value={query}
              type="text"
              class="dock-search-input"
              role="combobox"
              aria-autocomplete="list"
              aria-expanded="true"
              aria-controls={LISTBOX_ID}
              aria-activedescendant={activeIndex >= 0 && activeIndex < rows.length
                ? `${LISTBOX_ID}-option-${activeIndex}`
                : undefined}
              aria-label={m.chat_dock_search_placeholder()}
              placeholder={m.chat_dock_search_placeholder()}
              autocomplete="off"
              spellcheck="false"
              oninput={onSearchInput}
              onkeydown={onSearchKeydown}
            />
          </div>

          <div id={LISTBOX_ID} class="dock-list" role="listbox" aria-label={m.chat_dock_switcher_aria()}>
            {#if rows.length === 0}
              <p class="dock-list-empty">
                {needle
                  ? m.chat_dock_no_matches()
                  : chatDisabled
                    ? m.chat_dock_chat_disabled()
                    : m.chat_dock_no_friends()}
              </p>
            {/if}

            {#if shownOpen.length > 0}
              <p class="dock-list-section" id="{LISTBOX_ID}-open">{m.chat_dock_section_open()}</p>
            {/if}
            {#each shownOpen as row, i (row.hash)}
              <!-- svelte-ignore a11y_click_events_have_key_events -->
              <div
                class="dock-row"
                class:active={i === activeIndex}
                class:current={row.hash === $activeChatTab}
                role="option"
                id={`${LISTBOX_ID}-option-${i}`}
                aria-selected={i === activeIndex}
                tabindex="-1"
                onclick={() => activateRow(row)}
                onmouseenter={() => (activeHash = row.hash)}
                onauxclick={(e) => {
                  // Middle-click closes, the way it closes a tab everywhere else.
                  if (e.button !== 1) return;
                  e.preventDefault();
                  closeRow(row);
                }}
              >
                <span
                  class="dock-presence"
                  class:online={row.online}
                  role="img"
                  aria-label={row.online ? m.chat_online_label() : m.chat_offline_label()}
                ></span>
                <span class="dock-row-name"><bdi dir="auto">{row.label}</bdi></span>
                {#if row.unread > 0}
                  <span
                    class="dock-row-unread"
                    aria-label={plural(row.unread, {
                      one: m.chat_dock_unread_aria_one,
                      few: () => m.chat_dock_unread_aria_few({ count: row.unread }),
                      other: () => m.chat_dock_unread_aria_other({ count: row.unread }),
                    })}
                  >{row.unread > 99 ? '99+' : row.unread}</span>
                {/if}
                <!--
                  Deliberately `aria-hidden` + untabbable: a `role="option"`
                  must not contain interactive descendants, and keyboard users
                  have Delete on the highlighted row. This adds a pointer
                  target without breaking the listbox contract.
                -->
                <button
                  type="button"
                  class="dock-row-close"
                  tabindex="-1"
                  aria-hidden="true"
                  title={m.chat_dock_close_tab({ name: row.label })}
                  onclick={(e) => { e.stopPropagation(); closeRow(row); }}
                >
                  <IconX size={12} />
                </button>
              </div>
            {/each}

            {#if shownFriends.length > 0}
              <p class="dock-list-section">{m.chat_dock_section_start()}</p>
            {/if}
            {#each shownFriends as row, i (row.hash)}
              {@const idx = shownOpen.length + i}
              <!-- svelte-ignore a11y_click_events_have_key_events -->
              <div
                class="dock-row"
                class:active={idx === activeIndex}
                role="option"
                id={`${LISTBOX_ID}-option-${idx}`}
                aria-selected={idx === activeIndex}
                tabindex="-1"
                onclick={() => activateRow(row)}
                onmouseenter={() => (activeHash = row.hash)}
              >
                <span
                  class="dock-presence"
                  class:online={row.online}
                  role="img"
                  aria-label={row.online ? m.chat_online_label() : m.chat_offline_label()}
                ></span>
                <span class="dock-row-name"><bdi dir="auto">{row.label}</bdi></span>
              </div>
            {/each}
          </div>
        </div>
      {/if}

      {#if pendingOffers.length > 0}
        <div class="dock-offers" role="region" aria-label={m.chat_dock_offers_title()}>
          <div class="dock-offers-title">{m.chat_dock_offers_title()}</div>
          {#each pendingOffers as offer (`${offer.user_hash}:${offer.file_hash}`)}
            <div class="dock-offer">
              <div class="dock-offer-info">
                <span class="dock-offer-name"><bdi dir="auto">{offer.file_name}</bdi></span>
                <span class="dock-offer-meta">
                  {m.friends_offer_from({ name: friendLabel(offer.user_hash, undefined, $friendNames) })}
                  {#if offer.file_size}&nbsp;·&nbsp;{formatBytes(offer.file_size)}{/if}
                </span>
              </div>
              <div class="dock-offer-actions">
                <button
                  type="button"
                  class="dock-offer-accept"
                  disabled={acceptingOffer !== null}
                  onclick={() => void acceptDockOffer(offer)}
                >{m.friends_offer_download()}</button>
                <!-- Only the row being accepted is held: dismissing a
                     different offer starts nothing and can go through. -->
                <button
                  type="button"
                  class="dock-offer-dismiss"
                  disabled={acceptingOffer === `${offer.user_hash}:${offer.file_hash}`}
                  onclick={() => clearFileOffer(offer.user_hash, offer.file_hash)}
                >{m.common_dismiss()}</button>
              </div>
            </div>
          {/each}
        </div>
      {/if}

      {#if activeTab}
        <ChatConversation friendHash={activeTab.hash} friendName={activeTab.name} />
      {:else}
        <div class="dock-empty-state">
          <div class="empty-illustration" aria-hidden="true">
            <svg viewBox="0 0 64 64" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 18a6 6 0 016-6h28a6 6 0 016 6v18a6 6 0 01-6 6H30l-10 10v-10h-2a6 6 0 01-6-6V18z"/>
              <line x1="22" y1="26" x2="40" y2="26"/>
              <line x1="22" y1="32" x2="36" y2="32"/>
            </svg>
          </div>
          <p class="empty-title">{m.chat_dock_empty_title()}</p>
          <p class="empty-hint">
            {$friendsList.length ? m.chat_dock_empty_hint() : m.chat_dock_no_friends()}
          </p>
          <button type="button" class="secondary empty-cta" onclick={handleNewChat}>
            {$friendsList.length ? m.chat_dock_pick_friend() : m.chat_dock_empty_cta()}
          </button>
        </div>
      {/if}
    </div>
  </div>
{/if}

<style>
  .chat-dock {
    position: fixed;
    top: 0;
    right: 0;
    bottom: var(--statusbar-height);
    /* Width is an inline style so it can be dragged; this is only the floor
       and the ceiling the drag is clamped to, restated for a first paint that
       happens before the mount handler has measured the window. */
    min-width: 320px;
    max-width: 100vw;
    background: var(--bg-primary);
    border-left: 1px solid var(--border);
    z-index: 1000;
    display: flex;
    flex-direction: column;
    box-shadow: var(--shadow-panel-left);
    outline: none;
  }

  /* The whole window is the chat: no edge to sit against, nothing behind it
     to cast a shadow on. */
  .chat-dock.windowed {
    inset: 0;
    width: 100%;
    min-width: 0;
    border-left: none;
    box-shadow: none;
  }

  /* Mid-drag the pointer is captured by the handle, but the press began over
     the panel — without this the transcript selects as the pointer crosses it. */
  .chat-dock.resizing {
    user-select: none;
  }

  .dock-resize {
    position: absolute;
    top: 0;
    bottom: 0;
    /* Straddles the border rather than sitting inside it, so the target is
       where the edge looks like it is. */
    left: -3px;
    width: 7px;
    z-index: 2;
    cursor: col-resize;
    background: transparent;
    /* A touch drag here resizes; without this the gesture scrolls the page. */
    touch-action: none;
    transition: background var(--transition-fast);
  }

  .dock-resize:hover,
  .dock-resize:focus-visible {
    background: color-mix(in srgb, var(--accent) 55%, transparent);
    outline: none;
  }

  .chat-dock.resizing .dock-resize {
    background: var(--accent);
  }

  .dock-head {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 6px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  /* Takes the slack so the controls sit hard against the right edge, and
     ellipsizes rather than pushing them off it. */
  .dock-current {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1 1 auto;
    min-width: 0;
    padding: 6px 8px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-primary);
    font: inherit;
    font-size: var(--font-size-md);
    font-weight: 600;
    text-align: left;
    cursor: pointer;
    transition: background var(--transition-fast);
  }

  .dock-current:hover,
  .dock-current.open {
    background: var(--bg-hover);
  }

  .dock-current:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }

  .dock-current-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  .dock-current-none {
    color: var(--text-muted);
    font-weight: 500;
    font-style: italic;
  }

  .dock-chevron {
    width: 13px;
    height: 13px;
    flex-shrink: 0;
    color: var(--text-muted);
  }

  .dock-presence {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-muted);
    flex-shrink: 0;
    transition: background var(--transition-fast), box-shadow var(--transition-fast);
  }

  .dock-presence.online {
    background: var(--status-connected);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--status-connected) 18%, transparent);
  }

  .dock-encrypted {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    padding: 4px;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    color: var(--accent);
  }

  .dock-encrypted svg {
    width: 12px;
    height: 12px;
  }

  .dock-elsewhere {
    flex-shrink: 0;
    min-width: 20px;
    padding: 2px 7px;
    border: none;
    border-radius: var(--radius-pill);
    background: var(--accent);
    color: var(--on-accent);
    font: inherit;
    font-size: var(--font-size-xs);
    font-weight: 700;
    line-height: 1.4;
    cursor: pointer;
  }

  .dock-elsewhere:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .dock-new,
  .dock-close {
    width: 30px;
    height: 30px;
    padding: 0;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-secondary);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .dock-new:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .dock-close:hover {
    color: var(--danger);
    background: color-mix(in srgb, var(--danger) 12%, transparent);
  }

  .dock-new:focus-visible,
  .dock-close:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .dock-new svg,
  .dock-close svg {
    width: 14px;
    height: 14px;
  }

  .dock-body {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    overflow: hidden;
    position: relative;
  }

  /* Over the conversation rather than beside it: the dock is a narrow column,
     and a list that pushed the transcript aside would leave neither usable. */
  .dock-switcher {
    position: absolute;
    inset: 0;
    z-index: 4;
    display: flex;
    flex-direction: column;
    min-height: 0;
    background: var(--bg-primary);
  }

  .dock-search {
    padding: 8px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .dock-search-input {
    width: 100%;
    padding: 7px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-secondary);
    color: var(--text-primary);
    font: inherit;
    font-size: var(--font-size-md);
  }

  .dock-search-input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .dock-list {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 6px;
    scrollbar-width: thin;
  }

  .dock-list-section {
    margin: 6px 0 4px;
    padding: 0 8px;
    font-size: var(--font-size-xs);
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--text-muted);
  }

  .dock-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 7px 8px;
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: var(--font-size-md);
    cursor: pointer;
  }

  /* One highlight, driven by `activeHash`, which both the arrow keys and the
     pointer write — so hover and keyboard cannot disagree about the target. */
  .dock-row.active {
    background: var(--bg-hover);
  }

  .dock-row.current {
    font-weight: 600;
  }

  .dock-row-name {
    flex: 1 1 auto;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .dock-row-unread {
    background: var(--accent);
    color: var(--on-accent);
    font-size: var(--font-size-2xs);
    font-weight: 700;
    padding: 1px 6px;
    border-radius: var(--radius-pill);
    min-width: 18px;
    text-align: center;
    line-height: 1.2;
    flex-shrink: 0;
  }

  .dock-row-close {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    padding: 0;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--text-secondary);
    cursor: pointer;
    flex-shrink: 0;
    opacity: 0;
    font: inherit;
    transition: background var(--transition-fast), color var(--transition-fast), opacity var(--transition-fast);
  }

  .dock-row.active .dock-row-close {
    opacity: 1;
  }

  .dock-row-close:hover {
    background: var(--danger);
    color: var(--on-danger);
  }

  .dock-list-empty {
    margin: 0;
    padding: 14px 10px;
    color: var(--text-muted);
    font-size: var(--font-size-md);
    text-align: center;
  }

  .dock-offers {
    flex-shrink: 0;
    max-height: 40%;
    overflow: auto;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-secondary);
  }

  .dock-offers-title {
    margin-bottom: 8px;
    font-size: var(--font-size-sm);
    font-weight: 600;
    color: var(--text-secondary);
  }

  .dock-offer {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 10px;
    padding: 8px 0;
  }

  .dock-offer + .dock-offer {
    border-top: 1px solid var(--border);
  }

  .dock-offer-info {
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .dock-offer-name {
    font-size: var(--font-size-md);
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .dock-offer-meta {
    font-size: var(--font-size-sm);
    color: var(--text-muted);
  }

  .dock-offer-actions {
    display: flex;
    gap: 6px;
    flex-shrink: 0;
  }

  .dock-offer-accept,
  .dock-offer-dismiss {
    font: inherit;
    font-size: var(--font-size-sm);
    padding: 4px 8px;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }

  .dock-offer-accept {
    border: 1px solid var(--accent);
    background: var(--accent);
    color: var(--on-accent);
  }

  .dock-offer-dismiss {
    border: 1px solid var(--border);
    background: transparent;
    color: var(--text-secondary);
  }

  .dock-empty-state {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 32px;
    text-align: center;
    gap: 12px;
    color: var(--text-muted);
  }

  .empty-illustration {
    color: var(--text-muted);
    opacity: 0.55;
  }

  .empty-illustration svg {
    width: 64px;
    height: 64px;
  }

  .empty-title {
    margin: 4px 0 0;
    font-size: var(--font-size-base);
    font-weight: 600;
    color: var(--text-primary);
  }

  .empty-hint {
    margin: 0;
    font-size: var(--font-size-md);
    line-height: 1.5;
    max-width: 280px;
  }

  .empty-cta {
    margin-top: 8px;
    font-size: var(--font-size-md);
  }
</style>
