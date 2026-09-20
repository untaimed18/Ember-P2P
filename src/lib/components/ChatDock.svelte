<script lang="ts">
  import { onMount } from 'svelte';
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
    isRoomTab,
    roomTabChannelId,
  } from '$lib/stores/chatTabs';
  import {
    unreadCounts,
    onlineFriends,
    friendsList,
    fileOffers,
    friendDisplayName,
    acceptIncomingFileOffer,
    clearFileOffer,
  } from '$lib/stores/friends';
  import {
    awaitingChannelOfferList,
    channels as channelsStore,
    ignoredKeysForChannel,
    ignoredMembers,
    respondToChannelOffer,
  } from '$lib/stores/channels';
  import {
    channelRosters,
    loadChannelRoster,
    memberLabelsFrom,
    membersIn,
    mentionCandidatesFrom,
    rosterOf,
  } from '$lib/stores/channelRoster';
  import { appSettings } from '$lib/stores/settings';
  import { toastError, toastSuccess } from '$lib/stores/toast';
  import { formatBytes } from '$lib/utils';
  import { translateError } from '$lib/i18n';
  import { menuKeydown } from '$lib/a11y';
  import * as m from '$lib/paraglide/messages';
  import IconX from '$lib/components/IconX.svelte';
  import { shortcutModAria } from '$lib/platform';
  import {
    clampDockWidth,
    maxDockWidth,
    DOCK_WIDTH_DEFAULT,
    DOCK_WIDTH_MIN,
  } from '$lib/dockWidth';

  /**
   * How wide the dock is, in pixels, remembered per device.
   *
   * It used to be `min(420px, 40vw)` and nothing else — a fixed panel on every
   * window, at a size chosen for a glance at one line rather than for the
   * thing people actually do in it, with no way to change it.
   */
  const DOCK_WIDTH_KEY = 'ember.chatDock.width.v1';

  /** The window as the clamp needs to see it. Zero before the DOM exists,
   *  which `maxDockWidth` treats as "no measurement" rather than "no room". */
  function viewport(): number {
    return typeof window === 'undefined' ? 0 : window.innerWidth;
  }

  function loadDockWidth(): number {
    if (typeof localStorage === 'undefined') return DOCK_WIDTH_DEFAULT;
    try {
      const raw = localStorage.getItem(DOCK_WIDTH_KEY);
      if (!raw) return DOCK_WIDTH_DEFAULT;
      return clampDockWidth(Number.parseInt(raw, 10), viewport());
    } catch {
      return DOCK_WIDTH_DEFAULT;
    }
  }

  let dockWidth = $state(loadDockWidth());
  let dockWidthMax = $state(maxDockWidth(viewport()));
  let resizing = $state(false);

  /** `persist` is false mid-drag: writing on every pointer move would put a
   *  synchronous `localStorage` write inside the frame doing the resizing. */
  function setDockWidth(px: number, persist = true) {
    dockWidth = clampDockWidth(px, viewport());
    if (!persist || typeof localStorage === 'undefined') return;
    try {
      localStorage.setItem(DOCK_WIDTH_KEY, String(dockWidth));
    } catch {
      // Quota exceeded / private mode. The width holds for this session.
    }
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
    resizing = false;
    const handle = e.currentTarget as HTMLElement;
    if (handle.hasPointerCapture(e.pointerId)) handle.releasePointerCapture(e.pointerId);
    // The drag wrote nothing; this is the one write it makes.
    setDockWidth(dockWidth);
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
  let pickerOpen = $state(false);
  let pickerEl: HTMLDivElement | undefined = $state();
  let newChatEl: HTMLButtonElement | undefined = $state();
  let acceptingOffer: string | null = $state(null);
  let chatDisabled = $derived($appSettings?.friend_chat_disabled === true);
  let pendingOffers = $derived($fileOffers);
  /** Room offers waiting on an answer, wherever the user happens to be. They
   *  expire, and until now the only place to answer one was inside the room
   *  it arrived in. */
  let roomOffers = $derived($awaitingChannelOfferList);
  let respondingXfer: string | null = $state(null);

  function roomNameFor(channelId: string): string {
    return (
      $channelsStore.find((c) => c.channel_id === channelId)?.name ?? m.nav_channels()
    );
  }

  async function answerRoomOffer(xferId: string, accept: boolean) {
    if (respondingXfer) return;
    respondingXfer = xferId;
    try {
      await respondToChannelOffer(xferId, accept);
    } catch (e) {
      toastError(translateError(e));
    } finally {
      respondingXfer = null;
    }
  }
  let pickerFriends = $derived(
    [...$friendsList].sort((a, b) => {
      const ao = $onlineFriends.has(a.user_hash.toLowerCase()) ? 0 : 1;
      const bo = $onlineFriends.has(b.user_hash.toLowerCase()) ? 0 : 1;
      if (ao !== bo) return ao - bo;
      return (a.nickname || a.user_hash).localeCompare(b.nickname || b.user_hash);
    }),
  );

  // Activate the dock as a focus context so screen readers announce
  // it as a dialog and Tab cycling stays in scope. We bail early if
  // the dock is closed so the rest of the app keeps full focus.
  $effect(() => {
    if (!$chatDockOpen) pickerOpen = false;
  });

  $effect(() => {
    if ($chatDockOpen && panelEl) {
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
      if (!$chatDockOpen && returnFocusEl) {
        const el = returnFocusEl;
        returnFocusEl = null;
        requestAnimationFrame(() => {
          if (typeof document !== 'undefined' && document.contains(el)) el.focus();
        });
      }
    };
  });

  // Active tab metadata, looked up once per render so the
  // `<ChatConversation>` doesn't have to know about the tab list.
  let activeTab = $derived(
    $activeChatTab ? $chatTabs.find((t) => t.hash === $activeChatTab) ?? null : null,
  );

  /** The room behind the active tab, or null when it is a friend. */
  let activeRoomId = $derived(activeTab ? roomTabChannelId(activeTab.hash) : null);
  let activeRoom = $derived(
    activeRoomId ? $channelsStore.find((c) => c.channel_id === activeRoomId) ?? null : null,
  );
  /**
   * The roster for the room on screen, so a conversation in the dock names
   * people the way the Channels page does rather than by key fragment.
   *
   * Read through the store the page also reads, which is the whole reason a
   * room can be drawn here at all — the member list used to be that page's own
   * component state.
   */
  let activeRoomMembers = $derived(membersIn($channelRosters, activeRoomId));
  let activeRoomLabels = $derived(memberLabelsFrom(activeRoomMembers));
  let activeRoomMentions = $derived(mentionCandidatesFrom(activeRoomMembers));
  let activeRoomIgnored = $derived(ignoredKeysForChannel($ignoredMembers, activeRoomId));

  // A room tab can be restored from localStorage or activated while the user
  // is nowhere near Channels, so the dock has to fetch its own roster rather
  // than rely on that page having been open.
  $effect(() => {
    const id = activeRoomId;
    if (!id) return;
    if (rosterOf(id).members.length > 0) return;
    void loadChannelRoster(id).catch((e) =>
      console.warn('ChatDock: could not load the room roster', e),
    );
  });

  function isTypingTarget(t: EventTarget | null): boolean {
    if (!(t instanceof HTMLElement)) return false;
    const tag = t.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
    if (t.isContentEditable) return true;
    return false;
  }

  // Global hotkeys, scoped to "dock is open". Esc closes the dock
  // (preserves tabs); Ctrl+Tab / Ctrl+Shift+Tab cycles tabs without
  // leaving the dock; Ctrl+W closes the active tab. Ctrl+Tab is
  // intercepted only when the dock is open so it doesn't fight with
  // the OS-level browser tab cycle in the rest of the app.
  function onKeydown(e: KeyboardEvent) {
    if (!$chatDockOpen) return;
    // Esc — close the dock. Allowed even from inputs because users
    // press it instinctively to dismiss overlays.
    if (e.key === 'Escape') {
      // An open modal owns Escape. Those handlers sit on the dialog element and
      // let the event bubble to this window listener, so without this guard one
      // press both dismisses the dialog and collapses the dock behind it.
      if (typeof document !== 'undefined' && document.querySelector('[aria-modal="true"]')) {
        return;
      }
      // Page chrome that already handled Escape (recent-search dropdown, column
      // menus, clearing a filter) calls preventDefault. Don't also close the dock.
      if (e.defaultPrevented) return;
      if (pickerOpen) {
        e.preventDefault();
        pickerOpen = false;
        return;
      }
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
    if ((e.key === 'w' || e.key === 'W') && !isTypingTarget(e.target)) {
      // Ctrl+W is "close window" in the OS, but here it's "close
      // tab" — the dock isn't a real window so we can safely repurpose
      // it. Disabled while typing so a user mid-message doesn't lose
      // their conversation by reflex.
      e.preventDefault();
      const active = $activeChatTab;
      if (active) closeTab(active);
      return;
    }
  }

  // A window narrowed past the stored width would otherwise leave the dock
  // covering the app with no way back except widening the window again.
  function onWindowResize() {
    dockWidthMax = maxDockWidth(viewport());
    if (dockWidth > dockWidthMax) setDockWidth(dockWidthMax);
  }

  // A menu that only Escape can dismiss is a menu users leave open by
  // accident — it sits over the tab strip and the conversation below it.
  // `pointerdown` rather than `click` so the menu is gone before whatever
  // was clicked underneath reacts.
  function onPointerDown(e: PointerEvent) {
    if (!pickerOpen) return;
    const target = e.target;
    if (!(target instanceof Node)) return;
    if (pickerEl?.contains(target) || newChatEl?.contains(target)) return;
    pickerOpen = false;
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

  function unreadFor(hash: string): number {
    const room = roomTabChannelId(hash);
    if (room !== null) {
      return $channelsStore.find((c) => c.channel_id === room)?.unread ?? 0;
    }
    return $unreadCounts.get(hash) ?? 0;
  }

  /** Rooms have no presence of their own, so their tab carries no dot. */
  function isOnline(hash: string): boolean {
    if (isRoomTab(hash)) return false;
    return $onlineFriends.has(hash.toLowerCase());
  }

  // Keyboard activation for the role=tab elements. Enter and Space
  // are the canonical keys for activating a tab in WAI-ARIA's tab
  // pattern. The outer is a div (not a button) because we need to
  // nest a real `<button>` for close-X and HTML disallows nesting
  // buttons.
  function onTabKeydown(e: KeyboardEvent, hash: string) {
    // Activate the focused tab on Enter/Space (in case the user
    // tab-focused into an inactive tab — they almost never can,
    // since only the active tab has tabindex=0, but it costs
    // nothing to support).
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setActiveTab(hash);
      return;
    }
    // WAI-ARIA tab pattern: Left/Right arrows move focus AND
    // activate the previous/next tab. Home/End jump to first/last.
    // Delete closes the focused tab. We don't intercept Up/Down
    // (vertical lists aren't in play here).
    const tabs = $chatTabs;
    if (tabs.length === 0) return;
    const idx = tabs.findIndex((t) => t.hash === hash);
    if (idx === -1) return;
    let target = -1;
    if (e.key === 'ArrowRight') target = (idx + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') target = (idx - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') target = 0;
    else if (e.key === 'End') target = tabs.length - 1;
    else if (e.key === 'Delete') {
      e.preventDefault();
      closeTab(hash);
      return;
    }
    if (target === -1) return;
    e.preventDefault();
    const targetHash = tabs[target].hash;
    setActiveTab(targetHash);
    // Move DOM focus to the new tab so further arrow presses
    // advance from there. The active tab is the only one with
    // tabindex=0, so a re-render is needed before we can focus —
    // queue the focus on the next frame.
    requestAnimationFrame(() => {
      if (typeof document === 'undefined') return;
      const next = document.querySelector<HTMLElement>(
        `.dock-tab[data-hash="${CSS.escape(targetHash)}"]`,
      );
      next?.focus();
    });
  }

  function handleNewChat() {
    if (chatDisabled || pickerFriends.length === 0) {
      pickerOpen = false;
      void goto('/friends').catch((e) => console.warn('Failed to open Friends page:', e));
      return;
    }
    pickerOpen = !pickerOpen;
    // Land focus inside the menu so the arrow keys `menuKeydown` handles have
    // somewhere to start. Deferred a frame because the items do not exist
    // until this state change renders.
    if (pickerOpen) {
      requestAnimationFrame(() => {
        pickerEl?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();
      });
    }
  }

  function startChatWith(hash: string, name: string) {
    if (chatDisabled) return;
    pickerOpen = false;
    openChat(hash, name || friendDisplayName(hash));
    // Focus goes back to the control that opened the menu rather than being
    // dropped on the body when the item it was on unmounts.
    newChatEl?.focus();
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

{#if $chatDockOpen}
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
    style="width: {dockWidth}px"
    bind:this={panelEl}
    role="complementary"
    aria-label={m.chat_dock_aria_label()}
    aria-keyshortcuts={`Escape ${shortcutModAria()}+/`}
    tabindex="-1"
  >
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
      ondblclick={() => setDockWidth(DOCK_WIDTH_DEFAULT)}
      onkeydown={onResizeKeydown}
    ></div>
    <div class="dock-tabs" role="tablist" aria-label={m.chat_dock_tablist_aria()}>
      {#if $chatTabs.length === 0}
        <div class="dock-empty-tabs">{m.chat_dock_no_open()}</div>
      {:else}
        {#each $chatTabs as tab (tab.hash)}
          <div
            role="tab"
            class="dock-tab"
            class:active={tab.hash === $activeChatTab}
            class:online={isOnline(tab.hash)}
            aria-selected={tab.hash === $activeChatTab}
            tabindex={tab.hash === $activeChatTab ? 0 : -1}
            data-hash={tab.hash}
            title={tab.name}
            onclick={() => setActiveTab(tab.hash)}
            onkeydown={(e) => onTabKeydown(e, tab.hash)}
          >
            {#if isRoomTab(tab.hash)}
              <!-- A room is not online or offline, so it gets the mark that
                   says which kind of conversation this is instead of a dot
                   that would have to claim one. -->
              <span class="dock-tab-room" role="img" aria-label={m.chat_dock_room_tab()}>#</span>
            {:else}
              <!-- Named, not decorative: the tab says nothing else about whether
                   the friend is reachable, so hiding the dot hides the state. -->
              <span
                class="dock-tab-presence"
                role="img"
                aria-label={isOnline(tab.hash) ? m.chat_online_label() : m.chat_offline_label()}
              ></span>
            {/if}
            <span class="dock-tab-name"><bdi dir="auto">{tab.name}</bdi></span>
            {#if unreadFor(tab.hash) > 0}
              <span
                class="dock-tab-unread"
                aria-label={unreadFor(tab.hash) === 1
                  ? m.chat_dock_unread_aria_one()
                  : m.chat_dock_unread_aria_other({ count: unreadFor(tab.hash) })}
              >{unreadFor(tab.hash) > 99 ? '99+' : unreadFor(tab.hash)}</span>
            {/if}
            <button
              type="button"
              class="dock-tab-close"
              tabindex="-1"
              aria-label={m.chat_dock_close_tab({ name: tab.name })}
              title={m.chat_dock_close_tab_title()}
              onclick={(e) => { e.stopPropagation(); closeTab(tab.hash); }}
            >
              <IconX size={12} />
            </button>
          </div>
        {/each}
      {/if}
      <button
        type="button"
        class="dock-new"
        bind:this={newChatEl}
        title={m.chat_dock_new_chat()}
        aria-label={m.chat_dock_new_chat()}
        aria-expanded={pickerOpen}
        aria-haspopup="menu"
        onclick={handleNewChat}
      >
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <line x1="8" y1="3" x2="8" y2="13"/>
          <line x1="3" y1="8" x2="13" y2="8"/>
        </svg>
      </button>
      <button
        type="button"
        class="dock-close"
        title={m.chat_dock_close_title()}
        aria-label={m.chat_dock_close_aria()}
        onclick={closeDock}
      >
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M3.5 3.5l9 9M12.5 3.5l-9 9"/>
        </svg>
      </button>
    </div>

    {#if pickerOpen}
      <!--
        `menu`, not `listbox`: nothing here is a selected value, each row is an
        action that opens a conversation. That also lets it reuse the same
        arrow/Home/End handling as every other menu in the app.
      -->
      <div
        class="dock-picker"
        bind:this={pickerEl}
        role="menu"
        tabindex="-1"
        aria-label={m.chat_dock_pick_friend()}
        onkeydown={(e) => menuKeydown(e, e.currentTarget)}
      >
        {#each pickerFriends as friend (friend.user_hash)}
          <button
            type="button"
            role="menuitem"
            class="dock-picker-item"
            class:online={isOnline(friend.user_hash)}
            disabled={chatDisabled}
            onclick={() => startChatWith(friend.user_hash, friend.nickname || friendDisplayName(friend.user_hash))}
          >
            <span
              class="dock-tab-presence"
              role="img"
              aria-label={isOnline(friend.user_hash) ? m.chat_online_label() : m.chat_offline_label()}
            ></span>
            <span class="dock-picker-name"><bdi dir="auto">{friend.nickname || friendDisplayName(friend.user_hash)}</bdi></span>
          </button>
        {:else}
          <p class="dock-picker-empty">{m.chat_dock_no_friends()}</p>
        {/each}
      </div>
    {/if}

    <div class="dock-body">
      {#if roomOffers.length > 0}
        <div class="dock-offers" role="region" aria-label={m.chat_dock_room_offers_title()}>
          <div class="dock-offers-title">{m.chat_dock_room_offers_title()}</div>
          {#each roomOffers as offer (offer.xfer_id)}
            <div class="dock-offer">
              <div class="dock-offer-info">
                <span class="dock-offer-name"><bdi dir="auto">{offer.name}</bdi></span>
                <span class="dock-offer-meta">
                  {m.chat_dock_room_offer_from({ room: roomNameFor(offer.channel_id) })}
                  {#if offer.size}&nbsp;·&nbsp;{formatBytes(offer.size)}{/if}
                </span>
              </div>
              <div class="dock-offer-actions">
                <button
                  type="button"
                  class="dock-offer-accept"
                  disabled={respondingXfer !== null}
                  onclick={() => void answerRoomOffer(offer.xfer_id, true)}
                >{m.channels_xfer_accept()}</button>
                <!-- Both answers are the same guarded round trip, so neither
                     may look available while one is in flight — unlike the
                     friend dismiss below, which only edits a local store. -->
                <button
                  type="button"
                  class="dock-offer-dismiss"
                  disabled={respondingXfer !== null}
                  onclick={() => void answerRoomOffer(offer.xfer_id, false)}
                >{m.channels_xfer_decline()}</button>
              </div>
            </div>
          {/each}
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
                  {m.friends_offer_from({ name: friendDisplayName(offer.user_hash) })}
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
      {#if activeTab && activeRoomId}
        <!-- Everything a room conversation needs beyond the roster already
             lives on the channels store, so the dock reads the same row the
             Channels page draws from rather than a copy of it. -->
        <ChatConversation
          friendHash=""
          friendName={activeRoom?.name ?? activeTab.name}
          channelId={activeRoomId}
          youAreBanned={activeRoom?.you_are_banned ?? false}
          youAreKeyBehind={activeRoom?.key_behind ?? false}
          slowModeSecs={activeRoom?.slow_mode_secs ?? 0}
          memberNames={activeRoomLabels}
          ignoredSenders={activeRoomIgnored}
          mentionName={$appSettings?.channel_username || $appSettings?.nickname || ''}
          mentionCandidates={activeRoomMentions}
        />
      {:else if activeTab}
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
          <p class="empty-hint">{pickerFriends.length ? m.chat_dock_empty_hint() : m.chat_dock_no_friends()}</p>
          <button type="button" class="secondary empty-cta" onclick={handleNewChat}>
            {pickerFriends.length ? m.chat_dock_pick_friend() : m.chat_dock_empty_cta()}
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

  .dock-tabs {
    display: flex;
    align-items: stretch;
    gap: 2px;
    padding: 6px 6px 0;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    overflow-x: auto;
    /* Explicit, and not merely tidiness. Setting only `overflow-x` leaves
       `overflow-y` at `visible`, and CSS then computes `visible` to `auto`
       whenever the other axis is not visible — so the strip grew its own
       vertical scrollbar the moment anything inside it exceeded the box by a
       fraction of a pixel, which the active tab's indicator did by exactly 1px. */
    overflow-y: hidden;
    scrollbar-width: thin;
    flex-shrink: 0;
  }

  .dock-tabs::-webkit-scrollbar {
    height: 6px;
  }

  .dock-tabs::-webkit-scrollbar-thumb {
    background: var(--border);
    border-radius: 3px;
  }

  .dock-empty-tabs {
    display: flex;
    align-items: center;
    padding: 0 12px;
    color: var(--text-muted);
    font-size: 12px;
    font-style: italic;
  }

  .dock-tab {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px 8px 12px;
    border: none;
    border-radius: var(--radius-sm) var(--radius-sm) 0 0;
    background: transparent;
    color: var(--text-secondary);
    font-size: 12.5px;
    font-family: inherit;
    cursor: pointer;
    /* Share the strip rather than each claiming a fixed width and pushing the
       rest out of view. The dock is only ~420px wide, so fixed 180px tabs
       started scrolling at three conversations; now they narrow and ellipsize
       first, and scrolling is the last resort once they hit a width where the
       name and controls stop being usable. */
    flex: 1 1 auto;
    max-width: 180px;
    min-width: 96px;
    position: relative;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .dock-tab:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .dock-tab.active {
    background: var(--bg-primary);
    color: var(--text-primary);
    font-weight: 600;
  }

  .dock-tab.active::after {
    content: '';
    position: absolute;
    left: 0;
    right: 0;
    /* Inside the box, not 1px past it. Overhanging the strip's bottom edge is
       what pushed the container into vertical overflow, and `overflow-y: hidden`
       would now clip half of a 2px bar anyway. */
    bottom: 0;
    height: 2px;
    background: var(--accent);
  }

  .dock-tab-presence {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-muted);
    flex-shrink: 0;
    transition: background var(--transition-fast), box-shadow var(--transition-fast);
  }

  .dock-tab-room {
    width: 8px;
    font-size: 12px;
    font-weight: 700;
    line-height: 1;
    color: var(--text-muted);
    flex-shrink: 0;
  }

  .dock-tab.active .dock-tab-room {
    color: var(--accent);
  }

  .dock-tab.online .dock-tab-presence,
  .dock-picker-item.online .dock-tab-presence {
    background: var(--status-connected);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--status-connected) 18%, transparent);
  }

  .dock-tab-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  .dock-tab-unread {
    background: var(--accent);
    color: var(--on-accent);
    font-size: 10px;
    font-weight: 700;
    padding: 1px 6px;
    border-radius: var(--radius-pill);
    min-width: 18px;
    text-align: center;
    line-height: 1.2;
    flex-shrink: 0;
  }

  .dock-tab-close {
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

  .dock-tab:hover .dock-tab-close,
  .dock-tab.active .dock-tab-close {
    opacity: 1;
  }

  .dock-tab-close:hover {
    background: var(--danger);
    color: var(--on-danger);
  }

  .dock-new,
  .dock-close {
    width: 32px;
    height: 32px;
    margin: 4px 0;
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

  .dock-new {
    margin-left: 4px;
  }

  .dock-picker {
    position: absolute;
    top: 46px;
    right: 40px;
    z-index: 5;
    min-width: 220px;
    max-width: min(320px, 80vw);
    max-height: 280px;
    overflow: auto;
    padding: 6px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-primary);
    box-shadow: var(--shadow-md);
  }

  .dock-picker-item {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 8px 10px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-primary);
    font: inherit;
    font-size: 12.5px;
    text-align: left;
    cursor: pointer;
  }

  .dock-picker-item:hover,
  .dock-picker-item:focus-visible {
    background: var(--bg-hover);
  }

  .dock-picker-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .dock-picker-empty {
    margin: 0;
    padding: 10px;
    color: var(--text-muted);
    font-size: 12.5px;
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
    font-size: 12px;
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
    font-size: 12.5px;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .dock-offer-meta {
    font-size: 11.5px;
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
    font-size: 12px;
    padding: 4px 8px;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }

  .dock-offer-accept {
    border: 1px solid var(--accent);
    background: var(--accent);
    color: var(--on-accent, #fff);
  }

  .dock-offer-dismiss {
    border: 1px solid var(--border);
    background: transparent;
    color: var(--text-secondary);
  }

  .dock-close {
    margin-left: auto;
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
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .empty-hint {
    margin: 0;
    font-size: 12.5px;
    line-height: 1.5;
    max-width: 280px;
  }

  .empty-cta {
    margin-top: 8px;
    font-size: 13px;
  }
</style>
