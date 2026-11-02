<script module lang="ts">
  // Survive DeepLinkHandler remount (wizard dismiss / locale reload). Instance
  // Sets would reset and auto-open the same durable queue entry again.
  export const completedDeepLinkIds = new Set<string>();
  export const deferredDeepLinkIds = new Set<string>();
</script>

<script lang="ts">
  // Handler for OS-delivered deep links. It drains the backend's durable
  // buffer and presents an in-app confirmation before network side effects,
  // then routes confirmed payloads into the same flows the UI already uses:
  //   - ed2k://|file|...        -> queue a download
  //   - ed2k://|server|ip|port  -> add + connect to the ed2k server
  //   - ed2k://|serverlist|url  -> download a server.met list
  //   - *.emulecollection       -> open on the library page
  //
  // Backend contract (`list_pending_deep_links` / `ack_pending_deep_link`):
  // links remain durable until explicitly acknowledged. Ack only after a
  // completed action *or* an explicit user rejection — never after an
  // accidental Escape/overlay dismiss, so OS-delivered actions are not lost.
  import { onMount } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { deepLinkGoto } from '$lib/deepLinkNavigation';
  import { page } from '$app/stores';
  import { get } from 'svelte/store';
  import { parseEd2kLink } from '$lib/api/search';
  import { startDownload } from '$lib/api/transfers';
  import { addServer, connectToServer, downloadServerMet } from '$lib/api/server';
  import {
    ackPendingDeepLink,
    listPendingDeepLinks,
    openPendingCollection,
    previewDeepLink,
    type DeepLinkPreview,
    type PendingDeepLink,
  } from '$lib/api/deeplink';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import IconX from '$lib/components/IconX.svelte';
  import { cancelIncomingCollection, presentIncomingCollection } from '$lib/stores/collection';
  import { toastSuccess, toastError } from '$lib/stores/toast';
  import { codedErrorOf, translateError } from '$lib/i18n';
  import { serverMetDownloadedText } from '$lib/commandReplies';
  import { plural } from '$lib/plural';
  import { formatBytes, formatNumber } from '$lib/utils';
  import * as m from '$lib/paraglide/messages';
  import { alreadyQueuedText } from '$lib/alreadyQueued';

  type ConfirmDecision = 'accept' | 'reject' | 'defer';
  type HandleResult = 'done' | 'defer' | 'fail';

  const completedIds = completedDeepLinkIds;
  const deferredIds = deferredDeepLinkIds;

  // Parse the `|`-delimited body of an ed2k link, dropping the trailing empty
  // segment(s) the `…|/` terminator produces. e.g.
  //   ed2k://|server|1.2.3.4|4242|/  ->  ['server', '1.2.3.4', '4242']
  function ed2kSegments(link: string): string[] {
    return link
      .replace(/^ed2k:\/\/\|/i, '')
      .split('|')
      .map((s) => s.trim())
      .filter((s) => s.length > 0 && s !== '/');
  }

  function isAllowedServerListUrl(value: string): boolean {
    try {
      const url = new URL(value);
      return url.protocol === 'https:';
    } catch {
      return false;
    }
  }

  function deepLinkConfirmationMessage(preview: DeepLinkPreview): string {
    if (preview.kind === 'file') {
      const lines = [
        preview.name ?? '',
        formatBytes(preview.size ?? 0),
        preview.hash ?? '',
      ];
      if (preview.ember) {
        lines.push(m.deeplink_ember_digest({ hash: preview.ember }));
      }
      return lines.join('\n');
    }
    if (preview.kind === 'server') return preview.endpoint ?? '';
    if (preview.kind === 'serverList') return preview.host ?? '';
    if (preview.kind === 'channel') {
      return `${preview.name ?? m.nav_channels()}\n${preview.hash ?? ''}`;
    }
    if (preview.kind === 'friend') {
      return m.deeplink_friend_confirm({ hash: preview.hash ?? '' });
    }
    if (preview.kind === 'feed') {
      return m.deeplink_feed_confirm({ link: preview.hash ?? '' });
    }
    return preview.name ?? '';
  }

  function deepLinkConfirmLabel(preview: DeepLinkPreview): string {
    switch (preview.kind) {
      case 'file': return m.search_ctx_download();
      case 'server': return m.servers_connect();
      case 'serverList': return m.deeplink_confirm_update_server_list();
      case 'feed': return m.feeds_follow();
      default: return m.deeplink_confirm_open();
    }
  }

  /** Most files a batch confirmation names before summing up the rest. */
  const BATCH_LISTED = 8;

  function batchConfirmationMessage(previews: DeepLinkPreview[]): string {
    const lines = previews
      .slice(0, BATCH_LISTED)
      .map((p) => `${p.name ?? ''} (${formatBytes(p.size ?? 0)})`);
    if (previews.length > BATCH_LISTED) {
      lines.push(m.deeplink_batch_more({ count: formatNumber(previews.length - BATCH_LISTED) }));
    }
    return lines.join('\n');
  }

  let confirmOpen = $state(false);
  let confirmTitle = $state('');
  let confirmMessage = $state('');
  let confirmLabel = $state('');
  let confirmCancelLabel = $state('');
  let confirmResolver: ((decision: ConfirmDecision) => void) | null = null;

  function openConfirmation(title: string, message: string, label: string, cancelLabel: string): Promise<ConfirmDecision> {
    if (destroyed) return Promise.resolve('defer');
    confirmTitle = title;
    confirmMessage = message;
    confirmLabel = label;
    confirmCancelLabel = cancelLabel;
    confirmOpen = true;
    return new Promise((resolve) => {
      confirmResolver = resolve;
    });
  }

  function requestConfirmation(preview: DeepLinkPreview): Promise<ConfirmDecision> {
    return openConfirmation(
      m.deeplink_confirm_title(),
      deepLinkConfirmationMessage(preview),
      deepLinkConfirmLabel(preview),
      m.deeplink_confirm_ignore(),
    );
  }

  /** What was settled for a link before its own turn: its preview, and for a
   *  file opened together with others, the answer to the one dialog asking
   *  about all of them. */
  type Prepared = { preview: DeepLinkPreview; decision?: ConfirmDecision };

  /**
   * Several file links opened at once (a page's "download all", a multi-select
   * in a browser) used to ask one dialog per file. When two or more of the
   * links waiting are files, ask once for all of them. Anything else keeps
   * its own dialog, and a lone file link is asked about as before.
   */
  async function confirmFileBatch(links: PendingDeepLink[]): Promise<Map<string, Prepared>> {
    const prepared = new Map<string, Prepared>();
    if (links.length < 2) return prepared;
    const files: { id: string; preview: DeepLinkPreview }[] = [];
    for (const link of links) {
      if (destroyed) return prepared;
      // A link that fails to preview is left to its own turn, which reports it.
      const preview = await previewDeepLink(link.payload.trim()).catch(() => null);
      if (!preview) continue;
      prepared.set(link.id, { preview });
      if (preview.kind === 'file') files.push({ id: link.id, preview });
    }
    if (files.length < 2) return prepared;
    const decision = await openConfirmation(
      m.deeplink_batch_title(),
      batchConfirmationMessage(files.map((f) => f.preview)),
      m.deeplink_batch_download_all(),
      m.deeplink_batch_ignore_all(),
    );
    for (const f of files) prepared.set(f.id, { preview: f.preview, decision });
    return prepared;
  }

  function resolveConfirmation(decision: ConfirmDecision) {
    const resolve = confirmResolver;
    confirmResolver = null;
    confirmOpen = false;
    resolve?.(decision);
  }

  /** Files queued from the current batch dialog, announced in one toast once
   *  the batch is through rather than one toast each. */
  let batchQueued = 0;

  async function handlePayload(raw: string, pendingId: string, prepared?: Prepared): Promise<HandleResult> {
    const payload = raw.trim();
    let preview: DeepLinkPreview;
    if (prepared) {
      preview = prepared.preview;
    } else {
      try {
        preview = await previewDeepLink(payload);
      } catch (e: unknown) {
        // Parsing/validation errors are permanent for this immutable durable
        // payload. Surface once, then acknowledge so malformed links cannot
        // occupy all queue slots forever.
        if (!destroyed) toastError(translateError(e));
        return destroyed ? 'defer' : 'done';
      }
    }

    const batched = prepared?.decision !== undefined;
    const decision = prepared?.decision ?? (await requestConfirmation(preview));
    if (destroyed || decision === 'defer') return 'defer';
    // Explicit "Ignore link" is a terminal user decision: ack without
    // executing the network/filesystem action.
    if (decision === 'reject') return 'done';

    try {
      if (preview.kind === 'file') {
        const info = await parseEd2kLink(payload);
        // Do not pass `eh=` / `info.ember` into startDownload. A pasted or
        // OS-delivered link is untrusted; pinning that digest would make the
        // first writer we hear from the BLAKE3 we verify against.
        const res = await startDownload(
          info.hash,
          info.name,
          info.size,
          '',
          0,
          undefined,
          undefined,
          info.aich,
          undefined,
          info.web_sources,
        );
        if (!destroyed) {
          // Use the previewed name, not the re-parsed raw one: `preview.name`
          // has been through `sanitize_remote_text` (which strips bidi
          // overrides), and it is the exact string the user just approved in
          // the confirmation dialog. `parseEd2kLink` does no sanitizing, and
          // toasts have no bidi isolation.
          const displayName = preview.name ?? info.name;
          if (batched && !res.already_queued) batchQueued += 1;
          else {
            toastSuccess(
              res.already_queued
                ? alreadyQueuedText(res, displayName)
                : m.search_queued_name({ name: displayName }),
            );
          }
        }
      } else if (preview.kind === 'server') {
        // Prefer the previewed endpoint so a browser-encoded argv payload
        // (`%7C` instead of `|`) still connects after backend normalization.
        let ip = '';
        let port = NaN;
        const cut = preview.endpoint?.lastIndexOf(':') ?? -1;
        if (cut > 0 && preview.endpoint) {
          ip = preview.endpoint.slice(0, cut);
          port = parseInt(preview.endpoint.slice(cut + 1), 10);
        } else {
          const segs = ed2kSegments(payload); // ['server', ip, port]
          ip = segs[1] ?? '';
          port = parseInt(segs[2] ?? '', 10);
        }
        if (!ip || !Number.isFinite(port) || port <= 0 || port > 65535) {
          toastError(
            !ip
              ? m.servers_validation_ip_invalid()
              : m.servers_validation_port_range(),
          );
          return 'fail';
        }
        // A link to a server that is already listed should still connect.
        try {
          await addServer(ip, port, '');
        } catch (e: unknown) {
          const code = codedErrorOf(e)?.code;
          if (code === 'server_add_declined') return 'done';
          if (code !== 'server_already_listed') throw e;
        }
        await connectToServer(ip, port);
        if (!destroyed) toastSuccess(m.servers_connecting_to({ address: `${ip}:${port}` }));
      } else if (preview.kind === 'serverList') {
        const segs = ed2kSegments(payload); // ['serverlist', url]
        const url = preview.endpoint || segs[1] || '';
        if (!isAllowedServerListUrl(url)) {
          // Match the backend's pinned-fetch policy: never silently turn an
          // OS-delivered deep link into an insecure HTTP server-list request.
          toastError(m.security_url_must_be_https());
          return 'fail';
        }
        let reply: string;
        try {
          reply = await downloadServerMet(url);
        } catch (e: unknown) {
          // Declining the native prompt is the user's answer, like
          // `server_add_declined` above, not a failure to park for Review.
          if (codedErrorOf(e)?.code === 'server_met_declined') return 'done';
          throw e;
        }
        if (!destroyed) toastSuccess(serverMetDownloadedText(reply));
      } else if (preview.kind === 'collection') {
        // The native side resolves this durable queue id to the OS-delivered
        // path. Never return the raw path to an unrestricted path-taking IPC
        // command, or a compromised renderer could probe arbitrary files.
        const coll = await openPendingCollection(pendingId);
        if (destroyed) return 'defer';
        const presented = presentIncomingCollection(coll);
        await deepLinkGoto('/library');
        // A cancelled navigation resolves `goto` rather than rejecting it, so a
        // page that blocks it (Settings' unsaved-changes guard) would leave us
        // awaiting a presentation that can never happen — wedging `drain()` and
        // silently dropping every later deep link this session. Confirm we
        // actually landed, and park the link for Review if we did not.
        if (get(page).url.pathname !== '/library') {
          cancelIncomingCollection();
          return 'defer';
        }
        await presented;
        if (!destroyed) {
          const count = formatNumber(coll.files.length);
          toastSuccess(plural(coll.files.length, {
            one: () => m.library_collection_loaded_one({ name: coll.name, count }),
            oneShowsCount: true,
            few: () => m.library_collection_loaded_few({ name: coll.name, count }),
            other: () => m.library_collection_loaded({ name: coll.name, count }),
          }));
        }
      } else if (preview.kind === 'channel') {
        await deepLinkGoto(`/channels?join=${encodeURIComponent(payload)}`);
        if (get(page).url.pathname !== '/channels') {
          return 'defer';
        }
      } else if (preview.kind === 'friend') {
        await deepLinkGoto(`/friends?add=${encodeURIComponent(payload)}`);
        if (get(page).url.pathname !== '/friends') {
          return 'defer';
        }
      } else if (preview.kind === 'feed') {
        await deepLinkGoto(`/feeds?follow=${encodeURIComponent(preview.hash ?? payload)}`);
        if (get(page).url.pathname !== '/feeds') {
          return 'defer';
        }
      }
      // Unknown ed2k:// variants (e.g. magnet-style or future opcodes) are
      // ignored silently — the buffer already filtered to our known prefixes.
      return 'done';
    } catch (e: unknown) {
      if (destroyed) return 'defer';
      toastError(translateError(e));
      return 'fail';
    }
  }

  /** Batch answers for links not yet acknowledged, so a drain that stopped at
   *  a failed acknowledgement does not ask about the rest of the batch again. */
  const batchDecisions = new Map<string, Prepared>();

  let processing = false;
  let rerun = false;
  let deferredCount = $state(deferredIds.size);
  let reviewRequestedId = $state<string | null>(null);
  let ackRetryTimer: ReturnType<typeof setTimeout> | undefined;
  // Set on unmount so an in-flight drain stops routing payloads (goto/toasts)
  // into a component that no longer exists.
  let destroyed = false;

  /** How many links were waiting when the notice was closed. It stays closed
   *  until another link is parked; closing it leaves the links waiting. */
  let noticeDismissedAt = $state(0);

  function syncDeferredCount() {
    deferredCount = deferredIds.size;
    if (deferredCount < noticeDismissedAt) noticeDismissedAt = deferredCount;
  }

  function reviewDeferredLink() {
    if (destroyed || reviewRequestedId) return;
    const first = deferredIds.values().next();
    if (first.done) return;
    // Do not remove it yet: if listing the durable queue fails, the banner
    // remains actionable and a later click can retry.
    reviewRequestedId = first.value;
    void drain();
  }

  function scheduleAckRetry() {
    if (destroyed || ackRetryTimer) return;
    ackRetryTimer = setTimeout(() => {
      ackRetryTimer = undefined;
      void drain();
    }, 1_000);
  }

  async function acknowledgeCompletedLink(id: string): Promise<boolean> {
    try {
      await ackPendingDeepLink(id);
      completedIds.delete(id);
      batchDecisions.delete(id);
      return true;
    } catch (e) {
      console.warn('Failed to acknowledge completed deep link; retrying:', e);
      scheduleAckRetry();
      return false;
    }
  }

  async function drain() {
    // Coalesce concurrent triggers (mount + event, or two rapid events) into a
    // single in-flight drain. Anything that arrives mid-drain sets `rerun`, and
    // the outer loop picks it up so no payload is stranded in the buffer.
    if (processing) {
      rerun = true;
      return;
    }
    processing = true;
    try {
      do {
        rerun = false;
        if (destroyed) break;
        const pending = await listPendingDeepLinks();
        const pendingIds = new Set(pending.map((link) => link.id));
        let deferredChanged = false;
        for (const id of deferredIds) {
          if (!pendingIds.has(id)) {
            deferredIds.delete(id);
            deferredChanged = true;
          }
        }
        if (reviewRequestedId && !pendingIds.has(reviewRequestedId)) {
          reviewRequestedId = null;
        }
        if (deferredChanged) syncDeferredCount();
        for (const id of batchDecisions.keys()) {
          if (!pendingIds.has(id)) batchDecisions.delete(id);
        }

        const links = pending.filter(
          (link) => !deferredIds.has(link.id) || link.id === reviewRequestedId,
        );
        // A deferred link being reviewed is asked about on its own, as before.
        const prepared = await confirmFileBatch(
          links.filter(
            (link) =>
              !completedIds.has(link.id) &&
              link.id !== reviewRequestedId &&
              !batchDecisions.has(link.id),
          ),
        );
        for (const [id, p] of prepared) {
          if (p.decision !== undefined) batchDecisions.set(id, p);
        }
        batchQueued = 0;
        for (const link of links) {
          if (destroyed) break;
          const reviewingDeferred = link.id === reviewRequestedId;
          if (!completedIds.has(link.id)) {
            const result = await handlePayload(
              link.payload,
              link.id,
              batchDecisions.get(link.id) ?? prepared.get(link.id),
            );
            if (reviewingDeferred) reviewRequestedId = null;
            if (result === 'done') {
              if (deferredIds.delete(link.id)) syncDeferredCount();
              completedIds.add(link.id);
            } else {
              batchDecisions.delete(link.id);
              // 'defer' (user dismissed) and 'fail' (usually transient — a busy
              // network task, a timed-out command) are both parked: the durable
              // entry is kept and surfaced in the pending banner so Review can
              // retry it, but it is not reopened automatically. Continue so one
              // parked link cannot starve later entries. A 'fail' has already
              // shown its own error toast inside `handlePayload`.
              deferredIds.add(link.id);
              syncDeferredCount();
              continue;
            }
          }
          if (reviewingDeferred) reviewRequestedId = null;
          // If a completed link cannot be durably acknowledged, retry that ack
          // before running additional side effects.
          if (!(await acknowledgeCompletedLink(link.id))) break;
        }
        if (batchQueued > 0 && !destroyed) {
          const count = formatNumber(batchQueued);
          toastSuccess(plural(batchQueued, {
            one: () => m.search_bulk_queued_one({ count }),
            oneShowsCount: true,
            other: () => m.search_bulk_queued_other({ count }),
          }));
        }
        batchQueued = 0;
      } while (rerun);
    } catch (e) {
      // A failed durable-list read must not leave the Review action latched
      // disabled; the deferred ID itself remains available for another try.
      reviewRequestedId = null;
      console.error('Failed to drain pending deep links:', e);
    } finally {
      processing = false;
    }
  }

  onMount(() => {
    // Remount (wizard dismiss / locale reload) must clear the previous
    // instance's teardown latch so new deep links are processed again.
    destroyed = false;
    let mounted = true;
    let unlisten: UnlistenFn | null = null;

    // Await listener registration before the first drain. The backend queue is
    // durable, but a running-instance wake event could otherwise land in the
    // registration gap and remain queued until another link arrives.
    void (async () => {
      try {
        const fn = await listen('deep-link-received', () => {
          void drain();
        });
        if (!mounted) {
          fn();
          return;
        }
        unlisten = fn;
      } catch (e) {
        console.error('Failed to register deep-link listener:', e);
      }
      if (mounted) void drain();
    })();

    return () => {
      mounted = false;
      destroyed = true;
      resolveConfirmation('defer');
      clearTimeout(ackRetryTimer);
      if (unlisten) unlisten();
    };
  });
</script>

<ConfirmDialog
  bind:open={confirmOpen}
  title={confirmTitle || m.deeplink_confirm_title()}
  message={confirmMessage}
  confirmLabel={confirmLabel || m.deeplink_confirm_open()}
  cancelLabel={confirmCancelLabel || m.deeplink_confirm_ignore()}
  isolateMessage={true}
  focusCancel
  onconfirm={() => resolveConfirmation('accept')}
  oncancel={() => resolveConfirmation('reject')}
  ondismiss={() => resolveConfirmation('defer')}
/>

{#if deferredCount > 0 && deferredCount > noticeDismissedAt}
  <div class="deferred-link-notice" role="status" aria-live="polite">
    <span>
      {plural(deferredCount, {
        one: () => m.deeplink_pending_one({ count: deferredCount }),
        oneShowsCount: true,
        few: () => m.deeplink_pending_few({ count: deferredCount }),
        other: () => m.deeplink_pending_other({ count: deferredCount }),
      })}
    </span>
    <button
      type="button"
      aria-disabled={reviewRequestedId !== null}
      onclick={reviewDeferredLink}
    >
      {m.deeplink_review_pending()}
    </button>
    <button
      type="button"
      class="notice-dismiss"
      onclick={() => (noticeDismissedAt = deferredCount)}
      title={m.common_dismiss()}
      aria-label={m.common_dismiss()}
    >
      <IconX size={12} />
    </button>
  </div>
{/if}

<style>
  /* Clear of the sidebar, whose footer it used to cover, at either width. */
  .deferred-link-notice {
    position: fixed;
    left: calc(var(--sidebar-width) + 18px);
    bottom: calc(var(--statusbar-height) + 10px);
    z-index: 9400;
    display: flex;
    align-items: center;
    gap: 12px;
    max-width: min(440px, calc(100vw - var(--sidebar-width) - 36px));
    padding: 10px 12px 10px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-secondary);
    color: var(--text-primary);
    box-shadow: var(--shadow-md);
    font-size: var(--font-size-md);
  }

  .deferred-link-notice span {
    line-height: 1.35;
  }

  .deferred-link-notice button {
    flex-shrink: 0;
  }

  :global(.app-shell:has(.sidebar.collapsed)) .deferred-link-notice {
    left: calc(64px + 18px);
  }

  .deferred-link-notice button[aria-disabled='true'] {
    cursor: wait;
    opacity: 0.65;
  }

  .deferred-link-notice .notice-dismiss {
    width: 24px;
    height: 24px;
    padding: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
  }

  .deferred-link-notice .notice-dismiss:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
</style>
