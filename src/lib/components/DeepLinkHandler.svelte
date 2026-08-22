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
  import { goto } from '$app/navigation';
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
  } from '$lib/api/deeplink';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import { cancelIncomingCollection, presentIncomingCollection } from '$lib/stores/collection';
  import { toastSuccess, toastError } from '$lib/stores/toast';
  import { translateError } from '$lib/i18n';
  import * as m from '$lib/paraglide/messages';

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

  function formatSize(bytes: number): string {
    if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    const units = ['KiB', 'MiB', 'GiB', 'TiB'];
    let value = bytes;
    let unit = -1;
    do {
      value /= 1024;
      unit++;
    } while (value >= 1024 && unit < units.length - 1);
    return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[unit]}`;
  }

  function deepLinkConfirmationMessage(preview: DeepLinkPreview): string {
    if (preview.kind === 'file') {
      const lines = [
        preview.name ?? '',
        formatSize(preview.size ?? 0),
        preview.hash ?? '',
      ];
      if (preview.ember) {
        lines.push(m.deeplink_ember_digest({ hash: preview.ember }));
      }
      return lines.join('\n');
    }
    if (preview.kind === 'server') return preview.endpoint ?? '';
    if (preview.kind === 'serverList') return preview.host ?? '';
    return preview.name ?? '';
  }

  let confirmOpen = $state(false);
  let confirmMessage = $state('');
  let confirmResolver: ((decision: ConfirmDecision) => void) | null = null;

  function requestConfirmation(preview: DeepLinkPreview): Promise<ConfirmDecision> {
    if (destroyed) return Promise.resolve('defer');
    confirmMessage = deepLinkConfirmationMessage(preview);
    confirmOpen = true;
    return new Promise((resolve) => {
      confirmResolver = resolve;
    });
  }

  function resolveConfirmation(decision: ConfirmDecision) {
    const resolve = confirmResolver;
    confirmResolver = null;
    confirmOpen = false;
    resolve?.(decision);
  }

  async function handlePayload(raw: string, pendingId: string): Promise<HandleResult> {
    const payload = raw.trim();
    let preview: DeepLinkPreview;
    try {
      preview = await previewDeepLink(payload);
    } catch (e: unknown) {
      // Parsing/validation errors are permanent for this immutable durable
      // payload. Surface once, then acknowledge so malformed links cannot
      // occupy all queue slots forever.
      if (!destroyed) toastError(translateError(e));
      return destroyed ? 'defer' : 'done';
    }

    const decision = await requestConfirmation(preview);
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
        );
        if (!destroyed) {
          // Use the previewed name, not the re-parsed raw one: `preview.name`
          // has been through `sanitize_remote_text` (which strips bidi
          // overrides), and it is the exact string the user just approved in
          // the confirmation dialog. `parseEd2kLink` does no sanitizing, and
          // toasts have no bidi isolation.
          const displayName = preview.name ?? info.name;
          toastSuccess(
            res.already_queued
              ? m.search_already_queued_name({ name: displayName })
              : m.search_queued_name({ name: displayName }),
          );
        }
      } else if (preview.kind === 'server') {
        const segs = ed2kSegments(payload); // ['server', ip, port]
        const ip = segs[1] ?? '';
        const port = parseInt(segs[2] ?? '', 10);
        if (!ip || !Number.isFinite(port) || port <= 0 || port > 65535) {
          toastError(
            !ip
              ? m.servers_validation_ip_invalid()
              : m.servers_validation_port_range(),
          );
          return 'fail';
        }
        // Add to the list, but don't let a duplicate-add error block the
        // connect — a link pointing at an already-known server should still
        // connect rather than surface a confusing failure.
        try {
          await addServer(ip, port, '');
        } catch (e) {
          console.warn('Deep link: add server failed (continuing to connect):', e);
        }
        const msg = await connectToServer(ip, port);
        if (!destroyed) toastSuccess(msg);
      } else if (preview.kind === 'serverList') {
        const segs = ed2kSegments(payload); // ['serverlist', url]
        const url = segs[1] ?? '';
        if (!isAllowedServerListUrl(url)) {
          // Match the backend's pinned-fetch policy: never silently turn an
          // OS-delivered deep link into an insecure HTTP server-list request.
          toastError(m.security_url_must_be_https());
          return 'fail';
        }
        const msg = await downloadServerMet(url);
        if (!destroyed) toastSuccess(msg);
      } else if (preview.kind === 'collection') {
        // The native side resolves this durable queue id to the OS-delivered
        // path. Never return the raw path to an unrestricted path-taking IPC
        // command, or a compromised renderer could probe arbitrary files.
        const coll = await openPendingCollection(pendingId);
        if (destroyed) return 'defer';
        const presented = presentIncomingCollection(coll);
        await goto('/library');
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
          toastSuccess(m.library_collection_loaded({ name: coll.name, count: coll.files.length }));
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

  let processing = false;
  let rerun = false;
  let deferredCount = $state(deferredIds.size);
  let reviewRequestedId = $state<string | null>(null);
  let ackRetryTimer: ReturnType<typeof setTimeout> | undefined;
  // Set on unmount so an in-flight drain stops routing payloads (goto/toasts)
  // into a component that no longer exists.
  let destroyed = false;

  function syncDeferredCount() {
    deferredCount = deferredIds.size;
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

        const links = pending.filter(
          (link) => !deferredIds.has(link.id) || link.id === reviewRequestedId,
        );
        for (const link of links) {
          if (destroyed) break;
          const reviewingDeferred = link.id === reviewRequestedId;
          if (!completedIds.has(link.id)) {
            const result = await handlePayload(link.payload, link.id);
            if (reviewingDeferred) reviewRequestedId = null;
            if (result === 'done') {
              if (deferredIds.delete(link.id)) syncDeferredCount();
              completedIds.add(link.id);
            } else {
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
  title={m.deeplink_confirm_title()}
  message={confirmMessage}
  confirmLabel={m.deeplink_confirm_open()}
  cancelLabel={m.deeplink_confirm_ignore()}
  isolateMessage={true}
  onconfirm={() => resolveConfirmation('accept')}
  oncancel={() => resolveConfirmation('reject')}
  ondismiss={() => resolveConfirmation('defer')}
/>

{#if deferredCount > 0}
  <div class="deferred-link-notice" role="status" aria-live="polite">
    <span>
      {deferredCount === 1
        ? m.deeplink_pending_one()
        : m.deeplink_pending_other({ count: deferredCount })}
    </span>
    <button
      type="button"
      aria-disabled={reviewRequestedId !== null}
      onclick={reviewDeferredLink}
    >
      {m.deeplink_review_pending()}
    </button>
  </div>
{/if}

<style>
  .deferred-link-notice {
    position: fixed;
    left: 18px;
    bottom: calc(var(--statusbar-height) + 10px);
    z-index: 9400;
    display: flex;
    align-items: center;
    gap: 12px;
    max-width: min(440px, calc(100vw - 36px));
    padding: 10px 12px 10px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-secondary);
    color: var(--text-primary);
    box-shadow: var(--shadow-md);
    font-size: 13px;
  }

  .deferred-link-notice span {
    line-height: 1.35;
  }

  .deferred-link-notice button {
    flex-shrink: 0;
  }

  .deferred-link-notice button[aria-disabled='true'] {
    cursor: wait;
    opacity: 0.65;
  }
</style>
