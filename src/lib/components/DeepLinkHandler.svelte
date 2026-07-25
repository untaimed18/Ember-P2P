<script lang="ts">
  // Handler for OS-delivered deep links. It drains the backend's durable
  // buffer and presents an in-app confirmation before network side effects,
  // then routes confirmed payloads into the same flows the UI already uses:
  //   - ed2k://|file|...        -> queue a download
  //   - ed2k://|server|ip|port  -> add + connect to the ed2k server
  //   - ed2k://|serverlist|url  -> download a server.met list
  //   - *.emulecollection       -> open on the library page
  import { onMount } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { goto } from '$app/navigation';
  import { parseEd2kLink } from '$lib/api/search';
  import { startDownload } from '$lib/api/transfers';
  import { addServer, connectToServer, downloadServerMet } from '$lib/api/server';
  import {
    ackPendingDeepLink,
    listPendingDeepLinks,
    openCollectionFile,
    previewDeepLink,
    type DeepLinkPreview,
  } from '$lib/api/deeplink';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import { presentIncomingCollection } from '$lib/stores/collection';
  import { toastSuccess, toastError } from '$lib/stores/toast';
  import { translateError } from '$lib/i18n';
  import * as m from '$lib/paraglide/messages';

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
      return `${preview.name ?? ''}\n${formatSize(preview.size ?? 0)}\n${preview.hash ?? ''}`;
    }
    if (preview.kind === 'server') return preview.endpoint ?? '';
    if (preview.kind === 'serverList') return preview.host ?? '';
    return preview.name ?? '';
  }

  let confirmOpen = false;
  let confirmMessage = '';
  let confirmResolver: ((confirmed: boolean) => void) | null = null;

  function requestConfirmation(preview: DeepLinkPreview): Promise<boolean> {
    if (destroyed) return Promise.resolve(false);
    confirmMessage = deepLinkConfirmationMessage(preview);
    confirmOpen = true;
    return new Promise((resolve) => {
      confirmResolver = resolve;
    });
  }

  function resolveConfirmation(confirmed: boolean) {
    const resolve = confirmResolver;
    confirmResolver = null;
    confirmOpen = false;
    resolve?.(confirmed);
  }

  async function handlePayload(raw: string): Promise<boolean> {
    const payload = raw.trim();
    let preview: DeepLinkPreview;
    try {
      preview = await previewDeepLink(payload);
    } catch (e: unknown) {
      // Parsing/validation errors are permanent for this immutable durable
      // payload. Surface once, then acknowledge so malformed links cannot
      // occupy all queue slots forever.
      if (!destroyed) toastError(translateError(e));
      return !destroyed;
    }

    if (preview.kind !== 'collection') {
      const confirmed = await requestConfirmation(preview);
      if (destroyed) return false;
      // Explicit cancellation is a terminal user decision and is therefore
      // acknowledged without executing the network/filesystem action.
      if (!confirmed) return true;
    }

    try {
      if (preview.kind === 'file') {
        const info = await parseEd2kLink(payload);
        const res = await startDownload(
          info.hash,
          info.name,
          info.size,
          '',
          0,
          undefined,
          info.aich,
        );
        if (!destroyed) {
          toastSuccess(
            res.already_queued
              ? m.search_already_queued_name({ name: info.name })
              : m.search_queued_name({ name: info.name }),
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
          return false;
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
          return false;
        }
        const msg = await downloadServerMet(url);
        if (!destroyed) toastSuccess(msg);
      } else if (preview.kind === 'collection') {
        const coll = await openCollectionFile(payload);
        if (destroyed) return false;
        const presented = presentIncomingCollection(coll);
        await goto('/library');
        await presented;
        if (!destroyed) {
          toastSuccess(m.library_collection_loaded({ name: coll.name, count: coll.files.length }));
        }
      }
      // Unknown ed2k:// variants (e.g. magnet-style or future opcodes) are
      // ignored silently — the buffer already filtered to our known prefixes.
      return true;
    } catch (e: unknown) {
      if (destroyed) return false;
      toastError(translateError(e));
      return false;
    }
  }

  let processing = false;
  let rerun = false;
  // A completed side effect stays here until its durable ack succeeds. A
  // retry therefore performs only the acknowledgement, never another
  // download/connect/navigation.
  const completedIds = new Set<string>();
  // Failed entries remain durable for a later app/session retry, but must not
  // immediately re-toast in a tight drain loop.
  const failedIds = new Set<string>();
  let ackRetryTimer: ReturnType<typeof setTimeout> | undefined;
  // Set on unmount so an in-flight drain stops routing payloads (goto/toasts)
  // into a component that no longer exists.
  let destroyed = false;

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
        const links = (await listPendingDeepLinks()).filter((link) => !failedIds.has(link.id));
        for (const link of links) {
          if (destroyed) break;
          if (!completedIds.has(link.id)) {
            if (await handlePayload(link.payload)) {
              completedIds.add(link.id);
            } else {
              failedIds.add(link.id);
              continue;
            }
          }
          // Preserve queue order: if the head cannot be persisted as
          // acknowledged, retry it before presenting later payloads.
          if (!(await acknowledgeCompletedLink(link.id))) break;
        }
      } while (rerun);
    } catch (e) {
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
      resolveConfirmation(false);
      clearTimeout(ackRetryTimer);
      if (unlisten) unlisten();
    };
  });
</script>

<ConfirmDialog
  bind:open={confirmOpen}
  title={m.confirm_default_title()}
  message={confirmMessage}
  confirmLabel={m.confirm_default_button()}
  cancelLabel={m.common_cancel()}
  isolateMessage={true}
  onconfirm={() => resolveConfirmation(true)}
  oncancel={() => resolveConfirmation(false)}
/>
