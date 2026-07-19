<script lang="ts">
  import { untrack } from 'svelte';
  import { convertFileSrc } from '@tauri-apps/api/core';
  import { resolveMediaAssetPath } from '$lib/api/sharing';
  import * as m from '$lib/paraglide/messages';
  import { translateError } from '$lib/i18n';

  let {
    path,
    kind,
    /** Monotonic id; bump together with playPath to start/restart playback. */
    playId = 0,
    /** Path that playId applies to (ignored when it does not match `path`). */
    playPath = null as string | null,
    stopToken = 0,
  }: {
    path: string;
    kind: 'audio' | 'video';
    playId?: number;
    playPath?: string | null;
    /** Bump to pause in-app playback (e.g. before Open Externally). */
    stopToken?: number;
  } = $props();

  let mediaEl: HTMLAudioElement | HTMLVideoElement | null = $state(null);
  let src = $state('');
  let loadError = $state<string | null>(null);
  /** One-shot: true until we successfully issue play() for the latest playId. */
  let pendingPlay = $state(false);
  let lastPlayId = -1;
  let lastStopToken: number | null = null;

  function stopMedia(el: HTMLAudioElement | HTMLVideoElement | null) {
    if (!el) return;
    el.pause();
    el.removeAttribute('src');
    // Clearing src requires load() so the element releases the file handle.
    el.load();
  }

  function seekAndPlay(el: HTMLAudioElement | HTMLVideoElement) {
    try {
      el.currentTime = 0;
    } catch {
      // Ignore seek errors on freshly attached elements.
    }
    void el.play().then(() => {
      pendingPlay = false;
    }).catch(() => {
      // Autoplay may be blocked; leave pendingPlay so canplay can retry once.
    });
  }

  // Load media ONLY when the file path changes. Play/stop signals must not
  // appear here — depending on them previously cleared `src` and restarted
  // playback whenever the parent re-rendered autoplay state.
  $effect(() => {
    const filePath = path;
    let cancelled = false;

    src = '';
    loadError = null;
    pendingPlay = false;

    void (async () => {
      try {
        const canonical = await resolveMediaAssetPath(filePath);
        if (cancelled) return;
        // The `ember-media` protocol re-checks current shared/download roots
        // for every request. Unlike a global asset-protocol allowance, a URL
        // retained after its folder is removed cannot keep serving that file.
        // Tauri maps custom protocols to `http://<scheme>.localhost` on
        // WebView2. `convertFileSrc` produces that platform-correct URL while
        // the Rust protocol still validates the canonical path per request.
        src = convertFileSrc(canonical, 'ember-media');
      } catch (e: unknown) {
        if (cancelled) return;
        loadError = translateError(e, m.library_media_playback_error());
        src = '';
      }
    })();

    return () => {
      cancelled = true;
      pendingPlay = false;
      untrack(() => stopMedia(mediaEl));
      src = '';
    };
  });

  // Explicit play/restart requests from the Library page (Open, Enter, dblclick…).
  $effect(() => {
    const id = playId;
    const target = playPath;
    if (!target || target !== path || id <= 0 || id === lastPlayId) return;
    lastPlayId = id;
    pendingPlay = true;
    untrack(() => {
      if (mediaEl && src) seekAndPlay(mediaEl);
    });
  });

  // Open Externally bumps stopToken so in-app playback stops immediately.
  $effect(() => {
    const token = stopToken;
    if (lastStopToken === null) {
      lastStopToken = token;
      return;
    }
    if (token === lastStopToken) return;
    lastStopToken = token;
    pendingPlay = false;
    untrack(() => {
      mediaEl?.pause();
    });
  });

  // Catch play requests that arrived before src/element were ready. Never seek
  // here — seeking belongs to the explicit playId effect only. Clear
  // pendingPlay after issuing play so later effect re-runs cannot unpause the
  // user after they hit pause on the native controls.
  $effect(() => {
    const el = mediaEl;
    const mediaSrc = src;
    if (!el || !mediaSrc || !pendingPlay) return;

    const tryPlay = () => {
      if (!pendingPlay) return;
      void el.play().then(() => {
        pendingPlay = false;
      }).catch(() => {});
    };

    if (el.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA) {
      tryPlay();
      return;
    }

    el.addEventListener('canplay', tryPlay, { once: true });
    return () => el.removeEventListener('canplay', tryPlay);
  });

  function onMediaError() {
    // Ignore spurious errors from clearing src during teardown / path changes.
    if (!src) return;
    loadError = m.library_media_playback_error();
  }
</script>

<div class="library-media-player" class:is-video={kind === 'video'} class:is-audio={kind === 'audio'}>
  {#if loadError}
    <p class="media-error">{loadError}</p>
  {:else if src}
    {#if kind === 'video'}
      <!-- svelte-ignore a11y_media_has_caption -->
      <video
        bind:this={mediaEl}
        class="media-el media-video"
        {src}
        controls
        preload="metadata"
        onerror={onMediaError}
      ></video>
    {:else}
      <audio
        bind:this={mediaEl}
        class="media-el media-audio"
        {src}
        controls
        preload="metadata"
        onerror={onMediaError}
      ></audio>
    {/if}
  {/if}
</div>

<style>
  .library-media-player {
    margin-top: 10px;
    padding: 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
  }
  .library-media-player:not(:has(.media-el)):not(:has(.media-error)) {
    display: none;
  }
  .media-el {
    display: block;
    width: 100%;
    border-radius: calc(var(--radius-sm) - 2px);
    background: color-mix(in srgb, var(--bg-base, var(--bg-surface)) 70%, transparent);
  }
  .media-video {
    max-height: 220px;
    object-fit: contain;
    background: #000;
  }
  .media-audio {
    height: 36px;
  }
  .media-error {
    margin: 0;
    font-size: 12px;
    color: var(--danger, #c44);
    line-height: 1.35;
  }
</style>