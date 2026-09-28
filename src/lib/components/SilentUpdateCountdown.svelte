<script lang="ts">
  // The one-minute warning before a silent update, for a window someone can
  // see. The backend runs the clock; this only draws it and answers. A window
  // hidden in the tray gets the desktop notification and the tray's own
  // "Cancel update" entry instead, and is never pulled to the front for this.
  import * as m from '$lib/paraglide/messages';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import { translateError } from '$lib/i18n';
  import {
    silentUpdate,
    silentUpdateNow,
    silentUpdatePostpone,
    silentUpdateSkip,
  } from '$lib/stores/silentUpdate';
  import { toastError } from '$lib/stores/toast';

  let visible = $state(typeof document === 'undefined' || document.visibilityState === 'visible');
  let now = $state(Date.now());
  let open = $state(false);
  /** The countdown the user already answered, so the dialog does not come
   *  back for it while the backend catches up. */
  let answeredFor = $state<number | null>(null);

  $effect(() => {
    const onVisibility = () => (visible = document.visibilityState === 'visible');
    document.addEventListener('visibilitychange', onVisibility);
    return () => document.removeEventListener('visibilitychange', onVisibility);
  });

  const endsAt = $derived(
    $silentUpdate?.phase === 'countdown' ? $silentUpdate.countdownEndsAt : null,
  );

  $effect(() => {
    if (endsAt === null) return;
    now = Date.now();
    const timer = window.setInterval(() => (now = Date.now()), 250);
    return () => window.clearInterval(timer);
  });

  $effect(() => {
    open = endsAt !== null && visible && answeredFor !== endsAt;
  });

  const secondsLeft = $derived(endsAt === null ? 0 : Math.max(0, Math.ceil((endsAt - now) / 1000)));
  const timeText = $derived(`${Math.floor(secondsLeft / 60)}:${String(secondsLeft % 60).padStart(2, '0')}`);
  const version = $derived($silentUpdate?.version ?? '');

  function answer(action: () => Promise<void>) {
    answeredFor = endsAt;
    void action().catch((e) => toastError(translateError(e, m.error_operation_failed())));
  }
</script>

<ConfirmDialog
  bind:open
  title={m.silent_update_countdown_title({ time: timeText })}
  message={m.silent_update_countdown_body({ version })}
  confirmLabel={m.silent_update_countdown_now()}
  cancelLabel={m.silent_update_countdown_later()}
  altLabel={m.silent_update_countdown_skip()}
  onconfirm={() => answer(silentUpdateNow)}
  oncancel={() => answer(silentUpdatePostpone)}
  onalt={() => answer(() => silentUpdateSkip(version))}
/>
