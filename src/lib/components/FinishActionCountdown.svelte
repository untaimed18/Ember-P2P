<script lang="ts">
  // The last minute before "when downloads finish" exits Ember or puts the
  // computer to sleep. The backend runs the clock; this only draws it and
  // answers. A window hidden in the tray gets the desktop notification and the
  // countdown in the tray tooltip instead.
  import * as m from '$lib/paraglide/messages';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import { translateError } from '$lib/i18n';
  import { finishAction, cancelFinishAction, runFinishActionNow } from '$lib/stores/finishAction';
  import { toastError } from '$lib/stores/toast';

  let visible = $state(typeof document === 'undefined' || document.visibilityState === 'visible');
  let now = $state(Date.now());
  let open = $state(false);
  let answeredFor = $state<number | null>(null);

  $effect(() => {
    const onVisibility = () => (visible = document.visibilityState === 'visible');
    document.addEventListener('visibilitychange', onVisibility);
    return () => document.removeEventListener('visibilitychange', onVisibility);
  });

  const endsAt = $derived($finishAction?.countdownEndsAt ?? null);
  const sleeping = $derived($finishAction?.action === 'sleep');

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

  function answer(action: () => Promise<void>) {
    const answered = endsAt;
    answeredFor = answered;
    void action().catch((e) => {
      toastError(translateError(e, m.error_operation_failed()));
      // Still counting down: put the dialog back rather than leave the user
      // thinking it was cancelled.
      if (answeredFor === answered) answeredFor = null;
    });
  }
</script>

<ConfirmDialog
  bind:open
  title={sleeping
    ? m.finish_action_countdown_sleep_title({ time: timeText })
    : m.finish_action_countdown_exit_title({ time: timeText })}
  message={m.finish_action_countdown_body()}
  confirmLabel={sleeping ? m.finish_action_countdown_sleep_now() : m.finish_action_countdown_exit_now()}
  cancelLabel={m.common_cancel()}
  focusCancel
  onconfirm={() => answer(runFinishActionNow)}
  oncancel={() => answer(cancelFinishAction)}
/>
