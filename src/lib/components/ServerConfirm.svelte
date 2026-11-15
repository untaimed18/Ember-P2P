<script lang="ts">
  // emberd's questions: where the desktop app would show a native dialog, the
  // server asks every open page and takes the first answer. A page closed
  // without answering, or no page open at all, counts as "no".
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import ConfirmDialog from './ConfirmDialog.svelte';

  interface Question {
    id: number;
    title: string;
    message: string;
    ok: string;
    cancel: string;
    info: boolean;
    /** A web address going ahead opens: opened here, as the button is
     *  clicked, since a browser opens a tab only from a click. */
    opens?: string;
  }

  let questions = $state<Question[]>([]);
  const current = $derived(questions[0]);
  /** Questions emberd stopped waiting for, answered elsewhere or given up on. */
  const closed = new Set<number>();

  function settle(id: number) {
    questions = questions.filter((q) => q.id !== id);
  }

  function answer(accepted: boolean) {
    const question = current;
    if (!question) return;
    settle(question.id);
    if (accepted && question.opens && /^https?:\/\//i.test(question.opens)) {
      window.open(question.opens, '_blank', 'noopener,noreferrer');
    }
    void invoke('answer_confirm', { id: question.id, accepted }).catch((e) => {
      // Asked again rather than lost: emberd would otherwise wait minutes
      // for an answer and then take it as no. Unless it gave up meanwhile.
      console.error('Failed to answer emberd:', e);
      if (!closed.has(question.id)) questions = [question, ...questions];
    });
  }

  onMount(() => {
    const stops: Array<Promise<() => void>> = [
      listen<Question>('ember:confirm', (event) => {
        const question = event.payload;
        if (question && !questions.some((q) => q.id === question.id)) questions = [...questions, question];
      }),
      listen<number>('ember:confirm-closed', (event) => {
        closed.add(event.payload);
        settle(event.payload);
      }),
    ];
    return () => {
      for (const stop of stops) void stop.then((fn) => fn()).catch(() => {});
    };
  });
</script>

{#if current}
  {#key current.id}
    <ConfirmDialog
      open
      title={current.title}
      message={current.message}
      confirmLabel={current.ok}
      cancelLabel={current.cancel}
      danger={!current.info}
      focusCancel={!current.info}
      isolateMessage
      onconfirm={() => answer(true)}
      oncancel={() => answer(false)}
      ondismiss={() => answer(false)}
    />
  {/key}
{/if}
