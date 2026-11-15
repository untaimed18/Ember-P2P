<script lang="ts">
  import * as m from '$lib/paraglide/messages';
  import { translateError } from '$lib/i18n';
  import { logIn, setUp, type ServerSession } from '$lib/runtime/web/session';

  let { session }: { session: ServerSession } = $props();

  // Fixed for the life of the page: finishing setup reloads it.
  const setup = $derived(session.setup_required);
  let code = $state('');
  let password = $state('');
  let repeat = $state('');
  let busy = $state(false);
  let error = $state('');

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    error = '';
    if (setup && password !== repeat) {
      error = m.server_setup_mismatch();
      return;
    }
    busy = true;
    try {
      if (setup) await setUp(code, password);
      else await logIn(password);
      location.reload();
    } catch (e) {
      error = translateError(e, m.error_operation_failed());
      busy = false;
    }
  }
</script>

<main class="server-login">
  <form class="card" onsubmit={submit} aria-describedby={error ? 'server-login-error' : undefined}>
    <div class="brand">
      <img src="/icon.png" alt="" width="40" height="40" draggable="false" />
      <h1>{setup ? m.server_setup_title() : m.server_login_title()}</h1>
    </div>

    {#if session.unencrypted}
      <p class="warning" role="note">{m.server_unencrypted_warning()}</p>
    {/if}

    {#if setup}
      <p class="intro">{m.server_setup_intro()}</p>
      <label>
        <span>{m.server_setup_code()}</span>
        <input
          bind:value={code}
          autocomplete="one-time-code"
          autocapitalize="characters"
          spellcheck="false"
          placeholder="XXXX-XXXX"
          required
        />
      </label>
    {/if}

    <label>
      <span>{setup ? m.server_setup_password() : m.server_login_password()}</span>
      <input
        type="password"
        bind:value={password}
        autocomplete={setup ? 'new-password' : 'current-password'}
        minlength={setup ? session.min_password_chars : undefined}
        required
      />
    </label>
    {#if setup}
      <p class="hint">{m.server_password_hint({ count: session.min_password_chars })}</p>
      <label>
        <span>{m.server_setup_repeat()}</span>
        <input type="password" bind:value={repeat} autocomplete="new-password" required />
      </label>
    {/if}

    {#if error}
      <p class="error" id="server-login-error" role="alert">{error}</p>
    {/if}

    <button class="primary" type="submit" disabled={busy}>
      {#if busy}
        {m.server_login_busy()}
      {:else}
        {setup ? m.server_setup_submit() : m.server_login_submit()}
      {/if}
    </button>

    <p class="version">{m.server_version({ version: session.version })}</p>
  </form>
</main>

<style>
  .server-login {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    background: var(--bg-primary);
  }

  .card {
    width: 100%;
    max-width: 380px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    padding: 28px;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-lg);
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  h1 {
    margin: 0;
    font-size: var(--font-size-xl);
    color: var(--text-primary);
  }

  label {
    display: flex;
    flex-direction: column;
    gap: 6px;
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
  }

  input {
    width: 100%;
    box-sizing: border-box;
  }

  p {
    margin: 0;
    font-size: var(--font-size-sm);
    line-height: 1.45;
  }

  .intro {
    color: var(--text-secondary);
  }

  .hint {
    margin-top: -8px;
    color: var(--text-muted);
  }

  .warning {
    padding: 10px 12px;
    border-radius: var(--radius-md);
    border: 1px solid color-mix(in srgb, var(--warning) 45%, var(--border));
    background: color-mix(in srgb, var(--warning) 12%, transparent);
    color: var(--text-primary);
  }

  .error {
    color: var(--danger);
  }

  button {
    padding: 9px 14px;
  }

  .version {
    text-align: center;
    color: var(--text-muted);
    font-size: var(--font-size-xs);
  }
</style>
