import * as m from '$lib/paraglide/messages';
import { goto } from '$app/navigation';
import { relaunch } from '@tauri-apps/plugin-process';
import { getNetworkBinding, type NetworkBinding } from '$lib/api/networkInterface';
import { translateError } from '$lib/i18n';
import { addActionToast, flushToastActionsBeforeExit, removeToast, toastError } from '$lib/stores/toast';

/** How often the binding is looked at, and how many looks in a row must find
 *  the interface missing before that is said: a VPN that connects just after
 *  Ember starts should not flash a notice. */
const WATCH_MS = 5_000;
const LOOKS_TO_WARN = 2;

type Missing = Exclude<NetworkBinding['state'], 'any' | 'bound'>;

function noticeFor(binding: NetworkBinding & { state: Missing }): string {
  switch (binding.state) {
    case 'waiting':
      return m.network_bind_waiting({ name: binding.name });
    case 'lost':
      return m.network_bind_lost({ name: binding.name });
    case 'changed':
      return m.network_bind_changed({ name: binding.name, address: binding.address ?? '' });
  }
}

function isMissing(binding: NetworkBinding): binding is NetworkBinding & { state: Missing } {
  return binding.state === 'waiting' || binding.state === 'lost' || binding.state === 'changed';
}

async function restart() {
  try {
    await flushToastActionsBeforeExit();
    await relaunch();
  } catch (e) {
    toastError(m.settings_restart_failed({ error: translateError(e) }));
  }
}

/** While the network interface chosen in Settings is not there, say so
 *  wherever the user is: failing closed, Ember sends nothing at all then,
 *  which otherwise looks like a network that is down. Back at another
 *  address, only a restart puts Ember on it, so that is the notice's action;
 *  otherwise it opens the setting. Dismissed or acted on, it stays away
 *  until the interface is back or goes missing another way. For the main
 *  window. Returns the stop. */
export function startNetworkBindWatch(): () => void {
  let stopped = false;
  let looks = 0;
  let toastId: number | null = null;
  let shownFor: Missing | null = null;
  let dismissedFor: Missing | null = null;

  const hide = () => {
    shownFor = null;
    if (toastId === null) return;
    const id = toastId;
    toastId = null;
    removeToast(id);
  };

  const show = (binding: NetworkBinding & { state: Missing }) => {
    if (dismissedFor === binding.state || shownFor === binding.state) return;
    hide();
    shownFor = binding.state;
    const action =
      binding.state === 'changed'
        ? { label: m.settings_restart_now(), run: () => void restart() }
        : {
            label: m.network_bind_open_settings(),
            run: () => {
              void goto('/settings?section=network').catch((e) => console.warn('Failed to open settings:', e));
            },
          };
    toastId = addActionToast(
      'warning',
      noticeFor(binding),
      {
        label: action.label,
        run: () => {
          toastId = null;
          dismissedFor = shownFor;
          shownFor = null;
          action.run();
        },
      },
      () => {
        if (toastId === null) return;
        toastId = null;
        dismissedFor = shownFor;
        shownFor = null;
      },
      0,
    );
  };

  async function look() {
    let binding: NetworkBinding;
    try {
      binding = await getNetworkBinding();
    } catch {
      return;
    }
    if (stopped) return;
    if (!isMissing(binding)) {
      looks = 0;
      dismissedFor = null;
      hide();
      return;
    }
    looks += 1;
    if (looks >= LOOKS_TO_WARN) show(binding);
  }

  const timer = setInterval(() => void look(), WATCH_MS);
  void look();
  return () => {
    stopped = true;
    clearInterval(timer);
    hide();
  };
}
