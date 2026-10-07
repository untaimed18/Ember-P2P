import { listen } from '@tauri-apps/api/event';
import { kadRecheckFirewall } from '$lib/api/kad';

/** `untested`: no peer could be asked about that port this time. */
export type PortVerdict = 'open' | 'closed' | 'untested';

export interface PortTestResult {
  tcpPort: number;
  udpPort: number;
  tcp: PortVerdict;
  udp: PortVerdict;
}

/** The check answers once its 30 s response window closes, at the next 10 s
 *  tick; this leaves room for a busy network task on top of that. */
export const PORT_TEST_TIMEOUT_MS = 90_000;

export class PortTestTimeout extends Error {
  constructor() {
    super('port test timed out');
    this.name = 'PortTestTimeout';
  }
}

function verdict(raw: unknown): PortVerdict {
  return raw === true ? 'open' : raw === false ? 'closed' : 'untested';
}

/** The `firewall-check-finished` payload, or null if it is not one. */
export function parsePortTestResult(payload: unknown): PortTestResult | null {
  if (!payload || typeof payload !== 'object') return null;
  const p = payload as Record<string, unknown>;
  if (typeof p.tcp_port !== 'number' || typeof p.udp_port !== 'number') return null;
  return {
    tcpPort: p.tcp_port,
    udpPort: p.udp_port,
    tcp: verdict(p.tcp_open),
    udp: verdict(p.udp_open),
  };
}

/**
 * Ask a few KAD peers to connect back to our TCP and UDP ports, and resolve
 * with what this one check saw. Rejects with the backend's error when no peer
 * could be asked, and with `PortTestTimeout` when no answer came.
 */
export async function runPortTest(timeoutMs = PORT_TEST_TIMEOUT_MS): Promise<PortTestResult> {
  let started = false;
  let settle: ((result: PortTestResult) => void) | null = null;
  const answered = new Promise<PortTestResult>((resolve) => {
    settle = resolve;
  });
  // Listening before asking, so an answer cannot slip in between. Anything
  // that arrives before the backend confirms the new check began closed an
  // earlier one.
  const unlisten = await listen<unknown>('firewall-check-finished', (event) => {
    if (!started) return;
    const result = parsePortTestResult(event.payload);
    if (result) settle?.(result);
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await kadRecheckFirewall();
    started = true;
    return await Promise.race([
      answered,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new PortTestTimeout()), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
    unlisten();
  }
}
