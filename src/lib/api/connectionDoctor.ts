import { invoke } from '@tauri-apps/api/core';

/** `checking`: online, nothing has tested TCP from outside yet, and something
 *  still can. `untested`: the same, but nothing will as things stand. */
export type ConnectionVerdict = 'reachable' | 'relayed' | 'limited' | 'checking' | 'untested' | 'offline';
export type ConnectionCheckStatus = 'pass' | 'warn' | 'fail' | 'skip';

export interface ConnectionCheck {
  /** Which check, for its label: `listen_ports`, `upnp`, `outside_tcp`… */
  id: string;
  status: ConnectionCheckStatus;
  /** What it found, for the explanation: `ok`, `open`, `low_id`… */
  detail: string;
}

export interface ConnectionFix {
  id: string;
  /** Set for a fix the doctor can do itself, after the user confirms. */
  action: string | null;
}

export interface ConnectionReport {
  verdict: ConnectionVerdict;
  checks: ConnectionCheck[];
  /** What Ember already does about it: `relay`, `buddy`, `punch`. */
  helping: string[];
  /** Most likely first, at most three. */
  fixes: ConnectionFix[];
  tcp_port: number;
  udp_port: number;
  /** This computer's address on the local network; empty when unknown. */
  lan_ip: string;
  public_ip: string;
  /** Whether the server's outside-in probe ran. */
  probed: boolean;
}

/** Run every check. Takes a few seconds: the server dials back. */
export async function runConnectionCheck(): Promise<ConnectionReport> {
  return invoke('run_connection_check');
}

/** One of the fixes the backend does itself: `retry_upnp`, `recheck`,
 *  `add_firewall_rules` (asks Windows for permission). Resolves whether it
 *  took. */
export async function connectionDoctorAction(action: string): Promise<boolean> {
  return invoke('connection_doctor_action', { action });
}
