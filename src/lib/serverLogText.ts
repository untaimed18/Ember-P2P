import * as m from '$lib/paraglide/messages';
import { formatNumber } from '$lib/utils';
import type { ServerLogReason } from '$lib/types';

type LineFn = (inputs: Record<string, string>) => string;

/** The message for each line the backend writes (`log_line` in
 *  `network/server.rs`, whose test holds the two to the same keys and
 *  arguments). */
const LINES: Record<string, LineFn> = {
  connecting: m.server_log_connecting as unknown as LineFn,
  trying_encrypted: m.server_log_trying_encrypted as unknown as LineFn,
  encrypted_established: m.server_log_encrypted_established as unknown as LineFn,
  encrypted_failed: m.server_log_encrypted_failed as unknown as LineFn,
  tcp_established: m.server_log_tcp_established as unknown as LineFn,
  sending_login: m.server_log_sending_login as unknown as LineFn,
  encrypted_login_failed: m.server_log_encrypted_login_failed as unknown as LineFn,
  sending_plain_login: m.server_log_sending_plain_login as unknown as LineFn,
  connected: m.server_log_connected as unknown as LineFn,
  reassigned: m.server_log_reassigned as unknown as LineFn,
  added_from_update: m.server_log_added_from_update as unknown as LineFn,
  added_from_server: m.server_log_added_from_server as unknown as LineFn,
  moved: m.server_log_moved as unknown as LineFn,
  blocked: m.server_log_blocked as unknown as LineFn,
  not_connecting: m.server_log_not_connecting as unknown as LineFn,
  disconnecting: m.server_log_disconnecting as unknown as LineFn,
  disconnected: m.server_log_disconnected as unknown as LineFn,
  failed: m.server_log_failed as unknown as LineFn,
  retrying: m.server_log_retrying as unknown as LineFn,
  retrying_later: m.server_log_retrying_later as unknown as LineFn,
  retrying_network_down: m.server_log_retrying_network_down as unknown as LineFn,
  auto_connect_failed: m.server_log_auto_connect_failed as unknown as LineFn,
  connection_error: m.server_log_connection_error as unknown as LineFn,
  server_message: m.server_log_server_message as unknown as LineFn,
  server_warning: m.server_log_server_warning as unknown as LineFn,
  server_error: m.server_log_server_error as unknown as LineFn,
};

const REASONS: Record<string, () => string> = {
  refused: m.server_log_reason_refused,
  timed_out: m.server_log_reason_timed_out,
  reset: m.server_log_reason_reset,
  aborted: m.server_log_reason_aborted,
  host_unreachable: m.server_log_reason_host_unreachable,
  network_down: m.server_log_reason_network_down,
  lost: m.server_log_reason_lost,
  closed: m.server_log_reason_closed,
  dns: m.server_log_reason_dns,
  moved: m.server_log_reason_moved,
  ip_filter: m.server_log_reason_ip_filter,
  not_listed: m.server_log_reason_not_listed,
  rejected: m.server_log_reason_rejected,
  no_login: m.server_log_reason_no_login,
  you: m.server_log_reason_you,
  silent: m.server_log_reason_silent,
  bad_reply: m.server_log_reason_bad_reply,
  no_server: m.server_log_reason_no_server,
  server_met: m.server_log_reason_server_met,
};

/** Counts, as opposed to ports and IDs, which are read as they are. */
const COUNT_ARGS = new Set(['users', 'files', 'count']);

export interface ServerLogParts {
  message: string;
  key?: string;
  args?: Record<string, string>;
  reason?: ServerLogReason;
}

/** A reason in the user's language, or as the backend wrote it when it could
 *  not tell what the error was. */
export function serverLogReasonText(reason: ServerLogReason): string {
  const fn = reason.key ? REASONS[reason.key] : undefined;
  return fn ? fn() : reason.detail;
}

/** A server log line in the user's language. A line with no key, or one this
 *  build has no message for, is shown in the backend's English. */
export function serverLogText(line: ServerLogParts): string {
  const fn = line.key ? LINES[line.key] : undefined;
  if (!fn) return line.message;
  const inputs: Record<string, string> = {};
  for (const [name, value] of Object.entries(line.args ?? {})) {
    const count = Number(value);
    inputs[name] = COUNT_ARGS.has(name) && Number.isFinite(count) ? formatNumber(count) : value;
  }
  if (line.reason) inputs.reason = serverLogReasonText(line.reason);
  return fn(inputs);
}

/** The error as it came, for a line that says it in other words: what a
 *  report or a search for the error needs. */
export function serverLogDetail(line: ServerLogParts): string | undefined {
  return line.reason?.key ? line.reason.detail : undefined;
}
