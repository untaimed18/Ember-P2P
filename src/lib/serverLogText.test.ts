import { describe, expect, it } from 'vitest';
import * as m from '$lib/paraglide/messages';
import { formatNumber } from '$lib/utils';
import { serverLogDetail, serverLogReasonText, serverLogText } from './serverLogText';

describe('serverLogText', () => {
  it('renders a line from its message and arguments', () => {
    expect(serverLogText({ message: 'Connecting to 192.0.2.1:4661…', key: 'connecting', args: { addr: '192.0.2.1:4661' } }))
      .toBe(m.server_log_connecting({ addr: '192.0.2.1:4661' }));
  });

  it('says why in other words when the backend could tell, and as it came when not', () => {
    const refused = { key: 'refused', detail: 'Connect failed: Connection refused (os error 111)' };
    expect(serverLogText({ message: 'Connection failed (…).', key: 'failed', reason: refused }))
      .toBe(m.server_log_failed({ reason: m.server_log_reason_refused() }));
    expect(serverLogReasonText({ detail: 'server connection task failed' })).toBe('server connection task failed');
    expect(serverLogReasonText({ key: 'not_a_cause_this_build_knows', detail: 'raw' })).toBe('raw');
  });

  it('shows the English it came with for a line this build has no message for', () => {
    expect(serverLogText({ message: 'Something new', key: 'from_a_newer_backend' })).toBe('Something new');
    expect(serverLogText({ message: 'Page line' })).toBe('Page line');
  });

  it('writes counts in the locale and leaves ports and IDs alone', () => {
    const text = serverLogText({
      message: '',
      key: 'connected',
      args: { server: 'A server', users: '123456', files: '7890123', id: 'HighID' },
    });
    expect(text).toBe(
      m.server_log_connected({ server: 'A server', users: formatNumber(123456), files: formatNumber(7890123), id: 'HighID' }),
    );
    expect(serverLogText({ message: '', key: 'sending_login', args: { port: '14662' } }))
      .toBe(m.server_log_sending_login({ port: '14662' }));
  });

  it('keeps the error as it came for a reason said in other words, and only then', () => {
    expect(serverLogDetail({ message: '', reason: { key: 'reset', detail: 'Connection reset by peer (os error 104)' } }))
      .toBe('Connection reset by peer (os error 104)');
    expect(serverLogDetail({ message: '', reason: { detail: 'shown already' } })).toBeUndefined();
    expect(serverLogDetail({ message: '' })).toBeUndefined();
  });
});
