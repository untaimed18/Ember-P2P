import { describe, expect, it } from 'vitest';
import * as m from '$lib/paraglide/messages';
import { formatNumber } from '$lib/utils';
import { countsIn, kadNodesLoadedText, serverMetDownloadedText } from './commandReplies';

describe('countsIn', () => {
  it('returns the integers when there are exactly as many as expected', () => {
    expect(countsIn('Loaded 123 contacts from nodes.dat', 1)).toEqual([123]);
    expect(
      countsIn('Downloaded server.met: 3 added, 10 updated, 0 filtered, 2 dropped at capacity', 4),
    ).toEqual([3, 10, 0, 2]);
  });

  it('refuses a reply with more or fewer numbers than expected', () => {
    expect(countsIn('Loaded contacts', 1)).toBeNull();
    expect(countsIn('Loaded 12 of 40 contacts', 1)).toBeNull();
    expect(countsIn('Downloaded server.met: 3 added, 10 updated', 4)).toBeNull();
    expect(countsIn('', 1)).toBeNull();
  });
});

describe('serverMetDownloadedText', () => {
  it('re-renders the four counts in the translated sentence', () => {
    const reply = 'Downloaded server.met: 1234 added, 5 updated, 6 filtered, 7 dropped at capacity';
    expect(serverMetDownloadedText(reply)).toBe(
      m.servers_met_downloaded({
        added: formatNumber(1234),
        updated: '5',
        filtered: '6',
        dropped: '7',
      }),
    );
  });

  it('falls back to a count-free message when the reply changes shape', () => {
    expect(serverMetDownloadedText('Server list refreshed')).toBe(m.servers_met_updated());
  });
});

describe('kadNodesLoadedText', () => {
  it('uses the singular and plural messages', () => {
    expect(kadNodesLoadedText('Loaded 1 contacts from nodes.dat')).toBe(
      m.kad_bootstrap_url_loaded_one(),
    );
    expect(kadNodesLoadedText('Loaded 250 contacts from nodes.dat')).toBe(
      m.kad_bootstrap_url_loaded_other({ count: formatNumber(250) }),
    );
  });

  it('falls back to a count-free message when no single count is present', () => {
    expect(kadNodesLoadedText('done')).toBe(m.kad_bootstrap_url_loaded());
  });
});
