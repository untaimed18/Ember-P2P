import { beforeEach, describe, expect, it, vi } from 'vitest';

const invoke = vi.fn();
const addToast = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({ invoke: (...args: unknown[]) => invoke(...args) }));
vi.mock('$app/navigation', () => ({ goto: async () => {} }));
vi.mock('$lib/stores/toast', () => ({ addToast: (...args: unknown[]) => addToast(...args) }));

const { MAX_RELATED_SEEDS, startRelatedSearch } = await import('./relatedSearch');

const seeds = (n: number) => Array.from({ length: n }, (_, i) => ({ hash: `h${i}`, name: `file${i}.mkv` }));
const plannedSeeds = () => (invoke.mock.calls[0][1] as { seeds: { hash: string }[] }).seeds;

beforeEach(() => {
  invoke.mockReset();
  addToast.mockReset();
  invoke.mockResolvedValue({ query: 'file', probes: [], co_share_hashes: [], exclude_hashes: [], seed_label: 'file' });
});

describe('startRelatedSearch', () => {
  it('plans from the first files the backend takes, and says so', async () => {
    // The backend refuses a plan past the limit outright.
    expect(await startRelatedSearch(seeds(MAX_RELATED_SEEDS + 4))).toBe(true);

    expect(plannedSeeds().map((s) => s.hash)).toEqual(seeds(MAX_RELATED_SEEDS).map((s) => s.hash));
    expect(addToast).toHaveBeenCalledTimes(1);
    expect(addToast.mock.calls[0][0]).toBe('info');
  });

  it('sends every file and says nothing at the limit', async () => {
    expect(await startRelatedSearch(seeds(MAX_RELATED_SEEDS))).toBe(true);

    expect(plannedSeeds()).toHaveLength(MAX_RELATED_SEEDS);
    expect(addToast).not.toHaveBeenCalled();
  });
});
