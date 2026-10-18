import { describe, expect, it } from 'vitest';
import { disappearLabel, disappearsIn } from './chatDisappear';

describe('disappearing message labels', () => {
  it('names each offered timer, and an odd one by the nearest', () => {
    expect(disappearLabel(0)).toBe('Off');
    expect(disappearLabel(300)).toBe('5 minutes');
    expect(disappearLabel(86_400)).toBe('1 day');
    expect(disappearLabel(2_419_200)).toBe('4 weeks');
    expect(disappearLabel(4_000)).toBe('1 hour');
  });

  it('counts down in the largest unit that fits, never to zero', () => {
    const now = 1_000_000 * 1000;
    const at = (secs: number) => 1_000_000 + secs;
    expect(disappearsIn(at(5), now)).toBe('Disappears in 1 min');
    expect(disappearsIn(at(-30), now)).toBe('Disappears in 1 min');
    expect(disappearsIn(at(59 * 60), now)).toBe('Disappears in 59 min');
    expect(disappearsIn(at(3 * 3_600), now)).toBe('Disappears in 3 h');
    expect(disappearsIn(at(2 * 86_400), now)).toBe('Disappears in 2 d');
  });
});
