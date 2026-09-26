import { describe, expect, it } from 'vitest';
import { toolbarMove } from './rovingToolbar';

describe('toolbarMove', () => {
  it('steps along the row and wraps at both ends', () => {
    expect(toolbarMove(0, 'ArrowRight', 3)).toBe(1);
    expect(toolbarMove(2, 'ArrowRight', 3)).toBe(0);
    expect(toolbarMove(0, 'ArrowLeft', 3)).toBe(2);
  });

  it('follows the reading direction in a right-to-left layout', () => {
    expect(toolbarMove(0, 'ArrowLeft', 3, true)).toBe(1);
    expect(toolbarMove(0, 'ArrowRight', 3, true)).toBe(2);
  });

  it('jumps to the ends on Home and End', () => {
    expect(toolbarMove(1, 'Home', 4)).toBe(0);
    expect(toolbarMove(1, 'End', 4)).toBe(3);
  });

  it('leaves other keys, and an empty row, alone', () => {
    expect(toolbarMove(0, 'ArrowDown', 3)).toBeNull();
    expect(toolbarMove(0, 'Enter', 3)).toBeNull();
    expect(toolbarMove(0, 'ArrowRight', 0)).toBeNull();
  });
});
