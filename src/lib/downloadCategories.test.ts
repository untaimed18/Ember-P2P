import { describe, expect, it } from 'vitest';
import { UNCATEGORIZED_FILTER, inCategoryFilter, isUncategorized } from './downloadCategories';

describe('the Uncategorized filter', () => {
  it('takes no category, and the None the Category menu names it, as none', () => {
    expect(isUncategorized('')).toBe(true);
    expect(isUncategorized(undefined)).toBe(true);
    expect(isUncategorized(null)).toBe(true);
    expect(isUncategorized('None')).toBe(true);
    expect(isUncategorized('Video')).toBe(false);
    expect(isUncategorized('TV Series')).toBe(false);
  });

  it('holds only downloads without a category', () => {
    expect(inCategoryFilter('', UNCATEGORIZED_FILTER)).toBe(true);
    expect(inCategoryFilter('None', UNCATEGORIZED_FILTER)).toBe(true);
    expect(inCategoryFilter('Video', UNCATEGORIZED_FILTER)).toBe(false);
  });

  it('leaves a category filter matching its own category only', () => {
    expect(inCategoryFilter('Video', 'Video')).toBe(true);
    expect(inCategoryFilter('Audio', 'Video')).toBe(false);
    expect(inCategoryFilter('', 'Video')).toBe(false);
  });

  it('cannot be mistaken for a category the user named', () => {
    expect(UNCATEGORIZED_FILTER).toMatch(/\p{Cc}/u);
  });
});
