import { describe, expect, it } from 'vitest';
import { render } from 'svelte/server';
import ReleaseNotes from './ReleaseNotes.svelte';

/** The rendered HTML without hydration comments or scoped-style classes. */
const html = (notes: string) =>
  render(ReleaseNotes, { props: { notes } })
    .body.replace(/<!--[^>]*-->/g, '')
    .replace(/ class="svelte-[\w-]+"/g, '');

describe('ReleaseNotes', () => {
  it('lays the notes out as headings, lists and formatted text', () => {
    const out = html('## Highlights\n\n- **The `.deb`** is *signed*\n- Second\n\nThanks');
    expect(out).toContain('<h4>Highlights');
    expect(out).toMatch(/<ul>[\s\S]*<li>[\s\S]*<strong>The <code>\.deb<\/code>/);
    expect(out).toContain('<em>signed</em>');
    expect(out).toMatch(/<p>Thanks/);
    expect(out).not.toContain('**');
  });

  it('shows markup in the notes as text', () => {
    const out = html('- <img src=x onerror=alert(1)> and [x](javascript:alert(1))');
    expect(out).not.toContain('<img');
    expect(out).not.toContain('href');
    expect(out).toContain('&lt;img src=x onerror=alert(1)>');
  });
});
