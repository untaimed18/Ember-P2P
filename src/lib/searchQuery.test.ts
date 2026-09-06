import { describe, expect, it } from 'vitest';
import {
  MAX_SEARCH_QUERY_LEN,
  clampQueryBytes,
  isServerDirectiveQuery,
  queryHasNetworkKeyword,
} from './searchQuery';

const bytes = (s: string) => new TextEncoder().encode(s).length;

/** The hash `search::query::tests` uses, so the two sides read as one suite. */
const HASH = 'AABBCCDDEEFF00112233445566778899';

describe('clampQueryBytes', () => {
  it('leaves anything within the cap exactly as typed', () => {
    for (const sample of ['', 'linux mint iso', 'a'.repeat(MAX_SEARCH_QUERY_LEN), '日本語']) {
      expect(clampQueryBytes(sample)).toBe(sample);
    }
  });

  it('clamps by UTF-8 bytes, not by characters', () => {
    // The bug this exists for: 1024 CJK characters are ~3072 bytes, so a
    // character-wise slice handed the backend a query it rejects outright.
    const cjk = '語'.repeat(MAX_SEARCH_QUERY_LEN);
    expect(bytes(cjk)).toBeGreaterThan(MAX_SEARCH_QUERY_LEN);

    const clamped = clampQueryBytes(cjk);
    expect(bytes(clamped)).toBeLessThanOrEqual(MAX_SEARCH_QUERY_LEN);
    // Every character is 3 bytes, so the cap lands one byte short of exact.
    expect(clamped).toBe('語'.repeat(341));
  });

  it('never emits more than the cap, whatever the mix of widths', () => {
    const samples = [
      'a'.repeat(MAX_SEARCH_QUERY_LEN + 1),
      'a'.repeat(MAX_SEARCH_QUERY_LEN * 2),
      '語'.repeat(600),
      '🎬'.repeat(400),
      `${'a'.repeat(1022)}語`,
      `${'a'.repeat(1023)}🎬`,
    ];
    for (const sample of samples) {
      expect(bytes(clampQueryBytes(sample))).toBeLessThanOrEqual(MAX_SEARCH_QUERY_LEN);
    }
  });

  it('never splits a surrogate pair', () => {
    // An emoji is two UTF-16 units and four UTF-8 bytes. Cutting between the
    // halves would put a lone surrogate on the wire, which encodes as U+FFFD
    // and is not what the user typed.
    const clamped = clampQueryBytes('🎬'.repeat(400));
    expect(bytes(clamped)).toBe(1024);
    expect(clamped).toBe('🎬'.repeat(256));
    // Iterating with `Array.from` yields code points, so a properly paired
    // emoji comes back as one element well above the surrogate range. Testing
    // for `[\uD800-\uDFFF]` directly would be wrong: every emoji contains two
    // surrogate code *units*, and only an unpaired one is a defect.
    const lone = Array.from(clamped).some((ch) => {
      const cp = ch.codePointAt(0) ?? 0;
      return cp >= 0xd800 && cp <= 0xdfff;
    });
    expect(lone).toBe(false);

    // A pair straddling the boundary is dropped whole rather than halved.
    const straddling = clampQueryBytes(`${'a'.repeat(1022)}🎬`);
    expect(straddling).toBe('a'.repeat(1022));
  });
});

describe('isServerDirectiveQuery', () => {
  it('accepts every form the Rust parser accepts', () => {
    // Mirrors `search::query::tests::a_server_directive_stays_one_term` and
    // `a_directive_hash_is_normalized_to_the_form_emule_sends`.
    for (const query of [
      `ed2k::${HASH}`,
      `related::${HASH}`,
      // eMule: "related::<file hash> or related:<file size>:<file hash>".
      `related:1234:${HASH}`,
      // Several hashes in one request (eserver 17.14 and later).
      `related::${HASH}::${HASH}`,
      `RELATED::${HASH.toLowerCase()}`,
      // Rust splits on ':' and drops empty fields, so extra and trailing
      // colons are tolerated there and must be here.
      `ed2k:::${HASH}`,
      `ed2k::${HASH}::`,
      `  ed2k::${HASH}  `,
    ]) {
      expect(isServerDirectiveQuery(query)).toBe(true);
    }
  });

  it('rejects the near misses that are really ordinary keywords', () => {
    // Mirrors `search::query::tests::near_misses_are_still_ordinary_keywords`.
    for (const query of [
      'related::not-a-hash',
      'related::aabbcc',
      `ed2k://|file|movie.mkv|734003200|${HASH}|/`,
      'relatedness::stuff',
      `related:size:${HASH}`,
      `ed2k:12a4:${HASH}`,
      `ed2k::${HASH.slice(0, 31)}`,
      `ed2k::${HASH}Z`,
      'linux mint iso',
      '',
    ]) {
      expect(isServerDirectiveQuery(query)).toBe(false);
    }
  });

  it('does not claim a directive combined with operators', () => {
    // Pins the documented divergence from Rust, which recognises a directive
    // per term. The backend still keeps the DHT legs out of these; only the
    // page's explanation does not cover them.
    expect(isServerDirectiveQuery(`ed2k::${HASH} AND video`)).toBe(false);
    expect(isServerDirectiveQuery(`-ed2k::${HASH}`)).toBe(false);
  });
});

describe('queryHasNetworkKeyword', () => {
  it('holds the 3-byte floor the publisher indexes by', () => {
    expect(queryHasNetworkKeyword('abc')).toBe(true);
    expect(queryHasNetworkKeyword('ab')).toBe(false);
    expect(queryHasNetworkKeyword('')).toBe(false);
    expect(queryHasNetworkKeyword('   ')).toBe(false);
  });

  it('measures bytes, so one CJK character is a usable key', () => {
    expect(bytes('語')).toBe(3);
    expect(queryHasNetworkKeyword('語')).toBe(true);
  });

  it('splits on the separators a filename is tokenized by', () => {
    // Every token here is one byte, so there is nothing to look up even
    // though the string is long.
    expect(queryHasNetworkKeyword('a.b.c-d_e')).toBe(false);
    expect(queryHasNetworkKeyword('ab cd movie')).toBe(true);
  });
});
