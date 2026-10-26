<script lang="ts">
  import * as m from '$lib/paraglide/messages';
  // eMule-style chunked upload "Up Status" bar. Each ED2K part is drawn as a
  // segment in one of three states, mirroring eMule's
  // `CUploadListCtrl::DrawUpStatusBar`:
  //   • green (accent)  — we delivered this whole part to the peer this
  //                       session (the `m_DoneBlocks_list` fill).
  //   • dark            — the peer already had this part when it requested the
  //                       file (`m_abyUpPartStatus`), and we have NOT sent it
  //                       this session.
  //   • grey (track)    — neither.
  // Green wins over dark (eMule overlays the sent highlight on top). The whole
  // bar is one element backed by a merged CSS gradient so it stays cheap to
  // render even for multi-GB files with hundreds of parts.
  let {
    partStatus = '',
    partCount = 0,
    partFill = '',
    peerPartStatus = '',
    transferred = 0,
    total = 0,
    color = '',
    peerColor = '',
    title = '',
    peerSense = 'served',
  }: {
    partStatus?: string;
    partCount?: number;
    /** Uploads: hex, one byte per part, of how much of each part went out —
     *  255 whole, 1–254 partly. When present each part fills from its left
     *  edge in proportion, the way eMule draws delivered blocks, so a peer
     *  finishing parts from other sources still shows what we sent it. */
    partFill?: string;
    peerPartStatus?: string;
    /** What the dark overlay means, which differs by direction and is only
     *  observable in the accessible readout. Uploading, `peerPartStatus` is
     *  what the peer already holds; downloading, it is what the swarm holds
     *  and we do not. Saying "already on peer" for the latter states the
     *  opposite of what the bar shows. */
    peerSense?: 'served' | 'swarm';
    /** Unique coverage bytes. Unused while `partCount` is set — the overlay
     *  is served-parts / part-count so it matches the filled segments.
     *  Fallback when the bitmap is missing. */
    transferred?: number;
    total?: number;
    color?: string;
    peerColor?: string;
    title?: string;
  } = $props();

  const MAX_RENDERED_PARTS = 10_000;
  /** The file's real part count. Everything the caller can read back — the
   *  accessible readout, `aria-valuenow` — is in these terms, so it agrees
   *  with the legend a caller renders beside the bar. */
  let count = $derived(Math.max(0, Math.floor(Number(partCount) || 0)));
  /** Segments actually drawn. Past the cap the parts are *bucketed*, not
   *  dropped: clamping `count` truncated instead, so a 65,000-part file drew
   *  its first 10,000 parts — 15% of the file — under a legend describing all
   *  of it. At or below the cap this is 1:1 and nothing changes. */
  /// Derived in this order, not the other way round: picking `segments` first
  /// and dividing to get the bucket size overshoots whenever the division is
  /// inexact. At 10,001 parts that gives 10,000 segments of 2, covering 20,000
  /// parts — so half the bar would be drawn past the end of the file, empty.
  let partsPerSegment = $derived(
    count > MAX_RENDERED_PARTS ? Math.ceil(count / MAX_RENDERED_PARTS) : 1,
  );
  let segments = $derived(Math.ceil(count / partsPerSegment));
  let servedColor = $derived(color || 'var(--accent)');
  // Dark "peer already has" tone — clearly distinct from both the empty track
  // and the green served fill.
  let peerHasColor = $derived(
    peerColor || 'color-mix(in srgb, var(--text-secondary) 32%, var(--bg-input))'
  );

  function decodeBits(hex: string, n: number): boolean[] {
    const bits = new Array(n).fill(false) as boolean[];
    if (!hex) return bits;
    for (let i = 0; i < n; i++) {
      const off = (i >> 3) * 2;
      const byte = parseInt(hex.slice(off, off + 2), 16);
      if (!Number.isNaN(byte) && (byte & (1 << (i & 7))) !== 0) bits[i] = true;
    }
    return bits;
  }

  /** Per-part share sent, 0..1, from `partFill`; null when it is absent. */
  function decodeFill(hex: string, n: number): number[] | null {
    if (!hex || hex.length < n * 2) return null;
    const out = new Array(n).fill(0) as number[];
    for (let i = 0; i < n; i++) {
      const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      out[i] = Number.isNaN(byte) ? 0 : byte >= 255 ? 1 : byte / 255;
    }
    return out;
  }

  let fill = $derived(decodeFill(partFill ?? '', count));
  let bits = $derived(decodeBits(partStatus ?? '', count));
  let peerBits = $derived(decodeBits(peerPartStatus ?? '', count));
  let servedCount = $derived(bits.reduce((acc, b) => acc + (b ? 1 : 0), 0));
  // Parts the peer had that we haven't (re-)sent this session — the visible
  // dark area, used only for the accessible readout.
  let peerOnlyCount = $derived(
    peerBits.reduce((acc, b, i) => acc + (b && !bits[i] ? 1 : 0), 0)
  );
  /** Whether some part has bytes sent without being whole: the case the
   *  whole-part count reads as nothing at all. */
  let anyPartial = $derived(!!fill && fill.some((f) => f > 0 && f < 1));

  // Per segment: how much of it is sent (0..1, green from the left edge) and
  // whether the rest is a part the peer already had (dark) or nothing (grey).
  //
  // Without a fill map a segment is all or nothing, as it has always been: a
  // bucket of several parts reads as served only once every one of them is,
  // so the bar can under-state progress but never claim any the file does
  // not have. With one, a bucket fills by the average of its parts.
  let states = $derived.by(() => {
    const n = segments;
    const per = partsPerSegment;
    const s: { sent: number; peer: boolean }[] = [];
    for (let seg = 0; seg < n; seg++) {
      const start = seg * per;
      const end = Math.min(count, start + per);
      const held = end - start;
      let sent = 0;
      let whole = 0;
      let peer = false;
      for (let i = start; i < end; i++) {
        const f = fill ? fill[i] : bits[i] ? 1 : 0;
        sent += f;
        if (f >= 1) whole += 1;
        else if (peerBits[i]) peer = true;
      }
      const share = held === 0 ? 0 : fill ? sent / held : whole === held ? 1 : 0;
      // Without a fill map, a bucket only partly served still shades dark, as
      // it always has, rather than reading as untouched.
      s.push({ sent: share, peer: peer || (!fill && whole > 0 && whole < held) });
    }
    return s;
  });

  // Each segment becomes a sent run and a rest run; neighbouring runs of one
  // colour merge, so a mostly whole bar is still a handful of stops (hard
  // colour edges = crisp part boundaries).
  let gradient = $derived.by(() => {
    const n = states.length;
    if (n === 0) return 'var(--bg-input)';
    const seg = 100 / n;
    const runs: { color: string; from: number; to: number }[] = [];
    const push = (color: string, from: number, to: number) => {
      if (to <= from) return;
      const last = runs[runs.length - 1];
      if (last && last.color === color && Math.abs(last.to - from) < 1e-6) last.to = to;
      else runs.push({ color, from, to });
    };
    for (let i = 0; i < n; i++) {
      const { sent, peer } = states[i];
      const start = i * seg;
      const split = start + seg * Math.min(1, Math.max(0, sent));
      push(servedColor, start, split);
      push(peer ? peerHasColor : 'var(--bg-input)', split, start + seg);
    }
    const stops = runs.flatMap((r) => [
      `${r.color} ${r.from.toFixed(4)}%`,
      `${r.color} ${r.to.toFixed(4)}%`,
    ]);
    return `linear-gradient(to right, ${stops.join(', ')})`;
  });

  // Thin per-part dividers, but only while parts stay wide enough to read;
  // past ~120 segments the 1px lines smear into a haze, so we drop them and
  // let the filled/empty gradient carry the structure on its own.
  let showSeparators = $derived(segments > 1 && segments <= 120);
  let separator = $derived.by(() => {
    if (!showSeparators) return '';
    const seg = (100 / segments).toFixed(4);
    const line = 'color-mix(in srgb, var(--border) 70%, transparent)';
    return `repeating-linear-gradient(to right, transparent 0, transparent calc(${seg}% - 1px), ${line} calc(${seg}% - 1px), ${line} ${seg}%)`;
  });

  let background = $derived(separator ? `${separator}, ${gradient}` : gradient);

  // aria-valuenow matches the green segments (whole parts served this
  // session), not unique-byte coverage and never session wire bytes.
  // Unique bytes count partial parts the bar does not light; wire bytes
  // reach file size while the bar is still half empty. No on-bar percent
  // overlay: that figure is not session completion, and the digits sat
  // on top of the part map the cell is there to show. The tooltip and
  // sr-only label already carry the served/total counts.
  // With a fill map, what is drawn is every byte sent, so the figure follows
  // it: the caller's unique byte count when it has one, which weighs the short
  // last part correctly, else the parts' average.
  let rawPct = $derived(
    count > 0
      ? fill
        ? total > 0
          ? (transferred / total) * 100
          : (fill.reduce((acc, f) => acc + f, 0) / count) * 100
        : (servedCount / count) * 100
      : total > 0
        ? (transferred / total) * 100
        : 0
  );
  let pct = $derived(Math.min(100, Math.max(0, Number.isFinite(rawPct) ? rawPct : 0)));
</script>

<div
  class="parts-bar"
  role="progressbar"
  aria-valuenow={Math.round(pct)}
  aria-valuemin={0}
  aria-valuemax={100}
  aria-label={title || undefined}
  {title}
>
  <div class="parts-fill" style="background: {background};"></div>
  <span class="sr-only"
    >{m.transfers_parts({ have: servedCount, total: count })}{anyPartial
      ? `, ${m.transfers_parts_sent({ percent: Math.round(pct) })}`
      : ''}{peerOnlyCount > 0
      ? `, ${
          peerSense === 'swarm'
            ? m.transfers_parts_swarm({ peer: peerOnlyCount })
            : m.transfers_parts_peer({ peer: peerOnlyCount })
        }`
      : ''}</span
  >
</div>

<style>
  .parts-bar {
    position: relative;
    height: 16px;
    background: var(--bg-input);
    border: 1px solid color-mix(in srgb, var(--border) 60%, transparent);
    border-radius: var(--radius-pill);
    overflow: hidden;
    min-width: 100px;
  }

  .parts-fill {
    position: absolute;
    inset: 0;
    transition: background var(--transition-slow) ease;
  }

  @media (prefers-reduced-motion: reduce) {
    .parts-fill {
      transition: none;
    }
  }
</style>
