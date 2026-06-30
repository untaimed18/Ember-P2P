<script lang="ts">
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
    peerPartStatus = '',
    transferred = 0,
    total = 0,
    color = '',
    peerColor = '',
    title = '',
  }: {
    partStatus?: string;
    partCount?: number;
    peerPartStatus?: string;
    transferred?: number;
    total?: number;
    color?: string;
    peerColor?: string;
    title?: string;
  } = $props();

  let count = $derived(Math.max(0, Math.floor(Number(partCount) || 0)));
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

  let bits = $derived(decodeBits(partStatus ?? '', count));
  let peerBits = $derived(decodeBits(peerPartStatus ?? '', count));
  let servedCount = $derived(bits.reduce((acc, b) => acc + (b ? 1 : 0), 0));
  // Parts the peer had that we haven't (re-)sent this session — the visible
  // dark area, used only for the accessible readout.
  let peerOnlyCount = $derived(
    peerBits.reduce((acc, b, i) => acc + (b && !bits[i] ? 1 : 0), 0)
  );

  // Per-part state: 2 = served (green), 1 = peer-has (dark), 0 = empty (grey).
  let states = $derived.by(() => {
    const n = count;
    const s = new Array(n).fill(0) as number[];
    for (let i = 0; i < n; i++) s[i] = bits[i] ? 2 : peerBits[i] ? 1 : 0;
    return s;
  });

  // Collapse runs of same-state parts into as few gradient stops as
  // possible (hard colour edges = crisp part boundaries).
  let gradient = $derived.by(() => {
    const n = states.length;
    if (n === 0) return 'var(--bg-input)';
    const seg = 100 / n;
    const colorFor = (v: number) =>
      v === 2 ? servedColor : v === 1 ? peerHasColor : 'var(--bg-input)';
    const stops: string[] = [];
    let i = 0;
    while (i < n) {
      const v = states[i];
      let j = i;
      while (j < n && states[j] === v) j++;
      const c = colorFor(v);
      stops.push(`${c} ${(i * seg).toFixed(4)}%`, `${c} ${(j * seg).toFixed(4)}%`);
      i = j;
    }
    return `linear-gradient(to right, ${stops.join(', ')})`;
  });

  // Thin per-part dividers, but only while parts stay wide enough to read;
  // past ~120 segments the 1px lines smear into a haze, so we drop them and
  // let the filled/empty gradient carry the structure on its own.
  let showSeparators = $derived(count > 1 && count <= 120);
  let separator = $derived.by(() => {
    if (!showSeparators) return '';
    const seg = (100 / count).toFixed(4);
    const line = 'color-mix(in srgb, var(--border) 70%, transparent)';
    return `repeating-linear-gradient(to right, transparent 0, transparent calc(${seg}% - 1px), ${line} calc(${seg}% - 1px), ${line} ${seg}%)`;
  });

  let background = $derived(separator ? `${separator}, ${gradient}` : gradient);

  let rawPct = $derived(total > 0 ? (transferred / total) * 100 : 0);
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
  <span class="parts-text">{pct.toFixed(1)}%</span>
  <span class="sr-only"
    >{servedCount}/{count} parts sent{peerOnlyCount > 0
      ? `, ${peerOnlyCount} already on peer`
      : ''}</span
  >
</div>

<style>
  .parts-bar {
    position: relative;
    height: 16px;
    background: var(--bg-input);
    border: 1px solid color-mix(in srgb, var(--border) 60%, transparent);
    border-radius: 2px;
    overflow: hidden;
    min-width: 100px;
  }

  .parts-fill {
    position: absolute;
    inset: 0;
    transition: background 0.3s ease;
  }

  .parts-text {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 11px;
    font-weight: 600;
    color: var(--text-primary);
    pointer-events: none;
    /* Halo so the readout stays legible over both filled and empty
       segments without the two-layer clip trick a single-colour bar uses. */
    text-shadow:
      0 0 2px var(--bg-input),
      0 0 3px var(--bg-input);
  }

  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }

  @media (prefers-reduced-motion: reduce) {
    .parts-fill {
      transition: none;
    }
  }
</style>
