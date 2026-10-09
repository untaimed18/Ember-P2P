use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use flate2::{Decompress, FlushDecompress, Status};
use tokio::io::AsyncWriteExt;

use tracing::debug;

use super::credits::{CreditManager, IdentState};
use super::messages::*;

/// Returns `true` if the IP should be rejected as a source exchange result.
///
/// Delegates to `security::is_special_use_v4` so every parser path that
/// accepts IPs from the wire (OP_ANSWERSOURCES, SX, EPX injection) uses the
/// same predicate — RFC-1918, loopback, link-local, broadcast, CGNAT (RFC
/// 6598 100.64/10), documentation (TEST-NET-1/2/3), and benchmarking
/// (198.18/15) ranges.
pub(super) fn is_filtered_source_ip(ip: &std::net::Ipv4Addr) -> bool {
    crate::security::is_special_use_v4(*ip)
}

/// Convert parsed EPX result into the flattened vectors used by DownloadEvent.
pub(crate) fn epx_result_to_entries(
    result: &crate::network::ember::ExchangeResult,
) -> (
    Vec<([u8; 16], Vec<(std::net::Ipv4Addr, u16, u16, u8)>)>,
    Vec<([u8; 16], [u8; 20])>,
) {
    let entries = result
        .files
        .iter()
        .map(|e| {
            let srcs = e
                .sources
                .iter()
                .map(|s| (s.ip, s.tcp_port, s.udp_port, s.flags))
                .collect();
            (e.file_hash, srcs)
        })
        .collect();
    let aich_roots = result
        .files
        .iter()
        .filter_map(|e| e.aich_root.map(|r| (e.file_hash, r)))
        .collect();
    (entries, aich_roots)
}

const MAX_DECOMPRESSED_COMPRESSED_PART: usize = 10 * 1024 * 1024;
const MAX_PENDING_COMPRESSED_BLOCKS: usize = 16;
/// Output buffer per inflate round. Bounds allocation churn on a block that
/// arrives in many small fragments without capping how much a fragment may
/// inflate to — the loop simply runs again.
const INFLATE_ROUND_BYTES: usize = 64 * 1024;

/// How much inflated data to accumulate before handing it back to be written.
///
/// eMule compresses a whole requested block in one `compress2` and then splits
/// the result into 10240-byte packets (`UploadDiskIOThread.cpp:238-239`, `:444`),
/// so a 180 KB block usually arrives as ~15 packets of one zlib stream. Writing
/// each packet as it inflated turned one reserve/write/commit cycle per block
/// into fifteen — and each cycle takes the tracker write lock twice and makes an
/// mpsc round-trip to the per-file writer, whose queue also carries other
/// workers' `sync_data()` and 9.28 MB part hashes. That is a lot of contention to
/// add to the receive path, and it shrank disk writes to 10 KB each.
///
/// Batching is a direct trade against how much of an abandoned block survives:
/// whatever is still staged when a peer stops is lost. At 64 KiB a full block
/// costs three cycles instead of fifteen, writes stay comfortably large, and a
/// block abandoned near its end still leaves ~128 KB on disk rather than nothing.
const INFLATE_FLUSH_BYTES: usize = 64 * 1024;

/// Inflate state for one compressed block being received.
struct PendingCompressedBlock {
    declared_total: usize,
    /// Compressed bytes seen, against `declared_total`.
    packed_seen: usize,
    /// Total bytes zlib has produced for this block. Bounds the output allowance,
    /// which is what stops a stream inflating past its requested range.
    inflated: usize,
    /// Bytes already handed to the caller. Also the offset of the next handover
    /// within the block, which is how eMule places each packet's output:
    /// `StartOffset + totalUnzipped - lenUnzipped` (`DownloadClient.cpp:1057`).
    flushed: usize,
    /// Inflated bytes not yet handed over; they belong at `start + flushed`.
    /// Held back so several packets become one disk write — see
    /// [`INFLATE_FLUSH_BYTES`].
    staged: Vec<u8>,
    /// Inflated size the block must reach, from the requested range.
    expected_len: usize,
    inflate: InflateState,
}

/// A compressed block is a single zlib stream spread over several packets, so
/// the inflate state has to live as long as the block. eMule keeps one
/// `z_stream` per pending block and calls `unzip` on each packet
/// (`DownloadClient.cpp:1050`).
enum InflateState {
    /// Fewer than two bytes seen, so zlib and raw deflate are still
    /// indistinguishable. Holds at most one byte.
    Probing(Vec<u8>),
    Running(Box<Decompress>),
}

/// One packet's worth of inflated data, positioned absolutely.
#[derive(Debug)]
pub(super) struct InflatedFragment {
    /// Where in the file these bytes belong. Not the block start except for the
    /// first fragment.
    pub(super) offset: u64,
    pub(super) data: Vec<u8>,
}

/// Whether a two-byte prefix opens a zlib stream (RFC 1950): the low nibble of
/// CMF names the deflate method, and the two bytes together are a multiple of 31.
///
/// Sniffing the header replaces the old "inflate as zlib, and on failure inflate
/// the whole buffer again as raw deflate" fallback, which a streaming decoder
/// cannot do — by the time a mid-block fragment failed, the earlier fragments
/// would already have been written and discarded.
fn looks_like_zlib(header: &[u8]) -> bool {
    header.len() >= 2
        && header[0] & 0x0F == 8
        && ((u16::from(header[0]) << 8) | u16::from(header[1])) % 31 == 0
}

/// Shared bounded reassembly used by both download paths.
///
/// Each fragment is inflated as it arrives and its output returned for writing,
/// rather than the block's compressed bytes being buffered until the last
/// fragment lands. That is what eMule does, and it means a peer that dies
/// part-way through a block still leaves its earlier bytes on disk instead of
/// costing the whole block. It also drops the compressed-byte backlog to nothing:
/// what remains per block is the inflate window, so `MAX_PENDING_COMPRESSED_BLOCKS`
/// is now the only budget worth keeping.
#[derive(Default)]
pub(super) struct CompressedPartAccumulator {
    pending: HashMap<u64, PendingCompressedBlock>,
    /// Blocks whose stream would not inflate, by start, as `(declared_total,
    /// packed_seen)`. eD2K cannot cancel a requested block, so the rest of that
    /// stream is still coming; it is absorbed here rather than fed to a fresh
    /// inflater it would only fail again.
    broken: HashMap<u64, (usize, usize)>,
}

impl CompressedPartAccumulator {
    /// Drop reassembly state for blocks that are no longer outstanding.
    ///
    /// A partially reassembled block is abandoned whenever the receive loop
    /// leaves a part mid-block — most often the ordinary `is_part_complete`
    /// exit, when another source closes the last gap. Entries are otherwise
    /// removed only when a block *completes*, so in the multi-source worker,
    /// where this accumulator is session-scoped for cross-part pipelining, they
    /// simply accumulated. Once `MAX_PENDING_COMPRESSED_BLOCKS` stranded
    /// entries built up, `append` began returning an error that propagates out
    /// of the download and drops an actively transferring peer, which then
    /// reconnects with a fresh accumulator and repeats. Each entry can also
    /// hold up to `MAX_PENDING_COMPRESSED_BYTES` of dead buffer.
    ///
    /// `retained` names the block starts still in flight. The single-source
    /// path does not need this — it scopes its accumulator per part.
    pub(super) fn retain_outstanding(&mut self, retained: impl Fn(u64) -> bool) {
        let before = self.pending.len();
        self.pending.retain(|start, _| retained(*start));
        self.broken.retain(|start, _| retained(*start));
        if before != self.pending.len() {
            debug!(
                "Dropped {} abandoned compressed block(s) from reassembly",
                before - self.pending.len()
            );
        }
    }

    /// Inflate one packet of the block at `start`.
    ///
    /// An error ends that block's stream, never more: the block is dropped, the
    /// rest of its stream is absorbed, and the shortfall stays a gap to
    /// re-request. eMule does the same and keeps the client
    /// (`DownloadClient.cpp:1097`), because a block that was re-requested while
    /// its first stream was still arriving lands that stream's tail on a fresh
    /// inflater, which an honest peer causes as easily as a broken one.
    pub(super) fn append(
        &mut self,
        start: u64,
        requested_end: Option<u64>,
        declared_total: u32,
        chunk: &[u8],
    ) -> anyhow::Result<Option<InflatedFragment>> {
        let declared = declared_total as usize;
        if let Some((total, seen)) = self.broken.get_mut(&start) {
            if *total == declared {
                *seen = seen.saturating_add(chunk.len());
                if *seen >= *total {
                    self.broken.remove(&start);
                }
                return Ok(None);
            }
            self.broken.remove(&start);
        }
        let seen_before = self
            .pending
            .get(&start)
            .filter(|block| block.declared_total == declared)
            .map_or(0, |block| block.packed_seen);
        let result = self.inflate_packet(start, requested_end, declared_total, chunk);
        if result.is_err() {
            self.pending.remove(&start);
            let seen = seen_before.saturating_add(chunk.len());
            if seen < declared && self.broken.len() < MAX_PENDING_COMPRESSED_BLOCKS {
                self.broken.insert(start, (declared, seen));
            }
        }
        result
    }

    fn inflate_packet(
        &mut self,
        start: u64,
        requested_end: Option<u64>,
        declared_total: u32,
        chunk: &[u8],
    ) -> anyhow::Result<Option<InflatedFragment>> {
        let requested_end =
            requested_end.ok_or_else(|| anyhow::anyhow!("unsolicited compressed part start"))?;
        let expected_len = requested_end
            .checked_sub(start)
            .filter(|len| *len > 0)
            .ok_or_else(|| anyhow::anyhow!("invalid outstanding compressed-part range"))?
            as usize;
        if expected_len > MAX_DECOMPRESSED_COMPRESSED_PART {
            anyhow::bail!("outstanding compressed-part range exceeds limit");
        }
        let declared_total = declared_total as usize;
        let max_packed = expected_len
            .saturating_add(expected_len / 10)
            .saturating_add(1024)
            .min(MAX_DECOMPRESSED_COMPRESSED_PART);
        if declared_total == 0 || declared_total > max_packed {
            anyhow::bail!("compressed part declared size outside requested-range budget");
        }
        if chunk.is_empty() {
            anyhow::bail!("compressed part carried an empty fragment");
        }
        // A block's packets arrive back to back, so another size or range at the
        // same start is the stream of a fresh request for it, and the old one
        // is over.
        if self.pending.get(&start).is_some_and(|entry| {
            entry.declared_total != declared_total || entry.expected_len != expected_len
        }) {
            self.pending.remove(&start);
        }
        if !self.pending.contains_key(&start) && self.pending.len() >= MAX_PENDING_COMPRESSED_BLOCKS
        {
            anyhow::bail!("too many concurrent compressed parts");
        }
        let existing = self.pending.get(&start).map_or(0, |entry| entry.packed_seen);
        if chunk.len() > declared_total.saturating_sub(existing) {
            self.remove(start);
            anyhow::bail!("compressed part fragments exceed declared packed size");
        }

        let entry = self
            .pending
            .entry(start)
            .or_insert_with(|| PendingCompressedBlock {
                declared_total,
                packed_seen: 0,
                inflated: 0,
                flushed: 0,
                staged: Vec::new(),
                expected_len,
                inflate: InflateState::Probing(Vec::new()),
            });
        entry.packed_seen += chunk.len();
        let packed_complete = entry.packed_seen >= declared_total;

        // Hold the opening byte back until the format is decidable. `declared_total`
        // is validated non-zero, so a one-byte block resolves on this same call.
        let mut owned_chunk: Option<Vec<u8>> = None;
        let chunk: &[u8] = match &mut entry.inflate {
            InflateState::Probing(head) => {
                let mut combined = std::mem::take(head);
                combined
                    .try_reserve(chunk.len())
                    .map_err(|_| anyhow::anyhow!("compressed-part allocation failed"))?;
                combined.extend_from_slice(chunk);
                if combined.len() < 2 && combined.len() < declared_total {
                    *head = combined;
                    return Ok(None);
                }
                entry.inflate =
                    InflateState::Running(Box::new(Decompress::new(looks_like_zlib(&combined))));
                owned_chunk.insert(combined).as_slice()
            }
            InflateState::Running(_) => chunk,
        };
        let InflateState::Running(inflate) = &mut entry.inflate else {
            unreachable!("inflate state was just set to Running");
        };

        let mut produced: Vec<u8> = Vec::new();
        let mut consumed = 0usize;
        let mut stream_end = false;
        while consumed < chunk.len() && !stream_end {
            // The remaining output allowance is the anti-bomb bound: a stream that
            // wants to inflate past the range we asked for cannot, because the
            // buffer it writes into never has room for more.
            let allowance = entry
                .expected_len
                .saturating_sub(entry.inflated + produced.len());
            if allowance == 0 {
                break;
            }
            let mut buf: Vec<u8> = Vec::new();
            buf.try_reserve_exact(allowance.min(INFLATE_ROUND_BYTES))
                .map_err(|_| anyhow::anyhow!("compressed-part allocation failed"))?;
            let before_in = inflate.total_in();
            let status = inflate
                .decompress_vec(&chunk[consumed..], &mut buf, FlushDecompress::None)
                .map_err(|e| anyhow::anyhow!("compressed part failed to inflate: {e}"))?;
            consumed += (inflate.total_in() - before_in) as usize;
            produced
                .try_reserve(buf.len())
                .map_err(|_| anyhow::anyhow!("compressed-part allocation failed"))?;
            produced.extend_from_slice(&buf);
            if matches!(status, Status::StreamEnd) {
                stream_end = true;
            }
        }

        // Every fragment must be fully consumed, because none of it is retained.
        // Bytes left over mean either the output allowance ran out (the stream
        // inflates past its requested range) or the stream ended with trailing
        // data — both are a broken or hostile block.
        if consumed < chunk.len() {
            self.remove(start);
            anyhow::bail!("decompressed part exceeds requested range");
        }

        let entry = self
            .pending
            .get_mut(&start)
            .expect("pending compressed block removed while borrowed");
        entry.inflated += produced.len();
        entry
            .staged
            .try_reserve(produced.len())
            .map_err(|_| anyhow::anyhow!("compressed-part allocation failed"))?;
        entry.staged.extend_from_slice(&produced);

        let block_done = entry.inflated == entry.expected_len;
        // The stream finished, or every declared compressed byte arrived, yet the
        // output is short of the requested range. Hand over whatever is staged and
        // drop the block, so the shortfall stays a gap and is re-requested.
        let closing_short = !block_done && (stream_end || packed_complete);

        if !block_done && !closing_short && entry.staged.len() < INFLATE_FLUSH_BYTES {
            return Ok(None);
        }

        let offset = start + entry.flushed as u64;
        let data = std::mem::take(&mut entry.staged);
        entry.flushed += data.len();

        if block_done || closing_short {
            self.pending.remove(&start);
        }
        if data.is_empty() {
            if closing_short {
                anyhow::bail!("decompressed part is outside its requested range");
            }
            return Ok(None);
        }
        Ok(Some(InflatedFragment { offset, data }))
    }

    fn remove(&mut self, start: u64) {
        self.pending.remove(&start);
    }
}

/// Silence budget for one outstanding request-range.
///
/// A dropped `AddReqBlock` never produces a packet, so this is a
/// no-traffic timer, not a full-block-completion timer. 30 s is 3× the
/// inter-packet gap of a 1 KB/s trickle (10 KiB slices) and sits 30 s
/// inside the 60 s first-data timeout / 70 s inside `DOWNLOADTIMEOUT_SECS`
/// (100 s), so a discarded request is retried with budget left to wait
/// for the replacement. Any overlapping packet refreshes the deadline,
/// so a healthy 4 KB/s sender finishing a 180 KiB block (~45 s) is not
/// expired between slices.
pub(super) const OUTSTANDING_RANGE_TTL: std::time::Duration =
    std::time::Duration::from_secs(30);

#[derive(Clone, Copy, Debug)]
pub(super) struct OutstandingRange {
    pub start: u64,
    pub end: u64,
    expires_at: std::time::Instant,
}

impl OutstandingRange {
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            start,
            end,
            expires_at: std::time::Instant::now() + OUTSTANDING_RANGE_TTL,
        }
    }

    fn touch(&mut self) {
        self.expires_at = std::time::Instant::now() + OUTSTANDING_RANGE_TTL;
    }
}

pub(super) fn push_outstanding_batch(
    outstanding: &mut Vec<OutstandingRange>,
    batch: &[(u64, u64)],
) {
    outstanding.extend(
        batch
            .iter()
            .copied()
            .map(|(s, e)| OutstandingRange::new(s, e)),
    );
}

/// Drop ranges whose deadline has passed. Returns the expired byte count so
/// callers that track `total_sent_bytes` can shrink the budget; the bytes
/// themselves were never taken out of the gap map (write reservations are
/// acquired only when data arrives), so this does not double-release.
pub(super) fn expire_outstanding_ranges(outstanding: &mut Vec<OutstandingRange>) -> u64 {
    let now = std::time::Instant::now();
    let mut expired_bytes = 0u64;
    outstanding.retain(|r| {
        if r.expires_at <= now {
            expired_bytes = expired_bytes.saturating_add(r.end.saturating_sub(r.start));
            false
        } else {
            true
        }
    });
    expired_bytes
}

pub(super) fn refresh_outstanding_range(outstanding: &mut [OutstandingRange], pkt_start: u64) {
    if let Some(start) = outstanding
        .iter()
        .find(|r| pkt_start >= r.start && pkt_start < r.end)
        .map(|r| r.start)
    {
        touch_queued_from(outstanding, start);
    }
}

/// Refresh every range from `start` on. Uploaders serve requests in order and
/// ours ascend through the part, so the ranges after the one being sent are
/// waiting their turn, not dropped. Timed from the request alone, the second
/// of two blocks at 4 KB/s expired before its first byte (~45 s in), and each
/// expiry re-requested more than the peer could ever deliver. Ranges before
/// `start` the peer has skipped, and keep their own deadline.
fn touch_queued_from(outstanding: &mut [OutstandingRange], start: u64) {
    for r in outstanding.iter_mut().filter(|r| r.start >= start) {
        r.touch();
    }
}

/// Mark a requested `(start, end)` range complete when a packet's exclusive
/// end matches it (eMule `nEndPos == cur_block->block->EndOffset` after the
/// inclusive conversion). eMule also requires `lenWritten > 0` before
/// completing a range; we still count a duplicate (no-op write) as complete
/// so range-driven refill cannot stall. Returns true only the first time so
/// subsequent packets cannot drive another refill. A non-completing overlap
/// refreshes the range deadline so a slow-but-live sender is not expired.
pub(super) fn take_completed_outstanding_range(
    outstanding: &mut Vec<OutstandingRange>,
    pkt_start: u64,
    pkt_end: u64,
) -> bool {
    if let Some(i) = outstanding
        .iter()
        .position(|r| pkt_start >= r.start && pkt_start < r.end && pkt_end == r.end)
    {
        outstanding.swap_remove(i);
        touch_queued_from(outstanding, pkt_end);
        true
    } else {
        refresh_outstanding_range(outstanding, pkt_start);
        false
    }
}

#[cfg(test)]
mod compressed_part_bounds_tests {
    use super::*;
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    fn packed(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Feed `packed` in `fragments` even slices and return the inflated pieces
    /// with their absolute offsets, as the receive loop would write them.
    fn stream(
        start: u64,
        plain_len: usize,
        packed: &[u8],
        fragments: usize,
    ) -> anyhow::Result<Vec<(u64, Vec<u8>)>> {
        let mut accumulator = CompressedPartAccumulator::default();
        let chunk = packed.len().div_ceil(fragments);
        let mut out = Vec::new();
        for piece in packed.chunks(chunk) {
            if let Some(f) = accumulator.append(
                start,
                Some(start + plain_len as u64),
                packed.len() as u32,
                piece,
            )? {
                out.push((f.offset, f.data));
            }
        }
        Ok(out)
    }

    /// However a block is split across packets, the bytes written have to be the
    /// same bytes at the same offsets. This is the property that makes streaming
    /// safe to put on the receive path at all.
    #[test]
    fn fragmentation_does_not_change_what_reaches_disk() {
        // Compressible, but not so uniform that a single inflate round covers it.
        let plain: Vec<u8> = (0..180 * 1024).map(|i| (i / 977) as u8).collect();
        let packed = packed(&plain);

        for fragments in [1usize, 2, 3, 7, 64] {
            let pieces = stream(100, plain.len(), &packed, fragments).unwrap();
            let mut rebuilt = vec![0u8; plain.len()];
            let mut covered = 0usize;
            for (offset, data) in &pieces {
                let at = (*offset - 100) as usize;
                assert_eq!(at, covered, "fragments must tile the block in order");
                rebuilt[at..at + data.len()].copy_from_slice(data);
                covered += data.len();
            }
            assert_eq!(covered, plain.len(), "split into {fragments} fragments");
            assert_eq!(rebuilt, plain, "split into {fragments} fragments");
        }
        // And the whole point: output arrives before the last packet does.
        assert!(
            stream(100, plain.len(), &packed, 7).unwrap().len() > 1,
            "a fragmented block should yield data as it arrives, not all at the end"
        );
    }

    /// Inflated output is batched before it is handed back, because every handover
    /// becomes a reserve/write/commit cycle taking the tracker write lock twice
    /// and an mpsc round-trip to the per-file writer.
    ///
    /// eMule splits a compressed block into 10240-byte packets
    /// (`UploadDiskIOThread.cpp:444`), so a 180 KB block arrives as ~15 of them.
    /// Writing each one as it inflated put fifteen of those cycles on the receive
    /// path where there had been one.
    #[test]
    fn many_small_packets_still_produce_few_disk_writes() {
        // Barely compressible, which is the case that actually fragments — eMule's
        // own note puts the gain at ~4% for .exe and .avi.
        let plain: Vec<u8> = {
            let mut lcg: u32 = 0x1234_5678;
            (0..180 * 1024)
                .map(|_| {
                    lcg = lcg.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    (lcg >> 16) as u8
                })
                .collect()
        };
        let packed = packed(&plain);

        // Fragmented the way eMule fragments: 10240 bytes of compressed data each.
        let fragments = packed.len().div_ceil(10240);
        assert!(fragments >= 8, "test needs a genuinely fragmented block");
        let pieces = stream(0, plain.len(), &packed, fragments).unwrap();

        assert!(
            pieces.len() <= plain.len().div_ceil(INFLATE_FLUSH_BYTES) + 1,
            "{fragments} packets should batch into a handful of writes, got {}",
            pieces.len(),
        );
        assert!(
            pieces.len() * 4 <= fragments,
            "batching must be a large reduction, not a token one: {} writes for {fragments} packets",
            pieces.len(),
        );

        // Batching must not change the bytes or their placement.
        let mut rebuilt = vec![0u8; plain.len()];
        let mut covered = 0usize;
        for (offset, data) in &pieces {
            assert_eq!(*offset as usize, covered);
            rebuilt[covered..covered + data.len()].copy_from_slice(data);
            covered += data.len();
        }
        assert_eq!(covered, plain.len());
        assert_eq!(rebuilt, plain);
    }

    /// A peer that stops mid-block used to cost us every byte of it. The bytes
    /// that did arrive are now already written, and only the shortfall is left as
    /// a gap to re-request.
    #[test]
    fn an_abandoned_block_keeps_the_bytes_that_arrived() {
        let plain: Vec<u8> = (0..180 * 1024).map(|i| (i / 613) as u8).collect();
        let packed = packed(&plain);
        let mut accumulator = CompressedPartAccumulator::default();

        // Half the compressed stream, then silence.
        let fragment = accumulator
            .append(
                0,
                Some(plain.len() as u64),
                packed.len() as u32,
                &packed[..packed.len() / 2],
            )
            .unwrap()
            .expect("half a stream still inflates a usable prefix");
        assert_eq!(fragment.offset, 0);
        assert!(!fragment.data.is_empty());
        assert!(fragment.data.len() < plain.len());
        assert_eq!(plain[..fragment.data.len()], fragment.data[..]);
    }

    /// Raw deflate with no zlib header is still accepted. The old code inflated
    /// the buffered block as zlib and retried the whole thing as raw deflate on
    /// failure; a streaming decoder cannot retry, so the format is decided from
    /// the header instead.
    #[test]
    fn raw_deflate_without_a_zlib_header_still_inflates() {
        use flate2::write::DeflateEncoder;
        let plain = vec![0x31u8; 8192];
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&plain).unwrap();
        let raw = encoder.finish().unwrap();
        assert!(!looks_like_zlib(&raw), "test needs a header-less stream");

        let pieces = stream(0, plain.len(), &raw, 3).unwrap();
        let rebuilt: Vec<u8> = pieces.into_iter().flat_map(|(_, d)| d).collect();
        assert_eq!(rebuilt, plain);
    }

    #[test]
    fn zlib_header_detection_matches_real_streams() {
        assert!(looks_like_zlib(&packed(b"hello world, compress me")));
        assert!(!looks_like_zlib(&[]));
        assert!(!looks_like_zlib(&[0x78]));
        // Right method nibble, wrong checksum.
        assert!(!looks_like_zlib(&[0x78, 0x00]));
        // Valid mod-31 pair but not the deflate method.
        assert!(!looks_like_zlib(&[0x79, 0x9b]));
    }

    /// A stream that inflates past the range we asked for is refused rather than
    /// written. The output allowance is the bound, so a decompression bomb runs
    /// out of buffer instead of memory.
    #[test]
    fn refuses_a_stream_that_inflates_past_its_requested_range() {
        let plain = vec![0u8; 512 * 1024];
        let packed = packed(&plain);
        let mut accumulator = CompressedPartAccumulator::default();
        // Claim a 4 KiB range for a stream holding 512 KiB.
        let err = accumulator
            .append(0, Some(4096), packed.len() as u32, &packed)
            .unwrap_err();
        assert!(
            err.to_string().contains("exceeds requested range"),
            "unexpected error: {err}"
        );
        assert!(
            accumulator.pending.is_empty(),
            "a refused block must not stay in reassembly"
        );
    }

    #[test]
    fn rejects_unsolicited_or_overrun_compressed_parts() {
        let mut accumulator = CompressedPartAccumulator::default();
        assert!(accumulator.append(10, None, 10, b"abc").is_err());
        assert!(accumulator.append(10, Some(20), 2, b"abc").is_err());
        assert!(accumulator.pending.is_empty());
    }

    /// Declared lengths still never drive allocation: nothing is sized from the
    /// peer's claimed packed size, and with streaming there is no compressed
    /// backlog at all — only the inflate window.
    #[test]
    fn declared_total_does_not_preallocate() {
        let mut accumulator = CompressedPartAccumulator::default();
        accumulator
            .append(0, Some(1024 * 1024), 1024 * 1024, b"x")
            .unwrap();
        assert_eq!(accumulator.pending.len(), 1);
        assert_eq!(accumulator.pending[&0].packed_seen, 1);
        assert_eq!(accumulator.pending[&0].inflated, 0);
    }

    /// Reassembly state is dropped for blocks that are no longer outstanding, so
    /// a session-scoped accumulator cannot fill up with stranded entries.
    #[test]
    fn retain_outstanding_drops_abandoned_blocks() {
        let plain = vec![7u8; 4096];
        let packed = packed(&plain);
        let mut accumulator = CompressedPartAccumulator::default();
        for start in [0u64, 8192] {
            accumulator
                .append(
                    start,
                    Some(start + plain.len() as u64),
                    packed.len() as u32,
                    &packed[..1],
                )
                .unwrap();
        }
        assert_eq!(accumulator.pending.len(), 2);
        accumulator.retain_outstanding(|start| start == 0);
        assert_eq!(accumulator.pending.len(), 1);
        assert!(accumulator.pending.contains_key(&0));
    }

    /// A stream that will not inflate costs its own block. The rest of it is
    /// absorbed rather than failing packet after packet, and the next stream
    /// for the same block starts clean.
    #[test]
    fn a_stream_that_will_not_inflate_costs_only_its_own_block() {
        let plain = vec![9u8; 4096];
        let good = packed(&plain);
        let mut accumulator = CompressedPartAccumulator::default();
        // A valid zlib header, then a deflate block of the reserved type 3.
        let broken_head = [0x78, 0x9c, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert!(accumulator.append(0, Some(4096), 30, &broken_head).is_err());
        assert!(accumulator.pending.is_empty());

        for _ in 0..2 {
            assert!(accumulator.append(0, Some(4096), 30, &[0u8; 10]).unwrap().is_none());
        }
        assert!(accumulator.broken.is_empty(), "the whole broken stream was absorbed");

        let fragment = accumulator
            .append(0, Some(4096), good.len() as u32, &good)
            .unwrap()
            .expect("a fresh stream for the block inflates");
        assert_eq!(fragment.data, plain);
    }

    /// A block requested again with a shorter range gets a stream of its own
    /// at the same start. That stream replaces the one it cut short instead of
    /// being refused as a size change.
    #[test]
    fn a_fresh_stream_for_a_recut_block_replaces_the_old_one() {
        let plain: Vec<u8> = (0..8192).map(|i| (i / 97) as u8).collect();
        let first = packed(&plain);
        let mut accumulator = CompressedPartAccumulator::default();
        assert!(accumulator
            .append(0, Some(8192), first.len() as u32, &first[..1])
            .unwrap()
            .is_none());

        let second = packed(&plain[..4096]);
        let fragment = accumulator
            .append(0, Some(4096), second.len() as u32, &second)
            .unwrap()
            .expect("the re-cut block's stream inflates");
        assert_eq!(fragment.offset, 0);
        assert_eq!(fragment.data, plain[..4096]);
    }
}

/// eMule-style error classification: only protocol-level failures (FNF, hash
/// mismatch) should mark a source dead.  Transient TCP errors like connection
/// resets or EOF are normal in P2P and the source should be reasked later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceFailureKind {
    /// Connection reset, EOF, timeout -- source should be reasked later
    Transient,
    /// File Not Found, hash mismatch -- source should be marked dead
    Permanent,
    /// Download timed out (100s no data) -- source goes back to OnQueue
    DownloadTimeout,
    /// Local disk is full — transfer-level Insufficient, not a peer fault
    InsufficientDisk,
}

#[derive(Debug, Clone)]
pub enum DownloadEvent {
    Progress {
        transfer_id: String,
        /// Bytes present on disk, from the gap list — eMule's `m_completedsize`
        /// and its Completed column. Progress % and the remaining byte count
        /// derive from this (`DownloadListCtrl.cpp:1698`, `:1731`).
        downloaded: u64,
        /// Cumulative bytes peers have sent for this file — eMule's
        /// `m_uTransferred` and its Transferred column
        /// (`DownloadListCtrl.cpp:1984`). Counts duplicates, re-fetches after a
        /// failed part hash, and compressed payload, so it can exceed `total`.
        ///
        /// `None` from the terminal and zero-length paths, which have no tracker
        /// to read it from; the consumer then falls back to `downloaded` rather
        /// than reporting a byte count it does not have.
        transferred: Option<u64>,
        total: u64,
    },
    SourcesUpdate {
        transfer_id: String,
        total: u32,
        active: u32,
        queued: u32,
    },
    Verifying {
        transfer_id: String,
    },
    SourceDetail {
        transfer_id: String,
        ip: String,
        port: u16,
        status: String,
        queue_rank: Option<u32>,
        speed: u64,
        transferred: u64,
        client_software: String,
        peer_name: String,
        failure_kind: Option<SourceFailureKind>,
        available_parts: Option<u32>,
        total_parts: Option<u32>,
        country_code: Option<String>,
    },
    Completed {
        transfer_id: String,
        /// Absolute path the finished file was actually written to. May
        /// differ from `Downloads/<name>` when `move_part_to_final`
        /// deduplicated against a pre-existing file. `None` for completion
        /// paths that don't move a `.part` (e.g. zero-byte files) — the
        /// handler then falls back to reconstructing the path.
        final_path: Option<String>,
        /// The ed2k part-hash list ("hashset"), already fetched from a
        /// source and cryptographically verified against the file's own
        /// ed2k hash during the transfer (see `verify_hashset`), if this
        /// download path tracks one. Lets the completion handler write a
        /// `known.met` record without re-reading the whole file from disk a
        /// second time — empty when unavailable (zero-byte files,
        /// single-source callback downloads, restart re-verification),
        /// in which case the handler falls back to the old re-read.
        part_hashes: Vec<[u8; 16]>,
        /// Whether an Ember content BLAKE3 hash was known for this file
        /// *and* actually re-checked against the completed bytes on disk
        /// during this completion. `false` for zero-byte files, transfers
        /// with no Ember hash to check, and the crash-recovery re-verify
        /// paths in `network::mod` that only re-check ed2k/AICH — never
        /// `true` on a path that skipped the check.
        ember_verified: bool,
        /// [`TransferControl::generation`](crate::sharing::manager::TransferControl::generation)
        /// of the worker that sent this; `None` from a path that runs no worker.
        generation: Option<u64>,
    },
    Failed {
        transfer_id: String,
        error: String,
        failure_kind: SourceFailureKind,
        /// As for `Completed`.
        generation: Option<u64>,
    },
    /// Sources discovered via source exchange from a connected peer.
    /// The network loop injects these into the active download.
    SourceExchange {
        transfer_id: String,
        file_hash: [u8; 16],
        sources: Vec<SourceExchangeEntry>,
    },
    /// Sources discovered via Ember Peer Exchange from another Ember client.
    EmberSources {
        transfer_id: String,
        entries: Vec<([u8; 16], Vec<(std::net::Ipv4Addr, u16, u16, u8)>)>,
        aich_roots: Vec<([u8; 16], [u8; 20])>,
        ember_peers: Vec<(std::net::Ipv4Addr, u16)>,
        relay_attestations: Vec<crate::network::ember::RelayAttestation>,
        /// Ember identity of the peer that sent this exchange, when its HELLO
        /// bound one. Carried so the connection broker can charge any relay
        /// attestations in the trailer to whoever introduced them — the
        /// per-introducer cap is what stops one peer filling the relay pool
        /// with self-signed entries, and it needs a name to charge.
        from_ember_hash: Option<[u8; 16]>,
    },
    /// An Ember peer was detected (for peer discovery mesh bootstrap).
    ///
    /// `udp_port` is the peer's eMule UDP port from `OP_EMULEINFO`, or 0 when
    /// it never advertised one. Ember's Noise transport rides the UDP socket,
    /// so that — not `tcp_port` — is the address the DHT bridge can dial.
    EmberPeerDiscovered {
        ip: std::net::Ipv4Addr,
        tcp_port: u16,
        udp_port: u16,
    },
    /// Incoming friend request from an Ember peer on a download connection.
    EmberFriendRequest {
        ember_hash: [u8; 16],
        pubkey: Option<[u8; 32]>,
        nickname: String,
        peer_ip: String,
        peer_port: u16,
        verified: bool,
    },
    /// An Ember friend was seen on a download connection (EmuleInfo exchange completed).
    FriendSeen {
        ember_hash: [u8; 16],
        ip: std::net::IpAddr,
        port: u16,
    },
    /// Legacy parser-only chat event. Generic download chat is dropped.
    #[allow(dead_code)]
    EmberChatMessage {
        ember_hash: [u8; 16],
        message: String,
    },
    /// Incoming Ember browse response from a friend on a download connection.
    EmberBrowseResponse {
        ember_hash: [u8; 16],
        entries: Vec<(String, u64, String, Option<String>, Option<String>)>,
    },
    /// The .part file has been created on disk, signalling the network loop to
    /// offer this partial to the server and publish to KAD so other peers can
    /// discover us as a source.
    PartFileReady {
        transfer_id: String,
        file_hash: [u8; 16],
        file_size: u64,
        file_name: String,
    },
    /// A data block was received and written to disk — feeds the corruption blackbox.
    DataReceived {
        file_hash: [u8; 16],
        start: u64,
        end: u64,
        sender_ip: std::net::Ipv4Addr,
    },
    /// A part passed its MD4 hash check.
    PartVerified {
        file_hash: [u8; 16],
        part_start: u64,
        part_end: u64,
        sender_user_hash: Option<[u8; 16]>,
    },
    /// A part failed its MD4 hash check, or AICH recovery narrowed one to a
    /// bad 180 KiB block, which is then the range reported.
    PartCorrupted {
        file_hash: [u8; 16],
        part_start: u64,
        part_end: u64,
        sender_user_hash: Option<[u8; 16]>,
    },
    /// AICH recovery was attempted for a corrupt part but failed (timeout, bad data, etc.).
    /// The network loop uses this to schedule a retry with a different source.
    AichRecoveryFailed {
        file_hash: [u8; 16],
        part_index: u32,
        failed_ip: std::net::Ipv4Addr,
    },
    /// A peer broke the ed2k wire protocol badly enough that we tore the
    /// connection down — currently a run of consecutive structurally
    /// invalid data blocks (bad offsets / over-long compressed chunks),
    /// which a well-behaved client never sends. The network loop feeds
    /// this into the reputation tracker as a `ProtocolViolation`, so a
    /// peer that repeatedly does this is eventually banned rather than
    /// just disconnected and immediately retried.
    ProtocolViolation {
        sender_ip: std::net::Ipv4Addr,
        sender_user_hash: Option<[u8; 16]>,
    },
}

/// Shared pending AICH recovery retries: `(file_hash, part_index) -> (failed_ips, retry_count)`.
/// Written by the network event loop, read by download tasks before sending OP_AICHREQUEST.
pub type SharedAichPending = std::sync::Arc<
    std::sync::RwLock<std::collections::HashMap<([u8; 16], u32), (Vec<std::net::Ipv4Addr>, u32)>>,
>;

#[derive(Debug, Clone)]
pub struct SourceExchangeEntry {
    pub ip: std::net::Ipv4Addr,
    pub tcp_port: u16,
    pub user_hash: [u8; 16],
    pub crypt_options: u8,
}

/// True when completion refused the file because its Ember BLAKE3 pin did
/// not match. Distinct from an ed2k/AICH mismatch: the MD4 parts can all
/// be correct while the Ember digest is wrong, and retrying those parts
/// cannot fix a bad pin.
///
/// This reads raw anyhow chains, so it stays a substring test. Once a failure
/// has been through [`classify_failure`], compare against
/// [`TransferFailureCode::EmberContentHashMismatch`] instead — that is what the
/// UI does, and it is the reason the badge no longer depends on the wording.
pub fn is_ember_blake3_mismatch(err: &str) -> bool {
    let lower = err.to_lowercase();
    lower.contains("ember blake3 mismatch") || lower.contains("ember content hash mismatch")
}

/// True when a trusted `|h=` / `expected_aich` pin missed after the ed2k
/// file hash already matched. Same class as Ember BLAKE3: more sources
/// cannot change the digest of a complete, hash-verified file.
pub fn is_expected_aich_mismatch(err: &str) -> bool {
    let lower = err.to_lowercase();
    // Raw completion error, plus the canned sentence for
    // `TransferFailureCode::AichHashMismatch`.
    lower.contains("expected aich hash mismatch") || lower == "aich hash mismatch"
}

/// Canned error for a terminal Ember pin failure. Kept as one string so the
/// single-source and multi-source completion paths, plus the event-loop
/// re-queue skip, all agree.
pub const EMBER_BLAKE3_MISMATCH_MSG: &str =
    "ember blake3 mismatch: content did not match the expected Ember hash";

/// Error for a completed download whose final check neither passed nor showed
/// bad bytes: the `.part` could not be read, or a re-read found every part
/// intact. Neither this nor [`LOCAL_READ_FAILED_MSG`] is evidence against a
/// source, so both must classify as Transient and must not contain "hash
/// mismatch" or "hash verification failed".
pub const FINAL_VERIFY_INCONCLUSIVE_MSG: &str =
    "Final verification inconclusive — .part and progress kept, will re-verify";

/// Terminal error once repeated verifications and a part-by-part re-read still
/// cannot read the finished `.part`. The event loop does not re-queue it.
pub const LOCAL_READ_FAILED_MSG: &str =
    "Finished .part cannot be read back from the local drive — not retrying";

/// Classify an error string into transient vs permanent failure.
pub fn classify_error(err: &str) -> SourceFailureKind {
    let lower = err.to_lowercase();
    if is_disk_full_error(err) {
        SourceFailureKind::InsufficientDisk
    } else if is_ember_blake3_mismatch(err)
        || lower.contains("does not have the file")
        || lower.contains("filereqansnofil")
        || lower.contains("file not found")
        || lower.contains("hash mismatch")
        || lower.contains("hash verification failed")
    {
        SourceFailureKind::Permanent
    } else if lower.contains("download timeout") || lower.contains("more than 100 seconds") {
        SourceFailureKind::DownloadTimeout
    } else {
        SourceFailureKind::Transient
    }
}

/// True when a write/IO error indicates the download volume is out of space.
pub fn is_disk_full_error(err: &str) -> bool {
    let lower = err.to_lowercase();
    lower.contains("stage:insufficient_disk")
        || lower.contains("no space left")
        || lower.contains("not enough space")
        || lower.contains("disk full")
        || lower.contains("there is not enough space")
        // Raw errno text is platform-specific and these two numbers collide
        // with unrelated errors on the other platform: OS error 28 is
        // ERROR_OUT_OF_PAPER on Windows, and 112 is EHOSTDOWN on Linux — which
        // a download folder on an NFS/SMB share returns when the host goes
        // away. Reporting that as `InsufficientDisk` put a recoverable
        // transfer into a terminal state instead of retrying it.
        || (cfg!(unix) && lower.contains("os error 28")) // ENOSPC
        || (cfg!(windows) && lower.contains("os error 112")) // ERROR_DISK_FULL
        || lower.contains("storagefull")
}

/// Prefix on every error raised while preparing the local download folder or
/// opening a `.part` inside it.
///
/// Such an error involves no peer, so it is not a source failure, and retrying
/// another source cannot fix it. Untagged, it fell through `classify_failure` to
/// "Transient connection failure": the row went back to Searching and retried
/// forever while telling the user to look at the network (issue 128).
pub(crate) const DOWNLOAD_FOLDER_STAGE: &str = "stage:download_folder";

pub(crate) fn is_download_folder_error(error: &str) -> bool {
    error.contains(DOWNLOAD_FOLDER_STAGE)
}

pub(crate) fn download_folder_error(
    what: &str,
    download_dir: &std::path::Path,
    error: impl std::fmt::Display,
) -> anyhow::Error {
    anyhow::anyhow!("{DOWNLOAD_FOLDER_STAGE}: {what} in {}: {error}", download_dir.display())
}

/// Create `<download_dir>/Temp` (for `.part` files) and `<download_dir>/Downloads`
/// (for completed ones) inside the approved root, returning both.
pub(crate) async fn prepare_download_dirs(
    download_dir: &std::path::Path,
) -> anyhow::Result<(std::path::PathBuf, std::path::PathBuf)> {
    let root = download_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let allowed = vec![root.to_string_lossy().into_owned()];
        let temp = crate::security::filesystem::prepare_approved_subdir(&root, "Temp", &allowed)?;
        let done =
            crate::security::filesystem::prepare_approved_subdir(&root, "Downloads", &allowed)?;
        Ok::<_, std::io::Error>((temp, done))
    })
    .await
    .map_err(|e| anyhow::anyhow!("download folder task failed: {e}"))?
    .map_err(|e| download_folder_error("preparing Temp and Downloads", download_dir, e))
}

/// Also tagged [`DOWNLOAD_FOLDER_STAGE`], so the download is re-queued without
/// blaming a source, and starts again once the folder is back.
pub(crate) const PART_FOLDER_OFFLINE_STAGE: &str = "stage:part_folder_offline";

fn part_folder_offline_error(folder: &std::path::Path) -> anyhow::Error {
    anyhow::anyhow!(
        "{DOWNLOAD_FOLDER_STAGE}: {PART_FOLDER_OFFLINE_STAGE}: {} holds this download's progress \
         and cannot be reached",
        folder.display()
    )
}

/// The download folder holding this download's `.part` — the one it started
/// in — and that folder's `Temp`, prepared. Only the current folder gets a
/// `Downloads`: finished files never go to an earlier one.
pub(crate) async fn prepare_part_dir(
    folders: &crate::storage::part_folders::SharedDownloadFolders,
    transfer_id: &str,
) -> anyhow::Result<(std::path::PathBuf, std::path::PathBuf)> {
    let folders = folders.read().clone();
    let current = folders.current.clone();
    let id = transfer_id.to_string();
    let root = tokio::task::spawn_blocking(move || folders.folder_to_resume_in(&id))
        .await
        .map_err(|e| anyhow::anyhow!("download folder task failed: {e}"))?
        .map_err(|offline| part_folder_offline_error(&offline))?;
    let temp = if root == current {
        prepare_download_dirs(&root).await?.0
    } else {
        let part_root = root.clone();
        tokio::task::spawn_blocking(move || {
            let allowed = vec![part_root.to_string_lossy().into_owned()];
            crate::security::filesystem::prepare_approved_subdir(&part_root, "Temp", &allowed)
        })
        .await
        .map_err(|e| anyhow::anyhow!("download folder task failed: {e}"))?
        .map_err(|e| download_folder_error("preparing Temp", &root, e))?
    };
    crate::storage::part_folders::note_located(transfer_id, &root);
    Ok((root, temp))
}

/// Create `<download_root>/Downloads` inside the approved root. Blocking.
pub(crate) fn prepare_completed_dir(
    download_root: &std::path::Path,
) -> anyhow::Result<std::path::PathBuf> {
    let allowed = vec![download_root.to_string_lossy().into_owned()];
    crate::security::filesystem::prepare_approved_subdir(download_root, "Downloads", &allowed)
        .map_err(|e| download_folder_error("preparing Downloads", download_root, e))
}

/// The folder a finished download lands in: `<download_root>/Downloads`, then
/// `subdir`'s folders inside it, each made inside the approved root the way
/// `Downloads` is. When a category folder cannot be made — a file in its
/// place, a junction, no permission — the download lands in `Downloads`
/// itself: the user asked for a place to file it, not for it to fail. Only
/// `Downloads` failing is an error. Blocking.
pub(crate) fn prepare_completed_subdir(
    download_root: &std::path::Path,
    subdir: &[String],
) -> anyhow::Result<std::path::PathBuf> {
    let downloads = prepare_completed_dir(download_root)?;
    let allowed = vec![download_root.to_string_lossy().into_owned()];
    let mut dir = downloads.clone();
    for segment in subdir {
        match crate::security::filesystem::prepare_approved_subdir(&dir, segment, &allowed) {
            Ok(next) => dir = next,
            Err(e) => {
                tracing::warn!(
                    "Could not use the category folder {} in {}: {e}. Finishing into Downloads.",
                    subdir.join("/"),
                    downloads.display()
                );
                return Ok(downloads);
            }
        }
    }
    Ok(dir)
}

/// Move a verified `.part` into `<download_root>/Downloads/<file_name>`.
/// `download_root` is the download folder current at completion, which need
/// not be the one holding the `.part`. Blocking.
pub(crate) fn move_part_to_downloads(
    part_path: &std::path::Path,
    part_root: &std::path::Path,
    download_root: &std::path::Path,
    file_name: &str,
    expected_source_identity: &crate::security::filesystem::ObjectIdentity,
) -> anyhow::Result<std::path::PathBuf> {
    move_part_to_completed(
        part_path,
        part_root,
        download_root,
        &[],
        file_name,
        expected_source_identity,
    )
}

/// [`move_part_to_downloads`], into the category folder `subdir` inside
/// `Downloads` (see [`prepare_completed_subdir`]). Blocking.
pub(crate) fn move_part_to_completed(
    part_path: &std::path::Path,
    part_root: &std::path::Path,
    download_root: &std::path::Path,
    subdir: &[String],
    file_name: &str,
    expected_source_identity: &crate::security::filesystem::ObjectIdentity,
) -> anyhow::Result<std::path::PathBuf> {
    let completed_dir = prepare_completed_subdir(download_root, subdir)?;
    move_part_between_roots_approved(
        part_path,
        part_root,
        &completed_dir.join(file_name),
        download_root,
        expected_source_identity,
    )
    .map_err(|e| {
        let error = format!("{e:#}");
        if is_disk_full_error(&error) || is_download_folder_error(&error) {
            e
        } else {
            anyhow::anyhow!("{COMPLETION_MOVE_STAGE}: {error}")
        }
    })
}

/// Prefix on a failure to move a verified `.part` into `Downloads`. Every
/// retry reads the whole file again to verify it, so the event loop retries
/// such a failure once and then leaves the download Failed, `.part` kept, for
/// the user to resume.
pub(crate) const COMPLETION_MOVE_STAGE: &str = "stage:completion_move";

pub(crate) fn failure_kind_name(kind: &SourceFailureKind) -> String {
    match kind {
        SourceFailureKind::Transient => "transient".to_string(),
        SourceFailureKind::Permanent => "permanent".to_string(),
        SourceFailureKind::DownloadTimeout => "download_timeout".to_string(),
        SourceFailureKind::InsufficientDisk => "insufficient_disk".to_string(),
    }
}

/// Declares the closed set of failure sentences a transfer row can show, each
/// bound to a stable code.
///
/// The English stays because logs, download history, and a UI older than the
/// backend it is talking to all read it. The code is what the UI translates,
/// which is what stops a re-wording here from silently dropping a row back to
/// English for the eight non-English locales.
///
/// Both come out of one table on purpose: a variant cannot compile without a
/// code and a sentence, `ALL` is generated from the same list so it cannot go
/// stale, and `scripts/backend-codes.test.mjs` parses this table to require a
/// translation in all nine locales before a new variant can ship.
macro_rules! transfer_failure_codes {
    ($($variant:ident => $code:literal, $message:literal;)+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum TransferFailureCode {
            $($variant,)+
        }

        impl TransferFailureCode {
            /// Every variant, in declaration order. Only the exhaustiveness
            /// tests walk the set; production code always has a variant in
            /// hand, so this is not compiled into the shipped binary.
            #[cfg(test)]
            pub const ALL: &'static [TransferFailureCode] = &[$(TransferFailureCode::$variant,)+];

            /// Stable identifier carried to the UI as `Transfer::failure_code`.
            pub fn as_code(self) -> &'static str {
                match self {
                    $(Self::$variant => $code,)+
                }
            }

            /// English rendering, stored in `Transfer::failure_reason`.
            pub fn message(self) -> &'static str {
                match self {
                    $(Self::$variant => $message,)+
                }
            }
        }
    };
}

transfer_failure_codes! {
    Cancelled => "cancelled", "Cancelled";
    RemoteMissingFile => "remote_missing_file", "Remote missing file";
    EmberContentHashMismatch => "ember_content_hash_mismatch", "Ember content hash mismatch";
    AichHashMismatch => "aich_hash_mismatch", "AICH hash mismatch";
    HashMismatch => "hash_mismatch", "Hash mismatch";
    DownloadTimedOut => "download_timed_out", "Download timed out";
    InsufficientDisk => "insufficient_disk_space", "Insufficient disk space";
    ConnectionFailed => "connection_failed", "Connection failed";
    PeerHandshakeFailed => "peer_handshake_failed", "Peer handshake failed";
    QueueWaitInterrupted => "queue_wait_interrupted", "Queue wait interrupted";
    HashsetRequestFailed => "hashset_request_failed", "Hashset request failed";
    ConnectionLost => "connection_lost", "Connection lost during transfer";
    PermanentFailure => "permanent_failure", "Permanent transfer failure";
    TransientFailure => "transient_failure", "Transient connection failure";
    NetworkChannelUnavailable => "network_channel_unavailable", "Network channel unavailable";
    DownloadFolderUnavailable => "download_folder_unavailable",
        "The download folder cannot be written; check it in Settings";
    PartFolderOffline => "part_folder_offline",
        "The drive holding this download's progress is not connected; Resume starts it over";
    EmberPinCorrupt => "ember_pin_corrupt",
        "Persisted Ember digest was corrupt; cancel and re-add the eh= link";
    AichPinCorrupt => "aich_pin_corrupt",
        "Persisted AICH pin was corrupt; cancel and re-add the AICH link";
    FinalVerifyInconclusive => "final_verify_inconclusive",
        "Couldn't read the finished file to verify it";
    LocalReadFailed => "local_read_failed",
        "The finished file can't be read from the drive";
    CompletionMoveFailed => "completion_move_failed",
        "The finished file couldn't be moved into the download folder";
}

/// Reduce a raw error to the canned failure the UI shows.
///
/// The redaction this performs is load-bearing: peer IPs and local paths from
/// anyhow chains must not reach `Transfer::failure_reason`. Callers that need
/// to branch on *which* failure it was compare the returned variant rather than
/// re-matching its sentence.
pub(crate) fn classify_failure(error: &str, kind: &SourceFailureKind) -> TransferFailureCode {
    let lower = error.to_lowercase();
    if lower.contains("cancelled") {
        return TransferFailureCode::Cancelled;
    }
    if error.contains(PART_FOLDER_OFFLINE_STAGE) {
        return TransferFailureCode::PartFolderOffline;
    }
    if is_download_folder_error(error) {
        // Sizing a new `.part` runs inside the folder stage; a full volume is
        // not a folder the user has to fix in Settings.
        if matches!(kind, SourceFailureKind::InsufficientDisk) || is_disk_full_error(error) {
            return TransferFailureCode::InsufficientDisk;
        }
        return TransferFailureCode::DownloadFolderUnavailable;
    }
    if error.contains(COMPLETION_MOVE_STAGE) {
        return TransferFailureCode::CompletionMoveFailed;
    }
    if error.contains(LOCAL_READ_FAILED_MSG) {
        return TransferFailureCode::LocalReadFailed;
    }
    if error.contains(FINAL_VERIFY_INCONCLUSIVE_MSG) {
        return TransferFailureCode::FinalVerifyInconclusive;
    }
    if lower.contains("does not have the file")
        || lower.contains("filereqansnofil")
        || lower.contains("file not found")
    {
        return TransferFailureCode::RemoteMissingFile;
    }
    if is_ember_blake3_mismatch(error) {
        return TransferFailureCode::EmberContentHashMismatch;
    }
    if is_expected_aich_mismatch(error) {
        return TransferFailureCode::AichHashMismatch;
    }
    if lower.contains("hash mismatch") || lower.contains("hash verification failed") {
        return TransferFailureCode::HashMismatch;
    }
    if matches!(kind, SourceFailureKind::DownloadTimeout) {
        return TransferFailureCode::DownloadTimedOut;
    }
    if matches!(kind, SourceFailureKind::InsufficientDisk) || is_disk_full_error(error) {
        return TransferFailureCode::InsufficientDisk;
    }
    match infer_stage_from_error(error) {
        "tcp_connect" => TransferFailureCode::ConnectionFailed,
        "hello_wait" | "emule_info_wait" | "file_status_wait" => {
            TransferFailureCode::PeerHandshakeFailed
        }
        "queue_wait" => TransferFailureCode::QueueWaitInterrupted,
        "hashset_wait" => TransferFailureCode::HashsetRequestFailed,
        "data_wait" => TransferFailureCode::ConnectionLost,
        _ => match kind {
            SourceFailureKind::Permanent => TransferFailureCode::PermanentFailure,
            SourceFailureKind::Transient => TransferFailureCode::TransientFailure,
            SourceFailureKind::DownloadTimeout => TransferFailureCode::DownloadTimedOut,
            SourceFailureKind::InsufficientDisk => TransferFailureCode::InsufficientDisk,
        },
    }
}


pub(crate) fn infer_stage_from_error(error: &str) -> &'static str {
    if is_download_folder_error(error) {
        return "download_folder";
    }
    if error.contains("stage:tcp_connect") {
        return "tcp_connect";
    }
    if error.contains("stage:hello_wait") {
        return "hello_wait";
    }
    if error.contains("stage:emule_info_wait") {
        return "emule_info_wait";
    }
    if error.contains("stage:file_status_wait") {
        return "file_status_wait";
    }
    if error.contains("stage:queue_wait") {
        return "queue_wait";
    }
    if error.contains("stage:queue_detached") {
        return "queue_wait";
    }
    if error.contains("stage:data_wait") {
        return "data_wait";
    }
    // Both of these carry a `stage:` prefix that had no arm here, so they fell
    // through every check (and match none of the keyword fallbacks below) and
    // ended up as the generic `TransientFailure` rather than the specific code
    // the UI has a translation for. `stage:peer_dropped_after_accept` was added
    // precisely so that failure would read distinctly.
    if error.contains("stage:peer_dropped_after_accept") {
        return "data_wait";
    }
    if error.contains("stage:tcp_obfuscation") {
        return "tcp_connect";
    }
    if error.contains("stage:hashset_wait") {
        return "hashset_wait";
    }
    if error.contains("HelloAnswer") {
        return "hello_wait";
    }
    if error.contains("upload slot") || error.contains("queue") {
        return "queue_wait";
    }
    if error.contains("hashset") {
        return "hashset_wait";
    }
    "unknown"
}

pub(crate) fn is_queue_detached_error(error: &str) -> bool {
    error.contains("stage:queue_detached") || error.contains("connection lost while queued")
}

/// True when the source task ended in a normal eMule queue state rather than
/// a handshake or transfer failure. The per-source loop already emitted
/// `queued` / `queue_full`; overlaying `SourceDetail{status:"failed"}` would
/// penalize the peer and paint a red row for a source eMule keeps OnQueue.
pub(crate) fn is_queue_state_error(error: &str) -> bool {
    is_queue_detached_error(error)
        || error.contains("peer queue is full")
        || error.contains("timed out waiting for upload slot")
        || error.contains("OutOfPartReqs")
        || error.contains("peer revoked upload slot")
        // The uploader recalculated its queue and pushed us back to a rank
        // mid-transfer. eMule does this routinely; the worker has already
        // emitted `queued` with the new rank, so overlaying `failed` both
        // contradicts it and drops the peer out of `OnQueue` (and therefore
        // out of the Path-B push-grant index).
        || error.contains("put us back in queue")
        // Peer holds nothing we still need. The worker emitted
        // `no_needed_parts`; `multi_source`'s retry-round comment lists this
        // with the queue states that must not be penalized.
        || error.contains("no parts we need")
}

/// False for user Stop/Pause and for queue-state exits. Those must not emit
/// `SourceDetail{status:"failed"}` — that applies `set_failed_with_penalty`.
pub(crate) fn should_emit_source_failed(error: &str) -> bool {
    !is_user_cancel_error(error) && !is_queue_state_error(error)
}

/// True when a per-source download task unwound because the user
/// Stopped/Cancelled/Paused the transfer (the strings produced by the
/// `TransferControl` cancel/pause arms and `check_control`), rather than
/// because the source genuinely failed. Such unwinds must NOT emit a
/// `SourceDetail{status:"failed"}` event, because that applies a reputation
/// penalty (`set_failed_with_penalty`) — and `PauseDownload` keeps the
/// per-file source list for fast resume, so repeated pause/resume cycles
/// would otherwise steadily degrade and eventually evict a transfer's best
/// peers. eMule treats a user pause/stop as a clean teardown.
pub(crate) fn is_user_cancel_error(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("cancelled by user")
        || lower.contains("cancelled while paused")
        || lower.contains("download cancelled")
}

/// Aborts a spawned task when it leaves scope, however the scope exits.
///
/// The verification cancel-watchers are only ever released by an explicit
/// `abort()` on the success path. That is not enough: dropping the worker
/// future anywhere between the spawn and that line — which is exactly what a
/// Pause does — would leave the watcher parked on `wait_cancelled` for the rest
/// of the process, holding a `TransferControl` and the mirrored flag with it.
pub(super) struct AbortOnDrop(pub tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ed2k::hash::{ed2k_hash_bytes, PARTSIZE};
    use md4::{Digest, Md4};

    /// The codes are an IPC contract with the frontend, which looks each one up
    /// in a table keyed by exactly this string. A duplicate would make two
    /// failures indistinguishable there; a stray character would silently miss.
    #[test]
    fn every_failure_code_is_a_distinct_identifier() {
        let mut seen = std::collections::HashSet::new();
        for failure in TransferFailureCode::ALL {
            let code = failure.as_code();
            assert!(
                !code.is_empty()
                    && code
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{code} is not a snake_case identifier"
            );
            assert!(seen.insert(code), "{code} is used by two variants");
            assert!(
                !failure.message().is_empty(),
                "{code} has no English fallback"
            );
        }
        assert_eq!(seen.len(), TransferFailureCode::ALL.len());
    }

    /// Every canned sentence has to round-trip back to the variant that owns
    /// it, or a row assigned by English elsewhere in the tree would land on the
    /// wrong translation.
    #[test]
    fn no_two_failure_codes_share_a_sentence() {
        let mut seen = std::collections::HashSet::new();
        for failure in TransferFailureCode::ALL {
            assert!(
                seen.insert(failure.message()),
                "{:?} repeats a sentence another variant already owns",
                failure
            );
        }
    }

    /// The classifier is the only producer of a download failure, so its output
    /// is what decides whether the eight non-English locales see a translation.
    /// Walks one raw error per branch and pins the code, not the wording.
    #[test]
    fn the_classifier_emits_a_code_for_every_branch_it_has() {
        use SourceFailureKind::*;
        use TransferFailureCode as C;
        let cases: &[(&str, SourceFailureKind, TransferFailureCode)] = &[
            ("download cancelled by user", Transient, C::Cancelled),
            ("peer does not have the file", Permanent, C::RemoteMissingFile),
            (
                "peer does not have the file any more (FileNotFound during transfer)",
                Permanent,
                C::RemoteMissingFile,
            ),
            ("FileReqAnsNoFil", Permanent, C::RemoteMissingFile),
            (EMBER_BLAKE3_MISMATCH_MSG, Permanent, C::EmberContentHashMismatch),
            (
                "Expected AICH hash mismatch: expected aa, got bb",
                Permanent,
                C::AichHashMismatch,
            ),
            ("hash verification failed", Permanent, C::HashMismatch),
            ("no data for 100s", DownloadTimeout, C::DownloadTimedOut),
            ("no space left on device", Transient, C::InsufficientDisk),
            ("stage:tcp_connect refused", Transient, C::ConnectionFailed),
            ("stage:hello_wait timed out", Transient, C::PeerHandshakeFailed),
            (
                "stage:emule_info_wait timed out",
                Transient,
                C::PeerHandshakeFailed,
            ),
            (
                "stage:file_status_wait timed out",
                Transient,
                C::PeerHandshakeFailed,
            ),
            (
                "stage:file_status_wait never received FileStatus (last packet proto=0xC5 op=0x93 len=0)",
                Transient,
                C::PeerHandshakeFailed,
            ),
            (
                "stage:queue_wait dropped",
                Transient,
                C::QueueWaitInterrupted,
            ),
            (
                "stage:hashset_wait no answer",
                Transient,
                C::HashsetRequestFailed,
            ),
            ("stage:data_wait eof", Transient, C::ConnectionLost),
            (
                "stage:peer_dropped_after_accept peer FIN'd with no data",
                Transient,
                C::ConnectionLost,
            ),
            (
                "stage:tcp_obfuscation required by peer but failed",
                Transient,
                C::ConnectionFailed,
            ),
            (
                "stage:download_folder: opening the part file in /x: Permission denied",
                Transient,
                C::DownloadFolderUnavailable,
            ),
            (
                "stage:download_folder: opening the part file in /x: No space left on device",
                Transient,
                C::InsufficientDisk,
            ),
            (
                "stage:download_folder: stage:part_folder_offline: /x cannot be reached",
                Transient,
                C::PartFolderOffline,
            ),
            (FINAL_VERIFY_INCONCLUSIVE_MSG, Transient, C::FinalVerifyInconclusive),
            (LOCAL_READ_FAILED_MSG, Transient, C::LocalReadFailed),
            (
                "stage:completion_move: file not found (os error 2)",
                Permanent,
                C::CompletionMoveFailed,
            ),
            ("unrecognised", Permanent, C::PermanentFailure),
            ("unrecognised", Transient, C::TransientFailure),
            ("unrecognised", DownloadTimeout, C::DownloadTimedOut),
            ("unrecognised", InsufficientDisk, C::InsufficientDisk),
        ];
        for (error, kind, expected) in cases {
            assert_eq!(
                classify_failure(error, kind),
                *expected,
                "{error:?} with {kind:?}"
            );
        }

        // The three variants the classifier cannot reach are assigned directly:
        // two by the database loader for a corrupt persisted pin, one by the
        // command layer when the network channel is gone. Named here so a
        // variant added without a producer is visible rather than assumed.
        let assigned_elsewhere = [
            C::EmberPinCorrupt,
            C::AichPinCorrupt,
            C::NetworkChannelUnavailable,
        ];
        let produced: std::collections::HashSet<_> =
            cases.iter().map(|(_, _, code)| *code).collect();
        for failure in TransferFailureCode::ALL {
            assert!(
                produced.contains(failure) || assigned_elsewhere.contains(failure),
                "{failure:?} has no producer"
            );
        }
    }

    /// A peer that queues us is not a peer that failed. eMule holds such a
    /// source at DS_ONQUEUE and reasks it for hours; emitting
    /// `SourceDetail{status:"failed"}` applies `set_failed_with_penalty`, which
    /// eventually evicts exactly the sources that were about to grant a slot.
    /// Every string here is one a per-source task really bails with.
    #[test]
    fn queue_state_and_user_cancel_do_not_emit_source_failed() {
        for queue_state in [
            "peer queue is full",
            "stage:queue_wait peer queue is full",
            "stage:queue_detached connection lost while queued",
            // Queue wait exceeded: the worker lets the TCP session go but the
            // peer stays OnQueue, maintained by UDP reask / push-grant.
            "stage:queue_detached queue wait exceeded 1800s (rank Some(42))",
            "stage:queue_wait timed out waiting for upload slot after 1800s",
            "peer has no free upload slots (OutOfPartReqs)",
            "peer ended our upload slot (OutOfPartReqs)",
            "peer revoked upload slot (QueueFull during transfer)",
            "peer put us back in queue at rank 7 during transfer",
        ] {
            assert!(
                !should_emit_source_failed(queue_state),
                "{queue_state:?} is a queue state, not a failure"
            );
            assert_eq!(
                classify_failure(queue_state, &classify_error(queue_state)),
                TransferFailureCode::QueueWaitInterrupted,
                "{queue_state:?} must read as a queue interruption"
            );
        }

        // Not a queue *wait*, but equally not the peer failing: it answered
        // our file request and simply holds nothing we still need.
        assert!(!should_emit_source_failed("peer has no parts we need"));

        assert!(!should_emit_source_failed("cancelled by user"));

        // Handshake failures are still real failures.
        for failure in [
            "stage:file_status_wait never received FileStatus",
            "stage:hello_wait timed out",
        ] {
            assert!(should_emit_source_failed(failure), "{failure:?}");
        }
    }

    /// The verification watcher parks on `wait_cancelled` for a transfer that
    /// may never be cancelled, so it has to die with the scope that spawned it
    /// rather than only on the explicit release at the end of the happy path.
    #[tokio::test]
    async fn abort_on_drop_stops_a_watcher_that_is_still_parked() {
        let control = std::sync::Arc::new(crate::sharing::manager::TransferControl::new());
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = {
            let flag = flag.clone();
            let control = control.clone();
            tokio::spawn(async move {
                control.wait_cancelled().await;
                flag.store(true, std::sync::atomic::Ordering::Release);
            })
        };
        let raw = {
            let guard = AbortOnDrop(handle);
            // Nothing has cancelled the control, so the task is parked here.
            tokio::task::yield_now().await;
            assert!(!guard.0.is_finished(), "watcher should still be parked");
            let raw = guard.0.abort_handle();
            drop(guard);
            raw
        };

        // Dropping the guard must have aborted it even though `cancel` was
        // never called; without the guard this task would outlive the scope.
        for _ in 0..50 {
            if raw.is_finished() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            raw.is_finished(),
            "AbortOnDrop must abort the parked watcher"
        );
        assert!(
            !flag.load(std::sync::atomic::Ordering::Acquire),
            "an aborted watcher must not have set the mirrored flag"
        );
    }

    #[test]
    fn verify_hashset_single_part_under_partsize() {
        let data: Vec<u8> = (0u8..100).collect();
        let file_hash_hex = ed2k_hash_bytes(&data);
        let mut file_hash = [0u8; 16];
        file_hash.copy_from_slice(&hex::decode(file_hash_hex).unwrap());
        let part_hash: [u8; 16] = Md4::digest(&data).into();
        assert!(verify_hashset(&file_hash, &[part_hash], data.len() as u64));
    }

    #[test]
    fn verify_hashset_exactly_partsize_one_hash() {
        // eMule: size == PARTSIZE needs hashset; file hash is MD4(MD4(data) ‖ MD4("")).
        let data = vec![0xABu8; PARTSIZE as usize];
        let file_hash_hex = ed2k_hash_bytes(&data);
        let mut file_hash = [0u8; 16];
        file_hash.copy_from_slice(&hex::decode(file_hash_hex).unwrap());
        let part_hash: [u8; 16] = Md4::digest(&data).into();
        assert!(
            verify_hashset(&file_hash, &[part_hash], PARTSIZE),
            "single-hash path must not treat PARTSIZE file as small-file MD4(data)"
        );
    }

    #[test]
    fn hashset2_aich_pins_when_it_matches_the_expected_root() {
        let expected = [0x11u8; 20];
        let mut pinned = None;
        consider_hashset2_aich_pin(&mut pinned, Some(expected), None, "", expected);
        assert_eq!(pinned, Some(expected));
    }

    #[test]
    fn hashset2_aich_does_not_first_wins_without_expected_or_votes() {
        let mut pinned = None;
        consider_hashset2_aich_pin(&mut pinned, None, None, "", [0xAAu8; 20]);
        assert!(pinned.is_none());
    }

    #[test]
    fn hashset2_aich_requires_two_sources_when_expected_is_unknown() {
        let root = [0xBBu8; 20];
        let mut pinned = None;
        let mut votes: HashMap<[u8; 20], HashSet<String>> = HashMap::new();
        consider_hashset2_aich_pin(&mut pinned, None, Some(&mut votes), "203.0.113.5", root);
        assert!(pinned.is_none());
        // A reconnect gets a new worker index but is still the same peer.
        consider_hashset2_aich_pin(&mut pinned, None, Some(&mut votes), "203.0.113.5", root);
        assert!(
            pinned.is_none(),
            "the same source repeating a root is still one vote"
        );
        consider_hashset2_aich_pin(&mut pinned, None, Some(&mut votes), "198.51.100.9", root);
        assert_eq!(pinned, Some(root));
    }

    #[test]
    fn hashset2_aich_ignores_a_conflicting_root_when_expected_is_known() {
        let expected = [0x11u8; 20];
        let mut pinned = None;
        let mut votes: HashMap<[u8; 20], HashSet<String>> = HashMap::new();
        consider_hashset2_aich_pin(
            &mut pinned,
            Some(expected),
            Some(&mut votes),
            "203.0.113.5",
            [0xFFu8; 20],
        );
        consider_hashset2_aich_pin(
            &mut pinned,
            Some(expected),
            Some(&mut votes),
            "198.51.100.9",
            [0xFFu8; 20],
        );
        assert!(pinned.is_none());
    }

    #[test]
    fn verify_hashset_two_parts_not_multiple() {
        let n = PARTSIZE as usize + 500;
        let data: Vec<u8> = (0..n).map(|i| (i % 256) as u8).collect();
        let file_hash_hex = ed2k_hash_bytes(&data);
        let mut file_hash = [0u8; 16];
        file_hash.copy_from_slice(&hex::decode(file_hash_hex).unwrap());
        let h1: [u8; 16] = Md4::digest(&data[..PARTSIZE as usize]).into();
        let h2: [u8; 16] = Md4::digest(&data[PARTSIZE as usize..]).into();
        assert!(verify_hashset(&file_hash, &[h1, h2], n as u64));
    }

    /// eMule writes a trailing `MD4("")` for a file that is an exact multiple of
    /// PARTSIZE, and `part_tracker::load_emule_format` normalizes that form on
    /// disk. The wire path rejected it, which silently disabled per-part MD4
    /// verification for the whole file rather than failing loudly.
    #[test]
    fn verify_hashset_accepts_the_known_met_sentinel_form() {
        let part = vec![0x5Au8; PARTSIZE as usize];
        let mut data = part.clone();
        data.extend_from_slice(&part);
        let file_size = data.len() as u64;
        assert_eq!(file_size % PARTSIZE, 0, "test needs an exact multiple");

        let mut file_hash = [0u8; 16];
        file_hash.copy_from_slice(&hex::decode(ed2k_hash_bytes(&data)).unwrap());
        let h = |b: &[u8]| -> [u8; 16] { Md4::digest(b).into() };
        let two = vec![h(&part), h(&part)];
        assert!(
            verify_hashset(&file_hash, &two, file_size),
            "the plain per-part form must still verify"
        );

        let mut with_sentinel = two.clone();
        with_sentinel.push(h(&[]));
        assert!(
            verify_hashset(&file_hash, &with_sentinel, file_size),
            "and so must the known.met form eMule writes for exact multiples"
        );

        // A third real hash is not the sentinel form and must still be refused.
        let mut padded = two;
        padded.push(h(&part));
        padded.push(h(&[]));
        assert!(!verify_hashset(&file_hash, &padded, file_size));
    }

    #[test]
    fn verify_hashset_two_full_parts_appends_sentinel() {
        let n = (2 * PARTSIZE) as usize;
        let data = vec![0xCDu8; n];
        let file_hash_hex = ed2k_hash_bytes(&data);
        let mut file_hash = [0u8; 16];
        file_hash.copy_from_slice(&hex::decode(file_hash_hex).unwrap());
        let h1: [u8; 16] = Md4::digest(&data[..PARTSIZE as usize]).into();
        let h2: [u8; 16] = Md4::digest(&data[PARTSIZE as usize..]).into();
        assert!(verify_hashset(&file_hash, &[h1, h2], n as u64));
    }

    #[test]
    fn summarize_timeout_error_is_user_friendly() {
        let error = "stage:data_wait download timeout: no data for 100s";
        let kind = classify_error(error);
        assert_eq!(kind, SourceFailureKind::DownloadTimeout);
        let failure = classify_failure(error, &kind);
        assert_eq!(failure, TransferFailureCode::DownloadTimedOut);
        assert_eq!(failure.message(), "Download timed out");
        assert_eq!(failure_kind_name(&kind), "download_timeout");
    }

    #[test]
    fn summarize_missing_file_error_is_user_friendly() {
        let kind = classify_error("peer does not have the file");
        assert_eq!(kind, SourceFailureKind::Permanent);
        let failure = classify_failure("peer does not have the file", &kind);
        assert_eq!(failure, TransferFailureCode::RemoteMissingFile);
        assert_eq!(failure.message(), "Remote missing file");
    }

    /// The raw error names a path and an OS error, and the path must not reach
    /// the UI; the code is what says which folder problem this is.
    #[test]
    fn a_download_folder_error_is_not_reported_as_a_connection_failure() {
        let raw = download_folder_error(
            "opening the part file",
            std::path::Path::new("/home/someone/Ember"),
            "Permission denied (os error 13)",
        )
        .to_string();
        let kind = classify_error(&raw);
        assert_eq!(kind, SourceFailureKind::Transient, "it still re-queues");
        assert_eq!(classify_failure(&raw, &kind), TransferFailureCode::DownloadFolderUnavailable);
        assert_eq!(infer_stage_from_error(&raw), "download_folder");
        assert!(!TransferFailureCode::DownloadFolderUnavailable.message().contains("/home"));
    }

    // The registry lock is held across the await on purpose: it serialises
    // tests that swap the process-global approved-root registry, and the
    // folder check under test is the window it has to cover. Current-thread
    // runtime, so there is no executor thread for the guard to strand.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn a_download_folder_that_is_not_an_approved_root_is_tagged() {
        let _registry = crate::security::filesystem::test_registry_lock();
        let dir = std::env::temp_dir().join(format!("ember-unapproved-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let error = prepare_download_dirs(&dir).await.expect_err("not approved").to_string();
        assert!(is_download_folder_error(&error), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ember_blake3_mismatch_is_permanent_and_distinct() {
        let raw = "ember blake3 mismatch: expected=aa got=bb";
        let kind = classify_error(raw);
        assert_eq!(kind, SourceFailureKind::Permanent);
        assert_eq!(
            classify_failure(raw, &kind),
            TransferFailureCode::EmberContentHashMismatch
        );
        assert!(is_ember_blake3_mismatch(raw));
        assert!(is_ember_blake3_mismatch(EMBER_BLAKE3_MISMATCH_MSG));
        assert!(
            is_ember_blake3_mismatch("Ember content hash mismatch"),
            "the canned UI summary must also classify as an Ember pin failure"
        );
        assert!(
            !is_ember_blake3_mismatch("Download hash mismatch for file: expected=x, got=y"),
            "ed2k mismatch must not be classified as an Ember pin failure"
        );
    }

    /// An unreadable `.part` must not blame the source, and must not look like
    /// a user cancel, a full disk, or a pin failure — each of which the event
    /// loop handles differently.
    #[test]
    fn local_read_failures_are_transient_and_keep_their_own_codes() {
        for (msg, code) in [
            (FINAL_VERIFY_INCONCLUSIVE_MSG, TransferFailureCode::FinalVerifyInconclusive),
            (LOCAL_READ_FAILED_MSG, TransferFailureCode::LocalReadFailed),
        ] {
            let kind = classify_error(msg);
            assert_eq!(kind, SourceFailureKind::Transient, "{msg}");
            assert_eq!(classify_failure(msg, &kind), code);
            assert!(!is_user_cancel_error(msg));
            assert!(!is_disk_full_error(msg));
            assert!(!is_ember_blake3_mismatch(msg));
            assert!(!is_expected_aich_mismatch(msg));
        }
    }

    #[test]
    fn expected_aich_mismatch_is_distinct_from_ed2k() {
        let raw = "Expected AICH hash mismatch: expected aa, got bb";
        assert!(is_expected_aich_mismatch(raw));
        assert!(!is_ember_blake3_mismatch(raw));
        assert_eq!(
            classify_failure(raw, &classify_error(raw)),
            TransferFailureCode::AichHashMismatch
        );
        assert!(
            !is_expected_aich_mismatch("Download hash mismatch for file: expected=x, got=y"),
            "ed2k mismatch must not be classified as an AICH pin failure"
        );
        assert!(
            !is_expected_aich_mismatch("AICH verification did not produce a root"),
            "missing AICH root is retryable, not a pin miss"
        );
        assert!(
            is_expected_aich_mismatch("AICH hash mismatch"),
            "the canned UI summary must also classify as an AICH pin failure"
        );
    }

    #[test]
    fn completed_download_name_uses_tracker_then_fallback() {
        assert_eq!(
            completed_download_name("renamed.bin", "original.bin"),
            "renamed.bin"
        );
        assert_eq!(completed_download_name("", "original.bin"), "original.bin");
        assert_eq!(
            completed_download_name("../evil.txt", "original.bin"),
            "evil.txt",
            "completion must still sanitize a renamed display name"
        );
    }

    #[test]
    fn a_duplicate_of_a_full_length_name_still_fits() {
        let dir = std::path::Path::new("Downloads");
        // `sanitize_filename` clamps to 255 bytes; the duplicate must not
        // grow past that.
        let ascii = format!("{}.mkv", "a".repeat(251));
        assert_eq!(ascii.len(), 255);
        let wide = format!("{}.mkv", "é".repeat(125));
        for name in [ascii, wide] {
            for suffix in [1, 42, 10_000] {
                let candidate = dedup_candidate(&dir.join(&name), suffix);
                let file_name = candidate.file_name().unwrap().to_str().unwrap();
                assert!(file_name.len() <= 255, "{} bytes", file_name.len());
                assert!(file_name.ends_with(&format!(" ({suffix}).mkv")));
            }
        }
        // Short names are untouched.
        assert_eq!(
            dedup_candidate(&dir.join("movie.mkv"), 2),
            dir.join("movie (2).mkv")
        );
    }

    #[test]
    fn a_block_queued_behind_the_one_arriving_does_not_expire() {
        let mut outstanding = Vec::new();
        push_outstanding_batch(&mut outstanding, &[(0, 100), (100, 200), (200, 300)]);
        for r in &mut outstanding {
            r.expires_at = std::time::Instant::now();
        }
        // Data for the middle block: it and the one queued after it are
        // live; the one before it the peer skipped keeps its deadline.
        refresh_outstanding_range(&mut outstanding, 150);
        let now = std::time::Instant::now();
        let live = |start: u64| outstanding.iter().find(|r| r.start == start).unwrap().expires_at > now;
        assert!(!live(0));
        assert!(live(100));
        assert!(live(200));

        // Completing a block refreshes the ones behind it as well.
        for r in &mut outstanding {
            r.expires_at = std::time::Instant::now();
        }
        assert!(take_completed_outstanding_range(&mut outstanding, 100, 200));
        let now = std::time::Instant::now();
        assert!(outstanding.iter().find(|r| r.start == 200).unwrap().expires_at > now);
    }

    #[test]
    fn concurrent_completed_files_claim_distinct_names() {
        let dir = std::env::temp_dir().join(format!(
            "ember-final-name-race-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let first_part = dir.join("first.part");
        let second_part = dir.join("second.part");
        let target = dir.join("same-name.bin");
        std::fs::write(&first_part, b"first").unwrap();
        std::fs::write(&second_part, b"second").unwrap();

        let (first_final, second_final) = std::thread::scope(|scope| {
            let first = scope.spawn(|| move_part_to_final(&first_part, &target).unwrap());
            let second = scope.spawn(|| move_part_to_final(&second_part, &target).unwrap());
            (first.join().unwrap(), second.join().unwrap())
        });

        assert_ne!(first_final, second_final);
        let mut contents = [
            std::fs::read(first_final).unwrap(),
            std::fs::read(second_final).unwrap(),
        ];
        contents.sort();
        assert_eq!(contents, [b"first".to_vec(), b"second".to_vec()]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn approved_completion_uses_identity_checked_hard_link() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-approved-hard-link-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let root = base.join("root");
        let data = base.join("data");
        let temp = root.join("Temp");
        let downloads = root.join("Downloads");
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::create_dir_all(&downloads).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let part = temp.join("source.part");
        let target = downloads.join("finished.bin");
        std::fs::write(&part, b"verified bytes").unwrap();
        let root_string = root.to_string_lossy().into_owned();
        crate::security::filesystem::initialize_approved_roots(
            &data,
            std::slice::from_ref(&root_string),
        )
        .unwrap();
        let (_, opened) = crate::security::filesystem::open_existing_approved(
            &part,
            std::slice::from_ref(&root_string),
            false,
        )
        .unwrap();
        let source_identity = crate::security::filesystem::opened_file_identity(&opened).unwrap();
        drop(opened);

        let final_path =
            move_part_to_final_approved(&part, &target, &root, &source_identity).unwrap();
        let (_, final_file) = crate::security::filesystem::open_existing_approved(
            &final_path,
            std::slice::from_ref(&root_string),
            false,
        )
        .unwrap();
        #[cfg(any(target_os = "linux", target_os = "android", windows))]
        assert_eq!(
            crate::security::filesystem::opened_file_identity(&final_file).unwrap(),
            source_identity,
            "same-volume completion must publish a hard link to the verified source"
        );
        #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
        assert_ne!(
            crate::security::filesystem::opened_file_identity(&final_file).unwrap(),
            source_identity,
            "platforms without an atomic handle-link API must use the copy fallback"
        );
        assert!(!part.exists());
        assert_eq!(std::fs::read(&final_path).unwrap(), b"verified bytes");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn a_part_left_in_an_earlier_download_folder_completes_into_the_current_one() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-completion-across-folders-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let old = base.join("old");
        let new = base.join("new");
        let data = base.join("data");
        for dir in [old.join("Temp"), new.clone(), data.clone()] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let part = old.join("Temp").join("started-before.part");
        std::fs::write(&part, b"verified bytes").unwrap();
        let old_string = old.to_string_lossy().into_owned();
        let roots = [old_string.clone(), new.to_string_lossy().into_owned()];
        crate::security::filesystem::initialize_approved_roots(&data, &roots).unwrap();
        let (_, opened) = crate::security::filesystem::open_existing_approved(
            &part,
            std::slice::from_ref(&old_string),
            false,
        )
        .unwrap();
        let identity = crate::security::filesystem::opened_file_identity(&opened).unwrap();
        drop(opened);

        let final_path =
            move_part_to_downloads(&part, &old, &new, "finished.bin", &identity).unwrap();
        assert_eq!(
            final_path,
            new.canonicalize().unwrap().join("Downloads").join("finished.bin")
        );
        assert_eq!(std::fs::read(&final_path).unwrap(), b"verified bytes");
        assert!(!part.exists());

        let stray = old.join("Temp").join("stray.part");
        std::fs::write(&stray, b"x").unwrap();
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        assert!(
            move_part_to_downloads(&stray, &new, &new, "x.bin", &identity).is_err(),
            "the part must be inside the root it is said to be in"
        );
        assert!(
            move_part_to_downloads(&stray, &old, &outside, "x.bin", &identity).is_err(),
            "and the target inside an approved one"
        );
        let changed = move_part_to_downloads(&stray, &old, &new, "x.bin", &identity)
            .unwrap_err()
            .to_string();
        assert_eq!(
            classify_failure(&changed, &SourceFailureKind::Transient),
            TransferFailureCode::CompletionMoveFailed,
            "{changed}"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    /// A download filed under a category lands in that category's folder
    /// inside Downloads, made as needed; when the folder cannot be made it
    /// lands in Downloads itself rather than failing.
    #[test]
    fn a_categorised_download_completes_into_its_folder_inside_downloads() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-completion-category-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let root = base.join("dl");
        let data = base.join("data");
        for dir in [root.join("Temp"), data.clone()] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let root_string = root.to_string_lossy().into_owned();
        crate::security::filesystem::initialize_approved_roots(&data, std::slice::from_ref(&root_string))
            .unwrap();
        let part_with = |name: &str| {
            let part = root.join("Temp").join(name);
            std::fs::write(&part, b"verified bytes").unwrap();
            let (_, opened) = crate::security::filesystem::open_existing_approved(
                &part,
                std::slice::from_ref(&root_string),
                false,
            )
            .unwrap();
            let identity = crate::security::filesystem::opened_file_identity(&opened).unwrap();
            (part, identity)
        };
        let downloads = root.canonicalize().unwrap().join("Downloads");

        let subdir = vec!["Video".to_string(), "TV Series".to_string()];
        let (part, identity) = part_with("episode.part");
        let final_path =
            move_part_to_completed(&part, &root, &root, &subdir, "episode.mkv", &identity).unwrap();
        assert_eq!(final_path, downloads.join("Video").join("TV Series").join("episode.mkv"));
        assert_eq!(std::fs::read(&final_path).unwrap(), b"verified bytes");

        // A file where the category's folder would go.
        std::fs::write(downloads.join("Blocked"), b"not a folder").unwrap();
        let (part, identity) = part_with("other.part");
        let final_path = move_part_to_completed(
            &part,
            &root,
            &root,
            &["Blocked".to_string()],
            "other.bin",
            &identity,
        )
        .unwrap();
        assert_eq!(final_path, downloads.join("other.bin"), "falls back to Downloads");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn approved_completion_copy_fallback_preserves_identity_checks() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-approved-copy-fallback-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let root = base.join("root");
        let data = base.join("data");
        let temp = root.join("Temp");
        let downloads = root.join("Downloads");
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::create_dir_all(&downloads).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let part = temp.join("source.part");
        let target = downloads.join("finished.bin");
        std::fs::write(&part, b"fallback bytes").unwrap();
        let root_string = root.to_string_lossy().into_owned();
        crate::security::filesystem::initialize_approved_roots(
            &data,
            std::slice::from_ref(&root_string),
        )
        .unwrap();
        let (_, opened) = crate::security::filesystem::open_existing_approved(
            &part,
            std::slice::from_ref(&root_string),
            false,
        )
        .unwrap();
        let source_identity = crate::security::filesystem::opened_file_identity(&opened).unwrap();
        drop(opened);
        let allowed = [root_string];
        let final_path =
            move_part_to_final_with_roots(&part, &target, &allowed, Some(&source_identity), false)
                .unwrap();
        let (_, final_file) =
            crate::security::filesystem::open_existing_approved(&final_path, &allowed, false)
                .unwrap();
        assert_ne!(
            crate::security::filesystem::opened_file_identity(&final_file).unwrap(),
            source_identity,
            "forced fallback must be a separately created copy"
        );
        assert!(!part.exists());
        assert_eq!(std::fs::read(&final_path).unwrap(), b"fallback bytes");
        let _ = std::fs::remove_dir_all(base);
    }

    fn completion_copies_in(dir: &std::path::Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.starts_with(COMPLETION_COPY_PREFIX))
            .collect()
    }

    /// The cross-volume path: copied under a name the library skips, then
    /// renamed. A kill mid-copy leaves that name, never a truncated file
    /// under the real one, which the watcher would index and the retried
    /// completion would step around as "name (1)".
    #[test]
    fn a_copied_completion_is_published_by_renaming_a_finished_temporary_copy() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-completion-copy-rename-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let root = base.join("root");
        let data = base.join("data");
        let downloads = root.join("Downloads");
        for dir in [root.join("Temp"), downloads.clone(), data.clone()] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let root_string = root.to_string_lossy().into_owned();
        crate::security::filesystem::initialize_approved_roots(
            &data,
            std::slice::from_ref(&root_string),
        )
        .unwrap();
        let allowed = [root_string];
        let target = downloads.join("finished.bin");
        std::fs::write(&target, b"someone else's").unwrap();
        let part = root.join("Temp").join("source.part");
        std::fs::write(&part, b"copied bytes").unwrap();
        let (_, opened) =
            crate::security::filesystem::open_existing_approved(&part, &allowed, false).unwrap();
        let identity = crate::security::filesystem::opened_file_identity(&opened).unwrap();
        drop(opened);

        let final_path =
            move_part_to_final_with_roots(&part, &target, &allowed, Some(&identity), false)
                .unwrap();
        assert_eq!(final_path.file_name().unwrap(), "finished (1).bin");
        assert_eq!(std::fs::read(&final_path).unwrap(), b"copied bytes");
        assert_eq!(std::fs::read(&target).unwrap(), b"someone else's", "never replaced");
        assert!(!part.exists());
        assert!(completion_copies_in(&downloads).is_empty(), "the copy was renamed, not left");
        let _ = std::fs::remove_dir_all(base);
    }

    /// A volume that has neither a rename that refuses to replace nor hard
    /// links (FUSE, NFS, exFAT, SMB) still completes: the file is copied
    /// straight to a free name, as before the temporary copy existed.
    #[test]
    fn a_volume_without_a_no_replace_rename_or_hard_links_still_completes() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-completion-no-rename-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let (root, data) = (base.join("root"), base.join("data"));
        let downloads = root.join("Downloads");
        for dir in [root.join("Temp"), downloads.clone(), data.clone()] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let root_string = root.to_string_lossy().into_owned();
        crate::security::filesystem::initialize_approved_roots(
            &data,
            std::slice::from_ref(&root_string),
        )
        .unwrap();
        let allowed = [root_string];
        let target = downloads.join("finished.bin");
        std::fs::write(&target, b"someone else's").unwrap();
        let part = root.join("Temp").join("source.part");
        std::fs::write(&part, b"copied bytes").unwrap();
        let (_, opened) =
            crate::security::filesystem::open_existing_approved(&part, &allowed, false).unwrap();
        let identity = crate::security::filesystem::opened_file_identity(&opened).unwrap();
        drop(opened);

        NO_REPLACE_PUBLISH_UNSUPPORTED.with(|unsupported| unsupported.set(true));
        let moved = move_part_to_final_with_roots(&part, &target, &allowed, Some(&identity), false);
        NO_REPLACE_PUBLISH_UNSUPPORTED.with(|unsupported| unsupported.set(false));

        let final_path = moved.unwrap();
        assert_eq!(final_path.file_name().unwrap(), "finished (1).bin");
        assert_eq!(std::fs::read(&final_path).unwrap(), b"copied bytes");
        assert_eq!(std::fs::read(&target).unwrap(), b"someone else's", "never replaced");
        assert!(!part.exists());
        assert!(completion_copies_in(&downloads).is_empty(), "the temporary copy is removed");
        let _ = std::fs::remove_dir_all(base);
    }

    /// A rename that happened but could not be confirmed (a filesystem
    /// without stable inode numbers) counts as published, so completion
    /// neither fails nor publishes the file again as "name (1)".
    #[test]
    fn a_rename_that_took_place_counts_as_published() {
        let base = std::env::temp_dir().join(format!(
            "ember-renamed-copy-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let published = base.join("finished.bin");
        std::fs::write(&published, b"copied bytes").unwrap();
        let copy = |len| CompletionCopy {
            path: base.join(completion_copy_name(std::path::Path::new("x.part"))),
            identity: crate::security::filesystem::object_identity(&published).unwrap(),
            len,
            source: None,
        };
        assert!(copy(12).renamed_to(&published));
        assert!(!copy(5).renamed_to(&published), "not a file of the copy's length");
        let still_there = copy(12);
        std::fs::write(&still_there.path, b"copied bytes").unwrap();
        assert!(!still_there.renamed_to(&published), "the copy was not renamed");

        let other = base.join("other.bin");
        std::fs::write(&other, b"other bytes!").unwrap();
        let vanished = CompletionCopy {
            identity: crate::security::filesystem::object_identity(&other).unwrap(),
            ..copy(12)
        };
        assert!(
            !vanished.renamed_to(&published),
            "a copy that vanished is not published by a different file of its length"
        );
        let source = base.join("x.part");
        std::fs::write(&source, b"copied bytes").unwrap();
        let unstable_inodes = CompletionCopy {
            source: Some(source),
            ..vanished
        };
        assert!(
            unstable_inodes.renamed_to(&published),
            "where file IDs do not survive a rename, the source's exact bytes do"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    /// A scanner or the indexer holding the fresh copy refuses the rename
    /// for a moment: it is retried, never answered with a copy in place
    /// that could leave a truncated file under the real name.
    #[cfg(windows)]
    #[test]
    fn a_completion_copy_held_by_a_scanner_is_retried_and_never_copied_in_place() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        for code in [5, 32, 33] {
            let error = std::io::Error::from_raw_os_error(code);
            assert!(held_by_another_process(&error));
            assert!(!no_replace_publish_unavailable(&error), "{code}");
        }
        let base = std::env::temp_dir().join(format!(
            "ember-held-completion-copy-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let (root, data) = (base.join("root"), base.join("data"));
        let downloads = root.join("Downloads");
        for dir in [root.join("Temp"), downloads.clone(), data.clone()] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let root_string = root.to_string_lossy().into_owned();
        crate::security::filesystem::initialize_approved_roots(
            &data,
            std::slice::from_ref(&root_string),
        )
        .unwrap();
        let allowed = [root_string];
        let part = root.join("Temp").join("source.part");
        let identity = |part: &std::path::Path| {
            let (_, opened) =
                crate::security::filesystem::open_existing_approved(part, &allowed, false)
                    .unwrap();
            crate::security::filesystem::opened_file_identity(&opened).unwrap()
        };

        std::fs::write(&part, b"held a moment").unwrap();
        COMPLETION_COPY_HELD.with(|held| held.set(2));
        let moved = move_part_to_final_with_roots(
            &part,
            &downloads.join("moment.bin"),
            &allowed,
            Some(&identity(&part)),
            false,
        );
        let left = COMPLETION_COPY_HELD.with(|held| held.replace(0));
        assert_eq!(moved.unwrap().file_name().unwrap(), "moment.bin");
        assert_eq!(left, 0, "both refusals were waited out");
        assert_eq!(std::fs::read(downloads.join("moment.bin")).unwrap(), b"held a moment");
        assert!(completion_copies_in(&downloads).is_empty());

        std::fs::write(&part, b"held for good").unwrap();
        COMPLETION_COPY_HELD.with(|held| held.set(u32::MAX));
        let moved = move_part_to_final_with_roots(
            &part,
            &downloads.join("held.bin"),
            &allowed,
            Some(&identity(&part)),
            false,
        );
        COMPLETION_COPY_HELD.with(|held| held.set(0));
        assert!(moved.is_err(), "the completion fails and is tried again later");
        assert!(part.exists(), "the .part is kept");
        assert!(!downloads.join("held.bin").exists(), "nothing under the real name");
        assert!(completion_copies_in(&downloads).is_empty(), "the copy is not left behind");
        let _ = std::fs::remove_dir_all(base);
    }

    /// Regression for volumes without hard links (exFAT, FAT32, some
    /// shares), where the scanner's hold cannot be got round by a link: a
    /// short hold is waited out as everywhere, and a long one ends in the
    /// file copied straight to a free name, as before the temporary copy
    /// existed, rather than in a failed completion.
    #[cfg(windows)]
    #[test]
    fn a_held_copy_on_a_volume_without_hard_links_still_completes() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-held-no-links-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let (root, data) = (base.join("root"), base.join("data"));
        let downloads = root.join("Downloads");
        for dir in [root.join("Temp"), downloads.clone(), data.clone()] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let root_string = root.to_string_lossy().into_owned();
        crate::security::filesystem::initialize_approved_roots(
            &data,
            std::slice::from_ref(&root_string),
        )
        .unwrap();
        let allowed = [root_string];
        let part = root.join("Temp").join("source.part");
        let identity = |part: &std::path::Path| {
            let (_, opened) =
                crate::security::filesystem::open_existing_approved(part, &allowed, false)
                    .unwrap();
            crate::security::filesystem::opened_file_identity(&opened).unwrap()
        };
        let complete = |held: u32, name: &str| {
            HARD_LINKS_UNSUPPORTED.with(|unsupported| unsupported.set(true));
            COMPLETION_COPY_HELD.with(|copy_held| copy_held.set(held));
            let moved = move_part_to_final_with_roots(
                &part,
                &downloads.join(name),
                &allowed,
                Some(&identity(&part)),
                false,
            );
            COMPLETION_COPY_HELD.with(|copy_held| copy_held.set(0));
            HARD_LINKS_UNSUPPORTED.with(|unsupported| unsupported.set(false));
            moved
        };

        std::fs::write(&part, b"held a moment").unwrap();
        let moved = complete(2, "moment.bin").unwrap();
        assert_eq!(moved.file_name().unwrap(), "moment.bin");
        assert_eq!(std::fs::read(&moved).unwrap(), b"held a moment");
        assert!(!part.exists());

        std::fs::write(&part, b"held for good").unwrap();
        std::fs::write(downloads.join("held.bin"), b"someone else's").unwrap();
        let moved = complete(u32::MAX, "held.bin").unwrap();
        assert_eq!(moved.file_name().unwrap(), "held (1).bin", "a free name, never a replace");
        assert_eq!(std::fs::read(&moved).unwrap(), b"held for good");
        assert_eq!(std::fs::read(downloads.join("held.bin")).unwrap(), b"someone else's");
        assert!(!part.exists());
        assert!(completion_copies_in(&downloads).is_empty(), "the held copy is removed");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn a_completion_copy_is_named_so_the_library_never_shares_it() {
        let id = uuid::Uuid::new_v4().to_string();
        let attachment = format!("ember-attach-{}", "ab".repeat(16));
        for stem in [id.as_str(), attachment.as_str()] {
            let part = std::path::Path::new("Temp").join(format!("{stem}.part"));
            let name = completion_copy_name(&part);
            assert_eq!(parse_completion_copy_name(&name), Some(stem));
            let copy_of_copy = completion_copy_name(std::path::Path::new(&name));
            assert_eq!(
                parse_completion_copy_name(&copy_of_copy),
                Some(stem),
                "a recovered copy published across volumes keeps naming its download"
            );
            assert!(crate::sharing::indexer::is_excluded_share_file_name(
                std::path::Path::new(&name)
            ));
        }
        for other in [
            ".ember-copy-.tmp",
            ".ember-copy-0123456789abcdef.tmp",
            ".ember-copy-0123456789abcdeg.x.tmp",
            ".ember-copy-0123456789abcdef.a.b.tmp",
            "movie.tmp",
        ] {
            assert_eq!(parse_completion_copy_name(other), None, "{other}");
        }
    }

    #[test]
    fn stale_completion_copies_are_settled_by_whose_they_are() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-stale-completion-copies-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let (old, new, data) = (base.join("old"), base.join("new"), base.join("data"));
        for root in [&old, &new] {
            for dir in ["Temp"].into_iter().chain(finished_file_dirs()) {
                std::fs::create_dir_all(root.join(dir)).unwrap();
            }
        }
        std::fs::create_dir_all(&data).unwrap();
        let roots = [
            new.to_string_lossy().into_owned(),
            old.to_string_lossy().into_owned(),
        ];
        crate::security::filesystem::initialize_approved_roots(&data, &roots).unwrap();
        let downloads = new.join("Downloads");
        let copy_of = |root: &std::path::Path, dir: &str, stem: &str, bytes: &[u8]| {
            let path = root
                .join(dir)
                .join(completion_copy_name(std::path::Path::new(&format!("{stem}.part"))));
            std::fs::write(&path, bytes).unwrap();
            path
        };
        let uuid = || uuid::Uuid::new_v4().to_string();
        let (redo, unfinished, recovered, partial, duplicate, linked, newer) =
            (uuid(), uuid(), uuid(), uuid(), uuid(), uuid(), uuid());
        let attachment = format!("ember-attach-{}", "cd".repeat(16));
        let room = format!("ember-xfer-{}", "ef".repeat(16));
        std::fs::write(old.join("Temp").join(format!("{redo}.part")), b"x").unwrap();
        std::fs::write(new.join("Temp").join(format!("{attachment}.part")), b"x").unwrap();

        let redone = copy_of(&new, "Downloads", &redo, b"half");
        let chat = copy_of(&old, crate::network::chat_attach::CHAT_FILES_DIR, &attachment, b"half");
        let resumed = copy_of(&new, "Downloads", &unfinished, b"finished bytes");
        let only_copy = copy_of(&new, "Downloads", &recovered, b"finished bytes");
        let cut_short = copy_of(&new, "Downloads", &partial, b"fini");
        let leftover = copy_of(&new, "Downloads", &duplicate, b"song bytes");
        std::fs::write(downloads.join("song.bin"), b"song bytes").unwrap();
        let linked_copy = copy_of(&new, "Downloads", &linked, b"clip bytes");
        std::fs::write(downloads.join("clip.bin"), b"another clip").unwrap();
        std::fs::hard_link(&linked_copy, downloads.join("clip (1).bin")).unwrap();
        let restarted = copy_of(&new, "Downloads", &newer, b"finished bytes");
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(new.join("Temp").join(format!("{newer}.part")), b"x").unwrap();
        let unknown = copy_of(&new, crate::network::ember::xfer::CHANNEL_FILES_DIR, &room, b"?");
        let taken = downloads.join("movie.bin");
        std::fs::write(&taken, b"someone else's").unwrap();
        let unrelated = downloads.join(".ember-copy-mine.tmp");
        std::fs::write(&unrelated, b"keep").unwrap();

        let hash_of = |bytes: &[u8]| {
            let path = base.join("hashed");
            std::fs::write(&path, bytes).unwrap();
            super::super::hash::ed2k_hash_open_file(&mut std::fs::File::open(&path).unwrap())
                .unwrap()
        };
        let finished_file = |name: &str, bytes: &[u8]| ExpectedFinishedFile {
            name: name.into(),
            ed2k_hash: hash_of(bytes),
            size: bytes.len() as u64,
        };
        let owner = |stem: &str| {
            if stem == unfinished {
                CopyOwner::Unfinished
            } else if stem == recovered || stem == partial {
                CopyOwner::Finished(finished_file("movie.bin", b"finished bytes"))
            } else if stem == duplicate {
                CopyOwner::Finished(finished_file("song.bin", b"song bytes"))
            } else if stem == linked {
                CopyOwner::Finished(finished_file("clip.bin", b"clip bytes"))
            } else {
                CopyOwner::Unknown
            }
        };
        let settle = |cutoff| {
            for root in &roots {
                settle_stale_completion_copies(root, &roots, cutoff, &owner);
            }
        };

        settle(std::time::UNIX_EPOCH);
        for path in [&redone, &chat, &only_copy, &cut_short, &unknown, &leftover] {
            assert!(path.exists(), "a copy from this run is never touched");
        }

        settle(std::time::SystemTime::now() + std::time::Duration::from_secs(60));
        assert!(!redone.exists(), "its .part, in another folder, completes again");
        assert!(!chat.exists(), "chat copies are settled the same way");
        assert!(resumed.exists(), "an unfinished download's copy is left to its resume");
        assert!(!only_copy.exists());
        assert_eq!(
            std::fs::read(downloads.join("movie (1).bin")).unwrap(),
            b"finished bytes",
            "a finished download's only complete copy is published under a free name"
        );
        assert_eq!(std::fs::read(&taken).unwrap(), b"someone else's");
        assert!(!cut_short.exists(), "a copy that is not the finished file is removed");
        assert!(!leftover.exists(), "the finished file is there: its copy goes");
        assert!(!downloads.join("song (1).bin").exists(), "and is not published again");
        assert!(!linked_copy.exists(), "a copy linked as the finished file goes");
        assert_eq!(
            std::fs::read(downloads.join("clip (1).bin")).unwrap(),
            b"clip bytes",
            "the name it was published as, the plain one being taken"
        );
        assert!(!downloads.join("clip (2).bin").exists(), "and it is not published again");
        assert!(restarted.exists(), "a .part newer than the copy never costs the copy");
        assert!(unknown.exists(), "a copy nothing can check is kept");
        assert!(unrelated.exists());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn a_destination_without_room_fails_before_copying_and_keeps_the_part() {
        let dir = std::path::Path::new("downloads");
        let buffer = crate::network::downloads::DISK_SPACE_BUFFER;
        let error = room_for_completion_copy(100, Some(99), dir).unwrap_err().to_string();
        assert!(is_disk_full_error(&error), "{error}");
        assert_eq!(
            classify_failure(&error, &SourceFailureKind::Transient),
            TransferFailureCode::InsufficientDisk
        );
        assert!(
            room_for_completion_copy(100, Some(100 + buffer - 1), dir).is_err(),
            "the same margin the download keeps"
        );
        assert!(room_for_completion_copy(100, Some(100 + buffer), dir).is_ok());
        assert!(
            room_for_completion_copy(100, None, dir).is_ok(),
            "a volume that will not say lets the copy try"
        );
    }

    // Held across the awaits for the reason given above
    // `a_download_folder_that_is_not_an_approved_root_is_tagged`.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn a_worker_holds_a_download_whose_progress_is_on_an_offline_folder() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-offline-part-folder-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let (new, data) = (base.join("new"), base.join("data"));
        let volume = base.join("unplugged");
        let offline = volume.join("old");
        for dir in [new.clone(), data.clone()] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let folders = crate::storage::part_folders::DownloadFolders::new(
            &new.to_string_lossy(),
            &[offline.to_string_lossy().into_owned()],
        );
        let roots = folders.roots();
        let shared = folders.shared();
        let id = uuid::Uuid::new_v4().to_string();
        crate::storage::part_folders::note_located(&id, &offline);
        crate::storage::part_folders::simulate_unplugged(&volume, true);

        let error = prepare_part_dir(&shared, &id).await.unwrap_err().to_string();
        crate::storage::part_folders::simulate_unplugged(&volume, false);
        assert_eq!(
            classify_failure(&error, &SourceFailureKind::Transient),
            TransferFailureCode::PartFolderOffline
        );
        assert!(
            !new.join("Temp").join(format!("{id}.part")).exists(),
            "no second `.part` started from zero"
        );

        std::fs::create_dir_all(offline.join("Temp")).unwrap();
        std::fs::write(offline.join("Temp").join(format!("{id}.part")), b"progress").unwrap();
        crate::security::filesystem::initialize_approved_roots(&data, &roots).unwrap();
        let (root, temp) = prepare_part_dir(&shared, &id).await.unwrap();
        assert_eq!(root, offline, "resumed where the progress is once the drive is back");
        assert_eq!(temp.file_name().unwrap(), "Temp");
        assert!(
            !offline.join("Downloads").exists(),
            "an earlier folder never gets a Downloads"
        );
        let _ = std::fs::remove_dir_all(base);
    }
}

/// Display name used when a finished `.part` is moved into Downloads.
///
/// The `.part` itself is named by transfer id, so a rename while downloading
/// is metadata: the live tracker holds the current name, and this is what
/// completion must read. An empty tracker name (a tracker that never got
/// `set_file_name`) falls back to the name the download task started with.
pub(super) fn completed_download_name(tracker_name: &str, fallback: &str) -> String {
    crate::security::sanitize_filename(if tracker_name.is_empty() {
        fallback
    } else {
        tracker_name
    })
}

pub(super) fn apply_control_rename(
    control: &crate::sharing::manager::TransferControl,
    tracker: &mut super::part_tracker::PartTracker,
) {
    if let Some(name) = control.pending_rename() {
        tracker.set_file_name(&name);
    }
}

/// [`apply_control_rename`] for the moment completion reads the name it moves
/// the file under: renames after this are refused rather than left to relabel
/// a row whose file already carries the old name.
pub(super) fn seal_control_rename(
    control: &crate::sharing::manager::TransferControl,
    tracker: &mut super::part_tracker::PartTracker,
) {
    if let Some(name) = control.seal_pending_rename() {
        tracker.set_file_name(&name);
    }
}

/// Writes an empty `.part`, verifies ed2k hash ([`super::hash::empty_ed2k_file_md4`]), moves to Downloads.
pub(super) async fn finalize_zero_ed2k_file(
    transfer_id: &str,
    file_name: &str,
    file_hash: [u8; 16],
    download_dir: &std::path::Path,
) -> anyhow::Result<std::path::PathBuf> {
    if file_hash != super::hash::empty_ed2k_file_md4() {
        anyhow::bail!(
            "zero-byte ed2k file requires file hash {}",
            hex::encode(super::hash::empty_ed2k_file_md4())
        );
    }
    let allowed = vec![download_dir.to_string_lossy().into_owned()];
    let (temp_dir, completed_dir) = prepare_download_dirs(download_dir).await?;
    crate::storage::part_folders::note_located(transfer_id, download_dir);
    let safe_name = crate::security::sanitize_filename(file_name);
    let part_path = temp_dir.join(format!("{transfer_id}.part"));
    let final_path = completed_dir.join(&safe_name);
    for stale in [&part_path, &part_path.with_extension("part.met")] {
        if let Err(error) = crate::security::filesystem::remove_approved_file(stale, &allowed) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error.into());
            }
        }
    }
    {
        let part = part_path.clone();
        let allowed = allowed.clone();
        tokio::task::spawn_blocking(move || {
            let parent = part.parent().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "part has no parent")
            })?;
            let name = part.file_name().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "part has no file name")
            })?;
            let (_path, file) =
                crate::security::filesystem::create_new_in_approved_parent(parent, name, &allowed)?;
            file.sync_all()
        })
        .await
        .map_err(|error| anyhow::anyhow!("zero-byte create task failed: {error}"))??;
    }
    let verify_path = part_path.clone();
    let verify_allowed = allowed.clone();
    let expected = hex::encode(file_hash);
    let verified_identity = tokio::task::spawn_blocking(move || {
        let (_, mut file) = crate::security::filesystem::open_existing_approved(
            &verify_path,
            &verify_allowed,
            false,
        )?;
        let identity = crate::security::filesystem::opened_file_identity(&file)?;
        let hash = super::hash::ed2k_hash_open_file(&mut file)?;
        Ok::<_, anyhow::Error>((hash == expected).then_some(identity))
    })
    .await
    .map_err(|e| anyhow::anyhow!("hash task: {e}"))??
    .ok_or_else(|| anyhow::anyhow!("zero-byte file ed2k hash verification failed"))?;
    let pp = part_path.clone();
    let fp = final_path.clone();
    let root = download_dir.to_path_buf();
    let actual_final = tokio::task::spawn_blocking(move || {
        move_part_to_final_approved(&pp, &fp, &root, &verified_identity)
    })
    .await
    .map_err(|e| anyhow::anyhow!("rename task: {e}"))??;
    Ok(actual_final)
}

/// Move (or copy+delete) a `.part` file to its final destination, deduplicating
/// the filename if the target already exists.  Returns the actual final path.
#[cfg(test)]
pub(crate) fn move_part_to_final(
    part_path: &std::path::Path,
    target: &std::path::Path,
) -> anyhow::Result<std::path::PathBuf> {
    move_part_to_final_with_roots(part_path, target, &[], None, true)
}

fn move_part_to_final_with_roots(
    part_path: &std::path::Path,
    target: &std::path::Path,
    allowed_roots: &[String],
    expected_source_identity: Option<&crate::security::filesystem::ObjectIdentity>,
    allow_hard_link: bool,
) -> anyhow::Result<std::path::PathBuf> {
    // `exists()` followed by `rename()` is not an atomic name claim. On
    // Windows the loser fails despite having a complete .part; on Unix,
    // rename can replace the winner. Hard-linking claims an absent destination
    // atomically without replacement and remains O(1) on the common same-volume
    // path. Across volumes, or on filesystems without hard links, the file is
    // copied under a temporary name first and then renamed into a free name
    // without replacement, which is also collision-safe. Where that rename
    // is unavailable too, the file is copied straight to a free name with an
    // exclusive create, as before the temporary copy existed.
    let mut staged: Option<CompletionCopy> = None;
    let mut copy_in_place = false;
    let mut suffix = 0u32;
    while suffix <= 10_000 {
        let final_path = dedup_candidate(target, suffix);
        suffix += 1;
        if copy_in_place {
            let copied =
                copy_exclusive(part_path, &final_path, allowed_roots, expected_source_identity);
            match copied {
                Ok(_) => {
                    sync_published(&final_path, allowed_roots);
                    remove_completed_part_best_effort(
                        part_path,
                        &final_path,
                        "copied",
                        allowed_roots,
                        expected_source_identity,
                    );
                    return Ok(final_path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists || final_path.exists() => {
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        if allow_hard_link && staged.is_none() {
            let link_result = if allowed_roots.is_empty() {
                std::fs::hard_link(part_path, &final_path).map(|()| final_path.clone())
            } else if let Some(expected) = expected_source_identity {
                crate::security::filesystem::hard_link_approved(
                    part_path,
                    &final_path,
                    allowed_roots,
                    expected,
                )
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "approved hard-link completion requires a pinned source identity",
                ))
            };
            match link_result {
                Ok(linked_path) => {
                    remove_completed_part_best_effort(
                        part_path,
                        &linked_path,
                        "linked",
                        allowed_roots,
                        expected_source_identity,
                    );
                    return Ok(linked_path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists || final_path.exists() => {
                    continue;
                }
                Err(e) if hard_link_fallback_allowed(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let copy = match &staged {
            Some(copy) => copy,
            None => staged.insert(stage_completion_copy(
                part_path,
                target,
                allowed_roots,
                expected_source_identity,
            )?),
        };
        match copy.publish(&final_path, allowed_roots) {
            Ok(published) => {
                sync_published(&published, allowed_roots);
                remove_completed_part_best_effort(
                    part_path,
                    &published,
                    "copied",
                    allowed_roots,
                    expected_source_identity,
                );
                return Ok(published);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists || final_path.exists() => {
                continue;
            }
            Err(e) if no_replace_publish_unavailable(&e) => {
                tracing::info!(
                    "{} cannot take a rename that refuses to replace ({e}); copying the \
                     finished file straight to its name instead",
                    final_path.parent().unwrap_or(&final_path).display()
                );
                copy.discard(allowed_roots);
                staged = None;
                copy_in_place = true;
                suffix -= 1;
            }
            Err(e) => {
                copy.discard(allowed_roots);
                return Err(e.into());
            }
        }
    }
    if let Some(copy) = staged {
        copy.discard(allowed_roots);
    }
    anyhow::bail!(
        "Could not allocate a unique completed filename for {}",
        target.display()
    )
}

/// Prefix and suffix of the name a finished file is copied under before it is
/// published: `.ember-copy-<16 hex>.<part stem>.tmp`. The `.tmp` keeps the
/// indexer and the folder watcher off it
/// (`sharing::indexer::is_excluded_share_file_name`), the part stem names the
/// `.part` it was copied from, and the startup cleanup
/// ([`settle_stale_completion_copies`]) only ever touches names of this shape.
const COMPLETION_COPY_PREFIX: &str = ".ember-copy-";
const COMPLETION_COPY_SUFFIX: &str = ".tmp";

/// A `.part` stem a completion copy's name can carry: a download's UUID, or a
/// chat or room transfer's `ember-attach-<hex>` / `ember-xfer-<hex>`.
fn is_copy_name_stem(stem: &str) -> bool {
    (1..=64).contains(&stem.len())
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn completion_copy_name(part_path: &std::path::Path) -> String {
    let stem = part_path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".part").or_else(|| parse_completion_copy_name(name)))
        .filter(|stem| is_copy_name_stem(stem))
        .unwrap_or("unknown");
    format!(
        "{COMPLETION_COPY_PREFIX}{:016x}.{stem}{COMPLETION_COPY_SUFFIX}",
        rand::random::<u64>()
    )
}

/// The `.part` stem a completion copy's name carries, or `None` for any
/// other name.
fn parse_completion_copy_name(name: &str) -> Option<&str> {
    let (hex, stem) = name
        .strip_prefix(COMPLETION_COPY_PREFIX)?
        .strip_suffix(COMPLETION_COPY_SUFFIX)?
        .split_once('.')?;
    (hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()) && is_copy_name_stem(stem))
        .then_some(stem)
}

/// What a finished download's file has to be: its name, ed2k hash (hex)
/// and size. Startup recovers a completion copy only when it matches.
pub(crate) struct ExpectedFinishedFile {
    pub name: String,
    pub ed2k_hash: String,
    pub size: u64,
}

/// Whether a failed no-replace publication is the filesystem or platform not
/// offering one (FUSE, NFS, exFAT and SMB volumes, other Unixes), rather than
/// something an exclusive create would also run into. A scanner or indexer
/// holding the fresh copy ([`held_by_another_process`]) is not: copying the
/// file in place under its real name could leave it truncated there.
fn no_replace_publish_unavailable(error: &std::io::Error) -> bool {
    if matches!(
        error.kind(),
        std::io::ErrorKind::Unsupported
            | std::io::ErrorKind::CrossesDevices
            | std::io::ErrorKind::InvalidInput
    ) {
        return true;
    }
    #[cfg(unix)]
    {
        return error.raw_os_error().is_some_and(|code| {
            [
                libc::EINVAL,
                libc::ENOTSUP,
                libc::EOPNOTSUPP,
                libc::ENOSYS,
                libc::EXDEV,
                libc::EPERM,
            ]
            .contains(&code)
        });
    }
    #[cfg(windows)]
    {
        // ERROR_INVALID_FUNCTION, ERROR_NOT_SAME_DEVICE, ERROR_NOT_SUPPORTED,
        // ERROR_INVALID_PARAMETER.
        return matches!(
            error.raw_os_error(),
            Some(1) | Some(17) | Some(50) | Some(87)
        );
    }
    #[allow(unreachable_code)]
    false
}

/// Whether a rename failed because another process has the file open: on
/// Windows a virus scanner or the indexer opening a fresh file without
/// delete sharing, which lets go within moments.
fn held_by_another_process(error: &std::io::Error) -> bool {
    // ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION.
    cfg!(windows) && matches!(error.raw_os_error(), Some(5) | Some(32) | Some(33))
}

/// The waits between renames refused by [`held_by_another_process`].
const HELD_RENAME_BACKOFF_MS: [u64; 5] = [50, 100, 200, 400, 800];

/// Completion copies this run created, by file name. The startup cleanup
/// leaves them to the completion making them, whatever their dates say.
fn copies_of_this_run() -> &'static parking_lot::Mutex<std::collections::HashSet<String>> {
    static COPIES: std::sync::OnceLock<parking_lot::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    COPIES.get_or_init(Default::default)
}

/// Make a published name durable before the `.part` it was copied from, on
/// another volume, is removed: a power cut must not keep the removal and
/// lose the name. Unix syncs the directory; on Windows flushing the file
/// commits its metadata.
fn sync_published(path: &std::path::Path, allowed_roots: &[String]) {
    #[cfg(unix)]
    let synced = {
        let _ = allowed_roots;
        path.parent().map_or(Ok(()), |parent| {
            std::fs::File::open(parent).and_then(|dir| dir.sync_all())
        })
    };
    #[cfg(not(unix))]
    let synced = if allowed_roots.is_empty() {
        Ok(())
    } else {
        crate::security::filesystem::open_existing_approved(path, allowed_roots, true)
            .and_then(|(_, file)| file.sync_all())
    };
    if let Err(e) = synced {
        tracing::debug!("Could not sync the publication of {}: {e}", path.display());
    }
}

#[cfg(test)]
thread_local! {
    /// Makes [`CompletionCopy::publish`] fail as a volume without either.
    static NO_REPLACE_PUBLISH_UNSUPPORTED: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    /// Makes this many renames in [`CompletionCopy::publish`] fail as a
    /// scanner holding the copy would; `u32::MAX` holds it for good, against
    /// the hard link too.
    static COMPLETION_COPY_HELD: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    /// Makes [`CompletionCopy::publish`]'s hard link fail as on a volume
    /// without hard links.
    static HARD_LINKS_UNSUPPORTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A finished file copied in full, flushed and synced under a temporary name
/// next to where it is published.
struct CompletionCopy {
    path: std::path::PathBuf,
    identity: crate::security::filesystem::ObjectIdentity,
    len: u64,
    /// The `.part` it was copied from, while that is still there.
    source: Option<std::path::PathBuf>,
}

impl CompletionCopy {
    /// Rename the copy to `final_path`, which must not exist yet. A rename
    /// refused because another process holds the copy is tried again for a
    /// moment, then by hard link, and otherwise fails, keeping the copy's
    /// source.
    fn publish(
        &self,
        final_path: &std::path::Path,
        allowed_roots: &[String],
    ) -> std::io::Result<std::path::PathBuf> {
        if allowed_roots.is_empty() {
            std::fs::hard_link(&self.path, final_path)?;
            let _ = std::fs::remove_file(&self.path);
            return Ok(final_path.to_path_buf());
        }
        #[cfg(test)]
        if NO_REPLACE_PUBLISH_UNSUPPORTED.with(std::cell::Cell::get) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "no rename that refuses to replace, and no hard links",
            ));
        }
        let mut backoff = HELD_RENAME_BACKOFF_MS.iter();
        let error = loop {
            match self.rename_no_replace(final_path, allowed_roots) {
                Err(e) if held_by_another_process(&e) => match backoff.next() {
                    Some(ms) => std::thread::sleep(std::time::Duration::from_millis(*ms)),
                    None => break e,
                },
                Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => break e,
                published => return published,
            }
        };
        if self.renamed_to(final_path) {
            tracing::warn!(
                "Published {} although the rename could not be confirmed: {error}",
                final_path.display()
            );
            return Ok(final_path.to_path_buf());
        }
        if final_path.exists() {
            return Err(error);
        }
        // A scanner holding the fresh copy open without delete sharing
        // blocks a rename on Windows, but not a hard link. A volume without
        // hard links (exFAT, FAT32, some shares) is answered like one without
        // a no-replace rename: the caller copies the file straight to a free
        // name, as before the temporary copy existed.
        match self.hard_link_to(final_path, allowed_roots) {
            Ok(linked) => {
                self.discard(allowed_roots);
                Ok(linked)
            }
            Err(link_error)
                if hard_link_fallback_allowed(&link_error)
                    && !held_by_another_process(&link_error) =>
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!("{error}; no hard links here either ({link_error})"),
                ))
            }
            Err(_) => Err(error),
        }
    }

    fn hard_link_to(
        &self,
        final_path: &std::path::Path,
        allowed_roots: &[String],
    ) -> std::io::Result<std::path::PathBuf> {
        #[cfg(test)]
        if HARD_LINKS_UNSUPPORTED.with(std::cell::Cell::get) {
            return Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
        }
        #[cfg(test)]
        if COMPLETION_COPY_HELD.with(std::cell::Cell::get) == u32::MAX {
            return Err(std::io::Error::from_raw_os_error(32));
        }
        crate::security::filesystem::hard_link_approved(
            &self.path,
            final_path,
            allowed_roots,
            &self.identity,
        )
    }

    fn rename_no_replace(
        &self,
        final_path: &std::path::Path,
        allowed_roots: &[String],
    ) -> std::io::Result<std::path::PathBuf> {
        #[cfg(test)]
        if COMPLETION_COPY_HELD.with(|held| {
            let left = held.get();
            if left > 0 && left != u32::MAX {
                held.set(left - 1);
            }
            left > 0
        }) {
            return Err(std::io::Error::from_raw_os_error(32));
        }
        crate::security::filesystem::rename_approved_no_replace(
            &self.path,
            final_path,
            allowed_roots,
            &self.identity,
        )
    }

    /// Whether a rename that reported failure took place anyway: the copy's
    /// name is gone and `final_path` is the same file — its volume and file
    /// ID, or device and inode — or, on a filesystem without stable inode
    /// numbers, has exactly the source's bytes.
    fn renamed_to(&self, final_path: &std::path::Path) -> bool {
        let copy_gone = matches!(
            std::fs::symlink_metadata(&self.path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound
        );
        if !copy_gone
            || !std::fs::symlink_metadata(final_path)
                .is_ok_and(|metadata| metadata.is_file() && metadata.len() == self.len)
        {
            return false;
        }
        crate::security::filesystem::object_identity(final_path)
            .is_ok_and(|identity| identity == self.identity)
            || self
                .source
                .as_deref()
                .is_some_and(|source| same_contents(source, final_path))
    }

    /// Remove the copy, or have it removed once whatever holds it lets go.
    fn discard(&self, allowed_roots: &[String]) {
        let removed = if allowed_roots.is_empty() {
            std::fs::remove_file(&self.path)
        } else {
            crate::security::filesystem::remove_approved_file_if_identity(
                &self.path,
                allowed_roots,
                &self.identity,
            )
        };
        match removed {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(
                    "Could not remove the completion copy {}: {e}. Removing it later.",
                    self.path.display()
                );
                crate::storage::deferred_removals::defer(&self.path, allowed_roots);
            }
        }
    }
}

/// Whether two files have the same bytes. Blocking.
fn same_contents(a: &std::path::Path, b: &std::path::Path) -> bool {
    use std::io::Read;
    let (Ok(mut a), Ok(mut b)) = (std::fs::File::open(a), std::fs::File::open(b)) else {
        return false;
    };
    let (mut left, mut right) = (vec![0u8; 1 << 16], vec![0u8; 1 << 16]);
    loop {
        let Ok(read) = a.read(&mut left) else {
            return false;
        };
        if read == 0 {
            return b.read(&mut right).is_ok_and(|more| more == 0);
        }
        if b.read_exact(&mut right[..read]).is_err() || left[..read] != right[..read] {
            return false;
        }
    }
}

/// Fail before copying when the volume `target` is on has no room for the
/// whole file, with the error that marks the download Insufficient and keeps
/// its `.part`. A failed query lets the copy try: running out of space while
/// writing fails the same way.
fn ensure_room_for_completion_copy(
    part_path: &std::path::Path,
    target_dir: &std::path::Path,
) -> anyhow::Result<()> {
    let Ok(needed) = std::fs::metadata(part_path).map(|metadata| metadata.len()) else {
        return Ok(());
    };
    room_for_completion_copy(needed, fs2::available_space(target_dir).ok(), target_dir)
}

fn room_for_completion_copy(
    needed: u64,
    available: Option<u64>,
    target_dir: &std::path::Path,
) -> anyhow::Result<()> {
    let wanted = needed.saturating_add(crate::network::downloads::DISK_SPACE_BUFFER);
    match available {
        Some(available) if available < wanted => anyhow::bail!(
            "stage:insufficient_disk: the finished file needs {needed} bytes and {} has {available} free",
            target_dir.display()
        ),
        _ => Ok(()),
    }
}

fn stage_completion_copy(
    part_path: &std::path::Path,
    target: &std::path::Path,
    allowed_roots: &[String],
    expected_source_identity: Option<&crate::security::filesystem::ObjectIdentity>,
) -> anyhow::Result<CompletionCopy> {
    let target_dir = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("completed file target has no folder"))?;
    ensure_room_for_completion_copy(part_path, target_dir)?;
    let name = completion_copy_name(part_path);
    copies_of_this_run().lock().insert(name.clone());
    let path = target_dir.join(name);
    let (identity, len) =
        copy_exclusive(part_path, &path, allowed_roots, expected_source_identity)?;
    Ok(CompletionCopy {
        path,
        identity,
        len,
        source: Some(part_path.to_path_buf()),
    })
}

/// The folders of a download folder that finished files are published into:
/// eD2K downloads, chat attachments and room transfers.
fn finished_file_dirs() -> [&'static str; 3] {
    [
        "Downloads",
        crate::network::chat_attach::CHAT_FILES_DIR,
        crate::network::ember::xfer::CHANNEL_FILES_DIR,
    ]
}

/// Whose a completion copy is, by the `.part` stem its name carries.
pub(crate) enum CopyOwner {
    /// An unfinished download. Resuming it settles its copies first
    /// (`network::event_loop::resume_downloads`), before it can start.
    Unfinished,
    /// A finished download, and what its file is.
    Finished(ExpectedFinishedFile),
    /// A chat or room transfer, or a download no longer listed.
    Unknown,
}

/// `<stem>.part` in some download folder's `Temp`: `Ok(None)` when none
/// holds it, `Err(())` when a folder that cannot be looked at might.
fn completion_source(
    download_roots: &[String],
    stem: &str,
) -> Result<Option<std::fs::Metadata>, ()> {
    let mut unknown = false;
    for root in download_roots {
        let part = std::path::Path::new(root)
            .join("Temp")
            .join(format!("{stem}.part"));
        match std::fs::symlink_metadata(part) {
            Ok(metadata) => return Ok(Some(metadata)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => unknown = true,
        }
    }
    if unknown {
        Err(())
    } else {
        Ok(None)
    }
}

/// Whether `part` was there before `copy` was written: created — or, where
/// that is not known, last written — no later than the copy's last write.
/// Dates that cannot be read say it was not.
pub(crate) fn made_before(part: &std::fs::Metadata, copy: &std::fs::Metadata) -> bool {
    match (part.created().or_else(|_| part.modified()), copy.modified()) {
        (Ok(part), Ok(copy)) => part <= copy,
        _ => false,
    }
}

/// Settle the completion copies a crash, a kill or a power cut left, in an
/// earlier run, where finished files are published ([`finished_file_dirs`])
/// in the download folder `root`, one of `download_roots`. `owner` says
/// whose each is:
///
/// - an unfinished download's is left to resuming it;
/// - a finished download's is removed when the file it was published as is
///   there — that very file, or one with its hash — and otherwise, being
///   the only copy, published once when it is the file and removed when it
///   is not;
/// - any other is removed while a `.part` it was made from remains, and
///   kept when none does, since it can be the only complete copy.
///
/// A copy this run made, or modified at or after `cutoff`, may belong to a
/// completion running now and is left alone. Blocking.
pub(crate) fn settle_stale_completion_copies(
    root: &str,
    download_roots: &[String],
    cutoff: std::time::SystemTime,
    owner: &dyn Fn(&str) -> CopyOwner,
) {
    let allowed = [root.to_string()];
    // The category folders inside Downloads as well: a completion copy is
    // made beside where its file is published.
    let category_dirs = crate::storage::category_folders::finished_download_dirs(
        std::path::Path::new(root),
    )
    .into_iter()
    .skip(1);
    let dirs = finished_file_dirs()
        .into_iter()
        .map(|dir| std::path::Path::new(root).join(dir))
        .chain(category_dirs);
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            let Some(stem) = parse_completion_copy_name(name) else {
                continue;
            };
            if copies_of_this_run().lock().contains(name) {
                continue;
            }
            let Ok(copy) = entry.metadata() else {
                continue;
            };
            if !copy.modified().is_ok_and(|modified| modified < cutoff) {
                continue;
            }
            let path = entry.path();
            match owner(stem) {
                CopyOwner::Unfinished => {}
                CopyOwner::Finished(expected) => settle_finished_copy(
                    &path,
                    root,
                    download_roots.first().map_or(root, String::as_str),
                    &expected,
                ),
                CopyOwner::Unknown => match completion_source(download_roots, stem) {
                    Ok(Some(part)) if made_before(&part, &copy) => {
                        remove_interrupted_copy(&path, &allowed)
                    }
                    Ok(Some(_)) => tracing::warn!(
                        "Keeping completion copy {}: the .part it names is newer than it",
                        path.display()
                    ),
                    Ok(None) => tracing::warn!(
                        "Keeping completion copy {}: its source is gone and what it should be \
                         is unknown",
                        path.display()
                    ),
                    Err(()) => {}
                },
            }
        }
    }
}

fn remove_interrupted_copy(path: &std::path::Path, allowed: &[String]) {
    match crate::security::filesystem::remove_approved_file(path, allowed) {
        Ok(()) => tracing::info!("Removed interrupted completion copy {}", path.display()),
        Err(e) => tracing::warn!(
            "Could not remove interrupted completion copy {}: {e}",
            path.display()
        ),
    }
}

fn settle_finished_copy(
    path: &std::path::Path,
    root: &str,
    download_root: &str,
    expected: &ExpectedFinishedFile,
) {
    let is_the_file = |file: &mut std::fs::File| -> anyhow::Result<bool> {
        Ok(super::hash::ed2k_hash_open_file(file)?.eq_ignore_ascii_case(&expected.ed2k_hash))
    };
    match recover_completion_copy(
        path,
        root,
        download_root,
        &expected.name,
        expected.size,
        &is_the_file,
    ) {
        Ok(CopyRecovery::Published(published)) => tracing::warn!(
            "Recovered a finished file whose publication was interrupted as {}",
            published.display()
        ),
        Ok(CopyRecovery::AlreadyPublished(_)) => tracing::info!(
            "Removed interrupted completion copy {}: the finished file is there",
            path.display()
        ),
        Ok(CopyRecovery::NotTheFile) => tracing::info!(
            "Removed completion copy {}, which is not the finished file",
            path.display()
        ),
        Err(e) => tracing::warn!("Keeping completion copy {}: {e}", path.display()),
    }
}

/// What [`recover_completion_copy`] did with a copy.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CopyRecovery {
    Published(std::path::PathBuf),
    /// The file was published before, as this name: the copy is removed.
    AlreadyPublished(std::path::PathBuf),
    NotTheFile,
}

/// `name` in `dir` and every name completion gives it there when that one
/// is taken (`name (1)`, `name (2)`, …), lowest first. Blocking.
pub(crate) fn published_names(dir: &std::path::Path, name: &str) -> Vec<std::path::PathBuf> {
    let base = dir.join(name);
    let mut variants: Vec<(u32, std::path::PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let file_name = entry.file_name();
            let text = file_name.to_str()?;
            let open = text.rfind(" (")?;
            let rest = &text[open + 2..];
            let suffix: u32 = rest[..rest.find(')')?].parse().ok()?;
            (suffix > 0
                && dedup_candidate(&base, suffix).file_name() == Some(file_name.as_os_str()))
            .then(|| (suffix, entry.path()))
        })
        .collect();
    variants.sort();
    std::iter::once(base)
        .chain(variants.into_iter().map(|(_, path)| path))
        .collect()
}

/// Whether `published`, in the download folder `root`, is the finished file:
/// the copy itself (`identity`), or `size` bytes `is_the_file` accepts.
/// Blocking.
fn is_published_copy(
    published: &std::path::Path,
    root: &str,
    identity: &crate::security::filesystem::ObjectIdentity,
    size: u64,
    is_the_file: &dyn Fn(&mut std::fs::File) -> anyhow::Result<bool>,
) -> bool {
    let Ok((_, mut file)) = crate::security::filesystem::open_existing_approved(
        published,
        &[root.to_string()],
        false,
    ) else {
        return false;
    };
    crate::security::filesystem::opened_file_identity(&file).is_ok_and(|id| id == *identity)
        || (file.metadata().is_ok_and(|metadata| metadata.len() == size)
            && is_the_file(&mut file).unwrap_or(false))
}

/// The completion copies an earlier run left in `dir`, each with the
/// `.part` stem its name carries. Blocking.
pub(crate) fn earlier_completion_copies(
    dir: &std::path::Path,
) -> Vec<(String, std::path::PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let this_run = copies_of_this_run().lock().clone();
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let stem = parse_completion_copy_name(&name)?.to_string();
            (!this_run.contains(&name)).then(|| (stem, entry.path()))
        })
        .collect()
}

/// Publish the completion copy at `path`, in the download folder `root`,
/// when it is `size` bytes that `is_the_file` accepts, and remove it when it
/// is not. It is published in `download_root`, the current download folder,
/// under the first free name from `file_name` in its `Downloads`, the way a
/// completion publishes; but when the file was published already — the copy
/// is linked as, or `is_the_file` accepts, `file_name` or a `name (N)` of
/// it beside the copy or there — the copy is only removed. An error keeps
/// it. Blocking.
pub(crate) fn recover_completion_copy(
    path: &std::path::Path,
    root: &str,
    download_root: &str,
    file_name: &str,
    size: u64,
    is_the_file: &dyn Fn(&mut std::fs::File) -> anyhow::Result<bool>,
) -> anyhow::Result<CopyRecovery> {
    let allowed = [root.to_string()];
    let (_, mut file) = crate::security::filesystem::open_existing_approved(path, &allowed, false)?;
    let identity = crate::security::filesystem::opened_file_identity(&file)?;
    let len = file.metadata()?.len();
    let matches = len == size && is_the_file(&mut file)?;
    drop(file);
    let copy = CompletionCopy {
        path: path.to_path_buf(),
        identity,
        len,
        source: None,
    };
    if !matches {
        copy.discard(&allowed);
        return Ok(CopyRecovery::NotTheFile);
    }
    let name = crate::security::sanitize_filename(file_name);
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("completion copy has no folder"))?;
    let elsewhere = !crate::storage::part_folders::same_folder(root, download_root);
    // Its category's folder, when the download it names still has one; a
    // finished download's no longer does, and lands in Downloads.
    let subdir = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(parse_completion_copy_name)
        .map(crate::storage::category_folders::completion_subdir)
        .unwrap_or_default();
    let downloads = std::path::Path::new(download_root).join("Downloads");
    let category_dir = subdir.iter().fold(downloads.clone(), |dir, segment| dir.join(segment));
    let places = std::iter::once((dir.to_path_buf(), root)).chain(
        elsewhere
            .then(|| {
                std::iter::once((downloads.clone(), download_root))
                    .chain((!subdir.is_empty()).then(|| (category_dir.clone(), download_root)))
            })
            .into_iter()
            .flatten(),
    );
    for (dir, dir_root) in places {
        for published in published_names(&dir, &name) {
            if is_published_copy(&published, dir_root, &copy.identity, size, is_the_file) {
                copy.discard(&allowed);
                return Ok(CopyRecovery::AlreadyPublished(published));
            }
        }
    }
    if elsewhere {
        let published = move_part_to_completed(
            path,
            std::path::Path::new(root),
            std::path::Path::new(download_root),
            &subdir,
            &name,
            &copy.identity,
        )?;
        return Ok(CopyRecovery::Published(published));
    }
    let target = dir.join(&name);
    for suffix in 0..=10_000u32 {
        let final_path = dedup_candidate(&target, suffix);
        match copy.publish(&final_path, &allowed) {
            Ok(published) => {
                sync_published(&published, &allowed);
                return Ok(CopyRecovery::Published(published));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists || final_path.exists() => {}
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!("no free name for {}", target.display())
}

/// Approved-root wrapper used by production completion/recovery paths. The
/// compatibility helper above remains pure for eMule move semantics and unit
/// tests; this wrapper binds both source and destination to the unchanged
/// configured download root immediately before the name claim.
pub(crate) fn move_part_to_final_approved(
    part_path: &std::path::Path,
    target: &std::path::Path,
    download_root: &std::path::Path,
    expected_source_identity: &crate::security::filesystem::ObjectIdentity,
) -> anyhow::Result<std::path::PathBuf> {
    move_part_between_roots_approved(
        part_path,
        download_root,
        target,
        download_root,
        expected_source_identity,
    )
}

/// [`move_part_to_final_approved`] for a `.part` left in an earlier download
/// folder: each end is pinned to its own root, and the move is a copy when
/// the two are on different volumes.
pub(crate) fn move_part_between_roots_approved(
    part_path: &std::path::Path,
    part_root: &std::path::Path,
    target: &std::path::Path,
    target_root: &std::path::Path,
    expected_source_identity: &crate::security::filesystem::ObjectIdentity,
) -> anyhow::Result<std::path::PathBuf> {
    let part_allowed = vec![part_root.to_string_lossy().into_owned()];
    let target_allowed = vec![target_root.to_string_lossy().into_owned()];
    let verified_part =
        crate::security::filesystem::verify_existing_path(part_path, &part_allowed)?;
    let verified_target =
        crate::security::filesystem::verify_output_path(target, &target_allowed)?;
    let mut allowed = part_allowed;
    if target_allowed != allowed {
        allowed.extend(target_allowed);
    }
    move_part_to_final_with_roots(
        &verified_part,
        &verified_target,
        &allowed,
        Some(expected_source_identity),
        true,
    )
}

fn hard_link_fallback_allowed(error: &std::io::Error) -> bool {
    if matches!(
        error.kind(),
        std::io::ErrorKind::CrossesDevices | std::io::ErrorKind::Unsupported
    ) {
        return true;
    }
    #[cfg(unix)]
    {
        return matches!(
            error.raw_os_error(),
            Some(libc::EXDEV)
                | Some(libc::EOPNOTSUPP)
                | Some(libc::ENOSYS)
                | Some(libc::EPERM)
                | Some(libc::EMLINK)
        );
    }
    #[cfg(windows)]
    {
        // ERROR_NOT_SAME_DEVICE, ERROR_INVALID_FUNCTION,
        // ERROR_ACCESS_DENIED, ERROR_NOT_SUPPORTED, ERROR_INVALID_PARAMETER,
        // ERROR_TOO_MANY_LINKS. Native handle-relative hard linking may be
        // unavailable on a filesystem even when exclusive create+copy works.
        return matches!(
            error.raw_os_error(),
            Some(17) | Some(1) | Some(5) | Some(50) | Some(87) | Some(1142)
        );
    }
    #[allow(unreachable_code)]
    false
}

fn dedup_candidate(base: &std::path::Path, suffix: u32) -> std::path::PathBuf {
    if suffix == 0 {
        return base.to_path_buf();
    }
    let stem = base.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = base.extension().and_then(|s| s.to_str());
    let parent = base.parent().unwrap_or(base);
    let tail = match ext {
        Some(ext) => format!(" ({suffix}).{ext}"),
        None => format!(" ({suffix})"),
    };
    // `sanitize_filename` lets a name reach the 255-byte limit, so the
    // suffix has to come out of the stem: past it the link fails with an
    // error that is not `AlreadyExists`, and completion failed and re-verified
    // the whole file on every retry. 255 UTF-8 bytes is never more than
    // NTFS's 255 UTF-16 units.
    const MAX_NAME_BYTES: usize = 255;
    let mut end = stem.len().min(MAX_NAME_BYTES.saturating_sub(tail.len()));
    while end > 0 && !stem.is_char_boundary(end) {
        end -= 1;
    }
    // Windows drops trailing dots and spaces, as `sanitize_filename` notes.
    let stem = stem[..end].trim_end_matches(['.', ' ']);
    let stem = if stem.is_empty() { "file" } else { stem };
    parent.join(format!("{stem}{tail}"))
}

/// Copy `source_path` to the new file `destination_path`, synced and the same
/// length as the source, returning the copy's identity and length.
fn copy_exclusive(
    source_path: &std::path::Path,
    destination_path: &std::path::Path,
    allowed_roots: &[String],
    expected_source_identity: Option<&crate::security::filesystem::ObjectIdentity>,
) -> std::io::Result<(crate::security::filesystem::ObjectIdentity, u64)> {
    use std::io::Write;

    let mut source = if allowed_roots.is_empty() {
        std::fs::File::open(source_path)?
    } else {
        crate::security::filesystem::open_existing_approved(source_path, allowed_roots, false)?.1
    };
    if let Some(expected) = expected_source_identity {
        if &crate::security::filesystem::opened_file_identity(&source)? != expected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "verified part file changed before completion copy",
            ));
        }
    }
    let mut destination = if allowed_roots.is_empty() {
        crate::security::filesystem::create_new_nofollow(destination_path)?
    } else {
        let (_verified, file) = crate::security::filesystem::create_new_verified_output(
            destination_path,
            allowed_roots,
        )?;
        file
    };
    let destination_identity = crate::security::filesystem::opened_file_identity(&destination)?;
    let source_len = source.metadata()?.len();
    if let Err(e) = std::io::copy(&mut source, &mut destination)
        .and_then(|copied| {
            if copied == source_len {
                Ok(())
            } else {
                Err(std::io::Error::other(format!(
                    "completion copy wrote {copied} of {source_len} bytes"
                )))
            }
        })
        .and_then(|_| destination.flush())
        .and_then(|_| destination.sync_all())
    {
        drop(destination);
        if allowed_roots.is_empty() {
            let _ = std::fs::remove_file(destination_path);
        } else {
            let _ = crate::security::filesystem::remove_approved_file_if_identity(
                destination_path,
                allowed_roots,
                &destination_identity,
            );
        }
        return Err(e);
    }
    if let Ok(metadata) = source.metadata() {
        let _ = destination.set_permissions(metadata.permissions());
    }
    if !allowed_roots.is_empty() {
        let path_identity = crate::security::filesystem::open_existing_approved(
            destination_path,
            allowed_roots,
            false,
        )
        .and_then(|(_, file)| crate::security::filesystem::opened_file_identity(&file));
        if !matches!(path_identity, Ok(ref identity) if identity == &destination_identity) {
            let _ = crate::security::filesystem::remove_approved_file_if_identity(
                destination_path,
                allowed_roots,
                &destination_identity,
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "completed copy destination changed identity before publication",
            ));
        }
    }
    Ok((destination_identity, source_len))
}

fn remove_completed_part_best_effort(
    part_path: &std::path::Path,
    final_path: &std::path::Path,
    method: &str,
    allowed_roots: &[String],
    expected_source_identity: Option<&crate::security::filesystem::ObjectIdentity>,
) {
    // The download is complete once the final path exists. If an upload still
    // has the .part open on Windows, leave the harmless orphan for the startup
    // sweep instead of marking valid downloaded bytes as failed.
    let removed = if allowed_roots.is_empty() {
        std::fs::remove_file(part_path)
    } else if let Some(expected) = expected_source_identity {
        crate::security::filesystem::remove_approved_file_if_identity(
            part_path,
            allowed_roots,
            expected,
        )
    } else {
        crate::security::filesystem::remove_approved_file(part_path, allowed_roots)
    };
    if let Err(e) = removed {
        tracing::warn!(
            "Completed-file move: {method} {} -> {} but failed to remove the source .part: {}. \
             Orphan will be cleaned by the next startup sweep.",
            part_path.display(),
            final_path.display(),
            e,
        );
    }
}

/// Verify that peer-supplied part MD4s combine to the ed2k file hash (eMule `CFileIdentifier` / hashset handling).
///
/// The on-wire hashset is **one MD4 per full or partial part** (same chunking as [`super::hash::ed2k_hash_file`](super::hash::ed2k_hash_file)).
/// It does **not** include the trailing `MD4("")` block; when `file_size > 0` and `file_size % PARTSIZE == 0`,
/// that sentinel is appended here before the final MD4, matching eMule and our `ed2k_hash_file` rules.
///
/// Special case: `file_size < PARTSIZE` with a single hash — the file hash is `MD4(data)` (not `MD4(MD4(data)‖…)`),
/// so we compare the lone part hash to the file hash directly.
pub(crate) fn verify_hashset(
    file_hash: &[u8; 16],
    part_hashes: &[[u8; 16]],
    file_size: u64,
) -> bool {
    use md4::{Digest, Md4};
    if part_hashes.is_empty() {
        return false;
    }
    // One MD4 per ed2k part (`ceil(file_size / PARTSIZE)`), optionally followed
    // by the trailing `MD4("")` sentinel that eMule stores for a file whose size
    // is an exact multiple of PARTSIZE.
    //
    // Accepting that second form is the interop-correct choice and matches what
    // this codebase already does on disk: `part_tracker::load_emule_format`
    // takes both counts and truncates the sentinel, with a test noting that
    // "eMule stores one extra MD4("") for a file that is an exact multiple of
    // PARTSIZE". Rejecting it here meant a peer that sent that form had its
    // hashset dropped whole — `part_hashes` stayed empty, so per-part MD4
    // verification was silently off for the file's entire life, AICH narrowing
    // had no hashes to work from, `part_verified` was never set (so we
    // advertised zero serveable parts of it), and one bad block surfaced only at
    // the final whole-file hash, which then reopened every part.
    //
    // Permissiveness on the count cannot weaken the check: the recombination
    // below still has to reproduce the ed2k file hash exactly, and that is the
    // real gate. The anti-padding bound the strict count was protecting also
    // survives — `n + 1` is still `O(n)`.
    let expected_count = super::messages::ed2k_part_count_for_size(file_size);
    let part_hashes: &[[u8; 16]] = if part_hashes.len() == expected_count {
        part_hashes
    } else if part_hashes.len() == expected_count + 1
        && file_size > 0
        && file_size.is_multiple_of(super::hash::PARTSIZE)
    {
        &part_hashes[..expected_count]
    } else {
        return false;
    };
    if part_hashes.len() == 1 && file_size < super::hash::PARTSIZE {
        return part_hashes[0] == *file_hash;
    }
    let mut combined = Vec::with_capacity((part_hashes.len() + 1) * 16);
    for h in part_hashes {
        combined.extend_from_slice(h);
    }
    if file_size > 0 && file_size.is_multiple_of(super::hash::PARTSIZE) {
        let empty_hash: [u8; 16] = Md4::digest([]).into();
        combined.extend_from_slice(&empty_hash);
    }
    let computed: [u8; 16] = Md4::digest(&combined).into();
    computed == *file_hash
}

/// Pin an AICH master from a HashSet2 whose MD4 hashset already verified.
///
/// Whole-file ed2k still gates completion, but a first-wins pin poisons
/// recovery: later AICH answers are ignored if they disagree with the pin.
/// Catalog `expected` is enough on its own. Otherwise a single source is
/// not: two distinct peer addresses must advertise the same root. Keyed on
/// the address rather than the worker's index, which is new each time a peer
/// is re-injected or calls back, so one client voted twice by reconnecting
/// and pinned a root nothing could replace. When `expected` is already known,
/// a conflicting HashSet2 root is ignored even if several sources repeat it.
pub(super) fn consider_hashset2_aich_pin(
    pinned: &mut Option<[u8; 20]>,
    expected: Option<[u8; 20]>,
    votes: Option<&mut HashMap<[u8; 20], HashSet<String>>>,
    voter: &str,
    root: [u8; 20],
) {
    if pinned.is_some() {
        return;
    }
    if expected == Some(root) {
        *pinned = Some(root);
        return;
    }
    if expected.is_some() {
        return;
    }
    let Some(votes) = votes else {
        return;
    };
    votes.entry(root).or_default().insert(voter.to_string());
    if votes.get(&root).map(|s| s.len()).unwrap_or(0) >= 2 {
        *pinned = Some(root);
    }
}

pub(crate) async fn maybe_send_secident_challenge<W: AsyncWriteExt + Unpin + ?Sized>(
    writer: &mut W,
    credit_manager: Option<&Arc<tokio::sync::RwLock<CreditManager>>>,
    peer_user_hash: [u8; 16],
    peer_addr: SocketAddr,
    peer_secident_level: u8,
) -> std::io::Result<Option<u32>> {
    let Some(cm) = credit_manager else {
        return Ok(None);
    };
    let peer_ip_u32 = match peer_addr.ip() {
        std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| u32::from_be_bytes(v4.octets()))
            .unwrap_or(0),
    };
    // Read the request state under a short-lived guard and drop it before the
    // socket write. Holding the `CreditManager` read guard across
    // `write_packet_async().await` would block every `credit_manager.write()`
    // caller (and, since tokio's RwLock makes new readers queue behind a
    // pending writer, later readers too) for as long as the peer's socket is
    // backpressured. `handle_secident_signature` already scopes its guard the
    // same way.
    let Some(state) = ({
        let cm = cm.read().await;
        cm.secident_request_state(&peer_user_hash, peer_ip_u32, peer_secident_level)
    }) else {
        debug!(
            "SecIdent: not challenging {peer_addr} ({}): peer level {peer_secident_level}, \
             no local key, or already verified at this address",
            crate::security::short_hash(&peer_user_hash)
        );
        return Ok(None);
    };
    let challenge = rand::RngCore::next_u32(&mut rand::rngs::OsRng).wrapping_add(1);
    let mut secident_payload = Vec::with_capacity(5);
    secident_payload.push(state);
    secident_payload.extend_from_slice(&challenge.to_le_bytes());
    write_packet_async(writer, OP_EMULEPROT, OP_SECIDENTSTATE, &secident_payload).await?;
    debug!(
        "SecIdent: challenged {peer_addr} ({}) with state {state} (peer level {peer_secident_level})",
        crate::security::short_hash(&peer_user_hash)
    );
    Ok(Some(challenge))
}

/// A peer's IPv4 as SecIdent v2 signs it: eMule's in-memory network-order
/// `dwIP`, which `PokeUInt32` writes back out as the octets in order
/// (`ClientCredits.cpp:440, :481-495`) — the same form as a HighID client ID,
/// not the big-endian value credit bookkeeping keys on.
fn secident_wire_ip(peer_addr: SocketAddr) -> u32 {
    match peer_addr.ip() {
        std::net::IpAddr::V4(v4) => u32::from_le_bytes(v4.octets()),
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| u32::from_le_bytes(v4.octets()))
            .unwrap_or(0),
    }
}

pub(crate) async fn respond_to_secident_challenge<W: AsyncWriteExt + Unpin + ?Sized>(
    writer: &mut W,
    credit_manager: Option<&Arc<tokio::sync::RwLock<CreditManager>>>,
    state: u8,
    challenge: u32,
    peer_addr: SocketAddr,
    peer_user_hash: [u8; 16],
    peer_secident_level: u8,
    our_client_id: u32,
) -> std::io::Result<()> {
    let Some(cm) = credit_manager else {
        return Ok(());
    };
    let (challenge_ip_kind, challenge_ip, add_trailer) = if (peer_secident_level & 1) != 0 {
        (None, 0u32, false)
    } else {
        // eMule: use REMOTECLIENT if we don't know our own public IP (LowID)
        if our_client_id == 0 || our_client_id < 0x0100_0000 {
            (
                Some(super::credits::CRYPT_CIP_REMOTECLIENT),
                secident_wire_ip(peer_addr),
                true,
            )
        } else {
            (
                Some(super::credits::CRYPT_CIP_LOCALCLIENT),
                our_client_id,
                true,
            )
        }
    };
    // Pull the public key and signature bytes out of the credit manager under a
    // short-lived read guard, then drop it BEFORE any socket write. Holding the
    // read guard across `write_packet_async().await` would stall all
    // `credit_manager.write()` callers (and later readers) for the duration of
    // a backpressured peer socket. Mirrors `handle_secident_signature`.
    let (pub_key, sig) = {
        let cm = cm.read().await;
        let pub_key = if state >= 2 {
            cm.our_public_key().to_vec()
        } else {
            Vec::new()
        };
        let sig = cm.create_signature_for_peer(
            &peer_user_hash,
            challenge,
            challenge_ip,
            challenge_ip_kind,
        );
        (pub_key, sig)
    };
    if state >= 2 && !pub_key.is_empty() {
        let mut key_pkt = Vec::with_capacity(1 + pub_key.len());
        key_pkt.push(pub_key.len() as u8);
        key_pkt.extend_from_slice(&pub_key);
        write_packet_async(writer, OP_EMULEPROT, OP_PUBLICKEY, &key_pkt).await?;
    }
    if !sig.is_empty() {
        let mut sig_pkt = Vec::with_capacity(2 + sig.len() + usize::from(add_trailer));
        sig_pkt.push(sig.len() as u8);
        sig_pkt.extend_from_slice(&sig);
        if add_trailer {
            sig_pkt.push(challenge_ip_kind.unwrap_or(super::credits::CRYPT_CIP_NONECLIENT));
        }
        write_packet_async(writer, OP_EMULEPROT, OP_SIGNATURE, &sig_pkt).await?;
        debug!(
            "SecIdent: answered {peer_addr} ({}) challenge state {state}: key sent={}, v{}",
            crate::security::short_hash(&peer_user_hash),
            state >= 2 && !pub_key.is_empty(),
            if add_trailer { 2 } else { 1 }
        );
    } else {
        debug!(
            "SecIdent: could not sign {peer_addr} ({}) challenge state {state}: \
             no key for the peer or no local key",
            crate::security::short_hash(&peer_user_hash)
        );
    }
    Ok(())
}

pub(crate) async fn handle_secident_signature(
    credit_manager: Option<&Arc<tokio::sync::RwLock<CreditManager>>>,
    peer_user_hash: [u8; 16],
    pending_secident_challenge: &mut Option<u32>,
    peer_addr: SocketAddr,
    peer_secident_level: u8,
    payload: &[u8],
    our_client_id: u32,
) {
    let Some(cm) = credit_manager else {
        return;
    };
    let peer = crate::security::short_hash(&peer_user_hash);
    let sig_len = payload[0] as usize;
    if sig_len == 0 || payload.len() < 1 + sig_len {
        debug!(
            "SecIdent: ignored malformed OP_SIGNATURE from {peer_addr} ({peer}): \
             {} bytes, declared signature length {sig_len}",
            payload.len()
        );
        return;
    }
    let Some(challenge) = pending_secident_challenge.take() else {
        debug!("SecIdent: ignored OP_SIGNATURE from {peer_addr} ({peer}) with no challenge of ours outstanding");
        return;
    };
    let peer_ip_u32 = match peer_addr.ip() {
        std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| u32::from_be_bytes(v4.octets()))
            .unwrap_or(0),
    };
    let sig_bytes = &payload[1..1 + sig_len];
    let challenge_kind = if payload.len() == 1 + sig_len {
        None
    } else if payload.len() == 2 + sig_len && (peer_secident_level & 2) != 0 {
        Some(payload[1 + sig_len])
    } else {
        debug!(
            "SecIdent: ignored OP_SIGNATURE from {peer_addr} ({peer}): {} bytes for a \
             {sig_len}-byte signature does not fit peer level {peer_secident_level}",
            payload.len()
        );
        return;
    };
    let verified = {
        let cm = cm.read().await;
        let local_ip = if our_client_id >= 0x0100_0000 {
            our_client_id
        } else {
            0
        };
        cm.verify_signature(
            &peer_user_hash,
            challenge,
            challenge_kind,
            secident_wire_ip(peer_addr),
            local_ip,
            sig_bytes,
        )
    };
    let mut cm = cm.write().await;
    if verified {
        debug!("SecIdent: verified {peer_addr} ({peer}), v{}", if challenge_kind.is_some() { 2 } else { 1 });
        cm.set_ident_state(peer_user_hash, IdentState::Verified);
        cm.check_identity_ip(peer_user_hash, peer_ip_u32);
    } else if cm
        .get_record(&peer_user_hash)
        .is_none_or(|record| record.ident_state == IdentState::Needed)
    {
        debug!("SecIdent: signature from {peer_addr} ({peer}) did not verify; marked Failed");
        // Only demote a record that was actually awaiting its first proof,
        // matching eMule (`ClientCredits.cpp:507`, which sets IS_IDFAILED only
        // from IS_IDNEEDED). Demoting unconditionally let anyone who knows a
        // peer's user_hash — it travels in the clear in every Hello — knock an
        // established peer out of `Verified` with one bogus signature, which
        // both strips their score multiplier and, before the anchor was made
        // durable, set them up to have their credits reset later.
        cm.set_ident_state(peer_user_hash, IdentState::Failed);
    } else {
        debug!(
            "SecIdent: signature from {peer_addr} ({peer}) did not verify; state left as {:?}",
            cm.get_record(&peer_user_hash).map(|record| record.ident_state)
        );
    }
}

/// Carried inside the `io::Error` of a packet read that was abandoned after
/// consuming part of a packet. The next read would start mid-frame (and, on an
/// obfuscated link, mid-keystream), so the connection must be dropped.
#[derive(Debug)]
pub(super) struct PacketStreamDesynced(String);

impl std::fmt::Display for PacketStreamDesynced {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; stream can no longer be framed", self.0)
    }
}

impl std::error::Error for PacketStreamDesynced {}

pub(super) fn packet_stream_desynced_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        PacketStreamDesynced("peer stalled mid-packet".to_string()),
    )
}

/// Re-tag an error raised after a packet's first byte was consumed. The kind
/// is kept so reset/EOF classification still sees it.
pub(super) fn desynced_io_error(cause: std::io::Error) -> std::io::Error {
    if cause
        .get_ref()
        .is_some_and(|inner| inner.is::<PacketStreamDesynced>())
    {
        return cause;
    }
    std::io::Error::new(cause.kind(), PacketStreamDesynced(cause.to_string()))
}

pub(super) fn is_packet_stream_desynced(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .and_then(|io| io.get_ref())
            .is_some_and(|inner| inner.is::<PacketStreamDesynced>())
    })
}

async fn write_packet_async<W: AsyncWriteExt + Unpin + ?Sized>(
    writer: &mut W,
    protocol: u8,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    writer.write_u8(protocol).await?;
    let pkt_len = u32::try_from(1 + payload.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "packet payload too large")
    })?;
    writer.write_u32_le(pkt_len).await?;
    writer.write_u8(opcode).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod packet_framing_tests {
    use super::*;

    #[test]
    fn retagging_keeps_the_kind_and_message() {
        let tagged = desynced_io_error(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "forcibly closed",
        ));
        assert_eq!(tagged.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(tagged.to_string().contains("forcibly closed"));
        let twice = desynced_io_error(tagged);
        assert_eq!(
            twice.to_string(),
            "forcibly closed; stream can no longer be framed"
        );
    }
}
