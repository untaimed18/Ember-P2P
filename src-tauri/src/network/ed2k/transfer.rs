use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use flate2::read::ZlibDecoder;
use flate2::{Decompress, FlushDecompress, Status};
use futures::FutureExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::bandwidth::limiter::BandwidthLimiter;
use crate::sharing::manager::TransferControl;
use crate::types::Ed2kDownloadLimits;

use super::comments::CommentManager;
use super::credits::{CreditManager, IdentState};
use super::messages::*;
use super::part_tracker::PartTracker;
use super::sources::SourceManager;

const READ_TIMEOUT_SECS: u64 = super::dead_sources::DOWNLOADTIMEOUT_SECS as u64;

/// Maximum accepted on-wire ed2k packet length for a download connection.
/// The largest legitimate single packet is a file's hashset (16 bytes/part:
/// ~1.7 MiB even for a 1 TB file) or one ~180 KiB block, so 2 MiB is a wide
/// safety margin while keeping a malicious/buggy source from making us buffer
/// up to 10 MiB per connection (the prior cap) — multiplied across multi-source
/// slots that was a real memory-pressure vector. Mirrors the upload server's
/// own packet-length hardening.
const MAX_WIRE_PACKET_LEN: usize = 2 * 1024 * 1024;

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
        if before != self.pending.len() {
            debug!(
                "Dropped {} abandoned compressed block(s) from reassembly",
                before - self.pending.len()
            );
        }
    }

    pub(super) fn append(
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
        if !self.pending.contains_key(&start) && self.pending.len() >= MAX_PENDING_COMPRESSED_BLOCKS
        {
            anyhow::bail!("too many concurrent compressed parts");
        }
        let existing = self
            .pending
            .get(&start)
            .map(|entry| {
                if entry.declared_total != declared_total || entry.expected_len != expected_len {
                    Err(anyhow::anyhow!(
                        "compressed part changed declared packed size"
                    ))
                } else {
                    Ok(entry.packed_seen)
                }
            })
            .transpose()?
            .unwrap_or(0);
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
}

pub struct Ed2kDownload {
    pub transfer_id: String,
    pub file_hash: [u8; 16],
    pub file_name: String,
    pub file_size: u64,
    pub source_addr: SocketAddr,
    pub download_folders: crate::storage::part_folders::SharedDownloadFolders,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub bandwidth_limiter: Arc<BandwidthLimiter>,
    pub control: Arc<TransferControl>,
    pub source_manager: Option<Arc<tokio::sync::RwLock<SourceManager>>>,
    pub comment_manager: Option<Arc<tokio::sync::RwLock<CommentManager>>>,
    pub credit_manager: Option<Arc<tokio::sync::RwLock<CreditManager>>>,
    pub obfuscation_enabled: bool,
    pub ed2k_limits: Ed2kDownloadLimits,
    /// Our Ember identity hash, sent in EmuleInfo for friend identification
    pub ember_hash: [u8; 16],
    /// Our Ed25519 public key, advertised in `OP_EMBER_HELLO` /
    /// `OP_EMBER_HELLOANSWER` so the peer can run the
    /// `verify_ember_hash_binding` check against us. Used on the
    /// single-source download path to advertise an Ember-verifiable
    /// identity symmetrically with the multi-source path — so an
    /// `EmberFriendRequest` emitted from this code reports an honest
    /// `verified=true` whenever the peer's own pubkey + hash bind
    /// correctly (mirrors `multi_source.rs`'s binding-only check; the
    /// full `perform_ember_auth` proof-of-possession still runs on
    /// friend-connect dial-back).
    pub ed25519_public_key: [u8; 32],
    /// Our Ed25519 secret key. Held on the struct so any future
    /// patch that introduces the packet-buffering
    /// `perform_ember_auth` wrapper on the download side can sign
    /// peer challenges without another plumbing pass.
    pub ed25519_secret_key: [u8; 32],
    /// Our nickname for friend request messages
    pub our_nickname: String,
    /// Live friend user-hash set for detecting friend connections
    pub friend_hashes: Option<Arc<tokio::sync::RwLock<std::collections::HashSet<[u8; 16]>>>>,
    /// Pre-built Ember Peer Exchange payload (shared across tasks, read-only).
    pub ember_payload: crate::network::ember::SharedEmberPayload,
    /// Generation counter for detecting payload changes (for periodic re-sends).
    pub ember_payload_generation: crate::network::ember::EmberPayloadGeneration,
    /// IP filter for blocking known-bad ranges on SX receive
    pub ip_filter: Option<crate::network::kad::ip_filter::SharedIpFilter>,
    /// Banned peer IPs for rejecting SX sources
    pub banned_ips: Option<super::upload::SharedBannedIps>,
    /// Our external IP for self-source prevention
    pub external_ip: Option<std::net::Ipv4Addr>,
    /// Shared pending AICH recovery retries (read to gate OP_AICHREQUEST)
    pub aich_pending: Option<SharedAichPending>,
    /// Trusted AICH master from EPX / `aich_cache` when known before any
    /// peer HashSet2 arrives. Seeded so recovery does not wait on the wire.
    pub trusted_aich_master: Option<[u8; 20]>,
    /// Explicit AICH pin from the selected link/collection.
    pub expected_aich_master: Option<[u8; 20]>,
    /// GeoIP reader for country code lookups
    pub geoip: crate::geoip::GeoIpReader,
    /// Expected Ember content BLAKE3 (slice 18). All-zero skips verify.
    pub ember_file_hash: [u8; 32],
    /// Lock-free counter that the per-source loop bumps on every
    /// peer-to-peer Source Exchange packet (`OP_REQUESTSOURCES` /
    /// `OP_ANSWERSOURCES` and SX2). Ember `OP_EMBER_SOURCEEXCHANGE`
    /// is counted on `epx_overhead` instead. Drained on the network
    /// loop's stats tick into `OverheadCategory::SourceExchange`.
    pub sx_overhead: crate::storage::statistics::SharedSxOverheadCounters,
    /// Ember Peer Exchange (`OP_EMBER_SOURCEEXCHANGE`) wire bytes.
    /// Drained into `OverheadCategory::Epx`.
    pub epx_overhead: crate::storage::statistics::SharedSxOverheadCounters,
    /// Same idea as `sx_overhead`, but for file-open/queue handshake bytes
    /// (hashset request/answer, StartUploadReq/AcceptUploadReq/QueueFull/
    /// QueueRanking). Drained into `OverheadCategory::FileRequest`.
    pub file_req_overhead: crate::storage::statistics::SharedFileReqOverheadCounters,
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
    },
    Failed {
        transfer_id: String,
        error: String,
        failure_kind: SourceFailureKind,
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
        #[allow(dead_code)]
        sender_user_hash: Option<[u8; 16]>,
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
    let allowed = vec![download_root.to_string_lossy().into_owned()];
    let completed_dir =
        crate::security::filesystem::prepare_approved_subdir(download_root, "Downloads", &allowed)
            .map_err(|e| download_folder_error("preparing Downloads", download_root, e))?;
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

    fn build_sending_part_32(hash: [u8; 16], start: u32, end: u32, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24 + data.len());
        buf.extend_from_slice(&hash);
        buf.extend_from_slice(&start.to_le_bytes());
        buf.extend_from_slice(&end.to_le_bytes());
        buf.extend_from_slice(data);
        buf
    }

    #[test]
    fn parse_sending_part_32_accepts_matching_length() {
        let hash = [0x11; 16];
        let data = vec![0xABu8; 100];
        let payload = build_sending_part_32(hash, 1000, 1100, &data);
        let (h, start, end, out) = parse_sending_part_32(&payload).unwrap();
        assert_eq!(h, hash);
        assert_eq!(start, 1000);
        assert_eq!(end, 1100);
        assert_eq!(out, &data[..]);
    }

    #[test]
    fn parse_sending_part_32_rejects_length_mismatch() {
        // Peer claims a 100-byte block (start=1000, end=1100) but only
        // sends 50 trailing bytes — a naive parser would silently hand
        // back those 50 bytes as if they were the full claimed block.
        let hash = [0x22; 16];
        let short_data = vec![0xCDu8; 50];
        let payload = build_sending_part_32(hash, 1000, 1100, &short_data);
        assert!(
            parse_sending_part_32(&payload).is_err(),
            "declared block length must match the actual trailing data"
        );
    }

    #[test]
    fn parse_sending_part_32_rejects_end_before_start() {
        let hash = [0x33; 16];
        let payload = build_sending_part_32(hash, 2000, 1000, &[]);
        assert!(parse_sending_part_32(&payload).is_err());
    }

    /// A 32-bit OP_SENDINGPART is legal for a file of ANY size: the sender
    /// picks the opcode from the block's end offset, not the file size, so
    /// every block inside the first 4 GiB of a >4 GiB file arrives 32-bit.
    /// Refusing those made files over 4 GiB undownloadable — the first data
    /// packet from every source tore the connection down.
    #[test]
    fn parse_sending_part_32_addresses_a_file_over_4gib() {
        const FILE_SIZE: u64 = 8 * 1024 * 1024 * 1024;
        let hash = [0x44; 16];
        // Highest-addressed block eMule still frames with the 32-bit opcode.
        let end = u32::MAX;
        let start = end - 180;
        let data = vec![0x5Au8; 180];
        let payload = build_sending_part_32(hash, start, end, &data);
        let (h, s, e, out) = parse_sending_part_32(&payload).unwrap();
        assert_eq!(h, hash);
        assert_eq!(s, start as u64, "32-bit start must widen, not wrap");
        assert_eq!(e, end as u64, "32-bit end must widen, not wrap");
        assert_eq!(out, &data[..]);
        // ...and the receive loop's structural validation must accept it.
        assert!(s < e && e <= FILE_SIZE && out.len() == (e - s) as usize);
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

impl Ed2kDownload {
    /// Check if an SX-received source should be rejected (IP filter, banned,
    /// self-source). Returns true if the source should be skipped.
    fn is_sx_source_rejected(&self, ip: &std::net::Ipv4Addr, port: u16) -> bool {
        if let Some(ext_ip) = self.external_ip {
            if *ip == ext_ip && port == self.tcp_port {
                return true;
            }
        }
        if let Some(ref filter) = self.ip_filter {
            // Recover the guard if the lock is poisoned (a writer panicked)
            // instead of skipping the check — silently bypassing the IP filter
            // would let a banned/filtered peer through (fail-open security hole).
            let snap = filter.read().unwrap_or_else(|e| e.into_inner());
            if snap.is_blocked(*ip) {
                return true;
            }
        }
        if let Some(ref banned) = self.banned_ips {
            let set = banned.read().unwrap_or_else(|e| e.into_inner());
            if set.contains(ip) {
                return true;
            }
        }
        false
    }

    async fn check_control(&self) -> anyhow::Result<()> {
        if self.control.is_cancelled() {
            anyhow::bail!("cancelled by user");
        }
        while self.control.is_paused() {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            if self.control.is_cancelled() {
                anyhow::bail!("cancelled while paused");
            }
        }
        Ok(())
    }

    /// Zero-byte ed2k files: no P2P; hash must be MD4 of empty payload ([`super::hash::empty_ed2k_file_md4`]).
    async fn complete_zero_byte_local(
        &self,
        event_tx: &mpsc::Sender<DownloadEvent>,
    ) -> anyhow::Result<std::path::PathBuf> {
        self.emit_source_detail(event_tx, "connecting", None, 0, 0, "", "")
            .await;
        let _ = event_tx.try_send(DownloadEvent::Verifying {
            transfer_id: self.transfer_id.clone(),
        });
        if let Some(expected_aich) = self.expected_aich_master {
            use sha1::Digest;
            let actual: [u8; 20] = sha1::Sha1::digest([]).into();
            if actual != expected_aich {
                anyhow::bail!(
                    "Expected AICH hash mismatch: expected {}, got {}",
                    hex::encode(expected_aich),
                    hex::encode(actual)
                );
            }
        }
        let zero_name = self
            .control
            .seal_pending_rename()
            .unwrap_or_else(|| self.file_name.clone());
        let download_dir = self.download_folders.read().current.clone();
        let final_path = finalize_zero_ed2k_file(
            &self.transfer_id,
            &zero_name,
            self.file_hash,
            &download_dir,
        )
        .await?;
        self.emit_source_detail(event_tx, "completed", None, 0, 0, "", "")
            .await;
        let _ = event_tx.try_send(DownloadEvent::Progress {
            transfer_id: self.transfer_id.clone(),
            downloaded: 0,
            transferred: None,
            total: 0,
        });
        Ok(final_path)
    }

    async fn emit_source_detail(
        &self,
        event_tx: &mpsc::Sender<DownloadEvent>,
        status: &str,
        queue_rank: Option<u32>,
        speed: u64,
        transferred: u64,
        client_software: &str,
        peer_name: &str,
    ) {
        self.emit_source_detail_parts(
            event_tx,
            status,
            queue_rank,
            speed,
            transferred,
            client_software,
            peer_name,
            None,
            None,
        )
        .await;
    }

    fn country_code(&self) -> Option<String> {
        crate::geoip::lookup_country(&self.geoip, self.source_addr.ip())
    }

    async fn emit_source_detail_parts(
        &self,
        event_tx: &mpsc::Sender<DownloadEvent>,
        status: &str,
        queue_rank: Option<u32>,
        speed: u64,
        transferred: u64,
        client_software: &str,
        peer_name: &str,
        available_parts: Option<u32>,
        total_parts: Option<u32>,
    ) {
        let _ = event_tx.try_send(DownloadEvent::SourceDetail {
            transfer_id: self.transfer_id.clone(),
            ip: self.source_addr.ip().to_string(),
            port: self.source_addr.port(),
            status: status.to_string(),
            queue_rank,
            speed,
            transferred,
            client_software: client_software.to_string(),
            peer_name: peer_name.to_string(),
            failure_kind: None,
            available_parts,
            total_parts,
            country_code: self.country_code(),
        });
    }

    async fn emit_source_failed(
        &self,
        event_tx: &mpsc::Sender<DownloadEvent>,
        error: &str,
        transferred: u64,
        client_software: &str,
        peer_name: &str,
    ) {
        let _ = event_tx.try_send(DownloadEvent::SourceDetail {
            transfer_id: self.transfer_id.clone(),
            ip: self.source_addr.ip().to_string(),
            port: self.source_addr.port(),
            status: "failed".to_string(),
            queue_rank: None,
            speed: 0,
            transferred,
            client_software: client_software.to_string(),
            peer_name: peer_name.to_string(),
            failure_kind: Some(classify_error(error)),
            available_parts: None,
            total_parts: None,
            country_code: self.country_code(),
        });
    }

    /// Run a download on a pre-established connection (Hello handshake already done).
    /// Used for KAD callback connections where the firewalled source connected to us.
    ///
    /// Thin panic-isolating wrapper around [`Self::run_from_callback_inner`]:
    /// like the multi-source worker, this runs in a detached task, so a panic
    /// must become an `Err` (caught here) rather than silently killing the task
    /// and leaving the transfer stuck "active".
    pub async fn run_from_callback(
        self,
        reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
        peer_user_hash: [u8; 16],
        peer_caps: PeerCapabilities,
        emule_info_done: bool,
        event_tx: mpsc::Sender<DownloadEvent>,
    ) -> anyhow::Result<()> {
        match std::panic::AssertUnwindSafe(self.run_from_callback_inner(
            reader,
            writer,
            peer_user_hash,
            peer_caps,
            emule_info_done,
            event_tx,
        ))
        .catch_unwind()
        .await
        {
            Ok(result) => result,
            Err(panic) => {
                let msg = panic
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".to_string());
                Err(anyhow::anyhow!("callback download worker panicked: {msg}"))
            }
        }
    }

    async fn run_from_callback_inner(
        self,
        mut reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        mut writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
        peer_user_hash: [u8; 16],
        peer_caps: PeerCapabilities,
        emule_info_done: bool,
        event_tx: mpsc::Sender<DownloadEvent>,
    ) -> anyhow::Result<()> {
        info!(
            "Starting callback download {} from {}",
            hex::encode(self.file_hash),
            self.source_addr
        );

        if self.file_size == 0 {
            let zero_final = self.complete_zero_byte_local(&event_tx).await?;
            let _ = event_tx
                .send(DownloadEvent::Completed {
                    transfer_id: self.transfer_id.clone(),
                    final_path: Some(zero_final.to_string_lossy().into_owned()),
                    part_hashes: Vec::new(),
                    ember_verified: false,
                })
                .await;
            return Ok(());
        }

        self.emit_source_detail(&event_tx, "connected (callback)", None, 0, 0, "", "")
            .await;

        let _peer_session = match self.source_addr.ip() {
            std::net::IpAddr::V4(v4) => Some(super::peer_sessions::register(
                Some(peer_user_hash),
                v4,
                peer_caps.tcp_port,
            )),
            std::net::IpAddr::V6(_) => None,
        };

        if let Some(sm) = &self.source_manager {
            if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                let mut sm = sm.write().await;
                // Callback path: source_addr.port() is ephemeral. Keep it as a
                // live-session row; register Hello listening port when HighID.
                sm.register_inbound_callback_ports(
                    self.file_hash,
                    v4,
                    self.source_addr.port(),
                    peer_caps.tcp_port,
                    peer_user_hash,
                    0,
                    peer_caps.is_high_id(),
                    // `on_kad_callback_conn` registered this peer with the
                    // route's origin before starting this download.
                    None,
                );
            }
        }

        // `Completed` is sent by `download_from_streams` itself, from a task an
        // abort cannot drop. An `Err` propagates so the spawn site emits Failed
        // once.
        self.download_from_streams(
            &mut *reader,
            &mut *writer,
            peer_user_hash,
            // Same as multi-source EstablishedStream: format file requests
            // from the peer's Hello caps, not PeerCapabilities::default()
            // (ext_ver=0), or modern peers short-read and FIN.
            peer_caps,
            &event_tx,
            emule_info_done,
        )
        .await
    }

    async fn download_from_streams(
        &self,
        mut reader: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
        mut writer: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
        peer_user_hash: [u8; 16],
        initial_caps: PeerCapabilities,
        event_tx: &mpsc::Sender<DownloadEvent>,
        skip_emule_info: bool,
    ) -> anyhow::Result<()> {
        let mut peer_supports_large_files = initial_caps.supports_large_files;
        let mut peer_supports_multipacket = initial_caps.supports_multi_packet;
        let mut peer_supports_ext_multipacket = initial_caps.ext_multi_packet;
        let mut peer_supports_file_ident = initial_caps.supports_file_ident;
        let mut peer_supports_source_ex2 = initial_caps.supports_source_ex2;
        let mut peer_supports_aich = initial_caps.supports_aich;
        let mut peer_source_exchange_ver: u8 = initial_caps.source_exchange_ver;
        let mut peer_extended_requests_ver: u8 = initial_caps.extended_requests_ver;
        let mut peer_secure_ident_level: u8 = initial_caps.secure_ident_level;
        let mut peer_is_ember = initial_caps.is_ember;
        let mut peer_ember_hash: Option<[u8; 16]> = initial_caps.ember_hash;
        // Latest UDP port the peer advertised via `OP_EMULEINFO`. Held for the
        // session because `EmberPeerDiscovered` is emitted from the Ember-hello
        // paths, which run in different match arms from the EmuleInfo parse.
        // Stays 0 until (or unless) the peer advertises one.
        let mut peer_udp_port: u16 = initial_caps.udp_port;
        // Ember-hello-derived state. Mirrors the `multi_source.rs`
        // binding-verification flow: we learn the peer's Ed25519
        // public key from `OP_EMBER_HELLO` / `OP_EMBER_HELLOANSWER`,
        // run the offline `verify_ember_hash_binding` check (BLAKE3
        // prefix vs. advertised ember_hash), and thread the result
        // through to every `DownloadEvent::EmberFriendRequest` this
        // session emits so the Friends UI can render a trustworthy
        // verification badge on single-source downloads — previously
        // those always landed with `verified=false` regardless of
        // whether the peer carried a valid identity claim.
        let mut peer_ember_pubkey: Option<[u8; 32]> = None;
        let mut ember_hash_binding_verified = false;
        // Strict proof-of-possession flag. Mirrors the `multi_source.rs`
        // contract: `true` iff `perform_ember_auth_buffered` completed
        // successfully on THIS TCP session — the peer signed a fresh
        // random nonce we issued with the matching Ed25519 secret key.
        // Implies `ember_hash_binding_verified`. Used to mark
        // `EmberFriendRequest.verified` as PoP-backed rather than
        // binding-only, and to gate privilege-bearing friend opcodes
        // (CHAT_MSG) on genuine identity ownership.
        let mut ember_auth_verified = false;
        // Whether we've already promoted this session's PoP success
        // to a `DownloadEvent::FriendSeen`. We only emit once per
        // session so the dispatcher doesn't get repeated address-
        // update events for the same peer.
        let mut friend_seen_emitted = false;
        // Mirrors `friend_seen_emitted`: guards `EmberPeerDiscovered` so a
        // peer whose PoP completes mid-loop doesn't get double-fed into
        // the mesh (once from the "PoP just succeeded" handler, once more
        // from the later unconditional post-loop gate once its condition
        // is also satisfied).
        let mut mesh_discovered_emitted = false;
        let mut friend_request_sent = false;
        // FIFO of non-AUTH packets captured by
        // `perform_ember_auth_buffered` while it waited for CHALLENGE /
        // RESPONSE. The uploader emits proactive
        // `OP_SECIDENTSTATE` / `OP_PUBLICKEY` / `OP_SIGNATURE` / EPX
        // frames immediately after its `OP_EMBER_HELLO`; those queue
        // ahead of the uploader's auth response and would be silently
        // dropped by the non-buffered `perform_ember_auth`. We capture
        // them here and the pre-control / file-status-wait loop heads
        // below drain this deque before reading fresh packets from the
        // stream, so the main dispatch arms still see them in arrival
        // order and SecIdent credit accounting stays correct.
        let mut auth_deferred: std::collections::VecDeque<(u8, u8, Vec<u8>)> =
            std::collections::VecDeque::new();
        let mut sent_ember_hello = false;
        let mut epx_packets_received: u8 = 0;
        let mut early_upload_accept = false;
        let mut pending_secident_challenge: Option<u32> = None;
        let mut pending_peer_challenge: Option<(u32, u8)> = None;

        let mut deferred_packet: Option<(u8, u8, Vec<u8>)> = None;
        let mut client_software_label = client_software_from_caps(&initial_caps);
        let mut peer_name_label = initial_caps.peer_name.clone();
        let our_client_id = self
            .external_ip
            .map(|ip| u32::from_le_bytes(ip.octets()))
            .unwrap_or(0);

        let peer_is_new_emule =
            initial_caps.emule_version_min > 0 || initial_caps.version_major > 0;
        // `did_proactive_challenge` tracks whether `maybe_send_secident_challenge`
        // fired inside the branches below (it does, for the classic pre-EmuleInfo
        // peer path). After the match we send it unconditionally if we haven't
        // already — so the modern-eMule "fast path" (where the peer's Hello
        // carries CT_EMULE_VERSION and they short-circuit the EmuleInfo
        // exchange entirely, sending OP_SECIDENTSTATE directly after their
        // HelloAnswer — see BaseClient.cpp:659-664 / ListenSocket.cpp:284)
        // still gets its SecIdent kick-off. Without this, eMule treats us as
        // `IS_NOTAVAILABLE` on the download side and our peer sees us the
        // same way, which is exactly the symptom we just fixed on uploads.
        let mut did_proactive_challenge = false;
        if skip_emule_info || peer_is_new_emule {
            debug!(
                "Skipping EmuleInfo exchange (already done via obfuscation or Hello eMule tags)"
            );
        } else {
            let emule_payload = build_emule_info(
                self.udp_port,
                self.obfuscation_enabled,
                Some(&self.ember_hash),
                None,
            );
            write_packet_async(&mut writer, OP_EMULEPROT, OP_EMULEINFO, &emule_payload).await?;

            let (proto2, opcode2, payload2) = read_packet_with_timeout(&mut reader)
                .await
                .context("stage:emule_info_wait")?;
            if proto2 == OP_EMULEPROT && opcode2 == OP_EMULEINFOANSWER {
                let mut peer_caps = initial_caps.clone();
                merge_caps(&mut peer_caps, parse_emule_info(&payload2));
                debug!(
                    "Peer caps: compress={}, large_files={}, sx={}/{}, kad={}/{}, \
                     crypt={}/{}/{}, multi={}/{}, aich={}, unicode={}, secident={}, \
                     preview={}, captcha={}, file_ident={}, direct_cb={}, \
                     compat={}, emule_min={}, mod={}",
                    peer_caps.compression_ver,
                    peer_caps.supports_large_files,
                    peer_caps.source_exchange_ver,
                    peer_caps.supports_source_ex2,
                    peer_caps.kad_version,
                    peer_caps.kad_port,
                    peer_caps.supports_crypt_layer,
                    peer_caps.requests_crypt_layer,
                    peer_caps.requires_crypt_layer,
                    peer_caps.supports_multi_packet,
                    peer_caps.ext_multi_packet,
                    peer_caps.supports_aich,
                    peer_caps.supports_unicode,
                    peer_caps.supports_secure_ident,
                    peer_caps.supports_preview,
                    peer_caps.supports_captcha,
                    peer_caps.supports_file_ident,
                    peer_caps.supports_direct_udp_callback,
                    peer_caps.compatible_client,
                    peer_caps.emule_version_min,
                    peer_caps.mod_version,
                );
                let peer_udp = peer_caps.udp_port;
                if peer_udp > 0 {
                    peer_udp_port = peer_udp;
                }
                peer_supports_large_files = peer_caps.supports_large_files;
                peer_supports_multipacket = peer_caps.supports_multi_packet;
                peer_supports_ext_multipacket = peer_caps.ext_multi_packet;
                peer_supports_file_ident = peer_caps.supports_file_ident;
                peer_supports_source_ex2 = peer_caps.supports_source_ex2;
                peer_source_exchange_ver = peer_caps.source_exchange_ver;
                peer_supports_aich = peer_caps.supports_aich;
                peer_extended_requests_ver = peer_caps.extended_requests_ver;
                peer_secure_ident_level = peer_caps.secure_ident_level;
                // `is_ember` / `ember_hash` are sourced exclusively from
                // `OP_EMBER_HELLO` / `OP_EMBER_HELLOANSWER` — `parse_emule_info`
                // never sets either field (see `messages.rs`). `peer_caps` is
                // re-derived from `initial_caps` on every EmuleInfo packet, so
                // assigning from it here used to clobber a `peer_is_ember =
                // true` / `peer_ember_hash = Some(..)` that an earlier
                // OP_EMBER_HELLO had already established, silently disabling
                // EPX and friend detection for the rest of the session
                // whenever EmuleInfo arrived after Hello (the common case).
                client_software_label = client_software_from_caps(&peer_caps);
                if !peer_caps.peer_name.is_empty() {
                    peer_name_label = peer_caps.peer_name.clone();
                }
                if peer_udp > 0 {
                    if let Some(sm) = &self.source_manager {
                        let mut sm = sm.write().await;
                        if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                            sm.register_observed_peer_ports(
                                self.file_hash,
                                v4,
                                self.source_addr.port(),
                                peer_caps.tcp_port,
                                peer_udp,
                                peer_user_hash,
                                peer_caps.is_high_id(),
                            );
                        }
                    }
                    debug!("Got EmuleInfoAnswer (peer UDP port: {peer_udp})");
                } else {
                    debug!("Got EmuleInfoAnswer");
                }
                pending_secident_challenge = maybe_send_secident_challenge(
                    &mut writer,
                    self.credit_manager.as_ref(),
                    peer_user_hash,
                    self.source_addr,
                    peer_secure_ident_level,
                )
                .await?;
                did_proactive_challenge = true;
            } else if proto2 == OP_EMULEPROT && opcode2 == OP_EMULEINFO {
                // Peer sent OP_EMULEINFO instead of OP_EMULEINFOANSWER — parse
                // their capabilities and reply with our OP_EMULEINFOANSWER.
                let mut peer_caps = initial_caps.clone();
                merge_caps(&mut peer_caps, parse_emule_info(&payload2));
                let peer_udp = peer_caps.udp_port;
                if peer_udp > 0 {
                    peer_udp_port = peer_udp;
                }
                peer_supports_large_files = peer_caps.supports_large_files;
                peer_supports_multipacket = peer_caps.supports_multi_packet;
                peer_supports_ext_multipacket = peer_caps.ext_multi_packet;
                peer_supports_file_ident = peer_caps.supports_file_ident;
                peer_supports_source_ex2 = peer_caps.supports_source_ex2;
                peer_source_exchange_ver = peer_caps.source_exchange_ver;
                peer_supports_aich = peer_caps.supports_aich;
                peer_extended_requests_ver = peer_caps.extended_requests_ver;
                peer_secure_ident_level = peer_caps.secure_ident_level;
                // `is_ember` / `ember_hash` are sourced exclusively from
                // `OP_EMBER_HELLO` / `OP_EMBER_HELLOANSWER` — `parse_emule_info`
                // never sets either field (see `messages.rs`). `peer_caps` is
                // re-derived from `initial_caps` on every EmuleInfo packet, so
                // assigning from it here used to clobber a `peer_is_ember =
                // true` / `peer_ember_hash = Some(..)` that an earlier
                // OP_EMBER_HELLO had already established, silently disabling
                // EPX and friend detection for the rest of the session
                // whenever EmuleInfo arrived after Hello (the common case).
                client_software_label = client_software_from_caps(&peer_caps);
                if !peer_caps.peer_name.is_empty() {
                    peer_name_label = peer_caps.peer_name.clone();
                }
                if peer_udp > 0 {
                    if let Some(sm) = &self.source_manager {
                        let mut sm = sm.write().await;
                        if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                            sm.register_observed_peer_ports(
                                self.file_hash,
                                v4,
                                self.source_addr.port(),
                                peer_caps.tcp_port,
                                peer_udp,
                                peer_user_hash,
                                peer_caps.is_high_id(),
                            );
                        }
                    }
                }
                let emule_answer = build_emule_info(
                    self.udp_port,
                    self.obfuscation_enabled,
                    Some(&self.ember_hash),
                    None,
                );
                write_packet_async(&mut writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &emule_answer)
                    .await?;
                debug!("Received peer OP_EMULEINFO, replied with OP_EMULEINFOANSWER");
                pending_secident_challenge = maybe_send_secident_challenge(
                    &mut writer,
                    self.credit_manager.as_ref(),
                    peer_user_hash,
                    self.source_addr,
                    peer_secure_ident_level,
                )
                .await?;
                did_proactive_challenge = true;
            } else {
                debug!("Peer skipped EmuleInfoAnswer (got proto=0x{proto2:02X} op=0x{opcode2:02X}), deferring");
                deferred_packet = Some((proto2, opcode2, payload2));
            }
        }

        // Fire the SecIdent kick-off if the branches above didn't already.
        // Covers (a) `skip_emule_info || peer_is_new_emule` — the modern
        // eMule fast path that never sends OP_EMULEINFO, and
        // (b) the `else { deferred_packet }` branch where the peer sent an
        // unrelated packet (often OP_SECIDENTSTATE itself). In both cases
        // the peer is waiting for our OP_SECIDENTSTATE before it will ship
        // its own OP_PUBLICKEY / OP_SIGNATURE, so without this call the
        // handshake deadlocks and both sides settle at IS_NOTAVAILABLE.
        // `maybe_send_secident_challenge` is a no-op when the peer doesn't
        // advertise SecIdent or we have no local keypair.
        if !did_proactive_challenge {
            pending_secident_challenge = maybe_send_secident_challenge(
                &mut writer,
                self.credit_manager.as_ref(),
                peer_user_hash,
                self.source_addr,
                peer_secure_ident_level,
            )
            .await?;
        }

        // Handle secure identification packets that may arrive before file requests.
        // Be passive: store peer key material and answer explicit challenges.
        //
        // Iteration count bumped from 3 → 12 to mirror `multi_source.rs`:
        // `perform_ember_auth_buffered` (invoked from the OP_EMBER_HELLO
        // handler below) can capture up to AUTH_PACKET_MAX_SKIPS (8)
        // non-AUTH packets while waiting for the peer's CHALLENGE /
        // RESPONSE. Those captured packets are drained from
        // `auth_deferred` at the top of this loop on subsequent
        // iterations, and we need enough rounds to actually replay
        // them through the SecIdent / EPX match arms before
        // file-status-wait kicks in.
        for _ in 0..12 {
            let (p, o, pl) = if let Some(pkt) = deferred_packet.take() {
                pkt
            } else if let Some(pkt) = auth_deferred.pop_front() {
                // Replay a packet that `perform_ember_auth_buffered`
                // captured while waiting for an AUTH opcode — process
                // it through the standard match arms below so
                // SecIdent credit accounting still works for
                // Ember-to-Ember single-source downloads.
                pkt
            } else {
                match read_packet_within(
                    &mut reader,
                    std::time::Duration::from_secs(3),
                    std::time::Duration::from_secs(
                        super::multi_source::HANDSHAKE_READ_TIMEOUT_SECS,
                    ),
                )
                .await
                {
                    Ok(Some(pkt)) => pkt,
                    Err(e) if e.get_ref().is_some_and(|i| i.is::<PacketStreamDesynced>()) => {
                        return Err(anyhow::Error::from(e).context("stage:emule_info_wait"));
                    }
                    _ => break,
                }
            };

            match (p, o) {
                (OP_EMULEPROT, OP_PUBLICKEY) if !pl.is_empty() => {
                    let key = if pl.len() >= 2 && pl[0] as usize == pl.len() - 1 {
                        pl[1..].to_vec()
                    } else {
                        pl
                    };
                    if let Some(cm) = &self.credit_manager {
                        let mut cm = cm.write().await;
                        if !cm.set_public_key(peer_user_hash, key) {
                            debug!(
                                "Ignoring OP_PUBLICKEY from {}: a different key is already bound to this user hash",
                                self.source_addr
                            );
                        }
                    }
                    if let Some((challenge, state)) = pending_peer_challenge.take() {
                        respond_to_secident_challenge(
                            &mut writer,
                            self.credit_manager.as_ref(),
                            state,
                            challenge,
                            self.source_addr,
                            peer_user_hash,
                            peer_secure_ident_level,
                            our_client_id,
                        )
                        .await?;
                    }
                    if pending_secident_challenge.is_none() {
                        pending_secident_challenge = maybe_send_secident_challenge(
                            &mut writer,
                            self.credit_manager.as_ref(),
                            peer_user_hash,
                            self.source_addr,
                            peer_secure_ident_level,
                        )
                        .await?;
                    }
                    debug!("Received peer's public key");
                }
                (OP_EMULEPROT, OP_SECIDENTSTATE) if pl.len() >= 5 => {
                    let state = pl[0];
                    let challenge = u32::from_le_bytes([pl[1], pl[2], pl[3], pl[4]]);
                    // Any state needs the peer's key to sign against
                    // (BaseClient.cpp:1851-1852).
                    let missing_peer_key = if let Some(cm) = &self.credit_manager {
                        let cm = cm.read().await;
                        !cm.has_public_key(&peer_user_hash)
                    } else {
                        true
                    };
                    if missing_peer_key {
                        pending_peer_challenge = Some((challenge, state));
                    } else {
                        respond_to_secident_challenge(
                            &mut writer,
                            self.credit_manager.as_ref(),
                            state,
                            challenge,
                            self.source_addr,
                            peer_user_hash,
                            peer_secure_ident_level,
                            our_client_id,
                        )
                        .await?;
                    }
                    debug!("Responded to SecIdent challenge");
                }
                (OP_EMULEPROT, OP_SIGNATURE) if pl.len() >= 2 => {
                    handle_secident_signature(
                        self.credit_manager.as_ref(),
                        peer_user_hash,
                        &mut pending_secident_challenge,
                        self.source_addr,
                        peer_secure_ident_level,
                        &pl,
                        our_client_id,
                    )
                    .await;
                }
                (OP_EMULEPROT, OP_EMULEINFOANSWER) | (OP_EMULEPROT, OP_EMULEINFO) => {
                    let mut peer_caps = initial_caps.clone();
                    merge_caps(&mut peer_caps, parse_emule_info(&pl));
                    let peer_udp = peer_caps.udp_port;
                    if peer_udp > 0 {
                        peer_udp_port = peer_udp;
                    }
                    peer_supports_large_files = peer_caps.supports_large_files;
                    peer_supports_multipacket = peer_caps.supports_multi_packet;
                    peer_supports_ext_multipacket = peer_caps.ext_multi_packet;
                    peer_supports_file_ident = peer_caps.supports_file_ident;
                    peer_supports_source_ex2 = peer_caps.supports_source_ex2;
                    peer_source_exchange_ver = peer_caps.source_exchange_ver;
                    peer_supports_aich = peer_caps.supports_aich;
                    peer_extended_requests_ver = peer_caps.extended_requests_ver;
                    peer_secure_ident_level = peer_caps.secure_ident_level;
                    // `is_ember` / `ember_hash` come from `OP_EMBER_HELLO` /
                    // `OP_EMBER_HELLOANSWER` only — see the identical
                    // rationale above (`parse_emule_info` never sets either
                    // field, so assigning from `peer_caps` here would
                    // clobber an already-established Ember identity).
                    client_software_label = client_software_from_caps(&peer_caps);
                    if !peer_caps.peer_name.is_empty() {
                        peer_name_label = peer_caps.peer_name.clone();
                    }
                    if peer_udp > 0 {
                        if let Some(sm) = &self.source_manager {
                            let mut sm = sm.write().await;
                            if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                sm.register_observed_peer_ports(
                                    self.file_hash,
                                    v4,
                                    self.source_addr.port(),
                                    peer_caps.tcp_port,
                                    peer_udp,
                                    peer_user_hash,
                                    peer_caps.is_high_id(),
                                );
                            }
                        }
                    }
                    if o == OP_EMULEINFO {
                        let emule_answer = build_emule_info(
                            self.udp_port,
                            self.obfuscation_enabled,
                            Some(&self.ember_hash),
                            None,
                        );
                        let _ = write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_EMULEINFOANSWER,
                            &emule_answer,
                        )
                        .await;
                        debug!(
                            "Received delayed peer OP_EMULEINFO, replied with OP_EMULEINFOANSWER"
                        );
                    } else {
                        debug!("Got delayed EmuleInfoAnswer");
                    }
                }
                (OP_EDONKEYHEADER, OP_ACCEPTUPLOADREQ) => {
                    early_upload_accept = true;
                    debug!("Received early AcceptUploadReq before file status");
                }
                // EPX is an Ember-only extension; gate reception on
                // Ember HELLO + hash↔pubkey binding. Full PoP/Noise remains
                // required for friend privileges (chat/browse/priority).
                (OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE)
                    if peer_is_ember
                        && ember_hash_binding_verified
                        && epx_packets_received
                            < crate::network::ember::MAX_EPX_PACKETS_PER_CONNECTION =>
                {
                    self.epx_overhead.record_download((6 + pl.len()) as u64);
                    epx_packets_received += 1;
                    info!(
                        "Received early EPX from {} during pre-control ({} bytes)",
                        self.source_addr,
                        pl.len()
                    );
                    match crate::network::ember::parse_exchange_payload(&pl) {
                        Ok(result)
                            if !result.files.is_empty()
                                || !result.peers.is_empty()
                                || !result.relay_attestations.is_empty() =>
                        {
                            let (epx_entries, aich_roots) = epx_result_to_entries(&result);
                            let relay_attestations = result.relay_attestations.clone();
                            let epx_peers = result
                                .peers
                                .into_iter()
                                .map(|ep| (ep.ip, ep.tcp_port))
                                .collect();
                            let _ = event_tx
                                .send(DownloadEvent::EmberSources {
                                    transfer_id: self.transfer_id.clone(),
                                    entries: epx_entries,
                                    aich_roots,
                                    ember_peers: epx_peers,
                                    relay_attestations,
                                    from_ember_hash: peer_ember_hash,
                                })
                                .await;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            debug!("Failed to parse early EPX from {}: {e}", self.source_addr)
                        }
                    }
                }
                (OP_EMULEPROT, OP_EMBER_FRIEND_REQ) if peer_is_ember => {
                    if let Some(eh) = peer_ember_hash {
                        let nick = crate::security::normalize_inbound_friend_nickname(&pl);
                        // `verified` requires PoP (Ed25519 challenge-
                        // response). Binding-only is replayable — a
                        // peer who learned a victim's public
                        // (pubkey, ember_hash) on the wire could
                        // otherwise post a "Verified" friend request
                        // in the recipient's UI. PoP also re-runs on
                        // the friend-connect dial-back if the user
                        // accepts, so this never permanently marks a
                        // legitimate friend unverified.
                        let verified = ember_auth_verified;
                        debug!(
                            "Received early friend request from {} (nickname_chars={}, verified={verified}, pop={}, binding={ember_hash_binding_verified})",
                            self.source_addr,
                            nick.chars().count(),
                            ember_auth_verified
                        );
                        let _ = event_tx
                            .send(DownloadEvent::EmberFriendRequest {
                                ember_hash: eh,
                                pubkey: peer_ember_pubkey,
                                nickname: nick,
                                peer_ip: self.source_addr.ip().to_string(),
                                peer_port: super::advertised_listen_port(
                                    initial_caps.tcp_port,
                                    self.source_addr.port(),
                                ),
                                verified,
                            })
                            .await;
                    }
                }
                // Authoritative Ember peer detection. A peer that emits a
                // parseable `OP_EMBER_HELLO` / `OP_EMBER_HELLOANSWER`
                // payload is, by construction, an Ember client — vanilla
                // eMule never sends either opcode (private 0xF8/0xF9
                // range; `ListenSocket.cpp`'s default branch just logs
                // "Unknown extended emule protocol opcode" and returns).
                // When the peer beat us to it and sent `OP_EMBER_HELLO`
                // (rather than the answer), we respond with our own
                // `OP_EMBER_HELLOANSWER` so they learn our identity in
                // the same round trip.
                (OP_EMULEPROT, OP_EMBER_HELLO) | (OP_EMULEPROT, OP_EMBER_HELLOANSWER) => {
                    if let Some(ident) = parse_ember_hello(&pl) {
                        peer_is_ember = true;
                        // Identity lock: refuse to swap pubkey/hash
                        // after PoP verification (see upload.rs for
                        // the full rationale — same accounting risk).
                        let identity_changed = ember_auth_verified
                            && ((ident.ed25519_pubkey.is_some()
                                && peer_ember_pubkey.is_some()
                                && ident.ed25519_pubkey != peer_ember_pubkey)
                                || (ident.ember_hash != [0u8; 16]
                                    && peer_ember_hash.is_some()
                                    && Some(ident.ember_hash) != peer_ember_hash));
                        if identity_changed {
                            tracing::warn!(
                                "Ember identity-swap rejected from {}: peer already PoP-verified, ignoring re-keyed OP_EMBER_HELLO (old_hash={:?}, new_hash={})",
                                self.source_addr,
                                peer_ember_hash.as_ref().map(hex::encode),
                                hex::encode(ident.ember_hash),
                            );
                        }
                        if ident.ember_hash != [0u8; 16] && !identity_changed {
                            peer_ember_hash = Some(ident.ember_hash);
                        }
                        if let Some(pk) = ident.ed25519_pubkey {
                            if !identity_changed {
                                peer_ember_pubkey = Some(pk);
                            }
                        }
                        if !ident.nickname.is_empty() {
                            peer_name_label = ident.nickname.clone();
                        }
                        debug!(
                            "Peer {} identified as Ember via OP_EMBER_HELLO (mod='{}', nick='{}')",
                            self.source_addr, ident.mod_version, ident.nickname
                        );
                        if o == OP_EMBER_HELLO && !sent_ember_hello {
                            // Advertise our pubkey so the peer can run
                            // `verify_ember_hash_binding` on us
                            // symmetrically. Vanilla peers ignore the
                            // opcode, so this is safe to emit whenever
                            // we're responding to a peer-initiated
                            // Ember-Hello.
                            let payload = build_ember_hello(
                                &self.ember_hash,
                                &self.our_nickname,
                                Some(&self.ed25519_public_key),
                            );
                            let _ = write_packet_async(
                                &mut writer,
                                OP_EMULEPROT,
                                OP_EMBER_HELLOANSWER,
                                &payload,
                            )
                            .await;
                            sent_ember_hello = true;
                        }

                        // Offline identity-binding check first — cheap,
                        // and we need it regardless of whether the
                        // peer supports the full challenge-response.
                        if !ember_hash_binding_verified {
                            if let (Some(ref pk), Some(ref eh)) =
                                (peer_ember_pubkey, peer_ember_hash)
                            {
                                if crate::network::ember::crypto::verify_ember_hash_binding(pk, eh)
                                {
                                    ember_hash_binding_verified = true;
                                    info!(
                                        "Ember binding: peer {} pubkey BLAKE3-binds to advertised hash",
                                        self.source_addr
                                    );
                                    if peer_user_hash != [0u8; 16] {
                                        if let Some(cm) = &self.credit_manager {
                                            cm.write().await.note_bound_ember_hash(peer_user_hash, *eh);
                                        }
                                    }
                                } else {
                                    tracing::warn!(
                                        "Ember binding: peer {} advertised pubkey does not BLAKE3-bind to ember_hash={} (possible spoof)",
                                        self.source_addr,
                                        hex::encode(eh)
                                    );
                                }
                            }
                        }

                        // Full Ed25519 proof-of-possession via the
                        // packet-buffering auth wrapper. Mirrors the
                        // multi_source.rs pre-control flow: only
                        // attempt PoP when the binding check passed
                        // (don't leak our nonce to hash-spoofers) and
                        // we haven't already verified on this session.
                        // Captured non-AUTH packets are pushed into
                        // `auth_deferred` and replayed at the top of
                        // this loop on subsequent iterations, so the
                        // uploader's OP_SECIDENTSTATE / EPX bundled
                        // with its auth response still flow through
                        // the normal match arms.
                        //
                        // PoP failure is non-fatal — the download
                        // itself is separable from identity
                        // verification. We just leave
                        // `ember_auth_verified = false` so
                        // `DownloadEvent::EmberFriendRequest.verified`
                        // falls back to the binding-only signal.
                        // Legacy PoP is parser-only in v2.  Never sign a
                        // peer-selected nonce on a generic transfer stream.
                        if super::LEGACY_FRIEND_AUTH_ENABLED
                            && !ember_auth_verified
                            && ember_hash_binding_verified
                        {
                            if let (Some(peer_pk), Some(peer_eh)) =
                                (peer_ember_pubkey, peer_ember_hash)
                            {
                                match super::friend_connect::perform_ember_auth_buffered(
                                    &mut reader,
                                    &mut writer,
                                    &self.ed25519_public_key,
                                    &self.ed25519_secret_key,
                                    &peer_pk,
                                    Some(&peer_eh),
                                    self.source_addr,
                                    &mut auth_deferred,
                                )
                                .await
                                {
                                    Ok(()) => {
                                        ember_auth_verified = true;
                                        info!(
                                            "Ember auth: peer {} verified via PoP ({} deferred packet(s) queued for replay)",
                                            self.source_addr,
                                            auth_deferred.len()
                                        );
                                        // Feed the mesh now that PoP has
                                        // verified this peer (see the
                                        // gate comment above where this
                                        // was previously emitted
                                        // unconditionally on `is_ember`).
                                        if !mesh_discovered_emitted {
                                            if let std::net::IpAddr::V4(v4) = self.source_addr.ip()
                                            {
                                                let peer_tcp = self.source_addr.port();
                                                if peer_tcp > 0 && !crate::security::is_bogus_v4(v4)
                                                {
                                                    let _ = event_tx
                                                        .send(DownloadEvent::EmberPeerDiscovered {
                                                            ip: v4,
                                                            tcp_port: peer_tcp,
                                                            udp_port: peer_udp_port,
                                                        })
                                                        .await;
                                                    mesh_discovered_emitted = true;
                                                }
                                            }
                                        }
                                        // Pre-control PoP runs before
                                        // `peer_is_friend` is bound,
                                        // so re-check `friend_hashes`
                                        // inline to gate the
                                        // FriendSeen emit on PoP.
                                        if !friend_seen_emitted {
                                            if let (Some(ref fh_arc), Some(eh)) =
                                                (&self.friend_hashes, peer_ember_hash)
                                            {
                                                if fh_arc.read().await.contains(&eh) {
                                                    // Prefer the Hello listen port over
                                                    // the ephemeral socket port so this
                                                    // is a dialable download-source
                                                    // endpoint.
                                                    let friend_port = if initial_caps.tcp_port > 0 {
                                                        initial_caps.tcp_port
                                                    } else {
                                                        self.source_addr.port()
                                                    };
                                                    let _ = event_tx
                                                        .send(DownloadEvent::FriendSeen {
                                                            ember_hash: eh,
                                                            ip: self.source_addr.ip(),
                                                            port: friend_port,
                                                        })
                                                        .await;
                                                    friend_seen_emitted = true;
                                                    if !friend_request_sent {
                                                        let nick_bytes =
                                                            self.our_nickname.as_bytes();
                                                        if write_packet_async(
                                                            &mut writer,
                                                            OP_EMULEPROT,
                                                            OP_EMBER_FRIEND_REQ,
                                                            nick_bytes,
                                                        )
                                                        .await
                                                        .is_ok()
                                                        {
                                                            friend_request_sent = true;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Ember auth: peer {} PoP failed — continuing with binding-only verification: {e}",
                                            self.source_addr
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {
                    deferred_packet = Some((p, o, pl));
                    break;
                }
            }
        }

        // `OP_EMBER_HELLO` is sent below, once the file request is on the
        // wire. Shipping it here spliced an unknown OP_EMULEPROT opcode
        // between EmuleInfo and RequestFilename — the one window where our
        // handshake stopped being byte-identical to vanilla eMule. Peers that
        // beat us to it in the pre-control loop above already set
        // `sent_ember_hello` and got a HELLOANSWER there.

        // Ember Peer Exchange: share sources after Ember identity binding.
        // Snapshot the generation we sent so the periodic resend loop below
        // can detect rebuilds during file-status / queue wait.
        let mut initial_epx_sent_generation: Option<u64> = None;
        if peer_is_ember && ember_hash_binding_verified {
            let sent_gen = self
                .ember_payload_generation
                .load(std::sync::atomic::Ordering::Relaxed);
            let epx_data = self.ember_payload.read().await.clone();
            if !epx_data.is_empty() {
                debug!(
                    "Sending Ember Peer Exchange to verified peer {} ({} bytes, gen {})",
                    self.source_addr,
                    epx_data.len(),
                    sent_gen
                );
                let _ = write_packet_async(
                    &mut writer,
                    OP_EMULEPROT,
                    OP_EMBER_SOURCEEXCHANGE,
                    &epx_data,
                )
                .await;
                self.epx_overhead.record_upload((6 + epx_data.len()) as u64);
                initial_epx_sent_generation = Some(sent_gen);
            }
        }
        // Feed the peer-discovery mesh once Ember HELLO binding verifies
        // the advertised (pubkey, ember_hash) pair. Binding is weaker than
        // PoP (replayable if the pubkey was sniffed) but sufficient for
        // StatusBar/KAD Ember-peer identity; friend privileges stay on
        // secure_v2 / PoP.
        if peer_is_ember && ember_hash_binding_verified && !mesh_discovered_emitted {
            if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                let peer_tcp = self.source_addr.port();
                if peer_tcp > 0 && !crate::security::is_bogus_v4(v4) {
                    let _ = event_tx
                        .send(DownloadEvent::EmberPeerDiscovered {
                            ip: v4,
                            tcp_port: peer_tcp,
                            udp_port: peer_udp_port,
                        })
                        .await;
                    mesh_discovered_emitted = true;
                }
            }
        }

        let peer_is_friend =
            if let (Some(ref fh), Some(eh)) = (&self.friend_hashes, peer_ember_hash) {
                fh.read().await.contains(&eh)
            } else {
                false
            };
        // Friend request deferred until PoP (membership oracle otherwise).

        // Send file request in eMule order:
        // 1) OP_REQUESTFILENAME
        // 2) OP_SETREQFILEID (only needed for multipart files)
        let part_count = ed2k_part_count_for_size(self.file_size);
        let wire_part_count = ed2k_wire_part_count(self.file_size);
        let single_part = part_count <= 1;
        let file_req = build_file_request(&self.file_hash);
        let mut req_file_name_payload = file_req.clone();
        if peer_extended_requests_ver > 0 {
            req_file_name_payload.extend_from_slice(&(wire_part_count as u16).to_le_bytes());
            let bitmap_bytes = (wire_part_count + 7) / 8;
            req_file_name_payload.extend(std::iter::repeat_n(0u8, bitmap_bytes));
            if peer_extended_requests_ver > 1 {
                req_file_name_payload.extend_from_slice(&0u16.to_le_bytes());
            }
        }
        // eMule IsSourceRequestAllowed: throttle SX to once per 40 min per source
        let sx_allowed = if let Some(sm) = &self.source_manager {
            let sm = sm.read().await;
            if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                sm.can_request_sources_for(&self.file_hash, v4, self.source_addr.port())
            } else {
                true
            }
        } else {
            true
        };

        if peer_supports_file_ident || peer_supports_ext_multipacket || peer_supports_multipacket {
            // eMule-style multipacket file request.
            let mut mp = Vec::with_capacity(64 + req_file_name_payload.len());
            if peer_supports_file_ident {
                FileIdentifier {
                    md4_hash: self.file_hash,
                    file_size: Some(self.file_size),
                    aich_hash: None,
                }
                .write_identifier(&mut mp);
            } else if peer_supports_ext_multipacket {
                mp.extend_from_slice(&self.file_hash);
                mp.extend_from_slice(&self.file_size.to_le_bytes()); // EXT: file size
            } else {
                mp.extend_from_slice(&self.file_hash);
            }
            mp.push(OP_REQUESTFILENAME);
            if peer_extended_requests_ver > 0 {
                mp.extend_from_slice(&(wire_part_count as u16).to_le_bytes());
                let bitmap_bytes = (wire_part_count + 7) / 8;
                mp.extend(std::iter::repeat_n(0u8, bitmap_bytes));
                if peer_extended_requests_ver > 1 {
                    mp.extend_from_slice(&0u16.to_le_bytes());
                }
            }
            if !single_part {
                mp.push(OP_SETREQFILEID);
            }
            if sx_allowed {
                if peer_supports_source_ex2 {
                    mp.push(OP_REQUESTSOURCES2);
                    mp.push(SOURCEEXCHANGE2_VERSION);
                    mp.extend_from_slice(&0u16.to_le_bytes());
                } else {
                    mp.push(OP_REQUESTSOURCES);
                }
            }
            if peer_supports_aich && !peer_supports_file_ident {
                mp.push(OP_AICHFILEHASHREQ);
            }
            let mp_opcode = if peer_supports_file_ident {
                OP_MULTIPACKET_EXT2
            } else if peer_supports_ext_multipacket {
                OP_MULTIPACKET_EXT
            } else {
                OP_MULTIPACKET
            };
            write_packet_async(&mut writer, OP_EMULEPROT, mp_opcode, &mp).await?;
            if sx_allowed {
                if let Some(sm) = &self.source_manager {
                    let mut sm = sm.write().await;
                    if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                        sm.mark_sx_sent(&self.file_hash, v4, self.source_addr.port());
                    }
                }
            }
        } else {
            write_packet_async(
                &mut writer,
                OP_EDONKEYHEADER,
                OP_REQUESTFILENAME,
                &req_file_name_payload,
            )
            .await?;
            if !single_part {
                write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_SETREQFILEID, &file_req)
                    .await?;
            }
        }

        // Identify Ember only once the vanilla file request is on the wire —
        // same placement and rationale as `multi_source.rs`: eMule's sequence
        // is Hello → EmuleInfo → RequestFilename / MultiPacket, and an unknown
        // opcode spliced into the middle of that is what anti-leech mods
        // fingerprint. Vanilla eMule ignores 0xF8. The peer's HELLOANSWER is
        // picked up by the file-status-wait loop below.
        if !sent_ember_hello {
            let payload = build_ember_hello(
                &self.ember_hash,
                &self.our_nickname,
                Some(&self.ed25519_public_key),
            );
            if write_packet_async(&mut writer, OP_EMULEPROT, OP_EMBER_HELLO, &payload)
                .await
                .is_ok()
            {
                sent_ember_hello = true;
            }
        }

        // Read FileStatus and FileName responses
        // AICH root harvested from an `OP_AICHFILEHASHANS` sub-answer inside a
        // MultiPacket reply, held until `aich_master_hash` is declared below.
        let mut mp_aich_root: Option<[u8; 20]> = None;
        let mut got_status = single_part;
        let mut got_filename = false;
        let mut available_parts: Vec<bool> = if single_part { vec![true] } else { Vec::new() };

        for _ in 0..12 {
            let (proto, opcode, payload) = if let Some(pkt) = deferred_packet.take() {
                pkt
            } else if let Some(pkt) = auth_deferred.pop_front() {
                // Drain any remaining auth-captured packets before
                // reading fresh bytes off the stream. Same rationale
                // as the pre-control loop above: the uploader's
                // proactive opcodes must be processed in arrival
                // order so SecIdent state stays consistent.
                pkt
            } else {
                read_packet_with_timeout(&mut reader)
                    .await
                    .context("stage:file_status_wait")?
            };

            match (proto, opcode) {
                (OP_EDONKEYHEADER, OP_FILESTATUS) => {
                    // One bad packet must not end the session. `?` here let a
                    // 17-byte `OP_FILESTATUS` (or one carrying any other MD4)
                    // tear the whole download down — a single packet a hostile
                    // or buggy peer sends for free — and because neither error
                    // carried a `stage:` prefix the UI reported it as a generic
                    // transient failure rather than a handshake one. The
                    // multi-source twin ignores the packet and keeps waiting;
                    // do the same, and let the loop's own bound decide when to
                    // give up.
                    let Ok((hash, parts)) = parse_file_status(&payload) else {
                        debug!(
                            "Ignoring malformed OP_FILESTATUS ({} bytes) from {}",
                            payload.len(),
                            self.source_addr
                        );
                        continue;
                    };
                    if hash != self.file_hash {
                        debug!(
                            "Ignoring FileStatus for wrong file from {}: expected={} got={}",
                            self.source_addr,
                            hex::encode(self.file_hash),
                            hex::encode(hash)
                        );
                        continue;
                    }
                    if parts.is_empty() {
                        // Only trust the `part_count == 0` "complete file"
                        // sentinel for single-part files. Multi-part peers
                        // sending it have proven unreliable in the wild (see
                        // the identical Fix D rationale in
                        // `multi_source.rs`); leave `available_parts` empty
                        // (== "unknown, assume available" to `needed_parts`)
                        // rather than reporting false 100% availability.
                        if single_part {
                            debug!(
                                "FileStatus: part_count=0 → peer has complete file ({} parts)",
                                part_count
                            );
                            available_parts = vec![true; part_count.max(1)];
                        } else {
                            debug!(
                                "FileStatus: part_count=0 for multi-part file ({} parts) — treating as unverified",
                                part_count
                            );
                            available_parts = Vec::new();
                        }
                    } else {
                        debug!("FileStatus: {} parts", parts.len());
                        let mut padded = parts;
                        // Resize unconditionally: pad a short bitmap AND
                        // truncate a long one. Only padding left
                        // `available_parts.len()` at whatever the peer
                        // declared (up to `ED2K_MAX_WIRE_PARTS`), and
                        // `src_avail_parts` / `src_total_parts` are derived
                        // straight from it — so a peer could make the source
                        // row claim more parts than the file has. Matches the
                        // multi-source path.
                        padded.resize(part_count, false);
                        available_parts = padded;
                    }
                    got_status = true;
                }
                (OP_EDONKEYHEADER, OP_REQFILENAMEANSWER) => {
                    got_filename = true;
                    debug!("Got filename answer");
                }
                (OP_EDONKEYHEADER, OP_FILEREQANSNOFIL) => {
                    anyhow::bail!("peer does not have the file");
                }
                // OP_QUEUEFULL shares 0x93 with OP_MULTIPACKETANSWER (matched
                // below). Empty payload is QueueFull; a real multipacket answer
                // carries at least a 16-byte hash. Without this arm the peer's
                // "you're queued, no slot" answer fell through to the generic
                // handler and surfaced as a FileStatus failure.
                (OP_EMULEPROT, OP_QUEUEFULL) if payload.is_empty() => {
                    self.file_req_overhead.record_download(6u64);
                    self.emit_source_detail(
                        event_tx,
                        "queue_full",
                        None,
                        0,
                        0,
                        &client_software_label,
                        &peer_name_label,
                    )
                    .await;
                    anyhow::bail!("peer queue is full");
                }
                (OP_EDONKEYHEADER, OP_ACCEPTUPLOADREQ) => {
                    early_upload_accept = true;
                    debug!("Received early AcceptUploadReq during file-status wait");
                }
                (OP_EMULEPROT, OP_EMULEINFOANSWER) | (OP_EMULEPROT, OP_EMULEINFO) => {
                    let mut peer_caps = initial_caps.clone();
                    merge_caps(&mut peer_caps, parse_emule_info(&payload));
                    let peer_udp = peer_caps.udp_port;
                    if peer_udp > 0 {
                        peer_udp_port = peer_udp;
                    }
                    peer_supports_large_files = peer_caps.supports_large_files;
                    // `is_ember` / `ember_hash` come from `OP_EMBER_HELLO` /
                    // `OP_EMBER_HELLOANSWER` only — see the identical
                    // rationale above (`parse_emule_info` never sets either
                    // field, so assigning from `peer_caps` here would
                    // clobber an already-established Ember identity).
                    client_software_label = client_software_from_caps(&peer_caps);
                    if !peer_caps.peer_name.is_empty() {
                        peer_name_label = peer_caps.peer_name.clone();
                    }
                    if peer_udp > 0 {
                        if let Some(sm) = &self.source_manager {
                            let mut sm = sm.write().await;
                            if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                sm.register_observed_peer_ports(
                                    self.file_hash,
                                    v4,
                                    self.source_addr.port(),
                                    peer_caps.tcp_port,
                                    peer_udp,
                                    peer_user_hash,
                                    peer_caps.is_high_id(),
                                );
                            }
                        }
                    }
                    if opcode == OP_EMULEINFO {
                        let emule_answer = build_emule_info(
                            self.udp_port,
                            self.obfuscation_enabled,
                            Some(&self.ember_hash),
                            None,
                        );
                        let _ = write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_EMULEINFOANSWER,
                            &emule_answer,
                        )
                        .await;
                        debug!("Received peer OP_EMULEINFO during file-status wait, replied");
                    } else {
                        debug!("Ignoring delayed EmuleInfoAnswer during file-status wait");
                    }
                }
                (OP_EMULEPROT, OP_PUBLICKEY) if !payload.is_empty() => {
                    let key = if payload.len() >= 2 && payload[0] as usize == payload.len() - 1 {
                        payload[1..].to_vec()
                    } else {
                        payload.clone()
                    };
                    if let Some(cm) = &self.credit_manager {
                        let mut cm = cm.write().await;
                        if !cm.set_public_key(peer_user_hash, key) {
                            debug!(
                                "Ignoring OP_PUBLICKEY from {}: a different key is already bound to this user hash",
                                self.source_addr
                            );
                        }
                    }
                    if pending_secident_challenge.is_none() {
                        pending_secident_challenge = maybe_send_secident_challenge(
                            &mut writer,
                            self.credit_manager.as_ref(),
                            peer_user_hash,
                            self.source_addr,
                            peer_secure_ident_level,
                        )
                        .await?;
                    }
                }
                (OP_EMULEPROT, OP_SECIDENTSTATE) if payload.len() >= 5 => {
                    respond_to_secident_challenge(
                        &mut writer,
                        self.credit_manager.as_ref(),
                        payload[0],
                        u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]),
                        self.source_addr,
                        peer_user_hash,
                        peer_secure_ident_level,
                        our_client_id,
                    )
                    .await?;
                }
                (OP_EMULEPROT, OP_SIGNATURE) if payload.len() >= 2 => {
                    handle_secident_signature(
                        self.credit_manager.as_ref(),
                        peer_user_hash,
                        &mut pending_secident_challenge,
                        self.source_addr,
                        peer_secure_ident_level,
                        &payload,
                        our_client_id,
                    )
                    .await;
                }
                (OP_EMULEPROT, OP_MULTIPACKETANSWER)
                | (OP_EMULEPROT, OP_MULTIPACKETANSWER_EXT2) => {
                    if let Ok(mp) = parse_multipacket_answer(&payload, opcode) {
                        let local_ident = FileIdentifier {
                            md4_hash: self.file_hash,
                            file_size: Some(self.file_size),
                            aich_hash: None,
                        };
                        if mp.file_hash != self.file_hash
                            || mp
                                .file_identifier
                                .as_ref()
                                .map(|id| !local_ident.compare_relaxed(id))
                                .unwrap_or(false)
                        {
                            continue;
                        }
                        if mp.no_file {
                            anyhow::bail!("peer does not have the file");
                        }
                        // Stash the AICH root we asked for; it is applied once
                        // `aich_master_hash` exists, below. See the identical
                        // site in `multi_source.rs` for why dropping it
                        // disabled block-level recovery for every peer we ask.
                        if mp_aich_root.is_none() {
                            mp_aich_root = mp.aich_hash;
                        }
                        if let Some(parts) = mp.file_status {
                            if parts.is_empty() {
                                // See the standalone OP_FILESTATUS branch above:
                                // only trust the sentinel for single-part files.
                                if single_part {
                                    debug!("FileStatus via MultiPacket: part_count=0 → peer has complete file ({} parts)", part_count);
                                    available_parts = vec![true; part_count.max(1)];
                                } else {
                                    debug!("FileStatus via MultiPacket: part_count=0 for multi-part file ({} parts) — treating as unverified", part_count);
                                    available_parts = Vec::new();
                                }
                            } else {
                                debug!("FileStatus via MultiPacket: {} parts", parts.len());
                                let mut padded = parts;
                                // Pad short, truncate long — see the standalone
                                // `OP_FILESTATUS` branch above.
                                padded.resize(part_count, false);
                                available_parts = padded;
                            }
                            got_status = true;
                        }
                        if mp.file_name.is_some() {
                            got_filename = true;
                            debug!("Got filename answer via MultiPacket");
                        }
                    }
                }
                // EPX is Ember-only; gate on HELLO + hash↔pubkey binding.
                // Friend privileges still require PoP / secure_v2.
                (OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE)
                    if peer_is_ember && ember_hash_binding_verified =>
                {
                    self.epx_overhead
                        .record_download((6 + payload.len()) as u64);
                    if epx_packets_received >= crate::network::ember::MAX_EPX_PACKETS_PER_CONNECTION
                    {
                        debug!("Ignoring excess EPX packet from {}", self.source_addr);
                    } else {
                        epx_packets_received += 1;
                        match crate::network::ember::parse_exchange_payload(&payload) {
                            Ok(result)
                                if !result.files.is_empty()
                                    || !result.peers.is_empty()
                                    || !result.relay_attestations.is_empty() =>
                            {
                                info!(
                                    "Received Ember Peer Exchange from {} ({} files, {} peers, {} relay attestations)",
                                    self.source_addr,
                                    result.files.len(),
                                    result.peers.len(),
                                    result.relay_attestations.len()
                                );
                                let (epx_entries, aich_roots) = epx_result_to_entries(&result);
                                let relay_attestations = result.relay_attestations.clone();
                                let ember_peers = result
                                    .peers
                                    .into_iter()
                                    .map(|p| (p.ip, p.tcp_port))
                                    .collect();
                                let _ = event_tx
                                    .send(DownloadEvent::EmberSources {
                                        transfer_id: self.transfer_id.clone(),
                                        entries: epx_entries,
                                        aich_roots,
                                        ember_peers,
                                        relay_attestations,
                                        from_ember_hash: peer_ember_hash,
                                    })
                                    .await;
                            }
                            Ok(_) => {}
                            Err(e) => debug!(
                                "Failed to parse Ember exchange from {}: {e}",
                                self.source_addr
                            ),
                        }
                    }
                }
                (OP_EMULEPROT, OP_EMBER_FRIEND_REQ) if peer_is_ember => {
                    if let Some(eh) = peer_ember_hash {
                        let nick = crate::security::normalize_inbound_friend_nickname(&payload);
                        // Prefer the full PoP signal over the
                        // binding-only fallback. Both flags are set in
                        // the OP_EMBER_HELLO arms above / in the
                        // pre-control loop, so by the time we reach
                        // file-status-wait most well-behaved peers
                        // have already flipped `ember_auth_verified`.
                        // PoP-only (binding is replayable; see early
                        // friend-request site).
                        let verified = ember_auth_verified;
                        let _ = event_tx
                            .send(DownloadEvent::EmberFriendRequest {
                                ember_hash: eh,
                                pubkey: peer_ember_pubkey,
                                nickname: nick,
                                peer_ip: self.source_addr.ip().to_string(),
                                peer_port: super::advertised_listen_port(
                                    initial_caps.tcp_port,
                                    self.source_addr.port(),
                                ),
                                verified,
                            })
                            .await;
                    }
                }
                // Peer may delay their `OP_EMBER_HELLOANSWER` past the
                // pre-control loop — in which case it lands here.
                // Same handling: update identity, run the offline
                // binding check, echo our HELLOANSWER if they sent
                // a HELLO rather than an answer.
                (OP_EMULEPROT, OP_EMBER_HELLO) | (OP_EMULEPROT, OP_EMBER_HELLOANSWER) => {
                    if let Some(ident) = parse_ember_hello(&payload) {
                        peer_is_ember = true;
                        // Identity lock (see pre-control arm).
                        let identity_changed = ember_auth_verified
                            && ((ident.ed25519_pubkey.is_some()
                                && peer_ember_pubkey.is_some()
                                && ident.ed25519_pubkey != peer_ember_pubkey)
                                || (ident.ember_hash != [0u8; 16]
                                    && peer_ember_hash.is_some()
                                    && Some(ident.ember_hash) != peer_ember_hash));
                        if identity_changed {
                            tracing::warn!(
                                "Ember identity-swap rejected from {} (file-status-wait): peer already PoP-verified",
                                self.source_addr,
                            );
                        }
                        if ident.ember_hash != [0u8; 16] && !identity_changed {
                            peer_ember_hash = Some(ident.ember_hash);
                        }
                        if let Some(pk) = ident.ed25519_pubkey {
                            if !identity_changed {
                                peer_ember_pubkey = Some(pk);
                            }
                        }
                        if !ident.nickname.is_empty() {
                            peer_name_label = ident.nickname.clone();
                        }
                        debug!(
                            "Peer {} identified as Ember via OP_EMBER_HELLO during file-status-wait (mod='{}', nick='{}')",
                            self.source_addr, ident.mod_version, ident.nickname
                        );
                        if opcode == OP_EMBER_HELLO && !sent_ember_hello {
                            let payload = build_ember_hello(
                                &self.ember_hash,
                                &self.our_nickname,
                                Some(&self.ed25519_public_key),
                            );
                            let _ = write_packet_async(
                                &mut writer,
                                OP_EMULEPROT,
                                OP_EMBER_HELLOANSWER,
                                &payload,
                            )
                            .await;
                            sent_ember_hello = true;
                        }
                        if !ember_hash_binding_verified {
                            if let (Some(ref pk), Some(ref eh)) =
                                (peer_ember_pubkey, peer_ember_hash)
                            {
                                if crate::network::ember::crypto::verify_ember_hash_binding(pk, eh)
                                {
                                    ember_hash_binding_verified = true;
                                    info!(
                                        "Ember binding: peer {} pubkey BLAKE3-binds (file-status-wait)",
                                        self.source_addr
                                    );
                                    if peer_user_hash != [0u8; 16] {
                                        if let Some(cm) = &self.credit_manager {
                                            cm.write().await.note_bound_ember_hash(peer_user_hash, *eh);
                                        }
                                    }
                                    if peer_is_ember && !mesh_discovered_emitted {
                                        if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                            let peer_tcp = self.source_addr.port();
                                            if peer_tcp > 0 && !crate::security::is_bogus_v4(v4) {
                                                let _ = event_tx
                                                    .send(DownloadEvent::EmberPeerDiscovered {
                                                        ip: v4,
                                                        tcp_port: peer_tcp,
                                                        udp_port: peer_udp_port,
                                                    })
                                                    .await;
                                                mesh_discovered_emitted = true;
                                            }
                                        }
                                    }
                                    if peer_is_ember && initial_epx_sent_generation.is_none() {
                                        let sent_gen = self
                                            .ember_payload_generation
                                            .load(std::sync::atomic::Ordering::Relaxed);
                                        let epx_data = self.ember_payload.read().await.clone();
                                        if !epx_data.is_empty() {
                                            debug!(
                                                "Sending Ember Peer Exchange to newly bound peer {} ({} bytes, gen {})",
                                                self.source_addr,
                                                epx_data.len(),
                                                sent_gen
                                            );
                                            if write_packet_async(
                                                &mut writer,
                                                OP_EMULEPROT,
                                                OP_EMBER_SOURCEEXCHANGE,
                                                &epx_data,
                                            )
                                            .await
                                            .is_ok()
                                            {
                                                self.epx_overhead
                                                    .record_upload((6 + epx_data.len()) as u64);
                                                initial_epx_sent_generation = Some(sent_gen);
                                            }
                                        } else {
                                            initial_epx_sent_generation = Some(sent_gen);
                                        }
                                    }
                                } else {
                                    tracing::warn!(
                                        "Ember binding: peer {} advertised pubkey does not BLAKE3-bind to ember_hash={} (file-status-wait, possible spoof)",
                                        self.source_addr,
                                        hex::encode(eh)
                                    );
                                }
                            }
                        }

                        // Run PoP here too in case the peer delayed
                        // OP_EMBER_HELLOANSWER past the pre-control
                        // loop. Same buffering rationale: captured
                        // non-AUTH frames are drained on subsequent
                        // iterations of this file-status-wait loop.
                        // Secure friend-stream v2 is the only live friend
                        // authenticator; generic eD2K must not expose v1 PoP.
                        if super::LEGACY_FRIEND_AUTH_ENABLED
                            && !ember_auth_verified
                            && ember_hash_binding_verified
                        {
                            if let (Some(peer_pk), Some(peer_eh)) =
                                (peer_ember_pubkey, peer_ember_hash)
                            {
                                match super::friend_connect::perform_ember_auth_buffered(
                                    &mut reader,
                                    &mut writer,
                                    &self.ed25519_public_key,
                                    &self.ed25519_secret_key,
                                    &peer_pk,
                                    Some(&peer_eh),
                                    self.source_addr,
                                    &mut auth_deferred,
                                )
                                .await
                                {
                                    Ok(()) => {
                                        ember_auth_verified = true;
                                        info!(
                                            "Ember auth: peer {} verified via PoP during file-status-wait ({} deferred packet(s) queued for replay)",
                                            self.source_addr,
                                            auth_deferred.len()
                                        );
                                        // Feed the mesh now that PoP has
                                        // verified this peer (see the
                                        // gate comment where this is
                                        // normally emitted right after
                                        // the initial handshake).
                                        if !mesh_discovered_emitted {
                                            if let std::net::IpAddr::V4(v4) = self.source_addr.ip()
                                            {
                                                let peer_tcp = self.source_addr.port();
                                                if peer_tcp > 0 && !crate::security::is_bogus_v4(v4)
                                                {
                                                    let _ = event_tx
                                                        .send(DownloadEvent::EmberPeerDiscovered {
                                                            ip: v4,
                                                            tcp_port: peer_tcp,
                                                            udp_port: peer_udp_port,
                                                        })
                                                        .await;
                                                    mesh_discovered_emitted = true;
                                                }
                                            }
                                        }
                                        if initial_epx_sent_generation.is_none() {
                                            let sent_gen = self
                                                .ember_payload_generation
                                                .load(std::sync::atomic::Ordering::Relaxed);
                                            let epx_data = self.ember_payload.read().await.clone();
                                            if !epx_data.is_empty() {
                                                debug!(
                                                    "Sending Ember Peer Exchange to newly verified peer {} ({} bytes, gen {})",
                                                    self.source_addr,
                                                    epx_data.len(),
                                                    sent_gen
                                                );
                                                if write_packet_async(
                                                    &mut writer,
                                                    OP_EMULEPROT,
                                                    OP_EMBER_SOURCEEXCHANGE,
                                                    &epx_data,
                                                )
                                                .await
                                                .is_ok()
                                                {
                                                    self.epx_overhead
                                                        .record_upload((6 + epx_data.len()) as u64);
                                                    initial_epx_sent_generation = Some(sent_gen);
                                                }
                                            } else {
                                                initial_epx_sent_generation = Some(sent_gen);
                                            }
                                        }
                                        if !friend_seen_emitted {
                                            if let (true, Some(eh)) =
                                                (peer_is_friend, peer_ember_hash)
                                            {
                                                // See the comment on the other
                                                // `FriendSeen` emission in this file.
                                                let friend_port = if initial_caps.tcp_port > 0 {
                                                    initial_caps.tcp_port
                                                } else {
                                                    self.source_addr.port()
                                                };
                                                let _ = event_tx
                                                    .send(DownloadEvent::FriendSeen {
                                                        ember_hash: eh,
                                                        ip: self.source_addr.ip(),
                                                        port: friend_port,
                                                    })
                                                    .await;
                                                friend_seen_emitted = true;
                                                if !friend_request_sent {
                                                    let nick_bytes = self.our_nickname.as_bytes();
                                                    if write_packet_async(
                                                        &mut writer,
                                                        OP_EMULEPROT,
                                                        OP_EMBER_FRIEND_REQ,
                                                        nick_bytes,
                                                    )
                                                    .await
                                                    .is_ok()
                                                    {
                                                        friend_request_sent = true;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Ember auth: peer {} PoP failed (file-status-wait) — continuing with binding-only verification: {e}",
                                            self.source_addr
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                (OP_EMULEPROT, OP_EMBER_CHAT_MSG)
                | (OP_EMULEPROT, OP_EMBER_BROWSE_REQ)
                | (OP_EMULEPROT, OP_EMBER_BROWSE_RES) => {
                    debug!("Dropping friend-only opcode on generic eD2K transfer");
                }
                _ => {
                    debug!("Ignoring packet proto=0x{proto:02X} op=0x{opcode:02X}");
                }
            }

            if got_status {
                break;
            }
        }

        if !got_status && (got_filename || early_upload_accept) {
            // eMule-compatible fallback: some peers answer filename but omit FileStatus.
            // Continue optimistically with all parts potentially available.
            available_parts = vec![true; part_count.max(1)];
            got_status = true;
            debug!("Proceeding without FileStatus (filename/accept fallback)");
        }

        if !got_status {
            anyhow::bail!("stage:file_status_wait never received FileStatus");
        }

        let src_avail_parts: Option<u32> =
            Some(available_parts.iter().filter(|&&p| p).count() as u32);
        let src_total_parts: Option<u32> = Some(available_parts.len() as u32);

        // Request part hashset for verification
        if peer_supports_file_ident {
            let hashset_req2 =
                build_hashset_request2(&self.file_hash, self.file_size, None, true, false);
            write_packet_async(&mut writer, OP_EMULEPROT, OP_HASHSETREQUEST2, &hashset_req2)
                .await?;
            self.file_req_overhead
                .record_upload((6 + hashset_req2.len()) as u64);
        } else {
            let hashset_req = build_hashset_request(&self.file_hash);
            write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_HASHSETREQ, &hashset_req).await?;
            self.file_req_overhead
                .record_upload((6 + hashset_req.len()) as u64);
        }

        let mut part_hashes: Vec<[u8; 16]> = Vec::new();
        let mut aich_master_hash: Option<[u8; 20]> = self.trusted_aich_master;
        // Apply an AICH root harvested from the MultiPacket answer. Same voting
        // rule as the HashSet2 root, so an unverified single source cannot pin.
        if let Some(root) = mp_aich_root {
            consider_hashset2_aich_pin(&mut aich_master_hash, self.expected_aich_master, None, "", root);
        }
        if aich_master_hash.is_some() {
            debug!(
                "Seeded trusted AICH master for callback download {}",
                self.transfer_id
            );
        }
        // Try to read hashset answer. The peer may send other packets
        // (SecIdent, EmuleInfo) before the hashset, so read up to 5 packets.
        for _hs_attempt in 0..5u32 {
            match read_packet_with_timeout(&mut reader)
                .await
                .context("stage:hashset_wait")
            {
                Ok((proto, opcode, payload)) => {
                    if proto == OP_EDONKEYHEADER && opcode == OP_HASHSETANSWER {
                        self.file_req_overhead
                            .record_download((6 + payload.len()) as u64);
                        match parse_hashset_answer(&payload) {
                            Ok((_hash, hashes)) => {
                                if verify_hashset(&self.file_hash, &hashes, self.file_size) {
                                    debug!(
                                        "Got verified hashset with {} part hashes",
                                        hashes.len()
                                    );
                                    part_hashes = hashes;
                                } else {
                                    warn!("Hashset verification failed - combined hash doesn't match file hash");
                                }
                            }
                            Err(e) => debug!("Failed to parse hashset answer: {e}"),
                        }
                        break;
                    } else if proto == OP_EMULEPROT && opcode == OP_HASHSETANSWER2 {
                        self.file_req_overhead
                            .record_download((6 + payload.len()) as u64);
                        match parse_hashset_answer2(&payload) {
                            Ok(resp) => {
                                let local_ident = FileIdentifier {
                                    md4_hash: self.file_hash,
                                    file_size: Some(self.file_size),
                                    aich_hash: None,
                                };
                                if !local_ident.compare_relaxed(&resp.identifier) {
                                    anyhow::bail!("hashsetanswer2 file identifier mismatch");
                                }
                                // Match multi_source: pin AICH only after the
                                // accompanying MD4 hashset verifies against the
                                // file's ed2k hash. Otherwise a callback peer can
                                // first-win a bogus master and poison recovery.
                                let md4_ok = resp
                                    .md4_hashes
                                    .as_ref()
                                    .map(|h| verify_hashset(&self.file_hash, h, self.file_size))
                                    .unwrap_or(false);
                                if md4_ok {
                                    if let Some(hashes) = resp.md4_hashes {
                                        debug!(
                                            "Got verified hashset2 with {} part hashes",
                                            hashes.len()
                                        );
                                        part_hashes = hashes;
                                    }
                                    if aich_master_hash.is_none() {
                                        if let Some(root) = resp.aich_master_hash {
                                            consider_hashset2_aich_pin(
                                                &mut aich_master_hash,
                                                self.expected_aich_master,
                                                None,
                                                "",
                                                root,
                                            );
                                            if aich_master_hash == Some(root) {
                                                debug!(
                                                    "Got HashSet2 AICH data: master={}, parts={}",
                                                    hex::encode(root),
                                                    resp.aich_part_hashes
                                                        .as_ref()
                                                        .map(|p| p.len())
                                                        .unwrap_or(0)
                                                );
                                            }
                                        }
                                    }
                                } else if resp.aich_master_hash.is_some() {
                                    warn!(
                                        "HashSet2 had an AICH master but the MD4 hashset failed or was absent — deferring AICH pin"
                                    );
                                }
                            }
                            Err(e) => debug!("Failed to parse hashset answer2: {e}"),
                        }
                        break;
                    } else if proto == OP_EDONKEYHEADER && opcode == OP_ACCEPTUPLOADREQ {
                        self.file_req_overhead
                            .record_download((6 + payload.len()) as u64);
                        early_upload_accept = true;
                        debug!("Received AcceptUploadReq while waiting for hashset — stopping hashset wait");
                        break;
                    } else {
                        debug!("Waiting for hashset, got proto=0x{proto:02X} op=0x{opcode:02X} — skipping");
                    }
                }
                Err(e) if is_packet_stream_desynced(&e) => return Err(e),
                Err(e) => {
                    debug!("No hashset answer (peer may not support it): {e}");
                    break;
                }
            }
        }

        // Request source exchange only when not already sent in multipacket, and throttled.
        // eMule asks only a peer with SX2 or an SX1 version above 1.
        if !(peer_supports_file_ident || peer_supports_ext_multipacket || peer_supports_multipacket)
            && sx_allowed
            && (peer_supports_source_ex2 || peer_source_exchange_ver > 1)
        {
            if peer_supports_source_ex2 {
                let mut sx2_req = Vec::with_capacity(19);
                sx2_req.push(SOURCEEXCHANGE2_VERSION);
                sx2_req.extend_from_slice(&0u16.to_le_bytes());
                sx2_req.extend_from_slice(&self.file_hash);
                write_packet_async(&mut writer, OP_EMULEPROT, OP_REQUESTSOURCES2, &sx2_req).await?;
                self.sx_overhead.record_upload((6 + sx2_req.len()) as u64);
            } else {
                let sx_req = build_file_request(&self.file_hash);
                write_packet_async(&mut writer, OP_EMULEPROT, OP_REQUESTSOURCES, &sx_req).await?;
                self.sx_overhead.record_upload((6 + sx_req.len()) as u64);
            }
            if let Some(sm) = &self.source_manager {
                let mut sm = sm.write().await;
                if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                    sm.mark_sx_sent(&self.file_hash, v4, self.source_addr.port());
                }
            }
        }

        if early_upload_accept {
            debug!("Using early AcceptUploadReq without sending StartUploadReq");
            self.emit_source_detail_parts(
                event_tx,
                "transferring",
                None,
                0,
                0,
                &client_software_label,
                &peer_name_label,
                src_avail_parts,
                src_total_parts,
            )
            .await;
            let _ = event_tx
                .send(DownloadEvent::SourcesUpdate {
                    transfer_id: self.transfer_id.clone(),
                    total: 1,
                    active: 1,
                    queued: 0,
                })
                .await;
        } else {
            // Inside eMule's MIN_REQUESTTIME of our last ask we are still on
            // its queue, and asking again only counts toward `BADCLIENTBAN`.
            let ask_ports = [self.source_addr.port(), initial_caps.tcp_port];
            let source_v4 = match self.source_addr.ip() {
                std::net::IpAddr::V4(v4) => Some(v4),
                _ => None,
            };
            let ask_wait = source_v4.and_then(|v4| {
                super::peer_sessions::upload_request_wait(
                    Some(peer_user_hash),
                    v4,
                    &ask_ports,
                    &self.file_hash,
                )
            });
            if let Some(wait) = ask_wait {
                debug!(
                    "Not re-sending StartUploadReq to {} ({}s left of MIN_REQUESTTIME)",
                    self.source_addr,
                    wait.as_secs()
                );
            } else {
                let upload_req = build_file_request(&self.file_hash);
                write_packet_async(
                    &mut writer,
                    OP_EDONKEYHEADER,
                    OP_STARTUPLOADREQ,
                    &upload_req,
                )
                .await?;
                self.file_req_overhead
                    .record_upload((6 + upload_req.len()) as u64);
                if let Some(v4) = source_v4 {
                    super::peer_sessions::note_upload_request(
                        Some(peer_user_hash),
                        v4,
                        &ask_ports,
                        self.file_hash,
                    );
                }
            }

            let _ = event_tx
                .send(DownloadEvent::SourcesUpdate {
                    transfer_id: self.transfer_id.clone(),
                    total: 1,
                    active: 0,
                    queued: 1,
                })
                .await;

            // Wait for AcceptUploadReq. The uploader decides when to grant a slot;
            // we simply keep the connection open and listen. Re-requesting too
            // aggressively gets clients penalised by eMule servers.
            let queue_start = std::time::Instant::now();
            self.emit_source_detail_parts(
                event_tx,
                "queued",
                None,
                0,
                0,
                &client_software_label,
                &peer_name_label,
                src_avail_parts,
                src_total_parts,
            )
            .await;

            loop {
                self.check_control().await?;

                let qwait = self.ed2k_limits.queue_wait_secs;
                if queue_start.elapsed().as_secs() > qwait {
                    anyhow::bail!(
                        "stage:queue_wait timed out waiting for upload slot after {qwait}s"
                    );
                }

                // Use a longer timeout while queued — the uploader will push
                // OP_ACCEPTUPLOADREQ when a slot opens. We use the full queue
                // wait budget as the read timeout so we don't time out early.
                let remaining = qwait - queue_start.elapsed().as_secs().min(qwait);
                let read_timeout = remaining.max(30);

                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(read_timeout),
                    read_packet_async(&mut reader),
                )
                .await;

                let (proto, opcode, payload) = match result {
                    Ok(Ok(p)) => p,
                    Ok(Err(e)) => {
                        anyhow::bail!("stage:queue_detached connection lost while queued: {e}")
                    }
                    Err(_) => {
                        anyhow::bail!(
                            "stage:queue_wait timed out waiting for upload slot after {qwait}s"
                        );
                    }
                };

                if proto == OP_EDONKEYHEADER && opcode == OP_ACCEPTUPLOADREQ {
                    self.file_req_overhead
                        .record_download((6 + payload.len()) as u64);
                    debug!("Upload accepted");
                    self.emit_source_detail_parts(
                        event_tx,
                        "transferring",
                        None,
                        0,
                        0,
                        &client_software_label,
                        &peer_name_label,
                        src_avail_parts,
                        src_total_parts,
                    )
                    .await;
                    let _ = event_tx
                        .send(DownloadEvent::SourcesUpdate {
                            transfer_id: self.transfer_id.clone(),
                            total: 1,
                            active: 1,
                            queued: 0,
                        })
                        .await;
                    break;
                }

                if proto == OP_EMULEPROT && opcode == OP_QUEUEFULL && payload.is_empty() {
                    self.file_req_overhead.record_download(6u64);
                    self.emit_source_detail_parts(
                        event_tx,
                        "queue_full",
                        None,
                        0,
                        0,
                        &client_software_label,
                        &peer_name_label,
                        src_avail_parts,
                        src_total_parts,
                    )
                    .await;
                    anyhow::bail!("stage:queue_wait peer queue is full");
                }

                if proto == OP_EMULEPROT && opcode == OP_QUEUERANKING && payload.len() >= 2 {
                    self.file_req_overhead
                        .record_download((6 + payload.len()) as u64);
                    let rank = u16::from_le_bytes([payload[0], payload[1]]);
                    info!("Queued at position {} on peer {}", rank, self.source_addr);
                    self.emit_source_detail_parts(
                        event_tx,
                        "queued",
                        Some(rank as u32),
                        0,
                        0,
                        &client_software_label,
                        &peer_name_label,
                        src_avail_parts,
                        src_total_parts,
                    )
                    .await;
                    continue;
                }

                if proto == OP_EDONKEYHEADER && opcode == OP_QUEUERANK && payload.len() >= 4 {
                    let rank = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    info!(
                        "Queued at position {} on peer {} (legacy)",
                        rank, self.source_addr
                    );
                    self.emit_source_detail_parts(
                        event_tx,
                        "queued",
                        Some(rank),
                        0,
                        0,
                        &client_software_label,
                        &peer_name_label,
                        src_avail_parts,
                        src_total_parts,
                    )
                    .await;
                    continue;
                }

                if proto == OP_EMULEPROT && opcode == OP_ANSWERSOURCES && payload.len() >= 18 {
                    self.sx_overhead.record_download((6 + payload.len()) as u64);
                    match parse_answer_sources(&payload, peer_source_exchange_ver) {
                        Ok((version, answer_hash, entries)) if answer_hash == self.file_hash => {
                            let mut sx_count = 0u32;
                            let mut sx_entries: Vec<SourceExchangeEntry> = Vec::new();
                            for entry in entries {
                                if entry.tcp_port == 0 {
                                    continue;
                                }
                                let uh = entry.user_hash.unwrap_or([0u8; 16]);
                                let co = entry.crypt_options.unwrap_or(0);
                                // LowID source — see the matching block in
                                // `multi_source.rs` for the full rationale.
                                // eMule registers these via the named server
                                // and uses the callback path; dropping them
                                // silently halved our source pool on
                                // LowID-heavy networks.
                                // Normalize to eMule's hybrid (host-order) ID
                                // before classifying — SX versions < 3 send it
                                // byte-swapped, so a raw `< 16M` test would
                                // mis-read a LowID peer as a HighID.
                                let hybrid_id = source_exchange_hybrid_id(version, entry.source_id);
                                if hybrid_id < 16_777_216 {
                                    if entry.server_ip == 0 || entry.server_port == 0 {
                                        continue;
                                    }
                                    if let Some(sm) = &self.source_manager {
                                        let mut sm = sm.write().await;
                                        sm.register_lowid_source(
                                            self.file_hash,
                                            hybrid_id,
                                            entry.tcp_port,
                                            entry.server_ip,
                                            entry.server_port,
                                            uh,
                                            co,
                                            // Another peer passed this on; the
                                            // server address is only how the
                                            // callback gets relayed.
                                            Some(crate::types::SourceOrigin::Exchange),
                                        );
                                    }
                                    sx_count += 1;
                                    continue;
                                }
                                let ip = source_exchange_id_to_ipv4(version, entry.source_id);
                                if is_filtered_source_ip(&ip)
                                    || self.is_sx_source_rejected(&ip, entry.tcp_port)
                                {
                                    continue;
                                }
                                if let Some(sm) = &self.source_manager {
                                    let mut sm = sm.write().await;
                                    sm.register_source_full_server(
                                        self.file_hash,
                                        ip,
                                        entry.tcp_port,
                                        0,
                                        entry.server_ip,
                                        entry.server_port,
                                        uh,
                                        co,
                                        // Another peer handed us this address;
                                        // `entry.server_ip` is the server that
                                        // peer uses, not who told us.
                                        Some(crate::types::SourceOrigin::Exchange),
                                    );
                                }
                                sx_entries.push(SourceExchangeEntry {
                                    ip,
                                    tcp_port: entry.tcp_port,
                                    user_hash: uh,
                                    crypt_options: co,
                                });
                                sx_count += 1;
                            }
                            if sx_count > 0 {
                                debug!("Legacy source exchange: registered {sx_count} new sources from {}", self.source_addr);
                                let _ = event_tx
                                    .send(DownloadEvent::SourceExchange {
                                        transfer_id: self.transfer_id.clone(),
                                        file_hash: self.file_hash,
                                        sources: sx_entries,
                                    })
                                    .await;
                            }
                        }
                        Ok((_version, answer_hash, _)) => {
                            debug!(
                                "Ignoring OP_ANSWERSOURCES from {} for different file {}",
                                self.source_addr,
                                hex::encode(answer_hash)
                            );
                        }
                        Err(e) => debug!(
                            "Failed to parse OP_ANSWERSOURCES from {}: {e}",
                            self.source_addr
                        ),
                    }
                    continue;
                }

                if proto == OP_EMULEPROT && opcode == OP_ANSWERSOURCES2 && payload.len() >= 19 {
                    self.sx_overhead.record_download((6 + payload.len()) as u64);
                    match parse_answer_sources2(&payload) {
                        Ok((version, answer_hash, entries)) if answer_hash == self.file_hash => {
                            let mut sx_count = 0u32;
                            let mut sx_entries: Vec<SourceExchangeEntry> = Vec::new();
                            for entry in entries {
                                if entry.tcp_port == 0 {
                                    continue;
                                }
                                let uh = entry.user_hash.unwrap_or([0u8; 16]);
                                let co = entry.crypt_options.unwrap_or(0);
                                // Same LowID handling as the SX1 arm above —
                                // register with the named server so the
                                // callback path can reach this peer instead
                                // of dropping it outright.
                                let hybrid_id = source_exchange_hybrid_id(version, entry.source_id);
                                if hybrid_id < 16_777_216 {
                                    if entry.server_ip == 0 || entry.server_port == 0 {
                                        continue;
                                    }
                                    if let Some(sm) = &self.source_manager {
                                        let mut sm = sm.write().await;
                                        sm.register_lowid_source(
                                            self.file_hash,
                                            hybrid_id,
                                            entry.tcp_port,
                                            entry.server_ip,
                                            entry.server_port,
                                            uh,
                                            co,
                                            // Another peer passed this on; the
                                            // server address is only how the
                                            // callback gets relayed.
                                            Some(crate::types::SourceOrigin::Exchange),
                                        );
                                    }
                                    sx_count += 1;
                                    continue;
                                }
                                let ip = source_exchange_id_to_ipv4(version, entry.source_id);
                                if is_filtered_source_ip(&ip)
                                    || self.is_sx_source_rejected(&ip, entry.tcp_port)
                                {
                                    continue;
                                }
                                if entry.server_ip != 0 {
                                    debug!(
                                        "SX2 source {} advertises server {:08X}:{}",
                                        ip, entry.server_ip, entry.server_port
                                    );
                                }
                                if let Some(sm) = &self.source_manager {
                                    let mut sm = sm.write().await;
                                    sm.register_source_full_server(
                                        self.file_hash,
                                        ip,
                                        entry.tcp_port,
                                        0,
                                        entry.server_ip,
                                        entry.server_port,
                                        uh,
                                        co,
                                        // Another peer handed us this address;
                                        // `entry.server_ip` is the server that
                                        // peer uses, not who told us.
                                        Some(crate::types::SourceOrigin::Exchange),
                                    );
                                }
                                sx_entries.push(SourceExchangeEntry {
                                    ip,
                                    tcp_port: entry.tcp_port,
                                    user_hash: uh,
                                    crypt_options: co,
                                });
                                sx_count += 1;
                            }
                            if sx_count > 0 {
                                debug!(
                                    "Source exchange: registered {sx_count} new sources from {}",
                                    self.source_addr
                                );
                                let _ = event_tx
                                    .send(DownloadEvent::SourceExchange {
                                        transfer_id: self.transfer_id.clone(),
                                        file_hash: self.file_hash,
                                        sources: sx_entries,
                                    })
                                    .await;
                            }
                        }
                        Ok((_version, answer_hash, _)) => {
                            debug!(
                                "Ignoring OP_ANSWERSOURCES2 from {} for different file {}",
                                self.source_addr,
                                hex::encode(answer_hash)
                            );
                        }
                        Err(e) => debug!(
                            "Failed to parse OP_ANSWERSOURCES2 from {}: {e}",
                            self.source_addr
                        ),
                    }
                    continue;
                }

                if proto == OP_EDONKEYHEADER && opcode == OP_OUTOFPARTREQS {
                    info!("Peer rejected with OutOfPartReqs, will retry later");
                    self.emit_source_detail_parts(
                        event_tx,
                        "no_needed_parts",
                        None,
                        0,
                        0,
                        &client_software_label,
                        &peer_name_label,
                        src_avail_parts,
                        src_total_parts,
                    )
                    .await;
                    anyhow::bail!("peer has no free upload slots (OutOfPartReqs)");
                }

                debug!("Waiting for accept, got proto=0x{proto:02X} op=0x{opcode:02X}");
            }
        }

        let max_dl = self.ed2k_limits.max_download_bytes;
        if self.file_size > max_dl {
            anyhow::bail!(
                "file size {} exceeds maximum allowed ({})",
                self.file_size,
                max_dl
            );
        }

        // `.part` files live in `<part_root>/Temp`, completed files go to the
        // `Downloads` of whichever download folder is current at completion.
        let (part_root, temp_dir) =
            prepare_part_dir(&self.download_folders, &self.transfer_id).await?;
        let allowed_roots = vec![part_root.to_string_lossy().into_owned()];

        let part_path = temp_dir.join(format!("{}.part", self.transfer_id));

        let file_size = self.file_size;
        let load_path = part_path.clone();
        let expected_file_hash = self.file_hash;
        let mut tracker = tokio::task::spawn_blocking(move || {
            PartTracker::new_with_identity(file_size, &load_path, expected_file_hash)
        })
        .await
        .map_err(|e| anyhow::anyhow!("part tracker load task failed: {e}"))?;

        // A `.part.met` claiming progress with no `.part` beside it means the
        // sidecar is stale — the user deleted the data file, or a crash left it
        // behind. `sync_to_on_disk_part_length` deliberately returns early when
        // `metadata()` fails, and its own comment defers the case to "the resume
        // reset path": `multi_source.rs` has one, and this path did not.
        //
        // The consequence is not a stuck download. The restored bitmap's
        // complete-*and-verified* bits survive onto a `.part` that is about to
        // be `set_len` to zeros, `needed_parts()` comes back empty so nothing is
        // ever fetched, and `is_range_safe_to_serve` — the gate the upload path
        // uses — then reports those zeroed parts as verified and serves them to
        // peers as MD4-checked data.
        if tracker.completed_bytes() > 0 && !part_path.exists() {
            warn!(
                "Part tracker shows progress but .part file is missing for {} — resetting",
                self.transfer_id
            );
            tracker = PartTracker::new_empty(self.file_size, &part_path);
        }

        tracker.set_file_hash(self.file_hash);
        tracker.set_file_name(&self.file_name);
        apply_control_rename(&self.control, &mut tracker);
        if !part_hashes.is_empty() {
            tracker.set_part_hashes(part_hashes.clone());
        } else {
            // Seed live verification from the resumed `.part.met`, exactly as
            // the multi-source worker does. Without this the single-source
            // path ran with per-part MD4 verification disabled whenever the
            // peer never answered `OP_HASHSETREQ` (a LowID callback peer that
            // does not serve hashsets, say) — even though the tracker had just
            // loaded a verified hashset from disk. Nothing was ever marked
            // verified, the AICH narrowing block became unreachable, the
            // download advertised zero serveable parts for its whole life, and
            // a single corrupt block went unnoticed until the whole-file hash
            // at 100%, which then reset every part for re-download.
            //
            // The sidecar set is subject to the same `verify_hashset` gate as a
            // peer-supplied hashset: it becomes authoritative for every per-part
            // MD4, so a corrupt one would fail every part forever while its
            // non-empty state suppressed the OP_HASHSETREQ that would replace it.
            let resumed = tracker.part_hashes().to_vec();
            if !resumed.is_empty() {
                if verify_hashset(&self.file_hash, &resumed, self.file_size) {
                    debug!(
                        "Seeding {} part hash(es) from resumed .part.met for {}",
                        resumed.len(),
                        self.file_name
                    );
                    part_hashes = resumed;
                } else {
                    warn!(
                        "Resumed .part.met hashset for {} failed verification against {} — discarding it and re-fetching from a peer",
                        self.file_name,
                        hex::encode(self.file_hash),
                    );
                    tracker.clear_part_hashes_and_verified();
                    super::part_tracker::save_snapshot_async(tracker.snapshot_for_save()).await;
                }
            }
        }

        // Publish initial preview-readiness onto the shared transfer control so
        // the UI's Preview button is correct on resume (first part already
        // verified on disk). Refreshed below as parts verify.
        let preview_name = completed_download_name(tracker.file_name(), &self.file_name);
        self.control
            .set_preview_ready(tracker.is_preview_ready(&preview_name, self.file_size));

        // Per-file writer: dedicated thread + bounded channel replaces the
        // previous `Arc<Mutex<File>>`-with-`spawn_blocking`-per-block pattern
        // that serialized all writes on a single mutex. See
        // `network::ed2k::write_coordinator` for design notes.
        let output = {
            let completed_bytes = tracker.completed_bytes();
            let completed_parts = tracker.completed_count();
            let total_parts = tracker.part_count;
            let existing_len = if part_path.exists() {
                tokio::fs::metadata(&part_path)
                    .await
                    .map(|m| m.len())
                    .unwrap_or(0)
            } else {
                0
            };
            // Never truncate a non-empty .part when .part.met reports 0 completed bytes
            // (e.g. corrupt/missing metadata) — that would destroy recoverable data.
            let resuming = completed_bytes > 0 || existing_len > 0;
            if resuming {
                if completed_bytes > 0 {
                    info!("Resuming download: {completed_parts}/{total_parts} parts complete");
                } else {
                    warn!(
                        "Preserving non-empty .part ({existing_len} bytes) while resume metadata shows no completed bytes — \
                         .part.met may be missing or corrupt"
                    );
                }
            }
            super::write_coordinator::PartFileWriter::open(
                part_path.clone(),
                super::write_coordinator::OpenMode::CreateOrOpen {
                    set_len_to: if self.file_size > 0 {
                        Some(self.file_size)
                    } else {
                        None
                    },
                    truncate_existing: !resuming,
                },
                allowed_roots.clone(),
                Some(self.control.discarding_flag()),
            )
            .await
            .map_err(|e| download_folder_error("opening the part file", &part_root, e))?
        };

        let mut downloaded: u64 = tracker.completed_bytes();

        // Download needed parts with retry for hash-failed parts.
        // eMule-style adaptive pipelining: sends 1-3 OP_REQUESTPARTS_I64 packets
        // simultaneously based on connection speed, keeping the peer's upload pipe full.
        const MAX_BLOCKS_PER_REQUEST: usize = 3;
        let max_part_rounds = self.ed2k_limits.part_retry_rounds;
        let mut measured_speed: u64 = 0;
        let mut speed_measure_start = std::time::Instant::now();
        let mut speed_measure_bytes: u64 = 0;
        let mut last_periodic_save = std::time::Instant::now();
        const PERIODIC_SAVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

        // Throttle DownloadEvent::Progress emission. The DB persist side is
        // already throttled (3s), but the Tauri UI emit and the
        // transfer_manager.write() happen per-event, so a fast peer with
        // ~180 KiB blocks otherwise hits the webview hundreds of times per
        // second. ~200 ms is smooth enough for the UI without saturating it.
        let mut last_progress_emit = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_millis(500))
            .unwrap_or_else(std::time::Instant::now);
        const PROGRESS_EMIT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);
        let mut last_epx_resend = std::time::Instant::now();
        // Use the generation we sent at handshake as the resend baseline so
        // any rebuild during file-status / queue wait gets re-sent on the
        // first periodic check. Falls back to current generation when we
        // never sent (peer not Ember, or our payload was empty at the time).
        let mut last_epx_generation = initial_epx_sent_generation.unwrap_or_else(|| {
            self.ember_payload_generation
                .load(std::sync::atomic::Ordering::Relaxed)
        });
        const EPX_RESEND_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

        for retry_round in 0..=max_part_rounds {
            let mut needed = tracker.needed_parts(&available_parts);
            if needed.is_empty() {
                break;
            }

            // eMule-style preview priority: move first and last parts to front
            if self.control.is_preview_priority() && needed.len() > 1 {
                let last_part = tracker.part_count.saturating_sub(1);
                let mut front = Vec::new();
                if let Some(pos) = needed.iter().position(|&p| p == 0) {
                    front.push(needed.remove(pos));
                }
                if last_part > 0 {
                    if let Some(pos) = needed.iter().position(|&p| p == last_part) {
                        front.push(needed.remove(pos));
                    }
                }
                front.extend(needed);
                needed = front;
            }
            if retry_round > 0 {
                debug!(
                    "Retry round {}/{} for {} hash-failed parts",
                    retry_round,
                    max_part_rounds,
                    needed.len()
                );
            }

            for part_idx in needed {
                self.check_control().await?;
                let mut aich_recovery_data: Option<([u8; 20], Vec<u8>)> = None;

                let (part_start, part_end) = tracker.part_range(part_idx);

                // Request only the missing byte ranges within this part, like eMule's gap-based requests.
                let all_blocks: Vec<(u64, u64)> = tracker
                    .gap_list()
                    .iter()
                    .filter_map(|&(gs, ge)| {
                        let start = gs.max(part_start);
                        let end = ge.min(part_end);
                        (start < end).then_some((start, end))
                    })
                    .flat_map(|(start, end)| {
                        let mut blocks = Vec::new();
                        let mut cursor = start;
                        while cursor < end {
                            let chunk_end = (cursor + EMBLOCKSIZE).min(end);
                            blocks.push((cursor, chunk_end));
                            cursor = chunk_end;
                        }
                        blocks
                    })
                    .collect();

                // Group blocks into request batches of 3 (OP_REQUESTPARTS_I64 limit)
                let batches: Vec<Vec<(u64, u64)>> = all_blocks
                    .chunks(MAX_BLOCKS_PER_REQUEST)
                    .map(|c| c.to_vec())
                    .collect();

                let max_outstanding = outstanding_requests_for_speed_with_remaining(
                    measured_speed,
                    tracker.remaining_count(),
                    tracker.remaining_gap_bytes(),
                );
                let mut sent_idx: usize = 0;
                let mut total_sent_bytes: u64 = 0;
                let mut total_received: u64 = 0;
                // D12: credits accrue only for bytes that end up in a
                // verified part. `pending_credit_bytes` accumulates received
                // bytes; on part verification we flush to the credit
                // ledger, on mismatch we drop the tally.
                let mut pending_credit_bytes: u64 = 0;
                let mut consecutive_bad_blocks: u32 = 0;
                const MAX_CONSECUTIVE_BAD_BLOCKS: u32 = 5;

                // Match eMule: only use I64 when offsets actually exceed 32-bit range
                let has_large_offsets = all_blocks.iter().any(|&(_, end)| end > u32::MAX as u64);
                let needs_i64 = peer_supports_large_files && has_large_offsets;

                // If blocks exceed 4 GiB but the peer doesn't support large files,
                // filter them out to avoid sending (0,0) clamped garbage requests.
                if has_large_offsets && !peer_supports_large_files {
                    debug!(
                        "Skipping part {} — offsets exceed 4 GiB but peer lacks large-file support",
                        part_idx
                    );
                    continue;
                }

                // Send initial batch of requests to fill the pipeline
                let mut outstanding_ranges: Vec<OutstandingRange> = Vec::new();
                while sent_idx < batches.len() && sent_idx < max_outstanding {
                    let batch = &batches[sent_idx];
                    let (req_payload, req_proto, req_op) = if needs_i64 {
                        (
                            build_request_parts_i64(&self.file_hash, batch),
                            OP_EMULEPROT,
                            OP_REQUESTPARTS_I64,
                        )
                    } else {
                        (
                            build_request_parts(&self.file_hash, batch),
                            OP_EDONKEYHEADER,
                            OP_REQUESTPARTS,
                        )
                    };
                    write_packet_async(&mut writer, req_proto, req_op, &req_payload).await?;
                    total_sent_bytes += batch.iter().map(|(s, e)| e - s).sum::<u64>();
                    push_outstanding_batch(&mut outstanding_ranges, batch);
                    sent_idx += 1;
                }

                // Track completed requested ranges (not packets) for pipeline refill
                let mut blocks_received_in_current_req: usize = 0;
                let mut completed_reqs: usize = 0;
                let mut pending_compressed = CompressedPartAccumulator::default();
                let data_loop_start = std::time::Instant::now();
                let mut got_any_data = false;
                const INITIAL_DATA_TIMEOUT_SECS: u64 = 60;

                // Receive loop: process blocks and refill pipeline as requests complete
                while total_received < total_sent_bytes {
                    self.check_control().await?;

                    // Periodic EPX re-send: if payload has been rebuilt and 5min elapsed
                    if peer_is_ember
                        && ember_hash_binding_verified
                        && last_epx_resend.elapsed() >= EPX_RESEND_INTERVAL
                    {
                        let current_gen = self
                            .ember_payload_generation
                            .load(std::sync::atomic::Ordering::Relaxed);
                        if current_gen != last_epx_generation {
                            let epx_data = self.ember_payload.read().await.clone();
                            if !epx_data.is_empty() {
                                debug!(
                                    "Re-sending EPX to {} (gen {}->{}, {} bytes)",
                                    self.source_addr,
                                    last_epx_generation,
                                    current_gen,
                                    epx_data.len()
                                );
                                // Only advance the generation marker on a
                                // successful write; otherwise a failed/back-
                                // pressured send would suppress the retry on
                                // the next interval (mirrors upload.rs).
                                if write_packet_async(
                                    &mut writer,
                                    OP_EMULEPROT,
                                    OP_EMBER_SOURCEEXCHANGE,
                                    &epx_data,
                                )
                                .await
                                .is_ok()
                                {
                                    last_epx_generation = current_gen;
                                    self.epx_overhead.record_upload((6 + epx_data.len()) as u64);
                                }
                            } else {
                                // Empty payload is terminal for this generation
                                // (nothing to send); advance so we don't re-check
                                // the same empty gen every interval.
                                last_epx_generation = current_gen;
                            }
                        }
                        last_epx_resend = std::time::Instant::now();
                    }

                    let read_timeout = if got_any_data {
                        std::time::Duration::from_secs(READ_TIMEOUT_SECS)
                    } else {
                        let elapsed = data_loop_start.elapsed();
                        let budget = std::time::Duration::from_secs(INITIAL_DATA_TIMEOUT_SECS);
                        budget
                            .saturating_sub(elapsed)
                            .max(std::time::Duration::from_secs(1))
                    };

                    let packet_started = std::sync::atomic::AtomicBool::new(false);
                    let read_outcome = if let Some(packet) = auth_deferred.pop_front() {
                        Ok(Ok(packet))
                    } else {
                        let mut read_fut = std::pin::pin!(read_packet_marking_start(
                            &mut reader,
                            &packet_started
                        ));
                        let mut hard_deadline = tokio::time::Instant::now() + read_timeout;
                        let mut expire_tick =
                            tokio::time::interval(std::time::Duration::from_secs(2));
                        expire_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                        expire_tick.tick().await;
                        loop {
                            tokio::select! {
                                biased;
                                // User Stop/Cancel (or a network disconnect) landed
                                // while we're actively downloading from this callback
                                // source. Mirror eMule's CPartFile::PauseFile: send
                                // OP_CANCELTRANSFER so the uploader frees our slot
                                // immediately rather than waiting to notice the dropped
                                // TCP socket. Best-effort + time-boxed, then bail.
                                // Fires on Pause too (eMule's PauseFile notifies every
                                // DS_DOWNLOADING source); the Failed handler ignores the
                                // resulting unwind because the transfer is already
                                // marked Paused.
                                _ = self.control.wait_cancel_or_pause() => {
                                    let _ = tokio::time::timeout(
                                        std::time::Duration::from_millis(400),
                                        write_packet_async(
                                            &mut writer, OP_EDONKEYHEADER, OP_CANCELTRANSFER, &[],
                                        ),
                                    ).await;
                                    // This callback/single-source path isn't registered in
                                    // `tracker_registry` (only multi-source downloads are), so
                                    // `PauseDownload`'s `save_registered_part_tracker` is a
                                    // no-op here and the task is `abort()`'d right after this
                                    // command returns — without an explicit save here, up to
                                    // `PERIODIC_SAVE_INTERVAL` (60s) of gap-tracking progress
                                    // on the in-flight part would be silently lost on pause.
                                    super::part_tracker::save_snapshot_async(tracker.snapshot_for_save()).await;
                                    anyhow::bail!("cancelled by user");
                                }
                                res = &mut read_fut => break Ok(res),
                                _ = tokio::time::sleep_until(hard_deadline) => break Err(()),
                                _ = expire_tick.tick() => {
                                    let expired = expire_outstanding_ranges(&mut outstanding_ranges);
                                    if expired == 0 {
                                        continue;
                                    }
                                    total_sent_bytes = total_sent_bytes.saturating_sub(expired);
                                    while sent_idx < batches.len()
                                        && outstanding_ranges.len()
                                            < max_outstanding * MAX_BLOCKS_PER_REQUEST
                                    {
                                        let batch = &batches[sent_idx];
                                        let (req_payload, req_proto, req_op) = if needs_i64 {
                                            (
                                                build_request_parts_i64(&self.file_hash, batch),
                                                OP_EMULEPROT,
                                                OP_REQUESTPARTS_I64,
                                            )
                                        } else {
                                            (
                                                build_request_parts(&self.file_hash, batch),
                                                OP_EDONKEYHEADER,
                                                OP_REQUESTPARTS,
                                            )
                                        };
                                        write_packet_async(
                                            &mut writer, req_proto, req_op, &req_payload,
                                        )
                                        .await?;
                                        total_sent_bytes +=
                                            batch.iter().map(|(s, e)| e - s).sum::<u64>();
                                        push_outstanding_batch(&mut outstanding_ranges, batch);
                                        sent_idx += 1;
                                    }
                                    if total_received >= total_sent_bytes
                                        && !packet_started
                                            .load(std::sync::atomic::Ordering::Relaxed)
                                    {
                                        break Err(());
                                    }
                                    hard_deadline = tokio::time::Instant::now() + read_timeout;
                                    continue;
                                }
                            }
                        }
                    };
                    let (proto, opcode, payload) = match read_outcome {
                        Ok(Ok(pkt)) => pkt,
                        Ok(Err(e)) => return Err(e.into()),
                        Err(()) => {
                            let mid_packet =
                                packet_started.load(std::sync::atomic::Ordering::Relaxed);
                            if total_received >= total_sent_bytes && !mid_packet {
                                continue;
                            }
                            let _ = write_packet_async(
                                &mut writer,
                                OP_EDONKEYHEADER,
                                OP_CANCELTRANSFER,
                                &[],
                            )
                            .await;
                            if mid_packet {
                                return Err(anyhow::Error::from(packet_stream_desynced_error())
                                    .context(format!(
                                        "stage:data_wait download timeout: stalled mid-packet for {}s",
                                        read_timeout.as_secs()
                                    )));
                            }
                            if !got_any_data {
                                debug!("Source {} accepted transfer but sent no data in {}s — disconnecting",
                                    self.source_addr, INITIAL_DATA_TIMEOUT_SECS);
                                anyhow::bail!(
                                    "peer accepted transfer but sent no data in {}s",
                                    INITIAL_DATA_TIMEOUT_SECS
                                );
                            } else {
                                anyhow::bail!(
                                    "stage:data_wait download timeout: no data for {}s",
                                    READ_TIMEOUT_SECS
                                );
                            }
                        }
                    };

                    match (proto, opcode) {
                        (OP_EMULEPROT, OP_SENDINGPART_I64) | (OP_EDONKEYHEADER, OP_SENDINGPART) => {
                            let (hash, start, end, data) = if opcode == OP_SENDINGPART_I64 {
                                parse_sending_part_i64(&payload)?
                            } else {
                                // Accept a 32-bit frame whatever the
                                // file size: the sender picks the
                                // opcode from the *block's* end
                                // offset, not the file size (eMule's
                                // CreateStandardPackets keys on
                                // `endpos > _UI32_MAX`), so blocks
                                // inside the first 4 GiB of a >4 GiB
                                // file legitimately arrive as a plain
                                // OP_SENDINGPART — which is what our
                                // per-block `needs_i64` asked for. The
                                // 32-bit parser widens u32 to u64, so
                                // nothing wraps, and a mis-addressed
                                // block is still caught by the range
                                // validation below, the gap trimming,
                                // and the per-part MD4.
                                parse_sending_part_32(&payload)?
                            };
                            if hash != self.file_hash {
                                anyhow::bail!(
                                    "peer sent SENDINGPART for wrong file: expected={} got={}",
                                    hex::encode(self.file_hash),
                                    hex::encode(hash)
                                );
                            }

                            if start >= end
                                || end > self.file_size
                                || data.len() != (end - start) as usize
                            {
                                consecutive_bad_blocks += 1;
                                debug!("Invalid block offsets: start={start}, end={end}, data_len={}, file_size={} (bad streak: {consecutive_bad_blocks})", data.len(), self.file_size);
                                if consecutive_bad_blocks >= MAX_CONSECUTIVE_BAD_BLOCKS {
                                    if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                        let _ = event_tx
                                            .send(DownloadEvent::ProtocolViolation {
                                                sender_ip: v4,
                                                sender_user_hash: Some(peer_user_hash),
                                            })
                                            .await;
                                    }
                                    anyhow::bail!("peer sent {consecutive_bad_blocks} consecutive invalid blocks, disconnecting");
                                }
                                continue;
                            }
                            consecutive_bad_blocks = 0;
                            let piece_len = end - start;
                            self.acquire_download_bandwidth(piece_len).await?;
                            // Every byte the peer sent, counted before the gap
                            // check below decides which were needed — eMule's
                            // `m_uTransferred += transize` (`PartFile.cpp:3957`).
                            tracker.add_transferred(piece_len);

                            // Never overwrite bytes we already have. Write ONLY the
                            // gap sub-ranges of this block, not the whole block: a
                            // duplicate/overlapping (or cross-part) re-send must not
                            // replace already-present, possibly MD4-verified, data on
                            // disk while `part_verified` stays set (which the upload
                            // path then serves as safe). The transfer counters below
                            // still account the full piece.
                            let fill_subranges = tracker.fillable_subranges(start, end);
                            let mut newly_written = 0u64;
                            if !fill_subranges.is_empty() {
                                // Per-file writer thread serializes the writes for
                                // us; await is just an mpsc round-trip.
                                for &(gs, ge) in &fill_subranges {
                                    // `start <= gs <= ge <= end` and `data.len() ==
                                    // end - start` are guaranteed by the validation
                                    // above; saturating_sub keeps these offsets sound
                                    // even if that coupling is ever loosened.
                                    let off = gs.saturating_sub(start) as usize;
                                    let len = ge.saturating_sub(gs) as usize;
                                    if let Err(e) =
                                        output.write(gs, data[off..off + len].to_vec()).await
                                    {
                                        // Earlier subranges have already reached
                                        // disk and the tracker. Persist that state
                                        // before this single-source task unwinds.
                                        if newly_written > 0 {
                                            super::part_tracker::save_snapshot_async(
                                                tracker.snapshot_for_save(),
                                            )
                                            .await;
                                        }
                                        if e.kind() == std::io::ErrorKind::StorageFull
                                            || is_disk_full_error(&e.to_string())
                                        {
                                            return Err(anyhow::anyhow!(
                                                "stage:insufficient_disk part write at {gs}: {e}"
                                            ));
                                        }
                                        return Err(anyhow::anyhow!("part write at {gs}: {e}"));
                                    }
                                    // Commit immediately after each successful
                                    // write. Deferring all fill_range calls until
                                    // the loop ends loses earlier writes if a
                                    // later subrange fails.
                                    newly_written =
                                        newly_written.saturating_add(tracker.fill_range(gs, ge));
                                }

                                if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                    let _ = event_tx
                                        .send(DownloadEvent::DataReceived {
                                            file_hash: self.file_hash,
                                            start,
                                            end,
                                            sender_ip: v4,
                                            sender_user_hash: Some(peer_user_hash),
                                        })
                                        .await;
                                }
                            }

                            if !got_any_data {
                                info!(
                                    "Source {} first data received for part {} ({} bytes)",
                                    self.source_addr, part_idx, piece_len
                                );
                                got_any_data = true;
                            }
                            // Count only bytes that actually filled a gap toward the
                            // displayed progress and per-source speed. A duplicate or
                            // overlapping block (empty `fill_subranges`) consumes wire
                            // bandwidth but adds no new data, so charging `downloaded`
                            // and speed the full piece would over-report until the next
                            // `tracker.completed_bytes()` correction. `total_received`
                            // still tracks wire bytes — the round's exit condition
                            // compares it against what the peer announced it would send.
                            total_received += piece_len;
                            downloaded += newly_written;
                            if take_completed_outstanding_range(
                                &mut outstanding_ranges,
                                start,
                                end,
                            ) {
                                blocks_received_in_current_req += 1;
                            }
                            speed_measure_bytes += newly_written;

                            // D12: defer credit until the part verifies. Credit only
                            // the bytes actually written (gap-overlap sub-ranges), not
                            // the full wire piece — a duplicate/overlapping block adds
                            // no new data and must not inflate the peer's credit.
                            pending_credit_bytes =
                                pending_credit_bytes.saturating_add(newly_written);

                            if last_progress_emit.elapsed() >= PROGRESS_EMIT_INTERVAL {
                                let progress = tracker.progress_bytes().min(self.file_size);
                                let _ = event_tx.try_send(DownloadEvent::Progress {
                                    transfer_id: self.transfer_id.clone(),
                                    downloaded: progress,
                                    transferred: Some(tracker.transferred()),
                                    total: self.file_size,
                                });
                                last_progress_emit = std::time::Instant::now();
                            }
                        }
                        (OP_EMULEPROT, OP_COMPRESSEDPART_I64)
                        | (OP_EMULEPROT, OP_COMPRESSEDPART) => {
                            let (hash, start, compressed_total_size, compressed) =
                                if opcode == OP_COMPRESSEDPART_I64 {
                                    parse_compressed_part_i64(&payload)?
                                } else {
                                    // Mirror the OP_SENDINGPART branch: accept
                                    // 32-bit frames for files of any size. eMule
                                    // picks the width from the requested block's
                                    // end offset (CreatePackedPackets keys on
                                    // `uEndOffset > UINT32_MAX`), so blocks below
                                    // 4 GiB in a larger file arrive as plain
                                    // OP_COMPRESSEDPART. Nothing truncates here —
                                    // the 32-bit parser widens u32 to u64 — and
                                    // `pending_compressed.append` only accepts a
                                    // start matching a block we actually
                                    // requested.
                                    parse_compressed_part_32(&payload)?
                                };
                            if hash != self.file_hash {
                                anyhow::bail!(
                                    "peer sent COMPRESSEDPART for wrong file: expected={} got={}",
                                    hex::encode(self.file_hash),
                                    hex::encode(hash)
                                );
                            }
                            // Compressed length, counted per packet — eMule hands
                            // `WriteToBuffer` the same wire size for packed blocks
                            // as for plain ones (`DownloadClient.cpp:1066`), and
                            // counts each packet rather than each inflated block.
                            tracker.add_transferred(compressed.len() as u64);

                            let requested_end = batches.iter().take(sent_idx).flatten().find_map(
                                |(requested_start, requested_end)| {
                                    (*requested_start == start).then_some(*requested_end)
                                },
                            );
                            // See the matching branch in `multi_source.rs`: an
                            // unmatched start means the part moved on under us, not
                            // that the peer misbehaved, so discard the block
                            // instead of failing the whole session out.
                            let Some(requested_end) = requested_end else {
                                debug!(
                                    "Discarding compressed block at {start}: no outstanding request (part advanced)"
                                );
                                continue;
                            };
                            let Some(fragment) = pending_compressed.append(
                                start,
                                Some(requested_end),
                                compressed_total_size,
                                compressed,
                            )?
                            else {
                                refresh_outstanding_range(&mut outstanding_ranges, start);
                                continue;
                            };

                            // This packet's inflated bytes and where they belong —
                            // the block start only for the first packet. See the
                            // matching branch in `multi_source.rs`.
                            let decompressed = fragment.data;
                            let start = fragment.offset;
                            let piece_len = decompressed.len() as u64;
                            if start.saturating_add(piece_len) > self.file_size {
                                consecutive_bad_blocks += 1;
                                debug!("Compressed block exceeds file size: start={start}, len={piece_len}, file_size={} (bad streak: {consecutive_bad_blocks})", self.file_size);
                                if consecutive_bad_blocks >= MAX_CONSECUTIVE_BAD_BLOCKS {
                                    if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                        let _ = event_tx
                                            .send(DownloadEvent::ProtocolViolation {
                                                sender_ip: v4,
                                                sender_user_hash: Some(peer_user_hash),
                                            })
                                            .await;
                                    }
                                    anyhow::bail!("peer sent {consecutive_bad_blocks} consecutive invalid blocks, disconnecting");
                                }
                                continue;
                            }
                            consecutive_bad_blocks = 0;
                            self.acquire_download_bandwidth(piece_len).await?;

                            // D21 (compressed): write ONLY the gap sub-ranges of the
                            // decompressed block, never the whole block — see the
                            // uncompressed branch above. Prevents an overlapping or
                            // cross-part block from clobbering verified bytes.
                            let fill_subranges =
                                tracker.fillable_subranges(start, start + piece_len);
                            let mut newly_written = 0u64;
                            if !fill_subranges.is_empty() {
                                for &(gs, ge) in &fill_subranges {
                                    let off = (gs - start) as usize;
                                    let len = (ge - gs) as usize;
                                    if let Err(e) = output
                                        .write(gs, decompressed[off..off + len].to_vec())
                                        .await
                                    {
                                        if newly_written > 0 {
                                            super::part_tracker::save_snapshot_async(
                                                tracker.snapshot_for_save(),
                                            )
                                            .await;
                                        }
                                        if e.kind() == std::io::ErrorKind::StorageFull
                                            || is_disk_full_error(&e.to_string())
                                        {
                                            return Err(anyhow::anyhow!(
                                                "stage:insufficient_disk part write at {gs}: {e}"
                                            ));
                                        }
                                        return Err(anyhow::anyhow!("part write at {gs}: {e}"));
                                    }
                                    newly_written =
                                        newly_written.saturating_add(tracker.fill_range(gs, ge));
                                }

                                if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                    let _ = event_tx
                                        .send(DownloadEvent::DataReceived {
                                            file_hash: self.file_hash,
                                            start,
                                            end: start + piece_len,
                                            sender_ip: v4,
                                            sender_user_hash: Some(peer_user_hash),
                                        })
                                        .await;
                                }
                            }

                            if !got_any_data {
                                info!("Source {} first compressed data received for part {} ({} bytes)", self.source_addr, part_idx, piece_len);
                                got_any_data = true;
                            }
                            // See the uncompressed branch: only gap-filling bytes
                            // advance displayed progress and speed; duplicate/overlap
                            // blocks add wire bytes (counted in `total_received` for
                            // the round-exit check) but no new data.
                            total_received += piece_len;
                            downloaded += newly_written;
                            if take_completed_outstanding_range(
                                &mut outstanding_ranges,
                                start,
                                start + piece_len,
                            ) {
                                blocks_received_in_current_req += 1;
                            }
                            speed_measure_bytes += newly_written;

                            // D12: defer credit until the part verifies. Credit only
                            // the bytes actually written (gap-overlap sub-ranges), not
                            // the full wire piece — a duplicate/overlapping block adds
                            // no new data and must not inflate the peer's credit.
                            pending_credit_bytes =
                                pending_credit_bytes.saturating_add(newly_written);

                            if last_progress_emit.elapsed() >= PROGRESS_EMIT_INTERVAL {
                                let progress = tracker.progress_bytes().min(self.file_size);
                                let _ = event_tx.try_send(DownloadEvent::Progress {
                                    transfer_id: self.transfer_id.clone(),
                                    downloaded: progress,
                                    transferred: Some(tracker.transferred()),
                                    total: self.file_size,
                                });
                                last_progress_emit = std::time::Instant::now();
                            }
                        }
                        (OP_EDONKEYHEADER, OP_OUTOFPARTREQS) => {
                            // The uploader rotated us out and took the slot
                            // back. This path has no in-session re-queue, and
                            // carrying on sent the next round's requests into
                            // a slot we no longer held: every retry round went
                            // in milliseconds and the source was failed with a
                            // penalty. End as the queue state it is, like
                            // OP_QUEUEFULL above.
                            info!("Peer session limit reached (OutOfPartReqs), ending the session to re-queue");
                            self.emit_source_detail_parts(
                                event_tx,
                                "queued",
                                None,
                                0,
                                0,
                                &client_software_label,
                                &peer_name_label,
                                src_avail_parts,
                                src_total_parts,
                            )
                            .await;
                            anyhow::bail!("peer ended our upload slot (OutOfPartReqs)");
                        }
                        (OP_EMULEPROT, OP_QUEUEFULL) if payload.is_empty() => {
                            self.file_req_overhead.record_download(6u64);
                            self.emit_source_detail_parts(
                                event_tx,
                                "queue_full",
                                None,
                                0,
                                0,
                                &client_software_label,
                                &peer_name_label,
                                src_avail_parts,
                                src_total_parts,
                            )
                            .await;
                            anyhow::bail!("peer revoked upload slot (QueueFull during transfer)");
                        }
                        (OP_EMULEPROT, OP_QUEUERANKING) if payload.len() >= 2 => {
                            self.file_req_overhead
                                .record_download((6 + payload.len()) as u64);
                            let rank = u16::from_le_bytes([payload[0], payload[1]]);
                            self.emit_source_detail_parts(
                                event_tx,
                                "queued",
                                Some(rank as u32),
                                0,
                                0,
                                &client_software_label,
                                &peer_name_label,
                                src_avail_parts,
                                src_total_parts,
                            )
                            .await;
                            anyhow::bail!(
                                "peer put us back in queue at rank {} during transfer",
                                rank
                            );
                        }
                        (OP_EDONKEYHEADER, OP_QUEUERANK) if payload.len() >= 4 => {
                            let rank = u32::from_le_bytes([
                                payload[0], payload[1], payload[2], payload[3],
                            ]);
                            self.emit_source_detail_parts(
                                event_tx,
                                "queued",
                                Some(rank),
                                0,
                                0,
                                &client_software_label,
                                &peer_name_label,
                                src_avail_parts,
                                src_total_parts,
                            )
                            .await;
                            anyhow::bail!(
                                "peer put us back in queue at rank {} during transfer",
                                rank
                            );
                        }
                        (OP_EDONKEYHEADER, OP_FILEREQANSNOFIL) => {
                            anyhow::bail!(
                                "peer does not have the file any more (FileNotFound during transfer)"
                            );
                        }
                        (OP_EMULEPROT, OP_PUBLICKEY) if !payload.is_empty() => {
                            let key =
                                if payload.len() >= 2 && payload[0] as usize == payload.len() - 1 {
                                    payload[1..].to_vec()
                                } else {
                                    payload.clone()
                                };
                            if let Some(cm) = &self.credit_manager {
                                let mut cm = cm.write().await;
                                if !cm.set_public_key(peer_user_hash, key) {
                                    debug!(
                                        "Ignoring OP_PUBLICKEY from {}: a different key is already bound to this user hash",
                                        self.source_addr
                                    );
                                }
                            }
                            if pending_secident_challenge.is_none() {
                                pending_secident_challenge = maybe_send_secident_challenge(
                                    &mut writer,
                                    self.credit_manager.as_ref(),
                                    peer_user_hash,
                                    self.source_addr,
                                    peer_secure_ident_level,
                                )
                                .await?;
                            }
                        }
                        (OP_EMULEPROT, OP_SECIDENTSTATE) if payload.len() >= 5 => {
                            respond_to_secident_challenge(
                                &mut writer,
                                self.credit_manager.as_ref(),
                                payload[0],
                                u32::from_le_bytes([
                                    payload[1], payload[2], payload[3], payload[4],
                                ]),
                                self.source_addr,
                                peer_user_hash,
                                peer_secure_ident_level,
                                our_client_id,
                            )
                            .await?;
                        }
                        (OP_EMULEPROT, OP_SIGNATURE) if payload.len() >= 2 => {
                            handle_secident_signature(
                                self.credit_manager.as_ref(),
                                peer_user_hash,
                                &mut pending_secident_challenge,
                                self.source_addr,
                                peer_secure_ident_level,
                                &payload,
                                our_client_id,
                            )
                            .await;
                        }
                        // eMule OP_FILEDESC: peer sends comment/rating for the file
                        (OP_EMULEPROT, OP_FILEDESC) if payload.len() >= 5 => {
                            let rating = payload[0];
                            // The declared comment length is an attacker-controlled
                            // u32 bounded only by the (multi-MiB) packet size, so
                            // clamp it before reading/allocating: eMule file comments
                            // are short, and an unbounded `String` build is a cheap
                            // per-packet memory-pressure vector.
                            const MAX_PEER_COMMENT_LEN: usize = 8 * 1024;
                            let comment_len = (u32::from_le_bytes([
                                payload[1], payload[2], payload[3], payload[4],
                            ]) as usize)
                                .min(MAX_PEER_COMMENT_LEN);
                            if comment_len
                                .checked_add(5)
                                .is_some_and(|need| payload.len() >= need)
                            {
                                let comment = String::from_utf8_lossy(&payload[5..5 + comment_len])
                                    .to_string();
                                if let Some(cm) = &self.comment_manager {
                                    let mut cm = cm.write().await;
                                    cm.add_peer_comment(
                                        &hex::encode(self.file_hash),
                                        self.source_addr.to_string(),
                                        rating,
                                        comment.clone(),
                                        0,
                                    );
                                }
                                debug!("Peer comment: rating={rating}, comment='{comment}'");
                            }
                        }
                        // AICH recovery answer from peer. Bound the payload the
                        // same way `wait_for_aich_recovery_answer` does: the
                        // recovery blob can't legitimately exceed
                        // MAX_AICH_RECOVERY_BYTES, and without the upper bound a
                        // peer (who knows the public master hash) could force a
                        // multi-MB allocation held until part verification.
                        (OP_EMULEPROT, OP_AICHANSWER)
                            if (38..=38 + crate::network::ed2k::aich::MAX_AICH_RECOVERY_BYTES)
                                .contains(&payload.len()) =>
                        {
                            let mut ans_hash = [0u8; 16];
                            ans_hash.copy_from_slice(&payload[..16]);
                            let ans_part = u16::from_le_bytes([payload[16], payload[17]]) as usize;
                            let mut root_hash = [0u8; 20];
                            root_hash.copy_from_slice(&payload[18..38]);
                            let recovery_data = &payload[38..];
                            debug!(
                                "AICH answer: part={}, root={}, recovery={} bytes",
                                ans_part,
                                hex::encode(root_hash),
                                recovery_data.len()
                            );
                            if ans_hash == self.file_hash && ans_part == part_idx {
                                let master_ok = aich_master_hash == Some(root_hash);
                                if master_ok {
                                    aich_recovery_data = Some((root_hash, recovery_data.to_vec()));
                                } else {
                                    debug!(
                                        "Ignoring AICH answer: root {} != trusted master {:?}",
                                        hex::encode(root_hash),
                                        aich_master_hash.map(hex::encode)
                                    );
                                }
                            }
                        }
                        // EPX is Ember-only; gate on HELLO + hash↔pubkey binding.
                        // Friend privileges still require PoP / secure_v2.
                        (OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE)
                            if peer_is_ember && ember_hash_binding_verified =>
                        {
                            self.epx_overhead
                                .record_download((6 + payload.len()) as u64);
                            if epx_packets_received
                                >= crate::network::ember::MAX_EPX_PACKETS_PER_CONNECTION
                            {
                                debug!(
                                    "Ignoring excess EPX packet during download from {}",
                                    self.source_addr
                                );
                            } else {
                                epx_packets_received += 1;
                                match crate::network::ember::parse_exchange_payload(&payload) {
                                    Ok(result)
                                        if !result.files.is_empty()
                                            || !result.peers.is_empty()
                                            || !result.relay_attestations.is_empty() =>
                                    {
                                        info!("Received Ember Peer Exchange during download from {} ({} files, {} peers, {} relay attestations)", self.source_addr, result.files.len(), result.peers.len(), result.relay_attestations.len());
                                        let (epx_entries, aich_roots) =
                                            epx_result_to_entries(&result);
                                        let relay_attestations = result.relay_attestations.clone();
                                        let ember_peers = result
                                            .peers
                                            .into_iter()
                                            .map(|p| (p.ip, p.tcp_port))
                                            .collect();
                                        let _ = event_tx
                                            .send(DownloadEvent::EmberSources {
                                                transfer_id: self.transfer_id.clone(),
                                                entries: epx_entries,
                                                aich_roots,
                                                ember_peers,
                                                relay_attestations,
                                                from_ember_hash: peer_ember_hash,
                                            })
                                            .await;
                                    }
                                    Ok(_) => {}
                                    Err(e) => debug!("Failed to parse Ember exchange: {e}"),
                                }
                            }
                        }
                        (OP_EMULEPROT, OP_EMBER_FRIEND_REQ) if peer_is_ember => {
                            if let Some(eh) = peer_ember_hash {
                                let nick =
                                    crate::security::normalize_inbound_friend_nickname(&payload);
                                // By the time we reach the data loop
                                // the peer's Ember-Hello + PoP has
                                // usually completed in an earlier
                                // phase, so `ember_auth_verified` is
                                // the normal signal here. PoP-only —
                                // binding is replayable from public
                                // (pubkey, ember_hash) leaks (KAD,
                                // EPX, public trackers).
                                let verified = ember_auth_verified;
                                let _ = event_tx
                                    .send(DownloadEvent::EmberFriendRequest {
                                        ember_hash: eh,
                                        pubkey: peer_ember_pubkey,
                                        nickname: nick,
                                        peer_ip: self.source_addr.ip().to_string(),
                                        peer_port: super::advertised_listen_port(
                                            initial_caps.tcp_port,
                                            self.source_addr.port(),
                                        ),
                                        verified,
                                    })
                                    .await;
                            }
                        }
                        // Late Ember-Hello during the data loop. Some
                        // peers defer OP_EMBER_HELLOANSWER well past
                        // the handshake / file-status phases (e.g. Ember
                        // clients that wait for the first data exchange
                        // before publishing their identity). Handling
                        // it here keeps the binding flag accurate for
                        // any post-data friend requests.
                        (OP_EMULEPROT, OP_EMBER_HELLO) | (OP_EMULEPROT, OP_EMBER_HELLOANSWER) => {
                            if let Some(ident) = parse_ember_hello(&payload) {
                                peer_is_ember = true;
                                // Identity lock (see pre-control arm).
                                let identity_changed = ember_auth_verified
                                    && ((ident.ed25519_pubkey.is_some()
                                        && peer_ember_pubkey.is_some()
                                        && ident.ed25519_pubkey != peer_ember_pubkey)
                                        || (ident.ember_hash != [0u8; 16]
                                            && peer_ember_hash.is_some()
                                            && Some(ident.ember_hash) != peer_ember_hash));
                                if identity_changed {
                                    tracing::warn!(
                                        "Ember identity-swap rejected from {} (data-loop): peer already PoP-verified",
                                        self.source_addr,
                                    );
                                }
                                if ident.ember_hash != [0u8; 16] && !identity_changed {
                                    peer_ember_hash = Some(ident.ember_hash);
                                }
                                if let Some(pk) = ident.ed25519_pubkey {
                                    if !identity_changed {
                                        peer_ember_pubkey = Some(pk);
                                    }
                                }
                                if opcode == OP_EMBER_HELLO && !sent_ember_hello {
                                    let payload = build_ember_hello(
                                        &self.ember_hash,
                                        &self.our_nickname,
                                        Some(&self.ed25519_public_key),
                                    );
                                    let _ = write_packet_async(
                                        &mut writer,
                                        OP_EMULEPROT,
                                        OP_EMBER_HELLOANSWER,
                                        &payload,
                                    )
                                    .await;
                                    sent_ember_hello = true;
                                }
                                if !ember_hash_binding_verified {
                                    if let (Some(ref pk), Some(ref eh)) =
                                        (peer_ember_pubkey, peer_ember_hash)
                                    {
                                        if crate::network::ember::crypto::verify_ember_hash_binding(
                                            pk, eh,
                                        ) {
                                            ember_hash_binding_verified = true;
                                            info!(
                                                "Ember binding: peer {} pubkey BLAKE3-binds (data loop)",
                                                self.source_addr
                                            );
                                            if peer_user_hash != [0u8; 16] {
                                                if let Some(cm) = &self.credit_manager {
                                                    cm.write()
                                                        .await
                                                        .note_bound_ember_hash(peer_user_hash, *eh);
                                                }
                                            }
                                            if peer_is_ember && !mesh_discovered_emitted {
                                                if let std::net::IpAddr::V4(v4) =
                                                    self.source_addr.ip()
                                                {
                                                    let peer_tcp = self.source_addr.port();
                                                    if peer_tcp > 0
                                                        && !crate::security::is_bogus_v4(v4)
                                                    {
                                                        let _ = event_tx
                                                            .send(
                                                                DownloadEvent::EmberPeerDiscovered {
                                                                    ip: v4,
                                                                    tcp_port: peer_tcp,
                                                                    udp_port: peer_udp_port,
                                                                },
                                                            )
                                                            .await;
                                                        mesh_discovered_emitted = true;
                                                    }
                                                }
                                            }
                                        } else {
                                            tracing::warn!(
                                                "Ember binding: peer {} advertised pubkey does not BLAKE3-bind (data loop, possible spoof)",
                                                self.source_addr
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        (OP_EMULEPROT, OP_EMBER_CHAT_MSG)
                        | (OP_EMULEPROT, OP_EMBER_BROWSE_REQ)
                        | (OP_EMULEPROT, OP_EMBER_BROWSE_RES) => {
                            debug!("Dropping friend-only opcode on generic eD2K transfer");
                        }
                        _ => {
                            debug!(
                                "During download, ignoring proto=0x{proto:02X} op=0x{opcode:02X}"
                            );
                        }
                    }

                    // When a request's worth of requested ranges is complete, send the next one
                    let expired = expire_outstanding_ranges(&mut outstanding_ranges);
                    if expired > 0 {
                        total_sent_bytes = total_sent_bytes.saturating_sub(expired);
                    }
                    let blocks_in_current_batch = if completed_reqs < batches.len() {
                        batches[completed_reqs].len()
                    } else {
                        MAX_BLOCKS_PER_REQUEST
                    };
                    if blocks_received_in_current_req >= blocks_in_current_batch {
                        blocks_received_in_current_req = 0;
                        completed_reqs += 1;
                        // Pipeline refill: send next request if available, but
                        // never grow past max_outstanding (eMule
                        // CreateBlockRequests: pending > 2 * blockCount).
                        if sent_idx < batches.len()
                            && sent_idx.saturating_sub(completed_reqs) < max_outstanding
                            && outstanding_ranges.len()
                                <= 2 * max_outstanding * MAX_BLOCKS_PER_REQUEST
                        {
                            let batch = &batches[sent_idx];
                            let (req_payload, req_proto, req_op) = if needs_i64 {
                                (
                                    build_request_parts_i64(&self.file_hash, batch),
                                    OP_EMULEPROT,
                                    OP_REQUESTPARTS_I64,
                                )
                            } else {
                                (
                                    build_request_parts(&self.file_hash, batch),
                                    OP_EDONKEYHEADER,
                                    OP_REQUESTPARTS,
                                )
                            };
                            write_packet_async(&mut writer, req_proto, req_op, &req_payload)
                                .await?;
                            total_sent_bytes += batch.iter().map(|(s, e)| e - s).sum::<u64>();
                            push_outstanding_batch(&mut outstanding_ranges, batch);
                            sent_idx += 1;
                        }
                    } else if expired > 0 {
                        while sent_idx < batches.len()
                            && outstanding_ranges.len()
                                < max_outstanding * MAX_BLOCKS_PER_REQUEST
                        {
                            let batch = &batches[sent_idx];
                            let (req_payload, req_proto, req_op) = if needs_i64 {
                                (
                                    build_request_parts_i64(&self.file_hash, batch),
                                    OP_EMULEPROT,
                                    OP_REQUESTPARTS_I64,
                                )
                            } else {
                                (
                                    build_request_parts(&self.file_hash, batch),
                                    OP_EDONKEYHEADER,
                                    OP_REQUESTPARTS,
                                )
                            };
                            write_packet_async(&mut writer, req_proto, req_op, &req_payload)
                                .await?;
                            total_sent_bytes += batch.iter().map(|(s, e)| e - s).sum::<u64>();
                            push_outstanding_batch(&mut outstanding_ranges, batch);
                            sent_idx += 1;
                        }
                    }

                    // Update speed measurement every 2 seconds
                    let elapsed = speed_measure_start.elapsed();
                    if elapsed.as_millis() >= 2000 {
                        measured_speed = (speed_measure_bytes as u128 * 1000
                            / elapsed.as_millis().max(1))
                            as u64;
                        speed_measure_bytes = 0;
                        speed_measure_start = std::time::Instant::now();
                        self.emit_source_detail_parts(
                            event_tx,
                            "transferring",
                            None,
                            measured_speed,
                            downloaded,
                            &client_software_label,
                            &peer_name_label,
                            src_avail_parts,
                            src_total_parts,
                        )
                        .await;
                    }

                    if last_periodic_save.elapsed() >= PERIODIC_SAVE_INTERVAL {
                        // Snapshot after releasing mutable tracker work, then
                        // enqueue it through the per-file ordered writer.
                        let snap = tracker.snapshot_for_save();
                        super::part_tracker::save_snapshot_async(snap).await;
                        last_periodic_save = std::time::Instant::now();
                    }
                }

                // Guard against duplicate/overlapping blocks that satisfied the
                // byte budget without actually closing all gaps in this part.
                {
                    let (ps, pe) = tracker.part_range(part_idx);
                    let part_has_gaps = tracker
                        .gap_list()
                        .iter()
                        .any(|&(gs, ge)| gs < pe && ge > ps);
                    if part_has_gaps {
                        debug!(
                        "Part {} byte budget met but gaps remain — peer likely sent duplicate blocks, marking for retry",
                            part_idx
                        );
                        super::part_tracker::save_snapshot_async(tracker.snapshot_for_save()).await;
                        continue;
                    }
                }

                // Verify part hash if we have the hashset
                let part_verified = part_idx < part_hashes.len();
                if part_verified {
                    let expected_hash = part_hashes[part_idx];
                    let (ps, pe) = tracker.part_range(part_idx);
                    let part_len = (pe - ps) as usize;

                    // Read + MD4 in one writer-thread round-trip — keeps the
                    // hash off the async runtime and avoids re-locking the file.
                    let (part_data, actual_hash) = output
                        .hash_part_md4(ps, part_len)
                        .await
                        .map_err(|e| anyhow::anyhow!("part hash read at {ps}: {e}"))?;

                    if actual_hash != expected_hash {
                        let part_data = std::sync::Arc::new(part_data);
                        let aich_part = super::aich::compute_aich_part_blocking(
                            part_data.clone(),
                            part_idx,
                            tracker.part_count,
                        )
                        .await
                        .unwrap_or([0u8; 20]);
                        let total_blocks = (part_data.len() + super::aich::AICH_BLOCK_SIZE - 1)
                            / super::aich::AICH_BLOCK_SIZE;
                        warn!(
                            "Part {} hash mismatch! expected={} got={}, part_aich={}, {} blocks in part",
                            part_idx,
                            hex::encode(expected_hash),
                            hex::encode(actual_hash),
                            hex::encode(aich_part),
                            total_blocks,
                        );

                        let mut recovery_bytes: Option<Vec<u8>> =
                            aich_recovery_data.as_ref().map(|(_, d)| d.clone());
                        if let Some(master_hash) = aich_master_hash {
                            if recovery_bytes.is_none() && peer_supports_aich {
                                let aich_should_try = if let std::net::IpAddr::V4(v4) =
                                    self.source_addr.ip()
                                {
                                    if let Some(ref pending) = self.aich_pending {
                                        if let Ok(map) = pending.read() {
                                            match map.get(&(self.file_hash, part_idx as u32)) {
                                                Some((failed_ips, retry_count)) => {
                                                    !failed_ips.contains(&v4) && *retry_count < 3
                                                }
                                                None => true,
                                            }
                                        } else {
                                            true
                                        }
                                    } else {
                                        true
                                    }
                                } else {
                                    true
                                };

                                if aich_should_try {
                                    let mut aich_req = Vec::with_capacity(38);
                                    aich_req.extend_from_slice(&self.file_hash);
                                    aich_req.extend_from_slice(&(part_idx as u16).to_le_bytes());
                                    aich_req.extend_from_slice(&master_hash);
                                    if let Err(e) = write_packet_async(
                                        &mut writer,
                                        OP_EMULEPROT,
                                        OP_AICHREQUEST,
                                        &aich_req,
                                    )
                                    .await
                                    {
                                        debug!("Failed to send OP_AICHREQUEST: {e}");
                                    } else {
                                        debug!("Sent OP_AICHREQUEST for part {part_idx}, waiting for answer");
                                        match wait_for_aich_recovery_answer(
                                            &mut reader,
                                            &self.file_hash,
                                            part_idx,
                                            master_hash,
                                            &mut auth_deferred,
                                        )
                                        .await
                                        {
                                            AichAnswerOutcome::Recovered(data) => {
                                                recovery_bytes = Some(data);
                                            }
                                            AichAnswerOutcome::NotAvailable => {}
                                            // The reader may be parked
                                            // mid-packet, so anything read next
                                            // would be payload bytes parsed as
                                            // a header. End the source rather
                                            // than corrupt the rest of the
                                            // session with it.
                                            AichAnswerOutcome::StreamDesynced => {
                                                anyhow::bail!(
                                                    "AICH recovery wait left the stream desynchronized"
                                                );
                                            }
                                        }
                                    }
                                } else {
                                    debug!("Skipping OP_AICHREQUEST for part {part_idx}: source already tried or retries exhausted");
                                }
                            }

                            let mut narrowed = false;
                            if let Some(rec) = recovery_bytes.take() {
                                if let Some(corrupt) =
                                    super::aich::corrupt_blocks_from_aich_recovery_blocking(
                                        master_hash,
                                        rec,
                                        part_idx,
                                        part_data.clone(),
                                        part_len,
                                        self.file_size,
                                    )
                                    .await
                                {
                                    if !corrupt.is_empty() {
                                        let (ps, _) = tracker.part_range(part_idx);
                                        let mut invalidated = 0u64;
                                        for &bi in &corrupt {
                                            let rel =
                                                bi as u64 * super::aich::AICH_BLOCK_SIZE as u64;
                                            let gs = ps + rel;
                                            let ge = (gs + super::aich::AICH_BLOCK_SIZE as u64)
                                                .min(ps + part_len as u64);
                                            tracker.invalidate_range(gs, ge);
                                            invalidated += ge - gs;
                                        }
                                        super::part_tracker::save_snapshot_async(
                                            tracker.snapshot_for_save(),
                                        )
                                        .await;
                                        downloaded = downloaded.saturating_sub(invalidated);
                                        let progress = tracker.progress_bytes().min(self.file_size);
                                        let _ = event_tx.try_send(DownloadEvent::Progress {
                                            transfer_id: self.transfer_id.clone(),
                                            downloaded: progress,
                                            transferred: Some(tracker.transferred()),
                                            total: self.file_size,
                                        });
                                        info!(
                                            "AICH narrowed part {} to {} bad 180KiB block(s), ~{} bytes to re-fetch",
                                            part_idx,
                                            corrupt.len(),
                                            invalidated
                                        );
                                        narrowed = true;
                                    }
                                }
                            }

                            if !narrowed {
                                if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                    let _ = event_tx
                                        .send(DownloadEvent::AichRecoveryFailed {
                                            file_hash: self.file_hash,
                                            part_index: part_idx as u32,
                                            failed_ip: v4,
                                        })
                                        .await;
                                }
                            }

                            if narrowed {
                                // This bucket includes the invalidated AICH
                                // blocks. Clear it so a later successful repair
                                // cannot award credit for bytes proven corrupt.
                                #[allow(unused_assignments)]
                                {
                                    pending_credit_bytes = 0;
                                }
                                continue;
                            }
                        }

                        tracker.mark_incomplete(part_idx);
                        super::part_tracker::save_snapshot_async(tracker.snapshot_for_save()).await;
                        downloaded = tracker.completed_bytes();
                        // D12: drop the pending credit tally — bytes that
                        // didn't verify earn this peer nothing. Silenced
                        // unused_assignments (compiler can't see the
                        // next-iteration read via saturating_add through
                        // the nested `continue` control flow).
                        #[allow(unused_assignments)]
                        {
                            pending_credit_bytes = 0;
                        }
                        let _ = event_tx
                            .send(DownloadEvent::PartCorrupted {
                                file_hash: self.file_hash,
                                part_start: ps,
                                part_end: pe,
                                sender_user_hash: Some(peer_user_hash),
                            })
                            .await;
                        continue;
                    }
                    debug!("Part {} hash verified OK", part_idx);
                    // Durability before persisting verified bits: otherwise a
                    // crash can leave .part.met claiming verified (it is made
                    // durable by `atomic_write`'s sync_all + rename) while the
                    // .part data is still only in the page cache, and uploads
                    // would serve that range (T5). Mirrors the multi-source
                    // worker; a failed fsync means we do NOT persist the bit.
                    if let Err(e) = output.sync_data().await {
                        warn!("pre-verification fsync failed for part {part_idx}: {e}");
                        super::part_tracker::save_snapshot_async(tracker.snapshot_for_save()).await;
                        // Bytes we cannot prove reached disk earn no credit.
                        #[allow(unused_assignments)]
                        {
                            pending_credit_bytes = 0;
                        }
                        continue;
                    }
                    let _ = event_tx
                        .send(DownloadEvent::PartVerified {
                            file_hash: self.file_hash,
                            part_start: ps,
                            part_end: pe,
                            sender_user_hash: Some(peer_user_hash),
                        })
                        .await;
                }

                if part_verified {
                    tracker.mark_complete(part_idx);
                    // Flip the persistent verified flag so the upload path
                    // can safely serve this range.
                    tracker.set_part_verified(part_idx);
                    // A newly verified part may make this download previewable
                    // (first part done + media type) — refresh the UI flag.
                    // By the current name: a rename can change the type.
                    apply_control_rename(&self.control, &mut tracker);
                    let preview_name =
                        completed_download_name(tracker.file_name(), &self.file_name);
                    self.control.set_preview_ready(
                        tracker.is_preview_ready(&preview_name, self.file_size),
                    );
                    // D12: flush the peer's pending credit bytes now that
                    // the part they contributed to actually verified.
                    if pending_credit_bytes > 0 {
                        if let Some(cm) = &self.credit_manager {
                            let mut cm = cm.write().await;
                            cm.add_downloaded(peer_user_hash, pending_credit_bytes);
                            // Mirror for the Ember ledger — same
                            // rationale as `multi_source.rs`. Only
                            // write when the peer completed full
                            // Ed25519 PoP on this session; the
                            // binding-only fallback isn't enough for
                            // long-term credit accumulation (the
                            // PoP is what cryptographically ties the
                            // bytes to the peer's Ed25519 keypair).
                            if let Some(pk) = peer_ember_pubkey {
                                cm.add_ember_downloaded(
                                    pk,
                                    pending_credit_bytes,
                                    ember_auth_verified,
                                );
                            }
                        }
                        #[allow(unused_assignments)]
                        {
                            pending_credit_bytes = 0;
                        }
                    }
                }
                // Force one Progress emit at part boundary so the UI sees
                // verified-part jumps even if the throttle just fired.
                let progress = tracker.progress_bytes().min(self.file_size);
                let _ = event_tx.try_send(DownloadEvent::Progress {
                    transfer_id: self.transfer_id.clone(),
                    downloaded: progress,
                    transferred: Some(tracker.transferred()),
                    total: self.file_size,
                });
                last_progress_emit = std::time::Instant::now();
                // Save .part.met off-runtime: snapshot under no lock, then
                // run atomic_write on a blocking task. Avoids stalling the
                // download loop on fsync.
                super::part_tracker::save_snapshot_async(tracker.snapshot_for_save()).await;
            }
        }

        // Signal the uploader that we're done downloading from them. eMule
        // counts a payload without the file hash as a failed file request
        // (ListenSocket.cpp OP_END_OF_DOWNLOAD -> CheckFailedFileIdReqs).
        write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_END_OF_DOWNLOAD, &self.file_hash)
            .await
            .ok();

        self.emit_source_detail_parts(
            event_tx,
            "completed",
            None,
            measured_speed,
            downloaded.min(self.file_size),
            &client_software_label,
            &peer_name_label,
            src_avail_parts,
            src_total_parts,
        )
        .await;

        if !tracker.all_complete() {
            let remaining = tracker.part_count - tracker.completed_count();
            self.emit_source_failed(
                event_tx,
                &format!("{remaining} parts still failing hash verification"),
                downloaded.min(self.file_size),
                &client_software_label,
                &peer_name_label,
            )
            .await;
            anyhow::bail!(
                "{remaining} parts still failing hash verification after {max_part_rounds} retries"
            );
        }

        // One fsync at completion — the writer thread runs sync_data on the
        // dedicated thread, so we don't block the async runtime here.
        output
            .sync_data()
            .await
            .map_err(|e| anyhow::anyhow!("part file fsync: {e}"))?;
        drop(output);

        let retry_delay = super::multi_source::final_verify_retry_delay(
            super::multi_source::prior_inconclusive_final_verifies(&self.transfer_id),
        );
        if !retry_delay.is_zero() {
            info!(
                "Waiting {}s before re-verifying {} after an unreadable attempt",
                retry_delay.as_secs(),
                self.file_name
            );
            tokio::select! {
                _ = tokio::time::sleep(retry_delay) => {}
                _ = self.control.wait_cancelled() => anyhow::bail!("cancelled by user"),
            }
        }

        let _ = event_tx
            .send(DownloadEvent::Verifying {
                transfer_id: self.transfer_id.clone(),
            })
            .await;

        // Verify the final file hash BEFORE moving the .part file. Always
        // re-read the bytes on disk: a hash derived from known part hashes
        // cannot detect metadata/data divergence after a crash or external
        // Temp-file write.
        let expected_hash = hex::encode(self.file_hash);
        let verify_path = part_path.clone();
        let verify_root = part_root.clone();
        let expected_aich = self.expected_aich_master;
        let ember_expected = self.ember_file_hash;
        let mut ember_pin_failed = false;
        let mut could_not_verify = false;
        // `handle.abort()` cannot interrupt `spawn_blocking`, so a Stop or Pause
        // during "Verifying" would otherwise leave a thread reading a multi-GB
        // file for minutes. `TransferControl` does not expose its inner atomic,
        // so mirror it onto a flag the hashers poll between reads (same shape as
        // the archive-recovery job). Every pause path cancels as well, so
        // watching cancellation alone covers both.
        let verify_cancel = Arc::new(std::sync::atomic::AtomicBool::new(
            self.control.is_cancelled(),
        ));
        let cancel_watch = AbortOnDrop({
            let flag = verify_cancel.clone();
            let control = self.control.clone();
            tokio::spawn(async move {
                control.wait_cancelled().await;
                flag.store(true, std::sync::atomic::Ordering::Release);
            })
        });
        let job_cancel = verify_cancel.clone();
        let expected_ed2k = expected_hash.clone();
        let verified_result = match tokio::task::spawn_blocking(move || {
            let allowed = vec![verify_root.to_string_lossy().into_owned()];
            // Tell the library scheduler this drive is busy. It rations reads
            // per physical device to keep a mechanical disk from thrashing, and
            // a verification it cannot see is a read straight through that
            // budget. Advisory only: this never waits, because the user is
            // waiting on this file and a background scan is not.
            let _drive_busy = crate::sharing::disk::note_external_read(&verify_path);
            let (_, mut file) =
                crate::security::filesystem::open_existing_approved(&verify_path, &allowed, false)?;
            let identity = crate::security::filesystem::opened_file_identity(&file)?;
            // One pass for all three. Read separately, this cost a full extra
            // trip over the file per digest — three reads of a finished
            // download, on the drive the user is waiting on, to check things
            // that chunk the same bytes differently and can perfectly well be
            // computed together.
            let digests = super::hash::hash_open_file_digests_cancellable(
                &mut file,
                super::hash::WantedDigests {
                    aich: expected_aich.is_some(),
                    ember: ember_expected != [0u8; 32],
                },
                job_cancel.as_ref(),
            )?;
            // Only once the ed2k hash matched; see the multi-source worker.
            if let Some(got) = digests.ember.filter(|_| digests.ed2k == expected_ed2k) {
                if got != ember_expected {
                    anyhow::bail!(
                        "ember blake3 mismatch: expected={} got={}",
                        hex::encode(ember_expected),
                        hex::encode(got)
                    );
                }
            }
            Ok::<_, anyhow::Error>((digests.ed2k, identity, digests.aich, digests.part_hashes))
        })
        .await
        {
            Ok(Ok((actual_hash, identity, actual_aich, part_hashes)))
                if actual_hash == expected_hash =>
            {
                info!(
                    "Download complete and verified from disk: {}",
                    self.file_name
                );
                Some((identity, actual_aich, part_hashes))
            }
            Ok(Ok((actual_hash, _, _, _))) => {
                warn!(
                    "Download hash mismatch for {}: expected={}, got={}",
                    self.file_name, expected_hash, actual_hash
                );
                None
            }
            Ok(Err(e)) => {
                let msg = e.to_string();
                if is_ember_blake3_mismatch(&msg) {
                    ember_pin_failed = true;
                    warn!(
                        "Ember BLAKE3 pin failed for {}: {msg} — not retrying parts",
                        self.file_name
                    );
                } else {
                    could_not_verify = true;
                    warn!(
                        "Could not verify hash for {}: {e} — keeping progress",
                        self.file_name
                    );
                }
                None
            }
            Err(e) => {
                could_not_verify = true;
                warn!(
                    "Hash verification task failed for {}: {e} — keeping progress",
                    self.file_name
                );
                None
            }
        };
        drop(cancel_watch);

        let Some((verified_identity, actual_aich, verified_part_hashes)) = verified_result else {
            if ember_pin_failed {
                super::multi_source::clear_inconclusive_final_verifies(&self.transfer_id);
                anyhow::bail!(EMBER_BLAKE3_MISMATCH_MSG);
            }
            // A Stop aborts the verification read part-way through the file.
            // That is not evidence of corruption, so leave the gap list and the
            // `.part` alone rather than re-opening every part for re-download.
            if self.control.is_cancelled() {
                anyhow::bail!("cancelled by user");
            }
            // Narrow to the parts that actually mismatch, as the multi-source
            // path does. Re-opening every part cost a full re-download of a
            // multi-GB file for one bad 9.28 MB chunk — and the per-part MD4s
            // all passed during transfer, so the usual causes (a write lost to
            // a crash, external modification of `Temp/`) are localized. With no
            // hashset to diagnose with, every part is re-opened.
            use super::multi_source::FinalVerifyRecovery;
            let recovery = if could_not_verify {
                FinalVerifyRecovery::Reverify
            } else {
                super::multi_source::diagnose_final_hash_mismatch(
                    part_path.clone(),
                    self.file_hash,
                    self.file_size,
                    part_hashes.clone(),
                )
                .await
            };
            let inconclusive = recovery == FinalVerifyRecovery::Reverify;
            let recovery = super::multi_source::settle_final_verify_recovery(
                &self.transfer_id,
                recovery,
                part_path.clone(),
                self.file_size,
                part_hashes.clone(),
            )
            .await;
            let parts = match recovery {
                FinalVerifyRecovery::Reopen(parts) => parts,
                FinalVerifyRecovery::Reverify => {
                    warn!(
                        "Final verification of {} was inconclusive — gap list kept, will re-verify",
                        self.file_name
                    );
                    anyhow::bail!(FINAL_VERIFY_INCONCLUSIVE_MSG);
                }
                FinalVerifyRecovery::Unreadable => {
                    warn!(
                        "{} still cannot be read after repeated verification attempts and a \
                         part-by-part re-read — giving up",
                        self.file_name
                    );
                    anyhow::bail!(LOCAL_READ_FAILED_MSG);
                }
            };
            for &i in &parts {
                if i < tracker.part_count {
                    tracker.mark_incomplete(i);
                }
            }
            let reopened = parts.len();
            super::part_tracker::save_snapshot_async(tracker.snapshot_for_save()).await;
            warn!(
                "Final hash failed for {} — re-opened {} of {} parts for retry",
                self.file_name, reopened, tracker.part_count
            );
            if inconclusive {
                anyhow::bail!(FINAL_VERIFY_INCONCLUSIVE_MSG);
            }
            anyhow::bail!(
                "Final hash verification failed — .part and .part.met preserved for retry"
            );
        };
        super::multi_source::clear_inconclusive_final_verifies(&self.transfer_id);
        if let Some(expected_aich) = self.expected_aich_master {
            let actual = actual_aich
                .ok_or_else(|| anyhow::anyhow!("AICH verification did not produce a root"))?;
            if actual != expected_aich {
                anyhow::bail!(
                    "Expected AICH hash mismatch: expected {}, got {}",
                    hex::encode(expected_aich),
                    hex::encode(actual)
                );
            }
        }

        // Verification passed — safe to move file and clean up resume state.
        // Flip every part's verified flag (covers single-part < PARTSIZE
        // files that have no per-part hashset, and acts as a belt-and-braces
        // reset for multi-part files).
        tracker.mark_file_hash_verified();
        seal_control_rename(&self.control, &mut tracker);
        // As in the multi-source worker: stopped after verification, the
        // verified `.part` stays put and the next run completes it.
        if self.control.is_cancelled() {
            anyhow::bail!("cancelled by user");
        }
        let final_name = completed_download_name(tracker.file_name(), &self.file_name);
        let pp = part_path.clone();
        let pp_root = part_root.clone();
        let download_root = self.download_folders.read().current.clone();
        let met_roots = allowed_roots.clone();
        let finish_tx = event_tx.clone();
        let finish_id = self.transfer_id.clone();
        // `download_from_streams` only gets here after its Ember BLAKE3 check
        // passed (or there was none to run).
        let ember_verified = self.ember_file_hash != [0u8; 32];
        // Spawned so that an abort (Pause, Stop) landing during the move, which
        // `abort` cannot stop, does not drop the sidecar delete and `Completed`
        // after it. See the multi-source worker.
        let finish = tokio::spawn(async move {
            let actual_final = tokio::task::spawn_blocking(move || {
                move_part_to_downloads(
                    &pp,
                    &pp_root,
                    &download_root,
                    &final_name,
                    &verified_identity,
                )
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;
            tracker.delete_met(&met_roots);
            let _ = finish_tx
                .send(DownloadEvent::Completed {
                    transfer_id: finish_id,
                    // The real on-disk destination, deduplicated by the move,
                    // so Open/Reveal need not reconstruct it from the name.
                    final_path: Some(actual_final.to_string_lossy().into_owned()),
                    // Computed by the final verification, which had to read
                    // the file anyway. This path never gets a peer-supplied
                    // hashset, so without these the completion handler read
                    // the whole file again to recompute them.
                    part_hashes: verified_part_hashes,
                    ember_verified,
                })
                .await;
            Ok::<(), anyhow::Error>(())
        });
        finish
            .await
            .map_err(|e| anyhow::anyhow!("completion task: {e}"))?
    }

    async fn acquire_download_bandwidth(&self, bytes: u64) -> anyhow::Result<()> {
        if !self.bandwidth_limiter.acquire_download(bytes).await {
            anyhow::bail!("bandwidth limiter stopped");
        }
        Ok(())
    }
}

/// eMule-style adaptive pipelining: number of OP_REQUESTPARTS packets to
/// keep in flight simultaneously based on observed connection speed.
/// Each request carries up to 3 blocks (EMBLOCKSIZE each).
/// Ref: eMule DownloadClient.cpp CreateBlockRequests() thresholds.
///
/// When `remaining_parts` <= 4 (near completion), eMule reduces to 1-2
/// blocks for slow connections to avoid wasting bandwidth on duplicate
/// requests that arrive after another source already finished the part.
///
/// `remaining_gap_bytes` tightens pipelining further in endgame (few bytes left).
/// Returns the max number of OP_REQUESTPARTS packets to keep in flight.
/// eMule counts individual blocks (each packet carries 3), so we compute
/// the block target and ceil-divide by 3 to get packet count.
fn outstanding_requests_for_speed_with_remaining(
    speed: u64,
    remaining_parts: usize,
    remaining_gap_bytes: u64,
) -> usize {
    // eMule block counts per speed tier (DownloadClient.cpp:804-810),
    // extended with higher tiers for modern broadband connections.
    // Safe because eMule upload side queues all incoming block requests.
    let mut blocks = if remaining_parts <= 4 {
        if speed < 600 {
            1
        } else if speed < 1200 {
            2
        } else if speed < 4 * 1024 {
            1
        } else if speed < 9 * 1024 {
            2
        } else if speed < 75 * 1024 {
            3
        } else if speed < 150 * 1024 {
            6
        } else {
            9
        }
    } else if speed < 4 * 1024 {
        1
    } else if speed < 9 * 1024 {
        2
    } else if speed < 75 * 1024 {
        3
    } else if speed < 150 * 1024 {
        6
    } else if speed < 300 * 1024 {
        9
    } else if speed < 1024 * 1024 {
        12
    } else {
        15
    };
    if remaining_parts <= 2 || remaining_gap_bytes <= PARTSIZE {
        blocks = blocks.min(3);
    } else if remaining_parts <= 4 || remaining_gap_bytes <= PARTSIZE.saturating_mul(3) {
        blocks = blocks.min(6);
    }
    // Convert block count to packet count (3 blocks per packet), min 1
    ((blocks + 2) / 3).max(1)
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
    for dir in finished_file_dirs() {
        let dir = std::path::Path::new(root).join(dir);
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
fn published_names(dir: &std::path::Path, name: &str) -> Vec<std::path::PathBuf> {
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
    let places = std::iter::once((dir.to_path_buf(), root)).chain(
        elsewhere.then(|| (std::path::Path::new(download_root).join("Downloads"), download_root)),
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
        let published = move_part_to_downloads(
            path,
            std::path::Path::new(root),
            std::path::Path::new(download_root),
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

fn parse_sending_part_32(payload: &[u8]) -> std::io::Result<([u8; 16], u64, u64, &[u8])> {
    if payload.len() < 24 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sending part 32 too short",
        ));
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    let start = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]) as u64;
    let end = u32::from_le_bytes([payload[20], payload[21], payload[22], payload[23]]) as u64;
    // Enforce the declared (end - start) matches the actual trailing data,
    // same as `parse_sending_part_i64` — today's call sites happen to
    // re-check this themselves, but a parser that silently hands back
    // whatever bytes follow the header (regardless of what the peer
    // *claimed* the block size was) is one missed call-site check away
    // from a length-confusion bug on attacker-controlled data.
    let expected_len = end.checked_sub(start).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "part end before start")
    })?;
    let expected_len = usize::try_from(expected_len).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("sending part length too large: {expected_len}"),
        )
    })?;
    let data_len = payload.len() - 24;
    if data_len != expected_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("sending part length mismatch: expected {expected_len}, got {data_len}"),
        ));
    }
    Ok((hash, start, end, &payload[24..]))
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
        return Ok(None);
    };
    let challenge = rand::RngCore::next_u32(&mut rand::rngs::OsRng).wrapping_add(1);
    let mut secident_payload = Vec::with_capacity(5);
    secident_payload.push(state);
    secident_payload.extend_from_slice(&challenge.to_le_bytes());
    write_packet_async(writer, OP_EMULEPROT, OP_SECIDENTSTATE, &secident_payload).await?;
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
    let sig_len = payload[0] as usize;
    if sig_len == 0 || payload.len() < 1 + sig_len {
        return;
    }
    let Some(challenge) = pending_secident_challenge.take() else {
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
        cm.set_ident_state(peer_user_hash, IdentState::Verified);
        cm.check_identity_ip(peer_user_hash, peer_ip_u32);
    } else if cm
        .get_record(&peer_user_hash)
        .is_none_or(|record| record.ident_state == IdentState::Needed)
    {
        // Only demote a record that was actually awaiting its first proof,
        // matching eMule (`ClientCredits.cpp:507`, which sets IS_IDFAILED only
        // from IS_IDNEEDED). Demoting unconditionally let anyone who knows a
        // peer's user_hash — it travels in the clear in every Hello — knock an
        // established peer out of `Verified` with one bogus signature, which
        // both strips their score multiplier and, before the anchor was made
        // durable, set them up to have their credits reset later.
        cm.set_ident_state(peer_user_hash, IdentState::Failed);
    }
}

/// What a wait for `OP_AICHANSWER` ended in. Mirrors the multi-source path's
/// outcome so both react to a half-read packet the same way.
enum AichAnswerOutcome {
    Recovered(Vec<u8>),
    /// The peer answered, but has nothing we can use. The stream is still on a
    /// packet boundary, so the connection is fine to keep.
    NotAvailable,
    /// The read was abandoned partway through a packet. Nothing can be parsed
    /// from this connection afterwards.
    StreamDesynced,
}

/// Wait for `OP_AICHANSWER` matching file, part, and trusted AICH master hash (up to ~8s).
///
/// `read_packet_async` consumes the stream incrementally, so a dropped read
/// future leaves the reader mid-packet with no way to resynchronize. Slicing
/// the wait into short timeouts around a *fresh* read future — which is what
/// this did — meant that whenever the peer was still streaming the block sent
/// just before verification began (the normal case), the timer fired mid-payload
/// and the next read parsed file bytes as a packet header. One deadline covers
/// the whole wait instead, and if it fires the caller is told the stream is
/// unusable rather than left to read garbage from it. The multi-source path
/// carries the identical fix.
async fn wait_for_aich_recovery_answer<R: AsyncReadExt + Unpin + ?Sized>(
    reader: &mut R,
    file_hash: &[u8; 16],
    part_idx: usize,
    expected_master: [u8; 20],
    deferred_packets: &mut std::collections::VecDeque<(u8, u8, Vec<u8>)>,
) -> AichAnswerOutcome {
    const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(8);

    let scan = async {
        loop {
            let (proto, opcode, payload) = match read_packet_async(reader).await {
                Ok(packet) => packet,
                Err(_) => return AichAnswerOutcome::StreamDesynced,
            };
            if proto == OP_EMULEPROT && opcode == OP_AICHANSWER {
                if (38..=38 + crate::network::ed2k::aich::MAX_AICH_RECOVERY_BYTES)
                    .contains(&payload.len())
                {
                    let mut ans_hash = [0u8; 16];
                    ans_hash.copy_from_slice(&payload[..16]);
                    let ans_part = u16::from_le_bytes([payload[16], payload[17]]) as usize;
                    let mut root = [0u8; 20];
                    root.copy_from_slice(&payload[18..38]);
                    if ans_hash == *file_hash && ans_part == part_idx {
                        if root == expected_master {
                            return AichAnswerOutcome::Recovered(payload[38..].to_vec());
                        }
                        debug!(
                            "AICH recovery: part {part_idx} answered with an untrusted root {}",
                            hex::encode(root)
                        );
                        return AichAnswerOutcome::NotAvailable;
                    }
                } else {
                    // eMule's "no recovery data for that part" reply is too
                    // short to carry a hash block. Only one request is
                    // outstanding, so this is the answer to it — and treating
                    // it as an unrelated packet meant waiting out the deadline
                    // and then dropping a source that had done nothing wrong.
                    return AichAnswerOutcome::NotAvailable;
                }
            }
            // Bound the buffer by bytes as well as by count, as the multi-source
            // twin does. A count alone let a peer queue 64 whole packets, and a
            // packed frame is capped at 2 MiB on the wire but may inflate to
            // 10 MiB — roughly 640 MiB resident per connection, on a path the
            // sender reaches by corrupting a part so its MD4 fails. Both limits
            // leave the stream on a packet boundary, so giving up on the answer
            // is safe either way. The packet just read is kept (overshooting
            // the byte cap by at most one packet): it is usually a requested
            // data block, and dropping it loses that range for the session.
            const MAX_DEFERRED_PACKETS: usize = 64;
            const MAX_DEFERRED_BYTES: usize = 4 * 1024 * 1024;
            deferred_packets.push_back((proto, opcode, payload));
            let deferred_bytes: usize = deferred_packets
                .iter()
                .map(|(_, _, buffered)| buffered.len())
                .sum();
            if deferred_packets.len() >= MAX_DEFERRED_PACKETS
                || deferred_bytes >= MAX_DEFERRED_BYTES
            {
                return AichAnswerOutcome::NotAvailable;
            }
        }
    };

    match tokio::time::timeout(MAX_WAIT, scan).await {
        Ok(outcome) => outcome,
        Err(_) => {
            debug!("AICH recovery wait for part {part_idx} timed out mid-stream");
            AichAnswerOutcome::StreamDesynced
        }
    }
}

/// Read a single packet during the pre-transfer handshake, bounded by
/// [`super::multi_source::HANDSHAKE_READ_TIMEOUT_SECS`] of silence.
///
/// Every call site is a handshake wait (`emule_info_wait`, `file_status_wait`,
/// `hashset_wait`); the data loop computes its own budget from
/// `READ_TIMEOUT_SECS` / `INITIAL_DATA_TIMEOUT_SECS` and does not come through
/// here. This used to reuse `READ_TIMEOUT_SECS` — the 100 s *in-transfer*
/// no-data budget — and each of the 1 + 12 + 5 reads got a fresh one, so a peer
/// that answered Hello and then emitted one unrecognised packet every ~99 s
/// could hold a callback download at 0% for close to half an hour without ever
/// timing out. `multi_source` has always used the short handshake bound here,
/// for the reason its constant documents.
///
/// A timeout while no packet has begun is a plain `TimedOut` and leaves the
/// stream on a packet boundary; a stall part-way through a packet is reported
/// as [`PacketStreamDesynced`] (see [`read_packet_within`]).
async fn read_packet_with_timeout<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    let bound =
        std::time::Duration::from_secs(super::multi_source::HANDSHAKE_READ_TIMEOUT_SECS);
    read_packet_within(reader, bound, bound)
        .await?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timed out"))
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

/// Wait up to `start_within` for a packet to begin, then up to `finish_within`
/// for the rest of it.
///
/// Only the protocol byte races the idle deadline: a one-byte read consumes
/// that byte or nothing, so `Ok(None)` leaves the stream on a packet boundary.
/// Once a packet has begun, abandoning it would strand the reader mid-frame,
/// so that expiry is an error carrying [`PacketStreamDesynced`].
async fn read_packet_within<R: AsyncReadExt + Unpin + ?Sized>(
    reader: &mut R,
    start_within: std::time::Duration,
    finish_within: std::time::Duration,
) -> std::io::Result<Option<(u8, u8, Vec<u8>)>> {
    let protocol = match tokio::time::timeout(start_within, reader.read_u8()).await {
        Ok(result) => result?,
        Err(_) => return Ok(None),
    };
    match tokio::time::timeout(finish_within, read_packet_body(reader, protocol)).await {
        Ok(result) => result.map(Some),
        Err(_) => Err(packet_stream_desynced_error()),
    }
}

async fn read_packet_async<R: AsyncReadExt + Unpin + ?Sized>(
    reader: &mut R,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    let protocol = reader.read_u8().await?;
    read_packet_body(reader, protocol).await
}

/// [`read_packet_async`] that sets `started` once the first byte is consumed,
/// so a caller dropping the future can tell whether the stream is still framed.
async fn read_packet_marking_start<R: AsyncReadExt + Unpin + ?Sized>(
    reader: &mut R,
    started: &std::sync::atomic::AtomicBool,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    let protocol = reader.read_u8().await?;
    started.store(true, std::sync::atomic::Ordering::Relaxed);
    read_packet_body(reader, protocol).await
}

/// The rest of a packet once its protocol byte has been read.
async fn read_packet_body<R: AsyncReadExt + Unpin + ?Sized>(
    reader: &mut R,
    protocol: u8,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    const OP_PACKEDPROT: u8 = 0xD4;
    let length = reader.read_u32_le().await.map_err(desynced_io_error)? as usize;
    if length == 0 || length > MAX_WIRE_PACKET_LEN {
        return Err(desynced_io_error(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid packet length",
        )));
    }
    let opcode = reader.read_u8().await.map_err(desynced_io_error)?;
    let payload_len = length - 1;
    // Grow the buffer on the heap with bytes that actually arrive rather than
    // trusting the declared length up front. A peer that announces a large
    // packet but then stalls can otherwise pin a full allocation up to the
    // wire cap per connection. We grow in bounded steps directly into the Vec
    // instead
    // of via a large stack array: this read is awaited deep inside the
    // per-source download future, and a 64 KiB stack buffer there bloats that
    // (already huge) future's poll frame enough to overflow the worker stack
    // in debug builds.
    let mut payload = Vec::new();
    let mut remaining = payload_len;
    const READ_STEP: usize = 65536;
    while remaining > 0 {
        let want = remaining.min(READ_STEP);
        let start = payload.len();
        payload.resize(start + want, 0);
        reader
            .read_exact(&mut payload[start..start + want])
            .await
            .map_err(desynced_io_error)?;
        remaining -= want;
    }
    if protocol == OP_PACKEDPROT {
        let mut decoder = ZlibDecoder::new(&payload[..]);
        let mut unpacked = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = decoder.read(&mut buf).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("packed decode failed: {e}"),
                )
            })?;
            if n == 0 {
                break;
            }
            unpacked.extend_from_slice(&buf[..n]);
            if unpacked.len() > 10 * 1024 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "packed packet decompressed size exceeds limit",
                ));
            }
        }
        return Ok((OP_EMULEPROT, opcode, unpacked));
    }
    Ok((protocol, opcode, payload))
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
    use std::time::Duration;

    async fn send(peer: &mut tokio::io::DuplexStream, protocol: u8, opcode: u8, payload: &[u8]) {
        write_packet_async(peer, protocol, opcode, payload)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_packet_split_across_the_idle_tick_is_read_whole() {
        let (mut peer, mut reader) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            let mut frame = Vec::new();
            write_packet_async(&mut frame, OP_EDONKEYHEADER, OP_HASHSETANSWER, &[0x5A; 700])
                .await
                .unwrap();
            peer.write_all(&frame[..4]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            peer.write_all(&frame[4..]).await.unwrap();
            send(&mut peer, OP_EMULEPROT, OP_SECIDENTSTATE, &[1, 2, 3, 4, 5]).await;
            peer
        });

        let got = read_packet_within(&mut reader, Duration::from_millis(40), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(got, Some((OP_EDONKEYHEADER, OP_HASHSETANSWER, vec![0x5A; 700])));
        let next = read_packet_within(&mut reader, Duration::from_millis(40), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(next, Some((OP_EMULEPROT, OP_SECIDENTSTATE, vec![1, 2, 3, 4, 5])));
        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn an_idle_tick_leaves_the_stream_framed() {
        let (mut peer, mut reader) = tokio::io::duplex(4096);
        assert_eq!(
            read_packet_within(&mut reader, Duration::from_millis(20), Duration::from_secs(5))
                .await
                .unwrap(),
            None
        );
        send(&mut peer, OP_EMULEPROT, OP_PUBLICKEY, &[3, 9, 9, 9]).await;
        assert_eq!(
            read_packet_within(&mut reader, Duration::from_millis(500), Duration::from_secs(5))
                .await
                .unwrap(),
            Some((OP_EMULEPROT, OP_PUBLICKEY, vec![3, 9, 9, 9]))
        );
    }

    #[tokio::test]
    async fn a_stall_mid_packet_is_reported_as_desync() {
        let (mut peer, mut reader) = tokio::io::duplex(4096);
        let mut frame = Vec::new();
        write_packet_async(&mut frame, OP_EDONKEYHEADER, OP_HASHSETANSWER, &[0; 64])
            .await
            .unwrap();
        peer.write_all(&frame[..7]).await.unwrap();
        let err = read_packet_within(&mut reader, Duration::from_millis(500), Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(is_packet_stream_desynced(
            &anyhow::Error::from(err).context("stage:hashset_wait")
        ));
    }

    #[tokio::test]
    async fn an_invalid_length_after_the_header_is_a_desync() {
        let (mut peer, mut reader) = tokio::io::duplex(64);
        peer.write_all(&[OP_EDONKEYHEADER, 0, 0, 0, 0, OP_HASHSETANSWER])
            .await
            .unwrap();
        let err = read_packet_with_timeout(&mut reader).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(is_packet_stream_desynced(
            &anyhow::Error::from(err).context("stage:hashset_wait")
        ));
    }

    #[tokio::test]
    async fn eof_mid_packet_is_a_desync_but_eof_on_a_boundary_is_not() {
        let (mut peer, mut reader) = tokio::io::duplex(64);
        let mut frame = Vec::new();
        write_packet_async(&mut frame, OP_EMULEPROT, OP_PUBLICKEY, &[0; 20])
            .await
            .unwrap();
        peer.write_all(&frame[..12]).await.unwrap();
        drop(peer);
        let err = read_packet_async(&mut reader).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(is_packet_stream_desynced(&anyhow::Error::from(err)));

        let (peer, mut reader) = tokio::io::duplex(64);
        drop(peer);
        let err = read_packet_async(&mut reader).await.unwrap_err();
        assert!(!is_packet_stream_desynced(&anyhow::Error::from(err)));
    }

    #[tokio::test]
    async fn a_bad_packed_payload_leaves_the_stream_framed() {
        let (mut peer, mut reader) = tokio::io::duplex(4096);
        send(&mut peer, 0xD4, 0x40, &[0xDE, 0xAD, 0xBE, 0xEF]).await;
        send(&mut peer, OP_EMULEPROT, OP_PUBLICKEY, &[1]).await;
        let err = read_packet_async(&mut reader).await.unwrap_err();
        assert!(!is_packet_stream_desynced(&anyhow::Error::from(err)));
        assert_eq!(
            read_packet_async(&mut reader).await.unwrap(),
            (OP_EMULEPROT, OP_PUBLICKEY, vec![1])
        );
    }

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

    #[tokio::test]
    async fn marking_read_flags_a_packet_only_once_it_has_begun() {
        let (mut peer, mut reader) = tokio::io::duplex(4096);
        let started = std::sync::atomic::AtomicBool::new(false);
        assert!(tokio::time::timeout(
            Duration::from_millis(20),
            read_packet_marking_start(&mut reader, &started)
        )
        .await
        .is_err());
        assert!(!started.load(std::sync::atomic::Ordering::Relaxed));

        peer.write_all(&[OP_EDONKEYHEADER, 9]).await.unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(50),
            read_packet_marking_start(&mut reader, &started)
        )
        .await
        .is_err());
        assert!(started.load(std::sync::atomic::Ordering::Relaxed));
    }
}
