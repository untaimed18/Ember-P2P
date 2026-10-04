//! Converting KAD search results, extracting KAD sources, and evaluating
//! KAD search expressions against stored tags.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

pub(super) fn name_spam_penalty(name: &str) -> usize {
    crate::search::spam::fake_pattern_score(name) as usize
        + name.matches('[').count().saturating_sub(1) * 3
}

pub(super) fn kad_tag_file_rating(tag: &kad::types::KadTag) -> Option<u8> {
    let raw = kad_tag_uint::<u32>(tag)?;
    crate::network::ed2k::comments::unpack_file_rating(raw.into())
}

/// A KAD integer tag at whatever width it arrived in, if it fits `T`. eMule
/// writes each one at the smallest width that holds the value, so a sources
/// count of 5 comes as a UINT8 and a 40 KB file size as a UINT16; reading one
/// fixed width saw neither.
fn kad_tag_uint<T: TryFrom<u64>>(tag: &kad::types::KadTag) -> Option<T> {
    tag.as_uint().and_then(|v| T::try_from(v).ok())
}

pub(super) fn convert_search_results(
    entries: &[kad::messages::SearchResultEntry],
    is_source_safe: impl Fn(Ipv4Addr) -> bool,
) -> Vec<SearchResult> {
    use crate::search::index::infer_file_type;

    const MAX_KAD_SOURCE_ADDRS: usize = 500;

    struct ParsedEntry {
        hash: String,
        name: String,
        size: u64,
        file_type: String,
        extension: String,
        source_addr: String,
        sources_tag: u32,
        complete_sources_tag: u32,
        rating: Option<u8>,
        comment: Option<String>,
        media: crate::types::MediaMetadata,
    }

    // eMule sends a media length over KAD as a uint32 (seconds). When a value
    // arrives as a string (e.g. an ED2K-bridged "h:mm:ss"/"mm:ss"/"ss" form),
    // parse it the same way eMule's ConvertED2KTag does.
    fn parse_media_length(tag: &KadTag) -> Option<u32> {
        if tag.as_uint().is_some() {
            return kad_tag_uint(tag);
        }
        let s = tag.string_value()?;
        let parts: Vec<u32> = s
            .split(':')
            .map(|p| p.trim().parse::<u32>().ok())
            .collect::<Option<Vec<u32>>>()?;
        // The components come straight off the wire, and release builds have
        // `overflow-checks` off, so an unchecked multiply turns a hostile
        // "4294967295:0:0" into a plausible-looking duration (and panics in
        // debug, costing the whole result batch). Reject instead.
        match parts.as_slice() {
            [h, m, sec] => {
                let hours = h.checked_mul(3600)?;
                let minutes = m.checked_mul(60)?;
                hours.checked_add(minutes)?.checked_add(*sec)
            }
            [m, sec] => m.checked_mul(60)?.checked_add(*sec),
            [sec] => Some(*sec),
            _ => None,
        }
    }

    let parsed: Vec<ParsedEntry> = entries
        .iter()
        .filter_map(|entry| {
            let mut name = String::new();
            let mut size = 0u64;
            let mut file_type = String::new();
            let mut source_ip = 0u32;
            let mut source_port = 0u16;
            let mut sources_tag = 0u32;
            let mut complete_sources_tag = 0u32;
            let mut rating: Option<u8> = None;
            let mut comment: Option<String> = None;
            let mut media = crate::types::MediaMetadata::default();

            for tag in &entry.tags {
                match &tag.name {
                    TagName::Id(TAG_MEDIA_ARTIST) => {
                        if let Some(s) = tag.string_value() {
                            if !s.is_empty() {
                                media.artist = Some(s.to_string());
                            }
                        }
                    }
                    TagName::Id(TAG_MEDIA_ALBUM) => {
                        if let Some(s) = tag.string_value() {
                            if !s.is_empty() {
                                media.album = Some(s.to_string());
                            }
                        }
                    }
                    TagName::Id(TAG_MEDIA_TITLE) => {
                        if let Some(s) = tag.string_value() {
                            if !s.is_empty() {
                                media.title = Some(s.to_string());
                            }
                        }
                    }
                    TagName::Id(TAG_MEDIA_LENGTH) => {
                        if let Some(v) = parse_media_length(tag) {
                            if v > 0 {
                                media.duration = Some(v);
                            }
                        }
                    }
                    TagName::Id(TAG_MEDIA_BITRATE) => {
                        if let Some(v) = kad_tag_uint::<u32>(tag) {
                            if v > 0 {
                                media.bitrate = Some(v);
                            }
                        }
                    }
                    TagName::Id(TAG_MEDIA_CODEC) => {
                        if let Some(s) = tag.string_value() {
                            if !s.is_empty() {
                                media.codec = Some(s.to_string());
                            }
                        }
                    }
                    // ED2K-bridged KAD entries may carry the string tag names.
                    TagName::Str(s) if s.eq_ignore_ascii_case("artist") => {
                        if let Some(v) = tag.string_value() {
                            if !v.is_empty() {
                                media.artist = Some(v.to_string());
                            }
                        }
                    }
                    TagName::Str(s) if s.eq_ignore_ascii_case("album") => {
                        if let Some(v) = tag.string_value() {
                            if !v.is_empty() {
                                media.album = Some(v.to_string());
                            }
                        }
                    }
                    TagName::Str(s) if s.eq_ignore_ascii_case("title") => {
                        if let Some(v) = tag.string_value() {
                            if !v.is_empty() {
                                media.title = Some(v.to_string());
                            }
                        }
                    }
                    TagName::Str(s) if s.eq_ignore_ascii_case("length") => {
                        if let Some(v) = parse_media_length(tag) {
                            if v > 0 {
                                media.duration = Some(v);
                            }
                        }
                    }
                    TagName::Str(s) if s.eq_ignore_ascii_case("bitrate") => {
                        if let Some(v) = kad_tag_uint::<u32>(tag) {
                            if v > 0 {
                                media.bitrate = Some(v);
                            }
                        }
                    }
                    TagName::Str(s) if s.eq_ignore_ascii_case("codec") => {
                        if let Some(v) = tag.string_value() {
                            if !v.is_empty() {
                                media.codec = Some(v.to_string());
                            }
                        }
                    }
                    TagName::Id(TAG_FILENAME) => {
                        if let Some(s) = tag.string_value() {
                            name = s.to_string();
                        }
                    }
                    TagName::Id(TAG_FILESIZE) => {
                        if let Some(v) = tag.as_uint() {
                            size = v;
                        }
                    }
                    TagName::Id(TAG_FILETYPE) => {
                        if let Some(s) = tag.string_value() {
                            file_type = s.to_string();
                        }
                    }
                    TagName::Id(TAG_SOURCES) => {
                        if let Some(v) = tag.as_uint() {
                            sources_tag = v.min(MAX_KAD_AVAILABILITY.into()) as u32;
                        }
                    }
                    TagName::Id(TAG_COMPLETE_SOURCES) => {
                        if let Some(v) = tag.as_uint() {
                            complete_sources_tag = v.min(MAX_KAD_AVAILABILITY.into()) as u32;
                        }
                    }
                    TagName::Id(TAG_SOURCEIP) => {
                        if let Some(v) = kad_tag_uint(tag) {
                            source_ip = v;
                        }
                    }
                    TagName::Id(TAG_SOURCEPORT) => {
                        if let Some(v) = kad_tag_uint(tag) {
                            source_port = v;
                        }
                    }
                    TagName::Id(TAG_FILERATING) => {
                        rating = kad_tag_file_rating(tag);
                    }
                    TagName::Str(s) if s == "filerating" => {
                        rating = kad_tag_file_rating(tag);
                    }
                    TagName::Id(TAG_DESCRIPTION) => {
                        if let Some(s) = tag.string_value() {
                            comment = Some(s.to_string());
                        }
                    }
                    TagName::Str(s) if s == "description" => {
                        if let Some(s) = tag.string_value() {
                            comment = Some(s.to_string());
                        }
                    }
                    _ => {}
                }
            }

            // Sanitize every remote string before deriving extension/type.
            // Ordinary Arabic/Hebrew characters remain intact; only controls,
            // bidi overrides and zero-width formatters are removed.
            name = crate::security::sanitize_remote_text(&name, 8192);
            file_type = crate::security::sanitize_remote_text(&file_type, 128);
            comment = comment
                .map(|value| crate::security::sanitize_remote_text(&value, 4096))
                .filter(|value| !value.is_empty());
            media.artist = media
                .artist
                .map(|value| crate::security::sanitize_remote_text(&value, 1024))
                .filter(|value| !value.is_empty());
            media.album = media
                .album
                .map(|value| crate::security::sanitize_remote_text(&value, 1024))
                .filter(|value| !value.is_empty());
            media.title = media
                .title
                .map(|value| crate::security::sanitize_remote_text(&value, 1024))
                .filter(|value| !value.is_empty());
            media.codec = media
                .codec
                .map(|value| crate::security::sanitize_remote_text(&value, 128))
                .filter(|value| !value.is_empty());
            if name.is_empty() {
                return None;
            }

            let extension = name
                .rsplit_once('.')
                .map(|(_, ext)| ext.to_string())
                .unwrap_or_default();

            let inferred = infer_file_type(&extension);
            if !inferred.is_empty() {
                file_type = inferred;
            }

            let source_addr = if source_ip != 0 && source_port > 0 {
                let ip = Ipv4Addr::from(source_ip.to_be_bytes());
                if is_source_safe(ip) {
                    format!("{}:{}", ip, source_port)
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            // entry.id is the KAD ID (byte-swapped MD4). Reverse the swap
            // to get the raw MD4 hash needed for ED2K file transfers.
            let raw_md4 = kad_id_to_md4_bytes(&entry.id);
            Some(ParsedEntry {
                hash: hex::encode(raw_md4),
                name,
                size,
                file_type,
                extension,
                source_addr,
                sources_tag,
                complete_sources_tag,
                rating,
                comment,
                media,
            })
        })
        .collect();

    // Deduplicate by file hash, accumulating source counts across KAD nodes.
    // In eMule (CSearch::ProcessResult), each search result entry with the
    // same file hash adds to the source count. If TAG_SOURCES is 0 or absent,
    // the entry still counts as 1 source (the publishing node itself).
    let mut dedup: HashMap<String, SearchResult> = HashMap::new();
    let mut sources_accum: HashMap<String, u32> = HashMap::new();
    let mut complete_accum: HashMap<String, u32> = HashMap::new();

    for p in parsed {
        let effective_sources = if p.sources_tag > 0 { p.sources_tag } else { 1 };

        if let Some(existing) = dedup.get_mut(&p.hash) {
            existing.result_origin = crate::search::merge::combine_origin(
                &existing.result_origin,
                crate::search::merge::ORIGIN_KAD,
            );
            if !p.source_addr.is_empty()
                && existing.source_addresses.len() < MAX_KAD_SOURCE_ADDRS
                && !existing.source_addresses.contains(&p.source_addr)
            {
                existing.source_addresses.push(p.source_addr);
            }
            // Max, not sum. Both of these are one publisher's estimate of the
            // same swarm, so adding them counts that swarm twice: eMule's
            // `AddSources` and `AddCompleteSources` both branch on
            // `m_bKademlia` and keep the larger value, and its parent rollup in
            // `CSearchList::AddToList` maxes across children too.
            //
            // This summed `TAG_SOURCES`, citing `CSearch::ProcessResult`. That
            // is the wrong function: it is the Kad search layer handing results
            // to `AddToList`, which is where the merge — and the max — happens.
            // The effect was an availability that climbed with the number of
            // nodes that answered rather than with the size of the swarm.
            let acc = sources_accum.entry(p.hash.clone()).or_insert(0);
            *acc = (*acc).max(effective_sources).min(MAX_KAD_AVAILABILITY);
            existing.availability = (*acc).max(existing.source_addresses.len() as u32);

            let cs = complete_accum.entry(p.hash.clone()).or_insert(0);
            *cs = (*cs).max(p.complete_sources_tag).min(MAX_KAD_AVAILABILITY);
            existing.file.complete_sources = *cs;

            if name_spam_penalty(&p.name) < name_spam_penalty(&existing.file.name) {
                crate::search::merge::rename_result(existing, p.name);
            }
            if existing.file_type.is_empty() && !p.file_type.is_empty() {
                existing.file_type = p.file_type;
            }
            if existing.rating.is_none() && p.rating.is_some() {
                existing.rating = p.rating;
            }
            if existing.comment.is_none() && p.comment.is_some() {
                existing.comment = p.comment;
            }
            // Fill any media fields this node provided that we don't have yet
            // (only allocate the struct when there's something to store).
            if !p.media.is_empty() {
                let em = existing
                    .media
                    .get_or_insert_with(crate::types::MediaMetadata::default);
                if em.duration.is_none() {
                    em.duration = p.media.duration;
                }
                if em.bitrate.is_none() {
                    em.bitrate = p.media.bitrate;
                }
                if em.codec.is_none() {
                    em.codec = p.media.codec.clone();
                }
                if em.artist.is_none() {
                    em.artist = p.media.artist.clone();
                }
                if em.album.is_none() {
                    em.album = p.media.album.clone();
                }
                if em.title.is_none() {
                    em.title = p.media.title.clone();
                }
            }
        } else {
            let mut source_addresses = Vec::new();
            if !p.source_addr.is_empty() {
                source_addresses.push(p.source_addr.clone());
            }
            let availability = effective_sources.max(source_addresses.len() as u32);
            sources_accum.insert(p.hash.clone(), effective_sources);
            complete_accum.insert(p.hash.clone(), p.complete_sources_tag);
            dedup.insert(
                p.hash.clone(),
                SearchResult {
                    file: FileInfo {
                        id: p.hash.clone(),
                        name: p.name,
                        path: String::new(),
                        size: p.size,
                        hash: p.hash,
                        aich_hash: String::new(),
                        ember_file_hash: String::new(),
                        extension: p.extension,
                        modified_at: 0,
                        priority: "normal".to_string(),
                        requests: 0,
                        accepted: 0,
                        bytes_transferred: 0,
                        alltime_requests: 0,
                        alltime_accepted: 0,
                        alltime_transferred: 0,
                        complete_sources: p.complete_sources_tag,
                        folder: String::new(),
                        shared: false,
                        friends_only: false,
                        shared_kad: false,
                        shared_ed2k: false,
                        shared_ember: false,
                    },
                    peer_id: p.source_addr,
                    peer_name: String::new(),
                    availability,
                    file_type: p.file_type,
                    source_addresses,
                    rating: p.rating,
                    comment: p.comment,
                    media: p.media.into_option(),
                    spam_rating: 0,
                    is_spam: false,
                    clean_name: String::new(),
                    result_origin: crate::search::merge::ORIGIN_KAD.to_string(),
                    origin_server_ip: None,
                    spam_reasons: Vec::new(),
                    spam_reason_details: Vec::new(),
                },
            );
        }
    }

    let mut results: Vec<SearchResult> = dedup.into_values().collect();
    crate::search::merge::sort_search_results(&mut results);

    // Log availability distribution for debugging
    let with_multi_sources = results.iter().filter(|r| r.availability > 1).count();
    if !results.is_empty() {
        let max_avail = results.iter().map(|r| r.availability).max().unwrap_or(0);
        info!(
            "convert_search_results: {} unique files from {} raw entries, {} with >1 source, max availability={}",
            results.len(), entries.len(), with_multi_sources, max_avail
        );
    }

    results
}

pub(super) fn convert_note_search_results(
    entries: &[kad::messages::SearchResultEntry],
    file_hash: &KadId,
) -> Vec<SearchResult> {
    let forced_hash = hex::encode(kad_id_to_md4_bytes(file_hash));
    // Every node storing a publisher's note returns it; eMule's `AddNote`
    // keeps the first per source id, and so does this.
    let mut seen_publishers = HashSet::new();

    entries
        .iter()
        .filter_map(|entry| {
            let mut name = String::new();
            let mut size = 0u64;
            let mut rating: Option<u8> = None;
            let mut comment: Option<String> = None;

            for tag in &entry.tags {
                match &tag.name {
                    TagName::Id(TAG_FILENAME) => {
                        if let Some(s) = tag.string_value() {
                            name = s.to_string();
                        }
                    }
                    TagName::Id(TAG_FILESIZE) => {
                        if let Some(v) = tag.as_uint() {
                            size = v;
                        }
                    }
                    TagName::Id(TAG_FILERATING) => {
                        rating = kad_tag_file_rating(tag);
                    }
                    TagName::Id(TAG_DESCRIPTION) => {
                        if let Some(s) = tag.string_value() {
                            comment = Some(s.to_string());
                        }
                    }
                    TagName::Str(s) if s == "filerating" => {
                        rating = kad_tag_file_rating(tag);
                    }
                    TagName::Str(s) if s == "description" => {
                        if let Some(s) = tag.string_value() {
                            comment = Some(s.to_string());
                        }
                    }
                    _ => {}
                }
            }

            if rating.is_none() && comment.as_ref().is_none_or(|c| c.is_empty()) {
                return None;
            }
            if !seen_publishers.insert(entry.id) {
                return None;
            }

            name = crate::security::sanitize_remote_text(&name, 8192);
            comment = comment
                .map(|value| crate::security::sanitize_remote_text(&value, 4096))
                .filter(|value| !value.is_empty());
            let publisher_hex = entry.id.to_hex();
            let peer_name = publisher_hex.chars().take(8).collect::<String>();

            Some(SearchResult {
                file: FileInfo {
                    id: forced_hash.clone(),
                    name: if name.is_empty() {
                        "File note".to_string()
                    } else {
                        name
                    },
                    path: String::new(),
                    size,
                    hash: forced_hash.clone(),
                    aich_hash: String::new(),
                    ember_file_hash: String::new(),
                    extension: String::new(),
                    modified_at: 0,
                    priority: "normal".to_string(),
                    requests: 0,
                    accepted: 0,
                    bytes_transferred: 0,
                    alltime_requests: 0,
                    alltime_accepted: 0,
                    alltime_transferred: 0,
                    complete_sources: 0,
                    folder: String::new(),
                    shared: false,
                    friends_only: false,
                    shared_kad: false,
                    shared_ed2k: false,
                    shared_ember: false,
                },
                peer_id: publisher_hex,
                peer_name,
                availability: 0,
                file_type: String::new(),
                source_addresses: Vec::new(),
                rating,
                comment,
                media: None,
                spam_rating: 0,
                is_spam: false,
                clean_name: String::new(),
                result_origin: crate::search::merge::ORIGIN_NOTES.to_string(),
                origin_server_ip: None,
                spam_reasons: Vec::new(),
                spam_reason_details: Vec::new(),
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
pub(super) struct KadSource {
    pub(super) ip: Ipv4Addr,
    pub(super) tcp_port: u16,
    pub(super) udp_port: u16,
    pub(super) source_type: u8,
    pub(super) connect_options: u8,
    pub(super) buddy_ip: Option<Ipv4Addr>,
    pub(super) buddy_port: Option<u16>,
    pub(super) buddy_hash: Option<KadId>,
    /// For source-search results this is the publisher's ED2K user hash.
    pub(super) source_user_hash: Option<[u8; 16]>,
    /// Type-2: eD2K LowID value (0 = not a LowID source).
    pub(super) lowid: u32,
    /// Type-2: eD2K server IP (network u32).
    pub(super) ed2k_server_ip: u32,
    /// Type-2: eD2K server TCP port.
    pub(super) ed2k_server_port: u16,
    /// `true` if this peer advertised `EMBER_CAP_RELAY_PUNCH_V1` in the
    /// KAD source publish (string tag `"ember"`). The KAD-callback path
    /// gates its LowID-to-LowID broker attempt on this — see the
    /// `attempt_low_to_low` call site in this file. Defaults to `false`
    /// for any source we haven't seen the tag from (vanilla eMule peers,
    /// type-2 LowID sources from the ed2k server, or older Ember peers
    /// from before this tag existed).
    pub(super) is_ember_capable: bool,
    /// Ember Noise X25519 static public key, when the source publish
    /// carried [`kad::publish::EMBER_NOISE_PUB_TAG`]. Cached by the
    /// network task on receive so callers like `ember_ping_peer` can
    /// dial the peer's Ember-native UDP transport without a separate
    /// key exchange.
    pub(super) ember_noise_pub: Option<[u8; 32]>,
}

/// Returns true if this `KadSource` actually describes us — either by
/// matching our externally-visible `(IP, TCP port)` pair or by carrying
/// our ed2k `user_hash`.
///
/// Self-sources arise naturally after a publish cycle: we publish
/// `(SourceIP=our_ext_ip, SourcePort=our_tcp_port, SourceUID=our_user_hash)`
/// to the DHT nodes closest to each file hash, and a subsequent source
/// search for the same hash converges on those same nodes, which
/// dutifully hand our own entry back to us. Injecting it as a download
/// source wastes an idx slot and produces a noisy
/// "Injected source N failed: stage:hello_wait" line when we attempt to
/// connect to ourselves. The user-hash check also catches the dynamic
/// IP case where our publishes were made under a different IP than the
/// one we report now.
pub(super) fn is_self_source(src: &KadSource, state: &NetworkState) -> bool {
    if let Some(ext) = state.external_ip {
        // Compare against whatever port we actually publish (which may be
        // STUN-remapped), not the raw local bind port — otherwise our own
        // echoed-back publish is missed as "foreign" whenever a remap is
        // active, producing the exact self-connect noise this function
        // exists to prevent.
        if src.ip == ext
            && (src.tcp_port == state.tcp_port || src.tcp_port == advertised_tcp_port(state))
        {
            return true;
        }
    }
    if let Some(uh) = src.source_user_hash {
        if uh == state.user_hash {
            return true;
        }
    }
    false
}

/// Egress-target guard for LowID "connect-and-serve" dials triggered by a peer
/// callback (server `OP_CALLBACKREQUESTED` / KAD buddy `OP_CALLBACK`). eMule
/// mirrors a callback by connecting back to serve the requester, but we must
/// never dial an undialable or self target: port 0, a special-use / multicast
/// range (`is_special_use_v4` already covers multicast), our own external
/// endpoint, or our own user identity (self-dial / reflection). Runtime
/// `ip_filter` / banned-IP checks need live state and are applied by callers in
/// addition to this. Returns `true` only when the target is safe to dial.
pub(super) fn connect_serve_target_ok(
    dest_ip: Ipv4Addr,
    dest_port: u16,
    external_ip: Option<Ipv4Addr>,
    self_tcp_port: u16,
    self_tcp_port_alt: u16,
    dest_user_hash: Option<[u8; 16]>,
    self_user_hash: &[u8; 16],
) -> bool {
    if dest_port == 0 || crate::security::is_special_use_v4(dest_ip) {
        return false;
    }
    if let Some(ext) = external_ip {
        // Check both the raw bind port and whatever we currently advertise
        // (which may be STUN-remapped) — a caller may echo either back,
        // depending on when it last learned our port. See `is_self_source`.
        if dest_ip == ext && (dest_port == self_tcp_port || dest_port == self_tcp_port_alt) {
            return false;
        }
    }
    if let Some(uh) = dest_user_hash {
        if uh != [0u8; 16] && uh == *self_user_hash {
            return false;
        }
    }
    true
}

/// Drain buddy-relayed Ember `CALLBACK`s and eD2K `OP_DIRECTCALLBACKREQ`s:
/// connect-and-serve the requester (same upload-listener path as KAD
/// `OP_CALLBACK`).
pub(super) async fn drain_ember_callback_connects(
    state: &mut NetworkState,
    connect_serve_tx: &tokio::sync::mpsc::Sender<upload_server::ConnectServeRequest>,
) {
    let direct = std::mem::take(&mut state.pending_direct_callbacks);
    let pending = std::mem::take(&mut state.ember_pending_callback_connects);
    if pending.is_empty() && direct.is_empty() {
        return;
    }
    let self_tcp = advertised_tcp_port(state);
    for cb in direct {
        let safe = !state.ip_filter.is_blocked(cb.dest_ip)
            && !state.banned_ips.contains(&cb.dest_ip)
            && connect_serve_target_ok(
                cb.dest_ip,
                cb.dest_port,
                state.external_ip,
                state.tcp_port,
                self_tcp,
                cb.user_hash,
                &state.user_hash,
            );
        if !safe {
            continue;
        }
        let peer_addr = SocketAddr::new(cb.dest_ip.into(), cb.dest_port);
        debug!("Direct UDP callback: connecting to {peer_addr}");
        if let Err(e) = connect_serve_tx.try_send(upload_server::ConnectServeRequest {
            peer_addr,
            crypt_options: cb.crypt_options,
            user_hash: cb.user_hash,
            push_grant_file_hash: None,
            push_grant_accepted: None,
            secure_friend_ember_hash: None,
        }) {
            debug!("Could not enqueue direct callback-serve for {peer_addr}: {e}");
        }
    }
    for cb in pending {
        // Same as KAD `OP_CALLBACK`: connect-and-serve, do not treat this as
        // an AddUpNextClient push-grant (`push_grant_file_hash` would send
        // `OP_ACCEPTUPLOADREQ` immediately). `file_hash` is the published
        // source the searcher asked for — log it so a bad dest can be tied
        // back to the grant that unlocked this CALLBACK.
        info!(
            "Ember callback: connect to {}:{} for file {}",
            cb.dest_ip,
            cb.dest_port,
            hex::encode(cb.file_hash)
        );
        let safe = !state.ip_filter.is_blocked(cb.dest_ip)
            && !state.banned_ips.contains(&cb.dest_ip)
            && connect_serve_target_ok(
                cb.dest_ip,
                cb.dest_port,
                state.external_ip,
                state.tcp_port,
                self_tcp,
                cb.user_hash,
                &state.user_hash,
            );
        if !safe {
            continue;
        }
        let peer_addr = SocketAddr::new(cb.dest_ip.into(), cb.dest_port);
        if let Err(e) = connect_serve_tx.try_send(upload_server::ConnectServeRequest {
            peer_addr,
            crypt_options: cb.crypt_options,
            user_hash: cb.user_hash,
            push_grant_file_hash: None,
            push_grant_accepted: None,
            secure_friend_ember_hash: None,
        }) {
            debug!("Could not enqueue Ember callback-serve for {peer_addr}: {e}");
            continue;
        }
        state.ember_diagnostics.ember_dht_callback_connects = state
            .ember_diagnostics
            .ember_dht_callback_connects
            .saturating_add(1);
    }
}

pub(super) fn extract_kad_sources(entries: &[kad::messages::SearchResultEntry]) -> Vec<KadSource> {
    let mut sources = Vec::new();
    for entry in entries {
        let mut ip = 0u32;
        let mut port = 0u16;
        let mut udp_port = 0u16;
        let mut source_type = 0u8;
        let mut connect_options = 0u8;
        let mut server_ip = 0u32;
        let mut server_port = 0u16;
        let mut buddy_hash: Option<[u8; 16]> = None;
        let mut is_ember_capable = false;
        let mut ember_noise_pub: Option<[u8; 32]> = None;
        for tag in &entry.tags {
            match &tag.name {
                TagName::Id(TAG_SOURCEIP) => {
                    if let Some(v) = kad_tag_uint(tag) {
                        ip = v;
                    }
                }
                TagName::Id(TAG_SOURCEPORT) => {
                    if let Some(v) = kad_tag_uint(tag) {
                        port = v;
                    }
                }
                TagName::Id(TAG_SOURCEUPORT) => {
                    if let Some(v) = kad_tag_uint(tag) {
                        udp_port = v;
                    }
                }
                TagName::Id(TAG_SOURCETYPE) => {
                    if let Some(v) = kad_tag_uint(tag) {
                        source_type = v;
                    }
                }
                TagName::Id(TAG_ENCRYPTION) => {
                    if let Some(v) = kad_tag_uint(tag) {
                        connect_options = v;
                    }
                }
                TagName::Id(TAG_SERVERIP) => {
                    if let Some(v) = kad_tag_uint(tag) {
                        server_ip = v;
                    }
                }
                TagName::Id(TAG_SERVERPORT) => {
                    if let Some(v) = kad_tag_uint(tag) {
                        server_port = v;
                    }
                }
                TagName::Id(TAG_BUDDYHASH) => {
                    if let Some(h) = tag.hash_value() {
                        buddy_hash = Some(h);
                    } else if let Some(s) = tag.string_value() {
                        if let Ok(bytes) = hex::decode(s) {
                            if bytes.len() == 16 {
                                let mut h = [0u8; 16];
                                h.copy_from_slice(&bytes);
                                buddy_hash = Some(h);
                            }
                        }
                    }
                }
                // Ember capability advertisement — see the corresponding
                // emit site in `kad/publish.rs::build_source_publish` and
                // `EMBER_CAP_RELAY_PUNCH_V1`. Bit 0 means "speaks Ember
                // v1 LowID-to-LowID protocol". Higher bits are reserved.
                // Vanilla eMule peers won't carry this tag so the field
                // stays `false`, which is exactly what gates the broker.
                TagName::Str(s) if s == "ember" => {
                    if let Some(v) = tag.uint8_value() {
                        is_ember_capable = (v & kad::publish::EMBER_CAP_RELAY_PUNCH_V1) != 0;
                    }
                }
                // Ember Noise pubkey for the publisher — see
                // `kad::publish::EMBER_NOISE_PUB_TAG` for the emit
                // side. Reject anything that isn't exactly 32 bytes
                // (the X25519 raw key length) and reject all-zero
                // keys (suppressed on emission, treat as malformed
                // on receive too).
                TagName::Str(s) if s == kad::publish::EMBER_NOISE_PUB_TAG => {
                    if let Some(blob) = tag.blob_value() {
                        if blob.len() == 32 && blob != [0u8; 32] {
                            let mut key = [0u8; 32];
                            key.copy_from_slice(blob);
                            ember_noise_pub = Some(key);
                        }
                    }
                }
                _ => {}
            }
        }

        let source_user_hash = if entry.id.0 != [0u8; 16] {
            Some(cuint128_swap(&entry.id.0))
        } else {
            None
        };

        match source_type {
            1 | 4 => {
                if ip != 0 && port != 0 {
                    let addr = Ipv4Addr::from(ip.to_be_bytes());
                    if !sources
                        .iter()
                        .any(|s: &KadSource| s.ip == addr && s.tcp_port == port)
                    {
                        sources.push(KadSource {
                            ip: addr,
                            tcp_port: port,
                            udp_port,
                            source_type,
                            connect_options,
                            buddy_ip: None,
                            buddy_port: None,
                            buddy_hash: None,
                            source_user_hash,
                            lowid: 0,
                            ed2k_server_ip: 0,
                            ed2k_server_port: 0,
                            is_ember_capable,
                            ember_noise_pub,
                        });
                    }
                }
            }
            2 => {
                if ip > 0
                    && ip < ed2k::server::LOWID_THRESHOLD
                    && server_ip != 0
                    && server_port != 0
                {
                    if !sources
                        .iter()
                        .any(|s: &KadSource| s.lowid == ip && s.ed2k_server_ip == server_ip)
                    {
                        sources.push(KadSource {
                            ip: Ipv4Addr::UNSPECIFIED,
                            tcp_port: port,
                            udp_port,
                            source_type,
                            connect_options,
                            buddy_ip: None,
                            buddy_port: None,
                            buddy_hash: None,
                            source_user_hash,
                            lowid: ip,
                            ed2k_server_ip: server_ip,
                            ed2k_server_port: server_port,
                            is_ember_capable,
                            ember_noise_pub,
                        });
                    }
                } else if ip != 0 && port != 0 {
                    let addr = Ipv4Addr::from(ip.to_be_bytes());
                    if !sources
                        .iter()
                        .any(|s: &KadSource| s.ip == addr && s.tcp_port == port)
                    {
                        sources.push(KadSource {
                            ip: addr,
                            tcp_port: port,
                            udp_port,
                            source_type,
                            connect_options,
                            buddy_ip: None,
                            buddy_port: None,
                            buddy_hash: None,
                            source_user_hash,
                            lowid: 0,
                            ed2k_server_ip: 0,
                            ed2k_server_port: 0,
                            is_ember_capable,
                            ember_noise_pub,
                        });
                    }
                }
            }
            3 | 5 => {
                // Prefer callback path when buddy data is present, otherwise fall back
                // to direct candidate handling for interoperability with mixed clients.
                if server_ip != 0 && server_port != 0 {
                    let source_addr = Ipv4Addr::from(ip.to_be_bytes());
                    // CRITICAL byte-order asymmetry (eMule DownloadQueue.cpp
                    // CDownloadQueue::KademliaSearchFile): the source IP and the
                    // buddy IP arrive in *opposite* byte orders even though both
                    // tags decode identically off the wire. eMule applies
                    // `htonl()` to the source IP (`ED2Kip = htonl(ip)`) but feeds
                    // the buddy IP to `SetBuddyIP(dwBuddyIP)` / the callback
                    // `SendPacket` RAW (already network order). So the source
                    // needs the big-endian transform (`to_be_bytes`) while the
                    // buddy must use little-endian (`to_le_bytes`). Using
                    // `to_be_bytes` here byte-reversed every buddy address —
                    // turning real residential buddies (e.g. 88.147.30.21) into
                    // unroutable DoD ranges (21.30.147.88), so every
                    // KADEMLIA_CALLBACK_REQ was fired into the void and no
                    // firewalled source ever connected back.
                    let b_ip = Ipv4Addr::from(server_ip.to_le_bytes());
                    let b_hash = buddy_hash.map(KadId);
                    if !sources.iter().any(|s: &KadSource| {
                        s.buddy_ip == Some(b_ip) && s.buddy_port == Some(server_port)
                    }) {
                        sources.push(KadSource {
                            ip: source_addr,
                            tcp_port: port,
                            udp_port,
                            source_type,
                            connect_options,
                            buddy_ip: Some(b_ip),
                            buddy_port: Some(server_port),
                            buddy_hash: b_hash,
                            source_user_hash,
                            lowid: 0,
                            ed2k_server_ip: 0,
                            ed2k_server_port: 0,
                            is_ember_capable,
                            ember_noise_pub,
                        });
                    }
                } else if ip != 0 && port != 0 {
                    let addr = Ipv4Addr::from(ip.to_be_bytes());
                    debug!("Source type {} without buddy tags, treating {addr}:{port} as direct fallback", source_type);
                    if !sources
                        .iter()
                        .any(|s: &KadSource| s.ip == addr && s.tcp_port == port)
                    {
                        sources.push(KadSource {
                            ip: addr,
                            tcp_port: port,
                            udp_port,
                            source_type,
                            connect_options,
                            buddy_ip: None,
                            buddy_port: None,
                            buddy_hash: None,
                            source_user_hash,
                            lowid: 0,
                            ed2k_server_ip: 0,
                            ed2k_server_port: 0,
                            is_ember_capable,
                            ember_noise_pub,
                        });
                    }
                }
            }
            6 => {
                if ip != 0 && port != 0 {
                    let addr = Ipv4Addr::from(ip.to_be_bytes());
                    debug!("Type-6 source {addr}:{port} treated as direct fallback");
                    if !sources
                        .iter()
                        .any(|s: &KadSource| s.ip == addr && s.tcp_port == port)
                    {
                        sources.push(KadSource {
                            ip: addr,
                            tcp_port: port,
                            udp_port,
                            source_type,
                            connect_options,
                            buddy_ip: None,
                            buddy_port: None,
                            buddy_hash: None,
                            source_user_hash,
                            lowid: 0,
                            ed2k_server_ip: 0,
                            ed2k_server_port: 0,
                            is_ember_capable,
                            ember_noise_pub,
                        });
                    }
                }
            }
            _ => {
                if ip != 0 && port != 0 {
                    let addr = Ipv4Addr::from(ip.to_be_bytes());
                    if !sources
                        .iter()
                        .any(|s: &KadSource| s.ip == addr && s.tcp_port == port)
                    {
                        sources.push(KadSource {
                            ip: addr,
                            tcp_port: port,
                            udp_port,
                            source_type: 3,
                            connect_options,
                            buddy_ip: None,
                            buddy_port: None,
                            buddy_hash: None,
                            source_user_hash,
                            lowid: 0,
                            ed2k_server_ip: 0,
                            ed2k_server_port: 0,
                            is_ember_capable,
                            ember_noise_pub,
                        });
                    }
                }
            }
        }
    }
    sources
}

#[derive(Debug, Clone)]
pub(super) enum KadSearchExpr {
    And(Box<KadSearchExpr>, Box<KadSearchExpr>),
    Or(Box<KadSearchExpr>, Box<KadSearchExpr>),
    Not(Box<KadSearchExpr>, Box<KadSearchExpr>),
    String(String),
    MetaString {
        tag: SearchTagRef,
        value: String,
    },
    Numeric {
        tag: SearchTagRef,
        op: KadNumericOp,
        value: u64,
    },
}

#[derive(Debug, Clone)]
pub(super) enum SearchTagRef {
    Id(u8),
    Str(String),
}

#[derive(Debug, Clone, Copy)]
pub(super) enum KadNumericOp {
    Eq,
    Gt,
    Lt,
    Ge,
    Le,
    Ne,
}

pub(super) fn parse_kad_search_expression(data: &[u8]) -> Option<KadSearchExpr> {
    const MAX_KAD_SEARCH_EXPR_BYTES: usize = 16 * 1024;

    if data.is_empty() {
        return None;
    }
    if data.len() > MAX_KAD_SEARCH_EXPR_BYTES {
        return None;
    }
    let mut cursor = Cursor::new(data);
    // K5: hostile peers can craft a deep left-leaning boolean expression
    // in a ~64 KiB UDP packet; recursive descent would blow the stack.
    // Cap both depth and total node count. eMule's own SearchKeyReq
    // expressions are trivially small in practice (a few leaves).
    let mut node_budget: u32 = 256;
    let expr = parse_kad_search_expression_node(&mut cursor, 0, &mut node_budget).ok()?;
    if cursor.position() as usize != data.len() {
        return None;
    }
    Some(expr)
}

/// Maximum nesting depth for a KAD search expression. Chosen so a legit
/// `(a AND b AND c AND d AND ...)` of 32 conjuncts still parses but
/// nothing remotely close to stack exhaustion is possible.
pub(super) const MAX_KAD_SEARCH_EXPR_DEPTH: u32 = 32;

pub(super) fn parse_kad_search_expression_node(
    cursor: &mut Cursor<&[u8]>,
    depth: u32,
    node_budget: &mut u32,
) -> std::io::Result<KadSearchExpr> {
    if depth >= MAX_KAD_SEARCH_EXPR_DEPTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "search expression nested too deeply",
        ));
    }
    if *node_budget == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "search expression exceeded node-count budget",
        ));
    }
    *node_budget -= 1;
    match ReadBytesExt::read_u8(cursor)? {
        0x00 => {
            let op = ReadBytesExt::read_u8(cursor)?;
            let left = Box::new(parse_kad_search_expression_node(
                cursor,
                depth + 1,
                node_budget,
            )?);
            let right = Box::new(parse_kad_search_expression_node(
                cursor,
                depth + 1,
                node_budget,
            )?);
            match op {
                0x00 => Ok(KadSearchExpr::And(left, right)),
                0x01 => Ok(KadSearchExpr::Or(left, right)),
                0x02 => Ok(KadSearchExpr::Not(left, right)),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unknown boolean search operator",
                )),
            }
        }
        0x01 => Ok(KadSearchExpr::String(read_kad_search_string(cursor)?)),
        0x02 => {
            let value = read_kad_search_string(cursor)?;
            let tag = read_kad_search_tag_ref(cursor)?;
            Ok(KadSearchExpr::MetaString { tag, value })
        }
        0x03 => {
            let value = ReadBytesExt::read_u32::<LittleEndian>(cursor)? as u64;
            let op = read_kad_numeric_op(ReadBytesExt::read_u8(cursor)?)?;
            let tag = read_kad_search_tag_ref(cursor)?;
            Ok(KadSearchExpr::Numeric { tag, op, value })
        }
        0x08 => {
            let value = ReadBytesExt::read_u64::<LittleEndian>(cursor)?;
            let op = read_kad_numeric_op(ReadBytesExt::read_u8(cursor)?)?;
            let tag = read_kad_search_tag_ref(cursor)?;
            Ok(KadSearchExpr::Numeric { tag, op, value })
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unknown search expression node",
        )),
    }
}

pub(super) fn read_kad_numeric_op(op: u8) -> std::io::Result<KadNumericOp> {
    match op {
        0x00 => Ok(KadNumericOp::Eq),
        0x01 => Ok(KadNumericOp::Gt),
        0x02 => Ok(KadNumericOp::Lt),
        0x03 => Ok(KadNumericOp::Ge),
        0x04 => Ok(KadNumericOp::Le),
        0x05 => Ok(KadNumericOp::Ne),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unknown numeric search operator",
        )),
    }
}

pub(super) fn read_kad_search_string(cursor: &mut Cursor<&[u8]>) -> std::io::Result<String> {
    const MAX_KAD_SEARCH_STRING_BYTES: usize = 1024;

    let len = ReadBytesExt::read_u16::<LittleEndian>(cursor)? as usize;
    if len > MAX_KAD_SEARCH_STRING_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "search string exceeds length cap",
        ));
    }
    let start = cursor.position() as usize;
    let end = start.saturating_add(len);
    if end > cursor.get_ref().len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "search string exceeds payload",
        ));
    }
    let bytes = &cursor.get_ref()[start..end];
    cursor.set_position(end as u64);
    Ok(String::from_utf8_lossy(bytes).to_string())
}

pub(super) fn read_kad_search_tag_ref(cursor: &mut Cursor<&[u8]>) -> std::io::Result<SearchTagRef> {
    const MAX_KAD_SEARCH_TAG_BYTES: usize = 128;

    let len = ReadBytesExt::read_u16::<LittleEndian>(cursor)? as usize;
    if len > MAX_KAD_SEARCH_TAG_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "search tag name exceeds length cap",
        ));
    }
    let start = cursor.position() as usize;
    let end = start.saturating_add(len);
    if end > cursor.get_ref().len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "search tag name exceeds payload",
        ));
    }
    let bytes = &cursor.get_ref()[start..end];
    cursor.set_position(end as u64);
    if len == 1 {
        Ok(SearchTagRef::Id(bytes[0]))
    } else {
        Ok(SearchTagRef::Str(
            String::from_utf8_lossy(bytes).to_string().to_lowercase(),
        ))
    }
}

pub(super) fn matches_search_expr_for_tags(expr: &KadSearchExpr, tags: &[KadTag]) -> bool {
    let file_name = tags
        .iter()
        .find(|tag| matches!(&tag.name, TagName::Id(TAG_FILENAME)))
        .and_then(|tag| tag.string_value())
        .map(kad::publish::kad_keyword_lowercase)
        .unwrap_or_default();
    let file_size = tags.iter().find_map(search_entry_tag_u64).unwrap_or(0);
    matches_search_expr_impl(expr, &file_name, file_size, Some(tags))
}

pub(super) fn search_entry_tag_u64(tag: &KadTag) -> Option<u64> {
    if !matches!(&tag.name, TagName::Id(TAG_FILESIZE)) {
        return None;
    }
    tag.uint64_value()
        .or_else(|| tag.uint32_value().map(|v| v as u64))
        .or_else(|| tag.uint16_value().map(|v| v as u64))
        .or_else(|| tag.uint8_value().map(|v| v as u64))
}

pub(super) fn matches_search_expr_impl(
    expr: &KadSearchExpr,
    lower_name: &str,
    file_size: u64,
    tags: Option<&[KadTag]>,
) -> bool {
    match expr {
        KadSearchExpr::And(left, right) => {
            matches_search_expr_impl(left, lower_name, file_size, tags)
                && matches_search_expr_impl(right, lower_name, file_size, tags)
        }
        KadSearchExpr::Or(left, right) => {
            matches_search_expr_impl(left, lower_name, file_size, tags)
                || matches_search_expr_impl(right, lower_name, file_size, tags)
        }
        KadSearchExpr::Not(left, right) => {
            matches_search_expr_impl(left, lower_name, file_size, tags)
                && !matches_search_expr_impl(right, lower_name, file_size, tags)
        }
        KadSearchExpr::String(value) => {
            // eMule tokenizes a string term on the keyword separators and
            // requires every word (`SSearchTerm::Evaluate`), so a quoted
            // `"pink floyd"` matches `Pink_Floyd-The_Wall`. A term with no
            // word in it matches nothing, as there.
            let value = kad::publish::kad_keyword_lowercase(value);
            let mut words = value
                .split(kad::publish::is_kad_keyword_separator)
                .filter(|word| !word.is_empty())
                .peekable();
            words.peek().is_some() && words.all(|word| lower_name.contains(word))
        }
        KadSearchExpr::MetaString { tag, value } => {
            let value = kad::publish::kad_keyword_lowercase(value);
            if tag_matches_filename(tag) {
                lower_name.contains(&value)
            } else if tag_matches_fileformat(tag) {
                // Nobody publishes the extension as a tag: it is part of the
                // name, and eMule matches it there (`Entry.cpp`, "special
                // handling for TAG_FILEFORMAT"). Looked up as a stored tag, an
                // extension filter matched nothing on an Ember storage node.
                let wanted = value.trim_start_matches('.');
                lower_name
                    .rsplit_once('.')
                    .is_some_and(|(_, ext)| !wanted.is_empty() && ext == wanted)
            } else if let Some(tags) = tags {
                tags.iter()
                    .find(|entry_tag| tag_name_matches(tag, &entry_tag.name))
                    .and_then(|entry_tag| entry_tag.string_value())
                    .map(|entry_value| {
                        kad::publish::kad_keyword_lowercase(entry_value).contains(&value)
                    })
                    .unwrap_or(false)
            } else {
                false
            }
        }
        KadSearchExpr::Numeric { tag, op, value } => {
            let numeric = if tag_matches_filesize(tag) {
                Some(file_size)
            } else if let Some(tags) = tags {
                tags.iter()
                    .find(|entry_tag| tag_name_matches(tag, &entry_tag.name))
                    .and_then(|entry_tag| {
                        entry_tag
                            .uint64_value()
                            .or_else(|| entry_tag.uint32_value().map(|v| v as u64))
                            .or_else(|| entry_tag.uint16_value().map(|v| v as u64))
                            .or_else(|| entry_tag.uint8_value().map(|v| v as u64))
                    })
            } else {
                None
            };
            numeric
                .map(|actual| match op {
                    KadNumericOp::Eq => actual == *value,
                    KadNumericOp::Gt => actual > *value,
                    KadNumericOp::Lt => actual < *value,
                    KadNumericOp::Ge => actual >= *value,
                    KadNumericOp::Le => actual <= *value,
                    KadNumericOp::Ne => actual != *value,
                })
                .unwrap_or(false)
        }
    }
}

pub(super) fn tag_name_matches(search_tag: &SearchTagRef, tag_name: &TagName) -> bool {
    match (search_tag, tag_name) {
        (SearchTagRef::Id(a), TagName::Id(b)) => a == b,
        (SearchTagRef::Str(a), TagName::Str(b)) => a == &b.to_lowercase(),
        (SearchTagRef::Str(a), TagName::Id(b)) if a.len() == 1 => a.as_bytes()[0] == *b,
        _ => false,
    }
}

pub(super) fn tag_matches_filename(tag: &SearchTagRef) -> bool {
    match tag {
        SearchTagRef::Id(id) => *id == TAG_FILENAME,
        SearchTagRef::Str(name) => name == "filename" || name == "name",
    }
}

/// eMule `TAG_FILEFORMAT` (`FT_FILEFORMAT`): the file extension, no dot.
const TAG_FILEFORMAT: u8 = 0x04;

pub(super) fn tag_matches_fileformat(tag: &SearchTagRef) -> bool {
    match tag {
        SearchTagRef::Id(id) => *id == TAG_FILEFORMAT,
        SearchTagRef::Str(_) => false,
    }
}

pub(super) fn tag_matches_filesize(tag: &SearchTagRef) -> bool {
    match tag {
        SearchTagRef::Id(id) => *id == TAG_FILESIZE,
        SearchTagRef::Str(name) => name == "filesize" || name == "size",
    }
}

pub(super) fn matches_requested_file_size_tags(tags: &[KadTag], requested_size: u64) -> bool {
    if requested_size == 0 {
        return true;
    }
    // A specific size was requested. eMule's source/notes search requests
    // carry the exact file size and the index only returns entries that match
    // it; an entry with no size tag cannot be confirmed to match, so reject it
    // rather than leak a possibly-wrong-size source into the requester's
    // download source selection.
    tags.iter()
        .find_map(search_entry_tag_u64)
        .map(|size| size == requested_size)
        .unwrap_or(false)
}

#[cfg(test)]
mod fileformat_tests {
    use super::*;

    fn named(name: &str) -> Vec<KadTag> {
        vec![KadTag {
            name: TagName::Id(TAG_FILENAME),
            value: TagValue::String(name.to_string()),
        }]
    }

    fn ext(value: &str) -> KadSearchExpr {
        KadSearchExpr::MetaString {
            tag: SearchTagRef::Id(TAG_FILEFORMAT),
            value: value.to_string(),
        }
    }

    #[test]
    fn an_extension_term_matches_the_file_name_like_emule() {
        let tags = named("Some.Movie.2024.MKV");
        assert!(matches_search_expr_for_tags(&ext("mkv"), &tags));
        assert!(matches_search_expr_for_tags(&ext(".mkv"), &tags));
        assert!(!matches_search_expr_for_tags(&ext("mk"), &tags), "equality, not a substring");
        assert!(!matches_search_expr_for_tags(&ext("avi"), &tags));
        assert!(!matches_search_expr_for_tags(&ext("mkv"), &named("no_extension")));
        assert!(!matches_search_expr_for_tags(&ext(""), &tags));
    }
}

#[cfg(test)]
mod convert_tests {
    use super::*;

    fn entry(name: &str) -> kad::messages::SearchResultEntry {
        kad::messages::SearchResultEntry {
            id: KadId([0x42; 16]),
            tags: vec![
                KadTag {
                    name: TagName::Id(TAG_FILENAME),
                    value: TagValue::String(name.to_string()),
                },
                KadTag {
                    name: TagName::Id(TAG_FILESIZE),
                    value: TagValue::Uint32(4096),
                },
            ],
        }
    }

    #[test]
    fn a_better_name_from_a_later_node_brings_its_extension_and_type() {
        let padded = "[promo] [promo] Holiday Clip.avi";
        let clean = "Holiday Clip.zip";
        assert!(name_spam_penalty(clean) < name_spam_penalty(padded));

        let results = convert_search_results(&[entry(padded), entry(clean)], |_| true);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file.name, clean);
        assert_eq!(results[0].file.extension, "zip");
        assert_eq!(results[0].file_type, "Arc");
    }
}
