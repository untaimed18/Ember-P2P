//! Ember DHT searches: driving and finishing searches, parsing source and
//! keyword records, and publisher digest corroboration.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// Push an iterative lookup forward: pull the next α-bounded batch of
/// contacts from the search, send each a signed `FIND_NODE` over the
/// Noise transport, and record the in-flight wire requests. Then check
/// whether the search has converged (or had nothing to do) and, if so,
/// resolve its waiter.
///
/// Called when a lookup starts, when a `FOUND_NODE` advances it, and
/// from the staleness sweep after a query is marked failed.
pub(super) async fn drive_ember_search(socket: &UdpSocket, state: &mut NetworkState, search_id: u32) {
    // A FIND_NODE search queries by target id; a FIND_VALUE search queries
    // by the record key(s) (the primary key plus any extra keyword hashes
    // for multi-keyword lookups), and a peer answers either with the
    // records (FOUND_VALUE) or the closest contacts (FOUND_NODE).
    let (target, search_type, extra_keys, constraints) = match state.ember_search.get(search_id) {
        Some(s) => (
            s.target,
            s.search_type,
            s.keyword_hashes.clone(),
            s.value_constraints().clone(),
        ),
        None => return,
    };

    let mut batch_sent = 0u32;
    // Keep pulling batches until one of them actually reaches the wire.
    //
    // Nothing re-drives a search except a response or a query deadline, and a
    // query that was never sent has neither — so a call that retires its whole
    // batch without transmitting leaves the walk idle until `cleanup_expired`
    // reaps it two minutes later, holding a search slot and resolving its
    // waiter empty. A scattered send failure rarely takes a whole batch, but an
    // address the IP policy refuses is *systematically* correlated: an attacker
    // can choose node ids near the target (the id is theirs to pick, which is
    // the premise of the gate below) with addresses in a blocked range and
    // occupy the head of the shortlist deliberately.
    let mut barren_rounds = 0usize;
    loop {
        let batch = match state.ember_search.get_mut(search_id) {
            Some(s) => s.next_to_query(),
            None => return,
        };
        if batch.is_empty() {
            break;
        }
        for query in batch {
        let ember::dht::search::QueryTarget {
            contact,
            request_id: per_search_req_id,
            start_position,
        } = query;
        // The shortlist is not the routing table, and its contents arrive
        // straight out of a peer's `FOUND_NODE`. The table refuses an address
        // the user blocked, but a search dialled its own shortlist directly, so
        // a peer could name any IPv4 address it liked — a blocked range,
        // special-use space, or a third party — and have us open unsolicited
        // Noise handshakes to it. Getting into the top of the shortlist is
        // cheap, since the node id is the attacker's to choose. Every other
        // Ember dial path already consults this gate.
        //
        // `definitely_blocked`, not `!admits_addr`: the latter is fail-*closed*
        // while `ipfilter.dat` is still parsing, and Ember addresses are never
        // Kad seeds, so during that window it refuses every peer — which would
        // have made a search on any node with the filter enabled retire its
        // whole shortlist without dialling anyone. "Known bad" is the right
        // question for whether to dial; the routing table draws the same
        // distinction for admission versus eviction.
        if state.ember_dht.routing().definitely_blocked(&contact.addr) {
            debug!(
                "Ember search {search_id}: refusing to query {} — the IP policy blocks it",
                contact.addr
            );
            if let Some(search) = state.ember_search.get_mut(search_id) {
                let _ = search.mark_failed_with(
                    per_search_req_id,
                    ember::dht::search::QueryFailure::NotSent,
                );
            }
            continue;
        }
        let (wire_req_id, frame) = match search_type {
            ember::dht::search::SearchType::FindNode => state.ember_dht.build_find_node(target),
            ember::dht::search::SearchType::FindValue => {
                let mut keys = Vec::with_capacity(1 + extra_keys.len());
                keys.push(target.0);
                keys.extend_from_slice(&extra_keys);
                // Non-zero on a page follow-up: this node already answered and
                // said it holds records past what its datagram could carry.
                state
                    .ember_dht
                    .build_find_value(keys, start_position, constraints.clone())
            }
        };

        // Tracked separately from `send_ok`: a query still sitting behind a
        // handshake has not reached the peer yet, so the ordinary query budget
        // would expire it before it was ever asked anything.
        let mut behind_handshake = false;
        let send_ok = match state.ember_transport.prepare_outgoing(
            contact.addr,
            Some(&contact.noise_pub),
            &frame,
        ) {
            ember::transport::OutgoingResult::Ready { packet } => {
                match send_ember_udp(socket, &packet, contact.addr, &state.ember_dht_overhead).await
                {
                    Ok(_) => true,
                    Err(e) => {
                        debug!(
                            "Ember DHT search {search_id}: send to {} failed: {e}",
                            contact.addr
                        );
                        false
                    }
                }
            }
            ember::transport::OutgoingResult::HandshakeStarted { packet } => {
                behind_handshake = true;
                match send_ember_udp(socket, &packet, contact.addr, &state.ember_dht_overhead).await
                {
                    Ok(_) => true,
                    Err(e) => {
                        debug!(
                            "Ember DHT search {search_id}: send to {} failed: {e}",
                            contact.addr
                        );
                        false
                    }
                }
            }
            // A handshake to this peer is already in flight; the frame is
            // queued and will ride out when it completes — treat as sent, but
            // give it the longer budget below.
            ember::transport::OutgoingResult::Queued => {
                behind_handshake = true;
                true
            }
            ember::transport::OutgoingResult::Error(e) => {
                debug!(
                    "Ember DHT search {search_id}: transport error for {}: {e}",
                    contact.addr
                );
                false
            }
        };

        if !send_ok {
            // Couldn't get the query out — fail this shortlist entry so
            // the search doesn't wait on a node we never reached.
            //
            // `NotSent`, not the default timeout semantics: those deliberately
            // return a retryable entry to `Pending` because the deadline sweep
            // re-drives the search afterwards. Nothing re-drives this path — we
            // never registered a wire request to time out — so leaving the entry
            // pending stalled the whole walk. With a one-entry shortlist (the
            // small overlay this actually runs on) a single ENETUNREACH held the
            // search, and its waiter, until the 120s backstop reaped it.
            //
            // Count the miss like a lookup timeout, not a liveness ping:
            // `prepare_outgoing` Error (handshake in flight for another
            // identity) used to 3-strike the only `nodes_ember.dat` seed on a
            // cold join. Unverified leads still skip `fault_ember_search_contact`.
            let failed = state
                .ember_search
                .get_mut(search_id)
                .and_then(|s| {
                    s.mark_failed_with(
                        per_search_req_id,
                        ember::dht::search::QueryFailure::NotSent,
                    )
                });
            if let Some(node_id) = failed {
                fault_ember_search_contact(state, &node_id);
            }
            continue;
        }

        if !behind_handshake {
            if search_type == ember::dht::search::SearchType::FindNode {
                state.ember_diagnostics.ember_dht_find_nodes_sent = state
                    .ember_diagnostics
                    .ember_dht_find_nodes_sent
                    .saturating_add(1);
            } else {
                state.ember_diagnostics.ember_dht_find_values_sent = state
                    .ember_diagnostics
                    .ember_dht_find_values_sent
                    .saturating_add(1);
            }
        }
        batch_sent = batch_sent.saturating_add(1);
        let budget = if behind_handshake {
            EMBER_SEARCH_QUEUED_QUERY_TIMEOUT
        } else {
            EMBER_SEARCH_QUERY_TIMEOUT
        };
        state.ember_dht_search_requests.insert(
            wire_req_id,
            EmberSearchRequest {
                search_id,
                per_search_req_id,
                deadline: std::time::Instant::now() + budget,
                sent_unix: chrono::Utc::now().timestamp(),
            },
        );
        }
        if batch_sent > 0 {
            break;
        }
        // Nothing left this call. Bounded so a shortlist of entries we cannot
        // dial costs one pass, not a spin: every barren round retires its
        // whole batch, so the shortlist strictly shrinks and this terminates
        // well before the cap on any real search.
        barren_rounds += 1;
        if barren_rounds >= EMBER_SEARCH_MAX_BARREN_ROUNDS {
            debug!(
                "Ember search {search_id}: gave up after {barren_rounds} batches that could \
                 not be dialled"
            );
            break;
        }
    }

    if batch_sent > 0 {
        state.ember_diagnostics.ember_dht_search_rounds = state
            .ember_diagnostics
            .ember_dht_search_rounds
            .saturating_add(1);
    }

    maybe_finish_ember_search(state, search_id);
}

/// Resolve and tear down an iterative lookup if it has converged. Safe
/// to call after every batch / response; a no-op while the search is
/// still in progress.
pub(super) fn maybe_finish_ember_search(state: &mut NetworkState, search_id: u32) {
    let (complete, search_type) = match state.ember_search.get_mut(search_id) {
        Some(s) => (s.poll_complete(), s.search_type),
        None => return,
    };
    if !complete {
        return;
    }

    // A FIND_NODE lookup resolves with the closest contacts that
    // responded; a FIND_VALUE lookup resolves with the raw record blobs
    // the search gathered (the command re-verifies each signature before
    // surfacing it).
    match search_type {
        ember::dht::search::SearchType::FindNode => {
            let contacts = state
                .ember_search
                .get(search_id)
                .map(|s| s.closest_responded())
                .unwrap_or_default();
            if let Some(tx) = state.ember_dht_pending_lookups.remove(&search_id) {
                let local_id = state.ember_dht.local_id();
                let infos = contacts
                    .iter()
                    .map(|c| ember_dht_contact_info(c, local_id))
                    .collect();
                let _ = tx.send(infos);
            }
            // A publish-target lookup: file the closest nodes that answered
            // under the key they were found for. An empty result is not cached,
            // so a walk that reached nobody leaves the key queued rather than
            // pinning an empty target set for the whole TTL.
            if let Some(key) = state.ember_publish_target_lookups.remove(&search_id) {
                if contacts.is_empty() {
                    debug!(
                        "Ember DHT: target lookup for {} found nobody; keeping the table's answer",
                        hex::encode(key)
                    );
                } else {
                    if state.ember_publish_targets.len() >= EMBER_PUBLISH_TARGETS_MAX
                        && !state.ember_publish_targets.contains_key(&key)
                    {
                        // Drop whichever set we learned longest ago: it is the
                        // one closest to needing a fresh lookup anyway.
                        if let Some(stalest) = state
                            .ember_publish_targets
                            .iter()
                            .min_by_key(|(_, (_, at))| *at)
                            .map(|(k, _)| *k)
                        {
                            state.ember_publish_targets.remove(&stalest);
                        }
                    }
                    let now = chrono::Utc::now().timestamp();
                    // IDs only — see `NetworkState::ember_publish_targets` for why
                    // the addresses are deliberately not kept.
                    let ids: Vec<ember::dht::EmberNodeId> =
                        contacts.iter().map(|c| c.node_id).collect();
                    let learned = ids.len();
                    state.ember_publish_targets.insert(key, (ids, now));
                    debug!(
                        "Ember DHT: {learned} publish targets learned for {}",
                        hex::encode(key)
                    );
                }
            }
        }
        ember::dht::search::SearchType::FindValue => {
            if let Some(search) = state.ember_search.get(search_id) {
                record_ember_find_value_quality(&mut state.ember_diagnostics, search);
            }
            let records = state
                .ember_search
                .get(search_id)
                .map(|s| s.results.iter().map(|r| r.data.clone()).collect::<Vec<_>>())
                .unwrap_or_default();
            if records.is_empty() {
                state.ember_diagnostics.ember_dht_search_misses = state
                    .ember_diagnostics
                    .ember_dht_search_misses
                    .saturating_add(1);
            } else {
                state.ember_diagnostics.ember_dht_search_hits = state
                    .ember_diagnostics
                    .ember_dht_search_hits
                    .saturating_add(1);
            }
            if let Some(tx) = state.ember_dht_pending_value_lookups.remove(&search_id) {
                // Dev/command value lookup: hand the raw blobs to the waiter.
                let _ = tx.send(records);
            } else if let Some((_transfer_id, file_hash)) =
                state.ember_download_source_searches.remove(&search_id)
            {
                // Download source lookup (slice 9): parse the gathered blobs
                // into connectable sources and queue them for async injection
                // into the matching download on the next sweep tick.
                let self_ip = state.external_ip;
                let established = ember_established_addrs(state);
                let sources = parse_ember_source_records(
                    &records,
                    file_hash,
                    self_ip,
                    &mut state.ember_diagnostics,
                    &mut state.ember_noise_keys,
                    &established,
                    &mut state.ember_content_hashes,
                );
                if !sources.is_empty() {
                    state
                        .ember_pending_source_injections
                        .push((file_hash, sources));
                }
            } else if let Some(kw) = state.ember_keyword_searches.remove(&search_id) {
                // User keyword search (slice 10): build SearchResults from
                // the gathered keyword records and buffer them for the async
                // emit on the next sweep tick (which has the enrich pipeline
                // + app_handle). Always queued -- even when empty -- so the
                // sweep clears `ember_pending` and `search-complete` fires.
                //
                // Deliberately every record, not just the tail the streaming
                // sweep has yet to send. `build_ember_keyword_built`
                // aggregates across the records it is handed: `availability` is
                // the number of distinct publishers, and a row carries a
                // plurality digest for display/click while automatic map
                // seeding still requires two publishers to agree. Handing it
                // one batch at a time computes both per batch, so a file whose
                // publishers arrived in different batches is under-counted and
                // loses its corroborated digest — which silently drops the
                // BLAKE3 check the corroboration rule exists to guarantee.
                //
                // Re-emitting a streamed row is not a duplicate: `dedup_streamed_batch`
                // in the emit sweep turns any hash already streamed into an
                // availability update carrying these corrected values.
                let built =
                    build_ember_keyword_built(&records, &kw.keywords, kw.query_expr.as_ref());
                for (ed2k, digest, publishers) in &built.corroborated {
                    seed_ember_content_hash(
                        &mut state.ember_content_hashes,
                        *ed2k,
                        *digest,
                        EmberDigestProvenance::Corroborated(*publishers),
                    );
                }
                let results = built.results;
                state
                    .ember_pending_keyword_results
                    .push(EmberKeywordResultBatch {
                        request_id: kw.request_id,
                        keywords: kw.keywords,
                        file_type_filter: kw.file_type_filter,
                        min_size: kw.min_size,
                        max_size: kw.max_size,
                        file_extension: kw.file_extension,
                        min_availability: kw.min_availability,
                        results,
                        final_batch: true,
                    });
            } else if let Some(channel_id) =
                state.ember_channel_presence_searches.remove(&search_id)
            {
                buffer_channel_presence_records(state, channel_id, records);
            } else if let Some(channel_id) =
                state.ember_channel_claim_searches.remove(&search_id)
            {
                state
                    .ember_pending_channel_claim
                    .push((channel_id, records));
            } else if let Some((channel_id, epoch)) =
                state.ember_channel_epoch_searches.remove(&search_id)
            {
                state
                    .ember_pending_channel_epoch
                    .push((channel_id, epoch, records));
            } else if let Some(channel_id) =
                state.ember_channel_moderation_searches.remove(&search_id)
            {
                // How many peers actually answered. An empty result from a
                // search nobody answered says nothing about the owner — it says
                // we could not reach the network — and succession must not read
                // the two the same way.
                let answered = state
                    .ember_search
                    .get(search_id)
                    .map(|s| s.responded_count())
                    .unwrap_or(0);
                state
                    .ember_pending_channel_moderation
                    .push((channel_id, records, answered));
            } else if let Some(channel_id) =
                state.ember_channel_handoff_searches.remove(&search_id)
            {
                state
                    .ember_pending_channel_handoff
                    .push((channel_id, records));
            }
        }
    }

    state.ember_search.remove(search_id);
    state
        .ember_dht_search_requests
        .retain(|_, r| r.search_id != search_id);
}

/// Parse the blobs returned by an Ember DHT source `FIND_VALUE` into
/// verified [`ember::dht::publish::DiscoveredSource`]s (slice 9).
///
/// Each blob is re-verified (`from_value_blob` checks the publisher
/// signature), filtered to source records whose embedded file hash matches
/// the download we asked about, self-filtered against our own external IP,
/// and counted for diagnostics. When a record carries a Noise pubkey and
/// UDP port, it is cached under that UDP endpoint so later Ember dials
/// (bridge / native) can find it. Dedup / ban / cap handling is left to
/// `handle_epx_sources` downstream; the drain path applies the same
/// `ip_filter` / banlist gates before writing SourceManager.
pub(super) fn parse_ember_source_records(
    blobs: &[Vec<u8>],
    file_hash: [u8; 16],
    self_ip: Option<Ipv4Addr>,
    diag: &mut crate::types::EmberDiagnostics,
    noise_keys: &mut HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
    established: &HashSet<(Ipv4Addr, u16)>,
    content_hashes: &mut HashMap<[u8; 16], EmberDigestPin>,
) -> Vec<ember::dht::publish::DiscoveredSource> {
    let mut out = Vec::new();
    // Expected-digest votes, keyed by publisher. A source record is signed
    // only by a key the record carries itself, so there is no trust anchor —
    // any node can assert any digest for any file hash. Collect the claims and
    // take the publisher majority below (same defence the keyword path
    // applies) instead of believing whichever record parsed last.
    let mut publisher_digests: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
    for blob in blobs {
        let Some(rec) = ember::dht::publish::SignedRecord::from_value_blob(blob) else {
            continue;
        };
        if rec.record_type != ember::dht::publish::RECORD_TYPE_SOURCE {
            continue;
        }
        // The record must actually be for the file we asked about; a peer
        // can't smuggle unrelated sources under our key.
        if rec.file_hash != file_hash {
            continue;
        }
        if rec.ember_file_hash != [0u8; 32] {
            publisher_digests.insert(rec.publisher_key, rec.ember_file_hash);
        }
        let Some(sc) = rec.source_contact else {
            continue;
        };
        diag.ember_dht_source_records_found = diag.ember_dht_source_records_found.saturating_add(1);
        // Never inject ourselves, and drop unusable contacts.
        if Some(sc.ip) == self_ip || sc.tcp_port == 0 {
            continue;
        }
        if sc.udp_port != 0 && sc.noise_pub != [0u8; 32] {
            // Firewalled contacts skip the STORE IP-bind, so their claimed
            // address is unauthenticated. Caching that (ip, udp) → noise_pub
            // would let a publisher eclipse Noise_IK to a third party.
            if sc.flags & ember::SOURCE_FLAG_FIREWALLED == 0 {
                let _ = cache_bound_ember_noise_key(
                    noise_keys,
                    sc.ip,
                    sc.udp_port,
                    sc.noise_pub,
                    established.contains(&(sc.ip, sc.udp_port)),
                );
            }
        }
        out.push(ember::dht::publish::DiscoveredSource {
            ip: sc.ip,
            tcp_port: sc.tcp_port,
            udp_port: sc.udp_port,
            flags: sc.flags,
            user_hash: sc.user_hash,
            buddy: sc.buddy,
            callback_token: sc.callback_token,
            publisher_id: ember::crypto::node_id_from_ed25519_bytes(&rec.publisher_key)
                .unwrap_or([0u8; 16]),
        });
    }
    // Only ever on corroboration, and only if this plurality rests on more
    // publishers than whatever is already pinned. This map is the digest the
    // transfer enforces at completion, so a careless overwrite fails the verify,
    // leaves `corrupt_part_indices_on_disk` nothing to point at, and re-downloads
    // every part forever — which is why `seed_ember_content_hash` demands
    // strictly better evidence rather than taking the newest claim.
    if let Some((digest, publishers)) = corroborated_ember_digest_with_count(&publisher_digests) {
        seed_ember_content_hash(
            content_hashes,
            file_hash,
            digest,
            EmberDigestProvenance::Corroborated(publishers),
        );
    }
    out
}

pub(super) struct EmberKeywordBuilt {
    pub(super) results: Vec<SearchResult>,
    /// Digests at least [`MIN_EMBER_DIGEST_PUBLISHERS`] publishers agree on,
    /// with the number that agreed — safe to seed into `ember_content_hashes`
    /// without a user click. The count travels with the digest so a later or
    /// more complete walk can supersede a pin made on thinner evidence.
    pub(super) corroborated: Vec<([u8; 16], [u8; 32], usize)>,
}

/// Build search rows from Ember DHT keyword `FIND_VALUE` blobs (slice 10).
///
/// Each blob is re-verified (`from_value_blob` checks the publisher
/// signature), kept only if it is a keyword record whose embedded
/// `keyword_hash` matches the primary query keyword (defense in depth vs
/// a LOOKUP peer returning unrelated signed records), and -- for multi-word
/// queries -- AND-filtered so every query keyword appears in the file name
/// (the DHT key only matched the primary keyword). Multi-keyword queries
/// already ask peers to intersect by `file_hash` on the wire; the filename
/// filter is defense-in-depth (and for peers that only held the primary
/// key). Records are deduped by eD2K file hash, with `availability`
/// reflecting the number of distinct publishers. Sources are empty: a
/// keyword hit identifies the file, and source discovery runs separately
/// via the slice-9 source lookup when a download starts.
///
/// `complete_sources` is that same publisher count, not zero. Only complete
/// public shares are keyword-published (`is_ember_publishable` requires a
/// listable index row with a content digest), so every distinct publisher of
/// a keyword record holds the whole file — the count is a floor on the
/// complete sources rather than an unknown. Leaving it zero meant the Min
/// Complete filter silently dropped every Ember row (0 is below any
/// threshold), the Complete column read as unknown, and `sort_search_results`,
/// which ranks that field first, put Ember last. It is also the honest side of
/// the comparison with KAD, whose `TAG_COMPLETE_SOURCES` is one peer's claim
/// about a swarm it cannot see; this one is counted from distinct signatures.
///
/// Each row's `ember_file_hash` is the plurality digest (shown so a click
/// can pin a unique file). Automatic seeding of the enforced map uses only
/// [`EmberKeywordBuilt::corroborated`].
pub(super) fn build_ember_keyword_built(
    blobs: &[Vec<u8>],
    keywords: &[String],
    query_expr: Option<&crate::search::query::QueryExpr>,
) -> EmberKeywordBuilt {
    use crate::search::index::infer_file_type;

    let kw_lower: Vec<String> = keywords.iter().map(|k| k.to_lowercase()).collect();
    // Boolean queries get the same treatment as the KAD result path. Falling
    // back to the flat AND below would reject the non-matching half of an
    // `OR` and ignore the excluded side of a `NOT`.
    let expr = query_expr.filter(|e| !e.is_trivial());
    // Must be the same key the lookup walked, so it is derived the same way
    // rather than re-implemented: picking the longest keyword independently
    // disagrees with `compute_keyword_hashes` whenever two keywords tie on
    // length (a stable descending sort keeps the first, `max_by_key` returns
    // the last), which silently dropped every hit for queries like
    // "ubuntu server".
    let primary_hash = ember::dht::search::compute_keyword_hashes(&keywords.join(" "))
        .first()
        .map(|(h, _)| *h);
    // file_hash -> (result, publisher_key -> ember digest votes)
    let mut dedup: HashMap<[u8; 16], (SearchResult, HashMap<[u8; 32], [u8; 32]>)> = HashMap::new();

    for blob in blobs {
        let Some(rec) = ember::dht::publish::SignedRecord::from_value_blob(blob) else {
            continue;
        };
        if rec.record_type != ember::dht::publish::RECORD_TYPE_KEYWORD {
            continue;
        }
        if let Some(expected) = primary_hash {
            if rec.keyword_hash != expected {
                continue;
            }
        }
        // Local re-filter, mirroring the KAD keyword path: the DHT key only
        // matched the primary keyword, so the rest of the query is applied
        // against the file name here.
        if let Some(expr) = expr {
            if !expr.matches(&rec.file_name.to_lowercase()) {
                continue;
            }
        } else if kw_lower.len() > 1 {
            let name_lower = rec.file_name.to_lowercase();
            if !kw_lower.iter().all(|k| name_lower.contains(k)) {
                continue;
            }
        }

        match dedup.get_mut(&rec.file_hash) {
            Some((existing, publisher_digests)) => {
                if rec.ember_file_hash != [0u8; 32] {
                    publisher_digests.insert(rec.publisher_key, rec.ember_file_hash);
                } else {
                    publisher_digests
                        .entry(rec.publisher_key)
                        .or_insert([0u8; 32]);
                }
                existing.availability = publisher_digests.len() as u32;
                existing.file.complete_sources = publisher_digests.len() as u32;
                existing.file.ember_file_hash = majority_ember_digest_hex(publisher_digests);
                // First publisher to carry media decides the row's. Records from
                // before the block existed have none, so a single peer that
                // published it fills the columns for everyone.
                if existing.media.is_none() {
                    existing.media = rec.media.clone();
                }
            }
            None => {
                let extension = rec
                    .file_name
                    .rsplit_once('.')
                    .map(|(_, e)| e.to_string())
                    .unwrap_or_default();
                let file_type = infer_file_type(&extension);
                let hash_hex = hex::encode(rec.file_hash);
                let mut publisher_digests = HashMap::new();
                if rec.ember_file_hash != [0u8; 32] {
                    publisher_digests.insert(rec.publisher_key, rec.ember_file_hash);
                } else {
                    publisher_digests.insert(rec.publisher_key, [0u8; 32]);
                }
                let ember_hex = majority_ember_digest_hex(&publisher_digests);
                let sr = SearchResult {
                    file: FileInfo {
                        id: hash_hex.clone(),
                        name: rec.file_name.clone(),
                        path: String::new(),
                        size: rec.file_size,
                        hash: hash_hex,
                        aich_hash: String::new(),
                        ember_file_hash: ember_hex,
                        extension,
                        modified_at: 0,
                        priority: "normal".to_string(),
                        requests: 0,
                        accepted: 0,
                        bytes_transferred: 0,
                        alltime_requests: 0,
                        alltime_accepted: 0,
                        alltime_transferred: 0,
                        complete_sources: 1,
                        folder: String::new(),
                        shared: false,
                        friends_only: false,
                        shared_kad: false,
                        shared_ed2k: false,
                        shared_ember: false,
                    },
                    peer_id: String::new(),
                    peer_name: String::new(),
                    availability: 1,
                    file_type,
                    source_addresses: Vec::new(),
                    rating: None,
                    comment: None,
                    media: rec.media.clone(),
                    spam_rating: 0,
                    is_spam: false,
                    clean_name: String::new(),
                    result_origin: crate::search::merge::ORIGIN_EMBER.to_string(),
                    origin_server_ip: None,
                    spam_reasons: Vec::new(),
                    spam_reason_details: Vec::new(),
                };
                dedup.insert(rec.file_hash, (sr, publisher_digests));
            }
        }
    }

    // The digest on the row is what the search page hands to start_download
    // on click (user-chosen pin, even a plurality of one). Automatic fills
    // of ember_content_hashes still require two publishers.
    let mut corroborated = Vec::new();
    for (hash, (result, votes)) in dedup.iter_mut() {
        result.file.ember_file_hash = majority_ember_digest(votes)
            .map(hex::encode)
            .unwrap_or_default();
        if let Some((digest, publishers)) = corroborated_ember_digest_with_count(votes) {
            corroborated.push((*hash, digest, publishers));
        }
    }
    EmberKeywordBuilt {
        results: dedup.into_values().map(|(sr, _)| sr).collect(),
        corroborated,
    }
}

/// Pick the most common non-zero Ember BLAKE3 among publishers; empty if none.
pub(super) fn majority_ember_digest_hex(publisher_digests: &HashMap<[u8; 32], [u8; 32]>) -> String {
    majority_ember_digest(publisher_digests)
        .map(hex::encode)
        .unwrap_or_default()
}

/// Raw-byte form of [`majority_ember_digest_hex`]: the digest the most
/// distinct publishers agree on, or `None` when none of them published one.
///
/// This is a plurality with no minimum, which is right for display — one
/// publisher's claim is worth showing — but not for anything enforced. Use
/// [`corroborated_ember_digest`] for that.
pub(super) fn majority_ember_digest(publisher_digests: &HashMap<[u8; 32], [u8; 32]>) -> Option<[u8; 32]> {
    majority_ember_digest_with_count(publisher_digests).map(|(digest, _)| digest)
}

pub(super) fn majority_ember_digest_with_count(
    publisher_digests: &HashMap<[u8; 32], [u8; 32]>,
) -> Option<([u8; 32], usize)> {
    let mut counts: HashMap<[u8; 32], usize> = HashMap::new();
    for digest in publisher_digests.values() {
        if *digest != [0u8; 32] {
            *counts.entry(*digest).or_insert(0) += 1;
        }
    }
    counts.into_iter().max_by_key(|(_, n)| *n)
}

/// Distinct publishers that must agree before a DHT-sourced digest is allowed
/// into the map a transfer *enforces* at completion.
///
/// Publisher keys are free to mint, so this does not bound a determined Sybil —
/// it only stops a single record from deciding, which is what a plurality of one
/// amounted to. The cost of being wrong is asymmetric: a missing digest just
/// means the ed2k/AICH hashes carry the verification, while a wrong one fails
/// completion forever and leaves `corrupt_part_indices_on_disk` nothing to point
/// at, so the file re-downloads endlessly.
pub(super) const MIN_EMBER_DIGEST_PUBLISHERS: usize = 2;

/// The plurality digest, but only once [`MIN_EMBER_DIGEST_PUBLISHERS`] agree.
///
/// Runtime callers need the agreeing-publisher count as well, so they use
/// [`corroborated_ember_digest_with_count`]; this is the shape the corroboration
/// tests assert against.
#[cfg(test)]
pub(super) fn corroborated_ember_digest(publisher_digests: &HashMap<[u8; 32], [u8; 32]>) -> Option<[u8; 32]> {
    corroborated_ember_digest_with_count(publisher_digests).map(|(digest, _)| digest)
}

/// [`corroborated_ember_digest`] plus how many publishers agreed.
///
/// The count is what lets a later, more complete walk supersede a pin an
/// earlier one made on thinner evidence — see [`EmberDigestProvenance`].
pub(super) fn corroborated_ember_digest_with_count(
    publisher_digests: &HashMap<[u8; 32], [u8; 32]>,
) -> Option<([u8; 32], usize)> {
    majority_ember_digest_with_count(publisher_digests)
        .filter(|(_, agreeing)| *agreeing >= MIN_EMBER_DIGEST_PUBLISHERS)
}

/// How much evidence stands behind an entry in
/// [`NetworkState::ember_content_hashes`].
///
/// That map is what a transfer *enforces* at completion, so which of several
/// competing digests wins has to be decided by evidence, not by arrival order.
/// Ordering by arrival was wrong in two ways at once. An incremental
/// `FIND_VALUE` page corroborates within its own slice, so two early publishers
/// could pin a digest that the finished walk then contradicts — and once pinned,
/// nothing could correct it. And the digest on the row the user actually clicked
/// lost to whatever a partial page had already seeded, so an explicit choice was
/// silently overridden by a guess.
///
/// Derived `Ord` is the precedence, so variants are declared weakest first:
/// more agreeing publishers beat fewer, an explicit user pick beats any DHT
/// plurality, and bytes hashed on this machine beat everything remote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum EmberDigestProvenance {
    /// Plurality agreement among this many distinct DHT publishers. Publisher
    /// keys are free to mint, so this only ranks claims against each other; it
    /// is not a trust anchor.
    Corroborated(usize),
    /// The digest carried by the search row the user clicked to download. One
    /// publisher is enough here because the user chose it.
    UserSelected,
    /// Computed from bytes on this machine — known.met, the library index, or a
    /// completed local hash. Nothing remote may outrank it.
    Local,
}

/// An expected Ember BLAKE3 together with the evidence behind it.
#[derive(Clone, Copy, Debug)]
pub(super) struct EmberDigestPin {
    pub(super) digest: [u8; 32],
    pub(super) provenance: EmberDigestProvenance,
}

/// Record `digest` as the expected content hash for `file_hash`, keeping
/// whichever of the incumbent and the newcomer rests on better evidence.
///
/// Replacement is strict: equal evidence leaves the incumbent alone, so two
/// publishers asserting a rival digest cannot flip a live pin back and forth
/// mid-transfer. An all-zero digest means "no claim" and is ignored.
pub(super) fn seed_ember_content_hash(
    pins: &mut HashMap<[u8; 16], EmberDigestPin>,
    file_hash: [u8; 16],
    digest: [u8; 32],
    provenance: EmberDigestProvenance,
) {
    if digest == [0u8; 32] {
        return;
    }
    let pin = EmberDigestPin { digest, provenance };
    match pins.entry(file_hash) {
        std::collections::hash_map::Entry::Vacant(slot) => {
            slot.insert(pin);
        }
        std::collections::hash_map::Entry::Occupied(mut slot) => {
            if provenance > slot.get().provenance {
                slot.insert(pin);
            }
        }
    }
}

/// Start an Ember DHT `FIND_VALUE` for the sources of `file_hash` on behalf
/// of a download (slice 9). Returns whether a search was started (`false`
/// if the search-manager slot cap is hit). Results are delivered
/// asynchronously: `maybe_finish_ember_search` parses them into
/// `ember_pending_source_injections`, which the search-timer sweep drains
/// through `handle_epx_sources` into the download.
pub(super) async fn start_ember_source_search(
    socket: &UdpSocket,
    state: &mut NetworkState,
    transfer_id: &str,
    file_hash: [u8; 16],
) -> bool {
    let source_key = ember::dht::publish::source_key(&file_hash);
    let target = ember::dht::EmberNodeId(source_key);
    let Some(search_id) =
        state
            .ember_search
            .start_background_find_value(target, Vec::new(), state.ember_dht.routing())
    else {
        return false;
    };
    seed_ember_local_records(state, search_id, &source_key, &[]);
    seed_ember_session_search_contacts(state, search_id);
    state
        .ember_download_source_searches
        .insert(search_id, (transfer_id.to_string(), file_hash));
    state.ember_diagnostics.ember_dht_source_searches = state
        .ember_diagnostics
        .ember_dht_source_searches
        .saturating_add(1);
    drive_ember_search(socket, state, search_id).await;
    true
}

#[cfg(test)]
mod ember_digest_corroboration_tests {
    use super::*;

    fn digests(pairs: &[(u8, u8)]) -> HashMap<[u8; 32], [u8; 32]> {
        pairs
            .iter()
            .map(|(publisher, digest)| ([*publisher; 32], [*digest; 32]))
            .collect()
    }

    #[test]
    fn one_publisher_is_not_a_majority() {
        let single = digests(&[(1, 0xAA)]);
        assert_eq!(
            majority_ember_digest(&single),
            Some([0xAA; 32]),
            "display still shows a lone claim"
        );
        assert_eq!(
            corroborated_ember_digest(&single),
            None,
            "but nothing enforced may rest on it"
        );
    }

    #[test]
    fn two_agreeing_publishers_corroborate() {
        assert_eq!(
            corroborated_ember_digest(&digests(&[(1, 0xAA), (2, 0xAA)])),
            Some([0xAA; 32])
        );
    }

    #[test]
    fn disagreeing_publishers_do_not_corroborate() {
        assert_eq!(
            corroborated_ember_digest(&digests(&[(1, 0xAA), (2, 0xBB), (3, 0xCC)])),
            None,
            "a plurality of one each is still one each"
        );
        // A real majority inside a disputed set still wins.
        assert_eq!(
            corroborated_ember_digest(&digests(&[(1, 0xAA), (2, 0xAA), (3, 0xCC)])),
            Some([0xAA; 32])
        );
    }

    #[test]
    fn publishers_that_named_no_digest_are_not_counted() {
        assert_eq!(
            corroborated_ember_digest(&digests(&[(1, 0xAA), (2, 0x00), (3, 0x00)])),
            None
        );
    }
}
