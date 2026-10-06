//! Types the Tauri command layer exchanges with the network task: the
//! [`NetworkCommand`] enum, search filters, and the UI snapshot structs.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchMethod {
    Global,
    Server,
    Kad,
    Ember,
}

#[derive(Debug, Default, Clone)]
pub struct SearchFilters {
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    pub file_type: Option<String>,
    pub file_extension: Option<String>,
    pub min_availability: Option<u32>,
}

#[derive(Debug)]
pub enum NetworkCommand {
    SearchFiles {
        query: String,
        method: SearchMethod,
        request_id: u64,
        tx: oneshot::Sender<Vec<SearchResult>>,
        search_filters: Option<SearchFilters>,
        /// Seed hashes (lowercase hex) of a "find related files" search. When
        /// the connected eD2k server advertises `SRV_TCPFLG_RELATEDSEARCH`,
        /// its leg of this search becomes eMule's native co-share request
        /// (`related::<HASH>`) instead of the keyword query; every other leg
        /// still runs `query`. Empty for an ordinary search.
        related_hashes: Vec<String>,
        /// Hashes to withhold from the UI for this request: the seed files of
        /// a related search, which are not related to themselves.
        exclude_hashes: Vec<String>,
        /// Hashes of files this library already holds that matched the query,
        /// resolved by the caller from the local index.
        ///
        /// A network sighting of one of these is the user's own file coming
        /// back from a server or a DHT, and the spam scorer exempts it: we have
        /// the bytes, so no claim about the result set it arrived in can make it
        /// fake. Sent with the search because the network task has no business
        /// taking the index lock once per inbound result packet to work it out.
        owned_hashes: Vec<String>,
    },
    StartDownload {
        file_hash: String,
        file_name: String,
        file_size: u64,
        peer_ip: String,
        peer_port: u16,
        /// Additional candidate sources known up-front (e.g. the rest
        /// of `source_addresses` from a search result). Validated and
        /// IP-filtered in the handler before being merged into the
        /// initial multi-source download seed list. Empty means the
        /// caller only had the primary `peer_ip:peer_port` (or none).
        extra_sources: Vec<(String, u16)>,
        /// Optional Ember content BLAKE3 hex from search/UI. Seeded into
        /// `ember_content_hashes` so completion verify does not depend
        /// solely on having seen a DHT keyword hit this session.
        ember_file_hash: String,
        /// Optional trusted AICH master from an ed2k link/collection.
        expected_aich: Option<String>,
        transfer_id: String,
        control: Arc<TransferControl>,
        /// When true, register seeds + run KAD/TCP/UDP source discovery
        /// without starting `MultiSourceDownload` workers. Used for
        /// queued / add-paused downloads so sources are ready at promote.
        discovery_only: bool,
        /// Set when the frontend started this download from a friend's
        /// browse listing. Resolved (best-effort, via
        /// `CreditManager::find_user_hash_by_ember`) to the peer's eD2K
        /// `user_hash` so the primary seed is registered into
        /// `SourceManager` *with identity* up front — without this, a
        /// friend download that never completes even one Hello handshake
        /// (e.g. both peers restart before it connects) leaves nothing for
        /// `reseed_friend_endpoint` to relocate when rendezvous later finds
        /// the friend at a new address. `None` for every other caller
        /// (resumed/promoted downloads, collections, generic search
        /// results) — those either already have an identity-linked
        /// `sources.met` row from a prior session or aren't friend sources
        /// at all.
        friend_ember_hash: Option<[u8; 16]>,
    },
    AnnounceFiles {
        files: Vec<FileInfo>,
    },
    /// Force an immediate re-publish of a single already-known file to KAD.
    /// The file must already be registered with the publish manager (e.g. via
    /// `AnnounceFiles`); this command just resets its source/keyword publish
    /// timestamps so the next publish cycle picks it up.
    RepublishFile {
        file_hash_hex: String,
    },
    /// Ask every connected network for the sources of one file, on behalf of
    /// the transfer that wants them. Replies as soon as the asks are away —
    /// what they find is written into the transfer as it arrives, not returned
    /// here. See [`ask_networks_for_sources`].
    FindSources {
        transfer_id: String,
        file_hash: [u8; 16],
        file_size: u64,
        tx: oneshot::Sender<crate::types::SourceAskOutcome>,
    },
    BanPeer {
        peer_id_hex: String,
    },
    UnbanPeer {
        peer_id_hex: String,
    },
    FindNotes {
        file_hash: KadId,
        file_size: u64,
        request_id: u64,
        tx: oneshot::Sender<Result<Vec<SearchResult>, String>>,
    },
    PublishNote {
        file_hash: KadId,
        file_name: Option<String>,
        file_size: Option<u64>,
        rating: u8,
        comment: String,
        tx: oneshot::Sender<Result<(), String>>,
    },
    CancelSearch {
        request_id: u64,
    },
    CancelDownload {
        transfer_id: String,
        /// When set, the handler will skip saving .part.met (files are about to
        /// be deleted), await the task abort so file handles are released, remove
        /// the tracker from the registry, and signal the sender so the caller
        /// can safely delete the .part / .part.met files.
        cleanup_ack: Option<oneshot::Sender<()>>,
    },
    PauseDownload {
        transfer_id: String,
    },
    BootstrapContacts {
        contacts: Vec<kad::types::KadContact>,
        tx: oneshot::Sender<usize>,
    },
    ReloadIpFilter {
        path: PathBuf,
        /// When present, report whether the network task actually loaded and
        /// installed the fresh filter rather than merely accepting the queue
        /// item.
        tx: Option<oneshot::Sender<Result<(), String>>>,
    },
    GetIpFilterStats {
        query: String,
        sort: String,
        sort_asc: bool,
        offset: usize,
        limit: usize,
        tx: oneshot::Sender<IpFilterStats>,
    },
    AddIpRange {
        start_ip: String,
        end_ip: String,
        description: String,
    },
    RemoveIpRange {
        start_ip: String,
        end_ip: String,
        tx: oneshot::Sender<bool>,
    },
    SetIpFilterEnabled {
        enabled: bool,
    },
    SetBlockPrivateIps {
        block_private: bool,
    },
    KadConnect,
    KadBootstrapIp {
        ip: String,
        port: u16,
        /// Result channel — `Ok(message)` with a human-readable success
        /// string on completion, or `Err(message)` describing the failure.
        /// Wire K0: the command must not return success until this
        /// resolves, otherwise the UI shows "Bootstrapping…" for a
        /// connection that never happened.
        tx: oneshot::Sender<Result<String, String>>,
    },
    /// Contacts already downloaded and parsed by the IPC task
    /// (`kad_bootstrap_url`). Only the routing-table insert and the bootstrap
    /// datagrams need the network task's state, so the HTTP fetch and the
    /// synchronous `nodes.dat` parse deliberately do not happen here — running
    /// them inside the `select!` stalled all networking for the length of the
    /// download. Contacts arrive marked unproven.
    KadBootstrapContacts {
        contacts: Vec<kad::types::KadContact>,
        tx: oneshot::Sender<Result<String, String>>,
    },
    KadBootstrapClients {
        tx: oneshot::Sender<Result<usize, String>>,
    },
    /// K30: fire-and-forget cancellation of an active search by id.
    CancelKadSearch {
        id: u64,
    },
    RecheckFirewall {
        tx: oneshot::Sender<Result<usize, String>>,
    },
    GetNetworkStatsSnapshot {
        tx: oneshot::Sender<NetworkStats>,
    },
    /// Snapshot of the current upload queue (peers waiting for an upload
    /// slot). Backs the "Queued" tab in the transfers/uploads pane.
    /// Returns rows with wait time, queue rank, and credit info already
    /// resolved so the UI doesn't need to invoke any further commands.
    GetUploadQueueSnapshot {
        tx: oneshot::Sender<Vec<crate::types::UploadQueueClient>>,
    },
    /// Chunk map and part-level counters for one download, backing the
    /// "File Details" window. Lives here rather than on the transfer row
    /// because the part tracker and the sources' part bitmaps belong to the
    /// network task, and because it is read on demand — a per-part bitmap on
    /// every transfers poll would be paid for by every user who never opens
    /// the window.
    GetDownloadFileDetails {
        transfer_id: String,
        tx: oneshot::Sender<crate::types::DownloadFileDetails>,
    },
    /// Change the display name of a download in flight. The `.part` is named
    /// by transfer id, so this is metadata: pending-download state, the live
    /// part tracker, and the `.part.met` sidecar. Completion reads the tracker
    /// name when it moves the file into Downloads.
    RenameDownload {
        transfer_id: String,
        file_name: String,
        /// False when completion had already read the name.
        tx: oneshot::Sender<bool>,
    },
    /// Snapshot of every persistent SecIdent credit record. Backs the
    /// "Known Clients" tab — this is the lifetime view from clients.met,
    /// independent of which peers are currently connected.
    GetKnownClientsSnapshot {
        tx: oneshot::Sender<Vec<crate::types::KnownClient>>,
    },
    /// Just the two row counts [`GetKnownClientsSnapshot`] would produce.
    ///
    /// The tab labels carry those counts, so they have to keep moving while
    /// some other tab is showing — but the full snapshot is far too expensive
    /// to poll for two integers: it joins a `spawn_blocking` SQLite read for
    /// friend metadata, resolves an ident state, credit ratio and GeoIP
    /// country per record, and allocates six owned strings per row, for up to
    /// `MAX_CREDIT_RECORDS` rows. None of that changes which tab a record
    /// lands on, which is decided solely by whether it has a bound Ember
    /// identity, so counting needs no allocation, no database and no GeoIP.
    GetKnownClientCounts {
        tx: oneshot::Sender<crate::types::KnownClientCounts>,
    },
    /// Anti-leech client filter — read the current pattern list + flag
    /// for the Settings UI.
    GetAntiLeechSnapshot {
        tx: oneshot::Sender<crate::types::AntiLeechSnapshot>,
    },
    /// Anti-leech: replace the entire pattern list, persist to disk,
    /// recompile. Per-pattern compile errors come back via the result.
    SetAntiLeechPatterns {
        patterns: Vec<String>,
        tx: oneshot::Sender<Result<crate::types::AntiLeechReplaceResult, String>>,
    },
    /// Anti-leech: toggle on/off without modifying the pattern list.
    SetAntiLeechEnabled {
        enabled: bool,
        tx: oneshot::Sender<Result<(), String>>,
    },
    /// Anti-leech: discard the current list and reload built-in defaults.
    ResetAntiLeechToDefaults {
        tx: oneshot::Sender<Result<crate::types::AntiLeechSnapshot, String>>,
    },
    GetKadContactsSnapshot {
        tx: oneshot::Sender<Vec<KadContactInfo>>,
    },
    GetKadSearchesSnapshot {
        tx: oneshot::Sender<Vec<KadSearchInfo>>,
    },
    /// Reconcile the live index into known.met and acknowledge completion.
    SharedFilesChangedAck {
        tx: oneshot::Sender<Result<(), String>>,
    },
    /// Withdraw our Ember DHT publications for files that have stopped being
    /// offered — unshared, deleted, or dropped from the library with their
    /// folder. Sent by the command that made the change, because it is the only
    /// thing that knows which hashes those were: a hash simply missing from the
    /// index is not evidence of a retraction, since the library scan is paged
    /// and most of a large library is absent from the index for a while after
    /// launch. Answers with how many hashes it acted on.
    UnpublishEmberFiles {
        file_hashes: Vec<String>,
        tx: oneshot::Sender<usize>,
    },
    SetUploadPriorities {
        file_hashes: Vec<String>,
        priority: u8,
        tx: oneshot::Sender<Result<(), String>>,
    },
    ConnectToServer {
        ip: String,
        port: u16,
    },
    DisconnectServer,
    AddServer {
        ip: String,
        port: u16,
        name: String,
        tx: oneshot::Sender<Result<String, String>>,
    },
    RemoveServer {
        ip: String,
        port: u16,
        tx: oneshot::Sender<Result<String, String>>,
    },
    SetServerStatic {
        ip: String,
        port: u16,
        is_static: bool,
        tx: oneshot::Sender<Result<String, String>>,
    },
    SetServerPriority {
        ip: String,
        port: u16,
        priority: String,
        tx: oneshot::Sender<Result<String, String>>,
    },
    GetServerListSnapshot {
        tx: oneshot::Sender<Vec<ServerInfo>>,
    },
    GetConnectedServerSnapshot {
        tx: oneshot::Sender<Option<ServerInfo>>,
    },
    /// The eD2K server the user means to be on: connected, connecting, or
    /// waiting out an auto-reconnect backoff. `None` once they disconnected or
    /// were never connected. What an update restart reconnects to.
    GetEd2kServerIntent {
        tx: oneshot::Sender<Option<(String, u16)>>,
    },
    /// How many Ember Transfers (room and friend file hand-offs) are sending,
    /// receiving or verifying right now — work a silent update must not cut off.
    GetEmberTransferActivity {
        tx: oneshot::Sender<usize>,
    },
    /// The startup scan has put the library into the index (or there is no
    /// library to scan), so last session's upload waiters can rejoin the queue.
    StartupLibraryIndexed,
    UpdateSettings {
        settings: Box<AppSettings>,
    },
    SetFileComment {
        file_hash: String,
        rating: u8,
        comment: String,
        /// Answered once the comment is in the database.
        tx: oneshot::Sender<Result<(), String>>,
    },
    /// Atomically validates and applies a batch of share-state changes to the
    /// in-memory known.met catalog, then acknowledges central processing.
    SetFilesShared {
        updates: Vec<(String, bool)>,
        /// Who the unshares in `updates` are by.
        origin: crate::storage::share_intent::UnshareOrigin,
        tx: oneshot::Sender<Result<usize, String>>,
    },
    /// Persist the friends-only scope for a batch of content hashes.
    SetFilesFriendsOnly {
        updates: Vec<(String, bool)>,
        /// The hashes this did not save: known.met had no record for them, or
        /// declined the write.
        tx: oneshot::Sender<Result<Vec<String>, String>>,
    },
    /// Files confirmed gone from these paths (deleted, or found missing from
    /// a folder that is there): known.met forgets the paths.
    ForgetKnownPaths {
        paths: Vec<String>,
    },
    /// A folder taken out of the library: known.met forgets the paths under
    /// `root` that none of `keep_roots` still shares.
    ForgetKnownPathsUnder {
        root: String,
        keep_roots: Vec<String>,
    },
    /// Offer one of our shared files to a friend over their live session.
    OfferFileToFriend {
        ember_hash: [u8; 16],
        file_hash: [u8; 16],
        tx: oneshot::Sender<Result<(), String>>,
    },
    /// Whether a file could be offered to this friend right now. Asked before
    /// the file picker opens; `SendChatAttachment` checks the same again.
    ChatAttachmentPreflight {
        ember_hash: [u8; 16],
        tx: oneshot::Sender<Result<(), String>>,
    },
    /// Offer a friend a file in chat. The caller has already picked, checked and
    /// hashed it off the network task, so this only records the grant and sends
    /// the offer.
    SendChatAttachment {
        ember_hash: [u8; 16],
        xfer_id: [u8; 16],
        path: PathBuf,
        name: String,
        size: u64,
        root: [u8; 32],
        tx: oneshot::Sender<Result<chat_attach::ChatAttachmentInfo, String>>,
    },
    /// Accept or decline an attachment a friend offered us.
    RespondChatAttachment {
        xfer_id: [u8; 16],
        accept: bool,
        tx: oneshot::Sender<Result<(), String>>,
    },
    /// Stop an attachment in either direction, and tell the friend.
    CancelChatAttachment {
        xfer_id: [u8; 16],
        tx: oneshot::Sender<Result<(), String>>,
    },
    GetFileComments {
        file_hash: String,
        tx: oneshot::Sender<Option<ed2k::comments::FileCommentInfo>>,
    },
    MergeServerMet {
        data: Vec<u8>,
        tx: oneshot::Sender<anyhow::Result<ed2k::server_list::ServerMergeStats>>,
    },
    PreviewFile {
        transfer_id: String,
        tx: oneshot::Sender<Result<String, String>>,
        /// Carried with the command so the claim is released by the work
        /// finishing rather than by the caller's timeout.
        ///
        /// `preview_file` waits 30 seconds and then returns, but the work it
        /// started is a detached `spawn_blocking` that keeps going — and on an
        /// AICH-pinned transfer that work is a full SHA-1 tree over the whole
        /// file, minutes on a large download. Holding the guard in the command
        /// meant every timeout admitted another one, so a user clicking Preview
        /// again after each stall stacked concurrent whole-file hashes.
        single_flight: crate::security::SingleFlightGuard<'static>,
    },
    SendChatMessage {
        ember_hash: [u8; 16],
        message: String,
        tx: oneshot::Sender<Result<(), String>>,
    },
    /// Live composing signal. Never queued: if the friend is not on a fresh
    /// session the packet is dropped and the next keystroke retries.
    SendChatTyping {
        ember_hash: [u8; 16],
        typing: bool,
    },
    /// Read-receipt watermark (BLAKE3-16 of the latest inbound line we have
    /// opened). Offline sends are retried the next time a session comes up.
    SendChatReadReceipt {
        ember_hash: [u8; 16],
        body_hash: [u8; 16],
    },
    BrowseFriend {
        ember_hash: [u8; 16],
        request_id: String,
        tx: oneshot::Sender<Result<(), String>>,
    },
    CancelBrowseFriend {
        ember_hash: [u8; 16],
        request_id: String,
    },
    FriendRemoved {
        ember_hash: [u8; 16],
        tx: oneshot::Sender<()>,
    },
    /// Withdraw a friend request the user has just cancelled. Fire-and-forget:
    /// the row in `friend_request_retractions` is what guarantees delivery, so
    /// the UI never waits on the peer being reachable this second.
    RetractFriendRequest {
        ember_hash: [u8; 16],
    },
    /// Tell somebody the request they sent has been refused. Fire-and-forget
    /// for the same reason as the withdrawal above: the row in
    /// `friend_request_declines` is what guarantees delivery, so rejecting
    /// never waits on the sender being reachable this second.
    DeclineFriendRequest {
        ember_hash: [u8; 16],
    },
    FindFriendAndConnect {
        ember_hash: [u8; 16],
    },
    /// Force an immediate rendezvous presence re-register (intro + pairwise)
    /// instead of waiting for the ~120s heartbeat. Used after add_friend so
    /// the newly-added peer can find us via pairwise without delay.
    ForceRendezvousRegister,
    RetryFriendSearch {
        ember_hash: [u8; 16],
        tx: oneshot::Sender<Result<(), String>>,
    },
    IsFriendDiscoverable {
        tx: oneshot::Sender<bool>,
    },
    /// Snapshot of friends currently considered online (hex hashes). Lets the
    /// UI seed its online set at startup instead of waiting for the next
    /// `ember:friend-online` transition, which otherwise leaves every friend
    /// showing offline (chat/browse disabled) until a fresh session forms.
    GetOnlineFriends {
        tx: oneshot::Sender<Vec<String>>,
    },
    /// Reputation for many peers at once, keyed by lowercase hex user hash.
    ///
    /// The Known Clients tab needs a Trust badge per visible row and refreshes
    /// them on a timer. Asking one command per hash put a hundred entries into
    /// the bounded command channel every eight seconds, which is what made
    /// unrelated actions fail with "Network busy" while that tab was open — the
    /// answers all come from the same in-memory tracker, so one round trip is
    /// enough. Absent peers are reported as `None` rather than omitted, so the
    /// caller can tell "no record" from "not asked".
    GetPeerReputationBatch {
        user_hashes: Vec<[u8; 16]>,
        tx: oneshot::Sender<HashMap<String, Option<PeerReputationInfo>>>,
    },
    GetReputationStats {
        tx: oneshot::Sender<ReputationStatsInfo>,
    },
    /// Snapshot of Ember diagnostic counters (EPX events, broker punch /
    /// relay outcomes, mesh peer count). Backs the developer-facing
    /// `get_ember_diagnostics` Tauri command; not on the regular
    /// `NetworkStats` payload to keep the status-bar IPC focused on
    /// user-visible state.
    GetEmberDiagnostics {
        tx: oneshot::Sender<EmberDiagnostics>,
    },
    /// Send an Ember-native `Ping` over the Noise transport to a peer.
    ///
    /// When `peer_pubkey` is `Some`, the network task uses it directly
    /// (the harness path: caller already knows the pubkey). When
    /// `None`, the task looks the pubkey up in the cache populated
    /// from KAD source publishes (`ember_noise_keys`), which is how
    /// production peers will eventually dial each other without
    /// out-of-band key distribution. A cache miss with `None` is
    /// surfaced as a clear error rather than a silent timeout.
    /// Compiled out of release: the Tauri command is `debug_assertions`-only.
    #[cfg(debug_assertions)]
    SendEmberPing {
        addr: SocketAddr,
        peer_pubkey: Option<[u8; 32]>,
        tx: oneshot::Sender<Result<EmberPingPending, String>>,
    },
    /// Manually seed an Ember DHT contact into the routing table
    /// (harness / dev: bootstrap a node without waiting for live
    /// traffic). The node ID is derived from `ed25519_pub`.
    /// Compiled out of release: the Tauri command is `debug_assertions`-only.
    #[cfg(debug_assertions)]
    AddEmberDhtContact {
        addr: SocketAddr,
        ed25519_pub: [u8; 32],
        noise_pub: [u8; 32],
        tx: oneshot::Sender<Result<(), String>>,
    },
    /// Snapshot of the Ember DHT routing table for the dev panel.
    GetEmberDhtContacts {
        tx: oneshot::Sender<Vec<EmberDhtContactInfo>>,
    },
    /// Snapshot of in-flight Ember DHT searches (slice 16).
    GetEmberDhtSearches {
        tx: oneshot::Sender<Vec<EmberDhtSearchInfo>>,
    },
    /// Snapshot of live local store keys (slice 16).
    GetEmberDhtStore {
        tx: oneshot::Sender<Vec<EmberDhtStoreInfo>>,
    },
    /// Send an Ember DHT `PING` over the Noise transport. Like
    /// [`NetworkCommand::SendEmberPing`] but exercises the DHT
    /// PING/PONG path (and so populates the routing table on both
    /// ends). `peer_pubkey` is the peer's Noise key; when `None` it is
    /// resolved from the KAD-fed cache.
    /// Compiled out of release: the Tauri command is `debug_assertions`-only.
    #[cfg(debug_assertions)]
    SendEmberDhtPing {
        addr: SocketAddr,
        peer_pubkey: Option<[u8; 32]>,
        tx: oneshot::Sender<Result<EmberPingPending, String>>,
    },
    /// Send an Ember DHT `FIND_NODE` for `target` to one peer and return
    /// the contacts it answers with (single hop — the iterative driver
    /// lands in a later slice). `peer_pubkey` is the peer's Noise key;
    /// when `None` it is resolved from the KAD-fed cache. A `None`
    /// `target` asks the peer for the contacts closest to a random ID.
    /// Compiled out of release: the Tauri command is `debug_assertions`-only.
    #[cfg(debug_assertions)]
    SendEmberDhtFindNode {
        addr: SocketAddr,
        peer_pubkey: Option<[u8; 32]>,
        target: Option<[u8; 16]>,
        tx: oneshot::Sender<Result<EmberDhtFindPending, String>>,
    },
    /// Run an **iterative** Ember DHT `FIND_NODE` lookup for `target`:
    /// the network task drives a `SearchManager` search across multiple
    /// hops (α-parallel `FIND_NODE` rounds over the closest contacts it
    /// learns) until it converges, then returns the closest contacts
    /// that responded. A `None` `target` runs a random self-style probe.
    /// Compiled out of release: the Tauri command is `debug_assertions`-only.
    #[cfg(debug_assertions)]
    SendEmberDhtIterativeFindNode {
        target: Option<[u8; 16]>,
        tx: oneshot::Sender<Result<EmberDhtLookupPending, String>>,
    },
    /// Publish a signed keyword record into the Ember DHT: the network
    /// task signs the record with our identity, finds the closest known
    /// contacts to the keyword's key, and `STORE`s on them, returning how
    /// many acknowledged. `file_hash` is random per dev-published record.
    /// Compiled out of release: the Tauri command is `debug_assertions`-only.
    #[cfg(debug_assertions)]
    PublishEmberKeyword {
        keyword: String,
        file_name: String,
        file_size: u64,
        file_hash: [u8; 16],
        tx: oneshot::Sender<Result<EmberPublishPending, String>>,
    },
    /// Run an iterative Ember DHT `FIND_VALUE` lookup for a keyword: the
    /// network task drives a `SearchManager` search that sends `FIND_VALUE`
    /// (falling back to `FOUND_NODE` hops) until it gathers signed records
    /// or converges, then returns the verified records it collected.
    /// Compiled out of release: the Tauri command is `debug_assertions`-only.
    #[cfg(debug_assertions)]
    FindEmberValue {
        keyword: String,
        tx: oneshot::Sender<Result<EmberValueLookupPending, String>>,
    },
    /// Publish an already-signed Ember DHT record (channel index/presence/moderation).
    PublishEmberRecord {
        record: Box<crate::network::ember::dht::publish::SignedRecord>,
        tx: oneshot::Sender<Result<EmberPublishPending, String>>,
    },
    /// Iterative FIND_VALUE for raw 16-byte DHT keys (channel Gather).
    FindEmberKeys {
        keys: Vec<[u8; 16]>,
        tx: oneshot::Sender<Result<EmberValueLookupPending, String>>,
    },
    /// Fan a sealed channel gossip frame to XOR-closest members we already
    /// have a Noise session with. Fire-and-forget: local persist already
    /// succeeded in the Tauri command.
    FanoutChannelGossip {
        body: Vec<u8>,
    },
    /// Live composing signal for a room, one hop to members we already hold a
    /// session with. Never queued, relayed, or stored; the next keystroke
    /// refreshes it.
    SendChannelTyping {
        channel_id: [u8; 16],
        typing: bool,
    },
    /// Drop an in-flight Ember `FIND_VALUE` the caller has already given
    /// up on, so the search slot is not held until [`ember::dht::search`]
    /// times out on its own (60s). Discover presence probes wait 6s.
    CancelEmberSearch {
        search_id: u32,
    },
    /// Walk this room's presence keys now rather than at the next maintenance
    /// tick. Sent on join and create: publishing our own presence tells the
    /// room we exist, but nothing pulls the roster the other way, so without
    /// this a joiner sat with an empty member list — and therefore no one to
    /// gossip to and no working chat — until a tick came round.
    RefreshChannelMembers {
        channel_id: [u8; 16],
    },
    /// Announce our arrival or departure on the live mesh right now.
    ///
    /// The DHT record this pairs with takes a republish interval to be written
    /// and a fetch interval to be read, so on its own it makes joining a room
    /// something the rest of the room learns about minutes later. This is the
    /// same fact, signed the same way, taking the path the room's own chat
    /// takes.
    AnnounceChannelPresence {
        channel_id: [u8; 16],
        departed: bool,
    },
    /// Which room the user is looking at, if any. Raises that room's presence
    /// cadence and lowers the previous one back to the resting rate.
    SetChannelFocus {
        channel_id: Option<[u8; 16]>,
    },
    /// Ember Transfer: offer one file to one channel member. The file is
    /// already hashed by the caller, so the network task never blocks on a
    /// 100 MB read.
    OfferChannelTransfer {
        channel_id: [u8; 16],
        peer: [u8; 32],
        xfer_id: [u8; 16],
        path: PathBuf,
        name: String,
        size: u64,
        root: [u8; 32],
        tx: oneshot::Sender<Result<(), String>>,
    },
    /// Answer an offer that is waiting on the user. `download_folder` comes
    /// from the caller because settings live on that side; the network task
    /// only knows the file name.
    RespondChannelTransfer {
        xfer_id: [u8; 16],
        accept: bool,
        download_folder: PathBuf,
        tx: oneshot::Sender<Result<(), String>>,
    },
    /// Stop a transfer in either direction and tell the other end why.
    CancelChannelTransfer {
        xfer_id: [u8; 16],
        tx: oneshot::Sender<Result<(), String>>,
    },
    /// Send the plain offer for one of our offers the user was asked about.
    /// Does nothing once the recipient has shown it read the sealed one.
    SendChannelTransferPlainOffer {
        xfer_id: [u8; 16],
        tx: oneshot::Sender<Result<(), String>>,
    },
    /// Everything in flight, for the Channels page to draw.
    ListChannelTransfers {
        tx: oneshot::Sender<Vec<ChannelTransferSnapshot>>,
    },
    /// Drop transfers tied to a room, because it has just been left or somebody
    /// in it has just been banned. Sends no cancel: the room's content key is
    /// what those frames travel under, and after a leave it is gone along with
    /// the membership.
    ///
    /// `member` of `None` is the whole room; naming one is a ban, where only the
    /// transfers with that member stop.
    DropChannelTransfers {
        channel_id: [u8; 16],
        member: Option<[u8; 32]>,
    },
    /// Run one Ember DHT maintenance cycle on demand (dev/harness): refresh
    /// stale buckets, liveness-ping stale contacts, and republish stored
    /// records. With the timer this happens automatically; the command
    /// forces a cycle (ignoring staleness gates) so it can be observed
    /// immediately. Returns a tally of what it kicked off.
    /// Compiled out of release: the Tauri command is `debug_assertions`-only.
    #[cfg(debug_assertions)]
    RunEmberMaintenance {
        tx: oneshot::Sender<Result<EmberMaintenanceResult, String>>,
    },
    /// Send an Ember-native `ExchangeRequest` over the Noise transport,
    /// asking the peer to reply with its current EPX source/peer payload
    /// (which we then ingest via the shared `handle_epx_sources` path).
    /// Pubkey resolution mirrors `SendEmberPing`: explicit value wins,
    /// otherwise the KAD-fed Noise-key cache is consulted. The reply is
    /// delivered asynchronously on the receive loop, so the oneshot only
    /// reports whether the request was dispatched.
    /// Compiled out of release: the Tauri command is `debug_assertions`-only.
    #[cfg(debug_assertions)]
    SendEmberExchangeRequest {
        addr: SocketAddr,
        peer_pubkey: Option<[u8; 32]>,
        tx: oneshot::Sender<Result<(), String>>,
    },
    Shutdown {
        /// One process-wide absolute deadline, created by the outer Tauri exit
        /// handler and shared by every network persistence phase.
        deadline: tokio::time::Instant,
    },
}

/// One in-flight Ember Transfer, flattened for IPC.
///
/// Deliberately not persisted: a transfer belongs to the session that started
/// it. Resuming across a restart would mean keeping half-written files and the
/// peer's agreement to send them, neither of which survives a restart today.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChannelTransferSnapshot {
    pub xfer_id: String,
    pub channel_id: String,
    pub peer_pubkey: String,
    /// `"send"` or `"receive"`.
    pub direction: String,
    pub name: String,
    pub size: u64,
    pub transferred: u64,
    /// `"offered"`, `"awaiting"`, `"active"`.
    pub status: String,
    /// The name is a program, shortcut or script, or one dressed up as a
    /// document (`report.pdf.exe`); see `security::is_dangerous_extension`.
    pub risky: bool,
    /// A send whose recipient has not shown it read the sealed offer, and
    /// whose user is being asked whether to send the plain one.
    pub awaiting_consent: bool,
}

/// One Ember DHT routing-table contact, flattened to strings for IPC.
/// Backs the `get_ember_dht_contacts` snapshot and harness `FIND_NODE`
/// replies. The UI contacts table redacts `addr` so peer IPs never reach
/// the webview; harness replies still include it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EmberDhtContactInfo {
    /// 128-bit node ID, hex-encoded.
    pub node_id: String,
    /// `ip:port` of the contact. Empty (and omitted from JSON) for the
    /// Ember Network page snapshot so the webview never sees peer IPs.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub addr: String,
    /// X25519 Noise public key, hex-encoded. Empty (and omitted from JSON)
    /// for the Ember Network page snapshot.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub noise_pub: String,
    /// Ed25519 public key, hex-encoded. Empty (and omitted from JSON) for
    /// the Ember Network page snapshot.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ed25519_pub: String,
    /// Unix timestamp of the last successful response.
    pub last_seen: i64,
    /// Consecutive unanswered queries.
    pub failed_queries: u8,
    /// XOR distance from our local node ID, hex-encoded (slice 16).
    #[serde(default)]
    pub distance: String,
}

/// One in-flight Ember DHT search for the diagnostic UI (slice 16).
#[derive(Debug, Clone, serde::Serialize)]
pub struct EmberDhtSearchInfo {
    pub id: u32,
    #[serde(rename = "type")]
    pub search_type: String,
    pub target: String,
    pub keyword_count: u32,
    pub results: u32,
    pub queried: u32,
    pub in_flight: u32,
    pub responded: u32,
    pub pending: u32,
    pub complete: bool,
    pub age_secs: u64,
}

/// One live store key for the diagnostic UI (slice 16).
#[derive(Debug, Clone, serde::Serialize)]
pub struct EmberDhtStoreInfo {
    pub key: String,
    pub record_count: u32,
    pub keyword_records: u32,
    pub source_records: u32,
}

/// Flatten a routing-table contact into its IPC representation. Shared
/// by the `get_ember_dht_contacts` snapshot and the `FIND_NODE` reply
/// path so the two never drift. The UI snapshot clears `addr` after
/// this so peer IPs never reach the webview.
pub(super) fn ember_dht_contact_info(
    c: &ember::dht::EmberContact,
    local_id: ember::dht::EmberNodeId,
) -> EmberDhtContactInfo {
    EmberDhtContactInfo {
        node_id: c.node_id.to_hex(),
        addr: c.addr.to_string(),
        noise_pub: hex::encode(c.noise_pub),
        ed25519_pub: hex::encode(c.ed25519_pub),
        last_seen: c.last_seen,
        failed_queries: c.failed_queries,
        distance: local_id.distance(&c.node_id).to_hex(),
    }
}

/// Per-peer reputation snapshot. Returned by the `get_peer_reputation_batch`
/// Tauri command so the UI can render a verification / trust badge
/// next to a peer (upload queue, transfer detail panel, etc.).
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerReputationInfo {
    pub score: i32,
    pub successful_transfers: u64,
    pub failed_transfers: u64,
    pub is_banned: bool,
    pub first_seen: u64,
    pub last_interaction: u64,
}

/// Aggregate reputation tracker stats for the security / statistics UI.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReputationStatsInfo {
    pub tracked_peers: usize,
    pub banned_peers: usize,
    /// Total IP addresses currently in the enforced ban set
    /// (`state.banned_ips`): manual bans plus the automatic IP bans
    /// (request flooding / corruption) that never touch the per-user-hash
    /// reputation tracker, so `banned_peers` alone undercounts them.
    pub banned_ips: usize,
}
