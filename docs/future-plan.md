# Future plan

Everything still open for Ember, gathered from every earlier plan. Each item
says what it is, why it matters, when to pick it up when it waits on evidence,
and where its full design is. When an item ships, take it out of this file and
put it in the release notes; when one is decided against, move it to
[Considered and dropped](#considered-and-dropped) with the reason.

The earlier plans are kept in [`archived-plans/`](archived-plans/) as history:
the `post-1.7.x.md` plans, the feed-reachability and update-mirror plans, and
the release checklists. They hold the full designs this file points to, and
what was decided along the way. The overlay's design record (decisions,
known limits, closed work) stays in [`ember-dht.md`](ember-dht.md), and the
Channels formats in [`channels-format.md`](channels-format.md).

## 1. 1.8.0: the Channels format cut-over

1.8.0 is the release that changes formats, so these were held for it. They go
out together, so a room has one cut-over to test.

- **Retire the old chat frames and the v1 membership records.** Stop sending
  chat frames 15 and 19, and set `EXT_FLAG_DISPLAY` on kinds 64 and 65. Stop
  publishing v1 private membership records (`PUBLISH_V1_MEMBERSHIP_RECORDS`),
  except the owner's own key copy. Rotate every private room once as it does
  (`V1_CUT_OVER_ROTATES`, not built yet; v1 cannot be switched off until it
  is). Decide then whether to renew every retained epoch's key records, not
  just the current one's. Detail: `archived-plans/post-1.7.4.md` items 2 and
  9, and `channels-format.md`, "What freezes at the end of the beta".
- **Relayed catch-up replies move the frontier.** A catch-up reply that
  reaches us through another member's hop cannot be told from that hop's own
  line, so only a neighbor whose reply came directly is credited
  (`catch_up_progress` in `channel_gossip.rs`), and a neighbor whose replies
  are relayed is asked the same range again each round. It costs bandwidth,
  never a line. The fix is a marker saying a frame is a relayed catch-up reply
  and for whom. To decide: where it goes (the relay envelope is the natural
  place), whether the neighbor that served the reply signs it so a hop cannot
  forge progress, and how a 1.7.x member that does not send it is read (as
  today: not credited).
- **Pad the owned-rooms list.** Switch on `PAD_OWNED_ROOMS_LIST`, so the list
  says neither how many rooms an identity owns nor which were carried. Built
  in 1.7.5 and left off only because a 1.7.4 device on the same identity reads
  every pad as a room.
- **Room transfers send only the sealed offer.** A sender still holds a plain
  offer back for recipients on 1.6, and asks whether to send it when a sealed
  one goes unanswered (`XFER_PLAIN_OFFER_FALLBACK_SECS`). After the cut-over a
  1.6 member cannot read the room's chat anyway, so the plain offer, its
  question and `sealed_offer_readers` can go in the same release. Detail:
  `archived-plans/post-1.7.0.md` item 1.
- **Run it across real machines** before tagging, with a 1.7.7 member in the
  same room during the transition: chat, edits, private-room presence and key
  records after the rotation, and catch-up. `archived-plans/release-checklist-1.7.5.md`
  is the model for the checklist.

## 2. Privacy

- **Membership traffic and feed lookups through a one-hop relay.** Private-room
  presence and key-epoch STOREs and lookups are signed under the member's
  long-term DHT identity and ride a Noise session keyed by its long-term
  static key, from its own address, so storers learn who is in private rooms
  (not which room, nor anything said in it), and feed lookups say who follows
  what. A throwaway key alone hides nothing: the Noise key and the address tie
  it back. The version worth building sends these through a one-hop relay (a
  HighID peer or the rendezvous relay) under a throwaway identity and Noise key,
  so the storer sees the relay's address and a key it has never seen. Settle
  first: how long a throwaway identity lives, that its STOREs are accepted and
  its lookups answered as readily, and that it neither trips nor slips past
  the per-publisher and per-address budgets. The same relay path would reach
  friends behind a symmetric NAT, which friend meets skip. Detail:
  `archived-plans/post-1.7.5.md` item 1.

## 3. Rooms and private messages

- **"Add friend" from a private conversation with no shared room.** The text
  already says to; the button is not there.
- **Offline delivery of room private messages** through the chat mailbox
  (`derive_chat_mailbox_box` already works for any two identities). Today a
  message reaches only a recipient online within the 10-minute relay window,
  and ends "Not delivered" after 20 minutes of resends.
- **Disappearing-message timers** for room private messages, as friend chat
  has.
- **An end-to-end test of private messages** over two network loops. The
  receive path is covered only by its parts' tests.
- **Room transfers: check block-protocol data as it arrives.** The direct
  stream verifies every 256 KiB chunk before writing it; the block protocol
  (the fallback) hashes only the finished file, so an accepted sender can waste
  bandwidth up to the offered size. Send the chunk-hash list first and verify
  each 256 KiB run as it completes, re-requesting only a bad run. Needs a new
  frame and a version bump on both ends, so it suits a release that changes
  formats. Detail: `archived-plans/post-1.7.0.md` item 2.
- **Room transfers: replay protection for control frames (low).** Transfer
  frames carry no sequence number. A member an offer was forwarded through can
  replay it once the recipient has forgotten the transfer (180 s after it
  ended) and put the prompt up again; accepting only stalls. An offer
  timestamp under the pairwise tag would let the recipient refuse one older
  than the offer window. Detail: `archived-plans/post-1.7.0.md` item 3.
- **Tune Discover's spam folding from real use.** `LIKELY_SPAM_SCORE` and
  `DUPLICATE_NAME_FLOOD` stay as they are until reports of folded good rooms,
  or spam that gets through, say otherwise.

## 4. Feeds

- **"Feeds" on a friend's card, and feed cards in room messages,** with a
  Follow button.
- **Carry a feed to another device of the same identity.** The format allows
  several devices to publish one feed (the clock-based `sequence` makes the
  latest publish win), but nothing carries a feed's salt and items to a second
  device, so an identity restored elsewhere does not bring its feeds.
- **Followers who help share a feed's files (opt-in per feed).** A feed's
  files cost its publisher every byte, to every follower, because feed
  downloads stay private. A per-feed switch, "Share files from this feed", off
  by default, would share finished files from where they are, like any public
  file, and unshare them when switched off or on Unfollow. Settle first:
  whether partials are shared too, whether co-seeders' source records should
  end the 45-second publisher-first hold early, whether a publisher may ask
  followers to share (a field in the head, shown, never applied silently), and
  what upload priority co-seeded files take. The help text has to say that it
  ties the follower to the feed for anyone looking up an item's hash. Detail:
  `archived-plans/post-1.7.5.md` item 5. A swarm among a link-only feed's
  followers alone is the later, bigger step, and waits on Ember downloading
  from several Ember peers at once (section 7, "Ember-native transfers").

## 5. Friends

- **Filter a friend's browse on the wire, and browse past 1,000 files.** A
  browse answer stops at 1,000 files and 400 KiB, and today's filter runs on
  the client, so browsing a friend with 40,000 files filters an arbitrary
  thousand. Designed in `ember-dht.md`, item 6:
  - Feature bits on the Ember hello (`flags & 0x02`, then a `u32`), so a peer
    learns what the other speaks before sending; reusable by every later
    friend-session feature.
  - A new request marker, `EBR2` with a filter block, sent only to a peer that
    advertised the bit. `browse_request_supports_v1` compares the whole payload
    for equality, so appending to `EBR1` would make an old friend answer in the
    pre-v1 format.
  - `ValueConstraints` as the filter, applied before the caps, with
    `total_matched` in the answer so the dialog can say "showing 1,000 of
    3,400".
  - A rate limit stamped before the walk, as `EMBER_FRIEND_CONTACT_SERVE_INTERVAL`
    is.

  Once that is in, the `EBR2` answer is also where a folder view (folder paths
  relative to the shared folder, opt-in, since they are a privacy decision) and
  media details (duration, bitrate) would go.
- **Check friend meets on real restricted NATs.** 1.7.6 resends the first
  handshake message and carries the Noise key in the meet. Tests replay the
  failure, but no meet has run between two real restricted NATs. Compare
  `ember_dht_friend_meets` with `ember_dht_friend_meets_converted` in
  Diagnostics; conversions should be close to meets for friends not behind a
  symmetric NAT.
- **Decide whether the popped-out chat reopens at launch.** Relaunching with
  the chat popped out remembers the mode but opens no window until a
  conversation is opened.

## 6. Downloads, uploads and sharing

- **Keep verified web mirrors with the finished file.** When a download
  finishes its mirrors are dropped, so Copy eD2K Link on the finished file
  carries none. Keep a mirror that filled at least one part that passed its
  hash check and was never blamed for a corrupt one, at most 5 per file in a
  table keyed by file hash, and have Copy eD2K Link append them as
  `|s=<url>|`, which eMule reads too. Deleting the file drops them. A switch
  leaves them out of copied links, since a mirror URL can name the user's own
  server. Detail: `archived-plans/post-1.7.5.md` item 6, step 2.
- **Give up on an upload waiter whose slot dial fails.** A disconnected HighID
  waiter at the top of the queue is dialled for its slot, and a failed dial
  only backs off 30 seconds (`PUSH_GRANT_BACKOFF_SECS`) for the rest of its
  hour, so a few peers that went offline can keep all three dials busy above a
  reachable waiter. eMule drops a waiter whose slot connection fails. It needs
  `connect_and_serve` to tell a failed connect from a soft end, then drop the
  row or back off longer after each failure. A waiter for a friends-only file
  is better left to its own re-ask, since push-grant sessions are plain eD2K.
  Detail: `archived-plans/post-1.7.0.md`, "Upload queue".
- **Unshare a folder inside a listed folder entry.** "Unshare folder" on
  `F:\Music\Live`, while a partial share of `F:\` lists `F:\Music`, unshares
  what is there now, but the list still offers `Live`, so files added to it
  later are shared. Either a per-folder exclusion that discovery,
  `allowlist_permits` and the withheld tidy-up all honour, or expanding the
  `F:\Music` entry into its contents minus `Live`, which changes what new files
  in `F:\Music` get.
- **eMule import: offer eMule's one-folder sharing.** eMule shares exactly the
  folders listed; Ember shares a folder with its subfolders. The import warns
  and lets each folder be unticked, but cannot import a folder the eMule way.
  Offer "without subfolders" per imported folder, reusing the allowlist.

## 7. The Ember network

Detail for every item here is in `ember-dht.md`: "Outstanding work" items 1,
5 and 7, "Future improvements", and the 2026-08-18 audit notes.

**Do next:**

- **Bring the specification up to date.** The spec and its HTML source predate
  1.7.7's additive changes: the reachability tag in the `PING`/`PONG` block
  (`UDP_REACH_TAG` `0x02`), the refusal reasons trailing `STORE_BATCH_ACK`
  (`STORE_ACK_REASONS_TAG` `0x01`, one code per record), and the publisher-side
  rule of 150 records per keyword. Mark each additive and rebuild with
  `scripts/build-ember-dht-spec.sh`.
- **Validate firewalled publishing live.** The buddy `PROXY_STORE` chain has
  changed in three places none of which has been seen on a live network: an
  endorsement before the buddy proxies, no compatibility trailer, and the
  buddy's own replica attributed to the sender. Walk the chain by its counters,
  from `BUDDY_ENDORSE_REQ` to `ember_dht_callback_connects`, and check that a
  publisher with no endorsement publishes nothing for that file and lights
  `ember_dht_waiting_buddy` until one lands. Also still unexercised: a cold
  join from an empty contact file with no KAD, and republishing across a full
  record TTL on a large library.
- **Find out why rendezvous adverts do not become contacts.** On the 1.7.6
  run, 11 of 20 listed peers matched no contact. They are probably stale
  adverts or changed addresses, but if they are reachable nodes failing to
  join, that is a real loss. A debug line per listed peer the bridge tries, and
  how it ended, would settle it in one run.

**Waiting on a number:**

- **End source, room and directory lookups sooner.** Lookups other than keyword
  searches walk their whole shortlist, and each silent node costs the full 12
  seconds. The 1.7.6 run averaged 20 seconds a lookup against 9.7 on 1.7.3.
  *When:* if "Keyword search avg. time" stays quick while the overall average
  stays high. Then per-peer timeouts from measured round trips first, and
  settling for source and presence lookups second.
- **Hole punching through an introducer** (BitTorrent's BEP 55 on the DHT), so
  a node that says it is firewalled can be a routing contact. *When:*
  `ember_dht_contacts_reach_firewalled` reaches tens of percent of verified
  contacts, once most run 1.7.7 or later. Gate it on a capability tag, take
  the requester's address from the UDP source, keep punched paths alive, and
  leave symmetric NATs out.
- **Offer records before sending them (`STORE_OFFER`).** *When:* nodes
  routinely run as selective storers (the republish backlog shows a number
  rather than "Paused (small network)"), or "Stores acked" grows faster than
  the overlay. Gate it on a capability, and never leave an older storer owing
  a reply.
- **Shard the rendezvous key space.** *When:* `ember_dht_rendezvous_key_load`
  reaches 90. The derivation is already versioned for it.
- **Richer keyword indexing** (stemming, more than space-split tokens).
  *When:* the recall counters show `kad_only` pulling ahead of `both`. Ember
  already indexes four-letter extensions KAD strips, so tuning toward KAD's
  tokenizer can lose recall.
- **Node identities that cost something** (proof of work on node ids, and
  lookups over disjoint paths, as S/Kademlia does). Node ids are free, so one
  host can mint as many as it likes; most caps are keyed on address and /24,
  but the store's per-publisher caps are not. It is a version bump and a flag
  day. *When:* before the overlay is worth attacking, or sooner if
  `ember_dht_store_addr_ceiling` climbs together with `ember_dht_rate_limited`.
  Binding keyword keys to the signed name was built and backed out (it is in
  `git stash`), because it would make the stemming item above a wire break.

**Larger work:**

- **Responder-side key confirmation for crossed IK dials.** A captured
  `IK_INIT` replayed from the peer's address while we have a dial pending can
  take over the crossing, and our first message and queue go into a session
  the real peer cannot read until a fault. The fix, as WireGuard has it: a
  session we answered is not sent on until it decrypts a frame from the peer.
  Still to settle: the peer's frames on a crossing session that a faster
  `IK_RESP` replaced. Costs one round trip before the first message in an
  honest crossing.
- **Ember-native transfers.** Library downloads find sources over Ember and
  move bytes over eD2K. Ember Transfer moves files between room members over
  the room session, in 1008-byte blocks. Moving it onto QUIC would lift the
  throughput ceiling, and downloading from several Ember peers at once is what
  a feed's follower swarm (section 4) needs. Reach is the other limit: an
  arbitrary room member holding a file may not be dialable.
- **Retire the legacy QUIC listener.** It stays on the TCP port number for
  relays that dial a KAD-only source there. It can go once those sources have
  a relay target of their own.
- **A storer-side replication heartbeat,** to sit beside the publish side's
  per-minute `Ember publish cycle` log line.

## 8. Updates and releases

- **A second place to fetch updates from,** for users who cannot reach
  GitHub's download hosts and have no proxy (mainland China). The updater
  already uses the system proxy, and since 1.7.7 every release can be
  downloaded over eD2K by hand, but the updater itself still cannot update
  those users. The plan: a mirror host chosen by a real download test from
  China (Alibaba Cloud OSS Hong Kong or Cloudflare R2 behind a domain), a
  second manifest signed in `sign-publish` with the same key, a `mirror.yml`
  workflow that uploads on publish with credentials of its own, and an updater
  that tries the mirror only when GitHub is unreachable, sharing the one
  downgrade floor. Detail: `archived-plans/update-mirror-plan.md`.
- **Build the AppImage on a newer distribution.** It is built on Ubuntu 22.04
  so it runs on glibc 2.35. Moving it raises the glibc floor, and an AppImage
  replaces itself in place, so the newer build goes out under
  `linux-x86_64-appimage-glibc` with its `min_glibc`, which 1.7.7 and later
  read (`choose_appimage_target`), while the plain entry keeps a build that
  runs wherever today's does, or is dropped. `BUILT_AGAINST_FREETYPE` in
  `appimage_fonts.rs` moves with the build. See the comment on the
  `build-linux` job in `release.yml`.

## 9. Code health

- **Split `NetworkState` per stack.** One struct on one task is the model that
  produced the original starvation bug, and it is still the most pressing
  architectural risk in the codebase. Each stack would get its own task with
  an explicit message boundary. It is a redesign rather than code motion, so it
  needs integration testing against live peers. `command.rs` is separable and
  `NetworkDeps` gives the entry point a real signature.
- **Make clippy warnings fail CI.** `ci.yml` runs `cargo clippy --all-targets`
  without `-D warnings`. The default lint levels were clean, but a newer
  toolchain (Rust 1.98) reports 16 library warnings on Linux, mostly
  `chunks_exact` with a constant size. Fix those, then add `-- -D warnings`.
- **Remove the legacy friend authentication.** `LEGACY_FRIEND_AUTH_ENABLED` is
  a `const false` and nothing turns it on, but `ed2k/ember_auth.rs` and its
  branches in `multi_source.rs` and `upload.rs` still compile. Delete them, and
  keep the arms that log and ignore `OP_EMBER_AUTH_CHALLENGE` and
  `OP_EMBER_AUTH_RESPONSE`, which an old client may still send. Detail:
  `archived-plans/post-1.7.1.md` item 3.
- **Fold the `user_offline` flag.** It is set to `false` at startup and every
  store to it stores `false`, so every branch it guards is dead. Remove it and
  inline each check as `false`, keeping the KAD-disconnect exemption the
  comment in `server.rs` explains. Detail: `archived-plans/post-1.7.1.md`
  item 4.
- **Longer fuzz and property tests in CI,** and overnight soak runs.
- **Find out why most known peers show verification as Needed.** SecureIdent is
  per session, which explains part of it. Run 30 to 60 minutes with
  `RUST_LOG=info,ember_lib::network::ed2k::transfer=debug` and compare each
  peer's `SecIdent:` state with its Known Clients row; if queued or
  download-side peers never get a challenge, send one when their session
  starts. Detail: `archived-plans/post-1.7.1.md` item 5.

## 10. Translations

- **Three Russian plurals read wrongly for 21, 31 and so on:**
  `channels_reactors_others_one`, `statusbar_epx_title_active_one_one` and
  `transfers_confirm_batch_cancel_mixed_one_one`. Each carries two counts or a
  count in another form, so the 1.7.6 fix (`oneShowsCount` in
  `src/lib/plural.ts`) does not fit them. They need rewording, ideally by a
  native speaker.

## Considered and dropped

Taken off the plan, with why, so they are not added back without a new reason.

- **Accepting only a member's known public address for a room transfer**
  (`post-1.7.0.md` item 4). Ember holds no STUN reading for other members and
  few past sessions with them, so it would refuse members whose address
  changed, and the connection already has to prove the member's key. Private
  and special-use ranges are already refused.
- **A shorter re-fetch window after an attachment is delivered**
  (`post-1.7.0.md` item 8). It would only take away the retry a failed save
  needs; the 24-hour grant already bounds it.
- **Re-checking friendship on attachment replies and cancels**
  (`post-1.7.0.md` item 9). For symmetry only: both already arrive on
  authenticated friend sessions and are matched against the attachment's
  friend.
- **Web mirrors in feed lists** (`post-1.7.5.md` item 6, step 3). It would let
  a publisher name a server it runs and learn who downloads and when, which it
  cannot learn today without being a source. Followers who opt in to share a
  feed's files (section 4) relieve the publisher without that.
- **Stronger observed-IP and STUN interplay, and tuning announce against bucket
  refresh** (`ember-dht.md`, "Future improvements"). Neither had a problem or a
  design behind it. Reopen with soak data that shows one.
- **Migration guidance for turning the DHT on beside KAD and eD2K**
  (`ember-dht.md`, "Product / UX"). The overlay is always on, with no switch.
- **Already done, found while gathering this plan:** digest corroboration
  across colluding storers (`post-1.7.0.md`; responders are counted per /24 and
  a contested digest is not pinned), and keeping withheld lists in a store of
  their own (`post-1.7.0.md`; 1.7.2 made the list name folders instead, see
  `post-1.7.1.md` item 2).
