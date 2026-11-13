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

## 1. Before 1.8.0 ships

1.8.0's Channels cut-over is built: the v2 chat frames go out alone with the
display flag, private membership records go out in v2 alone but for the
owner's own key copy, each owned private room is rotated once
(`take_channel_cut_over_rotations`) and once more where members were still on
1.7.x (`take_channel_relink_rotation`), the owned-rooms list is padded, and
room transfers send sealed offers only. Owners also renew the older epochs a
room keeps, and derive every rotated key from the room's seed so two devices
owning a room stay on one key. The 1.7 sending paths are gone; reading 15,
19, v1 records and plain offers stays. The detail is in `channels-format.md`,
"The cut-over in 1.8.0", "The transition, and the cut-over in 1.8.0" and
"Two devices owning a room".

The release notes are in `docs/index.html`; check the date against the tag.
What only a run between two machines can show, each with both on 1.8.0
unless it says otherwise:

- **The cut-over**, from 1.7.8 and beside 1.7.4. A checklist was written and
  not run; `git log --all -- docs/release-checklist-1.8.0.md` finds it.
- **Room mail:** a message to a member who has gone offline shows *Waiting in
  their mailbox* after its first two minutes, arrives when they come back, and
  turns delivered; to a member on 1.7.8 it is never left.
- **Disappearing private messages:** each side deletes at its time, and a
  member on 1.7.8 keeps its copy.
- **A friend's slot for a friends-only file** granted over the secure dial
  (`secure_push_grant_target`): the friend's download adopts it and the file
  is served. Nothing else exercises that dial for an upload grant.
- **Searching all of a friend's files** (`EBR2`): a friend sharing more than
  1,000 files is searched whole, and one on 1.7.8 is listed and filtered as
  before.

What only the tagged release can show is the AppImage built on Ubuntu 24.04:
`latest.json` carries `linux-x86_64-appimage-glibc` with a `min_glibc` of
2.39 and no plain `linux-x86_64-appimage`; a 1.7.8 AppImage on Ubuntu 24.04
or Fedora takes the update and starts; one on Ubuntu 22.04 says the update
needs glibc 2.39 and keeps its version; and on Fedora the 1.8.0 AppImage
draws emoji with the system's font, its debug log saying the host FreeType
matches the bundled WebKit.
`linux-test-build.yml` builds the same AppImage on demand for the last of
these.

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

## 3. Feeds

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
  from several Ember peers at once (section 5, "Ember-native transfers").

## 4. Friends

- **Check friend meets on real restricted NATs.** 1.7.6 resends the first
  handshake message and carries the Noise key in the meet. Tests replay the
  failure, but no meet has run between two real restricted NATs. Compare
  `ember_dht_friend_meets` with `ember_dht_friend_meets_converted` in
  Diagnostics; conversions should be close to meets for friends not behind a
  symmetric NAT.

## 5. The Ember network

Detail for every item here is in `ember-dht.md`: "Outstanding work" items 1,
5 and 7, "Future improvements", and the 2026-08-18 audit notes.

**Do next:**

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
  join, that is a real loss. From 1.8.0 each listed peer gets a debug line
  saying why it is or is not dialable, then its ping and its answer
  (`Ember rendezvous advert` under `RUST_LOG=debug`); one run with those read
  settles it.

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
  a feed's follower swarm (section 3) needs. Reach is the other limit: an
  arbitrary room member holding a file may not be dialable.
- **Retire the legacy QUIC listener.** It stays on the TCP port number for
  relays that dial a KAD-only source there. It can go once those sources have
  a relay target of their own.

## 6. Updates and releases

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
- **Build the `.deb` on a newer distribution.** From 1.8.0 the AppImage is
  built on Ubuntu 24.04 and published under `linux-x86_64-appimage-glibc`
  alone, with its `min_glibc`. The `.deb` stays on 22.04 (glibc 2.35): a
  `.deb` before 1.8.0 asks for `linux-x86_64-deb` and checks no glibc, so a
  build from a newer distro would install on an older one and then not
  start. 1.8.0's `.deb` prefers `linux-x86_64-deb-glibc` when its system
  meets that entry's `min_glibc`, and says so when it cannot
  (`choose_glibc_target`). Once enough `.deb` installs are on 1.8.0 or later,
  a release can build the `.deb` on 24.04 and publish it there, with
  `add-linux-platforms.mjs` and the release policy following. Whether a 22.04
  build keeps the plain entry beside it, for `.deb` installs before 1.8.0 and
  systems older than 24.04, is the choice then; the two files would need
  different names, since both are `Ember_<version>_amd64.deb` today. It has
  to happen before GitHub retires its Ubuntu 22.04 runners, and until then
  the release policy holds `build-linux-deb` to `ubuntu-22.04`.
- **Flatpak and Snap packages.** Both bring their own runtime (Flatpak a
  GNOME runtime with WebKitGTK, Snap `core24` with its `gnome` extension), so
  one build would run on any distribution with Flatpak or snapd whatever its
  glibc or FreeType, and neither the glibc floors above nor the AppImage's
  emoji workaround would apply. The costs: updates come from Flathub or the
  Snap Store rather than Ember's signed manifest, so the updater has to stand
  aside for them (a build without a bundle marker already finds no entry and
  reports no update); Flathub builds from source on its own infrastructure,
  so what its users run is not the release's signed artifact; and the
  sandbox needs permissions for the download and shared folders, which Ember
  lets the user put anywhere, and for the tray and the `ed2k:` link handler.
  Pick it up when users ask for one, or if the `.deb` cannot leave 22.04 in
  time.

## 7. Code health

- **Split `NetworkState` per stack.** One struct on one task is the model that
  produced the original starvation bug, and it is still the most pressing
  architectural risk in the codebase. Each stack would get its own task with
  an explicit message boundary. It is a redesign rather than code motion, so it
  needs integration testing against live peers. `command.rs` is separable and
  `NetworkDeps` gives the entry point a real signature. Today only
  `start_network` builds a `NetworkState`, from live sockets and managers; a
  state tests can build comes with the split, and with it a test of private
  messages through two network loops for their routing (the wire, storage and
  pacing are covered: `a_private_message_goes_end_to_end_between_two_members`,
  `dm_pacing_invariants_hold`). The receiver's events need an `AppHandle`,
  which Tauri's `test` feature provides.
- **Overnight runs of Ember itself, and property tests for more of it.** The
  fuzz loops and the `*_invariants_hold` property tests (the Ember routing
  table, the batch publisher, private-message pacing) run 200 times longer
  each night from a new seed (`soak.yml`, `src/fuzz.rs`). Still missing: a
  build left running against the live network, and the same kind of test for
  the record store and the KAD routing table.
- **Find out why most known peers show verification as Needed.** SecureIdent is
  per session, which explains part of it. Run 30 to 60 minutes with
  `RUST_LOG=info,ember_lib::network::ed2k::transfer=debug` and compare each
  peer's `SecIdent:` state with its Known Clients row; if queued or
  download-side peers never get a challenge, send one when their session
  starts. Detail: `archived-plans/post-1.7.1.md` item 5.

## 8. Translations

- **A native speaker's read of the 1.8.0 Russian and Polish plurals.** The
  source-exchange tooltip and the cancel-and-remove confirmation now carry a
  form for 2 to 4 and show the count in their singular, which serves 21, 31
  and so on; `channels_reactors_others_*` needed nothing, as `ещё {count}`
  takes no noun.

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
- **A marker that lets relayed catch-up replies move the frontier**
  (`post-1.7.5.md`, "Already scheduled for 1.8.0"). A reply that reaches the
  asker through another member's relay still moves no catch-up frontier, so
  that range is asked for again: it costs bandwidth, never a line. Marking
  such replies needs a field the relay envelope has no room for, and the
  frozen formats send a new envelope version beside v1 until every build in
  the room reads it, which would double relayed catch-up traffic for that
  long. A signed note from the neighbor saying how far it served could carry
  the frontier past lines lost on the way, which is worse than asking twice.
- **Web mirrors in feed lists** (`post-1.7.5.md` item 6, step 3). It would let
  a publisher name a server it runs and learn who downloads and when, which it
  cannot learn today without being a source. Followers who opt in to share a
  feed's files (section 3) relieve the publisher without that.
- **Stronger observed-IP and STUN interplay, and tuning announce against bucket
  refresh** (`ember-dht.md`, "Future improvements"). Neither had a problem or a
  design behind it. Reopen with soak data that shows one.
- **Migration guidance for turning the DHT on beside KAD and eD2K**
  (`ember-dht.md`, "Product / UX"). The overlay is always on, with no switch.
- **Room mail for a stranger's first message.** A first message from someone
  with no conversation is a request the user answers; left in a mailbox, it
  would let anyone in a shared room fill one's box on the server while one is
  away. A first contact waiting for both to be online is the right gate, and
  the alternative needs a field the frozen presence record does not have.
- **Checking block-protocol room transfers chunk by chunk**
  (`post-1.7.0.md` item 2). The block protocol is the fallback for members
  who can only meet through a relay, and the finished file is still checked
  against the offer, so nothing bad is kept. What a bad sender can waste is
  bandwidth, up to the size of a file the user chose to accept from it: not
  worth a new frame on both ends.
- **Tuning Discover's spam folding as a plan item.** There is nothing to
  build; `LIKELY_SPAM_SCORE` and `DUPLICATE_NAME_FLOOD` are revisited when a
  report of a folded good room, or of spam getting through, comes in.
- **Carrying a feed to another device of the same identity.** A backup holds
  `ember.db`, a user's own feeds and their items included (`feeds_own`,
  `feeds_own_items`), so an identity restored from one brings its feeds.
  Keeping two running devices' feeds in step would be a sync feature Ember
  has nowhere else.
- **Sharing any folder without its subfolders from the folder picker.** Ember
  shares a folder with what is under it by design, and the share browser
  already unshares a subfolder, files added to it later included; only a
  subfolder made later is shared. The eMule import makes flat shares itself
  for users who expect eMule's way.
- **A test of private messages through two network loops, on its own.** It
  needs a `NetworkState` that tests can build, which is the split's work, so
  it is part of that item (section 7).
- **Already done, found while gathering this plan:** digest corroboration
  across colluding storers (`post-1.7.0.md`; responders are counted per /24 and
  a contested digest is not pinned), and keeping withheld lists in a store of
  their own (`post-1.7.0.md`; 1.7.2 made the list name folders instead, see
  `post-1.7.1.md` item 2).
- **Already done, found since:** unsharing a folder inside a listed folder
  entry (`withhold_under` gives it an empty list of its own, so files added
  later stay unshared).
