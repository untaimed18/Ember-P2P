# After 1.7.5: planned for later releases

1.7.5 freezes the Channels formats (`docs/post-1.7.4.md`, "Channels: the
format freeze"; `docs/channels-format.md`, "What freezes at the end of the
beta"). What follows changes no frozen format, so none of it is tied to a
particular release: it can come in whichever release has room. If 1.7.6
needs no format change, it removes the BETA badge.

## 1. Private-room membership traffic under a throwaway DHT identity

**Why:** 1.7.5's v2 private membership records (item 9 of the 1.7.5 plan)
name neither the room nor the member in what a storer keeps. But every DHT
STORE and lookup that carries them is signed under the sender's long-term DHT
identity (`identity.ed25519_secret_key`, with `sender_id = BLAKE3(pubkey)`;
the engine signs every message with it), which is the key the member is known
by in its rooms. So storers still learn the member:

- **Presence.** A v2 presence record goes straight from the member to the
  storers nearest its key, every republish. A storer learns that this member
  is in some private room, though not which one.
- **Key lookups.** A member that is behind on a room's key looks up its own
  v2 key-epoch record. That record's header names the room, since the room
  key signs it, so the nodes answering learn that this member belongs to that
  room. This is the more revealing of the two.
- **Over time,** a node near many keys can tie one member's pseudonyms across
  rooms and rotations back to them.

It is a privacy limit, not a security one: nobody learns content, keys or
messages, and nobody can join a room or pass as a member. The room is hidden
from storers; who is in private rooms is not.

**To do:** send membership STOREs and lookups (presence, key epochs) under a
short-lived DHT identity of their own instead of the long-term one. Questions
to settle first:

- **Lifetime.** One identity per room, per publish, or per lookup. Shorter
  hides more and costs more handshakes.
- **The address.** Without a relay the storer still sees the sender's IP
  address, which for anyone watching the network is as identifying as the
  key. Route these messages through a relay (the existing relay and buddy
  paths are the place to start), or decide that hiding the key alone is
  worth it.
- **Routing standing.** A fresh identity is in nobody's routing table and has
  no history, so check that its STOREs are accepted and its lookups answered
  as readily as the long-term identity's.
- **Per-node limits.** Storers budget per publisher and per address
  (`publisher_index`, `MAX_RECORDS_PER_PUBLISHER_PER_KEY`, the per-IP caps).
  Make sure throwaway identities are neither refused as abuse nor a way to
  slip past those budgets.

**Not a format change.** Records, keys and storer rules stay as frozen in
1.7.5; only which identity signs the transport message changes, so it needs
no cut-over and old and new builds keep reading each other.

**Tests:** a membership STORE and lookup go out under an identity that is
not the long-term one, and a new one per the chosen lifetime; storers accept
and answer them; nothing else (friend sessions, file search, publishing a
library) changes identity; and the per-publisher and per-address budgets
still bind.

**Looked into after 1.7.5, and deferred until it can go through a relay.**
What the code showed:

- **The DHT key alone is not the identity a storer sees.** Every frame rides
  a Noise session keyed by the node's long-term static Noise key, which is
  generated apart from the ed25519 identity and is just as linkable. The
  receiver does not bind the session to the frame's `sender_id`, so a
  throwaway ed25519 key could ride the existing session, but it would hide
  nothing: the Noise key ties it back. Hiding the identity needs a fresh
  Noise key and session too, per throwaway identity.
- **The address ties it back anyway.** Without a relay, the storer sees the
  sender's IP address, which for most home connections holds for days or
  months, so a storer that logs addresses links one member's rooms however
  often the keys change. A fresh identity and Noise key would only defeat a
  storer that keeps keys and not addresses, and links across an address
  change.
- **No proof of work or verified-contact gate exists** for STORE or
  FIND_VALUE, and the per-publisher cap is charged to the record's signed
  author, not the sender, so a throwaway sender is accepted as readily as the
  long-term one and gets no budget of its own.

Decided: building fresh-key sessions per room for that small gain is not
worth the complexity in the transport. The version that hides the member is
the one that also hides the address: membership STOREs and lookups sent
through a one-hop relay (a HighID peer or the rendezvous relay), under a
throwaway identity and Noise key, so the storer sees the relay's address and
a key it has never seen. That is its own project, and feed lookups
(item 3) would use the same path. Until then the limit stands as described
under **Why**.

## 2. Private messages between room members

**Why:** two people in a room have no way to talk privately except becoming
friends first, which is heavy for a quick word and grants browse and file
sharing along with it. Rooms already carry a message to one member that the
members relaying it cannot attribute (the room friend request, frame 27), and
frames encrypted to one recipient (21, 25, 26). A private message is the same
idea with a body.

**Decided:**

- **Carried by the room, encrypted to the recipient.** A new extension frame,
  kind 66, relayed through the room like chat. Not a direct connection: that
  would give each side the other's address and a new kind of session for
  people who are not friends.
- **First contact is a request.** The first message from someone arrives as a
  request to accept or ignore, and nothing about the conversation shows as
  unread until it is accepted. A setting offers "Ask first" (default), "Allow
  from anyone" and "Off".

**The frame (kind 66).** An ordinary extension frame, signed by the sender,
without `EXT_FLAG_DISPLAY`, so 1.7.2 and later relay it under chat's rules
(the sender's ban, retired-key roster check and chat rate) and no build shows
a "needs a newer Ember" line for it. Body: `version(1) || tag(16) ||
nonce(24) || ciphertext`.

- **Tag.** Pairwise and bound to the envelope's `msg_id`, as frame 27's is, so
  relays cannot group messages by recipient. A receiver derives one pairwise
  base per sender (cached) and one keyed BLAKE3 hash per frame to recognise
  its own.
- **Key.** `derive_pairwise_capability` with a purpose of its own
  (`ch-dm-v1 || channel_id`), never `derive_chat_key`: friend chat's key
  depends on the two identities only, so reusing it would make a room message
  a valid friend-chat ciphertext and the other way round. XChaCha20-Poly1305,
  with `"ember-room-dm-v1\0" || channel_id || msg_id || timestamp || sender
  || tag` as associated data, so a body cannot be lifted into another
  envelope.
- **Plaintext.** `type(1) || fields` (as built, `type || len(2) || fields`),
  one kind for everything so relays cannot tell a message from a receipt:
  message (`message_id(16) || text`), receipt (`message_id(16)`), accept,
  decline. Padded to fixed buckets so length says little: 256, a middle one
  (built as 960, not 1024, to stay unfragmented), and a top bucket sized to
  what one datagram carries once the gossip envelope and the extension frame
  around the body are counted (and, as built, the overlay relay envelope).
  That is well under 4096 (a room line's sealed frame stops fitting at about
  3,760 bytes of text), so the text cap follows from the top bucket, less
  `type(1) || message_id(16)`, rather than being `CHAT_TEXT_MAX_BYTES`.

**Delivery.** Extension frames are not stored for catch-up, so a message
reaches only a recipient online within the 10-minute relay window. The
recipient answers with a receipt; the sender resends under a fresh envelope
for a bounded time and then marks it "Not delivered — they may be offline or
on an older Ember". Offline delivery through the chat mailbox
(`derive_chat_mailbox_box` already works for any two identities) is a later
step, not part of the first version.

**Conversations.** One per person, keyed by their member key, carried through
a room both are in (the one it started in while both remain, else any shared
room, as `send_room_friend_request` picks). No shared room: sending is
unavailable and the conversation offers Add friend. Someone already a friend
gets friend chat instead.

**Safety.**

- **The sender is visible to relays,** since bans and rates need it: members
  passing a frame learn that someone sent a private message, not to whom or
  what. The help text says so.
- **Moderators cannot read them.** A room ban still stops them (relays drop
  a banned sender), and each message costs the sender a chat-rate charge
  (within the 10-minute relay window, which is also as old as a frame the
  recipient acts on).
- **The ignore list moves to the backend.** Today `ignoredMembers` lives in
  the webview's `localStorage` only; it moves into settings (migrated once
  from `localStorage`) so an ignored member's message is dropped before it
  is stored or notified. Ignoring from a request does the same.
- **Requests are capped** per room per hour, as room friend requests are
  (`ROOM_FRIEND_REQUESTS_PER_ROOM_HOUR`), and a declined sender cannot ask
  again for a while.
- **No forward secrecy:** static keys, as sealed offers and friend chat use.

**Storage.** New tables: threads (`member_pubkey`, state request / open /
declined, room last used) and messages, the bodies encrypted with the chat
key like `chat_messages`. Deleting a conversation deletes both, except that a
declined one keeps its bare row while the refusal lasts. Leaving or being
banned from a room does not delete history.

**UI.** "Message privately" in a member's menu; a chat tab in the dock,
labelled with the room; requests listed on the Channels page; notifications
under the message-notification settings; the new setting under Channels.
Strings in all nine languages.

**Spec.** Kind 66 goes into `channels-format.md` under Extension frames, and
into `UNDERSTOOD_EXT_KINDS`, in the release that builds it. Adding a kind is
what the freeze allows, so no frozen format changes and no cut-over is needed.

**Tests:** only the recipient recognises its tag, and tags differ for two
messages to the same person; a body does not open under another envelope,
room or sender; a friend-chat ciphertext does not open as a room message and
the other way round; 1.7.4's unknown-kind path relays the frame without
storing or counting it; a banned or ignored sender's message is dropped; the
first message is held as a request and not notified as unread; receipts stop
resends; a message to someone with no shared room is refused.

**Built.** As decided above, with these choices made on the way:

- **Code.** `network/ember/room_dm.rs` (the codec), `network/room_dm.rs`
  (receiving, and the one place frames are sealed and sent, through
  `NetworkCommand::SendRoomDm`), `storage/database/room_dm.rs` (tables
  `room_dm_threads` and `room_dm_messages`, created on first use outside the
  numbered chain) and `commands/room_dm.rs` (commands, room choice, the
  resend loop). Spec: `channels-format.md`, "Private messages (kind 66)".
- **Plaintext** carries a two-byte length after the type, so padding is
  unambiguous. Buckets 256, 960 and 3670 bytes; the text cap is 3651. The top
  bucket leaves room for the overlay relay envelope, without which a long
  message never reached a firewalled member.
- **Resends** every 2 minutes for 20 minutes, under a fresh envelope with the
  same `message_id`; then "Not delivered", with Try again, which meets the
  same rules as a new message.
- **Replies** (receipts, declines) wait a random 10 to 90 seconds, so their
  timing does not say whom a message was for, and are rationed: 30 and one
  decline per member per 10 minutes, 2 a second in all, so a member cannot
  spend our author rate and crowd out our chat.
- **Caps.** A request holds 20 messages until answered; 120 are kept from
  one member an hour; a conversation keeps its newest 2000. Past a cap,
  messages are dropped unanswered.
- **"Off"** declines everything, an open conversation and resends too, stops
  what is still being sent, and blocks sending. A message from someone in a
  conversation we have open clears a decline they sent earlier: writing to
  us is taking ours. Their decline otherwise lasts 7 days, as ours does, and
  is recorded only in a conversation we started or accepted, and only if
  newer than the answer held.
- **Declining**, or deleting a request, forgets what they sent and refuses
  them for 7 days, a refusal deleting the conversation does not lift.
- **The ignore list** is kept in settings (`ignored_members`, owned by the
  backend, written by `set_ignored_members`). The webview moves its own copy
  over once, then takes the backend's; an edit made before settings load is
  pushed rather than lost.
- **UI.** "Message privately" in a member's menu (not for someone ignored,
  banned or a friend), a dock tab labelled "(private)" that also works in
  the popped-out chat window, requests as banners on the Channels page with
  Accept, Decline and Ignore, and counted on its nav item rather than as
  unread. A conversation that receives a message gets a tab without opening
  the dock. The policy is under Settings > Channels. Notifications use the
  message switch.

**Not yet:** "Add friend" from a conversation with no shared room (the text
says to), offline delivery through the chat mailbox, "load older" in a
conversation (the newest 100 show), disappearing-message timers, and an
end-to-end test over two network loops; the receive path is covered by its
parts' tests.

## 3. Follow a publisher (feeds)

**Why:** on eD2K you find things by searching and hoping: names are
unreliable, fakes are common, and nothing tells you when someone you trust
shares something new. Ember already gives every user a signed identity, a DHT
that stores records signed by it, and collections that carry Ember's content
hash. A feed puts them together: a publisher keeps a signed, updatable list of
files under their identity, and anyone can follow it. Followers see what is
new, and can have it downloaded for them. No eMule-compatible client can offer
this, because none has identities to sign with.

**Decided:**

- **A feed belongs to an identity.** It is signed by the publisher's Ember
  identity key, the one their friends and rooms already know. One identity
  can have several feeds (at most 8), each told apart by a random 16-byte
  salt, as owned rooms are (`channel::owned_rooms_key`).
- **Two parts: a small signed head in the DHT, and the list as a file.** A
  feed can hold far more than a DHT record fits
  (`MAX_STORE_RECORD_BYTES`), so the record only points at the current list.
  The list is an ordinary collection file, fetched like any download.
- **Following is opt-in per feed, and auto-download more so.** A followed
  feed shows what is new. It downloads nothing until the user turns on
  auto-download for that feed.
- **No public directory in the first version.** A feed is found through a
  link, a friend or a room, never through a global list that spam would
  fill on day one.

**The head record.** A new record type, `RECORD_TYPE_FEED` (0x04), with the
header and trailer framing of channel records. It is filed under
`feed_key = BLAKE3("ember-feed-v1" || publisher_pubkey || salt)[..16]`, which
storers recompute from the record and refuse when it differs, as they do for
kind 7. Signed by the identity key. Extra:
`version(1) || sequence(8) || list_ed2k_hash(16) || list_size(8) ||
list_blake3(32) || item_count(4) || title_len(1) || title || description_len(2)
|| description`. Title at most 64 bytes, description at most 256. The highest
`sequence` wins, with a newer timestamp breaking ties (as
`moderation_supersedes` does), so a storer never goes back to an older list.
TTL 30 days, like channel governance records. The publisher republishes
daily and on every change.

**The list.** A collection file (`network/ed2k/collection.rs`, format v2)
whose entries carry name, size, eD2K hash, AICH hash and Ember BLAKE3 digest,
with the feed title as its name and the publisher's nickname as author. The
head commits to its eD2K and BLAKE3 hashes, so the list needs no signature of
its own: a list that does not match the signed head is discarded. At most
2,000 items. Each item may carry a short note (a new tag, at most 256 bytes),
which eMule's collection reader skips like any unknown tag. The publisher
keeps the list under the app data folder, not in a shared folder. It is
shared hidden: it answers download requests and has Ember source records,
but never appears in the Library, a friend's browse or keyword search.
Followers keep and serve the latest list for as long as they follow, so it
stays reachable when the publisher is offline.

**Following.**

- **Links.** `ember-feed:<publisher>/<salt>` in base32, plus an
  `https://emberp2p.org/feed/...` form the website can later turn into a
  landing page. Both go through the existing deep-link handler.
- **Elsewhere.** "Feeds" on a friend's card. A feed link in a room message
  renders as a card with a Follow button.
- **Polling.** Followers look up the head on startup and then every 30
  minutes with jitter. Publishing also pushes the new head to online friends
  over the friend session, so friends see an update at once.
- **New items.** When a newer head arrives, the follower fetches the list,
  works out what is new against the list it holds, and marks the feed
  unread. Items the publisher removed stay downloaded and are shown as
  removed.

**Auto-download (off by default, per feed).** Each feed has its own size cap
per item and per day, plus a category and folder. Files Ember never
auto-tags (executables, scripts, app data; the `NEVER_AUTO_TAG_EXTENSIONS`
idea) are never auto-downloaded and have to be started by hand. Nothing is
started when the file would leave less free space than a headroom like the
64 MiB friend attachments keep (`ATTACH_DISK_HEADROOM`). Every auto-started
download is labelled with its feed in Transfers.

**Publishing.** "Add to feed…" on Library rows (the selection or one file),
and a feed editor with title, description, reordering and removal.
Publishing bumps `sequence`, rebuilds the list and republishes the head.
Only files the user shares can be added, so every item has at least one
source when it is published.

**UI.** A "Following" page in the sidebar listing followed feeds with
unread counts. Each feed's page shows its items, newest first, with
Download, Download all new, the auto-download settings and Unfollow. "My
feeds" sits beside it for publishing. Notifications for new items go under
the existing notification settings. Strings in all nine languages.

**Safety and privacy.**

- **Names.** Item names and notes go through the same sanitising and spam
  scoring as search results. A feed whose list fails to parse, or does not
  match its head, is marked broken rather than shown in part.
- **Following is not secret.** Storers answering a head lookup learn that
  someone at this address and identity asked for that feed, and a list's
  sources learn who fetched it. Item 1's throwaway identity would cover the
  first, so feed lookups should use it once it exists. The help text says so
  meanwhile.
- **Publishing is public by design.** The feed is tied to the publisher's
  identity, which is the point. The editor says so before the first publish.
- **Unfollow purges the list and stops serving it.** Downloaded files stay.
- **A lost identity loses its feeds.** The identity backup already covers
  this.

**Rollout.** Builds before the one that ships this refuse the new record
type, as they refuse an unknown channel kind, so heads are stored only on
nodes that understand them. Early on, with few such nodes, lookups will miss
more often. The friend-session push and followers republishing the signed
head they hold (check that storers accept a record whose publisher is not
the sender, as the proxy-store path does) are the fallbacks. Nothing that
already exists changes format.

**Questions to settle first:**

- **Who may republish a head.** The publisher only, or any follower
  re-storing it, which keeps the feed alive while the publisher is away
  but costs storer budget.
- **Per-node limits.** Heads per publisher and per address, so a publisher
  cannot flood the DHT with feeds. 8 feeds per identity is the client's
  rule, so storers need their own.
- **Several devices.** Whether one identity on two devices can publish
  the same feed: the `sequence` race would need the same care as room
  ownership.

**Tests:**
- **Keys.** Storers refuse a head whose key does not match its publisher and
  salt, and keep the highest sequence.
- **List integrity.** A list that does not hash to the head's hashes is
  discarded.
- **New and removed items.** They are computed correctly across sequences,
  including a removal.
- **Auto-download limits.** It respects caps, blocked types and free space,
  and never starts with the switch off.
- **Hidden list.** It is served but never listed or keyword-published.
- **Old peers.** A pre-feed build refuses the record cleanly.
- **Friend push.** A pushed head from a friend is verified like a fetched
  one.
- **Unfollow.** It removes the list and its sources.

## 4. Connection doctor

**Why:** LowID and "firewalled" are the most common eD2K support problem, and
the hardest for a newcomer to fix. Ember already knows most of what is wrong:
- **Kad firewall checker:** TCP and UDP open or firewalled.
- **eD2K server:** whether it gave us a LowID (`ed2k_low_id`).
- **UPnP:** whether ports are mapped, and whether it stood down behind a VPN.
- **STUN:** NAT type and public ports.
- **Buddy status.**
- **Windows Firewall rules:** `security::firewall`.

Today these show only as technical tiles and status dots. Ember also already
works around much of it with relays, hole punching and buddies, which the user
never hears about. A doctor puts it into plain words: what works, what does
not, what Ember is doing about it, and the one thing worth trying next.

**Decided:**

- **One check, one verdict.** Run on demand from Settings > Connection, and
  offered automatically, once, when a LowID or firewalled state has lasted 10
  minutes. The result is one of:
  - **Fully reachable.**
  - **Reachable through Ember's relays.** Everything works; new
    connections take a little longer.
  - **Limited.** Some eMule users cannot download from you, and you reach
    fewer sources.
  - **Offline.** The check names what is blocking.
- **Ember's own help is listed as such.** Relays, hole punching and a Kad
  buddy appear as things already handled, so a user who cannot change their
  router knows they are not broken.
- **Fixes are ranked and concrete.** At most three, most likely first, each
  with exact steps using the user's own numbers: the ports, the computer's
  LAN address and the router's address.

**What it checks.** Each check reads state the network loop already holds,
re-run on demand where that is cheap:
- **Listen ports:** bound, or taken by another program (often eMule itself,
  still running).
- **Windows Firewall:** inbound rules present for the TCP, Kad UDP and QUIC
  ports (`ensure_firewall_rules`), and whether adding them needs elevation.
- **UPnP:** off, not found, mapped, refused, or stood down because the
  router's WAN address is not the one peers see.
- **Router WAN address:** private or `100.64.0.0/10` (carrier-grade NAT),
  read from the UPnP gateway. Port forwarding cannot help then; only the
  ISP or relays can.
- **Probes from outside:** Kad TCP and UDP firewall results (a fresh cycle
  on demand), the eD2K server's ID, and the new outside-in probe below.
- **NAT type:** a symmetric NAT means hole punching to other symmetric
  peers cannot work, and relays carry those connections.
- **Ember DHT health:** routing-table contacts and recent lookup answers.
- **Rendezvous and relays:** whether we are registered, and whether a
  relay or buddy is available to us now.
- **Clock skew:** compared with the rendezvous server's `Date`. Signed
  records and session timestamps go wrong when the clock is far off.

**Outside-in probe.** A new rendezvous endpoint (`POST /v4/reachability`) that
connects back to the caller's TCP port and sends a short UDP datagram to its
Kad and QUIC ports, answering with what got through. It is the only check
that does not depend on finding other peers, so it answers in seconds.

Rules:
- **Own address only.** It only ever probes the source address of the
  request, so it cannot be pointed at anyone else.
- **Rate-limited.** A few probes per address per hour.
- **What it sends.** A fixed probe that Ember recognises and answers. Any
  other program on the port sees nothing it would act on.
- **Optional.** Without the endpoint (an older or third-party rendezvous
  server), the doctor relies on the Kad and eD2K results and says the
  check took longer.

**Actions it can take, each after the user confirms:**
- **Retry UPnP now.**
- **Add the Windows Firewall rules,** asking for elevation once, through the
  existing rule code.
- **Move to free ports** when the configured ones are taken, then
  restart networking.
- **Re-run the firewall checks and reconnect the eD2K server.**

It never changes the router, and never turns off a VPN.

**Report.** "Copy report" puts the findings, versions and NAT type on the
clipboard for support. IP addresses are masked by default, with a switch to
include them.

**UI.** A "Check connection" button under Settings > Connection. The status
bar's LowID / firewalled indicator links to it. The results are a short
list of checks with a passed, failed or skipped mark and a one-line
explanation each, the verdict on top and the fixes below. Strings in all
nine languages, with router steps kept generic: "port forwarding", not one
router brand's menu names.

**Not a client format change.** Everything but the probe is client-side. The
probe needs the rendezvous server change above, and works without it.

**Questions to settle first:**

- **Probe ports.** Whether the probe also covers the QUIC port when it
  shares the Kad UDP port (`quic_shares_udp_port`). One datagram may answer
  both.
- **IPv6.** Whether to report IPv6 reachability now, or once Ember listens
  on it.
- **The automatic offer.** Whether it fits in the first-run flow, or
  stays a status-bar prompt only.

**Tests:**
- **Verdicts.** Each one is reached from the right combination of signals,
  including relayed-but-working and carrier-grade NAT, where port-forwarding
  advice would be wrong.
- **Probe scope.** The probe endpoint only ever probes the requester's
  address, and enforces its rate limit.
- **Clock skew.** It is reported past the threshold and not under it.
- **Fixes.** A fix that needs elevation asks once, and reports a refusal
  plainly.
- **Missing endpoint.** The doctor still finishes, from Kad and eD2K results
  alone.
- **Report.** Copying it masks addresses unless the user chose to include
  them.

**Done in 1.7.5.**

- **Backend.** `commands/connection_doctor.rs`: `run_connection_check`
  gathers the signals and `assess` turns them into the verdict, the checks,
  what Ember already does and at most three fixes. `assess` is pure and
  tested for each verdict, carrier-grade NAT, VPN, a taken port, offline,
  clock skew, a missing or rate-limited probe and a change waiting on a
  restart. It judges what the session runs on (`session_tcp_port`,
  `session_udp_port`, `session_upnp_enabled` in `NetworkStats`), not saved
  settings, and a saved change to them is the first fix, "restart". A TCP
  port Ember could not open is never called open, whatever answers on it.
- **Probe, client side.** `network/reachability.rs` takes the 32-byte UDP
  probe ahead of STUN, Ember and Kad on the shared socket. The doctor
  registers its nonce before asking (`expect_probe`), and only that nonce
  counts, so probe-shaped traffic from anyone else neither fakes an arrival
  nor crowds out the real one. The probe goes to the public ports STUN saw;
  the report and the forwarding steps name the local ones.
- **Probe, server side.** `/v4/reachability` in the rendezvous server
  (`reachability_v4`, advertised as `reachability` on `/v4/protocol`). It
  probes only the requester's address, at most 6 per hour per IPv4 address,
  TCP connect then the tagged datagram three times, and is tested against
  loopback listeners. It probes a routable public IPv4 caller only and
  answers anyone else `"available": false` without dialling or charging the
  limit: an IPv6 caller would be probed where Ember does not listen, and a
  loopback or private one is a proxy in front of the server. The answer
  carries the server's clock, which is what the skew check reads. A 429
  shows as "the hourly limit is used up".
- **New stats.** `NetworkStats` gained `upnp_wan_ip`, `tcp_listen_failed`,
  `bound_udp_port` and the session's ports. Windows gained
  `firewall::rules_in_place` and `add_rules_elevated`: one permission prompt,
  running `netsh` from an `-EncodedCommand` script, with the program path
  passed base64-encoded so no character in a folder name can end a string.
- **UI.** `ConnectionDoctor.svelte` sits at the top of Settings > Network,
  above the port fields. The status bar shows "Check connection" beside a
  LowID or firewalled state. The automatic offer is a status-bar toast,
  once a session, after ten unbroken minutes (`connectionDoctorOffer.ts`;
  the stepper and its timer are tested, the status bar sets the timer), not
  part of the first-run flow. Retrying UPnP checks again ten seconds later.

**Left as they are:**

- **Firewall rules are judged by name and port.** A disabled or blocking
  rule of that name passes, and Windows Firewall switched off, or a
  third-party firewall, reads as missing rules. The outside probe is what
  says whether traffic gets through.
- **No QUIC rule from the doctor.** With QUIC on the Kad UDP port (the
  default) none is needed; on a port of its own, the rule startup adds is
  the only one.
- **"Reconnect the eD2K server" is not an action.** "Check again" restarts
  the Kad firewall checks only, and is offered only when offline.
- **The TCP probe is a connect.** A SYN-proxying firewall, or a router
  service on the port, reads as open. Writing the nonce on the connection
  for the upload listener to recognise would close it; not done.
- **The permission prompt has no owner window** and may open behind Ember,
  as a flashing taskbar button.

**How the open questions were settled:**

- **Probe ports.** The tagged datagram to the Kad UDP port. With QUIC
  sharing that port (the default), it answers for both. A separate QUIC port
  is not probed, and Ember does not answer the probe: it only notes it.
- **IPv6.** Not reported until Ember listens on it; the server declines an
  IPv6 caller and the client ignores an answer about anything but IPv4.
- **"Move to free ports".** Brings the port field up and selects it rather
  than choosing ports itself. A port picked unasked could be taken too, and
  the field's restart badge already says when it applies.

**Deployment.** The probe needs the rendezvous server deployed with this
change. Until then the doctor reports from the Kad and eD2K results and
says the outside test did not run.

## Already scheduled for 1.8.0

Decided in 1.7.5 and written into the spec, so that a room has one cut-over to
test: stop sending chat frames 15 and 19 and set `EXT_FLAG_DISPLAY` on kinds
64 and 65; stop publishing v1 private membership records
(`PUBLISH_V1_MEMBERSHIP_RECORDS`), except the owner's own key copy; and
rotate every private room once as it does (`V1_CUT_OVER_ROTATES`, not built
yet; v1 cannot be switched off until it is). Whether to renew every retained
epoch's key records, not just the current one's, is also left to decide then.
Detail in `docs/post-1.7.4.md` items 2 and 9.

**Also in 1.8.0: relayed catch-up replies move the frontier.** A catch-up
reply that reaches us through another member's hop arrives as an ordinary
`CHANNEL_MSG` from that hop, and cannot be told from the hop's own TTL-1
line, so progress is credited only to a neighbor whose reply came directly
(`catch_up_progress` in `channel_gossip.rs`). A neighbor whose replies are
relayed is asked the same range again each round: bandwidth, never a lost
line. The fix is a marker saying a frame is a relayed catch-up reply and for
whom, in the relay envelope or the gossip frame. Both formats froze with
1.7.5, which is why it waits for 1.8.0, the release that changes formats
anyway. To decide then: where the marker goes (the relay envelope is the
natural place, since only relays forward a reply), whether it is signed by
the neighbor that served the reply so a hop cannot forge progress for it, and
how a 1.7.x member that does not send it is read (as today: not credited).
Origin: `docs/post-1.7.4.md`, "Channels: smaller follow-ups".

**Also in 1.8.0: pad the owned-rooms list.** 1.7.5 can pad the identity's
list (kind 7) to 8, 16, 32 or 48 entries with salts derived from the identity
secret, so the list says neither how many rooms the identity owns nor which
were carried (`pad_owned_rooms_list`), and it already drops its own pads when
it reads a list. It does not publish them yet (`PAD_OWNED_ROOMS_LIST` is
off): a 1.7.4 device on the same identity reads every pad as a room it cannot
find, carries it as unsettled, keeps looking every six hours and publishes the
pads back in its own list, unpadded and in the order it holds them. 1.8.0
switches it on, once a second device on 1.7.4 or older is no longer expected.
Origin: `docs/post-1.7.4.md`, "Known limits" of owned-room recovery.

## Carried from the 1.7.5 plan

What `docs/post-1.7.4.md` leaves open, apart from the item above, which this
plan now owns: under "Later", the Away status, component tests, Discover spam
folding and the smaller Friends items; under "Channels: smaller follow-ups",
the relayed catch-up frontier, the moderation lock race and pre-1.7.3 bans;
and its "Known limits".
