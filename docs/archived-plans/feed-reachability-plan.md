# Feed reachability

Plan for letting followers fetch a feed whose publisher cannot place source
records: firewalled with no buddy, or on a network that blocks the usual
paths.

**Status:** built in 1.7.6 (see "As built" at the end, which records where
the build differs from the plan). The wire details are in
`docs/channels-format.md`, "Reaching a publisher".

## The problem

A follower finds a feed through its signed head record, then fetches the
list the head names like any download: by hash, from whoever has a source
record for it. Items are fetched the same way.

The head and the Discover listing are stored by any node, so they go out
whatever the publisher's network is like. Source records do not. A
firewalled publisher must name a buddy (a HighID peer that endorsed it) in
every source record, and until one endorses it, `ember_publishing.rs`
deliberately publishes no source records at all: not the Library's and not
the feed lists' (`waiting_buddy`, and `proxy_allowance` of 0 for
`firewalled_like` without a named buddy).

The result, seen on 2026-11-02 with the feed "1233软件库": its head was found
(62 items, a 12 KB list), its publisher looked active in Discover, and the
list fetch gave up every hour with no source. A direct DHT lookup of the
list's source key had 14 nodes answer and none hold a record, while the same
lookup for one of our own lists found two sources. Nobody who is not the
publisher's friend can read such a feed, and its items could not be fetched
either if they could.

## What the user gets

- **Follower:** the file list of a feed whose publisher is online loads,
  even when the publisher could never be reached the usual way. Its items
  come over any path that reaches the publisher or another source. Nothing
  to set. When even this fails, the page keeps saying the publisher can't
  be reached.
- **Anyone browsing Discover:** a publisher that is online but can't share
  files is shown that way, not as simply "active".
- **Publisher:** My feeds warns when followers cannot fetch a feed (no
  buddy, so nothing placed), says why, and points to the Ember Network page,
  rather than the publisher believing the feed works.

## What must not change

- **Only holders of the feed link learn anything new.** Whatever a follower
  can look up is keyed by the feed's publisher key and salt, which only the
  link carries. Nobody can enumerate publishers or map a key to an address
  without the link.
- **No address a source record would not already give.** A follower learns
  the publisher's endpoint, which a firewalled source record already
  carries.
- **The server stays cheap and bounded.** The relay already caps sessions
  per network, bytes per session (256 MiB) and rate (1 MiB/s per network).
  Feed traffic gets its own budget, so a popular feed cannot crowd out
  friends' chats and transfers.
- **Trust rests on the head.** Everything fetched this way is checked
  against the signed head (size, eD2K, BLAKE3) and the item hashes the list
  names, exactly as now. A relay or a punched peer can withhold bytes, never
  substitute them.
- **1.7.x keeps working.** A 1.7.x publisher simply never registers. 1.8
  followers fall back to today's behaviour and today's message.

## Phases

### Phase 0: tell the publisher (small; could ship in a 1.7.x)

- Add `followers_cannot_fetch` to the own-feed info when the node is
  `firewalled_like`, has no named buddy, and owns a published feed. The flag
  comes from the same state `ember_dht_waiting_buddy` reports.
- My feeds shows a warning strip on each such feed: "Followers can't fetch
  this feed right now. Ember is waiting for another peer to relay for you."
  Link it to the Ember Network page.
- Log once per change of state, so a user's log says why their feed has no
  sources.
- Add a `can_share` bit to the Discover listing the publisher signs: set
  when it can place source records, or, once Phase 1 ships, when it is
  registered on the server. Discover then shows three states rather than
  two: "Online", "Online, but its files can't be fetched right now" (amber),
  and "Last seen …". Listings from 1.7.x carry no bit and show as they do
  today. Check `docs/channels-format.md` for how a listing takes a new field
  without 1.7.x storers refusing it.

### Phase 1: feed presence on the rendezvous server

- **Capability.** `BLAKE3("ember-feed-presence-v1" || publisher_key || salt
  || epoch)`, with the epoch rotated as `pairwise_capability_epoch` rotates
  friends' capabilities. Any link holder can compute it; nobody else can.
- **Publisher.** Register presence under each published feed's capability
  whenever Ember is online, whether or not it can place source records.
  Sign with the identity key, like `/v4/presence/register`. Cap it at 16
  feeds per identity, newest-published first.
- **Server.** First try reusing `/v4/presence/register` and `lookup`
  unchanged: they already store an endpoint under an opaque 32-byte
  capability with a signed, IP-bound proof. The open question is the
  per-identity cap: a publisher with many feeds registers one capability per
  feed. Raise or split that cap rather than add a route, if it suffices.
- **Follower.** When a list fetch has gone `FETCH_TIMEOUT` with no source,
  or on Retry while `unsourced`, look up the feed's capability. Accept only
  an entry whose proof is signed by the head's publisher key.

### Phase 2: connect and fetch

In order, stopping at the first that works:

1. **Direct, if the entry names a dialable endpoint.** Use the
   `feed_direct` QUIC stream, which already serves feed files to followers
   with `MAX_SERVES` and per-follower limits. Teach it to serve the list
   (it serves items today).
2. **Hole punch.** Use `/v4/punch/register` and `poll` keyed by the same
   capability. The publisher already polls punches for friends; add feed
   capabilities to what it polls, under a lower poll budget.
3. **Server relay, for the list only.** Offer through
   `/v4/relay-mailbox/offer` with a new purpose `feed-list`. The publisher
   accepts only for a list of its own feeds. The server closes the session
   past `MAX_LIST_BYTES` plus framing.

Items never go over the server relay. Without it they still have:
- the direct and punched paths above;
- peer relays (`network/ember/relay.rs`), where reachable Ember peers relay
  for firewalled ones;
- every source the download pipeline already asks: eD2K servers, KAD and
  Ember source records. Feed items are ordinary files by hash, and many
  have other sources.

An item with none of these shows the item's ordinary "no source yet" state.

Once a follower holds the list (and items), it publishes source records for
them, if it can, as it does today. The second follower usually finds them
there and never touches the publisher or the server. That is what keeps the
relay's load near one fetch per feed update rather than one per follower.

### Phase 3: why the publisher has no buddy

Separately from the fallback, find out why a publisher can sit with no buddy
for hours:

- Record on the Ember Network page how many endorsement asks went out, to
  whom, and how each ended (no answer, refused, endorsed but no ack).
- Check whether UDP to Ember peers works at all from the networks this shows
  up on (CGNAT, mainland China).
- If HighID Ember peers are scarce, weigh letting a publisher use any
  reachable follower of its own feeds as a buddy. A follower has a reason to
  keep the feed alive.

## Server cost

Feed presence entries are a few hundred bytes each: at most 16 per online
publisher. Lookups come only from followers whose fetch found no source.
Punch traffic is control messages only. The relay carries lists alone, so
one session is at most `MAX_LIST_BYTES`. Still, give it its own counters
(`feed_relay_bytes`), its own per-network cap, and a kill switch in the
server's config. Under load it refuses feed-list offers first, and followers
fall back to waiting.

Watch `/stats` after release for feed relay sessions, bytes, and refusals.
Size the Fly machine from that, not in advance.

## Testing

- Unit tests:
  - capability derivation (same inputs, same output; epoch rotation);
  - the follower accepts only entries signed by the head's publisher key;
  - the relay purpose's budget accounting.
- Two-node test: a publisher with source publishing forced off (no buddy)
  and a follower that must fetch the list over each path in turn: direct,
  punched, relayed.
- Server tests:
  - per-identity presence cap with many feeds;
  - the feed relay budget and kill switch;
  - a refused offer when over budget.
- Manual: a real firewalled publisher, at home or on a phone hotspot, and a
  follower elsewhere.

## Decisions

- **Publishers register feed presence always, not only while they cannot
  place source records.**
  - A buddy can drop at any moment, and source records already placed name
    it for up to their republish interval. "Can place records" therefore
    lags reality in exactly the cases this plan is for.
  - Registering always removes a state change that both ends would have to
    race over.
  - The cost is small: at most 16 entries of a few hundred bytes per online
    publisher.
  - It reveals nothing new: link holders could already learn the
    publisher's address from a source record, firewalled or not.
- **The server relay carries feed lists only, never items.**
  - A list is small, bounded by `MAX_LIST_BYTES`, and it is what turns a
    dead feed into a readable one.
  - Items are arbitrary files, often large: this feed was a software
    library. Relaying them would make Ember's server a distributor of
    whatever strangers publish, with the bandwidth bill and the abuse
    exposure that come with it.
  - Friends' transfers are different: private, between people who chose
    each other.
  - Items still have the direct and punched paths, peer relays, and every
    other source for their hash. A follower who gets one becomes a source
    for the next.
  - The cost is that a feed whose publisher is fully blocked can show
    items that never arrive. The item's "no source yet" state says so
    honestly, which is better than paying to remove that case.
- **Discover separates "online" from "files can be fetched", using a bit
  the publisher signs into its listing.**
  - Today "active" means "signed a listing lately". That is true, and it is
    what made this publisher look fine.
  - Probing every listing's list in the DHT would multiply Discover's
    lookups. The publisher already knows whether it can share, so it
    states it.
  - A publisher that lies only misleads people about its own feed, which
    it can already do by publishing nothing.
  - This ships in Phase 0, so the badge is honest before the fallback
    exists. Once Phase 1 is out, a registered publisher counts as able to
    share.

## As built (1.7.6)

All phases shipped together. Where the build differs from the plan above:

- **No server change.** Feed presence is registered as a sealed intro whose
  epoch key is derived from the feed (`derive_feed_presence_capability`), so
  the deployed server checks it like any sealed intro and keeps no
  per-identity count to raise. Punches and relay offers under an open-intro
  capability were already allowed for any registered identity.
- **No feed relay counters or kill switch on the server.** The relay purpose
  is inside the sealed envelope, so the server cannot tell feed relays from
  friends'. The bounds are on the publisher instead: 2 relayed list sessions
  at once, 2 minutes each, lists only; 6 feed punches answered a minute, 2
  from one follower. The
  server's existing relay caps still apply.
- **The fallback starts after 3 minutes without a source**, not after the
  30-minute `FETCH_TIMEOUT`, at most every 20 minutes per feed, and at once
  on Retry after a fetch that found no source.
- **Items:** a feed download with no source 90 seconds after it started,
  whose hold for its publisher has ended, punches the publisher (at most
  every 10 minutes per publisher) and streams from the punched address
  (`feed_direct::punched`). Items never use the server relay.
- **Phase 0's flag** is `OwnFeedInfo::reach` (`direct`, `server`, `none`,
  `unknown`), and the listing carries flag `0x02` (`FEED_LISTING_CANNOT_SHARE`)
  for `none`, sent again at most every 10 minutes when it changes. Discover
  keeps it in memory, not in its cache.
- **Phase 3** added two counters to the Ember Network page: buddy requests
  sent and buddies that agreed. A follower acting as its publisher's buddy
  was not built.

Not yet tried between two real NATs; the two-node test above is still to do.
