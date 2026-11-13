# Membership traffic through a one-hop relay

A design, not yet built: the plan item is section 2 of
[future-plan.md](future-plan.md). It settles the questions that item and
`archived-plans/post-1.7.5.md` item 1 left open, from what the 1.8.0 code
does.

## What it hides, and from whom

Today every private-room membership message and every feed lookup leaves the
member's own address, signed under its long-term DHT identity, on a Noise
session keyed by its long-term static key:

- **Presence.** Each private room's v2 presence record is stored again every
  10 minutes (`PRESENCE_REPUBLISH_SECS`) at up to 20 nodes nearest its key,
  after a lookup of the key, and members' records are fetched by FIND_VALUE
  walks, at most 2 a tick (`CHANNEL_PRESENCE_FETCH_PER_TICK`). A storer
  learns that this member is in some private room.
- **Key epochs.** A member behind on a room's key walks for its v2 epoch
  record every 60 seconds until found (`CHANNEL_EPOCH_FETCH_SECS`), and 6 hours
  after a miss. The record names the room, so the nodes answering learn which
  room the member is in. Owners store the records.
- **Feeds.** A follower looks each feed's head up every 30 minutes (every 3
  while it has never been found), so the nodes near a feed's key learn who
  follows it.

The relay hides the member from storers: they see the relay's address and a
key they have never seen. It does not hide the member from the relay, which
knows who it serves and which addresses it sends to; those are nodes near the
keys, so a relay that logs them can guess the keys. A member spreading its
rooms over several relays limits what any one learns. Content stays hidden
from everyone, as today.

## Design

**Relays.** A node on the release that builds this, reachable over UDP (not
firewalled by its own reachability check) and verified, offers the role with
a capability tag in the PING/PONG trailing block (`VERSION_RANGE_TAG` and
`UDP_REACH_TAG` are 0x01 and 0x02; this is 0x03). A member picks relays from
its verified contacts that carry the tag, outside its own /24 and each other's,
and prefers a friend when one qualifies, since a friend already knows its
address. The rendezvous server cannot be the relay: every member's traffic
from one address would trip each storer's per-address limits at once.

**Leases.** The member opens a lease over its ordinary session with the
relay, `RELAY_OPEN`, so the relay knows whom it serves and can bound it. The
relay answers with a lease id and binds a UDP socket of its own to the lease,
on an ephemeral port: everything the lease sends leaves from that port, and
whatever arrives there goes back to the member in `RELAY_DATA` frames. A
port per lease gives each lease its own address at the storers, whose Noise
sessions are keyed by address and static key, at most 4 to an address
(`MAX_SESSIONS_PER_ADDR`). `RELAY_CLOSE` ends a lease, and one idle for 5
minutes ends itself.

**End to end.** The member runs a second Ember transport with a throwaway
ed25519 identity and Noise key, and its datagrams travel inside `RELAY_DATA`,
so the Noise session runs between the throwaway key and the storer and the
relay sees only ciphertext and the address each datagram goes to. The
member's lookup and publish drivers (`IterativeSearch`, `drive_ember_publish`)
run unchanged on that transport: only where its datagrams are sent differs.
The relay runs no lookup on anyone's behalf.

**Lifetime.** One throwaway identity per room (presence and epochs) and per
feed (lookups), per lease, and a lease lives at most an hour. One identity
across a member's rooms would let storers near two rooms' keys tie them
together; one per message would cost a handshake at each of 20 storers every
10 minutes per room for nothing more. Records keep their own signers: a v2
presence record is signed by the member's pseudonym, so the per-publisher
caps (`MAX_RECORDS_PER_PUBLISHER_PER_KEY`) still bind by author and a
throwaway sender earns no budget of its own.

**Limits at the storers.** Storers of every build count per address: at most
8 storing identities a minute (`MAX_STORE_IDENTITIES_PER_ADDR`), 60 lookups in
10 seconds and 40 frames a second. Each lease port is its own address for
sessions but not for these, which go by IP. So a relay takes at most 4 leases
at once, and a lease at most 8 identities at once; at about one presence
store per room per 10 minutes, collisions at a single storer stay rare. A
relay's `ember_dht_store_addr_ceiling` on a test run is what confirms or
lowers those numbers before the role is on for everyone.

**Abuse.** A relay is not an open UDP forwarder. A lease sends only Ember
transport packets, only to the relay's own verified contacts or to addresses
it has relayed back in a FOUND_NODE answer during the lease, at most a few
frames a second and a few kilobytes a minute, which is several times what
membership traffic needs. A member may hold leases at no more than 3 relays.

**When no relay is there.** The member sends directly, as today, and counts
it (`ember_dht_membership_unrelayed` in Diagnostics), so a network short of
relays shows up. A setting to send membership traffic only through a relay,
holding it otherwise, can follow once relays are common.

## On the wire

Additive, as `PROXY_STORE` and the buddy messages were: an older build reads
the new types as `DhtPayload::Unknown` and ignores the capability tag, and
nothing frozen changes. Records, keys and storer rules stay as they are.

- `RELAY_OPEN` and its answer: the lease id, or a refusal with a reason (full,
  rate-limited).
- `RELAY_DATA`, both ways: the lease id, the address, and one transport
  datagram.
- `RELAY_CLOSE`.

## Tests

- A presence store, a presence fetch, an epoch lookup and a feed lookup leave
  through the lease under a throwaway identity, one per room or feed, and a new
  one with the next lease; nothing else (friend sessions, file search,
  publishing a library) does.
- A storer accepts and answers them as it does the member's own, and the
  per-publisher caps still bind by author.
- A relay refuses a fifth lease, a ninth identity, a target it has not seen,
  a datagram that is not Ember's, and traffic over the lease's rate, and ends
  an idle lease.
- With no relay, membership traffic goes direct and is counted.
- Live: two members of a private room behind relays, with the storers' logs
  showing only the relays' addresses.

## Left to measure

The lease and identity caps above, from a relay's counters on a test run, and
whether members should hold one relay per room or share a few across rooms.
