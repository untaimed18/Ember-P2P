# After 1.7.4: planned for 1.7.5

Written before 1.7.4 shipped, when its scope was settled: 1.7.4 is testing
and small fixes with no Channels format change, so it can be judged on its
own, and 1.7.5 is the release that freezes the Channels formats. Everything
in `docs/post-1.7.3.md` outside 1.7.4's list is here. If 1.7.4 does not
finish something on its list, move it here. Ordered by priority within each
section.

What 1.7.4 does is listed in `docs/post-1.7.3.md`. Two of its items feed this
plan: the decision on item 1 below (a kind 8 record), and the cross-machine
run in `docs/release-checklist-1.7.4.md`, which is the baseline item 5 is
measured against.

1.7.5 has done these so far, from user reports after 1.7.4 shipped:

- **Library sorting by all-time totals.** Requests, Accepted and Transferred
  sort by the all-time figure in brackets, with this session's breaking ties
  (`compareAllTime`). By the session alone nearly every file sorted as 0
  after a restart.
- **Updates through the system proxy.** Where GitHub's download hosts are
  blocked, as in mainland China, the update check failed with no way round
  it: the updater ignored proxies by design. It now goes through the HTTP or
  HTTPS proxy the OS or environment names for the address
  (`system_proxy_for`, Windows and macOS settings through hyper-util's
  `client-proxy-system`), and stays direct and DNS-pinned otherwise.
  Integrity is unchanged: the manifest and every installer are still checked
  against the signing key. Every other HTTP client in Ember stays direct.
- **Saying when the update server cannot be reached.** A connection, DNS or
  timeout failure now reads "Couldn't reach the update server. Check your
  connection or proxy and try again." (`updater_check_unreachable`, and
  `updater_install_unreachable` for the download), instead of "Secure update
  check failed", which users took for a certificate problem.
- **Downloads whose part files were removed wait Stopped.** Removing a
  download's `.part` and `.part.met` from `Temp` while Ember was closed got
  it started over from zero at the next launch, downloading everything again
  unasked; removing them is how eMule drops a download. When the recorded
  folder answered and no finished file turns up, the row is restored Stopped
  with no progress and reads "Stopped: part files removed"
  (`part_files_removed`). Resume starts it over, Cancel removes it. A folder
  that did not answer still holds its downloads, as before.
- **Discover keeps its rooms and their languages.** Discover's shard lookups
  share the background search pool, and once other work filled it they were
  refused and read as empty shards. Rooms only the DHT knew dropped out and
  every listing lost its language flag a few minutes after launch. Directory
  rows now start from the last signed listing's language, rooms cached under a
  shard that did not settle stay listed, and a refused shard is asked once
  more (`walk_index_shard`, `carry_forward_cached`).
- **Shared folders after a restore onto a new computer.** Approvals are tied
  to the volume and file IDs, so a restore onto a reinstalled Windows leaves
  every share unapproved. Re-approving a folder now starts the scan that lists
  its files (`scan_reapproved_folders`); before, the Library stayed empty
  until Reload. `reapprove_shared_folders` approves them all after one native
  dialog, and the Library says why it is empty instead of "No shared files"
  (GitHub #144).
- **Backups open after a Windows reinstall.** The exported `.emberbackup` took
  the current-user-only ACL Ember's own files get, which a reinstalled
  Windows (a new account SID under the same name) cannot open. It now takes
  the permissions of the folder it is saved to; an older, still-locked backup
  gets `backup_source_access_denied`, which says how to take ownership
  (GitHub #142).
- **A UI and accessibility pass.** Confirmations before taking over a room,
  removing a moderator, deleting a download category and closing a friend's
  file list mid-download; visible keyboard focus throughout; the Library
  table and the emoji grid as single tab stops; clickable Settings switch
  titles; busy labels; a shortcuts sheet that matches the bindings;
  locale-aware decimals (`formatDecimal`) and one file-name order
  (`compareFileNames`).
- **A member's language beside their name.** Settings > Channels has a
  language picker beside the Channel username, the same list rooms are
  marked with, and the member list shows it as a flag. Chosen rather than
  taken from the app language, which has 9 languages to the rooms' 37 and is
  not ours to publish unasked; none until picked, with a one-click
  suggestion from the app or system language (`suggestedChannelLanguage`).
  It rides the presence record: byte 67 of a public room's, the nickname
  pad's last byte inside a private room's seal, so storers never read it
  (`PRESENCE_LANGUAGE_AT`); older builds read none and are read as before.
  Only the member's own presence record sets or clears the roster's
  `channel_members.language`, added at open outside the numbered chain.
  Specified under [DHT channel records](channels-format.md#dht-channel-records).
  Tests: `a_members_language_rides_every_presence_form` (`publish.rs`),
  `a_sealed_presence_language_is_invisible_to_older_readers` (`channel.rs`),
  `presence_reads_v2_first_and_falls_back_to_v1` (`channel_membership.rs`),
  `channel_member_language_comes_only_from_presence` and
  `applying_a_handoff_twice_converges_on_the_same_state` (`database.rs`).
- **Still open from the update report:** a second download location for users
  with no proxy at all. It needs a host reachable from those networks, the
  release workflow uploading to it, a second manifest signed with the same
  key, and the updater trying it after GitHub. Planned separately in
  `docs/update-mirror-plan.md`, not scheduled.

## Channels: the format freeze

All nine items ship together in 1.7.5, and the formats freeze with them.
Items 1, 2, 7, 8 and 9 each change a wire or DHT format; items 2 and 9 each
need a transition in which old and new builds share a room, and doing them in
one release means one cut-over to test. Item 1 decides what the formats
freeze as, so it comes first.

### 1. Decide the future of the room settings snapshot

**Why:** The owner's signed governance snapshot (`CHANNEL_KIND_MODERATION`)
is a whole replacement, and its worst case is 1164 of the 1165 bytes a STORE
carries (`MODERATION_TAIL_MAX_LEN` and the budget comment in
`network/ember/dht/publish.rs`). It has one byte of slack. Any new room
setting either takes that byte or squeezes the pins.

**Decided in 1.7.4:** a second record, a "room settings" kind signed by the
room key under a key of its own, with a version byte and room to grow. The
moderation snapshot freezes as it is. The alternative, freezing the snapshot
and putting anything new in extension frames, was turned down because
extension frames are gossip only and not kept on the DHT, so a member who was
offline when a setting changed would never learn it.

**Done in 1.7.5:** `CHANNEL_KIND_SETTINGS` (8), signed by the room key under
`settings_key`, its `extra` a version byte then fields tagged by type and
length, which a reader skips when it does not know them. Storers check the
signer, the slot and the framing and keep unknown tags and versions; the TTL
is `CHANNEL_GOVERNANCE_TTL`. The owner publishes it whenever the commitments
it would carry differ from those it last published, compared as a list, so a
rotation taken back and minted again under the same epoch goes out too; right
after a rotation commits, again within 30 minutes, and every six hours
(`maybe_publish_channel_settings`); the first of a launch is confirmed within
30 minutes as well when it differs from the copy held. It reads a room's keys,
on the blocking pool, only when the room's key generation has moved or the
record is due, and signs nothing while a rotation of the room is in flight
(`RotatingRoom`) or from a read the generation moved under, so no record
commits to a key that is then taken back.
Members look it up on every third moderation pass, at once after a snapshot
naming a new key epoch, on every pass while they are behind and hold no
commitment to the epoch announced, and again after a lookup given up on; they
keep the newest copy. Either record arriving alone is applied on its own, and
absence is never a reset. Its first field is item 7's key commitment, its
second item 8's admission rule. Specified under
[Room settings (kind 8)](channels-format.md#room-settings-kind-8).

Tests: `the_newest_settings_record_is_held_and_absence_changes_nothing`,
`settings_ride_every_third_moderation_pass_of_a_room_this_device_reads`,
`a_pass_asks_for_settings_at_once_while_the_announced_epoch_is_uncommitted`,
`an_abandoned_settings_lookup_is_owed_again`,
`the_owner_publishes_on_a_change_then_confirms_then_republishes`,
`a_rotation_taken_back_and_minted_again_under_the_same_epoch_publishes_again`,
`an_uncommitted_rotation_never_reaches_a_published_commitment_list`
(`channel_membership.rs`);
`dropping_key_epochs_frees_their_slots_and_moves_the_key_generation`
(`database.rs`).

### 2. A second version of the chat message

**Why:** A chat line (`CHAT_PLAIN_VERSION`, 15) has a fixed layout. Replies,
mentions and attachments have each been fitted around it. A new message type
with optional fields (a version byte, then fields tagged by type and length
that a reader skips when it does not know them) would stop each new feature
needing a new number.

**Done in 1.7.5:** two extension kinds, 64 for a line and 65 for its
revision (`EXT_KIND_CHAT_LINE`, `EXT_KIND_CHAT_EDIT`), each an ordinary
extension frame, so the author's signature covers every field. The body is a
version byte (1) then fields tagged by type and length, framed as kind 8's
`extra` is (`tagged_fields`): tag 1 the line id, tag 2 the text with its emoji
joiners, tag 3 the reply parent in place of the tag-character trailer, and,
for a revision, tag 4 the original send time. Readers skip tags they do not
know and drop a malformed body, and a body whose two forms would not name the
same reply parent. Every line and revision is sent in both forms, and the pair
counts once against the author's rate (a credit keyed by the time both forms
sign and lasting five seconds), the sender's own limit and slow mode.
Receivers keep one row per line id, made by whichever form arrives first: a v2
frame after its legacy line replaces only the text, bringing the joiners back;
a legacy line after its v2 frame only gives the row its signature for
re-serving; the two are paired only when the legacy text is the v2 text
without joiners at the same signed time, and otherwise the first stands and
the second is not relayed. A v2 frame naming another author's line, or whose
text sanitising would change, is dropped. Revisions pair the same way. Catch-up
re-serves whichever forms are held. Specified under
[Chat v2](channels-format.md#chat-v2-kinds-64-and-65).

Decided while building it:

- **The v2 frame has a `msg_id` of its own, not the line's.** The plan said
  receivers keep the first frame under the line's `msg_id`. Every build drops
  a frame whose `msg_id` it has seen, so a 1.7.4 build that met a v2 frame
  under the line's id first would drop the legacy line as a duplicate and
  never show it. The v2 frame travels under a random id and names the line in
  its signed body, and the line id has to be bound to its author and time
  (`chat_msg_id_binds`), so a v2 frame can only ever name its own author's
  line.
- **No display flag during the transition.** Kinds 64 and 65 go out without
  `EXT_FLAG_DISPLAY`: 1.7.2–1.7.4 count displayable frames of kinds they
  cannot read as lines needing a newer Ember, and with the flag every line
  would raise the banner there although its legacy twin shows it.
- **1.8.0 stops sending 15 and 19,** the release that also stops publishing
  v1 membership records (item 9), so a room has one cut-over. It is one
  constant, `SEND_LEGACY_CHAT_FRAMES`, which also sets `EXT_FLAG_DISPLAY` on
  64 and 65 and lets a line's v2 frame take the line's id once there is no
  legacy frame to shadow. 1.8.0 still reads 15 and 19.

Tests: `a_v2_chat_body_round_trips_and_skips_unknown_fields`,
`a_v2_frame_never_shares_its_twins_id_or_asks_for_a_newer_ember`,
`a_reader_that_knows_only_the_legacy_line_still_shows_it`,
`every_field_of_a_v2_frame_is_under_its_authors_signature`,
`emoji_joiners_ride_the_v2_frame_and_the_two_texts_pair`,
`a_v2_body_is_refused_unless_both_forms_read_the_same_reply`,
`the_two_forms_of_a_line_count_once_against_its_author`,
`a_revision_does_not_spend_the_credit_of_the_line_it_revises`,
`a_twin_credit_is_bound_to_its_lines_time_and_expires` (`channel.rs`);
`a_v2_line_changed_by_sanitising_is_left_to_its_legacy_twin`,
`a_chat_frame_is_relayed_only_when_it_says_something_new`
(`channel_gossip.rs`);
`both_forms_of_a_line_store_one_line_in_either_order`,
`a_v2_line_naming_another_authors_line_or_disagreeing_with_its_twin_changes_nothing`,
`a_form_dated_otherwise_than_the_row_under_its_id_is_unpaired`,
`both_forms_of_a_revision_pair_in_either_order`,
`a_legacy_edit_at_time_zero_does_not_pair_with_an_unrevised_line`,
`a_v2_revision_pairs_with_one_an_older_build_applied_over_its_predecessor`,
`catch_up_offers_the_forms_of_a_line_this_device_holds`,
`the_v2_columns_come_at_open_and_the_schema_stays_at_62` (`database.rs`).

Known limits:

- Members on 1.7.4 charge both frames against the author's rate, so they see
  a 1.7.5 author capped at two lines a second rather than four. The legacy
  frame goes first, so it is the one they keep at the edge.
- Relay and catch-up budgets count frames, so while both forms go out each
  carries half as many lines: 8 relayed a second rather than 16, and as few
  as 20 lines in a catch-up reply rather than 40.
- An author can still send each build different words, the legacy line to
  one part of the room and the v2 frame to another. A 1.7.5 member keeps and
  passes on only the form that reached it first, so the second never spreads
  from there, but the members it reached first see it.
- Downgrading to 1.7.0–1.7.4 loses re-serving of some lines: those builds
  sign a re-served line over the stored text, which for a paired line with
  emoji joiners is the v2 text and not what the signature covers, so
  receivers reject it; and a row only a v2 revision changed has no edit
  signature for them to serve the revision with. Availability only: the lines
  stay readable on that device.
- The pairing, relay and rate rules are tested where they are decided (the
  storage calls, `chat_author_allow`, `kept_chat_form` and
  `ChatLineIngest::relays`); the gossip handler that strings them together
  has no test harness, and is left to the cross-machine run (item 5).

### 3. "Needs a newer Ember" for the two envelopes still silent

**Done in 1.7.4:** unknown outer gossip (`CHANNEL_MSG_VERSION`) and relay
(`CHANNEL_RELAY_ENVELOPE_VERSION`) envelope versions are counted per room in
`channel_newer_frames` (sources `envelope` and `relay`) and show the existing
banner, from hops on the room's roster only (`note_unread_channel_envelope`).
Every future version must keep the version at byte 0 and the room id at bytes
1 to 17, which is what the count reads.

**Decided in 1.7.5: an unknown outer version is not relayed, and is not
going to be.** Members forward only frames that open
(`handle_inbound_channel_relay`), which is what stops a hop using them to
spread junk; an unknown version cannot open, and an announcement in a signed
field would not change that, since the frame itself still could not be
checked. So a later gossip or relay envelope version is introduced the way
item 2 introduced chat v2: sent beside a v1 envelope carrying the same
content for as long as builds that read only v1 are in the room, then on its
own. Until then the banner (above) is all an older member sees of it.

### 4. A short format spec

**Done in 1.7.4:** `docs/channels-format.md`. **Marked in 1.7.5:** its
"What freezes at the end of the beta" section lists everything frozen with
this release, items 1, 2, 3, 7, 8 and 9 included, and says that nothing is
left open and what 1.8.0 changes.

### 5. Test across real machines

**Written in 1.7.5:** `docs/release-checklist-1.7.5.md`, from 1.7.4's, with
what this section changed; it is still to be run before tagging.

1.7.4 runs `docs/release-checklist-1.7.4.md` section 1 on today's formats.
For 1.7.5, write `docs/release-checklist-1.7.5.md` from it and run it on
three or more machines, at least one behind a firewall that is not
reachable, adding what this section changes:

- Chat and edits in the new frame (item 2) between 1.7.5 machines, and with a
  1.7.4 machine in the same room during the transition: one line per
  `msg_id` everywhere, emoji joiners kept between 1.7.5 machines.
- The room settings record (item 1), if it is added: a setting change reaches
  every member, and a member that gets only one of the two records behaves as
  the rule says.
- A member behind a private room's key gets back in from a fresh invite
  (item 7), and a crafted invite with the wrong key is refused.
- A line an evicted member wrote, re-served by a lagging member, does not put
  the evicted identity back on the roster (item 8).
- Private rooms still find their presence and key records after item 9's
  cut-over and the rotation it brings, and a 1.7.4 member in the same room
  still reads it for as long as the transition promises.

### 6. Release with the formats frozen and the badge still on

Ship 1.7.5 with items 1 to 4 and 7 to 9 done and the formats frozen. If 1.7.6
needs no format change, remove the BETA badge in 1.7.6.

**Ready in code:** items 1 to 4 and 7 to 9 are done. What is left before
tagging is item 5's cross-machine run, the translation review the checklist
lists, and the release itself.

### 7. A way back in for a member behind a private room's key

**Why:** A member who falls behind past the retained epochs, or whose sealed
key record lapsed, is stuck until they leave and rejoin. 1.7.3 briefly took
the key from a fresh invite for a room already held, and backed it out: an
invite is unauthenticated, nothing signed commits to an epoch's key, and the
store keeps the first key it is given for an epoch, so a crafted invite would
have the device seal under a key its author reads and refuse the genuine one
later.

**Done in 1.7.5:** the room settings record (item 1) carries, as tag 1, the
owner's commitment to the content key of each epoch it keeps
(`key_commitment`). `join_channel` takes an invite's key for a private room
already held only when this device is behind the room's key (by the owner's
announcement, or by the invite naming an epoch past the newest it holds), the
invite names an epoch above 0, and the newest settings record held names that
epoch with a matching commitment (`committed_key_epoch`, `take_offered_key`);
the key is then stored and the room entered as before. A first join is
unchanged.

Built around that check:

- **Pending invites.** A device whose view of the room is stale at join time
  (it left the room, so stopped looking up its records; it has just launched;
  or its lookup fell between a rotation's kind 3 and its kind 8) has nothing
  to check a genuine invite against. An invite naming an epoch at or past the
  newest held, whose key is not already held for it, is kept in memory, never
  on disk, for 30 minutes and at most 16 at once (`PendingInviteKeys`); both
  records are looked up at once, and the check runs again after each kind 3 or
  kind 8 lookup for the room, taking the key once it passes. Members also look
  kind 8 up on every moderation pass while they are behind and hold no
  commitment to the epoch announced, and again after a lookup given up on.
- **Publish on rotation.** The owner publishes kind 8 right after a rotation
  commits rather than on the next tick, and republishes whenever its
  commitment list changes, not only its epoch number. A rotation's sealed key
  records go out only after its snapshot commits, so a rotation taken back
  hands its key to nobody, and its snapshot is checked for size before the
  key is stored. No kind 8 is signed while the rotation is in flight, so none
  commits to it either.
- **Keys the commitments contradict.** After each newly held kind 8, and
  after a kind 3 lookup that applies the room's first snapshot or raises the
  announced epoch, a member drops any held key its commitments contradict
  (named under another commitment, or, once a snapshot has been applied,
  past every epoch the owner has announced or committed to), which is what a
  crafted first-join invite leaves behind. Before the first snapshot a
  genuine first-join key could be judged against a kind 8 from before its
  rotation, so the second rule waits for one. A drop deletes a key only if
  the row still holds the secret judged, in the same transaction, so two
  settles that interleave never delete the genuine key one of them stored.
  The room falls back to the newest key it still holds and is behind again;
  the genuine key then comes from an invite that checks or from the owner's
  sealed record, and the dropped key waits in memory in case a later record
  vouches for it. A join that drops or takes a key clears the room's epoch
  fetch stamp and redraws it, as an ingest does.

Specified under
[Room settings (kind 8)](channels-format.md#fields-in-version-1).

Tests: `an_invite_key_is_taken_for_a_held_room_only_against_the_owners_commitment`
(`commands/channels.rs`);
`an_invite_this_device_could_not_check_is_taken_once_the_owners_records_catch_up`,
`pending_invite_keys_lapse_and_are_bounded`,
`a_held_key_the_owners_commitments_contradict_gives_way_to_the_genuine_one`,
`a_first_joins_key_survives_a_settings_record_ingested_before_the_first_snapshot`,
`a_settle_judging_on_an_older_read_never_drops_the_key_that_replaced_it`
(`channel_membership.rs`);
`dropping_key_epochs_frees_their_slots_and_moves_the_key_generation`
(`database.rs`).

Known limits:

- Epoch 0, the secret a private room was created with, has no commitment, so
  a crafted first-join invite to a room that has never rotated cannot be told
  from a genuine one; the member stays stuck until they forget the room and
  join again from a genuine invite, as before 1.7.5.
- A first join whose newest reachable kind 3 and kind 8 both predate the
  rotation to the invite's epoch drops the genuine key as past everything
  announced. It waits in memory for 30 minutes for a kind 8 naming it;
  after that the room is behind until the owner's renewal of its sealed
  record reaches the member. Sparing keys equal to the join secret would not
  help: every first-join key is the join secret, crafted ones included.
- A pending invite lives only as long as the app: one pasted just before
  quitting has to be pasted again.

### 8. An authenticated marker on catch-up re-serves

**Why:** A catch-up reply is re-sealed by the responder under its current key
and sent at TTL 1, and TTL is the only thing marking it as not the author's own
seal. TTL is outside the AEAD, so a relay can raise it. That gets a line an
evicted member wrote, stored by a lagging member and later re-served, read as
live under the current key, which puts the evicted identity's new key on the
owner's roster and has the next epoch sealed to it. 1.7.3 narrowed it by also
requiring the line to be recent (`chat_author_joins_gossip_roster`), and did
not drop chat-based admission altogether because members on builds without
key-proven beacons are admitted only that way.

**Done in 1.7.5,** by the second way: the room settings record (item 1)
carries, as tag 2, how a private room admits a member its roster does not
hold, and the gossip envelope and its seal do not change. An owner on 1.7.5
writes 1 for every private room it owns, so a room that never rotated now
publishes kind 8 too, and applies 1 to its own rooms from launch. A member
keeps the byte with the record it holds (`channel_settings.admission`) and,
under 1, `chat_author_joins_gossip_roster` admits nobody; a line from a member
already on the roster still refreshes them. The chat handler reaches it
through one site (`chat_line_admits_author`), which reads the room's private
and owner flags from its row. Newcomers are then admitted only
by a beacon carrying their own proof of the current key, or by a DHT presence
record that opens under it, which is how a newcomer and the room find each
other at all. Absent, 0, or no record held is the rule before 1.7.5; any value
above 1 reads as 1, so a later build may only use one for a stricter rule.
Every path that adds to a private room's roster, and what 1 does to each, is
listed under
[Admission](channels-format.md#admission-item-8).

Tests: `the_held_settings_record_decides_whether_a_chat_line_admits`
(`channel_membership.rs`);
`a_chat_line_admits_its_author_only_where_the_room_allows_it`,
`chat_authors_reach_the_roster_through_one_admission_site`
(`channel_gossip.rs`).

Known limits:

- Members on builds that send no key-proven beacons (before 1.7.0: key proofs
  were first sent by `bd66781c`, in 1.7.0) are no longer admitted through
  their chat lines by 1.7.5 members in a room whose owner runs 1.7.5. They are
  not shut out: every build since 1.6.0 seals its presence record under the
  current epoch, so they reach rosters on the presence walk, within five
  minutes, rather than at their first line. Existing roster entries are kept.
- A private presence record's seal names the room but not the member, so a
  storer holding a current member's record could copy the sealed part into a
  record it signs itself and be read as holding the current key. A lagging
  member's re-serve does not give anyone that. Item 9's v2 record closes it;
  v1 records, which 1.7.4 members publish, are still read and still have it.

### 9. Keep private-room membership out of the DHT

**Why:** A private room's presence record is stored under a key blinded with
the join secret, but its body carries the room id and the member's long-term
public key in the clear, so every storing node learns the roster. Key-epoch
records are worse: `epoch_key(channel_id, member_pubkey, epoch)` is built
from public values, so anyone who knows the room id (it is in every gossip
header) can test whether a given key is a member.

**Done in 1.7.5,** both ways at once, as a second form of each record.
A private room's presence record v2 is signed by a pseudonym derived from the
member's seed, the room and the join secret (`presence_pseudonym`), and
carries a room-blind key derived from the room and the join secret
(`presence_room_blind`) where v1 carries the room id and pubkey, so the
record names neither who nor which room. Its seal (version 2, 234 bytes)
carries the member's own key and the member's signature binding it to the
pseudonym, the presence epoch, the leave flag and the stamp, with the
pseudonym in the AAD, so a seal copied into another key's record no longer
opens and one re-sealed for another pseudonym by a content-key holder fails
the binding, which closes item 8's limit for v2. A reader drops a v2 record
whose binding fails. A key-epoch record v2 is flagged `CHANNEL_FLAG_BLINDED`
(`0x04`) and carries a blinded member id where v1 has the member's key: the
id derives from a blind (`epoch_blind`) taken from the owner–member pairwise
secret, the static DH the envelope's wrapping key already uses, under a
purpose of its own and without the epoch, and the record is filed under
`epoch_key_v2(channel_id, member_id, E)`. So a member computes its record's
key for any epoch from the owner's key alone, whatever it missed, and a
storer recomputes the key from the record and refuses a misfiled one, as for
v1. Storers on 1.7.5 keep v2 presence on its length. The transition: this
build publishes both forms and reads v2 first, falling back to v1, and 1.8.0,
the release that stops sending the old chat frames (item 2), stops publishing
v1 (`PUBLISH_V1_MEMBERSHIP_RECORDS`) except the owner's own key copy, and
rotates every private room once as it does (`V1_CUT_OVER_ROTATES`; not built
yet, and v1 cannot be turned off until it is). Specified under
[Private membership records, v2](channels-format.md#private-membership-records-v2-item-9).

**Changed before the freeze, after an audit.** The first build blinded epoch
`E`'s records with epoch `E - 1`'s join secret. A member whose copy of a
rotation was never published could not open the renewal, since it was
blinded with a secret they never got; an unban's re-seal after two or more
rotations was blinded with one the member had been left out of; the forward
walk this needed could pick the wrong epoch; and storers kept a flagged
record under any key for 30 days. All of these mattered more once v1 stops.
The pairwise blind removed the walk and the previous-epoch plumbing, and made
the key storer-checkable.

Tests: `a_v2_presence_record_round_trips_and_names_only_the_member_inside_the_seal`,
`a_v2_seal_copied_into_a_record_another_pseudonym_signs_fails_the_binding`,
`storers_keep_v2_presence_and_blinded_epoch_records_and_refuse_malformed_ones`,
`both_forms_of_private_membership_records_are_published` (`publish.rs`);
`the_room_blind_key_satisfies_the_storer_rule_and_hides_the_room`,
`the_v2_epoch_blind_is_pairwise_and_the_key_is_recomputable_from_the_record`
(`channel.rs`); `presence_reads_v2_first_and_falls_back_to_v1`,
`a_member_several_epochs_behind_finds_its_current_v2_record_directly`,
`a_missed_rotation_and_an_unban_after_several_rotations_both_open_the_current_record`,
`epoch_records_read_v2_first_and_only_where_they_are_filed`
(`channel_membership.rs`).

Known limits:

- **Storers still learn the member from the transport.** Every DHT STORE and
  lookup is signed under the sender's long-term DHT identity
  (`identity.ed25519_secret_key`, `sender_id = BLAKE3(pubkey)`), the key the
  member is known by in its rooms. A v2 presence record goes straight from
  the member to its storers, and key-epoch lookups come from the member. So
  v2 hides the room from storers, not the member: a storer sees which member
  stores or asks for which key, and so which pseudonym, room-blind key and
  blinded member id are theirs, though not which room those belong to. The
  fix is transport behaviour, not a format, and is planned in
  `docs/post-1.7.5.md` item 1.
- v1 still leaks until 1.8.0: both forms are published, and a v1 record
  already stored lives out its TTL (45 minutes for presence, 30 days for a
  key epoch). A 1.7.4 member's records are v1 only for as long as they run
  1.7.4.
- **The transition links the v2 ids to the v1 ones.** A member's two presence
  copies sit under one presence key with the same stamp and flags, so a
  storer keeping a table links the pseudonym and room-blind key to the member
  and the room, and those change only with the join secret. That is why the
  1.8.0 cut-over rotates every private room once: owners do it when they stop
  publishing v1, so the v2 ids after it are unlinkable to the transition's,
  as far as the records go (the transport limit above still stands).
- Storers on 1.7.4 keep neither v2 form, so until the network updates, v2
  lives on fewer nodes, as kinds 7 and 8 do. A 1.7.5 reader still finds the
  v1 copy on every storer.
- Anyone holding the current join secret, every member, can read who is
  present, as in v1. A former member can no longer test whether some key was
  resealed to: the blind is per member, so it holds only its own.
- The room-blind key and the pseudonym hold while the join secret does, so a
  storer can link a room's presence records, and one pseudonym's, across
  15-minute epochs until the next rotation. A member's blinded id differs in
  every epoch (the epoch is hashed into it), so once v1 stops, key records
  cannot be linked across rotations. Until then they can: each v2 key record
  goes out beside a v1 copy stamped the same second with the same envelope,
  and the v1 copy names the member, whose `epoch_key` anyone who knows the
  room can still compute and test. Being per epoch, the ids need no cut-over
  rotation of their own; the first epoch after v1 stops starts unlinked. A v2
  key record's header still names the room, so the number of them hints at
  the roster's size.
- The owner renews only the current epoch's key records, so an intermediate
  epoch's records lapse 30 days after its rotation, and the history sealed
  under one stays unreadable to a member who missed it by then. The current
  key is never cut off by this: it is looked up first and renewed. Renewing
  every retained epoch would close it, at four times the key-record traffic,
  and is left to decide with 1.8.0.
- A leave counts as landed when either form stored, so a v2-only landing
  leaves a 1.7.4 reader showing the member until the live record ages out.

**With it: not done.** Key-epoch records still go to our own table's closest
nodes, reusing a lookup already cached but never queuing one
(`own_record_target_queue_limit`). It does not fit the publish-target
machinery as it stands. Each member's key is its own hash, in v2 as in v1 (a
storer keeps one record per key, publisher and `file_hash`, and a room's key
records share both), so there is no room neighbourhood to resolve once. A
looked-up set lives `EMBER_PUBLISH_TARGETS_TTL_SECS` (4 hours) and the owner
renews key records every `MODERATION_REPUBLISH_SECS` (6 hours), so a lookup
queued by one renewal has lapsed by the next. Holding a publish until its
lookup lands (`ember_publish_awaits_lookup`) suits library records, which stay
due tick to tick, not records published in one pass on a rotation or a
renewal. Doing it needs a key-record schedule of its own that queues a
bounded share of lookups and publishes each member's records once its set
lands.

## Channels: smaller follow-ups

- **Relayed catch-up replies do not move the frontier.** Progress is credited
  only to the neighbor asked, when its reply reaches us directly; a reply
  carried by another member hop cannot be told from that member's own TTL-1
  line. Such a neighbor is asked the same range again next round, which costs
  bandwidth but loses nothing. Planned with item 8's marker, but item 8 was
  done without one (admission, not a marker), so this stays open: it needs a
  marker of its own that says a reply was relayed.
- **Room transfer key derivation. Done in 1.7.5:** an inbound transfer frame
  is checked under the key its transfer derived at setup
  (`xfer_frame_key`, from `xfer_recv`, `xfer_send` or `xfer_pending` when the
  room and peer match), so only an offer for a transfer not held yet pays the
  DH. 1.7.4 moved the disk-work half off the network task.
- **Moderation lock and the registry.** Releasing `MODERATION_LOCK` across
  Rendezvous round-trips means two racing owner commands can briefly leave the
  registry on the older value until the next republish. Left as it is in
  1.7.5: it corrects itself within a republish, and holding the lock across
  the round-trip is what froze moderation in every other room before 1.7.4.
- **Bans stored before 1.7.3 are not known to be the owner's** until the
  owner's next republish (about six hours), so a moderator could lift one in
  that window. It matters less with each release, since it applies only to
  bans no owner has republished since 1.7.3. Left as it is in 1.7.5.

## Friends: offers that wait for the friend, the receiving half

1.7.3 queues a sent file until the friend can be reached. An inbound offer
still lapsed after five minutes unanswered (`ATTACH_OFFER_TTL_SECS`), so a
friend at their desk but away from it still missed a file over the
auto-accept ceiling.

**Done in 1.7.5:** a new friend-session sub-type, `EMBER_EXT_ATTACH_WAITS`
(`0x12`), in two forms, and the two ends agree per offer, each waiting past
five minutes only on the other's word:

- **Empty, either way.** Each side sends it when a secure session comes up
  (`chat_attach::on_friend_session`), ahead of the files queued for the
  friend, and a sender sends it again when one of the friend's sessions ended
  while the session map still routes through another live one and it let
  held offers go. The reader marks the session (`mark_holds_offers`, spread
  to the friend's other live sessions like the friends-only mark). On
  receiving it, a receiver first settles every offer that lapsed here, then
  puts every offer from that friend the friend had said it holds back on five
  minutes from then, and names every offer of theirs still waiting on the
  user that the friend does not hold, including ones that came before any of
  their sessions said it waits (`on_friend_waits`).
- **`ATTACH_VERSION || xfer_id`, receiver to sender:** "I am keeping your
  offer for my user" (`encode_attach_held`, `hold_for_user`,
  `name_held_offer`). Sent when an offer is left waiting on the user, only to
  a marked session, and again when the friend's empty form arrives or a
  session with them ends while the map still routes through another; never
  for an offer that lapsed. The offer still lapses at five minutes here until
  the sender answers. A note, or an empty form, that found the session's
  queue full is sent again on the next half-minute ticks, up to four
  (`retry_owed_holds`, `OWED_HOLD_TRIES`); after that the next session's
  empty form starts the round again.
- **The same 17 bytes, sender to receiver:** the echo, "I hold it". Only the
  echo moves the receiver's wait to `HELD_OFFER_WAIT_SECS` (a day from the
  offer's arrival, `confirm_held`). Which of the two a named note is follows
  from which end of the offer the reader is on.

The sender holds the grant only on the receiver's note (`on_held`,
`answer_hold_note`, `hold_chat_attachment_offer`), recording `held_at`:
the first time only while the offer is still `offered` and on its five
minutes, until `HELD_OFFER_GRANT_SECS` (a day and five minutes) after that
first note, so an accept sent at the receiver's last moment still finds it.
A repeat while held moves nothing and is echoed again. A sender that will
not hold an offer that is still answerable (a "Try again" re-offer that went
out `accepted`, say) does not echo, and the receiver stays on five minutes; a
sender whose offer is over answers with `AttachCancel` (`SourceGone` for a
file that went, `User` otherwise), so the card stops waiting on it. The
session flag alone was not enough: queued files go out the moment a session
comes up, before the friend's flag can arrive.

An offer the friend's "Try again" reopened is never held: it goes back on an
offer's lifetime with its hold spent (`reopen_chat_attachment_for_friend`,
`held_at` 0 and released), since a hold from the retry would run past the
day the user's own send had, and a shorter one would leave the friend's side
waiting longer than the grant. Our own user's offering again
(`reopen_chat_attachment`) clears both columns and may be held afresh. A held
offer that ended before anyone accepted it is not mistaken for a row from
before grants were recorded, whose expiry also moved past the offer's: a
friend's retry reopens it as `offered`, not `accepted`
(`friend_retry_reopens`, `chat_attachment_was_held`).

**Sessions ending.** Each end decides independently that a session ended, so
neither keeps a hold across one. When any secure session with the friend
ends — the one the session map routes through, one it retired, or a
duplicate that never held the map's slot — the sender releases its holds
back to five minutes from then and marks them released (`on_session_ended`,
`release_held_chat_attachment_offers`, `hold_released`), and the receiver
puts every echoed offer back on five minutes from then. A duplicate is what
each end of a crossed pair of dials reads the friend's frames on; its end
reaches the loop as `EmberFriendSessionEnded`, which only does this and
neither marks the friend offline nor redials (`session_end_event`). Each
names or asks again over the session the map still routes through, or over
the next one once its empty form arrives. A duplicate is not moved into the
slot when the owner ends first: the owner's end redials, and the new
session's empty form starts the round again. A release allows one re-hold,
only while the offer is still in date, and only back to where the first hold
ended, never past it; the echo gives the receiver back no more than a day
from the offer's arrival. So a sleep or a redial that the two ends see in
either order ends with both holding the offer, and with no session back
within five minutes both let it go. The accept dials the address of the
session it goes out on, not of the one the offer came in on
(`session_peer_addr`); while that session is relayed the accept is refused
as `peers_attach_relayed` and the offer keeps waiting (`accept_dial`).
Startup releases every held offer (`sweep_interrupted`). `held_at` and
`hold_released` are added to `chat_attachments` at open, outside the numbered
chain, so the schema stays at 62 and 1.7.0 still opens the database.

An offer never named, which is every offer to or from 1.7.4, lapses at five
minutes on both ends as before: 1.7.4 sends neither form, so its sessions are
never marked and nothing is named to it, and it never names one to us. The
attachment expiry sweep moved from the hourly block to the half-minute tick,
so an unanswered offer's card reads "did not answer in time" within half a
minute of lapsing rather than up to an hour later; deleting settled rows past
retention (`prune_settled_chat_attachments`) stays hourly.

The file moving first: the sender starts watching the file of a held offer
when its hold starts or resumes (a note on a standing hold starts nothing)
and looks again every half-minute (`check_held_sources`,
`attach_stream::check_held_source`). Each look runs on the blocking pool, one
at a time per offer, and posts its result back to the loop
(`attach_held_tx`, `apply_held_look`), so a file on a share that is asleep
never holds up the network task; the watch stays in place while a look runs,
so one that fails leaves it watched. An unmoved stamp settles it without a
read. A moved one, and the first look, are decided by the tree for the file
as it is now against the offered root: the hash cache's, when it still has
one for the file as it is (the file is hashed into it when offered,
`hash_for_serving`, so a first look at a file that has not moved since reads
nothing unless the tree aged out), and otherwise one read on the blocking pool
(`prewarm_attachment_hash`). So a same-size edit between the offer and the
first look is caught and a touched file is not taken for a changed one. Only
a file that is not there, a different size or a different tree is gone; any
other failure to open it is looked at again on the next tick. One look that
finds it gone settles nothing: some of a day's looks catch a save midway
through deleting and renaming, or truncating and writing, so it takes two
settling looks in a row, a tick apart (`note_held_look`, `HeldWatch`). A gone
file then settles the row as `source_gone` only while it is still `offered`
(an accepted one is left to its stream) and sends `AttachCancel::SourceGone`,
which now settles a waiting offer as `source_gone` rather than `cancelled`
(`cancelled_as`). The card says so before Accept is pressed, and an Accept on
it is answered `peers_attach_source_gone` from the row, with no dial
(`why_unanswerable`). A rewrite the stamp cannot see, or one in the minute
before the second look, still ends as `source_gone` on the stream.

Tests: `an_offer_answered_after_an_hour_still_transfers`,
`an_offer_answered_after_the_wait_fails_cleanly_on_both_ends`,
`offers_to_and_from_a_build_that_never_said_it_waits_lapse_at_five_minutes`,
`a_held_offer_survives_a_session_replacement_with_both_ends_agreeing`,
`a_duplicate_sessions_end_puts_both_ends_of_a_crossed_pair_back_in_step`,
`a_held_offer_whose_session_stays_gone_lapses_on_both_ends`,
`a_lapsed_offer_is_settled_rather_than_named_again`,
`a_note_or_empty_form_that_found_no_room_is_sent_again_a_few_times`,
`an_offer_that_came_before_the_senders_empty_form_is_named_by_it`,
`an_accept_over_a_relayed_session_keeps_the_offer_waiting`,
`a_held_but_unanswered_offer_reopens_as_offered_on_a_friends_retry`,
`a_refused_hold_leaves_the_receiver_on_five_minutes`,
`repeated_notes_never_extend_a_hold`,
`an_accept_after_the_file_changed_says_source_gone_without_dialing`,
`a_held_look_that_settles_nothing_keeps_the_offer_watched`,
`one_look_caught_mid_save_does_not_settle_a_held_offer`
(`chat_attach.rs`); `an_offer_is_held_once_and_released_with_its_session`
and `a_database_from_before_held_offers_gets_both_columns_at_open`
(`database.rs`); `the_first_look_at_a_held_source_compares_it_with_the_offer`
and `a_held_source_that_cannot_be_opened_is_gone_only_when_missing`
(`attach_stream.rs`); `a_duplicate_secure_sessions_end_reaches_the_loop`
(`upload.rs`) and `a_duplicates_end_finds_the_session_that_still_routes`
(`upload_event.rs`), with the session-mark rule beside its own code. The
async wrappers (`on_session_ended`, `on_friend_waits`, `retry_owed_holds`)
only read the session map and call what these drive; a Standing note starting
no look is not under test.

**Still open:** saving waiting offers across a restart, which needs
`AttachOffer`'s fields and the hold on both ends, not just the `awaiting`
row.

**Decided when 1.7.4's scope was set:**

- **Session only, first.** The receiver keeps a pending offer in memory
  (`state.attach_inbound`) until the user answers, it lapses (five minutes
  after a session ends unless the sender confirms it again), or
  `ATTACH_GRANT_TTL_SECS` (a day) passes. A restart still lapses it. Saving
  offers across restarts (it needs `AttachOffer`'s fields, not just the
  `awaiting` row) can follow later.
- **A capability signal of its own,** sent when the session comes up, not
  `EMBER_EXT_MAILBOX_AWARE`. 1.7.4 sends that flag and still drops offers at
  `ATTACH_OFFER_TTL_SECS`, so it cannot prove a receiver waits. The sender
  holds its grant past `ATTACH_OFFER_TTL_SECS` only for a session that sent
  the new signal; for anyone else, offers lapse as they do today.
- **The file moving first.** An accept after the file changed already ends as
  `source_gone` on the stream. The card should say so when the accept is
  pressed rather than after a dial.

**Tests:** an offer answered after an hour still transfers; one answered after
the grant lapses fails cleanly on both ends; a 1.7.4 receiver's offer still
lapses at five minutes and the sender's card says so; an accept after the
file changed says "source gone" without dialing.

## Later: not needed for the freeze

Not planned for 1.7.5. Take them on if there is room, or when real use says
they matter.

- **Private-room membership traffic under a throwaway DHT identity.** Item 9's
  v2 records name neither the room nor the member, but every STORE and lookup
  that carries them is signed under the member's long-term DHT identity, so
  storers still learn the member (see item 9's known limits). Moved to
  `docs/post-1.7.5.md` item 1, which plans it.
- **An Away status.** An "Away" or "Not at PC" state, set by hand and by idle
  time, sent as a new friend-session extension frame (older builds ignore
  unknown ones), shown in the friends list and the chat header.
- **No component tests** for the 1.7.3 changes to `ChatConversation.svelte`
  and the Channels page (early delivery, pin cleanup, slow-mode announcements,
  coalesced refreshes); only the store logic is unit tested. A component
  harness would cover them.
- **Discover spam folding.** Member counts come from presence records, which
  anyone can sign; friends in the room, or the listing's age, would be better
  signals. Tune `LIKELY_SPAM_SCORE` and `DUPLICATE_NAME_FLOOD` from real use.
- **Friends, smaller:**
  - The pop-out chat window runs its own copy of the friends store, so the
    shared offer-accept lock does not reach it; the backend's
    `already_queued` answer covers the double accept.
  - Unread counts on startup can still miss one message if messages arrive
    during both seed fetches; the backend returning the newest message id
    with each count would make them exact.
  - Derive the Friends page's firewall state from `$networkStats` instead of
    its own fetch and listener, and reuse `friendsList` in the layout instead
    of a second `getFriends`.
  - The hash-probe exemption trusts a claimed user hash. A request under a
    mutual friend's eD2K user hash is not counted toward the probe ban, so
    someone spoofing that hash can probe without being banned (the answers
    are the same either way). Matching the friend's live session address
    would close it.

## Known limits

Carried unchanged. Not beta blockers, but they belong in the format spec and
the release notes.

### Friends, from the 1.7.3 audit

- **Idle sessions with a pre-1.7.3 friend still drop.** The fix paces each
  side's keepalive off its own writes; an older build still resets its timer
  on inbound traffic, so on an idle link it rarely sends and our reader hits
  the 180-second record timeout. Fully fixed once both ends run 1.7.3.
- **Friends on 1.7.0 to 1.7.2 no longer see our friends-only files in
  Browse.** They honour the scope marking but do not send
  `EMBER_EXT_BROWSE_SCOPE_AWARE`, and a friend session carries nothing else
  that tells them from 1.6.x, which would republish the files. Kept that way
  on purpose, since a leak cannot be taken back and the gap closes as friends
  update.
- **Friends-only offers to 1.7.3 friends.** `OfferFileToFriend` refuses a
  friends-only file unless the session has shown it honours the marking
  (`EmberSessionHandle::honours_friends_only`). A 1.7.3 friend counts only
  once they have browsed us in that session, since 1.7.3 sends the scope
  frame only then.

### Owned-room recovery

- **One identity on two devices at once.** Each device publishes its own
  owned-rooms list and the newer one wins, so the other device's rooms stay
  recoverable only until its next publish. A fix would read the network's
  list before every publish and merge it.
- **A taken-over private room lost before its first rotation.** Recovery
  derives the wrong key and nothing is pending to correct it. Sealing epoch 0
  to ourselves for rooms we did not create would close the gap.
- **Old backups keep rooms deleted since.** A room key signature on the
  deletion, served by the registry, would let it be trusted.
- **The list shows how many rooms an identity owns.** Padding it to a fixed
  size would hide that.
- **Older builds don't store record kind 7.** Absence is only concluded after
  four nodes have answered (`MIN_RESPONDERS_FOR_ABSENCE`).
- **Recovery has no end-to-end test**; item 5's restore run is the only cover
  for the network flow.

### From the 1.7.2 audit

- **A claim the owner meets on its way back.** An owner back from a claimable
  silence follows its nominee's claim only in a copy signed before it
  returned, so a re-sign landing just before the owner's first successful
  fetch leaves it running a room its members have left.
- **Downgrading to 1.7.1 leaves one upload slot.** Auto is stored as
  `max_concurrent_uploads = 0`, which 1.7.1 repairs to 1 and saves. A separate
  `upload_slots_auto` flag, with the number kept in 1.7.1's range, would make
  the downgrade harmless.
