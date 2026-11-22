# 1.7.0 release checklist

What automated checks cannot cover before tagging `v1.7.0`. Tick each box, and
file anything that fails before tagging rather than after.

## 0. Automated checks

- [ ] `npm test` and `npm run check` pass.
- [ ] `cargo clippy --tests` is clean and `cargo test --lib` passes in `src-tauri`.
- [ ] `node scripts/verify-release-policy.mjs` passes (1.7.0, Ember DHT wire
      version 4, security epoch 1).
- [ ] `node scripts/release-notes.mjs` prints the 1.7.0 notes, and they read
      correctly as Markdown (paste into a GitHub comment preview).
- [ ] The download heading on the site says "Get Ember 1.7.0".

## 1. Visual pass, light and dark

Do each page twice, once per theme, at three window widths: full screen,
about 1100 px, and the 900 px minimum. Look for: text cut off or overlapping,
controls that wrap badly, colours that are unreadable in one theme, a spinner,
banner, badge or empty state that looks different from the same thing on
another page, and focus rings missing when you Tab through.

- [ ] Transfers: downloads and uploads tables, a selected row on a striped
      row, the details dialog, the filter search, toolbars below 980 px.
- [ ] Search: results, filtered-empty state, spam marking, download history.
- [ ] Library: table, sidebar splitter, file details drawer (type icon, shared
      with, copy buttons, ratio), selection bar, Chat Files / Channel Files
      buttons, Share Folder dialog.
- [ ] Friends: cards, unread count on Chat, relay-only hint, Browse Friend
      dialog (categories, sort, multi-select, badges, "1,000 of N").
- [ ] Chat dock: one header with the padlock, width drag, slide in/out, search
      by name, typing indicator (transcript must not jump), growing composer,
      empty state.
- [ ] Chat pop-out: open, pop back, close; unread counts and notifications
      while it is open and focused, open and in the background, and minimised.
- [ ] Channels: room list sizing and long names with flags, conversation,
      replies, pins bar, reactions, formatting, typing, announcement notice,
      transfer drawer, room settings window (all cards, confirms stacked above
      it, Escape and focus return), Discover with language flags.
- [ ] Servers, KAD, Ember, Security, Statistics: page subtitles, stat tiles,
      no-match states with Clear filters.
- [ ] Settings: every section, the section nav, Import, the IP filter switches
      applying at once.
- [ ] Dialogs: Close App, About, Keyboard Shortcuts, update notice.
- [ ] First-run wizard, including the eMule import step.

## 2. Two-machine transfer matrix

Two computers, A sending and B receiving, both on 1.7.0 and mutual friends in a
shared room. For each row, send once as a friend chat attachment and once as a
room transfer. Use a file of about 200 MB unless the row says otherwise.

| Setup | Expect |
| --- | --- |
| Both reachable, direct | Starts within a few seconds over QUIC; speed near the link or upload cap; progress moves smoothly |
| A's UDP port not forwarded (or UDP blocked) | Falls back to the TCP upload port about 3 s after accept; no 15 s wait |
| Same home network | Starts directly, without going out to the internet |
| Only reachable through a relay | Friend chat: the card says files are not sent through relays. Room: falls back to the block protocol |
| File over 1 GB with an upload cap on A | Speed holds at the cap; time left is sensible; completes and verifies |
| Cancel from each side mid-transfer | Both cards show cancelled; no stuck row |
| Kill B mid-transfer, restart | Chat: can be fetched again. Room: resumes from verified chunks |
| B's disk too full | Refused before any bytes move, with a clear message |
| `setup.exe`, `report.pdf.exe`, `invoice.pdf.lnk` | Warning shown on B's card; Open shows the folder instead of launching |
| `holiday.jpg` | No warning |
| Room offer from a member B ignores | B never sees it |

- [ ] Chat attachments land in Chat Files and room files in Channel Files, and
      neither folder shows up as shared in the Library.
- [ ] Auto-download takes a file under the size set in Settings and asks for
      one over it.

## 3. Mixed versions (1.7.0 with 1.6.7)

Machine A on 1.7.0, machine B on 1.6.7.

- [ ] Both see each other on the Ember DHT; searches and downloads work.
- [ ] Existing friends stay friends; online status, chat and browse work both
      ways after the upgrade.
- [ ] A new friendship: B cannot read A's `ember3:` code (expected); A can add
      B from B's `ember2:` code, and B can accept.
- [ ] A friend chat attachment from A is not shown to B, and A's card does not
      claim it was delivered.
- [ ] A room transfer from A to B under 100 MB completes over the block
      protocol; one over 100 MB is dropped by B and A's offer says so on expiry.
- [ ] A room transfer from B to A works as it did in 1.6.7.
- [ ] In a room with both: A's reply shows on B as an ordinary line; A's
      formatting shows as typed marks; A's new reactions do not break B; typing
      is not shown on B; B still sees A's edits and the original three reactions.
- [ ] A room owned by A with a language set and pins: B still relays and shows
      the room normally; A renaming the room reaches B.
- [ ] Announcement-only room owned by A: B can still post (expected, documented).
- [ ] Downgrading A to 1.6.7 after running 1.7.0 either works or refuses
      cleanly (database migrations v58 and v59); note which in the release.

## 4. Translation review

1.7.0 adds about 610 strings and changes about 240, in all eight non-English
locales (de, es, fr, it, pt-BR, ru, zh-CN, zh-TW). The locale tests check keys and
placeholders, not wording. List them with:

```
git diff v1.6.7 -- messages/en.json
```

Ask a native speaker, or at least a careful reader, to check these areas first,
since they are the most visible:

- [ ] eMule import and the first-run wizard (`emule_*`, `wizard_*`).
- [ ] Rooms: replies, pins, announcements, language picker, room settings
      window, transfer drawer (`channels_*`).
- [ ] Chat attachments and the pop-out (`chat_*`), including the risky-file
      warning (`common_risky_file`).
- [ ] Library details and sharing (`library_*`, `shares_*`).
- [ ] Native file-picker titles (`picker_*`); open each picker once in each
      language and check the title fits.
- [ ] Page subtitles on Servers, Security and Statistics.
- [ ] German uses the formal *Sie* everywhere, French uses *vous* with typographic
      apostrophes, and plurals read correctly for 0, 1, 2 and 5 in Russian.
