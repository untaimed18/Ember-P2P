# Headless Ember

`emberd` runs Ember on a server with no screen. It shares and downloads like
the desktop app and is driven from a web browser, as aMule's `amuled` is with
`amuleweb`.

**Status:** built from the same code as the desktop app, for Linux on x86-64
and ARM64, and released with it from 1.8.0: a tarball and a `.deb` for each,
and a Docker image for both. CI checks, lints and tests it on every push.

**For users:** the website's [emberd page](emberd.html)
(emberp2p.org/emberd.html) covers installing, setting up and using it. A
change here that a user would notice belongs there too.

## What the user gets

- **One program**, `emberd`. It needs no display, GTK or WebKit, runs as a
  systemd service or in a Docker container, keeps running when nobody is logged
  in, and stops cleanly when the service is stopped.
- **The same networks and features** as the desktop app: eD2K servers, KAD, the
  Ember network, search and the spam filter, downloads and uploads, the library
  and hashing, friends and chat, rooms and private messages, feeds, the IP
  filter, statistics, the Connection Doctor and *Connect through*.
- **The same pages in a web browser,** behind a sign-in. Controls that mean
  nothing on a server are hidden; the few that need another form have one
  (see [Features by build](#features-by-build)).
- **Finished files are saved to the browser's computer** (*Save to this
  computer*), and audio and video play in the page.
- **Backups** download to the browser's computer and restore from a file sent
  from it, so a desktop Ember moves onto a server with its identity, friends
  and rooms.
- **A config file** for what the desktop app asks for with native dialogs: the
  download folder, the shared folders, and where the web interface listens.

The desktop app gives up nothing, and is built from the same code.

## Installing and running

Each release carries `emberd_<version>_amd64.deb` and `_arm64.deb`,
`emberd-<version>-linux-x86_64.tar.gz` and `-aarch64.tar.gz`, and
`emberd-<version>-SHA256SUMS`. They need glibc 2.35 or later (Ubuntu 22.04,
Debian 12, and anything newer) and the system's CA certificates, and no other
library.

### With the .deb (Debian, Ubuntu)

```sh
sudo apt install ./emberd_*_amd64.deb
sudo nano /etc/emberd/emberd.toml       # the folders, and where it listens
sudo systemctl enable --now emberd
journalctl -u emberd                    # the setup code for the first visit
```

The package makes the `emberd` user, installs the systemd unit and
`/usr/bin/emberd`, and does not start the service, so the folders can be set
before Ember joins any network. An upgrade restarts it if it was running.
Removing the package stops it; purging it leaves Ember's data, identity and
downloads in `/var/lib/emberd`.

### With systemd, from the tarball

Unpack the tarball to `/opt/emberd`, so that `/opt/emberd/emberd` sits beside
`web/` and `resources/`. Then:

```sh
sudo useradd --system --home-dir /var/lib/emberd --shell /usr/sbin/nologin emberd
sudo ln -s /opt/emberd/emberd /usr/local/bin/emberd
sudo install -Dm644 /opt/emberd/emberd.service /etc/systemd/system/emberd.service
sudo install -Dm644 /opt/emberd/emberd.toml /etc/emberd/emberd.toml
sudo systemctl enable --now emberd
journalctl -u emberd
```

Either way, Ember keeps its data in `/var/lib/emberd/data`. Unless the config
names a download folder, downloads go to `/var/lib/emberd/Downloads/Ember`.

### With Docker

```sh
docker run -d --name emberd --restart unless-stopped \
  -p 4711:4711 -p 4662:4662/tcp -p 4662:4662/udp -p 4672:4672/udp \
  -v emberd-data:/data -v /srv/downloads:/downloads ghcr.io/untaimed18/emberd
docker logs emberd
```

The image is for x86-64 and ARM64 alike, tagged with each version, its
`major.minor`, and `latest`. The data volume is `/data` and downloads go to
`/downloads`. To share a folder, mount it and name it:
`-v /srv/music:/shared/music:ro -e EMBERD_SHARED_DIRS=/shared/music`. To build
the image from source instead:
`docker build -f packaging/emberd/Dockerfile -t emberd .`

### The first visit

On its first start `emberd` writes a setup code to its log, and to
`emberd-setup-code` in its data folder:

```text
No password is set for the web interface yet. Open http://localhost:4711
and enter this setup code to choose one: 2BLD-WZ8J
```

Open the address, enter the code and choose a password. The code proves the
person choosing it can read the server's log, so nobody else on the network
can claim a fresh install first. Case and the dash do not matter.

To set the password from a shell instead, stop `emberd` and run
`emberd passwd` as the user it runs as (or `emberd passwd --stdin` to read it
from a pipe):

```sh
sudo systemctl stop emberd
sudo -u emberd emberd passwd
sudo systemctl start emberd
```

### From a shell

`emberd ctl` manages downloads and searches from a shell or a script:

```text
emberd ctl status                    Connections, speeds and downloads
emberd ctl list                      Downloads, each with its id
emberd ctl add LINK...               Download ed2k:// links (or read them from standard input)
emberd ctl pause|resume|stop ID...|all
emberd ctl cancel ID...              Cancel them and delete what arrived
emberd ctl search [--type TYPE] [--method METHOD] [--limit N] WORDS...
```

An ID is the one `list` shows, or the start of it, or the start of the file's
eD2K hash. `--json` prints what `emberd` answered. Run it as the `emberd` user
(`sudo -u emberd emberd ctl status`), or as a member of its group
(`sudo usermod -aG emberd $USER`, then log in again); in Docker,
`docker exec emberd /opt/emberd/emberd ctl status`.

### Reaching it from another computer

By default the web interface listens on `127.0.0.1:4711`, this computer only.
To use it from elsewhere, set `listen = "0.0.0.0:4711"` and either:

- give it a certificate and key (`tls_cert`, `tls_key`) to serve HTTPS, or
- put it behind a reverse proxy that serves HTTPS, listening on loopback. The
  proxy must pass the host the browser asked for, as `Host` or
  `X-Forwarded-Host` (nginx: `proxy_set_header Host $host;`, Apache:
  `ProxyPreserveHost On`), and forward WebSocket upgrades for `/api/events`:
  emberd checks a request's `Origin` against it.

Over plain HTTP from another computer it still works, and says so: the log
warns at every start and the sign-in page shows that the password would travel
unencrypted. The Docker image listens on every address, so that the port can be
published at all.

## Configuration

Every key is optional. An environment variable wins over the file, so a
container needs no file at all. `packaging/emberd/emberd.toml` is the same
list with comments.

| Key | Variable | Default |
|---|---|---|
| (the file itself) | `EMBERD_CONFIG` | `/etc/emberd/emberd.toml` if it exists |
| `data_dir` | `EMBER_DATA_DIR` | the desktop app's data folder for the user |
| `key_file` | `EMBERD_KEY_FILE` | `<data_dir>/emberd-secret.key` |
| `resource_dir` | `EMBERD_RESOURCE_DIR` | beside the program if `web/` is there, else `/usr/share/emberd` |
| `web.root` | `EMBERD_WEB_ROOT` | `<resource_dir>/web` |
| `web.listen` | `EMBERD_LISTEN` | `127.0.0.1:4711` (a bare port means 127.0.0.1) |
| `web.tls_cert`, `web.tls_key` | `EMBERD_TLS_CERT`, `EMBERD_TLS_KEY` | none: plain HTTP |
| `folders.download` | `EMBERD_DOWNLOAD_DIR` | Ember's default in the home folder |
| `folders.shared` | `EMBERD_SHARED_DIRS` | none |
| `folders.browse_under` | `EMBERD_BROWSE_UNDER` | none |

The folder variables take a list separated by `:`. Unknown keys are refused, so
a typing mistake stops `emberd` rather than being ignored.

**Folders** have to be full paths, outside the data folder, and outside system
and private folders: no folder on the way to one may be named `etc`, `usr`,
`var`, `tmp`, `temp`, `AppData`, `.ssh`, `.config` and the like, except the
folders leading to the home folder. These are the desktop app's own rules for
the download and shared folders, checked at startup so a folder they refuse
stops `emberd` with its name, instead of Ember resetting its settings once it
runs. This is why the systemd unit sets the service's home to its state
folder: the default download folder is then under it.

Everything else is in `config.json` as on the desktop, and set in the web
interface's Settings. The section *This server* shows what the config file set
and where `emberd` keeps its data.

## How it works

### One crate, two builds

`src-tauri` builds both programs. The Cargo feature `desktop` (the default)
builds the app with Tauri; `--no-default-features --features server` builds
`emberd` with no Tauri in its dependency tree at all, so a desktop call slipping
into shared code fails to build there.

- **`crate::host`** is what the code talks to instead of Tauri. On the desktop
  it re-exports Tauri's `AppHandle`, `State`, `Manager`, `Emitter` and friends.
  On the server (`host/server.rs`) it supplies types of the same names: events
  go to a `tokio::sync::broadcast` channel the web pages subscribe to, state is
  kept by type, and `exit` asks `emberd` to stop or restart.
- **Confirmations** that the desktop asks in a native dialog
  (`host::confirm`) are asked of every open page as an `ember:confirm` event,
  answered with `answer_confirm`. No page open, or no answer in five minutes,
  is *no*. A question whose answer opens a web address carries it, so the page
  opens the tab as the button is clicked, the only time a browser allows it.
- **Commands** are marked `#[ember_macros::command]` (shared),
  `(desktop)` or `(server)`. `command_table.rs` names every command once;
  `ember_macros::command_table!` turns it into the desktop's
  `generate_handler!` and the server's dispatch table, so the two cannot list
  different commands by accident.
- **Startup and shutdown** are shared: `init_process` (logging, the runtime,
  the crypto provider) and `setup` (the data folder, database, config,
  identity, approved roots, library scan and network) run in both, the desktop
  adding its tray, window, deep links and updater around them.
  `run_graceful_shutdown` saves everything in both.

### The web interface

- `POST /api/invoke/{command}` with the arguments as JSON, in the camelCase the
  UI already sends. The answer is `{ "ok": value }` or `{ "error": coded }`,
  the same coded error string the desktop returns, so `translateError` works
  unchanged. A command the server does not have answers `server_unsupported`
  and is logged, since a page that still offers it is a bug.
- `GET /api/events` is a WebSocket carrying `{ event, payload }`. A page that
  falls behind is closed with code 4000 and reloads; one whose session ended
  is closed with 4001 and shows the sign-in.
- `GET /api/media/{path}` serves the library's audio and video for the
  player, with the desktop's `ember-media` checks.
- `GET /api/file/{path}` is *Save to this computer*: only a file in the library
  index, opened through an approved folder, sent as an attachment.
- `GET /api/saved/{id}` is *Save to this computer* for what the library index
  does not hold: a followed feed's file (`save_feed_item`), a friend's
  attachment (`save_chat_attachment`), a file received in a room or fetched
  from its library (`save_channel_transfer`), and a collection made in the
  Library (`create_collection_for_download`). Each command finds its file as
  its desktop twin finds what it opens, and leaves it under a one-time id the
  page fetches at once; an id is sent once and lapses unfetched after two
  minutes.
- `GET /api/backup` downloads the backup `export_backup_for_download` just
  made, once; `POST /api/backup` receives one to restore, which Settings then
  inspects and restores as it would a picked file.
- `POST /api/upload?name=` receives any other file the page sends (an IP
  filter, a collection, a web services list, a file for a friend or a room)
  into `<data>/emberd-uploads/<id>/`, and answers with the id. The page then
  calls the command that takes it: `import_ipfilter_upload`,
  `load_collection_upload`, `import_webservices_upload`,
  `send_chat_attachment_upload` or `offer_channel_transfer_upload`, each
  doing what its desktop twin does with a picked path. An id is 32 hex
  digits and names nothing outside that folder. Uploads are cleared at each
  start; a file sent to a friend or a room moves to `emberd-sent/` until it
  has been offered for two weeks, as an attachment waits a week to be taken.
- Sign-in: `/api/session`, `/api/setup`, `/api/login`, `/api/logout`,
  `/api/password`, and `/api/restart` for Settings' restart.
- **The control socket** serves the same routes to `emberd ctl`, on a Unix
  socket: `/run/emberd/emberd.sock` under systemd (its folder open to the
  `emberd` group), `<data>/emberd.sock` otherwise (`emberd` alone), or where
  `EMBERD_SOCKET` says. Who can open the socket can read the API token, so a
  request on it counts as one made with the token.

The pages are the desktop UI built a second time with `npm run build:web`
(into `build-web/`). Vite points `@tauri-apps/api/core`, `/event`, `/window`,
`/webview` and `@tauri-apps/plugin-process` at stand-ins in
`src/lib/runtime/web/`, and `isServer` hides or replaces what a browser cannot
do.

### Sign-in and exposure

- **One password,** stored as an Argon2id hash in `emberd-auth.json`. The
  first one is chosen with the setup code; changing it signs out every other
  browser and keeps the one that changed it.
- **Sessions** are random tokens in an `HttpOnly`, `SameSite=Strict` cookie,
  `Secure` under HTTPS, kept by their SHA-256 and dropped after 30 days unused.
- **Every request is checked.** Everything but the files, the health check and
  sign-in needs a session or the API token; the `Origin`, if any, must be this
  server; and a request that changes anything must carry `X-Ember-Request`,
  which a form on another site cannot send. There are no CORS headers.
- **Wrong passwords slow down:** three are free, then each address waits twice
  as long as the last time, up to five minutes, even for the right one. Behind
  a reverse proxy every browser comes from the proxy's address, so they share
  one count. An attempt is counted as it starts, so many sent at once are
  slowed like many sent one after another; an IPv6 address counts by its /64,
  the block one machine is given; and the addresses remembered are capped, so
  a flood from many of them cannot grow the list without end.
- **Load has limits.** Two password checks run at once (Argon2 takes a moment
  and 19 MiB each); more wait their turn, or are told after 20 seconds that
  `emberd` is busy. Sign-in requests are at most 16 KiB, 256 connections are
  served at once (and 64 more on the control socket, counted apart), and a
  connection has 30 seconds to send its headers and 15 to finish a TLS
  handshake.
- **The API token** in `emberd-cli-token` lets scripts call the same interface
  with `Authorization: Bearer`, without the same-site checks a browser needs.
  Changing the password replaces it, so a token that leaked with the password
  stops working too.
- **Security headers** on everything: a Content-Security-Policy that allows the
  page's own scripts by hash and nothing else, `nosniff`, `no-referrer`,
  `DENY` for framing, and `no-store` for the interface and the page.
- **The interface's listener is the one socket outside `net_bind`,** on
  purpose: it is for the administrator, and must stay on loopback or the LAN
  when *Connect through* keeps everything else on a VPN.

### Folders and files

The desktop app never lets the webview name a folder to write to or share;
`ApprovedRootRegistry` checks every open, write, rename and delete against
the folders the user approved. `emberd` keeps all of that and changes only how
a folder gets approved:

- **The config file names them.** At startup they are written into the
  settings and approved, before anything is indexed. A shared folder taken out
  of the config is unshared at the next start.
- **The share browser lists only what is inside `browse_under`,** and refuses
  to list, open or share anything outside it, whatever path the page sends. A
  folder shared from it can be unshared there.
- **The download folder, `browse_under` and the shared folders the config
  names change only in the config.** The pages show them as set there and offer
  no way to remove them.

### Keys at rest

On the desktop, `secret_store.rs` seals `identity.json` and `cryptkey.dat`
with the system keyring, or on Linux with a key derived from
`/etc/machine-id`. A server rarely runs a keyring and a container often has no
machine-id, so `emberd` seals them with a **key file** of its own: 32 random
bytes made on first start, readable by `emberd` alone, recorded as its own key
source in each sealed file. Keep it with the data in backups; without it the
data folder cannot be read. (On Windows, where `emberd` is not shipped, the
account's DPAPI key is used as on the desktop.)

### Restarting

Settings' restart (after a restore, or changing the network interface) stops
Ember with everything saved and starts it again in the same process, by
`exec`, so systemd and Docker see one service throughout. The page shows
*Lost the connection to emberd*, reconnects, and reloads.

A lock file, `instance.lock` in the data folder, keeps a second `emberd`, or
the desktop app, from opening the same data.

## Features by build

**Not on the server,** with what stands in:

- The tray, closing to the tray, starting minimized, the window's position,
  the splash screen and the popped-out chat window.
- Starting at login: the systemd unit or Docker's restart policy.
- Desktop notifications: the browser shows the same ones while the page is
  open, once it is allowed to in Settings, which needs HTTPS or `localhost`.
  In-app pop-ups stay.
- Watching the clipboard for links, and `ed2k://` links from other programs:
  pasting into the page, which reads the browser's clipboard.
- The Recycle Bin or Trash: deleting a file in the Library, or a finished
  download's file, deletes it outright, and the confirmation says so, as
  nothing on a server empties a trash.
- Keeping the computer awake, and *When downloads finish*.
- *Open file*, *Show in folder*, *Open log folder* and the external player:
  *Save to this computer* (for the Library, finished downloads, followed
  feeds' files, friends' attachments and files received in rooms), the
  in-page player, and the log path shown in About.
- Native pickers: the config file for folders, and a file sent from the
  browser for everything else that opens a file: a backup, an IP filter, a
  collection, a web services list, and a file for a friend or a room. A
  collection made in the Library is saved by the browser. eMule's or aMule's
  folder is typed, under `browse_under`, and an import there shares only
  folders under `browse_under`, takes unfinished downloads only from them or
  the eMule folder itself, and never sets the download folder, which is the
  config's.
- Silent updates and the in-app installer: emberd is updated the way it was
  installed. *Share every Ember release* works as on the desktop, from a check
  of its own each hour (`release_fetch::seed_newest_release`) with the
  manifest and every file verified as the updater verifies them.
- The Windows Firewall fix, the AppImage font workaround, and dragging files
  onto the Library.

**Everything else is the same,** as listed under
[What the user gets](#what-the-user-gets).

## Where it lives and how it ships

- **In this repository, on the same branches,** as one crate with the desktop
  app, so a change to shared code is built and tested for both at once.
- **Built on every push.** CI's `emberd` job checks, lints and tests the
  server build on Ubuntu 22.04, and the desktop `check` job builds the web
  interface. `emberd-test-build.yml` builds the x86-64 packages and the Docker
  image from source on demand, unsigned and with no release, as
  `linux-test-build.yml` does for the desktop packages.
- **Released with the desktop app, under the same version and tag.** It speaks
  the same network formats and its pages are the desktop UI, so one set of
  release notes holds for both. In `release.yml`, `build-emberd` builds it on
  Ubuntu 22.04 for x86-64 and ARM64 and packages it with
  `packaging/emberd/package.sh`; `sign-publish` attaches the tarballs and
  `.deb`s with their SHA-256 list, from a folder of their own, so nothing signs
  them with the updater key and `emberd` stays out of `latest.json`: the
  desktop updater never offers it. The release policy and its tests hold all
  of that, and `add-linux-platforms.mjs` refuses an `emberd` package outright.
- **The Docker image is pushed when the release is published,** by
  `emberd-image.yml`: made from the release's own tarballs, checked against
  their SHA-256, on an x86-64 and an ARM64 runner, and joined into one image on
  `ghcr.io`. It waits for publishing, as `latest.json` does, so `latest` never
  moves to a draft. The jobs that can push compile nothing.
- **A fix only `emberd` needs** goes out with the next release. Every release
  builds both, so the desktop gets the new version number too.

## Still to do

- **A security review by a person** who did not write the interface. It has
  had an automated one, by a reviewer that was not its author, besides the
  fuzzing and the tests under load below.

## Testing

- The Rust suite runs against both builds, on Windows and Linux.
- The interface's own tests cover the same-origin rule, the cookie, the
  Content-Security-Policy, the saved file's name, the config file's rules
  (including folders the settings would refuse), and the sign-in: the setup
  code, wrong passwords slowing down, sessions, and a password change keeping
  the browser that made it.
- The shared code's tests cover the host stand-ins: command arguments and
  results, state, events and confirmations. The browser's stand-ins have tests
  of their own: a refused request before sign-in never reloads the page, and a
  link opens only as a web address.
- A settings file reset because it cannot be read keeps the network interface
  it named, so a reset cannot send traffic out of another one, on the desktop
  as on `emberd`.
- **Fuzzing:** what a request with no session reaches (its cookies, token and
  `Origin`, the saved file's name, the setup code, upload names and the paths
  of `/api/file` and `/api/media`) and `emberd ctl`'s reading of answers,
  chunked or not, run through thousands of generated inputs each, which must
  never panic and must keep their guarantees.
- **Under load:** wrong passwords sent from eight threads at once are slowed
  as if sent in turn, an IPv6 network counts as one address, and a flood from
  thousands of addresses keeps the list of them bounded.
- **`emberd ctl`:** its arguments, an ID by its start or its hash, adding a
  link starts each file once and never trusts a digest the link claims, and a
  refusal prints its reason.
- **Packaging:** `package.sh` run on the release build, then the tarball and
  the `.deb` read back: every file and its mode and owner, the control file's
  dependencies (glibc and libgcc only, as `dpkg-shlibdeps` reads them), the
  conffile, the checksums, the unit through `systemd-analyze verify`, and the
  maintainer scripts run against stand-ins for a first install, an upgrade, a
  removal and a purge. The config file it ships is read by `emberd`'s own
  parser in the Rust suite. CI runs the same check on both machines' packages
  before a release takes them.
- **Offline, on Linux, for 1.8.0:** the release build packaged and checked as
  above, then `emberd` run with the network held offline as below: every
  `emberd ctl` command and its refusals, a collection, an IP filter and a web
  services list sent as uploads, twelve wrong passwords at once (three
  checked, nine told to wait), a 20 KB sign-in refused, 256 connections held
  and the next turned away, half a request let go after 30 seconds, and a
  clean stop on SIGTERM. In a browser, the notifications setting and the
  upload buttons.
- Before this landed, `emberd` was run on a scratch data folder with the
  network held offline by a network interface that does not exist, and every
  page was used from a browser: the first visit and its setup code, signing in
  and out, a wrong and a changed password, the share browser inside and
  outside `browse_under`, its confirmation, sharing and unsharing, *Save to
  this computer*, a backup downloaded and restored from an upload, Settings'
  restart, and the page reconnecting after `emberd` was stopped and started
  again. Every page was visited with `emberd` logging any command it does not
  have; none was asked for.

## Decisions

These were the open questions. Each is settled here with its reason, so it is
not reopened without a new one.

- **The name is `emberd`:** the binary, the package, the systemd unit and the
  Docker image, with `emberd passwd` for the password and `emberd ctl` for the
  command line to come. In Ember, *server* already means an eD2K server or the
  Rendezvous server, so `ember-server` would read as one of those. A trailing
  `d` is what Linux administrators expect of a daemon, and what aMule's
  `amuled` taught eMule's users.
- **The first release includes the web interface.** The people asking for this
  run it on a machine they reach over the network, and from a command line they
  could only manage downloads: search, friends, chat, rooms and feeds need the
  pages.
- **Linux only at first.** The requests are for Linux machines, NAS boxes and
  Docker, and the Docker image also covers Synology, Unraid and TrueNAS. On
  Windows the desktop app already starts at login, sits in the tray and
  updates itself. `emberd` builds and runs on Windows (it was tested there),
  but a Windows service would need its own wrapper and installer.
- **Plain HTTP is allowed beyond loopback, and said aloud.** The design first
  refused to listen on the network without HTTPS. That turns the most common
  setup, a home server reached from the same network, into certificates before
  the first page loads, and the people it stops are the ones least able to
  set one up. So it listens, warns in the log at every start, and the sign-in
  page says the password travels unencrypted.
- **The desktop app does not offer the web interface yet.** It would put a
  network service on the computer that holds the user's own files, and the
  reason to do it, using Ember from a phone, is met by running `emberd` at
  home. Once `emberd`'s interface has had its security review and some months
  of use, the desktop can offer it behind a switch: off by default, on the
  local network only, and with no more power over folders than the pages have.
- **The browser can share and unshare folders inside `browse_under`, and
  nothing more.** Sharing only reads files, and `browse_under`, empty unless the
  operator sets it, bounds what a stolen session could publish. The download
  folder is where files from strangers are written, so it changes only in the
  config, as do `browse_under` and the shared folders the config names.
