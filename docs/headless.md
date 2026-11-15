# Headless Ember

`emberd` runs Ember on a server with no screen. It shares and downloads like
the desktop app and is driven from a web browser, as aMule's `amuled` is with
`amuleweb`.

**Status:** built, for Linux on x86-64, from the same code as the desktop app.
It is published only as test builds, by `.github/workflows/emberd-test-build.yml`,
until the release jobs under [Still to do](#still-to-do) are in place. CI
checks, lints and tests it on every push.

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

### With systemd

Unpack the tarball (`emberd-<version>-linux-x86_64.tar.gz`) to `/opt/emberd`,
so that `/opt/emberd/emberd` sits beside `web/` and `resources/`. Then:

```sh
sudo useradd --system --home-dir /var/lib/emberd --shell /usr/sbin/nologin emberd
sudo install -Dm644 /opt/emberd/emberd.service /etc/systemd/system/emberd.service
sudo install -Dm644 /opt/emberd/emberd.toml /etc/emberd/emberd.toml
sudo systemctl enable --now emberd
journalctl -u emberd
```

Ember keeps its data in `/var/lib/emberd/data`. Unless the config names a
download folder, downloads go to `/var/lib/emberd/Downloads/Ember`.

### With Docker

```sh
docker build -f packaging/emberd/Dockerfile -t emberd .
docker run -d --name emberd --restart unless-stopped \
  -p 4711:4711 -p 4662:4662/tcp -p 4662:4662/udp -p 4672:4672/udp \
  -v emberd-data:/data -v /srv/downloads:/downloads emberd
docker logs emberd
```

The data volume is `/data` and downloads go to `/downloads`. To share a
folder, mount it and name it:
`-v /srv/music:/shared/music:ro -e EMBERD_SHARED_DIRS=/shared/music`.

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
`emberd passwd` (or `emberd passwd --stdin` to read it from a pipe).

### Reaching it from another computer

By default the web interface listens on `127.0.0.1:4711`, this computer only.
To use it from elsewhere, set `listen = "0.0.0.0:4711"` and either:

- give it a certificate and key (`tls_cert`, `tls_key`) to serve HTTPS, or
- put it behind a reverse proxy that serves HTTPS, listening on loopback.

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
- `GET /api/backup` downloads the backup `export_backup_for_download` just
  made, once; `POST /api/backup` receives one to restore, which Settings then
  inspects and restores as it would a picked file.
- Sign-in: `/api/session`, `/api/setup`, `/api/login`, `/api/logout`,
  `/api/password`, and `/api/restart` for Settings' restart.

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
  one count.
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
- Desktop notifications. In-app pop-ups stay.
- Watching the clipboard for links, and `ed2k://` links from other programs:
  pasting into the page, which reads the browser's clipboard.
- Keeping the computer awake, and *When downloads finish*.
- *Open file*, *Show in folder*, *Open log folder* and the external player:
  *Save to this computer*, the in-page player, and the log path shown in
  About.
- Native pickers: the config file for folders, and a file sent from the
  browser for a backup. The rest (an IP filter, a collection, a web services
  list or eMule's folder from a file, and sending a file to a friend or a room)
  is not offered yet.
- Silent updates and the in-app installer: emberd is updated the way it was
  installed.
- The Windows Firewall fix, the AppImage font workaround, and dragging files
  onto the Library.

**Everything else is the same,** as listed under
[What the user gets](#what-the-user-gets).

## Where it lives and how it ships

- **In this repository, on the same branches,** as one crate with the desktop
  app, so a change to shared code is built and tested for both at once.
- **Built on every push, published when ready.** CI's `emberd` job checks,
  lints and tests the server build on Ubuntu 22.04, and the desktop `check` job
  builds the web interface. Until the release jobs exist, `emberd-test-build.yml`
  builds a tarball and the Docker image on demand, unsigned and with no
  release, as `linux-test-build.yml` does for the desktop packages.
- **Released with the desktop app, under the same version and tag.** It speaks
  the same network formats and its pages are the desktop UI, so one set of
  release notes holds for both. `emberd` stays out of `latest.json`, so the
  desktop updater never offers it.
- **A fix only `emberd` needs** goes out as a patch release that publishes
  `emberd` alone and leaves `latest.json` as it was.

## Still to do

1. **Release jobs** in `release.yml`: x86-64 and ARM64 tarballs, a `.deb` with
   the systemd unit and the `emberd` user, the Docker image pushed, and the
   release policy test holding `emberd` out of `latest.json`.
2. **`emberd ctl`,** the command line over the same interface and the API
   token: status, add a link, list, pause, resume and cancel downloads, search.
3. **The remaining uploads:** an IP filter, a collection or a web services list
   from a file, and a file for a friend or a room.
4. **Browser notifications,** while the page is open and allowed.
5. **Hardening:** a security review of the interface by someone who did not
   write it, fuzzing its request parsing, and the rate limits under load.

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
