# Headless Ember

Design for running Ember on a server with no screen: a program, `emberd`,
that shares and downloads like the desktop app and is driven from a web browser
or the command line, as aMule's `amuled` is with `amuleweb` and `amulecmd`.

**Status:** designed, with its questions settled under [Decisions](#decisions).
Nothing is built yet; the work starts after 1.8.0 ships. The order it would be
built in, each step leaving the desktop app working as before, is under
[Implementation order](#implementation-order).

## What the user gets

- **One program**, `emberd`, for Linux on x86-64 and ARM64. It needs no
  display, GTK or WebKit, and runs as a systemd service or in a Docker
  container. It keeps running when nobody is logged in and stops cleanly when
  the service is stopped.
- **The same networks and features** as the desktop app: eD2K servers, KAD, the
  Ember network, search and the spam filter, downloads and uploads, the
  library and hashing, friends and chat, rooms and private messages, feeds,
  collections, the IP filter, statistics, the Connection Doctor and
  *Connect through* (useful for a seedbox behind a VPN).
- **The same pages in a web browser.** The desktop UI, built a second time for
  the browser, with a login page in front of it. Controls that mean nothing
  on a server are hidden; the few that need a different form get one
  (see [Features by build](#features-by-build)).
- **Finished files can be fetched** through the browser, and audio and video
  played in it, in place of *Open file* and the external player.
- **A command line** for scripts: status, add a link, list, pause, resume and
  cancel downloads, search. It talks to the same interface the web pages use.
- **A config file** for what the desktop app asks for with native dialogs: the
  download folder, the shared folders, and where the web interface listens.

The desktop app gives up nothing. It keeps every feature it has, and is built
from the same code.

## Scope

**First version:** Linux x86-64 and ARM64, as a plain binary, a `.deb` with a
systemd unit, and a Docker image, with the web UI and the command line. One
administrator account.

**Not in the first version** (the reasons for the first three are under
[Decisions](#decisions)):

- Windows and macOS servers. Nothing in the design rules them out (DPAPI works
  under a service account), but each needs its own service wrapper and tests.
- Changing folders from the browser beyond sharing inside the operator's
  `browse_under` (see [Folders and files](#folders-and-files)).
- The web interface in the desktop app, to reach a desktop Ember from a phone.
- More than one account, or accounts with fewer rights.
- Sending a file from the browser's computer to a friend or a room. A file has
  to be on the server to be sent; uploading it there first can come later.

## Why it can be done

The work is large, but none of it fights the code:

- **The core does not need a window.** Search, security, bandwidth and eMule
  import do not touch Tauri. The network code (about 297,000 lines) holds an
  `AppHandle` in 65 files, and across it, sharing and storage, apart from
  cloning the handle, the only calls made on it are 184 `emit`s to the UI and
  2 `path()` lookups: one for the bundled GeoIP database, one for an old data
  folder to migrate, which only the desktop has.
- **`AppState` holds plain Rust types,** no Tauri ones.
- **The UI reaches the backend two ways:** `invoke`, wrapped almost entirely in
  `src/lib/api/*.ts` (about 320 calls there, 17 elsewhere), and `listen`. The
  frontend is already a static single-page app (`adapter-static`,
  `ssr = false`), so a server can hand it to a browser as files.
- **Commands already speak JSON:** arguments in, `Result<T, String>` out, with
  errors as the coded envelope from `commands/errors.rs` that `translateError`
  reads. That is what an HTTP call carries too.
- **The repository already ships a headless server,** `rendezvous-server`, on
  axum with WebSockets and signal handling.
- **The shutdown that saves everything is one function,**
  `run_graceful_shutdown` in `lib.rs`, already called from three places.

What stands in the way, measured:

| What | How much |
|---|---|
| Commands to make callable without Tauri | 372 (plus 9 debug-only) |
| Commands taking `tauri::State<AppState>` / `AppHandle` / `WebviewWindow` | 314 / 105 / 62 |
| Distinct events the backend emits | about 105, from about 311 call sites |
| Places the core reaches back into `commands` | 82 (error helpers, `emit_transfer_status`, settings saves, path helpers) |
| Startup inside Tauri's `.setup` closure | about 1,750 lines of `lib.rs` |

## How it works

### Three crates

- **`ember-core`**, a library with no Tauri dependency: the network, sharing,
  storage, search, security, bandwidth and import code, `net_bind`, GeoIP,
  automatic IP filter updates, the core of `background.rs`, startup and
  shutdown, and the body of every command. Because the crate cannot name
  Tauri, a desktop call slipping back into the core fails to build, the way
  `clippy.toml` now refuses a socket made outside `net_bind`.
- **`ember`**, the desktop app (today's `src-tauri`): thin `#[tauri::command]`
  wrappers, the tray, windows, dialogs, notifications, the updater, deep links
  and the `ember-media` protocol.
- **`emberd`**, the binary: config, the HTTP and WebSocket interface on
  axum, login, the web UI's files, the command line, signals and the lock file.

### The host the core talks to

Where the core holds an `AppHandle` today, it holds a `Host`:

```rust
pub trait Host: Send + Sync + 'static {
    /// Tell every UI attached that `event` happened.
    fn emit(&self, event: &'static str, payload: serde_json::Value);
    /// Where read-only files shipped with Ember are (the GeoIP database).
    fn resource_dir(&self) -> PathBuf;
}
```

The desktop implements it on `AppHandle`. The server implements it with a
`tokio::sync::broadcast` channel that each WebSocket subscribes to. Events stay
named and shaped exactly as they are, so the UI's listeners do not change. The
two events sent to one window (`emit_to` the main window for the update-resume
snapshot, and to the chat window to dock it) stay in the desktop crate.

Desktop-only abilities a command needs (a dialog, a notification, opening a
folder) are not on `Host`. Those commands stay in the desktop crate whole, and
the server does not offer them.

### Commands over HTTP

Each command body becomes a plain function in `ember-core` taking `&Ctx` (the
`AppState`, the `Host`, and the updater and resume services where needed) and
its arguments. One list names every command once, with whether the server
offers it, and a macro generates from it both the Tauri wrappers with
`generate_handler!` and the server's dispatch table. A test holds the list,
the desktop handler and the server table to the same names.

- `POST /api/invoke/{command}`, the arguments as a JSON object with the
  camelCase names the UI already sends (Tauri's default; no command overrides
  it). The answer is the command's value as JSON, or a 4xx with the same coded
  error string the desktop returns, so `translateError` works unchanged.
- A command the server does not offer answers with the coded error
  `server_unsupported`, never 404 by accident.
- No command streams on the server: the only one that does,
  `secure_updater_install`, is desktop-only.
- Requests are capped in size, and every command keeps the timeouts it has
  (`CMD_REPLY_TIMEOUT` for the network task).

### Events over a WebSocket

- `GET /api/events` upgrades to a WebSocket that carries `{ event, payload }`
  frames. The browser shim hands them to listeners in Tauri's shape,
  `{ event, id, payload }`.
- Each connection has a bounded queue. A browser that falls behind (a laptop
  lid closed) is disconnected rather than allowed to hold memory, and on
  reconnecting the shim tells the stores to read their state afresh. Most
  already poll (network statistics every 3 seconds, transfers), so this is a
  small list to complete, not a new mechanism.
- `emit` from the frontend is only used between the main window and the
  popped-out chat. The browser build has no chat window, so it does nothing.

### The web UI

The same SvelteKit app, built with `VITE_EMBER_RUNTIME=web`. Vite aliases
`@tauri-apps/api/core`, `/event`, `/window`, `/webview` and
`@tauri-apps/plugin-process` to shims in `src/lib/runtime/web/`:

- `invoke` posts to `/api/invoke/{command}`; `listen` and `once` subscribe on
  the WebSocket; `Channel` is never used.
- `convertFileSrc(path, 'ember-media')` becomes a same-origin `/api/media/…`
  URL, served with the checks `serve_media_request` applies today: the file
  must be in the library index, inside an approved root, and opened through
  its handle.
- `getCurrentWindow()` answers as the main window; its theme follows the
  browser's `prefers-color-scheme`.
- `relaunch()` asks the server to restart its network (or is hidden where a
  restart means the whole service).

An `isServer` flag hides or replaces the desktop-only controls listed below.
The server embeds the built files in its binary and serves them with its own
Content-Security-Policy (`default-src 'self'`, `connect-src 'self'`,
`frame-ancestors 'none'`).

### Login and exposure

The desktop UI is local and its webview cannot reach the network. The web
interface is a network service, and everything behind it can read the library,
delete files and talk as the user's identity. So:

- **Listens on `127.0.0.1:4711` by default** (eMule's web interface port). A
  non-loopback address must be asked for in the config, and then needs either
  a TLS certificate and key or `behind_proxy = true` for a reverse proxy that
  terminates TLS. Ember refuses to start otherwise.
- **One administrator password,** stored as an Argon2id hash. On first run
  `emberd` writes a random one to `<data dir>/initial-password` (mode
  `0600`) and logs where, not what; `emberd passwd` sets another.
- **Sessions** are random tokens in an `HttpOnly`, `SameSite=Strict` cookie,
  `Secure` under TLS, expiring after a period without use.
- **Every request is checked:** a session or an API token for every route,
  the WebSocket upgrade included; the `Origin` header must be the server's
  own; state-changing requests also need a custom header, which a cross-site
  form cannot send. There are no CORS headers.
- **Logins are rate-limited** per address, with a growing delay.
- **API tokens** for the command line and scripts, kept in a file only the
  service user can read.
- **The interface's listener is the one socket outside `net_bind`,** on
  purpose: it is for the administrator, not the networks, and must stay on
  loopback or the LAN even when *Connect through* keeps everything else on a
  VPN.
- Logins, failed logins and file deletions are logged.

### Folders and files

The desktop app never lets the webview name a folder to write to or share.
Folders count only once a native dialog or the share browser picked them, and
`ApprovedRootRegistry` (`security/filesystem.rs`) records each by file
identity, in `approved_roots.json`, and checks it on every open, write, rename
and delete. The server keeps every one of those checks, and replaces only how a
folder gets approved:

- **The operator names the folders** in the config file: the download folder,
  the shared folders, and optionally `browse_under`, folders inside which the
  browser may pick more to share.
- **At startup** the server writes them into the settings and approves them
  with `initialize_approved_roots_with_additions`, as an eMule import and a
  backup restore already do, before anything is indexed.
- **From the browser,** with `browse_under` set, the share browser lists only
  what is inside those folders, and its selection is approved as it is after
  the desktop's confirmation; folders shared that way can be unshared there
  too. The download folder and the folders the config names change only in
  the config (see [Decisions](#decisions)).
- **Fetching a finished file** is `GET /api/files/{id}` by library or transfer
  id, never by path, through the same handle-bound open, sent as an
  attachment with `X-Content-Type-Options: nosniff`, so a downloaded HTML file
  is never shown as a page.
- **Backups** download as a file and restore from an uploaded one; **eMule
  import** takes the eMule folder from the command line.
- **The IP filter, a collection, or a web services list** from a file is an
  upload in the browser, read from memory, never written where it was named.

The system-folder refusals the desktop applies (the system drive, the profile,
Ember's own data folder) apply to the config's folders too, with `/` and
`/etc`, `/proc`, `/sys` and `/dev` added for Linux.

### Startup and shutdown

`ember-core::start(options, host)` does what the `.setup` closure does today
that a server needs, in the same order: the data folder and a pending restore,
the database, the config, the identity, the eMule import, `net_bind`, the
approved roots, the security policy gate, the spam filter and caches, the
library scan, `start_network`, and the bandwidth refill. The desktop calls it
inside `.setup` and adds what only it has: the tray, the window, deep links, the
`ember-media` protocol, the WebView's media scope and login-at-start. The
server calls it from `main`.

Two parts are split rather than moved:

- **`background::spawn`** keeps the schedule, disk-space and upload-quota work
  in the core; keep-awake, the tray tooltip, the taskbar badge and *When
  downloads finish* stay on the desktop.
- **The update scheduler** only checks on the server, and the web UI says when
  a release is out. Installing is the package manager's or Docker's job.

The server holds a lock file in the data folder in place of the single-instance
plugin, and `EMBER_DATA_DIR` keeps working as it does now.

**Shutdown:** SIGTERM or SIGINT calls `run_graceful_shutdown` directly, which
`session_end.rs` reaches today through `app.exit(0)`: hashing stops, the
network task saves `nodes.dat`, `known.met`, credits and the rest (it is given
up to 45 seconds), then the upload queue and spam filter are saved and the
database is marked clean. The systemd unit sets `TimeoutStopSec=60` and the
Docker example `stop_grace_period: 60s`, so neither kills Ember mid-save.

**Logs** go to standard output as now, where journald and Docker collect them,
and to `<data dir>/logs` unless `log_files = false`.

**GeoIP:** the server embeds the database in its binary, so it has no resource
folder to find.

### Keys at rest

`secret_store.rs` protects `identity.json` and `cryptkey.dat`. On Linux it
keeps the wrapping key in the system keyring, and falls back to a key derived
from `/etc/machine-id` and the uid when no keyring answers. A server rarely
runs a keyring, so it would use the fallback and warn, which works. But a
container often has no machine-id at all, and then sealing fails closed:
Ember could not create its identity.

So the server takes a **key file**: 32 random bytes, named in the config or
passed as a systemd credential (`LoadCredential=`) or Docker secret, recorded
as a key source of its own in the sealed file's header. Kept on the same volume
as the data, it protects no more than the machine-id key does; its worth is
that a container starts at all and the data volume can move to another host. The
docs will say to mount it separately.

## Features by build

**Dropped on the server,** with what stands in:

- The tray, close to tray, start minimized or maximized, the remembered window
  position and the splash screen.
- The popped-out chat window: chat stays in the page.
- Start at login: the systemd unit or Docker's restart policy.
- Desktop notifications: the browser's, while the page is open and allowed.
- Watching the clipboard for links, and opening `ed2k://` links from other
  programs: an *Add links* box, and `emberd ctl add <link>`.
- Keeping the computer awake, and *When downloads finish* (exit or sleep).
- Showing friends *Away* after idle time: the status is set by hand.
- *Open file*, *Show in folder*, *Open log folder* and preview in an external
  player: downloading the file, and playing audio and video in the browser.
- Native file and folder pickers: the config file, and uploads.
- Silent updates, the update watchdog and the in-app installer: the package
  manager and Docker images. *An update is available* stays.
- The Windows Firewall fix in the Connection Doctor, and the AppImage emoji
  font workaround.
- Dragging files from the desktop onto the Library.

**Changed:** choosing folders, backups, eMule import and file imports (see
[Folders and files](#folders-and-files)); key storage (see
[Keys at rest](#keys-at-rest)); UPnP stays available but is usually off on a
server.

**The same:** everything else, as listed under
[What the user gets](#what-the-user-gets).

## Configuration

```toml
# /etc/ember/emberd.toml
data_dir = "/var/lib/ember"
key_file = "/run/credentials/emberd.service/ember-key"

[web]
listen = "127.0.0.1:4711"
# tls_cert = "/etc/ember/cert.pem"
# tls_key = "/etc/ember/key.pem"
# behind_proxy = true

[folders]
download = "/srv/ember/downloads"
shared = ["/srv/ember/share"]
# browse_under = ["/srv/media"]
```

Only what the operator owns is in this file. Every other setting is in
`config.json` as on the desktop, and changed from the web UI.

## Implementation order

Steps 1 to 5 change no behavior, and each lands with the desktop tests passing.

1. **Host trait.** Add `Host`, implement it on `AppHandle`, and replace
   `AppHandle` with it in the network, sharing and storage code.
2. **Untangle the core from `commands`.** Move the 82 helpers the core
   borrows (coded errors, `emit_transfer_status`, settings saves, path helpers)
   into the core.
3. **Startup and shutdown as functions.** Lift the core steps of `.setup`
   into `ember-core::start`, and split `background::spawn`.
4. **Command bodies on `&Ctx`.** Move each body out of its `#[tauri::command]`,
   generate the wrappers from the one command list, and add the parity test.
5. **Split the crates.** `ember-core` without Tauri, and CI building and
   testing it alone.
6. **`emberd` without a web UI.** Config, key file, lock file, signals,
   logs, the HTTP interface with API tokens, and the command line: `amuled`
   and `amulecmd`. Published as test builds only, not as a release (see
   [Decisions](#decisions)).
7. **The web UI.** The shims, the `isServer` gating, the login page, the media
   and file routes, and the security headers.
8. **Packaging.** The `.deb` with its systemd unit, the Docker image, docs on
   the website, and a release workflow.
9. **Hardening.** A security review of the interface, fuzzing its request
   parsing, and the rate limits under load.

## Testing

- The Rust suite runs against both builds, and CI checks with `cargo tree`
  that `ember-core` has no Tauri dependency.
- The command-list parity test, and a test that every command the server
  offers takes no desktop-only argument.
- Interface tests start `emberd` on loopback with a scratch data folder:
  without a session every route, the WebSocket included, refuses; a wrong
  `Origin` or a missing custom header refuses; repeated failed logins slow down;
  a command's answer and its coded error match the desktop's.
- The folder rules: a path outside the configured folders is refused for
  every file route; `browse_under` cannot be left with `..` or a symbolic link.
- The vitest suite also runs with the web runtime, with tests for the shims.
- A Docker smoke test: start the container, log in, add a link, stop it, and
  check that it shut down clean (`mark_clean_shutdown`) with `nodes.dat`
  saved.

## Decisions

These were the open questions. Each is settled here with its reason, so it is
not reopened without a new one.

- **The name is `emberd`:** the binary, the package, the systemd unit and the
  Docker image, with `emberd ctl` for the command line and `emberd passwd` for
  the password. In Ember, *server* already means an eD2K server (Settings →
  Servers, `server.met`) or the Rendezvous server (`rendezvous-server`), so
  `ember-server` would read as one of those. A trailing `d` is what Linux
  administrators expect of a daemon, and what aMule's `amuled` taught eMule's
  users.
- **The first release includes the web UI.** The command-line build (step 6)
  goes out as test builds only, to try the daemon's startup, shutdown and keys
  on real servers. The people asking for this run it on a machine they reach
  over the network, and from a command line they could only manage downloads:
  search, friends, chat, rooms and feeds need the pages. The web UI is also the
  cheaper half, being the desktop UI already written, and the login it needs
  guards the command line's interface as well.
- **Linux only at first, with no Windows or macOS server.** The requests are
  for Linux machines, NAS boxes and Docker, and the Docker image also covers
  Synology, Unraid and TrueNAS. On Windows the desktop app already starts at
  login, sits in the tray and updates itself silently, which is most of what a
  Windows user wants from a server; a Windows service would add a service
  wrapper, session 0's differences and another installer to test. `emberd`
  keeps nothing Linux-only outside its service glue, so either can be added
  when someone needs it.
- **The desktop app does not offer the web interface yet.** Turning it on would
  put a network service on the computer that holds the user's own files, and
  the reason to do it, using Ember from a phone, is met by running `emberd` at
  home. Once `emberd`'s interface has had its security review and some months
  of use, the desktop can link the same crate behind a switch: off by default,
  on the local network only, and with no more power over folders than the web
  pages have.
- **The browser can share and unshare folders inside `browse_under`, and
  nothing more.** Sharing only reads files, and `browse_under`, empty unless the
  operator sets it, bounds what a stolen session could publish. The download
  folder is where files from strangers are written, so it changes only in the
  config, as do `browse_under` itself and the shared folders the config names.
  Those show in the browser as set in the config, and cannot be unshared there:
  the next start would share them again, and the page would have been wrong.
