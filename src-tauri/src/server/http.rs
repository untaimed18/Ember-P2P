//! `emberd`'s web interface: the web UI's files, the login, the commands
//! (`POST /api/invoke/{command}`), the events (`GET /api/events`, a
//! WebSocket) and the library's media (`GET /api/media/{path}`).
//!
//! Every route but the files, the health check and the login pages needs a
//! session cookie or a token. A request that changes anything also has to
//! come from the web UI itself: it carries `X-Ember-Request`, which a form on
//! another site cannot send, and an `Origin` naming this server, if any.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path as UrlPath, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use futures::FutureExt;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast::error::RecvError;

use super::auth::{Auth, Refusal};
use crate::host::{AppHandle, Handler, Invoke, InvokeError};

const SESSION_COOKIE: &str = "emberd_session";
/// The header the web UI sends with every request that changes something.
const REQUEST_HEADER: &str = "x-ember-request";
/// Largest request body: a command's arguments, or an uploaded list.
const MAX_BODY: usize = 64 * 1024 * 1024;
/// How often an open event stream checks that its session still holds.
const SESSION_RECHECK: Duration = Duration::from_secs(60);
/// The close code that tells the web UI it fell behind and should read its
/// state afresh, rather than that it was logged out.
const CLOSE_BEHIND: u16 = 4000;
const CLOSE_LOGGED_OUT: u16 = 4001;

pub struct Web {
    app: AppHandle,
    auth: Arc<Auth>,
    commands: HashMap<&'static str, Handler>,
    /// The Content-Security-Policy, with the hashes of `index.html`'s own
    /// scripts.
    csp: HeaderValue,
    tls: bool,
    /// Served over plain HTTP to more than this computer.
    exposed_plain: bool,
    /// Turns at checking a password; see [`PASSWORD_WORK`].
    password_work: Arc<tokio::sync::Semaphore>,
}

/// Password checks at once. Argon2 takes a moment and 19 MiB each time, so a
/// flood of logins waits its turn rather than taking the server's memory.
const PASSWORD_WORK: usize = 2;
/// How long a login waits for its turn before it is told to try again.
const PASSWORD_WAIT: Duration = Duration::from_secs(20);
/// Largest login, setup or password change: a password is at most 1 KiB.
const SMALL_BODY: usize = 16 * 1024;
/// Connections to the web interface at once, so it cannot take the file
/// handles Ember's networks need.
const MAX_CONNECTIONS: usize = 256;
/// The same for the control socket, which a script may hold open beside the
/// pages; its own count, so neither can crowd the other out.
#[cfg(unix)]
const MAX_CONTROL_CONNECTIONS: usize = 64;
/// How long a connection has to send its request's headers, and a TLS
/// handshake to finish, so a client that never does lets its connection go.
const HEADER_WAIT: Duration = Duration::from_secs(30);
const TLS_WAIT: Duration = Duration::from_secs(15);

async fn password_turn(web: &Web) -> Option<tokio::sync::OwnedSemaphorePermit> {
    tokio::time::timeout(PASSWORD_WAIT, web.password_work.clone().acquire_owned()).await.ok()?.ok()
}

fn busy() -> Response {
    refuse(StatusCode::SERVICE_UNAVAILABLE, "server_busy", "emberd is busy; try again in a moment")
}

/// The whole of a login's, setup's or password change's small body within
/// this long, read before anyone has signed in: a client trickling one in
/// would hold its connection for good.
const SMALL_BODY_WAIT: Duration = Duration::from_secs(20);

async fn small_body_in_time(request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    match tokio::time::timeout(SMALL_BODY_WAIT, axum::body::to_bytes(body, SMALL_BODY)).await {
        Ok(Ok(bytes)) => next.run(Request::from_parts(parts, Body::from(bytes))).await,
        Ok(Err(_)) => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        Err(_) => busy(),
    }
}

/// The web UI's `index.html` boots with an inline script, which a policy
/// without its hash would block, as Tauri's own build adds it for the window.
fn content_security_policy(web_root: &Path) -> HeaderValue {
    let index = std::fs::read_to_string(web_root.join("index.html")).unwrap_or_default();
    let mut hashes = String::new();
    let mut rest = index.as_str();
    while let Some(open) = rest.find("<script") {
        let after = &rest[open..];
        let Some(tag_end) = after.find('>') else { break };
        let tag = &after[..tag_end];
        let body_start = tag_end + 1;
        let Some(close) = after[body_start..].find("</script>") else { break };
        let body = &after[body_start..body_start + close];
        if !tag.contains("src=") && !body.trim().is_empty() {
            let digest = Sha256::digest(body.as_bytes());
            hashes.push_str(&format!(" 'sha256-{}'", base64::engine::general_purpose::STANDARD.encode(digest)));
        }
        rest = &after[body_start + close..];
    }
    let policy = format!(
        "default-src 'self'; script-src 'self'{hashes}; style-src 'self' 'unsafe-inline'; style-src-elem 'self'; \
         img-src 'self' data:; media-src 'self'; connect-src 'self'; base-uri 'self'; object-src 'none'; \
         frame-ancestors 'none'; form-action 'none'; worker-src 'none'"
    );
    HeaderValue::from_str(&policy).unwrap_or_else(|_| HeaderValue::from_static("default-src 'self'"))
}

impl Web {
    pub fn new(app: AppHandle, auth: Arc<Auth>, config: &super::config::Config) -> Self {
        let commands = crate::command_table::SERVER_COMMANDS.iter().copied().collect();
        Web {
            app,
            auth,
            commands,
            csp: content_security_policy(&config.web_root),
            tls: config.tls.is_some(),
            exposed_plain: config.tls.is_none() && !config.loopback_only(),
            password_work: Arc::new(tokio::sync::Semaphore::new(PASSWORD_WORK)),
        }
    }
}

type Shared = Arc<Web>;

pub fn router(web: Shared, web_root: &Path) -> Router {
    let index = web_root.join("index.html");
    let files = tower_http::services::ServeDir::new(web_root)
        .append_index_html_on_directories(true)
        .fallback(tower_http::services::ServeFile::new(index));
    Router::new()
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/session", get(session))
        .route("/api/setup", post(set_up).layer(DefaultBodyLimit::max(SMALL_BODY)).layer(middleware::from_fn(small_body_in_time)))
        .route("/api/login", post(log_in).layer(DefaultBodyLimit::max(SMALL_BODY)).layer(middleware::from_fn(small_body_in_time)))
        .route("/api/logout", post(log_out))
        .route(
            "/api/password",
            post(change_password).layer(DefaultBodyLimit::max(SMALL_BODY)).layer(middleware::from_fn(small_body_in_time)),
        )
        .route("/api/restart", post(restart))
        .route("/api/invoke/{command}", post(invoke))
        .route("/api/events", get(events))
        .route("/api/media/{*path}", get(media))
        .route("/api/file/{*path}", get(download))
        .route("/api/saved/{id}", get(saved))
        .route("/api/backup", get(download_backup).post(upload_backup))
        .route("/api/upload", post(upload))
        .fallback_service(files)
        .layer(middleware::from_fn_with_state(web.clone(), guard))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(web)
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value.to_string())
        .filter(|v| !v.is_empty())
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Whether the request's `Origin`, if it has one, is this server: the `Host`
/// it was sent to, or, from a proxy on this computer, the host the proxy says
/// the browser asked for. nginx and Apache pass their own upstream address as
/// `Host` unless told otherwise.
fn same_origin(headers: &HeaderMap, via_local_proxy: bool) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let authority = origin.split_once("://").map(|(_, rest)| rest).unwrap_or("");
    let names = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .is_some_and(|host| !authority.is_empty() && authority.eq_ignore_ascii_case(host.trim()))
    };
    names(header::HOST.as_str()) || (via_local_proxy && names("x-forwarded-host"))
}

fn refuse(status: StatusCode, code: &'static str, message: &str) -> Response {
    (status, Json(json!({ "error": crate::commands::errors::coded(code, message) }))).into_response()
}

/// How a request was let in.
#[derive(Clone)]
enum Caller {
    Session(String),
    Token,
}

/// Marks a request that came in on the control socket (`emberd ctl`). Only
/// emberd's own user, or its group under systemd, can open that socket, the
/// same people who can read the API token, so it counts as the token.
#[derive(Clone, Copy)]
struct ControlSocket;

/// Security headers on everything, the session or token on what needs one,
/// and the same-site checks on what changes anything.
async fn guard(State(web): State<Shared>, mut request: Request, next: Next) -> Response {
    let path = request.uri().path().to_string();
    let api = path.starts_with("/api/");
    let public = matches!(path.as_str(), "/api/health" | "/api/session" | "/api/setup" | "/api/login");
    let control = request.extensions().get::<ControlSocket>().is_some();
    let headers = request.headers();
    let changes = request.method() != Method::GET && request.method() != Method::HEAD;
    let bearer = bearer_token(headers);

    if api {
        // A token is for scripts, which send no cookies a page could abuse.
        let caller = match (&bearer, cookie_token(headers)) {
            _ if control => Some(Caller::Token),
            (Some(token), _) if web.auth.api_token_valid(token) => Some(Caller::Token),
            (Some(_), _) => None,
            (None, Some(token)) if web.auth.session_valid(&token) => Some(Caller::Session(token)),
            _ => None,
        };
        let from_page = !matches!(caller, Some(Caller::Token));
        let via_local_proxy = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .is_some_and(|ConnectInfo(peer)| peer.ip().is_loopback());
        if from_page && !same_origin(headers, via_local_proxy) {
            return refuse(StatusCode::FORBIDDEN, "server_cross_origin", "That request came from another site");
        }
        if from_page && changes && headers.get(REQUEST_HEADER).is_none() {
            return refuse(StatusCode::FORBIDDEN, "server_cross_origin", "That request did not come from Ember's page");
        }
        if !public {
            match caller {
                Some(caller) => {
                    request.extensions_mut().insert(caller);
                }
                None => return refuse(StatusCode::UNAUTHORIZED, "server_login_required", "Log in to Ember first"),
            }
        }
    }

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, web.csp.clone());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    let html = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/html"));
    if api || html {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

fn session_cookie(web: &Web, token: &str) -> HeaderValue {
    let secure = if web.tls { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000{secure}"
    ))
    .unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn cleared_cookie() -> HeaderValue {
    HeaderValue::from_static("emberd_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

fn signed_in(web: &Web, token: &str) -> Response {
    let mut response = Json(json!({ "ok": true })).into_response();
    response.headers_mut().insert(header::SET_COOKIE, session_cookie(web, token));
    response
}

fn refusal(refusal: Refusal) -> Response {
    match refusal {
        Refusal::Wrong => refuse(StatusCode::UNAUTHORIZED, "server_wrong_password", "That is not the password"),
        Refusal::WrongSetupCode => refuse(
            StatusCode::UNAUTHORIZED,
            "server_wrong_setup_code",
            "That is not the setup code; emberd prints it in its log",
        ),
        Refusal::Wait(wait) => {
            let mut response = refuse(
                StatusCode::TOO_MANY_REQUESTS,
                "server_login_wait",
                "Too many wrong tries; wait a little and try again",
            );
            let secs = wait.as_secs().max(1).to_string();
            if let Ok(value) = HeaderValue::from_str(&secs) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        Refusal::WrongStep => refuse(StatusCode::CONFLICT, "server_wrong_step", "Reload the page and try again"),
        Refusal::Invalid(code) => refuse(StatusCode::BAD_REQUEST, code, "That password cannot be used"),
    }
}

/// What the page needs before anything else: whether to show the app, the
/// login, or the first-run setup.
async fn session(State(web): State<Shared>, headers: HeaderMap) -> Json<Value> {
    let authenticated = cookie_token(&headers).is_some_and(|token| web.auth.session_valid(&token));
    Json(json!({
        "authenticated": authenticated,
        "setup_required": !web.auth.password_set(),
        "unencrypted": web.exposed_plain,
        "min_password_chars": super::auth::MIN_PASSWORD_CHARS,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[derive(Deserialize)]
struct SetUpBody {
    code: String,
    password: String,
}

async fn set_up(State(web): State<Shared>, ConnectInfo(peer): ConnectInfo<SocketAddr>, Json(body): Json<SetUpBody>) -> Response {
    let ip = peer.ip();
    let auth = web.auth.clone();
    let Some(turn) = password_turn(&web).await else {
        return busy();
    };
    match tokio::task::spawn_blocking(move || {
        let _turn = turn;
        auth.set_up(ip, &body.code, &body.password)
    })
    .await
    {
        Ok(Ok(token)) => {
            tracing::info!("The web interface's password was set from {ip}");
            signed_in(&web, &token)
        }
        Ok(Err(e)) => refusal(e),
        Err(_) => refuse(StatusCode::INTERNAL_SERVER_ERROR, "server_internal", "Something went wrong"),
    }
}

#[derive(Deserialize)]
struct LogInBody {
    password: String,
}

async fn log_in(State(web): State<Shared>, ConnectInfo(peer): ConnectInfo<SocketAddr>, Json(body): Json<LogInBody>) -> Response {
    let ip = peer.ip();
    let auth = web.auth.clone();
    let Some(turn) = password_turn(&web).await else {
        return busy();
    };
    match tokio::task::spawn_blocking(move || {
        let _turn = turn;
        auth.log_in(ip, &body.password)
    })
    .await
    {
        Ok(Ok(token)) => {
            tracing::info!("Logged in to the web interface from {ip}");
            signed_in(&web, &token)
        }
        Ok(Err(e)) => {
            if e == Refusal::Wrong {
                tracing::warn!("A wrong password was given to the web interface from {ip}");
            }
            refusal(e)
        }
        Err(_) => refuse(StatusCode::INTERNAL_SERVER_ERROR, "server_internal", "Something went wrong"),
    }
}

async fn log_out(State(web): State<Shared>, caller: Option<axum::Extension<Caller>>) -> Response {
    if let Some(axum::Extension(Caller::Session(token))) = caller {
        web.auth.log_out(&token);
    }
    let mut response = Json(json!({ "ok": true })).into_response();
    response.headers_mut().insert(header::SET_COOKIE, cleared_cookie());
    response
}

#[derive(Deserialize)]
struct PasswordBody {
    current: String,
    new: String,
}

async fn change_password(
    State(web): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    axum::Extension(caller): axum::Extension<Caller>,
    Json(body): Json<PasswordBody>,
) -> Response {
    let ip = peer.ip();
    let auth = web.auth.clone();
    let keep = match caller {
        Caller::Session(token) => Some(token),
        Caller::Token => None,
    };
    let Some(turn) = password_turn(&web).await else {
        return busy();
    };
    let changed = tokio::task::spawn_blocking(move || {
        let _turn = turn;
        auth.change_password(ip, &body.current, &body.new, keep.as_deref())
    });
    match changed.await {
        Ok(Ok(token)) => {
            tracing::info!("The web interface's password was changed from {ip}");
            match token {
                Some(token) => signed_in(&web, &token),
                None => Json(json!({ "ok": true })).into_response(),
            }
        }
        Ok(Err(e)) => refusal(e),
        Err(_) => refuse(StatusCode::INTERNAL_SERVER_ERROR, "server_internal", "Something went wrong"),
    }
}

/// Restart Ember, as the desktop app's Restart button relaunches it: the
/// network stops cleanly and `emberd` starts again in the same process, so
/// a service manager sees nothing stop.
async fn restart(State(web): State<Shared>) -> Json<Value> {
    tracing::info!("Restarting, as the web interface asked");
    web.app.exit(super::RESTART);
    Json(json!({ "ok": true }))
}

/// One command, as the desktop app's `invoke` would call it: `{ "ok": value }`
/// or `{ "error": what the command returned }`.
async fn invoke(State(web): State<Shared>, UrlPath(command): UrlPath<String>, body: Bytes) -> Response {
    let Some(handler) = web.commands.get(command.as_str()).copied() else {
        // The web UI hides what emberd cannot do, so this is a page that
        // still offers it.
        tracing::warn!("The web UI asked for {command}, which emberd does not have");
        return refuse(
            StatusCode::NOT_FOUND,
            "server_unsupported",
            "emberd cannot do that: it has no window, tray or desktop of its own",
        );
    };
    let args = match serde_json::from_slice::<Value>(&body) {
        _ if body.is_empty() => serde_json::Map::new(),
        Ok(Value::Object(args)) => args,
        Ok(Value::Null) => serde_json::Map::new(),
        _ => return refuse(StatusCode::BAD_REQUEST, "server_bad_request", "The arguments must be a JSON object"),
    };
    let call = std::panic::AssertUnwindSafe(handler(Invoke::new(web.app.clone(), args))).catch_unwind();
    match call.await {
        Ok(Ok(value)) => Json(json!({ "ok": value })).into_response(),
        Ok(Err(InvokeError::Command(error))) => Json(json!({ "error": error })).into_response(),
        Ok(Err(InvokeError::Args(error))) => (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))).into_response(),
        Err(_) => {
            tracing::error!("Command {command} panicked");
            refuse(StatusCode::INTERNAL_SERVER_ERROR, "server_internal", "Something went wrong")
        }
    }
}

/// Every event the backend emits, for as long as the page is open and its
/// session holds.
async fn events(
    State(web): State<Shared>,
    caller: axum::Extension<Caller>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    let receiver = web.app.subscribe();
    let held = match caller.0 {
        Caller::Session(token) => StreamHolder::Session(token),
        // Changing the password replaces the API token.
        Caller::Token => match bearer_token(&headers) {
            Some(token) => StreamHolder::Token(token),
            None => StreamHolder::ControlSocket,
        },
    };
    upgrade.on_upgrade(move |socket| stream_events(web, socket, receiver, held))
}

/// What let an event stream in, checked again while it stays open.
enum StreamHolder {
    Session(String),
    Token(String),
    ControlSocket,
}

async fn stream_events(
    web: Shared,
    mut socket: WebSocket,
    mut receiver: tokio::sync::broadcast::Receiver<Arc<crate::host::Event>>,
    held: StreamHolder,
) {
    let mut recheck = tokio::time::interval(SESSION_RECHECK);
    recheck.tick().await;
    let close = |code: u16, reason: &'static str| Message::Close(Some(CloseFrame { code, reason: reason.into() }));
    loop {
        tokio::select! {
            event = receiver.recv() => match event {
                Ok(event) => {
                    let Ok(text) = serde_json::to_string(&*event) else { continue };
                    if socket.send(Message::Text(text.into())).await.is_err() {
                        return;
                    }
                }
                Err(RecvError::Lagged(_)) => {
                    let _ = socket.send(close(CLOSE_BEHIND, "behind")).await;
                    return;
                }
                Err(RecvError::Closed) => return,
            },
            incoming = socket.recv() => match incoming {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(_)) => {}
            },
            _ = recheck.tick() => {
                let gone = match &held {
                    StreamHolder::Session(token) => !web.auth.session_valid(token),
                    StreamHolder::Token(token) => !web.auth.api_token_valid(token),
                    StreamHolder::ControlSocket => false,
                };
                if gone {
                    let _ = socket.send(close(CLOSE_LOGGED_OUT, "logged out")).await;
                    return;
                }
            }
        }
    }
}

/// A library file for the browser's player, with the checks the desktop's
/// `ember-media` protocol makes (`commands::sharing::serve_media_request`).
async fn media(State(web): State<Shared>, uri: Uri, headers: HeaderMap) -> Response {
    let encoded = uri.path().strip_prefix("/api/media/").unwrap_or_default().to_string();
    let range = headers.get(header::RANGE).and_then(|v| v.to_str().ok()).map(str::to_string);
    let served = crate::commands::sharing::serve_media_request(web.app.clone(), encoded, range).await;
    let (parts, body) = served.into_parts();
    Response::from_parts(parts, Body::from(body))
}

/// A library file, saved to the browser's computer: "Save to this computer".
async fn download(State(web): State<Shared>, uri: Uri) -> Response {
    let encoded = uri.path().strip_prefix("/api/file/").unwrap_or_default();
    let Some((file, length, name)) = crate::commands::sharing::open_library_file_for_download(&web.app, encoded).await
    else {
        return refuse(StatusCode::NOT_FOUND, "server_file_unavailable", "That file is not in the Library");
    };
    saved_file(file, length, &name, None)
}

/// What a command left for the browser to save (`super::saved`), sent once.
async fn saved(uri: Uri) -> Response {
    let id = uri.path().strip_prefix("/api/saved/").unwrap_or_default();
    match super::saved::take(id) {
        Some((super::saved::Content::File(file, length), name)) => saved_file(file, length, &name, None),
        Some((super::saved::Content::Bytes(bytes), name)) => {
            let length = bytes.len() as u64;
            let mut response = Response::new(Body::from(bytes));
            attachment_headers(response.headers_mut(), length, &name);
            response
        }
        None => refuse(StatusCode::NOT_FOUND, "server_file_unavailable", "Save it again"),
    }
}

/// The headers that have the browser save a response as `name`.
fn attachment_headers(headers: &mut HeaderMap, length: u64, name: &str) {
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    if let Ok(value) = HeaderValue::from_str(&attachment(name)) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
}

/// What [`saved_file`] reads from. `then_remove` goes once the response is
/// done with it, sent in full or cut off: the server stops reading at the
/// length it announced, so the end of the file is never seen.
struct Sending {
    file: Option<tokio::fs::File>,
    then_remove: Option<std::path::PathBuf>,
}

impl Drop for Sending {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Some(path) = self.then_remove.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// A file for the browser to save as `name`, read as it is sent.
fn saved_file(file: std::fs::File, length: u64, name: &str, then_remove: Option<std::path::PathBuf>) -> Response {
    let sending = Sending { file: Some(tokio::fs::File::from_std(file)), then_remove };
    let chunks = futures::stream::unfold(sending, |mut sending| async move {
        use tokio::io::AsyncReadExt as _;
        let file = sending.file.as_mut()?;
        let mut buffer = vec![0u8; 256 * 1024];
        match file.read(&mut buffer).await {
            Ok(0) => None,
            Ok(read) => {
                buffer.truncate(read);
                Some((Ok::<_, std::io::Error>(Bytes::from(buffer)), sending))
            }
            Err(e) => {
                sending.file = None;
                Some((Err(e), sending))
            }
        }
    });
    let mut response = Response::new(Body::from_stream(chunks));
    attachment_headers(response.headers_mut(), length, name);
    response
}

/// Largest backup the web page may upload for a restore.
const MAX_BACKUP_UPLOAD: u64 = 4 * 1024 * 1024 * 1024;

/// The backup `export_backup_for_download` just made, saved to the browser's
/// computer and then removed from the server.
async fn download_backup() -> Response {
    let path = crate::storage::paths::resolve_data_dir().join(crate::commands::backup::DOWNLOAD_BACKUP);
    let opened = std::fs::File::open(&path).and_then(|file| file.metadata().map(|meta| (file, meta.len())));
    let Ok((file, length)) = opened else {
        return refuse(StatusCode::NOT_FOUND, "server_file_unavailable", "Make the backup again");
    };
    saved_file(file, length, &crate::commands::backup::backup_file_name(), Some(path))
}

/// A backup uploaded from the browser's computer, chosen for restore: the
/// Settings page then inspects and restores it as it would a picked file.
async fn upload_backup(State(web): State<Shared>, body: Body) -> Response {
    let path = crate::storage::paths::resolve_data_dir().join(crate::commands::backup::UPLOADED_BACKUP);
    match save_upload(body, &path).await {
        Ok(()) => {}
        Err(Upload::TooLarge) => return refuse(StatusCode::BAD_REQUEST, "server_upload_too_large", "That file is too large"),
        Err(Upload::Failed) => return refuse(StatusCode::BAD_REQUEST, "server_upload_failed", "The upload did not finish"),
    }
    let state = crate::host::Manager::state::<crate::app_state::AppState>(&web.app);
    match crate::commands::backup::choose_uploaded_backup(&state, &path).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))).into_response(),
    }
}

#[derive(Deserialize)]
struct UploadName {
    name: String,
}

/// A file from the browser's computer, for a command to use by the id this
/// answers with (`super::uploads`).
async fn upload(axum::extract::Query(file): axum::extract::Query<UploadName>, body: Body) -> Response {
    match super::uploads::receive(body, &file.name).await {
        Ok(id) => Json(json!({ "ok": id })).into_response(),
        Err(super::uploads::Refused::TooLarge) => {
            refuse(StatusCode::BAD_REQUEST, "server_upload_too_large", "That file is too large")
        }
        Err(super::uploads::Refused::Failed) => {
            refuse(StatusCode::BAD_REQUEST, "server_upload_failed", "The upload did not finish")
        }
    }
}

enum Upload {
    TooLarge,
    Failed,
}

/// Write an upload to `path`, readable by emberd alone, replacing any earlier
/// one only once all of it has arrived.
async fn save_upload(body: Body, path: &Path) -> Result<(), Upload> {
    use futures::StreamExt as _;
    use tokio::io::AsyncWriteExt as _;
    let partial = path.with_extension("partial");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options.open(&partial).map_err(|_| Upload::Failed)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut stream = body.into_data_stream();
    let mut total = 0u64;
    let outcome = async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| Upload::Failed)?;
            total += chunk.len() as u64;
            if total > MAX_BACKUP_UPLOAD {
                return Err(Upload::TooLarge);
            }
            file.write_all(&chunk).await.map_err(|_| Upload::Failed)?;
        }
        file.flush().await.map_err(|_| Upload::Failed)
    }
    .await;
    drop(file);
    match outcome {
        Ok(()) => tokio::fs::rename(&partial, path).await.map_err(|_| Upload::Failed),
        Err(why) => {
            let _ = tokio::fs::remove_file(&partial).await;
            Err(why)
        }
    }
}

/// `Content-Disposition` for saving `name`: an ASCII stand-in, and the real
/// name percent-encoded (RFC 6266).
fn attachment(name: &str) -> String {
    let plain: String = name
        .chars()
        .map(|c| if c.is_ascii_graphic() && c != '"' && c != '\\' || c == ' ' { c } else { '_' })
        .collect();
    let mut encoded = String::new();
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    format!("attachment; filename=\"{plain}\"; filename*=UTF-8''{encoded}")
}

/// The certificate and key for HTTPS.
fn tls_acceptor(tls: &super::config::Tls) -> Result<tokio_rustls::TlsAcceptor, String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    let certs = CertificateDer::pem_file_iter(&tls.cert)
        .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
        .map_err(|e| format!("Could not read the certificate {}: {e}", tls.cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(&tls.key)
        .map_err(|e| format!("Could not read the key {}: {e}", tls.key.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("The certificate and key do not go together: {e}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// Listen for the web interface until `shutdown` fires.
pub async fn serve(
    web: Shared,
    config: &super::config::Config,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let acceptor = config.tls.as_ref().map(tls_acceptor).transpose()?;
    // The one socket `net_bind` does not place: it is for the operator, and
    // must stay on this computer or the local network even while every
    // connection to the networks is kept on a VPN.
    #[allow(clippy::disallowed_methods)]
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|e| format!("Could not listen on {}: {e}", config.listen))?;
    let router = router(web, &config.web_root);
    let scheme = if acceptor.is_some() { "https" } else { "http" };
    tracing::info!("Web interface at {scheme}://{}", display_address(config.listen));
    #[cfg(unix)]
    serve_control_socket(
        router.clone(),
        super::control_socket_path(&crate::storage::paths::resolve_data_dir()),
        shutdown.clone(),
    );
    let connections = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    tracing::debug!("Web interface accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = shutdown.changed() => return Ok(()),
        };
        let Ok(held) = connections.clone().try_acquire_owned() else {
            tracing::debug!("Web interface turned {peer} away: {MAX_CONNECTIONS} connections open");
            continue;
        };
        let router = router.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _held = held;
            let service = tower::ServiceExt::map_request(router, move |mut request: Request<hyper::body::Incoming>| {
                request.extensions_mut().insert(ConnectInfo(peer));
                request
            });
            let service = hyper_util::service::TowerToHyperService::new(service);
            // HTTP/1 alone, as the pages speak it: the auto builder reads the
            // protocol's first bytes with no timer, so a connection that sent
            // nothing held its slot for good.
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder.timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(HEADER_WAIT);
            let result = match acceptor {
                Some(acceptor) => match tokio::time::timeout(TLS_WAIT, acceptor.accept(stream)).await {
                    Ok(Ok(tls)) => {
                        builder.serve_connection(hyper_util::rt::TokioIo::new(tls), service).with_upgrades().await
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("TLS handshake from {peer} failed: {e}");
                        return;
                    }
                    Err(_) => {
                        tracing::debug!("TLS handshake from {peer} took too long");
                        return;
                    }
                },
                None => {
                    // A request's first byte within the header wait, whenever
                    // hyper's own timer starts.
                    let mut first = [0u8; 1];
                    if !matches!(tokio::time::timeout(HEADER_WAIT, stream.peek(&mut first)).await, Ok(Ok(n)) if n > 0) {
                        return;
                    }
                    builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service).with_upgrades().await
                }
            };
            if let Err(e) = result {
                tracing::debug!("Web interface connection from {peer} ended: {e}");
            }
        });
    }
}

/// The control socket for `emberd ctl`: the web interface's routes, reached
/// as the API token reaches them, by whoever may open the socket. Without it
/// emberd runs on, with no command line.
#[cfg(unix)]
fn serve_control_socket(router: Router, path: std::path::PathBuf, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    use std::os::unix::fs::PermissionsExt;
    // Whatever is there is a socket an emberd before this one left: the
    // instance lock lets only one run on this data folder.
    let _ = std::fs::remove_file(&path);
    let listener = match tokio::net::UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::warn!("No command line: could not open {}: {e}", path.display());
            return;
        }
    };
    // systemd's runtime folder is shared with the service's group; the data
    // folder is emberd's alone.
    let mode = if std::env::var_os("RUNTIME_DIRECTORY").is_some() { 0o660 } else { 0o600 };
    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)) {
        tracing::warn!("No command line: could not restrict {}: {e}", path.display());
        let _ = std::fs::remove_file(&path);
        return;
    }
    tracing::info!("Command line (emberd ctl) at {}", path.display());
    let connections = Arc::new(tokio::sync::Semaphore::new(MAX_CONTROL_CONNECTIONS));
    tokio::spawn(async move {
        loop {
            let stream = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => stream,
                    Err(e) => {
                        tracing::debug!("Control socket accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                },
                _ = shutdown.changed() => break,
            };
            let Ok(held) = connections.clone().try_acquire_owned() else {
                tracing::debug!("Control socket turned a connection away: {MAX_CONTROL_CONNECTIONS} open");
                continue;
            };
            let router = router.clone();
            tokio::spawn(async move {
                let _held = held;
                let service = tower::ServiceExt::map_request(router, |mut request: Request<hyper::body::Incoming>| {
                    request.extensions_mut().insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
                    request.extensions_mut().insert(ControlSocket);
                    request
                });
                let service = hyper_util::service::TowerToHyperService::new(service);
                let builder = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
                if let Err(e) = builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service).await {
                    tracing::debug!("Control socket connection ended: {e}");
                }
            });
        }
        let _ = std::fs::remove_file(&path);
    });
}

/// The address to type: `localhost` for this computer.
pub fn display_address(listen: SocketAddr) -> String {
    if listen.ip().is_loopback() || listen.ip().is_unspecified() {
        format!("localhost:{}", listen.port())
    } else {
        listen.to_string()
    }
}

/// The web UI's files, if they are where `emberd` looks.
pub fn web_root_usable(web_root: &Path) -> bool {
    web_root.join("index.html").is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn only_a_page_from_this_server_counts_as_the_same_site() {
        assert!(same_origin(&headers(&[("host", "box:4711")]), false), "no Origin is a script or a same-site GET");
        assert!(same_origin(&headers(&[("host", "box:4711"), ("origin", "http://box:4711")]), false));
        assert!(same_origin(&headers(&[("host", "BOX:4711"), ("origin", "https://box:4711")]), false));
        assert!(!same_origin(&headers(&[("host", "box:4711"), ("origin", "http://evil.example")]), false));
        assert!(!same_origin(&headers(&[("host", "box:4711"), ("origin", "null")]), false));
        assert!(!same_origin(&headers(&[("origin", "http://box:4711")]), false), "no Host to match");
    }

    #[test]
    fn a_proxy_on_this_computer_may_name_the_host_the_browser_asked_for() {
        let proxied = headers(&[
            ("host", "127.0.0.1:4711"),
            ("origin", "https://ember.example.com"),
            ("x-forwarded-host", "ember.example.com"),
        ]);
        assert!(same_origin(&proxied, true));
        assert!(!same_origin(&proxied, false), "only from loopback, where the proxy is");
        let evil = headers(&[
            ("host", "127.0.0.1:4711"),
            ("origin", "https://evil.example"),
            ("x-forwarded-host", "ember.example.com"),
        ]);
        assert!(!same_origin(&evil, true));
    }

    /// Text built from what headers and names are made of, the awkward
    /// characters most of all.
    fn fuzz_text(rng: &mut rand::rngs::StdRng) -> String {
        use rand::Rng;
        const PIECES: &[&str] = &[
            ";", "=", ":", " ", "\"", "\\", "/", "%", "%2F", "%00", "\r\n", "\t", "\0", "é", "漢", "🙂", "\u{202e}",
            "emberd_session=", "Bearer ", "http://", "://", "localhost:4711", "..",
        ];
        let mut text = String::new();
        for _ in 0..rng.gen_range(0..24) {
            if rng.gen_bool(0.6) {
                text.push_str(PIECES[rng.gen_range(0..PIECES.len())]);
            } else {
                text.push(char::from_u32(rng.gen_range(0..0x3000)).unwrap_or('x'));
            }
        }
        text
    }

    /// What a request with no session reaches: its cookies, its token, its
    /// Origin, and the name a saved file goes by.
    #[test]
    fn request_parsing_fuzz_never_panics() {
        let mut rng = crate::fuzz::rng(0xE3BE_D001);
        for _ in 0..crate::fuzz::rounds(4_000) {
            let text = fuzz_text(&mut rng);
            let mut map = HeaderMap::new();
            if let Ok(value) = HeaderValue::from_bytes(text.as_bytes()) {
                for name in [header::COOKIE, header::AUTHORIZATION, header::ORIGIN, header::HOST] {
                    map.insert(name, value.clone());
                }
            }
            let _ = cookie_token(&map);
            let _ = bearer_token(&map);
            let _ = same_origin(&map, true);
            assert!(HeaderValue::from_str(&attachment(&text)).is_ok(), "{text:?}");
            let _ = super::super::auth::normalize_code(&text);
            let name = super::super::uploads::safe_name(&text);
            assert!(!name.is_empty() && !name.contains(['/', '\\']) && name != "." && name != "..", "{text:?} -> {name:?}");
            let _ = crate::commands::sharing::percent_decode_path(&text);
        }
    }

    #[test]
    fn a_saved_file_keeps_its_name_and_cannot_break_the_header() {
        assert_eq!(
            attachment("Movie (2001).mkv"),
            "attachment; filename=\"Movie (2001).mkv\"; filename*=UTF-8''Movie%20%282001%29.mkv"
        );
        assert_eq!(
            attachment("a\"b\\c\r\nd é.txt"),
            "attachment; filename=\"a_b_c__d _.txt\"; filename*=UTF-8''a%22b%5Cc%0D%0Ad%20%C3%A9.txt"
        );
        assert!(HeaderValue::from_str(&attachment("x\u{0}y\n")).is_ok());
    }

    #[test]
    fn the_session_cookie_is_found_among_others() {
        let map = headers(&[("cookie", "theme=dark; emberd_session=abc123; other=1")]);
        assert_eq!(cookie_token(&map).as_deref(), Some("abc123"));
        assert_eq!(cookie_token(&headers(&[("cookie", "emberd_session=")])), None);
        assert_eq!(bearer_token(&headers(&[("authorization", "Bearer tok")])).as_deref(), Some("tok"));
    }

    #[test]
    fn the_policy_lets_index_html_boot_and_nothing_inline_else() {
        let dir = std::env::temp_dir().join(format!("emberd-csp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("index.html"),
            "<html><script src=\"/a.js\"></script><script>\n  boot();\n</script></html>",
        )
        .unwrap();
        let policy = content_security_policy(&dir);
        let policy = policy.to_str().unwrap();
        let expected = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(b"\n  boot();\n"));
        assert!(policy.contains(&format!("'sha256-{expected}'")), "{policy}");
        assert!(policy.contains("frame-ancestors 'none'"));
        assert_eq!(policy.matches("sha256-").count(), 1, "the src script needs no hash");
        let _ = std::fs::remove_dir_all(dir);
    }
}
