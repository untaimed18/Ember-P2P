use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::info;

const ENTRY_TTL: Duration = Duration::from_secs(300);
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const MAX_REQUESTS_PER_MINUTE: u64 = 60;
const RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_STORE_ENTRIES: usize = 100_000;

#[derive(Clone)]
struct PresenceEntry {
    ip: IpAddr,
    port: u16,
    conn_ip: IpAddr,
    expires_at: Instant,
}

#[derive(Clone)]
struct RateEntry {
    count: u64,
    window_start: Instant,
}

#[derive(Clone)]
struct AppState {
    store: Arc<RwLock<HashMap<String, PresenceEntry>>>,
    rate_limits: Arc<RwLock<HashMap<IpAddr, RateEntry>>>,
}

#[derive(Deserialize)]
struct RegisterRequest {
    id: String,
    port: u16,
    ip: Option<String>,
}

#[derive(Serialize)]
struct LookupResponse {
    ip: String,
    port: u16,
}

#[derive(Deserialize)]
struct UnregisterRequest {
    id: String,
}

fn extract_client_ip(headers: &HeaderMap, addr: SocketAddr) -> IpAddr {
    // Only trust proxy headers when running behind a reverse proxy (e.g. Fly.io).
    // Set TRUST_PROXY=false to disable when running without a proxy.
    let trust_proxy = std::env::var("TRUST_PROXY")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(false);

    if trust_proxy {
        if let Some(val) = headers.get("fly-client-ip") {
            if let Ok(s) = val.to_str() {
                if let Ok(ip) = s.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
        if let Some(val) = headers.get("x-forwarded-for") {
            if let Ok(s) = val.to_str() {
                if let Some(first) = s.split(',').next() {
                    if let Ok(ip) = first.trim().parse::<IpAddr>() {
                        return ip;
                    }
                }
            }
        }
    }
    addr.ip()
}

async fn check_rate_limit(state: &AppState, ip: IpAddr) -> bool {
    let mut limits = state.rate_limits.write().await;
    let now = Instant::now();
    let entry = limits.entry(ip).or_insert(RateEntry {
        count: 0,
        window_start: now,
    });
    if now.duration_since(entry.window_start) >= RATE_WINDOW {
        entry.count = 1;
        entry.window_start = now;
        true
    } else {
        entry.count += 1;
        entry.count <= MAX_REQUESTS_PER_MINUTE
    }
}

fn validate_hex_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> StatusCode {
    if !validate_hex_id(&body.id) {
        return StatusCode::BAD_REQUEST;
    }
    if body.port == 0 {
        return StatusCode::BAD_REQUEST;
    }

    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }

    let presence_ip = body.ip
        .as_deref()
        .and_then(|s| s.parse::<IpAddr>().ok())
        .filter(|ip| match ip {
            IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_unspecified()
                && !v4.is_private() && !v4.is_link_local(),
            IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
        })
        .unwrap_or(client_ip);

    let entry = PresenceEntry {
        ip: presence_ip,
        port: body.port,
        conn_ip: client_ip,
        expires_at: Instant::now() + ENTRY_TTL,
    };

    let mut store = state.store.write().await;
    if store.len() >= MAX_STORE_ENTRIES {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    let key = body.id.to_lowercase();
    if let Some(existing) = store.get(&key) {
        if existing.conn_ip != client_ip && existing.expires_at > Instant::now() {
            return StatusCode::FORBIDDEN;
        }
    }
    store.insert(key, entry);
    info!("registered {} ip={} (conn={})", &body.id[..8], presence_ip, client_ip);
    StatusCode::OK
}

async fn lookup(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<LookupResponse>, StatusCode> {
    if !validate_hex_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let store = state.store.read().await;
    match store.get(&id.to_lowercase()) {
        Some(entry) if entry.expires_at > Instant::now() => {
            info!("lookup hit {} from {}", &id[..8], client_ip);
            Ok(Json(LookupResponse {
                ip: entry.ip.to_string(),
                port: entry.port,
            }))
        }
        _ => {
            info!("lookup miss {} from {}", &id[..8], client_ip);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

async fn unregister(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<UnregisterRequest>,
) -> StatusCode {
    if !validate_hex_id(&body.id) {
        return StatusCode::BAD_REQUEST;
    }

    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }

    let mut store = state.store.write().await;
    if let Some(entry) = store.get(&body.id.to_lowercase()) {
        if entry.conn_ip == client_ip || entry.ip == client_ip {
            store.remove(&body.id.to_lowercase());
            info!("unregistered {} from {}", &body.id[..8], client_ip);
            return StatusCode::OK;
        }
        return StatusCode::FORBIDDEN;
    }
    StatusCode::NOT_FOUND
}

async fn health() -> &'static str {
    "ok"
}

async fn sweep_expired(state: AppState) {
    loop {
        tokio::time::sleep(SWEEP_INTERVAL).await;
        let now = Instant::now();
        let mut store = state.store.write().await;
        let before = store.len();
        store.retain(|_, entry| entry.expires_at > now);
        let removed = before - store.len();
        if removed > 0 {
            info!("swept {} expired entries, {} remain", removed, store.len());
        }

        let mut limits = state.rate_limits.write().await;
        limits.retain(|_, entry| now.duration_since(entry.window_start) < RATE_WINDOW * 2);
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ember_rendezvous=info".into()),
        )
        .init();

    let state = AppState {
        store: Arc::new(RwLock::new(HashMap::new())),
        rate_limits: Arc::new(RwLock::new(HashMap::new())),
    };

    tokio::spawn(sweep_expired(state.clone()));

    let app = Router::new()
        .route("/register", post(register))
        .route("/lookup/{id}", get(lookup))
        .route("/unregister", delete(unregister))
        .route("/health", get(health))
        .with_state(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("rendezvous server listening on {}", addr);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to {addr}: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        eprintln!("Server error: {e}");
        std::process::exit(1);
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let term = signal(SignalKind::terminate());
        let int = signal(SignalKind::interrupt());
        match (term, int) {
            (Ok(mut term), Ok(mut int)) => {
                tokio::select! {
                    _ = term.recv() => {},
                    _ = int.recv() => {},
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                tracing::warn!("Failed to register signal handler: {e}, falling back to ctrl_c");
                tokio::signal::ctrl_c().await.ok();
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }
    info!("shutdown signal received");
}
