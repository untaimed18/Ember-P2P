//! Who may use `emberd`'s web interface: one administrator, by password.
//!
//! The password is kept as an Argon2id hash in `emberd-auth.json` in the data
//! folder, beside the sessions it opened (by the SHA-256 of their tokens,
//! never the tokens). With no password yet, the first visit asks for a setup
//! code, which `emberd` writes to its log and to `emberd-setup-code` in the
//! data folder: only someone who can read either can choose the password.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use argon2::password_hash::{rand_core::OsRng as HashRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const AUTH_FILE: &str = "emberd-auth.json";
pub const SETUP_CODE_FILE: &str = "emberd-setup-code";
/// A token for scripts on this computer, readable by the service's user.
pub const CLI_TOKEN_FILE: &str = "emberd-cli-token";

/// A session unused this long has to log in again.
const SESSION_IDLE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Most sessions kept at once; the least recently used go first.
const MAX_SESSIONS: usize = 64;
/// Shortest password accepted.
pub const MIN_PASSWORD_CHARS: usize = 8;
/// Longest password accepted, to keep hashing bounded.
pub const MAX_PASSWORD_BYTES: usize = 1024;
/// Failed logins from one address before each further try waits.
const FREE_FAILURES: u32 = 3;
/// The longest wait between tries.
const MAX_WAIT: Duration = Duration::from_secs(300);

#[derive(Default, Serialize, Deserialize)]
struct Stored {
    password: Option<String>,
    #[serde(default)]
    sessions: Vec<StoredSession>,
    #[serde(default)]
    tokens: Vec<StoredToken>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredSession {
    hash: String,
    created: i64,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredToken {
    hash: String,
    name: String,
}

struct Failures {
    count: u32,
    last: Instant,
}

/// The most addresses whose wrong passwords are counted at once.
const MAX_TRACKED: usize = 4096;

/// Whose wrong passwords count together: an IPv4 address, or an IPv6
/// network's /64, which one connection usually has all of to choose from.
fn throttle_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                IpAddr::V6(octets.into())
            }
        },
    }
}

struct State {
    stored: Stored,
    /// When each session was last used, this run.
    last_used: HashMap<String, Instant>,
    setup_code: Option<String>,
    failures: HashMap<IpAddr, Failures>,
}

pub struct Auth {
    dir: PathBuf,
    state: Mutex<State>,
}

/// Why a login did not go through.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Wrong,
    WrongSetupCode,
    /// Too many wrong tries from this address; try again after this long.
    Wait(Duration),
    /// A password is set already, or none is yet.
    WrongStep,
    Invalid(&'static str),
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Eight characters in two groups, from letters and digits nobody misreads.
fn random_setup_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let chars: String = bytes.iter().map(|b| ALPHABET[usize::from(*b) % ALPHABET.len()] as char).collect();
    format!("{}-{}", &chars[..4], &chars[4..])
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The setup code as typed: case and the dash do not matter.
pub(super) fn normalize_code(code: &str) -> String {
    code.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect()
}

pub fn check_new_password(password: &str) -> Result<(), Refusal> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(Refusal::Invalid("server_password_too_short"));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(Refusal::Invalid("server_password_too_long"));
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut HashRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| e.to_string())
}

fn password_matches(stored: &str, password: &str) -> bool {
    PasswordHash::new(stored)
        .map(|hash| Argon2::default().verify_password(password.as_bytes(), &hash).is_ok())
        .unwrap_or(false)
}

impl Auth {
    /// Load what the data folder holds. With no password set, a setup code is
    /// made, written beside it and returned so the caller can log it.
    pub fn load(dir: &Path) -> Result<(Self, Option<String>), String> {
        let path = dir.join(AUTH_FILE);
        let stored = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<Stored>(&bytes)
                .map_err(|e| format!("{} is not readable: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Stored::default(),
            Err(e) => return Err(format!("Could not read {}: {e}", path.display())),
        };
        let setup_code = stored.password.is_none().then(random_setup_code);
        let started = Instant::now();
        let last_used = stored.sessions.iter().map(|s| (s.hash.clone(), started)).collect();
        let auth = Auth {
            dir: dir.to_path_buf(),
            state: Mutex::new(State { stored, last_used, setup_code: setup_code.clone(), failures: HashMap::new() }),
        };
        match &setup_code {
            Some(code) => auth.write_private(SETUP_CODE_FILE, &format!("{code}\n"))?,
            None => {
                let _ = std::fs::remove_file(dir.join(SETUP_CODE_FILE));
            }
        }
        Ok((auth, setup_code))
    }

    fn write_private(&self, name: &str, text: &str) -> Result<(), String> {
        crate::security::atomic_write(&self.dir.join(name), text.as_bytes(), true)
            .map_err(|e| format!("Could not write {name}: {e}"))
    }

    fn save(&self, stored: &Stored) -> Result<(), String> {
        let text = serde_json::to_string_pretty(stored).map_err(|e| e.to_string())?;
        self.write_private(AUTH_FILE, &text)
    }

    pub fn password_set(&self) -> bool {
        self.state.lock().stored.password.is_some()
    }

    /// The token `emberd ctl` reads, made on first use.
    pub fn ensure_cli_token(&self) -> Result<(), String> {
        let path = self.dir.join(CLI_TOKEN_FILE);
        let existing = std::fs::read_to_string(&path).ok().map(|t| t.trim().to_string());
        let mut state = self.state.lock();
        if let Some(token) = existing.filter(|t| !t.is_empty()) {
            if state.stored.tokens.iter().any(|t| t.hash == token_hash(&token)) {
                return Ok(());
            }
        }
        let token = random_token();
        state.stored.tokens.retain(|t| t.name != "cli");
        state.stored.tokens.push(StoredToken { hash: token_hash(&token), name: "cli".to_string() });
        self.save(&state.stored)?;
        drop(state);
        self.write_private(CLI_TOKEN_FILE, &format!("{token}\n"))
    }

    /// How long `ip` must wait before trying again, if it must.
    fn wait_for(state: &State, ip: IpAddr) -> Option<Duration> {
        let failures = state.failures.get(&throttle_key(ip))?;
        if failures.count < FREE_FAILURES {
            return None;
        }
        let wait = Duration::from_secs(1u64 << (failures.count - FREE_FAILURES).min(9)).min(MAX_WAIT);
        let waited = failures.last.elapsed();
        (waited < wait).then(|| wait - waited)
    }

    fn note_failure(state: &mut State, ip: IpAddr) {
        let entry = state.failures.entry(throttle_key(ip)).or_insert(Failures { count: 0, last: Instant::now() });
        entry.count = entry.count.saturating_add(1);
        entry.last = Instant::now();
        // Bounded: an address that stopped trying is forgotten first, then,
        // under a flood from more addresses than that frees, the longest
        // quiet of the rest.
        if state.failures.len() > MAX_TRACKED {
            state.failures.retain(|_, f| f.last.elapsed() < MAX_WAIT);
        }
        if state.failures.len() > MAX_TRACKED {
            // A quarter at a time, so a flood sorts once per thousand tries
            // rather than once per try.
            let mut by_age: Vec<(IpAddr, Instant)> = state.failures.iter().map(|(ip, f)| (*ip, f.last)).collect();
            by_age.sort_by_key(|(_, last)| *last);
            let excess = state.failures.len() - MAX_TRACKED * 3 / 4;
            for (ip, _) in by_age.into_iter().take(excess) {
                state.failures.remove(&ip);
            }
        }
    }

    /// A wrong password was found: its wait runs from now, not from when the
    /// try was counted, since Argon2 took a moment in between.
    fn failure_found(state: &mut State, ip: IpAddr) {
        if let Some(entry) = state.failures.get_mut(&throttle_key(ip)) {
            entry.last = Instant::now();
        }
    }

    fn new_session(state: &mut State) -> String {
        let token = random_token();
        let hash = token_hash(&token);
        state.stored.sessions.push(StoredSession { hash: hash.clone(), created: now() });
        state.last_used.insert(hash, Instant::now());
        if state.stored.sessions.len() > MAX_SESSIONS {
            let oldest = state
                .stored
                .sessions
                .iter()
                .min_by_key(|s| state.last_used.get(&s.hash).copied().unwrap_or_else(Instant::now))
                .map(|s| s.hash.clone());
            if let Some(oldest) = oldest {
                state.stored.sessions.retain(|s| s.hash != oldest);
                state.last_used.remove(&oldest);
            }
        }
        token
    }

    /// Choose the first password, with the setup code. Returns a session.
    pub fn set_up(&self, ip: IpAddr, code: &str, password: &str) -> Result<String, Refusal> {
        check_new_password(password)?;
        let mut state = self.state.lock();
        if state.stored.password.is_some() {
            return Err(Refusal::WrongStep);
        }
        if let Some(wait) = Self::wait_for(&state, ip) {
            return Err(Refusal::Wait(wait));
        }
        let expected = state.setup_code.as_deref().map(normalize_code).unwrap_or_default();
        let given = normalize_code(code);
        let matches: bool = !expected.is_empty()
            && subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), given.as_bytes()).into();
        if !matches {
            Self::note_failure(&mut state, ip);
            return Err(Refusal::WrongSetupCode);
        }
        let hash = hash_password(password).map_err(|_| Refusal::Invalid("server_password_unusable"))?;
        state.stored.password = Some(hash);
        state.setup_code = None;
        state.failures.remove(&throttle_key(ip));
        let token = Self::new_session(&mut state);
        self.save(&state.stored).map_err(|_| Refusal::Invalid("server_auth_save_failed"))?;
        drop(state);
        let _ = std::fs::remove_file(self.dir.join(SETUP_CODE_FILE));
        Ok(token)
    }

    /// Log in. Returns a session. Argon2 takes a moment, so this blocks:
    /// call it off the async runtime.
    pub fn log_in(&self, ip: IpAddr, password: &str) -> Result<String, Refusal> {
        let stored_hash = {
            let mut state = self.state.lock();
            let Some(hash) = state.stored.password.clone() else {
                return Err(Refusal::WrongStep);
            };
            if let Some(wait) = Self::wait_for(&state, ip) {
                return Err(Refusal::Wait(wait));
            }
            // Counted as it starts, so tries made at once wait as tries made
            // one after another do; the right password clears the count.
            Self::note_failure(&mut state, ip);
            hash
        };
        let matches = password.len() <= MAX_PASSWORD_BYTES && password_matches(&stored_hash, password);
        let mut state = self.state.lock();
        if !matches {
            Self::failure_found(&mut state, ip);
            return Err(Refusal::Wrong);
        }
        state.failures.remove(&throttle_key(ip));
        let token = Self::new_session(&mut state);
        self.save(&state.stored).map_err(|_| Refusal::Invalid("server_auth_save_failed"))?;
        Ok(token)
    }

    /// Change the password, which ends every session but `keep`, the one
    /// asking, and replaces the API token, which a changed password must not
    /// leave working. Without a session still valid to keep, a new one is
    /// returned. Blocks.
    pub fn change_password(
        &self,
        ip: IpAddr,
        current: &str,
        new: &str,
        keep: Option<&str>,
    ) -> Result<Option<String>, Refusal> {
        check_new_password(new)?;
        let stored_hash = {
            let mut state = self.state.lock();
            if let Some(wait) = Self::wait_for(&state, ip) {
                return Err(Refusal::Wait(wait));
            }
            let hash = state.stored.password.clone().ok_or(Refusal::WrongStep)?;
            // Counted as it starts, as `log_in` counts.
            Self::note_failure(&mut state, ip);
            hash
        };
        if !password_matches(&stored_hash, current) {
            Self::failure_found(&mut self.state.lock(), ip);
            return Err(Refusal::Wrong);
        }
        let hash = hash_password(new).map_err(|_| Refusal::Invalid("server_password_unusable"))?;
        let mut state = self.state.lock();
        state.failures.remove(&throttle_key(ip));
        state.stored.password = Some(hash);
        let kept = keep.map(token_hash).filter(|kept| state.stored.sessions.iter().any(|s| &s.hash == kept));
        state.stored.sessions.retain(|s| Some(&s.hash) == kept.as_ref());
        state.last_used.retain(|hash, _| Some(hash) == kept.as_ref());
        let token = kept.is_none().then(|| Self::new_session(&mut state));
        state.stored.tokens.clear();
        self.save(&state.stored).map_err(|_| Refusal::Invalid("server_auth_save_failed"))?;
        drop(state);
        self.replace_cli_token();
        Ok(token)
    }

    /// Set the password from the command line, ending every session and
    /// replacing the API token.
    pub fn set_password(&self, password: &str) -> Result<(), String> {
        check_new_password(password).map_err(|_| {
            format!("A password needs at least {MIN_PASSWORD_CHARS} characters")
        })?;
        let hash = hash_password(password)?;
        let mut state = self.state.lock();
        state.stored.password = Some(hash);
        state.stored.sessions.clear();
        state.last_used.clear();
        state.stored.tokens.clear();
        state.setup_code = None;
        self.save(&state.stored)?;
        drop(state);
        let _ = std::fs::remove_file(self.dir.join(SETUP_CODE_FILE));
        self.replace_cli_token();
        Ok(())
    }

    /// A new API token in its file, for the old one was just revoked.
    fn replace_cli_token(&self) {
        if let Err(e) = self.ensure_cli_token() {
            tracing::warn!("The API token could not be replaced: {e}");
        }
    }

    /// Whether `token` is a live session, and if so mark it used.
    pub fn session_valid(&self, token: &str) -> bool {
        let hash = token_hash(token);
        let mut state = self.state.lock();
        let Some(last) = state.last_used.get(&hash).copied() else {
            return false;
        };
        if last.elapsed() > SESSION_IDLE {
            state.last_used.remove(&hash);
            state.stored.sessions.retain(|s| s.hash != hash);
            let _ = self.save(&state.stored);
            return false;
        }
        state.last_used.insert(hash, Instant::now());
        true
    }

    /// Whether `token` is one of the tokens for scripts.
    pub fn api_token_valid(&self, token: &str) -> bool {
        let hash = token_hash(token);
        self.state.lock().stored.tokens.iter().any(|t| t.hash == hash)
    }

    pub fn log_out(&self, token: &str) {
        let hash = token_hash(token);
        let mut state = self.state.lock();
        state.last_used.remove(&hash);
        let before = state.stored.sessions.len();
        state.stored.sessions.retain(|s| s.hash != hash);
        if state.stored.sessions.len() != before {
            let _ = self.save(&state.stored);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("emberd-auth-{}", random_token()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7));

    /// One IPv6 connection has a /64 to choose its address from, so a new
    /// address in it does not start the count again.
    #[test]
    fn an_ipv6_network_counts_as_one_address() {
        let in_net = |last: u16| IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last));
        let next_net = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1));
        assert_eq!(throttle_key(in_net(1)), throttle_key(in_net(0xffff)));
        assert_ne!(throttle_key(in_net(1)), throttle_key(next_net));
        assert_eq!(throttle_key("::ffff:192.0.2.7".parse().unwrap()), IP, "a mapped IPv4 address is that address");

        let dir = temp_dir();
        let (auth, _) = Auth::load(&dir).unwrap();
        auth.set_password("long enough").unwrap();
        for last in 1..=FREE_FAILURES as u16 {
            assert_eq!(auth.log_in(in_net(last), "nope"), Err(Refusal::Wrong));
        }
        assert!(matches!(auth.log_in(in_net(99), "long enough"), Err(Refusal::Wait(_))));
        assert!(auth.log_in(next_net, "long enough").is_ok(), "the next network is not held up");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Tries made at once from one address are counted as they start, so
    /// they wait as tries made one after another do.
    #[test]
    fn wrong_passwords_tried_at_once_still_slow_down() {
        let dir = temp_dir();
        let (auth, _) = Auth::load(&dir).unwrap();
        auth.set_password("long enough").unwrap();
        let auth = std::sync::Arc::new(auth);
        let tries: Vec<_> = (0..8)
            .map(|_| {
                let auth = auth.clone();
                std::thread::spawn(move || auth.log_in(IP, "nope"))
            })
            .collect();
        let refused: Vec<Refusal> = tries.into_iter().map(|t| t.join().unwrap().unwrap_err()).collect();
        let checked = refused.iter().filter(|r| **r == Refusal::Wrong).count();
        assert!(checked <= FREE_FAILURES as usize, "only {FREE_FAILURES} free tries, at once or not; {checked} were checked");
        assert!(matches!(auth.log_in(IP, "long enough"), Err(Refusal::Wait(_))));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A flood from more addresses than are counted stays bounded, and keeps
    /// counting the latest.
    #[test]
    fn a_flood_from_many_addresses_stays_bounded() {
        let dir = temp_dir();
        let (auth, _) = Auth::load(&dir).unwrap();
        let mut state = auth.state.lock();
        let address = |i: u32| IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
        let flood = MAX_TRACKED as u32 * 3;
        for i in 0..flood {
            Auth::note_failure(&mut state, address(i));
            assert!(state.failures.len() <= MAX_TRACKED);
        }
        assert!(state.failures.contains_key(&address(flood - 1)));
        drop(state);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_first_password_takes_the_setup_code_and_then_logs_in() {
        let dir = temp_dir();
        let (auth, code) = Auth::load(&dir).unwrap();
        let code = code.expect("a code while no password is set");
        assert_eq!(std::fs::read_to_string(dir.join(SETUP_CODE_FILE)).unwrap().trim(), code);
        assert_eq!(auth.set_up(IP, "WRONG-CODE", "long enough"), Err(Refusal::WrongSetupCode));
        assert_eq!(auth.set_up(IP, &code, "short"), Err(Refusal::Invalid("server_password_too_short")));
        let session = auth.set_up(IP, &code.to_lowercase().replace('-', ""), "long enough").unwrap();
        assert!(auth.session_valid(&session));
        assert!(!dir.join(SETUP_CODE_FILE).exists(), "the code is spent");
        assert_eq!(auth.set_up(IP, &code, "another one"), Err(Refusal::WrongStep));

        // Read back from disk, the session and the password still hold.
        let (again, code) = Auth::load(&dir).unwrap();
        assert!(code.is_none());
        assert!(again.session_valid(&session));
        assert!(again.log_in(IP, "long enough").is_ok());
        assert_eq!(again.log_in(IP, "not it"), Err(Refusal::Wrong));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn repeated_wrong_passwords_wait_longer() {
        let dir = temp_dir();
        let (auth, _) = Auth::load(&dir).unwrap();
        auth.set_password("long enough").unwrap();
        for _ in 0..FREE_FAILURES {
            assert_eq!(auth.log_in(IP, "nope"), Err(Refusal::Wrong));
        }
        assert!(matches!(auth.log_in(IP, "long enough"), Err(Refusal::Wait(_))), "even the right one waits");
        let other = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 8));
        assert!(auth.log_in(other, "long enough").is_ok(), "another address is not held up");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn changing_the_password_ends_other_sessions() {
        let dir = temp_dir();
        let (auth, _) = Auth::load(&dir).unwrap();
        auth.set_password("long enough").unwrap();
        let other = auth.log_in(IP, "long enough").unwrap();
        let asking = auth.log_in(IP, "long enough").unwrap();
        assert_eq!(auth.change_password(IP, "long enough", "even longer", Some(&asking)).unwrap(), None);
        assert!(!auth.session_valid(&other));
        assert!(auth.session_valid(&asking), "the browser that changed it stays signed in");
        assert!(auth.log_in(IP, "long enough").is_err());

        // From a script, with no session to keep: a new one comes back.
        let fresh = auth.change_password(IP, "even longer", "longer still", None).unwrap().unwrap();
        assert!(!auth.session_valid(&asking));
        assert!(auth.session_valid(&fresh));
        auth.log_out(&fresh);
        assert!(!auth.session_valid(&fresh));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_cli_token_is_made_once_and_checked_by_hash() {
        let dir = temp_dir();
        let (auth, _) = Auth::load(&dir).unwrap();
        auth.ensure_cli_token().unwrap();
        let token = std::fs::read_to_string(dir.join(CLI_TOKEN_FILE)).unwrap().trim().to_string();
        assert!(auth.api_token_valid(&token));
        auth.ensure_cli_token().unwrap();
        assert_eq!(std::fs::read_to_string(dir.join(CLI_TOKEN_FILE)).unwrap().trim(), token);
        assert!(!auth.api_token_valid("not a token"));
        let stored = std::fs::read_to_string(dir.join(AUTH_FILE)).unwrap();
        assert!(!stored.contains(&token), "only the hash is kept");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A token that leaked with the password stops working when the password
    /// is changed, by either way, and its file holds the new one.
    #[test]
    fn changing_the_password_replaces_the_api_token() {
        let dir = temp_dir();
        let (auth, _) = Auth::load(&dir).unwrap();
        auth.set_password("long enough").unwrap();
        let read = || std::fs::read_to_string(dir.join(CLI_TOKEN_FILE)).unwrap().trim().to_string();
        let first = read();
        assert!(auth.api_token_valid(&first));

        auth.change_password(IP, "long enough", "even longer", None).unwrap();
        let second = read();
        assert!(!auth.api_token_valid(&first));
        assert!(auth.api_token_valid(&second));

        auth.set_password("longer still").unwrap();
        assert!(!auth.api_token_valid(&second));
        assert!(auth.api_token_valid(&read()));
        let _ = std::fs::remove_dir_all(dir);
    }
}
