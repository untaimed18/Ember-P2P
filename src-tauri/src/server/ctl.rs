//! `emberd ctl`: Ember's downloads and search from a shell or a script, as
//! aMule's `amulecmd` does for `amuled`. It reaches the running emberd over
//! the control socket beside the web interface, which only emberd's own user
//! (and, under systemd, its group) can open, and asks the same commands the
//! web pages do.

use std::collections::HashSet;
use std::path::PathBuf;

use serde_json::{json, Value};

pub const USAGE: &str = "\
emberd ctl: Ember's downloads and search from a shell.

Usage:
  emberd ctl status                    Connections, speeds and downloads
  emberd ctl list                      Downloads, each with its id
  emberd ctl add LINK...               Download ed2k:// links; with -, or none,
                                       the links are read from standard input
  emberd ctl pause ID...|all           Pause downloads
  emberd ctl resume ID...|all          Resume them
  emberd ctl stop ID...|all            Stop them, keeping what arrived
  emberd ctl cancel ID...              Cancel them and delete what arrived
  emberd ctl search [--type TYPE] [--method METHOD] [--limit N] WORDS...
                                       Search, and print what was found as
                                       ed2k:// links to add

An ID is a download's id as `list` shows it, or the start of it, or the start
of the file's eD2K hash. TYPE is audio, video, image, program, document,
archive, iso or collection; METHOD is global (the default), server, kad or
ember.

Options:
  --config FILE    The config emberd runs with, to find its data folder
  --socket PATH    The control socket, if not where emberd puts it
  --json           Print what emberd answered, as JSON

Run it as the user emberd runs as, or as a member of its group:
  sudo -u emberd emberd ctl status
  docker exec emberd /opt/emberd/emberd ctl status";

/// Where the systemd unit's runtime folder puts the socket.
const SYSTEMD_SOCKET: &str = "/run/emberd/emberd.sock";

#[derive(Debug, PartialEq)]
enum Action {
    Help,
    Status,
    List,
    Add(Vec<String>),
    Pause(Vec<String>),
    Resume(Vec<String>),
    Stop(Vec<String>),
    Cancel(Vec<String>),
    Search { words: String, method: String, file_type: Option<String>, limit: usize },
}

#[derive(Debug, PartialEq)]
struct Ctl {
    action: Action,
    config: Option<PathBuf>,
    socket: Option<PathBuf>,
    json: bool,
}

fn parse(args: &[String]) -> Result<Ctl, String> {
    let mut config = None;
    let mut socket = None;
    let mut json = false;
    let mut method = "global".to_string();
    let mut file_type = None;
    let mut limit = 20usize;
    let mut words = Vec::new();
    let mut iter = args.iter();
    let value = |iter: &mut std::slice::Iter<String>, flag: &str| -> Result<String, String> {
        iter.next().cloned().ok_or_else(|| format!("{flag} needs a value"))
    };
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" | "help" => return Ok(Ctl { action: Action::Help, config, socket, json }),
            "--config" | "-c" => config = Some(PathBuf::from(value(&mut iter, arg)?)),
            "--socket" => socket = Some(PathBuf::from(value(&mut iter, arg)?)),
            "--json" => json = true,
            "--method" => {
                method = value(&mut iter, arg)?;
                if !matches!(method.as_str(), "global" | "server" | "kad" | "ember") {
                    return Err(format!("unknown search method \"{method}\""));
                }
            }
            "--type" => {
                let name = value(&mut iter, arg)?;
                file_type = Some(search_type(&name).ok_or_else(|| format!("unknown file type \"{name}\""))?.to_string());
            }
            "--limit" => {
                limit = value(&mut iter, arg)?
                    .parse()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or("--limit needs a number above 0")?;
            }
            other => words.push(other.to_string()),
        }
    }
    let mut words = words.into_iter();
    let Some(command) = words.next() else {
        return Err("say what to do".into());
    };
    let rest: Vec<String> = words.collect();
    let needs_ids = |rest: &Vec<String>| {
        if rest.is_empty() {
            Err(format!("{command} needs the id of a download"))
        } else {
            Ok(rest.clone())
        }
    };
    let action = match command.as_str() {
        "status" => Action::Status,
        "list" => Action::List,
        "add" => Action::Add(rest),
        "pause" => Action::Pause(needs_ids(&rest)?),
        "resume" => Action::Resume(needs_ids(&rest)?),
        "stop" => Action::Stop(needs_ids(&rest)?),
        "cancel" => {
            let ids = needs_ids(&rest)?;
            if ids.iter().any(|id| id == "all") {
                return Err("cancel deletes what arrived, so it takes ids, not all".into());
            }
            Action::Cancel(ids)
        }
        "search" => {
            if rest.is_empty() {
                return Err("search needs words to look for".into());
            }
            Action::Search { words: rest.join(" "), method, file_type, limit }
        }
        other => return Err(format!("unknown command \"{other}\"")),
    };
    Ok(Ctl { action, config, socket, json })
}

/// The file types `search_files` knows, by the names eMule gives them.
fn search_type(name: &str) -> Option<&'static str> {
    Some(match name.to_ascii_lowercase().as_str() {
        "audio" | "music" => "Audio",
        "video" | "film" => "Video",
        "image" | "picture" => "Image",
        "program" => "Pro",
        "document" => "Doc",
        "archive" => "Arc",
        "iso" | "cd" | "dvd" => "Iso",
        "collection" => "EmuleCollection",
        _ => return None,
    })
}

pub fn run(args: &[String]) -> i32 {
    let ctl = match parse(args) {
        Ok(ctl) => ctl,
        Err(e) => {
            eprintln!("emberd ctl: {e}\n\n{USAGE}");
            return 2;
        }
    };
    if ctl.action == Action::Help {
        println!("{USAGE}");
        return 0;
    }
    let socket = match socket_path(&ctl) {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("emberd ctl: {e}");
            return 2;
        }
    };
    let client = Client { socket };
    match execute(&ctl, &client) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("emberd ctl: {e}");
            1
        }
    }
}

/// `--socket`, then `EMBERD_SOCKET`, then the systemd unit's, then the data
/// folder's, as emberd chooses where to put it. With `--config`, the data
/// folder's first, unless only the unit's answers: the unit runs emberd with
/// `--config` too, and its socket is in its runtime folder.
fn socket_path(ctl: &Ctl) -> Result<PathBuf, String> {
    if let Some(socket) = &ctl.socket {
        return Ok(socket.clone());
    }
    if let Some(socket) = std::env::var_os("EMBERD_SOCKET") {
        return Ok(PathBuf::from(socket));
    }
    let systemd = PathBuf::from(SYSTEMD_SOCKET);
    if ctl.config.is_none() && systemd.exists() {
        return Ok(systemd);
    }
    super::prepare(ctl.config.as_deref()).map_err(|e| e.to_string())?;
    let own = crate::storage::paths::resolve_data_dir().join(super::SOCKET_NAME);
    Ok(own_or_unit(own, systemd, answers))
}

fn own_or_unit(own: PathBuf, unit: PathBuf, answers: impl Fn(&std::path::Path) -> bool) -> PathBuf {
    if !answers(&own) && answers(&unit) {
        unit
    } else {
        own
    }
}

#[cfg(unix)]
fn answers(socket: &std::path::Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket).is_ok()
}

#[cfg(not(unix))]
fn answers(_socket: &std::path::Path) -> bool {
    false
}

/// What the commands below ask emberd through.
trait Ask {
    /// `method` on `path` with a JSON body; the status and the body back.
    fn request(&self, method: &str, path: &str, body: &Value) -> Result<(u16, Vec<u8>), String>;

    /// A command, as the web pages invoke it: its value, or the English of
    /// the coded error it was refused with.
    fn invoke(&self, command: &str, args: Value) -> Result<Value, String> {
        let (status, body) = self.request("POST", &format!("/api/invoke/{command}"), &args)?;
        let reply: Value = serde_json::from_slice(&body)
            .map_err(|_| format!("emberd answered {status} with something that is not JSON"))?;
        if let Some(error) = reply.get("error") {
            return Err(error_text(error));
        }
        if status != 200 {
            return Err(format!("emberd answered {status}"));
        }
        Ok(reply.get("ok").cloned().unwrap_or(Value::Null))
    }
}

/// The English of a coded error (`commands/errors.rs`), or the text itself.
fn error_text(error: &Value) -> String {
    let text = error.as_str().map(str::to_string).unwrap_or_else(|| error.to_string());
    serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|coded| {
            let message = coded.get("message")?.as_str()?.to_string();
            Some(match coded.get("context").and_then(Value::as_str) {
                Some(context) if !context.is_empty() => format!("{message} ({context})"),
                _ => message,
            })
        })
        .unwrap_or(text)
}

struct Client {
    socket: PathBuf,
}

impl Ask for Client {
    #[cfg(unix)]
    fn request(&self, method: &str, path: &str, body: &Value) -> Result<(u16, Vec<u8>), String> {
        use std::io::{Read, Write};
        let mut stream = std::os::unix::net::UnixStream::connect(&self.socket).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => format!(
                "emberd is not running, or not with this data folder: nothing answers at {}",
                self.socket.display()
            ),
            std::io::ErrorKind::PermissionDenied => format!(
                "{} is emberd's alone: run this as the user emberd runs as, or as a member of its group",
                self.socket.display()
            ),
            _ => format!("Could not reach emberd at {}: {e}", self.socket.display()),
        })?;
        // A search waits for every network to answer.
        let wait = Some(std::time::Duration::from_secs(300));
        let _ = stream.set_read_timeout(wait);
        let _ = stream.set_write_timeout(wait);
        let body = serde_json::to_vec(body).map_err(|e| e.to_string())?;
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: emberd\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(&body))
            .map_err(|e| format!("Could not ask emberd: {e}"))?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).map_err(|e| format!("emberd did not answer: {e}"))?;
        parse_response(&raw)
    }

    #[cfg(not(unix))]
    fn request(&self, _method: &str, _path: &str, _body: &Value) -> Result<(u16, Vec<u8>), String> {
        Err(format!(
            "emberd ctl reaches emberd over a Unix socket ({}), which this system does not have; use the web interface",
            self.socket.display()
        ))
    }
}

/// An HTTP/1.1 response read to its end: the status, and the body, with
/// chunked encoding undone.
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("emberd's answer was cut short")?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| "emberd's answer was not readable")?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("emberd's answer had no status")?;
    let chunked = lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("transfer-encoding") && value.to_ascii_lowercase().contains("chunked")
        })
    });
    let body = &raw[split + 4..];
    Ok((status, if chunked { dechunk(body)? } else { body.to_vec() }))
}

#[cfg_attr(not(unix), allow(dead_code))]
fn dechunk(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let end = body.windows(2).position(|w| w == b"\r\n").ok_or("emberd's answer was cut short")?;
        let size_text = std::str::from_utf8(&body[..end]).map_err(|_| "emberd's answer was not readable")?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "emberd's answer was not readable")?;
        body = &body[end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size.saturating_add(2) {
            return Err("emberd's answer was cut short".into());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

fn execute(ctl: &Ctl, emberd: &impl Ask) -> Result<(), String> {
    match &ctl.action {
        Action::Help => Ok(()),
        Action::Status => status(emberd, ctl.json),
        Action::List => list(emberd, ctl.json),
        Action::Add(links) => add(emberd, links, ctl.json),
        // The Transfers page's own rules (`canPause`, `canResume`, `canStop`).
        Action::Pause(ids) => act(emberd, ids, "pause_transfer", "Paused", |s| matches!(s, "active" | "queued" | "searching")),
        Action::Resume(ids) => act(emberd, ids, "resume_transfer", "Resumed", |s| {
            matches!(s, "paused" | "stopped" | "insufficient" | "failed")
        }),
        Action::Stop(ids) => act(emberd, ids, "stop_transfer", "Stopped", |s| {
            !matches!(s, "completed" | "failed" | "stopped" | "completing")
        }),
        Action::Cancel(ids) => act(emberd, ids, "remove_transfer", "Cancelled", |s| !matches!(s, "completed" | "completing")),
        Action::Search { words, method, file_type, limit } => search(emberd, words, method, file_type.as_deref(), *limit, ctl.json),
    }
}

fn print_json(value: &Value) {
    println!("{}", serde_json::to_string_pretty(value).unwrap_or_default());
}

fn status(emberd: &impl Ask, as_json: bool) -> Result<(), String> {
    // While Ember waits for the network interface it is set to use, the
    // network has not started and answers nothing; the downloads still do.
    let stats = emberd.invoke("get_network_stats", json!({})).ok();
    let binding = emberd.invoke("get_network_binding", json!({})).unwrap_or(Value::Null);
    let downloads = downloads(emberd)?;
    if as_json {
        print_json(&json!({ "network": stats, "binding": binding, "downloads": downloads }));
        return Ok(());
    }
    let (_, session) = emberd.request("GET", "/api/session", &Value::Null)?;
    let version = serde_json::from_slice::<Value>(&session)
        .ok()
        .and_then(|s| s.get("version").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_default();
    for line in status_lines(&version, stats.as_ref(), &binding, &downloads) {
        println!("{line}");
    }
    Ok(())
}

fn status_lines(version: &str, stats: Option<&Value>, binding: &Value, downloads: &[Value]) -> Vec<String> {
    let mut lines = vec![format!("emberd {version}")];
    let interface = field(binding, "name");
    let address = field(binding, "address");
    match field(binding, "state") {
        "bound" => lines.push(format!("Interface:  {interface} ({address})")),
        "waiting" => lines.push(format!("Interface:  waiting for {interface} to connect; Ember goes online once it does")),
        "lost" => lines.push(format!("Interface:  {interface} is gone; nothing goes out until it is back")),
        "changed" => lines.push(format!("Interface:  {interface} came back at {address}; restart emberd to use it")),
        _ => {}
    }
    match stats {
        Some(stats) => {
            let text = |key: &str| stats.get(key).and_then(Value::as_str).unwrap_or("").to_string();
            let number = |key: &str| stats.get(key).and_then(Value::as_u64).unwrap_or(0);
            let ed2k = match text("server_status").as_str() {
                "connected" => match stats.get("ed2k_low_id").and_then(Value::as_bool) {
                    Some(true) => "connected, Low ID".to_string(),
                    _ => "connected, High ID".to_string(),
                },
                "" => "disconnected".to_string(),
                other => other.to_string(),
            };
            let kad = match text("status").as_str() {
                "connected" if stats.get("firewalled").and_then(Value::as_bool) == Some(true) => {
                    "connected, firewalled".to_string()
                }
                "connected" => "connected, open".to_string(),
                other => other.to_string(),
            };
            lines.push(format!("eD2K:       {ed2k}"));
            lines.push(format!("Kad:        {kad}"));
            lines.push(format!("Ember:      {} peers", number("ember_dht_verified_contacts")));
            lines.push(format!(
                "Speed:      down {}, up {}",
                speed(number("download_speed")),
                speed(number("upload_speed"))
            ));
        }
        None => lines.push("Network:    not running".to_string()),
    }
    let count = |wanted: &dyn Fn(&str) -> bool| downloads.iter().filter(|d| wanted(&state_of(d))).count();
    lines.push(format!(
        "Downloads:  {} active, {} waiting, {} paused or stopped, {} finished",
        count(&|s| s == "active"),
        count(&|s| matches!(s, "queued" | "searching" | "hashing" | "verifying" | "completing")),
        count(&|s| matches!(s, "paused" | "stopped")),
        count(&|s| s == "completed"),
    ));
    lines
}

fn downloads(emberd: &impl Ask) -> Result<Vec<Value>, String> {
    let all = emberd.invoke("get_transfers", json!({}))?;
    Ok(all
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter(|row| row.get("direction").and_then(Value::as_str) == Some("download"))
                .cloned()
                .collect()
        })
        .unwrap_or_default())
}

fn state_of(row: &Value) -> String {
    row.get("status").and_then(Value::as_str).unwrap_or("").to_string()
}

fn field<'a>(row: &'a Value, key: &str) -> &'a str {
    row.get(key).and_then(Value::as_str).unwrap_or("")
}

fn short_id(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

fn list(emberd: &impl Ask, as_json: bool) -> Result<(), String> {
    let rows = downloads(emberd)?;
    if as_json {
        print_json(&Value::Array(rows));
        return Ok(());
    }
    if rows.is_empty() {
        println!("No downloads.");
        return Ok(());
    }
    println!("{:<8}  {:<11} {:>6}  {:>10}  {:>9}  NAME", "ID", "STATUS", "DONE", "SPEED", "SIZE");
    for row in &rows {
        let progress = row.get("progress").and_then(Value::as_f64).unwrap_or(0.0);
        let speed_now = row.get("speed").and_then(Value::as_u64).unwrap_or(0);
        let total = row.get("total_size").and_then(Value::as_u64).unwrap_or(0);
        println!(
            "{:<8}  {:<11} {:>5.1}%  {:>10}  {:>9}  {}",
            short_id(field(row, "id")),
            state_of(row),
            progress,
            if speed_now > 0 { speed(speed_now) } else { "-".into() },
            size(total),
            field(row, "file_name")
        );
    }
    Ok(())
}

fn add(emberd: &impl Ask, links: &[String], as_json: bool) -> Result<(), String> {
    let text = if links.is_empty() || links == ["-"] {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut text).map_err(|e| format!("Could not read the links: {e}"))?;
        text
    } else {
        links.join("\n")
    };
    let batch = emberd.invoke("parse_ed2k_links", json!({ "text": text }))?;
    let found = batch.get("links").and_then(Value::as_array).cloned().unwrap_or_default();
    let invalid = batch.get("invalid").and_then(Value::as_u64).unwrap_or(0);
    if found.is_empty() {
        return Err("No ed2k:// file links in that".into());
    }
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    let mut failed = 0;
    for link in found.iter().filter(|link| seen.insert(field(link, "hash").to_string())) {
        let name = field(link, "name");
        let started = emberd.invoke(
            "start_download",
            json!({
                "fileHash": field(link, "hash"),
                "fileName": name,
                "fileSize": link.get("size").and_then(Value::as_u64).unwrap_or(0),
                "peerIp": "",
                "peerPort": 0,
                "extraSources": null,
                // A link is not trusted to name the digest a download is
                // checked against, as the web pages do not let it.
                "emberFileHash": null,
                "expectedAich": link.get("aich").cloned().unwrap_or(Value::Null),
                "friendEmberHash": null,
                "webSources": link.get("web_sources").cloned().unwrap_or(Value::Null),
            }),
        );
        match started {
            Ok(reply) => {
                let already = reply.get("already_queued").and_then(Value::as_bool) == Some(true);
                if !as_json {
                    println!("{} {name}", if already { "Already downloading" } else { "Downloading" });
                }
                results.push(json!({ "name": name, "ok": reply }));
            }
            Err(e) => {
                failed += 1;
                if !as_json {
                    eprintln!("Not downloading {name}: {e}");
                }
                results.push(json!({ "name": name, "error": e }));
            }
        }
    }
    if as_json {
        print_json(&json!({ "added": results, "invalid": invalid }));
    } else if invalid > 0 {
        eprintln!("{invalid} line(s) were not ed2k:// file links");
    }
    if failed > 0 {
        return Err(format!("{failed} link(s) could not be added"));
    }
    Ok(())
}

/// The downloads `ids` name: each one's id, the start of it, or the start of
/// its file's hash; `all` is every download `fits` takes.
fn resolve<'a>(rows: &'a [Value], ids: &[String], fits: &dyn Fn(&str) -> bool) -> Result<Vec<&'a Value>, String> {
    if ids.iter().any(|id| id == "all") {
        return Ok(rows.iter().filter(|row| fits(&state_of(row))).collect());
    }
    let mut chosen: Vec<&Value> = Vec::new();
    for wanted in ids {
        let wanted_lower = wanted.to_ascii_lowercase();
        let exact: Vec<&Value> = rows.iter().filter(|row| field(row, "id") == wanted).collect();
        let matches = if exact.is_empty() {
            if wanted.len() < 4 {
                return Err(format!("\"{wanted}\" is too short to name one download; give 4 characters or more"));
            }
            rows.iter()
                .filter(|row| {
                    field(row, "id").to_ascii_lowercase().starts_with(&wanted_lower)
                        || field(row, "file_hash").to_ascii_lowercase().starts_with(&wanted_lower)
                })
                .collect()
        } else {
            exact
        };
        match matches.as_slice() {
            [] => return Err(format!("No download is \"{wanted}\"")),
            [one] => {
                if !chosen.iter().any(|row| field(row, "id") == field(one, "id")) {
                    chosen.push(one);
                }
            }
            several => {
                let names: Vec<String> = several
                    .iter()
                    .map(|row| format!("{} {}", short_id(field(row, "id")), field(row, "file_name")))
                    .collect();
                return Err(format!("\"{wanted}\" is more than one download:\n  {}", names.join("\n  ")));
            }
        }
    }
    Ok(chosen)
}

fn act(emberd: &impl Ask, ids: &[String], command: &str, done: &str, fits: impl Fn(&str) -> bool) -> Result<(), String> {
    let rows = downloads(emberd)?;
    let chosen = resolve(&rows, ids, &fits)?;
    if chosen.is_empty() {
        println!("Nothing to do.");
        return Ok(());
    }
    let mut failed = 0;
    for row in chosen {
        let name = field(row, "file_name");
        if !fits(&state_of(row)) {
            eprintln!("Left {name} as it is: it is {}", state_of(row));
            continue;
        }
        match emberd.invoke(command, json!({ "transferId": field(row, "id") })) {
            Ok(_) => println!("{done} {name}"),
            Err(e) => {
                failed += 1;
                eprintln!("{name}: {e}");
            }
        }
    }
    if failed > 0 {
        return Err(format!("{failed} download(s) could not be changed"));
    }
    Ok(())
}

fn search(
    emberd: &impl Ask,
    words: &str,
    method: &str,
    file_type: Option<&str>,
    limit: usize,
    as_json: bool,
) -> Result<(), String> {
    // Unique per search, like the page's: a request id names the search its
    // results and its cancel belong to.
    let request_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1);
    if !as_json {
        eprintln!("Searching for \"{words}\"…");
    }
    let found = emberd.invoke(
        "search_files",
        json!({ "query": words, "method": method, "requestId": request_id, "fileType": file_type }),
    )?;
    let mut results: Vec<Value> = found
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|result| result.get("is_spam").and_then(Value::as_bool) != Some(true))
        .collect();
    let sources = |result: &Value| result.get("availability").and_then(Value::as_u64).unwrap_or(0);
    results.sort_by_key(|result| std::cmp::Reverse(sources(result)));
    results.truncate(limit);
    if as_json {
        print_json(&Value::Array(results));
        return Ok(());
    }
    if results.is_empty() {
        println!("Nothing found.");
        return Ok(());
    }
    for result in &results {
        let file = result.get("file").cloned().unwrap_or(Value::Null);
        let name = field(&file, "name");
        let bytes = file.get("size").and_then(Value::as_u64).unwrap_or(0);
        let link = emberd.invoke(
            "format_ed2k_link",
            json!({ "name": name, "size": bytes, "fileHash": field(&file, "hash"), "emberFileHash": null }),
        )?;
        println!("{name}  ({}, {} sources)", size(bytes), sources(result));
        println!("  {}", link.as_str().unwrap_or(""));
    }
    Ok(())
}

fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn speed(bytes_per_second: u64) -> String {
    format!("{}/s", size(bytes_per_second))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn commands_and_their_options_parse() {
        assert_eq!(parse(&args(&["status"])).unwrap().action, Action::Status);
        let search = parse(&args(&["--json", "search", "--type", "video", "--limit", "5", "big", "buck"])).unwrap();
        assert!(search.json);
        assert_eq!(
            search.action,
            Action::Search { words: "big buck".into(), method: "global".into(), file_type: Some("Video".into()), limit: 5 }
        );
        assert_eq!(parse(&args(&["add"])).unwrap().action, Action::Add(Vec::new()), "links from standard input");
        assert!(parse(&args(&["pause"])).is_err(), "an id is needed");
        assert!(parse(&args(&["cancel", "all"])).is_err(), "cancel deletes, so never all");
        assert!(parse(&args(&["search", "--type", "spreadsheet", "x"])).is_err());
        assert!(parse(&args(&["search", "--method", "web", "x"])).is_err());
        assert!(parse(&args(&["frobnicate"])).is_err());
        assert!(parse(&args(&[])).is_err());
        let with_paths = parse(&args(&["list", "--config", "/etc/emberd/emberd.toml", "--socket", "/tmp/s"])).unwrap();
        assert_eq!(with_paths.config, Some(PathBuf::from("/etc/emberd/emberd.toml")));
        assert_eq!(with_paths.socket, Some(PathBuf::from("/tmp/s")));
    }

    #[test]
    fn an_answer_is_read_whole_or_chunked() {
        let plain = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 11\r\n\r\n{\"ok\":true}";
        assert_eq!(parse_response(plain).unwrap(), (200, b"{\"ok\":true}".to_vec()));
        let chunked = b"HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"ok\r\n7;x=1\r\n\":null}\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked).unwrap(), (404, b"{\"ok\":null}".to_vec()));
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n").is_err(), "cut short");
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nff\r\nabc").is_err());
        let huge = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nabc";
        assert!(parse_response(huge).is_err(), "a size past the end is cut short, not an overflow");
    }

    #[test]
    fn reading_an_answer_fuzz_never_panics() {
        use rand::Rng;
        let mut rng = crate::fuzz::rng(0xC71C_0001);
        let pieces: [&[u8]; 9] = [b"HTTP/1.1 200 OK", b"\r\n", b"\r\n\r\n", b"Transfer-Encoding: chunked", b"ffffffffffffffff", b"0", b";", b":", b"{\"ok\":1}"];
        for _ in 0..crate::fuzz::rounds(4_000) {
            let mut raw = Vec::new();
            for _ in 0..rng.gen_range(0..12) {
                if rng.gen_bool(0.7) {
                    raw.extend_from_slice(pieces[rng.gen_range(0..pieces.len())]);
                } else {
                    raw.push(rng.gen());
                }
            }
            let _ = parse_response(&raw);
            let _ = dechunk(&raw);
        }
    }

    #[test]
    fn a_refusal_reads_as_its_english() {
        let coded = Value::String(r#"{"__coded":true,"code":"x","message":"Download not found","context":"abc"}"#.into());
        assert_eq!(error_text(&coded), "Download not found (abc)");
        assert_eq!(error_text(&Value::String("plain words".into())), "plain words");
    }

    fn rows() -> Vec<Value> {
        vec![
            json!({ "id": "1a2b3c4d5e", "file_hash": "AABBCCDD00", "file_name": "one.mkv", "status": "active" }),
            json!({ "id": "1a2b9999", "file_hash": "EEFF0011", "file_name": "two.iso", "status": "paused" }),
            json!({ "id": "77777777", "file_hash": "aabb0000", "file_name": "three.mp3", "status": "completed" }),
        ]
    }

    #[test]
    fn a_download_is_named_by_its_id_or_its_hash() {
        let rows = rows();
        let any = |_: &str| true;
        let names = |found: Vec<&Value>| found.iter().map(|r| field(r, "file_name").to_string()).collect::<Vec<_>>();
        assert_eq!(names(resolve(&rows, &args(&["1a2b3c"]), &any).unwrap()), ["one.mkv"]);
        assert_eq!(names(resolve(&rows, &args(&["eeff"]), &any).unwrap()), ["two.iso"], "by hash, in any case");
        assert_eq!(names(resolve(&rows, &args(&["77777777", "7777"]), &any).unwrap()), ["three.mp3"], "once");
        let several = resolve(&rows, &args(&["1a2b"]), &any).unwrap_err();
        assert!(several.contains("one.mkv") && several.contains("two.iso"), "{several}");
        assert!(resolve(&rows, &args(&["aab"]), &any).unwrap_err().contains("too short"));
        assert!(resolve(&rows, &args(&["dead"]), &any).is_err());
        let paused = |s: &str| s == "paused";
        assert_eq!(names(resolve(&rows, &args(&["all"]), &paused).unwrap()), ["two.iso"]);
    }

    /// Asks answered from a list, recording what was asked.
    struct Fake {
        asked: RefCell<Vec<(String, Value)>>,
        answer: Box<dyn Fn(&str, &Value) -> Value>,
    }

    impl Ask for Fake {
        fn request(&self, _method: &str, path: &str, body: &Value) -> Result<(u16, Vec<u8>), String> {
            let command = path.trim_start_matches("/api/invoke/").to_string();
            self.asked.borrow_mut().push((command.clone(), body.clone()));
            Ok((200, serde_json::to_vec(&(self.answer)(&command, body)).unwrap()))
        }
    }

    #[test]
    fn adding_starts_each_file_once_without_trusting_its_digest() {
        let fake = Fake {
            asked: RefCell::new(Vec::new()),
            answer: Box::new(|command, _| match command {
                "parse_ed2k_links" => json!({ "ok": { "links": [
                    { "name": "a.mkv", "size": 5, "hash": "aa", "aich": "AICH", "ember": "trust-me" },
                    { "name": "a.mkv", "size": 5, "hash": "aa" },
                ], "invalid": 0, "skipped": 0 } }),
                _ => json!({ "ok": { "transfer_id": "t", "already_queued": false } }),
            }),
        };
        add(&fake, &args(&["ed2k://|file|a.mkv|5|aa|/"]), true).unwrap();
        let asked = fake.asked.borrow();
        let starts: Vec<&Value> = asked.iter().filter(|(c, _)| c == "start_download").map(|(_, b)| b).collect();
        assert_eq!(starts.len(), 1, "the same file twice is one download");
        assert_eq!(starts[0]["fileHash"], "aa");
        assert_eq!(starts[0]["expectedAich"], "AICH");
        assert!(starts[0]["emberFileHash"].is_null());
    }

    #[test]
    fn a_refused_command_is_an_error_with_its_reason() {
        let fake = Fake {
            asked: RefCell::new(Vec::new()),
            answer: Box::new(|_, _| json!({ "error": r#"{"__coded":true,"code":"x","message":"No such download"}"# })),
        };
        assert_eq!(fake.invoke("pause_transfer", json!({})).unwrap_err(), "No such download");
    }

    #[test]
    fn with_a_config_the_data_folders_socket_wins_unless_only_the_units_answers() {
        let own = PathBuf::from("/var/lib/emberd/data/emberd.sock");
        let unit = PathBuf::from(SYSTEMD_SOCKET);
        let pick = |live: &[&PathBuf]| own_or_unit(own.clone(), unit.clone(), |p| live.iter().any(|l| l.as_path() == p));
        assert_eq!(pick(&[&own, &unit]), own, "a second emberd beside the service");
        assert_eq!(pick(&[&own]), own);
        assert_eq!(pick(&[&unit]), unit, "the service, which runs with --config itself");
        assert_eq!(pick(&[]), own, "neither: the error names the data folder's");
    }

    #[test]
    fn status_says_why_the_network_is_quiet_and_still_counts_downloads() {
        let downloads = vec![json!({ "status": "paused" }), json!({ "status": "searching" })];
        let waiting = json!({ "state": "waiting", "name": "wg0", "address": null });
        let lines = status_lines("1.8.0", None, &waiting, &downloads);
        assert_eq!(lines[0], "emberd 1.8.0");
        assert!(lines.iter().any(|l| l.contains("waiting for wg0 to connect")), "{lines:?}");
        assert!(lines.iter().any(|l| l == "Network:    not running"), "{lines:?}");
        assert_eq!(lines.last().unwrap(), "Downloads:  0 active, 1 waiting, 1 paused or stopped, 0 finished");

        let stats = json!({
            "server_status": "connected", "ed2k_low_id": false, "status": "connected", "firewalled": true,
            "ember_dht_verified_contacts": 12, "download_speed": 0, "upload_speed": 0,
        });
        let lines = status_lines("1.8.0", Some(&stats), &json!({ "state": "any" }), &[]);
        assert!(lines.contains(&"eD2K:       connected, High ID".to_string()), "{lines:?}");
        assert!(lines.contains(&"Kad:        connected, firewalled".to_string()), "{lines:?}");
        assert!(!lines.iter().any(|l| l.starts_with("Interface:") || l.starts_with("Network:")), "{lines:?}");
    }

    #[test]
    fn sizes_read_as_people_write_them() {
        assert_eq!(size(512), "512 B");
        assert_eq!(size(1536), "1.5 KB");
        assert_eq!(size(700 * 1024 * 1024), "700.0 MB");
        assert_eq!(speed(2 * 1024 * 1024), "2.0 MB/s");
    }
}
