//! `emberd.toml`: what the operator decides, which the desktop app asks for
//! in native dialogs. Every key may be left out, and each has an environment
//! variable of its own for a container (`EMBERD_*`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Where the web interface listens unless told otherwise: this computer only.
/// 4711 is eMule's own web interface port.
pub const DEFAULT_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4711);

/// Where a system install keeps its config.
#[cfg(unix)]
const SYSTEM_CONFIG: &str = "/etc/emberd/emberd.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    data_dir: Option<PathBuf>,
    key_file: Option<PathBuf>,
    resource_dir: Option<PathBuf>,
    #[serde(default)]
    web: WebFile,
    #[serde(default)]
    folders: FoldersFile,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebFile {
    listen: Option<String>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    root: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FoldersFile {
    download: Option<PathBuf>,
    #[serde(default)]
    shared: Vec<PathBuf>,
    #[serde(default)]
    browse_under: Vec<PathBuf>,
}

/// The certificate and key for HTTPS, in PEM.
#[derive(Debug, Clone)]
pub struct Tls {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// The folders the operator names. Approved at every start, because naming
/// them here is the operator's authorization, as picking one in a native
/// dialog is the desktop user's.
#[derive(Debug, Clone, Default)]
pub struct Folders {
    pub download: Option<PathBuf>,
    pub shared: Vec<PathBuf>,
    /// Folders inside which the web interface may choose more to share.
    pub browse_under: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// The file this came from, if any.
    pub path: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    /// What ships with `emberd`: the GeoIP database.
    pub resource_dir: PathBuf,
    /// The web UI's files.
    pub web_root: PathBuf,
    pub listen: SocketAddr,
    pub tls: Option<Tls>,
    pub folders: Folders,
}

impl Config {
    /// Whether the web interface answers only on this computer.
    pub fn loopback_only(&self) -> bool {
        self.listen.ip().is_loopback()
    }
}

/// Read the config: `explicit` (`--config`), else `EMBERD_CONFIG`, else the
/// system file if there is one, else defaults; then the environment over it.
pub fn load(explicit: Option<&Path>) -> Result<Config, String> {
    let path = explicit
        .map(Path::to_path_buf)
        .or_else(|| env_path("EMBERD_CONFIG"))
        .or_else(system_config);
    let file = match &path {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("Could not read the config file {}: {e}", path.display()))?;
            toml::from_str::<FileConfig>(&text)
                .map_err(|e| format!("The config file {} is not valid: {e}", path.display()))?
        }
        None => FileConfig::default(),
    };
    resolve(file, path, &|name| std::env::var_os(name))
}

#[cfg(unix)]
fn system_config() -> Option<PathBuf> {
    let path = PathBuf::from(SYSTEM_CONFIG);
    path.is_file().then_some(path)
}

#[cfg(not(unix))]
fn system_config() -> Option<PathBuf> {
    None
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from)
}

fn resolve(
    file: FileConfig,
    path: Option<PathBuf>,
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<Config, String> {
    let var = |name: &str| env(name).filter(|v| !v.is_empty());
    let var_path = |name: &str| var(name).map(PathBuf::from);
    let var_paths = |name: &str| var(name).map(|v| std::env::split_paths(&v).collect::<Vec<_>>());

    let listen_text = var("EMBERD_LISTEN")
        .map(|v| v.to_string_lossy().into_owned())
        .or(file.web.listen);
    let listen = match listen_text {
        Some(text) => parse_listen(&text)?,
        None => DEFAULT_LISTEN,
    };
    let tls = match (
        var_path("EMBERD_TLS_CERT").or(file.web.tls_cert),
        var_path("EMBERD_TLS_KEY").or(file.web.tls_key),
    ) {
        (Some(cert), Some(key)) => Some(Tls { cert, key }),
        (None, None) => None,
        _ => return Err("Give both a TLS certificate and its key, or neither".to_string()),
    };
    let resource_dir = var_path("EMBERD_RESOURCE_DIR")
        .or(file.resource_dir)
        .unwrap_or_else(default_resource_dir);
    let web_root = var_path("EMBERD_WEB_ROOT")
        .or(file.web.root)
        .unwrap_or_else(|| resource_dir.join("web"));
    let data_dir = var_path("EMBER_DATA_DIR").or(file.data_dir);
    let folders = Folders {
        download: var_path("EMBERD_DOWNLOAD_DIR").or(file.folders.download),
        shared: var_paths("EMBERD_SHARED_DIRS").unwrap_or(file.folders.shared),
        browse_under: var_paths("EMBERD_BROWSE_UNDER").unwrap_or(file.folders.browse_under),
    };
    let config = Config {
        path,
        data_dir,
        key_file: var_path("EMBERD_KEY_FILE").or(file.key_file),
        resource_dir,
        web_root,
        listen,
        tls,
        folders,
    };
    check_folders(&config)?;
    Ok(config)
}

/// `4711`, `0.0.0.0:4711`, `[::]:4711` or `192.168.1.5:4711`.
fn parse_listen(text: &str) -> Result<SocketAddr, String> {
    let text = text.trim();
    if let Ok(port) = text.parse::<u16>() {
        return Ok(SocketAddr::new(DEFAULT_LISTEN.ip(), port));
    }
    text.parse::<SocketAddr>()
        .map_err(|_| format!("\"{text}\" is not an address to listen on, such as 127.0.0.1:4711"))
}

/// Beside the program, where a plain download unpacks everything, unless a
/// system install put its files in `/usr/share/emberd`.
fn default_resource_dir() -> PathBuf {
    let beside = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    if beside.join("web").is_dir() {
        return beside;
    }
    #[cfg(unix)]
    {
        let system = PathBuf::from("/usr/share/emberd");
        if system.join("web").is_dir() {
            return system;
        }
    }
    beside
}

/// Folders no one means to share or download into: the whole filesystem and
/// the system's own.
#[cfg(unix)]
const SYSTEM_FOLDERS: &[&str] = &["/", "/bin", "/boot", "/dev", "/etc", "/lib", "/proc", "/root", "/run", "/sbin", "/sys", "/usr", "/var"];

fn is_system_folder(path: &Path) -> bool {
    #[cfg(unix)]
    {
        SYSTEM_FOLDERS.iter().any(|system| path == Path::new(system))
    }
    #[cfg(windows)]
    {
        // A drive's root, or the system's own folders.
        path.parent().is_none()
            || std::env::var_os("SystemRoot").is_some_and(|root| path.starts_with(root))
    }
    #[cfg(not(any(unix, windows)))]
    {
        path.parent().is_none()
    }
}

fn check_folders(config: &Config) -> Result<(), String> {
    let named = config
        .folders
        .download
        .iter()
        .map(|p| ("download", p))
        .chain(config.folders.shared.iter().map(|p| ("shared", p)))
        .chain(config.folders.browse_under.iter().map(|p| ("browse_under", p)));
    for (kind, folder) in named {
        if !folder.is_absolute() {
            return Err(format!("The {kind} folder {} must be a full path", folder.display()));
        }
        if is_system_folder(folder) {
            return Err(format!(
                "The {kind} folder {} is a system folder; name a folder of its own",
                folder.display()
            ));
        }
        // The settings' own rules, so a folder they refuse stops emberd here
        // with its name rather than resetting every setting once it starts.
        let refused = if kind == "download" {
            crate::commands::settings::validate_download_folder(&folder.to_string_lossy()).err()
        } else {
            let private = crate::sharing::path_has_sensitive_component(folder)
                || folder.canonicalize().is_ok_and(|real| crate::sharing::path_has_sensitive_component(&real));
            private.then(String::new)
        };
        if let Some(why) = refused {
            let why = serde_json::from_str::<serde_json::Value>(&why)
                .ok()
                .and_then(|coded| coded["message"].as_str().map(str::to_string))
                .unwrap_or(why);
            return Err(format!(
                "The {kind} folder {} cannot be used{}{why}. Ember keeps out of system and private folders: \
                 none of the folders on its path may be named etc, usr, var, tmp, temp, AppData, .ssh, .config \
                 or the like, except the ones leading to the home folder",
                folder.display(),
                if why.is_empty() { "" } else { ": " },
            ));
        }
        if let Some(data_dir) = &config.data_dir {
            if folder.starts_with(data_dir) || data_dir.starts_with(folder) {
                return Err(format!(
                    "The {kind} folder {} overlaps Ember's data folder {}",
                    folder.display(),
                    data_dir.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn with_env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<std::ffi::OsString> {
        let vars: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |name| vars.get(name).map(Into::into)
    }

    fn file(text: &str) -> FileConfig {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn nothing_given_is_this_computer_only_on_4711() {
        let config = resolve(FileConfig::default(), None, &with_env(&[])).unwrap();
        assert_eq!(config.listen, DEFAULT_LISTEN);
        assert!(config.loopback_only());
        assert!(config.tls.is_none());
        assert!(config.folders.download.is_none());
    }

    #[test]
    fn the_environment_wins_over_the_file() {
        let shared = std::env::join_paths([abs("a"), abs("b")]).unwrap();
        let config = resolve(
            file("[web]\nlisten = \"127.0.0.1:9000\"\n[folders]\nshared = [\"/srv/one\"]"),
            None,
            &with_env(&[("EMBERD_LISTEN", "0.0.0.0:4711"), ("EMBERD_SHARED_DIRS", shared.to_str().unwrap())]),
        )
        .unwrap();
        assert_eq!(config.listen, "0.0.0.0:4711".parse::<SocketAddr>().unwrap());
        assert!(!config.loopback_only());
        assert_eq!(config.folders.shared, vec![abs("a"), abs("b")]);
    }

    #[test]
    fn a_bare_port_listens_on_this_computer() {
        assert_eq!(parse_listen("8080").unwrap(), SocketAddr::new(DEFAULT_LISTEN.ip(), 8080));
        assert!(parse_listen("somewhere").is_err());
    }

    /// The file the tarball and the .deb install as /etc/emberd/emberd.toml: a
    /// key it misspelled would stop every install that kept it.
    #[test]
    fn the_shipped_config_file_is_read_as_written() {
        let shipped = file(include_str!("../../../packaging/emberd/emberd.toml"));
        assert_eq!(shipped.data_dir, Some(PathBuf::from("/var/lib/emberd/data")));
        #[cfg(unix)]
        assert!(resolve(shipped, None, &with_env(&[])).is_ok());
    }

    #[test]
    fn unknown_keys_and_half_a_tls_pair_are_refused() {
        assert!(toml::from_str::<FileConfig>("listen = \"x\"").is_err(), "listen belongs under [web]");
        assert!(resolve(FileConfig::default(), None, &with_env(&[("EMBERD_TLS_CERT", "/c.pem")])).is_err());
    }

    #[test]
    fn folders_must_be_full_paths_of_their_own() {
        let refuse = |vars: &[(&str, &str)]| resolve(FileConfig::default(), None, &with_env(vars)).is_err();
        assert!(refuse(&[("EMBERD_DOWNLOAD_DIR", "downloads")]), "relative");
        #[cfg(unix)]
        assert!(refuse(&[("EMBERD_DOWNLOAD_DIR", "/etc")]), "a system folder");
        let data = abs("data");
        let inside = data.join("downloads");
        assert!(refuse(&[
            ("EMBER_DATA_DIR", data.to_str().unwrap()),
            ("EMBERD_DOWNLOAD_DIR", inside.to_str().unwrap()),
        ]));
        assert!(!refuse(&[("EMBERD_DOWNLOAD_DIR", abs("downloads").to_str().unwrap())]));
    }

    /// The settings would reset every setting over these, so emberd refuses
    /// them at the start, by name.
    #[test]
    fn folders_the_settings_refuse_stop_emberd_first() {
        let refused = |var: &str, path: PathBuf| {
            resolve(FileConfig::default(), None, &with_env(&[(var, path.to_str().unwrap())])).err()
        };
        let inside_tmp = abs("tmp").join("downloads");
        let why = refused("EMBERD_DOWNLOAD_DIR", inside_tmp.clone()).expect("a download folder under tmp");
        assert!(why.contains(&inside_tmp.display().to_string()) && why.contains("system directory"), "{why}");
        let why = refused("EMBERD_SHARED_DIRS", abs("var").join("media")).expect("a shared folder under var");
        assert!(why.starts_with("The shared folder"), "{why}");
        assert!(refused("EMBERD_BROWSE_UNDER", abs(".ssh")).is_some());
        assert!(refused("EMBERD_SHARED_DIRS", abs("media")).is_none());
    }

    /// An absolute path on this platform.
    fn abs(name: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!("D:\\srv\\{name}"))
        } else {
            PathBuf::from(format!("/srv/{name}"))
        }
    }
}
