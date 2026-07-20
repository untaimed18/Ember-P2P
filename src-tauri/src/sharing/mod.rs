pub mod indexer;
pub mod manager;
pub mod watcher;

/// Directory basenames that must not be shared as roots and must be skipped
/// during recursive indexing under an allowed parent. Without the indexer
/// skip, sharing e.g. a home folder would still walk into `.ssh` / `.gnupg`
/// / `AppData` and expose secrets. Matched case-insensitively.
pub const SENSITIVE_DIR_NAMES: &[&str] = &[
    "windows",
    "program files",
    "program files (x86)",
    "programdata",
    "appdata",
    ".ssh",
    ".gnupg",
    "etc",
    "usr",
    "bin",
    "sbin",
    "var",
    "root",
    "tmp",
    "temp",
    "proc",
    "sys",
    "dev",
];

/// True when `name` is a sensitive directory basename (ASCII case-insensitive).
pub fn is_sensitive_dir_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_DIR_NAMES.iter().any(|s| lower.as_str() == *s)
}
