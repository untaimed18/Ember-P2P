//! eMule-compatible web services: a user-curated list of external sites that
//! can be opened for a specific file, with the file's facts substituted into a
//! URL template.
//!
//! The feature this reproduces is eMule's right-click → *Web services*, whose
//! canonical use is answering "why will this download not complete?" by looking
//! the hash up on a site that reports how many complete sources the network has
//! seen. eMule keeps the list in `webservices.dat` in its config folder, one
//! `Name,URL` per line, which is why [`parse_webservices_dat`] exists at all:
//! somebody arriving from eMule has that file already.
//!
//! Everything here is pure. Opening a URL is
//! [`crate::commands::settings::open_web_service`]'s job, and it applies the
//! same scheme allowlist and private-host refusal that any externally-opened
//! link in this application goes through. This module only decides *what* URL
//! that is.
//!
//! Consent sits on the *list* rather than on each open. A service is asked
//! about once, natively, when it joins the list ([`newly_added`]), because the
//! question — "may this site learn which files you are looking for?" — is a
//! property of the site, and a prompt on a diagnostic clicked repeatedly while
//! triaging one download is a prompt people learn to dismiss.

use serde::{Deserialize, Serialize};

/// One configured service.
///
/// `url` is a *template*, not a URL: it may contain placeholders, and
/// [`substitute_placeholders`] is what turns it into something openable. The
/// distinction matters for validation order — see [`validate_service_template`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebService {
    pub name: String,
    pub url: String,
}

/// Services one profile may hold.
///
/// Generous next to the handful anyone curates by hand, and low enough that a
/// hostile or malformed `webservices.dat` cannot turn the context menu into a
/// scrolling wall or the settings page into a slow render.
pub const MAX_WEB_SERVICES: usize = 32;

/// Longest service name kept. Names are menu labels, so this is a layout bound
/// rather than a safety one.
pub const MAX_SERVICE_NAME_BYTES: usize = 64;

/// Longest URL template kept. Comfortably past any real service and well under
/// the length the opener itself refuses, so a template that survives here
/// cannot fail that check on length alone once its placeholders are filled with
/// ordinary values.
pub const MAX_SERVICE_URL_BYTES: usize = 512;

/// Bytes read from a picked `webservices.dat`.
///
/// The file is a few lines of text in every real case. The cap exists because
/// the picker will hand us whatever the user selected, and reading an
/// arbitrarily large file to find at most [`MAX_WEB_SERVICES`] entries is work
/// with no upside.
pub const MAX_WEBSERVICES_FILE_BYTES: u64 = 256 * 1024;

/// The example offered in Settings, and what a fresh profile starts with.
///
/// Held here rather than in the renderer so the string that gets stored is the
/// one that was reviewed — which is also what makes it defensible as a default
/// (see `AppSettings::default_web_services`): it ships because this exact
/// destination was reviewed, and nothing contacts it until a user clicks it.
/// A service the *user* adds has no such review behind it, so that path asks
/// natively instead; see [`newly_added`].
pub const EXAMPLE_SERVICE_NAME: &str = "ed2k stats (shortypower)";
pub const EXAMPLE_SERVICE_URL: &str = "https://ed2k.shortypower.org/?hash=#hashid";

/// The facts about one file that a template may ask for.
#[derive(Debug, Clone)]
pub struct FileFacts<'a> {
    /// eD2K hash as hex. Case is normalised on substitution.
    pub hash: &'a str,
    pub name: &'a str,
    pub size: u64,
}

/// Percent-encode one substituted value.
///
/// Keeps only RFC 3986 unreserved characters and encodes everything else, which
/// is the conservative choice: a value lands in a query string, a path segment
/// or a bare `ed2k:` style term depending on the template, and this set is safe
/// in all three.
///
/// Not `form_urlencoded`, whose `+` for space is form semantics and would be
/// read literally by a site that is not decoding a form. Not skipped either: a
/// file name is peer-supplied text that reaches a URL, and the opener refuses
/// any URL containing whitespace or control characters — so encoding is what
/// makes a file called `some movie.avi` work at all, not merely what makes it
/// safe.
fn percent_encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// eMule's "cleaned up" rendering of a file name: separators become spaces.
///
/// An approximation rather than a port. eMule's own cleanup has accumulated
/// release-tag heuristics over the years; what every version of it agrees on,
/// and what a search box actually needs, is that `Some.Movie_2009-x264` should
/// read as words. Runs collapse so a name full of dots does not become a name
/// full of spaces.
fn cleanup_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut pending_space = false;
    for ch in name.chars() {
        if matches!(ch, '.' | '_' | '-' | '+') || ch.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(ch);
    }
    out
}

/// The file name with its extension removed, matching eMule's `#name`.
fn strip_extension(name: &str) -> &str {
    match name.rfind('.') {
        // A leading dot is the whole name of a dotfile, not an extension.
        Some(0) | None => name,
        Some(cut) => &name[..cut],
    }
}

/// Fill a template's placeholders from `facts`.
///
/// The six placeholders are eMule's, documented in the header of its own
/// `webservices.dat`: `#filename`, `#cleanfilename`, `#name`, `#cleanname`,
/// `#hashid` and `#filesize`. An imported file is far more likely to use them
/// than not, so they are all supported rather than only the one this feature
/// was asked for.
///
/// Replaced longest-first. No shorter placeholder is currently a substring of a
/// longer one — every one of them begins at its own `#` — but that is a property
/// of the current six names rather than of the scheme, and a future `#hash`
/// beside `#hashid` would silently corrupt every template if the order were
/// arbitrary.
///
/// `#hashid` is upper-cased because eMule's `md4str` produces upper-case hex and
/// services were built against that; a site matching case-sensitively would
/// otherwise answer "not found" for every file.
pub fn substitute_placeholders(template: &str, facts: &FileFacts<'_>) -> String {
    let hash = facts.hash.to_ascii_uppercase();
    let stripped = strip_extension(facts.name);
    let replacements: [(&str, String); 6] = [
        ("#cleanfilename", cleanup_name(facts.name)),
        ("#cleanname", cleanup_name(stripped)),
        ("#filename", facts.name.to_string()),
        ("#filesize", facts.size.to_string()),
        ("#hashid", hash),
        ("#name", stripped.to_string()),
    ];
    let mut out = template.to_string();
    for (token, value) in replacements {
        if out.contains(token) {
            out = out.replace(token, &percent_encode_component(&value));
        }
    }
    out
}

/// Whether a stored template is worth keeping.
///
/// Deliberately looser than the check the opener applies, and it has to be: a
/// template's placeholder is written `#hashid`, and `#` starts a URL fragment —
/// so `https://example.test/?hash=#hashid` parses as a URL whose query is empty
/// and whose fragment is `hashid`. The strict validation therefore cannot run
/// until the placeholders are gone, which is at open time, on the substituted
/// result. What is checked here is only what stays true through substitution:
/// the scheme, the presence of a host, and the absence of credentials.
///
/// Both checks are real. This one stops a template that could never open from
/// being stored at all; the one at open time is what actually guards the shell,
/// and it runs against the exact string that will be handed to it.
pub fn validate_service_template(name: &str, url: &str) -> Result<WebService, &'static str> {
    let name = name.trim();
    let url = url.trim();
    if name.is_empty() {
        return Err("A service needs a name");
    }
    if name.len() > MAX_SERVICE_NAME_BYTES {
        return Err("That service name is too long");
    }
    // A name is a menu label, and a control or bidi character in it reorders or
    // truncates how the *rest* of the menu reads. The same reasoning as the
    // opener's own refusal of these in a URL.
    if name.chars().any(|c| c.is_control()) {
        return Err("That service name contains control characters");
    }
    if url.is_empty() {
        return Err("A service needs a URL");
    }
    if url.len() > MAX_SERVICE_URL_BYTES {
        return Err("That service URL is too long");
    }
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("That service URL contains spaces or control characters");
    }
    let parsed = url::Url::parse(url).map_err(|_| "That service URL is not a valid URL")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("A service URL must start with http:// or https://");
    }
    if !parsed.has_host() || parsed.host_str().is_none_or(str::is_empty) {
        return Err("That service URL names no site");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("A service URL must not contain a username or password");
    }
    Ok(WebService {
        name: name.to_string(),
        url: url.to_string(),
    })
}

/// Parse an eMule `webservices.dat`.
///
/// Format, from the header eMule ships in the file itself: one `Name,URL` per
/// line, and comment lines begin with `#` or `/`.
///
/// The `#` doing double duty is the one thing here that needs care: it is both
/// the comment marker and the placeholder prefix, so it only starts a comment at
/// the beginning of a line. A line reading `Stats,http://x.test/?h=#hashid` is an
/// entry, not a comment.
///
/// Split on the *first* comma, because a URL may contain one and a name may not.
/// Malformed and unusable lines are skipped rather than failing the import: a
/// hand-edited file with one bad line should give up that line, not the file.
pub fn parse_webservices_dat(contents: &str) -> Vec<WebService> {
    let mut out = Vec::new();
    for line in contents.lines() {
        if out.len() >= MAX_WEB_SERVICES {
            break;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('/') {
            continue;
        }
        let Some((name, url)) = line.split_once(',') else {
            continue;
        };
        if let Ok(service) = validate_service_template(name, url) {
            // A file listing the same site twice would otherwise put two
            // identical rows in every context menu.
            if !out.iter().any(|existing: &WebService| existing.url == service.url) {
                out.push(service);
            }
        }
    }
    out
}

/// Normalise a list arriving from the renderer or an import.
///
/// Applies the same per-entry validation as a single add, drops duplicates by
/// URL, and truncates to [`MAX_WEB_SERVICES`]. Returns the accepted list and the
/// rejected `(row, reason)` pairs, so a settings page can report a typo on one
/// row without discarding the rest — the shape `set_antileech_patterns` already
/// established for a user-edited list.
pub fn sanitize_services(input: Vec<WebService>) -> (Vec<WebService>, Vec<(String, String)>) {
    let mut accepted: Vec<WebService> = Vec::new();
    let mut rejected: Vec<(String, String)> = Vec::new();
    for candidate in input {
        if accepted.len() >= MAX_WEB_SERVICES {
            rejected.push((
                candidate.name.clone(),
                format!("Only {MAX_WEB_SERVICES} web services can be saved"),
            ));
            continue;
        }
        match validate_service_template(&candidate.name, &candidate.url) {
            Ok(service) => {
                if accepted.iter().any(|existing| existing.url == service.url) {
                    rejected.push((service.name, "That site is already in the list".to_string()));
                } else {
                    accepted.push(service);
                }
            }
            Err(reason) => rejected.push((candidate.name, reason.to_string())),
        }
    }
    (accepted, rejected)
}

/// Entries in `proposed` naming a site `current` does not already hold.
///
/// This is the set a save has to collect consent for, and the reason consent is
/// scoped to additions rather than to "the list changed". Removing a service,
/// renaming one, or reordering the menu cannot send anything anywhere it could
/// not already go; introducing a *destination* can. Keyed by URL because that
/// is what gets opened — a name is a menu label, and treating a rename as a new
/// site would ask about a site already approved.
///
/// Called with the sanitized list, so every entry here is one
/// [`validate_service_template`] has already accepted.
pub fn newly_added(current: &[WebService], proposed: &[WebService]) -> Vec<WebService> {
    proposed
        .iter()
        .filter(|candidate| !current.iter().any(|held| held.url == candidate.url))
        .cloned()
        .collect()
}

/// The site a template names, for a consent prompt.
///
/// The host rather than the whole template, because the host is what learns the
/// lookup and the rest is placeholders. Falls back to the raw string only if the
/// URL will not parse, which [`validate_service_template`] has already ruled out
/// for anything reaching a prompt.
pub fn service_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(String::from))
        .unwrap_or_else(|| url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts<'a>(hash: &'a str, name: &'a str, size: u64) -> FileFacts<'a> {
        FileFacts { hash, name, size }
    }

    fn service(name: &str, url: &str) -> WebService {
        WebService {
            name: name.to_string(),
            url: url.to_string(),
        }
    }

    /// The gate exists for one thing: a destination that was not there before.
    #[test]
    fn only_a_new_destination_needs_consent() {
        let held = vec![service("Stats", "https://a.test/?hash=#hashid")];

        assert!(
            newly_added(&held, &held).is_empty(),
            "an unchanged list must not ask"
        );
        assert!(
            newly_added(&held, &[]).is_empty(),
            "removing a service cannot send anything anywhere"
        );
        assert!(
            newly_added(&held, &[service("Renamed", "https://a.test/?hash=#hashid")]).is_empty(),
            "a rename reaches the same site the user already approved"
        );

        let added = newly_added(
            &held,
            &[
                service("Stats", "https://a.test/?hash=#hashid"),
                service("Other", "https://b.test/?hash=#hashid"),
            ],
        );
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].url, "https://b.test/?hash=#hashid");
    }

    /// A prompt names the site, not the template: `#hashid` is noise to the
    /// question being asked, and the host is the part that learns the lookup.
    #[test]
    fn a_prompt_names_the_site() {
        assert_eq!(
            service_host("https://ed2k.shortypower.org/?hash=#hashid"),
            "ed2k.shortypower.org"
        );
    }

    /// The case this feature was asked for, end to end: the request's own
    /// service line and hash have to produce the request's own URL.
    #[test]
    fn the_requested_service_produces_the_requested_url() {
        let parsed = parse_webservices_dat(
            "ed2k stats shortypower,http://ed2k.shortypower.org/?hash=#hashid",
        );
        assert_eq!(parsed.len(), 1);
        let filled = substitute_placeholders(
            &parsed[0].url,
            &facts("ffdd6a41a2b30f27a1c3858a433b9822", "movie.avi", 700),
        );
        assert_eq!(
            filled,
            "http://ed2k.shortypower.org/?hash=FFDD6A41A2B30F27A1C3858A433B9822"
        );
    }

    /// eMule's `md4str` is upper-case and services were built against it, so a
    /// case-sensitive lookup must not be handed lower-case hex.
    #[test]
    fn the_hash_is_upper_cased() {
        let filled = substitute_placeholders(
            "https://x.test/?h=#hashid",
            &facts("abcdef01", "f.bin", 1),
        );
        assert_eq!(filled, "https://x.test/?h=ABCDEF01");
    }

    /// All six of eMule's placeholders, since an imported file is as likely to
    /// use any of them as the one this feature was asked for.
    #[test]
    fn every_emule_placeholder_is_filled() {
        let filled = substitute_placeholders(
            "https://x.test/?a=#filename&b=#cleanfilename&c=#name&d=#cleanname&e=#hashid&f=#filesize",
            &facts("aa", "Some.Movie_2009-x264.mkv", 4096),
        );
        assert_eq!(
            filled,
            "https://x.test/?a=Some.Movie_2009-x264.mkv\
             &b=Some%20Movie%202009%20x264%20mkv\
             &c=Some.Movie_2009-x264\
             &d=Some%20Movie%202009%20x264\
             &e=AA\
             &f=4096"
        );
    }

    /// A space in a file name is not a safety question but a correctness one:
    /// the opener refuses any URL containing whitespace, so an unencoded name
    /// would make the menu item silently fail rather than open.
    #[test]
    fn a_file_name_with_spaces_survives_because_it_is_encoded() {
        let filled = substitute_placeholders(
            "https://x.test/?q=#filename",
            &facts("aa", "some movie.avi", 1),
        );
        assert_eq!(filled, "https://x.test/?q=some%20movie.avi");
        assert!(!filled.contains(' '));
    }

    /// A peer-supplied name cannot break out of the value it is substituted
    /// into: reserved characters are encoded, so it cannot add a parameter, a
    /// path segment, or a second URL.
    #[test]
    fn a_hostile_file_name_cannot_escape_its_value() {
        let filled = substitute_placeholders(
            "https://x.test/?q=#filename",
            &facts("aa", "a&admin=1#/../b?c=d", 1),
        );
        assert_eq!(
            filled,
            "https://x.test/?q=a%26admin%3D1%23%2F..%2Fb%3Fc%3Dd"
        );
        let parsed = url::Url::parse(&filled).expect("still one valid URL");
        assert_eq!(parsed.host_str(), Some("x.test"));
        assert_eq!(parsed.path(), "/");
        assert!(parsed.fragment().is_none(), "no fragment was smuggled in");
    }

    /// `#` is both eMule's comment marker and its placeholder prefix, so it can
    /// only mean "comment" at the start of a line.
    #[test]
    fn a_hash_placeholder_mid_line_is_not_a_comment() {
        let parsed = parse_webservices_dat(
            "# Webservices Configuration File\n\
             / also a comment\n\
             \n\
             Stats,https://x.test/?h=#hashid\n",
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "Stats");
        assert_eq!(parsed[0].url, "https://x.test/?h=#hashid");
    }

    /// The real file eMule ships is almost entirely comments, and the one live
    /// line uses a URL with no placeholder at all.
    #[test]
    fn the_shipped_emule_file_parses_to_its_single_entry() {
        let parsed = parse_webservices_dat(
            "#########################################\n\
             # Webservices Configuration File\n\
             # input one service per line\n\
             #\n\
             # Format: Name,URL\n\
             #\n\
             # Placeholders\n\
             # ------------\n\
             # #filename       -> name of the file\n\
             # #hashid         -> hashid of the file\n\
             #\n\
             # Comment lines begin with # or /\n\
             \n\
             eMule FAQ,http://www.emule-project.org/faq/\n",
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "eMule FAQ");
    }

    /// Split on the first comma: a URL may contain one, a name may not.
    #[test]
    fn only_the_first_comma_separates_name_from_url() {
        let parsed = parse_webservices_dat("Stats,https://x.test/?a=1,2&h=#hashid");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].url, "https://x.test/?a=1,2&h=#hashid");
    }

    /// One bad line gives up that line, not the file. A hand-edited
    /// `webservices.dat` is the normal case and a typo in it is expected.
    #[test]
    fn a_malformed_line_does_not_lose_the_rest_of_the_file() {
        let parsed = parse_webservices_dat(
            "Good,https://good.test/?h=#hashid\n\
             no-comma-at-all\n\
             Bad scheme,ftp://bad.test/\n\
             Bad shell,file:///etc/passwd\n\
             Also good,https://other.test/\n",
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "Good");
        assert_eq!(parsed[1].name, "Also good");
    }

    /// The templates that matter are exactly the ones a naive strict check would
    /// reject, because `#hashid` parses as a URL fragment. Storing them has to
    /// stay possible; the strict check runs later, on the substituted result.
    #[test]
    fn a_placeholder_template_validates_even_though_it_parses_as_a_fragment() {
        let service =
            validate_service_template("Stats", "https://ed2k.shortypower.org/?hash=#hashid")
                .expect("a placeholder template is storable");
        assert_eq!(service.url, "https://ed2k.shortypower.org/?hash=#hashid");
        // And the reason the loose check is not the last word: before
        // substitution this URL's query is empty and its fragment is the
        // placeholder, so nothing about the destination is settled yet.
        let parsed = url::Url::parse(&service.url).unwrap();
        assert_eq!(parsed.fragment(), Some("hashid"));
    }

    /// Anything the shell would treat as a protocol handler is refused at the
    /// point it would be stored, not only at the point it would be opened.
    #[test]
    fn only_http_and_https_templates_can_be_stored() {
        for bad in [
            "file:///etc/passwd",
            "ms-msdt:/id",
            "javascript:alert(1)",
            "ftp://x.test/",
            "https://user:pw@x.test/",
            // No host at all, which for a special scheme is a parse error
            // rather than an empty host.
            "https://",
            "not a url",
        ] {
            assert!(
                validate_service_template("Name", bad).is_err(),
                "{bad} must not be storable"
            );
        }
        assert!(validate_service_template("Name", "http://x.test/").is_ok());
        assert!(validate_service_template("Name", "https://x.test/p?q=1").is_ok());
    }

    /// A slash count that looks like a typo is not one, and is worth pinning so
    /// nobody "fixes" it into a refusal: for a special scheme the URL parser
    /// skips any run of slashes after the colon, so `https:///nohost` names the
    /// host `nohost` and is a perfectly ordinary URL. It only *reads* like the
    /// hostless case.
    #[test]
    fn extra_slashes_are_collapsed_rather_than_hostless() {
        let service = validate_service_template("Name", "https:///nohost")
            .expect("extra slashes are collapsed, so this names a host");
        let parsed = url::Url::parse(&service.url).unwrap();
        assert_eq!(parsed.host_str(), Some("nohost"));
    }

    #[test]
    fn a_service_needs_a_name_and_a_url() {
        assert!(validate_service_template("", "https://x.test/").is_err());
        assert!(validate_service_template("   ", "https://x.test/").is_err());
        assert!(validate_service_template("Name", "").is_err());
        assert!(validate_service_template("Na\u{0}me", "https://x.test/").is_err());
        assert!(validate_service_template(&"n".repeat(MAX_SERVICE_NAME_BYTES + 1), "https://x.test/").is_err());
        assert!(validate_service_template("Name", &format!("https://x.test/{}", "p".repeat(MAX_SERVICE_URL_BYTES))).is_err());
    }

    /// Names and URLs are trimmed, because `Name , url` is what hand-editing
    /// produces and refusing it would be pedantry.
    #[test]
    fn entries_are_trimmed() {
        let parsed = parse_webservices_dat("  Stats  ,  https://x.test/  \n");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "Stats");
        assert_eq!(parsed[0].url, "https://x.test/");
    }

    #[test]
    fn duplicates_and_overflow_are_dropped() {
        let same = (0..MAX_WEB_SERVICES + 8)
            .map(|i| WebService {
                name: format!("s{i}"),
                url: format!("https://x{i}.test/"),
            })
            .collect::<Vec<_>>();
        let (accepted, rejected) = sanitize_services(same);
        assert_eq!(accepted.len(), MAX_WEB_SERVICES);
        assert_eq!(rejected.len(), 8);

        let dupes = vec![
            WebService { name: "a".into(), url: "https://x.test/".into() },
            WebService { name: "b".into(), url: "https://x.test/".into() },
        ];
        let (accepted, rejected) = sanitize_services(dupes);
        assert_eq!(accepted.len(), 1);
        assert_eq!(rejected.len(), 1);
    }

    /// The rejected list is per-row so a settings page can point at the typo
    /// instead of refusing the whole save.
    #[test]
    fn a_bad_row_is_reported_without_losing_the_good_ones() {
        let (accepted, rejected) = sanitize_services(vec![
            WebService { name: "Good".into(), url: "https://good.test/".into() },
            WebService { name: "Bad".into(), url: "file:///etc/passwd".into() },
        ]);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].name, "Good");
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].0, "Bad");
    }

    /// The example we offer in Settings has to be storable by our own rules, or
    /// the button would hand the user something the save path then refuses.
    #[test]
    fn the_offered_example_is_valid_by_our_own_rules() {
        let service = validate_service_template(EXAMPLE_SERVICE_NAME, EXAMPLE_SERVICE_URL)
            .expect("the offered example must be storable");
        let filled = substitute_placeholders(
            &service.url,
            &facts("ffdd6a41a2b30f27a1c3858a433b9822", "x.avi", 1),
        );
        assert!(filled.ends_with("FFDD6A41A2B30F27A1C3858A433B9822"));
        assert!(!filled.contains('#'), "no placeholder is left behind");
    }

    #[test]
    fn extension_stripping_handles_dotfiles_and_no_extension() {
        assert_eq!(strip_extension("movie.avi"), "movie");
        assert_eq!(strip_extension("archive.tar.gz"), "archive.tar");
        assert_eq!(strip_extension("README"), "README");
        assert_eq!(strip_extension(".gitignore"), ".gitignore");
    }

    /// A template with no placeholders is a plain bookmark, which eMule
    /// supports and its shipped file uses.
    #[test]
    fn a_template_without_placeholders_opens_unchanged() {
        let filled = substitute_placeholders(
            "https://www.emule-project.org/faq/",
            &facts("aa", "f.bin", 1),
        );
        assert_eq!(filled, "https://www.emule-project.org/faq/");
    }
}
