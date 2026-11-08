//! The AppImage's emoji, kept away from a crash in its bundled WebKit.
//!
//! The AppImage carries WebKitGTK from the distro it is built on (Ubuntu
//! 22.04), compiled against that distro's FreeType 2.11, but not FreeType
//! itself: WebKit loads the host's. FreeType 2.13 added a field to
//! `FT_ColorStopIterator`, so on a host with 2.13 or newer (Fedora 40 and
//! later, Debian 13, Arch) the two disagree on its layout. The first gradient
//! drawn from a COLRv1 colour font, which Fedora's default emoji font is, then
//! aborts the web process in Skia's `colrv1_configure_skpaint`. The backend
//! keeps running; the window dies at the first emoji, which in practice is a
//! room's older messages.
//!
//! On such a host, before anything else starts, fontconfig is pointed at a
//! configuration of Ember's own: the host's, minus every colour font except
//! the bitmap (CBDT) Noto Color Emoji the AppImage carries, which that code
//! never draws. Emoji stay in colour, under the family name the host's
//! configuration already prefers for them. The `.deb` uses the host's own
//! WebKit and FreeType and needs none of this, nor does a host whose FreeType
//! is on the same side of 2.13 as the one WebKit was built against.
//!
//! The bundled font is `NotoColorEmoji.ttf` from googlefonts/noto-emoji at
//! commit `e20cbc2bbec1926686be9f9bee7d1d2cfa1fea0e` (tag
//! `v2026-09-24-unicode18_0`, `2D/fonts/`), under the SIL Open Font License
//! 1.1 shipped beside it.

#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

/// Set beside `FONTCONFIG_FILE`, to the same path, when the configuration is
/// Ember's. A program Ember launches loses both (see
/// `security::filesystem::apply_host_desktop_env`), and an Ember started by
/// Ember (a restart, an update) knows the inherited value is its own to redo
/// rather than the user's to keep.
pub const OVERRIDE_MARKER: &str = "EMBER_FONTCONFIG_FILE";

/// The FreeType the bundled WebKit was compiled against: the build distro's
/// (`build-linux` in `.github/workflows/release.yml`). Moves with it.
const BUILT_AGAINST_FREETYPE: (i32, i32) = (2, 11);

/// The release that changed `FT_ColorStopIterator`.
const COLOR_STOP_LAYOUT_CHANGED_IN: (i32, i32) = (2, 13);

/// The bundled font's file name, in the AppImage and in Ember's copy of it.
const FONT_FILE_NAME: &str = "NotoColorEmoji.ttf";

#[cfg(target_os = "linux")]
const BUNDLED_FONT_DIR: &str = "usr/share/ember/fonts";

/// The host configuration Ember's includes. The default fontconfig reads when
/// `FONTCONFIG_FILE` is unset, on every distro that ships a WebKitGTK 4.1.
#[cfg(target_os = "linux")]
const SYSTEM_CONFIG: &str = "/etc/fonts/fonts.conf";

/// Whether a host with FreeType `host` disagrees with the bundled WebKit on
/// the colour-stop layout.
fn layouts_differ(host: (i32, i32, i32)) -> bool {
    let built_new = BUILT_AGAINST_FREETYPE >= COLOR_STOP_LAYOUT_CHANGED_IN;
    let host_new = (host.0, host.1) >= COLOR_STOP_LAYOUT_CHANGED_IN;
    built_new != host_new
}

fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// Ember's configuration: `system`, with every colour font rejected but the
/// bundled one in `font_dir` when there is one.
fn config_xml(system: &str, font_dir: Option<&str>) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n\
         <!DOCTYPE fontconfig SYSTEM \"urn:fontconfig:fonts.dtd\">\n\
         <!-- Written by Ember's AppImage at every start; see appimage_fonts.rs. -->\n\
         <fontconfig>\n",
    );
    xml.push_str(&format!("  <include ignore_missing=\"no\">{}</include>\n", xml_escape(system)));
    if let Some(dir) = font_dir {
        xml.push_str(&format!("  <dir>{}</dir>\n", xml_escape(dir)));
    }
    xml.push_str("  <selectfont>\n");
    // By pattern, not by glob: fontconfig weighs file globs and font patterns
    // separately, so an accepted glob does not save a font a pattern rejects.
    if let Some(dir) = font_dir {
        xml.push_str(&format!(
            "    <acceptfont><pattern><patelt name=\"file\"><string>{}/{FONT_FILE_NAME}</string></patelt></pattern></acceptfont>\n",
            xml_escape(dir)
        ));
    }
    xml.push_str(
        "    <rejectfont><pattern><patelt name=\"color\"><bool>true</bool></patelt></pattern></rejectfont>\n\
         \x20 </selectfont>\n\
         </fontconfig>\n",
    );
    xml
}

/// What [`prepare`] did, logged once logging is up.
#[cfg(target_os = "linux")]
pub enum Outcome {
    /// Not an AppImage.
    NotAppImage,
    /// `FONTCONFIG_FILE` was the user's, and is left as they set it.
    UserConfig,
    /// The host's FreeType agrees with the bundled WebKit.
    HostMatches((i32, i32, i32)),
    /// The host's FreeType could not be loaded or asked.
    FreetypeUnknown,
    /// The host has no configuration at the usual place to build on.
    NoSystemConfig,
    /// Ember's configuration is in force. `font_error` is why the bundled font
    /// could not be used, in which case emoji are drawn without colour.
    Applied {
        freetype: (i32, i32, i32),
        font_error: Option<String>,
    },
    /// Needed, and could not be written.
    Failed {
        freetype: (i32, i32, i32),
        error: String,
    },
}

#[cfg(target_os = "linux")]
impl Outcome {
    pub fn log(&self) {
        let version = |v: &(i32, i32, i32)| format!("{}.{}.{}", v.0, v.1, v.2);
        match self {
            Outcome::NotAppImage => {}
            Outcome::UserConfig => tracing::info!(
                "AppImage fonts: FONTCONFIG_FILE is set; using that font configuration as given"
            ),
            Outcome::HostMatches(freetype) => tracing::debug!(
                "AppImage fonts: host FreeType {} matches the bundled WebKit; fonts left as they are",
                version(freetype)
            ),
            Outcome::FreetypeUnknown => tracing::info!(
                "AppImage fonts: could not read the host's FreeType version; fonts left as they are"
            ),
            Outcome::NoSystemConfig => tracing::warn!(
                "AppImage fonts: no {SYSTEM_CONFIG} to build on; colour emoji fonts are left as they \
                 are, and one in COLRv1 format can stop the window"
            ),
            Outcome::Applied {
                freetype,
                font_error: None,
            } => tracing::info!(
                "AppImage fonts: host FreeType {} is newer than the bundled WebKit expects; colour \
                 emoji come from Ember's own Noto Color Emoji",
                version(freetype)
            ),
            Outcome::Applied {
                freetype,
                font_error: Some(error),
            } => tracing::warn!(
                "AppImage fonts: host FreeType {} is newer than the bundled WebKit expects, and \
                 Ember's emoji font could not be used ({error}); emoji are drawn without colour",
                version(freetype)
            ),
            Outcome::Failed { freetype, error } => tracing::warn!(
                "AppImage fonts: host FreeType {} is newer than the bundled WebKit expects, and \
                 Ember's font configuration could not be written ({error}); an emoji in a COLRv1 \
                 font can stop the window",
                version(freetype)
            ),
        }
    }
}

/// Point fontconfig at Ember's configuration when the AppImage runs on a host
/// whose FreeType the bundled WebKit disagrees with.
///
/// Sets environment variables, so it runs before anything starts a thread:
/// first thing in `run`, before the async runtime.
#[cfg(target_os = "linux")]
pub fn prepare() -> Outcome {
    let Some(appdir) = std::env::var_os("APPDIR").map(PathBuf::from) else {
        return Outcome::NotAppImage;
    };
    let current = std::env::var_os("FONTCONFIG_FILE");
    if current.is_some() && current != std::env::var_os(OVERRIDE_MARKER) {
        return Outcome::UserConfig;
    }
    // Any value from here on is an earlier Ember's, made for its own mount of
    // the AppImage; decided afresh below.
    std::env::remove_var("FONTCONFIG_FILE");
    std::env::remove_var(OVERRIDE_MARKER);

    let Some(freetype) = host_freetype_version() else {
        return Outcome::FreetypeUnknown;
    };
    if !layouts_differ(freetype) {
        return Outcome::HostMatches(freetype);
    }
    if !Path::new(SYSTEM_CONFIG).is_file() {
        return Outcome::NoSystemConfig;
    }
    match write_config(&appdir) {
        Ok((path, font_error)) => {
            std::env::set_var("FONTCONFIG_FILE", &path);
            std::env::set_var(OVERRIDE_MARKER, &path);
            Outcome::Applied { freetype, font_error }
        }
        Err(error) => Outcome::Failed {
            freetype,
            error: error.to_string(),
        },
    }
}

/// Write the configuration into Ember's data folder, with the bundled font
/// copied beside it: a path that stays put across launches, where the
/// AppImage's mount does not, so fontconfig caches the font once.
#[cfg(target_os = "linux")]
fn write_config(appdir: &Path) -> std::io::Result<(PathBuf, Option<String>)> {
    let dir = crate::storage::paths::resolve_data_dir().join("fonts");
    std::fs::create_dir_all(&dir)?;
    let dir_text = dir
        .to_str()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "data folder path is not UTF-8"))?;
    let font_error = install_font(&appdir.join(BUNDLED_FONT_DIR).join(FONT_FILE_NAME), &dir.join(FONT_FILE_NAME))
        .err()
        .map(|error| error.to_string());
    let xml = config_xml(SYSTEM_CONFIG, font_error.is_none().then_some(dir_text));
    let path = dir.join("fonts.conf");
    if std::fs::read(&path).ok().as_deref() != Some(xml.as_bytes()) {
        crate::security::atomic_write(&path, xml.as_bytes(), false)?;
    }
    Ok((path, font_error))
}

/// Copy the AppImage's font to `dest`, unless the copy there is already it.
/// Judged by size, which every release of the font so far has changed.
#[cfg(target_os = "linux")]
fn install_font(source: &Path, dest: &Path) -> std::io::Result<()> {
    let size = std::fs::metadata(source)?.len();
    if std::fs::metadata(dest).is_ok_and(|meta| meta.len() == size) {
        return Ok(());
    }
    let bytes = std::fs::read(source)?;
    crate::security::atomic_write(dest, &bytes, false)
}

/// The FreeType this process will load, as WebKit will: `libfreetype.so.6`
/// from the library path, which for the AppImage is the host's.
#[cfg(target_os = "linux")]
fn host_freetype_version() -> Option<(i32, i32, i32)> {
    // SAFETY: `dlopen` of a library by soname; a null handle is checked.
    let handle = unsafe { libc::dlopen(c"libfreetype.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        return None;
    }
    // SAFETY: `handle` is a live handle from the `dlopen` above.
    let version = unsafe { freetype_version_from(handle) };
    // SAFETY: as above; nothing from the library outlives this call.
    unsafe { libc::dlclose(handle) };
    version
}

/// # Safety
/// `handle` must be a live `dlopen` handle for FreeType.
#[cfg(target_os = "linux")]
unsafe fn freetype_version_from(handle: *mut libc::c_void) -> Option<(i32, i32, i32)> {
    use libc::{c_int, c_void};
    type Init = unsafe extern "C" fn(*mut *mut c_void) -> c_int;
    type Version = unsafe extern "C" fn(*mut c_void, *mut c_int, *mut c_int, *mut c_int);
    type Done = unsafe extern "C" fn(*mut c_void) -> c_int;

    let init = libc::dlsym(handle, c"FT_Init_FreeType".as_ptr());
    let version = libc::dlsym(handle, c"FT_Library_Version".as_ptr());
    let done = libc::dlsym(handle, c"FT_Done_FreeType".as_ptr());
    if init.is_null() || version.is_null() || done.is_null() {
        return None;
    }
    // SAFETY: the three symbols have these signatures in every FreeType 2.
    let (init, version, done) = (
        std::mem::transmute::<*mut c_void, Init>(init),
        std::mem::transmute::<*mut c_void, Version>(version),
        std::mem::transmute::<*mut c_void, Done>(done),
    );
    let mut library: *mut c_void = std::ptr::null_mut();
    if init(&mut library) != 0 || library.is_null() {
        return None;
    }
    let (mut major, mut minor, mut patch) = (0, 0, 0);
    version(library, &mut major, &mut minor, &mut patch);
    done(library);
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn the_hosts_freetype_version_is_read_through_the_library_webkit_loads() {
        let (major, minor, _) = host_freetype_version().expect("libfreetype.so.6 loads and answers");
        assert_eq!(major, 2);
        assert!(minor >= 10, "every distro with WebKitGTK 4.1 has 2.10 or newer, got 2.{minor}");
    }

    #[test]
    fn only_a_host_across_the_layout_change_from_the_build_is_overridden() {
        assert!(!layouts_differ((2, 11, 1)), "Ubuntu 22.04, the build distro");
        assert!(!layouts_differ((2, 12, 1)), "Debian 12");
        assert!(layouts_differ((2, 13, 0)));
        assert!(layouts_differ((2, 13, 3)), "Fedora 44, Debian 13");
        assert!(layouts_differ((2, 14, 1)));
        assert!(layouts_differ((3, 0, 0)));
    }

    #[test]
    fn the_configuration_keeps_the_hosts_and_rejects_every_colour_font_but_the_bundled_one() {
        let xml = config_xml("/etc/fonts/fonts.conf", Some("/home/a & b/.local/share/p2p/fonts"));
        assert!(xml.contains("<include ignore_missing=\"no\">/etc/fonts/fonts.conf</include>"));
        assert!(xml.contains("<dir>/home/a &amp; b/.local/share/p2p/fonts</dir>"));
        assert!(xml.contains(
            "<acceptfont><pattern><patelt name=\"file\"><string>/home/a &amp; b/.local/share/p2p/fonts/NotoColorEmoji.ttf</string></patelt></pattern></acceptfont>"
        ));
        assert!(xml.contains("<patelt name=\"color\"><bool>true</bool></patelt>"));
        let accept = xml.find("<acceptfont>").unwrap();
        let reject = xml.find("<rejectfont>").unwrap();
        assert!(accept < reject);

        let without = config_xml("/etc/fonts/fonts.conf", None);
        assert!(!without.contains("<dir>"));
        assert!(!without.contains("<acceptfont>"));
        assert!(without.contains("<rejectfont>"), "colour fonts go even without ours");
    }

    /// The font must stay the bitmap one: a COLR table would bring back the
    /// very code path it is there to avoid.
    #[test]
    fn the_bundled_font_is_bitmap_colour_with_no_colr_table() {
        let font = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/resources/appimage/NotoColorEmoji.ttf"
        ))
        .expect("the AppImage's emoji font is in the tree");
        let tables = usize::from(u16::from_be_bytes([font[4], font[5]]));
        let tags: Vec<&[u8]> = (0..tables).map(|i| &font[12 + i * 16..16 + i * 16]).collect();
        assert!(tags.contains(&&b"CBDT"[..]));
        assert!(!tags.contains(&&b"COLR"[..]));
        use sha2::Digest;
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&font)),
            "15671215ab769fdc7162a045d56fd7d7e477c51b04e6b3c761d914d8fdd6cc44",
            "the font pinned in the module docs"
        );
    }
}
