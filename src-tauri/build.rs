fn main() {
    built_against_freetype();
    tauri_build::build()
}

/// The FreeType this build's WebKit was compiled against, for
/// `appimage_fonts.rs`: an AppImage carries the build distro's WebKit, and
/// the build distro's FreeType is the one whose header is here. Read from the
/// header rather than written down, so the value moves with the distro the
/// AppImage is built on.
fn built_against_freetype() {
    const HEADER: &str = "/usr/include/freetype2/freetype/freetype.h";
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    println!("cargo:rerun-if-changed={HEADER}");
    let version = std::fs::read_to_string(HEADER).ok().and_then(|header| {
        let define = |name: &str| {
            header.lines().find_map(|line| {
                let mut words = line.split_whitespace();
                (words.next()? == "#define" && words.next()? == name).then(|| words.next()?.parse::<u32>().ok())?
            })
        };
        Some((define("FREETYPE_MAJOR")?, define("FREETYPE_MINOR")?))
    });
    match version {
        Some((major, minor)) => println!("cargo:rustc-env=EMBER_BUILT_AGAINST_FREETYPE={major}.{minor}"),
        None => println!(
            "cargo:warning=no FreeType header at {HEADER}; an AppImage of this build overrides colour fonts on every host"
        ),
    }
}
