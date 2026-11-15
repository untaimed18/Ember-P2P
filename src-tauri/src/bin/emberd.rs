//! `emberd`: Ember with no window, used from a web browser (`docs/headless.md`).

fn main() {
    std::process::exit(ember_lib::emberd_main());
}
