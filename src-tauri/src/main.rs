// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Before anything else: an update watchdog must start no window, no
    // single-instance registration and no network.
    if ember_lib::run_update_watchdog_if_requested() {
        return;
    }
    ember_lib::run()
}
