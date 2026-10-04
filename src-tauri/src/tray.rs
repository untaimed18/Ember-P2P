//! The tray menu's words, in the language the user chose.
//!
//! The locale lives in the webview's local storage and the backend never learns
//! it, so the frontend hands over the translated labels at startup and again
//! after a language change (which reloads the page). English stands in until
//! then. The menu itself is rebuilt by the silent-update driver, which owns the
//! countdown's "Cancel update" entry and so is the one place that knows whether
//! to keep it.
//!
//! It also answers whether the icon can be seen at all, which decides whether
//! "close to tray" may hide the window or has to minimize it instead.

use std::sync::atomic::{AtomicBool, Ordering};

static BUILT: AtomicBool = AtomicBool::new(false);

/// Record whether the tray icon was created, and on Linux start watching for a
/// panel that shows it. Call once, after building the icon.
pub fn note_built(built: bool) {
    BUILT.store(built, Ordering::Release);
    #[cfg(target_os = "linux")]
    if built {
        host::watch();
    }
}

/// Whether a hidden window could be brought back through the tray icon.
///
/// On Linux a built icon is not a visible one: libayatana-appindicator creates
/// it whether or not anything is there to draw it, and stock GNOME has no
/// StatusNotifier host. Hiding the only window there left Ember running with no
/// way back short of launching it again.
pub fn reachable() -> bool {
    if !BUILT.load(Ordering::Acquire) {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        host::present()
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// Watches the session bus for a StatusNotifier host.
///
/// A panel that only offers the older XEmbed tray is not seen here, so on one
/// of those "close to tray" minimizes. That is the safe way to be wrong: a
/// minimized window is still on the taskbar, a hidden one is nowhere.
#[cfg(target_os = "linux")]
mod host {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use zbus::blocking::Connection;
    use zbus::zvariant::Value;

    static PRESENT: AtomicBool = AtomicBool::new(false);
    /// A panel can come and go during a session (the GNOME extension switched
    /// on, plasmashell restarting), so the answer is refreshed on this cadence
    /// rather than taken once.
    const PROBE_INTERVAL: Duration = Duration::from_secs(5);
    /// How long startup waits for the first answer before showing the window.
    /// Past this the window is shown normally rather than left in a tray that
    /// may not exist.
    const FIRST_PROBE_WAIT: Duration = Duration::from_secs(1);

    pub(super) fn present() -> bool {
        PRESENT.load(Ordering::Acquire)
    }

    pub(super) fn watch() {
        let (first_tx, first_rx) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("ember-tray-host".to_string())
            .spawn(move || {
                let mut connection = None;
                let mut first_tx = Some(first_tx);
                let mut last = None;
                loop {
                    let present = probe(&mut connection);
                    PRESENT.store(present, Ordering::Release);
                    if last != Some(present) {
                        if present {
                            tracing::info!("A system tray host is showing Ember's icon");
                        } else {
                            tracing::info!(
                                "No system tray host is showing Ember's icon; \
                                 closing to the tray minimizes the window instead"
                            );
                        }
                        last = Some(present);
                    }
                    if let Some(tx) = first_tx.take() {
                        let _ = tx.send(());
                    }
                    std::thread::sleep(PROBE_INTERVAL);
                }
            });
        match spawned {
            Ok(_) => {
                let _ = first_rx.recv_timeout(FIRST_PROBE_WAIT);
            }
            Err(e) => tracing::warn!("Could not start the tray-host probe ({e})"),
        }
    }

    fn probe(connection: &mut Option<Connection>) -> bool {
        if connection.is_none() {
            *connection = Connection::session().ok();
        }
        let Some(bus) = connection.as_ref() else {
            return false;
        };
        let reply = bus.call_method(
            Some("org.kde.StatusNotifierWatcher"),
            "/StatusNotifierWatcher",
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.kde.StatusNotifierWatcher", "IsStatusNotifierHostRegistered"),
        );
        match reply {
            Ok(reply) => matches!(reply.body().deserialize::<Value<'_>>(), Ok(Value::Bool(true))),
            Err(zbus::Error::MethodError(name, _, _)) => !matches!(
                name.as_str(),
                "org.freedesktop.DBus.Error.ServiceUnknown"
                    | "org.freedesktop.DBus.Error.NameHasNoOwner"
            ),
            Err(_) => {
                *connection = None;
                false
            }
        }
    }
}

/// Where the countdown goes in [`TrayLabels::cancel_update`].
pub const TIME_PLACEHOLDER: &str = "{time}";
const MAX_LABEL_CHARS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayLabels {
    pub show: String,
    pub quit: String,
    /// Holds [`TIME_PLACEHOLDER`] exactly once.
    pub cancel_update: String,
}

impl Default for TrayLabels {
    fn default() -> Self {
        Self {
            show: "Show Ember".to_string(),
            quit: "Quit Ember".to_string(),
            cancel_update: format!("Cancel update ({TIME_PLACEHOLDER})"),
        }
    }
}

impl TrayLabels {
    /// The "Cancel update" entry with the time left filled in.
    pub fn cancel_update_with(&self, time: &str) -> String {
        self.cancel_update.replacen(TIME_PLACEHOLDER, time, 1)
    }
}

static LABELS: parking_lot::RwLock<Option<TrayLabels>> = parking_lot::RwLock::new(None);
static CHANGED: AtomicBool = AtomicBool::new(false);

/// The labels in force: the frontend's, or English until it has sent them.
pub fn labels() -> TrayLabels {
    LABELS.read().clone().unwrap_or_default()
}

/// Whether the labels changed since the last call, so the menu needs building
/// again.
pub fn take_changed() -> bool {
    CHANGED.swap(false, Ordering::AcqRel)
}

/// Bidirectional embeddings, overrides and isolates: format characters rather
/// than controls to Rust, but they reorder the text around them all the same.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// `label` fit for a menu entry, or `None` to keep English.
fn clean(label: &str, needs_time: bool) -> Option<String> {
    let label = label.trim();
    if label.is_empty()
        || label.len() > MAX_LABEL_CHARS * 4
        || label.chars().count() > MAX_LABEL_CHARS
        || label.chars().any(|c| c.is_control() || is_bidi_control(c))
    {
        return None;
    }
    if needs_time && label.matches(TIME_PLACEHOLDER).count() != 1 {
        return None;
    }
    if !needs_time && label.contains(TIME_PLACEHOLDER) {
        return None;
    }
    Some(label.to_string())
}

/// The labels to use for what the frontend sent, each falling back to English
/// on its own when it is not fit to show.
fn accept(show: &str, quit: &str, cancel_update: &str) -> TrayLabels {
    let english = TrayLabels::default();
    let pick = |label: &str, needs_time: bool, fallback: String, name: &str| {
        clean(label, needs_time).unwrap_or_else(|| {
            tracing::warn!("Keeping the English tray label for {name}: the translation is not usable");
            fallback
        })
    };
    TrayLabels {
        show: pick(show, false, english.show, "Show"),
        quit: pick(quit, false, english.quit, "Quit"),
        cancel_update: pick(cancel_update, true, english.cancel_update, "Cancel update"),
    }
}

fn store(labels: TrayLabels) {
    let mut current = LABELS.write();
    if current.as_ref() != Some(&labels) {
        *current = Some(labels);
        CHANGED.store(true, Ordering::Release);
    }
}

/// The tray menu's labels in the frontend's language. `cancel_update` carries
/// `{time}` where the countdown goes.
#[tauri::command]
pub fn set_tray_labels(show: String, quit: String, cancel_update: String) {
    store(accept(&show, &quit, &cancel_update));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_usable_translation_is_taken_as_is() {
        let labels = accept("  Ember anzeigen ", "Ember beenden", "Update abbrechen ({time})");
        assert_eq!(labels.show, "Ember anzeigen");
        assert_eq!(labels.quit, "Ember beenden");
        assert_eq!(labels.cancel_update_with("0:45"), "Update abbrechen (0:45)");
    }

    #[test]
    fn each_unusable_label_falls_back_to_english_on_its_own() {
        let english = TrayLabels::default();
        let labels = accept("", "Quit\nnow", "取消更新（{time}）");
        assert_eq!(labels.show, english.show, "empty");
        assert_eq!(labels.quit, english.quit, "a control character");
        assert_eq!(labels.cancel_update_with("1:00"), "取消更新（1:00）");

        let labels = accept(&"x".repeat(MAX_LABEL_CHARS + 1), "\u{202E}tiuQ", "Cancel update");
        assert_eq!(labels.show, english.show, "too long");
        assert_eq!(labels.quit, english.quit, "a bidi override");
        assert_eq!(labels.cancel_update, english.cancel_update, "no place for the time");

        let labels = accept("Show {time}", "Quit", "{time} {time}");
        assert_eq!(labels.show, english.show, "a placeholder nothing fills");
        assert_eq!(labels.cancel_update, english.cancel_update, "the time twice");
    }

    #[test]
    fn the_longest_label_allowed_counts_characters_not_bytes() {
        let russian = "Ы".repeat(MAX_LABEL_CHARS);
        assert_eq!(accept(&russian, "Quit", "{time}").show, russian);
    }

    #[test]
    fn english_until_the_frontend_says_otherwise() {
        assert_eq!(
            TrayLabels::default().cancel_update_with("0:05"),
            "Cancel update (0:05)"
        );
    }

    #[test]
    fn only_a_real_change_rebuilds_the_menu() {
        let french = accept("Afficher Ember", "Quitter Ember", "Annuler la mise à jour ({time})");
        store(french.clone());
        assert!(take_changed());
        assert_eq!(labels(), french);
        store(french);
        assert!(!take_changed(), "the same labels again, as every page load sends them");
    }
}
