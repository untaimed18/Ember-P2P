//! What the rest of Ember needs from the program it runs in. The desktop app
//! runs in Tauri, and these are Tauri's own types. `emberd` has no window: it
//! gives the same names its own meaning (`host/server.rs`), so the network,
//! sharing and storage code, and the commands, are one code for both.

#[cfg(all(feature = "desktop", feature = "server"))]
compile_error!(
    "build the desktop app (the default) or emberd (`--no-default-features --features server`), not both"
);

#[cfg(feature = "desktop")]
pub use tauri::{async_runtime, AppHandle, Emitter, Manager, State, WebviewWindow};

#[cfg(feature = "server")]
mod server;
#[cfg(feature = "server")]
pub use server::*;

/// A question Ember asks before doing something it should not do on the
/// UI's word alone. The desktop app asks in a native dialog; `emberd` asks
/// every web page open on it.
pub struct Confirm {
    pub title: String,
    pub message: String,
    /// The button that goes ahead.
    pub ok: String,
    /// The button that does not.
    pub cancel: String,
    /// A question with nothing at risk, shown without a warning sign.
    pub info: bool,
    /// A web address that going ahead opens. On emberd the web page opens it
    /// as the button is clicked, since a browser opens a tab only from a
    /// click; the desktop app opens it after the answer.
    #[cfg_attr(feature = "desktop", allow(dead_code))]
    pub opens: Option<String>,
}

impl Confirm {
    pub fn new(title: impl Into<String>, message: impl Into<String>, ok: impl Into<String>, cancel: impl Into<String>) -> Self {
        Confirm { title: title.into(), message: message.into(), ok: ok.into(), cancel: cancel.into(), info: false, opens: None }
    }

    /// The same question, without the warning sign.
    pub fn without_warning(mut self) -> Self {
        self.info = true;
        self
    }

    /// The same question, for opening `url`.
    pub fn opening(mut self, url: impl Into<String>) -> Self {
        self.opens = Some(url.into());
        self
    }
}

/// Ask `question`, true only if the user chose to go ahead.
#[cfg(feature = "desktop")]
pub async fn confirm(app: &AppHandle, question: Confirm) -> bool {
    let app = app.clone();
    // `blocking_show` parks its thread until the main thread pumps the
    // dialog, so it cannot run on the caller's task.
    tokio::task::spawn_blocking(move || confirm_blocking(&app, question)).await.unwrap_or(false)
}

/// [`confirm`] for a thread that may block: never an async task's.
#[cfg(feature = "desktop")]
pub fn confirm_blocking(app: &AppHandle, question: Confirm) -> bool {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
    app.dialog()
        .message(question.message)
        .title(question.title)
        .kind(if question.info { MessageDialogKind::Info } else { MessageDialogKind::Warning })
        .buttons(MessageDialogButtons::OkCancelCustom(question.ok, question.cancel))
        .blocking_show()
}
