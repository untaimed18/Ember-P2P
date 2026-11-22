//! The host `emberd` gives Ember in place of Tauri: no window, a store for
//! the state commands read, and events that go to the web interface's
//! WebSockets rather than to a webview. The names and signatures follow
//! Tauri's, so the code above them is the same in both builds.
#![warn(dead_code, unused_imports)]

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::ops::Deref;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::de::{Deserialize, Deserializer, Visitor};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{broadcast, watch};

/// Why a host call failed.
#[derive(Debug, Clone)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// One event for whoever is watching: a name the UI listens for, and its
/// payload as Tauri would have serialized it.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub event: String,
    pub payload: Value,
}

/// Events waiting for a slow WebSocket. One that falls further behind is
/// dropped and reads its state afresh when it reconnects.
const EVENT_BACKLOG: usize = 4096;

/// `emberd`'s version, as Tauri reads it from the package.
pub struct PackageInfo {
    pub version: semver::Version,
}

struct Inner {
    states: RwLock<HashMap<TypeId, &'static (dyn Any + Send + Sync)>>,
    events: broadcast::Sender<Arc<Event>>,
    exit: watch::Sender<Option<i32>>,
    resource_dir: PathBuf,
    package: PackageInfo,
    /// Questions waiting on a web page's answer, by id.
    confirms: parking_lot::Mutex<HashMap<u64, tokio::sync::oneshot::Sender<bool>>>,
    next_confirm: std::sync::atomic::AtomicU64,
}

/// Ember's handle on the program it runs in.
#[derive(Clone)]
pub struct AppHandle(Arc<Inner>);

impl AppHandle {
    /// `resource_dir` holds what ships with `emberd` (the GeoIP database).
    pub fn new(resource_dir: PathBuf) -> Self {
        let (events, _) = broadcast::channel(EVENT_BACKLOG);
        let (exit, _) = watch::channel(None);
        let version = semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap_or_else(|_| semver::Version::new(0, 0, 0));
        AppHandle(Arc::new(Inner {
            states: RwLock::new(HashMap::new()),
            events,
            exit,
            resource_dir,
            package: PackageInfo { version },
            confirms: parking_lot::Mutex::new(HashMap::new()),
            next_confirm: std::sync::atomic::AtomicU64::new(1),
        }))
    }

    /// As Tauri's, which `AppHandle` has without `Manager` in scope.
    pub fn package_info(&self) -> &PackageInfo {
        &self.0.package
    }

    /// Every event emitted from now on.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Event>> {
        self.0.events.subscribe()
    }

    /// Ask `emberd` to shut down cleanly and exit with `code`.
    pub fn exit(&self, code: i32) {
        self.0.exit.send_replace(Some(code));
    }

    /// Becomes `Some(code)` once something asks `emberd` to exit.
    pub fn exit_requested(&self) -> watch::Receiver<Option<i32>> {
        self.0.exit.subscribe()
    }
}

/// Folders Tauri would find for the app.
pub struct PathResolver<'a>(&'a Inner);

impl PathResolver<'_> {
    pub fn resource_dir(&self) -> Result<PathBuf> {
        Ok(self.0.resource_dir.clone())
    }

    /// Tauri's own data folder, which only matters to the desktop app, as the
    /// place an old install kept its data. `emberd` never had one.
    pub fn app_data_dir(&self) -> Result<PathBuf> {
        Err(Error("emberd has no Tauri data folder".to_string()))
    }
}

/// The kept state of type `T`. Kept state is never dropped, so it is borrowed
/// for as long as the process runs.
fn kept<T: Send + Sync + 'static>(inner: &Inner) -> Option<&'static T> {
    let state: &'static (dyn Any + Send + Sync) = *inner.states.read().get(&TypeId::of::<T>())?;
    state.downcast_ref::<T>()
}

/// State a command reads, as Tauri hands it over: `Clone`, and like Tauri's
/// not `Copy`, so the code shared with the desktop reads the same.
pub struct State<'r, T: Send + Sync + 'static>(&'r T);

impl<'r, T: Send + Sync + 'static> State<'r, T> {
    pub fn inner(&self) -> &'r T {
        self.0
    }
}

impl<T: Send + Sync + 'static> Deref for State<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.0
    }
}

impl<T: Send + Sync + 'static> Clone for State<'_, T> {
    fn clone(&self) -> Self {
        State(self.0)
    }
}

/// `emberd`'s one "window": the web interface. Commands that refuse every
/// window but the main one accept it.
#[derive(Clone)]
pub struct WebviewWindow {
    app: AppHandle,
}

impl WebviewWindow {
    pub fn label(&self) -> &str {
        "main"
    }
}

/// Tauri's `Manager`, for what `emberd` has.
pub trait Manager {
    fn app_handle(&self) -> &AppHandle;

    fn state<T: Send + Sync + 'static>(&self) -> State<'_, T> {
        self.try_state::<T>().unwrap_or_else(|| {
            panic!("state not managed: {}", std::any::type_name::<T>());
        })
    }

    fn try_state<T: Send + Sync + 'static>(&self) -> Option<State<'_, T>> {
        kept::<T>(&self.app_handle().0).map(State)
    }

    /// Keep `state` for the life of the process. False if one of its type is
    /// already kept, as Tauri's `manage` answers.
    fn manage<T: Send + Sync + 'static>(&self, state: T) -> bool {
        let mut states = self.app_handle().0.states.write();
        if states.contains_key(&TypeId::of::<T>()) {
            return false;
        }
        let leaked: &'static T = Box::leak(Box::new(state));
        states.insert(TypeId::of::<T>(), leaked);
        true
    }

    fn path(&self) -> PathResolver<'_> {
        PathResolver(&self.app_handle().0)
    }
}

impl Manager for AppHandle {
    fn app_handle(&self) -> &AppHandle {
        self
    }
}

impl Manager for WebviewWindow {
    fn app_handle(&self) -> &AppHandle {
        &self.app
    }
}

/// Tauri's `Emitter`: an event for every UI watching.
pub trait Emitter {
    fn emit<S: Serialize + Clone>(&self, event: &str, payload: S) -> Result<()>;
}

impl Emitter for AppHandle {
    fn emit<S: Serialize + Clone>(&self, event: &str, payload: S) -> Result<()> {
        let payload = serde_json::to_value(payload).map_err(|e| Error(format!("event {event}: {e}")))?;
        // No receiver is no browser open, which is not a failure.
        let _ = self.0.events.send(Arc::new(Event { event: event.to_string(), payload }));
        Ok(())
    }
}

impl Emitter for WebviewWindow {
    fn emit<S: Serialize + Clone>(&self, event: &str, payload: S) -> Result<()> {
        self.app.emit(event, payload)
    }
}

/// How long a question waits for an answer. Unanswered, it is a no.
const CONFIRM_WAIT: std::time::Duration = std::time::Duration::from_secs(300);

/// What a web page shows for an `ember:confirm` event.
#[derive(Clone, Serialize)]
struct ConfirmRequest {
    id: u64,
    title: String,
    message: String,
    ok: String,
    cancel: String,
    info: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    opens: Option<String>,
}

/// Ask every web page open on `emberd`; the first answer counts. With no page
/// open, or none answering in time, the answer is no.
pub async fn confirm(app: &AppHandle, question: super::Confirm) -> bool {
    if app.0.events.receiver_count() == 0 {
        tracing::info!("Declined \"{}\": no web page is open to ask", question.title);
        return false;
    }
    let id = app.0.next_confirm.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (answer_tx, answer_rx) = tokio::sync::oneshot::channel();
    app.0.confirms.lock().insert(id, answer_tx);
    let request = ConfirmRequest {
        id,
        title: question.title,
        message: question.message,
        ok: question.ok,
        cancel: question.cancel,
        info: question.info,
        opens: question.opens,
    };
    let _ = app.emit("ember:confirm", request);
    let answer = tokio::time::timeout(CONFIRM_WAIT, answer_rx).await;
    app.0.confirms.lock().remove(&id);
    // The other pages close the question too.
    let _ = app.emit("ember:confirm-closed", id);
    matches!(answer, Ok(Ok(true)))
}

/// [`confirm`] for a thread that may block: never an async task's.
pub fn confirm_blocking(app: &AppHandle, question: super::Confirm) -> bool {
    async_runtime::block_on(confirm(app, question))
}

/// A web page's answer to question `id`. A question already answered or
/// given up on ignores it.
pub fn answer_confirm(app: &AppHandle, id: u64, accepted: bool) {
    if let Some(answer) = app.0.confirms.lock().remove(&id) {
        let _ = answer.send(accepted);
    }
}

/// Tauri's `async_runtime`, on the runtime `emberd` starts with.
pub mod async_runtime {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::OnceLock;
    use std::task::{Context, Poll};

    static RUNTIME: OnceLock<tokio::runtime::Handle> = OnceLock::new();

    /// The runtime everything spawns onto, set once at startup.
    pub fn set(handle: tokio::runtime::Handle) {
        let _ = RUNTIME.set(handle);
    }

    fn runtime() -> tokio::runtime::Handle {
        RUNTIME
            .get()
            .cloned()
            .or_else(|| tokio::runtime::Handle::try_current().ok())
            .expect("emberd sets its async runtime before anything is spawned")
    }

    pub struct JoinHandle<T>(tokio::task::JoinHandle<T>);

    impl<T> Future for JoinHandle<T> {
        type Output = super::Result<T>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            Pin::new(&mut self.0).poll(cx).map_err(|e| super::Error(e.to_string()))
        }
    }

    pub fn spawn<F>(task: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        JoinHandle(runtime().spawn(task))
    }

    pub fn spawn_blocking<F, R>(work: F) -> JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        JoinHandle(runtime().spawn_blocking(work))
    }

    pub fn block_on<F: Future>(task: F) -> F::Output {
        runtime().block_on(task)
    }

    pub struct RuntimeHandle(tokio::runtime::Handle);

    impl RuntimeHandle {
        pub fn inner(&self) -> &tokio::runtime::Handle {
            &self.0
        }

        pub fn block_on<F: Future>(&self, task: F) -> F::Output {
            self.0.block_on(task)
        }
    }

    pub fn handle() -> RuntimeHandle {
        RuntimeHandle(runtime())
    }
}

/// Why a call over the web interface failed: its arguments, or the command
/// itself, whose error is passed on as the desktop app would pass it.
#[derive(Debug)]
pub enum InvokeError {
    Args(String),
    Command(Value),
}

/// What a command's dispatcher returns.
pub type InvokeFuture = Pin<Box<dyn Future<Output = std::result::Result<Value, InvokeError>> + Send>>;

/// A command's dispatcher, in `command_table::SERVER_COMMANDS`.
pub type Handler = fn(Invoke) -> InvokeFuture;

/// One call from the web interface: the arguments, as the UI would have
/// passed them to Tauri's `invoke`.
pub struct Invoke {
    app: AppHandle,
    args: serde_json::Map<String, Value>,
}

impl Invoke {
    pub fn new(app: AppHandle, args: serde_json::Map<String, Value>) -> Self {
        Invoke { app, args }
    }

    pub fn state<T: Send + Sync + 'static>(&self) -> std::result::Result<State<'static, T>, InvokeError> {
        kept::<T>(&self.app.0)
            .map(State)
            .ok_or_else(|| InvokeError::Args(format!("state not managed: {}", std::any::type_name::<T>())))
    }

    pub fn app_handle(&self) -> AppHandle {
        self.app.clone()
    }

    pub fn window(&self) -> WebviewWindow {
        WebviewWindow { app: self.app.clone() }
    }

    /// The argument at `key`, read the way Tauri reads it: a missing key is
    /// `None` for an `Option` and an error for anything else.
    pub fn arg<'de, T: Deserialize<'de>>(&'de self, command: &str, key: &str) -> std::result::Result<T, InvokeError> {
        let read = match self.args.get(key) {
            Some(value) => T::deserialize(value),
            None => T::deserialize(Missing { command, key }),
        };
        read.map_err(|e| InvokeError::Args(format!("invalid args `{key}` for command `{command}`: {e}")))
    }
}

/// A key the call left out.
struct Missing<'a> {
    command: &'a str,
    key: &'a str,
}

impl<'de> Deserializer<'de> for Missing<'_> {
    type Error = serde_json::Error;

    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error> {
        Err(serde::de::Error::custom(format!(
            "command {} missing required key {}",
            self.command, self.key
        )))
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> std::result::Result<V::Value, Self::Error> {
        visitor.visit_none()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf unit
        unit_struct newtype_struct seq tuple tuple_struct map struct enum identifier ignored_any
    }
}

/// What a command returned, on its way to JSON. A `Result` is told apart
/// from a plain value by which of the two traits below applies (the same
/// trick `tauri::ipc` plays), so a command's error goes back as an error.
pub struct InvokeTag<T>(pub T);

fn to_json<T: Serialize>(value: &T) -> std::result::Result<Value, InvokeError> {
    serde_json::to_value(value).map_err(|e| InvokeError::Command(Value::String(e.to_string())))
}

pub trait InvokeResult {
    fn invoke_value(&self) -> std::result::Result<Value, InvokeError>;
}

impl<T: Serialize, E: Serialize> InvokeResult for InvokeTag<std::result::Result<T, E>> {
    fn invoke_value(&self) -> std::result::Result<Value, InvokeError> {
        match &self.0 {
            Ok(value) => to_json(value),
            Err(error) => Err(InvokeError::Command(to_json(error)?)),
        }
    }
}

pub trait InvokePlain {
    fn invoke_value(&self) -> std::result::Result<Value, InvokeError>;
}

impl<T: Serialize> InvokePlain for &InvokeTag<T> {
    fn invoke_value(&self) -> std::result::Result<Value, InvokeError> {
        to_json(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invoke(args: Value) -> Invoke {
        let Value::Object(args) = args else { unreachable!() };
        Invoke::new(AppHandle::new(PathBuf::new()), args)
    }

    /// The JSON a command gets matches what Tauri would give it.
    #[test]
    fn arguments_are_read_as_tauri_reads_them() {
        let call = invoke(serde_json::json!({ "requestId": 7, "name": null }));
        assert_eq!(call.arg::<u64>("c", "requestId").unwrap(), 7);
        assert_eq!(call.arg::<Option<String>>("c", "name").unwrap(), None);
        assert_eq!(call.arg::<Option<String>>("c", "absent").unwrap(), None);
        let missing = call.arg::<u64>("c", "absent").unwrap_err();
        assert!(matches!(missing, InvokeError::Args(text) if text.contains("missing required key absent")));
        assert!(call.arg::<u64>("c", "name").is_err(), "null is not a number");
    }

    /// A command's error comes back as an error, and a plain value as a value.
    #[test]
    fn results_and_plain_values_are_told_apart() {
        #[allow(unused_imports)]
        use super::{InvokePlain as _, InvokeResult as _};
        let ok: std::result::Result<u32, String> = Ok(3);
        assert_eq!(InvokeTag(ok).invoke_value().unwrap(), serde_json::json!(3));
        let err: std::result::Result<u32, String> = Err("no".into());
        assert!(matches!(InvokeTag(err).invoke_value(), Err(InvokeError::Command(Value::String(s))) if s == "no"));
        assert_eq!((&InvokeTag("plain")).invoke_value().unwrap(), serde_json::json!("plain"));
        assert_eq!((&InvokeTag(())).invoke_value().unwrap(), Value::Null);
    }

    #[test]
    fn state_is_kept_once_and_found_by_type() {
        let app = AppHandle::new(PathBuf::new());
        assert!(app.manage(5u32));
        assert!(!app.manage(6u32), "a second value of a kept type is refused");
        assert_eq!(*app.state::<u32>(), 5);
        assert!(app.try_state::<String>().is_none());
    }

    /// A question goes to the open pages, and only a yes from one of them
    /// goes ahead; with no page open nothing is asked and the answer is no.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_question_waits_for_a_page_and_takes_its_answer() {
        let app = AppHandle::new(PathBuf::new());
        let question = || super::super::Confirm::new("Add?", "Add the server?", "Add", "Cancel");
        assert!(!confirm(&app, question()).await, "no page open is a no");

        let mut page = app.subscribe();
        let answering = {
            let app = app.clone();
            tokio::spawn(async move {
                let asked = page.recv().await.unwrap();
                assert_eq!(asked.event, "ember:confirm");
                assert_eq!(asked.payload["ok"], "Add");
                let id = asked.payload["id"].as_u64().unwrap();
                answer_confirm(&app, id, true);
                answer_confirm(&app, id, false);
            })
        };
        assert!(confirm(&app, question()).await);
        answering.await.unwrap();
    }

    #[tokio::test]
    async fn events_reach_every_subscriber() {
        let app = AppHandle::new(PathBuf::new());
        let mut first = app.subscribe();
        let mut second = app.subscribe();
        app.emit("network-status", "Connected").unwrap();
        assert_eq!(first.recv().await.unwrap().event, "network-status");
        assert_eq!(second.recv().await.unwrap().payload, serde_json::json!("Connected"));
    }
}
