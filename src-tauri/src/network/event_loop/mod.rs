//! Handlers for the arms of `start_network`'s event loop, one file per arm.
//!
//! Each handler is the body of its `select!` arm as an `async fn`. The arm
//! still wraps the call in `catch_unwind`, so a panic in one handler is
//! logged and the loop carries on. Parameters are the loop's locals the arm
//! uses, borrowed the way the arm's `async` block borrowed them.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

mod a4af_tick;
mod bootstrap_tick;
mod cleanup_tick;
mod ember_refresh_tick;
mod ember_search_tick;
mod kad_callback;
mod search_poll_tick;
mod server_tick;
mod server_udp_ping_tick;
mod source_retry_tick;

pub(super) use self::a4af_tick::on_a4af_tick;
pub(super) use self::bootstrap_tick::on_bootstrap_tick;
pub(super) use self::cleanup_tick::on_cleanup_tick;
pub(super) use self::ember_refresh_tick::on_ember_refresh_tick;
pub(super) use self::ember_search_tick::on_ember_search_tick;
pub(super) use self::kad_callback::on_kad_callback_conn;
pub(super) use self::search_poll_tick::on_search_poll_tick;
pub(super) use self::server_tick::on_server_tick;
pub(super) use self::server_udp_ping_tick::on_server_udp_ping_tick;
pub(super) use self::source_retry_tick::on_source_retry_tick;
