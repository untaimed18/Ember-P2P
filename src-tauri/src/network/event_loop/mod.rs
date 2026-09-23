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
mod broker_tick;
mod buddy_tick;
mod cache_refresh_tick;
mod cleanup_tick;
mod ember_maintenance_tick;
mod ember_refresh_tick;
mod ember_search_tick;
mod flood_cleanup_tick;
mod kad_callback;
mod kad_process_tick;
mod kad_publish_tick;
mod known_met_save_tick;
mod mapping_keepalive_tick;
mod nat_probe_result;
mod nodes_save_tick;
mod publish_tick;
mod punch_poll_tick;
mod rendezvous_register_result;
mod search_poll_tick;
mod server_tcp_source_tick;
mod server_tick;
mod server_udp_ping_tick;
mod server_udp_source_tick;
mod small_tick;
mod source_count_sync_tick;
mod source_retry_tick;
mod stats_tick;
mod tcp_mapping_keepalive_result;
mod udp_discovery_health_tick;
mod udp_mapping_keepalive_result;
mod udp_source_tick;
mod upnp_maintain_result;
mod uss_ping_tick;
mod watchdog_tick;

pub(super) use self::a4af_tick::on_a4af_tick;
pub(super) use self::bootstrap_tick::on_bootstrap_tick;
pub(super) use self::broker_tick::on_broker_tick;
pub(super) use self::buddy_tick::on_buddy_tick;
pub(super) use self::cache_refresh_tick::on_cache_refresh_tick;
pub(super) use self::cleanup_tick::on_cleanup_tick;
pub(super) use self::ember_maintenance_tick::on_ember_maintenance_tick;
pub(super) use self::ember_refresh_tick::on_ember_refresh_tick;
pub(super) use self::ember_search_tick::on_ember_search_tick;
pub(super) use self::flood_cleanup_tick::on_flood_cleanup_tick;
pub(super) use self::kad_callback::on_kad_callback_conn;
pub(super) use self::kad_process_tick::on_kad_process_tick;
pub(super) use self::kad_publish_tick::on_kad_publish_tick;
pub(super) use self::known_met_save_tick::on_known_met_save_tick;
pub(super) use self::mapping_keepalive_tick::on_mapping_keepalive_tick;
pub(super) use self::nat_probe_result::on_nat_probe_result;
pub(super) use self::nodes_save_tick::on_nodes_save_tick;
pub(super) use self::publish_tick::on_publish_tick;
pub(super) use self::punch_poll_tick::on_punch_poll_tick;
pub(super) use self::rendezvous_register_result::on_rendezvous_register_result;
pub(super) use self::search_poll_tick::on_search_poll_tick;
pub(super) use self::server_tcp_source_tick::on_server_tcp_source_tick;
pub(super) use self::server_tick::on_server_tick;
pub(super) use self::server_udp_ping_tick::on_server_udp_ping_tick;
pub(super) use self::server_udp_source_tick::on_server_udp_source_tick;
pub(super) use self::small_tick::on_small_tick;
pub(super) use self::source_count_sync_tick::on_source_count_sync_tick;
pub(super) use self::source_retry_tick::on_source_retry_tick;
pub(super) use self::stats_tick::on_stats_tick;
pub(super) use self::tcp_mapping_keepalive_result::on_tcp_mapping_keepalive_result;
pub(super) use self::udp_discovery_health_tick::on_udp_discovery_health_tick;
pub(super) use self::udp_mapping_keepalive_result::on_udp_mapping_keepalive_result;
pub(super) use self::udp_source_tick::on_udp_source_tick;
pub(super) use self::upnp_maintain_result::on_upnp_maintain_result;
pub(super) use self::uss_ping_tick::on_uss_ping_tick;
pub(super) use self::watchdog_tick::on_watchdog_tick;
