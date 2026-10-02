//! Handlers for the arms of `start_network`'s event loop, one file per arm,
//! plus the deferred-startup steps that run at the top of each pass and the
//! save sequence that runs once the loop ends.
//!
//! Each handler is the body of its `select!` arm as an `async fn`. Arms that
//! ran their body under `catch_unwind` still wrap the call in it, so a panic
//! in one handler is logged and the loop carries on. The rest (download and
//! upload events, the server-connect and buddy results, relay tickets) never
//! were, and are still called bare; in those, a `return` is what was a
//! `continue` of the loop. Parameters are the loop's locals the arm uses,
//! borrowed the way the arm borrowed them.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

mod a4af_tick;
mod bootstrap_tick;
mod broker_tick;
mod buddy_event;
mod buddy_tick;
mod cache_refresh_tick;
mod cleanup_tick;
mod download_event;
mod ember_maintenance_tick;
mod ember_refresh_tick;
mod ember_search_tick;
mod flood_cleanup_tick;
mod friend_relay_ticket_result;
mod kad_callback;
mod kad_process_tick;
mod kad_publish_tick;
mod known_met_save_tick;
mod mapping_keepalive_tick;
mod nat_probe_result;
mod nodes_save_tick;
mod offer_files;
mod publish_tick;
mod punch_poll_tick;
mod rendezvous_register_result;
mod resume_downloads;
mod search_poll_tick;
mod server_connect_result;
mod server_tcp_source_tick;
mod server_tick;
mod server_udp_ping_tick;
mod server_udp_source_tick;
mod shutdown;
mod small_tick;
mod source_count_sync_tick;
mod source_retry_tick;
mod startup_disk_loads;
mod stats_tick;
mod tcp_mapping_keepalive_result;
mod udp_discovery_health_tick;
mod udp_mapping_keepalive_result;
mod udp_source_tick;
mod upload_event;
mod upnp_maintain_result;
mod uss_ping_tick;
mod watchdog_tick;

pub(super) use self::a4af_tick::on_a4af_tick;
pub(super) use self::bootstrap_tick::on_bootstrap_tick;
pub(super) use self::broker_tick::on_broker_tick;
pub(super) use self::buddy_event::on_buddy_event;
pub(super) use self::buddy_tick::on_buddy_tick;
pub(super) use self::cache_refresh_tick::on_cache_refresh_tick;
pub(super) use self::cleanup_tick::on_cleanup_tick;
pub(super) use self::download_event::on_download_event;
pub(super) use self::ember_maintenance_tick::on_ember_maintenance_tick;
pub(super) use self::ember_refresh_tick::on_ember_refresh_tick;
pub(super) use self::ember_search_tick::on_ember_search_tick;
pub(super) use self::flood_cleanup_tick::on_flood_cleanup_tick;
pub(super) use self::friend_relay_ticket_result::on_friend_relay_ticket_poll_result;
pub(super) use self::kad_callback::on_kad_callback_conn;
pub(super) use self::kad_process_tick::on_kad_process_tick;
pub(super) use self::kad_publish_tick::on_kad_publish_tick;
pub(super) use self::known_met_save_tick::{on_known_met_save_tick, start_known_met_save};
pub(super) use self::mapping_keepalive_tick::on_mapping_keepalive_tick;
pub(super) use self::nat_probe_result::on_nat_probe_result;
pub(super) use self::nodes_save_tick::on_nodes_save_tick;
pub(super) use self::offer_files::drain_offer_files;
pub(super) use self::publish_tick::on_publish_tick;
pub(super) use self::punch_poll_tick::on_punch_poll_tick;
pub(super) use self::rendezvous_register_result::on_rendezvous_register_result;
pub(super) use self::resume_downloads::resume_incomplete_downloads;
pub(super) use self::search_poll_tick::on_search_poll_tick;
pub(super) use self::server_connect_result::on_server_connect_result;
pub(super) use self::server_tcp_source_tick::on_server_tcp_source_tick;
pub(super) use self::server_tick::on_server_tick;
pub(super) use self::server_udp_ping_tick::on_server_udp_ping_tick;
pub(super) use self::server_udp_source_tick::on_server_udp_source_tick;
pub(super) use self::shutdown::save_on_shutdown;
pub(super) use self::small_tick::on_small_tick;
pub(super) use self::source_count_sync_tick::on_source_count_sync_tick;
pub(super) use self::source_retry_tick::on_source_retry_tick;
pub(super) use self::startup_disk_loads::apply_deferred_disk_loads;
pub(super) use self::stats_tick::on_stats_tick;
pub(super) use self::tcp_mapping_keepalive_result::on_tcp_mapping_keepalive_result;
pub(super) use self::udp_discovery_health_tick::on_udp_discovery_health_tick;
pub(super) use self::udp_mapping_keepalive_result::on_udp_mapping_keepalive_result;
pub(super) use self::udp_source_tick::on_udp_source_tick;
pub(super) use self::upload_event::on_upload_event;
pub(super) use self::upnp_maintain_result::on_upnp_maintain_result;
pub(super) use self::uss_ping_tick::on_uss_ping_tick;
pub(super) use self::watchdog_tick::on_watchdog_tick;
