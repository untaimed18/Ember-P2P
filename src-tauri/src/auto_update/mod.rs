//! Ember's own update scheduling: when to look for a release while the app is
//! left running, and the bookkeeping that survives restarts.
//!
//! Verification and installation stay in `commands::updater`; this module only
//! decides *when* those run, so it never has to be trusted with what gets
//! installed. See `docs/silent-update.md` for the design.

pub mod record;
pub mod resume;
pub mod scheduler;
pub mod silent;
