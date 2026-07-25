use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyResetScope {
    /// Clear persisted peer/IP ban rows.
    pub reset_bans: bool,
    /// Quarantine/recreate reputation.json when it fails validation.
    pub reset_reputation: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityPolicyStatus {
    pub loaded: bool,
    pub reset_required: bool,
    pub reason: Option<String>,
    pub scope: PolicyResetScope,
}

/// Startup gate shared by the Tauri command layer and network task. When a
/// durable security source was recovered/reset unexpectedly, sockets and the
/// upload listener remain unopened until the user explicitly acknowledges the
/// reset.
pub struct SecurityPolicyGate {
    loaded: AtomicBool,
    reset_required: AtomicBool,
    reason: parking_lot::RwLock<Option<String>>,
    scope: parking_lot::RwLock<PolicyResetScope>,
    data_dir: PathBuf,
}

impl SecurityPolicyGate {
    pub fn ready(data_dir: PathBuf) -> Self {
        Self {
            loaded: AtomicBool::new(true),
            reset_required: AtomicBool::new(false),
            reason: parking_lot::RwLock::new(None),
            scope: parking_lot::RwLock::new(PolicyResetScope::default()),
            data_dir,
        }
    }

    pub fn blocked(data_dir: PathBuf, reason: impl Into<String>, scope: PolicyResetScope) -> Self {
        Self {
            loaded: AtomicBool::new(false),
            reset_required: AtomicBool::new(true),
            reason: parking_lot::RwLock::new(Some(reason.into())),
            scope: parking_lot::RwLock::new(scope),
            data_dir,
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::Acquire)
    }

    pub fn reset_scope(&self) -> PolicyResetScope {
        *self.scope.read()
    }

    pub fn status(&self) -> SecurityPolicyStatus {
        SecurityPolicyStatus {
            loaded: self.is_loaded(),
            reset_required: self.reset_required.load(Ordering::Acquire),
            reason: self.reason.read().clone(),
            scope: self.reset_scope(),
        }
    }

    /// Atomically claim and complete an explicit reset acknowledgement.
    /// The ban-reset closure is invoked only when the blocked scope includes bans.
    pub fn acknowledge_reset_if_required(
        &self,
        reset_bans: impl FnOnce() -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        if self
            .reset_required
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "security policy reset is not required",
            ));
        }

        let result = self.finish_reset(reset_bans);
        if result.is_err() {
            self.reset_required.store(true, Ordering::Release);
        }
        result
    }

    fn finish_reset(
        &self,
        reset_bans: impl FnOnce() -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let scope = self.reset_scope();
        if scope.reset_bans {
            reset_bans()?;
        }
        if scope.reset_reputation {
            let reputation = self.data_dir.join("reputation.json");
            if reputation.exists()
                && crate::network::ember::reputation::ReputationManager::load_checked(&reputation)
                    .is_err()
            {
                preserve_corrupt(&reputation)?;
                crate::network::ember::reputation::ReputationManager::new()
                    .save(&reputation)
                    .map_err(std::io::Error::other)?;
            }
        }
        let acknowledgement = serde_json::json!({
            "version": 1,
            "acknowledgedAt": chrono::Utc::now().timestamp(),
            "reason": self.reason.read().clone(),
            "scope": scope,
        });
        let data = serde_json::to_vec_pretty(&acknowledgement)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        crate::security::atomic_write(
            &self.data_dir.join("security_policy_reset.json"),
            &data,
            true,
        )?;
        self.loaded.store(true, Ordering::Release);
        Ok(())
    }
}

fn preserve_corrupt(path: &Path) -> std::io::Result<()> {
    let stamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let mut destination = path.with_extension(format!("json.{stamp}.corrupt"));
    let mut suffix = 0u32;
    while destination.exists() {
        suffix = suffix.saturating_add(1);
        destination = path.with_extension(format!("json.{stamp}.{suffix}.corrupt"));
    }
    std::fs::rename(path, &destination).or_else(|_| {
        std::fs::copy(path, &destination)?;
        std::fs::remove_file(path)
    })?;
    crate::security::restrict_file_permissions_checked(&destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    fn test_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ember-policy-ack-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn ready_gate_rejects_acknowledgement_without_clearing_policy() {
        let dir = test_dir("ready");
        let gate = SecurityPolicyGate::ready(dir.clone());
        let bans = AtomicUsize::new(3);
        let before = gate.status();

        let result = gate.acknowledge_reset_if_required(|| {
            bans.store(0, AtomicOrdering::Release);
            Ok(())
        });

        assert!(result.is_err());
        assert_eq!(bans.load(AtomicOrdering::Acquire), 3);
        let after = gate.status();
        assert_eq!(after.loaded, before.loaded);
        assert_eq!(after.reset_required, before.reset_required);
        assert_eq!(after.reason, before.reason);
        assert!(!dir.join("security_policy_reset.json").exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn blocked_gate_acknowledgement_resets_policy_and_releases_gate() {
        let dir = test_dir("blocked");
        let gate = SecurityPolicyGate::blocked(
            dir.clone(),
            "corrupt bans",
            PolicyResetScope {
                reset_bans: true,
                reset_reputation: false,
            },
        );
        let bans = AtomicUsize::new(3);

        gate.acknowledge_reset_if_required(|| {
            bans.store(0, AtomicOrdering::Release);
            Ok(())
        })
        .unwrap();

        assert_eq!(bans.load(AtomicOrdering::Acquire), 0);
        let status = gate.status();
        assert!(status.loaded);
        assert!(!status.reset_required);
        assert!(dir.join("security_policy_reset.json").exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reputation_only_scope_does_not_invoke_ban_reset() {
        let dir = test_dir("reputation-only");
        let gate = SecurityPolicyGate::blocked(
            dir.clone(),
            "corrupt reputation",
            PolicyResetScope {
                reset_bans: false,
                reset_reputation: true,
            },
        );
        let bans = AtomicUsize::new(3);
        gate.acknowledge_reset_if_required(|| {
            bans.store(0, AtomicOrdering::Release);
            Ok(())
        })
        .unwrap();
        assert_eq!(bans.load(AtomicOrdering::Acquire), 3);
        assert!(gate.is_loaded());
        let _ = std::fs::remove_dir_all(dir);
    }
}
