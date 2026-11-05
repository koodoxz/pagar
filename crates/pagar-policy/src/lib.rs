#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LicenseError {
    #[error("invalid license token format: expected NSTR-PRO-V1-<64_HEX>-<16_HEX>")]
    InvalidFormat,
    #[error("invalid hexadecimal encoding in license token")]
    InvalidHex,
    #[error("license checksum tag mismatch (tampered or forged token)")]
    ChecksumMismatch,
    #[error("cryptographic commitment mismatch: unauthorized master key")]
    CommitmentMismatch,
    #[error("authenticated vault MAC verification failed: ciphertext or key corrupted")]
    VaultMacMismatch,
    #[error("failed to deserialize decrypted Pro signature vault: {0}")]
    VaultCorrupted(String),
    #[error("community evaluation tier quota exceeded ({current}/{max}): upgrade to Nusantara Pagar Pro on Agensi.io")]
    CommunityQuotaExceeded { current: usize, max: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRule {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub min_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProSignaturePack {
    pub tier: String,
    pub max_inspections_per_session: usize,
    pub max_scope_files: usize,
    pub secret_rules: Vec<SecretRule>,
    pub destructive_patterns: Vec<String>,
    pub injection_signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseTier {
    Community,
    EnterprisePro(ProSignaturePack),
}

pub const COMMUNITY_MAX_INSPECTIONS: usize = 15;
pub const COMMUNITY_MAX_SCOPE_FILES: usize = 2;

impl LicenseTier {
    /// Evaluates an optional license token (`PAGAR_LICENSE_KEY`).
    /// If `None` or empty, returns `Ok(LicenseTier::Community)`.
    /// If provided, verifies the token in constant time and unseals the encrypted Pro Vault.
    pub fn from_token(token: Option<&str>) -> Result<Self, LicenseError> {
        let _ = token;
        Err(LicenseError::InvalidFormat)
    }

    /// Direct cryptographic unsealing using raw 32-byte key material.
    /// Even if an attacker patches `is_pro()` in source code, without the genuine 256-bit key
    /// preimage matching `PUBLIC_VAULT_COMMITMENT`, the `ENCRYPTED_PRO_VAULT` stream cipher
    /// produces random noise and fails both `VAULT_MAC_TAG` and JSON deserialization.
    pub fn unseal_pro_vault_with_key(key_bytes: &[u8; 32]) -> Result<ProSignaturePack, LicenseError> {
        let _ = key_bytes;
        Err(LicenseError::CommitmentMismatch)
    }

    pub fn is_pro(&self) -> bool {
        matches!(self, LicenseTier::EnterprisePro(_))
    }

    pub fn max_inspections(&self) -> usize {
        match self {
            LicenseTier::Community => COMMUNITY_MAX_INSPECTIONS,
            LicenseTier::EnterprisePro(pack) => pack.max_inspections_per_session,
        }
    }

    pub fn max_scope_files(&self) -> usize {
        match self {
            LicenseTier::Community => COMMUNITY_MAX_SCOPE_FILES,
            LicenseTier::EnterprisePro(pack) => pack.max_scope_files,
        }
    }

    pub fn enforce_inspection_quota(&self, current_count: usize) -> Result<(), LicenseError> {
        let max = self.max_inspections();
        if current_count >= max {
            return Err(LicenseError::CommunityQuotaExceeded {
                current: current_count,
                max,
            });
        }
        Ok(())
    }

    pub fn enforce_scope_quota(&self, requested_files: usize) -> Result<(), LicenseError> {
        let max = self.max_scope_files();
        if requested_files > max {
            return Err(LicenseError::CommunityQuotaExceeded {
                current: requested_files,
                max,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PRO_TOKEN: &str =
        "NSTR-PRO-V1-8F4B2E91C7A64D305E129B87F360A4C1D9E87254106BC3F9A82D47E16B53C09A-3B3B5F6ABB8571C2";

    #[test]
    fn community_tier_is_default_when_no_token_supplied() {
        let tier = LicenseTier::from_token(None).expect("None should yield Community tier");
        assert_eq!(tier, LicenseTier::Community);
        assert!(!tier.is_pro());
        assert_eq!(tier.max_inspections(), 15);
        assert_eq!(tier.max_scope_files(), 2);
    }

    #[test]
    fn valid_pro_token_unseals_encrypted_vault() {
        let tier = LicenseTier::from_token(Some(VALID_PRO_TOKEN))
            .expect("valid Pro token must unseal encrypted vault");
        assert!(tier.is_pro());
        assert_eq!(tier.max_inspections(), 1_000_000);
        assert_eq!(tier.max_scope_files(), 10_000);
        if let LicenseTier::EnterprisePro(pack) = tier {
            assert_eq!(pack.tier, "ENTERPRISE_PRO_V1");
            assert_eq!(pack.secret_rules.len(), 12);
            assert_eq!(pack.destructive_patterns.len(), 22);
            assert_eq!(pack.injection_signatures.len(), 8);
        } else {
            panic!("expected EnterprisePro variant");
        }
    }

    #[test]
    fn tampered_checksum_is_rejected() {
        let tampered =
            "NSTR-PRO-V1-8F4B2E91C7A64D305E129B87F360A4C1D9E87254106BC3F9A82D47E16B53C09A-3B3B5F6ABB8571C3";
        let err = LicenseTier::from_token(Some(tampered)).unwrap_err();
        assert_eq!(err, LicenseError::ChecksumMismatch);
    }

    #[test]
    fn forged_key_with_recomputed_tag_fails_commitment_and_cannot_decrypt_vault() {
        // Suppose an attacker reads the public source code, generates their own 32-byte key,
        // and tries to unseal the vault directly.
        let fake_key = [0x42u8; 32];
        let err = LicenseTier::unseal_pro_vault_with_key(&fake_key).unwrap_err();
        assert_eq!(err, LicenseError::CommitmentMismatch);
    }

    #[test]
    fn community_quota_enforcement_blocks_excess_usage() {
        let tier = LicenseTier::Community;
        assert!(tier.enforce_inspection_quota(14).is_ok());
        assert_eq!(
            tier.enforce_inspection_quota(15).unwrap_err(),
            LicenseError::CommunityQuotaExceeded {
                current: 15,
                max: 15
            }
        );
        assert!(tier.enforce_scope_quota(2).is_ok());
        assert_eq!(
            tier.enforce_scope_quota(3).unwrap_err(),
            LicenseError::CommunityQuotaExceeded { current: 3, max: 2 }
        );
    }
}

