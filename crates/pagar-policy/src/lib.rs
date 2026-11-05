#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PUBLIC_VAULT_COMMITMENT: [u8; 32] = [
    248, 65, 58, 86, 161, 172, 112, 183, 4, 152, 198, 2, 22, 248, 234, 186, 80, 44, 6, 81, 22, 214,
    227, 214, 231, 44, 131, 23, 227, 155, 126, 121,
];

pub const VAULT_MAC_TAG: [u8; 32] = [
    167, 167, 97, 84, 169, 40, 219, 24, 121, 64, 78, 115, 126, 136, 100, 29, 141, 212, 180, 60,
    117, 106, 68, 159, 227, 228, 21, 95, 183, 158, 108, 210,
];

pub const ENCRYPTED_PRO_VAULT: &[u8] = &[
    126, 46, 234, 104, 7, 203, 122, 0, 48, 35, 4, 48, 161, 35, 60, 189, 101, 211, 186, 254, 96,
    151, 13, 96, 211, 217, 226, 102, 248, 102, 94, 13, 139, 173, 246, 159, 158, 45, 43, 211, 225,
    59, 106, 128, 22, 100, 80, 125, 118, 178, 174, 74, 101, 64, 164, 63, 128, 152, 165, 10, 66,
    220, 134, 158, 149, 202, 18, 101, 188, 19, 174, 42, 19, 52, 1, 3, 112, 5, 90, 13, 167, 169,
    190, 154, 1, 41, 170, 175, 157, 226, 81, 28, 17, 132, 183, 175, 57, 99, 227, 54, 189, 248, 31,
    189, 208, 252, 93, 49, 10, 120, 151, 202, 41, 97, 120, 150, 81, 206, 158, 220, 88, 82, 220, 78,
    230, 244, 185, 73, 13, 95, 203, 92, 8, 33, 67, 208, 156, 225, 104, 119, 239, 254, 126, 36, 142,
    203, 117, 155, 199, 163, 110, 85, 12, 228, 189, 146, 82, 151, 142, 54, 185, 35, 100, 21, 147,
    61, 217, 29, 4, 73, 148, 64, 250, 41, 254, 175, 112, 147, 54, 180, 249, 32, 11, 238, 246, 218,
    160, 50, 205, 68, 160, 245, 46, 237, 59, 59, 84, 231, 52, 54, 68, 51, 156, 81, 178, 188, 204,
    164, 124, 175, 125, 172, 189, 46, 49, 209, 123, 184, 35, 107, 219, 88, 202, 217, 43, 145, 188,
    81, 213, 117, 159, 165, 236, 154, 201, 23, 35, 21, 145, 131, 109, 82, 173, 76, 139, 214, 158,
    101, 226, 237, 202, 26, 105, 233, 16, 170, 93, 131, 130, 250, 182, 28, 174, 59, 167, 28, 128,
    100, 107, 240, 4, 97, 13, 11, 95, 186, 192, 20, 215, 127, 70, 35, 248, 118, 11, 4, 114, 33, 46,
    14, 233, 235, 165, 159, 41, 183, 105, 66, 200, 39, 77, 195, 52, 154, 111, 173, 163, 96, 111,
    163, 131, 155, 142, 129, 231, 30, 2, 29, 145, 35, 34, 88, 75, 1, 11, 155, 211, 80, 47, 50, 147,
    109, 220, 66, 57, 42, 175, 81, 113, 76, 120, 29, 30, 239, 145, 122, 2, 140, 5, 159, 209, 18,
    191, 167, 20, 42, 165, 16, 233, 239, 158, 181, 203, 253, 192, 144, 11, 193, 76, 241, 137, 67,
    159, 228, 93, 233, 23, 56, 106, 231, 114, 77, 157, 100, 26, 146, 187, 227, 181, 103, 209, 83,
    96, 225, 145, 241, 172, 14, 113, 43, 252, 84, 119, 209, 47, 6, 66, 144, 80, 122, 101, 38, 94,
    164, 241, 241, 91, 11, 14, 226, 211, 171, 49, 29, 69, 226, 2, 67, 219, 161, 255, 227, 186, 5,
    180, 86, 162, 176, 67, 200, 112, 26, 101, 158, 190, 41, 108, 196, 211, 155, 53, 82, 182, 38,
    136, 69, 6, 80, 133, 15, 133, 10, 63, 221, 222, 209, 220, 174, 119, 75, 126, 219, 149, 131,
    50, 241, 80, 248, 193, 1, 139, 70, 192, 146, 11, 130, 28, 5, 236, 211, 100, 76, 234, 17, 34,
    225, 203, 43, 132, 49, 186, 248, 64, 244, 86, 226, 157, 60, 63, 129, 0, 240, 90, 99, 255, 133,
    134, 153, 145, 124, 247, 242, 224, 202, 173, 196, 40, 104, 187, 176, 107, 216, 31, 214, 198,
    173, 249, 67, 122, 48, 239, 138, 144, 124, 118, 173, 24, 19, 105, 224, 248, 76, 135, 218, 121,
    38, 31, 203, 123, 19, 240, 66, 34, 99, 32, 194, 219, 103, 229, 216, 43, 196, 177, 245, 222,
    211, 36, 55, 88, 14, 48, 94, 192, 247, 10, 164, 189, 237, 96, 190, 105, 82, 15, 196, 126, 197,
    72, 145, 145, 22, 213, 90, 24, 153, 151, 90, 97, 193, 21, 241, 196, 66, 68, 253, 72, 106, 13,
    68, 200, 62, 179, 165, 172, 242, 35, 95, 16, 241, 178, 182, 72, 170, 102, 69, 131, 132, 94,
    222, 4, 68, 147, 190, 16, 58, 152, 246, 67, 99, 232, 3, 32, 115, 28, 128, 98, 145, 100, 117,
    222, 154, 137, 13, 228, 178, 199, 175, 160, 149, 197, 161, 140, 122, 161, 62, 173, 187, 184,
    200, 117, 142, 148, 46, 160, 30, 230, 109, 32, 9, 249, 220, 126, 110, 226, 51, 185, 46, 155,
    166, 233, 246, 81, 3, 46, 16, 219, 143, 154, 48, 231, 75, 101, 160, 216, 56, 138, 112, 5, 131,
    89, 63, 8, 106, 6, 88, 151, 155, 198, 115, 142, 213, 34, 10, 238, 137, 54, 174, 1, 161, 254,
    58, 51, 16, 255, 194, 101, 227, 29, 124, 246, 14, 219, 67, 106, 251, 127, 188, 64, 255, 41,
    94, 215, 90, 1, 30, 109, 26, 176, 64, 146, 209, 51, 252, 65, 127, 109, 73, 150, 213, 60, 123,
    29, 153, 200, 249, 83, 193, 78, 104, 46, 244, 153, 181, 178, 118, 195, 195, 26, 173, 107, 3,
    32, 244, 52, 149, 52, 235, 52, 12, 74, 212, 255, 31, 158, 235, 252, 201, 32, 212, 84, 172, 24,
    177, 21, 135, 21, 231, 5, 43, 64, 55, 118, 198, 34, 8, 45, 54, 181, 192, 232, 90, 233, 68, 99,
    36, 88, 0, 10, 242, 119, 182, 214, 31, 17, 22, 250, 141, 125, 77, 186, 117, 211, 100, 139, 83,
    133, 215, 36, 108, 3, 164, 84, 80, 205, 126, 5, 199, 2, 24, 30, 69, 169, 115, 17, 207, 136,
    70, 230, 51, 110, 107, 86, 210, 45, 211, 138, 148, 14, 89, 207, 189, 46, 97, 43, 139, 3, 105,
    9, 54, 150, 67, 45, 235, 8, 200, 216, 159, 200, 34, 148, 140, 164, 154, 20, 11, 241, 249, 154,
    55, 54, 165, 54, 249, 162, 225, 33, 169, 165, 93, 201, 94, 89, 77, 142, 171, 242, 132, 59, 61,
    217, 151, 196, 9, 222, 4, 75, 10, 78, 250, 133, 35, 108, 223, 128, 211, 178, 209, 186, 27, 122,
    104, 93, 13, 134, 227, 201, 39, 24, 157, 178, 125, 85, 6, 85, 201, 243, 69, 117, 255, 197, 212,
    98, 243, 155, 175, 70, 187, 253, 131, 239, 87, 235, 12, 168, 31, 239, 168, 9, 163, 179, 38,
    239, 126, 27, 92, 231, 239, 98, 144, 121, 118, 135, 35, 99, 170, 65, 23, 87, 239, 162, 46, 142,
    11, 251, 6, 130, 58, 143, 80, 41, 196, 140, 171, 159, 84, 33, 76, 194, 158, 158, 58, 118, 124,
    185, 39, 195, 231, 116, 38, 104, 223, 195, 40, 219, 107, 3, 125, 10, 112, 7, 66, 177, 42, 85,
    230, 56, 108, 208, 201, 15, 245, 226, 118, 22, 244, 10, 236, 246, 199, 85, 127, 7, 7, 70, 1,
    217, 253, 7, 77, 23, 208, 210, 239, 47, 219, 255, 143, 179, 236, 46, 121, 161, 177, 16, 200,
    115, 141, 168, 149, 136, 82, 206, 162, 172, 62, 248, 43, 180, 169, 126, 232, 120, 101, 72, 110,
    204, 92, 138, 59, 45, 9, 75, 183, 35, 11, 139, 218, 232, 156, 244, 131, 105, 159, 203, 142,
    204, 85, 135, 124, 202, 141, 34, 45, 156, 222, 44, 236, 199, 108, 32, 226, 168, 11, 26, 10,
    135, 225, 223, 164, 2, 39, 38, 178, 28, 217, 237, 133, 139, 150, 230, 77, 161, 124, 5, 250,
    237, 1, 157, 138, 168, 171, 65, 72, 15, 53, 14, 146, 68, 32, 2, 230, 143, 165, 87, 96, 227,
    157, 31, 183, 98, 63, 236, 130, 241, 134, 9, 0, 158, 11, 186, 32, 164, 110, 152, 31, 7, 28,
    152, 198, 36, 112, 91, 100, 195, 133, 209, 90, 41, 250, 198, 83, 199, 234, 1, 239, 118, 168,
    14, 102, 187, 147, 212, 252, 73, 9, 19, 86, 19, 234, 141, 20, 54, 14, 33, 103, 67, 250, 204,
    42, 181, 200, 15, 161, 177, 92, 50, 236, 148, 84, 116, 179, 83, 230, 248, 19, 8, 124, 106, 161,
    138, 48, 126, 82, 78, 195, 234, 160, 197, 183, 249, 225, 39, 252, 39, 52, 111, 185, 171, 39,
    223, 95, 23, 178, 146, 254, 32, 60, 33, 62, 223, 86, 239, 146, 227, 90, 181, 55, 77, 96, 209,
    200, 247, 106, 93, 87, 49, 198, 182, 62, 12, 7, 31, 149, 175, 107, 82, 227, 93, 169, 213, 155,
    197, 212, 51, 254, 143, 134, 117, 162, 85, 107, 105, 170, 6, 229, 62, 221, 168, 159, 90, 108,
    192, 81, 34, 183, 246, 21, 180, 104, 84, 220, 171, 162, 251, 68, 68, 187, 195, 19, 7, 15, 79,
    239, 139, 224, 217, 54, 138, 130, 218, 184, 92, 240, 65, 50, 136, 76, 66, 215, 162, 120, 232,
    75, 115, 97, 235, 164, 114, 63, 38, 228, 248, 126, 120, 48, 10, 241, 215, 30, 84, 56, 82, 150,
    193, 144, 102, 247, 100, 35, 99, 129, 31, 235, 145, 107, 98, 23, 133, 36, 85, 194, 42, 77, 42,
    114, 152, 251, 213, 205, 174, 26, 228, 159, 123, 158, 95, 21, 150, 131, 118, 153, 26, 172, 178,
    88, 207, 151, 31, 48, 231, 75, 161, 61, 139, 163, 107, 135, 149, 59, 115, 66, 156, 1, 174, 57,
    95, 14, 128, 131, 47, 253, 191, 71, 156, 105, 171, 63, 241, 172, 215, 171, 33, 161, 251, 35,
    107, 139, 152, 222, 31, 247, 6, 68, 153, 39, 82, 194, 58, 38, 242, 157, 149, 152, 189, 199,
    168, 87, 49, 118, 125, 20, 93, 61, 11, 106, 29, 152, 187, 216, 40, 148, 177, 241, 123, 31, 228,
    169, 169, 147, 208, 88, 187, 188, 140, 254, 68, 78, 239, 167, 58, 33, 154, 140, 27, 82, 223,
    69, 254, 176, 178, 118, 232, 229, 12, 232, 104, 221, 64, 34, 196, 74, 182, 210, 98, 96, 249,
    143, 6, 77, 143, 155, 56, 7, 30, 115, 143, 15, 127, 218, 97, 170, 139, 210, 48, 11, 198, 41,
    43, 194, 255, 25, 112, 172, 3, 248, 250, 188, 102, 185, 84, 201, 17, 25, 0, 32, 59, 168, 158,
    204, 38, 127, 133, 210, 32, 38, 165, 247, 75, 48, 77, 79, 120, 71, 136, 147, 203, 105, 2, 108,
    219, 202, 16, 72, 18, 212, 7, 240, 146, 177, 195, 79,
];

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

/// Constant-time byte comparison to prevent timing side-channel attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, LicenseError> {
    if !hex.len().is_multiple_of(2) {
        return Err(LicenseError::InvalidHex);
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, LicenseError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(LicenseError::InvalidHex),
    }
}

/// Raw stream decryption helper (`SHA256-CTR`) without commitment/MAC checks,
/// exposed to prove in tests that bypassing commitment checks still fails to deserialize the vault.
pub fn raw_decrypt_vault_bytes(key_bytes: &[u8; 32]) -> Vec<u8> {
    let mut plain = vec![0u8; ENCRYPTED_PRO_VAULT.len()];
    let mut offset = 0usize;
    while offset < ENCRYPTED_PRO_VAULT.len() {
        let block_idx = (offset / 32) as u64;
        let mut hasher = Sha256::new();
        hasher.update(b"NUSANTARA-PAGAR-STREAM-V1:");
        hasher.update(key_bytes);
        hasher.update(block_idx.to_le_bytes());
        let stream_block = hasher.finalize();
        let take = std::cmp::min(32, ENCRYPTED_PRO_VAULT.len() - offset);
        for j in 0..take {
            plain[offset + j] = ENCRYPTED_PRO_VAULT[offset + j] ^ stream_block[j];
        }
        offset += 32;
    }
    plain
}

impl LicenseTier {
    /// Evaluates an optional license token (`PAGAR_LICENSE_KEY`).
    /// If `None` or empty, returns `Ok(LicenseTier::Community)`.
    /// If provided, verifies the token in constant time and unseals the encrypted Pro Vault.
    pub fn from_token(token: Option<&str>) -> Result<Self, LicenseError> {
        let raw = match token {
            None => return Ok(LicenseTier::Community),
            Some(s) if s.trim().is_empty() => return Ok(LicenseTier::Community),
            Some(s) => s.trim(),
        };

        let rest = raw
            .strip_prefix("NSTR-PRO-V1-")
            .ok_or(LicenseError::InvalidFormat)?;
        let (key_hex, tag_hex) = rest
            .split_once('-')
            .ok_or(LicenseError::InvalidFormat)?;

        if key_hex.len() != 64 || tag_hex.len() != 16 {
            return Err(LicenseError::InvalidFormat);
        }

        let key_vec = decode_hex(key_hex)?;
        let tag_vec = decode_hex(tag_hex)?;
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key_vec);

        let mut tag_hasher = Sha256::new();
        tag_hasher.update(b"NUSANTARA-LICENSE-TAG-V1:");
        tag_hasher.update(key_bytes);
        let expected_tag_full = tag_hasher.finalize();

        if !constant_time_eq(&tag_vec, &expected_tag_full[..8]) {
            return Err(LicenseError::ChecksumMismatch);
        }

        let pack = Self::unseal_pro_vault_with_key(&key_bytes)?;
        Ok(LicenseTier::EnterprisePro(pack))
    }

    /// Direct cryptographic unsealing using raw 32-byte key material.
    /// Even if an attacker patches `is_pro()` in source code, without the genuine 256-bit key
    /// preimage matching `PUBLIC_VAULT_COMMITMENT`, the `ENCRYPTED_PRO_VAULT` stream cipher
    /// produces random noise and fails both `VAULT_MAC_TAG` and JSON deserialization.
    pub fn unseal_pro_vault_with_key(key_bytes: &[u8; 32]) -> Result<ProSignaturePack, LicenseError> {
        let mut commit_hasher = Sha256::new();
        commit_hasher.update(b"NUSANTARA-PAGAR-COMMITMENT-V1:");
        commit_hasher.update(key_bytes);
        let actual_commit = commit_hasher.finalize();

        if !constant_time_eq(&actual_commit, &PUBLIC_VAULT_COMMITMENT) {
            return Err(LicenseError::CommitmentMismatch);
        }

        let mut mac_hasher = Sha256::new();
        mac_hasher.update(b"NUSANTARA-PAGAR-MAC-V1:");
        mac_hasher.update(key_bytes);
        mac_hasher.update(ENCRYPTED_PRO_VAULT);
        let actual_mac = mac_hasher.finalize();

        if !constant_time_eq(&actual_mac, &VAULT_MAC_TAG) {
            return Err(LicenseError::VaultMacMismatch);
        }

        let decrypted = raw_decrypt_vault_bytes(key_bytes);
        serde_json::from_slice::<ProSignaturePack>(&decrypted)
            .map_err(|e| LicenseError::VaultCorrupted(e.to_string()))
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
        let fake_key = [0x42u8; 32];
        let err = LicenseTier::unseal_pro_vault_with_key(&fake_key).unwrap_err();
        assert_eq!(err, LicenseError::CommitmentMismatch);

        // Even if an attacker comments out the commitment and MAC checks in source code,
        // decrypting ENCRYPTED_PRO_VAULT without the true 256-bit preimage produces gibberish!
        let garbage = raw_decrypt_vault_bytes(&fake_key);
        assert!(serde_json::from_slice::<ProSignaturePack>(&garbage).is_err());
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
