//! Password hashing for Proton auth v4.
//!
//! ## Algorithm
//!
//! 1. Decode the server salt from base64 (typically 10 bytes on Proton's API).
//! 2. Append the literal suffix `"proton"` (6 bytes).
//!    For the common 10-byte salt: 10 + 6 = **exactly 16 bytes** — the bcrypt
//!    salt size.  For a 16-byte salt: 16 + 6 = 22 bytes, only the first 16 are
//!    used.
//! 3. Run `bcrypt(password, cost = 10, salt = first_16_bytes_of_combined)`.
//! 4. Normalise the output prefix from `$2b$` (Rust crate) to `$2y$`
//!    (Proton's convention) so the full 60-byte string is byte-for-byte
//!    identical to what go-srp produces.
//! 5. Return those **60 raw bytes**.  They are concatenated with the modulus
//!    bytes in [`super::srp`] and fed into `expand_hash` to derive the SRP
//!    private key x:
//!
//! ```text
//! x = expand_hash(bcrypt_output_bytes ‖ modulus_bytes)
//! ```

use base64::{engine::general_purpose::STANDARD, Engine};

use crate::{Error, Result};

/// Hash `password` with the server-supplied salt using bcrypt (cost = 10).
///
/// Returns the normalised 60-byte bcrypt output string
/// (`$2y$10$<22-char-salt><31-char-hash>`) as raw bytes.
pub fn hash_password(password: &str, server_salt_b64: &str) -> Result<Vec<u8>> {
    let salt_bytes = STANDARD.decode(server_salt_b64)?;

    // Append "proton" suffix before taking the 16-byte bcrypt salt.
    // Common case: 10-byte server salt + 6 bytes "proton" = 16 bytes exactly.
    let mut combined = salt_bytes;
    combined.extend_from_slice(b"proton");

    if combined.len() < 16 {
        return Err(Error::Auth(format!(
            "Salt + \"proton\" is only {} bytes; need at least 16 for bcrypt",
            combined.len()
        )));
    }

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&combined[..16]);

    // bcrypt cost 10 matches Proton's server-side verifier generation.
    let hashed = bcrypt::hash_with_salt(password, 10, salt)
        .map_err(|e| Error::Auth(format!("bcrypt failed: {e}")))?
        .to_string();

    // Sanity-check length: "$2b$10$" (7) + 22-char salt + 31-char hash = 60.
    if hashed.len() != 60 {
        return Err(Error::Auth(format!(
            "Unexpected bcrypt output length: {} (expected 60)",
            hashed.len()
        )));
    }

    // Normalise "$2b$" → "$2y$".  The hash bytes are identical; Proton always
    // uses $2y$ and passes the full string into expand_hash, so the prefix
    // must match for x to be correct.
    let normalised = if let Some(stripped) = hashed.strip_prefix("$2b$") {
        format!("$2y${}", stripped)
    } else {
        hashed
    };

    Ok(normalised.into_bytes())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    /// Encode 10 zero bytes — Proton's typical server salt length.
    fn ten_byte_salt_b64() -> String {
        STANDARD.encode([0u8; 10])
    }

    /// Encode 16 zero bytes.
    fn sixteen_byte_salt_b64() -> String {
        STANDARD.encode([0u8; 16])
    }

    #[test]
    fn hash_password_returns_60_bytes_for_10_byte_salt() {
        let result = hash_password("test-password", &ten_byte_salt_b64()).unwrap();
        assert_eq!(result.len(), 60);
    }

    #[test]
    fn hash_password_returns_60_bytes_for_16_byte_salt() {
        let result = hash_password("test-password", &sixteen_byte_salt_b64()).unwrap();
        assert_eq!(result.len(), 60);
    }

    #[test]
    fn hash_password_outputs_2y_prefix() {
        let result = hash_password("test-password", &ten_byte_salt_b64()).unwrap();
        let s = std::str::from_utf8(&result).unwrap();
        assert!(
            s.starts_with("$2y$10$"),
            "expected $2y$10$ prefix, got: {s}"
        );
    }

    #[test]
    fn hash_password_is_deterministic() {
        let salt = STANDARD.encode([42u8; 10]);
        let a = hash_password("hunter2", &salt).unwrap();
        let b = hash_password("hunter2", &salt).unwrap();
        assert_eq!(a, b, "same password + salt must produce the same hash");
    }

    #[test]
    fn hash_password_differs_for_different_passwords() {
        let salt = STANDARD.encode([1u8; 10]);
        let a = hash_password("password1", &salt).unwrap();
        let b = hash_password("password2", &salt).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn hash_password_differs_for_different_salts() {
        let salt_a = STANDARD.encode([1u8; 10]);
        let salt_b = STANDARD.encode([2u8; 10]);
        let a = hash_password("same-password", &salt_a).unwrap();
        let b = hash_password("same-password", &salt_b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn hash_password_rejects_too_short_salt() {
        // 9 bytes + "proton" (6) = 15 bytes < 16 → should fail.
        let bad_salt = STANDARD.encode([0u8; 9]);
        let err = hash_password("password", &bad_salt).unwrap_err();
        assert!(
            err.to_string().contains("15 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn hash_password_rejects_invalid_base64() {
        let err = hash_password("password", "not-valid-base64!!!").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Base64") || msg.contains("base64") || msg.contains("decode"),
            "unexpected error: {msg}"
        );
    }
}
