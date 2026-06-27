//! SRP-6a implementation for Proton's authentication protocol.
//!
//! ## Proton-specific variant
//!
//! | Parameter | Value |
//! |-----------|-------|
//! | Prime N   | 2048-bit safe prime, PGP-signed, fetched from API |
//! | Generator g | 2 |
//! | Hash H    | `expand_hash` (4× SHA-512, 256-byte output) |
//! | Wire encoding | Big-endian, zero-padded to 256 bytes |
//! | x (password key) | `expand_hash(bcrypt_output ‖ modulus_bytes)` |
//! | K (session key) | `expand_hash(S_padded)` — 256 bytes |
//! | M1 (client proof) | `expand_hash(A ‖ B ‖ K)` |
//! | M2 (server proof) | `expand_hash(A ‖ M1 ‖ K)` |
//!
//! Reference: <https://github.com/ProtonMail/go-srp>

use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigUint;
use num_traits::Zero;
use rand::RngCore;
use sha2::{Digest, Sha512};

use crate::{Error, Result};

const GENERATOR: u64 = 2;
/// All SRP values are padded to this size on the wire (2048 bits).
const SRP_LEN: usize = 256;

/// SRP client proofs ready to be sent to the server.
pub struct SrpProof {
    /// Base64-encoded big-endian client ephemeral A (256 bytes).
    pub client_ephemeral: String,
    /// Base64-encoded client proof M1 (256 bytes).
    pub client_proof: String,
    /// Expected server proof M2 — compare against `AuthResponse.server_proof`.
    pub expected_server_proof: String,
}

/// Compute SRP-6a client proofs for Proton's auth v4.
///
/// # Arguments
/// - `bcrypt_output` — Full bcrypt output string as raw bytes
///   (from [`super::password::hash_password`]).
/// - `modulus_bytes` — Raw 256-byte big-endian prime N
///   (decoded from the PGP-signed modulus field).
/// - `server_ephemeral_b64` — Base64-encoded server ephemeral B.
pub fn generate_srp_proof(
    bcrypt_output: &[u8],
    modulus_bytes: &[u8],
    server_ephemeral_b64: &str,
) -> Result<SrpProof> {
    let b_bytes = STANDARD.decode(server_ephemeral_b64)?;

    let n = BigUint::from_bytes_be(modulus_bytes);
    let b = BigUint::from_bytes_be(&b_bytes);
    let g = BigUint::from(GENERATOR);

    if b.is_zero() || b >= n {
        return Err(Error::Srp("Invalid server ephemeral B".into()));
    }

    // Pad to SRP_LEN bytes (big-endian) — the canonical form used for both
    // transmission and hashing.
    let n_padded = be_padded(&n, SRP_LEN);
    let g_padded = be_padded(&g, SRP_LEN);
    let b_padded = be_padded(&b, SRP_LEN);

    // k = expand_hash(g_padded ‖ n_padded)
    let k = {
        let mut buf = Vec::with_capacity(SRP_LEN * 2);
        buf.extend_from_slice(&g_padded);
        buf.extend_from_slice(&n_padded);
        BigUint::from_bytes_be(&expand_hash(&buf))
    };

    // Random client secret a (256-bit).
    let a = random_256bit();

    // A = g^a mod N
    let big_a = g.modpow(&a, &n);
    let a_padded = be_padded(&big_a, SRP_LEN);

    // u = expand_hash(A_padded ‖ B_padded)
    let u = {
        let mut buf = Vec::with_capacity(SRP_LEN * 2);
        buf.extend_from_slice(&a_padded);
        buf.extend_from_slice(&b_padded);
        BigUint::from_bytes_be(&expand_hash(&buf))
    };
    if u.is_zero() {
        return Err(Error::Srp("SRP abort: u = 0".into()));
    }

    // x = expand_hash(bcrypt_output ‖ modulus_bytes)
    // The bcrypt output already encodes the user's password and salt.
    let x = {
        let mut buf = Vec::with_capacity(bcrypt_output.len() + modulus_bytes.len());
        buf.extend_from_slice(bcrypt_output);
        buf.extend_from_slice(modulus_bytes);
        BigUint::from_bytes_be(&expand_hash(&buf))
    };

    // S = (B − k·g^x mod N)^(a + u·x) mod N
    let gx = g.modpow(&x, &n);
    let kgx = (&k * &gx) % &n;
    let diff = if b >= kgx {
        b - &kgx
    } else {
        // Modular subtraction: (b − kgx) ≡ (b + N − kgx)  mod N
        b + &n - kgx
    };
    let exp = &a + &u * &x;
    let big_s = diff.modpow(&exp, &n);

    // K = expand_hash(S_padded)  — 256-byte session key
    let big_k: [u8; 256] = expand_hash(&be_padded(&big_s, SRP_LEN));

    // M1 = expand_hash(A_padded ‖ B_padded ‖ K)
    let m1: [u8; 256] = {
        let mut buf = Vec::with_capacity(SRP_LEN * 3);
        buf.extend_from_slice(&a_padded);
        buf.extend_from_slice(&b_padded);
        buf.extend_from_slice(&big_k);
        expand_hash(&buf)
    };

    // M2 = expand_hash(A_padded ‖ M1 ‖ K)
    let expected_m2: [u8; 256] = {
        let mut buf = Vec::with_capacity(SRP_LEN * 3);
        buf.extend_from_slice(&a_padded);
        buf.extend_from_slice(&m1);
        buf.extend_from_slice(&big_k);
        expand_hash(&buf)
    };

    Ok(SrpProof {
        client_ephemeral: STANDARD.encode(a_padded),
        client_proof: STANDARD.encode(m1),
        expected_server_proof: STANDARD.encode(expected_m2),
    })
}

/// Strip the PGP signed-message envelope and return the raw modulus bytes.
///
/// Proton delivers N inside a PGP signed message:
/// ```text
/// -----BEGIN PGP SIGNED MESSAGE-----
/// Hash: SHA256
///
/// <base64-encoded modulus (big-endian)>
/// -----BEGIN PGP SIGNATURE-----
/// …
/// ```
///
/// Note: Signature verification is now handled by
/// [`crate::crypto::verify_modulus_signature`] before this is called.
pub fn decode_modulus(pgp_or_b64: &str) -> Result<Vec<u8>> {
    let b64 = if pgp_or_b64.contains("-----BEGIN PGP SIGNED MESSAGE-----") {
        let after_headers = pgp_or_b64
            .find("\n\n")
            .map(|i| &pgp_or_b64[i + 2..])
            .unwrap_or(pgp_or_b64);
        let end = after_headers
            .find("\n-----BEGIN PGP SIGNATURE-----")
            .unwrap_or(after_headers.len());
        after_headers[..end].trim()
    } else {
        pgp_or_b64.trim()
    };

    Ok(STANDARD.decode(b64)?)
}

// ── Core crypto primitives ─────────────────────────────────────────────────

/// `expand_hash(data)` = SHA-512(data‖0) ‖ SHA-512(data‖1) ‖ SHA-512(data‖2) ‖ SHA-512(data‖3)
///
/// Produces a 256-byte digest used everywhere in Proton's SRP in place of plain SHA-512.
pub fn expand_hash(data: &[u8]) -> [u8; 256] {
    let mut out = [0u8; 256];
    for i in 0u8..4 {
        let mut input = data.to_vec();
        input.push(i);
        let hash: [u8; 64] = Sha512::digest(&input).into();
        out[i as usize * 64..(i as usize + 1) * 64].copy_from_slice(&hash);
    }
    out
}

/// Serialize `n` as big-endian bytes, left-zero-padded to exactly `len` bytes.
pub fn be_padded(n: &BigUint, len: usize) -> Vec<u8> {
    let raw = n.to_bytes_be();
    if raw.len() >= len {
        raw[raw.len() - len..].to_vec()
    } else {
        let mut out = vec![0u8; len - raw.len()];
        out.extend_from_slice(&raw);
        out
    }
}

/// Generate a cryptographically random 256-bit (32-byte) BigUint.
fn random_256bit() -> BigUint {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    BigUint::from_bytes_be(&bytes)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    // ── expand_hash ────────────────────────────────────────────────────────

    #[test]
    fn expand_hash_output_is_256_bytes() {
        let out = expand_hash(b"hello");
        assert_eq!(out.len(), 256);
    }

    #[test]
    fn expand_hash_first_64_bytes_match_sha512_with_suffix_0() {
        use sha2::{Digest, Sha512};
        let data = b"proton-drive-test";
        let expected: [u8; 64] = Sha512::digest([data.as_ref(), &[0u8]].concat()).into();
        let got = expand_hash(data);
        assert_eq!(&got[..64], &expected[..]);
    }

    #[test]
    fn expand_hash_last_64_bytes_match_sha512_with_suffix_3() {
        use sha2::{Digest, Sha512};
        let data = b"proton-drive-test";
        let expected: [u8; 64] = Sha512::digest([data.as_ref(), &[3u8]].concat()).into();
        let got = expand_hash(data);
        assert_eq!(&got[192..], &expected[..]);
    }

    #[test]
    fn expand_hash_is_deterministic() {
        assert_eq!(expand_hash(b"same"), expand_hash(b"same"));
    }

    #[test]
    fn expand_hash_differs_for_different_inputs() {
        assert_ne!(expand_hash(b"aaa"), expand_hash(b"bbb"));
    }

    // ── be_padded ──────────────────────────────────────────────────────────

    #[test]
    fn be_padded_pads_short_value() {
        let n = BigUint::from(2u32);
        let padded = be_padded(&n, 4);
        assert_eq!(padded, vec![0, 0, 0, 2]);
    }

    #[test]
    fn be_padded_exact_length_unchanged() {
        let n = BigUint::from(0x0102u32);
        let padded = be_padded(&n, 2);
        assert_eq!(padded, vec![1, 2]);
    }

    #[test]
    fn be_padded_truncates_leading_zeros() {
        // BigUint 256 = 0x0100, padded to 1 byte → 0x00
        let n = BigUint::from(256u32);
        let padded = be_padded(&n, 1);
        assert_eq!(padded, vec![0]);
    }

    // ── SRP math: round-trip (S_client == S_server) ────────────────────────
    //
    // Uses a small safe prime p=23 (2*11+1) to verify the SRP equations
    // without requiring 2048-bit arithmetic in the test.

    fn srp_round_trip_with_prime(p: u64, x_val: u64) {
        let n = BigUint::from(p);
        let g = BigUint::from(2u64);
        let a = BigUint::from(5u64); // client secret
        let b = BigUint::from(3u64); // server secret

        // Fake k and u (just arbitrary small values for math verification)
        let k = BigUint::from(7u64);
        let u = BigUint::from(11u64);
        let x = BigUint::from(x_val);

        // v = g^x mod N  (password verifier, stored on server)
        let v = g.modpow(&x, &n);
        // A = g^a mod N, B = (k*v + g^b) mod N
        let big_a = g.modpow(&a, &n);
        let big_b = ((&k * &v) + g.modpow(&b, &n)) % &n;

        // Client S
        let gx = g.modpow(&x, &n);
        let kgx = (&k * &gx) % &n;
        let diff = if big_b >= kgx {
            big_b.clone() - &kgx
        } else {
            big_b.clone() + &n - &kgx
        };
        let client_s = diff.modpow(&(&a + &u * &x), &n);

        // Server S = (A * v^u)^b mod N
        let server_s = (&big_a * v.modpow(&u, &n) % &n).modpow(&b, &n);

        assert_eq!(client_s, server_s, "S_client must equal S_server");
    }

    #[test]
    fn srp_client_and_server_share_same_secret_p23() {
        srp_round_trip_with_prime(23, 2);
    }

    #[test]
    fn srp_client_and_server_share_same_secret_p47() {
        // 47 = 2*23+1, also a safe prime
        srp_round_trip_with_prime(47, 3);
    }

    // ── decode_modulus ─────────────────────────────────────────────────────

    #[test]
    fn decode_modulus_strips_pgp_wrapper() {
        let pgp = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\naGVsbG8=\n-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----";
        let bytes = decode_modulus(pgp).unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn decode_modulus_plain_base64() {
        let b64 = "aGVsbG8="; // "hello"
        let bytes = decode_modulus(b64).unwrap();
        assert_eq!(bytes, b"hello");
    }

    // ── Full generate_srp_proof smoke test ─────────────────────────────────
    //
    // We cannot reproduce the go-srp test vectors without knowing the exact
    // 2048-bit modulus used in those tests (it is fetched live from the API).
    // This test verifies that the function runs without error and returns
    // correctly-sized, non-empty base64 values.

    #[test]
    fn generate_srp_proof_returns_valid_structure() {
        // Minimal synthetic test: use a small (insecure) prime for speed.
        // Replace with the real 2048-bit Proton modulus for integration tests.
        // Use p=167 which is a safe prime: 167 = 2*83+1
        let n = BigUint::from(167u64);
        let g = BigUint::from(2u64);
        let modulus_bytes = be_padded(&n, 4); // 4 bytes for the tiny test prime

        // Fake B = g^b mod N for some b
        let b_val = BigUint::from(13u64);
        let big_b = g.modpow(&b_val, &n);
        let b_padded = be_padded(&big_b, 4);
        let server_ephemeral_b64 = base64::engine::general_purpose::STANDARD.encode(&b_padded);

        // Fake bcrypt output (just some bytes; x computation will still be deterministic)
        let bcrypt_output = b"$2b$10$fakefakefakefakefakefaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

        let result = generate_srp_proof(bcrypt_output, &modulus_bytes, &server_ephemeral_b64);
        let proof = result.expect("generate_srp_proof should not error with valid inputs");

        // Outputs must be non-empty base64 strings.
        assert!(!proof.client_ephemeral.is_empty());
        assert!(!proof.client_proof.is_empty());
        assert!(!proof.expected_server_proof.is_empty());

        // M1 and M2 are expand_hash outputs = 256 bytes = 344 base64 chars (with padding).
        let m1_bytes = STANDARD.decode(&proof.client_proof).unwrap();
        let m2_bytes = STANDARD.decode(&proof.expected_server_proof).unwrap();
        assert_eq!(m1_bytes.len(), 256, "M1 must be 256 bytes");
        assert_eq!(m2_bytes.len(), 256, "M2 must be 256 bytes");
    }
}
