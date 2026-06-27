//! Integration tests for the authentication pipeline.
//!
//! ## go-srp test vectors
//!
//! The values below come from `TestSRPauth` in the ProtonMail/go-srp repository.
//! The test uses a randomly-seeded RNG (seed=42) so the client ephemeral `a`
//! is deterministic.
//!
//! | Field | Value |
//! |-------|-------|
//! | Username | `jakubqa` |
//! | Password | `abc123` |
//! | Salt (base64) | `yKlc5/CvObfoiw==` |
//! | Version | 4 |
//! | Expected M1 | see `EXPECTED_M1` below |
//! | Expected M2 | see `EXPECTED_M2` below |
//!
//! **Note:** The modulus N used in those tests is fetched live from Proton's API
//! and is NOT hardcoded in the go-srp source.  To reproduce the exact M1/M2
//! values below you would need the specific modulus that was returned to that
//! test run.  These constants are kept here for reference and will be enabled
//! once the modulus is obtained.
//!
//! ## Running live tests
//!
//! Tests marked `#[ignore]` require a real Proton account.  Run with:
//!
//! ```bash
//! PROTON_USER=you@proton.me PROTON_PASS=yourpassword \
//!     cargo test --test auth_integration -- --ignored
//! ```

use base64::{engine::general_purpose::STANDARD, Engine};
use proton_core::auth::{password, srp};

// ── go-srp reference values ────────────────────────────────────────────────

const GOSTRP_USERNAME: &str = "jakubqa";
const GOSTRP_PASSWORD: &str = "abc123";
const GOSTRP_SALT_B64: &str = "yKlc5/CvObfoiw==";

/// Expected server ephemeral B from the go-srp TestSRPauth run.
const GOSTRP_SERVER_EPHEMERAL_B64: &str =
    "l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UD\
     tayoX4aOTJihoRvifas8Hr3icd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+vZWh24G\
     2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1d9ZdmuR0/VCjUOdJbYjgtIH7BQo\
     Zs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWLXz\
     gKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA==";

// M1 and M2 from go-srp TestSRPauth — only reproducible with the exact modulus
// used in that test run (fetched live from API, not hardcoded).
// Uncomment and fill in once the modulus is known.
// const GOSTRP_EXPECTED_M1: &str = "Qb+1+jEqHRqpJ3nEJX2FEj0kXg...";
// const GOSTRP_EXPECTED_M2: &str = "SLCSIClioSAtozauZZzcJuVPyY+M...";

// ── expand_hash cross-check ────────────────────────────────────────────────

/// Verify that `expand_hash` matches the 4× SHA-512 definition from go-srp.
///
/// go-srp `expandHash(data)` = SHA512(data‖0) ‖ SHA512(data‖1) ‖ SHA512(data‖2) ‖ SHA512(data‖3)
#[test]
fn expand_hash_matches_go_srp_definition() {
    use sha2::{Digest, Sha512};

    let data = b"cross-check";
    let got = srp::expand_hash(data);

    for i in 0u8..4 {
        let mut input = data.to_vec();
        input.push(i);
        let expected: [u8; 64] = Sha512::digest(&input).into();
        let slice = &got[i as usize * 64..(i as usize + 1) * 64];
        assert_eq!(slice, &expected[..], "chunk {i} mismatch");
    }
}

// ── bcrypt output shape ────────────────────────────────────────────────────

/// Verify that the bcrypt output for the go-srp test credentials has the
/// expected shape (60 bytes, correct prefix).
#[test]
fn hash_password_shape_for_gostrp_credentials() {
    let out = password::hash_password(GOSTRP_PASSWORD, GOSTRP_SALT_B64)
        .expect("hash_password should succeed");
    assert_eq!(out.len(), 60);
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.starts_with("$2b$10$") || s.starts_with("$2y$10$"));
}

// ── SRP structure tests ────────────────────────────────────────────────────

/// Verify that `generate_srp_proof` produces 256-byte M1 and M2 for the
/// go-srp test credentials, given a synthetic modulus.
///
/// We cannot verify the exact M1/M2 values without the original modulus,
/// but we can check the output structure.
#[test]
fn srp_proof_structure_with_gostrp_inputs() {
    // Use a 256-byte synthetic modulus (a known 2048-bit safe prime would be ideal,
    // but any 256 non-zero bytes serve to verify output shapes).
    let modulus_bytes = vec![0xffu8; 256];

    let bcrypt_out = password::hash_password(GOSTRP_PASSWORD, GOSTRP_SALT_B64).unwrap();

    // Decode B — strip newlines that may be in the const string.
    let b64_clean: String = GOSTRP_SERVER_EPHEMERAL_B64
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let b_bytes = STANDARD.decode(&b64_clean).unwrap();
    // Re-encode cleanly for the function.
    let b_b64 = STANDARD.encode(&b_bytes);

    let proof = srp::generate_srp_proof(&bcrypt_out, &modulus_bytes, &b_b64)
        .expect("generate_srp_proof should succeed");

    let m1 = STANDARD.decode(&proof.client_proof).unwrap();
    let m2 = STANDARD.decode(&proof.expected_server_proof).unwrap();
    assert_eq!(m1.len(), 256, "M1 must be 256 bytes");
    assert_eq!(m2.len(), 256, "M2 must be 256 bytes");
    assert_ne!(m1, m2, "M1 and M2 must differ");
}

// ── Live login (requires real credentials) ─────────────────────────────────

/// End-to-end login against the real Proton API.
///
/// Requires env vars: `PROTON_USER`, `PROTON_PASS`.
/// Run with: `cargo test -- --ignored`
#[tokio::test]
#[ignore = "requires real Proton credentials and network access"]
async fn live_login_succeeds() {
    let username = std::env::var("PROTON_USER").expect("PROTON_USER not set");
    let password = std::env::var("PROTON_PASS").expect("PROTON_PASS not set");

    let result = proton_core::auth::login(&username, &password).await;
    match result {
        Ok(proton_core::auth::LoginResult::Success(session)) => {
            let _ = GOSTRP_USERNAME; // suppress dead-code warning in live test
            assert_eq!(session.username, username);
            assert!(!session.access_token.is_empty());
            assert!(!session.refresh_token.is_empty());
            println!("Logged in successfully as {}", session.username);
        }
        Ok(proton_core::auth::LoginResult::TwoFactorRequired(_)) => {
            println!("2FA required — test account must not have 2FA enabled");
        }
        Err(e) => panic!("Login failed: {e}"),
    }
}
