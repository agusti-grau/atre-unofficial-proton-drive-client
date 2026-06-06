//! High-level authentication flow for Proton Drive.
//!
//! Orchestrates: auth-info fetch → bcrypt → SRP → token exchange → 2FA → session storage.

pub mod password;
pub mod srp;

use crate::api::{ApiClient, Session};
use crate::api::types::AuthRequest;
use crate::crypto;
use crate::{Error, Result};

/// Outcome of a completed login attempt.
pub enum LoginResult {
    /// Login succeeded; session is ready.
    Success(Session),
    /// The account has 2FA enabled and a TOTP code is still required.
    /// Call [`complete_2fa`] with the returned `ApiClient`.
    TwoFactorRequired(ApiClient),
}

/// Authenticate with Proton's SRP-based login flow.
///
/// # Steps
/// 1. Fetch SRP parameters from `/auth/v4/info`.
/// 2. Hash the password with bcrypt (cost 10, server-supplied salt).
/// 3. Decode and strip the PGP wrapper from the modulus.
/// 4. Compute SRP-6a proofs (`expand_hash`-based).
/// 5. Submit proof and verify server response.
/// 6. Return a `Session` (or indicate that 2FA is still needed).
pub async fn login(username: &str, password: &str) -> Result<LoginResult> {
    let client = ApiClient::new()?;

    // ── Step 1: Fetch SRP parameters ──────────────────────────────────────
    let info = client.get_auth_info(username).await?;

    if info.version != 4 {
        return Err(Error::Auth(format!(
            "Unsupported Proton auth version {} (only v4 is supported). \
             The account may be using a legacy password scheme.",
            info.version
        )));
    }

    // ── Step 2: Hash password with bcrypt ─────────────────────────────────
    // Returns the full 60-byte bcrypt string for use as SRP x input.
    let bcrypt_output = password::hash_password(password, &info.salt)?;

    // ── Step 3: Verify PGP signature on modulus and decode ────────────────
    let modulus_bytes = crypto::verify_modulus_signature(&info.modulus)?;

    // ── Step 4: Compute SRP-6a proofs ─────────────────────────────────────
    let proof = srp::generate_srp_proof(
        &bcrypt_output,
        &modulus_bytes,
        &info.server_ephemeral,
    )?;

    // ── Step 5: Submit proof ───────────────────────────────────────────────
    let auth_req = AuthRequest {
        username: username.to_string(),
        client_ephemeral: proof.client_ephemeral,
        client_proof: proof.client_proof,
        srp_session: info.srp_session,
    };
    let auth_resp = client.authenticate(&auth_req).await?;

    // ── Step 5b: Verify server proof (mutual authentication) ───────────────
    if auth_resp.server_proof != proof.expected_server_proof {
        return Err(Error::Auth(
            "Server proof mismatch — possible MITM or API incompatibility".into(),
        ));
    }

    // ── Step 6: Build session ──────────────────────────────────────────────
    let session = Session {
        uid: auth_resp.uid,
        access_token: auth_resp.access_token,
        refresh_token: auth_resp.refresh_token,
        username: username.to_string(),
    };

    // Bit 0 of two_factor.enabled = TOTP required.
    if auth_resp.two_factor.enabled & 1 != 0 {
        let client_with_session = ApiClient::new()?.with_session(session);
        return Ok(LoginResult::TwoFactorRequired(client_with_session));
    }

    Ok(LoginResult::Success(session))
}

/// Complete a 2FA challenge with a TOTP code.
///
/// Must be called when [`login`] returns [`LoginResult::TwoFactorRequired`].
pub async fn complete_2fa(client: &ApiClient, totp_code: &str) -> Result<Session> {
    client.submit_2fa(totp_code).await?;
    client
        .session()
        .ok_or_else(|| Error::Auth("No session on client after 2FA".into()))
}

/// Refresh an expired access token using the stored refresh token.
pub async fn refresh_session(session: &Session) -> Result<Session> {
    let client = ApiClient::new()?.with_session(session.clone());
    let resp = client.refresh_token().await?;
    Ok(Session {
        uid: resp.uid,
        access_token: resp.access_token,
        refresh_token: resp.refresh_token,
        username: session.username.clone(),
    })
}

/// Revoke the session on the server and remove it from the keyring.
pub async fn logout(session: &Session) -> Result<()> {
    let client = ApiClient::new()?.with_session(session.clone());
    client.logout().await?;
    crate::keyring::delete_session().await?;
    Ok(())
}
