use serde::{Deserialize, Serialize};

// ── Auth info ──────────────────────────────────────────────────────────────

/// Response from `POST /auth/v4/info`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthInfoResponse {
    pub code: i32,
    /// PGP-signed, base64-encoded 2048-bit prime (N) used for SRP.
    pub modulus: String,
    /// Base64-encoded server ephemeral value B.
    pub server_ephemeral: String,
    /// Auth version — we require 4.
    pub version: u32,
    /// Base64-encoded 16-byte salt (used for both bcrypt and SRP x computation).
    pub salt: String,
    /// Opaque session identifier echoed back in the auth request.
    pub srp_session: String,
}

// ── Auth request / response ────────────────────────────────────────────────

/// Body for `POST /auth/v4`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthRequest {
    pub username: String,
    /// Base64-encoded client ephemeral A (little-endian, 256 bytes).
    pub client_ephemeral: String,
    /// Base64-encoded client proof M1.
    pub client_proof: String,
    pub srp_session: String,
}

/// Response from `POST /auth/v4`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthResponse {
    pub code: i32,
    #[serde(rename = "UID")]
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub scope: String,
    /// Base64-encoded server proof M2 — must be verified before trusting the session.
    pub server_proof: String,
    #[serde(rename = "2FA")]
    pub two_factor: TwoFactorInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TwoFactorInfo {
    /// Bitmask: 0 = none, 1 = TOTP, 2 = FIDO2, 3 = both.
    pub enabled: u32,
}

// ── 2FA ───────────────────────────────────────────────────────────────────

/// Body for `POST /auth/v4/2fa`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TwoFactorRequest {
    #[serde(rename = "TwoFactorCode")]
    pub code: String,
}

// ── Token refresh ─────────────────────────────────────────────────────────

/// Body for `POST /auth/v4/refresh`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RefreshRequest {
    pub uid: String,
    pub refresh_token: String,
    pub grant_type: String,    // "refresh_token"
    pub redirect_uri: String,  // "https://proton.me"
    pub response_type: String, // "token"
}

// ── Address keys ──────────────────────────────────────────────────────────

/// A single PGP key attached to an address.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AddressKey {
    #[serde(rename = "ID")]
    pub id: String,
    /// PGP-armored encrypted private key.
    pub private_key: String,
    /// 1 = this is the primary key for the address.
    pub primary: u32,
    /// 1 = active (usable).
    pub active: u32,
    /// For migrated keys: PGP-armored token (encrypted with user key).
    pub token: Option<String>,
    /// For migrated keys: PGP-armored signature of the token.
    pub signature: Option<String>,
}

/// A Proton mail/drive address with its associated keys.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Address {
    #[serde(rename = "ID")]
    pub id: String,
    pub email: String,
    pub keys: Vec<AddressKey>,
}

// ── Key salts ─────────────────────────────────────────────────────────────

/// Per-key bcrypt salt used to derive the key password.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct KeySalt {
    #[serde(rename = "ID")]
    pub id: String,
    /// Base64-encoded salt.  `None` means use the raw password directly.
    pub key_salt: Option<String>,
}

// ── Stored session ────────────────────────────────────────────────────────

/// Credentials stored in the system keyring after a successful login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    pub username: String,
}
