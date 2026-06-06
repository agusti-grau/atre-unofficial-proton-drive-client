use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("API error {code}: {message}")]
    Api { code: i32, message: String },

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("SRP error: {0}")]
    Srp(String),

    #[error("Keyring error: {0}")]
    Keyring(String),

    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("UTF-8 decode error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Database error: {0}")]
    Db(String),
}
