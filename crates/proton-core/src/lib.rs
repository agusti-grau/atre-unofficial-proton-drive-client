pub mod api;
pub mod auth;
pub mod crypto;
pub mod db;
pub mod drive;
pub mod error;
pub mod ipc;
pub mod keyring;
pub mod local;
pub mod sync;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
