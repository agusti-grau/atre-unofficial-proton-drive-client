use keyring::Entry;
use tokio::sync::oneshot;

use crate::api::Session;
use crate::{Error, Result};

const SERVICE: &str = "proton-drive";
const ACCOUNT: &str = "session";

/// Persist a session to the system keyring as JSON.
pub async fn save_session(session: &Session) -> Result<()> {
    let json = serde_json::to_string(session)?;
    let (tx, rx) = oneshot::channel();
    std::thread::spawn(move || {
        let result = (|| -> Result<()> {
            let entry = entry()?;
            entry.set_password(&json).map_err(keyring_err)?;
            Ok(())
        })();
        let _ = tx.send(result);
    });
    rx.await
        .map_err(|e| Error::Io(format!("keyring thread dropped: {e}")))?
}

/// Load the stored session from the system keyring, or `None` if not found.
pub async fn load_session() -> Result<Option<Session>> {
    let (tx, rx) = oneshot::channel();
    std::thread::spawn(move || {
        let result = (|| -> Result<Option<Session>> {
            match entry()?.get_password() {
                Ok(json) => {
                    let session: Session = serde_json::from_str(&json)?;
                    Ok(Some(session))
                }
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(keyring_err(e)),
            }
        })();
        let _ = tx.send(result);
    });
    rx.await
        .map_err(|e| Error::Io(format!("keyring thread dropped: {e}")))?
}

/// Remove the stored session from the system keyring.
pub async fn delete_session() -> Result<()> {
    let (tx, rx) = oneshot::channel();
    std::thread::spawn(move || {
        let result = (|| -> Result<()> {
            match entry()?.delete_credential() {
                Ok(()) => Ok(()),
                Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(keyring_err(e)),
            }
        })();
        let _ = tx.send(result);
    });
    rx.await
        .map_err(|e| Error::Io(format!("keyring thread dropped: {e}")))?
}

fn entry() -> Result<Entry> {
    Entry::new(SERVICE, ACCOUNT).map_err(keyring_err)
}

fn keyring_err(e: keyring::Error) -> Error {
    Error::Keyring(e.to_string())
}
