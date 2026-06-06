//! Filesystem watcher using inotify (via `notify` crate).
//!
//! Watches `~/Proton Drive/` recursively and emits debounced events
//! that can trigger sync cycles.

use std::path::PathBuf;
use std::time::Duration;

use notify::{RecursiveMode, Watcher};
use tokio::sync::mpsc;

/// Minimum delay between consecutive sync triggers.
const DEBOUNCE_MS: u64 = 100;

/// Start watching `base_path` and send a notification on `sync_tx`
/// whenever files change.  Events are debounced so rapid sequences
/// produce at most one trigger per `DEBOUNCE_MS` window.
pub fn spawn(
    base_path: PathBuf,
    sync_tx: mpsc::Sender<()>,
) -> Result<(), String> {
    let mut last_trigger = std::time::Instant::now();

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        match res {
            Ok(event) => {
                tracing::trace!("inotify event: {:?}", event.kind);
                let now = std::time::Instant::now();
                if now.duration_since(last_trigger) >= Duration::from_millis(DEBOUNCE_MS) {
                    last_trigger = now;
                    let _ = sync_tx.blocking_send(());
                }
            }
            Err(e) => {
                tracing::warn!("watcher error: {e}");
            }
        }
    })
    .map_err(|e| format!("create watcher: {e}"))?;

    watcher
        .watch(&base_path, RecursiveMode::Recursive)
        .map_err(|e| format!("watch {}: {e}", base_path.display()))?;

    // Keep the watcher alive for the process lifetime by leaking it.
    Box::leak(Box::new(watcher));

    Ok(())
}
