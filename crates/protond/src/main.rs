//! `protond` — Proton Drive sync daemon.
//!
//! Listens on a Unix domain socket at `$XDG_RUNTIME_DIR/protond.sock`
//! for IPC requests, watches `~/Proton Drive/` via inotify, and runs
//! periodic background sync cycles.  Graceful shutdown on SIGTERM/SIGINT.

mod handler;
mod watcher;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::signal;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use proton_core::db::StateDb;
use proton_core::ipc::{self, IpcRequest, IpcResponse};

/// Interval for periodic timer-based sync.
const SYNC_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes

/// Interval for token refresh.
const TOKEN_REFRESH_INTERVAL: Duration = Duration::from_secs(600); // 10 minutes

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env_lossy(),
        )
        .with_target(true)
        .init();

    let socket_path = ipc::socket_path();

    // Remove stale socket file from a previous run.
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)?;
    tracing::info!("protond listening on {socket_path}");

    let db = Arc::new(StateDb::open(&StateDb::default_dir())?);
    let base_path = data_dir();

    // Ensure the base directory exists.
    std::fs::create_dir_all(&base_path).ok();

    // ── Channels for triggering sync ───────────────────────────────────────
    let (sync_tx, mut sync_rx) = mpsc::channel::<()>(64);
    let cancel = CancellationToken::new();

    // ── Start filesystem watcher ───────────────────────────────────────────
    if let Err(e) = watcher::spawn(base_path.clone(), sync_tx.clone()) {
        tracing::warn!("failed to start file watcher: {e}");
    }

    // ── Start background sync loop ─────────────────────────────────────────
    let handler = Arc::new(handler::IpcHandler::new(db.clone(), base_path.clone()).await);
    let bg_handler = Arc::clone(&handler);
    let bg_cancel = cancel.clone();

    tokio::spawn(async move {
        background_loop(bg_handler, &mut sync_rx, bg_cancel).await;
    });

    // ── Token refresh loop ─────────────────────────────────────────────────
    let refresh_handler = Arc::clone(&handler);
    let refresh_cancel = cancel.clone();
    tokio::spawn(async move {
        token_refresh_loop(refresh_handler, refresh_cancel).await;
    });

    // ── Accept IPC connections ────────────────────────────────────────────
    let accept_cancel = cancel.clone();
    let accept_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = accept_cancel.cancelled() => break,
                result = listener.accept() => {
                    let (stream, _addr) = match result {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!("accept error: {e}");
                            continue;
                        }
                    };
                    let h = Arc::clone(&handler);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, &h).await {
                            tracing::error!("connection error: {e}");
                        }
                    });
                }
            }
        }
    });

    // ── Wait for shutdown signal ───────────────────────────────────────────
    signal::ctrl_c().await.ok();
    tracing::info!("protond shutting down...");
    cancel.cancel();
    accept_handle.await.ok();

    // Clean up the socket.
    let _ = std::fs::remove_file(&socket_path);
    tracing::info!("protond exited");
    Ok(())
}

/// Resolve the local sync directory (`~/Proton Drive/`).
fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PROTON_DRIVE_DIR") {
        return PathBuf::from(dir);
    }
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join("Proton Drive"))
        .unwrap_or_else(|_| PathBuf::from("/tmp/Proton Drive"))
}

/// Background loop that triggers sync cycles on timer or external events.
async fn background_loop(
    handler: Arc<handler::IpcHandler>,
    sync_rx: &mut mpsc::Receiver<()>,
    cancel: CancellationToken,
) {
    let mut timer = tokio::time::interval(SYNC_INTERVAL);
    timer.tick().await; // skip immediate first tick

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = timer.tick() => {
                // Periodic timer sync.
                handler.trigger_sync().await;
            }
            _ = sync_rx.recv() => {
                // Filesystem change detected — run sync.
                handler.trigger_sync().await;
            }
        }
    }
}

/// Background loop that periodically refreshes the auth token.
async fn token_refresh_loop(handler: Arc<handler::IpcHandler>, cancel: CancellationToken) {
    let mut timer = tokio::time::interval(TOKEN_REFRESH_INTERVAL);
    timer.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = timer.tick() => {
                handler.refresh_token().await;
            }
        }
    }
}

/// Handle a single client connection: read JSON Lines requests, write responses.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    handler: &handler::IpcHandler,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(());
        }

        let req: IpcRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(e) => {
                let resp = IpcResponse::err(0, -1, format!("parse error: {e}"));
                write_response(&mut writer, &resp).await?;
                continue;
            }
        };

        let resp = handler.handle(req).await;
        write_response(&mut writer, &resp).await?;
    }
}

/// Serialize a response and write it as a JSON Line.
async fn write_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    resp: &IpcResponse,
) -> anyhow::Result<()> {
    let mut buf = serde_json::to_vec(resp)?;
    buf.push(b'\n');
    writer.write_all(&buf).await?;
    Ok(())
}
