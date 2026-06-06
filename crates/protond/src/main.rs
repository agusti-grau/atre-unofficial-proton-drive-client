//! `protond` — Proton Drive sync daemon.
//!
//! Listens on a Unix domain socket at `$XDG_RUNTIME_DIR/protond.sock`
//! and accepts JSON Lines IPC requests from the CLI and future GUI.

mod handler;

use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use proton_core::db::StateDb;
use proton_core::ipc::{self, IpcRequest, IpcResponse};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let socket_path = ipc::socket_path();

    // Remove stale socket file from a previous run.
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)?;
    eprintln!("protond listening on {socket_path}");

    let db = Arc::new(StateDb::open(&StateDb::default_dir())?);

    let base_path = data_dir();

    let handler = Arc::new(handler::IpcHandler::new(db, base_path).await);

    loop {
        let (stream, _addr) = listener.accept().await?;
        let handler = Arc::clone(&handler);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &handler).await {
                eprintln!("connection error: {e}");
            }
        });
    }
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
            // EOF — client disconnected.
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
