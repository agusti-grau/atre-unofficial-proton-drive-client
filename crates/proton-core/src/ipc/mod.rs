//! IPC protocol between proton-drive / GUI and protond daemon.
//!
//! Wire format: JSON Lines (one JSON object per line, `\n`-terminated)
//! over a Unix domain socket at `$XDG_RUNTIME_DIR/protond.sock`.
//!
//! # Protocol
//!
//! ```text
//! → {"id":1, "method":"ping", "params":{}}
//! ← {"id":1, "result":"pong"}
//!
//! → {"id":2, "method":"auth.status", "params":{}}
//! ← {"id":2, "result":{"logged_in":true, "username":"user@pm.me"}}
//!
//! → {"id":3, "method":"drive.ls", "params":{"recursive":false, "share_id":"...", "folder_link_id":"..."}}
//! ← {"id":3, "result":{"items":[{"link_id":"...", "parent_link_id":"...", "type":"folder", "name":"...", ...}]}}
//!
//! → {"id":4, "method":"drive.ls_decrypted", "params":{"password":"...", "recursive":false}}
//! ← {"id":4, "result":{"items":[{"link_id":"...", "name":"plaintext_name", ...}]}}
//!
//! → {"id":5, "method":"drive.sync", "params":{"password":"..."}}
//! ← {"id":5, "result":{"dirs_created":0,"downloads_attempted":0,"downloads_succeeded":0,"uploads_attempted":0,"uploads_succeeded":0,"errors":[]}}
//!
//! → {"id":6, "method":"drive.status", "params":{}}
//! ← {"id":6, "result":{"logged_in":true,"username":"user@pm.me","db":{"total_nodes":42,"synced":40,"pending":2},"last_sync":"2024-01-15T10:30:00Z"}}
//! ```

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::{Error, Result};

// ── Protocol types ───────────────────────────────────────────────────────────

pub type RequestId = u64;

/// Request from CLI/GUI to protond.
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcRequest {
    pub id: RequestId,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// Response from protond to CLI/GUI.
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcResponse {
    pub id: RequestId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
}

/// Error payload in an IPC response.
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcError {
    pub code: i32,
    pub message: String,
}

impl IpcResponse {
    pub fn ok(id: RequestId, result: serde_json::Value) -> Self {
        Self { id, result: Some(result), error: None }
    }

    pub fn err(id: RequestId, code: i32, message: impl Into<String>) -> Self {
        Self {
            id,
            result: None,
            error: Some(IpcError { code, message: message.into() }),
        }
    }
}

/// Return the path for the protond Unix domain socket.
pub fn socket_path() -> String {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        format!("{}/protond.sock", runtime_dir)
    } else {
        "/tmp/protond.sock".to_string()
    }
}

// ── IPC client ───────────────────────────────────────────────────────────────

/// Client for communicating with the protond daemon over its Unix socket.
pub struct IpcClient {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
    next_id: RequestId,
}

impl IpcClient {
    /// Connect to the running protond daemon at the default socket path.
    pub async fn connect() -> Result<Self> {
        Self::connect_to(&socket_path()).await
    }

    /// Connect to protond at a specific socket path.
    pub async fn connect_to(path: &str) -> Result<Self> {
        let stream = UnixStream::connect(path)
            .await
            .map_err(|e| Error::Io(format!("connect to protond at {path}: {e}")))?;
        let (reader, writer) = stream.into_split();
        Ok(Self {
            reader: BufReader::new(reader),
            writer,
            next_id: 1,
        })
    }

    /// Send a request and await the response.
    pub async fn request(&mut self, method: &str, params: serde_json::Value) -> Result<IpcResponse> {
        let id = self.next_id;
        self.next_id += 1;

        let req = IpcRequest {
            id,
            method: method.to_string(),
            params,
        };

        let mut buf = serde_json::to_vec(&req)
            .map_err(|e| Error::Io(format!("serialize request: {e}")))?;
        buf.push(b'\n');

        self.writer
            .write_all(&buf)
            .await
            .map_err(|e| Error::Io(format!("write request: {e}")))?;

        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .await
            .map_err(|e| Error::Io(format!("read response: {e}")))?;

        if line.is_empty() {
            return Err(Error::Io("protond closed connection".into()));
        }

        serde_json::from_str(&line)
            .map_err(|e| Error::Io(format!("parse response: {e}")))
    }
}
