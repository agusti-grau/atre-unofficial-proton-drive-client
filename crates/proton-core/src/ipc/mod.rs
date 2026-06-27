//! IPC protocol between proton-drive / GUI and protond daemon.
//!
//! Wire format: JSON Lines (one JSON object per line, `\n`-terminated)
//! over a Unix domain socket at `$XDG_RUNTIME_DIR/protond.sock`.
//!
//! # Security
//!
//! The socket is created with mode `0o600` and the daemon validates that
//! every peer is running as the same user via `SO_PEERCRED`. JSON Lines are
//! length-limited to prevent memory exhaustion.
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
//!
//! → {"id":7, "method":"drive.delete", "params":{"share_id":"...","link_id":"..."}}
//! ← {"id":7, "result":{"status":"deleted"}}
//!
//! → {"id":8, "method":"drive.rename", "params":{"share_id":"...","link_id":"...","new_name":"NewName","password":"..."}}
//! ← {"id":8, "result":{"status":"renamed"}}
//!
//! → {"id":9, "method":"drive.create_folder", "params":{"share_id":"...","parent_link_id":"...","folder_name":"NewFolder","password":"..."}}
//! ← {"id":9, "result":{"status":"created","link_id":"..."}}
//!
//! → {"id":10, "method":"drive.upload_file", "params":{"share_id":"...","parent_link_id":"...","local_path":"/path/to/file","password":"..."}}
//! ← {"id":10, "result":{"status":"uploaded","link_id":"..."}}
//! ```

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::{Error, Result};

/// Maximum length of a single JSON Line request/response (1 MiB).
pub const MAX_LINE_LEN: usize = 1024 * 1024;

/// Default permissions for the Unix socket: owner read/write only.
pub const SOCKET_MODE: u32 = 0o600;

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
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: RequestId, code: i32, message: impl Into<String>) -> Self {
        Self {
            id,
            result: None,
            error: Some(IpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

/// Return the directory where the protond socket lives.
///
/// Prefers `$XDG_RUNTIME_DIR`; falls back to `~/.cache/proton-drive/run` so
/// the socket is never created in world-writable `/tmp`.
pub fn socket_dir() -> std::path::PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        std::path::PathBuf::from(runtime_dir)
    } else if let Ok(home) = std::env::var("HOME") {
        std::path::PathBuf::from(home)
            .join(".cache")
            .join("proton-drive")
            .join("run")
    } else {
        // Last-resort fallback for constrained environments. The caller should
        // still set permissions as restrictively as possible.
        std::path::PathBuf::from("/run/proton-drive")
    }
}

/// Return the path for the protond Unix domain socket.
pub fn socket_path() -> String {
    socket_dir()
        .join("protond.sock")
        .to_string_lossy()
        .to_string()
}

/// Set restrictive permissions on the socket file.
pub fn set_socket_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))
            .map_err(|e| Error::Io(format!("set socket permissions: {e}")))?;
    }
    Ok(())
}

/// Return the peer UID for a Unix stream using `SO_PEERCRED`.
///
/// The stream is briefly converted to a std stream to access its raw fd and
/// then restored.
#[cfg(unix)]
pub async fn peer_uid(stream: UnixStream) -> Result<(UnixStream, u32)> {
    use std::os::unix::io::AsRawFd;

    let std_stream = stream
        .into_std()
        .map_err(|e| Error::Io(format!("convert stream to std: {e}")))?;
    let fd = std_stream.as_raw_fd();

    let mut creds: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut creds as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(Error::Io("getsockopt(SO_PEERCRED) failed".into()));
    }

    let stream = UnixStream::from_std(std_stream)
        .map_err(|e| Error::Io(format!("convert stream back to tokio: {e}")))?;
    Ok((stream, creds.uid))
}

#[cfg(not(unix))]
pub async fn peer_uid(stream: UnixStream) -> Result<(UnixStream, u32)> {
    let _ = stream;
    Err(Error::Io(
        "peer credentials not supported on this platform".into(),
    ))
}

// ── IPC client ───────────────────────────────────────────────────────────────

/// Client for communicating with the protond daemon over its Unix socket.
pub struct IpcClient {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
    next_id: RequestId,
}

/// Read a single line from `reader`, rejecting lines longer than `max_len`.
pub async fn read_line_limited<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    line: &mut String,
    max_len: usize,
) -> Result<usize> {
    line.clear();
    let mut total = 0usize;
    loop {
        let start_len = line.len();
        let n = reader
            .read_line(line)
            .await
            .map_err(|e| Error::Io(format!("read line: {e}")))?;
        if n == 0 {
            return Ok(0);
        }
        total += n;
        if total > max_len {
            return Err(Error::Io(format!("line exceeds {max_len} bytes")));
        }
        if line.len() > start_len && line.ends_with('\n') {
            return Ok(total);
        }
    }
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
    pub async fn request(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<IpcResponse> {
        let id = self.next_id;
        self.next_id += 1;

        let req = IpcRequest {
            id,
            method: method.to_string(),
            params,
        };

        let mut buf =
            serde_json::to_vec(&req).map_err(|e| Error::Io(format!("serialize request: {e}")))?;
        if buf.len() > MAX_LINE_LEN {
            return Err(Error::Io(format!("request exceeds {MAX_LINE_LEN} bytes")));
        }
        buf.push(b'\n');

        self.writer
            .write_all(&buf)
            .await
            .map_err(|e| Error::Io(format!("write request: {e}")))?;

        let mut line = String::new();
        let n = read_line_limited(&mut self.reader, &mut line, MAX_LINE_LEN).await?;
        if n == 0 {
            return Err(Error::Io("protond closed connection".into()));
        }

        serde_json::from_str(&line).map_err(|e| Error::Io(format!("parse response: {e}")))
    }
}
