//! Integration tests for the protond daemon.

use std::process::{Child, Command};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use proton_core::ipc::{IpcClient, IpcResponse};

const START_TIMEOUT: Duration = Duration::from_secs(5);

static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

struct Daemon {
    child: Child,
    socket: String,
}

impl Daemon {
    /// Start protond on a unique temp directory.
    fn start() -> Self {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmpdir = std::env::temp_dir().join(format!("protond-test-{n}"));
        let _ = std::fs::remove_dir_all(&tmpdir);
        std::fs::create_dir_all(&tmpdir).expect("create temp dir");
        let socket_path = tmpdir.join("protond.sock");
        let socket = socket_path.to_str().unwrap().to_string();

        let bin = std::env!("CARGO_BIN_EXE_protond");

        let child = Command::new(bin)
            .env("XDG_RUNTIME_DIR", tmpdir.to_str().unwrap())
            .env("XDG_DATA_HOME", tmpdir.to_str().unwrap())
            .env("PROTON_DRIVE_DIR", tmpdir.to_str().unwrap())
            .spawn()
            .expect("spawn protond");

        let deadline = std::time::Instant::now() + START_TIMEOUT;
        loop {
            if socket_path.exists() {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("timed out waiting for protond on {socket}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        Self { child, socket }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn unwrap_ok(resp: IpcResponse) -> serde_json::Value {
    assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
    resp.result.expect("expected result")
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn ping_pong() {
    let d = Daemon::start();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut client = IpcClient::connect_to(&d.socket).await.unwrap();
        let resp = client.request("ping", serde_json::json!({})).await.unwrap();
        assert_eq!(unwrap_ok(resp), serde_json::json!("pong"));
    });
    // Daemon killed on drop.
}

#[test]
fn auth_status_not_logged_in() {
    let d = Daemon::start();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut client = IpcClient::connect_to(&d.socket).await.unwrap();
        let resp = client
            .request("auth.status", serde_json::json!({}))
            .await
            .unwrap();
        let result = unwrap_ok(resp);
        assert_eq!(result["logged_in"], serde_json::json!(false));
        assert_eq!(result["username"], serde_json::json!(null));
    });
}

#[test]
fn drive_ls_not_logged_in() {
    let d = Daemon::start();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut client = IpcClient::connect_to(&d.socket).await.unwrap();
        let resp = client
            .request("drive.ls", serde_json::json!({}))
            .await
            .unwrap();
        let err = resp.error.expect("expected error");
        assert_eq!(err.message, "Not logged in");
    });
}

#[test]
fn drive_ls_decrypted_not_logged_in() {
    let d = Daemon::start();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut client = IpcClient::connect_to(&d.socket).await.unwrap();
        let resp = client
            .request(
                "drive.ls_decrypted",
                serde_json::json!({"password": "test"}),
            )
            .await
            .unwrap();
        let err = resp.error.expect("expected error");
        assert_eq!(err.message, "Not logged in");
    });
}

#[test]
fn drive_ls_decrypted_missing_password() {
    let d = Daemon::start();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut client = IpcClient::connect_to(&d.socket).await.unwrap();
        let resp = client
            .request("drive.ls_decrypted", serde_json::json!({}))
            .await
            .unwrap();
        let err = resp.error.expect("expected error");
        assert_eq!(err.message, "Missing required param: 'password'");
    });
}

#[test]
fn unknown_method_returns_error() {
    let d = Daemon::start();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut client = IpcClient::connect_to(&d.socket).await.unwrap();
        let resp = client
            .request("nonexistent", serde_json::json!({}))
            .await
            .unwrap();
        let err = resp.error.expect("expected error");
        assert!(err.message.contains("unknown method"));
    });
}

#[test]
fn multiple_requests_same_connection() {
    let d = Daemon::start();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut client = IpcClient::connect_to(&d.socket).await.unwrap();
        let r1 = client.request("ping", serde_json::json!({})).await.unwrap();
        assert_eq!(unwrap_ok(r1), serde_json::json!("pong"));
        let r2 = client.request("ping", serde_json::json!({})).await.unwrap();
        assert_eq!(unwrap_ok(r2), serde_json::json!("pong"));
    });
}

#[test]
fn drive_rename_not_logged_in() {
    let d = Daemon::start();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut client = IpcClient::connect_to(&d.socket).await.unwrap();
        let resp = client
            .request(
                "drive.rename",
                serde_json::json!({
                    "share_id": "test",
                    "link_id": "test",
                    "new_name": "newname",
                    "password": "test",
                }),
            )
            .await
            .unwrap();
        let err = resp.error.expect("expected error");
        assert_eq!(err.message, "Not logged in");
    });
}

#[test]
fn drive_rename_missing_params() {
    let d = Daemon::start();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut client = IpcClient::connect_to(&d.socket).await.unwrap();
        let resp = client
            .request("drive.rename", serde_json::json!({}))
            .await
            .unwrap();
        let err = resp.error.expect("expected error");
        assert!(err.message.contains("Missing required param"));
    });
}

#[test]
fn drive_delete_not_logged_in() {
    let d = Daemon::start();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut client = IpcClient::connect_to(&d.socket).await.unwrap();
        let resp = client
            .request(
                "drive.delete",
                serde_json::json!({
                    "share_id": "test",
                    "link_id": "test",
                }),
            )
            .await
            .unwrap();
        let err = resp.error.expect("expected error");
        assert_eq!(err.message, "Not logged in");
    });
}

#[test]
fn drive_delete_missing_params() {
    let d = Daemon::start();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut client = IpcClient::connect_to(&d.socket).await.unwrap();
        let resp = client
            .request("drive.delete", serde_json::json!({}))
            .await
            .unwrap();
        let err = resp.error.expect("expected error");
        assert!(err.message.contains("Missing required param"));
    });
}

fn concurrent_connections() {
    let d = Daemon::start();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut c1 = IpcClient::connect_to(&d.socket).await.unwrap();
        let mut c2 = IpcClient::connect_to(&d.socket).await.unwrap();

        let r1 = c1.request("ping", serde_json::json!({})).await.unwrap();
        assert_eq!(unwrap_ok(r1), serde_json::json!("pong"));

        let r2 = c2.request("ping", serde_json::json!({})).await.unwrap();
        assert_eq!(unwrap_ok(r2), serde_json::json!("pong"));
    });
}

#[test]
fn drive_pause_resume_persists() {
    let d = Daemon::start();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut client = IpcClient::connect_to(&d.socket).await.unwrap();

        // Initially not paused.
        let status = unwrap_ok(
            client
                .request("drive.status", serde_json::json!({}))
                .await
                .unwrap(),
        );
        assert_eq!(status["paused"], serde_json::json!(false));

        // Pause.
        let r = client
            .request("drive.pause", serde_json::json!({}))
            .await
            .unwrap();
        let result = unwrap_ok(r);
        assert_eq!(result["status"], serde_json::json!("paused"));

        let status = unwrap_ok(
            client
                .request("drive.status", serde_json::json!({}))
                .await
                .unwrap(),
        );
        assert_eq!(status["paused"], serde_json::json!(true));
        assert_eq!(status["transfers_allowed"], serde_json::json!(false));

        // Resume.
        let r = client
            .request("drive.resume", serde_json::json!({}))
            .await
            .unwrap();
        let result = unwrap_ok(r);
        assert_eq!(result["status"], serde_json::json!("resumed"));

        let status = unwrap_ok(
            client
                .request("drive.status", serde_json::json!({}))
                .await
                .unwrap(),
        );
        assert_eq!(status["paused"], serde_json::json!(false));
        assert_eq!(status["transfers_allowed"], serde_json::json!(true));
    });
}

#[test]
fn transfer_config_get_set() {
    let d = Daemon::start();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut client = IpcClient::connect_to(&d.socket).await.unwrap();

        // Default: unrestricted.
        let r = client
            .request("transfer.config", serde_json::json!({}))
            .await
            .unwrap();
        let result = unwrap_ok(r);
        assert_eq!(result["transfers_allowed"], serde_json::json!(true));
        let cfg = result["config"].as_object().expect("config object");
        assert!(cfg["windows"].as_array().unwrap().is_empty());

        // Set a restrictive window far in the past/future so it is never active.
        let r = client
            .request(
                "transfer.config",
                serde_json::json!({
                    "windows": [{
                        "days": ["Mon"],
                        "start": "02:00",
                        "end": "03:00"
                    }]
                }),
            )
            .await
            .unwrap();
        let result = unwrap_ok(r);
        assert_eq!(result["config"]["windows"].as_array().unwrap().len(), 1);
    });
}
