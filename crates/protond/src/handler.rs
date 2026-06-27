use std::path::PathBuf;
use std::sync::Arc;

use proton_core::api::ApiClient;
use tracing; // ensure tracing is imported
use proton_core::auth::{self, LoginResult};
use proton_core::db::StateDb;
use proton_core::api::drive_types::{CreateFolderReq, RenameLinkReq};
use proton_core::crypto::{compute_name_hash, generate_hash_key, generate_node_keypair, pgp_decrypt, pgp_encrypt, pgp_sign};
use proton_core::drive::keyring::derive_key_password;
use proton_core::drive::DriveClient;
use proton_core::ipc::{IpcRequest, IpcResponse};
use proton_core::keyring;
use proton_core::sync::{SyncEngine, SyncReport};
use proton_core::transfer::TransferConfig;
use tokio::sync::Mutex;

/// Token bucket rate limiter — simple in-memory.
struct TokenBucket {
    capacity: u32,
    tokens: f64,
    refill_per_sec: f64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_per_sec,
            last_refill: std::time::Instant::now(),
        }
    }

    fn acquire(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity as f64);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct IpcHandler {
    api: Mutex<Option<ApiClient>>,
    pending_login: Mutex<Option<ApiClient>>,
    password_cache: Mutex<Option<String>>,
    db: Arc<StateDb>,
    base_path: PathBuf,
    rate_limiter: Mutex<TokenBucket>,
    sync_state: Mutex<SyncState>,
    last_report: Mutex<Option<SyncReport>>,
}

#[derive(Debug, Clone)]
enum SyncState {
    Idle,
    Syncing,
}

impl IpcHandler {
    pub async fn new(db: Arc<StateDb>, base_path: PathBuf) -> Self {
        let api = match keyring::load_session().await {
            Ok(Some(session)) => {
                match ApiClient::new() {
                    Ok(client) => Some(client.with_session(session)),
                    Err(e) => {
                        tracing::warn!("failed to create API client from saved session: {e}");
                        None
                    }
                }
            }
            Ok(None) => None,
            Err(e) => {
                tracing::warn!("failed to load session from keyring: {e}");
                None
            }
        };
        Self {
            api: Mutex::new(api),
            pending_login: Mutex::new(None),
            password_cache: Mutex::new(None),
            db,
            base_path,
            rate_limiter: Mutex::new(TokenBucket::new(10, 10.0)), // 10 req/s
            sync_state: Mutex::new(SyncState::Idle),
            last_report: Mutex::new(None),
        }
    }

    pub async fn handle(&self, req: IpcRequest) -> IpcResponse {
        // Rate limit check for mutating drive operations.
        match req.method.as_str() {
            "drive.sync" | "drive.ls" | "drive.ls_decrypted" | "drive.resolve" | "drive.delete" | "drive.rename" | "drive.create_folder" | "drive.upload_file" => {
                let mut limiter = self.rate_limiter.lock().await;
                if !limiter.acquire() {
                    return IpcResponse::err(
                        req.id, -1, "Rate limit exceeded. Try again shortly.",
                    );
                }
                drop(limiter);
            }
            _ => {}
        }

        match req.method.as_str() {
            "ping" => IpcResponse::ok(req.id, serde_json::json!("pong")),
            "auth.status" => self.handle_auth_status(req).await,
            "auth.login" => self.handle_auth_login(req).await,
            "auth.2fa" => self.handle_auth_2fa(req).await,
            "auth.logout" => self.handle_auth_logout(req).await,
            "drive.ls" => self.handle_drive_ls(req).await,
            "drive.ls_decrypted" => self.handle_drive_ls_decrypted(req).await,
            "drive.status" => self.handle_drive_status(req).await,
            "drive.sync" => self.handle_drive_sync(req).await,
            "drive.conflicts" => self.handle_drive_conflicts(req).await,
            "drive.resolve" => self.handle_drive_resolve(req).await,
            "drive.delete" => self.handle_drive_delete(req).await,
            "drive.rename" => self.handle_drive_rename(req).await,
            "drive.create_folder" => self.handle_drive_create_folder(req).await,
            "drive.upload_file" => self.handle_drive_upload_file(req).await,
            "transfer.config" => self.handle_transfer_config(req).await,
            _ => IpcResponse::err(req.id, -1, format!("unknown method: {}", req.method)),
        }
    }

    /// Check if transfers are allowed by the current schedule.
    pub async fn transfers_allowed(&self) -> bool {
        let config = self
            .db
            .get_meta("transfer.config")
            .ok()
            .flatten()
            .and_then(|s| serde_json::from_str::<TransferConfig>(&s).ok())
            .unwrap_or_default();
        config.is_in_window()
    }

    /// Called by the background loop. Uses cached password if available.
    pub async fn trigger_sync(&self) {
        // Respect transfer schedule.
        if !self.transfers_allowed().await {
            tracing::debug!("background sync skipped: outside transfer window");
            return;
        }

        let session = {
            let api = self.api.lock().await;
            api.as_ref().and_then(|a| a.session())
        };
        let session = match session {
            Some(s) => s,
            None => return,
        };

        let password = { self.password_cache.lock().await.clone() };
        let password = match password {
            Some(p) => p,
            None => {
                tracing::warn!("background sync skipped: no password cached");
                return;
            }
        };

        *self.sync_state.lock().await = SyncState::Syncing;
        let api = match ApiClient::new() {
            Ok(c) => c.with_session(session),
            Err(_) => {
                *self.sync_state.lock().await = SyncState::Idle;
                return;
            }
        };
        let mut engine = SyncEngine::new(api, Arc::clone(&self.db), self.base_path.clone());
        let result = engine.sync(&password).await;
        match &result {
            Ok(report) => {
                *self.last_report.lock().await = Some(report.clone());
                let now = chrono::Utc::now().to_rfc3339();
                let _ = self.db.set_meta("last_sync", &now);
                if report.has_errors() {
                    tracing::warn!("background sync completed with {} errors", report.errors.len());
                    for err in &report.errors {
                        tracing::error!("sync error: {err}");
                    }
                } else {
                    tracing::info!("background sync completed successfully");
                }
            }
            Err(e) => {
                tracing::error!("background sync failed: {e}");
            }
        }
        *self.sync_state.lock().await = SyncState::Idle;
    }

    /// Called by the background loop to refresh the auth token.
    pub async fn refresh_token(&self) {
        let session = {
            let api = self.api.lock().await;
            api.as_ref().and_then(|a| a.session())
        };
        let session = match session {
            Some(s) => s,
            None => return,
        };

        let new_session = match proton_core::auth::refresh_session(&session).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("token refresh failed: {e}");
                return;
            }
        };
        let _ = keyring::save_session(&new_session).await;
        let client = match ApiClient::new() {
            Ok(c) => c.with_session(new_session),
            Err(e) => {
                tracing::error!("token refresh: failed to create client: {e}");
                return;
            }
        };
        *self.api.lock().await = Some(client);
    }

    // ── Auth handlers ─────────────────────────────────────────────────────

    async fn handle_auth_status(&self, req: IpcRequest) -> IpcResponse {
        let api = self.api.lock().await;
        match &*api {
            Some(client) => {
                let session = client.session();
                IpcResponse::ok(req.id, serde_json::json!({
                    "logged_in": true,
                    "username": session.as_ref().map(|s| &s.username),
                }))
            }
            None => IpcResponse::ok(req.id, serde_json::json!({
                "logged_in": false,
                "username": null,
            })),
        }
    }

    async fn handle_auth_login(&self, req: IpcRequest) -> IpcResponse {
        let username = match req.params.get("username").and_then(|v| v.as_str()) {
            Some(u) => u.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'username'"),
        };
        let password = match req.params.get("password").and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'password'"),
        };

        match auth::login(&username, &password).await {
            Ok(LoginResult::Success(session)) => {
                if let Err(e) = keyring::save_session(&session).await {
                    return IpcResponse::err(req.id, -1, format!("Failed to save session: {e}"));
                }
                let client = match ApiClient::new() {
                    Ok(c) => c.with_session(session),
                    Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
                };
                *self.api.lock().await = Some(client);
                *self.pending_login.lock().await = None;
                IpcResponse::ok(req.id, serde_json::json!({
                    "status": "success",
                    "username": username,
                }))
            }
            Ok(LoginResult::TwoFactorRequired(client)) => {
                *self.pending_login.lock().await = Some(client);
                IpcResponse::ok(req.id, serde_json::json!({
                    "status": "2fa_required",
                }))
            }
            Err(e) => IpcResponse::err(req.id, -1, format!("Login failed: {e}")),
        }
    }

    async fn handle_auth_2fa(&self, req: IpcRequest) -> IpcResponse {
        let code = match req.params.get("code").and_then(|v| v.as_str()) {
            Some(c) => c.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'code'"),
        };

        let client = self.pending_login.lock().await.take();
        let client = match client {
            Some(c) => c,
            None => return IpcResponse::err(req.id, -1, "No pending 2FA login"),
        };

        match auth::complete_2fa(&client, &code).await {
            Ok(session) => {
                if let Err(e) = keyring::save_session(&session).await {
                    return IpcResponse::err(req.id, -1, format!("Failed to save session: {e}"));
                }
                let new_client = match ApiClient::new() {
                    Ok(c) => c.with_session(session),
                    Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
                };
                *self.api.lock().await = Some(new_client);
                IpcResponse::ok(req.id, serde_json::json!({
                    "status": "success",
                    "username": client.session().as_ref().map(|s| &s.username),
                }))
            }
            Err(e) => IpcResponse::err(req.id, -1, format!("2FA failed: {e}")),
        }
    }

    async fn handle_auth_logout(&self, req: IpcRequest) -> IpcResponse {
        let session = {
            let api = self.api.lock().await;
            api.as_ref().and_then(|a| a.session())
        };
        match session {
            Some(s) => {
                if let Err(e) = auth::logout(&s).await {
                    return IpcResponse::err(req.id, -1, format!("Logout failed: {e}"));
                }
                *self.api.lock().await = None;
                *self.password_cache.lock().await = None;
                IpcResponse::ok(req.id, serde_json::json!({ "status": "logged_out" }))
            }
            None => IpcResponse::ok(req.id, serde_json::json!({ "status": "not_logged_in" })),
        }
    }

    // ── Drive handlers ────────────────────────────────────────────────────

    async fn handle_drive_status(&self, req: IpcRequest) -> IpcResponse {
        let api = self.api.lock().await;
        let (logged_in, username) = match &*api {
            Some(client) => {
                let session = client.session();
                (true, session.as_ref().map(|s| &s.username).cloned())
            }
            None => (false, None),
        };
        drop(api);

        let total = self.db.count_nodes("").unwrap_or(0);
        let synced = self.db.count_nodes("synced").unwrap_or(0);
        let pending = self.db.count_nodes("pending").unwrap_or(0);
        let conflicts = self.db.count_nodes("conflict").unwrap_or(0);
        let last_sync = self.db.get_meta("last_sync").unwrap_or(None);

        let state_str = match &*self.sync_state.lock().await {
            SyncState::Idle => "idle",
            SyncState::Syncing => "syncing",
        };
        let report_val = self.last_report.lock().await.clone();
        IpcResponse::ok(req.id, serde_json::json!({
            "logged_in": logged_in,
            "username": username,
            "db": {
                "total_nodes": total,
                "synced": synced,
                "pending": pending,
                "conflicts": conflicts,
            },
            "last_sync": last_sync,
            "sync_state": state_str,
            "last_report": report_val,
        }))
    }

    async fn handle_drive_conflicts(&self, req: IpcRequest) -> IpcResponse {
        let nodes = self.db.list_nodes("conflict").unwrap_or_default();
        let items: Vec<serde_json::Value> = nodes
            .iter()
            .map(|n| {
                serde_json::json!({
                    "local_path": n.local_path,
                    "link_id": n.link_id,
                    "share_id": n.share_id,
                    "size": n.size,
                    "modified_time": n.modified_time,
                    "is_file": n.is_file,
                })
            })
            .collect();
        IpcResponse::ok(req.id, serde_json::json!({ "items": items }))
    }

    async fn handle_drive_resolve(&self, req: IpcRequest) -> IpcResponse {
        let local_path_str = match req.params.get("local_path").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'local_path'"),
        };
        let strategy = match req.params.get("strategy").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'strategy'"),
        };
        let password = match req.params.get("password").and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'password'"),
        };

        let local_path = PathBuf::from(local_path_str);

        // Check that the node exists and is in conflict state.
        let row = match self.db.get_node(&local_path).ok().flatten() {
            Some(r) => {
                if r.state != "conflict" {
                    return IpcResponse::err(req.id, -1, "Node is not in conflict state");
                }
                r
            }
            None => return IpcResponse::err(req.id, -1, "Node not found"),
        };

        let link_id = match &row.link_id {
            Some(id) => id.clone(),
            None => return IpcResponse::err(req.id, -1, "Node has no link_id"),
        };
        let share_id = match &row.share_id {
            Some(id) => id.clone(),
            None => return IpcResponse::err(req.id, -1, "Node has no share_id"),
        };

        let session = {
            let api = self.api.lock().await;
            api.as_ref().and_then(|a| a.session())
        };
        let session = match session {
            Some(s) => s,
            None => return IpcResponse::err(req.id, -1, "Not logged in"),
        };

        let api = match ApiClient::new() {
            Ok(c) => c.with_session(session.clone()),
            Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
        };

        match strategy {
            "local" => {
                if let Err(e) = self.db.upsert_node(&proton_core::db::NodeFields {
                    local_path: local_path.clone(),
                    link_id: Some(link_id),
                    share_id: Some(share_id),
                    name_encrypted: row.name_encrypted.clone(),
                    size: row.size,
                    modified_time: row.modified_time,
                    hash: row.hash.clone(),
                    is_file: row.is_file,
                    state: "pending".into(),
                }) {
                    return IpcResponse::err(req.id, -1, format!("db error: {e}"));
                }
                IpcResponse::ok(req.id, serde_json::json!({ "status": "local_wins" }))
            }
            "remote" => {
                let drive = DriveClient::new(api);
                let (kr, _sid, _root) = match drive.build_keyring(&password).await {
                    Ok(k) => k,
                    Err(e) => return IpcResponse::err(req.id, -1, format!("build keyring: {e}")),
                };
                let mut engine = match ApiClient::new() {
                    Ok(c) => SyncEngine::new(c.with_session(session.clone()), Arc::clone(&self.db), self.base_path.clone()),
                    Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
                };
                let all_nodes = match drive.walk_all().await {
                    Ok(n) => n,
                    Err(e) => return IpcResponse::err(req.id, -1, format!("walk: {e}")),
                };
                let node = match all_nodes.into_iter().find(|n| n.link_id == link_id) {
                    Some(n) => n,
                    None => return IpcResponse::err(req.id, -1, "Remote node not found"),
                };
                match engine.download_file(&node, &local_path, &kr).await {
                    Ok(()) => IpcResponse::ok(req.id, serde_json::json!({ "status": "remote_wins" })),
                    Err(e) => IpcResponse::err(req.id, -1, format!("download: {e}")),
                }
            }
            "rename_local" => {
                let renamed = local_path.with_extension("conflicted");
                if let Err(e) = tokio::fs::rename(&local_path, &renamed).await {
                    return IpcResponse::err(req.id, -1, format!("rename: {e}"));
                }
                if let Err(e) = self.db.upsert_node(&proton_core::db::NodeFields {
                    local_path: local_path.clone(),
                    link_id: Some(link_id),
                    share_id: Some(share_id),
                    name_encrypted: row.name_encrypted.clone(),
                    size: row.size,
                    modified_time: row.modified_time,
                    hash: None,
                    is_file: true,
                    state: "pending".into(),
                }) {
                    return IpcResponse::err(req.id, -1, format!("db error: {e}"));
                }
                if let Err(e) = self.db.upsert_node(&proton_core::db::NodeFields {
                    local_path: renamed,
                    link_id: None,
                    share_id: None,
                    name_encrypted: String::new(),
                    size: 0,
                    modified_time: 0,
                    hash: None,
                    is_file: true,
                    state: "synced".into(),
                }) {
                    return IpcResponse::err(req.id, -1, format!("db error: {e}"));
                }
                IpcResponse::ok(req.id, serde_json::json!({ "status": "renamed_local" }))
            }
            _ => IpcResponse::err(req.id, -1, format!("Unknown strategy: {strategy}")),
        }
    }

    async fn handle_drive_ls(&self, req: IpcRequest) -> IpcResponse {
        let Ok(drive) = self.drive_client().await else {
            return IpcResponse::err(req.id, -1, "Not logged in");
        };

        let recursive = req.params.get("recursive").and_then(|v| v.as_bool()).unwrap_or(false);

        let nodes = if recursive {
            match drive.walk_all().await {
                Ok(n) => n,
                Err(e) => return IpcResponse::err(req.id, -1, format!("walk: {e}")),
            }
        } else {
            let (share_id, folder_link_id) = self.resolve_folder(&req.params, &drive).await;
            let (share_id, folder_link_id) = match (share_id, folder_link_id) {
                (Some(s), Some(f)) => (s, f),
                _ => return IpcResponse::err(req.id, -1, "Could not determine folder"),
            };

            match drive.list_children(&share_id, &folder_link_id).await {
                Ok(n) => n,
                Err(e) => return IpcResponse::err(req.id, -1, format!("list: {e}")),
            }
        };

        let items: Vec<serde_json::Value> =
            nodes.iter().map(|n| serde_json::to_value(n).unwrap_or_default()).collect();
        IpcResponse::ok(req.id, serde_json::json!({ "items": items }))
    }

    async fn handle_drive_ls_decrypted(&self, req: IpcRequest) -> IpcResponse {
        let password = match req.params.get("password").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'password'"),
        };

        let Ok(drive) = self.drive_client().await else {
            return IpcResponse::err(req.id, -1, "Not logged in");
        };

        let recursive = req.params.get("recursive").and_then(|v| v.as_bool()).unwrap_or(false);

        let items: Vec<serde_json::Value> = if recursive {
            match drive.walk_all_decrypted(password).await {
                Ok((pairs, _kr)) => pairs
                    .iter()
                    .map(|(node, plain_name)| {
                        let mut v = serde_json::to_value(node).unwrap_or_default();
                        if let Some(obj) = v.as_object_mut() {
                            obj.insert("name".into(), serde_json::Value::String(plain_name.clone()));
                        }
                        v
                    })
                    .collect(),
                Err(e) => return IpcResponse::err(req.id, -1, format!("walk: {e}")),
            }
        } else {
            let (share_id, folder_link_id) = self.resolve_folder(&req.params, &drive).await;
            if share_id.is_none() || folder_link_id.is_none() {
                return IpcResponse::err(req.id, -1, "Could not determine folder");
            }
            let share_id = share_id.unwrap();
            let folder_link_id = folder_link_id.unwrap();

            let (mut kr, _sid, root_link_id) = match drive.build_keyring(password).await {
                Ok(k) => k,
                Err(e) => return IpcResponse::err(req.id, -1, format!("build keyring: {e}")),
            };

            let parent_key_id = if folder_link_id == root_link_id {
                root_link_id.clone()
            } else {
                folder_link_id.clone()
            };

            let children = match drive.list_children(&share_id, &folder_link_id).await {
                Ok(c) => c,
                Err(e) => return IpcResponse::err(req.id, -1, format!("list: {e}")),
            };

            let mut items = Vec::new();
            for node in &children {
                let name = kr
                    .decrypt_name_raw(&node.encrypted_name, &parent_key_id)
                    .unwrap_or_else(|_| node.encrypted_name.clone());
                let mut v = serde_json::to_value(node).unwrap_or_default();
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("name".into(), serde_json::Value::String(name));
                }
                items.push(v);

                if node.is_folder() && node.is_active() {
                    let _ = kr.unlock_with_parent(
                        &node.link_id,
                        &parent_key_id,
                        &node.node_key,
                        &node.node_passphrase,
                    );
                }
            }
            items
        };

        IpcResponse::ok(req.id, serde_json::json!({ "items": items }))
    }

    async fn handle_drive_sync(&self, req: IpcRequest) -> IpcResponse {
        let password = match req.params.get("password").and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'password'"),
        };

        let session = {
            let api = self.api.lock().await;
            api.as_ref().and_then(|a| a.session())
        };
        let session = match session {
            Some(s) => s,
            None => return IpcResponse::err(req.id, -1, "Not logged in"),
        };

        let api = match ApiClient::new() {
            Ok(c) => c.with_session(session),
            Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
        };

        *self.sync_state.lock().await = SyncState::Syncing;
        let mut engine = SyncEngine::new(api, Arc::clone(&self.db), self.base_path.clone());
        let result = engine.sync(&password).await;
        *self.sync_state.lock().await = SyncState::Idle;

        match result {
            Ok(report) => {
                *self.last_report.lock().await = Some(report.clone());
                *self.password_cache.lock().await = Some(password);
                let now = chrono::Utc::now().to_rfc3339();
                let _ = self.db.set_meta("last_sync", &now);
                let value = serde_json::to_value(&report).unwrap_or_default();
                IpcResponse::ok(req.id, value)
            }
            Err(e) => IpcResponse::err(req.id, -1, format!("sync failed: {e}")),
        }
    }

    async fn handle_drive_rename(&self, req: IpcRequest) -> IpcResponse {
        let share_id = match req.params.get("share_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'share_id'"),
        };
        let link_id = match req.params.get("link_id").and_then(|v| v.as_str()) {
            Some(l) => l.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'link_id'"),
        };
        let new_name = match req.params.get("new_name").and_then(|v| v.as_str()) {
            Some(n) => n.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'new_name'"),
        };
        let password = match req.params.get("password").and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'password'"),
        };

        let session = {
            let api = self.api.lock().await;
            api.as_ref().and_then(|a| a.session())
        };
        let session = match session {
            Some(s) => s,
            None => return IpcResponse::err(req.id, -1, "Not logged in"),
        };

        // Fetch signature address and link info using ApiClient directly.
        let lookup_api = match ApiClient::new() {
            Ok(c) => c.with_session(session.clone()),
            Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
        };

        let addresses = match lookup_api.get_addresses().await {
            Ok(a) => a,
            Err(e) => return IpcResponse::err(req.id, -1, format!("get addresses: {e}")),
        };
        let signature_address = addresses.first().map(|a| a.email.clone()).unwrap_or_default();

        let link = match lookup_api.get_link(&share_id, &link_id).await {
            Ok(l) => l,
            Err(e) => return IpcResponse::err(req.id, -1, format!("get link: {e}")),
        };
        drop(lookup_api);

        // Build keyring using DriveClient.
        let drive_api = match ApiClient::new() {
            Ok(c) => c.with_session(session.clone()),
            Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
        };
        let drive = DriveClient::new(drive_api);
        let (mut kr, _sid, root_link_id) = match drive.build_keyring(&password).await {
            Ok(k) => k,
            Err(e) => return IpcResponse::err(req.id, -1, format!("build keyring: {e}")),
        };

        let parent_key_id = match &link.parent_link_id {
            Some(pid) => pid.clone(),
            None => root_link_id.clone(),
        };

        // Unlock parent key if needed.
        if parent_key_id != root_link_id && parent_key_id != share_id {
            let parent_lookup = match ApiClient::new() {
                Ok(c) => c.with_session(session.clone()),
                Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
            };
            let parent = match parent_lookup.get_link(&share_id, &parent_key_id).await {
                Ok(p) => p,
                Err(e) => return IpcResponse::err(req.id, -1, format!("get parent link: {e}")),
            };
            drop(parent_lookup);
            let grandparent_id = parent.parent_link_id.clone().unwrap_or_else(|| root_link_id.clone());
            if let Err(e) = kr.unlock_with_parent(
                &parent_key_id,
                &grandparent_id,
                &parent.node_key,
                &parent.node_passphrase,
            ) {
                return IpcResponse::err(req.id, -1, format!("unlock parent: {e}"));
            }
        }

        let encrypted_name = match kr.encrypt_name_raw(&new_name, &parent_key_id) {
            Ok(n) => n,
            Err(e) => return IpcResponse::err(req.id, -1, format!("encrypt name: {e}")),
        };

        let rename_api = match ApiClient::new() {
            Ok(c) => c.with_session(session),
            Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
        };

        match rename_api
            .rename_link(
                &share_id,
                &link_id,
                &RenameLinkReq { name: encrypted_name, signature_address },
            )
            .await
        {
            Ok(()) => IpcResponse::ok(req.id, serde_json::json!({ "status": "renamed" })),
            Err(e) => IpcResponse::err(req.id, -1, format!("rename failed: {e}")),
        }
    }

    async fn handle_drive_create_folder(&self, req: IpcRequest) -> IpcResponse {
        let folder_name = match req.params.get("folder_name").and_then(|v| v.as_str()) {
            Some(n) => n.trim().to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'folder_name'"),
        };
        if folder_name.is_empty() {
            return IpcResponse::err(req.id, -1, "folder_name must not be empty");
        }
        let password = match req.params.get("password").and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'password'"),
        };

        let session = {
            let api = self.api.lock().await;
            api.as_ref().and_then(|a| a.session())
        };
        let session = match session {
            Some(s) => s,
            None => return IpcResponse::err(req.id, -1, "Not logged in"),
        };

        // Resolve share_id and parent_link_id, defaulting to main share root.
        let lookup_api = match ApiClient::new() {
            Ok(c) => c.with_session(session.clone()),
            Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
        };
        let drive_lookup = DriveClient::new(lookup_api);
        let (default_share_id, default_root_link_id) = match drive_lookup.find_main_share().await {
            Ok(ids) => ids,
            Err(e) => return IpcResponse::err(req.id, -1, format!("find main share: {e}")),
        };
        drop(drive_lookup);

        let share_id = req.params.get("share_id").and_then(|v| v.as_str()).unwrap_or(&default_share_id).to_string();
        let parent_link_id = req.params.get("parent_link_id").and_then(|v| v.as_str()).unwrap_or(&default_root_link_id).to_string();

        // Build keyring.
        let api = match ApiClient::new() {
            Ok(c) => c.with_session(session.clone()),
            Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
        };
        let drive = DriveClient::new(api);

        let (mut kr, _sid, root_link_id) = match drive.build_keyring(&password).await {
            Ok(k) => k,
            Err(e) => return IpcResponse::err(req.id, -1, format!("build keyring: {e}")),
        };

        // Get parent link to determine if it's the root or a child.
        let parent_key_id = if parent_link_id == root_link_id {
            root_link_id.clone()
        } else {
            parent_link_id.clone()
        };

        // Fetch parent link to get its crypto material.
        let parent_lookup = match ApiClient::new() {
            Ok(c) => c.with_session(session.clone()),
            Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
        };
        let parent = match parent_lookup.get_link(&share_id, &parent_link_id).await {
            Ok(p) => p,
            Err(e) => return IpcResponse::err(req.id, -1, format!("get parent link: {e}")),
        };
        drop(parent_lookup);

        // Unlock the parent key if needed.
        if parent_link_id != root_link_id {
            let grandparent_id = parent.parent_link_id.clone().unwrap_or_else(|| root_link_id.clone());
            if let Err(e) = kr.unlock_with_parent(
                &parent_key_id,
                &grandparent_id,
                &parent.node_key,
                &parent.node_passphrase,
            ) {
                return IpcResponse::err(req.id, -1, format!("unlock parent: {e}"));
            }
        }

        // Generate crypto material for the new folder.
        let (node_key, node_pass) = match generate_node_keypair() {
            Ok(p) => p,
            Err(e) => return IpcResponse::err(req.id, -1, format!("generate keypair: {e}")),
        };
        let hash_key = generate_hash_key();

        // Encrypt name with parent's key.
        let enc_name = match kr.encrypt_name_raw(&folder_name, &parent_key_id) {
            Ok(n) => n,
            Err(e) => return IpcResponse::err(req.id, -1, format!("encrypt name: {e}")),
        };

        // Encrypt passphrase with parent's node key.
        let enc_pass = match pgp_encrypt(
            hex::encode(&node_pass).as_bytes(),
            &parent.node_key,
        ) {
            Ok(p) => p,
            Err(e) => return IpcResponse::err(req.id, -1, format!("encrypt passphrase: {e}")),
        };

        // Get signature address and sign passphrase.
        let addr_api = match ApiClient::new() {
            Ok(c) => c.with_session(session.clone()),
            Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
        };
        let addresses = match addr_api.get_addresses().await {
            Ok(a) => a,
            Err(e) => return IpcResponse::err(req.id, -1, format!("get addresses: {e}")),
        };
        let signature_address = addresses.first().map(|a| a.email.clone()).unwrap_or_default();
        drop(addr_api);

        // Get address key for signing.
        let address_key_info = {
            let addr_api = match ApiClient::new() {
                Ok(c) => c.with_session(session.clone()),
                Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
            };
            let addr = match addr_api.get_addresses().await {
                Ok(a) => a.into_iter().next(),
                Err(_) => None,
            };
            addr.and_then(|a| {
                let key = a.keys.into_iter().find(|k| k.active == 1)?;
                let key_password = derive_key_password(&password, None).ok()?;
                Some((key.private_key, key_password))
            })
        };

        let (pass_sig, sig_addr) = match &address_key_info {
            Some((priv_key, key_pass)) => {
                match pgp_sign(enc_pass.as_bytes(), priv_key, key_pass) {
                    Ok(sig) => (sig, signature_address.clone()),
                    Err(_) => (String::new(), signature_address.clone()),
                }
            }
            None => (String::new(), signature_address.clone()),
        };

        // Compute name hash if parent has a hash key.
        let name_hash;
        let enc_hash_key;
        let parent_hash_key_str = parent.folder_properties.as_ref().map(|p| p.node_hash_key.as_str()).unwrap_or("");
        if parent_hash_key_str.is_empty() {
            name_hash = String::new();
            enc_hash_key = String::new();
        } else {
            let (parent_key, parent_pass) = match kr.get_key(&parent_key_id) {
                Some(k) => k,
                None => return IpcResponse::err(req.id, -1, "parent key not found"),
            };
            let parent_hash_key = match pgp_decrypt(parent_hash_key_str, parent_key, parent_pass) {
                Ok(k) => k,
                Err(e) => return IpcResponse::err(req.id, -1, format!("decrypt hash key: {e}")),
            };
            name_hash = compute_name_hash(&parent_hash_key, &folder_name);
            enc_hash_key = match pgp_encrypt(&hash_key, &node_key) {
                Ok(k) => k,
                Err(e) => return IpcResponse::err(req.id, -1, format!("encrypt hash key: {e}")),
            };
        }

        let req_body = CreateFolderReq {
            parent_link_id,
            name: enc_name,
            hash: name_hash,
            node_key,
            node_hash_key: enc_hash_key,
            node_passphrase: enc_pass,
            node_passphrase_signature: pass_sig,
            signature_address: sig_addr,
        };

        let create_api = match ApiClient::new() {
            Ok(c) => c.with_session(session),
            Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
        };

        match create_api.create_link(&share_id, &req_body).await {
            Ok(id) => IpcResponse::ok(req.id, serde_json::json!({ "status": "created", "link_id": id })),
            Err(e) => IpcResponse::err(req.id, -1, format!("create folder failed: {e}")),
        }
    }

    async fn handle_drive_upload_file(&self, req: IpcRequest) -> IpcResponse {
        let share_id = match req.params.get("share_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'share_id'"),
        };
        let parent_link_id = match req.params.get("parent_link_id").and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'parent_link_id'"),
        };
        let local_path = match req.params.get("local_path").and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'local_path'"),
        };
        let password = match req.params.get("password").and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'password'"),
        };

        let session = {
            let api = self.api.lock().await;
            api.as_ref().and_then(|a| a.session())
        };
        let session = match session {
            Some(s) => s,
            None => return IpcResponse::err(req.id, -1, "Not logged in"),
        };

        // Build keyring.
        let api = match ApiClient::new() {
            Ok(c) => c.with_session(session.clone()),
            Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
        };
        let drive = DriveClient::new(api);
        let (mut kr, _sid, root_link_id) = match drive.build_keyring(&password).await {
            Ok(k) => k,
            Err(e) => return IpcResponse::err(req.id, -1, format!("build keyring: {e}")),
        };

        // Unlock parent key if needed.
        if parent_link_id != root_link_id {
            let parent_lookup = match ApiClient::new() {
                Ok(c) => c.with_session(session.clone()),
                Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
            };
            let parent = match parent_lookup.get_link(&share_id, &parent_link_id).await {
                Ok(p) => p,
                Err(e) => return IpcResponse::err(req.id, -1, format!("get parent link: {e}")),
            };
            drop(parent_lookup);
            let grandparent_id = parent.parent_link_id.unwrap_or_else(|| root_link_id.clone());
            let parent_key_id = parent_link_id.clone();
            if let Err(e) = kr.unlock_with_parent(
                &parent_key_id,
                &grandparent_id,
                &parent.node_key,
                &parent.node_passphrase,
            ) {
                return IpcResponse::err(req.id, -1, format!("unlock parent: {e}"));
            }
        }

        let engine_api = match ApiClient::new() {
            Ok(c) => c.with_session(session),
            Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
        };
        let mut engine = SyncEngine::new(engine_api, Arc::clone(&self.db), self.base_path.clone());

        match engine.upload_file(&share_id, &parent_link_id, &std::path::Path::new(&local_path), &kr, &password).await {
            Ok(link_id) => IpcResponse::ok(req.id, serde_json::json!({ "status": "uploaded", "link_id": link_id })),
            Err(e) => IpcResponse::err(req.id, -1, format!("upload failed: {e}")),
        }
    }

    async fn handle_drive_delete(&self, req: IpcRequest) -> IpcResponse {
        let share_id = match req.params.get("share_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'share_id'"),
        };
        let link_id = match req.params.get("link_id").and_then(|v| v.as_str()) {
            Some(l) => l.to_string(),
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'link_id'"),
        };

        let api = self.api.lock().await;
        let client = match &*api {
            Some(c) => c,
            None => return IpcResponse::err(req.id, -1, "Not logged in"),
        };

        match client.delete_link(&share_id, &link_id).await {
            Ok(()) => IpcResponse::ok(req.id, serde_json::json!({ "status": "deleted" })),
            Err(e) => IpcResponse::err(req.id, -1, format!("delete failed: {e}")),
        }
    }

    async fn handle_transfer_config(&self, req: IpcRequest) -> IpcResponse {
        // Check if this is a SET or GET.
        let has_windows = req.params.get("windows").is_some();

        if has_windows {
            // SET config.
            let config: TransferConfig = match serde_json::from_value(req.params.clone()) {
                Ok(c) => c,
                Err(e) => {
                    return IpcResponse::err(req.id, -1, format!("invalid config: {e}"));
                }
            };
            let json = match serde_json::to_string(&config) {
                Ok(s) => s,
                Err(e) => {
                    return IpcResponse::err(req.id, -1, format!("serialize: {e}"));
                }
            };
            if let Err(e) = self.db.set_meta("transfer.config", &json) {
                return IpcResponse::err(req.id, -1, format!("db error: {e}"));
            }
            let allowed = config.is_in_window();
            IpcResponse::ok(
                req.id,
                serde_json::json!({
                    "config": config,
                    "transfers_allowed": allowed,
                }),
            )
        } else {
            // GET config.
            let config = self
                .db
                .get_meta("transfer.config")
                .ok()
                .flatten()
                .and_then(|s| serde_json::from_str::<TransferConfig>(&s).ok())
                .unwrap_or_default();
            let allowed = config.is_in_window();
            IpcResponse::ok(
                req.id,
                serde_json::json!({
                    "config": config,
                    "transfers_allowed": allowed,
                }),
            )
        }
    }

    async fn drive_client(&self) -> Result<DriveClient, ()> {
        let api = self.api.lock().await;
        let session = api.as_ref().and_then(|a| a.session()).ok_or(())?;
        ApiClient::new().ok().map(|c| DriveClient::new(c.with_session(session))).ok_or(())
    }

    async fn resolve_folder(
        &self,
        params: &serde_json::Value,
        drive: &DriveClient,
    ) -> (Option<String>, Option<String>) {
        let sid = params.get("share_id").and_then(|v| v.as_str().map(String::from));
        let fid = params.get("folder_link_id").and_then(|v| v.as_str().map(String::from));

        if sid.is_some() && fid.is_some() {
            return (sid, fid);
        }

        drive.find_main_share().await.ok().map(|(s, f)| (Some(s), Some(f))).unwrap_or_default()
    }
}
