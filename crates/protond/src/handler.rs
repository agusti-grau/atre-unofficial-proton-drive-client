use std::path::PathBuf;
use std::sync::Arc;

use proton_core::api::ApiClient;
use proton_core::db::StateDb;
use proton_core::drive::DriveClient;
use proton_core::ipc::{IpcRequest, IpcResponse};
use proton_core::sync::SyncEngine;

pub struct IpcHandler {
    api: Option<ApiClient>,
    db: Arc<StateDb>,
    base_path: PathBuf,
}

impl IpcHandler {
    /// Create a new handler, loading any stored session from the keyring.
    pub async fn new(db: Arc<StateDb>, base_path: PathBuf) -> Self {
        let api = proton_core::keyring::load_session()
            .await
            .ok()
            .flatten()
            .map(|session| ApiClient::new().unwrap().with_session(session));
        Self { api, db, base_path }
    }

    /// Dispatch an IPC request to the appropriate handler.
    pub async fn handle(&self, req: IpcRequest) -> IpcResponse {
        match req.method.as_str() {
            "ping" => IpcResponse::ok(req.id, serde_json::json!("pong")),
            "auth.status" => self.handle_auth_status(req),
            "drive.ls" => self.handle_drive_ls(req).await,
            "drive.ls_decrypted" => self.handle_drive_ls_decrypted(req).await,
            "drive.status" => self.handle_drive_status(req),
            "drive.sync" => self.handle_drive_sync(req).await,
            _ => IpcResponse::err(req.id, -1, format!("unknown method: {}", req.method)),
        }
    }

    fn handle_auth_status(&self, req: IpcRequest) -> IpcResponse {
        match &self.api {
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

    fn handle_drive_status(&self, req: IpcRequest) -> IpcResponse {
        let (logged_in, username) = match &self.api {
            Some(client) => {
                let session = client.session();
                (
                    true,
                    session.as_ref().map(|s| &s.username).cloned(),
                )
            }
            None => (false, None),
        };

        let total = self.db.count_nodes("").unwrap_or(0);
        let synced = self.db.count_nodes("synced").unwrap_or(0);
        let pending = self.db.count_nodes("pending").unwrap_or(0);
        let last_sync = self.db.get_meta("last_sync").unwrap_or(None);

        IpcResponse::ok(req.id, serde_json::json!({
            "logged_in": logged_in,
            "username": username,
            "db": {
                "total_nodes": total,
                "synced": synced,
                "pending": pending,
            },
            "last_sync": last_sync,
        }))
    }

    async fn handle_drive_ls(&self, req: IpcRequest) -> IpcResponse {
        let Ok(drive) = self.drive_client() else {
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

        let Ok(drive) = self.drive_client() else {
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
            match drive.list_root_decrypted(password).await {
                Ok(pairs) => pairs
                    .iter()
                    .map(|(node, plain_name)| {
                        let mut v = serde_json::to_value(node).unwrap_or_default();
                        if let Some(obj) = v.as_object_mut() {
                            obj.insert("name".into(), serde_json::Value::String(plain_name.clone()));
                        }
                        v
                    })
                    .collect(),
                Err(e) => return IpcResponse::err(req.id, -1, format!("list: {e}")),
            }
        };

        IpcResponse::ok(req.id, serde_json::json!({ "items": items }))
    }

    async fn handle_drive_sync(&self, req: IpcRequest) -> IpcResponse {
        let password = match req.params.get("password").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return IpcResponse::err(req.id, -1, "Missing required param: 'password'"),
        };

        let session = match self.api.as_ref().and_then(|a| a.session()) {
            Some(s) => s,
            None => return IpcResponse::err(req.id, -1, "Not logged in"),
        };

        let api = match ApiClient::new() {
            Ok(c) => c.with_session(session),
            Err(e) => return IpcResponse::err(req.id, -1, format!("create client: {e}")),
        };

        let engine = SyncEngine::new(api, Arc::clone(&self.db), self.base_path.clone());
        match engine.sync(password).await {
            Ok(report) => {
                let value = serde_json::to_value(&report).unwrap_or_default();
                IpcResponse::ok(req.id, value)
            }
            Err(e) => IpcResponse::err(req.id, -1, format!("sync failed: {e}")),
        }
    }

    /// Build a [`DriveClient`] from the stored session.
    fn drive_client(&self) -> Result<DriveClient, ()> {
        let session = self.api.as_ref().and_then(|a| a.session()).ok_or(())?;
        ApiClient::new().ok().map(|c| DriveClient::new(c.with_session(session))).ok_or(())
    }

    /// Resolve `share_id` and `folder_link_id` from request params, falling
    /// back to the main share root.
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

        // Fall back to the main share root.
        drive.find_main_share().await.ok().map(|(s, f)| (Some(s), Some(f))).unwrap_or_default()
    }
}
