use std::sync::Mutex;

use reqwest::{Client, header, StatusCode};

use crate::{Error, Result};
use crate::api::types::*;
use crate::api::drive_types::*;

/// Proton API base URL.
const BASE_URL: &str = "https://mail.proton.me/api";

/// Value sent in the `x-pm-appversion` header.
/// Must match a version Proton's server accepts; use a known-good value.
const APP_VERSION: &str = "Other/0.1.0";

pub struct ApiClient {
    client: Client,
    session: Mutex<Option<Session>>,
}

impl ApiClient {
    /// Build a new client with default Proton headers.
    pub fn new() -> Result<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "x-pm-appversion",
            header::HeaderValue::from_static(APP_VERSION),
        );
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/vnd.protonmail.v1+json"),
        );

        let client = Client::builder()
            .default_headers(headers)
            .https_only(true)
            .build()?;

        Ok(Self { client, session: Mutex::new(None) })
    }

    /// Attach an existing session (used after login or token refresh).
    pub fn with_session(self, session: Session) -> Self {
        *self.session.lock().unwrap() = Some(session);
        self
    }

    pub fn session(&self) -> Option<Session> {
        self.session.lock().unwrap().clone()
    }

    // ── Auth endpoints ─────────────────────────────────────────────────────

    /// `POST /auth/v4/info` — fetch SRP parameters for the given username.
    pub async fn get_auth_info(&self, username: &str) -> Result<AuthInfoResponse> {
        let body = serde_json::json!({ "Username": username });
        let text = self
            .client
            .post(format!("{BASE_URL}/auth/v4/info"))
            .json(&body)
            .send()
            .await?
            .text()
            .await?;

        let parsed: AuthInfoResponse = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed)
    }

    /// `POST /auth/v4` — submit SRP proof and receive session tokens.
    pub async fn authenticate(&self, req: &AuthRequest) -> Result<AuthResponse> {
        let text = self
            .client
            .post(format!("{BASE_URL}/auth/v4"))
            .json(req)
            .send()
            .await?
            .text()
            .await?;

        let parsed: AuthResponse = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed)
    }

    /// `POST /auth/v4/2fa` — submit a TOTP code after the main auth step.
    pub async fn submit_2fa(&self, code: &str) -> Result<()> {
        let session = self.require_session()?;
        let req = TwoFactorRequest { code: code.to_string() };

        let text = self
            .client
            .post(format!("{BASE_URL}/auth/v4/2fa"))
            .header(header::AUTHORIZATION, format!("Bearer {}", session.access_token))
            .header("x-pm-uid", &session.uid)
            .json(&req)
            .send()
            .await?
            .text()
            .await?;

        let v: serde_json::Value = serde_json::from_str(&text)?;
        let api_code = v["Code"].as_i64().unwrap_or(0) as i32;
        if api_code != 1000 {
            return Err(Error::Api { code: api_code, message: text });
        }
        Ok(())
    }

    /// `POST /auth/v4/refresh` — exchange a refresh token for a new access token.
    pub async fn refresh_token(&self) -> Result<AuthResponse> {
        let session = self.require_session()?;
        let req = RefreshRequest {
            uid: session.uid.clone(),
            refresh_token: session.refresh_token.clone(),
            grant_type: "refresh_token".to_string(),
            redirect_uri: "https://proton.me".to_string(),
            response_type: "token".to_string(),
        };

        let text = self
            .client
            .post(format!("{BASE_URL}/auth/v4/refresh"))
            .header("x-pm-uid", &session.uid)
            .json(&req)
            .send()
            .await?
            .text()
            .await?;

        let parsed: AuthResponse = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed)
    }

    /// `DELETE /auth/v4` — revoke the current session on the server.
    pub async fn logout(&self) -> Result<()> {
        let session = self.require_session()?;
        let resp = self
            .client
            .delete(format!("{BASE_URL}/auth/v4"))
            .header(header::AUTHORIZATION, format!("Bearer {}", session.access_token))
            .header("x-pm-uid", &session.uid)
            .send()
            .await?;

        // If 401, the session is already invalid — silently succeed.
        if resp.status() == StatusCode::UNAUTHORIZED {
            return Ok(());
        }
        resp.error_for_status().map_err(|e| Error::Http(e))?;
        Ok(())
    }

    // ── Drive endpoints ────────────────────────────────────────────────────

    /// `GET /drive/volumes` — list all volumes for the authenticated user.
    pub async fn list_volumes(&self) -> Result<Vec<Volume>> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Resp { code: i32, volumes: Vec<Volume> }

        let text = self.authed_get("/drive/volumes").await?;
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed.volumes)
    }

    /// `GET /drive/shares` — list all shares visible to the user.
    pub async fn list_shares(&self) -> Result<Vec<ShareMetadata>> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Resp { code: i32, shares: Vec<ShareMetadata> }

        let text = self.authed_get("/drive/shares?ShowAll=1").await?;
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed.shares)
    }

    /// `GET /drive/shares/{id}` — fetch full share details (including keys).
    pub async fn get_share(&self, share_id: &str) -> Result<Share> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Resp { code: i32, share: Share }

        let text = self.authed_get(&format!("/drive/shares/{share_id}")).await?;
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed.share)
    }

    /// `GET /drive/shares/{shareID}/links/{linkID}` — fetch a single link.
    pub async fn get_link(&self, share_id: &str, link_id: &str) -> Result<Link> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Resp { code: i32, link: Link }

        let text = self
            .authed_get(&format!("/drive/shares/{share_id}/links/{link_id}"))
            .await?;
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed.link)
    }

    /// `GET /drive/shares/{shareID}/folders/{linkID}/children` — list folder children.
    ///
    /// Returns one page (up to `page_size` links).  Call repeatedly with
    /// increasing `page` (0-indexed) until fewer than `page_size` links are
    /// returned.
    pub async fn list_children(
        &self,
        share_id: &str,
        folder_link_id: &str,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<Link>> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Resp { code: i32, links: Vec<Link> }

        let url = format!(
            "/drive/shares/{share_id}/folders/{folder_link_id}/children\
             ?Page={page}&PageSize={page_size}&ShowAll=1"
        );
        let text = self.authed_get(&url).await?;
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed.links)
    }

    // ── Revision endpoints ────────────────────────────────────────────────

    /// `GET /drive/shares/{shareID}/links/{linkID}/revisions/{revisionID}` — fetch revision metadata and block list.
    pub async fn get_revision(
        &self,
        share_id: &str,
        link_id: &str,
        revision_id: &str,
    ) -> Result<Revision> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Resp { code: i32, revision: Revision }

        let text = self
            .authed_get(&format!(
                "/drive/shares/{share_id}/links/{link_id}/revisions/{revision_id}"
            ))
            .await?;
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed.revision)
    }

    /// Download a raw block from a pre-signed URL (no auth needed).
    pub async fn download_block(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::Http(e))?;
        Ok(resp.bytes().await.map_err(|e| Error::Http(e))?.to_vec())
    }

    // ── Upload endpoints ───────────────────────────────────────────────────

    /// `POST /drive/shares/{shareID}/links` — create a file or folder.
    pub async fn create_link(&self, share_id: &str, body: &impl serde::Serialize) -> Result<String> {
        let text = self
            .authed(&format!("/drive/shares/{share_id}/links"), "POST", body)
            .await?;
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Resp {
            code: i32,
            #[serde(rename = "ID")]
            id: String,
        }
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed.id)
    }

    /// `POST /drive/shares/{shareID}/links/{linkID}/revisions` — create a
    /// revision with the block list; returns upload URLs.
    pub async fn create_revision(
        &self,
        share_id: &str,
        link_id: &str,
        body: &CreateRevisionReq,
    ) -> Result<CreateRevisionRes> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Resp {
            code: i32,
            revision: CreateRevisionRes,
        }
        let text = self
            .authed(
                &format!("/drive/shares/{share_id}/links/{link_id}/revisions"),
                "POST",
                body,
            )
            .await?;
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed.revision)
    }

    /// `PUT <pre-signed-url>` — upload a single encrypted block.
    pub async fn upload_block(&self, url: &str, data: &[u8]) -> Result<()> {
        // Blocks are uploaded with raw binary content type.
        self.client
            .put(url)
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| Error::Http(e))?;
        Ok(())
    }

    /// `PUT /drive/shares/{shareID}/links/{linkID}/revisions/{revisionID}/state`
    /// — mark a revision as active (complete upload).
    pub async fn complete_revision(
        &self,
        share_id: &str,
        link_id: &str,
        revision_id: &str,
    ) -> Result<()> {
        let body = UpdateRevisionStateReq { state: 1 }; // 1 = Active
        #[derive(serde::Deserialize)]
        struct Resp {
            code: i32,
        }
        let text = self
            .authed(
                &format!(
                    "/drive/shares/{share_id}/links/{link_id}/revisions/{revision_id}/state"
                ),
                "PUT",
                &body,
            )
            .await?;
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(())
    }

    /// Send an authed request with the given method and JSON body.
    async fn authed(
        &self,
        path: &str,
        method: &str,
        body: &impl serde::Serialize,
    ) -> Result<String> {
        let session = self.require_session()?;
        let url = format!("{BASE_URL}{path}");
        let json = serde_json::to_vec(body)
            .map_err(|e| Error::Io(format!("serialize body: {e}")))?;

        let req = self
            .client
            .request(
                reqwest::Method::from_bytes(method.as_bytes())
                    .map_err(|e| Error::Io(format!("method: {e}")))?,
                &url,
            )
            .header("x-pm-uid", &session.uid)
            .header("Authorization", format!("Bearer {}", session.access_token))
            .header("x-pm-appversion", APP_VERSION)
            .header("Content-Type", "application/json;charset=utf-8")
            .body(json);

        let resp = req.send().await.map_err(|e| Error::Http(e))?;
        let status = resp.status();
        let text = resp.text().await.map_err(|e| Error::Http(e))?;

        if status == reqwest::StatusCode::UNAUTHORIZED {
            // Token expired — refresh and retry once.
            self.refresh_and_update_session().await?;
            // No need to rebuild the request body for the second call.
            return self.authed_unchecked(path, method, body).await;
        }

        Ok(text)
    }

    /// Like `authed` but skips the 401 check (used for retry after refresh).
    async fn authed_unchecked(
        &self,
        path: &str,
        method: &str,
        body: &impl serde::Serialize,
    ) -> Result<String> {
        let session = self.require_session()?;
        let url = format!("{BASE_URL}{path}");
        let json = serde_json::to_vec(body)
            .map_err(|e| Error::Io(format!("serialize body: {e}")))?;

        let resp = self
            .client
            .request(
                reqwest::Method::from_bytes(method.as_bytes())
                    .map_err(|e| Error::Io(format!("method: {e}")))?,
                &url,
            )
            .header("x-pm-uid", &session.uid)
            .header("Authorization", format!("Bearer {}", session.access_token))
            .header("x-pm-appversion", APP_VERSION)
            .header("Content-Type", "application/json;charset=utf-8")
            .body(json)
            .send()
            .await
            .map_err(|e| Error::Http(e))?;
        let text = resp.text().await.map_err(|e| Error::Http(e))?;
        Ok(text)
    }

    // ── Key / address endpoints ───────────────────────────────────────────

    /// `GET /core/v4/addresses` — list all addresses with their key material.
    pub async fn get_addresses(&self) -> Result<Vec<Address>> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Resp { code: i32, addresses: Vec<Address> }

        let text = self.authed_get("/core/v4/addresses").await?;
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed.addresses)
    }

    /// `GET /core/v4/keys/salts` — per-key bcrypt salts for key-password derivation.
    pub async fn get_key_salts(&self) -> Result<Vec<KeySalt>> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Resp { code: i32, key_salts: Vec<KeySalt> }

        let text = self.authed_get("/core/v4/keys/salts").await?;
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed.key_salts)
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    /// Perform an authenticated GET to a path under `BASE_URL`.
    ///
    /// Automatically refreshes the access token on 401 and retries once.
    async fn authed_get(&self, path: &str) -> Result<String> {
        let session = self.require_session()?;
        let resp = self
            .client
            .get(format!("{BASE_URL}{path}"))
            .header(header::AUTHORIZATION, format!("Bearer {}", session.access_token))
            .header("x-pm-uid", &session.uid)
            .send()
            .await?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            return self.authed_get_with_refresh(path).await;
        }

        let text = resp.text().await?;
        Ok(text)
    }

    /// Retry an authenticated GET after refreshing the session token.
    async fn authed_get_with_refresh(&self, path: &str) -> Result<String> {
        let new_session = self.refresh_and_update_session().await?;
        let resp = self
            .client
            .get(format!("{BASE_URL}{path}"))
            .header(header::AUTHORIZATION, format!("Bearer {}", new_session.access_token))
            .header("x-pm-uid", &new_session.uid)
            .send()
            .await?;

        let status = resp.status();
        let text = resp.text().await?;
        if status == StatusCode::UNAUTHORIZED {
            return Err(Error::Auth(
                "Session expired and refresh failed — please log in again".into(),
            ));
        }
        Ok(text)
    }

    /// Refresh the access token, persist to keyring, and update in-memory session.
    async fn refresh_and_update_session(&self) -> Result<Session> {
        let session = self.require_session()?;
        let client = ApiClient::new()?.with_session(session.clone());
        let resp = client.refresh_token().await?;

        let new_session = Session {
            uid: resp.uid,
            access_token: resp.access_token,
            refresh_token: resp.refresh_token,
            username: session.username,
        };

        // Persist the updated tokens so they survive process restart.
        crate::keyring::save_session(&new_session).await.map_err(|e| {
            Error::Keyring(format!("failed to persist refreshed session: {e}"))
        })?;

        let mut guard = self.session.lock().unwrap();
        *guard = Some(new_session.clone());
        Ok(new_session)
    }

    fn require_session(&self) -> Result<Session> {
        self.session
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| Error::Auth("No active session — login first".into()))
    }
}
