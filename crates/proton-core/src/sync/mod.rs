//! Sync engine — orchestrates remote → local file synchronization.
//!
//! ## Algorithm
//!
//! 1. Walk the remote tree with decrypted names (needs user password).
//! 2. Build local paths by walking the parent_link_id chain.
//! 3. For each remote folder → ensure the local directory exists.
//! 4. For each remote file → compare with state DB by `link_id`;
//!    if new or modified, download it.
//! 5. Local-only nodes are tracked for future upload.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::ApiClient;
use crate::api::drive_types::{BlockEntry, CreateFileReq, CreateFolderReq, CreateRevisionReq};
use crate::api::types::AddressKey;
use crate::crypto::{
    compute_name_hash, decrypt_block, decrypt_session_key, encrypt_block,
    generate_hash_key, generate_node_keypair, generate_session_key, pgp_decrypt,
    pgp_encrypt, pgp_sign, create_content_key_packet,
};
use crate::db::{JobFields, NodeFields, StateDb};
use crate::drive::keyring::{derive_key_password, DriveKeyring};
use crate::drive::{DriveClient, DriveNode};
use crate::local::LocalClient;
use crate::{Error, Result};

// ── SyncReport ─────────────────────────────────────────────────────────────

/// Result of a sync cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncReport {
    pub dirs_created: usize,
    pub downloads_attempted: usize,
    pub downloads_succeeded: usize,
    pub uploads_attempted: usize,
    pub uploads_succeeded: usize,
    pub errors: Vec<String>,
}

impl SyncReport {
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

// ── SyncEngine ─────────────────────────────────────────────────────────────

/// Two-way sync orchestrator.
pub struct SyncEngine {
    api: ApiClient,
    db: Arc<StateDb>,
    base_path: PathBuf,
}

/// Interim representation: a remote node with its plaintext name and local path.
struct RemoteEntry {
    node: DriveNode,
    plain_name: String,
    local_path: PathBuf,
}

impl SyncEngine {
    pub fn new(api: ApiClient, db: Arc<StateDb>, base_path: PathBuf) -> Self {
        Self { api, db, base_path }
    }

    /// Run a full remote → local sync cycle.
    ///
    /// `password` is the user's login password, needed to decrypt remote
    /// file/folder names so they can be mapped to local paths.
    pub async fn sync(&self, password: &str) -> Result<SyncReport> {
        let mut report = SyncReport {
            dirs_created: 0,
            downloads_attempted: 0,
            downloads_succeeded: 0,
            uploads_attempted: 0,
            uploads_succeeded: 0,
            errors: Vec::new(),
        };

        let session = self
            .api
            .session()
            .ok_or_else(|| Error::Auth("no session".into()))?;
        let drive = DriveClient::new(ApiClient::new()?.with_session(session));

        // ── Fetch address key info for upload signing ─────────────────────
        let (address_key_info, signature_address) = self
            .fetch_address_key(&drive, password)
            .await
            .unwrap_or((None, String::new()));

        // ── 1. Walk remote tree with decrypted names ──────────────────────
        let (remote, kr) = match drive.walk_all_decrypted(password).await {
            Ok(pair) => pair,
            Err(e) => {
                report.errors.push(format!("remote walk failed: {e}"));
                return Ok(report);
            }
        };

        // ── 2. Build RemoteEntries by resolving paths from the root down ──
        // First pass — collect all entries without paths.
        let mut entries: Vec<RemoteEntry> = remote
            .iter()
            .map(|(node, name)| RemoteEntry {
                node: node.clone(),
                plain_name: name.clone(),
                local_path: PathBuf::new(), // filled below
            })
            .collect();

        // Build a link_id → entry index lookup.
        let mut by_link: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            by_link.insert(e.node.link_id.clone(), i);
        }

        // Resolve paths top-down. Sort by depth (root has 0 depth).
        // The root link has parent_link_id == None and depth 0.
        // We walk in increasing depth so parent paths are known first.
        let mut depth_cache: Vec<u32> = vec![0; entries.len()];
        for i in 0..entries.len() {
            let mut depth = 0u32;
            let mut pid = entries[i].node.parent_link_id.clone();
            while let Some(id) = pid {
                depth += 1;
                pid = by_link.get(&id).and_then(|&idx| entries[idx].node.parent_link_id.clone());
                if depth > 1000 {
                    break;
                }
            }
            depth_cache[i] = depth;
        }

        let mut order: Vec<usize> = (0..entries.len()).collect();
        order.sort_by_key(|&i| depth_cache[i]);

        let mut local_paths: Vec<PathBuf> = vec![PathBuf::new(); entries.len()];
        for &i in &order {
            let name = sanitize_name(&entries[i].plain_name);
            let parent_path = match &entries[i].node.parent_link_id {
                Some(pid) => {
                    let pidx = *by_link.get(pid).unwrap();
                    local_paths[pidx].clone()
                }
                None => PathBuf::new(),
            };
            local_paths[i] = parent_path.join(name);
        }

        for (i, path) in local_paths.into_iter().enumerate() {
            entries[i].local_path = path;
        }

        // ── 3. Create local directories ───────────────────────────────────
        for e in &entries {
            if !e.node.is_folder() {
                continue;
            }
            let full = self.base_path.join(&e.local_path);
            if !full.exists() {
                if let Err(err) = std::fs::create_dir_all(&full) {
                    report.errors.push(format!("create dir {}: {err}", full.display()));
                    continue;
                }
                report.dirs_created += 1;
            }
            self.db.upsert_node(&NodeFields {
                local_path: e.local_path.clone(),
                link_id: Some(e.node.link_id.clone()),
                share_id: Some(e.node.share_id.clone()),
                name_encrypted: e.node.encrypted_name.clone(),
                size: 0,
                modified_time: 0,
                hash: None,
                is_file: false,
                state: "synced".into(),
            }).ok();
        }

        // Build path → (node, name) map for upload parent lookup.
        let mut remote_by_path: std::collections::HashMap<PathBuf, (DriveNode, String)> =
            std::collections::HashMap::new();
        for e in &entries {
            remote_by_path.insert(e.local_path.clone(), (e.node.clone(), e.plain_name.clone()));
        }

        // ── 5. Upload new/changed local files ──────────────────────────────
        let share_id = entries.first().map(|e| e.node.share_id.clone()).unwrap_or_default();
        let addr_ref = address_key_info.as_ref().map(|(k, p)| (k, p.as_slice()));

        // Ensure remote folders exist for local-only directories.
        let local_nodes = match LocalClient::new(self.base_path.clone()).walk_all().await {
            Ok(nodes) => nodes,
            Err(e) => {
                report.errors.push(format!("local walk failed: {e}"));
                return Ok(report);
            }
        };
        self.ensure_remote_folders(
            &mut report,
            &share_id,
            &kr,
            &mut remote_by_path,
            &local_nodes,
            addr_ref,
            &signature_address,
        )
        .await;

        self.upload_new_files(&mut report, &share_id, &kr, &remote_by_path, addr_ref, &signature_address)
            .await;

        // ── 4. Sync files ─────────────────────────────────────────────────
        for e in &entries {
            if !e.node.is_file() {
                continue;
            }

            let exists = self
                .db
                .get_node_by_link_id(&e.node.link_id)
                .ok()
                .flatten();

            let needs_download = match &exists {
                None => true,
                Some(row) => row.size != e.node.size || row.modified_time != e.node.modify_time,
            };

            if !needs_download {
                continue;
            }

            report.downloads_attempted += 1;

            // Persist pending state.
            self.db.upsert_node(&NodeFields {
                local_path: e.local_path.clone(),
                link_id: Some(e.node.link_id.clone()),
                share_id: Some(e.node.share_id.clone()),
                name_encrypted: e.node.encrypted_name.clone(),
                size: e.node.size,
                modified_time: e.node.modify_time,
                hash: None,
                is_file: true,
                state: "pending".into(),
            }).ok();

            self.db.enqueue_job(&JobFields {
                job_type: "download".into(),
                local_path: e.local_path.clone(),
                link_id: Some(e.node.link_id.clone()),
            }).ok();

            // Attempt the download inline for the MVP.
            match self.download_file(&e.node, &e.local_path, &kr).await {
                Ok(()) => report.downloads_succeeded += 1,
                Err(err) => report.errors.push(format!("download {}: {err}", e.node.link_id)),
            }
        }

        // Persist last sync timestamp.
        self.db.set_meta("last_sync", &Self::chrono_now_rfc3339()).ok();

        Ok(report)
    }

    /// RFC 3339 timestamp string for the current time.
    fn chrono_now_rfc3339() -> String {
        // Use a simple format since we don't depend on chrono.
        // `date` in ISO 8601 / RFC 3339 without chrono.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs();
        // Format as RFC 3339: 2024-01-15T10:30:00Z
        let days = secs / 86400;
        let time_secs = secs % 86400;
        let hours = time_secs / 3600;
        let minutes = (time_secs % 3600) / 60;
        let seconds = time_secs % 60;

        // Simple Gregorian calendar date calculation from Unix epoch days.
        let (year, month, day) = Self::days_to_date(days as i64);
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year, month, day, hours, minutes, seconds
        )
    }

    /// Convert a Unix epoch day count to Gregorian (year, month, day).
    fn days_to_date(days: i64) -> (i64, u32, u32) {
        // Algorithm from Howard Hinnant's public-domain date algorithms.
        let z = days + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        (y, m as u32, d as u32)
    }

    /// Download a single remote file to the local filesystem, decrypting
    /// block content using the node key from `kr`.
    async fn download_file(
        &self,
        node: &DriveNode,
        local_path: &Path,
        kr: &DriveKeyring,
    ) -> Result<()> {
        let link = self.api.get_link(&node.share_id, &node.link_id).await?;
        let rev_meta = match link.file_properties {
            Some(ref fp) => &fp.active_revision,
            None => return Err(Error::Crypto("no active revision".into())),
        };

        let content_key_packet = match link.file_properties {
            Some(ref fp) => fp.content_key_packet.clone(),
            None => return Err(Error::Crypto("no content key packet".into())),
        };

        // Get the node's unlocked private key from the keyring.
        let (node_armored_key, node_passphrase) = kr.get_key(&node.link_id).ok_or_else(|| {
            Error::Crypto(format!("node key not in keyring: {}", node.link_id))
        })?;

        // Decrypt the content key packet → 32-byte session key.
        let session_key = decrypt_session_key(&content_key_packet, node_armored_key, node_passphrase)?;

        let revision = self
            .api
            .get_revision(&node.share_id, &node.link_id, &rev_meta.id)
            .await?;

        let full_path = self.base_path.join(local_path);
        if let Some(parent) = full_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| Error::Io(format!("create parent dir: {e}")))?;
        }

        // Download and decrypt each block, then write plaintext.
        let mut file = tokio::fs::File::create(&full_path)
            .await
            .map_err(|e| Error::Io(format!("create {}: {e}", full_path.display())))?;

        for block in &revision.blocks {
            let enc = self.api.download_block(&block.url).await?;
            let pt = decrypt_block(&enc, &session_key, block.index)?;
            tokio::io::AsyncWriteExt::write_all(&mut file, &pt)
                .await
                .map_err(|e| Error::Io(format!("write block: {e}")))?;
        }

        // Mark synced in DB.
        self.db.upsert_node(&NodeFields {
            local_path: local_path.to_path_buf(),
            link_id: Some(node.link_id.clone()),
            share_id: Some(node.share_id.clone()),
            name_encrypted: node.encrypted_name.clone(),
            size: node.size,
            modified_time: node.modify_time,
            hash: None,
            is_file: true,
            state: "synced".into(),
        })?;

        // Complete the pending download job(s) for this file.
        while let Ok(Some(job)) = self.db.dequeue_job() {
            if job.job_type == "download" && job.link_id.as_deref() == Some(&node.link_id) {
                self.db.complete_job(job.id).ok();
                break;
            }
        }

        Ok(())
    }

    /// Create remote folders for local-only directories.
    ///
    /// Walks `local_nodes`, finds directories without a remote entry, and
    /// creates them on the server in depth order.  Newly created folders are
    /// inserted into `remote_by_path` so subsequent file uploads can find
    /// their parent.
    async fn ensure_remote_folders(
        &self,
        report: &mut SyncReport,
        share_id: &str,
        kr: &DriveKeyring,
        remote_by_path: &mut std::collections::HashMap<PathBuf, (DriveNode, String)>,
        local_nodes: &[crate::local::LocalNode],
        address_key: Option<(&AddressKey, &[u8])>,
        signature_address: &str,
    ) {
        // Collect local-only directories and sort by depth (shallowest first).
        let mut new_dirs: Vec<(usize, PathBuf, String)> = Vec::new();
        for (_, node) in local_nodes.iter().enumerate() {
            if node.is_file {
                continue;
            }
            let rel = match node.relative_path(&self.base_path) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if remote_by_path.contains_key(&rel) {
                continue; // already exists on remote
            }
            let dir_name = rel
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if dir_name.is_empty() {
                continue;
            }
            new_dirs.push((rel.components().count(), rel, dir_name));
        }
        new_dirs.sort_by_key(|(depth, _, _)| *depth);

        for (_depth, rel, dir_name) in &new_dirs {
            let parent_path = rel.parent().map(|p| p.to_path_buf()).unwrap_or_default();

            // Determine the parent node (may have been created this iteration).
            let parent_node = if parent_path.as_os_str().is_empty() {
                // Root folder — parent is the top-level remote folder.
                // This shouldn't normally happen but handle gracefully.
                report.errors.push(format!("cannot create root folder remotely"));
                continue;
            } else {
                match remote_by_path.get(&parent_path) {
                    Some((pn, _)) => pn.clone(),
                    None => {
                        report.errors.push(format!(
                            "parent not found for dir {}",
                            rel.display()
                        ));
                        continue;
                    }
                }
            };

            // Generate key material.
            let (node_key, node_pass) = match generate_node_keypair() {
                Ok(pair) => pair,
                Err(e) => {
                    report.errors.push(format!("generate key for dir {}: {e}", rel.display()));
                    continue;
                }
            };

            // Encrypt name with parent's key.
            let enc_name = match kr.encrypt_name_raw(dir_name, &parent_node.link_id) {
                Ok(n) => n,
                Err(e) => {
                    report.errors.push(format!("encrypt name for dir {}: {e}", rel.display()));
                    continue;
                }
            };

            // Encrypt passphrase with parent's key.
            let enc_pass = match pgp_encrypt(
                hex::encode(&node_pass).as_bytes(),
                &parent_node.node_key,
            ) {
                Ok(p) => p,
                Err(e) => {
                    report
                        .errors
                        .push(format!("encrypt passphrase for dir {}: {e}", rel.display()));
                    continue;
                }
            };

            // Sign passphrase with address key.
            let (pass_sig, sig_addr) = if let Some((addr_key, addr_pass)) = address_key {
                let sig = pgp_sign(enc_pass.as_bytes(), &addr_key.private_key, addr_pass)
                    .unwrap_or_default();
                (sig, signature_address.to_string())
            } else {
                (String::new(), signature_address.to_string())
            };

            // ── Compute name hash and hash key ──────────────────────────────
            // Decrypt the parent folder's node_hash_key with the parent's key.
            let name_hash;
            let enc_hash_key;
            let hash_key = generate_hash_key();
            if parent_node.node_hash_key.is_empty() {
                // Root or missing hash key — skip hash computation.
                name_hash = String::new();
                enc_hash_key = String::new();
            } else {
                let (parent_key, parent_pass) = match kr.get_key(&parent_node.link_id) {
                    Some(k) => k,
                    None => {
                        report.errors.push(format!(
                            "parent key not found for {}",
                            rel.display()
                        ));
                        continue;
                    }
                };
                let parent_hash_key = pgp_decrypt(
                    &parent_node.node_hash_key,
                    parent_key,
                    parent_pass,
                )
                .unwrap_or_default();

                name_hash = compute_name_hash(&parent_hash_key, dir_name);
                enc_hash_key = pgp_encrypt(&hash_key, &node_key).unwrap_or_default();
            }

            let req = CreateFolderReq {
                parent_link_id: parent_node.link_id.clone(),
                name: enc_name.clone(),
                hash: name_hash,
                node_key,
                node_hash_key: enc_hash_key,
                node_passphrase: enc_pass,
                node_passphrase_signature: pass_sig,
                signature_address: sig_addr,
            };

            match self.api.create_link(share_id, &req).await {
                Ok(id) => {
                    // Build a minimal DriveNode representing the new remote folder.
                    let new_node = DriveNode {
                        share_id: share_id.to_string(),
                        link_id: id,
                        parent_link_id: Some(parent_node.link_id.clone()),
                        link_type: crate::api::drive_types::LinkType::Folder,
                        encrypted_name: enc_name,
                        hash: req.hash,
                        size: 0,
                        state: crate::api::drive_types::LinkState::Active,
                        mime_type: "".into(),
                        create_time: 0,
                        modify_time: 0,
                        node_key: req.node_key,
                        node_passphrase: req.node_passphrase,
                        node_hash_key: req.node_hash_key,
                    };
                    remote_by_path
                        .insert(rel.clone(), (new_node, dir_name.clone()));
                    report.dirs_created += 1;
                }
                Err(e) => {
                    report
                        .errors
                        .push(format!("create folder {}: {e}", rel.display()));
                }
            }
        }
    }

    /// Upload new local files to the remote.
    ///
    /// `remote_by_path` maps local relative paths to their corresponding
    /// `(DriveNode, plain_name)` for the remote tree.  May be modified by
    /// [`ensure_remote_folders`] before this is called.
    async fn upload_new_files(
        &self,
        report: &mut SyncReport,
        share_id: &str,
        kr: &DriveKeyring,
        remote_by_path: &std::collections::HashMap<PathBuf, (DriveNode, String)>,
        address_key: Option<(&AddressKey, &[u8])>,
        signature_address: &str,
    ) {
        let local = LocalClient::new(self.base_path.clone());
        let local_nodes = match local.walk_all().await {
            Ok(nodes) => nodes,
            Err(e) => {
                report.errors.push(format!("local walk failed: {e}"));
                return;
            }
        };

        for local_node in &local_nodes {
            if !local_node.is_file {
                continue;
            }

            let rel = match local_node.relative_path(&self.base_path) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let parent_path = match rel.parent() {
                Some(p) => p.to_path_buf(),
                None => PathBuf::new(),
            };

            // Find the remote parent folder for this file's directory.
            let (parent_node, _parent_name) = match remote_by_path.get(&parent_path) {
                Some(e) => e,
                None => {
                    report
                        .errors
                        .push(format!("remote parent not found for {}", rel.display()));
                    continue;
                }
            };

            if !parent_node.is_folder() {
                report.errors.push(format!(
                    "parent {} is not a folder",
                    parent_path.display()
                ));
                continue;
            }

            let file_name = match rel.file_name() {
                Some(n) => n.to_string_lossy().to_string(),
                None => continue,
            };

            // Check DB to see if this file is already known.
            let existing = self
                .db
                .list_nodes("synced")
                .ok()
                .unwrap_or_default()
                .into_iter()
                .find(|n| n.local_path == rel);

            if let Some(row) = existing {
                // File already synced — check if modified.
                if row.size == local_node.size as i64
                    && (row.modified_time as u64)
                        == local_node
                            .modified_time
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                {
                    continue; // unchanged
                }

                // ── Modified — upload new revision ────────────────────────
                report.uploads_attempted += 1;

                let link_id = match &row.link_id {
                    Some(id) => id.clone(),
                    None => {
                        report.errors.push(format!(
                            "{} has no link_id — skipping revision",
                            rel.display()
                        ));
                        continue;
                    }
                };

                // Get the existing remote node for its key material.
                let (existing_node, _) = match remote_by_path.get(&rel) {
                    Some(e) => e,
                    None => {
                        report.errors.push(format!(
                            "remote entry not found for modified {}",
                            rel.display()
                        ));
                        continue;
                    }
                };

                // Decrypt the existing node passphrase with the parent's key.
                let (parent_key, parent_pass) = match kr.get_key(&parent_node.link_id) {
                    Some(k) => k,
                    None => {
                        report.errors.push(format!(
                            "parent key not found for modified {}",
                            rel.display()
                        ));
                        continue;
                    }
                };
                let node_passphrase = match pgp_decrypt(
                    &existing_node.node_passphrase,
                    parent_key,
                    parent_pass,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        report.errors.push(format!(
                            "decrypt passphrase for modified {}: {e}",
                            rel.display()
                        ));
                        continue;
                    }
                };
                let node_key = &existing_node.node_key;

                let encrypted_name = row.name_encrypted.clone();

                // ── Upload blocks ─────────────────────────────────────────
                let session_key = generate_session_key();
                let content_key_packet = match create_content_key_packet(
                    &session_key,
                    node_key,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        report.errors.push(format!(
                            "content key packet for modified {}: {e}",
                            rel.display()
                        ));
                        continue;
                    }
                };

                let content_key_sig = pgp_sign(
                    content_key_packet.as_bytes(),
                    node_key,
                    &node_passphrase,
                )
                .unwrap_or_default();

                let x_attr = serde_json::json!({
                    "contentKeyPacket": content_key_packet,
                    "contentKeyPacketSignature": content_key_sig,
                }).to_string();

                let file_bytes = match tokio::fs::read(&local_node.path).await {
                    Ok(b) => b,
                    Err(e) => {
                        report.errors.push(format!(
                            "read modified {}: {e}",
                            rel.display()
                        ));
                        continue;
                    }
                };

                const BLOCK_SIZE: usize = 4 * 1024 * 1024;
                let mut block_entries = Vec::new();
                let mut encrypted_blocks: Vec<(u32, Vec<u8>)> = Vec::new();

                let mut offset = 0usize;
                let mut index = 0u32;
                while offset < file_bytes.len() {
                    let end = (offset + BLOCK_SIZE).min(file_bytes.len());
                    let chunk = &file_bytes[offset..end];

                    let enc = match encrypt_block(chunk, &session_key, index) {
                        Ok(b) => b,
                        Err(e) => {
                            report.errors.push(format!(
                                "encrypt block {index} for modified {}: {e}",
                                rel.display()
                            ));
                            break;
                        }
                    };

                    use sha2::{Digest, Sha256};
                    let hash = format!("{:x}", Sha256::digest(chunk));

                    block_entries.push(BlockEntry {
                        hash,
                        enc_signature: String::new(),
                        size: chunk.len() as u64,
                        index,
                    });
                    encrypted_blocks.push((index, enc));

                    offset = end;
                    index += 1;
                }

                if block_entries.len() as u32 != index {
                    continue;
                }

                let rev = match self.api.create_revision(share_id, &link_id, &CreateRevisionReq {
                    block_list: block_entries,
                    manifest_signature: String::new(),
                    signature_address: String::new(),
                    x_attr,
                }).await {
                    Ok(r) => r,
                    Err(e) => {
                        report.errors.push(format!(
                            "create revision for modified {}: {e}",
                            rel.display()
                        ));
                        continue;
                    }
                };

                for (block_index, enc_data) in &encrypted_blocks {
                    let url = match rev.block_list.iter().find(|b| b.index == *block_index) {
                        Some(b) => &b.url,
                        None => {
                            report.errors.push(format!(
                                "no upload URL for block {block_index} of modified {}",
                                rel.display()
                            ));
                            continue;
                        }
                    };

                    if let Err(e) = self.api.upload_block(url, enc_data).await {
                        report.errors.push(format!(
                            "upload block {block_index} for modified {}: {e}",
                            rel.display()
                        ));
                        continue;
                    }
                }

                if let Err(e) = self.api.complete_revision(share_id, &link_id, &rev.id).await {
                    report.errors.push(format!(
                        "complete revision for modified {}: {e}",
                        rel.display()
                    ));
                    continue;
                }

                report.uploads_succeeded += 1;

                self.db.upsert_node(&NodeFields {
                    local_path: rel.clone(),
                    link_id: Some(link_id),
                    share_id: Some(share_id.to_string()),
                    name_encrypted: encrypted_name,
                    size: local_node.size as i64,
                    modified_time: local_node
                        .modified_time
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64,
                    hash: local_node.hash.clone(),
                    is_file: true,
                    state: "synced".into(),
                }).ok();

                continue; // skip the new-file path below
            }

            report.uploads_attempted += 1;

            // ── Create the remote file ────────────────────────────────────
            let (node_key_armored, node_passphrase) = match generate_node_keypair() {
                Ok(pair) => pair,
                Err(e) => {
                    report.errors.push(format!("generate key for {}: {e}", rel.display()));
                    continue;
                }
            };

            let encrypted_name = match kr.encrypt_name_raw(&file_name, &parent_node.link_id) {
                Ok(n) => n,
                Err(e) => {
                    report.errors.push(format!("encrypt name for {}: {e}", rel.display()));
                    continue;
                }
            };

            let pass_str = hex::encode(&node_passphrase);
            let encrypted_passphrase = match pgp_encrypt(pass_str.as_bytes(), &parent_node.node_key) {
                Ok(p) => p,
                Err(e) => {
                    report
                        .errors
                        .push(format!("encrypt passphrase for {}: {e}", rel.display()));
                    continue;
                }
            };

            let (pass_sig, sig_addr) = if let Some((addr_key, addr_pass)) = address_key {
                let sig = pgp_sign(
                    encrypted_passphrase.as_bytes(),
                    &addr_key.private_key,
                    addr_pass,
                )
                .unwrap_or_default();
                (sig, signature_address.to_string())
            } else {
                (String::new(), signature_address.to_string())
            };

            // ── Compute name hash and hash key ──────────────────────────────
            let name_hash;
            let enc_hash_key;
            let hash_key = generate_hash_key();
            if parent_node.node_hash_key.is_empty() {
                name_hash = String::new();
                enc_hash_key = String::new();
            } else {
                let (parent_key, parent_pass) = match kr.get_key(&parent_node.link_id) {
                    Some(k) => k,
                    None => {
                        report.errors.push(format!(
                            "parent key not found for {}",
                            rel.display()
                        ));
                        continue;
                    }
                };
                let parent_hash_key = pgp_decrypt(
                    &parent_node.node_hash_key,
                    parent_key,
                    parent_pass,
                )
                .unwrap_or_default();

                name_hash = compute_name_hash(&parent_hash_key, &file_name);
                enc_hash_key = pgp_encrypt(&hash_key, &node_key_armored).unwrap_or_default();
            }

            let node_key_for_content = node_key_armored.clone();
            let req = CreateFileReq {
                parent_link_id: parent_node.link_id.clone(),
                node_hash_key: enc_hash_key,
                name: encrypted_name.clone(),
                hash: name_hash,
                node_key: node_key_armored,
                node_passphrase: encrypted_passphrase,
                node_passphrase_signature: pass_sig,
                signature_address: sig_addr,
                mime_type: guess_mime(&file_name),
                size: local_node.size as i64,
            };

            let link_id = match self.api.create_link(share_id, &req).await {
                Ok(id) => id,
                Err(e) => {
                    report.errors.push(format!("create link for {}: {e}", rel.display()));
                    continue;
                }
            };

            // ── Upload blocks ─────────────────────────────────────────────
            let session_key = generate_session_key();
            let content_key_packet = match create_content_key_packet(
                &session_key,
                &node_key_for_content,
            ) {
                Ok(p) => p,
                Err(e) => {
                    report
                        .errors
                        .push(format!("content key packet for {}: {e}", rel.display()));
                    continue;
                }
            };

            let content_key_sig = pgp_sign(
                content_key_packet.as_bytes(),
                &node_key_for_content,
                &node_passphrase,
            )
            .unwrap_or_default();

            let x_attr = serde_json::json!({
                "contentKeyPacket": content_key_packet,
                "contentKeyPacketSignature": content_key_sig,
            }).to_string();

            let file_bytes = match tokio::fs::read(&local_node.path).await {
                Ok(b) => b,
                Err(e) => {
                    report
                        .errors
                        .push(format!("read {}: {e}", rel.display()));
                    continue;
                }
            };

            const BLOCK_SIZE: usize = 4 * 1024 * 1024;
            let mut block_entries = Vec::new();
            let mut encrypted_blocks: Vec<(u32, Vec<u8>, String)> = Vec::new();

            let mut offset = 0usize;
            let mut index = 0u32;
            while offset < file_bytes.len() {
                let end = (offset + BLOCK_SIZE).min(file_bytes.len());
                let chunk = &file_bytes[offset..end];

                let enc = match encrypt_block(chunk, &session_key, index) {
                    Ok(b) => b,
                    Err(e) => {
                        report.errors.push(format!(
                            "encrypt block {index} for {}: {e}",
                            rel.display()
                        ));
                        break;
                    }
                };

                use sha2::{Digest, Sha256};
                let hash = format!("{:x}", Sha256::digest(chunk));

                block_entries.push(BlockEntry {
                    hash,
                    enc_signature: String::new(),
                    size: chunk.len() as u64,
                    index,
                });
                encrypted_blocks.push((index, enc, String::new()));

                offset = end;
                index += 1;
            }

            if block_entries.len() as u32 != index {
                continue;
            }

            let rev = match self.api.create_revision(share_id, &link_id, &CreateRevisionReq {
                block_list: block_entries,
                manifest_signature: String::new(),
                signature_address: String::new(),
                x_attr,
            }).await {
                Ok(r) => r,
                Err(e) => {
                    report.errors.push(format!("create revision for {}: {e}", rel.display()));
                    continue;
                }
            };

            for (block_index, enc_data, _) in &encrypted_blocks {
                let url = match rev.block_list.iter().find(|b| b.index == *block_index) {
                    Some(b) => &b.url,
                    None => {
                        report.errors.push(format!(
                            "no upload URL for block {block_index} of {}",
                            rel.display()
                        ));
                        continue;
                    }
                };

                if let Err(e) = self.api.upload_block(url, enc_data).await {
                    report.errors.push(format!(
                        "upload block {block_index} for {}: {e}",
                        rel.display()
                    ));
                    continue;
                }
            }

            if let Err(e) = self.api.complete_revision(share_id, &link_id, &rev.id).await {
                report
                    .errors
                    .push(format!("complete revision for {}: {e}", rel.display()));
                continue;
            }

            report.uploads_succeeded += 1;

            self.db.upsert_node(&NodeFields {
                local_path: rel,
                link_id: Some(link_id),
                share_id: Some(share_id.to_string()),
                name_encrypted: encrypted_name,
                size: local_node.size as i64,
                modified_time: local_node
                    .modified_time
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
                hash: local_node.hash.clone(),
                is_file: true,
                state: "synced".into(),
            }).ok();
        }
    }

    /// Fetch the primary address key and its derived passphrase for upload
    /// signing. Returns `(address_key, key_password)` and the address email.
    async fn fetch_address_key(
        &self,
        drive: &DriveClient,
        password: &str,
    ) -> Result<(Option<(AddressKey, Vec<u8>)>, String)> {
        // Get the main share to find which address key to use.
        let (share_id, _) = drive.find_main_share().await?;
        let share = self.api.get_share(&share_id).await?;

        let addresses = self.api.get_addresses().await?;
        let key_salts = self.api.get_key_salts().await?;

        // Find the address referenced by the share.
        let addr = addresses
            .iter()
            .find(|a| a.keys.iter().any(|k| k.id == share.address_key_id))
            .ok_or_else(|| Error::Crypto("address not found for share".into()))?;
        let address_key = addr
            .keys
            .iter()
            .find(|k| k.id == share.address_key_id)
            .ok_or_else(|| Error::Crypto("address key not found".into()))?;

        let key_salt = key_salts
            .iter()
            .find(|s| s.id == address_key.id)
            .and_then(|s| s.key_salt.as_deref());
        let key_password = derive_key_password(password, key_salt)
            .map_err(|e| Error::Crypto(format!("derive key password: {e}")))?;

        Ok((
            Some((address_key.clone(), key_password)),
            addr.email.clone(),
        ))
    }
}

/// Guess MIME type from a file name extension.
fn guess_mime(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "doc" | "docx" => "application/msword",
        "xls" | "xlsx" => "application/vnd.ms-excel",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Replace characters unsafe for the local filesystem.
fn sanitize_name(name: &str) -> String {
    name.replace('/', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_replaces_slashes() {
        assert_eq!(sanitize_name("hello/world"), "hello_world");
        assert_eq!(sanitize_name("no-slash"), "no-slash");
        assert_eq!(sanitize_name(""), "");
    }

    #[test]
    fn sync_report_has_errors() {
        let r = SyncReport {
            dirs_created: 0,
            downloads_attempted: 0,
            downloads_succeeded: 0,
            uploads_attempted: 0,
            uploads_succeeded: 0,
            errors: vec!["err".into()],
        };
        assert!(r.has_errors());
    }

    #[test]
    fn sync_report_no_errors() {
        let r = SyncReport {
            dirs_created: 0,
            downloads_attempted: 0,
            downloads_succeeded: 0,
            uploads_attempted: 0,
            uploads_succeeded: 0,
            errors: vec![],
        };
        assert!(!r.has_errors());
    }
}
