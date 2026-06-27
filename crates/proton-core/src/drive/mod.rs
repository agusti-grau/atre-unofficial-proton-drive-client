//! High-level Proton Drive client: tree enumeration.
//!
//! Wraps [`ApiClient`] to provide ergonomic methods for listing and
//! walking the remote drive hierarchy (volumes → shares → links).
//!
//! ## Usage
//!
//! ```no_run
//! use proton_core::drive::DriveClient;
//! use proton_core::api::ApiClient;
//! use proton_core::api::types::Session;
//!
//! # async fn example(session: Session) -> proton_core::Result<()> {
//! let api = ApiClient::new()?.with_session(session);
//! let drive = DriveClient::new(api);
//! let nodes = drive.list_root().await?;
//! for node in &nodes {
//!     println!("{}", node.display_name());
//! }
//! # Ok(())
//! # }
//! ```

pub mod keyring;

use serde::{Deserialize, Serialize};

use crate::api::drive_types::{Link, LinkState, LinkType, VolumeState};
use crate::api::ApiClient;
use crate::drive::keyring::{derive_key_password, DriveKeyring};
use crate::{Error, Result};

/// Page size for folder-children requests.
const PAGE_SIZE: u32 = 150;

// ── DriveNode ──────────────────────────────────────────────────────────────

/// A node in the remote drive tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveNode {
    pub share_id: String,
    pub link_id: String,
    pub parent_link_id: Option<String>,
    pub link_type: LinkType,
    /// PGP-encrypted name as returned by the API.
    /// Use `display_name()` for a printable representation.
    #[serde(rename = "name")]
    pub encrypted_name: String,
    /// HMAC of the plaintext name (for collision detection).
    pub hash: String,
    pub size: i64,
    pub state: LinkState,
    pub mime_type: String,
    pub create_time: i64,
    pub modify_time: i64,
    /// PGP-armored encrypted private node key.
    /// Needed by [`DriveKeyring`] to unlock this node's key so its children
    /// can be decrypted.
    pub node_key: String,
    /// PGP-armored passphrase for `node_key` (encrypted with the parent's node key,
    /// or with the share key for the root link).
    pub node_passphrase: String,
    /// PGP-armored HMAC key used to hash child names.
    /// Only present on folders.
    pub node_hash_key: String,
}

impl DriveNode {
    fn from_link(share_id: &str, link: Link) -> Self {
        Self {
            share_id: share_id.to_string(),
            link_id: link.link_id,
            parent_link_id: link.parent_link_id,
            link_type: link.link_type,
            encrypted_name: link.name,
            hash: link.hash,
            size: link.size,
            state: link.state,
            mime_type: link.mime_type,
            create_time: link.create_time,
            modify_time: link.modify_time,
            node_key: link.node_key,
            node_passphrase: link.node_passphrase,
            node_hash_key: link
                .folder_properties
                .as_ref()
                .map(|p| p.node_hash_key.clone())
                .unwrap_or_default(),
        }
    }

    pub fn is_folder(&self) -> bool {
        self.link_type == LinkType::Folder
    }

    pub fn is_file(&self) -> bool {
        self.link_type == LinkType::File
    }

    pub fn is_active(&self) -> bool {
        self.state == LinkState::Active
    }

    /// Returns the encrypted name until PGP decryption is implemented.
    /// The name is a PGP-armored string; once decryption is wired in this
    /// method will return the plaintext filename.
    pub fn display_name(&self) -> &str {
        &self.encrypted_name
    }
}

// ── DriveClient ────────────────────────────────────────────────────────────

/// High-level client for enumerating the Proton Drive tree.
pub struct DriveClient {
    api: ApiClient,
}

impl DriveClient {
    pub fn new(api: ApiClient) -> Self {
        Self { api }
    }

    /// Find the main (primary) share of the user's default volume.
    ///
    /// Returns `(share_id, root_link_id)`.
    pub async fn find_main_share(&self) -> Result<(String, String)> {
        // Strategy: list volumes and pick the active one, then use its share.
        let volumes = self.api.list_volumes().await?;
        let volume = volumes
            .into_iter()
            .find(|v| v.state == VolumeState::Active)
            .ok_or_else(|| crate::Error::Api {
                code: 0,
                message: "No active volume found".into(),
            })?;

        Ok((volume.share.share_id, volume.share.link_id))
    }

    /// List the immediate children of a folder.
    ///
    /// Fetches all pages automatically.
    pub async fn list_children(
        &self,
        share_id: &str,
        folder_link_id: &str,
    ) -> Result<Vec<DriveNode>> {
        let mut nodes = Vec::new();
        let mut page = 0u32;

        loop {
            let links = self
                .api
                .list_children(share_id, folder_link_id, page, PAGE_SIZE)
                .await?;
            let count = links.len();
            for link in links {
                nodes.push(DriveNode::from_link(share_id, link));
            }
            if count < PAGE_SIZE as usize {
                break;
            }
            page += 1;
        }

        Ok(nodes)
    }

    /// List the root of the user's main share.
    pub async fn list_root(&self) -> Result<Vec<DriveNode>> {
        let (share_id, root_link_id) = self.find_main_share().await?;
        self.list_children(&share_id, &root_link_id).await
    }

    /// Recursively walk the drive tree starting from `folder_link_id`.
    ///
    /// Calls `visitor` for every node encountered (files and folders).
    /// Traversal is depth-first.
    pub async fn walk<F>(&self, share_id: &str, folder_link_id: &str, visitor: &mut F) -> Result<()>
    where
        F: FnMut(&DriveNode),
    {
        let children = self.list_children(share_id, folder_link_id).await?;
        for node in &children {
            visitor(node);
            if node.is_folder() && node.is_active() {
                // SAFETY: recursion depth is bounded by the drive tree depth,
                // which in practice is well under stack limits.
                Box::pin(self.walk(share_id, &node.link_id, visitor)).await?;
            }
        }
        Ok(())
    }

    /// Walk the entire main share and return all nodes.
    pub async fn walk_all(&self) -> Result<Vec<DriveNode>> {
        let (share_id, root_link_id) = self.find_main_share().await?;
        let mut nodes = Vec::new();
        self.walk(&share_id, &root_link_id, &mut |n| nodes.push(n.clone()))
            .await?;
        Ok(nodes)
    }

    // ── Decryption helpers ─────────────────────────────────────────────────

    /// Build a [`DriveKeyring`] for the user's main share.
    ///
    /// # Arguments
    /// - `user_password` — The user's plaintext login password.
    ///
    /// Fetches addresses, key salts, and the full share in order to bootstrap
    /// the key chain.
    pub async fn build_keyring(
        &self,
        user_password: &str,
    ) -> Result<(DriveKeyring, String, String)> {
        let (share_id, root_link_id) = self.find_main_share().await?;

        // Fetch full share (contains encrypted key + passphrase + address_key_id).
        let share = self.api.get_share(&share_id).await?;

        // Fetch address keys and key salts.
        let addresses = self.api.get_addresses().await?;
        let key_salts = self.api.get_key_salts().await?;

        // Locate the specific address key referenced by the share.
        let address_key = addresses
            .iter()
            .flat_map(|a| a.keys.iter())
            .find(|k| k.id == share.address_key_id)
            .ok_or_else(|| {
                Error::Crypto(format!("address key {} not found", share.address_key_id))
            })?;

        // Derive key password using the key-specific salt.
        let key_salt = key_salts
            .iter()
            .find(|s| s.id == address_key.id)
            .and_then(|s| s.key_salt.as_deref());
        let key_password = derive_key_password(user_password, key_salt)?;

        // Bootstrap: share key → root node key.
        let mut kr = DriveKeyring::new();
        kr.init_share(&share, &address_key.private_key, &key_password)?;

        // Unlock root link's node key (parent = share key, looked up by share_id).
        let root_link = self.api.get_link(&share_id, &root_link_id).await?;
        kr.unlock_with_parent(
            &root_link.link_id,
            &share_id,
            &root_link.node_key,
            &root_link.node_passphrase,
        )?;

        Ok((kr, share_id, root_link_id))
    }

    /// List root folder children with decrypted names.
    ///
    /// Returns `(node, plaintext_name)` pairs.
    pub async fn list_root_decrypted(
        &self,
        user_password: &str,
    ) -> Result<Vec<(DriveNode, String)>> {
        let (kr, share_id, root_link_id) = self.build_keyring(user_password).await?;
        let children = self.list_children(&share_id, &root_link_id).await?;

        children
            .into_iter()
            .map(|node| {
                // Every root child's name is encrypted with the root node key.
                let name = kr.decrypt_name_raw(&node.encrypted_name, &root_link_id)?;
                Ok((node, name))
            })
            .collect()
    }

    /// Recursively walk the entire drive tree with decrypted names.
    ///
    /// Calls `visitor` for every node encountered.  Node keys are unlocked
    /// depth-first as folders are entered, so the keyring grows as the walk
    /// descends.  `visitor` receives the node and its plaintext name.
    ///
    /// Returns the populated `DriveKeyring` so callers can later decrypt
    /// file content key packets (see [`crate::crypto::decrypt_session_key`]).
    pub async fn walk_decrypted<F>(
        &self,
        user_password: &str,
        visitor: &mut F,
    ) -> Result<DriveKeyring>
    where
        F: FnMut(&DriveNode, &str) + Send,
    {
        let (mut kr, share_id, root_link_id) = self.build_keyring(user_password).await?;
        Box::pin(self.walk_decrypted_inner(
            &share_id,
            &root_link_id,
            &root_link_id,
            &mut kr,
            visitor,
        ))
        .await?;
        Ok(kr)
    }

    /// Walk all nodes under `folder_link_id` with decrypted names.
    ///
    /// `parent_key_id` is the key ring ID whose key was used to encrypt this
    /// folder's children's names and node passphrases.  For the root folder
    /// that equals `root_link_id`; for sub-folders it equals their own
    /// `link_id`.
    fn walk_decrypted_inner<'a, F>(
        &'a self,
        share_id: &'a str,
        folder_link_id: &'a str,
        parent_key_id: &'a str,
        kr: &'a mut DriveKeyring,
        visitor: &'a mut F,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
    where
        F: FnMut(&DriveNode, &str) + Send,
    {
        Box::pin(async move {
            let children = self.list_children(share_id, folder_link_id).await?;

            for node in &children {
                // Decrypt this node's name using the parent folder's key.
                let name = match kr.decrypt_name_raw(&node.encrypted_name, parent_key_id) {
                    Ok(n) => n,
                    Err(_) => node.encrypted_name.clone(), // fall back to raw on error
                };

                visitor(node, &name);

                // If this is a folder, unlock its own node key and recurse.
                if node.is_folder() && node.is_active() {
                    if let Err(e) = kr.unlock_with_parent(
                        &node.link_id,
                        parent_key_id,
                        &node.node_key,
                        &node.node_passphrase,
                    ) {
                        // Key unlock failed: report the encrypted name and skip subtree.
                        eprintln!("warn: could not unlock key for {}: {e}", node.link_id);
                        continue;
                    }

                    self.walk_decrypted_inner(share_id, &node.link_id, &node.link_id, kr, visitor)
                        .await?;
                }
            }
            Ok(())
        })
    }

    /// Walk the entire drive and return `(node, plaintext_name)` pairs.
    ///
    /// Also returns the populated [`DriveKeyring`] keyed by link/share ID,
    /// useful for subsequent file-content decryption.
    pub async fn walk_all_decrypted(
        &self,
        user_password: &str,
    ) -> Result<(Vec<(DriveNode, String)>, DriveKeyring)> {
        let mut items = Vec::new();
        let kr = self
            .walk_decrypted(user_password, &mut |node, name| {
                items.push((node.clone(), name.to_string()));
            })
            .await?;
        Ok((items, kr))
    }
}
