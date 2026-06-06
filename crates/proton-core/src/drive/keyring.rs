//! Drive-level key management.
//!
//! ## Key hierarchy in Proton Drive
//!
//! ```text
//! [user password]
//!       │  bcrypt + key salt
//!       ▼
//! [key password]  ──unlocks──►  [address private key]
//!                                      │
//!                           decrypt share.passphrase
//!                                      │
//!                                      ▼
//!                              [share key passphrase]
//!                              ──unlocks──►  [share private key]
//!                                                  │
//!                                    decrypt root_link.node_passphrase
//!                                                  │
//!                                                  ▼
//!                                     [root node key passphrase]
//!                                     ──unlocks──►  [root node private key]
//!                                                         │
//!                                           decrypt child.node_passphrase / name
//!                                                         ▼
//!                                                        ...
//! ```
//!
//! `DriveKeyring` holds the decrypted key material for an entire subtree.
//! Keys are stored as `(armored_key, passphrase_bytes)` pairs and parsed
//! on each use to avoid lifetime complexity.
//!
//! All keys — share keys and node keys alike — live in a single map keyed by
//! their respective ID (share_id for share keys, link_id for node keys).
//! This lets the low-level primitives use the same lookup path regardless of
//! whether the parent is a share or another node.

use std::collections::HashMap;

use crate::api::drive_types::Share;
use crate::auth::password::hash_password;
use crate::crypto::{pgp_decrypt, pgp_encrypt};
use crate::{Error, Result};

/// Stored representation of one PGP private key.
#[derive(Debug, Clone)]
struct KeyEntry {
    /// PGP-armored private key (locked with `passphrase`).
    armored_key: String,
    /// Passphrase that unlocks `armored_key`.
    passphrase: Vec<u8>,
}

/// Holds the chain of unlocked keys for one share subtree.
///
/// Keys are indexed by their own ID — either a `share_id` (for the share key)
/// or a `link_id` (for node keys).  The caller is responsible for providing the
/// correct parent ID when unlocking a new key.
#[derive(Debug, Clone)]
pub struct DriveKeyring {
    keys: HashMap<String, KeyEntry>,
}

impl DriveKeyring {
    /// Create an empty keyring.
    pub fn new() -> Self {
        Self { keys: HashMap::new() }
    }

    // ── Initialisation ─────────────────────────────────────────────────────

    /// Bootstrap from a share and its address key.
    ///
    /// Stores the share private key under the share's own ID so it can later
    /// be used as the "parent" when unlocking the root link's node key.
    ///
    /// # Arguments
    /// - `share`                 — Full share (contains `key` + `passphrase`).
    /// - `address_key_armored`   — PGP-armored address private key.
    /// - `address_key_passphrase` — Passphrase that unlocks the address key
    ///                              (the "key password" derived from the user's password).
    pub fn init_share(
        &mut self,
        share: &Share,
        address_key_armored: &str,
        address_key_passphrase: &[u8],
    ) -> Result<()> {
        let share_passphrase =
            pgp_decrypt(&share.passphrase, address_key_armored, address_key_passphrase)?;

        self.keys.insert(
            share.metadata.share_id.clone(),
            KeyEntry {
                armored_key: share.key.clone(),
                passphrase: share_passphrase,
            },
        );
        Ok(())
    }

    /// Unlock a node key given its cryptographic material and the ID of its parent key.
    ///
    /// `parent_id` can be either a `share_id` (for the root link) or a `link_id`
    /// (for any other link) — both are looked up in the same map.
    ///
    /// # Arguments
    /// - `link_id`               — The ID under which to store the unlocked key.
    /// - `parent_id`             — ID of the key that encrypts `node_passphrase_armored`.
    /// - `node_key_armored`      — PGP-armored encrypted private key for this node.
    /// - `node_passphrase_armored` — PGP-armored passphrase for `node_key_armored`.
    pub fn unlock_with_parent(
        &mut self,
        link_id: &str,
        parent_id: &str,
        node_key_armored: &str,
        node_passphrase_armored: &str,
    ) -> Result<()> {
        let parent = self.keys.get(parent_id).ok_or_else(|| {
            Error::Crypto(format!("no key found for parent id '{parent_id}'"))
        })?;

        let node_passphrase = pgp_decrypt(
            node_passphrase_armored,
            &parent.armored_key,
            &parent.passphrase,
        )?;

        self.keys.insert(
            link_id.to_string(),
            KeyEntry {
                armored_key: node_key_armored.to_string(),
                passphrase: node_passphrase,
            },
        );
        Ok(())
    }

    // ── Access ─────────────────────────────────────────────────────────────

    /// Borrow the key material for a given ID (share_id or link_id).
    ///
    /// Returns `(armored_key, passphrase)`.
    pub fn get_key(&self, id: &str) -> Option<(&str, &[u8])> {
        self.keys
            .get(id)
            .map(|e| (e.armored_key.as_str(), e.passphrase.as_slice()))
    }

    // ── Decryption ─────────────────────────────────────────────────────────

    /// Decrypt an armored name string using the key stored under `parent_id`.
    ///
    /// `parent_id` is the `link_id` of the parent folder (or `share_id` for the
    /// root link's children if the share key was used to encrypt them directly).
    pub fn decrypt_name_raw(&self, encrypted_name: &str, parent_id: &str) -> Result<String> {
        let parent = self.keys.get(parent_id).ok_or_else(|| {
            Error::Crypto(format!("no key found for parent id '{parent_id}'"))
        })?;

        let plaintext =
            pgp_decrypt(encrypted_name, &parent.armored_key, &parent.passphrase)?;
        String::from_utf8(plaintext)
            .map_err(|e| Error::Crypto(format!("decrypted name is not valid UTF-8: {e}")))
    }

    // ── Encryption ───────────────────────────────────────────────────────────

    /// Encrypt a plaintext name string using the key stored under `parent_id`.
    ///
    /// Returns the PGP-armored ciphertext. `parent_id` must refer to a key that
    /// has been previously unlocked (a share_id or link_id).
    ///
    /// The passphrase is **not** needed for encryption — PGP encryption uses
    /// the public-key material of the secret key, which is available without
    /// unlocking.
    pub fn encrypt_name_raw(&self, plaintext_name: &str, parent_id: &str) -> Result<String> {
        let parent = self.keys.get(parent_id).ok_or_else(|| {
            Error::Crypto(format!("no key found for parent id '{parent_id}'"))
        })?;

        pgp_encrypt(plaintext_name.as_bytes(), &parent.armored_key)
    }
}

// ── Key-password derivation ────────────────────────────────────────────────

/// Derive the key password for an address key.
///
/// Uses the same bcrypt derivation as the SRP password hash, but with the
/// per-key salt returned by `GET /core/v4/keys/salts`.
///
/// # Arguments
/// - `user_password` — The user's plaintext login password.
/// - `key_salt_b64`  — Base64-encoded key salt from `/keys/salts`.
///                     If `None` or empty, `user_password` is used directly.
pub fn derive_key_password(user_password: &str, key_salt_b64: Option<&str>) -> Result<Vec<u8>> {
    match key_salt_b64 {
        Some(salt) if !salt.is_empty() => {
            hash_password(user_password, salt)
                .map_err(|e| Error::Crypto(format!("key password derivation failed: {e}")))
        }
        _ => Ok(user_password.as_bytes().to_vec()),
    }
}
