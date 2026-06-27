//! Proton Drive API response and request types.
//!
//! Field names use `PascalCase` to match the Proton API's JSON convention.
//! Integer enums (State, Type, Flags) use `#[serde(from = "i32")]` so unknown
//! values are safely preserved instead of causing a parse error.

use serde::{Deserialize, Serialize};

// ── Volume ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Volume {
    pub volume_id: String,
    pub state: VolumeState,
    /// The default share / root of this volume.
    pub share: VolumeShare,
    pub max_space: Option<i64>,
    pub used_space: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VolumeShare {
    pub share_id: String,
    /// LinkID of the root folder.
    pub link_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeState {
    Active,
    Locked,
    Other(i32),
}

impl From<i32> for VolumeState {
    fn from(n: i32) -> Self {
        match n {
            1 => Self::Active,
            3 => Self::Locked,
            other => Self::Other(other),
        }
    }
}

impl<'de> Deserialize<'de> for VolumeState {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(i32::deserialize(d)?))
    }
}

impl Serialize for VolumeState {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let n: i32 = match self {
            Self::Active => 1,
            Self::Locked => 3,
            Self::Other(n) => *n,
        };
        s.serialize_i32(n)
    }
}

// ── Share ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ShareMetadata {
    pub share_id: String,
    /// LinkID of the share's root folder.
    pub link_id: String,
    pub volume_id: String,
    #[serde(rename = "Type")]
    pub share_type: ShareType,
    pub state: ShareState,
    pub flags: ShareFlags,
    pub creator: String,
    pub locked: bool,
}

/// Full share including the encrypted share key and passphrase.
/// Used to derive the keyring for decrypting link names.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Share {
    #[serde(flatten)]
    pub metadata: ShareMetadata,

    pub address_id: String,
    pub address_key_id: String,

    /// PGP-armored encrypted share private key.
    pub key: String,
    /// PGP-armored passphrase (encrypted with the address key).
    pub passphrase: String,
    /// PGP-armored signature of the passphrase.
    pub passphrase_signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareType {
    Main,
    Standard,
    Device,
    Other(i32),
}

impl From<i32> for ShareType {
    fn from(n: i32) -> Self {
        match n {
            1 => Self::Main,
            2 => Self::Standard,
            3 => Self::Device,
            other => Self::Other(other),
        }
    }
}

impl<'de> Deserialize<'de> for ShareType {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(i32::deserialize(d)?))
    }
}

impl Serialize for ShareType {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let n: i32 = match self {
            Self::Main => 1,
            Self::Standard => 2,
            Self::Device => 3,
            Self::Other(n) => *n,
        };
        s.serialize_i32(n)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareState {
    Active,
    Deleted,
    Other(i32),
}

impl From<i32> for ShareState {
    fn from(n: i32) -> Self {
        match n {
            1 => Self::Active,
            2 => Self::Deleted,
            other => Self::Other(other),
        }
    }
}

impl<'de> Deserialize<'de> for ShareState {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(i32::deserialize(d)?))
    }
}

impl Serialize for ShareState {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let n: i32 = match self {
            Self::Active => 1,
            Self::Deleted => 2,
            Self::Other(n) => *n,
        };
        s.serialize_i32(n)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareFlags {
    None,
    Primary,
    Other(i32),
}

impl From<i32> for ShareFlags {
    fn from(n: i32) -> Self {
        match n {
            0 => Self::None,
            1 => Self::Primary,
            other => Self::Other(other),
        }
    }
}

impl<'de> Deserialize<'de> for ShareFlags {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(i32::deserialize(d)?))
    }
}

impl Serialize for ShareFlags {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let n: i32 = match self {
            Self::None => 0,
            Self::Primary => 1,
            Self::Other(n) => *n,
        };
        s.serialize_i32(n)
    }
}

// ── Link (file / folder node) ──────────────────────────────────────────────

/// A node in the Proton Drive tree.  Represents both files and folders.
///
/// File and folder names are PGP-encrypted; use the drive crypto module to
/// decrypt them with the parent folder's node keyring.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Link {
    pub link_id: String,
    /// `None` only for the root link of a share.
    pub parent_link_id: Option<String>,

    #[serde(rename = "Type")]
    pub link_type: LinkType,

    /// PGP-armored encrypted file/folder name.
    /// Decrypt with the *parent* folder's node keyring.
    pub name: String,

    /// HMAC of the name (for collision detection).
    pub hash: String,

    /// File size in bytes.  0 for folders.
    pub size: i64,
    pub state: LinkState,
    pub mime_type: String,

    pub create_time: i64,
    pub modify_time: i64,

    /// PGP-armored encrypted private node key.
    pub node_key: String,
    /// PGP-armored passphrase for the node key (encrypted with parent's node key).
    pub node_passphrase: String,
    /// PGP-armored signature of the node passphrase.
    pub node_passphrase_signature: String,

    pub file_properties: Option<FileProperties>,
    pub folder_properties: Option<FolderProperties>,
}

impl Link {
    pub fn is_folder(&self) -> bool {
        self.link_type == LinkType::Folder
    }

    pub fn is_file(&self) -> bool {
        self.link_type == LinkType::File
    }

    pub fn is_active(&self) -> bool {
        self.state == LinkState::Active
            && (self.link_type == LinkType::Folder || self.link_type == LinkType::File)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FileProperties {
    /// Base64-encoded key packet (encrypted with the node key).
    pub content_key_packet: String,
    /// PGP-armored signature of the content key packet.
    pub content_key_packet_signature: String,
    pub active_revision: RevisionMetadata,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FolderProperties {
    /// PGP-armored HMAC key used to hash child names.
    pub node_hash_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RevisionMetadata {
    #[serde(rename = "ID")]
    pub id: String,
    pub create_time: i64,
    pub size: i64,
    pub state: RevisionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Folder,
    File,
    Other(i32),
}

impl From<i32> for LinkType {
    fn from(n: i32) -> Self {
        match n {
            1 => Self::Folder,
            2 => Self::File,
            other => Self::Other(other),
        }
    }
}

impl<'de> Deserialize<'de> for LinkType {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(i32::deserialize(d)?))
    }
}

impl Serialize for LinkType {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let tag = match self {
            Self::Folder => "folder",
            Self::File => "file",
            Self::Other(n) => return s.serialize_i32(*n),
        };
        s.serialize_str(tag)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Draft,
    Active,
    Trashed,
    Deleted,
    Restoring,
    Other(i32),
}

impl From<i32> for LinkState {
    fn from(n: i32) -> Self {
        match n {
            0 => Self::Draft,
            1 => Self::Active,
            2 => Self::Trashed,
            3 => Self::Deleted,
            4 => Self::Restoring,
            other => Self::Other(other),
        }
    }
}

impl<'de> Deserialize<'de> for LinkState {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(i32::deserialize(d)?))
    }
}

impl Serialize for LinkState {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let tag = match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Trashed => "trashed",
            Self::Deleted => "deleted",
            Self::Restoring => "restoring",
            Self::Other(n) => return s.serialize_i32(*n),
        };
        s.serialize_str(tag)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevisionState {
    Draft,
    Active,
    Obsolete,
    Deleted,
    Other(i32),
}

impl From<i32> for RevisionState {
    fn from(n: i32) -> Self {
        match n {
            0 => Self::Draft,
            1 => Self::Active,
            2 => Self::Obsolete,
            3 => Self::Deleted,
            other => Self::Other(other),
        }
    }
}

impl<'de> Deserialize<'de> for RevisionState {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(i32::deserialize(d)?))
    }
}

impl Serialize for RevisionState {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let tag = match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Obsolete => "obsolete",
            Self::Deleted => "deleted",
            Self::Other(n) => return s.serialize_i32(*n),
        };
        s.serialize_str(tag)
    }
}

// ── Revision (file content) ───────────────────────────────────────────────

/// A single revision of a file, returned by `GET .../revisions/{id}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Revision {
    #[serde(rename = "ID")]
    pub id: String,
    pub create_time: i64,
    pub size: i64,
    pub state: RevisionState,
    pub manifest_signature: String,
    pub signature_address: String,
    pub x_attr: String,
    pub blocks: Vec<Block>,
}

/// One encrypted block within a revision.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Block {
    pub index: u32,
    pub size: u64,
    pub enc_signature: String,
    pub hash: String,
    /// Pre-signed download URL for this block.
    pub url: String,
    pub enc_sha256: String,
}

// ── Folder-create request ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateFolderReq {
    pub parent_link_id: String,
    pub name: String,
    pub hash: String,
    pub node_key: String,
    pub node_hash_key: String,
    pub node_passphrase: String,
    pub node_passphrase_signature: String,
    pub signature_address: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateFolderRes {
    #[serde(rename = "ID")]
    pub id: String,
}

// ── File-create request ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateFileReq {
    #[serde(rename = "ParentLinkID")]
    pub parent_link_id: String,
    #[serde(rename = "NodeHashKey")]
    pub node_hash_key: String,
    pub name: String,
    pub hash: String,
    #[serde(rename = "NodeKey")]
    pub node_key: String,
    #[serde(rename = "NodePassphrase")]
    pub node_passphrase: String,
    #[serde(rename = "NodePassphraseSignature")]
    pub node_passphrase_signature: String,
    #[serde(rename = "SignatureAddress")]
    pub signature_address: String,
    #[serde(rename = "MIMEType")]
    pub mime_type: String,
    pub size: i64,
}

// ── Create-link response ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateLinkRes {
    #[serde(rename = "ID")]
    pub id: String,
}

// ── Block-list entry for revision creation ─────────────────────────────────

#[derive(Debug, Serialize)]
pub struct BlockEntry {
    /// SHA-256 hash of the **plaintext** block.
    pub hash: String,
    /// PGP signature of the block plaintext, armored.
    pub enc_signature: String,
    /// Size of the **plaintext** block.
    pub size: u64,
    /// 0-based index.
    pub index: u32,
}

// ── Create-revision request / response ─────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateRevisionReq {
    #[serde(rename = "BlockList")]
    pub block_list: Vec<BlockEntry>,
    pub manifest_signature: String,
    pub signature_address: String,
    #[serde(rename = "XAttr")]
    pub x_attr: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateRevisionRes {
    #[serde(rename = "ID")]
    pub id: String,
    /// Pre-signed upload URLs for each block, in order.
    #[serde(rename = "BlockList")]
    pub block_list: Vec<BlockUploadUrl>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BlockUploadUrl {
    pub index: u32,
    /// Pre-signed URL to PUT the encrypted block data.
    pub url: String,
}

// ── Rename link request ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RenameLinkReq {
    /// PGP-armored encrypted name (encrypted with parent key).
    pub name: String,
    /// Address used for the signature.
    pub signature_address: String,
}

// ── Revision-state request (complete / activate) ───────────────────────────

#[derive(Debug, Serialize)]
pub struct UpdateRevisionStateReq {
    pub state: i32,
}
