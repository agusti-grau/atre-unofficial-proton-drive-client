//! End-to-end integration tests using wiremock to simulate the Proton API.
//!
//! These tests verify that the API client and sync engine correctly handle
//! HTTP request/response cycles without needing a real Proton server.
//! They use [`wiremock::MockServer`] to provide controlled JSON responses
//! matching the Proton API format.

use std::path::PathBuf;
use std::sync::Arc;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use proton_core::api::drive_types::{
    BlockEntry, CreateFolderReq, CreateRevisionReq, LinkState, LinkType,
};
use proton_core::api::{ApiClient, Session};
use proton_core::crypto::{
    create_content_key_packet, encrypt_block, generate_node_keypair, generate_session_key,
    pgp_encrypt,
};
use proton_core::db::StateDb;
use proton_core::drive::keyring::DriveKeyring;
use proton_core::drive::DriveNode;
use proton_core::sync::SyncEngine;

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Create a minimal `ApiClient` pointing at the mock server with a test session.
fn mock_client(uri: &str) -> ApiClient {
    let session = Session {
        uid: "test-uid-001".into(),
        access_token: "test-access-token".into(),
        refresh_token: "test-refresh-token".into(),
        username: "e2e-test-user".into(),
    };
    ApiClient::with_base_url(uri)
        .expect("ApiClient::with_base_url")
        .with_session(session)
}

// ── Test: Auth Info ─────────────────────────────────────────────────────────

/// Verify that `ApiClient::get_auth_info` correctly parses a mock SRP-info
/// response.
#[tokio::test]
async fn mock_api_auth_info_returns_valid_params() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/auth/v4/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000,
            "Modulus": "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nwyIECQM...",
            "ServerEphemeral": "w+4BcD3Xk8R5...",
            "Version": 4,
            "Salt": "dGhpcyBpcyBhIHNhbHQ=",
            "SrpSession": "mock-srp-session-42"
        })))
        .mount(&mock_server)
        .await;

    let client = ApiClient::with_base_url(&mock_server.uri()).expect("ApiClient::with_base_url");
    let info = client
        .get_auth_info("testuser")
        .await
        .expect("get_auth_info");

    assert_eq!(info.code, 1000, "API response code must be 1000");
    assert_eq!(info.version, 4, "auth version must be 4");
    assert_eq!(info.srp_session, "mock-srp-session-42");
    assert!(!info.modulus.is_empty(), "modulus must be present");
    assert!(
        !info.server_ephemeral.is_empty(),
        "server ephemeral must be present"
    );
    assert!(!info.salt.is_empty(), "salt must be present");
}

// ── Test: Create folder ─────────────────────────────────────────────────────

/// Verify that `ApiClient::create_link` correctly creates a folder via the
/// mock API.
#[tokio::test]
async fn mock_api_create_folder() {
    let mock_server = MockServer::start().await;

    let share_id = "share-folder-test-001";
    let expected_link_id = "new-folder-link-abc123";

    Mock::given(method("POST"))
        .and(path(&format!("/drive/shares/{share_id}/links")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000,
            "ID": expected_link_id
        })))
        .mount(&mock_server)
        .await;

    let client = mock_client(&mock_server.uri());

    let req = CreateFolderReq {
        parent_link_id: "parent-root-000".into(),
        name: "-----BEGIN PGP MESSAGE-----\nencrypted-name".into(),
        hash: "aabbccddee".into(),
        node_key: "-----BEGIN PGP PRIVATE KEY BLOCK-----\nkey-material".into(),
        node_hash_key: "-----BEGIN PGP MESSAGE-----\nhash-key".into(),
        node_passphrase: "-----BEGIN PGP MESSAGE-----\nencrypted-passphrase".into(),
        node_passphrase_signature: "-----BEGIN PGP SIGNATURE-----\nsignature".into(),
        signature_address: "testuser@proton.me".into(),
    };

    let created_id = client
        .create_link(share_id, &req)
        .await
        .expect("create_link");
    assert_eq!(created_id, expected_link_id, "returned link ID must match");
}

// ── Test: SyncEngine download ───────────────────────────────────────────────

/// Verify `SyncEngine::download_file` end-to-end with a mock API server and
/// real cryptographic operations.
///
/// Generates a real PGP node key, encrypts test plaintext with a session key,
/// and wires the mock to return the corresponding encrypted blocks.  The test
/// then decrypts via `download_file` and asserts the output matches the original.
#[tokio::test]
async fn mock_sync_engine_download() {
    let mock_server = MockServer::start().await;
    let tmpdir = std::env::temp_dir().join("proton-e2e-dl-test");
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).expect("create tmpdir");
    let db_dir = tmpdir.join("db");
    let download_dir = tmpdir.join("download");

    // ── Generate crypto material ───────────────────────────────────────────
    // Key hierarchy: address key → share key → node key.
    let share_id = "share-dl-001";
    let root_link_id = "root-link-dl-001";
    let node_link_id = "file-link-dl-001";
    let revision_id = "rev-dl-001";

    // Address key (mimics the user's address key)
    let (addr_key_armored, addr_raw_pass) = generate_node_keypair().unwrap();
    let addr_pass_hex = hex::encode(&addr_raw_pass);

    // Share key (mimics the share private key)
    let (share_key_armored, share_raw_pass) = generate_node_keypair().unwrap();
    let share_pass_hex = hex::encode(&share_raw_pass);

    // Node key (the file's own node key)
    let (node_key_armored, node_raw_pass) = generate_node_keypair().unwrap();
    let node_pass_hex = hex::encode(&node_raw_pass);

    // Session key + test data
    let plaintext = b"Hello from the Proton Drive mock E2E test!";
    let session_key = generate_session_key();

    // Encrypt the plaintext block
    let encrypted_block = encrypt_block(plaintext, &session_key, 0).unwrap();

    // Create a content key packet by encrypting the session key with the node key
    let content_key_packet = create_content_key_packet(&session_key, &node_key_armored).unwrap();

    // ── Set up the DriveKeyring ────────────────────────────────────────────
    // Build a minimal Share to bootstrap the keyring.
    let encrypted_share_pass = pgp_encrypt(share_pass_hex.as_bytes(), &addr_key_armored).unwrap();

    let share = proton_core::api::drive_types::Share {
        metadata: proton_core::api::drive_types::ShareMetadata {
            share_id: share_id.to_string(),
            link_id: root_link_id.to_string(),
            volume_id: "vol-001".into(),
            share_type: proton_core::api::drive_types::ShareType::Main,
            state: proton_core::api::drive_types::ShareState::Active,
            flags: proton_core::api::drive_types::ShareFlags::Primary,
            creator: "e2e-test".into(),
            locked: false,
        },
        address_id: "addr-001".into(),
        address_key_id: "addr-key-001".into(),
        key: share_key_armored.clone(),
        passphrase: encrypted_share_pass,
        passphrase_signature: String::new(),
    };

    let mut kr = DriveKeyring::new();
    kr.init_share(&share, &addr_key_armored, addr_pass_hex.as_bytes())
        .expect("init_share");

    // Unlock the node key with the share key as parent.
    let encrypted_node_pass = pgp_encrypt(node_pass_hex.as_bytes(), &share_key_armored).unwrap();
    kr.unlock_with_parent(
        node_link_id,
        share_id,
        &node_key_armored,
        &encrypted_node_pass,
    )
    .expect("unlock node key");

    // ── Register mock endpoints ────────────────────────────────────────────

    // 1. GET /drive/shares/{share_id}/links/{node_link_id} — link metadata
    let link_response = serde_json::json!({
        "Code": 1000,
        "Link": {
            "LinkId": node_link_id,
            "ParentLinkId": root_link_id,
            "Type": 2,
            "Name": "-----BEGIN PGP MESSAGE-----\nencrypted-name",
            "Hash": "mock-hash",
            "Size": plaintext.len() as i64,
            "State": 1,
            "MimeType": "text/plain",
            "CreateTime": 1717000000,
            "ModifyTime": 1717000000,
            "NodeKey": node_key_armored,
            "NodePassphrase": encrypted_node_pass,
            "NodePassphraseSignature": "",
            "FileProperties": {
                "ContentKeyPacket": content_key_packet,
                "ContentKeyPacketSignature": "",
                "ActiveRevision": {
                    "ID": revision_id,
                    "CreateTime": 1717000000,
                    "Size": encrypted_block.len() as i64,
                    "State": 1
                }
            },
            "FolderProperties": null
        }
    });

    let link_path = format!("/drive/shares/{share_id}/links/{node_link_id}");
    Mock::given(method("GET"))
        .and(path(&link_path))
        .respond_with(ResponseTemplate::new(200).set_body_json(link_response))
        .mount(&mock_server)
        .await;

    // 2. GET /drive/shares/{share_id}/links/{node_link_id}/revisions/{revision_id}
    //    — revision with block list
    let block_url = format!("{}/blocks/test-block-0", mock_server.uri());
    let revision_response = serde_json::json!({
        "Code": 1000,
        "Revision": {
            "ID": revision_id,
            "CreateTime": 1717000000,
            "Size": encrypted_block.len() as i64,
            "State": 1,
            "ManifestSignature": "",
            "SignatureAddress": "test@proton.me",
            "XAttr": "{}",
            "Blocks": [
                {
                    "Index": 0,
                    "Size": encrypted_block.len() as u64,
                    "EncSignature": "",
                    "Hash": "block-hash-0",
                    "Url": block_url,
                    "EncSha256": ""
                }
            ]
        }
    });

    let rev_path = format!("/drive/shares/{share_id}/links/{node_link_id}/revisions/{revision_id}");
    Mock::given(method("GET"))
        .and(path(&rev_path))
        .respond_with(ResponseTemplate::new(200).set_body_json(revision_response))
        .mount(&mock_server)
        .await;

    // 3. GET {block_url} — raw encrypted block data
    Mock::given(method("GET"))
        .and(path("/blocks/test-block-0"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(encrypted_block.clone()))
        .mount(&mock_server)
        .await;

    // ── Build SyncEngine ───────────────────────────────────────────────────
    let api = mock_client(&mock_server.uri());
    let db = Arc::new(StateDb::open(&db_dir).expect("StateDb::open"));

    // Pre-create the download directory
    std::fs::create_dir_all(&download_dir).expect("create download dir");

    let mut engine = SyncEngine::new(api, db, download_dir.clone());

    // Construct a DriveNode representing the remote file.
    let node = DriveNode {
        share_id: share_id.to_string(),
        link_id: node_link_id.to_string(),
        parent_link_id: Some(root_link_id.to_string()),
        link_type: LinkType::File,
        encrypted_name: "mock-encrypted-name".into(),
        hash: "mock-hash".into(),
        size: plaintext.len() as i64,
        state: LinkState::Active,
        mime_type: "text/plain".into(),
        create_time: 1717000000,
        modify_time: 1717000000,
        node_key: node_key_armored,
        node_passphrase: encrypted_node_pass,
        node_hash_key: String::new(),
    };

    let local_rel_path = PathBuf::from("downloaded-test-file.txt");

    engine
        .download_file(&node, &local_rel_path, &kr)
        .await
        .expect("download_file should succeed");

    // ── Verify the decrypted output ────────────────────────────────────────
    let output_path = download_dir.join(&local_rel_path);
    let output_bytes = tokio::fs::read(&output_path)
        .await
        .expect("read downloaded file");
    assert_eq!(
        output_bytes, plaintext,
        "downloaded and decrypted file must match original plaintext"
    );
}

// ── Test: Upload flow (API level) ───────────────────────────────────────────

/// Verify the upload-related API methods that `SyncEngine` uses internally:
/// `create_revision`, `upload_block`, and `complete_revision`.
///
/// This test confirms the HTTP integration works correctly for the upload
/// code path without needing the full crypto walk.
#[tokio::test]
async fn mock_sync_engine_upload() {
    let mock_server = MockServer::start().await;

    let share_id = "share-upload-001";
    let link_id = "link-upload-001";
    let revision_id = "rev-upload-001";

    // ── 1. Create revision ─────────────────────────────────────────────────

    // Pre-signed upload URL that points back to the mock server.
    let block_upload_url = format!("{}/blocks/upload-block-0", mock_server.uri());

    Mock::given(method("POST"))
        .and(path(&format!(
            "/drive/shares/{share_id}/links/{link_id}/revisions"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": revision_id,
                "BlockList": [
                    {
                        "Index": 0,
                        "Url": block_upload_url
                    }
                ]
            }
        })))
        .mount(&mock_server)
        .await;

    let client = mock_client(&mock_server.uri());

    let create_req = CreateRevisionReq {
        block_list: vec![BlockEntry {
            hash: "test-plaintext-hash".into(),
            enc_signature: "test-signature".into(),
            size: 13,
            index: 0,
        }],
        manifest_signature: "".into(),
        signature_address: "test@proton.me".into(),
        x_attr: r#"{"contentKeyPacket":"test","contentKeyPacketSignature":"test"}"#.into(),
    };

    let rev = client
        .create_revision(share_id, link_id, &create_req)
        .await
        .expect("create_revision should succeed");

    assert_eq!(rev.id, revision_id);
    assert_eq!(rev.block_list.len(), 1);
    assert_eq!(rev.block_list[0].index, 0);
    assert!(
        !rev.block_list[0].url.is_empty(),
        "upload URL must be present"
    );

    // ── 2. Upload block (PUT pre-signed URL) ───────────────────────────────

    let block_data = b"encrypted-block-data";
    Mock::given(method("PUT"))
        .and(path("/blocks/upload-block-0"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    client
        .upload_block(&rev.block_list[0].url, block_data)
        .await
        .expect("upload_block should succeed");

    // ── 3. Complete revision (mark as active) ──────────────────────────────

    Mock::given(method("PUT"))
        .and(path(&format!(
            "/drive/shares/{share_id}/links/{link_id}/revisions/{revision_id}/state"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "code": 1000
        })))
        .mount(&mock_server)
        .await;

    client
        .complete_revision(share_id, link_id, revision_id)
        .await
        .expect("complete_revision should succeed");

    // All three upload steps completed successfully.
}
