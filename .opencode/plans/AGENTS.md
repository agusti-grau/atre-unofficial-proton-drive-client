# Proton Drive Client for Linux

A native Rust client for [Proton Drive](https://proton.me/drive) — CLI + daemon + (future) GUI. Two-way sync via Unix socket IPC.

## Architecture

```
proton-drive (CLI) ─┐
                     ├─ Unix socket ── protond (daemon)
GUI (future) ────────┘     JSON Lines at $XDG_RUNTIME_DIR/protond.sock
                              Methods: ping, auth.status, drive.ls, drive.ls_decrypted, drive.sync
                           Auth · Sync · Queue · Transfer
```

Three crates in a Cargo workspace:
- **proton-core** — library: all business logic
- **proton-drive** — CLI binary
- **protond** — daemon binary

## File Map

```
Cargo.toml                     workspace root (resolver = "2")
crates/
  proton-core/
    Cargo.toml                 deps: reqwest 0.12, pgp 0.14, keyring 3, sha2 0.10, bcrypt 0.15, num-bigint 0.4
    src/lib.rs                 pub mod: api, auth, crypto, db, drive, error, ipc, keyring, local, sync (58 tests)
    src/error.rs               Error enum (thiserror): Http, Api, Auth, Srp, Keyring, Crypto, Io, Utf8
    src/keyring.rs             libsecret: save_session, load_session, delete_session (Entry)
    src/api/mod.rs             re-exports: ApiClient, Session
    src/api/client.rs          ApiClient — HTTP wrapper, all Proton API endpoints (auth + drive + addresses + upload)
    src/api/types.rs           AuthInfoResponse, AuthRequest, AuthResponse, Session, Address, KeySalt, etc.
    src/api/drive_types.rs     Volume, Share, Link, LinkType, CreateFolderReq, CreateFileReq, CreateRevisionReq, BlockEntry
    src/auth/mod.rs            login, complete_2fa, refresh_session, logout (orchestration)
    src/auth/password.rs       hash_password: bcrypt + "proton" salt suffix + $2b→$2y normalize
    src/auth/srp.rs            generate_srp_proof, expand_hash, decode_modulus, be_padded
    src/crypto/mod.rs          pgp_decrypt, pgp_encrypt, decrypt/encrypt_block, session key, keygen, signing
    src/db/mod.rs              StateDb — SQLite state: nodes (local↔remote map), meta (kv), jobs (sync queue)
    src/drive/mod.rs           DriveClient, DriveNode — tree walk (encrypted + decrypted), build_keyring
    src/drive/keyring.rs       DriveKeyring — PGP key chain: share → node → child keys
    src/ipc/mod.rs             Protocol types (IpcRequest, IpcResponse, IpcClient), socket_path()
    src/local/mod.rs           LocalClient, LocalNode — filesystem walker + SHA256 hash
    src/sync/mod.rs            SyncEngine — two-way sync: remote→local download + local→remote upload
    tests/auth_integration.rs  go-srp cross-check, live login test (#[ignore])
  proton-drive/
    Cargo.toml                 deps: clap 4 (derive), rpassword 7
    src/main.rs                CLI: auth login/logout/status, ls [-r] [--decrypt], sync, status
  protond/
    Cargo.toml                 deps: tokio 1, anyhow 1, serde_json, proton-core
    src/main.rs                UnixListener accept loop, JSON Lines dispatch per connection
    src/handler.rs             IpcHandler: dispatches ping, auth.status, drive.ls, drive.ls_decrypted
    tests/integration.rs       8 tests: start/stop daemon, test all IPC methods
```

## Key Types

| Type | File:line | Purpose |
|------|-----------|---------|
| `Session` | `api/types.rs:128` | uid + access_token + refresh_token + username |
| `ApiClient` | `api/client.rs:14` | HTTP with Proton headers, auth + drive endpoints; auto-refresh on 401 via `Mutex<Option<Session>>` |
| `verify_modulus_signature` | `crypto/mod.rs:70` | Verifies PGP signature on SRP modulus using embedded Proton public key |
| `pgp_decrypt` | `crypto/mod.rs:29` | Decrypt PGP-armored message with unlocked key |
| `decrypt_session_key` | `crypto/mod.rs:55` | Decrypt PKESK content key packet → 32-byte session key |
| `decrypt_block` | `crypto/mod.rs:97` | AES-256-CBC block decrypt, IV=SHA256(key‖index)[:16] |
| `pgp_encrypt` | `crypto/mod.rs:122` | PGP-encrypt plaintext to armored (public/secret) key |
| `pgp_encrypt_to_key` | `crypto/mod.rs:152` | PGP-encrypt to an already-parsed SignedSecretKey |
| `encrypt_block` | `crypto/mod.rs:168` | AES-256-CBC block encrypt, IV=SHA256(key‖index)[:16] |
| `generate_session_key` | `crypto/mod.rs:195` | Random 32-byte AES session key |
| `create_content_key_packet` | `crypto/mod.rs:201` | PGP-encrypt session key → base64 PKESK packet |
| `generate_node_keypair` | `crypto/mod.rs:236` | Generate RSA-2048 PGP key pair → (armored_key, passphrase) |
| `pgp_sign` | `crypto/mod.rs:288` | PGP-sign data with armored key → armored signature string |
| `generate_hash_key` | `crypto/mod.rs:330` | Generate 32 random bytes for name HMAC key |
| `compute_name_hash` | `crypto/mod.rs:340` | HMAC-SHA256(32-byte-key, plaintext_name) → hex string |
| `DriveNode` | `drive/mod.rs:38` | Flattened link: share_id, link_id, name, size, type, node_key, node_passphrase |
| `DriveClient` | `drive/mod.rs:101` | Tree walk (walk_all, walk_all_decrypted), build_keyring |
| `DriveKeyring` | `drive/keyring.rs:57` | HashMap<id, KeyEntry> — decrypt/encrypt names/passphrases via PGP chain |
| `DriveKeyring::encrypt_name_raw` | `drive/keyring.rs:170` | PGP-encrypt a plaintext name with a parent key |
| `Link` | `api/drive_types.rs:168` | Raw API node: name, hash, node_key, node_passphrase, parent_link_id |
| `Share` | `api/drive_types.rs:74` | Full share: key, passphrase, address_key_id |
| `IpcRequest` / `IpcResponse` | `ipc/mod.rs:31` | JSON Lines protocol types |
| `IpcClient` | `ipc/mod.rs:81` | Async Unix socket client: connect(), request(method, params) |
| `IpcHandler` | `protond/src/handler.rs` | Daemon request dispatcher: ping, auth.status, drive.ls, drive.ls_decrypted, drive.status, drive.sync |
| `DriveKeyring::get_key` | `drive/keyring.rs:138` | Borrow (armored_key, passphrase) for a given link/share ID |
| `StateDb` | `db/mod.rs` | SQLite state: upsert/get/list/delete for nodes, key-value meta, job queue |
| `NodeRow` / `NodeFields` | `db/mod.rs` | Sync node: local_path, link_id, share_id, name_encrypted, size, hash, state |
| `JobRow` / `JobFields` | `db/mod.rs` | Sync job: job_type, local_path, link_id, state (queued/running/done/failed) |
| `LocalNode` | `local/mod.rs:14` | path, is_file, size, modified_time, hash (SHA256) |
| `LocalClient` | `local/mod.rs:78` | walk_all() → Vec<LocalNode> |
| `SyncEngine` | `sync/mod.rs:58` | sync(password) → SyncReport: walk remote, create dirs, diff, download, upload |
| `SyncReport` | `sync/mod.rs:15` | dirs_created, downloads_attempted/succeeded, uploads_attempted/succeeded, errors |
| `RemoteEntry` | `sync/mod.rs:35` | Interim: node + decrypted name + resolved local path |
| `CreateFileReq` | `api/drive_types.rs:461` | File-create request body |
| `CreateFolderReq` | `api/drive_types.rs:440` | Folder-create request body |
| `CreateLinkRes` | `api/drive_types.rs:477` | Create-link response (ID) |
| `BlockEntry` | `api/drive_types.rs:483` | Block metadata for revision creation |
| `CreateRevisionReq` | `api/drive_types.rs:493` | Revision-create request (block list + x_attr) |
| `CreateRevisionRes` | `api/drive_types.rs:499` | Revision-create response (ID + upload URLs) |
| `BlockUploadUrl` | `api/drive_types.rs:508` | Pre-signed URL for one block upload |

## Sync Pipeline Status

| Step | Status | Component |
|------|--------|-----------|
| SRP-6a auth (login, 2FA, logout, refresh) | ✅ | `auth/` |
| Auto-retry on 401 (token refresh loop) | ✅ | `api/client.rs` |
| Session in libsecret keyring | ✅ | `keyring.rs` |
| Remote tree enumeration (walk + pagination) | ✅ | `drive/mod.rs` |
| PGP name decryption (address→share→node→child) | ✅ | `drive/keyring.rs` + `crypto/mod.rs` |
| PGP modulus signature verification | ✅ | `crypto/mod.rs` |
| Local filesystem walk + SHA256 hash | ✅ 7 tests | `local/mod.rs` |
| SQLite state DB (nodes, meta, jobs) | ✅ 13 tests | `db/mod.rs` |
| Diff engine (size+modify_time) | ✅ | `sync/mod.rs` |
| Job queue with persistence | ✅ 3 tests | `db/mod.rs` |
| Block download | ✅ | `sync/mod.rs` + `api/client.rs:download_block` |
| Block decryption (AES-256-CBC) | ✅ | `crypto/mod.rs` + `sync/mod.rs` |
| Block encryption (AES-256-CBC) | ✅ | `crypto/mod.rs` |
| Session key generation + wrapping | ✅ | `crypto/mod.rs` |
| Node PGP keypair generation | ✅ | `crypto/mod.rs` |
| PGP signing | ✅ | `crypto/mod.rs` |
| PGP name encryption | ✅ | `drive/keyring.rs:encrypt_name_raw` |
| File upload (create link → blocks → revision) | ✅ | `sync/mod.rs:upload_new_files` + `api/client.rs` |
| Upload API methods | ✅ | `api/client.rs:create_link, create_revision, upload_block, complete_revision` |
| Remote folder creation for local-only directories | ✅ | `sync/mod.rs:ensure_remote_folders` |
| `NodeHashKey` + name `Hash` computation | ✅ | `crypto/mod.rs:compute_name_hash, generate_hash_key` + `sync/mod.rs` |
| Modified-file revision upload | ✅ | `sync/mod.rs:upload_new_files` |
| protond IPC socket | ✅ | `protond/` — ping, auth.status, drive.ls, drive.ls_decrypted |
| Serialize (LinkType, LinkState, DriveNode → JSON) | ✅ | `api/drive_types.rs`, `drive/mod.rs` |
| Integration tests (daemon spawn, IPC, error paths) | ✅ 8 tests | `protond/tests/integration.rs` |
| `drive.status` IPC method + CLI output | ✅ | `protond/src/handler.rs` + `proton-drive/src/main.rs` |
| Human-friendly sync summary in CLI | ✅ | `proton-drive/src/main.rs:cmd_sync` |
| Last-sync timestamp persistence | ✅ | `sync/mod.rs:sync` → `meta.last_sync` |
| Transfer manager (rate/time limits) | 🔲 | not started |
| systemd user unit | 🔲 | not started |
| GUI app | 🔲 | not started |

## Code Conventions

- **Serde**: `#[serde(rename_all = "PascalCase")]` on API types. `#[serde(rename = "ID")]` for id fields. `#[serde(flatten)]` for Share/metadata combo.
- **Enums**: Integer enums use `From<i32>` + custom `Deserialize` → `Other(i32)` for unknown values.
- **Errors**: `thiserror` in `error.rs`. Library uses `crate::Result<T>`, binaries use `anyhow::Result<T>`.
- **Async**: tokio runtime. Recursive fns return `Pin<Box<dyn Future>>` — see `drive/mod.rs:297` for pattern.
- **Session mutability**: `ApiClient` stores session in `std::sync::Mutex<Option<Session>>` — lock, clone, drop pattern avoids holding locks across `.await`.
- **401 retry**: `authed_get` detects `StatusCode::UNAUTHORIZED`, calls `refresh_and_update_session()`, persists to keyring, and retries once.
- **Modules**: `pub mod` in `lib.rs`, sub-modules re-export key types with `pub use`.
- **Tests**: `#[cfg(test)] mod tests` inline for units, `tests/` dir for integration.
- **IPC protocol**: JSON Lines over Unix socket at `$XDG_RUNTIME_DIR/protond.sock`. Request: `{"id":u64,"method":"str","params":{…}}`. Response: `{"id":u64,"result":…}` or `{"id":u64,"error":{"code":i32,"message":"str"}}`.
- **keyring async**: Uses `std::thread::spawn` + `oneshot` channel instead of `spawn_blocking` because zbus (keyring backend) panics if a tokio runtime is detected on the current thread.
- **Send bounds**: Drive's recursive decrypted walk (`walk_decrypted_inner`) returns `Pin<Box<dyn Future + Send>>` and requires `F: FnMut + Send` so the future can be spawned with `tokio::spawn`.
- **Dependencies**: Shared workspace deps in root `Cargo.toml` workspace.dependencies.

## Build & Test

```bash
cargo check                           # type-check all crates
cargo test                            # 58 tests (46 unit + 3 auth integration + 8 protond integration + 1 doc-test)
PROTON_USER=u PROTON_PASS=p \
  cargo test --test auth_integration -- --ignored   # live test
```

## Known Issues

- Auth version < 4 rejected (legacy password schemes not supported)
- `ApiClient::new()` creates new reqwest `Client` each time — inefficient; should reuse
- `drive.ls_decrypted` non-recursive mode only supports root folder (no arbitrary folder_id arg yet)
- Block IV derivation is a best-guess from Proton Go client; verify against real data before production use
- Block `enc_signature` and `enc_sha256` are downloaded but not verified yet
- Block manifest signature is missing

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| reqwest | 0.12 | HTTP (rustls-tls, no OpenSSL) |
| pgp (rpgp) | 0.14 | OpenPGP decrypt |
| keyring | 3 | libsecret session store |
| clap | 4 | CLI derive args |
| sha2 | 0.10 | SHA-512 for expand_hash |
| bcrypt | 0.15 | Password stretching |
| num-bigint | 0.4 | SRP big-int math |
| serde/serde_json | 1 | JSON serde |
| tokio | 1 | Async runtime |
| thiserror | 2 | Error derive |
| rusqlite | 0.31 | SQLite state DB (bundled) |
| smallvec | 1 | Inline small vectors (pgp builder API) |
| hex | 0.4 | Hex encoding for key passphrases |
| hmac | 0.12 | HMAC-SHA256 for name hash computation |
