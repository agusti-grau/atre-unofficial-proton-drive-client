# Programming Diary — Proton Drive Client for Linux Mint

---

## Session 1 — 2026-03-14

### Overview

First session. Went from blank repository to a working scaffolding with a full authentication pipeline.

---

### 1. Project definition

Decided to build an unofficial Proton Drive client for Linux Mint.

**Key decisions made:**

| Topic | Decision |
|-------|----------|
| Platform | Linux Mint 21+ (Ubuntu 22.04 base) |
| Language | Rust |
| Client type | GUI desktop app + CLI + background daemon |
| IPC | Unix domain socket (`$XDG_RUNTIME_DIR/protond.sock`) |
| Authentication | SRP-6a (Proton's protocol — see note below) |
| Conflict resolution | Ask the user (manual per-file resolution) |
| Bandwidth control | Rate cap (KB/s) + time-window scheduling |

> **OAuth note:** The original plan mentioned browser-based OAuth, but research confirmed that Proton's API uses a custom SRP-6a protocol for all third-party clients. There is no public OAuth 2.0 endpoint. Authentication is done entirely via the SRP exchange.

---

### 2. Architecture design

Three binaries communicating over a Unix socket:

```
┌───────────────┐     ┌───────────────┐
│  GUI Desktop  │     │   CLI client  │
│     App       │     │ proton-drive  │
└───────┬───────┘     └───────┬───────┘
        │   Unix socket IPC   │
        └──────────┬──────────┘
                   │
         ┌─────────▼─────────┐
         │   protond (daemon) │
         │  Auth · Sync · Queue · Transfer  │
         └───────────────────┘
```

**Sync pipeline order:**
1. Authenticate (SRP → tokens → keyring)
2. Connect to Proton Drive API
3. Enumerate remote files (decrypt metadata)
4. Enumerate local files (walk + hash)
5. Diff against last-known state (SQLite)
6. Pause conflicts → notify user
7. Build prioritised job queue (persist to SQLite)
8. Transfer with rate limiting + time-window scheduling

**Storage layout decided:**
```
~/.config/proton-drive/config.toml
~/.local/share/proton-drive/state.db   (SQLite)
$XDG_RUNTIME_DIR/protond.sock
$XDG_RUNTIME_DIR/protond.pid
```
Credentials stored exclusively in the system keyring (libsecret).

---

### 3. README written

Created `README.md` with:
- Project description and status badge
- Full architecture diagram (ASCII)
- Sync pipeline table
- IPC protocol description
- Storage layout
- Build from source instructions
- Roadmap checklist

---

### 4. Authentication module implemented

#### Research findings

- Proton uses **SRP-6a** (RFC 5054 variant) for all account authentication.
- The API endpoint is `POST /auth/v4/info` → `POST /auth/v4`.
- All big-integer SRP values are transmitted as **big-endian** base64 bytes.
- The 2048-bit prime modulus N is served **PGP-signed** from the API.
- Password is stretched with **bcrypt** (cost 10) before entering SRP.
- Reference implementations studied: `go-srp`, `proton-python-client`, `proton-api-rs` (archived).

#### Files created

```
Cargo.toml                              workspace (resolver = "2")
crates/
  proton-core/
    Cargo.toml
    src/
      lib.rs
      error.rs                          Error enum
      api/
        mod.rs
        types.rs                        AuthInfoResponse, AuthRequest, AuthResponse,
                                        TwoFactorInfo, TwoFactorRequest,
                                        RefreshRequest, Session
        client.rs                       ApiClient — HTTP wrapper around Proton API
      auth/
        mod.rs                          login(), complete_2fa(), refresh_session(), logout()
        password.rs                     bcrypt key derivation
        srp.rs                          SRP-6a math
      keyring.rs                        libsecret save/load/delete session
  protond/
    Cargo.toml
    src/main.rs                         daemon skeleton
  proton-drive/
    Cargo.toml
    src/main.rs                         CLI: auth login / logout / status
```

#### Authentication flow implemented

```
proton-drive auth login
        │
        ├─ prompt username + password (rpassword — hidden input)
        │
        ├─ GET /auth/v4/info
        │       └─ returns: modulus (PGP-signed N), server_ephemeral (B),
        │                   salt, srp_session, version
        │
        ├─ bcrypt(password, salt+"proton", cost=10) → full 60-byte string → bcrypt_output
        │
        ├─ SRP-6a computation
        │       k  = expand_hash(g_padded ‖ N_padded)
        │       a  = random 256-bit secret
        │       A  = g^a mod N
        │       u  = expand_hash(A_padded ‖ B_padded)
        │       x  = expand_hash(bcrypt_output ‖ modulus_bytes)
        │       S  = (B − k·g^x)^(a + u·x) mod N
        │       K  = expand_hash(S_padded)
        │       M1 = expand_hash(A_padded ‖ B_padded ‖ K)
        │       M2_expected = expand_hash(A_padded ‖ M1 ‖ K)
        │
        ├─ POST /auth/v4 → { ClientEphemeral: A, ClientProof: M1, SRPSession }
        │       └─ returns: uid, access_token, refresh_token, server_proof (M2)
        │
        ├─ verify server_proof == M2_expected   ← mutual authentication
        │
        ├─ if 2FA enabled → prompt TOTP → POST /auth/v4/2fa
        │
        └─ save Session { uid, access_token, refresh_token, username }
               to system keyring via libsecret
```

#### Key dependencies

| Crate | Purpose |
|-------|---------|
| `reqwest` 0.12 | HTTP client (rustls, no OpenSSL) |
| `sha2` 0.10 | SHA-512 for SRP hashing |
| `bcrypt` 0.15 | Password stretching |
| `num-bigint` 0.4 | Arbitrary-precision integers for SRP |
| `rand` 0.8 | Random client ephemeral |
| `base64` 0.22 | Encode/decode SRP wire values |
| `keyring` 3 | libsecret / GNOME Keyring / KWallet |
| `clap` 4 | CLI argument parsing |
| `rpassword` 7 | Hidden password prompt |
| `thiserror` 2 | Error type derivation |

---

### 5. Known limitations / TODOs at end of session

- [ ] PGP signature on the modulus is parsed but **not verified** against Proton's public key.
- [ ] Auth version < 4 is rejected; older accounts using legacy password schemes not supported.
- [ ] Token refresh on expiry is implemented but not wired into an automatic retry loop.
- [ ] `protond` daemon is a skeleton only — no IPC socket, no sync engine yet.
- [ ] No unit tests yet for SRP math or bcrypt derivation.
- [ ] Rust is not yet installed on the development machine — build not verified.

---

## Session 2 — 2026-03-14

### Goal: unit tests for `srp.rs` using go-srp test vectors

### Research findings (go-srp source)

Studying `ProtonMail/go-srp` revealed that the Session 1 SRP implementation had several errors.

| Component | Session 1 (wrong) | Session 2 (corrected) |
|-----------|-------------------|----------------------|
| Hash function | SHA-512 (64 bytes) | `expand_hash` = 4× SHA-512 (256 bytes) |
| Endianness | Little-endian | **Big-endian** |
| x (password key) | `H(salt ‖ H(user:pass))` | `expand_hash(bcrypt_output ‖ modulus_bytes)` |
| Session key K | `SHA-512(S)` | `expand_hash(S_padded)` — 256 bytes |
| M1 (client proof) | RFC 2945 formula | `expand_hash(A ‖ B ‖ K)` |
| M2 (server proof) | `H(A ‖ M1 ‖ K)` | `expand_hash(A ‖ M1 ‖ K)` |
| password.rs return | Stripped 31-char hash | Full 60-byte bcrypt string |

#### `expand_hash` — the core hash primitive

```
expand_hash(data) = SHA512(data‖0x00) ‖ SHA512(data‖0x01) ‖ SHA512(data‖0x02) ‖ SHA512(data‖0x03)
                  = 256 bytes total
```

#### Note on bcrypt "proton" salt suffix (initial — later revised in Session 3)

Session 2 analysis concluded the `"proton"` suffix was a no-op because bcrypt decodes the
base64 salt back to 16 bytes and the extra bits fall below the precision boundary.
**This analysis was wrong** — see Session 3 for the correction.

### Files changed

| File | Change |
|------|--------|
| `src/auth/srp.rs` | Full rewrite: `expand_hash`, big-endian, corrected M1/M2/x/k formulas |
| `src/auth/password.rs` | Returns full 60-byte bcrypt string bytes (not stripped hash) |
| `src/auth/mod.rs` | Updated call: passes `bcrypt_output` + `modulus_bytes` to `srp::generate_srp_proof` |

### Tests written

#### Inline unit tests in `srp.rs`

| Test | What it verifies |
|------|-----------------|
| `expand_hash_output_is_256_bytes` | Output length |
| `expand_hash_first_64_bytes_match_sha512_with_suffix_0` | Correct SHA-512 with suffix 0 |
| `expand_hash_last_64_bytes_match_sha512_with_suffix_3` | Correct SHA-512 with suffix 3 |
| `expand_hash_is_deterministic` | Same input → same output |
| `expand_hash_differs_for_different_inputs` | Collision resistance |
| `be_padded_pads_short_value` | Left zero-padding |
| `be_padded_exact_length_unchanged` | No change when already correct size |
| `srp_client_and_server_share_same_secret_p23` | S_client == S_server (safe prime 23) |
| `srp_client_and_server_share_same_secret_p47` | S_client == S_server (safe prime 47) |
| `decode_modulus_strips_pgp_wrapper` | PGP envelope parsing |
| `decode_modulus_plain_base64` | Plain base64 fallback |
| `generate_srp_proof_returns_valid_structure` | M1/M2 are 256-byte, non-empty |

#### Inline unit tests in `password.rs`

| Test | What it verifies |
|------|-----------------|
| `hash_password_returns_60_bytes` | Output length |
| `hash_password_starts_with_bcrypt_prefix` | `$2b$10$` or `$2y$10$` prefix |
| `hash_password_is_deterministic` | Reproducible |
| `hash_password_differs_for_different_passwords` | Password sensitivity |
| `hash_password_differs_for_different_salts` | Salt sensitivity |
| `hash_password_rejects_wrong_salt_length` | 8-byte salt rejected |
| `hash_password_rejects_invalid_base64` | Bad base64 rejected |

#### Integration tests in `tests/auth_integration.rs`

| Test | What it verifies |
|------|-----------------|
| `expand_hash_matches_go_srp_definition` | Cross-check against go-srp's formula |
| `hash_password_shape_for_gostrp_credentials` | Shape with actual go-srp test credentials |
| `srp_proof_structure_with_gostrp_inputs` | M1/M2 sizes with go-srp B value |
| `live_login_succeeds` *(#[ignore])* | Real API login (needs PROTON_USER/PROTON_PASS) |

### Known limitation

The go-srp test vectors include expected M1/M2 values but the **modulus N** used in that
test run is fetched live from Proton's API and is not hardcoded in go-srp.  Without the
exact modulus we cannot reproduce the exact M1/M2 values.  The constants are kept as
comments in `tests/auth_integration.rs`.

---

## Session 3 — 2026-03-15

### Goal: install Rust, compile, run tests

### Step 1 — Install Rust

Rust was not installed. Ran the official installer:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

Installed: **rustc 1.94.0** (stable, 2026-03-02).

### Step 2 — First compile attempt

`cargo check` failed with:

```
package `proton-core` depends on `keyring` with feature
`linux-secret-service-rt-tokio-crypto-rust` but `keyring` does not have that feature.
```

**Fix:** Updated `keyring` feature flags in `crates/proton-core/Cargo.toml`:

```toml
# Before
keyring = { version = "3", features = ["linux-secret-service-rt-tokio-crypto-rust"] }
# After
keyring = { version = "3", features = ["async-secret-service", "tokio", "crypto-rust"] }
```

`cargo check` then passed cleanly.

### Step 3 — First test run

21 unit tests passed. 2 integration tests failed:

```
Auth("Expected 16-byte salt, got 10 bytes")
```

### Root cause analysis

The go-srp test salt `yKlc5/CvObfoiw==` decodes to **10 bytes**, not 16.
This revealed two additional errors in `password.rs`, and also corrected the Session 2
analysis of the `"proton"` suffix:

| Issue | Wrong | Correct |
|-------|-------|---------|
| Salt length assumption | Always 16 bytes | Variable; API typically sends 10 bytes |
| `"proton"` suffix | Dismissed as no-op | Pads 10-byte salt to exactly 16 bytes: `10 + 6 = 16` |
| Output prefix | `$2b$10$` (Rust crate default) | `$2y$10$` (Proton convention) — prefix is part of `x` input |

**The "proton" suffix is not cosmetic.** For a 10-byte server salt, appending `"proton"`
(6 bytes) produces exactly the 16 bytes bcrypt needs.  The Session 2 analysis assumed a
16-byte salt where the suffix happened to be a no-op — that assumption was wrong.

**The `$2b$` → `$2y$` normalisation matters** because the full 60-byte bcrypt string is
passed as input to `expand_hash` for `x` derivation.  Different prefix → different `x`
→ wrong session key.

### Fixes applied to `password.rs`

1. Decode server salt (any length ≥ 10 bytes).
2. Append `b"proton"`.
3. Take first 16 bytes as the bcrypt salt.
4. After hashing, replace `$2b$` prefix with `$2y$`.

### Final result

```
running 21 tests  →  21 passed; 0 failed   (unit tests, proton-core)
running  4 tests  →   3 passed; 0 failed; 1 ignored   (integration tests)
```

Total: **24 tests, 0 failures, 0 warnings.**
The 1 ignored test (`live_login_succeeds`) requires real Proton credentials.

---

## Session 4 — 2026-03-15

### Goal: remote filesystem enumeration (listing)

### Files created / modified

| File | Change |
|------|--------|
| `crates/proton-core/src/api/drive_types.rs` | **Created** — all Drive API types |
| `crates/proton-core/src/api/client.rs` | Added Drive API methods + `authed_get` helper |
| `crates/proton-core/src/api/mod.rs` | Export `drive_types` module |
| `crates/proton-core/src/drive/mod.rs` | **Created** — `DriveClient`, `DriveNode`, `walk()` |
| `crates/proton-core/src/lib.rs` | Export `drive` module |
| `crates/proton-drive/src/main.rs` | Added `ls` subcommand |

### Drive API types (`drive_types.rs`)

All Proton Drive response/request types, using `#[serde(rename_all = "PascalCase")]`:

| Type | Purpose |
|------|---------|
| `Volume`, `VolumeShare`, `VolumeState` | Top-level volume |
| `ShareMetadata`, `Share`, `ShareType`, `ShareState`, `ShareFlags` | Share (root of a volume) |
| `Link`, `LinkType`, `LinkState` | File/folder node |
| `FileProperties`, `FolderProperties`, `RevisionMetadata`, `RevisionState` | Node details |
| `CreateFolderReq`, `CreateFolderRes` | Folder creation (future use) |

Integer enum pattern: manual `From<i32>` + custom `Deserialize` so unknown server values
are preserved as `Other(i32)` instead of crashing.

### Drive API client methods added to `client.rs`

| Method | Endpoint |
|--------|----------|
| `list_volumes()` | `GET /drive/volumes` |
| `list_shares()` | `GET /drive/shares?ShowAll=1` |
| `get_share(id)` | `GET /drive/shares/{id}` |
| `get_link(share, link)` | `GET /drive/shares/{shareID}/links/{linkID}` |
| `list_children(share, folder, page, size)` | `GET /drive/shares/{shareID}/folders/{linkID}/children` |

A private `authed_get(path)` helper deduplicates the auth-header boilerplate across all
authenticated endpoints.

### Drive module (`src/drive/mod.rs`)

`DriveClient` wraps `ApiClient` with higher-level methods:

| Method | What it does |
|--------|-------------|
| `find_main_share()` | Picks the active volume's share; returns `(share_id, root_link_id)` |
| `list_children(share, folder)` | All pages of folder children (auto-paginated) |
| `list_root()` | Children of the share root |
| `walk(share, folder, visitor)` | Depth-first tree walk via `Box::pin` recursion |
| `walk_all()` | Full tree → `Vec<DriveNode>` |

`DriveNode` is a flattened view of `Link` + `share_id`.  `display_name()` returns the
encrypted name until PGP decryption is wired in.

### CLI `ls` command

```bash
proton-drive ls          # list root folder (encrypted names)
proton-drive ls -r       # recursive walk of entire drive
```

### Test results

```
running 21 tests  → 21 passed (unit tests, proton-core)
running  4 tests  →  3 passed; 1 ignored (integration, auth)
doc-tests         →  1 passed (drive module doctest)
Total: 25 tests, 0 failures, 0 warnings.
```

---

## Session 5 — 2026-03-15

### Goal: PGP name decryption

### Key-decryption chain

```
user password
    │  hash_password(password, key_salt)  ← GET /core/v4/keys/salts
    ▼
key password  ──unlocks──►  address private key  (GET /core/v4/addresses)
                                   │
                       pgp_decrypt(share.passphrase, address_key, key_pw)
                                   ▼
                        share key passphrase
                        ──unlocks──►  share private key  (share.key)
                                           │
                           pgp_decrypt(root_link.node_passphrase, share_key, ...)
                                           ▼
                               root node key passphrase
                               ──unlocks──►  root node key  (root_link.node_key)
                                                   │
                               pgp_decrypt(child.name, root_node_key, ...)
                                                   ▼
                                         plaintext filename
```

The key-password derivation reuses the existing `hash_password()` function (same bcrypt
logic as SRP), but with the per-key salt from `/core/v4/keys/salts` instead of the
SRP auth salt.

### Files created / modified

| File | Change |
|------|--------|
| `crates/proton-core/Cargo.toml` | Added `pgp = "0.14"` (rpgp 0.14.2) |
| `crates/proton-core/src/error.rs` | Added `Crypto(String)` and `Utf8` error variants |
| `crates/proton-core/src/api/types.rs` | Added `AddressKey`, `Address`, `KeySalt` types |
| `crates/proton-core/src/api/client.rs` | Added `get_addresses()`, `get_key_salts()` |
| `crates/proton-core/src/crypto/mod.rs` | **Created** — `pgp_decrypt()` |
| `crates/proton-core/src/drive/keyring.rs` | **Created** — `DriveKeyring`, `derive_key_password()` |
| `crates/proton-core/src/drive/mod.rs` | Added `build_keyring()`, `list_root_decrypted()` |
| `crates/proton-core/src/lib.rs` | Export `crypto` module |
| `crates/proton-drive/src/main.rs` | Added `--decrypt` flag to `ls` |

### New API endpoints

| Endpoint | Returns |
|----------|---------|
| `GET /core/v4/addresses` | All addresses with `Keys[]` (armored private keys) |
| `GET /core/v4/keys/salts` | Per-key bcrypt salt for key-password derivation |

Key-password rule: if `KeySalt` is non-empty → `hash_password(password, key_salt)`;
if null/empty → use raw password bytes directly.

### rpgp 0.14.2 API (confirmed by reading crate source)

```rust
use pgp::{Deserializable, Message, SignedSecretKey};
use std::io::Cursor;

let (key, _) = SignedSecretKey::from_armor_single(Cursor::new(armored_key.as_bytes()))?;
let (msg, _) = Message::from_armor_single(Cursor::new(armored_msg.as_bytes()))?;
// key_pw (FnOnce() -> String + Clone) is called to unlock the secret key's private material.
let (decrypted, _) = msg.decrypt(|| key_password_str.clone(), &[&key])?;
// get_content() handles both Literal and Compressed inner messages.
let plaintext: Vec<u8> = decrypted.get_content()?.unwrap();
```

### `DriveKeyring` design

Stores `(armored_key, passphrase_bytes)` per key ID.  Keys are parsed fresh on each
decryption call to avoid lifetime complexity.

| Method | What it does |
|--------|-------------|
| `init_share(share, addr_key, addr_pw)` | Decrypts share passphrase → stores share key entry |
| `unlock_root_node(share_id, root_link)` | Decrypts root node passphrase with share key |
| `unlock_node(link)` | Decrypts node passphrase with parent's key |
| `decrypt_name(link)` | Decrypts `link.name` with parent's key → UTF-8 string |
| `decrypt_name_raw(name, parent_id)` | Same, but takes raw fields instead of `&Link` |

`DriveClient::build_keyring(password)` orchestrates the full bootstrap: fetches
addresses, key salts, full share, and root link, then calls the above in order.

### CLI usage

```bash
proton-drive ls               # list root (encrypted names, fast, no password needed)
proton-drive ls --decrypt     # list root with real names (prompts for password)
proton-drive ls -r            # recursive walk (encrypted names)
```

### Test results

```
25 tests, 0 failures, 0 warnings
```

No new unit tests added this session (crypto functions require live keys to test).

### Open items / next steps

1. ~~Recursive walk with decryption.~~ → **Done in Session 6**
2. Verify PGP signature on the SRP modulus (fingerprint `248097092b458509c508dac0350585c4e9518f26`).
3. Local filesystem scanner + SQLite state DB for sync diffing.
4. `protond` IPC socket implementation.
5. Token refresh wired into an automatic retry loop.

---

## Session 6 — 2026-03-15

### Goal: recursive walk with decryption

### Changes

The key insight: during a depth-first walk, each folder's node key must be unlocked
*before* recursing into it, so its children's names and passphrases can be decrypted.

#### `DriveNode` — added crypto fields

`node_key` and `node_passphrase` are now stored on every `DriveNode` (populated from
the API response via `from_link`).  This lets the walker unlock sub-folder keys without
making extra API calls.

#### `DriveKeyring` — refactored to a unified key store

The previous design had two separate HashMaps (`share_key` and `node_keys`).  These
are now merged into a single `keys: HashMap<String, KeyEntry>` where the map key is
either a `share_id` or a `link_id`.  This allows one lookup path for both:

| Method | What it does |
|--------|-------------|
| `init_share(share, addr_key, addr_pw)` | Decrypts share passphrase → stores under `share_id` |
| `unlock_with_parent(link_id, parent_id, node_key, node_passphrase)` | Decrypts passphrase with parent's key → stores under `link_id` |
| `decrypt_name_raw(encrypted_name, parent_id)` | Decrypts a name using the key stored under `parent_id` |

`parent_id` is seamlessly either a `share_id` (for the root link) or a `link_id`
(for any other node) — both live in the same map.

#### `DriveClient` — new methods

| Method | What it does |
|--------|-------------|
| `build_keyring(password)` | Bootstraps keyring (share key + root node key); returns `(DriveKeyring, share_id, root_link_id)` |
| `walk_decrypted(password, visitor)` | Depth-first walk; unlocks each folder key before recursing |
| `walk_decrypted_inner(…)` | Internal recursive helper (pinned future for async recursion) |
| `walk_all_decrypted(password)` | Convenience wrapper → `Vec<(DriveNode, String)>` |

The walker falls back to the raw encrypted name if a key unlock fails (with a warning
to stderr), so a single bad key does not abort the entire walk.

#### Files modified

| File | Change |
|------|--------|
| `src/drive/mod.rs` | `DriveNode`: +`node_key`, +`node_passphrase`; new `walk_decrypted`, `walk_all_decrypted` |
| `src/drive/keyring.rs` | Unified key store; new `unlock_with_parent`; removed old `unlock_root_node` / `unlock_node` |
| `crates/proton-drive/src/main.rs` | `ls --decrypt` now works for both root and `-r` |

### CLI usage (complete)

```bash
proton-drive ls                   # root, encrypted names
proton-drive ls --decrypt         # root, decrypted names (prompts for password)
proton-drive ls -r                # full tree, encrypted names
proton-drive ls -r --decrypt      # full tree, decrypted names (prompts for password)
```

### Test results

```
25 tests, 0 failures, 0 warnings
```

### Open items / next steps

1. Verify PGP signature on the SRP modulus (fingerprint `248097092b458509c508dac0350585c4e9518f26`).
2. Local filesystem scanner + SQLite state DB for sync diffing.
3. `protond` IPC socket implementation.
4. Token refresh wired into an automatic retry loop.

---

---

## Session 7 — 2026-06-06

### Goal: review project and complete all pending tasks

### Audit findings

An exhaustive audit of the codebase against the README and project documentation
revealed that the README was significantly **out of date** — every feature listed
as 🔲 (inotify, rate limiting, conflict resolution, systemd unit, packaging) was
already implemented in the latest commit.

| Feature | README claimed | Actual status |
|---------|---------------|---------------|
| Inotify file watching | 🔲 | ✅ `crates/protond/src/watcher.rs` |
| Rate limiting / bandwidth control | 🔲 | ✅ `crates/proton-core/src/throttle.rs` |
| Conflict resolution (GUI + CLI) | 🔲 | ✅ handler + GUI + CLI commands |
| Systemd user unit | 🔲 | ✅ `packaging/protond.service` |
| .deb / AppImage / Flatpak | 🔲 | ✅ full packaging directory |
| System tray icon | not in table | ✅ `tray.rs` (behind optional feature) |
| Transfer manager | [ ] in roadmap | 🔲 truly not implemented |

### Changes made

#### 1. README updated
- Feature status table rewritten to reflect actual state (all items ✅, one 🔲 remaining)
- Roadmap checklist updated (13/14 items checked)
- Status banner updated
- GUI description updated to mention onboarding wizard, conflict resolution, tray icon

#### 2. Build warning fixed
- `[profile.release]` was defined in `proton-gui/Cargo.toml` instead of workspace
  root → moved to root `Cargo.toml`

#### 3. System tray icon
- Set `exit_on_close_request = false` so closing the window keeps the daemon and
  tray icon alive
- Tray feature was kept **non-default** because it depends on GTK development
  libraries (`libglib-2.0-dev`, `libgtk-3-dev`). Users build with
  `cargo build --features tray` to enable it.

#### 4. Transfer manager with time-window scheduling (new feature)
- **`crates/proton-core/src/transfer.rs`** (created) — `TransferConfig`, `TimeWindow`,
  `DayOfWeek` types with `is_in_window()` check. Supports:
  - Multiple time windows (OR logic)
  - Day-of-week filtering
  - Midnight-crossing windows (e.g. 22:00—06:00)
  - Unrestricted mode when no windows configured (backward compatible)
  - 5 unit tests
- **`crates/proton-core/src/lib.rs`** — exported `transfer` module
- **`crates/protond/src/handler.rs`** — added `transfer.config` IPC method (GET/SET),
  `transfers_allowed()` check called from `trigger_sync()` before running background sync
- **`crates/proton-drive/src/main.rs`** — added `proton-drive transfer` CLI command
  (show status or set JSON config)
- **`crates/proton-core/src/i18n.rs`** — added 5 translation keys (EN + CA)

#### 5. DIARY.md — this entry

### Test results

```
62 tests, 0 failures, 1 ignored, 0 warnings (plus 5 new transfer tests)
```

*Last updated: 2026-06-06*
