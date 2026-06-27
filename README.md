# Proton Drive Client for Linux

A native CLI, GUI, and background daemon for Linux that provides two-way synchronisation with [Proton Drive](https://proton.me/drive). Built in Rust.

> **Disclaimer:** This is an **unofficial, community-developed client**. It is not
> affiliated with, endorsed by, or sponsored by **Proton AG**. Proton Drive is a
> trademark of Proton AG.

> **Status: Feature-complete — authentication, PGP key chain, two-way sync, daemon IPC, GUI, inotify watching, conflict resolution, bandwidth throttle, transfer scheduling, pause/resume, packaging, and i18n are working.**

---

## Architecture

Three binaries sharing a Unix domain socket:

```
┌───────────────┐     ┌───────────────┐
│  proton-gui   │     │ proton-drive  │
│  (desktop)    │     │ (CLI)         │
└───────┬───────┘     └───────┬───────┘
        │   Unix socket IPC   │
        └──────────┬──────────┘
                   │
          ┌────────▼────────┐
          │    protond      │
          │  (daemon)       │
          │  Auth · Sync ·  │
          │  Queue · Watcher│
          └─────────────────┘
```

### Crate layout

```
Cargo.toml                     workspace root
crates/
  proton-core/                 library — all business logic
    src/
      api/                     ApiClient, API types (auth + drive)
      auth/                    SRP-6a, bcrypt, 2FA, token refresh
      crypto/                  PGP decrypt/encrypt, AES-256-CBC blocks, key generation
      db/                      SQLite state database (nodes, meta, job queue)
      drive/                   DriveClient, DriveNode, DriveKeyring, walk_decrypted()
      ipc/                     JSON Lines protocol + IpcClient
      keyring.rs               libsecret session storage
      local/                   Filesystem scanner (SHA-256 hashing)
      sync/                    Two-way sync engine (download, upload, folder creation)
      error.rs                 Error enum
  protond/                     Background daemon (Unix socket IPC handler)
  proton-drive/                CLI client
  proton-gui/                  Iced 0.12 desktop GUI
```

---

## Feature status

| Feature | Status |
|---------|--------|
| SRP-6a authentication (login, 2FA, logout, token refresh) | ✅ |
| Session storage in system keyring (libsecret) | ✅ |
| Auto-refresh expired tokens on 401 | ✅ |
| Remote volume / share / link enumeration | ✅ |
| Depth-first tree walk (auto-paginated) | ✅ |
| PGP name decryption (full address → share → node key chain) | ✅ |
| PGP signature verification on SRP modulus | ✅ |
| Local filesystem scanner with SHA-256 hashing | ✅ |
| SQLite state DB (nodes, meta, job queue) | ✅ |
| Two-way sync engine (download, upload, folder creation) | ✅ |
| Block-based file encryption/decryption (AES-256-CBC) | ✅ |
| Node key generation, name hashing, PGP signing | ✅ |
| `protond` daemon with Unix socket IPC | ✅ |
| CLI client (`proton-drive` — auth, ls, status, sync) | ✅ |
| Iced 0.12 GUI desktop app (login, 2FA, browse, decrypt) | ✅ |
| Daemon integration tests (7 passing) | ✅ |
| Inotify file watching | ✅ |
| Bandwidth throttling (token-bucket) | ✅ |
| Conflict detection & resolution (GUI + CLI) | ✅ |
| System tray icon (`--features tray`) | ✅ |
| Systemd user unit | ✅ |
| .deb / AppImage / Flatpak packaging | ✅ |
| Transfer manager with time-window scheduling | ✅ |
| Pause/resume transfers (CLI + GUI) | ✅ |
| Parallel block download/upload (×4 concurrency) | ✅ |
| E2E mock tests (wiremock) | ✅ |
| Tracing (structured logging, env-filter) | ✅ |
| i18n (English + Catalan) | ✅ |
| Onboarding wizard (GUI) | ✅ |
| Man pages (`proton-drive.1`, `protond.1`) | ✅ |

---

## Quick start

### Prerequisites

- [Rust](https://rustup.rs/) 1.75 or later (tested on 1.94.0)
- `libsecret` development headers:

```bash
sudo apt install libsecret-1-dev pkg-config
```

### Build

```bash
git clone https://github.com/your-username/proton-drive-client.git
cd proton-drive-client

cargo build --release

# Binaries:
#   ./target/release/proton-drive   (CLI)
#   ./target/release/protond        (daemon)
#   ./target/release/proton-gui     (GUI)
```

### Run tests

```bash
cargo test

# Live login test (requires a real Proton account):
PROTON_USER=you@proton.me PROTON_PASS=yourpassword \
    cargo test --test auth_integration -- --ignored
```

---

## Usage

### 1. Start the daemon (required for sync & status)

```bash
protond &
```

The daemon listens on `$XDG_RUNTIME_DIR/protond.sock`. It logs to stderr.

### 2. CLI

```bash
# Authentication
proton-drive auth login           # interactive SRP login (prompts for username + password)
proton-drive auth logout          # revoke session on server and remove from keyring
proton-drive auth status          # print currently logged-in account

# Remote file listing
proton-drive ls                   # list root folder (encrypted names)
proton-drive ls --decrypt         # list root folder with real names (prompts for password)
proton-drive ls -r                # recursive walk, encrypted names
proton-drive ls -r --decrypt      # recursive walk with real names

# Sync and status
proton-drive status               # show logged-in user, DB node counts, last sync time
proton-drive sync                 # run full two-way sync (downloads + uploads)
proton-drive pause                # pause all background transfers and sync
proton-drive resume               # resume background transfers and sync

# Transfer schedule
proton-drive transfer             # show current transfer schedule
proton-drive transfer '{"windows":[{"days":["Mon","Tue","Wed","Thu","Fri"],"start":"02:00","end":"06:00"}]}'
```

### 3. GUI

```bash
proton-gui
```

The GUI communicates with the daemon for auth, sync, and conflict resolution, and calls proton-core directly for remote browsing. It provides:
- Onboarding wizard with sync directory selection
- Login view with username, password, and 2FA TOTP support
- Browse view with folder navigation, decryption password prompt, and file listing
- Conflict resolution view (Keep Local / Keep Remote / Rename)
- System tray icon (build with `--features tray`; requires GTK dev libraries)
- Dark theme

---

## Daemon IPC protocol

Wire format: JSON Lines (`\n`-terminated) over a Unix domain socket.

```text
→ {"id":1, "method":"ping", "params":{}}
← {"id":1, "result":"pong"}

→ {"id":2, "method":"auth.status", "params":{}}
← {"id":2, "result":{"logged_in":true, "username":"user@pm.me"}}

→ {"id":3, "method":"drive.ls", "params":{"recursive":false}}
← {"id":3, "result":{"items":[{...}]}}

→ {"id":4, "method":"drive.ls_decrypted", "params":{"password":"...","recursive":true}}
← {"id":4, "result":{"items":[{..., "name":"plaintext_name"}]}}

→ {"id":5, "method":"drive.status", "params":{}}
← {"id":5, "result":{"logged_in":true,"db":{"total_nodes":42,...},"last_sync":"..."}}

→ {"id":6, "method":"drive.sync", "params":{"password":"..."}}
← {"id":6, "result":{"dirs_created":0,"downloads_attempted":5,...}}
```

---

## Storage layout

```
~/.config/proton-drive/
    config.toml              user preferences (future)

~/.local/share/proton-drive/
    state.db                 SQLite: file snapshots, sync queue, conflicts

$XDG_RUNTIME_DIR/
    protond.sock             Unix socket
```

Credentials are stored exclusively in the **system keyring** (libsecret / GNOME Keyring / KWallet) and never written to disk in plaintext.

---

## Sync pipeline

| Step | Description | Status |
|------|-------------|--------|
| 1 | Authenticate via SRP-6a → store session in libsecret | ✅ |
| 2 | Enumerate remote tree, decrypt file names with PGP key chain | ✅ |
| 3 | Enumerate local sync folder (walk + SHA-256 hash) | ✅ |
| 4 | Diff remote vs local vs last-known state (SQLite) | ✅ |
| 5 | Resolve conflicts — pause and notify user | ✅ |
| 6 | Build prioritised job queue (persisted to SQLite) | ✅ |
| 7 | Transfer blocks with encryption/decryption (respects schedule + pause) | ✅ |

---

## Authentication

Proton uses a custom **SRP-6a** variant (no OAuth):

```
POST /auth/v4/info  →  server ephemeral B, PGP-signed modulus N, bcrypt salt
bcrypt(password, salt + "proton", cost=10)  →  60-byte bcrypt string
expand_hash = SHA-512(data‖0) ‖ SHA-512(data‖1) ‖ SHA-512(data‖2) ‖ SHA-512(data‖3)
x  = expand_hash(bcrypt_output ‖ modulus_bytes)
K  = expand_hash(S_padded)
M1 = expand_hash(A ‖ B ‖ K)          ← client proof
POST /auth/v4  →  verify server proof M2, get uid + tokens
```

## PGP key-decryption chain

```
user password
    │  hash_password(password, key_salt)
    ▼
key password  ──unlocks──►  address private key
                                   │  decrypt share.passphrase
                                   ▼
                          share key passphrase
                          ──unlocks──►  share private key
                                              │  decrypt root_link.node_passphrase
                                              ▼
                                     root node key passphrase
                                     ──unlocks──►  root node key
                                                        │  decrypt child names / passphrases
                                                        ▼
                                                   plaintext filename
                                                   (recurse for sub-folders)
```

---

## Key dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `reqwest` | 0.12 | HTTP client (rustls, no OpenSSL) |
| `pgp` (rpgp) | 0.14 | OpenPGP key decryption and encryption |
| `sha2` | 0.10 | SHA-256/512 hashing |
| `bcrypt` | 0.15 | Password stretching |
| `num-bigint` | 0.4 | SRP big-integer math |
| `keyring` | 3 | libsecret / GNOME Keyring |
| `clap` | 4 | CLI argument parsing |
| `iced` | 0.12 | GUI toolkit |
| `rusqlite` | 0.31 | SQLite state database |
| `aes` / `cbc` | 0.8/0.1 | Block cipher for file content |
| `serde` / `serde_json` | 1 | JSON serialisation |
| `tokio` | 1 | Async runtime |

---

## Roadmap

- [x] SRP-6a authentication (login, 2FA, logout, token refresh)
- [x] Session storage in system keyring
- [x] Proton Drive API client (volumes, shares, links, pagination)
- [x] Remote file tree listing (depth-first walk, auto-paginated)
- [x] PGP name decryption (full address → share → node key chain)
- [x] Verify PGP signature on SRP modulus
- [x] Local filesystem walker + SHA-256 hash cache
- [x] SQLite state store (snapshots, job queue)
- [x] Diff engine
- [x] Sync queue with job persistence
- [x] Full two-way sync (download, upload, folder creation, revision management)
- [x] Block-based file encryption/decryption (AES-256-CBC)
- [x] `protond` IPC socket (daemon ↔ CLI/GUI protocol)
- [x] CLI sync and status commands
- [x] Iced 0.12 GUI desktop app
- [x] Inotify file watching (automatic change detection)
- [x] Bandwidth throttling (token-bucket)
- [x] Conflict resolution (GUI + CLI)
- [x] System tray icon (optional `tray` feature)
- [x] Systemd user unit for auto-start
- [x] Transfer manager with time-window scheduling
- [x] Pause/resume transfers (CLI + GUI)
- [x] Packaging (`.deb`, AppImage, Flatpak)
- [x] E2E mock tests (wiremock)
- [x] Parallel block download/upload (×4 concurrency)
- [x] Tracing (structured logging, env-filter)
- [x] i18n (English + Catalan)
- [x] Onboarding wizard (GUI)
- [x] Man pages (`proton-drive.1`, `protond.1`)

---

## License

MIT — see [LICENSE](LICENSE).
