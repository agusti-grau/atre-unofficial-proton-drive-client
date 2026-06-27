# AGENTS.md — proton-drive-client

## Workspace

Cargo workspace at `/home/gus/repositories/proton-drive-client`. 4 crate members under `crates/`:

| Crate | Type | Entrypoint |
|---|---|---|
| `proton-core` | library | `crates/proton-core/src/lib.rs` |
| `protond` | binary (daemon) | `crates/protond/src/main.rs` |
| `proton-drive` | binary (CLI) | `crates/proton-drive/src/main.rs` |
| `proton-gui` | binary (GUI) | `crates/proton-gui/src/main.rs` |

## Required commands

```bash
cargo check --workspace            # Compile check (faster than build)
cargo test --workspace             # All tests
cargo clippy --workspace -- -D warnings
cargo fmt --all --check
cargo build --release              # Release binaries
cargo build --features tray        # GUI with system tray (non-default)
```

Single-crate: `cargo check -p protond`, `cargo test -p proton-core`, etc.

## Running a single test

```bash
cargo test -p proton-core -- <test_name>
cargo test -p protond --test integration -- ping_pong
```

Integration tests are in `crates/*/tests/`. Daemon tests spawn the real `protond` binary (`CARGO_BIN_EXE_protond`). E2e mock tests use `wiremock` and are in `proton-core/tests/e2e_mock.rs`.

Live auth test (requires real Proton credentials):
```bash
PROTON_USER=you@pm.me PROTON_PASS=yourpass \
  cargo test -p proton-core --test auth_integration -- --ignored
```

## Verification order

`cargo check --workspace` → `cargo test --workspace` → `cargo clippy --workspace -- -D warnings` → `cargo fmt --all --check`

## Architecture

```
proton-drive (CLI) ─┐
proton-gui (GUI)   ─┤── Unix socket IPC (JSON Lines) ──► protond (daemon)
                     ├─ Auth · Sync · Queue · Watcher
                     └─ $XDG_RUNTIME_DIR/protond.sock
```

Three binaries share `proton-core` lib. Daemon must be running for `sync`/`status`/`transfer`/`resolve` CLI commands.

## Quirks & conventions

- **`tray` feature**: non-default; requires GTK dev libs (`libglib-2.0-dev`, `libgtk-3-dev`)
- **keyring**: `proton-core` uses `keyring` crate with `async-secret-service` + `tokio` + `crypto-rust` features; requires `libsecret-1-dev` + `pkg-config` at build time
- **i18n**: `t!("key")` / `t!("key", var=val)` macro from `proton_core::i18n`; data embedded in `i18n.rs` (EN + CA)
- **Error handling**: `proton_core::Error` enum with `thiserror`; re-exported as `proton_core::Result<T>`
- **IPC types**: `IpcRequest`/`IpcResponse` in `proton_core::ipc`; wire format is JSON Lines
- **PGP**: uses `rpgp` 0.14 with `default-features = false`; `pgp_decrypt` helper in `proton_core::crypto`
- **Throttle**: token-bucket in `proton_core::throttle`; 0 = unlimited
- **API types**: `#[serde(rename_all = "PascalCase")]` for Proton API types; integer enums use `Other(i32)` fallback
- **Profile.release**: `opt-level = 2` at workspace root
- **Config**: `--features tray` for tray icon; optional `PROTON_DRIVE_DIR` env var overrides sync dir
- **test helpers**: auth integration tests reference go-srp test vectors as comments (modulus N fetched live, so exact M1/M2 can't be hardcoded)
- **StateDb**: `StateDb::open(&StateDb::default_dir())` opens SQLite at `~/.local/share/proton-drive/state.db`
- **File dialog**: GUI uses `rfd` crate (`rfd = "0.14"`) for native file picker dialogs; only in `proton-gui`

## Upload flow (single file from GUI)

1. User clicks "Upload file" button in `browse_view`
2. `rfd::AsyncFileDialog` opens native file picker
3. Selected path sent to daemon via `drive.upload_file` IPC
4. Daemon handler (`handle_drive_upload_file`) builds keyring, unlocks parent key, creates `SyncEngine`
5. `SyncEngine::upload_file()` generates keypair, encrypts filename/passphrase, creates link on API
6. Reads file, splits into 4MB blocks, encrypts each with session key, creates revision
7. Uploads blocks in parallel batches of 4 via pre-signed URLs, completes revision
8. Returns `link_id` to GUI, which re-fetches the folder listing

## Test infrastructure

- protond integration tests create isolated temp dirs for each test
- e2e mock tests use `wiremock::MockServer` and generate real crypto material (PGP keys, encrypted blocks)
- `#[ignore]` on live tests requiring network/proton credentials
