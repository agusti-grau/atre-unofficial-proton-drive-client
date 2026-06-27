//! `proton-drive` — CLI client for the Proton Drive sync daemon.
//!
//! Communicates with `protond` over a Unix socket (TODO).
//! For now, auth commands call `proton-core` directly.

use std::io::{self, Write};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use proton_core::api::ApiClient;
use proton_core::auth::{self, LoginResult};
use proton_core::drive::DriveClient;
use proton_core::ipc::IpcClient;
use proton_core::keyring;
use proton_core::sync::SyncReport;
use proton_core::t;

// ── CLI definition ─────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "proton-drive",
    about = "Proton Drive client for Linux",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authentication commands.
    Auth {
        #[command(subcommand)]
        action: AuthCommands,
    },
    /// List files and folders in the remote drive.
    Ls {
        /// Folder path to list (not yet implemented — lists root for now).
        #[arg(default_value = "/")]
        path: String,
        /// Recursively list all files and folders.
        #[arg(short, long)]
        recursive: bool,
        /// Decrypt file names (prompts for password).
        #[arg(short, long)]
        decrypt: bool,
    },
    /// Show sync status (requires protond to be running).
    Status,
    /// Sync the local drive with the remote (requires protond to be running).
    Sync,
    /// Show or configure transfer schedule.
    Transfer {
        /// JSON config with time windows, or omit to show current config.
        config: Option<String>,
    },
    /// Pause all background transfers and sync.
    Pause,
    /// Resume background transfers and sync.
    Resume,
    /// Create a remote folder.
    Mkdir {
        /// Name of the new folder.
        name: String,
        /// Share ID (uses main share if omitted).
        #[arg(long)]
        share_id: Option<String>,
        /// Parent folder link ID (uses root if omitted).
        #[arg(long)]
        parent_link_id: Option<String>,
        /// Decryption password (will prompt if not provided).
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Rename a remote file or folder.
    Rename {
        /// Share ID of the item.
        #[arg(long)]
        share_id: String,
        /// Link ID of the item.
        #[arg(long)]
        link_id: String,
        /// New plaintext name.
        #[arg(long)]
        new_name: String,
        /// Decryption password (will prompt if not provided).
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Delete a remote file or folder.
    Rm {
        /// Share ID of the item.
        #[arg(long)]
        share_id: String,
        /// Link ID of the item.
        #[arg(long)]
        link_id: String,
    },
    /// List or resolve conflicts.
    Resolve {
        /// Local path of the conflicted file (omit to list all conflicts).
        path: Option<String>,
        /// Strategy: "local" (keep local), "remote" (keep remote), "rename_local" (keep both).
        #[arg(short, long)]
        strategy: Option<String>,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Log in to your Proton account.
    Login,
    /// Log out and revoke the current session.
    Logout,
    /// Print the currently logged-in account.
    Status,
}

// ── Entry point ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env_lossy(),
        )
        .with_target(true)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Auth { action } => handle_auth(action).await,
        Commands::Ls {
            recursive, decrypt, ..
        } => cmd_ls(recursive, decrypt).await,
        Commands::Status => cmd_status().await,
        Commands::Sync => cmd_sync().await,
        Commands::Transfer { config } => cmd_transfer(config).await,
        Commands::Pause => cmd_pause().await,
        Commands::Resume => cmd_resume().await,
        Commands::Mkdir {
            name,
            share_id,
            parent_link_id,
            password,
        } => cmd_mkdir(name, share_id, parent_link_id, password).await,
        Commands::Rename {
            share_id,
            link_id,
            new_name,
            password,
        } => cmd_rename(share_id, link_id, new_name, password).await,
        Commands::Rm { share_id, link_id } => cmd_rm(share_id, link_id).await,
        Commands::Resolve { path, strategy } => cmd_resolve(path, strategy).await,
    }
}

// ── Drive handlers ─────────────────────────────────────────────────────────

async fn cmd_ls(recursive: bool, decrypt: bool) -> Result<()> {
    let session = keyring::load_session()
        .await
        .context("Failed to read keyring")?
        .ok_or_else(|| anyhow::anyhow!("Not logged in — run `proton-drive auth login` first"))?;

    let api = ApiClient::new()
        .context("Failed to build API client")?
        .with_session(session);
    let drive = DriveClient::new(api);

    if decrypt {
        let password = rpassword::prompt_password("Password (for key decryption): ")
            .context("Failed to read password")?;

        if recursive {
            println!("Fetching and decrypting full drive tree…");
            let (items, _kr) = drive
                .walk_all_decrypted(&password)
                .await
                .context("Failed to walk drive")?;
            for (node, name) in &items {
                let kind = if node.is_folder() { "DIR " } else { "FILE" };
                println!("{kind}  {name}");
            }
            println!("\n{} item(s) total", items.len());
        } else {
            println!("Fetching and decrypting root folder…");
            let items = drive
                .list_root_decrypted(&password)
                .await
                .context("Failed to list drive root")?;
            for (node, name) in &items {
                let kind = if node.is_folder() { "DIR " } else { "FILE" };
                let size = if node.is_file() {
                    format!("  {:>12} B", node.size)
                } else {
                    String::new()
                };
                println!("{kind}{size}  {name}");
            }
            println!("\n{} item(s)", items.len());
        }
    } else if recursive {
        println!("Fetching full drive tree…");
        let nodes = drive.walk_all().await.context("Failed to list drive")?;
        for node in &nodes {
            let kind = if node.is_folder() { "DIR " } else { "FILE" };
            println!("{kind}  {}", node.display_name());
        }
        println!(
            "\n{} item(s) total — use --decrypt to show real names",
            nodes.len()
        );
    } else {
        println!("Fetching root folder…");
        let nodes = drive
            .list_root()
            .await
            .context("Failed to list drive root")?;
        for node in &nodes {
            let kind = if node.is_folder() { "DIR " } else { "FILE" };
            let size = if node.is_file() {
                format!("  {:>12} B", node.size)
            } else {
                String::new()
            };
            println!("{kind}{size}  {}", node.display_name());
        }
        println!(
            "\n{} item(s) — use --decrypt to show real names",
            nodes.len()
        );
    }

    Ok(())
}

// ── Auth handlers ──────────────────────────────────────────────────────────

async fn handle_auth(action: AuthCommands) -> Result<()> {
    match action {
        AuthCommands::Login => cmd_login().await,
        AuthCommands::Logout => cmd_logout().await,
        AuthCommands::Status => cmd_auth_status().await,
    }
}

async fn cmd_login() -> Result<()> {
    // Prompt for credentials interactively.
    let username = prompt("Proton account (email or username): ")?;
    let password = rpassword::prompt_password("Password: ").context("Failed to read password")?;

    println!("Authenticating…");

    let result = auth::login(username.trim(), &password)
        .await
        .context("Login failed")?;

    match result {
        LoginResult::Success(session) => {
            keyring::save_session(&session)
                .await
                .context("Failed to save session to keyring")?;
            println!("{}", t!("status.logged_in", username = &session.username));
        }
        LoginResult::TwoFactorRequired(client) => {
            let code = prompt("2FA code (TOTP): ")?;
            let session = auth::complete_2fa(&client, code.trim())
                .await
                .context("2FA failed")?;
            keyring::save_session(&session)
                .await
                .context("Failed to save session to keyring")?;
            println!(
                "{} (2FA verified).",
                t!("status.logged_in", username = &session.username)
            );
        }
    }

    Ok(())
}

async fn cmd_logout() -> Result<()> {
    match keyring::load_session()
        .await
        .context("Failed to read keyring")?
    {
        None => {
            println!("{}", t!("status.not_logged_in"));
        }
        Some(session) => {
            let username = session.username.clone();
            auth::logout(&session).await.context("Logout failed")?;
            println!("{}", t!("status.logged_out", username = &username));
        }
    }
    Ok(())
}

async fn cmd_auth_status() -> Result<()> {
    match keyring::load_session()
        .await
        .context("Failed to read keyring")?
    {
        None => println!("{}", t!("status.not_logged_in")),
        Some(s) => println!("{}", t!("status.logged_in", username = &s.username)),
    }
    Ok(())
}

// ── Sync / Status via IPC ──────────────────────────────────────────────────

async fn cmd_sync() -> Result<()> {
    let password = rpassword::prompt_password("Password (for key decryption): ")
        .context("Failed to read password")?;

    let mut client = IpcClient::connect().await?;
    let resp = client
        .request("drive.sync", serde_json::json!({ "password": password }))
        .await?;

    if let Some(err) = resp.error {
        anyhow::bail!("sync failed: {} (code {})", err.message, err.code);
    }

    if let Some(result) = resp.result {
        let report: SyncReport =
            serde_json::from_value(result).context("failed to parse sync report")?;

        if !report.errors.is_empty() {
            println!("{}", t!("sync.errors", count = report.errors.len()));
            for err in &report.errors {
                println!("  ⚠ {err}");
            }
            println!();
        }

        println!(
            "{}",
            t!(
                "sync.downloads",
                attempted = report.downloads_attempted,
                succeeded = report.downloads_succeeded
            )
        );
        println!(
            "{}",
            t!(
                "sync.uploads",
                attempted = report.uploads_attempted,
                succeeded = report.uploads_succeeded
            )
        );
        println!("{}", t!("sync.dirs_created", count = report.dirs_created));
    }
    Ok(())
}

async fn cmd_status() -> Result<()> {
    let mut client = IpcClient::connect().await?;
    let resp = client
        .request("drive.status", serde_json::json!({}))
        .await?;

    if let Some(err) = resp.error {
        anyhow::bail!("status failed: {}", err.message);
    }

    if let Some(result) = resp.result {
        let logged_in = result
            .get("logged_in")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if logged_in {
            let username = result
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("{}", t!("status.logged_in", username = username));

            if let Some(db) = result.get("db") {
                let total = db.get("total_nodes").and_then(|v| v.as_i64()).unwrap_or(0);
                let synced = db.get("synced").and_then(|v| v.as_i64()).unwrap_or(0);
                let pending = db.get("pending").and_then(|v| v.as_i64()).unwrap_or(0);
                println!(
                    "{}",
                    t!(
                        "status.db_status",
                        total = total,
                        synced = synced,
                        pending = pending
                    )
                );
            }

            if let Some(last_sync) = result.get("last_sync").and_then(|v| v.as_str()) {
                if !last_sync.is_empty() {
                    println!("{}", t!("status.last_sync", time = last_sync));
                }
            }

            let paused = result
                .get("paused")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if paused {
                println!("{}", t!("status.paused"));
            }

            if let Some(status) = result.get("transfer_status").and_then(|v| v.as_str()) {
                println!("{status}");
            }
        } else {
            println!("{}", t!("status.not_logged_in"));
        }
    }
    Ok(())
}

// ── Transfer schedule / pause ──────────────────────────────────────────────

async fn cmd_pause() -> Result<()> {
    let mut client = IpcClient::connect().await?;
    let resp = client.request("drive.pause", serde_json::json!({})).await?;
    if let Some(err) = resp.error {
        anyhow::bail!("pause failed: {}", err.message);
    }
    println!("{}", t!("pause.success"));
    Ok(())
}

async fn cmd_resume() -> Result<()> {
    let mut client = IpcClient::connect().await?;
    let resp = client
        .request("drive.resume", serde_json::json!({}))
        .await?;
    if let Some(err) = resp.error {
        anyhow::bail!("resume failed: {}", err.message);
    }
    println!("{}", t!("resume.success"));
    Ok(())
}

async fn cmd_transfer(config: Option<String>) -> Result<()> {
    let mut client = IpcClient::connect().await?;

    match config {
        Some(json_str) => {
            // SET config.
            let params: serde_json::Value =
                serde_json::from_str(&json_str).context("Invalid JSON config")?;
            let resp = client.request("transfer.config", params).await?;
            if let Some(err) = resp.error {
                anyhow::bail!("transfer config failed: {}", err.message);
            }
            if let Some(result) = resp.result {
                let allowed = result
                    .get("transfers_allowed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                println!("{}", t!("transfer.config_updated"));
                if allowed {
                    println!("{}", t!("transfer.allowed"));
                } else {
                    println!("{}", t!("transfer.not_allowed"));
                }
            }
        }
        None => {
            // GET config.
            let resp = client
                .request("transfer.config", serde_json::json!({}))
                .await?;
            if let Some(err) = resp.error {
                anyhow::bail!("transfer config failed: {}", err.message);
            }
            if let Some(result) = resp.result {
                let allowed = result
                    .get("transfers_allowed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if allowed {
                    println!("{}", t!("transfer.allowed"));
                } else {
                    println!("{}", t!("transfer.not_allowed"));
                }

                if let Some(cfg) = result.get("config") {
                    if let Some(windows) = cfg.get("windows").and_then(|v| v.as_array()) {
                        if windows.is_empty() {
                            println!("{}", t!("transfer.no_schedule"));
                        } else {
                            println!("{}", t!("transfer.schedule"));
                            for w in windows {
                                let days = w
                                    .get("days")
                                    .and_then(|v| v.as_array())
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|d| d.as_str())
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    })
                                    .unwrap_or_else(|| "*".into());
                                let start = w.get("start").and_then(|v| v.as_str()).unwrap_or("?");
                                let end = w.get("end").and_then(|v| v.as_str()).unwrap_or("?");
                                println!("  {days}: {start} → {end}");
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// ── Mkdir ──────────────────────────────────────────────────────────────────

async fn cmd_mkdir(
    name: String,
    share_id: Option<String>,
    parent_link_id: Option<String>,
    password: Option<String>,
) -> Result<()> {
    let password = match password {
        Some(p) => p,
        None => rpassword::prompt_password("Password (for key decryption): ")
            .context("Failed to read password")?,
    };

    let mut client = IpcClient::connect().await?;

    let resp = client
        .request(
            "drive.create_folder",
            serde_json::json!({
                "share_id": share_id,
                "parent_link_id": parent_link_id,
                "folder_name": name,
                "password": password,
            }),
        )
        .await?;

    if let Some(err) = resp.error {
        anyhow::bail!("create folder failed: {} (code {})", err.message, err.code);
    }

    if let Some(result) = resp.result {
        let link_id = result
            .get("link_id")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        println!("{}", t!("create_folder.success", name = &name));
        println!("  link_id: {link_id}");
    }
    Ok(())
}

// ── Rename ─────────────────────────────────────────────────────────────────

async fn cmd_rename(
    share_id: String,
    link_id: String,
    new_name: String,
    password: Option<String>,
) -> Result<()> {
    let password = match password {
        Some(p) => p,
        None => rpassword::prompt_password("Password (for key decryption): ")
            .context("Failed to read password")?,
    };

    let mut client = IpcClient::connect().await?;
    let resp = client
        .request(
            "drive.rename",
            serde_json::json!({
                "share_id": share_id,
                "link_id": link_id,
                "new_name": new_name,
                "password": password,
            }),
        )
        .await?;

    if let Some(err) = resp.error {
        anyhow::bail!("rename failed: {} (code {})", err.message, err.code);
    }

    println!("{}", t!("rename.success", name = &new_name));
    Ok(())
}

// ── Delete ─────────────────────────────────────────────────────────────────

async fn cmd_rm(share_id: String, link_id: String) -> Result<()> {
    let mut client = IpcClient::connect().await?;
    let resp = client
        .request(
            "drive.delete",
            serde_json::json!({
                "share_id": share_id,
                "link_id": link_id,
            }),
        )
        .await?;

    if let Some(err) = resp.error {
        anyhow::bail!("delete failed: {} (code {})", err.message, err.code);
    }

    println!("{}", t!("delete.success", name = &link_id));
    Ok(())
}

// ── Conflict resolution ────────────────────────────────────────────────────

async fn cmd_resolve(path: Option<String>, strategy: Option<String>) -> Result<()> {
    let mut client = IpcClient::connect().await?;

    match (path, strategy) {
        (None, _) => {
            // List all conflicts.
            let resp = client
                .request("drive.conflicts", serde_json::json!({}))
                .await?;
            if let Some(err) = resp.error {
                anyhow::bail!("list conflicts failed: {}", err.message);
            }
            if let Some(result) = resp.result {
                let items = result
                    .get("items")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                if items.is_empty() {
                    println!("{}", t!("conflict.no_conflicts"));
                } else {
                    println!("Conflicts:");
                    for item in &items {
                        let lp = item
                            .get("local_path")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?");
                        println!("  {lp}");
                    }
                    println!("\nResolve with: proton-drive resolve <path> --strategy <local|remote|rename_local>");
                }
            }
        }
        (Some(local_path), Some(strategy)) => {
            let password = rpassword::prompt_password("Password (for key decryption): ")
                .context("Failed to read password")?;

            let resp = client
                .request(
                    "drive.resolve",
                    serde_json::json!({
                        "local_path": local_path,
                        "strategy": strategy,
                        "password": password,
                    }),
                )
                .await?;

            if let Some(err) = resp.error {
                anyhow::bail!("resolve failed: {}", err.message);
            }

            println!(
                "{}",
                t!(
                    "conflict.resolved",
                    strategy = &strategy,
                    path = &local_path
                )
            );
        }
        (Some(_), None) => {
            anyhow::bail!("--strategy is required when specifying a path. Use --strategy local, --strategy remote, or --strategy rename_local");
        }
    }

    Ok(())
}

// ── Utilities ──────────────────────────────────────────────────────────────

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input)
}
