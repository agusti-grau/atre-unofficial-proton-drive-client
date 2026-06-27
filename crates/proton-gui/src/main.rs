use std::time::Duration;

use iced::{
    widget::{button, column, container, scrollable, text, text_input, Column, Row},
    Application, Command, Element, Length, Settings, Subscription, Theme,
};

use notify_rust::Notification;
use proton_core::{
    api::Session,
    drive::{keyring::DriveKeyring, DriveClient, DriveNode},
    ipc::{socket_path, IpcClient},
    keyring,
    sync::SyncReport,
    t,
};

#[cfg(feature = "tray")]
mod tray;
#[cfg(feature = "tray")]
use tray::TrayMessage;

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env_lossy(),
        )
        .with_target(true)
        .init();

    #[cfg(feature = "tray")]
    {
        std::thread::spawn(|| {
            let tray = tray::Tray::new();
            while let Ok(msg) = tray.receiver().recv() {
                match msg {
                    TrayMessage::Quit => {
                        tracing::info!("Tray: quit requested");
                        std::process::exit(0);
                    }
                    TrayMessage::Show | TrayMessage::Hide => {
                        tracing::debug!("Tray: show/hide (not yet implemented)");
                    }
                }
            }
        });
    }

    ProtonDrive::run(Settings {
        window: iced::window::Settings {
            size: iced::Size {
                width: 800.0,
                height: 600.0,
            },
            min_size: Some(iced::Size {
                width: 500.0,
                height: 400.0,
            }),
            exit_on_close_request: false,
            ..Default::default()
        },
        ..Default::default()
    })
}

// ── App ─────────────────────────────────────────────────────────────────────

struct ProtonDrive {
    state: State,
}

#[allow(clippy::large_enum_variant)]
enum State {
    Loading,
    Onboarding(OnboardingData),
    Login(LoginData),
    Browse(BrowseData),
}

struct OnboardingData {
    sync_dir: String,
}

struct LoginData {
    username: String,
    password: String,
    twofa_code: String,
    needs_2fa: bool,
    error: Option<String>,
    loading: bool,
}

struct BrowseData {
    session: Session,
    password: String,
    kr: Option<DriveKeyring>,
    share_id: Option<String>,
    root_link_id: Option<String>,
    current_parent_key_id: Option<String>,
    path: Vec<(String, String)>,
    files: Vec<FileEntry>,
    conflicts: Vec<ConflictEntry>,
    conflict_count: u32,
    loading: bool,
    creating_folder: bool,
    new_folder_input: String,
    deleting: bool,
    renaming: Option<(String, String, String)>, // (share_id, link_id, current_name)
    rename_input: String,
    error: Option<String>,
    sync_state: String,
    last_sync: Option<String>,
    last_report: Option<SyncReport>,
    sync_error: Option<String>,
    confirm_delete: Option<(String, String, String)>, // (share_id, link_id, name)
    uploading: bool,
    paused: bool,
    transfer_status: String,
}
struct FileEntry {
    node: DriveNode,
    name: String,
}

#[derive(Debug, Clone)]
struct ConflictEntry {
    local_path: String,
}

#[derive(Debug, Clone)]
struct SyncStatusInfo {
    state: String,
    last_sync: Option<String>,
    last_report: Option<SyncReport>,
    error: Option<String>,
    paused: bool,
    transfer_status: String,
}

// ── Messages ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Message {
    // Login
    UsernameChanged(String),
    PasswordChanged(String),
    TwoFACodeChanged(String),
    LoginPressed,
    TwoFAPressed,
    LoginDone(Result<(), String>),
    TwoFADone(Result<(), String>),
    CheckAuthDone(Option<Result<Session, String>>),

    // Onboarding
    OnboardingDone,
    OnboardingDirChanged(String),

    // Browse
    PasswordForDecryptChanged(String),
    DecryptPressed,
    KeyringBuilt(Result<(DriveKeyring, String, String), String>),
    FolderClickedEncrypted(String, String),
    BackPressed,
    FolderLoaded(Result<Vec<DriveNode>, String>),
    ConflictsFetched(Result<Vec<ConflictEntry>, String>),
    ResolveConflict(String, String),
    ResolveDone(String),
    LogoutPressed,
    LogoutDone,

    // Create folder
    NewFolderPressed,
    NewFolderInputChanged(String),
    NewFolderConfirmed,
    NewFolderCancelled,
    NewFolderDone(Result<String, String>),

    // Rename
    RenamePressed(String, String, String),
    RenameInputChanged(String),
    RenameConfirmed,
    RenameCancelled,
    RenameDone(Result<(), String>),

    // Delete
    DeletePressed(String, String, String),
    DeleteConfirmed,
    DeleteCancelled,
    DeleteDone(Result<(), String>),

    // Upload file
    UploadPressed,
    UploadDone(Result<String, String>),

    // Sync status
    SyncStatusTick,
    SyncStatusUpdated(SyncStatusInfo),

    // Pause / resume
    PausePressed,
    ResumePressed,
    PauseDone(Result<(), String>),
    ResumeDone(Result<(), String>),
}

// ── Application impl ────────────────────────────────────────────────────────

impl Application for ProtonDrive {
    type Executor = iced::executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        (
            Self {
                state: State::Loading,
            },
            Command::perform(check_auth(), Message::CheckAuthDone),
        )
    }

    fn title(&self) -> String {
        t!("app_name").to_string()
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            // ── Auth check ─────────────────────────────────────────────
            Message::CheckAuthDone(result) => {
                match result {
                    Some(Ok(session)) => {
                        let state = State::Browse(BrowseData {
                            session,
                            password: String::new(),
                            kr: None,
                            share_id: None,
                            root_link_id: None,
                            current_parent_key_id: None,
                            path: Vec::new(),
                            files: Vec::new(),
                            conflicts: Vec::new(),
                            conflict_count: 0,
                            loading: false,
                            creating_folder: false,
                            new_folder_input: String::new(),
                            deleting: false,
                            renaming: None,
                            rename_input: String::new(),
                            error: None,
                            sync_state: "unknown".into(),
                            last_sync: None,
                            last_report: None,
                            sync_error: None,
                            confirm_delete: None,
                            uploading: false,
                            paused: false,
                            transfer_status: String::new(),
                        });
                        self.state = state;
                        return fetch_conflicts();
                    }
                    Some(Err(e)) => {
                        self.state = State::Login(LoginData {
                            username: String::new(),
                            password: String::new(),
                            twofa_code: String::new(),
                            needs_2fa: false,
                            error: Some(format!("Daemon error: {e}")),
                            loading: false,
                        });
                    }
                    None => {
                        let home = std::env::var("HOME").unwrap_or_else(|_| "~".into());
                        self.state = State::Onboarding(OnboardingData {
                            sync_dir: format!("{home}/Proton Drive"),
                        });
                    }
                }
                Command::none()
            }

            // ── Onboarding ───────────
            Message::OnboardingDirChanged(v) => {
                if let State::Onboarding(ref mut d) = self.state {
                    d.sync_dir = v;
                }
                Command::none()
            }
            Message::OnboardingDone => {
                self.state = State::Login(LoginData {
                    username: String::new(),
                    password: String::new(),
                    twofa_code: String::new(),
                    needs_2fa: false,
                    error: None,
                    loading: false,
                });
                Command::none()
            }

            // ── Login ────────────────────────────────────────────────
            Message::UsernameChanged(v) => {
                if let State::Login(ref mut d) = self.state {
                    d.username = v;
                }
                Command::none()
            }
            Message::PasswordChanged(v) => {
                if let State::Login(ref mut d) = self.state {
                    d.password = v;
                }
                Command::none()
            }
            Message::TwoFACodeChanged(v) => {
                if let State::Login(ref mut d) = self.state {
                    d.twofa_code = v;
                }
                Command::none()
            }
            Message::LoginPressed => {
                if let State::Login(ref mut d) = self.state {
                    d.loading = true;
                    d.error = None;
                    let username = d.username.clone();
                    let password = d.password.clone();
                    return Command::perform(login_async(username, password), Message::LoginDone);
                }
                Command::none()
            }
            Message::TwoFAPressed => {
                if let State::Login(ref mut d) = self.state {
                    d.loading = true;
                    d.error = None;
                    let code = d.twofa_code.clone();
                    return Command::perform(twofa_async(code), Message::TwoFADone);
                }
                Command::none()
            }
            Message::LoginDone(result) => {
                if let State::Login(ref mut d) = self.state {
                    d.loading = false;
                    match result {
                        Ok(()) => {
                            return Command::perform(load_session_after_login(), |r| match r {
                                Ok(session) => Message::CheckAuthDone(Some(Ok(session))),
                                Err(e) => Message::CheckAuthDone(Some(Err(e))),
                            });
                        }
                        Err(ref e) if e == "2FA_REQUIRED" => {
                            d.needs_2fa = true;
                            d.error = None;
                        }
                        Err(e) => {
                            d.error = Some(e);
                        }
                    }
                }
                Command::none()
            }
            Message::TwoFADone(result) => {
                if let State::Login(ref mut d) = self.state {
                    d.loading = false;
                    d.needs_2fa = false;
                    match result {
                        Ok(()) => {
                            return Command::perform(load_session_after_login(), |r| match r {
                                Ok(session) => Message::CheckAuthDone(Some(Ok(session))),
                                Err(e) => Message::CheckAuthDone(Some(Err(e))),
                            });
                        }
                        Err(e) => {
                            d.error = Some(e);
                        }
                    }
                }
                Command::none()
            }

            // ── Browse: decryption ───────────────────────────────────
            Message::PasswordForDecryptChanged(v) => {
                if let State::Browse(ref mut d) = self.state {
                    d.password = v;
                }
                Command::none()
            }
            Message::DecryptPressed => {
                if let State::Browse(ref d) = self.state {
                    let session = d.session.clone();
                    let password = d.password.clone();
                    return Command::perform(
                        build_keyring_async(session, password),
                        Message::KeyringBuilt,
                    );
                }
                Command::none()
            }
            Message::KeyringBuilt(result) => {
                if let State::Browse(ref mut d) = self.state {
                    d.loading = false;
                    match result {
                        Ok((kr, share_id, root_link_id)) => {
                            d.kr = Some(kr);
                            d.share_id = Some(share_id.clone());
                            d.root_link_id = Some(root_link_id.clone());
                            return Command::perform(
                                fetch_children_async(d.session.clone(), share_id, root_link_id),
                                Message::FolderLoaded,
                            );
                        }
                        Err(e) => {
                            d.error = Some(e);
                        }
                    }
                }
                Command::none()
            }

            // ── Browse: navigation ───────────────────────────────────
            Message::FolderClickedEncrypted(folder_id, _name) => {
                if let State::Browse(ref mut d) = self.state {
                    d.loading = true;
                    d.current_parent_key_id = Some(folder_id.clone());
                    let share_id = d.share_id.clone().unwrap_or_default();
                    return Command::perform(
                        fetch_children_async(d.session.clone(), share_id, folder_id),
                        Message::FolderLoaded,
                    );
                }
                Command::none()
            }
            Message::BackPressed => {
                if let State::Browse(ref mut d) = self.state {
                    if d.path.len() > 1 {
                        d.path.pop();
                        if let Some((prev_id, _)) = d.path.last() {
                            d.current_parent_key_id = Some(prev_id.clone());
                        }
                        d.loading = true;
                        let (folder_id, _) = d.path.last().cloned().unwrap_or_default();
                        let share_id = d.share_id.clone().unwrap_or_default();
                        return Command::perform(
                            fetch_children_async(d.session.clone(), share_id, folder_id),
                            Message::FolderLoaded,
                        );
                    }
                }
                Command::none()
            }
            Message::FolderLoaded(result) => {
                if let State::Browse(ref mut d) = self.state {
                    d.loading = false;
                    match result {
                        Ok(children) => {
                            let parent_key_id = d
                                .current_parent_key_id
                                .clone()
                                .unwrap_or_else(|| d.root_link_id.clone().unwrap_or_default());
                            let mut entries = Vec::new();
                            if let Some(ref mut kr) = d.kr {
                                for node in &children {
                                    let name = kr
                                        .decrypt_name_raw(&node.encrypted_name, &parent_key_id)
                                        .unwrap_or_else(|_| node.encrypted_name.clone());
                                    if node.is_folder() && node.is_active() {
                                        let _ = kr.unlock_with_parent(
                                            &node.link_id,
                                            &parent_key_id,
                                            &node.node_key,
                                            &node.node_passphrase,
                                        );
                                    }
                                    entries.push(FileEntry {
                                        node: node.clone(),
                                        name,
                                    });
                                }
                            }
                            d.files = entries;
                        }
                        Err(e) => {
                            d.error = Some(e);
                        }
                    }
                }
                Command::none()
            }

            // ── Conflict resolution ────────────────────────────────
            Message::ConflictsFetched(result) => {
                if let State::Browse(ref mut d) = self.state {
                    match result {
                        Ok(entries) => {
                            d.conflicts = entries;
                            d.conflict_count = d.conflicts.len() as u32;
                        }
                        Err(_e) => {}
                    }
                }
                Command::none()
            }
            Message::ResolveConflict(local_path, strategy) => {
                let password = if let State::Browse(ref d) = self.state {
                    d.password.clone()
                } else {
                    String::new()
                };
                Command::perform(
                    resolve_conflict_async(local_path, strategy, password),
                    Message::ResolveDone,
                )
            }
            Message::ResolveDone(path) => {
                if !path.is_empty() {
                    // Re-fetch conflicts.
                    fetch_conflicts()
                } else {
                    Command::none()
                }
            }

            // ── Sync status ────────────────────────────────────────
            Message::SyncStatusTick => {
                Command::perform(fetch_sync_status(), Message::SyncStatusUpdated)
            }
            Message::SyncStatusUpdated(info) => {
                if let State::Browse(ref mut d) = self.state {
                    let was_syncing = d.sync_state == "syncing";
                    d.sync_state = info.state;
                    d.last_sync = info.last_sync;
                    d.last_report = info.last_report;
                    d.sync_error = info.error;
                    d.paused = info.paused;
                    d.transfer_status = info.transfer_status;

                    // Show notification when sync transitions from syncing to idle.
                    if was_syncing && d.sync_state == "idle" {
                        if let Some(ref report) = d.last_report {
                            let (summary, body) = if report.errors.is_empty()
                                && report.downloads_attempted + report.uploads_attempted > 0
                            {
                                (
                                    t!("sync.completed").to_string(),
                                    format!(
                                        "↓ {}↑ {}📁 {}",
                                        t!(
                                            "sync.downloads",
                                            attempted = report.downloads_attempted,
                                            succeeded = report.downloads_succeeded
                                        ),
                                        t!(
                                            "sync.uploads",
                                            attempted = report.uploads_attempted,
                                            succeeded = report.uploads_succeeded
                                        ),
                                        t!("sync.dirs_created", count = report.dirs_created),
                                    ),
                                )
                            } else if !report.errors.is_empty() {
                                (
                                    t!("sync.errors", count = report.errors.len()).to_string(),
                                    format!(
                                        "↓ {}↑ {}",
                                        t!(
                                            "sync.downloads",
                                            attempted = report.downloads_attempted,
                                            succeeded = report.downloads_succeeded
                                        ),
                                        t!(
                                            "sync.uploads",
                                            attempted = report.uploads_attempted,
                                            succeeded = report.uploads_succeeded
                                        ),
                                    ),
                                )
                            } else {
                                (
                                    "Proton Drive Sync".into(),
                                    t!(
                                        "sync.status_idle_at",
                                        time = d.last_sync.as_deref().unwrap_or("?")
                                    ),
                                )
                            };
                            let _ = Notification::new()
                                .summary(&summary)
                                .body(&body)
                                .appname("Proton Drive")
                                .icon("proton-drive")
                                .timeout(5000)
                                .show();
                        }
                    }
                }
                Command::none()
            }

            // ── Pause / resume ───────────────────────────────────────
            Message::PausePressed => Command::perform(pause_async(), Message::PauseDone),
            Message::ResumePressed => Command::perform(resume_async(), Message::ResumeDone),
            Message::PauseDone(result) => {
                if let State::Browse(ref mut d) = self.state {
                    match result {
                        Ok(()) => d.paused = true,
                        Err(e) => d.error = Some(e),
                    }
                }
                Command::perform(fetch_sync_status(), Message::SyncStatusUpdated)
            }
            Message::ResumeDone(result) => {
                if let State::Browse(ref mut d) = self.state {
                    match result {
                        Ok(()) => d.paused = false,
                        Err(e) => d.error = Some(e),
                    }
                }
                Command::perform(fetch_sync_status(), Message::SyncStatusUpdated)
            }

            // ── Create folder ────────────────────────────────────────
            Message::NewFolderPressed => {
                if let State::Browse(ref mut d) = self.state {
                    d.creating_folder = true;
                    d.new_folder_input = String::new();
                }
                Command::none()
            }
            Message::NewFolderInputChanged(v) => {
                if let State::Browse(ref mut d) = self.state {
                    d.new_folder_input = v;
                }
                Command::none()
            }
            Message::NewFolderConfirmed => {
                if let State::Browse(ref mut d) = self.state {
                    let name = d.new_folder_input.trim().to_string();
                    if name.is_empty() {
                        d.error = Some("Folder name cannot be empty".into());
                        return Command::none();
                    }
                    let sid = d.share_id.clone().unwrap_or_default();
                    let pid = d.current_parent_key_id.clone().unwrap_or_default();
                    let password = d.password.clone();
                    if sid.is_empty() || pid.is_empty() {
                        d.error = Some("No share/parent folder selected".into());
                        return Command::none();
                    }
                    d.creating_folder = false;
                    return Command::perform(
                        create_folder_async(sid, pid, name, password),
                        Message::NewFolderDone,
                    );
                }
                Command::none()
            }
            Message::NewFolderCancelled => {
                if let State::Browse(ref mut d) = self.state {
                    d.creating_folder = false;
                    d.new_folder_input.clear();
                }
                Command::none()
            }
            Message::NewFolderDone(result) => {
                if let State::Browse(ref mut d) = self.state {
                    match result {
                        Ok(_link_id) => {
                            let share_id = d.share_id.clone().unwrap_or_default();
                            let folder_id = d.current_parent_key_id.clone().unwrap_or_default();
                            if !share_id.is_empty() && !folder_id.is_empty() {
                                let session = d.session.clone();
                                return Command::perform(
                                    fetch_children_async(session, share_id, folder_id),
                                    Message::FolderLoaded,
                                );
                            }
                        }
                        Err(e) => {
                            d.error = Some(e);
                        }
                    }
                }
                Command::none()
            }

            // ── Rename ──────────────────────────────────────────────
            Message::RenamePressed(share_id, link_id, name) => {
                if let State::Browse(ref mut d) = self.state {
                    d.renaming = Some((share_id, link_id, name.clone()));
                    d.rename_input = name;
                }
                Command::none()
            }
            Message::RenameInputChanged(v) => {
                if let State::Browse(ref mut d) = self.state {
                    d.rename_input = v;
                }
                Command::none()
            }
            Message::RenameConfirmed => {
                if let State::Browse(ref mut d) = self.state {
                    if let Some((share_id, link_id, _)) = d.renaming.take() {
                        let new_name = d.rename_input.clone();
                        let password = d.password.clone();
                        return Command::perform(
                            rename_async(share_id, link_id, new_name, password),
                            Message::RenameDone,
                        );
                    }
                }
                Command::none()
            }
            Message::RenameCancelled => {
                if let State::Browse(ref mut d) = self.state {
                    d.renaming = None;
                    d.rename_input.clear();
                }
                Command::none()
            }
            Message::RenameDone(result) => {
                if let State::Browse(ref mut d) = self.state {
                    match result {
                        Ok(()) => {
                            let share_id = d.share_id.clone().unwrap_or_default();
                            let folder_id = d.current_parent_key_id.clone().unwrap_or_default();
                            if !share_id.is_empty() && !folder_id.is_empty() {
                                let session = d.session.clone();
                                return Command::perform(
                                    fetch_children_async(session, share_id, folder_id),
                                    Message::FolderLoaded,
                                );
                            }
                        }
                        Err(e) => {
                            d.error = Some(e);
                        }
                    }
                }
                Command::none()
            }

            // ── Delete ──────────────────────────────────────────────
            Message::DeletePressed(share_id, link_id, name) => {
                if let State::Browse(ref mut d) = self.state {
                    d.confirm_delete = Some((share_id, link_id, name));
                }
                Command::none()
            }
            Message::DeleteConfirmed => {
                if let State::Browse(ref mut d) = self.state {
                    if let Some((share_id, link_id, _)) = d.confirm_delete.take() {
                        d.deleting = true;
                        return Command::perform(
                            delete_async(share_id, link_id),
                            Message::DeleteDone,
                        );
                    }
                }
                Command::none()
            }
            Message::DeleteCancelled => {
                if let State::Browse(ref mut d) = self.state {
                    d.confirm_delete = None;
                }
                Command::none()
            }
            Message::DeleteDone(result) => {
                if let State::Browse(ref mut d) = self.state {
                    d.deleting = false;
                    match result {
                        Ok(()) => {
                            // Re-fetch current folder.
                            let share_id = d.share_id.clone().unwrap_or_default();
                            let folder_id = d.current_parent_key_id.clone().unwrap_or_default();
                            if !share_id.is_empty() && !folder_id.is_empty() {
                                let session = d.session.clone();
                                return Command::perform(
                                    fetch_children_async(session, share_id, folder_id),
                                    Message::FolderLoaded,
                                );
                            }
                        }
                        Err(e) => {
                            d.error = Some(e);
                        }
                    }
                }
                Command::none()
            }

            // ── Upload file ──────────────────────────────────────────
            Message::UploadPressed => {
                if let State::Browse(ref mut d) = self.state {
                    d.uploading = true;
                    let password = d.password.clone();
                    let share_id = d.share_id.clone().unwrap_or_default();
                    let parent_link_id = d.current_parent_key_id.clone().unwrap_or_default();
                    return Command::perform(
                        upload_async(password, share_id, parent_link_id),
                        Message::UploadDone,
                    );
                }
                Command::none()
            }
            Message::UploadDone(result) => {
                if let State::Browse(ref mut d) = self.state {
                    d.uploading = false;
                    match result {
                        Ok(link_id) => {
                            tracing::info!("Uploaded file, link_id={}", link_id);
                            // Re-fetch current folder.
                            let share_id = d.share_id.clone().unwrap_or_default();
                            let folder_id = d.current_parent_key_id.clone().unwrap_or_default();
                            if !share_id.is_empty() && !folder_id.is_empty() {
                                let session = d.session.clone();
                                return Command::perform(
                                    fetch_children_async(session, share_id, folder_id),
                                    Message::FolderLoaded,
                                );
                            }
                        }
                        Err(e) => {
                            d.error = Some(e);
                        }
                    }
                }
                Command::none()
            }

            // ── Logout ──────────────────────────────────────────────
            Message::LogoutPressed => Command::perform(logout_async(), |_| Message::LogoutDone),
            Message::LogoutDone => {
                self.state = State::Login(LoginData {
                    username: String::new(),
                    password: String::new(),
                    twofa_code: String::new(),
                    needs_2fa: false,
                    error: None,
                    loading: false,
                });
                Command::none()
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        match &self.state {
            State::Loading => loading_view(),
            State::Onboarding(data) => onboarding_view(data),
            State::Login(data) => login_view(data),
            State::Browse(data) => browse_view(data),
        }
    }

    fn theme(&self) -> Theme {
        Theme::Dark
    }

    fn subscription(&self) -> Subscription<Message> {
        match &self.state {
            State::Browse(_) => {
                iced::time::every(Duration::from_secs(5)).map(|_| Message::SyncStatusTick)
            }
            _ => Subscription::none(),
        }
    }
}

// ── IPC helpers ─────────────────────────────────────────────────────────────

async fn ipc_request(method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let mut ipc = IpcClient::connect().await.map_err(|e| e.to_string())?;
    let resp = ipc
        .request(method, params)
        .await
        .map_err(|e| e.to_string())?;
    resp.result.ok_or_else(|| {
        resp.error
            .map(|e| e.message)
            .unwrap_or_else(|| "unknown error".into())
    })
}

// ── Async helpers ───────────────────────────────────────────────────────────

async fn check_auth() -> Option<Result<Session, String>> {
    let status = match ipc_request("auth.status", serde_json::json!({})).await {
        Ok(v) => v,
        Err(_) => {
            // Daemon not reachable — try to spawn it with retry.
            spawn_daemon();
            // Wait up to 5 seconds with polling.
            let mut last_err = String::new();
            for _ in 0..10 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                match ipc_request("auth.status", serde_json::json!({})).await {
                    Ok(v) => {
                        // Connected.
                        let _ = Notification::new()
                            .summary("Proton Drive")
                            .body("Daemon started")
                            .appname("Proton Drive")
                            .icon("proton-drive")
                            .timeout(2000)
                            .show();
                        return parse_auth_status(v).await;
                    }
                    Err(e) => last_err = e,
                }
            }
            return Some(Err(format!(
                "Cannot connect to daemon after multiple attempts: {last_err}"
            )));
        }
    };

    parse_auth_status(status).await
}

async fn parse_auth_status(status: serde_json::Value) -> Option<Result<Session, String>> {
    let logged_in = status
        .get("logged_in")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if logged_in {
        match keyring::load_session().await {
            Ok(Some(session)) => Some(Ok(session)),
            Ok(None) => None,
            Err(e) => Some(Err(e.to_string())),
        }
    } else {
        None
    }
}

fn spawn_daemon() {
    let socket = socket_path();
    if std::path::Path::new(&socket).exists() {
        return;
    }

    // Search in multiple locations: next to our binary, in PATH, and common build dirs.
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    let builtin = [
        "protond",
        "/usr/lib/proton-drive/protond",
        "/usr/local/lib/proton-drive/protond",
    ];

    let mut candidates: Vec<std::path::PathBuf> = Vec::new();

    // 1. Same directory as the GUI binary.
    if let Some(ref dir) = exe_dir {
        candidates.push(dir.join("protond"));
    }

    // 2. Common relative paths from build directories.
    if let Some(ref dir) = exe_dir {
        // GUI is in target/release/ or target/debug/
        let target_dir = dir.parent().and_then(|d| d.parent());
        if let Some(target) = target_dir {
            candidates.push(target.join("release").join("protond"));
            candidates.push(target.join("debug").join("protond"));
        }
        // Also try ../protond (sibling binary)
        candidates.push(dir.join("../protond"));
        candidates.push(dir.join("../../target/release/protond"));
        candidates.push(dir.join("../../target/debug/protond"));
    }

    // 3. Builtin paths.
    for p in &builtin {
        candidates.push(std::path::PathBuf::from(p));
    }

    // 4. Search PATH.
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            candidates.push(dir.join("protond"));
        }
    }

    for candidate in &candidates {
        if candidate.exists() {
            tracing::info!("starting protond from {:?}", candidate);
            match std::process::Command::new(candidate)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                Ok(_) => {
                    tracing::info!("protond spawned successfully");
                    return;
                }
                Err(e) => {
                    tracing::warn!("failed to spawn protond from {:?}: {e}", candidate);
                }
            }
        }
    }
    tracing::error!("protond binary not found in any candidate location");
}

async fn login_async(username: String, password: String) -> Result<(), String> {
    let result = ipc_request(
        "auth.login",
        serde_json::json!({
            "username": username,
            "password": password,
        }),
    )
    .await?;

    let status = result.get("status").and_then(|v| v.as_str()).unwrap_or("");
    match status {
        "success" => Ok(()),
        "2fa_required" => Err("2FA_REQUIRED".into()),
        _ => Err(format!("Unexpected login result: {result}")),
    }
}

async fn twofa_async(code: String) -> Result<(), String> {
    ipc_request("auth.2fa", serde_json::json!({ "code": code })).await?;
    Ok(())
}

async fn load_session_after_login() -> Result<Session, String> {
    keyring::load_session()
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "No session found after login".into())
}

async fn logout_async() {
    let _ = ipc_request("auth.logout", serde_json::json!({})).await;
    let _ = keyring::delete_session().await;
}

async fn build_keyring_async(
    session: Session,
    password: String,
) -> Result<(DriveKeyring, String, String), String> {
    let api = proton_core::api::ApiClient::new()
        .map_err(|e| e.to_string())?
        .with_session(session);
    let drive = DriveClient::new(api);
    drive
        .build_keyring(&password)
        .await
        .map_err(|e| e.to_string())
}

fn fetch_conflicts() -> Command<Message> {
    Command::perform(
        async {
            match ipc_request("drive.conflicts", serde_json::json!({})).await {
                Ok(v) => {
                    let items = v
                        .get("items")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let entries: Vec<ConflictEntry> = items
                        .iter()
                        .filter_map(|item| {
                            Some(ConflictEntry {
                                local_path: item.get("local_path")?.as_str()?.to_string(),
                            })
                        })
                        .collect();
                    Ok(entries)
                }
                Err(e) => Err(e),
            }
        },
        Message::ConflictsFetched,
    )
}

async fn resolve_conflict_async(local_path: String, strategy: String, password: String) -> String {
    let result = ipc_request(
        "drive.resolve",
        serde_json::json!({
            "local_path": local_path,
            "strategy": strategy,
            "password": password,
        }),
    )
    .await;

    match result {
        Ok(_) => "".to_string(),
        Err(e) => e,
    }
}

async fn create_folder_async(
    share_id: String,
    parent_link_id: String,
    folder_name: String,
    password: String,
) -> Result<String, String> {
    let result = ipc_request(
        "drive.create_folder",
        serde_json::json!({
            "share_id": share_id,
            "parent_link_id": parent_link_id,
            "folder_name": folder_name,
            "password": password,
        }),
    )
    .await?;
    let link_id = result
        .get("link_id")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    Ok(link_id)
}

async fn rename_async(
    share_id: String,
    link_id: String,
    new_name: String,
    password: String,
) -> Result<(), String> {
    ipc_request(
        "drive.rename",
        serde_json::json!({
            "share_id": share_id,
            "link_id": link_id,
            "new_name": new_name,
            "password": password,
        }),
    )
    .await?;
    Ok(())
}

async fn delete_async(share_id: String, link_id: String) -> Result<(), String> {
    ipc_request(
        "drive.delete",
        serde_json::json!({ "share_id": share_id, "link_id": link_id }),
    )
    .await?;
    Ok(())
}

async fn upload_async(
    password: String,
    share_id: String,
    parent_link_id: String,
) -> Result<String, String> {
    let file = rfd::AsyncFileDialog::new()
        .set_title("Select a file to upload")
        .pick_file()
        .await;
    let file = match file {
        Some(f) => f,
        None => return Err("No file selected".into()),
    };
    let local_path = file.path().to_string_lossy().to_string();
    let result = ipc_request(
        "drive.upload_file",
        serde_json::json!({
            "share_id": share_id,
            "parent_link_id": parent_link_id,
            "local_path": local_path,
            "password": password,
        }),
    )
    .await?;
    let link_id = result
        .get("link_id")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    Ok(link_id)
}

async fn fetch_sync_status() -> SyncStatusInfo {
    match ipc_request("drive.status", serde_json::json!({})).await {
        Ok(v) => {
            let state = v
                .get("sync_state")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let last_sync = v
                .get("last_sync")
                .and_then(|v| v.as_str())
                .map(String::from);
            let last_report = v.get("last_report").and_then(|v| {
                if v.is_null() {
                    None
                } else {
                    serde_json::from_value(v.clone()).ok()
                }
            });
            let paused = v.get("paused").and_then(|v| v.as_bool()).unwrap_or(false);
            let transfer_status = v
                .get("transfer_status")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            SyncStatusInfo {
                state,
                last_sync,
                last_report,
                error: None,
                paused,
                transfer_status,
            }
        }
        Err(e) => SyncStatusInfo {
            state: "unknown".into(),
            last_sync: None,
            last_report: None,
            error: Some(e),
            paused: false,
            transfer_status: String::new(),
        },
    }
}

async fn pause_async() -> Result<(), String> {
    ipc_request("drive.pause", serde_json::json!({})).await?;
    Ok(())
}

async fn resume_async() -> Result<(), String> {
    ipc_request("drive.resume", serde_json::json!({})).await?;
    Ok(())
}

async fn fetch_children_async(
    session: Session,
    share_id: String,
    folder_id: String,
) -> Result<Vec<DriveNode>, String> {
    let api = proton_core::api::ApiClient::new()
        .map_err(|e| e.to_string())?
        .with_session(session);
    let drive = DriveClient::new(api);
    drive
        .list_children(&share_id, &folder_id)
        .await
        .map_err(|e| e.to_string())
}

// ── View helpers ────────────────────────────────────────────────────────────

fn loading_view<'a>() -> Element<'a, Message> {
    container(
        column![
            text(t!("app_name")).size(28),
            text(t!("browse.loading")).size(16),
        ]
        .spacing(8)
        .align_items(iced::Alignment::Center),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x()
    .center_y()
    .into()
}

fn onboarding_view(data: &OnboardingData) -> Element<'_, Message> {
    use iced::alignment::Horizontal;

    let desc1 = t!("onboarding.setup_desc1", dir = &data.sync_dir);
    let col = Column::new()
        .spacing(16)
        .align_items(iced::Alignment::Center)
        .push(text(t!("onboarding.welcome")).size(28))
        .push(text(t!("onboarding.tagline")).size(14))
        .push(
            text(t!("onboarding.description"))
                .size(13)
                .width(450)
                .horizontal_alignment(Horizontal::Center),
        )
        .push(iced::widget::horizontal_rule(1))
        .push(text(t!("onboarding.sync_dir")).size(14))
        .push(
            text_input("", &data.sync_dir)
                .on_input(Message::OnboardingDirChanged)
                .width(400),
        )
        .push(
            text(desc1)
                .size(12)
                .width(450)
                .horizontal_alignment(Horizontal::Center),
        )
        .push(
            text(t!("onboarding.setup_desc2"))
                .size(12)
                .width(450)
                .horizontal_alignment(Horizontal::Center),
        )
        .push(
            button(text(t!("onboarding.get_started")))
                .on_press(Message::OnboardingDone)
                .padding(12),
        );

    container(col)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x()
        .center_y()
        .into()
}

fn login_view(data: &LoginData) -> Element<'_, Message> {
    let mut col = Column::new()
        .spacing(12)
        .align_items(iced::Alignment::Center)
        .push(text(t!("app_name")).size(28))
        .push(text(t!("auth.login_title")).size(14));

    col = col.push(
        text_input(t!("auth.username"), &data.username)
            .on_input(Message::UsernameChanged)
            .width(320),
    );

    col = col.push(
        text_input(t!("auth.password"), &data.password)
            .secure(true)
            .on_input(Message::PasswordChanged)
            .width(320),
    );

    if data.needs_2fa {
        col = col.push(
            text_input(t!("auth.twofa_code"), &data.twofa_code)
                .on_input(Message::TwoFACodeChanged)
                .width(320),
        );
    }

    let btn = if data.needs_2fa {
        button(text(t!("auth.verify_2fa"))).on_press(Message::TwoFAPressed)
    } else {
        button(text(t!("auth.sign_in"))).on_press(Message::LoginPressed)
    };

    col = if data.loading {
        col.push(button(text(t!("auth.please_wait"))))
    } else {
        col.push(btn)
    };

    if data.needs_2fa {
        col = col.push(
            text(t!("auth.enter_2fa"))
                .style(iced::Color::from_rgb(1.0, 0.8, 0.2))
                .size(14),
        );
    }

    if let Some(ref err) = data.error {
        col = col.push(
            text(err)
                .style(iced::Color::from_rgb(1.0, 0.3, 0.3))
                .size(14),
        );
    }

    container(col)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x()
        .center_y()
        .into()
}

fn browse_view(data: &BrowseData) -> Element<'_, Message> {
    let mut col = Column::new().spacing(8).padding(16);

    // Header
    let header = Row::new()
        .spacing(12)
        .align_items(iced::Alignment::Center)
        .push(text(format!("{} — {}", t!("app_name"), data.session.username)).size(20))
        .push(button(t!("auth.logout")).on_press(Message::LogoutPressed));

    col = col.push(header);

    // Sync status bar
    let mut status_text = match data.sync_state.as_str() {
        "syncing" => t!("sync.status_syncing").to_string(),
        "idle" => {
            if let Some(ref ls) = data.last_sync {
                t!("sync.status_idle_at", time = ls).to_string()
            } else {
                t!("sync.status_idle_never").to_string()
            }
        }
        _ => {
            if let Some(ref err) = data.sync_error {
                format!("⚠ {err}")
            } else {
                t!("sync.status_idle_never").to_string()
            }
        }
    };
    if data.paused {
        status_text = format!("{status_text} — ⏸ {}", t!("status.paused"));
    } else if !data.transfer_status.is_empty()
        && data.transfer_status != "Transfers are unrestricted."
    {
        status_text = format!("{status_text} — {}", data.transfer_status);
    }
    if let Some(ref report) = data.last_report {
        if !report.errors.is_empty() {
            status_text = format!(
                "{status_text} — ⚠ {}",
                t!("sync.errors", count = report.errors.len())
            );
        }
    }
    let status_color = match data.sync_state.as_str() {
        "syncing" => iced::Color::from_rgb(0.3, 0.7, 1.0),
        _ => iced::Color::from_rgb(0.5, 0.5, 0.5),
    };

    let pause_btn = if data.paused {
        button(text(t!("resume.button"))).on_press(Message::ResumePressed)
    } else {
        button(text(t!("pause.button"))).on_press(Message::PausePressed)
    };
    col = col.push(
        container(
            Row::new()
                .spacing(8)
                .align_items(iced::Alignment::Center)
                .push(text(status_text).size(12).style(status_color))
                .push(pause_btn),
        )
        .padding([4, 8])
        .width(Length::Fill),
    );

    // Decryption prompt (if keyring not built yet)
    if data.kr.is_none() {
        col = col.push(Space(Length::Fixed(0.0), Length::Fixed(16.0)));
        col = col.push(
            Row::new()
                .spacing(8)
                .align_items(iced::Alignment::Center)
                .push(text(t!("browse.decrypt_password")))
                .push(
                    text_input("Password for key decryption", &data.password)
                        .secure(true)
                        .on_input(Message::PasswordForDecryptChanged)
                        .width(250),
                )
                .push(button(text(t!("browse.decrypt"))).on_press(Message::DecryptPressed)),
        );
    }

    // Breadcrumb
    if !data.path.is_empty() {
        col = col.push(Space(Length::Fixed(0.0), Length::Fixed(8.0)));
        let mut breadcrumb = Row::new().spacing(4);
        if data.path.len() > 1 {
            breadcrumb = breadcrumb.push(button(t!("browse.back")).on_press(Message::BackPressed));
        }
        for (i, (_, name)) in data.path.iter().enumerate() {
            if i > 0 {
                breadcrumb = breadcrumb.push(text(" / "));
            }
            breadcrumb = breadcrumb.push(text(name));
        }
        col = col.push(breadcrumb);
    }

    // Loading / Error
    if data.loading {
        col = col.push(Space(Length::Fixed(0.0), Length::Fixed(8.0)));
        col = col.push(text(t!("browse.loading")));
    }

    if let Some(ref err) = data.error {
        col = col.push(Space(Length::Fixed(0.0), Length::Fixed(8.0)));
        col = col.push(
            text(err)
                .style(iced::Color::from_rgb(1.0, 0.3, 0.3))
                .size(14),
        );
    }

    // New Folder button / input
    if data.kr.is_some() {
        if data.creating_folder {
            let nf_row = Row::new()
                .spacing(8)
                .align_items(iced::Alignment::Center)
                .push(text(t!("create_folder.name")).size(14))
                .push(
                    text_input("", &data.new_folder_input)
                        .on_input(Message::NewFolderInputChanged)
                        .on_submit(Message::NewFolderConfirmed)
                        .width(250),
                )
                .push(
                    button(text(t!("create_folder.create"))).on_press(Message::NewFolderConfirmed),
                )
                .push(
                    button(text(t!("create_folder.cancel"))).on_press(Message::NewFolderCancelled),
                );
            col = col.push(nf_row);
        } else {
            col =
                col.push(button(text(t!("create_folder.new"))).on_press(Message::NewFolderPressed));
        }
        col = col.push(Space(Length::Fixed(0.0), Length::Fixed(4.0)));
    }

    // Upload button
    if data.kr.is_some() {
        let upload_btn = if data.uploading {
            button(text("Uploading…"))
        } else {
            button(text(t!("upload_file.upload"))).on_press(Message::UploadPressed)
        };
        col = col.push(upload_btn);
        col = col.push(Space(Length::Fixed(0.0), Length::Fixed(4.0)));
    }

    // File list
    if !data.files.is_empty() {
        col = col.push(Space(Length::Fixed(0.0), Length::Fixed(8.0)));
        let mut list = Column::new().spacing(2);
        for entry in &data.files {
            let icon = if entry.node.is_folder() {
                "📁"
            } else {
                "📄"
            };
            let size_str = if entry.node.is_file() {
                format!(" {:>12} B", entry.node.size)
            } else {
                String::new()
            };
            let line = Row::new()
                .spacing(8)
                .align_items(iced::Alignment::Center)
                .push(text(format!("{icon}{size_str}")).width(Length::Fixed(140.0)))
                .push({
                    let mut t = text(&entry.name);
                    if entry.node.is_file() {
                        t = t.style(iced::Color::from_rgb(0.7, 0.7, 0.7));
                    }
                    t
                })
                .push({
                    let sid = entry.node.share_id.clone();
                    let lid = entry.node.link_id.clone();
                    let ename = entry.name.clone();
                    button(text(t!("rename.rename_btn")))
                        .style(iced::theme::Button::Text)
                        .on_press(Message::RenamePressed(sid, lid, ename))
                })
                .push({
                    let sid = entry.node.share_id.clone();
                    let lid = entry.node.link_id.clone();
                    let ename = entry.name.clone();
                    button(text("🗑"))
                        .style(iced::theme::Button::Text)
                        .on_press(Message::DeletePressed(sid, lid, ename))
                });

            if entry.node.is_folder() {
                let fid = entry.node.link_id.clone();
                let ename = entry.node.encrypted_name.clone();
                list = list.push(
                    button(line)
                        .style(iced::theme::Button::Text)
                        .on_press(Message::FolderClickedEncrypted(fid, ename)),
                );
            } else {
                list = list.push(line);
            }
        }
        col = col.push(scrollable(list).height(Length::Fill));
    } else if data.kr.is_some() {
        col = col.push(text(t!("browse.no_files")).style(iced::Color::from_rgb(0.5, 0.5, 0.5)));
    }

    // Inline rename input
    if let Some((_, _, ref current_name)) = data.renaming {
        col = col.push(Space(Length::Fixed(0.0), Length::Fixed(8.0)));
        let rename_row = Row::new()
            .spacing(8)
            .align_items(iced::Alignment::Center)
            .push(text(t!("rename.rename")).size(14))
            .push(
                text_input(current_name, &data.rename_input)
                    .on_input(Message::RenameInputChanged)
                    .on_submit(Message::RenameConfirmed)
                    .width(250),
            )
            .push(button(text(t!("rename.rename"))).on_press(Message::RenameConfirmed))
            .push(button(text(t!("rename.cancel"))).on_press(Message::RenameCancelled));
        col = col.push(rename_row);
    }

    // Delete confirmation dialog
    if let Some((_, _, ref name)) = data.confirm_delete {
        col = col.push(Space(Length::Fixed(0.0), Length::Fixed(16.0)));
        let confirm_row = Row::new()
            .spacing(12)
            .align_items(iced::Alignment::Center)
            .push(
                text(t!("delete.confirm_msg", name = name))
                    .style(iced::Color::from_rgb(1.0, 0.8, 0.2))
                    .size(14),
            )
            .push(
                button(text(t!("delete.delete")))
                    .on_press(Message::DeleteConfirmed)
                    .style(iced::theme::Button::Destructive),
            )
            .push(button(text(t!("delete.cancel"))).on_press(Message::DeleteCancelled));
        col = col.push(confirm_row);
    }

    if data.deleting {
        col = col.push(
            text("Deleting...")
                .size(12)
                .style(iced::Color::from_rgb(1.0, 0.8, 0.2)),
        );
    }

    // Sync report
    if let Some(ref report) = data.last_report {
        if report.downloads_attempted > 0 || report.uploads_attempted > 0 || report.dirs_created > 0
        {
            col = col.push(Space(Length::Fixed(0.0), Length::Fixed(4.0)));
            col = col.push(
                text(format!(
                    "↓ {}↑ {}📁 {}",
                    t!(
                        "sync.downloads",
                        attempted = report.downloads_attempted,
                        succeeded = report.downloads_succeeded
                    ),
                    t!(
                        "sync.uploads",
                        attempted = report.uploads_attempted,
                        succeeded = report.uploads_succeeded
                    ),
                    t!("sync.dirs_created", count = report.dirs_created),
                ))
                .size(11)
                .style(iced::Color::from_rgb(0.4, 0.6, 0.4)),
            );
        }
        if !report.errors.is_empty() {
            col = col.push(Space(Length::Fixed(0.0), Length::Fixed(4.0)));
            col = col.push(
                text(t!("sync.errors", count = report.errors.len()))
                    .style(iced::Color::from_rgb(1.0, 0.3, 0.3))
                    .size(12),
            );
            for err in report.errors.iter().take(3) {
                col = col.push(
                    text(err)
                        .size(11)
                        .style(iced::Color::from_rgb(0.8, 0.3, 0.3)),
                );
            }
        }
    }

    // Conflict list
    if !data.conflicts.is_empty() {
        col = col.push(Space(Length::Fixed(0.0), Length::Fixed(8.0)));
        col = col.push(
            text(t!("browse.conflicts", count = data.conflicts.len()))
                .style(iced::Color::from_rgb(1.0, 0.8, 0.2))
                .size(14),
        );
        for conflict in &data.conflicts {
            let row = Row::new()
                .spacing(8)
                .align_items(iced::Alignment::Center)
                .push(text(&conflict.local_path).width(Length::Fill))
                .push(
                    button(t!("browse.keep_local")).on_press(Message::ResolveConflict(
                        conflict.local_path.clone(),
                        "local".into(),
                    )),
                )
                .push(
                    button(t!("browse.keep_remote")).on_press(Message::ResolveConflict(
                        conflict.local_path.clone(),
                        "remote".into(),
                    )),
                )
                .push(
                    button(t!("browse.rename")).on_press(Message::ResolveConflict(
                        conflict.local_path.clone(),
                        "rename_local".into(),
                    )),
                );
            col = col.push(row);
        }
    }

    container(col)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

#[allow(non_snake_case)]
fn Space(w: Length, h: Length) -> iced::widget::Space {
    iced::widget::Space::new(w, h)
}
