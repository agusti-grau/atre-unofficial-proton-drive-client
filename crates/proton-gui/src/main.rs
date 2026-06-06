use std::time::Duration;

use iced::{
    widget::{button, column, container, scrollable, text, text_input, Column, Row},
    Application, Command, Element, Length, Settings, Theme,
};

use proton_core::{
    api::Session,
    drive::{keyring::DriveKeyring, DriveClient, DriveNode},
    ipc::{socket_path, IpcClient},
    keyring, t,
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
            ..Default::default()
        },
        ..Default::default()
    })
}

// ── App ─────────────────────────────────────────────────────────────────────

struct ProtonDrive {
    state: State,
}

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
    error: Option<String>,
}

struct FileEntry {
    node: DriveNode,
    name: String,
}

#[derive(Debug, Clone)]
struct ConflictEntry {
    local_path: String,
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
                            error: None,
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
                return Command::perform(
                    resolve_conflict_async(local_path, strategy, password),
                    Message::ResolveDone,
                );
            }
            Message::ResolveDone(path) => {
                if !path.is_empty() {
                    // Re-fetch conflicts.
                    return fetch_conflicts();
                }
                Command::none()
            }

            // ── Logout ──────────────────────────────────────────────
            Message::LogoutPressed => {
                return Command::perform(logout_async(), |_| Message::LogoutDone);
            }
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
            // Daemon not reachable — try to spawn it.
            spawn_daemon();
            tokio::time::sleep(Duration::from_millis(1500)).await;
            match ipc_request("auth.status", serde_json::json!({})).await {
                Ok(v) => v,
                Err(e) => return Some(Err(format!("Cannot connect to daemon: {e}"))),
            }
        }
    };

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
    // If socket already exists, daemon is (probably) running.
    if std::path::Path::new(&socket).exists() {
        return;
    }

    let candidates = [
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("protond"))),
        Some(std::path::PathBuf::from("protond")),
        Some(std::path::PathBuf::from("../target/release/protond")),
        Some(std::path::PathBuf::from("../target/debug/protond")),
        Some(std::path::PathBuf::from("../../target/release/protond")),
        Some(std::path::PathBuf::from("../../target/debug/protond")),
    ];

    for candidate in candidates.into_iter().flatten() {
        if candidate.exists() {
            let _ = std::process::Command::new(&candidate)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            return;
        }
    }
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
                .push(text(format!("{icon}{size_str}")).width(Length::Fixed(180.0)))
                .push({
                    let mut t = text(&entry.name);
                    if entry.node.is_file() {
                        t = t.style(iced::Color::from_rgb(0.7, 0.7, 0.7));
                    }
                    t
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
