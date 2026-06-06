use iced::{
    widget::{button, column, container, scrollable, text, text_input, Column, Row},
    Application, Command, Element, Length, Settings, Theme,
};

use proton_core::{
    api::{ApiClient, Session},
    auth::{self, LoginResult},
    drive::{DriveClient, DriveNode, keyring::DriveKeyring},
    keyring,
};

fn main() -> iced::Result {
    ProtonDrive::run(Settings {
        window: iced::window::Settings {
            size: iced::Size { width: 800.0, height: 600.0 },
            min_size: Some(iced::Size { width: 500.0, height: 400.0 }),
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
    Login(LoginData),
    Browse(BrowseData),
}

struct LoginData {
    username: String,
    password: String,
    twofa_code: String,
    twofa_client: Option<ApiClient>,
    error: Option<String>,
    loading: bool,
}

struct BrowseData {
    session: Session,
    password: String,
    kr: Option<DriveKeyring>,
    share_id: Option<String>,
    root_link_id: Option<String>,
    current_folder_id: Option<String>,
    current_parent_key_id: Option<String>,
    path: Vec<(String, String)>,
    files: Vec<FileEntry>,
    loading: bool,
    error: Option<String>,
}

struct FileEntry {
    node: DriveNode,
    name: String,
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
    LoginDone(Result<Session, String>),
    TwoFADone(Result<Session, String>),
    CheckAuthDone(Option<Result<Session, String>>),

    // Browse
    PasswordForDecryptChanged(String),
    DecryptPressed,
    KeyringBuilt(Result<(DriveKeyring, String, String), String>),
    FolderClicked(String),
    FolderClickedEncrypted(String, String),
    BackPressed,
    FolderLoaded(Result<Vec<DriveNode>, String>),
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
            Self { state: State::Loading },
            Command::perform(check_auth(), Message::CheckAuthDone),
        )
    }

    fn title(&self) -> String {
        "Proton Drive".into()
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            // ── Auth check ─────────────────────────────────────────────
            Message::CheckAuthDone(result) => {
                match result {
                    Some(Ok(session)) => {
                        self.state = State::Browse(BrowseData {
                            session,
                            password: String::new(),
                            kr: None,
                            share_id: None,
                            root_link_id: None,
                            current_folder_id: None,
                            current_parent_key_id: None,
                            path: Vec::new(),
                            files: Vec::new(),
                            loading: false,
                            error: None,
                        });
                    }
                    Some(Err(e)) => {
                        self.state = State::Login(LoginData {
                            username: String::new(),
                            password: String::new(),
                            twofa_code: String::new(),
                            twofa_client: None,
                            error: Some(format!("Failed to load session: {e}")),
                            loading: false,
                        });
                    }
                    None => {
                        self.state = State::Login(LoginData {
                            username: String::new(),
                            password: String::new(),
                            twofa_code: String::new(),
                            twofa_client: None,
                            error: None,
                            loading: false,
                        });
                    }
                }
                Command::none()
            }

            // ── Login ────────────────────────────────────────────────
            Message::UsernameChanged(v) => {
                if let State::Login(ref mut d) = self.state { d.username = v; }
                Command::none()
            }
            Message::PasswordChanged(v) => {
                if let State::Login(ref mut d) = self.state { d.password = v; }
                Command::none()
            }
            Message::TwoFACodeChanged(v) => {
                if let State::Login(ref mut d) = self.state { d.twofa_code = v; }
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
                    if let Some(ref client) = d.twofa_client {
                        d.loading = true;
                        d.error = None;
                        let code = d.twofa_code.clone();
                        let client_uid = client.session().map(|s| s.uid.clone());
                        let client_at = client.session().map(|s| s.access_token.clone());
                        let client_rt = client.session().map(|s| s.refresh_token.clone());
                        let client_un = client.session().map(|s| s.username.clone());
                        return Command::perform(
                            twofa_async(code, client_uid, client_at, client_rt, client_un),
                            Message::TwoFADone,
                        );
                    }
                }
                Command::none()
            }
            Message::LoginDone(result) => {
                if let State::Login(ref mut d) = self.state {
                    d.loading = false;
                    match result {
                        Ok(session) => {
                            self.state = State::Browse(BrowseData {
                                session,
                                password: String::new(),
                                kr: None,
                                share_id: None,
                                root_link_id: None,
                                current_folder_id: None,
                                current_parent_key_id: None,
                                path: Vec::new(),
                                files: Vec::new(),
                                loading: false,
                                error: None,
                            });
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
                    d.twofa_client = None;
                    match result {
                        Ok(session) => {
                            self.state = State::Browse(BrowseData {
                                session,
                                password: String::new(),
                                kr: None,
                                share_id: None,
                                root_link_id: None,
                                current_folder_id: None,
                                current_parent_key_id: None,
                                path: Vec::new(),
                                files: Vec::new(),
                                loading: false,
                                error: None,
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
                if let State::Browse(ref mut d) = self.state { d.password = v; }
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
                            // Load root folder
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
            Message::FolderClicked(folder_id) => {
                if let State::Browse(ref mut d) = self.state {
                    d.loading = true;
                    // The parent key for children is this folder's link_id
                    d.current_parent_key_id = Some(folder_id.clone());
                    let share_id = d.share_id.clone().unwrap_or_default();
                    return Command::perform(
                        fetch_children_async(d.session.clone(), share_id, folder_id),
                        Message::FolderLoaded,
                    );
                }
                Command::none()
            }
            Message::FolderClickedEncrypted(folder_id, _name) => {
                // Same as FolderClicked but we don't need the name here
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
                        // Restore parent key to the folder we're going back to
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
                            let parent_key_id = d.current_parent_key_id
                                .clone()
                                .unwrap_or_else(|| d.root_link_id.clone().unwrap_or_default());
                            let mut entries = Vec::new();
                            if let Some(ref mut kr) = d.kr {
                                for node in &children {
                                    let name = kr
                                        .decrypt_name_raw(&node.encrypted_name, &parent_key_id)
                                        .unwrap_or_else(|_| node.encrypted_name.clone());
                                    // Unlock folder keys for future navigation
                                    if node.is_folder() && node.is_active() {
                                        let _ = kr
                                            .unlock_with_parent(
                                                &node.link_id,
                                                &parent_key_id,
                                                &node.node_key,
                                                &node.node_passphrase,
                                            );
                                    }
                                    entries.push(FileEntry { node: node.clone(), name });
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

            // ── Logout ──────────────────────────────────────────────
            Message::LogoutPressed => {
                if let State::Browse(ref d) = self.state {
                    let session = d.session.clone();
                    return Command::perform(logout_async(session), |_| Message::LogoutDone);
                }
                Command::none()
            }
            Message::LogoutDone => {
                self.state = State::Login(LoginData {
                    username: String::new(),
                    password: String::new(),
                    twofa_code: String::new(),
                    twofa_client: None,
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
            State::Login(data) => login_view(data),
            State::Browse(data) => browse_view(data),
        }
    }

    fn theme(&self) -> Theme {
        Theme::Dark
    }
}

// ── Async helpers ───────────────────────────────────────────────────────────

async fn check_auth() -> Option<Result<Session, String>> {
    match keyring::load_session().await {
        Ok(Some(session)) => Some(Ok(session)),
        Ok(None) => None,
        Err(e) => Some(Err(e.to_string())),
    }
}

async fn login_async(username: String, password: String) -> Result<Session, String> {
    match auth::login(&username, &password).await {
        Ok(LoginResult::Success(session)) => {
            keyring::save_session(&session).await.map_err(|e| e.to_string())?;
            Ok(session)
        }
        Ok(LoginResult::TwoFactorRequired(client)) => {
            // Send back the client's session data so we can reconstruct it
            Err(format!("2FA_REQUIRED:{}", serde_json::to_string(&client.session().ok_or("no session")?).map_err(|e| e.to_string())?))
        }
        Err(e) => Err(e.to_string()),
    }
}

async fn twofa_async(
    code: String,
    uid: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    username: Option<String>,
) -> Result<Session, String> {
    let session = Session {
        uid: uid.ok_or("missing uid")?,
        access_token: access_token.ok_or("missing access_token")?,
        refresh_token: refresh_token.ok_or("missing refresh_token")?,
        username: username.ok_or("missing username")?,
    };
    let client = ApiClient::new()
        .map_err(|e| e.to_string())?
        .with_session(session.clone());
    let session = auth::complete_2fa(&client, &code)
        .await
        .map_err(|e| e.to_string())?;
    keyring::save_session(&session).await.map_err(|e| e.to_string())?;
    Ok(session)
}

async fn build_keyring_async(
    session: Session,
    password: String,
) -> Result<(DriveKeyring, String, String), String> {
    let api = ApiClient::new()
        .map_err(|e| e.to_string())?
        .with_session(session);
    let drive = DriveClient::new(api);
    drive
        .build_keyring(&password)
        .await
        .map_err(|e| e.to_string())
}

async fn fetch_children_async(
    session: Session,
    share_id: String,
    folder_id: String,
) -> Result<Vec<DriveNode>, String> {
    let api = ApiClient::new()
        .map_err(|e| e.to_string())?
        .with_session(session);
    let drive = DriveClient::new(api);
    drive
        .list_children(&share_id, &folder_id)
        .await
        .map_err(|e| e.to_string())
}

async fn logout_async(session: Session) {
    let _ = auth::logout(&session).await;
    let _ = keyring::delete_session().await;
}

// ── View helpers ────────────────────────────────────────────────────────────

fn loading_view<'a>() -> Element<'a, Message> {
    container(
        column![
            text("Proton Drive").size(28),
            text("Loading…").size(16),
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

fn login_view(data: &LoginData) -> Element<'_, Message> {
    let mut col = Column::new()
        .spacing(12)
        .align_items(iced::Alignment::Center)
        .push(text("Proton Drive").size(28))
        .push(text("Sign in to your Proton account").size(14));

    col = col.push(text_input("Username or email", &data.username)
        .on_input(Message::UsernameChanged)
        .width(320));

    col = col.push(text_input("Password", &data.password)
        .secure(true)
        .on_input(Message::PasswordChanged)
        .width(320));

    if data.twofa_client.is_some() {
        col = col.push(text_input("2FA Code (TOTP)", &data.twofa_code)
            .on_input(Message::TwoFACodeChanged)
            .width(320));
    }

    let btn = if data.twofa_client.is_some() {
        button(text("Verify 2FA")).on_press(Message::TwoFAPressed)
    } else {
        button(text("Sign In")).on_press(Message::LoginPressed)
    };

    col = if data.loading {
        col.push(button(text("Please wait…")))
    } else {
        col.push(btn)
    };

    if let Some(ref err) = data.error {
        if err.starts_with("2FA_REQUIRED:") {
            // This means we need to ask for 2FA - reconstruct the client
            // We handle this via state transition instead
            col = col.push(text("2FA code required. Enter your TOTP code above.").style(iced::Color::from_rgb(1.0, 0.8, 0.2)));
        } else {
            col = col.push(text(err).style(iced::Color::from_rgb(1.0, 0.3, 0.3)).size(14));
        }
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
        .push(
            text(format!("Proton Drive — {}", data.session.username))
                .size(20),
        )
        .push(button("Logout").on_press(Message::LogoutPressed));

    col = col.push(header);

    // Decryption prompt (if keyring not built yet)
    if data.kr.is_none() {
        col = col.push(Space(Length::Fixed(0.0), Length::Fixed(16.0)));
        col = col.push(
            Row::new()
                .spacing(8)
                .align_items(iced::Alignment::Center)
                .push(text("Decryption password:"))
                .push(
                    text_input("Password for key decryption", &data.password)
                        .secure(true)
                        .on_input(Message::PasswordForDecryptChanged)
                        .width(250),
                )
                .push(
                    button(text("Decrypt")).on_press(Message::DecryptPressed),
                ),
        );
    }

    // Breadcrumb
    if !data.path.is_empty() {
        col = col.push(Space(Length::Fixed(0.0), Length::Fixed(8.0)));
        let mut breadcrumb = Row::new().spacing(4);
        if data.path.len() > 1 {
            breadcrumb = breadcrumb
                .push(button("← Back").on_press(Message::BackPressed));
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
        col = col.push(text("Loading…"));
    }

    if let Some(ref err) = data.error {
        col = col.push(Space(Length::Fixed(0.0), Length::Fixed(8.0)));
        col = col.push(text(err).style(iced::Color::from_rgb(1.0, 0.3, 0.3)).size(14));
    }

    // File list
    if !data.files.is_empty() {
        col = col.push(Space(Length::Fixed(0.0), Length::Fixed(8.0)));
        let mut list = Column::new().spacing(2);
        for entry in &data.files {
            let icon = if entry.node.is_folder() { "📁" } else { "📄" };
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
        // Keyring built but no files = success or empty
        col = col.push(text("No files found or press Decrypt to browse").style(iced::Color::from_rgb(0.5, 0.5, 0.5)));
    }

    container(col).width(Length::Fill).height(Length::Fill).into()
}

fn Space(w: Length, h: Length) -> iced::widget::Space {
    iced::widget::Space::new(w, h)
}
