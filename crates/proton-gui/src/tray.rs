use crossbeam_channel::{unbounded, Receiver};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem},
    TrayIconBuilder,
};

pub enum TrayMessage {
    Show,
    Hide,
    Quit,
}

pub struct Tray {
    _tray: tray_icon::TrayIcon,
    rx: Receiver<TrayMessage>,
}

impl Tray {
    pub fn new() -> Self {
        let (tx, rx) = unbounded();

        // Create menu items – each gets a unique string-based id so we can
        // identify them in the global MenuEvent stream.
        let show = MenuItem::with_id("show", "Show Proton Drive", true, None);
        let hide = MenuItem::with_id("hide", "Hide", true, None);
        let quit = MenuItem::with_id("quit", "Quit", true, None);

        let menu = Menu::with_items(&[&show, &hide, &quit]).expect("Failed to create tray menu");

        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Proton Drive")
            .build()
            .expect("Failed to create tray icon");

        // Forward muda MenuEvents (fired when a menu item is clicked) into
        // our own crossbeam channel so the rest of the application can react.
        std::thread::spawn(move || {
            while let Ok(event) = MenuEvent::receiver().recv() {
                let msg = match event.id().as_ref() {
                    "show" => TrayMessage::Show,
                    "hide" => TrayMessage::Hide,
                    "quit" => TrayMessage::Quit,
                    _ => continue,
                };
                if tx.send(msg).is_err() {
                    break;
                }
            }
        });

        Self { _tray: tray, rx }
    }

    pub fn receiver(&self) -> &Receiver<TrayMessage> {
        &self.rx
    }
}
