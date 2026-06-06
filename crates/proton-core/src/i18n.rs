use std::collections::HashMap;
use std::sync::OnceLock;

type Translations = HashMap<&'static str, HashMap<&'static str, &'static str>>;

fn translations() -> &'static Translations {
    static DATA: OnceLock<Translations> = OnceLock::new();
    DATA.get_or_init(|| {
        let mut m: Translations = HashMap::new();

        // English
        let mut en = HashMap::new();
        en.insert("app_name", "Proton Drive");
        en.insert("auth.login_title", "Sign in to your Proton account");
        en.insert("auth.username", "Username or email");
        en.insert("auth.password", "Password");
        en.insert("auth.twofa_code", "2FA Code (TOTP)");
        en.insert("auth.sign_in", "Sign In");
        en.insert("auth.verify_2fa", "Verify 2FA");
        en.insert("auth.please_wait", "Please wait...");
        en.insert("auth.enter_2fa", "Enter your 2FA code to continue.");
        en.insert("auth.logout", "Logout");
        en.insert("browse.decrypt_password", "Decryption password:");
        en.insert("browse.decrypt", "Decrypt");
        en.insert("browse.back", "← Back");
        en.insert("browse.no_files", "No files found or press Decrypt to browse");
        en.insert("browse.loading", "Loading...");
        en.insert("browse.conflicts", "⚠ {count} conflict(s) — resolve below:");
        en.insert("browse.keep_local", "Keep Local");
        en.insert("browse.keep_remote", "Keep Remote");
        en.insert("browse.rename", "Rename");
        en.insert("status.logged_in", "Logged in as {username}");
        en.insert("status.not_logged_in", "Not logged in");
        en.insert("status.db_status", "DB: {total} total nodes ({synced} synced, {pending} pending)");
        en.insert("status.last_sync", "Last sync: {time}");
        en.insert("sync.downloading", "Downloading {path}");
        en.insert("sync.uploading", "Uploading {path}");
        en.insert("sync.completed", "Sync completed");
        en.insert("sync.errors", "Sync completed with {count} error(s)");
        en.insert("sync.downloads", "Downloads: {attempted} attempted, {succeeded} succeeded");
        en.insert("sync.uploads", "Uploads: {attempted} attempted, {succeeded} succeeded");
        en.insert("sync.dirs_created", "Directories created: {count}");
        en.insert("conflict.no_conflicts", "No conflicts detected.");
        en.insert("conflict.resolved", "Conflict resolved: {strategy} wins for {path}");
        en.insert("general.error", "Error: {message}");
        en.insert("onboarding.welcome", "Welcome to Proton Drive");
        en.insert("onboarding.tagline", "End-to-end encrypted cloud storage for Linux");
        en.insert("onboarding.description", "Proton Drive keeps your files synchronized between your computer and Proton's encrypted servers, so you always have access — even if something happens to your device.");
        en.insert("onboarding.sync_dir", "Sync directory:");
        en.insert("onboarding.sync_dir_default", "~/Proton Drive");
        en.insert("onboarding.setup_desc1", "Files placed in your local {dir} folder will be automatically uploaded to your Proton Drive.");
        en.insert("onboarding.setup_desc2", "Your files are encrypted before they leave your device — nobody but you can read them.");
        en.insert("onboarding.get_started", "Get Started");
        m.insert("en", en);

        // Catalan
        let mut ca = HashMap::new();
        ca.insert("app_name", "Proton Drive");
        ca.insert("auth.login_title", "Inicia sessió al teu compte de Proton");
        ca.insert("auth.username", "Usuari o correu electrònic");
        ca.insert("auth.password", "Contrasenya");
        ca.insert("auth.twofa_code", "Codi 2FA (TOTP)");
        ca.insert("auth.sign_in", "Inicia sessió");
        ca.insert("auth.verify_2fa", "Verifica 2FA");
        ca.insert("auth.please_wait", "Espereu si us plau...");
        ca.insert("auth.enter_2fa", "Introduïu el vostre codi 2FA per continuar.");
        ca.insert("auth.logout", "Tanca sessió");
        ca.insert("browse.decrypt_password", "Contrasenya de desxifrat:");
        ca.insert("browse.decrypt", "Desxifra");
        ca.insert("browse.back", "← Enrere");
        ca.insert("browse.no_files", "No s'han trobat fitxers o premeu Desxifra per navegar");
        ca.insert("browse.loading", "Carregant...");
        ca.insert("browse.conflicts", "⚠ {count} conflicte(s) — resoleu a sota:");
        ca.insert("browse.keep_local", "Mantén local");
        ca.insert("browse.keep_remote", "Mantén remot");
        ca.insert("browse.rename", "Reanomena");
        ca.insert("status.logged_in", "Sessió iniciada com a {username}");
        ca.insert("status.not_logged_in", "No has iniciat sessió");
        ca.insert("status.db_status", "BD: {total} nodes totals ({synced} sincronitzats, {pending} pendents)");
        ca.insert("status.last_sync", "Darrera sincronització: {time}");
        ca.insert("sync.downloading", "Baixant {path}");
        ca.insert("sync.uploading", "Pujant {path}");
        ca.insert("sync.completed", "Sincronització completada");
        ca.insert("sync.errors", "Sincronització completada amb {count} error(s)");
        ca.insert("sync.downloads", "Baixades: {attempted} intentades, {succeeded} amb èxit");
        ca.insert("sync.uploads", "Pujades: {attempted} intentades, {succeeded} amb èxit");
        ca.insert("sync.dirs_created", "Directoris creats: {count}");
        ca.insert("conflict.no_conflicts", "No s'han detectat conflictes.");
        ca.insert("conflict.resolved", "Conflicte resolt: {strategy} guanya per a {path}");
        ca.insert("general.error", "Error: {message}");
        ca.insert("onboarding.welcome", "Benvingut/da a Proton Drive");
        ca.insert("onboarding.tagline", "Emmagatzematge al núvol xifrat d'extrem a extrem per a Linux");
        ca.insert("onboarding.description", "Proton Drive manté els vostres fitxers sincronitzats entre el vostre ordinador i els servidors xifrats de Proton, perquè sempre hi tingueu accés — fins i tot si li passa alguna cosa al vostre dispositiu.");
        ca.insert("onboarding.sync_dir", "Directori de sincronització:");
        ca.insert("onboarding.sync_dir_default", "~/Proton Drive");
        ca.insert("onboarding.setup_desc1", "Els fitxers col·locats a la vostra carpeta local {dir} es pujaran automàticament al vostre Proton Drive.");
        ca.insert("onboarding.setup_desc2", "Els vostres fitxers es xifren abans de sortir del vostre dispositiu — ningú més que vosaltres pot llegir-los.");
        ca.insert("onboarding.get_started", "Comença");
        m.insert("ca", ca);

        m
    })
}

fn get_locale() -> &'static str {
    // Check env var, then system locale
    if let Ok(lang) = std::env::var("PROTON_LANG") {
        return Box::leak(lang.into_boxed_str());
    }
    // Check system locale
    if let Ok(lang) = std::env::var("LANG") {
        if lang.starts_with("ca") {
            return "ca";
        }
    }
    "en"
}

/// Look up a key with no arguments — returns `&'static str`.
pub fn t_static(key: &str) -> &'static str {
    let locale = get_locale();
    let dict = translations()
        .get(locale)
        .or_else(|| translations().get("en"));
    if let Some(dict) = dict {
        if let Some(val) = dict.get(key) {
            return val;
        }
    }
    // Fallback: leak the key as a static str
    Box::leak(key.to_string().into_boxed_str())
}

/// Translate a key with optional replacements.
/// Example: `t!("browse.conflicts", count = 3)` -> "⚠ 3 conflict(s) — resolve below:"
#[macro_export]
macro_rules! t {
    ($key:expr) => {{
        $crate::i18n::t_static($key)
    }};
    ($key:expr, $($k:ident = $v:expr),*) => {{
        let args: Vec<(&str, String)> = vec![$((stringify!($k), $v.to_string())),*];
        $crate::i18n::translate($key, &args)
    }};
}

pub fn translate(key: &str, args: &[(&str, String)]) -> String {
    let locale = get_locale();
    let dict = translations()
        .get(locale)
        .or_else(|| translations().get("en"));

    if let Some(dict) = dict {
        if let Some(template) = dict.get(key) {
            let mut s = template.to_string();
            for (k, v) in args {
                s = s.replace(&format!("{{{}}}", k), v);
            }
            return s;
        }
    }

    // Fallback: return the key itself
    key.to_string()
}

pub fn current_locale() -> &'static str {
    get_locale()
}

pub fn set_locale(locale: &str) {
    std::env::set_var("PROTON_LANG", locale);
}
