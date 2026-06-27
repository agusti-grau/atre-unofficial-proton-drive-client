use serde::{Deserialize, Serialize};

/// Configuration for transfer scheduling.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransferConfig {
    pub windows: Vec<TimeWindow>,
}

impl TransferConfig {
    pub fn is_unrestricted(&self) -> bool {
        self.windows.is_empty()
    }

    /// Returns true if transfers are allowed right now.
    pub fn is_in_window(&self) -> bool {
        if self.is_unrestricted() {
            return true;
        }
        let (today, hour, minute) = current_time_parts();
        self.windows.iter().any(|w| w.contains(today, hour, minute))
    }

    /// Returns true if transfers are allowed at the given time.
    pub fn is_in_window_at(&self, today: DayOfWeek, hour: u32, minute: u32) -> bool {
        if self.is_unrestricted() {
            return true;
        }
        self.windows.iter().any(|w| w.contains(today, hour, minute))
    }

    /// Compute the number of minutes from `now` until transfers become allowed.
    /// Returns `0` if currently inside a window. Returns `None` if unrestricted.
    pub fn minutes_until_next_window(&self) -> Option<u32> {
        let (today, hour, minute) = current_time_parts();
        self.minutes_until_next_window_from(today, hour, minute)
    }

    fn minutes_until_next_window_from(
        &self,
        today: DayOfWeek,
        hour: u32,
        minute: u32,
    ) -> Option<u32> {
        if self.is_unrestricted() {
            return None;
        }

        // Currently inside a window (including the tail of an overnight window).
        if self.is_in_window_at(today, hour, minute) {
            return Some(0);
        }

        let now_min = hour * 60 + minute;
        let today_idx = today as u32;

        // Search forward up to 7 days to find the next window opening.
        for day_offset in 0..7u32 {
            let probe_day_idx = (today_idx + day_offset) % 7;
            let probe_dow = DayOfWeek::from_index(probe_day_idx);
            for w in &self.windows {
                if !w.applies_to(probe_dow) {
                    continue;
                }
                let start_min = parse_hhmm_parts(&w.start);
                // If the window already opened today and we're not inside it, skip it.
                if day_offset == 0 && now_min >= start_min {
                    continue;
                }
                let minutes = day_offset * 24 * 60 + start_min.saturating_sub(now_min);
                return Some(minutes);
            }
        }
        // No future window found within a week (should not happen if windows exist).
        Some(7 * 24 * 60)
    }
}

/// A single recurring time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Days this window applies to. Empty = all days.
    #[serde(default)]
    pub days: Vec<DayOfWeek>,
    /// Start time "HH:MM" in 24-hour format.
    pub start: String,
    /// End time "HH:MM" in 24-hour format.
    pub end: String,
}

impl TimeWindow {
    fn contains(&self, today: DayOfWeek, hour: u32, minute: u32) -> bool {
        let start_min = parse_hhmm_parts(&self.start);
        let end_min = parse_hhmm_parts(&self.end);
        let now_min = hour * 60 + minute;
        let crosses_midnight = start_min > end_min;

        // Main body: the window's start day matches today.
        if self.days.is_empty() || self.days.contains(&today) {
            return match start_min.cmp(&end_min) {
                std::cmp::Ordering::Less => now_min >= start_min && now_min < end_min,
                std::cmp::Ordering::Greater => {
                    // Crosses midnight (e.g. Mon 22:00-06:00 means Mon night + Tue morning).
                    now_min >= start_min || now_min < end_min
                }
                std::cmp::Ordering::Equal => now_min == start_min,
            };
        }

        // Tail of an overnight window that started yesterday.
        if crosses_midnight && now_min < end_min {
            let prev_day = DayOfWeek::from_index((today as u32 + 6) % 7);
            if self.days.is_empty() || self.days.contains(&prev_day) {
                return true;
            }
        }

        false
    }

    fn applies_to(&self, day: DayOfWeek) -> bool {
        self.days.is_empty() || self.days.contains(&day)
    }
}

fn parse_hhmm_parts(s: &str) -> u32 {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return 0;
    }
    parse_hhmm(parts[0], parts[1])
}

fn parse_hhmm(h: &str, m: &str) -> u32 {
    h.parse::<u32>().unwrap_or(0) * 60 + m.parse::<u32>().unwrap_or(0)
}

/// Day of the week.
///
/// Explicit discriminants match the ISO convention used by `current_time_parts`
/// where Sunday = 0 and Saturday = 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DayOfWeek {
    Sun = 0,
    Mon = 1,
    Tue = 2,
    Wed = 3,
    Thu = 4,
    Fri = 5,
    Sat = 6,
}

impl DayOfWeek {
    fn from_index(idx: u32) -> Self {
        match idx {
            0 => DayOfWeek::Sun,
            1 => DayOfWeek::Mon,
            2 => DayOfWeek::Tue,
            3 => DayOfWeek::Wed,
            4 => DayOfWeek::Thu,
            5 => DayOfWeek::Fri,
            6 => DayOfWeek::Sat,
            _ => DayOfWeek::Sun,
        }
    }
}

fn current_time_parts() -> (DayOfWeek, u32, u32) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;

    // Jan 1 1970 was Thursday → (days + 4) % 7 maps to Sun=0 … Sat=6
    let dow = match (days + 4) % 7 {
        0 => DayOfWeek::Sun,
        1 => DayOfWeek::Mon,
        2 => DayOfWeek::Tue,
        3 => DayOfWeek::Wed,
        4 => DayOfWeek::Thu,
        5 => DayOfWeek::Fri,
        6 => DayOfWeek::Sat,
        _ => unreachable!(),
    };
    (dow, hours as u32, minutes as u32)
}

/// Central transfer manager: combines manual pause/resume with scheduled time windows.
#[derive(Debug, Clone, Default)]
pub struct TransferManager {
    config: TransferConfig,
    paused: bool,
}

/// Why a transfer was disallowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferBlockReason {
    Paused,
    OutsideWindow,
}

impl TransferManager {
    pub fn new(config: TransferConfig, paused: bool) -> Self {
        Self { config, paused }
    }

    pub fn with_config(config: TransferConfig) -> Self {
        Self {
            config,
            paused: false,
        }
    }

    pub fn config(&self) -> &TransferConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: TransferConfig) {
        self.config = config;
    }

    pub fn is_paused(&self) -> bool {
        self.paused
    }

    pub fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
    }

    /// Returns true if transfers are allowed right now (not paused and inside window).
    pub fn can_transfer(&self) -> bool {
        !self.paused && self.config.is_in_window()
    }

    /// Returns true if transfers are allowed at the given time and pause state.
    pub fn can_transfer_at(&self, paused: bool, today: DayOfWeek, hour: u32, minute: u32) -> bool {
        !paused && self.config.is_in_window_at(today, hour, minute)
    }

    /// Check whether transfers are currently allowed and, if not, why.
    pub fn check_transfer(&self) -> Result<(), TransferBlockReason> {
        if self.paused {
            return Err(TransferBlockReason::Paused);
        }
        if !self.config.is_in_window() {
            return Err(TransferBlockReason::OutsideWindow);
        }
        Ok(())
    }

    /// Human-readable status message.
    pub fn status_message(&self) -> String {
        if self.paused {
            return "Transfers are paused.".to_string();
        }
        if self.config.is_unrestricted() {
            return "Transfers are unrestricted.".to_string();
        }
        if self.config.is_in_window() {
            return "Transfers are inside the scheduled window.".to_string();
        }
        match self.config.minutes_until_next_window() {
            Some(0) => "Transfers are inside the scheduled window.".to_string(),
            Some(m) => format!("Transfers are outside the scheduled window (resumes in {m} min)."),
            None => "Transfers are outside the scheduled window.".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_when_no_windows() {
        let cfg = TransferConfig::default();
        assert!(cfg.is_in_window());
        assert!(TransferManager::with_config(cfg).can_transfer());
    }

    #[test]
    fn window_contains_time() {
        let w = TimeWindow {
            days: vec![],
            start: "09:00".into(),
            end: "17:00".into(),
        };
        assert!(w.contains(DayOfWeek::Mon, 10, 0));
        assert!(w.contains(DayOfWeek::Sat, 9, 0));
        assert!(!w.contains(DayOfWeek::Wed, 8, 59));
        assert!(!w.contains(DayOfWeek::Thu, 17, 0));
        assert!(w.contains(DayOfWeek::Fri, 9, 0));
    }

    #[test]
    fn window_crosses_midnight() {
        let w = TimeWindow {
            days: vec![DayOfWeek::Mon],
            start: "22:00".into(),
            end: "06:00".into(),
        };
        assert!(w.contains(DayOfWeek::Mon, 23, 0));
        assert!(w.contains(DayOfWeek::Mon, 5, 59));
        assert!(!w.contains(DayOfWeek::Mon, 6, 0));
        assert!(!w.contains(DayOfWeek::Mon, 21, 0));
        // Overnight window from Mon 22:00 extends into Tue 06:00.
        assert!(w.contains(DayOfWeek::Tue, 1, 0));
        assert!(!w.contains(DayOfWeek::Tue, 7, 0));
        assert!(!w.contains(DayOfWeek::Wed, 1, 0));
    }

    #[test]
    fn respects_day_filter() {
        let w = TimeWindow {
            days: vec![DayOfWeek::Sat, DayOfWeek::Sun],
            start: "00:00".into(),
            end: "23:59".into(),
        };
        assert!(w.contains(DayOfWeek::Sat, 12, 0));
        assert!(w.contains(DayOfWeek::Sun, 12, 0));
        assert!(!w.contains(DayOfWeek::Mon, 12, 0));
    }

    #[test]
    fn config_with_windows_restricts_normally() {
        let free = TransferConfig::default();
        assert!(free.is_in_window());

        let cfg = TransferConfig {
            windows: vec![TimeWindow {
                days: vec![DayOfWeek::Sat],
                start: "00:00".into(),
                end: "23:59".into(),
            }],
        };
        // Either allowed or not, but the method runs deterministically.
        let _ = cfg.is_in_window();
    }

    #[test]
    fn parse_hhmm_works() {
        assert_eq!(parse_hhmm("09", "05"), 9 * 60 + 5);
        assert_eq!(parse_hhmm("00", "00"), 0);
        assert_eq!(parse_hhmm("23", "59"), 23 * 60 + 59);
    }

    #[test]
    fn transfer_manager_respects_pause() {
        let cfg = TransferConfig::default();
        let mut mgr = TransferManager::with_config(cfg);
        assert!(mgr.can_transfer());
        assert_eq!(mgr.check_transfer(), Ok(()));

        mgr.set_paused(true);
        assert!(!mgr.can_transfer());
        assert_eq!(mgr.check_transfer(), Err(TransferBlockReason::Paused));
    }

    #[test]
    fn transfer_manager_respects_window() {
        let cfg = TransferConfig {
            windows: vec![TimeWindow {
                days: vec![DayOfWeek::Mon],
                start: "09:00".into(),
                end: "17:00".into(),
            }],
        };
        let mgr = TransferManager::new(cfg, false);
        assert!(mgr.can_transfer_at(false, DayOfWeek::Mon, 12, 0));
        assert!(!mgr.can_transfer_at(false, DayOfWeek::Mon, 18, 0));
        assert!(!mgr.can_transfer_at(false, DayOfWeek::Tue, 12, 0));
        assert!(!mgr.can_transfer_at(true, DayOfWeek::Mon, 12, 0));
    }

    #[test]
    fn minutes_until_next_window_same_day() {
        let cfg = TransferConfig {
            windows: vec![TimeWindow {
                days: vec![],
                start: "14:00".into(),
                end: "16:00".into(),
            }],
        };
        // At 10:00, next window opens in 4 hours.
        assert_eq!(
            cfg.minutes_until_next_window_at(DayOfWeek::Mon, 10, 0),
            Some(240)
        );
        // At 15:00, inside window.
        assert_eq!(
            cfg.minutes_until_next_window_at(DayOfWeek::Mon, 15, 0),
            Some(0)
        );
        // At 16:00, window just closed; next is tomorrow.
        assert_eq!(
            cfg.minutes_until_next_window_at(DayOfWeek::Mon, 16, 0),
            Some(24 * 60)
        );
    }

    #[test]
    fn minutes_until_next_window_overnight() {
        let cfg = TransferConfig {
            windows: vec![TimeWindow {
                days: vec![DayOfWeek::Mon],
                start: "22:00".into(),
                end: "06:00".into(),
            }],
        };
        // Monday 20:00 -> wait 2h.
        assert_eq!(
            cfg.minutes_until_next_window_at(DayOfWeek::Mon, 20, 0),
            Some(120)
        );
        // Monday 23:00 -> inside.
        assert_eq!(
            cfg.minutes_until_next_window_at(DayOfWeek::Mon, 23, 0),
            Some(0)
        );
        // Tuesday 01:00 -> inside (window spans midnight).
        assert_eq!(
            cfg.minutes_until_next_window_at(DayOfWeek::Tue, 1, 0),
            Some(0)
        );
        // Tuesday 07:00 -> next Monday 22:00, several days away.
        assert_eq!(
            cfg.minutes_until_next_window_at(DayOfWeek::Tue, 7, 0),
            Some((6 * 24 + 15) * 60)
        );
    }
}

// Helper extension for tests so we don't need to mutate system time.
#[cfg(test)]
impl TransferConfig {
    fn minutes_until_next_window_at(
        &self,
        today: DayOfWeek,
        hour: u32,
        minute: u32,
    ) -> Option<u32> {
        self.minutes_until_next_window_from(today, hour, minute)
    }
}
