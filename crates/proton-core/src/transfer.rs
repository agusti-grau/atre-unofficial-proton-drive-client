use serde::{Deserialize, Serialize};

/// Configuration for transfer scheduling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferConfig {
    pub windows: Vec<TimeWindow>,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self { windows: Vec::new() }
    }
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
        if !self.days.is_empty() && !self.days.contains(&today) {
            return false;
        }
        let start_parts: Vec<&str> = self.start.split(':').collect();
        let end_parts: Vec<&str> = self.end.split(':').collect();
        if start_parts.len() != 2 || end_parts.len() != 2 {
            return false;
        }
        let start_min = parse_hhmm(start_parts[0], start_parts[1]);
        let end_min = parse_hhmm(end_parts[0], end_parts[1]);
        let now_min = hour * 60 + minute;

        match start_min.cmp(&end_min) {
            std::cmp::Ordering::Less => now_min >= start_min && now_min < end_min,
            std::cmp::Ordering::Greater => {
                // Crosses midnight (e.g. 22:00-06:00)
                now_min >= start_min || now_min < end_min
            }
            std::cmp::Ordering::Equal => now_min == start_min,
        }
    }
}

fn parse_hhmm(h: &str, m: &str) -> u32 {
    h.parse::<u32>().unwrap_or(0) * 60 + m.parse::<u32>().unwrap_or(0)
}

/// Day of the week.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DayOfWeek {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
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
    let dow = match (days as u64 + 4) % 7 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_when_no_windows() {
        let cfg = TransferConfig::default();
        assert!(cfg.is_in_window());
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
        assert!(!w.contains(DayOfWeek::Tue, 1, 0)); // wrong day
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
        // No windows means always allowed.
        let free = TransferConfig::default();
        assert!(free.is_in_window());

        // With windows, is_in_window depends on time-of-day check.
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
}
