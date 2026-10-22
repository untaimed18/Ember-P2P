//! How long since the user last touched the keyboard or mouse, so friends can
//! be shown Away while nobody is at the machine.
//!
//! Input anywhere on the desktop counts, not just in Ember's window: someone
//! typing in another program is at their PC.

/// Whether this build can tell how long the user has been idle. The UI asks
/// so it can disable the setting rather than offer one that never fires.
pub const fn supported() -> bool {
    cfg!(windows)
}

/// Whole seconds since the last keyboard or mouse input in this session, or
/// `None` where that cannot be read.
pub fn seconds_since_input() -> Option<u64> {
    imp::seconds_since_input()
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::System::SystemInformation::GetTickCount;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

    pub fn seconds_since_input() -> Option<u64> {
        let mut info = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        // SAFETY: `info` is a valid, writable LASTINPUTINFO with `cbSize` set,
        // which is all GetLastInputInfo reads before writing `dwTime`.
        if unsafe { GetLastInputInfo(&mut info) } == 0 {
            return None;
        }
        // SAFETY: GetTickCount takes no arguments and cannot fail.
        let now = unsafe { GetTickCount() };
        // Both are milliseconds since boot in a u32, which wraps every 49.7
        // days; the wrapping difference is still the elapsed time.
        Some(u64::from(now.wrapping_sub(info.dwTime)) / 1000)
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn seconds_since_input() -> Option<u64> {
        None
    }
}
