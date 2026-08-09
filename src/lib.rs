//! Get/Set system proxy. Supports Windows, macOS, Linux and FreeBSD (via gsettings/KDE).
//! On FreeBSD, the Linux implementation is reused (GNOME gsettings/dconf and KDE
//! kreadconfig/kwriteconfig), since FreeBSD desktops ship the same tooling.

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

// #[cfg(feature = "utils")]
pub mod utils;

#[cfg(feature = "guard")]
pub mod guard;

#[cfg(feature = "guard")]
pub use guard::{GuardMonitor, GuardType};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Sysproxy {
    pub host: String,
    pub bypass: String,
    pub port: u16,
    pub enable: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Autoproxy {
    pub url: String,
    pub enable: bool,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to parse string `{0}`")]
    ParseStr(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("failed to get default network interface")]
    NetworkInterface,

    #[error("failed to set proxy for this environment")]
    NotSupport,

    #[error("admin privileges required to modify system proxy")]
    RequiresAdminPrivileges,

    #[cfg(target_os = "macos")]
    #[error("failed to interact with SCPreferences")]
    SCPreferences,

    #[cfg(target_os = "macos")]
    #[error("failed to interact with SCDynamicStore")]
    SCDynamicStore,

    #[cfg(target_os = "macos")]
    #[error("networksetup failed: {0}")]
    NetworkSetup(String),

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    #[error(transparent)]
    Xdg(#[from] xdg::BaseDirectoriesError),

    #[cfg(target_os = "windows")]
    #[error("Windows system call failed: {0}")]
    SystemCall(#[from] windows::Win32Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Sysproxy {
    pub const fn is_support() -> bool {
        cfg!(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "macos",
            target_os = "windows",
        ))
    }
}

impl Autoproxy {
    pub const fn is_support() -> bool {
        cfg!(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "macos",
            target_os = "windows",
        ))
    }
}
