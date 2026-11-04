//! The engine's few file calls that differ between Windows and Unix: an
//! open that never follows a link, what the open handle is (a link, not a
//! regular file, how many names it has, its size), and the open of the
//! pass lock. Windows opens a link as itself (FILE_FLAG_OPEN_REPARSE_POINT)
//! and reads its attributes; Unix refuses to open one at all (O_NOFOLLOW,
//! ELOOP), so a link never gets a handle there.
use std::{fs::File, io, path::Path};

/// What the gates need to know about an open handle.
pub(super) struct Info {
    /// A symlink or junction (Windows; on Unix the open already refused it).
    pub link: bool,
    /// A directory (Windows), or anything but a regular file (Unix: a
    /// directory, a FIFO, a device, a socket).
    pub not_file: bool,
    pub links: u64,
    pub size: u64,
}
/// Why an open failed.
pub(super) enum OpenError {
    Missing,
    /// Replaced right now (delete pending), or open elsewhere: Windows only.
    #[cfg_attr(unix, allow(dead_code))]
    Busy,
    /// A symlink at the name (Unix: ELOOP).
    #[cfg_attr(windows, allow(dead_code))]
    Link,
    Other,
}

/// Opens `path` itself even if it is a symlink or junction
/// (FILE_FLAG_OPEN_REPARSE_POINT), so a link is seen as a link and its
/// target, perhaps a key file, is never opened. FILE_FLAG_BACKUP_SEMANTICS
/// lets a directory open too, so it is refused instead of failing quietly.
#[cfg(windows)]
pub(super) fn open_no_follow(path: &Path) -> Result<File, OpenError> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x0020_0000 | 0x0200_0000)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(2 | 3) => OpenError::Missing,
            Some(5 | 32 | 33) => OpenError::Busy,
            _ => OpenError::Other,
        })
}
/// O_NOFOLLOW (a symlink fails the open) and O_NONBLOCK (a FIFO cannot hang
/// it). Unix has no sharing modes, so nothing here is ever Busy.
#[cfg(unix)]
pub(super) fn open_no_follow(path: &Path) -> Result<File, OpenError> {
    crate::posix::open_nofollow(path).map_err(|e| match e.raw_os_error() {
        Some(2 | 20) => OpenError::Missing, // ENOENT, ENOTDIR
        Some(40) => OpenError::Link,        // ELOOP
        _ => OpenError::Other,
    })
}

/// `helper.lock`, read-write, created when missing, opened as itself if it
/// is a link (Windows) or not at all (Unix).
#[cfg(windows)]
pub(super) fn open_lock(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(0x0020_0000) // FILE_FLAG_OPEN_REPARSE_POINT
        .open(path)
}
#[cfg(unix)]
pub(super) fn open_lock(path: &Path) -> io::Result<File> {
    crate::posix::open_lock_nofollow(path)
}

/// BY_HANDLE_FILE_INFORMATION.
#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
struct ByHandleInfo {
    attributes: u32,
    times: [u32; 6],
    volume: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}
#[cfg(windows)]
pub(super) fn info(file: &File) -> io::Result<Info> {
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(h: *mut std::ffi::c_void, info: *mut ByHandleInfo) -> i32;
    }
    let mut i = ByHandleInfo::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut i) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Info {
        link: i.attributes & 0x400 != 0,    // FILE_ATTRIBUTE_REPARSE_POINT
        not_file: i.attributes & 0x10 != 0, // FILE_ATTRIBUTE_DIRECTORY
        links: u64::from(i.links),
        size: (u64::from(i.size_high) << 32) | u64::from(i.size_low),
    })
}
/// fstat of the handle itself.
#[cfg(unix)]
pub(super) fn info(file: &File) -> io::Result<Info> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    Ok(Info {
        link: m.file_type().is_symlink(),
        not_file: !m.file_type().is_file(),
        links: m.nlink(),
        size: m.len(),
    })
}
