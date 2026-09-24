//! Free space on the filesystem holding the data directory (audit v4 OPS-3).
//!
//! Seven validators stalled on 2026-09-24 with full disks and nothing in `rand_getHealth` to say
//! so. The node now refuses to start under [`NodeConfig::min_free_disk_bytes`]
//! (`--min-free-disk-mb`, default 1024) and reports `disk_low` in its health while free space is
//! under [`DISK_LOW_FACTOR`] times that minimum.
//!
//! [`NodeConfig::min_free_disk_bytes`]: crate::node::NodeConfig::min_free_disk_bytes
use std::path::Path;

/// Bytes available to this process on `path`'s filesystem (`f_bavail * f_frsize`).
pub fn free_bytes(path: &Path) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path and `st` is a zeroed out-parameter.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st.f_bavail as u64 * st.f_frsize as u64)
}

/// Free space under this many times the startup minimum is reported as `disk_low`.
pub const DISK_LOW_FACTOR: u64 = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_bytes_of_a_real_directory_is_positive() {
        let dir = tempfile::tempdir().unwrap();
        assert!(free_bytes(dir.path()).unwrap() > 0);
    }

    #[test]
    fn a_missing_path_is_an_error_not_zero() {
        assert!(free_bytes(std::path::Path::new("/definitely/not/here")).is_err());
    }
}
