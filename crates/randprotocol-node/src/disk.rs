//! Free space on the filesystem holding the data directory (audit v4 OPS-3).
//!
//! Seven validators stalled on 2026-09-24 with full disks and nothing in `rand_getHealth` to say
//! so. The node now refuses to start under [`NodeConfig::min_free_disk_bytes`]
//! (`--min-free-disk-mb`, default 1024) and reports `disk_low` in its health while free space is
//! under [`DISK_LOW_FACTOR`] times that minimum. Audit v12 (OPS-601) adds an early warning at
//! [`DISK_WARN_FACTOR`] times it and a measured growth rate, so an unpruned archive's ~5 GB/day
//! is seen days before `disk_low`.
//!
//! [`NodeConfig::min_free_disk_bytes`]: crate::node::NodeConfig::min_free_disk_bytes
use std::path::Path;

/// Bytes available to this process on `path`'s filesystem (`f_bavail * f_frsize`).
pub fn free_bytes(path: &Path) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `libc::statvfs` is a plain C struct of integer fields (no references, no niches),
    // so the all-zero bit pattern is a valid value of it; it is only an out-parameter, fully
    // written by the call below before any field is read.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path that outlives the call, and `&mut st` is a
    // valid, exclusive, properly aligned pointer to a `statvfs` for the call's duration; on a
    // non-zero return nothing in `st` is read.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st.f_bavail as u64 * st.f_frsize as u64)
}

/// Free space under this many times the startup minimum is reported as `disk_low`.
pub const DISK_LOW_FACTOR: u64 = 4;

/// Free space under this many times the startup minimum raises the early warning (audit v12,
/// OPS-601): 16 GB at the default 1 GB minimum, three days of an unpruned chain-21 archive's
/// >= 5 GB/day, where `disk_low` (4 GB) is under one. A warning, not a health state: the node's
/// `rand_getHealth` status word is unchanged and gains `disk_warn` beside it, so a roll waiting on
/// `ok` is not stopped by it, but a monitor reading the field has days, not hours.
pub const DISK_WARN_FACTOR: u64 = 16;

/// Whether `free` is under the early-warning threshold for a startup minimum of `min` (zero
/// disables the guard, and so the warning).
pub fn disk_warn(free: u64, min: u64) -> bool {
    free < min.saturating_mul(DISK_WARN_FACTOR)
}

/// The data directory's growth, measured as free space lost per day over hour-long windows
/// (OPS-601). Each window's rate replaces the last; time is whole seconds on any monotone clock.
#[derive(Clone, Debug, Default)]
pub struct DiskTrend {
    anchor: Option<(u64, u64)>,
    bytes_per_day: Option<u64>,
}

impl DiskTrend {
    /// The measurement window.
    pub const WINDOW_SECS: u64 = 3600;

    /// Record free space `free` at `now_secs`.
    pub fn observe(&mut self, now_secs: u64, free: u64) {
        match self.anchor {
            None => self.anchor = Some((now_secs, free)),
            Some((t0, f0)) if now_secs.saturating_sub(t0) >= Self::WINDOW_SECS => {
                let dt = (now_secs - t0) as u128;
                let used = f0.saturating_sub(free) as u128;
                self.bytes_per_day = Some(u64::try_from(used * 86_400 / dt).unwrap_or(u64::MAX));
                self.anchor = Some((now_secs, free));
            }
            Some(_) => {}
        }
    }

    /// Free space lost per day over the last full window; `None` before the first one.
    pub fn bytes_per_day(&self) -> Option<u64> {
        self.bytes_per_day
    }

    /// Days until `free` reaches `floor` at the measured rate; `None` without a rate or when free
    /// space is not shrinking.
    pub fn days_until(&self, free: u64, floor: u64) -> Option<f64> {
        let rate = self.bytes_per_day.filter(|r| *r > 0)?;
        Some(free.saturating_sub(floor) as f64 / rate as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_bytes_of_a_real_directory_is_positive() {
        let dir = tempfile::tempdir().unwrap();
        assert!(free_bytes(dir.path()).unwrap() > 0);
    }

    const GB: u64 = 1 << 30;

    /// OPS-601: an unpruned chain-21 archive gains >= 5 GB a day; `disk_low` (4 GB at the
    /// default minimum) is under a day of warning at that rate. The early warning sits at
    /// DISK_WARN_FACTOR times the minimum.
    #[test]
    fn disk_warn_fires_well_above_disk_low() {
        let min = GB;
        assert!(!disk_warn(17 * GB, min));
        assert!(disk_warn(15 * GB, min));
        assert!(disk_warn(3 * GB, min), "under disk_low is under the warning too");
        assert!(DISK_WARN_FACTOR * min >= 3 * 5 * GB, "the warning leaves >= 3 days at 5 GB/day");
        assert!(!disk_warn(0, 0), "a zero minimum disables the guard, warning included");
    }

    #[test]
    fn the_trend_measures_bytes_per_day_over_an_hour() {
        let mut t = DiskTrend::default();
        t.observe(0, 100 * GB);
        t.observe(1800, 99 * GB);
        assert_eq!(t.bytes_per_day(), None, "no rate before a full window");
        // 5 GB/day is 5/24 GB an hour.
        t.observe(3600, 100 * GB - 5 * GB / 24);
        let r = t.bytes_per_day().unwrap();
        assert!(r.abs_diff(5 * GB) < GB / 1000, "{r}");
        // 20 GB free over a 4 GB floor at 5 GB/day: 3.2 days.
        let d = t.days_until(20 * GB, 4 * GB).unwrap();
        assert!((d - 3.2).abs() < 0.01, "{d}");
        assert_eq!(t.days_until(3 * GB, 4 * GB), Some(0.0), "already under the floor");
    }

    #[test]
    fn a_disk_that_grows_free_space_has_no_deadline() {
        let mut t = DiskTrend::default();
        t.observe(0, 10 * GB);
        t.observe(3600, 12 * GB); // a prune or a cleanup
        assert_eq!(t.bytes_per_day(), Some(0));
        assert_eq!(t.days_until(12 * GB, 4 * GB), None);
    }

    #[test]
    fn a_missing_path_is_an_error_not_zero() {
        assert!(free_bytes(std::path::Path::new("/definitely/not/here")).is_err());
    }
}
