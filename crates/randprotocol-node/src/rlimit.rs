//! The open-files limit (issue #41, 2026-09-27).
//!
//! RocksDB keeps every table file of every column family open, and an archive — or a validator
//! holding a day of history — has about a thousand of them. On 2026-09-27 obs1, the public RPC's
//! archive upstream, ran out at the default soft limit of 1024: axum's accept loop answered every
//! connection with `Too many open files`, the node stopped committing, and E and C sat at ~845 of
//! 1024. A systemd drop-in (`LimitNOFILE=65536:524288`) fixed the fleet; this makes the node not
//! depend on one. At startup the soft limit is raised toward [`WANTED_NOFILE`], never past the
//! hard limit (an unprivileged process may not raise that), and never lowered.

/// The soft open-files limit the node asks for: the same number the fleet's drop-in and node A's
/// launchd plist set, far above ~1000 SSTs plus the swarm's 256 inbound connections and the RPC's.
pub const WANTED_NOFILE: u64 = 65_536;

/// Raise the soft `RLIMIT_NOFILE` to `min(WANTED_NOFILE, hard)` if it is lower; return the
/// (soft, hard) pair in force afterwards. On macOS the kernel also caps it at `OPEN_MAX` for
/// `setrlimit`, so an `EINVAL` there is retried at that cap rather than treated as fatal.
pub fn raise_nofile_limit() -> std::io::Result<(u64, u64)> {
    let (soft, hard) = current()?;
    let target = WANTED_NOFILE.min(hard);
    if soft >= target {
        return Ok((soft, hard));
    }
    // macOS refuses a soft limit above OPEN_MAX (10240) with EINVAL even under an "unlimited"
    // hard limit; Linux takes `target` as asked.
    for want in [target, target.min(MACOS_OPEN_MAX)] {
        if want <= soft {
            break;
        }
        let rl = libc::rlimit { rlim_cur: want as libc::rlim_t, rlim_max: hard as libc::rlim_t };
        // SAFETY: a valid rlimit whose soft value is at most the unchanged hard one.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) } == 0 {
            return current();
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINVAL) {
            return Err(e);
        }
    }
    current()
}

/// macOS's `OPEN_MAX`, the most `setrlimit` accepts for a soft `RLIMIT_NOFILE` there.
const MACOS_OPEN_MAX: u64 = 10_240;

fn current() -> std::io::Result<(u64, u64)> {
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `rl` is a valid out-parameter for getrlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((rl.rlim_cur as u64, rl.rlim_max as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_soft(soft: u64) {
        let (_, hard) = current().unwrap();
        let rl = libc::rlimit { rlim_cur: soft.min(hard) as libc::rlim_t, rlim_max: hard as libc::rlim_t };
        // SAFETY: a valid rlimit; lowering the soft limit is always permitted.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) }, 0);
    }

    /// The 2026-09-27 obs1 outage: a node started under a 1024 soft limit must leave startup
    /// with a soft limit that ~1000 RocksDB table files plus its sockets cannot exhaust.
    #[test]
    fn a_low_soft_limit_is_raised_at_startup() {
        set_soft(256);
        let (soft, hard) = raise_nofile_limit().unwrap();
        let (now, _) = current().unwrap();
        assert_eq!(soft, now, "the returned pair is the one in force");
        assert!(
            now >= WANTED_NOFILE.min(hard).min(10_240),
            "soft limit left at {now} (hard {hard}): RocksDB's table files alone exhaust it"
        );
    }

    #[test]
    fn a_soft_limit_is_never_lowered() {
        let (_, hard) = current().unwrap();
        let high = hard.min(WANTED_NOFILE * 2);
        set_soft(high);
        let (soft, _) = raise_nofile_limit().unwrap();
        assert!(soft >= high.min(hard), "lowered from {high} to {soft}");
    }
}
