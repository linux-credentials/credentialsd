//! Process-level protections for the UI, which handles PINs typed by the user.

use std::io;

/// Sets the core dump size limit to zero, both soft and hard, so the kernel
/// and systemd-coredump write no core dump for this process.
///
/// `prctl(PR_SET_DUMPABLE, 0)` would additionally block same-user ptrace, but
/// it also makes `/proc/<pid>/root` unreadable to xdg-desktop-portal, which
/// then rejects every portal call from this process, including the Settings
/// portal GTK uses for the colour scheme. Ptrace protection is left to Yama.
pub(crate) fn disable_core_dumps() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid rlimit that outlives the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_limit_is_zero_afterwards() {
        disable_core_dumps().unwrap();
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: `limit` is a valid, writable rlimit.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
        assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
    }
}
