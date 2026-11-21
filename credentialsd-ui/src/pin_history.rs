//! Remembers which client PINs were already sent to the authenticator during a
//! request, so the user can be told instead of wasting a PIN attempt on a PIN
//! that already failed.
//!
//! Each PIN is stored as a SHA-256 hash, so every entry has the same size
//! whatever the PIN length. The hash covers a random pepper created per
//! history (that is, per request), a [`PinSalt`] that the caller creates each
//! time a device asks for a PIN, and the PIN, so different devices and PIN
//! prompts have distinct histories. The pepper and hashes live in an
//! anonymous mapping that is locked into RAM (`mlock`) and excluded from core
//! dumps (`MADV_DONTDUMP`), and are zeroed before it is unmapped.
//!
//! Limitation: the `sha2` crate does not zeroize its state, so a copy of the
//! PIN, salt and pepper can remain on the hashing thread's stack until it is
//! overwritten. The PIN itself is already held in ordinary memory by GTK
//! while the user types it.

use std::{io, ptr::NonNull};

use rand::{TryRng, rngs::SysRng};
use sha2::{
    Digest, Sha256,
    digest::{OutputSizeUser, typenum::Unsigned},
};
use zeroize::Zeroize;

const PEPPER_LEN: usize = 32;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;
const _: () = assert!(HASH_LEN == <Sha256 as OutputSizeUser>::OutputSize::USIZE);
/// One PIN prompt allows at most 8 attempts (CTAP's retry limit), so this
/// is enough for a whole prompt.
/// A power of two, so the ring buffer index is a cheap mask.
const MAX_ENTRIES: usize = 16;
const _: () = assert!(MAX_ENTRIES.is_power_of_two());

const SCRATCH_OFFSET: usize = PEPPER_LEN;
const ENTRIES_OFFSET: usize = SCRATCH_OFFSET + HASH_LEN;
const REGION_LEN: usize = ENTRIES_OFFSET + MAX_ENTRIES * HASH_LEN;

/// What to do with a PIN the user just entered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinCheck {
    /// Send the PIN to the authenticator.
    Send,
    /// The PIN was already tried for this device. Tell the user instead of
    /// sending it.
    AlreadyTried,
}

#[derive(Debug)]
pub(crate) enum PinHistoryError {
    /// Setting up the locked memory page failed.
    Memory(io::Error),
    /// The kernel random number generator failed.
    Random(rand::rngs::SysError),
}

impl std::fmt::Display for PinHistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory(err) => write!(f, "failed to set up locked memory for PIN history: {err}"),
            Self::Random(err) => write!(f, "failed to generate random bytes: {err}"),
        }
    }
}

impl std::error::Error for PinHistoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Memory(err) => Some(err),
            Self::Random(err) => Some(err),
        }
    }
}

/// Salt for one PIN prompt. It is not secret, so it does not need locked
/// memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PinSalt([u8; SALT_LEN]);

impl PinSalt {
    pub(crate) fn generate() -> Result<Self, PinHistoryError> {
        let mut salt = [0; SALT_LEN];
        SysRng
            .try_fill_bytes(&mut salt)
            .map_err(PinHistoryError::Random)?;
        Ok(Self(salt))
    }
}

/// Hashes of the PINs already tried on the current device, kept in a ring
/// buffer of `MAX_ENTRIES`.
pub(crate) struct PinHistory {
    page: LockedPage,
    /// Number of PINs recorded since the last `clear`. The next hash is
    /// written to slot `attempt_count % MAX_ENTRIES`.
    attempt_count: usize,
}

impl PinHistory {
    pub(crate) fn new() -> Result<Self, PinHistoryError> {
        let mut page = LockedPage::new(REGION_LEN).map_err(PinHistoryError::Memory)?;
        SysRng
            .try_fill_bytes(&mut page.as_mut_slice()[..PEPPER_LEN])
            .map_err(PinHistoryError::Random)?;
        Ok(Self {
            page,
            attempt_count: 0,
        })
    }

    /// Checks `pin` against the PINs already tried with `salt` and records it
    /// if it is new.
    pub(crate) fn check(&mut self, salt: &PinSalt, pin: &[u8]) -> PinCheck {
        self.hash_into_scratch(salt, pin);
        let result = if self.scratch_is_recorded() {
            PinCheck::AlreadyTried
        } else {
            self.push_scratch();
            PinCheck::Send
        };
        self.page.as_mut_slice()[SCRATCH_OFFSET..ENTRIES_OFFSET].zeroize();
        result
    }

    /// Forgets all tried PINs. The pepper is kept.
    pub(crate) fn clear(&mut self) {
        self.page.as_mut_slice()[SCRATCH_OFFSET..].zeroize();
        self.attempt_count = 0;
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.attempt_count == 0
            && self.page.as_slice()[ENTRIES_OFFSET..]
                .iter()
                .all(|b| *b == 0)
    }

    fn hash_into_scratch(&mut self, salt: &PinSalt, pin: &[u8]) {
        let bytes = self.page.as_mut_slice();
        let (pepper, rest) = bytes.split_at_mut(SCRATCH_OFFSET);
        let scratch = &mut rest[..HASH_LEN];
        let mut hasher = Sha256::new();
        hasher.update(&*pepper);
        hasher.update(salt.0);
        hasher.update(pin);
        hasher.finalize_into(scratch.into());
    }

    fn scratch_is_recorded(&self) -> bool {
        let bytes = self.page.as_slice();
        let scratch = &bytes[SCRATCH_OFFSET..ENTRIES_OFFSET];
        bytes[ENTRIES_OFFSET..]
            .chunks_exact(HASH_LEN)
            .take(self.attempt_count.min(MAX_ENTRIES))
            .any(|entry| entry == scratch)
    }

    /// Writes the scratch hash to the next ring buffer slot, overwriting the
    /// oldest entry when full.
    fn push_scratch(&mut self) {
        let dst = ENTRIES_OFFSET + (self.attempt_count & (MAX_ENTRIES - 1)) * HASH_LEN;
        self.page
            .as_mut_slice()
            .copy_within(SCRATCH_OFFSET..ENTRIES_OFFSET, dst);
        // Wrapping would take 2^64 PINs; if it did, the history would only
        // look shorter until it fills again.
        self.attempt_count = self.attempt_count.wrapping_add(1);
    }
}

impl std::fmt::Debug for PinHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinHistory")
            .field("attempt_count", &self.attempt_count)
            .finish_non_exhaustive()
    }
}

/// Anonymous private memory, locked into RAM and excluded from core dumps.
struct LockedPage {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: `LockedPage` exclusively owns its mapping; nothing else holds the
// pointer, so moving it to another thread is sound.
unsafe impl Send for LockedPage {}
// SAFETY: shared references only allow reading the mapping through
// `as_slice`; writes need `&mut self`, so the usual borrow rules apply.
unsafe impl Sync for LockedPage {}

impl LockedPage {
    fn new(len: usize) -> io::Result<Self> {
        // SAFETY: an anonymous private mapping with no address hint has no
        // preconditions; the result is checked against MAP_FAILED.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = NonNull::new(addr.cast::<u8>()).ok_or_else(io::Error::last_os_error)?;
        // From here on, `Drop` unmaps the region if a later step fails.
        let page = Self { ptr, len };
        // SAFETY: `addr` is a page-aligned mapping of `len` bytes owned by us.
        if unsafe { libc::madvise(addr, len, libc::MADV_DONTDUMP) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as above.
        if unsafe { libc::mlock(addr, len) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(page)
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: the mapping is `len` readable bytes, zero-initialised by
        // the kernel, and lives as long as `self`.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as in `as_slice`; `&mut self` guarantees exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for LockedPage {
    fn drop(&mut self) {
        self.as_mut_slice().zeroize();
        let addr = self.ptr.as_ptr().cast();
        // SAFETY: `addr`/`len` describe our own mapping, which is not used
        // after this point. munlock on an unlocked range is harmless.
        unsafe {
            libc::munlock(addr, self.len);
            libc::munmap(addr, self.len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn salt() -> PinSalt {
        PinSalt::generate().unwrap()
    }

    #[test]
    fn new_pin_is_sent() {
        let mut history = PinHistory::new().unwrap();
        assert_eq!(history.check(&salt(), b"1234"), PinCheck::Send);
    }

    #[test]
    fn repeated_pin_is_always_refused() {
        let mut history = PinHistory::new().unwrap();
        let salt = salt();
        history.check(&salt, b"1234");
        assert_eq!(history.check(&salt, b"1234"), PinCheck::AlreadyTried);
        assert_eq!(history.check(&salt, b"1234"), PinCheck::AlreadyTried);
    }

    #[test]
    fn every_tried_pin_is_remembered() {
        let mut history = PinHistory::new().unwrap();
        let salt = salt();
        history.check(&salt, b"1111");
        history.check(&salt, b"2222");
        assert_eq!(history.check(&salt, b"1111"), PinCheck::AlreadyTried);
        assert_eq!(history.check(&salt, b"2222"), PinCheck::AlreadyTried);
        assert_eq!(history.check(&salt, b"3333"), PinCheck::Send);
    }

    #[test]
    fn different_salts_keep_separate_histories() {
        let mut history = PinHistory::new().unwrap();
        history.check(&salt(), b"1234");
        assert_eq!(history.check(&salt(), b"1234"), PinCheck::Send);
    }

    #[test]
    fn clear_forgets_tried_pins() {
        let mut history = PinHistory::new().unwrap();
        let salt = salt();
        history.check(&salt, b"1234");
        history.clear();
        assert_eq!(history.check(&salt, b"1234"), PinCheck::Send);
    }

    #[test]
    fn clear_wipes_stored_hashes() {
        let mut history = PinHistory::new().unwrap();
        history.check(&salt(), b"1234");
        history.clear();
        let bytes = history.page.as_slice();
        assert!(bytes[ENTRIES_OFFSET..].iter().all(|b| *b == 0));
    }

    #[test]
    fn oldest_entry_is_dropped_when_full() {
        let mut history = PinHistory::new().unwrap();
        let salt = salt();
        for i in 0..=MAX_ENTRIES {
            assert_eq!(
                history.check(&salt, format!("{i:04}").as_bytes()),
                PinCheck::Send
            );
        }
        // 0000 was overwritten by 0016; sending it again overwrites 0001.
        assert_eq!(history.check(&salt, b"0000"), PinCheck::Send);
        assert_eq!(history.check(&salt, b"0001"), PinCheck::Send);
        assert_eq!(history.check(&salt, b"0003"), PinCheck::AlreadyTried);
        assert_eq!(history.check(&salt, b"0016"), PinCheck::AlreadyTried);
        assert_eq!(history.check(&salt, b"0000"), PinCheck::AlreadyTried);
    }

    #[test]
    fn scratch_hash_is_wiped_after_check() {
        let mut history = PinHistory::new().unwrap();
        history.check(&salt(), b"98765432");
        let bytes = history.page.as_slice();
        assert!(
            bytes[SCRATCH_OFFSET..ENTRIES_OFFSET]
                .iter()
                .all(|b| *b == 0)
        );
    }
}
