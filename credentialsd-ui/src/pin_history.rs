//! Remembers which client PINs were already sent to the authenticator during a
//! request, so the user can be told instead of wasting a PIN attempt on a PIN
//! that already failed.
//!
//! PINs are never stored. Each PIN is hashed with Argon2id, keyed with a
//! random pepper and salted with a random salt, both created per history
//! (that is, per request). The pepper, salt and hashes live in an anonymous
//! mapping that is locked into RAM (`mlock`) and excluded from core dumps
//! (`MADV_DONTDUMP`); so does Argon2's working memory while a PIN is hashed.
//! Both are zeroed before they are unmapped.
//!
//! Limitation: the `blake2` crate used inside Argon2 does not zeroize its
//! state, so a copy of the PIN, salt and pepper can remain on the hashing
//! thread's stack until it is overwritten. The PIN itself is already held in
//! ordinary memory by GTK while the user types it.

use std::{io, ptr::NonNull};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroize;

const PEPPER_LEN: usize = 32;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;
/// CTAP authenticators allow at most 8 PIN retries before blocking, so this
/// leaves room for a device being re-plugged within one request.
const MAX_ENTRIES: usize = 16;

/// Argon2 memory cost in KiB (one block each). Kept far below the usual
/// 8 MiB `RLIMIT_MEMLOCK` so the working memory can be locked. The pepper is
/// secret, so memory-hardness matters little here.
const M_COST_KIB: u32 = 512;
const T_COST: u32 = 3;

const SALT_OFFSET: usize = PEPPER_LEN;
const SCRATCH_OFFSET: usize = SALT_OFFSET + SALT_LEN;
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
    Random(io::Error),
    /// Argon2 rejected its parameters or inputs.
    Hash(argon2::Error),
}

impl std::fmt::Display for PinHistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory(err) => write!(f, "failed to set up locked memory for PIN history: {err}"),
            Self::Random(err) => write!(f, "failed to generate random bytes: {err}"),
            Self::Hash(err) => write!(f, "failed to hash PIN: {err}"),
        }
    }
}

impl std::error::Error for PinHistoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Memory(err) | Self::Random(err) => Some(err),
            // argon2::Error only implements std::error::Error with the
            // crate's `std` feature; its message is included in Display.
            Self::Hash(_) => None,
        }
    }
}

/// Hashes of the PINs already tried on the current device.
pub(crate) struct PinHistory {
    page: LockedPage,
    len: usize,
}

impl PinHistory {
    pub(crate) fn new() -> Result<Self, PinHistoryError> {
        let mut page = LockedPage::new(REGION_LEN).map_err(PinHistoryError::Memory)?;
        fill_random(&mut page.as_mut_slice()[..SCRATCH_OFFSET]).map_err(PinHistoryError::Random)?;
        Ok(Self { page, len: 0 })
    }

    /// Checks `pin` against the PINs already tried and records it if it is
    /// new.
    pub(crate) fn check(&mut self, pin: &[u8]) -> Result<PinCheck, PinHistoryError> {
        self.hash_into_scratch(pin)?;
        let result = if self.scratch_is_recorded() {
            PinCheck::AlreadyTried
        } else {
            self.push_scratch();
            PinCheck::Send
        };
        self.page.as_mut_slice()[SCRATCH_OFFSET..ENTRIES_OFFSET].zeroize();
        Ok(result)
    }

    /// Forgets all tried PINs, e.g. because a different device may now be
    /// connected, and picks a new salt.
    pub(crate) fn clear(&mut self) -> Result<(), PinHistoryError> {
        let bytes = self.page.as_mut_slice();
        bytes[SCRATCH_OFFSET..].zeroize();
        self.len = 0;
        fill_random(&mut bytes[SALT_OFFSET..SCRATCH_OFFSET]).map_err(PinHistoryError::Random)
    }

    fn hash_into_scratch(&mut self, pin: &[u8]) -> Result<(), PinHistoryError> {
        let bytes = self.page.as_mut_slice();
        let (keys, rest) = bytes.split_at_mut(SCRATCH_OFFSET);
        let (pepper, salt) = keys.split_at(PEPPER_LEN);
        let scratch = &mut rest[..HASH_LEN];
        let params =
            Params::new(M_COST_KIB, T_COST, 1, Some(HASH_LEN)).map_err(PinHistoryError::Hash)?;
        let argon = Argon2::new_with_secret(pepper, Algorithm::Argon2id, Version::V0x13, params)
            .map_err(PinHistoryError::Hash)?;
        // Dropped (zeroed and unmapped) at the end of this function.
        let mut memory = LockedPage::new(M_COST_KIB as usize * size_of::<Block>())
            .map_err(PinHistoryError::Memory)?;
        argon
            .hash_password_into_with_memory(pin, salt, scratch, memory.as_mut_blocks())
            .map_err(PinHistoryError::Hash)
    }

    fn scratch_is_recorded(&self) -> bool {
        let bytes = self.page.as_slice();
        let scratch = &bytes[SCRATCH_OFFSET..ENTRIES_OFFSET];
        bytes[ENTRIES_OFFSET..]
            .chunks_exact(HASH_LEN)
            .take(self.len)
            .any(|entry| entry == scratch)
    }

    /// Appends the scratch hash, dropping the oldest entry when full.
    fn push_scratch(&mut self) {
        let bytes = self.page.as_mut_slice();
        if self.len == MAX_ENTRIES {
            bytes.copy_within(ENTRIES_OFFSET + HASH_LEN.., ENTRIES_OFFSET);
            self.len -= 1;
        }
        let dst = ENTRIES_OFFSET + self.len * HASH_LEN;
        bytes.copy_within(SCRATCH_OFFSET..ENTRIES_OFFSET, dst);
        self.len += 1;
    }
}

impl std::fmt::Debug for PinHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinHistory")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let rest = &mut buf[filled..];
        // SAFETY: `rest` is a valid, writable buffer of `rest.len()` bytes.
        let n = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        filled += n as usize;
    }
    Ok(())
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

    /// Views the mapping as Argon2 blocks; trailing bytes that do not fill a
    /// whole block are left out.
    fn as_mut_blocks(&mut self) -> &mut [Block] {
        let count = self.len / size_of::<Block>();
        // SAFETY: mmap returns page-aligned memory, which satisfies Block's
        // 64-byte alignment; `count` blocks fit in `len` bytes; a Block is a
        // plain array of u64, for which the all-zero (or any) bit pattern is
        // valid; `&mut self` guarantees exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr().cast::<Block>(), count) }
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

    #[test]
    fn new_pin_is_sent() {
        let mut history = PinHistory::new().unwrap();
        assert_eq!(history.check(b"1234").unwrap(), PinCheck::Send);
    }

    #[test]
    fn repeated_pin_is_always_refused() {
        let mut history = PinHistory::new().unwrap();
        history.check(b"1234").unwrap();
        assert_eq!(history.check(b"1234").unwrap(), PinCheck::AlreadyTried);
        assert_eq!(history.check(b"1234").unwrap(), PinCheck::AlreadyTried);
    }

    #[test]
    fn every_tried_pin_is_remembered() {
        let mut history = PinHistory::new().unwrap();
        history.check(b"1111").unwrap();
        history.check(b"2222").unwrap();
        assert_eq!(history.check(b"1111").unwrap(), PinCheck::AlreadyTried);
        assert_eq!(history.check(b"2222").unwrap(), PinCheck::AlreadyTried);
        assert_eq!(history.check(b"3333").unwrap(), PinCheck::Send);
    }

    #[test]
    fn clear_forgets_tried_pins() {
        let mut history = PinHistory::new().unwrap();
        history.check(b"1234").unwrap();
        history.clear().unwrap();
        assert_eq!(history.check(b"1234").unwrap(), PinCheck::Send);
    }

    #[test]
    fn oldest_entry_is_dropped_when_full() {
        let mut history = PinHistory::new().unwrap();
        for i in 0..=MAX_ENTRIES {
            assert_eq!(
                history.check(format!("{i:04}").as_bytes()).unwrap(),
                PinCheck::Send
            );
        }
        assert_eq!(history.check(b"0000").unwrap(), PinCheck::Send);
        assert_eq!(history.check(b"0002").unwrap(), PinCheck::AlreadyTried);
    }

    #[test]
    fn scratch_hash_is_wiped_after_check() {
        let mut history = PinHistory::new().unwrap();
        history.check(b"98765432").unwrap();
        let bytes = history.page.as_slice();
        assert!(
            bytes[SCRATCH_OFFSET..ENTRIES_OFFSET]
                .iter()
                .all(|b| *b == 0)
        );
    }
}
