use std::{
    io::{self, ErrorKind, Read, Write},
    mem::{ManuallyDrop, MaybeUninit},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        raw::c_void,
    },
    ptr::{self, NonNull},
};

use libc::{
    MAP_SHARED, MS_SYNC, O_CLOEXEC, PROT_READ, PROT_WRITE, SYS_memfd_secret, fstat, ftruncate,
    mmap, msync, munmap, off_t, syscall,
};
use zeroize::Zeroize;

/// On most architectures, the minimum page size is 4KB, so we use that as a baseline for creating
/// memory-mapped files. If the page size is larger, the OS will just map a larger page than we
/// need.
const MIN_PAGE_SIZE: usize = 4096;

/// Read a secret from a memory-mapped file.
pub fn read_secret(fd: OwnedFd) -> io::Result<Vec<u8>> {
    let mut reader = MmapReader::from_fd(fd)?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Write a secret to a memfd_secret and return its file descriptor. The secret will be zeroized
/// from memory.
pub fn write_secret(mut secret: Vec<u8>) -> io::Result<OwnedFd> {
    // For now, we're only accepting values that fit within a single page.
    // This can be raised in the future if needed.
    if secret.len() > MIN_PAGE_SIZE {
        return Err(io::Error::new(
            ErrorKind::FileTooLarge,
            "value is too large",
        ));
    }

    let memfd_secret = open_memfd_secret(secret.len())?;
    let mut mem = Mmap::from_fd(memfd_secret)?;
    mem.write_all(&secret)?;
    secret.zeroize();
    drop(secret);

    Ok(mem.into_fd())
}

struct Mmap {
    inner: NonNull<u8>,
    fd: OwnedFd,
    size: usize,
    pos: usize,
}

impl Mmap {
    fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        let size = MIN_PAGE_SIZE;
        let ptr = unsafe {
            let ptr = mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                fd.as_raw_fd(),
                0,
            );
            if ptr == usize::MAX as *mut c_void {
                let err = io::Error::last_os_error();
                tracing::error!(%err, "mmap failed");
                return Err(err);
            }
            NonNull::new(ptr as *mut u8)
                .ok_or_else(|| io::Error::other("mmap returned NULL pointer"))?
        };

        return Ok(Self {
            inner: ptr,
            fd,
            size,
            pos: 0,
        });
    }

    fn into_fd(self) -> OwnedFd {
        let mmap = ManuallyDrop::new(self);
        assert!(unsafe { munmap(mmap.inner.as_ptr().cast(), 4096) != -1 });
        unsafe { ptr::read(&mmap.fd) }
    }
}

impl Write for Mmap {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = self.size - self.pos;
        if remaining == 0 {
            return Ok(0);
        }

        let bytes_to_write = usize::min(remaining, buf.len());
        unsafe {
            self.inner
                .as_ptr()
                .wrapping_add(self.pos)
                .copy_from_nonoverlapping(buf.as_ptr(), bytes_to_write)
        };
        self.pos += bytes_to_write;

        Ok(bytes_to_write)
    }

    fn flush(&mut self) -> io::Result<()> {
        // No-op if there's no bytes to flush, prevents errors on call to msyc
        if self.pos == 0 {
            return Ok(());
        }

        if unsafe { msync(self.inner.as_ptr().cast(), self.pos, MS_SYNC) == -1 } {
            let err = io::Error::last_os_error();
            // msync is invalid on some file descriptors, so we ignore the error if called on one of those.
            let ErrorKind::InvalidInput = err.kind() else {
                tracing::error!("Failed to flush bytes");
                return Err(err);
            };
        }
        Ok(())
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        unsafe {
            assert!(munmap(self.inner.as_ptr().cast(), MIN_PAGE_SIZE) != -1);
        }
    }
}

struct MmapReader {
    inner: NonNull<u8>,
    _fd: OwnedFd,
    size: usize,
    pos: usize,
}

impl MmapReader {
    fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        let ptr = unsafe {
            let size = MIN_PAGE_SIZE;
            let flags = PROT_READ;
            let ptr = mmap(ptr::null_mut(), size, flags, MAP_SHARED, fd.as_raw_fd(), 0);
            if ptr == usize::MAX as *mut c_void {
                let err = io::Error::last_os_error();
                tracing::error!(%err, "mmap failed");
                return Err(err);
            }
            NonNull::new(ptr as *mut u8)
                .ok_or_else(|| io::Error::other("mmap returned NULL pointer"))?
        };

        // actual size of the data in the file
        let size = {
            let mut stat_buf = MaybeUninit::<libc::stat>::uninit();
            let res = unsafe { fstat(fd.as_raw_fd(), stat_buf.as_mut_ptr()) };
            if res == -1 {
                tracing::error!("fstat failed");
                return Err(io::Error::last_os_error());
            }
            let stat_buf = unsafe { stat_buf.assume_init() };
            usize::try_from(stat_buf.st_size)
                .map_err(|_| io::Error::new(ErrorKind::FileTooLarge, "file is too large"))?
        };
        Ok(Self {
            inner: ptr,
            _fd: fd,
            size,
            pos: 0,
        })
    }
}

impl Drop for MmapReader {
    fn drop(&mut self) {
        unsafe {
            assert!(munmap(self.inner.as_ptr().cast(), MIN_PAGE_SIZE) != -1);
        }
    }
}

impl Read for MmapReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.size - self.pos;
        if remaining == 0 {
            return Ok(0);
        }
        let bytes_to_read = usize::min(remaining, buf.len());
        unsafe {
            self.inner
                .as_ptr()
                .wrapping_add(self.pos)
                .copy_to_nonoverlapping(buf.as_mut_ptr(), bytes_to_read);
        }
        self.pos += bytes_to_read;
        Ok(bytes_to_read)
    }
}

fn open_memfd_secret(len: usize) -> io::Result<OwnedFd> {
    let len = off_t::try_from(len)
        .map_err(|_| io::Error::new(ErrorKind::FileTooLarge, "File is too large"))?;

    // Open memfd_secret
    let fd = {
        let ret = unsafe { syscall(SYS_memfd_secret, O_CLOEXEC) };
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }
        unsafe { OwnedFd::from_raw_fd(ret as i32) }
    };

    // Set length on fd. We have to do this before memory-mapping it.
    if unsafe { ftruncate(fd.as_raw_fd(), len) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}
