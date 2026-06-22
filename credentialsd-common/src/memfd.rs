use std::{
    io::{self, ErrorKind},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        raw::c_void,
    },
};

use libc::{
    ftruncate, mmap, off_t, SYS_memfd_secret, MAP_SHARED, O_CLOEXEC, PROT_READ, PROT_WRITE,
};
use zeroize::Zeroize;

pub fn read_secret(pin_fd: std::os::fd::OwnedFd) -> Result<String, std::io::Error> {
    // Get pin length
    let len = {
        let mut stat_buf = MaybeUninit::<libc::stat>::uninit();
        let res = unsafe { libc::fstat(pin_fd.as_raw_fd(), stat_buf.as_mut_ptr()) };
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
        let stat_buf = unsafe { stat_buf.assume_init() };
        usize::try_from(stat_buf.st_size)
            .map_err(|_| io::Error::new(ErrorKind::FileTooLarge, "pin is too large"))?
    };

    // map the memory from the file descriptor
    let ptr = unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            pin_fd.as_raw_fd(),
            0,
        );
        if ptr == usize::MAX as *mut c_void {
            return Err(std::io::Error::last_os_error());
        }
        ptr as *const u8
    };

    // Copy the bytes.
    let buf = unsafe {
        let mut buf: Vec<u8> = Vec::with_capacity(len);
        ptr.copy_to_nonoverlapping(buf.as_mut_ptr().cast(), len);
        buf.set_len(len);
        buf
    };

    // Clean up mapping
    unsafe {
        if libc::munmap(ptr as *mut c_void, 4096) == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }
    drop(pin_fd);

    String::from_utf8(buf).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid UTF-8 data found in buffer",
        )
    })
}

pub fn write_secret(mut secret: Vec<u8>, max_len: usize) -> Result<OwnedFd, std::io::Error> {
    let bytes_len = if secret.len() <= max_len {
        secret.len() as u8
    } else {
        return Err(io::Error::new(
            ErrorKind::FileTooLarge,
            "value is too large",
        ));
    };

    // Open memfd_secret
    let ret: i64 = unsafe { libc::syscall(SYS_memfd_secret, O_CLOEXEC) };
    if ret == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = i32::try_from(ret).map_err(|_| std::io::Error::other("invalid file descriptor"))?;
    if unsafe { ftruncate(fd, bytes_len as off_t) } == -1 {
        return Err(std::io::Error::last_os_error());
    }

    let ptr = unsafe {
        let ptr = mmap(
            std::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            0,
        );
        if ptr == usize::MAX as *mut c_void {
            return Err(std::io::Error::last_os_error());
        }
        // ptr as *mut u8
        ptr
    };

    // Copy the data
    unsafe {
        ptr.copy_from_nonoverlapping(secret.as_ptr().cast(), secret.len());
    }

    // Cleanup
    if unsafe { libc::munmap(ptr, 4096) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    secret.zeroize();
    drop(secret);

    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(owned_fd)
}
