// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 rekit contributors

use std::ffi::c_void;
use std::fs;
use std::io;

use crate::maps::{parse_readable_regions, Region};

const PTRACE_ATTACH: i32 = 16;
const PTRACE_DETACH: i32 = 17;

#[repr(C)]
struct IoVec {
    base: *mut c_void,
    len: usize,
}

extern "C" {
    fn ptrace(request: i32, pid: i32, address: *mut c_void, data: *mut c_void) -> isize;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn process_vm_readv(
        pid: i32,
        local: *const IoVec,
        local_count: usize,
        remote: *const IoVec,
        remote_count: usize,
        flags: usize,
    ) -> isize;
}

pub struct RemoteProcess {
    pid: i32,
    attached: bool,
}

impl RemoteProcess {
    pub fn attach(pid: i32) -> io::Result<Self> {
        // SAFETY: ptrace receives a valid positive PID and null address/data for
        // PTRACE_ATTACH, as required by the Linux interface.
        if unsafe {
            ptrace(
                PTRACE_ATTACH,
                pid,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }

        let mut process = Self {
            pid,
            attached: true,
        };
        let mut status = 0;
        // SAFETY: status points to valid writable storage and pid is attached.
        let waited = unsafe { waitpid(pid, &mut status, 0) };
        if waited != pid {
            let error = if waited == -1 {
                io::Error::last_os_error()
            } else {
                io::Error::new(
                    io::ErrorKind::Other,
                    "waitpid returned an unexpected process",
                )
            };
            process.detach();
            return Err(error);
        }
        // The low byte 0x7f denotes a ptrace/job-control stop in wait status.
        if status & 0xff != 0x7f {
            process.detach();
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("target did not enter a stopped state (status 0x{status:x})"),
            ));
        }
        Ok(process)
    }

    pub fn regions(&self) -> io::Result<Vec<Region>> {
        let maps = fs::read_to_string(format!("/proc/{}/maps", self.pid))?;
        Ok(parse_readable_regions(&maps))
    }

    pub fn read_some(&self, address: usize, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let local = IoVec {
            base: buffer.as_mut_ptr().cast(),
            len: buffer.len(),
        };
        let remote = IoVec {
            base: address as *mut c_void,
            len: buffer.len(),
        };
        // SAFETY: both iovecs describe live buffers for the duration of the
        // call. The remote address is only read; the kernel validates it.
        let read = unsafe { process_vm_readv(self.pid, &local, 1, &remote, 1, 0) };
        if read == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(read as usize)
        }
    }

    pub fn read_exact(&self, address: usize, size: usize) -> io::Result<Vec<u8>> {
        const READ_BLOCK: usize = 1024 * 1024;
        let mut result = vec![0u8; size];
        let mut completed = 0usize;
        while completed < size {
            let amount = (size - completed).min(READ_BLOCK);
            let remote_address = address.checked_add(completed).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "remote address overflow")
            })?;
            let count =
                self.read_some(remote_address, &mut result[completed..completed + amount])?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short remote-memory read",
                ));
            }
            completed += count;
        }
        Ok(result)
    }

    fn detach(&mut self) {
        if self.attached {
            // SAFETY: this process owns the matching ptrace attachment. Null
            // address/data requests a normal detach with no delivered signal.
            unsafe {
                ptrace(
                    PTRACE_DETACH,
                    self.pid,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
            }
            self.attached = false;
        }
    }
}

impl Drop for RemoteProcess {
    fn drop(&mut self) {
        self.detach();
    }
}
