//! memmap2 doesn't support MAP_FIXED so here's our own!

pub(crate) enum Mode {
    Read,
    Write,
    Execute,
}

#[cfg(windows)]
mod imp {
    use std::{ffi::c_void, io, u32};

    use windows::Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        System::{
            Memory::{
                FILE_MAP_EXECUTE, FILE_MAP_WRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
                PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
            },
            SystemInformation::SYSTEM_INFO,
        },
    };

    use super::Mode;

    pub(crate) fn allocation_granularity() -> usize {
        let mut info = SYSTEM_INFO::default();
        unsafe {
            windows::Win32::System::SystemInformation::GetSystemInfo(&mut info);
        }
        info.dwAllocationGranularity as usize
    }

    pub(crate) fn page_size() -> usize {
        let mut info = SYSTEM_INFO::default();
        unsafe {
            windows::Win32::System::SystemInformation::GetSystemInfo(&mut info);
        }
        info.dwPageSize as usize
    }

    pub(crate) fn protect(address: *const (), size: usize, mode: Mode) -> io::Result<()> {
        debug_assert_eq!(address.addr() & (page_size() - 1), 0);
        let mut old = PAGE_PROTECTION_FLAGS::default();
        unsafe {
            windows::Win32::System::Memory::VirtualProtect(
                address.cast::<c_void>(),
                size,
                match mode {
                    Mode::Read => PAGE_READONLY,
                    Mode::Write => PAGE_READWRITE,
                    Mode::Execute => PAGE_EXECUTE_READ,
                },
                &mut old,
            )
            .map_err(Into::into)
        }
    }

    pub(crate) unsafe fn call_entrypoint_via_stdcall(fnptr: *const ()) -> u32 {
        let fnptr = unsafe { std::mem::transmute::<_, unsafe extern "stdcall" fn() -> u32>(fnptr) };
        unsafe { fnptr() }
    }
}

#[cfg(unix)]
mod imp {
    use std::io;

    use super::Mode;

    pub(crate) fn allocation_granularity() -> usize {
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
    }

    pub(crate) fn page_size() -> usize {
        allocation_granularity()
    }

    pub(crate) fn protect(address: *const (), size: usize, mode: super::Mode) -> io::Result<()> {
        debug_assert_eq!(address.addr() & (page_size() - 1), 0);
        let prot = match mode {
            Mode::Read => libc::PROT_READ,
            Mode::Write => libc::PROT_READ | libc::PROT_WRITE,
            Mode::Execute => libc::PROT_READ | libc::PROT_EXEC,
        };
        let ret = unsafe { libc::mprotect(address as _, size, prot) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(crate) unsafe fn call_entrypoint_via_stdcall(fnptr: usize) -> u32 {
        // todo this might be correct or not idk??? is it close enough in this case maybe?? use asm probably.
        let fnptr = unsafe {
            std::mem::transmute::<*const (), unsafe extern "C" fn() -> u32>(
                std::ptr::with_exposed_provenance(fnptr),
            )
        };
        unsafe { fnptr() }
    }
}

pub(crate) use imp::*;
