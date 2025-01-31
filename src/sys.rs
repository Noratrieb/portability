//! memmap2 doesn't support MAP_FIXED so here's our own!

pub(crate) enum Mode {
    Read,
    Write,
    Execute,
}

#[cfg(windows)]
mod imp {
    use std::{ffi::c_void, io, path::PathBuf, u32};

    use windows::Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        System::{
            Memory::{
                FILE_MAP_EXECUTE, FILE_MAP_WRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
                PAGE_READONLY, PAGE_READWRITE,
            },
            SystemInformation::{GetSystemDirectoryW, SYSTEM_INFO},
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

    pub(crate) unsafe fn anon_write_map<'a>(
        size: usize,
        address: *const (),
    ) -> io::Result<&'a mut [u8]> {
        let map = windows::Win32::System::Memory::CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            None,
            PAGE_EXECUTE_READWRITE,
            (size >> 32) as u32,
            size as u32,
            None,
        )?;

        eprintln!("created {address:p} {size:x}");

        debug_assert_eq!(address.addr() & (allocation_granularity() - 1), 0);
        debug_assert_eq!(size & (allocation_granularity() - 1), 0);

        let addr = unsafe {
            windows::Win32::System::Memory::MapViewOfFileEx(
                map,
                FILE_MAP_WRITE | FILE_MAP_EXECUTE,
                0,
                0,
                size,
                Some(address as *const c_void),
            )
        };

        let _ = unsafe { windows::Win32::Foundation::CloseHandle(map) };

        if addr.Value.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(std::slice::from_raw_parts_mut(addr.Value.cast(), size))
        }
    }

    pub(crate) fn protect(address: *const (), size: usize, mode: Mode) -> io::Result<()> {
        debug_assert_eq!(address.addr() & (page_size() - 1), 0);

        unsafe {
            windows::Win32::System::Memory::VirtualProtect(
                address.cast::<c_void>(),
                size,
                match mode {
                    Mode::Read => PAGE_READONLY,
                    Mode::Write => PAGE_READWRITE,
                    Mode::Execute => PAGE_EXECUTE_READ,
                },
                std::ptr::null_mut(),
            )
            .map_err(Into::into)
        }
    }
}

#[cfg(unix)]
mod imp {
    compile_error!("no unix yet lol skill issue");
}

pub(crate) use imp::*;
