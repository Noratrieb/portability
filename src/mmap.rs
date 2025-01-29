//! memmap2 doesn't support MAP_FIXED so here's our own!

#[expect(dead_code)]
pub(crate) struct MapView(*const ());

pub(crate) enum Mode {
    Read,
    Write,
    Execute,
}

#[cfg(windows)]
mod imp {
    use std::{ffi::c_void, fs::File, io, os::windows::io::AsRawHandle, u32};

    use windows::Win32::{
        Foundation::HANDLE,
        System::Memory::{FILE_MAP_COPY, FILE_MAP_EXECUTE, FILE_MAP_READ, PAGE_EXECUTE_READ},
    };

    use super::{MapView, Mode};

    pub(crate) struct Map(HANDLE);

    pub(crate) unsafe fn map(file: File) -> io::Result<Map> {
        windows::Win32::System::Memory::CreateFileMappingA(
            HANDLE(file.as_raw_handle()),
            None,
            PAGE_EXECUTE_READ,
            0,
            0,
            None,
        )
        .map(Map)
        .map_err(Into::into)
    }

    impl Map {
        pub(crate) unsafe fn view(
            &self,
            mode: Mode,
            file_offset: u64,
            size: usize,
            address: *const (),
        ) -> Result<MapView, io::Error> {
            let addr = unsafe {
                windows::Win32::System::Memory::MapViewOfFileEx(
                    self.0,
                    match mode {
                        Mode::Read => FILE_MAP_READ,
                        Mode::Write => FILE_MAP_READ | FILE_MAP_COPY,
                        Mode::Execute => FILE_MAP_READ | FILE_MAP_EXECUTE,
                    },
                    (file_offset << 32) as u32,
                    file_offset as u32,
                    size,
                    Some(address as *const c_void),
                )
            };

            if addr.Value.is_null() {
                Err(io::Error::last_os_error())
            } else {
                Ok(MapView(addr.Value as *const ()))
            }
        }
    }

    impl Drop for Map {
        fn drop(&mut self) {
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}
#[cfg(unix)]
mod imp {
    compile_error!("no unix yet lol skill issue");
}

pub(crate) use imp::*;
