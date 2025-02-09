#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

mod base_defs {
    use std::{ffi::CStr, fmt::Debug, os::fd::RawFd, sync::atomic::Ordering};

    pub(crate) type SIZE_T = usize;
    pub(crate) type DWORD = i32;

    pub(crate) type HANDLE = usize;

    #[repr(transparent)]
    pub(crate) struct LPCWSTR(pub *const u16);
    impl LPCWSTR {
        pub(crate) fn to_string(&self) -> String {
            let mut s = String::new();
            unsafe {
                let mut p = self.0;
                let mut v = p.read();
                while v != 0 {
                    s.extend(std::char::decode_utf16([v]).map(Result::unwrap));
                    p = p.add(1);
                    v = p.read();
                }
            }
            s
        }
    }
    impl std::fmt::Debug for LPCWSTR {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.to_string())
        }
    }

    #[repr(transparent)]
    pub(crate) struct LPCSTR(pub *const std::ffi::c_char);
    impl LPCSTR {
        pub(crate) fn as_cstr(&self) -> &CStr {
            unsafe { CStr::from_ptr(self.0) }
        }
    }
    impl std::fmt::Debug for LPCSTR {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            Debug::fmt(self.as_cstr(), f)
        }
    }

    #[repr(C)]
    pub(super) struct CRITICAL_SECTION {
        pub(super) mutex: std::sync::atomic::AtomicU64,
        pub(super) pad: [u8; 40 - 8],
    }

    pub(crate) enum HandleImpl {
        Fd(#[expect(dead_code)] RawFd),
    }

    impl crate::GlobalStateWrapper {
        pub(crate) fn crate_handle(&self, imp: HandleImpl) -> HANDLE {
            let mut state = self.state.lock().unwrap();
            let handle = state.next_handle_nr.fetch_add(1, Ordering::Relaxed);
            assert!(state.handles.insert(handle, imp).is_none());
            handle
        }
    }
}
pub(crate) use base_defs::HandleImpl;

macro_rules! define_emulation_entry {
    ($($name:ident,)*) => {
        pub(crate) fn supports_dll(dll_name: &str) -> bool {
            [
                $($name::DLL_NAME,)*
            ]
            .contains(&dll_name.to_lowercase().as_str())
        }

        pub(crate) fn emulate(dll_name: &str, function_name: &str) -> Option<usize> {
            None
            $(.or($name::emulate(dll_name, function_name)))*
        }
    };
}

define_emulation_entry!(
    advapi32,
    api_ms_win_core_synch_l1_2_0,
    api_ms_win_core_winrt_error_l1_1_0,
    api_ms_win_crt_heap_l1_1_0,
    api_ms_win_crt_locale_l1_1_0,
    api_ms_win_crt_math_l1_1_0,
    api_ms_win_crt_runtime_l1_1_0,
    api_ms_win_crt_stdio_l1_1_0,
    bcrypt,
    bcryptprimitives,
    kernel32,
    ntdll,
    ole32,
    oleaut32,
    shell32,
    userenv,
    vcruntime140,
    ws2_32,
);

macro_rules! make_body {
    ($name:ident $($argname:ident),* @ delegate($dll:ident)) => {
        crate::emulated::$dll::$name($($argname),*)
    };
    ($name:ident $($argname:ident),* @ $($body:tt)*) => {
        #[allow(unused_unsafe)]
        unsafe { $($body)* }
    };
}

macro_rules! emulate {
    ($dllname:literal, mod $modname:ident {
        $(
            $(#[$attr:meta])*
            fn $name:ident($($argname:ident: $argty:ty),* $(,)?) $(-> $ret:ty)? {
                $($body:tt)*
            }
        )*
    }) => {
        mod $modname {
            pub(super) const DLL_NAME: &str = $dllname;
            pub(super) fn emulate(dll_name: &str, function_name: &str) -> Option<usize> {
                #[allow(unused_imports)]
                use crate::emulated::base_defs::*;

                if dll_name.to_lowercase() != $dllname {
                    return None;
                }

                $(
                    if function_name == stringify!($name) {
                        unsafe {
                            // NOTE: The ABI string is a lie.....
                            return Some(std::mem::transmute($name as unsafe extern "win64" fn($($argty),*) $(-> $ret)?));
                        }
                    }
                )*

                None
            }

            #[allow(unused_imports)]
            use crate::emulated::base_defs::*;

            $(
                $(#[$attr])*
                pub(super) unsafe extern "win64" fn $name($($argname: $argty),*) $(-> $ret)? {
                    make_body! { $name $($argname),* @ $($body)* }
                }
            )*
        }
    };
}

emulate!(
    "advapi32.dll",
    mod advapi32 {
        fn CryptAcquireContextW() {
            todo!("CryptAcquireContextW")
        }
        fn CryptGenRandom() {
            todo!("CryptGenRandom")
        }
        fn CryptReleaseContext() {
            todo!("CryptReleaseContext")
        }
        fn RegCloseKey() {
            todo!("RegCloseKey")
        }
        fn RegEnumKeyExW() {
            todo!("RegEnumKeyExW")
        }
        fn RegGetValueW() {
            todo!("RegGetValueW")
        }
        fn RegOpenKeyExA() {
            todo!("RegOpenKeyExA")
        }
        fn RegOpenKeyExW() {
            todo!("RegOpenKeyExW")
        }
        fn RegQueryValueExW() {
            todo!("RegQueryValueExW")
        }
        fn SystemFunction036() {
            todo!("SystemFunction036")
        }
    }
);

emulate!(
    "api-ms-win-core-synch-l1-2-0.dll",
    mod api_ms_win_core_synch_l1_2_0 {
        fn InitializeCriticalSectionEx(
            lpCriticalSection: *mut (),
            dwSpinCount: DWORD,
            flags: DWORD,
        ) -> bool {
            delegate(kernel32)
        }
        fn WaitOnAddress() {
            todo!("WaitOnAddress")
        }
        fn WakeByAddressAll() {
            todo!("WakeByAddressAll")
        }
        fn WakeByAddressSingle() {
            todo!("WakeByAddressSingle")
        }
    }
);
emulate!(
    "api-ms-win-core-winrt-error-l1-1-0.dll",
    mod api_ms_win_core_winrt_error_l1_1_0 {
        fn RoOriginateErrorW() {
            todo!("RoOriginateErrorW")
        }
    }
);

emulate!(
    "api-ms-win-crt-heap-l1-1-0.dll",
    mod api_ms_win_crt_heap_l1_1_0 {
        fn _set_new_mode() {
            todo!("_set_new_mode")
        }
        fn free() {
            todo!("free")
        }
    }
);

emulate!(
    "api-ms-win-crt-locale-l1-1-0.dll",
    mod api_ms_win_crt_locale_l1_1_0 {
        fn _configthreadlocale() {
            todo!("_configthreadlocale")
        }
    }
);
emulate!(
    "api-ms-win-crt-math-l1-1-0.dll",
    mod api_ms_win_crt_math_l1_1_0 {
        fn __setusermatherr() {
            todo!("__setusermatherr")
        }
    }
);

emulate!(
    "api-ms-win-crt-runtime-l1-1-0.dll",
    mod api_ms_win_crt_runtime_l1_1_0 {
        fn __p___argc() -> *const DWORD {
            static ARGC: i32 = 1;
            (&raw const ARGC).cast()
        }
        /// returns the address of argv
        fn __p___argv() -> *const *const *const u8 {
            static EMPTY_ARGS: [usize; 1] = [0];
            static ARGV: &[usize; 1] = &EMPTY_ARGS;
            (&raw const ARGV).cast()
        }
        fn _c_exit() {
            todo!("_c_exit")
        }
        fn _cexit() {
            todo!("_cexit")
        }
        fn _crt_atexit() {
            todo!("_crt_atexit")
        }
        fn _configure_narrow_argv() {
            todo!("_configure_narrow_argv")
        }
        fn _exit() {
            todo!("_exit")
        }
        fn _get_initial_narrow_environment() -> *const () {
            std::ptr::null()
        }
        fn _initialize_narrow_environment() {
            todo!("_initialize_narrow_environment")
        }
        fn _initialize_onexit_table() {
            todo!("_initialize_onexit_table")
        }
        /// <https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/initterm-initterm-e?view=msvc-170>
        fn _initterm(_start: *const (), _end: *const ()) {}
        /// <https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/initterm-initterm-e?view=msvc-170>
        fn _initterm_e(_start: *const (), _end: *const ()) -> DWORD {
            0
        }
        fn _register_onexit_function() {
            todo!("_register_onexit_function")
        }
        fn _register_thread_local_exe_atexit_callback() {
            todo!("_register_thread_local_exe_atexit_callback")
        }
        fn _seh_filter_exe() {
            todo!("_seh_filter_exe")
        }
        fn _set_app_type() {
            todo!("_set_app_type")
        }
        /// <https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/exit-exit-exit?view=msvc-170>
        fn exit(code: i32) -> ! {
            tracing::info!("application requested exit with code {code}");
            // TODO: we need to do all kinds of cleanup
            std::process::exit(code);
        }
        fn terminate() {
            todo!("terminate")
        }
    }
);

emulate!(
    "api-ms-win-crt-stdio-l1-1-0.dll",
    mod api_ms_win_crt_stdio_l1_1_0 {
        fn __p__commode() {
            todo!("__p__commode")
        }
        fn _set_fmode() {
            todo!("_set_fmode")
        }
    }
);

emulate!(
    "bcrypt.dll",
    mod bcrypt {
        fn BCryptGenRandom() {
            todo!("BCryptGenRandom")
        }
    }
);
emulate!(
    "bcryptprimitives.dll",
    mod bcryptprimitives {
        fn ProcessPrng() {
            todo!("ProcessPrng")
        }
    }
);
emulate!(
    "kernel32.dll",
    mod kernel32 {
        fn AcquireSRWLockExclusive() {
            todo!("AcquireSRWLockExclusive")
        }
        fn AcquireSRWLockShared() {
            todo!("AcquireSRWLockShared")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler>
        fn AddVectoredExceptionHandler(_first: u64, _handler: *const ()) {}
        fn AssignProcessToJobObject() {
            todo!("AssignProcessToJobObject")
        }
        fn CancelIo() {
            todo!("CancelIo")
        }
        fn CloseHandle() {
            todo!("CloseHandle")
        }
        fn CompareStringOrdinal() {
            todo!("CompareStringOrdinal")
        }
        fn CompareStringW() {
            todo!("CompareStringW")
        }
        fn ConvertFiberToThread() {
            todo!("ConvertFiberToThread")
        }
        fn ConvertThreadToFiber() {
            todo!("ConvertThreadToFiber")
        }
        fn CopyFileExW() {
            todo!("CopyFileExW")
        }
        fn CreateDirectoryW() {
            todo!("CreateDirectoryW")
        }
        fn CreateEventA() {
            todo!("CreateEventA")
        }
        fn CreateEventW() {
            todo!("CreateEventW")
        }
        fn CreateFiber() {
            todo!("CreateFiber")
        }
        fn CreateFileMappingW() {
            todo!("CreateFileMappingW")
        }
        fn CreateFileW() {
            todo!("CreateFileW")
        }
        fn CreateHardLinkW() {
            todo!("CreateHardLinkW")
        }
        fn CreateJobObjectW() {
            todo!("CreateJobObjectW")
        }
        fn CreateMutexA() {
            todo!("CreateMutexA")
        }
        fn CreateNamedPipeW() {
            todo!("CreateNamedPipeW")
        }
        fn CreatePipe() {
            todo!("CreatePipe")
        }
        fn CreateProcessW() {
            todo!("CreateProcessW")
        }
        fn CreateSemaphoreA() {
            todo!("CreateSemaphoreA")
        }
        fn CreateSymbolicLinkW() {
            todo!("CreateSymbolicLinkW")
        }
        fn CreateThread() {
            todo!("CreateThread")
        }
        fn CreateWaitableTimerExW() {
            todo!("CreateWaitableTimerExW")
        }
        fn DebugBreak() {
            todo!("DebugBreak")
        }
        fn DecodePointer() {
            todo!("DecodePointer")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-deletecriticalsection>
        fn DeleteCriticalSection(_lpCriticalSection: *mut ()) {}
        fn DeleteFiber() {
            todo!("DeleteFiber")
        }
        fn DeleteFileW() {
            todo!("DeleteFileW")
        }
        fn DeleteProcThreadAttributeList() {
            todo!("DeleteProcThreadAttributeList")
        }
        fn DeviceIoControl() {
            todo!("DeviceIoControl")
        }
        fn DuplicateHandle() {
            todo!("DuplicateHandle")
        }
        fn EncodePointer() {
            todo!("EncodePointer")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-entercriticalsection>
        fn EnterCriticalSection(lpCriticalSection: *mut CRITICAL_SECTION) {
            // a shitty spinlock
            while (&*lpCriticalSection)
                .mutex
                .compare_exchange_weak(
                    0,
                    1,
                    std::sync::atomic::Ordering::Acquire,
                    std::sync::atomic::Ordering::Relaxed,
                )
                .is_err()
            {}
        }
        fn EnumSystemLocalesW() {
            todo!("EnumSystemLocalesW")
        }
        fn ExitProcess() {
            todo!("ExitProcess")
        }
        fn ExpandEnvironmentStringsW() {
            todo!("ExpandEnvironmentStringsW")
        }
        fn FindClose() {
            todo!("FindClose")
        }
        fn FindFirstFileExW() {
            todo!("FindFirstFileExW")
        }
        fn FindNextFileW() {
            todo!("FindNextFileW")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsalloc>
        fn FlsAlloc(_callback: extern "win64" fn()) -> DWORD {
            const FLS_OUT_OF_INDEXES: DWORD = -1_i32;
            FLS_OUT_OF_INDEXES
        }
        fn FlsFree() {
            todo!("FlsFree")
        }
        fn FlsGetValue() {
            todo!("FlsGetValue")
        }
        fn FlsSetValue() {
            todo!("FlsSetValue")
        }
        fn FlushFileBuffers() {
            todo!("FlushFileBuffers")
        }
        fn FlushViewOfFile() {
            todo!("FlushViewOfFile")
        }
        fn FormatMessageA() {
            todo!("FormatMessageA")
        }
        fn FormatMessageW() {
            todo!("FormatMessageW")
        }
        fn FreeEnvironmentStringsW() {
            todo!("FreeEnvironmentStringsW")
        }
        fn FreeLibrary() {
            todo!("FreeLibrary")
        }
        fn GetACP() {
            todo!("GetACP")
        }
        fn GetCPInfo() {
            todo!("GetCPInfo")
        }
        fn GetCommandLineA() {
            todo!("GetCommandLineA")
        }
        fn GetCommandLineW() {
            todo!("GetCommandLineW")
        }
        fn GetComputerNameExW() {
            todo!("GetComputerNameExW")
        }
        /// <https://learn.microsoft.com/en-us/windows/console/getconsolemode>
        fn GetConsoleMode(_hConsoleHandle: HANDLE, _lpMode: *mut DWORD) -> bool {
            true
        }
        fn GetConsoleOutputCP() {
            todo!("GetConsoleOutputCP")
        }
        fn GetConsoleScreenBufferInfo() {
            todo!("GetConsoleScreenBufferInfo")
        }
        fn GetCurrentDirectoryW() {
            todo!("GetCurrentDirectoryW")
        }
        fn GetCurrentProcess() {
            todo!("GetCurrentProcess")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid>
        fn GetCurrentProcessId() -> DWORD {
            std::process::id() as DWORD
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthread>
        fn GetCurrentThread() -> *mut () {
            std::ptr::dangling_mut()
        }
        // <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadid>
        fn GetCurrentThreadId() -> DWORD {
            use std::sync::atomic;
            static THREAD_ID_COUNTER: atomic::AtomicI32 = atomic::AtomicI32::new(0);
            std::thread_local! {
                static THREAD_ID: DWORD = THREAD_ID_COUNTER.fetch_add(1, atomic::Ordering::Relaxed);
            }

            THREAD_ID.with(|id| *id)
        }
        fn GetDateFormatW() {
            todo!("GetDateFormatW")
        }
        fn GetDriveTypeW() {
            todo!("GetDriveTypeW")
        }
        fn GetEnvironmentStringsW() {
            todo!("GetEnvironmentStringsW")
        }
        fn GetEnvironmentVariableW() {
            todo!("GetEnvironmentVariableW")
        }
        fn GetExitCodeProcess() {
            todo!("GetExitCodeProcess")
        }
        fn GetFileAttributesW() {
            todo!("GetFileAttributesW")
        }
        fn GetFileInformationByHandle() {
            todo!("GetFileInformationByHandle")
        }
        fn GetFileInformationByHandleEx() {
            todo!("GetFileInformationByHandleEx")
        }
        fn GetFileSizeEx() {
            todo!("GetFileSizeEx")
        }
        fn GetFileType() {
            todo!("GetFileType")
        }
        fn GetFinalPathNameByHandleW() {
            todo!("GetFinalPathNameByHandleW")
        }
        fn GetFullPathNameW() {
            todo!("GetFullPathNameW")
        }
        fn GetLastError() -> DWORD {
            crate::THREAD_STATE.with(|state| (*state.state.borrow().teb).last_error_number)
        }
        fn GetLocaleInfoEx() {
            todo!("GetLocaleInfoEx")
        }
        fn GetLocaleInfoW() {
            todo!("GetLocaleInfoW")
        }
        fn GetLogicalProcessorInformation() {
            todo!("GetLogicalProcessorInformation")
        }
        fn GetModuleFileNameW() {
            todo!("GetModuleFileNameW")
        }
        fn GetModuleHandleA() -> HANDLE {
            tracing::error!("TODO GetModuleHandleW");
            0
        }
        fn GetModuleHandleExW() -> HANDLE {
            tracing::error!("TODO GetModuleHandleW");
            0
        }
        fn GetModuleHandleW() -> HANDLE {
            tracing::error!("TODO GetModuleHandleW");
            0
        }
        fn GetNativeSystemInfo() {
            todo!("GetNativeSystemInfo")
        }
        fn GetOEMCP() {
            todo!("GetOEMCP")
        }
        fn GetOverlappedResult() {
            todo!("GetOverlappedResult")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress>
        fn GetProcAddress(hModule: u64, lpProcName: LPCSTR) -> usize {
            let dll = crate::GLOBAL_STATE
                .state
                .lock()
                .unwrap()
                .hmodule_to_dll
                .get(&hModule)
                .cloned()
                .unwrap();
            // TODO: error handling...
            crate::va_for_dll_export_by_name(&dll, lpProcName.as_cstr(), 0)
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-getprocessheap>
        fn GetProcessHeap() -> HANDLE {
            1
        }
        fn GetProcessId() {
            todo!("GetProcessId")
        }
        fn GetProcessTimes() {
            todo!("GetProcessTimes")
        }
        fn GetStartupInfoW() {
            todo!("GetStartupInfoW")
        }
        /// <https://learn.microsoft.com/en-us/windows/console/getstdhandle>
        fn GetStdHandle(nStdHandle: DWORD) -> HANDLE {
            const STD_INPUT_HANDLE: DWORD = -10;
            const STD_OUTPUT_HANDLE: DWORD = -11;
            const STD_ERROR_HANDLE: DWORD = -12;

            let fd = match nStdHandle {
                STD_INPUT_HANDLE => 0,
                STD_OUTPUT_HANDLE => 1,
                STD_ERROR_HANDLE => 2,
                _ => panic!("invalid std handle: {nStdHandle}"),
            };

            crate::GLOBAL_STATE.crate_handle(HandleImpl::Fd(fd))
        }
        fn GetStringTypeW() {
            todo!("GetStringTypeW")
        }
        fn GetSystemDirectoryW() {
            todo!("GetSystemDirectoryW")
        }
        fn GetSystemInfo() {
            todo!("GetSystemInfo")
        }
        fn GetSystemTime() {
            todo!("GetSystemTime")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime>
        fn GetSystemTimeAsFileTime(lpSystemTimeAsFileTime: *mut std::ffi::c_void) {
            #[repr(C)]
            struct _FILETIME {
                dwLowDateTime: DWORD,
                dwHighDateTime: DWORD,
            }
            lpSystemTimeAsFileTime.cast::<_FILETIME>().write(_FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            });
        }
        fn GetSystemTimePreciseAsFileTime() {
            todo!("GetSystemTimePreciseAsFileTime")
        }
        fn GetTempPathW() {
            todo!("GetTempPathW")
        }
        fn GetTimeFormatW() {
            todo!("GetTimeFormatW")
        }
        fn GetTimeZoneInformation() {
            todo!("GetTimeZoneInformation")
        }
        fn GetUserDefaultLCID() {
            todo!("GetUserDefaultLCID")
        }
        fn GetVolumePathNameW() {
            todo!("GetVolumePathNameW")
        }
        fn GetWindowsDirectoryW() {
            todo!("GetWindowsDirectoryW")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc>
        fn HeapAlloc(heap: HANDLE, dwFlags: DWORD, dwBytes: SIZE_T) -> *mut u8 {
            const HEAP_GENERATE_EXCEPTIONS: DWORD = 0x00000004;
            const HEAP_ZERO_MEMORY: DWORD = 0x00000008;
            assert_eq!(heap, 1);

            let layout = std::alloc::Layout::from_size_align(dwBytes as usize, 8).unwrap();

            let result = if (dwFlags & HEAP_ZERO_MEMORY) == 1 {
                std::alloc::alloc_zeroed(layout)
            } else {
                std::alloc::alloc(layout)
            };
            if (dwFlags & HEAP_GENERATE_EXCEPTIONS) == 1 && result.is_null() {
                panic!("throw exception lol");
            }
            result
        }
        fn HeapFree() {
            todo!("HeapFree")
        }
        fn HeapQueryInformation() {
            todo!("HeapQueryInformation")
        }
        fn HeapReAlloc() {
            todo!("HeapReAlloc")
        }
        fn HeapSize() {
            todo!("HeapSize")
        }
        fn HeapValidate() {
            todo!("HeapValidate")
        }
        fn HeapWalk() {
            todo!("HeapWalk")
        }
        fn InitOnceBeginInitialize() {
            todo!("InitOnceBeginInitialize")
        }
        fn InitOnceComplete() {
            todo!("InitOnceComplete")
        }
        fn InitializeCriticalSection() {
            todo!("InitializeCriticalSection")
        }
        fn InitializeCriticalSectionAndSpinCount() {
            todo!("InitializeCriticalSectionAndSpinCount")
        }
        fn InitializeCriticalSectionEx(
            lpCriticalSection: *mut (),
            _dwSpinCount: DWORD,
            _flags: DWORD,
        ) -> bool {
            lpCriticalSection
                .cast::<CRITICAL_SECTION>()
                .write(CRITICAL_SECTION {
                    mutex: Default::default(),
                    pad: Default::default(),
                });
            const _: () = assert!(size_of::<CRITICAL_SECTION>() == 40);
            true
        }
        fn InitializeProcThreadAttributeList() {
            todo!("InitializeProcThreadAttributeList")
        }
        fn InitializeSListHead() {
            todo!("InitializeSListHead")
        }
        fn InterlockedFlushSList() {
            todo!("InterlockedFlushSList")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent>
        fn IsDebuggerPresent() -> bool {
            false
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent>
        fn IsProcessorFeaturePresent(_ProcessorFeature: DWORD) -> bool {
            false
        }
        fn IsThreadAFiber() {
            todo!("IsThreadAFiber")
        }
        fn IsValidCodePage() {
            todo!("IsValidCodePage")
        }
        fn IsValidLocale() {
            todo!("IsValidLocale")
        }
        fn K32EnumProcessModulesEx() {
            todo!("K32EnumProcessModulesEx")
        }
        fn K32GetProcessMemoryInfo() {
            todo!("K32GetProcessMemoryInfo")
        }
        fn LCMapStringEx() {
            todo!("LCMapStringEx")
        }
        fn LCMapStringW() {
            todo!("LCMapStringW")
        }
        fn LeaveCriticalSection() {
            todo!("LeaveCriticalSection")
        }
        fn LoadLibraryA() {
            todo!("LoadLibraryA")
        }
        fn LoadLibraryExA() {
            todo!("LoadLibraryExA")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw>
        fn LoadLibraryExW(lpLibFileName: LPCWSTR, _hFile: HANDLE, _dwFlags: DWORD) -> u64 {
            let result = crate::load_dll(
                &format!("{}.dll", &lpLibFileName.to_string()),
                &crate::GLOBAL_STATE.executable_path(),
            );
            match result {
                Some(result) => result.hmodule(),
                None => 0,
            }
        }
        fn LoadLibraryW() {
            todo!("LoadLibraryW")
        }
        fn LocalFree() {
            todo!("LocalFree")
        }
        fn LockFileEx() {
            todo!("LockFileEx")
        }
        fn MapViewOfFile() {
            todo!("MapViewOfFile")
        }
        fn MoveFileExW() {
            todo!("MoveFileExW")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar>
        fn MultiByteToWideChar() {
            todo!("MultiByteToWideChar")
        }
        fn OpenSemaphoreA() {
            todo!("OpenSemaphoreA")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter>
        fn QueryPerformanceCounter(lpPerformanceCount: *mut u64) -> bool {
            lpPerformanceCount.write(0);
            true
        }
        fn QueryPerformanceFrequency() {
            todo!("QueryPerformanceFrequency")
        }
        fn RaiseException() {
            todo!("RaiseException")
        }
        fn ReOpenFile() {
            todo!("ReOpenFile")
        }
        fn ReadConsoleW() {
            todo!("ReadConsoleW")
        }
        fn ReadFile() {
            todo!("ReadFile")
        }
        fn ReadFileEx() {
            todo!("ReadFileEx")
        }
        fn ReleaseMutex() {
            todo!("ReleaseMutex")
        }
        fn ReleaseSRWLockExclusive() {
            todo!("ReleaseSRWLockExclusive")
        }
        fn ReleaseSRWLockShared() {
            todo!("ReleaseSRWLockShared")
        }
        fn ReleaseSemaphore() {
            todo!("ReleaseSemaphore")
        }
        fn RemoveDirectoryW() {
            todo!("RemoveDirectoryW")
        }
        fn ResumeThread() {
            todo!("ResumeThread")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlcapturecontext>
        fn RtlCaptureContext() {
            delegate(ntdll)
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtllookupfunctionentry>
        fn RtlLookupFunctionEntry(
            _ControlPc: u64,
            _ImageBase: *mut (),
            _HistoryTable: *mut (),
        ) -> *const () {
            delegate(ntdll)
        }
        fn RtlPcToFileHeader() {
            todo!("RtlPcToFileHeader")
        }
        fn RtlUnwind() {
            todo!("RtlUnwind")
        }
        fn RtlVirtualUnwind() {
            todo!("RtlVirtualUnwind")
        }
        fn SearchPathW() {
            todo!("SearchPathW")
        }
        fn SetConsoleCtrlHandler() {
            todo!("SetConsoleCtrlHandler")
        }
        fn SetConsoleMode() {
            todo!("SetConsoleMode")
        }
        fn SetConsoleTextAttribute() {
            todo!("SetConsoleTextAttribute")
        }
        fn SetCurrentDirectoryW() {
            todo!("SetCurrentDirectoryW")
        }
        fn SetEnvironmentVariableW() {
            todo!("SetEnvironmentVariableW")
        }
        fn SetErrorMode() {
            todo!("SetErrorMode")
        }
        fn SetEvent() {
            todo!("SetEvent")
        }
        fn SetFileAttributesW() {
            todo!("SetFileAttributesW")
        }
        fn SetFileInformationByHandle() {
            todo!("SetFileInformationByHandle")
        }
        fn SetFilePointerEx() {
            todo!("SetFilePointerEx")
        }
        fn SetFileTime() {
            todo!("SetFileTime")
        }
        fn SetHandleInformation() {
            todo!("SetHandleInformation")
        }
        fn SetInformationJobObject() {
            todo!("SetInformationJobObject")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setlasterror>
        fn SetLastError(dw_err_code: DWORD) {
            crate::THREAD_STATE
                .with(|state| (*state.state.borrow_mut().teb).last_error_number = dw_err_code);
        }
        fn SetProcessAffinityMask() {
            todo!("SetProcessAffinityMask")
        }
        fn SetStdHandle() {
            todo!("SetStdHandle")
        }
        fn SetThreadErrorMode() {
            todo!("SetThreadErrorMode")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadstackguarantee>
        fn SetThreadStackGuarantee(_stack_size_in_bytes: *mut u64) {}
        /// <https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter>
        fn SetUnhandledExceptionFilter(_lpTopLevelExceptionFilter: *mut ()) -> *mut () {
            std::ptr::null_mut()
        }
        fn SetWaitableTimer() {
            todo!("SetWaitableTimer")
        }
        fn Sleep() {
            todo!("Sleep")
        }
        fn SleepConditionVariableSRW() {
            todo!("SleepConditionVariableSRW")
        }
        fn SleepEx() {
            todo!("SleepEx")
        }
        fn SwitchToFiber() {
            todo!("SwitchToFiber")
        }
        fn SwitchToThread() {
            todo!("SwitchToThread")
        }
        fn SystemTimeToFileTime() {
            todo!("SystemTimeToFileTime")
        }
        fn TerminateProcess() {
            todo!("TerminateProcess")
        }
        fn TlsAlloc() {
            todo!("TlsAlloc")
        }
        fn TlsFree() {
            todo!("TlsFree")
        }
        fn TlsGetValue() {
            todo!("TlsGetValue")
        }
        fn TlsSetValue() {
            todo!("TlsSetValue")
        }
        fn TryAcquireSRWLockExclusive() {
            todo!("TryAcquireSRWLockExclusive")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-unhandledexceptionfilter>
        fn UnhandledExceptionFilter(_ExceptionInfo: *const ()) -> u64 {
            const EXCEPTION_CONTINUE_SEARCH: u64 = 0x0;
            EXCEPTION_CONTINUE_SEARCH
        }
        fn UnlockFile() {
            todo!("UnlockFile")
        }
        fn UnlockFileEx() {
            todo!("UnlockFileEx")
        }
        fn UnmapViewOfFile() {
            todo!("UnmapViewOfFile")
        }
        fn UpdateProcThreadAttribute() {
            todo!("UpdateProcThreadAttribute")
        }
        fn VirtualProtect() {
            todo!("VirtualProtect")
        }
        fn VirtualQuery() {
            todo!("VirtualQuery")
        }
        fn WaitForMultipleObjects() {
            todo!("WaitForMultipleObjects")
        }
        fn WaitForSingleObject() {
            todo!("WaitForSingleObject")
        }
        fn WaitForSingleObjectEx() {
            todo!("WaitForSingleObjectEx")
        }
        fn WakeAllConditionVariable() {
            todo!("WakeAllConditionVariable")
        }
        fn WideCharToMultiByte() {
            todo!("WideCharToMultiByte")
        }
        fn WriteConsoleW() {
            todo!("WriteConsoleW")
        }
        fn WriteFile() {
            todo!("WriteFile")
        }
        fn WriteFileEx() {
            todo!("WriteFileEx")
        }
        fn lstrlenW() {
            todo!("lstrlenW")
        }
    }
);
emulate!(
    "ntdll.dll",
    mod ntdll {
        fn NtOpenFile() {
            todo!("NtOpenFile")
        }
        fn NtReadFile() {
            todo!("NtReadFile")
        }
        fn NtWriteFile() {
            todo!("NtWriteFile")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlcapturecontext>
        fn RtlCaptureContext() {
            tracing::error!("TODO: RtlCaptureContext - looks like someone feels like crashing...")
        }
        fn RtlGetLastNtStatus() {
            todo!("RtlGetLastNtStatus")
        }
        /// <https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtllookupfunctionentry>
        fn RtlLookupFunctionEntry(
            _ControlPc: u64,
            _ImageBase: *mut (),
            _HistoryTable: *mut (),
        ) -> *const () {
            std::ptr::null()
        }
        fn RtlNtStatusToDosError() {
            todo!("RtlNtStatusToDosError")
        }
        fn RtlPcToFileHeader() {
            todo!("RtlPcToFileHeader")
        }
        fn RtlUnwindEx() {
            todo!("RtlUnwindEx")
        }
        fn RtlVirtualUnwind() {
            todo!("RtlVirtualUnwind")
        }
    }
);
emulate!(
    "ole32.dll",
    mod ole32 {
        fn CoCreateGuid() {
            todo!("CoCreateGuid")
        }
        fn CoCreateInstance() {
            todo!("CoCreateInstance")
        }
        fn CoInitializeEx() {
            todo!("CoInitializeEx")
        }
        fn CoTaskMemFree() {
            todo!("CoTaskMemFree")
        }
    }
);
emulate!(
    "oleaut32.dll",
    mod oleaut32 {
        fn GetErrorInfo() {
            todo!("GetErrorInfo")
        }
        fn SetErrorInfo() {
            todo!("SetErrorInfo")
        }
        fn SysAllocStringLen() {
            todo!("SysAllocStringLen")
        }
        fn SysFreeString() {
            todo!("SysFreeString")
        }
        fn SysStringLen() {
            todo!("SysStringLen")
        }
    }
);
emulate!(
    "shell32.dll",
    mod shell32 {
        fn SHGetKnownFolderPath() {
            todo!("SHGetKnownFolderPath")
        }
    }
);
emulate!(
    "userenv.dll",
    mod userenv {
        fn GetUserProfileDirectoryW() {
            todo!("GetUserProfileDirectoryW")
        }
    }
);

emulate!(
    "vcruntime140.dll",
    mod vcruntime140 {
        fn __current_exception() {
            todo!("__current_exception")
        }
        fn __current_exception_context() {
            todo!("__current_exception_context")
        }
        fn __C_specific_handler() {
            todo!("__C_specific_handler")
        }
        fn __CxxFrameHandler3() {
            todo!("__CxxFrameHandler3")
        }
        fn _CxxThrowException() {
            todo!("_CxxThrowException")
        }
        fn memcpy() {
            todo!("memcpy")
        }
        fn memcmp() {
            todo!("memcmp")
        }
        fn memmove() {
            todo!("memmove")
        }
        fn memset() {
            todo!("memset")
        }
    }
);

emulate!(
    "ws2_32.dll",
    mod ws2_32 {
        fn WSADuplicateSocketW() {
            todo!("WSADuplicateSocketW")
        }
        fn WSARecv() {
            todo!("WSARecv")
        }
        fn WSASend() {
            todo!("WSASend")
        }
        fn WSASocketW() {
            todo!("WSASocketW")
        }
        fn freeaddrinfo() {
            todo!("freeaddrinfo")
        }
        fn getaddrinfo() {
            todo!("getaddrinfo")
        }
    }
);
