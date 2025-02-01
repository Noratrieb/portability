mod base_defs {
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
}

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
    bcrypt,
    bcryptprimitives,
    kernel32,
    ntdll,
    ole32,
    oleaut32,
    shell32,
    userenv,
    ws2_32,
);

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
                            return Some(std::mem::transmute($name::trampoline as unsafe extern "C" fn($($argty),*)));
                        }
                    }
                )*

                None
            }

            $(
                #[allow(non_snake_case)]
                mod $name {
                    #[allow(unused_imports)]
                    use crate::emulated::base_defs::*;

                    // https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions
                    cfg_if::cfg_if! {
                        if #[cfg(windows)] {
                            pub(super) unsafe extern "C" fn trampoline($($argname: $argty)*) {
                                unsafe { inner($($argname),*) }
                            }
                        } else if #[cfg(all(target_os = "linux", target_arch = "x86_64"))] {
                            #[naked_function::naked]
                            #[export_name = concat!("portability_callconv_trampoline_", stringify!($modname), "__", stringify!($name))]
                            pub(super) unsafe extern "C" fn trampoline($($argname: $argty),*) {
                                // Map Windows arguments to System V arguments.
                                // For now we only support 4 integer arguments.
                                asm!(
                                    "mov rdi, rcx", // arg 1
                                    "mov rsi, rdx", // arg 2
                                    "mov rdx, r8", // arg 3
                                    "mov rcx, r9", // arg 4
                                    "jmp {}",
                                    sym inner,
                                );
                            }
                        } else {
                            compile_error!("unsupported architecture or operating system");
                        }
                    }

                    $(#[$attr])*
                    unsafe extern "C" fn inner($($argname: $argty),*) $(-> $ret)? {
                        #[allow(unused_unsafe)]
                        unsafe { $($body)* }
                    }
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
        fn AddVectoredExceptionHandler() {
            todo!("AddVectoredExceptionHandler")
        }
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
        fn DeleteCriticalSection() {
            todo!("DeleteCriticalSection")
        }
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
        fn EnterCriticalSection() {
            todo!("EnterCriticalSection")
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
        fn FlsAlloc() {
            todo!("FlsAlloc")
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
        fn GetConsoleMode() {
            todo!("GetConsoleMode")
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
        fn GetCurrentProcessId() -> u32 {
            std::process::id()
        }
        fn GetCurrentThread() {
            todo!("GetCurrentThread")
        }
        // <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadid>
        fn GetCurrentThreadId() -> u32 {
            use std::sync::atomic;
            static THREAD_ID_COUNTER: atomic::AtomicU32 = atomic::AtomicU32::new(0);
            std::thread_local! {
                static THREAD_ID: u32 = THREAD_ID_COUNTER.fetch_add(1, atomic::Ordering::Relaxed);
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
        fn GetLastError() {
            todo!("GetLastError")
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
        fn GetModuleHandleA() {
            todo!("GetModuleHandleA")
        }
        fn GetModuleHandleExW() {
            todo!("GetModuleHandleExW")
        }
        fn GetModuleHandleW() {
            todo!("GetModuleHandleW")
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
        fn GetProcAddress(hModule: u64, lpProcName: LPCWSTR) {
            todo!("GetProcAddress: {lpProcName:?}")
        }
        fn GetProcessHeap() {
            todo!("GetProcessHeap")
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
        fn GetStdHandle() {
            todo!("GetStdHandle")
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
                dwLowDateTime: u32,
                dwHighDateTime: u32,
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
        fn HeapAlloc() {
            todo!("HeapAlloc")
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
        fn InitializeCriticalSectionEx() {
            todo!("InitializeCriticalSectionEx")
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
        fn IsDebuggerPresent() {
            todo!("IsDebuggerPresent")
        }
        fn IsProcessorFeaturePresent() {
            todo!("IsProcessorFeaturePresent")
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
        fn LoadLibraryExW(lpLibFileName: LPCWSTR, _hFile: HANDLE, _dwFlags: u32) -> u64 {
            let result = crate::load_dll(
                &format!("{}.dll", &lpLibFileName.to_string()),
                &crate::GLOBAL_STATE.executable_path(),
            );
            match result {
                crate::LoadedDll::Emulated => 1,
                crate::LoadedDll::Real(img, _, _) => img.base as u64,
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
        fn RtlPcToFileHeader() {
            todo!("RtlPcToFileHeader")
        }
        fn RtlUnwind() {
            todo!("RtlUnwind")
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
        fn SetLastError() {
            todo!("SetLastError")
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
        fn SetThreadStackGuarantee() {
            todo!("SetThreadStackGuarantee")
        }
        fn SetUnhandledExceptionFilter() {
            todo!("SetUnhandledExceptionFilter")
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
        fn UnhandledExceptionFilter() {
            todo!("UnhandledExceptionFilter")
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
        fn RtlCaptureContext() {
            todo!("RtlCaptureContext")
        }
        fn RtlGetLastNtStatus() {
            todo!("RtlGetLastNtStatus")
        }
        fn RtlLookupFunctionEntry() {
            todo!("RtlLookupFunctionEntry")
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
