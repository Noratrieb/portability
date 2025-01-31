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
    kernel32,
    vcruntime140,
    api_ms_win_crt_runtime_l1_1_0,
    api_ms_win_crt_math_l1_1_0,
    api_ms_win_crt_stdio_l1_1_0,
    api_ms_win_crt_locale_l1_1_0,
    api_ms_win_crt_heap_l1_1_0,
);

macro_rules! emulate {
    ($dllname:literal, mod $modname:ident {
        $(
            fn $name:ident($($args:tt)*) $(-> $ret:ty)? {
                $($body:tt)*
            }
        )*
    }) => {
        mod $modname {
            pub(super) const DLL_NAME: &str = $dllname;
            pub(super) fn emulate(dll_name: &str, function_name: &str) -> Option<usize> {
                if dll_name.to_lowercase() != $dllname {
                    return None;
                }

                $(
                    if function_name == stringify!($name) {
                        unsafe {
                            return Some(std::mem::transmute($name as extern "system" fn()));
                        }
                    }
                )*

                None
            }

            $(
                // TODO: Windows API adapter...
                #[allow(non_snake_case)]
                extern "system" fn $name($($args)*) $(-> $ret)? {
                    $($body)*
                }
            )*
        }
    };
}

emulate!(
    "kernel32.dll",
    mod kernel32 {
        fn QueryPerformanceCounter() {
            todo!("QueryPerformanceCounter")
        }
        fn GetCurrentProcessId() {
            todo!("GetCurrentProcessId")
        }
        fn GetCurrentThreadId() {
            todo!("GetCurrentThreadId")
        }
        fn GetSystemTimeAsFileTime() {
            todo!("GetSystemTimeAsFileTime")
        }
        fn InitializeSListHead() {
            todo!("InitializeSListHead")
        }
        fn RtlCaptureContext() {
            todo!("RtlCaptureContext")
        }
        fn RtlLookupFunctionEntry() {
            todo!("RtlLookupFunctionEntry")
        }
        fn RtlVirtualUnwind() {
            todo!("RtlVirtualUnwind")
        }
        fn IsDebuggerPresent() {
            todo!("IsDebuggerPresent")
        }
        fn UnhandledExceptionFilter() {
            todo!("UnhandledExceptionFilter")
        }
        fn SetUnhandledExceptionFilter() {
            todo!("SetUnhandledExceptionFilter")
        }
        fn IsProcessorFeaturePresent() {
            todo!("IsProcessorFeaturePresent")
        }
        fn GetModuleHandleW() {
            todo!("GetModuleHandleW")
        }
    }
);

emulate!(
    "vcruntime140.dll",
    mod vcruntime140 {
        fn __C_specific_handler() {
            todo!("__C_specific_handler")
        }
        fn __current_exception() {
            todo!("__current_exception")
        }
        fn __current_exception_context() {
            todo!("__current_exception_context")
        }
        fn memset() {
            todo!("memset")
        }
        fn memcpy() {
            todo!("memcpy")
        }
    }
);

emulate!(
    "api-ms-win-crt-runtime-l1-1-0.dll",
    mod api_ms_win_crt_runtime_l1_1_0 {
        fn _initterm_e() {
            todo!("_initterm_e")
        }
        fn exit() {
            todo!("exit")
        }
        fn _exit() {
            todo!("_exit")
        }
        fn _initterm() {
            todo!("_initterm")
        }
        fn __p___argc() {
            todo!("__p___argc")
        }
        fn __p___argv() {
            todo!("__p___argv")
        }
        fn _initialize_narrow_environment() {
            todo!("_initialize_narrow_environment")
        }
        fn _c_exit() {
            todo!("_c_exit")
        }
        fn _register_thread_local_exe_atexit_callback() {
            todo!("_register_thread_local_exe_atexit_callback")
        }
        fn _seh_filter_exe() {
            todo!("_seh_filter_exe")
        }
        fn _configure_narrow_argv() {
            todo!("_configure_narrow_argv")
        }
        fn _set_app_type() {
            todo!("_set_app_type")
        }
        fn _initialize_onexit_table() {
            todo!("_initialize_onexit_table")
        }
        fn _register_onexit_function() {
            todo!("_register_onexit_function")
        }
        fn _crt_atexit() {
            todo!("_crt_atexit")
        }
        fn terminate() {
            todo!("terminate")
        }
        fn _cexit() {
            todo!("_cexit")
        }
        fn _get_initial_narrow_environment() {
            todo!("_get_initial_narrow_environment")
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
    "api-ms-win-crt-stdio-l1-1-0.dll",
    mod api_ms_win_crt_stdio_l1_1_0 {
        fn _set_fmode() {
            todo!("_set_fmode")
        }
        fn __p__commode() {
            todo!("__p__commode")
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
    "api-ms-win-crt-heap-l1-1-0.dll",
    mod api_ms_win_crt_heap_l1_1_0 {
        fn _set_new_mode() {
            todo!("_set_new_mode")
        }
    }
);
