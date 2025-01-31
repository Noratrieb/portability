#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

fn main() {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    OpenOptionsExt::access_mode(
        &mut opts,
        windows::Win32::Foundation::GENERIC_EXECUTE.0 | windows::Win32::Foundation::GENERIC_READ.0,
    );

    let file = opts
        .open(
            std::env::args()
                .nth(1)
                .unwrap_or_else(|| "example_exe.exe".into()),
        )
        .unwrap();
    let map = unsafe { memmap2::Mmap::map(&file).unwrap() };

    portability::execute(&map);
}
