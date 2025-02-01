#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::{field::MakeExt, EnvFilter};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .map_fmt_fields(|f| f.debug_alt())
        .init();

    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    OpenOptionsExt::access_mode(
        &mut opts,
        windows::Win32::Foundation::GENERIC_EXECUTE.0 | windows::Win32::Foundation::GENERIC_READ.0,
    );

    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "test/example_exe.exe".into());
    let file = opts.open(&path).unwrap();
    let map = unsafe { memmap2::Mmap::map(&file).unwrap() };

    portability::execute(&map, Path::new(&path));
}
