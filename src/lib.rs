mod emulated;
mod sys;

use std::{
    ffi::CStr,
    fmt::Debug,
    ops::Deref,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
struct CoffHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: Characteristics,
}

#[derive(Clone, Copy, Debug, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
struct OptionalHeader {
    // standard COFF
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    // Windows extension
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: DllCharacteristics,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    sizeof_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    // Data directories
    export_table: DataDirectory,
    import_table: DataDirectory,
    resource_table: DataDirectory,
    exception_table: DataDirectory,
    certificate_table: DataDirectory,
    base_relocation_table: DataDirectory,
    debug: DataDirectory,
    architecture: DataDirectory,
    global_ptr: DataDirectory,
    tls_table: DataDirectory,
    load_config_table: DataDirectory,
    bound_import: DataDirectory,
    iat: DataDirectory,
    delay_import_descriptor: DataDirectory,
    clr_runtime_header: DataDirectory,
    _reserved: DataDirectory,
}

#[derive(Clone, Copy, Debug, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
struct DataDirectory {
    // RVA
    va: u32,
    size: u32,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, bytemuck::Zeroable, bytemuck::Pod)]
    #[repr(transparent)]
    pub struct Characteristics: u16 {
        const IMAGE_FILE_RELOCS_STRIPPED = 0x0001; // Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
        const IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002; // Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
        const IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004; // COFF line numbers have been removed. This flag is deprecated and should be zero.
        const IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008; // COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
        const IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010; // Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
        const IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020; // Application can handle > 2-GB addresses.
        const IMAGE_FILE_BYTES_REVERSED_LO = 0x0080; // Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
        const IMAGE_FILE_32BIT_MACHINE = 0x0100; // Machine is based on a 32-bit-word architecture.
        const IMAGE_FILE_DEBUG_STRIPPED = 0x0200; // Debugging information is removed from the image file.
        const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400; // If the image is on removable media, fully load it and copy it to the swap file.
        const IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800; // If the image is on network media, fully load it and copy it to the swap file.
        const IMAGE_FILE_SYSTEM = 0x1000; // The image file is a system file, not a user program.
        const IMAGE_FILE_DLL = 0x2000; // The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
        const IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000; // The file should be run only on a uniprocessor machine.
        const IMAGE_FILE_BYTES_REVERSED_HI = 0x8000; // Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, bytemuck::Zeroable, bytemuck::Pod)]
    #[repr(transparent)]
    pub struct DllCharacteristics: u16 {
        const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020; // Image can handle a high entropy 64-bit virtual address space.
        const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040; // DLL can be relocated at load time.
        const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080; // Code Integrity checks are enforced.
        const IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100; // Image is NX compatible.
        const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200; // Isolation aware, but do not isolate the image.
        const IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400; // Does not use structured exception (SE) handling. No SE handler may be called in this image.
        const IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800; // Do not bind the image.
        const IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000; // Image must execute in an AppContainer.
        const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000; // A WDM driver.
        const IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000; // Image supports Control Flow Guard.
        const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000; // Terminal Server aware.
    }
}

#[derive(Clone, Copy, Debug, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
struct SectionHeader {
    name: SectionName,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: SectionFlags,
}

#[derive(Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(transparent)]
struct SectionName([u8; 8]);
impl Debug for SectionName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = CStr::from_bytes_until_nul(&self.0).unwrap();
        f.write_str(s.to_str().unwrap())
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, bytemuck::Zeroable, bytemuck::Pod)]
    #[repr(transparent)]
    pub struct SectionFlags: u32 {
        const IMAGE_SCN_TYPE_NO_PAD = 0x00000008; // The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
        const IMAGE_SCN_CNT_CODE = 0x00000020; // The section contains executable code.
        const IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040; // The section contains initialized data.
        const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080; // The section contains uninitialized data.
        const IMAGE_SCN_LNK_OTHER = 0x00000100; // Reserved for future use.
        const IMAGE_SCN_LNK_INFO = 0x00000200; // The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
        const IMAGE_SCN_LNK_REMOVE = 0x00000800; // The section will not become part of the image. This is valid only for object files.
        const IMAGE_SCN_LNK_COMDAT = 0x00001000; // The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
        const IMAGE_SCN_GPREL = 0x00008000; // The section contains data referenced through the global pointer (GP).
        const IMAGE_SCN_MEM_PURGEABLE = 0x00020000; // Reserved for future use.
        const IMAGE_SCN_MEM_16BIT = 0x00020000; // Reserved for future use.
        const IMAGE_SCN_MEM_LOCKED = 0x00040000; // Reserved for future use.
        const IMAGE_SCN_MEM_PRELOAD = 0x00080000; // Reserved for future use.
        const IMAGE_SCN_ALIGN_1BYTES = 0x00100000; // Align data on a 1-byte boundary. Valid only for object files.
        const IMAGE_SCN_ALIGN_2BYTES = 0x00200000; // Align data on a 2-byte boundary. Valid only for object files.
        const IMAGE_SCN_ALIGN_4BYTES = 0x00300000; // Align data on a 4-byte boundary. Valid only for object files.
        const IMAGE_SCN_ALIGN_8BYTES = 0x00400000; // Align data on an 8-byte boundary. Valid only for object files.
        const IMAGE_SCN_ALIGN_16BYTES = 0x00500000; // Align data on a 16-byte boundary. Valid only for object files.
        const IMAGE_SCN_ALIGN_32BYTES = 0x00600000; // Align data on a 32-byte boundary. Valid only for object files.
        const IMAGE_SCN_ALIGN_64BYTES = 0x00700000; // Align data on a 64-byte boundary. Valid only for object files.
        const IMAGE_SCN_ALIGN_128BYTES = 0x00800000; // Align data on a 128-byte boundary. Valid only for object files.
        const IMAGE_SCN_ALIGN_256BYTES = 0x00900000; // Align data on a 256-byte boundary. Valid only for object files.
        const IMAGE_SCN_ALIGN_512BYTES = 0x00A00000; // Align data on a 512-byte boundary. Valid only for object files.
        const IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000; // Align data on a 1024-byte boundary. Valid only for object files.
        const IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000; // Align data on a 2048-byte boundary. Valid only for object files.
        const IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000; // Align data on a 4096-byte boundary. Valid only for object files.
        const IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000; // Align data on an 8192-byte boundary. Valid only for object files.
        const IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000; // The section contains extended relocations.
        const IMAGE_SCN_MEM_DISCARDABLE = 0x02000000; // The section can be discarded as needed.
        const IMAGE_SCN_MEM_NOT_CACHED = 0x04000000; // The section cannot be cached.
        const IMAGE_SCN_MEM_NOT_PAGED = 0x08000000; // The section is not pageable.
        const IMAGE_SCN_MEM_SHARED = 0x10000000; // The section can be shared in memory.
        const IMAGE_SCN_MEM_EXECUTE = 0x20000000; // The section can be executed as code.
        const IMAGE_SCN_MEM_READ = 0x40000000; // The section can be read.
        const IMAGE_SCN_MEM_WRITE = 0x80000000; // The section can be written to.

    }
}

#[derive(Clone, Copy, Debug, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
struct ImportDirectoryTableEntry {
    import_lookup_table_rva: u32,
    timestamp: u32,
    forwarder_chain: u32,
    name_rva: u32,
    import_address_table_rva: u32,
}

#[derive(Clone, Copy, Debug, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
struct ExportDirectoryTable {
    export_flags: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name_rva: u32,
    ordinal_base: u32,
    address_table_entries: u32,
    number_of_name_pointers: u32,
    export_address_table_rva: u32,
    name_pointer_rva: u32,
    ordinal_table_rva: u32,
}
const _: () = assert!(size_of::<ExportDirectoryTable>() == 40);

const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

pub fn execute(pe: &[u8], executable_path: &Path) {
    let image = load(pe, executable_path, false);

    let entrypoint =
        image.opt_header.image_base as usize + image.opt_header.address_of_entry_point as usize;
    eprintln!("YOLO to {:#x}", entrypoint);

    unsafe {
        let result = sys::call_entrypoint_via_stdcall(entrypoint);
        eprintln!("result: {result}");
    };
}

struct Image<'pe> {
    base: usize,
    opt_header: &'pe OptionalHeader,
    loaded: &'static mut [u8],
}

impl<'pe> Deref for Image<'pe> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.loaded
    }
}

fn load<'pe>(pe: &'pe [u8], executable_path: &Path, is_dll: bool) -> Image<'pe> {
    let (coff_header, after_header) = parse_header(pe);

    match (std::env::consts::ARCH, coff_header.machine) {
        ("x86_64", IMAGE_FILE_MACHINE_AMD64) => {}
        ("aarch64", IMAGE_FILE_MACHINE_ARM64) => {}
        (arch, machine) => {
            panic!("unsupported, cannot execute PE for machine {machine:x} on {arch}")
        }
    }

    if !coff_header
        .characteristics
        .contains(Characteristics::IMAGE_FILE_EXECUTABLE_IMAGE)
    {
        panic!("unsupported, cannot execute invalid executable")
    }

    if is_dll {
        if !coff_header
            .characteristics
            .contains(Characteristics::IMAGE_FILE_DLL)
        {
            panic!("unsupported, trying to dll-load an executable")
        }
    } else {
        if coff_header
            .characteristics
            .contains(Characteristics::IMAGE_FILE_DLL)
        {
            panic!("unsupported, cannot execute DLL")
        }
    }

    if (coff_header.size_of_optional_header as usize) < size_of::<OptionalHeader>() {
        panic!("file does not have enough of the required optional header (lol)");
    }

    dbg!(coff_header);

    let opt_header: &OptionalHeader =
        &bytemuck::cast_slice(&pe[after_header..][..size_of::<OptionalHeader>()])[0];
    dbg!(opt_header);

    if opt_header.magic != 0x20b {
        panic!("unsupported, only PE32+ is supported");
    }

    if !is_dll {
        if opt_header.subsystem != 3 {
            panic!("unsupported, only IMAGE_SUBSYSTEM_WINDOWS_CUI subsystem is supported");
        }
    }

    if opt_header.number_of_rva_and_sizes < 16 {
        panic!("unsupported, we want at least 16 data directories")
    }

    let section_table_offset = after_header + coff_header.size_of_optional_header as usize;
    let section_table: &[SectionHeader] = bytemuck::cast_slice(
        &pe[section_table_offset..]
            [..(coff_header.number_of_sections as usize * size_of::<SectionHeader>())],
    );
    dbg!(section_table);

    // let's always load it at the image base for now...
    let base = opt_header.image_base as usize;

    let allocation_granularity = crate::sys::allocation_granularity();

    assert_eq!(base & (allocation_granularity - 1), 0);

    let last_section = section_table.last().unwrap();
    let total_size = (last_section.virtual_address as usize + last_section.virtual_size as usize)
        .next_multiple_of(allocation_granularity);

    let loaded = unsafe {
        crate::sys::anon_write_map(total_size, std::ptr::with_exposed_provenance(base)).unwrap()
    };

    let image = Image {
        base,
        opt_header,
        loaded,
    };

    // allocate the sections.
    for section in section_table {
        if section.virtual_size > section.size_of_raw_data {
            todo!("zero padding")
        }
        eprintln!("mapping section {:?}", section.name);

        let section_a = &mut image.loaded[section.virtual_address as usize..];

        section_a[..section.size_of_raw_data as usize].copy_from_slice(
            &pe[section.pointer_to_raw_data as usize..][..section.size_of_raw_data as usize],
        );
    }

    let import_directory_table = bytemuck::cast_slice::<_, ImportDirectoryTableEntry>(
        &image.loaded[opt_header.import_table.va as usize..]
            [..opt_header.import_table.size as usize],
    )
    .to_vec();

    eprintln!("checking imports");
    for import_directory in import_directory_table {
        dbg!(import_directory);

        let dll_name =
            CStr::from_bytes_until_nul(&image.loaded[import_directory.name_rva as usize..])
                .unwrap()
                .to_owned();
        let dll_name = dll_name.to_str().unwrap();
        if dll_name.is_empty() {
            // Trailing null import directory.
            break;
        }
        eprintln!("loading dll {dll_name}");

        enum LoadedDll {
            Emulated,
            Real(Image<'static>),
        }

        let dll = find_dll(&dll_name, executable_path);
        let dll = match dll {
            Some(DllLocation::Emulated) => {
                eprintln!("  emulating {dll_name:?}");
                LoadedDll::Emulated
            }
            Some(DllLocation::Found(path)) => {
                let file = std::fs::File::open(&path).unwrap();
                // leak the mapping object to get a &'static
                let mmap =
                    std::mem::ManuallyDrop::new(unsafe { memmap2::Mmap::map(&file).unwrap() });
                let mmap = unsafe { &*(&**mmap as *const [u8]) };

                let image = load(&mmap, &path, true);
                LoadedDll::Real(image)
            }
            None => panic!("could not find dll {dll_name:?}"),
        };

        let import_lookups = bytemuck::cast_slice::<u8, u64>(
            &image.loaded[import_directory.import_address_table_rva as usize..],
        )
        .to_vec();
        for (i, import_lookup) in import_lookups.iter().enumerate() {
            let import_lookup = *import_lookup;
            if import_lookup == 0 {
                break;
            }
            let ordinal_name_flag = import_lookup >> 63;
            if ordinal_name_flag == 1 {
                let ordinal_number = import_lookup & 0xFFFF;
                eprintln!(" import by ordinal: {ordinal_number}");
                todo!("unsupported, import by ordinal");
            } else {
                let hint_name_table_rva = import_lookup & 0xFFFF_FFFF;
                let hint = bytemuck::cast_slice::<u8, u16>(
                    &image.loaded[hint_name_table_rva as usize..][..2],
                )[0];
                let func_name =
                    CStr::from_bytes_until_nul(&image.loaded[hint_name_table_rva as usize + 2..])
                        .unwrap();
                eprintln!(" import by name: hint={hint} name={func_name:?}");

                let resolved_va = match &dll {
                    LoadedDll::Emulated => emulated::emulate(dll_name, func_name.to_str().unwrap())
                        .unwrap_or_else(|| {
                            panic!("could not find function {func_name:?} in dll {dll_name:?}")
                        }),
                    LoadedDll::Real(img) => {
                        // Read the single export directory table from the front
                        // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table

                        // The export table consists of 3 tables.
                        // The Export Address Table is indexed by unbiased ordinals and contains the function pointers.
                        // If you have an ordinal, you need to subtract OrdinalBase to get the actual ordinal.
                        // If you do not have an ordinal but just have a name, you need to figure out the ordinal from the name.
                        // To do this, you binary search the asc sorted Name Pointer Table to find the index there.
                        // Then you look up the found index in the Ordinal Table (which has the same size) and grab the ordinal from there.
                        // Proceed with that ordinal to the Export Address Table as usual.
                        // You may be able to skip the binary search of the "hint" of the import is the correct index already.

                        let export_directory_table = bytemuck::cast_slice::<u8, ExportDirectoryTable>(
                            &img[img.opt_header.export_table.va as usize..]
                                [..size_of::<ExportDirectoryTable>()],
                        )[0];
                        dbg!(export_directory_table);

                        // This is not aligned..?
                        let mut names = vec![];
                        for name_ptr in (export_directory_table.name_pointer_rva as usize..)
                            .step_by(4)
                            .take(export_directory_table.number_of_name_pointers as usize)
                        {
                            let name = u32::from_ne_bytes(img[name_ptr..][..4].try_into().unwrap());
                            let name = CStr::from_bytes_until_nul(&img[name as usize..]).unwrap();
                            names.push(name);
                            dbg!(name);
                        }

                        let idx = if names.get(hint as usize) == Some(&func_name) {
                            hint as usize
                        } else {
                            names.binary_search(&func_name).unwrap_or_else(|_| {
                                panic!("could not find function {func_name:?} in dll {dll_name}")
                            })
                        };

                        // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-ordinal-table
                        let ordinal_table = bytemuck::cast_slice::<u8, u16>(
                            &img[export_directory_table.ordinal_table_rva as usize..]
                                [..2 * export_directory_table.number_of_name_pointers as usize],
                        );
                        let unbiased_ordinal = ordinal_table[idx];

                        let eat_addr_rva = export_directory_table.export_address_table_rva as usize
                            + (unbiased_ordinal as usize * 4);
                        let export_rva =
                            u32::from_ne_bytes(img[eat_addr_rva..][..4].try_into().unwrap());

                        if (img.opt_header.export_table.va
                            ..(img.opt_header.export_table.va + img.opt_header.export_table.size))
                            .contains(&export_rva)
                        {
                            todo!("symbol forwarding of {func_name:?} in {dll_name}")
                        }

                        img.base + export_rva as usize
                    }
                };

                assert_eq!(size_of::<usize>(), size_of::<u64>());
                image.loaded[import_directory.import_address_table_rva as usize..]
                    [i * size_of::<u64>()..][..size_of::<u64>()]
                    .copy_from_slice(&resolved_va.to_ne_bytes());
            }
        }
    }

    eprintln!("applying section protections");
    for section in section_table {
        let mode = if section
            .characteristics
            .contains(SectionFlags::IMAGE_SCN_MEM_EXECUTE)
        {
            crate::sys::Mode::Execute
        } else if section
            .characteristics
            .contains(SectionFlags::IMAGE_SCN_MEM_WRITE)
        {
            crate::sys::Mode::Write
        } else {
            crate::sys::Mode::Read
        };

        let section_a = &image.loaded[section.virtual_address as usize..];

        crate::sys::protect(
            section_a.as_ptr().cast(),
            section.virtual_size as usize,
            mode,
        )
        .unwrap();
    }

    image
}

fn parse_header(pe: &[u8]) -> (&CoffHeader, usize) {
    // After the MS-DOS stub, at the file offset specified at offset 0x3c,
    // is a 4-byte signature that identifies the file as a PE format image file.
    // This signature is "PE\0\0" (the letters "P" and "E" followed by two null bytes).
    let signature_pointer = u32::from_le_bytes(pe[0x3c..][..4].try_into().unwrap());
    let signature = &pe[(signature_pointer as usize)..][..4];
    assert_eq!(signature, b"PE\0\0");

    // At the beginning of an object file, or immediately after the signature of an image file,
    // is a standard COFF file header in the following format.
    // Note that the Windows loader limits the number of sections to 96.

    let header = &bytemuck::cast_slice(
        &pe[(signature_pointer as usize) + 4..][..std::mem::size_of::<CoffHeader>()],
    )[0];
    (
        header,
        (signature_pointer as usize) + 4 + std::mem::size_of::<CoffHeader>(),
    )
}

#[derive(Debug)]
enum DllLocation {
    Emulated,
    Found(PathBuf),
}

fn find_dll(name: &str, executable_path: &Path) -> Option<DllLocation> {
    // https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
    if name.starts_with("api-") && emulated::supports_dll(name) {
        // This is an API set, essentially a virtual alias
        // https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets
        return Some(DllLocation::Emulated);
    }
    if emulated::supports_dll(name) {
        return Some(DllLocation::Emulated);
    }

    let name_lowercase = name.to_lowercase();

    let probe_path = |path: &Path| -> Option<PathBuf> {
        std::fs::read_dir(path)
            .ok()?
            .find(|entry| {
                entry
                    .as_ref()
                    .map(|entry| {
                        entry
                            .file_name()
                            .to_str()
                            .is_some_and(|name| name.to_lowercase() == name_lowercase)
                    })
                    .unwrap_or(false)
            })
            .map(|entry| entry.unwrap().path())
    };

    if let Some(path) = probe_path(executable_path.parent().unwrap()) {
        return Some(DllLocation::Found(path));
    }

    None
}
