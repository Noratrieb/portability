mod sys;

use std::{
    ffi::CStr,
    fmt::Debug,
    fs::File,
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
    virtual_address: u32,
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

const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

pub fn execute(pe: &[u8]) {
    let (header, after_header) = parse_header(pe);

    match (std::env::consts::ARCH, header.machine) {
        ("x86_64", IMAGE_FILE_MACHINE_AMD64) => {}
        ("aarch64", IMAGE_FILE_MACHINE_ARM64) => {}
        (arch, machine) => {
            panic!("unsupported, cannot execute PE for machine {machine:x} on {arch}")
        }
    }

    if !header
        .characteristics
        .contains(Characteristics::IMAGE_FILE_EXECUTABLE_IMAGE)
    {
        panic!("unsupported, cannot execute invalid executable")
    }

    if header
        .characteristics
        .contains(Characteristics::IMAGE_FILE_DLL)
    {
        panic!("unsupported, cannot execute DLL")
    }

    if (header.size_of_optional_header as usize) < size_of::<OptionalHeader>() {
        panic!("file does not have enough of the required optional header (lol)");
    }

    dbg!(header);

    let optional_header: &OptionalHeader =
        &bytemuck::cast_slice(&pe[after_header..][..size_of::<OptionalHeader>()])[0];
    dbg!(optional_header);

    if optional_header.magic != 0x20b {
        panic!("unsupported, only PE32+ is supported");
    }

    if optional_header.subsystem != 3 {
        panic!("unsupported, only IMAGE_SUBSYSTEM_WINDOWS_CUI subsystem is supported");
    }

    if optional_header.number_of_rva_and_sizes < 16 {
        panic!("unsupported, we want at least 16 data directories")
    }

    let section_table_offset = after_header + header.size_of_optional_header as usize;
    let section_table: &[SectionHeader] = bytemuck::cast_slice(
        &pe[section_table_offset..]
            [..(header.number_of_sections as usize * size_of::<SectionHeader>())],
    );
    dbg!(section_table);

    // let's always load it at the image base for now...
    let base = optional_header.image_base as usize;

    let allocation_granularity = crate::sys::allocation_granularity();

    assert_eq!(base & (allocation_granularity - 1), 0);

    let total_size = section_table.last().unwrap().virtual_address as usize;

    let a = unsafe {
        crate::sys::anon_write_map(
            total_size.next_multiple_of(allocation_granularity),
            std::ptr::with_exposed_provenance(base),
        )
        .unwrap()
    };

    // allocate the sections.
    for section in section_table {
        if section.virtual_size > section.size_of_raw_data {
            todo!("zero padding")
        }

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

        let section_a = &mut a[section.virtual_address as usize..];

        dbg!(section);

        section_a[..section.size_of_raw_data as usize].copy_from_slice(
            &pe[section.pointer_to_raw_data as usize..][..section.size_of_raw_data as usize],
        );

        //crate::sys::protect(
        //    section_a.as_ptr().cast(),
        //    section.virtual_size as usize,
        //    mode,
        //)
        //.unwrap();
    }

    let import_directory_table: &[ImportDirectoryTableEntry] = bytemuck::cast_slice(
        &a[optional_header.import_table.virtual_address as usize..]
            [..optional_header.import_table.size as usize],
    );

    for import_directory in import_directory_table {
        dbg!(import_directory);

        let name = CStr::from_bytes_until_nul(&a[import_directory.name_rva as usize..]).unwrap();
        if name.is_empty() {
            // Trailing null import directory.
            break;
        }
        dbg!(name);

        let dll = find_dll(name);
        match dll {
            Some(path) => eprintln!("  found {name:?} at {path:?}"),
            None => eprintln!("  COULD NOT FIND {name:?}"),
        }

        let import_lookups = bytemuck::cast_slice::<u8, u64>(
            &a[import_directory.import_lookup_table_rva as usize..],
        );
        for import_lookup in import_lookups {
            if *import_lookup == 0 {
                break;
            }
            let ordinal_name_flag = import_lookup >> 63;
            if ordinal_name_flag == 1 {
                let ordinal_number = import_lookup & 0xFFFF;
                eprintln!(" import by ordinal: {ordinal_number}");
            } else {
                let hint_name_table_rva = import_lookup & 0xFFFF_FFFF;
                let hint =
                    bytemuck::cast_slice::<u8, u16>(&a[hint_name_table_rva as usize..][..2])[0];
                let name =
                    CStr::from_bytes_until_nul(&a[hint_name_table_rva as usize + 2..]).unwrap();
                eprintln!(" import by name: hint={hint} name={name:?}");
            }
        }
    }

    eprintln!("YOLO");

    unsafe {
        let entrypoint = std::mem::transmute::<usize, unsafe fn() -> !>(
            optional_header.address_of_entry_point as usize,
        );
        entrypoint();
    };
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

fn find_dll(name: &CStr) -> Option<PathBuf> {
    // https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
    let name = name.to_str().unwrap();
    if name.starts_with("api-") {
        // This is an API set, essentially a virtual alias
        // https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets
        return None;
    }

    let system = sys::system_directory().unwrap();
    eprintln!(" searching {system:?} for {name}");
    let from_system = std::fs::read_dir(system).unwrap().find(|child| {
        child
            .as_ref()
            .unwrap()
            .file_name()
            .to_str()
            .unwrap()
            .eq_ignore_ascii_case(name)
    });
    if let Some(from_system) = from_system {
        return Some(from_system.unwrap().path());
    }

    None
}
