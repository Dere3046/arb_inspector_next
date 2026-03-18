use std::env;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;

#[allow(dead_code)]
const PF_X: u32 = 0x1;
#[allow(dead_code)]
const PF_W: u32 = 0x2;
#[allow(dead_code)]
const PF_R: u32 = 0x4;

const ELF32_HDR_SIZE: usize = 52;
const ELF64_HDR_SIZE: usize = 64;
const ELF32_PHDR_SIZE: usize = 32;
const ELF64_PHDR_SIZE: usize = 56;

const HASH_TABLE_HEADER_SIZE: usize = 40;
const OS_TYPE_HASH: u32 = 2;

const VERSION_MIN: u32 = 1;
const VERSION_MAX: u32 = 1000;
const COMMON_SIZE_MAX: usize = 0x1000;
const QTI_SIZE_MAX: usize = 0x1000;
const OEM_SIZE_MAX: usize = 0x4000;
const HASH_TABLE_SIZE_MAX: usize = 0x10000;
const ARB_VALUE_MAX: u32 = 127;

#[allow(dead_code)]
const MAX_SEGMENT_BYTES: u64 = 20 * 1024 * 1024;

const MBN_HDR_SIZE: usize = 40;
const MBN_V7_HDR_SIZE: usize = 64;
const MBN_V8_HDR_SIZE: usize = 80;

#[inline]
fn read_le_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off+2].try_into().unwrap())
}

#[inline]
fn read_le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off+4].try_into().unwrap())
}

#[inline]
fn read_le_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off+8].try_into().unwrap())
}

#[allow(dead_code)]
trait ElfHeaderTrait {
    fn e_type(&self) -> u16;
    fn e_machine(&self) -> u16;
    fn e_version(&self) -> u32;
    fn e_entry(&self) -> u64;
    fn e_phoff(&self) -> u64;
    fn e_shoff(&self) -> u64;
    fn e_flags(&self) -> u32;
    fn e_ehsize(&self) -> u16;
    fn e_phentsize(&self) -> u16;
    fn e_phnum(&self) -> u16;
    fn e_shentsize(&self) -> u16;
    fn e_shnum(&self) -> u16;
    fn e_shstrndx(&self) -> u16;
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Elf32Header {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u32,
    e_phoff: u32,
    e_shoff: u32,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

impl Elf32Header {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < ELF32_HDR_SIZE {
            return Err("Insufficient data for ELF32 header");
        }
        let mut e_ident = [0u8; 16];
        e_ident.copy_from_slice(&data[0..16]);
        Ok(Self {
            e_ident,
            e_type: read_le_u16(data, 16),
            e_machine: read_le_u16(data, 18),
            e_version: read_le_u32(data, 20),
            e_entry: read_le_u32(data, 24),
            e_phoff: read_le_u32(data, 28),
            e_shoff: read_le_u32(data, 32),
            e_flags: read_le_u32(data, 36),
            e_ehsize: read_le_u16(data, 40),
            e_phentsize: read_le_u16(data, 42),
            e_phnum: read_le_u16(data, 44),
            e_shentsize: read_le_u16(data, 46),
            e_shnum: read_le_u16(data, 48),
            e_shstrndx: read_le_u16(data, 50),
        })
    }
}

impl ElfHeaderTrait for Elf32Header {
    fn e_type(&self) -> u16 { self.e_type }
    fn e_machine(&self) -> u16 { self.e_machine }
    fn e_version(&self) -> u32 { self.e_version }
    fn e_entry(&self) -> u64 { self.e_entry as u64 }
    fn e_phoff(&self) -> u64 { self.e_phoff as u64 }
    fn e_shoff(&self) -> u64 { self.e_shoff as u64 }
    fn e_flags(&self) -> u32 { self.e_flags }
    fn e_ehsize(&self) -> u16 { self.e_ehsize }
    fn e_phentsize(&self) -> u16 { self.e_phentsize }
    fn e_phnum(&self) -> u16 { self.e_phnum }
    fn e_shentsize(&self) -> u16 { self.e_shentsize }
    fn e_shnum(&self) -> u16 { self.e_shnum }
    fn e_shstrndx(&self) -> u16 { self.e_shstrndx }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Elf64Header {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

impl Elf64Header {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < ELF64_HDR_SIZE {
            return Err("Insufficient data for ELF64 header");
        }
        let mut e_ident = [0u8; 16];
        e_ident.copy_from_slice(&data[0..16]);
        Ok(Self {
            e_ident,
            e_type: read_le_u16(data, 16),
            e_machine: read_le_u16(data, 18),
            e_version: read_le_u32(data, 20),
            e_entry: read_le_u64(data, 24),
            e_phoff: read_le_u64(data, 32),
            e_shoff: read_le_u64(data, 40),
            e_flags: read_le_u32(data, 48),
            e_ehsize: read_le_u16(data, 52),
            e_phentsize: read_le_u16(data, 54),
            e_phnum: read_le_u16(data, 56),
            e_shentsize: read_le_u16(data, 58),
            e_shnum: read_le_u16(data, 60),
            e_shstrndx: read_le_u16(data, 62),
        })
    }
}

impl ElfHeaderTrait for Elf64Header {
    fn e_type(&self) -> u16 { self.e_type }
    fn e_machine(&self) -> u16 { self.e_machine }
    fn e_version(&self) -> u32 { self.e_version }
    fn e_entry(&self) -> u64 { self.e_entry }
    fn e_phoff(&self) -> u64 { self.e_phoff }
    fn e_shoff(&self) -> u64 { self.e_shoff }
    fn e_flags(&self) -> u32 { self.e_flags }
    fn e_ehsize(&self) -> u16 { self.e_ehsize }
    fn e_phentsize(&self) -> u16 { self.e_phentsize }
    fn e_phnum(&self) -> u16 { self.e_phnum }
    fn e_shentsize(&self) -> u16 { self.e_shentsize }
    fn e_shnum(&self) -> u16 { self.e_shnum }
    fn e_shstrndx(&self) -> u16 { self.e_shstrndx }
}

#[allow(dead_code)]
trait ProgramHeaderTrait {
    fn p_type(&self) -> u32;
    fn p_flags(&self) -> u32;
    fn p_offset(&self) -> u64;
    fn p_vaddr(&self) -> u64;
    fn p_paddr(&self) -> u64;
    fn p_filesz(&self) -> u64;
    fn p_memsz(&self) -> u64;
    fn p_align(&self) -> u64;
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Elf32ProgramHeader {
    p_type: u32,
    p_offset: u32,
    p_vaddr: u32,
    p_paddr: u32,
    p_filesz: u32,
    p_memsz: u32,
    p_flags: u32,
    p_align: u32,
}

impl Elf32ProgramHeader {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < ELF32_PHDR_SIZE {
            return Err("Insufficient data for ELF32 program header");
        }
        Ok(Self {
            p_type: read_le_u32(data, 0),
            p_offset: read_le_u32(data, 4),
            p_vaddr: read_le_u32(data, 8),
            p_paddr: read_le_u32(data, 12),
            p_filesz: read_le_u32(data, 16),
            p_memsz: read_le_u32(data, 20),
            p_flags: read_le_u32(data, 24),
            p_align: read_le_u32(data, 28),
        })
    }
}

impl ProgramHeaderTrait for Elf32ProgramHeader {
    fn p_type(&self) -> u32 { self.p_type }
    fn p_flags(&self) -> u32 { self.p_flags }
    fn p_offset(&self) -> u64 { self.p_offset as u64 }
    fn p_vaddr(&self) -> u64 { self.p_vaddr as u64 }
    fn p_paddr(&self) -> u64 { self.p_paddr as u64 }
    fn p_filesz(&self) -> u64 { self.p_filesz as u64 }
    fn p_memsz(&self) -> u64 { self.p_memsz as u64 }
    fn p_align(&self) -> u64 { self.p_align as u64 }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Elf64ProgramHeader {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

impl Elf64ProgramHeader {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < ELF64_PHDR_SIZE {
            return Err("Insufficient data for ELF64 program header");
        }
        Ok(Self {
            p_type: read_le_u32(data, 0),
            p_flags: read_le_u32(data, 4),
            p_offset: read_le_u64(data, 8),
            p_vaddr: read_le_u64(data, 16),
            p_paddr: read_le_u64(data, 24),
            p_filesz: read_le_u64(data, 32),
            p_memsz: read_le_u64(data, 40),
            p_align: read_le_u64(data, 48),
        })
    }
}

impl ProgramHeaderTrait for Elf64ProgramHeader {
    fn p_type(&self) -> u32 { self.p_type }
    fn p_flags(&self) -> u32 { self.p_flags }
    fn p_offset(&self) -> u64 { self.p_offset }
    fn p_vaddr(&self) -> u64 { self.p_vaddr }
    fn p_paddr(&self) -> u64 { self.p_paddr }
    fn p_filesz(&self) -> u64 { self.p_filesz }
    fn p_memsz(&self) -> u64 { self.p_memsz }
    fn p_align(&self) -> u64 { self.p_align }
}

enum ElfFormat {
    Elf32(Elf32Header, Vec<Elf32ProgramHeader>),
    Elf64(Elf64Header, Vec<Elf64ProgramHeader>),
}

struct Elf {
    format: ElfFormat,
    #[allow(dead_code)]
    segments: Vec<Vec<u8>>,
}

impl Elf {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 16 || &data[0..4] != ELF_MAGIC {
            return Err("Invalid ELF magic");
        }
        match data[EI_CLASS] {
            ELFCLASS32 => {
                let header = Elf32Header::from_bytes(data)?;
                let phoff = header.e_phoff as usize;
                let phnum = header.e_phnum as usize;
                let phentsize = header.e_phentsize as usize;

                let mut phdrs = Vec::with_capacity(phnum);
                for i in 0..phnum {
                    let offset = phoff + i * phentsize;
                    if offset + phentsize <= data.len() {
                        phdrs.push(Elf32ProgramHeader::from_bytes(&data[offset..offset + phentsize])?);
                    }
                }

                let mut segments = Vec::new();
                for phdr in &phdrs {
                    if phdr.p_type == PT_LOAD && phdr.p_filesz > 0 {
                        let start = phdr.p_offset as usize;
                        let end = start + phdr.p_filesz as usize;
                        if end <= data.len() {
                            segments.push(data[start..end].to_vec());
                        }
                    }
                }

                Ok(Self {
                    format: ElfFormat::Elf32(header, phdrs),
                    segments,
                })
            }
            ELFCLASS64 => {
                let header = Elf64Header::from_bytes(data)?;
                let phoff = header.e_phoff as usize;
                let phnum = header.e_phnum as usize;
                let phentsize = header.e_phentsize as usize;

                let mut phdrs = Vec::with_capacity(phnum);
                for i in 0..phnum {
                    let offset = phoff + i * phentsize;
                    if offset + phentsize <= data.len() {
                        phdrs.push(Elf64ProgramHeader::from_bytes(&data[offset..offset + phentsize])?);
                    }
                }

                let mut segments = Vec::new();
                for phdr in &phdrs {
                    if phdr.p_type == PT_LOAD && phdr.p_filesz > 0 {
                        let start = phdr.p_offset as usize;
                        let end = start + phdr.p_filesz as usize;
                        if end <= data.len() {
                            segments.push(data[start..end].to_vec());
                        }
                    }
                }

                Ok(Self {
                    format: ElfFormat::Elf64(header, phdrs),
                    segments,
                })
            }
            _ => Err("Unsupported ELF class"),
        }
    }

    fn phdrs(&self) -> Vec<&dyn ProgramHeaderTrait> {
        match &self.format {
            ElfFormat::Elf32(_, phdrs) => phdrs.iter().map(|p| p as &dyn ProgramHeaderTrait).collect(),
            ElfFormat::Elf64(_, phdrs) => phdrs.iter().map(|p| p as &dyn ProgramHeaderTrait).collect(),
        }
    }

    fn elf_header(&self) -> Option<&dyn ElfHeaderTrait> {
        match &self.format {
            ElfFormat::Elf32(h, _) => Some(h),
            ElfFormat::Elf64(h, _) => Some(h),
        }
    }

    fn elf_class(&self) -> u8 {
        match &self.format {
            ElfFormat::Elf32(_, _) => ELFCLASS32,
            ElfFormat::Elf64(_, _) => ELFCLASS64,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct HashTableSegmentHeader {
    reserved: u32,
    version: u32,
    common_metadata_size: u32,
    qti_metadata_size: u32,
    oem_metadata_size: u32,
    hash_table_size: u32,
    qti_sig_size: u32,
    qti_cert_chain_size: u32,
    oem_sig_size: u32,
    oem_cert_chain_size: u32,
}

impl HashTableSegmentHeader {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < HASH_TABLE_HEADER_SIZE {
            return Err("Insufficient data for hash table header");
        }
        Ok(Self {
            reserved: read_le_u32(data, 0),
            version: read_le_u32(data, 4),
            common_metadata_size: read_le_u32(data, 8),
            qti_metadata_size: read_le_u32(data, 12),
            oem_metadata_size: read_le_u32(data, 16),
            hash_table_size: read_le_u32(data, 20),
            qti_sig_size: read_le_u32(data, 24),
            qti_cert_chain_size: read_le_u32(data, 28),
            oem_sig_size: read_le_u32(data, 32),
            oem_cert_chain_size: read_le_u32(data, 36),
        })
    }

    fn get_arb_version(&self, oem_metadata: &[u8]) -> Option<u32> {
        if oem_metadata.len() >= 12 {
            Some(read_le_u32(oem_metadata, 8))
        } else {
            None
        }
    }

    fn is_plausible(&self) -> bool {
        let common_sz = self.common_metadata_size as usize;
        let qti_sz = self.qti_metadata_size as usize;
        let oem_sz = self.oem_metadata_size as usize;
        let hash_sz = self.hash_table_size as usize;

        (VERSION_MIN..=VERSION_MAX).contains(&self.version) &&
        common_sz <= COMMON_SIZE_MAX &&
        qti_sz <= QTI_SIZE_MAX &&
        oem_sz <= OEM_SIZE_MAX &&
        hash_sz > 0 && hash_sz <= HASH_TABLE_SIZE_MAX
    }
}

struct ElfWithHashTableSegment {
    elf: Elf,
    hash_table_header: Option<HashTableSegmentHeader>,
    #[allow(dead_code)]
    common_metadata: Vec<u8>,
    oem_metadata: Vec<u8>,
    #[allow(dead_code)]
    hash_table: Vec<u8>,
}

impl ElfWithHashTableSegment {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let elf = Elf::from_bytes(data)?;

        let mut hash_table_header = None;
        let mut common_metadata = Vec::new();
        let mut oem_metadata = Vec::new();
        let mut hash_table = Vec::new();

        if let Some(header) = elf.elf_header() {
            let phoff = header.e_phoff();
            let phnum = header.e_phnum();
            let phentsize = header.e_phentsize();

            for i in 0..phnum {
                let phdr_offset = (phoff + (i as u64) * (phentsize as u64)) as usize;
                if phdr_offset + (phentsize as usize) > data.len() {
                    continue;
                }

                let (p_flags_off, p_offset_off, p_filesz_off) = match elf.elf_class() {
                    ELFCLASS32 => (24, 4, 16),
                    ELFCLASS64 => (4, 8, 32),
                    _ => unreachable!(),
                };

                if phdr_offset + p_flags_off + 4 > data.len() {
                    continue;
                }
                let p_flags = read_le_u32(data, phdr_offset + p_flags_off);
                let os_type = (p_flags >> 24) & 0x7;

                if os_type == OS_TYPE_HASH {
                    if phdr_offset + p_offset_off + 8 > data.len() {
                        continue;
                    }
                    let p_offset = match elf.elf_class() {
                        ELFCLASS32 => read_le_u32(data, phdr_offset + p_offset_off) as usize,
                        ELFCLASS64 => read_le_u64(data, phdr_offset + p_offset_off) as usize,
                        _ => unreachable!(),
                    };
                    let p_filesz = match elf.elf_class() {
                        ELFCLASS32 => read_le_u32(data, phdr_offset + p_filesz_off) as usize,
                        ELFCLASS64 => read_le_u64(data, phdr_offset + p_filesz_off) as usize,
                        _ => unreachable!(),
                    };

                    if p_offset + p_filesz <= data.len() && p_filesz >= HASH_TABLE_HEADER_SIZE {
                        if let Ok(ht) = HashTableSegmentHeader::from_bytes(&data[p_offset..p_offset + HASH_TABLE_HEADER_SIZE]) {
                            if ht.is_plausible() {
                                hash_table_header = Some(ht.clone());

                                let mut offset = p_offset + HASH_TABLE_HEADER_SIZE;

                                if offset + ht.common_metadata_size as usize <= data.len() {
                                    common_metadata = data[offset..offset + ht.common_metadata_size as usize].to_vec();
                                    offset += ht.common_metadata_size as usize;
                                }
                                if offset + ht.oem_metadata_size as usize <= data.len() {
                                    oem_metadata = data[offset..offset + ht.oem_metadata_size as usize].to_vec();
                                    offset += ht.oem_metadata_size as usize;
                                }
                                if offset + ht.hash_table_size as usize <= data.len() {
                                    hash_table = data[offset..offset + ht.hash_table_size as usize].to_vec();
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            elf,
            hash_table_header,
            common_metadata,
            oem_metadata,
            hash_table,
        })
    }

    fn get_arb_version(&self) -> Option<u32> {
        if let Some(ref header) = self.hash_table_header {
            header.get_arb_version(&self.oem_metadata)
        } else {
            None
        }
    }
}

#[allow(dead_code)]
struct MbnHeader {
    image_id: u32,
    version: u32,
    image_src: u32,
    image_dest_ptr: u32,
    image_size: u32,
    code_size: u32,
    sig_ptr: u32,
    sig_size: u32,
    cert_chain_ptr: u32,
    cert_chain_size: u32,
}

impl MbnHeader {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < MBN_HDR_SIZE {
            return Err("Insufficient data for MBN header");
        }
        Ok(Self {
            image_id: read_le_u32(data, 0),
            version: read_le_u32(data, 4),
            image_src: read_le_u32(data, 8),
            image_dest_ptr: read_le_u32(data, 12),
            image_size: read_le_u32(data, 16),
            code_size: read_le_u32(data, 20),
            sig_ptr: read_le_u32(data, 24),
            sig_size: read_le_u32(data, 28),
            cert_chain_ptr: read_le_u32(data, 32),
            cert_chain_size: read_le_u32(data, 36),
        })
    }

    fn header_size(&self) -> usize {
        match self.version {
            7 => MBN_V7_HDR_SIZE,
            8 => MBN_V8_HDR_SIZE,
            _ => MBN_HDR_SIZE,
        }
    }
}

struct Mbn {
    header: MbnHeader,
    #[allow(dead_code)]
    code: Vec<u8>,
}

impl Mbn {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("Insufficient data for MBN");
        }
        let header = MbnHeader::from_bytes(data)?;
        let header_size = header.header_size();
        if data.len() < header_size {
            return Err("Insufficient data for MBN with padding");
        }
        let code = data[header_size..].to_vec();
        Ok(Self { header, code })
    }
}

enum FileType {
    Elf,
    Mbn,
    Unknown,
}

fn detect_file_type(data: &[u8]) -> FileType {
    if data.starts_with(ELF_MAGIC) {
        FileType::Elf
    } else if data.len() >= 8 {
        let version = read_le_u32(data, 4);
        if [3, 5, 6, 7, 8].contains(&version) {
            FileType::Mbn
        } else {
            FileType::Unknown
        }
    } else {
        FileType::Unknown
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut debug = false;
    let mut quick_mode = false;
    let mut full_mode = false;
    let mut path = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--debug" | "-d" => {
                debug = true;
                i += 1;
            }
            "--quick" | "-q" => {
                quick_mode = true;
                i += 1;
            }
            "--full" | "-f" => {
                full_mode = true;
                i += 1;
            }
            _ => {
                if path.is_none() {
                    path = Some(args[i].clone());
                    i += 1;
                } else {
                    eprintln!("Usage: {} [--debug] [--quick|--full] <image>", args[0]);
                    std::process::exit(1);
                }
            }
        }
    }

    if !quick_mode && !full_mode {
        quick_mode = true;
    }

    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("Usage: {} [--debug] [--quick|--full] <image>", args[0]);
            std::process::exit(1);
        }
    };

    let mut file = File::open(&path)?;
    let mut header_buf = [0u8; 64];
    file.read_exact(&mut header_buf)?;

    match detect_file_type(&header_buf) {
        FileType::Elf => {
            if debug {
                eprintln!("[DEBUG] Detected ELF file");
            }

            if header_buf[EI_DATA] != ELFDATA2LSB {
                return Err("Not a little-endian ELF file".into());
            }

            let elf_class = header_buf[EI_CLASS];
            if elf_class != ELFCLASS32 && elf_class != ELFCLASS64 {
                return Err("Unsupported ELF class".into());
            }

            if debug {
                eprintln!("[DEBUG] ELF class: {}", if elf_class == ELFCLASS32 { "32-bit" } else { "64-bit" });
            }

            file.seek(SeekFrom::Start(0))?;
            let mut full_data = Vec::new();
            file.read_to_end(&mut full_data)?;

            let elf_with_hash = ElfWithHashTableSegment::from_bytes(&full_data)?;
            let arb = elf_with_hash.get_arb_version();

            if quick_mode {
                if let Some(arb_val) = arb {
                    if arb_val <= ARB_VALUE_MAX {
                        println!("{}", arb_val);
                    } else {
                        eprintln!("Warning: ARB value {} exceeds expected maximum.", arb_val);
                        println!("{}", arb_val);
                    }
                } else {
                    eprintln!("No ARB version found in the image");
                    std::process::exit(1);
                }
            } else if full_mode {
                println!("File: {}", path);
                println!("Format: ELF ({})", if elf_class == ELFCLASS32 { "32-bit" } else { "64-bit" });
                if let Some(hdr) = elf_with_hash.elf.elf_header() {
                    println!("Entry point: 0x{:x}", hdr.e_entry());
                    println!("Program headers: {}", hdr.e_phnum());
                }

                let phdrs = elf_with_hash.elf.phdrs();
                for (i, phdr) in phdrs.iter().enumerate() {
                    println!("  [{}] Type: {} Offset: 0x{:x} VAddr: 0x{:x} FileSize: 0x{:x}",
                        i,
                        match phdr.p_type() {
                            PT_LOAD => "LOAD",
                            PT_NULL => "NULL",
                            PT_NOTE => "NOTE",
                            _ => "OTHER",
                        },
                        phdr.p_offset(),
                        phdr.p_vaddr(),
                        phdr.p_filesz());
                }

                if let Some(ref ht) = elf_with_hash.hash_table_header {
                    println!("Hash Table Segment Header:");
                    println!("  Version: {}", ht.version);
                    println!("  Common Metadata Size: {}", ht.common_metadata_size);
                    println!("  OEM Metadata Size: {}", ht.oem_metadata_size);
                    println!("  Hash Table Size: {}", ht.hash_table_size);
                }

                if let Some(arb_val) = arb {
                    if arb_val <= ARB_VALUE_MAX {
                        println!("Anti-Rollback Version: {}", arb_val);
                    } else {
                        eprintln!("Warning: ARB value {} exceeds expected maximum.", arb_val);
                        println!("Anti-Rollback Version: {}", arb_val);
                    }
                } else {
                    println!("Anti-Rollback Version: not present");
                }
            }

            if debug && full_mode {
                if let Some(ht) = &elf_with_hash.hash_table_header {
                    eprintln!("[DEBUG] Hash table version: {}", ht.version);
                    eprintln!("[DEBUG] OEM metadata size: {}", ht.oem_metadata_size);
                }
            }
        }

        FileType::Mbn => {
            if debug {
                eprintln!("[DEBUG] Detected MBN file");
            }
            file.seek(SeekFrom::Start(0))?;
            let mut full_data = Vec::new();
            file.read_to_end(&mut full_data)?;

            let mbn = Mbn::from_bytes(&full_data)?;

            if quick_mode {
                println!("MBN format does not contain ARB field");
            } else if full_mode {
                println!("File: {}", path);
                println!("Format: MBN v{}", mbn.header.version);
                println!("Image ID: 0x{:x}", mbn.header.image_id);
                println!("Code size: {} bytes", mbn.header.code_size);
                println!("Image size: {} bytes", mbn.header.image_size);
                println!("Signature ptr: 0x{:x}, size: {}", mbn.header.sig_ptr, mbn.header.sig_size);
                println!("Certificate chain ptr: 0x{:x}, size: {}", mbn.header.cert_chain_ptr, mbn.header.cert_chain_size);
                println!("ARB: not applicable");
            }

            if debug && full_mode {
                eprintln!("[DEBUG] MBN version: {}", mbn.header.version);
                eprintln!("[DEBUG] Code size: {}", mbn.header.code_size);
            }
        }

        FileType::Unknown => {
            return Err("Unknown file format (not ELF or MBN)".into());
        }
    }

    Ok(())
}