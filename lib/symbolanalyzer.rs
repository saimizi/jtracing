//! Symbol analysis and address resolution for kernel and userspace programs.
//!
//! This module provides comprehensive symbol analysis capabilities for both kernel and
//! userspace programs. It can resolve addresses to symbol names and vice versa using:
//!
//! - Kernel symbols from `/proc/kallsyms` or custom symbol files
//! - ELF binaries with symbol tables and debug information
//! - Process memory maps from `/proc/<pid>/maps`
//!
//! # Key Types
//!
//! - [`SymbolAnalyzer`]: Main interface for symbol resolution
//! - [`KernelMap`]: Kernel symbol table management
//! - [`ExecMap`]: Process memory mapping and userspace symbol resolution
//! - [`ElfFile`]: ELF binary symbol extraction and analysis
//!
//! # Supported File Formats
//!
//! - ELF binaries (executables, shared libraries)
//! - Symbol files in `/proc/kallsyms` format
//! - Debug symbols via `.debug` directories or `gnu_debuglink`
//!
//! # Limitations
//!
//! - Only supports ELF format binaries
//! - Requires read access to `/proc` filesystem
//! - Limited to x86_64 address format (8-byte addresses)
//! - No support for compressed debug information

use std::fmt::Display;

#[allow(unused)]
use {
    error_stack::{Report, Result, ResultExt},
    jlogger_tracing::{jdebug, jerror, jinfo, jwarn},
    std::error::Error,
};

use {
    object::{Object, ObjectSymbol},
    regex::Regex,
    std::{
        collections::HashMap,
        fs,
        io::{BufRead, BufReader},
        path::Path,
    },
};

/// Errors that can occur during symbol analysis operations.
#[derive(Debug)]
pub enum SymbolAnalyzerError {
    InvalidAddress,
    InvalidSymbolFile,
    InvalidElfFile,
    NoKallsymsFile,
    SymbolNotFound,
    FailedReadMap,
    Unexpected,
}

impl Display for SymbolAnalyzerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error_str = match self {
            SymbolAnalyzerError::InvalidAddress => "Invalid address",
            SymbolAnalyzerError::SymbolNotFound => "Symbol not found",
            SymbolAnalyzerError::InvalidSymbolFile => "Invalid symbol file",
            SymbolAnalyzerError::InvalidElfFile => "Invalid elf file",
            SymbolAnalyzerError::NoKallsymsFile => "No /proc/kallsyms found",
            SymbolAnalyzerError::FailedReadMap => "Failed to read /proc/<PID>/maps",
            SymbolAnalyzerError::Unexpected => "Unexpected error",
        };

        write!(f, "{}", error_str)
    }
}

impl Error for SymbolAnalyzerError {}

/// Demangles C++ symbol names using the `cpp_demangle` crate.
///
/// # Arguments
///
/// * `sym` - The mangled C++ symbol name
///
/// # Returns
///
/// The demangled symbol name, or the original string if demangling fails.
pub fn cpp_demangle_sym(sym: &str) -> String {
    if let Ok(sym) = cpp_demangle::Symbol::new(sym.as_bytes()) {
        sym.to_string()
    } else {
        sym.to_string()
    }
}

/// Symbol types as defined in the `nm` utility and `/proc/kallsyms` format.
///
/// These correspond to the single-character type codes used in symbol tables.
#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum NmSymbolType {
    Absolute,
    BssData,
    CommonSymbol,
    InitializedData,
    InitializedSmallData,
    IndirectFunction,
    IndirectRef,
    DebugSymbol,
    ReadOnlyN,
    StackUnwind,
    ReadOnlyR,
    UnInitializedData,
    Text,
    Undefined,
    UniqueGlobalSymbol,
    WeakObjectV,
    WeakObjectW,
    StabsSymbol,
    Unknown,
}

/// Represents a single kernel symbol entry from `/proc/kallsyms` or symbol files.
///
/// Each entry contains the symbol's address, type, name, module, and calculated size.
pub struct KernelSymbolEntry {
    addr: u64,
    ktype: NmSymbolType,
    name: String,
    module: String,
    len: u64,
}

/// Result of a symbol lookup operation.
///
/// Indicates whether an address falls within a symbol's range and provides
/// the symbol name with optional offset if found.
pub enum Symbol {
    Symbol(String),
    TooSmall,
    TooLarge,
}

impl KernelSymbolEntry {
    pub fn set_len(&mut self, len: u64) {
        self.len = len;
    }

    pub fn addr(&self) -> u64 {
        self.addr
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn size(&self) -> u64 {
        self.len
    }

    pub fn ktype(&self) -> NmSymbolType {
        self.ktype
    }

    pub fn module(&self) -> &str {
        self.module.as_str()
    }

    pub fn symbol(&self, addr: u64) -> Symbol {
        if addr < self.addr {
            Symbol::TooSmall
        } else if addr >= self.addr + self.len {
            Symbol::TooLarge
        } else if addr == self.addr {
            Symbol::Symbol(self.name.clone())
        } else {
            Symbol::Symbol(format!("{}+0x{:x}", self.name, addr - self.addr))
        }
    }
}

/// Manages kernel symbol table loaded from `/proc/kallsyms` or custom symbol files.
///
/// Provides efficient symbol lookup by maintaining symbols in sorted order and
/// calculating symbol sizes based on address gaps.
pub struct KernelMap {
    kallsyms: Vec<KernelSymbolEntry>,
}

impl KernelMap {
    /// Creates a new kernel symbol map from `/proc/kallsyms` or a custom symbol file.
    ///
    /// # Arguments
    ///
    /// * `symbol_file` - Optional path to custom symbol file. If `None`, uses `/proc/kallsyms`.
    ///
    /// # Returns
    ///
    /// A new [`KernelMap`] with symbols loaded and sorted by address.
    ///
    /// # Errors
    ///
    /// - [`SymbolAnalyzerError::InvalidSymbolFile`] if the file cannot be read
    /// - [`SymbolAnalyzerError::NoKallsymsFile`] if `/proc/kallsyms` is not accessible
    pub fn new(symbol_file: Option<&str>) -> Result<Self, SymbolAnalyzerError> {
        let f = if let Some(sf) = symbol_file {
            fs::OpenOptions::new()
                .read(true)
                .open(sf)
                .map_err(|_| Report::new(SymbolAnalyzerError::InvalidSymbolFile))
                .attach_printable(format!("Invalid symbol file: {}", sf))?
        } else {
            fs::OpenOptions::new()
                .read(true)
                .open("/proc/kallsyms")
                .map_err(|_| Report::new(SymbolAnalyzerError::NoKallsymsFile))?
        };

        let mut reader = BufReader::new(f);
        let mut kallsyms: Vec<KernelSymbolEntry> = Vec::new();

        loop {
            let mut line = String::new();

            match reader.read_line(&mut line) {
                Ok(a) if a != 0 => (),
                _ => break,
            }

            let mut entries = line.split(' ');

            let addr_str = entries
                .next()
                .ok_or(Report::new(SymbolAnalyzerError::InvalidSymbolFile))
                .attach_printable(format!("No address found in line: `{}`", line))?
                .trim();

            let addr = addr_str_to_u64(addr_str)?;

            let t = entries
                .next()
                .ok_or(Report::new(SymbolAnalyzerError::InvalidSymbolFile))
                .attach_printable(format!("No symbol type found in line: `{}`", line))?
                .trim();

            let ktype = match t {
                "A" | "a" => NmSymbolType::Absolute,
                "B" | "b" => NmSymbolType::BssData,
                "C" => NmSymbolType::CommonSymbol,
                "D" | "d" => NmSymbolType::InitializedData,
                "G" | "g" => NmSymbolType::InitializedSmallData,
                "i" => NmSymbolType::IndirectFunction,
                "I" => NmSymbolType::IndirectRef,
                "N" => NmSymbolType::DebugSymbol,
                "n" => NmSymbolType::ReadOnlyN,
                "p" => NmSymbolType::StackUnwind,
                "R" | "r" => NmSymbolType::ReadOnlyR,
                "S" | "s" => NmSymbolType::UnInitializedData,
                "T" | "t" => NmSymbolType::Text,
                "U" => NmSymbolType::Undefined,
                "u" => NmSymbolType::UniqueGlobalSymbol,
                "V" | "v" => NmSymbolType::WeakObjectV,
                "W" | "w" => NmSymbolType::WeakObjectW,
                "-" => NmSymbolType::StabsSymbol,
                "?" => NmSymbolType::Unknown,
                _ => {
                    return Err(Report::new(SymbolAnalyzerError::InvalidSymbolFile))
                        .attach_printable(format!("Invalid type {}", t))
                }
            };

            let name = String::from(
                entries
                    .next()
                    .ok_or(Report::new(SymbolAnalyzerError::InvalidSymbolFile))
                    .attach_printable(format!("No name found in line: `{}`", line))?
                    .trim(),
            );

            // In case of loadable module name may be something like following
            //   virtio_lo_add_pdev\t[virtio_lo]
            let name = name
                .split('\t')
                .collect::<Vec<&str>>()
                .first()
                .ok_or(Report::new(SymbolAnalyzerError::InvalidSymbolFile))?
                .to_string();

            jdebug!(name = name);

            let mut module = String::new();
            if let Some(m) = entries.next() {
                module.push_str(m);
            }

            kallsyms.push(KernelSymbolEntry {
                addr,
                ktype,
                name,
                module,
                len: u64::max_value(),
            });
        }

        /* Descending order */
        kallsyms.sort_by(|a, b| b.addr().partial_cmp(&a.addr()).unwrap());

        let mut addr = u64::max_value();

        for v in kallsyms.iter_mut() {
            if addr >= v.addr() {
                v.set_len(addr - v.addr())
            }

            addr = v.addr();
        }

        Ok(KernelMap { kallsyms })
    }

    /// Resolves a kernel address to its symbol name.
    ///
    /// # Arguments
    ///
    /// * `addr` - The kernel address to resolve
    ///
    /// # Returns
    ///
    /// Symbol name with optional offset (e.g., "function_name+0x10")
    ///
    /// # Errors
    ///
    /// Returns [`SymbolAnalyzerError::SymbolNotFound`] if no symbol contains the address.
    pub fn symbol(&self, addr: u64) -> Result<String, SymbolAnalyzerError> {
        let search_symbol =
            |v: &Vec<KernelSymbolEntry>, start: usize, end: usize, addr: u64| -> Symbol {
                let mut start = start;
                let mut end = end;
                loop {
                    if start == end {
                        return v[start].symbol(addr);
                    }

                    let i = (end - start) / 2 + start;
                    match v[i].symbol(addr) {
                        Symbol::Symbol(s) => return Symbol::Symbol(s),
                        Symbol::TooSmall => start = i,
                        Symbol::TooLarge => end = i,
                    }
                }
            };

        match search_symbol(&self.kallsyms, 0, self.kallsyms.len(), addr) {
            Symbol::Symbol(s) => Ok(s),
            Symbol::TooSmall => Err(Report::new(SymbolAnalyzerError::SymbolNotFound))
                .attach_printable(format!("Address {} is too small", addr)),
            Symbol::TooLarge => Err(Report::new(SymbolAnalyzerError::SymbolNotFound))
                .attach_printable(format!("Address {} is too large", addr)),
        }
    }

    /// Returns a vector of all kernel symbol entries.
    ///
    /// # Returns
    ///
    /// A vector containing references to all loaded kernel symbols.
    pub fn symbol_vec(&self) -> Vec<&KernelSymbolEntry> {
        let mut result = vec![];

        self.kallsyms.iter().for_each(|entry| result.push(entry));
        result
    }
}

/// Manages memory mappings and symbol resolution for a specific process.
///
/// Parses `/proc/<pid>/maps` to understand process memory layout and provides
/// symbol resolution for userspace addresses using cached ELF files.
pub struct ExecMap {
    entries: Vec<SymbolEntry>,
    pid: u32,
    file_cache: HashMap<String, ElfFile>,
}

impl ExecMap {
    /// Creates a new process memory map by parsing `/proc/<pid>/maps`.
    ///
    /// # Arguments
    ///
    /// * `pid` - Process ID to analyze
    ///
    /// # Returns
    ///
    /// A new [`ExecMap`] with memory mappings loaded.
    ///
    /// # Errors
    ///
    /// Returns [`SymbolAnalyzerError::FailedReadMap`] if `/proc/<pid>/maps` cannot be read.
    pub fn new(pid: u32) -> Result<Self, SymbolAnalyzerError> {
        let map = fs::OpenOptions::new()
            .read(true)
            .open(format!("/proc/{}/maps", pid))
            .map_err(|_| Report::new(SymbolAnalyzerError::FailedReadMap))
            .attach_printable(format!("Failed to read /proc/{}/maps", pid))?;

        let mut reader = BufReader::new(map);
        let mut entries = Vec::new();
        // match something like
        // 7fadf15000-7fadf1c000 r-xp 00000000 b3:02 12147                          /usr/lib/libipcon.so.0.0.0
        let re = Regex::new(
            r"^([0-9|a-f]+)-([0-9|a-f]+) r\-xp ([0-9|a-f]+ [0-9|a-f|:]+ [0-9]+ +)(/[a-z|A-Z|0-9|\.|\-|_|/|:]+.*)\n$",
        )
            .map_err(|_| Report::new(SymbolAnalyzerError::Unexpected))
            .attach_printable("Failed to build Regex")?;

        loop {
            let mut l = String::new();

            let len = reader
                .read_line(&mut l)
                .map_err(|_| Report::new(SymbolAnalyzerError::Unexpected))
                .attach_printable(format!("Failed to read /proc/{}/maps", pid))?;

            if len == 0 {
                break;
            }

            for g in re.captures_iter(&l) {
                let start = addr_str_to_u64(&g[1])?;
                let end = addr_str_to_u64(&g[2])?;
                let file = &g[4].trim_end_matches('\n').trim().to_string();

                entries.push(SymbolEntry {
                    start,
                    size: end - start,
                    name: file.trim_end_matches('\n').trim().to_string(),
                });
            }
        }

        Ok(ExecMap {
            entries,
            pid,
            file_cache: HashMap::new(),
        })
    }

    /// Resolves a userspace address to its symbol information.
    ///
    /// # Arguments
    ///
    /// * `addr` - The userspace address to resolve
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - Offset within the binary
    /// - Symbol name (or "[unknown]" if not found)
    /// - Binary file path
    ///
    /// # Errors
    ///
    /// Returns [`SymbolAnalyzerError::InvalidAddress`] if the address is not in any mapped region.
    pub fn symbol(&mut self, addr: u64) -> Result<(u64, String, String), SymbolAnalyzerError> {
        let mut keys = String::new();

        for entry in &self.entries {
            keys.push_str(&format!(" {:x}:{:x}", entry.start(), entry.end()));
            if entry.have(addr) {
                let offset = addr - entry.start;
                let elf = self
                    .file_cache
                    .entry(entry.name().to_string())
                    .or_insert(ElfFile::new(entry.name())?);

                if let Ok(sym) = elf.find_symbol(offset) {
                    return Ok((offset, sym, entry.name().to_string()));
                }

                return Ok((offset, String::from("[unknown]"), entry.name.to_string()));
            }
        }

        Err(Report::new(SymbolAnalyzerError::InvalidAddress)).attach_printable(format!(
            "Invalid addr {:x} for pid {}. Available range: {}",
            addr, self.pid, keys
        ))
    }
}

/// Main interface for symbol analysis combining kernel and userspace symbol resolution.
///
/// Provides unified access to both kernel symbols (via [`KernelMap`]) and process-specific
/// userspace symbols (via [`ExecMap`] instances cached per PID).
pub struct SymbolAnalyzer {
    kmap: KernelMap,
    map: HashMap<u32, ExecMap>,
}

/// Converts a hexadecimal address string to a 64-bit unsigned integer.
///
/// # Arguments
///
/// * `addr_str` - Hexadecimal address string (with or without "0x" prefix)
///
/// # Returns
///
/// The parsed address as `u64`.
///
/// # Errors
///
/// Returns [`SymbolAnalyzerError::InvalidAddress`] if:
/// - The string contains invalid hexadecimal characters
/// - The address is longer than 16 characters (64 bits)
/// - The string is empty
pub fn addr_str_to_u64(addr_str: &str) -> Result<u64, SymbolAnalyzerError> {
    let mut u8array: [u8; 8] = [0; 8];
    let trimmed_str = addr_str.trim();

    // Input validation
    if trimmed_str.is_empty() {
        return Err(Report::new(SymbolAnalyzerError::InvalidAddress))
            .attach_printable("Address string cannot be empty");
    }

    // Check for unreasonably long strings (max 16 hex chars + potential 0x prefix)
    if trimmed_str.len() > 18 {
        return Err(Report::new(SymbolAnalyzerError::InvalidAddress)).attach_printable(format!(
            "Address string too long: {} characters",
            trimmed_str.len()
        ));
    }

    // Remove 0x prefix if present
    let mut fixed_str = if trimmed_str.starts_with("0x") || trimmed_str.starts_with("0X") {
        trimmed_str[2..].to_string()
    } else {
        trimmed_str.to_string()
    };

    // Validate hex characters
    if !fixed_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Report::new(SymbolAnalyzerError::InvalidAddress)).attach_printable(format!(
            "Invalid hexadecimal characters in address: {}",
            addr_str
        ));
    }

    if fixed_str.len() % 2 != 0 {
        fixed_str = format!("0{}", fixed_str);
    }

    let bytes = hex::decode(&fixed_str)
        .map_err(|_| Report::new(SymbolAnalyzerError::InvalidAddress))
        .attach_printable(format!("Invalid address {}", fixed_str))?;

    if bytes.len() > 8 {
        return Err(Report::new(SymbolAnalyzerError::InvalidAddress)).attach_printable(format!(
            "Invalid address {} bytes len: {}",
            addr_str,
            bytes.len()
        ));
    }

    u8array[8 - bytes.len()..].clone_from_slice(&bytes[..]);

    Ok(u64::from_be_bytes(u8array))
}

impl SymbolAnalyzer {
    /// Creates a new symbol analyzer with kernel symbol support.
    ///
    /// # Arguments
    ///
    /// * `symbol_file` - Optional path to custom kernel symbol file
    ///
    /// # Returns
    ///
    /// A new [`SymbolAnalyzer`] instance.
    ///
    /// # Errors
    ///
    /// Returns error if kernel symbols cannot be loaded.
    pub fn new(symbol_file: Option<&str>) -> Result<Self, SymbolAnalyzerError> {
        Ok(SymbolAnalyzer {
            kmap: KernelMap::new(symbol_file)?,
            map: HashMap::new(),
        })
    }

    /// Resolves a kernel address string to its symbol name.
    ///
    /// # Arguments
    ///
    /// * `addr_str` - Hexadecimal address string
    ///
    /// # Returns
    ///
    /// Symbol name with optional offset.
    ///
    /// # Errors
    ///
    /// Returns error if address string is invalid or symbol is not found.
    pub fn ksymbol_str(&self, addr_str: &str) -> Result<String, SymbolAnalyzerError> {
        let addr = addr_str_to_u64(addr_str)?;
        self.ksymbol(addr)
    }

    /// Resolves a kernel address to its symbol name.
    ///
    /// # Arguments
    ///
    /// * `addr` - Kernel address to resolve
    ///
    /// # Returns
    ///
    /// Symbol name with optional offset.
    pub fn ksymbol(&self, addr: u64) -> Result<String, SymbolAnalyzerError> {
        self.kmap.symbol(addr)
    }

    /// Resolves a userspace address to its symbol information.
    ///
    /// # Arguments
    ///
    /// * `pid` - Process ID
    /// * `addr` - Userspace address to resolve
    ///
    /// # Returns
    ///
    /// A tuple containing (offset, symbol name, file name).
    ///
    /// # Errors
    ///
    /// Returns error if process maps cannot be read or address is invalid.
    pub fn usymbol(
        &mut self,
        pid: u32,
        addr: u64,
    ) -> Result<(u64, String, String), SymbolAnalyzerError> {
        let em = self.map.entry(pid).or_insert(ExecMap::new(pid)?);
        em.symbol(addr)
    }
}

/// Represents a symbol entry with its name, start address, and size.
///
/// Used for both kernel and userspace symbols to provide unified symbol information.
pub struct SymbolEntry {
    name: String,
    start: u64,
    size: u64,
}

impl SymbolEntry {
    /// Checks if the given address falls within this symbol's range.
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to check
    ///
    /// # Returns
    ///
    /// `true` if the address is within [start, start + size)
    pub fn have(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.start + self.size
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the start address of this symbol.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// Returns the size of this symbol.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the end address of this symbol (start + size).
    pub fn end(&self) -> u64 {
        self.start + self.size
    }
}

/// Represents an ELF binary file with its symbol table and debug information.
///
/// Handles ELF parsing, symbol extraction, and debug symbol loading via
/// `.debug` directories or `gnu_debuglink` sections.
pub struct ElfFile {
    name: String,
    sym_addr: HashMap<String, SymbolEntry>,
}

impl ElfFile {
    /// Creates a new ELF file analyzer.
    ///
    /// # Arguments
    ///
    /// * `file_name` - Path to the ELF binary file
    ///
    /// # Returns
    ///
    /// A new [`ElfFile`] with symbols loaded from the binary and any debug files.
    ///
    /// # Errors
    ///
    /// Returns [`SymbolAnalyzerError::InvalidElfFile`] if the file cannot be read or parsed.
    pub fn new(file_name: &str) -> Result<Self, SymbolAnalyzerError> {
        let mut fpathbuf = Path::new(file_name)
            .canonicalize()
            .map_err(|_| Report::new(SymbolAnalyzerError::InvalidElfFile))
            .attach_printable(format!("Invalid file path: {}", file_name))?;

        if fpathbuf.is_symlink() {
            fpathbuf = fs::read_link(fpathbuf)
                .map_err(|_| Report::new(SymbolAnalyzerError::InvalidElfFile))
                .attach_printable(format!("Invalid symbolic file: {}", file_name))?
                .canonicalize()
                .map_err(|_| Report::new(SymbolAnalyzerError::InvalidElfFile))
                .attach_printable(format!("Invalid symbolic file path: {}", file_name))?;
        }

        let fpath = fpathbuf.as_path();
        if !fpath.is_file() {
            return Err(Report::new(SymbolAnalyzerError::InvalidElfFile))
                .attach_printable(format!("Invalid ELF binary : {}", file_name));
        }

        let file = fs::File::open(fpath)
            .map_err(|_| Report::new(SymbolAnalyzerError::InvalidElfFile))
            .attach_printable(format!("Failed to open {}", file_name))?;

        let mut files = vec![file];
        let mut sym_addr = HashMap::new();

        while let Some(file) = files.pop() {
            let mut new_files = Vec::<std::fs::File>::new();

            let map = unsafe {
                memmap::Mmap::map(&file)
                    .map_err(|_| Report::new(SymbolAnalyzerError::Unexpected))
                    .attach_printable(format!("Failed to map {}", file_name))?
            };

            let object = object::File::parse(&map[..])
                .map_err(|_| Report::new(SymbolAnalyzerError::Unexpected))
                .attach_printable(format!("Failed to parse {}", file_name))?;

            if let Ok(Some((lfn, _crc))) = object.gnu_debuglink() {
                if let Ok(lf) = String::from_utf8(lfn.to_vec()) {
                    let plf = Path::new(&lf);
                    if plf.is_file() {
                        new_files.push(
                            fs::File::open(lf.clone())
                                .map_err(|_| Report::new(SymbolAnalyzerError::Unexpected))
                                .attach_printable(format!("Failed to open {}", lf))?,
                        );
                    } else if let Some(d) = fpath.to_path_buf().parent() {
                        let mut debug_file = d.to_path_buf();
                        debug_file.push(".debug");
                        debug_file.push(&lf);
                        if debug_file.is_file() {
                            new_files.push(
                                fs::File::open(debug_file.clone())
                                    .map_err(|_| Report::new(SymbolAnalyzerError::Unexpected))
                                    .attach_printable(format!(
                                        "Failed to open {}",
                                        debug_file.to_string_lossy()
                                    ))?,
                            );
                        }
                    }
                }
            }

            let symbols = object.symbols();
            let dynamic_symbols = object.dynamic_symbols();

            for sym in symbols {
                if let Ok(name) = sym.name() {
                    let name = cpp_demangle_sym(name);
                    let entry = SymbolEntry {
                        name,
                        start: sym.address(),
                        size: sym.size(),
                    };

                    sym_addr.insert(entry.name().to_string(), entry);
                }
            }

            for sym in dynamic_symbols {
                if let Ok(name) = sym.name() {
                    let name = cpp_demangle_sym(name);
                    let entry = SymbolEntry {
                        name,
                        start: sym.address(),
                        size: sym.size(),
                    };

                    sym_addr.insert(entry.name().to_string(), entry);
                }
            }

            if !new_files.is_empty() {
                files = new_files;
            }
        }
        Ok(ElfFile {
            name: String::from(fpath.to_str().unwrap()),
            sym_addr,
        })
    }

    /// Finds the symbol containing the given address.
    ///
    /// # Arguments
    ///
    /// * `addr` - Address within the ELF file
    ///
    /// # Returns
    ///
    /// The symbol name containing the address.
    ///
    /// # Errors
    ///
    /// Returns [`SymbolAnalyzerError::SymbolNotFound`] if no symbol contains the address.
    pub fn find_symbol(&self, addr: u64) -> Result<String, SymbolAnalyzerError> {
        for entry in self.sym_addr.values() {
            if entry.have(addr) {
                return Ok(entry.name().to_string());
            }
        }

        Err(Report::new(SymbolAnalyzerError::SymbolNotFound))
            .attach_printable(format!("Address 0x{:x} Not Found.", addr))
    }

    /// Finds the address of a symbol by name.
    ///
    /// # Arguments
    ///
    /// * `sym` - Symbol name to find
    ///
    /// # Returns
    ///
    /// The start address of the symbol.
    ///
    /// # Errors
    ///
    /// Returns [`SymbolAnalyzerError::SymbolNotFound`] if the symbol is not found.
    pub fn find_addr(&self, sym: &str) -> Result<u64, SymbolAnalyzerError> {
        let entry = self
            .sym_addr
            .get(sym)
            .ok_or(Report::new(SymbolAnalyzerError::SymbolNotFound))
            .attach_printable(format!("Symbol {} Not Found.", sym))?;
        Ok(entry.start())
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns a vector of all symbols in this ELF file.
    ///
    /// # Returns
    ///
    /// A vector containing references to all symbols found in the ELF file.
    pub fn symbol_vec(&self) -> Vec<&SymbolEntry> {
        let mut result = vec![];

        self.sym_addr.iter().for_each(|entry| result.push(entry.1));
        result
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn symbolanalyzer01() {
        use crate::symbolanalyzer::SymbolAnalyzer;
        let sa = SymbolAnalyzer::new(Some("testfiles/test_symbol")).unwrap();

        let sym = sa.ksymbol_str("ffffffffb731c4f0").unwrap();
        assert_eq!(sym, "do_sys_open");
    }

    #[test]
    fn addr_str_to_u64_test() {
        use crate::symbolanalyzer::addr_str_to_u64;
        assert_eq!(addr_str_to_u64("0").unwrap(), 0_u64);
        assert_eq!(addr_str_to_u64("f").unwrap(), 15_u64);
        assert_eq!(addr_str_to_u64("7f8d66a000").unwrap(), 547833159680_u64);
        assert_eq!(
            addr_str_to_u64("000000558e510590").unwrap(),
            367459894672_u64
        );
        assert_eq!(addr_str_to_u64("ffffffffffffffff").unwrap(), u64::MAX);

        // Test 0x prefix support
        assert_eq!(addr_str_to_u64("0x0").unwrap(), 0_u64);
        assert_eq!(addr_str_to_u64("0xf").unwrap(), 15_u64);
        assert_eq!(addr_str_to_u64("0X7f8d66a000").unwrap(), 547833159680_u64);

        // Test whitespace handling
        assert_eq!(addr_str_to_u64("  f  ").unwrap(), 15_u64);
        assert_eq!(
            addr_str_to_u64("\t0x7f8d66a000\n").unwrap(),
            547833159680_u64
        );
    }

    #[test]
    fn addr_str_to_u64_error_cases() {
        use crate::symbolanalyzer::addr_str_to_u64;

        // Empty string
        assert!(addr_str_to_u64("").is_err());
        assert!(addr_str_to_u64("   ").is_err());

        // Too long string
        assert!(addr_str_to_u64("0x12345678901234567890").is_err());

        // Invalid hex characters
        assert!(addr_str_to_u64("xyz").is_err());
        assert!(addr_str_to_u64("123g").is_err());
        assert!(addr_str_to_u64("0xghij").is_err());

        // Address too large for u64
        assert!(addr_str_to_u64("123456789012345678901").is_err());
    }

    #[test]
    fn kernel_symbol_entry_test() {
        use crate::symbolanalyzer::{KernelSymbolEntry, NmSymbolType, Symbol};

        let entry = KernelSymbolEntry {
            addr: 0x1000,
            ktype: NmSymbolType::Text,
            name: "test_function".to_string(),
            module: "".to_string(),
            len: 0x100,
        };

        // Test exact address match
        match entry.symbol(0x1000) {
            Symbol::Symbol(s) => assert_eq!(s, "test_function"),
            _ => panic!("Expected Symbol"),
        }

        // Test offset address
        match entry.symbol(0x1010) {
            Symbol::Symbol(s) => assert_eq!(s, "test_function+0x10"),
            _ => panic!("Expected Symbol with offset"),
        }

        // Test address too small
        match entry.symbol(0x900) {
            Symbol::TooSmall => (),
            _ => panic!("Expected TooSmall"),
        }

        // Test address too large
        match entry.symbol(0x1200) {
            Symbol::TooLarge => (),
            _ => panic!("Expected TooLarge"),
        }
    }

    #[test]
    fn symbol_entry_test() {
        use crate::symbolanalyzer::SymbolEntry;

        let entry = SymbolEntry {
            name: "test_symbol".to_string(),
            start: 0x2000,
            size: 0x200,
        };

        // Test address within range
        assert!(entry.have(0x2000));
        assert!(entry.have(0x2100));
        assert!(entry.have(0x21ff));

        // Test address outside range
        assert!(!entry.have(0x1fff));
        assert!(!entry.have(0x2200));

        // Test accessors
        assert_eq!(entry.start(), 0x2000);
        assert_eq!(entry.size(), 0x200);
        assert_eq!(entry.end(), 0x2200);
        assert_eq!(entry.name(), "test_symbol");
    }

    #[test]
    fn kernel_map01() {
        use crate::symbolanalyzer::KernelMap;
        let km = KernelMap::new(Some("testfiles/test_symbol")).unwrap();

        assert_eq!(km.symbol_vec().len(), 205982);
    }
}
