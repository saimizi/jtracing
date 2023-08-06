use std::fmt::Display;

#[allow(unused)]
use {
    error_stack::{IntoReport, Result, ResultExt},
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

pub fn cpp_demangle_sym(sym: &str) -> String {
    if let Ok(sym) = cpp_demangle::Symbol::new(sym.as_bytes()) {
        sym.to_string()
    } else {
        sym.to_string()
    }
}

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

pub struct KernelSymbolEntry {
    addr: u64,
    ktype: NmSymbolType,
    name: String,
    module: String,
    len: u64,
}

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

pub struct KernelMap {
    kallsyms: Vec<KernelSymbolEntry>,
}

impl KernelMap {
    pub fn new(symbol_file: Option<&str>) -> Result<Self, SymbolAnalyzerError> {
        let f = if let Some(sf) = symbol_file {
            fs::OpenOptions::new()
                .read(true)
                .open(sf)
                .into_report()
                .change_context(SymbolAnalyzerError::InvalidSymbolFile)
                .attach_printable(format!("Invalid symbol file: {}", sf))?
        } else {
            fs::OpenOptions::new()
                .read(true)
                .open("/proc/kallsyms")
                .into_report()
                .change_context(SymbolAnalyzerError::NoKallsymsFile)?
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
                .ok_or_else(|| SymbolAnalyzerError::InvalidSymbolFile)
                .into_report()
                .attach_printable(format!("No address found in line: `{}`", line))?
                .trim();
            let addr = addr_str_to_u64(addr_str)?;

            let t = entries
                .next()
                .ok_or_else(|| SymbolAnalyzerError::InvalidSymbolFile)
                .into_report()
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
                    return Err(SymbolAnalyzerError::InvalidSymbolFile)
                        .into_report()
                        .attach_printable(format!("Invalid type {}", t))
                }
            };

            let name = String::from(
                entries
                    .next()
                    .ok_or_else(|| SymbolAnalyzerError::InvalidSymbolFile)
                    .into_report()
                    .attach_printable(format!("No name found in line: `{}`", line))?
                    .trim(),
            );

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
        for i in 0..kallsyms.len() {
            let v = &mut kallsyms[i];
            if addr >= v.addr() {
                v.set_len(addr - v.addr())
            }

            addr = v.addr();
        }

        Ok(KernelMap { kallsyms })
    }

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
            Symbol::TooSmall => Err(SymbolAnalyzerError::SymbolNotFound)
                .into_report()
                .attach_printable(format!("Address {} is too small", addr)),
            Symbol::TooLarge => Err(SymbolAnalyzerError::SymbolNotFound)
                .into_report()
                .attach_printable(format!("Address {} is too large", addr)),
        }
    }

    pub fn symbol_vec(&self) -> Vec<&KernelSymbolEntry> {
        let mut result = vec![];

        self.kallsyms.iter().for_each(|entry| result.push(entry));
        result
    }
}

pub struct ExecMap {
    entries: Vec<SymbolEntry>,
    pid: u32,
    file_cache: HashMap<String, ElfFile>,
}

impl ExecMap {
    pub fn new(pid: u32) -> Result<Self, SymbolAnalyzerError> {
        let map = fs::OpenOptions::new()
            .read(true)
            .open(format!("/proc/{}/maps", pid))
            .into_report()
            .change_context(SymbolAnalyzerError::FailedReadMap)
            .attach_printable(format!("Failed to read /proc/{}/maps", pid))?;

        let mut reader = BufReader::new(map);
        let mut entries = Vec::new();
        // match something like
        // 7fadf15000-7fadf1c000 r-xp 00000000 b3:02 12147                          /usr/lib/libipcon.so.0.0.0
        let re = Regex::new(
            r"^([0-9|a-f]+)-([0-9|a-f]+) r\-xp ([0-9|a-f]+ [0-9|a-f|:]+ [0-9]+ +)(/[a-z|A-Z|0-9|\.|\-|_|/|:]+.*)\n$",
        ).into_report()
            .change_context(SymbolAnalyzerError::Unexpected)
            .attach_printable("Failed to build Regex")?;

        loop {
            let mut l = String::new();

            let len = reader
                .read_line(&mut l)
                .into_report()
                .change_context(SymbolAnalyzerError::Unexpected)
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

        return Err(SymbolAnalyzerError::InvalidAddress)
            .into_report()
            .attach_printable(format!(
                "Invalid addr {:x} for pid {}. Available range: {}",
                addr, self.pid, keys
            ));
    }
}

pub struct SymbolAnalyzer {
    kmap: KernelMap,
    map: HashMap<u32, ExecMap>,
}

pub fn addr_str_to_u64(addr_str: &str) -> Result<u64, SymbolAnalyzerError> {
    let mut u8array: [u8; 8] = [0; 8];
    let mut fixed_str = String::from(addr_str.trim());

    if fixed_str.len() % 2 != 0 {
        fixed_str = format!("0{}", fixed_str);
    }

    let bytes = hex::decode(&fixed_str)
        .into_report()
        .change_context(SymbolAnalyzerError::InvalidAddress)
        .attach_printable(format!("Invalid address {}", fixed_str))?;

    if bytes.len() > 8 {
        return Err(SymbolAnalyzerError::InvalidAddress)
            .into_report()
            .attach_printable(format!(
                "Invalid address {} bytes len: {}",
                addr_str,
                bytes.len()
            ));
    }

    u8array[8 - bytes.len()..].clone_from_slice(&bytes[..]);

    Ok(u64::from_be_bytes(u8array))
}

impl SymbolAnalyzer {
    pub fn new(symbol_file: Option<&str>) -> Result<Self, SymbolAnalyzerError> {
        Ok(SymbolAnalyzer {
            kmap: KernelMap::new(symbol_file)?,
            map: HashMap::new(),
        })
    }

    pub fn ksymbol_str(&self, addr_str: &str) -> Result<String, SymbolAnalyzerError> {
        let addr = addr_str_to_u64(addr_str)?;
        self.ksymbol(addr)
    }

    pub fn ksymbol(&self, addr: u64) -> Result<String, SymbolAnalyzerError> {
        self.kmap.symbol(addr)
    }

    /// Return (addr, symbol name, file name).
    pub fn usymbol(
        &mut self,
        pid: u32,
        addr: u64,
    ) -> Result<(u64, String, String), SymbolAnalyzerError> {
        let em = self.map.entry(pid).or_insert(ExecMap::new(pid)?);
        em.symbol(addr)
    }
}

pub struct SymbolEntry {
    name: String,
    start: u64,
    size: u64,
}

impl SymbolEntry {
    pub fn have(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.start + self.size
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn end(&self) -> u64 {
        self.start + self.size
    }
}

pub struct ElfFile {
    name: String,
    sym_addr: HashMap<String, SymbolEntry>,
}

impl ElfFile {
    pub fn new(file_name: &str) -> Result<Self, SymbolAnalyzerError> {
        let mut fpathbuf = Path::new(file_name)
            .canonicalize()
            .into_report()
            .change_context(SymbolAnalyzerError::InvalidElfFile)
            .attach_printable(format!("Invalid ELF file: {}", file_name))?;

        if fpathbuf.is_symlink() {
            fpathbuf = fs::read_link(fpathbuf)
                .into_report()
                .change_context(SymbolAnalyzerError::InvalidElfFile)
                .attach_printable(format!("Invalid ELF file: {}", file_name))?
                .canonicalize()
                .into_report()
                .change_context(SymbolAnalyzerError::InvalidElfFile)
                .attach_printable(format!("Invalid ELF file: {}", file_name))?;
        }

        let fpath = fpathbuf.as_path();
        if !fpath.is_file() {
            return Err(SymbolAnalyzerError::InvalidElfFile)
                .into_report()
                .attach_printable(format!("Invalid ELF binary : {}", file_name));
        }

        let file = fs::File::open(fpath)
            .into_report()
            .change_context(SymbolAnalyzerError::InvalidElfFile)
            .attach_printable(format!("Failed to open {}", file_name))?;

        let mut files = vec![file];
        let mut sym_addr = HashMap::new();

        while let Some(file) = files.pop() {
            let mut new_files = Vec::<std::fs::File>::new();

            let map = unsafe {
                memmap::Mmap::map(&file)
                    .into_report()
                    .change_context(SymbolAnalyzerError::Unexpected)
                    .attach_printable(format!("Failed to map {}", file_name))?
            };

            let object = object::File::parse(&map[..])
                .into_report()
                .change_context(SymbolAnalyzerError::Unexpected)
                .attach_printable(format!("Failed to parse {}", file_name))?;

            if let Ok(Some((lfn, _crc))) = object.gnu_debuglink() {
                if let Ok(lf) = String::from_utf8(lfn.to_vec()) {
                    let plf = Path::new(&lf);
                    if plf.is_file() {
                        new_files.push(
                            fs::File::open(lf.clone())
                                .into_report()
                                .change_context(SymbolAnalyzerError::Unexpected)
                                .attach_printable(format!("Failed to open {}", lf))?,
                        );
                    } else if let Some(d) = fpath.to_path_buf().parent() {
                        let mut debug_file = d.to_path_buf();
                        debug_file.push(".debug");
                        debug_file.push(&lf);
                        if debug_file.is_file() {
                            new_files.push(
                                fs::File::open(debug_file.clone())
                                    .into_report()
                                    .change_context(SymbolAnalyzerError::Unexpected)
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

    pub fn find_symbol(&self, addr: u64) -> Result<String, SymbolAnalyzerError> {
        for entry in self.sym_addr.values() {
            if entry.have(addr) {
                return Ok(entry.name().to_string());
            }
        }

        Err(SymbolAnalyzerError::SymbolNotFound)
            .into_report()
            .attach_printable(format!("Address 0x{:x} Not Found.", addr))
    }

    pub fn find_addr(&self, sym: &str) -> Result<u64, SymbolAnalyzerError> {
        let entry = self
            .sym_addr
            .get(sym)
            .ok_or_else(|| SymbolAnalyzerError::SymbolNotFound)
            .into_report()
            .attach_printable(format!("Symbol {} Not Found.", sym))?;
        Ok(entry.start())
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

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
    }

    #[test]
    fn kernel_map01() {
        use crate::symbolanalyzer::KernelMap;
        let km = KernelMap::new(Some("testfiles/test_symbol")).unwrap();

        assert_eq!(km.symbol_vec().len(), 205982);
    }
}
