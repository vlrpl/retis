//! Process
//!
//! Module providing process inspection and searching capabilities.

#![allow(dead_code)] // FIXME

use std::{
    ffi::CStr,
    fmt, fs,
    io::{BufRead, BufReader, Cursor},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Result};
#[cfg(target_endian = "big")]
use byteorder::BigEndian as Endian;
#[cfg(target_endian = "little")]
use byteorder::LittleEndian as Endian;
use byteorder::ReadBytesExt;
use elf::{endian::AnyEndian, note::Note, ElfBytes};
use log::warn;

/// Integer to represent all pids.
const PID_ALL: i32 = -1;
/// The standard ELF Note type for systemtap information.
const STAPSDT_TYPE: u64 = 3;

/// Specific types of errors that Process can generate.
#[derive(thiserror::Error, Debug, PartialEq)]
pub(crate) enum ProcessError {
    /// Emitted when the process was not found.
    #[error("Process not found")]
    NotFound,
    /// Emitted when there were too many processes matching input parameters.
    #[error("Too many processes found")]
    TooMany,
}

// The UsdtNote contains values whose size depend on the address size.
#[cfg(target_pointer_width = "32")]
type Address = u32;
#[cfg(target_pointer_width = "64")]
type Address = u64;

#[derive(Debug, Default)]
/// UsdtInfo holds the USDT information of a binary.
pub struct UsdtInfo {
    /// Base address for USDT address calculation (from stapsdt).
    base_addr: u64,
    /// List of USDT Notes containing information of each USDT probe.
    notes: Vec<UsdtNote>,
}

impl UsdtInfo {
    fn new(path: &PathBuf) -> Result<Self> {
        let mut notes = Vec::new();
        // Load ELF header.
        let file_data = std::fs::read(path)?;
        let slice_data = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice_data)?;

        // Retrieve STAPSDT base section address.
        let base_hdr = file.section_header_by_name(".stapsdt.base")?;
        if base_hdr.is_none() {
            // It's OK to not have a USDT header. Return an empty object to
            // differenciate it from a parsing error which should be fatal.
            return Ok(UsdtInfo::default());
        }
        let base_addr = base_hdr.unwrap().sh_addr;

        // Retrieve STAPSDT notes section.
        let notes_hdr = file.section_header_by_name(".note.stapsdt")?;
        if let Some(notes_hdr) = notes_hdr {
            let data: Vec<Note> = file.section_data_as_notes(&notes_hdr)?.collect();

            for note in data.iter() {
                let note = match note {
                    Note::Unknown(note) => note,
                    _ => bail!("Unexpected note variant found"),
                };
                if note.n_type != STAPSDT_TYPE || note.name.ne("stapsdt") {
                    bail!(
                        "Unexpected note type and name: {}/{}",
                        note.n_type,
                        note.name
                    );
                }
                notes.push(UsdtNote::from_elf(note.desc)?);
            }
        };

        Ok(UsdtInfo { base_addr, notes })
    }

    /// Determines whether a target specified as "provider::name" is a valid USDT.
    pub(crate) fn is_usdt(&self, target: &str) -> Result<bool> {
        Ok(self.get_note(target)?.is_some())
    }

    /// Returns the USDT note associated with a target. Targets are specified as "provider::name".
    pub(crate) fn get_note(&self, target: &str) -> Result<Option<&UsdtNote>> {
        let (provider, name) = target.split_once("::").ok_or_else(|| {
            anyhow!(
                "Target ({}) is not a valid USDT target. Format should be provider::name",
                target
            )
        })?;

        Ok(self
            .notes
            .iter()
            .find(|note| note.provider == provider && note.name == name))
    }

    /// Retrieves the Usdt note information whose address matches the given offset.
    pub(crate) fn get_note_from_offset(&self, addr: u64) -> Result<Option<&UsdtNote>> {
        Ok(self.notes.iter().find(|note| {
            // We need to compensate "prelink effect". For more information see:
            // https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
            let link_addr = note.addr + self.base_addr - note.base_addr;
            link_addr == addr
        }))
    }
}

/// UsdtNote is the object strored in the note.stapsdt ELF section.
#[derive(Debug)]
pub struct UsdtNote {
    /// The provider name.
    pub provider: String,
    /// The probe's name.
    pub name: String,
    /// The probe's address.
    pub addr: Address,
    /// The address of the link-time base section.
    pub base_addr: Address,
    /// The semafore's address.
    pub sema_addr: Address,
    /// The argument description string.
    pub args: String,
}

impl UsdtNote {
    fn from_elf(bytes: &[u8]) -> Result<Self> {
        // The binary layout of the USDT Note is the following:
        // - probe PC address (address size)
        // - link-time sh_addr of .stapsdt.base section (address size)
        // - link-time address of the semaphore variable (address size). This is zero if the probe does not have an associated semaphore; in this case no .stapsdt.base adjustment should be done
        // - provider name (null-terminated string)
        // - probe name (null-terminated string)
        // - argument format (null-terminated string)

        let mut cursor = Cursor::new(bytes);

        // Size of addresses depends on architecture.
        #[cfg(target_pointer_width = "32")]
        let read_addr = Cursor::read_u32::<Endian>;
        #[cfg(target_pointer_width = "64")]
        let read_addr = Cursor::read_u64::<Endian>;

        let addr = read_addr(&mut cursor)?;
        let base_addr = read_addr(&mut cursor)?;
        let sema_addr = read_addr(&mut cursor)?;

        // Read provider name.
        let mut provider_buf = vec![];
        cursor.read_until(b'\0', &mut provider_buf)?;
        let provider = CStr::from_bytes_with_nul(&provider_buf)?
            .to_str()?
            .to_string();

        // Read probe name.
        let mut name_buf = vec![];
        cursor.read_until(b'\0', &mut name_buf)?;
        let name = CStr::from_bytes_with_nul(&name_buf)?.to_str()?.to_string();

        // Read probe name.
        let mut args_buf = vec![];
        cursor.read_until(b'\0', &mut args_buf)?;
        let args = CStr::from_bytes_with_nul(&args_buf)?.to_str()?.to_string();
        Ok(UsdtNote {
            provider,
            name,
            addr,
            base_addr,
            sema_addr,
            args,
        })
    }
}

/// Allow nice log messages.
impl fmt::Display for UsdtNote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.provider, self.name)
    }
}

/// Object that represents a binary (library or executable) that might have USDT probes.
#[derive(Debug)]
pub(crate) struct Binary {
    /// The path of the program.
    path: PathBuf,
    /// USDT information
    usdt_info: Option<UsdtInfo>,
    /// Address where the binary is loaded within a process address space.
    addr: Option<u64>,
}

impl Binary {
    /// Create a new (unloaded) Binary object.
    pub(crate) fn new(path: PathBuf) -> Result<Binary> {
        let usdt_info = match UsdtInfo::new(&path) {
            Ok(usdt) => Some(usdt),
            Err(e) => {
                warn!("Failed to load symbols from path: {:?}: {:?}", path, e);
                None
            }
        };
        Ok(Binary {
            path,
            usdt_info,
            addr: None,
        })
    }

    /// Create a new loaded Binary object.
    pub(crate) fn new_loaded(path: PathBuf, addr: u64) -> Result<Binary> {
        let mut binary = Binary::new(path)?;
        binary.addr = Some(addr);
        Ok(binary)
    }

    /// Returns the USDT note associated with a target. Targets are specified as "provider::name".
    pub(crate) fn get_note(&self, target: &str) -> Result<Option<&UsdtNote>> {
        match &self.usdt_info {
            Some(info) => info.get_note(target),
            None => Ok(None),
        }
    }

    /// Retrieves the Usdt note information whose address matches the given offset.
    pub(crate) fn get_note_from_offset(&self, addr: u64) -> Result<Option<&UsdtNote>> {
        match &self.usdt_info {
            Some(info) => info.get_note_from_offset(addr),
            None => Ok(None),
        }
    }
}

/// Object that represents one running process to which probes can be attached.
/// It allows clients to query the existence of USDT probes regardless of whether they might
/// be defined in the process' binary or in it's share libraries.
#[derive(Debug)]
pub(crate) struct Process {
    /// Process ID.
    pid: i32,
    /// Executable information.
    exec: Binary,
    /// Shared libraries.
    libs: Vec<Binary>,
}

impl Process {
    /// Create a new Process object with a specific pid
    pub(crate) fn from_pid(pid: i32) -> Result<Process> {
        let proc_dir = PathBuf::from("/proc").join(pid.to_string());
        if !proc_dir.exists() {
            bail!(ProcessError::NotFound);
        }

        let path = match proc_dir.join("exe").read_link() {
            Ok(bin_path) => bin_path
                .to_str()
                .ok_or_else(|| anyhow!("Failed to process path"))?
                .into(),
            Err(e) => {
                bail!("Cannot open executable path for process {}: {}", pid, e)
            }
        };
        Process::new(pid, path)
    }

    fn new(pid: i32, path: PathBuf) -> Result<Process> {
        if pid == PID_ALL {
            return Ok(Process {
                pid,
                exec: Binary::new(path)?,
                libs: Vec::new(),
            });
        }

        let mut maps = get_process_maps(pid)?;
        // Get the binary address from the first entry in the map.
        let bin_addr = maps
            .get(0)
            .ok_or_else(|| anyhow!("Failed to get process maps"))?
            .addr_start;

        let mut libs = Vec::new();

        // We're only interested on the map first entry of each shared library.
        maps.dedup_by(|a, b| a.path.eq(&b.path));
        for map in maps.iter().filter(|m| m.is_file()) {
            let libpath = PathBuf::from(&map.path);
            // Skip the executable
            if path.eq(&libpath) {
                continue;
            }
            libs.push(Binary::new_loaded(libpath, map.addr_start)?);
        }

        let exec = Binary::new_loaded(path, bin_addr)?;
        Ok(Process { pid, exec, libs })
    }

    /// Create a new Process object with a specific cmd.
    pub(crate) fn from_cmd(cmd: &str) -> Result<Process> {
        let mut pid: i32 = PID_ALL;
        // Look in /proc for a process with this cmd.
        for entry in Path::new("/proc/").read_dir()? {
            let entry = entry?;
            if !entry.path().is_dir()
                || !entry.path().join("comm").exists()
                || fs::read_to_string(entry.path().join("comm"))?
                    .trim()
                    .ne(cmd)
            {
                continue;
            }

            // Return a specific error indicating there are more than once process with this
            // cmd so that the user can decide which one to probe.
            if pid != PID_ALL {
                bail!(ProcessError::TooMany);
            }
            pid = match entry
                .file_name()
                .into_string()
                .map_err(|s| anyhow!("Unable to convert path into string {:?}", s))?
                .parse::<i32>()
            {
                Ok(pid) => pid,
                Err(_) => {
                    continue;
                }
            };
        }
        if pid == PID_ALL {
            bail!(ProcessError::NotFound);
        }
        Process::from_pid(pid)
    }

    /// Create a new Process object that represent all existing and future processes with a
    /// specific path.
    pub(crate) fn all(path: &str) -> Result<Process> {
        let path = PathBuf::from(path);
        if !path.exists() {
            bail!(ProcessError::NotFound);
        }
        Process::new(PID_ALL, path)
    }

    pub(crate) fn pid(&self) -> i32 {
        self.pid
    }

    pub(crate) fn path(&self) -> &PathBuf {
        &self.exec.path
    }

    /// Gets the runtime USDT information of a symbol.
    pub(crate) fn get_note_from_symbol(&self, symbol: u64) -> Result<Option<&UsdtNote>> {
        // Find in the executable.
        if let Some(addr) = self.exec.addr {
            if let Some(note) = self.exec.get_note_from_offset(symbol - addr)? {
                return Ok(Some(note));
            }
        }

        for lib in self.libs.iter() {
            if let Some(addr) = lib.addr {
                if let Some(note) = lib.get_note_from_offset(symbol - addr)? {
                    return Ok(Some(note));
                }
            }
        }
        Ok(None)
    }

    /// Returns the USDT note and path associated with a target. Targets are specified as "provider::name".
    pub(crate) fn get_note(&self, target: &str) -> Result<Option<(&PathBuf, &UsdtNote)>> {
        // Find in the executable.
        if let Some(note) = self.exec.get_note(target)? {
            return Ok(Some((&self.exec.path, note)));
        }

        // Find in libraries.
        for lib in self.libs.iter() {
            if let Some(note) = lib.get_note(target)? {
                return Ok(Some((&lib.path, note)));
            }
        }
        Ok(None)
    }

    /// Determines whether a target specified as "provider::name" is a valid USDT.
    pub(crate) fn is_usdt(&self, target: &str) -> Result<bool> {
        Ok(self.get_note(target)?.is_some())
    }
}

#[derive(Debug)]
struct ProcessMap {
    addr_start: u64,
    addr_end: u64,
    perm: String,
    offset: u64,
    inode: u64,
    path: String,
}

impl ProcessMap {
    /// Returns a ProcessMap object from a string that has the following cannonical format:
    /// 5594f8dce000-5594f8dd7000 r--p 00000000 00:1f 3526003                    /usr/bin/kitty
    fn from_string(mapstr: String) -> Result<ProcessMap> {
        let parts: Vec<&str> = mapstr.split_whitespace().collect();
        if parts.len() < 5 {
            bail!("Invalid map string format {}", mapstr);
        }
        let addr_parts: Vec<&str> = parts[0].split('-').collect();
        if addr_parts.len() != 2 {
            bail!("Invalid map string format {}", mapstr);
        }

        Ok(ProcessMap {
            addr_start: u64::from_str_radix(addr_parts[0], 16)?,
            addr_end: u64::from_str_radix(addr_parts[1], 16)?,
            perm: parts[1].to_owned(),
            offset: u64::from_str_radix(parts[2], 16)?,
            inode: parts[4].parse::<u64>()?,
            path: match parts.get(5) {
                Some(val) => val.to_string(),
                None => String::default(),
            },
        })
    }

    /// Returns if the map is backed by a file.
    fn is_file(&self) -> bool {
        !((self.path.starts_with('[') && self.path.ends_with(']')) || self.path.is_empty())
    }
}

/// Returns the list of ProcessMaps of a given pid.
fn get_process_maps(pid: i32) -> Result<Vec<ProcessMap>> {
    let mut maps = Vec::new();
    // Open /proc/{pid}/maps.
    let maps_file = PathBuf::from("/proc").join(pid.to_string()).join("maps");
    if !maps_file.exists() {
        bail!("Failed to find process maps");
    }
    let file = fs::File::open(maps_file)?;
    for line in BufReader::new(file).lines() {
        maps.push(ProcessMap::from_string(line?)?);
    }
    Ok(maps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use probe::probe;

    #[test]
    fn process_create() -> Result<()> {
        assert!(Process::from_pid(std::process::id() as i32).is_ok());
        let p = Process::from_pid(-1);
        assert!(
            p.is_err()
                && p.unwrap_err().downcast_ref::<ProcessError>() == Some(&ProcessError::NotFound)
        );
        Ok(())
    }

    #[test]
    fn process_from_cmd() -> Result<()> {
        let p = Process::from_cmd("cargo");
        // The test should have been run by cargo so there's at least one process running with that
        // cmd.
        assert!(
            (p.is_err()
                && p.as_ref().unwrap_err().downcast_ref::<ProcessError>()
                    == Some(&ProcessError::TooMany))
                || p.is_ok()
        );

        let p = Process::from_cmd("_no_way_a_process_with_this_cmd_exists__");
        assert!(
            p.is_err()
                && p.unwrap_err().downcast_ref::<ProcessError>() == Some(&ProcessError::NotFound)
        );
        Ok(())
    }

    #[test]
    fn process_all() -> Result<()> {
        let p = Process::all("_no_way_this_path/_exists");
        assert!(
            p.is_err()
                && p.unwrap_err().downcast_ref::<ProcessError>() == Some(&ProcessError::NotFound)
        );

        let p = Process::all("/bin/sh");
        assert!(p.is_ok() && p.unwrap().pid == PID_ALL);
        Ok(())
    }

    #[test]
    fn is_usdt() -> Result<()> {
        // This is an actual USDT.
        probe!(test_provider, test_function, 1);

        let p = Process::from_pid(std::process::id() as i32)?;
        let traceable = p.is_usdt("test_provider::test_function");
        assert!(traceable.is_ok() && traceable.unwrap());
        let traceable = p.is_usdt("foo::bar");
        assert!(traceable.is_ok() && !traceable.unwrap());

        assert!(!Process::all("/bin/true")?.is_usdt("func::bar")?);
        assert!(Process::from_pid(std::process::id() as i32)?
            .is_usdt("wrong_format")
            .is_err());
        Ok(())
    }

    #[test]
    fn shared_libs() -> Result<()> {
        let p = Process::from_pid(std::process::id() as i32)?;
        assert!(!p.libs.is_empty()); // At least ld should be listed.
        for lib in p.libs.iter().as_ref() {
            for note in lib
                .usdt_info
                .as_ref()
                .expect("should have valid USDT info")
                .notes
                .iter()
                .as_ref()
            {
                // All available notes should be available at from the Program.
                let name = format!("{}::{}", note.provider, note.name);
                let traceable = p.is_usdt(name.as_str());
                assert!(traceable.is_ok() && traceable.unwrap());
            }
        }
        Ok(())
    }
}