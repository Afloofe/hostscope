use object::elf::{self, FileHeader64};
use object::read::elf::{Dyn as _, FileHeader as _, ProgramHeader as _};
use object::Endianness;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DynInfo {

    pub interp: Option<String>,

    pub dynamic: bool,

    pub needed: Vec<String>,

    pub rpath: Vec<String>,

    pub runpath: Vec<String>,
}

impl DynInfo {

    pub fn is_static(&self) -> bool {
        self.interp.is_none() && !self.dynamic
    }
}

pub fn dyn_info(data: &[u8]) -> Result<DynInfo, String> {
    let header = FileHeader64::<Endianness>::parse(data).map_err(|e| format!("not a 64-bit ELF object: {e}"))?;
    let e = header.endian().map_err(|err| format!("ELF endianness: {err}"))?;
    let phdrs = header.program_headers(e, data).map_err(|err| format!("ELF program headers: {err}"))?;

    let mut out = DynInfo::default();
    let mut dynamic = None;
    for ph in phdrs {
        match ph.p_type(e) {
            elf::PT_INTERP => {
                let raw = ph
                    .interpreter(e, data)
                    .map_err(|err| format!("PT_INTERP: {err}"))?
                    .ok_or("PT_INTERP without a path")?;
                out.interp = Some(String::from_utf8(raw.to_vec()).map_err(|_| "PT_INTERP is not UTF-8")?);
            }
            elf::PT_DYNAMIC => {
                if dynamic.is_some() {
                    return Err("two PT_DYNAMIC segments".into());
                }
                dynamic = ph.dynamic(e, data).map_err(|err| format!("PT_DYNAMIC: {err}"))?;
            }
            _ => {}
        }
    }
    let Some(dyns) = dynamic else { return Ok(out) };
    out.dynamic = true;

    let mut strtab = None;
    let mut strsz = None;
    for d in dyns {
        match d.tag(e) {
            elf::DT_NULL => break,
            elf::DT_STRTAB => strtab = Some(d.val(e)),
            elf::DT_STRSZ => strsz = Some(d.val(e)),
            _ => {}
        }
    }
    let (Some(strtab), Some(strsz)) = (strtab, strsz) else {
        return Err("PT_DYNAMIC has no DT_STRTAB/DT_STRSZ".into());
    };
    let off = vaddr_to_offset(phdrs, e, strtab).ok_or("DT_STRTAB is outside every PT_LOAD segment")?;
    let table = usize::try_from(off)
        .ok()
        .zip(usize::try_from(strsz).ok())
        .and_then(|(o, n)| data.get(o..o.checked_add(n)?))
        .ok_or("DT_STRTAB runs past the end of the file")?;
    let string = |at: u64| -> Result<String, String> {
        let rest = usize::try_from(at).ok().and_then(|a| table.get(a..)).ok_or("a dynamic string is outside DT_STRTAB")?;
        let end = rest.iter().position(|b| *b == 0).ok_or("an unterminated dynamic string")?;
        String::from_utf8(rest.get(..end).unwrap_or_default().to_vec()).map_err(|_| "a dynamic string is not UTF-8".into())
    };
    let split = |s: String| -> Vec<String> { s.split(':').filter(|p| !p.is_empty()).map(String::from).collect() };

    let mut filtees = Vec::new();
    for d in dyns {
        match d.tag(e) {
            elf::DT_NULL => break,
            elf::DT_NEEDED => out.needed.push(string(d.val(e))?),
            elf::DT_FILTER | elf::DT_AUXILIARY => filtees.push(string(d.val(e))?),
            elf::DT_RPATH => out.rpath.extend(split(string(d.val(e))?)),
            elf::DT_RUNPATH => out.runpath.extend(split(string(d.val(e))?)),
            _ => {}
        }
    }
    out.needed.extend(filtees);
    Ok(out)
}

fn vaddr_to_offset(phdrs: &[elf::ProgramHeader64<Endianness>], e: Endianness, va: u64) -> Option<u64> {
    phdrs.iter().filter(|p| p.p_type(e) == elf::PT_LOAD).find_map(|p| {
        let start = p.p_vaddr(e);
        let inside = va >= start && va < start.checked_add(p.p_filesz(e))?;
        inside.then(|| p.p_offset(e).checked_add(va - start)).flatten()
    })
}
