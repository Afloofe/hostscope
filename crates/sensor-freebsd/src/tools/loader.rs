pub const LIBMAP_CONF: &str = "/etc/libmap.conf";

pub const HINTS: &str = "/var/run/ld-elf.so.hints";

pub const INTERP: &str = "/libexec/ld-elf.so.1";

pub const STANDARD_PATH: &[&str] = &["/lib", "/usr/lib"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LibMap {

    pub include: Vec<String>,

    pub include_dir: Vec<String>,

    pub mappings: Vec<usize>,
}

pub fn parse_libmap(text: &str) -> LibMap {
    let mut m = LibMap::default();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            m.mappings.push(n + 1);
            continue;
        }
        let mut words = line.split_whitespace();
        match (words.next(), words.next()) {
            (Some("include"), Some(p)) => m.include.push(p.to_string()),
            (Some("includedir"), Some(p)) => m.include_dir.push(p.to_string()),
            _ => m.mappings.push(n + 1),
        }
    }
    m
}

pub fn libmap_dir_reads(name: &str) -> bool {
    name.len() > ".conf".len() && name.ends_with(".conf")
}

pub fn parse_hints(b: &[u8]) -> Result<Vec<String>, String> {
    let word = |i: usize| -> Option<u32> {
        let s = b.get(i * 4..i * 4 + 4)?;
        Some(u32::from_le_bytes([*s.first()?, *s.get(1)?, *s.get(2)?, *s.get(3)?]))
    };
    let (Some(magic), Some(version), Some(strtab), Some(strsize), Some(dirlist), Some(dirlen)) =
        (word(0), word(1), word(2), word(3), word(4), word(5))
    else {
        return Err("shorter than its header".into());
    };
    if magic != 0x746e_6845 {
        return Err(format!("bad magic {magic:#x}"));
    }
    if version != 1 {
        return Err(format!("version {version}, expected 1"));
    }
    if dirlist.checked_add(dirlen).is_none_or(|end| end > strsize) {
        return Err("the directory list runs past the string table".into());
    }
    let start = strtab as usize + dirlist as usize;
    let list = b.get(start..start + dirlen as usize).ok_or("the directory list runs past the file")?;
    let list = core::str::from_utf8(list).map_err(|_| "the directory list is not UTF-8")?;
    Ok(list.split(':').filter(|d| !d.is_empty()).map(String::from).collect())
}

pub fn search_order(
    refobj_rpath: &[String],
    refobj_runpath: &[String],
    main_rpath: &[String],
    main_runpath: &[String],
    is_main: bool,
    library_path: &[&str],
    setid_hints: Option<&[String]>,
) -> Vec<String> {
    let mut dirs: Vec<String> = Vec::new();
    if refobj_runpath.is_empty() {
        dirs.extend(refobj_rpath.iter().cloned());
        if !is_main && main_runpath.is_empty() {
            dirs.extend(main_rpath.iter().cloned());
        }
    }
    if setid_hints.is_none() {
        dirs.extend(library_path.iter().map(|d| (*d).to_string()));
    }
    dirs.extend(refobj_runpath.iter().cloned());
    if let Some(hints) = setid_hints {
        dirs.extend(hints.iter().cloned());
        dirs.extend(STANDARD_PATH.iter().map(|d| (*d).to_string()));
    }
    dirs
}

pub fn followable_dir(dir: &str) -> bool {
    dir.starts_with('/') && !dir.contains('$') && !dir.split('/').any(|c| c == "..")
}
