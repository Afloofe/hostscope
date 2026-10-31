const BTF_MAGIC: u16 = 0xeb9f;

const BTF_KIND_FUNC: u32 = 12;

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Option<u32> {
        let bytes = self.buf.get(self.at..self.at + 4)?;
        self.at += 4;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.buf.get(self.at..self.at + 2)?;
        self.at += 2;
        Some(u16::from_le_bytes(bytes.try_into().ok()?))
    }

    fn u8(&mut self) -> Option<u8> {
        let b = self.buf.get(self.at)?;
        self.at += 1;
        Some(*b)
    }
}

struct Header {
    type_off: usize,
    type_len: usize,
    str_off: usize,
}

fn header(buf: &[u8]) -> Option<Header> {
    let mut r = Reader { buf, at: 0 };
    if r.u16()? != BTF_MAGIC {
        return None;
    }
    let _version = r.u8()?;
    let _flags = r.u8()?;
    let hdr_len = r.u32()? as usize;
    let type_off = r.u32()? as usize;
    let type_len = r.u32()? as usize;
    let str_off = r.u32()? as usize;
    let _str_len = r.u32()?;

    Some(Header {
        type_off: hdr_len.checked_add(type_off)?,
        type_len,
        str_off: hdr_len.checked_add(str_off)?,
    })
}

fn trailing_len(kind: u32, vlen: u32) -> Option<usize> {
    let vlen = vlen as usize;
    Some(match kind {
        1 => 4,
        2 => 0,
        3 => 12,
        4 | 5 => vlen * 12,
        6 => vlen * 8,
        7 => 0,
        8..=12 => 0,
        13 => vlen * 8,
        14 => 4,
        15 => vlen * 12,

        16 => 0,
        17 => 4,
        18 => 0,
        19 => vlen * 12,

        _ => return None,
    })
}

fn name_at(buf: &[u8], str_off: usize, name_off: u32) -> Option<&str> {
    let start = str_off.checked_add(name_off as usize)?;
    let rest = buf.get(start..)?;
    let end = rest.iter().position(|b| *b == 0)?;
    core::str::from_utf8(rest.get(..end)?).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotFound {

    WalkedEverything {

        types: u32,
    },

    NotBtf,

    StoppedEarly {

        at_type: u32,

        kind: u32,
    },

    NotByteAligned {

        bit_offset: u32,

        width: u32,
    },
}

pub fn func_id(buf: &[u8], wanted: &str) -> Result<u32, NotFound> {
    let h = header(buf).ok_or(NotFound::NotBtf)?;
    let end = h.type_off.checked_add(h.type_len).ok_or(NotFound::NotBtf)?;
    let mut r = Reader { buf, at: h.type_off };
    let mut id: u32 = 0;

    while r.at < end {
        let Some(next_id) = id.checked_add(1) else {
            return Err(NotFound::StoppedEarly { at_type: id, kind: u32::MAX });
        };
        id = next_id;
        let stopped = |kind| Err(NotFound::StoppedEarly { at_type: id, kind });

        let (Some(name_off), Some(info), Some(_size)) = (r.u32(), r.u32(), r.u32()) else {

            return stopped(u32::MAX);
        };

        let kind = (info >> 24) & 0x1f;
        let vlen = info & 0xffff;

        if kind == BTF_KIND_FUNC && name_at(buf, h.str_off, name_off) == Some(wanted) {
            return Ok(id);
        }
        let Some(trailing) = trailing_len(kind, vlen) else {
            return stopped(kind);
        };
        let Some(at) = r.at.checked_add(trailing) else {
            return stopped(kind);
        };
        r.at = at;
    }
    Err(NotFound::WalkedEverything { types: id })
}

const BTF_KIND_FUNC_PROTO: u32 = 13;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proto {

    pub func_id: u32,

    pub params: u32,
}

struct Index {

    offsets: Vec<usize>,
    str_off: usize,
}

fn index(buf: &[u8]) -> Result<Index, NotFound> {
    let h = header(buf).ok_or(NotFound::NotBtf)?;
    let end = h.type_off.checked_add(h.type_len).ok_or(NotFound::NotBtf)?;
    let mut r = Reader { buf, at: h.type_off };
    let mut offsets = Vec::new();

    while r.at < end {
        let start = r.at;
        let id = u32::try_from(offsets.len() + 1)
            .map_err(|_| NotFound::StoppedEarly { at_type: u32::MAX, kind: u32::MAX })?;
        let stopped = |kind| NotFound::StoppedEarly { at_type: id, kind };

        let (Some(_name), Some(info), Some(_size)) = (r.u32(), r.u32(), r.u32()) else {
            return Err(stopped(u32::MAX));
        };
        offsets.push(start);

        let kind = (info >> 24) & 0x1f;
        let trailing = trailing_len(kind, info & 0xffff).ok_or_else(|| stopped(kind))?;
        r.at = r.at.checked_add(trailing).ok_or_else(|| stopped(kind))?;
    }
    Ok(Index { offsets, str_off: h.str_off })
}

impl Index {

    fn type_at(&self, buf: &[u8], id: u32) -> Option<(u32, u32, u32)> {
        let at = *self.offsets.get((id as usize).checked_sub(1)?)?;
        let mut r = Reader { buf, at };
        Some((r.u32()?, r.u32()?, r.u32()?))
    }
}

pub fn prototypes(buf: &[u8], wanted: &[&str]) -> Result<Vec<Option<Proto>>, NotFound> {
    let idx = index(buf)?;
    let mut out = vec![None; wanted.len()];
    let mut left = wanted.len();

    for id in 1..=u32::try_from(idx.offsets.len()).unwrap_or(u32::MAX) {
        if left == 0 {
            break;
        }
        let Some((name_off, info, size_or_type)) = idx.type_at(buf, id) else {
            break;
        };
        if (info >> 24) & 0x1f != BTF_KIND_FUNC {
            continue;
        }
        let Some(name) = name_at(buf, idx.str_off, name_off) else {
            continue;
        };
        let Some(slot) = wanted.iter().position(|w| *w == name) else {
            continue;
        };
        if out.get(slot).is_some_and(Option::is_some) {
            continue;
        }

        let params = match idx.type_at(buf, size_or_type) {
            Some((_, proto_info, _)) if (proto_info >> 24) & 0x1f == BTF_KIND_FUNC_PROTO => {
                proto_info & 0xffff
            }

            _ => u32::MAX,
        };
        if let Some(entry) = out.get_mut(slot) {
            *entry = Some(Proto { func_id: id, params });
            left -= 1;
        }
    }
    Ok(out)
}

const BTF_KIND_STRUCT: u32 = 4;

const MEMBER_LEN: usize = 12;

pub fn member_offset(buf: &[u8], structure: &str, member: &str) -> Result<u32, NotFound> {
    let idx = index(buf)?;

    for id in 1..=u32::try_from(idx.offsets.len()).unwrap_or(u32::MAX) {
        let Some((name_off, info, _size)) = idx.type_at(buf, id) else {
            break;
        };
        if (info >> 24) & 0x1f != BTF_KIND_STRUCT {
            continue;
        }
        if name_at(buf, idx.str_off, name_off) != Some(structure) {
            continue;
        }

        let kflag = (info >> 31) & 1 == 1;
        let vlen = info & 0xffff;
        let Some(at) = idx.offsets.get((id as usize).saturating_sub(1)).map(|o| o + 12) else {
            break;
        };

        let mut r = Reader { buf, at };
        for _ in 0..vlen {
            let (Some(m_name), Some(_m_type), Some(m_off)) = (r.u32(), r.u32(), r.u32()) else {
                return Err(NotFound::StoppedEarly { at_type: id, kind: BTF_KIND_STRUCT });
            };
            if name_at(buf, idx.str_off, m_name) != Some(member) {
                continue;
            }
            let (bits, width) =
                if kflag { (m_off & 0x00ff_ffff, (m_off >> 24) & 0xff) } else { (m_off, 0) };

            if width != 0 || bits % 8 != 0 {
                return Err(NotFound::NotByteAligned { bit_offset: bits, width });
            }
            return Ok(bits / 8);
        }

        let _ = MEMBER_LEN;
    }
    Err(NotFound::WalkedEverything { types: u32::try_from(idx.offsets.len()).unwrap_or(u32::MAX) })
}

pub fn vmlinux() -> Result<Vec<u8>, i32> {
    crate::saferead::read_kernel_bytes("/sys/kernel/btf/vmlinux").map_err(|e| {
        e.raw_os_error()
            .unwrap_or(if e.kind() == std::io::ErrorKind::NotFound { libc::ENOENT } else { libc::EINVAL })
    })
}
