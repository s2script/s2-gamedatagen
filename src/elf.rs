//! An ELF shared object loaded the way the dynamic loader would see it: every PT_LOAD segment
//! mapped at its virtual address, R_X86_64_RELATIVE / R_64 / GLOB_DAT relocations applied, and
//! RTTI vtables indexed. Read-only; nothing is ever executed.

use anyhow::{Context, Result};
use object::elf;
use object::read::elf::{ElfFile64, FileHeader, ProgramHeader, SectionHeader, Sym};
use object::{Endianness, Object, ObjectSection};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

const CLASS_TI_VTABLES: [&str; 3] = [
    "_ZTVN10__cxxabiv117__class_type_infoE",
    "_ZTVN10__cxxabiv120__si_class_type_infoE",
    "_ZTVN10__cxxabiv121__vmi_class_type_infoE",
];

pub struct Segment {
    pub vaddr: u64,
    pub data: Vec<u8>,
    pub exec: bool,
}

/// One vtable slot: a function in this module, or an import (`__cxa_pure_virtual` and friends).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Slot {
    Fn(u64),
    Ext,
}

impl Slot {
    pub fn addr(self) -> Option<u64> {
        match self {
            Slot::Fn(a) => Some(a),
            Slot::Ext => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VTable {
    /// Mangled class name as the typeinfo spells it, e.g. `16CNetworkMessages`.
    pub mangled: String,
    pub offset_to_top: i64,
    /// Address of slot 0.
    #[allow(dead_code)]
    pub addr: u64,
    pub slots: Vec<Slot>,
}

pub struct Image {
    pub segs: Vec<Segment>,
    pub sections: HashMap<String, (u64, u64)>,
    extfuncs: HashSet<u64>,
    /// Relocated pointers that land in code (vtable slots, function-pointer tables).
    pub code_ptrs: Vec<u64>,
    typeinfos: HashSet<u64>,
    /// Function ranges from .eh_frame, sorted by start: (start, size).
    pub funcs: Vec<(u64, u64)>,
    vtables: Vec<VTable>,
    vt_by_name: HashMap<(String, i64), usize>,
}

pub fn demangle_simple(n: &str) -> String {
    let digits = n.bytes().take_while(|b| b.is_ascii_digit()).count();
    if digits > 0 {
        if let Ok(len) = n[..digits].parse::<usize>() {
            if len == n.len() - digits {
                return n[digits..].to_string();
            }
        }
    }
    n.to_string()
}

impl Image {
    pub fn load(path: &Path) -> Result<Image> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let file = ElfFile64::<Endianness>::parse(&*bytes).context("parsing ELF")?;
        let endian = file.endian();
        let hdr = file.elf_header();
        let mut segs = Vec::new();
        for ph in hdr.program_headers(endian, &*bytes)? {
            if ph.p_type(endian) != elf::PT_LOAD {
                continue;
            }
            let memsz = ph.p_memsz(endian) as usize;
            let filesz = ph.p_filesz(endian) as usize;
            let off = ph.p_offset(endian) as usize;
            let mut data = vec![0u8; memsz];
            data[..filesz].copy_from_slice(&bytes[off..off + filesz]);
            segs.push(Segment { vaddr: ph.p_vaddr(endian), data, exec: ph.p_flags(endian) & elf::PF_X != 0 });
        }
        segs.sort_by_key(|s| s.vaddr);
        let mut sections = HashMap::new();
        for s in file.sections() {
            if s.address() != 0 {
                sections.insert(s.name().unwrap_or("").to_string(), (s.address(), s.size()));
            }
        }
        let mut img = Image {
            segs,
            sections,
            extfuncs: HashSet::new(),
            code_ptrs: Vec::new(),
            typeinfos: HashSet::new(),
            funcs: Vec::new(),
            vtables: Vec::new(),
            vt_by_name: HashMap::new(),
        };

        // Relocations (every SHT_RELA section, like the Python checker).
        let elf_sections = hdr.sections(endian, &*bytes)?;
        for sh in elf_sections.iter() {
            if sh.sh_type(endian) != elf::SHT_RELA {
                continue;
            }
            let link = object::SectionIndex(sh.sh_link(endian) as usize);
            let symtab = elf_sections.symbol_table_by_index(endian, &*bytes, link).ok();
            let rels = sh.data_as_array::<elf::Rela64<Endianness>, _>(endian, &*bytes)?;
            for r in rels {
                let off = r.r_offset.get(endian);
                let ty = r.r_type(endian, false);
                let addend = r.r_addend.get(endian);
                let symi = r.r_sym(endian, false) as usize;
                match ty {
                    elf::R_X86_64_RELATIVE => {
                        img.w64(off, addend as u64);
                        img.code_ptrs.push(addend as u64);
                    }
                    elf::R_X86_64_64 | elf::R_X86_64_GLOB_DAT => {
                        let Some(st) = symtab.as_ref() else { continue };
                        let Ok(sym) = st.symbol(object::SymbolIndex(symi)) else { continue };
                        let sname = sym.name(endian, st.strings()).map(|n| String::from_utf8_lossy(n).into_owned()).unwrap_or_default();
                        if ty == elf::R_X86_64_64 && CLASS_TI_VTABLES.contains(&sname.as_str()) {
                            img.typeinfos.insert(off);
                        }
                        if sym.st_shndx(endian) == elf::SHN_UNDEF {
                            if sym.st_type() == elf::STT_FUNC || sname.starts_with("__cxa_") {
                                img.extfuncs.insert(off);
                            }
                            img.w64(off, 0);
                        } else {
                            img.w64(off, sym.st_value(endian).wrapping_add(addend as u64));
                        }
                    }
                    _ => {}
                }
            }
        }

        let fdes = img.eh_frame_funcs(&file).unwrap_or_default();
        img.code_ptrs.retain(|&p| p != 0);
        let mut ptrs = std::mem::take(&mut img.code_ptrs);
        ptrs.retain(|&p| img.executable(p));
        img.code_ptrs = ptrs;
        img.funcs = crate::x86::discover_functions(&img, &fdes);
        img.index_vtables();
        Ok(img)
    }

    fn eh_frame_funcs(&self, file: &ElfFile64<Endianness>) -> Result<Vec<(u64, u64)>> {
        use gimli::{BaseAddresses, CieOrFde, EhFrame, LittleEndian, UnwindSection};
        let sec = file.section_by_name(".eh_frame").context("no .eh_frame")?;
        let data = sec.data()?;
        let eh = EhFrame::new(data, LittleEndian);
        let mut bases = BaseAddresses::default().set_eh_frame(sec.address());
        if let Some(t) = file.section_by_name(".text") {
            bases = bases.set_text(t.address());
        }
        if let Some(h) = file.section_by_name(".eh_frame_hdr") {
            bases = bases.set_eh_frame_hdr(h.address());
        }
        let mut out = Vec::new();
        let mut entries = eh.entries(&bases);
        while let Some(e) = entries.next()? {
            if let CieOrFde::Fde(partial) = e {
                if let Ok(fde) = partial.parse(EhFrame::cie_from_offset) {
                    if fde.len() > 0 && self.executable(fde.initial_address()) {
                        out.push((fde.initial_address(), fde.len()));
                    }
                }
            }
        }
        out.sort();
        out.dedup_by_key(|f| f.0);
        Ok(out)
    }

    fn seg_index(&self, at: u64, n: usize) -> Option<usize> {
        let i = self.segs.partition_point(|s| s.vaddr <= at);
        if i == 0 {
            return None;
        }
        let s = &self.segs[i - 1];
        if at + n as u64 <= s.vaddr + s.data.len() as u64 { Some(i - 1) } else { None }
    }

    pub fn read(&self, at: u64, n: usize) -> Option<&[u8]> {
        let i = self.seg_index(at, n)?;
        let s = &self.segs[i];
        let o = (at - s.vaddr) as usize;
        Some(&s.data[o..o + n])
    }

    /// Up to `n` bytes from `at`, clipped at the end of the segment.
    pub fn read_upto(&self, at: u64, n: usize) -> Option<&[u8]> {
        let i = self.seg_index(at, 1)?;
        let s = &self.segs[i];
        let o = (at - s.vaddr) as usize;
        Some(&s.data[o..(o + n).min(s.data.len())])
    }

    pub fn r64(&self, at: u64) -> Option<u64> {
        self.read(at, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn ri32(&self, at: u64) -> Option<i32> {
        self.read(at, 4).map(|b| i32::from_le_bytes(b.try_into().unwrap()))
    }

    fn w64(&mut self, at: u64, val: u64) {
        if let Some(i) = self.seg_index(at, 8) {
            let s = &mut self.segs[i];
            let o = (at - s.vaddr) as usize;
            s.data[o..o + 8].copy_from_slice(&val.to_le_bytes());
        }
    }

    pub fn executable(&self, at: u64) -> bool {
        self.seg_index(at, 1).map(|i| self.segs[i].exec).unwrap_or(false)
    }

    pub fn cstr(&self, at: u64, max: usize) -> Option<&[u8]> {
        let b = self.read_upto(at, max)?;
        let end = memchr::memchr(0, b)?;
        Some(&b[..end])
    }

    /// The function (from .eh_frame) that contains `at`.
    pub fn func_at(&self, at: u64) -> Option<(u64, u64)> {
        let i = self.funcs.partition_point(|f| f.0 <= at);
        if i == 0 {
            return None;
        }
        let f = self.funcs[i - 1];
        if at < f.0 + f.1 { Some(f) } else { None }
    }

    pub fn func_starting(&self, at: u64) -> Option<(u64, u64)> {
        self.func_at(at).filter(|f| f.0 == at)
    }

    // ---- pattern scan over executable segments (like s2sig::FindPatterns)
    pub fn find(&self, pat: &[i16]) -> Vec<u64> {
        let mut out = Vec::new();
        if pat.iter().all(|&p| p < 0) {
            return out;
        }
        // anchor on the longest fixed run
        let (mut best_off, mut best_len) = (0usize, 0usize);
        let mut i = 0;
        while i < pat.len() {
            if pat[i] < 0 {
                i += 1;
                continue;
            }
            let mut j = i;
            while j < pat.len() && pat[j] >= 0 {
                j += 1;
            }
            if j - i > best_len {
                best_off = i;
                best_len = j - i;
            }
            i = j;
        }
        let anchor: Vec<u8> = pat[best_off..best_off + best_len].iter().map(|&p| p as u8).collect();
        let finder = memchr::memmem::Finder::new(&anchor);
        for s in self.segs.iter().filter(|s| s.exec) {
            let mb = &s.data;
            for pos in finder.find_iter(mb) {
                if pos < best_off {
                    continue;
                }
                let st = pos - best_off;
                if st + pat.len() > mb.len() {
                    continue;
                }
                if pat.iter().enumerate().all(|(k, &p)| p < 0 || mb[st + k] == p as u8) {
                    out.push(s.vaddr + st as u64);
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    pub fn slots(&self, vt: u64) -> Vec<Slot> {
        let mut out = Vec::new();
        for i in 0..512u64 {
            let at = vt + 8 * i;
            if self.extfuncs.contains(&at) {
                out.push(Slot::Ext);
                continue;
            }
            match self.r64(at) {
                Some(p) if self.executable(p) => out.push(Slot::Fn(p)),
                _ => break,
            }
        }
        out
    }

    fn index_vtables(&mut self) {
        let mut names: HashMap<u64, String> = HashMap::new();
        for &ti in &self.typeinfos {
            if let Some(np) = self.r64(ti + 8) {
                if let Some(s) = self.cstr(np, 512) {
                    names.insert(ti, String::from_utf8_lossy(s).into_owned());
                }
            }
        }
        let mut found: BTreeMap<u64, (String, i64)> = BTreeMap::new();
        for sname in [".data.rel.ro", ".data.rel.ro.local"] {
            let Some(&(sa, sn)) = self.sections.get(sname) else { continue };
            let Some(sb) = self.read(sa, sn as usize) else { continue };
            let mut p = 8usize;
            while p + 16 <= sb.len() {
                let q = u64::from_le_bytes(sb[p..p + 8].try_into().unwrap());
                if let Some(n) = names.get(&q) {
                    let ott = i64::from_le_bytes(sb[p - 8..p].try_into().unwrap());
                    if (-0x1000000..=0).contains(&ott) {
                        found.insert(sa + p as u64 + 8, (n.clone(), ott));
                    }
                }
                p += 8;
            }
        }
        for (addr, (mangled, ott)) in found {
            let slots = self.slots(addr);
            if slots.is_empty() {
                continue;
            }
            let key = (demangle_simple(&mangled), ott);
            let idx = self.vtables.len();
            // First wins, like a first-match RTTI walk; keep the largest if duplicated.
            match self.vt_by_name.get(&key) {
                Some(&old) if self.vtables[old].slots.len() >= slots.len() => {}
                _ => {
                    self.vt_by_name.insert(key, idx);
                }
            }
            self.vtables.push(VTable { mangled, offset_to_top: ott, addr, slots });
        }
    }

    pub fn vtable(&self, cls: &str, ott: i64) -> Option<&VTable> {
        self.vt_by_name.get(&(cls.to_string(), ott)).map(|&i| &self.vtables[i])
    }

    pub fn vtables(&self) -> &[VTable] {
        &self.vtables
    }

    /// Every (vtable, slot index) whose slot points at `f`.
    pub fn vtable_refs(&self, f: u64) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        for (vi, vt) in self.vtables.iter().enumerate() {
            for (si, s) in vt.slots.iter().enumerate() {
                if *s == Slot::Fn(f) {
                    out.push((vi, si));
                }
            }
        }
        out
    }

}

#[cfg(test)]
mod tests {
    #[test]
    fn demangles_plain_names_only() {
        assert_eq!(super::demangle_simple("16CNetworkMessages"), "CNetworkMessages");
        assert_eq!(super::demangle_simple("N5Outer5InnerE"), "N5Outer5InnerE");
    }
}
