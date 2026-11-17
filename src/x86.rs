//! x86-64 decoding helpers: per-instruction masks for signatures, normalised tokens for comparing
//! two builds of the same function, and the references (strings, calls) a function makes.

use crate::elf::Image;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug)]
pub struct Ins {
    pub ip: u64,
    pub len: usize,
    pub bytes: Vec<u8>,
    /// Signature mask: true = byte may change between builds (branch / RIP-relative displacement).
    pub wild: Vec<bool>,
    /// Also masks every other displacement and immediate (struct offsets, constants).
    pub wild_consts: Vec<bool>,
    pub mnemonic: Mnemonic,
    /// RIP-relative memory target, if any.
    pub rip_target: Option<u64>,
    /// Near branch / call target, if any.
    pub branch_target: Option<u64>,
    pub is_call: bool,
    /// Byte offset of the RIP displacement inside the instruction (for string-xref validators).
    pub disp_off: Option<usize>,
}

impl Ins {
    /// Token with branch/RIP displacements masked: identical across builds if the code is.
    pub fn tok_code(&self) -> u64 {
        let mut h = DefaultHasher::new();
        for (b, w) in self.bytes.iter().zip(&self.wild) {
            if *w { 0x100u16.hash(&mut h) } else { (*b as u16).hash(&mut h) }
        }
        h.finish()
    }

    /// Token with every constant masked: identical if only offsets / immediates changed.
    pub fn tok_shape(&self) -> u64 {
        let mut h = DefaultHasher::new();
        for (b, w) in self.bytes.iter().zip(&self.wild_consts) {
            if *w { 0x100u16.hash(&mut h) } else { (*b as u16).hash(&mut h) }
        }
        h.finish()
    }

    pub fn sig_bytes(&self) -> Vec<i16> {
        self.bytes.iter().zip(&self.wild).map(|(b, w)| if *w { -1 } else { *b as i16 }).collect()
    }
}

fn decode_one(dec: &mut Decoder, ins: &Instruction, bytes: &[u8]) -> Ins {
    let co = dec.get_constant_offsets(ins);
    let len = ins.len();
    let mut wild = vec![false; len];
    let mut wild_consts = vec![false; len];
    let is_branch = ins.is_call_near() || ins.is_jmp_short_or_near() || ins.is_jcc_short_or_near()
        || matches!(ins.mnemonic(), Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne | Mnemonic::Jrcxz | Mnemonic::Jecxz);
    let rip = ins.is_ip_rel_memory_operand();
    let mut disp_off = None;
    if co.has_displacement() {
        let (o, n) = (co.displacement_offset(), co.displacement_size());
        for k in o..o + n {
            wild_consts[k] = true;
            if rip {
                wild[k] = true;
            }
        }
        if rip {
            disp_off = Some(o);
        }
    }
    if co.has_immediate() {
        let (o, n) = (co.immediate_offset(), co.immediate_size());
        for k in o..o + n {
            wild_consts[k] = true;
            if is_branch {
                wild[k] = true;
            }
        }
    }
    if co.has_immediate2() {
        let (o, n) = (co.immediate_offset2(), co.immediate_size2());
        for k in o..o + n {
            wild_consts[k] = true;
        }
    }
    Ins {
        ip: ins.ip(),
        len,
        bytes: bytes.to_vec(),
        wild,
        wild_consts,
        mnemonic: ins.mnemonic(),
        rip_target: if rip { Some(ins.ip_rel_memory_address()) } else { None },
        branch_target: if is_branch { Some(ins.near_branch_target()) } else { None },
        is_call: ins.is_call_near(),
        disp_off,
    }
}

/// Decode `[start, start+size)`. Stops early at an undecodable byte.
pub fn decode(img: &Image, start: u64, size: u64) -> Vec<Ins> {
    let Some(code) = img.read_upto(start, size as usize) else { return Vec::new() };
    let mut dec = Decoder::with_ip(64, code, start, DecoderOptions::NONE);
    let mut out = Vec::new();
    let mut ins = Instruction::default();
    while dec.can_decode() {
        let pos = dec.position();
        dec.decode_out(&mut ins);
        if ins.is_invalid() {
            break;
        }
        let b = &code[pos..pos + ins.len()];
        out.push(decode_one(&mut dec, &ins, b));
    }
    out
}

/// Decode a whole function (bounds from .eh_frame). Falls back to a linear sweep to the first
/// `ret`/`ud2`/unconditional jmp when the function has no FDE.
pub fn decode_func(img: &Image, start: u64) -> Vec<Ins> {
    if let Some((s, n)) = img.func_starting(start) {
        let mut v = decode(img, s, n);
        trim_padding(&mut v);
        return v;
    }
    let mut v = decode(img, start, 4096);
    if let Some(i) = v.iter().position(|x| matches!(x.mnemonic, Mnemonic::Ret | Mnemonic::Ud2 | Mnemonic::Int3)) {
        v.truncate(i + 1);
    }
    v
}

/// A printable C string at `at` (at least 3 chars), as the referenced literal.
pub fn string_at(img: &Image, at: u64) -> Option<String> {
    if img.executable(at) {
        return None;
    }
    let s = img.cstr(at, 1024)?;
    if s.len() < 3 || !s.iter().all(|&c| c == b'\t' || c == b'\n' || (0x20..0x7f).contains(&c)) {
        return None;
    }
    Some(String::from_utf8_lossy(s).into_owned())
}

pub fn strings_of(img: &Image, code: &[Ins]) -> Vec<String> {
    let mut v: Vec<String> = code.iter().filter_map(|i| i.rip_target).filter_map(|t| string_at(img, t)).collect();
    v.sort();
    v.dedup();
    v
}


pub fn code_hash(code: &[Ins]) -> u64 {
    let mut h = DefaultHasher::new();
    for i in code {
        i.tok_code().hash(&mut h);
    }
    h.finish()
}

pub fn shape_hash(code: &[Ins]) -> u64 {
    let mut h = DefaultHasher::new();
    for i in code {
        i.tok_shape().hash(&mut h);
    }
    h.finish()
}

/// Short fingerprint over the first instructions (mirrors check.py's vtable alignment fingerprint,
/// but code-masked bytes instead of disassembly text).
pub fn head_hash(code: &[Ins]) -> u64 {
    let mut h = DefaultHasher::new();
    for (n, i) in code.iter().enumerate() {
        i.tok_code().hash(&mut h);
        if n >= 23 || matches!(i.mnemonic, Mnemonic::Ret | Mnemonic::Jmp | Mnemonic::Ud2) {
            break;
        }
    }
    h.finish()
}

/// Similarity in [0, 1] of two instruction streams over shape tokens.
pub fn similarity(a: &[Ins], b: &[Ins]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let ta: Vec<u64> = a.iter().map(|i| i.tok_shape()).collect();
    let tb: Vec<u64> = b.iter().map(|i| i.tok_shape()).collect();
    ratio(&ta, &tb)
}

pub fn ratio<T: Hash + Eq + Ord + Clone>(a: &[T], b: &[T]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let ops = similar::capture_diff_slices(similar::Algorithm::Myers, a, b);
    let same: usize = ops
        .iter()
        .map(|o| match o {
            similar::DiffOp::Equal { len, .. } => *len,
            _ => 0,
        })
        .sum();
    2.0 * same as f64 / (a.len() + b.len()) as f64
}

/// Map instruction index `i` of `a` onto `b` through a shape-token alignment. Equal runs map
/// directly; an equal-length replace maps positionally.
pub fn map_index(a: &[Ins], b: &[Ins], i: usize) -> Option<usize> {
    let ta: Vec<u64> = a.iter().map(|x| x.tok_shape()).collect();
    let tb: Vec<u64> = b.iter().map(|x| x.tok_shape()).collect();
    for op in similar::capture_diff_slices(similar::Algorithm::Myers, &ta, &tb) {
        match op {
            similar::DiffOp::Equal { old_index, new_index, len } if (old_index..old_index + len).contains(&i) => {
                return Some(new_index + (i - old_index));
            }
            similar::DiffOp::Replace { old_index, old_len, new_index, new_len }
                if old_len == new_len && (old_index..old_index + old_len).contains(&i) =>
            {
                if a[i].mnemonic == b[new_index + (i - old_index)].mnemonic {
                    return Some(new_index + (i - old_index));
                }
                return None;
            }
            _ => {}
        }
    }
    None
}

/// Function starts for a module built without full unwind tables (most of CS2's code has no FDE):
/// every FDE start, every direct call target, every relocated code pointer and every RIP-relative
/// reference into code, from one linear sweep of the executable segments. A function runs to the
/// next start; trailing padding is trimmed when it is decoded.
pub fn discover_functions(img: &Image, fdes: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut starts: Vec<u64> = fdes.iter().map(|f| f.0).collect();
    starts.extend(img.code_ptrs.iter().copied());
    let text = img.sections.get(".text").copied();
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    if let Some((a, n)) = text {
        ranges.push((a, a + n));
    } else {
        for s in img.segs.iter().filter(|s| s.exec) {
            ranges.push((s.vaddr, s.vaddr + s.data.len() as u64));
        }
    }
    for &(a, end) in &ranges {
        let Some(code) = img.read(a, (end - a) as usize) else { continue };
        let mut dec = Decoder::with_ip(64, code, a, DecoderOptions::NONE);
        let mut ins = Instruction::default();
        while dec.can_decode() {
            dec.decode_out(&mut ins);
            if ins.is_invalid() {
                continue;
            }
            if ins.is_call_near() {
                starts.push(ins.near_branch_target());
            } else if ins.is_ip_rel_memory_operand() && ins.mnemonic() == Mnemonic::Lea {
                let t = ins.ip_rel_memory_address();
                if t >= a && t < end {
                    starts.push(t);
                }
            }
        }
    }
    // A 16-aligned address right after int3 padding starts a function (CS2 pads with 0xCC).
    for &(a, end) in &ranges {
        let Some(code) = img.read(a, (end - a) as usize) else { continue };
        let mut p = ((a + 15) & !15) - a;
        while (p as usize) < code.len() {
            let i = p as usize;
            if i > 0 && code[i - 1] == 0xCC && code[i] != 0xCC {
                starts.push(a + p);
            }
            p += 16;
        }
    }
    starts.retain(|&s| ranges.iter().any(|&(a, e)| s >= a && s < e));
    starts.sort();
    starts.dedup();
    let mut out = Vec::with_capacity(starts.len());
    for (i, &s) in starts.iter().enumerate() {
        let lim = ranges.iter().find(|&&(a, e)| s >= a && s < e).map(|r| r.1).unwrap();
        let next = starts.get(i + 1).copied().unwrap_or(lim).min(lim);
        out.push((s, next - s));
    }
    out
}

fn is_pad(i: &Ins) -> bool {
    matches!(i.mnemonic, Mnemonic::Int3 | Mnemonic::Nop) || (i.mnemonic == Mnemonic::Xchg && i.bytes == [0x66, 0x90])
}

pub fn trim_padding(v: &mut Vec<Ins>) {
    while v.last().map_or(false, is_pad) {
        v.pop();
    }
}
