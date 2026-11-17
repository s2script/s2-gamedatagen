//! Signature entries: parse, resolve exactly the way the shim does at boot, and generate new ones.

use crate::elf::{Image, Slot};
use crate::x86::Ins;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct StringXref {
    pub at: i64,
    #[serde(rename = "dispOff")]
    pub disp_off: i64,
    #[serde(rename = "instrLen")]
    pub instr_len: i64,
    pub expect: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct Validate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prologue: Option<String>,
    #[serde(rename = "string-xref", default, skip_serializing_if = "Option::is_none")]
    pub string_xref: Option<StringXref>,
    #[serde(rename = "vtable-member", default, skip_serializing_if = "Option::is_none")]
    pub vtable_member: Option<String>,
}

impl Validate {
    pub fn is_empty(&self) -> bool {
        self.prologue.is_none() && self.string_xref.is_none() && self.vtable_member.is_none()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct SigEntry {
    pub module: String,
    pub pattern: String,
    #[serde(default = "direct")]
    pub resolve: String,
    #[serde(default)]
    pub validate: Validate,
}

fn direct() -> String {
    "direct".into()
}

pub fn parse_pattern(s: &str) -> Vec<i16> {
    s.split_whitespace()
        .map(|t| if t == "?" || t == "??" { -1 } else { i16::from_str_radix(t, 16).unwrap_or(-2) })
        .collect()
}

pub fn format_pattern(p: &[i16]) -> String {
    p.iter().map(|&b| if b < 0 { "?".to_string() } else { format!("{b:02X}") }).collect::<Vec<_>>().join(" ")
}

fn matches_at(img: &Image, at: u64, pat: &[i16]) -> bool {
    match img.read(at, pat.len()) {
        Some(b) => pat.iter().enumerate().all(|(i, &p)| p < 0 || b[i] == p as u8),
        None => false,
    }
}

pub fn rel(img: &Image, pc: u64, off: u64, len: u64) -> Option<u64> {
    let d = img.ri32(pc + off)?;
    Some((pc + len).wrapping_add(d as i64 as u64))
}

pub fn validate(img: &Image, v: &Validate, f: u64) -> Option<String> {
    if v.is_empty() {
        return None;
    }
    if !img.executable(f) {
        return Some("validator input outside .text".into());
    }
    if let Some(p) = &v.prologue {
        if !matches_at(img, f, &parse_pattern(p)) {
            return Some("prologue mismatch".into());
        }
    }
    if let Some(x) = &v.string_xref {
        let tgt = rel(img, (f as i64 + x.at) as u64, x.disp_off as u64, x.instr_len as u64);
        let got = tgt.and_then(|t| img.cstr(t, 512));
        if got != Some(x.expect.as_bytes()) {
            let shown = got.map(|g| String::from_utf8_lossy(g).into_owned());
            return Some(format!("string-xref expected {:?}, got {:?}", x.expect, shown));
        }
    }
    if let Some(cls) = &v.vtable_member {
        let Some(vt) = img.vtable(cls, 0) else { return Some(format!("vtable {cls} not found")) };
        if !vt.slots.contains(&Slot::Fn(f)) {
            return Some(format!("not a member of {cls} primary vtable"));
        }
    }
    None
}

#[derive(Clone, Copy, Debug)]
pub struct Resolved {
    /// Where the pattern matched (the validated call site, for validated-call).
    pub site: u64,
    /// What the shim ends up with.
    pub target: u64,
}

pub fn resolve(img: &Image, e: &SigEntry) -> Result<Resolved, String> {
    let pat = parse_pattern(&e.pattern);
    if pat.iter().any(|&b| b < -1) {
        return Err("unparseable pattern".into());
    }
    resolve_pat(img, e, &pat)
}

pub fn resolve_pat(img: &Image, e: &SigEntry, pat: &[i16]) -> Result<Resolved, String> {
    let v = &e.validate;
    let mut cands = img.find(pat);
    if e.resolve == "validated-call" {
        let ok: Vec<u64> = cands
            .iter()
            .copied()
            .filter(|&c| img.read(c, 1) == Some(&[0xe8]) && validate(img, v, c).is_none())
            .collect();
        if ok.len() != 1 {
            return Err(format!("validated-call: {} matches, {} validated", cands.len(), ok.len()));
        }
        return Ok(Resolved { site: ok[0], target: rel(img, ok[0], 1, 5).unwrap_or(0) });
    }
    if cands.len() > 1 && e.resolve == "direct" && !v.is_empty() {
        let passed: Vec<u64> = cands.iter().copied().filter(|&c| validate(img, v, c).is_none()).collect();
        if passed.len() != 1 {
            return Err(format!("ambiguous ({} matches, {} passed validators)", cands.len(), passed.len()));
        }
        cands = passed;
    }
    if cands.len() != 1 {
        return Err(if cands.is_empty() { "NOT FOUND".into() } else { format!("ambiguous ({} matches)", cands.len()) });
    }
    let t = cands[0];
    match e.resolve.as_str() {
        "lea-disp" => Ok(Resolved { site: t, target: rel(img, t, 3, 7).ok_or("lea-disp: unreadable")? }),
        "ctor-body-xref" => {
            let callers: Vec<u64> =
                img.find(&[0xe8, -1, -1, -1, -1]).into_iter().filter(|&c| rel(img, c, 1, 5) == Some(t)).collect();
            if callers.len() != 1 {
                return Err(format!("ctor-body-xref: {} ctor callers", callers.len()));
            }
            let c = callers[0];
            for back in 7..33 {
                if let Some(b) = img.read(c - back, 3) {
                    if b[0] == 0x4c && b[1] == 0x8d && (b[2] == 0x35 || b[2] == 0x2d) {
                        return Ok(Resolved { site: t, target: rel(img, c - back, 3, 7).unwrap_or(0) });
                    }
                }
            }
            Err("ctor-body-xref: preceding LEA not found".into())
        }
        _ => match validate(img, v, t) {
            Some(err) => Err(err),
            None => Ok(Resolved { site: t, target: t }),
        },
    }
}

/// Grow a signature from instruction `start` of `code` until it matches exactly once (or, for an
/// entry whose validators disambiguate, until `accept` says so). Branch and RIP displacements are
/// wildcarded; everything else is kept. Never ends on a wildcard.
pub fn grow_sig(_img: &Image, code: &[Ins], start: usize, min_len: usize, max_len: usize, accept: &dyn Fn(&[i16]) -> bool) -> Option<Vec<i16>> {
    let mut pat: Vec<i16> = Vec::new();
    for ins in &code[start..] {
        pat.extend(ins.sig_bytes());
        if pat.len() > max_len {
            return None;
        }
        if pat.len() < min_len {
            continue;
        }
        let mut trimmed = pat.clone();
        while trimmed.last() == Some(&-1) {
            trimmed.pop();
        }
        // Cheap pre-check before running the full resolver: a pattern is useful only if it is
        // rare. find() is one anchored scan of the executable segments.
        if accept(&trimmed) {
            return Some(trimmed);
        }
    }
    None
}

/// The instruction index in `code` that starts at `ip`.
pub fn ins_index(code: &[Ins], ip: u64) -> Option<usize> {
    code.iter().position(|i| i.ip == ip)
}

/// Recompute a string-xref validator for `site` in the new image: the first instruction at or
/// after `site` (within `code`) whose RIP target is the expected string.
pub fn find_string_xref(img: &Image, code: &[Ins], site: u64, expect: &str) -> Option<StringXref> {
    for i in code.iter().filter(|i| i.ip >= site) {
        if let (Some(t), Some(off)) = (i.rip_target, i.disp_off) {
            if img.cstr(t, 512) == Some(expect.as_bytes()) {
                return Some(StringXref {
                    at: (i.ip - site) as i64,
                    disp_off: off as i64,
                    instr_len: i.len as i64,
                    expect: expect.to_string(),
                });
            }
        }
    }
    None
}

pub fn masked_prologue(code: &[Ins], nbytes: usize) -> Option<String> {
    let mut p: Vec<i16> = Vec::new();
    for i in code {
        p.extend(i.sig_bytes());
        if p.len() >= nbytes {
            break;
        }
    }
    if p.len() < nbytes {
        return None;
    }
    p.truncate(nbytes);
    while p.last() == Some(&-1) {
        p.pop();
    }
    Some(format_pattern(&p))
}


/// If `p` is "fixed prefix, a run of at least 8 wildcards, then a fixed tail", the tail's offset.
pub fn gap_form(p: &[i16]) -> Option<usize> {
    let mut i = 0;
    while i < p.len() {
        if p[i] < 0 {
            let st = i;
            while i < p.len() && p[i] < 0 {
                i += 1;
            }
            if i - st >= 8 && st > 0 && i < p.len() {
                return Some(i);
            }
        } else {
            i += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_round_trip() {
        let p = parse_pattern("55 48 ? ?? E8");
        assert_eq!(p, vec![0x55, 0x48, -1, -1, 0xe8]);
        assert_eq!(format_pattern(&p), "55 48 ? ? E8");
        assert!(parse_pattern("55 ZZ").contains(&-2));
    }

    #[test]
    fn gap_form_finds_the_tail() {
        let mut p = parse_pattern("55 48 89 E5");
        p.extend(std::iter::repeat(-1).take(20));
        p.extend(parse_pattern("48 8D 15 ? ? ? ?"));
        assert_eq!(gap_form(&p), Some(24));
        assert_eq!(gap_form(&parse_pattern("55 ? ? ? 48")), None);
    }
}
