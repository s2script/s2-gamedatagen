//! Find the new build's copy of an old build's function, from independent evidence: an identical
//! or same-shape body, the strings it references, the vtable slots it fills, and where its
//! callers call it. Every candidate is also scored by instruction-stream similarity.

use crate::elf::{Image, Slot};
use crate::x86::{self, Ins};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

pub struct Analysis<'a> {
    pub img: &'a Image,
    by_code: HashMap<u64, Vec<u64>>,
    by_shape: HashMap<u64, Vec<u64>>,
    by_string: HashMap<String, Vec<u64>>,
    /// callee -> (caller function start, call instruction ip)
    callers: HashMap<u64, Vec<(u64, u64)>>,
    /// function start -> code hash, shape hash
    hashes: HashMap<u64, (u64, u64)>,
}

impl<'a> Analysis<'a> {
    pub fn new(img: &'a Image) -> Analysis<'a> {
        let mut a = Analysis {
            img,
            by_code: HashMap::new(),
            by_shape: HashMap::new(),
            by_string: HashMap::new(),
            callers: HashMap::new(),
            hashes: HashMap::new(),
        };
        for &(s, n) in &img.funcs {
            let mut code = x86::decode(img, s, n);
            x86::trim_padding(&mut code);
            let ch = x86::code_hash(&code);
            let sh = x86::shape_hash(&code);
            a.hashes.insert(s, (ch, sh));
            a.by_code.entry(ch).or_default().push(s);
            a.by_shape.entry(sh).or_default().push(s);
            for st in x86::strings_of(img, &code) {
                a.by_string.entry(st).or_default().push(s);
            }
            for i in code.iter().filter(|i| i.is_call) {
                if let Some(t) = i.branch_target {
                    a.callers.entry(t).or_default().push((s, i.ip));
                }
            }
        }
        a
    }

    pub fn functions_with_string(&self, s: &str) -> &[u64] {
        self.by_string.get(s).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn strings(&self) -> impl Iterator<Item = (&String, &Vec<u64>)> {
        self.by_string.iter()
    }

    pub fn callers_of(&self, f: u64) -> &[(u64, u64)] {
        self.callers.get(&f).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Candidate {
    pub addr: u64,
    pub score: f64,
    pub similarity: f64,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Located {
    pub old: u64,
    pub best: Option<u64>,
    pub confident: bool,
    pub candidates: Vec<Candidate>,
}

/// Cheap, non-recursive identity: identical body, same shape, or a string only it references.
fn quick_map(old: &Analysis, new: &Analysis, f: u64) -> Option<u64> {
    let &(ch, sh) = old.hashes.get(&f)?;
    if let (Some(o), Some(n)) = (old.by_code.get(&ch), new.by_code.get(&ch)) {
        if o.len() == 1 && n.len() == 1 {
            return Some(n[0]);
        }
    }
    if let (Some(o), Some(n)) = (old.by_shape.get(&sh), new.by_shape.get(&sh)) {
        if o.len() == 1 && n.len() == 1 {
            return Some(n[0]);
        }
    }
    let code = x86::decode_func(old.img, f);
    let mut votes: BTreeMap<u64, usize> = BTreeMap::new();
    for s in x86::strings_of(old.img, &code) {
        if old.functions_with_string(&s).len() == 1 {
            if let [only] = new.functions_with_string(&s) {
                *votes.entry(*only).or_default() += 1;
            }
        }
    }
    if votes.len() == 1 { votes.keys().next().copied() } else { None }
}

/// Align two vtables' slots by a head fingerprint, then fill equal-length replaced runs
/// positionally. Returns old index -> new index.
pub fn align_slots(oi: &Image, os: &[Slot], ni: &Image, ns: &[Slot]) -> HashMap<usize, usize> {
    let fp = |img: &Image, s: &Slot| match s {
        Slot::Ext => 0u64,
        Slot::Fn(a) => x86::head_hash(&x86::decode_func(img, *a)) | 1,
    };
    let of: Vec<u64> = os.iter().map(|s| fp(oi, s)).collect();
    let nf: Vec<u64> = ns.iter().map(|s| fp(ni, s)).collect();
    let mut m = HashMap::new();
    for op in similar::capture_diff_slices(similar::Algorithm::Myers, &of, &nf) {
        match op {
            similar::DiffOp::Equal { old_index, new_index, len } => {
                for k in 0..len {
                    m.insert(old_index + k, new_index + k);
                }
            }
            similar::DiffOp::Replace { old_index, old_len, new_index, new_len } if old_len == new_len => {
                for k in 0..old_len {
                    m.insert(old_index + k, new_index + k);
                }
            }
            _ => {}
        }
    }
    m
}

pub fn locate(old: &Analysis, new: &Analysis, f: u64) -> Located {
    let oimg = old.img;
    let nimg = new.img;
    let ocode = x86::decode_func(oimg, f);
    let mut ev: BTreeMap<u64, (f64, Vec<String>)> = BTreeMap::new();
    let mut add = |a: u64, s: f64, why: String| {
        let e = ev.entry(a).or_default();
        e.0 += s;
        e.1.push(why);
    };
    let mut strong = false;
    if let Some(&(ch, sh)) = old.hashes.get(&f) {
        let oc = old.by_code.get(&ch).map(|v| v.len()).unwrap_or(0);
        if let Some(n) = new.by_code.get(&ch) {
            if oc == 1 && n.len() == 1 {
                add(n[0], 100.0, "identical body".into());
                strong = true;
            } else if n.len() <= 4 {
                for &c in n {
                    add(c, 10.0, format!("identical body ({} copies)", n.len()));
                }
            }
        }
        let os = old.by_shape.get(&sh).map(|v| v.len()).unwrap_or(0);
        if let Some(n) = new.by_shape.get(&sh) {
            if os == 1 && n.len() == 1 {
                add(n[0], 90.0, "same shape (only constants changed)".into());
                strong = true;
            } else if n.len() <= 4 {
                for &c in n {
                    add(c, 8.0, format!("same shape ({} copies)", n.len()));
                }
            }
        }
    }
    for s in x86::strings_of(oimg, &ocode) {
        let on = old.functions_with_string(&s).len();
        let nf = new.functions_with_string(&s);
        let shown = if s.len() > 48 { format!("{}…", &s[..s.char_indices().nth(47).map(|c| c.0).unwrap_or(47)]) } else { s.clone() };
        if on == 1 && nf.len() == 1 {
            add(nf[0], 40.0, format!("only function using string {shown:?}"));
        } else if !nf.is_empty() && nf.len() <= 4 && on <= 4 {
            for &c in nf {
                add(c, 10.0 / nf.len() as f64, format!("uses string {shown:?}"));
            }
        }
    }
    for (vi, si) in oimg.vtable_refs(f) {
        let ovt = &oimg.vtables()[vi];
        let cls = crate::elf::demangle_simple(&ovt.mangled);
        if let Some(nvt) = nimg.vtable(&cls, ovt.offset_to_top) {
            let m = align_slots(oimg, &ovt.slots, nimg, &nvt.slots);
            if let Some(&ni) = m.get(&si) {
                if let Some(Slot::Fn(a)) = nvt.slots.get(ni) {
                    let w = if oimg.vtable_refs(f).len() <= 2 { 40.0 } else { 20.0 };
                    add(*a, w, format!("{cls}[{si}] -> [{ni}]"));
                }
            }
        }
    }
    for &(caller, call_ip) in old.callers_of(f).iter().take(24) {
        let Some(nc) = quick_map(old, new, caller) else { continue };
        let occ = x86::decode_func(oimg, caller);
        let ncc = x86::decode_func(nimg, nc);
        let Some(i) = occ.iter().position(|x| x.ip == call_ip) else { continue };
        if let Some(j) = x86::map_index(&occ, &ncc, i) {
            if let Some(t) = ncc[j].branch_target.filter(|_| ncc[j].is_call) {
                add(t, 25.0, format!("called from the same place in sub_{caller:x}"));
            }
        }
    }
    // Same callees: tiny or duplicated bodies (thunks, wrappers) differ only in where they go.
    let ext: Vec<u64> = ocode
        .iter()
        .filter_map(|i| i.branch_target)
        .filter(|&t| t < f || t >= f + ocode.last().map_or(0, |l| l.ip + l.len as u64 - f))
        .take(8)
        .collect();
    if !ext.is_empty() && ev.len() > 1 {
        let mapped: Vec<u64> = ext.iter().filter_map(|&t| quick_map(old, new, t)).collect();
        if !mapped.is_empty() {
            for (&a, e) in ev.iter_mut() {
                let nc = x86::decode_func(nimg, a);
                let hits = nc.iter().filter_map(|i| i.branch_target).filter(|t| mapped.contains(t)).count();
                if hits > 0 {
                    e.0 += 30.0 * hits as f64 / mapped.len() as f64;
                    e.1.push(format!("same callees ({hits}/{})", mapped.len()));
                }
            }
        }
    }
    // Neighbours: identical copies (two thunks to one target) are told apart by what the linker
    // put next to them, which survives most rebuilds.
    if ev.len() > 1 {
        let nb = |img: &Image, a: u64| -> (Option<u64>, Option<u64>) {
            let i = img.funcs.partition_point(|x| x.0 < a);
            let prev = if i > 0 { Some(img.funcs[i - 1].0) } else { None };
            let next = img.funcs.get(i + 1).filter(|_| img.funcs.get(i).map_or(false, |x| x.0 == a)).map(|x| x.0);
            (prev, next)
        };
        let (op, on) = nb(oimg, f);
        let mp = op.and_then(|p| quick_map(old, new, p));
        let mn = on.and_then(|n| quick_map(old, new, n));
        if mp.is_some() || mn.is_some() {
            for (&a, e) in ev.iter_mut() {
                let (np, nn) = nb(nimg, a);
                let hits = (mp.is_some() && np == mp) as usize + (mn.is_some() && nn == mn) as usize;
                if hits > 0 {
                    e.0 += 20.0 * hits as f64;
                    e.1.push(format!("same neighbours ({hits}/2)"));
                }
            }
        }
    }
    let mut cands: Vec<Candidate> = ev
        .into_iter()
        .map(|(addr, (score, evidence))| {
            let sim = x86::similarity(&ocode, &x86::decode_func(nimg, addr));
            Candidate { addr, score: score + 30.0 * sim, similarity: sim, evidence }
        })
        .collect();
    cands.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    cands.truncate(5);
    let best = cands.first().map(|c| c.addr);
    let confident = cands.first().map_or(false, |c| {
        let margin = cands.get(1).map_or(true, |d| c.score >= d.score + 15.0);
        let kinds = distinct_kinds(&c.evidence);
        margin && (strong && c.score >= 90.0 || (kinds >= 2 && c.similarity >= 0.5) || (c.score >= 60.0 && c.similarity >= 0.65))
    });
    Located { old: f, best, confident, candidates: cands }
}

fn distinct_kinds(ev: &[String]) -> usize {
    let mut k: Vec<&str> = ev
        .iter()
        .map(|e| {
            if e.contains("body") || e.contains("shape") {
                "body"
            } else if e.contains("string") {
                "string"
            } else if e.contains("->") {
                "vtable"
            } else if e.contains("neighbours") {
                "neighbours"
            } else if e.contains("callees") {
                "callees"
            } else {
                "caller"
            }
        })
        .collect();
    k.sort();
    k.dedup();
    k.len()
}

/// Map an instruction address inside old function `of` to the same instruction in new `nf`.
pub fn map_site(oimg: &Image, of: u64, nimg: &Image, nf: u64, site: u64) -> Option<(u64, Vec<Ins>)> {
    let oc = x86::decode_func(oimg, of);
    let nc = x86::decode_func(nimg, nf);
    let i = oc.iter().position(|x| x.ip == site)?;
    if i == 0 {
        return Some((nf, nc));
    }
    let j = if i == 0 { 0 } else { x86::map_index(&oc, &nc, i)? };
    Some((nc[j].ip, nc))
}
