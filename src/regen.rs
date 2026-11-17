//! Regenerate the gamedata for a new build from the previous one: re-derive every broken
//! signature, follow every vtable index that moved, and re-pin vtable sizes that s2sdk agrees
//! with. Whatever cannot be resolved with confidence is left untouched and reported, with the
//! best candidates, for a human (or the update-day Claude session) to finish.

use crate::elf::{Image, Slot};
use crate::jsonc::Edits;
use crate::matcher::{self, Analysis, Candidate};
use crate::sdk::{self, LayoutRow};
use crate::sig::{self, SigEntry};
use crate::targets::{self, Gamedata, Targets};
use crate::x86;
use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

pub struct Opts {
    pub repo: PathBuf,
    pub targets: Option<PathBuf>,
    pub old: Option<PathBuf>,
    pub new: PathBuf,
    pub out: PathBuf,
    pub write: bool,
    pub no_sdk: bool,
    pub no_fetch: bool,
    /// Self-test: re-derive every signature as if it were broken and compare with what the
    /// shipped one resolves to. Writes nothing.
    pub selftest: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SigRow {
    pub owner: String,
    pub name: String,
    pub module: String,
    /// ok | fixed | unresolved | broken-before
    pub status: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_pattern: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<CandRow>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CandRow {
    pub addr: String,
    pub score: f64,
    pub similarity: f64,
    pub evidence: Vec<String>,
}

impl From<&Candidate> for CandRow {
    fn from(c: &Candidate) -> Self {
        CandRow { addr: format!("0x{:x}", c.addr), score: (c.score * 10.0).round() / 10.0, similarity: (c.similarity * 100.0).round() / 100.0, evidence: c.evidence.clone() }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct IndexRow {
    pub key: String,
    pub owner: String,
    pub class: String,
    pub old: i64,
    pub new: Option<usize>,
    pub old_slots: usize,
    pub new_slots: usize,
    /// ok | fixed | unresolved | rebodied
    pub status: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PinRow {
    pub key: String,
    pub class: String,
    pub pin: i64,
    pub old: Option<usize>,
    pub new: Option<usize>,
    /// ok | fixed | unresolved
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub signatures: Vec<SigRow>,
    pub indices: Vec<IndexRow>,
    pub pins: Vec<PinRow>,
    pub sdk_layout: Vec<LayoutRow>,
    pub sdk_freshness: sdk::Freshness,
    pub sdk_error: Option<String>,
    pub changed_files: Vec<String>,
    pub needs_attention: bool,
}

fn load_dir(dir: &Path, modules: &BTreeSet<String>) -> HashMap<String, Image> {
    let mut m = HashMap::new();
    for name in modules {
        let p = dir.join(name);
        if !p.exists() {
            eprintln!("  (missing module {})", p.display());
            continue;
        }
        match Image::load(&p) {
            Ok(i) => {
                m.insert(name.clone(), i);
            }
            Err(e) => eprintln!("  (cannot load {}: {e:#})", p.display()),
        }
    }
    m
}

struct SigRef {
    gd: usize,
    owner: String,
    name: String,
    entry: SigEntry,
}

struct IdxRef {
    gd: usize,
    key: String,
    /// json path of the integer
    path: String,
    module: String,
    class: String,
    ott: i64,
    value: i64,
    iface: Option<String>,
}

fn collect(t: &Targets, gds: &[Gamedata]) -> (Vec<SigRef>, Vec<IdxRef>, Vec<(usize, String, i64)>) {
    let plat = &t.platform;
    let mut sigs = Vec::new();
    let mut idx = Vec::new();
    let mut pins = Vec::new();
    let pin_by_iface: HashMap<&str, &targets::Pin> = t.pins.iter().map(|p| (p.iface(), p)).collect();
    for (gi, g) in gds.iter().enumerate() {
        if let Some(Value::Object(m)) = g.doc.value.get("signatures") {
            for (name, s) in m {
                if let Some(e) = s.get(plat) {
                    if let Ok(entry) = serde_json::from_value::<SigEntry>(e.clone()) {
                        sigs.push(SigRef { gd: gi, owner: g.owner.clone(), name: name.clone(), entry });
                    }
                }
            }
        }
        if let Some(Value::Object(m)) = g.doc.value.get("offsets") {
            for (k, v) in m {
                let Some(val) = v.get(plat).and_then(|x| x.as_i64()) else { continue };
                let path = format!("/offsets/{k}/{plat}");
                if t.pins.iter().any(|p| &p.key == k) {
                    pins.push((gi, k.clone(), val));
                    continue;
                }
                let prefix = k.split('_').next().unwrap_or("");
                if let Some(p) = pin_by_iface.get(prefix) {
                    idx.push(IdxRef { gd: gi, key: k.clone(), path, module: p.module.clone(), class: p.class.clone(), ott: p.offset_to_top, value: val, iface: Some(p.key.clone()) });
                } else if let Some(c) = t.indices.get(k) {
                    idx.push(IdxRef { gd: gi, key: k.clone(), path, module: c.module.clone(), class: c.class.clone(), ott: c.offset_to_top, value: val, iface: None });
                }
            }
        }
        if let Some(Value::Object(m)) = g.doc.value.get("calls") {
            for (name, c) in m {
                let tg = &c["target"];
                if tg["kind"] != "vtable" {
                    continue;
                }
                let Some(val) = tg[plat]["index"].as_i64() else { continue };
                idx.push(IdxRef {
                    gd: gi,
                    key: format!("calls.{name}"),
                    path: format!("/calls/{name}/target/{plat}/index"),
                    module: tg["module"].as_str().unwrap_or("libserver.so").to_string(),
                    class: tg["class"].as_str().unwrap_or("").to_string(),
                    ott: 0,
                    value: val,
                    iface: None,
                });
            }
        }
    }
    (sigs, idx, pins)
}

pub fn run(o: &Opts) -> Result<Report> {
    let (t, gds) = targets::load(&o.repo, o.targets.as_deref())?;
    let (sigs, idxs, pin_vals) = collect(&t, &gds);
    let mut modules: BTreeSet<String> = sigs.iter().map(|s| s.entry.module.clone()).collect();
    modules.extend(t.pins.iter().map(|p| p.module.clone()));
    modules.extend(idxs.iter().map(|i| i.module.clone()));
    eprintln!("== loading {} modules", modules.len());
    let new = load_dir(&o.new, &modules);
    let old = o.old.as_ref().map(|d| load_dir(d, &modules)).unwrap_or_default();

    let mut edits: Vec<Edits> = gds.iter().map(|_| Edits::default()).collect();
    let mut report = Report {
        signatures: vec![],
        indices: vec![],
        pins: vec![],
        sdk_layout: vec![],
        sdk_freshness: Default::default(),
        sdk_error: None,
        changed_files: vec![],
        needs_attention: false,
    };

    // ---- signatures: which ones need work?
    eprintln!("== signatures");
    let mut pending = Vec::new();
    for (i, s) in sigs.iter().enumerate() {
        let Some(ni) = new.get(&s.entry.module) else {
            report.signatures.push(row(s, "unresolved", "module missing from the new build"));
            continue;
        };
        match sig::resolve(ni, &s.entry) {
            Ok(r) if o.selftest => pending.push((i, format!("selftest (shipped resolves to 0x{:x})", r.target))),
            Ok(r) => {
                let mut rw = row(s, "ok", "");
                rw.new_addr = Some(format!("0x{:x}", r.target));
                report.signatures.push(rw);
            }
            Err(e) => pending.push((i, e)),
        }
    }
    let need: BTreeSet<String> = pending.iter().map(|(i, _)| sigs[*i].entry.module.clone()).collect();
    let mut an_new: HashMap<String, Analysis> = HashMap::new();
    let mut an_old: HashMap<String, Analysis> = HashMap::new();
    for m in &need {
        if let (Some(n), Some(oi)) = (new.get(m), old.get(m)) {
            eprintln!("  analysing {m} (old + new)");
            an_new.insert(m.clone(), Analysis::new(n));
            an_old.insert(m.clone(), Analysis::new(oi));
        }
    }
    for (i, err) in pending {
        let s = &sigs[i];
        let r = regen_sig(s, &err, old.get(&s.entry.module), &new[&s.entry.module], an_old.get(&s.entry.module), an_new.get(&s.entry.module));
        if o.selftest {
            let shipped = sig::resolve(&new[&s.entry.module], &s.entry).ok().map(|x| format!("0x{:x}", x.target));
            let mut rw = r.row;
            if rw.status == "fixed" {
                rw.status = if shipped.is_none() { "fixed".into() } else if shipped == rw.new_addr { "agree".into() } else { "DISAGREE".into() };
            }
            eprintln!("  {:10} {}/{}: {}", rw.status, s.owner, s.name, rw.detail);
            report.signatures.push(rw);
            continue;
        }
        if r.status == "fixed" {
            let g = &gds[s.gd];
            let base = format!("/signatures/{}/{}", s.name, t.platform);
            if let Some(p) = &r.new_pattern {
                edits[s.gd].set(&g.doc, &format!("{base}/pattern"), &json!(p))?;
            }
            if let Some(v) = r.new_validate.as_ref() {
                if let Some(x) = &v.string_xref {
                    edits[s.gd].set(&g.doc, &format!("{base}/validate/string-xref/at"), &json!(x.at))?;
                    edits[s.gd].set(&g.doc, &format!("{base}/validate/string-xref/dispOff"), &json!(x.disp_off))?;
                    edits[s.gd].set(&g.doc, &format!("{base}/validate/string-xref/instrLen"), &json!(x.instr_len))?;
                }
                if let Some(p) = &v.prologue {
                    edits[s.gd].set(&g.doc, &format!("{base}/validate/prologue"), &json!(p))?;
                }
            }
        }
        eprintln!("  {:10} {}/{}: {}", r.row.status, s.owner, s.name, r.row.detail);
        report.signatures.push(r.row);
    }
    report.signatures.sort_by(|a, b| (a.owner.as_str(), a.name.as_str()).cmp(&(b.owner.as_str(), b.name.as_str())));

    // ---- s2sdk layout (decides which pins may follow the binary)
    let headers = if o.no_sdk {
        None
    } else {
        match sdk::header_vtables(&o.repo, &t) {
            Ok(h) => Some(h),
            Err(e) => {
                report.sdk_error = Some(format!("{e:#}"));
                None
            }
        }
    };
    report.sdk_layout = sdk::layout(&t, headers.as_ref(), &old, &new);
    if !o.no_fetch {
        report.sdk_freshness = sdk::freshness(&o.repo, &t);
    }

    // ---- vtable indices
    eprintln!("== vtable indices");
    let mut iface_ok: HashMap<String, bool> = HashMap::new();
    for ix in &idxs {
        let r = regen_index(ix, old.get(&ix.module), new.get(&ix.module), &gds[ix.gd].owner);
        if let Some(p) = &ix.iface {
            let e = iface_ok.entry(p.clone()).or_insert(true);
            *e &= r.status == "ok" || r.status == "fixed";
        }
        if r.status == "fixed" {
            edits[ix.gd].set(&gds[ix.gd].doc, &ix.path, &json!(r.new.unwrap()))?;
        }
        eprintln!("  {:10} {}: {}", r.status, r.key, r.detail);
        report.indices.push(r);
    }

    // ---- pins
    eprintln!("== vtable pins");
    for p in &t.pins {
        let Some((gi, _, val)) = pin_vals.iter().find(|x| x.1 == p.key) else { continue };
        let nn = new.get(&p.module).and_then(|i| i.vtable(&p.class, p.offset_to_top)).map(|v| v.slots.len());
        let on = old.get(&p.module).and_then(|i| i.vtable(&p.class, p.offset_to_top)).map(|v| v.slots.len());
        let lay = report.sdk_layout.iter().find(|l| l.pin == p.key);
        let mut r = PinRow { key: p.key.clone(), class: p.class.clone(), pin: *val, old: on, new: nn, status: "ok".into(), detail: String::new() };
        match nn {
            None => {
                r.status = "unresolved".into();
                r.detail = format!("{} vtable not found in the new build", p.class);
            }
            Some(n) if n as i64 == *val => r.detail = format!("{n} slots"),
            Some(n) => {
                let sdk_ok = lay.map_or(false, |l| l.verdict == "ok") || (p.header.is_none() && lay.map_or(false, |l| l.verdict != "stale"));
                let idx_ok = *iface_ok.get(&p.key).unwrap_or(&true);
                if sdk_ok && idx_ok {
                    edits[*gi].set(&gds[*gi].doc, &format!("/offsets/{}/{}", p.key, t.platform), &json!(n))?;
                    r.status = "fixed".into();
                    r.detail = format!("{val} -> {n}: {}", lay.map(|l| l.detail.as_str()).unwrap_or("no s2sdk header"));
                } else {
                    r.status = "unresolved".into();
                    r.detail = if !sdk_ok {
                        format!("{val} -> {n} slots, but s2sdk is not confirmed for this build ({}); update the header first, then the pin", lay.map(|l| l.detail.as_str()).unwrap_or("no layout"))
                    } else {
                        format!("{val} -> {n} slots, but a hook index on this interface is unresolved")
                    };
                }
            }
        }
        eprintln!("  {:10} {}: {}", r.status, r.key, r.detail);
        report.pins.push(r);
    }

    // ---- write
    let gd_out = o.out.join("gamedata");
    let mut patch = String::new();
    for (g, e) in gds.iter().zip(&edits) {
        if e.is_empty() {
            continue;
        }
        let new_src = e.apply(&g.doc.src);
        // Re-parse: an edit must never leave the file unreadable.
        crate::jsonc::Doc::parse(new_src.clone())?;
        let dst = gd_out.join(&g.rel);
        std::fs::create_dir_all(dst.parent().unwrap())?;
        std::fs::write(&dst, &new_src)?;
        if o.write {
            std::fs::write(&g.path, &new_src)?;
        }
        let diff = similar::TextDiff::from_lines(&g.doc.src, &new_src);
        patch.push_str(&diff.unified_diff().context_radius(3).header(&format!("a/{}", g.rel), &format!("b/{}", g.rel)).to_string());
        report.changed_files.push(g.rel.clone());
    }
    std::fs::create_dir_all(&o.out)?;
    std::fs::write(o.out.join("gamedata.patch"), &patch)?;
    report.needs_attention = report.signatures.iter().any(|s| s.status == "unresolved")
        || report.indices.iter().any(|s| s.status == "unresolved")
        || report.pins.iter().any(|s| s.status == "unresolved")
        || report.sdk_layout.iter().any(|l| l.verdict == "stale");
    std::fs::write(o.out.join("regen.json"), serde_json::to_string_pretty(&report)?)?;
    std::fs::write(o.out.join("regen.md"), crate::report::markdown(&report))?;
    Ok(report)
}

fn row(s: &SigRef, status: &str, detail: &str) -> SigRow {
    SigRow {
        owner: s.owner.clone(),
        name: s.name.clone(),
        module: s.entry.module.clone(),
        status: status.into(),
        detail: detail.into(),
        old_addr: None,
        new_addr: None,
        new_pattern: None,
        candidates: vec![],
    }
}

struct SigResult {
    row: SigRow,
    status: String,
    new_pattern: Option<String>,
    new_validate: Option<sig::Validate>,
}

fn fail(mut r: SigRow, status: &str, why: String) -> SigResult {
    r.status = status.into();
    r.detail = why;
    SigResult { row: r, status: status.into(), new_pattern: None, new_validate: None }
}

fn regen_sig(s: &SigRef, new_err: &str, oi: Option<&Image>, ni: &Image, ao: Option<&Analysis>, an: Option<&Analysis>) -> SigResult {
    let r = row(s, "unresolved", "");
    let (Some(oi), Some(ao), Some(an)) = (oi, ao, an) else {
        return fail(r, "unresolved", format!("{new_err}; no old build to regenerate from"));
    };
    let old = match sig::resolve(oi, &s.entry) {
        Ok(x) => x,
        Err(oe) => {
            // Broken in both builds: offer what the validators point at.
            let mut r = r;
            r.candidates = hint_candidates(ni, an, &s.entry);
            return fail(r, "broken-before", format!("{new_err} (already failing on the old build: {oe})"));
        }
    };
    let mut r = r;
    r.old_addr = Some(format!("0x{:x}", old.target));
    let Some((of, _)) = oi.func_at(old.site) else {
        return fail(r, "unresolved", format!("{new_err}; old match 0x{:x} is not inside a known function", old.site));
    };
    let loc = matcher::locate(ao, an, of);
    r.candidates = loc.candidates.iter().map(CandRow::from).collect();
    let Some(nf) = loc.best.filter(|_| loc.confident) else {
        return fail(r, "unresolved", format!("{new_err}; no confident match for sub_{of:x} in the new build"));
    };
    let Some((site, _)) = matcher::map_site(oi, of, ni, nf, old.site) else {
        return fail(r, "unresolved", format!("{new_err}; matched sub_{nf:x} but could not map the match offset +0x{:x}", old.site - of));
    };
    // Grow from a linear window rather than the discovered function: a function's end is only
    // the next known start, and a signature may run past it.
    let ncode = x86::decode(ni, site, 4096);
    let start = 0;
    // Recompute the validators against the new site.
    let mut v = s.entry.validate.clone();
    if let Some(x) = &s.entry.validate.string_xref {
        match sig::find_string_xref(ni, &ncode, site, &x.expect) {
            Some(nx) => v.string_xref = Some(nx),
            None => return fail(r, "unresolved", format!("{new_err}; sub_{nf:x} no longer references {:?}", x.expect)),
        }
    }
    if let Some(p) = &s.entry.validate.prologue {
        let probe = sig::Validate { prologue: Some(p.clone()), ..Default::default() };
        if sig::validate(ni, &probe, site).is_some() {
            let n = sig::parse_pattern(p).len();
            match sig::masked_prologue(&x86::decode(ni, site, 256), n) {
                Some(np) => v.prologue = Some(np),
                None => return fail(r, "unresolved", format!("{new_err}; prologue validator could not be rebuilt")),
            }
        }
    }
    // For validated-call the callee must still be the same function.
    let want_target = |rt: u64| -> bool {
        match s.entry.resolve.as_str() {
            "validated-call" => {
                let a = x86::decode_func(oi, old.target);
                let b = x86::decode_func(ni, rt);
                x86::similarity(&a, &b) >= 0.6
            }
            "lea-disp" | "ctor-body-xref" => true,
            _ => rt == site,
        }
    };
    let probe_entry = |pat: &[i16]| -> bool {
        let mut e = s.entry.clone();
        e.validate = v.clone();
        matches!(sig::resolve_pat(ni, &e, pat), Ok(rr) if rr.site == site && want_target(rr.target))
    };
    // Keep the shipped entry's form. Many entries are "a short prologue, a long wildcard gap,
    // then the instruction the string-xref validator checks"; regenerate those the same way, so
    // the pattern does not pin every byte of the body in between.
    let old_pat = sig::parse_pattern(&s.entry.pattern);
    let gap_tail = sig::gap_form(&old_pat);
    let mut pat = None;
    if let (Some(tail_at), Some(ox), Some(nx)) = (gap_tail, &s.entry.validate.string_xref, &v.string_xref) {
        if tail_at as i64 == ox.at {
            if let Some(xi) = ncode.iter().find(|i| i.ip == site + nx.at as u64) {
                let tail = xi.sig_bytes();
                let mut prefix: Vec<i16> = Vec::new();
                for ins in &ncode {
                    if prefix.len() >= 8 && prefix.len() <= nx.at as usize {
                        let mut p = prefix.clone();
                        p.resize(nx.at as usize, -1);
                        p.extend(&tail);
                        if probe_entry(&p) {
                            pat = Some(p);
                            break;
                        }
                    }
                    if ins.ip >= site + nx.at as u64 {
                        break;
                    }
                    prefix.extend(ins.sig_bytes());
                }
            }
        }
    }
    if pat.is_none() {
        pat = sig::grow_sig(ni, &ncode, start, 16, 256, &probe_entry);
    }
    let Some(pat) = pat else {
        return fail(r, "unresolved", format!("{new_err}; matched sub_{nf:x} (+0x{:x}) but no unique signature fits", site - nf));
    };
    let mut e = s.entry.clone();
    e.validate = v.clone();
    let rr = sig::resolve_pat(ni, &e, &pat).unwrap();
    r.new_addr = Some(format!("0x{:x}", rr.target));
    r.new_pattern = Some(sig::format_pattern(&pat));
    let why = loc.candidates.first().map(|c| c.evidence.join(", ")).unwrap_or_default();
    r.status = "fixed".into();
    r.detail = format!("{new_err} -> re-derived at 0x{:x} ({why}; similarity {:.2})", rr.target, loc.candidates[0].similarity);
    SigResult { row: r, status: "fixed".into(), new_pattern: Some(sig::format_pattern(&pat)), new_validate: Some(v) }
}

fn hint_candidates(ni: &Image, an: &Analysis, e: &SigEntry) -> Vec<CandRow> {
    let mut out: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    if let Some(x) = &e.validate.string_xref {
        for &f in an.functions_with_string(&x.expect).iter().take(8) {
            out.entry(f).or_default().push(format!("references {:?}", x.expect));
        }
    }
    if let Some(cls) = &e.validate.vtable_member {
        if let Some(vt) = ni.vtable(cls, 0) {
            let want: Vec<u64> = out.keys().copied().collect();
            for (i, s) in vt.slots.iter().enumerate() {
                if let Slot::Fn(a) = s {
                    if want.is_empty() || want.contains(a) {
                        out.entry(*a).or_default().push(format!("{cls}[{i}]"));
                    }
                }
            }
        }
    }
    out.into_iter()
        .take(8)
        .map(|(a, ev)| CandRow { addr: format!("0x{a:x}"), score: ev.len() as f64, similarity: 0.0, evidence: ev })
        .collect()
}

fn regen_index(ix: &IdxRef, oi: Option<&Image>, ni: Option<&Image>, owner: &str) -> IndexRow {
    let mut r = IndexRow { key: ix.key.clone(), owner: owner.to_string(), class: ix.class.clone(), old: ix.value, new: None, old_slots: 0, new_slots: 0, status: "unresolved".into(), detail: String::new() };
    let nv = ni.and_then(|i| i.vtable(&ix.class, ix.ott));
    let Some(nv) = nv else {
        r.detail = format!("{} vtable not found in the new build", ix.class);
        return r;
    };
    r.new_slots = nv.slots.len();
    let Some((oi, ov)) = oi.and_then(|i| i.vtable(&ix.class, ix.ott).map(|v| (i, v))) else {
        r.status = if (ix.value as usize) < nv.slots.len() { "ok".into() } else { "unresolved".into() };
        r.detail = "no old build; index only range-checked".into();
        return r;
    };
    let ni = ni.unwrap();
    r.old_slots = ov.slots.len();
    let i = ix.value as usize;
    if i >= ov.slots.len() {
        r.detail = format!("index {i} is past the old build's {} slots", ov.slots.len());
        return r;
    }
    let m = matcher::align_slots(oi, &ov.slots, ni, &nv.slots);
    let Some(&j) = m.get(&i) else {
        r.detail = format!("{}[{i}] has no counterpart in the new vtable ({} -> {} slots)", ix.class, ov.slots.len(), nv.slots.len());
        return r;
    };
    r.new = Some(j);
    let body = |img: &Image, s: Slot| s.addr().map(|a| x86::decode_func(img, a)).unwrap_or_default();
    let (a, b) = (body(oi, ov.slots[i]), body(ni, nv.slots[j]));
    let same = !a.is_empty() && x86::code_hash(&a) == x86::code_hash(&b);
    let sim = x86::similarity(&a, &b);
    if j == i {
        if same || ov.slots[i] == Slot::Ext {
            r.status = "ok".into();
            r.detail = format!("unchanged ({} -> {} slots)", ov.slots.len(), nv.slots.len());
        } else if sim >= 0.5 {
            r.status = "ok".into();
            r.detail = format!("same index, body recompiled (similarity {sim:.2})");
        } else {
            r.status = "rebodied".into();
            r.detail = format!("same index but the body changed a lot (similarity {sim:.2}); check it is still the same virtual");
        }
    } else if same || sim >= 0.8 {
        r.status = "fixed".into();
        r.detail = format!("{}[{i}] -> [{j}] ({}, {} -> {} slots)", ix.class, if same { "identical body".to_string() } else { format!("similarity {sim:.2}") }, ov.slots.len(), nv.slots.len());
    } else {
        r.detail = format!("{}[{i}] probably -> [{j}], but the body changed (similarity {sim:.2})", ix.class);
    }
    r
}
