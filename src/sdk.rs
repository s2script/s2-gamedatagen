//! Is s2sdk still right for this build? Two questions:
//!
//! 1. **Layout.** clang lays out every interface s2script calls through a compiled s2sdk header
//!    (`-fdump-vtable-layouts`); each one's slot count and the position of any slot the new build
//!    inserted or removed are compared with the implementing class's vtable in both builds.
//! 2. **Freshness.** Whether the submodule pin is the fork branch's head, and how far the fork
//!    branch is behind upstream (upstream often fixes a header within a day of an update).

use crate::elf::Image;
use crate::matcher;
use crate::targets::{Pin, Targets};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::process::Command;

#[derive(Clone, Debug, Serialize)]
pub struct HeaderVtable {
    pub class: String,
    /// Method text for each slot (offset_to_top and RTTI dropped).
    pub slots: Vec<String>,
}

/// Run clang over the s2sdk headers and return every interface's primary vtable.
pub fn header_vtables(repo: &Path, t: &Targets) -> Result<BTreeMap<String, HeaderVtable>> {
    let sdk = repo.join(t.sdk.path.as_deref().unwrap_or("third_party/hl2sdk"));
    if !sdk.join("public").is_dir() {
        bail!("s2sdk not checked out at {} (git submodule update --init {})", sdk.display(), t.sdk.path.as_deref().unwrap_or("third_party/hl2sdk"));
    }
    let mut tu = String::new();
    for h in &t.sdk.headers {
        tu.push_str(&format!("#include <{h}>\n"));
    }
    // An abstract interface's vtable is only laid out when something constructs it: a probe
    // subclass with an out-of-line constructor makes clang emit (and dump) each one.
    let mut seen = std::collections::BTreeSet::new();
    for p in &t.pins {
        if let Some(h) = &p.header {
            if seen.insert(h.clone()) {
                tu.push_str(&format!("struct S2Probe_{h} : {h} {{ S2Probe_{h}(); }};\nS2Probe_{h}::S2Probe_{h}() {{}}\n"));
            }
        }
    }
    let dir = std::env::temp_dir().join(format!("gdgen-sdk-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let src = dir.join("probe.cpp");
    std::fs::write(&src, tu)?;
    let cxx = std::env::var("CXX").unwrap_or_else(|_| "clang++".into());
    let mut cmd = Command::new(&cxx);
    cmd.args(["-std=c++17", "-c", "-o", "/dev/null", "-w", "-m64", "-Xclang", "-fdump-vtable-layouts"]);
    for d in &t.sdk.defines {
        cmd.arg(format!("-D{d}"));
    }
    for i in &t.sdk.includes {
        cmd.arg(format!("-I{}", repo.join(i).display()));
    }
    for i in &t.sdk.sdk_includes {
        cmd.arg(format!("-I{}", sdk.join(i).display()));
    }
    cmd.arg(&src);
    let out = cmd.output().with_context(|| format!("running {cxx} (set CXX to a clang++)"))?;
    let _ = std::fs::remove_dir_all(&dir);
    if !out.status.success() {
        bail!("{cxx} failed:\n{}", String::from_utf8_lossy(&out.stderr).lines().take(30).collect::<Vec<_>>().join("\n"));
    }
    Ok(parse_dump(&String::from_utf8_lossy(&out.stdout)))
}

pub fn parse_dump(s: &str) -> BTreeMap<String, HeaderVtable> {
    let mut out = BTreeMap::new();
    let mut cur: Option<HeaderVtable> = None;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("Vtable for '") {
            if let Some(v) = cur.take() {
                out.entry(v.class.clone()).or_insert(v);
            }
            let Some(end) = rest.find('\'') else { continue };
            let name = &rest[..end];
            // Only a class's own primary vtable ("Vtable for 'X' (N entries)."), not the
            // "Vtable for 'B' (N entries) in 'X'" sub-tables.
            if rest[end..].contains(" in '") {
                continue;
            }
            cur = Some(HeaderVtable { class: name.to_string(), slots: Vec::new() });
            continue;
        }
        let Some(v) = cur.as_mut() else { continue };
        let t = line.trim_start();
        let Some((num, text)) = t.split_once(" | ") else {
            if t.is_empty() {
                out.entry(v.class.clone()).or_insert(cur.take().unwrap());
            }
            continue;
        };
        if num.trim().parse::<usize>().is_err() {
            continue;
        }
        if text.starts_with("vcall_offset") || text.starts_with("vbase_offset") || text.starts_with("offset_to_top") || text.ends_with(" RTTI") {
            continue;
        }
        v.slots.push(text.trim().to_string());
    }
    if let Some(v) = cur.take() {
        out.entry(v.class.clone()).or_insert(v);
    }
    out
}

#[derive(Clone, Debug, Serialize)]
pub struct Change {
    /// First old slot index affected.
    pub at: usize,
    pub removed: usize,
    pub inserted: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct LayoutRow {
    pub pin: String,
    pub header: Option<String>,
    pub class: String,
    pub header_slots: Option<usize>,
    pub old_slots: Option<usize>,
    pub new_slots: Option<usize>,
    pub changes: Vec<Change>,
    /// ok | stale | unknown
    pub verdict: String,
    pub detail: String,
}

fn vt_changes(oi: &Image, ni: &Image, p: &Pin) -> Option<(usize, usize, Vec<Change>)> {
    let ov = oi.vtable(&p.class, p.offset_to_top)?;
    let nv = ni.vtable(&p.class, p.offset_to_top)?;
    let m = matcher::align_slots(oi, &ov.slots, ni, &nv.slots);
    // Walk the old slots; a gap in the mapping or a jump in the new index is a change.
    let mut ch = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < ov.slots.len() || j < nv.slots.len() {
        match m.get(&i) {
            Some(&nj) if nj == j => {
                i += 1;
                j += 1;
            }
            _ => {
                let start = i;
                let mut removed = 0;
                while i < ov.slots.len() && !m.contains_key(&i) {
                    i += 1;
                    removed += 1;
                }
                let target = if i < ov.slots.len() { m[&i] } else { nv.slots.len() };
                let inserted = target.saturating_sub(j);
                j = target;
                if removed == 0 && inserted == 0 {
                    // Mapping went backwards (reorder); count one slot as changed and move on.
                    ch.push(Change { at: start, removed: 1, inserted: 1 });
                    i += 1;
                    j += 1;
                    continue;
                }
                ch.push(Change { at: start, removed, inserted });
            }
        }
    }
    Some((ov.slots.len(), nv.slots.len(), ch))
}

pub fn layout(t: &Targets, headers: Option<&BTreeMap<String, HeaderVtable>>, old: &HashMap<String, Image>, new: &HashMap<String, Image>) -> Vec<LayoutRow> {
    let mut rows = Vec::new();
    for p in &t.pins {
        let hv = p.header.as_ref().and_then(|h| headers.and_then(|m| m.get(h)));
        let hn = hv.map(|h| h.slots.len());
        let ni = new.get(&p.module);
        let oi = old.get(&p.module);
        let nn = ni.and_then(|i| i.vtable(&p.class, p.offset_to_top)).map(|v| v.slots.len());
        let mut row = LayoutRow {
            pin: p.key.clone(),
            header: p.header.clone(),
            class: p.class.clone(),
            header_slots: hn,
            old_slots: None,
            new_slots: nn,
            changes: vec![],
            verdict: "unknown".into(),
            detail: String::new(),
        };
        let name = |k: usize| hv.and_then(|h| h.slots.get(k)).map(|s| short_method(s)).unwrap_or_else(|| format!("slot {k}"));
        match (oi, ni) {
            (Some(oi), Some(ni)) => {
                if let Some((on, nn2, ch)) = vt_changes(oi, ni, p) {
                    row.old_slots = Some(on);
                    row.new_slots = Some(nn2);
                    let inside: Vec<&Change> = ch.iter().filter(|c| hn.map_or(true, |h| c.at < h)).collect();
                    if p.header.is_none() {
                        row.verdict = if ch.is_empty() { "ok".into() } else { "unknown".into() };
                        row.detail = if ch.is_empty() { "unchanged; no s2sdk header (pin only)".into() } else { "changed; no s2sdk header to compare".into() };
                    } else if hn.is_none() {
                        row.detail = "header not laid out (clang unavailable or class missing)".into();
                    } else if ch.is_empty() {
                        row.verdict = "ok".into();
                        row.detail = "vtable unchanged".into();
                    } else if hn == Some(nn2) {
                        row.verdict = "ok".into();
                        row.detail = "header already matches the new build".into();
                    } else if inside.is_empty() {
                        row.verdict = "ok".into();
                        row.detail = format!("changed only past the interface's {} slots", hn.unwrap());
                    } else {
                        row.verdict = "stale".into();
                        row.detail = inside
                            .iter()
                            .map(|c| {
                                let before = if c.at == 0 { "the start".to_string() } else { format!("{} [{}]", name(c.at - 1), c.at - 1) };
                                match (c.removed, c.inserted) {
                                    (0, n) => format!("{n} slot(s) inserted at [{}], after {before}", c.at),
                                    (n, 0) => format!("{n} slot(s) removed at [{}] ({}…)", c.at, name(c.at)),
                                    (r, n) => format!("{r} slot(s) at [{}] ({}…) became {n}", c.at, name(c.at)),
                                }
                            })
                            .collect::<Vec<_>>()
                            .join("; ");
                    }
                    row.changes = ch;
                } else {
                    row.detail = "vtable not found in one of the builds".into();
                }
            }
            (None, Some(_)) => {
                // No old build: compare counts only.
                match (hn, nn) {
                    (Some(h), Some(n)) if h == n => {
                        row.verdict = "ok".into();
                        row.detail = "header slot count equals the new build's".into();
                    }
                    (Some(h), Some(n)) => row.detail = format!("header {h} vs new build {n}; no old build to tell where"),
                    _ => row.detail = "no old build to compare".into(),
                }
            }
            _ => row.detail = "module missing".into(),
        }
        rows.push(row);
    }
    rows
}

fn short_method(s: &str) -> String {
    // "bool IVEngineServer2::IsSpawnGroupLoadedForClient(SpawnGroupHandle_t, CPlayerSlot) [pure]"
    let s = s.trim_end_matches(" [pure]");
    let head = s.split('(').next().unwrap_or(s);
    head.rsplit(' ').next().unwrap_or(head).to_string()
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct Freshness {
    pub pinned: Option<String>,
    pub fork_head: Option<String>,
    pub pin_is_fork_head: Option<bool>,
    pub pin_in_fork: Option<bool>,
    pub upstream_head: Option<String>,
    pub behind_upstream: Option<usize>,
    pub upstream_commits: Vec<String>,
    pub error: Option<String>,
}

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let o = Command::new("git").arg("-C").arg(dir).args(args).output()?;
    if !o.status.success() {
        bail!("git {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

pub fn freshness(repo: &Path, t: &Targets) -> Freshness {
    let mut f = Freshness::default();
    if let Err(e) = freshness_inner(repo, t, &mut f) {
        f.error = Some(format!("{e:#}"));
    }
    f
}

fn freshness_inner(repo: &Path, t: &Targets, f: &mut Freshness) -> Result<()> {
    let path = t.sdk.path.as_deref().unwrap_or("third_party/hl2sdk");
    // The gitlink in the superproject, so it works without the submodule checked out.
    let ls = git(repo, &["ls-tree", "HEAD", path])?;
    let pinned = ls.split_whitespace().nth(2).context("submodule not in HEAD")?.to_string();
    f.pinned = Some(pinned.clone());
    let (Some(fork), Some(fb)) = (&t.sdk.fork, &t.sdk.fork_branch) else { return Ok(()) };
    let dir = std::env::temp_dir().join(format!("gdgen-s2sdk-{}.git", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let o = Command::new("git").args(["init", "-q", "--bare"]).arg(&dir).output()?;
    if !o.status.success() {
        bail!("git init failed");
    }
    let r = (|| -> Result<()> {
        git(&dir, &["fetch", "-q", "--filter=tree:0", fork, &format!("+refs/heads/{fb}:refs/fork")])?;
        let fh = git(&dir, &["rev-parse", "refs/fork"])?;
        f.pin_is_fork_head = Some(fh == pinned);
        f.fork_head = Some(fh);
        f.pin_in_fork = Some(git(&dir, &["merge-base", "--is-ancestor", &pinned, "refs/fork"]).is_ok());
        if let (Some(up), Some(ub)) = (&t.sdk.upstream, &t.sdk.upstream_branch) {
            git(&dir, &["fetch", "-q", "--filter=tree:0", up, &format!("+refs/heads/{ub}:refs/upstream")])?;
            f.upstream_head = Some(git(&dir, &["rev-parse", "refs/upstream"])?);
            let n: usize = git(&dir, &["rev-list", "--count", "refs/fork..refs/upstream"])?.parse()?;
            f.behind_upstream = Some(n);
            let log = git(&dir, &["log", "--no-merges", "--format=%h %ad %s", "--date=short", "-15", "refs/fork..refs/upstream"])?;
            f.upstream_commits = log.lines().map(String::from).collect();
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMP: &str = "Vtable for 'IFoo' (5 entries).
   0 | offset_to_top (0)
   1 | IFoo RTTI
       -- (IFoo, 0) vtable address --
   2 | void IFoo::A() [pure]
   3 | int IFoo::B(int) [pure]
   4 | IFoo::~IFoo() [complete]

Vtable for 'IBar' (3 entries) in 'S2Probe_IFoo'.
   0 | offset_to_top (-8)
   1 | S2Probe_IFoo RTTI
   2 | void IBar::C()

";

    #[test]
    fn parses_primary_vtables_only() {
        let m = parse_dump(DUMP);
        assert_eq!(m.len(), 1);
        assert_eq!(m["IFoo"].slots.len(), 3);
        assert_eq!(short_method(&m["IFoo"].slots[1]), "IFoo::B");
    }
}
