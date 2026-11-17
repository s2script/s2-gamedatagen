//! gdgen: regenerate s2script's gamedata for a new CS2 build from the previous one.
//!
//!   gdgen regen  --repo <s2script> --old <dir> --new <dir> --out <dir> [--write]
//!   gdgen sdk    --repo <s2script> [--old <dir>] --new <dir>
//!   gdgen locate --old <lib.so> --new <lib.so> <addr>...
//!   gdgen sig    --bin <lib.so> <addr>
//!
//! Reads binaries only; never executes them.

mod elf;
mod jsonc;
mod matcher;
mod regen;
mod report;
mod sdk;
mod sig;
mod targets;
mod x86;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "gdgen", version, about = "Regenerate Source 2 gamedata from the previous build")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Re-derive broken signatures, moved vtable indices and pins; write a patch and a report.
    Regen {
        /// The consumer repo (s2script checkout).
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// targets.jsonc (default: <repo>/tools/gamedata-offline/targets.jsonc).
        #[arg(long)]
        targets: Option<PathBuf>,
        /// Directory with the previous build's modules (the build the gamedata is right for).
        #[arg(long)]
        old: Option<PathBuf>,
        /// Directory with the new build's modules.
        #[arg(long)]
        new: PathBuf,
        /// Where to put regen.md, regen.json, gamedata.patch and the rewritten files.
        #[arg(long)]
        out: PathBuf,
        /// Also rewrite the gamedata files in the repo.
        #[arg(long)]
        write: bool,
        /// Skip the s2sdk header layout check (pins then never follow the binary).
        #[arg(long)]
        no_sdk: bool,
        /// Skip the s2sdk fork/upstream freshness check (no network).
        #[arg(long)]
        no_fetch: bool,
        /// Exit 1 when anything is left for a human.
        #[arg(long)]
        strict: bool,
        /// Self-test: re-derive every signature (even working ones) and compare.
        #[arg(long)]
        selftest: bool,
    },
    /// Only the s2sdk check: header layouts vs the builds, and fork/upstream freshness.
    Sdk {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        targets: Option<PathBuf>,
        #[arg(long)]
        old: Option<PathBuf>,
        #[arg(long)]
        new: PathBuf,
        #[arg(long)]
        no_fetch: bool,
        /// Dump the header vtables clang saw, slot by slot.
        #[arg(long)]
        dump: bool,
    },
    /// Find the new build's copy of old-build functions, with the evidence for each candidate.
    Locate {
        #[arg(long)]
        old: PathBuf,
        #[arg(long)]
        new: PathBuf,
        addrs: Vec<String>,
    },
    /// Functions that reference a string literal (exact, or with --contains a substring).
    Xref {
        #[arg(long)]
        bin: PathBuf,
        #[arg(long)]
        contains: bool,
        text: String,
    },
    /// Make the shortest unique signature for the function (or instruction) at an address.
    Sig {
        #[arg(long)]
        bin: PathBuf,
        addr: String,
    },
}

fn parse_addr(s: &str) -> Result<u64> {
    let t = s.trim_start_matches("sub_").trim_start_matches("0x");
    u64::from_str_radix(t, 16).with_context(|| format!("bad address {s}"))
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Regen { repo, targets, old, new, out, write, no_sdk, no_fetch, strict, selftest } => {
            let r = regen::run(&regen::Opts { repo, targets, old, new, out: out.clone(), write: write && !selftest, no_sdk, no_fetch, selftest })?;
            println!("{}", report::markdown(&r));
            eprintln!("wrote {}/regen.md, regen.json, gamedata.patch", out.display());
            if strict && r.needs_attention {
                std::process::exit(1);
            }
        }
        Cmd::Sdk { repo, targets, old, new, no_fetch, dump } => {
            let (t, _) = targets::load(&repo, targets.as_deref())?;
            let mods: std::collections::BTreeSet<String> = t.pins.iter().map(|p| p.module.clone()).collect();
            let load = |d: &PathBuf| -> std::collections::HashMap<String, elf::Image> {
                mods.iter().filter_map(|m| elf::Image::load(&d.join(m)).ok().map(|i| (m.clone(), i))).collect()
            };
            let nm = load(&new);
            let om = old.as_ref().map(load).unwrap_or_default();
            let h = sdk::header_vtables(&repo, &t);
            if dump {
                if let Ok(h) = &h {
                    for v in h.values() {
                        println!("{} ({} slots)", v.class, v.slots.len());
                        for (i, s) in v.slots.iter().enumerate() {
                            println!("  [{i}] {s}");
                        }
                    }
                }
            }
            let (headers, err) = match h {
                Ok(h) => (Some(h), None),
                Err(e) => (None, Some(format!("{e:#}"))),
            };
            let rep = regen::Report {
                signatures: vec![],
                indices: vec![],
                pins: vec![],
                sdk_layout: sdk::layout(&t, headers.as_ref(), &om, &nm),
                sdk_freshness: if no_fetch { Default::default() } else { sdk::freshness(&repo, &t) },
                sdk_error: err,
                changed_files: vec![],
                needs_attention: false,
            };
            let md = report::markdown(&rep);
            // Only the s2sdk section.
            println!("{}", md.split("### s2sdk").nth(1).map(|s| format!("### s2sdk{s}")).unwrap_or(md.clone()));
            if rep.sdk_layout.iter().any(|l| l.verdict == "stale") {
                std::process::exit(1);
            }
        }
        Cmd::Locate { old, new, addrs } => {
            let oi = elf::Image::load(&old)?;
            let ni = elf::Image::load(&new)?;
            eprintln!("analysing {} functions (old) and {} (new)", oi.funcs.len(), ni.funcs.len());
            let ao = matcher::Analysis::new(&oi);
            let an = matcher::Analysis::new(&ni);
            for a in addrs {
                let a = parse_addr(&a)?;
                let f = oi.func_at(a).map(|f| f.0).unwrap_or(a);
                let l = matcher::locate(&ao, &an, f);
                println!("sub_{f:x}: {}", if l.confident { "confident" } else { "NOT confident" });
                for c in &l.candidates {
                    println!("  0x{:x} score {:.0} similarity {:.2}: {}", c.addr, c.score, c.similarity, c.evidence.join(", "));
                }
            }
        }
        Cmd::Xref { bin, contains, text } => {
            let img = elf::Image::load(&bin)?;
            let an = matcher::Analysis::new(&img);
            for (s, fs) in an.strings() {
                if (contains && s.contains(&text)) || *s == text {
                    for f in fs {
                        println!("sub_{f:x}\t{s:?}");
                    }
                }
            }
        }
        Cmd::Sig { bin, addr } => {
            let img = elf::Image::load(&bin)?;
            let a = parse_addr(&addr)?;
            let code = match img.func_at(a) {
                Some((s, n)) => x86::decode(&img, s, n),
                None => x86::decode(&img, a, 512),
            };
            let Some(start) = sig::ins_index(&code, a) else { bail!("0x{a:x} is not an instruction boundary") };
            let accept = |p: &[i16]| img.find(p) == vec![a];
            match sig::grow_sig(&img, &code, start, 12, 256, &accept) {
                Some(p) => println!("{}", sig::format_pattern(&p)),
                None => bail!("no unique signature within the function"),
            }
        }
    }
    Ok(())
}
