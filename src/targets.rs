//! What to regenerate, read from the consumer repo (s2script's
//! `tools/gamedata-offline/targets.jsonc`), plus the gamedata documents it names.

use crate::jsonc::Doc;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize)]
pub struct Pin {
    pub key: String,
    pub module: String,
    pub class: String,
    #[serde(rename = "offsetToTop", default)]
    pub offset_to_top: i64,
    /// The s2sdk class whose virtuals the compiled calls go through, if any.
    #[serde(default)]
    pub header: Option<String>,
}

impl Pin {
    pub fn iface(&self) -> &str {
        self.key.strip_suffix("_vtableSize").unwrap_or(&self.key)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct VClass {
    pub module: String,
    pub class: String,
    #[serde(rename = "offsetToTop", default)]
    pub offset_to_top: i64,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct Sdk {
    /// Path of the s2sdk checkout, relative to the repo root.
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: Vec<String>,
    /// Extra include dirs, relative to the repo root (s2sdk-relative ones go in `sdkIncludes`).
    #[serde(default)]
    pub includes: Vec<String>,
    #[serde(rename = "sdkIncludes", default)]
    pub sdk_includes: Vec<String>,
    #[serde(default)]
    pub defines: Vec<String>,
    #[serde(default)]
    pub fork: Option<String>,
    #[serde(rename = "forkBranch", default)]
    pub fork_branch: Option<String>,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(rename = "upstreamBranch", default)]
    pub upstream_branch: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Targets {
    pub platform: String,
    /// owner -> gamedata file, relative to the repo root
    pub gamedata: BTreeMap<String, String>,
    pub pins: Vec<Pin>,
    /// Bare vtable indices not behind an interface pin: offsets key -> class.
    #[serde(default)]
    pub indices: BTreeMap<String, VClass>,
    #[serde(default)]
    pub sdk: Sdk,
}

pub struct Gamedata {
    pub owner: String,
    pub rel: String,
    pub path: PathBuf,
    pub doc: Doc,
}

pub fn strip_comments_value(src: &str) -> Result<serde_json::Value> {
    Ok(Doc::parse(src.to_string())?.value)
}

pub fn load(repo: &Path, targets: Option<&Path>) -> Result<(Targets, Vec<Gamedata>)> {
    let tp = targets.map(PathBuf::from).unwrap_or_else(|| repo.join("tools/gamedata-offline/targets.jsonc"));
    let src = std::fs::read_to_string(&tp).with_context(|| format!("reading {}", tp.display()))?;
    let t: Targets = serde_json::from_value(strip_comments_value(&src)?).context("targets.jsonc")?;
    let mut gds = Vec::new();
    for (owner, rel) in &t.gamedata {
        let path = repo.join(rel);
        let src = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let doc = Doc::parse(src).with_context(|| format!("parsing {}", path.display()))?;
        gds.push(Gamedata { owner: owner.clone(), rel: rel.clone(), path, doc });
    }
    Ok((t, gds))
}
