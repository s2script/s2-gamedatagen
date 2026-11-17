use crate::regen::Report;

fn esc(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

pub fn markdown(r: &Report) -> String {
    let mut l: Vec<String> = Vec::new();
    let cnt = |v: &[&str], st: &str| v.iter().filter(|s| **s == st).count();
    let ss: Vec<&str> = r.signatures.iter().map(|s| s.status.as_str()).collect();
    let is: Vec<&str> = r.indices.iter().map(|s| s.status.as_str()).collect();
    let ps: Vec<&str> = r.pins.iter().map(|s| s.status.as_str()).collect();
    l.push("### Gamedata regeneration (gdgen)\n".into());
    l.push(format!(
        "- Signatures: {} ok, **{} re-derived**, **{} need a look**, {} already failing before this build",
        cnt(&ss, "ok"), cnt(&ss, "fixed"), cnt(&ss, "unresolved"), cnt(&ss, "broken-before")
    ));
    l.push(format!(
        "- Vtable indices: {} ok, **{} moved and updated**, **{} need a look**{}",
        cnt(&is, "ok"), cnt(&is, "fixed"), cnt(&is, "unresolved"),
        if cnt(&is, "rebodied") > 0 { format!(", {} same index with a very different body", cnt(&is, "rebodied")) } else { String::new() }
    ));
    l.push(format!("- Vtable pins: {} ok, **{} re-pinned**, **{} held back**", cnt(&ps, "ok"), cnt(&ps, "fixed"), cnt(&ps, "unresolved")));
    let stale = r.sdk_layout.iter().filter(|x| x.verdict == "stale").count();
    l.push(format!("- s2sdk headers: {} interfaces checked, **{} stale**", r.sdk_layout.iter().filter(|x| x.header.is_some()).count(), stale));
    if !r.changed_files.is_empty() {
        l.push(format!("- Applied to: {} (see `gamedata.patch`)", r.changed_files.iter().map(|f| format!("`{f}`")).collect::<Vec<_>>().join(", ")));
    }
    l.push(String::new());

    let todo: Vec<_> = r.signatures.iter().filter(|s| s.status == "unresolved" || s.status == "broken-before").collect();
    if !todo.is_empty() {
        l.push("#### Signatures that need a look\n".into());
        l.push("| Owner | Name | Why | Best candidates (new build) |\n|---|---|---|---|".into());
        for s in todo {
            let c = s
                .candidates
                .iter()
                .take(3)
                .map(|c| format!("`{}` {:.0} (sim {:.2}: {})", c.addr, c.score, c.similarity, esc(&c.evidence.join(", "))))
                .collect::<Vec<_>>()
                .join("<br>");
            l.push(format!("| {} | `{}` | {} | {} |", s.owner, s.name, esc(&s.detail), if c.is_empty() { "none".into() } else { c }));
        }
        l.push(String::new());
    }
    let fixed: Vec<_> = r.signatures.iter().filter(|s| s.status == "fixed").collect();
    if !fixed.is_empty() {
        l.push("#### Signatures re-derived\n".into());
        l.push("| Owner | Name | Old → new | How |\n|---|---|---|---|".into());
        for s in fixed {
            l.push(format!(
                "| {} | `{}` | {} → {} | {} |",
                s.owner, s.name, s.old_addr.as_deref().unwrap_or("?"), s.new_addr.as_deref().unwrap_or("?"), esc(&s.detail)
            ));
        }
        l.push(String::new());
    }
    let idx: Vec<_> = r.indices.iter().filter(|s| s.status != "ok").collect();
    if !idx.is_empty() {
        l.push("#### Vtable indices\n".into());
        l.push("| | Key | Old | New | Detail |\n|---|---|---|---|---|".into());
        for x in idx {
            l.push(format!("| {} | `{}` | {} | {} | {} |", x.status, x.key, x.old, x.new.map(|n| n.to_string()).unwrap_or("?".into()), esc(&x.detail)));
        }
        l.push(String::new());
    }
    let pins: Vec<_> = r.pins.iter().filter(|s| s.status != "ok").collect();
    if !pins.is_empty() {
        l.push("#### Vtable pins\n".into());
        l.push("| | Pin | Class | Pin value | New build | Detail |\n|---|---|---|---|---|---|".into());
        for x in pins {
            l.push(format!("| {} | `{}` | {} | {} | {} | {} |", x.status, x.key, x.class, x.pin, x.new.map(|n| n.to_string()).unwrap_or("?".into()), esc(&x.detail)));
        }
        l.push(String::new());
    }
    l.push("### s2sdk\n".into());
    if let Some(e) = &r.sdk_error {
        l.push(format!("Header layout check did not run: {}\n", esc(e)));
    }
    let rows: Vec<_> = r.sdk_layout.iter().filter(|x| x.header.is_some()).collect();
    if !rows.is_empty() {
        l.push("| | Header | Implemented by | Header slots | Old build | New build | Detail |\n|---|---|---|---|---|---|---|".into());
        for x in rows {
            let mark = match x.verdict.as_str() {
                "ok" => "ok",
                "stale" => "**STALE**",
                _ => "?",
            };
            let f = |v: Option<usize>| v.map(|n| n.to_string()).unwrap_or("?".into());
            l.push(format!("| {mark} | `{}` | {} | {} | {} | {} | {} |", x.header.as_deref().unwrap_or(""), x.class, f(x.header_slots), f(x.old_slots), f(x.new_slots), esc(&x.detail)));
        }
        l.push(String::new());
    }
    let f = &r.sdk_freshness;
    if let Some(p) = &f.pinned {
        let short = |s: &str| s.chars().take(10).collect::<String>();
        let mut line = format!("- Submodule pin `{}`", short(p));
        match (f.pin_is_fork_head, &f.fork_head) {
            (Some(true), _) => line.push_str(" is the fork branch head."),
            (Some(false), Some(h)) => line.push_str(&format!(
                " is not the fork branch head (`{}`){}.",
                short(h),
                if f.pin_in_fork == Some(true) { ", but is in its history" } else { " and is not in its history" }
            )),
            _ => line.push('.'),
        }
        l.push(line);
        if let Some(n) = f.behind_upstream {
            if n == 0 {
                l.push("- The fork branch has every upstream commit.".into());
            } else {
                l.push(format!("- The fork branch is **{n} commits behind upstream**. Latest upstream commits not merged:"));
                l.push(String::new());
                l.push("```".into());
                l.extend(f.upstream_commits.iter().cloned());
                l.push("```".into());
            }
        }
    }
    if let Some(e) = &f.error {
        l.push(format!("- Freshness check failed: {}", esc(e)));
    }
    l.push(String::new());
    l.join("\n")
}
