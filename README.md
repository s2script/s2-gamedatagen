# s2-gamedatagen

Update-day tooling for [s2script](https://github.com/s2script/s2script): notice a new CS2 build
within seconds, and regenerate the gamedata for it from the previous build, so the only work left
for a person (or the update-day Claude session) is what the tools could not prove.

```
Steam PICS feed ──> watcher/ (Docker, always on) ──repository_dispatch──> s2script cs2-update.yml
                                                                            │ fetch both builds' modules
                                                                            │ check.py, schema.py, gdgen regen
                                                                            │ file the cs2-update issue
                                                                            └─> wake the Claude fix task
                                                                                 git apply gamedata.patch,
                                                                                 finish what gdgen listed
```

## `gdgen` (Rust)

```bash
cargo build --release          # target/release/gdgen
gdgen regen --repo ../s2script --old <old build dir> --new <new build dir> --out report/
```

`<dir>`s are flat directories of the depot's `.so` files (s2script's
`tools/gamedata-offline/fetch-depot.sh` makes them). What to look at comes from the consumer repo's
`tools/gamedata-offline/targets.jsonc`: the gamedata files, the interface pins and the classes that
back them, the bare vtable indices, and how to build the s2sdk headers.

`regen` writes `report/regen.md` (for the issue), `report/regen.json`, `report/gamedata.patch`
(`git apply`-able) and the rewritten files under `report/gamedata/`. `--write` also rewrites them in
the repo. `--strict` exits 1 when anything is left for a human.

### What it regenerates

- **Signatures.** Each entry is resolved the way the shim resolves it at boot (`direct`,
  `lea-disp`, `ctor-body-xref`, `validated-call`, and the `prologue` / `string-xref` /
  `vtable-member` validators). A broken one is resolved on the old build, and the function it
  matched is found in the new build from independent evidence: an identical body, the same body
  with only constants changed, strings only it references, the vtable slots it fills, where its
  callers call it, what it calls, and its neighbours. The match must be confident (strong
  evidence, a clear margin over the runner-up, and instruction-level similarity). Then a new
  pattern is grown from the same instruction, with branch and RIP displacements wildcarded,
  until the shim's own resolver accepts it uniquely at that address. Entries written as
  "prologue, gap, string-xref instruction" are regenerated in that form, and validators
  (`string-xref.at`, `prologue`) are recomputed.
- **Vtable indices.** Each hook slot, bare index and `calls` vtable index is followed old → new by
  aligning the two vtables slot by slot. A move is applied only when the function at the new slot
  is the same body or at least 80% similar.
- **Pins.** `<Iface>_vtableSize` follows the new build only when s2sdk agrees (below) and every
  hook index on that interface resolved. A pin is the guard on compiled s2sdk calls, so it is
  never bumped past a header that would now call the wrong slot.

Anything it cannot do with confidence is left untouched and listed with its best candidates.

### The s2sdk check

`gdgen sdk` (also part of `regen`) answers "is s2sdk still right for this build?":

- **Layout.** clang lays out each interface the shim calls through a compiled s2sdk header
  (`-fdump-vtable-layouts`). Each is compared with the implementing class's vtable in both builds:
  a slot inserted or removed inside the interface's range marks the header **stale**, with the
  slot index and the header method next to it. A change past the interface's own slots
  (implementation-only virtuals) is fine.
- **Freshness.** Whether s2script's submodule pin is the head of the fork branch
  (`s2script/s2sdk` `s2script-cs2`), and how many upstream (`alliedmodders/s2sdk` `cs2`) commits
  the fork is missing. Upstream usually fixes a header within a day of an update.

Needs `clang++` (or `CXX`) and the s2sdk submodule checked out.

### Helpers for the leftovers

```bash
gdgen locate --old old/libserver.so --new new/libserver.so 0x1c0e770   # candidates + evidence
gdgen xref   --bin new/libserver.so --contains "TakeDamageOld"          # functions using a string
gdgen sig    --bin new/libserver.so 0x1c199f0                           # shortest unique pattern
```

### Testing against real updates

`--selftest` re-derives every signature, working or not, and compares each with what the shipped
one resolves to. Against the saved builds:

| Old → new | Gamedata | Result |
|---|---|---|
| Oct 22 → Nov 5 | before s2script#334 | 74 of 74 working sigs re-derived to the same address; the broken HUD click receiver re-derived to the same function and `+0x160` vcall as the hand fix; `INetworkStringTableContainer_vtableSize` 22 → 19 re-pinned as #334 did |
| Nov 5 → Nov 11 | before s2script#361 | all signatures fine; `INetChannel` and `INetworkMessages` flagged **stale** (the boot crash), `INetChannelInfo_vtableSize` held back |
| Nov 5 → Nov 11 | current | 78 of 78 re-derived, 0 disagree |
| Oct 22 → Nov 11 | current | 77 of 77 re-derived, 0 disagree |

A full `regen` takes about 5 seconds; `--selftest` about 10.

## `watcher/` (Node, Docker)

An always-on service that logs into Steam anonymously and follows the PICS change feed (every 5
seconds by default). When CS2's public depot manifest changes, it sends a `repository_dispatch`
(`cs2-update-poll`) to s2script with the build id and manifest in `client_payload`, so the
workflow starts within seconds instead of waiting for the next cron tick. The 5-minute cron in the
workflow stays as the backup.

```bash
cd watcher
echo 'GITHUB_TOKEN=github_pat_…' > .env   # fine-grained, s2script/s2script only, Contents: read and write
docker compose up -d --build
docker logs -f cs2-steam-watch
```

| Variable | Default | |
|---|---|---|
| `GITHUB_TOKEN` | (required) | Fine-grained token. `repository_dispatch` needs Contents: read and write on the target repo, nothing else. |
| `GITHUB_REPO` | `s2script/s2script` | |
| `DISPATCH_EVENT` | `cs2-update-poll` | |
| `APP_ID` / `DEPOT_ID` / `BRANCH` | `730` / `2347773` / `public` | |
| `POLL_MS` | `5000` | How often to ask Steam for changes since the last changelist. |
| `STATE_FILE` | `/data/state.json` | Last build dispatched. A build that ships while the watcher is down fires on the next start. |
| `HEALTH_PORT` | `8080` in the image | `GET /` is 200 while polls succeed. |
| `DRY_RUN` | | `1` logs the dispatch instead of sending it. |
| `FIRE_ON_START` | | `1` fires for the current build on a first run with no state. |

The first run only records the current build. The workflow's own `baseline.json` decides whether
a build needs work, and an issue per manifest stops duplicates, so an extra dispatch is harmless.

`npm test` runs the unit tests.
