// cs2-steam-watch: logs into Steam anonymously, follows the PICS change feed, and fires a GitHub
// repository_dispatch within seconds of a new CS2 public build. The cs2-update workflow in
// s2script does the rest (fetch the depot, run the checks and gdgen, file the issue, wake Claude).
//
// Configuration is all environment; see README.md.

import SteamUser from 'steam-user';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { backoff, decide, dispatchBody, readBuild } from './lib.js';

const env = process.env;
const cfg = {
  app: Number(env.APP_ID ?? 730),
  depot: Number(env.DEPOT_ID ?? 2347773),
  branch: env.BRANCH ?? 'public',
  repo: env.GITHUB_REPO ?? 's2script/s2script',
  token: env.GITHUB_TOKEN ?? '',
  eventType: env.DISPATCH_EVENT ?? 'cs2-update-poll',
  pollMs: Number(env.POLL_MS ?? 5000),
  stateFile: env.STATE_FILE ?? '/data/state.json',
  healthPort: env.HEALTH_PORT ? Number(env.HEALTH_PORT) : null,
  fireOnStart: env.FIRE_ON_START === '1',
  dryRun: env.DRY_RUN === '1',
};
if (!cfg.token && !cfg.dryRun) {
  console.error('GITHUB_TOKEN is required (a fine-grained token with Contents: read and write on the repo), or set DRY_RUN=1');
  process.exit(2);
}

const log = (...a) => console.log(new Date().toISOString(), ...a);

function loadState() {
  try {
    return JSON.parse(fs.readFileSync(cfg.stateFile, 'utf8'));
  } catch {
    return {};
  }
}
function saveState(s) {
  fs.mkdirSync(path.dirname(cfg.stateFile), { recursive: true });
  const tmp = `${cfg.stateFile}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(s, null, 2));
  fs.renameSync(tmp, cfg.stateFile);
}

let state = loadState();
let changenumber = state.changenumber ?? 0;
let lastPollOk = 0;
let busy = false;

async function dispatch(build) {
  const body = dispatchBody(cfg.eventType, build, changenumber);
  if (cfg.dryRun) {
    log('DRY_RUN dispatch', JSON.stringify(body));
    return true;
  }
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      const r = await fetch(`https://api.github.com/repos/${cfg.repo}/dispatches`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${cfg.token}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
          'User-Agent': 'cs2-steam-watch',
        },
        body: JSON.stringify(body),
      });
      if (r.status === 204) return true;
      const text = await r.text();
      log(`dispatch HTTP ${r.status}: ${text.slice(0, 200)}`);
      if (r.status === 401 || r.status === 403 || r.status === 404) return false; // token problem: retrying won't help
    } catch (e) {
      log('dispatch failed:', e.message);
    }
    await new Promise((res) => setTimeout(res, backoff(attempt)));
  }
  return false;
}

async function check(client, why) {
  const info = await client.getProductInfo([cfg.app], [], true);
  const app = info.apps?.[cfg.app];
  const build = readBuild(app?.appinfo, cfg);
  const d = decide(state, build, { fireOnStart: cfg.fireOnStart && !state.manifest });
  if (d.action === 'none') return;
  if (d.action === 'remember') {
    log(`watching ${cfg.branch} build ${build.buildid} manifest ${build.manifest} (${d.reason})`);
    state = { ...state, ...build, changenumber };
    saveState(state);
    return;
  }
  log(`NEW BUILD ${build.buildid} manifest ${build.manifest} (${d.reason}; ${why}) -> repository_dispatch ${cfg.repo}`);
  if (await dispatch(build)) {
    state = { ...state, ...build, changenumber, dispatchedAt: new Date().toISOString() };
    saveState(state);
    log('dispatched');
  } else {
    // Leave state alone: the next poll sees the same difference and tries again.
    log('dispatch did not go through; will retry on the next poll');
  }
}

async function poll(client) {
  if (busy) return;
  busy = true;
  try {
    const ch = await client.getProductChanges(changenumber);
    const touched = ch.appChanges?.some((a) => a.appid === cfg.app);
    // A gap too large for Steam to list comes back as an empty list with a newer number; read
    // the app directly then, so nothing is missed after a long disconnect.
    const gap = changenumber && ch.currentChangeNumber - changenumber > 5000;
    changenumber = ch.currentChangeNumber;
    lastPollOk = Date.now();
    if (touched || gap) await check(client, touched ? `changelist ${changenumber}` : 'changelist gap');
  } catch (e) {
    log('poll failed:', e.message);
  } finally {
    busy = false;
  }
}

const client = new SteamUser({ enablePicsCache: false, webCompatibilityMode: true, autoRelogin: true });
let timer = null;

client.on('loggedOn', async () => {
  log('logged on to Steam anonymously');
  try {
    if (!changenumber) changenumber = (await client.getProductChanges(0)).currentChangeNumber;
    await check(client, 'startup');
  } catch (e) {
    log('startup check failed:', e.message);
  }
  if (!timer) {
    timer = setInterval(() => poll(client), cfg.pollMs);
    setInterval(() => log(`alive: changelist ${changenumber}, watching build ${state.buildid} manifest ${state.manifest}`), 30 * 60 * 1000);
  }
});
client.on('disconnected', (eresult, msg) => log(`disconnected from Steam (${msg ?? eresult}); steam-user reconnects`));
client.on('error', (e) => {
  // Fatal for this session; let the container's restart policy bring it back.
  log('steam error:', e.message);
  process.exit(1);
});

if (cfg.healthPort) {
  http
    .createServer((req, res) => {
      const ok = Date.now() - lastPollOk < Math.max(120000, cfg.pollMs * 10);
      res.writeHead(ok ? 200 : 503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok, lastPollOk, changenumber, ...state }));
    })
    .listen(cfg.healthPort);
}

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    log(`${sig}: logging off`);
    client.logOff();
    setTimeout(() => process.exit(0), 500);
  });
}

log(`cs2-steam-watch: app ${cfg.app} depot ${cfg.depot} branch ${cfg.branch} -> ${cfg.repo} (${cfg.eventType}), poll ${cfg.pollMs} ms${cfg.dryRun ? ', DRY_RUN' : ''}`);
client.logOn({ anonymous: true });
