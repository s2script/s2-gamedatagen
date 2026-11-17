// Pure pieces of the watcher, kept apart from the Steam connection so they can be unit-tested.

/** Read the watched branch's build and depot manifest out of a PICS appinfo record. */
export function readBuild(appinfo, { depot, branch }) {
  const depots = appinfo?.depots ?? {};
  const b = depots.branches?.[branch];
  const m = depots[String(depot)]?.manifests?.[branch];
  // PICS gives the manifest either as a bare gid string or as { gid, size, download }.
  const manifest = typeof m === 'string' ? m : m?.gid;
  if (!b?.buildid || !manifest) return null;
  return {
    buildid: String(b.buildid),
    manifest: String(manifest),
    timeupdated: b.timeupdated ? Number(b.timeupdated) : null,
  };
}

/**
 * What to do with a freshly read build, given what was last dispatched.
 *   - nothing seen yet: remember it, don't fire (the workflow's own baseline covers the first run)
 *   - same manifest: nothing
 *   - new manifest: fire
 */
export function decide(state, build, { fireOnStart = false } = {}) {
  if (!build) return { action: 'none', reason: 'no build in appinfo' };
  if (!state?.manifest) {
    return fireOnStart
      ? { action: 'fire', reason: 'first run (FIRE_ON_START)' }
      : { action: 'remember', reason: 'first run' };
  }
  if (state.manifest === build.manifest) return { action: 'none', reason: 'unchanged' };
  return { action: 'fire', reason: `manifest ${state.manifest} -> ${build.manifest}` };
}

/** The repository_dispatch body the cs2-update workflow reads. */
export function dispatchBody(eventType, build, changenumber) {
  return {
    event_type: eventType,
    client_payload: {
      buildid: build.buildid,
      manifest: build.manifest,
      timeupdated: build.timeupdated,
      changenumber,
      source: 'steam-watch',
    },
  };
}

export function backoff(attempt, base = 2000, cap = 60000) {
  return Math.min(cap, base * 2 ** attempt);
}

/**
 * Whether the Steam session looks dead and the process should exit so the container's restart
 * policy brings up a fresh one. steam-user keeps a session whose requests all time out (a
 * half-open connection) without ever emitting `disconnected`, so retrying on it never recovers.
 */
export function sessionDead({ failures, lastOkMs, now, maxFailures = 3, staleMs = 60000 }) {
  if (failures >= maxFailures) return true;
  return lastOkMs > 0 && now - lastOkMs > staleMs;
}
