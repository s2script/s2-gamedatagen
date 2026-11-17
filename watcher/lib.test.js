import test from 'node:test';
import assert from 'node:assert/strict';
import { backoff, decide, dispatchBody, readBuild } from './lib.js';

const cfg = { depot: 2347773, branch: 'public' };
const appinfo = (buildid, gid, asObject = false) => ({
  depots: {
    branches: { public: { buildid, timeupdated: '1762900000' } },
    2347773: { manifests: { public: asObject ? { gid, size: '1' } : gid } },
  },
});

test('reads the build from either manifest shape', () => {
  assert.deepEqual(readBuild(appinfo('26598758', '3634295490837307276'), cfg), {
    buildid: '26598758', manifest: '3634295490837307276', timeupdated: 1762900000,
  });
  assert.equal(readBuild(appinfo('1', '2', true), cfg).manifest, '2');
  assert.equal(readBuild({}, cfg), null);
});

test('first sight is remembered, not fired', () => {
  const b = readBuild(appinfo('1', 'a'), cfg);
  assert.equal(decide({}, b).action, 'remember');
  assert.equal(decide({}, b, { fireOnStart: true }).action, 'fire');
});

test('fires only on a new manifest', () => {
  const b = readBuild(appinfo('2', 'b'), cfg);
  assert.equal(decide({ manifest: 'b' }, b).action, 'none');
  assert.equal(decide({ manifest: 'a' }, b).action, 'fire');
});

test('dispatch body carries what the workflow reads', () => {
  const body = dispatchBody('cs2-update-poll', { buildid: '2', manifest: 'b', timeupdated: 5 }, 9);
  assert.equal(body.event_type, 'cs2-update-poll');
  assert.deepEqual(body.client_payload, { buildid: '2', manifest: 'b', timeupdated: 5, changenumber: 9, source: 'steam-watch' });
});

test('backoff is capped', () => {
  assert.equal(backoff(0), 2000);
  assert.equal(backoff(20), 60000);
});
