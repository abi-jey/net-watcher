import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evidenceLabel, fit, layout, nodeWidth, short } from './topology.ts';

test('layout retains dragged nodes, removes stale ones and positions new nodes', () => {
  const nodes = [{ ID: 'pod', Kind: 'pod' }, { ID: 'dns', Kind: 'dns' }, { ID: 'remote', Kind: 'ip' }];
  const links = [{ Source: 'pod', Target: 'remote', Kind: 'connection' }];
  const positions = layout(nodes, links, { pod: { x: -100, y: 100 }, stale: { x: 0, y: 0 } });
  assert.deepEqual(positions.pod, { x: -100, y: 100 });
  assert.equal(positions.stale, undefined);
  assert.ok(positions.dns.x < positions.remote.x);
  const fitted = fit(positions, 700, 450);
  for (const p of Object.values(positions)) {
    assert.ok(fitted.x + p.x * fitted.scale >= 0);
    assert.ok(fitted.x + (p.x + nodeWidth) * fitted.scale <= 700);
  }
});

test('missing DNS evidence is not labeled literal-IP access', () => {
  assert.equal(evidenceLabel({ EvidenceIDs: [] }), 'No matched DNS evidence');
  assert.equal(evidenceLabel({ EvidenceIDs: null }), 'No matched DNS evidence');
  assert.equal(evidenceLabel({ EvidenceIDs: [1] }), 'Matched DNS query + response');
});

test('short truncates long labels', () => {
  assert.equal(short('a'.repeat(40)).length, 31);
  assert.equal(short('short'), 'short');
});
