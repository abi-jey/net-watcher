const test = require('node:test');
const assert = require('node:assert/strict');
const topology = require('../internal/web/static/pages/map/topology.js');

test('layout retains dragged nodes, removes stale ones and positions new nodes', () => {
    const nodes = [{ ID: 'pod', Kind: 'pod' }, { ID: 'dns', Kind: 'dns' }, { ID: 'remote', Kind: 'ip' }];
    const links = [{ Source: 'pod', Target: 'remote', Kind: 'connection' }];
    const positions = topology.layout(nodes, links, { pod: { x: -100, y: 100 }, stale: { x: 0, y: 0 } });
    assert.deepEqual(positions.pod, { x: -100, y: 100 });
    assert.equal(positions.stale, undefined);
    assert.ok(positions.dns.x < positions.remote.x);
    const fitted = topology.fit(positions, 700, 450);
    for (const p of Object.values(positions)) {
        assert.ok(fitted.x + p.x * fitted.scale >= 0);
        assert.ok(fitted.x + (p.x + 250) * fitted.scale <= 700);
    }
});

test('missing DNS evidence is not labeled literal-IP access', () => {
    assert.equal(topology.evidenceLabel({ EvidenceIDs: [] }), 'No matched DNS evidence');
    assert.equal(topology.evidenceLabel({ EvidenceIDs: [1] }), 'Matched DNS query + response');
});
