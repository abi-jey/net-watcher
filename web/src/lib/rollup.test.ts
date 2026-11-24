import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { PodSummary, ProcessSummary } from './api.ts';
import { rollupPods, rollupProcesses, splitWorkload } from './rollup.ts';

const pod = (namespace: string, name: string, workload: string, egressBytes: number, lastSeen: string): PodSummary => ({
  namespace, name, uid: `uid-${name}`, workload, firstSeen: '2026-11-24T00:00:00Z', lastSeen,
  egress: 1, ingress: 2, egressBytes, ingressBytes: 0, uncertain: name.endsWith('x') ? 1 : 0, replacement: false,
});

test('pods roll up to one row per workload, busiest first', () => {
  const namespaces = rollupPods([
    pod('nw', 'ingest-a', 'Deployment/ingest', 10, '2026-11-24T01:00:00Z'),
    pod('nw', 'ingest-b', 'Deployment/ingest', 20, '2026-11-24T03:00:00Z'),
    pod('nw', 'ingest-x', 'Deployment/ingest', 5, '2026-11-24T02:00:00Z'),
    pod('nw', 'probe', '', 100, '2026-11-24T01:00:00Z'),
    pod('base', 'api-1', 'Deployment/api', 1, '2026-11-24T01:00:00Z'),
  ]);
  assert.deepEqual([...namespaces.keys()], ['base', 'nw']);
  const [probe, ingest] = namespaces.get('nw')!;
  assert.equal(probe.workload, '', 'a pod without an owner keeps its own row');
  assert.equal(probe.pods[0].name, 'probe');
  assert.deepEqual(ingest.pods.map(item => item.name), ['ingest-b', 'ingest-x', 'ingest-a'], 'newest pod first');
  assert.deepEqual([ingest.egress, ingest.ingress, ingest.egressBytes, ingest.uncertain], [3, 6, 35, 1]);
  assert.equal(ingest.lastSeen, '2026-11-24T03:00:00Z');
});

const process = (collector: string, pod: string, command: string, opened: number, lastSeen: string): ProcessSummary => ({
  collector, pod, namespace: pod.split('/')[0] ?? '', container: pod ? 'main' : '', command,
  opened, accepted: 0, openedBytes: opened * 10, acceptedBytes: 0, events: opened, firstSeen: '2026-11-24T00:00:00Z', lastSeen,
});

test('processes keep one row across pod restarts', () => {
  const workloads = new Map([['nw/ingest-a', 'Deployment/ingest'], ['nw/ingest-b', 'Deployment/ingest']]);
  const rows = rollupProcesses([
    process('desktop', 'nw/ingest-a', 'net-watcher', 5, '2026-11-24T01:00:00Z'),
    process('desktop', 'nw/ingest-b', 'net-watcher', 7, '2026-11-24T02:00:00Z'),
    process('abja', 'nw/ingest-c', 'net-watcher', 1, '2026-11-24T02:00:00Z'),
    process('desktop', '', 'tailscaled', 3, '2026-11-24T02:00:00Z'),
  ], workloads);
  assert.equal(rows.length, 3);
  assert.deepEqual(rows[0], {
    key: 'desktop|nw/Deployment/ingest|main|net-watcher', collector: 'desktop', namespace: 'nw', container: 'main', command: 'net-watcher',
    workload: 'Deployment/ingest', pods: ['nw/ingest-b', 'nw/ingest-a'], opened: 12, accepted: 0, openedBytes: 120, acceptedBytes: 0,
    firstSeen: '2026-11-24T00:00:00Z', lastSeen: '2026-11-24T02:00:00Z',
  });
  assert.equal(rows.find(row => row.collector === 'abja')!.workload, '', 'an unknown pod keeps its own row');
  assert.deepEqual(rows.find(row => row.command === 'tailscaled')!.pods, [], 'host process');
});

test('splitWorkload', () => {
  assert.deepEqual(splitWorkload('Deployment/api'), { kind: 'Deployment', name: 'api' });
  assert.deepEqual(splitWorkload('api'), { kind: '', name: 'api' });
});
