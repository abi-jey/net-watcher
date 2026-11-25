import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { NetworkEvent } from './api.ts';
import { format } from './filter.ts';
import { endProcesses, healthChecks, isHealthCheck, splitPod } from './process.ts';

const event = (fields: Partial<NetworkEvent>): NetworkEvent => ({ ProcessSide: '', ProcessCommand: '', ProcessPID: 0, ProcessPod: '', ProcessContainer: '', DstKind: '', ...fields }) as NetworkEvent;

test('each end has its own process', () => {
  const check = event({ ProcessSide: 'src', ProcessCommand: 'kubelet', ProcessPID: 900, DstKind: 'pod',
    PeerProcessCommand: 'keda', PeerProcessPID: 4100, PeerProcessPod: 'keda/keda-operator-1', PeerProcessContainer: 'keda-operator' });
  assert.deepEqual(endProcesses(check), {
    src: { command: 'kubelet', pid: 900, pod: '', container: '' },
    dst: { command: 'keda', pid: 4100, pod: 'keda/keda-operator-1', container: 'keda-operator' },
  });
  assert.equal(isHealthCheck(check), true);

  // Only the accepting process known: nothing at the source.
  const accepted = event({ ProcessSide: 'dst', ProcessCommand: 'python', ProcessPod: 'base/base-server-1', ProcessContainer: 'base-server', DstKind: 'pod' });
  assert.deepEqual(endProcesses(accepted), { src: undefined, dst: { command: 'python', pid: 0, pod: 'base/base-server-1', container: 'base-server' } });
  assert.equal(isHealthCheck(accepted), false);

  assert.deepEqual(endProcesses(event({})), {});
  // The kubelet reaching a node address is not a pod health check.
  assert.equal(isHealthCheck(event({ ProcessSide: 'src', ProcessCommand: 'kubelet', DstKind: 'node' })), false);
});

test('health checks as a filter', () => {
  assert.equal(format(healthChecks), 'src.process = kubelet and dst.kind = pod');
});

test('splitPod', () => {
  assert.deepEqual(splitPod('cloudflared/cloudflared-nrm9h'), { namespace: 'cloudflared', name: 'cloudflared-nrm9h' });
  assert.deepEqual(splitPod('lonely'), { namespace: '', name: 'lonely' });
});
