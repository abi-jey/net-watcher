import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { NetworkEvent } from './api.ts';
import { format, negate } from './filter.ts';
import { describeProbe, endProcesses, healthCheckEvidence, healthChecks, isHealthCheck, isKernel, probeMatches, splitPod } from './process.ts';

const event = (fields: Partial<NetworkEvent>): NetworkEvent => ({ ProcessSide: '', ProcessCommand: '', ProcessPID: 0, ProcessPod: '', ProcessContainer: '', DstKind: '', ...fields }) as NetworkEvent;

test('each end has its own process', () => {
  const check = event({ ProcessSide: 'src', ProcessCommand: 'kubelet', ProcessPID: 900, DstKind: 'pod',
    PeerProcessCommand: 'keda', PeerProcessPID: 4100, PeerProcessPod: 'keda/keda-operator-1', PeerProcessContainer: 'keda-operator' });
  assert.deepEqual(endProcesses(check), {
    src: { command: 'kubelet', pid: 900, pod: '', container: '' },
    dst: { command: 'keda', pid: 4100, pod: 'keda/keda-operator-1', container: 'keda-operator' },
  });

  // Only the accepting process known: nothing at the source.
  const accepted = event({ ProcessSide: 'dst', ProcessCommand: 'python', ProcessPod: 'base/base-server-1', ProcessContainer: 'base-server', DstKind: 'pod' });
  assert.deepEqual(endProcesses(accepted), { src: undefined, dst: { command: 'python', pid: 0, pod: 'base/base-server-1', container: 'base-server' } });
  assert.deepEqual(endProcesses(event({})), {});
});

test('health checks are probe matches', () => {
  const seen = event({ ProcessSide: 'src', ProcessCommand: 'kubelet', DstKind: 'pod', Probe: 'keda-operator:liveness,readiness' });
  const matched = event({ ProcessSide: 'dst', ProcessCommand: 'keda', DstKind: 'pod', Probe: 'keda-operator:liveness,readiness' });
  assert.equal(isHealthCheck(seen), true);
  assert.equal(isHealthCheck(matched), true);
  assert.match(healthCheckEvidence(seen), /kubelet was seen/);
  assert.match(healthCheckEvidence(matched), /^Matched from the pod's probes/);
  // The kubelet reaching a port no probe targets is not counted.
  assert.equal(isHealthCheck(event({ ProcessSide: 'src', ProcessCommand: 'kubelet', DstKind: 'pod' })), false);
  assert.equal(format(healthChecks), 'probe != none');
  assert.equal(format(negate(healthChecks)), 'probe = none');
});

test('probe descriptions', () => {
  assert.deepEqual(probeMatches('keda-operator:liveness,readiness; native-sidecar:readiness'), [
    { container: 'keda-operator', kinds: ['liveness', 'readiness'] }, { container: 'native-sidecar', kinds: ['readiness'] }]);
  assert.equal(describeProbe('keda-operator:liveness,readiness; sidecar:startup'), 'liveness and readiness probes of keda-operator; startup probe of sidecar');
  assert.equal(describeProbe('api:liveness,readiness,startup'), 'liveness, readiness and startup probes of api');
  assert.equal(describeProbe(''), '');
});

test('splitPod', () => {
  assert.deepEqual(splitPod('cloudflared/cloudflared-nrm9h'), { namespace: 'cloudflared', name: 'cloudflared-nrm9h' });
  assert.deepEqual(splitPod('lonely'), { namespace: '', name: 'lonely' });
});

test('kernel tunnel ends', () => {
  const tunnel = event({ ProcessSide: 'dst', ProcessCommand: 'kernel', ProcessPID: 0 });
  assert.equal(isKernel(endProcesses(tunnel).dst), true);
  // A process that happens to be called kernel has a PID or a pod.
  assert.equal(isKernel({ command: 'kernel', pid: 42, pod: '', container: '' }), false);
  assert.equal(isKernel(undefined), false);
});
