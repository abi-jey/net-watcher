// The processes an event records at its two ends (tested with node --test).
//
// A collector looks up the socket of every end on its node. An event stores
// one process at ProcessSide and, when both ends were on the node, the other
// end's as PeerProcess*: the kubelet opening a health check and the pod's
// server accepting it.

import type { NetworkEvent } from './api.ts';
import type { Term } from './filter.ts';

export interface EndProcess {
  command: string;
  /** Host PID; 0 when only the socket's owner identified it. */
  pid: number;
  /** namespace/name, empty for a process outside any pod. */
  pod: string;
  container: string;
}

export interface EndProcesses { src?: EndProcess; dst?: EndProcess }

/** The process recorded at each end, if any. */
export function endProcesses(event: NetworkEvent): EndProcesses {
  if (event.ProcessSide !== 'src' && event.ProcessSide !== 'dst') return {};
  const recorded: EndProcess = { command: event.ProcessCommand, pid: event.ProcessPID, pod: event.ProcessPod, container: event.ProcessContainer };
  const peer: EndProcess | undefined = event.PeerProcessCommand
    ? { command: event.PeerProcessCommand, pid: event.PeerProcessPID ?? 0, pod: event.PeerProcessPod ?? '', container: event.PeerProcessContainer ?? '' }
    : undefined;
  return event.ProcessSide === 'src' ? { src: recorded, dst: peer } : { src: peer, dst: recorded };
}

/** Health checks: connections matched to a pod's probes (isHealthCheck as a filter). */
export const healthChecks: Term = { kind: 'compare', field: 'probe', op: '!=', values: ['none'] };

/**
 * Whether this is a kubelet health check: a TCP connection from a pod's node
 * to a port the pod's liveness, readiness or startup probe targets. The
 * collector matches it from the pod's spec and drops the match when another
 * process was seen opening the connection.
 */
export function isHealthCheck(event: NetworkEvent): boolean {
  return !!event.Probe;
}

/** Command names the kubelet runs under, as the collector knows them. */
const kubeletCommands = new Set(['kubelet', 'kubelite', 'k3s-server', 'k3s-agent']);

export interface ProbeMatch { container: string; kinds: string[] }

/** "a:liveness,readiness; b:startup" → the probes of each container. */
export function probeMatches(probe: string | undefined): ProbeMatch[] {
  if (!probe) return [];
  return probe.split(';').map(part => part.trim()).filter(Boolean).map(part => {
    const colon = part.indexOf(':');
    const kinds = (colon < 0 ? part : part.slice(colon + 1)).split(',').filter(Boolean);
    return { container: colon < 0 ? '' : part.slice(0, colon), kinds };
  });
}

/** "liveness and readiness probes of keda-operator", for display. */
export function describeProbe(probe: string | undefined): string {
  return probeMatches(probe).map(({ container, kinds }) =>
    `${words(kinds)} probe${kinds.length > 1 ? 's' : ''}${container ? ` of ${container}` : ''}`).join('; ');
}

/** How the health check was recognised: the kubelet seen, or matched from the probes alone. */
export function healthCheckEvidence(event: NetworkEvent): string {
  return kubeletCommands.has(endProcesses(event).src?.command ?? '')
    ? 'The kubelet was seen opening it.'
    : 'Matched from the pod\'s probes: the process that opened it was not identified (the kubelet\'s connections usually close before their socket can be looked up).';
}

function words(list: string[]): string {
  return list.length < 2 ? list.join('') : `${list.slice(0, -1).join(', ')} and ${list[list.length - 1]}`;
}

/** "namespace/name" → { namespace, name }. */
export function splitPod(pod: string): { namespace: string; name: string } {
  const slash = pod.indexOf('/');
  return slash < 0 ? { namespace: '', name: pod } : { namespace: pod.slice(0, slash), name: pod.slice(slash + 1) };
}
