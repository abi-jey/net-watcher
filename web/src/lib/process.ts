// The processes an event records at its two ends (tested with node --test).
//
// A collector looks up the socket of every end on its node. An event stores
// one process at ProcessSide and, when both ends were on the node, the other
// end's as PeerProcess*: the kubelet opening a health check and the pod's
// server accepting it.

import type { NetworkEvent } from './api.ts';
import { allOf, is, type Term } from './filter.ts';

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

/** Kubelet health checks: connections the kubelet opened to a pod (isHealthCheck as a filter). */
export const healthChecks: Term = allOf([is('src.process', 'kubelet'), is('dst.kind', 'pod')])!;

/**
 * Whether the kubelet opened this connection to a pod: a liveness, readiness
 * or startup probe (or, rarely, a lifecycle hook) of a pod on its node.
 */
export function isHealthCheck(event: NetworkEvent): boolean {
  return endProcesses(event).src?.command === 'kubelet' && event.DstKind === 'pod';
}

/** "namespace/name" → { namespace, name }. */
export function splitPod(pod: string): { namespace: string; name: string } {
  const slash = pod.indexOf('/');
  return slash < 0 ? { namespace: '', name: pod } : { namespace: pod.slice(0, slash), name: pod.slice(slash + 1) };
}
