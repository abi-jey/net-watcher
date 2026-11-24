// Rolls pod and process summaries up to their workload (tested with node --test).
//
// Each rollout or restart creates new pods, so per-pod rows pile up: a
// Deployment updated twenty times in a day lists twenty pods. Rows here are
// one per workload; the pods stay available for drill-down.

import type { PodSummary, ProcessSummary } from './api.ts';

interface Traffic { firstSeen: string; lastSeen: string }

function span<T extends Traffic>(items: T[]): Traffic {
  const first = items.map(item => item.firstSeen).filter(Boolean).sort()[0] ?? '';
  const last = items.map(item => item.lastSeen).filter(Boolean).sort().at(-1) ?? '';
  return { firstSeen: first, lastSeen: last };
}

/** "Deployment/api" → { kind: "Deployment", name: "api" }. */
export function splitWorkload(workload: string): { kind: string; name: string } {
  const slash = workload.indexOf('/');
  return slash < 0 ? { kind: '', name: workload } : { kind: workload.slice(0, slash), name: workload.slice(slash + 1) };
}

export interface WorkloadRow extends Traffic {
  key: string;
  namespace: string;
  /** Kind/name, or empty for a pod without an owner. */
  workload: string;
  pods: PodSummary[];
  egress: number; ingress: number; egressBytes: number; ingressBytes: number; uncertain: number;
}

/** One row per workload in each namespace, busiest first; pods newest first. */
export function rollupPods(pods: PodSummary[]): Map<string, WorkloadRow[]> {
  const rows = new Map<string, WorkloadRow>();
  for (const pod of pods) {
    const key = pod.workload ? `${pod.namespace}/${pod.workload}` : `pod:${pod.uid}`;
    let row = rows.get(key);
    if (!row) {
      row = { key, namespace: pod.namespace, workload: pod.workload, pods: [], egress: 0, ingress: 0, egressBytes: 0, ingressBytes: 0, uncertain: 0, firstSeen: '', lastSeen: '' };
      rows.set(key, row);
    }
    row.pods.push(pod);
    row.egress += pod.egress; row.ingress += pod.ingress;
    row.egressBytes += pod.egressBytes; row.ingressBytes += pod.ingressBytes;
    row.uncertain += pod.uncertain;
  }
  const namespaces = new Map<string, WorkloadRow[]>();
  for (const row of rows.values()) {
    Object.assign(row, span(row.pods));
    row.pods.sort((a, b) => b.lastSeen.localeCompare(a.lastSeen) || a.name.localeCompare(b.name));
    namespaces.set(row.namespace, [...(namespaces.get(row.namespace) ?? []), row]);
  }
  for (const list of namespaces.values()) {
    list.sort((a, b) => (b.egressBytes + b.ingressBytes) - (a.egressBytes + a.ingressBytes) || (b.egress + b.ingress) - (a.egress + a.ingress) || (a.workload || a.pods[0].name).localeCompare(b.workload || b.pods[0].name));
  }
  return new Map([...namespaces.entries()].sort(([a], [b]) => a.localeCompare(b)));
}

export interface ProcessRow extends Traffic {
  key: string;
  collector: string; namespace: string; container: string; command: string;
  /** Kind/name when the pods' workload is known. */
  workload: string;
  /** Pods as namespace/name, newest first; empty for host processes. */
  pods: string[];
  opened: number; accepted: number; openedBytes: number; acceptedBytes: number;
}

/**
 * One row per node, workload (or pod when its workload is unknown),
 * container and command, so a process keeps its row across pod restarts.
 * workloadOf maps namespace/pod to Kind/name.
 */
export function rollupProcesses(processes: ProcessSummary[], workloadOf: Map<string, string>): ProcessRow[] {
  const rows = new Map<string, ProcessRow & { members: ProcessSummary[] }>();
  for (const process of processes) {
    const workload = process.pod ? workloadOf.get(process.pod) ?? '' : '';
    const owner = workload ? `${process.namespace}/${workload}` : process.pod;
    const key = [process.collector, owner, process.container, process.command].join('|');
    let row = rows.get(key);
    if (!row) {
      row = { key, collector: process.collector, namespace: process.namespace, container: process.container, command: process.command, workload, pods: [], opened: 0, accepted: 0, openedBytes: 0, acceptedBytes: 0, firstSeen: '', lastSeen: '', members: [] };
      rows.set(key, row);
    }
    row.members.push(process);
    row.opened += process.opened; row.accepted += process.accepted;
    row.openedBytes += process.openedBytes; row.acceptedBytes += process.acceptedBytes;
  }
  return [...rows.values()].map(({ members, ...row }) => ({
    ...row,
    ...span(members),
    pods: members.filter(member => member.pod).sort((a, b) => b.lastSeen.localeCompare(a.lastSeen)).map(member => member.pod),
  })).sort((a, b) => (b.opened + b.accepted) - (a.opened + a.accepted) || a.command.localeCompare(b.command));
}
