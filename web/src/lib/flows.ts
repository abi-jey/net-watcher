// Records grouped into what happened (tested with node --test).
//
// A process sending to one destination is one action, however many records
// it leaves: a flow's open, progress updates and close; the same flow seen
// by both nodes; a DNS lookup seen by the client's node and the resolver's.
// Those become one flow. Flows one process (or, when it is unknown, one
// address) opens to one destination again and again, such as health checks
// or a resolver asked the same name, become one repeat row that expands.

import type { NetworkEvent } from './api.ts';
import { endProcesses, type EndProcess } from './process.ts';

export interface Flow {
  key: string;
  /** 'lookup' for DNS, 'flow' for TCP and UDP. */
  kind: 'flow' | 'lookup';
  /** Newest first. */
  records: NetworkEvent[];
  /** One record standing for the flow: its ends, both processes, totals. */
  merged: NetworkEvent;
  first: string;
  last: string;
  /** No close (or end) among the records. */
  open: boolean;
  /** Collectors that recorded it. */
  nodes: string[];
  /** Bytes and packets sent by the source (the end that opened it) and by the destination. */
  sent: number; received: number; sentPackets: number; receivedPackets: number;
}

export interface Repeat {
  key: string;
  /** Newest first. */
  flows: Flow[];
  first: string;
  last: string;
  sent: number;
  received: number;
  /** Median time between the flows' starts, in milliseconds; 0 with fewer than three. */
  every: number;
}

export type Row =
  | { kind: 'record'; key: string; last: string; event: NetworkEvent }
  | { kind: 'flow'; key: string; last: string; flow: Flow }
  | { kind: 'repeat'; key: string; last: string; repeat: Repeat };

/** How far apart two nodes' records of one flow may be and still join. */
const sameFlowSlack = 2 * 60_000;

const flowTypes = new Set(['TCP_START', 'TCP_UPDATE', 'TCP_END', 'UDP_START', 'UDP_UPDATE', 'UDP_END', 'TLS_SNI']);

function protocolOf(event: NetworkEvent): 'tcp' | 'udp' | '' {
  if (event.EventType.startsWith('TCP') || event.EventType === 'TLS_SNI' || (event.EventType === 'TIMEOUT' && event.Protocol === 'TCP')) return 'tcp';
  if (event.EventType.startsWith('UDP')) return 'udp';
  return '';
}

const ended = (event: NetworkEvent) => event.EventType.endsWith('_END') || event.EventType === 'TIMEOUT';
const time = (value: string) => new Date(value).getTime();
const end = (ip: string, port: number) => `${ip}|${port}`;

/** The lookup a DNS record belongs to: the same on the client's and the resolver's node. */
function lookupKey(event: NetworkEvent): string {
  const response = event.DNSType === 'RESPONSE';
  const client = response ? end(event.DstIP, event.DstPort) : end(event.SrcIP, event.SrcPort);
  const resolver = response ? end(event.SrcIP, event.SrcPort) : end(event.DstIP, event.DstPort);
  return ['dns', event.Protocol, client, resolver, event.DNSID ?? '', event.DNSQuery, event.DNSQuestionType ?? ''].join('|');
}

/** A flow's addresses and ports in either direction. */
function tupleKey(event: NetworkEvent): string {
  const a = end(event.SrcIP, event.SrcPort), b = end(event.DstIP, event.DstPort);
  return [protocolOf(event), a < b ? a : b, a < b ? b : a].join('|');
}

/** Groups records of one flow: one node's by flow ID, both nodes' by addresses and time. */
function groupFlows(events: NetworkEvent[]): { groups: NetworkEvent[][]; others: NetworkEvent[] } {
  const others: NetworkEvent[] = [];
  const parent = new Map<string, string>();
  const find = (id: string): string => {
    let root = id;
    while (parent.get(root) !== root) root = parent.get(root)!;
    parent.set(id, root);
    return root;
  };
  const join = (a: string, b: string) => { const ra = find(a), rb = find(b); if (ra !== rb) parent.set(rb, ra); };
  const members = new Map<string, NetworkEvent[]>();
  for (const event of events) {
    let id: string;
    if (event.EventType === 'DNS' && event.DNSQuery && event.DNSType) id = lookupKey(event);
    else if (flowTypes.has(event.EventType) || (event.EventType === 'TIMEOUT' && event.Protocol === 'TCP')) {
      id = event.FlowID ? `flow|${event.CollectorID}|${event.FlowID}` : `record|${event.ID}`;
    } else { others.push(event); continue; }
    if (!parent.has(id)) { parent.set(id, id); members.set(id, []); }
    members.get(id)!.push(event);
  }
  // Records of one flow on different nodes, or without a flow ID: the same
  // addresses and ports, at times that overlap.
  const spans = new Map<string, { id: string; from: number; to: number }[]>();
  for (const [id, records] of members) {
    if (id.startsWith('dns|')) continue;
    const times = records.map(record => time(record.Timestamp));
    const tuple = tupleKey(records[0]);
    spans.set(tuple, [...(spans.get(tuple) ?? []), { id, from: Math.min(...times), to: Math.max(...times) }]);
  }
  for (const list of spans.values()) {
    list.sort((a, b) => a.from - b.from);
    for (let i = 0; i < list.length; i++) {
      for (let j = i + 1; j < list.length && list[j].from <= list[i].to + sameFlowSlack; j++) {
        // One node's flow IDs never join each other: each is its own flow.
        const [a, b] = [list[i].id, list[j].id];
        if (a.startsWith('flow|') && b.startsWith('flow|') && a.split('|')[1] === b.split('|')[1]) continue;
        join(a, b);
      }
    }
  }
  const groups = new Map<string, NetworkEvent[]>();
  for (const [id, records] of members) {
    const root = find(id);
    groups.set(root, [...(groups.get(root) ?? []), ...records]);
  }
  return { groups: [...groups.values()], others };
}

/** Whether a record names the flow's ends the other way round from base. */
function reversed(record: NetworkEvent, base: NetworkEvent): boolean {
  return record.SrcIP === base.DstIP && record.SrcPort === base.DstPort && !(record.SrcIP === base.SrcIP && record.SrcPort === base.SrcPort);
}

function sameProcess(a: EndProcess | undefined, b: EndProcess | undefined): boolean {
  return !!a && !!b && a.command === b.command && a.pod === b.pod && a.container === b.container;
}

function toFlow(records: NetworkEvent[]): Flow {
  records.sort((a, b) => b.Timestamp.localeCompare(a.Timestamp) || b.ID - a.ID);
  const lookup = records[0].EventType === 'DNS';
  const chronological = [...records].reverse();
  // The record whose orientation the flow takes: a lookup's response, a flow's open.
  const base = (lookup ? chronological.find(record => record.DNSType === 'RESPONSE') : chronological.find(record => record.EventType.endsWith('_START'))) ?? chronological[0];
  let src: EndProcess | undefined, dst: EndProcess | undefined;
  let sent = 0, received = 0, sentPackets = 0, receivedPackets = 0, duration = 0;
  let probe = '', reason = '';
  for (const record of chronological) {
    const flip = reversed(record, base);
    const processes = endProcesses(record);
    const [atSrc, atDst] = flip ? [processes.dst, processes.src] : [processes.src, processes.dst];
    src ??= atSrc;
    dst ??= atDst;
    const [bySrc, byDst] = flip ? [record.DstBytes ?? 0, record.SrcBytes ?? 0] : [record.SrcBytes ?? 0, record.DstBytes ?? 0];
    const [packetsSrc, packetsDst] = flip ? [record.DstPackets ?? 0, record.SrcPackets ?? 0] : [record.SrcPackets ?? 0, record.DstPackets ?? 0];
    // Totals grow over a flow's records, and both nodes count the same packets.
    sent = Math.max(sent, bySrc); received = Math.max(received, byDst);
    sentPackets = Math.max(sentPackets, packetsSrc); receivedPackets = Math.max(receivedPackets, packetsDst);
    duration = Math.max(duration, record.Duration ?? 0);
    if (record.Probe) probe = record.Probe;
    if (record.Reason) reason = record.Reason;
  }
  const merged: NetworkEvent = { ...base, SrcBytes: sent, DstBytes: received, SrcPackets: sentPackets, DstPackets: receivedPackets, Duration: duration, Reason: reason };
  // Records from before flows were counted by direction carry only a total,
  // at their end; both nodes' count the same packets.
  merged.ByteCount = sent || received ? sent + received : Math.max(...records.map(record => record.ByteCount ?? 0));
  merged.ProcessSide = ''; merged.ProcessPID = 0; merged.ProcessCommand = ''; merged.ProcessPod = ''; merged.ProcessContainer = '';
  merged.PeerProcessPID = undefined; merged.PeerProcessCommand = undefined; merged.PeerProcessPod = undefined; merged.PeerProcessContainer = undefined;
  const primary = src ?? dst;
  if (primary) {
    merged.ProcessSide = src ? 'src' : 'dst';
    merged.ProcessPID = primary.pid; merged.ProcessCommand = primary.command; merged.ProcessPod = primary.pod; merged.ProcessContainer = primary.container;
    if (src && dst && !sameProcess(src, dst)) {
      merged.PeerProcessPID = dst.pid; merged.PeerProcessCommand = dst.command; merged.PeerProcessPod = dst.pod; merged.PeerProcessContainer = dst.container;
    }
  }
  merged.Probe = probe || undefined;
  const nodes = [...new Set(records.map(record => record.CollectorID || 'local'))].sort();
  return {
    key: lookup ? lookupKey(base) : `flow|${records.map(record => `${record.CollectorID}:${record.FlowID || record.ID}`).sort()[0]}`,
    kind: lookup ? 'lookup' : 'flow',
    records, merged,
    first: records[records.length - 1].Timestamp,
    last: records[0].Timestamp,
    open: !lookup && !records.some(ended),
    nodes, sent, received, sentPackets, receivedPackets,
  };
}

/** Who opened a flow: its process when known, else its source's identity. */
function opener(flow: Flow): string {
  const event = flow.merged;
  if (event.ProcessSide === 'src') {
    // A process on one node; the same command on another node is another process.
    const node = flow.records.find(record => record.ProcessCommand === event.ProcessCommand || record.PeerProcessCommand === event.ProcessCommand)?.CollectorID ?? '';
    return `process|${node}|${event.ProcessCommand}|${event.ProcessPod}|${event.ProcessContainer}`;
  }
  if (flow.kind === 'lookup') return event.DstKind === 'pod' ? `pod|${event.DstNamespace}/${event.DstName}` : `ip|${event.DstIP}`;
  return event.SrcKind === 'pod' ? `pod|${event.SrcNamespace}/${event.SrcName}` : `ip|${event.SrcIP}`;
}

/** What a flow reached: a lookup's name, else the destination's address and port. */
function target(flow: Flow): string {
  const event = flow.merged;
  if (flow.kind === 'lookup') return `dns|${event.DNSQuery}`;
  return `${protocolOf(event)}|${event.DstIP}|${event.DstPort}`;
}

function median(values: number[]): number {
  if (values.length < 2) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

/**
 * Rows for records, newest first: each flow once, flows one opener repeats
 * to one destination together, other records as they are.
 */
export function groupRecords(events: NetworkEvent[]): Row[] {
  const { groups, others } = groupFlows(events);
  const rows: Row[] = others.map(event => ({ kind: 'record', key: `record|${event.ID}`, last: event.Timestamp, event }));
  const repeats = new Map<string, Flow[]>();
  for (const flow of groups.map(toFlow)) {
    const key = `${opener(flow)}→${target(flow)}`;
    repeats.set(key, [...(repeats.get(key) ?? []), flow]);
  }
  for (const [key, flows] of repeats) {
    flows.sort((a, b) => b.last.localeCompare(a.last));
    if (flows.length === 1) {
      rows.push({ kind: 'flow', key: flows[0].key, last: flows[0].last, flow: flows[0] });
      continue;
    }
    const starts = flows.map(flow => time(flow.first)).sort((a, b) => a - b);
    const gaps = starts.slice(1).map((start, i) => start - starts[i]);
    rows.push({
      kind: 'repeat', key: `repeat|${key}`, last: flows[0].last,
      repeat: {
        key, flows,
        first: flows.map(flow => flow.first).sort()[0], last: flows[0].last,
        sent: flows.reduce((sum, flow) => sum + flow.sent, 0),
        received: flows.reduce((sum, flow) => sum + flow.received, 0),
        every: flows.length >= 3 ? median(gaps) : 0,
      },
    });
  }
  return rows.sort((a, b) => b.last.localeCompare(a.last) || b.key.localeCompare(a.key));
}
