// The network map as flows between groups (tested with node --test).
//
// The API returns one node per address, which at cluster scale means hundreds
// of boxes, most of them single internet addresses. The map groups them by
// what a reader recognizes: a workload's pods, a node's addresses, a Service,
// or a network (internet, LAN, tailnet), and draws who opened connections
// (left) to whom (right).

import type { MapLink, MapNode } from './api.ts';
import { ipScope, type Scope } from './network.ts';
import { anyOf, allOf, is, type Compare, type Term } from './filter.ts';

export type GroupKind = 'workload' | 'pod' | 'service' | 'node' | 'network' | 'dns';

export interface Group {
  id: string;
  kind: GroupKind;
  label: string;
  /** Second line: namespace and kind, or how many addresses. */
  detail: string;
  namespace: string;
  scope: Scope | 'cluster';
  members: MapNode[];
  /** Conditions selecting this group's end of a connection, without src./dst. */
  conditions: Compare[];
}

export interface Flow {
  id: string;
  source: string;
  target: string;
  links: MapLink[];
  events: number;
  bytes: number;
  /** Addresses seen at each end of this flow. */
  sourceAddresses: Set<string>;
  targetAddresses: Set<string>;
}

const networkNames: Partial<Record<Scope, string>> = {
  public: 'Internet', private: 'Private network', tailscale: 'Tailnet', 'link-local': 'Link-local', multicast: 'Multicast', loopback: 'Loopback',
};

/** Addresses are listed in a group's filter up to this many. */
export const maxListedAddresses = 100;

function groupFor(node: MapNode): Omit<Group, 'members' | 'detail'> & { detail?: string } {
  const context = node.Context;
  const namespace = context?.Namespace ?? '';
  const name = context?.Name || node.Label;
  if (node.Kind === 'pod') {
    const owner = context?.Owner?.Kind && context.Owner.Name ? `${context.Owner.Kind}/${context.Owner.Name}` : '';
    return owner
      ? { id: `workload:${namespace}/${owner}`, kind: 'workload', label: context!.Owner.Name, namespace, scope: 'cluster', conditions: [is('ns', namespace), is('workload', owner)] }
      : { id: `pod:${namespace}/${name}`, kind: 'pod', label: name, namespace, scope: 'cluster', conditions: [is('ns', namespace), is('name', name)] };
  }
  if (node.Kind === 'service') return { id: `service:${namespace}/${name}`, kind: 'service', label: name, namespace, scope: 'cluster', conditions: [is('kind', 'service'), is('ns', namespace), is('name', name)] };
  if (node.Kind === 'node') return { id: `node:${name}`, kind: 'node', label: name, namespace: '', scope: 'cluster', conditions: [is('kind', 'node'), is('name', name)] };
  if (node.Kind === 'dns') return { id: `dns:${node.Label}`, kind: 'dns', label: node.Label, namespace: '', scope: 'unknown', detail: 'DNS name', conditions: [is('domain', node.Label)] };
  const scope = ipScope(node.IP);
  return { id: `network:${scope}`, kind: 'network', label: networkNames[scope] ?? 'Other addresses', namespace: '', scope, conditions: [] };
}

const kindOrder: Record<GroupKind, number> = { workload: 0, pod: 0, service: 1, node: 2, network: 3, dns: 4 };

const plural = (n: number, one: string, many: string) => `${n.toLocaleString()} ${n === 1 ? one : many}`;

/** Groups the map's nodes and sums its connection links into flows between groups. */
export function groupMap(nodes: MapNode[], links: MapLink[]): { groups: Map<string, Group>; groupOf: Map<string, string>; flows: Flow[] } {
  const groups = new Map<string, Group>();
  const groupOf = new Map<string, string>();
  const address = new Map(nodes.map(node => [node.ID, node.IP]));
  for (const node of nodes) {
    const base = groupFor(node);
    let group = groups.get(base.id);
    if (!group) {
      group = { ...base, detail: base.detail ?? '', members: [] };
      groups.set(base.id, group);
    }
    group.members.push(node);
    groupOf.set(node.ID, base.id);
  }
  for (const group of groups.values()) {
    const addresses = [...new Set(group.members.map(member => member.IP).filter(Boolean))].sort();
    if (group.kind === 'workload') group.detail = `${group.namespace} · ${group.id.split('/').at(-2)} · ${plural(new Set(group.members.map(m => m.Context?.Name)).size, 'pod', 'pods')}`;
    else if (group.kind === 'pod' || group.kind === 'service') group.detail = `${group.namespace} · ${group.kind}`;
    else if (group.kind === 'node') group.detail = `node · ${plural(addresses.length, 'address', 'addresses')}`;
    else if (group.kind === 'network') {
      group.detail = plural(addresses.length, 'address', 'addresses');
      // The listed addresses select exactly this group's ends in the sample.
      group.conditions = addresses.length && addresses.length <= maxListedAddresses ? [is('ip', ...addresses)] : [];
    }
  }
  const flows = new Map<string, Flow>();
  for (const link of links) {
    if (link.Kind !== 'connection') continue;
    const source = groupOf.get(link.Source), target = groupOf.get(link.Target);
    if (!source || !target) continue;
    const id = `${source}>${target}`;
    let flow = flows.get(id);
    if (!flow) {
      flow = { id, source, target, links: [], events: 0, bytes: 0, sourceAddresses: new Set(), targetAddresses: new Set() };
      flows.set(id, flow);
    }
    flow.links.push(link);
    const from = address.get(link.Source), to = address.get(link.Target);
    if (from) flow.sourceAddresses.add(from);
    if (to) flow.targetAddresses.add(to);
    flow.events += link.Events;
    flow.bytes += link.Bytes;
  }
  return { groups, groupOf, flows: [...flows.values()] };
}

export interface Box { key: string; group: Group; side: 'source' | 'target'; x: number; y: number; events: number }

export interface FlowLayout {
  width: number;
  height: number;
  boxWidth: number;
  boxHeight: number;
  /** Group boxes; a group that both opens and receives connections appears on both sides. */
  boxes: Box[];
  headings: { side: 'source' | 'target'; y: number; text: string }[];
}

const sectionNames: Record<GroupKind, string> = { workload: 'Pods', pod: 'Pods', service: 'Services', node: 'Nodes', network: 'Other addresses', dns: 'DNS names' };

/**
 * Lays groups out in two columns, sources left and destinations right, in
 * sections (pods by namespace, Services, nodes, other addresses), busiest
 * first within a namespace.
 */
export function layoutFlows(groups: Map<string, Group>, flows: Flow[], width = 1000): FlowLayout {
  const boxWidth = 300, boxHeight = 40, gap = 6, sectionGap = 22, top = 30;
  const out = new Map<string, number>(), into = new Map<string, number>();
  for (const flow of flows) {
    out.set(flow.source, (out.get(flow.source) ?? 0) + flow.events);
    into.set(flow.target, (into.get(flow.target) ?? 0) + flow.events);
  }
  const boxes: Box[] = [];
  const headings: FlowLayout['headings'] = [];
  let height = 0;
  for (const side of ['source', 'target'] as const) {
    const traffic = side === 'source' ? out : into;
    const column = [...traffic.keys()].map(id => groups.get(id)).filter((group): group is Group => Boolean(group))
      .sort((a, b) => kindOrder[a.kind] - kindOrder[b.kind] || a.namespace.localeCompare(b.namespace) || (traffic.get(b.id) ?? 0) - (traffic.get(a.id) ?? 0) || a.label.localeCompare(b.label));
    let y = top, section = '';
    for (const group of column) {
      const name = sectionNames[group.kind];
      if (name !== section) {
        if (section) y += sectionGap;
        headings.push({ side, y, text: name });
        y += 12;
        section = name;
      }
      boxes.push({ key: `${side}:${group.id}`, group, side, x: side === 'source' ? 0 : width - boxWidth, y, events: traffic.get(group.id) ?? 0 });
      y += boxHeight + gap;
    }
    height = Math.max(height, y + 8);
  }
  return { width, height: Math.max(height, 120), boxWidth, boxHeight, boxes, headings };
}

/** Stroke width for a flow: 1.5 to 8 by the logarithm of its events. */
export function flowWidth(events: number, most: number): number {
  if (most <= 1) return 1.5;
  return 1.5 + 6.5 * Math.log(1 + events) / Math.log(1 + most);
}

function sided(conditions: Compare[], side: 'src' | 'dst'): Compare[] {
  return conditions.map(condition => ({ ...condition, field: `${side}.${condition.field}` }));
}

/**
 * The events filter for a flow, its source group to its destination group.
 * A network end lists the flow's own addresses; null when there are too many.
 */
export function flowFilter(flow: Flow, groups: Map<string, Group>): Term | null {
  const end = (id: string, addresses: Set<string>): Compare[] | null => {
    const group = groups.get(id);
    if (!group) return null;
    if (group.kind !== 'network') return group.conditions;
    return addresses.size && addresses.size <= maxListedAddresses ? [is('ip', ...[...addresses].sort())] : null;
  };
  const source = end(flow.source, flow.sourceAddresses), target = end(flow.target, flow.targetAddresses);
  if (!source || !target) return null;
  return allOf([...sided(source, 'src'), ...sided(target, 'dst')]);
}

/** The events filter for a group at either end; null when it cannot be listed. */
export function groupFilter(group: Group): Term | null {
  if (!group.conditions.length) return null;
  return anyOf([allOf(sided(group.conditions, 'src'))!, allOf(sided(group.conditions, 'dst'))!]);
}

export function evidenceLabel(link: { EvidenceIDs: number[] | null }): string {
  return link.EvidenceIDs?.length ? 'Matched DNS query + response' : 'No matched DNS evidence';
}

export function short(text: string, length = 31): string {
  return text.length > length ? `${text.slice(0, length - 1)}…` : text;
}
