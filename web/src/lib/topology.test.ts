import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { MapLink, MapNode } from './api.ts';
import { format, parse } from './filter.ts';
import { evidenceLabel, flowFilter, flowWidth, groupFilter, groupMap, layoutFlows, short } from './topology.ts';

const context = (kind = '', namespace = '', name = '', owner: [string, string] = ['', '']) =>
  ({ Kind: kind, Namespace: namespace, Name: name, UID: '', Node: '', Owner: { Kind: owner[0], Name: owner[1], UID: '' }, ObservedAt: '' });
const node = (id: string, kind: string, ip: string, ctx = context()): MapNode =>
  ({ ID: id, Label: ctx.Name || ip, IP: ip, Kind: kind, Scope: '', Ownership: '', OwnershipSource: '', Context: ctx });
const link = (source: string, target: string, events: number, bytes = 0): MapLink =>
  ({ ID: `${source}>${target}`, Source: source, Target: target, Kind: 'connection', Protocol: 'TCP', Interface: 'eth0', CollectorID: 'a', Port: 443, Events: events, Bytes: bytes, FirstSeen: '', LastSeen: '', EvidenceIDs: null, SNI: null });

const nodes = [
  node('p1', 'pod', '10.0.0.1', context('pod', 'base', 'api-1', ['Deployment', 'api'])),
  node('p2', 'pod', '10.0.0.2', context('pod', 'base', 'api-2', ['Deployment', 'api'])),
  node('p3', 'pod', '10.0.0.3', context('pod', 'base', 'job-x')),
  node('n1', 'node', '192.168.1.5', context('node', '', 'abja')),
  node('n2', 'node', '100.64.0.5', context('node', '', 'abja')),
  node('i1', 'ip', '8.8.8.8'),
  node('i2', 'ip', '1.1.1.1'),
  node('t1', 'ip', '100.101.1.2'),
];
const links = [link('p1', 'i1', 3, 100), link('p2', 'i2', 2, 50), link('p3', 'n1', 1), link('n2', 't1', 4), link('i1', 'n1', 5)];

test('groups pods by workload, a node by name and addresses by network', () => {
  const { groups, flows } = groupMap(nodes, links);
  assert.deepEqual([...groups.keys()].sort(), ['network:public', 'network:tailscale', 'node:abja', 'pod:base/job-x', 'workload:base/Deployment/api']);
  assert.equal(groups.get('workload:base/Deployment/api')!.detail, 'base · Deployment · 2 pods');
  assert.equal(groups.get('node:abja')!.detail, 'node · 2 addresses');
  assert.equal(groups.get('network:public')!.label, 'Internet');
  const api = flows.find(flow => flow.id === 'workload:base/Deployment/api>network:public')!;
  assert.deepEqual([api.events, api.bytes, api.links.length], [5, 150, 2], 'both pods to both addresses become one flow');
  assert.equal(flows.length, 4);
});

test('a flow and a group link to exactly their events', () => {
  const many = Array.from({ length: 101 }, (_, i) => node(`x${i}`, 'ip', `9.9.${i >> 8}.${i & 255}`));
  const crowded = groupMap([...nodes, ...many], [...links, ...many.map(item => link('p1', item.ID, 1))]);
  assert.equal(groupFilter(crowded.groups.get('network:public')!), null, 'too many addresses to list');
  assert.equal(flowFilter(crowded.flows.find(flow => flow.target === 'network:public')!, crowded.groups), null);
  const { groups } = groupMap(nodes, links);
  const { flows } = groupMap(nodes, links);
  const api = flows.find(flow => flow.id === 'workload:base/Deployment/api>network:public')!;
  assert.equal(format(flowFilter(api, groups)), 'src.ns = base and src.workload = Deployment/api and dst.ip = (1.1.1.1, 8.8.8.8)');
  const inbound = flows.find(flow => flow.id === 'network:public>node:abja')!;
  assert.equal(format(flowFilter(inbound, groups)), 'src.ip = 8.8.8.8 and dst.kind = node and dst.name = abja', 'a network end lists only the flow\'s addresses');
  const either = format(groupFilter(groups.get('node:abja')!));
  assert.equal(either, 'src.kind = node and src.name = abja or dst.kind = node and dst.name = abja');
  assert.equal(format(parse(either)), either, 'the filter reads back');
});

test('sources are laid out left and destinations right, without overlap', () => {
  const { groups, flows } = groupMap(nodes, links);
  const layout = layoutFlows(groups, flows, 1000);
  const left = layout.boxes.filter(box => box.side === 'source'), right = layout.boxes.filter(box => box.side === 'target');
  assert.ok(left.every(box => box.x === 0) && right.every(box => box.x === 1000 - layout.boxWidth));
  assert.deepEqual(left.map(box => box.group.label), ['api', 'job-x', 'abja', 'Internet'], 'pods, then nodes, then networks');
  for (const column of [left, right]) {
    for (let i = 1; i < column.length; i++) assert.ok(column[i].y >= column[i - 1].y + layout.boxHeight, 'boxes do not overlap');
  }
  assert.ok(layout.height >= Math.max(...layout.boxes.map(box => box.y + layout.boxHeight)));
});

test('flow widths grow with events and stay within bounds', () => {
  assert.equal(flowWidth(1, 1), 1.5);
  assert.ok(flowWidth(10, 1000) < flowWidth(100, 1000));
  assert.equal(flowWidth(1000, 1000), 8);
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
