import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { NetworkEvent } from './api.ts';
import { groupRecords, type Flow, type Row } from './flows.ts';

let nextID = 1;
const record = (fields: Partial<NetworkEvent>): NetworkEvent => ({
  ID: nextID++, Timestamp: '2026-11-25T08:00:00.000Z', EventType: 'TCP_START', Interface: 'eth0', CollectorID: 'abja',
  SrcIP: '10.0.1.155', SrcPort: 41000, DstIP: '10.0.1.169', DstPort: 8000, Protocol: '', ByteCount: 0, Duration: 0, Reason: '',
  ProcessSide: '', ProcessCommand: '', ProcessPID: 0, ProcessPod: '', ProcessContainer: '',
  SrcKind: '', SrcNamespace: '', SrcName: '', DstKind: '', DstNamespace: '', DstName: '',
  DNSType: '', DNSQuery: '', ...fields,
}) as NetworkEvent;
const at = (seconds: number) => new Date(Date.parse('2026-11-25T08:00:00.000Z') + seconds * 1000).toISOString();

const flowOf = (row: Row): Flow => {
  assert.equal(row.kind, 'flow', `row ${row.key} is a ${row.kind}`);
  return (row as Extract<Row, { kind: 'flow' }>).flow;
};

test('a flow\'s open, updates and close are one row', () => {
  const rows = groupRecords([
    record({ EventType: 'UDP_START', FlowID: 'f1', SrcPort: 40000, DstPort: 4500, SrcBytes: 1000, SrcPackets: 1, ProcessSide: 'src', ProcessCommand: 'rclone' }),
    record({ EventType: 'UDP_UPDATE', FlowID: 'f1', SrcPort: 40000, DstPort: 4500, Timestamp: at(300), SrcBytes: 5 << 20, DstBytes: 2000, ByteCount: (5 << 20) + 1000, ProcessSide: 'src', ProcessCommand: 'rclone' }),
    record({ EventType: 'UDP_END', FlowID: 'f1', SrcPort: 40000, DstPort: 4500, Timestamp: at(420), SrcBytes: 6 << 20, DstBytes: 3000, Duration: 300_000, ByteCount: 1 << 20, ProcessSide: 'src', ProcessCommand: 'rclone' }),
  ]);
  assert.equal(rows.length, 1);
  const flow = flowOf(rows[0]);
  assert.equal(flow.records.length, 3);
  assert.equal(flow.open, false);
  assert.equal(flow.sent, 6 << 20);
  assert.equal(flow.received, 3000);
  assert.equal(flow.merged.ProcessCommand, 'rclone');
  assert.equal(flow.first, at(0));
  assert.equal(flow.last, at(420));
});

test('both nodes\' records of one flow are one row with each node\'s process', () => {
  const rows = groupRecords([
    // abja: the client pod's node, which found the opener.
    record({ EventType: 'TCP_START', FlowID: 'a1', SrcIP: '10.0.1.84', SrcPort: 51000, DstIP: '10.0.0.151', DstPort: 4222, ProcessSide: 'src', ProcessCommand: 'base-server', ProcessPod: 'base/base-server-1' }),
    // desktop: the server pod's node, which found the acceptor; its open came 3 ms later.
    record({ EventType: 'TCP_START', FlowID: 'd7', CollectorID: 'desktop', Timestamp: '2026-11-25T08:00:00.003Z', SrcIP: '10.0.1.84', SrcPort: 51000, DstIP: '10.0.0.151', DstPort: 4222, ProcessSide: 'dst', ProcessCommand: 'nats-server', ProcessPod: 'nats/nats-0' }),
    record({ EventType: 'TCP_UPDATE', FlowID: 'd7', CollectorID: 'desktop', Timestamp: at(300), SrcIP: '10.0.1.84', SrcPort: 51000, DstIP: '10.0.0.151', DstPort: 4222, SrcBytes: 9000, DstBytes: 120_000 }),
  ]);
  assert.equal(rows.length, 1);
  const flow = flowOf(rows[0]);
  assert.deepEqual(flow.nodes, ['abja', 'desktop']);
  assert.equal(flow.open, true);
  assert.equal(flow.merged.ProcessSide, 'src');
  assert.equal(flow.merged.ProcessCommand, 'base-server');
  assert.equal(flow.merged.PeerProcessCommand, 'nats-server');
  assert.equal(flow.received, 120_000);
});

test('one node\'s flows with the same ends stay apart', () => {
  // The same addresses and ports again, after the first flow ended: two flows.
  const rows = groupRecords([
    record({ EventType: 'UDP_START', FlowID: 'x1', SrcPort: 5353, DstPort: 5353 }),
    record({ EventType: 'UDP_END', FlowID: 'x1', SrcPort: 5353, DstPort: 5353, Timestamp: at(130) }),
    record({ EventType: 'UDP_START', FlowID: 'x2', SrcPort: 5353, DstPort: 5353, Timestamp: at(140) }),
  ]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].kind, 'repeat');
  assert.equal((rows[0] as Extract<Row, { kind: 'repeat' }>).repeat.flows.length, 2);
});

test('a lookup seen by the client\'s and the resolver\'s node is one row', () => {
  const response = { EventType: 'DNS', DNSType: 'RESPONSE', DNSID: 7, DNSQuery: 'api.test', DNSQuestionType: 'A', Protocol: 'UDP',
    SrcIP: '10.0.0.20', SrcPort: 53, DstIP: '10.0.1.84', DstPort: 51000 } as Partial<NetworkEvent>;
  const rows = groupRecords([
    record({ ...response, CollectorID: 'abja', ProcessSide: 'dst', ProcessCommand: 'prometheus', SrcBytes: 120, DstBytes: 80 }),
    record({ ...response, CollectorID: 'desktop', ProcessSide: 'src', ProcessCommand: 'coredns', SrcBytes: 120, DstBytes: 80 }),
  ]);
  assert.equal(rows.length, 1);
  const flow = flowOf(rows[0]);
  assert.equal(flow.kind, 'lookup');
  assert.equal(flow.merged.ProcessCommand, 'coredns'); // The resolver is the response's source.
  assert.equal(flow.merged.ProcessSide, 'src');
  assert.equal(flow.merged.PeerProcessCommand, 'prometheus');
  assert.equal(flow.sent, 120);
});

test('one opener reaching one destination again and again is one repeat row', () => {
  const checks = [0, 10, 20, 30].map(second => [
    record({ EventType: 'TCP_START', FlowID: `c${second}`, Timestamp: at(second), SrcPort: 41000 + second, ProcessSide: 'src', ProcessCommand: 'kubelet', PeerProcessCommand: 'python3', Probe: 'api:liveness' }),
    record({ EventType: 'TCP_END', FlowID: `c${second}`, Timestamp: at(second + 0.002), SrcPort: 41000 + second, Reason: 'FIN', SrcBytes: 300, DstBytes: 500, ProcessSide: 'src', ProcessCommand: 'kubelet' }),
  ]).flat();
  const other = record({ EventType: 'TCP_START', FlowID: 'o1', Timestamp: at(5), DstPort: 9090, ProcessSide: 'src', ProcessCommand: 'kubelet' });
  const icmp = record({ EventType: 'ICMP', Timestamp: at(40) });
  const rows = groupRecords([...checks, other, icmp]);
  assert.deepEqual(rows.map(row => row.kind), ['record', 'repeat', 'flow']);
  const repeat = (rows[1] as Extract<Row, { kind: 'repeat' }>).repeat;
  assert.equal(repeat.flows.length, 4);
  assert.equal(repeat.every, 10_000);
  assert.equal(repeat.sent, 1200);
  assert.equal(repeat.received, 2000);
  assert.ok(repeat.flows.every(flow => !flow.open));
});

test('flows of unknown processes repeat by their source', () => {
  const rows = groupRecords([1, 2, 3].map(n => record({ EventType: 'UDP_START', FlowID: `n${n}`, Timestamp: at(n * 4.5), SrcIP: '192.168.1.80', SrcPort: 50000 + n, DstIP: '192.168.1.1', DstPort: 5351 })));
  assert.equal(rows.length, 1);
  assert.equal(rows[0].kind, 'repeat');
});

test('records from before flow IDs still pair by their ends', () => {
  const rows = groupRecords([
    record({ EventType: 'TCP_START', SrcPort: 42000 }),
    record({ EventType: 'TCP_END', SrcPort: 42000, Timestamp: at(2), ByteCount: 4096, Reason: 'FIN' }),
  ]);
  assert.equal(rows.length, 1);
  const flow = flowOf(rows[0]);
  assert.equal(flow.records.length, 2);
  assert.equal(flow.merged.ByteCount, 4096);
  assert.equal(flow.sent, 0);
});
