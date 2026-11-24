import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deviceName, family, interfaceRole, ipScope, rcodeName, routeInfo } from './network.ts';

test('classifies IPv4 and IPv6 scopes', () => {
  const cases: [string, string][] = [
    ['10.0.1.155', 'private'], ['172.20.0.1', 'private'], ['172.32.0.1', 'public'], ['192.168.1.170', 'private'],
    ['100.99.117.15', 'tailscale'], ['100.128.0.1', 'public'], ['127.0.0.1', 'loopback'], ['169.254.169.254', 'link-local'],
    ['224.0.0.251', 'multicast'], ['157.240.17.142', 'public'], ['0.0.0.0', 'unspecified'],
    ['fd7a:115c:a1e0::372d:7510', 'tailscale'], ['fd00::1', 'private'], ['fe80::1', 'link-local'], ['::1', 'loopback'],
    ['2a03:2880:f25b:d8:face:b00c:0:21ba', 'public'], ['ff02::fb', 'multicast'], ['not-an-ip', 'unknown'],
  ];
  for (const [ip, scope] of cases) assert.equal(ipScope(ip), scope, ip);
});

test('names interface roles', () => {
  assert.equal(interfaceRole('lxced27c086af56').role, 'pod link');
  assert.equal(interfaceRole('cilium_vxlan').role, 'overlay');
  assert.equal(interfaceRole('tailscale0').role, 'Tailscale');
  assert.equal(interfaceRole('enp0s25').role, 'uplink');
  assert.equal(interfaceRole('docker0').role, 'bridge');
  assert.equal(interfaceRole('').role, 'unknown');
});

test('groups event types into families', () => {
  assert.equal(family('TCP_END'), 'tcp');
  assert.equal(family('UDP_START'), 'udp');
  assert.equal(family('TLS_SNI'), 'tls');
  assert.equal(family('GAP'), 'gap');
});

test('interface role ids match the server filter', () => {
  assert.equal(interfaceRole('lxced27c086af56').id, 'pod');
  assert.equal(interfaceRole('eni77').id, 'pod'); // Not an uplink, though it starts with "en".
  assert.equal(interfaceRole('enp0s25').id, 'uplink');
  assert.equal(interfaceRole('wlp2s0').id, 'wifi');
  assert.equal(interfaceRole('ts0').id, 'tailscale');
  assert.equal(interfaceRole('cilium_host').id, 'cluster-host');
});

test('Tailscale routes and device names', () => {
  assert.equal(routeInfo('exit-node')?.label, 'exit node');
  assert.equal(routeInfo(''), undefined);
  assert.equal(deviceName('pixel-8a.tailfb4030.ts.net'), 'pixel-8a');
});

test('names DNS response codes as people know them', () => {
  assert.equal(rcodeName('Non-Existent Domain'), 'NXDOMAIN');
  assert.equal(rcodeName('Server Failure '), 'SERVFAIL');
  assert.equal(rcodeName('No Error'), 'NOERROR');
  assert.equal(rcodeName(''), '');
  assert.equal(rcodeName('Something New'), 'Something New');
});
