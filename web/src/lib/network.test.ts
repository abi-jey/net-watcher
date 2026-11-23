import { test } from 'node:test';
import assert from 'node:assert/strict';
import { family, interfaceRole, ipScope } from './network.ts';

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
