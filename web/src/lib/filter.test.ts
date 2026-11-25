import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { addCondition, allOf, format, fromLegacy, hiddenTypes, negate, parse, processIdentity, toggleType, tryParse, type Compare } from './filter.ts';

// The parse cases the server's tests read too (internal/web/filter_test.go).
const vectors: { input: string; canonical?: string; error?: string; serverOnly?: boolean }[] =
  JSON.parse(readFileSync(new URL('./filter.vectors.json', import.meta.url), 'utf8'));

test('reads filters as the server does', () => {
  for (const vector of vectors) {
    if (vector.serverOnly) continue;
    const { term, error } = tryParse(vector.input);
    if (vector.error) {
      assert.ok(error?.message.includes(vector.error), `${vector.input}: ${error?.message} lacks ${vector.error}`);
      continue;
    }
    assert.equal(error, undefined, `${vector.input}: ${error?.message}`);
    assert.equal(format(term), vector.canonical, vector.input);
    assert.equal(format(parse(format(term))), vector.canonical, `${vector.input} reads back`);
  }
});

test('a clicked tag shows only one value, or hides one more', () => {
  const only = (field: string, value: string): Compare => ({ kind: 'compare', field, op: '=', values: [value] });
  const hide = (field: string, value: string): Compare => ({ kind: 'compare', field, op: '!=', values: [value] });
  let filter = parse('port = 53');
  filter = addCondition(filter, only('ns', 'default'));
  filter = addCondition(filter, only('ns', 'web'));
  assert.equal(format(filter), 'port = 53 and ns = web');
  filter = addCondition(filter, hide('node', 'abja'));
  filter = addCondition(filter, hide('node', 'desktop'));
  filter = addCondition(filter, hide('node', 'abja'));
  assert.equal(format(filter), 'port = 53 and ns = web and node != (abja, desktop)');
});

test('type toggles hide types and keep the shorter list', () => {
  let filter = parse('port = 53');
  assert.deepEqual(hiddenTypes(filter)?.hidden, []);
  filter = toggleType(filter, 'DNS');
  assert.equal(format(filter), 'port = 53 and type != DNS');
  for (const type of ['TCP_START', 'TCP_UPDATE', 'TCP_END', 'UDP_START', 'UDP_UPDATE', 'UDP_END', 'TLS_SNI']) filter = toggleType(filter, type);
  assert.equal(format(filter), 'port = 53 and type = (ICMP, TIMEOUT, GAP)');
  filter = toggleType(filter, 'ICMP');
  assert.deepEqual(hiddenTypes(filter)?.hidden.length, 9);
  assert.equal(hiddenTypes(parse('type = dns or port = 1')), null, 'a type inside an alternative is edited as text');
  assert.deepEqual(hiddenTypes(parse('iface.type = uplink'))?.hidden, [], 'interface type is another field');
  assert.equal(format(toggleType(parse('type != DNS'), 'DNS')), '');
});

test('negation is written simply', () => {
  assert.equal(format(negate(parse('src.kind = pod')!)), 'src.kind != pod');
  assert.equal(format(negate(parse('bytes > 1k')!)), 'bytes <= 1k');
  assert.equal(format(negate(parse('not coredns')!)), 'coredns');
  assert.equal(format(negate(parse('a or b')!)), 'not (a or b)');
});

test('older link parameters become a filter', () => {
  const terms = fromLegacy(new URLSearchParams('process=python3&processPod=demo%2Fapi-1&collector=node-a&type=DNS,TLS_SNI&withProcess=yes&route=any&q=api'));
  assert.equal(format(allOf(terms)),
    'node = node-a and type = (DNS, TLS_SNI) and (src.process = python3 and src.process.pod = demo/api-1 and src.process.container = none' +
    ' or dst.process = python3 and dst.process.pod = demo/api-1 and dst.process.container = none) and process.side != none and route != none and api');
});

test('a process identity holds at one end', () => {
  assert.equal(format(processIdentity('kubelet', ['none'], 'none', ['src'])), 'src.process = kubelet and src.process.pod = none and src.process.container = none');
  assert.equal(format(processIdentity('keda', ['keda/a', 'keda/b'], 'keda-operator', ['dst'])), 'dst.process = keda and dst.process.pod = (keda/a, keda/b) and dst.process.container = keda-operator');
  // Parsed back, the text is the same condition.
  const text = format(processIdentity('python', ['none'], 'none', ['src', 'dst']));
  assert.equal(format(parse(text)), text);
});
