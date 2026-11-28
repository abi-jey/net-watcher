import { test } from 'node:test';
import assert from 'node:assert/strict';
import { asQuery, forgetSearch, namesSearch, saveSearch, savedSearch } from './savedSearch.ts';

function memory(): Storage {
  const values = new Map<string, string>();
  return {
    get length() { return values.size; },
    clear: () => values.clear(),
    getItem: key => values.get(key) ?? null,
    key: index => [...values.keys()][index] ?? null,
    removeItem: key => { values.delete(key); },
    setItem: (key, value) => { values.set(key, value); },
  };
}

test('a kept search survives until forgotten', () => {
  const storage = memory();
  assert.equal(savedSearch(storage), undefined);
  saveSearch({ w: '15m', f: 'node = desktop and port = 51660', v: 'records' }, storage);
  assert.deepEqual(savedSearch(storage), { w: '15m', f: 'node = desktop and port = 51660', v: 'records' });
  saveSearch({ w: '24h' }, storage); // A cleared filter is kept as cleared.
  assert.deepEqual(savedSearch(storage), { w: '24h', f: undefined, v: undefined });
  forgetSearch(storage);
  assert.equal(savedSearch(storage), undefined);
});

test('a damaged or missing store keeps nothing', () => {
  const storage = memory();
  storage.setItem('nw-events-search', '{not json');
  assert.equal(savedSearch(storage), undefined);
  storage.setItem('nw-events-search', JSON.stringify({ f: 'port = 53' }));
  assert.equal(savedSearch(storage), undefined);
  const broken = { ...memory(), getItem: () => { throw new Error('denied'); }, setItem: () => { throw new Error('quota'); } } as Storage;
  assert.equal(savedSearch(broken), undefined);
  assert.doesNotThrow(() => saveSearch({ w: '1h' }, broken));
  assert.equal(savedSearch(undefined), undefined);
});

test('only an address without a search opens the kept one', () => {
  assert.equal(namesSearch(new URLSearchParams('')), false);
  assert.equal(namesSearch(new URLSearchParams('w=1h')), true);
  assert.equal(namesSearch(new URLSearchParams('f=port+%3D+53')), true);
  assert.equal(namesSearch(new URLSearchParams('v=records')), true);
  assert.equal(namesSearch(new URLSearchParams('namespace=kube-system')), true); // An older link.
  assert.equal(asQuery({ w: '15m', f: 'port = 53' }).toString(), 'w=15m&f=port+%3D+53');
});
