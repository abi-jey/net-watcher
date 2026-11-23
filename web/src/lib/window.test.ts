import { test } from 'node:test';
import assert from 'node:assert/strict';
import { windowRange } from './window.ts';

test('windows over an hour start on an hour boundary within 7 days', () => {
  const now = new Date('2026-11-23T19:47:31.250Z');
  assert.deepEqual(windowRange('24h', now), { from: '2026-11-22T19:00:00Z', to: '2026-11-23T19:47:32Z' });
  assert.deepEqual(windowRange('15m', now), { from: '2026-11-23T19:32:31Z', to: '2026-11-23T19:47:32Z' });
  const week = windowRange('7d', now);
  assert.ok(new Date(week.to).getTime() - new Date(week.from).getTime() <= 7 * 24 * 3600 * 1000);
});
