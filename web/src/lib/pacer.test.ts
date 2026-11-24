import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Pacer } from './pacer.ts';

/** Runs the pacer in 100 ms ticks; returns how many items each tick showed. */
function run(pacer: Pacer<number>, ticks: number, start: number, arrivals: Record<number, number> = {}, paused = () => false): number[] {
  const shown: number[] = [];
  let next = 0;
  for (let tick = 0; tick < ticks; tick++) {
    const now = start + tick * 100;
    if (arrivals[tick]) pacer.push(Array.from({ length: arrivals[tick] }, () => next++), now, paused());
    shown.push(pacer.take(now, paused()).length);
  }
  return shown;
}

test('a burst is spread over about a second and a half, not shown at once', () => {
  const pacer = new Pacer<number>();
  const shown = run(pacer, 30, 0, { 0: 12 });
  assert.equal(shown.reduce((a, b) => a + b, 0), 12);
  assert.ok(Math.max(...shown) <= 2, `at most two rows a tick: ${shown}`);
  const last = shown.findLastIndex(n => n > 0);
  assert.ok(last >= 8 && last <= 22, `drained by tick ${last}`);
});

test('a steady stream is shown at its own pace', () => {
  const pacer = new Pacer<number>();
  const arrivals: Record<number, number> = {};
  for (let tick = 0; tick < 200; tick += 20) arrivals[tick] = 6; // 3 a second, in bursts every 2 s.
  const shown = run(pacer, 220, 0, arrivals);
  assert.equal(shown.reduce((a, b) => a + b, 0), 60);
  assert.equal(pacer.dropped, 0);
  assert.ok(shown.filter(n => n > 0).length >= 40, 'rows trickle in rather than arriving in a few jumps');
});

test('a flood shows at most the readable rate, keeps current and counts the rest', () => {
  const pacer = new Pacer<number>();
  const arrivals: Record<number, number> = {};
  for (let tick = 0; tick < 100; tick += 20) arrivals[tick] = 100; // 50 a second.
  const shown = run(pacer, 100, 0, arrivals);
  const total = shown.reduce((a, b) => a + b, 0);
  assert.ok(total <= 12 * 10 + 2, `about 12 a second: ${total}`);
  assert.ok(pacer.dropped >= 500 - total - 60, `dropped ${pacer.dropped}`);
  assert.ok(pacer.rate(10_000) >= 40, `rate ${pacer.rate(10_000)}`);
});

test('pausing holds events, and resuming continues from them', () => {
  const pacer = new Pacer<number>();
  let paused = true;
  const held = run(pacer, 20, 0, { 0: 50, 10: 50 }, () => paused);
  assert.equal(held.reduce((a, b) => a + b, 0), 0);
  assert.equal(pacer.pending, 100);
  paused = false;
  assert.equal(pacer.flush().length, 100);
  assert.equal(pacer.pending, 0);
});
