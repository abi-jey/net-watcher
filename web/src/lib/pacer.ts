/**
 * Paces a live stream for reading. Events arrive in bursts (the server
 * polls every two seconds, collectors forward in batches); the pacer spreads
 * each burst over `spread` seconds, at `minRate` to `maxRate` items a second.
 * When more arrive than that shows, the oldest waiting are dropped so the
 * view stays current, and counted. While paused, up to `pausedBacklog` wait.
 */
export interface PacerOptions { minRate: number; maxRate: number; spread: number; runningBacklog: number; pausedBacklog: number }

// Collectors forward in bursts a few seconds apart; five seconds of rows at
// the top rate bridge the quiet between them.
export const pacerDefaults: PacerOptions = { minRate: 2, maxRate: 12, spread: 1.5, runningBacklog: 60, pausedBacklog: 300 };

export class Pacer<T> {
  private queue: T[] = [];
  private credit = 0;
  private pace = 0;
  private last: number | undefined;
  private arrivals: { at: number; count: number }[] = [];
  private readonly options: PacerOptions;
  /** Items dropped because more arrived than could be shown. */
  dropped = 0;

  constructor(options: Partial<PacerOptions> = {}) {
    this.options = { ...pacerDefaults, ...options };
  }

  push(items: T[], now: number, paused: boolean): void {
    if (!items.length) return;
    this.queue.push(...items);
    this.arrivals.push({ at: now, count: items.length });
    this.trim(paused);
    // The rate is set when a burst arrives and kept until it is shown, so
    // a burst drains evenly instead of slowing as it shrinks.
    const { minRate, maxRate, spread } = this.options;
    this.pace = Math.max(this.pace, Math.min(maxRate, Math.max(minRate, this.queue.length / spread)));
  }

  /** Items to show now, oldest first. */
  take(now: number, paused: boolean): T[] {
    const elapsed = this.last === undefined ? 0 : Math.max(0, (now - this.last) / 1000);
    this.last = now;
    this.trim(paused);
    if (paused || !this.queue.length) {
      this.credit = 0;
      if (!this.queue.length) this.pace = 0;
      return [];
    }
    const { minRate, maxRate } = this.options;
    this.credit = Math.min(this.credit + Math.max(this.pace, minRate) * elapsed, maxRate);
    const count = Math.min(this.queue.length, Math.floor(this.credit));
    this.credit -= count;
    const shown = this.queue.splice(0, count);
    if (!this.queue.length) this.pace = 0;
    return shown;
  }

  /** Everything waiting, oldest first. */
  flush(): T[] {
    this.credit = 0;
    this.pace = 0;
    return this.queue.splice(0);
  }

  get pending(): number {
    return this.queue.length;
  }

  /** Items arriving per second over the last ten seconds. */
  rate(now: number): number {
    this.arrivals = this.arrivals.filter(arrival => now - arrival.at <= 10_000);
    const total = this.arrivals.reduce((sum, arrival) => sum + arrival.count, 0);
    return total / 10;
  }

  private trim(paused: boolean): void {
    const limit = paused ? this.options.pausedBacklog : this.options.runningBacklog;
    if (this.queue.length > limit) {
      this.dropped += this.queue.length - limit;
      this.queue.splice(0, this.queue.length - limit);
    }
  }
}
