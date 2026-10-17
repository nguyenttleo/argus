export class TtlCache<V> {
  #map = new Map<string, { value: V; expires: number }>();
  #now: () => number;
  #max: number;

  constructor(opts: { now?: () => number; max?: number } = {}) {
    this.#now = opts.now ?? (() => Date.now());
    this.#max = opts.max ?? 5000;
  }

  get(key: string): V | undefined {
    const hit = this.#map.get(key);
    if (!hit) return undefined;
    if (hit.expires <= this.#now()) {
      this.#map.delete(key);
      return undefined;
    }
    return hit.value;
  }

  set(key: string, value: V, ttlMs: number): void {
    if (this.#map.size >= this.#max) {

      const first = this.#map.keys().next().value;
      if (first !== undefined) this.#map.delete(first);
    }
    this.#map.set(key, { value, expires: this.#now() + ttlMs });
  }

  get size(): number {
    return this.#map.size;
  }
}
