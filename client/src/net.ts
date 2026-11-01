// Network health for the sealed paths (page mux and worker fetch).
//
// The rule in offer mode: a sealed path that fails is
// retried with backoff; it falls back to plain only after it kept failing for
// a grace window WHILE the network is demonstrably up (a plain request to the
// tiny same-origin probe /_s/p gets any HTTP answer). Offline, a frozen or
// hidden page, or a machine that just woke from sleep never count towards the
// window: plain would fail there too, so the client waits instead.

export interface NetEnv {
  now(): number;
  online(): boolean;
  /** page hidden (timers throttled, possibly frozen): failures do not count */
  hidden(): boolean;
  /** any HTTP answer from the origin = the network is up */
  probe(): Promise<boolean>;
  /** "online" | "offline" | "visible" | "resume" (bfcache, freeze/resume) */
  subscribe(fn: (ev: string) => void): void;
}

export const GRACE_MS = 25000;
/** a gap longer than this between two failures restarts the window */
export const GAP_MS = 20000;

export class NetHealth {
  grace = GRACE_MS;
  failingSince = 0;
  lastFail = 0;
  lastOk = 0;
  private probeAt = 0;
  private probeUp = false;
  private probeP: Promise<boolean> | null = null;
  private wakers = new Set<() => void>();
  private listeners = new Set<(ev: string) => void>();

  constructor(public env: NetEnv, grace?: number) {
    if (grace !== undefined) this.grace = grace;
    env.subscribe((ev) => {
      if (ev === "offline") this.reset();
      if (ev === "online" || ev === "visible" || ev === "resume") { this.reset(); this.wake(); }
      for (const l of this.listeners) { try { l(ev); } catch { /* ignore */ } }
    });
  }

  on(fn: (ev: string) => void) { this.listeners.add(fn); }

  /** The sealed path worked. */
  ok() {
    this.failingSince = 0;
    this.lastFail = 0;
    this.lastOk = this.env.now();
  }

  /** Forget the failure window (offline, wake from sleep, resume). */
  reset() {
    this.failingSince = 0;
    this.lastFail = 0;
  }

  /** Record a transient failure of the sealed path. Counts only with the network up. */
  async failure(): Promise<void> {
    if (!this.env.online() || this.env.hidden()) { this.reset(); return; }
    const up = await this.up();
    const now = this.env.now();
    if (!up || !this.env.online()) { this.reset(); return; }
    if (!this.failingSince || now - this.lastFail > GAP_MS) this.failingSince = now;
    this.lastFail = now;
  }

  /** The sealed path kept failing for the grace window with the network up. */
  graceExpired(): boolean {
    return this.failingSince > 0 && this.env.now() - this.failingSince >= this.grace && this.env.online();
  }

  /** Is the network up? Probed at most every 2 s. */
  up(): Promise<boolean> {
    if (!this.env.online()) return Promise.resolve(false);
    const now = this.env.now();
    if (now - this.probeAt < 2000) return Promise.resolve(this.probeUp);
    if (!this.probeP) {
      this.probeP = this.env.probe().catch(() => false).then((v) => {
        this.probeAt = this.env.now();
        this.probeUp = v;
        this.probeP = null;
        return v;
      });
    }
    return this.probeP;
  }

  /** Sleep, cut short by online, visible or resume. */
  sleep(ms: number): Promise<void> {
    return new Promise((res) => {
      const done = () => { clearTimeout(t); this.wakers.delete(done); res(); };
      const t = setTimeout(done, ms);
      this.wakers.add(done);
    });
  }

  /** Wait until the browser says it is online (polled, and woken by events). */
  async waitOnline(maxMs = Infinity): Promise<boolean> {
    const end = this.env.now() + maxMs;
    while (!this.env.online()) {
      if (this.env.now() >= end) return false;
      await this.sleep(Math.min(1000, Math.max(1, end - this.env.now())));
    }
    return true;
  }

  wake() {
    for (const w of [...this.wakers]) w();
  }
}

/** Exponential backoff with jitter: 0.5 s, 1 s, 2 s, 4 s, 8 s (cap), half fixed, half random. */
export function backoff(attempt: number, base = 500, cap = 8000): number {
  const d = Math.min(cap, base * 2 ** Math.max(0, attempt));
  return d / 2 + Math.random() * (d / 2);
}

/** Environment of a page or a worker. */
export function browserEnv(probeURL = "/_s/p"): NetEnv {
  const g: any = globalThis;
  const doc: Document | undefined = g.document;
  const subs: ((ev: string) => void)[] = [];
  const emit = (ev: string) => { for (const f of subs) f(ev); };
  try {
    g.addEventListener?.("online", () => emit("online"));
    g.addEventListener?.("offline", () => emit("offline"));
    if (doc) {
      doc.addEventListener("visibilitychange", () => { if (!doc.hidden) emit("visible"); });
      doc.addEventListener("resume", () => emit("resume"));
      g.addEventListener?.("pageshow", (e: any) => { if (e.persisted) emit("resume"); });
    }
  } catch { /* no events here */ }
  return {
    now: () => Date.now(),
    online: () => (g.navigator && "onLine" in g.navigator ? !!g.navigator.onLine : true),
    hidden: () => !!doc?.hidden,
    probe: async () => {
      const ac = new AbortController();
      const t = setTimeout(() => ac.abort(), 5000);
      try {
        await fetch(probeURL + "?t=" + Date.now(), { cache: "no-store", credentials: "same-origin", redirect: "manual", signal: ac.signal });
        return true; // any HTTP answer (even an error status) proves the network is up
      } catch {
        return false;
      } finally {
        clearTimeout(t);
      }
    },
    subscribe: (fn) => { subs.push(fn); },
  };
}

/** An environment that is always online and visible (Node, tests). */
export function staticEnv(): NetEnv {
  return { now: () => Date.now(), online: () => true, hidden: () => false, probe: async () => true, subscribe: () => {} };
}

/** Failures that may heal by themselves (network, restart of a proxy in the path). */
export function transientCode(code: string): boolean {
  if (code === "SEAL_NETWORK" || code === "SEAL_MUX_CONNECT" || code === "SEAL_TRUNCATED") return true;
  const m = /^SEAL_HTTP_(\d+)$/.exec(code);
  if (m) {
    const s = Number(m[1]);
    return s === 408 || s === 429 || s >= 500;
  }
  return false;
}
