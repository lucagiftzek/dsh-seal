// Sealed WebSocket mux: one real WebSocket to /_s/ws carries every inner
// WebSocket and EventSource of the page as sealed, multiplexed channels.

import type { Note } from "./shim";
import { concat, DIR_C2S, DIR_S2C, MAX_PAYLOAD, SealError, Session, StreamCipher, u32, u64 } from "./seal";
import { backoff, NetHealth, staticEnv, transientCode } from "./net";

export const M_OPEN = 0x10, M_OPENED = 0x11, M_TEXT = 0x12, M_BINARY = 0x13, M_CLOSE = 0x14,
  M_ERROR = 0x15, M_CREDIT = 0x16, M_PING = 0x17, M_PONG = 0x18, FLAG_MORE = 0x80;

const CHUNK = MAX_PAYLOAD - 4;
const WINDOW = 4 * 1024 * 1024;
const te = new TextEncoder();
const td = new TextDecoder();

export interface ChannelHandler {
  opened(info: any): void;
  data(isText: boolean, data: Uint8Array, more: boolean): void;
  closed(code: number, reason: string): void;
  failed(err: SealError): void;
}

export interface Channel {
  id: number;
  send(isText: boolean, data: Uint8Array): void;
  close(code?: number, reason?: string): void;
  /** bytes accepted by send() but not yet acknowledged by the server */
  buffered(): number;
}

type WSFactory = (url: string) => WebSocket;

interface ChanState {
  id: number;
  h: ChannelHandler;
  credit: number; // bytes we may still send
  queue: { type: number; payload: Uint8Array }[];
  unacked: number;
  open: boolean;
}

export interface MuxOptions {
  /** network health shared with the indicator (default: always online) */
  net?: NetHealth;
  /** keepalive ping interval (ms) */
  pingMs?: number;
  /** how long a liveness check waits for an answer (ms) */
  verifyMs?: number;
  /** called on every state change (the indicator refreshes) */
  onState?: (state: string) => void;
}

function asSealError(e: any): SealError {
  if (e instanceof SealError) return e;
  // a fetch that threw (offline, connection reset) during the handshake
  return new SealError("SEAL_NETWORK", String(e?.message || e), 0, true);
}

/**
 * One mux connection. Reconnects lazily: a new channel after a drop dials
 * again. Dialling retries with exponential backoff and jitter; offline, a
 * hidden page and a wake from sleep make it wait instead of failing. It fails
 * (and the caller may fall back to plain in offer mode) only after the sealed
 * socket kept failing for the grace window while the network was demonstrably up.
 */
export class Mux {
  private ws: WebSocket | null = null;
  private ready: Promise<void> | null = null;
  private out!: StreamCipher;
  private inp!: StreamCipher;
  private sendChain: Promise<unknown> = Promise.resolve();
  private recvChain: Promise<unknown> = Promise.resolve();
  private chans = new Map<number, ChanState>();
  private nextId = 1;
  private pendingCredit = new Map<number, number>();
  private creditTimer: any = null;
  private pingTimer: any = null;
  private lastRecv = 0;
  private lastTick = 0;
  private verifying = false;
  readonly net: NetHealth;
  private pingMs: number;
  state: "idle" | "connecting" | "waiting" | "open" | "failed" = "idle";
  lastError: SealError | null = null;
  /** Inner sockets and event streams opened on this mux (status indicator). */
  channelsOpened = 0;
  /** mux sockets opened (the first one included) and dropped */
  connects = 0;
  drops = 0;
  /** wakes from sleep or freeze detected by the keepalive */
  wakes = 0;
  lastDrop = "";

  constructor(
    private getSession: (fresh: boolean) => Promise<Session>,
    private wsURL: string,
    private wsFactory: WSFactory,
    private opts: MuxOptions = {},
  ) {
    this.net = opts.net || new NetHealth(staticEnv());
    this.pingMs = opts.pingMs || 25000;
    this.net.on((ev) => {
      // back from sleep, offline or a frozen tab: check the socket at once
      if (ev === "online" || ev === "visible" || ev === "resume") this.verify(ev);
    });
  }

  private setState(s: Mux["state"]) {
    if (this.state === s) return;
    this.state = s;
    try { this.opts.onState?.(s); } catch { /* ignore */ }
  }

  private connect(): Promise<void> {
    if (this.ready) return this.ready;
    this.setState("connecting");
    this.ready = this.connectLoop().catch((e) => {
      this.setState("failed");
      this.lastError = asSealError(e);
      this.ready = null;
      throw this.lastError;
    });
    return this.ready;
  }

  private async connectLoop(): Promise<void> {
    let fresh = false;
    let fresh401 = 0;
    for (let attempt = 0; ; attempt++) {
      if (!this.net.env.online()) {
        this.setState("waiting");
        this.net.reset();
        await this.net.waitOnline();
        this.setState("connecting");
      }
      let code = -1;
      let err: SealError | null = null;
      try {
        const sess = await this.getSession(fresh);
        fresh = false;
        code = await this.dial(sess);
      } catch (e) {
        err = asSealError(e);
      }
      if (code === 0) {
        this.net.ok();
        return;
      }
      if (code === 4401) {
        // the server forgot the session (restart, or idle past its TTL): fresh handshake
        if (++fresh401 > 3) throw new SealError("SEAL_UNKNOWN_SESSION", "mux socket closed with 4401", 4401);
        fresh = true;
        attempt = -1;
        continue;
      }
      if (code === 4403) throw new SealError("SEAL_IDENTITY_MISMATCH", "mux socket closed with 4403", 4403);
      if (code === 4400) throw new SealError("SEAL_MUX_PROTOCOL", "mux socket closed with 4400", 4400);
      if (err && !transientCode(err.code)) throw err;
      // transient: offline, a proxy restarting, the machine waking up
      await this.net.failure();
      if (this.net.graceExpired()) {
        throw err && err.code !== "SEAL_NETWORK" ? err : new SealError("SEAL_MUX_CONNECT", "mux socket closed with " + (code < 0 ? "network error" : code), code < 0 ? 0 : code);
      }
      this.setState(this.net.env.online() ? "connecting" : "waiting");
      await this.net.sleep(backoff(attempt));
    }
  }

  /** Open the socket and confirm it with a ping/pong exchange. 0 = open, else a close code. */
  private dial(sess: Session): Promise<number> {
    const stream = sess.nextStream();
    const ws = this.wsFactory(this.wsURL);
    ws.binaryType = "arraybuffer";
    return new Promise<number>((res) => {
      let settled = false;
      const finish = (code: number) => {
        if (settled) return;
        settled = true;
        clearTimeout(t);
        if (code === 0) {
          ws.onclose = (ev) => { if (this.ws === ws) this.dropped(ev.code, ev.reason); };
          this.setState("open");
          this.connects++;
          this.lastRecv = this.lastTick = Date.now();
          clearInterval(this.pingTimer);
          this.pingTimer = setInterval(() => this.tick(), this.pingMs);
        } else {
          if (this.ws === ws) this.ws = null;
          try { ws.close(); } catch { /* ignore */ }
        }
        res(code);
      };
      // a dial that hangs (half-open network after a wake) counts as a failure
      const t = setTimeout(() => finish(4408), 15000);
      ws.onopen = () => {
        ws.send(concat(te.encode("DSW1"), sess.sid, u64(stream)) as BufferSource);
        this.out = new StreamCipher(sess, DIR_C2S, stream);
        this.inp = new StreamCipher(sess, DIR_S2C, stream);
        this.sendChain = Promise.resolve();
        this.recvChain = Promise.resolve();
        // The server answers a valid prefix silently; a bad one closes
        // within a round trip. Confirm with a ping/pong exchange.
        this.ws = ws;
        ws.onmessage = (ev) => this.onMessage(ev.data as ArrayBuffer);
        this.onFirstPong = () => finish(0);
        this.frame(M_PING, 0, u64(Date.now()));
      };
      ws.onclose = (ev) => finish(ev.code || 1006);
      ws.onerror = () => {};
    });
  }

  private onFirstPong: (() => void) | null = null;

  /**
   * Keepalive tick. A gap far beyond the interval means the machine slept or
   * the tab was frozen: the socket is probably dead, but that is not a
   * failure of the seal. Verify it and reconnect quietly.
   */
  tick() {
    const now = Date.now();
    const gap = this.lastTick ? now - this.lastTick : 0;
    this.lastTick = now;
    if (gap > this.pingMs * 2 + 10000) {
      this.wakes++;
      this.net.reset();
      this.verify("wake");
      return;
    }
    if (now - this.lastRecv > 70000) {
      this.kill("keepalive timeout");
      return;
    }
    this.frame(M_PING, 0, u64(now));
  }

  /** Ping now; no answer within 8 s drops the socket (the channels' owners reconnect). */
  verify(why: string) {
    if (this.state === "waiting" || this.state === "connecting") { this.net.wake(); return; }
    if (this.state !== "open" || this.verifying) return;
    const ws = this.ws;
    const mark = this.lastRecv;
    this.verifying = true;
    this.frame(M_PING, 0, u64(Date.now()));
    setTimeout(() => {
      this.verifying = false;
      if (this.ws === ws && this.lastRecv === mark) this.kill(why === "wake" ? "sleep" : why);
    }, this.opts.verifyMs || 8000);
  }

  private kill(reason: string) {
    const ws = this.ws;
    try { ws?.close(4408, reason); } catch { /* ignore */ }
    this.dropped(1006, reason);
  }

  private dropped(code: number, reason: string) {
    clearInterval(this.pingTimer);
    this.ws = null;
    this.ready = null;
    this.drops++;
    this.lastDrop = code + (reason ? " " + reason : "");
    this.setState("idle");
    const chans = [...this.chans.values()];
    this.chans.clear();
    for (const c of chans) c.h.closed(1006, "seal mux dropped (" + code + (reason ? " " + reason : "") + ")");
  }

  /** Connect without opening a channel (to find out whether the seal works again). */
  warm(): Promise<void> {
    return this.connect();
  }

  /** Test hook: close the outer socket as a network drop would. */
  dropForTest() {
    try { this.ws?.close(); } catch { /* ignore */ }
  }

  /** Seal and send one frame; ordering is kept by a promise chain. */
  private frame(type: number, ch: number, payload: Uint8Array) {
    const ws = this.ws;
    const out = this.out;
    if (!ws) return;
    const p = out.seal(type, concat(u32(ch), payload));
    this.sendChain = this.sendChain.then(() => p).then((ct) => {
      if (ws.readyState === 1) ws.send(ct as BufferSource);
    }).catch(() => {});
  }

  private onMessage(data: ArrayBuffer) {
    const p = this.inp.open(new Uint8Array(data));
    this.recvChain = this.recvChain.then(() => p).then(({ type, payload }) => this.dispatch(type, payload)).catch((e) => {
      try { this.ws?.close(4400, "SEAL_FRAME_AUTH"); } catch { /* ignore */ }
      this.dropped(4400, String(e?.code || e));
    });
  }

  private dispatch(type: number, payload: Uint8Array) {
    this.lastRecv = Date.now();
    if (type === M_PONG) {
      if (this.onFirstPong) { const f = this.onFirstPong; this.onFirstPong = null; f(); }
      return;
    }
    if (type === M_PING) {
      // the server pings too (keeps Cloudflare's idle timer from closing a quiet socket)
      this.frame(M_PONG, 0, payload.subarray(4));
      return;
    }
    if (payload.length < 4) return;
    const id = new DataView(payload.buffer, payload.byteOffset, 4).getUint32(0);
    const body = payload.subarray(4);
    const c = this.chans.get(id);
    if (!c) return;
    const base = type & ~FLAG_MORE;
    switch (base) {
      case M_OPENED:
        c.open = true;
        c.h.opened(JSON.parse(td.decode(body)));
        break;
      case M_TEXT:
      case M_BINARY:
        c.h.data(base === M_TEXT, body.slice(), (type & FLAG_MORE) !== 0);
        this.grant(id, body.length);
        break;
      case M_CREDIT: {
        const n = new DataView(body.buffer, body.byteOffset, 4).getUint32(0);
        c.credit += n;
        c.unacked -= n;
        this.flush(c);
        break;
      }
      case M_CLOSE: {
        this.chans.delete(id);
        const code = body.length >= 2 ? (body[0] << 8) | body[1] : 1005;
        c.h.closed(code, td.decode(body.subarray(2)));
        break;
      }
      case M_ERROR: {
        this.chans.delete(id);
        let j: any = {};
        try { j = JSON.parse(td.decode(body)); } catch { /* keep empty */ }
        c.h.failed(new SealError(j.code || "SEAL_MUX_ERROR", j.message || "channel failed", j.status || 0, false));
        break;
      }
    }
  }

  private grant(id: number, n: number) {
    this.pendingCredit.set(id, (this.pendingCredit.get(id) || 0) + n);
    if ((this.pendingCredit.get(id) || 0) >= 256 * 1024) return this.flushCredit();
    if (!this.creditTimer) this.creditTimer = setTimeout(() => this.flushCredit(), 0);
  }

  private flushCredit() {
    clearTimeout(this.creditTimer);
    this.creditTimer = null;
    for (const [id, n] of this.pendingCredit) if (n > 0 && this.chans.has(id)) this.frame(M_CREDIT, id, u32(n));
    this.pendingCredit.clear();
  }

  private flush(c: ChanState) {
    while (c.queue.length) {
      const f = c.queue[0];
      const isData = (f.type & ~FLAG_MORE) === M_TEXT || (f.type & ~FLAG_MORE) === M_BINARY;
      if (isData && c.credit < f.payload.length) return;
      c.queue.shift();
      if (isData) c.credit -= f.payload.length;
      this.frame(f.type, c.id, f.payload);
    }
  }

  /** Open a channel. kind "ws" = inner WebSocket, "http" = inner GET stream. */
  open(kind: "ws" | "http", req: Record<string, unknown>, h: ChannelHandler): Channel {
    const id = this.nextId++;
    this.channelsOpened++;
    const c: ChanState = { id, h, credit: WINDOW, queue: [], unacked: 0, open: false };
    let gone = false;
    this.connect().then(() => {
      if (gone) return;
      this.chans.set(id, c);
      this.frame(M_OPEN, id, te.encode(JSON.stringify({ k: kind, ...req })));
      this.flush(c);
    }, (e) => {
      if (!gone) h.failed(e);
    });
    return {
      id,
      send: (isText, data) => {
        const t = isText ? M_TEXT : M_BINARY;
        if (data.length === 0) c.queue.push({ type: t, payload: data });
        for (let o = 0; o < data.length; o += CHUNK) {
          const end = Math.min(data.length, o + CHUNK);
          c.queue.push({ type: end < data.length ? t | FLAG_MORE : t, payload: data.subarray(o, end) });
        }
        c.unacked += data.length;
        if (this.chans.has(id)) this.flush(c);
      },
      close: (code = 1000, reason = "") => {
        const p = concat(new Uint8Array([code >> 8, code & 255]), te.encode(reason));
        if (this.chans.has(id)) {
          c.queue.push({ type: M_CLOSE, payload: p });
          this.flush(c);
          if (kind === "http") this.chans.delete(id);
        } else gone = true;
      },
      buffered: () => Math.max(0, c.unacked),
    };
  }
}

/** A socket or event stream that fell back to plain and can move back onto the seal. */
export interface Upgradable { upgrade(why: string): void }

// WebSocket replacement ---------------------------------------------------------

type AnyData = string | ArrayBufferLike | Blob | ArrayBufferView;

/**
 * Build a WebSocket class whose instances ride the mux: same-origin ones to
 * DSH, cross-origin ones as sealed egress (the server dials them, wss only).
 * Excluded paths and an unavailable mux get a real WebSocket.
 */
export function makeSealedWebSocket(
  Native: typeof WebSocket,
  getMux: () => Mux | null,
  shouldSeal: (u: URL) => boolean,
  fallbackAllowed: () => boolean,
  onFallback: (why: string) => void,
  egressOn: () => boolean = () => false,
  note: Note = () => {},
  natives: Set<Upgradable> = new Set(),
): typeof WebSocket {
  class SealedWebSocket extends EventTarget {
    static readonly CONNECTING = 0;
    static readonly OPEN = 1;
    static readonly CLOSING = 2;
    static readonly CLOSED = 3;
    readonly CONNECTING = 0;
    readonly OPEN = 1;
    readonly CLOSING = 2;
    readonly CLOSED = 3;
    url!: string;
    readyState = 0;
    protocol = "";
    extensions = "";
    binaryType: BinaryType = "blob";
    onopen: ((ev: Event) => any) | null = null;
    onmessage: ((ev: MessageEvent) => any) | null = null;
    onclose: ((ev: CloseEvent) => any) | null = null;
    onerror: ((ev: Event) => any) | null = null;
    private ch: Channel | null = null;
    private native: WebSocket | null = null;
    private frag: Uint8Array[] = [];
    private sendChain: Promise<unknown> = Promise.resolve();
    private discarded = 0;

    constructor(url: string | URL, protocols?: string | string[]) {
      super();
      const u = new URL(String(url), location.href);
      if (u.protocol === "http:") u.protocol = "ws:";
      if (u.protocol === "https:") u.protocol = "wss:";
      const mux = getMux();
      const same = u.host === location.host && (u.protocol === "wss:") === (location.protocol === "https:");
      const cross = !same && (u.protocol === "wss:" || u.protocol === "ws:");
      if (cross && (!egressOn() || !mux)) note("escaped", u.host, "websocket");
      if (!mux || (same ? !shouldSeal(u) : !cross || !egressOn())) {
        return new Native(url, protocols) as unknown as SealedWebSocket;
      }
      if (u.hash) throw new DOMException("URL has a fragment", "SyntaxError");
      this.url = u.href;
      const prot = protocols === undefined ? [] : Array.isArray(protocols) ? protocols : [protocols];
      const path = same ? u.pathname + u.search : u.href;
      if (cross) note("egress", u.host, "websocket");
      this.ch = mux.open("ws", { u: path, p: prot }, {
        opened: (info) => {
          if (this.readyState !== 0) return;
          this.protocol = info.p || "";
          this.readyState = 1;
          this.fire(new Event("open"));
        },
        data: (isText, data, more) => {
          if (this.readyState !== 1 && this.readyState !== 2) return;
          this.frag.push(data);
          if (more) return;
          const all = this.frag.length === 1 ? this.frag[0] : concat(...this.frag);
          this.frag = [];
          let payload: any;
          if (isText) payload = td.decode(all);
          else if (this.binaryType === "arraybuffer") payload = all.buffer.slice(all.byteOffset, all.byteOffset + all.byteLength);
          else payload = new Blob([all as BlobPart]);
          this.fire(new MessageEvent("message", { data: payload, origin: u.origin }));
        },
        closed: (code, reason) => this.finish(code, reason, code !== 1006),
        failed: (err) => {
          if (this.readyState === 0 && err.preReplay && fallbackAllowed()) {
            if (cross) note("escaped", u.host, "websocket (" + err.code + ")");
            else onFallback(err.code);
            this.attachNative(u.href, protocols);
            return;
          }
          if (cross && this.readyState === 0) note("blocked", u.host, err.code);
          this.fire(new Event("error"));
          this.finish(1006, "", false);
        },
      });
    }

    private attachNative(url: string, protocols?: string | string[]) {
      const n = new Native(url, protocols);
      this.native = n;
      natives.add(this);
      n.binaryType = this.binaryType;
      n.onopen = () => { this.protocol = n.protocol; this.readyState = 1; this.fire(new Event("open")); };
      n.onmessage = (ev) => this.fire(new MessageEvent("message", { data: ev.data, origin: ev.origin }));
      n.onerror = () => this.fire(new Event("error"));
      n.onclose = (ev) => { natives.delete(this); this.finish(ev.code, ev.reason, ev.wasClean); };
    }

    /**
     * The seal works again: end this plain socket the way a network drop
     * would (1006), so its owner reconnects, this time over the seal.
     */
    upgrade(why: string) {
      const n = this.native;
      natives.delete(this);
      if (!n) return;
      n.onopen = n.onmessage = n.onerror = n.onclose = null;
      try { n.close(1000, "seal restored"); } catch { /* ignore */ }
      if (this.readyState < 3) { this.fire(new Event("error")); this.finish(1006, why, false); }
    }

    private fire(ev: Event) {
      const h = (this as any)["on" + ev.type];
      this.dispatchEvent(ev);
      if (typeof h === "function") h.call(this, ev);
    }

    private finish(code: number, reason: string, clean: boolean) {
      if (this.readyState === 3) return;
      this.readyState = 3;
      this.fire(new CloseEvent("close", { code, reason, wasClean: clean }));
    }

    get bufferedAmount(): number {
      if (this.native) return this.native.bufferedAmount;
      return (this.ch ? this.ch.buffered() : 0) + this.discarded;
    }

    send(data: AnyData) {
      if (this.readyState === 0) throw new DOMException("Still in CONNECTING state.", "InvalidStateError");
      if (this.native) { this.native.binaryType = this.binaryType; return this.native.send(data as any); }
      if (this.readyState !== 1) {
        this.discarded += typeof data === "string" ? te.encode(data).length : (data as any).byteLength || (data as any).size || 0;
        return;
      }
      const ch = this.ch!;
      if (typeof data === "string") {
        const b = te.encode(data);
        this.sendChain = this.sendChain.then(() => ch.send(true, b));
      } else if (data instanceof Blob) {
        const p = data.arrayBuffer();
        this.sendChain = this.sendChain.then(() => p).then((ab) => ch.send(false, new Uint8Array(ab)));
      } else if (ArrayBuffer.isView(data)) {
        const b = new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
        this.sendChain = this.sendChain.then(() => ch.send(false, b));
      } else {
        const b = new Uint8Array((data as ArrayBuffer).slice(0));
        this.sendChain = this.sendChain.then(() => ch.send(false, b));
      }
    }

    close(code?: number, reason?: string) {
      if (code !== undefined && code !== 1000 && (code < 3000 || code > 4999)) {
        throw new DOMException("invalid close code", "InvalidAccessError");
      }
      if (reason && te.encode(reason).length > 123) throw new DOMException("reason too long", "SyntaxError");
      if (this.native) return this.native.close(code, reason);
      if (this.readyState >= 2) return;
      if (this.readyState === 0) {
        this.readyState = 2;
        this.ch?.close(1000, "");
        this.fire(new Event("error"));
        this.finish(1006, "", false);
        return;
      }
      this.readyState = 2;
      const ch = this.ch!;
      this.sendChain = this.sendChain.then(() => ch.close(code ?? 1000, reason ?? ""));
    }
  }
  return SealedWebSocket as unknown as typeof WebSocket;
}

// EventSource replacement --------------------------------------------------------

export function makeSealedEventSource(
  Native: typeof EventSource,
  getMux: () => Mux | null,
  shouldSeal: (u: URL) => boolean,
  fallbackAllowed: () => boolean,
  onFallback: (why: string) => void,
  egressOn: () => boolean = () => false,
  note: Note = () => {},
  natives: Set<Upgradable> = new Set(),
): typeof EventSource {
  class SealedEventSource extends EventTarget {
    static readonly CONNECTING = 0;
    static readonly OPEN = 1;
    static readonly CLOSED = 2;
    readonly CONNECTING = 0;
    readonly OPEN = 1;
    readonly CLOSED = 2;
    url!: string;
    withCredentials: boolean;
    readyState = 0;
    onopen: ((ev: Event) => any) | null = null;
    onmessage: ((ev: MessageEvent) => any) | null = null;
    onerror: ((ev: Event) => any) | null = null;
    private ch: Channel | null = null;
    private native: EventSource | null = null;
    private lastId = "";
    private retry = 3000;
    private timer: any = null;
    private buf = "";
    private data: string[] = [];
    private event = "";
    private dec = new TextDecoder();
    private u: URL;
    private cross = false;

    constructor(url: string | URL, init?: EventSourceInit) {
      super();
      const u = new URL(String(url), location.href);
      this.u = u;
      this.withCredentials = !!init?.withCredentials;
      const cross = u.origin !== location.origin && (u.protocol === "https:" || u.protocol === "http:");
      if (cross && (!egressOn() || !getMux())) note("escaped", u.host, "eventsource");
      if (!getMux() || (cross ? !egressOn() : u.origin !== location.origin || !shouldSeal(u))) {
        return new Native(url, init) as unknown as SealedEventSource;
      }
      this.cross = cross;
      if (cross) note("egress", u.host, "eventsource");
      this.url = u.href;
      this.connect();
    }

    private fire(ev: Event) {
      const h = (this as any)["on" + ev.type];
      this.dispatchEvent(ev);
      if (typeof h === "function") h.call(this, ev);
    }

    private connect() {
      const mux = getMux();
      if (!mux) return;
      this.readyState = 0;
      this.buf = "";
      this.data = [];
      this.event = "";
      this.dec = new TextDecoder();
      const h: [string, string][] = [["Accept", "text/event-stream"], ["Cache-Control", "no-cache"]];
      if (this.lastId) h.push(["Last-Event-ID", this.lastId]);
      let ok = false;
      this.ch = mux.open("http", { m: "GET", u: this.cross ? this.url : this.u.pathname + this.u.search, h, md: "cors", dt: "empty" }, {
        opened: (info) => {
          const ct = ((info.h || []) as [string, string][]).find(([k]) => k.toLowerCase() === "content-type")?.[1] || "";
          if (info.s !== 200 || !ct.toLowerCase().startsWith("text/event-stream")) {
            this.readyState = 2;
            this.ch?.close();
            this.fire(new Event("error"));
            return;
          }
          ok = true;
          this.readyState = 1;
          this.fire(new Event("open"));
        },
        data: (_t, data) => { if (ok && this.readyState === 1) this.feed(this.dec.decode(data, { stream: true })); },
        closed: () => this.lost(),
        failed: (err) => {
          if (!ok && err.preReplay && fallbackAllowed()) {
            onFallback(err.code);
            const n = new Native(this.url, { withCredentials: this.withCredentials });
            this.native = n;
            natives.add(this);
            n.onopen = () => { this.readyState = 1; this.fire(new Event("open")); };
            n.onerror = () => { this.readyState = n.readyState; this.fire(new Event("error")); };
            n.onmessage = (ev) => this.fire(new MessageEvent("message", { data: ev.data, lastEventId: ev.lastEventId, origin: ev.origin }));
            const orig = n.addEventListener.bind(n);
            // named events are forwarded on demand
            this.forward = (type: string) => orig(type, (ev: Event) => { const me = ev as MessageEvent; this.fire(new MessageEvent(type, { data: me.data, lastEventId: me.lastEventId, origin: me.origin })); });
            return;
          }
          this.lost();
        },
      });
    }

    private forward: ((type: string) => void) | null = null;

    addEventListener(type: string, cb: any, opts?: any) {
      super.addEventListener(type, cb, opts);
      if (this.forward && !["open", "error", "message"].includes(type)) this.forward(type);
    }

    private lost() {
      if (this.readyState === 2) return;
      this.readyState = 0;
      this.fire(new Event("error"));
      if (this.readyState === 2) return;
      clearTimeout(this.timer);
      this.timer = setTimeout(() => { if (this.readyState !== 2) this.connect(); }, this.retry);
    }

    private feed(text: string) {
      this.buf += text;
      for (;;) {
        const m = /\r\n|\r|\n/.exec(this.buf);
        if (!m) return;
        if (m[0] === "\r" && m.index === this.buf.length - 1) return; // maybe CRLF split
        const line = this.buf.slice(0, m.index);
        this.buf = this.buf.slice(m.index + m[0].length);
        this.line(line);
      }
    }

    private line(line: string) {
      if (line === "") {
        if (this.data.length) {
          const ev = new MessageEvent(this.event || "message", { data: this.data.join("\n"), lastEventId: this.lastId, origin: this.u.origin });
          this.data = [];
          this.event = "";
          this.fire(ev);
        } else this.event = "";
        return;
      }
      if (line.startsWith(":")) return;
      const i = line.indexOf(":");
      const field = i < 0 ? line : line.slice(0, i);
      let value = i < 0 ? "" : line.slice(i + 1);
      if (value.startsWith(" ")) value = value.slice(1);
      if (field === "data") this.data.push(value);
      else if (field === "event") this.event = value;
      else if (field === "id" && !value.includes("\0")) this.lastId = value;
      else if (field === "retry" && /^\d+$/.test(value)) this.retry = parseInt(value, 10);
    }

    /** The seal works again: drop the plain stream and reconnect over the mux. */
    upgrade(_why: string) {
      const n = this.native;
      natives.delete(this);
      if (!n || this.readyState === 2) return;
      n.onopen = n.onmessage = n.onerror = null;
      n.close();
      this.native = null;
      this.forward = null;
      this.readyState = 1;
      this.lost();
    }

    close() {
      if (this.native) { this.native.close(); natives.delete(this); }
      this.readyState = 2;
      clearTimeout(this.timer);
      this.ch?.close();
    }
  }
  return SealedEventSource as unknown as typeof EventSource;
}
