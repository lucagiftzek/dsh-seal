// src/seal.ts
var LABEL = "dsh-seal/1";
var DIR_C2S = 99;
var DIR_S2C = 115;
var F_HEAD = 1;
var F_DATA = 2;
var F_END = 3;
var F_ERROR = 4;
var EPOCH_SHIFT = 16;
var MAX_PAYLOAD = 64 * 1024;
var MAX_FRAME = MAX_PAYLOAD + 64;
var subtle = globalThis.crypto.subtle;
var te = new TextEncoder();
var SealError = class extends Error {
  constructor(code, message, status = 0, preReplay = true) {
    super(code + ": " + message);
    this.code = code;
    this.status = status;
    this.preReplay = preReplay;
  }
};
function b64u(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64u(s) {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "===".slice((t.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function concat(...parts) {
  let n = 0;
  const arr = parts.map((p) => p instanceof Uint8Array ? p : new Uint8Array(p));
  for (const p of arr) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of arr) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
function u64(n) {
  const b = new Uint8Array(8);
  const v = new DataView(b.buffer);
  v.setUint32(0, Math.floor(n / 4294967296));
  v.setUint32(4, n >>> 0);
  return b;
}
function u32(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0);
  return b;
}
async function sha256(data) {
  return new Uint8Array(await subtle.digest("SHA-256", data));
}
async function fingerprint(idRaw) {
  return b64u(await sha256(concat(te.encode(LABEL + " id"), new Uint8Array([0]), idRaw)));
}
function kxCertMessage(kxRaw, nbf, exp) {
  return concat(te.encode(LABEL + " kx"), new Uint8Array([0]), kxRaw, u64(nbf), u64(exp));
}
function rotationMessage(prev, next, t) {
  return concat(te.encode(LABEL + " rot"), new Uint8Array([0]), prev, next, u64(t));
}
async function verifySig(pubRaw, msg, sig) {
  try {
    const k = await subtle.importKey("raw", pubRaw, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, k, sig, msg);
  } catch {
    return false;
  }
}
var MemoryKV = class {
  constructor() {
    this.m = /* @__PURE__ */ new Map();
  }
  async get(k) {
    return this.m.get(k);
  }
  async set(k, v) {
    this.m.set(k, v);
  }
};
var IDBKV = class {
  constructor(name = "dsh-seal") {
    this.db = new Promise((res, rej) => {
      const r = indexedDB.open(name, 1);
      r.onupgradeneeded = () => r.result.createObjectStore("kv");
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
  }
  async get(k) {
    const db = await this.db;
    return new Promise((res, rej) => {
      const q = db.transaction("kv", "readonly").objectStore("kv").get(k);
      q.onsuccess = () => res(q.result);
      q.onerror = () => rej(q.error);
    });
  }
  async set(k, v) {
    const db = await this.db;
    return new Promise((res, rej) => {
      const t = db.transaction("kv", "readwrite");
      t.objectStore("kv").put(v, k);
      t.oncomplete = () => res();
      t.onerror = () => rej(t.error);
    });
  }
};
var PIN_KEY = "idfp";
var SEALED_ONLY_KEY = "sealedOnly";
async function verifyBundle(b, trusted, nowSec = Date.now() / 1e3) {
  if (!b || b.v !== 1) throw new SealError("SEAL_BUNDLE_INVALID", "unsupported bundle");
  const idRaw = unb64u(b.id);
  const fp = await fingerprint(idRaw);
  if (fp !== b.fp) throw new SealError("SEAL_BUNDLE_INVALID", "fingerprint");
  const ok = await verifySig(idRaw, kxCertMessage(unb64u(b.kx.pub), b.kx.nbf, b.kx.exp), unb64u(b.kx.sig));
  if (!ok) throw new SealError("SEAL_BUNDLE_INVALID", "key exchange signature");
  if (nowSec > b.kx.exp + 86400) throw new SealError("SEAL_BUNDLE_EXPIRED", "key exchange key expired");
  if (!trusted || trusted === fp) return fp;
  let cur = trusted;
  for (const l of b.chain || []) {
    const prev = unb64u(l.prev);
    if (await fingerprint(prev) !== cur) continue;
    const next = unb64u(l.next);
    if (!await verifySig(prev, rotationMessage(prev, next, l.t), unb64u(l.sig))) {
      throw new SealError("SEAL_TOFU_MISMATCH", "invalid rotation link");
    }
    cur = await fingerprint(next);
    if (cur === fp) return fp;
  }
  throw new SealError("SEAL_TOFU_MISMATCH", "server identity changed without a signed rotation");
}
var Session = class {
  constructor(sid, ms, fp, base) {
    /** When the handshake completed (ms since the epoch). */
    this.created = Date.now();
    this.next = 1;
    this.keys = /* @__PURE__ */ new Map();
    this.sid = sid;
    this.ms = ms;
    this.fp = fp;
    this.base = base;
  }
  /** Fresh stream id (replay protection: each id is accepted once). */
  nextStream() {
    return this.next++;
  }
  streamKey(dir, stream, epoch) {
    const id = dir + ":" + stream + ":" + epoch;
    let k = this.keys.get(id);
    if (!k) {
      const info = concat(te.encode(LABEL + " k"), new Uint8Array([dir]), u64(stream), u32(epoch));
      k = subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info },
        this.ms,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
      this.keys.set(id, k);
      if (this.keys.size > 256) this.keys.delete(this.keys.keys().next().value);
    }
    return k;
  }
  forget(dir, stream) {
    for (const k of [...this.keys.keys()]) if (k.startsWith(dir + ":" + stream + ":")) this.keys.delete(k);
  }
};
async function establish(conf, kv, fetchImpl, base = "") {
  const b = conf.bundle;
  const pinned = await kv.get(PIN_KEY);
  const fp = await verifyBundle(b, pinned);
  if (fp !== pinned) await kv.set(PIN_KEY, fp);
  const pair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const cpub = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  const r = await fetchImpl(base + "/_s/h", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ v: 1, kid: b.kx.kid, cpub: b64u(cpub) }),
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error"
  });
  if (!r.ok) throw await outerError(r);
  const hs = await r.json();
  const sid = unb64u(hs.sid);
  const sn = unb64u(hs.sn);
  const kxRaw = unb64u(b.kx.pub);
  const kxKey = await subtle.importKey("raw", kxRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await subtle.deriveBits({ name: "ECDH", public: kxKey }, pair.privateKey, 256);
  const th = await transcriptHash(unb64u(b.id), kxRaw, cpub, sid, sn);
  const ms = await masterKey(shared, th);
  if (!await verifyConfirm(ms, th, unb64u(hs.cf))) {
    throw new SealError("SEAL_HS_CONFIRM", "server could not prove the session key");
  }
  return new Session(sid, ms, fp, base);
}
async function outerError(r) {
  let code = r.headers.get("x-seal-error") || "";
  let msg = "HTTP " + r.status;
  try {
    const j = await r.json();
    code = j.code || code;
    msg = j.message || msg;
  } catch {
  }
  if (!code && r.status === 404) code = "SEAL_ABSENT";
  return new SealError(code || "SEAL_HTTP_" + r.status, msg, r.status, true);
}
var StreamCipher = class {
  constructor(sess, dir, stream) {
    this.sess = sess;
    this.dir = dir;
    this.stream = stream;
    this.seq = 0;
  }
  parts(seq) {
    const nonce = concat(new Uint8Array(4), u64(seq));
    const aad = concat(te.encode(LABEL), this.sess.sid, new Uint8Array([this.dir]), u64(this.stream), u64(seq));
    return { nonce, aad, epoch: Math.floor(seq / 2 ** EPOCH_SHIFT) };
  }
  async seal(type, payload) {
    if (payload.length > MAX_PAYLOAD) throw new SealError("SEAL_FRAME_TOO_LARGE", "payload too large");
    const { nonce, aad, epoch } = this.parts(this.seq++);
    const key = await this.sess.streamKey(this.dir, this.stream, epoch);
    const pt = new Uint8Array(1 + payload.length);
    pt[0] = type;
    pt.set(payload, 1);
    return new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, pt));
  }
  async open(ct) {
    if (ct.length > MAX_FRAME) throw new SealError("SEAL_FRAME_TOO_LARGE", "frame too large", 0, false);
    const { nonce, aad, epoch } = this.parts(this.seq++);
    const key = await this.sess.streamKey(this.dir, this.stream, epoch);
    let pt;
    try {
      pt = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, ct));
    } catch {
      throw new SealError("SEAL_FRAME_AUTH", "frame failed authentication", 0, false);
    }
    if (pt.length === 0) throw new SealError("SEAL_FRAME_EMPTY", "empty frame", 0, false);
    return { type: pt[0], payload: pt.subarray(1) };
  }
};
function lengthPrefix(ct) {
  return concat(u32(ct.length), ct);
}
var FrameReader = class {
  constructor(reader) {
    this.reader = reader;
    this.buf = new Uint8Array(0);
    this.done = false;
  }
  async next() {
    for (; ; ) {
      if (this.buf.length >= 4) {
        const n = new DataView(this.buf.buffer, this.buf.byteOffset, 4).getUint32(0);
        if (n > MAX_FRAME || n < 17) throw new SealError("SEAL_FRAME_TOO_LARGE", "bad frame length", 0, false);
        if (this.buf.length >= 4 + n) {
          const f = this.buf.slice(4, 4 + n);
          this.buf = this.buf.slice(4 + n);
          return f;
        }
      }
      if (this.done) {
        if (this.buf.length) throw new SealError("SEAL_TRUNCATED", "stream ended inside a frame", 0, false);
        return null;
      }
      const { value, done } = await this.reader.read();
      if (done) this.done = true;
      else if (value && value.length) this.buf = this.buf.length ? concat(this.buf, value) : value;
    }
  }
  cancel() {
    this.reader.cancel().catch(() => {
    });
  }
};
async function transcriptHash(idRaw, kxRaw, cpub, sid, sn) {
  return sha256(concat(te.encode(LABEL + " hs"), new Uint8Array([0]), idRaw, kxRaw, cpub, sid, sn));
}
async function masterKey(shared, th) {
  const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const msBits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: th, info: te.encode(LABEL + " ms") }, ikm, 256);
  return subtle.importKey("raw", msBits, "HKDF", false, ["deriveBits", "deriveKey"]);
}
async function verifyConfirm(ms, th, cf) {
  const ckBits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: te.encode(LABEL + " cf") }, ms, 256);
  const ck = await subtle.importKey("raw", ckBits, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  return subtle.verify("HMAC", ck, cf, th);
}

// src/net.ts
var GRACE_MS = 25e3;
var GAP_MS = 2e4;
var NetHealth = class {
  constructor(env, grace) {
    this.env = env;
    this.grace = GRACE_MS;
    this.failingSince = 0;
    this.lastFail = 0;
    this.lastOk = 0;
    this.probeAt = 0;
    this.probeUp = false;
    this.probeP = null;
    this.wakers = /* @__PURE__ */ new Set();
    this.listeners = /* @__PURE__ */ new Set();
    if (grace !== void 0) this.grace = grace;
    env.subscribe((ev) => {
      if (ev === "offline") this.reset();
      if (ev === "online" || ev === "visible" || ev === "resume") {
        this.reset();
        this.wake();
      }
      for (const l of this.listeners) {
        try {
          l(ev);
        } catch {
        }
      }
    });
  }
  on(fn) {
    this.listeners.add(fn);
  }
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
  async failure() {
    if (!this.env.online() || this.env.hidden()) {
      this.reset();
      return;
    }
    const up = await this.up();
    const now = this.env.now();
    if (!up || !this.env.online()) {
      this.reset();
      return;
    }
    if (!this.failingSince || now - this.lastFail > GAP_MS) this.failingSince = now;
    this.lastFail = now;
  }
  /** The sealed path kept failing for the grace window with the network up. */
  graceExpired() {
    return this.failingSince > 0 && this.env.now() - this.failingSince >= this.grace && this.env.online();
  }
  /** Is the network up? Probed at most every 2 s. */
  up() {
    if (!this.env.online()) return Promise.resolve(false);
    const now = this.env.now();
    if (now - this.probeAt < 2e3) return Promise.resolve(this.probeUp);
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
  sleep(ms) {
    return new Promise((res) => {
      const done = () => {
        clearTimeout(t);
        this.wakers.delete(done);
        res();
      };
      const t = setTimeout(done, ms);
      this.wakers.add(done);
    });
  }
  /** Wait until the browser says it is online (polled, and woken by events). */
  async waitOnline(maxMs = Infinity) {
    const end = this.env.now() + maxMs;
    while (!this.env.online()) {
      if (this.env.now() >= end) return false;
      await this.sleep(Math.min(1e3, Math.max(1, end - this.env.now())));
    }
    return true;
  }
  wake() {
    for (const w of [...this.wakers]) w();
  }
};
function backoff(attempt, base = 500, cap = 8e3) {
  const d = Math.min(cap, base * 2 ** Math.max(0, attempt));
  return d / 2 + Math.random() * (d / 2);
}
function browserEnv(probeURL = "/_s/p") {
  const g = globalThis;
  const doc = g.document;
  const subs = [];
  const emit = (ev) => {
    for (const f of subs) f(ev);
  };
  try {
    g.addEventListener?.("online", () => emit("online"));
    g.addEventListener?.("offline", () => emit("offline"));
    if (doc) {
      doc.addEventListener("visibilitychange", () => {
        if (!doc.hidden) emit("visible");
      });
      doc.addEventListener("resume", () => emit("resume"));
      g.addEventListener?.("pageshow", (e) => {
        if (e.persisted) emit("resume");
      });
    }
  } catch {
  }
  return {
    now: () => Date.now(),
    online: () => g.navigator && "onLine" in g.navigator ? !!g.navigator.onLine : true,
    hidden: () => !!doc?.hidden,
    probe: async () => {
      const ac = new AbortController();
      const t = setTimeout(() => ac.abort(), 5e3);
      try {
        await fetch(probeURL + "?t=" + Date.now(), { cache: "no-store", credentials: "same-origin", redirect: "manual", signal: ac.signal });
        return true;
      } catch {
        return false;
      } finally {
        clearTimeout(t);
      }
    },
    subscribe: (fn) => {
      subs.push(fn);
    }
  };
}
function staticEnv() {
  return { now: () => Date.now(), online: () => true, hidden: () => false, probe: async () => true, subscribe: () => {
  } };
}
function transientCode(code) {
  if (code === "SEAL_NETWORK" || code === "SEAL_MUX_CONNECT" || code === "SEAL_TRUNCATED") return true;
  const m = /^SEAL_HTTP_(\d+)$/.exec(code);
  if (m) {
    const s = Number(m[1]);
    return s === 408 || s === 429 || s >= 500;
  }
  return false;
}

// src/fetch.ts
var te2 = new TextEncoder();
var td = new TextDecoder();
var NULL_BODY = /* @__PURE__ */ new Set([101, 103, 204, 205, 304]);
async function sealedFetch(sess, req, fetchImpl) {
  const stream = sess.nextStream();
  const out = new StreamCipher(sess, DIR_C2S, stream);
  const body = req.body || new Uint8Array(0);
  const head = te2.encode(JSON.stringify({ m: req.method, u: req.url, h: req.headers, n: body.length, md: req.mode || "", dt: req.dest || "", ...req.redirect ? { rd: req.redirect } : {} }));
  const parts = [te2.encode("DSX1"), sess.sid, u64(stream)];
  parts.push(lengthPrefix(await out.seal(F_HEAD, head)));
  for (let o = 0; o < body.length; o += MAX_PAYLOAD) {
    parts.push(lengthPrefix(await out.seal(F_DATA, body.subarray(o, Math.min(body.length, o + MAX_PAYLOAD)))));
  }
  parts.push(lengthPrefix(await out.seal(F_END, new Uint8Array(0))));
  sess.forget(DIR_C2S, stream);
  let r;
  try {
    r = await fetchImpl(sess.base + "/_s/x", {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: concat(...parts),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: req.signal || void 0
    });
  } catch (e) {
    if (e?.name === "AbortError") throw e;
    const idem = req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS";
    throw new SealError("SEAL_NETWORK", String(e?.message || e), 0, idem);
  }
  if (!r.ok || !r.body) throw await outerError(r);
  const inp = new StreamCipher(sess, DIR_S2C, stream);
  const fr = new FrameReader(r.body.getReader());
  const first = await fr.next();
  if (!first) throw new SealError("SEAL_TRUNCATED", "no head frame", 0, false);
  const h = await inp.open(first);
  if (h.type !== F_HEAD) throw new SealError("SEAL_BAD_ENVELOPE", "expected head frame", 0, false);
  const meta = JSON.parse(td.decode(h.payload));
  let bodyStream = new ReadableStream({
    async pull(ctl) {
      try {
        const f = await fr.next();
        if (!f) throw new SealError("SEAL_TRUNCATED", "response ended without an end frame", 0, false);
        const { type, payload } = await inp.open(f);
        if (type === F_DATA) ctl.enqueue(payload.slice());
        else if (type === F_END) {
          sess.forget(DIR_S2C, stream);
          ctl.close();
        } else if (type === F_ERROR) {
          let code = "SEAL_UPSTREAM_BROKEN";
          try {
            code = JSON.parse(td.decode(payload)).code || code;
          } catch {
          }
          throw new SealError(code, "upstream body ended early", 0, false);
        } else throw new SealError("SEAL_BAD_ENVELOPE", "unexpected frame type", 0, false);
      } catch (e) {
        sess.forget(DIR_S2C, stream);
        ctl.error(e);
        fr.cancel();
      }
    },
    cancel() {
      sess.forget(DIR_S2C, stream);
      fr.cancel();
    }
  });
  if (NULL_BODY.has(meta.s) || req.method === "HEAD") {
    const rd = bodyStream.getReader();
    while (!(await rd.read()).done) {
    }
    bodyStream = null;
  } else if (meta.z === "gzip") {
    bodyStream = bodyStream.pipeThrough(new DecompressionStream("gzip"));
  }
  return { status: meta.s, statusText: meta.t || "", headers: meta.h || [], body: bodyStream, url: meta.u };
}
function idempotent(m) {
  return m === "GET" || m === "HEAD" || m === "OPTIONS";
}
function retryable(e, method) {
  if (!transientCode(e.code)) return false;
  if (idempotent(method) || e.beforeSend) return true;
  return e.preReplay && [429, 502, 503, 521, 522, 523].includes(e.status);
}
async function sealedRetryWith(ctx, inner, method) {
  const start = Date.now();
  let fresh = 0;
  let renewed = 0;
  for (let attempt = 0; ; attempt++) {
    let err;
    try {
      const sess = await ctx.session(fresh);
      const res = await sealedFetch(sess, inner, ctx.fetchImpl);
      ctx.net.ok();
      ctx.onOk?.();
      return { res };
    } catch (e) {
      if (e?.name === "AbortError") throw e;
      err = e instanceof SealError ? e : new SealError("SEAL_NETWORK", String(e?.message || e), 0, idempotent(method));
    }
    if ((err.code === "SEAL_UNKNOWN_SESSION" || err.code === "SEAL_HS_UNKNOWN_KEY") && renewed++ < 2) {
      fresh = Date.now();
      continue;
    }
    if (!transientCode(err.code)) return { fail: err };
    if (!retryable(err, method)) return { fail: err, visible: true };
    await ctx.net.failure();
    if (ctx.net.graceExpired()) return { fail: err };
    const left = (ctx.budgetMs ?? 35e3) - (Date.now() - start);
    if (left <= 0) return { fail: err, visible: true };
    if (inner.signal?.aborted) throw new DOMException("aborted", "AbortError");
    if (!ctx.net.env.online()) await ctx.net.waitOnline(left);
    else await ctx.net.sleep(Math.min(left, backoff(attempt)));
    fresh = Date.now();
  }
}

// src/mux.ts
var M_OPEN = 16;
var M_OPENED = 17;
var M_TEXT = 18;
var M_BINARY = 19;
var M_CLOSE = 20;
var M_ERROR = 21;
var M_CREDIT = 22;
var M_PING = 23;
var M_PONG = 24;
var FLAG_MORE = 128;
var CHUNK = MAX_PAYLOAD - 4;
var WINDOW = 4 * 1024 * 1024;
var te3 = new TextEncoder();
var td2 = new TextDecoder();
function asSealError(e) {
  if (e instanceof SealError) return e;
  return new SealError("SEAL_NETWORK", String(e?.message || e), 0, true);
}
var Mux = class {
  constructor(getSession, wsURL, wsFactory, opts = {}) {
    this.getSession = getSession;
    this.wsURL = wsURL;
    this.wsFactory = wsFactory;
    this.opts = opts;
    this.ws = null;
    this.ready = null;
    this.sendChain = Promise.resolve();
    this.recvChain = Promise.resolve();
    this.chans = /* @__PURE__ */ new Map();
    this.nextId = 1;
    this.pendingCredit = /* @__PURE__ */ new Map();
    this.creditTimer = null;
    this.pingTimer = null;
    this.lastRecv = 0;
    this.lastTick = 0;
    this.verifying = false;
    this.state = "idle";
    this.lastError = null;
    /** Inner sockets and event streams opened on this mux (status indicator). */
    this.channelsOpened = 0;
    /** mux sockets opened (the first one included) and dropped */
    this.connects = 0;
    this.drops = 0;
    /** wakes from sleep or freeze detected by the keepalive */
    this.wakes = 0;
    this.lastDrop = "";
    this.onFirstPong = null;
    this.net = opts.net || new NetHealth(staticEnv());
    this.pingMs = opts.pingMs || 25e3;
    this.net.on((ev) => {
      if (ev === "online" || ev === "visible" || ev === "resume") this.verify(ev);
    });
  }
  setState(s) {
    if (this.state === s) return;
    this.state = s;
    try {
      this.opts.onState?.(s);
    } catch {
    }
  }
  connect() {
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
  async connectLoop() {
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
      let err = null;
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
        if (++fresh401 > 3) throw new SealError("SEAL_UNKNOWN_SESSION", "mux socket closed with 4401", 4401);
        fresh = true;
        attempt = -1;
        continue;
      }
      if (code === 4403) throw new SealError("SEAL_IDENTITY_MISMATCH", "mux socket closed with 4403", 4403);
      if (code === 4400) throw new SealError("SEAL_MUX_PROTOCOL", "mux socket closed with 4400", 4400);
      if (err && !transientCode(err.code)) throw err;
      await this.net.failure();
      if (this.net.graceExpired()) {
        throw err && err.code !== "SEAL_NETWORK" ? err : new SealError("SEAL_MUX_CONNECT", "mux socket closed with " + (code < 0 ? "network error" : code), code < 0 ? 0 : code);
      }
      this.setState(this.net.env.online() ? "connecting" : "waiting");
      await this.net.sleep(backoff(attempt));
    }
  }
  /** Open the socket and confirm it with a ping/pong exchange. 0 = open, else a close code. */
  dial(sess) {
    const stream = sess.nextStream();
    const ws = this.wsFactory(this.wsURL);
    ws.binaryType = "arraybuffer";
    return new Promise((res) => {
      let settled = false;
      const finish = (code) => {
        if (settled) return;
        settled = true;
        clearTimeout(t);
        if (code === 0) {
          ws.onclose = (ev) => {
            if (this.ws === ws) this.dropped(ev.code, ev.reason);
          };
          this.setState("open");
          this.connects++;
          this.lastRecv = this.lastTick = Date.now();
          clearInterval(this.pingTimer);
          this.pingTimer = setInterval(() => this.tick(), this.pingMs);
        } else {
          if (this.ws === ws) this.ws = null;
          try {
            ws.close();
          } catch {
          }
        }
        res(code);
      };
      const t = setTimeout(() => finish(4408), 15e3);
      ws.onopen = () => {
        ws.send(concat(te3.encode("DSW1"), sess.sid, u64(stream)));
        this.out = new StreamCipher(sess, DIR_C2S, stream);
        this.inp = new StreamCipher(sess, DIR_S2C, stream);
        this.sendChain = Promise.resolve();
        this.recvChain = Promise.resolve();
        this.ws = ws;
        ws.onmessage = (ev) => this.onMessage(ev.data);
        this.onFirstPong = () => finish(0);
        this.frame(M_PING, 0, u64(Date.now()));
      };
      ws.onclose = (ev) => finish(ev.code || 1006);
      ws.onerror = () => {
      };
    });
  }
  /**
   * Keepalive tick. A gap far beyond the interval means the machine slept or
   * the tab was frozen: the socket is probably dead, but that is not a
   * failure of the seal. Verify it and reconnect quietly.
   */
  tick() {
    const now = Date.now();
    const gap = this.lastTick ? now - this.lastTick : 0;
    this.lastTick = now;
    if (gap > this.pingMs * 2 + 1e4) {
      this.wakes++;
      this.net.reset();
      this.verify("wake");
      return;
    }
    if (now - this.lastRecv > 7e4) {
      this.kill("keepalive timeout");
      return;
    }
    this.frame(M_PING, 0, u64(now));
  }
  /** Ping now; no answer within 8 s drops the socket (the channels' owners reconnect). */
  verify(why) {
    if (this.state === "waiting" || this.state === "connecting") {
      this.net.wake();
      return;
    }
    if (this.state !== "open" || this.verifying) return;
    const ws = this.ws;
    const mark = this.lastRecv;
    this.verifying = true;
    this.frame(M_PING, 0, u64(Date.now()));
    setTimeout(() => {
      this.verifying = false;
      if (this.ws === ws && this.lastRecv === mark) this.kill(why === "wake" ? "sleep" : why);
    }, this.opts.verifyMs || 8e3);
  }
  kill(reason) {
    const ws = this.ws;
    try {
      ws?.close(4408, reason);
    } catch {
    }
    this.dropped(1006, reason);
  }
  dropped(code, reason) {
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
  warm() {
    return this.connect();
  }
  /** Test hook: close the outer socket as a network drop would. */
  dropForTest() {
    try {
      this.ws?.close();
    } catch {
    }
  }
  /** Seal and send one frame; ordering is kept by a promise chain. */
  frame(type, ch, payload) {
    const ws = this.ws;
    const out = this.out;
    if (!ws) return;
    const p = out.seal(type, concat(u32(ch), payload));
    this.sendChain = this.sendChain.then(() => p).then((ct) => {
      if (ws.readyState === 1) ws.send(ct);
    }).catch(() => {
    });
  }
  onMessage(data) {
    const p = this.inp.open(new Uint8Array(data));
    this.recvChain = this.recvChain.then(() => p).then(({ type, payload }) => this.dispatch(type, payload)).catch((e) => {
      try {
        this.ws?.close(4400, "SEAL_FRAME_AUTH");
      } catch {
      }
      this.dropped(4400, String(e?.code || e));
    });
  }
  dispatch(type, payload) {
    this.lastRecv = Date.now();
    if (type === M_PONG) {
      if (this.onFirstPong) {
        const f = this.onFirstPong;
        this.onFirstPong = null;
        f();
      }
      return;
    }
    if (type === M_PING) {
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
        c.h.opened(JSON.parse(td2.decode(body)));
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
        const code = body.length >= 2 ? body[0] << 8 | body[1] : 1005;
        c.h.closed(code, td2.decode(body.subarray(2)));
        break;
      }
      case M_ERROR: {
        this.chans.delete(id);
        let j = {};
        try {
          j = JSON.parse(td2.decode(body));
        } catch {
        }
        c.h.failed(new SealError(j.code || "SEAL_MUX_ERROR", j.message || "channel failed", j.status || 0, false));
        break;
      }
    }
  }
  grant(id, n) {
    this.pendingCredit.set(id, (this.pendingCredit.get(id) || 0) + n);
    if ((this.pendingCredit.get(id) || 0) >= 256 * 1024) return this.flushCredit();
    if (!this.creditTimer) this.creditTimer = setTimeout(() => this.flushCredit(), 0);
  }
  flushCredit() {
    clearTimeout(this.creditTimer);
    this.creditTimer = null;
    for (const [id, n] of this.pendingCredit) if (n > 0 && this.chans.has(id)) this.frame(M_CREDIT, id, u32(n));
    this.pendingCredit.clear();
  }
  flush(c) {
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
  open(kind, req, h) {
    const id = this.nextId++;
    this.channelsOpened++;
    const c = { id, h, credit: WINDOW, queue: [], unacked: 0, open: false };
    let gone = false;
    this.connect().then(() => {
      if (gone) return;
      this.chans.set(id, c);
      this.frame(M_OPEN, id, te3.encode(JSON.stringify({ k: kind, ...req })));
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
      close: (code = 1e3, reason = "") => {
        const p = concat(new Uint8Array([code >> 8, code & 255]), te3.encode(reason));
        if (this.chans.has(id)) {
          c.queue.push({ type: M_CLOSE, payload: p });
          this.flush(c);
          if (kind === "http") this.chans.delete(id);
        } else gone = true;
      },
      buffered: () => Math.max(0, c.unacked)
    };
  }
};
function makeSealedWebSocket(Native, getMux, shouldSeal, fallbackAllowed, onFallback, egressOn = () => false, note = () => {
}, natives = /* @__PURE__ */ new Set()) {
  class SealedWebSocket extends EventTarget {
    constructor(url, protocols) {
      super();
      this.CONNECTING = 0;
      this.OPEN = 1;
      this.CLOSING = 2;
      this.CLOSED = 3;
      this.readyState = 0;
      this.protocol = "";
      this.extensions = "";
      this.binaryType = "blob";
      this.onopen = null;
      this.onmessage = null;
      this.onclose = null;
      this.onerror = null;
      this.ch = null;
      this.native = null;
      this.frag = [];
      this.sendChain = Promise.resolve();
      this.discarded = 0;
      const u = new URL(String(url), location.href);
      if (u.protocol === "http:") u.protocol = "ws:";
      if (u.protocol === "https:") u.protocol = "wss:";
      const mux = getMux();
      const same = u.host === location.host && u.protocol === "wss:" === (location.protocol === "https:");
      const cross = !same && (u.protocol === "wss:" || u.protocol === "ws:");
      if (cross && (!egressOn() || !mux)) note("escaped", u.host, "websocket");
      if (!mux || (same ? !shouldSeal(u) : !cross || !egressOn())) {
        return new Native(url, protocols);
      }
      if (u.hash) throw new DOMException("URL has a fragment", "SyntaxError");
      this.url = u.href;
      const prot = protocols === void 0 ? [] : Array.isArray(protocols) ? protocols : [protocols];
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
          let payload;
          if (isText) payload = td2.decode(all);
          else if (this.binaryType === "arraybuffer") payload = all.buffer.slice(all.byteOffset, all.byteOffset + all.byteLength);
          else payload = new Blob([all]);
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
        }
      });
    }
    static {
      this.CONNECTING = 0;
    }
    static {
      this.OPEN = 1;
    }
    static {
      this.CLOSING = 2;
    }
    static {
      this.CLOSED = 3;
    }
    attachNative(url, protocols) {
      const n = new Native(url, protocols);
      this.native = n;
      natives.add(this);
      n.binaryType = this.binaryType;
      n.onopen = () => {
        this.protocol = n.protocol;
        this.readyState = 1;
        this.fire(new Event("open"));
      };
      n.onmessage = (ev) => this.fire(new MessageEvent("message", { data: ev.data, origin: ev.origin }));
      n.onerror = () => this.fire(new Event("error"));
      n.onclose = (ev) => {
        natives.delete(this);
        this.finish(ev.code, ev.reason, ev.wasClean);
      };
    }
    /**
     * The seal works again: end this plain socket the way a network drop
     * would (1006), so its owner reconnects, this time over the seal.
     */
    upgrade(why) {
      const n = this.native;
      natives.delete(this);
      if (!n) return;
      n.onopen = n.onmessage = n.onerror = n.onclose = null;
      try {
        n.close(1e3, "seal restored");
      } catch {
      }
      if (this.readyState < 3) {
        this.fire(new Event("error"));
        this.finish(1006, why, false);
      }
    }
    fire(ev) {
      const h = this["on" + ev.type];
      this.dispatchEvent(ev);
      if (typeof h === "function") h.call(this, ev);
    }
    finish(code, reason, clean) {
      if (this.readyState === 3) return;
      this.readyState = 3;
      this.fire(new CloseEvent("close", { code, reason, wasClean: clean }));
    }
    get bufferedAmount() {
      if (this.native) return this.native.bufferedAmount;
      return (this.ch ? this.ch.buffered() : 0) + this.discarded;
    }
    send(data) {
      if (this.readyState === 0) throw new DOMException("Still in CONNECTING state.", "InvalidStateError");
      if (this.native) {
        this.native.binaryType = this.binaryType;
        return this.native.send(data);
      }
      if (this.readyState !== 1) {
        this.discarded += typeof data === "string" ? te3.encode(data).length : data.byteLength || data.size || 0;
        return;
      }
      const ch = this.ch;
      if (typeof data === "string") {
        const b = te3.encode(data);
        this.sendChain = this.sendChain.then(() => ch.send(true, b));
      } else if (data instanceof Blob) {
        const p = data.arrayBuffer();
        this.sendChain = this.sendChain.then(() => p).then((ab) => ch.send(false, new Uint8Array(ab)));
      } else if (ArrayBuffer.isView(data)) {
        const b = new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
        this.sendChain = this.sendChain.then(() => ch.send(false, b));
      } else {
        const b = new Uint8Array(data.slice(0));
        this.sendChain = this.sendChain.then(() => ch.send(false, b));
      }
    }
    close(code, reason) {
      if (code !== void 0 && code !== 1e3 && (code < 3e3 || code > 4999)) {
        throw new DOMException("invalid close code", "InvalidAccessError");
      }
      if (reason && te3.encode(reason).length > 123) throw new DOMException("reason too long", "SyntaxError");
      if (this.native) return this.native.close(code, reason);
      if (this.readyState >= 2) return;
      if (this.readyState === 0) {
        this.readyState = 2;
        this.ch?.close(1e3, "");
        this.fire(new Event("error"));
        this.finish(1006, "", false);
        return;
      }
      this.readyState = 2;
      const ch = this.ch;
      this.sendChain = this.sendChain.then(() => ch.close(code ?? 1e3, reason ?? ""));
    }
  }
  return SealedWebSocket;
}
function makeSealedEventSource(Native, getMux, shouldSeal, fallbackAllowed, onFallback, egressOn = () => false, note = () => {
}, natives = /* @__PURE__ */ new Set()) {
  class SealedEventSource extends EventTarget {
    constructor(url, init) {
      super();
      this.CONNECTING = 0;
      this.OPEN = 1;
      this.CLOSED = 2;
      this.readyState = 0;
      this.onopen = null;
      this.onmessage = null;
      this.onerror = null;
      this.ch = null;
      this.native = null;
      this.lastId = "";
      this.retry = 3e3;
      this.timer = null;
      this.buf = "";
      this.data = [];
      this.event = "";
      this.dec = new TextDecoder();
      this.cross = false;
      this.forward = null;
      const u = new URL(String(url), location.href);
      this.u = u;
      this.withCredentials = !!init?.withCredentials;
      const cross = u.origin !== location.origin && (u.protocol === "https:" || u.protocol === "http:");
      if (cross && (!egressOn() || !getMux())) note("escaped", u.host, "eventsource");
      if (!getMux() || (cross ? !egressOn() : u.origin !== location.origin || !shouldSeal(u))) {
        return new Native(url, init);
      }
      this.cross = cross;
      if (cross) note("egress", u.host, "eventsource");
      this.url = u.href;
      this.connect();
    }
    static {
      this.CONNECTING = 0;
    }
    static {
      this.OPEN = 1;
    }
    static {
      this.CLOSED = 2;
    }
    fire(ev) {
      const h = this["on" + ev.type];
      this.dispatchEvent(ev);
      if (typeof h === "function") h.call(this, ev);
    }
    connect() {
      const mux = getMux();
      if (!mux) return;
      this.readyState = 0;
      this.buf = "";
      this.data = [];
      this.event = "";
      this.dec = new TextDecoder();
      const h = [["Accept", "text/event-stream"], ["Cache-Control", "no-cache"]];
      if (this.lastId) h.push(["Last-Event-ID", this.lastId]);
      let ok = false;
      this.ch = mux.open("http", { m: "GET", u: this.cross ? this.url : this.u.pathname + this.u.search, h, md: "cors", dt: "empty" }, {
        opened: (info) => {
          const ct = (info.h || []).find(([k]) => k.toLowerCase() === "content-type")?.[1] || "";
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
        data: (_t, data) => {
          if (ok && this.readyState === 1) this.feed(this.dec.decode(data, { stream: true }));
        },
        closed: () => this.lost(),
        failed: (err) => {
          if (!ok && err.preReplay && fallbackAllowed()) {
            onFallback(err.code);
            const n = new Native(this.url, { withCredentials: this.withCredentials });
            this.native = n;
            natives.add(this);
            n.onopen = () => {
              this.readyState = 1;
              this.fire(new Event("open"));
            };
            n.onerror = () => {
              this.readyState = n.readyState;
              this.fire(new Event("error"));
            };
            n.onmessage = (ev) => this.fire(new MessageEvent("message", { data: ev.data, lastEventId: ev.lastEventId, origin: ev.origin }));
            const orig = n.addEventListener.bind(n);
            this.forward = (type) => orig(type, (ev) => {
              const me = ev;
              this.fire(new MessageEvent(type, { data: me.data, lastEventId: me.lastEventId, origin: me.origin }));
            });
            return;
          }
          this.lost();
        }
      });
    }
    addEventListener(type, cb, opts) {
      super.addEventListener(type, cb, opts);
      if (this.forward && !["open", "error", "message"].includes(type)) this.forward(type);
    }
    lost() {
      if (this.readyState === 2) return;
      this.readyState = 0;
      this.fire(new Event("error"));
      if (this.readyState === 2) return;
      clearTimeout(this.timer);
      this.timer = setTimeout(() => {
        if (this.readyState !== 2) this.connect();
      }, this.retry);
    }
    feed(text) {
      this.buf += text;
      for (; ; ) {
        const m = /\r\n|\r|\n/.exec(this.buf);
        if (!m) return;
        if (m[0] === "\r" && m.index === this.buf.length - 1) return;
        const line = this.buf.slice(0, m.index);
        this.buf = this.buf.slice(m.index + m[0].length);
        this.line(line);
      }
    }
    line(line) {
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
    upgrade(_why) {
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
      if (this.native) {
        this.native.close();
        natives.delete(this);
      }
      this.readyState = 2;
      clearTimeout(this.timer);
      this.ch?.close();
    }
  }
  return SealedEventSource;
}

// src/state.ts
var ESCAPE_RECENT_MS = 5 * 60 * 1e3;
function decide(i) {
  if (i.warning) return { state: "warning", reason: "SEAL_TOFU_MISMATCH" };
  if (!i.controlled) return { state: "plain", reason: "worker: not-controlling" };
  if (!i.swOk) return { state: "plain", reason: "worker: " + (i.swReason || "no sealed session") };
  if (i.nativeLive > 0) return { state: "plain", reason: "fallback: " + i.nativeLive + (i.nativeLive === 1 ? " socket is" : " sockets are") + " still plain" };
  if (i.swFallbackMode) return { state: "plain", reason: "fallback: the sealed path is failing, requests go plain" };
  if (i.lastPlainAt && i.lastPlainAt >= i.lastHealthyAt) return { state: "plain", reason: "fallback: requests went plain, the sealed path has not recovered yet" };
  const current = Object.keys(i.escapedAt).filter((h) => i.egressOff || i.now - i.escapedAt[h] < ESCAPE_RECENT_MS);
  if (current.length) {
    return { state: "plain", reason: "escaped: " + current.slice(0, 3).map((h) => h + (i.escapedWhy[h] ? " (" + i.escapedWhy[h] + ")" : "")).join(", ") + (current.length > 3 ? " and " + (current.length - 3) + " more" : "") };
  }
  return { state: "sealed", reason: "" };
}
function hhmm(t) {
  const d = new Date(t);
  return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
}
function historyLines(events, max = 6) {
  const groups = /* @__PURE__ */ new Map();
  for (const e of [...events].sort((a, b) => a.t - b.t)) {
    const k = hhmm(e.t) + "|" + e.kind + "|" + e.why;
    const g = groups.get(k);
    if (g) g.n += e.n || 1;
    else groups.set(k, { t: e.t, kind: e.kind, why: e.why, n: e.n || 1 });
  }
  const lines = [...groups.values()].map((g) => {
    const at = " at " + hhmm(g.t) + (g.why ? " (" + g.why + ")" : "");
    switch (g.kind) {
      case "plain":
        return g.n + (g.n === 1 ? " request went plain" : " requests went plain") + at;
      case "escaped":
        return g.n + (g.n === 1 ? " connection went direct" : " connections went direct") + at;
      case "failed":
        return g.n + (g.n === 1 ? " request failed (not resent in plain)" : " requests failed (not resent in plain)") + at;
      default:
        return "page not controlled by the worker" + at;
    }
  });
  return lines.length > max ? [...lines.slice(0, 1), "...", ...lines.slice(-(max - 2))] : lines;
}
function pushEvent(list, e, cap = 200) {
  const last = list[list.length - 1];
  if (last && last.kind === e.kind && last.why === e.why && e.t - last.t < 6e4) {
    last.n = (last.n || 1) + (e.n || 1);
    return;
  }
  list.push(e);
  if (list.length > cap) list.splice(0, list.length - cap);
}
export {
  DIR_C2S,
  DIR_S2C,
  EPOCH_SHIFT,
  ESCAPE_RECENT_MS,
  FLAG_MORE,
  F_DATA,
  F_END,
  F_ERROR,
  F_HEAD,
  FrameReader,
  GAP_MS,
  GRACE_MS,
  IDBKV,
  LABEL,
  MAX_FRAME,
  MAX_PAYLOAD,
  M_BINARY,
  M_CLOSE,
  M_CREDIT,
  M_ERROR,
  M_OPEN,
  M_OPENED,
  M_PING,
  M_PONG,
  M_TEXT,
  MemoryKV,
  Mux,
  NULL_BODY,
  NetHealth,
  PIN_KEY,
  SEALED_ONLY_KEY,
  SealError,
  Session,
  StreamCipher,
  b64u,
  backoff,
  browserEnv,
  concat,
  decide,
  establish,
  fingerprint,
  historyLines,
  idempotent,
  lengthPrefix,
  makeSealedEventSource,
  makeSealedWebSocket,
  masterKey,
  outerError,
  pushEvent,
  retryable,
  sealedFetch,
  sealedRetryWith,
  staticEnv,
  transcriptHash,
  transientCode,
  u32,
  u64,
  unb64u,
  verifyBundle,
  verifyConfirm
};
