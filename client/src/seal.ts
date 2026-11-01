// dsh-seal client core: bundle verification (silent TOFU with signed
// rotations), handshake, per stream AES-256-GCM ciphers and frame helpers.
// It runs unchanged in the page, in the service worker and in Node 22+
// (WebCrypto is the same API everywhere). docs/PROTOCOL.md is normative.

export const LABEL = "dsh-seal/1";
export const DIR_C2S = 0x63; // 'c'
export const DIR_S2C = 0x73; // 's'
export const F_HEAD = 0x01;
export const F_DATA = 0x02;
export const F_END = 0x03;
export const F_ERROR = 0x04;
export const EPOCH_SHIFT = 16;
export const MAX_PAYLOAD = 64 * 1024;
export const MAX_FRAME = MAX_PAYLOAD + 64;

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();

export interface Link { prev: string; next: string; t: number; sig: string }
export interface KXCert { kid: string; pub: string; nbf: number; exp: number; sig: string }
export interface Bundle { v: number; id: string; fp: string; chain: Link[] | null; kx: KXCert }
export interface ClientCfg { mode: string; shell: string[]; exclude: string[]; sealedOnly: boolean; version: string; egress?: boolean; webrtc?: string }
export interface SealConfig { bundle: Bundle; cfg: ClientCfg }

/** A stable SEAL_* error code travels with every failure. */
export class SealError extends Error {
  code: string;
  status: number;
  /** true when the server rejected the request before replaying it upstream */
  preReplay: boolean;
  constructor(code: string, message: string, status = 0, preReplay = true) {
    super(code + ": " + message);
    this.code = code;
    this.status = status;
    this.preReplay = preReplay;
  }
}

// Encoding helpers ---------------------------------------------------------------

export function b64u(buf: ArrayBuffer | Uint8Array): string {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64u(s: string): Uint8Array {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "===".slice((t.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function concat(...parts: (Uint8Array | ArrayBuffer)[]): Uint8Array {
  let n = 0;
  const arr = parts.map((p) => (p instanceof Uint8Array ? p : new Uint8Array(p)));
  for (const p of arr) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of arr) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function u64(n: number): Uint8Array {
  const b = new Uint8Array(8);
  const v = new DataView(b.buffer);
  v.setUint32(0, Math.floor(n / 0x100000000));
  v.setUint32(4, n >>> 0);
  return b;
}

export function u32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0);
  return b;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest("SHA-256", data as BufferSource));
}

export async function fingerprint(idRaw: Uint8Array): Promise<string> {
  return b64u(await sha256(concat(te.encode(LABEL + " id"), new Uint8Array([0]), idRaw)));
}

function kxCertMessage(kxRaw: Uint8Array, nbf: number, exp: number): Uint8Array {
  return concat(te.encode(LABEL + " kx"), new Uint8Array([0]), kxRaw, u64(nbf), u64(exp));
}

function rotationMessage(prev: Uint8Array, next: Uint8Array, t: number): Uint8Array {
  return concat(te.encode(LABEL + " rot"), new Uint8Array([0]), prev, next, u64(t));
}

async function verifySig(pubRaw: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<boolean> {
  try {
    const k = await subtle.importKey("raw", pubRaw as BufferSource, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, k, sig as BufferSource, msg as BufferSource);
  } catch {
    return false;
  }
}

// TOFU store ----------------------------------------------------------------------------

/** Persistent per-browser storage for the pinned fingerprint and flags. */
export interface KV {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string): Promise<void>;
}

export class MemoryKV implements KV {
  m = new Map<string, string>();
  async get(k: string) { return this.m.get(k); }
  async set(k: string, v: string) { this.m.set(k, v); }
}

/** IndexedDB store shared by the page and the service worker (same origin). */
export class IDBKV implements KV {
  private db: Promise<IDBDatabase>;
  constructor(name = "dsh-seal") {
    this.db = new Promise((res, rej) => {
      const r = indexedDB.open(name, 1);
      r.onupgradeneeded = () => r.result.createObjectStore("kv");
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
  }
  async get(k: string): Promise<string | undefined> {
    const db = await this.db;
    return new Promise((res, rej) => {
      const q = db.transaction("kv", "readonly").objectStore("kv").get(k);
      q.onsuccess = () => res(q.result as string | undefined);
      q.onerror = () => rej(q.error);
    });
  }
  async set(k: string, v: string): Promise<void> {
    const db = await this.db;
    return new Promise((res, rej) => {
      const t = db.transaction("kv", "readwrite");
      t.objectStore("kv").put(v, k);
      t.oncomplete = () => res();
      t.onerror = () => rej(t.error);
    });
  }
}

export const PIN_KEY = "idfp";
export const SEALED_ONLY_KEY = "sealedOnly";

/**
 * Verify a bundle: the key exchange key must be signed by the bundle identity,
 * and if the browser pinned another identity before, a valid chain of signed
 * rotations must lead from the pin to the new identity. Returns the
 * fingerprint to pin. Throws SEAL_TOFU_MISMATCH or SEAL_BUNDLE_*.
 */
export async function verifyBundle(b: Bundle, trusted: string | undefined, nowSec = Date.now() / 1000): Promise<string> {
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
    if ((await fingerprint(prev)) !== cur) continue;
    const next = unb64u(l.next);
    if (!(await verifySig(prev, rotationMessage(prev, next, l.t), unb64u(l.sig)))) {
      throw new SealError("SEAL_TOFU_MISMATCH", "invalid rotation link");
    }
    cur = await fingerprint(next);
    if (cur === fp) return fp;
  }
  throw new SealError("SEAL_TOFU_MISMATCH", "server identity changed without a signed rotation");
}

// Session ------------------------------------------------------------------------------

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export class Session {
  sid: Uint8Array;
  ms: CryptoKey;
  fp: string;
  base: string;
  /** When the handshake completed (ms since the epoch). */
  created = Date.now();
  private next = 1;
  private keys = new Map<string, Promise<CryptoKey>>();
  constructor(sid: Uint8Array, ms: CryptoKey, fp: string, base: string) {
    this.sid = sid;
    this.ms = ms;
    this.fp = fp;
    this.base = base;
  }
  /** Fresh stream id (replay protection: each id is accepted once). */
  nextStream(): number {
    return this.next++;
  }
  streamKey(dir: number, stream: number, epoch: number): Promise<CryptoKey> {
    const id = dir + ":" + stream + ":" + epoch;
    let k = this.keys.get(id);
    if (!k) {
      const info = concat(te.encode(LABEL + " k"), new Uint8Array([dir]), u64(stream), u32(epoch));
      k = subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: info as BufferSource },
        this.ms,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
      );
      this.keys.set(id, k);
      if (this.keys.size > 256) this.keys.delete(this.keys.keys().next().value as string);
    }
    return k;
  }
  forget(dir: number, stream: number) {
    for (const k of [...this.keys.keys()]) if (k.startsWith(dir + ":" + stream + ":")) this.keys.delete(k);
  }
}

/**
 * Verify the bundle (TOFU), then run the handshake against base + "/_s/h".
 */
export async function establish(conf: SealConfig, kv: KV, fetchImpl: FetchLike, base = ""): Promise<Session> {
  const b = conf.bundle;
  const pinned = await kv.get(PIN_KEY);
  const fp = await verifyBundle(b, pinned);
  if (fp !== pinned) await kv.set(PIN_KEY, fp);

  const pair = (await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
  const cpub = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  const r = await fetchImpl(base + "/_s/h", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ v: 1, kid: b.kx.kid, cpub: b64u(cpub) }),
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
  });
  if (!r.ok) throw await outerError(r);
  const hs = (await r.json()) as { v: number; sid: string; sn: string; cf: string };
  const sid = unb64u(hs.sid);
  const sn = unb64u(hs.sn);
  const kxRaw = unb64u(b.kx.pub);
  const kxKey = await subtle.importKey("raw", kxRaw as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await subtle.deriveBits({ name: "ECDH", public: kxKey }, pair.privateKey, 256);
  const th = await transcriptHash(unb64u(b.id), kxRaw, cpub, sid, sn);
  const ms = await masterKey(shared, th);
  if (!(await verifyConfirm(ms, th, unb64u(hs.cf)))) {
    throw new SealError("SEAL_HS_CONFIRM", "server could not prove the session key");
  }
  return new Session(sid, ms, fp, base);
}

export async function outerError(r: Response): Promise<SealError> {
  let code = r.headers.get("x-seal-error") || "";
  let msg = "HTTP " + r.status;
  try {
    const j = await r.json();
    code = j.code || code;
    msg = j.message || msg;
  } catch {
    /* not JSON */
  }
  // A 404 that dsh-seal did not answer (no X-Seal-Error) means traefik no
  // longer routes through dsh-seal: the worker retires itself.
  if (!code && r.status === 404) code = "SEAL_ABSENT";
  return new SealError(code || "SEAL_HTTP_" + r.status, msg, r.status, true);
}

// Stream cipher ----------------------------------------------------------------------

/**
 * One direction of one stream. Sequence numbers are implicit: callers must
 * seal and open frames strictly in wire order (seq is taken synchronously at
 * call time, so issuing calls in order is enough even though they resolve
 * asynchronously).
 */
export class StreamCipher {
  private seq = 0;
  constructor(private sess: Session, private dir: number, private stream: number) {}
  private parts(seq: number) {
    const nonce = concat(new Uint8Array(4), u64(seq));
    const aad = concat(te.encode(LABEL), this.sess.sid, new Uint8Array([this.dir]), u64(this.stream), u64(seq));
    return { nonce, aad, epoch: Math.floor(seq / 2 ** EPOCH_SHIFT) };
  }
  async seal(type: number, payload: Uint8Array): Promise<Uint8Array> {
    if (payload.length > MAX_PAYLOAD) throw new SealError("SEAL_FRAME_TOO_LARGE", "payload too large");
    const { nonce, aad, epoch } = this.parts(this.seq++);
    const key = await this.sess.streamKey(this.dir, this.stream, epoch);
    const pt = new Uint8Array(1 + payload.length);
    pt[0] = type;
    pt.set(payload, 1);
    return new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource }, key, pt));
  }
  async open(ct: Uint8Array): Promise<{ type: number; payload: Uint8Array }> {
    if (ct.length > MAX_FRAME) throw new SealError("SEAL_FRAME_TOO_LARGE", "frame too large", 0, false);
    const { nonce, aad, epoch } = this.parts(this.seq++);
    const key = await this.sess.streamKey(this.dir, this.stream, epoch);
    let pt: Uint8Array;
    try {
      pt = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource }, key, ct as BufferSource));
    } catch {
      throw new SealError("SEAL_FRAME_AUTH", "frame failed authentication", 0, false);
    }
    if (pt.length === 0) throw new SealError("SEAL_FRAME_EMPTY", "empty frame", 0, false);
    return { type: pt[0], payload: pt.subarray(1) };
  }
}

/** [u32 BE length][ciphertext] */
export function lengthPrefix(ct: Uint8Array): Uint8Array {
  return concat(u32(ct.length), ct);
}

/** Incremental reader of length-prefixed frames from a byte stream. */
export class FrameReader {
  private buf: Uint8Array = new Uint8Array(0);
  private done = false;
  constructor(private reader: ReadableStreamDefaultReader<Uint8Array>) {}
  async next(): Promise<Uint8Array | null> {
    for (;;) {
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
    this.reader.cancel().catch(() => {});
  }
}

// Key schedule building blocks (exported for the interop vectors) -----------------

export async function transcriptHash(idRaw: Uint8Array, kxRaw: Uint8Array, cpub: Uint8Array, sid: Uint8Array, sn: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(te.encode(LABEL + " hs"), new Uint8Array([0]), idRaw, kxRaw, cpub, sid, sn));
}

/** Master secret as a non-extractable HKDF key: HKDF(ikm = ECDH x, salt = th). */
export async function masterKey(shared: ArrayBuffer | Uint8Array, th: Uint8Array): Promise<CryptoKey> {
  const ikm = await subtle.importKey("raw", shared as BufferSource, "HKDF", false, ["deriveBits"]);
  const msBits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: th as BufferSource, info: te.encode(LABEL + " ms") }, ikm, 256);
  return subtle.importKey("raw", msBits, "HKDF", false, ["deriveBits", "deriveKey"]);
}

export async function verifyConfirm(ms: CryptoKey, th: Uint8Array, cf: Uint8Array): Promise<boolean> {
  const ckBits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: te.encode(LABEL + " cf") }, ms, 256);
  const ck = await subtle.importKey("raw", ckBits, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  return subtle.verify("HMAC", ck, cf as BufferSource, th as BufferSource);
}
