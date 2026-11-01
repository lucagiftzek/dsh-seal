// Sealed fetch: one inner HTTP request per POST /_s/x, response streamed back
// in sealed frames (so event streams and large downloads stay incremental).

import {
  concat, DIR_C2S, DIR_S2C, F_DATA, F_END, F_ERROR, F_HEAD, FetchLike, FrameReader, lengthPrefix,
  MAX_PAYLOAD, outerError, SealError, Session, StreamCipher, u64,
} from "./seal";
import { backoff, NetHealth, transientCode } from "./net";

const te = new TextEncoder();
const td = new TextDecoder();

export interface InnerRequest {
  method: string;
  url: string; // path + query, starting with "/"
  headers: [string, string][];
  body?: Uint8Array | null;
  mode?: string;
  dest?: string;
  /** egress: the page request's redirect mode (follow, error, manual) */
  redirect?: string;
  signal?: AbortSignal | null;
}

export interface InnerResponse {
  status: number;
  statusText: string;
  headers: [string, string][];
  /** already decompressed when the server forwarded gzip */
  body: ReadableStream<Uint8Array> | null;
  /** egress: the URL that answered, after redirects */
  url?: string;
}

/** Statuses whose responses must not carry a body. */
export const NULL_BODY = new Set([101, 103, 204, 205, 304]);

export async function sealedFetch(sess: Session, req: InnerRequest, fetchImpl: FetchLike): Promise<InnerResponse> {
  const stream = sess.nextStream();
  const out = new StreamCipher(sess, DIR_C2S, stream);
  const body = req.body || new Uint8Array(0);
  const head = te.encode(JSON.stringify({ m: req.method, u: req.url, h: req.headers, n: body.length, md: req.mode || "", dt: req.dest || "", ...(req.redirect ? { rd: req.redirect } : {}) }));
  const parts: Uint8Array[] = [te.encode("DSX1"), sess.sid, u64(stream)];
  parts.push(lengthPrefix(await out.seal(F_HEAD, head)));
  for (let o = 0; o < body.length; o += MAX_PAYLOAD) {
    parts.push(lengthPrefix(await out.seal(F_DATA, body.subarray(o, Math.min(body.length, o + MAX_PAYLOAD)))));
  }
  parts.push(lengthPrefix(await out.seal(F_END, new Uint8Array(0))));
  sess.forget(DIR_C2S, stream);

  let r: Response;
  try {
    r = await fetchImpl(sess.base + "/_s/x", {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: concat(...parts) as BodyInit,
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: req.signal || undefined,
    });
  } catch (e) {
    if ((e as Error)?.name === "AbortError") throw e;
    // The request may or may not have reached the server: not safe to
    // replay in plain for non-idempotent methods.
    const idem = req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS";
    throw new SealError("SEAL_NETWORK", String((e as Error)?.message || e), 0, idem);
  }
  if (!r.ok || !r.body) throw await outerError(r);

  const inp = new StreamCipher(sess, DIR_S2C, stream);
  const fr = new FrameReader(r.body.getReader());
  const first = await fr.next();
  if (!first) throw new SealError("SEAL_TRUNCATED", "no head frame", 0, false);
  const h = await inp.open(first);
  if (h.type !== F_HEAD) throw new SealError("SEAL_BAD_ENVELOPE", "expected head frame", 0, false);
  const meta = JSON.parse(td.decode(h.payload)) as { s: number; t?: string; h: [string, string][]; z?: string; u?: string };

  let bodyStream: ReadableStream<Uint8Array> | null = new ReadableStream<Uint8Array>({
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
          try { code = JSON.parse(td.decode(payload)).code || code; } catch { /* keep default */ }
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
    },
  });
  if (NULL_BODY.has(meta.s) || req.method === "HEAD") {
    // drain to END so the frame order is verified, but expose no body
    const rd = bodyStream!.getReader();
    while (!(await rd.read()).done) { /* drain */ }
    bodyStream = null;
  } else if (meta.z === "gzip") {
    bodyStream = bodyStream!.pipeThrough(new DecompressionStream("gzip") as unknown as ReadableWritablePair<Uint8Array, Uint8Array>);
  }
  return { status: meta.s, statusText: meta.t || "", headers: meta.h || [], body: bodyStream, url: meta.u };
}

// Resilience ---------------------------------------------------

export interface RetryCtx {
  /** a session started at or after the given time (0 = any) */
  session(after: number): Promise<Session>;
  net: NetHealth;
  fetchImpl: FetchLike;
  /** how long one request may wait for the sealed path (default 35 s) */
  budgetMs?: number;
  onOk?: () => void;
}

export function idempotent(m: string) {
  return m === "GET" || m === "HEAD" || m === "OPTIONS";
}

/**
 * May a transient failure be retried? Idempotent requests always; others only
 * when the inner request surely never reached DSH: the handshake failed, or a
 * proxy in front of dsh-seal answered (dsh-seal restarting) with a status that
 * means "not forwarded". A network error after sending may have run upstream:
 * never replayed, never sent plain, it fails visibly.
 */
export function retryable(e: SealError, method: string): boolean {
  if (!transientCode(e.code)) return false;
  if (idempotent(method) || (e as any).beforeSend) return true;
  return e.preReplay && [429, 502, 503, 521, 522, 523].includes(e.status);
}

export type Outcome = { res: InnerResponse } | { fail: SealError; visible?: boolean };

/**
 * One sealed request with the resilience rules: a lost session re-handshakes,
 * a transient failure (offline, a proxy restarting, the machine waking up)
 * is retried after a fresh handshake with backoff and jitter. The result is a
 * response, or a failure the caller may turn into a plain fallback (offer
 * mode, grace window expired with the network up, safe to replay) or, with
 * visible set, into a network error (never plain).
 */
export async function sealedRetryWith(ctx: RetryCtx, inner: InnerRequest, method: string): Promise<Outcome> {
  const start = Date.now();
  let fresh = 0;
  let renewed = 0;
  for (let attempt = 0; ; attempt++) {
    let err: SealError;
    try {
      const sess = await ctx.session(fresh);
      const res = await sealedFetch(sess, inner, ctx.fetchImpl);
      ctx.net.ok();
      ctx.onOk?.();
      return { res };
    } catch (e: any) {
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
    const left = (ctx.budgetMs ?? 35000) - (Date.now() - start);
    if (left <= 0) return { fail: err, visible: true };
    if (inner.signal?.aborted) throw new DOMException("aborted", "AbortError");
    if (!ctx.net.env.online()) await ctx.net.waitOnline(left);
    else await ctx.net.sleep(Math.min(left, backoff(attempt)));
    fresh = Date.now(); // a fresh handshake before the retry (shared by parallel requests)
  }
}
