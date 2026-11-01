// sw.js: the sealing service worker. Every same-origin request of the pages
// it controls (API calls, plugin routes, assets, report pages and their
// queries) travels inside a sealed envelope through POST /_s/x. Exceptions:
// /_s/* itself, the shell navigation (it must stay plain so dsh-seal can inject
// boot.js), and the prefixes other traefik services own.
//
// Sealed egress: requests of controlled pages to OTHER hosts (images, fonts,
// scripts, styles, media with Range, fetch/XHR) travel the same way with an
// absolute URL; dsh-seal fetches them from the internet and streams them back
// sealed. A refusal of the server (private address, deny list, rate) becomes a
// network error here ("blocked"); a request that goes out directly (no session,
// or egress=off) is counted as "escaped".

import { establish, IDBKV, SealConfig, SealError, SEALED_ONLY_KEY, Session } from "./seal";
import { InnerRequest, InnerResponse, NULL_BODY, RetryCtx, sealedRetryWith } from "./fetch";
import { neutralizeFramesText, neutralizeHintsText, hintLinkHeader } from "./hints";
import { browserEnv, NetHealth } from "./net";
import { pushEvent, SealEvent } from "./state";

declare const self: any;

const conf: SealConfig = self.__DSH_SEAL_CFG;
const cfg = conf.cfg;
const kv = new IDBKV();
const CACHE = "dsh-seal-http-v1";
let sessP: Promise<Session> | null = null;
let lastError = "";
let sealedOnly = !!cfg.sealedOnly;
let disabled = false;
let egressOff = false; // the server answered SEAL_EGRESS_OFF: egress=off was reloaded, go direct
// Network health: a failing sealed request is retried; offer mode falls back to
// plain only after the grace window with the network demonstrably up.
const net = new NetHealth(browserEnv("/_s/p"));
/** how long one request may wait for the sealed path before it gives up */
const BUDGET_MS = 35000;
let lastHealthyAt = 0; // last sealed answer of this worker (any page)

kv.get(SEALED_ONLY_KEY).then((v) => { if (v === "1") sealedOnly = true; }).catch(() => {});

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e: any) => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k.startsWith("dsh-seal-") && k !== CACHE) await caches.delete(k);
    // take every open page in scope at once (also pages loaded before this worker)
    await self.clients.claim();
  })());
});

let sessStarted = 0;
function session(fresh = false): Promise<Session> {
  if (!sessP || fresh) {
    sessStarted = Date.now();
    sessP = establish(conf, kv, (i, init) => fetch(i, init), self.location.origin).catch((e) => {
      sessP = null;
      // a fetch that threw during the handshake: the network, not the seal
      const err = e instanceof SealError ? e : new SealError("SEAL_NETWORK", String(e?.message || e), 0, true);
      (err as any).beforeSend = true;
      lastError = err.code;
      throw err;
    });
  }
  return sessP;
}

/** A session started at or after t (one fresh handshake shared by every retry). */
function sessionAfter(t: number): Promise<Session> {
  return session(!(sessP && sessStarted >= t));
}

self.addEventListener("message", (e: any) => {
  const d = e.data || {};
  if (d.t === "dsh-seal-status") {
    session().then(
      () => {
        const pc = perClient.get(e.source?.id || "") || newPC();
        e.ports[0]?.postMessage({
          ok: !disabled, reason: disabled ? "disabled" : "", fallbacks, sealed: pc.sealed, pageFallbacks: pc.fallbacks, lastFallback: pc.last,
          egress: pc.egress, blocked: pc.blocked, escaped: pc.escaped, handled: pc.handled,
          escapedAt: pc.escapedAt, events: pc.events, lastPlainAt: pc.lastPlainAt, lastHealthyAt,
          fallbackMode: net.graceExpired(), egressOff, failed: pc.failed,
        });
      },
      (err) => {
        const pc = perClient.get(e.source?.id || "") || newPC();
        e.ports[0]?.postMessage({ ok: false, reason: err?.code || String(err), egress: pc.egress, blocked: pc.blocked, escaped: pc.escaped,
          escapedAt: pc.escapedAt, events: pc.events, lastPlainAt: pc.lastPlainAt, lastHealthyAt, fallbackMode: net.graceExpired(), egressOff, failed: pc.failed });
      },
    );
  } else if (d.t === "dsh-seal-claim") {
    // second line of defence for a page the worker does not control (hard reload)
    e.waitUntil(self.clients.claim().then(() => e.ports?.[0]?.postMessage({ ok: true }), () => e.ports?.[0]?.postMessage({ ok: false })));
  } else if (d.t === "dsh-seal-sealed-only") {
    sealedOnly = !!d.on || !!cfg.sealedOnly;
  }
});

function isShell(p: string) {
  return cfg.shell.some((s) => (s.endsWith("*") ? p.startsWith(s.slice(0, -1)) : p === s));
}

self.addEventListener("fetch", (e: any) => {
  const req: Request = e.request;
  const u = new URL(req.url);
  const cid = e.clientId || e.resultingClientId || "";
  if (disabled) return;
  if (u.origin !== self.location.origin) {
    if ((u.protocol !== "https:" && u.protocol !== "http:") || req.mode === "navigate") return;
    if (!cfg.egress || egressOff) {
      note(cid, "escaped", u.host, "egress off");
      return;
    }
    handledURL(cid, req.url);
    e.respondWith(egress(req, u, cid));
    return;
  }
  if (u.pathname.startsWith("/_s/") || cfg.exclude.some((x) => u.pathname.startsWith(x))) return;
  if (req.mode === "navigate" && isShell(u.pathname)) return;
  if (req.cache === "only-if-cached" && req.mode !== "same-origin") return;
  e.respondWith(handle(req, u, cid));
});

let fallbacks = 0;

// Counters per page (client id), read by that page's status indicator.
interface PC {
  sealed: number;
  fallbacks: number;
  failed: number; // requests failed visibly instead of going plain
  last: string;
  lastPlainAt: number;
  events: SealEvent[];
  escapedAt: Record<string, number>;
  egress: Record<string, number>;
  blocked: Record<string, string>;
  escaped: Record<string, string>;
  handled: string[]; // recent cross-origin URLs this worker answered (escape check)
}
function newPC(): PC {
  return { sealed: 0, fallbacks: 0, failed: 0, last: "", lastPlainAt: 0, events: [], escapedAt: {}, egress: {}, blocked: {}, escaped: {}, handled: [] };
}
function handledURL(id: string, url: string) {
  const c = pc(id);
  if (!c) return;
  c.handled.push(url);
  if (c.handled.length > 600) c.handled.splice(0, 100);
}
const perClient = new Map<string, PC>();
function pc(id: string): PC | null {
  if (!id) return null;
  let c = perClient.get(id);
  if (!c) {
    c = newPC();
    perClient.set(id, c);
    if (perClient.size > 64) perClient.delete(perClient.keys().next().value as string);
  }
  return c;
}
function count(id: string, sealed: boolean, why = "") {
  const c = pc(id);
  if (!c) return;
  if (sealed) c.sealed++;
  else {
    c.fallbacks++;
    c.last = why;
    c.lastPlainAt = Date.now();
    pushEvent(c.events, { t: c.lastPlainAt, kind: "plain", why: why.split(" ")[0] });
  }
}
function failedVisibly(id: string, why: string) {
  const c = pc(id);
  if (!c) return;
  c.failed++;
  pushEvent(c.events, { t: Date.now(), kind: "failed", why });
}
function note(id: string, kind: "egress" | "blocked" | "escaped", host: string, why: string) {
  const c = pc(id);
  if (!c) return;
  if (kind === "egress") {
    if (host in c.egress || Object.keys(c.egress).length < 64) c.egress[host] = (c.egress[host] || 0) + 1;
    return;
  }
  const m = kind === "blocked" ? c.blocked : c.escaped;
  if (!(host in m) && Object.keys(m).length < 64) m[host] = why;
  if (kind === "escaped" && host in m) {
    c.escapedAt[host] = Date.now();
    pushEvent(c.events, { t: Date.now(), kind: "escaped", why: host + ": " + why });
  }
}

const retryCtx: RetryCtx = {
  session: (after) => sessionAfter(after),
  net,
  fetchImpl: (i, init) => fetch(i, init),
  budgetMs: BUDGET_MS,
  onOk: () => { lastHealthyAt = Date.now(); },
};
function sealedRetry(inner: InnerRequest, method: string) {
  return sealedRetryWith(retryCtx, inner, method);
}

async function bodyOf(req: Request, method: string): Promise<Uint8Array | null> {
  if (method === "GET" || method === "HEAD") return null;
  return new Uint8Array(await req.clone().arrayBuffer());
}

function replay(req: Request, method: string, body: Uint8Array | null): Promise<Response> {
  return fetch(body ? new Request(req.url, { method, headers: req.headers, body: body as BodyInit, credentials: req.credentials, cache: req.cache, redirect: req.redirect, referrer: req.referrer, integrity: req.integrity, signal: req.signal }) : req);
}

function toResponse(res: InnerResponse, drop: (k: string) => boolean = () => false): Response {
  const headers = new Headers();
  for (const [k, v] of res.headers) {
    if (drop(k.toLowerCase())) continue;
    try { headers.append(k, v); } catch { /* invalid for the Headers class */ }
  }
  const status = res.status >= 200 && res.status <= 599 ? res.status : 502;
  return new Response(NULL_BODY.has(status) ? null : res.body, { status, statusText: res.statusText, headers });
}

/** Store long-lived answers in the worker cache and return the response. */
function maybeCache(req: Request, u: URL, response: Response, cacheable: boolean): Response {
  if (!(cacheable && response.status === 200 && isCacheable(response.headers))) return response;
  const [a, b] = response.body ? response.body.tee() : [null, null];
  const stored = new Response(b, { status: 200, headers: withStamp(response.headers) });
  caches.open(CACHE).then(async (c) => {
    await pruneSiblings(c, u);
    await c.put(req.url, stored);
  }).catch(() => {});
  return new Response(a, { status: 200, statusText: response.statusText, headers: response.headers });
}

async function handle(req: Request, u: URL, clientId: string): Promise<Response> {
  const method = req.method.toUpperCase();
  const cacheable = method === "GET" && !req.headers.has("range");
  if (cacheable && req.cache !== "no-store" && req.cache !== "reload") {
    const hit = await fromCache(req);
    if (hit) return hit;
  }
  const body = await bodyOf(req, method);
  const inner = {
    method,
    url: u.pathname + u.search,
    headers: [...req.headers] as [string, string][],
    body,
    mode: req.mode,
    dest: req.destination || "empty",
    signal: req.signal,
  };
  const out = await sealedRetry(inner, method);
  if (!("res" in out)) {
    const e = out.fail;
    const code = e.code || "SEAL_UNKNOWN";
    lastError = code;
    if (code === "SEAL_DISABLED" || code === "SEAL_ABSENT") {
      // Kill switch: dsh-seal went back to passthrough. Retire this worker.
      disabled = true;
      self.registration.unregister();
    }
    if (!out.visible && e.preReplay && (!sealedOnly || disabled) && code !== "SEAL_TOFU_MISMATCH") {
      fallbacks++;
      count(clientId, false, code + " " + u.pathname.slice(0, 48));
      return replay(req, method, body);
    }
    failedVisibly(clientId, code);
    return Response.error();
  }
  const res = out.res;
  count(clientId, true);
  let response = toResponse(res);
  if (req.mode === "navigate" && response.status === 200) response = await rewriteDocument(response, clientId);
  return maybeCache(req, u, response, cacheable);
}

// Same-origin documents (report pages in iframes or tabs): the boot script in
// frame mode is injected (sockets, hints, beacons, peer connections, frames of
// that document), and connection hints to other hosts are removed before the
// parser's preload scanner sees them.
async function rewriteDocument(r: Response, cid = ""): Promise<Response> {
  const ct = (r.headers.get("content-type") || "").toLowerCase();
  if (!ct.startsWith("text/html")) return r;
  const cs = /charset=([^;]+)/.exec(ct)?.[1]?.trim();
  const len = Number(r.headers.get("content-length") || 0);
  if ((cs && cs !== "utf-8" && cs !== "utf8") || len > 8 << 20) return r;
  let html = await r.text();
  html = neutralizeHintsText(html, self.location.host);
  if (cfg.egress) html = neutralizeFramesText(html, self.location.host, (h) => note(cid, "blocked", h, "iframe"));
  const tag = '<meta http-equiv="x-dns-prefetch-control" content="off"><script src="/_s/boot.js?f=1"></script>';
  const head = /<head\b[^>]*>/i.exec(html);
  if (head) html = html.slice(0, head.index + head[0].length) + tag + html.slice(head.index + head[0].length);
  else {
    const dt = /^\s*<!doctype[^>]*>/i.exec(html);
    const at = dt ? dt[0].length : 0;
    html = html.slice(0, at) + tag + html.slice(at);
  }
  const h = new Headers(r.headers);
  h.delete("content-length");
  const link = h.get("link");
  if (link) {
    const kept = hintLinkHeader(link);
    if (kept) h.set("link", kept); else h.delete("link");
  }
  return new Response(html, { status: r.status, statusText: r.statusText, headers: h });
}

// Sealed egress ------------------------------------------------------------------------

function header(res: InnerResponse, name: string): string | null {
  for (const [k, v] of res.headers) if (k.toLowerCase() === name) return v;
  return null;
}

async function egress(req: Request, u: URL, cid: string): Promise<Response> {
  const method = req.method.toUpperCase();
  const cacheable = method === "GET" && !req.headers.has("range");
  if (cacheable && req.cache !== "no-store" && req.cache !== "reload") {
    const hit = await fromCache(req);
    if (hit) {
      note(cid, "egress", u.host, "");
      return hit;
    }
  }
  const body = await bodyOf(req, method);
  const target = new URL(u.href);
  target.hash = "";
  const inner = {
    method,
    url: target.href,
    headers: [...req.headers] as [string, string][],
    body,
    mode: req.mode,
    dest: req.destination || "empty",
    redirect: req.redirect,
    signal: req.signal,
  };
  const out = await sealedRetry(inner, method);
  if (!("res" in out)) {
    const e = out.fail;
    const code = e.code || "SEAL_UNKNOWN";
    lastError = code;
    if (code === "SEAL_DISABLED" || code === "SEAL_ABSENT") {
      disabled = true;
      self.registration.unregister();
    }
    if (!out.visible && e.preReplay && (!sealedOnly || disabled) && code !== "SEAL_TOFU_MISMATCH") {
      note(cid, "escaped", u.host, (e as any).beforeSend ? "no sealed session (" + code + ")" : code);
      return replay(req, method, body);
    }
    if (out.visible) failedVisibly(cid, code);
    else note(cid, "blocked", u.host, code);
    return Response.error();
  }
  const res = out.res;
  const refusal = header(res, "x-seal-egress-error");
  if (refusal === "SEAL_EGRESS_OFF") {
    // Kill switch: back to the behaviour before egress (direct), visible as escaped.
    egressOff = true;
    res.body?.cancel().catch(() => {});
    note(cid, "escaped", u.host, "egress off");
    return replay(req, method, body);
  }
  const isRedirect = res.status >= 300 && res.status < 400 && !!header(res, "location");
  let why = "";
  if (refusal) why = refusal;
  else if (req.redirect === "error" && isRedirect) why = "redirect refused";
  else if (req.mode === "cors") {
    // The CORS check the browser would have made on the remote answer.
    const acao = header(res, "access-control-allow-origin");
    if (!acao || (acao.trim() !== "*" && acao.trim() !== self.location.origin)) why = "CORS refused by the remote";
  }
  if (why) {
    note(cid, "blocked", u.host, why);
    res.body?.cancel().catch(() => {});
    return Response.error();
  }
  note(cid, "egress", u.host, "");
  const response = toResponse(res, (k) => k === "x-seal-egress-error");
  return maybeCache(req, u, response, cacheable);
}

// A tiny cache for responses the server marks long-lived (public, max-age),
// because responses built by a service worker never enter the HTTP cache.

function maxAge(h: Headers): number {
  const cc = (h.get("cache-control") || "").toLowerCase();
  if (/no-store|no-cache|private/.test(cc)) return 0;
  const m = /max-age=(\d+)/.exec(cc);
  return m ? parseInt(m[1], 10) : 0;
}

function isCacheable(h: Headers) {
  return maxAge(h) >= 3600 && !(h.get("vary") || "").includes("*");
}

function withStamp(h: Headers): Headers {
  const n = new Headers(h);
  n.set("x-dsh-seal-stored", String(Date.now()));
  return n;
}

async function fromCache(req: Request): Promise<Response | null> {
  try {
    const c = await caches.open(CACHE);
    const r = await c.match(req.url);
    if (!r) return null;
    const at = Number(r.headers.get("x-dsh-seal-stored") || 0);
    if (Date.now() - at > maxAge(r.headers) * 1000) {
      await c.delete(req.url);
      return null;
    }
    return r;
  } catch {
    return null;
  }
}

// Drop older revisions of the same resource (same path and query apart from
// the revision parameters) so the cache does not grow with every release.
function unversioned(u: URL): string {
  const p = new URLSearchParams(u.search);
  for (const k of ["rev", "v", "t"]) p.delete(k);
  return u.origin + u.pathname + "?" + p.toString();
}

async function pruneSiblings(c: Cache, u: URL) {
  const key = unversioned(u);
  for (const k of await c.keys()) {
    const ku = new URL(k.url);
    if (ku.search !== u.search && unversioned(ku) === key) await c.delete(k);
  }
}
