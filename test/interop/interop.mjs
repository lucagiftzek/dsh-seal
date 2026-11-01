// Node WebCrypto interop suite: the compiled browser client (client/dist/
// seal-node.mjs, the same code boot.js and sw.js bundle) against the Go
// server. Run by test/e2e.sh, which starts the mock upstream and two dsh-seal
// instances (offer and passthrough).
//
// env: SEAL_OFFER=http://127.0.0.1:3191 SEAL_PASS=http://127.0.0.1:3192
//      SEAL_BIN=bin/dsh-seal VECTORS=internal/sealcrypto/vectors.go
import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { execFileSync, spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as S from "../../client/dist/seal-node.mjs";

const OFFER = process.env.SEAL_OFFER || "http://127.0.0.1:3191";
const PASS = process.env.SEAL_PASS || "http://127.0.0.1:3192";
const BIN = process.env.SEAL_BIN || "bin/dsh-seal";
const te = new TextEncoder();
const td = new TextDecoder();
let passed = 0, failed = 0;
const results = [];

async function test(name, fn) {
  const t0 = performance.now();
  try {
    await fn();
    passed++;
    results.push(`ok   ${name} (${(performance.now() - t0).toFixed(0)} ms)`);
  } catch (e) {
    failed++;
    results.push(`FAIL ${name}: ${e?.stack || e}`);
  }
}
function assert(c, msg) { if (!c) throw new Error("assertion failed: " + msg); }
const hex = (b) => Buffer.from(b).toString("hex");

globalThis.location = new URL(OFFER + "/");

async function conf(base) {
  const r = await fetch(base + "/_s/boot.js");
  assert(r.ok, "boot.js " + r.status);
  const js = await r.text();
  const j = js.slice("self.__DSH_SEAL_CFG=".length, js.indexOf(";\n"));
  return JSON.parse(j);
}
const nodeFetch = (i, init) => fetch(i, init);

async function readAll(stream) {
  if (!stream) return new Uint8Array(0);
  const rd = stream.getReader();
  const parts = [];
  for (;;) {
    const { value, done } = await rd.read();
    if (done) break;
    parts.push(value);
  }
  return S.concat(...parts);
}

// 1. vectors --------------------------------------------------------------------------
await test("key schedule vectors match Go (th, cf, frame)", async () => {
  const src = readFileSync(process.env.VECTORS || "internal/sealcrypto/vectors.go", "utf8");
  const v = Object.fromEntries([...src.matchAll(/(Vec\w+)\s*=\s*"([0-9a-f]*)"/g)].map((m) => [m[1], m[2]]));
  const rep = (b, n) => new Uint8Array(n).fill(b);
  const th = await S.transcriptHash(rep(1, 65), rep(2, 65), rep(3, 65), rep(4, 16), rep(5, 32));
  assert(hex(th) === v.VecTH, "th " + hex(th));
  const ms = await S.masterKey(rep(0x11, 32), th);
  assert(await S.verifyConfirm(ms, th, Buffer.from(v.VecCF, "hex")), "confirm tag");
  const sess = new S.Session(rep(4, 16), ms, "", "");
  const ct = await new S.StreamCipher(sess, S.DIR_C2S, 7).seal(S.F_DATA, te.encode("hello"));
  assert(hex(ct) === v.VecFrame, "frame " + hex(ct));
  const opened = await new S.StreamCipher(sess, S.DIR_C2S, 7).open(ct);
  assert(opened.type === S.F_DATA && td.decode(opened.payload) === "hello", "open own frame");
});

// 2. handshake + sealed fetch ------------------------------------------------------------------
const C = await conf(OFFER);
const kv = new S.MemoryKV();
let sess;
await test("handshake verifies the bundle, pins it, confirms the key", async () => {
  sess = await S.establish(C, kv, nodeFetch, OFFER);
  assert(sess.sid.length === 16, "sid");
  assert((await kv.get(S.PIN_KEY)) === C.bundle.fp, "pinned fingerprint");
});

await test("sealed GET with query (query only inside the envelope)", async () => {
  const r = await S.sealedFetch(sess, { method: "GET", url: "/api/echo?u=https%3A%2F%2Fmail.example%2Fimg&q=secret", headers: [["x-test", "1"], ["x-auth-email", "evil@x"]] }, nodeFetch);
  const j = JSON.parse(td.decode(await readAll(r.body)));
  assert(r.status === 200 && j.query === "u=https%3A%2F%2Fmail.example%2Fimg&q=secret", "query " + j.query);
  assert(j.headers["X-Test"] === "1" && !j.headers["X-Auth-Email"], "headers " + JSON.stringify(j.headers));
});

await test("sealed POST with a 2 MB body", async () => {
  const body = new Uint8Array(2 << 20);
  crypto.getRandomValues(body.subarray(0, 65536));
  const r = await S.sealedFetch(sess, { method: "POST", url: "/api/echo", headers: [["content-type", "application/octet-stream"]], body }, nodeFetch);
  const j = JSON.parse(td.decode(await readAll(r.body)));
  const sum = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", body)));
  assert(j.sha256 === sum && j.contentLength === body.length, "body hash");
});

await test("gzip responses are decompressed by the client", async () => {
  const r = await S.sealedFetch(sess, { method: "GET", url: "/api/gzip", headers: [] }, nodeFetch);
  const j = JSON.parse(td.decode(await readAll(r.body)));
  assert(j.gzip === true && !r.headers.some(([k]) => k.toLowerCase() === "content-encoding"), "gzip");
});

await test("streaming response: first SSE event arrives before the stream ends", async () => {
  const t0 = performance.now();
  const r = await S.sealedFetch(sess, { method: "GET", url: "/api/sse?n=3&ms=300", headers: [["accept", "text/event-stream"]] }, nodeFetch);
  const rd = r.body.getReader();
  let text = "";
  while (!text.includes("tick 0")) {
    const { value, done } = await rd.read();
    if (done) break;
    text += td.decode(value);
  }
  const first = performance.now() - t0;
  while (!(await rd.read()).done) { /* drain */ }
  assert(first < 250, "first event after " + first.toFixed(0) + " ms");
});

await test("HEAD, 204, 304 and redirects keep HTTP semantics", async () => {
  let r = await S.sealedFetch(sess, { method: "HEAD", url: "/api/gzip", headers: [] }, nodeFetch);
  assert(r.status === 200 && r.body === null, "HEAD");
  r = await S.sealedFetch(sess, { method: "GET", url: "/api/status?c=304", headers: [] }, nodeFetch);
  assert(r.status === 304 && r.body === null, "304");
  r = await S.sealedFetch(sess, { method: "GET", url: "/api/redirect", headers: [] }, nodeFetch);
  assert(r.status === 302 && r.headers.find(([k]) => k === "Location")[1] === "/api/echo?from=redirect", "302");
  await readAll(r.body);
});

await test("50 parallel sealed requests (out of order arrival, replay window)", async () => {
  const rs = await Promise.all(Array.from({ length: 50 }, (_, i) => S.sealedFetch(sess, { method: "GET", url: "/api/echo?i=" + i, headers: [] }, nodeFetch)));
  const qs = await Promise.all(rs.map(async (r) => JSON.parse(td.decode(await readAll(r.body))).query));
  assert(qs.every((q, i) => q === "i=" + i), "parallel results");
});

await test("unknown session is reported as SEAL_UNKNOWN_SESSION (client re-handshakes)", async () => {
  const fake = new S.Session(new Uint8Array(16), sess.ms, sess.fp, OFFER);
  try {
    await S.sealedFetch(fake, { method: "GET", url: "/api/echo", headers: [] }, nodeFetch);
    throw new Error("accepted");
  } catch (e) {
    assert(e.code === "SEAL_UNKNOWN_SESSION" && e.preReplay, "code " + e.code);
  }
});

// 3. TOFU and rotation ---------------------------------------------------------------------
await test("TOFU mismatch: a different pinned identity refuses to seal", async () => {
  const pinned = new S.MemoryKV();
  await pinned.set(S.PIN_KEY, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  try {
    await S.establish(C, pinned, nodeFetch, OFFER);
    throw new Error("sealed anyway");
  } catch (e) {
    assert(e.code === "SEAL_TOFU_MISMATCH", "code " + e.code);
  }
});

await test("signed identity rotation is accepted, a swapped key is not", async () => {
  const dir = mkdtempSync(join(process.env.TMPDIR || tmpdir(), "seal-rot-"));
  const cfgA = join(dir, "a.conf");
  writeFileSync(cfgA, `state_dir=${dir}/a\n`);
  const bundle = (cfg) => JSON.parse(execFileSync(BIN, ["-config", cfg, "bundle-json"], { encoding: "utf8" }));
  const b0 = bundle(cfgA);
  execFileSync(BIN, ["-config", cfgA, "rotate-identity"]);
  execFileSync(BIN, ["-config", cfgA, "rotate-identity"]);
  const b2 = bundle(cfgA);
  assert(b2.fp !== b0.fp && b2.chain.length === 2, "rotated twice");
  assert((await S.verifyBundle(b2, b0.fp)) === b2.fp, "chain accepted");
  const cfgB = join(dir, "b.conf");
  writeFileSync(cfgB, `state_dir=${dir}/b\n`);
  const other = bundle(cfgB);
  try {
    await S.verifyBundle(other, b0.fp);
    throw new Error("swap accepted");
  } catch (e) {
    assert(e.code === "SEAL_TOFU_MISMATCH", e.code);
  }
  const forged = structuredClone(b2);
  forged.chain[1].sig = forged.chain[0].sig;
  try {
    await S.verifyBundle(forged, b0.fp);
    throw new Error("forged chain accepted");
  } catch (e) {
    assert(e.code === "SEAL_TOFU_MISMATCH", e.code);
  }
});

// 4. mux: sealed WebSockets and EventSource --------------------------------------------------
const wsURL = OFFER.replace("http", "ws") + "/_s/ws";
let mux;
await test("mux: 3 inner WebSockets through one sealed socket", async () => {
  mux = new S.Mux(async (fresh) => (fresh ? S.establish(C, kv, nodeFetch, OFFER) : sess), wsURL, (u) => new WebSocket(u));
  const SWS = S.makeSealedWebSocket(WebSocket, () => mux, () => true, () => false, () => {});
  const runOne = (i) => new Promise((res, rej) => {
    const ws = new SWS(OFFER.replace("http", "ws") + `/ws/echo?hello=1&n=${i}`, ["chat-v1"]);
    ws.binaryType = "arraybuffer";
    const got = [];
    const big = new Uint8Array(200000).map((_, k) => (k * i) & 255);
    ws.onopen = () => {
      if (ws.protocol !== "chat-v1") rej(new Error("protocol " + ws.protocol));
      ws.send("text " + i);
      ws.send(big);
    };
    ws.onmessage = (e) => {
      got.push(e.data);
      if (got.length === 3) {
        const hello = JSON.parse(got[0]);
        if (!hello.path.endsWith("n=" + i)) return rej(new Error("hello " + got[0]));
        if (got[1] !== "text " + i) return rej(new Error("text " + got[1]));
        if (hex(new Uint8Array(got[2])) !== hex(big)) return rej(new Error("binary echo differs"));
        ws.close(1000, "done");
      }
    };
    ws.onclose = (e) => (got.length === 3 && e.code === 1000 ? res() : rej(new Error("closed " + e.code + " after " + got.length)));
    setTimeout(() => rej(new Error("timeout")), 8000);
  });
  await Promise.all([1, 2, 3].map(runOne));
  assert(mux.state === "open", "mux state " + mux.state);
});

await test("mux: server close code and refused sockets surface like a real WebSocket", async () => {
  const SWS = S.makeSealedWebSocket(WebSocket, () => mux, () => true, () => false, () => {});
  await new Promise((res, rej) => {
    const ws = new SWS(OFFER.replace("http", "ws") + "/ws/echo");
    ws.onopen = () => ws.send("close-me");
    ws.onclose = (e) => (e.code === 4001 && e.reason === "asked" ? res() : rej(new Error("code " + e.code)));
    setTimeout(() => rej(new Error("timeout")), 5000);
  });
  await new Promise((res, rej) => {
    const ws = new SWS(OFFER.replace("http", "ws") + "/ws/deny");
    let err = false;
    ws.onerror = () => { err = true; };
    ws.onclose = (e) => (err && e.code === 1006 ? res() : rej(new Error("deny close " + e.code)));
    setTimeout(() => rej(new Error("timeout")), 5000);
  });
});

await test("mux: sealed EventSource receives named and unnamed events", async () => {
  const SES = S.makeSealedEventSource(globalThis.EventSource ?? class {}, () => mux, () => true, () => false, () => {});
  await new Promise((res, rej) => {
    const es = new SES(OFFER + "/api/sse?n=4&ms=20");
    const seen = [];
    es.onmessage = (e) => seen.push("message:" + e.data.split("\n")[0] + ":" + e.lastEventId);
    es.addEventListener("named", (e) => seen.push("named:" + e.data.split("\n")[0]));
    es.onerror = () => {
      es.close();
      seen.length >= 4 && seen[0] === "message:tick 0:1" && seen[1] === "named:tick 1" ? res() : rej(new Error(JSON.stringify(seen)));
    };
    setTimeout(() => rej(new Error("timeout " + JSON.stringify(seen))), 5000);
  });
});

// 5. sealed egress ------------------------------------------------------------------------
const REMOTE = process.env.SEAL_REMOTE || "https://127.0.0.1:3193";
const hdrOf = (r, k) => (r.headers.find(([n]) => n.toLowerCase() === k) || [])[1];

await test("egress: another host fetched by the server (generic headers, no identity, no cookies)", async () => {
  const r = await S.sealedFetch(sess, { method: "GET", url: REMOTE + "/api/echo?q=1", headers: [["cookie", "page=1"], ["x-auth-email", "evil@x"], ["x-forwarded-for", "6.6.6.6"], ["x-custom", "ok"]], mode: "cors", dest: "empty" }, nodeFetch);
  const j = JSON.parse(td.decode(await readAll(r.body)));
  const h = j.headers;
  assert(r.status === 200 && r.url === REMOTE + "/api/echo?q=1", "status/url " + r.status + " " + r.url);
  assert(h["X-Custom"] === "ok" && !h["Cookie"] && !h["X-Auth-Email"] && !h["X-Forwarded-For"], "headers " + JSON.stringify(h));
  assert(/Chrome\/130/.test(h["User-Agent"]) && h["Referer"] === REMOTE + "/" && /127\.0\.0\.1:3191$/.test(h["Origin"] || ""), "generic " + JSON.stringify(h));
});

await test("egress: image keeps type and cache headers, Set-Cookie dropped; Range answers 206", async () => {
  let r = await S.sealedFetch(sess, { method: "GET", url: REMOTE + "/remote/img.png", headers: [], mode: "no-cors", dest: "image" }, nodeFetch);
  const b = await readAll(r.body);
  assert(r.status === 200 && hdrOf(r, "content-type") === "image/png" && /immutable/.test(hdrOf(r, "cache-control") || ""), "img " + JSON.stringify(r.headers));
  assert(!hdrOf(r, "set-cookie") && td.decode(b.subarray(1)) === "PNG remote", "set-cookie or body");
  r = await S.sealedFetch(sess, { method: "GET", url: REMOTE + "/remote/media.bin", headers: [["range", "bytes=10-19"]], mode: "no-cors", dest: "video" }, nodeFetch);
  const m = await readAll(r.body);
  assert(r.status === 206 && hdrOf(r, "content-range") === "bytes 10-19/1048576" && m.length === 10 && m[0] === 10 && m[9] === 19, "range " + r.status + " " + JSON.stringify(r.headers));
});

await test("egress: private, loopback, upstream port and redirect-to-private are refused inside the envelope", async () => {
  const cases = { "https://10.0.0.1/": "SEAL_EGRESS_FORBIDDEN", "https://127.0.0.2:3193/": "SEAL_EGRESS_FORBIDDEN", "https://localhost:3193/": "SEAL_EGRESS_DENIED",
    "http://127.0.0.1:3190/": "SEAL_EGRESS_PORT", [REMOTE + "/remote/to?u=https://169.254.169.254/"]: "SEAL_EGRESS_FORBIDDEN" };
  for (const [u, code] of Object.entries(cases)) {
    const r = await S.sealedFetch(sess, { method: "GET", url: u, headers: [] }, nodeFetch);
    await readAll(r.body);
    assert(hdrOf(r, "x-seal-egress-error") === code, u + " -> " + hdrOf(r, "x-seal-egress-error") + " " + r.status);
  }
});

await test("mux: cross-origin WebSocket and EventSource ride the mux as egress", async () => {
  const notes = [];
  const noteFn = (k, h, w) => notes.push(k + ":" + h);
  const SWS = S.makeSealedWebSocket(WebSocket, () => mux, () => true, () => false, () => {}, () => true, noteFn);
  await new Promise((res, rej) => {
    const ws = new SWS(REMOTE.replace("https", "wss") + "/ws/echo?hello=1");
    const got = [];
    ws.onopen = () => ws.send("over the mux");
    ws.onmessage = (e) => {
      got.push(e.data);
      if (got.length === 2) {
        const hello = JSON.parse(got[0]);
        if (hello.hello || hello.cookie || !/127\.0\.0\.1:3191$/.test(hello.origin)) return rej(new Error("hello " + got[0]));
        if (got[1] !== "over the mux") return rej(new Error("echo " + got[1]));
        ws.close(1000, "done");
      }
    };
    ws.onclose = (e) => (got.length === 2 && e.code === 1000 ? res() : rej(new Error("closed " + e.code)));
    setTimeout(() => rej(new Error("timeout " + JSON.stringify(got))), 8000);
  });
  const SES = S.makeSealedEventSource(globalThis.EventSource ?? class {}, () => mux, () => true, () => false, () => {}, () => true, noteFn);
  await new Promise((res, rej) => {
    const es = new SES(REMOTE + "/api/sse?n=3&ms=10");
    const seen = [];
    es.onmessage = (e) => seen.push(e.data.split("\n")[0]);
    es.onerror = () => { es.close(); seen[0] === "tick 0" ? res() : rej(new Error(JSON.stringify(seen))); };
    setTimeout(() => rej(new Error("timeout " + JSON.stringify(seen))), 5000);
  });
  assert(notes.includes("egress:127.0.0.1:3193"), "notes " + notes);
});

// 6. resilience: reconnect, sleep, offline, grace window, current state -------------------
// A private dsh-seal on 3194 (same mock upstream) that the tests kill and restart.
const RES = "http://127.0.0.1:3194";
const resDir = mkdtempSync(join(process.env.TMPDIR || tmpdir(), "seal-res-"));
writeFileSync(join(resDir, "res.conf"), `listen=127.0.0.1:3194\nupstream=127.0.0.1:3190\nmode=offer\nstate_dir=${resDir}/state\nseal_anonymous=true\n`);
let resProc = null;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function resStart() {
  resProc = spawn(BIN, ["-config", join(resDir, "res.conf")], { stdio: "ignore" });
  for (let i = 0; i < 100; i++) {
    try { await fetch(RES + "/_s/p"); return; } catch { await sleep(50); }
  }
  throw new Error("test instance did not start");
}
function resKill() { resProc?.kill("SIGKILL"); resProc = null; }
function fakeEnv(online = true, probe = true) {
  const subs = [];
  const e = { on: online, pr: probe, now: () => Date.now(), online: () => e.on, hidden: () => false, probe: async () => e.pr, subscribe: (f) => subs.push(f), emit: (ev) => subs.forEach((f) => f(ev)) };
  return e;
}
const resWS = RES.replace("http", "ws") + "/_s/ws";
await resStart();
const RC = await conf(RES);
globalThis.location = new URL(RES + "/"); // the page is on the test instance for these tests

function resMux(env, grace, extra = {}) {
  const log = { fresh: 0, sessions: 0 };
  let cur = null;
  const getSession = async (fresh) => {
    if (fresh || !cur) { if (fresh) log.fresh++; log.sessions++; cur = await S.establish(RC, new S.MemoryKV(), nodeFetch, RES); }
    return cur;
  };
  const net = new S.NetHealth(env, grace);
  const m = new S.Mux(getSession, extra.url || resWS, extra.factory || ((u) => new WebSocket(u)), { net, verifyMs: 1000, ...extra.opts });
  return { m, net, log };
}
function echoOnce(SWS, base = RES) {
  return new Promise((res, rej) => {
    const ws = new SWS(base.replace("http", "ws") + "/ws/echo?hello=1");
    const got = [];
    ws.onopen = () => ws.send("ping");
    ws.onmessage = (e) => { got.push(e.data); if (got.length === 2) { ws.close(1000); res(got[1]); } };
    ws.onclose = (e) => { if (got.length < 2) rej(new Error("closed " + e.code + " " + e.reason)); };
    setTimeout(() => rej(new Error("echo timeout")), 15000);
  });
}

await test("resilience: mux reconnects after a server-side drop and a restart (4401: fresh handshake), never plain", async () => {
  const env = fakeEnv(true, true);
  env.probe = async () => { try { await fetch(RES + "/_s/p"); return true; } catch { return false; } };
  const { m, log } = resMux(env, 2000);
  const falls = [];
  const SWS = S.makeSealedWebSocket(WebSocket, () => m, () => true, () => true, (w) => falls.push(w));
  assert((await echoOnce(SWS)) === "ping", "first echo");
  // server killed: the open socket drops (server side close), the process is gone for 3 s
  const long = new SWS(resWS.replace("/_s/ws", "/ws/echo"));
  await new Promise((r) => { long.onopen = r; });
  const closed = new Promise((r) => { long.onclose = (e) => r(e.code); });
  resKill();
  assert((await closed) === 1006, "inner socket sees 1006");
  const pending = echoOnce(SWS); // opened while the server is down: waits, no fallback
  await sleep(3000);
  assert(falls.length === 0, "fell back while the origin was down: " + falls);
  await resStart(); // sessions are gone: 4401, fresh handshake, same keys
  assert((await pending) === "ping", "echo after restart");
  assert(falls.length === 0 && log.fresh >= 1 && m.state === "open", "fresh " + log.fresh + " falls " + falls + " state " + m.state);
  m.dropForTest();
});

await test("resilience: a sleep time jump drops a dead socket and reconnects without counting a failure", async () => {
  const env = fakeEnv();
  let deaf = false;
  const factory = (u) => {
    const ws = new WebSocket(u);
    const real = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(ws), "onmessage");
    let h = null;
    Object.defineProperty(ws, "onmessage", { set(f) { h = f; real.set.call(ws, (ev) => { if (!deaf) h?.(ev); }); }, get() { return h; } });
    return ws;
  };
  const { m, net } = resMux(env, 2000, { factory });
  const falls = [];
  const SWS = S.makeSealedWebSocket(WebSocket, () => m, () => true, () => true, (w) => falls.push(w));
  const ws = new SWS(RES.replace("http", "ws") + "/ws/echo");
  await new Promise((r) => { ws.onopen = r; });
  const closed = new Promise((r) => { ws.onclose = (e) => r(e.code + " " + e.reason); });
  deaf = true; // the machine slept: nothing arrives any more
  m.lastTick = Date.now() - 10 * 60 * 1000; // ten minutes since the last keepalive tick
  m.tick();
  assert(m.wakes === 1, "wake detected");
  const why = await closed;
  assert(/sleep/.test(why), "closed with " + why);
  deaf = false;
  assert((await echoOnce(SWS)) === "ping", "echo after wake");
  assert(falls.length === 0 && net.failingSince === 0, "no failure counted: " + falls + " " + net.failingSince);
  m.dropForTest();
});

await test("resilience: offline waits (no plain, even past the grace window), online reconnects at once", async () => {
  const env = fakeEnv(false, false);
  const { m } = resMux(env, 500);
  const falls = [];
  const SWS = S.makeSealedWebSocket(WebSocket, () => m, () => true, () => true, (w) => falls.push(w));
  const p = echoOnce(SWS);
  await sleep(2000);
  assert(falls.length === 0 && m.state === "waiting", "offline: falls " + falls + " state " + m.state);
  const t0 = Date.now();
  env.on = true; env.pr = true;
  env.emit("online");
  assert((await p) === "ping", "echo after online");
  assert(Date.now() - t0 < 1500 && falls.length === 0, "reconnect took " + (Date.now() - t0) + " ms");
  m.dropForTest();
});

await test("resilience: fallback to plain only after the grace window with the network up; network down never", async () => {
  // the sealed socket always fails (nothing listens on the mux address)
  const dead = "ws://127.0.0.1:3199/_s/ws";
  for (const up of [false, true]) {
    const env = fakeEnv(true, up);
    const { m } = resMux(env, 1500, { url: dead });
    const falls = [];
    const SWS = S.makeSealedWebSocket(WebSocket, () => m, () => true, () => true, (w) => falls.push({ w, t: Date.now() }));
    const t0 = Date.now();
    const ws = new SWS(RES.replace("http", "ws") + "/ws/echo");
    ws.onerror = () => {};
    await sleep(1200);
    assert(falls.length === 0, "fell back before the grace window (up=" + up + ")");
    await sleep(2500);
    if (up) {
      assert(falls.length === 1 && falls[0].w === "SEAL_MUX_CONNECT" && falls[0].t - t0 >= 1500, "grace fallback " + JSON.stringify(falls));
      await new Promise((r) => { if (ws.readyState === 1) r(); else ws.onopen = r; });
      ws.close();
    } else assert(falls.length === 0, "fell back with the network down");
    ws.close?.();
  }
});

await test("resilience: a plain fallback socket moves back onto the seal when it works again", async () => {
  const env = fakeEnv(true, true);
  let url = "ws://127.0.0.1:3199/_s/ws";
  const { m } = resMux(env, 300, { factory: () => new WebSocket(url) });
  const natives = new Set();
  const falls = [];
  const SWS = S.makeSealedWebSocket(WebSocket, () => m, () => true, () => true, (w) => falls.push(w), () => false, () => {}, natives);
  const ws = new SWS(RES.replace("http", "ws") + "/ws/echo");
  await new Promise((r) => { ws.onopen = r; });
  assert(falls.length === 1 && natives.size === 1, "native fallback");
  const closed = new Promise((r) => { ws.onclose = (e) => r(e); });
  url = resWS; // the seal works again
  await m.warm();
  for (const n of [...natives]) n.upgrade("seal restored");
  const e = await closed;
  assert(e.code === 1006 && natives.size === 0, "upgrade close " + e.code);
  assert((await echoOnce(SWS)) === "ping", "reopened sealed");
  m.dropForTest();
});

await test("resilience: sealed fetch retries an idempotent request after a fresh handshake; POST fails visibly, never plain", async () => {
  const env = fakeEnv(true, true);
  const net = new S.NetHealth(env, 60000);
  let cur = null, hs = 0;
  const ctx = {
    session: async (after) => { if (!cur || cur.created < after) { hs++; cur = await S.establish(RC, new S.MemoryKV(), nodeFetch, RES); } return cur; },
    net, fetchImpl: nodeFetch, budgetMs: 15000,
  };
  await ctx.session(0);
  resKill();
  setTimeout(() => resStart(), 2500);
  const t0 = Date.now();
  const out = await S.sealedRetryWith(ctx, { method: "GET", url: "/api/echo?r=1", headers: [] }, "GET");
  assert(out.res && out.res.status === 200, "GET result " + JSON.stringify(out.fail?.code));
  await readAll(out.res.body);
  assert(hs >= 2 && Date.now() - t0 >= 2000, "fresh handshake " + hs);
  // POST whose outer request fails at the network: not replayed, not plain
  const failing = { ...ctx, fetchImpl: async (u, init) => { if (String(u).endsWith("/_s/x")) throw new TypeError("network changed"); return nodeFetch(u, init); } };
  const post = await S.sealedRetryWith(failing, { method: "POST", url: "/api/echo", headers: [], body: new Uint8Array(3) }, "POST");
  assert(!post.res && post.visible && post.fail.code === "SEAL_NETWORK", "POST " + JSON.stringify(post));
  // offline: no plain, a network error after the budget
  env.on = false;
  const off = await S.sealedRetryWith({ ...failing, budgetMs: 1500 }, { method: "GET", url: "/api/echo", headers: [] }, "GET");
  assert(!off.res && off.visible, "offline GET must fail visibly, not fall back");
});

await test("resilience: the lock returns to Encrypted once the sealed path is healthy; history keeps the fallbacks", async () => {
  const base = { now: Date.now(), warning: false, controlled: true, swOk: true, swReason: "", nativeLive: 0, swFallbackMode: false, egressOff: false, escapedAt: {}, escapedWhy: {} };
  const t = Date.now() - 120000;
  assert(S.decide({ ...base, lastPlainAt: t, lastHealthyAt: t - 1000 }).state === "plain", "plain not yet recovered");
  assert(S.decide({ ...base, lastPlainAt: t, lastHealthyAt: t + 1000 }).state === "sealed", "recovered");
  assert(S.decide({ ...base, lastPlainAt: t, lastHealthyAt: t + 1000, nativeLive: 1 }).state === "plain", "a socket still plain");
  assert(S.decide({ ...base, lastPlainAt: 0, lastHealthyAt: t, swFallbackMode: true }).state === "plain", "worker in fallback mode");
  assert(S.decide({ ...base, lastPlainAt: 0, lastHealthyAt: t, controlled: false }).reason === "worker: not-controlling", "uncontrolled");
  assert(S.decide({ ...base, lastPlainAt: 0, lastHealthyAt: t, escapedAt: { "x.org": Date.now() - 600000 } }).state === "sealed", "old escape is history");
  assert(S.decide({ ...base, lastPlainAt: 0, lastHealthyAt: t, escapedAt: { "x.org": Date.now() - 600000 }, egressOff: true }).state === "plain", "egress off is current");
  const ev = [];
  for (let i = 0; i < 3; i++) S.pushEvent(ev, { t: t + i, kind: "plain", why: "SEAL_MUX_CONNECT" });
  const lines = S.historyLines(ev);
  const hm = new Date(t).toTimeString().slice(0, 5);
  assert(lines.length === 1 && lines[0] === "3 requests went plain at " + hm + " (SEAL_MUX_CONNECT)", JSON.stringify(lines));
});
resKill();
globalThis.location = new URL(OFFER + "/");

// 7. passthrough mode ----------------------------------------------------------------------
await test("passthrough mode: no injection, no seal endpoints, kill worker served", async () => {
  let r = await fetch(PASS + "/", { headers: { "x-auth-email": "alice@example.com" } });
  const html = await r.text();
  assert(!html.includes("/_s/"), "shell injected in passthrough");
  r = await fetch(PASS + "/_s/boot.js");
  assert(r.status === 404 && r.headers.get("x-seal-error") === "SEAL_DISABLED", "boot.js " + r.status);
  r = await fetch(PASS + "/_s/sw.js");
  assert((await r.text()).includes("unregister"), "kill worker");
  r = await fetch(OFFER + "/", { headers: { "x-auth-email": "alice@example.com" } });
  const boot = await r.text();
  assert(boot.includes("dsh-seal-bootstrap") && !boot.includes("mock dsh"), "first visit gets the bootstrap page");
  r = await fetch(OFFER + "/", { headers: { "x-auth-email": "alice@example.com", cookie: "sealboot=1" } });
  const shell = await r.text();
  assert(shell.includes("<head><meta http-equiv=\"x-dns-prefetch-control\" content=\"off\"><script src=\"/_s/boot.js?v=") && shell.includes("mock dsh"), "offer injects the shell");
});

for (const l of results) console.log(l);
console.log(`\ninterop: ${passed} passed, ${failed} failed`);
process.exitCode = failed ? 1 : 0;
setTimeout(() => process.exit(process.exitCode), 200).unref();
