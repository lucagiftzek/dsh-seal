// Resilience check in a Chrome with remote debugging on 127.0.0.1:9222 through a fake edge in
// front of a dsh-seal TEST instance (never the live port):
//   A. offline for 20 s (Network.emulateNetworkConditions on the page and the
//      service worker), then online;
//   B. the mux and every connection to the test instance dropped (ss -K);
//   C. the test instance restarted (sessions gone: 4401, fresh handshake);
//   D. three HARD reloads (Page.reload ignoreCache: true), the second within
//      15 s of the first.
// Pass: no plain DSH request after the shell in any phase (the fake edge log
// is what an observer sees), the lock returns to Encrypted, the page keeps
// working (sealed requests grow, the mux is open again).
//
//   node resilience.mjs <base> <outdir> <edgelog> <tag> <seal-port> <seal-unit>
import { connect } from "./cdp.mjs";
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync, truncateSync } from "node:fs";

const [base, out, edgeLog, tag, sealPort, sealUnit] = process.argv.slice(2);
// --only-hard: skip A to C; --client-path: set the sealhr cookie before each hard
// reload, so the server serves the real shell and only the client cure acts
const onlyHard = process.argv.includes("--only-hard");
const clientPath = process.argv.includes("--client-path");
const onlySleep = process.argv.includes("--only-sleep");
// --live: against the LIVE port: only what touches this tab (offline emulation,
// hard reloads); never kill connections or restart the service
const live = process.argv.includes("--live");
const ev = { tag, base, phases: {} };
const step = (k, v) => { console.log(k.padEnd(22), typeof v === "string" ? v : JSON.stringify(v).slice(0, 900)); };
const edgeLines = () => readFileSync(edgeLog, "utf8").trim().split("\n").filter(Boolean).map((l) => { const [t, m, u] = l.split(" "); return { t: +t, m, u }; });
const isSeal = (u) => u.startsWith("/_s/");
const isShell = (u) => u === "/" || u.startsWith("/?");
truncateSync(edgeLog, 0);
const c = await connect({ origin: base });
const deadline = setTimeout(async () => { step("FAIL", "deadline"); save(); await c.close(); process.exit(1); }, 900000);
function save() { writeFileSync(`${out}/${tag}-resilience-evidence.json`, JSON.stringify(ev, null, 1), { mode: 0o600 }); }
const user = `XDG_RUNTIME_DIR=/run/user/${process.getuid()}`;

const seal = () => c.evaluate(`(async () => { await __dshSeal.check(); const s = __dshSeal; return {
  state: s.state, reason: s.reason, sw: s.sw, controlled: !!navigator.serviceWorker.controller, mux: s.muxState, link: s.link,
  fallbacks: s.fallbacks, swFallbacks: s.swFallbacks || 0, failed: s.failedRequests || 0, sealed: s.sealedRequests || 0,
  channels: s.sealedChannels || 0, history: s.history, lock: document.getElementById('dsh-seal-badge')?.dataset.state } })()`, 30000).catch((e) => ({ error: e.message }));
const works = () => c.evaluate(`fetch('/manifest.webmanifest', { cache: 'no-store' }).then(r => r.status, e => 'error ' + e.message)`, 60000).catch((e) => "eval " + e.message);
const plainSince = (t) => edgeLines().filter((l) => l.t >= t && !isSeal(l.u)).map((l) => l.m + " " + l.u);
async function waitFor(pred, ms, every = 1000) {
  const end = Date.now() + ms;
  let last = null;
  while (Date.now() < end) {
    last = await seal();
    if (pred(last)) return { ok: true, after: ms - (end - Date.now()), s: last };
    await c.sleep(every);
  }
  return { ok: false, s: last };
}
async function emulate(offline) {
  for (const sid of c.sessions.keys()) {
    await c.send("Network.emulateNetworkConditions", { offline, latency: 0, downloadThroughput: -1, uploadThroughput: -1 }, sid).catch(() => {});
  }
}
async function waitLoaded(ms = 90000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    await c.sleep(1000);
    const st = await c.evaluate("window.__dshSeal && navigator.serviceWorker.controller && !document.querySelector('meta[name=dsh-seal-bootstrap]') ? __dshSeal.state : null").catch(() => null);
    if (st && st !== "starting") return st;
  }
  return null;
}

let fail = false;
const check = (name, cond, detail) => { if (!cond) { fail = true; step("FAIL " + name, detail); } };

try {
  await c.send("Storage.clearDataForOrigin", { origin: base, storageTypes: "service_workers,cache_storage,indexeddb,local_storage" }, c.page).catch((e) => console.log("clear warning", e.message));
  const ck = await c.send("Network.getCookies", { urls: [base + "/"] }, c.page).catch(() => ({ cookies: [] }));
  for (const k of ck.cookies) await c.send("Network.deleteCookies", { name: k.name, domain: k.domain, path: k.path }, c.page).catch(() => {});
  await c.sleep(500);
  await c.send("Page.navigate", { url: base + "/" }, c.page).catch((e) => step("navigate_warning", e.message));
  const st0 = await waitLoaded();
  await c.sleep(8000); // DSH loads its lists and opens its sockets
  ev.loaded = await seal();
  step("loaded", ev.loaded);
  check("loaded sealed", ev.loaded.state === "sealed", ev.loaded);

  // A. offline 20 s ---------------------------------------------------------------------
  if (!onlyHard && !onlySleep) {
    const t = Date.now();
    const before = await seal();
    await emulate(true);
    await c.sleep(2000);
    const during = await seal();
    const pending = works(); // a request made while offline: waits, never plain
    await c.sleep(18000);
    const during2 = await seal();
    await emulate(false);
    const tOn = Date.now();
    const pendingResult = await pending;
    const rec = await waitFor((s) => s.state === "sealed" && s.lock === "sealed", 45000);
    const after = await works();
    const afterS = await seal();
    const plain = plainSince(t);
    ev.phases.offline = { during, during2, pendingResult, recoveredMs: rec.ok ? Date.now() - tOn : null, after, afterS, plain, sealedGrew: (afterS.sealed || 0) > (before.sealed || 0) };
    step("A offline", ev.phases.offline);
    check("A no plain", plain.length === 0, plain);
    check("A no plain while offline", during.state !== "plain" && during2.state !== "plain" && during2.fallbacks === 0, [during, during2]);
    check("A recovered", rec.ok && after === 200, [rec, after]);
  }

  // A2. laptop sleep: offline AND every connection dropped, 20 s, then online -----------------
  if (!onlyHard && !live) {
    const t = Date.now();
    await emulate(true);
    try { execSync(`sudo ss -K -tn dst 127.0.0.1 dport = :${sealPort} >/dev/null 2>&1`); } catch { /* none */ }
    await c.sleep(3000);
    const during = await seal();
    await c.sleep(17000);
    const during2 = await seal();
    await emulate(false);
    const tOn = Date.now();
    const rec = await waitFor((s) => s.state === "sealed" && s.mux === "open", 60000);
    const after = await works();
    const afterS = await seal();
    const plain = plainSince(t);
    ev.phases.sleep = { during, during2, recoveredMs: rec.ok ? Date.now() - tOn : null, after, afterS, plain };
    step("A2 sleep", ev.phases.sleep);
    check("A2 no plain", plain.length === 0, plain);
    check("A2 no plain while offline", during.state !== "plain" && during2.state !== "plain" && during2.fallbacks === 0, [during, during2]);
    check("A2 recovered", rec.ok && after === 200, [rec, after]);
  }
  if (onlySleep) throw new Error("only-sleep done");

  // B. every connection to the test instance dropped (the mux included) --------------------
  if (!onlyHard && !live) {
    const t = Date.now();
    const before = await seal();
    let killed = "";
    try { killed = execSync(`sudo ss -K -tn dst 127.0.0.1 dport = :${sealPort} 2>&1 | wc -l`).toString().trim(); } catch (e) { killed = "error " + e.message; }
    await c.sleep(3000);
    const rec = await waitFor((s) => s.state === "sealed" && s.mux === "open", 60000);
    const after = await works();
    const afterS = await seal();
    const plain = plainSince(t);
    ev.phases.drop = { killedLines: killed, before: { mux: before.mux, channels: before.channels }, recovered: rec.ok, after, afterS, plain };
    step("B mux dropped", ev.phases.drop);
    check("B no plain", plain.length === 0, plain);
    check("B recovered", rec.ok && after === 200, [rec, after]);
  }

  // C. test instance restarted: sessions gone, 4401, fresh handshake -----------------------
  if (!onlyHard && !live) {
    const t = Date.now();
    execSync(`${user} systemctl --user restart ${sealUnit}`);
    await c.sleep(3000);
    const rec = await waitFor((s) => s.state === "sealed" && s.mux === "open", 60000);
    const after = await works();
    const afterS = await seal();
    const plain = plainSince(t);
    ev.phases.restart = { recovered: rec.ok, after, afterS, plain };
    step("C restart", ev.phases.restart);
    check("C no plain", plain.length === 0, plain);
    check("C recovered", rec.ok && after === 200, [rec, after]);
  }

  // D. hard reloads ----------------------------------------------------------------------
  ev.phases.hard = [];
  for (let i = 0; i < 3; i++) {
    if (clientPath) await c.send("Network.setCookie", { name: "sealhr", value: "1", url: base + "/", expires: Date.now() / 1000 + 30 }, c.page);
    const t = Date.now();
    await c.send("Page.reload", { ignoreCache: true }, c.page).catch((e) => step("reload_warning", e.message));
    const st = await waitLoaded(60000);
    // after the first hard reload, the next one comes at once (within 15 s of the
    // automatic reload: the case the old 15 s guard left uncontrolled)
    if (i === 0) { ev.phases.hard.push({ reload: 1, quick: true, lines: edgeLines().filter((l) => l.t >= t).map((l) => l.m + " " + l.u) }); continue; }
    await c.sleep(6000);
    const s = await seal();
    const lines = edgeLines().filter((l) => l.t >= t).map((l) => l.m + " " + l.u);
    const plain = lines.filter((l) => !isSeal(l.split(" ")[1]) && !isShell(l.split(" ")[1]));
    const shells = lines.filter((l) => isShell(l.split(" ")[1])).length;
    const r = { reload: i + 1, loaded: st, s, shellGETs: shells, bootJs: lines.filter((l) => l.includes("/_s/boot.js")).length, plain, sealedOnWire: lines.filter((l) => l.includes("/_s/x")).length };
    ev.phases.hard.push(r);
    step("D hard reload " + (i + 1), r);
    check("D" + (i + 1) + " sealed and controlled", s.state === "sealed" && s.controlled, s);
    check("D" + (i + 1) + " no plain DSH request", plain.length === 0, plain);
  }

  // popover after everything (history of this page view)
  ev.final = await seal();
  await c.evaluate(`document.getElementById('dsh-seal-badge')?.shadowRoot.querySelector('button').click()`).catch(() => {});
  await c.sleep(1200);
  await c.shot(`${out}/${tag}-final-popover.png`);
  ev.popover = await c.evaluate(`document.getElementById('dsh-seal-badge')?.shadowRoot.querySelector('.pop')?.innerText || ''`).catch(() => "");
  step("popover", ev.popover);
  ev.console = c.consoleLines.filter((l) => /error|exception/i.test(l)).slice(0, 20);
  ev.pass = !fail;
} catch (e) {
  if (String(e.message) !== "only-sleep done") { ev.error = e.stack || String(e); fail = true; } else ev.pass = !fail;
} finally {
  await emulate(false).catch(() => {});
  save();
  clearTimeout(deadline);
  await c.close();
}
step("RESULT", fail ? "FAIL" : "PASS");
setTimeout(() => process.exit(fail ? 1 : 0), 200);
