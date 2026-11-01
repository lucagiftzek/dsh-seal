// Sealed egress check in a Chrome with remote debugging through a fake edge (stands in
// for a reverse proxy plus an auth gateway) in front of a dsh-seal TEST instance. Every request
// any target of the test page makes is recorded; a request "reached the
// network" when Chrome emitted Network.requestWillBeSentExtraInfo for it (the
// network stack sent it; worker-answered requests never get one). The pass
// condition: every request that reached the network went to the test origin.
//
//   node egress.mjs <base> <outdir> <edgelog> <tag> [--full] [--turn]
// --full: Image Studio, probe artifact iframe, Mail, Notes, Phone Test audio,
//         latency; --turn: one turn in a scratch chat (markdown image).
import { connect } from "./cdp.mjs";
import { readFileSync, writeFileSync, truncateSync } from "node:fs";

const args = process.argv.slice(2);
const [base, out, edgeLog, tag] = args;
const full = args.includes("--full");
const doTurn = args.includes("--turn");
const SCRATCH = "session-8ba344aa-5c03-4937-b157-7e86e70a32c9";
const IMG = "https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png";
const host = new URL(base).host;
const ev = { tag, base };
const step = (k, v) => { ev[k] = v; console.log(k.padEnd(20), typeof v === "string" ? v : JSON.stringify(v).slice(0, 700)); };
const edgeLines = () => readFileSync(edgeLog, "utf8").trim().split("\n").filter(Boolean).map((l) => { const [t, m, u] = l.split(" "); return { t: +t, m, u }; });
truncateSync(edgeLog, 0);
const c = await connect({ origin: base });
const deadline = setTimeout(async () => { step("FAIL", "deadline"); save(); await c.close(); process.exit(1); }, 600000);

// network truth: requests that reached Chrome's network stack
const wire = new Map(); // sid+requestId -> true
const failed = new Map();
c.handlers.push((d) => {
  const p = d.params || {};
  if (d.method === "Network.requestWillBeSentExtraInfo") wire.set((d.sessionId || "") + p.requestId, true);
  if (d.method === "Network.loadingFailed") failed.set((d.sessionId || "") + p.requestId, p.errorText + (p.blockedReason ? " " + p.blockedReason : ""));
});
const reqIndex = new Map();
c.handlers.push((d) => {
  if (d.method === "Network.requestWillBeSent") reqIndex.set((d.sessionId || "") + d.params.requestId, d.params.request.url);
});
function audit(sinceT = 0) {
  const offOrigin = {}, sealedEgress = {}, blocked = {};
  for (const [k, url] of reqIndex) {
    let u;
    try { u = new URL(url); } catch { continue; }
    if (!/^(https?|wss?):$/.test(u.protocol)) continue;
    const foreign = u.host !== host;
    if (wire.has(k) && foreign) offOrigin[u.host] = (offOrigin[u.host] || 0) + 1;
    else if (foreign && failed.has(k)) blocked[u.host] = failed.get(k);
    else if (foreign) sealedEgress[u.host] = (sealedEgress[u.host] || 0) + 1;
  }
  const ws = c.log.filter((e) => e.type === "WebSocket").map((e) => e.url.split("?")[0]);
  const wsForeign = ws.filter((u) => new URL(u).host !== host);
  return { wireToOtherHosts: offOrigin, viaWorker: sealedEgress, failedOrBlocked: blocked, nativeWebSockets: ws, nativeWebSocketsForeign: wsForeign };
}
function save() { writeFileSync(`${out}/${tag}-egress-evidence.json`, JSON.stringify(ev, null, 1), { mode: 0o600 }); }
const text = () => c.evaluate("document.body.innerText", 20000).catch(() => "");
const clickEl = (js) => c.evaluate(`(() => { const e = ${js}; if (!e) return false; e.scrollIntoView({block: 'center'}); e.click(); return true })()`);
const seal = () => c.evaluate("(async () => { await __dshSeal.check(); const s = __dshSeal; return {state: s.state, reason: s.reason, sw: s.sw, mux: s.muxState, fallbacks: s.fallbacks, swFallbacks: s.swFallbacks || 0, egress: s.egress, view: s.view, lock: document.getElementById('dsh-seal-badge')?.dataset.state} })()", 30000).catch((e) => ({ error: e.message }));
const openStart = `(() => { const bs = [...document.querySelectorAll("button,[role=button]")].filter(b => { const r = b.getBoundingClientRect(); return r.x > innerWidth * 0.45 && r.y < 40 }); const s = bs.find(b => /^Start$/.test((b.innerText || "").trim())) || bs.find(b => /^New tab$/i.test(b.getAttribute("aria-label") || b.getAttribute("title") || "")); if (s) s.click(); return !!s })()`;
async function sideTab(name) {
  const sideOpen = await c.evaluate(`!![...document.querySelectorAll('button')].find(b => (b.getAttribute('aria-label') || '') === 'Collapse right sidebar')`);
  if (!sideOpen) await clickEl(`[...document.querySelectorAll('button')].find(b => /Open right sidebar/.test(b.getAttribute('aria-label') || ''))`);
  await c.sleep(1200);
  await c.evaluate(openStart);
  await c.sleep(1200);
  return clickEl(`[...document.querySelectorAll('button,[role=button],a,div')].filter(x => (x.innerText || '').trim().split('\\n')[0] === ${JSON.stringify(name)} && x.getBoundingClientRect().x > innerWidth * 0.45).pop()`);
}

try {
  await c.send("Storage.clearDataForOrigin", { origin: base, storageTypes: "service_workers,cache_storage,indexeddb,local_storage" }, c.page).catch((e) => console.log("clear warning", e.message));
  // stale DSH cookies of an earlier run on the same host (cookies ignore the port) stop dsh-proxy's token redirect
  const ck = await c.send("Network.getCookies", { urls: [base + "/"] }, c.page).catch(() => ({ cookies: [] }));
  for (const k of ck.cookies) await c.send("Network.deleteCookies", { name: k.name, domain: k.domain, path: k.path }, c.page).catch(() => {});
  await c.send("Browser.grantPermissions", { origin: base, permissions: ["audioCapture"] }).catch(() => {});
  await c.sleep(800);
  const t0 = Date.now();
  await c.send("Page.navigate", { url: base + "/" }, c.page).catch((e) => step("navigate_warning", e.message));
  for (let i = 0; i < 90; i++) {
    await c.sleep(1000);
    const st = await c.evaluate("window.__dshSeal ? __dshSeal.state : null").catch(() => null);
    if (st && st !== "starting") break;
  }
  step("time_to_state_ms", Date.now() - t0);
  for (let i = 0; i < 30; i++) { const rows = await c.evaluate("document.querySelectorAll('.wr-row[data-session-id]').length").catch(() => 0); if (rows > 0) break; await c.sleep(1000); }
  await c.sleep(4000);
  step("seal_loaded", await seal());
  step("audit_loaded", audit());
  await c.shot(`${out}/${tag}-eg-1-loaded.png`);

  if (full) {
    // Image Studio (tldraw assets from cdn.tldraw.com)
    const isOk = await sideTab("Image Studio");
    await c.sleep(12000);
    const tl = await c.evaluate(`(() => { const r = performance.getEntriesByType('resource').filter(e => /tldraw/.test(e.name)); return { entries: r.length, viaWorker: r.filter(e => e.workerStart > 0).length, direct: r.filter(e => e.workerStart === 0).map(e => e.name.slice(0, 80)).slice(0, 5), canvas: !!document.querySelector('.tl-container, .tl-canvas') } })()`).catch((e) => ({ error: e.message }));
    step("image_studio", { clicked: isOk, ...tl });
    await c.shot(`${out}/${tag}-eg-2-image-studio.png`);
    step("audit_image_studio", audit());

    // probe artifact in a same-origin iframe (external image, font, fetch, ws, beacon, rtc, iframes, hints)
    const probe = await c.evaluate(`new Promise(res => { const f = document.createElement('iframe'); f.id = 'egress-probe'; f.style.cssText = 'position:fixed;right:0;bottom:0;width:520px;height:420px;z-index:99999;background:#fff'; f.src = '/report/seal-egress-probe.html'; document.body.appendChild(f); setTimeout(() => { let r = {}; try { const w = f.contentWindow; r = { probe: w.__probe, frameSeal: w.__dshSeal && { frame: w.__dshSeal.frame, egress: w.__dshSeal.egress, blocked: w.__dshSeal.blocked, escaped: w.__dshSeal.escaped, egressHosts: w.__dshSeal.egressHosts }, controlled: !!w.navigator.serviceWorker.controller, hints: [...w.document.querySelectorAll('link[rel]')].map(l => l.rel + ' ' + l.href.slice(0, 50)), yt: w.document.getElementById('yt')?.getAttribute('data-dsh-seal-src') } } catch (e) { r = { error: String(e) } } res(r) }, 14000) })`, 30000).catch((e) => ({ error: e.message }));
    step("probe_iframe", probe);
    await c.shot(`${out}/${tag}-eg-3-probe.png`);
    await c.evaluate("document.getElementById('egress-probe')?.remove()");
    step("audit_probe", audit());


    // Phone Test audio
    const ph = await sideTab("Phone");
    await c.sleep(3500);
    const kp = await clickEl(`[...document.querySelectorAll('button,[role=tab]')].filter(x => (x.innerText || '').trim() === 'Keypad' && x.getBoundingClientRect().width > 0).pop()`);
    await c.sleep(1500);
    const ta = await clickEl(`[...document.querySelectorAll('button')].filter(x => (x.innerText || '').trim() === 'Test audio' && x.getBoundingClientRect().width > 0).pop()`);
    let pnote = "";
    for (let i = 0; i < 40; i++) {
      await c.sleep(1000);
      pnote = await c.evaluate(`[...document.querySelectorAll('.phx-note')].map(e => e.innerText).join(' | ')`).catch(() => "");
      if (/Audio works|fail|error|could not|blocked/i.test(pnote)) break;
    }
    step("phone_test_audio", { tab: ph, keypad: kp, test: ta, result: pnote.slice(0, 200) });
    await c.shot(`${out}/${tag}-eg-6-phone.png`);

    // Mail and Notes
    const mailOk = await sideTab("Mail");
    await c.sleep(5000);
    await c.shot(`${out}/${tag}-eg-4-mail.png`);
    const nk = await clickEl(`[...document.querySelectorAll('button,[role=button],a')].filter(b => (b.innerText || '').trim() === 'Notes' && b.getBoundingClientRect().x < 320 && b.getBoundingClientRect().width > 0).pop()`);
    await c.sleep(5000);
    await c.shot(`${out}/${tag}-eg-5-notes.png`);
    step("mail_notes", { mail: mailOk, notes: nk, bodyChars: await c.evaluate("document.body.innerText.length") });
    await c.key("Escape", "Escape", 27);

    // latency: egress fetch through the worker (no-store, sequential)
    const lat = await c.evaluate(`(async () => { const t = []; for (let i = 0; i < 12; i++) { const a = performance.now(); const r = await fetch('${IMG}?n=' + i + '-' + Date.now(), { cache: 'no-store', mode: 'no-cors' }); await r.arrayBuffer(); t.push(performance.now() - a); } t.shift(); t.sort((a, b) => a - b); return { n: t.length, p50: t[Math.floor(t.length / 2)].toFixed(1), min: t[0].toFixed(1), max: t[t.length - 1].toFixed(1) } })()`, 90000).catch((e) => ({ error: e.message }));
    step("latency_egress_ms", lat);
  }

  if (doTurn) {
    const opened = await clickEl(`document.querySelector('.wr-row[data-session-id="${SCRATCH}"] .wr-title') || document.querySelector('.wr-row[data-session-id="${SCRATCH}"]')`);
    await c.sleep(5000);
    const prompt = "Reply with exactly this one markdown line and nothing else: ![seal egress test](" + IMG + ")";
    await c.evaluate(`(() => { const all = [...document.querySelectorAll('[contenteditable=true]')]; const el = all[all.length - 1]; el.click(); el.focus(); document.execCommand('insertText', false, ${JSON.stringify(prompt)}) })()`);
    await c.sleep(600);
    const frameStart = c.log.length;
    const tSend = Date.now();
    await c.key("Enter", "Enter", 13);
    let img = null;
    for (let i = 0; i < 120; i++) {
      await c.sleep(1000);
      img = await c.evaluate(`(() => { const ims = [...document.querySelectorAll('img')].filter(i => i.src.startsWith('${IMG}') || i.currentSrc.startsWith('${IMG}')); return ims.length ? { count: ims.length, loaded: ims.filter(i => i.complete && i.naturalWidth > 0).length, w: ims[ims.length - 1].naturalWidth } : null })()`).catch(() => null);
      const tx = await text();
      if (img && img.loaded && !/Stop generating|Generating|Thinking\.\.\./i.test(tx)) break;
    }
    const frames = c.log.slice(frameStart).filter((e) => e.kind === "wsframe");
    step("turn", { opened, ms: Date.now() - tSend, image: img, sealedFramesReceived: frames.length });
    await c.shot(`${out}/${tag}-eg-7-turn.png`);
  }

  // indicator popover
  await c.key("Escape", "Escape", 27);
  const s = await seal();
  step("seal_end", s);
  await c.evaluate("document.getElementById('dsh-seal-badge')?.shadowRoot.querySelector('button').click()");
  await c.sleep(1500);
  step("popover", await c.evaluate("document.getElementById('dsh-seal-badge')?.shadowRoot.querySelector('.pop')?.innerText || ''"));
  await c.shot(`${out}/${tag}-eg-8-popover.png`);
  const a = audit();
  step("audit_final", a);
  const edge = edgeLines();
  step("edge", { lines: edge.length, nonSeal: edge.filter((l) => !l.u.startsWith("/_s/")).map((l) => l.m + " " + l.u.slice(0, 60)).slice(0, 12) });
  step("console_errors", c.consoleLines.filter((l) => /^(error|exception|warning)/.test(l)).slice(0, 15));
  ev.pass = Object.keys(a.wireToOtherHosts).length === 0 && a.nativeWebSocketsForeign.length === 0;
  step("PASS", ev.pass);
} catch (e) {
  step("FAIL", e.stack || e.message);
} finally {
  save();
  clearTimeout(deadline);
  await c.close();
}
setTimeout(() => process.exit(0), 300);
