// One identity: specific features through the seal (test instance, fake edge).
//   phone   Phone > Keypad > Test audio (server audio, wss /dsh-phone/api/io on the mux)
//   mail    image proxy: an already read HTML mail with images=1, one /img fetch
//   report  an artifact preview iframe (/report/<name>.html)
//   notes   note-keeper (left nav Notes)
//   voice   one short Kokoro sample (provider "grey", self-hosted) via /api/voice/tts
// No call, no turn, no mail state change (only messages already marked read).
//   node features.mjs <base> <outdir> <edgelog>
import { connect } from "./cdp.mjs";
import { readFileSync, writeFileSync, truncateSync } from "node:fs";

const [base, out, edgeLog] = process.argv.slice(2);
const ev = {};
const step = (k, v) => { ev[k] = v; console.log(k.padEnd(16), typeof v === "string" ? v : JSON.stringify(v).slice(0, 900)); };
const edgeLines = () => readFileSync(edgeLog, "utf8").trim().split("\n").filter(Boolean).map((l) => { const [t, m, u, len, up] = l.split(" "); return { t: +t, m, u, len, up: !!up }; });
truncateSync(edgeLog, 0);
const c = await connect({ origin: base });
const deadline = setTimeout(async () => { step("FAIL", "deadline"); writeFileSync(out + "/features-evidence.json", JSON.stringify(ev, null, 1)); await c.close(); process.exit(1); }, 360000);
const clickEl = (js) => c.evaluate(`(() => { const e = ${js}; if (!e) return false; e.scrollIntoView({block: 'center'}); e.click(); return true })()`);
const seal = () => c.evaluate("({state: __dshSeal.state, mux: __dshSeal.muxState, fallbacks: __dshSeal.fallbacks, swFallbacks: __dshSeal.swFallbacks || 0, channels: __dshSeal.sealedChannels})");
const plainSince = (n) => edgeLines().slice(n).filter((l) => !l.u.startsWith("/_s/")).map((l) => l.m + " " + l.u.slice(0, 70));
try {
  await c.send("Browser.grantPermissions", { origin: base, permissions: ["audioCapture"] }).catch((e) => step("grant_warning", e.message));
  await c.send("Page.navigate", { url: base + "/" }, c.page);
  for (let i = 0; i < 60; i++) { await c.sleep(1000); const s = await c.evaluate("window.__dshSeal && __dshSeal.state").catch(() => null); if (s && s !== "starting") break; }
  await c.sleep(6000);
  step("seal_start", await seal());

  // phone: side card, Phone tab, Keypad, Test audio
  let n = edgeLines().length;
  const ws0 = c.log.filter((e) => e.type === "WebSocket").length;
  await clickEl(`[...document.querySelectorAll('button')].find(b => /Open right sidebar/.test(b.getAttribute('aria-label') || ''))`);
  await c.sleep(1200);
  await c.evaluate(`(() => { const bs = [...document.querySelectorAll("button,[role=button]")].filter(b => { const r = b.getBoundingClientRect(); return r.x > innerWidth * 0.45 && r.y < 40 }); const s = bs.find(b => /^Start$/.test((b.innerText || "").trim())) || bs.find(b => /^New tab$/i.test(b.getAttribute("aria-label") || b.getAttribute("title") || "")); if (s) s.click() })()`);
  await c.sleep(1200);
  await clickEl(`[...document.querySelectorAll('button,[role=button],a,div')].filter(x => (x.innerText || '').trim().split('\\n')[0] === 'Phone' && x.getBoundingClientRect().x > innerWidth * 0.45).pop()`);
  await c.sleep(3500);
  const kp = await clickEl(`[...document.querySelectorAll('button,[role=tab]')].filter(x => (x.innerText || '').trim() === 'Keypad' && x.getBoundingClientRect().width > 0).pop()`);
  await c.sleep(1500);
  const ta = await clickEl(`[...document.querySelectorAll('button')].filter(x => (x.innerText || '').trim() === 'Test audio' && x.getBoundingClientRect().width > 0).pop()`);
  let note = "", during = null;
  for (let i = 0; i < 40; i++) {
    await c.sleep(1000);
    if (i === 4) { during = await seal(); await c.shot(out + "/feat-phone-during.png"); }
    note = await c.evaluate(`[...document.querySelectorAll('.phx-note')].map(e => e.innerText).join(' | ')`);
    if (/Audio works|fail|error|could not|blocked/i.test(note)) break;
  }
  await c.shot(out + "/feat-phone.png");
  step("phone", { keypad: kp, testClicked: ta, result: note.slice(0, 300), sealDuringTest: during, newPageWebSockets: c.log.filter((e) => e.type === "WebSocket").slice(ws0).map((e) => e.url.split("?")[0]), plain: plainSince(n), ioPlain: edgeLines().slice(n).filter((l) => l.u.includes("/dsh-phone/api/io")).length });

  // mail: image proxy (already read message with remote images)
  n = edgeLines().length;
  const mail = await c.evaluate(`(async () => {
    const out = { tried: 0 };
    const l = await (await fetch('/dsh-mail/api/messages?account=all&limit=80')).json();
    const items = (l.messages || l.items || []).filter(m => m.seen);
    out.listed = (l.messages || l.items || []).length; out.seen = items.length;
    for (const m of items.slice(0, 25)) {
      out.tried++;
      const r = await (await fetch('/dsh-mail/api/message?id=' + encodeURIComponent(m.id) + '&images=1')).json();
      const msg = r.message || {};
      if (!msg.imagesLoaded) continue;
      const u = (msg.srcdoc.match(/\\/dsh-mail\\/api\\/img\\?[^"'\\s)]+/) || [])[0];
      if (!u) continue;
      const img = await fetch(u.replace(/&amp;/g, '&'));
      const b = await img.blob();
      out.message = { blocked: msg.blocked, proxy: msg.proxy, imagesLoaded: msg.imagesLoaded, stillSeen: msg.seen };
      out.img = { status: img.status, type: img.headers.get('content-type'), bytes: b.size };
      break;
    }
    return out;
  })()`, 120000).catch((e) => ({ error: e.message }));
  step("mail_img_proxy", { ...mail, plain: plainSince(n) });

  // report iframe (artifact preview)
  n = edgeLines().length;
  const rep = await c.evaluate(`new Promise(res => { const f = document.createElement('iframe'); f.style.cssText = 'position:fixed;right:0;bottom:0;width:400px;height:300px;z-index:99999'; f.src = '/report/dsh-seal-activation.html'; f.onload = () => setTimeout(() => { let t = ''; try { t = f.contentDocument.body.innerText.slice(0, 80) } catch (e) { t = 'no access' } res({ loaded: true, text: t, controlled: !!(f.contentWindow.navigator.serviceWorker && f.contentWindow.navigator.serviceWorker.controller) }); }, 2500); document.body.appendChild(f); setTimeout(() => res({ loaded: false }), 20000) })`, 30000).catch((e) => ({ error: e.message }));
  await c.shot(out + "/feat-report-iframe.png");
  await c.evaluate("document.querySelectorAll('iframe[src^=\"/report/\"]').forEach(f => f.remove())");
  step("report_iframe", { ...rep, plain: plainSince(n) });

  // note-keeper
  n = edgeLines().length;
  await c.key("Escape", "Escape", 27);
  const nk = await clickEl(`[...document.querySelectorAll('button,[role=button],a')].filter(b => (b.innerText || '').trim() === 'Notes' && b.getBoundingClientRect().x < 320 && b.getBoundingClientRect().width > 0).pop()`);
  await c.sleep(5000);
  await c.shot(out + "/feat-notes.png");
  const nkText = await c.evaluate("document.body.innerText.length");
  step("notes", { clicked: nk, bodyChars: nkText, sealed: edgeLines().slice(n).filter((l) => l.u.startsWith("/_s/")).length, plain: plainSince(n) });

  // voice: one short Kokoro sample (self-hosted)
  n = edgeLines().length;
  const voice = await c.evaluate(`(async () => { const r = await fetch('/api/voice/tts', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text: 'Seal test.', provider: 'grey', lang: 'en' }) }); const b = await r.blob(); return { status: r.status, engine: r.headers.get('x-voice-engine'), type: b.type, bytes: b.size } })()`, 60000).catch((e) => ({ error: e.message }));
  step("voice_kokoro", { ...voice, plain: plainSince(n) });

  await c.evaluate("__dshSeal.check()").catch(() => {});
  await c.sleep(1500);
  step("seal_end", await seal());
  const cross = {};
  for (const e of c.log) {
    if (!e.url || e.url.startsWith(base) || /^(data|blob|about|chrome):/.test(e.url)) continue;
    const h = e.type + " " + new URL(e.url).origin;
    cross[h] = (cross[h] || 0) + 1;
  }
  step("third_party", cross);
  step("page_websockets", c.log.filter((e) => e.type === "WebSocket").map((e) => e.url.split("?")[0]));
  step("console_errors", c.consoleLines.filter((l) => /^(error|exception)/.test(l)).slice(0, 12));
} catch (e) {
  step("FAIL", e.stack || e.message);
} finally {
  writeFileSync(out + "/features-evidence.json", JSON.stringify(ev, null, 1));
  clearTimeout(deadline);
  await c.close();
}
setTimeout(() => process.exit(0), 300);
