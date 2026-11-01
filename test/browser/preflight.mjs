// Preflight of one identity through a fake edge (stands in for a reverse proxy plus
// an auth gateway, sets X-Auth-Email, logs request lines) in front of dsh-seal (offer).
// Read only: opens an existing chat, side card tabs and Settings; never sends
// a turn and never creates a chat.
//
//   node preflight.mjs <base> <outdir> <edgelog> <tag> [chatId|first]
import { connect } from "./cdp.mjs";
import { readFileSync, writeFileSync, truncateSync } from "node:fs";

const [base, out, edgeLog, tag, chatArg = "first"] = process.argv.slice(2);
const ev = { tag, base };
const step = (k, v) => { ev[k] = v; console.log(k.padEnd(20), typeof v === "string" ? v : JSON.stringify(v).slice(0, 600)); };
const edgeLines = () => readFileSync(edgeLog, "utf8").trim().split("\n").filter(Boolean).map((l) => { const [t, m, u, len, up] = l.split(" "); return { t: +t, m, u, len, up: !!up }; });
// tabs that create something or start a process are not clicked
const SKIP_TABS = /^(Side Chat|Terminal|New terminal|Agent Browser|Local preview|Git|More tools)/;

truncateSync(edgeLog, 0);
const c = await connect({ origin: base });
const deadline = setTimeout(async () => { step("FAIL", "deadline"); writeFileSync(`${out}/${tag}-evidence.json`, JSON.stringify(ev, null, 1)); await c.close(); process.exit(1); }, 420000);
const text = () => c.evaluate("document.body.innerText", 20000).catch(() => "");
const clickEl = (js) => c.evaluate(`(() => { const e = ${js}; if (!e) return false; e.scrollIntoView({block: 'center'}); e.click(); return true })()`);
const seal = () => c.evaluate("({state: __dshSeal.state, reason: __dshSeal.reason, sw: __dshSeal.sw, mux: __dshSeal.muxState, fallbacks: __dshSeal.fallbacks, swFallbacks: __dshSeal.swFallbacks || 0, sealedRequests: __dshSeal.sealedRequests, sealedChannels: __dshSeal.sealedChannels, lock: document.getElementById('dsh-seal-badge')?.dataset.state, placement: document.getElementById('dsh-seal-badge')?.dataset.placement})");
try {
  await c.send("Storage.clearDataForOrigin", { origin: base, storageTypes: "service_workers,cache_storage,indexeddb,local_storage" }).catch(() => {});
  await c.send("Network.deleteCookies", { name: "sealboot", domain: new URL(base).hostname }, c.page).catch(() => {});
  await c.sleep(1000);
  const t0 = Date.now();
  await c.send("Page.navigate", { url: base + "/" }, c.page).catch((e) => step("navigate_warning", e.message));
  let st = null;
  for (let i = 0; i < 90; i++) {
    await c.sleep(1000);
    st = await c.evaluate("window.__dshSeal ? __dshSeal.state : null").catch(() => null);
    if (st && st !== "starting") break;
  }
  step("time_to_state_ms", Date.now() - t0);
  let body = "";
  for (let i = 0; i < 40; i++) { body = await text(); const rows = await c.evaluate("document.querySelectorAll('.wr-row[data-session-id]').length").catch(() => 0); if (/[1-9]\d* chats/.test(body) && rows > 0) break; await c.sleep(1000); }
  step("chat_list", { count: (body.match(/\d+ chats/) || ["missing"])[0], rows: await c.evaluate("document.querySelectorAll('.wr-row[data-session-id]').length") });
  step("seal_initial", await seal());
  await c.shot(`${out}/${tag}-1-loaded.png`);

  // open an existing chat (read only)
  const pick = chatArg === "first"
    ? `[...document.querySelectorAll('.wr-row[data-session-id^="session-"]')].find(r => !r.classList.contains('wr-isworking'))`
    : `document.querySelector('.wr-row[data-session-id="${chatArg}"]')`;
  const title = await c.evaluate(`(() => { const r = ${pick}; return r ? r.querySelector('.wr-title').textContent : null })()`);
  const chBefore = (await seal()).sealedChannels || 0;
  await clickEl(`(${pick})?.querySelector('.wr-title')`);
  let opened = false;
  for (let i = 0; i < 30 && !opened; i++) {
    await c.sleep(700);
    opened = await c.evaluate(`(() => { const t = ${JSON.stringify(title || "")}; const h = [...document.querySelectorAll('header, [class*=header]')].some(e => (e.innerText || '').includes(t.slice(0, 20))); const msgs = document.querySelectorAll('[data-message-id], [class*=message], [class*=Message]').length; return h && msgs > 0 })()`);
  }
  await c.sleep(2500);
  const afterOpen = await seal();
  step("chat_opened", { title, opened, channelsBefore: chBefore, channelsAfter: afterOpen.sealedChannels, mux: afterOpen.mux });
  await c.shot(`${out}/${tag}-2-chat.png`);

  // side card tabs from the Start page
  const sideOpen = await c.evaluate(`!![...document.querySelectorAll('button')].find(b => (b.getAttribute('aria-label') || '') === 'Collapse right sidebar')`);
  if (!sideOpen) await clickEl(`[...document.querySelectorAll('button')].find(b => /Open right sidebar/.test(b.getAttribute('aria-label') || ''))`);
  await c.sleep(1500);
  const openStart = `(() => { const bs = [...document.querySelectorAll("button,[role=button]")].filter(b => { const r = b.getBoundingClientRect(); return r.x > innerWidth * 0.45 && r.y < 40 }); const s = bs.find(b => /^Start$/.test((b.innerText || "").trim())) || bs.find(b => /^New tab$/i.test(b.getAttribute("aria-label") || b.getAttribute("title") || "")); if (s) s.click(); return !!s })()`;
  await c.evaluate(openStart);
  await c.sleep(1500);
  const entries = await c.evaluate(`[...new Set([...document.querySelectorAll('button,[role=button],a,div')].filter(x => x.getBoundingClientRect().x > innerWidth * 0.45 && x.children.length < 4 && (x.innerText || '').trim() && (x.innerText || '').trim().length < 26 && x.getBoundingClientRect().height >= 40 && x.getBoundingClientRect().height <= 70).map(x => (x.innerText || '').trim().split('\\n')[0]))]`);
  step("start_entries", entries);
  const tabs = {};
  for (const name of entries.filter((n) => !SKIP_TABS.test(n)).slice(0, 14)) {
    await c.evaluate(openStart);
    await c.sleep(1200);
    const before = edgeLines().length;
    const ok = await clickEl(`[...document.querySelectorAll('button,[role=button],a,div')].filter(x => (x.innerText || '').trim().split('\\n')[0] === ${JSON.stringify(name)} && x.getBoundingClientRect().x > innerWidth * 0.45).pop()`);
    await c.sleep(4000);
    const tx = await text();
    const err = (tx.match(/(failed to load[^\n]{0,60}|error loading[^\n]{0,60}|Cannot GET[^\n]{0,40}|HTTP [45]\d\d[^\n]{0,40})/i) || [""])[0];
    const nl = edgeLines().slice(before);
    tabs[name] = { clicked: ok, error: err.slice(0, 80), sealed: nl.filter((l) => l.u.startsWith("/_s/")).length, plain: nl.filter((l) => !l.u.startsWith("/_s/")).map((l) => l.m + " " + l.u.slice(0, 60)) };
    await c.shot(`${out}/${tag}-tab-${name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.png`);
  }
  step("side_card_tabs", tabs);

  // Settings dialog and its sections
  await c.key("Escape", "Escape", 27);
  await c.evaluate("(() => { const e=[...document.querySelectorAll('button,[role=button]')].filter(b=>(b.innerText||'').trim()==='More').map(b=>[b,b.getBoundingClientRect()]).filter(([,r])=>r.x<320&&r.width>0).sort((a,b)=>b[1].y-a[1].y)[0]; if(e) e[0].click() })()");
  await c.sleep(1200);
  await c.evaluate("(() => { const e=[...document.querySelectorAll('[role=menu] *,[data-radix-popper-content-wrapper] *')].filter(x=>(x.innerText||'').trim()==='Settings').pop(); if(e) (e.closest('[role=menuitem],button')||e).click() })()");
  let dlg = "";
  for (let i = 0; i < 10; i++) { await c.sleep(1000); dlg = String(await c.evaluate("[...document.querySelectorAll('[role=dialog]')].map(e=>e.innerText).join('\\n')").catch(() => "")); if (dlg.length > 200) break; }
  const sect = {};
  for (const name of ["General", "Models", "Mail", "Phone", "Voice", "Idle Watchdog", "Note Keeper", "Plugins"]) {
    if (!dlg.includes(name)) continue;
    const before = edgeLines().length;
    const clicked = await clickEl(`[...document.querySelectorAll('[role=dialog] *')].filter(x => (x.innerText || '').trim() === ${JSON.stringify(name)}).pop()`);
    await c.sleep(2500);
    const d = String(await c.evaluate("[...document.querySelectorAll('[role=dialog]')].map(e => e.innerText).join(' ')").catch(() => ""));
    const nl = edgeLines().slice(before);
    sect[name] = { clicked, chars: d.length, error: (d.match(/(failed to load|error loading)[^.]{0,60}/i) || [""])[0], sealed: nl.filter((l) => l.u.startsWith("/_s/")).length, plain: nl.filter((l) => !l.u.startsWith("/_s/")).length };
  }
  step("settings", { dialogChars: dlg.length, sections: sect });
  await c.shot(`${out}/${tag}-3-settings.png`);
  await c.key("Escape", "Escape", 27);

  await c.sleep(2000);
  await c.evaluate("__dshSeal.check()").catch(() => {});
  await c.sleep(1500);
  step("seal_final", await seal());
  const lines = edgeLines();
  let shellIdx = -1;
  lines.forEach((l, i) => { if (l.m === "GET" && l.u === "/") shellIdx = i; });
  const after = lines.slice(shellIdx + 1);
  const byPath = {};
  for (const l of after) { const k = l.m + " " + l.u.split("?")[0] + (l.up ? " (websocket)" : ""); byPath[k] = (byPath[k] || 0) + 1; }
  step("edge_before_shell", lines.slice(0, shellIdx + 1).map((l) => l.m + " " + l.u.replace(/token=[^&]*/, "token=<redacted>").slice(0, 50)));
  step("edge_after_shell", byPath);
  step("plain_after_shell", after.filter((l) => !l.u.startsWith("/_s/")).map((l) => l.m + " " + l.u.slice(0, 80)));
  const cross = {};
  for (const e of c.log) {
    if (!e.url || e.url.startsWith(base) || /^(data|blob|about|chrome|chrome-extension):/.test(e.url)) continue;
    const h = e.type + " " + new URL(e.url).origin;
    cross[h] = (cross[h] || 0) + 1;
  }
  step("third_party", cross);
  step("console_errors", c.consoleLines.filter((l) => /^(error|exception)/.test(l)).slice(0, 12));
} catch (e) {
  step("FAIL", e.stack || e.message);
} finally {
  writeFileSync(`${out}/${tag}-evidence.json`, JSON.stringify(ev, null, 1));
  clearTimeout(deadline);
  await c.close();
}
setTimeout(() => process.exit(0), 300);
