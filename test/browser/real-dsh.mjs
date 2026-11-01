// Real-browser verification of dsh-seal in front of the REAL DSH:
// a Chrome with remote debugging (CDP 9222) -> fakeedge :3083 (stands in for a reverse proxy plus an auth gateway,
// logs every request line) -> dsh-seal :3082 (offer) -> dsh-proxy :3081 -> dsh-web.
//
// DSH_TOKEN=<launch token, never printed> node real-dsh.mjs [base] [outdir] [edgelog] [--turn]
// --turn sends "Reply with exactly: OK" to the throwaway scratch chat only.
import { connect } from "./cdp.mjs";
import { readFileSync, writeFileSync, truncateSync } from "node:fs";

const args = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const base = args[0] || "http://127.0.0.1:3083";
const out = args[1] || "/var/tmp/seal-work";
const edgeLog = args[2] || "/var/tmp/seal-work/edge.log";
const doTurn = process.argv.includes("--turn");
const SCRATCH = "preset check augmentor (scratch, safe to delete)";
const ev = {};
const step = (k, v) => { ev[k] = v; console.log(k.padEnd(22), typeof v === "string" ? v : JSON.stringify(v)); };
const edgeLines = () => readFileSync(edgeLog, "utf8").trim().split("\n").filter(Boolean).map((l) => { const [t, m, u, len, up] = l.split(" "); return { t: +t, m, u, len, up: !!up }; });

truncateSync(edgeLog, 0);
const c = await connect({ origin: base });
// hard deadline: always close our tab, even when the page hangs
const deadline = setTimeout(async () => { step("FAIL", "deadline reached"); writeFileSync(out + "/evidence.json", JSON.stringify(ev, null, 1)); await c.close(); process.exit(1); }, Number(process.env.DEADLINE_MS || 420000));
for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, async () => { await c.close(); process.exit(1); });
const text = () => c.evaluate("document.body.innerText", 20000).catch(() => "");
const clickEl = (js) => c.evaluate(`(() => { const e = ${js}; if (!e) return false; e.scrollIntoView({block: 'center'}); e.click(); return true })()`);
const findText = (t, scope = "document") => `[...${scope}.querySelectorAll('button,[role=button],[role=tab],[role=menuitem],a,div,span')].filter(x => (x.innerText || '').trim() === ${JSON.stringify(t)}).pop()`;
async function mouseOnText(substr, filter = "true") {
  const p = await c.evaluate(`(() => { const els = [...document.querySelectorAll("body *")].filter(e => e.children.length === 0 && (e.textContent || "").includes(${JSON.stringify(substr)}) && !e.closest("input,[contenteditable=true]")); for (const e of els) { const b = e.getBoundingClientRect(); if (b.width && b.height && (${filter})) return [b.x + b.width / 2, b.y + b.height / 2] } return null })()`);
  if (p) await c.mouse(p[0], p[1]);
  return !!p;
}

try {
  // 1. first visit, clean slate for this origin only
  await c.send("Storage.clearDataForOrigin", { origin: base, storageTypes: "service_workers,cache_storage,indexeddb,local_storage" }).catch(() => {});
  await c.send("Network.deleteCookies", { name: "sealboot", domain: new URL(base).hostname }, c.page).catch(() => {});
  await c.sleep(1500);
  const t0 = Date.now();
  await c.send("Page.navigate", { url: base + "/" + (process.env.DSH_TOKEN ? "?token=" + process.env.DSH_TOKEN : "") }, c.page).catch((e) => step("navigate_warning", e.message));
  let st = null;
  for (let i = 0; i < 90; i++) {
    await c.sleep(1000);
    st = await c.evaluate("window.__dshSeal ? {state: __dshSeal.state, reason: __dshSeal.reason, sw: __dshSeal.sw, mux: __dshSeal.muxState, fallbacks: __dshSeal.fallbacks, fp: __dshSeal.fingerprint} : null").catch(() => null);
    if (st && st.state !== "starting") break;
  }
  step("seal_state_initial", st);
  step("time_to_sealed_ms", Date.now() - t0);

  // 2. GUI loads, chat list
  let body = "";
  for (let i = 0; i < 30; i++) { body = await text(); if (/[1-9]\d* chats/.test(body)) break; await c.sleep(1000); }
  step("gui_loaded_ms", Date.now() - t0);
  step("chat_list", (body.match(/[1-9]\d* chats/) || ["missing"])[0]);
  await c.shot(out + "/ev-1-loaded.png");

  // 3. open the scratch chat through search
  const search = await c.evaluate(`(() => { const e = [...document.querySelectorAll('input')].find(i => i.placeholder === 'Search chats'); if (!e) return null; const b = e.getBoundingClientRect(); return [b.x + b.width / 2, b.y + b.height / 2] })()`);
  await c.mouse(search[0], search[1]);
  await c.send("Input.insertText", { text: "preset check augmentor" }, c.page);
  await c.sleep(2500);
  const tOpen = Date.now();
  await mouseOnText("preset check augmentor", "b.x < 300 && b.y > 380");
  let opened = false;
  for (let i = 0; i < 30 && !opened; i++) {
    await c.sleep(500);
    opened = await c.evaluate(`!!document.evaluate(${JSON.stringify(`//header//*[contains(normalize-space(.), "pre")]`)}, document, null, 9, null).singleNodeValue && /Completed in/.test(document.body.innerText)`);
  }
  step("chat_opened", { opened, ms: Date.now() - tOpen });
  await c.shot(out + "/ev-2-chat.png");

  // 4. a streamed turn in the scratch chat (sealed socket frames timed)
  if (doTurn) {
    const before = (await text()).split(/\n/).filter((l) => l.trim() === "OK").length;
    const frameStart = c.log.length;
    const prompt = "Reply with exactly: OK";
    await c.evaluate(`(() => { const all = [...document.querySelectorAll('[contenteditable=true]')]; const el = all[all.length - 1]; el.click(); el.focus(); document.execCommand('insertText', false, ${JSON.stringify(prompt)}) })()`);
    await c.sleep(600);
    const tSend = Date.now();
    await c.key("Enter", "Enter", 13);
    let after = before;
    for (let i = 0; i < 120; i++) {
      await c.sleep(1000);
      const tx = await text();
      after = tx.split(/\n/).filter((l) => l.trim() === "OK").length;
      if (after > before && !/Stop generating|Generating|Thinking\.\.\./i.test(tx)) break;
    }
    const frames = c.log.slice(frameStart).filter((e) => e.kind === "wsframe" && e.ts);
    const gaps = frames.slice(1).map((f, i) => (f.ts - frames[i].ts) * 1000).sort((a, b) => a - b);
    const q = (p) => (gaps.length ? gaps[Math.min(gaps.length - 1, Math.floor(p * gaps.length))].toFixed(1) : "n/a");
    step("turn", { replied: after > before, ms: Date.now() - tSend, sealedFrames: frames.length, bytes: frames.reduce((a, f) => a + f.len, 0), gapMsP50: q(0.5), gapMsP95: q(0.95), gapMsMax: q(0.999) });
    await c.shot(out + "/ev-3-turn.png");
  }

  // 5. side card: plugin tabs
  const tabs = {};
  let tabsStrip = null;
  const sideOpen = await c.evaluate(`!![...document.querySelectorAll('button,[role=button]')].find(b => (b.getAttribute('aria-label') || '') === 'Collapse right sidebar')`);
  if (!sideOpen) await c.evaluate(`(() => { const b = [...document.querySelectorAll('button,[role=button]')].find(b => /Expand right sidebar|Open right sidebar|right sidebar/i.test(b.getAttribute('aria-label') || '')); if (b) b.click() })()`);
  await c.sleep(1500);
  for (const name of ["Mail", "Phone", "Artifacts", "Files", "Tasks", "Orchestrate", "Subscriptions"]) {
    // a new side card tab shows the Start page with every plugin entry
    const strip = await c.evaluate(`[...document.querySelectorAll("button,[role=button],[role=tab]")].map(b => { const r = b.getBoundingClientRect(); return [Math.round(r.x), Math.round(r.y), (b.getAttribute("aria-label") || b.getAttribute("title") || b.innerText || "").trim().slice(0, 30)] }).filter(x => x[0] > 820 && x[1] < 40)`);
    tabsStrip = strip;
    await c.evaluate(`(() => { const bs = [...document.querySelectorAll("button,[role=button]")].filter(b => { const r = b.getBoundingClientRect(); return r.x > 820 && r.x < 1380 && r.y < 40 }); const s = bs.find(b => /^Start$/.test((b.innerText || "").trim())) || bs.find(b => /new tab|add tab|open tab|^\\+$/i.test((b.getAttribute("aria-label") || b.getAttribute("title") || b.innerText || "").trim())); if (s) s.click() })()`);
    await c.sleep(1200);
    const edgeBefore = edgeLines().length;
    const ok = await clickEl(`[...document.querySelectorAll('button,[role=button],a,div')].filter(x => (x.innerText || '').trim() === ${JSON.stringify(name)} && x.getBoundingClientRect().x > 820).pop()`);
    await c.sleep(5000);
    const tx = await text();
    const err = (tx.match(/(failed to load[^\n]{0,60}|error loading[^\n]{0,60}|Cannot GET[^\n]{0,40}|not sealed[^\n]{0,40}|HTTP [45]\d\d[^\n]{0,40})/i) || [""])[0];
    const plain = edgeLines().slice(edgeBefore).filter((l) => !l.u.startsWith("/_s/")).map((l) => l.m + " " + l.u.slice(0, 60));
    tabs[name] = { clicked: ok, error: err.slice(0, 80), plainRequests: plain };
    await c.shot(`${out}/ev-tab-${name.toLowerCase()}.png`);
  }
  step("side_card_tabs", tabs);
  step("side_card_strip", tabsStrip);

  // 6. Settings (sidebar footer "More" -> Settings)
  await c.key("Escape", "Escape", 27);
  await c.evaluate("(() => { const e=[...document.querySelectorAll('button,[role=button]')].filter(b=>(b.innerText||'').trim()==='More').map(b=>[b,b.getBoundingClientRect()]).filter(([,r])=>r.x<320&&r.width>0).sort((a,b)=>b[1].y-a[1].y)[0]; if(e) e[0].click() })()");
  await c.sleep(1200);
  await c.evaluate("(() => { const e=[...document.querySelectorAll('[role=menu] *,[data-radix-popper-content-wrapper] *')].filter(x=>(x.innerText||'').trim()==='Settings').pop(); if(e) (e.closest('[role=menuitem],button')||e).click() })()");
  let dlg = "";
  for (let i = 0; i < 10; i++) { await c.sleep(1000); dlg = String(await c.evaluate("[...document.querySelectorAll('[role=dialog]')].map(e=>e.innerText).join('\\n')").catch(() => "")); if (dlg.length > 200) break; }
  const wanted = ["General", "Models", "Mail", "Phone", "Voice", "Idle Watchdog"];
  step("settings", { dialogChars: dlg.length, sections: Object.fromEntries(wanted.map((w) => [w, dlg.includes(w)])) });
  // open the plugin sections: their settings load through the seal
  const sect = {};
  for (const name of ["Voice", "Mail", "Phone"]) {
    const before = edgeLines().length;
    const clicked = await clickEl(`[...document.querySelectorAll('[role=dialog] *')].filter(x => (x.innerText || '').trim() === ${JSON.stringify(name)}).pop()`);
    await c.sleep(3000);
    const d = String(await c.evaluate("[...document.querySelectorAll('[role=dialog]')].map(e => e.innerText).join(' ')").catch(() => ""));
    const nl = edgeLines().slice(before);
    sect[name] = { clicked, chars: d.length, error: (d.match(/(failed to load|error)[^.]{0,60}/i) || [""])[0], sealedRequests: nl.filter((l) => l.u.startsWith("/_s/")).length, plain: nl.filter((l) => !l.u.startsWith("/_s/")).length };
    await c.shot(`${out}/ev-4-settings-${name.toLowerCase()}.png`);
  }
  step("settings_sections", sect);
  await c.key("Escape", "Escape", 27);

  // 7. final state and egress
  await c.sleep(2000);
  const fin = await c.evaluate("({state: __dshSeal.state, reason: __dshSeal.reason, sw: __dshSeal.sw, mux: __dshSeal.muxState, fallbacks: __dshSeal.fallbacks, controller: !!navigator.serviceWorker.controller})");
  step("seal_state_final", fin);
  const lines = edgeLines();
  let shellIdx = -1;
  lines.forEach((l, i) => { if (l.m === "GET" && l.u === "/") shellIdx = i; });
  const after = lines.slice(shellIdx + 1);
  const plainAfter = after.filter((l) => !l.u.startsWith("/_s/"));
  const byPath = {};
  for (const l of after) { const k = l.m + " " + l.u.split("?")[0] + (l.up ? " (websocket)" : ""); byPath[k] = (byPath[k] || 0) + 1; }
  step("edge_before_shell", lines.slice(0, shellIdx + 1).map((l) => l.m + " " + l.u.slice(0, 50)));
  step("edge_after_shell", byPath);
  step("edge_plain_after_shell", plainAfter.map((l) => l.m + " " + l.u.slice(0, 80)));
  const cross = {};
  for (const e of c.log) {
    if (!e.url || e.url.startsWith(base) || e.url.startsWith("data:") || e.url.startsWith("blob:") || e.url.startsWith("about:") || e.url.startsWith("chrome")) continue;
    const h = e.type + " " + new URL(e.url).origin;
    cross[h] = (cross[h] || 0) + 1;
  }
  step("cross_origin_egress", cross);
  step("page_websockets", c.log.filter((e) => e.type === "WebSocket").map((e) => e.url.split("?")[0]));
  step("sw_answered_requests", c.log.filter((e) => e.kind === "page" && e.fromSW).length);
  step("console_errors", c.consoleLines.filter((l) => /^(error|exception)/.test(l)).slice(0, 12));
} catch (e) {
  step("FAIL", e.stack || e.message);
} finally {
  writeFileSync(out + "/evidence.json", JSON.stringify(ev, null, 1));
  await c.close();
}
clearTimeout(deadline);
setTimeout(() => process.exit(0), 300);
