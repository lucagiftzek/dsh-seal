// Exploration: load the real DSH through dsh-seal, wait for the seal state,
// dump visible controls and a screenshot. Usage: node explore.mjs [base] [outdir]
import { connect } from "./cdp.mjs";
import { writeFileSync } from "node:fs";

const base = process.argv[2] || "http://127.0.0.1:3083";
const out = process.argv[3] || "/var/tmp/seal-work";
const c = await connect({ origin: base });
try {
  await c.send("Storage.clearDataForOrigin", { origin: base, storageTypes: "service_workers,cache_storage,indexeddb,local_storage" }).catch(() => {});
  await c.send("Network.deleteCookies", { name: "sealboot", domain: new URL(base).hostname }, c.page).catch(() => {});
  await c.send("Page.navigate", { url: base + "/" + (process.env.DSH_TOKEN ? "?token=" + process.env.DSH_TOKEN : "") }, c.page);
  let st = null;
  for (let i = 0; i < 90; i++) {
    await c.sleep(1000);
    st = await c.evaluate("JSON.stringify(window.__dshSeal ? {state: __dshSeal.state, reason: __dshSeal.reason, sw: __dshSeal.sw, mux: __dshSeal.muxState, fallbacks: __dshSeal.fallbacks} : null)").catch(() => null);
    if (i % 5 === 0) console.log(i + "s", st, c.consoleLines.slice(-2).join(" | "));
    if (st && !/starting|installing/.test(st)) break;
  }
  console.log("seal:", st);
  await c.sleep(12000);
  const ctrls = await c.evaluate(`JSON.stringify([...document.querySelectorAll('button,[role=button],[role=tab],a')].map(b => { const r = b.getBoundingClientRect(); return [Math.round(r.x), Math.round(r.y), (b.getAttribute('aria-label') || b.innerText || '').replace(/\\s+/g, ' ').trim().slice(0, 40)] }).filter(x => x[2] && x[0] >= 0 && x[1] >= 0))`);
  writeFileSync(out + "/controls.json", ctrls);
  console.log("controls:", JSON.parse(ctrls).length);
  await c.shot(out + "/explore.png");
  writeFileSync(out + "/netlog.json", JSON.stringify(c.log.filter((e) => e.kind !== "wsframe"), null, 1));
  console.log("requests:", c.log.length, "console:", c.consoleLines.slice(-15).join("\n  "));
} catch (e) {
  console.log("FAIL", e.message);
} finally {
  await c.close();
}
setTimeout(() => process.exit(0), 300);
