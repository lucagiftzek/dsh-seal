// Layout probe: load the GUI through a fake edge, wait for the seal, take
// screenshots at desktop and phone widths and dump the controls near the
// screen edges (to place the seal status indicator where it hides nothing).
//
// node layout.mjs [base] [outdir] [tag]
import { connect } from "./cdp.mjs";
import { writeFileSync } from "node:fs";

const base = process.argv[2] || "http://127.0.0.1:3083";
const out = process.argv[3] || "/var/tmp/seal-work/pre";
const tag = process.argv[4] || "layout";
const c = await connect({ origin: base });
const deadline = setTimeout(async () => { console.log("FAIL deadline"); await c.close(); process.exit(1); }, 180000);
const ctrls = () => c.evaluate(`JSON.stringify([...document.querySelectorAll('button,[role=button],[role=tab],a,input,textarea,[contenteditable=true]')].map(b => { const r = b.getBoundingClientRect(); return [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height), (b.getAttribute('aria-label') || b.getAttribute('title') || b.innerText || b.placeholder || b.tagName).replace(/\\s+/g, ' ').trim().slice(0, 30)] }).filter(x => x[2] > 0 && x[3] > 0))`).then(JSON.parse);
try {
  await c.send("Page.navigate", { url: base + "/" }, c.page);
  for (let i = 0; i < 60; i++) {
    await c.sleep(1000);
    const st = await c.evaluate("window.__dshSeal && __dshSeal.state").catch(() => null);
    if (st && st !== "starting") { console.log("seal", st, i + "s"); break; }
  }
  await c.sleep(6000);
  for (const [name, w, h, mobile] of [["desktop", 1500, 950, false], ["phone", 390, 844, true]]) {
    await c.send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: 1, mobile }, c.page);
    await c.sleep(2500);
    await c.shot(`${out}/${tag}-${name}.png`);
    const all = await ctrls();
    writeFileSync(`${out}/${tag}-${name}.json`, JSON.stringify(all));
    console.log(name, "controls", all.length, "bottom-left", JSON.stringify(all.filter((x) => x[1] > h - 140 && x[0] < 400)), "top", JSON.stringify(all.filter((x) => x[1] < 50)));
  }
  console.log("seal", JSON.stringify(await c.evaluate("({state: __dshSeal.state, reason: __dshSeal.reason, sw: __dshSeal.sw, mux: __dshSeal.muxState})")));
  console.log("theme", await c.evaluate("JSON.stringify({cls: document.documentElement.className, ds: {...document.documentElement.dataset}, scheme: getComputedStyle(document.documentElement).colorScheme, bg: getComputedStyle(document.body).backgroundColor})"));
} catch (e) {
  console.log("FAIL", e.message);
} finally {
  clearTimeout(deadline);
  await c.close();
}
setTimeout(() => process.exit(0), 300);
