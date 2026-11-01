// Probe: load the GUI through a fake edge and evaluate an expression file in
// the page (prints the JSON result). Closes its tab at the end.
//   node probe.mjs <base> <expr.js> [shot.png] [width height]
import { connect } from "./cdp.mjs";
import { readFileSync } from "node:fs";

const [base, exprFile, shotFile, w, h] = process.argv.slice(2);
const c = await connect({ origin: base });
const deadline = setTimeout(async () => { console.log("FAIL deadline"); await c.close(); process.exit(1); }, 150000);
try {
  if (w) await c.send("Emulation.setDeviceMetricsOverride", { width: +w, height: +h, deviceScaleFactor: 1, mobile: +w < 600 }, c.page);
  await c.send("Page.navigate", { url: base + "/" }, c.page);
  for (let i = 0; i < 60; i++) {
    await c.sleep(1000);
    const st = await c.evaluate("window.__dshSeal && __dshSeal.state").catch(() => null);
    if (st && st !== "starting") break;
  }
  await c.sleep(7000);
  console.log(JSON.stringify(await c.evaluate(readFileSync(exprFile, "utf8"), 30000), null, 1));
  if (shotFile) await c.shot(shotFile);
} catch (e) {
  console.log("FAIL", e.message);
} finally {
  clearTimeout(deadline);
  await c.close();
}
setTimeout(() => process.exit(0), 300);
