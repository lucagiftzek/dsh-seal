// egress=off by SIGHUP while a page is open: the worker must go direct at
// once (kill switch) and the indicator must list the host as escaped.
//   node killswitch.mjs <base> <conf> <unit>
import { connect } from "./cdp.mjs";
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
const [base, conf, unit] = process.argv.slice(2);
const IMG = "https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png";
const c = await connect({ origin: base });
const out = {};
const hup = () => execSync(`XDG_RUNTIME_DIR=/run/user/${process.getuid()} systemctl --user kill -s HUP ${unit}`);
const orig = readFileSync(conf, "utf8");
try {
  await c.send("Storage.clearDataForOrigin", { origin: base, storageTypes: "service_workers,cache_storage,indexeddb,local_storage" }, c.page).catch((e) => console.log("clear warning", e.message));
  const ck = await c.send("Network.getCookies", { urls: [base + "/"] }, c.page);
  for (const k of ck.cookies) await c.send("Network.deleteCookies", { name: k.name, domain: k.domain, path: k.path }, c.page);
  await c.send("Page.navigate", { url: base + "/" }, c.page);
  for (let i = 0; i < 60; i++) { await c.sleep(1000); const s = await c.evaluate("window.__dshSeal && __dshSeal.state").catch(() => null); if (s && s !== "starting") break; }
  const get = (n) => c.evaluate(`fetch('${IMG}?k=${n}', { mode: 'no-cors', cache: 'no-store' }).then(r => r.blob()).then(b => b.size, e => 'error ' + e)`, 30000);
  out.on = await get(1);
  out.stateOn = await c.evaluate("__dshSeal.check().then(() => ({ state: __dshSeal.state, escaped: __dshSeal.view.escaped }))");
  writeFileSync(conf, orig.replace(/^egress=on$/m, "egress=off"));
  hup();
  await c.sleep(1000);
  out.off = await get(2);
  out.off2 = await get(3);
  out.stateOff = await c.evaluate("__dshSeal.check().then(() => ({ state: __dshSeal.state, reason: __dshSeal.reason, escaped: __dshSeal.view.escaped }))");
} catch (e) { out.error = e.message; } finally {
  writeFileSync(conf, orig);
  hup();
  await c.close();
}
console.log(JSON.stringify(out));
setTimeout(() => process.exit(0), 200);
