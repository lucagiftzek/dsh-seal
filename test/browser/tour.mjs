// Exploration step 2: open the scratch chat through the search box, open the
// right side card, dump controls of the right area and take screenshots.
import { connect } from "./cdp.mjs";
import { writeFileSync } from "node:fs";

const base = process.argv[2] || "http://127.0.0.1:3083";
const out = process.argv[3] || "/var/tmp/seal-work";
const TITLE = "preset check augmentor (scratch, safe to delete)";
const c = await connect({ origin: base });
const ctrls = (minX = 0) => c.evaluate(`JSON.stringify([...document.querySelectorAll('button,[role=button],[role=tab],a,input')].map(b => { const r = b.getBoundingClientRect(); return [Math.round(r.x + r.width / 2), Math.round(r.y + r.height / 2), (b.getAttribute('aria-label') || b.getAttribute('title') || b.innerText || b.placeholder || '').replace(/\\s+/g, ' ').trim().slice(0, 40)] }).filter(x => x[2] && x[0] >= ${minX} && x[1] >= 0 && x[1] < 950))`).then(JSON.parse);
try {
  await c.send("Page.navigate", { url: base + "/" }, c.page);
  for (let i = 0; i < 40; i++) {
    await c.sleep(1000);
    const st = await c.evaluate("window.__dshSeal && __dshSeal.state").catch(() => null);
    if (st && st !== "starting") { console.log("seal", st, i + "s"); break; }
  }
  await c.sleep(8000);
  // search the scratch chat
  const search = (await ctrls()).find((x) => x[2] === "Search chats");
  console.log("search box", !!search);
  await c.mouse(search[0], search[1]);
  await c.send("Input.insertText", { text: "preset check augmentor" }, c.page);
  await c.sleep(2500);
  const hit = await c.evaluate(`(() => { const els = [...document.querySelectorAll("body *")].filter(e => e.children.length === 0 && (e.textContent || "").includes("preset check augmentor") && !e.closest("input")); for (const e of els) { const b = e.getBoundingClientRect(); if (b.width && b.height && b.x < 300 && b.y > 380) return [b.x + b.width / 2, b.y + b.height / 2] } return null })()`);
  console.log("hit", hit);
  if (hit) await c.mouse(hit[0], hit[1]);
  await c.sleep(4000);
  const open = await c.evaluate(`!!document.evaluate(${JSON.stringify(`//header//*[contains(normalize-space(text()), "preset check augmentor")]`)}, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue`);
  console.log("open in header", open);
  await c.shot(out + "/tour-chat.png");
  writeFileSync(out + "/tour-controls.json", JSON.stringify(await ctrls(), null, 0));
  await c.mouse(1474, 25);
  await c.sleep(3000);
  await c.shot(out + "/tour-side.png");
  writeFileSync(out + "/tour-side.json", JSON.stringify(await ctrls(800), null, 0));
} catch (e) {
  console.log("FAIL", e.message);
} finally {
  await c.close();
}
setTimeout(() => process.exit(0), 300);
